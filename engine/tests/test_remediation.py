import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from common import audit

ENGINE = Path(__file__).resolve().parents[1]
HANDLER = ENGINE / "src" / "remediation" / "handler.py"
REGION = "us-west-2"
OTHER_REGION = "eu-west-1"
SCOPE = "cg-dev-"
AUDIT_TABLE = "cg-test-audit"


def load_handler():
    # Load by path: every Lambda's file is called handler.py, so a plain import would collide.
    spec = importlib.util.spec_from_file_location("engine_remediation_handler", HANDLER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rem = load_handler()


@pytest.fixture
def aws(monkeypatch):
    for var in ("DEV_SCOPE", "DETECTION_WINDOW_MINUTES"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("DRY_RUN", "false")  # tests opt in to dry-run explicitly
    monkeypatch.setenv("TABLE_AUDIT", AUDIT_TABLE)
    with mock_aws():
        audit_table = create_audit_table()
        audit.reset_clients()
        ec2 = boto3.client("ec2", region_name=REGION)
        yield {"ec2": ec2, "cw": boto3.client("cloudwatch", region_name=REGION), "audit": audit_table,
               "ami": ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]}
        audit.reset_clients()


def create_audit_table():
    """<prefix>audit as in CONTRACT §3.3 (resourceId + ts, GSI byDay)."""
    return boto3.resource("dynamodb", region_name=REGION).create_table(
        TableName=AUDIT_TABLE,
        KeySchema=[{"AttributeName": "resourceId", "KeyType": "HASH"}, {"AttributeName": "ts", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": a, "AttributeType": "S"} for a in ("resourceId", "ts", "day")],
        GlobalSecondaryIndexes=[{"IndexName": "byDay",
                                 "KeySchema": [{"AttributeName": "day", "KeyType": "HASH"},
                                               {"AttributeName": "ts", "KeyType": "RANGE"}],
                                 "Projection": {"ProjectionType": "ALL"}}],
        BillingMode="PAY_PER_REQUEST",
    )


def audit_entries(aws, rid=None):
    """Audit items (optionally for one resource), oldest first."""
    items = aws["audit"].scan()["Items"]
    return sorted((i for i in items if rid is None or i["resourceId"] == rid), key=lambda i: i["ts"])


def later(hours=2):
    """Check time: far enough after the moto launch time that the instance is older than the 30-min window."""
    return datetime.now(timezone.utc) + timedelta(hours=hours)


def tag_list(tags):
    return [{"Key": k, "Value": v} for k, v in tags.items()]


def launch(aws, tags=None, ec2=None):
    ec2 = ec2 or aws["ec2"]
    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    kwargs = {"TagSpecifications": [{"ResourceType": "instance", "Tags": tag_list(tags)}]} if tags else {}
    return ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.micro",
                             **kwargs)["Instances"][0]["InstanceId"]


def volume(aws, tags=None):
    kwargs = {"TagSpecifications": [{"ResourceType": "volume", "Tags": tag_list(tags)}]} if tags else {}
    return aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8, **kwargs)["VolumeId"]


def state(aws, iid):
    return aws["ec2"].describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]["State"]["Name"]


def snapshots_of(aws, vid):
    # moto preloads AMI snapshots owned by "self", so filter by source volume.
    return aws["ec2"].describe_snapshots(Filters=[{"Name": "volume-id", "Values": [vid]}])["Snapshots"]


def put_metrics(aws, iid, at, cpu=1.0, network=1000.0, disk=10.0):
    ts = at - timedelta(minutes=10)
    data = [("AWS/EC2", "CPUUtilization", "InstanceId", iid, cpu, "Percent"),
            ("AWS/EC2", "NetworkIn", "InstanceId", iid, network / 2, "Bytes"),
            ("AWS/EC2", "NetworkOut", "InstanceId", iid, network / 2, "Bytes")]
    inst = aws["ec2"].describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    vol = inst["BlockDeviceMappings"][0]["Ebs"]["VolumeId"]
    data += [("AWS/EBS", m, "VolumeId", vol, disk / 2, "Count") for m in ("VolumeReadOps", "VolumeWriteOps")]
    for ns, name, dim, value_id, value, unit in data:
        aws["cw"].put_metric_data(Namespace=ns, MetricData=[
            {"MetricName": name, "Dimensions": [{"Name": dim, "Value": value_id}], "Timestamp": ts,
             "Value": value, "Unit": unit}])


def call(action, rid, region=REGION, dry_run=False, now=None, **extra):
    return rem.handler(dict(action=action, resourceId=rid, region=region, dryRun=dry_run, **extra), None,
                       now=now)


def logs(capsys):
    return [json.loads(line) for line in capsys.readouterr().out.strip().splitlines() if line.startswith("{")]


# ---------------------------------------------------------------- CHECK_EC2


def test_check_ec2_idle(aws, capsys):
    iid = launch(aws)
    at = later()
    put_metrics(aws, iid, at)
    assert call("CHECK_EC2", iid, now=at) == {"stillIdle": True, "protected": False, "state": "running"}
    [line] = logs(capsys)
    assert line["action"] == "CHECK_EC2" and line["result"] == "idle" and line["resourceId"] == iid
    assert line["classification"] == "idle"


@pytest.mark.parametrize("metrics", [{"cpu": 50.0}, {"network": 50 * 1024 * 1024}, {"disk": 5000.0}])
def test_check_ec2_active_is_not_idle(aws, metrics):
    iid = launch(aws)
    at = later()
    put_metrics(aws, iid, at, **metrics)
    assert call("CHECK_EC2", iid, now=at)["stillIdle"] is False


def test_check_ec2_no_metrics_is_not_idle(aws):
    iid = launch(aws)
    assert call("CHECK_EC2", iid, now=later())["stillIdle"] is False


def test_check_ec2_uses_detection_window(aws, monkeypatch):
    iid = launch(aws)
    at = later(hours=30)
    put_metrics(aws, iid, at, network=5 * 1024 * 1024)  # 5 MB: busy over 30 min, idle over 1 day
    assert call("CHECK_EC2", iid, now=at)["stillIdle"] is False
    monkeypatch.setenv("DETECTION_WINDOW_MINUTES", "1440")
    assert call("CHECK_EC2", iid, now=at)["stillIdle"] is True


def test_check_ec2_recently_started_is_not_idle(aws):
    iid = launch(aws)
    now = datetime.now(timezone.utc)
    put_metrics(aws, iid, now)
    assert call("CHECK_EC2", iid, now=now)["stillIdle"] is False


def test_check_ec2_protected(aws):
    iid = launch(aws, {"guardian:protect": "TRUE"})
    at = later()
    put_metrics(aws, iid, at)
    assert call("CHECK_EC2", iid, now=at) == {"stillIdle": True, "protected": True, "state": "running"}


def test_check_ec2_stopped(aws):
    iid = launch(aws)
    aws["ec2"].stop_instances(InstanceIds=[iid])
    out = call("CHECK_EC2", iid, now=later())
    assert out["stillIdle"] is False and out["state"] == "stopped"


def test_check_ec2_missing_instance(aws):
    assert call("CHECK_EC2", "i-0123456789abcdef0") == {"stillIdle": False, "protected": False,
                                                        "state": "not_found"}


def test_runs_in_the_input_region(aws):
    other = boto3.client("ec2", region_name=OTHER_REGION)
    iid = launch(aws, ec2=other)
    assert call("CHECK_EC2", iid, region=OTHER_REGION, now=later())["state"] == "running"
    assert call("CHECK_EC2", iid, region=REGION, now=later())["state"] == "not_found"


# ---------------------------------------------------------------- STOP_INSTANCE


def test_stop_instance(aws, capsys):
    iid = launch(aws)
    alloc = aws["ec2"].allocate_address(Domain="vpc")
    aws["ec2"].associate_address(InstanceId=iid, AllocationId=alloc["AllocationId"])
    out = call("STOP_INSTANCE", iid)
    assert out == {"stopped": True, "dryRun": False, "elasticIps": [alloc["PublicIp"]]}
    assert state(aws, iid) in ("stopping", "stopped")
    [line] = logs(capsys)
    assert line["action"] == "STOP_INSTANCE" and line["result"] == "stopped" and line["dryRun"] is False


def test_stop_instance_dry_run(aws, capsys):
    iid = launch(aws)
    assert call("STOP_INSTANCE", iid, dry_run=True) == {"stopped": False, "dryRun": True, "elasticIps": []}
    assert state(aws, iid) == "running"
    [line] = logs(capsys)
    assert line["result"] == "dry_run"


@pytest.mark.parametrize("env", ["true", "", "yes"])
def test_env_dry_run_wins_over_input(aws, monkeypatch, env):
    monkeypatch.setenv("DRY_RUN", env)
    iid = launch(aws)
    assert call("STOP_INSTANCE", iid, dry_run=False)["dryRun"] is True
    assert state(aws, iid) == "running"


def test_missing_input_dry_run_is_dry(aws):
    iid = launch(aws)
    out = rem.handler({"action": "STOP_INSTANCE", "resourceId": iid, "region": REGION}, None)
    assert out["dryRun"] is True and state(aws, iid) == "running"


def test_stop_protected_refused(aws):
    iid = launch(aws, {"guardian:protect": "true"})
    with pytest.raises(rem.RefusedError):
        call("STOP_INSTANCE", iid)
    assert state(aws, iid) == "running"


@pytest.mark.parametrize("dry_run", [False, True])
def test_stop_already_stopped(aws, monkeypatch, dry_run):
    monkeypatch.setenv("DRY_RUN", "true" if dry_run else "false")
    iid = launch(aws)
    aws["ec2"].stop_instances(InstanceIds=[iid])
    # Stopped by someone else: never reported as a dry-run, so the workflow resolves it (CONTRACT §4.3).
    assert call("STOP_INSTANCE", iid, dry_run=dry_run) == {"stopped": False, "dryRun": False, "elasticIps": []}


def test_stop_missing_instance_raises(aws):
    with pytest.raises(rem.RefusedError):
        call("STOP_INSTANCE", "i-0123456789abcdef0")


# ---------------------------------------------------------------- dev scope


def test_dev_scope_refuses_untagged_resources(aws, monkeypatch, capsys):
    monkeypatch.setenv("DEV_SCOPE", SCOPE)
    iid = launch(aws, {"guardian:dev-scope": "cg-other-"})
    vid = volume(aws)
    for action, rid in (("CHECK_EC2", iid), ("STOP_INSTANCE", iid), ("CHECK_EBS", vid),
                        ("CREATE_SNAPSHOT", vid), ("DELETE_VOLUME", vid)):
        with pytest.raises(rem.RefusedError, match="dev scope"):
            call(action, rid, snapshotId="snap-0123456789abcdef0")
    assert state(aws, iid) == "running"
    assert snapshots_of(aws, vid) == []
    lines = logs(capsys)
    assert [line["result"] for line in lines] == ["refused"] * 5
    assert [line["findingType"] for line in lines] == ["EC2_IDLE"] * 2 + ["EBS_UNATTACHED"] * 3


def test_dev_scope_allows_tagged_resources(aws, monkeypatch):
    monkeypatch.setenv("DEV_SCOPE", SCOPE)
    iid = launch(aws, {"guardian:dev-scope": SCOPE})
    assert call("STOP_INSTANCE", iid)["stopped"] is True


def test_dev_scope_checks_the_snapshot(aws, monkeypatch):
    vid = volume(aws, {"guardian:dev-scope": SCOPE})
    snap = call("CREATE_SNAPSHOT", vid)["snapshotId"]
    monkeypatch.setenv("DEV_SCOPE", "cg-other-")
    with pytest.raises(rem.RefusedError, match="dev scope"):
        call("SNAPSHOT_STATUS", vid, snapshotId=snap)


# ---------------------------------------------------------------- EBS


def test_check_ebs(aws):
    vid = volume(aws)
    assert call("CHECK_EBS", vid) == {"stillUnattached": True, "protected": False, "exists": True,
                                      "sizeGb": 8, "availabilityZone": f"{REGION}a"}
    iid = launch(aws)
    aws["ec2"].attach_volume(VolumeId=vid, InstanceId=iid, Device="/dev/sdf")
    assert call("CHECK_EBS", vid)["stillUnattached"] is False


def test_check_ebs_protected_and_missing(aws):
    vid = volume(aws, {"guardian:protect": "true"})
    assert call("CHECK_EBS", vid)["protected"] is True
    assert call("CHECK_EBS", "vol-0123456789abcdef0") == {"stillUnattached": False, "protected": False,
                                                          "exists": False}


def test_create_snapshot_copies_tags(aws):
    vid = volume(aws, {"owner": "alice@example.com", "project": "demo", "Name": "data"})
    out = call("CREATE_SNAPSHOT", vid)
    assert out["dryRun"] is False and out["snapshotId"].startswith("snap-")
    [snap] = aws["ec2"].describe_snapshots(SnapshotIds=[out["snapshotId"]])["Snapshots"]
    assert {t["Key"]: t["Value"] for t in snap["Tags"]} == {
        "owner": "alice@example.com", "project": "demo", "Name": "data", "guardian:source-volume": vid}


def test_create_snapshot_dry_run(aws):
    vid = volume(aws)
    assert call("CREATE_SNAPSHOT", vid, dry_run=True) == {"snapshotId": None, "dryRun": True}
    assert snapshots_of(aws, vid) == []


def test_create_snapshot_protected_refused(aws):
    vid = volume(aws, {"guardian:protect": "true"})
    with pytest.raises(rem.RefusedError):
        call("CREATE_SNAPSHOT", vid)


def test_snapshot_status(aws):
    vid = volume(aws)
    snap = call("CREATE_SNAPSHOT", vid)["snapshotId"]
    assert call("SNAPSHOT_STATUS", vid, snapshotId=snap) == {"state": "completed"}


def test_snapshot_status_needs_snapshot_id(aws):
    with pytest.raises(ValueError):
        call("SNAPSHOT_STATUS", volume(aws))


def test_delete_volume(aws, capsys):
    vid = volume(aws)
    snap = call("CREATE_SNAPSHOT", vid)["snapshotId"]
    assert call("DELETE_VOLUME", vid, snapshotId=snap) == {"deleted": True, "dryRun": False}
    assert aws["ec2"].describe_volumes(Filters=[{"Name": "volume-id", "Values": [vid]}])["Volumes"] == []
    assert logs(capsys)[-1]["result"] == "deleted"


def test_delete_volume_dry_run(aws):
    vid = volume(aws)
    assert call("DELETE_VOLUME", vid, dry_run=True) == {"deleted": False, "dryRun": True}
    assert call("CHECK_EBS", vid)["exists"] is True


def test_delete_refused_without_snapshot(aws):
    vid = volume(aws)
    with pytest.raises(ValueError):
        call("DELETE_VOLUME", vid)
    with pytest.raises(rem.RefusedError, match="not found"):
        call("DELETE_VOLUME", vid, snapshotId="snap-0123456789abcdef0")
    assert call("CHECK_EBS", vid)["exists"] is True


def test_delete_refused_with_untagged_snapshot(aws):
    vid = volume(aws)
    snap = aws["ec2"].create_snapshot(VolumeId=vid)["SnapshotId"]  # not created by the Guardian
    with pytest.raises(rem.RefusedError, match="source-volume"):
        call("DELETE_VOLUME", vid, snapshotId=snap)
    assert call("CHECK_EBS", vid)["exists"] is True


def test_delete_refused_with_another_volumes_snapshot(aws):
    vid, other = volume(aws), volume(aws)
    snap = call("CREATE_SNAPSHOT", other)["snapshotId"]
    with pytest.raises(rem.RefusedError, match="source-volume"):
        call("DELETE_VOLUME", vid, snapshotId=snap)
    assert call("CHECK_EBS", vid)["exists"] is True


def test_delete_refused_while_snapshot_pending(aws, monkeypatch):
    vid = volume(aws)
    snap = call("CREATE_SNAPSHOT", vid)["snapshotId"]
    real = rem._snapshot
    monkeypatch.setattr(rem, "_snapshot", lambda ec2, sid: dict(real(ec2, sid), State="pending"))
    with pytest.raises(rem.RefusedError, match="pending"):
        call("DELETE_VOLUME", vid, snapshotId=snap)
    assert call("CHECK_EBS", vid)["exists"] is True


def test_delete_refused_when_attached_or_protected(aws):
    vid = volume(aws)
    snap = call("CREATE_SNAPSHOT", vid)["snapshotId"]
    aws["ec2"].attach_volume(VolumeId=vid, InstanceId=launch(aws), Device="/dev/sdf")
    with pytest.raises(rem.RefusedError, match="not available"):
        call("DELETE_VOLUME", vid, snapshotId=snap)
    pvid = volume(aws, {"guardian:protect": "true"})
    with pytest.raises(rem.RefusedError):
        call("DELETE_VOLUME", pvid, snapshotId=snap)


# ---------------------------------------------------------------- misc


def test_unknown_action(aws):
    with pytest.raises(ValueError):
        call("TERMINATE", "i-0123456789abcdef0")


def test_never_deletes_snapshots_or_releases_addresses():
    source = HANDLER.read_text(encoding="utf-8")
    assert "delete_snapshot" not in source and "release_address" not in source
    for tf in (ENGINE / "terraform").glob("*.tf"):
        text = tf.read_text(encoding="utf-8")
        assert '"ec2:DeleteSnapshot"' not in text and '"ec2:ReleaseAddress"' not in text
        assert '"ec2:*"' not in text


# ---------------------------------------------------------------- audit (CONTRACT §3.3, #29 follow-up)

AUDIT_FIELDS = ("resourceId", "actor", "event", "findingType", "region", "generation", "dryRun", "result")


def entry_of(aws, rid):
    [entry] = audit_entries(aws, rid)
    return entry


def test_stop_instance_writes_instance_stopped(aws):
    iid = launch(aws)
    call("STOP_INSTANCE", iid, findingType="EC2_IDLE", generation=2)
    entry = entry_of(aws, iid)
    assert {k: entry[k] for k in AUDIT_FIELDS} == {
        "resourceId": iid, "actor": "remediation", "event": "instance_stopped", "findingType": "EC2_IDLE",
        "region": REGION, "generation": 2, "dryRun": False, "result": "ok"}
    assert entry["details"] == {"elasticIps": []}


def test_dry_run_stop_writes_instance_stopped(aws):
    iid = launch(aws)
    call("STOP_INSTANCE", iid, dry_run=True, findingType="EC2_IDLE", generation=1)
    entry = entry_of(aws, iid)
    assert entry["event"] == "instance_stopped" and entry["dryRun"] is True and entry["generation"] == 1
    assert state(aws, iid) == "running"


def test_finding_type_and_generation_are_optional(aws):
    iid = launch(aws)
    call("STOP_INSTANCE", iid)
    entry = entry_of(aws, iid)
    assert entry["findingType"] == "EC2_IDLE" and "generation" not in entry


@pytest.mark.parametrize("dry_run", [False, True])
def test_already_stopped_writes_no_entry(aws, monkeypatch, dry_run):
    monkeypatch.setenv("DRY_RUN", "true" if dry_run else "false")
    iid = launch(aws)
    aws["ec2"].stop_instances(InstanceIds=[iid])
    assert call("STOP_INSTANCE", iid, dry_run=dry_run, generation=1)["stopped"] is False
    assert audit_entries(aws) == []


def test_refused_and_checks_write_no_entry(aws):
    iid = launch(aws, {"guardian:protect": "true"})
    with pytest.raises(rem.RefusedError):
        call("STOP_INSTANCE", iid)
    call("CHECK_EC2", iid, now=later())
    call("CHECK_EBS", volume(aws))
    assert audit_entries(aws) == []


def test_snapshot_and_delete_write_entries(aws):
    vid = volume(aws)
    snap = call("CREATE_SNAPSHOT", vid, findingType="EBS_UNATTACHED", generation=1)["snapshotId"]
    call("SNAPSHOT_STATUS", vid, snapshotId=snap)
    call("DELETE_VOLUME", vid, snapshotId=snap, findingType="EBS_UNATTACHED", generation=1)
    by_event = {e["event"]: e for e in audit_entries(aws, vid)}  # same second: order by ts is random
    created, deleted = by_event["snapshot_created"], by_event["volume_deleted"]
    assert (created["event"], created["dryRun"], created["details"]) == (
        "snapshot_created", False, {"snapshotId": snap})
    assert (deleted["event"], deleted["dryRun"], deleted["details"]) == (
        "volume_deleted", False, {"snapshotId": snap})
    assert all(e["actor"] == "remediation" and e["findingType"] == "EBS_UNATTACHED" and e["generation"] == 1
               for e in (created, deleted))


def test_dry_run_snapshot_and_delete_write_entries(aws):
    vid = volume(aws)
    call("CREATE_SNAPSHOT", vid, dry_run=True, generation=1)
    call("DELETE_VOLUME", vid, dry_run=True, generation=1)
    by_event = {e["event"]: e for e in audit_entries(aws, vid)}  # same second: order by ts is random
    created, deleted = by_event["snapshot_created"], by_event["volume_deleted"]
    assert (created["event"], created["dryRun"], created["details"]) == (
        "snapshot_created", True, {"snapshotId": None})
    assert (deleted["event"], deleted["dryRun"]) == ("volume_deleted", True)
    assert created["findingType"] == "EBS_UNATTACHED"


def test_audit_failure_does_not_fail_the_stop(aws, monkeypatch, capsys):
    monkeypatch.setenv("TABLE_AUDIT", "cg-test-missing")
    iid = launch(aws)
    assert call("STOP_INSTANCE", iid)["stopped"] is True
    assert any(line["action"] == "audit_write_failed" for line in logs(capsys))


# ---------------------------------------------------------------- IAM policy (engine/terraform/remediation.tf, #39)

REMEDIATION_TF = ENGINE / "terraform" / "remediation.tf"


def _remediation_statements():
    import re
    text = REMEDIATION_TF.read_text(encoding="utf-8")
    block = text[text.index('data "aws_iam_policy_document" "remediation" {'):]
    block = block[:block.index('resource "aws_iam_role_policy" "remediation"')]
    out = {}
    for chunk in block.split("statement {")[1:]:
        flat = re.sub(r"\s+", " ", chunk)
        out[re.search(r'sid = "([^"]+)"', flat).group(1)] = flat
    return out


def _dev_scope_key(flat):
    import re
    m = re.findall(r'dynamic "condition" \{ for_each = var\.dev_scope != "" \? \[var\.dev_scope\] : \[\] content \{ '
                   r'test = "StringEquals" variable = "([^"]+)" values = \[condition\.value\]', flat)
    return m


@pytest.mark.parametrize("sid,key,resource", [
    ("StopInstances", "ec2:ResourceTag/guardian:dev-scope", ":instance/*"),
    ("DeleteVolumes", "ec2:ResourceTag/guardian:dev-scope", ":volume/*"),
    ("CreateSnapshotOfVolume", "ec2:ResourceTag/guardian:dev-scope", ":volume/*"),
    ("CreateSnapshotNew", "aws:RequestTag/guardian:dev-scope", "::snapshot/*"),
    ("TagNewSnapshots", "aws:RequestTag/guardian:dev-scope", "::snapshot/*"),
])
def test_remediation_policy_dev_scope_in_iam(sid, key, resource):
    statements = _remediation_statements()
    assert _dev_scope_key(statements[sid]) == [key]
    assert resource in statements[sid]


def test_remediation_policy_protect_deny_unchanged_and_no_forbidden_actions():
    statements = _remediation_statements()
    assert "CreateSnapshots" not in statements  # split in two (#39)
    deny = statements["DenyProtected"]
    assert 'effect = "Deny"' in deny and 'actions = ["ec2:StopInstances", "ec2:DeleteVolume"]' in deny
    assert 'resources = ["*"]' in deny and "dynamic" not in deny
    assert ('test = "StringEqualsIgnoreCase" variable = "aws:ResourceTag/guardian:protect" values = ["true"]'
            in deny)
    for flat in statements.values():
        assert "DeleteSnapshot" not in flat and "ReleaseAddress" not in flat and '"ec2:*"' not in flat
