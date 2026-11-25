import json
import threading
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import boto3
import pytest
from moto import mock_aws

from common import audit, idle, timeline
from scanner import attachments, config, findings, handler

REGION = "us-west-2"
TABLE = "cg-test-findings"
AUDIT_TABLE = "cg-test-audit"
ATTACH_TABLE = "cg-test-volume-attachments"
SCOPE = "cg-dev-"
OWNED = {"owner": "Alice@Example.com", "project": "demo", "Name": "web-1"}


@pytest.fixture
def aws(monkeypatch):
    for var in ("DEV_SCOPE", "EC2_SFN_ARN", "EBS_SFN_ARN", "DETECTION_WINDOW_MINUTES",
                "EIP_STOPPED_THRESHOLD_HOURS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_REGION", REGION)
    monkeypatch.setenv("TABLE_FINDINGS", TABLE)
    monkeypatch.setenv("TABLE_AUDIT", AUDIT_TABLE)
    monkeypatch.setenv("TABLE_VOLUME_ATTACHMENTS", ATTACH_TABLE)
    monkeypatch.setenv("SCAN_REGIONS", REGION)
    monkeypatch.setenv("DRY_RUN", "true")
    with mock_aws():
        table = boto3.resource("dynamodb", region_name=REGION).create_table(
            TableName=TABLE,
            KeySchema=[{"AttributeName": "resourceId", "KeyType": "HASH"},
                       {"AttributeName": "findingType", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "resourceId", "AttributeType": "S"},
                                  {"AttributeName": "findingType", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        audit_table = create_audit_table()
        attach_table = boto3.resource("dynamodb", region_name=REGION).create_table(
            TableName=ATTACH_TABLE, KeySchema=[{"AttributeName": "volumeId", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "volumeId", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        findings.reset_clients()
        timeline.reset_clients()
        audit.reset_clients()
        attachments.reset_clients()
        ec2 = boto3.client("ec2", region_name=REGION)
        yield {"table": table, "ec2": ec2, "cw": boto3.client("cloudwatch", region_name=REGION),
               "audit": audit_table, "attachments": attach_table,
               "ami": ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]}
        findings.reset_clients()
        timeline.reset_clients()
        audit.reset_clients()
        attachments.reset_clients()


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
    """Scan time: far enough after the moto launch time that instances are older than the 30-min window."""
    return datetime.now(timezone.utc) + timedelta(hours=hours)


def tag_list(tags):
    return [{"Key": k, "Value": v} for k, v in tags.items()]


def launch(aws, tags=None, volume_tags=None):
    specs = []
    if tags:
        specs.append({"ResourceType": "instance", "Tags": tag_list(tags)})
    if volume_tags or tags:
        specs.append({"ResourceType": "volume", "Tags": tag_list(volume_tags or tags)})
    kwargs = {"TagSpecifications": specs} if specs else {}
    inst = aws["ec2"].run_instances(ImageId=aws["ami"], MinCount=1, MaxCount=1, InstanceType="t3.micro",
                                    **kwargs)["Instances"][0]
    return inst["InstanceId"]


def root_volume(aws, iid):
    inst = aws["ec2"].describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    return inst["BlockDeviceMappings"][0]["Ebs"]["VolumeId"]


def put_metrics(aws, iid, scan_at, cpu=(1.0,), network=1000.0, disk=10.0):
    """One 5-minute period of data, 10 minutes before the scan time."""
    ts = scan_at - timedelta(minutes=10)
    aws["cw"].put_metric_data(Namespace="AWS/EC2", MetricData=[
        {"MetricName": "CPUUtilization", "Dimensions": [{"Name": "InstanceId", "Value": iid}],
         "Timestamp": ts, "Value": v, "Unit": "Percent"} for v in cpu])
    for name in ("NetworkIn", "NetworkOut"):
        aws["cw"].put_metric_data(Namespace="AWS/EC2", MetricData=[
            {"MetricName": name, "Dimensions": [{"Name": "InstanceId", "Value": iid}],
             "Timestamp": ts, "Value": network / 2, "Unit": "Bytes"}])
    vol = root_volume(aws, iid)
    for name in ("VolumeReadOps", "VolumeWriteOps"):
        aws["cw"].put_metric_data(Namespace="AWS/EBS", MetricData=[
            {"MetricName": name, "Dimensions": [{"Name": "VolumeId", "Value": vol}],
             "Timestamp": ts, "Value": disk / 2, "Unit": "Count"}])


@pytest.fixture
def linux(monkeypatch):
    """moto leaves PlatformDetails out (real EC2 always sets it); mark the described instances Linux."""
    original = handler._all_instances
    monkeypatch.setattr(handler, "_all_instances",
                        lambda ec2: [dict(i, PlatformDetails="Linux/UNIX") for i in original(ec2)])


def get(aws, rid, ftype):
    return aws["table"].get_item(Key={"resourceId": rid, "findingType": ftype}).get("Item")


def all_findings(aws):
    return {(i["resourceId"], i["findingType"]): i for i in aws["table"].scan()["Items"]}


def logs(capsys):
    return [json.loads(line) for line in capsys.readouterr().out.strip().splitlines() if line.startswith("{")]


# ---------------------------------------------------------------- EC2 classification


def test_idle_instance_creates_ec2_idle_finding(aws, linux):
    iid = launch(aws, OWNED)
    scan_at = later()
    put_metrics(aws, iid, scan_at)
    summary = handler.scan_region(REGION, now=scan_at)

    item = get(aws, iid, "EC2_IDLE")
    assert item["classification"] == "idle"
    assert item["status"] == "open"
    assert item["resourceType"] == "ec2" and item["region"] == REGION
    assert item["owner"] == "alice@example.com" and item["ownerSource"] == "tag"
    assert item["project"] == "demo" and item["name"] == "web-1"
    assert item["firstSeenAt"] == item["lastSeenAt"] == scan_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    # Real table: t3.micro in us-west-2 x 730 h. moto's public IP has the account as IpOwnerId (like an Elastic
    # IP), so no IPv4 is added.
    assert item["estimatedMonthlyCost"] == Decimal("7.59")
    assert "estimatedSnapshotMonthlyCost" not in item  # EBS only
    assert "generation" not in item and "reportOnlyReason" not in item
    assert summary["findings"] == {"EC2_IDLE": 1}
    assert summary["timelines"] == {"skipped_no_state_machine": 1}


def test_non_linux_instance_has_no_estimate(aws, capsys):
    iid = launch(aws, OWNED)  # moto: no PlatformDetails
    scan_at = later()
    put_metrics(aws, iid, scan_at)
    handler.scan_region(REGION, now=scan_at)
    assert "estimatedMonthlyCost" not in get(aws, iid, "EC2_IDLE")
    [unknown] = [r for r in logs(capsys) if r["action"] == "price_unknown"]
    assert unknown["resourceId"] == iid and "platform" in unknown["reason"]


def test_estimate_kept_when_a_later_scan_cannot_price(aws, linux, monkeypatch):
    iid = launch(aws, OWNED)
    scan_at = later()
    put_metrics(aws, iid, scan_at)
    handler.scan_region(REGION, now=scan_at)
    monkeypatch.setattr(handler.pricing, "estimate", lambda *a, **k: None)
    handler.scan_region(REGION, now=scan_at + timedelta(minutes=5))
    assert get(aws, iid, "EC2_IDLE")["estimatedMonthlyCost"] == Decimal("7.59")


@pytest.mark.parametrize("cpu,network,disk,expected", [
    ((1.0,), 1000.0, 10.0, "idle"),
    ((1.0,) * 9 + (30.0,), 1000.0, 10.0, "periodic"),  # avg 3.9 %, max 30 %
    ((1.0,), 5 * 1024 * 1024, 10.0, "underused"),      # 5 MB in 30 min > 1 MB
    ((1.0,), 1000.0, 5000.0, "underused"),              # 5000 ops in 30 min > 1800
    ((50.0,), 1000.0, 10.0, None),                      # busy
])
def test_classifications(aws, capsys, cpu, network, disk, expected):
    iid = launch(aws, OWNED)
    scan_at = later()
    put_metrics(aws, iid, scan_at, cpu=cpu, network=network, disk=disk)
    handler.scan_region(REGION, now=scan_at)

    [line] = [entry for entry in logs(capsys) if entry["action"] == "classify"]
    assert line["result"] == (expected or "active")
    item = get(aws, iid, "EC2_IDLE")
    if expected == "idle":
        assert item["classification"] == "idle"
    else:
        assert item is None  # only idle creates an EC2_IDLE finding


def test_classify_thresholds_scale_with_window():
    base = {"cpuAvg": 1.0, "cpuMax": 2.0, "networkBytes": 0.0, "diskOps": 0.0}
    one_day = 1440
    assert idle.classify(dict(base, networkBytes=40 * 1024 * 1024), one_day) == "idle"  # < 48 MB
    assert idle.classify(dict(base, networkBytes=40 * 1024 * 1024), 30) == "underused"
    assert idle.classify(dict(base, diskOps=80000), one_day) == "idle"  # < 86400
    assert idle.classify(dict(base, diskOps=80000), 30) == "underused"  # > 1800
    assert idle.classify(dict(base, diskOps=914), 30) == "idle"  # the Nov 22 live-test instance
    assert idle.classify(dict(base, cpuAvg=None, cpuMax=None), 30) is None


def test_no_cpu_data_is_not_idle(aws):
    iid = launch(aws, OWNED)
    handler.scan_region(REGION, now=later())
    assert get(aws, iid, "EC2_IDLE") is None


def test_instance_younger_than_window_is_skipped(aws):
    iid = launch(aws, OWNED)
    scan_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    put_metrics(aws, iid, scan_at)
    handler.scan_region(REGION, now=scan_at)
    assert get(aws, iid, "EC2_IDLE") is None


def test_stopped_instance_is_not_idle(aws):
    iid = launch(aws, OWNED)
    scan_at = later()
    put_metrics(aws, iid, scan_at)
    aws["ec2"].stop_instances(InstanceIds=[iid])
    handler.scan_region(REGION, now=scan_at)
    assert get(aws, iid, "EC2_IDLE") is None


# ---------------------------------------------------------------- EBS / EIP / tags


def test_unattached_volume(aws):
    launch(aws, OWNED)  # its root volume is attached: no finding
    vol = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8, TagSpecifications=[
        {"ResourceType": "volume", "Tags": tag_list({"owner": "bob@example.com", "project": "demo"})}])["VolumeId"]
    summary = handler.scan_region(REGION, now=later())

    item = get(aws, vol, "EBS_UNATTACHED")
    assert item["resourceType"] == "ebs" and item["status"] == "open"
    assert item["owner"] == "bob@example.com"
    assert [k for k in all_findings(aws) if k[1] == "EBS_UNATTACHED"] == [(vol, "EBS_UNATTACHED")]
    assert summary["findings"]["EBS_UNATTACHED"] == 1
    vtype = aws["ec2"].describe_volumes(VolumeIds=[vol])["Volumes"][0]["VolumeType"]
    assert vtype == "gp2"  # moto's default
    assert item["estimatedMonthlyCost"] == Decimal("0.80")  # 8 GB x $0.10 (us-west-2 gp2)
    assert item["estimatedSnapshotMonthlyCost"] == Decimal("0.40")  # 8 GB x $0.05


def test_unattached_gp3_with_extra_iops(aws):
    vol = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=100, VolumeType="gp3", Iops=4000,
                                   TagSpecifications=[{"ResourceType": "volume", "Tags": tag_list(OWNED)}])
    handler.scan_region(REGION, now=later())
    item = get(aws, vol["VolumeId"], "EBS_UNATTACHED")
    assert item["estimatedMonthlyCost"] == Decimal("13.00")  # 100 x 0.08 + 1,000 IOPS x 0.005
    assert item["estimatedSnapshotMonthlyCost"] == Decimal("5.00")


def test_unassociated_eip(aws):
    alloc = aws["ec2"].allocate_address(Domain="vpc", TagSpecifications=[
        {"ResourceType": "elastic-ip", "Tags": tag_list({"owner": "a@example.com", "project": "p"})}])
    handler.scan_region(REGION, now=later())
    item = get(aws, alloc["AllocationId"], "EIP_UNASSOCIATED")
    assert item["resourceType"] == "eip" and item["status"] == "open"
    assert "reportOnlyReason" not in item  # EIP findings are report-only by type, no reason needed
    assert item["estimatedMonthlyCost"] == Decimal("3.65")  # $0.005 x 730 h
    assert "estimatedSnapshotMonthlyCost" not in item


def _eip_on_stopped(aws):
    iid = launch(aws, OWNED)
    alloc = aws["ec2"].allocate_address(Domain="vpc", TagSpecifications=[
        {"ResourceType": "elastic-ip", "Tags": tag_list({"owner": "a@example.com", "project": "p"})}])
    aws["ec2"].associate_address(AllocationId=alloc["AllocationId"], InstanceId=iid)
    aws["ec2"].stop_instances(InstanceIds=[iid])
    return alloc["AllocationId"]


def test_eip_on_instance_stopped_longer_than_threshold(aws):
    aid = _eip_on_stopped(aws)
    handler.scan_region(REGION, now=later(hours=25))
    assert get(aws, aid, "EIP_ON_STOPPED_INSTANCE")["resourceType"] == "eip"
    assert get(aws, aid, "EIP_UNASSOCIATED") is None


def test_eip_on_recently_stopped_instance_not_reported(aws, monkeypatch):
    aid = _eip_on_stopped(aws)
    handler.scan_region(REGION, now=later(hours=23))
    assert get(aws, aid, "EIP_ON_STOPPED_INSTANCE") is None

    monkeypatch.setenv("EIP_STOPPED_THRESHOLD_HOURS", "1")
    handler.scan_region(REGION, now=later(hours=2))
    assert get(aws, aid, "EIP_ON_STOPPED_INSTANCE") is not None


def test_stop_time_parsing():
    when = handler._stop_time({"StateTransitionReason": "User initiated (2026-11-20 10:15:00 GMT)"})
    assert when == datetime(2026, 11, 20, 10, 15, tzinfo=timezone.utc)
    assert handler._stop_time({"StateTransitionReason": "User initiated (2026-11-20 10:15:00 UTC)"}) == when
    assert handler._stop_time({"StateTransitionReason": "Server.SpotInstanceTermination"}) is None
    assert handler._stop_time({}) is None


def test_eip_with_unparseable_stop_time_skipped(aws, monkeypatch, capsys):
    aid = _eip_on_stopped(aws)
    real = handler._all_instances

    def no_reason(ec2):
        return [dict(i, StateTransitionReason="") for i in real(ec2)]

    monkeypatch.setattr(handler, "_all_instances", no_reason)
    handler.scan_region(REGION, now=later(hours=48))
    assert get(aws, aid, "EIP_ON_STOPPED_INSTANCE") is None
    assert any(e["result"] == "skipped: stop time unknown" for e in logs(capsys))


def test_missing_tags(aws):
    iid = launch(aws, {"owner": "c@example.com"}, volume_tags={"owner": "c@example.com", "project": "x"})
    vol = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    alloc = aws["ec2"].allocate_address(Domain="vpc")["AllocationId"]
    handler.scan_region(REGION, now=later())

    assert get(aws, iid, "MISSING_TAGS")["missingTags"] == ["project"]
    assert get(aws, iid, "MISSING_TAGS")["resourceType"] == "ec2"
    vol_item = get(aws, vol, "MISSING_TAGS")
    assert vol_item["missingTags"] == ["owner", "project"]
    assert vol_item["ownerSource"] == "unknown" and "owner" not in vol_item
    assert get(aws, alloc, "MISSING_TAGS")["resourceType"] == "eip"
    assert get(aws, root_volume(aws, iid), "MISSING_TAGS") is None  # fully tagged
    assert "estimatedMonthlyCost" not in vol_item and "estimatedSnapshotMonthlyCost" not in vol_item


# ---------------------------------------------------------------- dev scope, report-only


def test_dev_scope_filter(aws, monkeypatch, capsys):
    monkeypatch.setenv("DEV_SCOPE", SCOPE)
    mine = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8, TagSpecifications=[
        {"ResourceType": "volume", "Tags": tag_list({"guardian:dev-scope": SCOPE})}])["VolumeId"]
    aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8, TagSpecifications=[
        {"ResourceType": "volume", "Tags": tag_list({"guardian:dev-scope": "cg-other-"})}])
    aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8)
    launch(aws, OWNED)  # instance + root volume, not in scope
    aws["ec2"].allocate_address(Domain="vpc")

    summary = handler.scan_region(REGION, now=later())
    assert {k[0] for k in all_findings(aws)} == {mine}
    assert summary["skippedOutOfScope"] == 5  # 2 volumes + instance + its root volume + EIP
    assert any(e["action"] == "dev_scope_filter" and e["skipped"] == 5 for e in logs(capsys))


def test_empty_dev_scope_scans_everything(aws):
    aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8, TagSpecifications=[
        {"ResourceType": "volume", "Tags": tag_list({"guardian:dev-scope": "cg-other-"})}])
    summary = handler.scan_region(REGION, now=later())
    assert summary["skippedOutOfScope"] == 0
    assert summary["findings"]["EBS_UNATTACHED"] == 1


def test_protected_is_report_only(aws, monkeypatch):
    monkeypatch.setenv("EBS_SFN_ARN", "arn:aws:states:us-west-2:123456789012:stateMachine:cg-test-ebs-timeline")
    calls = []
    monkeypatch.setattr(timeline, "start_timeline", lambda *a: calls.append(a))
    vol = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8, TagSpecifications=[
        {"ResourceType": "volume", "Tags": tag_list({"guardian:protect": "true"})}])["VolumeId"]
    handler.scan_region(REGION, now=later())
    item = get(aws, vol, "EBS_UNATTACHED")
    assert item["reportOnlyReason"] == "protected" and item["status"] == "open"
    assert calls == []


def test_report_only_reasons():
    assert handler._report_only_reason({"guardian:protect": "true"}) == "protected"
    assert handler._report_only_reason({"guardian:protect": "TRUE"}) == "protected"
    assert handler._report_only_reason({"aws:autoscaling:groupName": "web-asg"}) == "autoscaling"
    assert handler._report_only_reason({"guardian:protect": "true", "aws:autoscaling:groupName": "a"}) == "protected"
    assert handler._report_only_reason({"guardian:protect": "false"}) is None


def test_autoscaling_instance_is_report_only(aws, monkeypatch):
    # AWS reserves the aws: tag prefix, so the tag is added to the Describe output instead.
    iid = launch(aws, OWNED)
    scan_at = later()
    put_metrics(aws, iid, scan_at)
    real = handler._all_instances

    def with_asg_tag(ec2):
        return [dict(i, Tags=i.get("Tags", []) + [{"Key": "aws:autoscaling:groupName", "Value": "web"}])
                for i in real(ec2)]

    monkeypatch.setattr(handler, "_all_instances", with_asg_tag)
    monkeypatch.setenv("EC2_SFN_ARN", "arn:aws:states:us-west-2:123456789012:stateMachine:cg-test-ec2-timeline")
    calls = []
    monkeypatch.setattr(timeline, "start_timeline", lambda *a: calls.append(a))
    handler.scan_region(REGION, now=scan_at)
    assert get(aws, iid, "EC2_IDLE")["reportOnlyReason"] == "autoscaling"
    assert calls == []


# ---------------------------------------------------------------- existing findings, timelines


def test_existing_in_progress_finding_not_overwritten(aws, monkeypatch):
    monkeypatch.setenv("EBS_SFN_ARN", "arn:aws:states:us-west-2:123456789012:stateMachine:cg-test-ebs-timeline")
    calls = []
    monkeypatch.setattr(timeline, "start_timeline", lambda *a: calls.append(a))
    vol = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8, TagSpecifications=[
        {"ResourceType": "volume", "Tags": tag_list({"owner": "d@example.com", "project": "p"})}])["VolumeId"]
    existing = {
        "resourceId": vol, "findingType": "EBS_UNATTACHED", "status": "in_progress",
        "generation": Decimal(3), "executionName": f"ebs-{vol}-gen3", "executionArn": "arn:x:gen3",
        "timelineStep": "waiting", "postponeCount": Decimal(1), "restartCount": Decimal(1),
        "firstSeenAt": "2026-11-01T00:00:00Z", "lastSeenAt": "2026-11-01T00:00:00Z",
        "estimatedMonthlyCost": Decimal("0.8"),
    }
    aws["table"].put_item(Item=existing)
    scan_at = later()
    summary = handler.scan_region(REGION, now=scan_at)

    item = get(aws, vol, "EBS_UNATTACHED")
    for key in ("status", "generation", "executionName", "executionArn", "timelineStep", "postponeCount",
                "restartCount", "firstSeenAt", "estimatedMonthlyCost"):
        assert item[key] == existing[key], key
    assert item["lastSeenAt"] == scan_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert item["owner"] == "d@example.com"
    assert "reportOnlyReason" not in item
    assert summary["reportOnly"] == {}
    assert calls == []


SFN_EBS = "arn:aws:states:us-west-2:123456789012:stateMachine:cg-test-ebs-timeline"


def _protected_volume(aws, status, **extra):
    vol = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8, TagSpecifications=[
        {"ResourceType": "volume", "Tags": tag_list({"guardian:protect": "true"})}])["VolumeId"]
    aws["table"].put_item(Item=dict({"resourceId": vol, "findingType": "EBS_UNATTACHED", "status": status,
                                     "generation": Decimal(2), "executionName": f"ebs-{vol}-gen2",
                                     "executionArn": "arn:x:gen2"}, **extra))
    return vol


@pytest.mark.parametrize("status", ["in_progress", "failed"])
def test_protect_tag_on_running_or_failed_timeline_stops_it(aws, monkeypatch, status):
    monkeypatch.setenv("EBS_SFN_ARN", SFN_EBS)
    stops, starts = [], []

    def fake_stop(rid, ftype, new_status, report_only_reason=None):
        stops.append((rid, ftype, new_status, report_only_reason))
        return dict(get(aws, rid, ftype), status="open", reportOnlyReason=report_only_reason)

    monkeypatch.setattr(timeline, "stop_timeline", fake_stop)
    monkeypatch.setattr(timeline, "start_timeline", lambda *a: starts.append(a))
    vol = _protected_volume(aws, status)
    summary = handler.scan_region(REGION, now=later())
    assert stops == [(vol, "EBS_UNATTACHED", "open", "protected")]
    assert starts == []  # report-only now: no new timeline
    assert summary["reportOnly"] == {"stopped_timeline": 1}


def test_protect_tag_with_real_stop_timeline(aws, monkeypatch):
    # End to end with common/timeline.py and moto Step Functions.
    sfn = boto3.client("stepfunctions", region_name=REGION)
    sm = sfn.create_state_machine(name="cg-test-ebs-timeline", roleArn="arn:aws:iam::123456789012:role/r",
                                  definition=json.dumps({"StartAt": "W", "States": {
                                      "W": {"Type": "Wait", "Seconds": 1, "End": True}}}))["stateMachineArn"]
    monkeypatch.setenv("EBS_SFN_ARN", sm)
    vol = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    handler.scan_region(REGION, now=later(1))  # starts gen1 for real
    started = get(aws, vol, "EBS_UNATTACHED")
    assert started["status"] == "in_progress"

    aws["ec2"].create_tags(Resources=[vol], Tags=[{"Key": "guardian:protect", "Value": "true"}])
    summary = handler.scan_region(REGION, now=later(2))
    item = get(aws, vol, "EBS_UNATTACHED")
    assert item["status"] == "open" and item["reportOnlyReason"] == "protected"
    assert item["timelineStep"] == "done"
    assert sfn.describe_execution(executionArn=started["executionArn"])["status"] == "ABORTED"
    assert summary["reportOnly"] == {"stopped_timeline": 1}
    assert summary["timelines"] == {}


def test_protect_tag_on_remediated_finding_unchanged(aws, monkeypatch):
    monkeypatch.setenv("EBS_SFN_ARN", SFN_EBS)
    stops = []
    monkeypatch.setattr(timeline, "stop_timeline", lambda *a, **k: stops.append(a))
    vol = _protected_volume(aws, "remediated")
    summary = handler.scan_region(REGION, now=later())
    item = get(aws, vol, "EBS_UNATTACHED")
    assert item["status"] == "remediated" and "reportOnlyReason" not in item
    assert stops == []
    assert summary["reportOnly"] == {"unchanged": 1}


def test_protect_tag_removed_clears_report_only_and_starts_timeline(aws, monkeypatch):
    monkeypatch.setenv("EBS_SFN_ARN", SFN_EBS)
    starts = []
    monkeypatch.setattr(timeline, "start_timeline",
                        lambda *a: starts.append(a) or {"result": "started", "finding": {}})
    vol = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]  # no protect tag
    aws["table"].put_item(Item={"resourceId": vol, "findingType": "EBS_UNATTACHED", "status": "open",
                                "reportOnlyReason": "protected"})
    summary = handler.scan_region(REGION, now=later())
    assert "reportOnlyReason" not in get(aws, vol, "EBS_UNATTACHED")
    assert starts == [(vol, "EBS_UNATTACHED", "new")]  # same scan
    assert summary["reportOnly"] == {"cleared": 1}
    assert summary["timelines"] == {"started": 1}


def test_report_only_kept_while_tag_present(aws, monkeypatch):
    monkeypatch.setenv("EBS_SFN_ARN", SFN_EBS)
    starts = []
    monkeypatch.setattr(timeline, "start_timeline", lambda *a: starts.append(a))
    vol = _protected_volume(aws, "open", reportOnlyReason="protected")
    summary = handler.scan_region(REGION, now=later())
    assert get(aws, vol, "EBS_UNATTACHED")["reportOnlyReason"] == "protected"
    assert starts == [] and summary["reportOnly"] == {}


@pytest.mark.parametrize("status", ["remediated", "failed", "resolved"])
def test_other_existing_statuses_kept(aws, status):
    vol = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    aws["table"].put_item(Item={"resourceId": vol, "findingType": "EBS_UNATTACHED", "status": status,
                                "generation": Decimal(2)})
    handler.scan_region(REGION, now=later())
    assert get(aws, vol, "EBS_UNATTACHED")["status"] == status
    assert get(aws, vol, "EBS_UNATTACHED")["generation"] == 2


def test_timeline_skipped_when_arn_empty(aws, monkeypatch, capsys):
    monkeypatch.setenv("EBS_SFN_ARN", "")
    calls = []
    monkeypatch.setattr(timeline, "start_timeline", lambda *a: calls.append(a))
    vol = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    summary = handler.scan_region(REGION, now=later())
    assert calls == []
    assert summary["timelines"] == {"skipped_no_state_machine": 1}
    assert any(e["resourceId"] == vol and e["result"] == "timeline skipped: no state machine"
               for e in logs(capsys))


def test_timeline_results_counted_when_arn_set(aws, monkeypatch):
    monkeypatch.setenv("EC2_SFN_ARN", "arn:aws:states:us-west-2:123456789012:stateMachine:cg-test-ec2-timeline")
    monkeypatch.setenv("EBS_SFN_ARN", "arn:aws:states:us-west-2:123456789012:stateMachine:cg-test-ebs-timeline")
    results = iter(["started", "lost_race", "already_running"])
    calls = []

    def fake_start(rid, ftype, reason):
        calls.append((rid, ftype, reason))
        return {"result": next(results), "finding": {}}

    monkeypatch.setattr(timeline, "start_timeline", fake_start)
    iid = launch(aws, OWNED)
    scan_at = later()
    put_metrics(aws, iid, scan_at)
    v1 = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    v2 = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    summary = handler.scan_region(REGION, now=scan_at)

    assert sorted(calls) == sorted([(iid, "EC2_IDLE", "new"), (v1, "EBS_UNATTACHED", "new"),
                                    (v2, "EBS_UNATTACHED", "new")])
    assert summary["timelines"] == {"started": 1, "lost_race": 1, "already_running": 1}


def test_timeline_error_is_counted_and_scan_continues(aws, monkeypatch):
    monkeypatch.setenv("EBS_SFN_ARN", "arn:aws:states:us-west-2:123456789012:stateMachine:cg-test-ebs-timeline")

    def boom(*a):
        raise RuntimeError("names taken")

    monkeypatch.setattr(timeline, "start_timeline", boom)
    aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8)
    aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8)
    summary = handler.scan_region(REGION, now=later())
    assert summary["timelines"] == {"error": 2}
    assert summary["findings"]["EBS_UNATTACHED"] == 2


def test_pending_start_is_retried(aws, monkeypatch):
    # design §9.1 step 4: name claimed, StartExecution failed earlier (no executionArn) → next scan retries.
    monkeypatch.setenv("EBS_SFN_ARN", "arn:aws:states:us-west-2:123456789012:stateMachine:cg-test-ebs-timeline")
    calls = []
    monkeypatch.setattr(timeline, "start_timeline",
                        lambda *a: calls.append(a) or {"result": "started", "finding": {}})
    vol = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    aws["table"].put_item(Item={"resourceId": vol, "findingType": "EBS_UNATTACHED", "status": "in_progress",
                                "generation": Decimal(1), "executionName": f"ebs-{vol}-gen1"})
    handler.scan_region(REGION, now=later())
    assert calls == [(vol, "EBS_UNATTACHED", "new")]


def test_second_scan_keeps_first_seen(aws):
    vol = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    first, second = later(1), later(3)
    handler.scan_region(REGION, now=first)
    handler.scan_region(REGION, now=second)
    item = get(aws, vol, "EBS_UNATTACHED")
    assert item["firstSeenAt"] == first.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert item["lastSeenAt"] == second.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- handler


def stub_scan(monkeypatch, fail=()):
    """Replace scan_region: records the regions it is called with; raises for the regions in `fail`."""
    seen = []

    def fake(region, now=None):
        seen.append(region)
        if region in fail:
            raise RuntimeError(f"boom in {region}")
        return {"region": region, "findings": {"EBS_UNATTACHED": 1}, "timelines": {"started": 1},
                "skippedOutOfScope": 2, "reportOnly": {}, "tagCopy": {"copied": 1, "would_copy": 2},
                "attachmentRecords": {"written": 3}}

    monkeypatch.setattr(handler, "scan_region", fake)
    return seen


EVENT = {"source": "schedule", "job": "scan"}


def test_scan_regions_parsing(monkeypatch):
    for raw in ("", "all", " ALL "):
        monkeypatch.setenv("SCAN_REGIONS", raw)
        assert config.scan_regions() == "all"
    monkeypatch.delenv("SCAN_REGIONS")
    assert config.scan_regions() == "all"
    monkeypatch.setenv("SCAN_REGIONS", "eu-west-1, us-east-1,,eu-west-1")
    assert config.scan_regions() == ["eu-west-1", "us-east-1"]


def test_all_uses_describe_regions(aws, monkeypatch):
    seen = stub_scan(monkeypatch)
    monkeypatch.setenv("SCAN_REGIONS", "all")
    expected = sorted(r["RegionName"] for r in aws["ec2"].describe_regions()["Regions"])
    summary = handler.handler(EVENT, None)
    assert len(expected) > 1 and sorted(seen) == expected
    assert summary["regionsScanned"] == expected and summary["regionsFailed"] == {}
    assert summary["regionDiscovery"] == {"mode": "all"}


def test_list_mode_uses_exactly_the_listed_regions(aws, monkeypatch):
    seen = stub_scan(monkeypatch)
    monkeypatch.setenv("SCAN_REGIONS", "us-east-1, eu-west-1")
    called = []
    monkeypatch.setattr(handler.clients, "client", lambda *a: called.append(a))  # no DescribeRegions
    summary = handler.handler(EVENT, None)
    assert sorted(seen) == ["eu-west-1", "us-east-1"] and called == []
    assert summary["regionsScanned"] == ["us-east-1", "eu-west-1"]
    assert summary["regionDiscovery"] == {"mode": "list"}


def test_describe_regions_failure_falls_back_to_us_west_2(aws, monkeypatch, capsys):
    seen = stub_scan(monkeypatch)
    monkeypatch.setenv("SCAN_REGIONS", "all")

    class Broken:
        def describe_regions(self):
            raise RuntimeError("AccessDenied")

    monkeypatch.setattr(handler.clients, "client", lambda *a: Broken())
    summary = handler.handler(EVENT, None)
    assert seen == ["us-west-2"] and summary["regionsScanned"] == ["us-west-2"]
    assert summary["regionDiscovery"] == {"mode": "all", "fallback": "us-west-2",
                                          "error": "RuntimeError: AccessDenied"}
    assert any(e["action"] == "describe_regions" and "RuntimeError" in e["error"] for e in logs(capsys))


def test_findings_in_several_regions_have_their_region_and_prices(aws, monkeypatch):
    # us-west-2 and us-east-1 have the same gp2 price; sa-east-1 is dearer, so the region's own price shows.
    regions = ("us-west-2", "us-east-1", "sa-east-1")
    vols = {}
    for region in regions:
        ec2 = boto3.client("ec2", region_name=region)
        vols[region] = ec2.create_volume(AvailabilityZone=f"{region}a", Size=10, VolumeType="gp2")["VolumeId"]
    monkeypatch.setenv("SCAN_REGIONS", ",".join(regions))
    summary = handler.handler(EVENT, None)

    assert summary["regionsScanned"] == list(regions) and summary["regionsFailed"] == {}
    expected = {"us-west-2": Decimal("1.00"), "us-east-1": Decimal("1.00"), "sa-east-1": Decimal("1.90")}
    for region, vid in vols.items():
        item = get(aws, vid, "EBS_UNATTACHED")
        assert item["region"] == region
        assert item["estimatedMonthlyCost"] == expected[region]
        assert get(aws, vid, "MISSING_TAGS")["region"] == region
        assert summary["regions"][region]["status"] == "ok"
        assert summary["regions"][region]["findings"] == {"MISSING_TAGS": 1, "EBS_UNATTACHED": 1}
    assert summary["totals"]["findings"] == {"MISSING_TAGS": 3, "EBS_UNATTACHED": 3}
    # One scan time for every region.
    assert len({get(aws, v, "EBS_UNATTACHED")["lastSeenAt"] for v in vols.values()}) == 1


def test_one_failing_region_does_not_stop_the_others(aws, monkeypatch, capsys):
    seen = stub_scan(monkeypatch, fail={"eu-west-1"})
    monkeypatch.setenv("SCAN_REGIONS", "us-west-2,eu-west-1,us-east-1")
    summary = handler.handler(EVENT, None)

    assert sorted(seen) == ["eu-west-1", "us-east-1", "us-west-2"]
    assert summary["regionsScanned"] == ["us-west-2", "us-east-1"]
    assert summary["regionsFailed"] == {"eu-west-1": "RuntimeError: boom in eu-west-1"}
    assert summary["regions"]["eu-west-1"]["status"] == "error"
    assert summary["regions"]["us-west-2"]["status"] == "ok"
    assert summary["totals"] == {"findings": {"EBS_UNATTACHED": 2}, "timelines": {"started": 2},
                                 "reportOnly": {}, "tagCopy": {"copied": 2, "would_copy": 4},
                                 "attachmentRecords": {"written": 6}, "skippedOutOfScope": 4}
    assert summary["slowestRegion"]["region"] in seen and summary["durationSeconds"] >= 0
    entries = logs(capsys)
    assert any(e["action"] == "scan_region" and e["region"] == "eu-west-1" and e["errorType"] == "RuntimeError"
               and e["message"] == "boom in eu-west-1" for e in entries)
    assert any(e["action"] == "scan" and e["result"] == "done" for e in entries)


def test_every_region_failing_raises(aws, monkeypatch, capsys):
    stub_scan(monkeypatch, fail={"us-west-2", "us-east-1"})
    monkeypatch.setenv("SCAN_REGIONS", "us-west-2,us-east-1")
    with pytest.raises(RuntimeError, match="every region"):
        handler.handler(EVENT, None)
    summary = [e for e in logs(capsys) if e["action"] == "scan"][-1]
    assert summary["result"] == "failed" and set(summary["regionsFailed"]) == {"us-west-2", "us-east-1"}


@pytest.mark.parametrize("env, regions, expected", [
    (None, 17, 8), (None, 3, 3), ("2", 17, 2), ("0", 5, 1), ("16", 17, 16)])
def test_max_workers_respects_scan_max_workers(aws, monkeypatch, env, regions, expected):
    if env is None:
        monkeypatch.delenv("SCAN_MAX_WORKERS", raising=False)
    else:
        monkeypatch.setenv("SCAN_MAX_WORKERS", env)
    monkeypatch.setenv("SCAN_REGIONS", ",".join(f"r-{i}" for i in range(regions)))
    stub_scan(monkeypatch)
    used = []
    real = handler.ThreadPoolExecutor
    monkeypatch.setattr(handler, "ThreadPoolExecutor",
                        lambda max_workers, **k: used.append(max_workers) or real(max_workers, **k))
    summary = handler.handler(EVENT, None)
    assert used == [expected] and summary["maxWorkers"] == expected


def _in_threads(fn, count=2):
    """Call fn twice in each of `count` threads; returns [(first, second), ...] per thread."""
    out = [None] * count

    def run(i):
        out[i] = (fn(), fn())

    threads = [threading.Thread(target=run, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return out


@pytest.mark.parametrize("get_client", [findings.table, timeline._table, timeline._sfn])
def test_client_caches_are_per_thread(aws, get_client):
    (a1, a2), (b1, b2) = _in_threads(get_client)
    assert a1 is a2 and b1 is b2  # cached within a thread
    assert a1 is not b1  # never shared between threads
    main = get_client()
    assert main is get_client() and main is not a1 and main is not b1


def test_reset_clients_forgets_every_thread(aws):
    before = findings.table(), timeline._table()
    findings.reset_clients()
    timeline.reset_clients()
    assert findings.table() is not before[0] and timeline._table() is not before[1]


def test_sessions_are_per_thread_but_share_the_model_loader(aws):
    from scanner import clients
    (a1, a2), (b1, b2) = _in_threads(clients.session)
    assert a1 is a2 and b1 is b2 and a1 is not b1
    loaders = {id(s._session.get_component("data_loader")) for s in (a1, b1, clients.session())}
    assert loaders == {id(clients._loader)}


# ---------------------------------------------------------------- audit (CONTRACT §3.3, #29 follow-up)


def test_new_findings_write_finding_opened(aws):
    vol = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    handler.scan_region(REGION, now=later())
    entries = audit_entries(aws, vol)
    # Same second: the ts suffix is random, so compare sorted.
    assert sorted((e["event"], e["findingType"]) for e in entries) == [
        ("finding_opened", "EBS_UNATTACHED"), ("finding_opened", "MISSING_TAGS")]
    by_type = {e["findingType"]: e for e in entries}
    for entry in by_type.values():
        assert (entry["actor"], entry["region"], entry["result"]) == ("scanner", REGION, "ok")
        assert "generation" not in entry and "dryRun" not in entry
    assert by_type["MISSING_TAGS"]["details"] == {"missingTags": ["owner", "project"]}
    assert by_type["EBS_UNATTACHED"]["details"]["estimatedMonthlyCost"] > 0


def test_later_scans_write_no_finding_opened(aws):
    vol = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    handler.scan_region(REGION, now=later(1))
    handler.scan_region(REGION, now=later(3))
    assert len([e for e in audit_entries(aws, vol) if e["event"] == "finding_opened"]) == 2  # one per type


def test_finding_opened_and_timeline_started(aws, linux, monkeypatch):
    sfn = boto3.client("stepfunctions", region_name=REGION)
    sm = sfn.create_state_machine(name="cg-test-ec2-timeline", roleArn="arn:aws:iam::123456789012:role/r",
                                  definition=json.dumps({"StartAt": "W", "States": {
                                      "W": {"Type": "Wait", "Seconds": 1, "End": True}}}))["stateMachineArn"]
    monkeypatch.setenv("EC2_SFN_ARN", sm)
    iid = launch(aws, OWNED)
    scan_at = later()
    put_metrics(aws, iid, scan_at)
    handler.scan_region(REGION, now=scan_at)
    handler.scan_region(REGION, now=scan_at + timedelta(minutes=30))
    entries = {e["event"]: e for e in audit_entries(aws, iid)}
    assert len(audit_entries(aws, iid)) == 2  # the second scan wrote nothing
    assert entries["finding_opened"]["findingType"] == "EC2_IDLE"
    started = entries["timeline_started"]
    assert started["actor"] == "scanner" and started["generation"] == 1 and started["details"]["reason"] == "new"


# ---------------------------------------------------------------- restarts (#32, CONTRACT §3.2 failed → in_progress)


def _state_machine():
    sfn = boto3.client("stepfunctions", region_name=REGION)
    return sfn, sfn.create_state_machine(
        name="cg-test-ebs-timeline", roleArn="arn:aws:iam::123456789012:role/r",
        definition=json.dumps({"StartAt": "W", "States": {"W": {"Type": "Wait", "Seconds": 1, "End": True}}}),
    )["stateMachineArn"]


def _failed_volume(aws, **extra):
    # Tagged, so the scan opens no MISSING_TAGS finding (and no audit entry) for it.
    vol = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8, TagSpecifications=[
        {"ResourceType": "volume", "Tags": tag_list({"owner": "d@example.com", "project": "p"})}])["VolumeId"]
    aws["table"].put_item(Item=dict({"resourceId": vol, "findingType": "EBS_UNATTACHED", "status": "failed",
                                     "generation": Decimal(2), "executionName": f"ebs-{vol}-gen2",
                                     "executionArn": "arn:x:gen2", "failedStep": "Remediate",
                                     "errorMessage": "boom"}, **extra))
    return vol


@pytest.mark.parametrize("count", [0, 1])
def test_failed_finding_still_seen_is_restarted(aws, monkeypatch, capsys, count):
    sfn, sm = _state_machine()
    monkeypatch.setenv("EBS_SFN_ARN", sm)
    monkeypatch.delenv("MAX_RESTARTS", raising=False)  # default 2
    extra = {"restartCount": Decimal(count)} if count else {}
    vol = _failed_volume(aws, **extra)
    summary = handler.scan_region(REGION, now=later())

    item = get(aws, vol, "EBS_UNATTACHED")
    assert item["status"] == "in_progress"
    assert item["generation"] == 3 and item["executionName"] == f"ebs-{vol}-gen3"
    assert item["restartCount"] == count + 1
    assert "failedStep" not in item and "errorMessage" not in item
    assert sfn.describe_execution(executionArn=item["executionArn"])["status"] == "RUNNING"
    assert summary["timelines"] == {"restart_started": 1}
    started = [e for e in audit_entries(aws, vol) if e["event"] == "timeline_started"]
    assert len(started) == 1 and started[0]["details"]["reason"] == "restart"


@pytest.mark.parametrize("env, count", [(None, 2), ("1", 1), ("0", 0)])
def test_restart_limit_reached_only_logs(aws, monkeypatch, capsys, env, count):
    monkeypatch.setenv("EBS_SFN_ARN", SFN_EBS)
    if env is None:
        monkeypatch.delenv("MAX_RESTARTS", raising=False)
    else:
        monkeypatch.setenv("MAX_RESTARTS", env)
    calls = []
    monkeypatch.setattr(timeline, "start_timeline", lambda *a: calls.append(a))
    monkeypatch.setattr(timeline, "_sfn", lambda: pytest.fail("no StartExecution at the limit"))
    vol = _failed_volume(aws, restartCount=Decimal(count))
    capsys.readouterr()
    summary = handler.scan_region(REGION, now=later())

    assert calls == []
    assert get(aws, vol, "EBS_UNATTACHED")["status"] == "failed"
    assert summary["timelines"] == {"restart_limit": 1}
    line = [e for e in logs(capsys) if e["action"] == "restart_timeline"]
    assert line == [{"resourceId": vol, "findingType": "EBS_UNATTACHED", "action": "restart_timeline",
                     "result": "limit", "restartCount": count}]
    assert audit_entries(aws, vol) == []


def test_report_only_failed_finding_not_restarted(aws, monkeypatch):
    # A failed finding that is already report-only (e.g. stop_timeline could not run earlier) is left alone.
    monkeypatch.setenv("EBS_SFN_ARN", SFN_EBS)
    calls = []
    monkeypatch.setattr(timeline, "start_timeline", lambda *a: calls.append(a))
    monkeypatch.setattr(timeline, "stop_timeline", lambda *a, **k: calls.append(("stop",) + a))
    vol = _failed_volume(aws, reportOnlyReason="protected")
    aws["ec2"].create_tags(Resources=[vol], Tags=[{"Key": "guardian:protect", "Value": "true"}])
    summary = handler.scan_region(REGION, now=later())
    assert calls == []
    assert get(aws, vol, "EBS_UNATTACHED")["status"] == "failed"
    assert summary["timelines"] == {}


def test_restart_value_error_counted_not_raised(aws, monkeypatch, capsys):
    monkeypatch.setenv("EBS_SFN_ARN", SFN_EBS)

    def refuse(rid, ftype, reason):
        assert reason == "restart"
        raise ValueError("reason 'restart' needs status 'failed', not 'open'")

    monkeypatch.setattr(timeline, "start_timeline", refuse)
    vol = _failed_volume(aws)
    summary = handler.scan_region(REGION, now=later())
    assert summary["timelines"] == {"restart_refused": 1}
    assert any(e["resourceId"] == vol and e["action"] == "restart_timeline" and e["result"] == "refused"
               for e in logs(capsys))


def test_restart_other_error_counted_as_error(aws, monkeypatch):
    monkeypatch.setenv("EBS_SFN_ARN", SFN_EBS)

    def boom(*a):
        raise RuntimeError("throttled")

    monkeypatch.setattr(timeline, "start_timeline", boom)
    _failed_volume(aws)
    summary = handler.scan_region(REGION, now=later())
    assert summary["timelines"] == {"error": 1}


def test_failed_finding_not_seen_is_not_restarted(aws, monkeypatch):
    # The volume is attached again (no longer a problem): the scan never records it, so no restart.
    monkeypatch.setenv("EBS_SFN_ARN", SFN_EBS)
    calls = []
    monkeypatch.setattr(timeline, "start_timeline", lambda *a: calls.append(a))
    aws["table"].put_item(Item={"resourceId": "vol-0gone", "findingType": "EBS_UNATTACHED", "status": "failed",
                                "generation": Decimal(1), "executionName": "ebs-vol-0gone-gen1"})
    summary = handler.scan_region(REGION, now=later())
    assert calls == []
    assert get(aws, "vol-0gone", "EBS_UNATTACHED")["status"] == "failed"
    assert summary["timelines"] == {}


def test_restart_counters_in_scan_summary_log(aws, monkeypatch, capsys):
    monkeypatch.setenv("EBS_SFN_ARN", SFN_EBS)
    monkeypatch.setattr(timeline, "start_timeline", lambda *a: {"result": "started", "finding": {}})
    _failed_volume(aws)
    _failed_volume(aws, restartCount=Decimal(2))
    out = handler.handler({}, None)
    assert out["totals"]["timelines"] == {"restart_started": 1, "restart_limit": 1}
    scan_line = [e for e in logs(capsys) if e["action"] == "scan"][-1]
    assert scan_line["totals"]["timelines"] == {"restart_started": 1, "restart_limit": 1}


# ---------------------------------------------------------------- tag copying + volume attachments (#33)


INSTANCE_TAGS = {"owner": "Alice@Example.com", "project": "demo", "Name": "web-1",
                 "guardian:dev-scope": "cg-dev-"}


def tags_of(aws, rid):
    out = aws["ec2"].describe_tags(Filters=[{"Name": "resource-id", "Values": [rid]}])["Tags"]
    return {t["Key"]: t["Value"] for t in out}


def tag_audits(aws, rid):
    return [e for e in audit_entries(aws, rid) if e["event"] == "tags_copied"]


def attachment(aws, vid):
    return aws["attachments"].get_item(Key={"volumeId": vid}).get("Item")


def attached_volume(aws, iid, tags=None):
    spec = {"TagSpecifications": [{"ResourceType": "volume", "Tags": tag_list(tags)}]} if tags else {}
    vol = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8, **spec)["VolumeId"]
    aws["ec2"].attach_volume(VolumeId=vol, InstanceId=iid, Device="/dev/sdf")
    return vol


@pytest.fixture
def real(monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")


def test_attached_volume_copies_owner_and_project(aws, real, capsys):
    iid = launch(aws, INSTANCE_TAGS, volume_tags={"Name": "root"})
    vol = root_volume(aws, iid)
    summary = handler.scan_region(REGION, now=later())

    tags = tags_of(aws, vol)
    assert tags["owner"] == "Alice@Example.com" and tags["project"] == "demo"  # exactly as on the instance
    assert tags["Name"] == "root" and "guardian:dev-scope" not in tags  # never Name or guardian:*
    assert get(aws, vol, "MISSING_TAGS") is None
    (entry,) = tag_audits(aws, vol)
    assert (entry["actor"], entry["region"], entry["result"], entry["dryRun"]) == ("scanner", REGION, "ok", False)
    assert "findingType" not in entry
    assert entry["details"] == {"tags": {"owner": "Alice@Example.com", "project": "demo"}, "fromInstance": iid}
    assert summary["tagCopy"] == {"copied": 1}
    assert any(e["resourceId"] == vol and e["action"] == "copy_tags" and e["result"] == "copied"
               for e in logs(capsys))


def test_only_the_missing_key_is_copied(aws, real):
    iid = launch(aws, INSTANCE_TAGS, volume_tags={"owner": "bob@example.com", "project": "  "})
    vol = root_volume(aws, iid)
    handler.scan_region(REGION, now=later())
    tags = tags_of(aws, vol)
    assert tags["owner"] == "bob@example.com"  # never overwritten
    assert tags["project"] == "demo"  # blank after strip counts as missing
    assert tag_audits(aws, vol)[0]["details"]["tags"] == {"project": "demo"}
    assert get(aws, vol, "MISSING_TAGS") is None


def test_existing_different_owner_never_overwritten(aws, real):
    iid = launch(aws, INSTANCE_TAGS, volume_tags={"owner": "bob@example.com", "project": "other"})
    vol = root_volume(aws, iid)
    summary = handler.scan_region(REGION, now=later())
    assert tags_of(aws, vol) == {"owner": "bob@example.com", "project": "other"}
    assert tag_audits(aws, vol) == [] and summary["tagCopy"] == {}


def test_instance_without_tags_copies_nothing(aws, real, capsys):
    iid = launch(aws)
    vol = root_volume(aws, iid)
    summary = handler.scan_region(REGION, now=later())
    assert tags_of(aws, vol) == {}
    assert get(aws, vol, "MISSING_TAGS")["missingTags"] == ["owner", "project"]
    assert summary["tagCopy"] == {}
    assert not [e for e in logs(capsys) if e["action"] == "copy_tags"]  # nothing to copy: no log line


def test_eip_associated_with_instance_copies(aws, real):
    iid = launch(aws, INSTANCE_TAGS)
    aid = aws["ec2"].allocate_address(Domain="vpc")["AllocationId"]
    aws["ec2"].associate_address(AllocationId=aid, InstanceId=iid)
    summary = handler.scan_region(REGION, now=later())
    assert tags_of(aws, aid) == {"owner": "Alice@Example.com", "project": "demo"}
    assert get(aws, aid, "MISSING_TAGS") is None
    assert tag_audits(aws, aid)[0]["details"]["fromInstance"] == iid
    assert summary["tagCopy"] == {"copied": 1}


def test_eip_without_instance_id_is_skipped(aws, real, capsys):
    # NAT gateway / network interface association: no InstanceId to copy from.
    scan = handler._Scan(REGION, later())
    addr = {"AllocationId": "eipalloc-0nat", "AssociationId": "eipassoc-0nat", "NetworkInterfaceId": "eni-0nat",
            "PublicIp": "198.51.100.7"}
    ec2 = handler.clients.client("ec2", REGION)
    handler._copy_tags(scan, ec2, [], [], [addr], "")
    assert scan.tag_copy == {"skipped": 1}
    (line,) = [e for e in logs(capsys) if e["action"] == "copy_tags"]
    assert line["resourceId"] == "eipalloc-0nat" and line["result"].startswith("skipped")
    assert tag_audits(aws, "eipalloc-0nat") == []


@pytest.mark.parametrize("value", [None, "", "true", "TRUE", "yes"])
def test_dry_run_only_logs(aws, monkeypatch, capsys, value):
    if value is None:
        monkeypatch.delenv("DRY_RUN", raising=False)
    else:
        monkeypatch.setenv("DRY_RUN", value)
    assert config.dry_run() is True
    iid = launch(aws, INSTANCE_TAGS, volume_tags={"Name": "root"})
    vol = root_volume(aws, iid)
    summary = handler.scan_region(REGION, now=later())

    assert tags_of(aws, vol) == {"Name": "root"}  # no CreateTags
    assert tag_audits(aws, vol) == []
    item = get(aws, vol, "MISSING_TAGS")
    assert item["missingTags"] == ["owner", "project"] and item["ownerSource"] == "unknown"
    (line,) = [e for e in logs(capsys) if e["action"] == "copy_tags"]
    assert line == {"resourceId": vol, "findingType": "*", "action": "copy_tags", "result": "dry-run: would copy",
                    "tags": {"owner": "Alice@Example.com", "project": "demo"}, "fromInstance": iid}
    assert summary["tagCopy"] == {"would_copy": 1}


@pytest.mark.parametrize("value", ["false", " False "])
def test_dry_run_false_reader(monkeypatch, value):
    monkeypatch.setenv("DRY_RUN", value)
    assert config.dry_run() is False


def test_out_of_scope_volume_gets_no_copy_and_no_record(aws, real, monkeypatch):
    monkeypatch.setenv("DEV_SCOPE", SCOPE)
    iid = launch(aws, INSTANCE_TAGS, volume_tags={"Name": "not-mine"})  # volume lacks guardian:dev-scope
    vol = root_volume(aws, iid)
    summary = handler.scan_region(REGION, now=later())
    assert tags_of(aws, vol) == {"Name": "not-mine"}
    assert attachment(aws, vol) is None
    assert summary["tagCopy"] == {} and summary["attachmentRecords"] == {}


def test_in_scope_volume_is_copied_and_recorded(aws, real, monkeypatch):
    monkeypatch.setenv("DEV_SCOPE", SCOPE)
    iid = launch(aws, INSTANCE_TAGS, volume_tags={"guardian:dev-scope": SCOPE})
    vol = root_volume(aws, iid)
    summary = handler.scan_region(REGION, now=later())
    assert tags_of(aws, vol)["owner"] == "Alice@Example.com"
    assert attachment(aws, vol)["instanceId"] == iid
    assert summary["tagCopy"] == {"copied": 1} and summary["attachmentRecords"] == {"written": 1}


def test_attachment_records_written_overwritten_and_kept(aws):
    iid = launch(aws, OWNED)
    vol = attached_volume(aws, iid, OWNED)
    loose = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    first = later(1)
    summary = handler.scan_region(REGION, now=first)
    row = attachment(aws, vol)
    assert row == {"volumeId": vol, "instanceId": iid, "region": REGION,
                   "seenAt": first.strftime("%Y-%m-%dT%H:%M:%SZ")}
    assert attachment(aws, root_volume(aws, iid))["instanceId"] == iid
    assert attachment(aws, loose) is None  # never attached: no record
    assert summary["attachmentRecords"] == {"written": 2}

    second = later(2)
    handler.scan_region(REGION, now=second)
    assert attachment(aws, vol)["seenAt"] == second.strftime("%Y-%m-%dT%H:%M:%SZ")  # overwritten

    aws["ec2"].detach_volume(VolumeId=vol, InstanceId=iid, Device="/dev/sdf")
    summary = handler.scan_region(REGION, now=later(3))
    kept = attachment(aws, vol)
    assert kept["instanceId"] == iid and kept["seenAt"] == second.strftime("%Y-%m-%dT%H:%M:%SZ")  # not deleted
    assert summary["attachmentRecords"] == {"written": 1}  # only the root volume now
    assert get(aws, vol, "EBS_UNATTACHED")["status"] == "open"


class _FailingCreateTags:
    def __init__(self, client):
        self._client = client

    def create_tags(self, **kwargs):
        raise RuntimeError("AccessDenied: not allowed")

    def __getattr__(self, name):
        return getattr(self._client, name)


def test_create_tags_failure_is_logged_audited_and_scan_continues(aws, real, monkeypatch, capsys):
    original = handler.clients.client
    monkeypatch.setattr(handler.clients, "client",
                        lambda service, region: _FailingCreateTags(original(service, region))
                        if service == "ec2" else original(service, region))
    iid = launch(aws, INSTANCE_TAGS, volume_tags={"Name": "root"})
    vol = root_volume(aws, iid)
    other = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    summary = handler.scan_region(REGION, now=later())

    assert tags_of(aws, vol) == {"Name": "root"}
    (entry,) = tag_audits(aws, vol)
    assert entry["result"] == "error" and "AccessDenied" in entry["details"]["error"]
    assert get(aws, vol, "MISSING_TAGS")["missingTags"] == ["owner", "project"]  # tags unchanged in memory
    assert get(aws, other, "EBS_UNATTACHED") is not None  # scan went on
    assert summary["tagCopy"] == {"error": 1}
    assert any(e["resourceId"] == vol and e["action"] == "copy_tags" and e["result"] == "error"
               for e in logs(capsys))


def test_put_item_failure_does_not_stop_the_scan(aws, monkeypatch, capsys):
    def boom(*a):
        raise RuntimeError("throttled")

    monkeypatch.setattr(attachments, "put", boom)
    iid = launch(aws, OWNED)
    loose = aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    summary = handler.scan_region(REGION, now=later())
    assert summary["attachmentRecords"] == {"error": 1}
    assert get(aws, loose, "EBS_UNATTACHED") is not None
    assert any(e["action"] == "volume_attachment" and e["result"] == "error"
               and e["resourceId"] == root_volume(aws, iid) for e in logs(capsys))


def test_owner_source_copied_only_in_the_copying_scan(aws, real):
    # The instance has an owner but no project: owner is copied, MISSING_TAGS (project) stays.
    iid = launch(aws, {"owner": "carol@example.com"}, volume_tags={"Name": "root"})
    vol = root_volume(aws, iid)
    handler.scan_region(REGION, now=later(1))
    item = get(aws, vol, "MISSING_TAGS")
    assert item["missingTags"] == ["project"]
    assert (item["owner"], item["ownerSource"]) == ("carol@example.com", "copied")

    handler.scan_region(REGION, now=later(2))
    item = get(aws, vol, "MISSING_TAGS")
    assert (item["owner"], item["ownerSource"]) == ("carol@example.com", "tag")
    assert len(tag_audits(aws, vol)) == 1  # nothing left to copy on the second scan


def test_tag_copy_and_attachment_counters_in_totals(aws, real, capsys):
    iid = launch(aws, INSTANCE_TAGS, volume_tags={"Name": "root"})
    attached_volume(aws, iid, {"owner": "x@example.com", "project": "p"})
    out = handler.handler({}, None)
    assert out["totals"]["tagCopy"] == {"copied": 1}
    assert out["totals"]["attachmentRecords"] == {"written": 2}
    scan_line = [e for e in logs(capsys) if e["action"] == "scan"][-1]
    assert scan_line["totals"]["tagCopy"] == {"copied": 1}
    assert scan_line["regions"][REGION]["attachmentRecords"] == {"written": 2}
