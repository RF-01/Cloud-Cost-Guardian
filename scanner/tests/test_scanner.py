import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import boto3
import pytest
from moto import mock_aws

from common import timeline
from scanner import config, findings, handler, metrics

REGION = "us-west-2"
TABLE = "cg-test-findings"
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
        findings.reset_clients()
        timeline.reset_clients()
        ec2 = boto3.client("ec2", region_name=REGION)
        yield {"table": table, "ec2": ec2, "cw": boto3.client("cloudwatch", region_name=REGION),
               "ami": ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]}
        findings.reset_clients()
        timeline.reset_clients()


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


def get(aws, rid, ftype):
    return aws["table"].get_item(Key={"resourceId": rid, "findingType": ftype}).get("Item")


def all_findings(aws):
    return {(i["resourceId"], i["findingType"]): i for i in aws["table"].scan()["Items"]}


def logs(capsys):
    return [json.loads(line) for line in capsys.readouterr().out.strip().splitlines() if line.startswith("{")]


# ---------------------------------------------------------------- EC2 classification


def test_idle_instance_creates_ec2_idle_finding(aws):
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
    assert "estimatedMonthlyCost" not in item  # pricing stub (#21)
    assert "generation" not in item and "reportOnlyReason" not in item
    assert summary["findings"] == {"EC2_IDLE": 1}
    assert summary["timelines"] == {"skipped_no_state_machine": 1}


@pytest.mark.parametrize("cpu,network,disk,expected", [
    ((1.0,), 1000.0, 10.0, "idle"),
    ((1.0,) * 9 + (30.0,), 1000.0, 10.0, "periodic"),  # avg 3.9 %, max 30 %
    ((1.0,), 5 * 1024 * 1024, 10.0, "underused"),      # 5 MB in 30 min > 1 MB
    ((1.0,), 1000.0, 500.0, "underused"),               # 500 ops in 30 min > 50
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
    assert metrics.classify(dict(base, networkBytes=40 * 1024 * 1024), one_day) == "idle"  # < 48 MB
    assert metrics.classify(dict(base, networkBytes=40 * 1024 * 1024), 30) == "underused"
    assert metrics.classify(dict(base, diskOps=2000), one_day) == "idle"  # < 2400
    assert metrics.classify(dict(base, cpuAvg=None, cpuMax=None), 30) is None


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


def test_unassociated_eip(aws):
    alloc = aws["ec2"].allocate_address(Domain="vpc", TagSpecifications=[
        {"ResourceType": "elastic-ip", "Tags": tag_list({"owner": "a@example.com", "project": "p"})}])
    handler.scan_region(REGION, now=later())
    item = get(aws, alloc["AllocationId"], "EIP_UNASSOCIATED")
    assert item["resourceType"] == "eip" and item["status"] == "open"
    assert "reportOnlyReason" not in item  # EIP findings are report-only by type, no reason needed


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
    assert "estimatedMonthlyCost" not in vol_item


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


def test_handler_scans_first_region_and_returns_summary(aws, monkeypatch):
    seen = []
    monkeypatch.setattr(handler, "scan_region", lambda region: seen.append(region) or {"region": region})
    monkeypatch.setenv("SCAN_REGIONS", "all")
    summary = handler.handler({"source": "schedule", "job": "scan"}, None)
    assert seen == ["us-west-2"] and "durationSeconds" in summary

    monkeypatch.setenv("SCAN_REGIONS", "us-east-1, us-west-2")
    handler.handler({"source": "schedule", "job": "scan"}, None)
    assert seen[-1] == "us-east-1"


def test_scan_regions_parsing(monkeypatch):
    monkeypatch.setenv("SCAN_REGIONS", "")
    assert config.scan_regions() == ["us-west-2"]
    monkeypatch.setenv("SCAN_REGIONS", "eu-west-1,us-east-1")
    assert config.scan_regions() == ["eu-west-1", "us-east-1"]
