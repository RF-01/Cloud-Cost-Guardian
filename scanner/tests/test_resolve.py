"""Resolve / reopen (design §9.7, CONTRACT §3.2, task #35)."""

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import boto3
import pytest
from botocore.exceptions import ClientError

from common import timeline
from scanner import findings, handler
from test_scanner import (  # noqa: F401 - fixtures
    INSTANCE_TAGS, OWNED, REGION, SCOPE, attached_volume, audit_entries, aws, get, later, launch, linux, logs,
    put_metrics, real, root_volume, tag_list,
)

TAGGED = {"owner": "d@example.com", "project": "p"}  # no MISSING_TAGS noise
EVENT = {"source": "schedule", "job": "scan"}


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def put(aws, rid, ftype, status, region=REGION, **extra):
    aws["table"].put_item(Item=dict({"resourceId": rid, "findingType": ftype, "status": status,
                                     "region": region, "firstSeenAt": "2026-11-01T00:00:00Z"}, **extra))


def status(aws, rid, ftype):
    return get(aws, rid, ftype)["status"]


def resolved_audits(aws, rid):
    return [e for e in audit_entries(aws, rid) if e["event"] == "finding_resolved"]


def volume(aws, tags=TAGGED):
    spec = {"TagSpecifications": [{"ResourceType": "volume", "Tags": tag_list(tags)}]} if tags else {}
    return aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8, **spec)["VolumeId"]


def assert_resolved(aws, rid, ftype, reason, previous):
    item = get(aws, rid, ftype)
    assert item["status"] == "resolved" and item.get("resolvedAt")
    (entry,) = resolved_audits(aws, rid)
    assert (entry["actor"], entry["findingType"], entry["region"], entry["result"]) == (
        "scanner", ftype, REGION, "ok")
    assert entry["details"] == {"reason": reason, "previousStatus": previous}
    return item, entry


def state_override(monkeypatch, fn_name, resource_key, resource_id, **changes):
    """Make _all_instances / _all_volumes report a different state for one resource."""
    real_fn = getattr(handler, fn_name)
    monkeypatch.setattr(handler, fn_name, lambda ec2: [dict(r, **changes) if r[resource_key] == resource_id
                                                       else r for r in real_fn(ec2)])


# ---------------------------------------------------------------- EBS_UNATTACHED


@pytest.mark.parametrize("st", ["open", "in_progress", "failed"])
def test_ebs_volume_gone_resolves(aws, capsys, st):
    put(aws, "vol-0gone", "EBS_UNATTACHED", st)
    summary = handler.scan_region(REGION, now=later())
    assert_resolved(aws, "vol-0gone", "EBS_UNATTACHED", "resource_gone", st)
    # via timeline.stop_timeline: it writes timeline_stopped too
    assert [e["event"] for e in audit_entries(aws, "vol-0gone") if e["event"] == "timeline_stopped"] == [
        "timeline_stopped"]
    assert summary["resolution"] == {"resolved": 1}
    (line,) = [e for e in logs(capsys) if e["action"] == "resolve_finding"]
    assert line["result"] == "resolved" and line["reason"] == "resource_gone" and line["previousStatus"] == st


@pytest.mark.parametrize("st", ["open", "failed"])
def test_ebs_volume_attached_resolves(aws, st):
    iid = launch(aws, OWNED)
    vol = attached_volume(aws, iid, TAGGED)
    put(aws, vol, "EBS_UNATTACHED", st)
    handler.scan_region(REGION, now=later())
    assert_resolved(aws, vol, "EBS_UNATTACHED", "attached", st)


def test_ebs_volume_still_available_stays(aws):
    vol = volume(aws)
    put(aws, vol, "EBS_UNATTACHED", "open")
    summary = handler.scan_region(REGION, now=later())
    assert status(aws, vol, "EBS_UNATTACHED") == "open"
    assert resolved_audits(aws, vol) == [] and summary["resolution"] == {}


def test_ebs_volume_in_error_state_is_unknown(aws, monkeypatch):
    vol = volume(aws)
    state_override(monkeypatch, "_all_volumes", "VolumeId", vol, State="error")
    put(aws, vol, "EBS_UNATTACHED", "open")
    summary = handler.scan_region(REGION, now=later())
    assert status(aws, vol, "EBS_UNATTACHED") == "open"
    assert summary["resolution"] == {"unknown": 1}


def test_out_of_scope_existing_resource_is_unknown_missing_is_gone(aws, monkeypatch):
    monkeypatch.setenv("DEV_SCOPE", SCOPE)
    iid = launch(aws, OWNED)
    vol = attached_volume(aws, iid, TAGGED)  # attached, but not in scope now: leave it
    put(aws, vol, "EBS_UNATTACHED", "open")
    put(aws, "vol-0gone", "EBS_UNATTACHED", "open")  # missing: gone regardless of scope
    summary = handler.scan_region(REGION, now=later())
    assert status(aws, vol, "EBS_UNATTACHED") == "open"
    assert status(aws, "vol-0gone", "EBS_UNATTACHED") == "resolved"
    assert summary["resolution"] == {"unknown": 1, "resolved": 1}


def test_remediated_ebs_never_touched(aws, monkeypatch):
    monkeypatch.setattr(timeline, "stop_timeline", lambda *a, **k: pytest.fail("must not stop"))
    put(aws, "vol-0deleted", "EBS_UNATTACHED", "remediated", remediatedAt="2026-11-01T00:00:00Z")
    summary = handler.scan_region(REGION, now=later())
    assert status(aws, "vol-0deleted", "EBS_UNATTACHED") == "remediated"
    assert audit_entries(aws, "vol-0deleted") == [] and summary["resolution"] == {}


# ---------------------------------------------------------------- running timelines


def _sfn(name="cg-test-ebs-timeline"):
    import json
    sfn = boto3.client("stepfunctions", region_name=REGION)
    sm = sfn.create_state_machine(name=name, roleArn="arn:aws:iam::123456789012:role/r",
                                  definition=json.dumps({"StartAt": "W", "States": {
                                      "W": {"Type": "Wait", "Seconds": 1, "End": True}}}))["stateMachineArn"]
    return sfn, sm


@pytest.mark.parametrize("st", ["open", "in_progress"])
def test_running_execution_is_stopped_via_stop_timeline(aws, monkeypatch, st):
    sfn, sm = _sfn()
    monkeypatch.setenv("EBS_SFN_ARN", sm)
    name = "ebs-vol-0gone-gen2"
    arn = sfn.start_execution(stateMachineArn=sm, name=name, input="{}")["executionArn"]
    put(aws, "vol-0gone", "EBS_UNATTACHED", st, generation=Decimal(2), executionName=name, executionArn=arn,
        timelineStep="waiting")
    calls = []
    real_stop = timeline.stop_timeline
    monkeypatch.setattr(timeline, "stop_timeline", lambda *a, **k: calls.append(a) or real_stop(*a, **k))
    handler.scan_region(REGION, now=later())

    assert calls == [("vol-0gone", "EBS_UNATTACHED", "resolved")]
    item, entry = assert_resolved(aws, "vol-0gone", "EBS_UNATTACHED", "resource_gone", st)
    assert item["timelineStep"] == "done" and item["generation"] == 2
    assert entry["generation"] == 2
    assert sfn.describe_execution(executionArn=arn)["status"] == "ABORTED"
    (stopped,) = [e for e in audit_entries(aws, "vol-0gone") if e["event"] == "timeline_stopped"]
    assert stopped["details"]["newStatus"] == "resolved" and stopped["details"]["stopResult"] == "stopped"


def test_workflow_acting_is_left_alone(aws, monkeypatch):
    # The workflow is stopping / deleting right now: it sets remediated itself (never abort it mid-action).
    monkeypatch.setattr(timeline, "stop_timeline", lambda *a, **k: pytest.fail("must not stop"))
    put(aws, "vol-0gone", "EBS_UNATTACHED", "in_progress", timelineStep="acting")
    summary = handler.scan_region(REGION, now=later())
    assert status(aws, "vol-0gone", "EBS_UNATTACHED") == "in_progress"
    assert summary["resolution"] == {"unknown": 1}


# ---------------------------------------------------------------- EC2_IDLE


def test_ec2_missing_or_terminated_resolves(aws):
    iid = launch(aws, OWNED)
    aws["ec2"].terminate_instances(InstanceIds=[iid])
    put(aws, iid, "EC2_IDLE", "in_progress")
    put(aws, "i-0gone", "EC2_IDLE", "open")
    handler.scan_region(REGION, now=later())
    assert_resolved(aws, iid, "EC2_IDLE", "terminated", "in_progress")
    assert_resolved(aws, "i-0gone", "EC2_IDLE", "terminated", "open")


def test_ec2_stopped_resolves(aws):
    iid = launch(aws, OWNED)
    aws["ec2"].stop_instances(InstanceIds=[iid])
    put(aws, iid, "EC2_IDLE", "failed")
    handler.scan_region(REGION, now=later())
    assert_resolved(aws, iid, "EC2_IDLE", "stopped", "failed")


def test_ec2_restarted_inside_window_resolves(aws):
    iid = launch(aws, OWNED)
    put(aws, iid, "EC2_IDLE", "open")
    handler.scan_region(REGION, now=datetime.now(timezone.utc) + timedelta(minutes=5))
    assert_resolved(aws, iid, "EC2_IDLE", "restarted", "open")


@pytest.mark.parametrize("cpu,network", [((50.0,), 1000.0), ((1.0,), 5 * 1024 * 1024), ((1.0,) * 9 + (30.0,), 1000.0)])
def test_ec2_no_longer_idle_resolves(aws, cpu, network):
    # busy, underused, periodic: CPU data present and not idle
    iid = launch(aws, OWNED)
    scan_at = later()
    put_metrics(aws, iid, scan_at, cpu=cpu, network=network)
    put(aws, iid, "EC2_IDLE", "open")
    handler.scan_region(REGION, now=scan_at)
    assert_resolved(aws, iid, "EC2_IDLE", "not_idle", "open")


def test_ec2_still_idle_stays(aws):
    iid = launch(aws, OWNED)
    scan_at = later()
    put_metrics(aws, iid, scan_at)
    put(aws, iid, "EC2_IDLE", "open")
    summary = handler.scan_region(REGION, now=scan_at)
    assert status(aws, iid, "EC2_IDLE") == "open" and summary["resolution"] == {}


def test_ec2_without_cpu_data_is_unknown(aws):
    iid = launch(aws, OWNED)
    put(aws, iid, "EC2_IDLE", "in_progress")
    summary = handler.scan_region(REGION, now=later())  # no metrics at all
    assert status(aws, iid, "EC2_IDLE") == "in_progress"
    assert summary["resolution"] == {"unknown": 1}


def test_ec2_pending_is_unknown(aws, monkeypatch):
    iid = launch(aws, OWNED)
    state_override(monkeypatch, "_all_instances", "InstanceId", iid, State={"Code": 0, "Name": "pending"})
    put(aws, iid, "EC2_IDLE", "open")
    summary = handler.scan_region(REGION, now=later())
    assert status(aws, iid, "EC2_IDLE") == "open"
    assert summary["resolution"] == {"unknown": 1}


# ---------------------------------------------------------------- remediated EC2 (CONTRACT §3.2 (a) / (b))


def _no_stop_timeline(monkeypatch):
    monkeypatch.setattr(timeline, "stop_timeline", lambda *a, **k: pytest.fail("remediated: conditional resolve"))


def test_remediated_ec2_really_restarted_resolves(aws, monkeypatch):
    _no_stop_timeline(monkeypatch)
    iid = launch(aws, OWNED)  # LaunchTime = now, after remediatedAt
    put(aws, iid, "EC2_IDLE", "remediated", remediatedAt="2020-01-01T00:00:00Z", generation=Decimal(1),
        dryRun=False)
    handler.scan_region(REGION, now=later())
    _, entry = assert_resolved(aws, iid, "EC2_IDLE", "restarted", "remediated")
    assert entry["generation"] == 1


@pytest.mark.parametrize("remediated_at", ["2020-01-01T00:00:00Z", None])
def test_remediated_ec2_terminated_or_missing_resolves(aws, monkeypatch, remediated_at):
    _no_stop_timeline(monkeypatch)
    extra = {"remediatedAt": remediated_at} if remediated_at else {}
    iid = launch(aws, OWNED)
    aws["ec2"].terminate_instances(InstanceIds=[iid])
    put(aws, iid, "EC2_IDLE", "remediated", **extra)
    put(aws, "i-0gone", "EC2_IDLE", "remediated", **extra)
    handler.scan_region(REGION, now=later())
    assert_resolved(aws, iid, "EC2_IDLE", "terminated", "remediated")
    assert_resolved(aws, "i-0gone", "EC2_IDLE", "terminated", "remediated")


def test_remediated_ec2_without_remediated_at_only_rule_b(aws, monkeypatch):
    _no_stop_timeline(monkeypatch)
    iid = launch(aws, OWNED)  # running, new LaunchTime: rule (a) can't apply without remediatedAt
    put(aws, iid, "EC2_IDLE", "remediated")
    summary = handler.scan_region(REGION, now=later())
    assert status(aws, iid, "EC2_IDLE") == "remediated" and summary["resolution"] == {}


def test_dry_run_remediated_ec2_stays_remediated_across_scans(aws, monkeypatch):
    # A dry-run "stop" leaves LaunchTime older than remediatedAt: no resolve, no reopen, no new timeline.
    sfn, sm = _sfn("cg-test-ec2-timeline")
    monkeypatch.setenv("EC2_SFN_ARN", sm)
    _no_stop_timeline(monkeypatch)
    monkeypatch.setattr(timeline, "start_timeline", lambda *a, **k: pytest.fail("no new timeline"))
    iid = launch(aws, OWNED)
    remediated_at = iso(datetime.now(timezone.utc) + timedelta(minutes=30))
    put(aws, iid, "EC2_IDLE", "remediated", remediatedAt=remediated_at, dryRun=True, generation=Decimal(1))
    for hours in (2, 3, 4):
        scan_at = later(hours)
        if hours != 3:
            put_metrics(aws, iid, scan_at)  # idle (recorded) on two scans, no CPU data on one
        summary = handler.scan_region(REGION, now=scan_at)
        item = get(aws, iid, "EC2_IDLE")
        assert item["status"] == "remediated" and item["remediatedAt"] == remediated_at
        assert summary["resolution"] == {}
    assert [e for e in audit_entries(aws, iid) if e["event"] in ("finding_resolved", "finding_reopened")] == []


# ---------------------------------------------------------------- Elastic IPs


def address(aws, tags=TAGGED):
    return aws["ec2"].allocate_address(Domain="vpc", TagSpecifications=[
        {"ResourceType": "elastic-ip", "Tags": tag_list(tags)}])["AllocationId"]


def test_eip_unassociated_gone_and_associated_resolve(aws):
    put(aws, "eipalloc-0gone", "EIP_UNASSOCIATED", "open")
    iid = launch(aws, OWNED)
    aid = address(aws)
    aws["ec2"].associate_address(AllocationId=aid, InstanceId=iid)
    put(aws, aid, "EIP_UNASSOCIATED", "open")
    handler.scan_region(REGION, now=later())
    assert_resolved(aws, "eipalloc-0gone", "EIP_UNASSOCIATED", "resource_gone", "open")
    assert_resolved(aws, aid, "EIP_UNASSOCIATED", "associated", "open")


def test_eip_unassociated_still_stays(aws):
    aid = address(aws)
    put(aws, aid, "EIP_UNASSOCIATED", "open")
    handler.scan_region(REGION, now=later())
    assert status(aws, aid, "EIP_UNASSOCIATED") == "open"


def test_eip_matched_by_public_ip_like_the_finding_key():
    scan = handler._Scan(REGION, later())
    seen = handler._Seen(scan, None, [], [], [{"PublicIp": "198.51.100.7", "AssociationId": "x"}], "")
    assert handler._eip_unassociated_verdict(seen, {"resourceId": "198.51.100.7"}) == ("gone", "associated")
    assert handler._eip_unassociated_verdict(seen, {"resourceId": "198.51.100.8"}) == ("gone", "resource_gone")


def _eip_on_stopped(aws):
    iid = launch(aws, OWNED)
    aid = address(aws)
    assoc = aws["ec2"].associate_address(AllocationId=aid, InstanceId=iid)["AssociationId"]
    aws["ec2"].stop_instances(InstanceIds=[iid])
    put(aws, aid, "EIP_ON_STOPPED_INSTANCE", "open")
    return iid, aid, assoc


def test_eip_on_stopped_still_stopped_stays(aws):
    _, aid, _ = _eip_on_stopped(aws)
    summary = handler.scan_region(REGION, now=later(1))  # under the threshold: not recorded, verdict "still"
    assert status(aws, aid, "EIP_ON_STOPPED_INSTANCE") == "open" and summary["resolution"] == {}


def test_eip_on_stopped_instance_started_resolves(aws):
    iid, aid, _ = _eip_on_stopped(aws)
    aws["ec2"].start_instances(InstanceIds=[iid])
    handler.scan_region(REGION, now=later())
    assert_resolved(aws, aid, "EIP_ON_STOPPED_INSTANCE", "restarted", "open")


def test_eip_on_stopped_disassociated_resolves(aws):
    _, aid, assoc = _eip_on_stopped(aws)
    aws["ec2"].disassociate_address(AssociationId=assoc)
    handler.scan_region(REGION, now=later())
    assert_resolved(aws, aid, "EIP_ON_STOPPED_INSTANCE", "associated", "open")


def test_eip_on_stopped_address_released_resolves(aws):
    _, aid, assoc = _eip_on_stopped(aws)
    aws["ec2"].disassociate_address(AssociationId=assoc)
    aws["ec2"].release_address(AllocationId=aid)
    handler.scan_region(REGION, now=later())
    assert_resolved(aws, aid, "EIP_ON_STOPPED_INSTANCE", "resource_gone", "open")


def test_eip_on_stopped_instance_terminated_resolves(aws, monkeypatch):
    iid, aid, _ = _eip_on_stopped(aws)
    real_fn = handler._all_instances
    monkeypatch.setattr(handler, "_all_instances", lambda ec2: [i for i in real_fn(ec2) if i["InstanceId"] != iid])
    handler.scan_region(REGION, now=later())
    assert_resolved(aws, aid, "EIP_ON_STOPPED_INSTANCE", "terminated", "open")


def test_eip_on_stopped_unknown_stop_time_left(aws, monkeypatch):
    iid, aid, _ = _eip_on_stopped(aws)
    state_override(monkeypatch, "_all_instances", "InstanceId", iid, StateTransitionReason="")
    summary = handler.scan_region(REGION, now=later(48))
    assert status(aws, aid, "EIP_ON_STOPPED_INSTANCE") == "open" and summary["resolution"] == {"unknown": 1}


# ---------------------------------------------------------------- MISSING_TAGS


def test_missing_tags_now_present_resolves(aws):
    vol = volume(aws, tags=None)
    aws["ec2"].create_tags(Resources=[vol], Tags=tag_list(TAGGED))
    put(aws, vol, "MISSING_TAGS", "open", resourceType="ebs", missingTags=["owner", "project"])
    iid = launch(aws, OWNED)
    put(aws, iid, "MISSING_TAGS", "open", resourceType="ec2", missingTags=["project"])
    aid = address(aws)
    put(aws, aid, "MISSING_TAGS", "open", resourceType="eip", missingTags=["owner"])
    handler.scan_region(REGION, now=later())
    for rid in (vol, iid, aid):
        assert_resolved(aws, rid, "MISSING_TAGS", "tags_present", "open")


@pytest.mark.parametrize("rtype,rid", [("ebs", "vol-0gone"), ("ec2", "i-0gone"), ("eip", "eipalloc-0gone")])
def test_missing_tags_resource_gone_resolves(aws, rtype, rid):
    put(aws, rid, "MISSING_TAGS", "open", resourceType=rtype, missingTags=["owner"])
    handler.scan_region(REGION, now=later())
    assert_resolved(aws, rid, "MISSING_TAGS", "resource_gone", "open")


def test_missing_tags_still_missing_stays(aws):
    vol = volume(aws, tags={"owner": "a@example.com", "project": "  "})
    put(aws, vol, "MISSING_TAGS", "open", resourceType="ebs", missingTags=["project"])
    handler.scan_region(REGION, now=later())
    assert status(aws, vol, "MISSING_TAGS") == "open"


def test_missing_tags_resolved_in_same_scan_after_real_copy(aws, real):
    iid = launch(aws, INSTANCE_TAGS, volume_tags={"Name": "root"})
    vol = root_volume(aws, iid)
    put(aws, vol, "MISSING_TAGS", "open", resourceType="ebs", missingTags=["owner", "project"])
    summary = handler.scan_region(REGION, now=later())
    assert summary["tagCopy"] == {"copied": 1}
    assert_resolved(aws, vol, "MISSING_TAGS", "tags_present", "open")


def test_missing_tags_not_resolved_by_dry_run_copy(aws):
    iid = launch(aws, INSTANCE_TAGS, volume_tags={"Name": "root"})
    vol = root_volume(aws, iid)
    put(aws, vol, "MISSING_TAGS", "open", resourceType="ebs", missingTags=["owner", "project"])
    summary = handler.scan_region(REGION, now=later())
    assert summary["tagCopy"] == {"would_copy": 1}
    assert status(aws, vol, "MISSING_TAGS") == "open" and resolved_audits(aws, vol) == []


# ---------------------------------------------------------------- SNAPSHOT_REMINDER


def test_snapshot_gone_resolves_found_stays(aws):
    vol = volume(aws)
    snap = aws["ec2"].create_snapshot(VolumeId=vol)["SnapshotId"]
    put(aws, snap, "SNAPSHOT_REMINDER", "open", resourceType="snapshot")
    put(aws, "snap-0123456789abcdef0", "SNAPSHOT_REMINDER", "open", resourceType="snapshot")
    summary = handler.scan_region(REGION, now=later())
    assert status(aws, snap, "SNAPSHOT_REMINDER") == "open"
    assert_resolved(aws, "snap-0123456789abcdef0", "SNAPSHOT_REMINDER", "snapshot_gone", "open")
    assert summary["resolution"] == {"resolved": 1}


class _DescribeSnapshotsFails:
    def __init__(self, client):
        self._client = client

    def describe_snapshots(self, **kwargs):
        raise ClientError({"Error": {"Code": "UnauthorizedOperation", "Message": "no"}}, "DescribeSnapshots")

    def __getattr__(self, name):
        return getattr(self._client, name)


def test_snapshot_describe_other_error_is_unknown(aws, monkeypatch, capsys):
    original = handler.clients.client
    monkeypatch.setattr(handler.clients, "client", lambda service, region: _DescribeSnapshotsFails(
        original(service, region)) if service == "ec2" else original(service, region))
    put(aws, "snap-0123456789abcdef0", "SNAPSHOT_REMINDER", "open", resourceType="snapshot")
    summary = handler.scan_region(REGION, now=later())
    assert status(aws, "snap-0123456789abcdef0", "SNAPSHOT_REMINDER") == "open"
    assert summary["resolution"] == {"unknown": 1}
    (line,) = [e for e in logs(capsys) if e["action"] == "resolve_finding"]
    assert line["result"] == "unknown" and "UnauthorizedOperation" in line["reason"]


# ---------------------------------------------------------------- races, listing, regions


def test_status_changed_between_scan_and_action_is_skipped(aws, monkeypatch):
    monkeypatch.setattr(timeline, "stop_timeline", lambda *a, **k: pytest.fail("must not stop"))
    put(aws, "vol-0gone", "EBS_UNATTACHED", "remediated")  # the workflow finished after the Scan
    stale = [{"resourceId": "vol-0gone", "findingType": "EBS_UNATTACHED", "status": "in_progress",
              "region": REGION}]
    summary = handler.scan_region(REGION, now=later(), active=stale)
    assert status(aws, "vol-0gone", "EBS_UNATTACHED") == "remediated"
    assert summary["resolution"] == {"skipped": 1}


def test_conditional_resolve_lost_race_is_skipped(aws, monkeypatch):
    put(aws, "eipalloc-0gone", "EIP_UNASSOCIATED", "open")
    monkeypatch.setattr(findings, "resolve", lambda *a: False)
    summary = handler.scan_region(REGION, now=later())
    assert summary["resolution"] == {"skipped": 1} and resolved_audits(aws, "eipalloc-0gone") == []


def test_one_finding_error_is_counted_and_others_continue(aws, monkeypatch, capsys):
    put(aws, "vol-0bad", "EBS_UNATTACHED", "open")
    put(aws, "vol-0gone", "EBS_UNATTACHED", "open")
    real_stop = timeline.stop_timeline

    def stop(rid, *a, **k):
        if rid == "vol-0bad":
            raise RuntimeError("throttled")
        return real_stop(rid, *a, **k)

    monkeypatch.setattr(timeline, "stop_timeline", stop)
    summary = handler.scan_region(REGION, now=later())
    assert summary["resolution"] == {"error": 1, "resolved": 1}
    assert status(aws, "vol-0gone", "EBS_UNATTACHED") == "resolved"
    assert status(aws, "vol-0bad", "EBS_UNATTACHED") == "open"
    assert any(e["resourceId"] == "vol-0bad" and e["result"] == "error" for e in logs(capsys))


def test_scan_region_without_active_loads_its_own_region(aws, capsys):
    put(aws, "vol-0here", "EBS_UNATTACHED", "open")
    put(aws, "vol-0there", "EBS_UNATTACHED", "open", region="eu-west-1")
    aws["table"].put_item(Item={"resourceId": "vol-0noregion", "findingType": "EBS_UNATTACHED", "status": "open"})
    put(aws, "vol-0done", "EBS_UNATTACHED", "resolved")
    handler.scan_region(REGION, now=later())
    assert status(aws, "vol-0here", "EBS_UNATTACHED") == "resolved"
    assert status(aws, "vol-0there", "EBS_UNATTACHED") == "open"
    assert status(aws, "vol-0noregion", "EBS_UNATTACHED") == "open"
    assert resolved_audits(aws, "vol-0done") == []
    assert any(e["resourceId"] == "vol-0noregion" and e["result"] == "skipped: no region" for e in logs(capsys))


def test_list_active_paginates(aws, monkeypatch):
    for i in range(5):
        put(aws, f"vol-0gone{i}", "EBS_UNATTACHED", "open")
    put(aws, "vol-0done", "EBS_UNATTACHED", "resolved")
    calls = []
    table = findings.table()

    class OnePerPage:
        def scan(self, **kwargs):
            calls.append(kwargs.get("ExclusiveStartKey"))
            return table.scan(Limit=1, **kwargs)

        def __getattr__(self, name):
            return getattr(table, name)

    monkeypatch.setattr(findings, "table", lambda: OnePerPage())
    items = findings.list_active()
    assert sorted(i["resourceId"] for i in items) == [f"vol-0gone{i}" for i in range(5)]
    assert len(calls) >= 6 and calls[0] is None and all(calls[1:])
    assert set(items[0]) <= set(findings.ACTIVE_PROJECTION)


def test_failing_region_resolves_nothing(aws, monkeypatch):
    put(aws, "vol-0west", "EBS_UNATTACHED", "open")
    put(aws, "vol-0east", "EBS_UNATTACHED", "open", region="us-east-1")
    real_scan = handler.scan_region

    def scan(region, now=None, active=None, budget=None):
        if region == "us-east-1":
            raise RuntimeError("DescribeVolumes failed")
        return real_scan(region, now=now, active=active, budget=budget)

    monkeypatch.setattr(handler, "scan_region", scan)
    monkeypatch.setenv("SCAN_REGIONS", "us-west-2,us-east-1")
    out = handler.handler(EVENT, None)
    assert out["regionsFailed"] == {"us-east-1": "RuntimeError: DescribeVolumes failed"}
    assert status(aws, "vol-0west", "EBS_UNATTACHED") == "resolved"
    assert status(aws, "vol-0east", "EBS_UNATTACHED") == "open"
    assert out["totals"]["resolution"] == {"resolved": 1}


def test_scan_failure_skips_resolve_but_detection_and_reopen_run(aws, monkeypatch, capsys):
    def boom():
        raise RuntimeError("AccessDenied: dynamodb:Scan")

    monkeypatch.setattr(findings, "list_active", boom)
    put(aws, "vol-0gone", "EBS_UNATTACHED", "open")
    back = volume(aws)
    put(aws, back, "EBS_UNATTACHED", "resolved", resolvedAt="2026-11-01T00:00:00Z")
    new = volume(aws)
    out = handler.handler(EVENT, None)
    assert status(aws, "vol-0gone", "EBS_UNATTACHED") == "open"
    assert status(aws, back, "EBS_UNATTACHED") == "open"  # reopened
    assert status(aws, new, "EBS_UNATTACHED") == "open"  # detected
    assert out["totals"]["resolution"] == {"error": 1, "reopened": 1}
    assert any(e["action"] == "list_findings" and e["result"] == "error" for e in logs(capsys))


def test_resolution_counters_in_totals(aws, monkeypatch, capsys):
    put(aws, "vol-0gone", "EBS_UNATTACHED", "open")
    iid = launch(aws, OWNED)
    # The handler scans at the real time, so a just-launched running instance would be "restarted": pending instead.
    state_override(monkeypatch, "_all_instances", "InstanceId", iid, State={"Code": 0, "Name": "pending"})
    put(aws, iid, "EC2_IDLE", "open")  # pending: unknown
    back = volume(aws)
    put(aws, back, "EBS_UNATTACHED", "resolved")
    out = handler.handler(EVENT, None)
    assert out["totals"]["resolution"] == {"resolved": 1, "unknown": 1, "reopened": 1}
    assert out["regions"][REGION]["resolution"] == {"resolved": 1, "unknown": 1, "reopened": 1}
    scan_line = [e for e in logs(capsys) if e["action"] == "scan"][-1]
    assert scan_line["totals"]["resolution"] == {"resolved": 1, "unknown": 1, "reopened": 1}


# ---------------------------------------------------------------- reopen


SFN_EBS = "arn:aws:states:us-west-2:123456789012:stateMachine:cg-test-ebs-timeline"
OLD_EPISODE = {"resolvedAt": "2026-11-10T00:00:00Z", "remediatedAt": "2026-11-09T00:00:00Z", "dryRun": True,
               "realizedMonthlySavings": Decimal("0.4"), "failedStep": "X", "errorMessage": "e",
               "deadlineAt": "2026-11-12T00:00:00Z"}
KEPT = {"generation": Decimal(2), "executionName": "ebs-x-gen2", "executionArn": "arn:x:gen2",
        "timelineStep": "done", "postponeCount": Decimal(1), "restartCount": Decimal(1),
        "lastNotifiedAt": "2026-11-08T00:00:00Z"}


def test_reopen_resolved_timeline_finding(aws, monkeypatch, capsys):
    monkeypatch.setenv("EBS_SFN_ARN", SFN_EBS)
    starts = []
    monkeypatch.setattr(timeline, "start_timeline",
                        lambda *a, **k: starts.append(a) or {"result": "started", "finding": {}})
    vol = volume(aws)
    put(aws, vol, "EBS_UNATTACHED", "resolved", **OLD_EPISODE, **KEPT)
    scan_at = later()
    summary = handler.scan_region(REGION, now=scan_at)

    item = get(aws, vol, "EBS_UNATTACHED")
    assert item["status"] == "open" and item["firstSeenAt"] == iso(scan_at)
    for key in OLD_EPISODE:
        assert key not in item, key
    for key, value in KEPT.items():
        assert item[key] == value, key  # the scanner never touches generation / counters
    assert starts == [(vol, "EBS_UNATTACHED", "reopen")]
    (entry,) = [e for e in audit_entries(aws, vol) if e["event"] == "finding_reopened"]
    assert (entry["actor"], entry["findingType"], entry["region"], entry["generation"]) == (
        "scanner", "EBS_UNATTACHED", REGION, 2)
    assert entry["details"] == {"previousResolvedAt": "2026-11-10T00:00:00Z"}
    assert summary["resolution"] == {"reopened": 1} and summary["timelines"] == {"started": 1}
    assert any(e["action"] == "reopen_finding" and e["result"] == "reopened" for e in logs(capsys))


def test_reopen_starts_next_generation_for_real(aws, monkeypatch):
    sfn, sm = _sfn()
    monkeypatch.setenv("EBS_SFN_ARN", sm)
    vol = volume(aws)
    put(aws, vol, "EBS_UNATTACHED", "resolved", generation=Decimal(2), executionName=f"ebs-{vol}-gen2",
        resolvedAt="2026-11-10T00:00:00Z")
    handler.scan_region(REGION, now=later())
    item = get(aws, vol, "EBS_UNATTACHED")
    assert item["status"] == "in_progress" and item["generation"] == 3
    assert sfn.describe_execution(executionArn=item["executionArn"])["status"] == "RUNNING"
    (started,) = [e for e in audit_entries(aws, vol) if e["event"] == "timeline_started"]
    assert started["details"]["reason"] == "reopen" and started["generation"] == 3


def test_reopen_then_protect_tag_is_report_only(aws, monkeypatch):
    monkeypatch.setenv("EBS_SFN_ARN", SFN_EBS)
    monkeypatch.setattr(timeline, "start_timeline", lambda *a, **k: pytest.fail("report-only: no timeline"))
    vol = volume(aws, tags=dict(TAGGED, **{"guardian:protect": "true"}))
    put(aws, vol, "EBS_UNATTACHED", "resolved", resolvedAt="2026-11-10T00:00:00Z")
    summary = handler.scan_region(REGION, now=later())
    item = get(aws, vol, "EBS_UNATTACHED")
    assert item["status"] == "open" and item["reportOnlyReason"] == "protected"
    assert summary["reportOnly"] == {"set": 1} and summary["resolution"] == {"reopened": 1}


def test_reopen_eip_and_missing_tags(aws):
    aid = address(aws)
    put(aws, aid, "EIP_UNASSOCIATED", "resolved", resolvedAt="2026-11-10T00:00:00Z")
    vol = volume(aws, tags={"owner": "a@example.com"})
    put(aws, vol, "MISSING_TAGS", "resolved", resourceType="ebs", resolvedAt="2026-11-10T00:00:00Z")
    scan_at = later()
    summary = handler.scan_region(REGION, now=scan_at)
    for rid, ftype in ((aid, "EIP_UNASSOCIATED"), (vol, "MISSING_TAGS")):
        item = get(aws, rid, ftype)
        assert item["status"] == "open" and item["firstSeenAt"] == iso(scan_at) and "resolvedAt" not in item
        assert [e["event"] for e in audit_entries(aws, rid) if e["event"] == "finding_reopened"] == [
            "finding_reopened"]
    assert get(aws, vol, "MISSING_TAGS")["missingTags"] == ["project"]
    assert summary["resolution"] == {"reopened": 2}


def test_reopen_lost_race_is_skipped(aws, monkeypatch):
    monkeypatch.setattr(findings, "reopen", lambda *a: None)
    aid = address(aws)
    put(aws, aid, "EIP_UNASSOCIATED", "resolved")
    summary = handler.scan_region(REGION, now=later())
    assert status(aws, aid, "EIP_UNASSOCIATED") == "resolved"
    assert summary["resolution"] == {"skipped": 1}
    assert [e for e in audit_entries(aws, aid) if e["event"] == "finding_reopened"] == []
