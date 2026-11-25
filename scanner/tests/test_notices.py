"""Scanner emails through Notify (design §10.1 / §10.2, CONTRACT §4.1 / §4.2 / §4.8, task #36)."""

import importlib.util
import threading
from decimal import Decimal
from pathlib import Path

import boto3
import pytest

from common import timeline
from scanner import clients, config, findings, handler, notices
from test_creator import ROOT, iam_user, user
from test_scanner import (  # noqa: F401 - aws / real are fixtures
    NOTIFY, OWNED, REGION, SCOPE, _FailingCreateTags, attached_volume, aws, get, later, launch, logs, real,
    root_volume, tag_list,
)

TAGGED = {"owner": "d@example.com", "project": "p"}  # no MISSING_TAGS noise
NO_EVENT_TEXT = "no CloudTrail creation event found (older than 90 days, or not recorded yet)"
EVENT = {"source": "schedule", "job": "scan"}
SFN_EBS = "arn:aws:states:us-west-2:123456789012:stateMachine:cg-test-ebs-timeline"


def eip(aws, tags=TAGGED, ec2=None):
    spec = {"TagSpecifications": [{"ResourceType": "elastic-ip", "Tags": tag_list(tags)}]} if tags else {}
    return (ec2 or aws["ec2"]).allocate_address(Domain="vpc", **spec)["AllocationId"]


def volume(aws, tags=TAGGED, ec2=None, region=REGION):
    spec = {"TagSpecifications": [{"ResourceType": "volume", "Tags": tag_list(tags)}]} if tags else {}
    return (ec2 or aws["ec2"]).create_volume(AvailabilityZone=f"{region}a", Size=8, **spec)["VolumeId"]


def sent(aws, template=None):
    return aws["notify"].events(template)


def ref(rid, ftype, generation=0):
    return {"resourceId": rid, "findingType": ftype, "generation": generation, "actions": []}


def notify_logs(capsys):
    return [e for e in logs(capsys) if e["action"] == "notify"]


def with_volume_tags(monkeypatch, vid, extra):
    """Add tags to one volume in the Describe output (AWS reserves the aws: prefix, so it can't be created)."""
    real_fn = handler._all_volumes
    monkeypatch.setattr(handler, "_all_volumes", lambda ec2: [
        dict(v, Tags=(v.get("Tags") or []) + tag_list(extra)) if v["VolumeId"] == vid else v for v in real_fn(ec2)])


def _load_notify_templates():
    path = Path(__file__).resolve().parents[2] / "platform" / "src" / "notify" / "notify_templates.py"
    spec = importlib.util.spec_from_file_location("notify_templates_for_scanner_tests", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


NOTIFY_TEMPLATES = _load_notify_templates()


def assert_notify_accepts(events):
    """Every captured input passes Notify's own validation and renders (CONTRACT §4.1 / §4.2)."""
    for event in events:
        template, items, vars_ = NOTIFY_TEMPLATES.validate(event)
        subject, html_body, text_body = NOTIFY_TEMPLATES.render(template, vars_, items, {})
        assert subject and html_body and text_body


# ---------------------------------------------------------------- REPORT_NOTICE


def test_new_unassociated_eip_sends_one_report_notice(aws, capsys):
    aid = eip(aws, dict(TAGGED, Name="spare-ip"))
    summary = handler.scan_region(REGION, now=later())

    (call,) = aws["notify"].calls
    assert call["FunctionName"] == NOTIFY and call["InvocationType"] == "RequestResponse"
    assert call["event"] == {
        "template": "REPORT_NOTICE", "to": "d@example.com", "findings": [ref(aid, "EIP_UNASSOCIATED")],
        "vars": {"resourceId": aid, "resourceType": "eip", "region": REGION, "findingType": "EIP_UNASSOCIATED",
                 "estimatedMonthlyCost": 3.65, "reason": "eip_unassociated", "name": "spare-ip"}}
    assert summary["notices"] == {"sent": 1}
    (line,) = notify_logs(capsys)
    assert (line["resourceId"], line["template"], line["result"], line["resourceIds"]) == (
        aid, "REPORT_NOTICE", "sent", [aid])
    assert_notify_accepts(sent(aws))

    summary = handler.scan_region(REGION, now=later(3))  # same episode: nothing more
    assert len(aws["notify"].calls) == 1 and summary["notices"] == {}


def test_eip_on_stopped_instance_report_notice(aws):
    iid = launch(aws, OWNED)
    aid = eip(aws)
    aws["ec2"].associate_address(AllocationId=aid, InstanceId=iid)
    aws["ec2"].stop_instances(InstanceIds=[iid])
    handler.scan_region(REGION, now=later(25))
    (event,) = sent(aws)
    assert event["template"] == "REPORT_NOTICE" and event["findings"] == [ref(aid, "EIP_ON_STOPPED_INSTANCE")]
    assert event["vars"]["reason"] == "eip_on_stopped_instance" and "name" not in event["vars"]
    assert_notify_accepts(sent(aws))


def test_untagged_eip_report_notice_to_team_and_missing_tags_email(aws):
    aid = eip(aws, tags=None)
    summary = handler.scan_region(REGION, now=later())
    (report,) = sent(aws, "REPORT_NOTICE")
    assert report["to"] is None  # owner unknown: the team address
    (missing,) = sent(aws, "MISSING_TAGS")
    assert missing == {"template": "MISSING_TAGS", "to": None, "findings": [ref(aid, "MISSING_TAGS")],
                       "vars": {"resourceId": aid, "resourceType": "eip", "region": REGION,
                                "missingTags": ["owner", "project"], "creatorLookup": NO_EVENT_TEXT}}
    assert summary["notices"] == {"sent": 2}
    assert_notify_accepts(sent(aws))


def test_reopened_eip_finding_sends_again(aws):
    aid = eip(aws)
    aws["table"].put_item(Item={"resourceId": aid, "findingType": "EIP_UNASSOCIATED", "status": "resolved",
                                "region": REGION, "resolvedAt": "2026-11-01T00:00:00Z",
                                "firstSeenAt": "2026-10-01T00:00:00Z"})
    summary = handler.scan_region(REGION, now=later())
    assert get(aws, aid, "EIP_UNASSOCIATED")["status"] == "open"
    (event,) = sent(aws)
    assert event["template"] == "REPORT_NOTICE" and event["vars"]["reason"] == "eip_unassociated"
    assert summary["notices"] == {"sent": 1}


def test_open_eip_finding_from_an_earlier_scan_sends_nothing(aws):
    # Even if that earlier send failed: no retry (CONTRACT §4.8).
    aid = eip(aws)
    aws["table"].put_item(Item={"resourceId": aid, "findingType": "EIP_UNASSOCIATED", "status": "open",
                                "region": REGION, "firstSeenAt": "2026-10-01T00:00:00Z"})
    summary = handler.scan_region(REGION, now=later())
    assert aws["notify"].calls == [] and summary["notices"] == {}


def test_new_autoscaling_volume_report_notice(aws, monkeypatch):
    vid = volume(aws)
    with_volume_tags(monkeypatch, vid, {"aws:autoscaling:groupName": "web-asg"})
    handler.scan_region(REGION, now=later())
    (event,) = sent(aws)
    assert event["findings"] == [ref(vid, "EBS_UNATTACHED")]
    assert event["vars"]["reason"] == "autoscaling" and event["vars"]["autoScalingGroup"] == "web-asg"
    assert event["vars"]["estimatedMonthlyCost"] == 0.8 and event["to"] == "d@example.com"
    assert_notify_accepts(sent(aws))
    handler.scan_region(REGION, now=later(3))
    assert len(aws["notify"].calls) == 1


def test_autoscaling_newly_applied_to_existing_open_finding(aws, monkeypatch):
    vid = volume(aws)
    aws["table"].put_item(Item={"resourceId": vid, "findingType": "EBS_UNATTACHED", "status": "open",
                                "region": REGION, "firstSeenAt": "2026-10-01T00:00:00Z", "generation": Decimal(3),
                                "estimatedMonthlyCost": Decimal("0.80")})
    with_volume_tags(monkeypatch, vid, {"aws:autoscaling:groupName": "web-asg"})
    summary = handler.scan_region(REGION, now=later())
    assert get(aws, vid, "EBS_UNATTACHED")["reportOnlyReason"] == "autoscaling"
    (event,) = sent(aws)
    assert event["findings"] == [ref(vid, "EBS_UNATTACHED", generation=3)]  # Decimal -> int
    assert summary["notices"] == {"sent": 1}
    handler.scan_region(REGION, now=later(3))  # already report-only: nothing more
    assert len(aws["notify"].calls) == 1


def test_autoscaling_newly_applied_to_in_progress_finding(aws, monkeypatch):
    monkeypatch.setenv("EBS_SFN_ARN", SFN_EBS)
    vid = volume(aws)
    aws["table"].put_item(Item={"resourceId": vid, "findingType": "EBS_UNATTACHED", "status": "in_progress",
                                "region": REGION, "firstSeenAt": "2026-10-01T00:00:00Z", "generation": Decimal(2),
                                "executionName": f"ebs-{vid}-gen2", "executionArn": "arn:x"})

    def stop(rid, ftype, new_status, reason=None, **k):
        aws["table"].update_item(Key={"resourceId": rid, "findingType": ftype},
                                 UpdateExpression="SET #s = :s, reportOnlyReason = :r",
                                 ExpressionAttributeNames={"#s": "status"},
                                 ExpressionAttributeValues={":s": new_status, ":r": reason})
        return get(aws, rid, ftype)

    monkeypatch.setattr(timeline, "stop_timeline", stop)
    with_volume_tags(monkeypatch, vid, {"aws:autoscaling:groupName": "web-asg"})
    handler.scan_region(REGION, now=later())
    (event,) = sent(aws)
    assert event["vars"]["reason"] == "autoscaling" and event["findings"][0]["generation"] == 2


def test_protected_finding_sends_no_email(aws, monkeypatch):
    monkeypatch.setattr(timeline, "start_timeline", lambda *a, **k: None)
    vid = volume(aws, dict(TAGGED, **{"guardian:protect": "true"}))
    summary = handler.scan_region(REGION, now=later())
    assert get(aws, vid, "EBS_UNATTACHED")["reportOnlyReason"] == "protected"
    assert aws["notify"].calls == [] and summary["notices"] == {}


def test_protected_unassociated_eip_sends_no_report_notice(aws, capsys):
    aid = eip(aws, dict(TAGGED, **{"guardian:protect": " TRUE "}))  # same rule as EC2 / EBS: stripped, any case
    summary = handler.scan_region(REGION, now=later())
    assert get(aws, aid, "EIP_UNASSOCIATED")["status"] == "open"  # still a finding (digest)
    assert aws["notify"].calls == [] and summary["notices"] == {"suppressed_protected": 1}
    (line,) = notify_logs(capsys)
    assert (line["resourceId"], line["findingType"], line["result"], line["template"]) == (
        aid, "EIP_UNASSOCIATED", "suppressed_protected", "REPORT_NOTICE")
    summary = handler.scan_region(REGION, now=later(3))  # same episode: not counted again
    assert aws["notify"].calls == [] and summary["notices"] == {}


def test_protected_eip_on_stopped_instance_sends_no_report_notice(aws):
    iid = launch(aws, OWNED)
    aid = eip(aws, dict(TAGGED, **{"guardian:protect": "true"}))
    aws["ec2"].associate_address(AllocationId=aid, InstanceId=iid)
    aws["ec2"].stop_instances(InstanceIds=[iid])
    summary = handler.scan_region(REGION, now=later(25))
    assert get(aws, aid, "EIP_ON_STOPPED_INSTANCE")["status"] == "open"
    assert sent(aws, "REPORT_NOTICE") == [] and summary["notices"]["suppressed_protected"] == 1


def test_eip_protect_tag_not_true_still_sends(aws):
    eip(aws, dict(TAGGED, **{"guardian:protect": "false"}))
    summary = handler.scan_region(REGION, now=later())
    assert len(sent(aws, "REPORT_NOTICE")) == 1 and summary["notices"] == {"sent": 1}


def test_normal_timeline_finding_sends_no_report_notice(aws):
    volume(aws)  # the engine workflow sends its FIRST_NOTICE, not the scanner
    handler.scan_region(REGION, now=later())
    assert aws["notify"].calls == []


def test_dry_run_does_not_suppress_emails(aws):
    assert config.dry_run() is True
    eip(aws)
    handler.scan_region(REGION, now=later())
    assert len(sent(aws, "REPORT_NOTICE")) == 1


# ---------------------------------------------------------------- MISSING_TAGS


def test_unattached_untagged_volume_single_missing_tags_email(aws, capsys):
    vid = volume(aws, tags=None)
    summary = handler.scan_region(REGION, now=later())
    (event,) = sent(aws)
    assert event == {"template": "MISSING_TAGS", "to": None, "findings": [ref(vid, "MISSING_TAGS")],
                     "vars": {"resourceId": vid, "resourceType": "ebs", "region": REGION,
                              "missingTags": ["owner", "project"], "creatorLookup": NO_EVENT_TEXT}}
    assert summary["notices"] == {"sent": 1}
    assert_notify_accepts(sent(aws))
    handler.scan_region(REGION, now=later(3))  # once per episode
    assert len(aws["notify"].calls) == 1


def test_missing_project_only_goes_to_the_owner_without_lookup_text(aws):
    vid = volume(aws, {"owner": "Bob@Example.com"})
    handler.scan_region(REGION, now=later())
    (event,) = sent(aws)
    assert event["to"] == "bob@example.com" and event["vars"]["missingTags"] == ["project"]
    assert "creatorLookup" not in event["vars"]  # owner present: never looked up, no record


def test_unknown_root_user_lookup_text(aws):
    vid = volume(aws, tags=None)
    aws["cloudtrail"].add(vid, "CreateVolume", ROOT)
    handler.scan_region(REGION, now=later())
    (event,) = sent(aws)
    assert event["vars"]["creatorLookup"] == "created by the root user"


def test_creator_lookup_text_mapping():
    assert notices.creator_lookup_text(None) is None
    assert notices.creator_lookup_text({"result": "found", "email": "a@b.co"}) is None
    assert notices.creator_lookup_text({"result": "unknown", "reason": "no_event"}) == NO_EVENT_TEXT
    for reason in ("root_user", "no_email_tag", "role_without_email", "service"):
        assert notices.creator_lookup_text({"result": "unknown", "reason": reason})
    assert notices.creator_lookup_text({"result": "unknown", "reason": "<b>new</b>"}) is None  # never echoed


def test_covered_by_dry_run_tag_copy(aws, capsys):
    iid = launch(aws, {"owner": "c@example.com", "project": "x"}, volume_tags={"Name": "root"})
    vol = root_volume(aws, iid)
    summary = handler.scan_region(REGION, now=later())
    assert get(aws, vol, "MISSING_TAGS") is not None  # dry-run: the tags are not written
    assert aws["notify"].calls == []
    assert summary["notices"] == {"suppressed_covered": 1}
    (line,) = notify_logs(capsys)
    assert line["resourceId"] == vol and line["result"] == "suppressed_covered" and line["instanceId"] == iid


def test_covered_by_real_tag_copy(aws, real):
    iid = launch(aws, {"owner": "c@example.com", "project": "x"}, volume_tags={"Name": "root"})
    summary = handler.scan_region(REGION, now=later())
    assert get(aws, root_volume(aws, iid), "MISSING_TAGS") is None
    assert aws["notify"].calls == [] and summary["notices"] == {}


def test_eip_on_instance_covered_by_copy(aws):
    iid = launch(aws, {"owner": "c@example.com", "project": "x"})
    aid = eip(aws, tags=None)
    aws["ec2"].associate_address(AllocationId=aid, InstanceId=iid)
    summary = handler.scan_region(REGION, now=later())
    assert aws["notify"].calls == [] and summary["notices"] == {"suppressed_covered": 1}


def test_creator_found_fresh_lookup_suppresses(aws):
    iam_user("alice", "alice@example.com")
    vid = volume(aws, {"project": "p"})
    aws["cloudtrail"].add(vid, "CreateVolume", user("alice"))
    summary = handler.scan_region(REGION, now=later())  # dry-run: owner not written, the finding stays
    assert get(aws, vid, "MISSING_TAGS")["missingTags"] == ["owner"]
    assert aws["notify"].calls == [] and summary["notices"] == {"suppressed_creator_found": 1}


def test_creator_found_cached_record_suppresses(aws):
    vid = volume(aws, {"project": "p"})
    aws["creator"].put_item(Item={"resourceId": vid, "region": REGION, "result": "found",
                                  "email": "alice@example.com", "method": "CreateVolume",
                                  "lookedUpAt": "2026-11-01T00:00:00Z"})
    summary = handler.scan_region(REGION, now=later())
    assert aws["cloudtrail"].calls == []
    assert aws["notify"].calls == [] and summary["notices"] == {"suppressed_creator_found": 1}


def test_failed_real_copy_sends_single_email(aws, real, monkeypatch):
    # The instance is fully tagged ("fine"), the copy to its volume fails: a single email, not a grouped one.
    original = clients.client
    monkeypatch.setattr(clients, "client", lambda service, region: _FailingCreateTags(original(service, region))
                        if service == "ec2" else original(service, region))
    iid = launch(aws, {"owner": "c@example.com", "project": "x"}, volume_tags={"Name": "root"})
    vol = root_volume(aws, iid)
    summary = handler.scan_region(REGION, now=later())
    (event,) = sent(aws)
    assert event["template"] == "MISSING_TAGS" and event["findings"] == [ref(vol, "MISSING_TAGS")]
    assert event["to"] is None and "creatorLookup" not in event["vars"]  # attached: never looked up
    assert summary["notices"] == {"sent": 1}


def test_grouped_email_for_untagged_instance_and_its_resources(aws):
    iid = launch(aws)  # instance and root volume untagged
    vol = root_volume(aws, iid)
    aid = eip(aws, tags=None)
    aws["ec2"].associate_address(AllocationId=aid, InstanceId=iid)
    loose = volume(aws, tags=None)  # not attached: its own email
    summary = handler.scan_region(REGION, now=later())

    (grouped,) = sent(aws, "MISSING_TAGS_GROUPED")
    assert grouped["to"] is None
    assert grouped["findings"] == [ref(iid, "MISSING_TAGS"), ref(vol, "MISSING_TAGS"), ref(aid, "MISSING_TAGS")]
    assert grouped["vars"] == {"instanceId": iid, "region": REGION, "resources": [
        {"resourceId": vol, "resourceType": "ebs", "missingTags": ["owner", "project"]},
        {"resourceId": aid, "resourceType": "eip", "missingTags": ["owner", "project"]}]}
    (single,) = sent(aws, "MISSING_TAGS")
    assert single["vars"]["resourceId"] == loose
    assert summary["notices"] == {"sent": 2}
    assert_notify_accepts(sent(aws))


def test_instance_not_new_this_scan_attached_volume_gets_single_email(aws):
    iid = launch(aws)
    handler.scan_region(REGION, now=later(1))
    assert len(sent(aws, "MISSING_TAGS_GROUPED")) == 1
    vol = attached_volume(aws, iid)
    handler.scan_region(REGION, now=later(2))
    (single,) = sent(aws, "MISSING_TAGS")
    assert single["findings"] == [ref(vol, "MISSING_TAGS")] and single["to"] is None
    assert len(aws["notify"].calls) == 2


def test_reopened_missing_tags_sends_again(aws):
    vid = volume(aws, {"owner": "e@example.com"})
    aws["table"].put_item(Item={"resourceId": vid, "findingType": "MISSING_TAGS", "status": "resolved",
                                "region": REGION, "resolvedAt": "2026-11-01T00:00:00Z",
                                "firstSeenAt": "2026-10-01T00:00:00Z"})
    handler.scan_region(REGION, now=later())
    (event,) = sent(aws, "MISSING_TAGS")
    assert event["to"] == "e@example.com" and event["findings"] == [ref(vid, "MISSING_TAGS")]


# ---------------------------------------------------------------- dev scope


def test_out_of_scope_resources_never_trigger_notify(aws, monkeypatch):
    monkeypatch.setenv("DEV_SCOPE", SCOPE)
    eip(aws, tags=None)
    volume(aws, tags={"guardian:dev-scope": "cg-other-"})
    launch(aws)
    summary = handler.scan_region(REGION, now=later())
    assert aws["notify"].calls == [] and aws["notify"].regions == []
    assert summary["notices"] == {}


def test_in_scope_resource_is_emailed(aws, monkeypatch):
    monkeypatch.setenv("DEV_SCOPE", SCOPE)
    aid = eip(aws, dict(TAGGED, **{"guardian:dev-scope": SCOPE}))
    handler.scan_region(REGION, now=later())
    (event,) = sent(aws)
    assert event["vars"]["resourceId"] == aid


def test_send_step_drops_queued_out_of_scope_notice(aws, monkeypatch):
    # Defence in depth: even a queued notice is dropped (and counted nowhere) if its resource is out of scope.
    scan = handler._Scan(REGION, later())
    item = {"resourceId": "eipalloc-0x", "findingType": "EIP_UNASSOCIATED"}
    attrs = {"resourceType": "eip", "owner": None}
    scan.report_queue.append(handler._Notice(item, attrs, {"guardian:dev-scope": "cg-other-"}, "eip_unassociated"))
    handler._send_notices(scan, [], SCOPE, notices.Budget(30))
    assert aws["notify"].calls == [] and scan.notices == {}


# ---------------------------------------------------------------- the Notify call


def test_lambda_client_is_built_for_us_west_2_while_scanning_another_region(aws):
    ec2 = boto3.client("ec2", region_name="eu-west-1")
    aid = eip(aws, ec2=ec2)
    handler.scan_region("eu-west-1", now=later())
    assert aws["notify"].regions == ["us-west-2"]
    (event,) = sent(aws)
    assert event["vars"]["region"] == "eu-west-1" and event["vars"]["resourceId"] == aid


def test_notify_client_has_no_automatic_retry(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    clients.reset()
    client = clients.notify_client("us-west-2")
    assert client.meta.region_name == "us-west-2" and client.meta.service_model.service_name == "lambda"
    assert client.meta.config.retries["total_max_attempts"] == 1  # the first try only
    assert client.meta.config.read_timeout == 65 and client.meta.config.connect_timeout == 5
    assert "lambda" in clients.SERVICES  # preloaded before the threads
    clients.reset()


def test_decimal_values_become_plain_json_numbers():
    assert notices.plain({"a": Decimal("3"), "b": [Decimal("0.80"), Decimal("1.5")], "c": None, "d": True}) == {
        "a": 3, "b": [0.8, 1.5], "c": None, "d": True}
    assert isinstance(notices.plain(Decimal("3")), int)
    with pytest.raises(TypeError):
        notices.plain({"x": {1, 2}})
    assert notices.finding_ref({"resourceId": "i-1", "findingType": "EC2_IDLE", "generation": Decimal(4)}) == {
        "resourceId": "i-1", "findingType": "EC2_IDLE", "generation": 4, "actions": []}


@pytest.mark.parametrize("failure", ["function_error", "exception"])
def test_notify_failure_is_counted_and_the_rest_of_the_region_skipped(aws, capsys, failure):
    if failure == "function_error":
        aws["notify"].function_error = "SES quota exceeded"
    else:
        aws["notify"].fail = RuntimeError("Read timeout on endpoint URL")
    for _ in range(3):
        eip(aws)
    aws["table"].put_item(Item={"resourceId": "vol-0gone", "findingType": "EBS_UNATTACHED", "status": "open",
                                "region": REGION, "firstSeenAt": "2026-10-01T00:00:00Z"})
    summary = handler.scan_region(REGION, now=later())

    assert len(aws["notify"].calls) == 1  # one attempt, no retry, nothing more in this region
    assert summary["notices"] == {"error": 1, "skipped_error": 2}
    assert get(aws, "vol-0gone", "EBS_UNATTACHED")["status"] == "resolved"  # the scan went on (resolve pass)
    lines = notify_logs(capsys)
    (error,) = [e for e in lines if e["result"] == "error"]
    assert ("FunctionError" in error["error"]) == (failure == "function_error")
    assert len([e for e in lines if e["result"] == "skipped_error"]) == 2

    aws["notify"].fail = aws["notify"].function_error = None
    summary = handler.scan_region(REGION, now=later(3))  # the failed notices are never resent
    assert len(aws["notify"].calls) == 1 and summary["notices"] == {}


def test_missing_function_name_is_an_error_not_a_crash(aws, monkeypatch):
    monkeypatch.delenv("NOTIFY_FUNCTION_NAME")
    eip(aws)
    summary = handler.scan_region(REGION, now=later())
    assert aws["notify"].calls == [] and summary["notices"] == {"error": 1}


def test_per_region_cap_of_10(aws, capsys):
    for _ in range(12):
        volume(aws, tags=None)
    summary = handler.scan_region(REGION, now=later())
    assert len(aws["notify"].calls) == 10
    assert summary["notices"] == {"sent": 10, "skipped_cap": 2}
    assert len([e for e in notify_logs(capsys) if e["result"] == "skipped_cap"]) == 2


def test_total_cap_of_30_across_regions_and_reset_per_invocation(aws, monkeypatch):
    regions = ("us-west-2", "us-east-1", "eu-west-1", "sa-east-1")
    for region in regions:
        ec2 = boto3.client("ec2", region_name=region)
        for _ in range(10):
            volume(aws, tags=None, ec2=ec2, region=region)
    monkeypatch.setenv("SCAN_REGIONS", ",".join(regions))
    out = handler.handler(EVENT, None)
    assert len(aws["notify"].calls) == 30
    assert out["totals"]["notices"] == {"sent": 30, "skipped_cap": 10}
    assert sum(out["regions"][r]["notices"].get("sent", 0) for r in regions) == 30

    ec2 = boto3.client("ec2", region_name="us-east-1")
    for _ in range(5):
        volume(aws, tags=None, ec2=ec2, region="us-east-1")
    out = handler.handler(EVENT, None)  # a new invocation gets a new budget
    assert out["totals"]["notices"] == {"sent": 5}


def test_budget_is_thread_safe():
    budget = notices.Budget(30)
    taken = []
    threads = [threading.Thread(target=lambda: taken.extend(budget.take() for _ in range(10))) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert taken.count(True) == 30 and taken.count(False) == 50


def test_direct_scan_region_calls_get_a_fresh_budget(aws):
    for _ in range(3):
        eip(aws)
    spent = notices.Budget(30)
    spent.used = 30
    summary = handler.scan_region(REGION, now=later(), budget=spent)
    assert summary["notices"] == {"skipped_cap": 3}
    for _ in range(2):
        eip(aws)
    summary = handler.scan_region(REGION, now=later(2))  # no budget given: a fresh one
    assert summary["notices"] == {"sent": 2}


def test_queued_notices_of_a_failing_region_are_lost(aws, monkeypatch):
    eip(aws)
    real_scan = handler._scan_addresses

    def detect_then_fail(scan, addresses, instances, scope):
        real_scan(scan, addresses, instances, scope)
        raise RuntimeError("DescribeAddresses page 2 failed")

    monkeypatch.setattr(handler, "_scan_addresses", detect_then_fail)
    with pytest.raises(RuntimeError):
        handler.scan_region(REGION, now=later())
    monkeypatch.setattr(handler, "_scan_addresses", real_scan)
    handler.scan_region(REGION, now=later(2))  # the finding exists now: not new, never sent
    assert aws["notify"].calls == []


def test_notice_counters_in_totals_and_scan_log(aws, capsys):
    eip(aws)
    out = handler.handler(EVENT, None)
    assert out["totals"]["notices"] == {"sent": 1}
    scan_line = [e for e in logs(capsys) if e["action"] == "scan"][-1]
    assert scan_line["totals"]["notices"] == {"sent": 1}
    assert scan_line["regions"][REGION]["notices"] == {"sent": 1}


# ---------------------------------------------------------------- active findings log


def test_active_findings_loaded_in_log_and_totals(aws, capsys):
    for rid, status in (("vol-0a", "open"), ("vol-0b", "in_progress"), ("vol-0c", "resolved")):
        aws["table"].put_item(Item={"resourceId": rid, "findingType": "EBS_UNATTACHED", "status": status,
                                    "region": "eu-north-1", "firstSeenAt": "2026-10-01T00:00:00Z"})
    out = handler.handler(EVENT, None)
    assert out["totals"]["activeFindingsLoaded"] == 2
    (line,) = [e for e in logs(capsys) if e["action"] == "list_findings"]
    assert line["active_findings_loaded"] == 2 and line["result"] == "ok"


def test_active_findings_scan_error_marker(aws, monkeypatch, capsys):
    def boom():
        raise RuntimeError("AccessDenied")

    monkeypatch.setattr(findings, "list_active", boom)
    out = handler.handler(EVENT, None)
    assert out["totals"]["activeFindingsLoaded"] == "error"
    line = [e for e in logs(capsys) if e["action"] == "list_findings"][-1]
    assert line["active_findings_loaded"] == "error" and line["result"] == "error"
