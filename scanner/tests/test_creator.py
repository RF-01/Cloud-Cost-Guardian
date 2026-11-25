"""CloudTrail creator lookup (design §8.6 step 2, CONTRACT §3.5, task #34)."""

from datetime import timedelta

import boto3
import pytest
from botocore.exceptions import ClientError

from scanner import creator, handler
from test_scanner import (  # noqa: F401 - aws / real are fixtures
    REGION, SCOPE, _FailingCreateTags, audit_entries, aws, get, later, launch, logs, real, root_volume, tag_list,
    tags_of,
)

ACCOUNT = "123456789012"  # moto's account
OTHER_INSTANCE = "i-0123456789abcdef0"


def user(name):
    return {"type": "IAMUser", "userName": name, "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}", "accountId": ACCOUNT}


def role(session):
    return {"type": "AssumedRole", "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/Admin/{session}"}


ROOT = {"type": "Root", "arn": f"arn:aws:iam::{ACCOUNT}:root"}
SERVICE = {"type": "AWSService", "invokedBy": "autoscaling.amazonaws.com"}


def iam_user(name, email=None):
    tags = [{"Key": "email", "Value": email}] if email else [{"Key": "team", "Value": "x"}]
    boto3.client("iam", region_name=REGION).create_user(UserName=name, Tags=tags)


def volume(aws, tags=None):
    spec = {"TagSpecifications": [{"ResourceType": "volume", "Tags": tag_list(tags)}]} if tags else {}
    return aws["ec2"].create_volume(AvailabilityZone=f"{REGION}a", Size=8, **spec)["VolumeId"]


def eip(aws, tags=None):
    spec = {"TagSpecifications": [{"ResourceType": "elastic-ip", "Tags": tag_list(tags)}]} if tags else {}
    return aws["ec2"].allocate_address(Domain="vpc", **spec)["AllocationId"]


def record(aws, rid):
    return aws["creator"].get_item(Key={"resourceId": rid}).get("Item")


def owner_audits(aws, rid):
    return [e for e in audit_entries(aws, rid) if e["event"] == "owner_found"]


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- methods


def test_instance_found_via_run_instances_iam_user(aws, real, capsys):
    iid = launch(aws, {"project": "p"})
    iam_user("dana", "Dana@Example.com")
    ct = aws["cloudtrail"]
    ct.add(iid, "RunInstances", user("dana"))
    ct.add(iid, "StopInstances", user("someone-else"))  # newer, other event names are ignored
    scan_at = later()
    summary = handler.scan_region(REGION, now=scan_at)

    assert tags_of(aws, iid)["owner"] == "dana@example.com"  # lowercased (CONTRACT §2)
    assert record(aws, iid) == {"resourceId": iid, "region": REGION, "result": "found", "method": "RunInstances",
                                "email": "dana@example.com", "creatorArn": f"arn:aws:iam::{ACCOUNT}:user/dana",
                                "lookedUpAt": iso(scan_at)}
    (entry,) = owner_audits(aws, iid)
    assert (entry["actor"], entry["region"], entry["result"], entry["dryRun"]) == ("scanner", REGION, "ok", False)
    assert entry["details"] == {"email": "dana@example.com", "method": "RunInstances",
                                "creatorArn": f"arn:aws:iam::{ACCOUNT}:user/dana"}
    assert get(aws, iid, "MISSING_TAGS") is None  # owner set, project present
    assert summary["creatorLookup"] == {"found": 1, "set": 1}
    (line,) = [e for e in logs(capsys) if e["action"] == "set_owner"]
    assert line == {"resourceId": iid, "findingType": "*", "action": "set_owner", "result": "set",
                    "owner": "dana@example.com", "method": "RunInstances"}


def test_eip_found_via_allocate_address(aws, real):
    aid = eip(aws, {"project": "p"})
    iam_user("erin", "erin@example.com")
    aws["cloudtrail"].add(aid, "AllocateAddress", user("erin"))
    handler.scan_region(REGION, now=later())
    assert tags_of(aws, aid)["owner"] == "erin@example.com"
    assert record(aws, aid)["method"] == "AllocateAddress"
    assert get(aws, aid, "EIP_UNASSOCIATED")["ownerSource"] == "cloudtrail"


def test_volume_found_via_create_volume(aws, real):
    vid = volume(aws, {"project": "p"})
    iam_user("finn", "finn@example.com")
    ct = aws["cloudtrail"]
    ct.add(vid, "CreateVolume", user("finn"))
    ct.add(vid, "AttachVolume", user("other"), {"instanceId": OTHER_INSTANCE})
    ct.add(vid, "DetachVolume", user("other"))
    handler.scan_region(REGION, now=later())
    assert record(aws, vid)["method"] == "CreateVolume" and record(aws, vid)["email"] == "finn@example.com"
    assert tags_of(aws, vid)["owner"] == "finn@example.com"
    assert ct.calls == [vid]  # one paged lookup by the volume id, nothing else needed


def test_volume_found_via_last_attached_instance(aws, real):
    vid = volume(aws, {"project": "p"})
    row = {"volumeId": vid, "instanceId": OTHER_INSTANCE, "region": REGION, "seenAt": "2026-11-01T00:00:00Z"}
    aws["attachments"].put_item(Item=row)
    iam_user("gail", "gail@example.com")
    ct = aws["cloudtrail"]
    ct.add(OTHER_INSTANCE, "RunInstances", user("gail"))
    ct.add(vid, "AttachVolume", user("other"), {"instanceId": "i-0fffffffffffffff0"})  # step 2 comes first
    handler.scan_region(REGION, now=later())
    rec = record(aws, vid)
    assert (rec["method"], rec["email"]) == ("last-attached", "gail@example.com")
    assert aws["attachments"].get_item(Key={"volumeId": vid})["Item"] == row  # read-only
    assert ct.calls == [vid, OTHER_INSTANCE]


def test_volume_found_via_attach_event(aws, real):
    vid = volume(aws, {"project": "p"})
    iam_user("hal", "hal@example.com")
    ct = aws["cloudtrail"]
    ct.add(vid, "AttachVolume", user("old"), {"instanceId": "i-0aaaaaaaaaaaaaaa0"})
    ct.add(vid, "AttachVolume", user("other"), {"instanceId": OTHER_INSTANCE})  # newest attach wins
    ct.add(OTHER_INSTANCE, "RunInstances", user("hal"))
    handler.scan_region(REGION, now=later())
    rec = record(aws, vid)
    assert (rec["method"], rec["email"]) == ("Attach", "hal@example.com")


@pytest.mark.parametrize("with_attach", [False, True])
def test_volume_found_via_detach_only(aws, real, with_attach):
    vid = volume(aws, {"project": "p"})
    iam_user("ivy", "ivy@example.com")
    ct = aws["cloudtrail"]
    if with_attach:  # the attach names an instance whose RunInstances is gone (older than 90 days)
        ct.add(vid, "AttachVolume", user("other"), {"instanceId": OTHER_INSTANCE})
    ct.add(vid, "DetachVolume", user("old"))
    ct.add(vid, "DetachVolume", user("ivy"))  # newest detach
    handler.scan_region(REGION, now=later())
    rec = record(aws, vid)
    assert (rec["method"], rec["email"]) == ("Detach", "ivy@example.com")


def test_volume_with_no_event_is_unknown(aws, capsys):
    vid = volume(aws)
    scan_at = later()
    summary = handler.scan_region(REGION, now=scan_at)
    assert record(aws, vid) == {"resourceId": vid, "region": REGION, "result": "unknown", "reason": "no_event",
                                "lookedUpAt": iso(scan_at)}
    assert owner_audits(aws, vid) == []
    assert summary["creatorLookup"] == {"unknown": 1}
    assert get(aws, vid, "MISSING_TAGS")["missingTags"] == ["owner", "project"]
    (line,) = [e for e in logs(capsys) if e["action"] == "creator_lookup"]
    assert line["result"] == "unknown: no_event" and line["resourceId"] == vid


def test_failed_calls_are_ignored(aws):
    vid = volume(aws)
    iam_user("jo", "jo@example.com")
    aws["cloudtrail"].add(vid, "CreateVolume", user("jo"), error_code="Client.UnauthorizedOperation")
    handler.scan_region(REGION, now=later())
    assert record(aws, vid)["reason"] == "no_event"


# ---------------------------------------------------------------- identity -> email


@pytest.mark.parametrize("identity, reason", [
    (ROOT, "root_user"),
    (user("nomail"), "no_email_tag"),
    (user("badmail"), "no_email_tag"),
    (user("deleted"), "no_email_tag"),
    (role("terraform-run"), "role_without_email"),
    (role("a b@example.com"), "role_without_email"),
    (SERVICE, "service"),
    ({"type": "FederatedUser", "arn": f"arn:aws:sts::{ACCOUNT}:federated-user/x@example.com"}, "service"),
])
def test_unknown_reasons(aws, identity, reason):
    iam_user("nomail")
    boto3.client("iam", region_name=REGION).create_user(UserName="badmail", Tags=[{"Key": "email", "Value": "nope"}])
    vid = volume(aws)
    aws["cloudtrail"].add(vid, "CreateVolume", identity)
    handler.scan_region(REGION, now=later())
    rec = record(aws, vid)
    assert (rec["result"], rec["reason"], rec["method"]) == ("unknown", reason, "CreateVolume")
    assert "email" not in rec
    assert rec.get("creatorArn") == identity.get("arn")
    assert owner_audits(aws, vid) == []


def test_role_session_with_email_name(aws):
    vid = volume(aws)
    aws["cloudtrail"].add(vid, "CreateVolume", role("Kim@Example.com"))
    handler.scan_region(REGION, now=later())
    rec = record(aws, vid)
    assert (rec["result"], rec["email"]) == ("found", "kim@example.com")
    assert rec["creatorArn"] == f"arn:aws:sts::{ACCOUNT}:assumed-role/Admin/Kim@Example.com"


def test_iam_user_tags_read_once_per_region_scan(aws, monkeypatch):
    iam_user("lee", "lee@example.com")
    vols = [volume(aws), volume(aws)]
    for vid in vols:
        aws["cloudtrail"].add(vid, "CreateVolume", user("lee"))
    calls = []
    original = creator.Lookup._user_email

    def counting(self, name):
        if name not in self._user_emails:
            calls.append(name)
        return original(self, name)

    monkeypatch.setattr(creator.Lookup, "_user_email", counting)
    summary = handler.scan_region(REGION, now=later())
    assert calls == ["lee"] and summary["creatorLookup"] == {"found": 2, "would_set": 2}


@pytest.mark.parametrize("value, ok", [
    ("a@example.com", True), ("a.b+c@sub.example.org", True), ("a@example", False), ("a@@example.com", False),
    ("@example.com", False), ("a b@example.com", False), ("", False), (None, False), ("a@b.c\n", False)])
def test_looks_like_email(value, ok):
    assert creator.looks_like_email(value) is ok


# ---------------------------------------------------------------- who is looked up


def test_attached_volume_and_instance_eip_not_looked_up(aws):
    iid = launch(aws, {"owner": "m@example.com", "project": "p"}, volume_tags={"Name": "root"})  # dry-run: no copy
    aid = eip(aws)
    aws["ec2"].associate_address(AllocationId=aid, InstanceId=iid)
    summary = handler.scan_region(REGION, now=later())
    assert aws["cloudtrail"].calls == []
    assert record(aws, root_volume(aws, iid)) is None and record(aws, aid) is None
    assert summary["creatorLookup"] == {}


def test_owner_from_tag_copying_not_looked_up(aws, real):
    iid = launch(aws, {"owner": "n@example.com", "project": "p"}, volume_tags={"Name": "root"})
    handler.scan_region(REGION, now=later())
    assert tags_of(aws, root_volume(aws, iid))["owner"] == "n@example.com"
    assert aws["cloudtrail"].calls == []


def test_out_of_scope_not_looked_up(aws, monkeypatch):
    monkeypatch.setenv("DEV_SCOPE", SCOPE)
    volume(aws)  # no scope tag
    mine = volume(aws, {"guardian:dev-scope": SCOPE})
    handler.scan_region(REGION, now=later())
    assert aws["cloudtrail"].calls == [mine]


def test_eip_without_allocation_id_skipped(aws):
    scan = handler._Scan(REGION, later())
    handler._lookup_owners(scan, None, [], [], [{"PublicIp": "198.51.100.9"}], "")
    assert aws["cloudtrail"].calls == [] and scan.creator_lookup == {}


def test_eip_associated_with_network_interface_is_looked_up():
    addr = {"AllocationId": "eipalloc-0nat", "AssociationId": "eipassoc-0nat", "NetworkInterfaceId": "eni-0nat"}
    assert handler._owner_candidates([], [], [addr], "") == [("eip", "eipalloc-0nat", addr)]


# ---------------------------------------------------------------- stored records


def test_cached_found_record_is_used_without_cloudtrail(aws):
    vid = volume(aws)
    aws["creator"].put_item(Item={"resourceId": vid, "region": REGION, "result": "found", "method": "CreateVolume",
                                  "email": "o@example.com", "lookedUpAt": "2026-01-01T00:00:00Z"})
    summary = handler.scan_region(REGION, now=later())
    assert aws["cloudtrail"].calls == []
    assert owner_audits(aws, vid) == []
    assert summary["creatorLookup"] == {"cached": 1, "would_set": 1}


@pytest.mark.parametrize("age_hours, retried", [(23, False), (25, True)])
def test_unknown_record_retried_after_24_hours(aws, age_hours, retried):
    vid = volume(aws)
    scan_at = later()
    old = iso(scan_at - timedelta(hours=age_hours))
    aws["creator"].put_item(Item={"resourceId": vid, "region": REGION, "result": "unknown", "reason": "no_event",
                                  "lookedUpAt": old})
    aws["cloudtrail"].add(vid, "CreateVolume", ROOT)
    summary = handler.scan_region(REGION, now=scan_at)
    rec = record(aws, vid)
    if retried:
        assert aws["cloudtrail"].calls == [vid]
        assert (rec["reason"], rec["lookedUpAt"]) == ("root_user", iso(scan_at))  # overwritten
        assert summary["creatorLookup"] == {"unknown": 1}
    else:
        assert aws["cloudtrail"].calls == []
        assert rec["lookedUpAt"] == old
        assert summary["creatorLookup"] == {"cached": 1}


@pytest.mark.parametrize("code, counter", [("ThrottlingException", "throttled"), ("AccessDeniedException", "error")])
def test_cloudtrail_errors_not_stored(aws, capsys, code, counter):
    vid = volume(aws)
    aws["cloudtrail"].fail = ClientError({"Error": {"Code": code, "Message": "no"}}, "LookupEvents")
    summary = handler.scan_region(REGION, now=later())
    assert record(aws, vid) is None  # the next scan tries again
    assert summary["creatorLookup"] == {counter: 1}
    assert any(e["action"] == "creator_lookup" and e["result"] == counter for e in logs(capsys))

    aws["cloudtrail"].fail = None
    handler.scan_region(REGION, now=later(3))
    assert record(aws, vid)["result"] == "unknown"


def test_first_throttle_stops_lookups_for_the_region(aws, real):
    ct = aws["cloudtrail"]
    first, second, third, cached = (volume(aws) for _ in range(4))
    for vid in (first, second, third):
        ct.add(vid, "CreateVolume", role("yan@example.com"))
    aws["creator"].put_item(Item={"resourceId": cached, "region": REGION, "result": "found", "method": "CreateVolume",
                                  "email": "zoe@example.com", "lookedUpAt": "2026-01-01T00:00:00Z"})
    real_lookup = ct.lookup_events

    def throttle_first(**kwargs):
        if not ct.calls:
            ct.calls.append(kwargs["LookupAttributes"][0]["AttributeValue"])
            raise ClientError({"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}}, "LookupEvents")
        return real_lookup(**kwargs)

    ct.lookup_events = throttle_first
    by_id = {v["VolumeId"]: v for v in aws["ec2"].describe_volumes()["Volumes"]}
    scan = handler._Scan(REGION, later())
    ec2 = handler.clients.client("ec2", REGION)
    handler._lookup_owners(scan, ec2, [], [by_id[v] for v in (first, second, third, cached)], [], "")

    assert scan.creator_lookup == {"throttled": 1, "skipped_throttle": 2, "cached": 1, "set": 1}
    assert ct.calls == [first]  # no LookupEvents after the throttle
    assert all(record(aws, v) is None for v in (first, second, third))  # nothing stored
    assert tags_of(aws, cached)["owner"] == "zoe@example.com"  # the cached found record is still applied


def test_iam_error_not_stored(aws, monkeypatch):
    vid = volume(aws)
    aws["cloudtrail"].add(vid, "CreateVolume", user("pat"))

    def throttled(self, name):
        raise ClientError({"Error": {"Code": "Throttling", "Message": "slow down"}}, "ListUserTags")

    monkeypatch.setattr(creator.Lookup, "_user_email", throttled)
    summary = handler.scan_region(REGION, now=later())
    assert record(aws, vid) is None and summary["creatorLookup"] == {"throttled": 1}


def test_cap_of_20_per_region(aws, capsys):
    vols = [volume(aws) for _ in range(22)]
    summary = handler.scan_region(REGION, now=later())
    assert summary["creatorLookup"] == {"unknown": 20, "skipped_cap": 2}
    assert len(aws["cloudtrail"].calls) == 20
    assert sum(record(aws, v) is not None for v in vols) == 20
    assert aws["sleeps"] == [creator.PAUSE_SECONDS] * 19  # a pause between calls, none before the first

    summary = handler.scan_region(REGION, now=later(3))  # the next scan picks up the rest
    assert summary["creatorLookup"] == {"cached": 20, "unknown": 2}


def test_paging_finds_older_events_and_stops_after_5_pages(aws):
    found, lost = volume(aws), volume(aws)
    ct = aws["cloudtrail"]
    ct.add(found, "CreateVolume", role("q@example.com"))
    ct.add(lost, "CreateVolume", role("r@example.com"))
    for _ in range(120):
        ct.add(found, "CreateTags", user("noise"))  # 3 pages of 50
    for _ in range(creator.MAX_PAGES * creator.PAGE_SIZE):
        ct.add(lost, "CreateTags", user("noise"))  # CreateVolume is on page 6
    handler.scan_region(REGION, now=later())
    assert record(aws, found)["email"] == "q@example.com"
    assert record(aws, lost)["reason"] == "no_event"
    assert ct.calls.count(found) == 3 and ct.calls.count(lost) == creator.MAX_PAGES


# ---------------------------------------------------------------- applying the result


def test_dry_run_logs_only(aws, capsys):
    vid = volume(aws)
    aws["cloudtrail"].add(vid, "CreateVolume", role("sam@example.com"))
    summary = handler.scan_region(REGION, now=later())

    assert tags_of(aws, vid) == {}  # no CreateTags
    item = get(aws, vid, "MISSING_TAGS")
    assert item["missingTags"] == ["owner", "project"] and item["ownerSource"] == "unknown"
    assert record(aws, vid)["result"] == "found"
    (entry,) = owner_audits(aws, vid)
    assert entry["dryRun"] is True and entry["details"]["email"] == "sam@example.com"
    assert summary["creatorLookup"] == {"found": 1, "would_set": 1}
    (line,) = [e for e in logs(capsys) if e["action"] == "set_owner"]
    assert line == {"resourceId": vid, "findingType": "*", "action": "set_owner", "result": "dry-run: would set",
                    "owner": "sam@example.com", "method": "CreateVolume"}

    summary = handler.scan_region(REGION, now=later(3))
    assert summary["creatorLookup"] == {"cached": 1, "would_set": 1}
    assert len(owner_audits(aws, vid)) == 1 and aws["cloudtrail"].calls == [vid]


def test_real_mode_sets_owner_and_owner_source_only_in_that_scan(aws, real):
    vid = volume(aws)  # no project either: MISSING_TAGS stays for project
    aws["cloudtrail"].add(vid, "CreateVolume", role("tess@example.com"))
    handler.scan_region(REGION, now=later(1))
    assert tags_of(aws, vid) == {"owner": "tess@example.com"}
    item = get(aws, vid, "MISSING_TAGS")
    assert item["missingTags"] == ["project"]
    assert (item["owner"], item["ownerSource"]) == ("tess@example.com", "cloudtrail")
    assert get(aws, vid, "EBS_UNATTACHED")["ownerSource"] == "cloudtrail"

    summary = handler.scan_region(REGION, now=later(2))
    assert get(aws, vid, "MISSING_TAGS")["ownerSource"] == "tag"
    assert summary["creatorLookup"] == {}  # has an owner now: not a candidate
    assert aws["cloudtrail"].calls == [vid]


def test_create_tags_failure_retries_from_the_stored_record(aws, real, monkeypatch, capsys):
    vid = volume(aws, {"project": "p"})
    aws["cloudtrail"].add(vid, "CreateVolume", role("uma@example.com"))
    original = handler.clients.client
    monkeypatch.setattr(handler.clients, "client", lambda service, region: _FailingCreateTags(
        original(service, region)) if service == "ec2" else original(service, region))
    summary = handler.scan_region(REGION, now=later(1))

    assert tags_of(aws, vid) == {"project": "p"}
    assert get(aws, vid, "MISSING_TAGS")["missingTags"] == ["owner"]  # in-memory tags unchanged
    assert record(aws, vid)["result"] == "found" and len(owner_audits(aws, vid)) == 1
    assert summary["creatorLookup"] == {"found": 1, "error": 1}
    assert any(e["action"] == "set_owner" and e["result"] == "error" for e in logs(capsys))

    monkeypatch.setattr(handler.clients, "client", original)
    summary = handler.scan_region(REGION, now=later(2))
    assert tags_of(aws, vid)["owner"] == "uma@example.com"
    assert summary["creatorLookup"] == {"cached": 1, "set": 1}
    assert aws["cloudtrail"].calls == [vid]  # no new CloudTrail call
    assert len(owner_audits(aws, vid)) == 1  # not written again
    assert get(aws, vid, "EBS_UNATTACHED")["ownerSource"] == "cloudtrail"


def test_put_record_failure_counts_error_and_sets_nothing(aws, real, monkeypatch):
    vid = volume(aws)
    aws["cloudtrail"].add(vid, "CreateVolume", role("vic@example.com"))

    def boom(item):
        raise RuntimeError("table missing")

    monkeypatch.setattr(creator, "put_record", boom)
    summary = handler.scan_region(REGION, now=later())
    assert summary["creatorLookup"] == {"error": 1}
    assert owner_audits(aws, vid) == [] and tags_of(aws, vid) == {}


def test_one_failing_lookup_does_not_stop_the_scan(aws, monkeypatch, capsys):
    bad, good = volume(aws), volume(aws)
    aws["cloudtrail"].add(good, "CreateVolume", role("wes@example.com"))
    original = creator.Lookup.volume

    def flaky(self, vid):
        if vid == bad:
            raise ValueError("unexpected event shape")
        return original(self, vid)

    monkeypatch.setattr(creator.Lookup, "volume", flaky)
    summary = handler.scan_region(REGION, now=later())
    assert summary["creatorLookup"] == {"error": 1, "found": 1, "would_set": 1}
    assert record(aws, bad) is None and record(aws, good)["result"] == "found"
    assert get(aws, bad, "EBS_UNATTACHED") is not None  # detection rules still ran
    assert any(e["resourceId"] == bad and e["action"] == "creator_lookup" and e["result"] == "error"
               for e in logs(capsys))


def test_counters_in_totals(aws, capsys):
    vid = volume(aws)
    volume(aws)
    aws["cloudtrail"].add(vid, "CreateVolume", role("xia@example.com"))
    out = handler.handler({}, None)
    assert out["totals"]["creatorLookup"] == {"found": 1, "would_set": 1, "unknown": 1}
    scan_line = [e for e in logs(capsys) if e["action"] == "scan"][-1]
    assert scan_line["totals"]["creatorLookup"] == out["totals"]["creatorLookup"]
    assert scan_line["regions"][REGION]["creatorLookup"] == out["totals"]["creatorLookup"]
