"""Action Lambda (engine/src/action, design §10.4, CONTRACT §3.4 / §4.6, task #31). AWS mocked with moto;
the Notify Lambda is a stub (moto's Lambda needs Docker)."""

import base64
import importlib.util
import io
import json
import re
import secrets
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlencode

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from common import timeline

ENGINE = Path(__file__).resolve().parents[1]
ACTION_SRC = ENGINE / "src" / "action"
ACTION_TF = ENGINE / "terraform" / "action.tf"
REGION = "us-west-2"        # where the Guardian runs
RES_REGION = "us-east-1"    # where the resources are (the finding's region)
AZ = "us-east-1a"
SCOPE = "cg-test-"
TABLES = {"TABLE_FINDINGS": "cg-test-findings", "TABLE_AUDIT": "cg-test-audit", "TABLE_TOKENS": "cg-test-tokens"}
DEFINITION = json.dumps({"StartAt": "W", "States": {"W": {"Type": "Wait", "Seconds": 1000, "End": True}}})
ROLE = "arn:aws:iam::123456789012:role/cg-test-sfn"
POSTPONE_SECONDS = 600
WAIT_ACTION_EC2 = 120


def load_handler():
    # Load by path: every Lambda's file is called handler.py. Its sibling module is imported by name.
    if str(ACTION_SRC) not in sys.path:
        sys.path.insert(0, str(ACTION_SRC))
    spec = importlib.util.spec_from_file_location("engine_action_handler", ACTION_SRC / "handler.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


act = load_handler()


class FakeLambda:
    """Stands in for the Notify invoke."""

    def __init__(self, error=None):
        self.calls, self.error = [], error

    def invoke(self, **kwargs):
        self.calls.append({**kwargs, "Payload": json.loads(kwargs["Payload"])})
        if self.error:
            raise self.error
        return {"StatusCode": 200, "Payload": io.BytesIO(b'{"sent": true}')}


def key_table(name, *keys):
    return boto3.resource("dynamodb", region_name=REGION).create_table(
        TableName=name,
        KeySchema=[{"AttributeName": k, "KeyType": t} for k, t in zip(keys, ("HASH", "RANGE"))],
        AttributeDefinitions=[{"AttributeName": k, "AttributeType": "S"} for k in keys],
        BillingMode="PAY_PER_REQUEST",
    )


@pytest.fixture
def aws(monkeypatch):
    for var in ("DEV_SCOPE", "MAX_POSTPONES", "MAX_RESTARTS", "WAIT_BEFORE_FINAL_SECONDS_EC2",
                "WAIT_BEFORE_FINAL_SECONDS_EBS", "WAIT_BEFORE_ACTION_SECONDS_EBS"):
        monkeypatch.delenv(var, raising=False)
    for name, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                        "AWS_DEFAULT_REGION": REGION, "AWS_REGION": REGION, "DRY_RUN": "true",
                        "NAME_PREFIX": "cg-test-", "NOTIFY_FUNCTION_NAME": "cg-test-notify",
                        "POSTPONE_SECONDS": str(POSTPONE_SECONDS),
                        "WAIT_BEFORE_ACTION_SECONDS_EC2": str(WAIT_ACTION_EC2), **TABLES}.items():
        monkeypatch.setenv(name, value)
    with mock_aws():
        findings = key_table(TABLES["TABLE_FINDINGS"], "resourceId", "findingType")
        audit_table = key_table(TABLES["TABLE_AUDIT"], "resourceId", "ts")
        tokens = key_table(TABLES["TABLE_TOKENS"], "tokenHash")
        sfn = boto3.client("stepfunctions", region_name=REGION)
        for kind in ("ec2", "ebs"):
            arn = sfn.create_state_machine(name=f"cg-test-{kind}-timeline", definition=DEFINITION,
                                           roleArn=ROLE)["stateMachineArn"]
            monkeypatch.setenv(f"{kind.upper()}_SFN_ARN", arn)
        act.reset_clients()
        notify = FakeLambda()
        act._clients[("lambda", REGION)] = notify
        ec2 = boto3.client("ec2", region_name=RES_REGION)
        yield {"findings": findings, "audit": audit_table, "tokens": tokens, "sfn": sfn, "ec2": ec2,
               "notify": notify, "ami": ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]}
        act.reset_clients()


# ---------------------------------------------------------------- builders


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def in_hours(hours):
    return iso(datetime.now(timezone.utc) + timedelta(hours=hours))


def tag_list(tags):
    return [{"Key": k, "Value": v} for k, v in tags.items()]


def launch(aws, tags=None):
    tags = {"owner": "owner@example.com", "project": "demo", **(tags or {})}
    return aws["ec2"].run_instances(
        ImageId=aws["ami"], MinCount=1, MaxCount=1, InstanceType="t3.micro",
        TagSpecifications=[{"ResourceType": "instance", "Tags": tag_list(tags)}])["Instances"][0]["InstanceId"]


def volume(aws, tags=None):
    tags = {"owner": "owner@example.com", "project": "demo", **(tags or {})}
    return aws["ec2"].create_volume(AvailabilityZone=AZ, Size=8, VolumeType="gp3",
                                    TagSpecifications=[{"ResourceType": "volume", "Tags": tag_list(tags)}]
                                    )["VolumeId"]


def snapshot(aws, source, tags=None):
    tags = {"owner": "owner@example.com", "project": "demo", "Name": "data",
            "guardian:source-volume": source, **(tags or {})}
    vid = volume(aws)
    return aws["ec2"].create_snapshot(VolumeId=vid, TagSpecifications=[
        {"ResourceType": "snapshot", "Tags": tag_list(tags)}])["SnapshotId"]


def put_finding(aws, rid, ftype="EC2_IDLE", **attrs):
    item = {"resourceId": rid, "findingType": ftype, "resourceType": "ec2" if ftype == "EC2_IDLE" else "ebs",
            "region": RES_REGION, "owner": "owner@example.com", "status": "open", "name": "web-1",
            "estimatedMonthlyCost": Decimal("8.47")}
    item.update(attrs)
    aws["findings"].put_item(Item=item)
    return item


def running_finding(aws, rid, ftype="EC2_IDLE", **attrs):
    """A finding with a running timeline (generation 1, in_progress) and a deadline."""
    put_finding(aws, rid, ftype, **attrs)
    assert timeline.start_timeline(rid, ftype, "new")["result"] == "started"
    aws["findings"].update_item(Key={"resourceId": rid, "findingType": ftype},
                                UpdateExpression="SET deadlineAt = :d", ExpressionAttributeValues={":d": in_hours(48)})
    return finding(aws, rid, ftype)


def remediated_volume_finding(aws, tags=None, **attrs):
    rid = "vol-0deleted0000000001"
    snap = snapshot(aws, rid, tags)
    values = {"status": "remediated", "dryRun": False, "snapshotId": snap, "availabilityZone": AZ,
              "generation": Decimal(1), "remediatedAt": in_hours(-1)}
    values.update(attrs)
    put_finding(aws, rid, "EBS_UNATTACHED", **values)
    return rid, snap


def finding(aws, rid, ftype="EC2_IDLE"):
    return aws["findings"].get_item(Key={"resourceId": rid, "findingType": ftype}, ConsistentRead=True)["Item"]


def token(aws, rid, action, ftype="EC2_IDLE", generation=1, **attrs):
    raw = secrets.token_urlsafe(32)
    item = {"tokenHash": act.token_hash(raw), "resourceId": rid, "findingType": ftype,
            "generation": Decimal(generation), "action": action, "recipient": "owner@example.com",
            "createdAt": in_hours(-1), "expiresAt": in_hours(24), "used": False, "ttl": Decimal(0)}
    item.update(attrs)
    aws["tokens"].put_item(Item=item)
    return raw


def token_item(aws, raw):
    return aws["tokens"].get_item(Key={"tokenHash": act.token_hash(raw)})["Item"]


def get(raw):
    params = {"t": raw} if raw is not None else None
    return act.handler({"requestContext": {"http": {"method": "GET"}}, "queryStringParameters": params}, None)


def post(raw, b64=False):
    body = urlencode({"t": raw}) if raw is not None else ""
    if b64:
        body = base64.b64encode(body.encode()).decode()
    return act.handler({"requestContext": {"http": {"method": "POST"}}, "body": body, "isBase64Encoded": b64,
                        "headers": {"content-type": "application/x-www-form-urlencoded"}}, None)


def audits(aws, event=None):
    items = sorted(aws["audit"].scan()["Items"], key=lambda i: i["ts"])
    return [i for i in items if event is None or i["event"] == event]


def tags_of_instance(aws, iid):
    inst = aws["ec2"].describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    return {t["Key"]: t["Value"] for t in inst.get("Tags", [])}


def dump_tables(aws):
    return {name: sorted(json.dumps(i, default=str, sort_keys=True) for i in aws[name].scan()["Items"])
            for name in ("findings", "audit", "tokens")}


def executions(aws, kind="ec2"):
    arn = [m for m in aws["sfn"].list_state_machines()["stateMachines"] if m["name"] == f"cg-test-{kind}-timeline"]
    return aws["sfn"].list_executions(stateMachineArn=arn[0]["stateMachineArn"])["executions"]


# ---------------------------------------------------------------- GET


def test_get_shows_confirmation_and_changes_nothing(aws, capsys):
    iid = launch(aws, {"Name": "web-server"})
    running_finding(aws, iid)
    raw = token(aws, iid, "postpone")
    before = dump_tables(aws)
    capsys.readouterr()

    resp = get(raw)

    assert resp["statusCode"] == 200
    assert dump_tables(aws) == before  # no DynamoDB writes
    assert tags_of_instance(aws, iid).get("guardian:protect") is None
    body = resp["body"]
    assert iid in body and "web-server" in body and RES_REGION in body
    assert "Current deadline" in body and "New deadline (approx.)" in body and "Postpones left" in body
    assert '<form method="post" action="action">' in body
    assert f'<input type="hidden" name="t" value="{raw}">' in body
    assert body.count("<button") == 1 and ">Confirm</button>" in body
    [line] = capsys.readouterr().out.strip().splitlines()
    record = json.loads(line)
    assert record["resourceId"] == iid and record["action"] == "postpone" and record["statusCode"] == 200
    assert raw not in line


def test_get_postpone_new_deadline_estimate(aws):
    iid = launch(aws)
    running_finding(aws, iid)
    resp = get(token(aws, iid, "postpone"))
    shown = re.search(r"New deadline \(approx\.\)</dt><dd>([^<]+)</dd>", resp["body"]).group(1)
    expected = datetime.now(timezone.utc) + timedelta(seconds=POSTPONE_SECONDS + WAIT_ACTION_EC2)
    assert abs((datetime.strptime(shown, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                - expected).total_seconds()) < 5
    assert "Postpones left after this one</dt><dd>1</dd>" in resp["body"]


def test_get_restore_page(aws):
    rid, snap = remediated_volume_finding(aws)
    resp = get(token(aws, rid, "restore", "EBS_UNATTACHED"))
    assert resp["statusCode"] == 200
    assert snap in resp["body"] and AZ in resp["body"] and "Current deadline" not in resp["body"]


# ---------------------------------------------------------------- refusals


def _refusal_cases():
    """name -> setup(aws) returning raw token; expected status and reason."""

    def unknown(aws):
        return secrets.token_urlsafe(32)

    def used(aws):
        iid = launch(aws)
        running_finding(aws, iid)
        return token(aws, iid, "protect", used=True)

    def expired(aws):
        iid = launch(aws)
        running_finding(aws, iid)
        return token(aws, iid, "protect", expiresAt=in_hours(-1))

    def older_generation(aws):
        iid = launch(aws)
        running_finding(aws, iid)
        timeline.start_timeline(iid, "EC2_IDLE", "postpone")  # generation 2
        return token(aws, iid, "protect", generation=1)

    def wrong_status(aws):
        iid = launch(aws)
        put_finding(aws, iid, status="remediated", generation=Decimal(1), dryRun=True)
        return token(aws, iid, "protect")

    def postpone_limit(aws):
        iid = launch(aws)
        running_finding(aws, iid)
        aws["findings"].update_item(Key={"resourceId": iid, "findingType": "EC2_IDLE"},
                                    UpdateExpression="SET postponeCount = :c", ExpressionAttributeValues={":c": 2})
        return token(aws, iid, "postpone")

    def restore_dry_run(aws):
        rid, _ = remediated_volume_finding(aws, dryRun=True)
        return token(aws, rid, "restore", "EBS_UNATTACHED")

    def restore_no_snapshot_id(aws):
        rid, _ = remediated_volume_finding(aws)
        aws["findings"].update_item(Key={"resourceId": rid, "findingType": "EBS_UNATTACHED"},
                                    UpdateExpression="REMOVE snapshotId")
        return token(aws, rid, "restore", "EBS_UNATTACHED")

    def restore_snapshot_gone(aws):
        rid, snap = remediated_volume_finding(aws)
        aws["ec2"].delete_snapshot(SnapshotId=snap)  # test setup only (the Guardian never deletes snapshots)
        return token(aws, rid, "restore", "EBS_UNATTACHED")

    def restore_snapshot_wrong_tag(aws):
        rid, _ = remediated_volume_finding(aws, {"guardian:source-volume": "vol-0someoneelse0000001"})
        return token(aws, rid, "restore", "EBS_UNATTACHED")

    def scope_resource(aws):
        iid = launch(aws, {"guardian:dev-scope": "cg-other-"})
        running_finding(aws, iid)
        return token(aws, iid, "protect")

    def scope_snapshot(aws):
        rid, _ = remediated_volume_finding(aws, {"guardian:dev-scope": "cg-other-"})
        return token(aws, rid, "restore", "EBS_UNATTACHED")

    return {
        "unknown": (unknown, 404, "unknown"),
        "used": (used, 410, "used"),
        "expired": (expired, 410, "expired"),
        "older_generation": (older_generation, 410, "older_generation"),
        "wrong_status": (wrong_status, 409, "wrong_status"),
        "postpone_limit": (postpone_limit, 409, "postpone_limit"),
        "restore_dry_run": (restore_dry_run, 409, "wrong_status"),
        "restore_no_snapshot_id": (restore_no_snapshot_id, 410, "snapshot_missing"),
        "restore_snapshot_gone": (restore_snapshot_gone, 410, "snapshot_missing"),
        "restore_snapshot_wrong_tag": (restore_snapshot_wrong_tag, 410, "snapshot_missing"),
        "scope_resource": (scope_resource, 409, "outside_dev_scope"),
        "scope_snapshot": (scope_snapshot, 409, "outside_dev_scope"),
    }


REFUSALS = _refusal_cases()


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_refusals(aws, monkeypatch, capsys, case, method):
    setup, status, reason = REFUSALS[case]
    if case.startswith("scope_"):
        monkeypatch.setenv("DEV_SCOPE", SCOPE)
    raw = setup(aws)
    before_tokens = sorted(json.dumps(i, default=str, sort_keys=True) for i in aws["tokens"].scan()["Items"])
    before_audit = {a["ts"] for a in audits(aws)}
    capsys.readouterr()

    resp = (get if method == "GET" else post)(raw)

    assert resp["statusCode"] == status
    record = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert record["reason"] == reason and record["result"] == "refused" and record["statusCode"] == status
    # Tokens never change on a refusal.
    assert sorted(json.dumps(i, default=str, sort_keys=True) for i in aws["tokens"].scan()["Items"]) == before_tokens
    new_audit = [a for a in audits(aws) if a["ts"] not in before_audit]
    if method == "GET" or case == "unknown":
        assert new_audit == []  # GET refusals and unknown tokens are only logged
    else:
        [entry] = new_audit
        assert entry["event"] == "link_refused" and entry["actor"] == "action-link"
        assert entry["details"]["reason"] == reason
        assert entry["details"]["tokenGeneration"] == token_item(aws, raw)["generation"]
        assert entry["details"]["action"] == token_item(aws, raw)["action"]


def test_older_generation_message_points_to_newest_email(aws):
    _, status, _ = REFUSALS["older_generation"]
    resp = get(REFUSALS["older_generation"][0](aws))
    assert resp["statusCode"] == status
    assert "a newer email was sent; use the links in the newest one" in resp["body"].lower()


def test_snapshot_missing_message(aws):
    resp = get(REFUSALS["restore_snapshot_gone"][0](aws))
    assert "the snapshot no longer exists; restore from the console is not possible either" in resp["body"].lower()


def test_dev_scope_allows_tagged_resources(aws, monkeypatch):
    monkeypatch.setenv("DEV_SCOPE", SCOPE)
    iid = launch(aws, {"guardian:dev-scope": SCOPE})
    running_finding(aws, iid)
    assert get(token(aws, iid, "protect"))["statusCode"] == 200


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize("raw", [None, "", "short", "x" * 200, "abc$def" + "a" * 40])
def test_missing_or_garbled_token_is_400(aws, raw, method):
    resp = (get if method == "GET" else post)(raw)
    assert resp["statusCode"] == 400
    assert audits(aws) == []


def test_repeated_form_field_is_400(aws):
    body = "t=" + "a" * 43 + "&t=" + "b" * 43
    resp = act.handler({"requestContext": {"http": {"method": "POST"}}, "body": body}, None)
    assert resp["statusCode"] == 400


@pytest.mark.parametrize("method", ["PUT", "DELETE", "HEAD", "PATCH"])
def test_other_methods_are_405(aws, method):
    resp = act.handler({"requestContext": {"http": {"method": method}}}, None)
    assert resp["statusCode"] == 405 and resp["headers"]["Allow"] == "GET, POST"


# ---------------------------------------------------------------- POST: protect


def test_post_protect(aws, capsys):
    iid = launch(aws)
    running_finding(aws, iid)
    raw = token(aws, iid, "protect")
    capsys.readouterr()

    resp = post(raw)

    assert resp["statusCode"] == 200
    assert tags_of_instance(aws, iid)["guardian:protect"] == "true"
    item = finding(aws, iid)
    assert item["status"] == "open" and item["reportOnlyReason"] == "protected" and item["timelineStep"] == "done"
    assert all(e["status"] != "RUNNING" for e in executions(aws))
    tok = token_item(aws, raw)
    assert tok["used"] is True and "usedAt" in tok
    [entry] = audits(aws, "link_protect")
    assert entry["result"] == "ok" and entry["actor"] == "action-link" and entry["findingType"] == "EC2_IDLE"
    [stopped] = audits(aws, "timeline_stopped")
    assert stopped["actor"] == "action-link"
    assert raw not in capsys.readouterr().out


def test_post_protect_volume(aws):
    vid = volume(aws)
    running_finding(aws, vid, "EBS_UNATTACHED")
    resp = post(token(aws, vid, "protect", "EBS_UNATTACHED"))
    assert resp["statusCode"] == 200
    vol = aws["ec2"].describe_volumes(VolumeIds=[vid])["Volumes"][0]
    assert {"Key": "guardian:protect", "Value": "true"} in vol["Tags"]


def test_protect_acts_in_dry_run(aws):
    assert act.os.environ["DRY_RUN"] == "true"
    iid = launch(aws)
    running_finding(aws, iid)
    assert post(token(aws, iid, "protect"))["statusCode"] == 200
    assert tags_of_instance(aws, iid)["guardian:protect"] == "true"


def test_double_post_second_is_410(aws):
    iid = launch(aws)
    running_finding(aws, iid)
    raw = token(aws, iid, "protect")
    assert post(raw)["statusCode"] == 200
    second = post(raw)
    assert second["statusCode"] == 410
    assert len(audits(aws, "link_protect")) == 1
    [refused] = audits(aws, "link_refused")
    assert refused["details"]["reason"] == "used"


# ---------------------------------------------------------------- POST: postpone


def test_post_postpone(aws):
    iid = launch(aws)
    running_finding(aws, iid)
    raw = token(aws, iid, "postpone")

    resp = post(raw)

    assert resp["statusCode"] == 200
    item = finding(aws, iid)
    assert item["status"] == "in_progress" and item["generation"] == 2 and item["postponeCount"] == 1
    assert item["executionName"] == f"ec2-{iid}-gen2"
    running = [e for e in executions(aws) if e["status"] == "RUNNING"]
    assert [e["name"] for e in running] == [f"ec2-{iid}-gen2"]
    desc = aws["sfn"].describe_execution(executionArn=running[0]["executionArn"])
    wf_input = json.loads(desc["input"])
    assert wf_input["dryRun"] is True  # keeps the stack's dry-run
    assert wf_input["waits"]["beforeFinalSeconds"] == POSTPONE_SECONDS
    [entry] = audits(aws, "link_postpone")
    assert entry["result"] == "ok" and entry["generation"] == 2
    assert entry["details"] == {"generation": 2, "executionName": f"ec2-{iid}-gen2"}
    [started] = [e for e in audits(aws, "timeline_started") if e["actor"] == "action-link"]
    assert started["details"]["reason"] == "postpone"
    assert token_item(aws, raw)["used"] is True
    # The old link is now from an older generation.
    assert get(token(aws, iid, "protect", generation=1))["statusCode"] == 410


# ---------------------------------------------------------------- POST: restore


def test_post_restore(aws, monkeypatch):
    monkeypatch.setenv("DEV_SCOPE", SCOPE)
    rid, snap = remediated_volume_finding(aws, {"guardian:dev-scope": SCOPE})
    raw = token(aws, rid, "restore", "EBS_UNATTACHED")

    resp = post(raw)

    assert resp["statusCode"] == 200
    vols = [v for v in aws["ec2"].describe_volumes()["Volumes"] if v.get("SnapshotId") == snap]
    [new] = vols
    assert new["AvailabilityZone"] == AZ and new["VolumeType"] == "gp3"
    assert new["VolumeId"] in resp["body"]
    tags = {t["Key"]: t["Value"] for t in new["Tags"]}
    assert tags == {"owner": "owner@example.com", "project": "demo", "Name": "data", "guardian:dev-scope": SCOPE,
                    "guardian:restored-from": snap}
    item = finding(aws, rid, "EBS_UNATTACHED")
    assert item["status"] == "remediated"
    [call] = aws["notify"].calls
    assert call["FunctionName"] == "cg-test-notify" and call["InvocationType"] == "RequestResponse"
    assert call["Payload"] == {
        "template": "RESTORE_DONE", "to": "owner@example.com",
        "findings": [{"resourceId": rid, "findingType": "EBS_UNATTACHED", "generation": 1, "actions": []}],
        "vars": {"sourceVolumeId": rid, "snapshotId": snap, "newVolumeId": new["VolumeId"],
                 "availabilityZone": AZ, "region": RES_REGION}}
    [entry] = audits(aws, "link_restore")
    assert entry["result"] == "ok" and entry["dryRun"] is False
    assert entry["details"]["snapshotId"] == snap and entry["details"]["newVolumeId"] == new["VolumeId"]


def test_restore_without_owner_sends_to_team(aws):
    rid, _ = remediated_volume_finding(aws)
    aws["findings"].update_item(Key={"resourceId": rid, "findingType": "EBS_UNATTACHED"},
                                UpdateExpression="REMOVE #o", ExpressionAttributeNames={"#o": "owner"})
    assert post(token(aws, rid, "restore", "EBS_UNATTACHED"))["statusCode"] == 200
    assert aws["notify"].calls[0]["Payload"]["to"] is None


def test_restore_notify_failure_still_succeeds(aws):
    aws["notify"].error = RuntimeError("SES down")
    rid, _ = remediated_volume_finding(aws)
    resp = post(token(aws, rid, "restore", "EBS_UNATTACHED"))
    assert resp["statusCode"] == 200 and "vol-" in resp["body"]
    [entry] = audits(aws, "link_restore")
    assert entry["result"] == "ok" and entry["details"]["notified"] is False


def test_restore_tags_drop_reserved_and_source_keys():
    snap = {"Tags": [{"Key": "aws:backup:source", "Value": "x"}, {"Key": "guardian:source-volume", "Value": "vol-1"},
                     {"Key": "owner", "Value": "o@example.com"}, {"Key": "guardian:restored-from", "Value": "old"}]}
    assert act._restore_tags(snap, "snap-1") == [{"Key": "owner", "Value": "o@example.com"},
                                                 {"Key": "guardian:restored-from", "Value": "snap-1"}]


# ---------------------------------------------------------------- races and failures


def test_transaction_cancelled_by_generation_change(aws, monkeypatch):
    iid = launch(aws)
    running_finding(aws, iid)
    raw = token(aws, iid, "protect")
    real_claim = act._claim

    def racing_claim(raw_, ctx):
        # Someone postpones (new generation) between our checks and our claim.
        aws["findings"].update_item(Key={"resourceId": iid, "findingType": "EC2_IDLE"},
                                    UpdateExpression="SET generation = :g", ExpressionAttributeValues={":g": 2})
        return real_claim(raw_, ctx)

    monkeypatch.setattr(act, "_claim", racing_claim)
    resp = post(raw)

    assert resp["statusCode"] == 410 and "newer email" in resp["body"]
    assert token_item(aws, raw)["used"] is False
    assert "guardian:protect" not in tags_of_instance(aws, iid)
    [refused] = audits(aws, "link_refused")
    assert refused["details"]["reason"] == "older_generation"
    assert audits(aws, "link_protect") == []


def test_transaction_cancelled_by_concurrent_click(aws, monkeypatch):
    iid = launch(aws)
    running_finding(aws, iid)
    raw = token(aws, iid, "protect")
    real_claim = act._claim

    def racing_claim(raw_, ctx):
        aws["tokens"].update_item(Key={"tokenHash": act.token_hash(raw_)}, UpdateExpression="SET used = :t",
                                  ExpressionAttributeValues={":t": True})
        return real_claim(raw_, ctx)

    monkeypatch.setattr(act, "_claim", racing_claim)
    assert post(raw)["statusCode"] == 410
    assert "guardian:protect" not in tags_of_instance(aws, iid)


def fail(*_args, **_kwargs):
    raise ClientError({"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}}, "Op")


def assert_given_back(aws, raw, event):
    tok = token_item(aws, raw)
    assert tok["used"] is False and "usedAt" not in tok
    [entry] = audits(aws, event)
    assert entry["result"] == "error" and entry["details"]["changed"] is False
    assert entry["details"]["tokenGivenBack"] is True


def test_token_given_back_when_create_tags_fails(aws, monkeypatch):
    iid = launch(aws)
    running_finding(aws, iid)
    raw = token(aws, iid, "protect")
    monkeypatch.setattr(act._client("ec2", RES_REGION), "create_tags", fail)

    resp = post(raw)

    assert resp["statusCode"] == 500
    assert "nothing was changed, you can try the link again" in resp["body"].lower()
    assert_given_back(aws, raw, "link_protect")
    assert finding(aws, iid)["status"] == "in_progress"
    # The link works again (a fresh EC2 client without the failure).
    del act._clients[("ec2", RES_REGION)]
    assert post(raw)["statusCode"] == 200
    assert tags_of_instance(aws, iid)["guardian:protect"] == "true"


def test_token_given_back_when_start_timeline_fails(aws, monkeypatch):
    iid = launch(aws)
    running_finding(aws, iid)
    raw = token(aws, iid, "postpone")
    monkeypatch.setattr(act.timeline, "start_timeline", fail)

    resp = post(raw)

    assert resp["statusCode"] == 500
    assert_given_back(aws, raw, "link_postpone")


def test_token_given_back_when_create_volume_fails(aws, monkeypatch):
    rid, _ = remediated_volume_finding(aws)
    raw = token(aws, rid, "restore", "EBS_UNATTACHED")
    monkeypatch.setattr(act._client("ec2", RES_REGION), "create_volume", fail)

    resp = post(raw)

    assert resp["statusCode"] == 500
    assert_given_back(aws, raw, "link_restore")
    assert aws["notify"].calls == []


def test_token_kept_used_when_tag_added_but_stop_timeline_fails(aws, monkeypatch):
    iid = launch(aws)
    running_finding(aws, iid)
    raw = token(aws, iid, "protect")
    monkeypatch.setattr(act.timeline, "stop_timeline", fail)

    resp = post(raw)

    assert resp["statusCode"] == 500
    assert "guardian:protect=true was added" in resp["body"]
    assert tags_of_instance(aws, iid)["guardian:protect"] == "true"
    assert token_item(aws, raw)["used"] is True
    [entry] = audits(aws, "link_protect")
    assert entry["result"] == "error" and entry["details"]["changed"] is True
    assert entry["details"]["tokenGivenBack"] is False


def test_unexpected_error_is_500_without_token(aws, monkeypatch, capsys):
    raw = secrets.token_urlsafe(32)

    def boom(*_a, **_k):
        raise RuntimeError("table missing")

    monkeypatch.setattr(act, "_get", boom)
    capsys.readouterr()
    resp = get(raw)
    assert resp["statusCode"] == 500 and raw not in resp["body"]
    assert raw not in capsys.readouterr().out


# ---------------------------------------------------------------- pages


def test_hostile_name_is_escaped(aws):
    hostile = '<script>alert("x")</script>&<img src=x onerror=1>'
    iid = launch(aws, {"Name": hostile})
    running_finding(aws, iid)
    body = get(token(aws, iid, "protect"))["body"]
    assert "<script>" not in body and "<img" not in body
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&amp;&lt;img src=x onerror=1&gt;" in body


EXPECTED_HEADERS = {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
                               "frame-ancestors 'none'; base-uri 'none'",
}


def test_security_headers_on_every_page(aws):
    iid = launch(aws)
    running_finding(aws, iid)
    raw = token(aws, iid, "protect")
    responses = [get(raw), post(raw), post(raw), get(None), get(secrets.token_urlsafe(32)),
                 act.handler({"requestContext": {"http": {"method": "PUT"}}}, None)]
    assert [r["statusCode"] for r in responses] == [200, 200, 410, 400, 404, 405]
    for resp in responses:
        for name, value in EXPECTED_HEADERS.items():
            assert resp["headers"][name] == value
        assert "<script" not in resp["body"]


def test_base64_form_body(aws):
    iid = launch(aws)
    running_finding(aws, iid)
    raw = token(aws, iid, "protect")
    assert post(raw, b64=True)["statusCode"] == 200
    assert token_item(aws, raw)["used"] is True


def test_bad_base64_body_is_400(aws):
    resp = act.handler({"requestContext": {"http": {"method": "POST"}}, "body": "%%%not-base64",
                        "isBase64Encoded": True}, None)
    assert resp["statusCode"] == 400


# ---------------------------------------------------------------- IAM policy (engine/terraform/action.tf)

FORBIDDEN = {"ec2:DeleteSnapshot", "ec2:ReleaseAddress", "ec2:DeleteVolume", "ec2:StopInstances",
             "ec2:TerminateInstances", "ec2:*", "*", "dynamodb:*", "states:*", "lambda:*",
             "dynamodb:DeleteItem", "dynamodb:Scan", "dynamodb:Query"}


def _hcl_list(text):
    return re.findall(r'"([^"]*)"', text)


def render_action_policy():
    """The action policy document as {sid: {actions, resources, conditions}}, read from action.tf."""
    text = ACTION_TF.read_text(encoding="utf-8")
    start = text.index('data "aws_iam_policy_document" "action" {')
    depth, end = 0, start
    for i in range(start, len(text)):
        depth += text[i] == "{"
        depth -= text[i] == "}"
        if text[i] == "}" and depth == 0:
            end = i
            break
    block = text[start:end]
    statements = {}
    for chunk in block.split("statement {")[1:]:
        sid = re.search(r'sid\s*=\s*"([^"]+)"', chunk).group(1)
        actions = _hcl_list(re.search(r"actions\s*=\s*\[(.*?)\]", chunk, re.S).group(1))
        resources = re.search(r"resources\s*=\s*(\[.*?\]\s*\n|[\w.]+)", chunk, re.S).group(1).strip()
        effect = re.search(r'effect\s*=\s*"(\w+)"', chunk)
        conditions = [
            (m.group(1), m.group(2), _hcl_list(m.group(3)))
            for m in re.finditer(r'condition\s*\{\s*test\s*=\s*"([^"]+)"\s*variable\s*=\s*"([^"]+)"\s*'
                                 r'values\s*=\s*\[(.*?)\]', chunk, re.S)]
        statements[sid] = {"actions": actions, "resources": resources, "conditions": conditions,
                           "effect": effect.group(1) if effect else "Allow"}
    return statements


def test_action_policy_has_no_forbidden_actions():
    policy = render_action_policy()
    actions = {a for s in policy.values() for a in s["actions"]}
    assert not actions & FORBIDDEN
    assert actions == {
        "logs:CreateLogStream", "logs:PutLogEvents", "dynamodb:GetItem", "dynamodb:UpdateItem",
        "dynamodb:ConditionCheckItem", "dynamodb:PutItem", "states:StartExecution", "states:StopExecution",
        "states:DescribeExecution", "lambda:InvokeFunction", "ec2:DescribeInstances", "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots", "ec2:CreateTags", "ec2:CreateVolume"}
    assert all(s["effect"] == "Allow" for s in policy.values())
    text = ACTION_TF.read_text(encoding="utf-8")
    for forbidden in ("DeleteSnapshot", "ReleaseAddress", "DeleteVolume", "StopInstances"):
        assert forbidden not in text


def test_action_policy_conditions():
    policy = render_action_policy()
    assert policy["ProtectTagOnly"]["actions"] == ["ec2:CreateTags"]
    assert policy["ProtectTagOnly"]["conditions"] == [
        ("ForAllValues:StringEquals", "aws:TagKeys", ["guardian:protect"]),
        ("StringEquals", "aws:RequestTag/guardian:protect", ["true"])]
    assert policy["RestoreFromGuardianSnapshots"]["conditions"] == [
        ("Null", "aws:ResourceTag/guardian:source-volume", ["false"])]
    assert "snapshot/*" in policy["RestoreFromGuardianSnapshots"]["resources"]
    assert policy["RestoredVolumes"]["conditions"] == [("Null", "aws:RequestTag/guardian:restored-from", ["false"])]
    assert policy["TagRestoredVolumes"]["conditions"] == [("StringEquals", "ec2:CreateAction", ["CreateVolume"])]
    assert "volume/*" in policy["TagRestoredVolumes"]["resources"]
    # Every ec2 write is conditioned.
    for sid, statement in policy.items():
        if any(a in ("ec2:CreateTags", "ec2:CreateVolume") for a in statement["actions"]):
            assert statement["conditions"], sid
    assert policy["Tokens"]["resources"] == '[var.table_arns["tokens"]]'
    assert policy["StopTimelines"]["resources"] == "local.timeline_execution_arns"
    # Links exist only for EC2_IDLE / EBS_UNATTACHED findings: instance / volume keys only (#39).
    assert policy["Findings"]["conditions"] == [
        ("ForAllValues:StringLike", "dynamodb:LeadingKeys", ["i-*", "vol-*"]),
        ("Null", "dynamodb:LeadingKeys", ["false"])]


def _statement_chunk(sid):
    text = ACTION_TF.read_text(encoding="utf-8")
    block = text[text.index('data "aws_iam_policy_document" "action" {'):]
    for chunk in block.split("statement {")[1:]:
        if f'sid = "{sid}"' in re.sub(r"\s+", " ", chunk):
            return chunk
    raise AssertionError(sid)


DEV_SCOPE_DYNAMIC = re.compile(
    r'dynamic "condition" \{\s*for_each = var\.dev_scope != "" \? \[var\.dev_scope\] : \[\]\s*content \{\s*'
    r'test\s*= "StringEquals"\s*variable = "([^"]+)"\s*values\s*= \[condition\.value\]')


@pytest.mark.parametrize("sid,key", [
    ("ProtectTagOnly", "ec2:ResourceTag/guardian:dev-scope"),
    ("RestoreFromGuardianSnapshots", "ec2:ResourceTag/guardian:dev-scope"),
    ("RestoredVolumes", "aws:RequestTag/guardian:dev-scope"),
    ("TagRestoredVolumes", "aws:RequestTag/guardian:dev-scope"),
])
def test_action_policy_dev_scope_in_iam(sid, key):
    """In a personal stack every ec2 write also needs the dev-scope tag (#39); the team stack has no condition."""
    assert DEV_SCOPE_DYNAMIC.findall(_statement_chunk(sid)) == [key]
