import hashlib
import importlib.util
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

import notify_templates as tpl
import notify_tokens

HANDLER = Path(__file__).resolve().parents[1] / "src" / "notify" / "handler.py"
REGION = "us-west-2"
TEAM = "team@example.com"
SENDER = "sender@example.com"
API = "https://abc123.execute-api.us-west-2.amazonaws.com"
EXPIRES = "2026-11-23T16:30:00Z"


def load_handler():
    # Load by path: every Lambda's file is called handler.py, so a plain import would collide.
    spec = importlib.util.spec_from_file_location("platform_notify_handler", HANDLER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


notify = load_handler()

# Only the R variables of each template (CONTRACT §4.2), money null where allowed.
R_VARS = {
    "FIRST_NOTICE": {"resourceId": "i-0abc123", "resourceType": "ec2", "region": "us-east-1",
                     "estimatedMonthlyCost": None, "deadlineAt": EXPIRES, "plannedAction": "stop",
                     "dryRun": False},
    "FINAL_WARNING": {"resourceId": "vol-0abc", "resourceType": "ebs", "region": "us-east-1",
                      "estimatedMonthlyCost": None, "deadlineAt": EXPIRES, "plannedAction": "snapshot_and_delete",
                      "dryRun": False},
    "STOP_CONFIRMATION": {"resourceId": "i-0abc123", "region": "us-east-1", "realizedMonthlySavings": None,
                          "dryRun": False, "elasticIps": []},
    "DELETE_CONFIRMATION": {"resourceId": "vol-0abc", "region": "us-east-1", "sizeGb": 8,
                            "snapshotId": "snap-123", "realizedMonthlySavings": None, "dryRun": False},
    "WORKFLOW_FAILED": {"resourceId": "vol-0abc", "region": "us-east-1", "findingType": "EBS_UNATTACHED",
                        "failedStep": "DELETE_VOLUME", "errorMessage": "boom",
                        "progress": "snapshot snap-123 created; volume not deleted"},
    "REPORT_NOTICE": {"resourceId": "eipalloc-1", "resourceType": "eip", "region": "us-east-1",
                      "findingType": "EIP_UNASSOCIATED", "estimatedMonthlyCost": None,
                      "reason": "eip_unassociated"},
    "MISSING_TAGS": {"resourceId": "vol-0abc", "resourceType": "ebs", "region": "us-east-1",
                     "missingTags": ["owner", "project"]},
    "MISSING_TAGS_GROUPED": {"instanceId": "i-0abc123", "region": "us-east-1",
                             "resources": [{"resourceId": "vol-0abc", "resourceType": "ebs",
                                            "missingTags": ["owner"]}]},
    "RESTORE_DONE": {"sourceVolumeId": "vol-0abc", "snapshotId": "snap-123", "newVolumeId": "vol-0new",
                     "availabilityZone": "us-east-1a", "region": "us-east-1"},
    "DIGEST": {"findings": [], "protected": [], "snapshots": [], "budgetAlerts": [], "missingTags": []},
}
FINDING_TYPE = {"FINAL_WARNING": "EBS_UNATTACHED", "DELETE_CONFIRMATION": "EBS_UNATTACHED",
                "WORKFLOW_FAILED": "EBS_UNATTACHED", "REPORT_NOTICE": "EIP_UNASSOCIATED",
                "MISSING_TAGS": "MISSING_TAGS", "MISSING_TAGS_GROUPED": "MISSING_TAGS",
                "RESTORE_DONE": "EBS_UNATTACHED"}


def finding(resource_id="i-0abc123", finding_type="EC2_IDLE", generation=1, actions=("protect", "postpone"),
            expires_at=EXPIRES):
    f = {"resourceId": resource_id, "findingType": finding_type, "generation": generation,
         "actions": list(actions)}
    if expires_at is not None:
        f["expiresAt"] = expires_at
    return f


def event(template="FIRST_NOTICE", to="owner@example.com", findings=None, **overrides):
    vars_ = dict(R_VARS[template])
    vars_.update(overrides)
    if findings is None:
        findings = [finding()] if template != "DIGEST" else []
    return {"template": template, "to": to, "findings": findings, "vars": vars_}


class FakeSes:
    """Records SendEmail calls. `errors` is a list consumed one per call (None = success)."""

    def __init__(self, errors=()):
        self.calls, self.errors = [], list(errors)

    def send_email(self, **kwargs):
        self.calls.append(kwargs)
        error = self.errors.pop(0) if self.errors else None
        if error:
            raise ClientError({"Error": {"Code": error, "Message": f"{error} for test"}}, "SendEmail")
        return {"MessageId": f"msg-{len(self.calls)}"}


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    for name, value in {"TABLE_FINDINGS": "cg-t-findings", "TABLE_AUDIT": "cg-t-audit",
                        "TABLE_TOKENS": "cg-t-tokens", "SENDER_EMAIL": SENDER, "TEAM_EMAIL": TEAM,
                        "ACTION_API_URL": API, "DRY_RUN": "true"}.items():
        monkeypatch.setenv(name, value)
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name=REGION)
        ddb.create_table(TableName="cg-t-findings", BillingMode="PAY_PER_REQUEST",
                         KeySchema=[{"AttributeName": "resourceId", "KeyType": "HASH"},
                                    {"AttributeName": "findingType", "KeyType": "RANGE"}],
                         AttributeDefinitions=[{"AttributeName": "resourceId", "AttributeType": "S"},
                                               {"AttributeName": "findingType", "AttributeType": "S"}])
        ddb.create_table(TableName="cg-t-audit", BillingMode="PAY_PER_REQUEST",
                         KeySchema=[{"AttributeName": "resourceId", "KeyType": "HASH"},
                                    {"AttributeName": "ts", "KeyType": "RANGE"}],
                         AttributeDefinitions=[{"AttributeName": "resourceId", "AttributeType": "S"},
                                               {"AttributeName": "ts", "AttributeType": "S"}])
        ddb.create_table(TableName="cg-t-tokens", BillingMode="PAY_PER_REQUEST",
                         KeySchema=[{"AttributeName": "tokenHash", "KeyType": "HASH"}],
                         AttributeDefinitions=[{"AttributeName": "tokenHash", "AttributeType": "S"}])
        fake = FakeSes()
        monkeypatch.setattr(notify, "_clients", {"ses": fake, "dynamodb": ddb})
        yield {"ddb": ddb, "ses": fake, "findings": ddb.Table("cg-t-findings"),
               "audit": ddb.Table("cg-t-audit"), "tokens": ddb.Table("cg-t-tokens")}


def put_finding(aws, resource_id="i-0abc123", finding_type="EC2_IDLE"):
    aws["findings"].put_item(Item={"resourceId": resource_id, "findingType": finding_type, "status": "in_progress"})


def scan(table):
    return table.scan()["Items"]


def raw_tokens(text):
    return re.findall(re.escape(API) + r"/action\?t=([A-Za-z0-9_-]+)", text)


def body_of(call):
    simple = call["Content"]["Simple"]
    return simple["Subject"]["Data"], simple["Body"]["Html"]["Data"], simple["Body"]["Text"]["Data"]


# ---------------------------------------------------------------- templates

@pytest.mark.parametrize("template", sorted(tpl.TEMPLATES))
def test_every_template_renders_with_only_required_vars(template):
    t, findings, vars_ = tpl.validate(event(template, findings=[] if template == "DIGEST" else
                                            [finding(finding_type=FINDING_TYPE.get(template, "EC2_IDLE"),
                                                     actions=())]))
    subject, html_body, text = tpl.render(t, vars_, findings, {})
    assert subject and "\n" not in subject and len(subject) <= 160
    assert html_body.startswith("<!DOCTYPE html>") and text.strip()
    if any(name in tpl.MONEY_VARS for name in tpl.REQUIRED_VARS[template]):
        assert tpl.NOT_ESTIMATED in html_body and tpl.NOT_ESTIMATED in text


@pytest.mark.parametrize("template", sorted(tpl.TEMPLATES))
def test_missing_required_var_raises(template):
    for name in tpl.REQUIRED_VARS[template]:
        if (template, name) == ("STOP_CONFIRMATION", "elasticIps"):
            continue  # missing = empty list (JSONata tolerance, CONTRACT §4.2)
        ev = event(template, findings=[] if template == "DIGEST" else
                   [finding(finding_type=FINDING_TYPE.get(template, "EC2_IDLE"), actions=())])
        del ev["vars"][name]
        with pytest.raises(ValueError, match=name):
            tpl.validate(ev)


def test_money_values_are_formatted():
    t, findings, vars_ = tpl.validate(event(estimatedMonthlyCost=1234.5))
    _, html_body, text = tpl.render(t, vars_, findings, {})
    assert "$1,234.50/month" in html_body and "$1,234.50/month" in text and tpl.NOT_ESTIMATED not in text


def test_null_non_money_required_var_raises():
    with pytest.raises(ValueError, match="region"):
        tpl.validate(event(region=None))


def test_dry_run_delete_confirmation_allows_null_snapshot():
    t, findings, vars_ = tpl.validate(event("DELETE_CONFIRMATION", dryRun=True, snapshotId=None,
                                            findings=[finding("vol-0abc", "EBS_UNATTACHED", actions=())]))
    subject, html_body, _ = tpl.render(t, vars_, findings, {})
    assert "none (dry run)" in html_body and subject.startswith("[DRY RUN] ")


def test_digest_renders_items_with_null_money_and_links():
    vars_ = dict(R_VARS["DIGEST"], aiSummary="Two volumes waste money.",
                 findings=[{"resourceId": "vol-0abc", "findingType": "EBS_UNATTACHED", "resourceType": "ebs",
                            "region": "us-east-1", "status": "in_progress", "estimatedMonthlyCost": None,
                            "costSoFar": None, "daysOpen": 9, "deadlineAt": EXPIRES}],
                 protected=[{"resourceId": "i-dash", "resourceType": "ec2", "region": "us-west-2",
                             "estimatedMonthlyCost": None, "name": "dashboard"}],
                 snapshots=[{"snapshotId": "snap-1", "sourceVolumeId": "vol-9", "region": "us-east-1",
                             "sizeGb": 8, "monthlyCost": None, "ageDays": 3}],
                 budgetAlerts=[{"budgetName": "cg", "thresholdType": "ACTUAL", "threshold": 80,
                                "receivedAt": EXPIRES}],
                 missingTags=[{"resourceId": "vol-7", "resourceType": "ebs", "region": "us-east-1",
                               "missingTags": ["owner"]}])
    links = {"vol-0abc#EBS_UNATTACHED": {"protect": f"{API}/action?t=AAA", "postpone": f"{API}/action?t=BBB"}}
    t, findings, v = tpl.validate({"template": "DIGEST", "to": None, "vars": vars_,
                                   "findings": [finding("vol-0abc", "EBS_UNATTACHED")]})
    _, html_body, text = tpl.render(t, v, findings, links)
    for needle in ("Two volumes waste money.", "Protected", "snap-1", "Budget alerts", "vol-7",
                   tpl.NOT_ESTIMATED, f"{API}/action?t=AAA", "Nov 23, 2026 16:30 UTC"):
        assert needle in html_body and needle in text


def test_script_in_name_is_escaped_in_html_but_literal_in_subject():
    name = '<script>alert("x")</script> R&D\r\nBcc: x@example.com'
    t, findings, vars_ = tpl.validate(event(name=name, project="<b>p</b>", idleSummary="<img src=x>"))
    subject, html_body, text = tpl.render(t, vars_, findings, {})
    assert "<script>" not in html_body and "&lt;script&gt;" in html_body and "R&amp;D" in html_body
    assert "<b>" not in html_body and "<img" not in html_body
    # The subject is a plain-text header: shown literally, never HTML-escaped, but no CR/LF.
    assert "<script>" in subject and "R&D" in subject and "&amp;" not in subject and "&lt;" not in subject
    assert "\r" not in subject and "\n" not in subject
    assert "<script>" in text  # the text part is plain text, shown as is


def test_crlf_stripped_and_subject_capped():
    t, findings, vars_ = tpl.validate(event(name="evil\r\nBcc: x@example.com" + "y" * 300))
    subject, _, _ = tpl.render(t, vars_, findings, {})
    assert "\r" not in subject and "\n" not in subject
    assert len(subject) <= 151
    assert tpl.clean_subject("a\r\nb" + "c" * 400, True).startswith("[DRY RUN] a b")
    assert len(tpl.clean_subject("x" * 400, False)) == tpl.SUBJECT_MAX


def test_dry_run_prefix_and_banner():
    t, findings, vars_ = tpl.validate(event(dryRun=True))
    subject, html_body, text = tpl.render(t, vars_, findings, {})
    assert subject.startswith("[DRY RUN] ")
    assert "Dry run: nothing will actually be stopped or deleted" in html_body
    assert "Dry run: nothing will actually be stopped or deleted" in text
    subject, html_body, _ = tpl.render(t, {**vars_, "dryRun": False}, findings, {})
    assert not subject.startswith("[DRY RUN]") and "Dry run:" not in html_body


def test_times_and_buttons_in_html_full_urls_in_text():
    links = {"i-0abc123#EC2_IDLE": {"protect": f"{API}/action?t=P1", "postpone": f"{API}/action?t=P2"}}
    t, findings, vars_ = tpl.validate(event())
    _, html_body, text = tpl.render(t, vars_, findings, links)
    assert "Nov 23, 2026 16:30 UTC" in html_body
    assert f'<a href="{API}/action?t=P1"' in html_body and "Protect (keep it)</a>" in html_body
    assert f"{API}/action?t=P1" in text and f"{API}/action?t=P2" in text


def test_stop_confirmation_lists_elastic_ips():
    t, findings, vars_ = tpl.validate(event("STOP_CONFIRMATION", elasticIps=["52.1.2.3", "eipalloc-9"],
                                            findings=[finding(actions=())]))
    _, html_body, text = tpl.render(t, vars_, findings, {})
    assert "52.1.2.3" in html_body and "eipalloc-9" in text and "still billed" in text


@pytest.mark.parametrize("value, expected", [("missing", []), (None, []), ("52.1.2.3", ["52.1.2.3"]),
                                             (["52.1.2.3", "52.4.5.6"], ["52.1.2.3", "52.4.5.6"])])
def test_stop_confirmation_elastic_ips_tolerates_jsonata_shapes(value, expected):
    ev = event("STOP_CONFIRMATION", findings=[finding(actions=())])
    if value == "missing":
        del ev["vars"]["elasticIps"]
    else:
        ev["vars"]["elasticIps"] = value
    t, findings, vars_ = tpl.validate(ev)
    assert vars_["elasticIps"] == expected
    assert ("elasticIps" not in ev["vars"]) if value == "missing" else (ev["vars"]["elasticIps"] == value)
    _, html_body, text = tpl.render(t, vars_, findings, {})
    assert ("still billed" in text) == bool(expected)
    assert all(ip in html_body for ip in expected)


@pytest.mark.parametrize("value", [{"ip": "52.1.2.3"}, 3, True])
def test_stop_confirmation_elastic_ips_other_types_raise(value):
    with pytest.raises(ValueError, match="elasticIps"):
        tpl.validate(event("STOP_CONFIRMATION", elasticIps=value, findings=[finding(actions=())]))


def test_report_notice_autoscaling_suggests_scaling_the_group():
    t, findings, vars_ = tpl.validate(event("REPORT_NOTICE", reason="autoscaling", resourceType="ec2",
                                            findingType="EC2_IDLE", resourceId="i-0abc123",
                                            autoScalingGroup="web-asg", findings=[finding(actions=())]))
    _, html_body, text = tpl.render(t, vars_, findings, {})
    assert "scale the group down" in text and "web-asg" in html_body


# ---------------------------------------------------------------- validation

@pytest.mark.parametrize("ev, message", [
    ({"template": "NOPE", "findings": [], "vars": {}}, "template"),
    (event(findings=[]), "at least one finding"),
    (event(findings=[finding(generation="1")]), "generation"),
    (event(findings=[finding(generation=True)]), "generation"),
    (event(findings=[finding(actions=["approve"])]), "unknown action"),
    (event(findings=[finding(expires_at=None)]), "ISO"),
    (event(findings=[finding(expires_at="2026-11-23 16:30")]), "ISO"),
    (event(findings=[finding(actions=["restore"])]), "not allowed"),
    (event(findings=[finding(finding_type="EIP_UNASSOCIATED")]), "not allowed"),
    (event("STOP_CONFIRMATION", findings=[finding()]), "not allowed"),
    (event("WORKFLOW_FAILED", findings=[finding()]), "not allowed"),
    (event("DELETE_CONFIRMATION", findings=[finding("vol-0abc", "EBS_UNATTACHED", actions=["protect"])]),
     "not allowed"),
    (event("DELETE_CONFIRMATION", dryRun=True, findings=[finding("vol-0abc", "EBS_UNATTACHED",
                                                                 actions=["restore"])]), "restore"),
    (event(dryRun="false"), "dryRun"),
    (event(plannedAction="terminate"), "plannedAction"),
    (event(estimatedMonthlyCost="12"), "number"),
    (event(findings=[finding(), finding()]), "duplicate"),
])
def test_invalid_input_raises(ev, message):
    with pytest.raises(ValueError, match=message):
        tpl.validate(ev)


def test_restore_allowed_on_real_delete_confirmation():
    tpl.validate(event("DELETE_CONFIRMATION", findings=[finding("vol-0abc", "EBS_UNATTACHED",
                                                                actions=["restore"])]))


def test_findings_without_actions_need_no_expiry():
    tpl.validate(event(findings=[finding(actions=(), expires_at=None)]))


def test_invalid_input_raises_before_any_aws_call(aws):
    with pytest.raises(ValueError):
        notify.handler(event(findings=[finding(generation="1")]), None)
    assert aws["ses"].calls == [] and scan(aws["tokens"]) == []


# ---------------------------------------------------------------- tokens

def test_tokens_stored_hashed_with_ttl_recipient_generation_and_link_format(aws):
    put_finding(aws)
    out = notify.handler(event(to="  Owner@Example.COM ", findings=[finding(generation=4)]), None)
    assert out["recipient"] == "owner@example.com" and out["tokensCreated"] == 2
    _, html_body, text = body_of(aws["ses"].calls[0])
    raws = raw_tokens(text)
    assert len(raws) == 2 and set(raws) == set(raw_tokens(html_body))
    items = {i["tokenHash"]: i for i in scan(aws["tokens"])}
    expected_ttl = int(datetime(2026, 11, 23, 16, 30, tzinfo=timezone.utc).timestamp()) + 7 * 86400
    for raw in raws:
        item = items[hashlib.sha256(raw.encode()).hexdigest()]
        assert raw not in json.dumps(item, default=str)
        assert item["recipient"] == "owner@example.com" and item["generation"] == 4
        assert item["expiresAt"] == EXPIRES and item["ttl"] == expected_ttl and item["used"] is False
        assert item["resourceId"] == "i-0abc123" and item["findingType"] == "EC2_IDLE"
        assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", item["createdAt"])
        assert len(raw) == 43  # token_urlsafe(32)
    assert {i["action"] for i in items.values()} == {"protect", "postpone"}


class RecordingDynamo:
    def __init__(self, unprocessed_rounds=0):
        self.calls, self.unprocessed_rounds = [], unprocessed_rounds

    def batch_write_item(self, RequestItems):
        self.calls.append(RequestItems)
        if self.unprocessed_rounds:
            self.unprocessed_rounds -= 1
            table, requests = next(iter(RequestItems.items()))
            return {"UnprocessedItems": {table: requests[:1]}}
        return {"UnprocessedItems": {}}


def test_thirty_tokens_go_in_two_batches():
    fake = RecordingDynamo()
    findings = [finding(f"i-{n:03d}", generation=1) for n in range(15)]  # 15 x 2 actions = 30
    links, count = notify_tokens.create_tokens(fake, "tok", findings, TEAM, "2026-11-22T10:00:00Z", API + "/")
    assert count == 30 and [len(c["tok"]) for c in fake.calls] == [25, 5]
    assert links["i-007#EC2_IDLE"]["postpone"].startswith(f"{API}/action?t=")


def test_unprocessed_items_are_retried_then_succeed():
    fake, sleeps = RecordingDynamo(unprocessed_rounds=2), []
    notify_tokens.create_tokens(fake, "tok", [finding()], TEAM, "2026-11-22T10:00:00Z", API, sleep=sleeps.append)
    assert [len(c["tok"]) for c in fake.calls] == [2, 1, 1] and len(sleeps) == 2


def test_unprocessed_items_give_up_after_bounded_attempts():
    fake = RecordingDynamo(unprocessed_rounds=99)
    with pytest.raises(RuntimeError, match="unprocessed"):
        notify_tokens.create_tokens(fake, "tok", [finding()], TEAM, "2026-11-22T10:00:00Z", API,
                                    sleep=lambda s: None)
    assert len(fake.calls) == notify_tokens.MAX_BATCH_ATTEMPTS


# ---------------------------------------------------------------- recipient and fallback

def test_null_to_goes_to_team_without_fallback_audit(aws):
    put_finding(aws)
    out = notify.handler(event(to=None), None)
    assert out["recipient"] == TEAM and out["fallback"] is False
    assert aws["ses"].calls[0]["Destination"] == {"ToAddresses": [TEAM]}
    assert {i["event"] for i in scan(aws["audit"])} == {"notice_sent"}


def test_malformed_to_is_a_fallback(aws):
    out = notify.handler(event(to="not-an-email"), None)
    assert out["recipient"] == TEAM and out["fallback"] is True and len(aws["ses"].calls) == 1
    fb = [i for i in scan(aws["audit"]) if i["event"] == "email_fallback"]
    assert len(fb) == 1 and fb[0]["details"] == {"intendedRecipient": "not-an-email", "reason": "invalid_address"}


def test_message_rejected_falls_back_to_team_with_new_tokens(aws):
    put_finding(aws)
    aws["ses"].errors = ["MessageRejected"]
    out = notify.handler(event(to="owner@example.com", findings=[finding(generation=2)]), None)
    assert out == {"sent": True, "recipient": TEAM, "fallback": True, "messageId": "msg-2", "tokensCreated": 2}
    first, second = aws["ses"].calls
    assert first["Destination"]["ToAddresses"] == ["owner@example.com"]
    assert second["Destination"]["ToAddresses"] == [TEAM]
    first_raws, second_raws = raw_tokens(body_of(first)[2]), raw_tokens(body_of(second)[2])
    assert not set(first_raws) & set(second_raws)
    by_hash = {i["tokenHash"]: i for i in scan(aws["tokens"])}
    assert len(by_hash) == 4
    assert all(by_hash[hashlib.sha256(r.encode()).hexdigest()]["recipient"] == TEAM for r in second_raws)
    assert all(by_hash[hashlib.sha256(r.encode()).hexdigest()]["recipient"] == "owner@example.com"
               for r in first_raws)
    audit = scan(aws["audit"])
    fb = [i for i in audit if i["event"] == "email_fallback"]
    assert len(fb) == 1 and fb[0]["details"]["intendedRecipient"] == "owner@example.com"
    assert fb[0]["details"]["reason"].startswith("MessageRejected")
    sent = [i for i in audit if i["event"] == "notice_sent"]
    assert sent[0]["details"] == {"template": "FIRST_NOTICE", "recipient": TEAM, "messageId": "msg-2",
                                  "fallback": True}


def test_message_rejected_when_sending_to_team_is_raised(aws):
    aws["ses"].errors = ["MessageRejected"]
    with pytest.raises(ClientError):
        notify.handler(event(to=None), None)
    assert len(aws["ses"].calls) == 1 and scan(aws["audit"]) == []


def test_second_send_failure_is_raised_and_only_two_sends(aws):
    aws["ses"].errors = ["MessageRejected", "MessageRejected"]
    with pytest.raises(ClientError):
        notify.handler(event(), None)
    assert len(aws["ses"].calls) == 2


def test_other_ses_error_is_raised(aws):
    aws["ses"].errors = ["AccessDeniedException"]
    with pytest.raises(ClientError):
        notify.handler(event(), None)
    assert len(aws["ses"].calls) == 1 and scan(aws["audit"]) == []


def test_send_request_shape(aws):
    notify.handler(event(), None)
    call = aws["ses"].calls[0]
    assert call["FromEmailAddress"] == SENDER
    simple = call["Content"]["Simple"]
    assert simple["Subject"]["Charset"] == simple["Body"]["Html"]["Charset"] == "UTF-8"
    assert simple["Body"]["Text"]["Charset"] == "UTF-8"


def test_dry_run_env_does_not_suppress_sending(aws, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "true")
    assert notify.handler(event(dryRun=True), None)["sent"] is True and len(aws["ses"].calls) == 1


# ---------------------------------------------------------------- post-send writes

def test_last_notified_at_set_on_all_findings_missing_one_skipped(aws, capsys):
    put_finding(aws, "i-0abc123")
    put_finding(aws, "vol-0abc", "EBS_UNATTACHED")
    vars_ = dict(R_VARS["DIGEST"])
    findings = [finding("i-0abc123"), finding("vol-0abc", "EBS_UNATTACHED"), finding("i-gone", actions=())]
    out = notify.handler({"template": "DIGEST", "to": "owner@example.com", "findings": findings,
                          "vars": vars_}, None)
    assert out["tokensCreated"] == 4
    stored = {(i["resourceId"], i["findingType"]): i for i in scan(aws["findings"])}
    assert set(stored) == {("i-0abc123", "EC2_IDLE"), ("vol-0abc", "EBS_UNATTACHED")}  # no item created
    assert all(re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", i["lastNotifiedAt"]) for i in stored.values())
    logs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert any(l.get("action") == "last_notified_at" and l["result"] == "skipped" and l["resourceId"] == "i-gone"
               for l in logs)
    assert scan(aws["audit"]) == []  # no audit entries for DIGEST without fallback


def test_post_send_write_errors_are_logged_not_raised(aws, monkeypatch, capsys):
    put_finding(aws)

    class Broken:
        def put_item(self, **kw):
            raise ClientError({"Error": {"Code": "InternalServerError", "Message": "x"}}, "PutItem")

        def update_item(self, **kw):
            raise ClientError({"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "x"}},
                              "UpdateItem")

    real = aws["ddb"]

    class Resource:
        def Table(self, name):
            return Broken()

        def batch_write_item(self, **kw):
            return real.batch_write_item(**kw)

    monkeypatch.setitem(notify._clients, "dynamodb", Resource())
    out = notify.handler(event(), None)
    assert out["sent"] is True and len(aws["ses"].calls) == 1
    logs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert any(l.get("action") == "last_notified_at" and l["result"] == "error" for l in logs)
    assert any(l.get("action") == "audit" and l["result"] == "error" for l in logs)


@pytest.mark.parametrize("template, event_name", [("FIRST_NOTICE", "notice_sent"),
                                                  ("FINAL_WARNING", "final_warning_sent")])
def test_notice_audit_entries(aws, template, event_name):
    findings = [finding("vol-0abc", "EBS_UNATTACHED", generation=3)]
    out = notify.handler(event(template, findings=findings), None)
    audit = scan(aws["audit"])
    assert len(audit) == 1
    a = audit[0]
    assert a["event"] == event_name and a["actor"] == "notify" and a["result"] == "ok"
    assert a["resourceId"] == "vol-0abc" and a["findingType"] == "EBS_UNATTACHED" and a["generation"] == 3
    assert a["region"] == "us-east-1" and a["day"] == a["ts"][:10]
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z#[0-9a-f]{8}$", a["ts"])
    assert a["details"] == {"template": template, "recipient": "owner@example.com",
                            "messageId": out["messageId"], "fallback": False}


def test_no_audit_for_other_templates(aws):
    notify.handler(event("STOP_CONFIRMATION", findings=[finding(actions=())]), None)
    assert scan(aws["audit"]) == []


def test_output_shape_exact(aws):
    out = notify.handler(event(), None)
    assert out == {"sent": True, "recipient": "owner@example.com", "fallback": False, "messageId": "msg-1",
                   "tokensCreated": 2}


def test_logs_never_contain_raw_tokens(aws, capsys):
    notify.handler(event(), None)
    raws = raw_tokens(body_of(aws["ses"].calls[0])[2])
    out = capsys.readouterr().out
    assert raws and not any(r in out for r in raws) and "/action?t=" not in out
    for line in out.splitlines():
        json.loads(line)


def test_real_sesv2_client_accepts_the_request(monkeypatch, aws):
    # Shape check against moto's SES v2 (the identity must be verified there too).
    monkeypatch.setitem(notify._clients, "ses", boto3.client("sesv2", region_name=REGION))
    boto3.client("ses", region_name=REGION).verify_email_identity(EmailAddress=SENDER)
    out = notify.handler(event(), None)
    assert out["sent"] is True and out["messageId"]
