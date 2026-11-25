import importlib.util
import json
from decimal import Decimal
from pathlib import Path

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

HANDLER = Path(__file__).resolve().parents[1] / "src" / "budget_subscriber" / "handler.py"
REGION = "us-west-2"
TABLE = "cg-test-budget-alerts"
TOPIC = "arn:aws:sns:us-west-2:123456789012:cg-test-team-alerts"


def load_handler():
    # Load by path: every Lambda's file is called handler.py, so a plain import would collide.
    spec = importlib.util.spec_from_file_location("platform_budget_subscriber_handler", HANDLER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sub = load_handler()

# Real AWS Budgets notification text (what arrives in Sns.Message).
ACTUAL_MESSAGE = """AWS Budget Notification November 25, 2026
AWS Account 123456789012

Dear AWS Customer,

You requested that we alert you when the ACTUAL Cost associated with your cg-test-account-monthly budget is greater than $4.00 for the current month. The ACTUAL Cost associated with this budget is $4.12. You can find additional details below and by accessing the AWS Budgets dashboard [1].

Budget Name: cg-test-account-monthly
Budget Type: Cost
Budgeted Amount: $5.00
Alert Type: ACTUAL
Alert Threshold: > $4.00
ACTUAL Amount: $4.12

[1] https://console.aws.amazon.com/billing/home#/budgets
"""

FORECAST_MESSAGE = """AWS Budget Notification November 25, 2026
AWS Account 123456789012

Dear AWS Customer,

You requested that we alert you when the FORECASTED Cost associated with your cg-test-project-cost-guardian budget is greater than $5.00 for the current month. The FORECASTED Cost associated with this budget is $1,206.50. You can find additional details below and by accessing the AWS Budgets dashboard [1].

Budget Name: cg-test-project-cost-guardian
Budget Type: Cost
Budgeted Amount: $5.00
Alert Type: FORECASTED
Alert Threshold: > $5.00
FORECASTED Amount: $1,206.50

[1] https://console.aws.amazon.com/billing/home#/budgets
"""

ALARM_MESSAGE = json.dumps({
    "AlarmName": "cg-test-dlq-not-empty", "NewStateValue": "ALARM", "OldStateValue": "OK",
    "NewStateReason": "Threshold Crossed", "AWSAccountId": "123456789012",
})


def record(message, subject=None, message_id="mid-1", timestamp="2026-11-25T10:15:30.123Z"):
    sns = {"Type": "Notification", "MessageId": message_id, "TopicArn": TOPIC,
           "Message": message, "Timestamp": timestamp}
    if subject is not None:
        sns["Subject"] = subject
    return {"EventSource": "aws:sns", "EventVersion": "1.0", "Sns": sns}


def event(*records):
    return {"Records": list(records)}


@pytest.fixture
def table(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("TABLE_BUDGET_ALERTS", TABLE)
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name=REGION)
        t = ddb.create_table(
            TableName=TABLE, BillingMode="PAY_PER_REQUEST",
            KeySchema=[{"AttributeName": "budgetName", "KeyType": "HASH"},
                       {"AttributeName": "receivedAt", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "budgetName", "AttributeType": "S"},
                                  {"AttributeName": "receivedAt", "AttributeType": "S"}])
        sub._clients.clear()
        yield t
        sub._clients.clear()


def items(t):
    return sorted(t.scan()["Items"], key=lambda i: (i["budgetName"], i["receivedAt"]))


def test_actual_alert_stored_with_all_fields(table, capsys):
    out = sub.handler(event(record(
        ACTUAL_MESSAGE, subject="AWS Budgets: cg-test-account-monthly has exceeded your alert threshold")), None)
    assert out == {"records": [{"result": "stored", "budgetName": "cg-test-account-monthly",
                                "receivedAt": "2026-11-25T10:15:30Z"}]}
    [item] = items(table)
    assert item == {
        "budgetName": "cg-test-account-monthly",
        "receivedAt": "2026-11-25T10:15:30Z",
        "day": "2026-11-25",
        "thresholdType": "ACTUAL",
        "threshold": Decimal("4.00"),
        "budgetedAmount": Decimal("5.00"),
        "amount": Decimal("4.12"),
        "message": ACTUAL_MESSAGE,
        "subject": "AWS Budgets: cg-test-account-monthly has exceeded your alert threshold",
        "messageId": "mid-1",
    }
    log = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert log["budgetName"] == "cg-test-account-monthly"
    assert log["thresholdType"] == "ACTUAL"
    assert log["result"] == "stored"


def test_forecasted_alert_with_thousands_separator(table):
    sub.handler(event(record(FORECAST_MESSAGE, subject="AWS Budgets: cg-test-project-cost-guardian has exceeded "
                                                       "your alert threshold")), None)
    [item] = items(table)
    assert item["thresholdType"] == "FORECASTED"
    assert item["threshold"] == Decimal("5.00")
    assert item["budgetedAmount"] == Decimal("5.00")
    assert item["amount"] == Decimal("1206.50")


def test_subject_only_fallback_for_name(table):
    sub.handler(event(record("Your budget went over. No details here.",
                             subject="AWS Budgets: cg-test-account-monthly has exceeded your alert threshold")), None)
    [item] = items(table)
    assert item["budgetName"] == "cg-test-account-monthly"
    # Nothing else could be parsed, so nothing else is stored (never guessed).
    for key in ("thresholdType", "threshold", "budgetedAmount", "amount"):
        assert key not in item
    assert item["message"] == "Your budget went over. No details here."


def test_missing_fields_are_omitted(table):
    message = "Budget Name: cg-test-x\nAlert Type: SOMETHING\nAlert Threshold: > 80%\nBudgeted Amount: n/a\n"
    sub.handler(event(record(message)), None)
    [item] = items(table)
    assert item["budgetName"] == "cg-test-x"
    assert "subject" not in item
    # Unknown alert type, a percentage threshold (not USD) and a non-number amount are all left out.
    for key in ("thresholdType", "threshold", "budgetedAmount", "amount"):
        assert key not in item


def test_threshold_type_from_amount_line_when_alert_type_missing(table):
    message = "Budget Name: cg-test-x\nAlert Threshold: > $4.00\nACTUAL Amount: $4.50\n"
    sub.handler(event(record(message)), None)
    [item] = items(table)
    assert item["thresholdType"] == "ACTUAL"
    assert item["amount"] == Decimal("4.50")


def test_alarm_message_skipped(table, capsys):
    out = sub.handler(event(record(ALARM_MESSAGE, subject='ALARM: "cg-test-dlq-not-empty" in US West (Oregon)')),
                      None)
    assert out["records"] == [{"result": "skipped", "reason": "alarm"}]
    assert items(table) == []
    assert json.loads(capsys.readouterr().out.strip())["result"] == "skipped: alarm"


def test_alarm_json_mentioning_budget_name_still_skipped(table):
    msg = json.dumps({"AlarmName": "x", "AlarmDescription": "Budget Name: y"})
    sub.handler(event(record(msg)), None)
    assert items(table) == []


def test_unknown_message_skipped(table, capsys):
    out = sub.handler(event(record("hello", subject="Something else")), None)
    assert out["records"] == [{"result": "skipped", "reason": "unknown"}]
    assert items(table) == []
    assert json.loads(capsys.readouterr().out.strip())["result"] == "skipped: unknown"


def test_record_without_sns_skipped(table):
    out = sub.handler({"Records": [{"foo": "bar"}]}, None)
    assert out["records"] == [{"result": "skipped", "reason": "unknown"}]


def test_budget_without_name_skipped(table):
    out = sub.handler(event(record("Alert Type: ACTUAL\nACTUAL Amount: $4.12", subject="AWS Budgets:")), None)
    assert out["records"] == [{"result": "skipped", "reason": "no_budget_name"}]
    assert items(table) == []


def test_sns_redelivery_writes_once(table):
    rec = record(ACTUAL_MESSAGE, subject="AWS Budgets: cg-test-account-monthly has exceeded your alert threshold")
    sub.handler(event(rec), None)
    out = sub.handler(event(rec), None)
    assert out["records"][0]["receivedAt"] == "2026-11-25T10:15:30Z"
    assert len(items(table)) == 1


def test_same_second_different_message_moves_one_second(table):
    sub.handler(event(record(ACTUAL_MESSAGE, message_id="mid-1")), None)
    out = sub.handler(event(record(ACTUAL_MESSAGE, message_id="mid-2")), None)
    assert out["records"][0]["receivedAt"] == "2026-11-25T10:15:31Z"
    got = items(table)
    assert [(i["receivedAt"], i["messageId"]) for i in got] == [
        ("2026-11-25T10:15:30Z", "mid-1"), ("2026-11-25T10:15:31Z", "mid-2")]
    # A redelivery of the shifted message finds its own item again (no third row).
    sub.handler(event(record(ACTUAL_MESSAGE, message_id="mid-2")), None)
    assert len(items(table)) == 2


def test_shift_crosses_midnight_updates_day(table):
    ts = "2026-11-30T23:59:59Z"
    sub.handler(event(record(ACTUAL_MESSAGE, message_id="a", timestamp=ts)), None)
    out = sub.handler(event(record(ACTUAL_MESSAGE, message_id="b", timestamp=ts)), None)
    assert out["records"][0]["receivedAt"] == "2026-12-01T00:00:00Z"
    assert items(table)[1]["day"] == "2026-12-01"


def test_gives_up_after_five_shifts(table):
    for i in range(6):
        sub.handler(event(record(ACTUAL_MESSAGE, message_id=f"m{i}")), None)
    assert len(items(table)) == 6
    with pytest.raises(RuntimeError):
        sub.handler(event(record(ACTUAL_MESSAGE, message_id="m6")), None)
    assert len(items(table)) == 6


def test_other_dynamodb_error_raises(table, monkeypatch):
    class Boom:
        def put_item(self, **kwargs):
            raise ClientError({"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "slow"}},
                              "PutItem")
    monkeypatch.setitem(sub._clients, "table", Boom())
    with pytest.raises(ClientError):
        sub.handler(event(record(ACTUAL_MESSAGE)), None)


def test_message_and_subject_truncated(table):
    long_message = ACTUAL_MESSAGE + ("x" * 5000)
    long_subject = "AWS Budgets: cg-test-account-monthly has exceeded your alert threshold " + "y" * 500
    sub.handler(event(record(long_message, subject=long_subject)), None)
    [item] = items(table)
    assert len(item["message"]) == 2000
    assert item["message"] == long_message[:2000]
    assert len(item["subject"]) == 200


def test_mixed_batch(table):
    out = sub.handler(event(record(ALARM_MESSAGE, message_id="a"),
                            record(ACTUAL_MESSAGE, message_id="b"),
                            record("nope", message_id="c")), None)
    assert [r["result"] for r in out["records"]] == ["skipped", "stored", "skipped"]
    assert len(items(table)) == 1


@pytest.mark.parametrize("ts,expected", [
    ("2026-11-25T10:15:30.123Z", "2026-11-25T10:15:30Z"),
    ("2026-11-25T10:15:30Z", "2026-11-25T10:15:30Z"),
    ("2026-11-25T12:15:30+02:00", "2026-11-25T10:15:30Z"),
    ("garbage", None),
    (None, None),
])
def test_iso_seconds(ts, expected):
    assert sub.iso_seconds(ts) == expected
