import importlib.util
import json
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from moto import mock_aws

HANDLER = Path(__file__).resolve().parents[1] / "src" / "daily_cost" / "handler.py"
REGION = "us-west-2"
TABLE = "cg-test-bill-history"
NOW = datetime(2026, 11, 23, 6, 15, 0, tzinfo=timezone.utc)
EVENT = {"source": "schedule", "job": "daily-cost"}


def load_handler():
    # Load by path: every Lambda's file is called handler.py, so a plain import would collide.
    spec = importlib.util.spec_from_file_location("dashboard_daily_cost_handler", HANDLER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dc = load_handler()


# ---------------------------------------------------------------- helpers


def day_result(day, groups, estimated=False):
    """One ResultsByTime entry. groups: {key: "amount string"}."""
    end = date.fromisoformat(day) + timedelta(days=1)
    return {
        "TimePeriod": {"Start": day, "End": end.isoformat()},
        "Total": {},
        "Groups": [{"Keys": [k], "Metrics": {"UnblendedCost": {"Amount": a, "Unit": "USD"}}}
                   for k, a in groups.items()],
        "Estimated": estimated,
    }


def expected_params(start, end, group_by, token=None):
    params = {
        "TimePeriod": {"Start": start, "End": end},
        "Granularity": "DAILY",
        "Metrics": ["UnblendedCost"],
        "Filter": {"Dimensions": {"Key": "RECORD_TYPE", "Values": ["Usage"]}},
        "GroupBy": [group_by],
    }
    if token:
        params["NextPageToken"] = token
    return params


SERVICE = {"Type": "DIMENSION", "Key": "SERVICE"}
PROJECT = {"Type": "TAG", "Key": "project"}


class FakeContext:
    pass


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("TABLE_BILL_HISTORY", TABLE)
    monkeypatch.setattr(dc, "_now", lambda: NOW)
    monkeypatch.setattr(dc.time, "sleep", lambda s: None)
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name=REGION)
        table = ddb.create_table(
            TableName=TABLE,
            KeySchema=[{"AttributeName": "day", "KeyType": "HASH"}, {"AttributeName": "key", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "day", "AttributeType": "S"},
                                  {"AttributeName": "key", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield table


@pytest.fixture
def ce(monkeypatch, aws):
    """A real Cost Explorer client (us-east-1) wrapped in a Stubber; boto3.client("ce") returns it."""
    client = boto3.client("ce", region_name="us-east-1")
    stubber = Stubber(client)
    real_client = boto3.client
    created = {}

    def fake_client(service, *args, **kwargs):
        if service == "ce":
            created["region"] = kwargs.get("region_name")
            return client
        return real_client(service, *args, **kwargs)

    monkeypatch.setattr(dc.boto3, "client", fake_client)
    with stubber:
        yield stubber, created
    stubber.assert_no_pending_responses()


def items(table):
    out = {}
    for it in table.scan()["Items"]:
        out[(it["day"], it["key"])] = it
    return out


# ---------------------------------------------------------------- days


def test_parse_days_default_and_bounds():
    assert dc.parse_days(EVENT) == 3
    assert dc.parse_days(None) == 3
    assert dc.parse_days({**EVENT, "days": 1}) == 1
    assert dc.parse_days({**EVENT, "days": 90}) == 90
    for bad in (0, -1, 91, "3", 2.5, True, None):
        with pytest.raises(ValueError):
            dc.parse_days({**EVENT, "days": bad})


def test_day_range_ends_yesterday_inclusive():
    start, end = dc.day_range(3, date(2026, 11, 23))
    assert start == date(2026, 11, 20)
    assert end == date(2026, 11, 23)  # exclusive in Cost Explorer: last day fetched is Nov 22


def test_bad_days_raises_before_any_call(ce):
    with pytest.raises(ValueError):
        dc.handler({**EVENT, "days": 91}, FakeContext())


# ---------------------------------------------------------------- full run


def test_rows_from_grouping_untagged_total_and_rounding(ce, aws):
    stubber, created = ce
    s, e = "2026-11-20", "2026-11-23"
    stubber.add_response("get_cost_and_usage", {"ResultsByTime": [
        day_result("2026-11-20", {"Amazon Elastic Compute Cloud - Compute": "0.123456",
                                  "Amazon DynamoDB": "0.00004", "AWS Lambda": "0"}),
        day_result("2026-11-21", {}),
        day_result("2026-11-22", {"Amazon Elastic Compute Cloud - Compute": "0.01005",
                                  "Amazon Simple Storage Service": "0.00025"}, estimated=True),
    ]}, expected_params(s, e, SERVICE))
    stubber.add_response("get_cost_and_usage", {"ResultsByTime": [
        day_result("2026-11-20", {"project$cost-guardian": "0.1", "project$": "0.023456"}),
        day_result("2026-11-21", {}),
        day_result("2026-11-22", {"project$": "0.0103"}, estimated=True),
    ]}, expected_params(s, e, PROJECT))

    out = dc.handler(EVENT, FakeContext())

    assert created["region"] == "us-east-1"
    assert out == {"days": ["2026-11-20", "2026-11-21", "2026-11-22"], "rowsWritten": 9, "requests": 2}
    got = items(aws)
    assert set(got) == {
        ("2026-11-20", "service#Amazon Elastic Compute Cloud - Compute"),
        ("2026-11-20", "project#cost-guardian"),
        ("2026-11-20", "project#untagged"),
        ("2026-11-20", "total"),
        ("2026-11-21", "total"),
        ("2026-11-22", "service#Amazon Elastic Compute Cloud - Compute"),
        ("2026-11-22", "service#Amazon Simple Storage Service"),
        ("2026-11-22", "project#untagged"),
        ("2026-11-22", "total"),
    }
    # 4 decimals, half up; DynamoDB (0.00004) and Lambda (0) are dropped: amount > 0 only.
    assert got[("2026-11-20", "service#Amazon Elastic Compute Cloud - Compute")]["amount"] == Decimal("0.1235")
    assert got[("2026-11-20", "project#untagged")]["amount"] == Decimal("0.0235")
    assert got[("2026-11-20", "total")]["amount"] == Decimal("0.1235")
    # A day with no spend still gets its total row.
    assert got[("2026-11-21", "total")]["amount"] == Decimal("0")
    assert got[("2026-11-22", "service#Amazon Elastic Compute Cloud - Compute")]["amount"] == Decimal("0.0101")
    assert got[("2026-11-22", "service#Amazon Simple Storage Service")]["amount"] == Decimal("0.0003")
    assert got[("2026-11-22", "total")]["amount"] == Decimal("0.0104")
    # estimated flag from Cost Explorer, BOOL in DynamoDB; fetchedAt ISO.
    assert got[("2026-11-20", "total")]["estimated"] is False
    assert got[("2026-11-22", "total")]["estimated"] is True
    assert got[("2026-11-22", "project#untagged")]["estimated"] is True
    assert all(it["fetchedAt"] == "2026-11-23T06:15:00Z" for it in got.values())


def test_pagination_merges_a_day_split_across_pages(ce, aws):
    stubber, _ = ce
    s, e = "2026-11-22", "2026-11-23"
    stubber.add_response("get_cost_and_usage", {
        "ResultsByTime": [day_result("2026-11-22", {"Amazon EC2": "0.5"})],
        "NextPageToken": "page2",
    }, expected_params(s, e, SERVICE))
    stubber.add_response("get_cost_and_usage", {
        "ResultsByTime": [day_result("2026-11-22", {"AWS Lambda": "0.25"})],
    }, expected_params(s, e, SERVICE, token="page2"))
    stubber.add_response("get_cost_and_usage", {
        "ResultsByTime": [day_result("2026-11-22", {"project$a": "0.5"})],
        "NextPageToken": "p2",
    }, expected_params(s, e, PROJECT))
    stubber.add_response("get_cost_and_usage", {
        "ResultsByTime": [day_result("2026-11-22", {"project$": "0.25"})],
    }, expected_params(s, e, PROJECT, token="p2"))

    out = dc.handler({**EVENT, "days": 1}, FakeContext())

    assert out["requests"] == 4
    got = items(aws)
    assert got[("2026-11-22", "service#Amazon EC2")]["amount"] == Decimal("0.5")
    assert got[("2026-11-22", "service#AWS Lambda")]["amount"] == Decimal("0.25")
    assert got[("2026-11-22", "total")]["amount"] == Decimal("0.75")
    assert got[("2026-11-22", "project#a")]["amount"] == Decimal("0.5")
    assert got[("2026-11-22", "project#untagged")]["amount"] == Decimal("0.25")


def test_rerun_overwrites_same_day_and_key(ce, aws):
    stubber, _ = ce
    s, e = "2026-11-22", "2026-11-23"
    aws.put_item(Item={"day": "2026-11-22", "key": "total", "amount": Decimal("9.9"), "estimated": True,
                       "fetchedAt": "2026-11-22T06:15:00Z"})
    stubber.add_response("get_cost_and_usage", {"ResultsByTime": [day_result("2026-11-22", {"Amazon EC2": "0.2"})]},
                         expected_params(s, e, SERVICE))
    stubber.add_response("get_cost_and_usage", {"ResultsByTime": [day_result("2026-11-22", {})]},
                         expected_params(s, e, PROJECT))

    dc.handler({**EVENT, "days": 1}, FakeContext())

    row = items(aws)[("2026-11-22", "total")]
    assert row["amount"] == Decimal("0.2")
    assert row["estimated"] is False
    assert row["fetchedAt"] == "2026-11-23T06:15:00Z"


def test_more_than_25_rows_are_batched(ce, aws, monkeypatch):
    stubber, _ = ce
    s, e = "2026-11-22", "2026-11-23"
    services = {f"Service {n:02d}": "0.01" for n in range(30)}
    stubber.add_response("get_cost_and_usage", {"ResultsByTime": [day_result("2026-11-22", services)]},
                         expected_params(s, e, SERVICE))
    stubber.add_response("get_cost_and_usage", {"ResultsByTime": [day_result("2026-11-22", {"project$": "0.3"})]},
                         expected_params(s, e, PROJECT))

    sizes = []
    real_batch = aws.meta.client.batch_write_item

    def spy(**kwargs):
        sizes.append(sum(len(v) for v in kwargs["RequestItems"].values()))
        return real_batch(**kwargs)

    monkeypatch.setattr(aws.meta.client, "batch_write_item", spy)
    # The handler builds its own Table; make it use the spied client.
    monkeypatch.setattr(dc.boto3, "resource", lambda *a, **k: type("R", (), {"Table": lambda self, n: aws})())

    out = dc.handler({**EVENT, "days": 1}, FakeContext())

    assert out["rowsWritten"] == 32  # 30 services + project#untagged + total
    assert sizes == [25, 7]
    got = items(aws)
    assert len(got) == 32
    assert got[("2026-11-22", "total")]["amount"] == Decimal("0.3")


def test_unprocessed_items_are_retried_then_raise():
    class FakeClient:
        def __init__(self, unprocessed_times):
            self.calls = 0
            self.unprocessed_times = unprocessed_times

        def batch_write_item(self, RequestItems):
            self.calls += 1
            if self.calls <= self.unprocessed_times:
                return {"UnprocessedItems": RequestItems}
            return {"UnprocessedItems": {}}

    class FakeTable:
        name = TABLE

        def __init__(self, client):
            self.meta = type("M", (), {"client": client})()

    rows = [{"day": "2026-11-22", "key": "total", "amount": Decimal("0"), "estimated": False, "fetchedAt": "x"}]
    orig_sleep = dc.time.sleep
    dc.time.sleep = lambda s: None
    try:
        ok = FakeClient(unprocessed_times=2)
        assert dc.write_rows(FakeTable(ok), rows) == 1
        assert ok.calls == 3
        with pytest.raises(RuntimeError):
            dc.write_rows(FakeTable(FakeClient(unprocessed_times=99)), rows)
    finally:
        dc.time.sleep = orig_sleep


def test_cost_explorer_error_raises_and_writes_nothing(ce, aws, capsys):
    stubber, _ = ce
    stubber.add_client_error("get_cost_and_usage", service_error_code="AccessDeniedException",
                             service_message="not allowed", http_status_code=400)

    with pytest.raises(ClientError):
        dc.handler(EVENT, FakeContext())

    assert items(aws) == {}
    assert '"result": "error"' in capsys.readouterr().out


def test_one_log_line_per_run(ce, aws, capsys):
    stubber, _ = ce
    s, e = "2026-11-22", "2026-11-23"
    stubber.add_response("get_cost_and_usage", {"ResultsByTime": [day_result("2026-11-22", {"Amazon EC2": "0.2"})]},
                         expected_params(s, e, SERVICE))
    stubber.add_response("get_cost_and_usage", {"ResultsByTime": [day_result("2026-11-22", {})]},
                         expected_params(s, e, PROJECT))

    dc.handler({**EVENT, "days": 1}, FakeContext())

    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["action"] == "daily_cost" and rec["result"] == "ok"
    assert rec["days"] == ["2026-11-22"]
    assert rec["rowsWritten"] == 2 and rec["requests"] == 2
    assert rec["totals"] == {"2026-11-22": 0.2}
