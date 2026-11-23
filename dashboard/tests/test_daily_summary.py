import importlib.util
import json
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

HANDLER = Path(__file__).resolve().parents[1] / "src" / "daily_summary" / "handler.py"
REGION = "us-west-2"
T_FINDINGS = "cg-test-findings"
T_AUDIT = "cg-test-audit"
T_SUMMARIES = "cg-test-daily-summaries"
NOW = datetime(2026, 11, 23, 23, 50, 0, tzinfo=timezone.utc)
DAY = "2026-11-23"
EVENT = {"source": "schedule", "job": "daily-summary"}


def load_handler():
    # Load by path: every Lambda's file is called handler.py, so a plain import would collide.
    spec = importlib.util.spec_from_file_location("dashboard_daily_summary_handler", HANDLER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ds = load_handler()


# ---------------------------------------------------------------- fixtures / helpers


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("TABLE_FINDINGS", T_FINDINGS)
    monkeypatch.setenv("TABLE_AUDIT", T_AUDIT)
    monkeypatch.setenv("TABLE_DAILY_SUMMARIES", T_SUMMARIES)
    monkeypatch.setattr(ds, "_now", lambda: NOW)
    monkeypatch.setattr(ds, "PAGE_LIMIT", None)
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name=REGION)
        findings = ddb.create_table(
            TableName=T_FINDINGS,
            KeySchema=[{"AttributeName": "resourceId", "KeyType": "HASH"},
                       {"AttributeName": "findingType", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "resourceId", "AttributeType": "S"},
                                  {"AttributeName": "findingType", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        audit = ddb.create_table(
            TableName=T_AUDIT,
            KeySchema=[{"AttributeName": "resourceId", "KeyType": "HASH"},
                       {"AttributeName": "ts", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "resourceId", "AttributeType": "S"},
                                  {"AttributeName": "ts", "AttributeType": "S"},
                                  {"AttributeName": "day", "AttributeType": "S"}],
            GlobalSecondaryIndexes=[{
                "IndexName": "byDay",
                "KeySchema": [{"AttributeName": "day", "KeyType": "HASH"},
                              {"AttributeName": "ts", "KeyType": "RANGE"}],
                "Projection": {"ProjectionType": "ALL"},
            }],
            BillingMode="PAY_PER_REQUEST",
        )
        summaries = ddb.create_table(
            TableName=T_SUMMARIES,
            KeySchema=[{"AttributeName": "day", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "day", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield {"findings": findings, "audit": audit, "summaries": summaries}


_counter = {"n": 0}


def finding(rid, ftype="EC2_IDLE", status="open", cost=None, region="us-east-1",
            owner="alice@example.com", project="alpha", **extra):
    item = {"resourceId": rid, "findingType": ftype, "status": status, "region": region}
    if cost is not None:
        item["estimatedMonthlyCost"] = Decimal(cost)
    if owner is not None:
        item["owner"] = owner
    if project is not None:
        item["project"] = project
    for k, v in extra.items():
        item[k] = Decimal(v) if isinstance(v, str) and k.endswith("Savings") else v
    return item


def audit_entry(event, day=DAY, dry_run=None, rid="i-1"):
    _counter["n"] += 1
    item = {"resourceId": rid, "ts": f"{day}T12:00:00Z#{_counter['n']:08d}", "day": day,
            "event": event, "actor": "remediation", "result": "ok"}
    if dry_run is not None:
        item["dryRun"] = dry_run
    return item


def put_all(table, items):
    with table.batch_writer() as bw:
        for it in items:
            bw.put_item(Item=it)


def run(aws):
    ds.handler(EVENT, None)
    return aws["summaries"].get_item(Key={"day": DAY})["Item"]


# ---------------------------------------------------------------- pure counting


def test_status_membership_in_each_sum():
    s = ds.summarize_findings([
        finding("i-open", status="open", cost="10"),
        finding("i-prog", status="in_progress", cost="20"),
        finding("i-fail", status="failed", cost="40"),
        finding("i-res", status="resolved", cost="80"),
        finding("i-rem", status="remediated", cost="160", dryRun=False, realizedMonthlySavings="150"),
    ])
    assert s["totalMonthlyWaste"] == Decimal("70.00")          # open + in_progress + failed
    assert s["potentialMonthlySavings"] == Decimal("30.00")    # open + in_progress (failed not)
    assert s["realizedMonthlySavings"] == Decimal("150.00")    # real remediated only
    assert s["openFindings"] == 3
    assert s["countsByType"] == {"EC2_IDLE": 3}


def test_resolved_ignored_entirely():
    s = ds.summarize_findings([finding("i-res", status="resolved", cost="80", owner="bob@example.com",
                                       ftype="EBS_UNATTACHED")])
    assert s["totalMonthlyWaste"] == 0 and s["potentialMonthlySavings"] == 0 and s["realizedMonthlySavings"] == 0
    assert s["countsByType"] == {} and s["openFindings"] == 0
    assert s["wasteByOwner"] == {} and s["wasteByRegion"] == {} and s["wasteByProject"] == {}


def test_missing_tags_excluded_from_waste_but_counted():
    s = ds.summarize_findings([
        finding("i-1", ftype="MISSING_TAGS", status="open", cost="99", missingTags=["owner"]),
        finding("i-1", ftype="EC2_IDLE", status="open", cost="5"),
    ])
    assert s["totalMonthlyWaste"] == Decimal("5.00")
    assert s["potentialMonthlySavings"] == Decimal("5.00")
    assert s["countsByType"] == {"MISSING_TAGS": 1, "EC2_IDLE": 1}
    assert s["openFindings"] == 2
    assert s["wasteByRegion"] == {"us-east-1": Decimal("5.00")}


def test_report_only_in_waste_not_in_potential():
    s = ds.summarize_findings([
        finding("eipalloc-1", ftype="EIP_UNASSOCIATED", status="open", cost="3.65", reportOnlyReason="protected"),
        finding("i-2", status="open", cost="10", reportOnlyReason="autoscaling"),
        finding("vol-1", ftype="EBS_UNATTACHED", status="in_progress", cost="4"),
    ])
    assert s["totalMonthlyWaste"] == Decimal("17.65")
    assert s["potentialMonthlySavings"] == Decimal("4.00")


def test_dry_run_vs_real_remediated():
    s = ds.summarize_findings([
        finding("i-real", status="remediated", cost="30", dryRun=False, realizedMonthlySavings="25"),
        finding("i-dry", status="remediated", cost="30", dryRun=True, realizedMonthlySavings="12"),
        finding("i-dry2", status="remediated", cost="7", dryRun=True),  # no realized -> estimate
    ])
    assert s["realizedMonthlySavings"] == Decimal("25.00")
    assert s["potentialMonthlySavings"] == Decimal("19.00")
    assert s["totalMonthlyWaste"] == 0
    assert s["openFindings"] == 0 and s["countsByType"] == {}


def test_remediated_without_dry_run_counts_as_dry_run():
    s = ds.summarize_findings([
        finding("i-a", status="remediated", cost="30", realizedMonthlySavings="12"),
        finding("i-b", status="remediated", cost="7"),
    ])
    assert s["realizedMonthlySavings"] == Decimal("0.00")
    assert s["potentialMonthlySavings"] == Decimal("19.00")


def test_snapshot_reminder_not_waste_but_counted():
    s = ds.summarize_findings([
        finding("snap-1", ftype="SNAPSHOT_REMINDER", status="open", cost="2.50"),
        finding("snap-2", ftype="SNAPSHOT_REMINDER", status="failed", cost="1"),
        finding("vol-1", ftype="EBS_UNATTACHED", status="open", cost="4"),
    ])
    assert s["totalMonthlyWaste"] == Decimal("4.00")
    assert s["potentialMonthlySavings"] == Decimal("4.00")
    assert s["wasteByRegion"] == {"us-east-1": Decimal("4.00")}
    assert s["wasteByOwner"] == {"alice@example.com": Decimal("4.00")}
    assert s["wasteByProject"] == {"alpha": Decimal("4.00")}
    assert s["countsByType"] == {"SNAPSHOT_REMINDER": 2, "EBS_UNATTACHED": 1}
    assert s["openFindings"] == 3


def test_unknown_owner_and_untagged_project():
    s = ds.summarize_findings([
        finding("i-1", status="open", cost="1", owner=None, project=None),
        finding("i-2", status="failed", cost="2", owner="bob@example.com", project=None, region="eu-west-1"),
        finding("i-3", status="open", cost="4"),
    ])
    assert s["wasteByOwner"] == {"unknown": Decimal("1.00"), "bob@example.com": Decimal("2.00"),
                                 "alice@example.com": Decimal("4.00")}
    assert s["wasteByProject"] == {"untagged": Decimal("3.00"), "alpha": Decimal("4.00")}
    assert s["wasteByRegion"] == {"us-east-1": Decimal("5.00"), "eu-west-1": Decimal("2.00")}


def test_missing_estimate_counts_zero():
    s = ds.summarize_findings([finding("i-1", status="open")])
    assert s["totalMonthlyWaste"] == Decimal("0.00")
    assert s["wasteByOwner"] == {"alice@example.com": Decimal("0.00")}
    assert s["openFindings"] == 1


def test_rounding_two_decimals_at_the_end():
    s = ds.summarize_findings([
        finding("i-1", status="open", cost="0.004"),
        finding("i-2", status="open", cost="0.004"),
        finding("i-3", status="open", cost="0.0025"),
    ])
    # Sum first (0.0105), then round -> 0.01; rounding each first would give 0.00.
    assert s["totalMonthlyWaste"] == Decimal("0.01")
    assert str(s["totalMonthlyWaste"]) == "0.01"
    assert s["wasteByOwner"]["alice@example.com"] == Decimal("0.01")
    s2 = ds.summarize_findings([finding("i-1", status="open", cost="2.345")])
    assert s2["totalMonthlyWaste"] == Decimal("2.35")  # half up


def test_audit_counts():
    a = ds.summarize_audit([
        audit_entry("notice_sent"), audit_entry("final_warning_sent"), audit_entry("notice_sent"),
        audit_entry("instance_stopped", dry_run=True), audit_entry("volume_deleted", dry_run=False),
        audit_entry("volume_deleted", dry_run=True),
        audit_entry("snapshot_created", dry_run=True), audit_entry("email_fallback"),
        audit_entry("finding_opened"), audit_entry("workflow_failed"),
    ])
    assert a == {"warningsSent": 3, "actionsTaken": 3, "actionsTakenDryRun": 2}


# ---------------------------------------------------------------- handler (moto)


def test_handler_writes_one_item_for_today(aws, capsys):
    put_all(aws["findings"], [
        finding("i-1", status="open", cost="10.10"),
        finding("vol-1", ftype="EBS_UNATTACHED", status="in_progress", cost="4.20", owner="bob@example.com",
                project=None, region="us-west-2"),
        finding("i-1", ftype="MISSING_TAGS", status="open", missingTags=["project"]),
        finding("i-9", status="resolved", cost="100"),
        finding("vol-2", ftype="EBS_UNATTACHED", status="remediated", cost="8", dryRun=False,
                realizedMonthlySavings="6.5"),
    ])
    put_all(aws["audit"], [
        audit_entry("notice_sent"), audit_entry("final_warning_sent"),
        audit_entry("instance_stopped", dry_run=True), audit_entry("snapshot_created", dry_run=False),
        audit_entry("volume_deleted", dry_run=False),
        # Other days are ignored.
        audit_entry("notice_sent", day="2026-11-22"), audit_entry("instance_stopped", day="2026-11-24",
                                                                  dry_run=True),
    ])

    item = run(aws)
    assert item == {
        "day": DAY,
        "totalMonthlyWaste": Decimal("14.3"),
        "realizedMonthlySavings": Decimal("6.5"),
        "potentialMonthlySavings": Decimal("14.3"),
        "countsByType": {"EC2_IDLE": 1, "EBS_UNATTACHED": 1, "MISSING_TAGS": 1},
        "wasteByRegion": {"us-east-1": Decimal("10.1"), "us-west-2": Decimal("4.2")},
        "wasteByOwner": {"alice@example.com": Decimal("10.1"), "bob@example.com": Decimal("4.2")},
        "wasteByProject": {"alpha": Decimal("10.1"), "untagged": Decimal("4.2")},
        "openFindings": 3,
        "warningsSent": 2,
        "actionsTaken": 2,
        "actionsTakenDryRun": 1,
        "createdAt": "2026-11-23T23:50:00Z",
    }
    logs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(logs) == 1
    assert logs[0]["action"] == "daily_summary" and logs[0]["result"] == "ok"
    assert logs[0]["totalMonthlyWaste"] == 14.3 and logs[0]["openFindings"] == 3
    assert logs[0]["findingsRead"] == 5 and logs[0]["auditEntriesRead"] == 5


def test_empty_tables_give_zeros_and_empty_maps(aws):
    item = run(aws)
    assert item == {
        "day": DAY,
        "totalMonthlyWaste": Decimal("0"),
        "realizedMonthlySavings": Decimal("0"),
        "potentialMonthlySavings": Decimal("0"),
        "countsByType": {},
        "wasteByRegion": {},
        "wasteByOwner": {},
        "wasteByProject": {},
        "openFindings": 0,
        "warningsSent": 0,
        "actionsTaken": 0,
        "actionsTakenDryRun": 0,
        "createdAt": "2026-11-23T23:50:00Z",
    }


def test_pagination_of_both_reads(aws, monkeypatch):
    monkeypatch.setattr(ds, "PAGE_LIMIT", 2)
    put_all(aws["findings"], [finding(f"i-{n}", status="open", cost="1") for n in range(7)])
    put_all(aws["audit"], [audit_entry("notice_sent", rid=f"i-{n}") for n in range(5)]
            + [audit_entry("notice_sent", day="2026-11-22", rid="i-x")])

    # Count the actual pages by wrapping the table methods.
    pages = {"scan": 0, "query": 0}
    real_resource = ds.boto3.resource

    def resource(*args, **kwargs):
        res = real_resource(*args, **kwargs)
        real_table = res.Table

        def table(name):
            t = real_table(name)
            for op in ("scan", "query"):
                orig = getattr(t, op)

                def wrapped(*a, _orig=orig, _op=op, **kw):
                    pages[_op] += 1
                    return _orig(*a, **kw)
                setattr(t, op, wrapped)
            return t
        res.Table = table
        return res

    monkeypatch.setattr(ds.boto3, "resource", resource)
    item = run(aws)
    assert item["openFindings"] == 7
    assert item["totalMonthlyWaste"] == Decimal("7")
    assert item["warningsSent"] == 5
    assert pages["scan"] >= 4    # 7 items, 2 per page
    assert pages["query"] >= 3   # 5 items, 2 per page


def test_rerun_overwrites_same_day(aws, monkeypatch):
    put_all(aws["findings"], [finding("i-1", status="open", cost="10")])
    first = run(aws)
    assert first["totalMonthlyWaste"] == Decimal("10")

    aws["findings"].put_item(Item=finding("i-1", status="resolved", cost="10"))
    aws["audit"].put_item(Item=audit_entry("notice_sent"))
    later = datetime(2026, 11, 23, 23, 55, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(ds, "_now", lambda: later)
    second = run(aws)
    assert second["totalMonthlyWaste"] == Decimal("0")
    assert second["openFindings"] == 0
    assert second["warningsSent"] == 1
    assert second["createdAt"] == "2026-11-23T23:55:00Z"
    assert aws["summaries"].scan()["Count"] == 1


def test_errors_are_raised_and_logged(aws, monkeypatch, capsys):
    monkeypatch.setenv("TABLE_FINDINGS", "cg-test-does-not-exist")
    with pytest.raises(Exception):
        ds.handler(EVENT, None)
    log = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert log["result"] == "error" and log["day"] == DAY
    assert aws["summaries"].scan()["Count"] == 0
