"""dashboard/tools/seed_demo.py on moto: prefix guard, preview, never today / never overwrite, delete."""

import importlib.util
from datetime import date
from decimal import Decimal
from pathlib import Path

import boto3
import pytest
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from moto import mock_aws

TOOL = Path(__file__).resolve().parents[1] / "tools" / "seed_demo.py"
spec = importlib.util.spec_from_file_location("dashboard_seed_demo", TOOL)
seed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seed)

PREFIX = "cg-demo-"
REGION = "us-west-2"
TODAY = date(2026, 11, 23)
_ser, _de = TypeSerializer(), TypeDeserializer()

SUMMARY_KEYS = {"day", "totalMonthlyWaste", "realizedMonthlySavings", "potentialMonthlySavings", "countsByType",
                "wasteByRegion", "wasteByOwner", "wasteByProject", "openFindings", "warningsSent", "actionsTaken",
                "actionsTakenDryRun", "createdAt", "sample"}
SEEDED_EVENTS = {"finding_opened", "notice_sent", "final_warning_sent", "instance_stopped", "volume_deleted"}


class NoAws:
    def __getattr__(self, name):
        raise AssertionError(f"seed made an AWS call ({name}) when it must not")


def run(argv, client=None):
    lines = []
    code = seed.main(argv, client=client, today=TODAY, out=lines.append)
    return code, "\n".join(lines)


@pytest.fixture
def ddb(monkeypatch, make_tables):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    with mock_aws():
        make_tables(PREFIX)
        yield boto3.client("dynamodb", region_name=REGION)


def scan(client, table):
    items = client.scan(TableName=PREFIX + table)["Items"]
    return [{k: _de.deserialize(v) for k, v in i.items()} for i in items]


def put(client, table, item):
    client.put_item(TableName=PREFIX + table, Item={k: _ser.serialize(v) for k, v in item.items()})


# ---------------------------------------------------------------- guards


@pytest.mark.parametrize("prefix", ["cg-dev-", "cg-demo", "cg-demo-x", "CG-DEMO-", "", "cg-team-"])
@pytest.mark.parametrize("extra", [[], ["--yes"], ["--delete", "--yes"]])
def test_prefix_guard_refuses_anything_but_cg_demo(prefix, extra):
    code, out = run(["--prefix", prefix] + extra, client=NoAws())
    assert code == 2 and "REFUSED" in out


@pytest.mark.parametrize("days", ["0", "61", "-3"])
def test_days_limits(days):
    code, out = run(["--prefix", PREFIX, "--days", days, "--yes"], client=NoAws())
    assert code == 2 and "REFUSED" in out


def test_preview_without_yes_makes_no_aws_calls():
    code, out = run(["--prefix", PREFIX], client=NoAws())
    assert code == 0 and "PREVIEW" in out and "nothing written" in out
    assert "2026-11-02:" in out and "2026-11-22:" in out and "2026-11-23:" not in out
    assert "total: 21 summaries" in out


# ---------------------------------------------------------------- plan


def test_plan_is_deterministic_past_days_only_and_shaped_like_contract():
    a, b = seed.build_plan(TODAY, 21), seed.build_plan(TODAY, 21)
    assert a == b
    days = [e["day"] for e in a]
    assert days[0] == "2026-11-02" and days[-1] == "2026-11-22" and len(days) == 21
    assert all(d < TODAY.isoformat() for d in days)
    assert len(seed.build_plan(TODAY, 60)) == 60
    with pytest.raises(ValueError):
        seed.build_plan(TODAY, 61)
    for e in a:
        s = e["summary"]
        assert set(s) == SUMMARY_KEYS and s["sample"] is True and s["createdAt"] == f"{e['day']}T23:50:00Z"
        for field in ("totalMonthlyWaste", "realizedMonthlySavings", "potentialMonthlySavings"):
            assert isinstance(s[field], Decimal) and s[field] == s[field].quantize(Decimal("0.01"))
            assert Decimal(0) <= s[field] < Decimal(10)                  # small: cents to a few dollars
        for m in ("wasteByRegion", "wasteByOwner", "wasteByProject"):
            assert sum(s[m].values()) == s["totalMonthlyWaste"]
        assert "untagged" in s["wasteByProject"] and "unknown" in s["wasteByOwner"]
        assert s["openFindings"] == sum(s["countsByType"].values())


def test_audit_entries_consistent_with_summary_counts():
    for e in seed.build_plan(TODAY, 30):
        s, audit = e["summary"], e["audit"]
        events = [a["event"] for a in audit]
        assert set(events) <= SEEDED_EVENTS and "finding_opened" in events
        assert events.count("notice_sent") + events.count("final_warning_sent") == s["warningsSent"]
        acts = [a for a in audit if a["event"] in ("instance_stopped", "volume_deleted")]
        assert len(acts) == s["actionsTaken"]
        assert sum(1 for a in acts if a["dryRun"] is True) == s["actionsTakenDryRun"]
        for a in audit:
            assert a["actor"] == "sample-seed" and a["sample"] is True
            assert a["resourceId"].startswith("sample-") and a["details"] == {"note": "demo seed"}
            assert a["day"] == e["day"] and a["ts"].startswith(e["day"] + "T") and len(a["ts"].split("#")[1]) == 8
            assert a["result"] == "ok" and a["region"]
        assert len({a["ts"] for a in audit}) == len(audit)


def test_waste_trends_down_and_realized_up():
    plan = seed.build_plan(TODAY, 21)
    first, last = plan[:7], plan[-7:]
    avg = lambda rows, k: sum(r["summary"][k] for r in rows) / len(rows)  # noqa: E731
    assert avg(first, "totalMonthlyWaste") > avg(last, "totalMonthlyWaste") * 2
    assert avg(last, "realizedMonthlySavings") > avg(first, "realizedMonthlySavings") * 2


# ---------------------------------------------------------------- write


def test_write_never_overwrites_an_existing_day_and_never_writes_other_tables(ddb):
    real = {"day": "2026-11-20", "totalMonthlyWaste": Decimal("1.23"), "openFindings": 1,
            "createdAt": "2026-11-20T23:50:00Z"}
    put(ddb, "daily-summaries", real)
    code, out = run(["--prefix", PREFIX, "--yes"], client=ddb)
    assert code == 0 and "skipped (already had a summary): 2026-11-20" in out

    summaries = {s["day"]: s for s in scan(ddb, "daily-summaries")}
    assert len(summaries) == 21 and summaries["2026-11-20"] == real              # untouched, no sample flag
    assert "2026-11-23" not in summaries
    audit = scan(ddb, "audit")
    assert audit and all(a["sample"] is True for a in audit)
    assert not [a for a in audit if a["day"] == "2026-11-20"]                    # skipped day: no audit
    assert not [a for a in audit if a["day"] >= "2026-11-23"]
    plan = {e["day"]: e for e in seed.build_plan(TODAY, 21)}
    assert len(audit) == sum(len(e["audit"]) for d, e in plan.items() if d != "2026-11-20")
    for t in ("findings", "bill-history", "budget-alerts"):
        assert scan(ddb, t) == []

    # a re-run writes nothing new
    before = len(audit)
    code, out = run(["--prefix", PREFIX, "--yes"], client=ddb)
    assert "WROTE: 0 summaries, 0 audit entries" in out and len(scan(ddb, "audit")) == before


# ---------------------------------------------------------------- delete


def test_delete_removes_only_sample_rows(ddb):
    run(["--prefix", PREFIX, "--days", "10", "--yes"], client=ddb)
    # real rows on seeded days must survive
    put(ddb, "audit", {"resourceId": "i-real", "ts": "2026-11-21T10:00:00Z#12345678", "day": "2026-11-21",
                       "actor": "scanner", "event": "finding_opened", "result": "ok"})
    put(ddb, "audit", {"resourceId": "i-real", "ts": "2026-11-21T11:00:00Z#87654321", "day": "2026-11-21",
                       "actor": "scanner", "event": "finding_opened", "result": "ok", "sample": True})   # wrong actor
    put(ddb, "daily-summaries", {"day": "2026-11-23", "totalMonthlyWaste": Decimal("2")})                 # today, real
    put(ddb, "daily-summaries", {"day": "2026-11-01", "totalMonthlyWaste": Decimal("3"), "sample": False})
    seeded_audit = len([a for a in scan(ddb, "audit") if a.get("actor") == "sample-seed"])

    code, out = run(["--prefix", PREFIX, "--delete"], client=ddb)               # preview: nothing deleted
    assert code == 0 and "PREVIEW" in out and "summariesFound: 10" in out and f"auditFound: {seeded_audit}" in out
    assert len(scan(ddb, "daily-summaries")) == 12

    code, out = run(["--prefix", PREFIX, "--delete", "--yes"], client=ddb)
    assert code == 0 and "summariesDeleted: 10" in out and f"auditDeleted: {seeded_audit}" in out
    assert "realSummariesKept: 1" in out                                         # 2026-11-01 (today not in range)
    assert sorted(s["day"] for s in scan(ddb, "daily-summaries")) == ["2026-11-01", "2026-11-23"]
    left = scan(ddb, "audit")
    assert sorted(a["ts"] for a in left) == ["2026-11-21T10:00:00Z#12345678", "2026-11-21T11:00:00Z#87654321"]
