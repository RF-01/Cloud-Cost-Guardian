"""Dashboard Flask app on moto tables: routes, JSON shapes, escaping, headers, read-only allowlist."""

import json
from datetime import datetime, timezone
from decimal import Decimal

import boto3
import pytest
from boto3.dynamodb.types import TypeSerializer
from moto import mock_aws

from dashboard.web import create_app
from dashboard.web.store import ALLOWED_CALLS, ForbiddenCall, ReadOnlyDynamo, Store, TTLCache

PREFIX = "cg-test-"
REGION = "us-west-2"
NOW = datetime(2026, 11, 23, 18, 0, 0, tzinfo=timezone.utc)
NAMES = {"findings": PREFIX + "findings", "audit": PREFIX + "audit", "daily_summaries": PREFIX + "daily-summaries",
         "bill_history": PREFIX + "bill-history", "budget_alerts": PREFIX + "budget-alerts"}
TABLE_TO_LOGICAL = {v: k for k, v in NAMES.items()}
HOSTILE = '<script>alert("x")</script><img src=x onerror=alert(1)>'
_ser = TypeSerializer()


class AllowlistClient:
    """Wraps the real (moto) client and FAILS the test on any DynamoDB operation outside the allowlist."""

    def __init__(self, inner):
        self._inner = inner
        self.calls = []

    def __getattr__(self, op):
        def call(**params):
            if op == "batch_get_item":
                tables = list(params["RequestItems"])
            else:
                tables = [params.get("TableName")]
            for t in tables:
                logical = TABLE_TO_LOGICAL.get(t)
                if (op, logical) not in ALLOWED_CALLS:
                    pytest.fail(f"dashboard made a forbidden DynamoDB call: {op} on {t}")
                if op == "query" and logical == "audit" and params.get("IndexName") != "byDay":
                    pytest.fail("audit queried without the byDay index")
                self.calls.append((op, logical))
            return getattr(self._inner, op)(**params)
        if op.startswith("_") or op in ("get_paginator", "get_waiter", "meta"):
            pytest.fail(f"dashboard used {op}")
        return call


@pytest.fixture
def env(monkeypatch, make_tables):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    with mock_aws():
        raw = make_tables(PREFIX)
        guarded = AllowlistClient(boto3.client("dynamodb", region_name=REGION))
        store = Store(NAMES, client=guarded)
        app = create_app(store=store, now=lambda: NOW, name_prefix=PREFIX)
        yield {"raw": raw, "client": app.test_client(), "guard": guarded, "store": store}


def put(raw, table, item):
    raw.put_item(TableName=PREFIX + table, Item={k: _ser.serialize(v) for k, v in item.items()})


def D(x):
    return Decimal(str(x))


def seed_real(raw):
    put(raw, "findings", {"resourceId": "i-0e30", "findingType": "EC2_IDLE", "status": "in_progress",
                          "region": "us-west-2", "owner": "alice@example.com", "project": "cost-guardian",
                          "name": "cg-test-idle", "estimatedMonthlyCost": D("11.24"),
                          "firstSeenAt": "2026-11-23T08:00:00Z", "timelineStep": "waiting",
                          "deadlineAt": "2026-11-25T08:00:00Z", "generation": D(1),
                          "executionArn": "arn:aws:states:us-west-2:123456789012:execution:cg-test-ec2-timeline:"
                                          "ec2-i-0e30-gen1"})
    put(raw, "findings", {"resourceId": "vol-1", "findingType": "EBS_UNATTACHED", "status": "open",
                          "region": "us-east-1", "firstSeenAt": "2026-11-22T00:00:00Z"})
    put(raw, "findings", {"resourceId": "i-rem", "findingType": "EC2_IDLE", "status": "remediated",
                          "region": "us-west-2", "realizedMonthlySavings": D("9.5"), "dryRun": True,
                          "remediatedAt": "2026-11-22T14:40:38Z"})
    put(raw, "findings", {"resourceId": "i-old", "findingType": "EC2_IDLE", "status": "resolved",
                          "region": "us-west-2"})
    put(raw, "daily-summaries", {"day": "2026-11-22", "totalMonthlyWaste": D("11.24"),
                                 "realizedMonthlySavings": D(0), "potentialMonthlySavings": D("20.74"),
                                 "countsByType": {"EC2_IDLE": D(1), "EBS_UNATTACHED": D(1)},
                                 "wasteByRegion": {"us-west-2": D("11.24"), "us-east-1": D(0)},
                                 "wasteByOwner": {"alice@example.com": D("11.24"), "unknown": D(0)},
                                 "wasteByProject": {"cost-guardian": D("11.24"), "untagged": D(0)},
                                 "openFindings": D(2), "warningsSent": D(2), "actionsTaken": D(1),
                                 "actionsTakenDryRun": D(1), "createdAt": "2026-11-22T23:50:00Z"})
    put(raw, "audit", {"resourceId": "i-0e30", "ts": "2026-11-23T13:57:34Z#4e688cb6", "day": "2026-11-23",
                       "actor": "notify", "event": "notice_sent", "findingType": "EC2_IDLE", "region": "us-west-2",
                       "generation": D(1), "result": "ok", "details": {"template": "FIRST_NOTICE"}})
    put(raw, "audit", {"resourceId": "i-0e30", "ts": "2026-11-23T09:00:00Z#00000001", "day": "2026-11-23",
                       "actor": "scanner", "event": "finding_opened", "findingType": "EC2_IDLE",
                       "region": "us-west-2", "result": "ok"})
    for key, amount in (("total", "0.5112"), ("service#Amazon Elastic Compute Cloud - Compute", "0.4"),
                        ("service#EC2 - Other", "0.1112"), ("project#untagged", "0.3"),
                        ("project#cost-guardian", "0.2112")):
        put(raw, "bill-history", {"day": "2026-11-22", "key": key, "amount": D(amount), "estimated": True,
                                  "fetchedAt": "2026-11-23T16:28:22Z"})


ROUTES = ["/", "/api/findings", "/api/summaries", "/api/summaries?days=7", "/api/summaries?days=90",
          "/api/bill", "/api/bill?days=90", "/api/activity", "/api/activity?weeks=12", "/api/budgets", "/healthz"]


# ---------------------------------------------------------------- empty stack


def test_empty_tables_every_route_200_with_empty_states(env):
    c = env["client"]
    for route in ROUTES:
        assert c.get(route).status_code == 200, route
    page = c.get("/").get_data(as_text=True)
    for text in ("No daily summary yet", "No active findings", "No failed timelines", "Nothing remediated yet",
                 "No report-only findings", "No audit entries in the last 7 days",
                 "No budget alerts received yet (budgets and the alert subscriber come with #37)"):
        assert text in page
    f = c.get("/api/findings").get_json()
    assert f["active"] == [] and f["resolvedCount"] == 0 and f["total"] == 0
    s = c.get("/api/summaries").get_json()
    assert s["kpi"] is None and s["latest"] is None and len(s["series"]) == 30
    assert all(p["present"] is False for p in s["series"])
    b = c.get("/api/bill").get_json()
    assert b["hasData"] is False and b["total"] == [None] * 30 and b["to"] == "2026-11-22"
    a = c.get("/api/activity").get_json()
    assert len(a["weeks"]) == 8 and a["recent"] == []
    assert c.get("/api/budgets").get_json()["alerts"] == []


def test_healthz_makes_no_aws_calls():
    class Exploding:
        def __getattr__(self, name):
            raise AssertionError(f"healthz touched DynamoDB ({name})")
    app = create_app(store=Store(NAMES, client=Exploding()), now=lambda: NOW, name_prefix=PREFIX)
    resp = app.test_client().get("/healthz")
    assert resp.status_code == 200 and resp.get_json() == {"status": "ok"}


# ---------------------------------------------------------------- real data, shapes


def test_json_shapes_and_decimal_as_numbers(env):
    seed_real(env["raw"])
    c = env["client"]
    resp = c.get("/api/findings")
    assert '"estimatedMonthlyCost":11.24' in resp.get_data(as_text=True).replace(" ", "")
    f = resp.get_json()
    assert set(f) >= {"active", "failed", "remediated", "reportOnly", "resolvedCount", "options", "filters",
                      "generatedAt"}
    assert f["generatedAt"] == "2026-11-23T18:00:00Z"
    top = f["active"][0]
    assert top["resourceId"] == "i-0e30" and top["estimatedMonthlyCost"] == 11.24
    assert top["costSoFar"] == round(11.24 / 730 * 10, 2)           # 10 h since firstSeenAt
    assert top["executionUrl"].endswith("execution:cg-test-ec2-timeline:ec2-i-0e30-gen1")
    assert f["active"][1]["owner"] == "unknown" and f["active"][1]["estimatedMonthlyCost"] is None
    assert f["remediated"][0]["realizedMonthlySavings"] == 9.5 and f["resolvedCount"] == 1

    s = c.get("/api/summaries?days=7").get_json()
    assert s["kpi"] == {"day": "2026-11-22", "sample": False, "createdAt": "2026-11-22T23:50:00Z",
                        "totalMonthlyWaste": 11.24, "potentialMonthlySavings": 20.74,
                        "realizedMonthlySavings": 0, "openFindings": 2}
    assert isinstance(s["kpi"]["openFindings"], int)
    assert s["latest"]["wasteByRegion"][0] == {"label": "us-west-2", "value": 11.24}
    assert s["units"] == "estimated, USD/month"

    b = c.get("/api/bill?days=7").get_json()
    assert b["total"][-1] == 0.5112 and b["estimatedDays"] == ["2026-11-22"]
    assert [p["name"] for p in b["projects"]] == ["untagged", "cost-guardian"]
    assert b["costExplorerUrl"].startswith("https://")

    a = c.get("/api/activity").get_json()
    assert a["weeks"][-1]["findingsOpened"] == 1 and a["weeks"][-1]["week"] == "2026-W48"
    assert [r["event"] for r in a["recent"]] == ["notice_sent", "finding_opened"]     # newest first
    assert a["recent"][0]["details"] == {"template": "FIRST_NOTICE"}

    page = c.get("/").get_data(as_text=True)
    assert "cg-test-idle" in page and "estimated, USD/month" in page and "$11.24" in page
    assert "https://us-west-2.console.aws.amazon.com/states/home?region=us-west-2" in page
    assert "not estimated" in page and "Resolved findings: <strong>1</strong>" in page


def test_filters_on_page_and_api(env):
    seed_real(env["raw"])
    c = env["client"]
    assert [r["resourceId"] for r in c.get("/api/findings?region=us-east-1").get_json()["active"]] == ["vol-1"]
    assert [r["resourceId"] for r in c.get("/api/findings?owner=unknown").get_json()["active"]] == ["vol-1"]
    assert c.get("/api/findings?status=remediated").get_json()["active"] == []
    page = c.get("/?status=in_progress").get_data(as_text=True)
    assert "i-0e30" in page and "vol-1</code>" not in page


@pytest.mark.parametrize("route", ["/api/summaries?days=14", "/api/summaries?days=x", "/api/bill?days=0",
                                   "/api/bill?days=91", "/api/activity?weeks=13"])
def test_bad_parameters_400(env, route):
    assert env["client"].get(route).status_code == 400


# ---------------------------------------------------------------- KPI + sample flags


def test_kpi_uses_real_summary_over_newer_sample(env):
    raw = env["raw"]
    put(raw, "daily-summaries", {"day": "2026-11-20", "totalMonthlyWaste": D("1.5"), "openFindings": D(1)})
    put(raw, "daily-summaries", {"day": "2026-11-22", "totalMonthlyWaste": D("7.77"), "openFindings": D(4),
                                 "sample": True})
    s = env["client"].get("/api/summaries?days=7").get_json()
    assert s["kpi"]["day"] == "2026-11-20" and s["kpi"]["sample"] is False
    page = env["client"].get("/").get_data(as_text=True)
    assert "$1.50" in page and "$7.77" not in page


def test_kpi_falls_back_to_sample_and_labels_it(env):
    put(env["raw"], "daily-summaries", {"day": "2026-11-22", "totalMonthlyWaste": D("7.77"), "sample": True})
    s = env["client"].get("/api/summaries").get_json()
    assert s["kpi"]["sample"] is True and s["latest"]["sample"] is True
    page = env["client"].get("/").get_data(as_text=True)
    assert "$7.77" in page and "Sample data (demo seed), not real" in page and "is-sample" in page


def test_sample_flagged_in_series_weeks_and_activity(env):
    raw = env["raw"]
    put(raw, "daily-summaries", {"day": "2026-11-21", "totalMonthlyWaste": D(3), "warningsSent": D(2),
                                 "actionsTaken": D(1), "actionsTakenDryRun": D(1), "sample": True})
    put(raw, "daily-summaries", {"day": "2026-11-23", "totalMonthlyWaste": D(2)})
    put(raw, "audit", {"resourceId": "sample-i-0001", "ts": "2026-11-21T10:00:00Z#abcdef01", "day": "2026-11-21",
                       "actor": "sample-seed", "event": "finding_opened", "result": "ok", "sample": True,
                       "details": {"note": "demo seed"}})
    c = env["client"]
    s = c.get("/api/summaries?days=7").get_json()
    flags = {p["day"]: p["sample"] for p in s["series"] if p["present"]}
    assert flags == {"2026-11-21": True, "2026-11-23": False} and s["sampleInRange"] is True
    a = c.get("/api/activity").get_json()
    w47 = next(w for w in a["weeks"] if w["week"] == "2026-W47")
    assert w47["sample"] is True and w47["findingsOpenedSample"] == 1 and w47["warningsSent"] == 2
    assert a["weeks"][-1]["sample"] is False
    assert a["recent"][0]["sample"] is True and a["recent"][0]["actor"] == "sample-seed"
    page = c.get("/").get_data(as_text=True)
    assert 'class="row-sample"' in page and "badge-sample" in page


# ---------------------------------------------------------------- escaping


def test_hostile_text_is_escaped_and_never_inlined_in_js(env):
    raw = env["raw"]
    put(raw, "findings", {"resourceId": "i-evil", "findingType": "EC2_IDLE", "status": "failed",
                          "region": "us-west-2", "name": HOSTILE, "owner": HOSTILE, "project": HOSTILE,
                          "errorMessage": HOSTILE, "failedStep": HOSTILE, "estimatedMonthlyCost": D(1)})
    put(raw, "audit", {"resourceId": "i-evil", "ts": "2026-11-23T10:00:00Z#00000002", "day": "2026-11-23",
                       "actor": "workflow", "event": "workflow_failed", "result": "error",
                       "details": {"errorMessage": HOSTILE, "x": "</script><script>alert(2)</script>"}})
    put(raw, "budget-alerts", {"budgetName": HOSTILE, "receivedAt": "2026-11-23T01:00:00Z", "message": HOSTILE})
    page = env["client"].get("/").get_data(as_text=True)
    assert "<script>alert" not in page and "<img src=x" not in page and "</script><script>" not in page
    assert "&lt;script&gt;alert(" in page and "&lt;img src=x onerror=alert(1)&gt;" in page
    # the only <script> tags are the JSON config block and two same-origin files
    assert page.count("<script") == 3
    assert '<script type="application/json" id="page-config">' in page
    config_block = page.split('id="page-config">', 1)[1].split("</script>", 1)[0]
    assert "alert" not in config_block
    # JSON API carries the text as data (escaped by the JSON encoder, served as application/json)
    resp = env["client"].get("/api/findings")
    assert resp.mimetype == "application/json"
    assert resp.get_json()["failed"][0]["errorMessage"] == HOSTILE


def test_owner_filter_value_is_escaped_when_echoed(env):
    page = env["client"].get("/?owner=" + "%22%3E%3Cscript%3Ealert(1)%3C/script%3E").get_data(as_text=True)
    assert "<script>alert(1)" not in page


# ---------------------------------------------------------------- headers + methods


def test_security_headers_on_every_response(env):
    for route in ["/", "/api/findings", "/healthz", "/static/app.js", "/nope"]:
        h = env["client"].get(route).headers
        csp = h["Content-Security-Policy"]
        assert "default-src 'self'" in csp and "unsafe-inline" not in csp and "http" not in csp
        assert h["X-Content-Type-Options"] == "nosniff"
        assert h["Referrer-Policy"] == "no-referrer"
        assert h["X-Frame-Options"] == "DENY"


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete", "options"])
@pytest.mark.parametrize("route", ["/", "/api/findings", "/api/summaries", "/healthz", "/static/app.js"])
def test_non_get_methods_405(env, method, route):
    resp = getattr(env["client"], method)(route)
    assert resp.status_code == 405
    assert env["guard"].calls == []        # nothing read, nothing written


def test_static_vendor_chart_js_served(env):
    resp = env["client"].get("/static/vendor/chart.umd.min.js")
    assert resp.status_code == 200 and b"Chart.js v4." in resp.data[:200] and b"MIT License" in resp.data[:200]


# ---------------------------------------------------------------- read-only allowlist


def test_only_allowlisted_dynamodb_calls_across_all_routes(env):
    seed_real(env["raw"])
    for route in ROUTES + ["/?status=open&region=us-west-2&owner=unknown"]:
        assert env["client"].get(route).status_code == 200, route
    seen = set(env["guard"].calls)
    assert seen <= ALLOWED_CALLS
    assert seen == ALLOWED_CALLS          # and every allowed call is actually exercised


@pytest.mark.parametrize("op,table", [("put_item", "findings"), ("update_item", "counters"),
                                      ("delete_item", "audit"), ("scan", "audit"), ("query", "findings"),
                                      ("batch_write_item", "daily_summaries"), ("get_item", "findings"),
                                      ("scan", "tokens")])
def test_read_only_wrapper_refuses_other_calls(op, table):
    db = ReadOnlyDynamo(client=None, table_names={**NAMES, "tokens": PREFIX + "tokens", "counters": "c"})
    with pytest.raises(ForbiddenCall):
        db._check(op, PREFIX + table.replace("_", "-") if table != "counters" else "c", {})


def test_audit_query_without_index_refused():
    db = ReadOnlyDynamo(client=None, table_names=NAMES)
    with pytest.raises(ForbiddenCall):
        db.query_day("audit", "2026-11-23")          # no IndexName


# ---------------------------------------------------------------- store: pagination, batch, cache


class FakeClient:
    def __init__(self):
        self.calls = []

    def scan(self, **p):
        self.calls.append(("scan", p))
        if "ExclusiveStartKey" not in p:
            return {"Items": [{"resourceId": {"S": "a"}, "estimatedMonthlyCost": {"N": "1.50"}}],
                    "LastEvaluatedKey": {"resourceId": {"S": "a"}}}
        return {"Items": [{"resourceId": {"S": "b"}, "generation": {"N": "2"}}]}

    def batch_get_item(self, RequestItems):
        self.calls.append(("batch_get_item", RequestItems))
        table = next(iter(RequestItems))
        keys = RequestItems[table]["Keys"]
        if len(self.calls) == 1:      # first round: return one, leave the rest unprocessed
            return {"Responses": {table: [{"day": keys[0]["day"]}]},
                    "UnprocessedKeys": {table: {"Keys": keys[1:]}}}
        return {"Responses": {table: [{"day": k["day"]} for k in keys]}, "UnprocessedKeys": {}}


def test_scan_paginates_and_converts_numbers():
    fake = FakeClient()
    items = ReadOnlyDynamo(fake, NAMES).scan("findings")
    assert items == [{"resourceId": "a", "estimatedMonthlyCost": 1.5}, {"resourceId": "b", "generation": 2}]
    assert isinstance(items[1]["generation"], int) and len(fake.calls) == 2


def test_batch_get_retries_unprocessed_keys_and_chunks_by_100():
    fake = FakeClient()
    days = [f"2026-{m:02d}-{d:02d}" for m in (8, 9, 10, 11) for d in range(1, 29)][:105]
    got = ReadOnlyDynamo(fake, NAMES).batch_get_days("daily_summaries", days, sleep=lambda s: None)
    assert sorted(i["day"] for i in got) == sorted(days)
    assert all(len(rq[NAMES["daily_summaries"]]["Keys"]) <= 100 for _, rq in fake.calls)


def test_findings_cached_30s_other_300s():
    t = [1000.0]
    fake = FakeClient()
    store = Store(NAMES, client=fake, cache=TTLCache(clock=lambda: t[0]))
    store.findings(); store.findings()
    assert len(fake.calls) == 2                     # one paginated scan (2 pages)
    t[0] += 29
    store.findings()
    assert len(fake.calls) == 2
    t[0] += 2
    store.findings()
    assert len(fake.calls) == 4


def test_cache_does_not_store_errors():
    cache = TTLCache(clock=lambda: 0.0)
    calls = []

    def boom():
        calls.append(1)
        raise RuntimeError("x")

    for _ in range(2):
        with pytest.raises(RuntimeError):
            cache.get("k", 300, boom)
    assert len(calls) == 2


def test_dynamo_error_gives_502_json_and_page_still_renders():
    class Failing:
        def __getattr__(self, name):
            def call(**_):
                raise RuntimeError("AccessDenied")
            return call
    app = create_app(store=Store(NAMES, client=Failing()), now=lambda: NOW, name_prefix=PREFIX)
    c = app.test_client()
    resp = c.get("/api/findings")
    assert resp.status_code == 502 and resp.get_json() == {"error": "data_unavailable"}
    page = c.get("/")
    assert page.status_code == 200 and "Data temporarily unavailable." in page.get_data(as_text=True)
    assert "AccessDenied" not in page.get_data(as_text=True)


def test_table_names_from_env_prefix_and_overrides():
    from dashboard.web.store import table_names_from_env
    names = table_names_from_env({"NAME_PREFIX": "cg-dev-", "TABLE_AUDIT": "custom-audit"})
    assert names["findings"] == "cg-dev-findings" and names["audit"] == "custom-audit"
    assert names["daily_summaries"] == "cg-dev-daily-summaries" and names["budget_alerts"] == "cg-dev-budget-alerts"
    with pytest.raises(ValueError):
        table_names_from_env({})


def test_json_dumps_round_trip_has_no_decimal_strings(env):
    seed_real(env["raw"])
    body = json.loads(env["client"].get("/api/summaries").get_data(as_text=True))
    assert isinstance(body["kpi"]["totalMonthlyWaste"], float)
