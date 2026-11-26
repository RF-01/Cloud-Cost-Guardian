"""Origin secret header check, REQUIRE_ORIGIN_SECRET, WARM_CACHE and the entry point (task #38)."""

import hmac
import json

import boto3
import pytest
from moto import mock_aws

import dashboard.web.__main__ as entry
from dashboard.web import app as app_module
from dashboard.web import create_app
from dashboard.web.app import origin_secret_from_env
from dashboard.web.store import Store

PREFIX = "cg-test-"
REGION = "us-west-2"
SECRET = "s3cr3t-origin-value-0123456789abcdef"
NAMES = {"findings": PREFIX + "findings", "audit": PREFIX + "audit", "daily_summaries": PREFIX + "daily-summaries",
         "bill_history": PREFIX + "bill-history", "budget_alerts": PREFIX + "budget-alerts"}
ROUTES = ["/", "/healthz", "/api/findings", "/api/summaries", "/api/bill", "/api/activity", "/api/budgets",
          "/static/app.js", "/static/style.css", "/static/vendor/chart.umd.min.js", "/no-such-page"]


@pytest.fixture
def aws(monkeypatch, make_tables):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    for var in ("ORIGIN_SECRET", "REQUIRE_ORIGIN_SECRET", "WARM_CACHE"):
        monkeypatch.delenv(var, raising=False)
    with mock_aws():
        make_tables(PREFIX)
        yield


class CountingClient:
    def __init__(self, inner, fail=False):
        self._inner, self.fail, self.calls = inner, fail, []

    def __getattr__(self, op):
        def call(**params):
            self.calls.append(op)
            if self.fail:
                raise RuntimeError("dynamodb down")
            return getattr(self._inner, op)(**params)
        return call


def make(secret, fail=False):
    client = CountingClient(boto3.client("dynamodb", region_name=REGION), fail=fail)
    budgets = CountingClient(boto3.client("budgets", region_name="us-east-1"), fail=fail)  # budget status (#43)
    store = Store(NAMES, client=client, workers=1, budgets_client=budgets)
    app = create_app(store=store, name_prefix=PREFIX, origin_secret=secret)
    return app, client


# ---------------------------------------------------------------- origin check


def test_every_route_needs_the_header(aws):
    app, client = make(SECRET)
    c = app.test_client()
    for route in ROUTES:
        for headers in ({}, {"X-Origin-Verify": "wrong"}, {"X-Origin-Verify": SECRET + "x"},
                        {"X-Origin-Verify": ""}, {"X-Origin-Verify": SECRET[:-1]}):
            r = c.get(route, headers=headers)
            assert r.status_code == 403, (route, headers)
            assert r.get_json() == {"error": "forbidden"}
            assert r.headers["Content-Security-Policy"].startswith("default-src 'self'")
            assert r.headers["Cache-Control"] == "no-store"
    assert client.calls == []  # refused before any data is read


def test_right_header_passes(aws):
    app, _ = make(SECRET)
    c = app.test_client()
    ok = {"X-Origin-Verify": SECRET}
    for route in ROUTES[:-1]:
        assert c.get(route, headers=ok).status_code == 200, route
    assert c.get("/no-such-page", headers=ok).status_code == 404
    assert c.head("/healthz", headers=ok).status_code == 200


def test_origin_check_runs_before_method_check(aws):
    app, _ = make(SECRET)
    c = app.test_client()
    assert c.post("/").status_code == 403
    assert c.delete("/api/findings").status_code == 403
    r = c.post("/", headers={"X-Origin-Verify": SECRET})
    assert r.status_code == 405 and r.headers["Allow"] == "GET, HEAD"


def test_uses_compare_digest(aws, monkeypatch):
    seen = []
    real = hmac.compare_digest

    def spy(a, b):
        seen.append((type(a), type(b)))
        return real(a, b)

    monkeypatch.setattr(app_module.hmac, "compare_digest", spy)
    app, _ = make(SECRET)
    app.test_client().get("/healthz", headers={"X-Origin-Verify": "nope"})
    assert seen == [(bytes, bytes)]


def test_non_ascii_header_is_refused_not_crashing(aws):
    app, _ = make(SECRET)
    r = app.test_client().get("/healthz", headers={"X-Origin-Verify": "caféÿ"})
    assert r.status_code == 403


def test_no_secret_means_no_check(aws):
    app, _ = make("")
    assert app.test_client().get("/healthz").status_code == 200


def test_secret_from_env_and_require(monkeypatch):
    assert origin_secret_from_env({}) == ""
    assert origin_secret_from_env({"ORIGIN_SECRET": SECRET}) == SECRET
    assert origin_secret_from_env({"ORIGIN_SECRET": SECRET, "REQUIRE_ORIGIN_SECRET": "1"}) == SECRET
    assert origin_secret_from_env({"REQUIRE_ORIGIN_SECRET": "0"}) == ""
    with pytest.raises(RuntimeError) as exc:
        origin_secret_from_env({"REQUIRE_ORIGIN_SECRET": "1"})
    assert "refusing to start" in str(exc.value)
    with pytest.raises(RuntimeError):
        origin_secret_from_env({"REQUIRE_ORIGIN_SECRET": "1", "ORIGIN_SECRET": ""})


def test_create_app_reads_env(aws, monkeypatch):
    monkeypatch.setenv("ORIGIN_SECRET", SECRET)
    app = create_app(store=Store(NAMES, workers=1), name_prefix=PREFIX)
    c = app.test_client()
    assert c.get("/healthz").status_code == 403
    assert c.get("/healthz", headers={"X-Origin-Verify": SECRET}).status_code == 200
    monkeypatch.setenv("ORIGIN_SECRET", "")
    monkeypatch.setenv("REQUIRE_ORIGIN_SECRET", "1")
    with pytest.raises(RuntimeError):
        create_app(store=Store(NAMES, workers=1), name_prefix=PREFIX)


def test_secret_never_logged(aws, capsys):
    app, _ = make(SECRET)
    c = app.test_client()
    c.get("/", headers={"X-Origin-Verify": "wrong-" + SECRET})
    c.get("/")
    c.get("/", headers={"X-Origin-Verify": SECRET})
    out = capsys.readouterr()
    assert SECRET not in out.out + out.err
    lines = [json.loads(line) for line in out.out.splitlines() if line.startswith("{")]
    reasons = [x["reason"] for x in lines if x["action"] == "origin_rejected"]
    assert reasons == ["mismatch", "missing"]


# ---------------------------------------------------------------- warm cache


def test_warm_cache_loads_everything_once(aws, capsys):
    app, client = make("")
    assert app.extensions["guardian_warm_cache"]() == {
        "findings": "ok", "summaries": "ok", "activity": "ok", "bill": "ok", "budgets": "ok",
        "budgetStatus": "ok"}
    warmed = len(client.calls)
    assert {"scan", "query", "batch_get_item"} <= set(client.calls)
    assert app.test_client().get("/").status_code == 200
    assert app.test_client().get("/api/bill").status_code == 200
    assert len(client.calls) == warmed  # the page and the 30-day bill come from the warm cache
    warm_log = [json.loads(x) for x in capsys.readouterr().out.splitlines() if '"cache_warm"' in x]
    assert warm_log[-1]["result"] == "ok"


def test_warm_cache_failures_are_logged_not_raised(aws, capsys):
    app, _ = make("", fail=True)
    result = app.extensions["guardian_warm_cache"]()
    assert set(result.values()) == {"error"}
    out = capsys.readouterr().out
    assert '"dashboard_read"' in out and '"cache_warm"' in out


# ---------------------------------------------------------------- entry point


@pytest.fixture
def entry_env(aws, monkeypatch):
    monkeypatch.setenv("NAME_PREFIX", PREFIX)
    served, threads = [], []
    monkeypatch.setattr(entry, "serve", lambda app, **kw: served.append(kw))

    class FakeThread:
        def __init__(self, target, name, daemon):
            threads.append({"target": target, "name": name, "daemon": daemon})

        def start(self):
            threads[-1]["started"] = True

    monkeypatch.setattr(entry.threading, "Thread", FakeThread)
    return served, threads


def test_main_warm_cache_and_secret(entry_env, monkeypatch, capsys):
    served, threads = entry_env
    monkeypatch.setenv("ORIGIN_SECRET", SECRET)
    monkeypatch.setenv("REQUIRE_ORIGIN_SECRET", "1")
    monkeypatch.setenv("WARM_CACHE", "1")
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("PORT", "80")
    entry.main()
    assert served == [{"host": "0.0.0.0", "port": 80, "threads": 8, "ident": "guardian-dashboard"}]
    assert len(threads) == 1 and threads[0]["daemon"] and threads[0]["started"]
    assert threads[0]["name"] == "warm-cache"
    out = capsys.readouterr().out
    assert SECRET not in out
    start = [json.loads(x) for x in out.splitlines() if '"dashboard_start"' in x][0]
    assert start["originCheck"] is True


def test_main_no_warm_by_default(entry_env):
    served, threads = entry_env
    entry.main()
    assert len(served) == 1 and threads == []


def test_main_refuses_without_secret_when_required(entry_env, monkeypatch):
    served, _ = entry_env
    monkeypatch.setenv("REQUIRE_ORIGIN_SECRET", "1")
    with pytest.raises(RuntimeError):
        entry.main()
    assert served == []
