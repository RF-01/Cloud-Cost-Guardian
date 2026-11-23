"""Flask app for the Cloud Cost Guardian dashboard (task #26). Read-only; GET only.

Routes:
    /                    the page (server-rendered tables; charts fetch the JSON below)
    /api/findings        ?status=&region=&owner=
    /api/summaries       ?days=7|30|90 (default 30)
    /api/bill            ?days=1..90 (default 30; full UTC days up to yesterday)
    /api/activity        ?weeks=1..12 (default 8) + the last 7 days of audit entries
    /api/budgets
    /healthz             no AWS calls

Origin check (#38, design §6.4): when ORIGIN_SECRET is set, every request (every route, including /healthz and
/static) must carry X-Origin-Verify with that value, else 403 {"error": "forbidden"}. CloudFront adds the header;
anything reaching the instance some other way (e.g. another distribution) is refused. The secret is never logged.

Untrusted text (tag values like `name`, `errorMessage`, audit `details`, budget messages) only reaches HTML
through Jinja autoescape, and only reaches JS as JSON (API responses or a `tojson` data block), never inline.
"""

import hmac
import os
from datetime import datetime, timezone
from decimal import Decimal

from flask import Flask, abort, jsonify, render_template, request
from flask.json.provider import DefaultJSONProvider

from . import views
from .store import Store, day_range, log, table_names_from_env

ALLOWED_METHODS = {"GET", "HEAD"}
ORIGIN_HEADER = "X-Origin-Verify"

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
       "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
}


class JSONProvider(DefaultJSONProvider):
    """Decimal -> number (Flask's default turns Decimal into a string)."""

    @staticmethod
    def default(o):
        if isinstance(o, Decimal):
            return int(o) if o == o.to_integral_value() else float(o)
        return DefaultJSONProvider.default(o)


def _utc_now():
    return datetime.now(timezone.utc)


def _int_arg(name, default, lo, hi, choices=None):
    raw = request.args.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        abort(400, f"{name} must be an integer")
    if choices is not None and value not in choices:
        abort(400, f"{name} must be one of {', '.join(map(str, choices))}")
    if not lo <= value <= hi:
        abort(400, f"{name} must be between {lo} and {hi}")
    return value


def origin_secret_from_env(environ=None):
    """ORIGIN_SECRET ("" = no origin check). REQUIRE_ORIGIN_SECRET=1 with an empty secret refuses to start."""
    env = os.environ if environ is None else environ
    secret = env.get("ORIGIN_SECRET", "")
    if env.get("REQUIRE_ORIGIN_SECRET") == "1" and not secret:
        raise RuntimeError("REQUIRE_ORIGIN_SECRET=1 but ORIGIN_SECRET is empty; refusing to start")
    return secret


def _origin_ok(got, secret):
    # Header values arrive as latin-1-decoded str; surrogateescape keeps any byte comparable without raising.
    return hmac.compare_digest(got.encode("utf-8", "surrogateescape"), secret.encode("utf-8", "surrogateescape"))


def create_app(store=None, now=None, name_prefix=None, origin_secret=None):
    """store: a Store (tests pass one built on moto); now: callable returning an aware UTC datetime;
    origin_secret: None = from the environment (origin_secret_from_env), "" = no origin check."""
    secret = origin_secret_from_env() if origin_secret is None else origin_secret
    app = Flask(__name__)
    app.json_provider_class = JSONProvider
    app.json = JSONProvider(app)
    app.jinja_env.autoescape = True  # every template, whatever its extension
    clock = now or _utc_now
    if store is None:
        store = Store(table_names_from_env())
    prefix = name_prefix if name_prefix is not None else os.environ.get("NAME_PREFIX", "")
    app.extensions["guardian_store"] = store

    # ---------------------------------------------------------------- template helpers

    @app.template_filter("utc")
    def utc_filter(text):
        dt = views.parse_time(text)
        return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "—"

    @app.template_filter("usd")
    def usd_filter(value, places=2):
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return "—"
        return f"${value:,.{places}f}"

    # ---------------------------------------------------------------- data builders

    def findings_data(filters):
        return views.findings_view(store.findings(), clock(), filters)

    def summaries_data(days):
        return views.summaries_view(store.summaries(views.today_of(clock())), views.today_of(clock()), days)

    def bill_data(days):
        day_list = day_range(views.yesterday_of(clock()), days)
        return views.bill_view(store.bill_days(day_list), day_list)

    def activity_data(weeks):
        today = views.today_of(clock())
        week_days = [d.isoformat() for d in views.week_days(weeks, today)]
        recent_days = day_range(today, views.RECENT_DAYS)
        audit = store.audit_days(week_days + recent_days)
        summaries = store.summaries(today)
        return {
            "weeks": views.weekly_activity(weeks, today, audit, summaries),
            "recent": views.recent_activity(audit, recent_days),
            "recentDays": views.RECENT_DAYS,
            "recentMax": views.RECENT_MAX,
            "sampleNote": views.SAMPLE_NOTE,
        }

    def budgets_data():
        return {"alerts": views.budgets_view(store.budget_alerts())}

    def guarded(builder, *args):
        """Run a data builder; on an AWS / data error, log it and return (None, message)."""
        try:
            return builder(*args), None
        except Exception as exc:  # noqa: BLE001 - one failing table must not take the page down
            log("dashboard_read", "error", builder=builder.__name__, error=f"{type(exc).__name__}: {exc}"[:500])
            return None, "Data temporarily unavailable."

    def api(builder, *args):
        data, error = guarded(builder, *args)
        if error:
            return jsonify({"error": "data_unavailable"}), 502
        data["generatedAt"] = views.iso(clock())
        return jsonify(data)

    def warm_cache():
        """Load what the page needs once (WARM_CACHE=1, run in a background thread at startup).
        Each part is guarded: failures are logged by `guarded`, never raised."""
        results = {}
        for name, builder, args in (("findings", findings_data, ({},)), ("summaries", summaries_data, (30,)),
                                    ("activity", activity_data, (8,)), ("bill", bill_data, (30,)),
                                    ("budgets", budgets_data, ())):
            _, error = guarded(builder, *args)
            results[name] = "error" if error else "ok"
        log("cache_warm", "ok" if all(v == "ok" for v in results.values()) else "error", parts=results)
        return results

    app.extensions["guardian_warm_cache"] = warm_cache

    # ---------------------------------------------------------------- hooks

    @app.before_request
    def origin_check():
        # Registered first, so it runs before the method check and covers /static too.
        if not secret:
            return None
        if _origin_ok(request.headers.get(ORIGIN_HEADER, ""), secret):
            return None
        log("origin_rejected", "error", path=request.path[:200],
            reason="missing" if ORIGIN_HEADER not in request.headers else "mismatch")
        resp = jsonify({"error": "forbidden"})
        resp.status_code = 403
        return resp

    @app.before_request
    def only_get():
        if request.method not in ALLOWED_METHODS:
            abort(405)

    @app.after_request
    def security_headers(resp):
        for k, v in SECURITY_HEADERS.items():
            resp.headers[k] = v
        if request.method not in ALLOWED_METHODS:
            resp.headers["Allow"] = "GET, HEAD"
        return resp

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(405)
    def http_error(err):
        body = {"error": err.name, "message": err.description if err.code == 400 else err.name}
        resp = jsonify(body)
        resp.status_code = err.code
        return resp

    # ---------------------------------------------------------------- routes

    @app.get("/healthz")
    def healthz():
        return jsonify({"status": "ok"})

    @app.get("/api/findings")
    def api_findings():
        return api(findings_data, views.clean_filters(request.args))

    @app.get("/api/summaries")
    def api_summaries():
        return api(summaries_data, _int_arg("days", 30, 7, 90, views.SUMMARY_DAY_CHOICES))

    @app.get("/api/bill")
    def api_bill():
        return api(bill_data, _int_arg("days", 30, 1, views.BILL_MAX_DAYS))

    @app.get("/api/activity")
    def api_activity():
        return api(activity_data, _int_arg("weeks", 8, 1, views.MAX_WEEKS))

    @app.get("/api/budgets")
    def api_budgets():
        return api(budgets_data)

    @app.get("/")
    def index():
        filters = views.clean_filters(request.args)
        findings, findings_error = guarded(findings_data, filters)
        summaries, summaries_error = guarded(summaries_data, 30)
        activity, activity_error = guarded(activity_data, 8)
        budgets, budgets_error = guarded(budgets_data)
        page_config = {"defaultDays": 30, "dayChoices": list(views.SUMMARY_DAY_CHOICES), "weeks": 8,
                       "sampleNote": views.SAMPLE_NOTE, "billLabel": views.BILL_LABEL}
        return render_template(
            "index.html",
            prefix=prefix,
            generated_at=views.iso(clock()),
            filters=filters,
            findings=findings, findings_error=findings_error,
            kpi=summaries["kpi"] if summaries else None, summaries_error=summaries_error,
            activity=activity, activity_error=activity_error,
            budgets=budgets["alerts"] if budgets else None, budgets_error=budgets_error,
            sample_note=views.SAMPLE_NOTE,
            bill_label=views.BILL_LABEL,
            cost_explorer_url=views.COST_EXPLORER_URL,
            page_config=page_config,
        )

    return app
