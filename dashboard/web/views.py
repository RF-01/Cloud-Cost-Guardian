"""Pure functions that turn table items into what the page and the JSON API show (task #26).

No AWS calls here. The dashboard never recomputes the daily summary's money rules (CONTRACT §3.6): waste and
savings come from daily-summaries; the only money computed here is a finding's "cost so far"
(estimatedMonthlyCost / 730 x hours since firstSeenAt) and sums of bill-history rows.
"""

import json
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

HOURS_PER_MONTH = 730
ACTIVE = ("open", "in_progress", "failed")
STATUS_FILTERS = ("open", "in_progress", "failed", "remediated")
RECENT_DAYS = 7
RECENT_MAX = 200
BUDGETS_MAX = 20
TOP_SERVICES = 5
SUMMARY_DAY_CHOICES = (7, 30, 90)
BILL_MAX_DAYS = 90
MAX_WEEKS = 12
DETAILS_MAX_CHARS = 300
SFN_REGION = "us-west-2"
SFN_CONSOLE = ("https://us-west-2.console.aws.amazon.com/states/home?region=us-west-2"
               "#/v2/executions/details/")
COST_EXPLORER_URL = "https://us-east-1.console.aws.amazon.com/costmanagement/home#/cost-explorer"
BILL_LABEL = "usage cost before credits, USD/day"
SAMPLE_NOTE = "Sample data (demo seed), not real"


def parse_time(text):
    """ISO 8601 UTC string -> aware datetime, or None."""
    if not isinstance(text, str) or not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cost_so_far(finding, now):
    """estimatedMonthlyCost / 730 x hours since firstSeenAt, 2 decimals; None if either is missing."""
    monthly = finding.get("estimatedMonthlyCost")
    started = parse_time(finding.get("firstSeenAt"))
    if not isinstance(monthly, (int, float)) or isinstance(monthly, bool) or started is None:
        return None
    hours = max((now - started).total_seconds() / 3600, 0)
    return round(monthly / HOURS_PER_MONTH * hours, 2)


def execution_url(finding):
    """Step Functions console link for an in_progress finding's execution (us-west-2 only), else None."""
    arn = finding.get("executionArn")
    if finding.get("status") != "in_progress" or not isinstance(arn, str):
        return None
    if not arn.startswith(f"arn:aws:states:{SFN_REGION}:"):
        return None
    return SFN_CONSOLE + quote(arn, safe=":")


def is_sample(item):
    return item.get("sample") is True


# ---------------------------------------------------------------- findings


def _cost_key(f):
    cost = f.get("estimatedMonthlyCost")
    has = isinstance(cost, (int, float)) and not isinstance(cost, bool)
    return (0 if has else 1, -(cost if has else 0), f.get("resourceId", ""), f.get("findingType", ""))


def finding_row(f, now):
    return {
        "resourceId": f.get("resourceId"),
        "findingType": f.get("findingType"),
        "name": f.get("name"),
        "resourceType": f.get("resourceType"),
        "region": f.get("region"),
        "owner": f.get("owner") or "unknown",
        "project": f.get("project") or "untagged",
        "status": f.get("status"),
        "timelineStep": f.get("timelineStep"),
        "deadlineAt": f.get("deadlineAt"),
        "firstSeenAt": f.get("firstSeenAt"),
        "estimatedMonthlyCost": f.get("estimatedMonthlyCost"),
        "costSoFar": cost_so_far(f, now),
        "reportOnlyReason": f.get("reportOnlyReason"),
        "dryRun": f.get("dryRun"),
        "executionUrl": execution_url(f),
        "failedStep": f.get("failedStep"),
        "errorMessage": f.get("errorMessage"),
        "restartCount": f.get("restartCount", 0),
        "realizedMonthlySavings": f.get("realizedMonthlySavings"),
        "remediatedAt": f.get("remediatedAt"),
        "snapshotId": f.get("snapshotId"),
    }


def clean_filters(args):
    """Server-side filters from query args. Unknown status values are dropped."""
    status = (args.get("status") or "").strip()
    return {
        "status": status if status in STATUS_FILTERS else "",
        "region": (args.get("region") or "").strip()[:64],
        "owner": (args.get("owner") or "").strip()[:254],
    }


def _matches(f, filters):
    if filters.get("status") and f.get("status") != filters["status"]:
        return False
    if filters.get("region") and f.get("region") != filters["region"]:
        return False
    if filters.get("owner") and (f.get("owner") or "unknown") != filters["owner"]:
        return False
    return True


def findings_view(findings, now, filters=None):
    filters = filters or {}
    live = [f for f in findings if f.get("status") != "resolved"]
    shown = sorted((f for f in live if _matches(f, filters)), key=_cost_key)
    rows = [finding_row(f, now) for f in shown]
    return {
        "filters": filters,
        "options": {
            "status": list(STATUS_FILTERS),
            "region": sorted({f["region"] for f in live if f.get("region")}),
            "owner": sorted({f.get("owner") or "unknown" for f in live}),
        },
        "active": [r for r in rows if r["status"] in ACTIVE],
        "failed": [r for r in rows if r["status"] == "failed"],
        "remediated": [r for r in rows if r["status"] == "remediated"],
        "reportOnly": [r for r in rows if r["reportOnlyReason"]],
        "resolvedCount": sum(1 for f in findings if f.get("status") == "resolved"),
        "total": len(findings),
    }


# ---------------------------------------------------------------- daily summaries


SUMMARY_FIELDS = ("totalMonthlyWaste", "realizedMonthlySavings", "potentialMonthlySavings", "openFindings",
                  "warningsSent", "actionsTaken", "actionsTakenDryRun")
BREAKDOWN_FIELDS = ("wasteByRegion", "wasteByOwner", "wasteByProject", "countsByType")


def choose_kpi_summary(summaries):
    """The latest non-sample summary; else the latest sample one; else None."""
    real = [s for s in summaries.values() if not is_sample(s)]
    pool = real or list(summaries.values())
    if not pool:
        return None
    return max(pool, key=lambda s: s["day"])


def kpi_view(summaries):
    s = choose_kpi_summary(summaries)
    if s is None:
        return None
    out = {"day": s["day"], "sample": is_sample(s), "createdAt": s.get("createdAt")}
    for field in ("totalMonthlyWaste", "potentialMonthlySavings", "realizedMonthlySavings", "openFindings"):
        out[field] = s.get(field)
    return out


def _ranked(mapping):
    if not isinstance(mapping, dict):
        return []
    return [{"label": k, "value": v} for k, v in sorted(mapping.items(), key=lambda kv: (-(kv[1] or 0), kv[0]))]


def summaries_view(summaries, today, days):
    day_list = [(today - timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]
    series = []
    for d in day_list:
        s = summaries.get(d)
        point = {"day": d, "present": s is not None, "sample": bool(s and is_sample(s))}
        for field in SUMMARY_FIELDS:
            point[field] = s.get(field) if s else None
        series.append(point)
    latest = choose_kpi_summary(summaries)
    latest_view = None
    if latest is not None:
        latest_view = {"day": latest["day"], "sample": is_sample(latest)}
        for field in BREAKDOWN_FIELDS:
            latest_view[field] = _ranked(latest.get(field))
    return {
        "days": days,
        "from": day_list[0],
        "to": day_list[-1],
        "series": series,
        "latest": latest_view,
        "kpi": kpi_view(summaries),
        "sampleInRange": any(p["sample"] for p in series) or bool(latest_view and latest_view["sample"]),
        "sampleNote": SAMPLE_NOTE,
        "units": "estimated, USD/month",
    }


# ---------------------------------------------------------------- activity


def iso_week_start(d):
    return d - timedelta(days=d.isoweekday() - 1)


def week_days(weeks, today):
    """Days (date objects) of the last `weeks` ISO weeks incl. the current one, up to today."""
    first = iso_week_start(today) - timedelta(weeks=weeks - 1)
    return [first + timedelta(days=i) for i in range((today - first).days + 1)]


def weekly_activity(weeks, today, audit_by_day, summaries):
    out = []
    start = iso_week_start(today) - timedelta(weeks=weeks - 1)
    for w in range(weeks):
        monday = start + timedelta(weeks=w)
        days = [monday + timedelta(days=i) for i in range(7) if monday + timedelta(days=i) <= today]
        iso_year, iso_wk, _ = monday.isocalendar()
        row = {"week": f"{iso_year}-W{iso_wk:02d}", "start": monday.isoformat(),
               "end": (monday + timedelta(days=6)).isoformat(),
               "findingsOpened": 0, "findingsOpenedSample": 0, "warningsSent": 0, "actionsTaken": 0,
               "actionsTakenDryRun": 0, "sampleDays": 0, "summaryDays": 0}
        for d in days:
            key = d.isoformat()
            day_sample = False
            for e in audit_by_day.get(key, []):
                if e.get("event") == "finding_opened":
                    row["findingsOpened"] += 1
                    if is_sample(e):
                        row["findingsOpenedSample"] += 1
                        day_sample = True
            s = summaries.get(key)
            if s:
                row["summaryDays"] += 1
                for field in ("warningsSent", "actionsTaken", "actionsTakenDryRun"):
                    value = s.get(field)
                    if isinstance(value, (int, float)) and not isinstance(value, bool):
                        row[field] += value
                day_sample = day_sample or is_sample(s)
            if day_sample:
                row["sampleDays"] += 1
        row["sample"] = row["sampleDays"] > 0
        out.append(row)
    return out


def details_text(details):
    if not details:
        return ""
    text = json.dumps(details, sort_keys=True, default=str, ensure_ascii=False)
    return text if len(text) <= DETAILS_MAX_CHARS else text[:DETAILS_MAX_CHARS - 1] + "…"


def recent_activity(audit_by_day, days):
    entries = [e for d in days for e in audit_by_day.get(d, [])]
    entries.sort(key=lambda e: e.get("ts", ""), reverse=True)
    out = []
    for e in entries[:RECENT_MAX]:
        out.append({
            "time": (e.get("ts") or "").split("#", 1)[0],
            "actor": e.get("actor"),
            "event": e.get("event"),
            "resourceId": e.get("resourceId"),
            "findingType": e.get("findingType"),
            "region": e.get("region"),
            "result": e.get("result"),
            "dryRun": e.get("dryRun"),
            "sample": is_sample(e),
            "details": e.get("details") or {},
            "detailsText": details_text(e.get("details")),
        })
    return out


# ---------------------------------------------------------------- bill history


def bill_view(rows_by_day, days):
    """days: ISO days oldest first. rows_by_day: {day: [bill-history items]}."""
    totals, estimated = [], []
    per_service, per_project = {}, {}
    service_sum = {}
    fetched = None
    for i, d in enumerate(days):
        rows = rows_by_day.get(d, [])
        total = None
        for r in rows:
            key, amount = r.get("key", ""), r.get("amount")
            if not isinstance(amount, (int, float)) or isinstance(amount, bool):
                continue
            if key == "total":
                total = amount
            elif key.startswith("service#"):
                name = key[len("service#"):]
                per_service.setdefault(name, [0.0] * len(days))[i] += amount
                service_sum[name] = service_sum.get(name, 0.0) + amount
            elif key.startswith("project#"):
                name = key[len("project#"):] or "untagged"
                per_project[name] = per_project.get(name, 0.0) + amount
            if r.get("fetchedAt") and (fetched is None or r["fetchedAt"] > fetched):
                fetched = r["fetchedAt"]
        totals.append(total)
        if any(r.get("estimated") is True for r in rows):
            estimated.append(d)

    ranked = sorted(service_sum, key=lambda n: (-service_sum[n], n))
    top, rest = ranked[:TOP_SERVICES], ranked[TOP_SERVICES:]
    services = [{"name": n, "amounts": [round(v, 4) for v in per_service[n]], "total": round(service_sum[n], 4)}
                for n in top]
    if rest:
        other = [round(sum(per_service[n][i] for n in rest), 4) for i in range(len(days))]
        services.append({"name": "other", "amounts": other, "total": round(sum(other), 4)})
    projects = [{"name": n, "total": round(v, 4)}
                for n, v in sorted(per_project.items(), key=lambda kv: (-kv[1], kv[0]))]
    known = [t for t in totals if t is not None]
    return {
        "days": days,
        "from": days[0] if days else None,
        "to": days[-1] if days else None,
        "total": totals,
        "rangeTotal": round(sum(known), 4) if known else None,
        "services": services,
        "projects": projects,
        "estimatedDays": estimated,
        "fetchedAt": fetched,
        "label": BILL_LABEL,
        "costExplorerUrl": COST_EXPLORER_URL,
        "hasData": bool(known),
    }


# ---------------------------------------------------------------- budgets


def budgets_view(alerts):
    newest = sorted(alerts, key=lambda a: a.get("receivedAt", ""), reverse=True)[:BUDGETS_MAX]
    return [{"budgetName": a.get("budgetName"), "receivedAt": a.get("receivedAt"),
             "thresholdType": a.get("thresholdType"), "threshold": a.get("threshold"),
             "message": a.get("message"), "day": a.get("day")} for a in newest]


BUDGET_STATUS_NOTE = "usage before credits"


def _money(spend):
    """{"amount": "1.5", "unit": "USD"} -> 1.5 (unrounded), None if absent or unreadable."""
    if not isinstance(spend, dict):
        return None
    try:
        value = float(spend.get("amount"))
    except (TypeError, ValueError):
        return None
    return value if value == value else None   # NaN -> None


def _round2(value):
    return round(value, 2) if value is not None else None


def budget_status_view(budgets, prefix):
    """This stack's budgets only (name starts with NAME_PREFIX), by name. Amounts in USD, percent of the limit."""
    if not prefix:
        return []
    out = []
    for b in budgets:
        name = b.get("name")
        if not isinstance(name, str) or not name.startswith(prefix):
            continue
        limit, actual, forecast = _money(b.get("limit")), _money(b.get("actual")), _money(b.get("forecast"))

        def pct(value):
            return round(value / limit * 100, 1) if value is not None and limit else None

        out.append({
            "name": name,
            "unit": (b.get("limit") or {}).get("unit") or "USD",
            "timeUnit": b.get("timeUnit"),
            "limit": _round2(limit),
            "actual": _round2(actual),
            "forecast": _round2(forecast),
            "percent": pct(actual),
            "forecastPercent": pct(forecast),
            "periodStart": b.get("periodStart"),
            "periodEnd": b.get("periodEnd"),
            "lastUpdated": b.get("lastUpdated"),
        })
    return sorted(out, key=lambda x: x["name"])


def today_of(now):
    return now.astimezone(timezone.utc).date()


def yesterday_of(now):
    return today_of(now) - timedelta(days=1)

