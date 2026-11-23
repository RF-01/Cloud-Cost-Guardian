"""Daily cost Lambda (task #27): Cost Explorer -> <prefix>bill-history (CONTRACT §3.5, §4.7).

Every run re-fetches the last `days` full UTC days up to and including yesterday and overwrites their rows,
because Cost Explorer keeps revising recent days. Exactly two GetCostAndUsage queries per run (plus their
NextPageToken pages): one grouped by SERVICE, one grouped by the `project` cost allocation tag.

Amounts are the usage cost before credits (RECORD_TYPE = Usage), USD per day, rounded to 4 decimals.
Errors are raised so a scheduled (async) invoke retries and then lands in the DLQ.
"""

import json
import os
import time
from datetime import datetime, timedelta, timezone
from decimal import ROUND_HALF_UP, Decimal

import boto3

CE_REGION = "us-east-1"  # Cost Explorer's only endpoint
DEFAULT_DAYS = 3
MAX_DAYS = 90
BATCH_SIZE = 25  # DynamoDB BatchWriteItem limit
MAX_BATCH_ATTEMPTS = 5
METRIC = "UnblendedCost"
FOUR_PLACES = Decimal("0.0001")
ZERO = Decimal("0")

USAGE_ONLY = {"Dimensions": {"Key": "RECORD_TYPE", "Values": ["Usage"]}}
GROUP_SERVICE = {"Type": "DIMENSION", "Key": "SERVICE"}
GROUP_PROJECT = {"Type": "TAG", "Key": "project"}


def _log(action, result, **extra):
    record = {"resourceId": "*", "findingType": "*", "action": action, "result": result}
    record.update(extra)
    print(json.dumps(record, default=str))


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_days(event):
    """`days` from the event: an integer 1..MAX_DAYS, default DEFAULT_DAYS. Anything else raises ValueError."""
    days = (event or {}).get("days", DEFAULT_DAYS)
    if isinstance(days, bool) or not isinstance(days, int):
        raise ValueError(f"days must be an integer 1..{MAX_DAYS}, got {days!r}")
    if not 1 <= days <= MAX_DAYS:
        raise ValueError(f"days must be between 1 and {MAX_DAYS}, got {days}")
    return days


def day_range(days, today):
    """The last `days` full UTC days up to and including yesterday: (start, end) with end exclusive (= today)."""
    return today - timedelta(days=days), today


def _round(amount):
    return amount.quantize(FOUR_PLACES, rounding=ROUND_HALF_UP)


def fetch(ce, start, end, group_by):
    """One GetCostAndUsage query, all pages. Returns ({day: {"estimated": bool, "groups": {key: Decimal}}}, requests).

    A day's groups can be split across pages, so pages are merged per day.
    """
    params = {
        "TimePeriod": {"Start": start.isoformat(), "End": end.isoformat()},
        "Granularity": "DAILY",
        "Metrics": [METRIC],
        "Filter": USAGE_ONLY,
        "GroupBy": [group_by],
    }
    by_day = {}
    requests = 0
    while True:
        resp = ce.get_cost_and_usage(**params)
        requests += 1
        for result in resp.get("ResultsByTime", []):
            day = result["TimePeriod"]["Start"]
            entry = by_day.setdefault(day, {"estimated": False, "groups": {}})
            entry["estimated"] = entry["estimated"] or bool(result.get("Estimated", False))
            for group in result.get("Groups", []):
                key = group["Keys"][0]
                amount = Decimal(group["Metrics"][METRIC]["Amount"])
                entry["groups"][key] = entry["groups"].get(key, ZERO) + amount
        token = resp.get("NextPageToken")
        if not token:
            return by_day, requests
        params["NextPageToken"] = token


def _project_name(tag_key):
    # Tag groups come back as "project$<value>"; "project$" (empty value) is spend without the tag.
    value = tag_key.split("$", 1)[1] if "$" in tag_key else tag_key
    return value or "untagged"


def build_rows(days_list, services, projects, fetched_at):
    """Bill-history rows (CONTRACT §3.5) for every day in days_list.

    - `service#<name>` for each service with a (rounded) amount > 0;
    - `project#<value>` / `project#untagged` likewise;
    - `total` = sum of that day's service amounts, always written (also when 0).
    """
    rows = []
    totals = {}
    for day in days_list:
        svc = services.get(day, {"estimated": True, "groups": {}})
        prj = projects.get(day, {"estimated": svc["estimated"], "groups": {}})

        total = ZERO
        for name, amount in sorted(svc["groups"].items()):
            amount = _round(amount)
            if amount > 0:
                total += amount
                rows.append(_row(day, f"service#{name}", amount, svc["estimated"], fetched_at))

        project_amounts = {}
        for tag_key, amount in prj["groups"].items():
            name = _project_name(tag_key)
            project_amounts[name] = project_amounts.get(name, ZERO) + amount
        for name, amount in sorted(project_amounts.items()):
            amount = _round(amount)
            if amount > 0:
                rows.append(_row(day, f"project#{name}", amount, prj["estimated"], fetched_at))

        rows.append(_row(day, "total", total, svc["estimated"], fetched_at))
        totals[day] = total
    return rows, totals


def _row(day, key, amount, estimated, fetched_at):
    return {"day": day, "key": key, "amount": amount, "estimated": bool(estimated), "fetchedAt": fetched_at}


def write_rows(table, rows):
    """BatchWriteItem in batches of 25, overwriting the same day+key. Retries unprocessed items, then raises."""
    client = table.meta.client
    for i in range(0, len(rows), BATCH_SIZE):
        pending = {table.name: [{"PutRequest": {"Item": row}} for row in rows[i:i + BATCH_SIZE]]}
        for attempt in range(MAX_BATCH_ATTEMPTS):
            resp = client.batch_write_item(RequestItems=pending)
            pending = resp.get("UnprocessedItems") or {}
            if not pending:
                break
            time.sleep(min(0.1 * 2 ** attempt, 2))
        else:
            left = sum(len(v) for v in pending.values())
            raise RuntimeError(f"{left} bill-history rows still unprocessed after {MAX_BATCH_ATTEMPTS} attempts")
    return len(rows)


def handler(event, context):
    days = parse_days(event)
    now = _now()
    start, end = day_range(days, now.date())
    days_list = [(start + timedelta(days=n)).isoformat() for n in range(days)]

    try:
        ce = boto3.client("ce", region_name=CE_REGION)
        services, req_services = fetch(ce, start, end, GROUP_SERVICE)
        projects, req_projects = fetch(ce, start, end, GROUP_PROJECT)
        rows, totals = build_rows(days_list, services, projects, _iso(now))
        table = boto3.resource("dynamodb").Table(os.environ["TABLE_BILL_HISTORY"])
        written = write_rows(table, rows)
    except Exception as exc:
        _log("daily_cost", "error", days=days_list, error=f"{type(exc).__name__}: {exc}"[:500])
        raise

    requests = req_services + req_projects
    _log("daily_cost", "ok", days=days_list, rowsWritten=written, requests=requests,
         totals={d: float(t) for d, t in totals.items()})
    return {"days": days_list, "rowsWritten": written, "requests": requests}

