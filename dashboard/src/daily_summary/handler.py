"""Daily summary Lambda (task #28): findings + audit -> <prefix>daily-summaries (CONTRACT §3.5, §3.6, §4.7).

Writes ONE item for `day` = the UTC day of the run and overwrites it on a re-run. The findings part is a
snapshot of the findings table at run time (past days can't be rebuilt, so there is no `day` parameter); the
schedule runs it late in the UTC day. The activity part (`warningsSent`, `actionsTaken`) comes from that day's
audit entries (GSI `byDay`).

Counting rules (CONTRACT §3.5 note, §3.6):
- active = status open / in_progress / failed; resolved findings are ignored entirely.
- totalMonthlyWaste and wasteBy* = estimatedMonthlyCost of active findings, MISSING_TAGS and
  SNAPSHOT_REMINDER excluded, report-only included; missing estimate = 0; missing owner -> "unknown", missing project -> "untagged".
- realizedMonthlySavings = realizedMonthlySavings of remediated findings with dryRun = false.
- potentialMonthlySavings = estimatedMonthlyCost of open / in_progress findings that are not report-only and not
  MISSING_TAGS / SNAPSHOT_REMINDER, plus remediated dry-run findings (realizedMonthlySavings, else
  estimatedMonthlyCost). A remediated finding without dryRun counts as dry-run (no unproven savings claimed).
- countsByType / openFindings count active findings, MISSING_TAGS included.

Errors are raised so a scheduled (async) invoke retries and then lands in the DLQ.
"""

import json
import os
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal

import boto3
from boto3.dynamodb.conditions import Key

TWO_PLACES = Decimal("0.01")
ZERO = Decimal("0")

ACTIVE = {"open", "in_progress", "failed"}
POTENTIAL = {"open", "in_progress"}
MISSING_TAGS = "MISSING_TAGS"
SNAPSHOT_REMINDER = "SNAPSHOT_REMINDER"
# Counted in countsByType / openFindings but never in waste or savings: MISSING_TAGS has no cost, and a kept
# snapshot is the owner's chosen backup whose cost is already netted out of the EBS realized savings.
NOT_WASTE = {MISSING_TAGS, SNAPSHOT_REMINDER}
WARNING_EVENTS = {"notice_sent", "final_warning_sent"}
ACTION_EVENTS = {"instance_stopped", "volume_deleted"}
AUDIT_INDEX = "byDay"

# Page size for Scan / Query. None = DynamoDB's default (1 MB pages); tests set it small to exercise pagination.
PAGE_LIMIT = None


def _log(action, result, **extra):
    record = {"resourceId": "*", "findingType": "*", "action": action, "result": result}
    record.update(extra)
    print(json.dumps(record, default=str))


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _money(value):
    """A DynamoDB number as Decimal; absent / null -> 0."""
    if value is None:
        return ZERO
    return value if isinstance(value, Decimal) else Decimal(str(value))


def _round(amount):
    return amount.quantize(TWO_PLACES, rounding=ROUND_HALF_UP)


def _paginate(call, **params):
    if PAGE_LIMIT:
        params["Limit"] = PAGE_LIMIT
    while True:
        resp = call(**params)
        yield from resp.get("Items", [])
        last = resp.get("LastEvaluatedKey")
        if not last:
            return
        params["ExclusiveStartKey"] = last


def read_findings(table):
    return list(_paginate(table.scan))


def read_audit_day(table, day):
    return list(_paginate(table.query, IndexName=AUDIT_INDEX, KeyConditionExpression=Key("day").eq(day)))


def _add(mapping, key, amount):
    mapping[key] = mapping.get(key, ZERO) + amount


def summarize_findings(findings):
    waste = ZERO
    realized = ZERO
    potential = ZERO
    by_region, by_owner, by_project = {}, {}, {}
    counts = {}
    active_count = 0

    for f in findings:
        status = f.get("status")
        ftype = f.get("findingType")
        cost = _money(f.get("estimatedMonthlyCost"))

        if status in ACTIVE:
            active_count += 1
            counts[ftype] = counts.get(ftype, 0) + 1
            if ftype not in NOT_WASTE:
                waste += cost
                _add(by_region, f.get("region") or "unknown", cost)
                _add(by_owner, f.get("owner") or "unknown", cost)
                _add(by_project, f.get("project") or "untagged", cost)
                if status in POTENTIAL and not f.get("reportOnlyReason"):
                    potential += cost
        elif status == "remediated":
            if f.get("dryRun") is False:
                realized += _money(f.get("realizedMonthlySavings"))
            else:  # dryRun true, or missing: treated as dry-run
                saved = f.get("realizedMonthlySavings")
                potential += _money(saved) if saved is not None else cost
        # resolved (and anything unknown) is ignored.

    return {
        "totalMonthlyWaste": _round(waste),
        "realizedMonthlySavings": _round(realized),
        "potentialMonthlySavings": _round(potential),
        "countsByType": counts,
        "wasteByRegion": {k: _round(v) for k, v in by_region.items()},
        "wasteByOwner": {k: _round(v) for k, v in by_owner.items()},
        "wasteByProject": {k: _round(v) for k, v in by_project.items()},
        "openFindings": active_count,
    }


def summarize_audit(entries):
    warnings = 0
    actions = 0
    actions_dry = 0
    for e in entries:
        event = e.get("event")
        if event in WARNING_EVENTS:
            warnings += 1
        elif event in ACTION_EVENTS:
            actions += 1
            if e.get("dryRun") is True:
                actions_dry += 1
    return {"warningsSent": warnings, "actionsTaken": actions, "actionsTakenDryRun": actions_dry}


def build_summary(day, findings, audit_entries, created_at):
    item = {"day": day}
    item.update(summarize_findings(findings))
    item.update(summarize_audit(audit_entries))
    item["createdAt"] = created_at
    return item


def handler(event, context):
    now = _now()
    day = now.date().isoformat()

    try:
        ddb = boto3.resource("dynamodb")
        findings = read_findings(ddb.Table(os.environ["TABLE_FINDINGS"]))
        audit_entries = read_audit_day(ddb.Table(os.environ["TABLE_AUDIT"]), day)
        item = build_summary(day, findings, audit_entries, _iso(now))
        ddb.Table(os.environ["TABLE_DAILY_SUMMARIES"]).put_item(Item=item)
    except Exception as exc:
        _log("daily_summary", "error", day=day, error=f"{type(exc).__name__}: {exc}"[:500])
        raise

    _log("daily_summary", "ok", day=day, findingsRead=len(findings), auditEntriesRead=len(audit_entries),
         totalMonthlyWaste=float(item["totalMonthlyWaste"]),
         realizedMonthlySavings=float(item["realizedMonthlySavings"]),
         potentialMonthlySavings=float(item["potentialMonthlySavings"]),
         openFindings=item["openFindings"], warningsSent=item["warningsSent"],
         actionsTaken=item["actionsTaken"], actionsTakenDryRun=item["actionsTakenDryRun"])
    return {"day": day, "openFindings": item["openFindings"],
            "totalMonthlyWaste": float(item["totalMonthlyWaste"])}
