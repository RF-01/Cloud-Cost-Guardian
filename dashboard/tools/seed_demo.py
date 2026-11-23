"""Demo seed for the dashboard (task #26). DEMO STACK ONLY (prefix exactly `cg-demo-`).

Writes plausible, small, deterministic SAMPLE data so the demo dashboard has history to draw:

- `<prefix>daily-summaries`: one item per past full UTC day (--days, default 21, max 60). Never today, never a
  day that already has an item (conditional PutItem attribute_not_exists(day)).
- `<prefix>audit`: a few finding_opened / notice_sent / final_warning_sent / instance_stopped / volume_deleted
  entries per seeded day, consistent with that day's summary (warningsSent, actionsTaken, actionsTakenDryRun).
  Only written for days whose summary was just written, so a re-run never duplicates them.

Nothing else is ever written: no findings, no bill-history (the demo stack backfills the real bill with the
daily-cost `days` input), no tokens. Every seeded item has `sample = true`; audit entries have actor
`sample-seed`, resourceId `sample-<id>` and details {"note": "demo seed"} (CONTRACT §3.3 / §3.5).

Usage (from the repo root, AWS_PROFILE set):
    python dashboard/tools/seed_demo.py --prefix cg-demo-              # preview only, no AWS calls
    python dashboard/tools/seed_demo.py --prefix cg-demo- --yes        # write
    python dashboard/tools/seed_demo.py --prefix cg-demo- --delete     # count sample rows (read-only)
    python dashboard/tools/seed_demo.py --prefix cg-demo- --delete --yes   # delete sample rows only

--delete looks at the last --days days (default 60, the seed maximum) and removes only items with
sample = true (audit: also actor = sample-seed), each with a conditional DeleteItem.
"""

import argparse
import random
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal

REQUIRED_PREFIX = "cg-demo-"
DEFAULT_DAYS = 21
MAX_DAYS = 60
RANDOM_SEED = 26_2611          # fixed: same values on every run
REGION = "us-west-2"
AUDIT_INDEX = "byDay"
ACTOR = "sample-seed"
DETAILS = {"note": "demo seed"}

REGIONS = (("us-west-2", 5), ("us-east-1", 3), ("eu-west-1", 2))
OWNERS = (("owner-a@example.com", 5), ("owner-b@example.com", 3), ("unknown", 2))
PROJECTS = (("demo-web", 5), ("demo-data", 3), ("untagged", 2))


# ---------------------------------------------------------------- plan (pure, deterministic)


def _usd(cents):
    return (Decimal(cents) / 100).quantize(Decimal("0.01"))


def _split(cents, weights):
    """Split an amount in cents by integer weights; the parts add up exactly."""
    total_w = sum(w for _, w in weights)
    out, used = {}, 0
    for i, (name, w) in enumerate(weights):
        part = cents - used if i == len(weights) - 1 else cents * w // total_w
        out[name] = _usd(part)
        used += part
    return out


def seed_days(today, days):
    """The `days` full UTC days before `today`, oldest first. Today is never included."""
    return [(today - timedelta(days=n)).isoformat() for n in range(days, 0, -1)]


def _audit(rng, day, event, resource_id, finding_type, region, dry_run=None):
    hh, mm, ss = rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59)
    item = {
        "resourceId": f"sample-{resource_id}",
        "ts": f"{day}T{hh:02d}:{mm:02d}:{ss:02d}Z#{rng.getrandbits(32):08x}",
        "day": day,
        "actor": ACTOR,
        "event": event,
        "findingType": finding_type,
        "region": region,
        "generation": 1,
        "result": "ok",
        "details": dict(DETAILS),
        "sample": True,
    }
    if dry_run is not None:
        item["dryRun"] = dry_run
    return item


def build_plan(today, days):
    """[{"day", "summary", "audit": [...]}] for each seeded day, oldest first. Same input -> same output."""
    if not 1 <= days <= MAX_DAYS:
        raise ValueError(f"--days must be 1..{MAX_DAYS}")
    rng = random.Random(RANDOM_SEED)
    plan = []
    span = max(days - 1, 1)
    region_names = [r for r, _ in REGIONS]
    for i, day in enumerate(seed_days(today, days)):
        t = i / span                                     # 0 (oldest) -> 1 (yesterday)
        waste = max(60, round(640 - 470 * t) + rng.randint(-25, 25))         # cents / month
        realized = max(0, round(20 + 430 * t) + rng.randint(-15, 15))
        dry_part = rng.randint(0, 60)
        potential = waste * rng.randint(70, 90) // 100 + dry_part

        counts = {"EC2_IDLE": rng.randint(1, 3), "EBS_UNATTACHED": rng.randint(1, 3)}
        if rng.random() < 0.5:
            counts["EIP_UNASSOCIATED"] = 1
        if rng.random() < 0.6:
            counts["MISSING_TAGS"] = rng.randint(1, 2)

        opened = rng.randint(1, 3)
        notices = rng.randint(0, 2)
        finals = rng.randint(0, 1)
        stops = rng.randint(0, 1)
        deletes = rng.randint(0, 1)
        actions = stops + deletes
        dry_actions = rng.randint(0, actions)

        summary = {
            "day": day,
            "totalMonthlyWaste": _usd(waste),
            "realizedMonthlySavings": _usd(realized),
            "potentialMonthlySavings": _usd(potential),
            "countsByType": counts,
            "wasteByRegion": _split(waste, REGIONS),
            "wasteByOwner": _split(waste, OWNERS),
            "wasteByProject": _split(waste, PROJECTS),
            "openFindings": sum(counts.values()),
            "warningsSent": notices + finals,
            "actionsTaken": actions,
            "actionsTakenDryRun": dry_actions,
            "createdAt": f"{day}T23:50:00Z",
            "sample": True,
        }

        audit = []
        n = i * 10
        for k in range(opened):
            ftype = ("EC2_IDLE", "EBS_UNATTACHED", "MISSING_TAGS")[k % 3]
            rid = f"i-{n + k:04d}" if ftype == "EC2_IDLE" else f"vol-{n + k:04d}"
            audit.append(_audit(rng, day, "finding_opened", rid, ftype, region_names[k % 3]))
        for k in range(notices):
            audit.append(_audit(rng, day, "notice_sent", f"i-{n + k:04d}", "EC2_IDLE", region_names[0]))
        for k in range(finals):
            audit.append(_audit(rng, day, "final_warning_sent", f"vol-{n + k:04d}", "EBS_UNATTACHED",
                                region_names[1]))
        dry_left = dry_actions
        for k in range(stops):
            audit.append(_audit(rng, day, "instance_stopped", f"i-{n + 5 + k:04d}", "EC2_IDLE", region_names[0],
                                dry_run=dry_left > 0))
            dry_left -= 1
        for k in range(deletes):
            audit.append(_audit(rng, day, "volume_deleted", f"vol-{n + 5 + k:04d}", "EBS_UNATTACHED",
                                region_names[1], dry_run=dry_left > 0))
            dry_left -= 1
        audit.sort(key=lambda e: e["ts"])
        plan.append({"day": day, "summary": summary, "audit": audit})
    return plan


# ---------------------------------------------------------------- AWS side


def _serializer():
    from boto3.dynamodb.types import TypeSerializer
    return TypeSerializer()


def _client(region, profile=None):
    import boto3
    session = boto3.session.Session(profile_name=profile) if profile else boto3.session.Session()
    return session.client("dynamodb", region_name=region)


def _tables(prefix):
    return {"summaries": f"{prefix}daily-summaries", "audit": f"{prefix}audit"}


def _is_conditional_fail(err):
    return getattr(err, "response", {}).get("Error", {}).get("Code") == "ConditionalCheckFailedException"


def write_plan(client, prefix, plan, today):
    ser = _serializer()
    tables = _tables(prefix)
    report = {"summariesWritten": 0, "daysSkipped": [], "auditWritten": 0}
    for entry in plan:
        day = entry["day"]
        if day >= today.isoformat():          # belt and braces: never today or later
            raise ValueError(f"refusing to seed {day}: not a past day")
        item = {k: ser.serialize(v) for k, v in entry["summary"].items()}
        try:
            client.put_item(TableName=tables["summaries"], Item=item,
                            ConditionExpression="attribute_not_exists(#d)",
                            ExpressionAttributeNames={"#d": "day"})
        except Exception as err:  # noqa: BLE001
            if _is_conditional_fail(err):
                report["daysSkipped"].append(day)
                continue
            raise
        report["summariesWritten"] += 1
        for a in entry["audit"]:
            client.put_item(TableName=tables["audit"], Item={k: ser.serialize(v) for k, v in a.items()},
                            ConditionExpression="attribute_not_exists(#r) AND attribute_not_exists(#t)",
                            ExpressionAttributeNames={"#r": "resourceId", "#t": "ts"})
            report["auditWritten"] += 1
    return report


def _sample_audit_keys(client, table, day):
    params = {
        "TableName": table, "IndexName": AUDIT_INDEX,
        "KeyConditionExpression": "#d = :d",
        "FilterExpression": "#s = :t AND #a = :actor",
        "ExpressionAttributeNames": {"#d": "day", "#s": "sample", "#a": "actor"},
        "ExpressionAttributeValues": {":d": {"S": day}, ":t": {"BOOL": True}, ":actor": {"S": ACTOR}},
    }
    keys = []
    while True:
        resp = client.query(**params)
        keys.extend({"resourceId": i["resourceId"], "ts": i["ts"]} for i in resp.get("Items", []))
        if not resp.get("LastEvaluatedKey"):
            return keys
        params["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def delete_sample(client, prefix, days_list, really):
    tables = _tables(prefix)
    report = {"summariesFound": 0, "summariesDeleted": 0, "realSummariesKept": 0,
              "auditFound": 0, "auditDeleted": 0}
    sample_cond = {"ConditionExpression": "#s = :t",
                   "ExpressionAttributeNames": {"#s": "sample"},
                   "ExpressionAttributeValues": {":t": {"BOOL": True}}}
    for day in days_list:
        resp = client.get_item(TableName=tables["summaries"], Key={"day": {"S": day}}, ConsistentRead=True)
        item = resp.get("Item")
        if item:
            if item.get("sample", {}).get("BOOL") is True:
                report["summariesFound"] += 1
                if really:
                    try:
                        client.delete_item(TableName=tables["summaries"], Key={"day": {"S": day}}, **sample_cond)
                        report["summariesDeleted"] += 1
                    except Exception as err:  # noqa: BLE001
                        if not _is_conditional_fail(err):  # replaced by a real summary meanwhile: keep it
                            raise
            else:
                report["realSummariesKept"] += 1
        for key in _sample_audit_keys(client, tables["audit"], day):
            report["auditFound"] += 1
            if really:
                try:
                    client.delete_item(
                        TableName=tables["audit"], Key=key,
                        ConditionExpression="#s = :t AND #a = :actor",
                        ExpressionAttributeNames={"#s": "sample", "#a": "actor"},
                        ExpressionAttributeValues={":t": {"BOOL": True}, ":actor": {"S": ACTOR}})
                    report["auditDeleted"] += 1
                except Exception as err:  # noqa: BLE001
                    if not _is_conditional_fail(err):
                        raise
    return report


# ---------------------------------------------------------------- CLI


def parse_args(argv):
    p = argparse.ArgumentParser(description="Seed (or delete) sample dashboard data in the DEMO stack only.")
    p.add_argument("--prefix", required=True, help=f"must be exactly {REQUIRED_PREFIX}")
    p.add_argument("--days", type=int, default=None,
                   help=f"past full UTC days (seed default {DEFAULT_DAYS}, delete default {MAX_DAYS}; max {MAX_DAYS})")
    p.add_argument("--yes", action="store_true", help="really write / delete (otherwise preview only)")
    p.add_argument("--delete", action="store_true", help="remove sample rows instead of seeding")
    p.add_argument("--region", default=REGION)
    p.add_argument("--profile", default=None, help="AWS CLI profile (default: AWS_PROFILE)")
    return p.parse_args(argv)


def main(argv=None, client=None, today=None, out=print):
    args = parse_args(argv)
    if args.prefix != REQUIRED_PREFIX:
        out(f"REFUSED: --prefix must be exactly {REQUIRED_PREFIX!r} (demo stack only), got {args.prefix!r}")
        return 2
    days = args.days if args.days is not None else (MAX_DAYS if args.delete else DEFAULT_DAYS)
    if not 1 <= days <= MAX_DAYS:
        out(f"REFUSED: --days must be 1..{MAX_DAYS}")
        return 2
    today = today or datetime.now(timezone.utc).date()
    tables = _tables(args.prefix)

    if args.delete:
        client = client or _client(args.region, args.profile)
        report = delete_sample(client, args.prefix, seed_days(today, days), args.yes)
        mode = "DELETED" if args.yes else "PREVIEW (nothing deleted; add --yes)"
        out(f"{mode}: {tables['summaries']} / {tables['audit']}, days {seed_days(today, days)[0]}.."
            f"{seed_days(today, days)[-1]}")
        for k, v in report.items():
            out(f"  {k}: {v}")
        return 0

    plan = build_plan(today, days)
    if not args.yes:
        out(f"PREVIEW (nothing written; add --yes). Would write to {tables['summaries']} and {tables['audit']}:")
        for e in plan:
            s = e["summary"]
            out(f"  {e['day']}: waste ${s['totalMonthlyWaste']} realized ${s['realizedMonthlySavings']} "
                f"potential ${s['potentialMonthlySavings']} findings {s['openFindings']} "
                f"warnings {s['warningsSent']} actions {s['actionsTaken']} (dry-run {s['actionsTakenDryRun']}) "
                f"+ {len(e['audit'])} audit entries")
        out(f"  total: {len(plan)} summaries, {sum(len(e['audit']) for e in plan)} audit entries, all sample = true."
            " Days that already have a summary are skipped (with their audit entries).")
        return 0

    client = client or _client(args.region, args.profile)
    report = write_plan(client, args.prefix, plan, today)
    out(f"WROTE: {report['summariesWritten']} summaries, {report['auditWritten']} audit entries "
        f"({tables['summaries']}, {tables['audit']}).")
    if report["daysSkipped"]:
        out(f"  skipped (already had a summary): {', '.join(report['daysSkipped'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
