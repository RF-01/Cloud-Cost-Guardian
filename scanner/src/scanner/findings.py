"""Reads and writes findings in <prefix>findings exactly per CONTRACT §3.1 / §3.2.

The scanner owns the descriptive attributes (resourceType, region, owner, ownerSource, project, name,
classification, estimatedMonthlyCost, estimatedSnapshotMonthlyCost, missingTags, firstSeenAt, lastSeenAt).
It never touches generation, execution fields, timelineStep or counters. It sets `status` only:
- on a new finding (if_not_exists → open);
- to resolve a finding whose problem is gone (task #35): `resolve` here, conditional on the status it read
  (timeline findings that are open / in_progress / failed go through common/timeline.stop_timeline instead);
- to reopen a resolved finding whose problem is back (`reopen`, conditional on status resolved): new firstSeenAt,
  the old episode's outcome fields removed (REOPEN_REMOVED).
`list_active` loads the not-resolved findings (one paginated Scan) for the resolve pass.
"""

import json
import os
import threading

from scanner import clients

_local = threading.local()  # per-thread Table resource: regions are scanned in parallel threads (task #22)

# Attributes the scanner writes from what it sees. Absent values are REMOVEd so a deleted tag disappears.
SCANNER_ATTRIBUTES = ("resourceType", "region", "owner", "ownerSource", "project", "name", "classification",
                      "estimatedMonthlyCost", "estimatedSnapshotMonthlyCost", "missingTags")
# Never REMOVEd: None means "could not price this scan" (pricing logs price_unknown), so the last estimate stays.
NEVER_REMOVE = ("estimatedMonthlyCost", "estimatedSnapshotMonthlyCost")
# What the resolve pass needs from each not-resolved finding (list_active).
ACTIVE_PROJECTION = ("resourceId", "findingType", "status", "region", "resourceType", "generation",
                     "remediatedAt", "timelineStep")
# CONTRACT §3.2 reopen: the old episode's outcome. generation, execution fields, timelineStep, postponeCount,
# restartCount and lastNotifiedAt are kept.
REOPEN_REMOVED = ("resolvedAt", "remediatedAt", "dryRun", "realizedMonthlySavings", "failedStep", "errorMessage",
                  "deadlineAt")


def table():
    """This thread's findings Table (boto3 resources are not thread-safe)."""
    local = _local
    if not hasattr(local, "table"):
        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-west-2"
        local.table = clients.resource("dynamodb", region).Table(os.environ["TABLE_FINDINGS"])
    return local.table


def reset_clients():
    """Forget the cached Table and sessions in every thread."""
    global _local
    _local = threading.local()
    clients.reset()


def log(resource_id, finding_type, action, result, **extra):
    record = {"resourceId": resource_id, "findingType": finding_type, "action": action, "result": result}
    record.update(extra)
    print(json.dumps(record, default=str))


def upsert(resource_id, finding_type, attrs, now):
    """Create or refresh a finding. Returns (is_new, item) where item is the finding after the write."""
    sets = ["#st = if_not_exists(#st, :open)", "firstSeenAt = if_not_exists(firstSeenAt, :now)",
            "lastSeenAt = :now"]
    names = {"#st": "status"}
    values = {":open": "open", ":now": now}
    removes = []
    for i, key in enumerate(SCANNER_ATTRIBUTES):
        value = attrs.get(key)
        if value is None:
            if key not in NEVER_REMOVE:
                removes.append(f"#a{i}")
                names[f"#a{i}"] = key
            continue
        sets.append(f"#a{i} = :a{i}")
        names[f"#a{i}"] = key
        values[f":a{i}"] = value
    expression = "SET " + ", ".join(sets)
    if removes:
        expression += " REMOVE " + ", ".join(removes)
    old = table().update_item(
        Key={"resourceId": resource_id, "findingType": finding_type},
        UpdateExpression=expression,
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
        ReturnValues="ALL_OLD",
    ).get("Attributes", {})
    item = {k: v for k, v in old.items() if k not in SCANNER_ATTRIBUTES}
    item.update({k: v for k, v in attrs.items() if v is not None})
    item.update({"resourceId": resource_id, "findingType": finding_type, "lastSeenAt": now,
                 "status": old.get("status", "open"), "firstSeenAt": old.get("firstSeenAt", now)})
    for key in NEVER_REMOVE:
        if key in old and attrs.get(key) is None:
            item[key] = old[key]
    log(resource_id, finding_type, "upsert_finding", "new" if not old else "seen", status=item["status"])
    return (not old), item


def set_report_only(resource_id, finding_type, reason):
    """Set reportOnlyReason on an `open` finding (conditional). Returns True if written."""
    try:
        table().update_item(
            Key={"resourceId": resource_id, "findingType": finding_type},
            UpdateExpression="SET reportOnlyReason = :r",
            ConditionExpression="#st = :open",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":r": reason, ":open": "open"},
        )
        log(resource_id, finding_type, "report_only", "set", reportOnlyReason=reason)
        return True
    except table().meta.client.exceptions.ConditionalCheckFailedException:
        return False


def clear_report_only(resource_id, finding_type):
    """REMOVE reportOnlyReason from an `open` finding whose tag is gone (conditional). Returns True if written."""
    try:
        table().update_item(
            Key={"resourceId": resource_id, "findingType": finding_type},
            UpdateExpression="REMOVE reportOnlyReason",
            ConditionExpression="#st = :open AND attribute_exists(reportOnlyReason)",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":open": "open"},
        )
        log(resource_id, finding_type, "report_only", "cleared")
        return True
    except table().meta.client.exceptions.ConditionalCheckFailedException:
        return False


def list_active():
    """Every finding whose status is not `resolved` (paginated Scan, only ACTIVE_PROJECTION). Raises on errors."""
    names = {f"#p{i}": key for i, key in enumerate(ACTIVE_PROJECTION)}  # status / region are reserved words
    kwargs = {
        "FilterExpression": "#p2 <> :resolved",
        "ProjectionExpression": ", ".join(names),
        "ExpressionAttributeNames": names,
        "ExpressionAttributeValues": {":resolved": "resolved"},
    }
    items = []
    while True:
        page = table().scan(**kwargs)
        items.extend(page.get("Items", []))
        if not page.get("LastEvaluatedKey"):
            return items
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def get_finding(resource_id, finding_type):
    """The finding as stored now (consistent read), or None."""
    return table().get_item(Key={"resourceId": resource_id, "findingType": finding_type},
                            ConsistentRead=True).get("Item")


def resolve(resource_id, finding_type, expected_status, now):
    """SET status resolved, resolvedAt = now, only if the status is still expected_status. Returns True if written."""
    try:
        table().update_item(
            Key={"resourceId": resource_id, "findingType": finding_type},
            UpdateExpression="SET #st = :resolved, resolvedAt = :now",
            ConditionExpression="#st = :expected",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":resolved": "resolved", ":now": now, ":expected": expected_status},
        )
        return True
    except table().meta.client.exceptions.ConditionalCheckFailedException:
        return False


def reopen(resource_id, finding_type, now):
    """CONTRACT §3.2 reopen of a `resolved` finding (conditional): status open, firstSeenAt = now, REOPEN_REMOVED
    removed. Returns the finding after the write, or None if it was no longer resolved (lost race)."""
    try:
        return table().update_item(
            Key={"resourceId": resource_id, "findingType": finding_type},
            UpdateExpression="SET #st = :open, firstSeenAt = :now REMOVE " + ", ".join(REOPEN_REMOVED),
            ConditionExpression="#st = :resolved",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":open": "open", ":now": now, ":resolved": "resolved"},
            ReturnValues="ALL_NEW",
        )["Attributes"]
    except table().meta.client.exceptions.ConditionalCheckFailedException:
        return None
