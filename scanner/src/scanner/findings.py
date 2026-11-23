"""Writes findings to <prefix>findings exactly per CONTRACT §3.1.

The scanner owns the descriptive attributes (resourceType, region, owner, ownerSource, project, name,
classification, estimatedMonthlyCost, estimatedSnapshotMonthlyCost, missingTags, firstSeenAt, lastSeenAt).
It never touches generation,
execution fields, timelineStep or counters, and only sets `status` on a new finding (if_not_exists).
"""

import json
import os

import boto3

_clients = {}

# Attributes the scanner writes from what it sees. Absent values are REMOVEd so a deleted tag disappears.
SCANNER_ATTRIBUTES = ("resourceType", "region", "owner", "ownerSource", "project", "name", "classification",
                      "estimatedMonthlyCost", "estimatedSnapshotMonthlyCost", "missingTags")
# Never REMOVEd: None means "could not price this scan" (pricing logs price_unknown), so the last estimate stays.
NEVER_REMOVE = ("estimatedMonthlyCost", "estimatedSnapshotMonthlyCost")


def table():
    if "table" not in _clients:
        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-west-2"
        _clients["table"] = boto3.resource("dynamodb", region_name=region).Table(os.environ["TABLE_FINDINGS"])
    return _clients["table"]


def reset_clients():
    _clients.clear()


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
