"""Budget alert subscriber (CONTRACT §3.5, §4.9; design §6.1, §11.2).

Subscribed to the team SNS topic. Stores each AWS Budgets alert in <prefix>budget-alerts for the digest and the
dashboard. CloudWatch alarm messages on the same topic and anything else are skipped (logged, nothing written).

AWS does not document the exact text of a Budgets notification, so parsing is tolerant: each field is read from
its own "Label: value" line, and a field that can't be parsed is omitted, never guessed. Without a budget name
(from the "Budget Name:" line or the Subject) the record is skipped.

Idempotent: PutItem with attribute_not_exists(budgetName) OR messageId = :mid. An SNS redelivery (same MessageId)
lands on its own item again; a different message in the same second moves to receivedAt + 1 s (at most 5 times).
Any other DynamoDB error is raised, so the async invocation is retried and then goes to the DLQ.
"""

import json
import os
import re
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation

import boto3
from botocore.exceptions import ClientError

MESSAGE_MAX = 2000
SUBJECT_MAX = 200
BUDGET_NAME_MAX = 100  # AWS Budgets' own limit
MAX_SHIFTS = 5
CENT = Decimal("0.01")

SUBJECT_PREFIX = "AWS Budgets:"
SUBJECT_NAME_RE = re.compile(r"^AWS Budgets:\s*(.+?)\s+(?:has|is|was)\s", re.IGNORECASE)
LINE_RE = r"^[ \t]*{label}[ \t]*:[ \t]*(.+?)[ \t]*$"
AMOUNT_RE = re.compile(r"(?:\$|USD)\s*([0-9][0-9,]*(?:\.[0-9]+)?)", re.IGNORECASE)
THRESHOLD_TYPES = ("ACTUAL", "FORECASTED")

_clients = {}


def table():
    if "table" not in _clients:
        _clients["table"] = boto3.resource("dynamodb").Table(os.environ["TABLE_BUDGET_ALERTS"])
    return _clients["table"]


def _log(**fields):
    print(json.dumps(fields, default=str))


def _line(text, label):
    """Value of the first 'label: value' line (case-insensitive), or None."""
    m = re.search(LINE_RE.format(label=label), text, re.IGNORECASE | re.MULTILINE)
    return m.group(1) if m else None


def _money(value):
    """'$4.12' / '> $4.00' / 'USD 1,234.5' -> Decimal('4.12'); anything else -> None. Percentages are not USD."""
    if value is None:
        return None
    m = AMOUNT_RE.search(value)
    if not m:
        return None
    try:
        return Decimal(m.group(1).replace(",", "")).quantize(CENT)
    except InvalidOperation:
        return None


def iso_seconds(timestamp):
    """SNS Timestamp ('2026-11-25T10:15:30.123Z') -> '2026-11-25T10:15:30Z', or None."""
    if not isinstance(timestamp, str):
        return None
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def classify(subject, message):
    """'alarm' | 'budget' | 'unknown'."""
    try:
        parsed = json.loads(message)
    except (TypeError, ValueError):
        parsed = None
    if isinstance(parsed, dict) and "AlarmName" in parsed:
        return "alarm"
    if (subject or "").strip().startswith(SUBJECT_PREFIX) or "budget name:" in (message or "").lower():
        return "budget"
    return "unknown"


def parse_budget(subject, message):
    """Fields found in a Budgets alert. Keys present only when parsed: budgetName, thresholdType, threshold,
    budgetedAmount, amount."""
    subject = (subject or "").strip()
    message = message or ""
    out = {}

    name = _line(message, r"Budget\s+Name")
    if not name:
        m = SUBJECT_NAME_RE.match(subject)
        name = m.group(1).strip() if m else None
    if name and len(name) <= BUDGET_NAME_MAX:
        out["budgetName"] = name

    kind = (_line(message, r"Alert\s+Type") or "").strip().upper()
    if kind not in THRESHOLD_TYPES:
        # Fall back to the "<TYPE> Amount:" line, only if exactly one kind appears.
        present = [t for t in THRESHOLD_TYPES if _line(message, rf"{t}\s+Amount") is not None]
        kind = present[0] if len(present) == 1 else None
    if kind:
        out["thresholdType"] = kind

    threshold = _money(_line(message, r"Alert\s+Threshold"))
    if threshold is not None:
        out["threshold"] = threshold
    budgeted = _money(_line(message, r"Budgeted\s+Amount"))
    if budgeted is not None:
        out["budgetedAmount"] = budgeted
    if kind:
        amount = _money(_line(message, rf"{kind}\s+Amount"))
        if amount is not None:
            out["amount"] = amount
    return out


def build_item(record):
    """(item, skip_reason). item is None when the record is skipped."""
    sns = record.get("Sns") if isinstance(record, dict) else None
    if not isinstance(sns, dict):
        return None, "unknown"
    subject = sns.get("Subject") or ""
    message = sns.get("Message") or ""
    kind = classify(subject, message)
    if kind != "budget":
        return None, kind

    fields = parse_budget(subject, message)
    if "budgetName" not in fields:
        return None, "no_budget_name"

    received_at = iso_seconds(sns.get("Timestamp"))
    if received_at is None:
        # SNS always sends Timestamp; without it, the arrival time is the best we have (it is the key).
        received_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    item = dict(fields)
    item["receivedAt"] = received_at
    item["day"] = received_at[:10]
    item["message"] = message[:MESSAGE_MAX]
    if subject:
        item["subject"] = subject[:SUBJECT_MAX]
    if sns.get("MessageId"):
        item["messageId"] = str(sns["MessageId"])
    return item, None


def _shift(received_at, seconds):
    dt = datetime.strptime(received_at, "%Y-%m-%dT%H:%M:%SZ") + timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def store(item):
    """Writes the item; returns the receivedAt it was stored under. Raises after MAX_SHIFTS collisions."""
    base = item["receivedAt"]
    mid = item.get("messageId", "")
    for shift in range(MAX_SHIFTS + 1):
        received_at = _shift(base, shift)
        attempt = dict(item, receivedAt=received_at, day=received_at[:10])
        try:
            table().put_item(
                Item=attempt,
                ConditionExpression="attribute_not_exists(budgetName) OR messageId = :mid",
                ExpressionAttributeValues={":mid": mid},
            )
            return received_at
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                raise
            # Another alert already holds this budgetName + second: try the next second.
    raise RuntimeError(f"budget alert {item['budgetName']} at {base}: {MAX_SHIFTS + 1} receivedAt slots taken")


def handler(event, context):
    results = []
    for record in (event or {}).get("Records", []):
        item, skipped = build_item(record)
        if item is None:
            _log(action="budget_alert", result=f"skipped: {skipped}",
                 messageId=(record.get("Sns") or {}).get("MessageId") if isinstance(record, dict) else None)
            results.append({"result": "skipped", "reason": skipped})
            continue
        try:
            received_at = store(item)
        except Exception as e:
            _log(action="budget_alert", budgetName=item["budgetName"], thresholdType=item.get("thresholdType"),
                 messageId=item.get("messageId"), result="error", error=str(e)[:300])
            raise
        _log(action="budget_alert", budgetName=item["budgetName"], thresholdType=item.get("thresholdType"),
             receivedAt=received_at, messageId=item.get("messageId"), result="stored")
        results.append({"result": "stored", "budgetName": item["budgetName"], "receivedAt": received_at})
    return {"records": results}
