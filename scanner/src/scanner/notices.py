"""Scanner emails through the Notify Lambda (design §10.1 / §10.2, CONTRACT §4.1 / §4.2 / §4.8, task #36).

What to send is decided in handler.py (_send_notices); this module holds the pieces that don't need the scan:
the per-invocation email budget, the JSON conversion of DynamoDB values, the Notify call and the creator-lookup text.

The call is a synchronous Invoke (RequestResponse) on a client with NO automatic retry (clients.notify_client): a
retry after a timeout could send the same email twice. A FunctionError or any exception is an error for the caller
to count; nothing here retries.
"""

import json
import threading
from decimal import Decimal

# CONTRACT §3.5 `reason` of an `unknown` creator-lookups record -> the MISSING_TAGS `creatorLookup` text (§4.2).
CREATOR_LOOKUP_TEXT = {
    "no_event": "no CloudTrail creation event found (older than 90 days, or not recorded yet)",
    "root_user": "created by the root user",
    "no_email_tag": "created by an IAM user without an email tag",
    "role_without_email": "created by a role session whose name is not an email address",
    "service": "created by an AWS service or automation",
}
ERROR_CHARS = 300


class Budget:
    """At most `limit` emails for one handler invocation, all regions together (thread-safe). A new one is made
    for every invocation, so nothing survives a warm start."""

    def __init__(self, limit):
        self.limit = limit
        self.used = 0
        self._lock = threading.Lock()

    def take(self):
        """Claim one email. False when the budget is spent."""
        with self._lock:
            if self.used >= self.limit:
                return False
            self.used += 1
            return True


def plain(value):
    """DynamoDB values -> plain JSON values (Decimal -> int / float). Raises TypeError on anything else, so a
    non-JSON value is never sent."""
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, dict):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    raise TypeError(f"not a JSON value: {type(value).__name__}")


def finding_ref(item):
    """CONTRACT §4.1 `findings` entry for a scanner email: no actions, so no expiresAt."""
    generation = item.get("generation")
    return {"resourceId": item["resourceId"], "findingType": item["findingType"],
            "generation": int(generation) if generation is not None else 0, "actions": []}


def creator_lookup_text(record):
    """The `creatorLookup` text for an `unknown` record, or None (no record, found, or an unexpected reason)."""
    if not record or record.get("result") != "unknown":
        return None
    return CREATOR_LOOKUP_TEXT.get(record.get("reason"))


def invoke(client, function_name, payload):
    """Invoke Notify once and wait for it. Returns Notify's output (dict). Raises on any error, including a
    FunctionError (Notify raised) and a missing function name."""
    if not function_name:
        raise RuntimeError("NOTIFY_FUNCTION_NAME is not set")
    body = json.dumps(plain(payload)).encode("utf-8")
    response = client.invoke(FunctionName=function_name, InvocationType="RequestResponse", Payload=body)
    raw = response["Payload"].read() if response.get("Payload") is not None else b""
    if response.get("FunctionError"):
        raise RuntimeError(f"FunctionError {response['FunctionError']}: "
                           + raw.decode("utf-8", "replace")[:ERROR_CHARS])
    try:
        out = json.loads(raw or b"{}")
    except ValueError:
        out = {}
    return out if isinstance(out, dict) else {}
