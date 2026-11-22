"""Notify Lambda (CONTRACT §4.1, §4.2, §3.4; design §10.4-10.5).

Validates the input, creates the action-link tokens, renders the email and sends it with SES v2.
If SES rejects the recipient, the email is rebuilt for the team address with new tokens (at most 2 sends).
After the send it writes the audit entries and lastNotifiedAt; those post-send writes are logged, never raised,
so a retry never sends the email twice.

DRY_RUN does not suppress sending: the dry-run state shown in the email comes from vars.dryRun only.
"""

import json
import os
import re
import secrets
from datetime import datetime, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

import notify_templates
import notify_tokens

SES_REGION = "us-west-2"
EMAIL_RE = re.compile(r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$")
AUDITED_TEMPLATES = {"FIRST_NOTICE": "notice_sent", "FINAL_WARNING": "final_warning_sent"}

_clients = {}


def ses():
    if "ses" not in _clients:
        _clients["ses"] = boto3.client(
            "sesv2", region_name=SES_REGION,
            config=Config(retries={"mode": "standard", "max_attempts": 5}))  # SES sandbox: 1 email/s
    return _clients["ses"]


def dynamodb():
    if "dynamodb" not in _clients:
        _clients["dynamodb"] = boto3.resource("dynamodb")
    return _clients["dynamodb"]


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log(**fields):
    print(json.dumps(fields, default=str))


def pick_recipient(to, team):
    """Returns (recipient, fallback_reason, intended). A null/empty `to` is not a fallback; a malformed one is."""
    if to is None or (isinstance(to, str) and not to.strip()):
        return team, None, None
    address = to.strip().lower() if isinstance(to, str) else None
    if address and EMAIL_RE.match(address) and len(address) <= 254:
        return address, None, None
    return team, "invalid_address", str(to)[:254]


def _send(template, findings, vars_, recipient, now):
    """Steps 3-5 for one recipient: tokens, render, SendEmail. Returns (messageId, tokensCreated)."""
    links, count = notify_tokens.create_tokens(
        dynamodb(), os.environ["TABLE_TOKENS"], findings, recipient, now, os.environ["ACTION_API_URL"])
    subject, html_body, text_body = notify_templates.render(template, vars_, findings, links)
    response = ses().send_email(
        FromEmailAddress=os.environ["SENDER_EMAIL"],
        Destination={"ToAddresses": [recipient]},
        Content={"Simple": {
            "Subject": {"Data": subject, "Charset": "UTF-8"},
            "Body": {"Html": {"Data": html_body, "Charset": "UTF-8"},
                     "Text": {"Data": text_body, "Charset": "UTF-8"}},
        }},
    )
    return response["MessageId"], count


def handler(event, context):
    template, findings, vars_ = notify_templates.validate(event)
    now = _now()
    team = os.environ["TEAM_EMAIL"].strip().lower()
    resource_ids = [f["resourceId"] for f in findings]
    recipient, fallback_reason, intended = pick_recipient(event.get("to"), team)
    if fallback_reason:
        _log(action="notify_fallback", template=template, recipient=recipient, resourceIds=resource_ids,
             result="fallback", reason=fallback_reason)

    try:
        message_id, tokens_created = _send(template, findings, vars_, recipient, now)
    except ClientError as err:
        code = err.response.get("Error", {}).get("Code")
        if code != "MessageRejected" or recipient == team:
            _log(action="notify_send", template=template, recipient=recipient, resourceIds=resource_ids,
                 result="error", error=code)
            raise
        # The first token set is never delivered; it expires by TTL. The second send is the last one.
        fallback_reason = f"MessageRejected: {err.response.get('Error', {}).get('Message', '')}"[:300]
        intended, recipient = recipient, team
        _log(action="notify_fallback", template=template, recipient=recipient, resourceIds=resource_ids,
             result="fallback", reason=fallback_reason)
        try:
            message_id, tokens_created = _send(template, findings, vars_, recipient, now)
        except ClientError as err2:
            _log(action="notify_send", template=template, recipient=recipient, resourceIds=resource_ids,
                 result="error", error=err2.response.get("Error", {}).get("Code"))
            raise

    fallback = fallback_reason is not None
    _log(action="notify_send", template=template, recipient=recipient, resourceIds=resource_ids,
         result="ok", fallback=fallback, messageId=message_id, tokensCreated=tokens_created)

    _after_send(template, findings, vars_, now, recipient, message_id, fallback, fallback_reason, intended)
    return {"sent": True, "recipient": recipient, "fallback": fallback, "messageId": message_id,
            "tokensCreated": tokens_created}


# ---------------------------------------------------------------- post-send writes (logged, never raised)

def _after_send(template, findings, vars_, now, recipient, message_id, fallback, fallback_reason, intended):
    regions = _regions(template, vars_)
    audit = dynamodb().Table(os.environ["TABLE_AUDIT"])
    for f in findings:
        if fallback:
            _audit(audit, now, f, regions, "email_fallback",
                   {"intendedRecipient": intended, "reason": fallback_reason})
        if template in AUDITED_TEMPLATES:
            _audit(audit, now, f, regions, AUDITED_TEMPLATES[template],
                   {"template": template, "recipient": recipient, "messageId": message_id, "fallback": fallback})

    table = dynamodb().Table(os.environ["TABLE_FINDINGS"])
    for f in findings:
        key = {"resourceId": f["resourceId"], "findingType": f["findingType"]}
        try:
            table.update_item(Key=key, UpdateExpression="SET lastNotifiedAt = :now",
                              ConditionExpression="attribute_exists(resourceId)",
                              ExpressionAttributeValues={":now": now}, ReturnValues="NONE")
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code")
            result = "skipped" if code == "ConditionalCheckFailedException" else "error"
            _log(action="last_notified_at", resourceId=f["resourceId"], findingType=f["findingType"],
                 result=result, error=code)
        except Exception as err:  # noqa: BLE001 — the email is already out
            _log(action="last_notified_at", resourceId=f["resourceId"], findingType=f["findingType"],
                 result="error", error=repr(err)[:300])


def _regions(template, vars_):
    """Region per finding key: vars.region, or (DIGEST) the matching vars.findings item."""
    regions = {}
    if template == "DIGEST":
        for item in vars_.get("findings") or []:
            regions[f"{item.get('resourceId')}#{item.get('findingType')}"] = item.get("region")
    return regions, vars_.get("region")


def _audit(table, now, finding, regions, event, details):
    by_key, default = regions
    item = {
        "resourceId": finding["resourceId"],
        "ts": f"{now}#{secrets.token_hex(4)}",
        "day": now[:10],
        "actor": "notify",
        "event": event,
        "findingType": finding["findingType"],
        "generation": finding["generation"],
        "result": "ok",
        "details": details,
    }
    region = by_key.get(notify_templates.finding_key(finding)) or default
    if region:
        item["region"] = region
    try:
        table.put_item(Item=item)
        _log(action="audit", resourceId=finding["resourceId"], findingType=finding["findingType"],
             event=event, result="ok")
    except Exception as err:  # noqa: BLE001 — the email is already out
        _log(action="audit", resourceId=finding["resourceId"], findingType=finding["findingType"],
             event=event, result="error", error=repr(err)[:300])
