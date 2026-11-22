"""Action-link tokens (CONTRACT §3.4, design §10.4).

One random token per finding and action. Only its SHA-256 hash is stored; the raw token exists only in the link.
"""

import hashlib
import secrets
import time

from notify_templates import finding_key, parse_iso

BATCH_SIZE = 25          # DynamoDB BatchWriteItem limit
MAX_BATCH_ATTEMPTS = 5   # first call + 4 retries of UnprocessedItems
TTL_GRACE_SECONDS = 7 * 86400


def token_hash(raw):
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def create_tokens(dynamodb, table_name, findings, recipient, now_iso, api_url, sleep=time.sleep):
    """Creates and stores the tokens for one recipient. Returns (links, count).

    links: {"<resourceId>#<findingType>": {"<action>": "<api_url>/action?t=<raw>"}}
    """
    api_url = api_url.rstrip("/")
    items, links = [], {}
    for finding in findings:
        if not finding["actions"]:
            continue
        expires_at = finding["expiresAt"]
        ttl = int(parse_iso(expires_at).timestamp()) + TTL_GRACE_SECONDS
        for action in finding["actions"]:
            raw = secrets.token_urlsafe(32)
            items.append({
                "tokenHash": token_hash(raw),
                "resourceId": finding["resourceId"],
                "findingType": finding["findingType"],
                "generation": finding["generation"],
                "action": action,
                "recipient": recipient,
                "createdAt": now_iso,
                "expiresAt": expires_at,
                "used": False,
                "ttl": ttl,
            })
            links.setdefault(finding_key(finding), {})[action] = f"{api_url}/action?t={raw}"
    write_items(dynamodb, table_name, items, sleep=sleep)
    return links, len(items)


def write_items(dynamodb, table_name, items, sleep=time.sleep):
    """BatchWriteItem in chunks of <= 25. UnprocessedItems are retried with backoff a bounded number of times."""
    for start in range(0, len(items), BATCH_SIZE):
        request = {table_name: [{"PutRequest": {"Item": item}} for item in items[start:start + BATCH_SIZE]]}
        attempt = 0
        while True:
            response = dynamodb.batch_write_item(RequestItems=request)
            request = response.get("UnprocessedItems") or {}
            if not any(request.values()):
                break
            attempt += 1
            if attempt >= MAX_BATCH_ATTEMPTS:
                left = sum(len(v) for v in request.values())
                raise RuntimeError(f"tokens: {left} items still unprocessed after {attempt} attempts")
            sleep(min(0.05 * 2 ** attempt, 1.0))
