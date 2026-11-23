"""Audit log writer shared by the Lambdas (CONTRACT §3.3).

    write_audit(resource_id, actor, event, *, finding_type=None, region=None, generation=None,
                dry_run=None, result="ok", details=None) -> bool

Builds one <prefix>audit item: `ts` = "<ISO time>#<8 random hex chars>", `day` = YYYY-MM-DD, numbers stored as
DynamoDB numbers, booleans as BOOL, top-level None fields left out (a None inside `details` is stored as NULL,
e.g. snapshotId in a dry-run).

An audit write never raises: the action it records has already happened. Any error (table missing, no
permission, bad value, TABLE_AUDIT unset) is logged as one JSON line (`audit_write_failed`) and returns False.

Thread-safe: each thread has its own boto3 session and client (the scanner runs regions in threads).

Environment: TABLE_AUDIT.
"""

import json
import os
import secrets
import threading
from datetime import datetime, timezone
from decimal import Decimal

import boto3
from boto3.dynamodb.types import TypeSerializer
from botocore.config import Config

ACTORS = ("scanner", "workflow", "remediation", "notify", "action-link", "digest")
RESULTS = ("ok", "error", "skipped")

_CONFIG = Config(connect_timeout=5, read_timeout=10, retries={"mode": "standard", "max_attempts": 3})
_serializer = TypeSerializer()
_local = threading.local()


def _region():
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-west-2"


def _client():
    local = _local
    if not hasattr(local, "client"):
        local.client = boto3.session.Session().client("dynamodb", region_name=_region(), config=_CONFIG)
    return local.client


def reset_clients():
    """Forget cached boto3 clients in every thread (tests, or after changing env)."""
    global _local
    _local = threading.local()


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _numbers(value):
    """Floats -> Decimal (recursively) so TypeSerializer stores them as N."""
    if isinstance(value, dict):
        return {k: _numbers(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_numbers(v) for v in value]
    if isinstance(value, float):
        return Decimal(str(value))
    return value


def build_item(resource_id, actor, event, *, finding_type=None, region=None, generation=None, dry_run=None,
               result="ok", details=None, now=None):
    """The §3.3 item as plain Python values (before DynamoDB typing)."""
    now = now or _now()
    item = {
        "resourceId": resource_id,
        "ts": f"{now}#{secrets.token_hex(4)}",
        "day": now[:10],
        "actor": actor,
        "event": event,
        "findingType": finding_type,
        "region": region,
        "generation": int(generation) if generation is not None else None,
        "dryRun": bool(dry_run) if dry_run is not None else None,
        "result": result,
        "details": details or None,
    }
    return {k: _numbers(v) for k, v in item.items() if v is not None}


def _log_failure(resource_id, finding_type, actor, event, err):
    print(json.dumps({"resourceId": resource_id, "findingType": finding_type, "action": "audit_write_failed",
                      "result": "error", "actor": actor, "event": event, "error": repr(err)[:300]},
                     default=str))


def write_audit(resource_id, actor, event, *, finding_type=None, region=None, generation=None, dry_run=None,
                result="ok", details=None):
    """Write one audit entry. Returns True if written, False (after logging audit_write_failed) otherwise."""
    try:
        item = build_item(resource_id, actor, event, finding_type=finding_type, region=region,
                          generation=generation, dry_run=dry_run, result=result, details=details)
        _client().put_item(TableName=os.environ["TABLE_AUDIT"],
                           Item={k: _serializer.serialize(v) for k, v in item.items()})
        return True
    except Exception as err:  # noqa: BLE001 - never raise: the audited action already happened
        _log_failure(resource_id, finding_type, actor, event, err)
        return False
