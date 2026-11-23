"""Read-only DynamoDB access for the dashboard, with an in-memory TTL cache (task #26).

The dashboard may make ONLY these DynamoDB calls (README "IAM for #38"):

    findings         Scan (paginated)
    audit            Query on GSI byDay (one query per day, paginated)
    daily-summaries  BatchGetItem by day keys (UnprocessedKeys retried)
    bill-history     Query per day (paginated)
    budget-alerts    Scan (paginated)

`ReadOnlyDynamo` enforces that list at runtime: any other operation or table raises `ForbiddenCall` before a
request is sent. Tests also wrap the raw boto3 client to prove nothing else is called.

Cache (thread-safe): findings 30 s, everything else 300 s. One loader runs per key at a time; other threads
asking for the same key wait for it instead of hitting DynamoDB again. Errors are not cached.
"""

import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from decimal import Decimal

import boto3
from boto3.dynamodb.types import TypeDeserializer
from botocore.config import Config

DEFAULT_REGION = "us-west-2"
AUDIT_INDEX = "byDay"
FINDINGS_TTL = 30
OTHER_TTL = 300
SUMMARY_WINDOW_DAYS = 90       # summaries are read for this many days (incl. today), then sliced per view
BATCH_GET_MAX_KEYS = 100       # DynamoDB BatchGetItem limit
BATCH_GET_MAX_ROUNDS = 8       # UnprocessedKeys retries before giving up
READ_WORKERS = 8               # parallel per-day queries on a cold cache (boto3 clients are thread-safe)

# Logical table name -> (env override, suffix after NAME_PREFIX). CONTRACT §1 / §6.
TABLES = {
    "findings": ("TABLE_FINDINGS", "findings"),
    "audit": ("TABLE_AUDIT", "audit"),
    "daily_summaries": ("TABLE_DAILY_SUMMARIES", "daily-summaries"),
    "bill_history": ("TABLE_BILL_HISTORY", "bill-history"),
    "budget_alerts": ("TABLE_BUDGET_ALERTS", "budget-alerts"),
}

# (operation, logical table) pairs the dashboard may use; Query on audit must also name the byDay index.
ALLOWED_CALLS = {
    ("scan", "findings"),
    ("query", "audit"),
    ("batch_get_item", "daily_summaries"),
    ("query", "bill_history"),
    ("scan", "budget_alerts"),
}

_CONFIG = Config(connect_timeout=5, read_timeout=10, retries={"mode": "standard", "max_attempts": 3})
_deserializer = TypeDeserializer()


class ForbiddenCall(RuntimeError):
    """A DynamoDB call outside the dashboard's read-only allowlist."""


def log(action, result, **extra):
    record = {"resourceId": "*", "findingType": "*", "action": action, "result": result}
    record.update(extra)
    print(json.dumps(record, default=str), flush=True)


def table_names_from_env(environ=None):
    """{logical name: table name}. TABLE_* overrides NAME_PREFIX + suffix (CONTRACT §6)."""
    env = os.environ if environ is None else environ
    prefix = env.get("NAME_PREFIX", "")
    names = {}
    for logical, (var, suffix) in TABLES.items():
        name = env.get(var) or (prefix + suffix if prefix else "")
        if not name:
            raise ValueError(f"set NAME_PREFIX (e.g. cg-dev-) or {var}")
        names[logical] = name
    return names


def plain(value):
    """DynamoDB-deserialized value -> JSON-friendly Python (Decimal -> int/float, sets -> sorted lists)."""
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted(plain(v) for v in value)
    if isinstance(value, (bytes, bytearray)):
        return None  # no binary attributes in the contract; never render raw bytes
    return value


def _item(raw):
    return plain({k: _deserializer.deserialize(v) for k, v in raw.items()})


class ReadOnlyDynamo:
    """The only way the dashboard talks to DynamoDB. Every call is checked against ALLOWED_CALLS."""

    def __init__(self, client, table_names):
        self._client = client
        self._names = dict(table_names)
        self._logical = {v: k for k, v in self._names.items()}

    def _check(self, op, table, params):
        logical = self._logical.get(table)
        if (op, logical) not in ALLOWED_CALLS:
            raise ForbiddenCall(f"{op} on {table!r} is not allowed")
        if op == "query" and logical == "audit" and params.get("IndexName") != AUDIT_INDEX:
            raise ForbiddenCall("audit may only be queried on the byDay index")

    def _paginate(self, op, logical, **params):
        table = self._names[logical]
        params["TableName"] = table
        self._check(op, table, params)
        call = getattr(self._client, op)
        while True:
            resp = call(**params)
            for raw in resp.get("Items", []):
                yield _item(raw)
            last = resp.get("LastEvaluatedKey")
            if not last:
                return
            params["ExclusiveStartKey"] = last

    def scan(self, logical):
        return list(self._paginate("scan", logical))

    def query_day(self, logical, day, index=None):
        params = {
            "KeyConditionExpression": "#d = :d",
            "ExpressionAttributeNames": {"#d": "day"},
            "ExpressionAttributeValues": {":d": {"S": day}},
        }
        if index:
            params["IndexName"] = index
        return list(self._paginate("query", logical, **params))

    def batch_get_days(self, logical, days, sleep=time.sleep):
        table = self._names[logical]
        self._check("batch_get_item", table, {})
        out = []
        days = list(dict.fromkeys(days))
        for start in range(0, len(days), BATCH_GET_MAX_KEYS):
            pending = {table: {"Keys": [{"day": {"S": d}} for d in days[start:start + BATCH_GET_MAX_KEYS]]}}
            for attempt in range(BATCH_GET_MAX_ROUNDS):
                resp = self._client.batch_get_item(RequestItems=pending)
                out.extend(_item(raw) for raw in resp.get("Responses", {}).get(table, []))
                pending = resp.get("UnprocessedKeys") or {}
                if not pending.get(table, {}).get("Keys"):
                    break
                sleep(min(0.05 * (2 ** attempt), 1.0))
            else:
                raise RuntimeError("BatchGetItem: keys still unprocessed after retries")
        return out


class TTLCache:
    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._lock = threading.Lock()
        self._values = {}       # key -> (expires_at, value)
        self._key_locks = {}

    def get(self, key, ttl, loader):
        now = self._clock()
        with self._lock:
            hit = self._values.get(key)
            if hit and hit[0] > now:
                return hit[1]
            key_lock = self._key_locks.setdefault(key, threading.Lock())
        with key_lock:
            with self._lock:  # another thread may have loaded it while we waited
                hit = self._values.get(key)
                if hit and hit[0] > self._clock():
                    return hit[1]
            started = time.perf_counter()
            value = loader()
            with self._lock:
                self._values[key] = (self._clock() + ttl, value)
            log("cache_load", "ok", key=str(key), ms=round((time.perf_counter() - started) * 1000, 1))
            return value

    def clear(self):
        with self._lock:
            self._values.clear()


class Store:
    """Cached, read-only views of the five tables the dashboard uses."""

    def __init__(self, table_names, client=None, region=None, cache=None, workers=READ_WORKERS):
        if client is None:
            region = region or os.environ.get("AWS_REGION") or DEFAULT_REGION
            client = boto3.session.Session().client("dynamodb", region_name=region, config=_CONFIG)
        self.table_names = dict(table_names)
        self.db = ReadOnlyDynamo(client, self.table_names)
        self.cache = cache or TTLCache()
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ddb-read") if workers > 1 else None

    def findings(self):
        return self.cache.get("findings", FINDINGS_TTL, lambda: self.db.scan("findings"))

    def summaries(self, today):
        """{day: summary} for the SUMMARY_WINDOW_DAYS days up to and including `today` (a date)."""
        days = [(today - timedelta(days=i)).isoformat() for i in range(SUMMARY_WINDOW_DAYS)]

        def load():
            return {s["day"]: s for s in self.db.batch_get_days("daily_summaries", days) if "day" in s}

        return self.cache.get(("summaries", today.isoformat()), OTHER_TTL, load)

    def audit_day(self, day):
        return self.cache.get(("audit", day), OTHER_TTL,
                              lambda: self.db.query_day("audit", day, index=AUDIT_INDEX))

    def bill_day(self, day):
        return self.cache.get(("bill", day), OTHER_TTL, lambda: self.db.query_day("bill_history", day))

    def many(self, loader, days):
        """{day: loader(day)} for many days; the per-day queries run in parallel (one query per day each)."""
        days = list(dict.fromkeys(days))
        if self._pool is None or len(days) < 2:
            return {d: loader(d) for d in days}
        return dict(zip(days, self._pool.map(loader, days)))

    def audit_days(self, days):
        return self.many(self.audit_day, days)

    def bill_days(self, days):
        return self.many(self.bill_day, days)

    def budget_alerts(self):
        return self.cache.get("budget_alerts", OTHER_TTL, lambda: self.db.scan("budget_alerts"))


def day_range(end, count):
    """`count` ISO days ending at `end` (a date), oldest first."""
    return [(end - timedelta(days=i)).isoformat() for i in range(count - 1, -1, -1)]

