"""Read-only DynamoDB access for the dashboard, with an in-memory TTL cache (task #26), plus the budget status
(AWS Budgets, #43).

The dashboard may make ONLY these DynamoDB reads (README "IAM for the instance role"):

    findings         Scan (paginated)
    audit            Query on GSI byDay (one query per day, paginated)
    daily-summaries  BatchGetItem by day keys (UnprocessedKeys retried)
    bill-history     Query per day (paginated)
    budget-alerts    Scan (paginated)

`ReadOnlyDynamo` enforces that list at runtime: any other operation or table raises `ForbiddenCall` before a
request is sent. Tests also wrap the raw boto3 client to prove nothing else is called. The dashboard's only
DynamoDB write is the Ask box's daily counter (#43). It lives in its own class (`BedrockCounter`), which makes
exactly one call: the conditional UpdateItem on counters.

Budget status: budgets DescribeBudgets (us-east-1, paginated) for this account; the view keeps only this
stack's budgets (name starts with NAME_PREFIX).

Cache (thread-safe): findings 30 s, everything else 300 s. One loader runs per key at a time; other threads
asking for the same key wait for it instead of hitting DynamoDB again. Errors are not cached.
"""

import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta, timezone
from decimal import Decimal

import boto3
from boto3.dynamodb.types import TypeDeserializer
from botocore.config import Config

DEFAULT_REGION = "us-west-2"
BUDGETS_REGION = "us-east-1"   # AWS Budgets is a global service whose endpoint is in us-east-1
BUDGETS_PAGE_SIZE = 100
BUDGETS_MAX_PAGES = 10
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
    "counters": ("TABLE_COUNTERS", "counters"),    # Ask box daily cap (#43): BedrockCounter only, never read
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
_BUDGETS_CONFIG = Config(connect_timeout=3, read_timeout=5, retries={"mode": "standard", "max_attempts": 2})
# The counter write is not idempotent (ADD): no client retry, short timeouts (the Ask request must stay under
# CloudFront's 30 s origin read timeout, CONTRACT §4.11).
COUNTER_CONFIG = Config(connect_timeout=1, read_timeout=2, retries={"total_max_attempts": 1})
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


class CapReached(Exception):
    """The Ask box's daily cap is used up (the counter's condition failed)."""


class BedrockCounter:
    """The Ask box's global daily cap (CONTRACT §3.5, §4.11). Its only call is one conditional UpdateItem on
    counters, key "bedrock#<UTC day>". The reservation is made before the Bedrock call and is never refunded."""

    def __init__(self, client, table_name):
        self._client = client
        self.table_name = table_name

    def reserve(self, day, cap, ttl):
        """+1 on bedrock#<day> if count < cap. Returns the new count; raises CapReached when the cap is used up."""
        try:
            resp = self._client.update_item(
                TableName=self.table_name,
                Key={"counterId": {"S": f"bedrock#{day}"}},
                UpdateExpression="ADD #c :one SET #t = if_not_exists(#t, :ttl)",
                ConditionExpression="attribute_not_exists(#c) OR #c < :cap",
                ExpressionAttributeNames={"#c": "count", "#t": "ttl"},
                ExpressionAttributeValues={":one": {"N": "1"}, ":ttl": {"N": str(int(ttl))},
                                           ":cap": {"N": str(int(cap))}},
                ReturnValues="UPDATED_NEW",
            )
        except Exception as exc:  # noqa: BLE001 - only the condition failure means "cap reached"
            if _error_code(exc) == "ConditionalCheckFailedException":
                raise CapReached() from None
            raise
        return int(resp["Attributes"]["count"]["N"])


def _error_code(exc):
    response = getattr(exc, "response", None)
    return response.get("Error", {}).get("Code") if isinstance(response, dict) else None


def _iso(value):
    if hasattr(value, "astimezone"):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return value if isinstance(value, str) else None


def _spend(value):
    """{"Amount": "1.5", "Unit": "USD"} -> {"amount": "1.5", "unit": "USD"} (strings kept; the view converts)."""
    if not isinstance(value, dict):
        return None
    return {"amount": value.get("Amount"), "unit": value.get("Unit")}


def budget_plain(b):
    """One DescribeBudgets entry -> the few fields the dashboard uses, JSON-friendly."""
    spend = b.get("CalculatedSpend") or {}
    period = b.get("TimePeriod") or {}
    return {
        "name": b.get("BudgetName"),
        "budgetType": b.get("BudgetType"),
        "timeUnit": b.get("TimeUnit"),
        "limit": _spend(b.get("BudgetLimit")),
        "actual": _spend(spend.get("ActualSpend")),
        "forecast": _spend(spend.get("ForecastedSpend")),
        "periodStart": _iso(period.get("Start")),
        "periodEnd": _iso(period.get("End")),
        "lastUpdated": _iso(b.get("LastUpdatedTime")),
    }


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

    def __init__(self, table_names, client=None, region=None, cache=None, workers=READ_WORKERS,
                 budgets_client=None, account_id=None):
        if client is None:
            region = region or os.environ.get("AWS_REGION") or DEFAULT_REGION
            client = boto3.session.Session().client("dynamodb", region_name=region, config=_CONFIG)
        self._budgets_client = budgets_client       # created on first use (us-east-1)
        self._account_id = account_id or os.environ.get("ACCOUNT_ID") or None
        self._lazy_lock = threading.Lock()
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

    # ------------------------------------------------------------ budget status (#43)

    def _budgets(self):
        with self._lazy_lock:
            if self._budgets_client is None:
                self._budgets_client = boto3.session.Session().client("budgets", region_name=BUDGETS_REGION,
                                                                      config=_BUDGETS_CONFIG)
            if self._account_id is None:
                # GetCallerIdentity needs no IAM permission; ACCOUNT_ID (set on EC2) avoids the call.
                self._account_id = boto3.session.Session().client(
                    "sts", region_name=DEFAULT_REGION, config=_BUDGETS_CONFIG).get_caller_identity()["Account"]
            return self._budgets_client, self._account_id

    def _describe_budgets(self):
        client, account = self._budgets()
        out, token = [], None
        for _ in range(BUDGETS_MAX_PAGES):
            params = {"AccountId": account, "MaxResults": BUDGETS_PAGE_SIZE}
            if token:
                params["NextToken"] = token
            try:
                resp = client.describe_budgets(**params)
            except Exception as exc:  # noqa: BLE001 - an account without budgets may answer NotFoundException
                if _error_code(exc) == "NotFoundException":
                    return out
                raise
            out.extend(budget_plain(b) for b in resp.get("Budgets", []))
            token = resp.get("NextToken")
            if not token:
                return out
        raise RuntimeError("DescribeBudgets: more pages than expected")

    def budget_status(self):
        """Every budget of the account (plain dicts, see budget_plain); the view keeps this stack's budgets."""
        return self.cache.get("budget_status", OTHER_TTL, self._describe_budgets)


def day_range(end, count):
    """`count` ISO days ending at `end` (a date), oldest first."""
    return [(end - timedelta(days=i)).isoformat() for i in range(count - 1, -1, -1)]

