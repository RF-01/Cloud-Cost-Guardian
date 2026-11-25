"""CloudTrail creator lookup (design §8.6 step 2, CONTRACT §3.5, task #34).

For an in-scope resource still without an `owner` tag after tag copying, find the identity that created it in
CloudTrail event history (LookupEvents, last 90 days) and map it to an email:

    instance  RunInstances (by instance id)                                    method RunInstances
    EIP       AllocateAddress (by allocation id)                               method AllocateAddress
    volume    1. CreateVolume (by volume id)                                   method CreateVolume
              2. volume-attachments row -> that instance's RunInstances        method last-attached
              3. newest AttachVolume -> its instance's RunInstances            method Attach
                 else newest DetachVolume: its caller                          method Detach
              4. nothing                                                       unknown, reason no_event

Identity -> email: IAMUser -> the user's `email` tag (iam:ListUserTags); AssumedRole -> the session name if it is
an email; Root -> root_user; anything else (AWSService, ...) -> service. Emails are lowercased (CONTRACT §2).

Results are kept in <prefix>creator-lookups: `found` is permanent, `unknown` is retried after UNKNOWN_RETRY_HOURS.
Throttling and errors are raised to the caller and never stored. Event content and tag values are untrusted
text: only the fields of the record (email, creatorArn, method, reason) are ever kept.

One `Lookup` per region scan (one thread): it paces LookupEvents (about 2 requests / s / region allowed) and
caches RunInstances results and IAM user emails for that scan.
"""

import json
import os
import re
import threading
import time

from botocore.exceptions import ClientError

from scanner import attachments, clients, config

PAGE_SIZE = 50  # LookupEvents MaxResults (50 is the API maximum)
MAX_PAGES = 5  # per lookup; older events beyond this are treated as not found
PAUSE_SECONDS = 0.55  # between LookupEvents calls in one region
THROTTLE_CODES = ("ThrottlingException", "Throttling", "TooManyRequestsException", "RequestLimitExceeded")
INSTANCE_ID = re.compile(r"^i-[0-9a-f]{8,17}$")
MAX_ARN_CHARS = 2048

_local = threading.local()  # per-thread Table resource (regions are scanned in parallel threads)


def _pause(seconds):
    time.sleep(seconds)


def table():
    """This thread's creator-lookups Table (boto3 resources are not thread-safe)."""
    local = _local
    if not hasattr(local, "table"):
        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or config.DEFAULT_REGION
        local.table = clients.resource("dynamodb", region).Table(config.table_creator_lookups())
    return local.table


def reset_clients():
    global _local
    _local = threading.local()


def get_record(resource_id):
    return table().get_item(Key={"resourceId": resource_id}).get("Item")


def put_record(record):
    table().put_item(Item={k: v for k, v in record.items() if v is not None})


def is_throttle(err):
    return isinstance(err, ClientError) and err.response.get("Error", {}).get("Code") in THROTTLE_CODES


def looks_like_email(value):
    """One "@", a dot after it, no whitespace, something before it."""
    if not isinstance(value, str) or len(value) > 254 or value.count("@") != 1:
        return False
    local, domain = value.split("@")
    return bool(local) and "." in domain and not any(c.isspace() for c in value)


def _found(email, method, arn):
    return {"result": "found", "email": email, "method": method, "creatorArn": arn}


def _unknown(reason, method=None, arn=None):
    return {"result": "unknown", "reason": reason, "method": method, "creatorArn": arn}


class Lookup:
    """Creator lookups for one region's scan (one thread)."""

    def __init__(self, region, sleep=None):
        self.region = region
        self.calls = 0  # LookupEvents calls made
        self.resources = 0  # resources looked up in CloudTrail (the per-region cap)
        self.throttled = False  # set by the caller after the first throttle: no more lookups this scan
        self._sleep = sleep or _pause
        self._cloudtrail = None
        self._iam = None
        self._run_instances = {}  # instance id -> RunInstances event detail or None
        self._user_emails = {}  # IAM user name -> email or None

    # ------------------------------------------------------------ CloudTrail

    def _events(self, resource_id, names, stop_at=()):
        """[(eventName, parsed CloudTrailEvent)] for successful events named in `names`, newest first. Paging stops
        after MAX_PAGES, or at the first event named in `stop_at`. Raises on throttling / errors."""
        if self._cloudtrail is None:
            self._cloudtrail = clients.client("cloudtrail", self.region)
        out, token = [], None
        for _ in range(MAX_PAGES):
            if self.calls:
                self._sleep(PAUSE_SECONDS)
            self.calls += 1
            kwargs = {"LookupAttributes": [{"AttributeKey": "ResourceName", "AttributeValue": resource_id}],
                      "MaxResults": PAGE_SIZE}
            if token:
                kwargs["NextToken"] = token
            page = self._cloudtrail.lookup_events(**kwargs)
            for event in page.get("Events") or []:
                name = event.get("EventName")
                if name not in names:
                    continue
                try:
                    detail = json.loads(event.get("CloudTrailEvent") or "{}")
                except (TypeError, ValueError):
                    continue
                if not isinstance(detail, dict) or detail.get("errorCode"):
                    continue  # a failed call created nothing
                out.append((name, detail))
                if name in stop_at:
                    return out
            token = page.get("NextToken")
            if not token:
                break
        return out

    def _run_instances_event(self, instance_id):
        if instance_id not in self._run_instances:
            events = self._events(instance_id, {"RunInstances"}, stop_at={"RunInstances"})
            self._run_instances[instance_id] = events[0][1] if events else None
        return self._run_instances[instance_id]

    # ------------------------------------------------------------ identity -> email

    def _user_email(self, user_name):
        if user_name not in self._user_emails:
            if self._iam is None:
                self._iam = clients.client("iam", config.DEFAULT_REGION)  # IAM is global
            email = None
            try:
                for page in self._iam.get_paginator("list_user_tags").paginate(UserName=user_name):
                    for tag in page.get("Tags") or []:
                        if tag.get("Key") == "email":
                            value = (tag.get("Value") or "").strip().lower()
                            email = value if looks_like_email(value) else None
            except ClientError as err:
                if err.response.get("Error", {}).get("Code") != "NoSuchEntity":
                    raise  # throttling / access denied: not cached, retried next scan
                # user deleted (or in another account): no tag to read
            self._user_emails[user_name] = email
        return self._user_emails[user_name]

    def _identity(self, detail, method):
        """The creating identity of one event -> found / unknown result."""
        identity = detail.get("userIdentity")
        identity = identity if isinstance(identity, dict) else {}
        arn = identity.get("arn") if isinstance(identity.get("arn"), str) else None
        arn = arn[:MAX_ARN_CHARS] if arn else None
        kind = identity.get("type")
        if kind == "Root":
            return _unknown("root_user", method, arn)
        if kind == "IAMUser":
            name = identity.get("userName")
            if not isinstance(name, str) or not name:
                name = arn.rsplit("/", 1)[-1] if arn and ":user/" in arn else None
            email = self._user_email(name) if name else None
            return _found(email, method, arn) if email else _unknown("no_email_tag", method, arn)
        if kind == "AssumedRole":
            session = arn.rsplit("/", 1)[-1].strip().lower() if arn else ""
            return _found(session, method, arn) if looks_like_email(session) else \
                _unknown("role_without_email", method, arn)
        return _unknown("service", method, arn)

    # ------------------------------------------------------------ per resource type

    def instance(self, instance_id):
        detail = self._run_instances_event(instance_id)
        return self._identity(detail, "RunInstances") if detail else _unknown("no_event")

    def address(self, allocation_id):
        events = self._events(allocation_id, {"AllocateAddress"}, stop_at={"AllocateAddress"})
        return self._identity(events[0][1], "AllocateAddress") if events else _unknown("no_event")

    def volume(self, volume_id):
        events = self._events(volume_id, {"CreateVolume", "AttachVolume", "DetachVolume"},
                              stop_at={"CreateVolume"})
        newest = {}
        for name, detail in events:
            newest.setdefault(name, detail)
        if "CreateVolume" in newest:
            return self._identity(newest["CreateVolume"], "CreateVolume")
        row = attachments.get(volume_id)
        last = row.get("instanceId") if row else None
        if isinstance(last, str) and INSTANCE_ID.match(last):
            detail = self._run_instances_event(last)
            if detail:
                return self._identity(detail, "last-attached")
        if "AttachVolume" in newest:
            params = newest["AttachVolume"].get("requestParameters")
            iid = params.get("instanceId") if isinstance(params, dict) else None
            if isinstance(iid, str) and INSTANCE_ID.match(iid):
                detail = self._run_instances_event(iid)
                if detail:
                    return self._identity(detail, "Attach")
        if "DetachVolume" in newest:
            return self._identity(newest["DetachVolume"], "Detach")
        return _unknown("no_event")

    def find(self, resource_type, resource_id):
        self.resources += 1
        return {"ec2": self.instance, "ebs": self.volume, "eip": self.address}[resource_type](resource_id)
