"""Action Lambda: the email action links (design §10.4, CONTRACT §3.4 / §4.6).

    GET  /action?t=<token>  -> confirmation page. Never writes to DynamoDB (one log line only).
    POST /action  (form t)  -> the same checks, then one TransactWriteItems claims the token (token unused and not
                               expired; ConditionCheck on the finding: same generation, required status, postpone
                               limit, restore dryRun = false), then the action runs and a result page is returned.

Actions:
- protect:  CreateTags guardian:protect=true, then timeline.stop_timeline(..., "open", "protected").
- postpone: timeline.start_timeline(..., "postpone") (stops the current execution, generation + 1).
- restore:  CreateVolume (gp3, the finding's availabilityZone) from the finding's snapshotId, tagged with the
            snapshot's tags minus guardian:source-volume / aws:* plus guardian:restored-from, then a RESTORE_DONE
            email. The finding stays remediated.
Protect and postpone also act when DRY_RUN is on: they only prevent or delay (CONTRACT §4.6).

If the action fails before anything changed, the token is given back (used = false) so the link works again.
If something already changed (e.g. the tag was added but the timeline could not be stopped), it stays used.

Audit (actor action-link): link_protect / link_postpone / link_restore (result ok or error), and link_refused only
for POST refusals of known tokens. GET refusals and unknown tokens are only logged.

The raw token is never logged or echoed, except in the confirmation page's hidden form field.

Environment: NAME_PREFIX, TABLE_FINDINGS, TABLE_AUDIT, TABLE_TOKENS, DEV_SCOPE, DRY_RUN, EC2_SFN_ARN, EBS_SFN_ARN,
WAIT_BEFORE_FINAL_SECONDS_<EC2|EBS>, WAIT_BEFORE_ACTION_SECONDS_<EC2|EBS>, POSTPONE_SECONDS, MAX_POSTPONES,
MAX_RESTARTS, NOTIFY_FUNCTION_NAME.
"""

import base64
import binascii
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs

import boto3
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from botocore.config import Config
from botocore.exceptions import ClientError

import action_pages as pages
from common import audit, timeline

ACTOR = "action-link"
PROTECT_TAG = "guardian:protect"
SCOPE_TAG = "guardian:dev-scope"
SOURCE_VOLUME_TAG = "guardian:source-volume"
RESTORED_FROM_TAG = "guardian:restored-from"
ACTIONS = ("protect", "postpone", "restore")
TIMELINE_ACTIONS = ("protect", "postpone")
TIMELINE_TYPES = ("EC2_IDLE", "EBS_UNATTACHED")
AUDIT_EVENTS = {"protect": "link_protect", "postpone": "link_postpone", "restore": "link_restore"}
# secrets.token_urlsafe(32) is 43 characters of the URL-safe base64 alphabet; accept a little slack.
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
MAX_BODY_BYTES = 4096
# CONTRACT §4.4 default before-action waits, used for the "new deadline" estimate of a postpone.
DEFAULT_BEFORE_ACTION = {"EC2_IDLE": 86400, "EBS_UNATTACHED": 259200}
WAIT_SUFFIX = {"EC2_IDLE": "EC2", "EBS_UNATTACHED": "EBS"}

_CONFIG = Config(connect_timeout=5, read_timeout=10, retries={"mode": "standard", "max_attempts": 3})
_serializer = TypeSerializer()
_deserializer = TypeDeserializer()
_clients = {}


# ---------------------------------------------------------------- clients and helpers


def _region():
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-west-2"


def _client(service, region=None):
    region = region or _region()
    key = (service, region)
    if key not in _clients:
        _clients[key] = boto3.client(service, region_name=region, config=_CONFIG)
    return _clients[key]


def reset_clients():
    """Forget cached clients (tests, or after changing env)."""
    _clients.clear()
    timeline.reset_clients()
    audit.reset_clients()


def _now_dt():
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value):
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _int_env(name, default):
    value = os.environ.get(name, "").strip()
    return int(value) if value else default


def _max_postpones():
    return _int_env("MAX_POSTPONES", 2)


def _code(err):
    return err.response.get("Error", {}).get("Code", "")


def token_hash(raw):
    """Same as platform/src/notify/notify_tokens.py token_hash."""
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def _plain(value):
    """DynamoDB item -> plain values (Decimal kept)."""
    return {k: _deserializer.deserialize(v) for k, v in value.items()}


def _typed(values):
    return {k: _serializer.serialize(v) for k, v in values.items()}


def _get(table_env, key):
    item = _client("dynamodb").get_item(TableName=os.environ[table_env], Key=_typed(key),
                                        ConsistentRead=True).get("Item")
    return _plain(item) if item else None


def _gen(value):
    return int(value) if value is not None else None


def _tags(resource):
    return {t["Key"]: t["Value"] for t in (resource or {}).get("Tags", []) or []}


def _log(record):
    print(json.dumps(record, default=str))


class Refusal(Exception):
    """A link that can't be used now: shown as an HTML page with an HTTP 4xx status."""

    def __init__(self, status, reason, title, message):
        super().__init__(reason)
        self.status, self.reason, self.title, self.message = status, reason, title, message


def _refuse(status, reason, title, message):
    raise Refusal(status, reason, title, message)


def _ref_used():
    _refuse(410, "used", "This link was already used",
            "Each link works only once, and this one has already been used.")


# ---------------------------------------------------------------- request parsing


def _method(event):
    return ((event.get("requestContext") or {}).get("http") or {}).get("method", "").upper()


def _single(values):
    """The one value of a form / query field, or None if absent or repeated."""
    return values[0] if isinstance(values, list) and len(values) == 1 else None


def _token_from_get(event):
    params = event.get("queryStringParameters") or {}
    raw = params.get("t")
    # HTTP API v2 joins repeated query parameters with commas; a comma is not in the token alphabet.
    return raw if isinstance(raw, str) else None


def _token_from_post(event):
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        try:
            body = base64.b64decode(body, validate=True).decode("utf-8")
        except (binascii.Error, ValueError):
            return None
    if len(body) > MAX_BODY_BYTES:
        return None
    try:
        form = parse_qs(body, keep_blank_values=True, strict_parsing=False, max_num_fields=10)
    except ValueError:
        return None
    return _single(form.get("t"))


# ---------------------------------------------------------------- checks


def _describe_resource(finding):
    """The instance / volume dict in the finding's region, or None if it no longer exists."""
    ec2 = _client("ec2", finding.get("region"))
    rid = finding["resourceId"]
    try:
        if finding["findingType"] == "EC2_IDLE":
            reservations = ec2.describe_instances(InstanceIds=[rid])["Reservations"]
            found = [i for r in reservations for i in r["Instances"]]
        else:
            found = ec2.describe_volumes(VolumeIds=[rid])["Volumes"]
    except ClientError as err:
        if _code(err) in ("InvalidInstanceID.NotFound", "InvalidInstanceID.Malformed", "InvalidVolume.NotFound",
                          "InvalidVolume.Malformed"):
            return None
        raise
    return found[0] if found else None


def _describe_snapshot(region, snapshot_id):
    try:
        found = _client("ec2", region).describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"]
    except ClientError as err:
        if _code(err) in ("InvalidSnapshot.NotFound", "InvalidSnapshot.Malformed"):
            return None
        raise
    return found[0] if found else None


def _check_scope(tags, what):
    scope = os.environ.get("DEV_SCOPE", "").strip()
    if scope and tags.get(SCOPE_TAG) != scope:
        _refuse(409, "outside_dev_scope", "Not handled by this stack",
                f"This {what} is outside this Cost Guardian stack's test scope, so this link can't act on it.")


def _required_status(action):
    return "remediated" if action == "restore" else "in_progress"


def _new_deadline(finding_type, now):
    seconds = (_int_env("POSTPONE_SECONDS", timeline.DEFAULT_POSTPONE_SECONDS)
               + _int_env(f"WAIT_BEFORE_ACTION_SECONDS_{WAIT_SUFFIX[finding_type]}",
                          DEFAULT_BEFORE_ACTION[finding_type]))
    return _iso(now + timedelta(seconds=seconds))


def evaluate(raw):
    """Look the token up and run every check (CONTRACT §3.4 / §4.6), in order. Reads only.

    Returns ctx = {token, finding, action, info, snapshot?}. Raises Refusal; ctx-so-far is on the exception
    (attribute ctx) so POST refusals of known tokens can be audited."""
    ctx = {}
    try:
        return _evaluate(raw, ctx)
    except Refusal as refusal:
        refusal.ctx = ctx
        raise


def _evaluate(raw, ctx):
    now = _now_dt()
    token = _get("TABLE_TOKENS", {"tokenHash": token_hash(raw)})
    if token is None or token.get("action") not in ACTIONS:
        _refuse(404, "unknown", "Link not recognized",
                "This link is not valid. Use the links in the most recent email from Cost Guardian.")
    ctx["token"] = token
    action = ctx["action"] = token["action"]
    if token.get("used") is True:
        _ref_used()
    expires = token.get("expiresAt")
    if not expires or _parse_iso(expires) <= now:
        _refuse(410, "expired", "This link has expired",
                "This link is no longer valid: its deadline has passed.")

    finding = _get("TABLE_FINDINGS", {"resourceId": token["resourceId"], "findingType": token["findingType"]})
    if finding is None:
        _refuse(410, "finding_missing", "Nothing to act on",
                "Cost Guardian no longer tracks this resource, so this link has nothing to act on.")
    ctx["finding"] = finding
    token_gen, finding_gen = _gen(token.get("generation")), _gen(finding.get("generation")) or 0
    if token_gen is None or token_gen < finding_gen:
        _refuse(410, "older_generation", "A newer email was sent",
                "A newer email was sent; use the links in the newest one.")
    if token_gen != finding_gen:
        _refuse(409, "generation_mismatch", "This link can't be used now",
                "This link doesn't match the resource's current warning. Use the links in the newest email.")

    status = finding.get("status")
    required = _required_status(action)
    wrong = status != required
    if action in TIMELINE_ACTIONS:
        wrong = wrong or finding["findingType"] not in TIMELINE_TYPES
    else:
        wrong = wrong or finding["findingType"] != "EBS_UNATTACHED" or finding.get("dryRun") is not False
    if wrong:
        _refuse(409, "wrong_status", "This link can't be used now",
                f"This action is no longer possible: the finding is now {status or 'unknown'}.")
    if action == "postpone" and int(finding.get("postponeCount", 0)) >= _max_postpones():
        _refuse(409, "postpone_limit", "No postpones left",
                f"This resource was already postponed {_max_postpones()} times, the maximum.")

    info = {"resourceId": finding["resourceId"], "findingType": finding["findingType"],
            "region": finding.get("region"), "name": finding.get("name"), "deadlineAt": finding.get("deadlineAt")}
    ctx["info"] = info

    if action == "restore":
        snapshot_id = finding.get("snapshotId")
        snapshot = _describe_snapshot(finding.get("region"), snapshot_id) if snapshot_id else None
        if snapshot is None or _tags(snapshot).get(SOURCE_VOLUME_TAG) != finding["resourceId"]:
            _refuse(410, "snapshot_missing", "The snapshot no longer exists",
                    "The snapshot no longer exists; restore from the console is not possible either.")
        _check_scope(_tags(snapshot), "snapshot")
        if not finding.get("availabilityZone"):
            _refuse(409, "zone_unknown", "Restore not possible from this link",
                    f"The original volume's Availability Zone is not recorded, so this link can't restore it. "
                    f"Snapshot {snapshot_id} still exists: create a volume from it in the console.")
        ctx["snapshot"] = snapshot
        info.update(snapshotId=snapshot_id, availabilityZone=finding["availabilityZone"])
    else:
        resource = _describe_resource(finding)
        if resource is None:
            _refuse(410, "resource_missing", "The resource no longer exists",
                    "This resource no longer exists, so there is nothing to protect or postpone.")
        tags = _tags(resource)
        _check_scope(tags, "resource")
        info["name"] = tags.get("Name") or info["name"]
        if action == "postpone":
            info["newDeadlineAt"] = _new_deadline(finding["findingType"], now)
            info["postponesLeftAfter"] = _max_postpones() - int(finding.get("postponeCount", 0)) - 1
    return ctx


# ---------------------------------------------------------------- token claim and give-back


def _claim(raw, ctx):
    """One TransactWriteItems: token used = true (if unused and not expired) + ConditionCheck on the finding.
    Returns True if claimed, False if the transaction was cancelled."""
    token, finding, action = ctx["token"], ctx["finding"], ctx["action"]
    now = _iso(_now_dt())
    check_cond = ["generation = :gen", "#st = :required"]
    check_values = {":gen": token["generation"], ":required": _required_status(action)}
    if action == "postpone":
        check_cond.append("(attribute_not_exists(postponeCount) OR postponeCount < :max)")
        check_values[":max"] = _max_postpones()
    if action == "restore":
        check_cond.append("dryRun = :false")
        check_values[":false"] = False
    try:
        _client("dynamodb").transact_write_items(TransactItems=[
            {"Update": {
                "TableName": os.environ["TABLE_TOKENS"],
                "Key": _typed({"tokenHash": token_hash(raw)}),
                "UpdateExpression": "SET used = :true, usedAt = :now",
                "ConditionExpression": "used = :false AND expiresAt > :now",
                "ExpressionAttributeValues": _typed({":true": True, ":false": False, ":now": now}),
            }},
            {"ConditionCheck": {
                "TableName": os.environ["TABLE_FINDINGS"],
                "Key": _typed({"resourceId": finding["resourceId"], "findingType": finding["findingType"]}),
                "ConditionExpression": " AND ".join(check_cond),
                "ExpressionAttributeNames": {"#st": "status"},
                "ExpressionAttributeValues": _typed(check_values),
            }},
        ])
        return True
    except ClientError as err:
        if _code(err) == "TransactionCanceledException":
            return False
        raise


def _give_back(raw, ctx):
    """The action failed before changing anything: the link works again."""
    try:
        _client("dynamodb").update_item(
            TableName=os.environ["TABLE_TOKENS"],
            Key=_typed({"tokenHash": token_hash(raw)}),
            UpdateExpression="SET used = :false REMOVE usedAt",
            ConditionExpression="used = :true",
            ExpressionAttributeValues=_typed({":true": True, ":false": False}),
        )
        return True
    except Exception as err:  # noqa: BLE001 - the page and audit still go out
        _log({"resourceId": ctx["finding"]["resourceId"], "findingType": ctx["finding"]["findingType"],
              "action": "token_give_back", "result": "error", "error": repr(err)[:300]})
        return False


# ---------------------------------------------------------------- actions


class ActionFailed(Exception):
    """The action failed. changed=False: nothing was changed (the token is given back)."""

    def __init__(self, changed, message, cause, rows=()):
        super().__init__(message)
        self.changed, self.message, self.cause, self.rows = changed, message, cause, rows


def _do_protect(ctx):
    finding = ctx["finding"]
    rid, ftype = finding["resourceId"], finding["findingType"]
    try:
        _client("ec2", finding.get("region")).create_tags(
            Resources=[rid], Tags=[{"Key": PROTECT_TAG, "Value": "true"}])
    except Exception as err:  # noqa: BLE001
        raise ActionFailed(False, "Nothing was changed, you can try the link again.", err) from err
    try:
        timeline.stop_timeline(rid, ftype, "open", "protected", actor=ACTOR)
    except Exception as err:  # noqa: BLE001
        raise ActionFailed(
            True, "The tag guardian:protect=true was added, but the warning timeline could not be stopped. "
                  "The Guardian re-checks the tag before acting, so the resource will not be stopped or deleted.",
            err) from err
    return {}


def _do_postpone(ctx):
    finding = ctx["finding"]
    rid, ftype = finding["resourceId"], finding["findingType"]
    try:
        outcome = timeline.start_timeline(rid, ftype, "postpone", actor=ACTOR)
    except Exception as err:  # noqa: BLE001
        raise ActionFailed(False, "Nothing was changed, you can try the link again.", err) from err
    result, new = outcome["result"], outcome["finding"]
    if result == "lost_race":
        # The finding changed between the claim and the timeline's own conditional write: nothing changed.
        raise ActionFailed(False, "The resource changed meanwhile and nothing was postponed. "
                                  "You can try the link again.", RuntimeError("lost_race"))
    if result not in ("started", "adopted"):
        raise ActionFailed(True, "The timeline was restarted, but the resource changed meanwhile "
                                 "(it may have been resolved).", RuntimeError(result))
    return {"generation": _gen(new.get("generation")), "executionName": new.get("executionName")}


def _restore_tags(snapshot, snapshot_id):
    tags = [{"Key": k, "Value": v} for k, v in _tags(snapshot).items()
            if not k.startswith("aws:") and k not in (SOURCE_VOLUME_TAG, RESTORED_FROM_TAG)]
    tags.append({"Key": RESTORED_FROM_TAG, "Value": snapshot_id})
    return tags


def _notify_restore(finding, new_volume_id):
    payload = {
        "template": "RESTORE_DONE",
        "to": finding.get("owner") or None,
        "findings": [{"resourceId": finding["resourceId"], "findingType": finding["findingType"],
                      "generation": _gen(finding.get("generation")), "actions": []}],
        "vars": {"sourceVolumeId": finding["resourceId"], "snapshotId": finding["snapshotId"],
                 "newVolumeId": new_volume_id, "availabilityZone": finding["availabilityZone"],
                 "region": finding.get("region")},
    }
    try:
        response = _client("lambda").invoke(FunctionName=os.environ["NOTIFY_FUNCTION_NAME"],
                                            InvocationType="RequestResponse", Payload=json.dumps(payload).encode())
        if response.get("FunctionError"):
            body = response["Payload"].read().decode("utf-8", "replace")[:300]
            raise RuntimeError(f"notify {response['FunctionError']}: {body}")
        return True
    except Exception as err:  # noqa: BLE001 - the volume exists; the page still shows success
        _log({"resourceId": finding["resourceId"], "findingType": finding["findingType"], "action": "notify_restore",
              "result": "error", "error": repr(err)[:300]})
        return False


def _do_restore(ctx):
    finding, snapshot = ctx["finding"], ctx["snapshot"]
    snapshot_id = finding["snapshotId"]
    try:
        volume = _client("ec2", finding.get("region")).create_volume(
            AvailabilityZone=finding["availabilityZone"], SnapshotId=snapshot_id, VolumeType="gp3",
            TagSpecifications=[{"ResourceType": "volume", "Tags": _restore_tags(snapshot, snapshot_id)}])
    except Exception as err:  # noqa: BLE001
        raise ActionFailed(False, "Nothing was changed, you can try the link again.", err) from err
    new_volume_id = volume["VolumeId"]
    ctx["info"]["newVolumeId"] = new_volume_id
    notified = _notify_restore(finding, new_volume_id)
    return {"snapshotId": snapshot_id, "newVolumeId": new_volume_id, "notified": notified}


DO = {"protect": _do_protect, "postpone": _do_postpone, "restore": _do_restore}


# ---------------------------------------------------------------- audit


def _audit(ctx, event, result, details, generation=None):
    finding = ctx.get("finding") or {}
    token = ctx["token"]
    audit.write_audit(
        token["resourceId"], ACTOR, event, finding_type=token["findingType"], region=finding.get("region"),
        generation=generation if generation is not None else _gen(finding.get("generation", token["generation"])),
        dry_run=False if ctx["action"] == "restore" else None, result=result, details=details)


def _audit_refused(ctx, reason):
    _audit(ctx, "link_refused", "skipped",
           {"reason": reason, "action": ctx["action"], "tokenGeneration": _gen(ctx["token"].get("generation"))})


# ---------------------------------------------------------------- request handling


def _refusal_response(refusal):
    return pages.response(refusal.status, pages.refusal(refusal.title, refusal.message))


def _handle_get(raw, log):
    try:
        ctx = evaluate(raw)
    except Refusal as refusal:
        log.update(_ids(refusal.ctx), result="refused", reason=refusal.reason)
        return _refusal_response(refusal)
    log.update(_ids(ctx), result="confirm_page")
    return pages.response(200, pages.confirmation(ctx["action"], ctx["info"], raw))


def _ids(ctx):
    token = ctx.get("token") or {}
    return {"resourceId": token.get("resourceId"), "findingType": token.get("findingType"),
            "action": ctx.get("action")}


def _handle_post(raw, log):
    try:
        ctx = evaluate(raw)
    except Refusal as refusal:
        return _post_refused(refusal, log)
    log.update(_ids(ctx))

    if not _claim(raw, ctx):
        # Cancelled: a concurrent click, an expiry or a generation / status change. Re-read for the reason.
        try:
            evaluate(raw)
        except Refusal as refusal:
            return _post_refused(refusal, log, claim="cancelled")
        refusal = Refusal(409, "claim_conflict", "Please try again",
                          "The resource was being changed at the same moment. Nothing was changed; "
                          "you can try the link again.")
        refusal.ctx = ctx
        return _post_refused(refusal, log, claim="cancelled")

    action = ctx["action"]
    try:
        details = DO[action](ctx)
    except ActionFailed as failed:
        given_back = False if failed.changed else _give_back(raw, ctx)
        log.update(result="error", changed=failed.changed, tokenGivenBack=given_back,
                   error=repr(failed.cause)[:300])
        _audit(ctx, AUDIT_EVENTS[action], "error",
               {"changed": failed.changed, "tokenGivenBack": given_back, "error": repr(failed.cause)[:300]})
        message = failed.message
        if not failed.changed and not given_back:
            message = "Nothing was changed, but the link could not be reset. Use the links in the next email."
        return pages.response(500, pages.error(message, [("Resource", ctx["finding"]["resourceId"]),
                                                         ("Region", ctx["finding"].get("region"))]))
    _audit(ctx, AUDIT_EVENTS[action], "ok", details, generation=details.get("generation"))
    log.update(result="ok", **{k: v for k, v in details.items() if k != "generation"})
    return pages.response(200, pages.done(action, ctx["info"]))


def _post_refused(refusal, log, **extra):
    ctx = refusal.ctx
    log.update(_ids(ctx), result="refused", reason=refusal.reason, **extra)
    if ctx.get("token"):  # known token: audit (CONTRACT §4.6)
        _audit_refused(ctx, refusal.reason)
    return _refusal_response(refusal)


def handler(event, context):
    method = _method(event)
    log = {"resourceId": None, "findingType": None, "action": None, "result": None, "method": method}
    try:
        if method not in ("GET", "POST"):
            log["result"] = "method_not_allowed"
            response = pages.response(405, pages.refusal("Method not allowed", "Use the link from the email."),
                                      {"Allow": "GET, POST"})
        else:
            raw = _token_from_get(event) if method == "GET" else _token_from_post(event)
            if not raw or not TOKEN_RE.match(raw):
                log["result"] = "bad_request"
                response = pages.response(400, pages.refusal(
                    "Link not recognized", "This link is incomplete. Copy the whole link from the email."))
            elif method == "GET":
                response = _handle_get(raw, log)
            else:
                response = _handle_post(raw, log)
    except Exception as err:  # noqa: BLE001 - always answer with a page; never echo the token
        log.update(result="error", error=repr(err)[:300])
        response = pages.response(500, pages.error("Something went wrong. Nothing was changed by this page; "
                                                   "you can try the link again later."))
    log["statusCode"] = response["statusCode"]
    _log(log)
    return response
