"""Start and stop a finding's warning timeline (CONTRACT §4.5, design §9.1).

This is the only code that calls Step Functions StartExecution / StopExecution.

    start_timeline(resource_id, finding_type, reason) -> {"result": str, "finding": dict}
    stop_timeline(resource_id, finding_type, new_status, report_only_reason=None) -> dict

Exactly one timeline per finding: every execution is named <ec2|ebs>-<resourceId>-gen<N>, and the
generation N is claimed in the findings table with a conditional write before StartExecution. The same
write checks the required status and the restart / postpone limits and bumps their counters.
`generation` is always stored as a DynamoDB number. This module writes no audit entries (callers do).

Refusals (wrong reason, finding type, status, report-only, limit reached) raise ValueError.

Environment: TABLE_FINDINGS, EC2_SFN_ARN, EBS_SFN_ARN, DRY_RUN, MAX_RESTARTS, MAX_POSTPONES,
POSTPONE_SECONDS, WAIT_BEFORE_FINAL_SECONDS_<EC2|EBS>, WAIT_BEFORE_ACTION_SECONDS_<EC2|EBS>.
"""

import json
import os
import threading
from datetime import datetime, timezone
from decimal import Decimal

import boto3
from botocore.exceptions import ClientError

STATUSES = ("open", "in_progress", "remediated", "resolved", "failed")
REPORT_ONLY_REASONS = ("protected", "autoscaling")

# reason -> status the finding must have (CONTRACT §4.5)
REQUIRED_STATUS = {"new": "open", "reopen": "open", "restart": "failed", "postpone": "in_progress"}
REASONS = tuple(REQUIRED_STATUS)

# reason -> (counter attribute, limit env var, default limit)
COUNTERS = {
    "restart": ("restartCount", "MAX_RESTARTS", 2),
    "postpone": ("postponeCount", "MAX_POSTPONES", 2),
}

# Removed on every new generation (plus executionArn), so a new timeline doesn't show the old one's outcome.
STALE_FIELDS = ("failedStep", "errorMessage", "deadlineAt", "remediatedAt", "resolvedAt", "dryRun",
                "realizedMonthlySavings")

# findingType -> (name prefix / resourceType, state machine ARN env var)
TIMELINE_TYPES = {
    "EC2_IDLE": ("ec2", "EC2_SFN_ARN"),
    "EBS_UNATTACHED": ("ebs", "EBS_SFN_ARN"),
}

# CONTRACT §4.4 default waits in seconds: (before final warning, before action)
DEFAULT_WAITS = {"ec2": (172800, 86400), "ebs": (950400, 259200)}
DEFAULT_POSTPONE_SECONDS = 604800
MAX_START_ATTEMPTS = 3

_local = threading.local()  # per-thread boto3 session and clients (the scanner runs regions in threads)


# ---------------------------------------------------------------- clients and helpers


def _region():
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-west-2"


def _thread_clients():
    """This thread's client cache. boto3 sessions and resources are not thread-safe, so each thread builds its own."""
    local = _local
    if not hasattr(local, "clients"):
        local.session = boto3.session.Session()
        local.clients = {}
    return local


def _table():
    local = _thread_clients()
    if "table" not in local.clients:
        local.clients["table"] = local.session.resource("dynamodb", region_name=_region()).Table(
            os.environ["TABLE_FINDINGS"])
    return local.clients["table"]


def _sfn():
    local = _thread_clients()
    if "sfn" not in local.clients:
        local.clients["sfn"] = local.session.client("stepfunctions", region_name=_region())
    return local.clients["sfn"]


def reset_clients():
    """Forget cached boto3 clients in every thread (tests, or after changing env)."""
    global _local
    _local = threading.local()


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log(resource_id, finding_type, action, result, **extra):
    record = {"resourceId": resource_id, "findingType": finding_type, "action": action, "result": result}
    record.update(extra)
    print(json.dumps(record, default=str))


def _error_code(err):
    return err.response.get("Error", {}).get("Code", "")


def _int_env(name, default):
    value = os.environ.get(name, "").strip()
    return int(value) if value else default


def _dry_run():
    # Safe default: anything other than an explicit "false" is a dry run.
    return os.environ.get("DRY_RUN", "true").strip().lower() != "false"


def execution_name(finding_type, resource_id, generation):
    prefix, _ = TIMELINE_TYPES[finding_type]
    return f"{prefix}-{resource_id}-gen{int(generation)}"


def _state_machine_arn(finding_type):
    return os.environ[TIMELINE_TYPES[finding_type][1]]


def _execution_arn(finding_type, name):
    # arn:aws:states:<region>:<acct>:stateMachine:<sm>  ->  arn:aws:states:<region>:<acct>:execution:<sm>:<name>
    return _state_machine_arn(finding_type).replace(":stateMachine:", ":execution:", 1) + ":" + name


def _current_execution_arn(finding):
    """The stored ARN, or the one derived from executionName (start may have succeeded without saving it)."""
    if finding.get("executionArn"):
        return finding["executionArn"]
    if finding.get("executionName") and finding["findingType"] in TIMELINE_TYPES:
        return _execution_arn(finding["findingType"], finding["executionName"])
    return None


def _get_finding(resource_id, finding_type):
    item = _table().get_item(
        Key={"resourceId": resource_id, "findingType": finding_type}, ConsistentRead=True
    ).get("Item")
    if item is None:
        raise ValueError(f"finding {resource_id}#{finding_type} not found")
    return item


def _key(resource_id, finding_type):
    return {"resourceId": resource_id, "findingType": finding_type}


def _conditional_update(resource_id, finding_type, **kwargs):
    """update_item returning the new item, or None if the condition failed."""
    try:
        return _table().update_item(Key=_key(resource_id, finding_type), ReturnValues="ALL_NEW",
                                    **kwargs)["Attributes"]
    except ClientError as err:
        if _error_code(err) == "ConditionalCheckFailedException":
            return None
        raise


def _limit(reason):
    _, env, default = COUNTERS[reason]
    return _int_env(env, default)


# ---------------------------------------------------------------- start


def _claim_generation(finding, old_gen, required_status, counter_reason=None):
    """Conditional write claiming generation old_gen + 1 (status, report-only and limit checked in the same
    write; the counter for counter_reason bumped). Returns the new item, or None if the condition failed."""
    new_gen = old_gen + 1
    name = execution_name(finding["findingType"], finding["resourceId"], new_gen)
    sets = ["generation = :new", "executionName = :name", "#st = :in_progress", "timelineStep = :first"]
    values = {
        ":new": Decimal(new_gen),
        ":name": name,
        ":in_progress": "in_progress",
        ":first": "first_notice",
        ":old": Decimal(old_gen),
        ":required": required_status,
    }
    conditions = [
        "attribute_exists(resourceId)",
        "attribute_not_exists(reportOnlyReason)",
        "#st = :required",
        "(attribute_not_exists(generation) OR generation = :old)" if old_gen == 0 else "generation = :old",
    ]
    if counter_reason is not None:
        attr = COUNTERS[counter_reason][0]
        sets.append(f"{attr} = if_not_exists({attr}, :zero) + :one")
        conditions.append(f"(attribute_not_exists({attr}) OR {attr} < :limit)")
        values.update({":zero": Decimal(0), ":one": Decimal(1), ":limit": Decimal(_limit(counter_reason))})
    return _conditional_update(
        finding["resourceId"], finding["findingType"],
        UpdateExpression="SET " + ", ".join(sets) + " REMOVE " + ", ".join(("executionArn",) + STALE_FIELDS),
        ConditionExpression=" AND ".join(conditions),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues=values,
    )


def _claim_pending(finding):
    """Re-claim a pending start (name stored, no ARN, still in_progress): same name, no gen+1."""
    return _conditional_update(
        finding["resourceId"], finding["findingType"],
        UpdateExpression="SET timelineStep = :first",
        ConditionExpression=(
            "generation = :gen AND executionName = :name AND attribute_not_exists(executionArn)"
            " AND attribute_not_exists(reportOnlyReason) AND #st = :in_progress"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":gen": finding["generation"],
            ":name": finding["executionName"],
            ":in_progress": "in_progress",
            ":first": "first_notice",
        },
    )


def _store_arn(finding, arn):
    """Record the started execution. Returns the new item, or None if the finding moved on meanwhile."""
    return _conditional_update(
        finding["resourceId"], finding["findingType"],
        UpdateExpression="SET executionArn = :arn",
        ConditionExpression="generation = :gen AND executionName = :name AND #st = :in_progress",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":arn": arn,
            ":gen": finding["generation"],
            ":name": finding["executionName"],
            ":in_progress": "in_progress",
        },
    )


def build_input(finding, reason):
    """CONTRACT §4.4 workflow input built from the finding item."""
    prefix, _ = TIMELINE_TYPES[finding["findingType"]]
    default_final, default_action = DEFAULT_WAITS[prefix]
    suffix = prefix.upper()
    before_final = _int_env(f"WAIT_BEFORE_FINAL_SECONDS_{suffix}", default_final)
    if reason == "postpone":
        before_final = _int_env("POSTPONE_SECONDS", DEFAULT_POSTPONE_SECONDS)
    cost = finding.get("estimatedMonthlyCost")
    return {
        "resourceId": finding["resourceId"],
        "findingType": finding["findingType"],
        "resourceType": finding.get("resourceType", prefix),
        "region": finding.get("region"),
        "owner": finding.get("owner"),
        "generation": int(finding["generation"]),
        "executionName": finding["executionName"],
        "dryRun": _dry_run(),
        "estimatedMonthlyCost": float(cost) if cost is not None else None,
        "waits": {
            "beforeFinalSeconds": before_final,
            "beforeActionSeconds": _int_env(f"WAIT_BEFORE_ACTION_SECONDS_{suffix}", default_action),
        },
    }


def _is_ours(finding, arn):
    """True if the existing execution with our name is RUNNING for this finding and generation (adopt it)."""
    try:
        desc = _sfn().describe_execution(executionArn=arn)
    except ClientError as err:
        if _error_code(err) == "ExecutionDoesNotExist":
            return False
        raise
    if desc.get("status") != "RUNNING":
        return False
    try:
        existing = json.loads(desc.get("input") or "{}")
    except ValueError:
        return False
    return (existing.get("resourceId") == finding["resourceId"]
            and existing.get("generation") == int(finding["generation"]))


def _outcome(resource_id, finding_type, result, finding, **extra):
    _log(resource_id, finding_type, "start_timeline", result, executionName=finding.get("executionName"),
         generation=finding.get("generation"), **extra)
    return {"result": result, "finding": finding}


def start_timeline(resource_id, finding_type, reason):
    """Start the next timeline for a finding. Returns {"result", "finding"} (CONTRACT §4.5)."""
    if reason not in REASONS:
        raise ValueError(f"unknown reason {reason!r}")
    if finding_type not in TIMELINE_TYPES:
        raise ValueError(f"{finding_type} has no timeline")
    finding = _get_finding(resource_id, finding_type)
    if finding.get("reportOnlyReason"):
        raise ValueError(f"{resource_id}#{finding_type} is report-only ({finding['reportOnlyReason']})")

    status = finding.get("status")
    gen = int(finding.get("generation", 0))
    pending = (reason != "postpone" and status == "in_progress" and gen > 0
               and finding.get("executionName") == execution_name(finding_type, resource_id, gen)
               and not finding.get("executionArn"))

    if pending:
        # design §9.1 step 4: an earlier StartExecution failed; retry with the same name, no gen+1.
        claimed = _claim_pending(finding)
    else:
        if reason != "postpone" and status == "in_progress" and finding.get("executionArn"):
            # A timeline is already running (e.g. a retried scan).
            return _outcome(resource_id, finding_type, "already_running", finding, reason=reason)
        required = REQUIRED_STATUS[reason]
        if status != required:
            raise ValueError(f"{resource_id}#{finding_type}: reason {reason!r} needs status {required!r}, "
                             f"not {status!r}")
        counter_reason = reason if reason in COUNTERS else None
        if counter_reason is not None:
            attr = COUNTERS[counter_reason][0]
            if int(finding.get(attr, 0)) >= _limit(counter_reason):
                raise ValueError(f"{resource_id}#{finding_type}: {reason} limit ({_limit(counter_reason)}) reached")
        # Postpone: remember the old execution now; it is stopped only once gen+1 is claimed.
        old_arn = _current_execution_arn(finding) if reason == "postpone" else None
        old_name = finding.get("executionName")
        claimed = _claim_generation(finding, gen, required, counter_reason)

    if claimed is None:
        return _outcome(resource_id, finding_type, "lost_race", _get_finding(resource_id, finding_type),
                        reason=reason)
    if not pending and old_arn:
        _log(resource_id, finding_type, "stop_timeline", _stop_quietly(old_arn), reason="postpone",
             executionName=old_name)
    finding = claimed

    for _attempt in range(MAX_START_ATTEMPTS):
        name = finding["executionName"]
        try:
            arn = _sfn().start_execution(
                stateMachineArn=_state_machine_arn(finding_type),
                name=name,
                input=json.dumps(build_input(finding, reason)),
            )["executionArn"]
            result = "started"
        except ClientError as err:
            if _error_code(err) != "ExecutionAlreadyExists":
                # Leaves the name stored without an ARN: the next call retries with the same name.
                _log(resource_id, finding_type, "start_timeline", "error", reason=reason,
                     executionName=name, error=str(err))
                raise
            arn = _execution_arn(finding_type, name)
            if _is_ours(finding, arn):
                result = "adopted"
            else:
                # An old execution (Step Functions keeps names for 90 days): move to the next generation.
                _log(resource_id, finding_type, "start_timeline", "name_taken", executionName=name)
                bumped = _claim_generation(finding, int(finding["generation"]), "in_progress")
                if bumped is None:
                    return _outcome(resource_id, finding_type, "lost_race",
                                    _get_finding(resource_id, finding_type), reason=reason)
                finding = bumped
                continue

        stored = _store_arn(finding, arn)
        if stored is None:
            # The finding moved on (stopped / resolved / next generation) while we started: don't leave
            # an orphan timeline running.
            if result != "adopted":
                _stop_quietly(arn)
            return _outcome(resource_id, finding_type, "superseded", _get_finding(resource_id, finding_type),
                            reason=reason, startedName=name)
        return _outcome(resource_id, finding_type, result, stored, reason=reason, pendingRetry=pending)

    _log(resource_id, finding_type, "start_timeline", "error", reason=reason,
         error="execution names taken after max attempts")
    raise RuntimeError(f"{resource_id}#{finding_type}: could not start a timeline after "
                       f"{MAX_START_ATTEMPTS} attempts (names already used)")


# ---------------------------------------------------------------- stop


def _stop_quietly(arn):
    """StopExecution, ignoring executions that don't exist or have already finished. Returns a result word."""
    try:
        status = _sfn().describe_execution(executionArn=arn).get("status")
    except ClientError as err:
        if _error_code(err) == "ExecutionDoesNotExist":
            return "not_found"
        raise
    if status != "RUNNING":
        return "already_finished"
    try:
        _sfn().stop_execution(executionArn=arn, cause="stopped by cost guardian timeline")
        return "stopped"
    except ClientError as err:
        if _error_code(err) == "ExecutionDoesNotExist":
            return "not_found"
        # Finished between describe and stop?
        if _sfn().describe_execution(executionArn=arn).get("status") != "RUNNING":
            return "already_finished"
        raise


def stop_timeline(resource_id, finding_type, new_status, report_only_reason=None):
    """Stop the finding's current execution (if any) and set its status. Returns the updated item."""
    if new_status not in STATUSES:
        raise ValueError(f"unknown status {new_status!r}")
    if report_only_reason is not None and report_only_reason not in REPORT_ONLY_REASONS:
        raise ValueError(f"unknown reportOnlyReason {report_only_reason!r}")
    finding = _get_finding(resource_id, finding_type)

    arn = _current_execution_arn(finding)
    stop_result = _stop_quietly(arn) if arn else "no_execution"

    sets = ["#st = :status"]
    values = {":status": new_status}
    if finding.get("executionName"):
        sets.append("timelineStep = :done")
        values[":done"] = "done"
    if report_only_reason is not None:
        sets.append("reportOnlyReason = :ror")
        values[":ror"] = report_only_reason
    if new_status == "resolved":
        sets.append("resolvedAt = :now")
        values[":now"] = _now()
    updated = _table().update_item(
        Key=_key(resource_id, finding_type),
        UpdateExpression="SET " + ", ".join(sets),
        ConditionExpression="attribute_exists(resourceId)",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues=values,
        ReturnValues="ALL_NEW",
    )["Attributes"]
    _log(resource_id, finding_type, "stop_timeline", stop_result, newStatus=new_status,
         executionName=finding.get("executionName"), reportOnlyReason=report_only_reason)
    return updated
