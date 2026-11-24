"""Structure of the EBS timeline definition (engine/terraform/ebs_timeline.asl.json, design §9.3, task #30).

Like test_ec2_timeline_definition.py: the template's ${...} parts are filled with stand-ins of the same shape as
sfn.tf / ebs_timeline.tf (the error-message expression is the real file); this checks the safety properties of the
graph, not the JSONata evaluation (that runs in Step Functions).
"""

import json
import re
from pathlib import Path

import pytest

TF = Path(__file__).resolve().parents[1] / "terraform"
ASL = TF / "ebs_timeline.asl.json"
EBS_TF = TF / "ebs_timeline.tf"
ERROR_MESSAGE = TF / "failure_error_message.jsonata"
CONDITION = "generation = :gen AND #st = :inProgress"
REMEDIATION_ARGS = {"resourceId": "{% $input.resourceId %}", "region": "{% $input.region %}",
                    "dryRun": "{% $input.dryRun %}", "findingType": "{% $input.findingType %}",
                    "generation": "{% $input.generation %}"}
SNAP_ID = {"snapshotId": "{% $snap.snapshotId %}"}
POLL_SECONDS, MAX_POLLS, RESTORE_DAYS = 120, 90, 30
PARTS = {
    "findings_table": "cg-test-findings",
    "notify_arn": "arn:aws:lambda:us-west-2:123456789012:function:cg-test-notify",
    "remediation_arn": "arn:aws:lambda:us-west-2:123456789012:function:cg-test-remediation",
    "finding_key": json.dumps({"resourceId": {"S": "{% $input.resourceId %}"},
                               "findingType": {"S": "{% $input.findingType %}"}}),
    "check_payload": json.dumps({"action": "CHECK_EBS", **REMEDIATION_ARGS}),
    "create_snapshot_payload": json.dumps({"action": "CREATE_SNAPSHOT", **REMEDIATION_ARGS}),
    "snapshot_status_payload": json.dumps({"action": "SNAPSHOT_STATUS", **REMEDIATION_ARGS, **SNAP_ID}),
    "delete_payload": json.dumps({"action": "DELETE_VOLUME", **REMEDIATION_ARGS, **SNAP_ID}),
    "snapshot_poll_seconds": str(POLL_SECONDS),
    "snapshot_max_polls": str(MAX_POLLS),
    "restore_link_days": str(RESTORE_DAYS),
    "notify_retry": json.dumps([{"ErrorEquals": ["Lambda.ServiceException"]}]),
    "remediation_retry": json.dumps([{"ErrorEquals": ["RefusedError"], "MaxAttempts": 0}]),
    "ddb_retry": json.dumps([{"ErrorEquals": ["DynamoDB.ThrottlingException"]}]),
    "audit_table": "cg-test-audit",
    "error_message": json.dumps("{% " + ERROR_MESSAGE.read_text(encoding="utf-8").strip() + " %}"),
    "failure_audit_item": json.dumps({
        "resourceId": {"S": "{% $input.resourceId %}"}, "ts": {"S": "{% $ts %}"}, "day": {"S": "{% $day %}"},
        "actor": {"S": "workflow"}, "event": {"S": "workflow_failed"},
        "details": {"M": {"failedStep": {"S": "{% $failedStep %}"}, "errorMessage": {"S": "{% $errorMessage %}"},
                          "progress": {"S": "{% $progress %}"}}}}),
}
BRANCH = {"MarkFailed", "WriteFailureAudit", "NotifyFailure", "ConfirmationFailed", "Failed"}
CCF = {"ErrorEquals": ["DynamoDB.ConditionalCheckFailedException"], "Next": "Superseded"}
# Snapshot loop outcomes that are not task errors but still end in the failure branch.
SNAPSHOT_PASS = {"SnapshotFailed", "SnapshotTimedOut"}
# After MarkRemediated the finding is no longer in_progress: errors only audit (ConfirmationFailed).
AFTER_REMEDIATED = {"CreateSnapshotReminder", "DeleteConfirmation"}

REAL = ["StepFinalWarning", "StepActing", "RecordSnapshot", "DeleteVolume", "CreateSnapshotReminder"]
DRY = ["StepFinalWarning", "StepActing", "DeleteVolume", "Done"]
COMMON_START = ["SetDeadline", "FirstNotice", "StepWaiting", "WaitBeforeFinal", "RecheckBeforeFinal",
                "StillUnattachedBeforeFinal", "StepFinalWarning", "FinalWarning", "WaitBeforeAction",
                "RecheckBeforeAction", "StillUnattachedBeforeAction", "StepActing", "CreateSnapshot", "HasSnapshot"]


@pytest.fixture(scope="module")
def sm():
    text = ASL.read_text(encoding="utf-8")
    names = set(re.findall(r"\$\{(\w+)\}", text))
    assert names == set(PARTS), "template placeholders changed: update ebs_timeline.tf and this test"
    for name, value in PARTS.items():
        text = text.replace("${" + name + "}", value)
    return json.loads(text)


def nexts(state):
    out = [state.get("Next"), state.get("Default")]
    out += [c["Next"] for c in state.get("Choices", [])] + [c["Next"] for c in state.get("Catch", [])]
    return [n for n in out if n]


def reachable(sm, *start):
    seen, todo = set(), list(start)
    while todo:
        name = todo.pop()
        if name not in seen:
            seen.add(name)
            todo += nexts(sm["States"][name])
    return seen


def path(sm, *choices):
    """Follow the success path from StartAt, taking the given Choice targets in order."""
    order, name, picks = [], sm["StartAt"], list(choices)
    while True:
        order.append(name)
        state = sm["States"][name]
        if state["Type"] == "Succeed":
            return order
        if state["Type"] == "Choice":
            name = picks.pop(0)
            assert name in nexts(state), name
        else:
            name = state["Next"]


def choice(sm, name, target):
    """The Condition of a Choice rule (asserts there is exactly one rule to that target)."""
    [rule] = [c for c in sm["States"][name]["Choices"] if c["Next"] == target]
    return rule["Condition"]


def tasks(sm):
    return {n: s for n, s in sm["States"].items() if s["Type"] == "Task" and n not in BRANCH}


def lambda_tasks(sm, arn):
    return {n: s for n, s in sm["States"].items()
            if s.get("Resource") == "arn:aws:states:::lambda:invoke" and s["Arguments"]["FunctionName"] == arn}


# ---------------------------------------------------------------- graph


def test_top_level(sm):
    assert sm["QueryLanguage"] == "JSONata"
    assert sm["TimeoutSeconds"] == 30 * 24 * 3600


def test_every_state_reachable(sm):
    assert reachable(sm, sm["StartAt"]) == set(sm["States"])


def test_happy_path_order_real(sm):
    assert path(sm, *REAL) == COMMON_START + [
        "RecordSnapshot", "WaitForSnapshot", "SnapshotStatus", "SnapshotReady", "DeleteVolume", "MarkRemediated",
        "DeleteConfirmation", "IsRealDelete", "CreateSnapshotReminder", "Done"]


def test_happy_path_order_dry_run(sm):
    order = path(sm, *DRY)
    assert order == COMMON_START + ["DeleteVolume", "MarkRemediated", "DeleteConfirmation", "IsRealDelete", "Done"]


def test_dry_run_skips_record_snapshot_and_the_loop(sm):
    assert choice(sm, "HasSnapshot", "DeleteVolume") == "{% $snap.snapshotId = null %}"
    assert sm["States"]["HasSnapshot"]["Default"] == "RecordSnapshot"
    order = path(sm, *DRY)
    assert not {"RecordSnapshot", "WaitForSnapshot", "SnapshotStatus", "SnapshotReady"} & set(order)


@pytest.mark.parametrize("name,proceed", [("StillUnattachedBeforeFinal", "StepFinalWarning"),
                                          ("StillUnattachedBeforeAction", "StepActing")])
def test_recheck_branches(sm, name, proceed):
    state = sm["States"][name]
    assert state["Default"] == "MarkResolved"  # attached again, or exists = false
    protect, unattached = state["Choices"]  # protected is checked first
    assert protect == {"Condition": "{% $states.input.protected = true %}", "Next": "MarkProtected"}
    assert unattached == {"Condition": "{% $states.input.stillUnattached = true and $states.input.protected = false %}",
                          "Next": proceed}


def test_final_warning_and_recheck_before_snapshot(sm):
    order = path(sm, *REAL)
    assert (order.index("FinalWarning") < order.index("WaitBeforeAction") < order.index("RecheckBeforeAction")
            < order.index("StillUnattachedBeforeAction") < order.index("StepActing") < order.index("CreateSnapshot")
            < order.index("DeleteVolume"))
    # The only way into CreateSnapshot is StepActing, and into StepActing the last re-check.
    into = {n for n, s in sm["States"].items() if "CreateSnapshot" in nexts(s)}
    assert into == {"StepActing"}
    assert {n for n, s in sm["States"].items() if "StepActing" in nexts(s)} == {"StillUnattachedBeforeAction"}
    into_delete = {n for n, s in sm["States"].items() if "DeleteVolume" in nexts(s)}
    assert into_delete == {"HasSnapshot", "SnapshotReady"}


def test_recheck_before_action_keeps_size_and_zone(sm):
    state = sm["States"]["RecheckBeforeAction"]
    assert state["Assign"] == {"check": "{% $states.result.Payload %}"}
    assert state["Output"] == "{% $states.result.Payload %}"


# ---------------------------------------------------------------- snapshot loop


def test_snapshot_loop_wait(sm):
    wait = sm["States"]["WaitForSnapshot"]
    assert wait == {"Type": "Wait", "Seconds": POLL_SECONDS, "Next": "SnapshotStatus"}
    assert sm["States"]["RecordSnapshot"]["Next"] == "WaitForSnapshot"
    status = sm["States"]["SnapshotStatus"]
    assert status["Assign"] == {"polls": "{% $polls + 1 %}"}
    assert status["Output"] == "{% $states.result.Payload %}"
    assert status["Next"] == "SnapshotReady"
    assert sm["States"]["StepActing"]["Assign"]["polls"] == 0


@pytest.mark.parametrize("target,condition", [
    ("DeleteVolume", "{% $states.input.state = 'completed' %}"),
    ("WaitForSnapshot", "{% $states.input.state = 'pending' and $polls < " + str(MAX_POLLS) + " %}"),
    ("SnapshotFailed", "{% $states.input.state = 'error' %}"),
])
def test_snapshot_ready_rules(sm, target, condition):
    assert choice(sm, "SnapshotReady", target) == condition


def test_snapshot_ready_order_and_default(sm):
    state = sm["States"]["SnapshotReady"]
    assert [c["Next"] for c in state["Choices"]] == ["DeleteVolume", "WaitForSnapshot", "SnapshotFailed"]
    assert state["Default"] == "SnapshotTimedOut"  # pending at the limit, or any unknown state


def simulate_ready(state, snapshot_state, polls):
    """Python reading of the SnapshotReady conditions (checked literally above)."""
    if snapshot_state == "completed":
        return "DeleteVolume"
    if snapshot_state == "pending" and polls < MAX_POLLS:
        return "WaitForSnapshot"
    if snapshot_state == "error":
        return "SnapshotFailed"
    return state["Default"]


@pytest.mark.parametrize("snapshot_state,polls,expected", [
    ("completed", 1, "DeleteVolume"), ("completed", MAX_POLLS, "DeleteVolume"),
    ("pending", 1, "WaitForSnapshot"), ("pending", MAX_POLLS - 1, "WaitForSnapshot"),
    ("pending", MAX_POLLS, "SnapshotTimedOut"),
    ("error", 1, "SnapshotFailed"), ("error", MAX_POLLS, "SnapshotFailed"),
    ("recovering", 1, "SnapshotTimedOut"),
])
def test_snapshot_loop_outcomes(sm, snapshot_state, polls, expected):
    assert simulate_ready(sm["States"]["SnapshotReady"], snapshot_state, polls) == expected


@pytest.mark.parametrize("name,words", [("SnapshotFailed", "is in state error"),
                                        ("SnapshotTimedOut", "is still pending after about ")])
def test_snapshot_failures_go_to_the_failure_branch(sm, name, words):
    state = sm["States"][name]
    assert state["Type"] == "Pass" and state["Next"] == "MarkFailed"
    assign = state["Assign"]
    assert set(assign) == {"failedStep", "progress", "error", "errorMessage"}
    assert assign["failedStep"] == name
    assert words in assign["progress"] and "the volume was not deleted." in assign["progress"]
    assert "$snap.snapshotId" in assign["progress"]
    assert assign["errorMessage"].startswith("{% '" + name + ": snapshot ' & $snap.snapshotId")


def test_timed_out_hours_come_from_the_two_numbers(sm):
    progress = sm["States"]["SnapshotTimedOut"]["Assign"]["progress"]
    assert f"$round({POLL_SECONDS} * {MAX_POLLS} / 3600, 1)" in progress
    assert POLL_SECONDS * MAX_POLLS / 3600 == 3  # "about 3 hours" (task #30)


# ---------------------------------------------------------------- findings writes


def test_every_finding_update_is_conditional_and_ends_quietly(sm):
    updates = {n: s for n, s in sm["States"].items() if s.get("Resource") == "arn:aws:states:::dynamodb:updateItem"}
    assert set(updates) == {"SetDeadline", "StepWaiting", "StepFinalWarning", "StepActing", "RecordSnapshot",
                            "MarkRemediated", "MarkResolved", "MarkProtected", "MarkFailed"}
    for name, state in updates.items():
        args = state["Arguments"]
        assert args["TableName"] == PARTS["findings_table"], name
        assert args["ConditionExpression"] == CONDITION, name
        assert args["ExpressionAttributeNames"] == {"#st": "status"}, name
        assert state["Catch"][0] == CCF, name
        values = args["ExpressionAttributeValues"]
        if isinstance(values, dict):
            assert values[":inProgress"] == {"S": "in_progress"}, name
        else:  # MarkRemediated builds them with $merge
            assert "':gen': {'N': $string($input.generation)}" in values
            assert "':inProgress': {'S': 'in_progress'}" in values
    assert sm["States"]["Superseded"]["Type"] == "Succeed"


def test_step_acting_returns_the_finding(sm):
    state = sm["States"]["StepActing"]
    assert state["Arguments"]["ReturnValues"] == "ALL_NEW"
    assert state["Arguments"]["ExpressionAttributeValues"][":step"] == {"S": "acting"}
    finding = state["Assign"]["finding"]
    for name in ("owner", "ownerSource", "project", "name"):
        assert f"$exists($states.result.Attributes.{name}.S) ? {{'{name}': $states.result.Attributes.{name}.S}} : {{}}" \
            in finding, name
    assert ("{'estimatedSnapshotMonthlyCost': $number($states.result.Attributes.estimatedSnapshotMonthlyCost.N)}"
            in finding)


def test_savings_expression_clamps_at_zero(sm):
    savings = sm["States"]["StepActing"]["Assign"]["savings"]
    assert savings == ("{% $cost = null ? null : $round($max([0, $cost - "
                       "($exists($states.result.Attributes.estimatedSnapshotMonthlyCost.N) ? "
                       "$number($states.result.Attributes.estimatedSnapshotMonthlyCost.N) : 0)]), 2) %}")


def test_record_snapshot(sm):
    args = sm["States"]["RecordSnapshot"]["Arguments"]
    assert args["UpdateExpression"] == "SET snapshotId = :snap"
    assert args["ExpressionAttributeValues"][":snap"] == {"S": "{% $snap.snapshotId %}"}


def test_mark_remediated_sets_contract_fields(sm):
    args = sm["States"]["MarkRemediated"]["Arguments"]
    update = args["UpdateExpression"]
    assert update.startswith("{% 'SET #st = :remediated, remediatedAt = :now, dryRun = :dryRun, timelineStep = :done'")
    assert "($del.dryRun = false ? ', snapshotId = :snap' : '')" in update
    assert "($savings != null ? ', realizedMonthlySavings = :savings' : '')" in update
    values = args["ExpressionAttributeValues"]
    assert "':dryRun': {'BOOL': $del.dryRun}" in values
    assert "$del.dryRun = false ? {':snap': {'S': $snap.snapshotId}} : {}" in values
    assert "$savings != null ? {':savings': {'N': $string($savings)}} : {}" in values
    assert sm["States"]["MarkRemediated"]["Next"] == "DeleteConfirmation"
    resolved = sm["States"]["MarkResolved"]["Arguments"]
    assert resolved["UpdateExpression"] == "SET #st = :resolved, resolvedAt = :now, timelineStep = :done"


def test_mark_protected_makes_finding_report_only(sm):
    state = sm["States"]["MarkProtected"]
    args = state["Arguments"]
    assert args["UpdateExpression"] == "SET #st = :open, reportOnlyReason = :protected, timelineStep = :done"
    assert args["ExpressionAttributeValues"][":protected"] == {"S": "protected"}
    assert state["Next"] == "Protected" and sm["States"]["Protected"]["Type"] == "Succeed"


def test_snapshot_reminder_only_on_the_real_path(sm):
    assert choice(sm, "IsRealDelete", "CreateSnapshotReminder") == "{% $del.dryRun = false %}"
    assert sm["States"]["IsRealDelete"]["Default"] == "Done"
    assert "CreateSnapshotReminder" not in path(sm, *DRY)
    puts = {n for n, s in sm["States"].items() if s.get("Resource") == "arn:aws:states:::dynamodb:putItem"
            and s["Arguments"]["TableName"] == PARTS["findings_table"]}
    assert puts == {"CreateSnapshotReminder"}
    assert {n for n, s in sm["States"].items() if "CreateSnapshotReminder" in nexts(s)} == {"IsRealDelete"}


def test_snapshot_reminder_item(sm):
    state = sm["States"]["CreateSnapshotReminder"]
    args = state["Arguments"]
    assert args["ConditionExpression"] == "attribute_not_exists(resourceId)"
    item = args["Item"]
    for part in ("'resourceId': {'S': $snap.snapshotId}", "'findingType': {'S': 'SNAPSHOT_REMINDER'}",
                 "'resourceType': {'S': 'snapshot'}", "'region': {'S': $input.region}", "'status': {'S': 'open'}",
                 "'sourceVolumeId': {'S': $input.resourceId}", "'sizeGb': {'N': $string($check.sizeGb)}",
                 "'firstSeenAt': {'S': $fromMillis($millis()", "'lastSeenAt': {'S': $fromMillis($millis()",
                 "'generation': {'N': '0'}",
                 "$exists($finding.estimatedSnapshotMonthlyCost) ? "
                 "{'estimatedMonthlyCost': {'N': $string($finding.estimatedSnapshotMonthlyCost)}} : {}"):
        assert part in item, part
    for name in ("owner", "ownerSource", "project", "name"):
        assert f"$exists($finding.{name}) ? {{'{name}': {{'S': $finding.{name}}}}} : {{}}" in item, name
    # Already there: done. Anything else: audit only (the finding is remediated, the email already sent).
    catches = state["Catch"]
    assert catches[0] == {"ErrorEquals": ["DynamoDB.ConditionalCheckFailedException"], "Next": "Done"}
    assert catches[-1]["ErrorEquals"] == ["States.ALL"] and catches[-1]["Next"] == "ConfirmationFailed"
    assert catches[-1]["Assign"]["progress"] == (
        "{% 'Snapshot ' & $snap.snapshotId & ' was created, the volume was deleted, the finding marked remediated "
        "and the confirmation email sent; the snapshot reminder could not be recorded.' %}")
    assert state["Next"] == "Done"


def test_reminder_after_the_confirmation(sm):
    order = path(sm, *REAL)
    assert order.index("MarkRemediated") < order.index("DeleteConfirmation") < order.index("IsRealDelete")         < order.index("CreateSnapshotReminder") < order.index("Done")
    # Only reached once the email went out: the confirmation's only success exit is IsRealDelete.
    assert {n for n, s in sm["States"].items() if "IsRealDelete" in nexts(s)} == {"DeleteConfirmation"}
    assert {n for n, s in sm["States"].items() if "DeleteConfirmation" in nexts(s)} == {"MarkRemediated"}


# ---------------------------------------------------------------- emails


@pytest.mark.parametrize("name", ["FirstNotice", "FinalWarning"])
def test_notice_payload(sm, name):
    payload = sm["States"][name]["Arguments"]["Payload"]
    [finding] = payload["findings"]
    assert finding["actions"] == ["protect", "postpone"]
    assert finding["expiresAt"] == "{% $deadlineAt %}"
    assert set(payload["vars"]) == {"resourceId", "resourceType", "region", "estimatedMonthlyCost", "deadlineAt",
                                    "plannedAction", "dryRun"}
    assert payload["vars"]["plannedAction"] == "snapshot_and_delete"


def test_delete_confirmation_payload(sm):
    state = sm["States"]["DeleteConfirmation"]
    payload = state["Arguments"]["Payload"]
    assert payload["template"] == "DELETE_CONFIRMATION"
    [finding] = payload["findings"]
    assert finding["actions"] == "{% $del.dryRun = false ? ['restore'] : [] %}"  # restore only when not dry-run
    assert finding["expiresAt"] == ("{% $del.dryRun = false ? $fromMillis($millis() + " + str(RESTORE_DAYS) +
                                    " * 86400000, '[Y0001]-[M01]-[D01]T[H01]:[m01]:[s01]Z') : null %}")
    vars_ = payload["vars"]
    # CONTRACT §4.2 R: resourceId, region, sizeGb, snapshotId, realizedMonthlySavings, dryRun. O: availabilityZone, name.
    for part in ("'resourceId': $input.resourceId", "'region': $input.region", "'sizeGb': $check.sizeGb",
                 "'snapshotId': $snap.snapshotId", "'realizedMonthlySavings': $savings", "'dryRun': $del.dryRun",
                 "'availabilityZone': $check.availabilityZone", "$exists($finding.name) ? {'name': $finding.name} : {}"):
        assert part in vars_, part
    assert state["Catch"][-1]["Next"] == "ConfirmationFailed"
    assert state["Next"] == "IsRealDelete" and sm["States"]["Done"]["Type"] == "Succeed"


def test_notify_tasks(sm):
    notify = lambda_tasks(sm, PARTS["notify_arn"])
    templates = {n: s["Arguments"]["Payload"]["template"] for n, s in notify.items()}
    assert templates == {"FirstNotice": "FIRST_NOTICE", "FinalWarning": "FINAL_WARNING",
                         "DeleteConfirmation": "DELETE_CONFIRMATION", "NotifyFailure": "WORKFLOW_FAILED"}
    for name, state in {**notify, **lambda_tasks(sm, PARTS["remediation_arn"])}.items():
        assert state["TimeoutSeconds"] >= 60, name
        assert state["Retry"], name


def test_remediation_calls_pass_finding_type_and_generation(sm):
    calls = lambda_tasks(sm, PARTS["remediation_arn"])
    actions = {n: s["Arguments"]["Payload"]["action"] for n, s in calls.items()}
    assert actions == {"RecheckBeforeFinal": "CHECK_EBS", "RecheckBeforeAction": "CHECK_EBS",
                       "CreateSnapshot": "CREATE_SNAPSHOT", "SnapshotStatus": "SNAPSHOT_STATUS",
                       "DeleteVolume": "DELETE_VOLUME"}
    for name, state in calls.items():
        payload = state["Arguments"]["Payload"]
        assert {k: payload[k] for k in REMEDIATION_ARGS} == REMEDIATION_ARGS, name
    for name in ("SnapshotStatus", "DeleteVolume"):
        assert calls[name]["Arguments"]["Payload"]["snapshotId"] == "{% $snap.snapshotId %}", name
    assert calls["CreateSnapshot"]["Assign"] == {"snap": "{% $states.result.Payload %}"}
    assert calls["DeleteVolume"]["Assign"] == {"del": "{% $states.result.Payload %}"}


def test_ebs_tf_payloads_and_constants():
    tf = EBS_TF.read_text(encoding="utf-8")
    for line in ('check_payload           = jsonencode(merge({ action = "CHECK_EBS" }, local.remediation_args))',
                 'create_snapshot_payload = jsonencode(merge({ action = "CREATE_SNAPSHOT" }, local.remediation_args))',
                 'snapshot_poll_seconds = 120', 'snapshot_max_polls    = 90', 'restore_link_days = 30',
                 'merge(local.timeline_parts, {', 'merge(local.ebs_timeline_parts, local.failure_parts)'):
        assert line in tf, line
    assert '"ForAllValues:StringLike"' in tf and '"dynamodb:LeadingKeys"' in tf and '["snap-*"]' in tf


# ---------------------------------------------------------------- failure handling


def test_every_task_has_a_failure_catch(sm):
    ts = tasks(sm)
    assert len(ts) == 17
    for name, state in ts.items():
        catches = state["Catch"]
        last = catches[-1]
        assert last["ErrorEquals"] == ["States.ALL"], name
        assert last["Next"] == ("ConfirmationFailed" if name in AFTER_REMEDIATED else "MarkFailed"), name
        if state["Resource"] == "arn:aws:states:::dynamodb:updateItem":
            assert catches == [CCF, last], name
        elif name == "CreateSnapshotReminder":
            assert len(catches) == 2, name
        else:
            assert catches == [last], name
        assert state["Retry"], name


def test_catchers_assign_literal_step_and_progress(sm):
    for name, state in tasks(sm).items():
        assign = state["Catch"][-1]["Assign"]
        assert assign["failedStep"] == name, name
        assert isinstance(assign["progress"], str) and assign["progress"].strip(), name
        assert assign["error"] == "{% $states.errorOutput %}", name
        assert assign["errorMessage"] == json.loads(PARTS["error_message"]), name
        extra = {"input"} if name == "SetDeadline" else set()
        assert set(assign) == {"failedStep", "progress", "error", "errorMessage"} | extra, name
    assert sm["States"]["SetDeadline"]["Catch"][-1]["Assign"]["input"] == "{% $states.input %}"


NOTHING_SENT = "No action was taken on the volume; the first notice may not have been sent."
FIRST_SENT = "The first notice was sent; the volume was not changed."
FINAL_MAYBE = "The first notice was sent; the final warning may not have been sent. The volume was not changed."
BOTH_SENT = "The first notice and the final warning were sent; the volume was not changed."
SNAP_KEPT = "{% 'Snapshot ' & $snap.snapshotId & ' was created; the volume was not deleted.' %}"


@pytest.mark.parametrize("name,progress", [
    ("SetDeadline", NOTHING_SENT), ("FirstNotice", NOTHING_SENT),
    ("StepWaiting", FIRST_SENT), ("RecheckBeforeFinal", FIRST_SENT), ("StepFinalWarning", FIRST_SENT),
    ("FinalWarning", FINAL_MAYBE), ("RecheckBeforeAction", BOTH_SENT), ("StepActing", BOTH_SENT),
    ("RecordSnapshot", SNAP_KEPT), ("SnapshotStatus", SNAP_KEPT),
])
def test_progress_says_what_happened_to_the_volume(sm, name, progress):
    assert sm["States"][name]["Catch"][-1]["Assign"]["progress"] == progress


def test_progress_of_the_acting_steps(sm):
    def progress(name):
        return sm["States"][name]["Catch"][-1]["Assign"]["progress"]
    assert progress("CreateSnapshot").startswith("{% $input.dryRun = true ? 'Dry run: nothing was changed.' : ")
    assert "the volume was not changed." in progress("CreateSnapshot")
    assert progress("DeleteVolume") == (
        "{% $snap.dryRun = true ? 'Dry run: nothing was changed.' : 'Snapshot ' & $snap.snapshotId & "
        "' was created; the delete request failed or its result is unknown; check the volume in the console.' %}")
    assert progress("MarkRemediated").startswith("{% $del.dryRun = true ? 'Dry run: nothing was changed")


def test_failure_branch_never_returns_to_the_timeline(sm):
    seen = reachable(sm, "MarkFailed", "ConfirmationFailed")
    assert seen == BRANCH | {"Superseded"}
    assert {n for n in seen if sm["States"][n]["Type"] == "Succeed"} == {"Superseded"}
    assert reachable(sm, "ConfirmationFailed") == {"ConfirmationFailed", "Failed"}
    assert reachable(sm, "WriteFailureAudit") == {"WriteFailureAudit", "NotifyFailure", "Failed"}
    for name in SNAPSHOT_PASS:
        assert reachable(sm, name) == {name} | BRANCH - {"ConfirmationFailed"} | {"Superseded"}


def test_failure_branch_matches_the_ec2_one(sm):
    states = sm["States"]
    assert states["MarkFailed"]["Catch"] == [CCF, {"ErrorEquals": ["States.ALL"], "Next": "Failed"}]
    assert states["MarkFailed"]["Next"] == "WriteFailureAudit"
    assert states["WriteFailureAudit"]["Catch"] == [{"ErrorEquals": ["States.ALL"], "Next": "NotifyFailure"}]
    assert states["NotifyFailure"]["Next"] == "Failed"
    for name in ("WriteFailureAudit", "ConfirmationFailed"):
        assert states[name]["Arguments"]["Item"] == json.loads(PARTS["failure_audit_item"]), name
        assert states[name]["Arguments"]["TableName"] == PARTS["audit_table"], name
    assert states["Failed"] == {"Type": "Fail", "Comment": states["Failed"]["Comment"], "Error": "WorkflowFailed",
                                "Cause": "{% $failedStep & ': ' & $errorMessage %}"}
    ec2 = json.loads(re.sub(r"\$\{(\w+)\}", lambda m: PARTS.get(m.group(1), '"x"'),
                            (TF / "ec2_timeline.asl.json").read_text(encoding="utf-8")))
    for name in BRANCH - {"ConfirmationFailed"}:
        assert states[name] == ec2["States"][name], name


def test_branch_variables_are_set_on_every_way_in(sm):
    used = set()
    for name in BRANCH:
        used |= set(re.findall(r"\$(failedStep|progress|errorMessage)\b", json.dumps(sm["States"][name])))
    used |= set(re.findall(r"\$(failedStep|progress|errorMessage)\b", PARTS["failure_audit_item"]))
    assert used == {"failedStep", "progress", "errorMessage"}
    for name, state in tasks(sm).items():
        assert used <= set(state["Catch"][-1]["Assign"]), name
    for name in SNAPSHOT_PASS:
        assert used <= set(sm["States"][name]["Assign"]), name
