"""Structure of the EC2 timeline definition (engine/terraform/ec2_timeline.asl.json, design §9.2).

The template's ${...} parts are filled with stand-ins of the same shape as sfn.tf (the error-message expression
is the real file); this checks the safety properties of the graph, not the JSONata evaluation (that runs in
Step Functions).
"""

import json
import re
from pathlib import Path

import pytest

TF = Path(__file__).resolve().parents[1] / "terraform"
ASL = TF / "ec2_timeline.asl.json"
ERROR_MESSAGE = TF / "failure_error_message.jsonata"
SFN_TF = TF / "sfn.tf"
CONDITION = "generation = :gen AND #st = :inProgress"
# sfn.tf local.remediation_args: every Remediation call (CONTRACT §4.3, incl. findingType / generation for audit).
REMEDIATION_ARGS = {"resourceId": "{% $input.resourceId %}", "region": "{% $input.region %}",
                    "dryRun": "{% $input.dryRun %}", "findingType": "{% $input.findingType %}",
                    "generation": "{% $input.generation %}"}
PARTS = {
    "findings_table": "cg-test-findings",
    "notify_arn": "arn:aws:lambda:us-west-2:123456789012:function:cg-test-notify",
    "remediation_arn": "arn:aws:lambda:us-west-2:123456789012:function:cg-test-remediation",
    "finding_key": json.dumps({"resourceId": {"S": "{% $input.resourceId %}"},
                               "findingType": {"S": "{% $input.findingType %}"}}),
    "check_payload": json.dumps({"action": "CHECK_EC2", **REMEDIATION_ARGS}),
    "stop_payload": json.dumps({"action": "STOP_INSTANCE", **REMEDIATION_ARGS}),
    "notify_retry": json.dumps([{"ErrorEquals": ["Lambda.ServiceException"]}]),
    "remediation_retry": json.dumps([{"ErrorEquals": ["RefusedError"], "MaxAttempts": 0}]),
    "ddb_retry": json.dumps([{"ErrorEquals": ["DynamoDB.ThrottlingException"]}]),
    "audit_table": "cg-test-audit",
    # The real expression, wrapped like sfn.tf does (jsonencode("{% ... %}")).
    "error_message": json.dumps("{% " + ERROR_MESSAGE.read_text(encoding="utf-8").strip() + " %}"),
    "failure_audit_item": json.dumps({
        "resourceId": {"S": "{% $input.resourceId %}"}, "ts": {"S": "{% $ts %}"}, "day": {"S": "{% $day %}"},
        "actor": {"S": "workflow"}, "event": {"S": "workflow_failed"},
        "findingType": {"S": "{% $input.findingType %}"}, "region": {"S": "{% $input.region %}"},
        "generation": {"N": "{% $string($input.generation) %}"}, "dryRun": {"BOOL": "{% $input.dryRun = true %}"},
        "result": {"S": "error"},
        "details": {"M": {"failedStep": {"S": "{% $failedStep %}"}, "errorMessage": {"S": "{% $errorMessage %}"},
                          "progress": {"S": "{% $progress %}"},
                          "executionName": {"S": "{% $states.context.Execution.Name %}"}}}}),
}
BRANCH = {"MarkFailed", "WriteFailureAudit", "NotifyFailure", "ConfirmationFailed", "Failed"}
CCF = {"ErrorEquals": ["DynamoDB.ConditionalCheckFailedException"], "Next": "Superseded"}


@pytest.fixture(scope="module")
def sm():
    text = ASL.read_text(encoding="utf-8")
    names = set(re.findall(r"\$\{(\w+)\}", text))
    assert names == set(PARTS), "template placeholders changed: update sfn.tf and this test"
    for name, value in PARTS.items():
        text = text.replace("${" + name + "}", value)
    return json.loads(text)


def nexts(state):
    out = [state.get("Next"), state.get("Default")]
    out += [c["Next"] for c in state.get("Choices", [])] + [c["Next"] for c in state.get("Catch", [])]
    return [n for n in out if n]


def path(sm, *choices):
    """Follow the happy path from StartAt, taking the given Choice targets in order."""
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


def test_top_level(sm):
    assert sm["QueryLanguage"] == "JSONata"
    assert sm["TimeoutSeconds"] == 30 * 24 * 3600


def test_every_state_reachable(sm):
    seen, todo = set(), [sm["StartAt"]]
    while todo:
        name = todo.pop()
        if name not in seen:
            seen.add(name)
            todo += nexts(sm["States"][name])
    assert seen == set(sm["States"])


def test_happy_path_order(sm):
    assert path(sm, "StepFinalWarning", "StepActing", "MarkRemediated") == [
        "SetDeadline", "FirstNotice", "StepWaiting", "WaitBeforeFinal", "RecheckBeforeFinal",
        "StillIdleBeforeFinal", "StepFinalWarning", "FinalWarning", "WaitBeforeAction", "RecheckBeforeAction",
        "StillIdleBeforeAction", "StepActing", "StopInstance", "StoppedByGuardian", "MarkRemediated", "StopConfirmation",
        "Remediated"]


@pytest.mark.parametrize("choice,proceed", [("StillIdleBeforeFinal", "StepFinalWarning"),
                                            ("StillIdleBeforeAction", "StepActing")])
def test_recheck_branches(sm, choice, proceed):
    state = sm["States"][choice]
    assert state["Default"] == "MarkResolved"  # not still idle
    protect, idle = state["Choices"]  # protected is checked first
    assert protect == {"Condition": "{% $states.input.protected = true %}", "Next": "MarkProtected"}
    assert "stillIdle = true" in idle["Condition"] and "protected = false" in idle["Condition"]
    assert idle["Next"] == proceed


def test_mark_protected_makes_finding_report_only(sm):
    state = sm["States"]["MarkProtected"]
    args = state["Arguments"]
    assert args["UpdateExpression"] == "SET #st = :open, reportOnlyReason = :protected, timelineStep = :done"
    assert args["ExpressionAttributeValues"][":open"] == {"S": "open"}
    assert args["ExpressionAttributeValues"][":protected"] == {"S": "protected"}
    assert state["Retry"] and state["Next"] == "Protected"
    assert sm["States"]["Protected"]["Type"] == "Succeed"


def test_stopped_by_someone_else_is_resolved_not_remediated(sm):
    state = sm["States"]["StoppedByGuardian"]
    assert sm["States"]["StopInstance"]["Next"] == "StoppedByGuardian"
    assert state["Default"] == "MarkRemediated"
    [rule] = state["Choices"]
    assert rule == {"Condition": "{% $stop.stopped = false and $stop.dryRun = false %}", "Next": "MarkResolved"}


def test_final_warning_and_recheck_before_stop(sm):
    order = path(sm, "StepFinalWarning", "StepActing", "MarkRemediated")
    stop = order.index("StopInstance")
    assert order.index("FinalWarning") < order.index("RecheckBeforeAction") < order.index("StepActing") < stop
    assert sm["States"]["RecheckBeforeAction"]["Arguments"]["Payload"]["action"] == "CHECK_EC2"


def test_every_finding_update_is_conditional_and_ends_quietly(sm):
    updates = {n: s for n, s in sm["States"].items() if s.get("Resource") == "arn:aws:states:::dynamodb:updateItem"}
    assert set(updates) == {"SetDeadline", "StepWaiting", "StepFinalWarning", "StepActing", "MarkRemediated",
                            "MarkResolved", "MarkProtected", "MarkFailed"}
    for name, state in updates.items():
        args = state["Arguments"]
        assert args["TableName"] == PARTS["findings_table"], name
        assert args["ConditionExpression"] == CONDITION, name
        assert state["Catch"][0] == CCF, name  # the finding moved on: checked before any other catcher
    assert sm["States"]["Superseded"]["Type"] == "Succeed"


# ---------------------------------------------------------------- failure handling (task #19, design §9.1)

def timeline_tasks(sm):
    return {n: s for n, s in sm["States"].items() if s["Type"] == "Task" and n not in BRANCH}


def reachable(sm, *start):
    seen, todo = set(), list(start)
    while todo:
        name = todo.pop()
        if name not in seen:
            seen.add(name)
            todo += nexts(sm["States"][name])
    return seen


def test_every_timeline_task_has_a_failure_catch(sm):
    tasks = timeline_tasks(sm)
    assert len(tasks) == 13
    for name, state in tasks.items():
        catches = state["Catch"]
        last = catches[-1]
        assert last["ErrorEquals"] == ["States.ALL"], name  # ASL: States.ALL must be the last catcher
        assert last["Next"] == ("ConfirmationFailed" if name == "StopConfirmation" else "MarkFailed"), name
        if state["Resource"].startswith("arn:aws:states:::dynamodb:"):
            assert catches == [CCF, last], name
        else:
            assert catches == [last], name
        assert state["Retry"], name  # retries stay; the Catch fires after them


def test_catchers_assign_literal_step_and_progress(sm):
    tasks = timeline_tasks(sm)
    for name, state in tasks.items():
        assign = state["Catch"][-1]["Assign"]
        assert assign["failedStep"] == name, name  # a literal, not $states.context
        progress = assign["progress"]
        assert isinstance(progress, str) and progress.strip(), name
        if progress.startswith("{%"):  # only a dry-run choice between two literals
            assert re.fullmatch(r"\{% \$\w+\.dryRun = true \? '[^']+' : '[^']+' %\}", progress), name
        assert assign["error"] == "{% $states.errorOutput %}", name
        assert assign["errorMessage"] == json.loads(PARTS["error_message"]), name
        extra = {"input"} if name == "SetDeadline" else set()
        assert set(assign) == {"failedStep", "progress", "error", "errorMessage"} | extra, name
    # SetDeadline's success-path Assign never ran, and the branch reads $input.
    assert tasks["SetDeadline"]["Catch"][-1]["Assign"]["input"] == "{% $states.input %}"


NOTHING_SENT = "No action was taken on the instance; the first notice may not have been sent."
FIRST_SENT = "The first notice was sent; the instance was not changed."
FINAL_MAYBE = "The first notice was sent; the final warning may not have been sent. The instance was not changed."
BOTH_SENT = "The first notice and the final warning were sent; the instance was not changed."


@pytest.mark.parametrize("name,progress", [
    ("SetDeadline", NOTHING_SENT), ("FirstNotice", NOTHING_SENT),
    ("StepWaiting", FIRST_SENT), ("RecheckBeforeFinal", FIRST_SENT), ("StepFinalWarning", FIRST_SENT),
    ("FinalWarning", FINAL_MAYBE),
    ("RecheckBeforeAction", BOTH_SENT), ("StepActing", BOTH_SENT),
])
def test_progress_before_the_stop_says_which_emails_were_sent(sm, name, progress):
    assert sm["States"][name]["Catch"][-1]["Assign"]["progress"] == progress


def test_stop_instance_progress_depends_on_dry_run(sm):
    progress = sm["States"]["StopInstance"]["Catch"][-1]["Assign"]["progress"]
    assert "$input.dryRun = true" in progress and "'Dry run: nothing was changed.'" in progress
    assert "check the instance state in the console" in progress


def test_error_message_expression_cannot_throw_by_parsing():
    expr = ERROR_MESSAGE.read_text(encoding="utf-8")
    assert "$parse" not in expr and "$eval" not in expr and "$error(" not in expr
    assert "$match($cause" in expr and '"errorMessage"' in expr
    assert "$substring(" in expr and ", 0, 500)" in expr
    assert "\\]" not in expr  # the JSONata regex lexer miscounts brackets after a backslash
    assert "$states.errorOutput" in expr


def test_mark_failed(sm):
    state = sm["States"]["MarkFailed"]
    args = state["Arguments"]
    assert args["UpdateExpression"] == ("SET #st = :failed, failedStep = :failedStep, errorMessage = :errorMessage, "
                                        "timelineStep = :done")
    assert args["ConditionExpression"] == CONDITION
    values = args["ExpressionAttributeValues"]
    assert values[":failed"] == {"S": "failed"} and values[":done"] == {"S": "done"}
    assert values[":inProgress"] == {"S": "in_progress"}
    assert values[":failedStep"] == {"S": "{% $failedStep %}"}
    assert values[":errorMessage"] == {"S": "{% $errorMessage %}"}
    assert state["Retry"]
    # It moved on: end quietly, no email. Anything else: Failed.
    assert state["Catch"] == [CCF, {"ErrorEquals": ["States.ALL"], "Next": "Failed"}]


def test_failure_branch_order(sm):
    states = sm["States"]
    assert states["MarkFailed"]["Next"] == "WriteFailureAudit"
    assert states["WriteFailureAudit"]["Next"] == "NotifyFailure"
    # An audit error must not stop the owner email.
    assert states["WriteFailureAudit"]["Catch"] == [{"ErrorEquals": ["States.ALL"], "Next": "NotifyFailure"}]
    assert states["NotifyFailure"]["Next"] == "Failed"
    assert states["ConfirmationFailed"]["Next"] == "Failed"
    for name in ("NotifyFailure", "ConfirmationFailed"):
        assert states[name]["Catch"] == [{"ErrorEquals": ["States.ALL"], "Next": "Failed"}], name
    for name in BRANCH - {"Failed"}:
        assert states[name]["Retry"], name


def test_failed_is_a_fail_state(sm):
    failed = sm["States"]["Failed"]
    assert failed["Type"] == "Fail"
    assert failed["Error"] == "WorkflowFailed"
    assert failed["Cause"] == "{% $failedStep & ': ' & $errorMessage %}"


def test_failure_branch_never_returns_to_the_timeline(sm):
    seen = reachable(sm, "MarkFailed", "ConfirmationFailed")
    assert seen == BRANCH | {"Superseded"}
    assert {n for n in seen if sm["States"][n]["Type"] == "Succeed"} == {"Superseded"}
    assert reachable(sm, "ConfirmationFailed") == {"ConfirmationFailed", "Failed"}
    assert reachable(sm, "WriteFailureAudit") == {"WriteFailureAudit", "NotifyFailure", "Failed"}


def test_every_failure_branch_error_path_ends_in_failed(sm):
    for name in BRANCH - {"Failed"}:
        for catch in sm["States"][name]["Catch"]:
            if catch == CCF:
                assert name == "MarkFailed"  # the only quiet end: the finding moved on
                continue
            assert "Failed" in reachable(sm, catch["Next"]), name
            assert reachable(sm, catch["Next"]) <= BRANCH, name


def test_failure_audit_entries(sm):
    for name in ("WriteFailureAudit", "ConfirmationFailed"):
        state = sm["States"][name]
        assert state["Resource"] == "arn:aws:states:::dynamodb:putItem", name
        args = state["Arguments"]
        assert args["TableName"] == PARTS["audit_table"], name
        assert args["Item"] == json.loads(PARTS["failure_audit_item"]), name


def test_sfn_tf_failure_parts():
    tf = SFN_TF.read_text(encoding="utf-8")
    assert "superseded_catch" not in tf
    assert "failure_error_message.jsonata" in tf
    assert "'#' & $substring($uuid(), 0, 8)" in tf  # ts = <ISO now>#<8 random chars> (CONTRACT §3.3)
    for line in ('actor       = { S = "workflow" }', 'event       = { S = "workflow_failed" }',
                 'result      = { S = "error" }', 'dryRun      = { BOOL = "{% $input.dryRun = true %}" }',
                 'failedStep    = { S = "{% $failedStep %}" }', 'errorMessage  = { S = "{% $errorMessage %}" }',
                 'progress      = { S = "{% $progress %}" }',
                 'executionName = { S = "{% $states.context.Execution.Name %}" }'):
        assert line in tf, line
    assert 'actions   = ["dynamodb:PutItem"]' in tf and 'resources = [var.table_arns["audit"]]' in tf


def test_workflow_failed_payload(sm):
    state = sm["States"]["NotifyFailure"]
    assert state["Arguments"]["FunctionName"] == PARTS["notify_arn"]
    assert state["TimeoutSeconds"] >= 60
    payload = state["Arguments"]["Payload"]
    assert payload["template"] == "WORKFLOW_FAILED"
    assert payload["to"] == "{% $input.owner %}"
    [finding] = payload["findings"]
    assert finding == {"resourceId": "{% $input.resourceId %}", "findingType": "{% $input.findingType %}",
                       "generation": "{% $input.generation %}", "actions": []}
    # All R variables of CONTRACT §4.2 (no O ones), each from a value set on every way into the branch.
    assert payload["vars"] == {
        "resourceId": "{% $input.resourceId %}", "region": "{% $input.region %}",
        "findingType": "{% $input.findingType %}", "failedStep": "{% $failedStep %}",
        "errorMessage": "{% $errorMessage %}", "progress": "{% $progress %}"}


def test_branch_variables_are_set_by_every_catcher(sm):
    used = set()
    for name in BRANCH:
        used |= set(re.findall(r"\$(failedStep|progress|errorMessage)\b", json.dumps(sm["States"][name])))
    used |= set(re.findall(r"\$(failedStep|progress|errorMessage)\b", PARTS["failure_audit_item"]))
    assert used == {"failedStep", "progress", "errorMessage"}
    for name, state in timeline_tasks(sm).items():
        assert used <= set(state["Catch"][-1]["Assign"]), name


def test_lambda_tasks(sm):
    tasks = {n: s for n, s in sm["States"].items() if s.get("Resource") == "arn:aws:states:::lambda:invoke"}
    for name, state in tasks.items():
        assert state["TimeoutSeconds"] >= 60, name  # at least the Lambda's own timeout (design §17)
        assert state["Retry"], name
    notify = {n for n, s in tasks.items() if s["Arguments"]["FunctionName"] == PARTS["notify_arn"]}
    assert notify == {"FirstNotice", "FinalWarning", "StopConfirmation", "NotifyFailure"}
    templates = {n: tasks[n]["Arguments"]["Payload"]["template"] for n in notify}
    assert templates == {"FirstNotice": "FIRST_NOTICE", "FinalWarning": "FINAL_WARNING",
                         "StopConfirmation": "STOP_CONFIRMATION", "NotifyFailure": "WORKFLOW_FAILED"}


def test_remediation_calls_pass_finding_type_and_generation(sm):
    tasks = {n: s for n, s in sm["States"].items()
             if s.get("Resource") == "arn:aws:states:::lambda:invoke"
             and s["Arguments"]["FunctionName"] == PARTS["remediation_arn"]}
    assert set(tasks) == {"RecheckBeforeFinal", "RecheckBeforeAction", "StopInstance"}
    for name, state in tasks.items():
        payload = state["Arguments"]["Payload"]
        assert {k: payload[k] for k in REMEDIATION_ARGS} == REMEDIATION_ARGS, name
    assert tasks["StopInstance"]["Arguments"]["Payload"]["action"] == "STOP_INSTANCE"


def test_sfn_tf_remediation_args():
    tf = SFN_TF.read_text(encoding="utf-8")
    for line in ('resourceId  = "{% $input.resourceId %}"', 'region      = "{% $input.region %}"',
                 'dryRun      = "{% $input.dryRun %}"', 'findingType = "{% $input.findingType %}"',
                 'generation  = "{% $input.generation %}"',
                 'check_payload = jsonencode(merge({ action = "CHECK_EC2" }, local.remediation_args))',
                 'stop_payload  = jsonencode(merge({ action = "STOP_INSTANCE" }, local.remediation_args))'):
        assert line in tf, line


@pytest.mark.parametrize("name", ["FirstNotice", "FinalWarning"])
def test_notice_payload(sm, name):
    payload = sm["States"][name]["Arguments"]["Payload"]
    [finding] = payload["findings"]
    assert finding["actions"] == ["protect", "postpone"]
    assert finding["expiresAt"] == "{% $deadlineAt %}"
    assert set(payload["vars"]) >= {"resourceId", "resourceType", "region", "estimatedMonthlyCost", "deadlineAt",
                                    "plannedAction", "dryRun"}
    assert payload["vars"]["plannedAction"] == "stop"


def test_stop_confirmation_payload(sm):
    payload = sm["States"]["StopConfirmation"]["Arguments"]["Payload"]
    assert payload["findings"][0]["actions"] == []
    assert set(payload["vars"]) >= {"resourceId", "region", "realizedMonthlySavings", "dryRun", "elasticIps"}


def test_mark_remediated_sets_contract_fields(sm):
    args = sm["States"]["MarkRemediated"]["Arguments"]
    for field in ("#st = :remediated", "remediatedAt", "dryRun = :dryRun", "timelineStep = :done",
                  "realizedMonthlySavings"):
        assert field in args["UpdateExpression"]
    resolved = sm["States"]["MarkResolved"]["Arguments"]
    assert resolved["UpdateExpression"] == "SET #st = :resolved, resolvedAt = :now, timelineStep = :done"
