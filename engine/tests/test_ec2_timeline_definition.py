"""Structure of the EC2 timeline definition (engine/terraform/ec2_timeline.asl.json, design §9.2).

The template's ${...} parts are filled with stand-ins of the same shape as sfn.tf; this checks the
safety properties of the graph, not the JSONata evaluation (that runs in Step Functions).
"""

import json
import re
from pathlib import Path

import pytest

ASL = Path(__file__).resolve().parents[1] / "terraform" / "ec2_timeline.asl.json"
CONDITION = "generation = :gen AND #st = :inProgress"
PARTS = {
    "findings_table": "cg-test-findings",
    "notify_arn": "arn:aws:lambda:us-west-2:123456789012:function:cg-test-notify",
    "remediation_arn": "arn:aws:lambda:us-west-2:123456789012:function:cg-test-remediation",
    "finding_key": json.dumps({"resourceId": {"S": "{% $input.resourceId %}"},
                               "findingType": {"S": "{% $input.findingType %}"}}),
    "check_payload": json.dumps({"action": "CHECK_EC2", "resourceId": "{% $input.resourceId %}",
                                 "region": "{% $input.region %}", "dryRun": "{% $input.dryRun %}"}),
    "notify_retry": json.dumps([{"ErrorEquals": ["Lambda.ServiceException"]}]),
    "remediation_retry": json.dumps([{"ErrorEquals": ["RefusedError"], "MaxAttempts": 0}]),
    "ddb_retry": json.dumps([{"ErrorEquals": ["DynamoDB.ThrottlingException"]}]),
    "superseded_catch": json.dumps([{"ErrorEquals": ["DynamoDB.ConditionalCheckFailedException"],
                                     "Next": "Superseded"}]),
}


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
                            "MarkResolved", "MarkProtected"}
    for name, state in updates.items():
        args = state["Arguments"]
        assert args["TableName"] == PARTS["findings_table"], name
        assert args["ConditionExpression"] == CONDITION, name
        assert state["Catch"] == [{"ErrorEquals": ["DynamoDB.ConditionalCheckFailedException"],
                                   "Next": "Superseded"}], name
    assert sm["States"]["Superseded"]["Type"] == "Succeed"


def test_no_failure_catch_yet(sm):
    # Task #19 adds the Handle-failure branch; until then only the superseded Catch exists.
    for name, state in sm["States"].items():
        for catch in state.get("Catch", []):
            assert catch["Next"] == "Superseded", name


def test_lambda_tasks(sm):
    tasks = {n: s for n, s in sm["States"].items() if s.get("Resource") == "arn:aws:states:::lambda:invoke"}
    for name, state in tasks.items():
        assert state["TimeoutSeconds"] >= 60, name  # at least the Lambda's own timeout (design §17)
        assert state["Retry"], name
    notify = {n for n, s in tasks.items() if s["Arguments"]["FunctionName"] == PARTS["notify_arn"]}
    assert notify == {"FirstNotice", "FinalWarning", "StopConfirmation"}
    templates = {n: tasks[n]["Arguments"]["Payload"]["template"] for n in notify}
    assert templates == {"FirstNotice": "FIRST_NOTICE", "FinalWarning": "FINAL_WARNING",
                         "StopConfirmation": "STOP_CONFIRMATION"}


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
