import json
import re
from decimal import Decimal

import boto3
import pytest
from moto import mock_aws

from common import timeline

REGION = "us-west-2"
TABLE = "cg-test-findings"
DEFINITION = json.dumps({"StartAt": "W", "States": {"W": {"Type": "Wait", "Seconds": 1, "End": True}}})
ROLE = "arn:aws:iam::123456789012:role/cg-test-sfn"
ARN_X = "arn:aws:states:us-west-2:123456789012:execution:x:"

STALE = {"failedStep": "Stop", "errorMessage": "AccessDenied", "deadlineAt": "2026-11-20T16:30:00Z",
         "remediatedAt": "2026-11-20T16:30:00Z", "resolvedAt": "2026-11-21T16:30:00Z", "dryRun": True,
         "realizedMonthlySavings": Decimal("8.47")}


@pytest.fixture
def aws(monkeypatch):
    for var in ("WAIT_BEFORE_FINAL_SECONDS_EC2", "WAIT_BEFORE_ACTION_SECONDS_EC2", "WAIT_BEFORE_FINAL_SECONDS_EBS",
                "WAIT_BEFORE_ACTION_SECONDS_EBS", "POSTPONE_SECONDS", "MAX_RESTARTS", "MAX_POSTPONES"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_REGION", REGION)
    monkeypatch.setenv("TABLE_FINDINGS", TABLE)
    monkeypatch.setenv("DRY_RUN", "true")
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name=REGION)
        table = ddb.create_table(
            TableName=TABLE,
            KeySchema=[{"AttributeName": "resourceId", "KeyType": "HASH"},
                       {"AttributeName": "findingType", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "resourceId", "AttributeType": "S"},
                                  {"AttributeName": "findingType", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        sfn = boto3.client("stepfunctions", region_name=REGION)
        ec2_arn = sfn.create_state_machine(name="cg-test-ec2-timeline", definition=DEFINITION,
                                           roleArn=ROLE)["stateMachineArn"]
        ebs_arn = sfn.create_state_machine(name="cg-test-ebs-timeline", definition=DEFINITION,
                                           roleArn=ROLE)["stateMachineArn"]
        monkeypatch.setenv("EC2_SFN_ARN", ec2_arn)
        monkeypatch.setenv("EBS_SFN_ARN", ebs_arn)
        timeline.reset_clients()
        yield {"table": table, "sfn": sfn, "ec2_arn": ec2_arn, "ebs_arn": ebs_arn}
        timeline.reset_clients()


def put(aws, **attrs):
    item = {
        "resourceId": "i-0abc123",
        "findingType": "EC2_IDLE",
        "resourceType": "ec2",
        "region": "us-east-1",
        "owner": "owner@example.com",
        "status": "open",
        "estimatedMonthlyCost": Decimal("8.47"),
    }
    item.update(attrs)
    aws["table"].put_item(Item=item)
    return item


def get(aws, rid="i-0abc123", ftype="EC2_IDLE"):
    return aws["table"].get_item(Key={"resourceId": rid, "findingType": ftype})["Item"]


def executions(aws, sm="ec2_arn"):
    return aws["sfn"].list_executions(stateMachineArn=aws[sm])["executions"]


def exec_input(aws, arn):
    return json.loads(aws["sfn"].describe_execution(executionArn=arn)["input"])


def log_lines(capsys):
    return [json.loads(line) for line in capsys.readouterr().out.strip().splitlines()]


def start(reason="new", rid="i-0abc123", ftype="EC2_IDLE"):
    return timeline.start_timeline(rid, ftype, reason)


def first_read_returns(monkeypatch, stale):
    """Make the next start_timeline see a stale read (an overlapping caller), then real reads after."""
    real_get = timeline._get_finding
    reads = []

    def fake(rid, ftype):
        reads.append(1)
        return stale if len(reads) == 1 else real_get(rid, ftype)

    monkeypatch.setattr(timeline, "_get_finding", fake)


# ---------------------------------------------------------------- start


def test_new_start(aws, capsys):
    put(aws)
    out = start()
    assert out["result"] == "started"
    result = out["finding"]

    assert result["generation"] == 1 and isinstance(result["generation"], Decimal)
    assert result["executionName"] == "ec2-i-0abc123-gen1"
    assert result["status"] == "in_progress"
    assert result["timelineStep"] == "first_notice"
    assert result["executionArn"].endswith(":ec2-i-0abc123-gen1")
    assert get(aws) == result

    [execution] = executions(aws)
    assert execution["status"] == "RUNNING"
    assert exec_input(aws, execution["executionArn"]) == {
        "resourceId": "i-0abc123",
        "findingType": "EC2_IDLE",
        "resourceType": "ec2",
        "region": "us-east-1",
        "owner": "owner@example.com",
        "generation": 1,
        "executionName": "ec2-i-0abc123-gen1",
        "dryRun": True,
        "estimatedMonthlyCost": 8.47,
        "waits": {"beforeFinalSeconds": 172800, "beforeActionSeconds": 86400},
    }
    [log] = log_lines(capsys)
    assert log["resourceId"] == "i-0abc123" and log["findingType"] == "EC2_IDLE"
    assert log["action"] == "start_timeline" and log["result"] == "started"


def test_ebs_waits_from_env_owner_null_and_dry_run_false(aws, monkeypatch):
    monkeypatch.setenv("WAIT_BEFORE_FINAL_SECONDS_EBS", "120")
    monkeypatch.setenv("WAIT_BEFORE_ACTION_SECONDS_EBS", "60")
    monkeypatch.setenv("DRY_RUN", "false")
    item = put(aws, resourceId="vol-0abc", findingType="EBS_UNATTACHED", resourceType="ebs")
    del item["owner"]
    aws["table"].put_item(Item=item)

    result = start(rid="vol-0abc", ftype="EBS_UNATTACHED")["finding"]
    assert result["executionName"] == "ebs-vol-0abc-gen1"
    data = exec_input(aws, result["executionArn"])
    assert data["owner"] is None
    assert data["dryRun"] is False
    assert data["waits"] == {"beforeFinalSeconds": 120, "beforeActionSeconds": 60}
    assert executions(aws, "ec2_arn") == []


def test_ebs_default_waits(aws):
    put(aws, resourceId="vol-0abc", findingType="EBS_UNATTACHED", resourceType="ebs")
    result = start(rid="vol-0abc", ftype="EBS_UNATTACHED")["finding"]
    assert exec_input(aws, result["executionArn"])["waits"] == {
        "beforeFinalSeconds": 950400, "beforeActionSeconds": 259200}


def test_concurrent_start_second_loses_conditional_write(aws, monkeypatch, capsys):
    put(aws)
    stale = get(aws)  # what a second, overlapping scan read before the first one wrote
    start()
    capsys.readouterr()

    first_read_returns(monkeypatch, stale)
    out = start()

    assert out["result"] == "lost_race"
    assert out["finding"]["generation"] == 1
    assert out["finding"]["executionName"] == "ec2-i-0abc123-gen1"
    assert len(executions(aws)) == 1
    assert log_lines(capsys)[-1]["result"] == "lost_race"


def test_second_call_while_running_does_nothing(aws, capsys):
    put(aws)
    first = start()["finding"]
    out = start()
    assert out == {"result": "already_running", "finding": first}
    assert len(executions(aws)) == 1
    assert log_lines(capsys)[-1]["result"] == "already_running"


def test_pending_start_retry_reuses_name(aws, capsys):
    # An earlier StartExecution failed after the generation was claimed: name stored, no ARN.
    put(aws, generation=Decimal(3), executionName="ec2-i-0abc123-gen3", status="in_progress",
        timelineStep="first_notice")
    out = start()
    assert out["result"] == "started"
    result = out["finding"]

    assert result["generation"] == 3
    assert result["executionName"] == "ec2-i-0abc123-gen3"
    assert result["executionArn"].endswith(":ec2-i-0abc123-gen3")
    [execution] = executions(aws)
    assert execution["name"] == "ec2-i-0abc123-gen3"
    assert log_lines(capsys)[-1]["pendingRetry"] is True


def test_start_failure_leaves_pending_then_retry_succeeds(aws, monkeypatch):
    put(aws)
    real_sfn = timeline._sfn()

    class Failing:
        def start_execution(self, **kwargs):
            from botocore.exceptions import ClientError
            raise ClientError({"Error": {"Code": "ServiceUnavailable", "Message": "boom"}}, "StartExecution")

    monkeypatch.setattr(timeline, "_sfn", lambda: Failing())
    with pytest.raises(Exception):
        start()
    pending = get(aws)
    assert pending["executionName"] == "ec2-i-0abc123-gen1" and "executionArn" not in pending

    monkeypatch.setattr(timeline, "_sfn", lambda: real_sfn)
    result = start()["finding"]
    assert result["generation"] == 1 and result["executionArn"].endswith(":ec2-i-0abc123-gen1")


def test_already_exists_running_same_generation_is_adopted(aws, capsys):
    # StartExecution succeeded earlier but the ARN was never saved.
    put(aws)
    existing = aws["sfn"].start_execution(
        stateMachineArn=aws["ec2_arn"], name="ec2-i-0abc123-gen1",
        input=json.dumps({"resourceId": "i-0abc123", "generation": 1}))["executionArn"]

    out = start()
    assert out["result"] == "adopted"
    assert out["finding"]["generation"] == 1
    assert out["finding"]["executionArn"] == existing
    assert len(executions(aws)) == 1
    assert log_lines(capsys)[-1]["result"] == "adopted"


def test_already_exists_old_execution_bumps_generation(aws):
    # Findings table was reset, but Step Functions still remembers gen1 (stopped) for 90 days.
    put(aws)
    old = aws["sfn"].start_execution(
        stateMachineArn=aws["ec2_arn"], name="ec2-i-0abc123-gen1",
        input=json.dumps({"resourceId": "i-0abc123", "generation": 1}))["executionArn"]
    aws["sfn"].stop_execution(executionArn=old)

    out = start()
    assert out["result"] == "started"
    assert out["finding"]["generation"] == 2
    assert out["finding"]["executionName"] == "ec2-i-0abc123-gen2"
    assert exec_input(aws, out["finding"]["executionArn"])["generation"] == 2


def test_already_exists_every_attempt_raises(aws):
    put(aws)
    for n in (1, 2, 3):
        arn = aws["sfn"].start_execution(stateMachineArn=aws["ec2_arn"], name=f"ec2-i-0abc123-gen{n}",
                                         input=json.dumps({"resourceId": "other"}))["executionArn"]
        aws["sfn"].stop_execution(executionArn=arn)
    with pytest.raises(RuntimeError):
        start()


def test_superseded_start_is_stopped(aws, monkeypatch):
    # The finding is resolved between StartExecution and saving the ARN: the new execution must not keep running.
    put(aws)
    real_store = timeline._store_arn

    def resolve_first(finding, arn):
        aws["table"].update_item(Key={"resourceId": "i-0abc123", "findingType": "EC2_IDLE"},
                                 UpdateExpression="SET #s = :r", ExpressionAttributeNames={"#s": "status"},
                                 ExpressionAttributeValues={":r": "resolved"})
        return real_store(finding, arn)

    monkeypatch.setattr(timeline, "_store_arn", resolve_first)
    out = start()
    assert out["result"] == "superseded"
    assert out["finding"]["status"] == "resolved"
    [execution] = executions(aws)
    assert execution["status"] == "ABORTED"


def test_restart_increments_restart_count(aws):
    put(aws, generation=Decimal(1), executionName="ec2-i-0abc123-gen1",
        executionArn=ARN_X + "ec2-i-0abc123-gen1", status="failed")
    out = start("restart")
    assert out["result"] == "started"
    assert out["finding"]["generation"] == 2
    assert out["finding"]["restartCount"] == 1
    assert out["finding"]["status"] == "in_progress"


def test_restart_limit(aws, monkeypatch):
    put(aws, generation=Decimal(3), executionName="ec2-i-0abc123-gen3",
        executionArn=ARN_X + "ec2-i-0abc123-gen3", status="failed", restartCount=Decimal(2))
    with pytest.raises(ValueError, match="restart limit"):
        start("restart")
    assert get(aws)["generation"] == 3
    assert executions(aws) == []

    monkeypatch.setenv("MAX_RESTARTS", "3")
    assert start("restart")["finding"]["restartCount"] == 3


def test_restart_limit_checked_in_conditional_write(aws, monkeypatch):
    # The read says restartCount 1, but another caller has already reached the limit: the write must refuse.
    put(aws, generation=Decimal(1), executionName="ec2-i-0abc123-gen1",
        executionArn=ARN_X + "ec2-i-0abc123-gen1", status="failed", restartCount=Decimal(2))
    first_read_returns(monkeypatch, dict(get(aws), restartCount=Decimal(1)))
    out = start("restart")
    assert out["result"] == "lost_race"
    assert out["finding"]["generation"] == 1
    assert executions(aws) == []


@pytest.mark.parametrize("reason,status", [
    ("new", "failed"), ("new", "resolved"), ("new", "remediated"),
    ("reopen", "resolved"), ("reopen", "failed"), ("reopen", "remediated"),
    ("restart", "open"), ("restart", "resolved"), ("restart", "remediated"),
    ("postpone", "open"), ("postpone", "failed"), ("postpone", "resolved"),
])
def test_wrong_status_refused(aws, reason, status):
    put(aws, status=status)
    with pytest.raises(ValueError, match="needs status"):
        start(reason)
    assert executions(aws) == []
    assert get(aws)["status"] == status


def test_status_checked_in_conditional_write(aws, monkeypatch):
    # The read says open, but the finding was resolved before the write: nothing starts.
    put(aws, status="resolved")
    first_read_returns(monkeypatch, dict(get(aws), status="open"))
    out = start()
    assert out["result"] == "lost_race"
    assert out["finding"]["status"] == "resolved"
    assert executions(aws) == []


def test_reopen_from_open(aws):
    put(aws, generation=Decimal(1), executionName="ec2-i-0abc123-gen1",
        executionArn=ARN_X + "ec2-i-0abc123-gen1", status="open")
    out = start("reopen")
    assert out["result"] == "started" and out["finding"]["generation"] == 2


def test_postpone_stops_old_execution_and_bumps_postpone_count(aws, monkeypatch):
    put(aws)
    first = start()["finding"]
    old_arn = first["executionArn"]

    out = start("postpone")
    assert out["result"] == "started"
    result = out["finding"]
    assert result["generation"] == 2
    assert result["postponeCount"] == 1
    assert result["status"] == "in_progress"
    assert aws["sfn"].describe_execution(executionArn=old_arn)["status"] == "ABORTED"
    assert exec_input(aws, result["executionArn"])["waits"] == {
        "beforeFinalSeconds": 604800, "beforeActionSeconds": 86400}

    monkeypatch.setenv("POSTPONE_SECONDS", "300")
    result = start("postpone")["finding"]
    assert result["postponeCount"] == 2
    assert exec_input(aws, result["executionArn"])["waits"]["beforeFinalSeconds"] == 300
    running = [e["name"] for e in executions(aws) if e["status"] == "RUNNING"]
    assert running == ["ec2-i-0abc123-gen3"]


def test_postpone_limit(aws, monkeypatch):
    put(aws)
    running = start()["finding"]
    aws["table"].update_item(Key={"resourceId": "i-0abc123", "findingType": "EC2_IDLE"},
                             UpdateExpression="SET postponeCount = :n", ExpressionAttributeValues={":n": Decimal(2)})
    with pytest.raises(ValueError, match="postpone limit"):
        start("postpone")
    # Nothing changed: the current timeline keeps running.
    assert aws["sfn"].describe_execution(executionArn=running["executionArn"])["status"] == "RUNNING"
    assert get(aws)["generation"] == 1

    monkeypatch.setenv("MAX_POSTPONES", "3")
    assert start("postpone")["finding"]["postponeCount"] == 3


def test_stale_fields_cleared_on_restart(aws):
    put(aws, generation=Decimal(1), executionName="ec2-i-0abc123-gen1",
        executionArn=ARN_X + "ec2-i-0abc123-gen1", status="failed", **STALE)
    result = start("restart")["finding"]
    for field in STALE:
        assert field not in result, field
    assert result["estimatedMonthlyCost"] == Decimal("8.47")  # scanner data is kept


def test_stale_fields_cleared_on_reopen(aws):
    put(aws, generation=Decimal(4), executionName="ec2-i-0abc123-gen4",
        executionArn=ARN_X + "ec2-i-0abc123-gen4", status="open", firstSeenAt="2026-11-22T10:00:00Z", **STALE)
    result = start("reopen")["finding"]
    for field in STALE:
        assert field not in result, field
    assert result["firstSeenAt"] == "2026-11-22T10:00:00Z"
    assert result["generation"] == 5


def test_report_only_refused(aws):
    put(aws, reportOnlyReason="protected")
    with pytest.raises(ValueError, match="report-only"):
        start()
    assert executions(aws) == []
    assert "generation" not in get(aws)


@pytest.mark.parametrize("ftype", ["EIP_UNASSOCIATED", "MISSING_TAGS", "SNAPSHOT_REMINDER"])
def test_no_timeline_type_refused(aws, ftype):
    put(aws, findingType=ftype)
    with pytest.raises(ValueError):
        start(ftype=ftype)


def test_unknown_reason_refused(aws):
    put(aws)
    with pytest.raises(ValueError):
        start("because")


def test_gen9_to_gen10_stays_numeric(aws):
    put(aws, generation=Decimal(9), executionName="ec2-i-0abc123-gen9", status="open",
        executionArn=ARN_X + "ec2-i-0abc123-gen9")
    result = start("reopen")["finding"]

    assert result["generation"] == Decimal(10)
    assert result["executionName"] == "ec2-i-0abc123-gen10"
    raw = boto3.client("dynamodb", region_name=REGION).get_item(
        TableName=TABLE, Key={"resourceId": {"S": "i-0abc123"}, "findingType": {"S": "EC2_IDLE"}})["Item"]
    assert raw["generation"] == {"N": "10"}
    assert exec_input(aws, result["executionArn"])["generation"] == 10


# ---------------------------------------------------------------- stop


def test_stop_running_execution_and_resolve(aws, capsys):
    put(aws)
    started = start()["finding"]
    capsys.readouterr()
    result = timeline.stop_timeline("i-0abc123", "EC2_IDLE", "resolved")

    assert aws["sfn"].describe_execution(executionArn=started["executionArn"])["status"] == "ABORTED"
    assert result["status"] == "resolved"
    assert result["timelineStep"] == "done"
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", result["resolvedAt"])
    assert result["generation"] == 1
    [log] = log_lines(capsys)
    assert log["action"] == "stop_timeline" and log["result"] == "stopped"


def test_stop_on_finished_execution(aws, capsys):
    put(aws)
    started = start()["finding"]
    aws["sfn"].stop_execution(executionArn=started["executionArn"])  # already finished
    capsys.readouterr()

    result = timeline.stop_timeline("i-0abc123", "EC2_IDLE", "open", report_only_reason="protected")
    assert result["status"] == "open"
    assert result["reportOnlyReason"] == "protected"
    assert "resolvedAt" not in result
    assert log_lines(capsys)[-1]["result"] == "already_finished"


def test_stop_on_missing_execution(aws, capsys):
    put(aws, generation=Decimal(1), executionName="ec2-i-0abc123-gen1", status="in_progress",
        executionArn=aws["ec2_arn"].replace(":stateMachine:", ":execution:") + ":ec2-i-0abc123-gen1")
    result = timeline.stop_timeline("i-0abc123", "EC2_IDLE", "resolved")
    assert result["status"] == "resolved"
    assert log_lines(capsys)[-1]["result"] == "not_found"


def test_stop_without_arn_stops_by_name(aws):
    # Started, but the ARN was never saved (crash): stop must still find it by name.
    put(aws, generation=Decimal(1), executionName="ec2-i-0abc123-gen1", status="in_progress")
    arn = aws["sfn"].start_execution(stateMachineArn=aws["ec2_arn"], name="ec2-i-0abc123-gen1",
                                     input="{}")["executionArn"]
    timeline.stop_timeline("i-0abc123", "EC2_IDLE", "resolved")
    assert aws["sfn"].describe_execution(executionArn=arn)["status"] == "ABORTED"


def test_stop_without_execution_name_sets_no_timeline_step(aws, capsys):
    put(aws, findingType="MISSING_TAGS")
    result = timeline.stop_timeline("i-0abc123", "MISSING_TAGS", "resolved")
    assert result["status"] == "resolved"
    assert "timelineStep" not in result
    assert log_lines(capsys)[-1]["result"] == "no_execution"

    put(aws)  # an EC2_IDLE finding that never had a timeline
    result = timeline.stop_timeline("i-0abc123", "EC2_IDLE", "resolved")
    assert "timelineStep" not in result


def test_stop_bad_values_refused(aws):
    put(aws)
    with pytest.raises(ValueError):
        timeline.stop_timeline("i-0abc123", "EC2_IDLE", "closed")
    with pytest.raises(ValueError):
        timeline.stop_timeline("i-0abc123", "EC2_IDLE", "open", report_only_reason="scheduled")
