"""common/audit.py: the §3.3 audit item, and audit writes never raise."""

import json
import re
from decimal import Decimal

import boto3
import pytest
from moto import mock_aws

from common import audit

REGION = "us-west-2"
AUDIT_TABLE = "cg-test-audit"
TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z#[0-9a-f]{8}$")


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_REGION", REGION)
    monkeypatch.setenv("TABLE_AUDIT", AUDIT_TABLE)
    with mock_aws():
        table = boto3.resource("dynamodb", region_name=REGION).create_table(
            TableName=AUDIT_TABLE,
            KeySchema=[{"AttributeName": "resourceId", "KeyType": "HASH"},
                       {"AttributeName": "ts", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "resourceId", "AttributeType": "S"},
                                  {"AttributeName": "ts", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        audit.reset_clients()
        yield table
        audit.reset_clients()


def raw_items():
    """Items with their DynamoDB types, to check N / BOOL / NULL."""
    return boto3.client("dynamodb", region_name=REGION).scan(TableName=AUDIT_TABLE)["Items"]


def log_lines(capsys):
    return [json.loads(line) for line in capsys.readouterr().out.strip().splitlines() if line.startswith("{")]


def test_item_shape(aws):
    assert audit.write_audit("i-0abc123", "remediation", "instance_stopped", finding_type="EC2_IDLE",
                             region="us-east-1", generation=Decimal("3"), dry_run=True,
                             details={"elasticIps": [], "snapshotId": None, "cost": 8.47})
    [raw] = raw_items()
    assert TS.match(raw["ts"]["S"])
    assert raw["day"] == {"S": raw["ts"]["S"][:10]}
    assert raw["generation"] == {"N": "3"}
    assert raw["dryRun"] == {"BOOL": True}
    assert raw["details"]["M"] == {"elasticIps": {"L": []}, "snapshotId": {"NULL": True},
                                   "cost": {"N": "8.47"}}
    item = {k: v for k, v in aws.scan()["Items"][0].items() if k not in ("ts", "day", "details")}
    assert item == {"resourceId": "i-0abc123", "actor": "remediation", "event": "instance_stopped",
                    "findingType": "EC2_IDLE", "region": "us-east-1", "generation": 3, "dryRun": True,
                    "result": "ok"}


def test_none_fields_left_out(aws):
    assert audit.write_audit("vol-1", "scanner", "finding_opened")
    [item] = aws.scan()["Items"]
    assert set(item) == {"resourceId", "ts", "day", "actor", "event", "result"}
    assert item["result"] == "ok"


def test_dry_run_false_is_stored(aws):
    audit.write_audit("i-1", "remediation", "instance_stopped", dry_run=False, generation=0)
    [raw] = raw_items()
    assert raw["dryRun"] == {"BOOL": False} and raw["generation"] == {"N": "0"}


def test_ts_unique_for_same_second(aws):
    for _ in range(5):
        audit.write_audit("i-1", "scanner", "finding_opened")
    assert len(aws.scan()["Items"]) == 5


def test_never_raises_when_table_missing(aws, monkeypatch, capsys):
    monkeypatch.setenv("TABLE_AUDIT", "cg-test-no-such-table")
    assert audit.write_audit("i-1", "scanner", "finding_opened", finding_type="EC2_IDLE") is False
    [line] = log_lines(capsys)
    assert line["action"] == "audit_write_failed" and line["result"] == "error"
    assert line["resourceId"] == "i-1" and line["event"] == "finding_opened" and line["actor"] == "scanner"
    assert "ResourceNotFoundException" in line["error"]


def test_never_raises_without_table_env(aws, monkeypatch, capsys):
    monkeypatch.delenv("TABLE_AUDIT")
    assert audit.write_audit("i-1", "scanner", "finding_opened") is False
    assert log_lines(capsys)[0]["action"] == "audit_write_failed"


def test_never_raises_on_bad_value(aws, capsys):
    assert audit.write_audit("i-1", "scanner", "finding_opened", details={"x": object()}) is False
    assert log_lines(capsys)[0]["action"] == "audit_write_failed"
