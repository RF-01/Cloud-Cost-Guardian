import importlib.util
import json
from pathlib import Path

HANDLER = Path(__file__).resolve().parents[1] / "src" / "notify" / "handler.py"


def load_handler():
    # Load by path: every Lambda's file is called handler.py, so a plain import would collide.
    spec = importlib.util.spec_from_file_location("platform_notify_handler", HANDLER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EVENT = {
    "template": "FIRST_NOTICE",
    "to": "owner@example.com",
    "findings": [
        {
            "resourceId": "i-0abc123",
            "findingType": "EC2_IDLE",
            "generation": 1,
            "actions": ["protect", "postpone"],
            "expiresAt": "2026-11-23T16:30:00Z",
        }
    ],
    "vars": {"resourceId": "i-0abc123"},
}


def test_returns_stub_result():
    assert load_handler().handler(EVENT, None) == {"sent": False, "stub": True}


def test_logs_event_as_one_json_line(capsys):
    load_handler().handler(EVENT, None)
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["action"] == "notify_stub"
    assert record["result"] == "skipped"
    assert record["event"] == EVENT


def test_never_calls_ses_or_any_aws_api():
    # The stub must not send email: no AWS SDK import, no SES call anywhere in the file.
    source = HANDLER.read_text(encoding="utf-8")
    assert "import boto3" not in source
    assert "botocore" not in source
    assert "send_email" not in source
    assert "boto3" not in vars(load_handler())
