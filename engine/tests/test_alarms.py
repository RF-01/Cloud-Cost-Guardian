"""Workflow alarms (engine/terraform/alarms.tf, design §9.1, CONTRACT §8, task #32), read from the Terraform file."""

import re
from pathlib import Path

ALARMS_TF = Path(__file__).resolve().parents[1] / "terraform" / "alarms.tf"
TEXT = ALARMS_TF.read_text(encoding="utf-8")

EXPECTED = {
    "ec2-timeline-failed": ("ec2_timeline", "ExecutionsFailed"),
    "ec2-timeline-timed-out": ("ec2_timeline", "ExecutionsTimedOut"),
    "ebs-timeline-failed": ("ebs_timeline", "ExecutionsFailed"),
    "ebs-timeline-timed-out": ("ebs_timeline", "ExecutionsTimedOut"),
}


def _alarm_map():
    entries = re.findall(r'"([a-z0-9-]+)"\s*=\s*\{(.*?)\}', TEXT, re.S)
    out = {}
    for key, body in entries:
        arn = re.search(r"arn\s*=\s*aws_sfn_state_machine\.(\w+)\.arn", body)
        metric = re.search(r'metric\s*=\s*"(\w+)"', body)
        out[key] = (arn.group(1), metric.group(1))
    return out


def _resource():
    start = TEXT.index('resource "aws_cloudwatch_metric_alarm" "workflow" {')
    return TEXT[start:]


def test_four_alarms_one_per_machine_and_metric():
    assert _alarm_map() == EXPECTED


def test_alarm_settings():
    res = _resource()
    assert "for_each = local.workflow_alarms" in res
    assert 'alarm_name        = "${var.name_prefix}${each.key}"' in res
    for line in ('namespace           = "AWS/States"', "metric_name         = each.value.metric",
                 "dimensions          = { StateMachineArn = each.value.arn }", 'statistic           = "Sum"',
                 "period              = 300", "evaluation_periods  = 1", "threshold           = 1",
                 'comparison_operator = "GreaterThanOrEqualToThreshold"',
                 'treat_missing_data  = "notBreaching"'):
        assert line in res, line


def test_alarm_notifies_team_topic_only_on_alarm():
    res = _resource()
    assert re.search(r"alarm_actions\s*=\s*\[var\.team_topic_arn\]", res)
    assert "ok_actions" not in res and "insufficient_data_actions" not in res


def test_description_points_to_dashboard_and_audit():
    desc = re.search(r'alarm_description\s*=\s*"([^"]+)"', _resource()).group(1)
    assert "${each.value.timeline}" in desc
    assert "dashboard" in desc and "workflow_failed" in desc
