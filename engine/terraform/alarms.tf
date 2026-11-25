# Workflow alarms (design §9.1 "Alarms", CONTRACT §8, task #32): any failed or timed-out timeline execution
# notifies the team topic. The finding itself is already marked failed by the workflow's Catch (visible on the
# dashboard and as workflow_failed in the audit log); these alarms make sure someone looks at it.

locals {
  workflow_alarms = {
    "ec2-timeline-failed" = {
      timeline = "EC2"
      arn      = aws_sfn_state_machine.ec2_timeline.arn
      metric   = "ExecutionsFailed"
      what     = "failed"
    }
    "ec2-timeline-timed-out" = {
      timeline = "EC2"
      arn      = aws_sfn_state_machine.ec2_timeline.arn
      metric   = "ExecutionsTimedOut"
      what     = "timed out"
    }
    "ebs-timeline-failed" = {
      timeline = "EBS"
      arn      = aws_sfn_state_machine.ebs_timeline.arn
      metric   = "ExecutionsFailed"
      what     = "failed"
    }
    "ebs-timeline-timed-out" = {
      timeline = "EBS"
      arn      = aws_sfn_state_machine.ebs_timeline.arn
      metric   = "ExecutionsTimedOut"
      what     = "timed out"
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "workflow" {
  for_each = local.workflow_alarms

  alarm_name        = "${var.name_prefix}${each.key}"
  alarm_description = "A ${each.value.timeline} timeline execution ${each.value.what}. The finding is marked failed: see it on the dashboard and in the audit log (workflow_failed). The scanner restarts it while restartCount < MAX_RESTARTS (CONTRACT §3.2)."

  namespace           = "AWS/States"
  metric_name         = each.value.metric
  dimensions          = { StateMachineArn = each.value.arn }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [var.team_topic_arn]
}
