# EventBridge Scheduler jobs (CONTRACT §4.7, design §6.1, §13.5). All times UTC.
# Scheduler invokes Lambda asynchronously: its retry_policy only covers failed deliveries (the Invoke call);
# a function error is retried by Lambda's own async retries (see the scanner's event invoke config below).

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  all_schedules = {
    scan = {
      arn         = var.scanner_function_arn
      cron        = "cron(7 */3 * * ? *)" # every 3 h at :07
      retries     = 0                     # a missed scan is not retried: the next one comes in 3 h
      description = "Scanner: every 3 hours"
    }
    daily-cost = {
      arn         = var.daily_cost_function_arn
      cron        = "cron(20 5 * * ? *)"
      retries     = 2
      description = "Daily cost (Cost Explorer -> bill-history): 05:20 UTC"
    }
    daily-summary = {
      arn         = var.daily_summary_function_arn
      cron        = "cron(40 23 * * ? *)" # late in the UTC day, after that day's activity
      retries     = 2
      description = "Daily summary: 23:40 UTC"
    }
    digest = {
      arn         = var.digest_function_arn
      cron        = "cron(30 6 ? * MON *)"
      retries     = 2
      description = "Weekly digest: Monday 06:30 UTC"
    }
  }

  # The key set must be known at plan time (for_each): it depends only on the digest_enabled bool, never on
  # the function ARNs, which are unknown on a fresh stack.
  schedules = { for k, s in local.all_schedules : k => s if k != "digest" || var.digest_enabled }
}

resource "aws_scheduler_schedule_group" "this" {
  name = "${var.name_prefix}schedules"
}

data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "${var.name_prefix}scheduler-role"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
}

# Least privilege: invoke exactly the target functions; failed deliveries go to the DLQ (Scheduler sends
# them with this role).
data "aws_iam_policy_document" "scheduler" {
  statement {
    sid       = "InvokeTargets"
    actions   = ["lambda:InvokeFunction"]
    resources = sort(distinct([for s in local.schedules : s.arn]))
  }

  statement {
    sid       = "DeadLetterQueue"
    actions   = ["sqs:SendMessage"]
    resources = [var.dlq_arn]
  }
}

resource "aws_iam_role_policy" "scheduler" {
  name   = "scheduler"
  role   = aws_iam_role.scheduler.id
  policy = data.aws_iam_policy_document.scheduler.json
}

resource "aws_scheduler_schedule" "this" {
  for_each = local.schedules

  name        = "${var.name_prefix}${each.key}"
  group_name  = aws_scheduler_schedule_group.this.name
  description = each.value.description

  schedule_expression          = each.value.cron
  schedule_expression_timezone = "UTC"
  state                        = var.schedules_enabled ? "ENABLED" : "DISABLED"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = each.value.arn
    role_arn = aws_iam_role.scheduler.arn
    input    = jsonencode({ source = "schedule", job = each.key }) # CONTRACT §4.7

    retry_policy {
      maximum_retry_attempts = each.value.retries
    }

    dead_letter_config {
      arn = var.dlq_arn
    }
  }

  depends_on = [aws_iam_role_policy.scheduler]
}

# A failed or timed-out scan is not retried by Lambda either: the next one comes in 3 h, and no scan can run
# twice by accident. daily-cost / daily-summary keep Lambda's default 2 retries + their DLQ (they overwrite rows).
resource "aws_lambda_function_event_invoke_config" "scanner" {
  function_name          = var.scanner_function_name
  maximum_retry_attempts = 0
}

# A failed scan has no retry and no DLQ, so the team hears about it here.
resource "aws_cloudwatch_metric_alarm" "scanner_errors" {
  alarm_name          = "${var.name_prefix}scanner-errors"
  alarm_description   = "The scanner Lambda (${var.scanner_function_name}) failed or timed out; it is not retried, the next scan runs in up to 3 h."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = var.scanner_function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.team_topic_arn]
}
