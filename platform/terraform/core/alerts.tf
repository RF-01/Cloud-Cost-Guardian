# Team alerts (design §10.5): SNS topic for AWS Budgets and CloudWatch alarms, emailed to the team address.
# Plus the Lambda dead-letter queue and its alarm (design §6.1, §17).

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "team_alerts" {
  name = "${var.name_prefix}team-alerts"
}

data "aws_iam_policy_document" "team_alerts" {
  # Keep the account's own access (a topic policy replaces the default one).
  statement {
    sid = "AccountOwner"
    actions = [
      "sns:GetTopicAttributes",
      "sns:SetTopicAttributes",
      "sns:AddPermission",
      "sns:RemovePermission",
      "sns:DeleteTopic",
      "sns:Subscribe",
      "sns:ListSubscriptionsByTopic",
      "sns:Publish",
    ]
    resources = [aws_sns_topic.team_alerts.arn]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  # AWS Budgets alerts (design §11.2) and CloudWatch alarms, from this account only.
  statement {
    sid       = "BudgetsAndAlarmsPublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.team_alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["budgets.amazonaws.com", "cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "team_alerts" {
  arn    = aws_sns_topic.team_alerts.arn
  policy = data.aws_iam_policy_document.team_alerts.json
}

# AWS sends one confirmation email on apply; the subscription stays pending until it is clicked.
resource "aws_sns_topic_subscription" "team_email" {
  topic_arn = aws_sns_topic.team_alerts.arn
  protocol  = "email"
  endpoint  = var.team_email
}

resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name_prefix}dlq"
  sqs_managed_sse_enabled   = true
  message_retention_seconds = 1209600 # 14 days (the maximum)
}

resource "aws_cloudwatch_metric_alarm" "dlq_not_empty" {
  alarm_name          = "${var.name_prefix}dlq-not-empty"
  alarm_description   = "A Guardian Lambda failed an asynchronous invocation after its retries (message in ${aws_sqs_queue.dlq.name})."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.dlq.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.team_alerts.arn]
}
