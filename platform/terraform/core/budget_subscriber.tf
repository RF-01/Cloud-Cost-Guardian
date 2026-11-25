# Budget alert subscriber (CONTRACT §3.5, §4.9; design §6.1, §11.2, §16.1): subscribed to the team topic,
# stores each AWS Budgets alert in <prefix>budget-alerts. Alarm messages on the same topic are skipped.
# The team email subscription (alerts.tf) stays: people still get every alert by email.

locals {
  budget_subscriber_src  = "${local.repo_root}/platform/src/budget_subscriber"
  budget_subscriber_name = "${var.name_prefix}budget-subscriber"
}

data "archive_file" "budget_subscriber" {
  type        = "zip"
  output_path = "${path.module}/build/budget-subscriber.zip" # build/ is ignored by .gitignore

  dynamic "source" {
    for_each = fileset(local.budget_subscriber_src, "**/*.py")
    content {
      content  = file("${local.budget_subscriber_src}/${source.value}")
      filename = source.value
    }
  }

  dynamic "source" {
    for_each = local.notify_common
    content {
      content  = file("${local.common_src}/${source.value}")
      filename = "common/${source.value}"
    }
  }
}

resource "aws_cloudwatch_log_group" "budget_subscriber" {
  name              = "/aws/lambda/${local.budget_subscriber_name}"
  retention_in_days = 14
}

resource "aws_iam_role" "budget_subscriber" {
  name               = "${local.budget_subscriber_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# Least privilege: its own logs, one PutItem on budget-alerts, the DLQ. Nothing else.
data "aws_iam_policy_document" "budget_subscriber" {
  statement {
    sid       = "OwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.budget_subscriber.arn}:*"]
  }

  statement {
    sid       = "WriteBudgetAlerts"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.budget_alerts.arn]
  }

  # SNS invokes the function asynchronously: after Lambda's retries the event goes to the DLQ (alarmed).
  # AWS checks this permission when the DLQ is set, so it lives in this policy, which the function depends_on.
  statement {
    sid       = "DeadLetterQueue"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
  }
}

resource "aws_iam_role_policy" "budget_subscriber" {
  name   = "budget-subscriber"
  role   = aws_iam_role.budget_subscriber.id
  policy = data.aws_iam_policy_document.budget_subscriber.json
}

resource "aws_lambda_function" "budget_subscriber" {
  function_name    = local.budget_subscriber_name
  role             = aws_iam_role.budget_subscriber.arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.budget_subscriber.output_path
  source_code_hash = data.archive_file.budget_subscriber.output_base64sha256
  timeout          = 30 # design §17
  memory_size      = 128

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  environment {
    variables = {
      NAME_PREFIX         = var.name_prefix
      TABLE_BUDGET_ALERTS = aws_dynamodb_table.budget_alerts.name
    }
  }

  depends_on = [aws_cloudwatch_log_group.budget_subscriber, aws_iam_role_policy.budget_subscriber]
}

# SNS -> Lambda needs only this resource policy on the function; the topic policy is unchanged.
resource "aws_lambda_permission" "budget_subscriber_sns" {
  statement_id  = "AllowTeamTopic"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.budget_subscriber.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.team_alerts.arn
}

resource "aws_sns_topic_subscription" "budget_subscriber" {
  topic_arn = aws_sns_topic.team_alerts.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.budget_subscriber.arn

  depends_on = [aws_lambda_permission.budget_subscriber_sns]
}
