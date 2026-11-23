# Daily cost Lambda (task #27, CONTRACT §3.5, §4.7): Cost Explorer -> <prefix>bill-history.
# The EventBridge schedule that invokes it is lane C's (platform).

locals {
  repo_root       = "${path.module}/../.."
  daily_cost_src  = "${local.repo_root}/dashboard/src/daily_cost"
  common_src      = "${local.repo_root}/common"
  daily_cost_name = "${var.name_prefix}daily-cost"
}

# Zip layout: handler.py (handler handler.handler) + common/*.py.
data "archive_file" "daily_cost" {
  type        = "zip"
  output_path = "${path.module}/build/daily-cost.zip" # build/ is ignored by .gitignore

  dynamic "source" {
    for_each = fileset(local.daily_cost_src, "**/*.py")
    content {
      content  = file("${local.daily_cost_src}/${source.value}")
      filename = source.value
    }
  }

  dynamic "source" {
    for_each = fileset(local.common_src, "**/*.py")
    content {
      content  = file("${local.common_src}/${source.value}")
      filename = "common/${source.value}"
    }
  }
}

resource "aws_cloudwatch_log_group" "daily_cost" {
  name              = "/aws/lambda/${local.daily_cost_name}"
  retention_in_days = 14
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "daily_cost" {
  name               = "${local.daily_cost_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# Least privilege. Logs go to its own log group (Terraform creates it, so no logs:CreateLogGroup).
data "aws_iam_policy_document" "daily_cost" {
  statement {
    sid       = "OwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.daily_cost.arn}:*"]
  }

  # Cost Explorer has no resource-level permissions, so the resource must be "*".
  # Read-only, and only this one call (no GetCostForecast: Budgets covers forecasts).
  statement {
    sid       = "CostExplorerRead"
    actions   = ["ce:GetCostAndUsage"]
    resources = ["*"]
  }

  # Overwrites day+key rows (PutItem / BatchWriteItem only; no reads, updates or deletes).
  statement {
    sid       = "WriteBillHistory"
    actions   = ["dynamodb:PutItem", "dynamodb:BatchWriteItem"]
    resources = [var.table_arns["bill_history"]]
  }

  # Failed async invocations go to the DLQ (design §6.1). AWS checks this permission when the DLQ is set,
  # so it lives in this policy, which the function depends_on.
  statement {
    sid       = "DeadLetterQueue"
    actions   = ["sqs:SendMessage"]
    resources = [var.dlq_arn]
  }
}

resource "aws_iam_role_policy" "daily_cost" {
  name   = "daily-cost"
  role   = aws_iam_role.daily_cost.id
  policy = data.aws_iam_policy_document.daily_cost.json
}

resource "aws_lambda_function" "daily_cost" {
  function_name    = local.daily_cost_name
  role             = aws_iam_role.daily_cost.arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.daily_cost.output_path
  source_code_hash = data.archive_file.daily_cost.output_base64sha256
  timeout          = 60 # design §17
  memory_size      = 128

  dead_letter_config {
    target_arn = var.dlq_arn
  }

  environment {
    variables = {
      NAME_PREFIX        = var.name_prefix
      TABLE_BILL_HISTORY = var.table_names["bill_history"]
    }
  }

  depends_on = [aws_cloudwatch_log_group.daily_cost, aws_iam_role_policy.daily_cost]
}
