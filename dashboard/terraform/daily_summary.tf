# Daily summary Lambda (task #28, CONTRACT §3.5, §3.6, §4.7): findings + audit -> <prefix>daily-summaries.
# The EventBridge schedule that invokes it (late in the UTC day) is lane C's (#37).

locals {
  daily_summary_src  = "${local.repo_root}/dashboard/src/daily_summary"
  daily_summary_name = "${var.name_prefix}daily-summary"
}

# Zip layout: handler.py (handler handler.handler) + common/*.py.
data "archive_file" "daily_summary" {
  type        = "zip"
  output_path = "${path.module}/build/daily-summary.zip" # build/ is ignored by .gitignore

  dynamic "source" {
    for_each = fileset(local.daily_summary_src, "**/*.py")
    content {
      content  = file("${local.daily_summary_src}/${source.value}")
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

resource "aws_cloudwatch_log_group" "daily_summary" {
  name              = "/aws/lambda/${local.daily_summary_name}"
  retention_in_days = 14
}

resource "aws_iam_role" "daily_summary" {
  name               = "${local.daily_summary_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json # daily_cost.tf
}

# Least privilege. Logs go to its own log group (Terraform creates it, so no logs:CreateLogGroup).
data "aws_iam_policy_document" "daily_summary" {
  statement {
    sid       = "OwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.daily_summary.arn}:*"]
  }

  # Snapshot of all findings (paginated Scan; the table is small). No GetItem / Query / writes.
  statement {
    sid       = "ScanFindings"
    actions   = ["dynamodb:Scan"]
    resources = [var.table_arns["findings"]]
  }

  # The day's audit entries via GSI byDay only (not the base table).
  statement {
    sid       = "QueryAuditByDay"
    actions   = ["dynamodb:Query"]
    resources = ["${var.table_arns["audit"]}/index/byDay"]
  }

  # One item per UTC day, overwritten by a re-run.
  statement {
    sid       = "WriteDailySummary"
    actions   = ["dynamodb:PutItem"]
    resources = [var.table_arns["daily_summaries"]]
  }

  # Failed async invocations go to the DLQ (design §6.1). AWS checks this permission when the DLQ is set,
  # so it lives in this policy, which the function depends_on.
  statement {
    sid       = "DeadLetterQueue"
    actions   = ["sqs:SendMessage"]
    resources = [var.dlq_arn]
  }
}

resource "aws_iam_role_policy" "daily_summary" {
  name   = "daily-summary"
  role   = aws_iam_role.daily_summary.id
  policy = data.aws_iam_policy_document.daily_summary.json
}

resource "aws_lambda_function" "daily_summary" {
  function_name    = local.daily_summary_name
  role             = aws_iam_role.daily_summary.arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.daily_summary.output_path
  source_code_hash = data.archive_file.daily_summary.output_base64sha256
  timeout          = 60 # design §17
  memory_size      = 128

  dead_letter_config {
    target_arn = var.dlq_arn
  }

  environment {
    variables = {
      NAME_PREFIX           = var.name_prefix
      TABLE_FINDINGS        = var.table_names["findings"]
      TABLE_AUDIT           = var.table_names["audit"]
      TABLE_DAILY_SUMMARIES = var.table_names["daily_summaries"]
    }
  }

  depends_on = [aws_cloudwatch_log_group.daily_summary, aws_iam_role_policy.daily_summary]
}
