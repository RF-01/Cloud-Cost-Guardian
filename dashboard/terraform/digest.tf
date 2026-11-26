# Weekly digest Lambda (task #42, CONTRACT §4.10, §4.2 DIGEST, §4.7): findings + budget alerts -> Bedrock
# summary -> one Notify DIGEST email per recipient. The schedule (Monday 06:30 UTC) is lane C's schedules module.

locals {
  digest_src  = "${local.repo_root}/dashboard/src/digest"
  digest_name = "${var.name_prefix}digest"

  # The US geo inference profile (us.<model>) routes to the foundation model in these regions; InvokeModel is
  # authorized on the profile AND on the foundation model in the region that serves the request.
  bedrock_profile_regions = ["us-east-1", "us-east-2", "us-west-2"]
  bedrock_foundation_id   = trimprefix(var.bedrock_model_id, "us.")
}

# Zip layout: handler.py (handler handler.handler) + common/*.py.
data "archive_file" "digest" {
  type        = "zip"
  output_path = "${path.module}/build/digest.zip" # build/ is ignored by .gitignore

  dynamic "source" {
    for_each = fileset(local.digest_src, "**/*.py")
    content {
      content  = file("${local.digest_src}/${source.value}")
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

resource "aws_cloudwatch_log_group" "digest" {
  name              = "/aws/lambda/${local.digest_name}"
  retention_in_days = 14
}

resource "aws_iam_role" "digest" {
  name               = "${local.digest_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json # daily_cost.tf
}

# Least privilege. Logs go to its own log group (Terraform creates it, so no logs:CreateLogGroup).
data "aws_iam_policy_document" "digest" {
  statement {
    sid       = "OwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.digest.arn}:*"]
  }

  # Read-only: paginated Scan of findings and budget-alerts (small tables). No GetItem / Query / writes;
  # lastNotifiedAt is written by Notify.
  statement {
    sid       = "ScanFindingsAndBudgetAlerts"
    actions   = ["dynamodb:Scan"]
    resources = [var.table_arns["findings"], var.table_arns["budget_alerts"]]
  }

  # Sends every email through Notify (synchronous invoke), nothing else.
  statement {
    sid       = "InvokeNotify"
    actions   = ["lambda:InvokeFunction"]
    resources = [var.notify_function_arn]
  }

  # The configured inference profile only, plus the foundation model it routes to.
  statement {
    sid     = "InvokeConfiguredModel"
    actions = ["bedrock:InvokeModel"]
    resources = concat(
      ["arn:aws:bedrock:us-west-2:${local.account_id}:inference-profile/${var.bedrock_model_id}"],
      [for r in local.bedrock_profile_regions : "arn:aws:bedrock:${r}::foundation-model/${local.bedrock_foundation_id}"],
    )
  }

  # Failed async invocations go to the DLQ (design §6.1). AWS checks this permission when the DLQ is set,
  # so it lives in this policy, which the function depends_on.
  statement {
    sid       = "DeadLetterQueue"
    actions   = ["sqs:SendMessage"]
    resources = [var.dlq_arn]
  }
}

resource "aws_iam_role_policy" "digest" {
  name   = "digest"
  role   = aws_iam_role.digest.id
  policy = data.aws_iam_policy_document.digest.json
}

resource "aws_lambda_function" "digest" {
  function_name    = local.digest_name
  role             = aws_iam_role.digest.arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.digest.output_path
  source_code_hash = data.archive_file.digest.output_base64sha256
  timeout          = 180 # design §17 (3 min); the handler stops starting recipients below 120 s left
  memory_size      = 128

  dead_letter_config {
    target_arn = var.dlq_arn
  }

  environment {
    variables = {
      NAME_PREFIX                  = var.name_prefix
      TABLE_FINDINGS               = var.table_names["findings"]
      TABLE_BUDGET_ALERTS          = var.table_names["budget_alerts"]
      NOTIFY_FUNCTION_NAME         = var.notify_function_name
      TEAM_EMAIL                   = var.team_email
      BEDROCK_MODEL_ID             = var.bedrock_model_id
      BEDROCK_MAX_TOKENS           = tostring(var.bedrock_max_tokens)
      DRY_RUN                      = tostring(var.dry_run) # display only ("Dry run" note in the email)
      DIGEST_MIN_DAYS_SINCE_NOTICE = "6"
      DIGEST_MAX_EMAILS            = "20"
      DIGEST_MAX_ITEMS             = "50"
    }
  }

  depends_on = [aws_cloudwatch_log_group.digest, aws_iam_role_policy.digest]
}
