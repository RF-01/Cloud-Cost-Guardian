# Notify Lambda — STUB until task #24: logs the event and returns {"sent": false, "stub": true}.
# No SES or DynamoDB permissions yet (added with the real code in #24).

locals {
  repo_root     = "${path.module}/../../.."
  notify_src    = "${local.repo_root}/platform/src/notify"
  common_src    = "${local.repo_root}/common"
  notify_name   = "${var.name_prefix}notify"
  notify_common = fileset(local.common_src, "**/*.py") # empty until common/ exists (CLAUDE.md: every zip includes common/)
}

data "archive_file" "notify" {
  type        = "zip"
  output_path = "${path.module}/build/notify.zip" # build/ is ignored by .gitignore

  dynamic "source" {
    for_each = fileset(local.notify_src, "**/*.py")
    content {
      content  = file("${local.notify_src}/${source.value}")
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

resource "aws_cloudwatch_log_group" "notify" {
  name              = "/aws/lambda/${local.notify_name}"
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

resource "aws_iam_role" "notify" {
  name               = "${local.notify_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# Logs only, to its own log group (Terraform creates the group, so no logs:CreateLogGroup).
data "aws_iam_policy_document" "notify" {
  statement {
    sid       = "OwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.notify.arn}:*"]
  }
}

resource "aws_iam_role_policy" "notify" {
  name   = "notify"
  role   = aws_iam_role.notify.id
  policy = data.aws_iam_policy_document.notify.json
}

resource "aws_lambda_function" "notify" {
  function_name    = local.notify_name
  role             = aws_iam_role.notify.arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.notify.output_path
  source_code_hash = data.archive_file.notify.output_base64sha256
  timeout          = 60 # design §17
  memory_size      = 128

  environment {
    # CONTRACT §6; tables per Notify's needs in §4.1 (tokens, findings, audit).
    variables = {
      NAME_PREFIX    = var.name_prefix
      TABLE_FINDINGS = aws_dynamodb_table.findings.name
      TABLE_AUDIT    = aws_dynamodb_table.audit.name
      TABLE_TOKENS   = aws_dynamodb_table.tokens.name
      SENDER_EMAIL   = var.sender_email
      TEAM_EMAIL     = var.team_email
      ACTION_API_URL = local.action_api_url
      DRY_RUN        = tostring(var.dry_run)
    }
  }

  depends_on = [aws_cloudwatch_log_group.notify, aws_iam_role_policy.notify]
}
