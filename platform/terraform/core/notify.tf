# Notify Lambda (CONTRACT §4.1, §4.2, §3.4; design §10.4-10.5): renders the emails, creates the action-link
# tokens, sends with SES v2, falls back to the team address, writes lastNotifiedAt and audit entries.

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

# Least privilege (CONTRACT §4.1). Logs go to its own log group (Terraform creates it, so no logs:CreateLogGroup).
data "aws_iam_policy_document" "notify" {
  statement {
    sid       = "OwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.notify.arn}:*"]
  }

  # In the SES sandbox IAM also checks the recipient identities, so the resource is identity/*; the condition
  # pins the From address (a plain address, no display name, so it matches exactly). SES runs in us-west-2.
  statement {
    sid       = "SendFromSenderOnly"
    actions   = ["ses:SendEmail"]
    resources = ["arn:aws:ses:us-west-2:${data.aws_caller_identity.current.account_id}:identity/*"]
    condition {
      test     = "StringEquals"
      variable = "ses:FromAddress"
      values   = [var.sender_email]
    }
  }

  statement {
    sid       = "WriteTokens"
    actions   = ["dynamodb:BatchWriteItem", "dynamodb:PutItem"]
    resources = [aws_dynamodb_table.tokens.arn]
  }

  statement {
    sid       = "WriteAudit"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.audit.arn]
  }

  # Notify owns lastNotifiedAt and nothing else on findings (CONTRACT §3.1).
  statement {
    sid       = "SetLastNotifiedAt"
    actions   = ["dynamodb:UpdateItem"]
    resources = [aws_dynamodb_table.findings.arn]
    condition {
      test     = "ForAllValues:StringEquals"
      variable = "dynamodb:Attributes"
      values   = ["resourceId", "findingType", "lastNotifiedAt"]
    }
    condition {
      test     = "StringEqualsIfExists"
      variable = "dynamodb:ReturnValues"
      values   = ["NONE"]
    }
  }

  # Failed async invocations go to the DLQ (design §6.1). AWS checks this permission when the DLQ is set,
  # so it lives in this policy, which the function depends_on.
  statement {
    sid       = "DeadLetterQueue"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
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

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

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
