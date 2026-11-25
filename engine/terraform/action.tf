# Action Lambda + the /action routes on platform core's HTTP API (design §10.4, CONTRACT §3.4 / §4.6, task #31).

locals {
  action_src  = "${local.repo_root}/engine/src/action"
  action_name = "${var.name_prefix}action"
  # Execution ARNs of both timelines (postpone stops the current one; timeline.py describes it first).
  timeline_execution_arns = [
    "arn:aws:states:${data.aws_region.current.region}:${local.account_id}:execution:${var.name_prefix}ec2-timeline:*",
    "arn:aws:states:${data.aws_region.current.region}:${local.account_id}:execution:${var.name_prefix}ebs-timeline:*",
  ]
}

# Zip layout: handler.py + action_pages.py (handler handler.handler) + common/*.py.
data "archive_file" "action" {
  type        = "zip"
  output_path = "${path.module}/build/action.zip" # build/ is ignored by .gitignore

  dynamic "source" {
    for_each = fileset(local.action_src, "**/*.py")
    content {
      content  = file("${local.action_src}/${source.value}")
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

resource "aws_cloudwatch_log_group" "action" {
  name              = "/aws/lambda/${local.action_name}"
  retention_in_days = 14
}

resource "aws_iam_role" "action" {
  name               = "${local.action_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# Least privilege (design §16.1). Only creates tags / volumes; never stops, deletes or releases anything.
data "aws_iam_policy_document" "action" {
  statement {
    sid       = "OwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.action.arn}:*"]
  }

  # Token lookup, claim (TransactWriteItems is authorized per item action) and give-back.
  statement {
    sid       = "Tokens"
    actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
    resources = [var.table_arns["tokens"]]
  }

  # GetItem / ConditionCheckItem: the checks and the claim; UpdateItem: common/timeline.py.
  # Links exist only for EC2_IDLE / EBS_UNATTACHED findings (CONTRACT §4.1), so only instance / volume keys.
  statement {
    sid       = "Findings"
    actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem", "dynamodb:ConditionCheckItem"]
    resources = [var.table_arns["findings"]]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["i-*", "vol-*"]
    }
    condition {
      test     = "Null"
      variable = "dynamodb:LeadingKeys"
      values   = ["false"]
    }
  }

  statement {
    sid       = "WriteAudit"
    actions   = ["dynamodb:PutItem"]
    resources = [var.table_arns["audit"]]
  }

  # Postpone (common/timeline.py start_timeline).
  statement {
    sid       = "StartTimelines"
    actions   = ["states:StartExecution"]
    resources = [aws_sfn_state_machine.ec2_timeline.arn, aws_sfn_state_machine.ebs_timeline.arn]
  }

  # Protect / postpone stop the current execution (timeline.py describes it first).
  statement {
    sid       = "StopTimelines"
    actions   = ["states:StopExecution", "states:DescribeExecution"]
    resources = local.timeline_execution_arns
  }

  # RESTORE_DONE email.
  statement {
    sid       = "InvokeNotify"
    actions   = ["lambda:InvokeFunction"]
    resources = [var.notify_function_arn]
  }

  # Describe* calls don't support resource-level permissions.
  statement {
    sid       = "Ec2Describe"
    actions   = ["ec2:DescribeInstances", "ec2:DescribeVolumes", "ec2:DescribeSnapshots"]
    resources = ["*"]
  }

  # Protect: the guardian:protect tag and nothing else.
  statement {
    sid     = "ProtectTagOnly"
    actions = ["ec2:CreateTags"]
    resources = [
      "arn:aws:ec2:*:${local.account_id}:instance/*",
      "arn:aws:ec2:*:${local.account_id}:volume/*",
    ]
    condition {
      test     = "ForAllValues:StringEquals"
      variable = "aws:TagKeys"
      values   = ["guardian:protect"]
    }
    # ... and only to the value true.
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/guardian:protect"
      values   = ["true"]
    }
    # In a personal stack only on resources tagged guardian:dev-scope = DEV_SCOPE (CONTRACT §6).
    dynamic "condition" {
      for_each = var.dev_scope != "" ? [var.dev_scope] : []
      content {
        test     = "StringEquals"
        variable = "ec2:ResourceTag/guardian:dev-scope"
        values   = [condition.value]
      }
    }
  }

  # Restore: only from snapshots the Guardian made (tagged guardian:source-volume) ...
  statement {
    sid       = "RestoreFromGuardianSnapshots"
    actions   = ["ec2:CreateVolume"]
    resources = ["arn:aws:ec2:*::snapshot/*"]
    condition {
      test     = "Null"
      variable = "aws:ResourceTag/guardian:source-volume"
      values   = ["false"]
    }
    # Guardian snapshots carry the volume's dev-scope tag (remediation copies the volume's tags).
    dynamic "condition" {
      for_each = var.dev_scope != "" ? [var.dev_scope] : []
      content {
        test     = "StringEquals"
        variable = "ec2:ResourceTag/guardian:dev-scope"
        values   = [condition.value]
      }
    }
  }

  # ... and only volumes tagged guardian:restored-from at creation.
  statement {
    sid       = "RestoredVolumes"
    actions   = ["ec2:CreateVolume"]
    resources = ["arn:aws:ec2:*:${local.account_id}:volume/*"]
    condition {
      test     = "Null"
      variable = "aws:RequestTag/guardian:restored-from"
      values   = ["false"]
    }
    # _restore_tags copies the snapshot's tags, dev-scope included.
    dynamic "condition" {
      for_each = var.dev_scope != "" ? [var.dev_scope] : []
      content {
        test     = "StringEquals"
        variable = "aws:RequestTag/guardian:dev-scope"
        values   = [condition.value]
      }
    }
  }

  # Tags on the new volume, only as part of CreateVolume (tag-on-create).
  statement {
    sid       = "TagRestoredVolumes"
    actions   = ["ec2:CreateTags"]
    resources = ["arn:aws:ec2:*:${local.account_id}:volume/*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["CreateVolume"]
    }
    dynamic "condition" {
      for_each = var.dev_scope != "" ? [var.dev_scope] : []
      content {
        test     = "StringEquals"
        variable = "aws:RequestTag/guardian:dev-scope"
        values   = [condition.value]
      }
    }
  }
}

resource "aws_iam_role_policy" "action" {
  name   = "action"
  role   = aws_iam_role.action.id
  policy = data.aws_iam_policy_document.action.json
}

resource "aws_lambda_function" "action" {
  function_name    = local.action_name
  role             = aws_iam_role.action.arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.action.output_path
  source_code_hash = data.archive_file.action.output_base64sha256
  timeout          = 29 # design §17 (API Gateway's integration limit)
  memory_size      = 256

  environment {
    variables = {
      NAME_PREFIX                    = var.name_prefix
      TABLE_FINDINGS                 = var.table_names["findings"]
      TABLE_AUDIT                    = var.table_names["audit"]
      TABLE_TOKENS                   = var.table_names["tokens"]
      DEV_SCOPE                      = var.dev_scope
      DRY_RUN                        = tostring(var.dry_run) # timeline.py puts it in the postponed workflow's input
      EC2_SFN_ARN                    = aws_sfn_state_machine.ec2_timeline.arn
      EBS_SFN_ARN                    = aws_sfn_state_machine.ebs_timeline.arn
      WAIT_BEFORE_FINAL_SECONDS_EC2  = tostring(var.timeline_waits.ec2_before_final)
      WAIT_BEFORE_ACTION_SECONDS_EC2 = tostring(var.timeline_waits.ec2_before_action)
      WAIT_BEFORE_FINAL_SECONDS_EBS  = tostring(var.timeline_waits.ebs_before_final)
      WAIT_BEFORE_ACTION_SECONDS_EBS = tostring(var.timeline_waits.ebs_before_action)
      POSTPONE_SECONDS               = tostring(var.postpone_seconds)
      MAX_POSTPONES                  = "2"
      MAX_RESTARTS                   = "2"
      NOTIFY_FUNCTION_NAME           = var.notify_function_name
    }
  }

  depends_on = [aws_cloudwatch_log_group.action, aws_iam_role_policy.action]
}

# ---- Routes on platform core's HTTP API (CONTRACT §4.6, §8) ---------------------------------------------------

resource "aws_apigatewayv2_integration" "action" {
  api_id                 = var.action_api_id
  integration_type       = "AWS_PROXY"
  integration_method     = "POST"
  integration_uri        = aws_lambda_function.action.invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = 29000
}

resource "aws_apigatewayv2_route" "action_get" {
  api_id    = var.action_api_id
  route_key = "GET /action"
  target    = "integrations/${aws_apigatewayv2_integration.action.id}"
}

resource "aws_apigatewayv2_route" "action_post" {
  api_id    = var.action_api_id
  route_key = "POST /action"
  target    = "integrations/${aws_apigatewayv2_integration.action.id}"
}

resource "aws_lambda_permission" "action_api" {
  statement_id  = "AllowActionApi"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.action.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.action_api_execution_arn}/*/*/action"
}
