# Scanner Lambda (lane B, design §8). Invoked by the scan schedule (platform, task later) or by hand with
# {"source": "schedule", "job": "scan"} (CONTRACT §4.7).

locals {
  repo_root    = "${path.module}/../.."
  scanner_src  = "${local.repo_root}/scanner/src/scanner"
  common_src   = "${local.repo_root}/common"
  scanner_name = "${var.name_prefix}scanner"

  sfn_arns       = compact([var.ec2_sfn_arn, var.ebs_sfn_arn])
  execution_arns = [for arn in local.sfn_arns : "${replace(arn, ":stateMachine:", ":execution:")}:*"]

  # Workflow waits passed into the timeline input by common/timeline.py (CONTRACT §4.4).
  waits = {
    WAIT_BEFORE_FINAL_SECONDS_EC2  = tostring(var.timeline_waits.ec2_before_final)
    WAIT_BEFORE_ACTION_SECONDS_EC2 = tostring(var.timeline_waits.ec2_before_action)
    WAIT_BEFORE_FINAL_SECONDS_EBS  = tostring(var.timeline_waits.ebs_before_final)
    WAIT_BEFORE_ACTION_SECONDS_EBS = tostring(var.timeline_waits.ebs_before_action)
  }
}

# Zip layout: scanner/*.py (package, handler scanner.handler.handler) + common/*.py.
data "archive_file" "scanner" {
  type        = "zip"
  output_path = "${path.module}/build/scanner.zip" # build/ is ignored by .gitignore

  dynamic "source" {
    for_each = fileset(local.scanner_src, "**/*.py")
    content {
      content  = file("${local.scanner_src}/${source.value}")
      filename = "scanner/${source.value}"
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

resource "aws_cloudwatch_log_group" "scanner" {
  name              = "/aws/lambda/${local.scanner_name}"
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

resource "aws_iam_role" "scanner" {
  name               = "${local.scanner_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "scanner" {
  statement {
    sid       = "OwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.scanner.arn}:*"]
  }

  # Describe* calls don't support resource-level permissions.
  statement {
    sid = "Ec2Describe"
    actions = [
      "ec2:DescribeRegions",
      "ec2:DescribeInstances",
      "ec2:DescribeVolumes",
      "ec2:DescribeAddresses",
    ]
    resources = ["*"]
  }

  # GetMetricStatistics only (free API allowance); never GetMetricData. No resource-level permissions.
  statement {
    sid       = "Metrics"
    actions   = ["cloudwatch:GetMetricStatistics"]
    resources = ["*"]
  }

  statement {
    sid       = "FindingsTable"
    actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
    resources = [var.table_arns["findings"]]
  }

  # Audit entries only (common/audit.py, CONTRACT §3.3): finding_opened, and timeline_started / timeline_stopped
  # written by common/timeline.py.
  statement {
    sid       = "WriteAudit"
    actions   = ["dynamodb:PutItem"]
    resources = [var.table_arns["audit"]]
  }

  # common/timeline.py: only when the engine's state machines exist.
  dynamic "statement" {
    for_each = length(local.sfn_arns) > 0 ? [1] : []
    content {
      sid       = "StartTimelines"
      actions   = ["states:StartExecution"]
      resources = local.sfn_arns
    }
  }

  dynamic "statement" {
    for_each = length(local.sfn_arns) > 0 ? [1] : []
    content {
      sid       = "ManageTimelineExecutions"
      actions   = ["states:StopExecution", "states:DescribeExecution"]
      resources = local.execution_arns
    }
  }
}

resource "aws_iam_role_policy" "scanner" {
  name   = "scanner"
  role   = aws_iam_role.scanner.id
  policy = data.aws_iam_policy_document.scanner.json
}

resource "aws_lambda_function" "scanner" {
  function_name    = local.scanner_name
  role             = aws_iam_role.scanner.arn
  runtime          = "python3.12"
  handler          = "scanner.handler.handler"
  filename         = data.archive_file.scanner.output_path
  source_code_hash = data.archive_file.scanner.output_base64sha256
  timeout          = 300 # design §17
  memory_size      = 256

  environment {
    variables = merge(local.waits, {
      NAME_PREFIX                 = var.name_prefix
      TABLE_FINDINGS              = var.table_names["findings"]
      TABLE_AUDIT                 = var.table_names["audit"]
      DRY_RUN                     = tostring(var.dry_run)
      SCAN_REGIONS                = var.scan_regions
      DEV_SCOPE                   = var.dev_scope
      DETECTION_WINDOW_MINUTES    = tostring(var.detection_window_minutes)
      EIP_STOPPED_THRESHOLD_HOURS = tostring(var.eip_stopped_threshold_hours)
      EC2_SFN_ARN                 = var.ec2_sfn_arn
      EBS_SFN_ARN                 = var.ebs_sfn_arn
      NOTIFY_FUNCTION_NAME        = var.notify_function_name
    })
  }

  depends_on = [aws_cloudwatch_log_group.scanner, aws_iam_role_policy.scanner]
}
