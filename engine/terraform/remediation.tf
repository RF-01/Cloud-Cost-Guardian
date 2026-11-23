# Remediation Lambda (CONTRACT §4.3): re-checks, stop, snapshot, delete. Called by the workflows only.

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  repo_root        = "${path.module}/../.."
  remediation_src  = "${local.repo_root}/engine/src/remediation"
  common_src       = "${local.repo_root}/common"
  remediation_name = "${var.name_prefix}remediation"
  account_id       = data.aws_caller_identity.current.account_id
  remediation_arn  = "arn:aws:lambda:${data.aws_region.current.region}:${local.account_id}:function:${local.remediation_name}"
}

# Zip layout: handler.py (handler handler.handler) + common/*.py.
data "archive_file" "remediation" {
  type        = "zip"
  output_path = "${path.module}/build/remediation.zip" # build/ is ignored by .gitignore

  dynamic "source" {
    for_each = fileset(local.remediation_src, "**/*.py")
    content {
      content  = file("${local.remediation_src}/${source.value}")
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

resource "aws_cloudwatch_log_group" "remediation" {
  name              = "/aws/lambda/${local.remediation_name}"
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

resource "aws_iam_role" "remediation" {
  name               = "${local.remediation_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# Least privilege (design §16.1, CLAUDE.md safety rules). Resources in every region: the scanner covers
# all enabled regions, so the workflows act there too. Never DeleteSnapshot or ReleaseAddress.
data "aws_iam_policy_document" "remediation" {
  statement {
    sid       = "OwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.remediation.arn}:*"]
  }

  # Describe* calls don't support resource-level permissions.
  statement {
    sid = "Ec2Describe"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeVolumes",
      "ec2:DescribeSnapshots",
      "ec2:DescribeAddresses",
    ]
    resources = ["*"]
  }

  # CHECK_EC2 uses GetMetricStatistics only (free API allowance). No resource-level permissions.
  statement {
    sid       = "Metrics"
    actions   = ["cloudwatch:GetMetricStatistics"]
    resources = ["*"]
  }

  statement {
    sid       = "StopInstances"
    actions   = ["ec2:StopInstances"]
    resources = ["arn:aws:ec2:*:${local.account_id}:instance/*"]
  }

  statement {
    sid       = "DeleteVolumes"
    actions   = ["ec2:DeleteVolume"]
    resources = ["arn:aws:ec2:*:${local.account_id}:volume/*"]
  }

  # IAM, not only code: never stop or delete anything tagged guardian:protect=true (any letter case,
  # like the code's check).
  statement {
    sid       = "DenyProtected"
    effect    = "Deny"
    actions   = ["ec2:StopInstances", "ec2:DeleteVolume"]
    resources = ["*"]
    condition {
      test     = "StringEqualsIgnoreCase"
      variable = "aws:ResourceTag/guardian:protect"
      values   = ["true"]
    }
  }

  # Audit entries only (common/audit.py, CONTRACT §3.3): instance_stopped, snapshot_created, volume_deleted.
  statement {
    sid       = "WriteAudit"
    actions   = ["dynamodb:PutItem"]
    resources = [var.table_arns["audit"]]
  }

  # CreateSnapshot is authorized on both the source volume and the new snapshot.
  statement {
    sid     = "CreateSnapshots"
    actions = ["ec2:CreateSnapshot"]
    resources = [
      "arn:aws:ec2:*:${local.account_id}:volume/*",
      "arn:aws:ec2:*::snapshot/*",
    ]
  }

  # Tags only on snapshots, and only as part of CreateSnapshot (tag-on-create).
  statement {
    sid       = "TagNewSnapshots"
    actions   = ["ec2:CreateTags"]
    resources = ["arn:aws:ec2:*::snapshot/*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["CreateSnapshot"]
    }
  }
}

resource "aws_iam_role_policy" "remediation" {
  name   = "remediation"
  role   = aws_iam_role.remediation.id
  policy = data.aws_iam_policy_document.remediation.json
}

resource "aws_lambda_function" "remediation" {
  function_name    = local.remediation_name
  role             = aws_iam_role.remediation.arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.remediation.output_path
  source_code_hash = data.archive_file.remediation.output_base64sha256
  timeout          = 60 # design §17
  memory_size      = 128

  environment {
    variables = {
      NAME_PREFIX              = var.name_prefix
      TABLE_FINDINGS           = var.table_names["findings"]
      TABLE_AUDIT              = var.table_names["audit"]
      DRY_RUN                  = tostring(var.dry_run)
      DEV_SCOPE                = var.dev_scope
      DETECTION_WINDOW_MINUTES = tostring(var.detection_window_minutes)
    }
  }

  depends_on = [aws_cloudwatch_log_group.remediation, aws_iam_role_policy.remediation]
}
