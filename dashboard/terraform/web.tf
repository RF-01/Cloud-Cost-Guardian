# Dashboard web app on EC2 (task #38, design §6.3, §6.4, §16): artifact bucket, origin secret in SSM,
# instance role, security group and the instance. CloudFront in front of it is platform edge's.
#
# New code = new instance: the zip's S3 key contains its MD5 and is written into user_data, and
# user_data_replace_on_change replaces the instance. The public DNS name changes with it, and the same
# apply updates CloudFront's origin (platform edge takes dashboard_public_dns).

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  dashboard_name   = "${var.name_prefix}dashboard"
  account_id       = data.aws_caller_identity.current.account_id
  region           = data.aws_region.current.region
  artifact_bucket  = "${var.name_prefix}dashboard-artifacts-${local.account_id}"
  web_src          = "${local.repo_root}/dashboard/web"
  web_artifact_key = "dashboard-web/${data.archive_file.web.output_md5}.zip"
  origin_param     = "/${var.name_prefix}dashboard/origin-secret"
  # Built from known parts (not resource attributes), so the plan shows the full role policy.
  origin_param_arn = "arn:aws:ssm:${local.region}:${local.account_id}:parameter${local.origin_param}"

  # dashboard/web/** minus bytecode. Zip layout dashboard/web/..., so `python -m dashboard.web` runs from the root.
  web_files = [
    for f in fileset(local.web_src, "**") : f
    if !strcontains(f, "__pycache__") && !endswith(f, ".pyc")
  ]
}

# ---------------------------------------------------------------- artifact bucket

data "archive_file" "web" {
  type        = "zip"
  output_path = "${path.module}/build/dashboard-web.zip" # build/ is ignored by .gitignore

  dynamic "source" {
    for_each = local.web_files
    content {
      content  = file("${local.web_src}/${source.value}")
      filename = "dashboard/web/${source.value}"
    }
  }
}

resource "aws_s3_bucket" "artifacts" {
  bucket        = local.artifact_bucket
  force_destroy = true # only build artifacts; every one can be rebuilt from Git
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # SSE-S3
    }
  }
}

data "aws_iam_policy_document" "artifacts_bucket" {
  statement {
    sid       = "DenyNonTLS"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.artifacts.arn, "${aws_s3_bucket.artifacts.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  policy = data.aws_iam_policy_document.artifacts_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.artifacts]
}

resource "aws_s3_object" "web" {
  bucket = aws_s3_bucket.artifacts.id
  key    = local.web_artifact_key
  source = data.archive_file.web.output_path
  etag   = data.archive_file.web.output_md5
}

# ---------------------------------------------------------------- origin secret

# SecureString with the AWS managed key aws/ssm. Its key policy lets every principal in the account decrypt
# through SSM in this region, so the instance role needs ssm:GetParameter only (no kms:Decrypt statement).
resource "aws_ssm_parameter" "origin_secret" {
  name        = local.origin_param
  description = "X-Origin-Verify value CloudFront sends to the dashboard (design §6.4)"
  type        = "SecureString"
  value       = var.origin_secret
}

# ---------------------------------------------------------------- instance role

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "dashboard" {
  name               = "${local.dashboard_name}-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

# Exactly the allowlist in dashboard/web/README.md (enforced at runtime by store.ReadOnlyDynamo), plus the
# artifact download and the origin secret. No writes. Bedrock and the counters table come with #43.
data "aws_iam_policy_document" "dashboard" {
  statement {
    sid       = "ScanFindings"
    actions   = ["dynamodb:Scan"]
    resources = [var.table_arns["findings"]]
  }

  statement {
    sid       = "QueryAuditByDay"
    actions   = ["dynamodb:Query"]
    resources = ["${var.table_arns["audit"]}/index/byDay"]
  }

  statement {
    sid       = "BatchGetDailySummaries"
    actions   = ["dynamodb:BatchGetItem"]
    resources = [var.table_arns["daily_summaries"]]
  }

  statement {
    sid       = "QueryBillHistory"
    actions   = ["dynamodb:Query"]
    resources = [var.table_arns["bill_history"]]
  }

  statement {
    sid       = "ScanBudgetAlerts"
    actions   = ["dynamodb:Scan"]
    resources = [var.table_arns["budget_alerts"]]
  }

  statement {
    sid       = "GetDashboardArtifact"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${local.artifact_bucket}/dashboard-web/*"]
  }

  statement {
    sid       = "GetOriginSecret"
    actions   = ["ssm:GetParameter"]
    resources = [local.origin_param_arn]
  }
}

resource "aws_iam_role_policy" "dashboard" {
  name   = "dashboard"
  role   = aws_iam_role.dashboard.id
  policy = data.aws_iam_policy_document.dashboard.json
}

resource "aws_iam_instance_profile" "dashboard" {
  name = local.dashboard_name
  role = aws_iam_role.dashboard.name
}

# ---------------------------------------------------------------- security group

data "aws_ec2_managed_prefix_list" "cloudfront" {
  name = "com.amazonaws.global.cloudfront.origin-facing"
}

data "aws_ec2_managed_prefix_list" "instance_connect" {
  name = "com.amazonaws.${local.region}.ec2-instance-connect"
}

# The CloudFront prefix list counts as 55 rules against the 60 inbound default (design §6.4): keep rules few.
resource "aws_security_group" "dashboard" {
  name        = local.dashboard_name
  description = "Dashboard: HTTP only from CloudFront, SSH only from EC2 Instance Connect"
  vpc_id      = var.vpc_id

  tags = { Name = local.dashboard_name }
}

resource "aws_vpc_security_group_ingress_rule" "http_from_cloudfront" {
  security_group_id = aws_security_group.dashboard.id
  description       = "HTTP from CloudFront origin-facing servers"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  prefix_list_id    = data.aws_ec2_managed_prefix_list.cloudfront.id
}

resource "aws_vpc_security_group_ingress_rule" "ssh_from_instance_connect" {
  security_group_id = aws_security_group.dashboard.id
  description       = "SSH from EC2 Instance Connect"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  prefix_list_id    = data.aws_ec2_managed_prefix_list.instance_connect.id
}

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.dashboard.id
  description       = "AWS APIs (DynamoDB, S3, SSM) and package installs"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# ---------------------------------------------------------------- instance

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_instance" "dashboard" {
  ami                    = data.aws_ssm_parameter.al2023.insecure_value # a public AMI ID, not a secret
  instance_type          = "t3.micro"
  subnet_id              = var.public_subnet_id
  vpc_security_group_ids = [aws_security_group.dashboard.id]
  iam_instance_profile   = aws_iam_instance_profile.dashboard.name
  monitoring             = false

  credit_specification {
    cpu_credits = "standard"
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 8
    encrypted             = true
    delete_on_termination = true
  }

  # Launch guardrails check the volume's tags at create time; default_tags don't reach volume_tags.
  volume_tags = {
    Name       = "${local.dashboard_name}-root"
    owner      = var.owner_email
    project    = "cost-guardian"
    managed-by = "terraform"
  }

  user_data = templatefile("${path.module}/templates/dashboard_user_data.sh.tftpl", {
    region       = local.region
    bucket       = local.artifact_bucket
    artifact_key = aws_s3_object.web.key
    origin_param = aws_ssm_parameter.origin_secret.name
    # Not the secret: its SSM version number. A new origin_secret bumps it, so user_data changes and the
    # instance is replaced in the same apply (the service reads the value only at start).
    origin_secret_version = aws_ssm_parameter.origin_secret.version
    name_prefix           = var.name_prefix
    table_env             = { for k, v in var.table_names : "TABLE_${upper(k)}" => v }
    web_root              = "/opt/guardian-dashboard"
    origin_script         = "/usr/local/libexec/guardian-dashboard-origin-env"
  })
  user_data_replace_on_change = true

  # Protected by our own rule (design §6.3): reported as idle, never stopped. IAM denies the stop too.
  tags = {
    Name               = local.dashboard_name
    "guardian:protect" = "true"
  }

  lifecycle {
    ignore_changes = [ami] # a new AMI arrives only with a replacement (new code)
  }

  depends_on = [aws_iam_role_policy.dashboard] # the role can read S3 / SSM before user_data runs
}
