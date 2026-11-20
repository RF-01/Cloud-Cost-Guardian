# Bootstrap: creates the S3 bucket that stores Terraform state for the whole project.
# Run once. Its own (tiny) state stays local in this folder.

terraform {
  required_version = ">= 1.10" # needed for S3 native state locking (use_lockfile)

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

variable "aws_profile" {
  description = "AWS CLI profile to run as (your IAM user, never root)"
  type        = string
  default     = "guardian"
}

variable "owner_email" {
  description = "Email of the person responsible (used for the owner tag)"
  type        = string
}

provider "aws" {
  region  = "us-west-2"
  profile = var.aws_profile

  default_tags {
    tags = {
      project    = "cost-guardian"
      owner      = var.owner_email
      managed-by = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}

# Bucket names are global, so the account ID makes it unique.
resource "aws_s3_bucket" "tfstate" {
  bucket = "cost-guardian-tfstate-${data.aws_caller_identity.current.account_id}"

  lifecycle {
    prevent_destroy = true # protects the team's state from an accidental destroy
  }
}

# Keeps old versions of the state, so a bad apply can be rolled back.
resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket                  = aws_s3_bucket.tfstate.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Safety net from day 1: emails you when spending (before credits) passes $5,
# or is forecast to. Free. The full Guardian adds per-project budgets later.
resource "aws_budgets_budget" "account" {
  name         = "cost-guardian-account-monthly"
  budget_type  = "COST"
  limit_amount = "5"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  # Count usage before credits; otherwise credits hide everything and it always shows $0.
  cost_types {
    include_credit = false
    include_refund = false
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.owner_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.owner_email]
  }
}

output "state_bucket" {
  value = aws_s3_bucket.tfstate.bucket
}
