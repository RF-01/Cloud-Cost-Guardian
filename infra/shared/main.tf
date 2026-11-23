# infra/shared — account-wide resources (one copy for the whole AWS account).
# Owned by lane C. State: s3://cost-guardian-tfstate-<account id>/shared/terraform.tfstate
#
# First time:
#   terraform init -backend-config="bucket=cost-guardian-tfstate-<ACCOUNT_ID>" -backend-config="profile=guardian"

terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Partial config: the bucket name (it contains the account ID) is passed at init.
  backend "s3" {
    key          = "shared/terraform.tfstate"
    region       = "us-west-2"
    use_lockfile = true
    encrypt      = true
  }
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

# ---------------------------------------------------------------------------
# Team group: every team member is an admin in this sandbox account.
# The launch guardrails (design §8.7) are attached to this group below (task #25).
# ---------------------------------------------------------------------------
resource "aws_iam_group" "team" {
  name = "cost-guardian-team"
}

resource "aws_iam_group_policy_attachment" "team_admin" {
  group      = aws_iam_group.team.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ---------------------------------------------------------------------------
# One IAM user per team member, with the `email` tag the CloudTrail creator
# lookup relies on (design §8.6).
# ---------------------------------------------------------------------------
resource "aws_iam_user" "member" {
  for_each = var.team_members

  name = each.key
  tags = {
    email = each.value
  }

  lifecycle {
    prevent_destroy = true
  }
}

# The admin user was created by hand in the console (manual setup step 3).
# This brings it under Terraform instead of creating a second one.
# (An import address must be written literally, so the name is spelled out here.)
import {
  to = aws_iam_user.member["reda"]
  id = "reda"
}

resource "aws_iam_user_group_membership" "member" {
  for_each = var.team_members

  user   = aws_iam_user.member[each.key].name
  groups = [aws_iam_group.team.name]
}

# Console passwords for the new users only: reda's console access is managed by hand.
# AWS generates each password; it must be changed at first sign-in.
resource "aws_iam_user_login_profile" "member" {
  for_each = { for name, email in var.team_members : name => email if name != "reda" }

  user                    = aws_iam_user.member[each.key].name
  password_reset_required = true

  lifecycle {
    ignore_changes = [password_length, password_reset_required, pgp_key]
  }
}

resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = 12
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = false
  allow_users_to_change_password = true
}

# ---------------------------------------------------------------------------
# SES identities (sandbox): the sender / team address and every member's address.
# AWS emails each address a verification link that its owner must click
# (manual setup step 5).
# ---------------------------------------------------------------------------
resource "aws_sesv2_email_identity" "address" {
  for_each = toset(concat(values(var.team_members), [var.sender_email, var.team_email]))

  email_identity = each.value
}

# ---------------------------------------------------------------------------
# Launch guardrails (design §8.7, task #25): deny rules on the team group only.
# The Guardian's own Lambda roles are not affected.
#
# - Every Deny is scoped to the resources that carry the tags (instance, volume,
#   elastic-ip). RunInstances is also checked against the ENI, subnet, SG, AMI and
#   key pair, which carry no tags: "Resource": "*" would refuse every launch.
# - `owner` and `project` are checked in SEPARATE statements: two keys in one
#   `Null` block are ANDed, so the deny would only fire when both are missing.
# - No snapshot rule: the Guardian only tracks its own snapshots.
# - User `reda` also has AdministratorAccess attached directly (and via the group);
#   an explicit Deny wins over any Allow, so the guardrails still apply to him.
#   IAM never restricts the root user.
# Test with the --dry-run script (design §8.7, five cases).
# ---------------------------------------------------------------------------
locals {
  guardrail_tagged_resources = {
    RunInstances    = ["arn:aws:ec2:*:*:instance/*", "arn:aws:ec2:*:*:volume/*"]
    CreateVolume    = ["arn:aws:ec2:*:*:volume/*"]
    AllocateAddress = ["arn:aws:ec2:*:*:elastic-ip/*"]
  }

  # One statement per (action, required tag), e.g. DenyRunInstancesWithoutOwnerTag.
  guardrail_missing_tag_rules = flatten([
    for action, resources in local.guardrail_tagged_resources : [
      for tag in ["owner", "project"] : {
        sid       = "Deny${action}Without${title(tag)}Tag"
        action    = "ec2:${action}"
        tag       = tag
        resources = resources
      }
    ]
  ])
}

data "aws_iam_policy_document" "launch_guardrails" {
  dynamic "statement" {
    for_each = local.guardrail_missing_tag_rules

    content {
      sid       = statement.value.sid
      effect    = "Deny"
      actions   = [statement.value.action]
      resources = statement.value.resources

      condition {
        test     = "Null"
        variable = "aws:RequestTag/${statement.value.tag}"
        values   = ["true"]
      }
    }
  }

  statement {
    sid       = "DenyRunInstancesDisallowedType"
    effect    = "Deny"
    actions   = ["ec2:RunInstances"]
    resources = ["arn:aws:ec2:*:*:instance/*"]

    condition {
      test     = "StringNotEquals"
      variable = "ec2:InstanceType"
      values   = var.guardrail_allowed_instance_types
    }
  }

  statement {
    sid       = "DenyOwnerTagNotEmail"
    effect    = "Deny"
    actions   = ["ec2:RunInstances", "ec2:CreateVolume", "ec2:AllocateAddress"]
    resources = distinct(flatten(values(local.guardrail_tagged_resources)))

    condition {
      test     = "StringNotLike"
      variable = "aws:RequestTag/owner"
      values   = ["*@*"]
    }
  }
}

resource "aws_iam_policy" "launch_guardrails" {
  name        = "cost-guardian-launch-guardrails"
  description = "Team launch guardrails (design 8.7): owner/project tags at create time, allowed instance types"
  policy      = data.aws_iam_policy_document.launch_guardrails.json
}

resource "aws_iam_group_policy_attachment" "team_guardrails" {
  group      = aws_iam_group.team.name
  policy_arn = aws_iam_policy.launch_guardrails.arn
}

# ---------------------------------------------------------------------------
# Cost allocation tags (task #40): lets Cost Explorer group spend by `project`
# (the daily-cost Lambda, CONTRACT §3.5) and `owner`. Account-wide, so here and
# not in a stack. Both keys have been on resources since Nov 21, so they can be
# activated now (activation only works once a key has appeared in billing).
# Spend from before activation has no tag data unless a backfill is requested
# (manual setup step 7).
# ---------------------------------------------------------------------------
resource "aws_ce_cost_allocation_tag" "this" {
  for_each = toset(["project", "owner"])

  tag_key = each.value
  status  = "Active"
}
