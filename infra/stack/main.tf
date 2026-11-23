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

locals {
  # CONTRACT §6: empty in the team stack; in personal stacks = the name prefix, so only resources
  # tagged guardian:dev-scope=<prefix> are acted on or emailed.
  dev_scope = var.team_stack ? "" : var.name_prefix
}

# ---------------------------------------------------------------------------
# Lane modules, in CONTRACT §8 order (a straight chain, no cycles):
#   platform core  ──►  engine, scanner, dashboard  ──►  platform edge
#
# All commented out until each module exists. Each lane uncomments ONLY its own block.
# No depends_on between lane modules (CONTRACT §8): the wiring below is the only ordering.
# ---------------------------------------------------------------------------

# --- Lane C: platform core ---------------------------------------------------
# Outputs (§8): table_names / table_arns (maps, keys in CONTRACT §8), team_topic_arn, dlq_arn, notify_function_arn / name,
# vpc_id, public_subnet_id, action_api_id, action_api_execution_arn, action_api_url.

module "platform_core" {
  source = "../../platform/terraform/core"

  name_prefix  = var.name_prefix
  owner_email  = var.owner_email
  dry_run      = var.dry_run
  team_email   = var.team_email
  sender_email = var.sender_email
}

# --- Lane A: engine ----------------------------------------------------------
# Outputs (§8): ec2_sfn_arn, ebs_sfn_arn, remediation_function_arn, action_function_arn.
# (Engine adds the /action routes, the integration and the Lambda permission to core's API, task #31.)

module "engine" {
  source = "../../engine/terraform"

  name_prefix = var.name_prefix
  owner_email = var.owner_email
  dry_run     = var.dry_run

  table_names              = module.platform_core.table_names
  table_arns               = module.platform_core.table_arns
  notify_function_arn      = module.platform_core.notify_function_arn
  notify_function_name     = module.platform_core.notify_function_name
  team_topic_arn           = module.platform_core.team_topic_arn
  action_api_id            = module.platform_core.action_api_id
  action_api_execution_arn = module.platform_core.action_api_execution_arn
  dev_scope                = local.dev_scope

  timeline_waits           = var.timeline_waits
  postpone_seconds         = var.postpone_seconds
  detection_window_minutes = var.detection_window_minutes
}

# --- Lane B: scanner ---------------------------------------------------------
# Outputs (§8): scanner_function_arn.

module "scanner" {
  source = "../../scanner/terraform"

  name_prefix = var.name_prefix
  owner_email = var.owner_email
  dry_run     = var.dry_run

  table_names          = module.platform_core.table_names
  table_arns           = module.platform_core.table_arns
  ec2_sfn_arn          = module.engine.ec2_sfn_arn
  ebs_sfn_arn          = module.engine.ebs_sfn_arn # null until engine #30
  notify_function_name = module.platform_core.notify_function_name
  scan_regions         = var.scan_regions
  dev_scope            = local.dev_scope

  timeline_waits              = var.timeline_waits
  detection_window_minutes    = var.detection_window_minutes
  eip_stopped_threshold_hours = var.eip_stopped_threshold_hours
}

# --- Lane D: dashboard -------------------------------------------------------
# Outputs (§8): daily_cost_function_arn, daily_summary_function_arn, digest_function_arn,
# dashboard_instance_id, dashboard_public_dns.
# Inputs are added as each dashboard task needs them (CONTRACT §8): bedrock_model_id, vpc_id, public_subnet_id,
# origin_secret and notify_function_name come with #38, #42 and #43.

module "dashboard" {
  source = "../../dashboard/terraform"

  name_prefix = var.name_prefix
  owner_email = var.owner_email
  dry_run     = var.dry_run

  table_names = module.platform_core.table_names
  table_arns  = module.platform_core.table_arns
  dlq_arn     = module.platform_core.dlq_arn
}

# --- Lane C: platform edge ---------------------------------------------------
# Outputs (§8): dashboard_url.
#
# module "platform_edge" {
#   source = "../../platform/terraform/edge"
#
#   name_prefix = var.name_prefix
#   owner_email = var.owner_email
#   dry_run     = var.dry_run
#
#   dashboard_public_dns = module.dashboard.dashboard_public_dns
#   origin_secret        = var.origin_secret
#   dashboard_password   = var.dashboard_password
# }
