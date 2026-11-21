output "name_prefix" {
  value = var.name_prefix
}

output "dev_scope" {
  description = "Empty in the team stack; the name prefix in personal stacks (CONTRACT §6)"
  value       = local.dev_scope
}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "action_api_url" {
  description = "Base URL of the action links API (platform core)"
  value       = module.platform_core.action_api_url
}

output "team_topic_arn" {
  description = "SNS topic for team alerts (platform core)"
  value       = module.platform_core.team_topic_arn
}
