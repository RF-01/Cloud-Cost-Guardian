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

output "dashboard_url" {
  description = "The dashboard, through CloudFront (login: dashboard_username / dashboard_password)"
  value       = module.platform_edge.dashboard_url
}

output "dashboard_instance_id" {
  description = "Dashboard EC2 instance (EC2 Instance Connect for SSH)"
  value       = module.dashboard.dashboard_instance_id
}

output "dashboard_public_dns" {
  description = "CloudFront's origin; changes after a stop / start (run terraform apply then)"
  value       = module.dashboard.dashboard_public_dns
}

output "team_topic_arn" {
  description = "SNS topic for team alerts (platform core)"
  value       = module.platform_core.team_topic_arn
}
