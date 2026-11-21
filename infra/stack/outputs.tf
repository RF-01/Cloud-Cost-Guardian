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
