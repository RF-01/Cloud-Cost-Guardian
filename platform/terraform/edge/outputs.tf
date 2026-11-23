# CONTRACT §8 platform edge outputs.

output "dashboard_url" {
  description = "Open this (team login from terraform.tfvars)"
  value       = "https://${aws_cloudfront_distribution.dashboard.domain_name}"
}
