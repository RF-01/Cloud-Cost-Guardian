# CONTRACT §8 dashboard outputs; the others are added by the tasks that create them.

output "daily_cost_function_arn" {
  value = aws_lambda_function.daily_cost.arn
}

output "daily_summary_function_arn" {
  value = aws_lambda_function.daily_summary.arn
}

output "digest_function_arn" {
  value = aws_lambda_function.digest.arn
}

output "dashboard_instance_id" {
  value = aws_instance.dashboard.id
}

output "dashboard_public_dns" {
  description = "CloudFront's origin. Changes when the instance is replaced or stopped and started (design §6.3)"
  value       = aws_instance.dashboard.public_dns
}
