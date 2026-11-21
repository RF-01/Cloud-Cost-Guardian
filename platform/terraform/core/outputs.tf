# Exactly the CONTRACT §8 platform core outputs.

output "table_names" {
  description = "Table names keyed findings, audit, tokens, creator_lookups, volume_attachments, daily_summaries, bill_history, budget_alerts, counters"
  value       = { for k, t in local.tables : k => t.name }
}

output "table_arns" {
  description = "Table ARNs, same keys as table_names"
  value       = { for k, t in local.tables : k => t.arn }
}

output "team_topic_arn" {
  value = aws_sns_topic.team_alerts.arn
}

output "dlq_arn" {
  value = aws_sqs_queue.dlq.arn
}

output "notify_function_arn" {
  value = aws_lambda_function.notify.arn
}

output "notify_function_name" {
  value = aws_lambda_function.notify.function_name
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "public_subnet_id" {
  value = aws_subnet.public.id
}

output "action_api_id" {
  value = aws_apigatewayv2_api.action.id
}

output "action_api_execution_arn" {
  value = aws_apigatewayv2_api.action.execution_arn
}

output "action_api_url" {
  description = "Base URL, no trailing slash: links are <action_api_url>/action?t=<token>"
  value       = local.action_api_url
}
