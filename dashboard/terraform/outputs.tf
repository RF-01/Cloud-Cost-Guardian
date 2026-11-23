# CONTRACT §8 dashboard outputs; the others are added by the tasks that create them.

output "daily_cost_function_arn" {
  value = aws_lambda_function.daily_cost.arn
}
