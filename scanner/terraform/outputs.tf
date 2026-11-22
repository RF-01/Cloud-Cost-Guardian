output "scanner_function_arn" {
  description = "Scanner Lambda ARN (EventBridge schedule target, platform)"
  value       = aws_lambda_function.scanner.arn
}
