# Exactly the CONTRACT §8 engine outputs.

output "ec2_sfn_arn" {
  description = "EC2 timeline state machine (EC2_SFN_ARN for common/timeline.py)"
  value       = aws_sfn_state_machine.ec2_timeline.arn
}

output "ebs_sfn_arn" {
  description = "EBS timeline state machine (EBS_SFN_ARN for common/timeline.py)"
  value       = aws_sfn_state_machine.ebs_timeline.arn
}

output "remediation_function_arn" {
  value = aws_lambda_function.remediation.arn
}

output "action_function_arn" {
  description = "Action Lambda. null until task #31"
  value       = null # action Lambda + /action routes: task #31
}
