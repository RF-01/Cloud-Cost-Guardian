output "console_sign_in_url" {
  description = "Where team members sign in"
  value       = "https://${data.aws_caller_identity.current.account_id}.signin.aws.amazon.com/console"
}

output "team_group" {
  value = aws_iam_group.team.name
}

output "initial_passwords" {
  description = "One-time passwords for the new users (they must change them at first sign-in). Show with: terraform output -json initial_passwords"
  value       = { for name, profile in aws_iam_user_login_profile.member : name => profile.password }
  sensitive   = true
}

output "ses_identities" {
  description = "Addresses that must click their SES verification email"
  value       = keys(aws_sesv2_email_identity.address)
}
