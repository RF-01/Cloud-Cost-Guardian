# Inputs per CONTRACT §8 (engine row) plus name_prefix, owner_email, dry_run.

variable "name_prefix" {
  description = "Prefix of every resource name, e.g. cg-dev- (CONTRACT §1)"
  type        = string
}

variable "owner_email" {
  description = "Owner of this stack (tags come from the root's default_tags)"
  type        = string
}

variable "dry_run" {
  description = "DRY_RUN for the remediation Lambda (it also honours the workflow input's dryRun: either one makes it a dry run)"
  type        = bool
}

variable "table_names" {
  description = "Platform core table names, keyed per CONTRACT §8"
  type        = map(string)
}

variable "table_arns" {
  description = "Platform core table ARNs, keyed per CONTRACT §8"
  type        = map(string)
}

variable "notify_function_arn" {
  description = "Notify Lambda ARN (invoked by the workflows)"
  type        = string
}

variable "notify_function_name" {
  description = "Notify Lambda name (NOTIFY_FUNCTION_NAME for the action Lambda, task #31). Unused until then"
  type        = string
}

variable "team_topic_arn" {
  description = "Team SNS topic (workflow alarms, task #32). Unused until then"
  type        = string
}

variable "action_api_id" {
  description = "Platform core HTTP API id (engine adds the /action routes, task #31). Unused until then"
  type        = string
}

variable "action_api_execution_arn" {
  description = "Platform core HTTP API execution ARN (Lambda permission, task #31). Unused until then"
  type        = string
}

variable "dev_scope" {
  description = "Empty in the team stack; the name prefix in personal stacks (DEV_SCOPE, CONTRACT §6)"
  type        = string
}

variable "timeline_waits" {
  description = "Workflow waits in seconds (CONTRACT §4.4, §8). The workflows read waits from their input; the action Lambda (#31) uses these. Unused until then"
  type = object({
    ec2_before_final  = number
    ec2_before_action = number
    ebs_before_final  = number
    ebs_before_action = number
  })
}

variable "postpone_seconds" {
  description = "POSTPONE_SECONDS for the action Lambda (task #31). Unused until then"
  type        = number
}

variable "detection_window_minutes" {
  description = "DETECTION_WINDOW_MINUTES: the CHECK_EC2 re-check uses the same window as the scanner (CONTRACT v2.5)"
  type        = number
}
