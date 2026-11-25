variable "name_prefix" {
  description = "Prefix of every resource name, e.g. cg-dev- (CONTRACT §1)"
  type        = string
}

variable "owner_email" {
  description = "Owner of this stack (tags come from the root's default_tags)"
  type        = string
}

variable "dry_run" {
  description = "Module convention (CONTRACT §8); schedules run the same in dry-run"
  type        = bool
}

variable "schedules_enabled" {
  description = "false creates the schedules DISABLED (nothing runs on its own; manual invokes still work)"
  type        = bool
}

variable "scanner_function_arn" {
  type = string
}

variable "scanner_function_name" {
  description = "For the retry setting and the scanner-errors alarm"
  type        = string
}

variable "daily_cost_function_arn" {
  type = string
}

variable "daily_summary_function_arn" {
  type = string
}

variable "digest_enabled" {
  description = "Create the weekly digest schedule (#42 turns it on). Decides the schedule key set, so it must be a plain bool"
  type        = bool
  default     = false
}

variable "digest_function_arn" {
  description = "Digest Lambda ARN; required when digest_enabled (not used to decide which schedules exist)"
  type        = string
  default     = ""

  # Checked at plan when the ARN is known, otherwise at apply.
  validation {
    condition     = !var.digest_enabled || var.digest_function_arn != ""
    error_message = "digest_enabled = true requires digest_function_arn."
  }
}

variable "dlq_arn" {
  description = "Core DLQ (alarmed): target of failed schedule deliveries"
  type        = string
}

variable "team_topic_arn" {
  description = "Team SNS topic for the scanner-errors alarm"
  type        = string
}
