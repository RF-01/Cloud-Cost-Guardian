# Inputs per CONTRACT §8 (scanner row) plus name_prefix, owner_email, dry_run.

variable "name_prefix" {
  description = "Prefix of every resource name, e.g. cg-dev- (CONTRACT §1)"
  type        = string
}

variable "owner_email" {
  description = "Owner of this stack (tags come from the root's default_tags)"
  type        = string
}

variable "dry_run" {
  description = "Passed to the scanner as DRY_RUN (tag copying, and into workflow input via common/timeline.py)"
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

variable "ec2_sfn_arn" {
  description = "EC2 timeline state machine ARN (engine). Empty or null: timelines are skipped and no states:* permission is granted"
  type        = string
  default     = ""
  nullable    = false # engine outputs null until a workflow exists (EBS: #30); null becomes ""
}

variable "ebs_sfn_arn" {
  description = "EBS timeline state machine ARN (engine). Empty or null: timelines are skipped and no states:* permission is granted"
  type        = string
  default     = ""
  nullable    = false # engine outputs null until a workflow exists (EBS: #30); null becomes ""
}

variable "notify_function_name" {
  description = "Notify Lambda name (NOTIFY_FUNCTION_NAME). Not invoked yet (emails come in task #36)"
  type        = string
}

variable "scan_regions" {
  description = "\"all\" or a comma-separated list of regions (SCAN_REGIONS, CONTRACT §6)"
  type        = string
}

variable "dev_scope" {
  description = "Empty in the team stack; the name prefix in personal stacks (DEV_SCOPE, CONTRACT §6)"
  type        = string
}

variable "timeline_waits" {
  description = "Workflow waits in seconds, passed as WAIT_* (CONTRACT §4.4, §8)"
  type = object({
    ec2_before_final  = number
    ec2_before_action = number
    ebs_before_final  = number
    ebs_before_action = number
  })
}

variable "detection_window_minutes" {
  description = "DETECTION_WINDOW_MINUTES"
  type        = number
}

variable "eip_stopped_threshold_hours" {
  description = "EIP_STOPPED_THRESHOLD_HOURS"
  type        = number
}
