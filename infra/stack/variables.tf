variable "name_prefix" {
  description = "Prefix of every resource name in this stack, e.g. cg-dev- (CONTRACT §1)"
  type        = string

  validation {
    condition     = can(regex("^cg-[a-z0-9]+-$", var.name_prefix))
    error_message = "name_prefix must look like cg-<name>- (lowercase letters and digits), e.g. cg-dev-."
  }
}

variable "owner_email" {
  description = "Owner tag on everything this stack creates (lowercase email)"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$", var.owner_email))
    error_message = "owner_email must be a lowercase email address (CONTRACT §2)."
  }
}

variable "aws_profile" {
  description = "AWS CLI profile to run as (your IAM user, never root)"
  type        = string
  default     = "guardian"
}

variable "team_stack" {
  description = "true only for the one shared team stack; false for personal stacks (turns on the dev scope filter)"
  type        = bool
  default     = false
}

variable "dry_run" {
  description = "Log actions instead of executing them. Must stay true in every personal stack"
  type        = bool
  default     = true

  validation {
    condition     = var.dry_run || var.team_stack
    error_message = "dry_run must be true unless team_stack is true. CLAUDE.md: keep DRY_RUN=true in every personal stack; only the final team test turns it off."
  }
}

variable "team_email" {
  description = "Team address: alerts and findings with no known owner (verified in SES)"
  type        = string
  default     = "rif07@mail.aub.edu"
}

variable "sender_email" {
  description = "From address of every Guardian email (verified in SES)"
  type        = string
  default     = "rif07@mail.aub.edu"
}

variable "scan_regions" {
  description = "Regions the scanner reads: \"all\" or a comma-separated list, e.g. us-west-2,us-east-1 (CONTRACT §6)"
  type        = string
  default     = "all"
}

variable "bedrock_model_id" {
  description = "Bedrock model for the digest and the Ask box (set after task #15)"
  type        = string
  default     = ""
}

variable "origin_secret" {
  description = "Secret X-Origin-Verify header value between CloudFront and the dashboard (design §6.4)"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.origin_secret) >= 16
    error_message = "origin_secret must be at least 16 characters."
  }

  validation {
    condition     = !startswith(var.origin_secret, "CHANGE-ME")
    error_message = "origin_secret still has the placeholder from terraform.tfvars.example; generate a random value."
  }
}

variable "dashboard_password" {
  description = "Shared team password checked by the CloudFront Function (design §6.4)"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.dashboard_password) >= 16
    error_message = "dashboard_password must be at least 16 characters."
  }

  validation {
    condition     = !startswith(var.dashboard_password, "CHANGE-ME")
    error_message = "dashboard_password still has the placeholder from terraform.tfvars.example; generate a random value."
  }
}

# --- Timing (CONTRACT §8: variables of infra/stack, passed to scanner and engine) ---------------------

variable "timeline_waits" {
  description = "Workflow waits in seconds (CONTRACT §4.4; defaults EC2 2 d + 1 d, EBS 11 d + 3 d). Minutes for dev / demo"
  type = object({
    ec2_before_final  = number
    ec2_before_action = number
    ebs_before_final  = number
    ebs_before_action = number
  })
  default = {
    ec2_before_final  = 172800
    ec2_before_action = 86400
    ebs_before_final  = 950400
    ebs_before_action = 259200
  }
}

variable "detection_window_minutes" {
  description = "EC2 idle detection window (DETECTION_WINDOW_MINUTES): 30 for the demo, e.g. 1440 for real use"
  type        = number
  default     = 30
}

variable "eip_stopped_threshold_hours" {
  description = "Report an Elastic IP on a stopped instance after this many hours stopped (EIP_STOPPED_THRESHOLD_HOURS)"
  type        = number
  default     = 24
}

variable "postpone_seconds" {
  description = "Postpone link: beforeFinalSeconds of the next generation (POSTPONE_SECONDS; engine, task #17)"
  type        = number
  default     = 604800
}
