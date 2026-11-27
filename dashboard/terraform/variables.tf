# Inputs per CONTRACT §8 (dashboard row) plus name_prefix, owner_email, dry_run. Inputs are added as each
# dashboard task needs them: #42 (digest) adds bedrock_model_id, bedrock_max_tokens, notify_function_name,
# notify_function_arn and team_email; #43 (Ask box) reuses the Bedrock ones and adds bedrock_daily_cap and
# bedrock_max_question_chars; rubric check A2 adds rate_limit_per_minute.

variable "name_prefix" {
  description = "Prefix of every resource name, e.g. cg-dev- (CONTRACT §1)"
  type        = string
}

variable "owner_email" {
  description = "Owner of this stack (tags come from the root's default_tags)"
  type        = string
}

variable "dry_run" {
  description = "Stack DRY_RUN. The dashboard lane's Lambdas only read and report: the digest passes it to its emails for display only"
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

variable "dlq_arn" {
  description = "Platform core DLQ: failed async (scheduled) invokes land here after Lambda's retries"
  type        = string
}

variable "vpc_id" {
  description = "Platform core VPC; the dashboard security group lives in it (#38)"
  type        = string
}

variable "public_subnet_id" {
  description = "Platform core public subnet for the dashboard instance (#38)"
  type        = string
}

variable "origin_secret" {
  description = "X-Origin-Verify value CloudFront sends; stored in SSM for the instance, never in user_data (#38)"
  type        = string
  sensitive   = true
}

variable "bedrock_model_id" {
  description = "Bedrock inference profile ID (BEDROCK_MODEL_ID, e.g. us.amazon.nova-2-lite-v1:0); the digest may invoke only it (#42)"
  type        = string

  validation {
    condition     = startswith(var.bedrock_model_id, "us.")
    error_message = "bedrock_model_id must be a US geo inference profile ID (us.<model>): the IAM policy derives the foundation model from it."
  }
}

variable "bedrock_max_tokens" {
  description = "Maximum output tokens per Bedrock call (BEDROCK_MAX_TOKENS)"
  type        = number
}

variable "bedrock_daily_cap" {
  description = "Ask box questions per UTC day for the whole dashboard (BEDROCK_DAILY_CAP, #43)"
  type        = number

  validation {
    condition     = var.bedrock_daily_cap >= 1 && floor(var.bedrock_daily_cap) == var.bedrock_daily_cap
    error_message = "bedrock_daily_cap must be a positive whole number."
  }
}

variable "bedrock_max_question_chars" {
  description = "Maximum Ask box question length in characters (BEDROCK_MAX_QUESTION_CHARS, #43)"
  type        = number

  validation {
    condition     = var.bedrock_max_question_chars >= 1 && var.bedrock_max_question_chars <= 2000 && floor(var.bedrock_max_question_chars) == var.bedrock_max_question_chars
    error_message = "bedrock_max_question_chars must be a whole number from 1 to 2000 (the request body is at most 4 KB)."
  }
}

variable "rate_limit_per_minute" {
  description = "Requests per visitor IP per sliding 60 s, every route except /healthz (RATE_LIMIT_PER_MINUTE, CONTRACT §4.11)"
  type        = number

  validation {
    condition     = var.rate_limit_per_minute >= 1 && var.rate_limit_per_minute <= 5000 && floor(var.rate_limit_per_minute) == var.rate_limit_per_minute
    error_message = "rate_limit_per_minute must be a whole number from 1 to 5000."
  }
}

variable "notify_function_name" {
  description = "Platform core Notify function name (NOTIFY_FUNCTION_NAME); the digest sends through it (#42)"
  type        = string
}

variable "notify_function_arn" {
  description = "Platform core Notify function ARN: the only function the digest role may invoke (#42)"
  type        = string
}

variable "team_email" {
  description = "Team address (TEAM_EMAIL): findings owned by it or with no valid owner go into the team's digest (#42)"
  type        = string
}
