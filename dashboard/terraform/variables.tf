# Inputs per CONTRACT §8 (dashboard row) plus name_prefix, owner_email, dry_run. Inputs are added as each
# dashboard task needs them: bedrock_model_id, vpc_id, public_subnet_id, origin_secret and notify_function_name
# come with #26, #38 and #42.

variable "name_prefix" {
  description = "Prefix of every resource name, e.g. cg-dev- (CONTRACT §1)"
  type        = string
}

variable "owner_email" {
  description = "Owner of this stack (tags come from the root's default_tags)"
  type        = string
}

variable "dry_run" {
  description = "Stack DRY_RUN. The dashboard lane's Lambdas only read and report, so it's unused for now"
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
