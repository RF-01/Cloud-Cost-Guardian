variable "name_prefix" {
  description = "Prefix of every resource name, e.g. cg-dev- (CONTRACT §1)"
  type        = string
}

variable "owner_email" {
  description = "Owner of this stack (tags come from the root's default_tags)"
  type        = string
}

variable "dry_run" {
  description = "Passed to the Lambdas as DRY_RUN"
  type        = bool
}

variable "team_email" {
  description = "Team address: SNS alert subscription, TEAM_EMAIL for Notify"
  type        = string
}

variable "sender_email" {
  description = "Verified SES sender, SENDER_EMAIL for Notify"
  type        = string
}
