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

# --- AWS Budgets (design §11.2, CONTRACT §8 / §9) ---------------------------------------------------------

variable "budgets_enabled" {
  description = "Create the account and project budgets (alerts to the team topic)"
  type        = bool
}

variable "account_budget_usd" {
  description = "Monthly account budget in USD (usage before credits)"
  type        = number

  validation {
    condition     = var.account_budget_usd > 0
    error_message = "account_budget_usd must be greater than 0."
  }
}

variable "project_budgets" {
  description = "Monthly budget in USD per project, keyed by the project tag value"
  type        = map(number)

  validation {
    condition     = alltrue([for k, v in var.project_budgets : v > 0 && can(regex("^[A-Za-z0-9._-]{1,60}$", k))])
    error_message = "project_budgets: keys are project tag values (letters, digits, . _ -; at most 60), amounts > 0."
  }
}
