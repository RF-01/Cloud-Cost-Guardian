# AWS Budgets (design §11.2, CONTRACT §9): one account budget and one budget per project, alerts to the team
# topic (its policy already lets budgets.amazonaws.com publish), where the budget subscriber stores them.
# Usage before credits, like bootstrap's budget: otherwise credits hide everything and it always shows $0.
# No budget actions: they cost money and could stop things.
# Project budgets filter on the `project` cost allocation tag (activated in infra/shared).

locals {
  budget_notifications = [
    { type = "ACTUAL", threshold = 80 },
    { type = "ACTUAL", threshold = 100 },
    { type = "FORECASTED", threshold = 100 },
  ]
  project_budgets = var.budgets_enabled ? var.project_budgets : {}
}

resource "aws_budgets_budget" "account" {
  count = var.budgets_enabled ? 1 : 0

  name         = "${var.name_prefix}account-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.account_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_types {
    include_credit = false
    include_refund = false
  }

  dynamic "notification" {
    for_each = local.budget_notifications
    content {
      comparison_operator       = "GREATER_THAN"
      threshold                 = notification.value.threshold
      threshold_type            = "PERCENTAGE"
      notification_type         = notification.value.type
      subscriber_sns_topic_arns = [aws_sns_topic.team_alerts.arn]
    }
  }

  depends_on = [aws_sns_topic_policy.team_alerts]
}

resource "aws_budgets_budget" "project" {
  for_each = local.project_budgets

  name         = "${var.name_prefix}project-${each.key}"
  budget_type  = "COST"
  limit_amount = tostring(each.value)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "TagKeyValue"
    values = [format("user:project$%s", each.key)]
  }

  cost_types {
    include_credit = false
    include_refund = false
  }

  dynamic "notification" {
    for_each = local.budget_notifications
    content {
      comparison_operator       = "GREATER_THAN"
      threshold                 = notification.value.threshold
      threshold_type            = "PERCENTAGE"
      notification_type         = notification.value.type
      subscriber_sns_topic_arns = [aws_sns_topic.team_alerts.arn]
    }
  }

  depends_on = [aws_sns_topic_policy.team_alerts]
}
