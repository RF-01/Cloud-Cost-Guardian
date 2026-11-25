# platform/terraform/schedules — lane C (task #37): EventBridge Scheduler jobs (CONTRACT §4.7), scanner retry
# setting and error alarm. Called from infra/stack after scanner and dashboard (CONTRACT §8).
# Provider configuration (region, profile, default_tags) comes from the root (infra/stack).

terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}
