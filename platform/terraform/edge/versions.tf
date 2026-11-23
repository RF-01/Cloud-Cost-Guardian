# platform/terraform/edge — lane C, last module in the CONTRACT §8 chain (task #38).
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
