# platform/terraform/core — lane C, first module in the CONTRACT §8 chain.
# Provider configuration (region, profile, default_tags) comes from the root (infra/stack).

terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}
