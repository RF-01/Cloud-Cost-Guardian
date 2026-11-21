# infra/stack — one full copy of the Guardian (a personal stack, or the team stack).
# Each lane adds only its own `module` block in main.tf (CLAUDE.md).
# State: s3://cost-guardian-tfstate-<account id>/stacks/<name_prefix>/terraform.tfstate (one per person).
#
# First time (bucket and key are both passed at init):
#   terraform init -backend-config="bucket=cost-guardian-tfstate-<ACCOUNT_ID>" -backend-config="key=stacks/<name_prefix>/terraform.tfstate" -backend-config="profile=guardian"

terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    # Lambda zips (archive_file), added by the lane modules later.
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }

  # Partial config: bucket (contains the account ID) and key (contains your name prefix) are passed at init.
  backend "s3" {
    region       = "us-west-2"
    use_lockfile = true
    encrypt      = true
  }
}
