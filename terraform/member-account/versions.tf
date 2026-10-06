terraform {
  required_version = ">= 1.7.0, < 2.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.58.0"
    }
  }
  # Add backend configuration before production; see docs/terraform.md.
}
provider "aws" {
  region              = var.region
  allowed_account_ids = [var.account_id]
  default_tags {
    tags = { Project = "enterprise-prowler", ManagedBy = "Terraform" }
  }
}
