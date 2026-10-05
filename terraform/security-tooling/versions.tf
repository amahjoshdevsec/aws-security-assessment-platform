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
variable "region" {
  type    = string
  default = "us-east-1"
}
variable "account_id" {
  type        = string
  description = "Account in which this root must be deployed."
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "Supply a 12-digit AWS account ID."
  }
}
