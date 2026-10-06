variable "tooling_role_arn" {
  type        = string
  description = "Exact security tooling runner ARN; deploy tooling first."
  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/security/ProwlerGitHubRunner$", var.tooling_role_arn))
    error_message = "Use the exact commercial AWS tooling runner role ARN."
  }
}
variable "external_id" {
  type = string
  validation {
    condition     = length(var.external_id) >= 2 && length(var.external_id) <= 1224 && can(regex("^[A-Za-z0-9+=,.@:/_-]+$", var.external_id))
    error_message = "Supply a valid, nonempty STS external ID."
  }
}
variable "audit_role_name" {
  type    = string
  default = "ProwlerAudit"
}
variable "permissions_boundary_arn" {
  type        = string
  default     = null
  description = "Optional organization-managed permissions boundary."
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
