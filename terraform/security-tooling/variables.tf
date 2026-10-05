variable "github_repository" {
  type    = string
  default = "amahjoshdevsec/prowler-docker-walkthrough"
  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "Use an exact owner/repository."
  }
}
variable "github_environment" {
  type    = string
  default = "security-scans"
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]+$", var.github_environment))
    error_message = "Use an environment name without wildcards or colons."
  }
}
variable "existing_oidc_provider_arn" {
  type        = string
  default     = null
  description = "Reuse the account's GitHub OIDC provider, if already provisioned."
}
variable "member_account_ids" {
  type = set(string)
  validation {
    condition     = length(var.member_account_ids) > 0 && alltrue([for id in var.member_account_ids : can(regex("^[0-9]{12}$", id))])
    error_message = "Supply at least one exact member account ID."
  }
}
variable "audit_role_name" {
  type    = string
  default = "ProwlerAudit"
  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]{1,64}$", var.audit_role_name))
    error_message = "Use a valid IAM role name."
  }
}
variable "external_id" {
  type        = string
  description = "Organization scan identifier; match member trust and inventory. Not a password."
  validation {
    condition     = length(var.external_id) >= 2 && length(var.external_id) <= 1224 && can(regex("^[A-Za-z0-9+=,.@:/_-]+$", var.external_id))
    error_message = "Supply a valid, nonempty STS external ID."
  }
}
variable "report_bucket_name" {
  type        = string
  description = "Globally unique S3 report bucket name."
}
variable "retention_days" {
  type    = number
  default = 365
  validation {
    condition     = var.retention_days >= 90 && floor(var.retention_days) == var.retention_days
    error_message = "Retain evidence for at least 90 days."
  }
}
variable "reader_role_arns" {
  type        = list(string)
  default     = []
  description = "Existing same-account analyst roles granted S3 and KMS read access."
}
