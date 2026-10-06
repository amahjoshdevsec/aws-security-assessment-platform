variable "github_repository" {
  type    = string
  default = "amahjoshdevsec/aws-security-assessment-platform"
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
variable "member_accounts" {
  type = map(object({
    role_name   = string
    external_id = string
  }))
  description = "Approved account IDs and their exact audit role/external ID pairs; match inventory."
  validation {
    condition = length(var.member_accounts) > 0 && alltrue([
      for id, member in var.member_accounts :
      can(regex("^[0-9]{12}$", id)) &&
      can(regex("^[A-Za-z0-9+=,.@_-]{1,64}$", member.role_name)) &&
      length(member.external_id) >= 2 && length(member.external_id) <= 1224 &&
      can(regex("^[A-Za-z0-9+=,.@:/_-]+$", member.external_id))
    ])
    error_message = "Each member needs a 12-digit ID, valid role name and nonempty STS external ID."
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

variable "github_oidc_subject" {
  description = "Exact GitHub OIDC subject allowed to assume the runner role."
  type        = string
}

