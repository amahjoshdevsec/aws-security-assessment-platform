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
data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.tooling_role_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}
resource "aws_iam_role" "audit" {
  name                 = var.audit_role_name
  path                 = "/security/"
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
  permissions_boundary = var.permissions_boundary_arn
}
resource "aws_iam_role_policy_attachment" "audit" {
  for_each   = toset(["arn:aws:iam::aws:policy/SecurityAudit", "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"])
  role       = aws_iam_role.audit.name
  policy_arn = each.value
}
resource "aws_iam_role_policy" "additions" {
  name   = "ProwlerReadAdditions"
  role   = aws_iam_role.audit.id
  policy = file("${path.module}/../policies/prowler-read-additions.json")
}
output "audit_role_arn" { value = aws_iam_role.audit.arn }
