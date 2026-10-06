
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
