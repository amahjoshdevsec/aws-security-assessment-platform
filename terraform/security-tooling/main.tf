data "aws_partition" "current" {}
locals {
  partition = data.aws_partition.current.partition
  oidc_arn  = var.existing_oidc_provider_arn != null ? var.existing_oidc_provider_arn : aws_iam_openid_connect_provider.github[0].arn
}
resource "aws_iam_openid_connect_provider" "github" {
  count          = var.existing_oidc_provider_arn == null ? 1 : 0
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}
data "aws_iam_policy_document" "oidc" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.oidc_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:environment:${var.github_environment}"]
    }
  }
}
resource "aws_iam_role" "runner" {
  name                 = "ProwlerGitHubRunner"
  path                 = "/security/"
  assume_role_policy   = data.aws_iam_policy_document.oidc.json
  max_session_duration = 3600
}
data "aws_iam_policy_document" "runner" {
  dynamic "statement" {
    for_each = var.member_accounts
    content {
      sid       = "AssumeMember${statement.key}"
      actions   = ["sts:AssumeRole"]
      resources = ["arn:${local.partition}:iam::${statement.key}:role/security/${statement.value.role_name}"]
      condition {
        test     = "StringEquals"
        variable = "sts:ExternalId"
        values   = [statement.value.external_id]
      }
    }
  }
  statement {
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${aws_s3_bucket.reports.arn}/reports/*", "${aws_s3_bucket.reports.arn}/state/*"]
  }
  statement {
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.reports.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["reports/*", "state/*"]
    }
  }
  statement {
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.reports.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }
  }
}
resource "aws_iam_role_policy" "runner" {
  role   = aws_iam_role.runner.id
  policy = data.aws_iam_policy_document.runner.json
}
resource "aws_kms_key" "reports" {
  description             = "Central Prowler report encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  lifecycle { prevent_destroy = true }
}
resource "aws_kms_alias" "reports" {
  name          = "alias/prowler-reports"
  target_key_id = aws_kms_key.reports.key_id
}
resource "aws_s3_bucket" "reports" {
  bucket        = var.report_bucket_name
  force_destroy = false
  lifecycle { prevent_destroy = true }
}
resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_ownership_controls" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule { object_ownership = "BucketOwnerEnforced" }
}
resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.reports.arn
    }
    bucket_key_enabled = true
  }
}
resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket     = aws_s3_bucket.reports.id
  depends_on = [aws_s3_bucket_versioning.reports]
  rule {
    id     = "report-retention"
    status = "Enabled"
    filter { prefix = "reports/" }
    expiration { days = var.retention_days }
    noncurrent_version_expiration { noncurrent_days = var.retention_days }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
  rule {
    id     = "state-history-retention"
    status = "Enabled"
    filter { prefix = "state/" }
    noncurrent_version_expiration { noncurrent_days = var.retention_days }
  }
}
data "aws_iam_policy_document" "bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.reports.arn, "${aws_s3_bucket.reports.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
  statement {
    sid       = "RequireKMS"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.reports.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }
  statement {
    sid       = "RequireReportKey"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.reports.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.reports.arn]
    }
  }
}
resource "aws_s3_bucket_policy" "reports" {
  bucket = aws_s3_bucket.reports.id
  policy = data.aws_iam_policy_document.bucket.json
}
data "aws_iam_policy_document" "reader" {
  statement {
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${aws_s3_bucket.reports.arn}/reports/*", "${aws_s3_bucket.reports.arn}/state/*"]
  }
  statement {
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.reports.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["reports/*", "state/*"]
    }
  }
  statement {
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.reports.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }
  }
}
resource "aws_iam_role_policy" "reader" {
  for_each = toset(var.reader_role_arns)
  name     = "ProwlerReportRead"
  role     = element(reverse(split("/", each.value)), 0)
  policy   = data.aws_iam_policy_document.reader.json
  lifecycle {
    precondition {
      condition     = startswith(each.value, "arn:${local.partition}:iam::${var.account_id}:role/")
      error_message = "Reader roles must exist in the security tooling account."
    }
  }
}
