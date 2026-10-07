resource "aws_s3_bucket" "remediation_canary" {
  bucket_prefix = "amah-prowler-canary-"

  tags = {
    Name    = "Prowler remediation canary"
    Purpose = "Controlled versioning remediation test"
  }
}

resource "aws_s3_bucket_public_access_block" "remediation_canary" {
  bucket = aws_s3_bucket.remediation_canary.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "remediation_canary" {
  bucket = aws_s3_bucket.remediation_canary.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

output "canary_bucket_name" {
  value = aws_s3_bucket.remediation_canary.id
}