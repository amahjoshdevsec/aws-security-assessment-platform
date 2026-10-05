output "github_role_arn" { value = aws_iam_role.runner.arn }
output "report_bucket" { value = aws_s3_bucket.reports.id }
output "report_kms_key_arn" { value = aws_kms_key.reports.arn }
