# Terraform deployment and state

Two independent roots are intentional: tooling infrastructure is deployed once and the member role is deployed once per approved account. Terraform providers cannot dynamically iterate across arbitrary accounts; use your provisioning pipeline to invoke the member root with separate credentials and state per account. Scanner credentials cannot provision infrastructure.

## Bootstrap and remote state

Use an administrator-approved SSO/provisioning role. Create or select an independently secured state backend before production: encrypted S3, versioning, public access blocked, a state-access role, and a concurrency lock appropriate to your installed Terraform version. Terraform 1.7 deployments can use an existing DynamoDB lock table. Do not use the report bucket as the bootstrap state bucket. Never put credentials in backend files or `tfvars`.

For example, add an empty `backend "s3" {}` inside the root's `terraform` block and initialize with your real state configuration:

```bash
terraform -chdir=terraform/security-tooling init \
  -backend-config="bucket=YOUR_STATE_BUCKET" \
  -backend-config="key=prowler/tooling/terraform.tfstate" \
  -backend-config="region=us-east-1" \
  -backend-config="encrypt=true" \
  -backend-config="dynamodb_table=YOUR_LOCK_TABLE"
```

Use `prowler/member/ACCOUNT_ID/terraform.tfstate` for each member. Use separate working copies or `TF_DATA_DIR` per member to avoid accidentally reusing cached backend configuration. Backend support changes with Terraform releases; follow the [S3 backend documentation](https://developer.hashicorp.com/terraform/language/backend/s3) for upgrades.

The checked-in roots omit a backend so credential-free validation works without organization infrastructure. Their local default is for evaluation only. State, plans, local variables and credentials are gitignored.

## Deploy tooling first

```bash
cp terraform/security-tooling/terraform.tfvars.example terraform/security-tooling/terraform.tfvars
# Edit account ID, member allowlist, external ID, region and unique report bucket name.
# Authenticate to the tooling account with your provisioning identity.
terraform -chdir=terraform/security-tooling init
terraform -chdir=terraform/security-tooling plan -out=tooling.tfplan
terraform -chdir=terraform/security-tooling apply tooling.tfplan
terraform -chdir=terraform/security-tooling output
```

The provider's `allowed_account_ids` guard rejects credentials for the wrong account. If a GitHub OIDC provider already exists, set `existing_oidc_provider_arn`; do not attempt to create a duplicate provider. Check its URL and audience. Protect the GitHub environment before enabling the runner role's use.

The tooling root creates an OIDC provider when needed, a runner role and policy, KMS key/alias, private S3 bucket with enforced encryption, versioning and lifecycle, and optional reader policies on existing same-account roles. Evidence retention defaults to 365 days; prior lifecycle-state versions use the same retention. The current state remains until explicitly retired. Actual physical deletion of versioned reports can lag logical expiration because noncurrent versions have their own retention period.

## Deploy each member

```bash
cp terraform/member-account/terraform.tfvars.example terraform/member-account/terraform.tfvars
# Authenticate to the selected member account. Edit its account_id and tooling_role_arn.
terraform -chdir=terraform/member-account init
terraform -chdir=terraform/member-account plan -out=member.tfplan
terraform -chdir=terraform/member-account apply member.tfplan
terraform -chdir=terraform/member-account output audit_role_arn
```

Use the same external ID in tooling, member trust and inventory. The member role path is `/security/`; keep inventory `role_name` consistent. The member trust names the exact tooling role, so tooling must exist before member apply. IAM propagation can delay the first scan. If the tooling role is deleted and recreated, reapply member trust policies because AWS binds role principals to unique principal IDs.

## Policy maintenance

[prowler-read-additions.json](../terraform/policies/prowler-read-additions.json) preserves the original 5.38.0 additional permissions except `securityhub:BatchImportFindings`, which is intentionally excluded. It is not a generic least-privilege policy for every organization. Compare it with [the pinned upstream policy](https://github.com/prowler-cloud/prowler/blob/5.38.0/permissions/prowler-additions-policy.json) during scanner upgrades, review every permission, and validate denied-check coverage in a canary account. Never grant AdministratorAccess to clear errors.

## Destruction and migration

The report bucket and KMS key use `prevent_destroy`; the bucket also has `force_destroy = false`. Decommission scanning and member trust first, then retain/archive evidence and state according to policy. Removing destruction guards or scheduling key deletion requires a separately reviewed change. A deleted key makes retained encrypted evidence unreadable.

Do not move the legacy Terraform state into these roots: resource addresses and lifecycle differ. Follow [migration](migration.md), provision roles independently, verify new scans, then revoke the old IAM access keys. No infrastructure is deployed automatically by the validation workflow.
