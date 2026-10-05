# Two-account canary validation

Status: **not yet deployed or validated against live AWS**. Local tests and a green CI run validate the implementation, not the cloud environment. Record actual evidence before changing this status or making deployment claims.

## Required deployment inputs

Identify the dedicated tooling account and a separate sandbox workload account, provisioning profiles/SSO roles, report region, unique evidence bucket, protected GitHub repository/environment, state backends, and budget/cleanup owner. Do not use a production workload or grant the scanner provisioning access. Prepare and review a plan for each account before apply.

## Evidence checklist

| Stage | Acceptance criterion | Evidence to record |
| --- | --- | --- |
| Provision | Tooling and sandbox Terraform apply successfully under the correct account guards | Reviewed plans, outputs and account identities |
| OIDC | Protected environment obtains the tooling role | GitHub run and CloudTrail `AssumeRoleWithWebIdentity` |
| Cross-account STS | Host assumes sandbox audit role using its exact external ID | CloudTrail `AssumeRole`, session ARN/run ID and account |
| Credential isolation | Docker receives only member credentials | Tested code revision; never store credential values |
| Assessment | Prowler produces error-free complete reports in approved scope | Native outputs, hashes, complete manifest |
| Evidence encryption | Object uses intended SSE-KMS key | S3 `head-object` encryption metadata and authorized read |
| Initial finding | A private, empty lab bucket has versioning disabled | `s3_bucket_object_versioning` FAIL and stable finding ID |
| Remediation | Enable versioning via the bucket's IaC and rescan | Same finding ID with unmuted PASS; `open → resolved` |
| Recurrence | In this empty lab only, suspend versioning and rescan | `resolved → reopened` |
| Acceptance | Approve a scoped, short-lived exception through the risk process | Source decision, ticket, next scan `risk_accepted` |
| Removal | Remove acceptance through review and rescan while condition remains | Active FAIL returns to `open` |
| Expiry | Use a test decision that expires; validate after UTC expiry | Validation refuses the expired record; no stale mute is applied |
| Final recovery | Restore versioning, remove the exception, rescan | Resolved finding and complete evidence |
| Cleanup | Remove the disposable lab bucket by approved IaC after evidence capture | Cleanup record; retain central evidence per policy |

The controlled test bucket must remain empty, private, encrypted and blocked from public access throughout. Do not weaken encryption, expose data or modify an existing production bucket to create a finding. If its check/resource identifier differs in the selected Prowler release, use the actual report values for exception scope and correlation.

Do not change the scanner's system clock to test expiry. Unit tests already verify date boundaries; the live exercise records the real validation result after an approved expiry. Remove expired decisions before the next operational scan.

## Evidence collection

Use authorized analyst/provisioning roles to inspect state and metadata, not scanner credentials:

```bash
aws s3api head-object --bucket YOUR_REPORT_BUCKET --key reports/ACCOUNT/REGION/RUN_ID/manifest.json
mkdir -p reports/canary
aws s3 cp s3://YOUR_REPORT_BUCKET/reports/ACCOUNT/REGION/RUN_ID/state.json reports/canary/state.json
python3 scripts/findings.py reports/canary/state.json FINDING_SHA256 RUN_ID
```

Keep CloudTrail event IDs, timestamps, region, principal ARN and workflow URL in a private evidence register. Publish only a redacted validation summary approved for the public portfolio. Record failed cases and coverage limits as well as successful ones. Until this checklist has real evidence, describe this work as a designed and implemented reference platform.
