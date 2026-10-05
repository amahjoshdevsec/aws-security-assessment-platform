# Migrating the original walkthrough

The original tracked files have been preserved under [examples/local-server](../examples/local-server/README.md). Their directory structure remains intact. Operational notes there describe the old lab and historical observations; they are not verification claims for the enterprise implementation. No root README or version pin was present in the source snapshot; this update adds both and restores a version pin for the lab's setup script.

1. Back up any existing Prowler database and the original Terraform state through your approved process. Moving code does not migrate running resources or local data directories.
2. Provision tooling and member roles using the new roots and independent state. Do not apply the new configuration against the legacy state file.
3. Configure OIDC protection and perform a canary scan. Compare resource/check coverage against the old assessment, accounting for explicit region scope and permission changes.
4. Review old mutelist entries individually. None are copied to the enterprise active list: the old wildcard acceptance is not suitable for all accounts. Obtain scoped approvals if a decision remains valid.
5. After successful cutover, revoke legacy IAM access keys and remove the old user through the original Terraform state/configuration where applicable. Remove stored copies from Prowler through its supported administration process. Treat old state and backups as sensitive because they can contain access-key material.
6. Retain historical reports as audit evidence without presenting them as new scans. Disable the old scheduler/server if no longer needed. Review deletion and retention separately before purging any local data.

The historical additions policy includes `securityhub:BatchImportFindings` despite older prose calling all permissions read-only. The enterprise policy removes that action. Historical broad muting, access-key provisioning, database repair commands and destructive teardown procedures are lab-only references and require fresh operational judgment.

## Standalone repository cutover

The canonical portfolio repository is `amahjoshdevsec/aws-security-assessment-platform`; the old fork retains the upgraded source for continuity. Git history, the original license and upstream attribution are preserved. Update Terraform `github_repository` to the exact standalone owner/repository before enabling scans there. Recreate environment protection and variables in the new repository, verify OIDC in the canary, and disable the old scheduled workflow before using the same state/report prefixes. Do not leave two repositories writing the same lifecycle state: GitHub workflow concurrency is scoped to one repository.
