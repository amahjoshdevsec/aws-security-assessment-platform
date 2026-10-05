# Validation and CI

`make test` runs standard-library unit tests, Python compilation, account/exception validation, enterprise Markdown file-link checks, and `bash -n` on preserved shell scripts. `make tf-init tf-check` installs locked providers, checks formatting, and runs `terraform validate` for both new roots. The validation workflow needs no AWS credentials or OIDC permissions.

Behavior tests cover inventory scope, duplicate records, exact exception matching, independent approval, expiry/lifetime rules, native CSV parsing, stable finding identity, FAIL/PASS/reopen transitions, suppressed and absent evidence, operational exit codes, error logs, state read failures, secret-free command arguments and supplementary read permissions. The scan orchestrator must preserve state on partial/error/upload failure; tests mock AWS and Docker to exercise those paths without cloud access.

The pinned container can be checked without AWS credentials. `make container-check` also exercises native mutelist matching, global region behavior, report suffixes and report mount permissions with networking disabled; CI runs this contract test:

```bash
IMAGE=$(cat .prowler-image)
docker run --rm --network none "$IMAGE" --version
docker run --rm --network none "$IMAGE" aws --help
make container-check
```

For workflow syntax and expression validation, run `actionlint .github/workflows/*.yml` when installed. Validation of the local-server archive is limited to shell syntax; historical deployments and their claims are not re-executed.

## Before production

Local checks do not prove cloud deployment, IAM authorization, scanner completeness or successful uploads. In a nonproduction account, review and apply the plans, verify the OIDC/STS chain, inspect CloudTrail, perform a full scan, confirm error-free private evidence and state, and test one approved remediation. Exercise an intentionally denied API and denied S3 write to confirm the operational alerts and state preservation. Roll out in small account batches while comparing expected coverage and run duration.

An `enabled: false` sample inventory is valid configuration but cannot run an assessment. This prevents an example account from being accidentally scanned. Active risk acceptances are checked against the current UTC date at both validation and execution time.

## Cross-platform dependency locks

Both enterprise roots record `darwin_arm64` and `linux_amd64` provider hashes. Regenerate signed hashes when changing the provider version:

```bash
terraform -chdir=terraform/security-tooling providers lock -platform=darwin_arm64 -platform=linux_amd64
terraform -chdir=terraform/member-account providers lock -platform=darwin_arm64 -platform=linux_amd64
```

Keep CI initialization read-only so lock drift cannot be silently accepted. Action commits are pinned to verified Node 24 releases. Credential-boundary tests use distinct tooling and member sessions, reject wrong role/account/expiry, and verify the scanner process never inherits host OIDC or other tokens.
