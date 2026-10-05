# Operations and centralized reporting

## Daily ownership

Security operations owns assessment completion and triage. Platform engineering owns OIDC, role onboarding, Terraform drift and runner health. Workload teams own fixes. Risk owners approve time-limited exceptions. Compliance teams own the control register and retention decisions.

The workflow schedules daily at 03:23 UTC on the repository default branch, which must remain `main` unless the workflow and protection configuration are updated together. GitHub schedules can be delayed, skipped under load, or disabled for inactivity in public repositories. Manual dispatch uses the same inventory and protections. A whole-workflow concurrency group serializes state writers, while `fail-fast: false` allows healthy accounts to complete when another fails. GitHub concurrency is not a durable queue: new runs may replace a pending run.

## Reporting contract

Raw reports, decisions, logs, a normalized finding set, lifecycle snapshot, and manifest live under `reports/ACCOUNT/REGION/RUN_ID/`. The manifest is uploaded last and includes per-file SHA-256 hashes. Consume a run only after a complete manifest exists and its checksums agree. The live lifecycle pointer is updated only after evidence upload succeeds. A pointer-upload failure leaves complete historical evidence but fails the job; the next scan reconciles from the older pointer.

S3 uploads explicitly select SSE-KMS and the exact report key. Analysts need both S3 and KMS access; Terraform can attach those grants to existing same-account roles. Retrieve HTML through authenticated download; this bucket is not a public website. Serve any future dashboard through an authenticated service. Evidence from a public source-code repository is still private.

No GitHub artifacts are created because repository readers should not automatically receive sensitive security reports. The Actions console shows scope, operational status and counts; raw Prowler stdout/errors stay in private evidence. Provision organization log retention and CloudTrail data events separately. Account IDs and approved scope in this public repository should not include confidential organization naming conventions.

## Failure responses

| Symptom | Response |
| --- | --- |
| OIDC denied | Check exact repo/environment subject, audience, environment branch restriction and tooling account ID |
| AssumeRole denied | Check exact role path, caller allowlist, member trust, external ID, SCP/boundary and IAM propagation |
| AccessDenied inside scan | Inspect private `errors.log`; review permission gap; do not broaden to AdministratorAccess |
| Timeout or throttling | Keep regional partitioning, reduce `max-parallel`, review API limits; do not exceed role-chain limits |
| Empty/malformed report | Treat as incomplete; inspect image version, report parser and private scan log |
| Expired exception | Remove or obtain a fresh approval via review; rerun validation and scanning |
| S3/KMS upload denied | Verify exact key ARN, headers, tooling region, IAM and key policy; latest state will not advance |
| State read denied/corrupt | Fix access or restore a verified prior S3 version; never initialize empty history to bypass failure |
| Job cancelled/runner lost | Evidence may be absent/partial; no complete manifest means no usable new scan; rerun |

Errors logged by Prowler at ERROR/CRITICAL level block success even if the CLI returns 0 or 3. This deliberately favors incomplete coverage visibility over green jobs. Not all missing coverage produces errors: reconcile expected inventory and resource/check counts too.

## Freshness and monitoring

A successful workflow means the scan operated successfully, not that all controls passed. Findings are triaged through their lifecycle. Monitor both the aggregate workflow result and one fresh complete manifest for every enabled account/region. Set an organization alert for evidence older than 26 hours and for critical/high backlog growth. Wire these to your existing monitoring or ticket platform; this repository does not deploy an alerting integration. GitHub notifications alone do not detect a schedule that never ran.

## Recovery and retention

Workflow concurrency prevents competing writers in this repository. Do not invoke local scans against the same prefix concurrently. S3 versioning preserves previous state snapshots; to recover, stop new writers, choose the last trusted complete scan, verify checksums and scope, restore its `state.json` as `latest.json` with required encryption headers, document the recovery, then run a canary. Never restore a failed or partial scan as authoritative.

Retention defaults to 365 days for report objects and noncurrent state versions. Review it with evidence owners. Versioning and deletion protection do not supply WORM guarantees. Add Object Lock and separate administrative custody if required; also decide on cross-region backup, key recovery, CloudTrail data events and access logging. KMS destruction invalidates evidence regardless of bucket retention.

## Upgrades

Review the Prowler release, resolve the official image tag to an immutable digest, update `.prowler-version` and `.prowler-image` together, compare permissions, CLI schema, checks and compliance mappings, then run all tests and a nonproduction canary. Verify that the native non-root UID, report-mount access, native output names and governed mutelists still work in the actual image. Provider/action upgrades follow reviewed dependency PRs. Never automatically replace the production digest with `latest`.
