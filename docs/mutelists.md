# Governed mutelists

A muted failure is accepted risk, not a passing control. The active source of truth is [config/exceptions.json](../config/exceptions.json), initially empty. The [example](../config/exception.example.json) is illustrative and is never loaded by the scanner.

Each acceptance records an exact account, check, region and resource plus owner, independent approver, approval ticket, reason, compensating control, approval date and exclusive UTC expiry date. The maximum lifetime is 90 days. The ticket must contain supporting evidence, business impact, the authorized risk owner's approval, and an explicit condition that would invalidate acceptance. Metadata validation cannot prove a human approved a ticket: enforce CODEOWNER review and protected branches.

## Workflow

1. Investigate the original FAIL and verify it is not a permissions or coverage problem.
2. Prefer remediation. If risk acceptance is justified, obtain a separate risk owner's approval and evidence in the organization's ticket system.
3. Add a scoped record using the example schema; owner and approver must differ. Run `make test mutelist`.
4. Submit the record through the protected review process. Do not edit generated `build/mutelist.yaml` or mutate the Prowler UI.
5. A new scan compiles the approved records into Prowler's native mutelist syntax and stores both the source decisions and the compiled list with its reports.
6. Review acceptances weekly and before expiry. Remove or renew through a new approval. On removal, a continuing failure becomes open again in the next successful scan.

Wildcard accounts/checks/regions/resources and duplicate IDs are rejected. Resources are escaped and anchored as regular expressions, preventing `public-site` from also muting `public-site-backup`. This baseline allows one exception per account/check, avoiding accidental region/resource cross-products; extend the data model with tests before allowing more complex patterns.

An expired/future-dated decision fails validation and the scan inventory job. This deliberately requires governance repair before another scan and therefore needs an operational alert for stale evidence. Historical acceptances are retained in S3 run directories and Git history. They are never retroactively applied to old reports.

Prowler retains the original CSV `STATUS` and marks `MUTED`; OCSF uses suppression semantics. The lifecycle code uses CSV so it can distinguish an accepted failure from remediation. See [Prowler mutelist behavior](https://docs.prowler.com/user-guide/cli/tutorials/mutelist).
