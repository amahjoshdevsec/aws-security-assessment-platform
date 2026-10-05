# Findings lifecycle and remediation validation

A stable finding ID is SHA-256 of the account ID, check ID, observed region and resource UID, serialized as a JSON array. Status and timestamps are excluded so a FAIL and its later PASS correlate. The latest state is separated by the account/region scan scope. Scanner upgrades that rename checks or resources need a reviewed identity migration; disappearance alone cannot close the old record.

## Automated states

| Observation | Lifecycle result |
| --- | --- |
| New unmuted FAIL | `open` |
| FAIL after a resolved finding | `reopened` |
| Muted finding with a prior/current failure | `risk_accepted` |
| Explicit unmuted PASS for a tracked failure | `resolved`, with validation run and time |
| MANUAL for a tracked finding | `needs_review` |
| Tracked finding absent from a successful report | `not_observed`; investigate scope/resource changes |
| Failed/partial scan, missing output or failed upload | Do not advance the previous successful state |

A PASS without a previous failure remains in raw/normalized evidence without creating a lifecycle ticket. Do not count `risk_accepted`, `not_observed`, or `needs_review` as remediated. `last_seen` and `observed_in_latest` distinguish old evidence from the most recent scan. Inspect scan health and freshness before consuming the state.

## Human workflow

The security team triages new findings, checks exploitability/exposure and assigns the inventory owner. The ticket system tracks `triaged`, `in progress`, `awaiting validation`, escalation and change approvals; this repository does not create or synchronize tickets. Record the stable finding ID, resource, severity, framework mappings, evidence S3 path, first seen time, owner and due date. Do not paste sensitive reports into public issues.

Suggested starting service targets (adopt through policy, not implied guarantees): critical within 24 hours, high within 7 days, medium within 30 days, low within 90 days. Severity alone does not determine business risk. Escalate overdue findings and recurring reopenings to accountable owners.

## Validate a remediation

1. Capture the initial FAIL and finding ID from the complete scan manifest and `normalized.json`.
2. Propose a fix through the workload's normal change process. Review blast radius and rollback before deployment. The scanner has no remediation authority and never passes `--fixer`.
3. After deployment, dispatch a new complete scan for the enabled inventory. It must include the same account, region, check and resource.
4. Download that run's `state.json` with an authorized analyst role, then require explicit evidence:

   ```bash
   python3 scripts/findings.py reports/state.json FINDING_SHA256 EXPECTED_RUN_ID
   ```

5. Close the ticket only after this command passes, retaining the before/after evidence, manifest hashes, change ID and verification run. A resource deletion or check retirement requires a separate human disposition supported by inventory and change evidence; it cannot pass this validator.
6. A later FAIL reopens a resolved finding. Review the regression and link it to the original ticket.

When comparing organization totals, deduplicate repeated global findings by stable finding ID while retaining regional observations and timestamps. Do not overwrite a healthy partition's evidence because another account failed.
