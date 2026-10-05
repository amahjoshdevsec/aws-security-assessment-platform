# Architecture and trust boundaries

The security tooling account owns `ProwlerGitHubRunner`, the report bucket and encryption key. Each workload account owns `ProwlerAudit`. No organization management-account permissions are needed by the scanner. The same member role can be deployed in the tooling account if that account itself needs assessment.

## Authentication sequence

1. A reviewed workflow runs on `main` and enters the protected `security-scans` environment.
2. GitHub requests an OIDC token with audience `sts.amazonaws.com`. STS checks the exact `repo:amahjoshdevsec/aws-security-assessment-platform:environment:security-scans` subject.
3. The configure-credentials action obtains a one-hour tooling role session. Its permissions include only explicit member role assumptions, report/state object access, scoped bucket listing, and S3-mediated use of the report KMS key.
4. The host uses the tooling session to assume the inventoried `/security/ROLE_NAME` with that account’s external ID. It checks the returned STS role ARN, expiry and `GetCallerIdentity` before launching Docker. Both the caller policy and member trust must permit the request.
5. The host passes only the short-lived member credentials into Docker through an explicit subprocess environment. Prowler receives no tooling session, GitHub token, OIDC request token, credential file or Docker socket, and does not perform role assumption. The host retains tooling credentials for state retrieval and encrypted evidence publication.
6. Every run records the Git commit, pinned image digest, workflow URL and scan scope. CloudTrail role session names include the GitHub run ID for correlation.

The environment's allowed deployment branch setting is essential: an OIDC environment subject does not encode the branch. A compromised trusted workflow has the tooling role's full authority, including member read access and report writes. CODEOWNERS without required reviews is advisory only. Avoid pull-request-triggered credentialed scans and `pull_request_target` execution of untrusted changes.

## Permission and isolation choices

The member attaches AWS `SecurityAudit`, `job-function/ViewOnlyAccess`, and a locally reviewed additions policy. These are broad configuration read permissions, not a guarantee that sensitive content is inaccessible. AWS-managed policies may change independently of this repository. Review changes, SCP impact and denied API calls. The optional permissions boundary must be created and maintained by your platform team; it does not grant missing permissions.

The member role has no S3 report access. The runner has no `iam:*`, no arbitrary role wildcard, and no delete-object permissions. The S3 bucket requires TLS and explicit SSE-KMS headers using its exact key. Existing same-account reader roles can receive report read permissions through Terraform.

Each account/region runs independently, with at most four parallel jobs. Workflow-level concurrency serializes scheduled and manual scans to prevent competing state updates. Do not run additional local writers or parallel workflows against the same state prefix. A single run's local work directory cannot be reused.

## Coverage boundaries

The region allowlist is explicit; global resources can be repeated across regional scans. State is partitioned by scan region, so an organization dashboard must deduplicate global observations by finding ID and retain the scope of each observation. Account offboarding requires removing inventory and role allowlist entries, revoking member trust, then retaining evidence according to policy.

Commercial AWS only is supported. GovCloud and China require different identity endpoints, partitions, DNS names, action audience configuration and testing. A successful local Terraform validation is not evidence of those deployments working.

## Credential isolation decision

The initial implementation let Prowler assume the member role itself, so the image inherited a tooling session that could also access central evidence. Host-side role assumption reduces that credential blast radius: even a compromised scanner image receives only the member audit session. Regression tests verify distinct tooling/member credentials and that denied assumption never falls back to tooling credentials. A container shares a host kernel; this boundary does not defend against a container escape or a compromised runner host. Use ephemeral isolated runners and review image provenance.

Member sessions are fixed-duration credentials and are not refreshed inside Prowler. The 40-minute scan budget fits within the validated one-hour STS session. Pull/version checks happen before assumption. The toolchain must not persist STS responses, environment files or secret values in manifests/logs.
