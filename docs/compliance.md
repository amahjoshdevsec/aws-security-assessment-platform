# Compliance mapping and evidence

Prowler maps checks to framework requirements using versioned metadata. Native CSV includes `COMPLIANCE`; OCSF and generated framework exports preserve additional structure. This platform retains the native mapping string in `normalized.json` rather than inventing mappings. The scan does not filter to a single framework, so all available checks are eligible within the approved region scope.

Inspect the exact framework names supported by the pinned image before selecting any reporting filter:

```bash
IMAGE=$(cat .prowler-image)
docker run --rm "$IMAGE" aws --list-compliance
```

Framework IDs and versions change over time. Keep [the pinned release's metadata](https://github.com/prowler-cloud/prowler/tree/5.38.0/prowler/compliance/aws) with the image version in your evidence catalog. See [Prowler reporting](https://docs.prowler.com/user-guide/cli/tutorials/reporting) for native exports.

## Control register

Maintain an organization-owned register with the following mapping:

| Register field | Evidence/source |
| --- | --- |
| Framework and version | Exact framework ID supported by the pinned release |
| Control/requirement ID | Native mapping from the applicable Prowler check |
| Check IDs and scope | Check ID, account, region, resource and scan manifest |
| Control owner | Account inventory owner plus the responsible control team |
| Automated evidence | Native finding, timestamp, image/commit, report path and checksum |
| Exception | Approved decision ID, ticket, compensating control and expiry |
| Manual evidence | Policy, procedure, interview, attestation or test evidence outside scanner coverage |
| Remediation | Change ticket and subsequent unmuted PASS, or reviewed resource retirement |

For example, bucket public-access observations may support a framework's storage-access requirements. The exact control identifiers must come from that release's mapping; do not assume the same check maps identically across CIS, NIST, PCI DSS, ISO 27001, SOC 2 or AWS foundational standards.

## Interpreting coverage

Report FAIL, PASS, muted, MANUAL, not observed, and operational errors separately. Pair any pass-rate metric with the number of expected/enabled accounts, assessed regions, completed scans, check-count drift, and evidence age. Muted failures remain risks. A missing account or denied API is a coverage gap rather than a pass.

A technical assessment does not certify compliance. Organizational controls, sampling, evidence retention, regulatory scope and auditor judgment remain outside this automation. Compliance exports are inputs to a control assessment, not its final conclusion.
