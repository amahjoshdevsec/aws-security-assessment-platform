#!/usr/bin/env python3
"""Normalize Prowler 5.38 CSV and maintain an evidence-based findings lifecycle."""
import argparse
import copy
import csv
import hashlib
import json
from pathlib import Path
from governance import require, read_json


def normalize(
    path,
    account,
    region,
    excluded_services=(),
    excluded_kms_resources=(),
):
    with Path(path).open(newline="") as stream:
        reader = csv.DictReader(stream, delimiter=";")

        required = {
            "ACCOUNT_UID",
            "CHECK_ID",
            "RESOURCE_UID",
            "REGION",
            "STATUS",
            "MUTED",
            "SEVERITY",
            "COMPLIANCE",
            "SERVICE_NAME",
        }
        require(
            required <= set(reader.fieldnames or []),
            "Missing Prowler CSV columns",
        )

        findings = []
        seen = set()

        for row in reader:
            require(
                row["ACCOUNT_UID"] == account,
                "Report contains an unexpected account",
            )

            # Global checks are retained, but each scan partition tracks
            # its own observations.
            global_service = row["SERVICE_NAME"] in {
                "cloudfront",
                "shield",
                "fms",
                "route53",
            }

            # This specific account-wide discovery check can reference an
            # index in another region. Retain its reported region and verify
            # that the resource ARN matches that region and this account.
            resource_explorer_observation = (
                row["SERVICE_NAME"] == "resourceexplorer2"
                and row["CHECK_ID"] == "resourceexplorer2_indexes_found"
                and row["REGION"] not in ("", "global")
                and row["RESOURCE_UID"].startswith(
                    f"arn:aws:resource-explorer-2:"
                    f"{row['REGION']}:{account}:index/"
                )
                and bool(row["RESOURCE_UID"].rsplit("/", 1)[-1])
            )

            require(
                row["REGION"] in (region, "global")
                or (
                    global_service
                    and row["REGION"] == "us-east-1"
                )
                or resource_explorer_observation,
                "Report contains an unexpected region",
            )

            if row["SERVICE_NAME"] in excluded_services:
                continue

            if (
                row["SERVICE_NAME"] == "kms"
                and row["RESOURCE_UID"] in excluded_kms_resources
            ):
                continue

            require(
                row["STATUS"] in ("PASS", "FAIL", "MANUAL"),
                "Unknown status or incomplete scan",
            )
            require(
                row["MUTED"].lower() in ("true", "false"),
                "Invalid muted value",
            )
            require(
                row["CHECK_ID"] and row["RESOURCE_UID"],
                "Missing finding identity",
            )

            identity = [
                account,
                row["CHECK_ID"],
                row["REGION"],
                row["RESOURCE_UID"],
            ]

            # These checks can produce multiple findings for the same
            # parent ARN. RESOURCE_NAME distinguishes the individual
            # policies or attachments.
            if (
                row["CHECK_ID"].startswith("iam_inline_policy_")
                or row["CHECK_ID"]
                == "iam_policy_attached_only_to_group_or_roles"
            ):
                policy_resource = row.get("RESOURCE_NAME", "").strip()
                require(
                    policy_resource,
                    "Missing IAM policy resource name",
                )
                identity.append(policy_resource)

            # Status is deliberately excluded so FAIL -> PASS retains
            # the same identity for remediation validation.
            uid = hashlib.sha256(
                json.dumps(
                    identity,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()

            require(uid not in seen, "Duplicate finding identity")
            seen.add(uid)

            findings.append(
                {
                    "id": uid,
                    "account_id": account,
                    "check_id": row["CHECK_ID"],
                    "region": row["REGION"],
                    "resource": row["RESOURCE_UID"],
                    "status": row["STATUS"],
                    "muted": row["MUTED"].lower() == "true",
                    "severity": row["SEVERITY"],
                    "compliance": row["COMPLIANCE"],
                }
            )

    require(findings, "Empty report is not a successful scan")
    return findings


def reconcile(previous, findings, run_id, timestamp, scope):
    require(previous.get('schema_version') == 1, 'Unsupported lifecycle schema')
    require(previous.get('scope') == scope, 'Lifecycle account/region scope mismatch')
    states = copy.deepcopy(previous.get('findings', {}))
    observed = set()
    for f in findings:
        uid = f['id']
        observed.add(uid)
        old = states.get(uid)
        # A clean resource without previous failure does not need a lifecycle ticket.
        if old is None and f['status'] != 'FAIL':
            continue
        state = old or {'first_seen': timestamp, 'first_run': run_id}
        prior_status = state.get('lifecycle')
        state.update(f)
        state.update(last_seen=timestamp, last_run=run_id, observed_in_latest=True)
        if f['muted']:
            state['lifecycle'] = 'risk_accepted'
            state.pop('resolved_at', None)
        elif f['status'] == 'PASS':
            state['lifecycle'] = 'resolved'
            state.setdefault('resolved_at', timestamp)
            state['validation_run'] = run_id
        elif f['status'] == 'FAIL':
            state['lifecycle'] = 'reopened' if prior_status in ('resolved', 'reopened') else 'open'
            state.pop('resolved_at', None)
            state.pop('validation_run', None)
        else:
            state['lifecycle'] = 'needs_review'
            state.pop('resolved_at', None)
            state.pop('validation_run', None)
        states[uid] = state
    for uid, state in states.items():
        if uid not in observed:
            state['observed_in_latest'] = False
            # Absence is a coverage gap. Never infer remediation from disappearance.
            state['lifecycle'] = 'not_observed'
            state.pop('resolved_at', None)
            state.pop('validation_run', None)
    return {'schema_version': 1, 'scope': scope, 'run_id': run_id,
            'updated_at': timestamp, 'findings': states}


def validate_remediation(state, finding_id, expected_run):
    f = state['findings'].get(finding_id)
    return bool(f and state['run_id'] == expected_run and f['lifecycle'] == 'resolved'
                and f['status'] == 'PASS' and not f['muted']
                and f['observed_in_latest'] and f.get('validation_run') == expected_run)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Require an explicit PASS in a specified remediation scan')
    parser.add_argument('state', type=Path)
    parser.add_argument('finding_id')
    parser.add_argument('run_id')
    args = parser.parse_args()
    require(validate_remediation(read_json(args.state), args.finding_id, args.run_id),
            'Remediation is not validated by an unmuted PASS in the requested run')
    print('Remediation validated')
