#!/usr/bin/env python3
"""Normalize Prowler 5.38 CSV and maintain an evidence-based findings lifecycle."""
import argparse
import copy
import csv
import hashlib
import json
from pathlib import Path
from governance import require, read_json


def normalize(path, account, region):
    with Path(path).open(newline='') as stream:
        reader = csv.DictReader(stream, delimiter=';')
        required = {'ACCOUNT_UID', 'CHECK_ID', 'RESOURCE_UID', 'REGION', 'STATUS', 'MUTED', 'SEVERITY', 'COMPLIANCE', 'SERVICE_NAME'}
        require(required <= set(reader.fieldnames or []), 'Missing Prowler CSV columns')
        findings = []
        seen = set()
        for row in reader:
            require(row['ACCOUNT_UID'] == account, 'Report contains an unexpected account')
            # Global checks are retained but each partition tracks its own observations.
            global_service = row['SERVICE_NAME'] in {'cloudfront', 'shield', 'fms', 'route53'}
            require(row['REGION'] in (region, 'global') or (global_service and row['REGION'] == 'us-east-1'),
                    'Report contains an unexpected region')
            require(row['STATUS'] in ('PASS', 'FAIL', 'MANUAL'), 'Unknown status or incomplete scan')
            require(row['MUTED'].lower() in ('true', 'false'), 'Invalid muted value')
            require(row['CHECK_ID'] and row['RESOURCE_UID'], 'Missing finding identity')
            identity = [account, row['CHECK_ID'], row['REGION'], row['RESOURCE_UID']]
            uid = hashlib.sha256(json.dumps(identity, separators=(',', ':')).encode()).hexdigest()
            require(uid not in seen, 'Duplicate finding identity')
            seen.add(uid)
            findings.append({'id': uid, 'account_id': account, 'check_id': row['CHECK_ID'],
                             'region': row['REGION'], 'resource': row['RESOURCE_UID'],
                             'status': row['STATUS'], 'muted': row['MUTED'].lower() == 'true',
                             'severity': row['SEVERITY'], 'compliance': row['COMPLIANCE']})
    require(findings, 'Empty report is not a successful scan')
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
