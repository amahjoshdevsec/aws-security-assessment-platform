"""Exercise scan publication ordering with mocked Docker/AWS, never real credentials."""
import datetime as dt
import csv
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import governance
import scan


class OrchestratorTests(unittest.TestCase):
    def exercise(self, mode):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'config').mkdir()
            accounts = governance.inventory()
            accounts[0]['enabled'] = True
            for name, content in [('accounts.json', {'accounts': accounts}), ('exceptions.json', {'exceptions': []})]:
                (root / 'config' / name).write_text(json.dumps(content))
            (root / '.prowler-version').write_text('5.38.0')
            (root / '.prowler-image').write_text('prowlercloud/prowler@sha256:' + 'a' * 64)
            output = root / 'reports/111111111111/us-east-1/run-1'
            calls = []

            def external(command, **kwargs):
                calls.append(command)
                if command[:3] == ['aws', 's3api', 'list-objects-v2']:
                    if mode == 'state_denied':
                        raise subprocess.CalledProcessError(1, command)
                    return subprocess.CompletedProcess(command, 0, '{"Contents": []}', '')
                if command[:3] == ['aws', 'sts', 'assume-role']:
                    self.assertNotIn('env', kwargs)  # Tooling session remains on the host.
                    expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()
                    response = {'Credentials': {'AccessKeyId': 'MEMBER-KEY', 'SecretAccessKey': 'MEMBER-SECRET', 'SessionToken': 'MEMBER-TOKEN', 'Expiration': expiry},
                                'AssumedRoleUser': {'Arn': 'arn:aws:sts::111111111111:assumed-role/ProwlerAudit/prowler-run-1'}}
                    return subprocess.CompletedProcess(command, 0, json.dumps(response), '')
                if command[:3] == ['aws', 'sts', 'get-caller-identity']:
                    self.assertEqual(kwargs['env']['AWS_ACCESS_KEY_ID'], 'MEMBER-KEY')
                    identity = {'Account': '111111111111', 'Arn': 'arn:aws:sts::111111111111:assumed-role/ProwlerAudit/prowler-run-1'}
                    return subprocess.CompletedProcess(command, 0, json.dumps(identity), '')
                if '--version' in command:
                    return subprocess.CompletedProcess(command, 0, 'Prowler 5.38.0', '')
                if command[:3] == ['docker', 'run', '--rm'] and '--filter-region' in command:
                    self.assertEqual(kwargs['env']['AWS_ACCESS_KEY_ID'], 'MEMBER-KEY')
                    self.assertNotIn('--role', command)
                    self.assertNotIn('ACTIONS_ID_TOKEN_REQUEST_TOKEN', kwargs['env'])
                    if mode == 'timeout':
                        raise subprocess.TimeoutExpired(command, 2400)
                    (output / 'errors.log').write_text('AccessDenied' if mode == 'scan_error' else '')
                    (output / 'prowler.html').write_text('<html>private evidence</html>')
                    (output / 'prowler.ocsf.json').write_text('[{}]')
                    row = {'ACCOUNT_UID': '111111111111', 'CHECK_ID': 's3_bucket_public_access',
                           'RESOURCE_UID': 'arn:aws:s3:::example', 'REGION': 'us-east-1', 'STATUS': 'FAIL',
                           'MUTED': 'False', 'SERVICE_NAME': 's3', 'SEVERITY': 'high', 'COMPLIANCE': 'CIS'}
                    with (output / 'prowler.csv').open('w') as file:
                        w = csv.DictWriter(file, fieldnames=list(row), delimiter=';')
                        w.writeheader()
                        w.writerow(row)
                    return subprocess.CompletedProcess(command, 3, '', '')
                if command[:3] == ['aws', 's3', 'cp']:
                    self.assertNotIn('env', kwargs)
                    self.assertEqual(os.environ['AWS_ACCESS_KEY_ID'], 'TOOLING-KEY')
                if command[:3] == ['aws', 's3', 'cp'] and mode == 'upload_error':
                    raise subprocess.CalledProcessError(1, command)
                return subprocess.CompletedProcess(command, 0, '', '')

            env = {'REPORT_BUCKET': 'test-reports', 'REPORT_KMS_KEY_ARN': 'arn:aws:kms:us-east-1:222222222222:key/test-key',
                   'AWS_ACCESS_KEY_ID': 'TOOLING-KEY', 'AWS_SECRET_ACCESS_KEY': 'TOOLING-SECRET', 'AWS_SESSION_TOKEN': 'TOOLING-TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'OIDC-SECRET'}
            with patch('scan.ROOT', root), patch('scan.inventory', return_value=accounts), patch('scan.subprocess.run', side_effect=external), patch.dict(os.environ, env), patch.object(sys, 'argv', ['scan.py', '--account', '111111111111', '--region', 'us-east-1', '--run-id', 'run-1']):
                if mode == 'success':
                    scan.main()
                else:
                    with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                        scan.main()
            manifest = json.loads((output / 'manifest.json').read_text())
            uploads = [c for c in calls if c[:3] == ['aws', 's3', 'cp']]
            state_updates = [c for c in uploads if c[4].endswith('/latest.json')]
            if mode == 'success':
                self.assertEqual(manifest['status'], 'complete')
                self.assertEqual(manifest['active_failures'], 1)
                self.assertEqual(len(state_updates), 1)
                self.assertEqual(uploads[-1], state_updates[0])
                self.assertTrue(uploads[-2][4].endswith('/manifest.json'))
            else:
                self.assertEqual(state_updates, [])
                if mode != 'upload_error':
                    self.assertEqual(manifest['status'], 'failed')
            self.assertTrue(any(c[:3] == ['docker', 'rm', '-f'] for c in calls))
            for command in uploads:
                self.assertIn('--sse-kms-key-id', command)
                self.assertIn('aws:kms', command)

    def test_success_publishes_state_after_evidence(self):
        self.exercise('success')

    def test_logged_error_preserves_state(self):
        self.exercise('scan_error')

    def test_state_access_failure_preserves_history(self):
        self.exercise('state_denied')

    def test_upload_failure_does_not_advance_state(self):
        self.exercise('upload_error')

    def test_timeout_cleans_up_and_preserves_state(self):
        self.exercise('timeout')
