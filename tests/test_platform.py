import copy
import csv
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import governance as g
import findings as f
import scan


class PlatformTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.accounts = g.inventory()
        self.account = self.accounts[0]
        self.scope = '111111111111/us-east-1'
        self.previous = {'schema_version': 1, 'scope': self.scope, 'findings': {}}
        self.finding = {'id': 'stable', 'account_id': '111111111111', 'region': 'us-east-1',
                        'check_id': 's3_bucket_public_access', 'resource': 'example',
                        'severity': 'high', 'status': 'FAIL', 'muted': False, 'compliance': 'CIS'}

    def file(self, value, name='input.json'):
        p = self.root / name
        p.write_text(json.dumps(value))
        return p

    def exception(self):
        return g.read_json(g.ROOT / 'config/exception.example.json')['exceptions'][0]

    def state(self, finding, previous=None, run='run-1'):
        return f.reconcile(previous or self.previous, [finding], run, '2026-10-04T03:00:00+00:00', self.scope)

    def test_inventory_disabled_by_default(self):
        with self.assertRaises(ValueError):
            g.matrix(self.accounts)
        self.account['enabled'] = True
        self.assertEqual(len(g.matrix(self.accounts)['include']), 2)

    def test_inventory_scope_validation(self):
        for changes in [{'id': '*'}, {'role_name': 'role; echo x'}, {'enabled': 'true'}, {'regions': ['*']}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                g.inventory(self.file({'accounts': [dict(self.account, **changes)]}))
        with self.assertRaises(ValueError):
            g.inventory(self.file({'accounts': [self.account, self.account]}))

    def test_terraform_member_map_preserves_distinct_role_external_id_pairs(self):
        other = dict(self.account, id='222222222222', role_name='AlternateAudit', external_id='different-external-id')
        members = g.terraform_members([self.account, other])['member_accounts']
        self.assertEqual(members['222222222222'], {'role_name': 'AlternateAudit', 'external_id': 'different-external-id'})
        self.assertEqual(members[self.account['id']]['external_id'], self.account['external_id'])
        self.assertEqual(len(members), 2)

    def test_duplicate_json_keys_rejected(self):
        p = self.root / 'bad.json'
        p.write_text('{"exceptions":[], "exceptions":[]}')
        with self.assertRaises(ValueError):
            g.read_json(p)

    def test_exact_exception_scope(self):
        e = self.exception()
        e['resource'] = 'arn:aws:s3:::website.example.com'
        compiled = g.exceptions(self.file({'exceptions': [e]}), self.accounts, dt.date(2026, 10, 4))
        rule = compiled['Mutelist']['Accounts'][e['account_id']]['Checks']['^s3_bucket_public_access$']
        self.assertEqual(rule['Resources'], ['^arn:aws:s3:::website\\.example\\.com$'])
        self.assertEqual(rule['Regions'], ['^us\\-east\\-1$'])

    def test_governance_rejections(self):
        for change in [{'account_id': '*'}, {'check_id': 's3_.*'}, {'region': '*'}, {'resource': '*'},
                       {'owner': 'security-risk-owner'}, {'expires_on': '2026-10-04'},
                       {'expires_on': '2027-01-01'}, {'approved_on': '2026-10-05'}, {'reason': ''}, {'ticket': 'none'}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                g.exceptions(self.file({'exceptions': [dict(self.exception(), **change)]}), self.accounts, dt.date(2026, 10, 4))

    def test_rules_do_not_create_cross_product(self):
        e = self.exception()
        other = dict(e, id='EX-002', region='us-west-2', resource='different')
        with self.assertRaises(ValueError):
            g.exceptions(self.file({'exceptions': [e, other]}), self.accounts, dt.date(2026, 10, 4))

    def report(self, overrides=None):
        row = {'ACCOUNT_UID': '111111111111', 'CHECK_ID': 's3_bucket_public_access',
               'RESOURCE_UID': 'arn:aws:s3:::example', 'REGION': 'us-east-1', 'STATUS': 'FAIL',
               'MUTED': 'False', 'SERVICE_NAME': 's3', 'SEVERITY': 'high', 'COMPLIANCE': 'CIS-3.0: 1.1'}
        row.update(overrides or {})
        path = self.root / 'prowler.csv'
        with path.open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(row), delimiter=';')
            writer.writeheader()
            writer.writerow(row)
        return path

    def test_normalize_and_stable_identity(self):
        a = f.normalize(self.report(), '111111111111', 'us-east-1')[0]
        b = f.normalize(self.report({'STATUS': 'PASS'}), '111111111111', 'us-east-1')[0]
        self.assertEqual(a['id'], b['id'])
        self.assertEqual(a['compliance'], 'CIS-3.0: 1.1')
        self.assertFalse(a['muted'])

    def test_global_service_region_is_valid_in_regional_scan(self):
        rows = f.normalize(self.report({'SERVICE_NAME': 'cloudfront'}), '111111111111', 'us-west-2')
        self.assertEqual(rows[0]['region'], 'us-east-1')
        with self.assertRaises(ValueError):
            f.normalize(self.report({'SERVICE_NAME': 's3'}), '111111111111', 'us-west-2')

    def test_normalize_rejects_bad_evidence(self):
        for change in [{'ACCOUNT_UID': '222222222222'}, {'REGION': 'us-west-2'}, {'STATUS': 'ERROR'}, {'MUTED': ''}, {'RESOURCE_UID': ''}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                f.normalize(self.report(change), '111111111111', 'us-east-1')
        with self.assertRaises(ValueError):
            f.normalize(self.file([], 'empty.csv'), '111111111111', 'us-east-1')

    def test_lifecycle_fail_pass_reopen(self):
        opened = self.state(self.finding)
        passed = self.state(dict(self.finding, status='PASS'), opened, 'run-2')
        self.assertTrue(f.validate_remediation(passed, 'stable', 'run-2'))
        self.assertFalse(f.validate_remediation(passed, 'stable', 'run-1'))
        reopened = self.state(self.finding, passed, 'run-3')
        self.assertEqual(reopened['findings']['stable']['lifecycle'], 'reopened')
        self.assertNotIn('resolved_at', reopened['findings']['stable'])

    def test_muted_or_absent_never_closes_finding(self):
        opened = self.state(self.finding)
        muted = self.state(dict(self.finding, status='PASS', muted=True), opened)
        self.assertFalse(f.validate_remediation(muted, 'stable', 'run-1'))
        self.assertEqual(muted['findings']['stable']['lifecycle'], 'risk_accepted')
        missing = f.reconcile(opened, [], 'run-2', 'later', self.scope)
        self.assertEqual(missing['findings']['stable']['lifecycle'], 'not_observed')
        self.assertFalse(f.validate_remediation(missing, 'stable', 'run-2'))
        self.assertEqual(opened['findings']['stable']['lifecycle'], 'open')

    def test_manual_and_expired_acceptance(self):
        accepted = self.state(dict(self.finding, muted=True))
        active = self.state(self.finding, accepted)
        self.assertEqual(active['findings']['stable']['lifecycle'], 'open')
        manual = self.state(dict(self.finding, status='MANUAL'), active)
        self.assertEqual(manual['findings']['stable']['lifecycle'], 'needs_review')
        with self.assertRaises(ValueError):
            f.reconcile(dict(self.previous, scope='other'), [], 'run', 'now', self.scope)

    def test_health_separates_findings_from_errors(self):
        for name in ('prowler.csv', 'prowler.ocsf.json', 'prowler.html'):
            (self.root / name).write_text('[{}]' if name.endswith('.json') else 'data')
        (self.root / 'errors.log').write_text('')
        scan.healthy_output(self.root, 3)
        with self.assertRaises(ValueError):
            scan.healthy_output(self.root, 1)
        (self.root / 'errors.log').write_text('AccessDenied')
        with self.assertRaises(ValueError):
            scan.healthy_output(self.root, 0)

    def test_state_download_only_initializes_missing_key(self):
        with patch('scan.run', return_value=subprocess.CompletedProcess([], 0, '{"Contents": []}', '')):
            self.assertEqual(scan.previous_state('bucket', 'key', self.root / 'state', self.scope), self.previous)
        with patch('scan.run', side_effect=subprocess.CalledProcessError(1, ['aws'])), self.assertRaises(subprocess.CalledProcessError):
            scan.previous_state('bucket', 'key', self.root / 'state', self.scope)
        listing = subprocess.CompletedProcess([], 0, '{"Contents": [{"Key": "key"}]}', '')
        with patch('scan.run', side_effect=[listing, subprocess.CalledProcessError(1, ['aws'])]), self.assertRaises(subprocess.CalledProcessError):
            scan.previous_state('bucket', 'key', self.root / 'state', self.scope)

    def test_command_never_serializes_secrets_or_remediates(self):
        with patch.dict(os.environ, {'AWS_ACCESS_KEY_ID': 'SECRET-VALUE'}):
            command = scan.scan_command(self.account, 'us-east-1', 'image', self.root, self.root / 'mutelist', 'run-1')
        self.assertNotIn('SECRET-VALUE', command)
        self.assertIn('--scan-unused-services', command)
        self.assertNotIn('--role', command)
        self.assertNotIn('--external-id', command)
        self.assertNotIn('--fixer', command)

    def test_additions_policy_has_no_write_actions(self):
        policy = g.read_json(g.ROOT / 'terraform/policies/prowler-read-additions.json')
        for statement in policy['Statement']:
            for action in statement['Action']:
                self.assertRegex(action.split(':')[1], r'^(Get|List|Describe|BatchGet|Search|Filter|GET)')


if __name__ == '__main__':
    unittest.main()
