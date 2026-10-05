import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import scan


class CredentialIsolationTests(unittest.TestCase):
    account = {'id': '111111111111', 'role_name': 'CustomAudit', 'external_id': 'account-one'}
    arn = 'arn:aws:sts::111111111111:assumed-role/CustomAudit/prowler-test'

    def responses(self, *, arn=None, account=None, minutes=60):
        expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=minutes)).isoformat()
        session = {'Credentials': {'AccessKeyId': 'MEMBER', 'SecretAccessKey': 'MEMBER-SECRET',
                                  'SessionToken': 'MEMBER-TOKEN', 'Expiration': expiry},
                   'AssumedRoleUser': {'Arn': arn or self.arn}}
        identity = {'Account': account or self.account['id'], 'Arn': self.arn}
        return [subprocess.CompletedProcess([], 0, json.dumps(x), '') for x in [session, identity]]

    def test_member_only_environment_and_host_unchanged(self):
        host = {'AWS_ACCESS_KEY_ID': 'TOOLING', 'AWS_SECRET_ACCESS_KEY': 'TOOLING-SECRET',
                'AWS_SESSION_TOKEN': 'TOOLING-TOKEN', 'AWS_PROFILE': 'admin',
                'AWS_WEB_IDENTITY_TOKEN_FILE': '/secret/token', 'GITHUB_TOKEN': 'GH-SECRET',
                'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'OIDC-SECRET', 'ARBITRARY_SECRET': 'SECRET'}
        with patch.dict(os.environ, host), patch('scan.run', side_effect=self.responses()) as runner:
            member = scan.member_environment(self.account, 'us-west-2', 'test')
            self.assertEqual(member['AWS_ACCESS_KEY_ID'], 'MEMBER')
            self.assertEqual(member['AWS_REGION'], 'us-west-2')
            self.assertEqual(os.environ['AWS_ACCESS_KEY_ID'], 'TOOLING')
            for key in host.keys() - {'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN'}:
                self.assertNotIn(key, member)
            self.assertNotIn('TOOLING-SECRET', member.values())
            self.assertIn('arn:aws:iam::111111111111:role/security/CustomAudit', runner.call_args_list[0].args[0])
            self.assertIn('account-one', runner.call_args_list[0].args[0])
            self.assertEqual(runner.call_args_list[1].kwargs['env']['AWS_ACCESS_KEY_ID'], 'MEMBER')

    def test_reject_wrong_role_account_and_short_session(self):
        for kwargs in [{'arn': 'arn:aws:sts::222222222222:assumed-role/Other/test'},
                       {'account': '222222222222'}, {'minutes': 30}]:
            with self.subTest(kwargs=kwargs), patch('scan.run', side_effect=self.responses(**kwargs)), self.assertRaises(ValueError):
                scan.member_environment(self.account, 'us-east-1', 'test')

    def test_assume_role_denial_does_not_fall_back_to_tooling(self):
        with patch('scan.run', side_effect=subprocess.CalledProcessError(1, ['aws'])) as runner, self.assertRaises(subprocess.CalledProcessError):
            scan.member_environment(self.account, 'us-east-1', 'test')
        self.assertEqual(runner.call_count, 1)
