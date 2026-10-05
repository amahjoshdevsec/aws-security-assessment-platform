"""Run inside the pinned Prowler image with /project mounted read-only; no AWS/network."""
import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
sys.path.insert(0, '/project/scripts')
import governance
from prowler.providers.aws.lib.mutelist.mutelist import AWSMutelist as Mutelist
from prowler.config.config import json_ocsf_file_suffix
from prowler.providers.aws.aws_provider import AwsProvider

accounts = governance.inventory()
example = governance.read_json('/project/config/exception.example.json')['exceptions'][0]
compiled = governance.exceptions('/project/config/exception.example.json', accounts, dt.date(2026, 10, 4))
with tempfile.TemporaryDirectory() as tmp:
    path = Path(tmp) / 'mutelist.yaml'
    path.write_text(json.dumps(compiled))
    native = Mutelist(mutelist_path=str(path))
    assert native.is_muted(example['account_id'], example['check_id'], example['region'], example['resource'], '')
    assert not native.is_muted(example['account_id'], example['check_id'], example['region'], example['resource'] + '-backup', '')
    assert not native.is_muted('222222222222', example['check_id'], example['region'], example['resource'], '')
    assert not native.is_muted(example['account_id'], example['check_id'], 'us-west-2', example['resource'], '')
    path.write_text('{"Mutelist": {"Accounts": {}}}')
    empty = Mutelist(mutelist_path=str(path))
    assert not empty.is_muted(example['account_id'], example['check_id'], example['region'], example['resource'], '')
assert json_ocsf_file_suffix == '.ocsf.json'
# Directly exercise the pure global-region logic without constructing an AWS provider.
class Scope:
    def get_global_region(self):
        return 'us-east-1'
assert AwsProvider.get_default_region(Scope(), 'cloudfront', global_service=True) == 'us-east-1'
print('Pinned container contract: native mutelist matching, empty mutelist, OCSF suffix and global region passed')

probe = Path('/reports/write-probe.txt')
probe.write_text('Native UID can write the report mount')
assert probe.read_text() == 'Native UID can write the report mount'
print('Pinned container contract: report mount is writable by native non-root UID')
