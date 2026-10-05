#!/usr/bin/env python3
"""Validate account scope and compile exact, time-bounded Prowler exceptions."""
import argparse
import datetime as dt
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"Duplicate JSON key: {key}")
            result[key] = value
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=unique)


def inventory(path=ROOT / 'config/accounts.json'):
    accounts = read_json(path)['accounts']
    require(isinstance(accounts, list) and accounts, 'Inventory must contain accounts')
    seen = set()
    for a in accounts:
        require(set(a) == {'id', 'name', 'owner', 'environment', 'role_name', 'external_id', 'regions', 'enabled'}, 'Unexpected inventory fields')
        require(isinstance(a['id'], str) and re.fullmatch(r'[0-9]{12}', a['id']), 'Invalid account ID')
        require(a['id'] not in seen, 'Duplicate account ID')
        seen.add(a['id'])
        require(type(a['enabled']) is bool, 'enabled must be boolean')
        for key in ('name', 'owner', 'environment'):
            require(isinstance(a[key], str) and a[key].strip(), f'Missing {key}')
        require(re.fullmatch(r'[A-Za-z0-9+=,.@_-]{1,64}', a['role_name']), 'Invalid role name')
        require(re.fullmatch(r'[A-Za-z0-9+=,.@:/_-]{2,1224}', a['external_id']), 'Invalid external ID')
        require(isinstance(a['regions'], list) and a['regions'], 'Explicit regions required')
        require(len(set(a['regions'])) == len(a['regions']), 'Duplicate region')
        require(all(re.fullmatch(r'(?:us|eu|ap|ca|sa|me|af|il|mx)-[a-z]+-\d', x) for x in a['regions']), 'Invalid commercial AWS region')
    return accounts


def matrix(accounts):
    rows = [{'account': a['id'], 'region': region} for a in accounts if a['enabled'] for region in a['regions']]
    require(rows, 'No enabled accounts: configure and approve config/accounts.json first')
    require(len(rows) <= 256, 'GitHub matrix limit exceeded; split inventories')
    return {'include': rows}


def exceptions(path, accounts, today=None):
    today = today or dt.datetime.now(dt.timezone.utc).date()
    entries = read_json(path)['exceptions']
    require(isinstance(entries, list), 'exceptions must be a list')
    inventory_by_id = {a['id']: a for a in accounts}
    ids, scopes = set(), set()
    compiled = {'Mutelist': {'Accounts': {}}}
    for e in entries:
        required = {'id', 'account_id', 'check_id', 'region', 'resource', 'owner', 'approved_by', 'ticket', 'reason', 'compensating_control', 'approved_on', 'expires_on'}
        require(set(e) == required, 'Exception has missing or unexpected fields')
        require(all(isinstance(v, str) and v.strip() for v in e.values()), 'Exception fields must be nonempty strings')
        require(e['id'] not in ids, 'Duplicate exception ID')
        ids.add(e['id'])
        require(e['owner'] != e['approved_by'], 'Exception approval must be independent of owner')
        require(e['ticket'].startswith('https://'), 'HTTPS approval ticket required')
        require(e['account_id'] in inventory_by_id, 'Exception account is not inventoried')
        require(e['region'] in inventory_by_id[e['account_id']]['regions'], 'Exception region is not inventoried')
        require(re.fullmatch(r'[a-z][a-z0-9_]+', e['check_id']), 'Exact check ID required')
        require('*' not in e['resource'] and e['resource'] != '.', 'Exact resource required')
        approved, expires = dt.date.fromisoformat(e['approved_on']), dt.date.fromisoformat(e['expires_on'])
        require(approved <= today < expires, 'Exception is future-dated or expired (expiry is exclusive, UTC)')
        require(0 < (expires - approved).days <= 90, 'Exception maximum lifetime is 90 days')
        # One rule per account/check prevents cross products of unrelated resources and regions.
        scope = (e['account_id'], e['check_id'])
        require(scope not in scopes, 'Only one exception per account/check; consolidate or use separate check governance')
        scopes.add(scope)
        checks = compiled['Mutelist']['Accounts'].setdefault(e['account_id'], {'Checks': {}})['Checks']
        checks['^' + e['check_id'] + '$'] = {
            'Regions': ['^' + re.escape(e['region']) + '$'],
            'Resources': ['^' + re.escape(e['resource']) + '$'],
            'Description': f"{e['id']} | {e['ticket']} | owner={e['owner']} | approved_by={e['approved_by']} | expires={e['expires_on']} | {e['reason']} | {e['compensating_control']}",
        }
    return compiled


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['validate', 'matrix', 'compile'])
    parser.add_argument('--output', type=Path, default=ROOT / 'build/mutelist.yaml')
    args = parser.parse_args()
    accounts = inventory()
    result = exceptions(ROOT / 'config/exceptions.json', accounts)
    if args.command == 'matrix':
        print(json.dumps(matrix(accounts), separators=(',', ':')))
    elif args.command == 'compile':
        args.output.parent.mkdir(parents=True, exist_ok=True)
        # JSON is a YAML subset, avoiding a runtime YAML dependency.
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    else:
        print('Account inventory and exception governance: valid')


if __name__ == '__main__':
    main()
