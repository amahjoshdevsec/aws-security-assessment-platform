#!/usr/bin/env python3
"""Check relative file links in current enterprise documentation."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
errors = []
for path in [ROOT / 'README.md', *sorted((ROOT / 'docs').glob('*.md'))]:
    text = path.read_text()
    text = re.sub(r'```.*?```', '', text, flags=re.S)
    for target in re.findall(r'\[[^\]]+\]\(([^)]+)\)', text):
        if '://' in target or target.startswith('#'):
            continue
        target = target.split('#')[0]
        if not (path.parent / target).exists():
            errors.append(f'{path.relative_to(ROOT)}: missing {target}')
if errors:
    raise SystemExit('\n'.join(errors))
print('Enterprise documentation links: valid')
