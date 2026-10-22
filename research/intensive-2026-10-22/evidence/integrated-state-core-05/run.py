#!/usr/bin/env python3
"""Qualify the copied state/binding cores in their integrated source locations."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path('/home/luke/projects/kpi-intensive-2026-10-22/integration')
OUT = Path(__file__).resolve().parent / 'attempt-02'
OUT.mkdir()
PACKAGES = ['poc/two-v6-binding/common', 'poc/two-v6-state/common']

def identities():
    return {
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for package in PACKAGES
        for p in sorted((ROOT / package).rglob('*'))
        if p.is_file() and not any(x in p.parts for x in ('evidence', 'target'))
    }

before = identities()
(OUT / 'sources-before.json').write_text(json.dumps(before, indent=2) + '\n')
env = dict(os.environ, PATH='/home/luke/.cargo/bin:/usr/local/bin:/usr/bin:/bin', CARGO_TARGET_DIR='/home/luke/projects/kpi-intensive-2026-10-22/integration-target', CARGO_BUILD_JOBS='2', CARGO_NET_OFFLINE='true')
cases = []
started = time.time()
for label, package, features in [
    ('binding', PACKAGES[0], ['--features', 'compiled-research-instance']),
    ('state', PACKAGES[1], []),
]:
    command = ['cargo', 'test', '--offline', '--locked', '--manifest-path', str(ROOT / package / 'Cargo.toml'), *features]
    with (OUT / f'{label}.stdout').open('xb') as stdout, (OUT / f'{label}.stderr').open('xb') as stderr:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=stdout, stderr=stderr, timeout=180)
    cases.append({'label': label, 'command': command, 'exit': result.returncode})
after = identities()
(OUT / 'sources-after.json').write_text(json.dumps(after, indent=2) + '\n')
report = {'scope': 'integrated source-location core regression only; no proving/native/chain claim', 'cases': cases, 'sources_unchanged': before == after, 'elapsed_seconds': time.time() - started}
(OUT / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
raise SystemExit(0 if before == after and all(c['exit'] == 0 for c in cases) else 1)
