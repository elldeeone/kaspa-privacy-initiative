"""Trusted public-only staging for the bounded selected Exit financial checks."""
from pathlib import Path
import hashlib
import json
import os
import runpy
import subprocess

h = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')
repo = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
base = Path('/var/tmp/kpi-owner-private-lifecycle-01')
financial_sha = '69a7adc46fc96b6a0368c48d4252290140ee500a5558749af7908624be9b923f'
h['read'](repo / 'poc/owner-private-lifecycle/financial-profile.json', financial_sha)
selection = json.loads(h['read'](base / 'public/local-01/NINE-EXIT-CASES-01.json',
                                '232d982a854081997f694f27c866dc3884136b46885e77ac2e8fbaf268df277e'))
assert selection['selected_financial_profile_sha256'] == financial_sha
continuing = next(row for row in selection['cases'] if row['ordinal'] == 1)['case']
terminal = next(row for row in selection['cases'] if row['ordinal'] == 9)['case']
worker = repo / 'poc/owner-private-lifecycle/verification/native/selected_exit_native_controls.py'
worker_sha = 'e8db4d9d3686833f9bf5d949d68f00cac97c1aee7d632fc16a4386d06e957e39'
control_sha = 'c40805e74a93c7dffe7ed8f08836e54af99707593a078b0ddfe57da53b087168'
items = [
    (Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/native-validator'),
     'native-validator', '077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061', 0o555),
    (base / 'assets/native-control-stage-03/control-codec', 'control-codec', control_sha, 0o555),
    (worker, 'controls.py', worker_sha, 0o444),
    (Path(continuing[0]), 'continuing.json', continuing[1], 0o444),
    (Path(terminal[0]), 'terminal.json', terminal[1], 0o444),
]
root = base / 'public/native-selected-exit-controls-01'
root.mkdir(mode=0o700)
public = root / 'public'
public.mkdir(mode=0o700)
output = root / 'out'
output.mkdir(mode=0o700)
files = []
for source, target, pin, mode in items:
    assert pin is not None
    raw = h['read'](source, pin)
    dest = public / target
    with dest.open('xb') as handle:
        handle.write(raw)
    dest.chmod(mode)
    assert dest.stat().st_nlink == 1
    files.append({'source': str(source), 'path': target, 'sha256': pin, 'bytes': len(raw)})
(root / 'STAGING.json').write_text(json.dumps({
    'schema': 'kpx8-selected-exit-native-controls-staging/v1', 'files': files,
    'financial_profile_sha256': financial_sha,
    'financial_core_unchanged': True, 'private_contents_read': False,
}, sort_keys=True, indent=2) + '\n')
public.chmod(0o555)
command = [
    '/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
    '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib', '--ro-bind', '/lib64', '/lib64',
    '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--ro-bind', str(public), '/public',
    '--bind', str(output), '/out', '--setenv', 'HOME', '/tmp', '--setenv', 'PATH', '/usr/bin:/bin',
    '--setenv', 'RAYON_NUM_THREADS', '2', '--chdir', '/out',
    '/usr/bin/python3', '/public/controls.py',
    '--engine', '/public/native-validator', '--engine-sha', files[0]['sha256'],
    '--control-codec', '/public/control-codec', '--control-codec-sha', control_sha,
    '--continuing', '/public/continuing.json', '--continuing-sha', continuing[1],
    '--terminal', '/public/terminal.json', '--terminal-sha', terminal[1], '--out', '/out',
]
allowed = sorted(os.sched_getaffinity(0))
os.sched_setaffinity(0, set(allowed[:2]))
done = subprocess.run(command, capture_output=True)
(root / 'stdout.log').write_bytes(done.stdout)
(root / 'stderr.log').write_bytes(done.stderr)
print(json.dumps({'returncode': done.returncode, 'staged_public_files': len(files),
                  'CPU_affinity': len(os.sched_getaffinity(0))}))
print(done.stdout.decode())
print(done.stderr.decode())
raise SystemExit(done.returncode)
