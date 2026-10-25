"""Public-seed-only namespace controls; never select an actual original backup."""
import hashlib
import json
from pathlib import Path
import subprocess


DOMAIN = 'b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'
PUBLIC_SEED = bytes(range(32))
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


def run_controls(checker_source, fresh_output, read_public):
    """Caller authenticates source bytes with the public guard before this call."""
    root = Path(fresh_output)
    if root.exists():
        raise ValueError('fresh-public-control-root-required')
    root.mkdir(parents=True, mode=0o700)
    checker = root / 'check.py'
    checker.write_bytes(checker_source)
    checker.chmod(0o400)
    base = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
            '--clearenv', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
            '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
            '--ro-bind', '/etc/alternatives', '/etc/alternatives', '--proc', '/proc',
            '--dev', '/dev', '--tmpfs', '/tmp', '--setenv', 'PATH', '/usr/bin:/bin',
            '--setenv', 'LANG', 'C.UTF-8']
    rows = []
    for name, payload, domain, owner_argument, expected in (
        ('miss', b'explicit public candidate, no seed', DOMAIN, '/BACKUP.json', 'PASS'),
        ('raw-hit-boundary', b'x' * 65525 + PUBLIC_SEED + b'y', DOMAIN, '/BACKUP.json', 'FAIL'),
        ('lowerhex-hit', PUBLIC_SEED.hex().encode(), DOMAIN, '/BACKUP.json', 'FAIL'),
        ('upperhex-hit', PUBLIC_SEED.hex().upper().encode(), DOMAIN, '/BACKUP.json', 'FAIL'),
        ('wrong-domain', b'public candidate', '00' * 32, '/BACKUP.json', 'REFUSE'),
        ('sibling-unmounted', b'public candidate', DOMAIN, '/SIBLING.json', 'REFUSE'),
    ):
        case = root / name
        case.mkdir(mode=0o700)
        candidate = case / 'candidate.bin'
        candidate.write_bytes(payload)
        backup = case / 'PUBLIC-SEED.fixture.json'
        backup.write_text(json.dumps({'schema': 'kpxa-original-seed-backup/v1',
            'domain_hex32': domain, 'seed_hex32': PUBLIC_SEED.hex()}))
        backup.chmod(0o600)
        manifest = json.dumps({'schema': 'kpx8-new-owner-seed-export-allowlist/v1',
            'files': [{'path': 'candidate.bin', 'bytes': len(payload),
                       'sha256': hashlib.sha256(payload).hexdigest()}]},
            sort_keys=True, separators=(',', ':')).encode()
        manifest_path = case / 'ALLOWLIST.json'
        manifest_path.write_bytes(manifest)
        output = case / 'out'
        output.mkdir(mode=0o700)
        command = base + ['--ro-bind', str(checker), '/check.py',
            '--ro-bind', str(backup), '/BACKUP.json',
            '--ro-bind', str(candidate), '/candidates/0.bin',
            '--ro-bind', str(manifest_path), '/ALLOWLIST.json', '--bind', str(output), '/out',
            '/usr/bin/python3', '-B', '/check.py', '--owner', owner_argument,
            '--allowlist', '/ALLOWLIST.json', '--allowlist-sha256', hashlib.sha256(manifest).hexdigest(),
            '--candidates', '/candidates', '--output', '/out/RESULTS.json']
        process = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, env=CLEAN)
        result = None
        if expected == 'REFUSE':
            passed = process.returncode == 2 and not (output / 'RESULTS.json').exists()
        else:
            # Only this known-public child result is read; no actual private input exists.
            result = json.loads(read_public(str(output / 'RESULTS.json'))) if process.returncode == 0 else None
            passed = result is not None and result == {
                'schema': 'kpxa-literal-seed-export-result/v1', 'status': expected,
                'candidate_count': 2, 'candidate_bytes': len(payload) + len(manifest),
                'matched_candidate_count': int(expected == 'FAIL'),
                'scope': 'LITERAL_SEED_CANARY_ONLY_NOT_SECURITY_OR_PRIVACY_PROOF'}
        rows.append({'control': name, 'passed': passed, 'exit_status': process.returncode})
    probe = base + ['/usr/bin/python3', '-B', '-c',
        "import os; assert not any(os.path.exists(p) for p in ('/home','/var','/BACKUP.json','/SIBLING.json')); print('PASS')"]
    process = subprocess.run(probe, stdin=subprocess.DEVNULL, capture_output=True, env=CLEAN)
    rows.append({'control': 'no-root-or-sibling-mount', 'passed': process.returncode == 0
                 and process.stdout == b'PASS\n', 'exit_status': process.returncode})
    return {'schema': 'kpxa-public-literal-canary-controls/v1',
            'explicitly_public_seed_hex32': PUBLIC_SEED.hex(),
            'all_passed': all(row['passed'] for row in rows), 'controls': rows,
            'actual_originals_selected_read_or_hashed': False,
            'private_namespace_root_or_sibling_mounted': False}
