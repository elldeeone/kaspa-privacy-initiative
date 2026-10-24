#!/usr/bin/env python3
"""Mount one original compound backup for one ordinary GN2 approval only."""
import argparse
import os
from pathlib import Path
import stat
import subprocess
import time

from gn2_common import (CLEAN, HERE, ROOT, digest, encoded, need, outside,
                        parse, public_bytes, regular, write_new)
from gn2_runtime import GENERIC, SDK_DIR, SDK_PINS
from gn2_selection import load_profile

MODULES = ('gn2_common.py', 'gn2_backup.py', 'gn2.py', 'gn2_entry.py',
    'gn2_selection.py', 'gn2_runtime.py', 'gn2_owner.py', 'sdk.mjs')
REFERENCES = ('poc/compact-batch-lifecycle/primitives.py', 'poc/future-recipient/v2/recipient.py',
              'poc/four-wallet-profile/selection.py')


def run(args):
    start = time.monotonic()
    owner = outside(args.owner)
    backup, info = regular(owner / 'backup.json')
    need(stat.S_IMODE(info.st_mode) == 0o600, 'original-compound-backup-mode')
    forbidden = ((info.st_dev, info.st_ino),)
    own_record = owner / 'owner-init.json'
    output = outside(args.output)
    need(not output.exists(), 'fresh-signature-client-output')
    sources = [*(HERE / n for n in MODULES), *(ROOT / n for n in REFERENCES)]
    generic_paths = {r: (Path(args.assets) / r if args.assets else GENERIC[r][0]) for r in GENERIC}
    all_public = [args.profile, args.case, own_record, *sources, *generic_paths.values(),
                  *(SDK_DIR / n for n in SDK_PINS)]
    # Check ALL metadata before hashing the first public source/profile. A
    # hardlink from any such input to the original backup must not be read.
    for path in all_public:
        regular(path, forbidden)
    need(stat.S_IMODE(own_record.stat().st_mode) == 0o400, 'own-original-public-record-mode')
    profile = load_profile(args.profile, args.profile_sha256, forbidden)
    for role in GENERIC:
        need(profile.executables[role]['sha256'] == GENERIC[role][1], 'profile-generic-runtime-identity')
        need(generic_paths[role].stat().st_size == profile.executables[role]['bytes'],
             'profile-generic-runtime-length')
    output.mkdir(parents=True, mode=0o700)
    software = output / 'software'
    software.mkdir(mode=0o700)
    staged = []
    for path in sources:
        relative = path.relative_to(ROOT)
        target = software / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_new(target, public_bytes(path, forbidden), 0o400)
        staged.append((target, Path('/work') / relative))
    public = output / 'public-inputs'
    public.mkdir(mode=0o700)
    for name, path in (('profile.json', args.profile), ('case.json', args.case), ('owner-init.json', own_record)):
        write_new(public / name, public_bytes(path, forbidden), 0o400)
    client = output / 'client'
    client.mkdir(mode=0o700)
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp']
    for source, target in staged:
        command += ['--ro-bind', str(source), str(target)]
    for role, path in generic_paths.items():
        command += ['--ro-bind', str(path), '/runtime/' + role]
    for name in SDK_PINS:
        command += ['--ro-bind', str(SDK_DIR / name), '/runtime/sdk/' + name]
    for name in ('profile.json', 'case.json'):
        command += ['--ro-bind', str(public / name), '/' + name]
    command += ['--ro-bind', str(backup), '/owner/backup.json',
        '--ro-bind', str(public / 'owner-init.json'), '/owner/owner-init.json',
        '--bind', str(client), '/out', '--chdir', '/work/poc/four-wallet-bootstrap',
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC',
        '/usr/bin/python3', '-B', '/work/poc/four-wallet-bootstrap/gn2_owner.py', 'sign-entry',
        '--owner', '/owner', '--profile', '/profile.json', '--profile-sha256', args.profile_sha256,
        '--case', '/case.json', '--trial-id', args.trial_id, '--output', '/out/run',
        '--fee-rate', str(args.fee_rate), '--crypto', '/runtime/crypto', '--node', '/runtime/node',
        '--native', '/runtime/native-validator', '--sdk-dir', '/runtime/sdk']
    result = subprocess.run(command, capture_output=True, text=True, env=dict(CLEAN))
    need(result.returncode == 0, 'isolated-own-GN2-approval-refused')
    approval = parse(result.stdout)
    actual = parse((client / 'run/APPROVAL.json').read_bytes())
    need(approval == actual and approval['trial_id'] == args.trial_id
         and approval['financial_profile_sha256'] == args.profile_sha256,
         'own-only-signature-export-file-match')
    receipt = {'schema': 'kpx6-isolated-GN2-signature-client/v1', 'wall_seconds': time.monotonic() - start,
        'network_namespace_isolated': True, 'one_compound_backup_mounted_read_only': True,
        'coordinator_backup_contents_read': False, 'proving_PK_or_submit_API': False,
        'input_index': approval['input_index'], 'approval': approval,
        'source_files': [{'path': str(p.relative_to(ROOT)), 'bytes': p.stat().st_size,
                          'sha256': digest(public_bytes(p, forbidden))} for p in sources]}
    write_new(output / 'RESULTS.json', encoded(receipt) + b'\n')
    return {'approval_path': str(client / 'run/APPROVAL.json'), 'input_index': approval['input_index'],
            'wall_seconds': receipt['wall_seconds'], 'coordinator_backup_contents_read': False}


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner', type=Path, required=True)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--profile-sha256', required=True)
    parser.add_argument('--case', type=Path, required=True)
    parser.add_argument('--trial-id', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--assets', type=Path)
    parser.add_argument('--fee-rate', type=int, default=100)
    args = parser.parse_args()
    try:
        print(encoded(run(args)).decode())
    except (ValueError, OSError, KeyError, TypeError):
        parser.exit(1, 'isolated GN2 owner approval refused\n')
