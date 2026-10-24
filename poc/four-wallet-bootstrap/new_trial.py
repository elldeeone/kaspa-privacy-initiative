#!/usr/bin/env python3
"""One command, four isolated fresh owners; no setup, funding or broadcast."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import subprocess
import time
import uuid

from gn2_common import (CLEAN, GENESIS, HERE, MAX, NOTE_FLOOR, ROOT, amount, checked, digest,
                        encoded, need, outside, parse, public_bytes, regular,
                        write_new)
from gn2_runtime import GENERIC, SDK_DIR, SDK_PINS, Runtime
from gn2_selection import load_identity

SOURCES = ('gn2_common.py', 'gn2_backup.py', 'gn2.py', 'gn2_entry.py', 'gn2_selection.py',
           'gn2_runtime.py', 'gn2_owner.py', 'sdk.mjs')
REFERENCES = ('poc/compact-batch-lifecycle/primitives.py', 'poc/future-recipient/v2/recipient.py')
ROLES = ('A', 'B', 'C', 'D')


def create(args):
    start = time.monotonic()
    destination = outside(args.destination)
    need(not destination.exists(), 'fresh-trial-destination-required')
    amount(args.note_value_A, True)
    amount(args.note_value_C, True)
    need(args.note_value_A >= NOTE_FLOOR and args.note_value_C >= NOTE_FLOOR
         and args.note_value_A + args.note_value_C <= MAX, 'initial-note-floor-and-reserve-bound')
    identity = load_identity(args.identity, args.identity_sha256)
    # Every mounted source is public. Validate the full metadata list first.
    sources = [*(HERE / name for name in SOURCES), *(ROOT / name for name in REFERENCES)]
    for path in sources:
        regular(path)
    source_bytes = {str(path): public_bytes(path) for path in sources}
    Runtime(require_native=False)
    trial_id = str(uuid.uuid4())
    destination.mkdir(parents=True, mode=0o700)
    (destination / 'owners').mkdir(mode=0o700)
    (destination / 'public').mkdir(mode=0o700)
    software = destination / 'software'
    software.mkdir(mode=0o700)
    staged = []
    for path in sources:
        relative = path.relative_to(ROOT)
        target = software / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_new(target, source_bytes[str(path)], 0o400)
        staged.append((target, Path('/work') / relative))
    identity_raw = public_bytes(args.identity)
    need(digest(identity_raw) == args.identity_sha256, 'identity-mutated-before-staging')
    identity_path = software / 'identity.json'
    write_new(identity_path, identity_raw, 0o400)
    owner_dirs = {}
    for role in ROLES:
        folder = destination / 'owners' / role
        folder.mkdir(mode=0o700)
        owner_dirs[role] = folder

    def initialize(role):
        command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
            '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp']
        for source, target in staged:
            command += ['--ro-bind', str(source), str(target)]
        for role_name in ('crypto', 'node'):
            command += ['--ro-bind', str(GENERIC[role_name][0]), '/runtime/' + role_name]
        for name in SDK_PINS:
            command += ['--ro-bind', str(SDK_DIR / name), '/runtime/sdk/' + name]
        command += ['--ro-bind', str(identity_path), '/identity.json', '--bind', str(owner_dirs[role]), '/owner',
            '--chdir', '/work/poc/four-wallet-bootstrap', '--setenv', 'PATH', '/usr/bin:/bin',
            '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC',
            '/usr/bin/python3', '-B', '/work/poc/four-wallet-bootstrap/gn2_owner.py', 'init',
            '--identity', '/identity.json', '--identity-sha256', args.identity_sha256,
            '--trial-id', trial_id, '--role', role, '--output', '/owner', '--crypto', '/runtime/crypto',
            '--node', '/runtime/node', '--sdk-dir', '/runtime/sdk']
        if role in ('A', 'C'):
            command += ['--note-value', str(args.note_value_A if role == 'A' else args.note_value_C)]
        result = subprocess.run(command, env=dict(CLEAN), text=True, capture_output=True)
        need(result.returncode == 0, 'isolated-owner-initialization-refused')
        value = parse(result.stdout)
        need(value['role'] == role and value['trial_id'] == trial_id, 'isolated-owner-public-export')
        # This is the only data returned to the coordinator. Never read the
        # sibling backup.json that the owning process has just written.
        write_new(destination / 'public' / ('owner-' + role + '.json'), encoded(value) + b'\n', 0o400)
        return value

    with ThreadPoolExecutor(max_workers=4) as pool:
        owners = list(pool.map(initialize, ROLES))
    need(len({v['funding']['xonly_hex32'] for v in owners}) == 4, 'distinct-four-ordinary-keys')
    need(len({v['invoices_hex208']['0'] for v in owners}) == 4, 'distinct-four-owner-invoices')
    public = {'schema': 'kpx6-four-wallet-trial/v1', 'classification': 'FRESH_UNFUNDED_IDENTITY_ONLY',
        'financial_profile_id': identity['financial_profile_id'], 'profile_identity_sha256': args.identity_sha256,
        'network_id': 'testnet-10', 'genesis_hash_hex': GENESIS,
        'domain_hex32': identity['child_domain_hex32'], 'trial_id': trial_id,
        'owners': [{'role': role, 'public_record_basename': 'owner-' + role + '.json'} for role in ROLES],
        'setup_proving_funding_or_broadcast_performed': False,
        'coordinator_backup_or_private_key_reads': False,
        'constructor_source_sha256': digest(public_bytes(Path(__file__))),
        'source_files': [{'path': str(p.relative_to(ROOT)), 'bytes': len(source_bytes[str(p)]),
                          'sha256': digest(source_bytes[str(p)])} for p in sources]}
    write_new(destination / 'public/TRIAL.json', encoded(public) + b'\n', 0o400)
    return {'trial_directory': str(destination), 'trial_id': trial_id, 'owners_created': 4,
        'elapsed_seconds': time.monotonic() - start, 'status': 'unfunded',
        'setup_proving_funding_or_broadcast_performed': False,
        'coordinator_backup_or_private_key_reads': False}


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--identity', type=Path, required=True)
    parser.add_argument('--identity-sha256', required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--note-value-A', type=int, default=2_000_000_000)
    parser.add_argument('--note-value-C', type=int, default=2_000_000_000)
    args = parser.parse_args()
    try:
        print(encoded(create(args)).decode())
    except (ValueError, OSError, KeyError, TypeError):
        parser.exit(1, 'fresh four-wallet identity refused\n')
