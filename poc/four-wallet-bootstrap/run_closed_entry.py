#!/usr/bin/env python3
"""Zero-backup frozen GN2 prepare/combine namespace; default stages only.

The fixed SDK cache pathname inside the namespace contains only staged pinned
SDK files. It never resolves to the host's mutable SDK cache. No broadcast API.
"""
import argparse
import os
from pathlib import Path
import subprocess
import time
import uuid

from run_closed_signer import (CLEAN, Exclusions, checked, digest, encoded,
    members, need, parse, sandbox, sha, stage, write_new)

ENTRY = 'poc/four-wallet-bootstrap/entry_cli.py'
ENTRY_SHA = 'd2be6e1bb14644028d2de61aff2cea213074d1d06e26e750f7323bc35605fcbb'
SDK_FIXED = '/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa/'


def run(a):
    started = time.monotonic()
    trial = uuid.UUID(a.trial_id)
    need(trial.version == 4 and trial.variant == uuid.RFC_4122 and str(trial) == a.trial_id,
         'canonical-trial-UUIDv4')
    need(a.operation in ('prepare', 'combine'), 'fixed-public-GN2-entry-operation')
    excluded = Exclusions(a.exclude_trial_directory)
    rows = (*members(), ('runtime-source/' + ENTRY, '/work/' + ENTRY, ENTRY_SHA, False))
    public = [('profile.json', a.profile, sha(a.profile_sha256))]
    if a.operation == 'prepare':
        need(len(a.owners) == len(a.owners_sha256) == 2, 'two-pinned-public-initial-records')
        public += [('owner-' + str(i) + '.json', path, sha(pin))
                   for i, (path, pin) in enumerate(zip(a.owners, a.owners_sha256))]
        public += [('sources.json', a.sources, sha(a.sources_sha256))]
        arguments = ['--owners', '/owner-0.json', '/owner-1.json', '--sources', '/sources.json']
    else:
        need(len(a.approvals) == len(a.approvals_sha256) == 2, 'two-pinned-public-approvals')
        public += [('case.json', a.case, sha(a.case_sha256))]
        public += [('approval-' + str(i) + '.json', path, sha(pin))
                   for i, (path, pin) in enumerate(zip(a.approvals, a.approvals_sha256))]
        arguments = ['--case', '/case.json', '--approvals', '/approval-0.json', '/approval-1.json']
    output, staged, inputs = stage(excluded, checked(a.software_root), a.output,
                                   rows, public, a.exclude_trial_directory)
    client = output / 'client'; client.mkdir(mode=0o700)
    command = sandbox(staged, inputs, [name for name, _, _ in public])
    # Frozen Runtime() uses this historical pathname. Provide only the exact
    # selected SDK3 at it; no host /home or cache directory is mounted.
    for source, destination in staged:
        if destination.startswith('/runtime/sdk/'):
            command += ['--ro-bind', str(source), SDK_FIXED + Path(destination).name]
    command += ['--bind', str(client), '/out', '--chdir', '/work/poc/four-wallet-bootstrap',
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC',
        '/usr/bin/python3', '-B', '/work/' + ENTRY, a.operation,
        '--profile', '/profile.json', '--profile-sha256', a.profile_sha256,
        '--trial-id', a.trial_id, '--output', '/out/run', '--assets', '/runtime', '--fee-rate', '100',
        *arguments]
    write_new(output / 'PLAN.json', encoded({'command': command, 'backup_mount_count': 0}) + b'\n')
    receipt = {'schema': 'kpx6-closed-GN2-public-entry/v1', 'operation': a.operation,
        'trial_id': a.trial_id, 'financial_profile_sha256': a.profile_sha256,
        'excluded_original_backup_count': 8, 'excluded_original_owner_directory_count': 8,
        'backup_mount_count': 0, 'original_owner_directories_mounted': False,
        'original_backup_contents_read_copied_or_hashed': False,
        'fixed_SDK_path_populated_only_with_selected_staged_files': True,
        'reference_fee_rate': 100, 'executed': False, 'SDK_or_Native_executed': False,
        'PK_prover_network_or_submission': False,
        'public_inputs': [{'name': name, 'sha256': pin} for name, _, pin in public],
        'source_members': [{'path': relative, 'sha256': pin} for relative, _, pin, _ in rows]}
    if a.execute:
        result = subprocess.run(command, capture_output=True, text=True, env=CLEAN)
        write_new(output / 'STDOUT.log', result.stdout.encode())
        write_new(output / 'STDERR.log', result.stderr.encode())
        need(result.returncode == 0, 'closed-public-GN2-operation-refused')
        reported = parse(result.stdout)
        filename = 'proposed-case.json' if a.operation == 'prepare' else 'selected-case.json'
        need(reported['case_path'] == '/out/run/' + filename
             and reported['broadcast_performed'] is False, 'fixed-public-GN2-result')
        path = client / 'run' / filename
        raw = excluded.read_generated(path)
        parse(raw)
        receipt.update({'executed': True, 'SDK_or_Native_executed': True,
                        'case_path': str(path), 'case_sha256': digest(raw),
                        'wall_seconds': time.monotonic() - started})
    write_new(output / 'RESULTS.json', encoded(receipt) + b'\n')
    return receipt


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='operation', required=True)
    for operation in ('prepare', 'combine'):
        q = sub.add_parser(operation)
        for name in ('software-root', 'profile', 'output'):
            q.add_argument('--' + name, type=Path, required=True)
        for name in ('profile-sha256', 'trial-id'):
            q.add_argument('--' + name, required=True)
        q.add_argument('--exclude-trial-directory', type=Path, action='append', required=True)
        q.add_argument('--execute', action='store_true')
        if operation == 'prepare':
            q.add_argument('--owners', type=Path, nargs=2, required=True)
            q.add_argument('--owners-sha256', nargs=2, required=True)
            q.add_argument('--sources', type=Path, required=True)
            q.add_argument('--sources-sha256', required=True)
        else:
            q.add_argument('--case', type=Path, required=True)
            q.add_argument('--case-sha256', required=True)
            q.add_argument('--approvals', type=Path, nargs=2, required=True)
            q.add_argument('--approvals-sha256', nargs=2, required=True)
    return p


if __name__ == '__main__':
    os.umask(0o077)
    p = parser()
    try:
        print(encoded(run(p.parse_args())).decode())
    except (ValueError, OSError, KeyError, TypeError, UnicodeError):
        p.exit(1, 'closed public GN2 operation incomplete; no submission performed\n')
