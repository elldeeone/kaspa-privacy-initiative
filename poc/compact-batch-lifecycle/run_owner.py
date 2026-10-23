#!/usr/bin/env python3
"""Prepare/execute one fresh network-off owner namespace; controller stays out.

One authenticated read-only public PK file may be shared by all clients. Each
fresh prover owns and authenticates its complete bytes before backup access.
The source snapshot, metadata and launcher paths are private controller records;
never recursively export this directory or hash its private request/plan.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time
import uuid

import owner
import receiver
from native_runtime import EMITTER, NATIVE, NODE, ROOT, SDK, SDK_FILES
from primitives import need, parse

HERE = Path(__file__).resolve().parent
SOURCES = ['primitives.py', 'receiver.py', 'actions.py', 'history.py', 'native_runtime.py', 'owner.py']
SDK_DIR = Path('/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa')


def write(path, value):
    with path.open('x') as file:
        json.dump(value, file, sort_keys=True, indent=2)
        file.write('\n')
    path.chmod(0o600)


def main(args):
    directory = receiver.no_symlinks(args.controller)
    need(not directory.is_relative_to(ROOT) and not directory.exists(), 'fresh-private-controller-directory')
    public = [args.selection, args.descriptor, args.history, args.manifest, args.pk, args.prover,
              *[HERE / name for name in SOURCES], receiver.SOURCE, SDK, *SDK_FILES,
              EMITTER, NATIVE, NODE, receiver.CRYPTO]
    if args.invoices:
        public.append(args.invoices)
    # Metadata before any caller-selected public file hash/read/copy.
    owner.metadata_guard(args.backup, public, directory / 'client-output/run')
    directory.mkdir(parents=True, mode=0o700)
    client = directory / 'client-output'
    client.mkdir(mode=0o700)
    software = directory / 'software'
    software.mkdir(mode=0o700)
    copied = []
    for src, target in [(HERE / name, software / name) for name in SOURCES] + [
            (receiver.SOURCE, software / 'recipient-v2.py'), (SDK, software / 'sdk.mjs')]:
        raw = receiver.no_symlinks(src).read_bytes()
        target.write_bytes(raw)
        target.chmod(0o400)
        copied.append({'source': str(src), 'snapshot': str(target), 'bytes': len(raw),
                       'sha256': hashlib.sha256(raw).hexdigest()})
    inputs = directory / 'public-inputs'
    inputs.mkdir(mode=0o700)
    for name in ('selection', 'descriptor', 'history', 'manifest'):
        src = receiver.no_symlinks(getattr(args, name))
        target = inputs / (name + '.json')
        target.write_bytes(src.read_bytes())
        target.chmod(0o400)
    if args.invoices:
        target = inputs / 'invoices.json'
        target.write_bytes(receiver.no_symlinks(args.invoices).read_bytes())
        target.chmod(0o400)
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp']
    for name in SOURCES:
        command += ['--ro-bind', str(software / name), '/work/poc/compact-batch-lifecycle/' + name]
    command += ['--ro-bind', str(software / 'recipient-v2.py'), '/work/poc/future-recipient/v2/recipient.py',
                '--ro-bind', str(software / 'sdk.mjs'), '/work/poc/private-cashout-trial/sdk.mjs']
    for path in (EMITTER, NATIVE, NODE, receiver.CRYPTO):
        command += ['--ro-bind', str(path), str(path)]
    for path in SDK_FILES:
        command += ['--ro-bind', str(path), str(path)]
    for name in ('selection', 'descriptor', 'history', 'manifest'):
        command += ['--ro-bind', str(inputs / (name + '.json')), '/' + name + '.json']
    command += ['--ro-bind', str(receiver.no_symlinks(args.pk)), '/parameters.pk',
                '--ro-bind', str(receiver.no_symlinks(args.prover)), '/prover',
                '--ro-bind', str(receiver.no_symlinks(args.backup)), '/own-backup.json',
                '--bind', str(client), '/out', '--chdir', '/work/poc/compact-batch-lifecycle',
                '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
                '--setenv', 'TZ', 'UTC', '/usr/bin/python3', '-B',
                '/work/poc/compact-batch-lifecycle/owner.py', '--role', args.role,
                '--selection', '/selection.json', '--descriptor', '/descriptor.json',
                '--history', '/history.json', '--manifest', '/manifest.json', '--pk', '/parameters.pk',
                '--prover', '/prover', '--backup', '/own-backup.json', '--output', '/out/run',
                '--fee-rate', str(args.fee_rate)]
    if args.invoices:
        # Insert mounts before the first executable argument.
        offset = command.index('/usr/bin/python3')
        command[offset:offset] = ['--ro-bind', str(inputs / 'invoices.json'), '/invoices.json']
        command += ['--invoices', '/invoices.json', '--recipient-gross-sompi', str(args.recipient_gross_sompi)]
    for path in args.must_be_absent:
        command += ['--must-be-absent', str(path)]
    unit = 'kpi-compact-batch-owner-' + uuid.uuid4().hex[:12]
    plan = {'schema': 'kpx4-private-owner-runtime-plan/v1', 'publish_or_hash': False,
        'unit': unit, 'role': args.role, 'command': command, 'source_snapshots': copied,
        'own_backup_path': str(args.backup), 'shared_readonly_PK_path': str(args.pk),
        'private_inputs_or_backup_hashes': None, 'network_unshared': True,
        'no_other_backup_profile_owner_map_or_previous_private_output_mounts': True,
        'requested_limits': {'CPUQuota': '1400%', 'MemoryMax': '20G', 'MemorySwapMax': '0'}}
    write(directory / 'PRIVATE-RUNTIME-PLAN.json', plan)
    # The outer entry records active caps before creating the network/pid mount
    # namespace; the metadata directory itself is never mounted inside it.
    entry = directory / 'entry.py'
    entry.write_text('''from pathlib import Path
import json,subprocess,time
base=Path(__file__).parent
plan=json.loads((base/'PRIVATE-RUNTIME-PLAN.json').read_bytes())
caps={"observed":None}
try:
 group=next(x[3:] for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::'))
 root=Path('/sys/fs/cgroup')/group.lstrip('/')
 caps['observed']={x:(root/x).read_text().strip() for x in ('cpu.max','memory.max','memory.swap.max')}
except (OSError,StopIteration):pass
(base/'ACTIVE-CAPS.json').write_text(json.dumps(caps,sort_keys=True)+'\\n')
start=time.monotonic()
result=subprocess.run(['/usr/bin/time','-v','-o',str(base/'resources.log'),*plan['command']],capture_output=True,text=True)
(base/'PRIVATE-STDOUT.log').write_text(result.stdout)
(base/'PRIVATE-STDERR.log').write_text(result.stderr)
(base/'EXECUTION.json').write_text(json.dumps({'returncode':result.returncode,'wall_seconds':time.monotonic()-start},sort_keys=True)+'\\n')
raise SystemExit(result.returncode)
''')
    entry.chmod(0o400)
    if not args.execute:
        print(json.dumps({'prepared': True, 'executed': False, 'private_inputs_read': False}))
        return
    started = time.monotonic()
    launch = subprocess.run(['systemd-run', '--user', '--collect', '--wait', '--pipe', '--unit=' + unit,
        '-p', 'CPUQuota=1400%', '-p', 'MemoryMax=20G', '-p', 'MemorySwapMax=0',
        '-p', 'RuntimeMaxSec=10800', '-p', 'KillMode=control-group', '/usr/bin/python3', '-B', str(entry)],
        capture_output=True, text=True)
    (directory / 'PRIVATE-LAUNCH-STDOUT.log').write_text(launch.stdout)
    (directory / 'PRIVATE-LAUNCH-STDERR.log').write_text(launch.stderr)
    observed = subprocess.run(['systemctl', '--user', 'show', unit,
        '--property=LoadState,ActiveState,SubState,MainPID,ControlGroup'], capture_output=True, text=True)
    state = dict(row.split('=', 1) for row in observed.stdout.splitlines() if '=' in row)
    write(directory / 'CLEANUP.json', {'manager_state': state, 'manager_returncode': observed.returncode,
        'kernel_cgroup_procs_observation': None, 'kernel_process_count': None,
        'missing_kernel_observation_is_not_zero': True})
    need(launch.returncode == 0 and (client / 'run/RESULTS.json').is_file(), 'owner-runtime-failed')
    summary = parse((client / 'run/RESULTS.json').read_bytes())
    print(json.dumps({'transaction_id': summary['transaction_id'], 'role': summary['role'],
        'fee_sompi': summary['fee_sompi'], 'native_payout_sompi': summary['native_payout_sompi'],
        'reserve_after_sompi': summary['reserve_after_sompi'],
        'native_Full_all_engines_with_supplied_contexts': True,
        'wall_seconds': time.monotonic() - started,
        'accepted_chain_or_currentness_claimed': False}, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('controller', type=Path)
    parser.add_argument('--role', choices=('compact2', 'wide32'), required=True)
    for name in ('selection', 'descriptor', 'history', 'manifest', 'pk', 'prover', 'backup'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--invoices', type=Path)
    parser.add_argument('--recipient-gross-sompi', type=int, default=1_018_867_700)
    parser.add_argument('--fee-rate', type=int, default=100)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--must-be-absent', type=Path, action='append', default=[])
    main(parser.parse_args())
