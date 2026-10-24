#!/usr/bin/env python3
"""Trusted one-backup launcher from an externally selected public software tree.

Stdlib-only metadata checks precede copied/downloaded source execution. Only
fixed selected source/runtime members, exact public inputs/pages, one backup
and optional public PK enter the network-off owner namespace. No broadcast.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import time
import uuid

from installation import (CLEAN, checked, digest, entries, mapping, need,
                          network_page_rows, outside, parse, read_public, regular)

MANAGER_ENV = dict(CLEAN, XDG_RUNTIME_DIR='/run/user/' + str(os.getuid()),
                   DBUS_SESSION_BUS_ADDRESS='unix:path=/run/user/' + str(os.getuid()) + '/bus')


def save(path, value, mode=0o600):
    with Path(path).open('x') as file:
        json.dump(value, file, sort_keys=True); file.write('\n')
    Path(path).chmod(mode)


def _inputs(args):
    names = ['financial_profile']
    names += ['history'] if args.source_kind == 'local' else ['descriptor', 'fetch']
    if args.op in ('prepare-payment', 'preflight-pending'):
        names += ['request', 'virtual_prefix']
    if args.op in ('prepare-payment', 'prepare-full-cashout'):
        names += ['manifest']
    return names


def run(args):
    need(args.op in ('recover', 'preflight-pending', 'prepare-payment', 'prepare-full-cashout')
         and args.source_kind in ('local', 'accepted'), 'selected-owner-operation')
    heavy = args.op in ('prepare-payment', 'prepare-full-cashout')
    need((args.pk is not None) == heavy, 'public-PK-only-for-proof-generation')
    backup = outside(args.backup)
    info = backup.stat()
    need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600,
         'one-original-backup-metadata')
    forbidden = {(info.st_dev, info.st_ino)}
    private_directories = {backup.parent}
    for path in args.exclude_private_file:
        path = outside(path); row = path.stat()
        need(stat.S_ISREG(row.st_mode), 'declared-original-private-file-type')
        forbidden.add((row.st_dev, row.st_ino))
    private_directories.update(outside(path) for path in args.exclude_private_dir)
    forbidden, private_directories = frozenset(forbidden), tuple(private_directories)
    directory = outside(args.controller)
    need(not directory.exists(), 'fresh-private-owner-controller')
    names = _inputs(args)
    for name in names:
        need(getattr(args, name) is not None, 'complete-public-input-paths')
        regular(getattr(args, name), forbidden, private_directories)
    if args.pk:
        regular(args.pk, forbidden, private_directories)
    rows = entries(args, forbidden, private_directories)
    page_rows = ()
    if args.source_kind == 'accepted':
        need(args.bundle_directory is not None, 'retained-public-bundle-root')
        fetch = read_public(args.fetch, forbidden, private_directories)
        page_rows = network_page_rows(fetch, args.fetch_sha256)
        for relative, _ in page_rows:
            regular(checked(args.bundle_directory) / relative, forbidden, private_directories)
    # All member/page metadata is checked before any member/page is copied.
    directory.mkdir(parents=True, mode=0o700)
    software = directory / 'software'; software.mkdir(mode=0o700)
    for row, path in rows:
        raw = read_public(path, forbidden, private_directories)
        need(len(raw) == row['bytes'] and digest(raw) == row['sha256'], 'selected-software-bytes')
        target = software / row['path']; target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with target.open('xb') as file:
            file.write(raw)
        target.chmod(0o500 if row['kind'] == 'selected-executable' else 0o400)
    inputs = directory / 'public-inputs'; inputs.mkdir(mode=0o700)
    for name in names:
        raw = read_public(getattr(args, name), forbidden, private_directories)
        if name == 'financial_profile':
            expected = args.financial_sha256
        elif name == 'manifest':
            expected = None  # The exact financial profile/owner checks this.
        else:
            expected = getattr(args, name + '_sha256')
        need(expected is None or digest(raw) == expected, 'external-public-input-pin')
        target = inputs / (name + '.json'); target.write_bytes(raw); target.chmod(0o400)
    bundle = directory / 'public-bundle'; bundle.mkdir(mode=0o700)
    for relative, _ in page_rows:
        raw = read_public(checked(args.bundle_directory) / relative, forbidden, private_directories)
        target = bundle / relative; target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with target.open('xb') as file:
            file.write(raw)
        target.chmod(0o400)
    client = directory / 'client-output'; client.mkdir(mode=0o700)
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp']
    for relative, destination in mapping(args.source_kind).items():
        command += ['--ro-bind', str(software / relative), destination]
    for name in names:
        command += ['--ro-bind', str(inputs / (name + '.json')), '/' + name + '.json']
    if args.source_kind == 'accepted':
        command += ['--ro-bind', str(bundle), '/public-bundle']
    command += ['--ro-bind', str(backup), '/own-backup.json', '--bind', str(client), '/out']
    if args.pk:
        command += ['--ro-bind', str(checked(args.pk)), '/parameters.pk']
    command += ['--chdir', '/work/poc/four-wallet-lifecycle', '--setenv', 'PATH', '/usr/bin:/bin',
        '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC', '/usr/bin/python3', '-B',
        '/work/poc/four-wallet-lifecycle/owner.py', args.op,
        '--financial-profile', '/financial_profile.json', '--financial-sha256', args.financial_sha256,
        '--runtime-root', '/runtime', '--backup', '/own-backup.json', '--output', '/out/run',
        '--source-kind', args.source_kind, '--workers', str(args.workers), '--fee-rate', str(args.fee_rate)]
    for name in names:
        if name in ('financial_profile', 'manifest'):
            continue
        command += ['--' + name.replace('_', '-'), '/' + name + '.json',
                    '--' + name.replace('_', '-') + '-sha256', getattr(args, name + '_sha256')]
    if args.source_kind == 'accepted':
        command += ['--bundle-directory', '/public-bundle']
    if heavy:
        command += ['--manifest', '/manifest.json', '--pk', '/parameters.pk', '--execute']
    if args.ordinal is not None:
        command += ['--ordinal', str(args.ordinal)]
    if args.minimum_payout_sompi is not None:
        command += ['--minimum-payout-sompi', str(args.minimum_payout_sompi)]
    for path in args.must_be_absent:
        command += ['--must-be-absent', str(checked(path))]
    unit = 'kpi-four-wallet-owner-' + uuid.uuid4().hex[:12]
    limits = {'CPUQuota': '1400%' if heavy else '200%',
              'MemoryMax': '20G' if heavy else '3G', 'MemorySwapMax': '0'}
    save(directory / 'PRIVATE-RUNTIME-PLAN.json', {'command': command, 'unit': unit,
        'requested_limits': limits, 'publish_or_hash_private_plan': False})
    entry = directory / 'entry.py'
    entry.write_text('''from pathlib import Path
import json,subprocess,time
base=Path(__file__).parent
plan=json.loads((base/'PRIVATE-RUNTIME-PLAN.json').read_bytes())
root=None
try:
 group=next(row[3:] for row in Path('/proc/self/cgroup').read_text().splitlines() if row.startswith('0::'))
 root=Path('/sys/fs/cgroup')/group.lstrip('/')
except (OSError,StopIteration):pass
def counters(names):
 result={}
 for name in names:
  try:result[name]=(root/name).read_text().strip() if root is not None else None
  except OSError:result[name]=None
 return result
(base/'ACTIVE-CAPS.json').write_text(json.dumps(counters(('cpu.max','memory.max','memory.swap.max')),sort_keys=True)+'\\n')
started=time.monotonic()
result=subprocess.run(plan['command'],capture_output=True,text=True)
(base/'PRIVATE-STDOUT.log').write_text(result.stdout)
(base/'PRIVATE-STDERR.log').write_text(result.stderr)
measured=counters(('cpu.stat','memory.peak','memory.swap.peak','memory.events','cgroup.procs'))
(base/'EXECUTION.json').write_text(json.dumps({'returncode':result.returncode,'wall_seconds':time.monotonic()-started,'whole_service_cgroup_counters':measured,'missing_counter_is_unavailable_not_zero':True},sort_keys=True)+'\\n')
raise SystemExit(result.returncode)
''')
    entry.chmod(0o400)
    if not args.execute:
        return {'prepared': True, 'executed': False, 'original_backup_bytes_read': False,
                'proving_worker_started': False}
    launch = ['systemd-run', '--user', '--collect', '--wait', '--pipe', '--unit=' + unit]
    for key, value in limits.items():
        launch += ['-p', key + '=' + value]
    launch += ['-p', 'RuntimeMaxSec=10800', '-p', 'KillMode=control-group',
               '/usr/bin/python3', '-B', str(entry)]
    started = time.monotonic()
    result = subprocess.run(launch, capture_output=True, text=True, env=MANAGER_ENV)
    (directory / 'PRIVATE-LAUNCH-STDOUT.log').write_text(result.stdout)
    (directory / 'PRIVATE-LAUNCH-STDERR.log').write_text(result.stderr)
    manager = subprocess.run(['systemctl', '--user', 'show', unit,
        '--property=LoadState,ActiveState,SubState,MainPID,ControlGroup'],
        capture_output=True, text=True, env=MANAGER_ENV)
    state = dict(row.split('=', 1) for row in manager.stdout.splitlines() if '=' in row)
    save(directory / 'CLEANUP.json', {'manager_state': state, 'manager_returncode': manager.returncode,
        'post_collection_kernel_process_count': None, 'missing_observation_is_not_zero': True})
    need(result.returncode == 0 and (client / 'run/RESULTS.json').is_file(), 'owner-runtime-incomplete')
    summary = parse((client / 'run/RESULTS.json').read_bytes())
    return {'passed': True, 'op': args.op, 'wall_seconds': time.monotonic()-started,
            'owner_summary': summary, 'submitted_by_this_launcher': False}


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('controller', type=Path)
    parser.add_argument('--op', choices=('recover', 'preflight-pending', 'prepare-payment', 'prepare-full-cashout'), required=True)
    parser.add_argument('--source-kind', choices=('local', 'accepted'), required=True)
    for name in ('software-root', 'inventory', 'financial-profile', 'backup'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inventory-sha256', required=True)
    parser.add_argument('--financial-sha256', required=True)
    for name in ('history', 'descriptor', 'fetch', 'bundle-directory', 'manifest', 'pk', 'request', 'virtual-prefix'):
        parser.add_argument('--' + name, type=Path)
    for name in ('history', 'descriptor', 'fetch', 'request', 'virtual-prefix'):
        parser.add_argument('--' + name + '-sha256')
    parser.add_argument('--ordinal', type=int, choices=(0, 1))
    parser.add_argument('--minimum-payout-sompi', type=int)
    parser.add_argument('--fee-rate', type=int, default=100)
    parser.add_argument('--workers', type=int, default=14)
    parser.add_argument('--execute', action='store_true')
    for name in ('must-be-absent', 'exclude-private-file', 'exclude-private-dir'):
        parser.add_argument('--' + name, type=Path, action='append', default=[])
    return parser.parse_args()


if __name__ == '__main__':
    try:
        print(json.dumps(run(arguments()), sort_keys=True))
    except Exception:
        print(json.dumps({'error': 'one-backup-launch-incomplete', 'submitted': False}))
        raise SystemExit(1)
