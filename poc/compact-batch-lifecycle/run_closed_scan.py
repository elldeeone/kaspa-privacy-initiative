#!/usr/bin/env python3
"""One read-only original-backup scan, with no PK/prover/controller mounted."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time
import uuid

import owner
import receiver
from native_runtime import EMITTER, NATIVE, NODE, ROOT, SDK, SDK_FILES
from primitives import need, parse

HERE = Path(__file__).resolve().parent
SOURCES = ('primitives.py', 'receiver.py', 'actions.py', 'history.py',
           'native_runtime.py', 'owner.py', 'scan_closed.py')


def run(args):
    directory = receiver.no_symlinks(args.controller)
    need(not directory.is_relative_to(ROOT) and not directory.exists(), 'fresh-private-scan-controller')
    public = [args.selection, args.descriptor, args.history,
              *[HERE / name for name in SOURCES], receiver.SOURCE, SDK,
              *SDK_FILES, EMITTER, NATIVE, NODE, receiver.CRYPTO]
    owner.metadata_guard(args.backup, public, directory / 'client-output/run')
    directory.mkdir(parents=True, mode=0o700)
    client, software, inputs = (directory / name for name in ('client-output', 'software', 'public-inputs'))
    for path in (client, software, inputs):
        path.mkdir(mode=0o700)
    snapshots = []
    sources = [(HERE / name, software / name) for name in SOURCES]
    sources += [(receiver.SOURCE, software / 'recipient-v2.py'), (SDK, software / 'sdk.mjs')]
    for src, target in sources:
        raw = receiver.no_symlinks(src).read_bytes()
        target.write_bytes(raw)
        target.chmod(0o400)
        snapshots.append({'source': str(src), 'snapshot': str(target), 'bytes': len(raw),
                          'sha256': hashlib.sha256(raw).hexdigest()})
    for name in ('selection', 'descriptor', 'history'):
        target = inputs / (name + '.json')
        target.write_bytes(receiver.no_symlinks(getattr(args, name)).read_bytes())
        target.chmod(0o400)
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp']
    for name in SOURCES:
        command += ['--ro-bind', str(software / name), '/work/poc/compact-batch-lifecycle/' + name]
    command += ['--ro-bind', str(software / 'recipient-v2.py'), '/work/poc/future-recipient/v2/recipient.py',
                '--ro-bind', str(software / 'sdk.mjs'), '/work/poc/private-cashout-trial/sdk.mjs']
    for path in (EMITTER, NATIVE, NODE, receiver.CRYPTO, *SDK_FILES):
        command += ['--ro-bind', str(path), str(path)]
    for name in ('selection', 'descriptor', 'history'):
        command += ['--ro-bind', str(inputs / (name + '.json')), '/' + name + '.json']
    command += ['--ro-bind', str(receiver.no_symlinks(args.backup)), '/own-backup.json',
        '--bind', str(client), '/out', '--chdir', '/work/poc/compact-batch-lifecycle',
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC',
        '/usr/bin/python3', '-B', '/work/poc/compact-batch-lifecycle/scan_closed.py',
        '--selection', '/selection.json', '--descriptor', '/descriptor.json', '--history', '/history.json',
        '--backup', '/own-backup.json', '--output', '/out/run']
    # These namespace paths would expose a proving service/key even if the
    # caller forgot to request original-path absence checks.
    for path in (Path('/parameters.pk'), Path('/prover'), *args.must_be_absent):
        command += ['--must-be-absent', str(path)]
    unit = 'kpi-compact-closed-scan-' + uuid.uuid4().hex[:12]
    plan = {'schema': 'kpx4-private-closed-scan-runtime-plan/v1', 'publish_or_hash': False,
        'unit': unit, 'command': command, 'source_snapshots': snapshots,
        'own_backup_path': str(args.backup), 'backup_or_input_hashes': None,
        'network_unshared': True, 'PK_prover_other_backups_or_controller_maps_mounted': False,
        'requested_limits': {'CPUQuota': '200%', 'MemoryMax': '4G', 'MemorySwapMax': '0'}}
    (directory / 'PRIVATE-RUNTIME-PLAN.json').write_text(json.dumps(plan, sort_keys=True, indent=2) + '\n')
    entry = directory / 'entry.py'
    entry.write_text('''from pathlib import Path
import json,subprocess,time
base=Path(__file__).parent
plan=json.loads((base/'PRIVATE-RUNTIME-PLAN.json').read_bytes())
group=next(x[3:] for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::'))
cg=Path('/sys/fs/cgroup')/group.lstrip('/')
(base/'ACTIVE-CAPS.json').write_text(json.dumps({x:(cg/x).read_text().strip() for x in ('cpu.max','memory.max','memory.swap.max')},sort_keys=True)+'\\n')
start=time.monotonic()
result=subprocess.run(['/usr/bin/time','-v','-o',str(base/'resources.log'),*plan['command']],capture_output=True,text=True)
(base/'PRIVATE-STDOUT.log').write_text(result.stdout)
(base/'PRIVATE-STDERR.log').write_text(result.stderr)
(base/'EXECUTION.json').write_text(json.dumps({'returncode':result.returncode,'wall_seconds':time.monotonic()-start},sort_keys=True)+'\\n')
raise SystemExit(result.returncode)
''')
    entry.chmod(0o400)
    started = time.monotonic()
    launched = subprocess.run(['systemd-run', '--user', '--collect', '--wait', '--pipe', '--unit=' + unit,
        '-p', 'CPUQuota=200%', '-p', 'MemoryMax=4G', '-p', 'MemorySwapMax=0',
        '-p', 'RuntimeMaxSec=10800', '-p', 'KillMode=control-group', '/usr/bin/python3', '-B', str(entry)],
        capture_output=True, text=True)
    (directory / 'PRIVATE-LAUNCH-STDOUT.log').write_text(launched.stdout)
    (directory / 'PRIVATE-LAUNCH-STDERR.log').write_text(launched.stderr)
    state = subprocess.run(['systemctl', '--user', 'show', unit,
        '--property=LoadState,ActiveState,SubState,MainPID,ControlGroup'], capture_output=True, text=True)
    (directory / 'CLEANUP.json').write_text(json.dumps({'manager_returncode': state.returncode,
        'manager_state': dict(row.split('=', 1) for row in state.stdout.splitlines() if '=' in row),
        'kernel_cgroup_procs_observation': None, 'missing_kernel_observation_is_not_zero': True},
        sort_keys=True) + '\n')
    need(launched.returncode == 0, 'closed-original-backup-namespace-failed')
    result = parse((client / 'run/RESULTS.json').read_bytes())
    return {'payout_transaction_id': result['selected_payout_transaction_id'],
            'original_receipt_spent': True, 'exact_native_payout_key_rederived': True,
            'prover_or_PK_used': False, 'wall_seconds': time.monotonic() - started,
            'accepted_chain_or_currentness_claimed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('controller', type=Path)
    for name in ('selection', 'descriptor', 'history', 'backup'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--must-be-absent', type=Path, action='append', default=[])
    print(json.dumps(run(parser.parse_args()), sort_keys=True))
