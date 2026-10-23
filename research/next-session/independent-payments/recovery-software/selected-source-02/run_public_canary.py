#!/usr/bin/env python3
"""Fixed isolated launcher for root's PUBLIC_UNSAFE_DO_NOT_FUND known seed.

Only previously externally selected software bytes are executed. No source
download or main owner input is accepted. Root separately schedules proving.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

from software_bundle import digest, forbidden_metadata, need, read_public, verify

ROOT = Path(__file__).resolve().parents[2]
CANARY = Path('/home/luke/projects/kpi-intensive-2026-10-22/independent-payment-public-recovery-canary-01')
INVENTORY = ROOT / 'research/next-session/independent-payments/recovery-software/distribution-03/SOFTWARE-BUNDLE.json'
INVENTORY_SHA = 'd8f96ce9f133d846b94ad5219f45d8664acba8972355fccd2d27b3315a06b808'
PROVER_SHA = '1662fcd9a5b90b8658e07aed2250a4c9c11d2390e80d7addae717090d63fb94d'
BINARIES = {
    'emitter': '/home/luke/projects/kpi-intensive-2026-10-22/compact-batch-native-target/selected-release-01/emitter',
    'native-validator': '/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/native-validator',
    'crypto': '/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/crypto',
    'node': '/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node'}
SDK = '/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa/'


def run(restored, output, *, pk=None, https_materials=None, downloaded_inventory=None):
    need(output.is_absolute() and not output.exists() and not output.is_relative_to(ROOT),
         'fresh-public-canary-output')
    backup = CANARY / 'PUBLIC-UNSAFE-SEED.json'
    need((pk is None and https_materials is None and downloaded_inventory is None)
         or (pk is not None and https_materials is not None and downloaded_inventory is not None),
         'proving-requires-actual-HTTPS-public-materials')
    inventory_path = INVENTORY if downloaded_inventory is None else downloaded_inventory
    descriptor_path = CANARY / 'descriptor.json' if https_materials is None else https_materials / 'descriptor'
    history_path = CANARY / 'history.json' if https_materials is None else https_materials / 'history'
    manifest_path = (restored / 'prover/pins/compact2/public-parameters.json' if https_materials is None
                     else https_materials / 'parameters_manifest')
    forbidden = forbidden_metadata([backup])
    # Every declared public argument's metadata precedes its byte read.
    data_paths = [inventory_path, descriptor_path, history_path, manifest_path,
                  CANARY / 'compact-client-selection.json']
    if pk is not None:
        data_paths.append(pk)
    for path in data_paths:
        info = path.stat()
        need((info.st_dev, info.st_ino) not in forbidden, 'public-private-inode-alias')
    inventory_raw = read_public(inventory_path, forbidden)
    verify(restored, inventory_raw, INVENTORY_SHA, forbidden_inputs=[backup])
    listed = {row['path'] for row in json.loads(inventory_raw)['files']}
    required = {'runtime-source/poc/compact-batch-lifecycle/' + name for name in (
        'primitives.py', 'receiver.py', 'actions.py', 'history.py', 'native_runtime.py', 'owner.py')}
    need(required <= listed and all((restored / name).is_file() for name in required),
         'restored-owner-runtime-source-closure')
    need(digest(read_public(restored / 'runtime/prover', forbidden)) == PROVER_SHA,
         'exact-selected-restored-prover-required')
    output.mkdir(parents=True, mode=0o700)
    # Root's previously confirmed public data identity is external to software/PK mirrors.
    descriptor = read_public(descriptor_path, forbidden)
    need(hashlib.sha256(json.dumps(json.loads(descriptor), sort_keys=True,
         separators=(',', ':')).encode()).hexdigest()
         == '61e0f955850f199305bb50ec57ad389aafbc645de2685ff3572d76f11d864ed8',
         'public-canary-descriptor-pin')
    if https_materials is not None:
        need(digest(read_public(history_path, forbidden))
             == '1d387cbc57a2379178763be75a2fe7a0633f9dfb2dd2ec6d93882995d7e5f750'
             and digest(read_public(manifest_path, forbidden))
             == 'f27a806928b5c2409d4e4c5428a75deabef6ecf9601b60889667e90363f26043',
             'exact-HTTPS-canary-history-and-selected-compact-manifest')
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--bind', str(output), '/out']
    for row in json.loads(inventory_raw)['files']:
        if row['kind'] == 'runtime-source' and row['path'].startswith('runtime-source/'):
            relative = row['path'].removeprefix('runtime-source/')
            command += ['--ro-bind', str(restored / row['path']), '/work/' + relative]
    for name, target in BINARIES.items():
        command += ['--ro-bind', str(restored / 'runtime' / name), target]
    for name in ('kaspa.js', 'kaspa_bg.wasm', 'package.json'):
        command += ['--ro-bind', str(restored / 'runtime-sdk' / name), SDK + name]
    command += ['--ro-bind', str(descriptor_path), '/descriptor.json',
                '--ro-bind', str(history_path), '/history.json',
                '--ro-bind', str(backup), '/own-backup.json']
    absent = [str(ROOT), str(CANARY), str(restored),
              '/home/luke/projects/kpi-intensive-2026-10-22/compact-batch-prover-target',
              '/home/luke/.cargo']
    if pk is None:
        command += ['--ro-bind', str(Path(__file__).with_name('canary_recognize.py')), '/runner.py']
        application = ['/usr/bin/python3', '-B', '/runner.py']
    else:
        command += ['--ro-bind', str(pk), '/parameters.pk',
                    '--ro-bind', str(restored / 'runtime/prover'), '/prover',
                    '--ro-bind', str(CANARY / 'compact-client-selection.json'), '/selection.json',
                    '--ro-bind', str(manifest_path), '/manifest.json']
        absent.append(str(pk))
        absent.append(str(https_materials))
        application = ['/usr/bin/python3', '-B', '/work/poc/compact-batch-lifecycle/owner.py',
            '--role', 'compact2', '--selection', '/selection.json', '--descriptor', '/descriptor.json',
            '--history', '/history.json', '--manifest', '/manifest.json', '--pk', '/parameters.pk',
            '--prover', '/prover', '--backup', '/own-backup.json', '--output', '/out/run', '--fee-rate', '100']
        for path in absent:
            application += ['--must-be-absent', path]
    command += ['--chdir', '/work/poc/compact-batch-lifecycle', '--setenv', 'PATH', '/usr/bin:/bin',
                '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC']
    # The static absence wrapper runs before ANY backup or PK read inside namespace.
    probe = ('import json,pathlib,subprocess,sys; paths=' + repr(absent)
             + '; assert all(not pathlib.Path(p).exists() for p in paths); '
             + 'pathlib.Path("/out/ABSENCE.json").write_text(json.dumps({"original_paths_absent":True,"count":len(paths)})); '
             + 'sys.exit(subprocess.call(' + repr(application) + '))')
    command += ['/usr/bin/python3', '-B', '-c', probe]
    (output / 'PUBLIC-RUNTIME-COMMAND.json').write_text(json.dumps({'command': command,
        'only_known_public_unsafe_canary_backup': True, 'software_inventory_sha256': INVENTORY_SHA,
        'exact_selected_prover_restored': PROVER_SHA, 'network_unshared': True,
        'public_history_and_manifest_from_HTTPS': https_materials is not None,
        'PK_and_prover_mounted': pk is not None}, sort_keys=True) + '\n')
    began = time.monotonic()
    result = subprocess.run(command, capture_output=True, text=True)
    (output / 'stdout.log').write_text(result.stdout)
    (output / 'stderr.log').write_text(result.stderr)
    outcome = {'returncode': result.returncode, 'wall_seconds': time.monotonic() - began,
               'classification': 'PUBLIC_UNSAFE_DO_NOT_FUND_NO_ACCEPTED_CURRENT_AUTHORITY',
               'PK_proving_requested': pk is not None, 'spend_authorized': False}
    (output / 'EXECUTION.json').write_text(json.dumps(outcome, sort_keys=True) + '\n')
    print(json.dumps(outcome, sort_keys=True))
    return result.returncode


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('restored_software_tree', type=Path)
    parser.add_argument('fresh_public_output', type=Path)
    parser.add_argument('--root-released-public-PK', type=Path)
    parser.add_argument('--https-materials', type=Path)
    parser.add_argument('--downloaded-software-inventory', type=Path)
    args = parser.parse_args()
    raise SystemExit(run(args.restored_software_tree, args.fresh_public_output,
                         pk=args.root_released_public_PK, https_materials=args.https_materials,
                         downloaded_inventory=args.downloaded_software_inventory))
