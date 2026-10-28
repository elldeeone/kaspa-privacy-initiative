#!/usr/bin/env python3
"""Source-selected one-colluder view producer; default never opens private data."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess

import privacy_codec as codec
import privacy_launch as launch

HERE = Path(__file__).absolute().parent
NODE = Path('/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node')
CRYPTO = Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/crypto')
NODE_PIN = 'd1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c'
CRYPTO_PIN = '6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff'
JS_ROOT = Path('/var/tmp/kpi-signature-predicate-tools-20261026-01')
LEAF_MAP = Path('/run/user/1000/kpi-nativeauthspend-resume-20261028-03/JS-INSTALLED-LEAF-MAP.json')
LEAF_MAP_PIN = '00b536cab3799984c2a2f9895329bc410daa0f11f5093f10aa48d92f3abdca50'


def sources():
    values = {name: HERE / name for name in ('privacy_colluder.py', 'privacy_colluder_worker.py',
        'privacy_launch.py', 'privacy_codec.py', 'privacy_observer.py', 'private_worker.py',
        'wallet_profile.py', 'output_producer.py', 'owner_authority.mjs')}
    values['recipient.py'] = HERE.parents[1] / 'future-recipient/v2/recipient.py'
    return values


def move_original_no_replace(source, destination):
    """Linux renameat2 NOREPLACE: atomic original-inode move, no body read."""
    source, destination = launch.leaf_metadata(source, 0o600), launch.checked(destination)
    before = source.lstat()
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1) != 0:
        error = ctypes.get_errno()
        raise OSError(error, 'private original metadata move refused')
    after = destination.lstat()
    codec.need((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), 'privacy-same-original-inode-routed')


def run(selection_path, selection_sha256, round_number, execute=False):
    codec.need(type(round_number) is int and round_number in (1, 2), 'privacy-fixed-colluder-round')
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    selected = codec.parse(read(launch.checked(selection_path), codec.word(selection_sha256)))
    codec.fields(selected, ('schema', 'diagnostic_selection', 'source_members'))
    codec.need(selected['schema'] == 'kpb-colluder-view-producer-selection/v1', 'privacy-explicit-colluder-producer-selection')
    diagnostic_path, _ = launch.public_ref(selected['diagnostic_selection'], read)
    diagnostic, trial_public, private, _, rounds = launch.admitted(diagnostic_path,
        selected['diagnostic_selection']['sha256'], read)
    expected = sources()
    codec.need([row['name'] for row in selected['source_members']] == list(expected), 'privacy-finite-colluder-source-closure')
    admitted = []
    for row in selected['source_members']:
        codec.fields(row, ('name', 'sha256'))
        path = expected[row['name']]; pin = codec.word(row['sha256']); raw = read(path, pin)
        admitted.append((path, pin, raw))
    bound = diagnostic['binding']; part = rounds[round_number - 1]
    own = launch.owner_directory(private, part['payments']['owners'][1])
    original = private / 'owner-1' / 'BACKUP.json'
    record = own / 'OWNER-LOCAL-RECORD.json'; destination = launch.checked(own / 'COLLUDER-CONSTRAINTS.json')
    state = private / 'owner-1' / 'diagnostics' / ('private-batch-colluder-round-' + str(round_number))
    output = trial_public / 'privacy-diagnostics' / ('colluder-round-' + str(round_number))
    if not execute:
        return {'schema': 'kpb-colluder-view-producer-plan/v1', 'binding': bound, 'round': round_number,
                'owner_component': 1, 'executed': False, 'private_bodies_read_or_hashed': False}
    launch.leaf_metadata(original, 0o600); launch.leaf_metadata(record, 0o600)
    codec.need(not destination.exists() and not output.exists(), 'privacy-original-colluder-view-once-only')
    # Only public software is read or hashed in the controller. The worker
    # independently checks all installed JS leaves inside the owner namespace.
    for path, pin in ((NODE, NODE_PIN), (CRYPTO, CRYPTO_PIN), (LEAF_MAP, LEAF_MAP_PIN)): read(path, pin)
    launch.mkdir(state); launch.mkdir(output); shared = launch.mkdir(output / 'selected-public')
    launch.write_new(state / 'PRODUCING-CLOSED', {'binding': bound, 'round': round_number,
        'selection_sha256': selection_sha256})
    mounts, source_members = [], []
    for index, (path, pin, raw) in enumerate(admitted):
        target = shared / ('source-' + str(index)); launch.write_new(target, raw)
        mounts += ['--ro-bind', str(target), str(path)]
        source_members.append({'path': str(path), 'sha256': pin})
    projection = shared / 'PROJECTION.bin'; projection_pin = launch.write_new(projection, part['projection'][1])
    mounts += ['--ro-bind', str(projection), '/public/PROJECTION.bin']
    route_pins = []
    for component, (_, raw) in enumerate(part['routes']):
        target = shared / ('ROUTE-' + str(component) + '.json'); route_pins.append(launch.write_new(target, raw))
        mounts += ['--ro-bind', str(target), '/routes/owner-' + str(component) + '.json']
    private_output = launch.mkdir(state / 'output')
    config = {'schema': 'kpb-one-colluder-view-worker/v1', 'binding': bound, 'round': round_number,
        'owner_component': 1, 'domain_hex32': launch.DOMAIN, 'profile_id_hex32': launch.PROFILE,
        'source_members': source_members, 'runtime_members': [
            {'path': '/runtime/node', 'sha256': NODE_PIN}, {'path': '/runtime/crypto', 'sha256': CRYPTO_PIN},
            {'path': '/runtime/JS-INSTALLED-LEAF-MAP.json', 'sha256': LEAF_MAP_PIN}],
        'js_leaf_map_sha256': LEAF_MAP_PIN, 'projection_sha256': projection_pin, 'route_sha256': route_pins}
    config_path, marker = state / 'PRIVATE-CONFIG.json', shared / 'NAMESPACE.json'
    launch.write_new(config_path, config, 0o600)
    launch.write_new(marker, {'schema': 'kpb-one-colluder-view-namespace/v1', 'network': 'disabled',
        'owner_component': 1, 'owner_slots': 1, 'truth_slots': 0, 'server_slots': 0})
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', *mounts,
        '--ro-bind', str(NODE), '/runtime/node', '--ro-bind', str(CRYPTO), '/runtime/crypto',
        '--ro-bind', str(JS_ROOT / 'node_modules'), '/runtime/js/node_modules',
        '--ro-bind', str(LEAF_MAP), '/runtime/JS-INSTALLED-LEAF-MAP.json',
        '--ro-bind', str(original), '/original/BACKUP.json', '--ro-bind', str(record), '/own/OWNER-LOCAL-RECORD.json',
        '--ro-bind', str(config_path), '/CONFIG.json', '--ro-bind', str(marker), '/NAMESPACE.json',
        '--bind', str(private_output), '/private-output', '--bind', str(output), '/out',
        '/usr/bin/python3', '-B', '-S', str(HERE / 'privacy_colluder_worker.py')]
    launch.write_new(state / 'PRIVATE-PLAN.json', {'command': command}, 0o600)
    with (state / 'PRIVATE-STDOUT.log').open('xb') as stdout, (state / 'PRIVATE-STDERR.log').open('xb') as stderr:
        result = subprocess.run(command, stdout=stdout, stderr=stderr, env={'PATH': '/usr/bin:/bin'})
    codec.need(result.returncode == 0, 'privacy-one-colluder-derivation-incomplete')
    receipt_path = output / 'PUBLIC.json'; raw = read(receipt_path); receipt = codec.parse(raw)
    codec.need(receipt == {'schema': 'kpb-colluder-view-produced/v1', 'binding': bound,
        'owner_component': 1, 'round': round_number, 'actual_incoming_CF_decrypted': True,
        'actual_all_three_routes_used': True, 'private_record_or_identifiers_exported': False},
        'privacy-typed-colluder-completion-no-private-data')
    produced = launch.leaf_metadata(private_output / 'COLLUDER-CONSTRAINTS.json', 0o600)
    # Move the same original inode, without reading, copying or hashing its body.
    # Permanent per-round producer reservation excludes a concurrent producer.
    codec.need(not destination.exists(), 'privacy-no-colluder-view-replacement')
    move_original_no_replace(produced, destination)
    for directory in (private_output, destination.parent):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    launch.leaf_metadata(destination, 0o600)
    exported = {'schema': 'kpb-colluder-view-producer-result/v1', 'binding': bound, 'round': round_number,
        'owner_component': 1, 'selection_sha256': selection_sha256, 'public_result': str(receipt_path),
        'public_result_sha256': hashlib.sha256(raw).hexdigest(), 'original_private_leaf_routed': True,
        'private_bodies_read_or_hashed': False, 'network_enabled': False}
    launch.write_new(output / 'LAUNCH.json', exported)
    return exported


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', required=True); parser.add_argument('--selection-sha256', required=True)
    parser.add_argument('--round', type=int, choices=(1, 2), required=True); parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    try: print(json.dumps(run(args.selection, args.selection_sha256, args.round, args.execute), sort_keys=True))
    except BaseException: raise SystemExit('colluder view incomplete; preserve fixed producer state')


if __name__ == '__main__': main()
