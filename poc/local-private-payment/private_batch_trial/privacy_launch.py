#!/usr/bin/env python3
"""Trusted finite network-off launcher. Default validates public inputs only.

Private truth, capsules, counts and captured view leaves are metadata-only host
inputs. Their contents are read only by the selected diagnostic role. Persistent
state derives from the admitted Original trial; a caller cannot choose a new
scoring root, truth path, capsule path or count path.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess

import privacy_codec as codec
import privacy_observer as observer

HERE = Path(__file__).absolute().parent
ROOT = HERE.parents[2]
PRIVATE = Path('/var/tmp/kpi-owner-private-lifecycle-01/private/private-batch-20261028')
BOOTSTRAP_PUBLIC = Path('/var/tmp/kpi-private-batch-bootstrap-20261028')
LIFECYCLE_PUBLIC = Path('/var/tmp/kpi-private-batch-lifecycle-20261028')
METHOD = ROOT / 'research/next-session/local-private-payment/private-batch-2026-10-28/PRIVACY-METHOD-FREEZE.md'
CORE_PINS = {
    'privacy_codec.py': '9523699d392f7d2c53a47f9ae96a2ce95099e6a26e3d47d27a0f4908a55455f4',
    'privacy_observer.py': 'f152b5745a0382de59f472885eba58c6eff910426016e3c7281437ee7967c3bd',
    'privacy_owner.py': 'cbc19629d7328ba1e416b62720d5edfe8d0e7be3a98a7c71ecaddcda68cc4198',
    'privacy_roles.py': '835d1c92e7ec9436c31423adef0d24adb2f400cac4e479e99cb26fc39af7bed8'}
DOMAIN = 'a0a1b4fbf4ce8505f17b24b354ffa81fc4201dc1e130b0358e3bc849611186e0'
PROFILE = 'ea19260a60a8d0a54b8ad9848f82317c1d84059a1881be34d318bcca42493700'
DIAGNOSTIC = 'private-batch-privacy'
need = codec.need


def checked(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'privacy-absolute-finite-path')
    need(not any(part.is_symlink() for part in (path, *path.parents)), 'privacy-no-symlink-route')
    return path


def leaf_metadata(path, mode, size=None):
    path = checked(path); row = path.lstat()
    need(stat.S_ISREG(row.st_mode) and row.st_nlink == 1 and row.st_uid == os.getuid()
         and stat.S_IMODE(row.st_mode) == mode, 'privacy-original-owned-single-link-leaf-metadata')
    need(size is None or row.st_size == size, 'privacy-original-leaf-size-metadata')
    return path


def mkdir(path):
    path = checked(path)
    if not path.exists():
        mkdir(path.parent); path.mkdir(mode=0o700)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), 'privacy-owned-state-directory')
    return path


def write_new(path, value, mode=0o400):
    path = checked(path); raw = value if type(value) is bytes else codec.encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)
    return hashlib.sha256(raw).hexdigest()


def public_ref(row, read):
    codec.fields(row, ('path', 'sha256'))
    path, expected = checked(row['path']), codec.word(row['sha256'])
    raw = read(path, expected)
    return path, raw


def named_public(row, read):
    path, raw = public_ref(row, read)
    return path, codec.parse(raw), raw


def owner_directory(root, row):
    component = codec.owner(row['owner_component'])
    path = checked(row['private_output_directory'])
    relative = path.relative_to(root / 'operations')
    need(len(relative.parts) == 2 and relative.parts[-1] == 'owner-' + str(component)
         and re.fullmatch(r'[a-z][a-z0-9-]{0,63}', relative.parts[0]), 'privacy-actual-owner-operation-route')
    return path


def operation(row, read, trial, private, round_number, kind):
    path, value, raw = named_public(row, read)
    need(path.name == 'RESULT.json' and path.parent.parent == LIFECYCLE_PUBLIC,
         'privacy-selected-actual-operation-result-path')
    need(value['schema'] == 'kpb-original-lifecycle-controller-result/v1'
         and value['bootstrap_trial_id'] == trial['trial_id'] and value['operation'] == kind
         and type(value['round']) is int and value['round'] == round_number
         and value['controller_read_or_hashed_private_bodies'] is False
         and value['native_settlement_or_privacy_qualification'] is False
         and [part['owner_component'] for part in value['owners']] == [0, 1, 2],
         'privacy-actual-all-owner-operation-identity')
    codec.need(type(value['operation_id']) is str and bool(value['operation_id']), 'privacy-operation-id')
    for part in value['owners']:
        own = owner_directory(private, part)
        need(own.parent.name == path.parent.name, 'privacy-same-actual-public-private-operation-label')
        receipt = part['status']
        need(receipt['schema'] == 'kpb-original-lifecycle-operation/v1' and receipt['operation'] == kind
             and receipt['private_original_or_witness_exported'] is False
             and receipt['accepted_backing_or_native_settlement'] is False,
             'privacy-typed-actual-owner-operation-receipt')
        public = checked(part['public_receipt'])
        need(public == path.parent / ('owner-' + str(part['owner_component'])) / 'PUBLIC.json',
             'privacy-exact-actual-owner-public-leaf')
        need(codec.parse(read(public)) == receipt, 'privacy-operation-inline-public-receipt-equality')
    return path, value, raw


def admitted(selection_path, selection_sha256, read):
    raw = read(checked(selection_path), codec.word(selection_sha256)); selected = codec.parse(raw)
    codec.fields(selected, ('schema', 'binding', 'run_selection', 'bootstrap_trial', 'source_members',
                            'rounds', 'corrupt_server_view'))
    need(selected['schema'] == 'kpb-private-diagnostic-launch-selection/v1', 'privacy-selected-finite-launch-schema')
    bound = codec.binding(selected['binding'])
    _, run_raw = public_ref(selected['run_selection'], read)
    need(hashlib.sha256(run_raw).hexdigest() == bound['selection_sha256']
         and hashlib.sha256(read(METHOD)).hexdigest() == bound['method_sha256'], 'privacy-same-frozen-method-run-selection')
    trial_path, trial, _ = named_public(selected['bootstrap_trial'], read)
    need(trial['schema'] == 'kpb-fresh-unfunded-private-original-trial/v1'
         and trial['trial_id'] == bound['trial_id'] and trial['domain_hex32'] == DOMAIN
         and trial['profile_id_hex32'] == PROFILE and trial['network_id'] == 'testnet-10'
         and trial['owner_count'] == 3 and trial['controller_read_or_hashed_private_bodies'] is False,
         'privacy-same-genuine-new-Original-trial')
    label = trial['label']; need(type(label) is str and re.fullmatch(r'[a-z][a-z0-9-]{0,63}', label), 'privacy-trial-label')
    need(trial_path == BOOTSTRAP_PUBLIC / label / 'TRIAL.json', 'privacy-exact-bootstrap-public-route')
    private = checked(trial['private_original_parent'])
    need(private == PRIVATE / label, 'privacy-fixed-Original-trial-parent')
    names = [row['name'] for row in selected['source_members']]
    need(names == [*CORE_PINS, 'privacy_launch.py'], 'privacy-finite-exact-launch-source-closure')
    sources = []
    for row in selected['source_members']:
        codec.fields(row, ('name', 'sha256')); name = row['name']; pin = codec.word(row['sha256'])
        need(name not in CORE_PINS or pin == CORE_PINS[name], 'privacy-unchanged-qualified-core-source')
        data = read(HERE / name, pin)
        sources.append((name, pin, data))
    need([part['round'] for part in selected['rounds']] == [1, 2], 'privacy-fixed-both-round-selection')
    rounds = []
    for part in selected['rounds']:
        codec.fields(part, ('round', 'invoice_result', 'pay_result', 'projection', 'dispatcher_artifacts'))
        r = part['round']
        invoice_path, invoices, invoice_raw = operation(part['invoice_result'], read, trial, private, r, 'invoice')
        pay_path, payments, pay_raw = operation(part['pay_result'], read, trial, private, r, 'pay')
        projection_path, projection = public_ref(part['projection'], read)
        observer.batch_from_projection(r, projection)
        routes = []
        for component in codec.OWNERS:
            route_path = pay_path.parent / ('owner-' + str(component)) / 'OBSERVED-INVOICE-ROUTE.json'
            route_raw = read(route_path); route = observer.route_record(codec.parse(route_raw))
            target = (component + r) % 3
            need(route['round'] == r and route['source_owner_component'] == component
                 and route['target_owner_component'] == target and route['source_operation_id'] == payments['operation_id']
                 and route['target_invoice_operation_id'] == invoices['operation_id']
                 and checked(route['invoice_leaf_path']) == owner_directory(private, invoices['owners'][target]) / 'INVOICE208.bin',
                 'privacy-actual-trusted-IPC-route-not-asserted-count')
            routes.append((route_path, route_raw))
        for artifact in part['dispatcher_artifacts']:
            codec.fields(artifact, ('kind', 'path', 'sha256', 'route_owner'))
            if artifact['route_owner'] is not None: codec.owner(artifact['route_owner'])
            if artifact['kind'] == 'invoice-route':
                extra_path, extra_raw = public_ref({'path': artifact['path'], 'sha256': artifact['sha256']}, read)
                extra = observer.route_record(codec.parse(extra_raw))
                need(extra_path.is_relative_to(LIFECYCLE_PUBLIC) and extra_path.name == 'OBSERVED-INVOICE-ROUTE.json'
                     and extra['round'] == r and extra['source_owner_component'] == artifact['route_owner']
                     and checked(extra['invoice_leaf_path']).is_relative_to(private / 'operations'),
                     'privacy-retained-additional-actual-route-attempt')
            else:
                need(artifact['kind'] in ('dispatcher-metadata', 'terminal-raw') and artifact['sha256'] is None,
                     'privacy-captured-private-dispatcher-view-no-host-hash')
                capture_root = private / 'diagnostics' / DIAGNOSTIC / 'dispatcher-capture' / ('round-' + str(r))
                need(checked(artifact['path']).is_relative_to(capture_root), 'privacy-fixed-dispatcher-capture-root-no-truth')
        rounds.append({'round': r, 'payments': payments, 'projection': (projection_path, projection), 'routes': routes,
                       'metadata': [(invoice_path, invoice_raw), (pay_path, pay_raw)], 'artifacts': part['dispatcher_artifacts']})
    capture = selected['corrupt_server_view']
    if capture is not None:
        codec.fields(capture, ('owner_component', 'root', 'relative_leaves'))
        need(type(capture['owner_component']) is int and capture['owner_component'] == 1
             and type(capture['relative_leaves']) is list and len(capture['relative_leaves']) == len(set(capture['relative_leaves'])),
             'privacy-only-declared-corrupt-server-one')
        server_root = checked(capture['root'])
        need(server_root == private / 'diagnostics' / DIAGNOSTIC / 'corrupt-server-1',
             'privacy-fixed-corrupt-server-one-capture-root-no-Original')
        for leaf in capture['relative_leaves']:
            need(type(leaf) is str and leaf and not Path(leaf).is_absolute() and '..' not in Path(leaf).parts,
                 'privacy-finite-corrupt-server-capture-leaves')
            checked(server_root / leaf)
    return selected, trial_path.parent, private, sources, rounds


def read_observation(public, bound, read):
    path = public / 'observe' / 'PUBLIC.json'; raw = read(path); value = codec.parse(raw)
    codec.fields(value, ('schema', 'binding', 'views', 'predictions_frozen_before_truth', 'private_view_or_prediction_records_exported'))
    need(value['schema'] == 'kpb-direct-observation-receipt/v1' and value['binding'] == bound
         and value['predictions_frozen_before_truth'] is True and value['private_view_or_prediction_records_exported'] is False
         and [row['view'] for row in value['views']] == list(codec.VIEWS), 'privacy-actual-observation-count-only-receipt')
    for row in value['views']:
        codec.word(row['capsule_seal_sha256'])
        need(type(row['capsule_bytes']) is int and row['capsule_bytes'] > 32, 'privacy-positive-capsule-size')
    return path, raw, value


def public_barrier(public, bound, selection_sha256, read):
    _, observation_raw, observation = read_observation(public, bound, read)
    barrier_path = public / 'observe' / 'BARRIER.json'
    leaf_metadata(barrier_path, 0o400); barrier_raw = read(barrier_path)
    need(codec.parse(barrier_raw) == {'schema': 'kpb-direct-prediction-barrier/v1', 'binding': bound,
         'observation_receipt_sha256': hashlib.sha256(observation_raw).hexdigest(),
         'capsules': [{'view': row['view'], 'capsule_seal_sha256': row['capsule_seal_sha256']} for row in observation['views']]},
         'privacy-public-barrier-exactly-precedes-truth-join')
    launch_path = public / 'observe' / 'LAUNCH.json'
    leaf_metadata(launch_path, 0o400); completed = codec.parse(read(launch_path))
    need(completed['schema'] == 'kpb-private-diagnostic-launch-result/v1'
         and completed['operation'] == 'observe' and completed['binding'] == bound
         and completed['selection_sha256'] == selection_sha256
         and completed['public_result_sha256'] == hashlib.sha256(observation_raw).hexdigest()
         and completed['persistent_query_consumed'] is True
         and completed['private_bodies_read_or_hashed'] is False and completed['network_enabled'] is False,
         'privacy-actual-completed-observer-before-truth')
    return observation_raw, observation, barrier_raw


def run(operation_name, selection_path, selection_sha256, owner_component=None, execute=False):
    need(operation_name in ('observe', 'score', 'aggregate'), 'privacy-finite-launch-operation')
    need((operation_name == 'score' and type(owner_component) is int and owner_component in codec.OWNERS)
         or (operation_name != 'score' and owner_component is None), 'privacy-exact-single-scorer-owner')
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    selected, trial_public, private, sources, rounds = admitted(selection_path, selection_sha256, read)
    bound = selected['binding']; public = trial_public / 'privacy-diagnostics'
    state_root = private / 'diagnostics' / DIAGNOSTIC
    state = (private / ('owner-' + str(owner_component)) / 'diagnostics' / DIAGNOSTIC
             if operation_name == 'score' else state_root / operation_name)
    output = public / (operation_name + ('-owner-' + str(owner_component) if operation_name == 'score' else ''))
    if not execute:
        return {'schema': 'kpb-private-diagnostic-launch-plan/v1', 'operation': operation_name,
                'binding': bound, 'executed': False, 'private_bodies_read_or_hashed': False}
    frozen_public = None
    if operation_name != 'observe':
        # Public-only qualification happens before consuming a score slot. The
        # fixed consume below still precedes all capsule/truth content reads.
        frozen_public = public_barrier(public, bound, selection_sha256, read)
        leaf_metadata(state_root / 'observe' / 'OBSERVATION-CLOSED', 0o400)
    mkdir(state); need(not output.exists(), 'privacy-no-repeated-diagnostic-public-output')
    mkdir(output); shared = mkdir(output / 'selected-public')
    # A launcher failure consumes the same persistent query too. Neither a new
    # output path nor a fresh attempt ID resets this fixed Original trial state.
    write_new(state / 'LAUNCH-CLOSED', {'operation': operation_name, 'binding': bound, 'selection_sha256': selection_sha256})
    mounts, source_members = [], []
    for name, pin, raw in sources:
        leaf = shared / name; write_new(leaf, raw); alias = '/software/' + name
        mounts += ['--ro-bind', str(leaf), alias]; source_members.append({'path': alias, 'sha256': pin})
    config = {'binding': bound, 'source_members': source_members}
    def public_mount(name, raw):
        leaf = shared / name; pin = write_new(leaf, raw); alias = '/public/' + name
        mounts.extend(['--ro-bind', str(leaf), alias]); return {'path': alias, 'sha256': pin}
    def private_mount(path, alias, mode, size=None):
        leaf_metadata(path, mode, size); mounts.extend(['--ro-bind', str(path), alias]); return alias
    if operation_name == 'observe':
        parts = []
        for part in rounds:
            r = part['round']; projection = public_mount('projection-' + str(r) + '.bin', part['projection'][1])
            artifacts = []
            for index, (_, raw) in enumerate(part['metadata']):
                ref = public_mount('metadata-' + str(r) + '-' + str(index) + '.json', raw)
                artifacts.append({'kind': 'dispatcher-metadata', **ref, 'route_owner': None})
            for component, (_, raw) in enumerate(part['routes']):
                ref = public_mount('route-' + str(r) + '-' + str(component) + '.json', raw)
                artifacts.append({'kind': 'invoice-route', **ref, 'route_owner': component})
            for index, artifact in enumerate(part['artifacts']):
                if artifact['kind'] == 'invoice-route':
                    raw = read(checked(artifact['path']), artifact['sha256'])
                    ref = public_mount('extra-route-' + str(r) + '-' + str(index) + '.json', raw)
                    artifacts.append({**artifact, **ref})
                else:
                    path = private_mount(checked(artifact['path']), '/dispatcher/' + str(r) + '-' + str(index), 0o600)
                    artifacts.append({**artifact, 'path': path})
            colluder = owner_directory(private, part['payments']['owners'][1]) / 'COLLUDER-CONSTRAINTS.json'
            facts = private_mount(colluder, '/colluder/round' + str(r) + '.json', 0o600) if colluder.exists() else None
            parts.append({'round': r, 'projection': projection, 'artifacts': artifacts, 'colluder_constraints': facts})
        server_artifacts = []
        if selected['corrupt_server_view'] is not None:
            capture = selected['corrupt_server_view']
            for index, leaf in enumerate(capture['relative_leaves']):
                path = private_mount(checked(capture['root']) / leaf, '/corrupt-server/leaf-' + str(index), 0o600)
                server_artifacts.append({'kind': 'corrupt-server-raw', 'path': path, 'sha256': None, 'route_owner': None})
        config['views'] = []
        for view in codec.VIEWS:
            values = []
            for part in parts:
                artifacts = []
                if view in ('dispatcher', 'union'): artifacts.extend(part['artifacts'])
                if view in ('corrupt-server-plus-wallet', 'union'): artifacts.extend(server_artifacts)
                values.append({**part, 'artifacts': artifacts,
                    'colluder_constraints': part['colluder_constraints'] if view in ('corrupt-server-plus-wallet', 'union') else None})
            config['views'].append({'view': view, 'rounds': values})
    else:
        observation_raw, observation, barrier_raw = frozen_public
        config['barrier'] = public_mount('BARRIER.json', barrier_raw)
        config['observation_receipt'] = public_mount('OBSERVATION.json', observation_raw)
        config['capsules'] = []
        for row in observation['views']:
            view = row['view']; alias = '/capsules/' + view + '.bin'
            private_mount(state_root / 'observe' / ('PREDICTIONS-' + view + '.bin'), alias, 0o400, row['capsule_bytes'])
            config['capsules'].append({'view': view, 'path': alias})
        if operation_name == 'score':
            config['owner_component'] = owner_component; config['truth_commitments'] = []
            for part in rounds:
                r = part['round']; own = owner_directory(private, part['payments']['owners'][owner_component])
                private_mount(own / 'PRIVACY-TRUTH.json', '/truth/round' + str(r) + '.json', 0o600)
                commit_path = checked(part['payments']['owners'][owner_component]['public_receipt']).parent / 'PRIVACY-COMMITMENT.json'
                commit_raw = read(commit_path); commit = codec.parse(commit_raw)
                need(commit['schema'] == 'kpb-owner-truth-commitment/v1' and commit['binding'] == bound
                     and commit['owner_component'] == owner_component and commit['round'] == r
                     and commit['truth_or_identifiers_exported'] is False, 'privacy-original-public-own-truth-commitment')
                config['truth_commitments'].append(public_mount('commit-' + str(r) + '.json', commit_raw))
        else:
            config['count_files'] = []
            for component in codec.OWNERS:
                leaf = private / ('owner-' + str(component)) / 'diagnostics' / DIAGNOSTIC / 'COUNTS.json'
                config['count_files'].append(private_mount(leaf, '/counts/owner-' + str(component) + '.json', 0o400))
    config_path, marker_path = state / 'PRIVATE-CONFIG.json', state / 'PRIVATE-NAMESPACE.json'
    write_new(config_path, config, 0o600)
    write_new(marker_path, {'schema': 'kpb-private-diagnostic-namespace/v1', 'operation': operation_name,
        'network': 'disabled', 'truth_owner_slots': 1 if operation_name == 'score' else 0,
        'colluder_owner_slots': 1 if operation_name == 'observe' else 0,
        'corrupt_server_slots': 1 if operation_name == 'observe' else 0})
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', *mounts,
        '--ro-bind', str(config_path), '/CONFIG.json', '--ro-bind', str(marker_path), '/NAMESPACE.json',
        '--bind', str(state), '/state', '--bind', str(output), '/out',
        '/usr/bin/python3', '-B', '-S', '/software/privacy_roles.py', operation_name]
    # These FD-only private logs/configs are never reopened or hashed by host.
    write_new(state / 'PRIVATE-PLAN.json', {'command': command}, 0o600)
    with (state / 'PRIVATE-STDOUT.log').open('xb') as stdout, (state / 'PRIVATE-STDERR.log').open('xb') as stderr:
        process = subprocess.run(command, stdout=stdout, stderr=stderr, env={'PATH': '/usr/bin:/bin'})
    need(process.returncode == 0, 'privacy-isolated-role-incomplete-retain-used-query')
    if operation_name == 'observe':
        _, obs_raw, observation = read_observation(public, bound, read)
        for row in observation['views']:
            leaf_metadata(state / ('PREDICTIONS-' + row['view'] + '.bin'), 0o400, row['capsule_bytes'])
        write_new(output / 'BARRIER.json', {'schema': 'kpb-direct-prediction-barrier/v1', 'binding': bound,
            'observation_receipt_sha256': hashlib.sha256(obs_raw).hexdigest(),
            'capsules': [{'view': row['view'], 'capsule_seal_sha256': row['capsule_seal_sha256']} for row in observation['views']]})
    elif operation_name == 'score':
        leaf_metadata(state / 'COUNTS.json', 0o400)
    receipt_path = output / 'PUBLIC.json'; receipt_raw = read(receipt_path); receipt = codec.parse(receipt_raw)
    expected = {'score': 'kpb-private-score-completed/v1', 'aggregate': 'kpb-public-all-view-direct-counts/v1',
                'observe': 'kpb-direct-observation-receipt/v1'}[operation_name]
    need(receipt['schema'] == expected and receipt['binding'] == bound, 'privacy-exact-public-role-completion')
    launch = {'schema': 'kpb-private-diagnostic-launch-result/v1', 'operation': operation_name,
        'binding': bound, 'selection_sha256': selection_sha256, 'public_result': str(receipt_path),
        'public_result_sha256': hashlib.sha256(receipt_raw).hexdigest(), 'persistent_query_consumed': True,
        'private_bodies_read_or_hashed': False, 'network_enabled': False}
    write_new(output / 'LAUNCH.json', launch)
    return launch


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('observe', 'score', 'aggregate'))
    parser.add_argument('--selection', required=True); parser.add_argument('--selection-sha256', required=True)
    parser.add_argument('--owner-component', type=int, choices=(0, 1, 2)); parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    try: print(json.dumps(run(args.operation, args.selection, args.selection_sha256, args.owner_component, args.execute), sort_keys=True))
    except BaseException: raise SystemExit('private diagnostic incomplete; preserve fixed consumed state')


if __name__ == '__main__': main()
