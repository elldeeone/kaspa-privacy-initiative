#!/usr/bin/env python3
"""Stage/run the frozen METHOD02 component study without controller secret IO.

This is a bounded unfunded privacy fixture, never a funding/broadcast launcher.
All Originals, plans, invoices, sender records and predictions stay in closed
roles. Only explicit public rows/proofs/CASEs/status and post-seal counts export.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import time
import uuid

from payout_linkage_guard import load_guard
_GUARDED = load_guard()

import exit_wire
import new_private_trial as bootstrap
import private_lifecycle as lifecycle
import private_worker as boundary
import wallet_history

HERE, ROOT = Path(__file__).absolute().parent, Path(__file__).absolute().parents[3]
METHOD = ROOT / 'research/next-session/local-private-payment/private-batch-2026-10-28/PRIVACY-PAYOUT-LINKAGE-METHOD-02-FREEZE.md'
METHOD_SHA = 'dc5026741ccc3bf8d19105a1528257d6934ed76877ec1fc3fe19e3e2b586834d'
TRIAL = Path('/var/tmp/kpi-private-batch-bootstrap-20261028/new-profile-original-01/TRIAL.json')
TRIAL_SHA = '2190cac2c541cc8a4acf805d8c65b5eb36fd9347fcd5d279e8d4ad543bcc61d3'
PARAMETERS = ROOT / '.local/private-batch-public-native-final-parameters-01/PARAMETERS.json'
PARAMETERS_SHA = '3f9f2f294c8203c8fc99ba66e1a78e769a1eecc4ecc5cf8f8b631eea28138751'
TAIL = PARAMETERS.parent / 'IMMUTABLE-TAIL.bin'
TAIL_SHA = '4081fc4efb08131bba7b64c38cfe002a3456c8a8a93394622ee9085e3706435d'
CODEC = Path('/var/tmp/kpi-local-private-native-target-01/release/kpi-private-batch-native')
CODEC_SHA = 'cc498d61898d15e077f483f8786d2b5993e0bd2a89e30a01d8489e03a31103c7'
NATIVE = Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/native-validator')
NATIVE_SHA = '077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061'
BASELINE = ROOT / '.local/fresh-self-payout-baseline-20261028-01/wallet_profile.py'
BASELINE_SHA = '04a7f4da5d5b9a512e8e7e86fb29119961cef771ae1f532a77ce3840443816e5'
need, parse, save = bootstrap.need, boundary.parse, bootstrap.save


def guard():
    return _GUARDED['read']


def reference(path, read, expected=None):
    path = bootstrap.checked(path)
    raw = read(path, expected)
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}


def stage(args):
    read = guard()
    need(re.fullmatch('[a-z][a-z0-9-]{0,35}', args.label), 'method02-short-fresh-label')
    trial = parse(read(TRIAL, TRIAL_SHA))
    read(METHOD, METHOD_SHA)
    original = bootstrap.checked(trial['private_original_parent'])
    need(original.parent == bootstrap.PRIVATE and original.name == trial['label']
         and trial['owner_count'] == 3 and trial['controller_read_or_hashed_private_bodies'] is False,
         'method02-exact-admitted-Original-set')
    public = ROOT / '.local/private-payout-linkage-02' / args.label
    private = original / 'diagnostics/private-payout-linkage-02' / args.label
    need(not public.exists() and not private.exists(), 'method02-unused-identity')
    public.mkdir(parents=True, mode=0o700); private.mkdir(parents=True, mode=0o700)
    shared = public / 'selected-public'; shared.mkdir(mode=0o700)
    sources = lifecycle.source_selection(shared, read, 'exit')
    extra = (HERE / 'payout_linkage_worker.py', HERE / 'payout_linkage_original.py',
             HERE / 'payout_linkage_native.py', HERE / 'payout_linkage_observe.py',
             HERE / 'payout_linkage_measure.py', HERE / 'payout_linkage_guard.py', HERE / 'payout_linkage_entry.py',
             HERE / 'payout_privacy_attack.py', HERE / 'exit_release.py', HERE / 'genesis.py', BASELINE)
    for path in extra:
        raw = read(path, BASELINE_SHA if path == BASELINE else None)
        index = len(sources); save(shared / ('source-' + str(index)), raw)
        sources.append({'index': index, 'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)})
    # Include ordinary local Python imports used by the selected controllers,
    # without broad runtime/SDK copying. Dynamic mature codec/tree imports are
    # already explicit in the established owner source selection.
    import ast
    examined = set()
    while True:
        pending = [row for row in sources if row['path'].endswith('.py') and row['path'] not in examined]
        if not pending:
            break
        for row in pending:
            examined.add(row['path'])
            tree = ast.parse(read(shared / ('source-' + str(row['index'])), row['sha256']))
            for node in ast.walk(tree):
                names = ([item.name for item in node.names] if isinstance(node, ast.Import)
                         else [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
                for name in names:
                    path = HERE / (name.split('.')[0] + '.py')
                    if path.is_file() and not any(item['path'] == str(path) for item in sources):
                        raw = read(path); index = len(sources)
                        save(shared / ('source-' + str(index)), raw)
                        sources.append({'index': index, 'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)})
    runtimes = lifecycle.selected_runtime(read, 'exit')
    runtime_rows = [{'path': alias, 'host_path': str(path), 'sha256': pin} for alias, path, pin in runtimes]
    descriptor = parse(read(bootstrap.PROFILE, bootstrap.PROFILE_SHA))
    profile = descriptor['profile_descriptor']
    for path, pin, name in ((PARAMETERS, PARAMETERS_SHA, 'PARAMETERS.json'), (TAIL, TAIL_SHA, 'IMMUTABLE-TAIL.bin'),
        (bootstrap.PARAMETERS / 'MANIFEST.json', bootstrap.MANIFEST_SHA, 'OUTPUT-MANIFEST.json'),
        (lifecycle.EXIT_PARAMETERS / 'MANIFEST.json', lifecycle.EXIT_MANIFEST_SHA, 'EXIT-MANIFEST.json'),
        (bootstrap.LEAF_MAP, bootstrap.LEAF_MAP_SHA, 'JS-LEAF-MAP.json')):
        save(shared / name, read(path, pin))
    selected = {'schema': 'kpb-method02-original-source-selection/v1', 'classification': 'UNFUNDED_COMPONENT_PRIVACY_FIXTURE',
        'label': args.label, 'attempt_id': str(uuid.uuid4()), 'trial_id': trial['trial_id'], 'phase': 'private-payout-linkage-02',
        'method': {'path': str(METHOD), 'sha256': METHOD_SHA}, 'trial': {'path': str(TRIAL), 'sha256': TRIAL_SHA},
        'public': str(public), 'private': str(private), 'original_parent': str(original),
        'source_members': sources, 'runtime_members': runtime_rows,
        'js_leaf_map_sha256': bootstrap.LEAF_MAP_SHA, 'baseline_wallet_sha256': BASELINE_SHA,
        'domain_hex32': profile['domain_hex32'], 'profile_hex32': descriptor['profile_id_hex32'],
        'binary_sha256': bootstrap.BINARY_SHA, 'output_manifest_sha256': bootstrap.MANIFEST_SHA,
        'exit_manifest_sha256': lifecycle.EXIT_MANIFEST_SHA, 'tail_sha256': TAIL_SHA,
        'codec': reference(CODEC, read, CODEC_SHA), 'native_validator': reference(NATIVE, read, NATIVE_SHA),
        'arms': {'A': {'index': 7, 'policy': 'invoice-native'}, 'B': {'index': 9, 'policy': 'fresh-self'}},
        'value_sompi': 200_000_000, 'fee_sompi': 1, 'reserve_sompi': 6_000_000_000,
        'private_receiver_choices': 'one private random bijection; self choices allowed; no public cyclic schedule',
        'contact_acquisition': 'corrupt owner1 actually receives private index7/9 invoices from all three contacts',
        'shared_public_projection_scope': 'independent hypothetical continuing heads; no accepted chain or backing',
        'dispatcher_view': 'retain actual existing owner-labelled exit_release argv/mounts/routes/timing',
        'funding_network_broadcast_available': False, 'controller_private_body_read_or_hash': False,
        'resources': {'parallel_owner_roles': 2, 'Rayon_threads_per_role': 3,
                      'foreground_CPU_total': 6, 'expected_two_proof_peak_GiB_from_public_control': 7.4,
                      'timeout_abort': False},
        'observation_and_scoring': 'separate source-pinned closed roles; generation does not release a privacy result'}
    pin = save(public / 'SELECTION.json', selected)
    return {'selection': str(public / 'SELECTION.json'), 'sha256': pin, 'status': 'STAGED_BEFORE_PRIVATE_GENERATION'}


def load_selection(path, pin, read):
    selected = parse(read(bootstrap.checked(path), pin))
    need(selected['schema'] == 'kpb-method02-original-source-selection/v1'
         and selected['method']['sha256'] == METHOD_SHA and selected['trial']['sha256'] == TRIAL_SHA,
         'method02-fixed-method-and-Original-selection')
    read(METHOD, METHOD_SHA)
    shared = Path(selected['public']) / 'selected-public'
    for row in selected['source_members']:
        read(shared / ('source-' + str(row['index'])), row['sha256'])
    return selected


def run_role(selected, selection_sha, operation, name, own, out, mounts, *, slot=None, arm=None, original=False, **extra):
    read = guard()
    shared = Path(selected['public']) / 'selected-public'
    own.mkdir(mode=0o700, parents=True); out.mkdir(mode=0o700, parents=True)
    config = {key: selected[key] for key in ('domain_hex32', 'profile_hex32', 'binary_sha256', 'output_manifest_sha256',
        'exit_manifest_sha256', 'js_leaf_map_sha256', 'baseline_wallet_sha256', 'tail_sha256')}
    config.update(binding={'method_sha256': METHOD_SHA, 'selection_sha256': selection_sha,
        'trial_id': selected['trial_id'], 'phase': selected['phase'], 'attempt_id': selected['attempt_id']},
        source_members=[{'path': row['path'], 'sha256': row['sha256']} for row in selected['source_members']],
        runtime_members=[{'path': row['path'], 'sha256': row['sha256']} for row in selected['runtime_members']],
        owner_component=slot, arm=arm, **extra)
    config_path, marker = shared / (name + '-CONFIG.json'), shared / (name + '-NAMESPACE.json')
    save(config_path, config)
    save(marker, {'schema': 'kpb-method02-namespace/v1', 'network': 'disabled', 'operation': operation,
                  'Original_slots': 1 if original else 0})
    selected_mounts = []
    for row in selected['source_members']:
        selected_mounts += ['--ro-bind', str(shared / ('source-' + str(row['index']))), row['path']]
    for row in selected['runtime_members']:
        read(Path(row['host_path']), row['sha256'])
        selected_mounts += ['--ro-bind', row['host_path'], row['path']]
    if original:
        backup = lifecycle.private_leaf(Path(selected['original_parent']) / ('owner-' + str(slot)) / 'BACKUP.json')
        selected_mounts += ['--ro-bind', str(backup), '/original/BACKUP.json']
    selected_mounts += ['--ro-bind', str(bootstrap.JS_ROOT / 'node_modules'), '/runtime/js/node_modules',
        '--ro-bind', str(bootstrap.JS_ROOT / 'node_modules'), '/src/node_modules',
        '--ro-bind', str(shared / 'JS-LEAF-MAP.json'), '/runtime/JS-INSTALLED-LEAF-MAP.json',
        '--ro-bind', str(shared / 'OUTPUT-MANIFEST.json'), '/output-parameters/MANIFEST.json',
        '--ro-bind', str(bootstrap.PARAMETERS / 'parameters.pk'), '/output-parameters/parameters.pk',
        '--ro-bind', str(shared / 'EXIT-MANIFEST.json'), '/exit-parameters/MANIFEST.json',
        '--ro-bind', str(lifecycle.EXIT_PARAMETERS / 'parameters.pk'), '/exit-parameters/parameters.pk',
        '--ro-bind', str(shared / 'IMMUTABLE-TAIL.bin'), '/policy/IMMUTABLE-TAIL.bin',
        '--ro-bind', str(shared / ('source-' + str(next(row['index'] for row in selected['source_members']
            if row['path'] == str(BASELINE))))), '/baseline/wallet_profile.py']
    argv = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
        *selected_mounts, *mounts, '--ro-bind', str(config_path), '/CONFIG.json', '--ro-bind', str(marker), '/NAMESPACE.json',
        '--bind', str(own), '/owner', '--bind', str(out), '/out', '--chdir', '/owner', '--setenv', 'PATH', '/usr/bin:/bin',
        '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'RAYON_NUM_THREADS', '3', '/usr/bin/python3', '-B',
        str(HERE / 'payout_linkage_worker.py'), operation]
    started = time.monotonic_ns()
    with (own / 'STDOUT.log').open('xb') as stdout, (own / 'STDERR.log').open('xb') as stderr:
        completed = subprocess.run(argv, stdout=stdout, stderr=stderr, env=bootstrap.CLEAN)
    save(out / 'ROUTE.json', {'schema': 'kpb-method02-actual-role-route/v1', 'role': name, 'operation': operation,
        'owner_component': slot, 'arm': arm, 'argv': argv, 'started_monotonic_ns': started,
        'completed_monotonic_ns': time.monotonic_ns(), 'returncode': completed.returncode})
    need(completed.returncode == 0, 'method02-role-failed-' + name)
    return reference(out / 'PUBLIC.json', read)


def history_from_notes(notes, arm):
    value = notes['arms'][arm]
    head = exit_wire.HeadContext.parse(bytes.fromhex(value['context_hex276']))
    origin = {'outpoint_hex36': head.point.hex(), 'state_hex112': head.state().hex(),
              'reserve_sompi': head.reserve, 'outputs_hex520': value['rows_hex520']}
    return {'schema': 'kpb-private-batch-public-history/v1', 'scope': wallet_history.SCOPE,
        **dict(zip(('chain_hex32', 'pool_hex32', 'profile_hex32', 'domain_hex32', 'service_hex32'),
                   (word.hex() for word in (head.chain, head.pool, head.profile, head.domain, head.service)))),
        'genesis': origin, 'transitions': [], 'head': {key: origin[key] for key in
            ('outpoint_hex36', 'state_hex112', 'reserve_sompi')}}


def execute(args):
    read = guard()
    selected = load_selection(args.selection, args.selection_sha256, read)
    public, private = Path(selected['public']), Path(selected['private'])
    # One fixed admitted-Original study reservation, independent of output label.
    closed = Path(selected['original_parent']) / 'diagnostics/private-payout-linkage-02/GENERATION-CLOSED.json'
    boundary.write(closed, {'selection_sha256': args.selection_sha256, 'method_sha256': METHOD_SHA,
                           'trial_id': selected['trial_id']})
    receipts = []
    for slot in range(3):
        receipts.append(run_role(selected, args.selection_sha256, 'invoice', 'invoice-' + str(slot),
            private / ('invoice-' + str(slot)), public / ('invoice-' + str(slot)), [], slot=slot, original=True))
    invoice_mounts = sum((['--ro-bind', str(private / ('invoice-' + str(slot)) / ('INVOICE-' + arm + '.bin')),
                          '/invoices/owner-' + str(slot) + '/INVOICE-' + arm + '.bin']
                         for slot in range(3) for arm in ('A', 'B')), [])
    receipts.append(run_role(selected, args.selection_sha256, 'plans', 'private-plans', private / 'plans', public / 'plans', invoice_mounts))
    for slot in range(3):
        receipts.append(run_role(selected, args.selection_sha256, 'construct', 'construct-' + str(slot),
            private / ('construct-' + str(slot)), public / ('construct-' + str(slot)),
            sum((['--ro-bind', str(private / 'plans' / ('owner-' + str(slot)) / name), '/plan/' + name]
                 for name in ('PLAN.json', 'INVOICE-A.bin', 'INVOICE-B.bin')), []), slot=slot, original=True))
    row_mounts = sum((['--ro-bind', str(private / ('construct-' + str(slot)) / ('ROW-' + arm + '.bin')),
                      '/rows/owner-' + str(slot) + '/ROW-' + arm + '.bin'] for slot in range(3) for arm in ('A', 'B')), [])
    receipts.append(run_role(selected, args.selection_sha256, 'feed', 'common-notes', private / 'collector', public / 'notes', row_mounts))
    notes_path = public / 'notes/NOTES.json'
    notes_ref = reference(notes_path, read); notes = parse(read(notes_path, notes_ref['sha256']))
    release_refs = {'A': [], 'B': []}
    original = Path(selected['original_parent'])
    for arm in ('A', 'B'):
        arm_started = time.monotonic()
        history_path = public / ('COMPONENT-HISTORY-' + arm + '.json')
        history_sha = save(history_path, history_from_notes(notes, arm))
        # This is explicitly NOT strict 20-KAS GEN3 admission. It is the frozen
        # 200M-note/6B-reserve supplied component shape, with no backing claim.
        operation_label = selected['label'] + '-' + arm.lower() + '-proof'
        operation_id = str(uuid.uuid4())
        operation_public = public / ('prepared-' + arm)
        operation_public.mkdir(mode=0o700)
        owners = []
        def prove_owner(slot):
            own = original / 'operations' / operation_label / ('owner-' + str(slot))
            out = operation_public / ('owner-' + str(slot))
            run_role(selected, args.selection_sha256, 'prove', 'prove-' + arm + '-' + str(slot), own, out,
                ['--ro-bind', str(notes_path), '/public/NOTES.json'], slot=slot, arm=arm,
                original=True, notes_sha256=notes_ref['sha256'])
            status = lifecycle.public_receipt(parse(read(out / 'PUBLIC.json')), 'exit')
            return {'owner_component': slot, 'private_output_directory': str(own),
                    'public_receipt': str(out / 'PUBLIC.json'), 'status': status}
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            owners = list(pool.map(prove_owner, range(3)))
        save(operation_public / 'SELECTION.json', {'schema': 'kpb-original-lifecycle-selection/v1',
            'operation': 'exit', 'operation_id': operation_id, 'bootstrap_trial_id': selected['trial_id'],
            'history_sha256': history_sha, 'tail_sha256': TAIL_SHA})
        result = {'schema': 'kpb-original-lifecycle-controller-result/v1', 'scope': wallet_history.SCOPE,
            'operation': 'exit', 'operation_id': operation_id, 'bootstrap_trial_id': selected['trial_id'],
            'round': 1, 'owners': owners, 'controller_read_or_hashed_private_bodies': False,
            'native_settlement_or_privacy_qualification': False, 'wall_seconds': time.monotonic() - arm_started}
        result_sha = save(operation_public / 'RESULT.json', result)
        for slot in range(3):
            label = selected['label'] + '-' + arm.lower() + '-release-' + str(slot)
            entry_row = next(row for row in selected['source_members'] if row['path'] == str(HERE / 'payout_linkage_entry.py'))
            entry_path = Path(selected['public']) / 'selected-public' / ('source-' + str(entry_row['index']))
            read(entry_path, entry_row['sha256'])
            argv = ['/usr/bin/python3', '-B', str(entry_path), '--selection', args.selection,
                '--selection-sha256', args.selection_sha256, 'release', '--label', label,
                '--bootstrap-trial', str(TRIAL), '--bootstrap-trial-sha256', TRIAL_SHA,
                '--prepared-exit-result', str(operation_public / 'RESULT.json'), '--prepared-exit-result-sha256', result_sha,
                '--owner-component', str(slot), '--history', str(history_path), '--history-sha256', history_sha,
                '--tail', str(TAIL), '--tail-sha256', TAIL_SHA, '--execute']
            # The real existing release process, including its owner-labelled
            # paths/route log, is retained as dispatcher evidence.
            with (private / ('RELEASE-' + arm + '-' + str(slot) + '-STDERR.log')).open('xb') as stderr:
                completed = subprocess.run(argv, env=bootstrap.CLEAN, stdout=subprocess.PIPE, stderr=stderr)
            need(completed.returncode == 0, 'method02-actual-owner-labelled-release')
            released = parse(completed.stdout)
            need(released['status'] == 'PUBLIC_EXIT_CANDIDATE_EXPLICITLY_RELEASED', 'method02-release-result')
            release_refs[arm].append({'owner': slot, **reference(Path(released['candidate']), read, released['candidate_sha256']),
                'route': reference(lifecycle.PUBLIC / label / 'OBSERVED-RELEASE-ROUTE.json', read), 'argv': argv})
    mounts = ['--ro-bind', str(private / 'collector/PUBLICATION-ORDER.json'), '/collector/PUBLICATION-ORDER.json']
    for arm in ('A', 'B'):
        for item in release_refs[arm]:
            mounts += ['--ro-bind', item['path'], '/released/' + arm + '/owner-' + str(item['owner']) + '/PUBLIC-CANDIDATE.json']
    receipts.append(run_role(selected, args.selection_sha256, 'publish', 'common-exits', private / 'publish', public / 'exits', mounts))
    exits_ref = reference(public / 'exits/EXITS.json', read)
    contact_mounts = ['--ro-bind', str(private / 'construct-1/OWN-SENDER-RECORD.json'), '/sender/OWN-SENDER-RECORD.json',
        '--ro-bind', str(notes_path), '/public/NOTES.json', '--ro-bind', exits_ref['path'], '/public/EXITS.json']
    contact_mounts += sum((['--ro-bind', str(private / ('invoice-' + str(slot)) / ('INVOICE-' + arm + '.bin')),
                           '/contacts/owner-' + str(slot) + '/INVOICE-' + arm + '.bin']
                          for slot in range(3) for arm in ('A', 'B')), [])
    receipts.append(run_role(selected, args.selection_sha256, 'contact', 'contact-owner-1', private / 'contact-owner-1',
        public / 'contact-owner-1', contact_mounts, slot=1, original=True,
        notes_sha256=notes_ref['sha256'], exits_sha256=exits_ref['sha256']))
    import payout_linkage_native
    native = payout_linkage_native.verify(exits_ref['path'], exits_ref['sha256'], public / 'native-verification')
    native_ref = reference(Path(native['result']), read, native['sha256'])
    exits = parse(read(Path(exits_ref['path']), exits_ref['sha256']))
    dispatcher = {'schema': 'kpb-method02-actual-release-routes/v1', 'binding': exits['binding'], 'arms': {}}
    for arm in ('A', 'B'):
        dispatcher['arms'][arm] = []
        for item in release_refs[arm]:
            released = parse(read(Path(item['path']), item['sha256']))
            exit_id = hashlib.sha256(bytes.fromhex(released['projection_hex'])).hexdigest()
            dispatcher['arms'][arm].append({'owner': item['owner'], 'exit_id': exit_id,
                'provenance': 'actual owner-labelled exit_release argv/path/route/timings ' + item['route']['path'],
                'actual_release_route_ref': item['route']['path'] + ' SHA256=' + item['route']['sha256']})
    dispatcher_sha = save(public / 'DISPATCHER.json', dispatcher)
    catalog = {'schema': 'kpb-method02-generated-artifact-catalog/v1', 'selection_sha256': args.selection_sha256,
        'method_sha256': METHOD_SHA, 'trial_id': selected['trial_id'], 'notes': notes_ref, 'unlabelled_exits': exits_ref,
        'owner_labelled_releases': release_refs, 'contact_private_leaf': str(private / 'contact-owner-1/CONTACT.json'),
        'role_receipts': receipts, 'controller_private_body_read_or_hash': False,
        'native_verification': native_ref, 'dispatcher': {'path': str(public / 'DISPATCHER.json'), 'sha256': dispatcher_sha},
        'native_case_validation_complete': native['actual_checks_passed'], 'privacy_predictions_or_scores_generated': False,
        'accepted_backing_chain_or_financial_readiness': False}
    pin = save(public / 'GENERATION.json', catalog)
    import payout_linkage_measure
    measurement = payout_linkage_measure.measure(args.selection, args.selection_sha256,
                                                str(public / 'GENERATION.json'), pin)
    return {'status': 'METHOD02_COMPONENT_STUDY_COMPLETED',
            'catalog': str(public / 'GENERATION.json'), 'sha256': pin, 'measurement': measurement}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('stage', 'run'))
    parser.add_argument('--label')
    parser.add_argument('--selection'); parser.add_argument('--selection-sha256')
    args = parser.parse_args()
    print(json.dumps(stage(args) if args.operation == 'stage' else execute(args), sort_keys=True))


if __name__ == '__main__':
    main()
