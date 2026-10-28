"""Trusted fixed-state METHOD02 measurement launcher; no private body IO.

Only selected public source snapshots and explicit public artifacts are read.
Private contact/capsule/log leaves are metadata-only host inputs. Each role
receives finite leaves, no Original, proving key, runtime or private tree.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import types

HERE = Path(__file__).absolute().parent
OBSERVER_SHA = '8b0deffe4892abe9f4b92b52c049e5a6868600b0a1a2e538ce815aabd3f2bc74'
MATCHER_SHA = '06282c791f5c8ca6ddb90e1ca0147a4bc0dc90639efb887bbd621b3a7d677089'
EXIT_SHA = 'fabf7361f030e25ec4a52a72691fef4bcfe03f6fef369ff33b8fa55dd01ccb6a'
VIEWS = ('CONTACT', 'DISPATCHER', 'UNION')
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}


def need(value, category):
    if not value:
        raise ValueError(category)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def checked(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts
         and not any(p.is_symlink() for p in (path, *path.parents)), 'method02-canonical-host-path')
    return path


def write_new(path, value, mode=0o400):
    path = checked(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(encoded(value)); handle.flush(); os.fsync(handle.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def mkdir(path):
    path = checked(path)
    if not path.exists():
        mkdir(path.parent); path.mkdir(mode=0o700)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), 'method02-owned-state-directory')
    return path


def private_leaf(path, mode):
    path = checked(path); info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
         and stat.S_IMODE(info.st_mode) == mode, 'method02-private-leaf-metadata-only')
    return path


def ref(read, path, pin=None):
    path = checked(path); raw = read(path, pin)
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}, json.loads(raw)


def selected_sources(selected, read):
    shared = checked(Path(selected['public']) / 'selected-public')
    result = {}
    for row in selected['source_members']:
        path = checked(row['path'])
        need(str(path) not in result and type(row['index']) is int, 'method02-distinct-selected-source')
        snapshot = shared / ('source-' + str(row['index']))
        raw = read(snapshot, row['sha256'])
        result[str(path)] = {'path': path, 'snapshot': snapshot, 'raw': raw, 'sha256': row['sha256']}
    return result


def load_runtime(selection_path, selection_sha):
    # This stdlib-only bootstrap and this entry are externally source-selected.
    # It inventories all private roots BEFORE opening any retained guard/helper
    # or other project body. Do not run an unextended guard09 first.
    guard_path = HERE / 'payout_linkage_guard.py'
    spec = importlib.util.spec_from_file_location('_method02_measure_guard', guard_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    read = module.load_guard()['read']
    _, selected = ref(read, selection_path, selection_sha)
    sources = selected_sources(selected, read)
    # The imported controller's transitive project imports must equal the
    # admitted frozen source bytes. Runtime/key files are not imported here.
    for member in sources.values():
        read(member['path'], member['sha256'])
    study_path = HERE / 'payout_linkage_original.py'
    need(str(study_path) in sources and str(Path(__file__).absolute()) in sources
         and str(guard_path) in sources, 'method02-complete-measurement-host-source-selection')
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    study = types.ModuleType('_method02_measure_study'); study.__file__ = str(study_path)
    sys.modules[study.__name__] = study
    exec(compile(sources[str(study_path)]['raw'], str(study_path), 'exec'), study.__dict__)
    selected = study.load_selection(selection_path, selection_sha, read)
    return read, study, selected, sources


def validate_inputs(selected, selection_sha, catalog, read, study):
    need(catalog['schema'] == 'kpb-method02-generated-artifact-catalog/v1'
         and catalog['selection_sha256'] == selection_sha
         and catalog['method_sha256'] == study.METHOD_SHA
         and catalog['trial_id'] == selected['trial_id']
         and catalog['controller_private_body_read_or_hash'] is False,
         'method02-same-generated-public-catalog')
    _, trial = ref(read, selected['trial']['path'], selected['trial']['sha256'])
    original = checked(trial['private_original_parent'])
    need(original == checked(selected['original_parent']) and trial['trial_id'] == selected['trial_id'],
         'method02-admitted-Original-root-from-selected-public-trial')
    fixed = original / 'diagnostics/private-payout-linkage-02'
    need(checked(selected['private']) == fixed / selected['label'], 'method02-fixed-private-study-root')
    expected_contact = Path(selected['private']) / 'contact-owner-1/CONTACT.json'
    need(checked(catalog['contact_private_leaf']) == expected_contact, 'method02-exact-actual-contact-leaf')
    private_leaf(expected_contact, 0o600)  # No open/hash/read in this process.
    exits_ref, exits = ref(read, catalog['unlabelled_exits']['path'], catalog['unlabelled_exits']['sha256'])
    binding = {'method_sha256': study.METHOD_SHA, 'selection_sha256': selection_sha,
               'trial_id': selected['trial_id'], 'phase': 'private-payout-linkage-02',
               'attempt_id': selected['attempt_id']}
    need(exits['schema'] == 'kpb-method02-unlabelled-exits/v1' and exits['binding'] == binding,
         'method02-same-exact-public-exits')
    return fixed, expected_contact, exits_ref, exits, binding


def source_mounts(sources):
    paths = [(HERE / 'payout_linkage_observe.py', OBSERVER_SHA),
             (HERE / 'payout_privacy_attack.py', MATCHER_SHA),
             (HERE / 'exit_wire.py', EXIT_SHA),
             (HERE.parent / 'verification/wire.py', None)]
    mounts, members = [], []
    for path, pin in paths:
        member = sources.get(str(path))
        need(member is not None and (pin is None or member['sha256'] == pin),
             'method02-exact-closed-role-source')
        mounts += ['--ro-bind', str(member['snapshot']), str(path)]
        members.append({'path': str(path), 'sha256': member['sha256']})
    return mounts, members


def native_coverage(catalog, read, exits_ref, exits):
    selected = catalog.get('native_verification')
    if not isinstance(selected, dict):
        return False
    _, value = ref(read, selected['path'], selected['sha256'])
    universe = {(arm, row['exit_id']) for arm in ('A', 'B') for row in exits['arms'][arm]}
    rows = value.get('records', [])
    return (value.get('schema') == 'kpb-method02-public-native-verification/v1'
            and value.get('binding') == exits['binding'] and value.get('exits_sha256') == exits_ref['sha256']
            and value.get('all_six_actual_checks_passed') is True
            and len(rows) == 6 and {(row.get('arm'), row.get('exit_id')) for row in rows} == universe
            and all(row.get('public_AuthExit_verified') is True
                    and row.get('native_Full_all_input_engines') is True for row in rows))


def run_role(operation, state, output, binding, members, software, mounts, config, read):
    # Fixed per-Original/view reservation; attempt/output labels cannot reset it.
    mkdir(state); mkdir(output)
    write_new(state / 'HOST-RESERVED.json', {'binding': binding, 'operation': operation})
    config_path, marker = state / 'CONFIG.json', state / 'NAMESPACE.json'
    write_new(config_path, config, 0o600)
    write_new(marker, {'schema': 'kpb-method02-observer-namespace/v1',
              'operation': operation, 'network': 'disabled', 'Original_slots': 0}, 0o600)
    argv = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
        *software, *mounts, '--ro-bind', str(config_path), '/CONFIG.json', '--ro-bind', str(marker), '/NAMESPACE.json',
        '--bind', str(state), '/state', '--bind', str(output), '/out', '--chdir', '/tmp',
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
        '/usr/bin/python3', '-B', '-S', str(HERE / 'payout_linkage_observe.py'), operation]
    start = time.monotonic_ns()
    # Only write descriptors enter private logs; never reopen/read/hash them.
    with (state / 'STDOUT.log').open('xb') as stdout, (state / 'STDERR.log').open('xb') as stderr:
        process = subprocess.run(argv, stdout=stdout, stderr=stderr, env=CLEAN)
    write_new(output / 'OPERATOR-ROUTE.json', {'schema': 'kpb-method02-measurement-actual-route/v1',
        'binding': binding, 'operation': operation, 'argv': argv,
        'started_monotonic_ns': start, 'completed_monotonic_ns': time.monotonic_ns(),
        'returncode': process.returncode, 'private_body_read_or_hash': False})
    need(process.returncode == 0, 'method02-closed-measurement-role-incomplete')
    leaf = 'RESULT.json' if operation == 'postseal-score' else 'SEAL.json'
    return ref(read, output / leaf)


def measure(selection_path, selection_sha, catalog_path, catalog_sha):
    read, study, selected, sources = load_runtime(selection_path, selection_sha)
    catalog_ref, catalog = ref(read, catalog_path, catalog_sha)
    need(checked(catalog_ref['path']) == checked(Path(selected['public']) / 'GENERATION.json'),
         'method02-fixed-generated-catalog-path')
    fixed, contact_path, exits_ref, exits, binding = validate_inputs(selected, selection_sha, catalog, read, study)
    software, members = source_mounts(sources)
    native_ok = native_coverage(catalog, read, exits_ref, exits)
    public_facts = {arm: {'economic': [{'owner': owner, 'allowed_payout_fee': [[199_999_999, 1]]}
                                      for owner in range(3)],
        'timing': [], 'public_identifier_edges': [],
        'unmodeled': ['opaque-proof-bytes-not-a-cryptographic-privacy-proof',
                      'complete-corrupt-server-and-terminal-network-view-unavailable',
                      'contact-observer-timing-beyond-actual-exported-projections-not-modeled']
                     + ([] if native_ok else ['actual-six-native-verification-incomplete'])} for arm in ('A', 'B')}
    base = {'schema': 'kpb-method02-payout-role-config/v1', 'binding': binding,
        'source_members': members, 'exits_sha256': exits_ref['sha256'], 'dispatcher_sha256': None,
        'public_facts': public_facts, 'seals_sha256': None}
    public = checked(Path(selected['public']) / 'measurement')
    seals, capsules = {}, {}
    for view in VIEWS:
        operation = view.lower() + '-observe'
        state = fixed / ('observe-' + view)
        output = public / view
        mounts = ['--ro-bind', exits_ref['path'], '/public/EXITS.json']
        config = {**base, 'operation': operation}
        if view in ('CONTACT', 'UNION'):
            mounts += ['--ro-bind', str(contact_path), '/contact/CONTACT.json']
        if view != 'CONTACT':
            # CONTACT seal was returned through guard09 and validated before
            # the first labelled dispatcher leaf can enter any role namespace.
            need('CONTACT' in seals, 'method02-contact-export-before-labelled-mount')
            dispatcher_ref, _ = ref(read, catalog['dispatcher']['path'], catalog['dispatcher']['sha256'])
            config['dispatcher_sha256'] = dispatcher_ref['sha256']
            mounts += ['--ro-bind', dispatcher_ref['path'], '/public/DISPATCHER.json']
        predictions = mkdir(state / 'predictions')
        mounts += ['--bind', str(predictions), '/private-output']
        seal_ref, seal = run_role(operation, state, output, binding, members, software, mounts, config, read)
        need(seal['schema'] == 'kpb-method02-public-prediction-seal/v1' and seal['binding'] == binding
             and seal['view'] == view and seal['exits_sha256'] == exits_ref['sha256']
             and seal['predictions_frozen_before_truth'] is True
             and seal['private_contact_or_prediction_records_exported'] is False,
             'method02-guard-admitted-actual-view-seal')
        seals[view] = seal_ref
        capsules[view] = private_leaf(predictions / 'PREDICTIONS.json', 0o400)
    # All three actual guard-admitted seals exist before score state/namespace.
    dispatcher_ref, _ = ref(read, catalog['dispatcher']['path'], catalog['dispatcher']['sha256'])
    score_config = {**base, 'operation': 'postseal-score', 'dispatcher_sha256': dispatcher_ref['sha256'],
                    'seals_sha256': {view: seals[view]['sha256'] for view in VIEWS}}
    mounts = ['--ro-bind', exits_ref['path'], '/public/EXITS.json',
              '--ro-bind', dispatcher_ref['path'], '/public/DISPATCHER.json']
    for view in VIEWS:
        mounts += ['--ro-bind', str(capsules[view]), '/predictions/' + view + '.json',
                   '--ro-bind', seals[view]['path'], '/seals/' + view + '.json']
    result_ref, result = run_role('postseal-score', fixed / 'score', public / 'score', binding,
                                 members, software, mounts, score_config, read)
    need(result['schema'] == 'kpb-method02-public-paired-linkage-result/v1' and result['binding'] == binding
         and result['all_predictions_sealed_before_truth'] is True
         and result['all_models_bound_to_exact_selected_exit_universes'] is True
         and result['same_position_cross_arm_linkage_included'] is True
         and result['private_contacts_salts_models_or_keys_exported'] is False
         and result['overall_crypto_dispatcher_or_terminal_privacy_qualified'] is False,
         'method02-complete-typed-public-score-only')
    if not native_ok:
        need(result['status'] in ('UNQUALIFIED', 'INVALID MODEL'), 'method02-missing-native-never-qualified')
    receipt = {'schema': 'kpb-method02-measurement-host-result/v1', 'binding': binding,
        'catalog': catalog_ref, 'public_seals': seals, 'public_result': result_ref,
        'native_verification_complete': native_ok,
        'fixed_Original_state_independent_of_output_labels': True,
        'contact_seal_admitted_before_labelled_observer_mounts': True,
        'all_three_seals_admitted_before_score_launch': True,
        'controller_private_body_read_or_hash': False, 'overall_privacy_qualified': False}
    path = public / 'MEASUREMENT.json'; write_new(path, receipt)
    reference, _ = ref(read, path)
    return reference


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', required=True); parser.add_argument('--selection-sha256', required=True)
    parser.add_argument('--catalog', required=True); parser.add_argument('--catalog-sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(measure(args.selection, args.selection_sha256, args.catalog, args.catalog_sha256), sort_keys=True))


if __name__ == '__main__':
    main()

