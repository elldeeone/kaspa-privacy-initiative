"""UNSELECTED METHOD03 finite wallet-generation adapter.

Source only until Root freezes the complete method/source/budget selection.
No existing Original input, financial admission or broadcast operation exists.
"""
import argparse
import ast
import concurrent.futures
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import time
import uuid

from method03_guard import load_guard
_GUARD = load_guard()  # All seven extra roots precede every project import.

import new_private_trial as bootstrap
import private_lifecycle as lifecycle
import private_worker as boundary
import exit_wire
import genesis
import wallet_history

HERE = Path(__file__).absolute().parent
ROOT = HERE.parents[2]
DEV = ROOT / '.local/private-exit-method03-source-01'
DRAFT = ROOT / '.local/private-exit-submission-proposal-01/OWNER-ORIGIN-METHOD03-DRAFT-02.md'
DRAFT_SHA = '0b4f01b0cc38963d9117248fa9ee3449928b4a36f00b0aa9e8cf4cd7d77694a6'
PARAMETERS = ROOT / '.local/private-batch-public-native-final-parameters-01/PARAMETERS.json'
PARAMETERS_SHA = '3f9f2f294c8203c8fc99ba66e1a78e769a1eecc4ecc5cf8f8b631eea28138751'
TAIL = PARAMETERS.with_name('IMMUTABLE-TAIL.bin')
TAIL_SHA = '4081fc4efb08131bba7b64c38cfe002a3456c8a8a93394622ee9085e3706435d'
CODEC = Path('/var/tmp/kpi-local-private-native-target-01/release/kpi-private-batch-native')
CODEC_SHA = 'cc498d61898d15e077f483f8786d2b5993e0bd2a89e30a01d8489e03a31103c7'
ENGINE = Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/native-validator')
ENGINE_SHA = '077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061'
PHASE = 'private-exit-route-03'
SCOPE = 'UNFUNDED_SUPPLIED_CONTEXT'
ARMS = {'A': {'index': 11, 'origin': 'controller'}, 'B': {'index': 13, 'origin': 'owner-pipe'}}
METHOD02_LABEL = 'new-profile-original-01'
SOURCE_STATUS = 'UNSELECTED_SOURCE_ONLY'


def guard():
    return load_guard()


def need(value, category):
    if not value:
        raise ValueError(category)


def parse(raw):
    return boundary.parse(raw)


def checked(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts
         and not any(p.is_symlink() for p in (path, *path.parents)), 'method03-absolute-canonical-path')
    return path


def save(path, value, mode=0o400):
    raw = value if type(value) is bytes else boundary.encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    return hashlib.sha256(raw).hexdigest()


def reference(path, read, pin=None):
    path = checked(path); raw = read(path, pin)
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}


def binding(selected, selection_sha):
    return {'method_sha256': selected['method']['sha256'], 'selection_sha256': selection_sha,
            'trial_id': selected['trial_id'], 'phase': PHASE, 'attempt_id': selected['attempt_id']}


def candidate_metadata(path):
    # No body read, hash, copy or content identifier for an owner candidate.
    path = checked(path); st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == os.getuid()
         and stat.S_IMODE(st.st_mode) == 0o600,
         'method03-private-candidate-metadata')
    return {'path': str(path), 'mode': stat.S_IMODE(st.st_mode), 'bytes': st.st_size,
            'uid': st.st_uid, 'gid': st.st_gid, 'nlink': st.st_nlink, 'dev': st.st_dev,
            'inode': st.st_ino, 'mtime_ns': st.st_mtime_ns, 'ctime_ns': st.st_ctime_ns}


def append_metadata(fd, event, lock):
    """Preserve complete content-free records from concurrent selected readers."""
    need(type(event) is dict, 'method03-typed-metadata-event')
    raw = json.dumps(event, sort_keys=True, separators=(',', ':')).encode() + b'\n'
    with lock:
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            need(count > 0, 'method03-metadata-journal-write')
            offset += count
        os.fsync(fd)


def validate_parameters(selected, *, execution=False):
    need(selected['schema'] == 'kpb-method03-wallet-source-selection/v1'
         and selected['phase'] == PHASE and selected['arms'] == ARMS
         and selected['value_sompi'] == 200_000_000 and type(selected['value_sompi']) is int
         and selected['fee_sompi'] == 1 and type(selected['fee_sompi']) is int
         and selected['reserve_sompi'] == 6_000_000_000 and type(selected['reserve_sompi']) is int,
         'method03-fixed-parameters')
    need(selected['identity'] == [word.hex() for word in genesis.EXPECTED_IDENTITY]
         and selected['profile_hex32'] == genesis.EXPECTED_IDENTITY[2].hex()
         and selected['domain_hex32'] == genesis.EXPECTED_IDENTITY[3].hex(),
         'method03-fixed-chain-pool-profile-domain-service')
    need(selected['bootstrap']['label'] != METHOD02_LABEL
         and selected['bootstrap']['existing_trial_input_allowed'] is False
         and selected['bootstrap']['new_Original_count'] == 3,
         'method03-genuinely-new-bootstrap-only')
    if execution:
        need(selected['status'] == 'ROOT_FROZEN_METHOD03_VECTOR'
             and selected['budget']['policy'] != 'UNSELECTED'
             and selected['method']['sha256'] != DRAFT_SHA,
             'method03-final-root-source-method-budget-freeze-required')
    return selected


def load_selection(path, pin, read, *, execution=False):
    selected = validate_parameters(parse(read(checked(path), pin)), execution=execution)
    read(selected['method']['path'], selected['method']['sha256'])
    seen = set()
    shared = checked(selected['public']) / 'selected-public'
    for row in selected['source_members']:
        need(row['path'] not in seen, 'method03-unique-source-paths'); seen.add(row['path'])
        read(shared / ('source-' + str(row['index'])), row['sha256'])
    return selected


def bootstrap_command(selected, selection_sha, selection_path=None):
    # Exactly one fresh three-owner invocation; no caller seed/backup/trial option.
    entry = next(row for row in selected['source_members'] if row['path'] == str(HERE / 'method03_entry.py'))
    return ['/usr/bin/python3', '-B', str(checked(selected['public']) / 'selected-public' /
        ('source-' + str(entry['index']))), '--selection',
        str(checked(selection_path or (checked(selected['public']) / 'SELECTION.json'))), '--selection-sha256', selection_sha,
        '--program', 'bootstrap']


def source_module(selected, name, read):
    path = str(DEV / (name + '.py'))
    row = next(item for item in selected['source_members'] if item['path'] == path)
    raw = read(Path(selected['public']) / 'selected-public' / ('source-' + str(row['index'])), row['sha256'])
    spec = importlib.util.spec_from_loader(name, loader=None)
    module = importlib.util.module_from_spec(spec); module.__file__ = path
    sys.modules[name] = module
    if str(DEV) not in sys.path:
        sys.path.insert(0, str(DEV))
    exec(compile(raw, path, 'exec'), module.__dict__)
    return module


def budget_inputs(selected, selection_sha, trial_ref, trial, read):
    """Derive budget metadata only from the just-completed selected bootstrap."""
    bootstrap_selection = bootstrap.PUBLIC / selected['bootstrap']['label'] / 'SELECTION.json'
    bootstrap_ref = reference(bootstrap_selection, read)
    source_map = {row['path']: row['sha256'] for row in selected['source_members']}
    provenance = {'trial_id': trial['trial_id'], 'trial_sha256': trial_ref['sha256'],
        'selection_sha256': bootstrap_ref['sha256'],
        'generator_sha256': source_map[str(HERE / 'new_private_trial.py')],
        'worker_sha256': source_map[str(HERE / 'private_worker.py')]}
    owners = []
    for slot, path in enumerate(trial['initial_public_files']):
        expected = bootstrap.PUBLIC / selected['bootstrap']['label'] / ('init-' + str(slot)) / 'PUBLIC.json'
        need(Path(path) == expected, 'method03-fresh-bootstrap-initial-public-leaf')
        ref = reference(expected, read); value = parse(read(expected, ref['sha256']))
        need(value['schema'] == 'kpb-fresh-owner-initial-public/v1'
             and value['public_known_seed_used'] is False
             and value['domain_hex32'] == selected['domain_hex32']
             and value['profile_id_hex32'] == selected['profile_hex32'], 'method03-new-public-owner-facts')
        owners.append({'owner_component': slot, 'funding_spk_hex36': value['funding_spk_hex36'],
                       'initial_public_sha256': ref['sha256']})
    facts = {'schema': 'kpb-method03-bootstrap-budget-facts/v1', 'bootstrap': provenance,
        'profile_id_hex32': selected['profile_hex32'], 'domain_hex32': selected['domain_hex32'], 'owners': owners}
    spec = {'schema': 'kpb-method03-budget-spec/v1', 'binding': binding(selected, selection_sha),
        'identity_policy': selected['budget']['policy'], 'profile_id_hex32': selected['profile_hex32'],
        'domain_hex32': selected['domain_hex32'], 'source_sha256': selected['source_sha256'],
        'slot_grammar_sha256': selected['slot_grammar_sha256'],
        'selected_view_labels': sorted(selected['selected_view_kinds']), 'bootstrap': provenance, 'owners': owners}
    return spec, facts


def stage(args):
    """Copy finite public source selections only; create no private identity."""
    read = guard()['read']
    need(type(args.label) is str and re.fullmatch('[a-z][a-z0-9-]{0,29}', args.label),
         'method03-short-source-label')
    public = ROOT / '.local/private-exit-method03-generator' / args.label
    bootstrap_label = 'method03-' + args.label
    need(not public.exists() and not (bootstrap.PRIVATE / bootstrap_label).exists()
         and not (bootstrap.PUBLIC / bootstrap_label).exists(), 'method03-unused-source-and-bootstrap-label')
    read(DRAFT, DRAFT_SHA)
    public.mkdir(parents=True, mode=0o700)
    shared = public / 'selected-public'; shared.mkdir(mode=0o700)
    sources = lifecycle.source_selection(shared, read, 'exit')
    transport_selection = DEV / 'TRANSPORT-SOURCE-SELECTION-02.json'
    transport_selection_sha = '0c8bbe9b5f58018dbce8e99c4c560f39f396936e0c82a30e4adf0f01e07a4ce2'
    transport_raw = read(transport_selection, transport_selection_sha)
    transport_descriptor = parse(transport_raw)
    save(shared / 'TRANSPORT-SOURCE-SELECTION.json', transport_raw)
    transport_pins = {row['path']: row['sha256'] for row in transport_descriptor['source_members']}
    extra = [HERE / name for name in ('new_private_trial.py', 'method03_generation.py',
        'method03_worker.py', 'method03_entry.py', 'method03_guard.py', 'method03_budget.py',
        'method03_measure.py', 'method03_roles.py', 'method03_native_host.py', 'exit_release.py', 'genesis.py')]
    extra += [DEV / name for name in ('metadata_attack.py', 'metadata_extract.py',
                                      'controller_metadata.py', 'method03_transport.py', 'method03_native.py')]
    extra += [HERE.parent / 'private_exit_submission' / name for name in
              ('packet.py', 'transport.py', 'receiver.py')]
    extra += [Path(row['path']) for row in transport_descriptor['source_members']]
    for path in extra:
        previous = next((row for row in sources if row['path'] == str(path)), None)
        if previous:
            need(str(path) not in transport_pins or previous['sha256'] == transport_pins[str(path)],
                 'method03-same-transport-source-in-wallet-closure')
            continue
        raw = read(path, transport_pins.get(str(path))); index = len(sources)
        save(shared / ('source-' + str(index)), raw)
        sources.append({'index': index, 'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(),
                        'bytes': len(raw)})
    # Existing local imports only; no broad package/runtime copy or private scan.
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
                    for directory in (HERE, DEV):
                        path = directory / (name.split('.')[0] + '.py')
                        if path.is_file() and not any(item['path'] == str(path) for item in sources):
                            raw = read(path); index = len(sources)
                            save(shared / ('source-' + str(index)), raw)
                            sources.append({'index': index, 'path': str(path),
                                'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)})
    runtime_rows = [{'path': alias, 'host_path': str(path), 'sha256': pin}
                    for alias, path, pin in lifecycle.selected_runtime(read, 'exit')]
    for path, pin, name in ((PARAMETERS, PARAMETERS_SHA, 'PARAMETERS.json'),
        (TAIL, TAIL_SHA, 'IMMUTABLE-TAIL.bin'),
        (bootstrap.PARAMETERS / 'MANIFEST.json', bootstrap.MANIFEST_SHA, 'OUTPUT-MANIFEST.json'),
        (lifecycle.EXIT_PARAMETERS / 'MANIFEST.json', lifecycle.EXIT_MANIFEST_SHA, 'EXIT-MANIFEST.json'),
        (bootstrap.LEAF_MAP, bootstrap.LEAF_MAP_SHA, 'JS-LEAF-MAP.json')):
        save(shared / name, read(path, pin))
    descriptor = parse(read(bootstrap.PROFILE, bootstrap.PROFILE_SHA))
    profile = descriptor['profile_descriptor']
    source_hash = hashlib.sha256(boundary.encoded({row['path']: row['sha256'] for row in sources})).hexdigest()
    native_map = {'adapter': next(row['sha256'] for row in sources if row['path'] == str(DEV / 'method03_native.py')),
        'codec': CODEC_SHA, 'engine': ENGINE_SHA, 'verifier': bootstrap.BINARY_SHA,
        'parameters': PARAMETERS_SHA, 'manifest': lifecycle.EXIT_MANIFEST_SHA, 'tail': TAIL_SHA}
    transport_map = source_module({'public': str(public), 'source_members': sources},
                                  'method03_transport', read).selected_transport_source_pins({**_GUARD, 'read': read})
    grammar = {'owners': [0, 1, 2], 'arms': ARMS, 'value_sompi': 200_000_000,
               'fee_sompi': 1, 'head_shape': {'cm_count': 3, 'nf_count': 1,
                   'reserve': 6_000_000_000, 'exit_mode': 'continuing'}}
    selected = {'schema': 'kpb-method03-wallet-source-selection/v1', 'status': SOURCE_STATUS,
        'classification': 'UNFUNDED_COMPONENT_ROUTE_SOURCE_ONLY', 'label': args.label,
        'trial_id': str(uuid.uuid4()), 'attempt_id': str(uuid.uuid4()), 'phase': PHASE,
        'method': {'path': str(DRAFT), 'sha256': DRAFT_SHA}, 'public': str(public),
        'bootstrap': {'label': bootstrap_label, 'new_Original_count': 3,
                      'existing_trial_input_allowed': False},
        'source_members': sources, 'runtime_members': runtime_rows, 'source_sha256': source_hash,
        'domain_hex32': profile['domain_hex32'], 'profile_hex32': descriptor['profile_id_hex32'],
        'identity': [word.hex() for word in __import__('genesis').EXPECTED_IDENTITY],
        'binary_sha256': bootstrap.BINARY_SHA, 'output_manifest_sha256': bootstrap.MANIFEST_SHA,
        'exit_manifest_sha256': lifecycle.EXIT_MANIFEST_SHA,
        'js_leaf_map_sha256': bootstrap.LEAF_MAP_SHA, 'tail_sha256': TAIL_SHA,
        'arms': ARMS, 'value_sompi': 200_000_000, 'fee_sompi': 1,
        'reserve_sompi': 6_000_000_000, 'slot_grammar_sha256': hashlib.sha256(boundary.encoded(grammar)).hexdigest(),
        'budget': {'policy': 'UNSELECTED', 'scope': 'fixed selected profile; no cross-profile identity claim'},
        'native_source_pins': native_map, 'transport_source_pins': transport_map,
        'native_program_selection': reference(DEV / 'NATIVE-PROGRAM-SOURCE-SELECTION-02.json', read),
        'transport_source_selection': {'path': str(shared / 'TRANSPORT-SOURCE-SELECTION.json'),
            'sha256': transport_selection_sha},
        'private_choices': 'one private bijection, self allowed; no public cyclic schedule',
        'publication': 'actual receiver order/context partition; no paired publication order/shuffle',
        'selected_view_kinds': {'PRIMARY': 'prediction', 'TERMINAL_CONTACT': 'coverage', 'GLOBAL_UNION': 'coverage'},
        'secondary_status': 'MISSING/UNQUALIFIED; no score or gain',
        'controller_private_body_read_or_hash': False, 'broadcast_available': False,
        'resources': {'parallel_proof_roles': 2, 'Rayon_threads_per_role': 3, 'CPU_total': 6,
                      'timeout_only_abort': False}}
    private_parent = Path('/var/tmp/kpi-owner-private-lifecycle-01/private/diagnostics')
    selected['transport_compartments'] = {
        'private_tor_state': str(private_parent / ('method03-tor-' + selected['trial_id'])),
        'capture_root': str(private_parent / ('method03-capture-' + selected['trial_id']))}
    pin = save(public / 'SELECTION.json', selected)
    return {'selection': str(public / 'SELECTION.json'), 'sha256': pin,
            'status': SOURCE_STATUS, 'Originals_or_notes_created': False,
            'bootstrap_command_after_Root_freeze': bootstrap_command(selected, pin)}


def run_role(selected, selection_sha, operation, name, own, out, mounts, *, slot=None, arm=None, original=False, **extra):
    read = guard()['read']
    shared = Path(selected['public']) / 'selected-public'
    own.mkdir(mode=0o700, parents=True); out.mkdir(mode=0o700, parents=True)
    config = {key: selected[key] for key in ('domain_hex32', 'profile_hex32', 'binary_sha256', 'output_manifest_sha256',
        'exit_manifest_sha256', 'js_leaf_map_sha256', 'tail_sha256')}
    config.update(binding={'method_sha256': selected['method']['sha256'], 'selection_sha256': selection_sha,
        'trial_id': selected['trial_id'], 'phase': selected['phase'], 'attempt_id': selected['attempt_id']},
        source_members=[{'path': row['path'], 'sha256': row['sha256']} for row in selected['source_members']],
        runtime_members=[{'path': row['path'], 'sha256': row['sha256']} for row in selected['runtime_members']],
        owner_component=slot, arm=arm, **extra)
    import method03_budget
    budget = method03_budget.describe_claim(selected['_budget_claim'])
    config.update({key: budget[key] for key in ('source_sha256', 'slot_grammar_sha256', 'spec_sha256')})
    config_path, marker = shared / (name + '-CONFIG.json'), shared / (name + '-NAMESPACE.json')
    save(marker, {'schema': 'kpb-method03-namespace/v1', 'network': 'disabled', 'operation': operation,
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
        own_budget = method03_budget.owner_record_ref(selected['_budget_claim'], slot)
        config.update(owner_budget_sha256=own_budget['sha256'], budget_identity_key=own_budget['identity_key'])
        selected_mounts += ['--ro-bind', own_budget['path'], '/budget/ORIGINAL.json']
    selected_mounts += ['--ro-bind', str(bootstrap.JS_ROOT / 'node_modules'), '/runtime/js/node_modules',
        '--ro-bind', str(bootstrap.JS_ROOT / 'node_modules'), '/src/node_modules',
        '--ro-bind', str(shared / 'JS-LEAF-MAP.json'), '/runtime/JS-INSTALLED-LEAF-MAP.json',
        '--ro-bind', str(shared / 'OUTPUT-MANIFEST.json'), '/output-parameters/MANIFEST.json',
        '--ro-bind', str(bootstrap.PARAMETERS / 'parameters.pk'), '/output-parameters/parameters.pk',
        '--ro-bind', str(shared / 'EXIT-MANIFEST.json'), '/exit-parameters/MANIFEST.json',
        '--ro-bind', str(lifecycle.EXIT_PARAMETERS / 'parameters.pk'), '/exit-parameters/parameters.pk',
        '--ro-bind', str(shared / 'IMMUTABLE-TAIL.bin'), '/policy/IMMUTABLE-TAIL.bin']
    save(config_path, config)
    argv = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
        *selected_mounts, *mounts, '--ro-bind', str(config_path), '/CONFIG.json', '--ro-bind', str(marker), '/NAMESPACE.json',
        '--bind', str(own), '/owner', '--bind', str(out), '/out', '--chdir', '/owner', '--setenv', 'PATH', '/usr/bin:/bin',
        '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'RAYON_NUM_THREADS', '3', '/usr/bin/python3', '-B',
        str(HERE / 'method03_worker.py'), operation]
    started = time.monotonic_ns()
    with (own / 'STDOUT.log').open('xb') as stdout, (own / 'STDERR.log').open('xb') as stderr:
        completed = subprocess.run(argv, stdout=stdout, stderr=stderr, env=bootstrap.CLEAN)
    save(out / 'ROUTE.json', {'schema': 'kpb-method03-actual-role-route/v1', 'role': name, 'operation': operation,
        'owner_component': slot, 'arm': arm, 'argv': argv, 'started_monotonic_ns': started,
        'completed_monotonic_ns': time.monotonic_ns(), 'returncode': completed.returncode})
    need(completed.returncode == 0, 'method03-role-failed-' + name)
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

def generate_notes(selected, selection_sha, trial_ref, budget_claim):
    # Called only after the new bootstrap and irreversible global budget claim.
    import method03_budget
    method03_budget.describe_claim(budget_claim)
    read = guard()['read']; trial = parse(read(trial_ref['path'], trial_ref['sha256']))
    original = checked(trial['private_original_parent'])
    need(original.parent == bootstrap.PRIVATE and original.name == selected['bootstrap']['label']
         and trial['label'] == selected['bootstrap']['label'] and trial['owner_count'] == 3
         and trial['controller_read_or_hashed_private_bodies'] is False,
         'method03-selected-fresh-Original-set')
    selected = {**selected, 'original_parent': str(original), '_budget_claim': budget_claim}
    public = checked(selected['public']); private = original / 'diagnostics/private-exit-route-03'
    private.mkdir(mode=0o700)
    receipts = []
    for slot in range(3):
        receipts.append(run_role(selected, selection_sha, 'invoice', 'invoice-' + str(slot),
            private / ('invoice-' + str(slot)), public / ('invoice-' + str(slot)), [], slot=slot, original=True))
    mounts = []
    for owner in range(3):
        for arm in ARMS:
            mounts += ['--ro-bind', str(private / ('invoice-' + str(owner)) / ('INVOICE-' + arm + '.bin')),
                       '/invoices/owner-' + str(owner) + '/INVOICE-' + arm + '.bin']
    receipts.append(run_role(selected, selection_sha, 'plans', 'plans', private / 'plans',
        public / 'plans', mounts))
    def construct(slot):
        own = private / ('construct-' + str(slot)); mounts = []
        for leaf in ('PLAN.json', 'INVOICE-A.bin', 'INVOICE-B.bin'):
            mounts += ['--ro-bind', str(private / 'plans' / ('owner-' + str(slot)) / leaf), '/plan/' + leaf]
        return run_role(selected, selection_sha, 'construct', 'construct-' + str(slot), own,
                        public / ('construct-' + str(slot)), mounts, slot=slot, original=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        receipts.extend(pool.map(construct, range(3)))
    mounts = []
    for slot in range(3):
        for arm in ARMS:
            mounts += ['--ro-bind', str(private / ('construct-' + str(slot)) / ('ROW-' + arm + '.bin')),
                       '/rows/owner-' + str(slot) + '/ROW-' + arm + '.bin']
    receipts.append(run_role(selected, selection_sha, 'feed', 'feed', private / 'feed', public / 'notes', mounts))
    notes_ref = reference(public / 'notes/NOTES.json', read)
    notes = parse(read(notes_ref['path'], notes_ref['sha256']))
    contexts = {arm: bytes.fromhex(notes['arms'][arm]['context_hex276']) for arm in ARMS}
    need(contexts['A'] != contexts['B'], 'method03-disjoint-public-arm-contexts')
    result = {'binding': binding(selected, selection_sha), 'trial': trial_ref,
        'notes': notes_ref, 'private': str(private), 'owners': {}, 'histories': {},
        'budget_claim': budget_claim, 'accepted_backing_or_readiness': False}
    for arm in ARMS:
        history = public / ('COMPONENT-HISTORY-' + arm + '.json')
        result['histories'][arm] = {'path': str(history), 'sha256': save(history, history_from_notes(notes, arm))}
        def prove(slot):
            name = 'prove-' + arm + '-' + str(slot)
            own = private / name; out = public / name
            receipt = run_role(selected, selection_sha, 'prove', name, own, out,
                ['--ro-bind', notes_ref['path'], '/public/NOTES.json'], slot=slot, arm=arm,
                original=True, notes_sha256=notes_ref['sha256'])
            return slot, {'candidate': candidate_metadata(own / 'EXIT-CANDIDATE.json'),
                          'private_truth_leaf': str(own / 'TRUTH.json'), 'public_receipt': receipt}
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            result['owners'][arm] = dict(pool.map(prove, range(3)))
    return selected, result


def execute(args):
    read = guard()['read']
    selected = load_selection(args.selection, args.selection_sha256, read, execution=True)
    import method03_budget
    need(method03_budget.SELECTED_IDENTITY_POLICY == selected['budget']['policy']
         and method03_budget.REGISTRY_ADMISSION is not None,
         'method03-production-budget-policy-and-registry-not-selected')
    public = checked(selected['public'])
    clock_source = source_module(selected, 'controller_metadata', read)
    early_clock = clock_source.clock_snapshot('controller')
    early_path = public / 'EARLY-CONTROLLER-CLOCK.json'
    early_pin = save(early_path, {'schema': 'kpb-method03-early-controller-clock/v1',
        'binding': binding(selected, args.selection_sha256), 'value': early_clock})
    early_ref = {'path': str(early_path), 'sha256': early_pin}
    # This single command is the ONLY Original admission route.
    process = subprocess.run(bootstrap_command(selected, args.selection_sha256, args.selection), env=bootstrap.CLEAN,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    need(process.returncode == 0, 'method03-fresh-bootstrap-incomplete')
    reply = parse(process.stdout)
    need(reply['status'] == 'FRESH_PRIVATE_ORIGINALS_AND_GENUINE_OUTPUTS_COMPLETED'
         and reply['owner_count'] == 3, 'method03-three-new-Originals-created')
    trial_ref = {'path': reply['trial'], 'sha256': reply['trial_sha256']}
    trial = parse(read(trial_ref['path'], trial_ref['sha256']))
    spec, facts = budget_inputs(selected, args.selection_sha256, trial_ref, trial, read)
    claim = method03_budget.reserve(spec, facts)
    # No METHOD03 note/view role can run before reserve returns.
    selected, generation = generate_notes(selected, args.selection_sha256, trial_ref, claim)
    transport = source_module(selected, 'method03_transport', read)
    private = checked(generation['private'])
    journal = public / 'TRANSPORT-METADATA.jsonl'
    fd = os.open(journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    journal_lock = threading.Lock()
    def emit_metadata(event):
        # The transport API guarantees this finite typed stream is content free.
        append_metadata(fd, event, journal_lock)
    try:
        session = transport.open_vector(binding=binding(selected, args.selection_sha256),
            selection_ref=selected['transport_source_selection'],
            public_output=str(public / 'transport'),
            private_tor_state=selected['transport_compartments']['private_tor_state'],
            capture_root=selected['transport_compartments']['capture_root'], guard={**_GUARD, 'read': read},
            early_controller_clock_ref=early_ref,
            emit_metadata=emit_metadata)
        for arm in ARMS:
            def submit(slot):
                return session.submit_one(arm, slot, generation['owners'][arm][slot]['candidate'],
                    generation['histories'][arm], {'path': str(TAIL), 'sha256': TAIL_SHA},
                    tuple(selected['identity']))
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                list(pool.map(submit, range(3)))
        capture = session.finish()
    finally:
        os.close(fd)
    capture = {**capture, 'metadata_journal': reference(journal, read),
               'driver_metadata_journal': capture['metadata_journal']}
    from method03_native_host import prepare_capture
    capture = prepare_capture(selected, args.selection_sha256, generation, capture, read)
    # Closed measurement owns all raw capture/contact/prediction/truth reads.
    from method03_measure import measure
    return measure(selected, args.selection_sha256, generation, capture, read)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('stage', 'run'))
    parser.add_argument('--label'); parser.add_argument('--selection'); parser.add_argument('--selection-sha256')
    args = parser.parse_args()
    need(args.operation != 'run' or (args.selection and args.selection_sha256), 'method03-exact-selection-required')
    print(json.dumps(stage(args) if args.operation == 'stage' else execute(args), sort_keys=True))


if __name__ == '__main__':
    main()
