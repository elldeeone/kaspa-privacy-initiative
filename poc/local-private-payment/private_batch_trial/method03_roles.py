"""UNSELECTED closed METHOD03 roles; no host, Original or network capability.

The selected host admits the entry and all source leaves through method03_guard
before launch, consumes persistent budget permits before private mounts, and
enforces actual completion/seal barriers. This worker repeats the finite public
checks before private reads. Its private capsules and owner masks must never be
read or hashed by the host. This source grants no experiment authority.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat
import sys


ENGINE_SHA = '5ace32051139233bc28b315085f6a73f4000530fe2b7d138bffd26f312f3c52e'
PROFILE = 'ea19260a60a8d0a54b8ad9848f82317c1d84059a1881be34d318bcca42493700'
DOMAIN = 'a0a1b4fbf4ce8505f17b24b354ffa81fc4201dc1e130b0358e3bc849611186e0'
SOURCE_PINS = {
    '/src/metadata_attack.py': ENGINE_SHA,
    '/src/private_batch_trial/exit_wire.py': 'fabf7361f030e25ec4a52a72691fef4bcfe03f6fef369ff33b8fa55dd01ccb6a',
    '/src/verification/wire.py': '6727e00a143596dbd31abf06c7fd5a2ceafa07082d6e3e6de47fa389a826def8',
    '/src/packet.py': '7c0ad5f630a94a1481384c8726d98ebcfbab7ff1f6ba5395b3d8da9fafda38a6',
}
SOURCE_PATHS = set(SOURCE_PINS) | {'/src/method03_roles.py', '/src/metadata_extract.py'}
VIEWS = ('PRIMARY', 'TERMINAL_CONTACT', 'GLOBAL_UNION')
KINDS = {'PRIMARY': 'prediction', 'TERMINAL_CONTACT': 'coverage', 'GLOBAL_UNION': 'coverage'}
OPERATIONS = ('observe-primary', 'secondary-coverage', 'score-owner', 'aggregate')
ARMS = ('A', 'B')
TAG = b'KPB_METHOD03_PRIVATE_CAPSULE_V1\0'
INPUTS = {
    'observe-primary': {'receiver_index': '/capture/INDEX.json',
        'event_journal': '/metadata/JOURNAL.jsonl', 'contact_facts': '/contact/CONTACT.json',
        'baseline_A_exposure': '/baseline-A/EXPOSURE.json'},
    'secondary-coverage': {},
    'score-owner': {'primary_capsule': '/capsules/PRIMARY.json',
                    'truth_A': '/truth/A.json', 'truth_B': '/truth/B.json'},
    'aggregate': {'primary_capsule': '/capsules/PRIMARY.json',
                  **{'score_' + str(o): '/scores/owner-' + str(o) + '.json' for o in range(3)}},
}


def need(condition, category):
    if not condition:
        raise ValueError('method03-role-' + category)


def fields(value, names):
    need(type(value) is dict and set(value) == set(names), 'exact-fields')


def word(value):
    need(type(value) is str and len(value) == 64
         and all(c in '0123456789abcdef' for c in value), 'sha256')
    return value


def hexbytes(value, width):
    need(type(value) is str and len(value) == width * 2
         and all(c in '0123456789abcdef' for c in value), 'fixed-canonical-hex')
    return bytes.fromhex(value)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def parse(raw):
    def unique(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate-json-field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('method03-role-json-number')))


def stable_read(path, expected=None, private=False):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts
         and not any(p.is_symlink() for p in (path, *path.parents)), 'finite-nonsymlink-leaf')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        before = os.fstat(handle.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid(),
             'owned-single-link-regular-leaf')
        if private:
            need(stat.S_IMODE(before.st_mode) in (0o400, 0o600), 'private-leaf-mode')
        raw = handle.read()
        after = os.fstat(handle.fileno())
        keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_nlink', 'st_uid')
        need(all(getattr(before, k) == getattr(after, k) for k in keys)
             and len(raw) == before.st_size, 'stable-leaf')
    if expected is not None:
        need(hashlib.sha256(raw).hexdigest() == word(expected), 'selected-public-leaf')
    return raw


def write_new(path, value, mode=0o400):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts
         and not any(p.is_symlink() for p in (path, *path.parents)), 'nonsymlink-output')
    raw = encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return raw


def public_ref(row, path):
    fields(row, ('path', 'sha256'))
    need(row['path'] == path, 'fixed-public-reference')
    return parse(stable_read(path, word(row['sha256'])))


def close_setup_fds():
    for text in os.listdir('/proc/self/fd'):
        descriptor = int(text)
        if descriptor > 2:
            try:
                os.close(descriptor)
            except OSError as error:
                if error.errno != 9:
                    raise


def assert_no_ambient_fds():
    for text in os.listdir('/proc/self/fd'):
        descriptor = int(text)
        if descriptor > 2:
            try:
                os.fstat(descriptor)
            except OSError as error:
                if error.errno == 9:
                    continue
                raise
            raise ValueError('method03-role-inherited-descriptor')


def require_namespace(operation):
    marker = parse(stable_read('/NAMESPACE.json'))
    need(marker == {'schema': 'kpb-method03-closed-role-namespace/v1', 'operation': operation,
                    'network': 'disabled', 'Original_slots': 0}, 'closed-namespace-marker')
    interfaces = [line.split(':', 1)[0].strip()
                  for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
    need(interfaces == ['lo'], 'network-disabled')
    need(not any(Path(path).exists() for path in ('/original', '/Original', '/parameters/parameters.pk',
        '/home/luke/.codex', '/home/luke/.ssh', '/var/tmp/kpi-owner-private-lifecycle-01/private')),
        'no-Original-key-or-host-private-parent')
    assert_no_ambient_fds()
    config = parse(stable_read('/CONFIG.json'))
    fields(config, ('schema', 'operation', 'binding', 'source_members', 'plan_ref', 'view', 'owner',
        'public_seals', 'score_seals', 'barrier_ref', 'budget_permit_ref', 'source_sha256', 'slot_grammar_sha256',
        'spec_sha256', 'profile_id_hex32', 'domain_hex32', 'input_refs'))
    need(config['schema'] == 'kpb-method03-closed-role-config/v1'
         and config['operation'] == operation, 'role-config-operation')
    need(config['profile_id_hex32'] == PROFILE and config['domain_hex32'] == DOMAIN,
         'fixed-profile-domain')
    for key in ('source_sha256', 'slot_grammar_sha256', 'spec_sha256'):
        word(config[key])
    need(config['input_refs'] == INPUTS[operation], 'finite-private-input-aliases')
    if operation == 'observe-primary':
        need(config['view'] == 'PRIMARY' and config['owner'] is None
             and config['public_seals'] is None and config['barrier_ref'] is None,
             'primary-no-scoring-or-truth')
    elif operation == 'secondary-coverage':
        need(config['view'] in VIEWS[1:] and config['owner'] is None
             and type(config['public_seals']) is dict and set(config['public_seals']) == {'PRIMARY'}
             and config['barrier_ref'] is None, 'secondary-coverage-only')
    else:
        need(config['view'] == 'PRIMARY' and type(config['public_seals']) is dict
             and set(config['public_seals']) == set(VIEWS), 'all-three-public-seal-references')
        need((type(config['owner']) is int and config['owner'] in range(3))
             if operation == 'score-owner' else config['owner'] is None, 'one-selected-score-owner')
    need((type(config['score_seals']) is dict and set(config['score_seals']) == {'0', '1', '2'})
         if operation == 'aggregate' else config['score_seals'] is None, 'finite-public-score-seals')
    forbidden = {
        'observe-primary': ('/truth', '/capsules', '/scores'),
        'secondary-coverage': ('/capture', '/metadata', '/contact', '/baseline-A', '/truth', '/capsules', '/scores'),
        'score-owner': ('/capture', '/metadata', '/contact', '/baseline-A', '/scores'),
        'aggregate': ('/capture', '/metadata', '/contact', '/baseline-A', '/truth'),
    }
    need(not any(Path(path).exists() for path in forbidden[operation]), 'role-private-mount-separation')
    return config


def selected_module(name, path, raw):
    spec = importlib.util.spec_from_loader(name, loader=None, origin=path)
    module = importlib.util.module_from_spec(spec)
    module.__file__ = path
    sys.modules[name] = module
    exec(compile(raw, path, 'exec'), module.__dict__)
    return module


def load_sources(config):
    rows = config['source_members']
    need(type(rows) is list, 'source-members')
    selected = {}
    for row in rows:
        fields(row, ('path', 'sha256'))
        need(row['path'] in SOURCE_PATHS and row['path'] not in selected, 'finite-distinct-source-aliases')
        selected[row['path']] = word(row['sha256'])
    need(set(selected) == SOURCE_PATHS and all(selected[p] == h for p, h in SOURCE_PINS.items()),
         'pinned-source-closure')
    need(str(Path(__file__).absolute()) == '/src/method03_roles.py', 'selected-entry-alias')
    raw = {path: stable_read(path, pin) for path, pin in selected.items()}
    # All closure leaves have been checked before the first project import. The
    # retained exit_wire then loads only the already admitted adjacent wire leaf.
    sys.dont_write_bytecode = True
    engine = selected_module('metadata_attack', '/src/metadata_attack.py', raw['/src/metadata_attack.py'])
    wire = selected_module('exit_wire', '/src/private_batch_trial/exit_wire.py',
                           raw['/src/private_batch_trial/exit_wire.py'])
    packet = selected_module('packet', '/src/packet.py', raw['/src/packet.py'])
    extractor = selected_module('metadata_extract', '/src/metadata_extract.py', raw['/src/metadata_extract.py'])
    return {'engine': engine, 'wire': wire, 'packet': packet, 'extractor': extractor}


def capsule_commitment(payload, salt):
    need(type(salt) is bytes and len(salt) == 32, 'high-entropy-private-salt-width')
    return hashlib.sha256(TAG + salt + encoded(payload)).hexdigest()


def universe_digest(universe):
    fields(universe, ARMS)
    for values in universe.values():
        need(type(values) is list and len(values) == 3 and len(set(values)) == 3,
             'three-unlabelled-arrivals-per-arm')
        for value in values:
            word(value)
    need(not set(universe['A']) & set(universe['B']), 'disjoint-unlabelled-arm-universes')
    return hashlib.sha256(encoded({arm: sorted(universe[arm]) for arm in ARMS})).hexdigest()


def publish_capsule(config, payload, universe_sha256):
    salt = secrets.token_bytes(32)
    commitment = capsule_commitment(payload, salt)
    write_new('/private-output/CAPSULE.json', {'schema': 'kpb-method03-private-role-capsule/v1',
        'salt_hex32': salt.hex(), 'payload': payload})
    seal = {'schema': 'kpb-method03-public-role-seal/v1', 'binding': config['binding'],
        'label': config['view'], 'kind': KINDS[config['view']],
        'source_sha256': config['source_sha256'], 'slot_grammar_sha256': config['slot_grammar_sha256'],
        'spec_sha256': config['spec_sha256'], 'actual_unlabelled_universe_sha256': word(universe_sha256),
        'salted_commitment_sha256': commitment, 'sealed_before_truth': True,
        'private_records_exported': False}
    write_new('/out/SEAL.json', seal)
    return seal


def read_plan(config, runtime):
    plan = public_ref(config['plan_ref'], '/public/PLAN.json')
    runtime['engine'].check_plan(plan)
    need(plan['binding'] == config['binding'], 'plan-binding')
    need(plan['arms']['A']['note_index'] == 11 and plan['arms']['B']['note_index'] == 13,
         'fixed-independent-note-indexes')
    need(plan['head_shape'] == {'cm_count': 3, 'nf_count': 1, 'reserve': 6_000_000_000,
                               'exit_mode': 'continuing'}, 'fixed-head-shape')
    need(plan['common_amounts'] == {'note': 200_000_000, 'fee': 1, 'payout': 199_999_999},
         'fixed-integer-economics')
    return plan


def public_seal(config, label):
    seal = public_ref(config['public_seals'][label], '/seals/' + label + '.json')
    fields(seal, ('schema', 'binding', 'label', 'kind', 'source_sha256', 'slot_grammar_sha256',
        'spec_sha256', 'actual_unlabelled_universe_sha256', 'salted_commitment_sha256',
        'sealed_before_truth', 'private_records_exported'))
    need(seal['schema'] == 'kpb-method03-public-role-seal/v1'
         and seal['binding'] == config['binding'] and seal['label'] == label
         and seal['kind'] == KINDS[label] and seal['sealed_before_truth'] is True
         and seal['private_records_exported'] is False, 'exact-public-salted-view-seal')
    for key in ('source_sha256', 'slot_grammar_sha256', 'spec_sha256'):
        need(seal[key] == config[key], 'same-source-spec-slot-grammar')
    word(seal['actual_unlabelled_universe_sha256']); word(seal['salted_commitment_sha256'])
    return seal


def all_public_seals(config):
    seals = {label: public_seal(config, label) for label in VIEWS}
    need(len({seal['actual_unlabelled_universe_sha256'] for seal in seals.values()}) == 1,
         'all-three-exact-unlabelled-universes')
    return seals


def check_public_barrier(config, seals):
    """Repeat public joins; the host must have made the stateful barrier call."""
    barrier = public_ref(config['barrier_ref'], '/public/ALL-SEALS-BARRIER.json')
    fields(barrier, ('schema', 'binding', 'source_sha256', 'slot_grammar_sha256',
        'actual_unlabelled_universe_sha256', 'completed_view_refs'))
    need(barrier['schema'] == 'kpb-method03-all-selected-views-sealed/v2'
         and barrier['binding'] == config['binding']
         and barrier['source_sha256'] == config['source_sha256']
         and barrier['slot_grammar_sha256'] == config['slot_grammar_sha256']
         and barrier['actual_unlabelled_universe_sha256']
             == seals['PRIMARY']['actual_unlabelled_universe_sha256'], 'actual-all-view-barrier')
    rows = barrier['completed_view_refs']
    need(type(rows) is list and len(rows) == 3
         and {row['label'] for row in rows} == set(VIEWS), 'exact-three-completed-slot-kinds')
    for row in rows:
        fields(row, ('label', 'kind', 'binding', 'source_sha256', 'public_plan_sha256',
            'slot_grammar_sha256', 'actual_unlabelled_universe_sha256', 'salted_public_seal',
            'salted_commitment_sha256', 'completion'))
        label = row['label']
        need(row['kind'] == KINDS[label] and row['binding'] == config['binding']
             and row['source_sha256'] == config['source_sha256']
             and row['public_plan_sha256'] == config['plan_ref']['sha256']
             and row['slot_grammar_sha256'] == config['slot_grammar_sha256']
             and row['actual_unlabelled_universe_sha256']
                 == seals[label]['actual_unlabelled_universe_sha256']
             and row['salted_commitment_sha256'] == seals[label]['salted_commitment_sha256'],
             'source-plan-slot-commitment-barrier-joins')
        fields(row['salted_public_seal'], ('path', 'sha256'))
        need(type(row['salted_public_seal']['path']) is str
             and Path(row['salted_public_seal']['path']).is_absolute()
             and row['salted_public_seal']['sha256'] == config['public_seals'][label]['sha256'],
             'actual-salted-public-seal-reference')
        completion = row['completion']
        fields(completion, ('observed_launcher_pid', 'returncode', 'completed_monotonic_ns', 'event_ref'))
        need(type(completion['observed_launcher_pid']) is int and completion['observed_launcher_pid'] > 0
             and type(completion['returncode']) is int and completion['returncode'] == 0
             and type(completion['completed_monotonic_ns']) is int
             and completion['completed_monotonic_ns'] >= 0, 'actual-completed-role-metadata')
        fields(completion['event_ref'], ('path', 'sha256'))
        need(type(completion['event_ref']['path']) is str
             and Path(completion['event_ref']['path']).is_absolute(), 'public-completion-event-reference')
        word(completion['event_ref']['sha256'])
    return barrier


def check_budget_permit(config, seals=None):
    """Public record checks never replace the host's stateful pre-mount call."""
    permit = public_ref(config['budget_permit_ref'], '/public/BUDGET-PERMIT.json')
    fields(permit, ('schema', 'operation', 'label', 'kind', 'owner_component', 'binding',
        'source_sha256', 'slot_grammar_sha256', 'spec_sha256', 'reservation_keys',
        'actual_unlabelled_universe_sha256', 'all_seals_sha256'))
    operation = config['operation']
    expected_operation = 'observe-view' if operation in ('observe-primary', 'secondary-coverage') else operation
    expected_kind = KINDS[config['view']] if expected_operation == 'observe-view' else (
        'score' if operation == 'score-owner' else 'aggregate')
    need(permit['schema'] == 'kpb-method03-budget-permit/v1'
         and permit['operation'] == expected_operation and permit['label'] == config['view']
         and permit['kind'] == expected_kind and permit['binding'] == config['binding']
         and permit['owner_component'] == config['owner'], 'stateful-permit-role-binding')
    need(permit['owner_component'] is None or type(permit['owner_component']) is int,
         'canonical-permit-owner')
    for key in ('source_sha256', 'slot_grammar_sha256', 'spec_sha256'):
        need(permit[key] == config[key], 'stateful-permit-source-spec-slot')
    keys = permit['reservation_keys']
    need(type(keys) is list and len(keys) == len(set(keys)) == 3, 'three-reserved-identity-keys')
    for key in keys:
        word(key)
    if seals is None:
        need(permit['actual_unlabelled_universe_sha256'] is None and permit['all_seals_sha256'] is None,
             'pre-observation-no-future-data')
    else:
        need(permit['actual_unlabelled_universe_sha256']
                 == seals['PRIMARY']['actual_unlabelled_universe_sha256']
             and permit['all_seals_sha256'] == config['barrier_ref']['sha256'],
             'actual-postseal-permit-universe-barrier')
    return permit


def read_primary_capsule(config, runtime, plan, seal):
    capsule = parse(stable_read('/capsules/PRIMARY.json', private=True))
    fields(capsule, ('schema', 'salt_hex32', 'payload'))
    need(capsule['schema'] == 'kpb-method03-private-role-capsule/v1', 'private-primary-capsule')
    payload = capsule['payload']
    fields(payload, ('schema', 'binding', 'source_sha256', 'slot_grammar_sha256', 'spec_sha256',
        'actual_unlabelled_universe_sha256', 'plan', 'observation', 'prediction'))
    need(payload['schema'] == 'kpb-method03-private-primary-prediction/v1'
         and payload['binding'] == config['binding'] and payload['plan'] == plan,
         'primary-payload-binding-plan')
    for key in ('source_sha256', 'slot_grammar_sha256', 'spec_sha256'):
        need(payload[key] == config[key], 'primary-payload-source-spec-slot')
    need(capsule_commitment(payload, hexbytes(capsule['salt_hex32'], 32))
         == seal['salted_commitment_sha256'], 'original-salted-primary-payload')
    need(payload['prediction'] == runtime['engine'].predict(plan, payload['observation']),
         'exact-frozen-primary-recomputation')
    actual = universe_digest(payload['prediction']['universe'])
    need(actual == payload['actual_unlabelled_universe_sha256']
         == seal['actual_unlabelled_universe_sha256'], 'primary-exact-universe')
    return payload


def parse_receiver_index(config, runtime, index):
    """Structural decode only; the pure extractor admits actual Native reports.

    Receiver037 did not preserve random packet padding. Never reconstruct that
    body from a digest. The extractor must retain missing raw-byte semantics as
    PRIMARY unmodeled unless selected capture source actually supplies them.
    """
    need(index['schema'] == 'kpb-method03-receiver-index/v1'
         and index['binding'] == config['binding'], 'receiver-index-binding')
    rows = index['records']
    need(type(rows) is list and len(rows) == 6, 'all-six-actual-receiver-records')
    records, ordinals = [], set()
    for row in rows:
        ordinal = row['arrival_sequence']
        need(type(ordinal) is int and ordinal > 0 and ordinal not in ordinals,
             'actual-global-receiver-ordinal')
        ordinals.add(ordinal)
        need(row['schema'] == 'kpb-exit-transport-arrival/v1'
             and row['scope'] == 'UNTRUSTED_PUBLIC_TRANSPORT_ONLY'
             and row['framing'] == 'PASS' and row['http_status'] == 202
             and row['received_body_bytes'] == 4096 and row['broadcast'] is False
             and row['financial_validation'] == 'NOT_RUN', 'actual-untrusted-frame-receipt')
        projection = bytes.fromhex(row['projection_hex'])
        need(row['projection_hex'] == projection.hex() and len(projection) == 1844,
             'canonical-projection-width')
        proof = hexbytes(row['proof_hex128'], 128)
        arrival_id = hashlib.sha256(projection).hexdigest()
        need(word(row['exit_id']) == arrival_id, 'receiver-exact-projection-digest')
        word(row['frame_sha256'])
        need('frame_hex4096' not in row, 'selected-decoded-receiver-records-only')
        body = runtime['wire'].validate_public(projection)
        context = body.context
        need(context.profile.hex() == PROFILE and context.domain.hex() == DOMAIN,
             'actual-fixed-native-profile-domain')
        records.append({'ordinal': ordinal, 'arrival_id': arrival_id,
            'projection_hex': projection.hex(), 'proof_hex128': proof.hex(),
            'native': {'nf_hex32': body.nf.hex(), 'destination_spk_hex36': body.payout_spk.hex(),
                'payout': body.payout, 'fee': body.fee, 'action_hex32': body.action.hex(),
                'context_sha256': hashlib.sha256(context.encode()).hexdigest(),
                'context_hex276': context.encode().hex(), 'outpoint_hex36': context.point.hex(),
                'head_shape': {'cm_count': context.cm_count, 'nf_count': context.nf_count,
                               'reserve': context.reserve, 'exit_mode': 'continuing'},
                'domain_hex32': context.domain.hex(), 'profile_hex32': context.profile.hex()}})
    return {'schema': 'kpb-method03-parsed-arrivals/v1', 'binding': config['binding'], 'records': records}


def closed_marker(config, filename):
    write_new('/state/' + filename, {'binding': config['binding'], 'operation': config['operation'],
        'label': config['view'], 'owner': config['owner'], 'source_sha256': config['source_sha256'],
        'slot_grammar_sha256': config['slot_grammar_sha256'], 'spec_sha256': config['spec_sha256']})


def observe_primary(config, runtime):
    plan = read_plan(config, runtime)
    check_budget_permit(config)
    closed_marker(config, 'OBSERVATION-CLOSED')
    index = parse(stable_read('/capture/INDEX.json', private=True))
    journal = {'schema': 'kpb-method03-controller-journal/v1', 'binding': config['binding'],
        'records': [parse(line) for line in stable_read('/metadata/JOURNAL.jsonl', private=True).splitlines()
                    if line.strip()]}
    contacts = parse(stable_read('/contact/CONTACT.json', private=True))
    exposure = parse(stable_read('/baseline-A/EXPOSURE.json'))
    parsed = parse_receiver_index(config, runtime, index)
    observation = runtime['extractor'].extract(plan, journal, index, parsed, contacts, exposure,
                                               view='CONTROLLER+TERMINAL')
    prediction = runtime['engine'].predict(plan, observation)
    universe_sha = universe_digest(prediction['universe'])
    payload = {'schema': 'kpb-method03-private-primary-prediction/v1', 'binding': config['binding'],
        'source_sha256': config['source_sha256'], 'slot_grammar_sha256': config['slot_grammar_sha256'],
        'spec_sha256': config['spec_sha256'], 'actual_unlabelled_universe_sha256': universe_sha,
        'plan': plan, 'observation': observation, 'prediction': prediction}
    publish_capsule(config, payload, universe_sha)
    write_new('/out/STATUS.json', {'schema': 'kpb-method03-observation-status/v1',
        'binding': config['binding'], 'label': 'PRIMARY', 'kind': 'prediction', 'status': 'SEALED',
        'private_records_exported': False, 'overall_privacy_qualified': False})


def secondary_coverage(config, runtime):
    read_plan(config, runtime)
    primary = public_seal(config, 'PRIMARY')
    check_budget_permit(config)
    closed_marker(config, 'OBSERVATION-CLOSED')
    universe_sha = primary['actual_unlabelled_universe_sha256']
    capsule = runtime['extractor'].secondary_coverage(config['binding'], config['view'],
        config['slot_grammar_sha256'], universe_sha, capture_refs=[],
        limitations=[{'category': 'COMPLETE_DECLARED_SECONDARY_VIEW_NOT_CAPTURED',
                      'evidence_refs': ['scope/' + config['view']]}])
    # A coverage-only slot may never silently turn into a second scored primary.
    fields(capsule, ('schema', 'binding', 'label', 'kind', 'slot_grammar_sha256',
        'actual_unlabelled_universe_sha256', 'capture_refs', 'limitations', 'status', 'scored', 'gain_claimed'))
    need(capsule['schema'] == 'kpb-method03-secondary-coverage/v1'
         and capsule['binding'] == config['binding'] and capsule['label'] == config['view']
         and capsule['kind'] == 'coverage' and capsule['slot_grammar_sha256'] == config['slot_grammar_sha256']
         and capsule['actual_unlabelled_universe_sha256'] == universe_sha and capsule['capture_refs'] == []
         and capsule['limitations'] == [{'category': 'COMPLETE_DECLARED_SECONDARY_VIEW_NOT_CAPTURED',
                                        'evidence_refs': ['scope/' + config['view']]}]
         and capsule['status'] == 'MISSING' and capsule['scored'] is False
         and capsule['gain_claimed'] is False, 'secondary-capsule-cannot-relabel-primary')
    status = runtime['extractor'].public_secondary_status(capsule)
    fields(status, ('schema', 'binding', 'label', 'kind', 'slot_grammar_sha256',
        'actual_unlabelled_universe_sha256', 'status', 'capture_ref_count', 'limitation_count',
        'scored', 'gain_claimed'))
    need(status['schema'] == 'kpb-method03-secondary-coverage-status/v1'
         and status['binding'] == config['binding'] and status['label'] == config['view']
         and status['kind'] == 'coverage' and status['slot_grammar_sha256'] == config['slot_grammar_sha256']
         and status['actual_unlabelled_universe_sha256'] == universe_sha
         and status['status'] == 'MISSING' and status['capture_ref_count'] == 0
         and type(status['limitation_count']) is int and status['limitation_count'] > 0
         and status['scored'] is False and status['gain_claimed'] is False, 'secondary-missing-only')
    publish_capsule(config, capsule, universe_sha)
    write_new('/out/STATUS.json', status)


def private_owner_truth(config, observation):
    arrivals = {}
    for arm in ARMS:
        truth = parse(stable_read('/truth/' + arm + '.json', private=True))
        fields(truth, ('schema', 'binding', 'source_sha256', 'slot_grammar_sha256', 'spec_sha256',
            'owner_component', 'arm', 'profile_id_hex32', 'domain_hex32', 'nf_hex32',
            'destination_spk_hex36'))
        need(truth['schema'] == 'kpb-method03-one-owner-exit-truth/v1'
             and truth['binding'] == config['binding'] and truth['owner_component'] == config['owner']
             and type(truth['owner_component']) is int and truth['arm'] == arm
             and truth['profile_id_hex32'] == PROFILE and truth['domain_hex32'] == DOMAIN,
             'one-own-arm-truth-binding')
        for key in ('source_sha256', 'slot_grammar_sha256', 'spec_sha256'):
            need(truth[key] == config[key], 'truth-source-spec-slot')
        hexbytes(truth['nf_hex32'], 32); hexbytes(truth['destination_spk_hex36'], 36)
        matches = [row['arrival_id'] for row in observation['arrivals'][arm]
                   if row['native']['nf_hex32'] == truth['nf_hex32']
                   and row['native']['destination_spk_hex36'] == truth['destination_spk_hex36']]
        need(len(matches) == 1, 'unique-own-NF-and-SPK-in-actual-arm')
        arrivals[arm] = matches[0]
    return {'schema': 'kpb-method03-one-owner-truth/v1', 'binding': config['binding'],
            'owner': config['owner'], 'arrivals': arrivals}


def score_owner(config, runtime):
    plan = read_plan(config, runtime)
    seals = all_public_seals(config)
    check_public_barrier(config, seals)
    check_budget_permit(config, seals)
    closed_marker(config, 'SCORING-CLOSED')
    payload = read_primary_capsule(config, runtime, plan, seals['PRIMARY'])
    # This is the first read of any owner-labelled actual truth in the role.
    truth = private_owner_truth(config, payload['observation'])
    score = runtime['engine'].score_owner(plan, payload['observation'], payload['prediction'], truth)
    private = {'schema': 'kpb-method03-private-owner-score-payload/v1', 'binding': config['binding'],
        'source_sha256': config['source_sha256'], 'slot_grammar_sha256': config['slot_grammar_sha256'],
        'spec_sha256': config['spec_sha256'], 'owner': config['owner'],
        'primary_salted_commitment_sha256': seals['PRIMARY']['salted_commitment_sha256'],
        'actual_unlabelled_universe_sha256': seals['PRIMARY']['actual_unlabelled_universe_sha256'],
        'score': score}
    salt = secrets.token_bytes(32)
    write_new('/private-output/OWNER-SCORE.json', {'schema': 'kpb-method03-private-owner-score-capsule/v1',
        'salt_hex32': salt.hex(), 'payload': private})
    write_new('/out/SCORE-SEAL.json', {'schema': 'kpb-method03-public-owner-score-seal/v1',
        'binding': config['binding'], 'source_sha256': config['source_sha256'],
        'slot_grammar_sha256': config['slot_grammar_sha256'], 'spec_sha256': config['spec_sha256'],
        'owner': config['owner'], 'primary_salted_commitment_sha256': seals['PRIMARY']['salted_commitment_sha256'],
        'actual_unlabelled_universe_sha256': seals['PRIMARY']['actual_unlabelled_universe_sha256'],
        'salted_commitment_sha256': capsule_commitment(private, salt), 'private_score_exported': False})


def private_owner_scores(config, seals):
    scores = []
    for owner in range(3):
        seal = public_ref(config['score_seals'][str(owner)], '/score-seals/owner-' + str(owner) + '.json')
        fields(seal, ('schema', 'binding', 'source_sha256', 'slot_grammar_sha256', 'spec_sha256', 'owner',
            'primary_salted_commitment_sha256', 'actual_unlabelled_universe_sha256',
            'salted_commitment_sha256', 'private_score_exported'))
        need(seal['schema'] == 'kpb-method03-public-owner-score-seal/v1'
             and seal['binding'] == config['binding'] and type(seal['owner']) is int
             and seal['owner'] == owner and seal['private_score_exported'] is False
             and seal['primary_salted_commitment_sha256'] == seals['PRIMARY']['salted_commitment_sha256']
             and seal['actual_unlabelled_universe_sha256'] == seals['PRIMARY']['actual_unlabelled_universe_sha256'],
             'same-primary-owner-score-seal')
        for key in ('source_sha256', 'slot_grammar_sha256', 'spec_sha256'):
            need(seal[key] == config[key], 'owner-score-seal-source-spec-slot')
        capsule = parse(stable_read('/scores/owner-' + str(owner) + '.json', private=True))
        fields(capsule, ('schema', 'salt_hex32', 'payload'))
        need(capsule['schema'] == 'kpb-method03-private-owner-score-capsule/v1', 'private-owner-score-capsule')
        payload = capsule['payload']
        fields(payload, ('schema', 'binding', 'source_sha256', 'slot_grammar_sha256', 'spec_sha256', 'owner',
            'primary_salted_commitment_sha256', 'actual_unlabelled_universe_sha256', 'score'))
        need(payload['schema'] == 'kpb-method03-private-owner-score-payload/v1'
             and payload['binding'] == config['binding'] and type(payload['owner']) is int
             and payload['owner'] == owner, 'private-owner-score-binding')
        for key in ('source_sha256', 'slot_grammar_sha256', 'spec_sha256',
                    'primary_salted_commitment_sha256', 'actual_unlabelled_universe_sha256'):
            need(payload[key] == seal[key], 'private-owner-score-seal-scope')
        need(capsule_commitment(payload, hexbytes(capsule['salt_hex32'], 32))
             == word(seal['salted_commitment_sha256']), 'authenticated-private-owner-score')
        scores.append(payload['score'])
    return scores


def safe_public_aggregate(value):
    names = ('schema', 'binding', 'view', 'candidate_counts', 'all_joint_true_assignment_retained',
        'finite_primary_view_complete', 'bounded_route_candidate_increase', 'clock_qualified',
        'missing_coverage', 'unmodeled_count', 'primary_unmodeled_count', 'status',
        'overall_privacy_qualified', 'scope')
    result = {key: value[key] for key in names}
    result['per_owner_metrics'] = [{'owner': row['owner'], 'arms': {
        arm: {key: row['arms'][arm][key] for key in
              ('candidate_count', 'rank_interval', 'correct_unique', 'wrong_unique')}
        for arm in ARMS}} for row in value['per_owner_metrics']]
    need(result['overall_privacy_qualified'] is False
         and result['status'] in ('INVALID_MODEL', 'UNQUALIFIED'), 'bounded-public-result-only')
    return result


def aggregate(config, runtime):
    plan = read_plan(config, runtime)
    seals = all_public_seals(config)
    check_public_barrier(config, seals)
    check_budget_permit(config, seals)
    closed_marker(config, 'AGGREGATE-CLOSED')
    payload = read_primary_capsule(config, runtime, plan, seals['PRIMARY'])
    scores = private_owner_scores(config, seals)
    result = runtime['engine'].aggregate_owner_scores(plan, payload['observation'], payload['prediction'], scores)
    public = safe_public_aggregate(result)
    public['secondary_views'] = {label: {'kind': 'coverage', 'status': 'MISSING',
        'scored': False, 'gain': False, 'overall_privacy_qualified': False} for label in VIEWS[1:]}
    write_new('/out/RESULT.json', public)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=OPERATIONS)
    operation = parser.parse_args().operation
    try:
        close_setup_fds()
        config = require_namespace(operation)
        runtime = load_sources(config)
        {'observe-primary': observe_primary, 'secondary-coverage': secondary_coverage,
         'score-owner': score_owner, 'aggregate': aggregate}[operation](config, runtime)
    except BaseException:
        # Never export a private exception, value, filename or traceback.
        try:
            if Path('/out').is_dir() and not Path('/out/INCOMPLETE.json').exists():
                write_new('/out/INCOMPLETE.json', {'schema': 'kpb-method03-role-incomplete/v1',
                    'operation': operation, 'private_records_exported': False})
        except BaseException:
            pass
        os._exit(2)
    os._exit(0)


if __name__ == '__main__':
    main()
