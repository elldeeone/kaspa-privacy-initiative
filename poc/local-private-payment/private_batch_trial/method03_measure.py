"""UNSELECTED finite METHOD03 closed-role host; no private body reader.

The Root-frozen launcher, durable budget state and completed namespace roles
establish provenance. Imported flags and reference dictionaries do not.
"""
import json
import os
from pathlib import Path
import stat
import subprocess
import time

from method03_guard import load_guard
_GUARD = load_guard()

import method03_budget as budget

HERE = Path(__file__).absolute().parent
ROOT = HERE.parents[2]
DEV = ROOT / '.local/private-exit-method03-source-01'
LABELS = ('PRIMARY', 'TERMINAL_CONTACT', 'GLOBAL_UNION')
KINDS = {'PRIMARY': 'prediction', 'TERMINAL_CONTACT': 'coverage', 'GLOBAL_UNION': 'coverage'}
PROFILE = 'ea19260a60a8d0a54b8ad9848f82317c1d84059a1881be34d318bcca42493700'
DOMAIN = 'a0a1b4fbf4ce8505f17b24b354ffa81fc4201dc1e130b0358e3bc849611186e0'
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1'}


def need(value, category):
    if not value:
        raise ValueError(category)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def write_new(path, value):
    raw = encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())


def private_leaf(path):
    """Metadata only: no private read/hash/copy, even after role completion."""
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts
         and not any(item.is_symlink() for item in (path, *path.parents)), 'method03-private-leaf-path')
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
         and stat.S_IMODE(info.st_mode) in (0o400, 0o600),
         'method03-private-single-owned-leaf')
    return str(path)


def public_ref(path, read, pin=None):
    import hashlib
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'method03-public-absolute-ref')
    raw = read(path, pin)
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}, json.loads(raw)


def software(selected):
    wanted = [(HERE / 'method03_roles.py', '/src/method03_roles.py'),
        (DEV / 'metadata_attack.py', '/src/metadata_attack.py'),
        (DEV / 'metadata_extract.py', '/src/metadata_extract.py'),
        (HERE / 'exit_wire.py', '/src/private_batch_trial/exit_wire.py'),
        (HERE.parent / 'verification/wire.py', '/src/verification/wire.py'),
        (HERE.parent / 'private_exit_submission/packet.py', '/src/packet.py')]
    shared = Path(selected['public']) / 'selected-public'
    mounts, members = [], []
    for path, alias in wanted:
        row = next(row for row in selected['source_members'] if row['path'] == str(path))
        mounts += ['--ro-bind', str(shared / ('source-' + str(row['index']))), alias]
        members.append({'path': alias, 'sha256': row['sha256']})
    return mounts, members


def run_role(operation, config, state, output, private_output, mounts, software_mounts, read):
    # Every directory is an exclusive sibling of a globally consumed identity.
    state.mkdir(mode=0o700); output.mkdir(mode=0o700, parents=True); private_output.mkdir(mode=0o700)
    config_path, marker_path = state / 'CONFIG.json', state / 'NAMESPACE.json'
    write_new(config_path, config)
    write_new(marker_path, {'schema': 'kpb-method03-closed-role-namespace/v1', 'operation': operation,
                           'network': 'disabled', 'Original_slots': 0})
    argv = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
        *software_mounts, *mounts, '--ro-bind', str(config_path), '/CONFIG.json',
        '--ro-bind', str(marker_path), '/NAMESPACE.json', '--bind', str(state), '/state',
        '--bind', str(private_output), '/private-output', '--bind', str(output), '/out',
        '--chdir', '/tmp', '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
        '/usr/bin/python3', '-I', '-B', '-S', '/src/method03_roles.py', operation]
    started = time.monotonic_ns()
    with (state / 'STDOUT.log').open('xb') as stdout, (state / 'STDERR.log').open('xb') as stderr:
        process = subprocess.Popen(argv, stdout=stdout, stderr=stderr, env=CLEAN)
        pid = process.pid
        returncode = process.wait()
    completed = time.monotonic_ns()
    route = output / 'OPERATOR-ROUTE.json'
    write_new(route, {'schema': 'kpb-method03-closed-role-actual-route/v1', 'operation': operation,
        'binding': config['binding'], 'argv': argv, 'observed_launcher_pid': pid,
        'started_monotonic_ns': started, 'completed_monotonic_ns': completed,
        'returncode': returncode, 'controller_private_body_read_or_hash': False})
    route_ref, _ = public_ref(route, read)
    need(returncode == 0, 'method03-closed-role-refused-' + operation)
    leaf = 'RESULT.json' if operation == 'aggregate' else 'SCORE-SEAL.json' if operation == 'score-owner' else 'SEAL.json'
    ref, result = public_ref(output / leaf, read)
    completion = {'observed_launcher_pid': pid, 'returncode': returncode,
                  'completed_monotonic_ns': completed, 'event_ref': route_ref}
    return ref, result, completion


def model_plan(selected, binding, engine):
    return {'schema': 'kpb-method03-metadata-plan/v1', 'binding': binding,
        'view': 'CONTROLLER+TERMINAL', 'owners': [0, 1, 2], 'corrupt_owner': 1,
        'arms': {arm: {'note_index': selected['arms'][arm]['index'], 'fresh_payout': True,
                      'origin': selected['arms'][arm]['origin']} for arm in ('A', 'B')},
        'common_amounts': {'note': selected['value_sompi'], 'fee': selected['fee_sompi'],
                           'payout': selected['value_sompi'] - selected['fee_sompi']},
        'head_shape': {'cm_count': 3, 'nf_count': 1, 'reserve': selected['reserve_sompi'],
                       'exit_mode': 'continuing'},
        'sources': {row['path']: row['sha256'] for row in selected['source_members']},
        'native_source_pins': selected['native_source_pins'],
        'transport_source_pins': selected['transport_source_pins'],
        'required_coverage': list(engine.REQUIRED_COVERAGE)}


def measure(selected, selection_sha, generation, capture, read):
    """Run the fixed vector once; public results only leave closed roles."""
    claim = generation['budget_claim']
    description = budget.describe_claim(claim)
    binding = description['binding']
    need(binding['selection_sha256'] == selection_sha, 'method03-issued-selection-binding')
    # The selected network-off Native/INDEX producer must have completed first.
    # These refs do not import an accepted:true authority; only the frozen host
    # producer path may assemble them. INDEX stays unread/unhashed by this host.
    need(capture['schema'] == 'kpb-method03-source-produced-capture/v1'
         and capture['binding'] == binding, 'method03-selected-capture-producer')
    if capture['actual_native_checks_passed'] is not True:
        # Invalid/missing financial evidence cannot trigger an honest truth query.
        return {'status': 'UNQUALIFIED', 'reason': 'received-native-checks-incomplete',
                'scored': False, 'truth_intake': False, 'overall_privacy_qualified': False,
                'controller_private_body_read_or_hash': False}
    index_path = private_leaf(capture['private_index']['path'])
    journal_ref = capture['metadata_journal']
    # JSONL is an exact content-free source journal, not a single JSON object.
    read(Path(journal_ref['path']), journal_ref['sha256'])
    a_ref = capture['baseline_A_exposure']
    public_ref(a_ref['path'], read, a_ref['sha256'])
    from method03_generation import source_module, run_role as owner_role
    engine = source_module(selected, 'metadata_attack', read)
    public = Path(selected['public']) / 'measurement'; public.mkdir(mode=0o700)
    plan_path = public / 'PLAN.json'; write_new(plan_path, model_plan(selected, binding, engine))
    plan_ref, _ = public_ref(plan_path, read)
    # The corrupt-contact collector is already PRIMARY private-view intake,
    # so reserve it before constructing or launching that role, not merely
    # before the later observer namespace. Reuse this exact one-shot permit.
    primary_permit = budget.claim_view_intake_once(claim, 'PRIMARY')
    # Only the corrupt owner's actual private sender record and invoices enter
    # this role. Honest Original/truth/candidate directories are never mounted.
    private = Path(generation['private'])
    contacts = []
    for owner in range(3):
        for arm in ('A', 'B'):
            contacts += ['--ro-bind', private_leaf(private / ('invoice-' + str(owner)) / ('INVOICE-' + arm + '.bin')),
                         '/contacts/owner-' + str(owner) + '/INVOICE-' + arm + '.bin']
    own_record = private_leaf(private / 'construct-1/OWN-SENDER-RECORD.json')
    exits = capture['public_exits']
    owner_role(selected, selection_sha, 'contact', 'contact-owner-1', private / 'contact-owner-1',
        Path(selected['public']) / 'contact-owner-1', [*contacts, '--ro-bind', own_record,
        '/sender/OWN-SENDER-RECORD.json', '--ro-bind', generation['notes']['path'], '/public/NOTES.json',
        '--ro-bind', exits['path'], '/public/EXITS.json'], slot=1, original=True,
        notes_sha256=generation['notes']['sha256'], exits_sha256=exits['sha256'])
    contact = private_leaf(private / 'contact-owner-1/CONTACT.json')
    root = Path(description['owner_record_refs'][0]['path']).parent
    software_mounts, members = software(selected)
    common = {'schema': 'kpb-method03-closed-role-config/v1', 'binding': binding,
        'source_members': members, 'plan_ref': {'path': '/public/PLAN.json', 'sha256': plan_ref['sha256']},
        'public_seals': None, 'score_seals': None, 'barrier_ref': None, 'budget_permit_ref': None,
        'source_sha256': description['source_sha256'], 'slot_grammar_sha256': description['slot_grammar_sha256'],
        'spec_sha256': description['spec_sha256'], 'profile_id_hex32': PROFILE, 'domain_hex32': DOMAIN}
    seals, completions, capsules = {}, {}, {}
    for label in LABELS:
        permit = primary_permit if label == 'PRIMARY' else budget.claim_view_intake_once(claim, label)
        operation = 'observe-primary' if label == 'PRIMARY' else 'secondary-coverage'
        config = {**common, 'operation': operation, 'view': label, 'owner': None,
            'budget_permit_ref': {'path': '/public/BUDGET-PERMIT.json', 'sha256': permit['sha256']},
            'public_seals': None if label == 'PRIMARY' else {'PRIMARY': {
                'path': '/seals/PRIMARY.json', 'sha256': seals['PRIMARY']['sha256']}},
            'input_refs': {'receiver_index': '/capture/INDEX.json', 'event_journal': '/metadata/JOURNAL.jsonl',
                'contact_facts': '/contact/CONTACT.json', 'baseline_A_exposure': '/baseline-A/EXPOSURE.json'}
                if label == 'PRIMARY' else {}}
        mounts = ['--ro-bind', plan_ref['path'], '/public/PLAN.json', '--ro-bind', permit['path'], '/public/BUDGET-PERMIT.json']
        if label == 'PRIMARY':
            mounts += ['--ro-bind', index_path, '/capture/INDEX.json', '--ro-bind', journal_ref['path'],
                '/metadata/JOURNAL.jsonl', '--ro-bind', contact, '/contact/CONTACT.json',
                '--ro-bind', a_ref['path'], '/baseline-A/EXPOSURE.json']
        else:
            mounts += ['--ro-bind', seals['PRIMARY']['path'], '/seals/PRIMARY.json']
        state = root / ('view-' + label + '-work'); private_output = root / ('view-' + label + '-capsule')
        ref, result, completion = run_role(operation, config, state, public / label, private_output,
                                          mounts, software_mounts, read)
        need(result['binding'] == binding and result['label'] == label and result['kind'] == KINDS[label],
             'method03-actual-selected-sealed-view')
        seals[label], completions[label] = ref, completion
        capsules[label] = private_leaf(private_output / 'CAPSULE.json')
    completed_refs = []
    for label in description['selected_view_labels']:
        ref, value = public_ref(seals[label]['path'], read, seals[label]['sha256'])
        completed_refs.append({'label': label, 'kind': KINDS[label], 'binding': binding,
            'source_sha256': description['source_sha256'], 'public_plan_sha256': plan_ref['sha256'],
            'slot_grammar_sha256': description['slot_grammar_sha256'],
            'actual_unlabelled_universe_sha256': value['actual_unlabelled_universe_sha256'],
            'salted_public_seal': ref, 'salted_commitment_sha256': value['salted_commitment_sha256'],
            'completion': completions[label]})
    barrier = budget.mark_views_sealed(claim, completed_refs)
    barrier_ref = budget.barrier_ref(claim, barrier)
    all_seals = {label: {'path': '/seals/' + label + '.json', 'sha256': seals[label]['sha256']} for label in LABELS}
    base_mounts = ['--ro-bind', plan_ref['path'], '/public/PLAN.json', '--ro-bind', barrier_ref['path'],
        '/public/ALL-SEALS-BARRIER.json', '--ro-bind', capsules['PRIMARY'], '/capsules/PRIMARY.json']
    for label in LABELS:
        base_mounts += ['--ro-bind', seals[label]['path'], '/seals/' + label + '.json']
    score_refs, score_capsules, score_completions = {}, {}, []
    for owner in range(3):
        permit = budget.claim_truth_once(claim, barrier, owner)
        config = {**common, 'operation': 'score-owner', 'view': 'PRIMARY', 'owner': owner,
            'public_seals': all_seals, 'barrier_ref': {'path': '/public/ALL-SEALS-BARRIER.json', 'sha256': barrier_ref['sha256']},
            'budget_permit_ref': {'path': '/public/BUDGET-PERMIT.json', 'sha256': permit['sha256']}, 'input_refs': {}}
        # This is the first point where this owner's honest truth is mounted.
        mounts = [*base_mounts, '--ro-bind', permit['path'], '/public/BUDGET-PERMIT.json']
        for arm in ('A', 'B'):
            mounts += ['--ro-bind', private_leaf(generation['owners'][arm][owner]['private_truth_leaf']), '/truth/' + arm + '.json']
        state, output = root / ('score-' + str(owner) + '-work'), root / ('score-' + str(owner) + '-capsule')
        ref, value, completion = run_role('score-owner', config, state, public / ('owner-' + str(owner)), output,
                                          mounts, software_mounts, read)
        need(value['owner'] == owner and value['binding'] == binding, 'method03-actual-one-owner-score')
        score_refs[str(owner)] = ref; score_capsules[owner] = private_leaf(output / 'OWNER-SCORE.json')
        score_completions.append({'owner_component': owner, 'binding': binding,
            'source_sha256': description['source_sha256'], 'slot_grammar_sha256': description['slot_grammar_sha256'],
            'actual_unlabelled_universe_sha256': value['actual_unlabelled_universe_sha256'], 'completion': completion})
    permit = budget.claim_aggregate_once(claim, barrier, score_completions)
    config = {**common, 'operation': 'aggregate', 'view': 'PRIMARY', 'owner': None, 'public_seals': all_seals,
        'score_seals': {owner: {'path': '/score-seals/owner-' + owner + '.json', 'sha256': ref['sha256']}
                        for owner, ref in score_refs.items()},
        'barrier_ref': {'path': '/public/ALL-SEALS-BARRIER.json', 'sha256': barrier_ref['sha256']},
        'budget_permit_ref': {'path': '/public/BUDGET-PERMIT.json', 'sha256': permit['sha256']}, 'input_refs': {}}
    mounts = [*base_mounts, '--ro-bind', permit['path'], '/public/BUDGET-PERMIT.json']
    for owner in range(3):
        mounts += ['--ro-bind', score_capsules[owner], '/scores/owner-' + str(owner) + '.json',
                   '--ro-bind', score_refs[str(owner)]['path'], '/score-seals/owner-' + str(owner) + '.json']
    ref, result, _ = run_role('aggregate', config, root / 'aggregate-work', public / 'aggregate',
        root / 'aggregate-private-output', mounts, software_mounts, read)
    need(result['binding'] == binding and result['overall_privacy_qualified'] is False,
         'method03-public-aggregate-scope')
    return {'status': result['status'], 'public_result': ref, 'controller_private_body_read_or_hash': False}
