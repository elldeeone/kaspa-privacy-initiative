"""PUBLIC FAKE FIXTURES ONLY. No Original, notes/proofs, capture, Tor or namespace run.

Role filesystem reads/writes use a public in-memory fixture. Only the frozen
pure metadata engine is real; raw parsing/extraction uses explicitly invented
public bytes and adapters. This qualifies role ordering/serialization boundaries,
not Native validity, actual clocks, source provenance or a private experiment.
"""
import copy
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
ROLE_PATH = ROOT / 'poc/local-private-payment/private_batch_trial/method03_roles.py'
ROLE_SHA = '85a9024476aa38ad56ea3a9e74e5c3a232fc0c39f320962da3d927189826329f'
ENGINE_SHA = '5ace32051139233bc28b315085f6a73f4000530fe2b7d138bffd26f312f3c52e'
FIXTURE_SHA = '12cec1f9512453fa5448e58353544ded11c8ef1f4cbcbe2dc7ddb2282bb6b263'
GUARD_SHA = '23f060f18f06ac5b81ec833964a71969ca04467d367ac3b62f6af5f0882ad8e6'
CANARY = 'DELIBERATELY_PUBLIC_FAKE_SECRET_CANARY'


def load_public_sources():
    path = ROOT / 'poc/local-private-payment/private_batch_trial/method03_guard.py'
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
    assert not any(p.is_symlink() for p in (path, *path.parents))
    raw = path.read_bytes()  # Externally selected initial stdlib trust root only.
    assert hashlib.sha256(raw).hexdigest() == GUARD_SHA
    guard = types.ModuleType('method03_role_fixture_guard')
    guard.__file__ = str(path)
    sys.modules[guard.__name__] = guard
    exec(compile(raw, str(path), 'exec'), guard.__dict__)
    read = guard.load_guard()['read']  # Inventories all seven roots first.
    raw_engine = read(ROOT / '.local/private-exit-method03-source-01/metadata_attack.py', ENGINE_SHA)
    raw_fixture = read(ROOT / '.local/private-exit-method03-source-01/test_metadata_attack.py', FIXTURE_SHA)
    raw_role = read(ROLE_PATH, ROLE_SHA)
    def module(name, source, filename):
        result = types.ModuleType(name)
        result.__file__ = filename
        sys.modules[name] = result
        exec(compile(source, filename, 'exec'), result.__dict__)
        return result
    engine = module('metadata_attack', raw_engine, '/src/metadata_attack.py')
    fixture = module('method03_public_math_fixture', raw_fixture, '/public-fixture/test_metadata_attack.py')
    roles = module('method03_role_fixture', raw_role, '/src/method03_roles.py')
    return roles, engine, fixture


def public_coverage_adapter(binding, label, slot, universe, capture_refs, limitations):
    """Declared fake data adapter; the parent's pure extractor has separate tests."""
    return {'schema': 'kpb-method03-secondary-coverage/v1', 'binding': copy.deepcopy(binding),
        'label': label, 'kind': 'coverage', 'slot_grammar_sha256': slot,
        'actual_unlabelled_universe_sha256': universe, 'capture_refs': copy.deepcopy(capture_refs),
        'limitations': copy.deepcopy(limitations), 'status': 'MISSING', 'scored': False, 'gain_claimed': False}


def public_coverage_status_adapter(capsule):
    return {'schema': 'kpb-method03-secondary-coverage-status/v1', 'binding': copy.deepcopy(capsule['binding']),
        'label': capsule['label'], 'kind': 'coverage', 'slot_grammar_sha256': capsule['slot_grammar_sha256'],
        'actual_unlabelled_universe_sha256': capsule['actual_unlabelled_universe_sha256'],
        'status': 'MISSING', 'capture_ref_count': 0, 'limitation_count': len(capsule['limitations']),
        'scored': False, 'gain_claimed': False}


class MemoryFiles:
    def __init__(self, roles):
        self.roles, self.blobs, self.trace = roles, {}, []
    def put(self, path, value):
        raw = value if type(value) is bytes else self.roles.encoded(value)
        self.blobs[path] = raw
        return {'path': path, 'sha256': hashlib.sha256(raw).hexdigest()}
    def read(self, path, expected=None, private=False):
        path = str(path)
        self.trace.append(('read', path, private))
        raw = self.blobs[path]
        if expected is not None and hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('fixture-public-hash')
        return raw
    def write(self, path, value, mode=0o400):
        path = str(path)
        self.trace.append(('write', path, mode))
        if path in self.blobs:
            raise FileExistsError(path)
        if mode != 0o400:
            raise AssertionError('fixture outputs must be private400 or public400')
        return self.roles.encoded(value) if self.put(path, value) else None
    def value(self, path):
        return self.roles.parse(self.blobs[path])


class RoleFixture:
    def __init__(self, roles, engine, fixture, operation='score-owner', owner=0, view='PRIMARY', attempt_id=None):
        self.r, self.engine = roles, engine
        self.plan, self.obs, self.truth = fixture.fixture()
        if attempt_id is not None:
            self.plan['binding']['attempt_id'] = attempt_id
            self.obs['binding'] = copy.deepcopy(self.plan['binding'])
            for truth in self.truth:
                truth['binding'] = copy.deepcopy(self.plan['binding'])
        # Root's current capture has no full4096 padding; preserve this primary
        # limitation even though the finite pure matching graph remains visible.
        self.obs['unmodeled'].append({'scope': engine.VIEW, 'category': 'full-received-packet-not-retained',
                                      'evidence_refs': ['public-fixture/decoded-only']})
        self.obs['private_canary'] = CANARY
        self.pred = engine.predict(self.plan, self.obs)
        self.fs = MemoryFiles(roles)
        self.config = {'schema': 'kpb-method03-closed-role-config/v1', 'operation': operation,
            'binding': copy.deepcopy(self.plan['binding']), 'source_members': [],
            'view': view, 'owner': owner if operation == 'score-owner' else None,
            'public_seals': None, 'score_seals': None, 'barrier_ref': None, 'budget_permit_ref': None,
            'source_sha256': '55' * 32, 'slot_grammar_sha256': '66' * 32, 'spec_sha256': '77' * 32,
            'profile_id_hex32': roles.PROFILE, 'domain_hex32': roles.DOMAIN,
            'input_refs': copy.deepcopy(roles.INPUTS[operation])}
        self.config['plan_ref'] = self.fs.put('/public/PLAN.json', self.plan)
        universe_sha = roles.universe_digest(self.pred['universe'])
        self.payload = {'schema': 'kpb-method03-private-primary-prediction/v1',
            'binding': copy.deepcopy(self.config['binding']), 'source_sha256': self.config['source_sha256'],
            'slot_grammar_sha256': self.config['slot_grammar_sha256'], 'spec_sha256': self.config['spec_sha256'],
            'actual_unlabelled_universe_sha256': universe_sha, 'plan': self.plan,
            'observation': self.obs, 'prediction': self.pred}
        self.seals, refs = {}, {}
        for index, label in enumerate(roles.VIEWS):
            private = self.payload if label == 'PRIMARY' else {'public_fixture': label, 'canary': CANARY}
            salt = bytes([10 + index]) * 32
            seal = {'schema': 'kpb-method03-public-role-seal/v1', 'binding': self.config['binding'],
                'label': label, 'kind': roles.KINDS[label], 'source_sha256': self.config['source_sha256'],
                'slot_grammar_sha256': self.config['slot_grammar_sha256'], 'spec_sha256': self.config['spec_sha256'],
                'actual_unlabelled_universe_sha256': universe_sha,
                'salted_commitment_sha256': roles.capsule_commitment(private, salt),
                'sealed_before_truth': True, 'private_records_exported': False}
            self.seals[label] = seal
            refs[label] = self.fs.put('/seals/' + label + '.json', seal)
            if label == 'PRIMARY':
                self.fs.put('/capsules/PRIMARY.json', {'schema': 'kpb-method03-private-role-capsule/v1',
                    'salt_hex32': salt.hex(), 'payload': private})
        if operation == 'secondary-coverage':
            self.config['public_seals'] = {'PRIMARY': refs['PRIMARY']}
        elif operation not in ('observe-primary',):
            self.config['public_seals'] = refs
        completions = []
        for index, label in enumerate(roles.VIEWS):
            completions.append({'label': label, 'kind': roles.KINDS[label], 'binding': self.config['binding'],
                'source_sha256': self.config['source_sha256'],
                'public_plan_sha256': self.config['plan_ref']['sha256'],
                'slot_grammar_sha256': self.config['slot_grammar_sha256'],
                'actual_unlabelled_universe_sha256': universe_sha,
                'salted_public_seal': {'path': '/fixture-source/' + label + '/SEAL.json', 'sha256': refs[label]['sha256']},
                'salted_commitment_sha256': self.seals[label]['salted_commitment_sha256'],
                'completion': {'observed_launcher_pid': 100 + index, 'returncode': 0,
                    'completed_monotonic_ns': 5000 + index,
                    'event_ref': {'path': '/fixture-source/events/' + label, 'sha256': '88' * 32}}})
        barrier = {'schema': 'kpb-method03-all-selected-views-sealed/v2', 'binding': self.config['binding'],
            'source_sha256': self.config['source_sha256'], 'slot_grammar_sha256': self.config['slot_grammar_sha256'],
            'actual_unlabelled_universe_sha256': universe_sha, 'completed_view_refs': completions}
        if operation in ('score-owner', 'aggregate'):
            self.config['barrier_ref'] = self.fs.put('/public/ALL-SEALS-BARRIER.json', barrier)
        self.set_permit()
        for arm in roles.ARMS:
            row = self.obs['arrivals'][arm][owner]
            self.fs.put('/truth/' + arm + '.json', {'schema': 'kpb-method03-one-owner-exit-truth/v1',
                'binding': self.config['binding'], 'source_sha256': self.config['source_sha256'],
                'slot_grammar_sha256': self.config['slot_grammar_sha256'], 'spec_sha256': self.config['spec_sha256'],
                'owner_component': owner, 'arm': arm, 'profile_id_hex32': roles.PROFILE,
                'domain_hex32': roles.DOMAIN, 'nf_hex32': row['native']['nf_hex32'],
                'destination_spk_hex36': row['native']['destination_spk_hex36']})
        self.runtime = {'engine': engine, 'extractor': types.SimpleNamespace(extract=lambda *a, **kw: copy.deepcopy(self.obs))}
    def set_permit(self):
        c, r = self.config, self.r
        observe = c['operation'] in ('observe-primary', 'secondary-coverage')
        value = {'schema': 'kpb-method03-budget-permit/v1',
            'operation': 'observe-view' if observe else c['operation'], 'label': c['view'],
            'kind': r.KINDS[c['view']] if observe else 'score' if c['operation'] == 'score-owner' else 'aggregate',
            'owner_component': c['owner'], 'binding': c['binding'], 'source_sha256': c['source_sha256'],
            'slot_grammar_sha256': c['slot_grammar_sha256'], 'spec_sha256': c['spec_sha256'],
            'reservation_keys': [str(i + 1) * 64 for i in range(3)],
            'actual_unlabelled_universe_sha256': None if observe else self.seals['PRIMARY']['actual_unlabelled_universe_sha256'],
            'all_seals_sha256': None if observe else c['barrier_ref']['sha256']}
        c['budget_permit_ref'] = self.fs.put('/public/BUDGET-PERMIT.json', value)
    def patches(self):
        return mock.patch.multiple(self.r, stable_read=self.fs.read, write_new=self.fs.write)
    def add_scores(self):
        refs = {}
        for owner, truth in enumerate(self.truth):
            score = self.engine.score_owner(self.plan, self.obs, self.pred, truth)
            payload = {'schema': 'kpb-method03-private-owner-score-payload/v1', 'binding': self.config['binding'],
                'source_sha256': self.config['source_sha256'], 'slot_grammar_sha256': self.config['slot_grammar_sha256'],
                'spec_sha256': self.config['spec_sha256'], 'owner': owner,
                'primary_salted_commitment_sha256': self.seals['PRIMARY']['salted_commitment_sha256'],
                'actual_unlabelled_universe_sha256': self.seals['PRIMARY']['actual_unlabelled_universe_sha256'], 'score': score}
            salt = bytes([20 + owner]) * 32
            self.fs.put('/scores/owner-' + str(owner) + '.json',
                {'schema': 'kpb-method03-private-owner-score-capsule/v1', 'salt_hex32': salt.hex(), 'payload': payload})
            seal = {key: value for key, value in payload.items() if key not in ('schema', 'score')}
            seal.update(schema='kpb-method03-public-owner-score-seal/v1',
                salted_commitment_sha256=self.r.capsule_commitment(payload, salt), private_score_exported=False)
            refs[str(owner)] = self.fs.put('/score-seals/owner-' + str(owner) + '.json', seal)
        self.config['score_seals'] = refs


class Method03RoleControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r, cls.engine, cls.math_fixture = load_public_sources()
    def fixture(self, **kwargs):
        result = RoleFixture(self.r, self.engine, self.math_fixture, **kwargs)
        result.runtime['extractor'].secondary_coverage = public_coverage_adapter
        result.runtime['extractor'].public_secondary_status = public_coverage_status_adapter
        return result
    def assert_no_public_secrets(self, fs):
        public = b''.join(raw for path, raw in fs.blobs.items() if path.startswith('/out/'))
        for forbidden in (CANARY.encode(), b'salt_hex32', b'joint_models', b'prediction_sha256',
                          b'observation_sha256', b'digest_tie_rank', b'compatible_joint_model_indices'):
            self.assertNotIn(forbidden, public)

    def test_primary_closes_before_private_intake_and_exports_only_salted_seal(self):
        f = self.fixture(operation='observe-primary')
        f.fs.put('/capture/INDEX.json', {'fixture': CANARY})
        f.fs.put('/metadata/JOURNAL.jsonl', b'{"fixture":"PUBLIC"}\n')
        f.fs.put('/contact/CONTACT.json', {'fixture': CANARY})
        f.fs.put('/baseline-A/EXPOSURE.json', {'fixture': 'PUBLIC_BASELINE_A'})
        def extract(plan, journal, index, parsed, contacts, exposure, view):
            self.assertEqual(journal, {'schema': 'kpb-method03-controller-journal/v1',
                'binding': f.config['binding'], 'records': [{'fixture': 'PUBLIC'}]})
            self.assertEqual(view, 'CONTROLLER+TERMINAL')
            return copy.deepcopy(f.obs)
        f.runtime['extractor'].extract = extract
        with f.patches(), mock.patch.object(self.r, 'parse_receiver_index', return_value={'fixture': 'PUBLIC_PARSED'}):
            self.r.observe_primary(f.config, f.runtime)
        closed = f.fs.trace.index(('write', '/state/OBSERVATION-CLOSED', 0o400))
        self.assertTrue(all(i > closed for i, row in enumerate(f.fs.trace) if row[0] == 'read' and row[2]))
        capsule = f.fs.value('/private-output/CAPSULE.json')
        seal = f.fs.value('/out/SEAL.json')
        self.assertEqual(self.r.capsule_commitment(capsule['payload'], bytes.fromhex(capsule['salt_hex32'])),
                         seal['salted_commitment_sha256'])
        self.assertIn(CANARY, str(capsule))
        self.assert_no_public_secrets(f.fs)

    def test_score_admits_all_public_barriers_before_capsule_and_own_truth(self):
        f = self.fixture()
        with f.patches():
            self.r.score_owner(f.config, f.runtime)
        reads = [row[1] for row in f.fs.trace if row[0] == 'read']
        first_private = next(i for i, row in enumerate(f.fs.trace) if row[0] == 'read' and row[2])
        for label in self.r.VIEWS:
            self.assertLess(next(i for i, row in enumerate(f.fs.trace) if row[:2] == ('read', '/seals/' + label + '.json')), first_private)
        self.assertLess(f.fs.trace.index(('write', '/state/SCORING-CLOSED', 0o400)), first_private)
        self.assertLess(reads.index('/capsules/PRIMARY.json'), reads.index('/truth/A.json'))
        private = f.fs.value('/private-output/OWNER-SCORE.json')['payload']['score']
        self.assertIn('digest_tie_rank', private['metrics']['B'])
        self.assertIn('compatible_joint_model_indices', private)
        self.assert_no_public_secrets(f.fs)

    def test_missing_or_mixed_seals_fail_before_slot_or_private_read(self):
        for mutation in ('missing', 'binding', 'universe', 'kind'):
            with self.subTest(mutation=mutation):
                f = self.fixture()
                if mutation == 'missing':
                    del f.fs.blobs['/seals/GLOBAL_UNION.json']
                else:
                    row = f.fs.value('/seals/GLOBAL_UNION.json')
                    if mutation == 'binding': row['binding'] = dict(row['binding'], attempt_id='33333333-3333-4333-8333-333333333333')
                    elif mutation == 'universe': row['actual_unlabelled_universe_sha256'] = '99' * 32
                    else: row['kind'] = 'prediction'
                    f.config['public_seals']['GLOBAL_UNION'] = f.fs.put('/seals/GLOBAL_UNION.json', row)
                with f.patches(), self.assertRaises((ValueError, KeyError)):
                    self.r.score_owner(f.config, f.runtime)
                self.assertNotIn('/state/SCORING-CLOSED', f.fs.blobs)
                self.assertFalse(any(row[0] == 'read' and row[2] for row in f.fs.trace))

    def test_tampered_capsule_and_wrong_owner_arm_or_nf_spk_refuse(self):
        for mutation in ('capsule', 'owner', 'arm', 'nf_spk'):
            with self.subTest(mutation=mutation):
                f = self.fixture()
                if mutation == 'capsule':
                    cap = f.fs.value('/capsules/PRIMARY.json'); cap['payload']['private_canary'] = CANARY
                    f.fs.put('/capsules/PRIMARY.json', cap)
                else:
                    truth = f.fs.value('/truth/A.json')
                    if mutation == 'owner': truth['owner_component'] = 2
                    elif mutation == 'arm': truth['arm'] = 'B'
                    else: truth['destination_spk_hex36'] = f.obs['arrivals']['A'][2]['native']['destination_spk_hex36']
                    f.fs.put('/truth/A.json', truth)
                with f.patches(), self.assertRaises(ValueError): self.r.score_owner(f.config, f.runtime)
                self.assertNotIn('/private-output/OWNER-SCORE.json', f.fs.blobs)
                self.assert_no_public_secrets(f.fs)

    def test_fixed_state_replay_and_fresh_attempt_cannot_reopen_intake(self):
        f = self.fixture()
        with f.patches(): self.r.score_owner(f.config, f.runtime)
        first_private_reads = sum(row[0] == 'read' and row[2] for row in f.fs.trace)
        with f.patches(), self.assertRaises(FileExistsError): self.r.score_owner(f.config, f.runtime)
        self.assertEqual(sum(row[0] == 'read' and row[2] for row in f.fs.trace), first_private_reads)
        fresh = self.fixture(attempt_id='44444444-4444-4444-8444-444444444444')
        # Even with entirely consistent fresh public bindings, the canonical
        # persistent state path stays closed independently of label spellings.
        fresh.fs.blobs['/state/SCORING-CLOSED'] = f.fs.blobs['/state/SCORING-CLOSED']
        with fresh.patches(), self.assertRaises(FileExistsError): self.r.score_owner(fresh.config, fresh.runtime)
        self.assertFalse(any(row[0] == 'read' and row[2] for row in fresh.fs.trace))

    def test_both_secondaries_are_salted_missing_coverage_without_private_reads(self):
        for label in self.r.VIEWS[1:]:
            with self.subTest(label=label):
                f = self.fixture(operation='secondary-coverage', view=label)
                with f.patches(): self.r.secondary_coverage(f.config, f.runtime)
                capsule = f.fs.value('/private-output/CAPSULE.json')
                self.assertEqual(capsule['payload']['kind'], 'coverage')
                self.assertEqual(capsule['payload']['status'], 'MISSING')
                self.assertFalse(capsule['payload']['scored']); self.assertFalse(capsule['payload']['gain_claimed'])
                self.assertNotIn('prediction', capsule['payload'])
                self.assertFalse(any(row[0] == 'read' and row[2] for row in f.fs.trace))
                self.assert_no_public_secrets(f.fs)

    def test_secondary_cannot_relabel_primary_or_export_extra_private_fields(self):
        for mutation in ('primary', 'private_status'):
            with self.subTest(mutation=mutation):
                f = self.fixture(operation='secondary-coverage', view='GLOBAL_UNION')
                if mutation == 'primary':
                    f.runtime['extractor'].secondary_coverage = lambda *a, **kw: copy.deepcopy(f.payload)
                else:
                    original = f.runtime['extractor'].public_secondary_status
                    f.runtime['extractor'].public_secondary_status = lambda value: dict(original(value), private_extra=CANARY)
                with f.patches(), self.assertRaises(ValueError): self.r.secondary_coverage(f.config, f.runtime)
                self.assertNotIn('/out/SEAL.json', f.fs.blobs)
                self.assert_no_public_secrets(f.fs)

    def test_decoded_receiver_parser_never_reconstructs_padding_or_proofs(self):
        f = self.fixture(operation='observe-primary')
        rows, bodies = [], {}
        for slot in range(6):
            projection = b'KPBXFX01' + bytes(1835) + bytes([slot])
            proof = bytes([slot + 10]) * 128
            native = f.obs['arrivals']['A' if slot < 3 else 'B'][slot % 3]['native']
            context_raw = bytes([slot // 3 + 1]) * 276
            context = types.SimpleNamespace(profile=bytes.fromhex(self.r.PROFILE), domain=bytes.fromhex(self.r.DOMAIN),
                point=bytes.fromhex(native['outpoint_hex36']), cm_count=3, nf_count=1, reserve=6_000_000_000,
                encode=lambda value=context_raw: value)
            bodies[projection] = types.SimpleNamespace(context=context, nf=bytes.fromhex(native['nf_hex32']),
                payout_spk=bytes.fromhex(native['destination_spk_hex36']), payout=199_999_999, fee=1,
                action=bytes.fromhex(native['action_hex32']))
            rows.append({'schema': 'kpb-exit-transport-arrival/v1', 'scope': 'UNTRUSTED_PUBLIC_TRANSPORT_ONLY',
                'arrival_sequence': slot + 1, 'framing': 'PASS', 'http_status': 202, 'received_body_bytes': 4096,
                'broadcast': False, 'financial_validation': 'NOT_RUN', 'projection_hex': projection.hex(),
                'proof_hex128': proof.hex(), 'exit_id': hashlib.sha256(projection).hexdigest(), 'frame_sha256': 'cc' * 32})
        index = {'schema': 'kpb-method03-receiver-index/v1', 'binding': f.config['binding'], 'records': rows}
        packet = types.SimpleNamespace(PROJECTION_BYTES=(1796, 1844),
            decode=mock.Mock(side_effect=AssertionError('no raw frame exists')),
            encode=mock.Mock(side_effect=AssertionError('never fabricate padding')))
        runtime = {'packet': packet, 'wire': types.SimpleNamespace(validate_public=lambda value: bodies[value])}
        parsed = self.r.parse_receiver_index(f.config, runtime, index)
        self.assertEqual([row['ordinal'] for row in parsed['records']], [1, 2, 3, 4, 5, 6])
        self.assertTrue(all(set(row) == {'ordinal', 'arrival_id', 'projection_hex', 'proof_hex128', 'native'}
                            for row in parsed['records']))
        packet.decode.assert_not_called(); packet.encode.assert_not_called()
        for mutation in ('ordinal', 'projection_hash', 'proof_case', 'invented_frame'):
            with self.subTest(mutation=mutation):
                bad = copy.deepcopy(index)
                if mutation == 'ordinal': bad['records'][1]['arrival_sequence'] = 1
                elif mutation == 'projection_hash': bad['records'][0]['exit_id'] = 'dd' * 32
                elif mutation == 'proof_case': bad['records'][0]['proof_hex128'] = bad['records'][0]['proof_hex128'].upper()
                else: bad['records'][0]['frame_hex4096'] = '00' * 4096
                with self.assertRaises(ValueError): self.r.parse_receiver_index(f.config, runtime, bad)

    def test_complete_aggregate_authenticates_private_scores_without_exporting_masks(self):
        f = self.fixture(operation='aggregate'); f.add_scores()
        with f.patches(): self.r.aggregate(f.config, f.runtime)
        result = f.fs.value('/out/RESULT.json')
        self.assertTrue(result['all_joint_true_assignment_retained'])
        self.assertFalse(result['bounded_route_candidate_increase'])
        self.assertEqual(result['status'], 'UNQUALIFIED')
        self.assertTrue(all(v['status'] == 'MISSING' and not v['scored'] and not v['gain']
                            for v in result['secondary_views'].values()))
        self.assert_no_public_secrets(f.fs)

    def test_tampered_owner_score_salt_or_scope_cannot_be_imported(self):
        for mutation in ('salt', 'owner', 'primary'):
            with self.subTest(mutation=mutation):
                f = self.fixture(operation='aggregate'); f.add_scores()
                cap = f.fs.value('/scores/owner-0.json')
                if mutation == 'salt': cap['salt_hex32'] = 'aa' * 32
                elif mutation == 'owner': cap['payload']['owner'] = 2
                else: cap['payload']['primary_salted_commitment_sha256'] = 'bb' * 32
                f.fs.put('/scores/owner-0.json', cap)
                with f.patches(), self.assertRaises(ValueError): self.r.aggregate(f.config, f.runtime)
                self.assertNotIn('/out/RESULT.json', f.fs.blobs)

    def test_budget_and_exact_barrier_mismatch_refuse_before_private_intake(self):
        for mutation in ('operation', 'owner', 'source', 'universe', 'barrier', 'view_kind'):
            with self.subTest(mutation=mutation):
                f = self.fixture()
                if mutation == 'view_kind':
                    value = f.fs.value('/public/ALL-SEALS-BARRIER.json')
                    value['completed_view_refs'][1]['kind'] = 'prediction'
                    f.config['barrier_ref'] = f.fs.put('/public/ALL-SEALS-BARRIER.json', value)
                else:
                    value = f.fs.value('/public/BUDGET-PERMIT.json')
                    key = {'operation': 'operation', 'owner': 'owner_component', 'source': 'source_sha256',
                           'universe': 'actual_unlabelled_universe_sha256', 'barrier': 'all_seals_sha256'}[mutation]
                    value[key] = 2 if mutation == 'owner' else 'WRONG_PUBLIC_FIXTURE_BINDING'
                    f.config['budget_permit_ref'] = f.fs.put('/public/BUDGET-PERMIT.json', value)
                with f.patches(), self.assertRaises(ValueError): self.r.score_owner(f.config, f.runtime)
                self.assertNotIn('/state/SCORING-CLOSED', f.fs.blobs)
                self.assertFalse(any(row[0] == 'read' and row[2] for row in f.fs.trace))

    def test_unlabelled_universe_is_order_invariant_and_salt_is_binding(self):
        f = self.fixture()
        universe = f.pred['universe']
        reverse = {a: list(reversed(v)) for a, v in universe.items()}
        self.assertEqual(self.r.universe_digest(universe), self.r.universe_digest(reverse))
        self.assertNotEqual(self.r.capsule_commitment({'fixture': CANARY}, b'a' * 32),
                            self.r.capsule_commitment({'fixture': CANARY}, b'b' * 32))
        with self.assertRaises(ValueError): self.r.capsule_commitment({'fixture': CANARY}, b'a' * 31)

    def test_public_aggregate_uses_explicit_field_allowlist(self):
        f = self.fixture(); scores = [self.engine.score_owner(f.plan, f.obs, f.pred, t) for t in f.truth]
        result = self.engine.aggregate_owner_scores(f.plan, f.obs, f.pred, scores)
        result['private_extra'] = CANARY
        for row in result['per_owner_metrics']:
            for arm in self.r.ARMS:
                row['arms'][arm].update(digest_tie_rank=1, owner_arrival_id=CANARY)
        safe = self.r.safe_public_aggregate(result)
        self.assertNotIn(CANARY, str(safe)); self.assertNotIn('digest_tie_rank', str(safe))

    def test_selected_source_admission_precedes_project_execution(self):
        f = self.fixture(operation='observe-primary')
        f.config['source_members'] = [{'path': p, 'sha256': h} for p, h in {
            **self.r.SOURCE_PINS, '/src/method03_roles.py': ROLE_SHA,
            '/src/metadata_extract.py': 'ab' * 32}.items()]
        trace = []
        def admitted(path, expected=None, private=False):
            self.assertFalse(private); trace.append(('admit', path, expected)); return b'PUBLIC_SOURCE_ORACLE'
        def execute(name, path, raw):
            self.assertEqual(sum(row[0] == 'admit' for row in trace), 6)
            trace.append(('exec', path)); return types.SimpleNamespace()
        with mock.patch.object(self.r, 'stable_read', side_effect=admitted), \
             mock.patch.object(self.r, 'selected_module', side_effect=execute): self.r.load_sources(f.config)
        bad = copy.deepcopy(f.config); bad['source_members'][0]['sha256'] = 'ff' * 32
        with mock.patch.object(self.r, 'stable_read') as reader, self.assertRaises(ValueError): self.r.load_sources(bad)
        reader.assert_not_called()

    def test_namespace_refuses_contact_in_secondary_and_network_interface(self):
        f = self.fixture(operation='secondary-coverage', view='TERMINAL_CONTACT')
        f.fs.put('/CONFIG.json', f.config)
        f.fs.put('/NAMESPACE.json', {'schema': 'kpb-method03-closed-role-namespace/v1',
            'operation': 'secondary-coverage', 'network': 'disabled', 'Original_slots': 0})
        for unexpected, interfaces in (('/contact', 'lo'), ('/original', 'lo'), (None, 'lo\neth0')):
            with self.subTest(path=unexpected, interfaces=interfaces), f.patches(), \
                 mock.patch.object(self.r, 'assert_no_ambient_fds'), \
                 mock.patch.object(Path, 'exists', lambda p: str(p) == unexpected), \
                 mock.patch.object(Path, 'read_text', return_value='header\nheader\n' + '\n'.join(' '+x+': 0' for x in interfaces.splitlines())), \
                 self.assertRaises(ValueError): self.r.require_namespace('secondary-coverage')

    def test_owned_public_fixture_leaf_rejects_symlink_hardlink_and_overwrite(self):
        with tempfile.TemporaryDirectory(prefix='public-method03-role-fixture-') as directory:
            leaf = Path(directory) / 'known-public.json'
            self.r.write_new(leaf, {'fixture': CANARY})
            raw = self.r.stable_read(leaf, hashlib.sha256(self.r.encoded({'fixture': CANARY})).hexdigest(), private=True)
            self.assertIn(CANARY.encode(), raw)
            with self.assertRaises(FileExistsError): self.r.write_new(leaf, {})
            alias = Path(directory) / 'alias'; alias.symlink_to(leaf)
            with self.assertRaises(ValueError): self.r.stable_read(alias, private=True)
            alias.unlink(); os.link(leaf, alias)
            with self.assertRaises(ValueError): self.r.stable_read(leaf, private=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
