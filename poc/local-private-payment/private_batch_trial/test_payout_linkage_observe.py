"""Public fixed model controls; no actual contact, Original, proof or truth body.

The mathematical fixtures mock only the public Exit parser/statement seam and
role filesystem aliases. A separate real bwrap control admits the four actual
public source leaves with a real netoff /proc and no contact or truth mount.
Dummy proof bytes are explicit; these controls establish no proof/privacy claim.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import payout_linkage_observe as worker

HERE = Path(__file__).absolute().parent
OBSERVER_SHA = '8b0deffe4892abe9f4b92b52c049e5a6868600b0a1a2e538ce815aabd3f2bc74'
MATCHER_SHA = '06282c791f5c8ca6ddb90e1ca0147a4bc0dc90639efb887bbd621b3a7d677089'
EXIT_SHA = 'fabf7361f030e25ec4a52a72691fef4bcfe03f6fef369ff33b8fa55dd01ccb6a'


class PublicModel:
    def __init__(self):
        self.bound = {'method_sha256': worker.METHOD, 'selection_sha256': 'ab' * 32,
                      'trial_id': 'public-method02-fixture', 'phase': 'private-payout-linkage-02',
                      'attempt_id': 'fixed-public-vector'}
        self.raws, self.effects, self.packet_arms = {}, {}, {}
        self.contacts = []
        for owner in range(3):
            for index in (7, 9):
                self.contacts.append({'owner': owner, 'native_pk_hex32': (bytes([10 + index + owner]) * 32).hex(),
                    'delivery_pk_hex32': (bytes([40 + owner]) * 32).hex(), 'invoice_index': index,
                    'domain_hex32': (b'D' * 32).hex(), 'profile_hex32': (b'P' * 32).hex()})
        for arm_number, arm in enumerate(worker.ARMS):
            context = SimpleNamespace(chain=b'C' * 32, pool=b'L' * 32, profile=b'P' * 32,
                domain=b'D' * 32, service=b'S' * 32, cm_count=3, nf_count=1,
                reserve=6_000_000_000, encode=lambda arm=arm: arm.encode() * 276)
            rows = []
            for owner in range(3):
                raw = (('PUBLIC-MODEL-' + arm + '-' + str(owner) + '/').encode() * 200)[:1844]
                self.raws[(arm, owner)] = raw
                native_pk = bytes([17 + owner] if arm == 'A' else [90 + owner]) * 32
                self.effects[raw] = SimpleNamespace(context=context, nf=bytes([50 + 3 * arm_number + owner]) * 32,
                    payout_spk=worker.attack.native_spk(native_pk), payout=199_999_999, fee=1,
                    action=bytes([70 + 3 * arm_number + owner]) * 32)
                rows.append({'projection_hex': raw.hex(), 'proof_hex128': '11' * 128,
                             'statement_hex152': self.statement(raw).hex(), 'exit_id': self.digest(raw)})
            # Same source-computable public position in both arms. No private
            # assignment is required to transfer A's lookup to arm B.
            self.packet_arms[arm] = [rows[i] for i in (2, 0, 1)]
        self.contact_arms, self.route_arms = {}, {}
        for arm in worker.ARMS:
            own = self.effects[self.raws[(arm, 1)]]
            self.contact_arms[arm] = {'contacts': copy.deepcopy(self.contacts),
                'own_payouts': [{'owner': 1, 'spk_hex36': own.payout_spk.hex(), 'nf_hex32': own.nf.hex()}],
                'known_receipts': [{'owner': 0, 'rho_hex32': '72' * 32, 'cm_hex32': '63' * 32,
                                    'value': 200_000_000, 'known_consumed': True}], 'unmodeled': []}
            self.route_arms[arm] = [{'owner': owner, 'exit_id': self.digest(self.raws[(arm, owner)]),
                'provenance': 'PUBLIC_MODEL_ACTUAL_RELEASE',
                'actual_release_route_ref': 'public-fixture/' + arm + '/owner-' + str(owner)} for owner in range(3)]
        self.exit_packet = {'schema': 'kpb-method02-unlabelled-exits/v1', 'binding': self.bound, 'arms': self.packet_arms}
        self.contact_packet = {'schema': 'kpb-method02-private-contact-view/v1', 'binding': self.bound,
                               'arms': self.contact_arms}
        self.dispatcher_packet = {'schema': 'kpb-method02-actual-release-routes/v1', 'binding': self.bound,
                                  'arms': self.route_arms}
        self.data, self.events, self.scope = {}, [], 'CONTACT'
        self.public_facts = {arm: {'economic': [], 'timing': [], 'public_identifier_edges': [],
            'unmodeled': ['PUBLIC_MODEL_OPAQUE_PROOF_NOT_CRYPTOGRAPHICALLY_MODELED']} for arm in worker.ARMS}
        self.reset_packets()

    @staticmethod
    def digest(raw):
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def statement(raw):
        value = hashlib.sha256(raw).digest()
        return value * 4 + value[:24]

    def reset_packets(self):
        for path, value, mode in [('/public/EXITS.json', self.exit_packet, 0o400),
                                  ('/contact/CONTACT.json', self.contact_packet, 0o600),
                                  ('/public/DISPATCHER.json', self.dispatcher_packet, 0o400)]:
            self.data[path] = (worker.encoded(value), mode)

    def key(self, path):
        path = str(path)
        if path.startswith(('/state/', '/out/', '/private-output/')):
            return self.scope + ':' + path
        return path

    def read(self, path, expected=None, private_mode=None):
        path = str(path); self.events.append(('read', path))
        key = self.key(path)
        if key not in self.data:
            raise FileNotFoundError('PUBLIC_MODEL_MISSING_LEAF')
        raw, mode = self.data[key]
        if expected is not None:
            worker.need(self.digest(raw) == expected, 'PUBLIC_MODEL_SELECTED_HASH')
        if private_mode is not None:
            worker.need(mode == private_mode, 'PUBLIC_MODEL_PRIVATE_MODE')
        return raw

    def write(self, path, value, mode=0o400):
        path = str(path); self.events.append(('write', path))
        key = self.key(path)
        if key in self.data:
            raise FileExistsError('PUBLIC_MODEL_PERSISTENT_SLOT_ALREADY_USED')
        raw = worker.encoded(value); self.data[key] = (raw, mode)
        return raw

    def config(self, operation):
        return {'schema': 'kpb-method02-payout-role-config/v1', 'operation': operation,
            'binding': self.bound, 'source_members': [], 'exits_sha256': self.digest(self.data['/public/EXITS.json'][0]),
            'dispatcher_sha256': None if operation == 'contact-observe' else self.digest(self.data['/public/DISPATCHER.json'][0]),
            'public_facts': copy.deepcopy(self.public_facts),
            'seals_sha256': ({view: self.digest(self.data['/seals/' + view + '.json'][0]) for view in worker.VIEWS}
                             if operation == 'postseal-score' else None)}

    def observe(self, view):
        self.scope = view
        operation = {'CONTACT': 'contact-observe', 'DISPATCHER': 'dispatcher-observe', 'UNION': 'union-observe'}[view]
        worker.observe(self.config(operation), view)
        self.data['/predictions/' + view + '.json'] = self.data[view + ':/private-output/PREDICTIONS.json']
        self.data['/seals/' + view + '.json'] = self.data[view + ':/out/SEAL.json']

    def prepare(self):
        for view in worker.VIEWS:
            self.observe(view)

    def score(self):
        self.scope = 'SCORE'; worker.postseal_score(self.config('postseal-score'))
        return worker.parse(self.data['SCORE:/out/RESULT.json'][0])

    def reseal(self, view, capsule):
        raw = worker.encoded(capsule)
        self.data['/predictions/' + view + '.json'] = (raw, 0o400)
        seal = worker.parse(self.data['/seals/' + view + '.json'][0])
        seal['commitment_sha256'] = worker.capsule_seal(capsule['payload'], bytes.fromhex(capsule['salt_hex32']))
        self.data['/seals/' + view + '.json'] = (worker.encoded(seal), 0o400)


class Controls(unittest.TestCase):
    def setUp(self):
        self.f = PublicModel()
        self.patches = [patch.object(worker, 'stable_read', side_effect=self.f.read),
                        patch.object(worker, 'write_new', side_effect=self.f.write),
                        patch.object(worker.attack.exit_wire, 'validate_public', side_effect=lambda raw: self.f.effects[raw]),
                        patch.object(worker.attack.exit_wire, 'statement', side_effect=self.f.statement)]
        for p in self.patches: p.start()
        self.addCleanup(lambda: [p.stop() for p in reversed(self.patches)])

    def test_all_six_contacts_retained_and_only_frozen_arm_indexes_applied(self):
        self.f.observe('CONTACT')
        capsule = worker.parse(self.f.data['/predictions/CONTACT.json'][0])
        for arm, applicable in (('A', 7), ('B', 9)):
            rows = capsule['payload']['arms'][arm]['retained_contact_records']
            self.assertEqual(len(rows), 6)
            self.assertEqual(sorted((r['owner'], r['invoice_index']) for r in rows),
                             [(owner, index) for owner in range(3) for index in (7, 9)])
            self.assertEqual(sum(r['native_lookup_applicable'] for r in rows), 3)
            self.assertTrue(all(r['native_lookup_applicable'] == (r['invoice_index'] == applicable) for r in rows))
        self.assertNotIn(('read', '/public/DISPATCHER.json'), self.f.events)
        public = worker.parse(self.f.data['/seals/CONTACT.json'][0])
        self.assertFalse(public['private_contact_or_prediction_records_exported'])
        self.assertNotIn('models', public)
        self.assertEqual(len(capsule['salt_hex32']), 64)

    def test_source_known_same_position_transfers_baseline_lookup_without_truth(self):
        self.f.prepare()
        self.f.events.clear()
        result = self.f.score()
        for view in worker.VIEWS:
            for arm in worker.ARMS:
                self.assertEqual(result['views'][view][arm]['candidate_counts'], [1, 1, 1])
                self.assertTrue(result['views'][view][arm]['true_assignment_retained'])
        self.assertFalse(result['finite_contact_candidate_increase'])
        self.assertEqual(result['status'], 'UNQUALIFIED')
        self.assertFalse(result['overall_crypto_dispatcher_or_terminal_privacy_qualified'])
        self.assertFalse(result['chain_or_native_backing_qualified'])
        diagnostic = result['arm_local_diagnostics_before_order_intersection']['CONTACT']
        self.assertEqual(diagnostic['A']['candidate_counts'], [1, 1, 1])
        self.assertEqual(diagnostic['B']['candidate_counts'], [2, 1, 2])
        self.assertEqual(diagnostic['A']['direct_known_invoice_native_key_matches'], 3)
        self.assertEqual(diagnostic['B']['direct_known_invoice_native_key_matches'], 0)
        reads = [p for action, p in self.f.events if action == 'read']
        first_truth = reads.index('/public/DISPATCHER.json')
        self.assertTrue(all(reads.index('/seals/' + v + '.json') < first_truth for v in worker.VIEWS))
        self.assertTrue(all(reads.index('/predictions/' + v + '.json') < first_truth for v in worker.VIEWS))
        reserved = self.f.events.index(('write', '/state/SCORING-CLOSED'))
        self.assertTrue(all(self.f.events.index(('read', '/seals/' + v + '.json')) < reserved for v in worker.VIEWS))
        self.assertTrue(all(reserved < self.f.events.index(('read', '/predictions/' + v + '.json')) for v in worker.VIEWS))

    def test_observation_and_scoring_are_one_shot_before_private_reads(self):
        self.f.prepare(); self.f.score(); self.f.events.clear()
        with self.assertRaises(FileExistsError): self.f.score()
        self.assertFalse(any(p.startswith('/predictions/') or p == '/public/DISPATCHER.json'
                             for action, p in self.f.events if action == 'read'))
        self.f.events.clear()
        with self.assertRaises(FileExistsError): self.f.observe('CONTACT')
        self.assertNotIn(('read', '/contact/CONTACT.json'), self.f.events)
        self.f.bound['attempt_id'] = 'new-label-same-persistent-slot'
        self.f.bound['selection_sha256'] = 'cd' * 32
        self.f.reset_packets(); self.f.events.clear()
        with self.assertRaises(FileExistsError): self.f.observe('CONTACT')
        self.assertNotIn(('read', '/contact/CONTACT.json'), self.f.events)

    def test_foreign_exit_identifier_cannot_enter_a_pretruth_seal(self):
        actual = worker.attack.candidates
        def foreign(*args):
            predicted = actual(*args)
            predicted['models'][0] = ['ff' * 32, *predicted['models'][0][1:]]
            return predicted
        with patch.object(worker.attack, 'candidates', side_effect=foreign):
            with self.assertRaises(ValueError): self.f.observe('CONTACT')
        self.assertNotIn('CONTACT:/out/SEAL.json', self.f.data)

    def test_future_nonfactorizing_matcher_cannot_relax_joint_projection(self):
        raw, universes = worker.exits(self.f.config('contact-observe'))
        facts = {arm: {'contacts': [], 'own_payouts': [], 'known_receipts': [], 'routes': [],
                       'economic': [], 'timing': [], 'public_identifier_edges': [], 'unmodeled': []}
                 for arm in worker.ARMS}
        # Three cyclic bijections have all nine marginal edges. A future richer
        # matcher must not expand this joint set into all six permutations.
        initial = {arm: {'models': [tuple(universes[arm][(owner + shift) % 3] for owner in range(3))
                                   for shift in range(3)]} for arm in worker.ARMS}
        with self.assertRaises(ValueError):
            worker.intersect_public_cross_arm_order(raw, universes, facts, initial)

    def test_missing_pretruth_seal_does_not_consume_slot_or_read_capsules(self):
        self.f.prepare(); config = self.f.config('postseal-score')
        del self.f.data['/seals/UNION.json']; self.f.events.clear()
        self.f.scope = 'SCORE'
        with self.assertRaises(FileNotFoundError): worker.postseal_score(config)
        self.assertNotIn('SCORE:/state/SCORING-CLOSED', self.f.data)
        self.assertFalse(any(p.startswith('/predictions/') for action, p in self.f.events if action == 'read'))

    def test_foreign_universe_or_policy_refuses_before_labelled_truth(self):
        self.f.prepare()
        original = copy.deepcopy(self.f.data)
        for change in ('selected-universe', 'model-universe', 'policy', 'seal-exits'):
            with self.subTest(change=change):
                self.f.data = copy.deepcopy(original); self.f.events.clear()
                capsule = worker.parse(self.f.data['/predictions/CONTACT.json'][0])
                if change == 'selected-universe': capsule['payload']['selected_exit_ids']['B'][0] = 'ff' * 32
                if change == 'model-universe': capsule['payload']['arms']['B']['models'][0][0] = 'ff' * 32
                if change == 'policy': capsule['payload']['arms']['B']['policy'] = 'invoice-native'
                self.f.reseal('CONTACT', capsule)
                if change == 'seal-exits':
                    seal = worker.parse(self.f.data['/seals/CONTACT.json'][0]); seal['exits_sha256'] = 'ff' * 32
                    self.f.data['/seals/CONTACT.json'] = (worker.encoded(seal), 0o400)
                with self.assertRaises(ValueError): self.f.score()
                self.assertNotIn(('read', '/public/DISPATCHER.json'), self.f.events)

    def test_cross_arm_scope_duplicate_nf_and_missing_contact_refuse(self):
        config = self.f.config('contact-observe')
        for change in ('chain', 'pool', 'duplicate-nf', 'missing-contact'):
            with self.subTest(change=change):
                bodies = copy.deepcopy(self.f.effects); contacts = copy.deepcopy(self.f.contact_packet)
                if change in ('chain', 'pool'):
                    setattr(self.f.effects[self.f.raws[('B', 0)]].context, change, b'X' * 32)
                if change == 'duplicate-nf': self.f.effects[self.f.raws[('B', 0)]].nf = self.f.effects[self.f.raws[('A', 0)]].nf
                if change == 'missing-contact': self.f.contact_packet['arms']['B']['contacts'].pop()
                self.f.reset_packets(); self.f.events.clear(); self.f.scope = change
                with self.assertRaises(ValueError): worker.observe(config, 'CONTACT')
                self.assertNotIn(self.f.scope + ':/out/SEAL.json', self.f.data)
                self.f.effects = bodies; self.f.contact_packet = contacts

    def test_private_unmodeled_strings_export_counts_and_never_qualified_gain(self):
        secret = 'PUBLIC-FIXTURE-STRING-STANDS-FOR-PRIVATE-UNMODELED-DETAIL'
        self.f.contact_packet['arms']['B']['unmodeled'] = [secret]
        self.f.reset_packets(); self.f.prepare(); result = self.f.score()
        self.assertNotIn(secret, json.dumps(result))
        self.assertFalse(result['contact_matching_model_complete'])
        self.assertEqual(result['status'], 'UNQUALIFIED')
        self.assertGreater(result['views']['CONTACT']['B']['unmodeled_count'], 0)


class ActualPublicNamespace(unittest.TestCase):
    def test_contact_netoff_source_closure_and_forbidden_dispatcher_mount(self):
        read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
        sources = [(Path(worker.__file__).absolute(), OBSERVER_SHA),
                   (Path(worker.attack.__file__).absolute(), MATCHER_SHA),
                   (Path(worker.attack.exit_wire.__file__).absolute(), EXIT_SHA),
                   (Path(worker.attack.exit_wire.old.__file__).absolute(), None)]
        with tempfile.TemporaryDirectory(prefix='method02-public-namespace-') as directory:
            root = Path(directory); members, mounts = [], []
            for i, (path, pin) in enumerate(sources):
                raw = read(path, pin); target = root / ('source-' + str(i)); target.write_bytes(raw); target.chmod(0o400)
                members.append({'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()})
                mounts += ['--ro-bind', str(target), str(path)]
            fixture = PublicModel(); config = fixture.config('contact-observe'); config['source_members'] = members
            marker = {'schema': 'kpb-method02-observer-namespace/v1', 'operation': 'contact-observe',
                      'network': 'disabled', 'Original_slots': 0}
            for name, value in (('CONFIG.json', config), ('NAMESPACE.json', marker)):
                (root / name).write_bytes(worker.encoded(value)); (root / name).chmod(0o400)
            probe = ('import sys;sys.path.insert(0,' + repr(str(HERE)) + ');'
                     'import payout_linkage_observe as w;'
                     'c=w.require_namespace("contact-observe");'
                     'assert c["dispatcher_sha256"] is None;print("PUBLIC_CONTACT_NAMESPACE_PASS")')
            command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
                '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
                '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
                *mounts, '--ro-bind', str(root / 'CONFIG.json'), '/CONFIG.json',
                '--ro-bind', str(root / 'NAMESPACE.json'), '/NAMESPACE.json']
            tail = ['/usr/bin/python3', '-B', '-S', '-c', probe]
            result = subprocess.run(command + tail, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env={'PATH': '/usr/bin:/bin'}, close_fds=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stdout.strip(), b'PUBLIC_CONTACT_NAMESPACE_PASS')
            (root / 'PUBLIC-DUMMY-DISPATCHER.json').write_bytes(b'{}\n')
            refused = subprocess.run(command + ['--ro-bind', str(root / 'PUBLIC-DUMMY-DISPATCHER.json'),
                '/public/DISPATCHER.json'] + tail, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={'PATH': '/usr/bin:/bin'}, close_fds=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn(b'method02-contact-without-labelled-release', refused.stderr)


if __name__ == '__main__':
    unittest.main()
