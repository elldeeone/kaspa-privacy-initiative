"""PUBLIC constructed fixture and owner-sequencing controls; no PK/proof/NativeVM."""
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

import public_child
import public_fixture
from payment import fresh_change
from reuse import ROOT, load


PROFILE = ROOT / 'poc/shared-settlement-proof/child-profile.json'
PROFILE_SHA = '492a0981ad04891ea68243f2c8221976f436501acf940e42211bb8773744fbdd'
MANIFEST = ROOT / 'poc/private-exit-stress/prover/pins/compact2/public-parameters.json'


class PublicProducerControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.base = Path(cls.directory.name)
        cls.profile = public_fixture.load_profile(PROFILE, PROFILE_SHA)
        cls.c = load()
        cls.rows = []
        for actor in (0, 1):
            target = cls.base / ('actor-' + str(actor) + '.json')
            result = subprocess.run([sys.executable, '-B', str(Path(public_fixture.__file__)),
                '--profile', str(PROFILE), '--profile-sha256', PROFILE_SHA,
                'public-note', '--actor', str(actor), '--output', str(target)],
                capture_output=True, text=True)
            assert result.returncode == 0
            cls.rows.append(target.read_bytes())
        cls.prestate = public_fixture.assemble(cls.profile, cls.rows)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def context(self):
        target = json.loads(self.rows[1])
        return {'schema': public_child.CONTEXT_SCHEMA, 'classification': public_fixture.CLASSIFICATION,
            'child_profile_sha256': self.profile.sha256, 'actor': 0, 'head': copy.deepcopy(self.prestate),
            'recipient_public_record': target,
            'request': {'schema': 'kpx4-single-invoice-payment-request/v1',
                'domain_hex32': self.profile.domain.hex(),
                'recipient_invoice_hex208': target['payment_invoice_hex208'],
                'net_principal_sompi': 1_000_000_000, 'recipient_exit_credit_sompi': 35_000_000},
            'allocated_fee_sompi': 12_345, 'fee_allocation_sompi': [12_345, 23_456],
            'outer_fee_sompi': 35_801, 'expected_exit_credit_sompi': 35_000_000,
            'quote_reference_sha256': 'ab' * 32, 'quote_reference_requires_final_confirmation': True}

    def test_two_actor_setup_assembled_without_deriving_either_seed(self):
        with mock.patch.object(public_fixture, 'actor_wallet', side_effect=AssertionError('seed touched')):
            row = public_fixture.assemble(self.profile, self.rows)
            _, snap = public_child.state_input(json.dumps(row), self.profile, 0)
        self.assertEqual((snap.cm_cursor, len(snap.nullifiers), row['reserve_sompi']), (2, 1, 4_000_000_000))
        self.assertEqual([entry.position for entry in snap.deliveries], [0, 1])
        self.assertFalse(row['accepted_chain_backing_currentness_or_GN_claimed'])
        self.assertEqual(len(bytes.fromhex(row['state_hex112'])), 112)

    def test_profile_pin_unselected_or_duplicate_actor_record_refused(self):
        with self.assertRaisesRegex(ValueError, 'installed-child-profile-pin'):
            public_fixture.load_profile(PROFILE, '00' * 32)
        bad = copy.deepcopy(self.profile.data)
        bad['selected'] = False
        raw = json.dumps(bad).encode()
        target = self.base / 'unselected.json'
        target.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'selected-public-child-profile'):
            public_fixture.load_profile(target, hashlib.sha256(raw).hexdigest())
        with self.assertRaisesRegex(ValueError, 'two-distinct-ordered-public-notes'):
            public_fixture.assemble(self.profile, [self.rows[0], self.rows[0]])

    def test_changed_note_state_position_or_private_hint_refused(self):
        for field, value in [('cm_hex32', '00' * 32), ('actor_position', True), ('seed_hex32', '00' * 32)]:
            row = json.loads(self.rows[0])
            row[field] = value
            with self.assertRaises(ValueError):
                public_fixture.read_note(json.dumps(row), self.profile)
        row = copy.deepcopy(self.prestate)
        row['snapshot']['deliveries'][1]['position'] = 0
        with self.assertRaises(ValueError):
            public_child.state_input(json.dumps(row), self.profile, 0)
        row = copy.deepcopy(self.prestate)
        row['state_hex112'] = '00' * 112
        with self.assertRaisesRegex(ValueError, 'snapshot-selected-state'):
            public_child.state_input(json.dumps(row), self.profile, 0)

    def test_missing_or_mismatched_Fi_credit_and_known_policy_refused_before_seed(self):
        valid = self.context()
        with mock.patch.object(public_fixture, 'actor_wallet', side_effect=AssertionError('seed touched')):
            public_child.validate_context(json.dumps(valid), self.profile)
            for mutate in (
                lambda r: r.pop('expected_exit_credit_sompi'),
                lambda r: r.update(allocated_fee_sompi=0),
                lambda r: r.update(outer_fee_sompi=35_800),
                lambda r: r.update(expected_exit_credit_sompi=0),
                lambda r: r['request'].update(net_principal_sompi=999_999_999),
                lambda r: r.update(actor=True),
                lambda r: r.update(hidden_owner_map={}),
            ):
                row = copy.deepcopy(valid)
                mutate(row)
                with self.assertRaises(ValueError):
                    public_child.validate_context(json.dumps(row), self.profile)

    def test_wrong_READY_rejects_before_actor_seed_or_witness_send(self):
        context = self.base / 'owner-context.json'
        raw = json.dumps(self.context()).encode()
        context.write_bytes(raw)
        args = types.SimpleNamespace(context=context, context_sha256=hashlib.sha256(raw).hexdigest(),
            manifest=MANIFEST, prover=Path('/PUBLIC_FAKE_PROVER'), prover_sha256='00' * 32,
            pk=self.base / 'PK_MUST_NOT_BE_OPENED', output=self.base / 'wrong-READY-owner',
            execute=True, workers=2, must_be_absent=[])
        class FakeProcess:
            stdout = io.StringIO('{"event":"parameters-ready"}\n')
            returncode = None
            def poll(self): return self.returncode
            def terminate(self): self.returncode = -15
            def communicate(self): return '', ''
        fake = FakeProcess()
        with mock.patch.object(self.c.native_runtime, 'Executable',
                               return_value=types.SimpleNamespace(path=Path('/PUBLIC_FAKE_PROVER'))), \
             mock.patch.object(public_child.subprocess, 'Popen', return_value=fake), \
             mock.patch.object(public_child, 'actor_wallet', side_effect=AssertionError('seed touched')), \
             mock.patch.object(public_child, 'normalize_public', side_effect=AssertionError('oracle touched')):
            with self.assertRaisesRegex(ValueError, 'exact-whole-PK-READY-before-actor-seed'):
                public_child.prove_child(self.profile, args)
        self.assertEqual(fake.returncode, -15)
        self.assertFalse((args.output / 'COMPONENT.json').exists())

    def test_exact_READY_and_reserved_public_receive_index(self):
        manifest = public_child.selected_manifest(MANIFEST.read_bytes(), self.profile)
        ready = public_child.ready_expected(self.profile, manifest)
        self.assertEqual(set(ready), {'event', 'role', 'output_arity', 'parameter_manifest_sha256',
                                     'domain_hex32', 'vk_sha256', 'compiled_build_identity_sha256'})
        self.assertEqual(ready['domain_hex32'], self.profile.domain.hex())
        # This is the known-unsafe public SETUP role, not an owner/proof run.
        wallet = public_fixture.actor_wallet(self.profile, 0)
        snapshot = public_fixture.parse_snapshot(self.prestate['snapshot'], self.profile.domain,
                              bytes.fromhex(self.prestate['state_hex112']))
        recovered = self.c.receiver.recover(wallet, snapshot, snapshot.state(self.profile.domain))
        own = [x for x in recovered.owned if x.owner_action_available]
        self.assertEqual(len(own), 1)
        target = self.c.actions.invoice(bytes.fromhex(json.loads(self.rows[1])['payment_invoice_hex208']),
                                        self.profile.domain)
        samples = iter([(1).to_bytes(8, 'little'), (2).to_bytes(8, 'little')])
        chosen = fresh_change(wallet, recovered.owned, own[0], target, lambda n: next(samples), (0, 1))
        self.assertEqual(chosen.index, 2)
        with self.assertRaisesRegex(ValueError, 'one-actor-seed-per-process'):
            public_fixture.actor_wallet(self.profile, 1)


if __name__ == '__main__':
    unittest.main()

