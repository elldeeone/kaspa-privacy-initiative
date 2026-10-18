"""R05/R06 through restored model transition and public replay boundaries."""
import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import random
import unittest

from model import MAX, Note, Wallet, refund_request_body
from recovery import reconstruct_public, restore_wallet
from recovery_fixture import build_fixture
from recovery_format import (RecoveryError, pending_note_from_backup, read_json,
                             wallet_from_backup, write_private_json)


def economic_state(export):
    state = reconstruct_public(export['archive'], export['checkpoint'])
    state.pop('checkpoint_hash')
    return state


class RestoredTransitionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = build_fixture()

    def test_r05_two_valid_spends_from_old_anchor_only_one_survives_restore(self):
        from recovery_session import RecoverySession
        f = self.fixture
        alice, bob = (wallet_from_backup(f['backups'][name]) for name in ('Alice', 'Bob'))
        restored = restore_wallet(f['archive'], f['checkpoint'], f['backups']['Alice'])
        note = Note(**restored['spendable_notes'][0]['note'])
        snapshot = reconstruct_public(f['archive'], f['checkpoint'])['commitments']
        first = RecoverySession(f['archive'], f['checkpoint'])
        proof = first.proof_oracle.spend(alice, [note], [(bob.note(250_000_000, 'first-pay'), bob.address),
                 (alice.note(350_000_000, 'first-change'), alice.address)], snapshot)
        self.assertTrue(first.process(proof)['accepted'])
        saved = first.export()
        second = RecoverySession(saved['archive'], saved['checkpoint'])
        competing = second.proof_oracle.spend(alice, [note], [(bob.note(200_000_000, 'second-pay'), bob.address),
                     (alice.note(400_000_000, 'second-change'), alice.address)], snapshot)
        # This predicate is individually valid under the historical anchor.
        self.assertEqual(second.proof_oracle.verify(competing), competing.public)
        before = economic_state(second.export())
        rejected = second.process(competing)
        self.assertFalse(rejected['accepted'])
        self.assertIn('nullifier', rejected['reason'])
        self.assertEqual(before, economic_state(second.export()))
        after = second.export()
        self.assertEqual(restore_wallet(after['archive'], after['checkpoint'], f['backups']['Alice'])['spendable_sompi'], 350_000_000)

    def test_r05_two_batches_in_separate_processes_and_valid_continuation(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'base'; base.mkdir()
            for name in ('archive', 'checkpoint'):
                write_private_json(base / (name + '.json'), self.fixture[name])
            for name, backup in self.fixture['backups'].items():
                write_private_json(base / (name.lower() + '-backup.json'), backup)
            prior = base
            for case in ('r05-first', 'r05-second'):
                output = Path(directory) / case
                run = subprocess.run([sys.executable, str(Path(__file__).with_name('recovery_trials.py')),
                                      case, str(prior), str(output)], cwd=directory,
                                     capture_output=True, text=True)
                self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
                self.assertEqual(run.stderr, '')
                for secret in ('spending_seed', self.fixture['backups']['Alice']['owner'], 'synthetic_balances'):
                    self.assertNotIn(secret, run.stdout)
                prior = output
            result = read_json(prior / 'result.json')
            self.assertEqual(result['outcomes'], [False, True])
            self.assertTrue(result['individually_valid_duplicate'])
            self.assertEqual(result['synthetic_balances_sompi'],
                             {'Alice': 350_000_000, 'Bob': 1_049_999_000, 'Carol': 100_000_000})
            self.assertFalse(result['chain_or_zk_verified'])

    def test_r05_same_batch_two_individually_valid_competing_spends(self):
        from recovery_session import RecoverySession
        f = self.fixture
        session = RecoverySession(f['archive'], f['checkpoint'])
        alice = wallet_from_backup(f['backups']['Alice'])
        state = economic_state(f)
        note = Note(**restore_wallet(f['archive'], f['checkpoint'], f['backups']['Alice'])['spendable_notes'][0]['note'])
        candidates = [session.proof_oracle.spend(alice, [note],
                      [(alice.note(600_000_000, label), alice.address)], state['commitments'])
                      for label in ('candidate-one', 'candidate-two')]
        for proof in candidates:
            session.proof_oracle.verify(proof)
        self.assertTrue(session.process(candidates[0])['accepted'])
        before = economic_state(session.export())
        self.assertFalse(session.process(candidates[1])['accepted'])
        self.assertEqual(before, economic_state(session.export()))

    def test_r05_existing_spent_note_and_wrong_anchor_or_domain_fail(self):
        from recovery_session import RecoverySession
        from recovery_trials import note_with_value
        f = self.fixture
        alice = wallet_from_backup(f['backups']['Alice'])
        state = economic_state(f)
        for value in (1_000_000_000, 600_000_000):
            session = RecoverySession(f['archive'], f['checkpoint'])
            note = note_with_value(alice, state, value)
            proof = session.proof_oracle.spend(alice, [note], [(alice.note(value, 'retry'), alice.address)],
                                                state['commitments'])
            if value == 1_000_000_000:
                before = economic_state(session.export())
                self.assertIn('nullifier', session.process(proof)['reason'])
                self.assertEqual(before, economic_state(session.export()))
            else:
                for field, changed in [('anchor', 'unknown'), ('network', 'wrong'), ('pool', 'wrong'),
                                       ('version', 2), ('version', True)]:
                    # Mutated public intent must fail its ideal-proof binding;
                    # this is not a valid proof for an alternate domain/root.
                    invalid = copy.deepcopy(proof); invalid.public[field] = changed
                    before = economic_state(session.export())
                    self.assertFalse(session.process(invalid)['accepted'])
                    self.assertEqual(before, economic_state(session.export()))

    def test_r06_pending_note_metadata_restores_and_binds_deposit(self):
        from recovery_format import pending_note_from_backup, RecoveryError
        f = self.fixture
        state = economic_state(f)
        event = next(event for event in state['deposits'].values() if event['state'] == 'pending')
        backup = f['backups']['Carol']
        self.assertEqual(backup['schema'], 'kpi-model-backup/v2')
        note = pending_note_from_backup(backup, event)
        self.assertEqual((note.value, note.commitment), (300_000_000, event['commitment']))
        for field, value in [('id', 'ab' * 32), ('amount', 300_000_001), ('commitment', 'cd' * 32)]:
            changed = {**event, field: value}
            with self.assertRaises(RecoveryError):
                pending_note_from_backup(backup, changed)

    def test_r06_refund_creates_backed_unpaid_claim_and_blocks_credit_after_restore(self):
        from recovery_session import RecoverySession
        from model import refund_request_body
        from recovery_format import pending_note_from_backup
        f = self.fixture
        session = RecoverySession(f['archive'], f['checkpoint'])
        carol = wallet_from_backup(f['backups']['Carol'])
        event = next(e for e in economic_state(f)['deposits'].values() if e['state'] == 'pending')
        note = pending_note_from_backup(f['backups']['Carol'], event)
        recipient = 'model-native:' + carol.owner
        session.fund_rent(50_000_000)
        signature = carol.sign(refund_request_body(event['id'], event['amount'], recipient))
        self.assertTrue(session.request_refund(event['id'], recipient, signature)['accepted'])
        exported = session.export()
        state = economic_state(exported)
        self.assertEqual(state['reserve_sompi'], 2_000_000_000)
        self.assertEqual(state['private_liability_sompi'], 1_499_999_000)
        self.assertEqual(sum(c['amount'] for c in state['claims'].values()), 500_000_000)
        self.assertEqual(state['rent_reserved_sompi'], 100_000_000)
        self.assertEqual(state['deposits'][event['id']]['state'], 'refund_pending')
        report = restore_wallet(exported['archive'], exported['checkpoint'], f['backups']['Carol'])
        self.assertEqual((report['pending_deposit_sompi'], report['unpaid_refund_sompi']), (0, 300_000_000))
        resumed = RecoverySession(exported['archive'], exported['checkpoint'])
        before = economic_state(resumed.export())
        credit = resumed.proof_oracle.credit(event, note, carol.address)
        self.assertFalse(resumed.process(credit)['accepted'])
        self.assertFalse(resumed.request_refund(event['id'], recipient, signature)['accepted'])
        self.assertEqual(before, economic_state(resumed.export()))

    def test_r06_credit_first_blocks_refund_and_second_credit_after_restore(self):
        from recovery_session import RecoverySession
        f = self.fixture
        session = RecoverySession(f['archive'], f['checkpoint'])
        carol = wallet_from_backup(f['backups']['Carol'])
        event = next(e for e in economic_state(f)['deposits'].values() if e['state'] == 'pending')
        note = pending_note_from_backup(f['backups']['Carol'], event)
        self.assertTrue(session.process(session.proof_oracle.credit(event, note, carol.address))['accepted'])
        export = session.export()
        resumed = RecoverySession(export['archive'], export['checkpoint'])
        before = economic_state(export)
        recipient = 'model-native:' + carol.owner
        signature = carol.sign(refund_request_body(event['id'], event['amount'], recipient))
        self.assertFalse(resumed.request_refund(event['id'], recipient, signature)['accepted'])
        self.assertFalse(resumed.process(resumed.proof_oracle.credit(event, note, carol.address))['accepted'])
        self.assertEqual(before, economic_state(resumed.export()))
        report = restore_wallet(export['archive'], export['checkpoint'], f['backups']['Carol'])
        self.assertEqual((report['spendable_sompi'], report['pending_deposit_sompi'], report['unpaid_refund_sompi']),
                         (300_000_000, 0, 0))

    def test_r06_both_race_orders_across_fresh_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'base'; base.mkdir()
            for name in ('archive', 'checkpoint'):
                write_private_json(base / (name + '.json'), self.fixture[name])
            for name, backup in self.fixture['backups'].items():
                write_private_json(base / (name.lower() + '-backup.json'), backup)
            for winner in ('credit', 'refund'):
                prior = base
                for stage in ('first', 'second'):
                    case = 'r06-' + winner + '-' + stage
                    output = Path(directory) / case
                    run = subprocess.run([sys.executable, str(Path(__file__).with_name('recovery_trials.py')),
                                          case, str(prior), str(output)], cwd=directory,
                                         capture_output=True, text=True)
                    self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
                    self.assertEqual(run.stderr, '')
                    self.assertNotIn('spending_seed', run.stdout)
                    prior = output
                result = read_json(prior / 'result.json')
                self.assertEqual(result['outcomes'], [False, False, True])
                self.assertEqual(result['reserve_sompi'], 2_000_000_000)
                self.assertEqual(result['synthetic_carol_spendable_sompi'], 300_000_000 if winner == 'credit' else 0)
                self.assertEqual(result['synthetic_carol_unpaid_refund_sompi'], 0 if winner == 'credit' else 300_000_000)
                self.assertEqual(result['native_payouts'], 0)

    def test_r06_bad_authority_and_mutated_signed_terms_are_atomic(self):
        from recovery_session import RecoverySession
        f = self.fixture
        carol = wallet_from_backup(f['backups']['Carol'])
        mallory = Wallet('refund-attacker')
        event = next(e for e in economic_state(f)['deposits'].values() if e['state'] == 'pending')
        recipient = 'model-native:' + carol.owner
        body = refund_request_body(event['id'], event['amount'], recipient)
        cases = [(event['id'], recipient, mallory.sign(body))]
        for position, altered in [(1, 'wrong-network'), (2, 'wrong-pool'), (3, 2), (3, True),
                                  (4, 'ab' * 32), (5, 300_000_001), (6, 'model-native:attacker')]:
            wrong = copy.deepcopy(body); wrong[position] = altered
            cases.append((event['id'], recipient, carol.sign(wrong)))
        cases.extend([('ab' * 32, recipient, carol.sign(body)),
                      (event['id'], 'changed-recipient', carol.sign(body)),
                      (event['id'], recipient, '00'), (event['id'], recipient, None)])
        session = RecoverySession(f['archive'], f['checkpoint']); session.fund_rent(50_000_000)
        before = economic_state(session.export())
        for identity, target, signature in cases:
            with self.subTest(identity=identity, target=target):
                self.assertFalse(session.request_refund(identity, target, signature)['accepted'])
                self.assertEqual(before, economic_state(session.export()))
        # A rejected request never consumes the deposit or blocks its valid owner.
        self.assertTrue(session.request_refund(event['id'], recipient, carol.sign(body))['accepted'])

    def test_r06_unfunded_rent_rejects_without_stranding_credit(self):
        from recovery_session import RecoverySession
        f = self.fixture; session = RecoverySession(f['archive'], f['checkpoint'])
        carol = wallet_from_backup(f['backups']['Carol'])
        event = next(e for e in economic_state(f)['deposits'].values() if e['state'] == 'pending')
        recipient = 'model-native:' + carol.owner
        before = economic_state(session.export())
        self.assertFalse(session.request_refund(event['id'], recipient,
                         carol.sign(refund_request_body(event['id'], event['amount'], recipient)))['accepted'])
        self.assertEqual(before, economic_state(session.export()))
        note = pending_note_from_backup(f['backups']['Carol'], event)
        self.assertTrue(session.process(session.proof_oracle.credit(event, note, carol.address))['accepted'])

    def test_r06_key_only_backup_can_request_refund_but_cannot_reconstruct_credit_note(self):
        from recovery_session import RecoverySession
        f = self.fixture
        old = copy.deepcopy(f['backups']['Carol'])
        old['schema'] = 'kpi-model-backup/v1'; old.pop('pending_notes')
        carol = wallet_from_backup(old)
        event = next(e for e in economic_state(f)['deposits'].values() if e['state'] == 'pending')
        with self.assertRaises(RecoveryError) as missing:
            pending_note_from_backup(old, event)
        self.assertEqual(missing.exception.code, 'pending_note_metadata_missing')
        session = RecoverySession(f['archive'], f['checkpoint']); session.fund_rent(50_000_000)
        recipient = 'model-native:' + carol.owner
        self.assertTrue(session.request_refund(event['id'], recipient,
                         carol.sign(refund_request_body(event['id'], event['amount'], recipient)))['accepted'])

    def test_r06_replay_verifies_signature_and_requires_matching_v2_profiles(self):
        from recovery import model_checkpoint
        from recovery_session import RecoverySession
        f = self.fixture; session = RecoverySession(f['archive'], f['checkpoint'])
        carol = wallet_from_backup(f['backups']['Carol'])
        event = next(e for e in economic_state(f)['deposits'].values() if e['state'] == 'pending')
        recipient = 'model-native:' + carol.owner
        session.fund_rent(50_000_000)
        session.request_refund(event['id'], recipient, carol.sign(refund_request_body(event['id'], event['amount'], recipient)))
        export = session.export()
        self.assertEqual((export['archive']['schema'], export['checkpoint']['schema']),
                         ('kpi-model-records/v2', 'kpi-model-checkpoint/v2'))
        for change in ('signature', 'legacy', 'profile', 'repeat'):
            bad = copy.deepcopy(export)
            if change == 'signature':
                bad['archive']['records'][-1]['signature'] = '00' * 64
            elif change == 'legacy':
                bad['archive']['schema'] = 'kpi-model-records/v1'
            elif change == 'repeat':
                repeated = copy.deepcopy(bad['archive']['records'][-1])
                repeated['seq'] = len(bad['archive']['records']); bad['archive']['records'].append(repeated)
            bad['checkpoint'] = model_checkpoint(bad['archive'])
            if change == 'profile':
                bad['checkpoint']['schema'] = 'kpi-model-checkpoint/v1'
            before = copy.deepcopy(bad)
            with self.assertRaises(RecoveryError):
                reconstruct_public(bad['archive'], bad['checkpoint'])
            self.assertEqual(before, bad)

    def test_r06_same_batch_races_and_seeded_u64_principal_conservation(self):
        from recovery import model_checkpoint
        from recovery_session import RecoverySession
        from model import hash_id
        rng = random.Random(20261018)
        values = [1, MAX, MAX - 50_000_000, 300_000_000] + [rng.randrange(1, MAX) for _ in range(16)]
        owner = Wallet('refund-boundary-owner')
        for value in values:
            for first in ('credit', 'refund'):
                with self.subTest(value=value, first=first):
                    note = owner.note(value, 'pending-' + str(value))
                    event = {'id': hash_id(['refund-boundary', value]), 'amount': value,
                             'commitment': note.commitment, 'refund_owner': owner.owner}
                    archive = copy.deepcopy(self.fixture['archive'])
                    archive['records'] = [{'seq': 0, 'kind': 'deposit', 'event': event},
                                          {'seq': 1, 'kind': 'rent_funding', 'amount': 50_000_000}]
                    session = RecoverySession(archive, model_checkpoint(archive))
                    credit = session.proof_oracle.credit(event, note, owner.address)
                    recipient = 'model-native:' + owner.owner
                    signature = owner.sign(refund_request_body(event['id'], value, recipient))
                    actions = {'credit': lambda: session.process(credit),
                               'refund': lambda: session.request_refund(event['id'], recipient, signature)}
                    self.assertTrue(actions[first]()['accepted'])
                    before = economic_state(session.export())
                    self.assertFalse(actions['refund' if first == 'credit' else 'credit']()['accepted'])
                    self.assertEqual(before, economic_state(session.export()))
                    state = economic_state(session.export())
                    self.assertEqual(state['reserve_sompi'], value)
                    self.assertEqual(state['private_liability_sompi'] + sum(c['amount'] for c in state['claims'].values()), value)
                    self.assertEqual(state['deposits'][event['id']]['state'], 'credited' if first == 'credit' else 'refund_pending')
        for invalid in (-1, MAX + 1, True, 1.0):
            with self.assertRaises(ValueError):
                refund_request_body('ab' * 32, invalid, 'model-native:owner')

    def test_r06_rejected_credit_survives_restart_and_owner_can_choose_either_route(self):
        from recovery_session import RecoverySession
        f = self.fixture
        carol = wallet_from_backup(f['backups']['Carol'])
        event = next(e for e in economic_state(f)['deposits'].values() if e['state'] == 'pending')
        note = pending_note_from_backup(f['backups']['Carol'], event)
        rejected_stage = RecoverySession(f['archive'], f['checkpoint'])
        proof = rejected_stage.proof_oracle.credit(event, note, carol.address)
        proof.token = 'MODEL-INVALID-INNER-PROOF'
        before = economic_state(rejected_stage.export())
        self.assertFalse(rejected_stage.process(proof)['accepted'])
        saved = rejected_stage.export()
        self.assertEqual(economic_state(saved), before)
        for route in ('credit', 'refund'):
            resumed = RecoverySession(saved['archive'], saved['checkpoint'])
            if route == 'credit':
                result = resumed.process(resumed.proof_oracle.credit(event, note, carol.address))
            else:
                resumed.fund_rent(50_000_000)
                recipient = 'model-native:' + carol.owner
                result = resumed.request_refund(event['id'], recipient,
                    carol.sign(refund_request_body(event['id'], event['amount'], recipient)))
            self.assertTrue(result['accepted'])
            self.assertEqual(economic_state(resumed.export())['reserve_sompi'], 2_000_000_000)


if __name__ == '__main__':
    unittest.main()
