"""R07 through the existing recovery session, replay and process boundaries."""
import copy
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

from recovery import model_checkpoint, reconstruct_public, restore_wallet
from recovery_fixture import build_fixture
from model import MAX, Note, Wallet, hash_id, refund_request_body
from recovery_format import RecoveryError, pending_note_from_backup, read_json, wallet_from_backup
from recovery_session import RecoverySession


def state_of(session):
    saved = session.export()
    state = reconstruct_public(saved['archive'], saved['checkpoint'])
    state.pop('checkpoint_hash')
    return state


def single_exit(fixture, value, fee=0, extra_rent=0):
    """A separately worked fee-free/fee-bearing note, with no producer Pool."""
    wallet = Wallet('r07-terminal-user')
    note = wallet.note(value, 'terminal-' + str(value))
    event = {'id': hash_id(['r07-terminal-deposit', value]), 'amount': value,
             'commitment': note.commitment, 'refund_owner': wallet.owner}
    archive = copy.deepcopy(fixture['archive'])
    archive['records'] = [{'seq': 0, 'kind': 'deposit', 'event': event}]
    session = RecoverySession(archive, model_checkpoint(archive))
    if not session.process(session.proof_oracle.credit(event, note, wallet.address))['accepted']:
        raise RuntimeError('terminal fixture credit failed')
    session.fund_rent(50_000_000 + extra_rent)
    proof = session.proof_oracle.spend(wallet, [note], [], state_of(session)['commitments'],
            withdrawal={'recipient': 'model-native:' + wallet.owner, 'amount': value - fee}, fee=fee)
    result = session.process(proof)
    if not result['accepted']:
        raise RuntimeError('terminal fixture exit failed')
    return session, result['id'], 'model-native:' + wallet.owner


class PaidRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = build_fixture()

    def test_exit_payment_survives_restore_and_cannot_pay_twice(self):
        f = self.fixture
        session = RecoverySession(f['archive'], f['checkpoint'])
        identity, claim = next(iter(state_of(session)['claims'].items()))
        self.assertEqual(restore_wallet(f['archive'], f['checkpoint'], f['backups']['Bob'])['unpaid_exit_sompi'], 200_000_000)
        paid = session.payout(identity, claim['recipient'], 200_000_000, 50_000_000, 1_800_000_000)
        self.assertTrue(paid['accepted'])
        self.assertEqual(paid['output_sompi'], 250_000_000)
        saved = session.export()
        resumed = RecoverySession(saved['archive'], saved['checkpoint'])
        before = state_of(resumed)
        self.assertEqual((before['reserve_sompi'], before['rent_reserved_sompi'], before['rent_paid_sompi']),
                         (1_800_000_000, 0, 50_000_000))
        self.assertTrue(before['claims'][identity]['paid'])
        report = restore_wallet(saved['archive'], saved['checkpoint'], f['backups']['Bob'])
        self.assertEqual((report['unpaid_exit_sompi'], report['spendable_sompi']), (0, 899_999_000))
        # Update the residual reserve too: rejection must depend on spentness.
        self.assertFalse(resumed.payout(identity, claim['recipient'], 200_000_000, 50_000_000, 1_600_000_000)['accepted'])
        self.assertEqual(state_of(resumed), before)

    def test_three_user_drain_in_fresh_processes_fee_last_and_user_last(self):
        script = str(Path(__file__).with_name('recovery_payout_trials.py'))
        fixture_script = str(Path(__file__).with_name('recovery_fixture.py'))
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'base'
            subprocess.run([sys.executable, '-O', fixture_script, str(base)], cwd=directory,
                           capture_output=True, text=True, check=True)
            for last in ('fee', 'user'):
                prior = base
                stages = ['prepare'] + ['pay-next'] * 5 + ['audit']
                for index, stage in enumerate(stages):
                    output = Path(directory) / (last + '-' + str(index))
                    run = subprocess.run([sys.executable, '-O', script, stage, str(prior), str(output), '--last', last],
                                         cwd=directory, capture_output=True, text=True)
                    self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
                    self.assertEqual(run.stderr, '')
                    self.assertNotIn('spending_seed', run.stdout)
                    self.assertNotIn('recipient', run.stdout)
                    self.assertEqual(output.stat().st_mode & 0o777, 0o700)
                    self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in output.iterdir()))
                    prior = output
                result = read_json(prior / 'result.json')
                self.assertEqual((result['reserve_sompi'], result['outstanding_principal_sompi']), (0, 0))
                self.assertEqual((result['paid_user_principal_sompi'], result['paid_fee_sompi'], result['rent_paid_sompi']),
                                 (1_999_999_000, 1_000, 200_000_000))
                self.assertEqual(result['paid_user_principal_by_user_sompi'],
                                 {'Alice': 600_000_000, 'Bob': 1_099_999_000, 'Carol': 300_000_000})
                self.assertEqual(result['synthetic_payment_count'], 5)
                self.assertEqual(result['last_payment_kind'], 'fee_payment' if last == 'fee' else 'payout')
                self.assertEqual(result['native_payouts'], 0)
                self.assertFalse(result['chain_or_zk_verified'])

    def test_fee_payment_survives_restore_and_cannot_pay_twice(self):
        f = self.fixture
        session = RecoverySession(f['archive'], f['checkpoint'])
        identity, fee = next(iter(state_of(session)['fees'].items()))
        self.assertTrue(session.pay_fee(identity, fee['recipient'], 1_000, 1_999_999_000)['accepted'])
        saved = session.export()
        resumed = RecoverySession(saved['archive'], saved['checkpoint'])
        before = state_of(resumed)
        self.assertTrue(before['fees'][identity]['paid'])
        self.assertEqual(before['reserve_sompi'], 1_999_999_000)
        self.assertFalse(resumed.pay_fee(identity, fee['recipient'], 1_000, 1_999_998_000)['accepted'])
        self.assertEqual(state_of(resumed), before)

    def test_bad_exit_payment_terms_reject_atomically_before_valid_continuation(self):
        f = self.fixture
        session = RecoverySession(f['archive'], f['checkpoint'])
        identity, claim = next(iter(state_of(session)['claims'].items()))
        valid = [identity, claim['recipient'], 200_000_000, 50_000_000, 1_800_000_000]
        bad = [(0, 'ab' * 32), (0, []), (1, 'model-native:attacker'), (1, None),
               (2, 199_999_999), (2, 200_000_001), (3, 49_999_999), (3, 50_000_001),
               (4, 0), (4, 1_800_000_001)]
        bad += [(position, value) for position in (2, 3, 4) for value in (-1, MAX + 1, True, 1.0, None, [])]
        before = state_of(session)
        for position, value in bad:
            request = list(valid); request[position] = value
            with self.subTest(position=position, value=value):
                self.assertFalse(session.payout(*request)['accepted'])
                self.assertEqual(state_of(session), before)
        self.assertTrue(session.payout(*valid)['accepted'])
        saved = session.export()
        self.assertEqual(state_of(RecoverySession(saved['archive'], saved['checkpoint']))['reserve_sompi'], 1_800_000_000)

    def test_bad_fee_payment_terms_and_claim_confusion_reject_atomically(self):
        f = self.fixture
        session = RecoverySession(f['archive'], f['checkpoint'])
        identity, fee = next(iter(state_of(session)['fees'].items()))
        valid = [identity, fee['recipient'], 1_000, 1_999_999_000]
        bad = [(0, 'ab' * 32), (0, {}), (1, 'attacker'), (1, []), (2, 999), (2, 1_001), (3, 0)]
        bad += [(position, value) for position in (2, 3) for value in (-1, MAX + 1, True, 1.0, None, [])]
        before = state_of(session)
        # Exit and fee claims share an operation ID, but never share payment rights.
        self.assertFalse(session.payout(identity, fee['recipient'], 1_000, 0, 1_999_999_000)['accepted'])
        for position, value in bad:
            request = list(valid); request[position] = value
            with self.subTest(position=position, value=value):
                self.assertFalse(session.pay_fee(*request)['accepted'])
                self.assertEqual(state_of(session), before)
        self.assertTrue(session.pay_fee(*valid)['accepted'])

    def test_public_replay_rejects_forged_duplicate_reordered_and_old_profile_payments(self):
        f = self.fixture
        for kind in ('payout', 'fee_payment'):
            session = RecoverySession(f['archive'], f['checkpoint'])
            if kind == 'payout':
                identity, claim = next(iter(state_of(session)['claims'].items()))
                session.payout(identity, claim['recipient'], 200_000_000, 50_000_000, 1_800_000_000)
            else:
                identity, fee = next(iter(state_of(session)['fees'].items()))
                session.pay_fee(identity, fee['recipient'], 1_000, 1_999_999_000)
            saved = session.export()
            for change in ('recipient', 'claim', 'amount', 'rent_or_extra', 'remaining', 'repeat',
                           'first', 'v1', 'v2', 'profile', 'domain'):
                bad = copy.deepcopy(saved['archive'])
                record = bad['records'][-1]
                if change == 'recipient':
                    record['recipient'] = 'attacker'
                elif change == 'claim':
                    record['claim'] = 'ab' * 32
                elif change == 'amount':
                    record['principal' if kind == 'payout' else 'amount'] = True
                elif change == 'rent_or_extra':
                    record['rent'] = 0
                elif change == 'remaining':
                    record['remaining_reserve'] += 1
                elif change == 'repeat':
                    repeated = copy.deepcopy(record)
                    repeated['seq'] += 1
                    repeated['remaining_reserve'] -= repeated.get('principal', repeated.get('amount'))
                    bad['records'].append(repeated)
                elif change == 'first':
                    bad['records'].insert(0, bad['records'].pop())
                    for index, item in enumerate(bad['records']):
                        item['seq'] = index
                elif change in ('v1', 'v2'):
                    bad['schema'] = 'kpi-model-records/' + change
                elif change == 'domain':
                    bad['descriptor']['lane'] = 'foreign-lane'
                checkpoint = model_checkpoint(bad)  # Even a trusted producer cannot bypass these public checks.
                if change == 'profile':
                    checkpoint['schema'] = 'kpi-model-checkpoint/v2'
                with self.subTest(kind=kind, change=change), self.assertRaises(RecoveryError):
                    reconstruct_public(bad, checkpoint)
            missing = copy.deepcopy(saved['archive']); missing['records'].pop()
            with self.assertRaises(RecoveryError) as error:
                reconstruct_public(missing, saved['checkpoint'])
            self.assertEqual(error.exception.status, 'incomplete_data')

    def test_later_refund_keeps_v3_paid_state_and_cannot_downgrade_history(self):
        f = self.fixture
        session = RecoverySession(f['archive'], f['checkpoint'])
        identity, claim = next(iter(state_of(session)['claims'].items()))
        session.payout(identity, claim['recipient'], 200_000_000, 50_000_000, 1_800_000_000)
        session.fund_rent(50_000_000)
        wallet = wallet_from_backup(f['backups']['Carol'])
        event = next(event for event in state_of(session)['deposits'].values() if event['state'] == 'pending')
        recipient = 'model-native:' + wallet.owner
        self.assertTrue(session.request_refund(event['id'], recipient,
                        wallet.sign(refund_request_body(event['id'], event['amount'], recipient)))['accepted'])
        saved = session.export()
        self.assertEqual((saved['archive']['schema'], saved['checkpoint']['schema']),
                         ('kpi-model-records/v3', 'kpi-model-checkpoint/v3'))
        resumed = RecoverySession(saved['archive'], saved['checkpoint'])
        self.assertTrue(state_of(resumed)['claims'][identity]['paid'])
        self.assertFalse(resumed.payout(identity, claim['recipient'], 200_000_000, 50_000_000, 1_600_000_000)['accepted'])

    def test_fee_free_terminal_output_boundaries_and_overflow_remain_backed(self):
        rent = 50_000_000
        for principal in (1, MAX - rent, MAX - rent + 1, MAX):
            with self.subTest(principal=principal):
                session, identity, recipient = single_exit(self.fixture, principal)
                before = state_of(session)
                result = session.payout(identity, recipient, principal, rent, 0)
                saved = session.export()
                resumed = RecoverySession(saved['archive'], saved['checkpoint'])
                if principal > MAX - rent:
                    self.assertFalse(result['accepted'])
                    self.assertEqual(state_of(resumed), before)
                    self.assertFalse(before['claims'][identity]['paid'])
                    forged = copy.deepcopy(saved['archive'])
                    forged['schema'] = 'kpi-model-records/v3'
                    forged['records'].append({'seq': len(forged['records']), 'kind': 'payout',
                        'claim': identity, 'recipient': recipient, 'principal': principal, 'rent': rent, 'remaining_reserve': 0})
                    with self.assertRaises(RecoveryError):
                        reconstruct_public(forged, model_checkpoint(forged))
                else:
                    self.assertTrue(result['accepted'])
                    self.assertEqual(result['output_sompi'], principal + rent)
                    after = state_of(resumed)
                    self.assertEqual((after['reserve_sompi'], after['private_liability_sompi'],
                                      after['rent_reserved_sompi'], after['rent_paid_sompi']), (0, 0, 0, rent))
                    self.assertTrue(after['claims'][identity]['paid'])
                    self.assertFalse(resumed.payout(identity, recipient, principal, rent, 0)['accepted'])
                    self.assertEqual(state_of(resumed), after)

    def test_seeded_terminal_payment_orders_preserve_principal_and_external_rent(self):
        rng = random.Random(20261018)
        principals = [1, 2, 50_000_000, MAX - 50_000_000] + [rng.randrange(2, MAX - 50_000_000) for _ in range(16)]
        for principal in principals:
            fee = principal // 7
            for last in ('fee', 'user'):
                with self.subTest(principal=principal, last=last):
                    session, identity, recipient = single_exit(self.fixture, principal, fee, extra_rent=21)
                    reserve = principal
                    for kind in (('user', 'fee') if last == 'fee' else ('fee', 'user')):
                        if kind == 'fee' and fee == 0:
                            continue
                        value = fee if kind == 'fee' else principal - fee
                        reserve -= value
                        if kind == 'fee':
                            result = session.pay_fee(identity, 'model-relayer', fee, reserve)
                        else:
                            result = session.payout(identity, recipient, principal - fee, 50_000_000, reserve)
                        self.assertTrue(result['accepted'])
                        saved = session.export()
                        session = RecoverySession(saved['archive'], saved['checkpoint'])
                    final = state_of(session)
                    self.assertEqual((final['reserve_sompi'], final['private_liability_sompi']), (0, 0))
                    self.assertTrue(all(claim['paid'] for claim in final['claims'].values()))
                    self.assertTrue(all(claim['paid'] for claim in final['fees'].values()))
                    self.assertEqual((final['rent_available_sompi'], final['rent_reserved_sompi'], final['rent_paid_sompi']),
                                     (21, 0, 50_000_000))
                    self.assertFalse(session.payout(identity, recipient, principal - fee, 50_000_000, 0)['accepted'])
                    if fee:
                        self.assertFalse(session.pay_fee(identity, 'model-relayer', fee, 0)['accepted'])
                    self.assertEqual(state_of(session), final)

    def test_refund_payment_closes_deposit_and_remains_consumed_after_restore(self):
        f = self.fixture
        session = RecoverySession(f['archive'], f['checkpoint'])
        wallet = wallet_from_backup(f['backups']['Carol'])
        event = next(event for event in state_of(session)['deposits'].values() if event['state'] == 'pending')
        session.fund_rent(50_000_000)
        recipient = 'model-native:' + wallet.owner
        request = session.request_refund(event['id'], recipient,
                   wallet.sign(refund_request_body(event['id'], event['amount'], recipient)))
        self.assertTrue(request['accepted'])
        self.assertTrue(session.payout(request['id'], recipient, 300_000_000, 50_000_000, 1_700_000_000)['accepted'])
        saved = session.export()
        resumed = RecoverySession(saved['archive'], saved['checkpoint'])
        before = state_of(resumed)
        self.assertEqual(before['deposits'][event['id']]['state'], 'refunded')
        self.assertTrue(before['claims'][request['id']]['paid'])
        self.assertEqual(restore_wallet(saved['archive'], saved['checkpoint'], f['backups']['Carol'])['unpaid_refund_sompi'], 0)
        self.assertFalse(resumed.payout(request['id'], recipient, 300_000_000, 50_000_000, 1_400_000_000)['accepted'])
        note = pending_note_from_backup(f['backups']['Carol'], event)
        self.assertFalse(resumed.process(resumed.proof_oracle.credit(event, note, wallet.address))['accepted'])
        self.assertEqual(state_of(resumed), before)


if __name__ == '__main__':
    unittest.main()
