"""Synthetic sequential-confirmation controls, with no genuine proofs or RPC."""
from copy import deepcopy
import unittest

from campaign import ExitSequence
from codec import canonical_json, sha
import public
from test_history import fixture, batch_projection, exit_projection


def accepted(history, transaction_id=None):
    return {'history': history, 'history_selector': ['/synthetic/history', sha(canonical_json(history))],
            'handoff': {'expected_transaction_id': transaction_id}}


def beginning():
    history, roster = fixture()
    for number in range(2):
        history = public.extend(history, batch_projection(history, number, roster))
    return ExitSequence(accepted(history)), roster


def ready(sequence, participant, empty=False):
    if empty:
        return canonical_json({'schema': 'kpx8-owner-no-unspent-claim/v1',
            'participant_id_hex32': participant, 'history_sha256': sequence.accepted['history_selector'][1],
            'empty': True})
    return canonical_json({'schema': 'kpx8-owner-exit-ready/v1', 'domain_hex32': public.DOMAIN.hex(),
        'participant_id_hex32': participant, 'history_sha256': sequence.accepted['history_selector'][1],
        'nf_hex32': '01' * 32, 'gross_claim_sompi': 600000000,
        'payout_spk_hex36': '00' * 36, 'financial_authorization': False})


class ExitSequenceTests(unittest.TestCase):
    def test_two_empty_owners_do_not_hide_remaining_owner_and_pending_blocks_new_candidate(self):
        sequence, roster = beginning()
        self.assertFalse(sequence.owner_ready(ready(sequence, roster[0], True), roster[0], 0))
        self.assertFalse(sequence.owner_ready(ready(sequence, roster[1], True), roster[1], 1))
        self.assertTrue(sequence.owner_ready(ready(sequence, roster[2]), roster[2], 2))
        with self.assertRaises(ValueError): sequence.owner_ready(ready(sequence, roster[0]), roster[0], 0)

    def test_three_empty_owners_before_drain_halts(self):
        sequence, roster = beginning()
        for index in range(2): sequence.owner_ready(ready(sequence, roster[index], True), roster[index], index)
        with self.assertRaises(ValueError):
            sequence.owner_ready(ready(sequence, roster[2], True), roster[2], 2)

    def test_stale_empty_or_nonempty_failure_is_not_rotation_permission(self):
        sequence, roster = beginning()
        value = {'schema': 'kpx8-owner-no-unspent-claim/v1', 'participant_id_hex32': roster[0],
                 'history_sha256': '00' * 32, 'empty': True}
        with self.assertRaises(ValueError): sequence.owner_ready(canonical_json(value), roster[0], 0)
        self.assertEqual(sequence.empty, set())
        self.assertIsNone(sequence.pending)
        with self.assertRaises(ValueError): sequence.owner_ready(b'{}\n', roster[0], 0)
        self.assertEqual(sequence.next_owner, 0)

    def test_all_nine_require_exact_accepted_predecessor_and_candidate_then_terminal_drain(self):
        sequence, roster = beginning()
        for index in range(9):
            owner = index % 3
            sequence.owner_ready(ready(sequence, roster[owner]), roster[owner], owner)
            history = sequence.accepted['history']
            gross = 600000000 if index < 8 else history['head']['reserve_sompi']
            transition = exit_projection(history, index, gross)
            projection = bytes.fromhex(transition['projection_hex'])
            txid = public.sha(b'synthetic terminal tx', bytes([index])).hex() if index == 8 else \
                transition['successor_outpoint_hex36'][:64]
            sequence.candidate(txid, ['/synthetic/projection', sha(projection)])
            following = accepted(public.extend(history, transition), txid)
            wrong = deepcopy(following)
            wrong['handoff']['expected_transaction_id'] = '00' * 32
            with self.assertRaises(ValueError): sequence.advance(wrong)
            self.assertIsNotNone(sequence.pending)
            sequence.advance(following)
            self.assertEqual(len(sequence.completed), index + 1)
            self.assertIsNone(sequence.pending)
        self.assertEqual(sequence.accepted['history']['head']['reserve_sompi'], 0)
        self.assertIsNone(sequence.accepted['history']['head']['outpoint_hex36'])


if __name__ == '__main__': unittest.main()
