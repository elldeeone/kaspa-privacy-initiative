"""Public source-rule simulation only; never a realized private plan or truth."""
from itertools import combinations, permutations
import unittest

from source_policy_prediction import FEE_CAP, NOTE_FLOOR, actor1_masks, predict, queue_profiles, analyze
from test_economic_linkage import symmetric_public_fixture


def forward_wallet(first, second, direction, fees):
    """Independent small wallet model: choose live notes, do not use formulas."""
    owned = [[(2_000_000_000, 'initial')] for _ in range(3)]
    selected = []
    for round_index, order in enumerate((first, second)):
        payment = (500_000_000, 200_000_000)[round_index]
        for ordinal, owner in enumerate(order):
            fee = fees[3 * round_index + ordinal]
            eligible = [note for note in owned[owner] if note[0] >= payment + fee + NOTE_FLOOR]
            if round_index == 1:
                if owner == 1:
                    eligible = [note for note in eligible if note[1] == 'change']
                else:
                    preferred = [note for note in eligible if note[1] == 'received']
                    eligible = preferred or [note for note in eligible if note[1] == 'change']
            note = max(eligible)
            selected.append((round_index, owner, note[0], note[1]))
            owned[owner].remove(note)
            owned[owner].append((note[0] - payment - fee, 'change'))
            owned[(owner + direction) % 3].append((payment, 'received'))
    return tuple(tuple(sorted((note[0] for note in notes), reverse=True)) for notes in owned), selected


def interleavings():
    positions = set(range(9))
    for zero in combinations(range(9), 3):
        remaining = positions - set(zero)
        for one in combinations(sorted(remaining), 3):
            result = [2] * 9
            for index in zero: result[index] = 0
            for index in one: result[index] = 1
            yield tuple(result)


def gross_order(queues, actors):
    counts, result = [0, 0, 0], []
    for owner in actors:
        result.append(queues[owner][counts[owner]])
        counts[owner] += 1
    return tuple(result)


def exhaustive_actor1_masks(queues, gross):
    return {sum(1 << i for i, actor in enumerate(order) if actor == 1)
            for order in interleavings() if gross_order(queues, order) == tuple(gross)}


class SourcePolicyControls(unittest.TestCase):
    def test_all72_forward_schedules_and_fee_boundaries(self):
        for fees in ([1_000_000 * i for i in range(1, 7)], [1] * 6, [FEE_CAP] * 6):
            seen, count = set(), 0
            for first in permutations(range(3)):
                for second in permutations(range(3)):
                    directions = []
                    for direction in (1, 2):
                        queues, selected = forward_wallet(first, second, direction, fees)
                        directions.append(queues); seen.add(queues); count += 1
                        self.assertTrue(all(value == 2_000_000_000 and kind == 'initial'
                                            for rnd, _, value, kind in selected if rnd == 0))
                        self.assertTrue(all(kind == ('change' if owner == 1 else 'received')
                                            for rnd, owner, _, kind in selected if rnd == 1))
                        self.assertEqual(sum(sum(q) for q in queues) + sum(fees), 6_000_000_000)
                    self.assertEqual(*directions)
            self.assertEqual(count, 72)
            self.assertEqual(seen, queue_profiles(fees))
            self.assertEqual(len(seen), 36 if len(set(fees)) == 6 else 1)

    def test_received2_ineligible_received5_eligible_and_no_fallback(self):
        for fee in (1, FEE_CAP):
            self.assertLess(200_000_000, 200_000_000 + fee + NOTE_FLOOR)
            self.assertGreaterEqual(500_000_000, 200_000_000 + fee + NOTE_FLOOR)
            self.assertLess(500_000_000, 500_000_000 + fee + NOTE_FLOOR)

    def test_queue_DP_matches_independent1680_interleavings(self):
        fees = [1_000_000 * i for i in range(1, 7)]
        queues, _ = forward_wallet((0, 1, 2), (0, 1, 2), 1, fees)
        self.assertEqual(sum(1 for _ in interleavings()), 1680)
        for order in [(0, 1, 2, 0, 1, 2, 0, 1, 2), (1, 1, 1, 0, 0, 0, 2, 2, 2)]:
            gross = gross_order(queues, order)
            self.assertEqual(actor1_masks(queues, gross), exhaustive_actor1_masks(queues, gross))

    def test_prospective_actor1_pair_and_possible_third_exit(self):
        fees = [1_000_000 * i for i in range(1, 7)]
        queues, _ = forward_wallet((0, 1, 2), (0, 1, 2), 1, fees)
        gross = gross_order(queues, (0, 1, 2, 0, 1, 2, 0, 1, 2))
        result = predict(fees, gross)
        self.assertEqual(result['status'], 'SOURCE_POLICY_PREDICTION_SUPPORTED')
        self.assertEqual(result['must_actor1_exit_indices'], [1, 4])
        self.assertEqual(result['possible_actor1_exit_indices'], [1, 4, 6, 7, 8])
        self.assertEqual(result['distinct_actor1_exit_position_mask_count'], 3)
        self.assertEqual(result['predicted_actor1_unique_gross500M_exit_index'], 4)
        self.assertEqual(result['predicted_actor1_unique_change_band_exit_index'], 1)
        front = predict(fees, gross_order(queues, (1, 1, 1, 0, 0, 0, 2, 2, 2)))
        self.assertEqual(front['must_actor1_exit_indices'], [0, 1, 2])

    def test_duplicate_schedules_do_not_add_evidence(self):
        fees = [1] * 6
        queues, _ = forward_wallet((0, 1, 2), (0, 1, 2), 1, fees)
        result = predict(fees, gross_order(queues, (0, 1, 2, 0, 1, 2, 0, 1, 2)))
        self.assertEqual(result['source_payment_schedules'], 72)
        self.assertEqual(result['distinct_value_queue_profiles'], 1)
        self.assertEqual(result['distinct_actor1_exit_position_mask_count'], 3)

    def test_failures_are_retained_without_vacuous_predictions(self):
        fees = [1_000_000 * i for i in range(1, 7)]
        queues, _ = forward_wallet((0, 1, 2), (0, 1, 2), 1, fees)
        gross = list(gross_order(queues, (0, 1, 2, 0, 1, 2, 0, 1, 2)))
        gross[1], gross[4] = gross[4], gross[1]  # Actor1's500m precedes its larger note.
        result = predict(fees, gross)
        self.assertEqual(result['status'], 'INCONSISTENT_SOURCE_POLICY_MODEL_OR_INPUT')
        self.assertEqual(result['must_actor1_exit_indices'], [])
        self.assertIsNone(result['predicted_actor1_unique_gross500M_exit_index'])
        result = predict([FEE_CAP + 1] + fees[1:], gross)
        self.assertEqual(result['status'], 'SOURCE_POLICY_ASSUMPTIONS_NOT_QUALIFIED')
        self.assertFalse(result['predicted_pair_supported_by_every_consistent_source_model'])
        for bad in (True, 1.0, '1'):
            with self.assertRaises(ValueError): predict([bad] + fees[1:], gross)

    def test_strict_public_ledger_scope_and_conditional_funding_claim(self):
        fees = [1_000_000 * i for i in range(1, 7)]
        queues, _ = forward_wallet((0, 1, 2), (0, 1, 2), 1, fees)
        gross = gross_order(queues, (0, 1, 2, 0, 1, 2, 0, 1, 2))
        value = symmetric_public_fixture()
        for row, fee in zip(value['payments'], fees): row['fee_sompi'] = fee
        for row, note in zip(value['exits'], gross): row['payout_sompi'] = note - row['fee_sompi']
        result = analyze(value)
        self.assertEqual([row['gross_sompi'] for row in result['public_actor1_exit_predictions']],
                         [gross[1], gross[4]])
        self.assertTrue(result['funding_association_conditional_on_selected_source_and_input_order_provenance'])
        self.assertFalse(result['contemporaneous_activation_argv_receipt_independently_verified'])
        self.assertFalse(result['funding_mapping_independently_verified_by_this_analysis'])
        self.assertFalse(result['owner_verified_accuracy_or_probability_claim'])
        self.assertFalse(result['generic_crypto_or_NF_preimage_break'])
        self.assertFalse(result['received500M_claim_and_original_change_same_asset_root_claimed'])
        self.assertFalse(result['prior_frozen_economic_arms_modified'])
        self.assertEqual(result['privacy_PASS_verdict'], 'NOT_DEFINED')
        interleaved = symmetric_public_fixture()
        for index, row in enumerate(interleaved['payments']): row['event_index'] = index + 1
        interleaved['exits'][0]['event_index'] = 0
        with self.assertRaisesRegex(ValueError, 'six-payments-before-nine-exits'):
            analyze(interleaved)
        value['private_PLAN'] = 'FORBIDDEN_SYNTHETIC_FIELD'
        with self.assertRaises(ValueError): analyze(value)


if __name__ == '__main__':
    unittest.main()
