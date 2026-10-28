"""Public matching-model controls only; no proof, key or Original generation."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

import payout_privacy_attack as attack


class Matching(unittest.TestCase):
    def setUp(self):
        self.pk = [bytes([i + 1]) * 32 for i in range(3)]
        self.old = [b'old-' + bytes([i]) for i in range(3)]
        self.new = [b'new-' + bytes([i]) for i in range(3)]
        self.rows = {}
        for arm, raws in enumerate((self.old, self.new)):
            for owner, raw in enumerate(raws):
                self.rows[raw] = {'id': hashlib.sha256(raw).hexdigest(),
                    'spk': attack.native_spk(self.pk[owner] if arm == 0 else bytes([17 + owner]) * 32),
                    'nf': bytes([33 + 3 * arm + owner]) * 32,
                    'payout': 199999999, 'fee': 1, 'action': bytes([owner + 1]) * 32,
                    'context': b'public fixture context', 'domain': b'D' * 32, 'profile': b'P' * 32}
        self.mock = patch.object(attack, 'public_exit', side_effect=lambda raw: self.rows[raw])
        self.mock.start()
        self.addCleanup(self.mock.stop)

    def facts(self, raws):
        own = self.rows[raws[1]]
        index = 7 if raws == self.old else 9
        return {'contacts': [{'owner': 0, 'native_pk': self.pk[0], 'delivery_pk': b'd' * 32,
                              'invoice_index': index, 'domain': b'D' * 32, 'profile': b'P' * 32}],
                'own_payouts': [{'owner': 1, 'spk': own['spk'], 'nf': own['nf']}],
                'known_receipts': [{'owner': 0, 'rho': b'r' * 32, 'cm': b'c' * 32,
                                    'value': 200000000, 'known_consumed': True}],
                'routes': [], 'economic': [], 'timing': [], 'public_identifier_edges': [],
                'unmodeled': []}

    def truth(self, raws):
        return [self.rows[raw]['id'] for raw in raws]

    def test_exact_old_lookup_and_new_honest_tie(self):
        before = attack.candidates(self.old, 'invoice-native', self.facts(self.old))
        after = attack.candidates(self.new, 'fresh-self', self.facts(self.new))
        self.assertEqual((before['compatible_assignments'], before['candidate_counts']), (1, [1, 1, 1]))
        self.assertEqual((after['compatible_assignments'], after['candidate_counts']), (2, [2, 1, 2]))
        # Predictions survive real JSON capsule serialization before scoring.
        score = attack.score_sealed(json.loads(json.dumps(after)), self.truth(self.new))
        self.assertTrue(score['true_assignment_retained'])
        self.assertEqual(score['wrong_unique'], 0)

    def test_actual_labelled_release_collapses_dispatcher_union(self):
        facts = self.facts(self.new)
        facts['routes'] = [{'owner': owner, 'exit_id': key, 'provenance': 'actual-public-release-fixture'}
                           for owner, key in enumerate(self.truth(self.new))]
        result = attack.candidates(self.new, 'fresh-self', facts)
        self.assertEqual(result['candidate_counts'], [1, 1, 1])
        self.assertEqual(result['compatible_assignments'], 1)

    def test_economic_fact_can_remove_the_entire_apparent_gain(self):
        self.rows[self.new[0]]['payout'] = 198999999
        facts = self.facts(self.new)
        facts['known_receipts'] = []
        facts['economic'] = [{'owner': 0, 'allowed_payout_fee': [[198999999, 1]]}]
        result = attack.candidates(self.new, 'fresh-self', facts)
        self.assertEqual(result['candidate_counts'], [1, 1, 1])

    def test_cross_arm_same_nf_control_is_linkable(self):
        for owner in range(3):
            self.rows[self.new[owner]]['nf'] = self.rows[self.old[owner]]['nf']
        before = attack.candidates(self.old, 'invoice-native', self.facts(self.old))
        facts = self.facts(self.new)
        for prediction in before['unique_predictions']:
            old = next(row for row in self.rows.values() if row['id'] == prediction['exit_id'])
            ids = [self.rows[raw]['id'] for raw in self.new if self.rows[raw]['nf'] == old['nf']]
            facts['public_identifier_edges'].append({'owner': prediction['owner'],
                'compatible_exit_ids': ids, 'provenance': 'actual-public-same-NF-equality-fixture'})
        self.assertEqual(attack.candidates(self.new, 'fresh-self', facts)['candidate_counts'], [1, 1, 1])

    def test_wrong_route_excludes_truth_instead_of_reporting_success(self):
        facts = self.facts(self.new)
        facts['routes'] = [{'owner': 0, 'exit_id': self.truth(self.new)[2], 'provenance': 'wrong-model-control'}]
        prediction = attack.candidates(self.new, 'fresh-self', facts)
        score = attack.score_sealed(prediction, self.truth(self.new))
        self.assertFalse(score['true_assignment_retained'])
        self.assertEqual(score['wrong_unique'], 2)

    def test_missing_model_coverage_is_explicit(self):
        facts = self.facts(self.new)
        facts['unmodeled'] = ['full corrupt-server view missing']
        prediction = attack.candidates(self.new, 'fresh-self', facts)
        self.assertFalse(prediction['matching_model_complete'])
        self.assertFalse(attack.score_sealed(prediction, self.truth(self.new))[
            'overall_crypto_or_dispatcher_privacy_qualified'])

    def test_refuse_extra_hidden_truth_or_honest_own_payout_fields(self):
        facts = self.facts(self.new)
        facts['truth'] = self.truth(self.new)
        with self.assertRaises(ValueError):
            attack.candidates(self.new, 'fresh-self', facts)

    def test_alternative_contact_keys_union_and_other_indexes_are_retained(self):
        facts = self.facts(self.old)
        alternative = dict(facts['contacts'][0], native_pk=self.pk[2])
        facts['contacts'].append(alternative)
        facts['contacts'].append(dict(alternative, invoice_index=9))
        prediction = attack.candidates(self.old, 'invoice-native', facts)
        self.assertEqual(prediction['candidate_counts'], [2, 1, 2])
        self.assertEqual(prediction['retained_contact_records'][-1]['inapplicability_reason'],
                         'different-frozen-arm-index')
        self.assertTrue(attack.score_sealed(prediction, self.truth(self.old))['true_assignment_retained'])

    def test_sealed_redundant_rank_fields_cannot_disagree_with_models(self):
        prediction = attack.candidates(self.new, 'fresh-self', self.facts(self.new))
        prediction['candidate_counts'][0] = 1
        with self.assertRaises(ValueError):
            attack.score_sealed(prediction, self.truth(self.new))
        facts = self.facts(self.new)
        facts['own_payouts'][0]['owner'] = 0
        with self.assertRaises(ValueError):
            attack.candidates(self.new, 'fresh-self', facts)


if __name__ == '__main__':
    unittest.main()
