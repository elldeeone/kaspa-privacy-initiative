#!/usr/bin/env python3
"""Disclosure and scoring failure controls; no proof generation or network."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('fresh_proof', Path(__file__).with_name('fresh-proof.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class Controls(unittest.TestCase):
    def test_secret_and_fallback_encodings_rejected(self):
        for length in [32, 128, 265]:
            secret = bytes(i % 256 for i in range(length))
            for raw in [b'prefix'+secret+b'suffix',
                        json.dumps({'nested': [secret.hex().upper()]}).encode()]:
                with self.subTest(length=length), self.assertRaises(ValueError):
                    runner.check_bytes(raw, {secret})

    def test_nested_key_and_fallback_arrays_rejected(self):
        for length in [32, 128, 265]:
            secret = bytes(i % 256 for i in range(length))
            raw = json.dumps({'nested': [{'arbitrary_name': list(secret)}]}).encode()
            with self.subTest(length=length), self.assertRaises(ValueError):
                runner.check_bytes(raw, {secret})

    def test_unknown_private_values_in_named_fields_rejected(self):
        for field in ['spending', 'viewing', 'privateKey', 'private_key', 'initial_note', 'rho', 'funding_key']:
            with self.subTest(field=field), self.assertRaises(ValueError):
                runner.check_bytes(json.dumps({'nested': {field: 'unknown'}}).encode(), set())

    def test_unrelated_public_proof_is_allowed(self):
        runner.check_bytes(json.dumps({'proof': bytes([77]*128).hex(),
                                      'inputs': [], 'fee_sompi': 21729600}).encode(), {bytes(range(32))})

    @staticmethod
    def example():
        truth = {'target_step': 2, 'spends': [{'step': 2, 'source_step': 1, 'position': 1}]}
        chain = {'records': [{'transaction': {'id': name}} for name in ['fund', 'source', 'exit']]}
        attack = {'candidate_set': 'a', 'source_candidate_count': 2, 'position_candidate_count': 4,
                  'singleton_source_prediction': None, 'nearest_time_source_ties': ['other']}
        row = {'step': 2, **{h: {a: copy.deepcopy(attack) for a in ['anchor_single_spend', 'joint_values']}
                            for h in ['at_withdrawal', 'complete_trace']}}
        observed = {'rows': [row], 'candidate_sets': {'a': {
            'creation_transaction_candidates': ['source', 'other'], 'consumed_position_candidates': [1, 2, 3, 4]}}}
        return truth, chain, observed

    def test_ambiguity_does_not_become_attack_success(self):
        result = runner.score(*self.example())['complete_trace']['joint_values']
        self.assertEqual(result['coverage'], 0)
        self.assertEqual(result['abstentions'], 1)
        self.assertEqual(result['full_coverage_recency_success'], 0)
        self.assertEqual(result['uniform_candidate_prior_expected_success'], 0.5)
        self.assertIsNone(result['population_confidence_interval'])

    def test_excluding_actual_history_fails_scoring(self):
        for field, wrong in [('creation_transaction_candidates', ['other']), ('consumed_position_candidates', [2])]:
            truth, chain, observed = self.example()
            observed['candidate_sets']['a'][field] = wrong
            with self.subTest(field=field), self.assertRaises(ValueError):
                runner.score(truth, chain, observed)


if __name__ == '__main__':
    unittest.main()
