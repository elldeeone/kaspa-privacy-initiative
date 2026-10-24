"""Pure synthetic public controls, not owner scores or privacy experiments."""
import copy
from fractions import Fraction
from itertools import product
from math import comb
import unittest

import cohort_stats as stats


def fixture(K=3, groups=2, unknown=4):
    ambiguity = {'candidate_creator_assignments': 2 * K, 'candidate_partitions': K,
                 'hash_tie_break_used': 2 * K > 1, 'unique_partition_from_constraints': K == 1}
    observer = {'schema': 'kpx7-colluder-observer-seal/v1',
        'experiment_sha256': stats.EXPERIMENT, 'session_sha256': '11' * 32,
        'projection_sha256': '22' * 32, 'strategy_sha256': stats.STRATEGY,
        'capsule_seal_sha256': '33' * 32, 'excluded_known_creator_count': 6 - unknown,
        'unknown_creator_target_count': unknown, **ambiguity,
        'scope': 'SEALED_ONE_COLLUDER_STRATEGY_NOT_ANONYMITY_QUALIFICATION'}
    aggregate = {'schema': 'kpx7-owner-privacy-global-counts/v1',
        'experiment_sha256': stats.EXPERIMENT, 'session_sha256': '11' * 32,
        'projection_sha256': '22' * 32, 'sealed_bundle_sha256': '44' * 32,
        'coordinator_only': {'eligible_count': 6, 'matched_count': 2,
                             'label_invariant_groups_matched': 1},
        'one_colluder': {'eligible_count': unknown, 'matched_count': 0,
            'excluded_known_creator_count': 6 - unknown,
            'label_invariant_unknown_groups_matched': groups,
            'presealed_ambiguity': copy.deepcopy(ambiguity)},
        'scope': 'FINITE_FROZEN_STRATEGIES_ONLY_NOT_AN_ANONYMITY_SCORE',
        'interpretation': 'A_CORRECT_TIE_BREAK_GUESS_IS_NOT_BY_ITSELF_A_RECOVERED_LEAK'}
    return observer, aggregate


def event(K=3, S=1):
    return stats.world_event(*fixture(K, 2 if S else 0))


def summary(values):
    if type(values) in (list, tuple):
        values = [dict(value, world_id=f'world-{index+1:02d}') if type(value) is dict else value
                  for index, value in enumerate(values)]
    return stats.summarize(values)


def enumerate_distribution(probabilities):
    result = [Fraction(0)] * (len(probabilities) + 1)
    for bits in product((0, 1), repeat=len(probabilities)):
        probability = Fraction(1)
        for bit, p in zip(bits, probabilities):
            probability *= p if bit else 1 - p
        result[sum(bits)] += probability
    return tuple(result)


class PublicWorldTests(unittest.TestCase):
    def test_primary_event_uses_groups_and_accepts_two_to_four_unknown_rows(self):
        for unknown, groups in product((2, 3, 4), (0, 2)):
            observed = stats.world_event(*fixture(3, groups, unknown))
            self.assertEqual(set(observed), stats.EVENT_FIELDS)
            self.assertEqual((observed['status'], observed['K'], observed['S']),
                             ('COMPLETE', 3, int(groups == 2)))
        observer, aggregate = fixture()
        aggregate['one_colluder']['matched_count'] = 0
        aggregate['coordinator_only']['matched_count'] = 6
        self.assertEqual(stats.world_event(observer, aggregate)['S'], 1)

    def test_one_correct_group_is_incomplete_not_miss(self):
        observed = stats.world_event(*fixture(2, 1))
        self.assertEqual((observed['status'], observed['S'], observed['K']), ('INCOMPLETE', None, 2))

    def test_unique_partition_failure_precedes_unexpected_shape(self):
        observer, aggregate = fixture(1, 1)
        aggregate['one_colluder']['eligible_count'] = 1
        observed = stats.world_event(observer, aggregate)
        self.assertTrue(observed['candidate_failed'])
        self.assertEqual((observed['status'], observed['K'], observed['S']), ('CANDIDATE_FAIL', 1, None))
        observer, aggregate = fixture(2, 1)
        observer['unique_partition_from_constraints'] = True
        aggregate['one_colluder']['presealed_ambiguity']['unique_partition_from_constraints'] = True
        self.assertEqual(stats.world_event(observer, aggregate)['status'], 'CANDIDATE_FAIL')

    def test_visible_context_must_join_before_classification(self):
        for field in ('experiment_sha256', 'session_sha256', 'projection_sha256'):
            observer, aggregate = fixture(1)
            aggregate[field] = '55' * 32
            self.assertEqual(stats.world_event(observer, aggregate)['status'], 'INCOMPLETE')
        observer, aggregate = fixture()
        observer['strategy_sha256'] = '55' * 32
        self.assertEqual(stats.world_event(observer, aggregate)['status'], 'INCOMPLETE')
        observer, aggregate = fixture()
        aggregate['one_colluder']['presealed_ambiguity']['candidate_partitions'] = 2
        self.assertEqual(stats.world_event(observer, aggregate)['status'], 'INCOMPLETE')

    def test_strict_public_shapes_types_and_count_joins(self):
        mutations = (
            lambda o, a: o.update(extra='unexpected'),
            lambda o, a: a.update(extra='unexpected'),
            lambda o, a: a['one_colluder'].update(eligible_count=2),
            lambda o, a: a['one_colluder'].update(excluded_known_creator_count=3),
            lambda o, a: a['one_colluder'].update(label_invariant_unknown_groups_matched=True),
            lambda o, a: o.update(candidate_partitions=True),
            lambda o, a: a['one_colluder']['presealed_ambiguity'].update(hash_tie_break_used=1),
            lambda o, a: o.update(session_sha256='AA' * 32),
        )
        for mutate in mutations:
            observer, aggregate = fixture(); mutate(observer, aggregate)
            self.assertEqual(stats.world_event(observer, aggregate)['status'], 'INCOMPLETE')
        self.assertEqual(stats.world_event(None, {})['status'], 'INCOMPLETE')


class ExactDistributionTests(unittest.TestCase):
    def test_dp_against_exhaustive_small_n(self):
        choices = (Fraction(0), Fraction(1, 3), Fraction(1, 2), Fraction(1))
        for n in range(5):
            for probabilities in product(choices, repeat=n):
                expected = enumerate_distribution(probabilities)
                self.assertEqual(stats.poisson_binomial(probabilities), expected)
                self.assertEqual(sum(expected), 1)
                for threshold in range(n + 2):
                    self.assertEqual(stats.poisson_binomial_tail(probabilities, threshold),
                                     sum(expected[threshold:], Fraction(0)))

    def test_exact_arithmetic_rejects_float_and_boolean(self):
        for bad in (0.5, True, -1, Fraction(4, 3)):
            with self.assertRaises(ValueError):
                stats.poisson_binomial([bad])
        with self.assertRaises(ValueError):
            stats.poisson_binomial_tail([], True)
        self.assertEqual(stats.poisson_binomial_tail([], 0), 1)
        self.assertEqual(stats.poisson_binomial_tail([], 1), 0)

    def test_homogeneous_sixteen_fixed_alpha_cutoffs(self):
        cases = ((2, 14, Fraction(697, 65536), Fraction(137, 65536)),
                 (3, 11, Fraction(686401, 43046721), Fraction(19321, 4782969)))
        for K, cutoff, before, at in cases:
            p = Fraction(1, K)
            independent = lambda s: sum((comb(16, k) * p**k * (1-p)**(16-k)
                                         for k in range(s, 17)), Fraction(0))
            self.assertEqual(independent(cutoff - 1), before)
            self.assertEqual(independent(cutoff), at)
            for successes, expected in ((cutoff - 1, False), (cutoff, True)):
                report = summary([event(K, int(i < successes)) for i in range(16)])
                self.assertEqual(report['status'], 'COMPLETE')
                self.assertEqual(report['tail'], {'numerator': independent(successes).numerator,
                                                  'denominator': independent(successes).denominator})
                self.assertEqual(report['excess_success_detected'], expected)

    def test_mixed_fixed_alpha_cutoff_independent_convolution(self):
        for successes, expected_flag, expected_tail in ((11, False, Fraction(13897, 559872)),
                                                       (12, True, Fraction(3649, 559872))):
            direct = sum((Fraction(comb(8, a), 2**8) * Fraction(comb(8, b)*2**(8-b), 3**8)
                          for a in range(9) for b in range(9) if a+b >= successes), Fraction(0))
            self.assertEqual(direct, expected_tail)
            values = [event(2 if i < 8 else 3, int(i < successes)) for i in range(16)]
            report = summary(values)
            self.assertEqual(report['excess_success_detected'], expected_flag)
            self.assertEqual(report['tail'], {'numerator': direct.numerator, 'denominator': direct.denominator})


class CohortCompletenessTests(unittest.TestCase):
    def test_all_statuses_export_the_conditional_model_and_scope(self):
        for values in ([event()] * 16, [], [stats.world_event(*fixture(1))]):
            report = summary(values)
            self.assertEqual(report['classification'], 'BOUNDED_FROZEN_STRATEGY_MODEL_COMPARISON_ONLY')
            self.assertEqual(report['baseline_assumptions'],
                {'conditional_uniform_hidden_partition': True,
                 'per_world_success_probability': '1/K_i', 'independent_worlds': True,
                 'proven_protocol_properties': False})
            self.assertEqual(report['event_unit'], 'ONE_WORLD_BOTH_ELIGIBLE_HONEST_GROUPS_RECOVERED')
            self.assertIs(report['privacy_qualification'], False)
            self.assertIs(report['financial_acceptance'], False)

    def test_missing_world_cannot_shrink_denominator(self):
        report = summary([event()] * 15)
        self.assertEqual((report['status'], report['planned_worlds'], report['complete_worlds'],
                          report['incomplete_worlds']), ('INCOMPLETE', 16, 15, 1))
        self.assertIsNone(report['tail'])
        placeholder = {'status': 'INCOMPLETE', 'candidate_failed': False, 'S': None,
                       'K': None, 'reason': 'missing-world'}
        report = summary([event()] * 15 + [placeholder])
        self.assertEqual(report['incomplete_worlds'], 1)
        self.assertIsNone(report['excess_success_detected'])

    def test_failure_dominates_incomplete_and_missing_worlds(self):
        failure = stats.world_event(*fixture(1, 1))
        for values in ([failure], [event()] * 14 + [failure, None], [failure] * 16):
            report = summary(values)
            self.assertEqual(report['status'], 'CANDIDATE_FAIL')
            self.assertTrue(report['candidate_failed'])
            self.assertIsNone(report['tail'])

    def test_invalid_or_extra_events_do_not_produce_statistic(self):
        for values in (None, [], [event()] * 17, [event()] * 15 + [dict(event(), S=True)]):
            report = summary(values)
            self.assertEqual(report['status'], 'INCOMPLETE')
            self.assertIsNone(report['tail'])
        values = [dict(event(), world_id=f'world-{i+1:02d}', wrapper_note='PUBLIC SYNTHETIC')
                  for i in range(16)]
        report = stats.summarize(values)
        self.assertEqual(report['status'], 'COMPLETE')
        self.assertNotIn('world_id', str(report))

    def test_exact_ordered_world_registry_and_sticky_unique_K(self):
        good = [dict(event(), world_id=world_id) for world_id in stats.WORLD_IDS]
        for positions in ((0,), (0, 1)):
            values = copy.deepcopy(good)
            for index in positions:
                values[index]['world_id'] = 'world-16'
            report = stats.summarize(values)
            self.assertEqual(report['status'], 'INCOMPLETE')
            self.assertIsNone(report['tail'])
        self.assertEqual(stats.summarize([event()] * 16)['complete_worlds'], 0)
        unique = summary([event()] * 15 + [dict(event(), K=1)])
        self.assertEqual(unique['status'], 'CANDIDATE_FAIL')
        self.assertIsNone(unique['tail'])


if __name__ == '__main__':
    unittest.main()
