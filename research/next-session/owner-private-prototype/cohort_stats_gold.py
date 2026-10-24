"""Independent closed-form controls on synthetic public records; no data I/O."""
from fractions import Fraction
from math import comb


def _receipts(stats, K, groups):
    ambiguity = {'candidate_creator_assignments': 2 * K,
                 'candidate_partitions': K, 'hash_tie_break_used': True,
                 'unique_partition_from_constraints': K == 1}
    observer = {'schema': 'kpx7-colluder-observer-seal/v1',
        'experiment_sha256': stats.EXPERIMENT, 'strategy_sha256': stats.STRATEGY,
        'session_sha256': '11' * 32, 'projection_sha256': '22' * 32,
        'capsule_seal_sha256': '33' * 32, 'excluded_known_creator_count': 2,
        'unknown_creator_target_count': 4, **ambiguity,
        'scope': 'SEALED_ONE_COLLUDER_STRATEGY_NOT_ANONYMITY_QUALIFICATION'}
    aggregate = {'schema': 'kpx7-owner-privacy-global-counts/v1',
        'experiment_sha256': stats.EXPERIMENT, 'session_sha256': '11' * 32,
        'projection_sha256': '22' * 32, 'sealed_bundle_sha256': '44' * 32,
        'coordinator_only': {'eligible_count': 6, 'matched_count': 0,
                             'label_invariant_groups_matched': 0},
        'one_colluder': {'eligible_count': 4, 'matched_count': 0,
            'excluded_known_creator_count': 2,
            'label_invariant_unknown_groups_matched': groups,
            'presealed_ambiguity': dict(ambiguity)},
        'scope': 'FINITE_FROZEN_STRATEGIES_ONLY_NOT_AN_ANONYMITY_SCORE',
        'interpretation': 'A_CORRECT_TIE_BREAK_GUESS_IS_NOT_BY_ITSELF_A_RECOVERED_LEAK'}
    return observer, aggregate


def run(stats):
    """Receive the already-authenticated pure module; return public gold results."""
    checks = []

    def check(name, actual, expected):
        if actual != expected:
            raise AssertionError(name)
        checks.append({'check': name, 'passed': True})

    def events(Ks, successes):
        return [{'world_id': f'world-{i + 1:02d}', 'status': 'COMPLETE',
                 'candidate_failed': False, 'S': int(i < successes),
                 'K': K, 'reason': 'SYNTHETIC_PUBLIC_GOLD'} for i, K in enumerate(Ks)]

    def tail(summary):
        value = summary['tail']
        return Fraction(value['numerator'], value['denominator'])

    # Closed-form binomial coefficients, independent of the module's DP.
    half = [2] * 16
    for successes in (0, 13, 14, 16):
        expected = Fraction(sum(comb(16, k) for k in range(successes, 17)), 2**16)
        report = stats.summarize(events(half, successes))
        check(f'binomial16-half-upper-tail-{successes}', tail(report), expected)
        check(f'alpha-inclusive-{successes}', report['excess_success_detected'],
              expected <= Fraction(1, 100))
        check(f'world-event-denominator-{successes}',
              (report['planned_worlds'], report['complete_worlds'], report['successes']),
              (16, 16, successes))
    check('binomial13-explicit-gold', tail(stats.summarize(events(half, 13))), Fraction(697, 65536))
    check('binomial14-explicit-gold', tail(stats.summarize(events(half, 14))), Fraction(137, 65536))

    # P(all successes) is the product. For >=15, multiply that product by
    # 1 + sum(failure/success odds) = 1 + 8*1 + 8*2 = 25.
    mixed = [2] * 8 + [3] * 8
    product_denominator = 2**8 * 3**8
    check('heterogeneous-all-success-product', tail(stats.summarize(events(mixed, 16))),
          Fraction(1, product_denominator))
    check('heterogeneous-one-failure-closed-form', tail(stats.summarize(events(mixed, 15))),
          Fraction(25, product_denominator))
    check('thirds-all-success-product', tail(stats.summarize(events([3] * 16, 16))), Fraction(1, 3**16))

    one_group = stats.world_event(*_receipts(stats, 2, 1))
    check('one-group-is-incomplete', (one_group['status'], one_group['S']), ('INCOMPLETE', None))
    observer, aggregate = _receipts(stats, 1, 1)
    aggregate['one_colluder']['eligible_count'] = 1
    unique = stats.world_event(observer, aggregate)
    check('unique-K1-precedes-invalid-group-shape',
          (unique['status'], unique['candidate_failed'], unique['S']), ('CANDIDATE_FAIL', True, None))

    missing = stats.summarize(events(half, 16)[:-1])
    check('missing-world-no-shrink',
          (missing['status'], missing['planned_worlds'], missing['complete_worlds'],
           missing['incomplete_worlds'], missing['tail']), ('INCOMPLETE', 16, 15, 1, None))
    invalid = events(half, 16); invalid[-1]['world_id'] = 'world-15'
    check('duplicate-registered-world-no-statistic', stats.summarize(invalid)['tail'], None)
    failed = events(half, 16); failed[-1].update(unique)
    failure = stats.summarize(failed)
    check('direct-failure-suppresses-statistic',
          (failure['status'], failure['candidate_failed'], failure['tail']), ('CANDIDATE_FAIL', True, None))
    for label, report in (('complete', stats.summarize(events(mixed, 16))),
                          ('incomplete', missing), ('candidate-fail', failure)):
        check('explicit-baseline-' + label, report['baseline_assumptions'], {
            'conditional_uniform_hidden_partition': True, 'per_world_success_probability': '1/K_i',
            'independent_worlds': True, 'proven_protocol_properties': False})
        check('no-qualification-' + label,
              (report['privacy_qualification'], report['financial_acceptance']), (False, False))
    return {'classification': 'PURE_SYNTHETIC_PUBLIC_GOLD_CONTROLS_NOT_COHORT_DATA_OR_PRIVACY_RESULT',
            'passed': True, 'check_count': len(checks), 'checks': checks,
            'actual_worlds_read_or_initialized': 0, 'private_content_read': False}
