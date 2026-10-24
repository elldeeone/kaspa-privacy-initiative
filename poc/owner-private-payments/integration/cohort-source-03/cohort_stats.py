"""Pure public statistics for the frozen 16-world grouping contract.

The caller authenticates the public receipt bytes and the preseal ordering.
This module joins their visible contexts; it never opens files or imports any
wallet, scorer, proof engine or private data. A COMPLETE cohort is a completed
bounded comparison, not a privacy qualification.
"""
from fractions import Fraction


COHORT_SIZE = 16
WORLD_IDS = tuple(f'world-{index:02d}' for index in range(1, COHORT_SIZE + 1))
ALPHA = Fraction(1, 100)
EXPERIMENT = '625f57369497b198d87e57d554e1d4976d4efa47b6b8f9a8ad94e936e7275803'
STRATEGY = '26e8279d8a4f76660e63a66372d07f51596d33f1638cb83a1426184a8fbda830'
CONTRACT_SHA256 = '28a3b29edff91634e193d28ed7b4914b1216d84bf6200c210899e967870016c2'

OBSERVER_FIELDS = frozenset((
    'schema', 'experiment_sha256', 'session_sha256', 'projection_sha256',
    'strategy_sha256', 'capsule_seal_sha256', 'excluded_known_creator_count',
    'unknown_creator_target_count', 'candidate_creator_assignments',
    'candidate_partitions', 'hash_tie_break_used', 'unique_partition_from_constraints', 'scope'))
AGGREGATE_FIELDS = frozenset((
    'schema', 'experiment_sha256', 'session_sha256', 'projection_sha256',
    'sealed_bundle_sha256', 'coordinator_only', 'one_colluder', 'scope', 'interpretation'))
AMBIGUITY_FIELDS = frozenset((
    'candidate_creator_assignments', 'candidate_partitions', 'hash_tie_break_used',
    'unique_partition_from_constraints'))
COORDINATOR_FIELDS = frozenset((
    'eligible_count', 'matched_count', 'label_invariant_groups_matched'))
COLLUDER_FIELDS = frozenset((
    'eligible_count', 'matched_count', 'excluded_known_creator_count',
    'label_invariant_unknown_groups_matched', 'presealed_ambiguity'))
EVENT_FIELDS = frozenset(('status', 'candidate_failed', 'S', 'K', 'reason'))


def _fields(value, names):
    return type(value) is dict and value.keys() == names


def _integer(value, lower, upper):
    return type(value) is int and lower <= value <= upper


def _hash(value):
    return (type(value) is str and len(value) == 64
            and all(char in '0123456789abcdef' for char in value))


def _event(status, reason, K=None, S=None):
    return {'status': status, 'candidate_failed': status == 'CANDIDATE_FAIL',
            'S': S, 'K': K, 'reason': reason}


def world_event(observer, aggregate):
    """Join selected public receipts and derive one world event, never 2 groups.

    Unknown eligible *rows* may number 2..4. The primary recovered group count
    must be 0 or 2. A joined presealed unique-partition claim fails the candidate
    before testing that expected cohort shape. Invalid/unjoined public contexts
    cannot establish such a claim and remain INCOMPLETE.
    """
    incomplete = lambda reason, K=None: _event('INCOMPLETE', reason, K)
    if not (_fields(observer, OBSERVER_FIELDS) and _fields(aggregate, AGGREGATE_FIELDS)
            and _fields(aggregate['coordinator_only'], COORDINATOR_FIELDS)
            and _fields(aggregate['one_colluder'], COLLUDER_FIELDS)):
        return incomplete('invalid-public-receipt-fields')
    if not (observer['schema'] == 'kpx7-colluder-observer-seal/v1'
            and aggregate['schema'] == 'kpx7-owner-privacy-global-counts/v1'
            and observer['experiment_sha256'] == aggregate['experiment_sha256'] == EXPERIMENT
            and observer['strategy_sha256'] == STRATEGY
            and all(_hash(observer[name]) and observer[name] == aggregate[name]
                    for name in ('session_sha256', 'projection_sha256'))
            and _hash(observer['capsule_seal_sha256']) and _hash(aggregate['sealed_bundle_sha256'])
            and observer['scope'] == 'SEALED_ONE_COLLUDER_STRATEGY_NOT_ANONYMITY_QUALIFICATION'
            and aggregate['scope'] == 'FINITE_FROZEN_STRATEGIES_ONLY_NOT_AN_ANONYMITY_SCORE'
            and aggregate['interpretation'] == 'A_CORRECT_TIE_BREAK_GUESS_IS_NOT_BY_ITSELF_A_RECOVERED_LEAK'):
        return incomplete('invalid-public-context')
    colluder = aggregate['one_colluder']
    ambiguity = colluder['presealed_ambiguity']
    if not _fields(ambiguity, AMBIGUITY_FIELDS):
        return incomplete('invalid-presealed-ambiguity')
    for value in (observer, ambiguity):
        if not (_integer(value['candidate_creator_assignments'], 1, 6)
                and _integer(value['candidate_partitions'], 1, 3)
                and type(value['hash_tie_break_used']) is bool
                and type(value['unique_partition_from_constraints']) is bool):
            return incomplete('invalid-presealed-ambiguity')
    if any(observer[name] != ambiguity[name] for name in AMBIGUITY_FIELDS):
        return incomplete('presealed-ambiguity-mismatch')
    K = observer['candidate_partitions']
    # A unique constraint-derived grouping is a direct failure, independently
    # of a score and before any unexpected group/eligible-count shape.
    if K == 1 or observer['unique_partition_from_constraints']:
        return _event('CANDIDATE_FAIL', 'unique-presealed-partition', K)
    if not (K <= observer['candidate_creator_assignments']
            and observer['hash_tie_break_used'] == (observer['candidate_creator_assignments'] > 1)):
        return incomplete('invalid-presealed-ambiguity', K)
    coordinator = aggregate['coordinator_only']
    unknown = observer['unknown_creator_target_count']
    excluded = observer['excluded_known_creator_count']
    if not (_integer(unknown, 2, 4) and _integer(excluded, 2, 4) and unknown + excluded == 6
            and _integer(colluder['eligible_count'], 2, 4) and colluder['eligible_count'] == unknown
            and _integer(colluder['excluded_known_creator_count'], 2, 4)
            and colluder['excluded_known_creator_count'] == excluded
            and _integer(colluder['matched_count'], 0, unknown)
            and _integer(coordinator['eligible_count'], 6, 6)
            and _integer(coordinator['matched_count'], 0, 6)
            and _integer(coordinator['label_invariant_groups_matched'], 0, 3)):
        return incomplete('invalid-public-counts', K)
    groups = colluder['label_invariant_unknown_groups_matched']
    if not _integer(groups, 0, 2) or groups == 1:
        return incomplete('unexpected-primary-group-count', K)
    return _event('COMPLETE', 'valid-primary-event', K, int(groups == 2))


def poisson_binomial(probabilities):
    """Return exact P(X=k), k=0..n, for independent Bernoulli probabilities."""
    distribution = [Fraction(1)]
    for probability in probabilities:
        if type(probability) not in (int, Fraction) or not 0 <= probability <= 1:
            raise ValueError('exact-probability-required')
        probability = Fraction(probability)
        following = [Fraction(0)] * (len(distribution) + 1)
        for successes, mass in enumerate(distribution):
            following[successes] += mass * (1 - probability)
            following[successes + 1] += mass * probability
        distribution = following
    return tuple(distribution)


def poisson_binomial_tail(probabilities, minimum_successes):
    """Exact upper tail, including the observed number of successful worlds."""
    if type(minimum_successes) is not int:
        raise ValueError('integer-success-count-required')
    distribution = poisson_binomial(probabilities)
    return sum(distribution[max(0, minimum_successes):], Fraction(0))


def _normalized_event(value):
    if type(value) is not dict:
        return _event('INCOMPLETE', 'invalid-world-event')
    # Explicit failure is sticky even if another field or world is incomplete.
    if (value.get('candidate_failed') is True or value.get('status') == 'CANDIDATE_FAIL'
            or (type(value.get('K')) is int and value['K'] == 1)):
        K = value.get('K')
        return _event('CANDIDATE_FAIL', 'candidate-world-failed', K if type(K) is int else None)
    if not (EVENT_FIELDS <= value.keys() and type(value['reason']) is str
            and value['candidate_failed'] is False):
        return _event('INCOMPLETE', 'invalid-world-event')
    if value['status'] == 'INCOMPLETE' and value['S'] is None:
        K = value['K']
        if K is None or _integer(K, 1, 3):
            return _event('INCOMPLETE', 'incomplete-world-event', K)
    if (value['status'] == 'COMPLETE' and _integer(value['K'], 2, 3)
            and _integer(value['S'], 0, 1)):
        return _event('COMPLETE', 'valid-primary-event', value['K'], value['S'])
    return _event('INCOMPLETE', 'invalid-world-event')


def summarize(events):
    """Summarize 16 ordered events; missing slots never shrink the denominator.

    The wrapper must add the exact ordered world-01..world-16 identities.
    Other wrapper metadata is ignored and never exported. Only sixteen COMPLETE
    outcomes permit the statistic; direct failure takes precedence.
    Excess success is a separate bounded statistical flag, not qualification.
    """
    received = events if type(events) in (list, tuple) else []
    values = []
    for index, original in enumerate(received):
        value = _normalized_event(original)
        correct_identity = (index < COHORT_SIZE and type(original) is dict
                            and original.get('world_id') == WORLD_IDS[index])
        if not correct_identity and not value['candidate_failed']:
            value = _event('INCOMPLETE', 'invalid-world-identity')
        values.append(value)
    complete = sum(value['status'] == 'COMPLETE' for value in values)
    failures = sum(value['candidate_failed'] for value in values)
    missing = max(0, COHORT_SIZE - len(values))
    incomplete = sum(value['status'] == 'INCOMPLETE' for value in values) + missing
    result = {'status': 'CANDIDATE_FAIL' if failures else 'INCOMPLETE',
        'classification': 'BOUNDED_FROZEN_STRATEGY_MODEL_COMPARISON_ONLY',
        'baseline_assumptions': {'conditional_uniform_hidden_partition': True,
            'per_world_success_probability': '1/K_i', 'independent_worlds': True,
            'proven_protocol_properties': False},
        'event_unit': 'ONE_WORLD_BOTH_ELIGIBLE_HONEST_GROUPS_RECOVERED',
        'privacy_qualification': False, 'financial_acceptance': False,
        'candidate_failed': bool(failures), 'planned_worlds': COHORT_SIZE,
        'received_world_events': len(values), 'complete_worlds': complete,
        'incomplete_worlds': incomplete, 'candidate_failed_worlds': failures,
        'successes': None, 'K_values': None, 'tail': None,
        'alpha': {'numerator': ALPHA.numerator, 'denominator': ALPHA.denominator},
        'excess_success_detected': None,
        'reason': 'candidate-world-failed' if failures else 'incomplete-cohort'}
    if len(values) != COHORT_SIZE or complete != COHORT_SIZE or failures:
        return result
    successes = sum(value['S'] for value in values)
    K_values = [value['K'] for value in values]
    tail = poisson_binomial_tail((Fraction(1, K) for K in K_values), successes)
    result.update(status='COMPLETE', successes=successes, K_values=K_values,
        tail={'numerator': tail.numerator, 'denominator': tail.denominator},
        excess_success_detected=tail <= ALPHA, reason='complete-frozen-model-comparison')
    return result
