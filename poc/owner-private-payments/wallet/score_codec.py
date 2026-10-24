"""Frozen count-only experiment encodings; no wallet authority or curve code."""
import itertools

from paths import digest, fields, hx, need
from support import MIN_NOTE, MAX_VALUE

EXPERIMENT = '625f57369497b198d87e57d554e1d4976d4efa47b6b8f9a8ad94e936e7275803'
CAPSULE_TAG = b'KPX7PC01'
COUNT_TAG = b'KPX7CT01'
CAPSULE_BYTES = 176
COUNT_BYTES = 142


def guesses(value):
    need(type(value) is list and len(value) == 6
         and all(type(v) is int and 0 <= v < 3 for v in value)
         and all(value.count(i) == 2 for i in range(3)), 'complete-two-per-creator-guesses')
    return value


def prediction(value, session, projection):
    fields(value, ('schema', 'experiment_sha256', 'session_sha256', 'projection_sha256',
                   'strategy_sha256', 'guesses_creator_index'), 'sealed-public-prediction-fields')
    need(value['schema'] == 'kpx7-public-creator-prediction/v1'
         and value['experiment_sha256'] == EXPERIMENT and value['session_sha256'] == session
         and value['projection_sha256'] == projection, 'fixed-experiment-prediction-context')
    hx(value['strategy_sha256'], 32)
    return guesses(value['guesses_creator_index'])


def capsule(session, projection, strategy, salt, colluder, eligible, proposed):
    need(type(salt) is bytes and len(salt) == 32 and salt != bytes(32), 'private-fresh-capsule-salt')
    need(type(colluder) is int and 0 <= colluder < 3
         and type(eligible) is list and len(eligible) == 6
         and all(type(v) is bool for v in eligible) and 2 <= sum(eligible) <= 4, 'known-creator-exclusion')
    guesses(proposed)
    need(all(not eligible[i] for i in range(6) if proposed[i] == colluder),
         'exclude-colluder-own-known-creator-facts')
    mask = sum(int(value) << i for i, value in enumerate(eligible))
    raw = (CAPSULE_TAG + hx(EXPERIMENT, 32) + hx(session, 32) + hx(projection, 32)
           + hx(strategy, 32) + salt + bytes([colluder, mask, *proposed]))
    need(len(raw) == CAPSULE_BYTES, 'fixed-private-capsule-width')
    return raw


def parse_capsule(raw, session, projection, strategy):
    need(type(raw) is bytes and len(raw) == CAPSULE_BYTES and raw[:8] == CAPSULE_TAG
         and raw[8:40] == hx(EXPERIMENT, 32) and raw[40:72] == hx(session, 32)
         and raw[72:104] == hx(projection, 32) and raw[104:136] == hx(strategy, 32),
         'private-capsule-context-and-width')
    colluder, mask, proposed = raw[168], raw[169], list(raw[170:176])
    eligible = [bool(mask & (1 << i)) for i in range(6)]
    need(mask < 64 and capsule(session, projection, strategy, raw[136:168],
         colluder, eligible, proposed) == raw, 'canonical-private-capsule')
    return colluder, eligible, proposed


def bundle(value, session, projection, predictions_sha, observer_sha):
    fields(value, ('schema', 'experiment_sha256', 'session_sha256', 'projection_sha256',
        'coordinator_predictions_sha256', 'colluder_observer_receipt_sha256',
        'colluder_capsule_seal_sha256'), 'sealed-two-view-bundle-fields')
    need(value['schema'] == 'kpx7-owner-privacy-prediction-bundle/v1'
         and value['experiment_sha256'] == EXPERIMENT and value['session_sha256'] == session
         and value['projection_sha256'] == projection
         and value['coordinator_predictions_sha256'] == predictions_sha
         and value['colluder_observer_receipt_sha256'] == observer_sha,
         'one-common-presealed-two-view-bundle')
    hx(value['colluder_capsule_seal_sha256'], 32)


def observer_receipt(value, session, projection, strategy):
    fields(value, ('schema', 'experiment_sha256', 'session_sha256', 'projection_sha256',
        'strategy_sha256', 'capsule_seal_sha256', 'excluded_known_creator_count',
        'unknown_creator_target_count', 'candidate_creator_assignments', 'candidate_partitions',
        'hash_tie_break_used', 'unique_partition_from_constraints', 'scope'), 'fixed-colluder-public-seal-fields')
    need(value['schema'] == 'kpx7-colluder-observer-seal/v1'
         and value['experiment_sha256'] == EXPERIMENT and value['session_sha256'] == session
         and value['projection_sha256'] == projection and value['strategy_sha256'] == strategy
         and type(value['excluded_known_creator_count']) is int and 2 <= value['excluded_known_creator_count'] <= 4
         and type(value['unknown_creator_target_count']) is int and 2 <= value['unknown_creator_target_count'] <= 4
         and value['excluded_known_creator_count'] + value['unknown_creator_target_count'] == 6
         and type(value['candidate_creator_assignments']) is int and 1 <= value['candidate_creator_assignments'] <= 6
         and type(value['candidate_partitions']) is int and 1 <= value['candidate_partitions'] <= 3
         and value['candidate_partitions'] <= value['candidate_creator_assignments']
         and type(value['hash_tie_break_used']) is bool
         and value['hash_tie_break_used'] == (value['candidate_creator_assignments'] > 1)
         and type(value['unique_partition_from_constraints']) is bool
         and value['unique_partition_from_constraints'] == (value['candidate_partitions'] == 1)
         and value['scope'] == 'SEALED_ONE_COLLUDER_STRATEGY_NOT_ANONYMITY_QUALIFICATION',
         'completed-permitted-colluder-view')
    hx(value['capsule_seal_sha256'], 32)


def infer(own_positions, known_values, known_creators, available, colluder, tie_seed):
    """Frozen bounded strategy: creator partition constraints from known values.

    Private issuance plus honest selected-worker behavior can label incoming
    receipt indices. That is not cryptographic sender authentication. This is
    one strategy, not an exhaustive attack; its whole view stays owner-local.
    """
    need(type(own_positions) is tuple and len(own_positions) == len(set(own_positions)) == 2
         and all(type(i) is int and 0 <= i < 6 for i in own_positions), 'own-two-contributed-positions')
    need(type(colluder) is int and 0 <= colluder < 3 and type(available) is list
         and len(available) == 3 and all(type(v) is int and 2 * MIN_NOTE <= v <= MAX_VALUE
         for v in available), 'public-admission-minus-fee-priors')
    need(type(known_values) is dict and all(type(i) is int and 0 <= i < 6
         and type(v) is int and MIN_NOTE <= v <= MAX_VALUE for i, v in known_values.items()),
         'legitimate-known-note-value-observations')
    need(type(tie_seed) is bytes and len(tie_seed) == 32, 'fixed-public-inference-tie-seed')
    need(type(known_creators) is dict and all(type(i) is int and 0 <= i < 6
         and type(v) is int and 0 <= v < 3 for i, v in known_creators.items())
         and all(known_creators.get(i) == colluder for i in own_positions), 'legitimately-known-creator-facts')
    honest = [i for i in range(3) if i != colluder]
    unknown = [i for i in range(6) if i not in own_positions]
    candidates = []
    for pair in itertools.combinations(unknown, 2):
        proposed = [colluder] * 6
        for i in unknown:
            proposed[i] = honest[0] if i in pair else honest[1]
        feasible = all(proposed[i] == creator for i, creator in known_creators.items())
        for owner in honest:
            positions = [i for i in unknown if proposed[i] == owner]
            total_known = sum(known_values[i] for i in positions if i in known_values)
            missing = sum(i not in known_values for i in positions)
            feasible &= missing * MIN_NOTE <= available[owner] - total_known <= missing * MAX_VALUE
        if feasible:
            candidates.append(proposed)
    need(candidates, 'INCOMPLETE-no-realistic-inference-candidate')
    # Record ambiguity BEFORE truth. A lucky hash-tie-break prediction is not
    # itself evidence that the public/legitimate view uniquely leaked a group.
    partitions = {tuple(sorted(tuple(i for i in unknown if row[i] == owner) for owner in honest))
                  for row in candidates}
    best = min(candidates, key=lambda row: digest(b'KPX7 bounded creator inference\0' + tie_seed + bytes(row)))
    return best, len(candidates), len(partitions)


def counts(session, projection, sealed_bundle, coordinator_eligible, coordinator_matches,
           colluder_eligible, colluder_matches, coordinator_groups, colluder_groups):
    need(type(coordinator_eligible) is int and coordinator_eligible == 2
         and type(coordinator_matches) is int and 0 <= coordinator_matches <= 2
         and type(colluder_eligible) is int and 0 <= colluder_eligible <= 2
         and type(colluder_matches) is int and 0 <= colluder_matches <= colluder_eligible,
         'bounded-private-counts')
    need(type(coordinator_groups) is int and 0 <= coordinator_groups <= 1
         and type(colluder_groups) is int and 0 <= colluder_groups <= min(1, colluder_eligible),
         'bounded-label-invariant-group-counts')
    return (COUNT_TAG + hx(EXPERIMENT, 32) + hx(session, 32) + hx(projection, 32)
            + hx(sealed_bundle, 32) + bytes([coordinator_eligible, coordinator_matches,
                                          colluder_eligible, colluder_matches, coordinator_groups, colluder_groups]))


def aggregate(records, session, projection, sealed_bundle):
    need(type(records) is list and len(records) == 3, 'three-private-count-leaves')
    values = []
    for raw in records:
        need(type(raw) is bytes and len(raw) == COUNT_BYTES and raw[:8] == COUNT_TAG
             and raw[8:40] == hx(EXPERIMENT, 32) and raw[40:72] == hx(session, 32)
             and raw[72:104] == hx(projection, 32) and raw[104:136] == hx(sealed_bundle, 32),
             'count-leaf-common-sealed-context')
        value = tuple(raw[136:142])
        need(counts(session, projection, sealed_bundle, *value) == raw, 'canonical-count-leaf')
        values.append(value)
    need(sum(row[2] == 0 for row in values) == 1 and 2 <= sum(row[2] for row in values) <= 4,
         'actual-one-colluder-view-required')
    return {'schema': 'kpx7-owner-privacy-global-counts/v1', 'experiment_sha256': EXPERIMENT,
        'session_sha256': session, 'projection_sha256': projection, 'sealed_bundle_sha256': sealed_bundle,
        'coordinator_only': {'eligible_count': 6, 'matched_count': sum(v[1] for v in values),
                             'label_invariant_groups_matched': sum(v[4] for v in values)},
        'one_colluder': {'eligible_count': sum(v[2] for v in values), 'matched_count': sum(v[3] for v in values),
                         'excluded_known_creator_count': 6 - sum(v[2] for v in values),
                         'label_invariant_unknown_groups_matched': sum(v[5] for v in values)},
        'scope': 'FINITE_FROZEN_STRATEGIES_ONLY_NOT_AN_ANONYMITY_SCORE'}
