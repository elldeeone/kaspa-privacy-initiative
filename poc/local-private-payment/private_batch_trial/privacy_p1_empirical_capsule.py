"""Fixed non-authorizing reduction for the passive-P1 empirical attack.

The selected observer will eventually build the empirical plan from ten typed
sealed leaves.  That input bridge is deliberately absent until its parser
schema is frozen.  This module only collapses the standalone two-hypothesis
receipt into a bounded internal value.  It cannot mint or return a completion
authority and cannot claim exhaustive four-view coverage.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid

import privacy_p1_empirical_observer as empirical


RESULT_SCHEMA = 'kpb-p1-passive-empirical-internal-result/v1'
MAX_EDGES = 64

STATUS_UNQUALIFIED_MISSING_COVERAGE = 0
STATUS_UNQUALIFIED_NO_CANDIDATE = 1
STATUS_UNIQUE = 2
STATUS_AMBIGUOUS = 3

_STATUS = {
    'UNQUALIFIED_MISSING_WITHIN_RUN_CONSTRAINT':
        STATUS_UNQUALIFIED_MISSING_COVERAGE,
    'UNQUALIFIED_NO_STRUCTURAL_CANDIDATE':
        STATUS_UNQUALIFIED_NO_CANDIDATE,
    'DETERMINISTIC_UNIQUE_CANDIDATE': STATUS_UNIQUE,
    'DETERMINISTIC_AMBIGUOUS_CANDIDATES': STATUS_AMBIGUOUS,
}
_FIELD_STATUSES = frozenset((
    'CONSTANT_PUBLIC', 'CONSTRAINT_MODELED', 'NOT_PRESENT_IN_CAPTURE',
    'UNMODELED',
))
_CANDIDATE_FIELDS = frozenset((
    'mapping_id', 'structural_mapping', 'exact_results', 'rank_results',
    'timing_results', 'retained',
))
_EXACT_RESULT_FIELDS = frozenset((
    'join_id', 'event_id', 'field', 'mode', 'matched',
))
_RECEIPT_FIELDS = frozenset((
    'schema', 'method_sha256', 'trial_id', 'capture_sha256',
    'source_manifest_sha256', 'plan_sha256', 'status', 'field_status',
    'candidate_results', 'retained_mapping_ids',
    'gate_authorizing_without_capsule_bridge',
    'requires_consumed_producer_spool_authority', 'internal_capsule_only',
    'public_export_allowed', 'cryptographic_theorem_coverage_claim',
    'active_or_host_privacy_claim', 'receipt_sha256',
))
_RANK_RESULT_FIELDS = frozenset((
    'rank_id', 'field', 'source_id', 'p1_order', 'event_order', 'status',
    'used_for_candidate_filter',
))
_TIMING_RESULT_FIELDS = frozenset((
    'timing_id', 'field', 'metric', 'signed_deltas', 'absolute_distance',
    'status', 'used_for_candidate_filter',
))
_FIELD_RESULT_BASE = frozenset((
    'status', 'expected_observation_count', 'compared_per_candidate',
    'positive_match_count', 'mismatch_count', 'ambiguous_count',
    'comparison_modes', 'used_for_candidate_filter',
))
_EXACT_MODES = frozenset((
    'EXACT_COMMON_CLOCK', 'EXACT_LITERAL_DIGEST', 'EXACT_FIELD',
))
_COMPARISON_MODES = _EXACT_MODES | frozenset((
    'RANK_WITHIN_SOURCE', 'COMMON_CLOCK_ABSOLUTE_DISTANCE',
))


class CapsuleRefused(ValueError):
    pass


def _need(value: bool, category: str) -> None:
    if not value:
        raise CapsuleRefused(category)


def _identifier(value: object) -> bool:
    return (type(value) is str and
            re.fullmatch('[A-Za-z0-9_.:-]{1,128}', value) is not None)


def _word(value: object) -> bool:
    return (type(value) is str and
            re.fullmatch('[0-9a-f]{64}', value) is not None)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True).encode()


def _permutation(value: object) -> bool:
    return (type(value) is list and value and
            all(type(item) is int and item >= 0 for item in value) and
            sorted(value) == list(range(len(value))))


def _candidate_edges(candidate: object) -> dict:
    _need(type(candidate) is dict and set(candidate) == _CANDIDATE_FIELDS and
          _identifier(candidate['mapping_id']) and
          type(candidate['structural_mapping']) is dict and
          candidate['structural_mapping'] and
          all(_identifier(key) and _identifier(value)
              for key, value in candidate['structural_mapping'].items()) and
          type(candidate['exact_results']) is list and
          candidate['exact_results'] and
          type(candidate['rank_results']) is list and
          type(candidate['timing_results']) is list and
          type(candidate['retained']) is bool,
          'p1-empirical-capsule-candidate')
    by_edge: dict[str, list[bool]] = {}
    event_by_edge: dict[str, str] = {}
    exact_signature = []
    for row in candidate['exact_results']:
        _need(type(row) is dict and set(row) == _EXACT_RESULT_FIELDS and
              _identifier(row['join_id']) and
              _identifier(row['event_id']) and
              _identifier(row['field']) and
              row['mode'] in _EXACT_MODES and type(row['matched']) is bool,
              'p1-empirical-capsule-exact-edge')
        by_edge.setdefault(row['join_id'], []).append(row['matched'])
        if row['join_id'] in event_by_edge:
            _need(event_by_edge[row['join_id']] == row['event_id'],
                  'p1-empirical-capsule-edge-provenance')
        else:
            event_by_edge[row['join_id']] = row['event_id']
        exact_signature.append((row['join_id'], row['field'], row['mode']))
    edges = set(by_edge)
    _need(0 < len(edges) <= MAX_EDGES,
          'p1-empirical-capsule-edge-bound')
    ordered = sorted(edges)
    mask = 0
    for index, edge in enumerate(ordered):
        if all(by_edge[edge]):
            mask |= 1 << index

    rank_signature = []
    for row in candidate['rank_results']:
        _need(type(row) is dict and set(row) == _RANK_RESULT_FIELDS and
              _identifier(row['rank_id']) and
              row['field'] in empirical.RANK_FIELDS and
              _identifier(row['source_id']) and
              (row['p1_order'] is None or _permutation(row['p1_order'])) and
              (row['event_order'] is None or
               _permutation(row['event_order'])) and
              row['status'] in ('MATCH', 'MISMATCH', 'AMBIGUOUS') and
              row['used_for_candidate_filter'] is True,
              'p1-empirical-capsule-rank-result')
        expected_status = (
            'AMBIGUOUS' if row['p1_order'] is None or
            row['event_order'] is None else
            'MATCH' if row['p1_order'] == row['event_order'] else
            'MISMATCH')
        _need(row['status'] == expected_status,
              'p1-empirical-capsule-rank-result')
        rank_signature.append(
            (row['rank_id'], row['field'], row['source_id']))

    timing_signature = []
    for row in candidate['timing_results']:
        _need(type(row) is dict and set(row) == _TIMING_RESULT_FIELDS and
              _identifier(row['timing_id']) and
              row['field'] in empirical.TIME_FIELDS and
              row['metric'] == 'ABSOLUTE_PAIR_DELTA' and
              type(row['signed_deltas']) is list and
              all(type(value) is int for value in row['signed_deltas']) and
              row['status'] in (
                  'CLOSER', 'FARTHER', 'TIE', 'MISSING_COMMON_CLOCK') and
              type(row['used_for_candidate_filter']) is bool,
              'p1-empirical-capsule-timing-result')
        missing = row['status'] == 'MISSING_COMMON_CLOCK'
        _need((missing and row['absolute_distance'] is None and
               row['used_for_candidate_filter'] is False) or
              (not missing and type(row['absolute_distance']) is int and
               row['absolute_distance'] >= 0 and
               row['absolute_distance'] == sum(
                   abs(value) for value in row['signed_deltas']) and
               row['used_for_candidate_filter'] is True),
              'p1-empirical-capsule-timing-result')
        timing_signature.append((row['timing_id'], row['field'],
                                 row['metric'], len(row['signed_deltas'])))

    expected_retained = (
        all(row['matched'] for row in candidate['exact_results']) and
        all(row['status'] != 'MISMATCH'
            for row in candidate['rank_results']) and
        all(row['status'] != 'FARTHER'
            for row in candidate['timing_results']))
    _need(candidate['retained'] == expected_retained,
          'p1-empirical-capsule-candidate-retention')
    return {
        'edges': edges,
        'mask': mask,
        'events': event_by_edge,
        'exact_signature': sorted(exact_signature),
        'rank_signature': sorted(rank_signature),
        'timing_signature': sorted(timing_signature),
    }


def _field_coverage(value: object) -> bool:
    _need(type(value) is dict and
          set(value) == set(empirical.FIELD_DISPOSITIONS),
          'p1-empirical-capsule-field-catalog')
    complete = True
    numeric = (
        'expected_observation_count', 'compared_per_candidate',
        'positive_match_count', 'mismatch_count', 'ambiguous_count')
    for path, row in value.items():
        disposition = empirical.FIELD_DISPOSITIONS[path]
        status = row.get('status') if type(row) is dict else None
        expected_fields = set(_FIELD_RESULT_BASE)
        if status == 'CONSTANT_PUBLIC':
            expected_fields.add('check')
            if 'value_sha256' in disposition:
                expected_fields.add('value_sha256')
        _need(type(row) is dict and set(row) == expected_fields and
              status in _FIELD_STATUSES and
              all(type(row[name]) is int and row[name] >= 0
                  for name in numeric) and
              type(row['comparison_modes']) is list and
              len(row['comparison_modes']) ==
                  len(set(row['comparison_modes'])) and
              set(row['comparison_modes']) <= _COMPARISON_MODES and
              type(row['used_for_candidate_filter']) is bool,
              'p1-empirical-capsule-field-status')
        expected = row['expected_observation_count']
        compared = row['compared_per_candidate']
        if status == 'CONSTANT_PUBLIC':
            _need(disposition['mode'] == 'CONSTANT_PUBLIC' and
                  row['check'] == disposition['check'] and
                  all(row[name] == 0 for name in numeric) and
                  row['comparison_modes'] == [] and
                  row['used_for_candidate_filter'] is False and
                  ('value_sha256' not in disposition or
                   row['value_sha256'] == disposition['value_sha256']),
                  'p1-empirical-capsule-field-status')
        elif status == 'NOT_PRESENT_IN_CAPTURE':
            _need(expected == compared == 0 and
                  row['comparison_modes'] == [] and
                  row['used_for_candidate_filter'] is False,
                  'p1-empirical-capsule-field-status')
        elif status == 'CONSTRAINT_MODELED':
            _need(expected > 0 and compared == expected and
                  row['comparison_modes'] and
                  row['used_for_candidate_filter'] is True,
                  'p1-empirical-capsule-field-status')
        else:
            _need(status == 'UNMODELED' and expected > 0 and
                  compared < expected,
                  'p1-empirical-capsule-field-status')
            complete = False
    return complete


def reduce_two_hypothesis_receipt(receipt: object) -> dict:
    """Return a fixed internal result; never a gate or parent authority."""
    _need(type(receipt) is dict and set(receipt) == _RECEIPT_FIELDS and
          receipt.get('schema') == empirical.WITHIN_RUN_RECEIPT_SCHEMA and
          receipt.get('method_sha256') == empirical.METHOD_ID and
          _word(receipt.get('capture_sha256')) and
          _word(receipt.get('source_manifest_sha256')) and
          _word(receipt.get('plan_sha256')) and
          _word(receipt.get('receipt_sha256')) and
          receipt.get('status') in _STATUS and
          receipt.get('gate_authorizing_without_capsule_bridge') is False and
          receipt.get('requires_consumed_producer_spool_authority') is True and
          receipt.get('internal_capsule_only') is True and
          receipt.get('public_export_allowed') is False and
          receipt.get('cryptographic_theorem_coverage_claim') is False and
          receipt.get('active_or_host_privacy_claim') is False and
          type(receipt.get('field_status')) is dict and
          receipt['field_status'] and
          type(receipt.get('candidate_results')) is list and
          len(receipt['candidate_results']) == 2 and
          type(receipt.get('retained_mapping_ids')) is list,
          'p1-empirical-capsule-receipt')
    try:
        trial_id = str(uuid.UUID(receipt['trial_id']))
    except (ValueError, TypeError, AttributeError):
        raise CapsuleRefused('p1-empirical-capsule-receipt') from None
    _need(trial_id == receipt['trial_id'],
          'p1-empirical-capsule-receipt')

    candidates = receipt['candidate_results']
    mapping_ids = [candidate.get('mapping_id')
                   if type(candidate) is dict else None
                   for candidate in candidates]
    _need(all(_identifier(value) for value in mapping_ids) and
          len(set(mapping_ids)) == 2,
          'p1-empirical-capsule-hypotheses')
    mappings = [candidate['structural_mapping']
                for candidate in candidates]
    _need(set(mappings[0]) == set(mappings[1]) and
          sorted(mappings[0].values()) == sorted(mappings[1].values()) and
          mappings[0] != mappings[1],
          'p1-empirical-capsule-hypotheses')
    retained = [candidate.get('retained') is True
                if type(candidate) is dict else False
                for candidate in candidates]
    _need(receipt['retained_mapping_ids'] == [
              mapping_id for mapping_id, keep in zip(mapping_ids, retained)
              if keep],
          'p1-empirical-capsule-retained-set')

    candidate_rows = [_candidate_edges(candidate)
                      for candidate in candidates]
    _need(candidate_rows[0]['edges'] == candidate_rows[1]['edges'],
          'p1-empirical-capsule-candidate-edge-set')
    _need(candidate_rows[0]['exact_signature'] ==
              candidate_rows[1]['exact_signature'] and
          candidate_rows[0]['rank_signature'] ==
              candidate_rows[1]['rank_signature'] and
          candidate_rows[0]['timing_signature'] ==
              candidate_rows[1]['timing_signature'],
          'p1-empirical-capsule-candidate-asymmetry')
    _need(any(candidate_rows[0]['events'][edge] !=
              candidate_rows[1]['events'][edge]
              for edge in candidate_rows[0]['edges']),
          'p1-empirical-capsule-edge-provenance')
    by_timing = [
        {row['timing_id']: row for row in candidate['timing_results']}
        for candidate in candidates]
    for timing_id in by_timing[0]:
        statuses = {by_timing[index][timing_id]['status']
                    for index in (0, 1)}
        _need(statuses in ({'TIE'}, {'MISSING_COMMON_CLOCK'},
                           {'CLOSER', 'FARTHER'}),
              'p1-empirical-capsule-timing-asymmetry')

    field_coverage = _field_coverage(receipt['field_status'])

    status = _STATUS[receipt['status']]
    _need((status == STATUS_UNQUALIFIED_MISSING_COVERAGE) ==
          (not field_coverage) and
          (status != STATUS_UNQUALIFIED_NO_CANDIDATE or not any(retained)) and
          (status != STATUS_UNIQUE or sum(retained) == 1) and
          (status != STATUS_AMBIGUOUS or retained == [True, True]),
          'p1-empirical-capsule-status-consistency')
    selected = dict(receipt)
    receipt_sha256 = selected.pop('receipt_sha256')
    _need(hashlib.sha256(_canonical(selected)).hexdigest() == receipt_sha256,
          'p1-empirical-capsule-receipt-digest')

    # The two-hypothesis attack cannot close cryptographic/source-assumption
    # categories or prove coverage of the independently derived four views.
    # Those booleans are intentionally constants, not caller inputs.
    return {
        'schema': RESULT_SCHEMA,
        'status': status,
        'hypothesis_ids': [0, 1],
        'retained_hypotheses': retained,
        'edge_count': len(candidate_rows[0]['edges']),
        'hypothesis_edge_match_masks': [
            row['mask'] for row in candidate_rows],
        'within_run_field_coverage_complete': field_coverage,
        'candidate_edge_coverage_complete': True,
        'zero_unmodeled_categories': False,
        'exhaustive_four_view_bridge_completed': False,
        'gate_authorizing': False,
    }
