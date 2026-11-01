"""Nonauthorizing phase scope for the private four-view coverage gate.

Step 2 is deliberately pre-network.  It may consume every locally available
privacy constraint, but it cannot claim the two accepted-chain families in
each round.  Those four occurrences remain unmodeled and travel only as an
an exact deferred set for Step 3.

Python constructor sentinels, ``_live`` bits and mutable registries are
importable and therefore are not capability boundaries. This module mints no
Step-2 prediction authority and no Step-3 residual. Even an otherwise-ready
partition stops at ``phase-scope-native-authority-required``. A future native,
non-importable one-shot boundary must issue both values atomically. Until then
prediction authorization and terminal completion remain impossible.
"""

import privacy_capture_model as capture


STEP3_ACCEPTED_CHAIN_REQUIREMENT = \
    'STEP3_ACCEPTED_CHAIN_STATE_AND_OUTPOINT_HISTORY_AUTHORITY'

STEP3_DEFERRED_FAMILIES = (
    ('context-identities',
     'context.accepted_chain_outpoint_and_external_history_linkage'),
    ('state-transition',
     'state.accepted_chain_state_and_outpoint_continuity'),
)

_PHASE_PARTITION_SCHEMA = 'kpb-private-completion-phase-partition/v1'
_COVERAGE_SUMMARY_SCHEMA = 'kpb-private-four-view-coverage-summary/v1'


def _need(condition, label):
    if not condition:
        raise ValueError(label)


def _exact(value, fields, label):
    _need(type(value) is dict and set(value) == set(fields), label)
    return value


def _expected_deferred_rows():
    return tuple({
        'round': round_number,
        'artifact_kind': 'public-projection',
        'category': category,
        'field_path': field_path,
        'proposed_resolution':
            'direct_constraint_pending_source_authority',
        'mapping_dependent': False,
        'evidence_requirement': STEP3_ACCEPTED_CHAIN_REQUIREMENT,
        'coverage_relabel_allowed': False,
    } for round_number in (1, 2)
      for category, field_path in STEP3_DEFERRED_FAMILIES)


def _row_key(row):
    return (row['round'], row['artifact_kind'], row['category'],
            row['field_path'])


def _validate_partition(partition):
    """Validate the private model hook without turning it into a receipt."""
    _exact(partition, ('schema', 'coverage_summary', 'views'),
           'phase-scope-partition-fields')
    _need(partition['schema'] == _PHASE_PARTITION_SCHEMA,
          'phase-scope-partition-schema')
    summary = _exact(
        partition['coverage_summary'],
        ('schema', 'views', 'exact_ten_typed_leaves',
         'exhaustive_lattice', 'completion_ready'),
        'phase-scope-summary-fields')
    _need(summary['schema'] == _COVERAGE_SUMMARY_SCHEMA
          and summary['exact_ten_typed_leaves'] is True
          and summary['exhaustive_lattice'] is True
          # The four deferred rows are still open.  Calling this complete is
          # exactly the Step-2/Step-3 relabel that this boundary forbids.
          and summary['completion_ready'] is False,
          'phase-scope-base-summary')
    _need(type(summary['views']) is list and len(summary['views']) == 4
          and type(partition['views']) is list
          and len(partition['views']) == 4,
          'phase-scope-four-views')

    expected_rows = _expected_deferred_rows()
    expected_by_key = {_row_key(row): row for row in expected_rows}
    _need(len(expected_by_key) == 4,
          'phase-scope-distinct-deferred-families')
    for view_index, (summary_view, phase_view) in enumerate(
            zip(summary['views'], partition['views'])):
        _exact(summary_view,
               ('view_index', 'candidate_count',
                'all_candidate_edges_covered', 'missing_artifact_count',
                'unmodeled_field_count', 'source_assumption_mask'),
               'phase-scope-summary-view-fields')
        _exact(phase_view,
               ('view_index', 'step2_open_fields',
                'deferred_step3_open_fields'),
               'phase-scope-view-fields')
        _need(summary_view['view_index'] == view_index
              and phase_view['view_index'] == view_index
              and type(summary_view['candidate_count']) is int
              and 1 <= summary_view['candidate_count'] <= 540 * 540
              and summary_view['all_candidate_edges_covered'] is False
              and summary_view['missing_artifact_count'] == 0
              and type(summary_view['unmodeled_field_count']) is int
              and summary_view['unmodeled_field_count'] >= 4
              and type(summary_view['source_assumption_mask']) is int
              and summary_view['source_assumption_mask'] >= 0,
              'phase-scope-summary-view-state')
        step2_open = phase_view['step2_open_fields']
        _need(type(step2_open) is list,
              'phase-scope-step2-open-array')
        step2_keys = set()
        for row in step2_open:
            _exact(row, ('round', 'artifact_kind', 'category', 'field_path',
                         'proposed_resolution', 'mapping_dependent',
                         'evidence_requirement',
                         'coverage_relabel_allowed'),
                   'phase-scope-step2-row-fields')
            key = _row_key(row)
            _need(key not in step2_keys and key not in expected_by_key
                  and row['coverage_relabel_allowed'] is False,
                  'phase-scope-step2-row-binding')
            step2_keys.add(key)
        deferred = phase_view['deferred_step3_open_fields']
        _need(type(deferred) is list and len(deferred) == 4,
              'phase-scope-exact-four-deferred')
        actual_by_key = {}
        for row in deferred:
            _exact(row, ('round', 'artifact_kind', 'category', 'field_path',
                         'proposed_resolution', 'mapping_dependent',
                         'evidence_requirement',
                         'coverage_relabel_allowed'),
                   'phase-scope-deferred-row-fields')
            key = _row_key(row)
            _need(key not in actual_by_key,
                  'phase-scope-duplicate-deferred-row')
            actual_by_key[key] = row
        _need(actual_by_key == expected_by_key,
              'phase-scope-deferred-row-binding')
        _need(summary_view['unmodeled_field_count'] ==
                  len(step2_open) + len(deferred),
              'phase-scope-partition-count-binding')
    return partition


def _require_step2_ready(partition):
    _need(all(view['step2_open_fields'] == []
              for view in partition['views']),
          'phase-scope-step2-still-open')
    return partition


def require_step2_private_coverage(public_rounds, artifact_rounds):
    """Validate exact phase scope, then refuse absent native authority.

    This deliberately never returns. Keeping the final refusal in the same
    function that recomputes the partition prevents a future caller from
    treating the diagnostic dictionary as prediction authorization.
    """
    _require_step2_ready(_validate_partition(
        capture._private_completion_phase_partition(
            public_rounds, artifact_rounds)))
    _need(False, 'phase-scope-native-authority-required')

