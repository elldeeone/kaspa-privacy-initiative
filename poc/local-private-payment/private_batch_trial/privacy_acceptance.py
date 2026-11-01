#!/usr/bin/env python3
"""Frozen public acceptance gate for the four-view private-batch study.

This module consumes only count-only public aggregate records.  It never sees
wallet truth, prediction capsules, assignments, masks, keys, Originals, or raw
observer captures.  Capture completeness and the observer implementation are
bound by the enclosing Root-frozen selection; this gate refuses incomplete or
unmodelled views instead of treating missing evidence as privacy.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

import privacy_source_closure as source_closure


VIEWS = ('public', 'dispatcher', 'corrupt-server-plus-wallet', 'union')
ROUNDS = (1, 2)
MIN_INPUT_ASSIGNMENTS = 2
MIN_OUTPUT_ASSIGNMENTS = 3
MIN_OUTPUT_PAIR_PARTITIONS = 3
MIN_JOINT_CANDIDATES = 6
MIN_NF_PAIR_RELATIONS = 6
MIN_PAIR_CANDIDATES_PER_HONEST_NF = 6
MIN_HONEST_NFS_WITH_MULTIPLE_PAIR_CANDIDATES = 2
OWNER_COMPARISON_BASE = Path(
    '/var/tmp/kpi-private-batch-bootstrap-20261028/privacy-comparisons')
TERMINAL_SCOPE = 'PRIVATE_BATCH_TERMINAL_ONLY_EXIT_LINKABILITY_UNMEASURED'
STEP3_TERMINAL_GATE = (
    'REQUIRED_SEPARATE_EXIT_LINKABILITY_GATE_BEFORE_STEP3'
)

PUBLIC_CATEGORIES = (
    'amounts', 'commitments', 'fees', 'nullifiers', 'operation-shape',
    'proofs', 'public-bytes', 'rejected-or-orphaned-candidates',
    'reorg-history', 'terminal-grouping',
)
DISPATCHER_CATEGORIES = tuple(sorted(set(PUBLIC_CATEGORIES) | {
    'cohort-membership', 'connection-order', 'filenames', 'lengths',
    'operation-timing', 'outbound-routes', 'public-receipts', 'retry-history',
    'role-identities', 'upload-order',
}))
CORRUPT_CATEGORIES = tuple(sorted(set(PUBLIC_CATEGORIES) | {
    'authenticated-transcript', 'colluder-decrypted-receipts',
    'colluder-inputs-and-outputs', 'colluder-invoices', 'colluder-original',
    'retry-history', 'server-local-shares', 'server-mac-state',
    'server-randomness',
}))
REQUIRED_CATEGORIES = {
    'public': PUBLIC_CATEGORIES,
    'dispatcher': DISPATCHER_CATEGORIES,
    'corrupt-server-plus-wallet': CORRUPT_CATEGORIES,
    'union': tuple(sorted(set(DISPATCHER_CATEGORIES) | set(CORRUPT_CATEGORIES))),
}

BUNDLE_FIELDS = (
    'schema', 'classification', 'comparison_selection_sha256',
    'run_selection_sha256', 'diagnostic_selection_sha256',
    'diagnostic_run_selection_sha256', 'binding',
    'method_sha256', 'measurement_freeze_sha256', 'workload_sha256',
    'observer_source_sha256', 'capture_source_sha256',
    'coverage_policy_sha256', 'bundle_producer_source_sha256',
    'owner_comparison_source_sha256',
    'owner_comparison_launcher_source_sha256',
    'capture_producer_source_sha256',
    'capture_producer_build_sha256',
    'capture_producer_launcher_source_sha256',
    'capture_launcher_source_sha256', 'source_closure_sha256',
    'runtime_identity_sha256', 'python_runtime_sha256',
    'namespace_tool_sha256', 'root_guard_helper_sha256',
    'host_runtime_trust_boundary', 'terminal_scope',
    'step3_terminal_gate',
    'capture_identity', 'capture_receipt_sha256',
    'capture_manifest_seal_sha256', 'observation_receipt_sha256',
    'construction_classification_receipt_sha256',
    'capture_producer_receipt_sha256', 'capture_launch_receipt_sha256',
    'financial_rounds',
    'observation_launch_sha256', 'barrier_sha256',
    'score_receipt_sha256', 'score_launch_sha256',
    'aggregate_result_sha256', 'aggregate_launch_sha256',
    'coverage_categories', 'lattice_attestation', 'views',
)
BINDING_FIELDS = (
    'method_sha256', 'selection_sha256', 'trial_id', 'phase', 'attempt_id',
)
VIEW_FIELDS = (
    'schema', 'binding', 'view', 'capsule_seal_sha256', 'rounds', 'coverage',
    'category_coverage', 'workload',
    'combined_terminal_status', 'scope', 'posterior_probability_claim',
    'private_truth_or_per_owner_scores_exported',
)
WORKLOAD_FIELDS = (
    'full_workload_candidates', 'truth_vector_retained',
    'honest_graph_alternative_retained', 'correct_unique_full_vectors',
    'wrong_unique_full_vectors', 'eligible_inputs', 'eligible_outputs',
    'correct_unique_inputs', 'wrong_unique_inputs',
    'correct_unique_outputs', 'wrong_unique_outputs',
    'correct_unique_pair_links', 'wrong_unique_pair_links',
    'honest_nf_pair_candidate_floor_met',
    'cross_round_constraints_modeled', 'terminal_constraints_modeled',
    'candidate_set_commitment_sha256',
)
LATTICE_FIELDS = (
    'exact_union_artifact_set', 'exact_union_constraints',
    'candidate_subset_lattice_verified',
    'full_workload_subset_lattice_verified',
)
OWNER_COMPARISON_FIELDS = (
    'schema', 'comparison_selection_sha256',
    'baseline_run_selection_sha256', 'candidate_run_selection_sha256',
    'owner_comparison_source_sha256',
    'owner_comparison_launcher_source_sha256',
    'source_closure_sha256', 'runtime_identity_sha256',
    'step3_terminal_gate', 'baseline_capsule_seal_sha256',
    'candidate_capsule_seal_sha256',
    'baseline_score_bundle_seal_sha256',
    'candidate_score_bundle_seal_sha256', 'dimensions',
    'honest_owner_count', 'all_honest_owner_counts_nonregressed',
    'honest_owners_with_strict_gain', 'private_owner_counts_exported',
)
OWNER_COMPARISON_DIMENSIONS = (
    'input-truth-candidates', 'output-truth-candidates',
    'joint-truth-candidates', 'full-workload-truth-candidates',
)
OWNER_COMPARISON_LAUNCH_FIELDS = (
    'schema', 'comparison_selection_sha256',
    'baseline_run_selection_sha256', 'candidate_run_selection_sha256',
    'owner_comparison_source_sha256',
    'owner_comparison_launcher_source_sha256',
    'source_closure_sha256', 'runtime_identity_sha256',
    'python_runtime_sha256', 'namespace_tool_sha256',
    'root_guard_helper_sha256', 'host_runtime_trust_boundary',
    'step3_terminal_gate',
    'baseline_capsule_seal_sha256', 'candidate_capsule_seal_sha256',
    'baseline_score_bundle_seal_sha256',
    'candidate_score_bundle_seal_sha256', 'public_result',
    'public_result_sha256', 'private_score_bundle_count',
    'network_enabled', 'private_score_bodies_exported',
)
ROUND_FIELDS = (
    'round', 'input_owner_assignments', 'output_creator_assignments',
    'output_pair_partitions', 'joint_candidates', 'truth_retained',
    'nf_to_created_pair_relations', 'nf_pair_candidate_count_histogram',
    'honest_input_swap_retained', 'honest_graph_alternative_retained',
    'honest_nf_pair_candidate_floor_met',
    'forbidden_exports', 'strict_H1_status',
    'eligible_inputs', 'eligible_outputs', 'correct_unique_inputs',
    'wrong_unique_inputs', 'correct_unique_outputs', 'wrong_unique_outputs',
    'correct_unique_pair_links', 'wrong_unique_pair_links',
)
COUNT_FIELDS = (
    'input_owner_assignments', 'output_creator_assignments',
    'output_pair_partitions', 'joint_candidates',
    'nf_to_created_pair_relations',
)
UNIQUE_FIELDS = (
    'correct_unique_inputs', 'wrong_unique_inputs', 'correct_unique_outputs',
    'wrong_unique_outputs', 'correct_unique_pair_links',
    'wrong_unique_pair_links',
)


def need(condition, category):
    if not condition:
        raise ValueError('privacy-acceptance-' + category)


def fields(value, names):
    need(type(value) is dict and set(value) == set(names), 'exact-fields')


def word(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None,
         'canonical-word')
    return value


def validate_binding(value):
    fields(value, BINDING_FIELDS)
    word(value['method_sha256']); word(value['selection_sha256'])
    need(type(value['trial_id']) is str
         and str(uuid.UUID(value['trial_id'])) == value['trial_id']
         and value['phase'] == 'private-batch-privacy'
         and type(value['attempt_id']) is str
         and re.fullmatch('[A-Za-z0-9_-]{1,128}', value['attempt_id']),
         'exact-binding')
    return value


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode()


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate-json-field')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(
            ValueError('privacy-acceptance-nonfinite-number')))
    need(encoded(value) == raw, 'canonical-json')
    return value


def nonnegative(value, category):
    need(type(value) is int and value >= 0, category)
    return value


def histogram(value):
    need(type(value) is dict and value, 'pair-histogram')
    total = 0
    multiple = 0
    for key, count in value.items():
        need(type(key) is str and re.fullmatch('0|[1-9][0-9]*', key),
             'pair-histogram-key')
        nonnegative(count, 'pair-histogram-count')
        total += count
        if int(key) >= MIN_PAIR_CANDIDATES_PER_HONEST_NF:
            multiple += count
    need(total == 3, 'pair-histogram-three-inputs')
    return multiple


def validate_round(row, round_number):
    fields(row, ROUND_FIELDS)
    need(type(row['round']) is int and row['round'] == round_number,
         'fixed-round-order')
    for name in COUNT_FIELDS + ('forbidden_exports', 'eligible_inputs',
            'eligible_outputs') + UNIQUE_FIELDS:
        nonnegative(row[name], 'nonnegative-' + name)
    need(type(row['truth_retained']) is bool
         and type(row['honest_input_swap_retained']) is bool
         and type(row['honest_graph_alternative_retained']) is bool
         and type(row['honest_nf_pair_candidate_floor_met']) is bool,
         'boolean-membership-results')
    need(row['input_owner_assignments'] <= 6
         and row['output_creator_assignments'] <= 90
         and row['output_pair_partitions'] <= 15
         and row['output_pair_partitions'] <=
            row['output_creator_assignments']
         and row['joint_candidates'] <=
            row['input_owner_assignments'] *
            row['output_creator_assignments']
         and row['nf_to_created_pair_relations'] <=
            row['joint_candidates']
         and row['eligible_inputs'] <= 3
         and row['eligible_outputs'] <= 6,
         'fixed-three-by-six-universe-bounds')
    need(row['correct_unique_inputs'] + row['wrong_unique_inputs'] <=
            row['eligible_inputs']
         and row['correct_unique_outputs'] + row['wrong_unique_outputs'] <=
            row['eligible_outputs']
         and row['correct_unique_pair_links'] +
            row['wrong_unique_pair_links'] <= row['eligible_inputs'],
         'unique-predictions-bounded-by-eligibility')
    need(not row['truth_retained'] or
         not any(row[name] for name in
                 ('wrong_unique_inputs', 'wrong_unique_outputs',
                  'wrong_unique_pair_links')),
         'retained-truth-forbids-wrong-unique-prediction')
    need(not row['honest_graph_alternative_retained'] or
         row['honest_input_swap_retained'],
         'graph-alternative-implies-input-swap')
    need(row['strict_H1_status'] in
         ('PASS_BOUNDED_DIRECT_CHECK', 'FAIL', 'UNQUALIFIED'),
         'fixed-H1-status')
    multiple = histogram(row['nf_pair_candidate_count_histogram'])
    need(not row['truth_retained'] or
         row['nf_pair_candidate_count_histogram'].get('0', 0) == 0,
         'retained-truth-has-created-pair-candidate')
    return {**row, '_inputs_with_multiple_pair_candidates': multiple}


def derived_round_status(row, model_complete):
    """Recompute the worker status; never trust a supplied PASS label."""
    if (not row['truth_retained'] or not row['honest_input_swap_retained']
            or not row['honest_graph_alternative_retained']
            or not row['honest_nf_pair_candidate_floor_met']
            or row['forbidden_exports']):
        return 'FAIL'
    return ('PASS_BOUNDED_DIRECT_CHECK' if model_complete
            else 'UNQUALIFIED')


def validate_category_coverage(value, expected_view):
    required = REQUIRED_CATEGORIES[expected_view]
    need(type(value) is dict and set(value) == set(required),
         'category-coverage-set-' + expected_view)
    result = {}
    for category in required:
        row = value[category]
        fields(row, ('modeled_artifacts', 'unmodeled_artifacts',
                     'missing_artifacts', 'constraint_modeled_fields',
                     'source_assumption_covered_fields',
                     'unmodeled_fields'))
        for name in row:
            nonnegative(row[name], 'category-' + name)
        need(row['modeled_artifacts'] > 0
             and row['constraint_modeled_fields'] +
                row['source_assumption_covered_fields'] +
                row['unmodeled_fields'] > 0
             and ((row['unmodeled_fields'] > 0) ==
                  (row['unmodeled_artifacts'] > 0)),
             'category-modeled-' + category)
        result[category] = row
    return result


def validate_workload(value):
    fields(value, WORKLOAD_FIELDS)
    nonnegative(value['full_workload_candidates'],
                'full-workload-candidates')
    need(value['full_workload_candidates'] <= 291600,
         'full-workload-universe-bound')
    for name in ('correct_unique_full_vectors',
                 'wrong_unique_full_vectors'):
        need(type(value[name]) is int and 0 <= value[name] <= 1,
             name)
    for name in ('eligible_inputs', 'eligible_outputs') + UNIQUE_FIELDS:
        nonnegative(value[name], 'workload-' + name)
    need(value['eligible_inputs'] <= 6
         and value['eligible_outputs'] <= 12
         and value['correct_unique_inputs'] +
            value['wrong_unique_inputs'] <= value['eligible_inputs']
         and value['correct_unique_outputs'] +
            value['wrong_unique_outputs'] <= value['eligible_outputs']
         and value['correct_unique_pair_links'] +
            value['wrong_unique_pair_links'] <= value['eligible_inputs'],
         'workload-unique-predictions-bounded-by-eligibility')
    for name in ('truth_vector_retained',
                 'honest_graph_alternative_retained',
                 'honest_nf_pair_candidate_floor_met',
                 'cross_round_constraints_modeled',
                 'terminal_constraints_modeled'):
        need(type(value[name]) is bool, 'workload-boolean-' + name)
    need(not value['truth_vector_retained'] or (
         value['wrong_unique_full_vectors'] == 0
         and value['wrong_unique_inputs'] == 0
         and value['wrong_unique_outputs'] == 0
         and value['wrong_unique_pair_links'] == 0),
         'workload-retained-truth-forbids-wrong-unique')
    word(value['candidate_set_commitment_sha256'])
    return value


def validate_view(value, expected_view):
    fields(value, VIEW_FIELDS)
    need(value['schema'] == 'kpb-public-direct-linkage-counts/v2'
         and value['view'] == expected_view, 'view-schema-and-order')
    word(value['capsule_seal_sha256'])
    validate_binding(value['binding'])
    need(type(value['rounds']) is list and len(value['rounds']) == 2,
         'two-rounds')
    rounds = [validate_round(row, number)
              for row, number in zip(value['rounds'], ROUNDS)]
    fields(value['coverage'],
           ('modeled_artifacts', 'unmodeled_artifacts', 'missing_artifacts',
            'terminal_modeled'))
    for name in ('modeled_artifacts', 'unmodeled_artifacts',
                 'missing_artifacts'):
        nonnegative(value['coverage'][name], 'coverage-' + name)
    need(type(value['coverage']['terminal_modeled']) is bool,
         'coverage-terminal-boolean')
    categories = validate_category_coverage(value['category_coverage'],
                                            expected_view)
    workload = validate_workload(value['workload'])
    model_complete = (value['coverage']['missing_artifacts'] == 0
                      and value['coverage']['unmodeled_artifacts'] == 0)
    need(all(row['strict_H1_status'] ==
             derived_round_status(row, model_complete)
             for row in rounds), 'round-status-derived-from-facts')
    need(value['combined_terminal_status'] in
         ('PASS_BOUNDED_DIRECT_CHECK', 'FAIL', 'UNQUALIFIED'),
         'combined-status')
    expected_status = (
        'UNQUALIFIED' if (value['coverage']['terminal_modeled'] is False
            or workload['cross_round_constraints_modeled'] is False
            or workload['terminal_constraints_modeled'] is False) else
        'FAIL' if (any(row['strict_H1_status'] == 'FAIL' for row in rounds)
            or not workload['truth_vector_retained']
            or not workload['honest_graph_alternative_retained']
            or not workload['honest_nf_pair_candidate_floor_met']
            or any(workload[name] for name in UNIQUE_FIELDS)) else
        'PASS_BOUNDED_DIRECT_CHECK'
            if all(row['strict_H1_status'] == 'PASS_BOUNDED_DIRECT_CHECK'
                   for row in rounds) else
        'UNQUALIFIED'
    )
    need(value['combined_terminal_status'] == expected_status,
         'combined-status-matches-rounds-and-terminal')
    need(value['scope'] ==
         'FINITE_DIRECT_CONSTRAINTS_NOT_CRYPTOGRAPHIC_OR_GENERAL_ANONYMITY'
         and value['posterior_probability_claim'] is False
         and value['private_truth_or_per_owner_scores_exported'] is False,
         'bounded-public-result')
    return {**value, 'rounds': rounds, 'category_coverage': categories,
            'workload': workload}


def validate_bundle(bundle, classification):
    fields(bundle, BUNDLE_FIELDS)
    need(bundle['schema'] == 'kpb-privacy-all-view-bundle/v2'
         and bundle['classification'] == classification
         and bundle['terminal_scope'] == TERMINAL_SCOPE
         and bundle['step3_terminal_gate'] == STEP3_TERMINAL_GATE,
         'bundle-schema-classification')
    for name in (
            'comparison_selection_sha256', 'run_selection_sha256',
            'diagnostic_selection_sha256',
            'diagnostic_run_selection_sha256', 'method_sha256',
            'measurement_freeze_sha256', 'workload_sha256',
            'observer_source_sha256', 'capture_source_sha256',
            'coverage_policy_sha256', 'bundle_producer_source_sha256',
            'owner_comparison_source_sha256',
            'owner_comparison_launcher_source_sha256',
            'capture_producer_source_sha256',
            'capture_producer_build_sha256',
            'capture_producer_launcher_source_sha256',
            'capture_launcher_source_sha256',
            'runtime_identity_sha256', 'python_runtime_sha256',
            'namespace_tool_sha256', 'root_guard_helper_sha256',
            'capture_receipt_sha256', 'capture_manifest_seal_sha256',
            'construction_classification_receipt_sha256',
            'capture_producer_receipt_sha256',
            'capture_launch_receipt_sha256',
            'observation_receipt_sha256', 'observation_launch_sha256',
            'barrier_sha256', 'aggregate_result_sha256',
            'aggregate_launch_sha256'):
        word(bundle[name])
    need(bundle['source_closure_sha256'] ==
         source_closure.all_digests(), 'executing-transitive-source-closures')
    runtime = source_closure.runtime_identity()
    need(bundle['runtime_identity_sha256'] ==
            source_closure.runtime_digest()
         and bundle['python_runtime_sha256'] ==
            runtime['python_runtime_sha256']
         and bundle['namespace_tool_sha256'] ==
            runtime['namespace_tool_sha256']
         and bundle['root_guard_helper_sha256'] ==
            runtime['root_guard_helper_sha256']
         and bundle['host_runtime_trust_boundary'] ==
            runtime['host_runtime_trust_boundary'],
         'executing-runtime-identity')
    need(type(bundle['financial_rounds']) is list
         and len(bundle['financial_rounds']) == 2,
         'two-financial-round-identities')
    for number, row in zip((1, 2), bundle['financial_rounds']):
        fields(row, ('round', 'financial_run_id',
                     'financial_artifacts_sha256',
                     'financial_result_sha256',
                     'retained_projection_sha256'))
        need(row['round'] == number, 'financial-round-order')
        for name in row:
            if name != 'round':
                word(row[name])
    need(bundle['financial_rounds'][0]['financial_run_id'] !=
            bundle['financial_rounds'][1]['financial_run_id']
         and bundle['financial_rounds'][0][
             'retained_projection_sha256'] !=
            bundle['financial_rounds'][1][
             'retained_projection_sha256'],
         'distinct-financial-round-identities')
    validate_binding(bundle['binding'])
    need(bundle['binding']['method_sha256'] == bundle['method_sha256']
         and bundle['binding']['selection_sha256'] ==
            bundle['diagnostic_run_selection_sha256'],
         'top-binding-source-selection')
    need(type(bundle['capture_identity']) is str
         and str(uuid.UUID(bundle['capture_identity'])) ==
             bundle['capture_identity'], 'capture-identity')
    for name in ('score_receipt_sha256', 'score_launch_sha256'):
        need(type(bundle[name]) is list and len(bundle[name]) == 3
             and len(set(bundle[name])) == 3, 'three-distinct-' + name)
        for digest in bundle[name]:
            word(digest)
    fields(bundle['lattice_attestation'], LATTICE_FIELDS)
    need(all(bundle['lattice_attestation'][name] is True
             for name in LATTICE_FIELDS), 'source-derived-lattice-attestation')
    categories = bundle['coverage_categories']
    need(type(categories) is dict and set(categories) == set(VIEWS),
         'coverage-category-view-set')
    for view in VIEWS:
        need(type(categories[view]) is list
             and categories[view] == list(REQUIRED_CATEGORIES[view]),
             'exact-required-coverage-' + view)
    need(type(bundle['views']) is list and len(bundle['views']) == len(VIEWS),
         'all-four-views')
    views = {name: validate_view(value, name)
             for name, value in zip(VIEWS, bundle['views'])}
    bindings = [encoded(value['binding']) for value in views.values()]
    need(len(set(bindings)) == 1, 'same-binding-across-views')
    need(views[VIEWS[0]]['binding'] == bundle['binding'],
         'view-binding-matches-bundle')
    seals = [value['capsule_seal_sha256'] for value in views.values()]
    need(len(set(seals)) == len(seals), 'distinct-view-capsules')
    return {**bundle, 'views_by_name': views}


def coverage_complete(view):
    coverage = view['coverage']
    return (coverage['modeled_artifacts'] > 0
            and coverage['unmodeled_artifacts'] == 0
            and coverage['missing_artifacts'] == 0
            and coverage['terminal_modeled'] is True
            and all(row['unmodeled_artifacts'] == 0
                    and row['unmodeled_fields'] == 0
                    and row['missing_artifacts'] == 0
                    for row in view['category_coverage'].values())
            and view['workload']['cross_round_constraints_modeled'] is True
            and view['workload']['terminal_constraints_modeled'] is True)


def union_is_monotone(views):
    """Validate the public/side-view/union candidate-set lattice.

    Unique counts are comparable only where eligibility is unchanged:
    public->dispatcher and corrupt-server-plus-wallet->union.
    """
    edges = (
        ('public', 'dispatcher'),
        ('public', 'corrupt-server-plus-wallet'),
        ('dispatcher', 'union'),
        ('corrupt-server-plus-wallet', 'union'),
    )
    for index in range(2):
        for weaker_name, stronger_name in edges:
            weaker = views[weaker_name]['rounds'][index]
            stronger = views[stronger_name]['rounds'][index]
            for name in COUNT_FIELDS:
                if stronger[name] > weaker[name]:
                    return False
            if (stronger['truth_retained'] and not weaker['truth_retained']
                    or stronger['honest_input_swap_retained']
                        and not weaker['honest_input_swap_retained']
                    or stronger['honest_graph_alternative_retained']
                        and not weaker['honest_graph_alternative_retained']
                    or stronger['honest_nf_pair_candidate_floor_met']
                        and not weaker['honest_nf_pair_candidate_floor_met']
                    or stronger['forbidden_exports']
                        < weaker['forbidden_exports']):
                return False
        public = views['public']['rounds'][index]
        dispatcher = views['dispatcher']['rounds'][index]
        corrupt = views['corrupt-server-plus-wallet']['rounds'][index]
        union = views['union']['rounds'][index]
        if (dispatcher['eligible_inputs'] != public['eligible_inputs']
                or dispatcher['eligible_outputs'] != public['eligible_outputs']
                or union['eligible_inputs'] != corrupt['eligible_inputs']
                or union['eligible_outputs'] != corrupt['eligible_outputs']):
            return False
        for name in UNIQUE_FIELDS:
            if dispatcher[name] < public[name] or union[name] < corrupt[name]:
                return False
    for weaker_name, stronger_name in edges:
        weaker = views[weaker_name]['workload']
        stronger = views[stronger_name]['workload']
        if (stronger['full_workload_candidates'] >
                weaker['full_workload_candidates']
                or stronger['truth_vector_retained']
                    and not weaker['truth_vector_retained']
                or stronger['honest_graph_alternative_retained']
                    and not weaker['honest_graph_alternative_retained']
                or stronger['honest_nf_pair_candidate_floor_met']
                    and not weaker['honest_nf_pair_candidate_floor_met']):
            return False
    public_workload = views['public']['workload']
    dispatcher_workload = views['dispatcher']['workload']
    corrupt_workload = views['corrupt-server-plus-wallet']['workload']
    union_workload = views['union']['workload']
    if (dispatcher_workload['eligible_inputs'] !=
            public_workload['eligible_inputs']
            or dispatcher_workload['eligible_outputs'] !=
                public_workload['eligible_outputs']
            or union_workload['eligible_inputs'] !=
                corrupt_workload['eligible_inputs']
            or union_workload['eligible_outputs'] !=
                corrupt_workload['eligible_outputs']):
        return False
    for name in (('correct_unique_full_vectors',
                  'wrong_unique_full_vectors') + UNIQUE_FIELDS):
        if (dispatcher_workload[name] < public_workload[name]
                or union_workload[name] < corrupt_workload[name]):
            return False
    return True


def candidate_round_passes(row):
    return (
        row['truth_retained'] is True
        and row['honest_input_swap_retained'] is True
        and row['honest_graph_alternative_retained'] is True
        and row['honest_nf_pair_candidate_floor_met'] is True
        and row['forbidden_exports'] == 0
        and row['strict_H1_status'] == 'PASS_BOUNDED_DIRECT_CHECK'
        and all(row[name] == 0 for name in UNIQUE_FIELDS)
        and row['input_owner_assignments'] >= MIN_INPUT_ASSIGNMENTS
        and row['output_creator_assignments'] >= MIN_OUTPUT_ASSIGNMENTS
        and row['output_pair_partitions'] >= MIN_OUTPUT_PAIR_PARTITIONS
        and row['joint_candidates'] >= MIN_JOINT_CANDIDATES
        and row['nf_to_created_pair_relations'] >= MIN_NF_PAIR_RELATIONS
        and row['_inputs_with_multiple_pair_candidates']
            >= MIN_HONEST_NFS_WITH_MULTIPLE_PAIR_CANDIDATES
    )


def candidate_workload_passes(value):
    return (
        value['truth_vector_retained'] is True
        and value['honest_graph_alternative_retained'] is True
        and value['full_workload_candidates'] >= 2
        and value['correct_unique_full_vectors'] == 0
        and value['wrong_unique_full_vectors'] == 0
        and all(value[name] == 0 for name in UNIQUE_FIELDS)
        and value['honest_nf_pair_candidate_floor_met'] is True
        and value['cross_round_constraints_modeled'] is True
        and value['terminal_constraints_modeled'] is True
    )


def baseline_round_fails(row):
    detected_link = (
        not row['honest_graph_alternative_retained']
        or not row['honest_nf_pair_candidate_floor_met']
        or row['output_pair_partitions'] < MIN_OUTPUT_PAIR_PARTITIONS
        or row['nf_to_created_pair_relations'] < MIN_NF_PAIR_RELATIONS
        or row['_inputs_with_multiple_pair_candidates']
            < MIN_HONEST_NFS_WITH_MULTIPLE_PAIR_CANDIDATES
        or row['forbidden_exports'] > 0
        or any(row[name] > 0 for name in UNIQUE_FIELDS)
    )
    return row['truth_retained'] is True and detected_link


def baseline_workload_fails(value):
    return (value['truth_vector_retained'] is True
            and (value['full_workload_candidates'] < 2
                 or not value['honest_graph_alternative_retained']
                 or value['correct_unique_full_vectors'] > 0
                 or value['wrong_unique_full_vectors'] > 0
                 or any(value[name] > 0 for name in UNIQUE_FIELDS)
                 or not value['honest_nf_pair_candidate_floor_met']))


def validate_owner_comparison(value, baseline, candidate):
    fields(value, OWNER_COMPARISON_FIELDS)
    need(value['schema'] == 'kpb-privacy-owner-nonregression/v1'
         and value['comparison_selection_sha256'] ==
            baseline['comparison_selection_sha256']
         and value['comparison_selection_sha256'] ==
            candidate['comparison_selection_sha256']
         and value['baseline_run_selection_sha256'] ==
            baseline['run_selection_sha256']
         and value['candidate_run_selection_sha256'] ==
            candidate['run_selection_sha256']
         and value['owner_comparison_source_sha256'] ==
            baseline['owner_comparison_source_sha256']
         and value['owner_comparison_source_sha256'] ==
            candidate['owner_comparison_source_sha256'],
         'owner-nonregression-selection-chain')
    word(value['owner_comparison_source_sha256'])
    need(value['owner_comparison_launcher_source_sha256'] ==
            baseline['owner_comparison_launcher_source_sha256'] ==
            candidate['owner_comparison_launcher_source_sha256']
         and value['source_closure_sha256'] ==
            baseline['source_closure_sha256'] ==
            candidate['source_closure_sha256']
         and value['runtime_identity_sha256'] ==
            baseline['runtime_identity_sha256'] ==
            candidate['runtime_identity_sha256']
         and value['step3_terminal_gate'] == STEP3_TERMINAL_GATE,
         'owner-nonregression-source-runtime-terminal-chain')
    word(value['owner_comparison_launcher_source_sha256'])
    for name, bundle in (('baseline_capsule_seal_sha256', baseline),
                         ('candidate_capsule_seal_sha256', candidate)):
        need(value[name] == [view['capsule_seal_sha256']
                             for view in bundle['views']],
             'owner-nonregression-' + name)
    score_seals = []
    for name in ('baseline_score_bundle_seal_sha256',
                 'candidate_score_bundle_seal_sha256'):
        need(type(value[name]) is list and len(value[name]) == 3
             and len(set(value[name])) == 3,
             'owner-nonregression-' + name)
        for digest in value[name]:
            word(digest); score_seals.append(digest)
    need(len(set(score_seals)) == 6,
         'six-distinct-private-score-bundle-seals')
    need(value['dimensions'] == list(OWNER_COMPARISON_DIMENSIONS)
         and value['honest_owner_count'] == 2
         and value['all_honest_owner_counts_nonregressed'] is True
         and type(value['honest_owners_with_strict_gain']) is int
         and 1 <= value['honest_owners_with_strict_gain'] <= 2
         and value['private_owner_counts_exported'] is False,
         'owner-nonregression-result')
    return value


def evaluate_synthetic_model(baseline_bundle, candidate_bundle,
                             owner_comparison):
    """Exercise the frozen scoring model without minting actual authority.

    This public test seam accepts in-memory values, so its result is always a
    synthetic model result.  Actual privacy authority must come from a future
    source-owned comparison -> run -> producer launch -> capture -> observer ->
    score -> aggregate chain, not from caller-supplied bundle dictionaries.
    """
    baseline = validate_bundle(baseline_bundle, 'ACTUAL_TRANSPARENT_BASELINE')
    candidate = validate_bundle(candidate_bundle,
                                'ACTUAL_HIDDEN_MAPPING_CANDIDATE')
    for name in ('comparison_selection_sha256', 'method_sha256',
                 'measurement_freeze_sha256', 'workload_sha256',
                 'observer_source_sha256', 'capture_source_sha256',
                 'coverage_policy_sha256',
                 'bundle_producer_source_sha256',
                 'owner_comparison_source_sha256',
                 'owner_comparison_launcher_source_sha256',
                 'capture_producer_source_sha256',
                 'capture_producer_build_sha256',
                 'capture_producer_launcher_source_sha256',
                 'capture_launcher_source_sha256',
                 'source_closure_sha256', 'runtime_identity_sha256',
                 'python_runtime_sha256', 'namespace_tool_sha256',
                 'root_guard_helper_sha256',
                 'host_runtime_trust_boundary'):
        need(baseline[name] == candidate[name], 'same-' + name)
    need(baseline['terminal_scope'] == candidate['terminal_scope'] ==
         TERMINAL_SCOPE
         and baseline['step3_terminal_gate'] ==
             candidate['step3_terminal_gate'] == STEP3_TERMINAL_GATE,
         'same-bounded-terminal-scope')
    for name in ('run_selection_sha256', 'diagnostic_selection_sha256',
                 'diagnostic_run_selection_sha256',
                 'capture_identity', 'capture_receipt_sha256',
                 'capture_manifest_seal_sha256',
                 'construction_classification_receipt_sha256',
                 'capture_producer_receipt_sha256',
                 'capture_launch_receipt_sha256',
                 'observation_receipt_sha256', 'barrier_sha256',
                 'aggregate_result_sha256'):
        need(baseline[name] != candidate[name],
             'distinct-actual-' + name.replace('_', '-'))
    need(not ({row['financial_run_id'] for row in
               baseline['financial_rounds']} &
              {row['financial_run_id'] for row in
               candidate['financial_rounds']})
         and not ({row['retained_projection_sha256'] for row in
                   baseline['financial_rounds']} &
                  {row['retained_projection_sha256'] for row in
                   candidate['financial_rounds']}),
         'distinct-baseline-candidate-financial-evidence')
    baseline_binding = baseline['views_by_name']['public']['binding']
    candidate_binding = candidate['views_by_name']['public']['binding']
    for name in ('selection_sha256', 'trial_id', 'attempt_id'):
        need(baseline_binding[name] != candidate_binding[name],
             'distinct-actual-' + name.replace('_', '-'))
    all_seals = [view['capsule_seal_sha256']
                 for bundle in (baseline, candidate)
                 for view in bundle['views_by_name'].values()]
    need(len(set(all_seals)) == 8, 'eight-distinct-actual-capsules')
    validate_owner_comparison(owner_comparison, baseline, candidate)
    need(union_is_monotone(baseline['views_by_name'])
         and union_is_monotone(candidate['views_by_name']),
         'union-candidates-must-not-increase')

    baseline_complete = all(coverage_complete(view)
                            for view in baseline['views_by_name'].values())
    candidate_complete = all(coverage_complete(view)
                             for view in candidate['views_by_name'].values())
    candidate_all_views_pass = all(
        coverage_complete(view)
        and all(candidate_round_passes(row) for row in view['rounds'])
        and candidate_workload_passes(view['workload'])
        for view in candidate['views_by_name'].values())
    baseline_rounds = baseline['views_by_name']['union']['rounds']
    candidate_rounds = candidate['views_by_name']['union']['rounds']
    baseline_detected = (baseline_complete
        and all(baseline_round_fails(row) for row in baseline_rounds)
        and baseline_workload_fails(
            baseline['views_by_name']['union']['workload']))
    candidate_passed = candidate_complete and candidate_all_views_pass
    ambiguity_increased = all(
        candidate_row['output_pair_partitions']
            > baseline_row['output_pair_partitions']
        and candidate_row['nf_to_created_pair_relations']
            > baseline_row['nf_to_created_pair_relations']
        for baseline_row, candidate_row in zip(baseline_rounds,
                                                candidate_rounds)
    ) and (candidate['views_by_name']['union']['workload']
           ['full_workload_candidates'] >
           baseline['views_by_name']['union']['workload']
           ['full_workload_candidates'])
    pareto_nonregression = all(
        candidate['views_by_name'][view]['rounds'][index][name]
            >= baseline['views_by_name'][view]['rounds'][index][name]
        for view in VIEWS for index in range(2) for name in COUNT_FIELDS
    ) and all(candidate['views_by_name'][view]['workload']
              ['full_workload_candidates'] >=
              baseline['views_by_name'][view]['workload']
              ['full_workload_candidates'] for view in VIEWS)

    if not baseline_complete or not baseline_detected:
        status = 'INVALID_BASELINE_CONTROL'
    elif any(not row['truth_retained'] for row in candidate_rounds) \
            or any(not view['workload']['truth_vector_retained']
                   for view in candidate['views_by_name'].values()) \
            or any(row['strict_H1_status'] == 'FAIL'
                   for view in candidate['views_by_name'].values()
                   for row in view['rounds']):
        status = 'FAIL_PRIVACY_GATE'
    elif not candidate_complete or any(
            view['combined_terminal_status'] == 'UNQUALIFIED'
            for view in candidate['views_by_name'].values()):
        status = 'UNQUALIFIED'
    elif (not candidate_passed or not ambiguity_increased
          or not pareto_nonregression):
        status = 'FAIL_PRIVACY_GATE'
    else:
        status = 'PASS_BOUNDED_SYNTHETIC_MODEL_CHECK'
    return {
        'schema': 'kpb-privacy-synthetic-model-result/v1',
        'comparison_selection_sha256':
            candidate['comparison_selection_sha256'],
        'measurement_freeze_sha256':
            candidate['measurement_freeze_sha256'],
        'owner_nonregression_receipt_sha256': hashlib.sha256(
            encoded(owner_comparison)).hexdigest(),
        'baseline_bundle_sha256': hashlib.sha256(
            encoded(baseline_bundle)).hexdigest(),
        'candidate_bundle_sha256': hashlib.sha256(
            encoded(candidate_bundle)).hexdigest(),
        'baseline_run_selection_sha256':
            baseline['run_selection_sha256'],
        'candidate_run_selection_sha256':
            candidate['run_selection_sha256'],
        'baseline_diagnostic_selection_sha256':
            baseline['diagnostic_selection_sha256'],
        'candidate_diagnostic_selection_sha256':
            candidate['diagnostic_selection_sha256'],
        'baseline_diagnostic_run_selection_sha256':
            baseline['diagnostic_run_selection_sha256'],
        'candidate_diagnostic_run_selection_sha256':
            candidate['diagnostic_run_selection_sha256'],
        'baseline_trial_id': baseline_binding['trial_id'],
        'candidate_trial_id': candidate_binding['trial_id'],
        'method_sha256': candidate['method_sha256'],
        'workload_sha256': candidate['workload_sha256'],
        'source_closure_sha256': candidate['source_closure_sha256'],
        'runtime_identity_sha256': candidate['runtime_identity_sha256'],
        'acceptance_source_closure_sha256':
            candidate['source_closure_sha256']['acceptance'],
        'baseline_capture_receipt_sha256':
            baseline['capture_receipt_sha256'],
        'candidate_capture_receipt_sha256':
            candidate['capture_receipt_sha256'],
        'all_four_baseline_views_complete': baseline_complete,
        'all_four_candidate_views_complete': candidate_complete,
        'all_four_candidate_views_passed': candidate_all_views_pass,
        'baseline_link_detected_in_both_rounds': baseline_detected,
        'candidate_union_truth_retained_in_both_rounds': all(
            row['truth_retained'] for row in candidate_rounds),
        'candidate_union_honest_graph_alternative_retained_in_both_rounds': all(
            row['honest_graph_alternative_retained']
            for row in candidate_rounds),
        'candidate_union_full_workload_truth_and_graph_alternative_retained': (
            candidate['views_by_name']['union']['workload']
            ['truth_vector_retained'] is True
            and candidate['views_by_name']['union']['workload']
            ['honest_graph_alternative_retained'] is True),
        'candidate_union_pair_partition_and_nf_pair_ambiguity_increased':
            ambiguity_increased,
        'all_view_round_count_dimensions_pareto_nonregressed':
            pareto_nonregression,
        'candidate_unique_eligible_predictions': sum(
            row[name] for row in candidate_rounds for name in UNIQUE_FIELDS)
            + sum(candidate['views_by_name']['union']['workload'][name]
                  for name in UNIQUE_FIELDS)
            + candidate['views_by_name']['union']['workload']
                ['correct_unique_full_vectors']
            + candidate['views_by_name']['union']['workload']
                ['wrong_unique_full_vectors'],
        'union_candidate_monotonicity': True,
        'posterior_probability_claim': False,
        'cryptographic_or_general_anonymity_claim': False,
        'exit_or_payout_linkability_measured': False,
        'complete_native_lifecycle_authorized': False,
        'step3_terminal_gate': STEP3_TERMINAL_GATE,
        'actual_authority_chain_verified': False,
        'actual_privacy_status_minted': False,
        'status': status,
    }


def evaluate(baseline_bundle, candidate_bundle, owner_comparison):
    """Fail closed until an actual source-owned authority chain exists.

    Validating mutually consistent bundles and an owner-comparison dictionary
    is useful model evidence, but cannot prove how those values were produced.
    The current repository deliberately has no selected actual capture-producer
    build/launcher/receipt, so neither this direct API nor the standalone CLI
    may emit an ACTUAL privacy PASS.
    """
    model = evaluate_synthetic_model(
        baseline_bundle, candidate_bundle, owner_comparison)
    return {
        **model,
        'schema': 'kpb-privacy-acceptance-source-only/v1',
        'synthetic_model_status': model['status'],
        'status': 'UNQUALIFIED_ACTUAL_AUTHORITY_ABSENT',
        'actual_authority_chain_verified': False,
        'actual_privacy_status_minted': False,
        'authority_absence_reason':
            'selected-actual-producer-build-launch-and-receipt-absent',
    }


def read_canonical(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts
         and not any(part.is_symlink() for part in (path, *path.parents)),
         'absolute-nonsymlink-input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as handle:
        before = os.fstat(handle.fileno())
        raw = handle.read()
        after = os.fstat(handle.fileno())
    keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns',
            'st_mode', 'st_nlink', 'st_uid')
    need(all(getattr(before, key) == getattr(after, key) for key in keys)
         and len(raw) == before.st_size and stat.S_ISREG(before.st_mode)
         and before.st_nlink == 1 and before.st_uid == os.getuid()
         and stat.S_IMODE(before.st_mode) == 0o400,
         'stable-single-link-input')
    return parse(raw)


def write_new(path, value):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts
         and not any(part.is_symlink() for part in (path, *path.parents)),
         'absolute-nonsymlink-output')
    raw = encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return hashlib.sha256(raw).hexdigest()


def read_owner_comparison_chain(baseline_bundle, candidate_bundle):
    baseline = validate_bundle(baseline_bundle,
                               'ACTUAL_TRANSPARENT_BASELINE')
    candidate = validate_bundle(candidate_bundle,
                                'ACTUAL_HIDDEN_MAPPING_CANDIDATE')
    need(baseline['comparison_selection_sha256'] ==
         candidate['comparison_selection_sha256'],
         'owner-chain-common-comparison')
    local = Path(__file__).absolute().parent
    need(hashlib.sha256((local / 'privacy_owner_comparison.py')
        .read_bytes()).hexdigest() ==
        baseline['owner_comparison_source_sha256'] ==
        candidate['owner_comparison_source_sha256'],
        'owner-chain-executing-comparison-source')
    need(hashlib.sha256((local / 'privacy_owner_comparison_launch.py')
        .read_bytes()).hexdigest() ==
        baseline['owner_comparison_launcher_source_sha256'] ==
        candidate['owner_comparison_launcher_source_sha256'],
        'owner-chain-executing-launcher-source')
    root = (OWNER_COMPARISON_BASE /
            baseline['comparison_selection_sha256'] / 'owner-comparison')
    result_path = root / 'PUBLIC.json'; launch_path = root / 'LAUNCH.json'
    result = read_canonical(result_path)
    validate_owner_comparison(result, baseline, candidate)
    launch = read_canonical(launch_path)
    # Import after module initialization because the worker imports this gate
    # for its frozen dimensions. The selected launcher is hard-disabled as an
    # authority until an outer supervisor supplies a move-only completion.
    import privacy_owner_comparison_launch as comparison_launcher
    comparison_launcher.validate_launch_receipt(launch)
    fields(launch, OWNER_COMPARISON_LAUNCH_FIELDS)
    expected_capsules = {
        'baseline_capsule_seal_sha256': [row['capsule_seal_sha256']
                                         for row in baseline['views']],
        'candidate_capsule_seal_sha256': [row['capsule_seal_sha256']
                                          for row in candidate['views']],
    }
    need(launch['schema'] == 'kpb-privacy-owner-comparison-launch/v1'
         and launch['comparison_selection_sha256'] ==
            baseline['comparison_selection_sha256']
         and launch['baseline_run_selection_sha256'] ==
            baseline['run_selection_sha256']
         and launch['candidate_run_selection_sha256'] ==
            candidate['run_selection_sha256']
         and launch['owner_comparison_source_sha256'] ==
            baseline['owner_comparison_source_sha256']
         and launch['owner_comparison_launcher_source_sha256'] ==
            baseline['owner_comparison_launcher_source_sha256']
         and launch['source_closure_sha256'] ==
            baseline['source_closure_sha256']
         and launch['runtime_identity_sha256'] ==
            baseline['runtime_identity_sha256']
         and launch['python_runtime_sha256'] ==
            baseline['python_runtime_sha256']
         and launch['namespace_tool_sha256'] ==
            baseline['namespace_tool_sha256']
         and launch['root_guard_helper_sha256'] ==
            baseline['root_guard_helper_sha256']
         and launch['host_runtime_trust_boundary'] ==
            baseline['host_runtime_trust_boundary']
         and launch['step3_terminal_gate'] == STEP3_TERMINAL_GATE
         and launch['baseline_capsule_seal_sha256'] ==
            expected_capsules['baseline_capsule_seal_sha256']
         and launch['candidate_capsule_seal_sha256'] ==
            expected_capsules['candidate_capsule_seal_sha256']
         and launch['baseline_score_bundle_seal_sha256'] ==
            result['baseline_score_bundle_seal_sha256']
         and launch['candidate_score_bundle_seal_sha256'] ==
            result['candidate_score_bundle_seal_sha256']
         and Path(launch['public_result']) == result_path
         and launch['public_result_sha256'] ==
            hashlib.sha256(encoded(result)).hexdigest()
         and launch['private_score_bundle_count'] == 6
         and launch['network_enabled'] is False
         and launch['private_score_bodies_exported'] is False,
         'owner-comparison-isolated-launch-chain')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--candidate', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    baseline = read_canonical(args.baseline)
    candidate = read_canonical(args.candidate)
    owner_comparison = read_owner_comparison_chain(baseline, candidate)
    result = evaluate(baseline, candidate, owner_comparison)
    write_new(args.output, result)


if __name__ == '__main__':
    main()
