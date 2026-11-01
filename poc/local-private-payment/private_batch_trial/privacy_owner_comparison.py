#!/usr/bin/env python3
"""Closed comparison of private owner score masks; exports no owner counts.

Invoke inside a selected network-off aggregate namespace after both fresh runs
have completed owner-local scoring.  The caller supplies all six original
private score bundles and the public pre-truth comparison selection.  Only one
global non-regression Boolean and the number of honest owners with any strict
gain are public.
"""
import hashlib
from pathlib import Path

import privacy_acceptance as gate
import privacy_codec as codec
import privacy_source_closure as source_closure


VIEWS = gate.VIEWS
DIMENSIONS = gate.OWNER_COMPARISON_DIMENSIONS
CONFIG_FIELDS = (
    'comparison_selection_sha256', 'baseline_run_selection_sha256',
    'candidate_run_selection_sha256', 'owner_comparison_source_sha256',
    'owner_comparison_launcher_source_sha256',
    'source_closure_sha256', 'runtime_identity_sha256',
    'python_runtime_sha256', 'namespace_tool_sha256',
    'root_guard_helper_sha256', 'host_runtime_trust_boundary',
    'step3_terminal_gate',
    'baseline_binding', 'candidate_binding',
    'baseline_capsule_seal_sha256', 'candidate_capsule_seal_sha256',
    'baseline_score_bundle_seal_sha256',
    'candidate_score_bundle_seal_sha256',
)
BUNDLE_FIELDS = (
    'schema', 'binding', 'run_selection_sha256', 'owner_component', 'views',
)
LEAF_FIELDS = (
    'schema', 'binding', 'view', 'capsule_seal_sha256', 'owner_component',
    'rounds', 'round_candidate_counts', 'workload_masks',
    'workload_candidate_count', 'workload_rounds',
)
ROUND_FIELDS = (
    'round', 'input_masks', 'output_masks', 'joint_masks',
    'eligible_inputs', 'eligible_outputs', 'correct_unique_inputs',
    'wrong_unique_inputs', 'correct_unique_outputs',
    'wrong_unique_outputs', 'correct_unique_pair_links',
    'wrong_unique_pair_links', 'nf_pair_candidate_floor_met',
)
WORKLOAD_ROUND_FIELDS = (
    'round', 'eligible_inputs', 'eligible_outputs',
    'correct_unique_inputs', 'wrong_unique_inputs',
    'correct_unique_outputs', 'wrong_unique_outputs',
    'correct_unique_pair_links', 'wrong_unique_pair_links',
    'nf_pair_candidate_floor_met',
)


def need(condition, category):
    if not condition:
        raise ValueError('privacy-owner-comparison-' + category)


def fields(value, names):
    need(type(value) is dict and set(value) == set(names), 'exact-fields')


def source_sha256():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def masks(value, size, category):
    need(type(value) is list and len(value) == 2
         and type(size) is int and size >= 0
         and all(type(item) is int and 0 <= item < (1 << size)
                 for item in value), category)
    return value


def validate_config(value):
    fields(value, CONFIG_FIELDS)
    for name in ('comparison_selection_sha256',
                 'baseline_run_selection_sha256',
                 'candidate_run_selection_sha256',
                 'owner_comparison_source_sha256',
                 'owner_comparison_launcher_source_sha256',
                 'runtime_identity_sha256', 'python_runtime_sha256',
                 'namespace_tool_sha256', 'root_guard_helper_sha256'):
        gate.word(value[name])
    need(value['owner_comparison_source_sha256'] == source_sha256(),
         'executing-source-pin')
    launcher = Path(__file__).absolute().parent / \
        'privacy_owner_comparison_launch.py'
    need(value['owner_comparison_launcher_source_sha256'] ==
            hashlib.sha256(launcher.read_bytes()).hexdigest(),
         'executing-launcher-source-pin')
    need(type(value['source_closure_sha256']) is dict
         and value['source_closure_sha256'].get('owner-comparison') ==
            source_closure.digest('owner-comparison')
         and value['source_closure_sha256'].get(
            'owner-comparison-launcher') ==
            source_closure.digest('owner-comparison-launcher'),
         'executing-comparison-source-closures')
    need(value['host_runtime_trust_boundary'] ==
            source_closure.HOST_RUNTIME_TRUST_BOUNDARY
         and value['step3_terminal_gate'] == gate.STEP3_TERMINAL_GATE,
         'runtime-and-terminal-boundary')
    declared_runtime = {
        'schema': 'kpb-privacy-runtime-identity/v1',
        'python_path': str(source_closure.PYTHON_RUNTIME),
        'python_runtime_sha256': value['python_runtime_sha256'],
        'namespace_tool_path': str(source_closure.NAMESPACE_TOOL),
        'namespace_tool_sha256': value['namespace_tool_sha256'],
        'root_guard_helper_path': str(source_closure.ROOT_GUARD),
        'root_guard_helper_sha256': value['root_guard_helper_sha256'],
        'host_runtime_trust_boundary': value['host_runtime_trust_boundary'],
    }
    need(value['runtime_identity_sha256'] == hashlib.sha256(
        source_closure.encoded(declared_runtime)).hexdigest(),
        'runtime-identity-pin')
    gate.validate_binding(value['baseline_binding'])
    gate.validate_binding(value['candidate_binding'])
    need(value['baseline_binding']['trial_id'] !=
            value['candidate_binding']['trial_id']
         and value['baseline_binding']['selection_sha256'] !=
            value['candidate_binding']['selection_sha256'],
         'fresh-distinct-runs')
    for name in ('baseline_capsule_seal_sha256',
                 'candidate_capsule_seal_sha256'):
        need(type(value[name]) is list and len(value[name]) == 4
             and len(set(value[name])) == 4, name)
        for item in value[name]: gate.word(item)
    need(not set(value['baseline_capsule_seal_sha256']) &
         set(value['candidate_capsule_seal_sha256']),
         'eight-distinct-capsules')
    score_seals = []
    for name in ('baseline_score_bundle_seal_sha256',
                 'candidate_score_bundle_seal_sha256'):
        need(type(value[name]) is list and len(value[name]) == 3
             and len(set(value[name])) == 3, name)
        for item in value[name]:
            gate.word(item); score_seals.append(item)
    need(len(set(score_seals)) == 6, 'six-distinct-score-bundle-seals')
    return value


def validate_bundles(values, binding, run_selection_sha256, seals):
    need(type(values) is list and len(values) == 3,
         'three-owner-score-bundles')
    need(sorted(value.get('owner_component', -1) for value in values)
         == [0, 1, 2], 'distinct-owner-score-bundles')
    result = {}
    for bundle in values:
        fields(bundle, BUNDLE_FIELDS)
        owner = bundle['owner_component']; codec.owner(owner)
        need(bundle['schema'] == 'kpb-private-all-view-count-leaves/v2'
             and bundle['binding'] == binding
             and bundle['run_selection_sha256'] == run_selection_sha256
             and type(bundle['views']) is list
             and len(bundle['views']) == 4,
             'score-bundle-selection')
        leaves = []
        for index, (view, seal, leaf) in enumerate(
                zip(VIEWS, seals, bundle['views'])):
            fields(leaf, LEAF_FIELDS)
            need(leaf['schema'] == 'kpb-private-direct-score-leaf/v2'
                 and leaf['binding'] == binding and leaf['view'] == view
                 and leaf['capsule_seal_sha256'] == seal
                 and leaf['owner_component'] == owner
                 and type(leaf['rounds']) is list
                 and len(leaf['rounds']) == 2,
                 'score-leaf-selection-' + str(index))
            need(type(leaf['round_candidate_counts']) is list
                 and len(leaf['round_candidate_counts']) == 2,
                 'round-candidate-counts')
            rounds = []
            for number, row, counts in zip(
                    (1, 2), leaf['rounds'], leaf['round_candidate_counts']):
                fields(row, ROUND_FIELDS)
                fields(counts, ('inputs', 'outputs', 'joint'))
                need(type(counts['inputs']) is int and 0 <= counts['inputs'] <= 6
                     and type(counts['outputs']) is int
                     and 0 <= counts['outputs'] <= 90
                     and type(counts['joint']) is int
                     and 0 <= counts['joint'] <= 540,
                     'bounded-round-candidate-counts')
                need(row['round'] == number, 'score-round-order')
                need(type(row['nf_pair_candidate_floor_met']) is bool,
                     'score-pair-floor-boolean')
                for name, count_name in (
                        ('input_masks', 'inputs'),
                        ('output_masks', 'outputs'),
                        ('joint_masks', 'joint')):
                    masks(row[name], counts[count_name], name)
                rounds.append(row)
            need(type(leaf['workload_candidate_count']) is int
                 and 0 <= leaf['workload_candidate_count'] <= 291600,
                 'bounded-workload-candidate-count')
            masks(leaf['workload_masks'], leaf['workload_candidate_count'],
                  'workload-masks')
            need(type(leaf['workload_rounds']) is list
                 and len(leaf['workload_rounds']) == 2,
                 'workload-rounds')
            for number, row in zip((1, 2), leaf['workload_rounds']):
                fields(row, WORKLOAD_ROUND_FIELDS)
                need(row['round'] == number
                     and type(row['nf_pair_candidate_floor_met']) is bool,
                     'workload-round-order-and-floor')
                for name, limit in (
                        ('eligible_inputs', 1), ('eligible_outputs', 2),
                        ('correct_unique_inputs', 1),
                        ('wrong_unique_inputs', 1),
                        ('correct_unique_outputs', 2),
                        ('wrong_unique_outputs', 2),
                        ('correct_unique_pair_links', 1),
                        ('wrong_unique_pair_links', 1)):
                    need(type(row[name]) is int and 0 <= row[name] <= limit,
                         'bounded-workload-round-count')
                need(row['correct_unique_inputs'] +
                        row['wrong_unique_inputs'] <= row['eligible_inputs']
                     and row['correct_unique_outputs'] +
                        row['wrong_unique_outputs'] <= row['eligible_outputs']
                     and row['correct_unique_pair_links'] +
                        row['wrong_unique_pair_links'] <=
                        row['eligible_inputs'],
                     'workload-round-unique-eligibility')
            leaves.append({**leaf, 'rounds': rounds})
        result[owner] = leaves
    return result


def truth_counts(leaves):
    result = []
    for leaf in leaves:
        values = []
        for row in leaf['rounds']:
            values.extend((row['input_masks'][0].bit_count(),
                           row['output_masks'][0].bit_count(),
                           row['joint_masks'][0].bit_count()))
        values.append(leaf['workload_masks'][0].bit_count())
        result.append(values)
    return result


def compare(config, baseline_bundles, candidate_bundles):
    config = validate_config(config)
    baseline = validate_bundles(
        baseline_bundles, config['baseline_binding'],
        config['baseline_run_selection_sha256'],
        config['baseline_capsule_seal_sha256'])
    candidate = validate_bundles(
        candidate_bundles, config['candidate_binding'],
        config['candidate_run_selection_sha256'],
        config['candidate_capsule_seal_sha256'])
    nonregressed = True; strict_owners = 0
    for owner in (0, 2):
        before, after = truth_counts(baseline[owner]), truth_counts(candidate[owner])
        pairs = [(left, right) for left_view, right_view in zip(before, after)
                 for left, right in zip(left_view, right_view)]
        nonregressed = nonregressed and all(right >= left
                                             for left, right in pairs)
        strict_owners += int(any(right > left for left, right in pairs))
    return {
        'schema': 'kpb-privacy-owner-nonregression/v1',
        'comparison_selection_sha256':
            config['comparison_selection_sha256'],
        'baseline_run_selection_sha256':
            config['baseline_run_selection_sha256'],
        'candidate_run_selection_sha256':
            config['candidate_run_selection_sha256'],
        'owner_comparison_source_sha256':
            config['owner_comparison_source_sha256'],
        'owner_comparison_launcher_source_sha256':
            config['owner_comparison_launcher_source_sha256'],
        'source_closure_sha256': config['source_closure_sha256'],
        'runtime_identity_sha256': config['runtime_identity_sha256'],
        'step3_terminal_gate': config['step3_terminal_gate'],
        'baseline_capsule_seal_sha256':
            config['baseline_capsule_seal_sha256'],
        'candidate_capsule_seal_sha256':
            config['candidate_capsule_seal_sha256'],
        'baseline_score_bundle_seal_sha256':
            config['baseline_score_bundle_seal_sha256'],
        'candidate_score_bundle_seal_sha256':
            config['candidate_score_bundle_seal_sha256'],
        'dimensions': list(DIMENSIONS),
        'honest_owner_count': 2,
        'all_honest_owner_counts_nonregressed': nonregressed,
        'honest_owners_with_strict_gain': strict_owners,
        'private_owner_counts_exported': False,
    }
