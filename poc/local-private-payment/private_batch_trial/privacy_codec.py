"""Finite direct-linkage candidates and isolated count leaves; no wallet keys.

Adapts the exact creator-partition enumeration and salted capsule/count-only
boundary of owner-private-payments/wallet/score_codec.py. Input ownership is a
separate bijection. No hash tie-break guess or posterior probability is used.
"""
import hashlib
import itertools
import json
import re
import uuid
from collections import Counter

CAPSULE_TAG = b'KPBPRD01'
OWNERS = (0, 1, 2)
VIEWS = ('public', 'dispatcher', 'corrupt-server-plus-wallet', 'union')


def need(value, code):
    if not value:
        raise ValueError(code)


def fields(value, names):
    need(type(value) is dict and set(value) == set(names), 'privacy-exact-fields')


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'privacy-duplicate-key')
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('privacy-nonfinite-number')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def word(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None,
         'privacy-canonical-hash-or-word')
    return value


def owner(value):
    need(type(value) is int and value in OWNERS, 'privacy-owner-component')
    return value


def binding(value):
    fields(value, ('method_sha256', 'selection_sha256', 'trial_id', 'phase', 'attempt_id'))
    word(value['method_sha256']); word(value['selection_sha256'])
    need(type(value['trial_id']) is str and str(uuid.UUID(value['trial_id'])) == value['trial_id']
         and value['phase'] == 'private-batch-privacy', 'privacy-exact-trial-phase')
    need(type(value['attempt_id']) is str and re.fullmatch('[A-Za-z0-9_-]{1,128}', value['attempt_id']) is not None,
         'privacy-frozen-attempt-id')
    return value


def batch(value):
    fields(value, ('round', 'projection_sha256', 'context_sha256', 'nfs_hex32', 'cms_hex32', 'tuple_sha256'))
    need(type(value['round']) is int and value['round'] in (1, 2), 'privacy-fixed-round')
    word(value['projection_sha256'])
    word(value['context_sha256'])
    for name, count in (('nfs_hex32', 3), ('cms_hex32', 6), ('tuple_sha256', 6)):
        need(type(value[name]) is list and len(value[name]) == len(set(value[name])) == count,
             'privacy-exact-distinct-public-slots')
        for item in value[name]:
            word(item); need(item != '0' * 64, 'privacy-nonzero-public-slot')
    return value


def constraints(value, public):
    fields(value, ('input_edges', 'creator_edges', 'pair_edges', 'individual_delta_exports'))
    for key, target in (('input_edges', 'nfs_hex32'), ('creator_edges', 'tuple_sha256')):
        need(type(value[key]) is list, 'privacy-edge-array')
        for edge in value[key]:
            fields(edge, ('owner_component', 'slot_id', 'provenance'))
            owner(edge['owner_component']); word(edge['slot_id'])
            need(edge['slot_id'] in public[target] and edge['provenance'] in ('colluder-knowledge', 'direct-export'),
                 'privacy-selected-direct-edge')
    need(type(value['pair_edges']) is list, 'privacy-pair-array')
    for edge in value['pair_edges']:
        fields(edge, ('tuple_sha256', 'provenance'))
        need(type(edge['tuple_sha256']) is list and len(edge['tuple_sha256']) == 2
             and len(set(edge['tuple_sha256'])) == 2
             and all(item in public['tuple_sha256'] for item in edge['tuple_sha256'])
             and edge['provenance'] == 'pair-tag-export', 'privacy-explicit-pair-export')
    need(type(value['individual_delta_exports']) is int and value['individual_delta_exports'] >= 0,
         'privacy-individual-Delta-export-count')
    return value


def empty_constraints():
    return {'input_edges': [], 'creator_edges': [], 'pair_edges': [], 'individual_delta_exports': 0}


def assignments(public, observed):
    """Enumerate all direct-fact-compatible assignments, before seeing truth."""
    batch(public); constraints(observed, public)
    input_candidates = []
    for proposal in itertools.permutations(OWNERS):
        if all(proposal[public['nfs_hex32'].index(edge['slot_id'])] == edge['owner_component']
               for edge in observed['input_edges']):
            input_candidates.append(proposal)
    output_candidates = []
    for first in itertools.combinations(range(6), 2):
        remaining = [i for i in range(6) if i not in first]
        for second in itertools.combinations(remaining, 2):
            proposal = tuple(0 if i in first else 1 if i in second else 2 for i in range(6))
            if not all(proposal[public['tuple_sha256'].index(edge['slot_id'])] == edge['owner_component']
                       for edge in observed['creator_edges']):
                continue
            if not all(len({proposal[public['tuple_sha256'].index(item)] for item in edge['tuple_sha256']}) == 1
                       for edge in observed['pair_edges']):
                continue
            output_candidates.append(proposal)
    input_candidates = sorted(input_candidates)
    output_candidates = sorted(output_candidates)
    partitions = {tuple(sorted(tuple(i for i in range(6) if proposal[i] == component) for component in OWNERS))
                  for proposal in output_candidates}
    joint = [{'inputs': list(left), 'outputs': list(right)}
             for left in input_candidates for right in output_candidates]
    link_relations = {tuple(tuple(i for i in range(6) if candidate['outputs'][i] == candidate['inputs'][slot])
                            for slot in range(3)) for candidate in joint}
    link_sizes = [len({relation[slot] for relation in link_relations}) for slot in range(3)]
    forbidden = (sum(edge['provenance'] == 'direct-export' for edge in observed['input_edges'])
        + sum(edge['provenance'] == 'direct-export' for edge in observed['creator_edges'])
        + len(observed['pair_edges']) + observed['individual_delta_exports'])
    return {'public': public, 'constraints': observed, 'inputs': [list(row) for row in input_candidates],
        'outputs': [list(row) for row in output_candidates], 'joint': joint,
        'input_owner_assignments': len(input_candidates), 'output_creator_assignments': len(output_candidates),
        'output_pair_partitions': len(partitions), 'joint_candidates': len(joint),
        'nf_to_created_pair_relations': len(link_relations),
        'nf_pair_candidate_count_histogram': {str(size): count for size, count in sorted(Counter(link_sizes).items())},
        'forbidden_exports': forbidden}


def prediction(bound, view, models, coverage):
    binding(bound)
    need(view in VIEWS and type(models) is list and [model['public']['round'] for model in models] == [1, 2],
         'privacy-complete-two-round-prediction')
    fields(coverage, ('modeled_artifacts', 'unmodeled_artifacts', 'missing_artifacts', 'terminal_modeled'))
    need(all(type(coverage[key]) is int and coverage[key] >= 0
             for key in ('modeled_artifacts', 'unmodeled_artifacts', 'missing_artifacts'))
         and type(coverage['terminal_modeled']) is bool, 'privacy-view-coverage-counts')
    # Recompute rather than admitting caller-supplied candidate arrays/counts.
    checked = [assignments(model['public'], model['constraints']) for model in models]
    return {'schema': 'kpb-private-direct-prediction/v1', 'binding': bound, 'view': view,
            'models': checked, 'coverage': coverage}


def seal(predicted, salt):
    need(type(salt) is bytes and len(salt) == 32 and salt != bytes(32), 'privacy-fresh-secret-capsule-salt')
    raw = CAPSULE_TAG + salt + encoded(predicted)
    return raw, hashlib.sha256(raw).hexdigest()


def unseal(raw, expected_sha256):
    word(expected_sha256)
    need(type(raw) is bytes and len(raw) > 40 and raw[:8] == CAPSULE_TAG and raw[8:40] != bytes(32)
         and hashlib.sha256(raw).hexdigest() == expected_sha256, 'privacy-exact-presealed-capsule')
    value = parse(raw[40:])
    fields(value, ('schema', 'binding', 'view', 'models', 'coverage'))
    need(value['schema'] == 'kpb-private-direct-prediction/v1', 'privacy-capsule-schema')
    expected = prediction(value['binding'], value['view'], value['models'], value['coverage'])
    need(value == expected and encoded(value) == raw[40:], 'privacy-canonical-complete-candidates')
    return value


def truth_record(bound, component, round_number, context_sha256, nf, rows):
    """Call only inside the owning role after actual intent construction."""
    binding(bound); owner(component); word(context_sha256)
    need(type(round_number) is int and round_number in (1, 2) and type(nf) is bytes and len(nf) == 32
         and nf != bytes(32) and type(rows) in (tuple, list) and len(rows) == 2
         and all(type(row) is bytes and len(row) == 520 for row in rows), 'privacy-own-financial-truth-shape')
    hashes = [hashlib.sha256(row).hexdigest() for row in rows]
    need(len(set(hashes)) == 2 and rows[0][:32] != rows[1][:32], 'privacy-own-two-distinct-created-rows')
    return {'schema': 'kpb-private-owner-direct-truth/v1', 'binding': bound, 'owner_component': component,
        'round': round_number, 'context_sha256': context_sha256,
        'input_nf_hex32': nf.hex(), 'outputs': [{'tuple_sha256': digest, 'cm_hex32': row[:32].hex()}
                                             for digest, row in zip(hashes, rows)]}


def check_truth(value, bound):
    fields(value, ('schema', 'binding', 'owner_component', 'round', 'context_sha256',
                   'input_nf_hex32', 'outputs'))
    need(value['schema'] == 'kpb-private-owner-direct-truth/v1' and binding(value['binding']) == bound,
         'privacy-own-truth-frozen-binding')
    owner(value['owner_component']); word(value['context_sha256']); word(value['input_nf_hex32'])
    need(type(value['round']) is int and value['round'] in (1, 2) and type(value['outputs']) is list
         and len(value['outputs']) == 2, 'privacy-own-truth-round-and-count')
    for row in value['outputs']:
        fields(row, ('tuple_sha256', 'cm_hex32')); word(row['tuple_sha256']); word(row['cm_hex32'])
    need(len({row['tuple_sha256'] for row in value['outputs']}) == 2
         and len({row['cm_hex32'] for row in value['outputs']}) == 2, 'privacy-distinct-own-truth')


def mask(rows, predicate):
    return sum(int(predicate(row)) << index for index, row in enumerate(rows))


def score_owner(predicted, owner_truth, capsule_sha256):
    """Produce private membership/count leaves, never a public owner result."""
    word(capsule_sha256)
    need(type(owner_truth) is list and len(owner_truth) == 2, 'privacy-own-two-round-truth-only')
    component = owner_truth[0]['owner_component']
    need(all(row['owner_component'] == component for row in owner_truth)
         and [row['round'] for row in owner_truth] == [1, 2], 'privacy-one-owner-complete-truth')
    result = []
    for model, truth in zip(predicted['models'], owner_truth):
        check_truth(truth, predicted['binding'])
        public = model['public']
        need(truth['round'] == public['round'] and truth['context_sha256'] == public['context_sha256']
             and public['nfs_hex32'].count(truth['input_nf_hex32']) == 1, 'privacy-truth-joins-selected-public-NF')
        input_slot = public['nfs_hex32'].index(truth['input_nf_hex32'])
        output_slots = []
        for own in truth['outputs']:
            need(public['tuple_sha256'].count(own['tuple_sha256']) == 1, 'privacy-truth-joins-selected-public-output')
            slot = public['tuple_sha256'].index(own['tuple_sha256'])
            need(public['cms_hex32'][slot] == own['cm_hex32'], 'privacy-own-CM-tuple-join')
            output_slots.append(slot)
        swapped = 2 - component if component != 1 else 1
        input_masks = [mask(model['inputs'], lambda row, label=label: row[input_slot] == label)
                       for label in (component, swapped)]
        output_masks = [mask(model['outputs'], lambda row, label=label: all(row[i] == label for i in output_slots))
                        for label in (component, swapped)]
        joint_masks = [mask(model['joint'], lambda row, label=label: row['inputs'][input_slot] == label
                           and all(row['outputs'][i] == label for i in output_slots)) for label in (component, swapped)]
        known_inputs = {edge['slot_id'] for edge in model['constraints']['input_edges']
                        if edge['provenance'] == 'colluder-knowledge'}
        known_outputs = {edge['slot_id'] for edge in model['constraints']['creator_edges']
                         if edge['provenance'] == 'colluder-knowledge'}
        def unique(rows, slot):
            labels = {row[slot] for row in rows}
            return next(iter(labels)) if len(labels) == 1 else None
        input_guess = unique(model['inputs'], input_slot)
        guesses = [(slot, unique(model['outputs'], slot)) for slot in output_slots]
        pair_guesses = {tuple(i for i in range(6) if candidate['outputs'][i] == candidate['inputs'][input_slot])
                        for candidate in model['joint']}
        unique_pair = next(iter(pair_guesses)) if len(pair_guesses) == 1 else None
        eligible_in = truth['input_nf_hex32'] not in known_inputs
        eligible_out = [slot for slot in output_slots if public['tuple_sha256'][slot] not in known_outputs]
        result.append({'round': truth['round'], 'input_masks': input_masks, 'output_masks': output_masks,
            'joint_masks': joint_masks, 'eligible_inputs': int(eligible_in), 'eligible_outputs': len(eligible_out),
            'correct_unique_inputs': int(eligible_in and input_guess == component),
            'wrong_unique_inputs': int(eligible_in and input_guess is not None and input_guess != component),
            'correct_unique_outputs': sum(slot in eligible_out and guess == component for slot, guess in guesses),
            'wrong_unique_outputs': sum(slot in eligible_out and guess is not None and guess != component for slot, guess in guesses),
            'correct_unique_pair_links': int(eligible_in and unique_pair == tuple(sorted(output_slots))),
            'wrong_unique_pair_links': int(eligible_in and unique_pair is not None and unique_pair != tuple(sorted(output_slots)))})
    return {'schema': 'kpb-private-direct-score-leaf/v1', 'binding': predicted['binding'],
        'view': predicted['view'], 'capsule_seal_sha256': capsule_sha256, 'owner_component': component,
        'rounds': result}


def aggregate(predicted, leaves, capsule_sha256):
    """Call only in the clean aggregate namespace with all three count leaves."""
    need(type(leaves) is list and len(leaves) == 3
         and sorted(leaf['owner_component'] for leaf in leaves) == [0, 1, 2], 'privacy-three-distinct-private-leaves')
    for leaf in leaves:
        fields(leaf, ('schema', 'binding', 'view', 'capsule_seal_sha256', 'owner_component', 'rounds'))
        need(leaf['schema'] == 'kpb-private-direct-score-leaf/v1' and leaf['binding'] == predicted['binding']
             and leaf['view'] == predicted['view'] and leaf['capsule_seal_sha256'] == capsule_sha256
             and type(leaf['rounds']) is list and len(leaf['rounds']) == 2, 'privacy-one-presealed-common-score')
    result = []
    for index, model in enumerate(predicted['models']):
        rows = [leaf['rounds'][index] for leaf in leaves]
        expected_keys = ('round', 'input_masks', 'output_masks', 'joint_masks', 'eligible_inputs', 'eligible_outputs',
            'correct_unique_inputs', 'wrong_unique_inputs', 'correct_unique_outputs', 'wrong_unique_outputs',
            'correct_unique_pair_links', 'wrong_unique_pair_links')
        counts = {}
        for row in rows:
            fields(row, expected_keys)
            need(row['round'] == index + 1, 'privacy-score-round')
            for kind, size in (('input_masks', len(model['inputs'])), ('output_masks', len(model['outputs'])), ('joint_masks', len(model['joint']))):
                need(type(row[kind]) is list and len(row[kind]) == 2
                     and all(type(item) is int and 0 <= item < (1 << size) for item in row[kind]), 'privacy-bounded-membership-masks')
            for name, limit in (('eligible_inputs', 1), ('eligible_outputs', 2), ('correct_unique_inputs', 1),
                                ('wrong_unique_inputs', 1), ('correct_unique_outputs', 2), ('wrong_unique_outputs', 2),
                                ('correct_unique_pair_links', 1), ('wrong_unique_pair_links', 1)):
                need(type(row[name]) is int and 0 <= row[name] <= limit, 'privacy-bounded-private-count')
                counts[name] = counts.get(name, 0) + row[name]
            need(row['correct_unique_inputs'] + row['wrong_unique_inputs'] <= row['eligible_inputs']
                 and row['correct_unique_pair_links'] + row['wrong_unique_pair_links'] <= row['eligible_inputs']
                 and row['correct_unique_outputs'] + row['wrong_unique_outputs'] <= row['eligible_outputs'],
                 'privacy-correct-wrong-disjoint-counts')
        def common(kind, offset):
            bits = rows[0][kind][offset]
            for row in rows[1:]: bits &= row[kind][offset]
            return bool(bits)
        truth, swapped = common('joint_masks', 0), common('joint_masks', 1)
        coverage = predicted['coverage']
        complete = coverage['missing_artifacts'] == coverage['unmodeled_artifacts'] == 0
        strict = ('FAIL' if not truth or not swapped or model['forbidden_exports'] else
                  'PASS_BOUNDED_DIRECT_CHECK' if complete else 'UNQUALIFIED')
        result.append({'round': index + 1, 'input_owner_assignments': model['input_owner_assignments'],
            'output_creator_assignments': model['output_creator_assignments'], 'output_pair_partitions': model['output_pair_partitions'],
            'joint_candidates': model['joint_candidates'], 'truth_retained': truth,
            'nf_to_created_pair_relations': model['nf_to_created_pair_relations'],
            'nf_pair_candidate_count_histogram': model['nf_pair_candidate_count_histogram'],
            'honest_input_swap_retained': common('input_masks', 1),
            'honest_creator_swap_retained': common('output_masks', 1), 'honest_joint_swap_retained': swapped,
            'forbidden_exports': model['forbidden_exports'], 'strict_H1_status': strict, **counts})
    coverage = predicted['coverage']
    return {'schema': 'kpb-public-direct-linkage-counts/v1', 'binding': predicted['binding'], 'view': predicted['view'],
        'capsule_seal_sha256': capsule_sha256, 'rounds': result, 'coverage': coverage,
        'combined_terminal_status': 'UNQUALIFIED' if not coverage['terminal_modeled'] else
            ('FAIL' if any(row['strict_H1_status'] == 'FAIL' for row in result) else
             'PASS_BOUNDED_DIRECT_CHECK' if all(row['strict_H1_status'] == 'PASS_BOUNDED_DIRECT_CHECK' for row in result)
             else 'UNQUALIFIED'),
        'scope': 'FINITE_DIRECT_CONSTRAINTS_NOT_CRYPTOGRAPHIC_OR_GENERAL_ANONYMITY',
        'posterior_probability_claim': False, 'private_truth_or_per_owner_scores_exported': False}
