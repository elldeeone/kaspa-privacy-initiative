#!/usr/bin/env python3
"""Exact private worker output ABI controls; FD62 remains unselected."""

import copy
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

import privacy_capture_model as capture
import privacy_codec as codec
import privacy_measurement_output_abi as abi


HERE = Path(__file__).resolve().parent
VIEW_KINDS = {
    'public': ('public-projection', 'terminal-history'),
    'dispatcher': (
        'public-projection', 'terminal-history', 'dispatcher-capture'),
    'corrupt-server-plus-wallet': (
        'public-projection', 'terminal-history', 'corrupt-server-capture',
        'colluder-wallet-capture'),
    'union': (
        'public-projection', 'terminal-history', 'dispatcher-capture',
        'corrupt-server-capture', 'colluder-wallet-capture'),
}


def digest(label):
    return hashlib.sha256(label.encode()).hexdigest()


def binding():
    return {
        'method_sha256': digest('method'),
        'selection_sha256': digest('selection'),
        'trial_id': '0d8205ba-82ef-452c-a762-9ad3f17cb91c',
        'phase': 'private-batch-privacy',
        'attempt_id': 'A' * 128,
    }


def public(round_number):
    def words(kind, count):
        return [digest(f'{kind}-{round_number}-{index}')
                for index in range(count)]
    return {
        'round': round_number,
        'projection_sha256': digest(f'projection-{round_number}'),
        'context_sha256': digest(f'context-{round_number}'),
        'nfs_hex32': words('nf', 3),
        'cms_hex32': words('cm', 6),
        'tuple_sha256': words('tuple', 6),
    }


def category_coverage(view):
    kinds = VIEW_KINDS[view]
    categories = sorted(set().union(
        *(capture.ARTIFACT_CATEGORIES[kind] for kind in kinds)))
    result = {}
    for category in categories:
        artifact_bound = 2 * sum(
            category in capture.ARTIFACT_CATEGORIES[kind]
            for kind in kinds)
        field_bound = 2 * sum(
            len(capture.ARTIFACT_LEAKAGE_FIELDS[kind].get(category, ()))
            for kind in kinds)
        result[category] = {
            'modeled_artifacts': artifact_bound,
            'unmodeled_artifacts': 0,
            'missing_artifacts': 0,
            'constraint_modeled_fields': field_bound,
            'source_assumption_covered_fields': 0,
            'unmodeled_fields': 0,
        }
    return result


def maximal_constraints(selected):
    value = codec.empty_constraints()
    value['input_edges'] = [
        {'owner_component': owner, 'slot_id': selected['nfs_hex32'][slot],
         'provenance': provenance}
        for owner in range(3) for slot in range(3)
        for provenance in ('colluder-knowledge', 'direct-export')]
    value['creator_edges'] = [
        {'owner_component': owner,
         'slot_id': selected['tuple_sha256'][slot],
         'provenance': provenance}
        for owner in range(3) for slot in range(6)
        for provenance in ('colluder-knowledge', 'direct-export')]
    pairs = [(left, right) for left in range(6)
             for right in range(left + 1, 6)]
    value['pair_edges'] = [
        {'tuple_sha256': [selected['tuple_sha256'][left],
                          selected['tuple_sha256'][right]],
         'provenance': 'pair-tag-export'}
        for left, right in pairs]
    value['nf_pair_edges'] = [
        {'nf_hex32': selected['nfs_hex32'][nf],
         'tuple_sha256': [selected['tuple_sha256'][left],
                          selected['tuple_sha256'][right]],
         'provenance': provenance}
        for nf in range(3) for left, right in pairs
        for provenance in ('terminal-grouping', 'direct-export',
                           'colluder-knowledge')]
    return value


def capsules(*, full_workload, maximum_constraints=False):
    models = [codec.assignments(
        public(number), maximal_constraints(public(number))
        if maximum_constraints else codec.empty_constraints())
        for number in (1, 2)]
    if full_workload:
        joint = [[left, right]
                 for left in range(len(models[0]['joint']))
                 for right in range(len(models[1]['joint']))]
    else:
        joint = ([[0, 0]] if all(model['joint'] for model in models) else [])
    workload = {
        'schema': 'kpb-two-round-candidate-join/v1',
        'round_candidate_counts': [len(model['joint']) for model in models],
        'cross_round_link_count': 0,
        'cross_round_constraints_modeled': True,
        'terminal_constraints_modeled': True,
        'joint': joint,
        'workload_joint_candidates': len(joint),
        'full_workload_candidates': len(joint),
        'round_candidate_set_commitment_sha256': digest('round-candidates'),
        'candidate_set_commitment_sha256': digest('workload-candidates'),
        'honest_vector_swap_structural_candidates': len(joint),
        'truth_scored': False,
    }
    lattice = {
        'exact_union_artifact_set': True,
        'exact_union_constraints': True,
        'candidate_subset_lattice_verified': True,
        'full_workload_subset_lattice_verified': True,
    }
    result = []
    for index, view in enumerate(codec.VIEWS, 1):
        kinds = VIEW_KINDS[view]
        predicted = codec.prediction(
            binding(), view, models,
            {'modeled_artifacts': 2 * len(kinds),
             'unmodeled_artifacts': 0,
             'missing_artifacts': 0,
             'terminal_modeled': True},
            category_coverage=category_coverage(view), workload=workload,
            lattice_attestation=lattice)
        result.append(codec.seal(predicted, bytes([index]) * 32)[0])
    return result


def score_bundle():
    full_input = (1 << abi.MAX_INPUT_ASSIGNMENTS) - 1
    full_output = (1 << abi.MAX_OUTPUT_ASSIGNMENTS) - 1
    full_joint = (1 << abi.MAX_ROUND_JOINT_CANDIDATES) - 1
    full_workload = (1 << abi.MAX_WORKLOAD_CANDIDATES) - 1
    round_row = {
        'round': 1,
        'input_masks': [full_input, full_input],
        'output_masks': [full_output, full_output],
        'joint_masks': [full_joint, full_joint],
        'eligible_inputs': 1,
        'eligible_outputs': 2,
        'correct_unique_inputs': 1,
        'wrong_unique_inputs': 0,
        'correct_unique_outputs': 2,
        'wrong_unique_outputs': 0,
        'correct_unique_pair_links': 1,
        'wrong_unique_pair_links': 0,
        'nf_pair_candidate_floor_met': True,
    }
    workload_round = {
        key: value for key, value in round_row.items()
        if key not in ('input_masks', 'output_masks', 'joint_masks')
    }
    leaves = []
    for index, view in enumerate(codec.VIEWS):
        second = {**round_row, 'round': 2}
        second_workload = {**workload_round, 'round': 2}
        leaves.append({
            'schema': 'kpb-private-direct-score-leaf/v2',
            'binding': binding(),
            'view': view,
            'capsule_seal_sha256': digest(f'capsule-{index}'),
            'owner_component': 0,
            'rounds': [copy.deepcopy(round_row), second],
            'round_candidate_counts': [
                {'inputs': abi.MAX_INPUT_ASSIGNMENTS,
                 'outputs': abi.MAX_OUTPUT_ASSIGNMENTS,
                 'joint': abi.MAX_ROUND_JOINT_CANDIDATES},
                {'inputs': abi.MAX_INPUT_ASSIGNMENTS,
                 'outputs': abi.MAX_OUTPUT_ASSIGNMENTS,
                 'joint': abi.MAX_ROUND_JOINT_CANDIDATES},
            ],
            'workload_masks': [full_workload, full_workload],
            'workload_candidate_count': abi.MAX_WORKLOAD_CANDIDATES,
            'workload_rounds': [
                copy.deepcopy(workload_round), second_workload],
        })
    return {
        'schema': 'kpb-private-all-view-count-leaves/v2',
        'binding': binding(),
        'run_selection_sha256': digest('run-selection'),
        'owner_component': 0,
        'views': leaves,
    }


class OutputAbiControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.max_capsules = capsules(full_workload=True)
        cls.small_capsules = capsules(full_workload=False)
        cls.max_constraint_capsules = capsules(
            full_workload=False, maximum_constraints=True)
        cls.bundle = score_bundle()

    def test_independent_worst_case_layout_derives_exact_padded_sizes(self):
        # This arithmetic intentionally does not call the production layout
        # helpers. It is the independent source-universe derivation.
        binding_bytes = 32 + 32 + 16 + 1 + 128
        public_round_bytes = 32 + 32 + 3 * 32 + 6 * 32 + 6 * 32
        constraint_round_bytes = (
            1 + 18 + 1 + 36 + 1 + 15 + 1 + 135 * 2 + 1)
        workload_bitmap_bytes = 540 * 540 // 8
        observer_slot_bytes = (
            32 + 2 * constraint_round_bytes + 4 + 32 * 6
            + 1 + 1 + 32 + 32 + 4 + workload_bitmap_bytes)
        observer_used = (
            8 + binding_bytes + 2 * public_round_bytes
            + 4 * observer_slot_bytes + 144 + 256)
        observer_padded = (observer_used + 4095) // 4096 * 4096
        self.assertEqual((observer_used, observer_padded),
                         (151449, 151552))
        self.assertEqual(abi.MAX_CATEGORY_ROWS, len(set().union(*(
            capture.ARTIFACT_CATEGORIES[kind]
            for kind in VIEW_KINDS['union']))))
        self.assertEqual((abi.OBSERVER_OUTPUT_USED_BYTES,
                          abi.OBSERVER_OUTPUT_PADDED_BYTES),
                         (observer_used, observer_padded))

        score_round_bytes = 2 * 1 + 2 * 12 + 2 * 68 + 9
        score_slot_bytes = (
            32 + 2 * 4 + 2 * score_round_bytes + 4
            + 2 * workload_bitmap_bytes + 2 * 9)
        score_used = (8 + binding_bytes + 32 + 1 + 4 * score_slot_bytes)
        score_padded = (score_used + 4095) // 4096 * 4096
        self.assertEqual((score_used, score_padded),
                         (293466, 294912))
        self.assertEqual((abi.OWNER_SCORE_OUTPUT_USED_BYTES,
                          abi.OWNER_SCORE_OUTPUT_PADDED_BYTES),
                         (score_used, score_padded))

    def test_worst_case_observer_and_score_round_trip_at_exact_size(self):
        observed = abi.test_only_encode_observer_capsules_v3(
            self.max_capsules)
        self.assertEqual(len(observed), abi.OBSERVER_OUTPUT_PADDED_BYTES)
        self.assertEqual(abi.decode_observer_capsules(observed),
                         self.max_capsules)
        constrained = abi.test_only_encode_observer_capsules_v3(
            self.max_constraint_capsules)
        self.assertEqual(abi.decode_observer_capsules(constrained),
                         self.max_constraint_capsules)
        scored = abi.encode_owner_score_bundle(self.bundle)
        self.assertEqual(len(scored), abi.OWNER_SCORE_OUTPUT_PADDED_BYTES)
        self.assertEqual(abi.decode_owner_score_bundle(scored), self.bundle)

    def test_observer_v2_phase_inventory_is_exact_and_v1_cannot_authorize(self):
        with self.assertRaisesRegex(ValueError, 'source-authority-required'):
            abi.encode_observer_capsules(self.small_capsules)
        observed = bytearray(
            abi.test_only_encode_observer_capsules_v3(self.small_capsules))
        start = abi.OBSERVER_PHASE_V2_OFFSET
        self.assertEqual(observed[start:start + 8], abi.PHASE_MAGIC)
        self.assertEqual(observed[start + 8:start + 12], b'\x00\x01\x00\x90')
        mutations = {
            'old-top-magic': (7, ord('2')),
            'phase-magic': (start, 0),
            'phase-version': (start + 9, 2),
            'phase-size': (start + 11, 143),
            'view-code': (start + 16, 2),
            'inventory-flag': (start + 17, 0),
            'unmodeled-total': (start + 19, 3),
            'deferred-count': (start + 21, 3),
            'step2-open': (start + 23, 1),
            'record-round': (start + 24, 2),
            'record-artifact': (start + 25, 2),
            'record-family': (start + 26, 3),
            'record-resolution': (start + 27, 2),
            'record-evidence': (start + 28, 2),
            'record-flags': (start + 29, 1),
        }
        for name, (offset, value) in mutations.items():
            with self.subTest(name=name):
                changed = bytearray(observed)
                changed[offset] = value
                with self.assertRaises(ValueError):
                    abi.decode_observer_capsules(bytes(changed))

    def test_observer_v3_step2_inventory_is_exact_open_and_non_authorizing(self):
        observed = bytearray(
            abi.test_only_encode_observer_capsules_v3(self.small_capsules))
        start = abi.OBSERVER_STEP2_V3_OFFSET
        self.assertEqual(start,
                         abi.OBSERVER_PHASE_V2_OFFSET
                         + abi.PHASE_SECTION_BYTES)
        self.assertEqual(abi.OBSERVER_OUTPUT_USED_BYTES,
                         start + abi.STEP2_SECTION_BYTES)
        self.assertEqual(observed[start:start + 8], b'KPBSTP21')
        self.assertEqual(observed[start + 8:start + 20],
                         b'\x00\x01\x01\x00\x04\x1a\x05\x02\x00\x01\x00\x00')
        self.assertEqual(
            tuple(int.from_bytes(observed[start + offset:start + offset + 2],
                                 'big')
                  for offset in (20, 22, 24, 26)),
            (42, 56, 108, 122))
        self.assertEqual(tuple(observed[start + 28:start + 32]),
                         (4, 4, 4, 4))
        self.assertEqual(observed[start + 32:start + 64].hex(),
                         'ee700075720da629ecfed7bc43f9725d14826fc2d0ecd201878a1c2d6bf86708')
        self.assertEqual(observed[start + 64:start + 96].hex(),
                         '3e22997c8932709496c843929e4a0752b3bc7f001690c2119a6692b6388a645a')
        rows = tuple(tuple(observed[start + 96 + index * 6:
                                    start + 102 + index * 6])
                     for index in range(26))
        expected_counts = (
            (0, 0, 4, 4), (0, 0, 6, 6), (0, 2, 0, 2),
            (0, 10, 0, 10), (2, 2, 2, 2), (0, 2, 0, 2),
            (2, 2, 2, 2), (2, 2, 2, 2), (4, 4, 4, 4),
            (2, 2, 2, 2), (2, 2, 2, 2), (0, 0, 20, 20),
            (0, 0, 4, 4), (4, 4, 4, 4), (0, 0, 2, 2),
            (2, 2, 2, 2), (2, 2, 2, 2), (2, 2, 2, 2),
            (2, 2, 2, 2), (0, 0, 18, 18), (2, 2, 2, 2),
            (4, 4, 4, 4), (0, 0, 2, 2), (0, 0, 10, 10),
            (8, 8, 8, 8), (2, 2, 2, 2),
        )
        self.assertEqual(
            rows,
            tuple((index, *counts,
                   2 if 12 <= index <= 20 else 3 if index == 24 else 1)
                  for index, counts in enumerate(expected_counts, 1)))
        self.assertEqual(observed[start + 252:start + 256],
                         b'\x03\xff\x00\x00')
        fields = (
            'attempt.abort_retry_partial_transcript',
            'wire.frames[].direction_peer_fork',
            'wire.frames[].monotonic_ns',
            'wire.frames[].payload_length',
            'wire.frames[].sequence_message_chunk_order',
        )
        self.assertEqual(abi.STEP2_EMPIRICAL_OCCURRENCES,
                         tuple((round_number, field)
                               for round_number in (1, 2)
                               for field in fields))

        mutations = {
            'magic': start,
            'version': start + 9,
            'size': start + 11,
            'view-count': start + 12,
            'family-count': start + 13,
            'empirical-field-count': start + 14,
            'round-count': start + 15,
            'inventory-flags': start + 17,
            'reserved-header': start + 18,
            'view-total': start + 21,
            'deferred-count': start + 28,
            'registry-digest': start + 32,
            'model-digest': start + 64,
            'family-code': start + 96,
            'family-count': start + 97,
            'missing-authority-disposition': start + 101,
            'assumption-disposition': start + 96 + 11 * 6 + 5,
            'empirical-disposition': start + 96 + 23 * 6 + 5,
            'empirical-mask': start + 253,
            'reserved-tail': start + 254,
        }
        for name, offset in mutations.items():
            with self.subTest(name=name):
                changed = bytearray(observed)
                changed[offset] ^= 1
                with self.assertRaises(ValueError):
                    abi.decode_observer_capsules(bytes(changed))

        downgraded = bytearray(observed)
        downgraded[7] = ord('2')
        downgraded[start:] = bytes(len(downgraded) - start)
        with self.assertRaises(ValueError):
            abi.decode_observer_capsules(bytes(downgraded))

    def test_four_ordered_unique_view_slots_and_finite_counts_refuse_tamper(self):
        for changed in (
                self.small_capsules[:3],
                [self.small_capsules[1], self.small_capsules[0],
                 *self.small_capsules[2:]],
                [self.small_capsules[0], self.small_capsules[0],
                 *self.small_capsules[2:]]):
            with self.subTest(kind='observer-cardinality'):
                with self.assertRaises(ValueError):
                    abi.test_only_encode_observer_capsules_v3(changed)

        predicted = codec.unseal(
            self.small_capsules[0],
            hashlib.sha256(self.small_capsules[0]).hexdigest())
        predicted['models'][0]['constraints']['input_edges'] = [{
            'owner_component': 0,
            'slot_id': predicted['models'][0]['public']['nfs_hex32'][0],
            'provenance': 'direct-export',
        }] * 2
        duplicated = codec.seal(predicted, b'\x71' * 32)[0]
        with self.assertRaises(ValueError):
            abi.test_only_encode_observer_capsules_v3(
                [duplicated, *self.small_capsules[1:]])

        def changed_constraints(constraints, salt):
            selected = codec.unseal(
                self.small_capsules[0],
                hashlib.sha256(self.small_capsules[0]).hexdigest())
            selected['models'][0] = codec.assignments(
                selected['models'][0]['public'], constraints)
            selected['workload']['round_candidate_counts'] = [
                len(model['joint']) for model in selected['models']]
            selected['workload']['joint'] = [[0, 0]]
            selected['workload']['workload_joint_candidates'] = 1
            selected['workload']['full_workload_candidates'] = 1
            selected['workload'][
                'honest_vector_swap_structural_candidates'] = 1
            return codec.seal(selected, bytes([salt]) * 32)[0]

        selected_public = public(1)
        reordered = codec.empty_constraints()
        reordered['input_edges'] = [
            {'owner_component': 1,
             'slot_id': selected_public['nfs_hex32'][1],
             'provenance': 'direct-export'},
            {'owner_component': 0,
             'slot_id': selected_public['nfs_hex32'][0],
             'provenance': 'direct-export'},
        ]
        reversed_pair = codec.empty_constraints()
        reversed_pair['pair_edges'] = [{
            'tuple_sha256': [selected_public['tuple_sha256'][1],
                             selected_public['tuple_sha256'][0]],
            'provenance': 'pair-tag-export',
        }]
        for changed in (changed_constraints(reordered, 0x72),
                        changed_constraints(reversed_pair, 0x73)):
            with self.subTest(kind='observer-canonical-edge-order'):
                with self.assertRaises(ValueError):
                    abi.test_only_encode_observer_capsules_v3(
                        [changed, *self.small_capsules[1:]])

        changed = copy.deepcopy(self.bundle)
        changed['views'][1] = copy.deepcopy(changed['views'][0])
        with self.assertRaises(ValueError):
            abi.encode_owner_score_bundle(changed)
        changed = copy.deepcopy(self.bundle)
        changed['views'][0]['workload_candidate_count'] += 1
        with self.assertRaises(ValueError):
            abi.encode_owner_score_bundle(changed)

    def test_python_and_cpp_tables_and_parsers_match_exact_fixtures(self):
        observer = abi.test_only_encode_observer_capsules_v3(
            self.small_capsules)
        score = abi.encode_owner_score_bundle(self.bundle)
        header = (HERE / 'privacy_measurement_output_abi.hpp').read_text()
        self.assertIn('"' + abi.OBSERVER_OUTPUT_ABI_IDENTITY + '"', header)
        self.assertIn('"' + abi.OWNER_SCORE_OUTPUT_ABI_IDENTITY + '"', header)
        with tempfile.TemporaryDirectory(prefix='kpb-output-abi-') as raw:
            root = Path(raw)
            (root / 'observer.bin').write_bytes(observer)
            (root / 'score.bin').write_bytes(score)
            source = root / 'control.cpp'
            source.write_text(r'''
#include "privacy_measurement_output_abi.hpp"
#include <algorithm>
#include <array>
#include <cassert>
#include <fstream>
#include <iterator>
#include <vector>
using namespace kpb::measurement::runtime_bridge;
std::vector<unsigned char> read(const char* path) {
    std::ifstream stream(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(stream), {}};
}
int main(int argc, char** argv) {
    assert(argc == 3);
    static_assert(OBSERVER_OUTPUT_ABI.version == 3);
    static_assert(OBSERVER_OUTPUT_ABI.used_bytes == 151449);
    static_assert(OBSERVER_OUTPUT_ABI.exact_bytes == 151552);
    static_assert(OWNER_SCORE_OUTPUT_ABI.used_bytes == 293466);
    static_assert(OWNER_SCORE_OUTPUT_ABI.exact_bytes == 294912);
    static_assert(kMeasurementOutputAbiStatus
                      .owner_score_exact_lineage_parser);
    static_assert(OUTPUT_ABI_CATEGORY_ROWS == 32);
    static_assert(OBSERVER_STEP2_EMPIRICAL_OCCURRENCES.size() == 10);
    static_assert(OBSERVER_STEP2_EMPIRICAL_OCCURRENCES.front().round == 1);
    static_assert(OBSERVER_STEP2_EMPIRICAL_OCCURRENCES.back().round == 2);
    auto observer = read(argv[1]); auto score = read(argv[2]);
    assert(validate_measurement_output_abi(
        RuntimeChildRole::Observer, observer));
    assert(validate_observer_phase_v2_section(std::span(
        observer).subspan(OBSERVER_PHASE_V2_OFFSET,
                          OBSERVER_PHASE_V2_BYTES)));
    assert(validate_observer_step2_v3_section(std::span(
        observer).subspan(OBSERVER_STEP2_V3_OFFSET,
                          OBSERVER_STEP2_V3_BYTES)));
    const std::array<std::size_t, 10> step2_mutations{
        0, 21, 28, 32, 64, 96, 101, 167, 239, 253};
    for (const auto relative : step2_mutations) {
        observer[OBSERVER_STEP2_V3_OFFSET + relative] ^= 1;
        assert(!validate_measurement_output_abi(
            RuntimeChildRole::Observer, observer));
        assert(!validate_observer_step2_v3_section(std::span(
            observer).subspan(OBSERVER_STEP2_V3_OFFSET,
                              OBSERVER_STEP2_V3_BYTES)));
        observer[OBSERVER_STEP2_V3_OFFSET + relative] ^= 1;
    }
    observer[7] = '2';
    std::fill(observer.begin() + OBSERVER_STEP2_V3_OFFSET, observer.end(), 0);
    assert(!validate_measurement_output_abi(
        RuntimeChildRole::Observer, observer));
    observer = read(argv[1]);
    assert(validate_measurement_output_abi(
        RuntimeChildRole::OwnerScore, score));
    observer.back() = 1;
    assert(!validate_measurement_output_abi(
        RuntimeChildRole::Observer, observer));
    observer = read(argv[1]);
    constexpr std::size_t observer_header = 1305;
    constexpr std::size_t observer_slot = 37436;
    std::copy(observer.begin() + observer_header,
              observer.begin() + observer_header + 32,
              observer.begin() + observer_header + observer_slot);
    assert(!validate_measurement_output_abi(
        RuntimeChildRole::Observer, observer));
    score = read(argv[2]);
    constexpr std::size_t score_header = 250;
    constexpr std::size_t score_slot = 73304;
    OwnerScoreOutputBindingExpectation expected{};
    std::copy_n(score.begin() + 8, 32, expected.method_sha256.begin());
    std::copy_n(score.begin() + 40, 32,
                expected.selection_sha256.begin());
    std::copy_n(score.begin() + 72, 16, expected.trial_id.begin());
    expected.attempt_length = score.at(88);
    std::copy_n(score.begin() + 89, 128, expected.attempt_id.begin());
    std::copy_n(score.begin() + 217, 32,
                expected.run_selection_sha256.begin());
    expected.owner = score.at(249);
    assert(validate_owner_score_output_abi_for_expected_lineage(
        score, expected));
    const std::array<std::size_t, 6> lineage_mutations{
        8, 40, 72, 89, 217, 249};
    const std::array<unsigned char, 6> lineage_masks{1, 1, 1, 3, 1, 1};
    for (std::size_t index = 0; index < lineage_mutations.size(); ++index) {
        const auto offset = lineage_mutations[index];
        score[offset] ^= lineage_masks[index];
        assert(validate_measurement_output_abi(
            RuntimeChildRole::OwnerScore, score));
        assert(!validate_owner_score_output_abi_for_expected_lineage(
            score, expected));
        score[offset] ^= lineage_masks[index];
    }
    std::copy(score.begin() + score_header,
              score.begin() + score_header + 32,
              score.begin() + score_header + score_slot);
    assert(!validate_measurement_output_abi(
        RuntimeChildRole::OwnerScore, score));
    assert(!validate_measurement_output_abi(
        RuntimeChildRole::OwnerScore, read(argv[1])));
    assert(!measurement_output_abi(RuntimeChildRole::Aggregate));
    assert(!measurement_output_abi(RuntimeChildRole::OwnerComparison));
    const auto test_observer = test_only_measurement_output_abi_body(
        RuntimeChildRole::Observer);
    const auto test_score = test_only_measurement_output_abi_body(
        RuntimeChildRole::OwnerScore, 1);
    assert(validate_measurement_output_abi(
        RuntimeChildRole::Observer, test_observer));
    assert(validate_measurement_output_abi(
        RuntimeChildRole::OwnerScore, test_score));
}
''', encoding='utf-8')
            compiled = subprocess.run([
                'c++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-DKPB_MEASUREMENT_OUTPUT_ABI_TEST_SETUP',
                '-I', str(HERE), str(source),
                str(HERE / 'privacy_measurement_output_abi.cpp'),
                '-o', str(root / 'control')],
                text=True, capture_output=True, check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([
                str(root / 'control'), str(root / 'observer.bin'),
                str(root / 'score.bin')], text=True, capture_output=True,
                check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_adjacent_authority_friend_names_cannot_be_redefined(self):
        probes = {
            'output-before': r'''
namespace kpb::measurement::runtime_bridge {
class MeasurementChildOutputPlane final {};
}
#include "privacy_measurement_child_output_authority.hpp"
''',
            'output-after': r'''
#include "privacy_measurement_child_output_authority.hpp"
namespace kpb::measurement::runtime_bridge {
class MeasurementChildOutputPlane final {};
}
''',
            'worker-before': r'''
namespace kpb::measurement::runtime_bridge {
class MeasurementChildSupervisor final {};
}
#include "privacy_measurement_worker_capsule.hpp"
''',
            'observer-before': r'''
namespace kpb::measurement::runtime_bridge {
class ObserverCaptureCapsuleBridge final {};
}
#include "privacy_measurement_worker_capsule.hpp"
''',
        }
        with tempfile.TemporaryDirectory(
                prefix='kpb-output-abi-hostile-friends-') as raw:
            root = Path(raw)
            for name, body in probes.items():
                with self.subTest(name=name):
                    source = root / f'{name}.cpp'
                    source.write_text(body + '\nint main() {}\n',
                                      encoding='utf-8')
                    compiled = subprocess.run([
                        'c++', '-std=c++20', '-I', str(HERE),
                        '-fsyntax-only', str(source)], text=True,
                        capture_output=True, check=False)
                    self.assertNotEqual(compiled.returncode, 0,
                                        'hostile friend redefinition compiled')


if __name__ == '__main__':
    unittest.main()
