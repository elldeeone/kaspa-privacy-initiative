#!/usr/bin/env python3
"""Nonauthorizing end-to-end readiness check for the frozen observer chain.

This module accepts only sealed, synthetic, complete capture material.  It
recomputes the four fixed views and the two-round terminal workload, then
checks the real public capture, observation, barrier, three-owner-score and
aggregate receipt contracts.  Success means only that an actual source-owned
capture may be attempted.  It never mints a privacy result or launch authority.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys

import privacy_acceptance as acceptance
import privacy_actual_capture as actual_capture
import privacy_capture_bundle as capture_bundle
import privacy_capture_model as capture_model
import privacy_codec as codec
import privacy_roles as roles


INPUT_SCHEMA = 'kpb-private-observer-readiness-input/v1'
RESULT_SCHEMA = 'kpb-private-observer-readiness-result/v1'
CLASSIFICATION = 'SYNTHETIC_COMPLETE_ARTIFACT_READINESS_ONLY'
READY = 'READY_FOR_ACTUAL_CAPTURE'
STOP_INPUT_SHAPE = 'STOP_INPUT_SHAPE'
STOP_SYNTHETIC_SEAL = 'STOP_SYNTHETIC_SEAL'
STOP_ASSUMPTION_SELECTION = 'STOP_ASSUMPTION_SELECTION'
STOP_MODEL_RECOMPUTATION = 'STOP_MODEL_RECOMPUTATION'
STOP_STEP2_OPEN = 'STOP_STEP2_OPEN'
STOP_MISSING_OR_UNMODELED = 'STOP_MISSING_OR_UNMODELED'
STOP_TRUTH_BEFORE_BARRIER = 'STOP_TRUTH_BEFORE_BARRIER'
STOP_PRETRUTH_CHAIN = 'STOP_PRETRUTH_CHAIN'
STOP_SCORER_CHAIN = 'STOP_SCORER_CHAIN'
STOP_AGGREGATE_CHAIN = 'STOP_AGGREGATE_CHAIN'
STOP_LATTICE = 'STOP_LATTICE'
STOP_BASELINE_CANDIDATE_COMPARISON = \
    'STOP_BASELINE_CANDIDATE_COMPARISON'
STOP_PASS_CLAIM = 'STOP_PASS_CLAIM'
STOP_ACTION_REQUEST = 'STOP_ACTION_REQUEST'
STOP_REASONS = frozenset({
    STOP_INPUT_SHAPE, STOP_SYNTHETIC_SEAL, STOP_ASSUMPTION_SELECTION,
    STOP_MODEL_RECOMPUTATION, STOP_STEP2_OPEN,
    STOP_MISSING_OR_UNMODELED, STOP_TRUTH_BEFORE_BARRIER,
    STOP_PRETRUTH_CHAIN, STOP_SCORER_CHAIN, STOP_AGGREGATE_CHAIN,
    STOP_LATTICE, STOP_BASELINE_CANDIDATE_COMPARISON, STOP_PASS_CLAIM,
    STOP_ACTION_REQUEST,
})

# This is the finite family/profile preimage from the reviewed combined
# P1+C1+public ledger.  S6 and S6A remain alternatives; this bounded readiness
# profile explicitly chooses S6A and records why S6 is not selected.  S13 is a
# reduction target and is never treated as a selectable cryptographic premise.
ASSUMPTION_FAMILIES = (
    'S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S6A', 'S7', 'S8', 'S9',
    'S10', 'S11', 'S12', 'S13',
)
ASSUMPTION_DISPOSITIONS = {
    **{name: 'SYNTHETIC_SELECTED_FOR_READINESS_ONLY'
       for name in ASSUMPTION_FAMILIES
       if name not in ('S6', 'S13')},
    'S6': 'REPLACED_BY_SELECTED_S6A',
    'S13': 'NONSELECTABLE_REDUCTION_TARGET_OPEN_UNRESOLVED',
}
SELECTED_ASSUMPTION_FAMILIES = tuple(
    family for family in ASSUMPTION_FAMILIES
    if ASSUMPTION_DISPOSITIONS[family] ==
        'SYNTHETIC_SELECTED_FOR_READINESS_ONLY')
ASSUMPTION_DEPENDENCIES = {
    'S1': (),
    'S2': ('S8', 'S9'),
    'S3': (),
    'S4': (),
    'S5': ('S6A',),
    'S6': ('S6A',),
    'S6A': (),
    'S7': ('S8', 'S9'),
    'S8': (),
    'S9': ('S8',),
    'S10': ('S8',),
    'S11': ('S8', 'S10'),
    'S12': ('S8', 'S10', 'S11'),
    'S13': ('S1', 'S2', 'S3', 'S4', 'S5', 'S6A', 'S7', 'S8',
            'S9', 'S10', 'S11', 'S12'),
}

VIEW_KINDS = {
    'public': ('public-projection', 'terminal-history'),
    'dispatcher': ('public-projection', 'terminal-history',
                   'dispatcher-capture'),
    'corrupt-server-plus-wallet': (
        'public-projection', 'terminal-history', 'corrupt-server-capture',
        'colluder-wallet-capture'),
    'union': ('public-projection', 'terminal-history',
              'dispatcher-capture', 'corrupt-server-capture',
              'colluder-wallet-capture'),
}
ARTIFACT_ORDER = (
    'public-projection', 'terminal-history', 'dispatcher-capture',
    'corrupt-server-capture', 'colluder-wallet-capture',
)
ROLE_BY_KIND = {
    'public-projection': 'financial-release',
    'terminal-history': 'terminal-controller',
    'dispatcher-capture': 'private-dispatcher',
    'corrupt-server-capture': 'server-P1',
    'colluder-wallet-capture': 'owner-C1',
}
MASCOT_BRANCH_REQUIREMENTS = {
    'schema': 'kpb-observer-readiness-mascot-branch-requirements/v1',
    'cache_hit_or_static_reuse': {
        'same_local_alpha_required': True,
        'complete_key_pre_post_chain_required': True,
        'get_fresh_preserves_scalar': True,
        'get_fresh_advances_embedded_ot_triple_setup': True,
    },
    'regenerated_after_missing_local_or_peer_reject': {
        'replacement_alpha_permitted': True,
        'authenticated_rejection_regeneration_writeback_required': True,
        'teardown_install_continuity_required': True,
    },
    'abort_or_retry_partial_prefix_disposition': 'UNAVAILABLE',
}
MASCOT_PROCESS_STATE_MISSING = {
    'schema': 'kpb-observer-readiness-mascot-process-state-applicability/v1',
    'source_receipt_schema': 'kpi-p1-mascot-secret-state/v2',
    'source_receipt_present': False,
    'selected_live_capsule': False,
    'persistent_child_thread_file_lifecycle': 'MISSING',
    'process_state_applicability': 'MISSING',
    'process_state_authority': False,
}
P1_ACTUAL_RUN_MISSING_FAMILIES = (
    'MASCOT_COMPLETE_KEY_CACHE_THREAD_AND_FILE_LIFECYCLE',
    'SIMPLEST_OT_RANDOM_TAPE',
    'SOFTSPOKEN_OT_RANDOM_TAPE',
    'ON_DEMAND_OT_MAP_CACHE_AND_PRNG_STATE',
    'BEAVER_RANDOMNESS_AND_CAPTURE_CORRESPONDENCE',
    'MAC_CHECK_RANDOMNESS_AND_TRANSCRIPT_STATE',
    'TLS_AND_NETWORK_PROCESS_STATE',
    'QUERY_MSM_TEMPORARIES_AND_CAPTURE_CORRESPONDENCE',
    'ABORT_RETRY_PARENT_RECONSTRUCTION',
)

# The typed future inventories split four public byte families and the C03
# authenticated group state more finely than the already-frozen public receipt
# ABI.  This is a count-only projection into that ABI, not another schema: all
# source categories are checked first, and none may be missing or open.
LEGACY_CATEGORY_SOURCES = {
    'public-bytes': (
        'ciphertexts', 'context-identities', 'state-transition',
        'value-commitments'),
    'authenticated-transcript': (
        'authenticated-transcript', 'authenticated-group-state'),
}

OUTER_FIELDS = (
    'schema', 'classification', 'assumption_selection', 'baseline',
    'candidate', 'owner_comparison', 'truth_mounted_before_barrier',
    'requested_actions', 'claimed_privacy_status', 'preimage_sha256',
)
RUN_FIELDS = (
    'classification', 'run_context', 'capture_models', 'capture_receipt',
    'observation_receipt', 'barrier', 'scoring_transcript',
    'score_receipts', 'aggregate_result', 'acceptance_bundle',
)
RUN_CONTEXT_FIELDS = (
    'classification', 'binding', 'capture_identity', 'method_sha256',
    'workload_sha256', 'observer_source_sha256', 'capture_source_sha256',
    'coverage_policy_sha256', 'capture_producer_receipt_sha256',
    'capture_producer_role_launch_sha256',
    'capture_producer_role_launch_closure',
    'typed_artifact_manifest_sha256', 'mascot_process_state',
    'source_closure_sha256', 'runtime_identity_sha256',
)
ASSUMPTION_SELECTION_FIELDS = (
    'schema', 'configured', 'selected_assumptions', 'selection_authority',
)
ASSUMPTION_ROW_FIELDS = (
    'family', 'disposition', 'dependencies', 'preimage', 'preimage_sha256',
    'applicability_identity_sha256', 'synthetic_readiness_only',
)
REQUEST_FIELDS = (
    'production_configured', 'launch', 'network', 'funds', 'mainnet',
)
PRETRUTH_ROUND_FIELDS = (
    'round', 'input_owner_assignments', 'output_creator_assignments',
    'output_pair_partitions', 'joint_candidates',
    'nf_to_created_pair_relations', 'nf_pair_candidate_count_histogram',
    'forbidden_exports',
)
SCORING_FIELDS = ('schema', 'barrier_sha256', 'views')
SCORING_VIEW_FIELDS = (
    'view', 'capsule_seal_sha256', 'owner_truth',
)
PUBLIC_INVENTORY_FIELDS = (
    'schema', 'projection_bytes', 'prefix_bytes', 'body_bytes',
    'body_core_bytes', 'spend_rows', 'output_rows', 'ciphertext_bytes',
    'output_proof_bytes', 'nf_witness_bytes', 'cm_path_bytes',
    'aggregate_proof_bytes', 'byte_lane_count', 'byte_lane_total_bytes',
    'byte_lanes', 'byte_lane_manifest_sha256',
    'context_identifiers_hex32', 'reserve_outpoint_hex36',
    'old_cm_root_hex32', 'old_nf_root_hex32', 'new_cm_root_hex32',
    'new_nf_root_hex32', 'old_cm_count', 'old_nf_count', 'new_cm_count',
    'new_nf_count', 'nf_witness_public_history_edges',
    'same_projection_public_byte_equalities',
    'honest_encryption_producer_authority_consumed',
    'complete_public_multiattempt_history_joined',
    'structural_continuity_authority_consumed',
    'structural_continuity_candidate_count_before',
    'structural_continuity_candidate_count_after',
    'accepted_chain_continuity_proven', 'cv_model', 'reserve_sompi',
    'remaining_sompi', 'fee_sompi', 'aggregate_value_constraints',
    'individual_input_amount_fields', 'individual_output_amount_fields',
    'owner_label_fields', 'direct_constraint_count',
    'proof_validity_or_privacy_claim',
)
TERMINAL_INVENTORY_FIELDS = (
    'schema', 'projection_sha256', 'event_count', 'group_count',
    'individual_amount_observation_count', 'retry_count',
    'rejected_or_orphaned_count', 'reorg_count', 'cross_round_link_count',
    'attempt_id', 'cohort_sha256', 'direct_constraint_count',
)
DISPATCHER_INVENTORY_FIELDS = (
    'schema', 'event_count', 'retry_count', 'owner_connection_count',
    'owner_upload_count', 'aggregate_release_count',
    'outbound_route_count', 'attempt_id', 'cohort_sha256',
    'construction_classification', 'release_order_policy',
    'release_policy_binding_count', 'source_bound_policy_authority',
    'private_body_or_hash_captured', 'direct_constraint_count',
)
C1_INVENTORY_FIELDS = (
    'schema', 'original_count', 'input_count', 'created_output_count',
    'invoice_count', 'decrypted_receipt_count', 'retry_count',
    'input_amount_sompi', 'created_amounts_sompi',
    'invoice_amounts_sompi', 'receipt_amounts_sompi',
    'public_individual_amount_join_fields',
    'source_bound_contact_value_authority',
    'candidate_count_before_contact_value',
    'candidate_count_after_contact_value', 'candidate_pruned_count',
    'attempt_id', 'cohort_sha256', 'direct_constraint_count',
    'cryptographic_privacy_claim',
)
P1_INVENTORY_FIELDS = (
    'schema', 'record_count', 'record_bytes', 'semantics',
    'owner_offset_count', 'owner_preprocessing_share_count',
    'owner_preprocessing_to_offset_width_ratio', 'mac_key_share_count',
    'masked_field_intermediate_count', 'masked_g1_intermediate_count',
    'final_proof_g1_count', 'final_proof_g2_count',
    'authenticated_g1_stage_object_counts',
    'authenticated_g2_stage_object_counts', 'direct_constraint_count',
    'attempt_id', 'cohort_sha256', 'observer_scope',
    'out_of_scope_unqualified_boundaries',
    'cryptographic_independence_or_privacy_claim',
    'c03_source_build_launch_role_bound', 'c03_wire_frame_count',
    'c03_wire_bytes', 'c03_wire_sha256', 'c03_fixed_fd',
    'c03_source_sha256', 'c03_build_sha256', 'c03_launch_sha256',
    'c03_model_preimage_sha256', 'c03_query_store_preimage_sha256',
    'c03_scalar_capture_manifest_sha256', 'c03_scalar_binding_count',
    'c03_scalar_site_bitmap',
    'c03_authenticated_group_equation_constraints', 'c03_wire_closure',
)
TYPED_ARTIFACT_FIELDS = (
    'schema', 'kind', 'round', 'artifact_sha256', 'constraints',
    'categories', 'inventory', 'leakage_ledger', 'terminal_modeled',
    'cross_round_links',
)
P1_WIRE_CLOSURE_FIELDS = (
    'schema', 'attempt_id', 'cohort_sha256', 'producer_record_count',
    'capture_record_count', 'producer_payload_bytes',
    'capture_payload_bytes', 'producer_stream_counts',
    'capture_stream_counts', 'record_chain_sha256',
    'unknown_record_count', 'capture_root_closed', 'producer_fd_closed',
    'raw_wire_bytes', 'raw_wire_sha256', 'end_frame_identity',
    'eof_identity',
)

SOURCE_STATUS = {
    'schema': 'kpb-private-observer-readiness-source-status/v1',
    'readiness_mechanics_implemented': False,
    'serialized_assumption_selection_is_authority': False,
    'production_configured': False,
    'actual_capture_configured': False,
    'launch_authorized': False,
    'network_enabled': False,
    'funds_enabled': False,
    'mainnet_enabled': False,
    'privacy_status_minted': False,
    'truth_chronology_self_report_authority': False,
    'mascot_round_alpha_independence_assumed': False,
    'mascot_cache_hit_same_alpha_required': True,
    'mascot_process_state_applicability': 'MISSING',
    'mascot_process_state_authority': False,
    'p1_actual_run_closure_applicability': 'MISSING',
    'p1_actual_run_closure_authority': False,
    'p1_actual_run_missing_families': P1_ACTUAL_RUN_MISSING_FAMILIES,
}


class _Stop(Exception):
    def __init__(self, status):
        super().__init__(status)
        self.status = status


def _stop(condition, status):
    if not condition:
        raise _Stop(status)


def _exact(value, names, status=STOP_INPUT_SHAPE):
    _stop(type(value) is dict and set(value) == set(names), status)
    return value


def _word(value, status=STOP_INPUT_SHAPE):
    _stop(type(value) is str and re.fullmatch('[0-9a-f]{64}', value),
          status)
    return value


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def _same_json(actual, expected):
    """Compare canonical JSON values without Python's bool/int aliasing."""
    try:
        return encoded(actual) == encoded(expected)
    except (TypeError, ValueError):
        return False


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('observer-readiness-duplicate-json-field')
            result[key] = value
        return result

    value = json.loads(
        raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(
            ValueError('observer-readiness-nonfinite-number')))
    if encoded(value) != raw:
        raise ValueError('observer-readiness-noncanonical-json')
    return value


def read_canonical(path):
    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size <= 0
                or metadata.st_size > (256 << 20)):
            raise ValueError('observer-readiness-input-file-shape')
        chunks = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1 << 20))
            if not chunk:
                raise ValueError('observer-readiness-short-input')
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError('observer-readiness-growing-input')
    finally:
        os.close(descriptor)
    return parse(b''.join(chunks))


def seal_preimage(value):
    """Return a copy carrying the canonical whole-input synthetic seal."""
    _exact(value, OUTER_FIELDS[:-1])
    sealed = dict(value)
    sealed['preimage_sha256'] = digest(value)
    return sealed


def _result(status):
    _stop(status == READY or status in STOP_REASONS, STOP_INPUT_SHAPE)
    return {
        'schema': RESULT_SCHEMA,
        'status': status,
        'classification': CLASSIFICATION,
        'production_configured': False,
        'actual_capture_configured': False,
        'launch_authorized': False,
        'network_enabled': False,
        'funds_enabled': False,
        'mainnet_enabled': False,
        'privacy_status_minted': False,
        'privacy_pass_claim': False,
    }


def _family_preimage(family):
    result = {
        'schema': 'kpb-observer-readiness-assumption-family/v1',
        'family': family,
        'disposition': ASSUMPTION_DISPOSITIONS[family],
        'dependencies': list(ASSUMPTION_DEPENDENCIES[family]),
        'profile': 'BOUNDED_S6A_SYNTHETIC_READINESS_ONLY',
    }
    if family == 'S8':
        result['mascot_branch_requirements'] = MASCOT_BRANCH_REQUIREMENTS
        result['mascot_process_state'] = MASCOT_PROCESS_STATE_MISSING
        result['process_state_is_not_covered_by_s8'] = True
    return result


def _field_assumption_family(kind, category, field_path):
    """Map one frozen nonliteral field to its exact selected family."""
    try:
        resolution = capture_model._unmodeled_resolution(
            kind, category, field_path)
    except ValueError:
        return None
    if resolution['proposed_resolution'] != \
            'source_assumption_pending_selection':
        return None
    requirement = resolution['evidence_requirement']
    direct = {
        'PINNED_SHA256_NOTE_COMMITMENT_HIDING_ASSUMPTION': 'S1',
        'PINNED_PEDERSEN_CV_JOINT_VIEW_ASSUMPTION': 'S2',
        'PINNED_OUTPUT_CIPHERTEXT_JOINT_CONFIDENTIALITY_ASSUMPTION':
            'S5',
        'PINNED_NULLIFIER_PRF_AND_UNLINKABILITY_ASSUMPTION': 'S7',
        'PINNED_STOCK_MASCOT_JOINT_VIEW_ASSUMPTION': 'S8',
        'PINNED_DDNNT_5N_OWNER_INPUT_ASSUMPTION': 'S9',
        'PINNED_AUTHENTICATED_GROUP_VIEW_ASSUMPTION': 'S10',
        'PINNED_MIXED_PROTOCOL_JOINT_VIEW_ASSUMPTION': 'S11',
    }
    if requirement in direct:
        return direct[requirement]
    if requirement == 'PINNED_GROTH16_PUBLIC_PROOF_ZK_ASSUMPTION':
        return ('S4' if kind == 'public-projection'
                and field_path == 'outputs[].proof_bytes' else 'S12')
    raise _Stop(STOP_ASSUMPTION_SELECTION)


def _synthetic_applicability_identity(family):
    return hashlib.sha256(
        b'KPB_OBSERVER_READINESS_SYNTHETIC_APPLICABILITY_V1\n'
        + family.encode()).hexdigest()


def _test_only_assumption_selection_preimage():
    """Build a deterministic *synthetic* exact family preimage for tests.

    This helper creates no applicability or selection authority.  Callers must
    still seal the complete outer input, and production remains CONFIGURED0.
    """
    rows = []
    for family in ASSUMPTION_FAMILIES:
        family_preimage = _family_preimage(family)
        rows.append({
            'family': family,
            'disposition': ASSUMPTION_DISPOSITIONS[family],
            'dependencies': list(ASSUMPTION_DEPENDENCIES[family]),
            'preimage': family_preimage,
            'preimage_sha256': digest(family_preimage),
            'applicability_identity_sha256':
                _synthetic_applicability_identity(family),
            'synthetic_readiness_only': True,
        })
    return {
        'schema': 'kpb-private-observer-assumption-selection/v1',
        'configured': True,
        'selected_assumptions': rows,
        'selection_authority': False,
    }


def _validate_assumptions(value):
    _exact(value, ASSUMPTION_SELECTION_FIELDS, STOP_ASSUMPTION_SELECTION)
    _stop(value['schema'] ==
          'kpb-private-observer-assumption-selection/v1'
          and value['configured'] is True
          and value['selection_authority'] is False
          and type(value['selected_assumptions']) is list
          and len(value['selected_assumptions']) ==
              len(ASSUMPTION_FAMILIES),
          STOP_ASSUMPTION_SELECTION)
    identities = set()
    for expected, row in zip(ASSUMPTION_FAMILIES,
                             value['selected_assumptions']):
        _exact(row, ASSUMPTION_ROW_FIELDS, STOP_ASSUMPTION_SELECTION)
        _stop(row['family'] == expected
              and row['disposition'] == ASSUMPTION_DISPOSITIONS[expected]
              and row['dependencies'] ==
                  list(ASSUMPTION_DEPENDENCIES[expected])
              and _same_json(row['preimage'], _family_preimage(expected))
              and row['synthetic_readiness_only'] is True,
              STOP_ASSUMPTION_SELECTION)
        _word(row['preimage_sha256'], STOP_ASSUMPTION_SELECTION)
        _stop(row['preimage_sha256'] == digest(_family_preimage(expected)),
              STOP_ASSUMPTION_SELECTION)
        identity = _word(row['applicability_identity_sha256'],
                         STOP_ASSUMPTION_SELECTION)
        _stop(identity == _synthetic_applicability_identity(expected)
              and identity not in identities, STOP_ASSUMPTION_SELECTION)
        identities.add(identity)
    return {row['family']: row['preimage_sha256']
            for row in value['selected_assumptions']
            if row['family'] in SELECTED_ASSUMPTION_FAMILIES}


def _validate_role_launch_closure(value, expected_sha256):
    _stop(type(value) is list and len(value) == 10,
          STOP_MODEL_RECOMPUTATION)
    _stop(digest(value) == expected_sha256, STOP_MODEL_RECOMPUTATION)
    result = {}
    expected_order = [(round_number, kind)
                      for round_number in (1, 2)
                      for kind in ARTIFACT_ORDER]
    for expected, row in zip(expected_order, value):
        base_fields = (
            'round', 'kind', 'role', 'source_sha256', 'build_sha256',
            'launch_sha256', 'fixed_fd',
        )
        p1_fields = (
            'model_preimage_sha256', 'query_store_preimage_sha256',
            'scalar_capture_manifest_sha256',
        )
        _exact(row, base_fields + (p1_fields if expected[1] ==
                                   'corrupt-server-capture' else ()),
               STOP_MODEL_RECOMPUTATION)
        _stop((row['round'], row['kind']) == expected
              and type(row['round']) is int
              and row['role'] == ROLE_BY_KIND[row['kind']]
              and type(row['fixed_fd']) is int
              and 3 <= row['fixed_fd'] <= 1024,
              STOP_MODEL_RECOMPUTATION)
        for name in ('source_sha256', 'build_sha256', 'launch_sha256'):
            _word(row[name], STOP_MODEL_RECOMPUTATION)
        for name in p1_fields if expected[1] == \
                'corrupt-server-capture' else ():
            _word(row[name], STOP_MODEL_RECOMPUTATION)
        _stop(expected not in result, STOP_MODEL_RECOMPUTATION)
        result[expected] = row
    _stop(len({row['fixed_fd'] for row in value}) == 10
          and len({row['launch_sha256'] for row in value}) == 10,
          STOP_MODEL_RECOMPUTATION)
    return result


def _run_context(run):
    value = _exact(run['run_context'], RUN_CONTEXT_FIELDS)
    _stop(value['classification'] == run['classification'],
          STOP_INPUT_SHAPE)
    acceptance.validate_binding(value['binding'])
    for name in ('method_sha256', 'workload_sha256',
                 'observer_source_sha256', 'capture_source_sha256',
                 'coverage_policy_sha256',
                 'capture_producer_receipt_sha256',
                 'capture_producer_role_launch_sha256',
                 'typed_artifact_manifest_sha256',
                 'runtime_identity_sha256'):
        _word(value[name])
    _stop(_same_json(value['mascot_process_state'],
                     MASCOT_PROCESS_STATE_MISSING),
          STOP_MODEL_RECOMPUTATION)
    roles = _validate_role_launch_closure(
        value['capture_producer_role_launch_closure'],
        value['capture_producer_role_launch_sha256'])
    return {
        **value,
        '_capture_producer_receipt_sha256':
            value['capture_producer_receipt_sha256'],
        '_roles_by_round_kind': roles,
    }


def _artifact_by_kind(artifacts):
    return {artifact['kind']: artifact for artifact in artifacts}


def _constraint_count(artifact, public):
    try:
        value = codec.constraints(artifact['constraints'], public)
    except Exception as error:
        raise _Stop(STOP_MODEL_RECOMPUTATION) from error
    return sum(len(value[name]) for name in (
        'input_edges', 'creator_edges', 'pair_edges', 'nf_pair_edges'))


def _typed_content_sha256(artifact):
    """Hash every typed leaf field except its raw-source digest."""
    _exact(artifact, TYPED_ARTIFACT_FIELDS, STOP_MODEL_RECOMPUTATION)
    return digest({
        'schema': 'kpb-observer-readiness-typed-content/v1',
        'typed_artifact': {
            name: artifact[name] for name in TYPED_ARTIFACT_FIELDS
            if name != 'artifact_sha256'
        },
    })


def _validate_public_inventory(artifact, public):
    value = _exact(artifact['inventory'], PUBLIC_INVENTORY_FIELDS,
                   STOP_MODEL_RECOMPUTATION)
    lanes = capture_model._public_projection_byte_lanes()
    constants = {
        'schema': 'kpb-public-projection-byte-inventory/v1',
        'projection_bytes': 10685,
        'prefix_bytes': 193,
        'body_bytes': 10492,
        'body_core_bytes': 10364,
        'spend_rows': 3,
        'output_rows': 6,
        'ciphertext_bytes': 1584,
        'output_proof_bytes': 768,
        'nf_witness_bytes': 3480,
        'cm_path_bytes': 3072,
        'aggregate_proof_bytes': 128,
        'byte_lane_count': 102,
        'byte_lane_total_bytes': 10685,
        'honest_encryption_producer_authority_consumed': False,
        'complete_public_multiattempt_history_joined': False,
        'structural_continuity_authority_consumed': False,
        'structural_continuity_candidate_count_before': None,
        'structural_continuity_candidate_count_after': None,
        'accepted_chain_continuity_proven': False,
        'individual_input_amount_fields': 0,
        'individual_output_amount_fields': 0,
        'owner_label_fields': 0,
        'direct_constraint_count': 0,
        'proof_validity_or_privacy_claim': False,
    }
    _stop(all(type(value[name]) is type(expected)
              and value[name] == expected
              for name, expected in constants.items())
          and _same_json(value['byte_lanes'], lanes)
          and value['byte_lane_manifest_sha256'] == digest(lanes)
          and artifact['artifact_sha256'] == public['projection_sha256'],
          STOP_MODEL_RECOMPUTATION)
    _stop(type(value['context_identifiers_hex32']) is list
          and len(value['context_identifiers_hex32']) == 5,
          STOP_MODEL_RECOMPUTATION)
    for name in value['context_identifiers_hex32']:
        _word(name, STOP_MODEL_RECOMPUTATION)
    for name in ('old_cm_root_hex32', 'old_nf_root_hex32',
                 'new_cm_root_hex32', 'new_nf_root_hex32'):
        _word(value[name], STOP_MODEL_RECOMPUTATION)
    _stop(type(value['reserve_outpoint_hex36']) is str
          and re.fullmatch('[0-9a-f]{72}', value['reserve_outpoint_hex36']),
          STOP_MODEL_RECOMPUTATION)
    _stop(all(type(value[name]) is int for name in (
              'old_cm_count', 'old_nf_count', 'new_cm_count',
              'new_nf_count', 'reserve_sompi', 'remaining_sompi',
              'fee_sompi'))
          and value['new_cm_count'] == value['old_cm_count'] + 6
          and value['new_nf_count'] == value['old_nf_count'] + 3
          and value['remaining_sompi'] + value['fee_sompi'] ==
              value['reserve_sompi']
          and value['aggregate_value_constraints'] == {
              'reserve_sompi': value['reserve_sompi'],
              'remaining_sompi': value['remaining_sompi'],
              'fee_sompi': value['fee_sompi'],
          }, STOP_MODEL_RECOMPUTATION)
    context_bytes = (b''.join(bytes.fromhex(item) for item in
                              value['context_identifiers_hex32'])
                     + bytes.fromhex(value['reserve_outpoint_hex36'])
                     + bytes.fromhex(value['old_cm_root_hex32'])
                     + bytes.fromhex(value['old_nf_root_hex32'])
                     + struct.pack('<IIQ', value['old_cm_count'],
                                   value['old_nf_count'],
                                   value['reserve_sompi']))
    _stop(hashlib.sha256(context_bytes).hexdigest() ==
          public['context_sha256'], STOP_MODEL_RECOMPUTATION)
    edges = value['nf_witness_public_history_edges']
    edge_fields = (
        'input_nf_hex32', 'predecessor_index', 'predecessor_nf_hex32',
        'successor_nf_hex32', 'successor_index',
        'predecessor_path_sha256', 'append_path_sha256',
    )
    _stop(type(edges) is list and len(edges) == 3
          and [row.get('input_nf_hex32') for row in edges] ==
              public['nfs_hex32'], STOP_MODEL_RECOMPUTATION)
    for row in edges:
        _exact(row, edge_fields, STOP_MODEL_RECOMPUTATION)
        _stop(type(row['predecessor_index']) is int
              and type(row['successor_index']) is int,
              STOP_MODEL_RECOMPUTATION)
        for name in edge_fields:
            if name not in ('predecessor_index', 'successor_index'):
                _word(row[name], STOP_MODEL_RECOMPUTATION)
    equalities = value['same_projection_public_byte_equalities']
    _exact(equalities, (
        'nullifier_pairs', 'commitment_pairs',
        'ciphertext_ephemeral_public_key_pairs',
        'ciphertext_poly1305_tag_pairs',
        'ciphertext_encrypted_receipt_pairs', 'ciphertext_hash_pairs',
        'output_proof_pairs'), STOP_MODEL_RECOMPUTATION)
    _stop(all(item == [] for item in equalities.values()),
          STOP_MODEL_RECOMPUTATION)
    cv = _exact(value['cv_model'], (
        'input_cv_count', 'output_cv_count',
        'canonical_subgroup_point_count', 'delta_scalar_hex32',
        'joint_public_balance_verified', 'candidate_grouping_count',
        'candidate_group_residual_partition_sha256',
        'candidate_grouping_pruned_count_without_openings',
        'candidate_residuals_feed_selected_prediction',
        'hiding_or_fresh_blind_claim'), STOP_MODEL_RECOMPUTATION)
    _word(cv['delta_scalar_hex32'], STOP_MODEL_RECOMPUTATION)
    _word(cv['candidate_group_residual_partition_sha256'],
          STOP_MODEL_RECOMPUTATION)
    _stop(cv['input_cv_count'] == 3 and cv['output_cv_count'] == 6
          and all(type(cv[name]) is int for name in (
              'input_cv_count', 'output_cv_count',
              'canonical_subgroup_point_count', 'candidate_grouping_count',
              'candidate_grouping_pruned_count_without_openings'))
          and cv['canonical_subgroup_point_count'] == 9
          and cv['joint_public_balance_verified'] is True
          and cv['candidate_grouping_count'] == 540
          and cv['candidate_grouping_pruned_count_without_openings'] == 0
          and cv['candidate_residuals_feed_selected_prediction'] is False
          and cv['hiding_or_fresh_blind_claim'] is False,
          STOP_MODEL_RECOMPUTATION)


def _validate_terminal_inventory(artifact, public):
    value = _exact(artifact['inventory'], TERMINAL_INVENTORY_FIELDS,
                   STOP_MODEL_RECOMPUTATION)
    _stop(value['schema'] == 'kpb-terminal-history-inventory/v1'
          and all(type(value[name]) is int for name in (
              'event_count', 'group_count',
              'individual_amount_observation_count', 'retry_count',
              'rejected_or_orphaned_count', 'reorg_count',
              'cross_round_link_count', 'direct_constraint_count'))
          and value['projection_sha256'] == public['projection_sha256']
          and value['event_count'] == 3
          and value['group_count'] == 1
          and all(value[name] == 0 for name in (
              'individual_amount_observation_count', 'retry_count',
              'rejected_or_orphaned_count', 'reorg_count',
              'cross_round_link_count'))
          and value['direct_constraint_count'] ==
              _constraint_count(artifact, public) == 0
          and artifact['terminal_modeled'] is True
          and artifact['cross_round_links'] == [],
          STOP_MODEL_RECOMPUTATION)
    _word(value['projection_sha256'], STOP_MODEL_RECOMPUTATION)


def _validate_dispatcher_inventory(artifact, public, classification):
    value = _exact(artifact['inventory'], DISPATCHER_INVENTORY_FIELDS,
                   STOP_MODEL_RECOMPUTATION)
    candidate = classification == 'ACTUAL_HIDDEN_MAPPING_CANDIDATE'
    _stop(value['schema'] == 'kpb-dispatcher-metadata-inventory/v1'
          and all(type(value[name]) is int for name in (
              'event_count', 'retry_count', 'owner_connection_count',
              'owner_upload_count', 'aggregate_release_count',
              'outbound_route_count', 'construction_classification',
              'release_policy_binding_count', 'direct_constraint_count'))
          and value['event_count'] == (10 if candidate else 11)
          and value['retry_count'] == 0
          and value['owner_connection_count'] == 3
          and value['owner_upload_count'] == 3
          and value['aggregate_release_count'] == 1
          and value['outbound_route_count'] == 1
          and value['construction_classification'] ==
              (1 if candidate else 2)
          and value['release_order_policy'] == (
              'SECRET_PERMUTATION_INDEPENDENT' if candidate else
              'EXPLICIT_OWNER_PUBLIC_EFFECTS')
          and value['release_policy_binding_count'] == 1
          and value['source_bound_policy_authority'] is True
          and value['private_body_or_hash_captured'] is False
          and value['direct_constraint_count'] ==
              _constraint_count(artifact, public) ==
              (0 if candidate else 12), STOP_MODEL_RECOMPUTATION)


def _validate_c1_inventory(artifact, public):
    value = _exact(artifact['inventory'], C1_INVENTORY_FIELDS,
                   STOP_MODEL_RECOMPUTATION)
    round_amount = 500_000_000 if public['round'] == 1 else 200_000_000
    _stop(value['schema'] == 'kpb-colluder-wallet-knowledge-inventory/v2'
          and all(type(value[name]) is int for name in (
              'original_count', 'input_count', 'created_output_count',
              'invoice_count', 'decrypted_receipt_count', 'retry_count',
              'input_amount_sompi', 'public_individual_amount_join_fields',
              'candidate_count_before_contact_value',
              'candidate_count_after_contact_value',
              'candidate_pruned_count', 'direct_constraint_count'))
          and all(type(item) is int for name in (
              'created_amounts_sompi', 'invoice_amounts_sompi',
              'receipt_amounts_sompi') for item in value[name])
          and value['original_count'] == value['input_count'] == 1
          and value['created_output_count'] == 2
          and value['invoice_count'] == value['decrypted_receipt_count'] == 2
          and value['retry_count'] == 0
          and value['input_amount_sompi'] == 1_000_000_000
          and value['created_amounts_sompi'] == [round_amount, 69_000_000]
          and value['invoice_amounts_sompi'] == [round_amount] * 2
          and value['receipt_amounts_sompi'] == [round_amount, 69_000_000]
          and value['public_individual_amount_join_fields'] == 2
          and value['source_bound_contact_value_authority'] is True
          and value['candidate_count_before_contact_value'] == 12
          and value['candidate_count_after_contact_value'] == 6
          and value['candidate_pruned_count'] == 6
          and value['direct_constraint_count'] ==
              _constraint_count(artifact, public) == 5
          and value['cryptographic_privacy_claim'] is False,
          STOP_MODEL_RECOMPUTATION)


def _validate_p1_inventory(artifact, public, role):
    value = _exact(artifact['inventory'], P1_INVENTORY_FIELDS,
                   STOP_MODEL_RECOMPUTATION)
    expected_semantics = [
        'authenticated-g1-state', 'authenticated-g2-state',
        'authenticated-share', 'field-opening', 'final-proof-g1',
        'final-proof-g2', 'mac-key-share', 'mac-share', 'mascot-message',
        'masked-field-intermediate', 'masked-g1-intermediate',
        'owner-input-offset', 'owner-input-preprocessing-share',
        'public-projection', 'randomness-mac', 'randomness-share',
    ]
    boundaries = {
        'schema': 'kpb-p1-out-of-scope-unqualified-boundaries/v1',
        'status': 'UNQUALIFIED_FOR_GENERAL_ACTIVE_OR_HOST_CLAIMS',
        'boundaries': [
            'P1_INTERNAL_OT_PRNG_RANDOM_TAPE',
            'ARBITRARY_MODIFIED_OR_MALICIOUS_HOST_OR_BINARY',
            'HOST_MEMORY_LOG_SWAP_CACHE_PAGE_SCHEDULE_CPU_GPU_STATE',
            'COVERT_AND_NETWORK_STACK_CHANNELS',
        ],
        'modeled_or_harmless': False,
        'blocks_general_active_or_host_claims': True,
    }
    _stop(value['schema'] == 'kpb-corrupt-server-c03-lane-inventory/v1'
          and all(type(value[name]) is int for name in (
              'record_count', 'record_bytes', 'owner_offset_count',
              'owner_preprocessing_share_count',
              'owner_preprocessing_to_offset_width_ratio',
              'mac_key_share_count', 'masked_field_intermediate_count',
              'masked_g1_intermediate_count', 'final_proof_g1_count',
              'final_proof_g2_count', 'direct_constraint_count',
              'c03_wire_frame_count', 'c03_wire_bytes', 'c03_fixed_fd',
              'c03_scalar_binding_count', 'c03_scalar_site_bitmap'))
          and value['record_count'] == 64
          and value['record_bytes'] == 15867
          and value['semantics'] == expected_semantics
          and value['owner_offset_count'] == 3
          and value['owner_preprocessing_share_count'] == 3
          and value['owner_preprocessing_to_offset_width_ratio'] == 5
          and value['mac_key_share_count'] == 1
          and value['masked_field_intermediate_count'] == 1
          and value['masked_g1_intermediate_count'] == 1
          and value['final_proof_g1_count'] == 1
          and value['final_proof_g2_count'] == 1
          and _same_json(value['authenticated_g1_stage_object_counts'], {
              'BASE': 4, 'FINAL': 2, 'MIXED': 6, 'PRODUCTS': 2}
          )
          and _same_json(value['authenticated_g2_stage_object_counts'], {
              'BASE': 1, 'FINAL': 1})
          and value['direct_constraint_count'] ==
              _constraint_count(artifact, public) == 0
          and value['observer_scope'] ==
              'PINNED_INSTRUMENTED_PASSIVE_P1_PROCESS_PLUS_PASSIVE_OWNER1'
          and _same_json(value['out_of_scope_unqualified_boundaries'],
                         boundaries)
          and value['cryptographic_independence_or_privacy_claim'] is False
          and value['c03_source_build_launch_role_bound'] is True
          and value['c03_wire_frame_count'] == 90
          and value['c03_wire_bytes'] == 27159
          and value['c03_wire_sha256'] == artifact['artifact_sha256']
          and value['c03_fixed_fd'] == role['fixed_fd']
          and value['c03_source_sha256'] == role['source_sha256']
          and value['c03_build_sha256'] == role['build_sha256']
          and value['c03_launch_sha256'] == role['launch_sha256']
          and value['c03_model_preimage_sha256'] ==
              role['model_preimage_sha256']
          and value['c03_query_store_preimage_sha256'] ==
              role['query_store_preimage_sha256']
          and value['c03_scalar_capture_manifest_sha256'] ==
              role['scalar_capture_manifest_sha256']
          and value['c03_scalar_binding_count'] == 22
          and value['c03_scalar_site_bitmap'] == (1 << 22) - 1
          and _same_json(
              value['c03_authenticated_group_equation_constraints'], {
              'C_equals_products_plus_L_plus_H': 2,
              'D_equals_Q_minus_U': 4,
              'beaver_product_equations': 4,
          }), STOP_MODEL_RECOMPUTATION)
    closure = _exact(value['c03_wire_closure'], P1_WIRE_CLOSURE_FIELDS,
                     STOP_MODEL_RECOMPUTATION)
    stream_counts = {
        'authenticated-g1-state': 4, 'authenticated-g2-state': 2,
        'authenticated-share': 18, 'field-opening': 1,
        'final-proof-g1': 1, 'final-proof-g2': 1, 'mac-key-share': 1,
        'mac-share': 18, 'mascot-message': 1,
        'masked-field-intermediate': 1, 'masked-g1-intermediate': 1,
        'owner-input-offset': 3, 'owner-input-preprocessing-share': 3,
        'public-projection': 1, 'randomness-mac': 4,
        'randomness-share': 4, 'scalar-capture-binding': 22,
    }
    _stop(closure['schema'] == 'kpb-capture-source-closure/v2'
          and all(type(closure[name]) is int for name in (
              'producer_record_count', 'capture_record_count',
              'producer_payload_bytes', 'capture_payload_bytes',
              'unknown_record_count', 'raw_wire_bytes'))
          and closure['attempt_id'] == value['attempt_id']
          and closure['cohort_sha256'] == value['cohort_sha256']
          and closure['producer_record_count'] ==
              closure['capture_record_count'] == 86
          and closure['producer_payload_bytes'] ==
              closure['capture_payload_bytes'] == 16219
          and _same_json(closure['producer_stream_counts'], stream_counts)
          and _same_json(closure['capture_stream_counts'], stream_counts)
          and closure['record_chain_sha256'] == artifact['artifact_sha256']
          and closure['unknown_record_count'] == 0
          and closure['capture_root_closed'] is True
          and closure['producer_fd_closed'] is True
          and closure['raw_wire_bytes'] == value['c03_wire_bytes']
          and closure['raw_wire_sha256'] == artifact['artifact_sha256'],
          STOP_MODEL_RECOMPUTATION)
    _word(closure['end_frame_identity'], STOP_MODEL_RECOMPUTATION)
    _word(closure['eof_identity'], STOP_MODEL_RECOMPUTATION)


def _validate_artifact_round(row, context):
    artifacts = row['typed_artifacts']
    _stop(type(artifacts) is list and len(artifacts) == 5
          and [artifact.get('kind') for artifact in artifacts] ==
              list(ARTIFACT_ORDER), STOP_MODEL_RECOMPUTATION)
    try:
        codec.batch(row['public'])
    except Exception as error:
        raise _Stop(STOP_MODEL_RECOMPUTATION) from error
    by_kind = {}
    for artifact in artifacts:
        _exact(artifact, TYPED_ARTIFACT_FIELDS, STOP_MODEL_RECOMPUTATION)
        kind = artifact['kind']
        _stop(artifact['schema'] == 'kpb-typed-capture-artifact-model/v2'
              and type(artifact['round']) is int
              and artifact['round'] == row['round']
              and artifact['categories'] ==
                  sorted(capture_model.ARTIFACT_CATEGORIES[kind])
              and artifact['terminal_modeled'] is
                  (kind == 'terminal-history')
              and (kind == 'terminal-history'
                   or artifact['cross_round_links'] == []),
              STOP_MODEL_RECOMPUTATION)
        _word(artifact['artifact_sha256'], STOP_MODEL_RECOMPUTATION)
        by_kind[kind] = artifact
    bound = tuple(kind for kind in ARTIFACT_ORDER
                  if kind != 'public-projection')
    attempts = {by_kind[kind]['inventory'].get('attempt_id')
                for kind in bound}
    cohorts = {by_kind[kind]['inventory'].get('cohort_sha256')
               for kind in bound}
    _stop(len(attempts) == len(cohorts) == 1
          and None not in attempts and None not in cohorts,
          STOP_MODEL_RECOMPUTATION)
    attempt = next(iter(attempts)); cohort = next(iter(cohorts))
    _stop(type(attempt) is str and 1 <= len(attempt) <= 128,
          STOP_MODEL_RECOMPUTATION)
    _word(cohort, STOP_MODEL_RECOMPUTATION)
    public = row['public']
    _validate_public_inventory(by_kind['public-projection'], public)
    _validate_terminal_inventory(by_kind['terminal-history'], public)
    _validate_dispatcher_inventory(
        by_kind['dispatcher-capture'], public, context['classification'])
    _validate_p1_inventory(
        by_kind['corrupt-server-capture'], public,
        context['_roles_by_round_kind'][
            (row['round'], 'corrupt-server-capture')])
    _validate_c1_inventory(by_kind['colluder-wallet-capture'], public)
    return by_kind


def _typed_artifact_manifest(classification, binding, capture_identity,
                             role_launch_sha256, roles_by_round_kind,
                             rounds):
    manifest_rounds = []
    for row in rounds:
        artifacts = _artifact_by_kind(row['typed_artifacts'])
        entries = []
        for kind in ARTIFACT_ORDER:
            artifact = artifacts[kind]
            inventory = artifact['inventory']
            role = roles_by_round_kind[(row['round'], kind)]
            entries.append({
                'round': row['round'],
                'kind': kind,
                'projection_sha256': row['public']['projection_sha256'],
                'attempt_id': inventory.get('attempt_id'),
                'cohort_sha256': inventory.get('cohort_sha256'),
                'artifact_sha256': artifact['artifact_sha256'],
                'typed_content_sha256': _typed_content_sha256(artifact),
                'role_provenance': copy.deepcopy(role),
                'role_provenance_sha256': digest(role),
            })
        manifest_rounds.append({
            'round': row['round'],
            'artifacts': entries,
        })
    return {
        'schema': 'kpb-observer-readiness-typed-artifact-manifest/v1',
        'classification': classification,
        'binding': copy.deepcopy(binding),
        'capture_identity': capture_identity,
        'role_launch_sha256': role_launch_sha256,
        'rounds': manifest_rounds,
        'synthetic_self_sealed_only': True,
        'raw_capture_origin_authority': False,
    }


def _synthetic_producer_receipt_preimage(context, comparison_sha, run_sha):
    return {
        'schema': 'kpb-observer-readiness-synthetic-producer-receipt/v1',
        'classification': context['classification'],
        'binding': copy.deepcopy(context['binding']),
        'capture_identity': context['capture_identity'],
        'comparison_selection_sha256': comparison_sha,
        'run_selection_sha256': run_sha,
        'role_launch_sha256':
            context['capture_producer_role_launch_sha256'],
        'typed_artifact_manifest_sha256':
            context['typed_artifact_manifest_sha256'],
        'source_closure_sha256': context['source_closure_sha256'],
        'runtime_identity_sha256': context['runtime_identity_sha256'],
        'synthetic_self_sealed_only': True,
        'source_capture_authority': False,
    }


def _derive_synthetic_view(public, artifacts, assumptions):
    """Validate selected assumption rows, then reuse the frozen derivation.

    ``privacy_capture_model`` intentionally has an empty production selection
    registry.  This adapter therefore normalizes already-validated synthetic
    assumption rows only in a private copy before calling its derivation.  The
    returned coverage is corrected back to assumption-covered field counts.
    The production registry is never mutated.
    """
    _stop(type(assumptions) is dict
          and set(assumptions) == set(SELECTED_ASSUMPTION_FAMILIES),
          STOP_ASSUMPTION_SELECTION)
    normalized = copy.deepcopy(artifacts)
    for source, target in zip(artifacts, normalized):
        _stop(source.get('kind') == target.get('kind')
              and type(source.get('leakage_ledger')) is list,
              STOP_MODEL_RECOMPUTATION)
        for source_row, target_row in zip(
                source['leakage_ledger'], target['leakage_ledger']):
            family = _field_assumption_family(
                source['kind'], source_row.get('category'),
                source_row.get('field_path'))
            if family is None:
                _stop(source_row.get('status') !=
                      'source_assumption_covered',
                      STOP_ASSUMPTION_SELECTION)
                continue
            if source_row.get('status') == 'unmodeled':
                continue
            _stop(source_row.get('status') ==
                  'source_assumption_covered'
                  and type(source_row.get('constraint_count')) is int
                  and source_row.get('constraint_count') == 0
                  and source_row.get('assumption_sha256') ==
                      assumptions[family],
                  STOP_ASSUMPTION_SELECTION)
            target_row.update({
                'status': 'constraint_modeled',
                'constraint_count': 1,
                'assumption_sha256': None,
            })
    try:
        derived = capture_model.derive_view_artifacts(public, normalized)
    except Exception as error:
        raise _Stop(STOP_MODEL_RECOMPUTATION) from error
    by_kind = _artifact_by_kind(artifacts)
    for view, kinds in VIEW_KINDS.items():
        selected = [by_kind[kind] for kind in kinds]
        modeled = derived['views'][view]
        for category in modeled['categories']:
            rows = [(artifact, row) for artifact in selected
                    for row in artifact['leakage_ledger']
                    if row['category'] == category]
            modeled['leakage_coverage'][category] = {
                'constraint_modeled_fields': sum(
                    row['status'] == 'constraint_modeled'
                    for _, row in rows),
                'source_assumption_covered_fields': sum(
                    row['status'] == 'source_assumption_covered'
                    for _, row in rows),
                'unmodeled_fields': sum(
                    row['status'] == 'unmodeled' for _, row in rows),
                'unmodeled_artifacts': len({
                    artifact['artifact_sha256'] for artifact, row in rows
                    if row['status'] == 'unmodeled'}),
            }
    return derived


def _recompute_models(run, context, assumptions):
    binding = context['binding']
    value = run['capture_models']
    _exact(value, ('schema', 'binding', 'rounds'),
           STOP_MODEL_RECOMPUTATION)
    _stop(value['schema'] == 'kpb-private-actual-capture-models/v1'
          and _same_json(value['binding'], binding)
          and type(value['rounds']) is list
          and len(value['rounds']) == 2,
          STOP_MODEL_RECOMPUTATION)
    models_by_view = {view: [] for view in acceptance.VIEWS}
    terminals = []
    derived_rounds = []
    seen_p1 = set()
    seen_c1 = set()
    for number, row in enumerate(value['rounds'], 1):
        _exact(row, ('round', 'public', 'typed_artifacts', 'derived'),
               STOP_MODEL_RECOMPUTATION)
        _stop(row['round'] == number
              and type(row['round']) is int
              and type(row['public']) is dict
              and row['public'].get('round') == number,
              STOP_MODEL_RECOMPUTATION)
        by_kind = _validate_artifact_round(row, context)
        derived = _derive_synthetic_view(
            row['public'], row['typed_artifacts'], assumptions)
        _stop(derived == row['derived'], STOP_MODEL_RECOMPUTATION)
        p1 = by_kind['corrupt-server-capture']
        c1 = by_kind['colluder-wallet-capture']
        _stop(p1['artifact_sha256'] != c1['artifact_sha256']
              and p1['artifact_sha256'] not in seen_p1
              and c1['artifact_sha256'] not in seen_c1,
              STOP_MODEL_RECOMPUTATION)
        seen_p1.add(p1['artifact_sha256'])
        seen_c1.add(c1['artifact_sha256'])
        for view in acceptance.VIEWS:
            modeled = derived['views'][view]
            _stop(modeled['unmodeled_inventory'][
                      'missing_artifact_count'] == 0,
                  STOP_MISSING_OR_UNMODELED)
            _stop(modeled['unmodeled_artifact_count'] == 0
                  and modeled['unmodeled_inventory'][
                      'unmodeled_field_count'] == 0,
                  STOP_STEP2_OPEN)
            models_by_view[view].append(codec.assignments(
                row['public'], modeled['constraints']))
        terminal = by_kind['terminal-history']
        _stop(terminal['terminal_modeled'] is True,
              STOP_MISSING_OR_UNMODELED)
        terminals.append(terminal)
        derived_rounds.append(derived)
    try:
        workloads = {
            view: capture_model.workload_candidates(
                models_by_view[view], terminals)
            for view in acceptance.VIEWS
        }
        lattice = roles._candidate_lattice(models_by_view, workloads)
    except Exception as error:
        raise _Stop(STOP_LATTICE) from error
    provenance = {
        'p1_artifact_sha256': sorted(seen_p1),
        'c1_artifact_sha256': sorted(seen_c1),
        'role_launch_sha256': sorted(
            row['launch_sha256'] for row in
            context['capture_producer_role_launch_closure']),
    }
    manifest = _typed_artifact_manifest(
        context['classification'], binding, context['capture_identity'],
        context['capture_producer_role_launch_sha256'],
        context['_roles_by_round_kind'], value['rounds'])
    manifest_sha = digest(manifest)
    _stop(manifest_sha == context['typed_artifact_manifest_sha256'],
          STOP_MODEL_RECOMPUTATION)
    return (models_by_view, workloads, lattice, derived_rounds, provenance,
            manifest_sha)


def _expected_capture_round(number, view, derived):
    modeled = derived['views'][view]
    expanded = actual_capture._category_coverage(
        view, VIEW_KINDS[view], modeled)
    categories = {}
    consumed = set()
    for target in acceptance.REQUIRED_CATEGORIES[view]:
        sources = LEGACY_CATEGORY_SOURCES.get(target, (target,))
        present = [expanded[name] for name in sources if name in expanded]
        _stop(present, STOP_MISSING_OR_UNMODELED)
        consumed.update(name for name in sources if name in expanded)
        categories[target] = {
            # Every source in either split is carried by one same typed leaf;
            # count that leaf once while summing its distinct field rows.
            'modeled_artifacts': max(
                row['modeled_artifacts'] for row in present),
            'unmodeled_artifacts': max(
                row['unmodeled_artifacts'] for row in present),
            'missing_artifacts': sum(
                row['missing_artifacts'] for row in present),
            'constraint_modeled_fields': sum(
                row['constraint_modeled_fields'] for row in present),
            'source_assumption_covered_fields': sum(
                row['source_assumption_covered_fields'] for row in present),
            'unmodeled_fields': sum(
                row['unmodeled_fields'] for row in present),
        }
    _stop(consumed == set(expanded), STOP_MISSING_OR_UNMODELED)
    return {
        'round': number,
        'artifact_count': len(VIEW_KINDS[view]),
        'category_counts': {
            category: row['modeled_artifacts'] + row['missing_artifacts']
            for category, row in categories.items()
        },
        'category_coverage': categories,
        'modeled_artifacts': len(VIEW_KINDS[view]),
        'unmodeled_artifacts': 0,
        'missing_artifacts': 0,
        'terminal_modeled': True,
    }


def _check_capture_receipt(capture, derived_rounds):
    by_view = {row['view']: row for row in capture['views']}
    _stop(set(by_view) == set(acceptance.VIEWS),
          STOP_MISSING_OR_UNMODELED)
    for view in acceptance.VIEWS:
        observed = by_view[view]
        _stop(len(observed['rounds']) == 2,
              STOP_MISSING_OR_UNMODELED)
        for number, (row, derived) in enumerate(
                zip(observed['rounds'], derived_rounds), 1):
            expected = _expected_capture_round(number, view, derived)
            _stop(all(_same_json(row[name], expected[name])
                      for name in expected),
                  STOP_MISSING_OR_UNMODELED)
            _stop(type(row['artifact_bytes']) is int
                  and row['artifact_bytes'] > 0,
                  STOP_MISSING_OR_UNMODELED)
        _stop(_same_json(observed['coverage'], {
            'modeled_artifacts': 2 * len(VIEW_KINDS[view]),
            'unmodeled_artifacts': 0,
            'missing_artifacts': 0,
            'terminal_modeled': True,
        }), STOP_MISSING_OR_UNMODELED)


def _check_observation(observation, models, workloads, lattice):
    for expected_view, row in zip(acceptance.VIEWS,
                                  observation['views']):
        expected_rounds = [{
            name: (index if name == 'round' else model[name])
            for name in PRETRUTH_ROUND_FIELDS
        } for index, model in enumerate(models[expected_view], 1)]
        _stop(_same_json(row['rounds'], expected_rounds),
              STOP_PRETRUTH_CHAIN)
        _stop(_same_json(row['workload'], {
            name: workloads[expected_view][name] for name in
            capture_bundle.OBSERVATION_WORKLOAD_FIELDS
        }) and _same_json(row['lattice_attestation'], lattice),
              STOP_PRETRUTH_CHAIN)


def _check_aggregate(aggregate, observation):
    by_name = {row['view']: row for row in aggregate['views']}
    _stop(set(by_name) == set(acceptance.VIEWS), STOP_AGGREGATE_CHAIN)
    _stop(acceptance.union_is_monotone(by_name), STOP_LATTICE)
    observed = {row['view']: row for row in observation['views']}
    for view in acceptance.VIEWS:
        _stop(all(
            _same_json(
                {name: result[name] for name in PRETRUTH_ROUND_FIELDS},
                source)
            for result, source in zip(by_name[view]['rounds'],
                                      observed[view]['rounds'])),
            STOP_AGGREGATE_CHAIN)


def _exercise_scorers(transcript, barrier_sha, binding, observation,
                      aggregate, models, workloads, lattice):
    """Re-run all 12 owner scorers and four aggregates after the barrier."""
    _exact(transcript, SCORING_FIELDS, STOP_SCORER_CHAIN)
    _stop(transcript['schema'] ==
          'kpb-observer-readiness-private-scoring/v1'
          and transcript['barrier_sha256'] == barrier_sha
          and type(transcript['views']) is list
          and len(transcript['views']) == 4,
          STOP_SCORER_CHAIN)
    observed = {row['view']: row for row in observation['views']}
    aggregate_views = {row['view']: row for row in aggregate['views']}
    _stop(set(observed) == set(aggregate_views) == set(acceptance.VIEWS),
          STOP_SCORER_CHAIN)
    for expected_view, row in zip(acceptance.VIEWS,
                                  transcript['views']):
        _exact(row, SCORING_VIEW_FIELDS, STOP_SCORER_CHAIN)
        _stop(row['view'] == expected_view
              and row['capsule_seal_sha256'] ==
                  observed[expected_view]['capsule_seal_sha256']
              and type(row['owner_truth']) is list
              and len(row['owner_truth']) == 3,
              STOP_SCORER_CHAIN)
        predicted = codec.prediction(
            binding, expected_view, models[expected_view],
            observed[expected_view]['coverage'],
            category_coverage=observed[expected_view][
                'category_coverage'],
            workload=workloads[expected_view],
            lattice_attestation=lattice)
        leaves = []
        for owner, truth in enumerate(row['owner_truth']):
            _stop(type(truth) is list and len(truth) == 2
                  and all(type(item) is dict
                          and item.get('owner_component') == owner
                          for item in truth),
                  STOP_SCORER_CHAIN)
            try:
                leaves.append(codec.score_owner(
                    predicted, truth, row['capsule_seal_sha256']))
            except Exception as error:
                raise _Stop(STOP_SCORER_CHAIN) from error
        try:
            recomputed = codec.aggregate(
                predicted, leaves, row['capsule_seal_sha256'])
        except Exception as error:
            raise _Stop(STOP_AGGREGATE_CHAIN) from error
        _stop(recomputed == aggregate_views[expected_view],
              STOP_AGGREGATE_CHAIN)


def _validate_run(run, expected_classification, assumptions):
    _exact(run, RUN_FIELDS)
    _stop(run['classification'] == expected_classification,
          STOP_INPUT_SHAPE)
    context = _run_context(run)
    acceptance_bundle = run['acceptance_bundle']
    _stop(type(acceptance_bundle) is dict
          and acceptance_bundle.get('classification') ==
              expected_classification
          and _same_json(acceptance_bundle.get('binding'),
                         context['binding']),
          STOP_INPUT_SHAPE)
    comparison_sha = acceptance_bundle.get(
        'comparison_selection_sha256')
    run_sha = acceptance_bundle.get('run_selection_sha256')
    _word(comparison_sha)
    _word(run_sha)
    _stop(acceptance_bundle.get('capture_identity') ==
          context['capture_identity'], STOP_INPUT_SHAPE)

    (models, workloads, lattice, derived, provenance,
     manifest_sha) = _recompute_models(run, context, assumptions)
    expected_producer_sha = digest(_synthetic_producer_receipt_preimage(
        context, comparison_sha, run_sha))
    _stop(context['capture_producer_receipt_sha256'] ==
          expected_producer_sha, STOP_MODEL_RECOMPUTATION)
    capture = run['capture_receipt']
    _stop(capture.get('capture_manifest_seal_sha256') == manifest_sha
          and capture.get('capture_producer_receipt_sha256') ==
              expected_producer_sha, STOP_MODEL_RECOMPUTATION)
    capture_sha = digest(capture)
    try:
        capture_views = capture_bundle.validate_capture(
            capture, comparison_sha, run_sha, context)
    except Exception as error:
        raise _Stop(STOP_MISSING_OR_UNMODELED) from error
    _check_capture_receipt(capture, derived)
    observation = run['observation_receipt']
    observation_sha = digest(observation)
    try:
        capture_bundle.validate_observation(
            observation, comparison_sha, run_sha, context, capture_sha,
            capture, capture_views)
    except Exception as error:
        raise _Stop(STOP_PRETRUTH_CHAIN) from error
    _check_observation(observation, models, workloads, lattice)
    barrier = run['barrier']
    barrier_sha = digest(barrier)
    try:
        capture_bundle.validate_barrier(
            barrier, comparison_sha, run_sha, context, capture_sha,
            capture, observation_sha, observation)
    except Exception as error:
        raise _Stop(STOP_PRETRUTH_CHAIN) from error
    aggregate = run['aggregate_result']
    _check_aggregate(aggregate, observation)
    _exercise_scorers(
        run['scoring_transcript'], barrier_sha, context['binding'],
        observation, aggregate, models, workloads, lattice)
    _stop(type(run['score_receipts']) is list
          and len(run['score_receipts']) == 3,
          STOP_SCORER_CHAIN)
    score_hashes = []
    for owner, score in enumerate(run['score_receipts']):
        try:
            capture_bundle.validate_score(
                score, owner, comparison_sha, run_sha, context,
                barrier_sha)
        except Exception as error:
            raise _Stop(STOP_SCORER_CHAIN) from error
        score_hashes.append(digest(score))
    _stop(len(set(score_hashes)) == 3, STOP_SCORER_CHAIN)

    try:
        aggregate_views = capture_bundle.validate_aggregate(
            aggregate, comparison_sha, run_sha, context, capture_sha,
            barrier_sha, observation, capture_views)
    except Exception as error:
        raise _Stop(STOP_AGGREGATE_CHAIN) from error
    _stop(_same_json(aggregate['lattice_attestation'], lattice),
          STOP_LATTICE)

    expected_bindings = {
        'capture_receipt_sha256': capture_sha,
        'observation_receipt_sha256': observation_sha,
        'barrier_sha256': barrier_sha,
        'score_receipt_sha256': score_hashes,
        'aggregate_result_sha256': digest(aggregate),
        'lattice_attestation': lattice,
        'views': aggregate_views,
    }
    _stop(all(_same_json(acceptance_bundle.get(name), value)
              for name, value in expected_bindings.items()),
          STOP_BASELINE_CANDIDATE_COMPARISON)
    return acceptance_bundle, provenance


def _evaluate(value):
    _exact(value, OUTER_FIELDS)
    _stop(value['schema'] == INPUT_SCHEMA
          and value['classification'] == CLASSIFICATION,
          STOP_INPUT_SHAPE)
    unsigned = {name: value[name] for name in OUTER_FIELDS[:-1]}
    _word(value['preimage_sha256'], STOP_SYNTHETIC_SEAL)
    _stop(value['preimage_sha256'] == digest(unsigned),
          STOP_SYNTHETIC_SEAL)
    # This is a synthetic self-report exercised against the real barrier
    # contract below.  It is deliberately not timing/process authority.
    _stop(value['truth_mounted_before_barrier'] is False,
          STOP_TRUTH_BEFORE_BARRIER)
    _exact(value['requested_actions'], REQUEST_FIELDS,
           STOP_ACTION_REQUEST)
    _stop(all(value['requested_actions'][name] is False
              for name in REQUEST_FIELDS), STOP_ACTION_REQUEST)
    _stop(value['claimed_privacy_status'] is None,
          STOP_PASS_CLAIM)
    assumptions = _validate_assumptions(value['assumption_selection'])

    baseline, baseline_provenance = _validate_run(
        value['baseline'], 'ACTUAL_TRANSPARENT_BASELINE', assumptions)
    candidate, candidate_provenance = _validate_run(
        value['candidate'], 'ACTUAL_HIDDEN_MAPPING_CANDIDATE', assumptions)
    _stop(all(not (set(baseline_provenance[name]) &
                       set(candidate_provenance[name]))
              for name in baseline_provenance),
          STOP_MODEL_RECOMPUTATION)
    try:
        synthetic = acceptance.evaluate_synthetic_model(
            baseline, candidate, value['owner_comparison'])
    except Exception as error:
        raise _Stop(STOP_BASELINE_CANDIDATE_COMPARISON) from error
    # Exercise the exact frozen comparison, but deliberately translate its
    # synthetic PASS label into readiness rather than returning or minting it.
    _stop(synthetic.get('status') ==
          'PASS_BOUNDED_SYNTHETIC_MODEL_CHECK',
          STOP_BASELINE_CANDIDATE_COMPARISON)
    _stop(synthetic.get('actual_authority_chain_verified') is False
          and synthetic.get('actual_privacy_status_minted') is False,
          STOP_PASS_CLAIM)
    # The selected/live complete P1 process-state closure is absent.  A MASCOT
    # capsule alone would still omit the other families enumerated by
    # P1_ACTUAL_RUN_MISSING_FAMILIES.  Caller policy or synthetic equality
    # cannot replace source-owned random-tape/replay/correspondence receipts.
    raise _Stop(STOP_MODEL_RECOMPUTATION)


def evaluate(value):
    """Return only one fixed readiness/STOP result; never exception detail."""
    try:
        return _evaluate(value)
    except _Stop as error:
        return _result(error.status)
    except Exception:
        return _result(STOP_INPUT_SHAPE)


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1 or args[0].startswith('-'):
        result = _result(STOP_INPUT_SHAPE)
    else:
        try:
            value = read_canonical(args[0])
        except Exception:
            result = _result(STOP_INPUT_SHAPE)
        else:
            result = evaluate(value)
    # The executable surface intentionally emits one fixed token and no
    # synthetic comparison details, truth, models or authority-shaped JSON.
    sys.stdout.write(result['status'] + '\n')
    return 0 if result['status'] == READY else 2


if __name__ == '__main__':
    raise SystemExit(main())

