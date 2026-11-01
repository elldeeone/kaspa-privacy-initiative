"""Typed direct-linkage adapters for complete private-batch observer captures.

This module does not call an opaque byte string harmless.  Each admitted
artifact has one exact schema and a finite source-defined meaning.  Unknown
schemas, missing protocol lanes, partial terminal history and selectively
declared view unions refuse.  The result remains a bounded direct-fact model;
it is not a proof that one corrupt server's authenticated shares are
computationally independent of honest-owner secrets.

Raw private captures are read only inside the isolated observer.  Public code
may exercise these adapters with synthetic fixtures, but may not publish the
private payload or its hash as a privacy result.
"""
import hashlib
import itertools
import re
import struct
import uuid

import privacy_codec as codec
import privacy_fd40_archive as fd40_archive
import privacy_fd40_structural as fd40_structural


FIELD_MODULUS = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)
FQ_MODULUS = (
    21888242871839275222246405745257275088696311157297823662689037894645226208583
)
PROJECTION_CATEGORIES = frozenset({
    'amounts', 'ciphertexts', 'commitments', 'context-identities', 'fees',
    'nullifiers', 'operation-shape', 'proofs', 'state-transition',
    'value-commitments',
})
TERMINAL_CATEGORIES = frozenset({
    'rejected-or-orphaned-candidates', 'reorg-history',
    'terminal-grouping',
})
PUBLIC_CATEGORIES = PROJECTION_CATEGORIES | TERMINAL_CATEGORIES
DISPATCHER_CATEGORIES = frozenset({
    'cohort-membership', 'connection-order', 'filenames', 'lengths',
    'operation-timing', 'outbound-routes', 'public-receipts',
    'retry-history', 'role-identities', 'upload-order',
})
SERVER_CATEGORIES = frozenset({
    'authenticated-group-state', 'authenticated-transcript',
    'server-local-shares', 'server-mac-state', 'server-randomness',
})
COLLUDER_CATEGORIES = frozenset({
    'colluder-decrypted-receipts', 'colluder-inputs-and-outputs',
    'colluder-invoices', 'colluder-original', 'retry-history',
})
ARTIFACT_CATEGORIES = {
    'public-projection': PROJECTION_CATEGORIES,
    'terminal-history': TERMINAL_CATEGORIES,
    'dispatcher-capture': DISPATCHER_CATEGORIES,
    'corrupt-server-capture': SERVER_CATEGORIES,
    'colluder-wallet-capture': COLLUDER_CATEGORIES,
}
LEAKAGE_STATUSES = frozenset({
    'constraint_modeled', 'source_assumption_covered', 'unmodeled',
})
# A digest is not authority by itself.  Entries may be added only for a
# selected, source-closed assumption ledger that pins the exact corruption
# model, implementation/build and applicability conditions.  Empty means every
# cryptographic source-assumption claim fails closed today.
SELECTED_SOURCE_ASSUMPTIONS = {}
PUBLIC_PROJECTION_LANE_MANIFEST_SHA256 = \
    '1bf69a2f0df24e494e5ad212ebf4770ee98e2c40f1186b912f9a9ae898e305ea'
ARTIFACT_LEAKAGE_FIELDS = {
    'public-projection': {
        'amounts': ('effect.reserve_sompi', 'effect.remaining_sompi'),
        'ciphertexts': (
            'outputs[].ciphertext_ephemeral_public_key',
            'outputs[].ciphertext_encrypted_receipt',
            'outputs[].ciphertext_poly1305_tag',
            'outputs[].ciphertext_hash',
            'outputs[].honest_encryption_provenance_and_malicious_owner_tagging',
            'outputs[].confidentiality_key_privacy_and_unlinkability',
        ),
        'commitments': (
            'outputs[].cm', 'outputs[].cm_hiding_and_unlinkability'),
        'context-identities': (
            'context.profile_genesis_lineage_domain_service_identifiers',
            'context.reserve_outpoint',
            'context.two_round_structural_profile_script_binding',
            'context.accepted_chain_outpoint_and_external_history_linkage',
        ),
        'fees': ('effect.fee_sompi',),
        'nullifiers': (
            'spends[].nf',
            'spends[].deterministic_retry_replay_equality',
            'spends[].nf_pseudorandomness_and_unlinkability',
        ),
        'operation-shape': (
            'projection.prefix_tag_version_counts_sequence_lengths_and_tail',
            'effect.tag',
        ),
        'proofs': ('outputs[].proof_bytes', 'aggregate.proof_bytes'),
        'state-transition': (
            'state.cm_roots_and_append_paths',
            'state.nf_roots_predecessors_successors_and_paths',
            'state.nf_witness_public_history_edges',
            'state.old_new_counts',
            'state.two_round_projection_structural_continuity',
            'state.accepted_chain_state_and_outpoint_continuity',
            'state.cross_attempt_public_byte_equalities',
        ),
        'value-commitments': (
            'inputs[].cv_bytes_and_subgroup',
            'outputs[].cv_bytes_and_subgroup',
            'effect.delta_scalar',
            'joint_public_balance_equation',
            'candidate_group_residuals',
            'joint_hiding_blind_freshness_and_reuse',
        ),
    },
    'terminal-history': {
        'rejected-or-orphaned-candidates':
            ('rejected_or_orphaned[].candidate_sha256_and_status',),
        'reorg-history': ('reorg_history[].heads_and_depth',),
        'terminal-grouping': ('groups[].owner_nf_tuple_membership',
                              'cross_round_links[]'),
    },
    'dispatcher-capture': {
        'cohort-membership': ('cohort_sha256',),
        'connection-order': ('events[owner-connected].sequence',),
        'filenames': ('events[].filename',),
        'lengths': ('events[].bytes',),
        'operation-timing': ('events[].monotonic_ns',),
        'outbound-routes': ('events[outbound-route].route_sha256',),
        'public-receipts': ('events[].public_sha256',
                            'release_order_policy_and_direct_exports'),
        'retry-history': ('retry_history[]',),
        'role-identities': ('events[].owner_component_and_role',),
        'upload-order': ('events[owner-upload-complete].sequence',),
    },
    'corrupt-server-capture': {
        'authenticated-transcript': (
            'capture.model_preimage_binding',
            'capture.public_query_preimage_binding',
            'capture.scalar_callsite_manifest_binding',
            'records[mascot-message].payload.literal_public_identifiers',
            'records[mascot-message].payload.nonliteral_implications',
            'records[field-opening].payload.literal_public_identifiers',
            'records[field-opening].payload.nonliteral_implications',
            'records[masked-field-intermediate].payload.literal_public_identifiers',
            'records[masked-field-intermediate].payload.nonliteral_implications',
            'records[masked-g1-intermediate].payload.literal_public_identifiers',
            'records[masked-g1-intermediate].payload.nonliteral_implications',
            'records[final-proof-g1].payload.literal_public_identifiers',
            'records[final-proof-g1].payload.nonliteral_implications',
            'records[final-proof-g2].payload.literal_public_identifiers',
            'records[final-proof-g2].payload.nonliteral_implications',
            'records[public-projection].payload',
            'records[scalar-capture-binding].site_kind_element_count_order',
            'records[scalar-capture-binding].payload.nonliteral_implications',
            'records[].schema_grammar',
            'wire.frames[].monotonic_ns',
            'wire.frames[].payload_length',
            'wire.frames[].sequence_message_chunk_order',
            'wire.frames[].direction_peer_fork',
            'wire.frames[].mixed_protocol_nonliteral_implications',
            'attempt.abort_retry_partial_transcript',
            'capture.source_build_launch_role_binding',
        ),
        'authenticated-group-state': (
            'records[authenticated-g1-state].payload.literal_public_identifiers',
            'records[authenticated-g1-state].payload.nonliteral_implications',
            'records[authenticated-g2-state].payload.literal_public_identifiers',
            'records[authenticated-g2-state].payload.nonliteral_implications',
            'records[authenticated-group-query-msm-temporary].capture_correspondence',
            'records[authenticated-group-query-msm-temporary].compressed_query_bytes',
            'records[authenticated-group-query-msm-temporary].decoded_public_point_chunks',
            'records[authenticated-group-query-msm-temporary].point_map_share_mac',
            'records[authenticated-group-query-msm-temporary].worker_partials',
            'records[authenticated-group-query-msm-temporary].running_query_sums',
            'records[authenticated-g1-state].D_equals_Q_minus_U',
            'records[authenticated-g1-state].beaver_product_equations',
            'records[authenticated-g1-state].C_equals_products_plus_L_plus_H',
        ),
        'server-local-shares': (
            'records[owner-input-offset].payload.literal_public_identifiers',
            'records[owner-input-offset].payload.nonliteral_implications',
            'records[owner-input-preprocessing-share].payload.literal_public_identifiers',
            'records[owner-input-preprocessing-share].payload.nonliteral_implications',
            'records[authenticated-share].payload.literal_public_identifiers',
            'records[authenticated-share].payload.nonliteral_implications',
        ),
        'server-mac-state': (
            'records[mac-key-share].payload.literal_public_identifiers',
            'records[mac-key-share].payload.nonliteral_implications',
            'records[mac-share].payload.literal_public_identifiers',
            'records[mac-share].payload.nonliteral_implications',
        ),
        'server-randomness': (
            'records[randomness-share].payload.literal_public_identifiers',
            'records[randomness-share].payload.nonliteral_implications',
            'records[randomness-mac].payload.literal_public_identifiers',
            'records[randomness-mac].payload.nonliteral_implications',
        ),
    },
    'colluder-wallet-capture': {
        'colluder-decrypted-receipts': (
            'decrypted_receipts[].source', 'decrypted_receipts[].value'),
        'colluder-inputs-and-outputs': (
            'original.value.input_and_created_outputs',),
        'colluder-invoices': ('invoices[].source', 'invoices[].value'),
        'colluder-original': ('original.source', 'original.value'),
        'retry-history': ('retry_history[].source_and_value',),
    },
}


def need(value, category):
    if not value:
        raise ValueError('privacy-capture-' + category)


def exact(value, names, category):
    need(type(value) is dict and set(value) == set(names), category)


def word(value, category='word'):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None,
         category)
    return value


def natural(value, category):
    need(type(value) is int and value >= 0, category)
    return value


def _unmodeled_resolution(kind, category, field_path):
    """Describe the evidence that could close one currently open field.

    This is an inventory, not coverage.  A proposal never changes the ledger
    status and cannot authorize a privacy result.  Mapping-dependent fields
    stay measured failures until their source-owned authority and candidate
    effect are actually present.
    """
    key = (kind, category, field_path)
    direct = 'direct_constraint_pending_source_authority'
    assumption = 'source_assumption_pending_selection'
    failure = 'measured_failure_mapping_dependent'
    if kind == 'public-projection':
        if key in {
                (kind, 'amounts', 'effect.reserve_sompi'),
                (kind, 'amounts', 'effect.remaining_sompi'),
                (kind, 'fees', 'effect.fee_sompi')}:
            mode = direct
            requirement = 'PUBLIC_PROJECTION_VALUE_CANDIDATE_CONSTRAINT'
        elif key == (kind, 'commitments',
                      'outputs[].cm_hiding_and_unlinkability'):
            mode = assumption
            requirement = \
                'PINNED_SHA256_NOTE_COMMITMENT_HIDING_ASSUMPTION'
        elif category == 'proofs' and field_path in (
                'outputs[].proof_bytes', 'aggregate.proof_bytes'):
            mode = assumption
            requirement = 'PINNED_GROTH16_PUBLIC_PROOF_ZK_ASSUMPTION'
        elif key == (kind, 'ciphertexts',
                      'outputs[].confidentiality_key_privacy_and_unlinkability'):
            mode = assumption
            requirement = \
                'PINNED_OUTPUT_CIPHERTEXT_JOINT_CONFIDENTIALITY_ASSUMPTION'
        elif key == (kind, 'ciphertexts',
                      'outputs[].honest_encryption_provenance_and_malicious_owner_tagging'):
            mode = direct
            requirement = \
                'AUTHENTICATED_HONEST_OUTPUT_ENCRYPTION_PRODUCER_AUTHORITY'
        elif category == 'ciphertexts' and field_path in (
                'outputs[].ciphertext_ephemeral_public_key',
                'outputs[].ciphertext_encrypted_receipt',
                'outputs[].ciphertext_poly1305_tag',
                'outputs[].ciphertext_hash'):
            mode = failure
            requirement = 'WITHIN_RUN_PUBLIC_CIPHERTEXT_CANDIDATE_FILTER'
        elif key == (kind, 'nullifiers',
                      'spends[].nf_pseudorandomness_and_unlinkability'):
            mode = assumption
            requirement = \
                'PINNED_NULLIFIER_PRF_AND_UNLINKABILITY_ASSUMPTION'
        elif key == (kind, 'nullifiers',
                      'spends[].deterministic_retry_replay_equality'):
            mode = failure
            requirement = \
                'COMPLETE_PUBLIC_MULTIATTEMPT_NF_EQUALITY_JOIN'
        elif key == (kind, 'value-commitments',
                      'joint_hiding_blind_freshness_and_reuse'):
            mode = assumption
            requirement = 'PINNED_PEDERSEN_CV_JOINT_VIEW_ASSUMPTION'
        elif key == (kind, 'value-commitments',
                      'candidate_group_residuals'):
            mode = failure
            requirement = \
                'WITHIN_RUN_PUBLIC_CV_RESIDUAL_CANDIDATE_FILTER'
        elif category == 'state-transition' and field_path in (
                'state.cm_roots_and_append_paths',
                'state.nf_roots_predecessors_successors_and_paths'):
            mode = direct
            requirement = 'PUBLIC_STATE_TRANSITION_CANDIDATE_CONSTRAINT'
        elif key == (kind, 'state-transition',
                      'state.nf_witness_public_history_edges'):
            mode = failure
            requirement = 'PUBLIC_NF_HISTORY_EDGE_CANDIDATE_FILTER'
        elif key == (kind, 'state-transition',
                      'state.cross_attempt_public_byte_equalities'):
            mode = failure
            requirement = \
                'COMPLETE_PUBLIC_MULTIATTEMPT_HISTORY_EQUALITY_JOIN'
        elif key == (kind, 'state-transition',
                      'state.two_round_projection_structural_continuity'):
            mode = direct
            requirement = \
                'LIVE_STRUCTURAL_PROJECTION_CONTINUITY_RESIDUAL_AND_WORKLOAD_JOIN'
        elif key == (kind, 'state-transition',
                      'state.accepted_chain_state_and_outpoint_continuity'):
            mode = direct
            requirement = \
                'STEP3_ACCEPTED_CHAIN_STATE_AND_OUTPOINT_HISTORY_AUTHORITY'
        elif key == (kind, 'context-identities',
                      'context.two_round_structural_profile_script_binding'):
            mode = direct
            requirement = \
                'LIVE_STRUCTURAL_PROJECTION_CONTINUITY_RESIDUAL_AND_WORKLOAD_JOIN'
        elif key == (kind, 'context-identities',
                      'context.accepted_chain_outpoint_and_external_history_linkage'):
            mode = direct
            requirement = \
                'STEP3_ACCEPTED_CHAIN_STATE_AND_OUTPOINT_HISTORY_AUTHORITY'
        else:
            need(False, 'unmodeled-public-proposal')
    elif kind == 'terminal-history':
        need(category == 'terminal-grouping' and field_path in (
            'groups[].owner_nf_tuple_membership', 'cross_round_links[]'),
            'unmodeled-terminal-proposal')
        mode = failure
        requirement = (
            'MATCHED_NATIVE_TERMINAL_PRODUCER_AUTHORITY_AND_PRIVATE_V2_LEAF'
            if field_path == 'groups[].owner_nf_tuple_membership' else
            'MATCHED_NATIVE_TERMINAL_PRODUCER_AUTHORITY_AND_PUBLIC_CONTINUITY_JOIN')
    elif kind == 'dispatcher-capture':
        need(key[1:] in {
            ('cohort-membership', 'cohort_sha256'),
            ('connection-order', 'events[owner-connected].sequence'),
            ('lengths', 'events[].bytes'),
            ('operation-timing', 'events[].monotonic_ns'),
            ('outbound-routes', 'events[outbound-route].route_sha256'),
            ('public-receipts',
             'release_order_policy_and_direct_exports'),
            ('retry-history', 'retry_history[]'),
            ('upload-order', 'events[owner-upload-complete].sequence'),
        }, 'unmodeled-dispatcher-proposal')
        if category == 'public-receipts':
            mode = failure
            requirement = 'AUTHENTICATED_CONSTRUCTION_POLICY_MAPPING'
        else:
            mode = direct
            requirement = ('AUTHENTICATED_ROLE_BLIND_ROUTE_HANDOFF'
                if category == 'outbound-routes'
                else 'AUTHENTICATED_DISPATCHER_EVENT_CANDIDATE_CONSTRAINT')
    elif kind == 'corrupt-server-capture':
        direct_fields = {
            'capture.model_preimage_binding',
            'capture.public_query_preimage_binding',
            'capture.scalar_callsite_manifest_binding',
            'records[scalar-capture-binding].site_kind_element_count_order',
            'wire.frames[].monotonic_ns',
            'wire.frames[].payload_length',
            'wire.frames[].sequence_message_chunk_order',
            'wire.frames[].direction_peer_fork',
            'attempt.abort_retry_partial_transcript',
            'capture.source_build_launch_role_binding',
            'records[authenticated-group-query-msm-temporary].capture_correspondence',
            'records[authenticated-g1-state].D_equals_Q_minus_U',
            'records[authenticated-g1-state].beaver_product_equations',
            'records[authenticated-g1-state].C_equals_products_plus_L_plus_H',
        }
        need(category in SERVER_CATEGORIES,
             'unmodeled-server-category-proposal')
        if field_path in direct_fields:
            mode = direct
            if field_path.startswith('capture.') or field_path.startswith(
                    'records[scalar-capture-binding]'):
                requirement = 'C03_SOURCE_AUTHORITY_BINDING'
            elif category == 'authenticated-group-state':
                requirement = 'TYPED_GROUP_CORRESPONDENCE_CHECK'
            else:
                requirement = 'WITHIN_RUN_EMPIRICAL_CANDIDATE_FILTER'
        else:
            source_fields = {
                path for paths in ARTIFACT_LEAKAGE_FIELDS[
                    'corrupt-server-capture'].values() for path in paths
                if (path.endswith('.nonliteral_implications')
                    or path in {
                        'wire.frames[].mixed_protocol_nonliteral_implications',
                        'records[authenticated-group-query-msm-temporary].compressed_query_bytes',
                        'records[authenticated-group-query-msm-temporary].decoded_public_point_chunks',
                        'records[authenticated-group-query-msm-temporary].point_map_share_mac',
                        'records[authenticated-group-query-msm-temporary].worker_partials',
                        'records[authenticated-group-query-msm-temporary].running_query_sums',
                    })
            }
            need(field_path in source_fields,
                 'unmodeled-server-source-proposal')
            mode = assumption
            if (category == 'authenticated-group-state'
                    or 'g1' in field_path or 'g2' in field_path):
                requirement = 'PINNED_AUTHENTICATED_GROUP_VIEW_ASSUMPTION'
            elif ('owner-input-' in field_path):
                requirement = 'PINNED_DDNNT_5N_OWNER_INPUT_ASSUMPTION'
            elif 'final-proof-' in field_path:
                requirement = 'PINNED_GROTH16_PUBLIC_PROOF_ZK_ASSUMPTION'
            elif field_path == \
                    'wire.frames[].mixed_protocol_nonliteral_implications':
                requirement = 'PINNED_MIXED_PROTOCOL_JOINT_VIEW_ASSUMPTION'
            else:
                requirement = 'PINNED_STOCK_MASCOT_JOINT_VIEW_ASSUMPTION'
    elif kind == 'colluder-wallet-capture':
        need(field_path in {
            'original.source', 'invoices[].source', 'invoices[].value',
            'decrypted_receipts[].source', 'decrypted_receipts[].value',
            'retry_history[].source_and_value',
        }, 'unmodeled-colluder-proposal')
        if field_path.endswith('.source'):
            mode = direct
            requirement = 'AUTHENTICATED_C1_SOURCE_PROVENANCE'
        else:
            mode = failure
            requirement = ('COMPLETE_MULTIATTEMPT_WORKLOAD_JOIN'
                if field_path.startswith('retry_history')
                else 'AUTHENTICATED_C1_CONTACT_AND_VALUE_BINDING')
    else:
        need(False, 'unmodeled-artifact-proposal')
    return {
        'status': 'unmodeled',
        'proposed_resolution': mode,
        'evidence_requirement': requirement,
        'mapping_dependent': mode == failure,
        'coverage_relabel_allowed': False,
    }


def _private_unmodeled_inventory(view, selected):
    unmodeled_artifacts = []
    for artifact in selected:
        fields = []
        for row in artifact['leakage_ledger']:
            if row['status'] != 'unmodeled':
                continue
            proposal = _unmodeled_resolution(
                artifact['kind'], row['category'], row['field_path'])
            fields.append({
                'category': row['category'],
                'field_path': row['field_path'],
                **proposal,
            })
        if fields:
            unmodeled_artifacts.append({
                'raw_typed_leaf_kind': artifact['kind'],
                'typed_artifact_schema': artifact['schema'],
                'typed_inventory_schema': artifact['inventory']['schema'],
                'artifact_sha256': artifact['artifact_sha256'],
                'fields': fields,
            })
    return {
        'schema': 'kpb-private-unmodeled-field-inventory/v1',
        'view': view,
        'missing_artifacts': [],
        'missing_artifact_count': 0,
        'unmodeled_artifacts': unmodeled_artifacts,
        'unmodeled_artifact_count': len(unmodeled_artifacts),
        'unmodeled_field_count': sum(
            len(artifact['fields']) for artifact in unmodeled_artifacts),
        'authorizes_coverage': False,
    }


def canonical(raw):
    value = codec.parse(raw)
    need(codec.encoded(value) == raw, 'canonical-json')
    return value


CAPTURE_KIND_CODE = {
    'public-projection': 1,
    'terminal-history': 2,
    'dispatcher-capture': 3,
    'corrupt-server-capture': 4,
    'colluder-wallet-capture': 5,
}


def capture_closure(value, records, payload_bytes, cohort_sha256,
                    round_number, kind):
    """Require producer/capture counter agreement and a closed source log."""
    base_fields = ('schema', 'attempt_id', 'cohort_sha256',
                   'producer_record_count', 'capture_record_count',
                   'producer_payload_bytes', 'capture_payload_bytes',
                   'producer_stream_counts', 'capture_stream_counts',
                   'record_chain_sha256', 'unknown_record_count',
                   'capture_root_closed', 'producer_fd_closed')
    wire_fields = ('raw_wire_bytes', 'raw_wire_sha256',
                   'end_frame_identity', 'eof_identity')
    need(kind in CAPTURE_KIND_CODE and round_number in (1, 2),
         'closure-context')
    need(type(value) is dict and value.get('schema') in (
        'kpb-capture-source-closure/v1',
        'kpb-capture-source-closure/v2'), 'closure-schema')
    exact(value, base_fields + (wire_fields if value['schema'].endswith('/v2')
                                else ()), 'closure-fields')
    stream_counts = {}
    for record in records:
        need(type(record) is dict and type(record.get('stream')) is str,
             'closure-typed-record-stream')
        stream_counts[record['stream']] = stream_counts.get(
            record['stream'], 0) + 1
    need(type(value['attempt_id']) is str
         and re.fullmatch('[A-Za-z0-9_-]{1,128}', value['attempt_id'])
         and value['cohort_sha256'] == cohort_sha256
         and value['producer_record_count'] == len(records)
         and value['capture_record_count'] == len(records)
         and value['producer_payload_bytes'] == payload_bytes
         and value['capture_payload_bytes'] == payload_bytes
         and value['producer_stream_counts'] == stream_counts
         and value['capture_stream_counts'] == stream_counts
         and value['record_chain_sha256'] == hashlib.sha256(
             codec.encoded(records)).hexdigest()
         and value['unknown_record_count'] == 0
         and value['capture_root_closed'] is True
         and value['producer_fd_closed'] is True,
         'complete-closed-source-log')
    if value['schema'].endswith('/v2'):
        need(type(value['raw_wire_bytes']) is int
             and value['raw_wire_bytes'] > 0,
             'closure-wire-bytes')
        for name in wire_fields[1:]:
            word(value[name], 'closure-' + name)
        eof_preimage = (b'KPB_CAPTURE_PRODUCER_STREAM_EOF_V1\n'
                        + struct.pack('>IBQQQ', round_number,
                                      CAPTURE_KIND_CODE[kind],
                                      value['producer_record_count'],
                                      value['producer_payload_bytes'],
                                      value['raw_wire_bytes'])
                        + bytes.fromhex(value['raw_wire_sha256'])
                        + bytes.fromhex(value['end_frame_identity']))
        need(hashlib.sha256(eof_preimage).hexdigest() ==
             value['eof_identity'], 'closure-eof-binding')
    return value['attempt_id']


def _leakage_ledger(kind, *, unmodeled_fields=(), constraint_counts=None,
                    source_assumptions=None):
    unmodeled_fields = set(unmodeled_fields)
    constraint_counts = {} if constraint_counts is None else constraint_counts
    source_assumptions = ({} if source_assumptions is None
                          else source_assumptions)
    known = {(category, field_path)
             for category, paths in ARTIFACT_LEAKAGE_FIELDS[kind].items()
             for field_path in paths}
    need(unmodeled_fields <= known
         and set(constraint_counts) <= known
         and set(source_assumptions) <= known
         and not (unmodeled_fields & set(source_assumptions))
         and not (unmodeled_fields & set(constraint_counts))
         and not (set(source_assumptions) & set(constraint_counts))
         and (unmodeled_fields | set(constraint_counts)
              | set(source_assumptions)) == known,
         'leakage-ledger-field-selection')
    need(all(SELECTED_SOURCE_ASSUMPTIONS.get((kind, *key)) == digest
             for key, digest in source_assumptions.items()),
         'unselected-source-assumption')
    result = []
    for category in sorted(ARTIFACT_LEAKAGE_FIELDS[kind]):
        for field_path in sorted(ARTIFACT_LEAKAGE_FIELDS[kind][category]):
            key = (category, field_path)
            assumption = source_assumptions.get(key)
            status = ('unmodeled' if key in unmodeled_fields else
                      'source_assumption_covered' if assumption is not None else
                      'constraint_modeled')
            count = constraint_counts.get(key, 0)
            need(type(count) is int and count >= 0,
                 'leakage-ledger-constraint-count')
            if status == 'source_assumption_covered':
                word(assumption, 'leakage-ledger-assumption')
                need(count == 0, 'assumption-is-not-measured-constraint')
            else:
                need(assumption is None, 'leakage-ledger-no-assumption')
            if status == 'constraint_modeled':
                need(count > 0,
                     'constraint-modeled-requires-positive-field-count')
            if status == 'unmodeled':
                need(count == 0, 'unmodeled-is-not-measured-constraint')
            result.append({
                'category': category,
                'field_path': field_path,
                'status': status,
                'constraint_count': count,
                'assumption_sha256': assumption,
            })
    return result


def _validate_leakage_ledger(kind, ledger):
    need(type(ledger) is list and ledger, 'nonempty-leakage-ledger')
    expected = {(category, field_path)
                for category, paths in ARTIFACT_LEAKAGE_FIELDS[kind].items()
                for field_path in paths}
    actual = set()
    for row in ledger:
        exact(row, ('category', 'field_path', 'status', 'constraint_count',
                    'assumption_sha256'), 'leakage-ledger-fields')
        key = (row['category'], row['field_path'])
        need(key in expected and key not in actual
             and row['status'] in LEAKAGE_STATUSES
             and type(row['constraint_count']) is int
             and row['constraint_count'] >= 0,
             'leakage-ledger-row')
        actual.add(key)
        if row['status'] == 'source_assumption_covered':
            word(row['assumption_sha256'], 'leakage-ledger-assumption')
            need(SELECTED_SOURCE_ASSUMPTIONS.get((kind, *key)) ==
                 row['assumption_sha256'],
                 'unselected-source-assumption')
            need(row['constraint_count'] == 0,
                 'assumption-is-not-measured-constraint')
        else:
            need(row['assumption_sha256'] is None,
                 'leakage-ledger-no-assumption')
        if row['status'] == 'constraint_modeled':
            need(row['constraint_count'] > 0,
                 'constraint-modeled-requires-positive-field-count')
        if row['status'] == 'unmodeled':
            need(row['constraint_count'] == 0,
                 'unmodeled-is-not-measured-constraint')
    need(actual == expected, 'complete-per-field-leakage-ledger')
    return ledger


def artifact_result(raw, kind, round_number, constraints, categories,
                    inventory, *, terminal=False, cross_round_links=(),
                    unmodeled_fields=(), constraint_counts=None,
                    source_assumptions=None):
    need(kind in ARTIFACT_CATEGORIES
         and frozenset(categories) == ARTIFACT_CATEGORIES[kind],
         'artifact-category-attribution')
    ledger = _leakage_ledger(
        kind, unmodeled_fields=unmodeled_fields,
        constraint_counts=constraint_counts,
        source_assumptions=source_assumptions)
    return {
        'schema': 'kpb-typed-capture-artifact-model/v2',
        'kind': kind,
        'round': round_number,
        'artifact_sha256': hashlib.sha256(raw).hexdigest(),
        'constraints': constraints,
        'categories': sorted(categories),
        'inventory': inventory,
        'leakage_ledger': ledger,
        'terminal_modeled': terminal,
        'cross_round_links': list(cross_round_links),
    }


def _u32(raw):
    return int.from_bytes(raw, 'little')


def _u64(raw):
    return int.from_bytes(raw, 'little')


BABYJUB_BASE_MODULUS = FIELD_MODULUS
BABYJUB_SCALAR_MODULUS = \
    2736030358979909402780800718157159386076813972158567259200215660948447373041
BABYJUB_D = \
    9706598848417545097372247223557719406784115219466060233080913168975159366771
BABYJUB_VALUE_GENERATOR = bytes.fromhex(
    '36b7c68c104228f1801433c7ad8b495b15ec16a0c75d3637e91f43eb21f3fc00'
    '77d597319843798462f0abf4bd615c8eb47732958db946f22dcebdf89085b300')
BABYJUB_BLINDING_GENERATOR = bytes.fromhex(
    '9b9ab526078e057c4be7be0d9a0b834a9ea42c55ec92e062177f1bfbc141232e'
    '13ddd21ee593ae324f9c79cf7a5d81c89103b615194c781b49314a17e298c712')
_BABYJUB_IDENTITY = (0, 1)
_BABYJUB_DECODE_CACHE = {}


def _babyjub_add(left, right):
    x1, y1 = left; x2, y2 = right; modulus = BABYJUB_BASE_MODULUS
    product = BABYJUB_D * x1 * x2 * y1 * y2 % modulus
    x_denominator = (1 + product) % modulus
    y_denominator = (1 - product) % modulus
    need(x_denominator != 0 and y_denominator != 0,
         'public-cv-group-denominator')
    return (((x1 * y2 + y1 * x2) % modulus)
            * pow(x_denominator, modulus - 2, modulus) % modulus,
            ((y1 * y2 - x1 * x2) % modulus)
            * pow(y_denominator, modulus - 2, modulus) % modulus)


def _babyjub_negate(point):
    return ((-point[0]) % BABYJUB_BASE_MODULUS, point[1])


def _babyjub_mul(point, scalar):
    need(type(scalar) is int and scalar >= 0, 'public-cv-scalar')
    result = _BABYJUB_IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _babyjub_add(result, addend)
        addend = _babyjub_add(addend, addend)
        scalar >>= 1
    return result


def _babyjub_encode(point):
    return (point[0].to_bytes(32, 'little')
            + point[1].to_bytes(32, 'little'))


def _babyjub_decode(raw):
    need(type(raw) is bytes and len(raw) == 64,
         'public-cv-canonical-width')
    cached = _BABYJUB_DECODE_CACHE.get(raw)
    if cached is not None:
        return cached
    x = int.from_bytes(raw[:32], 'little')
    y = int.from_bytes(raw[32:], 'little')
    modulus = BABYJUB_BASE_MODULUS
    need(x < modulus and y < modulus
         and (x * x + y * y - 1
              - BABYJUB_D * x * x * y * y) % modulus == 0
         and (x, y) != _BABYJUB_IDENTITY,
         'public-cv-canonical-curve-point')
    point = (x, y)
    need(_babyjub_mul(point, BABYJUB_SCALAR_MODULUS) ==
            _BABYJUB_IDENTITY,
         'public-cv-prime-subgroup')
    _BABYJUB_DECODE_CACHE[raw] = point
    return point


def _public_cv_model(public, input_raw, output_raw, fee, delta_raw):
    """Validate the exact public CV equation and enumerate grouping residuals."""
    input_points = [_babyjub_decode(row) for row in input_raw]
    output_points = [_babyjub_decode(row) for row in output_raw]
    need(type(delta_raw) is bytes and len(delta_raw) == 32,
         'public-cv-delta-width')
    delta = int.from_bytes(delta_raw, 'little')
    need(delta < BABYJUB_SCALAR_MODULUS,
         'public-cv-canonical-delta')
    difference = _BABYJUB_IDENTITY
    for point in input_points:
        difference = _babyjub_add(difference, point)
    for point in output_points:
        difference = _babyjub_add(difference, _babyjub_negate(point))
    value_generator = _babyjub_decode(BABYJUB_VALUE_GENERATOR)
    blinding_generator = _babyjub_decode(BABYJUB_BLINDING_GENERATOR)
    difference = _babyjub_add(
        difference, _babyjub_negate(_babyjub_mul(value_generator, fee)))
    need(difference == _babyjub_mul(blinding_generator, delta),
         'public-cv-joint-balance')

    candidates = codec.assignments(public, codec.empty_constraints())['joint']
    residual_cache = {}
    encoded_residuals = []
    for candidate in candidates:
        owner_rows = []
        for owner in codec.OWNERS:
            input_index = candidate['inputs'].index(owner)
            output_indexes = tuple(
                index for index, label in enumerate(candidate['outputs'])
                if label == owner)
            key = (input_index, output_indexes)
            if key not in residual_cache:
                residual = input_points[input_index]
                for index in output_indexes:
                    residual = _babyjub_add(
                        residual, _babyjub_negate(output_points[index]))
                residual_cache[key] = _babyjub_encode(residual).hex()
            owner_rows.append(residual_cache[key])
        encoded_residuals.append(owner_rows)
    need(len(encoded_residuals) == 540
         and all(len(row) == 3 for row in encoded_residuals),
         'public-cv-complete-candidate-residuals')
    return {
        'input_cv_count': len(input_points),
        'output_cv_count': len(output_points),
        'canonical_subgroup_point_count':
            len(input_points) + len(output_points),
        'delta_scalar_hex32': delta_raw.hex(),
        'joint_public_balance_verified': True,
        'candidate_grouping_count': len(encoded_residuals),
        'candidate_group_residual_partition_sha256': hashlib.sha256(
            codec.encoded(encoded_residuals)).hexdigest(),
        'candidate_grouping_pruned_count_without_openings': 0,
        'candidate_residuals_feed_selected_prediction': False,
        'hiding_or_fresh_blind_claim': False,
    }


def _validate_public_projection_byte_lanes(rows):
    need(type(rows) is list and rows
         and rows[0]['start'] == 0 and rows[-1]['end'] == 10685
         and all(left['end'] == right['start']
                 for left, right in zip(rows, rows[1:]))
         and sum(row['end'] - row['start'] for row in rows) == 10685
         and len({row['name'] for row in rows}) == len(rows),
         'public-projection-exact-byte-lane-partition')
    known = {(category, field_path)
             for category, fields in
                ARTIFACT_LEAKAGE_FIELDS['public-projection'].items()
             for field_path in fields}
    need(all((row['category'], row['field_path']) in known for row in rows),
         'public-projection-byte-lane-ledger-binding')
    need(hashlib.sha256(codec.encoded(rows)).hexdigest() ==
         PUBLIC_PROJECTION_LANE_MANIFEST_SHA256,
         'public-projection-frozen-byte-lane-manifest')
    return rows


def _public_projection_byte_lanes():
    """Exact disjoint partition of all 10,685 selected projection bytes."""
    rows = []
    def add(name, start, end, category, field_path):
        rows.append({'name': name, 'start': start, 'end': end,
                     'category': category, 'field_path': field_path})
    prefix_shape = \
        'projection.prefix_tag_version_counts_sequence_lengths_and_tail'
    add('prefix-tag-version-count', 0, 12, 'operation-shape', prefix_shape)
    add('prefix-reserve-outpoint', 12, 48, 'context-identities',
        'context.reserve_outpoint')
    add('prefix-sequence', 48, 56, 'operation-shape', prefix_shape)
    add('prefix-reserve-sompi', 56, 64, 'amounts',
        'effect.reserve_sompi')
    add('prefix-reserve-script-length', 64, 66, 'operation-shape',
        prefix_shape)
    add('prefix-reserve-script', 66, 103, 'context-identities',
        'context.two_round_structural_profile_script_binding')
    add('prefix-output-count', 103, 105, 'operation-shape', prefix_shape)
    add('prefix-remaining-sompi', 105, 113, 'amounts',
        'effect.remaining_sompi')
    add('prefix-successor-script-length', 113, 115, 'operation-shape',
        prefix_shape)
    add('prefix-successor-script', 115, 152, 'context-identities',
        'context.two_round_structural_profile_script_binding')
    add('prefix-sigops-locktime-subnetwork-gas', 152, 189,
        'operation-shape', prefix_shape)
    add('prefix-body-length', 189, 193, 'operation-shape', prefix_shape)
    base = 193
    add('effect-tag', base, base + 8, 'operation-shape', 'effect.tag')
    profile_names = ('chain-genesis', 'pool-lineage', 'wallet-profile',
                     'domain', 'service-policy')
    for index, name in enumerate(profile_names):
        add('context-' + name, base + 8 + index * 32,
            base + 40 + index * 32, 'context-identities',
            'context.profile_genesis_lineage_domain_service_identifiers')
    add('reserve-outpoint', base + 168, base + 204,
        'context-identities', 'context.reserve_outpoint')
    add('old-cm-root', base + 204, base + 236, 'state-transition',
        'state.cm_roots_and_append_paths')
    add('old-nf-root', base + 236, base + 268, 'state-transition',
        'state.nf_roots_predecessors_successors_and_paths')
    add('old-counts', base + 268, base + 276, 'state-transition',
        'state.old_new_counts')
    add('reserve-sompi', base + 276, base + 284, 'amounts',
        'effect.reserve_sompi')
    add('new-cm-root', base + 284, base + 316, 'state-transition',
        'state.cm_roots_and_append_paths')
    add('new-nf-root', base + 316, base + 348, 'state-transition',
        'state.nf_roots_predecessors_successors_and_paths')
    add('new-counts', base + 348, base + 356, 'state-transition',
        'state.old_new_counts')
    add('remaining-sompi', base + 356, base + 364, 'amounts',
        'effect.remaining_sompi')
    add('fee-sompi', base + 364, base + 372, 'fees',
        'effect.fee_sompi')
    add('public-delta', base + 372, base + 404, 'value-commitments',
        'effect.delta_scalar')
    for index in range(3):
        start = base + 404 + index * 96
        add('input-' + str(index) + '-nf', start, start + 32,
            'nullifiers', 'spends[].nf')
        add('input-' + str(index) + '-cv', start + 32, start + 96,
            'value-commitments', 'inputs[].cv_bytes_and_subgroup')
    for index in range(6):
        start = base + 692 + index * 520
        # Pinned crypto_box 0.9.1 seal() delegates to SalsaBox/SecretBox;
        # crypto_secretbox 0.1.1 encrypt_in_place prepends its 16-byte tag.
        # The sealed 264-byte lane is therefore eph32 || tag16 || ciphertext216.
        for suffix, left, right, category, field_path in (
                ('cm', 0, 32, 'commitments', 'outputs[].cm'),
                ('cv', 32, 96, 'value-commitments',
                 'outputs[].cv_bytes_and_subgroup'),
                ('ciphertext-ephemeral-public-key', 96, 128,
                 'ciphertexts',
                 'outputs[].ciphertext_ephemeral_public_key'),
                ('ciphertext-poly1305-tag', 128, 144, 'ciphertexts',
                 'outputs[].ciphertext_poly1305_tag'),
                ('ciphertext-encrypted-receipt', 144, 360,
                 'ciphertexts', 'outputs[].ciphertext_encrypted_receipt'),
                ('ciphertext-hash', 360, 392, 'ciphertexts',
                 'outputs[].ciphertext_hash'),
                ('proof', 392, 520, 'proofs',
                 'outputs[].proof_bytes')):
            add('output-' + str(index) + '-' + suffix,
                start + left, start + right, category, field_path)
    for index in range(3):
        start = base + 3812 + index * 1160
        for suffix, left, right, field_path in (
                ('predecessor-index', 0, 4,
                 'state.nf_witness_public_history_edges'),
                ('predecessor', 4, 36,
                 'state.nf_witness_public_history_edges'),
                ('successor', 36, 68,
                 'state.nf_witness_public_history_edges'),
                ('successor-index', 68, 72,
                 'state.nf_witness_public_history_edges'),
                ('predecessor-path', 72, 616,
                 'state.nf_roots_predecessors_successors_and_paths'),
                ('append-path', 616, 1160,
                 'state.nf_roots_predecessors_successors_and_paths')):
            add('nf-witness-' + str(index) + '-' + suffix,
                start + left, start + right, 'state-transition', field_path)
    for index in range(6):
        start = base + 7292 + index * 512
        add('cm-append-path-' + str(index), start, start + 512,
            'state-transition', 'state.cm_roots_and_append_paths')
    add('aggregate-proof', base + 10364, base + 10492, 'proofs',
        'aggregate.proof_bytes')
    return _validate_public_projection_byte_lanes(rows)


def inspect_fd40_structural_continuity_prefix(
        prefix, raw_rounds, public_rounds):
    """Decode the selected FD40 grammar without minting model authority."""
    return fd40_structural.parse_prefix(prefix, raw_rounds, public_rounds)


def _structural_projection_binding(raw_rounds, public_rounds):
    need(type(raw_rounds) is list and len(raw_rounds) == 2
         and type(public_rounds) is list and len(public_rounds) == 2
         and [public['round'] for public in public_rounds] == [1, 2],
         'structural-continuity-two-rounds')
    first, second = raw_rounds
    need(all(type(raw) is bytes and len(raw) == 10685
             for raw in raw_rounds), 'structural-continuity-projection-width')
    base = 193
    return {
        'projection_sha256': tuple(
            public['projection_sha256'] for public in public_rounds),
        'profile_context': (first[base + 8:base + 168],
                            second[base + 8:base + 168]),
        'scripts': (first[115:152], second[66:103]),
        'cm_roots': (first[base + 284:base + 316],
                     second[base + 204:base + 236]),
        'nf_roots': (first[base + 316:base + 348],
                     second[base + 236:base + 268]),
        'counts': (first[base + 348:base + 356],
                   second[base + 268:base + 276]),
        'reserve_sompi': (_u64(first[base + 356:base + 364]),
                          _u64(second[base + 276:base + 284])),
        'round2_old_outpoint': second[12:48],
        'accepted_chain_continuity': False,
    }


def _require_structural_projection_relation(binding):
    need(binding['profile_context'][0] == binding['profile_context'][1]
         and binding['scripts'][0] == binding['scripts'][1]
         and binding['cm_roots'][0] == binding['cm_roots'][1]
         and binding['nf_roots'][0] == binding['nf_roots'][1]
         and binding['counts'][0] == binding['counts'][1]
         and binding['reserve_sompi'][0] == binding['reserve_sompi'][1]
         and binding['round2_old_outpoint'] != bytes(36)
         and binding['accepted_chain_continuity'] is False,
         'structural-continuity-exact-relation')


_SELECTED_STRUCTURAL_CONTEXT_CONSTRUCTOR = object()


class _SelectedFd40StructuralContext:
    __slots__ = ('candidate_count_before', 'candidate_count_after')

    def __init__(self, constructor, before, after):
        need(constructor is _SELECTED_STRUCTURAL_CONTEXT_CONSTRUCTOR
             and type(before) is int and before > 0
             and type(after) is int and after == before,
             'selected-structural-context-constructor')
        self.candidate_count_before = before
        self.candidate_count_after = after


def _public_projection_model(raw, public, structural_context=None):
    """Inventory the exact selected 10,685-byte public projection.

    The selected source grammar contains no owner-label field, so this adapter
    emits no owner/NF/tuple/pair edge from public row order alone.  Proofs,
    CVs, ciphertexts, witnesses and paths remain observed typed bytes.  Frame
    parsing is deliberately not described as proof validity or hiding.
    """
    codec.batch(public)
    # A Python class, constructor sentinel or module registry is not a
    # capability boundary: any same-interpreter caller can import and forge
    # it.  Keep the two structural rows open until the isolated worker is
    # entered through a native, non-importable one-shot authority.
    need(structural_context is None,
         'selected-fd40-native-structural-authority-required')
    structural_bound = False
    need(type(raw) is bytes and len(raw) == 10685,
         'public-projection-width')
    prefix, body = raw[:193], raw[193:]
    need(prefix[:8] == b'KPBAFX01'
         and prefix[8:12] == bytes((1, 0, 1, 0))
         and prefix[48:56] == bytes([255]) * 8
         and prefix[64:66] == bytes((37, 0))
         and prefix[103:105] == bytes((1, 0))
         and prefix[113:115] == bytes((37, 0))
         and prefix[152] == 0
         and prefix[153:189] == bytes(36)
         and _u32(prefix[189:193]) == 10492,
         'public-projection-prefix')
    for script in (prefix[66:103], prefix[115:152]):
        need(script[:4] == bytes((0, 0, 0xaa, 0x20))
             and script[36] == 0x87,
             'public-projection-script-shape')
    need(body[:8] == b'KPBAEF01'
         and prefix[12:48] == body[168:204]
         and _u64(prefix[56:64]) == _u64(body[276:284])
         and _u64(prefix[105:113]) == _u64(body[356:364]),
         'public-projection-effect-binding')

    old_n, old_m = _u32(body[268:272]), _u32(body[272:276])
    new_n, new_m = _u32(body[348:352]), _u32(body[352:356])
    reserve, remaining, fee = (_u64(body[276:284]),
                               _u64(body[356:364]),
                               _u64(body[364:372]))
    need(body[168:200] != bytes(32)
         and 3 <= old_n <= 65536 and 1 <= old_m <= 131072
         and new_n == old_n + 6 and new_m == old_m + 3
         and 1 <= new_n <= 65536 and 1 <= new_m <= 131072,
         'public-projection-point-and-counts')
    need(60_000_000 <= reserve <= 2_870_000_000_000_000_000
         and 60_000_000 <= remaining <= 2_870_000_000_000_000_000
         and 1 <= fee <= 2_870_000_000_000_000_000
         and remaining + fee == reserve,
         'public-projection-money')

    nfs = [body[404 + 96 * index:436 + 96 * index]
           for index in range(3)]
    input_cvs = [body[436 + 96 * index:500 + 96 * index]
                 for index in range(3)]
    need(all(nf != bytes(32) for nf in nfs)
         and [int.from_bytes(nf, 'little') for nf in nfs]
             == sorted(int.from_bytes(nf, 'little') for nf in nfs)
         and len(set(nfs)) == 3,
         'public-projection-sorted-distinct-nfs')
    rows = [body[692 + 520 * index:692 + 520 * (index + 1)]
            for index in range(6)]
    cms = [row[:32] for row in rows]
    output_cvs = [row[32:96] for row in rows]
    ciphertexts = [row[96:360] for row in rows]
    ciphertext_ephemeral_public_keys = [row[:32] for row in ciphertexts]
    ciphertext_poly1305_tags = [row[32:48] for row in ciphertexts]
    ciphertext_encrypted_receipts = [row[48:] for row in ciphertexts]
    ciphertext_hashes = [row[360:392] for row in rows]
    output_proofs = [row[392:520] for row in rows]
    empty_cm = hashlib.sha256(b'KPX1CME\0').digest()
    need(all(cm not in (bytes(32), empty_cm) for cm in cms)
         and len(set(cms)) == 6 and len(set(rows)) == 6,
         'public-projection-distinct-outputs')
    need(all(hashlib.sha256(row[96:360]).digest() == row[360:392]
             for row in rows), 'public-projection-ciphertext-hashes')
    derived = {
        'round': public['round'],
        'projection_sha256': hashlib.sha256(raw).hexdigest(),
        'context_sha256': hashlib.sha256(body[8:284]).hexdigest(),
        'nfs_hex32': [nf.hex() for nf in nfs],
        'cms_hex32': [cm.hex() for cm in cms],
        'tuple_sha256': [hashlib.sha256(row).hexdigest() for row in rows],
    }
    need(derived == public, 'public-projection-model-binding')
    cv_model = _public_cv_model(
        public, input_cvs, output_cvs, fee, body[372:404])
    byte_lanes = _public_projection_byte_lanes()
    def equal_pairs(values):
        return [[left, right] for left in range(len(values))
                for right in range(left + 1, len(values))
                if values[left] == values[right]]
    nf_witness_history_edges = []
    for index, nf in enumerate(nfs):
        witness = body[3812 + index * 1160:3812 + (index + 1) * 1160]
        nf_witness_history_edges.append({
            'input_nf_hex32': nf.hex(),
            'predecessor_index': _u32(witness[:4]),
            'predecessor_nf_hex32': witness[4:36].hex(),
            'successor_nf_hex32': witness[36:68].hex(),
            'successor_index': _u32(witness[68:72]),
            'predecessor_path_sha256': hashlib.sha256(
                witness[72:616]).hexdigest(),
            'append_path_sha256': hashlib.sha256(
                witness[616:1160]).hexdigest(),
        })
    inventory = {
        'schema': 'kpb-public-projection-byte-inventory/v1',
        'projection_bytes': 10685,
        'prefix_bytes': 193,
        'body_bytes': 10492,
        'body_core_bytes': 10364,
        'spend_rows': 3,
        'output_rows': 6,
        'ciphertext_bytes': 6 * 264,
        'output_proof_bytes': 6 * 128,
        'nf_witness_bytes': 3480,
        'cm_path_bytes': 3072,
        'aggregate_proof_bytes': 128,
        'byte_lane_count': len(byte_lanes),
        'byte_lane_total_bytes': sum(
            row['end'] - row['start'] for row in byte_lanes),
        'byte_lanes': byte_lanes,
        'byte_lane_manifest_sha256': hashlib.sha256(
            codec.encoded(byte_lanes)).hexdigest(),
        'context_identifiers_hex32': [
            body[8 + 32 * index:40 + 32 * index].hex()
            for index in range(5)],
        'reserve_outpoint_hex36': body[168:204].hex(),
        'old_cm_root_hex32': body[204:236].hex(),
        'old_nf_root_hex32': body[236:268].hex(),
        'new_cm_root_hex32': body[284:316].hex(),
        'new_nf_root_hex32': body[316:348].hex(),
        'old_cm_count': old_n,
        'old_nf_count': old_m,
        'new_cm_count': new_n,
        'new_nf_count': new_m,
        'nf_witness_public_history_edges': nf_witness_history_edges,
        'same_projection_public_byte_equalities': {
            'nullifier_pairs': equal_pairs(nfs),
            'commitment_pairs': equal_pairs(cms),
            'ciphertext_ephemeral_public_key_pairs': equal_pairs(
                ciphertext_ephemeral_public_keys),
            'ciphertext_poly1305_tag_pairs': equal_pairs(
                ciphertext_poly1305_tags),
            'ciphertext_encrypted_receipt_pairs': equal_pairs(
                ciphertext_encrypted_receipts),
            'ciphertext_hash_pairs': equal_pairs(ciphertext_hashes),
            'output_proof_pairs': equal_pairs(output_proofs),
        },
        'honest_encryption_producer_authority_consumed': False,
        'complete_public_multiattempt_history_joined': False,
        'structural_continuity_authority_consumed': structural_bound,
        'structural_continuity_candidate_count_before':
            (structural_context.candidate_count_before
             if structural_bound else None),
        'structural_continuity_candidate_count_after':
            (structural_context.candidate_count_after
             if structural_bound else None),
        'accepted_chain_continuity_proven': False,
        'cv_model': cv_model,
        'reserve_sompi': reserve,
        'remaining_sompi': remaining,
        'fee_sompi': fee,
        'aggregate_value_constraints': {
            'reserve_sompi': reserve,
            'remaining_sompi': remaining,
            'fee_sompi': fee,
        },
        'individual_input_amount_fields': 0,
        'individual_output_amount_fields': 0,
        'owner_label_fields': 0,
        'direct_constraint_count': 0,
        'proof_validity_or_privacy_claim': False,
    }
    return artifact_result(raw, 'public-projection', public['round'],
                           codec.empty_constraints(),
                           PROJECTION_CATEGORIES, inventory,
                           unmodeled_fields=(set((
                               ('ciphertexts',
                                'outputs[].ciphertext_ephemeral_public_key'),
                               ('ciphertexts',
                                'outputs[].ciphertext_encrypted_receipt'),
                               ('ciphertexts',
                                'outputs[].ciphertext_poly1305_tag'),
                               ('ciphertexts', 'outputs[].ciphertext_hash'),
                               ('ciphertexts',
                                'outputs[].honest_encryption_provenance_and_malicious_owner_tagging'),
                               ('ciphertexts',
                                'outputs[].confidentiality_key_privacy_and_unlinkability'),
                               ('commitments',
                                'outputs[].cm_hiding_and_unlinkability'),
                               ('context-identities',
                                'context.two_round_structural_profile_script_binding'),
                               ('context-identities',
                                'context.accepted_chain_outpoint_and_external_history_linkage'),
                               ('nullifiers',
                                'spends[].deterministic_retry_replay_equality'),
                               ('nullifiers',
                                'spends[].nf_pseudorandomness_and_unlinkability'),
                               ('proofs', 'outputs[].proof_bytes'),
                               ('proofs', 'aggregate.proof_bytes'),
                               ('state-transition',
                                'state.cm_roots_and_append_paths'),
                               ('state-transition',
                                'state.nf_roots_predecessors_successors_and_paths'),
                               ('state-transition',
                                'state.nf_witness_public_history_edges'),
                               ('state-transition',
                                'state.two_round_projection_structural_continuity'),
                               ('state-transition',
                                'state.accepted_chain_state_and_outpoint_continuity'),
                               ('state-transition',
                                'state.cross_attempt_public_byte_equalities'),
                               ('value-commitments',
                                'candidate_group_residuals'),
                               ('value-commitments',
                                'joint_hiding_blind_freshness_and_reuse'),
                           )) - ({
                               ('context-identities',
                                'context.two_round_structural_profile_script_binding'),
                               ('state-transition',
                                'state.two_round_projection_structural_continuity'),
                           } if structural_bound else set())),
                           constraint_counts={
                               ('amounts', 'effect.reserve_sompi'): 1,
                               ('amounts', 'effect.remaining_sompi'): 1,
                               ('commitments', 'outputs[].cm'): 6,
                               ('context-identities',
                                'context.profile_genesis_lineage_domain_service_identifiers'): 5,
                               ('context-identities',
                                'context.reserve_outpoint'): 1,
                               ('fees', 'effect.fee_sompi'): 1,
                               ('nullifiers', 'spends[].nf'): 3,
                               ('operation-shape',
                                'projection.prefix_tag_version_counts_sequence_lengths_and_tail'): 8,
                               ('operation-shape', 'effect.tag'): 1,
                               ('state-transition',
                                'state.old_new_counts'): 4,
                               ('value-commitments',
                                'inputs[].cv_bytes_and_subgroup'): 3,
                               ('value-commitments',
                                'outputs[].cv_bytes_and_subgroup'): 6,
                               ('value-commitments',
                                'effect.delta_scalar'): 1,
                               ('value-commitments',
                                'joint_public_balance_equation'): 1,
                               **({
                                   ('context-identities',
                                    'context.two_round_structural_profile_script_binding'): 1,
                                   ('state-transition',
                                    'state.two_round_projection_structural_continuity'): 1,
                               } if structural_bound else {}),
                           })


def public_projection(raw, public, _structural_context=None):
    """General parser: caller objects can never close structural rows."""
    need(_structural_context is None,
         'structural-continuity-authenticated-fd40-admission-required')
    return _public_projection_model(raw, public)


def public_projection_pair(raw_rounds, public_rounds,
                           structural_authority=None):
    """Keep structural rows open until the selected FD40 child consumes them.

    A parsed section, caller dict, public receipt, digest or synthetic Python
    object is not the live native admission.  The future selected child path
    must consume that admission and apply the exact workload join internally;
    this general model API has no mint or receipt fallback.
    """
    need(type(raw_rounds) is list and len(raw_rounds) == 2
         and type(public_rounds) is list and len(public_rounds) == 2,
         'structural-continuity-two-rounds')
    unbound = [public_projection(raw_value, public)
               for raw_value, public in zip(raw_rounds, public_rounds)]
    need(structural_authority is None,
         'structural-continuity-authenticated-fd40-admission-required')
    return unbound


def inspect_fd40_public_state_candidate_filter(
        parsed, round_models, terminal_artifacts):
    """Apply public NF history edges to the finite workload, nonauthoritatively.

    Exact indexed-NF and CM transitions are checked against the two projection
    leaves.  The predecessor/successor graph contains no owner label, so its
    predicate is applied to every finite workload candidate and must retain
    every one.  The diagnostic neither closes a ledger row nor mints a token;
    only a future native/isolated admission may turn this computation into
    selected-worker evidence.
    """
    inspection = fd40_archive.inspect_public_state_transitions(parsed)
    publics = parsed['public_rounds']
    raws = parsed['projection_bytes']
    need(type(round_models) is list and len(round_models) == 2 and
         all(type(model) is dict and model.get('public') == public
             for model, public in zip(round_models, publics)),
         'public-nf-history-round-model-binding')
    artifacts = [public_projection(raw, public)
                 for raw, public in zip(raws, publics)]
    for artifact in artifacts:
        ledger = {(row['category'], row['field_path']): row
                  for row in artifact['leakage_ledger']}
        need(ledger[('state-transition',
             'state.cm_roots_and_append_paths')]['status'] == 'unmodeled'
             and ledger[('state-transition',
             'state.nf_roots_predecessors_successors_and_paths')][
                 'status'] == 'unmodeled'
             and ledger[('state-transition',
             'state.nf_witness_public_history_edges')][
                 'status'] == 'unmodeled',
             'public-state-rows-remain-unmodeled')
    workload = workload_candidates(round_models, terminal_artifacts)
    edges_by_round = inspection['nf_history_edges']
    need(type(edges_by_round) is list and len(edges_by_round) == 2,
         'public-nf-history-two-rounds')
    public_relation_holds = True
    for round_index, (edges, public, receipt) in enumerate(zip(
            edges_by_round, publics, inspection['rounds'])):
        need(type(edges) is list and len(edges) == 3,
             'public-nf-history-three-edges')
        for position, edge in enumerate(edges):
            exact(edge, ('input_nf_hex32', 'predecessor_index',
                         'predecessor_nf_hex32', 'successor_nf_hex32',
                         'successor_index'),
                  'public-nf-history-edge-fields')
            input_nf = bytes.fromhex(edge['input_nf_hex32'])
            predecessor = bytes.fromhex(edge['predecessor_nf_hex32'])
            successor = bytes.fromhex(edge['successor_nf_hex32'])
            count = receipt['old_nf_count'] + position
            public_relation_holds &= (
                edge['input_nf_hex32'] == public['nfs_hex32'][position]
                and type(edge['predecessor_index']) is int
                and type(edge['successor_index']) is int
                and 0 <= edge['predecessor_index'] < count
                and 0 <= edge['successor_index'] < count
                and (edge['predecessor_index'] == 0) ==
                    (predecessor == bytes(32))
                and (edge['successor_index'] == 0) ==
                    (successor == bytes(32))
                and int.from_bytes(predecessor, 'little') <
                    int.from_bytes(input_nf, 'little')
                and (successor == bytes(32) or
                     int.from_bytes(input_nf, 'little') <
                     int.from_bytes(successor, 'little')))
        need(public_relation_holds,
             'public-nf-history-source-relation')

    # Deliberately do not inspect either candidate's owner-label vectors. The
    # public predecessor/successor predicate is identical for every member of
    # the already-finite source-derived workload lattice.
    retained = [pair for pair in workload['joint']
                if public_relation_holds]
    need(retained == workload['joint'],
         'public-nf-history-all-candidates-retained')
    return {
        'schema': 'kpb-public-nf-history-finite-candidate-filter/v1',
        'workload_candidates_before': len(workload['joint']),
        'workload_candidates_after': len(retained),
        'pruned_candidates': 0,
        'all_candidates_retained': True,
        'owner_label_fields_consumed': 0,
        'projection_state_transitions_verified': 2,
        'candidate_set_commitment_sha256':
            workload['candidate_set_commitment_sha256'],
        'authorizes_coverage': False,
        'used_for_coverage': False,
        'requires_native_isolated_admission': True,
    }


def inspect_fd40_public_observable_candidate_filters(
        parsed, round_models, terminal_artifacts):
    """Apply ciphertext equality and CV residual tests to every candidate.

    Both features are exact public functions of the selected projection.  A
    ciphertext-component equality pattern has no authenticated owner meaning,
    while candidate CV residuals recombine to the same already-verified global
    balance for every partition without owner openings.  We still enumerate
    and apply both predicates to the finite workload rather than calling them
    harmless by inspection.  The result remains nonauthorizing and the ledger
    rows stay open.
    """
    fd40_archive.inspect_public_state_transitions(parsed)
    publics = parsed['public_rounds']
    raws = parsed['projection_bytes']
    need(type(round_models) is list and len(round_models) == 2 and
         all(type(model) is dict and model.get('public') == public
             for model, public in zip(round_models, publics)),
         'public-observable-round-model-binding')
    artifacts = [public_projection(raw, public)
                 for raw, public in zip(raws, publics)]
    workload = workload_candidates(round_models, terminal_artifacts)

    ciphertext_valid = []
    cv_valid = []
    ciphertext_pattern_identities = []
    cv_residual_identities = []
    ciphertext_paths = (
        'outputs[].ciphertext_ephemeral_public_key',
        'outputs[].ciphertext_encrypted_receipt',
        'outputs[].ciphertext_poly1305_tag',
        'outputs[].ciphertext_hash',
    )
    for round_index, (raw, artifact, model) in enumerate(zip(
            raws, artifacts, round_models)):
        ledger = {(row['category'], row['field_path']): row
                  for row in artifact['leakage_ledger']}
        need(all(ledger[('ciphertexts', path)]['status'] == 'unmodeled'
                 for path in ciphertext_paths) and
             ledger[('value-commitments',
                     'candidate_group_residuals')]['status'] == 'unmodeled',
             'public-observable-rows-remain-unmodeled')
        body = raw[193:]
        rows = [body[692 + 520 * index:692 + 520 * (index + 1)]
                for index in range(6)]
        component_vectors = {
            'ciphertext_ephemeral_public_key_pairs':
                [row[96:128] for row in rows],
            'ciphertext_poly1305_tag_pairs':
                [row[128:144] for row in rows],
            'ciphertext_encrypted_receipt_pairs':
                [row[144:360] for row in rows],
            'ciphertext_hash_pairs': [row[360:392] for row in rows],
        }
        expected_patterns = {}
        for name, values in component_vectors.items():
            expected_patterns[name] = [
                [left, right] for left in range(len(values))
                for right in range(left + 1, len(values))
                if values[left] == values[right]]
        observed_patterns = artifact['inventory'][
            'same_projection_public_byte_equalities']
        need(all(observed_patterns[name] == value
                 for name, value in expected_patterns.items()),
             'public-ciphertext-equality-pattern-binding')
        ciphertext_pattern_identities.append(hashlib.sha256(
            codec.encoded(expected_patterns)).hexdigest())
        # The predicate is public and independent of every hypothetical owner
        # assignment, so it is explicitly applied to (and retains) each row.
        ciphertext_valid.append([True for _ in model['joint']])

        input_points = [_babyjub_decode(
            body[436 + 96 * index:500 + 96 * index])
            for index in range(3)]
        output_points = [_babyjub_decode(row[32:96]) for row in rows]
        aggregate = _BABYJUB_IDENTITY
        for point in input_points:
            aggregate = _babyjub_add(aggregate, point)
        for point in output_points:
            aggregate = _babyjub_add(aggregate, _babyjub_negate(point))
        residual_rows = []
        valid_rows = []
        for candidate in model['joint']:
            owner_residuals = []
            recombined = _BABYJUB_IDENTITY
            for owner in codec.OWNERS:
                input_index = candidate['inputs'].index(owner)
                residual = input_points[input_index]
                for output_index, label in enumerate(candidate['outputs']):
                    if label == owner:
                        residual = _babyjub_add(
                            residual,
                            _babyjub_negate(output_points[output_index]))
                owner_residuals.append(_babyjub_encode(residual).hex())
                recombined = _babyjub_add(recombined, residual)
            valid_rows.append(recombined == aggregate)
            residual_rows.append(owner_residuals)
        need(all(valid_rows), 'public-cv-residual-recombination')
        cv_valid.append(valid_rows)
        cv_residual_identities.append(hashlib.sha256(
            codec.encoded(residual_rows)).hexdigest())

    ciphertext_retained = [pair for pair in workload['joint']
        if ciphertext_valid[0][pair[0]] and
           ciphertext_valid[1][pair[1]]]
    cv_retained = [pair for pair in workload['joint']
        if cv_valid[0][pair[0]] and cv_valid[1][pair[1]]]
    need(ciphertext_retained == workload['joint'] and
         cv_retained == workload['joint'],
         'public-observable-all-candidates-retained')
    before = len(workload['joint'])
    return {
        'schema': 'kpb-public-observable-finite-candidate-filters/v1',
        'ciphertext_component_equalities': {
            'workload_candidates_before': before,
            'workload_candidates_after': len(ciphertext_retained),
            'pruned_candidates': before - len(ciphertext_retained),
            'round_pattern_sha256': ciphertext_pattern_identities,
        },
        'cv_candidate_residuals': {
            'workload_candidates_before': before,
            'workload_candidates_after': len(cv_retained),
            'pruned_candidates': before - len(cv_retained),
            'round_residual_partition_sha256': cv_residual_identities,
            'owner_openings_consumed': 0,
        },
        'all_candidates_retained': True,
        'observed_owner_label_fields_consumed': 0,
        'authorizes_coverage': False,
        'used_for_coverage': False,
        'requires_native_isolated_admission': True,
    }


def inspect_fd40_c1_contact_value_candidate_filter(
        parsed, round_models, terminal_artifacts):
    """Apply the exact qualified C1 contact/value join nonauthoritatively.

    The FD40 parser has already joined each v2 C1 leaf to its private outer
    stage/contact/process evidence.  This diagnostic rechecks that source and
    applies the measured incoming-contact creator edge to the finite lattice.
    It deliberately leaves every qualified C1 ledger row open: only the
    native selected-worker authority may later authorize the same effect.
    """
    need(type(parsed) is dict
         and parsed.get('schema') == 'kpb-fd40-typed-archive-parse/v1'
         and parsed.get('authorizes_coverage') is False
         and parsed.get('requires_consumed_sealed_fd40') is True,
         'c1-filter-archive')
    publics = parsed.get('public_rounds')
    leaves = parsed.get('typed_leaves')
    c1_rounds = parsed.get('c1_rounds')
    need(type(publics) is list and len(publics) == 2
         and type(leaves) is list and len(leaves) == 10
         and type(c1_rounds) is list and len(c1_rounds) == 2
         and type(round_models) is list and len(round_models) == 2,
         'c1-filter-two-round-shape')
    for model, public in zip(round_models, publics):
        need(codec.assignments(public, model['constraints']) == model,
             'c1-filter-recomputed-round-model')

    before_workload = workload_candidates(round_models, terminal_artifacts)
    filtered_models = []
    round_before = []
    round_after = []
    observed_edges = []
    for index, (public, model, c1) in enumerate(
            zip(publics, round_models, c1_rounds)):
        leaf = leaves[index * 5 + 4]['typed']
        fd40_archive._validate_c1_v2(leaf, public, c1)
        issued = next((row for row in leaf['records']
                       if row['stream'] == 'invoice'
                       and row['value'].get('direction') == 'issued'), None)
        incoming = next((row for row in leaf['records']
                         if row['stream'] == 'decrypted-receipt'
                         and row['value'].get('kind') ==
                             'incoming-payment'), None)
        need(issued is not None and incoming is not None,
             'c1-filter-required-values')
        for row in (issued, incoming):
            source = row['source']
            need(source['value_sha256'] == hashlib.sha256(
                    codec.encoded(row['value'])).hexdigest()
                 and source['source_event_binding_sha256'] ==
                    _c1_source_event_sha256(
                        row['stream'], row['value'], source),
                 'c1-filter-value-source-binding')
        contact = c1['contact_owner_components'][0]
        incoming_tuple = incoming['value']['tuple_sha256']
        need(contact == c1['contact_owner_components'][2]
             and issued['source']['contact_owner_component'] == contact
             and incoming['source']['contact_owner_component'] == contact
             and issued['value']['source_owner_component'] == contact
             and incoming['value']['creator_owner_component'] == contact
             and issued['value']['amount_sompi'] ==
                incoming['value']['amount_sompi']
             and incoming_tuple in public['tuple_sha256'],
             'c1-filter-contact-value-join')
        constraints = codec.parse(codec.encoded(model['constraints']))
        need(not any(edge['slot_id'] == incoming_tuple
                     for edge in constraints['creator_edges']),
             'c1-filter-edge-already-present')
        constraints['creator_edges'].append({
            'owner_component': contact,
            'slot_id': incoming_tuple,
            'provenance': 'colluder-knowledge',
        })
        filtered = codec.assignments(public, constraints)
        need(0 < filtered['joint_candidates'] < model['joint_candidates'],
             'c1-filter-must-prune-round')
        round_before.append(model['joint_candidates'])
        round_after.append(filtered['joint_candidates'])
        observed_edges.append({
            'round': index + 1,
            'owner_component': contact,
            'tuple_sha256': incoming_tuple,
        })
        filtered_models.append(filtered)

    after_workload = workload_candidates(filtered_models, terminal_artifacts)
    before = before_workload['workload_joint_candidates']
    after = after_workload['workload_joint_candidates']
    need(0 < after < before, 'c1-filter-must-prune-workload')
    return {
        'schema': 'kpb-c1-qualified-finite-candidate-filter/v1',
        'round_candidates_before': round_before,
        'round_candidates_after': round_after,
        'workload_candidates_before': before,
        'workload_candidates_after': after,
        'pruned_candidates': before - after,
        'observed_creator_edges': observed_edges,
        'authorizes_coverage': False,
        'used_for_coverage': False,
        'requires_native_c1_postcapture_admission': True,
    }


_SELECTED_STRUCTURAL_MODELS_CONSTRUCTOR = object()


class _SelectedFd40StructuralModels:
    """Private one-shot result; no receipt/count/boolean export exists."""
    __slots__ = ('_public_rounds', '_projection_artifacts', '_typed_leaves',
                 '_live')

    def __init__(self, constructor, public_rounds, projection_artifacts,
                 typed_leaves):
        need(constructor is _SELECTED_STRUCTURAL_MODELS_CONSTRUCTOR
             and type(public_rounds) is list and len(public_rounds) == 2
             and type(projection_artifacts) is list
             and len(projection_artifacts) == 2
             and type(typed_leaves) is list and len(typed_leaves) == 10,
             'selected-structural-models-constructor')
        self._public_rounds = public_rounds
        self._projection_artifacts = projection_artifacts
        self._typed_leaves = typed_leaves
        self._live = True


def _selected_structural_models(parsed):
    need(type(parsed) is dict
         and parsed.get('schema') == 'kpb-fd40-typed-archive-parse/v1'
         and parsed.get('authorizes_coverage') is False
         and parsed.get('requires_consumed_sealed_fd40') is True,
         'selected-fd40-archive-parse')
    need(False, 'selected-fd40-native-structural-authority-required')


def consume_selected_fd40_structural_models(selected):
    """Burn FD40 input, then refuse until native authority enters the child.

    The parsed archive remains useful nonauthorizing evidence.  This Python
    object/registry path cannot close coverage because its runtime type and
    constructor token are forgeable by code in the same interpreter.
    """
    return _selected_structural_models(fd40_archive._consume_selected(selected))


_PRIVATE_PREDICTION_COVERAGE_CONSTRUCTOR = object()


class _PrivatePredictionCoverageAuthority:
    __slots__ = ('_models', '_live')

    def __init__(self, constructor, models):
        need(constructor is _PRIVATE_PREDICTION_COVERAGE_CONSTRUCTOR
             and type(models) is _SelectedFd40StructuralModels
             and models._live,
             'private-prediction-coverage-constructor')
        self._models = models
        self._live = True


def consume_selected_fd40_private_completion_for_prediction(
        selected, coverage):
    """Selected-child-only final gate, currently deliberately unreachable.

    FD40 is burned first.  The current archive parser can authoritatively
    close only the two structural projection rows. Terminal-v2, dispatcher,
    C03, C1 and empirical candidate effects are still separate nonauthorizing
    typed parses, so a complete ten-artifact prediction authority cannot yet
    be minted.  This explicit refusal prevents an old public count/boolean or
    a partial typed archive from becoming a privacy pass.
    """
    models = consume_selected_fd40_structural_models(selected)
    need(type(coverage) is _PrivateCompletionCoverageAuthority,
         'private-completion-authority-type')
    need(coverage._live, 'private-completion-authority-replay')
    coverage._live = False
    models._live = False
    need(False, 'selected-fd40-ten-typed-model-adapters-incomplete')
    return _PrivatePredictionCoverageAuthority(  # pragma: no cover
        _PRIVATE_PREDICTION_COVERAGE_CONSTRUCTOR, models)


def _public_projection_blocker_matrix(artifact):
    need(type(artifact) is dict
         and artifact.get('kind') == 'public-projection',
         'public-projection-blocker-artifact')
    _validate_leakage_ledger('public-projection',
                             artifact.get('leakage_ledger'))
    rows = []
    for ledger in artifact['leakage_ledger']:
        if ledger['status'] != 'unmodeled':
            continue
        proposal = _unmodeled_resolution(
            'public-projection', ledger['category'], ledger['field_path'])
        rows.append({
            'category': ledger['category'],
            'field_path': ledger['field_path'],
            'missing_authority_or_assumption':
                proposal['evidence_requirement'],
            'proposed_resolution': proposal['proposed_resolution'],
        })
    return {
        'schema': 'kpb-private-public-projection-blocker-matrix/v1',
        'rows': rows,
        'row_count': len(rows),
        'authorizes_coverage': False,
    }


def _event_time_order(events):
    need(type(events) is list and events, 'nonempty-events')
    prior = -1
    for sequence, event in enumerate(events):
        natural(event['sequence'], 'event-sequence')
        natural(event['monotonic_ns'], 'event-time')
        need(event['sequence'] == sequence and event['monotonic_ns'] >= prior,
             'ordered-events')
        prior = event['monotonic_ns']


EXPLICIT_OWNER_EFFECTS_LABEL = \
    b'KPB_EXPLICIT_OWNER_PUBLIC_EFFECTS_CAPTURE_V1\n'
EXPLICIT_OWNER_EFFECTS_BYTES = 693
RELEASE_POLICY_LABEL = b'KPB_DISPATCHER_RELEASE_POLICY_BINDING_V1\n'
RELEASE_POLICY_BYTES = 265
_DISPATCHER_POLICY_AUTHORITY_CONSTRUCTOR = object()
EXPLICIT_OWNER_EFFECTS_LINEAGE_FIELDS = (
    'run_sha256', 'trial_sha256', 'attempt_sha256', 'cohort_sha256',
    'capture_plan_sha256', 'projection_sha256', 'context_sha256',
)


class _DispatcherPolicySourceAuthority:
    """One-shot private proof that the dispatcher leaf came from its role.

    The isolated observer bridge may mint this only after consuming the
    producer spool/role-launch authority. JSON fields, event hashes, and a
    public producer receipt are not substitutes.
    """
    __slots__ = ('_binding', '_live')

    def __init__(self, constructor, binding):
        need(constructor is _DISPATCHER_POLICY_AUTHORITY_CONSTRUCTOR,
             'dispatcher-policy-authority-constructor')
        exact(binding, (
            'artifact_sha256', 'round', 'projection_sha256',
            'cohort_sha256', 'run_sha256',
            'construction_attempt_sha256', 'capture_plan_sha256',
            'construction_classification', 'release_order_policy',
            'source_identity', 'build_identity', 'runtime_identity',
            'launcher_identity', 'process_identity', 'child_exit_identity',
            'producer_closure_authority_identity'),
            'dispatcher-policy-authority-fields')
        for name in (
                'artifact_sha256', 'projection_sha256', 'cohort_sha256',
                'run_sha256', 'construction_attempt_sha256',
                'capture_plan_sha256', 'source_identity', 'build_identity',
                'runtime_identity', 'launcher_identity', 'process_identity',
                'child_exit_identity',
                'producer_closure_authority_identity'):
            word(binding[name], 'dispatcher-policy-authority-' + name)
        need(binding['round'] in (1, 2)
             and binding['construction_classification'] in (1, 2)
             and binding['release_order_policy'] in (
                 'SECRET_PERMUTATION_INDEPENDENT',
                 'EXPLICIT_OWNER_PUBLIC_EFFECTS'),
             'dispatcher-policy-authority-enum')
        self._binding = dict(binding)
        self._live = True


def _test_only_mint_dispatcher_policy_source_authority(binding):
    """Synthetic control seam; never a production capsule authority."""
    return _DispatcherPolicySourceAuthority(
        _DISPATCHER_POLICY_AUTHORITY_CONSTRUCTOR, binding)


def _explicit_owner_effects_preimage(round_number, exports):
    need(round_number in (1, 2) and type(exports) is list
         and len(exports) == 3, 'dispatcher-explicit-preimage-context')
    result = bytearray(EXPLICIT_OWNER_EFFECTS_LABEL)
    result.extend(struct.pack('<Q', 2))
    result.extend(struct.pack('<Q', round_number))
    for name in EXPLICIT_OWNER_EFFECTS_LINEAGE_FIELDS:
        result.extend(bytes.fromhex(exports[0][name]))
    for owner, export in enumerate(exports):
        result.extend(struct.pack('<Q', owner))
        result.extend(bytes.fromhex(export['owner_contract_sha256']))
        result.extend(bytes.fromhex(export['nf_hex32']))
        for digest in export['tuple_sha256']:
            result.extend(bytes.fromhex(digest))
    need(len(result) == EXPLICIT_OWNER_EFFECTS_BYTES,
         'dispatcher-explicit-preimage-size')
    return bytes(result)


def _release_policy_preimage(round_number, classification, policy,
                             export_count, run_sha256,
                             construction_attempt_sha256,
                             cohort_sha256, capture_plan_sha256,
                             projection_sha256, explicit_event_sha256):
    need(round_number in (1, 2)
         and type(classification) is int and classification in (1, 2)
         and policy in ('SECRET_PERMUTATION_INDEPENDENT',
                        'EXPLICIT_OWNER_PUBLIC_EFFECTS')
         and type(export_count) is int
         and export_count == (0 if classification == 1 else 3),
         'dispatcher-release-policy-preimage-context')
    policy_code = 1 if policy == 'SECRET_PERMUTATION_INDEPENDENT' else 2
    need(policy_code == classification,
         'dispatcher-release-policy-classification')
    words = (run_sha256, construction_attempt_sha256, cohort_sha256,
             capture_plan_sha256, projection_sha256,
             explicit_event_sha256)
    for name in words:
        word(name, 'dispatcher-release-policy-word')
    result = bytearray(RELEASE_POLICY_LABEL)
    for value in (classification, policy_code, round_number, export_count):
        result.extend(struct.pack('<Q', value))
    for name in words:
        result.extend(bytes.fromhex(name))
    need(len(result) == RELEASE_POLICY_BYTES,
         'dispatcher-release-policy-preimage-width')
    return bytes(result)


def dispatcher(raw, public, source_authority=None):
    """Admit the complete fixed financial-dispatcher metadata for one round."""
    codec.batch(public)
    value = canonical(raw)
    exact(value, ('schema', 'round', 'projection_sha256', 'cohort_sha256',
                  'run_sha256', 'construction_attempt_sha256',
                  'capture_plan_sha256', 'construction_classification',
                  'release_order_policy', 'direct_exports', 'events',
                  'retry_history', 'closure'), 'dispatcher-fields')
    need(value['schema'] == 'kpb-dispatcher-observer-capture/v1'
         and value['round'] == public['round']
         and value['projection_sha256'] == public['projection_sha256'],
         'dispatcher-binding')
    for name in ('cohort_sha256', 'run_sha256',
                 'construction_attempt_sha256', 'capture_plan_sha256'):
        word(value[name], 'dispatcher-' + name)
    need(type(value['construction_classification']) is int
         and value['construction_classification'] in (1, 2),
         'dispatcher-construction-classification')
    allowed = {'listeners-ready', 'owner-connected', 'owner-upload-complete',
               'aggregate-release', 'explicit-owner-public-effects',
               'release-policy-bound', 'outbound-route'}
    events = value['events']
    for event in events:
        exact(event, ('sequence', 'kind', 'owner_component', 'role',
                      'monotonic_ns', 'bytes', 'filename', 'public_sha256',
                      'route_sha256', 'outcome'), 'dispatcher-event-fields')
        need(event['kind'] in allowed and event['outcome'] in
             ('ok', 'refused', 'disconnected'), 'dispatcher-event-kind')
        natural(event['bytes'], 'dispatcher-event-bytes')
        if event['owner_component'] is not None:
            codec.owner(event['owner_component'])
        need(event['filename'] is None or
             (type(event['filename']) is str
              and re.fullmatch('[A-Za-z0-9_.-]{1,96}', event['filename'])),
             'dispatcher-filename')
        for name in ('public_sha256', 'route_sha256'):
            need(event[name] is None or word(event[name]),
                 'dispatcher-optional-hash')
        if event['kind'] in ('owner-connected', 'owner-upload-complete'):
            owner = event['owner_component']
            need(type(owner) is int and event['role'] == 'C' + str(owner),
                 'dispatcher-owner-role')
        else:
            need(event['owner_component'] is None and
                 event['role'] in ('controller', 'server-roster'),
                 'dispatcher-public-role')
        if event['kind'] == 'owner-upload-complete':
            need(event['outcome'] == 'ok' and event['bytes'] > 0
                 and event['filename'] == 'OWNER-PRIVATE-INPUT-V2.bin'
                 and event['public_sha256'] is None
                 and event['route_sha256'] is None,
                 'dispatcher-private-upload-metadata-only')
        elif event['kind'] == 'owner-connected':
            need(event['outcome'] == 'ok' and event['bytes'] == 0
                 and event['filename'] is None
                 and event['public_sha256'] is None
                 and event['route_sha256'] is None,
                 'dispatcher-owner-connection-shape')
        if event['kind'] == 'aggregate-release':
            need(event['outcome'] == 'ok' and event['bytes'] == 10685
                 and event['filename'] == 'released-projection.bin'
                 and event['public_sha256'] == public['projection_sha256']
                 and event['route_sha256'] is None,
                 'dispatcher-exact-aggregate-release')
        elif event['kind'] == 'outbound-route':
            need(event['outcome'] == 'ok' and event['bytes'] == 10685
                 and event['filename'] == 'released-projection.bin'
                 and event['public_sha256'] == public['projection_sha256']
                 and word(event['route_sha256']),
                 'dispatcher-exact-outbound-route')
        elif event['kind'] == 'explicit-owner-public-effects':
            need(event['outcome'] == 'ok'
                 and event['bytes'] == EXPLICIT_OWNER_EFFECTS_BYTES
                 and event['filename'] ==
                    'EXPLICIT-OWNER-PUBLIC-EFFECTS-V1.bin'
                 and word(event['public_sha256'])
                 and event['route_sha256'] is None,
                 'dispatcher-explicit-owner-effects-event')
        elif event['kind'] == 'release-policy-bound':
            need(event['outcome'] == 'ok'
                 and event['bytes'] == RELEASE_POLICY_BYTES
                 and event['filename'] == 'RELEASE-ORDER-POLICY-V1.bin'
                 and word(event['public_sha256'])
                 and event['route_sha256'] is None,
                 'dispatcher-release-policy-event')
        elif event['kind'] == 'listeners-ready':
            need(event['outcome'] == 'ok' and event['bytes'] == 0
                 and event['filename'] is None
                 and event['public_sha256'] is None
                 and event['route_sha256'] is None,
                 'dispatcher-listener-shape')
    _event_time_order(events)
    kinds = [event['kind'] for event in events]
    need(kinds.count('listeners-ready') == 1
         and kinds.count('aggregate-release') == 1
         and kinds.count('explicit-owner-public-effects') <= 1
         and kinds.count('release-policy-bound') == 1
         and kinds.count('outbound-route') >= 1,
         'dispatcher-complete-public-events')
    for kind in ('owner-connected', 'owner-upload-complete'):
        need(sorted(event['owner_component'] for event in events
                    if event['kind'] == kind) == [0, 1, 2],
             'dispatcher-all-owner-events')
    need(kinds[0] == 'listeners-ready'
         and kinds.index('aggregate-release')
             > max(index for index, kind in enumerate(kinds)
                   if kind == 'owner-upload-complete')
         and all(kinds.index('owner-connected') < index
                 for index, kind in enumerate(kinds)
                 if kind == 'owner-upload-complete')
         and min(index for index, kind in enumerate(kinds)
                 if kind == 'outbound-route')
             > kinds.index('aggregate-release'),
         'dispatcher-protocol-order')
    for owner in codec.OWNERS:
        connected = next(index for index, event in enumerate(events)
                         if event['kind'] == 'owner-connected'
                         and event['owner_component'] == owner)
        uploaded = next(index for index, event in enumerate(events)
                        if event['kind'] == 'owner-upload-complete'
                        and event['owner_component'] == owner)
        need(connected < uploaded, 'dispatcher-owner-protocol-order')
    retries = value['retry_history']
    need(type(retries) is list, 'dispatcher-retry-array')
    attempts = set()
    for retry in retries:
        exact(retry, ('attempt_id', 'owner_component', 'start_monotonic_ns',
                      'complete_monotonic_ns', 'outcome'),
              'dispatcher-retry-fields')
        need(type(retry['attempt_id']) is str
             and re.fullmatch('[A-Za-z0-9_-]{1,128}', retry['attempt_id'])
             and retry['attempt_id'] not in attempts,
             'dispatcher-retry-id')
        attempts.add(retry['attempt_id'])
        if retry['owner_component'] is not None:
            codec.owner(retry['owner_component'])
        start = natural(retry['start_monotonic_ns'], 'dispatcher-retry-start')
        complete = natural(retry['complete_monotonic_ns'],
                           'dispatcher-retry-complete')
        need(complete >= start and retry['outcome'] in
             ('refused', 'disconnected', 'completed'),
             'dispatcher-retry-outcome')
    # Retry/intersection inference is intentionally not guessed. A nonempty
    # history cannot be admitted until its other attempt/cohort projection is
    # part of the frozen workload model.
    need(retries == [], 'dispatcher-retry-intersection-unmodeled')

    policy = value['release_order_policy']
    exports = value['direct_exports']
    need(policy in ('SECRET_PERMUTATION_INDEPENDENT',
                    'EXPLICIT_OWNER_PUBLIC_EFFECTS')
         and type(exports) is list,
         'dispatcher-release-order-policy')
    source_bound = source_authority is not None
    if source_bound:
        need(type(source_authority) is _DispatcherPolicySourceAuthority
             and source_authority._live,
             'dispatcher-policy-source-authority-type')
        source_authority._live = False
        expected_authority = {
            'artifact_sha256': hashlib.sha256(raw).hexdigest(),
            'round': public['round'],
            'projection_sha256': value['projection_sha256'],
            'cohort_sha256': value['cohort_sha256'],
            'run_sha256': value['run_sha256'],
            'construction_attempt_sha256':
                value['construction_attempt_sha256'],
            'capture_plan_sha256': value['capture_plan_sha256'],
            'construction_classification':
                value['construction_classification'],
            'release_order_policy': policy,
        }
        need(all(source_authority._binding[name] == expected
                 for name, expected in expected_authority.items()),
             'dispatcher-policy-source-authority-binding')
    constraints = codec.empty_constraints()
    if policy == 'SECRET_PERMUTATION_INDEPENDENT':
        need(value['construction_classification'] == 1
             and exports == []
             and 'explicit-owner-public-effects' not in kinds,
             'dispatcher-secret-order-no-direct-export')
    else:
        need(value['construction_classification'] == 2
             and len(exports) == 3
             and kinds.count('explicit-owner-public-effects') == 1,
             'dispatcher-three-explicit-exports')
        owners = set(); contracts = set(); exported_nfs = set()
        exported_tuples = set(); common_lineage = None
        export_fields = (
            'owner_component', 'owner_contract_sha256', 'nf_hex32',
            'tuple_sha256', *EXPLICIT_OWNER_EFFECTS_LINEAGE_FIELDS,
        )
        for expected_owner, export in enumerate(exports):
            exact(export, export_fields,
                  'dispatcher-direct-export-fields')
            owner = codec.owner(export['owner_component'])
            tuples = export['tuple_sha256']
            lineage = tuple(export[name]
                            for name in EXPLICIT_OWNER_EFFECTS_LINEAGE_FIELDS)
            for name, digest in zip(EXPLICIT_OWNER_EFFECTS_LINEAGE_FIELDS,
                                    lineage):
                word(digest, 'dispatcher-explicit-' + name)
            need(owner == expected_owner and owner not in owners
                 and word(export['owner_contract_sha256'])
                 and export['owner_contract_sha256'] not in contracts
                 and export['nf_hex32'] in public['nfs_hex32']
                 and export['nf_hex32'] not in exported_nfs
                 and type(tuples) is list
                 and len(tuples) == len(set(tuples)) == 2
                 and tuples == sorted(tuples)
                 and all(digest in public['tuple_sha256']
                         and digest not in exported_tuples
                         for digest in tuples)
                 and export['run_sha256'] == value['run_sha256']
                 and export['attempt_sha256'] ==
                    value['construction_attempt_sha256']
                 and export['cohort_sha256'] == value['cohort_sha256']
                 and export['capture_plan_sha256'] ==
                    value['capture_plan_sha256']
                 and export['projection_sha256'] ==
                    public['projection_sha256']
                 and (common_lineage is None or lineage == common_lineage),
                 'dispatcher-direct-export-binding')
            owners.add(owner); contracts.add(export['owner_contract_sha256'])
            exported_nfs.add(export['nf_hex32'])
            exported_tuples.update(tuples)
            if common_lineage is None:
                common_lineage = lineage
            if source_bound:
                constraints['input_edges'].append({
                    'owner_component': owner, 'slot_id': export['nf_hex32'],
                    'provenance': 'direct-export'})
                constraints['creator_edges'].extend({
                    'owner_component': owner, 'slot_id': digest,
                    'provenance': 'direct-export'} for digest in tuples)
                constraints['nf_pair_edges'].append({
                    'nf_hex32': export['nf_hex32'], 'tuple_sha256': tuples,
                    'provenance': 'direct-export'})
        need(owners == set(codec.OWNERS)
             and exported_nfs == set(public['nfs_hex32'])
             and exported_tuples == set(public['tuple_sha256']),
             'dispatcher-all-explicit-owners')
        explicit_event = next(event for event in events
                              if event['kind'] ==
                              'explicit-owner-public-effects')
        preimage = _explicit_owner_effects_preimage(public['round'], exports)
        need(explicit_event['public_sha256'] ==
                hashlib.sha256(preimage).hexdigest()
             and kinds.index('explicit-owner-public-effects') ==
                kinds.index('aggregate-release') + 1,
             'dispatcher-explicit-owner-effects-binding')
    aggregate_index = kinds.index('aggregate-release')
    policy_index = kinds.index('release-policy-bound')
    first_outbound = min(index for index, kind in enumerate(kinds)
                         if kind == 'outbound-route')
    explicit_sha256 = '00' * 32
    if policy == 'SECRET_PERMUTATION_INDEPENDENT':
        need(policy_index == aggregate_index + 1,
             'dispatcher-secret-policy-order')
    else:
        explicit_index = kinds.index('explicit-owner-public-effects')
        explicit_sha256 = events[explicit_index]['public_sha256']
        need(policy_index == explicit_index + 1,
             'dispatcher-explicit-policy-order')
    policy_event = events[policy_index]
    policy_preimage = _release_policy_preimage(
        public['round'], value['construction_classification'], policy,
        len(exports), value['run_sha256'],
        value['construction_attempt_sha256'], value['cohort_sha256'],
        value['capture_plan_sha256'], value['projection_sha256'],
        explicit_sha256)
    need(policy_event['public_sha256'] ==
            hashlib.sha256(policy_preimage).hexdigest()
         and policy_index < first_outbound,
         'dispatcher-release-policy-binding')
    codec.constraints(constraints, public)
    closure_records = ([{'stream': 'event', 'value': event}
                        for event in events]
                       + [{'stream': 'retry', 'value': retry}
                          for retry in retries])
    attempt_id = capture_closure(
        value['closure'], closure_records,
        sum(event['bytes'] for event in events), value['cohort_sha256'],
        public['round'], 'dispatcher-capture')
    inventory = {
        'schema': 'kpb-dispatcher-metadata-inventory/v1',
        'event_count': len(events),
        'retry_count': len(retries),
        'owner_connection_count': kinds.count('owner-connected'),
        'owner_upload_count': kinds.count('owner-upload-complete'),
        'aggregate_release_count': kinds.count('aggregate-release'),
        'outbound_route_count': kinds.count('outbound-route'),
        'attempt_id': attempt_id,
        'cohort_sha256': value['cohort_sha256'],
        'construction_classification': value['construction_classification'],
        'release_order_policy': policy,
        'release_policy_binding_count': 1 if source_bound else 0,
        'source_bound_policy_authority': source_bound,
        'private_body_or_hash_captured': False,
        'direct_constraint_count': sum(len(constraints[name]) for name in
                                       ('input_edges', 'creator_edges',
                                        'pair_edges', 'nf_pair_edges')),
    }
    unmodeled_fields = {
        ('cohort-membership', 'cohort_sha256'),
        ('connection-order', 'events[owner-connected].sequence'),
        ('lengths', 'events[].bytes'),
        ('operation-timing', 'events[].monotonic_ns'),
        ('outbound-routes', 'events[outbound-route].route_sha256'),
        ('upload-order', 'events[owner-upload-complete].sequence'),
    }
    constraint_counts = {
        ('filenames', 'events[].filename'): sum(
            event['filename'] is not None for event in events),
        ('public-receipts', 'events[].public_sha256'): sum(
            event['public_sha256'] is not None for event in events),
        ('retry-history', 'retry_history[]'): 1,
        ('role-identities', 'events[].owner_component_and_role'):
            len(events),
    }
    mapping_field = (
        'public-receipts', 'release_order_policy_and_direct_exports')
    if source_bound:
        constraint_counts[mapping_field] = 1 + len(exports)
    else:
        unmodeled_fields.add(mapping_field)
    return artifact_result(raw, 'dispatcher-capture', public['round'],
                           constraints,
                           DISPATCHER_CATEGORIES, inventory,
                           unmodeled_fields=unmodeled_fields,
                           constraint_counts=constraint_counts)


C03_MAGIC = b'KPBP1C03'
C03_HEADER_BYTES = 112
C03_CHUNK_BYTES = 1 << 16
C03_SEMANTICS = {
    1: 'owner-input-offset',
    2: 'mascot-message',
    3: 'authenticated-share',
    4: 'mac-share',
    5: 'randomness-share',
    6: 'randomness-mac',
    7: 'final-proof-g1',
    8: 'final-proof-g2',
    9: 'public-projection',
    10: 'field-opening',
    11: 'owner-input-preprocessing-share',
    12: 'masked-g1-intermediate',
    13: 'masked-field-intermediate',
    14: 'mac-key-share',
    15: 'authenticated-g1-state',
    16: 'authenticated-g2-state',
    17: 'scalar-capture-binding',
}
C03_SELECTED_RANDOMNESS_SITES = frozenset((1, 7, 20, 21))
C03_SELECTED_SCALAR_SITES = frozenset(range(1, 23))
C03_SELECTED_SCALAR_SITE_BITMAP = (1 << 22) - 1
C03_SCALAR_CAPTURE_MANIFEST_SHA256 = (
    '5e6903569bc71cbfb5549b369b79a19ecda6686dc4ab25fca0d161c6e1527b6b'
)
C03_AUTHORITY_FIELDS = (
    'round', 'attempt_id', 'cohort_sha256', 'financial_run_id',
    'capture_identity', 'server_component', 'fixed_fd', 'source_sha256',
    'build_sha256', 'launch_sha256', 'model_preimage_sha256',
    'query_store_preimage_sha256', 'scalar_capture_manifest_sha256',
    'closure',
)
C03_CLOSURE_FIELDS = (
    'schema', 'attempt_id', 'cohort_sha256', 'producer_record_count',
    'capture_record_count', 'producer_payload_bytes',
    'capture_payload_bytes', 'producer_stream_counts',
    'capture_stream_counts', 'record_chain_sha256',
    'unknown_record_count', 'capture_root_closed', 'producer_fd_closed',
    'raw_wire_bytes', 'raw_wire_sha256', 'end_frame_identity',
    'eof_identity',
)
C03_ROLE_FIELDS = (
    'round', 'kind', 'role', 'source_sha256', 'build_sha256',
    'launch_sha256', 'fixed_fd',
)
C03_P1_ROLE_FIELDS = C03_ROLE_FIELDS + (
    'model_preimage_sha256', 'query_store_preimage_sha256',
    'scalar_capture_manifest_sha256',
)
C03_ROLE_KINDS = (
    'public-projection', 'terminal-history', 'dispatcher-capture',
    'corrupt-server-capture', 'colluder-wallet-capture',
)
C03_ROLE_BY_KIND = {
    'public-projection': 'financial-release',
    'terminal-history': 'terminal-controller',
    'dispatcher-capture': 'private-dispatcher',
    'corrupt-server-capture': 'server-P1',
    'colluder-wallet-capture': 'owner-C1',
}


def c03_role_launch_closure(value, digest):
    """Validate the selected preimage for the aggregate role-launch hash."""
    word(digest, 'c03-role-launch-digest')
    expected = [(round_number, kind)
                for round_number in (1, 2) for kind in C03_ROLE_KINDS]
    need(type(value) is list and len(value) == len(expected),
         'c03-role-launch-count')
    for index, (row, (round_number, kind)) in enumerate(
            zip(value, expected)):
        exact(row, C03_P1_ROLE_FIELDS if kind == 'corrupt-server-capture'
              else C03_ROLE_FIELDS, 'c03-role-launch-fields')
        need(row['round'] == round_number and row['kind'] == kind
             and row['role'] == C03_ROLE_BY_KIND[kind]
             and type(row['fixed_fd']) is int
             and row['fixed_fd'] == 20 + index,
             'c03-role-launch-order')
        for name in ('source_sha256', 'build_sha256', 'launch_sha256'):
            word(row[name], 'c03-role-launch-' + name)
        if kind == 'corrupt-server-capture':
            for name in ('model_preimage_sha256',
                         'query_store_preimage_sha256',
                         'scalar_capture_manifest_sha256'):
                word(row[name], 'c03-role-launch-' + name)
    need(hashlib.sha256(codec.encoded(value)).hexdigest() == digest,
         'c03-role-launch-preimage')
    return value


def _c03_role_authority(authority, role_launch_closure,
                        role_launch_sha256):
    roles = c03_role_launch_closure(
        role_launch_closure, role_launch_sha256)
    selected = [row for row in roles
                if row['round'] == authority['round']
                and row['kind'] == 'corrupt-server-capture']
    need(len(selected) == 1
         and selected[0]['role'] == 'server-P1'
         and selected[0]['fixed_fd'] == authority['fixed_fd']
         and all(selected[0][name] == authority[name]
                 for name in ('source_sha256', 'build_sha256',
                              'launch_sha256', 'model_preimage_sha256',
                              'query_store_preimage_sha256',
                              'scalar_capture_manifest_sha256')),
         'c03-authority-role-launch-join')
    return selected[0]


def _c03_authority(value, public):
    exact(value, C03_AUTHORITY_FIELDS, 'c03-authority-fields')
    need(type(value['round']) is int and value['round'] == public['round']
         and type(value['attempt_id']) is str
         and str(uuid.UUID(value['attempt_id'])) == value['attempt_id']
         and type(value['capture_identity']) is str
         and str(uuid.UUID(value['capture_identity'])) ==
            value['capture_identity']
         and type(value['server_component']) is int
         and value['server_component'] == 1
         and type(value['fixed_fd']) is int
         and 0 <= value['fixed_fd'] <= 255,
         'c03-authority-context')
    for name in ('cohort_sha256', 'financial_run_id', 'source_sha256',
                 'build_sha256', 'launch_sha256',
                 'model_preimage_sha256', 'query_store_preimage_sha256',
                 'scalar_capture_manifest_sha256'):
        word(value[name], 'c03-authority-' + name)
    need(value['scalar_capture_manifest_sha256'] ==
         C03_SCALAR_CAPTURE_MANIFEST_SHA256,
         'c03-authority-scalar-manifest')
    exact(value['closure'], C03_CLOSURE_FIELDS,
          'c03-authority-closure-fields')
    need(value['closure']['schema'] == 'kpb-capture-source-closure/v2'
         and type(value['closure']['raw_wire_bytes']) is int
         and value['closure']['raw_wire_bytes'] > 0,
         'c03-authority-wire-closure')
    for name in ('record_chain_sha256', 'raw_wire_sha256',
                 'end_frame_identity', 'eof_identity'):
        word(value['closure'][name], 'c03-authority-closure-' + name)
    return value


def _c03_abstract_record(sequence, semantic, peer, payload):
    name = C03_SEMANTICS[semantic]
    if semantic == 1:
        channel, phase, owner, encoding = (
            'owner-tls', 'intake', peer, 'fr32le')
    elif semantic == 11:
        channel, phase, owner, encoding = (
            'owner-tls', 'preprocessing', peer, 'fr32le')
    elif semantic == 17:
        channel, phase, owner, encoding = (
            'local', 'trace', None, 'scalar-binding-v1')
    else:
        owner = None
        channel, phase, encoding = {
            2: ('peer', 'preprocessing', 'bytes'),
            3: ('local', 'trace', 'fr32le'),
            4: ('local', 'validation', 'fr32le'),
            5: ('local', 'trace', 'fr32le'),
            6: ('local', 'trace', 'fr32le'),
            7: ('local', 'proof', 'g1-65'),
            8: ('local', 'proof', 'g2-129'),
            9: ('local', 'release', 'bytes'),
            10: ('local', 'proof', 'fr32le'),
            12: ('local', 'proof', 'g1-65'),
            13: ('local', 'proof', 'fr32le'),
            14: ('local', 'setup', 'fr32le'),
            15: ('local', 'proof', 'g1-share-mac'),
            16: ('local', 'proof', 'g2-share-mac'),
        }[semantic]
    return {
        'sequence': sequence,
        'channel': channel,
        'phase': phase,
        'owner_component': owner,
        'semantic': name,
        'encoding': encoding,
        'payload_hex': payload.hex(),
    }


def _parse_c03(raw, public, projection, authority, role_launch_closure,
               role_launch_sha256):
    """Independently verify one source-bound C03 P1 capture."""
    codec.batch(public); authority = _c03_authority(authority, public)
    _c03_role_authority(authority, role_launch_closure,
                        role_launch_sha256)
    need(isinstance(raw, (bytes, bytearray, memoryview))
         and bytes(raw[:len(C03_MAGIC)]) == C03_MAGIC,
         'c03-wire-prefix')
    raw = memoryview(raw)
    need(type(projection) is bytes
         and hashlib.sha256(projection).hexdigest() ==
            public['projection_sha256'],
         'c03-projection-binding')

    at = 0
    sequence = 0; next_message = 0; last_time = 0; first_time = 0
    current = None; records = []; stream_counts = {}
    forks = {bytes(32)}; sealed = False; complete = False; ended = False
    projection_payload = None; projection_messages = 0
    lane = [[0, 0, 0] for _ in range(17)]; total = [0, 0, 0]
    offset_owners = 0; preprocessing_owners = 0
    offset_bytes = [0, 0, 0]; preprocessing_bytes = [0, 0, 0]
    mac_key_seen = False; proof_opening_stage = 0
    authenticated_g1_states = []; authenticated_g2_states = []
    authenticated_group_stage = 0
    scalar_pending = None; scalar_site_bitmap = 0
    end_frame_identity = None

    def take(size, category):
        nonlocal at
        need(type(size) is int and size >= 0 and at + size <= len(raw),
             category)
        result = bytes(raw[at:at + size]); at += size
        return result

    while not ended:
        header = take(C03_HEADER_BYTES, 'c03-truncated-header')
        need(header[:8] == C03_MAGIC and header[13:16] == bytes(3),
             'c03-frame-header')
        record_type, semantic, direction, peer, flags = header[8:13]
        monotonic_ns = struct.unpack('>Q', header[16:24])[0]
        selected_sequence = struct.unpack('>Q', header[24:32])[0]
        message = struct.unpack('>Q', header[32:40])[0]
        chunk = struct.unpack('>I', header[40:44])[0]
        size = struct.unpack('>I', header[44:48])[0]
        fork = header[48:80]; expected_digest = header[80:112]
        payload = take(size, 'c03-truncated-payload')
        need(size <= C03_CHUNK_BYTES
             and selected_sequence == sequence
             and monotonic_ns > 0 and monotonic_ns >= last_time
             and record_type in (1, 2, 3, 4, 5, 6)
             and semantic in C03_SEMANTICS
             and flags & ~3 == 0
             and hashlib.sha256(payload).digest() == expected_digest,
             'c03-frame-envelope')
        previous_time = last_time
        if first_time == 0:
            first_time = monotonic_ns
        last_time = monotonic_ns

        first = bool(flags & 1); last = bool(flags & 2)
        if first:
            need(current is None and message == next_message and chunk == 0,
                 'c03-message-start')
            next_message += 1
            current = {
                'message': message, 'type': record_type,
                'semantic': semantic, 'direction': direction,
                'peer': peer, 'fork': fork, 'chunk': 0,
                'chunks': 0, 'bytes': 0, 'payload': bytearray(),
            }
        else:
            need(current is not None and message == current['message']
                 and chunk == current['chunk'] + 1,
                 'c03-message-continuation')
        need(current is not None and record_type == current['type']
             and semantic == current['semantic']
             and direction == current['direction']
             and peer == current['peer'] and fork == current['fork'],
             'c03-message-metadata')
        current['chunk'] = chunk; current['chunks'] += 1
        current['bytes'] += size; current['payload'].extend(payload)

        if record_type == 1:
            need(sequence == 0 and first and last and size == 332
                 and semantic == 1 and direction == 3 and peer == 0xff
                 and fork == bytes(32)
                 and payload[0:4] == bytes((
                     authority['round'], authority['server_component'], 0,
                     authority['fixed_fd']))
                 and payload[4:40] == authority['attempt_id'].encode()
                 and payload[40:72].hex() == authority['cohort_sha256']
                 and payload[72:104].hex() == authority['financial_run_id']
                 and payload[104:140] ==
                    authority['capture_identity'].encode()
                 and payload[140:172].hex() == authority['source_sha256']
                 and payload[172:204].hex() == authority['build_sha256']
                 and payload[204:236].hex() == authority['launch_sha256']
                 and payload[236:268].hex() ==
                    authority['model_preimage_sha256']
                 and payload[268:300].hex() ==
                    authority['query_store_preimage_sha256']
                 and payload[300:332].hex() ==
                    authority['scalar_capture_manifest_sha256'],
                 'c03-hello-authority-binding')
        elif record_type == 2:
            need(not sealed and not complete and fork in forks,
                 'c03-data-state')
            if semantic not in (2, 14):
                need(mac_key_seen, 'c03-mac-key-order')
            if semantic == 2:
                need(direction in (1, 2) and peer in (0, 2),
                     'c03-peer-transport-metadata')
            elif semantic == 1:
                need(direction == 2 and peer in (0, 1, 2)
                     and fork == bytes(32), 'c03-owner-offset-metadata')
            elif semantic == 11:
                need(direction == 1 and peer in (0, 1, 2)
                     and fork == bytes(32),
                     'c03-owner-preprocessing-metadata')
            else:
                need(direction == 3 and peer == 0xff
                     and fork == bytes(32), 'c03-local-metadata')
            if first:
                if scalar_pending is not None:
                    need(semantic == scalar_pending['expected'],
                         'c03-scalar-binding-order')
                elif semantic in (3, 4, 5, 6):
                    need(False, 'c03-scalar-binding-order')
        else:
            need(first and last and current['chunks'] == 1
                 and direction == 3 and peer == 0xff,
                 'c03-control-frame-shape')
            if record_type == 3:
                need(not sealed and not complete and semantic == 9
                     and fork == bytes(32) and size == 32
                     and projection_messages == 1
                     and projection_payload == projection
                     and payload == hashlib.sha256(projection).digest(),
                     'c03-projection-seal')
                sealed = True
            elif record_type == 4:
                need(sealed and not complete and semantic == 9
                     and fork == bytes(32) and size == 496,
                     'c03-completeness-state')
                version, count = struct.unpack('>II', payload[:8])
                reported_total = [
                    struct.unpack('>Q', payload[8 + 8 * index:
                                                16 + 8 * index])[0]
                    for index in range(3)]
                reported_lanes = []; cursor = 32
                for _ in range(17):
                    reported_lanes.append([
                        struct.unpack('>Q', payload[
                            cursor + 8 * index:cursor + 8 * (index + 1)])[0]
                        for index in range(3)])
                    cursor += 24
                instrumented, reported_offsets, reported_preprocessing, \
                    reported_scalar_sites, timed_frames, reported_first, \
                    reported_last = struct.unpack('>QQQQQQQ', payload[440:496])
                need(version == 9 and count == 17
                     and reported_total == total
                     and reported_lanes == lane
                     and instrumented == 0x1ffff
                     and reported_offsets == offset_owners == 7
                     and reported_preprocessing ==
                        preprocessing_owners == 7
                     and all(preprocessing_bytes[owner] ==
                             5 * offset_bytes[owner]
                             for owner in range(3))
                     and lane[6] == [1, 1, 2 * 65]
                     and lane[7] == [1, 1, 129]
                     and lane[11] == [1, 1, 2 * 65]
                     and lane[12] == [1, 1, 2 * 32]
                     and lane[13] == [1, 1, 32]
                     and lane[14] == [4, 4, 1824]
                     and lane[15] == [2, 2, 518]
                     and lane[16][0] == lane[2][0] + lane[4][0]
                     and lane[16][1] == lane[16][0]
                     and lane[16][2] == 16 * lane[16][0]
                     and lane[2][0] == lane[3][0]
                     and lane[2][2] == lane[3][2]
                     and lane[4][0] == lane[5][0]
                     and lane[4][2] == lane[5][2]
                     and scalar_pending is None
                     and reported_scalar_sites == scalar_site_bitmap ==
                        C03_SELECTED_SCALAR_SITE_BITMAP
                     and mac_key_seen
                     and authenticated_group_stage == 6
                     and proof_opening_stage == 4
                     and timed_frames == sequence
                     and reported_first == first_time
                     and reported_last == previous_time,
                     'c03-completeness-counters')
                complete = True
            elif record_type == 5:
                need(complete and semantic == 9 and fork == bytes(32)
                     and size == 0, 'c03-end-state')
                end_frame_identity = hashlib.sha256(
                    header + payload).hexdigest()
                ended = True
            elif record_type == 6:
                need(not sealed and not complete and semantic == 2
                     and fork in forks and size == 96
                     and payload[:32] == fork
                     and payload[32:64] != bytes(32)
                     and payload[32:64] not in forks,
                     'c03-fork-record')
                forks.add(payload[32:64])
            else:
                need(False, 'c03-control-type')

        if last:
            message_payload = bytes(current['payload'])
            if record_type == 2:
                if semantic in (1, 3, 4, 5, 6, 10, 11, 13, 14):
                    need(current['bytes'] > 0
                         and current['bytes'] % 32 == 0,
                         'c03-field-lane-shape')
                elif semantic in (7, 12):
                    need(current['bytes'] > 0
                         and current['bytes'] % 65 == 0,
                         'c03-g1-lane-shape')
                elif semantic == 8:
                    need(current['bytes'] > 0
                         and current['bytes'] % 129 == 0,
                         'c03-g2-lane-shape')
                elif semantic == 15:
                    need(current['chunks'] == 1 and current['bytes'] > 1
                         and (current['bytes'] - 1) % 130 == 0,
                         'c03-authenticated-g1-lane-shape')
                elif semantic == 16:
                    need(current['chunks'] == 1 and current['bytes'] > 1
                         and (current['bytes'] - 1) % 258 == 0,
                         'c03-authenticated-g2-lane-shape')
                elif semantic == 17:
                    need(current['chunks'] == 1 and current['bytes'] == 16,
                         'c03-scalar-binding-shape')
                index = semantic - 1
                lane[index][0] += 1
                lane[index][1] += current['chunks']
                lane[index][2] += current['bytes']
                total[0] += 1; total[1] += current['chunks']
                total[2] += current['bytes']
                if semantic == 14:
                    need(not mac_key_seen, 'c03-mac-key-order')
                    mac_key_seen = True
                elif semantic == 17:
                    version = message_payload[0]
                    kind = message_payload[1]
                    site = int.from_bytes(message_payload[2:4], 'big')
                    elements = int.from_bytes(message_payload[4:12], 'big')
                    need(version == 1 and kind in (1, 2)
                         and site in C03_SELECTED_SCALAR_SITES
                         and elements > 0
                         and message_payload[12:16] == bytes(4)
                         and ((site in C03_SELECTED_RANDOMNESS_SITES) ==
                              (kind == 2))
                         and scalar_pending is None,
                         'c03-scalar-binding-shape')
                    scalar_pending = {
                        'site': site, 'elements': elements,
                        'expected': 3 if kind == 1 else 5,
                        'mac': 4 if kind == 1 else 6,
                    }
                elif semantic in (3, 5):
                    need(scalar_pending is not None
                         and semantic == scalar_pending['expected']
                         and current['bytes'] ==
                            32 * scalar_pending['elements'],
                         'c03-scalar-binding-width')
                    scalar_pending['expected'] = scalar_pending['mac']
                elif semantic in (4, 6):
                    need(scalar_pending is not None
                         and semantic == scalar_pending['mac']
                         and current['bytes'] ==
                            32 * scalar_pending['elements'],
                         'c03-scalar-binding-width')
                    scalar_site_bitmap |= 1 << (scalar_pending['site'] - 1)
                    scalar_pending = None
                elif semantic == 1:
                    need(offset_owners & (1 << peer) == 0,
                         'c03-owner-offset-duplicate')
                    offset_owners |= 1 << peer
                    offset_bytes[peer] = current['bytes']
                elif semantic == 11:
                    need(preprocessing_owners & (1 << peer) == 0,
                         'c03-owner-preprocessing-duplicate')
                    preprocessing_owners |= 1 << peer
                    preprocessing_bytes[peer] = current['bytes']
                elif semantic == 13:
                    need(proof_opening_stage == 0
                         and authenticated_group_stage == 3,
                         'c03-proof-opening-order')
                    proof_opening_stage = 1
                elif semantic == 12:
                    need(proof_opening_stage == 1
                         and authenticated_group_stage == 3,
                         'c03-proof-opening-order')
                    proof_opening_stage = 2
                elif semantic in (15, 16):
                    stage = message_payload[0]
                    if semantic == 15:
                        need(len(authenticated_g1_states) < 4,
                             'c03-authenticated-group-order')
                        expected = ((1, 4, 0), (2, 6, 2),
                                    (3, 2, 3), (4, 2, 4))[
                                        len(authenticated_g1_states)]
                        need((stage, authenticated_group_stage) ==
                             (expected[0], expected[2]),
                             'c03-authenticated-group-order')
                        objects = _authenticated_group_objects(
                            message_payload, expected[0], expected[1], 65,
                            'c03-authenticated-group-canonical')
                        authenticated_g1_states.append((stage, objects))
                        authenticated_group_stage = (1 if stage == 1 else
                                                     3 if stage == 2 else
                                                     4 if stage == 3 else 5)
                    else:
                        need(len(authenticated_g2_states) < 2,
                             'c03-authenticated-group-order')
                        expected = ((1, 1, 1), (4, 1, 5))[
                            len(authenticated_g2_states)]
                        need((stage, authenticated_group_stage) ==
                             (expected[0], expected[2]),
                             'c03-authenticated-group-order')
                        objects = _authenticated_group_objects(
                            message_payload, expected[0], expected[1], 129,
                            'c03-authenticated-group-canonical')
                        authenticated_g2_states.append((stage, objects))
                        authenticated_group_stage = 2 if stage == 1 else 6
                        if stage == 4:
                            need(authenticated_g1_states[0][1][0] ==
                                    authenticated_g1_states[-1][1][0]
                                 and authenticated_g2_states[0][1][0] ==
                                    authenticated_g2_states[-1][1][0],
                                 'c03-authenticated-group-repeat')
                elif semantic == 7:
                    need(proof_opening_stage == 2
                         and authenticated_group_stage == 6,
                         'c03-proof-opening-order')
                    proof_opening_stage = 3
                elif semantic == 8:
                    need(proof_opening_stage == 3,
                         'c03-proof-opening-order')
                    proof_opening_stage = 4
                if semantic == 9:
                    projection_messages += 1
                    projection_payload = message_payload
                name = C03_SEMANTICS[semantic]
                stream_counts[name] = stream_counts.get(name, 0) + 1
                records.append(_c03_abstract_record(
                    len(records), semantic, peer, message_payload))
            current = None
        sequence += 1

    need(current is None and at == len(raw) and sealed and complete,
         'c03-end-eof')
    raw_wire_sha256 = hashlib.sha256(raw).hexdigest()
    need(end_frame_identity is not None, 'c03-end-frame-identity')
    eof_preimage = (b'KPB_CAPTURE_PRODUCER_STREAM_EOF_V1\n'
                    + struct.pack('>IBQQQ', authority['round'], 4,
                                  total[0], total[2], len(raw))
                    + bytes.fromhex(raw_wire_sha256)
                    + bytes.fromhex(end_frame_identity))
    computed_closure = {
        'schema': 'kpb-capture-source-closure/v2',
        'attempt_id': authority['attempt_id'],
        'cohort_sha256': authority['cohort_sha256'],
        'producer_record_count': total[0],
        'capture_record_count': total[0],
        'producer_payload_bytes': total[2],
        'capture_payload_bytes': total[2],
        'producer_stream_counts': stream_counts,
        'capture_stream_counts': stream_counts,
        'record_chain_sha256': raw_wire_sha256,
        'unknown_record_count': 0,
        'capture_root_closed': True,
        'producer_fd_closed': True,
        'raw_wire_bytes': len(raw),
        'raw_wire_sha256': raw_wire_sha256,
        'end_frame_identity': end_frame_identity,
        'eof_identity': hashlib.sha256(eof_preimage).hexdigest(),
    }
    need(authority['closure'] == computed_closure,
         'c03-source-closure-binding')
    return records, computed_closure, {
        'wire_frame_count': sequence,
        'wire_bytes': len(raw),
        'wire_sha256': raw_wire_sha256,
    }


def _projection_rows(projection, public):
    need(type(projection) is bytes and len(projection) == 10685
         and hashlib.sha256(projection).hexdigest()
             == public['projection_sha256']
         and projection[193:201] == b'KPBAEF01',
         'corrupt-projection-binding')
    body = projection[193:]
    rows = [body[692 + 520 * index:692 + 520 * (index + 1)]
            for index in range(6)]
    need([hashlib.sha256(row).hexdigest() for row in rows]
         == public['tuple_sha256'], 'corrupt-public-row-identity')
    return rows


def _payload(raw_hex, encoding):
    need(type(raw_hex) is str and len(raw_hex) % 2 == 0
         and re.fullmatch('[0-9a-f]*', raw_hex) is not None,
         'corrupt-payload-hex')
    raw = bytes.fromhex(raw_hex)
    if encoding == 'fr32le':
        need(raw and len(raw) % 32 == 0
             and all(int.from_bytes(raw[at:at + 32], 'little') < FIELD_MODULUS
                     for at in range(0, len(raw), 32)),
             'corrupt-canonical-field-lane')
    elif encoding == 'g1-65':
        need(raw and len(raw) % 65 == 0, 'corrupt-G1-lane')
    elif encoding == 'g2-129':
        need(raw and len(raw) % 129 == 0, 'corrupt-G2-lane')
    elif encoding == 'g1-share-mac':
        need(len(raw) >= 1 and (len(raw) - 1) % 130 == 0,
             'corrupt-authenticated-G1-lane')
    elif encoding == 'g2-share-mac':
        need(len(raw) >= 1 and (len(raw) - 1) % 258 == 0,
             'corrupt-authenticated-G2-lane')
    else:
        # Transport messages may be zero length.  Their presence, ordering,
        # direction and length remain explicit observer fields even when the
        # payload itself is empty.  Public projection bytes are checked
        # independently against the exact selected projection.
        need(encoding == 'bytes', 'corrupt-byte-lane')
    return raw


def _authenticated_group_objects(payload, stage, count, point_bytes,
                                 category):
    need(type(payload) is bytes and point_bytes in (65, 129)
         and len(payload) == 1 + count * 2 * point_bytes
         and payload[0] == stage, category)
    objects = []; at = 1
    for _ in range(count):
        start = at
        for _ in range(2):
            point = payload[at:at + point_bytes]; at += point_bytes
            need(point[0] in (0, 1), category)
            if point[0] == 0:
                need(point[1:] == bytes(point_bytes - 1), category)
            else:
                need(all(int.from_bytes(point[offset:offset + 32], 'little')
                         < FQ_MODULUS
                         for offset in range(1, point_bytes, 32)), category)
        objects.append(payload[start:at])
    need(at == len(payload), category)
    return objects


def _g1_decode(raw, category):
    need(type(raw) is bytes and len(raw) == 65 and raw[0] in (0, 1),
         category)
    if raw[0] == 0:
        need(raw[1:] == bytes(64), category)
        return None
    x = int.from_bytes(raw[1:33], 'little')
    y = int.from_bytes(raw[33:65], 'little')
    need(x < FQ_MODULUS and y < FQ_MODULUS
         and y * y % FQ_MODULUS == (x * x * x + 3) % FQ_MODULUS,
         category)
    return (x, y)


def _g1_add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left; x2, y2 = right
    if x1 == x2:
        if (y1 + y2) % FQ_MODULUS == 0:
            return None
        slope = (3 * x1 * x1) * pow(2 * y1, -1, FQ_MODULUS)
    else:
        slope = (y2 - y1) * pow((x2 - x1) % FQ_MODULUS,
                                -1, FQ_MODULUS)
    slope %= FQ_MODULUS
    x3 = (slope * slope - x1 - x2) % FQ_MODULUS
    y3 = (slope * (x1 - x3) - y1) % FQ_MODULUS
    return (x3, y3)


def _g1_negate(value):
    return None if value is None else (value[0], (-value[1]) % FQ_MODULUS)


def _g1_sum(*values):
    result = None
    for value in values:
        result = _g1_add(result, value)
    return result


def _g1_multiply(value, scalar):
    need(type(scalar) is int and 0 <= scalar < FIELD_MODULUS,
         'c03-authenticated-group-scalar')
    result = None; addend = value
    while scalar:
        if scalar & 1:
            result = _g1_add(result, addend)
        addend = _g1_add(addend, addend)
        scalar >>= 1
    return result


def _auth_g1_decode(raw, category):
    need(type(raw) is bytes and len(raw) == 130, category)
    return (_g1_decode(raw[:65], category),
            _g1_decode(raw[65:], category))


def _auth_g1_add(*values):
    share = None; mac = None
    for value in values:
        share = _g1_add(share, value[0])
        mac = _g1_add(mac, value[1])
    return (share, mac)


def _c03_authenticated_group_equations(records, wire_records, authority):
    """Check the three local AuthG correspondences from exact C03 sources."""
    need(authority['scalar_capture_manifest_sha256'] ==
            C03_SCALAR_CAPTURE_MANIFEST_SHA256
         and word(authority['model_preimage_sha256'])
         and word(authority['query_store_preimage_sha256']),
         'c03-authenticated-group-source-bindings')

    group_rows = [row for row in records
                  if row['semantic'] == 'authenticated-g1-state']
    need(len(group_rows) == 4, 'c03-authenticated-group-state-count')
    expected_counts = (4, 6, 2, 2)
    states = []
    for stage, (row, count) in enumerate(zip(group_rows, expected_counts), 1):
        payload = bytes.fromhex(row['payload_hex'])
        objects = _authenticated_group_objects(
            payload, stage, count, 65,
            'c03-authenticated-group-equation-encoding')
        states.append([_auth_g1_decode(
            value, 'c03-authenticated-group-equation-point')
            for value in objects])
    base, mixed, products, final = states

    # MIXED is U0,V0,D0,U1,V1,D1 and BASE starts A,B1,L,H.
    for index in range(2):
        u = mixed[3 * index]
        d = mixed[3 * index + 2]
        need(_auth_g1_add(u, d) == base[index],
             'c03-authenticated-group-D-equation')

    binding_groups = []
    for index, row in enumerate(wire_records):
        if row['semantic'] != 'scalar-capture-binding':
            continue
        payload = bytes.fromhex(row['payload_hex'])
        site = int.from_bytes(payload[2:4], 'big')
        elements = int.from_bytes(payload[4:12], 'big')
        if site != 22:
            continue
        need(index + 2 < len(wire_records)
             and payload[0:2] == bytes((1, 1))
             and elements == 6
             and wire_records[index + 1]['semantic'] ==
                'authenticated-share'
             and wire_records[index + 2]['semantic'] == 'mac-share',
             'c03-authenticated-group-scalar-bindings')
        shares = bytes.fromhex(wire_records[index + 1]['payload_hex'])
        macs = bytes.fromhex(wire_records[index + 2]['payload_hex'])
        need(len(shares) == len(macs) == 6 * 32,
             'c03-authenticated-group-scalar-bindings')
        binding_groups.append((
            [int.from_bytes(shares[32 * at:32 * (at + 1)], 'little')
             for at in range(6)],
            [int.from_bytes(macs[32 * at:32 * (at + 1)], 'little')
             for at in range(6)],
        ))
    need(len(binding_groups) == 1,
         'c03-authenticated-group-scalar-bindings')
    triple_shares, triple_macs = binding_groups[0]
    need(all(value < FIELD_MODULUS
             for value in triple_shares + triple_macs),
         'c03-authenticated-group-scalar-bindings')

    def unique_payload(semantic, size, category):
        selected = [bytes.fromhex(row['payload_hex']) for row in records
                    if row['semantic'] == semantic]
        need(len(selected) == 1 and len(selected[0]) == size, category)
        return selected[0]

    opened_scalars_raw = unique_payload(
        'masked-field-intermediate', 64,
        'c03-authenticated-group-opened-scalars')
    opened_scalars = [int.from_bytes(
        opened_scalars_raw[32 * at:32 * (at + 1)], 'little')
        for at in range(2)]
    need(all(value < FIELD_MODULUS for value in opened_scalars),
         'c03-authenticated-group-opened-scalars')
    opened_groups_raw = unique_payload(
        'masked-g1-intermediate', 130,
        'c03-authenticated-group-opened-groups')
    opened_groups = [_g1_decode(
        opened_groups_raw[65 * at:65 * (at + 1)],
        'c03-authenticated-group-opened-groups') for at in range(2)]
    alpha_raw = unique_payload(
        'mac-key-share', 32, 'c03-authenticated-group-alpha')
    alpha = int.from_bytes(alpha_raw, 'little')
    need(alpha < FIELD_MODULUS, 'c03-authenticated-group-alpha')

    # For corrupt P1 (party 1), a public constant contributes no local share,
    # while its MAC contribution is the public point times alpha_i.
    for index in range(2):
        u = mixed[3 * index]
        v = mixed[3 * index + 1]
        opened_d = opened_groups[index]
        opened_scalar = opened_scalars[index]
        b_share = triple_shares[3 * index + 1]
        b_mac = triple_macs[3 * index + 1]
        expected_share = _g1_sum(
            v[0], _g1_multiply(u[0], opened_scalar),
            _g1_multiply(opened_d, b_share))
        expected_mac = _g1_sum(
            v[1], _g1_multiply(u[1], opened_scalar),
            _g1_multiply(opened_d, b_mac),
            _g1_multiply(opened_d,
                         opened_scalar * alpha % FIELD_MODULUS))
        need(products[index] == (expected_share, expected_mac),
             'c03-authenticated-group-beaver-equations')

    need(final[1] == _auth_g1_add(
        products[0], products[1], base[2], base[3]),
        'c03-authenticated-group-C-equation')
    return {
        'D_equals_Q_minus_U': 4,
        'beaver_product_equations': 4,
        'C_equals_products_plus_L_plus_H': 2,
    }


def corrupt_server(raw, public, projection):
    """Admit a typed one-server capture and extract every literal public link.

    Source review must separately justify why the admitted lane grammar is the
    complete local view.  This adapter checks that the capture is nonempty,
    covers every selected lane and contains no unreported literal public ID.
    It makes no indistinguishability claim about authenticated shares.
    """
    codec.batch(public); rows = _projection_rows(projection, public)
    value = canonical(raw)
    exact(value, ('schema', 'round', 'projection_sha256', 'cohort_sha256',
                  'server_component', 'protocol_source_sha256',
                  'build_policy', 'records', 'closure'),
          'corrupt-fields')
    need(value['schema'] == 'kpb-corrupt-server-observer-capture/v1'
         and value['round'] == public['round']
         and value['projection_sha256'] == public['projection_sha256']
         and value['server_component'] == 1,
         'corrupt-binding')
    word(value['cohort_sha256'], 'corrupt-cohort')
    word(value['protocol_source_sha256'], 'corrupt-source')
    policy = value['build_policy']
    exact(policy, ('corruption_model', 'insecure', 'debug_mac', 'print_mac',
                   'no_client_tls'), 'corrupt-policy-fields')
    need(policy == {'corruption_model': 'ONE_SERVER_PLUS_OWNER1',
                    'insecure': False, 'debug_mac': False,
                    'print_mac': False, 'no_client_tls': False},
         'corrupt-selected-build-policy')
    records = value['records']
    need(type(records) is list and records, 'corrupt-record-array')
    semantics = set(); constraints = codec.empty_constraints()
    offset_owners = set(); preprocessing_owners = set()
    offset_bytes = {}; preprocessing_bytes = {}
    authenticated_g1_states = []; authenticated_g2_states = []
    authenticated_group_order = []
    allowed_channels = {'owner-tls', 'peer', 'local'}
    allowed_phases = {'setup', 'intake', 'preprocessing', 'trace', 'validation',
                      'proof', 'release'}
    allowed_semantics = {
        'owner-input-offset', 'owner-input-preprocessing-share',
        'mascot-message', 'authenticated-share', 'mac-key-share', 'mac-share',
        'randomness-share', 'randomness-mac', 'field-opening',
        'masked-field-intermediate', 'masked-g1-intermediate',
        'authenticated-g1-state', 'authenticated-g2-state',
        'final-proof-g1', 'final-proof-g2', 'public-projection',
    }
    for sequence, record in enumerate(records):
        exact(record, ('sequence', 'channel', 'phase', 'owner_component',
                       'semantic', 'encoding', 'payload_hex'),
              'corrupt-record-fields')
        need(record['sequence'] == sequence
             and record['channel'] in allowed_channels
             and record['phase'] in allowed_phases
             and record['semantic'] in allowed_semantics,
             'corrupt-record-enum')
        owner = record['owner_component']
        if owner is not None:
            codec.owner(owner)
        payload = _payload(record['payload_hex'], record['encoding'])
        semantics.add(record['semantic'])
        if record['semantic'] == 'owner-input-offset':
            need(record['channel'] == 'owner-tls'
                 and record['phase'] == 'intake' and type(owner) is int
                 and record['encoding'] == 'fr32le',
                 'corrupt-owner-offset-lane')
            need(owner not in offset_owners,
                 'corrupt-owner-offset-duplicate')
            offset_owners.add(owner); offset_bytes[owner] = len(payload)
        elif record['semantic'] == 'owner-input-preprocessing-share':
            need(record['channel'] == 'owner-tls'
                 and record['phase'] == 'preprocessing'
                 and type(owner) is int
                 and record['encoding'] == 'fr32le',
                 'corrupt-owner-preprocessing-lane')
            need(owner not in preprocessing_owners,
                 'corrupt-owner-preprocessing-duplicate')
            preprocessing_owners.add(owner)
            preprocessing_bytes[owner] = len(payload)
        elif record['semantic'] == 'public-projection':
            need(owner is None and record['phase'] == 'release'
                 and record['encoding'] == 'bytes' and payload == projection,
                 'corrupt-exact-public-release')
            continue
        else:
            need(owner is None, 'corrupt-no-owner-label-on-internal-lane')
            expected = {
                'mascot-message': ('peer', 'preprocessing', ('bytes',)),
                'authenticated-share': ('local', 'trace', ('fr32le',)),
                'mac-key-share': ('local', 'setup', ('fr32le',)),
                'mac-share': ('local', 'validation', ('fr32le',)),
                'randomness-share': ('local', 'trace', ('fr32le',)),
                'randomness-mac': ('local', 'trace', ('fr32le',)),
                'field-opening': ('local', 'proof', ('fr32le',)),
                'masked-field-intermediate': (
                    'local', 'proof', ('fr32le',)),
                'masked-g1-intermediate': (
                    'local', 'proof', ('g1-65',)),
                'authenticated-g1-state': (
                    'local', 'proof', ('g1-share-mac',)),
                'authenticated-g2-state': (
                    'local', 'proof', ('g2-share-mac',)),
                'final-proof-g1': ('local', 'proof', ('g1-65',)),
                'final-proof-g2': ('local', 'proof', ('g2-129',)),
            }[record['semantic']]
            need((record['channel'], record['phase']) == expected[:2]
                 and record['encoding'] in expected[2],
                 'corrupt-exact-semantic-lane')
            exact_width = {
                'mac-key-share': 32,
                'masked-field-intermediate': 64,
                'masked-g1-intermediate': 130,
                'final-proof-g1': 130,
                'final-proof-g2': 129,
            }.get(record['semantic'])
            need(exact_width is None or len(payload) == exact_width,
                 'corrupt-exact-opening-width')
            if record['semantic'] in (
                    'authenticated-g1-state',
                    'authenticated-g2-state'):
                object_bytes = (130 if record['semantic'] ==
                                'authenticated-g1-state' else 258)
                states = (authenticated_g1_states if record['semantic'] ==
                          'authenticated-g1-state'
                          else authenticated_g2_states)
                counts = ({1: 4, 2: 6, 3: 2, 4: 2}
                          if record['semantic'] == 'authenticated-g1-state'
                          else {1: 1, 4: 1})
                need(payload[0] in counts,
                     'corrupt-authenticated-group-stages')
                objects = _authenticated_group_objects(
                    payload, payload[0], counts[payload[0]],
                    object_bytes // 2,
                    'corrupt-authenticated-group-canonical')
                states.append((payload[0], objects))
                authenticated_group_order.append(
                    record['semantic'] + ':' + str(payload[0]))
            elif record['semantic'] in (
                    'masked-field-intermediate', 'masked-g1-intermediate',
                    'final-proof-g1', 'final-proof-g2'):
                authenticated_group_order.append(record['semantic'])

        found_nfs = [nf for nf in public['nfs_hex32']
                     if bytes.fromhex(nf) in payload]
        found_tuples = [digest for digest, row in
                        zip(public['tuple_sha256'], rows)
                        if bytes.fromhex(digest) in payload or row in payload]
        if owner is not None:
            constraints['input_edges'].extend({
                'owner_component': owner, 'slot_id': nf,
                'provenance': 'direct-export'} for nf in found_nfs)
            constraints['creator_edges'].extend({
                'owner_component': owner, 'slot_id': digest,
                'provenance': 'direct-export'} for digest in found_tuples)
        elif len(found_tuples) == 2:
            # Conservatively treat two public tuples literally co-located in a
            # non-public transcript frame as grouped.  This can only reduce
            # the measured candidate set; opaque crypto is not called safe.
            constraints['pair_edges'].append({
                'tuple_sha256': found_tuples,
                'provenance': 'pair-tag-export'})
        if len(found_nfs) == 1 and len(found_tuples) == 2:
            constraints['nf_pair_edges'].append({
                'nf_hex32': found_nfs[0],
                'tuple_sha256': found_tuples,
                'provenance': 'direct-export'})
    expected_g1_stages = ((1, 4), (2, 6), (3, 2), (4, 2))
    expected_g2_stages = ((1, 1), (4, 1))
    need(tuple((stage, len(objects)) for stage, objects in
               authenticated_g1_states) == expected_g1_stages
         and tuple((stage, len(objects)) for stage, objects in
                   authenticated_g2_states) == expected_g2_stages,
         'corrupt-authenticated-group-stages')
    need(tuple(authenticated_group_order) == (
        'authenticated-g1-state:1', 'authenticated-g2-state:1',
        'authenticated-g1-state:2', 'masked-field-intermediate',
        'masked-g1-intermediate', 'authenticated-g1-state:3',
        'authenticated-g1-state:4', 'authenticated-g2-state:4',
        'final-proof-g1', 'final-proof-g2'),
        'corrupt-authenticated-group-order')
    need(authenticated_g1_states[0][1][0] ==
            authenticated_g1_states[-1][1][0]
         and authenticated_g2_states[0][1][0] ==
            authenticated_g2_states[-1][1][0],
         'corrupt-authenticated-group-repeat')
    need(offset_owners == preprocessing_owners == set(codec.OWNERS)
         and all(preprocessing_bytes[owner] == 5 * offset_bytes[owner]
                 for owner in codec.OWNERS)
         and all(sum(row['semantic'] == semantic for row in records) == 1
                 for semantic in (
                     'mac-key-share',
                     'masked-field-intermediate',
                     'masked-g1-intermediate',
                     'final-proof-g1', 'final-proof-g2'))
         and semantics == allowed_semantics,
         'corrupt-complete-selected-lanes')
    # Deduplicate literal matches across transcript frames.
    for name in ('input_edges', 'creator_edges', 'pair_edges',
                 'nf_pair_edges'):
        constraints[name] = [value for index, value in
                             enumerate(constraints[name])
                             if value not in constraints[name][:index]]
    codec.constraints(constraints, public)
    payload_bytes = sum(len(bytes.fromhex(row['payload_hex']))
                        for row in records)
    closure_records = [{'stream': row['semantic'], 'value': row}
                       for row in records]
    attempt_id = capture_closure(value['closure'], closure_records,
                                 payload_bytes,
                                 value['cohort_sha256'], public['round'],
                                 'corrupt-server-capture')
    inventory = {
        'schema': 'kpb-corrupt-server-lane-inventory/v4',
        'record_count': len(records),
        'record_bytes': payload_bytes,
        'semantics': sorted(semantics),
        'owner_offset_count': sum(
            row['semantic'] == 'owner-input-offset' for row in records),
        'owner_preprocessing_share_count': sum(
            row['semantic'] == 'owner-input-preprocessing-share'
            for row in records),
        'owner_preprocessing_to_offset_width_ratio': 5,
        'mac_key_share_count': sum(
            row['semantic'] == 'mac-key-share' for row in records),
        'masked_field_intermediate_count': sum(
            row['semantic'] == 'masked-field-intermediate'
            for row in records),
        'masked_g1_intermediate_count': sum(
            row['semantic'] == 'masked-g1-intermediate'
            for row in records),
        'final_proof_g1_count': sum(
            row['semantic'] == 'final-proof-g1' for row in records),
        'final_proof_g2_count': sum(
            row['semantic'] == 'final-proof-g2' for row in records),
        'authenticated_g1_stage_object_counts': {
            name: count for name, count in
            (('BASE', 4), ('MIXED', 6), ('PRODUCTS', 2), ('FINAL', 2))},
        'authenticated_g2_stage_object_counts': {
            'BASE': 1, 'FINAL': 1},
        'direct_constraint_count': sum(len(constraints[name]) for name in
                                       ('input_edges', 'creator_edges',
                                        'pair_edges', 'nf_pair_edges')),
        'attempt_id': attempt_id,
        'cohort_sha256': value['cohort_sha256'],
        'observer_scope':
            'PINNED_INSTRUMENTED_PASSIVE_P1_PROCESS_PLUS_PASSIVE_OWNER1',
        'out_of_scope_unqualified_boundaries': {
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
        },
        'cryptographic_independence_or_privacy_claim': False,
    }
    return artifact_result(raw, 'corrupt-server-capture', public['round'],
                           constraints, SERVER_CATEGORIES, inventory,
                           unmodeled_fields=(
                               ('authenticated-transcript',
                                'capture.model_preimage_binding'),
                               ('authenticated-transcript',
                                'capture.public_query_preimage_binding'),
                               ('authenticated-transcript',
                                'capture.scalar_callsite_manifest_binding'),
                               ('authenticated-transcript',
                                'records[scalar-capture-binding].site_kind_element_count_order'),
                               ('authenticated-transcript',
                                'records[scalar-capture-binding].payload.nonliteral_implications'),
                               ('authenticated-transcript',
                                'records[mascot-message].payload.nonliteral_implications'),
                               ('authenticated-transcript',
                                'records[field-opening].payload.nonliteral_implications'),
                               ('authenticated-transcript',
                                'records[masked-field-intermediate].payload.nonliteral_implications'),
                               ('authenticated-transcript',
                                'records[masked-g1-intermediate].payload.nonliteral_implications'),
                               ('authenticated-transcript',
                                'records[final-proof-g1].payload.nonliteral_implications'),
                               ('authenticated-transcript',
                                'records[final-proof-g2].payload.nonliteral_implications'),
                               ('authenticated-transcript',
                                'wire.frames[].monotonic_ns'),
                               ('authenticated-transcript',
                                'wire.frames[].payload_length'),
                               ('authenticated-transcript',
                                'wire.frames[].sequence_message_chunk_order'),
                               ('authenticated-transcript',
                                'wire.frames[].direction_peer_fork'),
                               ('authenticated-transcript',
                                'wire.frames[].mixed_protocol_nonliteral_implications'),
                               ('authenticated-transcript',
                                'attempt.abort_retry_partial_transcript'),
                               ('authenticated-transcript',
                                'capture.source_build_launch_role_binding'),
                               ('authenticated-group-state',
                                'records[authenticated-g1-state].payload.nonliteral_implications'),
                               ('authenticated-group-state',
                                'records[authenticated-g2-state].payload.nonliteral_implications'),
                               ('authenticated-group-state',
                                'records[authenticated-group-query-msm-temporary].capture_correspondence'),
                               ('authenticated-group-state',
                                'records[authenticated-group-query-msm-temporary].compressed_query_bytes'),
                               ('authenticated-group-state',
                                'records[authenticated-group-query-msm-temporary].decoded_public_point_chunks'),
                               ('authenticated-group-state',
                                'records[authenticated-group-query-msm-temporary].point_map_share_mac'),
                               ('authenticated-group-state',
                                'records[authenticated-group-query-msm-temporary].worker_partials'),
                               ('authenticated-group-state',
                                'records[authenticated-group-query-msm-temporary].running_query_sums'),
                               ('authenticated-group-state',
                                'records[authenticated-g1-state].D_equals_Q_minus_U'),
                               ('authenticated-group-state',
                                'records[authenticated-g1-state].beaver_product_equations'),
                               ('authenticated-group-state',
                                'records[authenticated-g1-state].C_equals_products_plus_L_plus_H'),
                               ('server-local-shares',
                                'records[owner-input-offset].payload.nonliteral_implications'),
                               ('server-local-shares',
                                'records[owner-input-preprocessing-share].payload.nonliteral_implications'),
                               ('server-local-shares',
                                'records[authenticated-share].payload.nonliteral_implications'),
                               ('server-mac-state',
                                'records[mac-key-share].payload.nonliteral_implications'),
                               ('server-mac-state',
                                'records[mac-share].payload.nonliteral_implications'),
                               ('server-randomness',
                                'records[randomness-share].payload.nonliteral_implications'),
                               ('server-randomness',
                                'records[randomness-mac].payload.nonliteral_implications'),
                           ),
                           constraint_counts={
                               ('authenticated-transcript',
                                'records[public-projection].payload'): 1,
                               ('authenticated-transcript',
                                'records[].schema_grammar'):
                                   len(records),
                               ('authenticated-transcript',
                                'records[mascot-message].payload.literal_public_identifiers'):
                                   sum(row['semantic'] == 'mascot-message'
                                       for row in records),
                               ('authenticated-transcript',
                                'records[field-opening].payload.literal_public_identifiers'):
                                   sum(row['semantic'] == 'field-opening'
                                       for row in records),
                               ('authenticated-transcript',
                                'records[masked-field-intermediate].payload.literal_public_identifiers'):
                                   sum(row['semantic'] ==
                                       'masked-field-intermediate'
                                       for row in records),
                               ('authenticated-transcript',
                                'records[masked-g1-intermediate].payload.literal_public_identifiers'):
                                   sum(row['semantic'] ==
                                       'masked-g1-intermediate'
                                       for row in records),
                               ('authenticated-transcript',
                                'records[final-proof-g1].payload.literal_public_identifiers'):
                                   sum(row['semantic'] == 'final-proof-g1'
                                       for row in records),
                               ('authenticated-transcript',
                                'records[final-proof-g2].payload.literal_public_identifiers'):
                                   sum(row['semantic'] == 'final-proof-g2'
                                       for row in records),
                               ('authenticated-group-state',
                                'records[authenticated-g1-state].payload.literal_public_identifiers'):
                                   sum(row['semantic'] ==
                                       'authenticated-g1-state'
                                       for row in records),
                               ('authenticated-group-state',
                                'records[authenticated-g2-state].payload.literal_public_identifiers'):
                                   sum(row['semantic'] ==
                                       'authenticated-g2-state'
                                       for row in records),
                               ('server-local-shares',
                                'records[owner-input-offset].payload.literal_public_identifiers'):
                                   sum(row['semantic'] ==
                                       'owner-input-offset'
                                       for row in records),
                               ('server-local-shares',
                                'records[owner-input-preprocessing-share].payload.literal_public_identifiers'):
                                   sum(row['semantic'] ==
                                       'owner-input-preprocessing-share'
                                       for row in records),
                               ('server-local-shares',
                                'records[authenticated-share].payload.literal_public_identifiers'):
                                   sum(row['semantic'] ==
                                       'authenticated-share'
                                       for row in records),
                               ('server-mac-state',
                                'records[mac-key-share].payload.literal_public_identifiers'):
                                   sum(row['semantic'] == 'mac-key-share'
                                       for row in records),
                               ('server-mac-state',
                                'records[mac-share].payload.literal_public_identifiers'):
                                   sum(row['semantic'] == 'mac-share'
                                       for row in records),
                               ('server-randomness',
                                'records[randomness-share].payload.literal_public_identifiers'):
                                   sum(row['semantic'] ==
                                       'randomness-share'
                                       for row in records),
                               ('server-randomness',
                                'records[randomness-mac].payload.literal_public_identifiers'):
                                   sum(row['semantic'] == 'randomness-mac'
                                       for row in records),
                           })


def corrupt_server_c03(raw, public, projection, authority,
                       role_launch_closure, role_launch_sha256):
    """Bridge one source-bound opaque C03 leaf into the typed P1 model.

    The caller supplies the exact authority row minted by the selected capture
    producer receipt plus the independently selected exact preimage for the
    aggregate role-launch digest.  This function joins the P1 row to that
    preimage, re-verifies every identity from the wire, independently checks
    the v9/17-lane closure, and only then derives the abstract records used by
    ``corrupt_server``.  There is no raw JSON or caller Boolean substitute.
    """
    wire_records, wire_closure, wire_inventory = _parse_c03(
        raw, public, projection, authority, role_launch_closure,
        role_launch_sha256)
    scalar_bindings = [row for row in wire_records
                       if row['semantic'] == 'scalar-capture-binding']
    typed_records = [row for row in wire_records
                     if row['semantic'] != 'scalar-capture-binding']
    records = [dict(row, sequence=sequence)
               for sequence, row in enumerate(typed_records)]
    group_equations = _c03_authenticated_group_equations(
        records, wire_records, authority)
    closure_records = [{'stream': row['semantic'], 'value': row}
                       for row in records]
    payload_bytes = sum(len(bytes.fromhex(row['payload_hex']))
                        for row in records)
    stream_counts = {}
    for row in closure_records:
        stream_counts[row['stream']] = stream_counts.get(
            row['stream'], 0) + 1
    model_closure = {
        'schema': 'kpb-capture-source-closure/v1',
        'attempt_id': authority['attempt_id'],
        'cohort_sha256': authority['cohort_sha256'],
        'producer_record_count': len(records),
        'capture_record_count': len(records),
        'producer_payload_bytes': payload_bytes,
        'capture_payload_bytes': payload_bytes,
        'producer_stream_counts': stream_counts,
        'capture_stream_counts': stream_counts,
        'record_chain_sha256': hashlib.sha256(
            codec.encoded(closure_records)).hexdigest(),
        'unknown_record_count': 0,
        'capture_root_closed': True,
        'producer_fd_closed': True,
    }
    model_raw = codec.encoded({
        'schema': 'kpb-corrupt-server-observer-capture/v1',
        'round': public['round'],
        'projection_sha256': public['projection_sha256'],
        'cohort_sha256': authority['cohort_sha256'],
        'server_component': authority['server_component'],
        'protocol_source_sha256': authority['source_sha256'],
        'build_policy': {
            'corruption_model': 'ONE_SERVER_PLUS_OWNER1',
            'insecure': False,
            'debug_mac': False,
            'print_mac': False,
            'no_client_tls': False,
        },
        'records': records,
        'closure': model_closure,
    })
    modeled = corrupt_server(model_raw, public, projection)
    modeled['artifact_sha256'] = hashlib.sha256(raw).hexdigest()
    modeled['inventory'] = {
        **modeled['inventory'],
        'schema': 'kpb-corrupt-server-c03-lane-inventory/v1',
        'c03_source_build_launch_role_bound': True,
        'c03_wire_frame_count': wire_inventory['wire_frame_count'],
        'c03_wire_bytes': wire_inventory['wire_bytes'],
        'c03_wire_sha256': wire_inventory['wire_sha256'],
        'c03_fixed_fd': authority['fixed_fd'],
        'c03_source_sha256': authority['source_sha256'],
        'c03_build_sha256': authority['build_sha256'],
        'c03_launch_sha256': authority['launch_sha256'],
        'c03_model_preimage_sha256': authority['model_preimage_sha256'],
        'c03_query_store_preimage_sha256':
            authority['query_store_preimage_sha256'],
        'c03_scalar_capture_manifest_sha256':
            authority['scalar_capture_manifest_sha256'],
        'c03_scalar_binding_count': len(scalar_bindings),
        'c03_scalar_site_bitmap': C03_SELECTED_SCALAR_SITE_BITMAP,
        'c03_authenticated_group_equation_constraints': group_equations,
        'c03_wire_closure': wire_closure,
    }
    direct_bindings = {
        'capture.source_build_launch_role_binding': 1,
        'capture.model_preimage_binding': 1,
        'capture.public_query_preimage_binding': 1,
        'capture.scalar_callsite_manifest_binding': 1,
        'records[scalar-capture-binding].site_kind_element_count_order':
            len(scalar_bindings),
    }
    for field_path, count in direct_bindings.items():
        binding_rows = [
            row for row in modeled['leakage_ledger']
            if row['category'] == 'authenticated-transcript'
            and row['field_path'] == field_path]
        need(len(binding_rows) == 1
             and binding_rows[0]['status'] == 'unmodeled'
             and count > 0,
             'c03-single-unmodeled-authority-row')
        binding_rows[0].update({
            'status': 'constraint_modeled',
            'constraint_count': count,
            'assumption_sha256': None,
        })
    equation_paths = {
        'records[authenticated-g1-state].D_equals_Q_minus_U':
            group_equations['D_equals_Q_minus_U'],
        'records[authenticated-g1-state].beaver_product_equations':
            group_equations['beaver_product_equations'],
        'records[authenticated-g1-state].C_equals_products_plus_L_plus_H':
            group_equations['C_equals_products_plus_L_plus_H'],
    }
    for field_path, count in equation_paths.items():
        rows = [row for row in modeled['leakage_ledger']
                if row['category'] == 'authenticated-group-state'
                and row['field_path'] == field_path]
        need(len(rows) == 1 and rows[0]['status'] == 'unmodeled'
             and count > 0,
             'c03-single-unmodeled-group-equation-row')
        rows[0].update({
            'status': 'constraint_modeled',
            'constraint_count': count,
            'assumption_sha256': None,
        })
    _validate_leakage_ledger('corrupt-server-capture',
                             modeled['leakage_ledger'])
    return modeled


COLLUDER_SOURCE_FIELDS = (
    'observer_stage', 'stage_sequence', 'operation_id_sha256',
    'contact_owner_component', 'contact_binding_qualified',
    'source_event_sequence', 'observed_monotonic_ns',
)
COLLUDER_QUALIFIED_SOURCE_FIELDS = (
    'schema', *COLLUDER_SOURCE_FIELDS, 'value_binding_qualified',
    'value_kind', 'value_sha256', 'stage_config_sha256',
    'contact_value_authority_sha256', 'source_event_binding_sha256',
)
COLLUDER_QUALIFIED_SOURCE_SCHEMA = \
    'kpb-c1-authenticated-contact-value-source/v1'
COLLUDER_QUALIFIED_META_SCHEMA = \
    'kpb-colluder-wallet-observer-capture/v2'
COLLUDER_CONTACT_VALUE_EVENT_DOMAIN = \
    b'KPB_C1_CONTACT_VALUE_EVENT_V1\n'
COLLUDER_STAGE_SEQUENCE = {'invoice': 0, 'pay': 1, 'scan': 2}
_C1_CONTACT_VALUE_AUTHORITY_CONSTRUCTOR = object()


class _C1ContactValueSourceAuthority:
    """One-shot child-only join of the C1 residual and producer closure."""
    __slots__ = ('_binding', '_live')

    def __init__(self, constructor, binding):
        need(constructor is _C1_CONTACT_VALUE_AUTHORITY_CONSTRUCTOR,
             'c1-source-authority-constructor')
        scalar_fields = (
            'artifact_sha256', 'capture_identity_sha256',
            'financial_run_sha256',
            'round_attempt_sha256', 'round_cohort_sha256',
            'round_capture_plan_sha256', 'round_projection_sha256',
            'source_closure_sha256', 'role_closure_sha256',
            'contact_value_authority_sha256', 'stage_plan_sha256',
            'source_sha256', 'build_sha256', 'runtime_sha256',
            'assets_sha256', 'pinned_executable_sha256',
            'launcher_sha256', 'role_launch_sha256',
            'route_manifest_sha256', 'route_source_sha256',
            'process_sha256', 'child_exit_sha256',
            'producer_closure_authority_sha256',
        )
        exact(binding, (
            *scalar_fields, 'round', 'attempt_id', 'fixed_fd',
            'contact_owner_components', 'operation_id_sha256',
            'stage_config_sha256'), 'c1-source-authority-fields')
        for name in scalar_fields:
            word(binding[name], 'c1-source-authority-' + name)
        try:
            parsed_attempt = uuid.UUID(binding['attempt_id'])
        except (TypeError, ValueError, AttributeError):
            parsed_attempt = None
        need(binding['round'] in (1, 2)
             and binding['fixed_fd'] == {1: 24, 2: 29}[binding['round']]
             and parsed_attempt is not None
             and parsed_attempt.version == 4
             and str(parsed_attempt) == binding['attempt_id']
             and binding['source_closure_sha256'] ==
                binding['role_closure_sha256'] ==
                binding['role_launch_sha256'],
             'c1-source-authority-binding')
        contacts = binding['contact_owner_components']
        operations = binding['operation_id_sha256']
        stage_configs = binding['stage_config_sha256']
        incoming = (1 - binding['round']) % 3
        outgoing = (1 + binding['round']) % 3
        need(contacts == [incoming, outgoing, incoming]
             and type(operations) is list and len(operations) == 3
             and len(set(operations)) == 3
             and type(stage_configs) is list and len(stage_configs) == 3
             and len(set(stage_configs)) == 3,
             'c1-source-authority-stage-shape')
        for name, rows in (('operation', operations),
                           ('stage-config', stage_configs)):
            for row in rows:
                word(row, 'c1-source-authority-' + name)
        self._binding = {
            key: list(value) if type(value) is list else value
            for key, value in binding.items()
        }
        self._live = True


def _test_only_mint_c1_contact_value_source_authority(binding):
    """Synthetic control seam; the production observer has no minter yet."""
    return _C1ContactValueSourceAuthority(
        _C1_CONTACT_VALUE_AUTHORITY_CONSTRUCTOR, binding)


def _c1_qualified_value_kind(stream, body):
    if stream == 'original':
        result = 'ORIGINAL'
    elif stream == 'invoice':
        result = {'issued': 'ISSUED_INVOICE',
                  'accepted': 'ACCEPTED_INVOICE'}.get(
                      body.get('direction'))
    elif stream == 'decrypted-receipt':
        result = {'incoming-payment': 'INCOMING_RECEIPT',
                  'change': 'CHANGE_RECEIPT'}.get(body.get('kind'))
    elif stream == 'retry':
        result = 'RETRY'
    else:
        result = None
    need(result is not None, 'c1-qualified-value-kind')
    return result


def _c1_source_event_sha256(stream, body, source):
    preimage = {
        'schema': 'kpb-c1-contact-value-event-binding/v1',
        'contact_value_authority_sha256':
            source['contact_value_authority_sha256'],
        'stage_config_sha256': source['stage_config_sha256'],
        'observer_stage': source['observer_stage'],
        'stage_sequence': source['stage_sequence'],
        'operation_id_sha256': source['operation_id_sha256'],
        'contact_owner_component': source['contact_owner_component'],
        'source_event_sequence': source['source_event_sequence'],
        'observed_monotonic_ns': source['observed_monotonic_ns'],
        'stream': stream,
        'value_kind': source['value_kind'],
        'value_sha256': source['value_sha256'],
    }
    return hashlib.sha256(
        COLLUDER_CONTACT_VALUE_EVENT_DOMAIN + codec.encoded(preimage)
    ).hexdigest()


def _colluder_observed(row, stream, public, source_authority=None):
    exact(row, ('source', 'value'), 'colluder-observed-fields')
    source = row['source']; body = row['value']
    qualified = source_authority is not None
    exact(source, (COLLUDER_QUALIFIED_SOURCE_FIELDS if qualified else
                   COLLUDER_SOURCE_FIELDS), 'colluder-source-fields')
    stage = source['observer_stage']
    incoming = (1 - public['round']) % 3
    outgoing = (1 + public['round']) % 3
    need(stage in COLLUDER_STAGE_SEQUENCE
         and type(source['stage_sequence']) is int
         and source['stage_sequence'] == COLLUDER_STAGE_SEQUENCE[stage]
         and word(source['operation_id_sha256'],
                  'colluder-source-operation')
         and type(source['contact_owner_component']) is int
         and source['contact_owner_component'] ==
            (outgoing if stage == 'pay' else incoming)
         and source['contact_binding_qualified'] is qualified
         and natural(source['source_event_sequence'],
                     'colluder-source-event-sequence') >= 0
         and natural(source['observed_monotonic_ns'],
                     'colluder-source-monotonic-time') > 0
         and type(body) is dict,
         'colluder-source-binding')
    semantic_stage = None
    if stream == 'original':
        semantic_stage = 'pay'
    elif stream == 'invoice':
        semantic_stage = {'issued': 'invoice', 'accepted': 'pay'}.get(
            body.get('direction'))
    elif stream == 'decrypted-receipt':
        semantic_stage = 'scan'
    need(stream == 'retry' or stage == semantic_stage,
         'colluder-source-semantic-stage')
    if qualified:
        binding = source_authority._binding
        stage_index = COLLUDER_STAGE_SEQUENCE[stage]
        expected_kind = _c1_qualified_value_kind(stream, body)
        need(source['schema'] == COLLUDER_QUALIFIED_SOURCE_SCHEMA
             and source['value_binding_qualified'] is True
             and source['value_kind'] == expected_kind
             and source['value_sha256'] ==
                hashlib.sha256(codec.encoded(body)).hexdigest()
             and source['stage_config_sha256'] ==
                binding['stage_config_sha256'][stage_index]
             and source['contact_value_authority_sha256'] ==
                binding['contact_value_authority_sha256']
             and source['operation_id_sha256'] ==
                binding['operation_id_sha256'][stage_index]
             and source['contact_owner_component'] ==
                binding['contact_owner_components'][stage_index]
             and source['source_event_binding_sha256'] ==
                _c1_source_event_sha256(stream, body, source),
             'c1-source-event-binding')
    return source, body


def _colluder_source_closure(records):
    by_stage = {stage: [] for stage in COLLUDER_STAGE_SEQUENCE}
    for row in records:
        by_stage[row['source']['observer_stage']].append(row['source'])
    operation_ids = set(); previous_stage_time = 0
    for stage in ('invoice', 'pay', 'scan'):
        ordered = sorted(by_stage[stage],
                         key=lambda row: row['source_event_sequence'])
        need(ordered
             and [row['source_event_sequence'] for row in ordered] ==
                list(range(len(ordered)))
             and [row['observed_monotonic_ns'] for row in ordered] ==
                sorted(row['observed_monotonic_ns'] for row in ordered)
             and len({row['operation_id_sha256'] for row in ordered}) == 1
             and ordered[0]['observed_monotonic_ns'] >= previous_stage_time,
             'colluder-source-stage-closure')
        previous_stage_time = ordered[-1]['observed_monotonic_ns']
        operation_ids.add(ordered[0]['operation_id_sha256'])
    need(len(operation_ids) == 3, 'colluder-distinct-stage-operations')


def _colluder_wallet_model(raw, public, source_authority=None):
    """Model the selected owner-1 wallet's complete direct public knowledge.

    This artifact is built and retained inside the isolated observer from the
    wallet's own Original, invoices and successfully decrypted receipts.  It
    contains only the finite public joins needed by the direct-linkage model;
    admitting it is not a claim about other implications of secret keys or
    cryptographic transcript bytes.
    """
    codec.batch(public); value = canonical(raw)
    qualified = source_authority is not None
    exact(value, ('schema', 'round', 'projection_sha256', 'cohort_sha256',
                  'owner_component', 'original', 'invoices',
                  'decrypted_receipts', 'retry_history', 'closure') +
                 (('contact_value_authority_sha256',) if qualified else ()),
          'colluder-fields')
    need(value['schema'] == (COLLUDER_QUALIFIED_META_SCHEMA if qualified else
                             'kpb-colluder-wallet-observer-capture/v1')
         and value['round'] == public['round']
         and value['projection_sha256'] == public['projection_sha256']
         and value['owner_component'] == 1,
         'colluder-binding')
    word(value['cohort_sha256'], 'colluder-cohort')
    if qualified:
        need(type(source_authority) is _C1ContactValueSourceAuthority
             and source_authority._live,
             'c1-source-authority-type')
        binding = source_authority._binding
        need(binding['artifact_sha256'] == hashlib.sha256(raw).hexdigest()
             and binding['round'] == public['round']
             and binding['round_projection_sha256'] ==
                public['projection_sha256']
             and binding['round_cohort_sha256'] == value['cohort_sha256']
             and binding['attempt_id'] == value['closure']['attempt_id']
             and binding['contact_value_authority_sha256'] ==
                value['contact_value_authority_sha256'],
             'c1-source-authority-artifact-binding')
        source_authority._live = False
    original_observed = value['original']
    _, original = _colluder_observed(
        original_observed, 'original', public, source_authority)
    exact(original, ('input_nf_hex32', 'input_amount_sompi',
                     'created_outputs'),
          'colluder-original-fields')
    input_nf = original['input_nf_hex32']
    need(type(original['input_amount_sompi']) is int
         and original['input_amount_sompi'] > 0,
         'colluder-positive-input-amount')
    created_outputs = original['created_outputs']
    need(type(created_outputs) is list and len(created_outputs) == 2,
         'colluder-two-created-outputs')
    expected_kinds = ('outgoing-payment', 'change')
    created = []
    for output, expected_kind in zip(created_outputs, expected_kinds):
        exact(output, ('kind', 'tuple_sha256', 'amount_sompi'),
              'colluder-created-output-fields')
        need(output['kind'] == expected_kind
             and type(output['amount_sompi']) is int
             and output['amount_sompi'] > 0,
             'colluder-created-output-amount')
        created.append(output['tuple_sha256'])
    need(input_nf in public['nfs_hex32']
         and len(created) == len(set(created)) == 2
         and all(digest in public['tuple_sha256'] for digest in created),
         'colluder-original-public-joins')

    incoming = (1 - public['round']) % 3
    outgoing = (1 + public['round']) % 3
    invoice_observed = value['invoices']
    need(type(invoice_observed) is list and len(invoice_observed) == 2,
         'colluder-two-selected-invoices')
    invoices = [_colluder_observed(
                    row, 'invoice', public, source_authority)[1]
                for row in invoice_observed]
    expected_invoices = (
        ('issued', incoming, 1),
        ('accepted', 1, outgoing),
    )
    for invoice, expected in zip(invoices, expected_invoices):
        exact(invoice, ('direction', 'source_owner_component',
                        'target_owner_component', 'operation_id_sha256',
                        'amount_sompi'),
              'colluder-invoice-fields')
        need((invoice['direction'], invoice['source_owner_component'],
              invoice['target_owner_component']) == expected
             and word(invoice['operation_id_sha256'])
             and type(invoice['amount_sompi']) is int
             and invoice['amount_sompi'] > 0,
             'colluder-selected-invoice-schedule')
    if qualified:
        frozen_amount = 500_000_000 if public['round'] == 1 else 200_000_000
        need([invoice['amount_sompi'] for invoice in invoices] ==
             [frozen_amount, frozen_amount],
             'c1-qualified-frozen-invoice-values')
    invoice_stage_operation = invoice_observed[0]['source'][
        'operation_id_sha256']
    need(invoices[0]['operation_id_sha256'] == invoice_stage_operation
         and invoices[1]['operation_id_sha256'] == invoice_stage_operation,
         'colluder-invoice-operation-binding')

    receipt_observed = value['decrypted_receipts']
    need(type(receipt_observed) is list and len(receipt_observed) == 2,
         'colluder-two-decrypted-receipts')
    receipts = [_colluder_observed(
                    row, 'decrypted-receipt', public, source_authority)[1]
                for row in receipt_observed]
    expected_receipts = (
        ('incoming-payment', 2 * public['round'] - 1, incoming),
        ('change', 2 * public['round'], 1),
    )
    for receipt, expected in zip(receipts, expected_receipts):
        exact(receipt, ('kind', 'receipt_index', 'creator_owner_component',
                        'tuple_sha256', 'cm_hex32', 'amount_sompi'),
              'colluder-receipt-fields')
        digest = receipt['tuple_sha256']
        need((receipt['kind'], receipt['receipt_index'],
              receipt['creator_owner_component']) == expected
             and digest in public['tuple_sha256']
             and receipt['cm_hex32'] == public['cms_hex32'][
                 public['tuple_sha256'].index(digest)]
             and type(receipt['amount_sompi']) is int
             and receipt['amount_sompi'] > 0,
             'colluder-decrypted-receipt-join')
    incoming_tuple = receipts[0]['tuple_sha256']
    change_tuple = receipts[1]['tuple_sha256']
    need(incoming_tuple not in created and change_tuple in created
         and incoming_tuple != change_tuple
         and invoices[0]['amount_sompi'] == receipts[0]['amount_sompi']
         and invoices[1]['amount_sompi'] ==
             created_outputs[0]['amount_sompi']
         and receipts[1]['amount_sompi'] ==
             created_outputs[1]['amount_sompi'],
         'colluder-receipt-original-consistency')

    retry_observed = value['retry_history']
    need(type(retry_observed) is list, 'colluder-retry-array')
    retries = [_colluder_observed(
                   row, 'retry', public, source_authority)[1]
               for row in retry_observed]
    attempts = set()
    for retry in retries:
        exact(retry, ('attempt_id', 'start_monotonic_ns',
                      'complete_monotonic_ns', 'outcome'),
              'colluder-retry-fields')
        need(type(retry['attempt_id']) is str
             and re.fullmatch('[A-Za-z0-9_-]{1,128}', retry['attempt_id'])
             and retry['attempt_id'] not in attempts,
             'colluder-retry-id')
        attempts.add(retry['attempt_id'])
        start = natural(retry['start_monotonic_ns'], 'colluder-retry-start')
        complete = natural(retry['complete_monotonic_ns'],
                           'colluder-retry-complete')
        need(complete >= start and retry['outcome'] in
             ('refused', 'disconnected', 'completed'),
             'colluder-retry-outcome')
    source_records = ([{'stream': 'original', **original_observed}]
                      + [{'stream': 'invoice', **row}
                         for row in invoice_observed]
                      + [{'stream': 'decrypted-receipt', **row}
                         for row in receipt_observed]
                      + [{'stream': 'retry', **row}
                         for row in retry_observed])
    _colluder_source_closure(source_records)

    constraints = codec.empty_constraints()
    constraints['input_edges'].append({
        'owner_component': 1, 'slot_id': input_nf,
        'provenance': 'colluder-knowledge'})
    constraints['creator_edges'].extend({
        'owner_component': 1, 'slot_id': digest,
        'provenance': 'colluder-knowledge'} for digest in created)
    # The current source envelope truthfully records that contact identity is a
    # controller instruction, not an authenticated peer observation.  Never
    # turn that caller-selected label into a measured creator edge.
    constraints['nf_pair_edges'].append({
        'nf_hex32': input_nf, 'tuple_sha256': created,
        'provenance': 'colluder-knowledge'})
    before_contact_value = codec.assignments(
        public, constraints)['joint_candidates']
    after_contact_value = before_contact_value
    if qualified:
        # This edge is not inferred from a caller label.  The issued invoice
        # and incoming decrypted receipt have the same prospectively bound
        # contact, the same authenticated amount, and the receipt tuple/CM
        # joins exactly one public output.  Require an actual lattice effect
        # before calling either value field modeled.
        incoming_contact = source_authority._binding[
            'contact_owner_components'][0]
        need(incoming_contact == receipts[0]['creator_owner_component']
             and incoming_contact ==
                source_authority._binding['contact_owner_components'][2]
             and invoices[0]['source_owner_component'] == incoming_contact
             and invoices[0]['amount_sompi'] == receipts[0]['amount_sompi'],
             'c1-qualified-contact-value-receipt-join')
        constraints['creator_edges'].append({
            'owner_component': incoming_contact,
            'slot_id': incoming_tuple,
            'provenance': 'colluder-knowledge',
        })
        after_contact_value = codec.assignments(
            public, constraints)['joint_candidates']
        need(0 < after_contact_value < before_contact_value,
             'c1-qualified-value-must-prune-candidates')
    codec.constraints(constraints, public)
    closure_records = source_records
    payload_bytes = sum(len(codec.encoded(row['value']))
                        for row in closure_records)
    attempt_id = capture_closure(value['closure'], closure_records,
                                 payload_bytes,
                                 value['cohort_sha256'], public['round'],
                                 'colluder-wallet-capture')
    inventory = {
        'schema': ('kpb-colluder-wallet-knowledge-inventory/v2'
                   if qualified else
                   'kpb-colluder-wallet-knowledge-inventory/v1'),
        'original_count': 1,
        'input_count': 1,
        'created_output_count': 2,
        'invoice_count': len(invoices),
        'decrypted_receipt_count': len(receipts),
        'retry_count': len(retries),
        'input_amount_sompi': original['input_amount_sompi'],
        'created_amounts_sompi': [row['amount_sompi']
                                  for row in created_outputs],
        'invoice_amounts_sompi': [row['amount_sompi'] for row in invoices],
        'receipt_amounts_sompi': [row['amount_sompi'] for row in receipts],
        'public_individual_amount_join_fields': 2 if qualified else 0,
        'source_bound_contact_value_authority': qualified,
        'candidate_count_before_contact_value': before_contact_value,
        'candidate_count_after_contact_value': after_contact_value,
        'candidate_pruned_count':
            before_contact_value - after_contact_value,
        'attempt_id': attempt_id,
        'cohort_sha256': value['cohort_sha256'],
        'direct_constraint_count': sum(len(constraints[name]) for name in
                                       ('input_edges', 'creator_edges',
                                        'pair_edges', 'nf_pair_edges')),
        'cryptographic_privacy_claim': False,
    }
    unmodeled_fields = ((
        *((('retry-history', 'retry_history[].source_and_value'),)
          if retries else ()),
    ) if qualified else (
        ('colluder-original', 'original.source'),
        ('colluder-invoices', 'invoices[].source'),
        ('colluder-invoices', 'invoices[].value'),
        ('colluder-decrypted-receipts', 'decrypted_receipts[].source'),
        ('colluder-decrypted-receipts', 'decrypted_receipts[].value'),
        *((('retry-history', 'retry_history[].source_and_value'),)
          if retries else ()),
    ))
    constraint_counts = {
        ('colluder-inputs-and-outputs',
         'original.value.input_and_created_outputs'): 4,
        ('colluder-original', 'original.value'): 4,
        **({
            ('colluder-original', 'original.source'): 1,
            ('colluder-invoices', 'invoices[].source'): 2,
            ('colluder-invoices', 'invoices[].value'): 1,
            ('colluder-decrypted-receipts',
             'decrypted_receipts[].source'): 2,
            ('colluder-decrypted-receipts',
             'decrypted_receipts[].value'): 1,
        } if qualified else {}),
        **({('retry-history', 'retry_history[].source_and_value'): 1}
           if not retries else {}),
    }
    return artifact_result(
        raw, 'colluder-wallet-capture', public['round'], constraints,
        COLLUDER_CATEGORIES, inventory,
        unmodeled_fields=unmodeled_fields,
        constraint_counts=constraint_counts)


def colluder_wallet(raw, public):
    """Legacy v1 adapter; a v2 body without its paired authority refuses."""
    value = canonical(raw)
    need(value.get('schema') != COLLUDER_QUALIFIED_META_SCHEMA,
         'c1-v2-requires-paired-source-authority')
    return _colluder_wallet_model(raw, public)


def colluder_wallet_v2_pair(raw_rounds, public_rounds, source_authorities):
    """Admit the exact two-round C1 view from consumed private authorities.

    The same global RunBinding/source closure is expected across both rounds.
    Per-round route, process, child-exit and contact/value capabilities must be
    distinct so one live capture cannot be replayed into both rounds.
    """
    need(type(raw_rounds) is list and len(raw_rounds) == 2
         and all(type(row) is bytes for row in raw_rounds)
         and type(public_rounds) is list and len(public_rounds) == 2
         and [row.get('round') for row in public_rounds] == [1, 2]
         and type(source_authorities) is list
         and len(source_authorities) == 2,
         'c1-v2-two-round-inputs')
    need(all(type(authority) is _C1ContactValueSourceAuthority
             for authority in source_authorities),
         'c1-source-authority-type')
    need(all(authority._live for authority in source_authorities),
         'c1-source-authority-replay')
    bindings = [authority._binding for authority in source_authorities]
    need([binding['round'] for binding in bindings] == [1, 2],
         'c1-source-authority-round-order')
    for field in ('capture_identity_sha256', 'source_closure_sha256',
                  'role_closure_sha256', 'role_launch_sha256',
                  'producer_closure_authority_sha256'):
        need(bindings[0][field] == bindings[1][field],
             'c1-common-' + field.replace('_sha256', '').replace('_', '-'))
    distinct_fields = (
        ('artifact_sha256', 'artifact'),
        ('financial_run_sha256', 'financial-run'),
        ('round_attempt_sha256', 'round-attempt'),
        ('round_cohort_sha256', 'round-cohort'),
        ('round_capture_plan_sha256', 'round-capture-plan'),
        ('round_projection_sha256', 'round-projection'),
        ('contact_value_authority_sha256', 'contact-value-authority'),
        ('stage_plan_sha256', 'stage-plan'),
        ('route_manifest_sha256', 'route-manifest'),
        ('route_source_sha256', 'route-source'),
        ('process_sha256', 'process'),
        ('child_exit_sha256', 'child-exit'),
    )
    for field, label in distinct_fields:
        need(bindings[0][field] != bindings[1][field],
             'c1-distinct-' + label)
    need(bindings[0]['contact_owner_components'] !=
            bindings[1]['contact_owner_components']
         and bindings[0]['operation_id_sha256'] !=
            bindings[1]['operation_id_sha256'],
         'c1-distinct-round-contact-and-operations')
    for raw_value, public, binding in zip(
            raw_rounds, public_rounds, bindings):
        expected_attempt = hashlib.sha256(
            b'KPB_CAPTURE_ATTEMPT_ID_V1\n'
            + binding['attempt_id'].encode()).hexdigest()
        need(binding['artifact_sha256'] ==
                hashlib.sha256(raw_value).hexdigest()
             and binding['round_projection_sha256'] ==
                public['projection_sha256']
             and binding['round_attempt_sha256'] == expected_attempt,
             'c1-paired-run-binding')
    return [_colluder_wallet_model(raw_value, public, authority)
            for raw_value, public, authority in zip(
                raw_rounds, public_rounds, source_authorities)]


def terminal(raw, public):
    """Admit complete selected terminal/retry/reorg/grouping history."""
    codec.batch(public); value = canonical(raw)
    # V2 is currently only a CONFIGURED0 source/control protocol. Its caller-
    # supplied grouping/link controls must never become measured privacy facts
    # or an actual terminal receipt through the v1 adapter.
    if (type(value) is dict
            and value.get('schema') == 'kpb-terminal-observer-history/v2'
            and value.get('mode') == 'CONFIGURED0_NETWORK_DISABLED'):
        need(False, 'terminal-v2-configured0-control-not-evidence')
    exact(value, ('schema', 'round', 'projection_sha256', 'cohort_sha256',
                  'mode', 'events', 'groups', 'amount_observations',
                  'retry_history', 'rejected_or_orphaned', 'reorg_history',
                  'cross_round_links', 'closure'), 'terminal-fields')
    need(value['schema'] == 'kpb-terminal-observer-history/v1'
         and value['round'] == public['round']
         and value['projection_sha256'] == public['projection_sha256']
         and value['mode'] in ('UNFUNDED_NETWORK_DISABLED',
                               'TESTNET_10_ACCEPTED'),
         'terminal-binding')
    word(value['cohort_sha256'], 'terminal-cohort')
    events = value['events']; allowed = {
        'candidate-constructed', 'native-full', 'submitted', 'accepted',
        'trial-closed'}
    for event in events:
        exact(event, ('sequence', 'kind', 'monotonic_ns',
                      'candidate_sha256', 'transaction_id_hex32', 'outcome'),
              'terminal-event-fields')
        need(event['kind'] in allowed and event['outcome'] in
             ('ok', 'refused', 'orphaned'), 'terminal-event-enum')
        word(event['candidate_sha256'], 'terminal-candidate')
        need(event['transaction_id_hex32'] is None or
             word(event['transaction_id_hex32']), 'terminal-transaction')
    _event_time_order(events)
    kinds = [event['kind'] for event in events]
    required = (['candidate-constructed', 'native-full', 'trial-closed']
                if value['mode'] == 'UNFUNDED_NETWORK_DISABLED' else
                ['candidate-constructed', 'submitted', 'accepted',
                 'trial-closed'])
    need(kinds == required
         and len({event['candidate_sha256'] for event in events}) == 1
         and all(event['outcome'] == 'ok' for event in events),
         'terminal-complete-mode-events')
    transaction_ids = [event['transaction_id_hex32'] for event in events]
    if value['mode'] == 'UNFUNDED_NETWORK_DISABLED':
        need(all(identifier is None for identifier in transaction_ids),
             'terminal-unfunded-no-transaction')
    else:
        need(transaction_ids[0] is None
             and transaction_ids[1] is not None
             and transaction_ids[1:] == [transaction_ids[1]] * 3,
             'terminal-accepted-transaction-identity')

    constraints = codec.empty_constraints(); groups = value['groups']
    need(type(groups) is list and groups, 'terminal-groups')
    seen_nfs, seen_tuples, group_ids = [], [], set()
    for group in groups:
        exact(group, ('group_id_sha256', 'owner_component', 'nfs_hex32',
                      'tuple_sha256'), 'terminal-group-fields')
        group_id = word(group['group_id_sha256'], 'terminal-group-id')
        need(group_id not in group_ids, 'terminal-distinct-group-id')
        group_ids.add(group_id)
        owner = group['owner_component']
        if owner is not None:
            codec.owner(owner)
        nfs, tuples = group['nfs_hex32'], group['tuple_sha256']
        need(type(nfs) is list and type(tuples) is list and nfs and tuples
             and len(nfs) == len(set(nfs)) and len(tuples) == len(set(tuples))
             and all(nf in public['nfs_hex32'] for nf in nfs)
             and all(row in public['tuple_sha256'] for row in tuples),
             'terminal-group-members')
        seen_nfs.extend(nfs); seen_tuples.extend(tuples)
        if owner is not None:
            constraints['input_edges'].extend({
                'owner_component': owner, 'slot_id': nf,
                'provenance': 'direct-export'} for nf in nfs)
            constraints['creator_edges'].extend({
                'owner_component': owner, 'slot_id': row,
                'provenance': 'direct-export'} for row in tuples)
        if len(nfs) == 1 and len(tuples) == 2:
            constraints['nf_pair_edges'].append({
                'nf_hex32': nfs[0], 'tuple_sha256': tuples,
                'provenance': 'terminal-grouping'})
        elif len(tuples) == 2:
            constraints['pair_edges'].append({
                'tuple_sha256': tuples, 'provenance': 'pair-tag-export'})
    need(sorted(seen_nfs) == sorted(public['nfs_hex32'])
         and len(seen_nfs) == len(set(seen_nfs))
         and sorted(seen_tuples) == sorted(public['tuple_sha256'])
         and len(seen_tuples) == len(set(seen_tuples)),
         'terminal-complete-grouping')

    amounts = value['amount_observations']
    need(type(amounts) is list, 'terminal-amount-observation-array')
    # Public aggregate reserve/remaining/fee are parsed by public_projection.
    # Any individual amount observation needs a cross-artifact inference rule;
    # until that rule exists it must not be silently called modeled.
    need(amounts == [], 'terminal-individual-amount-linkage-unmodeled')

    retries = value['retry_history']
    need(type(retries) is list, 'terminal-retry-array')
    retry_ids = set(); retry_statuses = {}
    for retry in retries:
        exact(retry, ('attempt_id', 'outcome', 'candidate_sha256'),
              'terminal-retry-fields')
        need(type(retry['attempt_id']) is str
             and re.fullmatch('[A-Za-z0-9_-]{1,128}', retry['attempt_id'])
             and retry['attempt_id'] not in retry_ids
             and retry['outcome'] in ('refused', 'orphaned', 'disconnected')
             and word(retry['candidate_sha256']), 'terminal-retry-record')
        retry_ids.add(retry['attempt_id'])
        if retry['outcome'] != 'disconnected':
            status = ('rejected' if retry['outcome'] == 'refused'
                      else 'orphaned')
            need(retry['candidate_sha256'] not in retry_statuses,
                 'terminal-distinct-retry-candidate')
            retry_statuses[retry['candidate_sha256']] = status
    rejected = value['rejected_or_orphaned']
    need(type(rejected) is list, 'terminal-rejected-array')
    rejected_statuses = {}
    for row in rejected:
        exact(row, ('candidate_sha256', 'status'),
              'terminal-rejected-fields')
        need(word(row['candidate_sha256'])
             and row['candidate_sha256'] not in rejected_statuses
             and row['status'] in ('rejected', 'orphaned'),
             'terminal-rejected-record')
        rejected_statuses[row['candidate_sha256']] = row['status']
    need(rejected_statuses == retry_statuses,
         'terminal-retry-rejection-history-equality')
    reorgs = value['reorg_history']
    need(type(reorgs) is list, 'terminal-reorg-array')
    for row in reorgs:
        exact(row, ('old_head_hex32', 'new_head_hex32', 'depth'),
              'terminal-reorg-fields')
        word(row['old_head_hex32']); word(row['new_head_hex32'])
        need(row['old_head_hex32'] != row['new_head_hex32']
             and natural(row['depth'], 'terminal-reorg-depth') > 0,
             'terminal-positive-reorg-depth')
    need(retries == [] and rejected == [] and reorgs == [],
         'terminal-alternate-history-unmodeled')

    cross = value['cross_round_links']
    need(type(cross) is list, 'terminal-cross-round-array')
    checked_cross = []
    for link in cross:
        exact(link, ('input_round', 'nf_hex32', 'output_round',
                     'tuple_sha256', 'provenance'),
              'terminal-cross-round-fields')
        need(link['input_round'] == public['round']
             and link['output_round'] in (1, 2)
             and link['input_round'] != link['output_round']
             and word(link['nf_hex32'])
             and word(link['tuple_sha256'])
             and link['provenance'] == 'terminal-linkage',
             'terminal-cross-round-record')
        checked_cross.append(link)
    codec.constraints(constraints, public)
    closure_records = (
        [{'stream': 'event', 'value': row} for row in events]
        + [{'stream': 'group', 'value': row} for row in groups]
        + [{'stream': 'amount-observation', 'value': row}
           for row in amounts]
        + [{'stream': 'retry', 'value': row} for row in retries]
        + [{'stream': 'rejected-or-orphaned', 'value': row}
           for row in rejected]
        + [{'stream': 'reorg', 'value': row} for row in reorgs]
        + [{'stream': 'cross-round-link', 'value': row}
           for row in checked_cross])
    payload_bytes = sum(len(codec.encoded(row['value']))
                        for row in closure_records)
    attempt_id = capture_closure(value['closure'], closure_records,
                                 payload_bytes,
                                 value['cohort_sha256'], public['round'],
                                 'terminal-history')
    inventory = {
        'schema': 'kpb-terminal-history-inventory/v1',
        'projection_sha256': public['projection_sha256'],
        'event_count': len(events),
        'group_count': len(groups),
        'individual_amount_observation_count': len(amounts),
        'retry_count': len(retries),
        'rejected_or_orphaned_count': len(rejected),
        'reorg_count': len(reorgs),
        'cross_round_link_count': len(checked_cross),
        'attempt_id': attempt_id,
        'cohort_sha256': value['cohort_sha256'],
        'direct_constraint_count': sum(len(constraints[name]) for name in
                                       ('input_edges', 'creator_edges',
                                        'pair_edges', 'nf_pair_edges')),
    }
    return artifact_result(raw, 'terminal-history', public['round'],
                           constraints, TERMINAL_CATEGORIES, inventory,
                           terminal=True,
                           cross_round_links=checked_cross,
                           unmodeled_fields=(
                               ('terminal-grouping',
                                'groups[].owner_nf_tuple_membership'),
                               ('terminal-grouping', 'cross_round_links[]'),
                           ),
                           constraint_counts={
                               ('rejected-or-orphaned-candidates',
                                'rejected_or_orphaned[].candidate_sha256_and_status'):
                                   1,
                               ('reorg-history',
                                'reorg_history[].heads_and_depth'): 1,
                           })


def _merge_constraints(public, artifacts):
    merged = codec.empty_constraints()
    for artifact in artifacts:
        current = codec.constraints(artifact['constraints'], public)
        for name in ('input_edges', 'creator_edges', 'pair_edges',
                     'nf_pair_edges'):
            merged[name].extend(edge for edge in current[name]
                                if edge not in merged[name])
        merged['individual_delta_exports'] += \
            current['individual_delta_exports']
    return codec.constraints(merged, public)


def derive_view_artifacts(public, artifacts):
    """Derive every view, exact union and constraint lattice from typed kinds.

    There is no caller-selected public/dispatcher/corrupt partition.  Exactly
    one admitted artifact of every frozen kind is required for a round.
    """
    codec.batch(public)
    need(type(artifacts) is list and len(artifacts) == len(ARTIFACT_CATEGORIES),
         'complete-typed-artifact-array')
    by_kind = {}; identities = set()
    expected_fields = ('schema', 'kind', 'round', 'artifact_sha256',
                       'constraints', 'categories', 'inventory',
                       'leakage_ledger',
                       'terminal_modeled', 'cross_round_links')
    for artifact in artifacts:
        exact(artifact, expected_fields, 'typed-artifact-fields')
        kind = artifact['kind']
        need(artifact['schema'] == 'kpb-typed-capture-artifact-model/v2'
             and kind in ARTIFACT_CATEGORIES and kind not in by_kind
             and artifact['round'] == public['round']
             and artifact['categories'] == sorted(ARTIFACT_CATEGORIES[kind])
             and type(artifact['inventory']) is dict
             and type(artifact['inventory'].get('schema')) is str
             and type(artifact['terminal_modeled']) is bool
             and type(artifact['cross_round_links']) is list,
             'typed-artifact-attribution')
        identity = word(artifact['artifact_sha256'], 'artifact-hash')
        need(identity not in identities, 'distinct-artifact-hash')
        identities.add(identity); by_kind[kind] = artifact
        codec.constraints(artifact['constraints'], public)
        _validate_leakage_ledger(kind, artifact['leakage_ledger'])
    need(set(by_kind) == set(ARTIFACT_CATEGORIES)
         and by_kind['terminal-history']['terminal_modeled'] is True
         and all(not value['terminal_modeled'] for key, value in by_kind.items()
                 if key != 'terminal-history'),
         'exact-artifact-kind-set')
    bound_kinds = ('terminal-history', 'dispatcher-capture',
                   'corrupt-server-capture', 'colluder-wallet-capture')
    attempt_ids = {by_kind[kind]['inventory'].get('attempt_id')
                   for kind in bound_kinds}
    cohorts = {by_kind[kind]['inventory'].get('cohort_sha256')
               for kind in bound_kinds}
    need(len(attempt_ids) == len(cohorts) == 1
         and None not in attempt_ids and None not in cohorts,
         'common-attempt-and-cohort-binding')

    view_kinds = {
        'public': ('public-projection', 'terminal-history'),
        'dispatcher': ('public-projection', 'terminal-history',
                       'dispatcher-capture'),
        'corrupt-server-plus-wallet': (
            'public-projection', 'terminal-history',
            'corrupt-server-capture', 'colluder-wallet-capture'),
        'union': ('public-projection', 'terminal-history',
                  'dispatcher-capture', 'corrupt-server-capture',
                  'colluder-wallet-capture'),
    }
    expected_categories = {
        'public': PUBLIC_CATEGORIES,
        'dispatcher': PUBLIC_CATEGORIES | DISPATCHER_CATEGORIES,
        'corrupt-server-plus-wallet': (
            PUBLIC_CATEGORIES | SERVER_CATEGORIES | COLLUDER_CATEGORIES),
        'union': (PUBLIC_CATEGORIES | DISPATCHER_CATEGORIES
                  | SERVER_CATEGORIES | COLLUDER_CATEGORIES),
    }
    views = {}
    for name, kinds in view_kinds.items():
        selected = [by_kind[kind] for kind in kinds]
        categories = sorted({category for artifact in selected
                             for category in artifact['categories']})
        need(set(categories) == expected_categories[name],
             'exact-' + name + '-categories')
        category_counts = {category: sum(
            category in artifact['categories'] for artifact in selected)
            for category in categories}
        leakage_coverage = {}
        for category in categories:
            rows = [(artifact, row) for artifact in selected
                    for row in artifact['leakage_ledger']
                    if row['category'] == category]
            need(rows, 'nonempty-category-field-ledger-' + category)
            leakage_coverage[category] = {
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
        constraints = _merge_constraints(public, selected)
        artifact_ids = [artifact['artifact_sha256'] for artifact in selected]
        unmodeled_inventory = _private_unmodeled_inventory(name, selected)
        unmodeled_artifact_count = len({
            artifact['artifact_sha256'] for artifact in selected
            if any(row['status'] == 'unmodeled'
                   for row in artifact['leakage_ledger'])})
        need(unmodeled_inventory['missing_artifact_count'] == 0
             and unmodeled_inventory['unmodeled_artifact_count'] ==
                unmodeled_artifact_count
             and unmodeled_inventory['unmodeled_field_count'] == sum(
                coverage['unmodeled_fields']
                for coverage in leakage_coverage.values()),
             'exact-private-unmodeled-inventory-' + name)
        views[name] = {
            'artifact_sha256': artifact_ids,
            'artifact_set_sha256': hashlib.sha256(
                codec.encoded(sorted(artifact_ids))).hexdigest(),
            'categories': categories,
            'category_counts': category_counts,
            'leakage_coverage': leakage_coverage,
            'unmodeled_artifact_count': unmodeled_artifact_count,
            'unmodeled_inventory': unmodeled_inventory,
            'constraints': constraints,
            'constraint_set_sha256': hashlib.sha256(
                codec.encoded(constraints)).hexdigest(),
        }

    def subset(weaker, stronger):
        for name in ('input_edges', 'creator_edges', 'pair_edges',
                     'nf_pair_edges'):
            if any(edge not in stronger[name] for edge in weaker[name]):
                return False
        return (weaker['individual_delta_exports']
                <= stronger['individual_delta_exports'])

    artifact_lattice = all(set(views[weaker]['artifact_sha256']).issubset(
        views[stronger]['artifact_sha256']) for weaker, stronger in (
            ('public', 'dispatcher'),
            ('public', 'corrupt-server-plus-wallet'),
            ('dispatcher', 'union'),
            ('corrupt-server-plus-wallet', 'union')))
    constraint_lattice = all(subset(views[weaker]['constraints'],
                                    views[stronger]['constraints'])
        for weaker, stronger in (
            ('public', 'dispatcher'),
            ('public', 'corrupt-server-plus-wallet'),
            ('dispatcher', 'union'),
            ('corrupt-server-plus-wallet', 'union')))
    need(artifact_lattice and constraint_lattice,
         'exact-view-lattice')
    return {
        'schema': 'kpb-derived-four-view-inventory/v1',
        'round': public['round'],
        'attempt_id': next(iter(attempt_ids)),
        'cohort_sha256': next(iter(cohorts)),
        'views': views,
        'lattice_attestation': {
            'exact_union_artifact_set': True,
            'exact_union_constraints': True,
            'candidate_subset_lattice_verified': False,
            'full_workload_subset_lattice_verified': False,
        },
    }


def _private_completion_coverage_summary(public_rounds, artifact_rounds):
    """Recompute the four fixed views for the capsule-internal gate.

    This summary contains no leaf path, body or identity.  It is not a public
    receipt and cannot authorize coverage; the selected child may only pass it
    to ``require_private_completion_coverage`` before returning its separately
    issued opaque completion capability.
    """
    need(type(public_rounds) is list and len(public_rounds) == 2
         and type(artifact_rounds) is list and len(artifact_rounds) == 2,
         'private-completion-two-rounds')
    view_kinds = {
        'public': ('public-projection', 'terminal-history'),
        'dispatcher': ('public-projection', 'terminal-history',
                       'dispatcher-capture'),
        'corrupt-server-plus-wallet': (
            'public-projection', 'terminal-history',
            'corrupt-server-capture', 'colluder-wallet-capture'),
        'union': ('public-projection', 'terminal-history',
                  'dispatcher-capture', 'corrupt-server-capture',
                  'colluder-wallet-capture'),
    }
    need(tuple(view_kinds) == codec.VIEWS,
         'private-completion-fixed-view-order')
    derived_rounds = []
    by_kind_rounds = []
    for number, (public, artifacts) in enumerate(
            zip(public_rounds, artifact_rounds), 1):
        need(public['round'] == number and type(artifacts) is list
             and len(artifacts) == len(ARTIFACT_CATEGORIES),
             'private-completion-exact-round-leaves')
        derived_rounds.append(derive_view_artifacts(public, artifacts))
        by_kind_rounds.append({artifact['kind']: artifact
                               for artifact in artifacts})
    exact_ten = (sum(len(artifacts) for artifacts in artifact_rounds) == 10
                 and all(set(by_kind) == set(ARTIFACT_CATEGORIES)
                         for by_kind in by_kind_rounds))
    exhaustive_lattice = all(
        row['lattice_attestation']['exact_union_artifact_set']
        and row['lattice_attestation']['exact_union_constraints']
        for row in derived_rounds)
    field_order = tuple(sorted(
        (kind, category, field_path)
        for kind, categories in ARTIFACT_LEAKAGE_FIELDS.items()
        for category, paths in categories.items()
        for field_path in paths))
    field_bits = {key: index for index, key in enumerate(field_order)}
    terminal_artifacts = [by_kind['terminal-history']
                          for by_kind in by_kind_rounds]
    views = []
    for view_index, view in enumerate(codec.VIEWS):
        round_models = [codec.assignments(
            public_rounds[index],
            derived_rounds[index]['views'][view]['constraints'])
            for index in range(2)]
        workload = workload_candidates(round_models, terminal_artifacts)
        candidate_count = workload['full_workload_candidates']
        need(type(candidate_count) is int
             and 1 <= candidate_count <= 540 * 540,
             'private-completion-bounded-candidates')
        inventories = [derived['views'][view]['unmodeled_inventory']
                       for derived in derived_rounds]
        missing_count = sum(row['missing_artifact_count']
                            for row in inventories)
        unmodeled_count = sum(row['unmodeled_field_count']
                              for row in inventories)
        source_assumption_mask = 0
        for by_kind in by_kind_rounds:
            for kind in view_kinds[view]:
                for ledger in by_kind[kind]['leakage_ledger']:
                    if ledger['status'] == 'source_assumption_covered':
                        source_assumption_mask |= 1 << field_bits[(
                            kind, ledger['category'], ledger['field_path'])]
        all_covered = missing_count == 0 and unmodeled_count == 0
        views.append({
            'view_index': view_index,
            'candidate_count': candidate_count,
            'all_candidate_edges_covered': all_covered,
            'missing_artifact_count': missing_count,
            'unmodeled_field_count': unmodeled_count,
            'source_assumption_mask': source_assumption_mask,
        })
    completion_ready = (exact_ten and exhaustive_lattice
                        and all(row['all_candidate_edges_covered']
                                for row in views))
    return {
        'schema': 'kpb-private-four-view-coverage-summary/v1',
        'views': views,
        'exact_ten_typed_leaves': exact_ten,
        'exhaustive_lattice': exhaustive_lattice,
        'completion_ready': completion_ready,
    }


def _private_completion_phase_partition(public_rounds, artifact_rounds):
    """Partition open rows by the phase in which evidence can exist.

    This is a private diagnostic structure, not authority. It preserves the
    original all-rows summary unchanged and never calls a deferred row covered.
    Only the exact accepted-chain state/context families are Step-3 rows; every
    other open row remains a Step-2 blocker.
    """
    summary = _private_completion_coverage_summary(
        public_rounds, artifact_rounds)
    deferred_keys = {
        ('context-identities',
         'context.accepted_chain_outpoint_and_external_history_linkage'),
        ('state-transition',
         'state.accepted_chain_state_and_outpoint_continuity'),
    }
    deferred_requirement = \
        'STEP3_ACCEPTED_CHAIN_STATE_AND_OUTPOINT_HISTORY_AUTHORITY'
    expected_deferred = {
        (round_number, 'public-projection', category, field_path)
        for round_number in (1, 2)
        for category, field_path in deferred_keys
    }
    derived_rounds = [
        derive_view_artifacts(public, artifacts)
        for public, artifacts in zip(public_rounds, artifact_rounds)
    ]
    views = []
    for view_index, view in enumerate(codec.VIEWS):
        step2_open = []
        deferred_step3 = []
        for round_number, derived in enumerate(derived_rounds, 1):
            inventory = derived['views'][view]['unmodeled_inventory']
            for artifact in inventory['unmodeled_artifacts']:
                for field in artifact['fields']:
                    row = {
                        'round': round_number,
                        'artifact_kind': artifact['raw_typed_leaf_kind'],
                        'category': field['category'],
                        'field_path': field['field_path'],
                        'proposed_resolution': field['proposed_resolution'],
                        'mapping_dependent': field['mapping_dependent'],
                        'evidence_requirement':
                            field['evidence_requirement'],
                        'coverage_relabel_allowed':
                            field['coverage_relabel_allowed'],
                    }
                    key = (field['category'], field['field_path'])
                    if (artifact['raw_typed_leaf_kind'] ==
                            'public-projection'
                            and key in deferred_keys
                            and field['evidence_requirement'] ==
                                deferred_requirement):
                        deferred_step3.append(row)
                    else:
                        step2_open.append(row)
        order = lambda row: (row['round'], row['artifact_kind'],
                             row['category'], row['field_path'])
        step2_open.sort(key=order)
        deferred_step3.sort(key=order)
        need({order(row) for row in deferred_step3} == expected_deferred
             and len(deferred_step3) == len(expected_deferred)
             and all(row['proposed_resolution'] ==
                         'direct_constraint_pending_source_authority'
                     and row['mapping_dependent'] is False
                     and row['coverage_relabel_allowed'] is False
                     for row in deferred_step3),
             'private-completion-exact-step3-deferral')
        views.append({
            'view_index': view_index,
            'step2_open_fields': step2_open,
            'deferred_step3_open_fields': deferred_step3,
        })
    return {
        'schema': 'kpb-private-completion-phase-partition/v1',
        'coverage_summary': summary,
        'views': views,
    }


def _private_open_fields_by_missing_authority(public_rounds,
                                              artifact_rounds):
    """Group every still-open union field by its exact missing evidence.

    This child-internal diagnostic has no authority semantics.  It enumerates
    the two rounds separately so a field cannot disappear through set
    deduplication or a public aggregate count.
    """
    need(type(public_rounds) is list and len(public_rounds) == 2
         and type(artifact_rounds) is list and len(artifact_rounds) == 2,
         'private-open-field-two-rounds')
    grouped = {}
    for round_number, (public, artifacts) in enumerate(
            zip(public_rounds, artifact_rounds), 1):
        derived = derive_view_artifacts(public, artifacts)
        inventory = derived['views']['union']['unmodeled_inventory']
        for artifact in inventory['unmodeled_artifacts']:
            for field in artifact['fields']:
                requirement = field['evidence_requirement']
                grouped.setdefault(requirement, []).append({
                    'round': round_number,
                    'artifact_kind': artifact['raw_typed_leaf_kind'],
                    'category': field['category'],
                    'field_path': field['field_path'],
                    'proposed_resolution': field['proposed_resolution'],
                    'mapping_dependent': field['mapping_dependent'],
                })
    groups = [{
        'missing_authority_or_assumption': requirement,
        'open_fields': sorted(rows, key=lambda row: (
            row['round'], row['artifact_kind'], row['category'],
            row['field_path'])),
    } for requirement, rows in sorted(grouped.items())]
    return {
        'schema': 'kpb-private-open-fields-by-missing-authority/v1',
        'groups': groups,
        'open_field_occurrence_count': sum(
            len(group['open_fields']) for group in groups),
        'authorizes_coverage': False,
    }


_PRIVATE_COMPLETION_AUTHORITY_CONSTRUCTOR = object()


class _PrivateCompletionCoverageAuthority:
    """One-shot child-memory proof of the exact private coverage gate.

    This value has no serialization, public receipt, count, or boolean
    projection.  The selected observer must retain it in the isolated child
    and consume it immediately before deriving predictions.
    """
    __slots__ = ('_input_identity', '_live')

    def __init__(self, constructor, input_identity):
        need(constructor is _PRIVATE_COMPLETION_AUTHORITY_CONSTRUCTOR
             and word(input_identity),
             'private-completion-authority-constructor')
        self._input_identity = input_identity
        self._live = True


def _private_completion_input_identity(public_rounds, artifact_rounds,
                                       summary):
    return hashlib.sha256(codec.encoded({
        'public_projection_sha256': [
            public['projection_sha256'] for public in public_rounds],
        'typed_leaf_sha256': [
            [artifact['artifact_sha256'] for artifact in artifacts]
            for artifacts in artifact_rounds],
        'coverage_summary': summary,
    })).hexdigest()


def require_private_completion_coverage(public_rounds, artifact_rounds):
    summary = _private_completion_coverage_summary(
        public_rounds, artifact_rounds)
    need(summary['completion_ready'],
         'private-completion-unmodeled-or-missing')
    return _PrivateCompletionCoverageAuthority(
        _PRIVATE_COMPLETION_AUTHORITY_CONSTRUCTOR,
        _private_completion_input_identity(
            public_rounds, artifact_rounds, summary))


def consume_private_completion_coverage_for_prediction(
        authority, public_rounds, artifact_rounds):
    """Burn the private gate immediately before prediction derivation.

    Public counts, booleans, dictionaries, opaque nonces, and empirical
    receipts are intentionally not accepted.  Recompute the full four-view
    gate from the same ten typed leaves so a moved or stale authority cannot
    authorize different prediction inputs.
    """
    need(type(authority) is _PrivateCompletionCoverageAuthority,
         'private-completion-authority-type')
    need(authority._live, 'private-completion-authority-replay')
    summary = _private_completion_coverage_summary(
        public_rounds, artifact_rounds)
    need(summary['completion_ready'] and
         authority._input_identity == _private_completion_input_identity(
             public_rounds, artifact_rounds, summary),
         'private-completion-authority-binding')
    authority._live = False
    # This stays inside the isolated child.  It is not a public receipt and
    # must not be serialized or substituted for the opaque child completion.
    return summary


def workload_candidates(round_models, terminal_artifacts):
    """Enumerate the exact two-round/terminal join before seeing truth.

    Cross-round constraints come only from the two admitted terminal-history
    models.  A caller cannot pass a selected link subset.  ``joint`` contains
    canonical round-model candidate indices; the commitment also binds the
    complete canonical per-round vectors those indices address.
    """
    need(type(round_models) is list and len(round_models) == 2
         and [model['public']['round'] for model in round_models] == [1, 2],
         'workload-two-round-models')
    need(type(terminal_artifacts) is list and len(terminal_artifacts) == 2,
         'workload-two-terminal-artifacts')
    for model in round_models:
        # Recompute from the sealed source constraints; never trust candidate
        # arrays imported from a worker.
        checked = codec.assignments(model['public'], model['constraints'])
        need(checked == model, 'workload-recomputed-round-model')
    checked_links = []
    for round_number, artifact in enumerate(terminal_artifacts, 1):
        need(type(artifact) is dict
             and artifact.get('schema') ==
                 'kpb-typed-capture-artifact-model/v2'
             and artifact.get('kind') == 'terminal-history'
             and artifact.get('round') == round_number
             and artifact.get('terminal_modeled') is True
             and artifact.get('categories') == sorted(TERMINAL_CATEGORIES)
             and type(artifact.get('cross_round_links')) is list,
             'workload-exact-terminal-artifact')
        model_constraints = round_models[round_number - 1]['constraints']
        terminal_constraints = artifact['constraints']
        need(artifact['inventory'].get('projection_sha256') ==
                 round_models[round_number - 1]['public'][
                     'projection_sha256']
             and all(edge in model_constraints[name]
                     for name in ('input_edges', 'creator_edges',
                                  'pair_edges', 'nf_pair_edges')
                     for edge in terminal_constraints[name])
             and terminal_constraints['individual_delta_exports'] <=
                 model_constraints['individual_delta_exports'],
             'workload-terminal-constraints-in-round-model')
        checked_links.extend(artifact['cross_round_links'])
    normalized_links = []
    for link in checked_links:
        exact(link, ('input_round', 'nf_hex32', 'output_round',
                     'tuple_sha256', 'provenance'),
              'workload-cross-round-fields')
        input_index, output_index = link['input_round'] - 1, link['output_round'] - 1
        need(input_index != output_index
             and link['nf_hex32'] in round_models[input_index]['public']['nfs_hex32']
             and link['tuple_sha256'] in round_models[output_index]['public']['tuple_sha256']
             and link['provenance'] == 'terminal-linkage',
             'workload-cross-round-binding')
        normalized_links.append((input_index, output_index, link))
    canonical_links = sorted(
        (link for _, _, link in normalized_links),
        key=lambda link: (link['input_round'], link['nf_hex32'],
                          link['output_round'], link['tuple_sha256'],
                          link['provenance']))
    need(len(canonical_links) == len({codec.encoded(link)
                                     for link in canonical_links}),
         'workload-distinct-cross-round-links')
    normalized_links = [
        (link['input_round'] - 1, link['output_round'] - 1, link)
        for link in canonical_links]
    joint = []; honest_vector_swap_candidates = 0
    for left_index, left in enumerate(round_models[0]['joint']):
      for right_index, right in enumerate(round_models[1]['joint']):
        candidates = (left, right)
        valid = True
        for input_index, output_index, link in normalized_links:
            input_model = round_models[input_index]['public']
            output_model = round_models[output_index]['public']
            input_slot = input_model['nfs_hex32'].index(link['nf_hex32'])
            output_slot = output_model['tuple_sha256'].index(link['tuple_sha256'])
            if (candidates[input_index]['inputs'][input_slot]
                    != candidates[output_index]['outputs'][output_slot]):
                valid = False; break
        if not valid:
            continue
        joint.append([left_index, right_index])
        # This is a public structural count, not truth scoring: count vectors
        # in which both honest labels occur in both rounds.  The isolated
        # scorer still decides whether the actual consistent 0/2 swap remains.
        labels = {owner for candidate in candidates
                  for owner in (*candidate['inputs'], *candidate['outputs'])}
        honest_vector_swap_candidates += int({0, 2}.issubset(labels))
    round_commitment = hashlib.sha256(codec.encoded({
        'schema': 'kpb-canonical-round-candidate-vectors/v1',
        'rounds': [{'public': model['public'],
                    'constraints': model['constraints'],
                    'joint': model['joint']}
                   for model in round_models],
    })).hexdigest()
    commitment = hashlib.sha256(codec.encoded({
        'schema': 'kpb-full-workload-candidate-set/v1',
        'round_candidate_set_commitment_sha256': round_commitment,
        'cross_round_links': canonical_links,
        'joint': joint,
    })).hexdigest()
    return {'schema': 'kpb-two-round-candidate-join/v1',
            'round_candidate_counts': [len(model['joint'])
                                       for model in round_models],
            'cross_round_link_count': len(canonical_links),
            'cross_round_constraints_modeled': True,
            'terminal_constraints_modeled': True,
            'joint': joint,
            'workload_joint_candidates': len(joint),
            'full_workload_candidates': len(joint),
            'round_candidate_set_commitment_sha256': round_commitment,
            'candidate_set_commitment_sha256': commitment,
            'honest_vector_swap_structural_candidates':
                honest_vector_swap_candidates,
            'truth_scored': False}
