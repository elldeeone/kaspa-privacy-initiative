#!/usr/bin/env python3
"""Frozen, nonauthorizing feasibility-aware Observer-v4 byte grammar.

The bytes name required families and pinned historical provenance.  They are
not proof that any family applies.  Every family deliberately records a
missing live applicability authority, and this module exposes no encoder or
authority mint.
"""

import hashlib
import json
import struct

import privacy_measurement_output_abi as v3


VERSION = 4
MAGIC = b'KPBOABI4'
SECTION_MAGIC = b'KPBOAV41'
SECTION_OFFSET = v3.OBSERVER_OUTPUT_PADDED_BYTES
SECTION_BYTES_COUNT = 640
USED_BYTES = SECTION_OFFSET + SECTION_BYTES_COUNT
EXACT_BYTES = 155648
FLAGS = 3  # immutable-v3-prefix | nonauthorizing-requirement-registry
MODEL_IDENTITY = (
    'ca2328efdc5b4508f57cb37b4d223e520f476dd747720bd2c2691f02ca930162')

PINNED_S4 = {
    'historical_setup_source':
        'ccd4e28a728cbf8ffd6db0dd0fa81a6200c0c6e4ecb20242435f00e5b6aae19e',
    'matrix':
        'd8e94558a7b9e3a5cc6187a894cb7f141d85d3c6d862b6a628561a24c4bfdd31',
    'proving_key':
        '1c2d02992ae89810b8a95ede7bf38aefd503f4984e7b82b27db452141752339a',
    'verification_key':
        '8d5738e3726611b07bedec944dc26d8458b728a7d18c1fecf2ad6638aa1cd119',
}
PINNED_S12 = {
    'historical_setup_source':
        '3ff31adfc6f2666ac53606ecf60336366d850951fda22a38b7445262f380d829',
    'current_source':
        '04adfd77d3b97f60efe6c4547cda583856ea7f7be4c9538f4237330ac137a9d7',
    'matrix_equivalence_receipt':
        '52ca327ac2d3dd2921c0aa913060f8a97f127d81c5d125c1892dc989853ac692',
    'matrix':
        'c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab',
    'canonical_proving_key':
        '170431eee45f57ff6a3dc278d96f8a824145b8ca9ded04088a662983a449e945',
    'compressed_proving_key':
        '4a3d0ac3143ecc32a875af8107c923b851036363a68a8a744b97c74d0a3879ff',
    'verification_key':
        '2ca01e24f64b764e0470e67ff4fe183ed9e6d4a2d0b17e77887499c7ed0de102',
    'independent_verifier':
        'c1805cfe7ae9b2db7d58fd58727b57e92a0fec866506cd720fbd59242359131f',
}
PINNED_S5 = {
    'historical_executable':
        '6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff',
}


def _family(code, name, mode, prerequisites=(), requirements=None,
            pinned_provenance_count=0):
    return {
        'code': code,
        'name': name,
        'mode': mode,
        'prerequisites': list(prerequisites),
        'requirements': requirements or {},
        'pinned_provenance_count': pinned_provenance_count,
        'applicability_status': 'MISSING_LIVE_AUTHORITY',
        'applicability_identity': None,
    }


FAMILY_ROWS = (
    _family(1, 'S4_OUTPUT_GROTH16', 'independent', requirements={
        'rounds': 2, 'proofs_per_round': 6,
        'exact_statement_binding': True,
        'independent_randomizers': 12,
        'honest_crs_authority_required': True,
        'historical_local_setup_eligible': False,
    }, pinned_provenance_count=4),
    _family(2, 'S12_AGGREGATE_GROTH16', 'independent', requirements={
        'rounds': 2, 'proofs': 2, 'abc_only': True,
        'raw_b1_opened': False, 'fresh_authenticated_r_s': True,
        'requires': ['S8', 'S10', 'S11'],
        'historical_local_setup_eligible': False,
        'current_to_historical_matrix_equivalence_only': True,
    }, pinned_provenance_count=8),
    _family(3, 'S5_CRYPTOBOX_CONFIDENTIALITY', 'independent', requirements={
        'exact_ciphertext_bytes': 264,
        'honest_producer_required': True,
        'fresh_nonreused_ephemeral_secret_required': True,
        'decrypt_side_channel_absence_required': True,
        'key_privacy_included': False,
    }, pinned_provenance_count=1),
    _family(4, 'S6A_HIDDEN_DELIVERY_PRF', 'independent', requirements={
        'one_use_delivery_indices': True,
        'poison_on_abort': True,
        'forbidden_identifier_view_absence_authority_required': True,
    }),
    _family(5, 'S7_NULLIFIER_HMAC_PRF', 'independent', requirements={
        'seed_nonexposure_authority_required': True,
        'rust_python_circuit_message_equality_authority_required': True,
    }),
    _family(6, 'S5_AND_S6A_STRICT_CONJUNCTION', 'strict-conjunction',
            ('S5_CRYPTOBOX_CONFIDENTIALITY', 'S6A_HIDDEN_DELIVERY_PRF'), {
                'same_honest_producer_instance_required': True,
                'same_ciphertext_profile_required': True,
            }),
    _family(7, 'JOINT_S6A_S7_HMAC', 'joint-same-source-game',
            ('S6A_HIDDEN_DELIVERY_PRF', 'S7_NULLIFIER_HMAC_PRF'), {
                'same_owner_seed_required': True,
                'delivery_and_nullifier_domains_joint': True,
                'independent_label_shortcut_forbidden': True,
            }),
    _family(8, 'NARROW_S14_MPC_REALIZATION', 'independent', requirements={
        'corruption': 'P1_STATIC_ACTIVE_PLUS_C1_PASSIVE',
        'abort_exposed': True,
        'aggregate_groth16_included': False,
        'mapping_privacy_included': False,
        'timing_retry_contact_included': False,
    }),
    _family(9, 'NARROW_S14_AND_S12_CONJUNCTION', 'strict-conjunction',
            ('NARROW_S14_MPC_REALIZATION', 'S12_AGGREGATE_GROTH16'), {
                's14_does_not_subsume_s12': True,
            }),
    _family(10, 'COUNTERFACTUAL_FULL_W1_CLOSE', 'atomic-same-instance',
            requirements={
                'source_owned_w0_truth_required': True,
                'authenticated_c1_residual_required': True,
                'accepted_public_lineage_required': True,
                'full_w1_witness_required': True,
                'runtime_close_descendants_required': True,
                'identity_equality_is_not_authority': True,
            }),
    _family(11, 'ALL_FRESH_TRIAL_HISTORY_DIRECT_EMPIRICAL',
            'exhaustive-fresh-trial-history', requirements={
                'every_failed_fresh_trial_required': True,
                'exactly_one_final_success_required': True,
                'same_trial_retry_forbidden': True,
                'outer_ledger_authority_required': True,
            }),
    _family(12, 'SOURCE_RUNTIME_FRESHNESS', 'source-runtime-freshness',
            requirements={
                'selected_source_artifacts_required': True,
                'selected_runtime_artifacts_required': True,
                'actual_consumption_authority_required': True,
                'matching_digest_is_not_authority': True,
            }),
)

REGISTRY_PREIMAGE = {
    'schema': 'kpb-feasibility-aware-observer-v4-family-registry/v1',
    'research_model_sha256': MODEL_IDENTITY,
    'families': list(FAMILY_ROWS),
    'pinned_historical_provenance': {
        's4': PINNED_S4,
        's12': PINNED_S12,
        's5': PINNED_S5,
    },
    'boundary': {
        'serialized_body_is_authority': False,
        'historical_or_local_crs_is_eligible': False,
        'live_authority_required_for_every_family': True,
        'same_literal_or_digest_shortcut': False,
        'v3_semantics_mutated': False,
    },
}
REGISTRY_IDENTITY = hashlib.sha256((json.dumps(
    REGISTRY_PREIMAGE, sort_keys=True, separators=(',', ':'))
    + '\n').encode()).hexdigest()

SPEC_PREIMAGE = {
    'schema': 'kpb-measurement-private-output-abi/v4',
    'role': 'observer',
    'magic_hex': MAGIC.hex(),
    'version': VERSION,
    'used_bytes': USED_BYTES,
    'exact_padded_bytes': EXACT_BYTES,
    'page_bytes': v3.PAGE_BYTES,
    'immutable_v3_prefix': {
        'identity': v3.OBSERVER_OUTPUT_ABI_IDENTITY,
        'exact_bytes': SECTION_OFFSET,
    },
    'feasibility_requirement_section': {
        'offset': SECTION_OFFSET,
        'section_bytes': SECTION_BYTES_COUNT,
        'registry_identity': REGISTRY_IDENTITY,
        'model_identity': MODEL_IDENTITY,
        'family_count': len(FAMILY_ROWS),
        'flags': FLAGS,
        'authorizing': False,
        'every_family_missing_live_authority': True,
    },
}
OUTPUT_ABI_IDENTITY = hashlib.sha256((json.dumps(
    SPEC_PREIMAGE, sort_keys=True, separators=(',', ':'))
    + '\n').encode()).hexdigest()

_MODE_CODES = {
    'independent': 1,
    'strict-conjunction': 2,
    'joint-same-source-game': 3,
    'atomic-same-instance': 4,
    'exhaustive-fresh-trial-history': 5,
    'source-runtime-freshness': 6,
}
_CODE_BY_NAME = {row['name']: row['code'] for row in FAMILY_ROWS}


def _section():
    raw = bytearray(SECTION_MAGIC)
    raw.extend(struct.pack('>IIHH', VERSION, SECTION_BYTES_COUNT,
                           len(FAMILY_ROWS), FLAGS))
    raw.extend(bytes.fromhex(REGISTRY_IDENTITY))
    raw.extend(bytes.fromhex(MODEL_IDENTITY))
    raw.extend(bytes.fromhex(OUTPUT_ABI_IDENTITY))
    for value in PINNED_S4.values():
        raw.extend(bytes.fromhex(value))
    for value in PINNED_S12.values():
        raw.extend(bytes.fromhex(value))
    for value in PINNED_S5.values():
        raw.extend(bytes.fromhex(value))
    for row in FAMILY_ROWS:
        mask = sum(1 << (_CODE_BY_NAME[name] - 1)
                   for name in row['prerequisites'])
        raw.extend(struct.pack(
            '>BBBBHH', row['code'], _MODE_CODES[row['mode']], 0,
            row['pinned_provenance_count'], mask, 0))
    if len(raw) != 628:
        raise RuntimeError('measurement-output-abi-v4-layout-drift')
    raw.extend(bytes(SECTION_BYTES_COUNT - len(raw)))
    return bytes(raw)


SECTION_BYTES = _section()
SECTION_IDENTITY = hashlib.sha256(SECTION_BYTES).hexdigest()


def _need(condition, code):
    if not condition:
        raise ValueError('measurement-output-abi-v4-' + code)


def validate_observer_output_v4(raw):
    _need(type(raw) is bytes and len(raw) == EXACT_BYTES, 'exact-size')
    # This is a parser check only.  The returned v3 capsules are discarded and
    # cannot substitute for the selected child or any live v4 authority.
    v3.decode_observer_capsules(raw[:SECTION_OFFSET])
    _need(raw[SECTION_OFFSET:SECTION_OFFSET + SECTION_BYTES_COUNT]
          == SECTION_BYTES, 'section')
    _need(raw[USED_BYTES:] == bytes(EXACT_BYTES - USED_BYTES),
          'zero-padding')

