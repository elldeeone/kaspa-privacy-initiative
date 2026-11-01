"""Non-authorizing parser for the selected FD40 structural section.

The native parent writes this grammar only after consuming the live terminal,
producer, and structural-continuity capabilities.  Parsing caller bytes is not
authority.  This module deliberately returns an inspection receipt with
``authorizes_coverage=False``; only the selected capsule entrypoint may later
turn a consumed native FD40 admission into model coverage.
"""

import hashlib


CAPSULE_MAGIC = b'KPBOSA2\0'
CAPSULE_VERSION = 2
RUN_BINDING_OFFSET = 76
RUN_BINDING_BYTES = 3403
STRUCTURAL_OFFSET = 5874
STRUCTURAL_MAGIC = b'KPBSPC1\0'
STRUCTURAL_VERSION = 1
STRUCTURAL_BYTES = 1988
STRUCTURAL_END = STRUCTURAL_OFFSET + STRUCTURAL_BYTES
LEAF_COUNT_OFFSET = STRUCTURAL_END
PREFIX_BYTES = LEAF_COUNT_OFFSET + 1

LINEAGE_FIELDS = (
    'projection', 'accepted_input_head', 'successor_head',
    'retained_projection', 'fork_binding', 'intake', 'mapping_source',
    'stream_process', 'stream_child_exit', 'child_process', 'child_exit',
    'producer_stream_process', 'producer_stream_child_exit',
    'private_completion',
)
STRUCTURAL_DIGEST_FIELDS = (
    'projection_identity', 'profile_context_identity',
    'old_context_identity', 'old_reserve_outpoint_identity',
    'old_cm_root', 'old_nf_root', 'new_cm_root', 'new_nf_root',
    'old_state_identity', 'successor_state_identity',
    'old_script_identity', 'successor_script_identity',
    'structural_old_context_identity',
    'structural_successor_context_identity',
    'structural_projection_identity',
)
COUNT_FIELDS = (
    'old_cm_count', 'old_nf_count', 'new_cm_count', 'new_nf_count')
SOMPI_FIELDS = ('old_reserve_sompi', 'new_reserve_sompi', 'fee_sompi')


def _need(condition, name):
    if not condition:
        raise ValueError(name)


def _u32(value):
    _need(type(value) is bytes and len(value) == 4, 'fd40-u32')
    return int.from_bytes(value, 'little')


def _u64(value):
    _need(type(value) is bytes and len(value) == 8, 'fd40-u64')
    return int.from_bytes(value, 'little')


def _run_binding(value):
    """Validate the exact RunBinding wire already in the FD40 v2 envelope."""
    _need(type(value) is bytes and len(value) == RUN_BINDING_BYTES,
          'fd40-structural-run-binding-width')
    at = 0
    classification = value[at]
    at += 1
    _need(classification in (1, 2),
          'fd40-structural-run-binding-classification')

    def digest():
        nonlocal at
        result = value[at:at + 32]
        at += 32
        _need(len(result) == 32 and result != bytes(32),
              'fd40-structural-run-binding-digest')
        return result

    # comparison..runtime, then finite-manifest identities, then outer-parent
    # and capture source/build/runtime/launcher.  This is the native
    # run_binding_bytes order used by the continuity-identity preimage.
    for _ in range(10):
        digest()
    digest()
    digest()
    for _ in range(6):
        digest()
    for component in range(1, 11):
        _need(value[at] == component,
              'fd40-structural-run-binding-manifest-order')
        at += 1
        for _ in range(6):
            digest()
    for _ in range(3 * 6):
        digest()
    arrays = {}
    for name in ('financial_runs', 'round_attempts', 'round_cohorts',
                 'round_capture_plans', 'projections'):
        arrays[name] = (digest(), digest())
    _need(at == len(value)
          and all(left != right for left, right in arrays.values()),
          'fd40-structural-run-binding-complete')
    return {'classification': classification, **arrays, 'wire_bytes': value}


def structural_projection_evidence(raw):
    """Recompute the exact native PrivateStructuralProjectionEvidence."""
    _need(type(raw) is bytes and len(raw) == 10685,
          'fd40-structural-projection-width')
    body = raw[193:]
    _need(raw[:12] == b'KPBAFX01\x01\0\x01\0'
          and body[:8] == b'KPBAEF01',
          'fd40-structural-projection-header')
    old_cm_count = _u32(body[268:272])
    old_nf_count = _u32(body[272:276])
    new_cm_count = _u32(body[348:352])
    new_nf_count = _u32(body[352:356])
    old_reserve = _u64(body[276:284])
    new_reserve = _u64(body[356:364])
    fee = _u64(body[364:372])
    old_state = (b'KPBAST01' + body[104:136] + body[204:236]
                 + body[268:272] + body[236:268] + body[272:276])
    successor_state = (b'KPBAST01' + body[104:136] + body[284:316]
                       + body[348:352] + body[316:348]
                       + body[352:356])
    _need(len(old_state) == len(successor_state) == 112,
          'fd40-structural-state-width')
    old_context = (b'KPB_STRUCTURAL_PROJECTION_CONTEXT_V1\n'
                   + body[8:168] + body[204:236] + body[236:268]
                   + body[268:272] + body[272:276] + body[276:284]
                   + raw[66:103])
    successor_context = (b'KPB_STRUCTURAL_PROJECTION_CONTEXT_V1\n'
                         + body[8:168] + body[284:316] + body[316:348]
                         + body[348:352] + body[352:356] + body[356:364]
                         + raw[115:152])
    result = {
        'projection_identity': hashlib.sha256(raw).digest(),
        'profile_context_identity': hashlib.sha256(body[8:168]).digest(),
        'old_context_identity': hashlib.sha256(body[8:284]).digest(),
        'old_reserve_outpoint_identity': hashlib.sha256(
            body[168:204]).digest(),
        'old_cm_root': body[204:236],
        'old_nf_root': body[236:268],
        'new_cm_root': body[284:316],
        'new_nf_root': body[316:348],
        'old_state_identity': hashlib.sha256(old_state).digest(),
        'successor_state_identity': hashlib.sha256(successor_state).digest(),
        'old_script_identity': hashlib.sha256(raw[66:103]).digest(),
        'successor_script_identity': hashlib.sha256(raw[115:152]).digest(),
        'structural_old_context_identity': hashlib.sha256(
            old_context).digest(),
        'structural_successor_context_identity': hashlib.sha256(
            successor_context).digest(),
        'old_cm_count': old_cm_count,
        'old_nf_count': old_nf_count,
        'new_cm_count': new_cm_count,
        'new_nf_count': new_nf_count,
        'old_reserve_sompi': old_reserve,
        'new_reserve_sompi': new_reserve,
        'fee_sompi': fee,
    }
    preimage = b'KPB_PRIVATE_STRUCTURAL_PROJECTION_EVIDENCE_V1\n'
    for name in STRUCTURAL_DIGEST_FIELDS[:-1]:
        preimage += result[name]
    preimage += (old_cm_count.to_bytes(4, 'little')
                 + old_nf_count.to_bytes(4, 'little')
                 + old_reserve.to_bytes(8, 'little')
                 + new_cm_count.to_bytes(4, 'little')
                 + new_nf_count.to_bytes(4, 'little')
                 + new_reserve.to_bytes(8, 'little')
                 + fee.to_bytes(8, 'little'))
    result['structural_projection_identity'] = hashlib.sha256(
        preimage).digest()
    _need(all(result[name] != bytes(32)
              for name in STRUCTURAL_DIGEST_FIELDS)
          and 3 <= old_cm_count <= 65536
          and 1 <= old_nf_count <= 131072
          and new_cm_count == old_cm_count + 6
          and new_nf_count == old_nf_count + 3
          and new_cm_count <= 65536 and new_nf_count <= 131072
          and old_reserve >= 60_000_000 and new_reserve >= 60_000_000
          and fee > 0 and new_reserve + fee == old_reserve
          and result['old_state_identity'] != result['successor_state_identity']
          and result['old_script_identity'] !=
              result['successor_script_identity'],
          'fd40-structural-projection-evidence')
    return result


def parse_prefix(prefix, raw_rounds, public_rounds):
    """Validate the fixed FD40 prefix; the returned dict is not authority."""
    _need(type(prefix) is bytes and len(prefix) == PREFIX_BYTES,
          'fd40-structural-prefix-width')
    _need(prefix[:8] == CAPSULE_MAGIC
          and _u32(prefix[8:12]) == CAPSULE_VERSION
          and prefix[LEAF_COUNT_OFFSET] == 10,
          'fd40-structural-envelope')
    binding = _run_binding(prefix[
        RUN_BINDING_OFFSET:RUN_BINDING_OFFSET + RUN_BINDING_BYTES])
    section = prefix[STRUCTURAL_OFFSET:STRUCTURAL_END]
    _need(section[:8] == STRUCTURAL_MAGIC
          and _u32(section[8:12]) == STRUCTURAL_VERSION
          and _u32(section[12:16]) == STRUCTURAL_BYTES
          and section[16] == binding['classification']
          and section[17:20] == bytes((1, 0, 2)),
          'fd40-structural-section-header')
    continuity_identity = section[20:52]
    _need(continuity_identity != bytes(32),
          'fd40-structural-continuity-identity')
    at = 52
    rounds = []
    for _ in range(2):
        lineage = {}
        for name in LINEAGE_FIELDS:
            lineage[name] = section[at:at + 32]
            at += 32
        structural = {}
        for name in STRUCTURAL_DIGEST_FIELDS:
            structural[name] = section[at:at + 32]
            at += 32
        for name in COUNT_FIELDS:
            structural[name] = _u32(section[at:at + 4])
            at += 4
        for name in SOMPI_FIELDS:
            structural[name] = _u64(section[at:at + 8])
            at += 8
        _need(all(value != bytes(32) for value in lineage.values())
              and all(structural[name] != bytes(32)
                      for name in STRUCTURAL_DIGEST_FIELDS),
              'fd40-structural-round-digests')
        rounds.append({'lineage': lineage, 'structural': structural})
    _need(at == len(section), 'fd40-structural-section-complete')
    _need(type(raw_rounds) is list and len(raw_rounds) == 2
          and type(public_rounds) is list and len(public_rounds) == 2,
          'fd40-structural-two-rounds')
    expected = [structural_projection_evidence(raw) for raw in raw_rounds]
    _need([public['round'] for public in public_rounds] == [1, 2]
          and tuple(bytes.fromhex(public['projection_sha256'])
                    for public in public_rounds) == binding['projections'],
          'fd40-structural-binding-projections')
    for index, (round_value, expected_value, public) in enumerate(zip(
            rounds, expected, public_rounds)):
        lineage = round_value['lineage']
        structural = round_value['structural']
        _need(structural == expected_value
              and lineage['projection'] == expected_value[
                  'projection_identity']
              and lineage['projection'] == bytes.fromhex(
                  public['projection_sha256'])
              and lineage['accepted_input_head'] != lineage['successor_head']
              and lineage['stream_process'] ==
                  lineage['producer_stream_process']
              and lineage['stream_child_exit'] ==
                  lineage['producer_stream_child_exit'],
              'fd40-structural-round-' + str(index + 1) + '-binding')
    first_lineage, second_lineage = (
        value['lineage'] for value in rounds)
    first, second = (value['structural'] for value in rounds)
    _need(first['profile_context_identity'] ==
              second['profile_context_identity']
          and first['new_cm_root'] == second['old_cm_root']
          and first['new_nf_root'] == second['old_nf_root']
          and first['new_cm_count'] == second['old_cm_count']
          and first['new_nf_count'] == second['old_nf_count']
          and first['new_reserve_sompi'] == second['old_reserve_sompi']
          and first['successor_state_identity'] == second['old_state_identity']
          and first['successor_script_identity'] ==
              second['old_script_identity']
          and first['structural_successor_context_identity'] ==
              second['structural_old_context_identity']
          and first_lineage['successor_head'] ==
              second_lineage['accepted_input_head']
          and all(first_lineage[name] != second_lineage[name] for name in (
              'projection', 'retained_projection', 'fork_binding', 'intake',
              'mapping_source', 'stream_process', 'stream_child_exit',
              'child_process', 'child_exit', 'private_completion')),
          'fd40-structural-exact-cross-round-relation')
    identity_preimage = (
        b'KPB_STRUCTURAL_PROJECTION_CONTINUITY_AUTHORITY_V1\n'
        + binding['wire_bytes'] + bytes((binding['classification'],)))
    for value in rounds:
        identity_preimage += b''.join(
            value['lineage'][name] for name in LINEAGE_FIELDS)
        identity_preimage += value['structural'][
            'structural_projection_identity']
    identity_preimage += bytes((1, 0))
    _need(hashlib.sha256(identity_preimage).digest() == continuity_identity,
          'fd40-structural-continuity-identity-binding')
    return {
        'schema': 'kpb-fd40-structural-continuity-parse/v1',
        'classification': binding['classification'],
        'projection_sha256': [value.hex() for value in binding['projections']],
        'continuity_identity': continuity_identity.hex(),
        'structural_projection_continuity': True,
        'accepted_chain_continuity': False,
        'round_count': 2,
        'authorizes_coverage': False,
        'requires_consumed_native_fd40_admission': True,
    }
