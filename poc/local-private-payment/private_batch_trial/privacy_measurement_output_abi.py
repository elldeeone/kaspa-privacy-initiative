#!/usr/bin/env python3
"""Canonical fixed-size private output ABIs for selected measurement workers.

This module defines bytes only.  It neither opens FD62 nor mints an output
authority.  The selected supervisor remains CONFIGURED0 until it consumes the
same source-owned table and a reviewed single-write sandbox.
"""

import hashlib
import json
import struct
import uuid

import privacy_capture_model as capture
import privacy_codec as codec


VIEW_ORDER = codec.VIEWS
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

MAX_INPUT_ASSIGNMENTS = 6
MAX_OUTPUT_ASSIGNMENTS = 90
MAX_ROUND_JOINT_CANDIDATES = 540
MAX_WORKLOAD_CANDIDATES = 291600
MAX_CROSS_ROUND_LINKS = 36
UNION_CATEGORIES = tuple(sorted(set().union(*(
    capture.ARTIFACT_CATEGORIES[kind] for kind in VIEW_KINDS['union']))))
MAX_CATEGORY_ROWS = len(UNION_CATEGORIES)
PAGE_BYTES = 4096

OBSERVER_MAGIC = b'KPBOABI3'
OWNER_SCORE_MAGIC = b'KPBSABI1'
PHASE_MAGIC = b'KPBPHV01'
PHASE_SECTION_BYTES = 144
PHASE_VIEW_CODES = {
    'public': 1,
    'dispatcher': 2,
    'corrupt-server-plus-wallet': 3,
    'union': 4,
}
PHASE_REGISTRY = {
    'artifacts': {'public-projection': 1},
    'families': {
        'accepted-chain-context-outpoint-external-history': 1,
        'accepted-chain-state-outpoint-continuity': 2,
    },
    'resolutions': {'direct-constraint-pending-source-authority': 1},
    'evidence': {'STEP3_ACCEPTED_CHAIN_STATE_AND_OUTPOINT_HISTORY_AUTHORITY': 1},
    'flags': {'mapping-dependent': 1, 'relabel-allowed': 2},
}
PHASE_RECORDS = ((1, 1), (1, 2), (2, 1), (2, 2))
STEP2_MAGIC = b'KPBSTP21'
STEP2_SECTION_BYTES = 256
STEP2_COMPLETE_INVENTORY = 1
STEP2_MODEL_SHA256 = (
    '3e22997c8932709496c843929e4a0752b3bc7f001690c2119a6692b6388a645a')
STEP2_REGISTRY_SHA256 = (
    'ee700075720da629ecfed7bc43f9725d14826fc2d0ecd201878a1c2d6bf86708')
STEP2_VIEW_TOTALS = (42, 56, 108, 122)
STEP2_DEFERRED_STEP3_COUNTS = (4, 4, 4, 4)
STEP2_FAMILY_NAMES = (
    'AUTHENTICATED_C1_CONTACT_AND_VALUE_BINDING',
    'AUTHENTICATED_C1_SOURCE_PROVENANCE',
    'AUTHENTICATED_CONSTRUCTION_POLICY_MAPPING',
    'AUTHENTICATED_DISPATCHER_EVENT_CANDIDATE_CONSTRAINT',
    'AUTHENTICATED_HONEST_OUTPUT_ENCRYPTION_PRODUCER_AUTHORITY',
    'AUTHENTICATED_ROLE_BLIND_ROUTE_HANDOFF',
    'COMPLETE_PUBLIC_MULTIATTEMPT_HISTORY_EQUALITY_JOIN',
    'COMPLETE_PUBLIC_MULTIATTEMPT_NF_EQUALITY_JOIN',
    'LIVE_STRUCTURAL_PROJECTION_CONTINUITY_RESIDUAL_AND_WORKLOAD_JOIN',
    'MATCHED_NATIVE_TERMINAL_PRODUCER_AUTHORITY_AND_PRIVATE_V2_LEAF',
    'MATCHED_NATIVE_TERMINAL_PRODUCER_AUTHORITY_AND_PUBLIC_CONTINUITY_JOIN',
    'PINNED_AUTHENTICATED_GROUP_VIEW_ASSUMPTION',
    'PINNED_DDNNT_5N_OWNER_INPUT_ASSUMPTION',
    'PINNED_GROTH16_PUBLIC_PROOF_ZK_ASSUMPTION',
    'PINNED_MIXED_PROTOCOL_JOINT_VIEW_ASSUMPTION',
    'PINNED_NULLIFIER_PRF_AND_UNLINKABILITY_ASSUMPTION',
    'PINNED_OUTPUT_CIPHERTEXT_JOINT_CONFIDENTIALITY_ASSUMPTION',
    'PINNED_PEDERSEN_CV_JOINT_VIEW_ASSUMPTION',
    'PINNED_SHA256_NOTE_COMMITMENT_HIDING_ASSUMPTION',
    'PINNED_STOCK_MASCOT_JOINT_VIEW_ASSUMPTION',
    'PUBLIC_NF_HISTORY_EDGE_CANDIDATE_FILTER',
    'PUBLIC_STATE_TRANSITION_CANDIDATE_CONSTRAINT',
    'TYPED_GROUP_CORRESPONDENCE_CHECK',
    'WITHIN_RUN_EMPIRICAL_CANDIDATE_FILTER',
    'WITHIN_RUN_PUBLIC_CIPHERTEXT_CANDIDATE_FILTER',
    'WITHIN_RUN_PUBLIC_CV_RESIDUAL_CANDIDATE_FILTER',
)
STEP2_FAMILY_COUNTS = (
    (0, 0, 4, 4), (0, 0, 6, 6), (0, 2, 0, 2), (0, 10, 0, 10),
    (2, 2, 2, 2), (0, 2, 0, 2), (2, 2, 2, 2), (2, 2, 2, 2),
    (4, 4, 4, 4), (2, 2, 2, 2), (2, 2, 2, 2), (0, 0, 20, 20),
    (0, 0, 4, 4), (4, 4, 4, 4), (0, 0, 2, 2), (2, 2, 2, 2),
    (2, 2, 2, 2), (2, 2, 2, 2), (2, 2, 2, 2), (0, 0, 18, 18),
    (2, 2, 2, 2), (4, 4, 4, 4), (0, 0, 2, 2), (0, 0, 10, 10),
    (8, 8, 8, 8), (2, 2, 2, 2),
)
STEP2_DISPOSITION_MISSING_AUTHORITY = 1
STEP2_DISPOSITION_ASSUMPTION = 2
STEP2_DISPOSITION_EMPIRICAL = 3
STEP2_FAMILY_ROWS = tuple(
    (code, *counts,
     STEP2_DISPOSITION_ASSUMPTION if 12 <= code <= 20 else
     STEP2_DISPOSITION_EMPIRICAL if code == 24 else
     STEP2_DISPOSITION_MISSING_AUTHORITY)
    for code, counts in enumerate(STEP2_FAMILY_COUNTS, 1))
STEP2_EMPIRICAL_OPEN_MASK = 0x03ff
STEP2_EMPIRICAL_FIELDS = (
    'attempt.abort_retry_partial_transcript',
    'wire.frames[].direction_peer_fork',
    'wire.frames[].monotonic_ns',
    'wire.frames[].payload_length',
    'wire.frames[].sequence_message_chunk_order',
)
STEP2_EMPIRICAL_OCCURRENCES = tuple(
    (round_number, field)
    for round_number in (1, 2) for field in STEP2_EMPIRICAL_FIELDS)
ATTEMPT_BYTES = 128
WORKLOAD_BITMAP_BYTES = MAX_WORKLOAD_CANDIDATES // 8

INPUT_EDGE_MAX = 18
CREATOR_EDGE_MAX = 36
PAIR_EDGE_MAX = 15
NF_PAIR_EDGE_MAX = 135
CONSTRAINT_ROUND_BYTES = (
    1 + INPUT_EDGE_MAX + 1 + CREATOR_EDGE_MAX + 1 + PAIR_EDGE_MAX
    + 1 + NF_PAIR_EDGE_MAX * 2 + 1)
CATEGORY_BYTES = MAX_CATEGORY_ROWS * 6
OBSERVER_SLOT_BYTES = (
    32 + 2 * CONSTRAINT_ROUND_BYTES + 4 + CATEGORY_BYTES
    + 1 + 1 + 32 + 32 + 4 + WORKLOAD_BITMAP_BYTES)
BINDING_BYTES = 32 + 32 + 16 + 1 + ATTEMPT_BYTES
PUBLIC_ROUND_BYTES = 32 + 32 + 3 * 32 + 6 * 32 + 6 * 32
OBSERVER_PHASE_V2_OFFSET = (
    len(OBSERVER_MAGIC) + BINDING_BYTES + 2 * PUBLIC_ROUND_BYTES
    + len(VIEW_ORDER) * OBSERVER_SLOT_BYTES)
OBSERVER_STEP2_V3_OFFSET = OBSERVER_PHASE_V2_OFFSET + PHASE_SECTION_BYTES
OBSERVER_OUTPUT_USED_BYTES = OBSERVER_STEP2_V3_OFFSET + STEP2_SECTION_BYTES
OBSERVER_OUTPUT_PADDED_BYTES = (
    (OBSERVER_OUTPUT_USED_BYTES + PAGE_BYTES - 1) // PAGE_BYTES * PAGE_BYTES)

INPUT_MASK_BYTES = 1
OUTPUT_MASK_BYTES = 12
ROUND_JOINT_MASK_BYTES = 68
SCORE_COUNTER_BYTES = 9
SCORE_ROUND_BYTES = (
    2 * INPUT_MASK_BYTES + 2 * OUTPUT_MASK_BYTES
    + 2 * ROUND_JOINT_MASK_BYTES + SCORE_COUNTER_BYTES)
OWNER_SCORE_SLOT_BYTES = (
    32 + 2 * 4 + 2 * SCORE_ROUND_BYTES + 4
    + 2 * WORKLOAD_BITMAP_BYTES + 2 * SCORE_COUNTER_BYTES)
OWNER_SCORE_OUTPUT_USED_BYTES = (
    len(OWNER_SCORE_MAGIC) + BINDING_BYTES + 32 + 1
    + len(VIEW_ORDER) * OWNER_SCORE_SLOT_BYTES)
OWNER_SCORE_OUTPUT_PADDED_BYTES = (
    (OWNER_SCORE_OUTPUT_USED_BYTES + PAGE_BYTES - 1)
    // PAGE_BYTES * PAGE_BYTES)


def _need(condition, code):
    if not condition:
        raise ValueError('measurement-output-abi-' + code)


def _word(value):
    codec.word(value)
    return bytes.fromhex(value)


def _category_spec(view):
    kinds = VIEW_KINDS[view]
    categories = tuple(sorted(set().union(
        *(capture.ARTIFACT_CATEGORIES[kind] for kind in kinds))))
    rows = []
    for category in categories:
        artifact_bound = 2 * sum(
            category in capture.ARTIFACT_CATEGORIES[kind] for kind in kinds)
        field_bound = 2 * sum(
            len(capture.ARTIFACT_LEAKAGE_FIELDS[kind].get(category, ()))
            for kind in kinds)
        rows.append((category, artifact_bound, field_bound))
    _need(len(rows) <= MAX_CATEGORY_ROWS, 'category-table-overflow')
    _need(all(0 < artifacts <= 255 and 0 < fields <= 255
              for _, artifacts, fields in rows),
          'category-count-not-u8')
    return tuple(rows)


CATEGORY_SPECS = {view: _category_spec(view) for view in VIEW_ORDER}
_need(tuple(VIEW_KINDS) == VIEW_ORDER, 'view-source-order')
_need(tuple(row[0] for row in CATEGORY_SPECS['union']) == UNION_CATEGORIES,
      'union-category-source-order')
_step2_registry_preimage = {
    'schema': 'kpb-private-step2-evidence-family-registry/v1',
    'views': list(VIEW_ORDER),
    'families': [
        {'code': code, 'name': name, 'counts': list(counts)}
        for code, (name, counts) in enumerate(
            zip(STEP2_FAMILY_NAMES, STEP2_FAMILY_COUNTS), 1)
    ],
    'totals': list(STEP2_VIEW_TOTALS),
}
_need(hashlib.sha256((json.dumps(
          _step2_registry_preimage, sort_keys=True, separators=(',', ':'))
      + '\n').encode()).hexdigest() == STEP2_REGISTRY_SHA256,
      'step2-registry-identity-drift')
_need(tuple(sum(row[view] for row in STEP2_FAMILY_COUNTS)
            for view in range(4)) == STEP2_VIEW_TOTALS,
      'step2-view-total-drift')
_need(OBSERVER_OUTPUT_USED_BYTES == 151449
      and OBSERVER_OUTPUT_PADDED_BYTES == 151552
      and OWNER_SCORE_OUTPUT_USED_BYTES == 293466
      and OWNER_SCORE_OUTPUT_PADDED_BYTES == 294912,
      'layout-derivation-drift')


def _spec_identity(role, magic, used, padded, version=1,
                   phase_registry=None, step2_registry=None):
    value = {
        'schema': f'kpb-measurement-private-output-abi/v{version}',
        'role': role,
        'magic_hex': magic.hex(),
        'used_bytes': used,
        'exact_padded_bytes': padded,
        'page_bytes': PAGE_BYTES,
        'views': list(VIEW_ORDER),
        'maxima': {
            'input_assignments': MAX_INPUT_ASSIGNMENTS,
            'output_assignments': MAX_OUTPUT_ASSIGNMENTS,
            'round_joint_candidates': MAX_ROUND_JOINT_CANDIDATES,
            'workload_candidates': MAX_WORKLOAD_CANDIDATES,
            'cross_round_links': MAX_CROSS_ROUND_LINKS,
            'category_rows': MAX_CATEGORY_ROWS,
        },
        'category_specs': {
            view: [list(row) for row in CATEGORY_SPECS[view]]
            for view in VIEW_ORDER
        },
    }
    if phase_registry is not None:
        value['phase_section'] = {
            'magic_hex': PHASE_MAGIC.hex(),
            'section_bytes': PHASE_SECTION_BYTES,
            'view_codes': PHASE_VIEW_CODES,
            'registry': phase_registry,
            'records': [list(row) for row in PHASE_RECORDS],
            'view_flags': {'complete-inventory': 1},
            'unmodeled_total': 4,
            'deferred_count': 4,
            'step2_open_count': 0,
        }
    if step2_registry is not None:
        value['step2_inventory_section'] = {
            'magic_hex': STEP2_MAGIC.hex(),
            'section_bytes': STEP2_SECTION_BYTES,
            'flags': {'complete-inventory': STEP2_COMPLETE_INVENTORY},
            'model_sha256': STEP2_MODEL_SHA256,
            'registry_sha256': STEP2_REGISTRY_SHA256,
            'registry': step2_registry,
            'deferred_step3_counts': list(STEP2_DEFERRED_STEP3_COUNTS),
            'dispositions': {
                'missing-authority-open': STEP2_DISPOSITION_MISSING_AUTHORITY,
                'source-assumption-open': STEP2_DISPOSITION_ASSUMPTION,
                'empirical-open': STEP2_DISPOSITION_EMPIRICAL,
            },
            'family_rows': [list(row) for row in STEP2_FAMILY_ROWS],
            'empirical_open_mask': STEP2_EMPIRICAL_OPEN_MASK,
            'empirical_occurrences': [
                {'round': round_number, 'field': field}
                for round_number, field in STEP2_EMPIRICAL_OCCURRENCES
            ],
            'empirical_views': [
                'corrupt-server-plus-wallet', 'union'],
            'authorizing': False,
        }
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':'))
           + '\n').encode()
    return hashlib.sha256(raw).hexdigest()


OBSERVER_OUTPUT_ABI_IDENTITY = _spec_identity(
    'observer', OBSERVER_MAGIC, OBSERVER_OUTPUT_USED_BYTES,
    OBSERVER_OUTPUT_PADDED_BYTES, version=3,
    phase_registry=PHASE_REGISTRY,
    step2_registry=_step2_registry_preimage)
OWNER_SCORE_OUTPUT_ABI_IDENTITY = _spec_identity(
    'owner-score', OWNER_SCORE_MAGIC, OWNER_SCORE_OUTPUT_USED_BYTES,
    OWNER_SCORE_OUTPUT_PADDED_BYTES)


def abi_descriptor(role):
    if role == 'observer':
        return {
            'role': role, 'version': 3,
            'identity': OBSERVER_OUTPUT_ABI_IDENTITY,
            'used_bytes': OBSERVER_OUTPUT_USED_BYTES,
            'exact_bytes': OBSERVER_OUTPUT_PADDED_BYTES,
        }
    if role == 'owner-score':
        return {
            'role': role, 'version': 1,
            'identity': OWNER_SCORE_OUTPUT_ABI_IDENTITY,
            'used_bytes': OWNER_SCORE_OUTPUT_USED_BYTES,
            'exact_bytes': OWNER_SCORE_OUTPUT_PADDED_BYTES,
        }
    raise ValueError('measurement-output-abi-no-private-role')


class _Writer:
    def __init__(self):
        self.raw = bytearray()

    def add(self, value):
        self.raw.extend(value)

    def u8(self, value):
        _need(type(value) is int and 0 <= value <= 255, 'u8')
        self.raw.append(value)

    def u16(self, value):
        _need(type(value) is int and 0 <= value <= 65535, 'u16')
        self.add(struct.pack('>H', value))

    def u32(self, value):
        _need(type(value) is int and 0 <= value <= 0xffffffff, 'u32')
        self.add(struct.pack('>I', value))

    def fixed_records(self, records, maximum, width, encode):
        _need(len(records) <= maximum, 'record-cardinality')
        self.u8(len(records))
        for record in records:
            raw = encode(record)
            _need(type(raw) is bytes and len(raw) == width, 'record-width')
            self.add(raw)
        self.add(bytes((maximum - len(records)) * width))


class _Reader:
    def __init__(self, raw):
        _need(type(raw) is bytes, 'raw-bytes')
        self.raw = raw
        self.at = 0

    def take(self, count):
        _need(type(count) is int and count >= 0
              and self.at + count <= len(self.raw), 'truncated')
        result = self.raw[self.at:self.at + count]
        self.at += count
        return result

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack('>H', self.take(2))[0]

    def u32(self):
        return struct.unpack('>I', self.take(4))[0]

    def fixed_records(self, maximum, width, decode):
        count = self.u8()
        _need(count <= maximum, 'record-count')
        result = [decode(self.take(width)) for _ in range(count)]
        _need(self.take((maximum - count) * width) ==
              bytes((maximum - count) * width), 'nonzero-record-padding')
        return result


def _pack_binding(writer, value):
    codec.binding(value)
    writer.add(_word(value['method_sha256']))
    writer.add(_word(value['selection_sha256']))
    writer.add(uuid.UUID(value['trial_id']).bytes)
    attempt = value['attempt_id'].encode('ascii')
    _need(1 <= len(attempt) <= ATTEMPT_BYTES, 'attempt-width')
    writer.u8(len(attempt)); writer.add(attempt)
    writer.add(bytes(ATTEMPT_BYTES - len(attempt)))


def _unpack_binding(reader):
    method = reader.take(32).hex()
    selection = reader.take(32).hex()
    trial = str(uuid.UUID(bytes=reader.take(16)))
    length = reader.u8()
    _need(1 <= length <= ATTEMPT_BYTES, 'attempt-length')
    padded = reader.take(ATTEMPT_BYTES)
    _need(padded[length:] == bytes(ATTEMPT_BYTES - length),
          'attempt-padding')
    try:
        attempt = padded[:length].decode('ascii')
    except UnicodeDecodeError as error:
        raise ValueError('measurement-output-abi-attempt-ascii') from error
    value = {
        'method_sha256': method,
        'selection_sha256': selection,
        'trial_id': trial,
        'phase': 'private-batch-privacy',
        'attempt_id': attempt,
    }
    return codec.binding(value)


def _pack_public(writer, value, round_number):
    codec.batch(value)
    _need(value['round'] == round_number, 'public-round')
    for name in ('projection_sha256', 'context_sha256'):
        writer.add(_word(value[name]))
    for name in ('nfs_hex32', 'cms_hex32', 'tuple_sha256'):
        for item in value[name]:
            writer.add(_word(item))


def _unpack_public(reader, round_number):
    value = {
        'round': round_number,
        'projection_sha256': reader.take(32).hex(),
        'context_sha256': reader.take(32).hex(),
        'nfs_hex32': [reader.take(32).hex() for _ in range(3)],
        'cms_hex32': [reader.take(32).hex() for _ in range(6)],
        'tuple_sha256': [reader.take(32).hex() for _ in range(6)],
    }
    return codec.batch(value)


def _pack_phase_section(writer):
    start = len(writer.raw)
    writer.add(PHASE_MAGIC)
    writer.u16(1)
    writer.u16(PHASE_SECTION_BYTES)
    writer.u8(4); writer.u8(4); writer.u8(1); writer.u8(2)
    for view in VIEW_ORDER:
        writer.u8(PHASE_VIEW_CODES[view]); writer.u8(1)
        writer.u16(4)
        writer.u16(4)
        writer.u16(0)
        for round_number, family in PHASE_RECORDS:
            writer.u8(round_number)
            writer.u8(1)  # public-projection
            writer.u8(family)
            writer.u8(1)  # direct-constraint-pending-source-authority
            writer.u8(1)  # STEP3 accepted-chain authority
            writer.u8(0)  # no mapping/relabel/reserved flags
    _need(len(writer.raw) - start == PHASE_SECTION_BYTES,
          'phase-section-size')


def _unpack_phase_section(reader):
    start = reader.at
    _need(reader.take(8) == PHASE_MAGIC, 'phase-magic')
    _need(reader.u16() == 1,
          'phase-version')
    _need(reader.u16() == PHASE_SECTION_BYTES,
          'phase-size')
    _need((reader.u8(), reader.u8(), reader.u8(), reader.u8()) ==
          (4, 4, 1, 2), 'phase-registry-counts')
    for view in VIEW_ORDER:
        _need(reader.u8() == PHASE_VIEW_CODES[view]
              and reader.u8() == 1, 'phase-view-header')
        total = reader.u16()
        deferred = reader.u16()
        step2 = reader.u16()
        _need(total >= deferred and total - deferred == step2 == 0
              and total == deferred == 4, 'phase-counts')
        observed = []
        for _ in range(4):
            row = tuple(reader.take(6))
            _need(len(row) == 6 and row[1:] ==
                  (1, row[2], 1, 1, 0), 'phase-record-codes')
            _need(row[0] in (1, 2) and row[2] in (1, 2),
                  'phase-record-range')
            observed.append((row[0], row[2]))
        _need(tuple(observed) == PHASE_RECORDS,
              'phase-record-order')
    _need(reader.at - start == PHASE_SECTION_BYTES,
          'phase-consumed-size')


def _pack_step2_inventory_section(writer):
    start = len(writer.raw)
    writer.add(STEP2_MAGIC)
    writer.u16(1)
    writer.u16(STEP2_SECTION_BYTES)
    writer.u8(4)
    writer.u8(len(STEP2_FAMILY_ROWS))
    writer.u8(5)
    writer.u8(2)
    writer.u16(STEP2_COMPLETE_INVENTORY)
    writer.u16(0)
    for total in STEP2_VIEW_TOTALS:
        writer.u16(total)
    for count in STEP2_DEFERRED_STEP3_COUNTS:
        writer.u8(count)
    writer.add(bytes.fromhex(STEP2_REGISTRY_SHA256))
    writer.add(bytes.fromhex(STEP2_MODEL_SHA256))
    for row in STEP2_FAMILY_ROWS:
        for value in row:
            writer.u8(value)
    writer.u16(STEP2_EMPIRICAL_OPEN_MASK)
    writer.u16(0)
    _need(len(writer.raw) - start == STEP2_SECTION_BYTES,
          'step2-section-size')


def _unpack_step2_inventory_section(reader):
    start = reader.at
    _need(reader.take(8) == STEP2_MAGIC, 'step2-magic')
    _need(reader.u16() == 1, 'step2-version')
    _need(reader.u16() == STEP2_SECTION_BYTES, 'step2-size')
    _need((reader.u8(), reader.u8(), reader.u8(), reader.u8()) ==
          (4, len(STEP2_FAMILY_ROWS), 5, 2), 'step2-registry-counts')
    _need(reader.u16() == STEP2_COMPLETE_INVENTORY,
          'step2-inventory-flags')
    _need(reader.u16() == 0, 'step2-header-reserved')
    _need(tuple(reader.u16() for _ in range(4)) == STEP2_VIEW_TOTALS,
          'step2-view-totals')
    _need(tuple(reader.u8() for _ in range(4)) ==
          STEP2_DEFERRED_STEP3_COUNTS, 'step2-deferred-step3-counts')
    _need(reader.take(32).hex() == STEP2_REGISTRY_SHA256,
          'step2-registry-identity')
    _need(reader.take(32).hex() == STEP2_MODEL_SHA256,
          'step2-model-identity')
    observed = tuple(tuple(reader.u8() for _ in range(6))
                     for _ in STEP2_FAMILY_ROWS)
    _need(observed == STEP2_FAMILY_ROWS, 'step2-family-rows')
    _need(reader.u16() == STEP2_EMPIRICAL_OPEN_MASK,
          'step2-empirical-open-mask')
    _need(reader.u16() == 0, 'step2-tail-reserved')
    _need(reader.at - start == STEP2_SECTION_BYTES,
          'step2-consumed-size')


_PROVENANCE = {
    'colluder-knowledge': 0,
    'direct-export': 1,
}
_NF_PAIR_PROVENANCE = {
    'terminal-grouping': 0,
    'direct-export': 1,
    'colluder-knowledge': 2,
}


def _slot(items, value, code):
    _need(value in items, code)
    return items.index(value)


def _semantic_unique(rows, key, code):
    values = [key(row) for row in rows]
    _need(len(values) == len(set(values)), code)


def _pack_constraints(writer, value, public):
    codec.constraints(value, public)
    _need(value['individual_delta_exports'] == 0,
          'selected-individual-delta-absent')
    _semantic_unique(
        value['input_edges'],
        lambda row: (row['owner_component'], row['slot_id'],
                     row['provenance']), 'duplicate-input-edge')
    _semantic_unique(
        value['creator_edges'],
        lambda row: (row['owner_component'], row['slot_id'],
                     row['provenance']), 'duplicate-creator-edge')
    _semantic_unique(
        value['pair_edges'],
        lambda row: tuple(sorted(row['tuple_sha256'])),
        'duplicate-pair-edge')
    _semantic_unique(
        value['nf_pair_edges'],
        lambda row: (row['nf_hex32'], tuple(sorted(row['tuple_sha256'])),
                     row['provenance']), 'duplicate-nf-pair-edge')

    input_key = lambda row: (
        row['owner_component'],
        _slot(public['nfs_hex32'], row['slot_id'], 'input-slot'),
        _PROVENANCE[row['provenance']])
    creator_key = lambda row: (
        row['owner_component'],
        _slot(public['tuple_sha256'], row['slot_id'], 'creator-slot'),
        _PROVENANCE[row['provenance']])
    pair_key = lambda row: tuple(
        _slot(public['tuple_sha256'], item, 'pair-slot')
        for item in row['tuple_sha256'])
    nf_pair_key = lambda row: (
        _slot(public['nfs_hex32'], row['nf_hex32'], 'nf-pair-nf'),
        *( _slot(public['tuple_sha256'], item, 'nf-pair-tuple')
           for item in row['tuple_sha256']),
        _NF_PAIR_PROVENANCE[row['provenance']])
    _need(value['input_edges'] == sorted(value['input_edges'], key=input_key),
          'input-edge-order')
    _need(value['creator_edges'] ==
          sorted(value['creator_edges'], key=creator_key),
          'creator-edge-order')
    _need(all(pair_key(row)[0] < pair_key(row)[1]
              for row in value['pair_edges'])
          and value['pair_edges'] ==
              sorted(value['pair_edges'], key=pair_key),
          'pair-edge-order')
    _need(all(nf_pair_key(row)[1] < nf_pair_key(row)[2]
              for row in value['nf_pair_edges'])
          and value['nf_pair_edges'] ==
              sorted(value['nf_pair_edges'], key=nf_pair_key),
          'nf-pair-edge-order')

    def input_edge(row):
        slot = _slot(public['nfs_hex32'], row['slot_id'], 'input-slot')
        provenance = _PROVENANCE[row['provenance']]
        return bytes((row['owner_component'] | slot << 2
                      | provenance << 4,))

    def creator_edge(row):
        slot = _slot(public['tuple_sha256'], row['slot_id'], 'creator-slot')
        provenance = _PROVENANCE[row['provenance']]
        return bytes((row['owner_component'] | slot << 2
                      | provenance << 5,))

    def pair_edge(row):
        first, second = (_slot(public['tuple_sha256'], item, 'pair-slot')
                         for item in row['tuple_sha256'])
        return bytes((first | second << 3,))

    def nf_pair_edge(row):
        nf = _slot(public['nfs_hex32'], row['nf_hex32'], 'nf-pair-nf')
        first, second = (_slot(public['tuple_sha256'], item,
                               'nf-pair-tuple')
                         for item in row['tuple_sha256'])
        provenance = _NF_PAIR_PROVENANCE[row['provenance']]
        return bytes((nf | first << 2 | second << 5, provenance))

    writer.fixed_records(
        value['input_edges'], INPUT_EDGE_MAX, 1, input_edge)
    writer.fixed_records(
        value['creator_edges'], CREATOR_EDGE_MAX, 1, creator_edge)
    writer.fixed_records(value['pair_edges'], PAIR_EDGE_MAX, 1, pair_edge)
    writer.fixed_records(
        value['nf_pair_edges'], NF_PAIR_EDGE_MAX, 2, nf_pair_edge)
    writer.u8(0)


def _unpack_constraints(reader, public):
    reverse = {number: name for name, number in _PROVENANCE.items()}
    reverse_nf = {
        number: name for name, number in _NF_PAIR_PROVENANCE.items()}

    def input_edge(raw):
        value = raw[0]
        _need(value >> 5 == 0, 'input-edge-reserved-bits')
        owner = value & 3; slot = value >> 2 & 3; provenance = value >> 4
        _need(owner < 3 and slot < 3 and provenance in reverse,
              'input-edge-value')
        return {'owner_component': owner,
                'slot_id': public['nfs_hex32'][slot],
                'provenance': reverse[provenance]}

    def creator_edge(raw):
        value = raw[0]
        _need(value >> 6 == 0, 'creator-edge-reserved-bits')
        owner = value & 3; slot = value >> 2 & 7; provenance = value >> 5
        _need(owner < 3 and slot < 6 and provenance in reverse,
              'creator-edge-value')
        return {'owner_component': owner,
                'slot_id': public['tuple_sha256'][slot],
                'provenance': reverse[provenance]}

    def pair_edge(raw):
        value = raw[0]
        _need(value >> 6 == 0, 'pair-edge-reserved-bits')
        first = value & 7; second = value >> 3 & 7
        _need(first < 6 and second < 6 and first != second,
              'pair-edge-value')
        return {'tuple_sha256': [public['tuple_sha256'][first],
                                 public['tuple_sha256'][second]],
                'provenance': 'pair-tag-export'}

    def nf_pair_edge(raw):
        first = raw[0]
        nf = first & 3; left = first >> 2 & 7; right = first >> 5 & 7
        provenance = raw[1]
        _need(nf < 3 and left < 6 and right < 6 and left != right
              and provenance in reverse_nf, 'nf-pair-edge-value')
        return {'nf_hex32': public['nfs_hex32'][nf],
                'tuple_sha256': [public['tuple_sha256'][left],
                                 public['tuple_sha256'][right]],
                'provenance': reverse_nf[provenance]}

    value = {
        'input_edges': reader.fixed_records(
            INPUT_EDGE_MAX, 1, input_edge),
        'creator_edges': reader.fixed_records(
            CREATOR_EDGE_MAX, 1, creator_edge),
        'pair_edges': reader.fixed_records(PAIR_EDGE_MAX, 1, pair_edge),
        'nf_pair_edges': reader.fixed_records(
            NF_PAIR_EDGE_MAX, 2, nf_pair_edge),
        'individual_delta_exports': reader.u8(),
    }
    _need(value['individual_delta_exports'] == 0,
          'decoded-individual-delta')
    _pack_constraints(_Writer(), value, public)
    return value


def _validate_coverage(value, view):
    codec.fields(value, ('modeled_artifacts', 'unmodeled_artifacts',
                         'missing_artifacts', 'terminal_modeled'))
    maximum = 2 * len(VIEW_KINDS[view])
    _need(value['modeled_artifacts'] == maximum
          and type(value['unmodeled_artifacts']) is int
          and 0 <= value['unmodeled_artifacts'] <= maximum
          and value['missing_artifacts'] == 0
          and value['terminal_modeled'] is True,
          'selected-coverage')
    return value


def _pack_coverage(writer, value, view):
    _validate_coverage(value, view)
    writer.u8(value['modeled_artifacts'])
    writer.u8(value['unmodeled_artifacts'])
    writer.u8(value['missing_artifacts'])
    writer.u8(int(value['terminal_modeled']))


def _unpack_coverage(reader, view):
    modeled = reader.u8()
    unmodeled = reader.u8()
    missing = reader.u8()
    terminal = reader.u8()
    _need(terminal in (0, 1), 'coverage-terminal-boolean')
    return _validate_coverage({
        'modeled_artifacts': modeled,
        'unmodeled_artifacts': unmodeled,
        'missing_artifacts': missing,
        'terminal_modeled': bool(terminal),
    }, view)


_CATEGORY_FIELDS = (
    'modeled_artifacts', 'unmodeled_artifacts', 'missing_artifacts',
    'constraint_modeled_fields', 'source_assumption_covered_fields',
    'unmodeled_fields',
)


def _validate_categories(value, view):
    specs = CATEGORY_SPECS[view]
    _need(type(value) is dict and tuple(sorted(value)) ==
          tuple(row[0] for row in specs), 'category-key-set')
    for category, artifact_bound, field_bound in specs:
        row = value[category]
        codec.fields(row, _CATEGORY_FIELDS)
        _need(all(type(row[name]) is int and row[name] >= 0
                  for name in _CATEGORY_FIELDS), 'category-natural')
        _need(row['modeled_artifacts'] == artifact_bound
              and row['unmodeled_artifacts'] <= artifact_bound
              and row['missing_artifacts'] == 0
              and row['constraint_modeled_fields']
                  + row['source_assumption_covered_fields']
                  + row['unmodeled_fields'] == field_bound
              and ((row['unmodeled_fields'] > 0) ==
                   (row['unmodeled_artifacts'] > 0)),
              'category-source-cardinality')
    return value


def _pack_categories(writer, value, view):
    _validate_categories(value, view)
    specs = CATEGORY_SPECS[view]
    for category, _, _ in specs:
        for name in _CATEGORY_FIELDS:
            writer.u8(value[category][name])
    writer.add(bytes((MAX_CATEGORY_ROWS - len(specs)) * 6))


def _unpack_categories(reader, view):
    result = {}
    specs = CATEGORY_SPECS[view]
    for category, _, _ in specs:
        result[category] = {name: reader.u8() for name in _CATEGORY_FIELDS}
    padding = reader.take((MAX_CATEGORY_ROWS - len(specs)) * 6)
    _need(padding == bytes(len(padding)), 'category-padding')
    return _validate_categories(result, view)


def _bitmap(rows):
    result = bytearray(WORKLOAD_BITMAP_BYTES)
    for left, right in rows:
        index = left * MAX_ROUND_JOINT_CANDIDATES + right
        result[index // 8] |= 1 << (index % 8)
    return bytes(result)


def _rows_from_bitmap(raw):
    _need(len(raw) == WORKLOAD_BITMAP_BYTES, 'workload-bitmap-width')
    result = []
    for index in range(MAX_WORKLOAD_CANDIDATES):
        if raw[index // 8] >> (index % 8) & 1:
            result.append([index // MAX_ROUND_JOINT_CANDIDATES,
                           index % MAX_ROUND_JOINT_CANDIDATES])
    return result


def _validate_workload(value, models):
    codec._workload(value, models)
    _need(value['cross_round_link_count'] <= MAX_CROSS_ROUND_LINKS,
          'cross-round-link-cardinality')
    _need(value['workload_joint_candidates'] <= MAX_WORKLOAD_CANDIDATES
          and value['honest_vector_swap_structural_candidates'] <=
              value['workload_joint_candidates'], 'workload-cardinality')
    return value


def _pack_workload(writer, value, models):
    _validate_workload(value, models)
    writer.u8(value['cross_round_link_count'])
    writer.u8(int(value['cross_round_constraints_modeled'])
              | int(value['terminal_constraints_modeled']) << 1)
    writer.add(_word(value['round_candidate_set_commitment_sha256']))
    writer.add(_word(value['candidate_set_commitment_sha256']))
    writer.u32(value['honest_vector_swap_structural_candidates'])
    writer.add(_bitmap(value['joint']))


def _unpack_workload(reader, models):
    cross = reader.u8(); flags = reader.u8()
    _need(flags & ~3 == 0, 'workload-flags')
    round_commitment = reader.take(32).hex()
    commitment = reader.take(32).hex()
    honest = reader.u32()
    joint = _rows_from_bitmap(reader.take(WORKLOAD_BITMAP_BYTES))
    value = {
        'schema': 'kpb-two-round-candidate-join/v1',
        'round_candidate_counts': [len(model['joint']) for model in models],
        'cross_round_link_count': cross,
        'cross_round_constraints_modeled': bool(flags & 1),
        'terminal_constraints_modeled': bool(flags & 2),
        'joint': joint,
        'workload_joint_candidates': len(joint),
        'full_workload_candidates': len(joint),
        'round_candidate_set_commitment_sha256': round_commitment,
        'candidate_set_commitment_sha256': commitment,
        'honest_vector_swap_structural_candidates': honest,
        'truth_scored': False,
    }
    return _validate_workload(value, models)


def _validate_prediction(value, expected_view):
    codec.fields(value, ('schema', 'binding', 'view', 'models', 'coverage',
                         'category_coverage', 'workload',
                         'lattice_attestation'))
    _need(value['schema'] == 'kpb-private-direct-prediction/v2'
          and value['view'] == expected_view
          and type(value['models']) is list and len(value['models']) == 2,
          'prediction-schema-view')
    codec.binding(value['binding'])
    checked = []
    for round_number, model in enumerate(value['models'], 1):
        _need(type(model) is dict and 'public' in model
              and 'constraints' in model, 'prediction-model')
        codec.batch(model['public'])
        _need(model['public']['round'] == round_number,
              'prediction-model-round')
        _pack_constraints(_Writer(), model['constraints'], model['public'])
        expected = codec.assignments(model['public'], model['constraints'])
        _need(model == expected, 'prediction-recomputed-model')
        checked.append(expected)
    _validate_coverage(value['coverage'], expected_view)
    _validate_categories(value['category_coverage'], expected_view)
    _validate_workload(value['workload'], checked)
    _need(value['lattice_attestation'] == {
        'exact_union_artifact_set': True,
        'exact_union_constraints': True,
        'candidate_subset_lattice_verified': True,
        'full_workload_subset_lattice_verified': True,
    }, 'prediction-lattice')
    return value


def _encode_observer_capsules_v3_control(capsules):
    _need(type(capsules) is list and len(capsules) == len(VIEW_ORDER),
          'observer-four-capsules')
    decoded = []
    salts = []; seals = []
    for raw, view in zip(capsules, VIEW_ORDER):
        _need(type(raw) is bytes and len(raw) > 40
              and raw[:8] == codec.CAPSULE_TAG, 'observer-capsule-tag')
        seal = hashlib.sha256(raw).hexdigest()
        value = codec.unseal(raw, seal)
        _validate_prediction(value, view)
        salt = raw[8:40]
        decoded.append(value); salts.append(salt); seals.append(seal)
    _need(len(set(salts)) == len(salts) and len(set(seals)) == len(seals),
          'observer-unique-capsules')
    common_binding = decoded[0]['binding']
    publics = [model['public'] for model in decoded[0]['models']]
    _need(all(value['binding'] == common_binding
              and [model['public'] for model in value['models']] == publics
              for value in decoded), 'observer-common-source')

    writer = _Writer(); writer.add(OBSERVER_MAGIC)
    _pack_binding(writer, common_binding)
    for number, value in enumerate(publics, 1):
        _pack_public(writer, value, number)
    for value, salt, view in zip(decoded, salts, VIEW_ORDER):
        writer.add(salt)
        for model in value['models']:
            _pack_constraints(writer, model['constraints'], model['public'])
        _pack_coverage(writer, value['coverage'], view)
        _pack_categories(writer, value['category_coverage'], view)
        _pack_workload(writer, value['workload'], value['models'])
    _pack_phase_section(writer)
    _pack_step2_inventory_section(writer)
    _need(len(writer.raw) == OBSERVER_OUTPUT_USED_BYTES,
          'observer-used-size')
    writer.add(bytes(OBSERVER_OUTPUT_PADDED_BYTES - len(writer.raw)))
    return bytes(writer.raw)


def encode_observer_capsules(capsules):
    del capsules
    raise ValueError(
        'measurement-output-abi-native-result-source-authority-required')


def test_only_encode_observer_capsules_v3(capsules):
    """Synthetic transport/parser fixture; never a result authority."""
    return _encode_observer_capsules_v3_control(capsules)


def decode_observer_capsules(raw):
    _need(type(raw) is bytes and len(raw) == OBSERVER_OUTPUT_PADDED_BYTES,
          'observer-exact-size')
    reader = _Reader(raw)
    _need(reader.take(8) == OBSERVER_MAGIC, 'observer-magic')
    bound = _unpack_binding(reader)
    publics = [_unpack_public(reader, number) for number in (1, 2)]
    result = []; salts = []; seals = []
    lattice = {
        'exact_union_artifact_set': True,
        'exact_union_constraints': True,
        'candidate_subset_lattice_verified': True,
        'full_workload_subset_lattice_verified': True,
    }
    for view in VIEW_ORDER:
        salt = reader.take(32)
        _need(salt != bytes(32), 'observer-zero-salt')
        models = []
        for public in publics:
            constraints = _unpack_constraints(reader, public)
            models.append(codec.assignments(public, constraints))
        coverage = _unpack_coverage(reader, view)
        categories = _unpack_categories(reader, view)
        workload = _unpack_workload(reader, models)
        predicted = codec.prediction(
            bound, view, models, coverage,
            category_coverage=categories, workload=workload,
            lattice_attestation=lattice)
        capsule, seal = codec.seal(predicted, salt)
        result.append(capsule); salts.append(salt); seals.append(seal)
    _need(len(set(salts)) == len(salts) and len(set(seals)) == len(seals),
          'decoded-observer-unique-capsules')
    _unpack_phase_section(reader)
    _unpack_step2_inventory_section(reader)
    _need(reader.at == OBSERVER_OUTPUT_USED_BYTES
          and reader.take(len(raw) - reader.at) ==
              bytes(OBSERVER_OUTPUT_PADDED_BYTES -
                    OBSERVER_OUTPUT_USED_BYTES),
          'observer-zero-padding')
    return result


_SCORE_ROUND_FIELDS = (
    'round', 'input_masks', 'output_masks', 'joint_masks',
    'eligible_inputs', 'eligible_outputs', 'correct_unique_inputs',
    'wrong_unique_inputs', 'correct_unique_outputs',
    'wrong_unique_outputs', 'correct_unique_pair_links',
    'wrong_unique_pair_links', 'nf_pair_candidate_floor_met',
)
_WORKLOAD_ROUND_FIELDS = tuple(
    name for name in _SCORE_ROUND_FIELDS
    if name not in ('input_masks', 'output_masks', 'joint_masks'))
_COUNTER_FIELDS = (
    'eligible_inputs', 'eligible_outputs', 'correct_unique_inputs',
    'wrong_unique_inputs', 'correct_unique_outputs',
    'wrong_unique_outputs', 'correct_unique_pair_links',
    'wrong_unique_pair_links',
)


def _validate_counters(row, round_number, fields):
    codec.fields(row, fields)
    _need(row['round'] == round_number
          and type(row['nf_pair_candidate_floor_met']) is bool,
          'score-round-header')
    limits = (1, 2, 1, 1, 2, 2, 1, 1)
    _need(all(type(row[name]) is int and 0 <= row[name] <= limit
              for name, limit in zip(_COUNTER_FIELDS, limits)),
          'score-counter-bound')
    _need(row['correct_unique_inputs'] + row['wrong_unique_inputs']
              <= row['eligible_inputs']
          and row['correct_unique_outputs'] + row['wrong_unique_outputs']
              <= row['eligible_outputs']
          and row['correct_unique_pair_links']
              + row['wrong_unique_pair_links'] <= row['eligible_inputs'],
          'score-counter-disjoint')
    return row


def _validate_mask_list(value, size, code):
    _need(type(value) is list and len(value) == 2
          and type(size) is int and 0 <= size <= MAX_WORKLOAD_CANDIDATES
          and all(type(item) is int and 0 <= item < (1 << size)
                  for item in value), code)
    return value


def _validate_score_leaf(leaf, view, bound, owner):
    codec.fields(leaf, (
        'schema', 'binding', 'view', 'capsule_seal_sha256',
        'owner_component', 'rounds', 'round_candidate_counts',
        'workload_masks', 'workload_candidate_count', 'workload_rounds'))
    _need(leaf['schema'] == 'kpb-private-direct-score-leaf/v2'
          and leaf['binding'] == bound and leaf['view'] == view
          and leaf['owner_component'] == owner,
          'score-leaf-lineage')
    codec.word(leaf['capsule_seal_sha256'])
    _need(type(leaf['round_candidate_counts']) is list
          and len(leaf['round_candidate_counts']) == 2
          and type(leaf['rounds']) is list and len(leaf['rounds']) == 2,
          'score-two-rounds')
    for number, (counts, row) in enumerate(zip(
            leaf['round_candidate_counts'], leaf['rounds']), 1):
        codec.fields(counts, ('inputs', 'outputs', 'joint'))
        _need(type(counts['inputs']) is int
              and 0 <= counts['inputs'] <= MAX_INPUT_ASSIGNMENTS
              and type(counts['outputs']) is int
              and 0 <= counts['outputs'] <= MAX_OUTPUT_ASSIGNMENTS
              and type(counts['joint']) is int
              and 0 <= counts['joint'] <= MAX_ROUND_JOINT_CANDIDATES
              and counts['joint'] <= counts['inputs'] * counts['outputs'],
              'score-candidate-counts')
        _validate_counters(row, number, _SCORE_ROUND_FIELDS)
        _validate_mask_list(row['input_masks'], counts['inputs'],
                            'score-input-masks')
        _validate_mask_list(row['output_masks'], counts['outputs'],
                            'score-output-masks')
        _validate_mask_list(row['joint_masks'], counts['joint'],
                            'score-joint-masks')
    count = leaf['workload_candidate_count']
    _need(type(count) is int and 0 <= count <= MAX_WORKLOAD_CANDIDATES,
          'score-workload-count')
    _validate_mask_list(leaf['workload_masks'], count,
                        'score-workload-masks')
    _need(type(leaf['workload_rounds']) is list
          and len(leaf['workload_rounds']) == 2,
          'score-workload-rounds')
    for number, row in enumerate(leaf['workload_rounds'], 1):
        _validate_counters(row, number, _WORKLOAD_ROUND_FIELDS)
    return leaf


def _validate_score_bundle(value):
    codec.fields(value, ('schema', 'binding', 'run_selection_sha256',
                         'owner_component', 'views'))
    _need(value['schema'] == 'kpb-private-all-view-count-leaves/v2',
          'score-bundle-schema')
    bound = codec.binding(value['binding'])
    codec.word(value['run_selection_sha256'])
    owner = codec.owner(value['owner_component'])
    _need(type(value['views']) is list and len(value['views']) == 4,
          'score-four-views')
    for leaf, view in zip(value['views'], VIEW_ORDER):
        _validate_score_leaf(leaf, view, bound, owner)
    seals = [leaf['capsule_seal_sha256'] for leaf in value['views']]
    _need(len(set(seals)) == len(seals), 'score-unique-capsules')
    return value


def _pack_integer(writer, value, width):
    _need(type(value) is int and 0 <= value < (1 << (width * 8)),
          'fixed-integer')
    writer.add(value.to_bytes(width, 'little'))


def _unpack_integer(reader, width):
    return int.from_bytes(reader.take(width), 'little')


def _pack_counters(writer, row):
    for name in _COUNTER_FIELDS:
        writer.u8(row[name])
    writer.u8(int(row['nf_pair_candidate_floor_met']))


def _unpack_counters(reader, round_number, fields):
    result = {'round': round_number}
    result.update({name: reader.u8() for name in _COUNTER_FIELDS})
    floor = reader.u8()
    _need(floor in (0, 1), 'score-floor-boolean')
    result['nf_pair_candidate_floor_met'] = bool(floor)
    return _validate_counters(result, round_number, fields)


def encode_owner_score_bundle(value):
    _validate_score_bundle(value)
    writer = _Writer(); writer.add(OWNER_SCORE_MAGIC)
    _pack_binding(writer, value['binding'])
    writer.add(_word(value['run_selection_sha256']))
    writer.u8(value['owner_component'])
    for leaf in value['views']:
        writer.add(_word(leaf['capsule_seal_sha256']))
        for counts in leaf['round_candidate_counts']:
            writer.u8(counts['inputs']); writer.u8(counts['outputs'])
            writer.u16(counts['joint'])
        for row in leaf['rounds']:
            for item in row['input_masks']:
                _pack_integer(writer, item, INPUT_MASK_BYTES)
            for item in row['output_masks']:
                _pack_integer(writer, item, OUTPUT_MASK_BYTES)
            for item in row['joint_masks']:
                _pack_integer(writer, item, ROUND_JOINT_MASK_BYTES)
            _pack_counters(writer, row)
        writer.u32(leaf['workload_candidate_count'])
        for item in leaf['workload_masks']:
            _pack_integer(writer, item, WORKLOAD_BITMAP_BYTES)
        for row in leaf['workload_rounds']:
            _pack_counters(writer, row)
    _need(len(writer.raw) == OWNER_SCORE_OUTPUT_USED_BYTES,
          'score-used-size')
    writer.add(bytes(OWNER_SCORE_OUTPUT_PADDED_BYTES - len(writer.raw)))
    return bytes(writer.raw)


def decode_owner_score_bundle(raw):
    _need(type(raw) is bytes and len(raw) == OWNER_SCORE_OUTPUT_PADDED_BYTES,
          'score-exact-size')
    reader = _Reader(raw)
    _need(reader.take(8) == OWNER_SCORE_MAGIC, 'score-magic')
    bound = _unpack_binding(reader)
    run_selection = reader.take(32).hex()
    owner = reader.u8()
    leaves = []
    for view in VIEW_ORDER:
        seal = reader.take(32).hex()
        counts = [{'inputs': reader.u8(), 'outputs': reader.u8(),
                   'joint': reader.u16()} for _ in range(2)]
        rounds = []
        for number in (1, 2):
            row = {
                'round': number,
                'input_masks': [_unpack_integer(reader, INPUT_MASK_BYTES)
                                for _ in range(2)],
                'output_masks': [_unpack_integer(reader, OUTPUT_MASK_BYTES)
                                 for _ in range(2)],
                'joint_masks': [_unpack_integer(
                    reader, ROUND_JOINT_MASK_BYTES) for _ in range(2)],
            }
            row.update(_unpack_counters(
                reader, number, _WORKLOAD_ROUND_FIELDS))
            rounds.append(row)
        workload_count = reader.u32()
        workload_masks = [_unpack_integer(reader, WORKLOAD_BITMAP_BYTES)
                          for _ in range(2)]
        workload_rounds = [_unpack_counters(
            reader, number, _WORKLOAD_ROUND_FIELDS) for number in (1, 2)]
        leaves.append({
            'schema': 'kpb-private-direct-score-leaf/v2',
            'binding': bound,
            'view': view,
            'capsule_seal_sha256': seal,
            'owner_component': owner,
            'rounds': rounds,
            'round_candidate_counts': counts,
            'workload_masks': workload_masks,
            'workload_candidate_count': workload_count,
            'workload_rounds': workload_rounds,
        })
    result = {
        'schema': 'kpb-private-all-view-count-leaves/v2',
        'binding': bound,
        'run_selection_sha256': run_selection,
        'owner_component': owner,
        'views': leaves,
    }
    _validate_score_bundle(result)
    _need(reader.at == OWNER_SCORE_OUTPUT_USED_BYTES
          and reader.take(len(raw) - reader.at) ==
              bytes(OWNER_SCORE_OUTPUT_PADDED_BYTES -
                    OWNER_SCORE_OUTPUT_USED_BYTES),
          'score-zero-padding')
    return result


SOURCE_STATUS = {
    'observer_schema_frozen': True,
    'observer_step2_inventory_v3': True,
    'owner_score_schema_frozen': True,
    'cpp_parser_table': True,
    'selected_output_plane': False,
    'fd62_installed': False,
    'configured': False,
}
