"""Prospective empirical observer for one pinned passive P1 C03 stream.

This module treats bytes and metadata as observations.  It supplies no MASCOT,
DDNNT, group, Groth16, active-host, or side-channel security assumption.
Extraction and exact within-run joins are label-free and are intended to run
before any actual-trial truth is mounted.  The optional classifier is a
non-authorizing study; synthetic rows can test mechanics but cannot close a
gate field.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import struct
import uuid


MAGIC = b'KPBP1C03'
HEADER_BYTES = 112
MAX_CHUNK_BYTES = 1 << 16
MAX_SEMANTIC = 17
V9_SCALAR_CAPTURE_MANIFEST_SHA256 = (
    '5e6903569bc71cbfb5549b369b79a19ecda6686dc4ab25fca0d161c6e1527b6b')
V9_QUERY_MSM_CORRESPONDENCE_MANIFEST_SHA256 = (
    '7cd5956c8a30da0d9bf2e040b1d67b83ffd516a211aba8d08985c6ecdae13ace')
V9_RANDOMNESS_SITES = frozenset((1, 7, 20, 21))
V9_SCALAR_SITE_BITMAP = (1 << 22) - 1
FEATURE_SCHEMA = 'kpb-p1-passive-empirical-features/v2'
EXACT_OBSERVATION_SCHEMA = 'kpb-p1-passive-exact-observations/v2'
WITHIN_RUN_PLAN_SCHEMA = 'kpb-p1-passive-within-run-plan/v2'
WITHIN_RUN_RECEIPT_SCHEMA = (
    'kpb-p1-passive-within-run-constraint-receipt/v2')
OBSERVER_SCOPE = (
    'PINNED_INSTRUMENTED_PASSIVE_P1_PROCESS_PLUS_PASSIVE_OWNER1')
METHOD_ID = hashlib.sha256(
    b'KPB_P1_PASSIVE_EMPIRICAL_OBSERVER_METHOD_V2_C03_V9\n').hexdigest()
CALIBRATION_SCHEMA = 'kpb-p1-passive-empirical-calibration/v2'
SCORE_SCHEMA = 'kpb-p1-passive-empirical-candidate-score/v2'
SPLIT_DOMAIN = b'KPB_P1_EMPIRICAL_CALIBRATION_SPLIT_V1\n'
MIN_TRAIN_PER_LABEL = 24
MIN_HOLDOUT_PER_LABEL = 24
DIGEST_DISTANCE_WEIGHT = 1 / 16
ASSOCIATION_P_THRESHOLD = 0.01
HOLDOUT_THRESHOLD_QUANTILE = 0.95
POWER_ALTERNATIVE_ACCURACY = 0.75
MIN_CLASSIFICATION_POWER = 0.80

FRAME_EXACT_FIELDS = (
    'record_type', 'semantic', 'direction', 'peer', 'flags', 'sequence',
    'message', 'chunk', 'payload_length', 'fork_hex', 'payload_sha256',
    'monotonic_ns',
    'hello_round', 'hello_role', 'hello_configured', 'hello_fixed_fd',
    'hello_attempt_id', 'hello_cohort_sha256',
    'hello_financial_run_id', 'hello_capture_identity',
    'hello_source_sha256', 'hello_build_sha256', 'hello_launch_sha256',
    'hello_model_preimage_sha256', 'hello_query_store_preimage_sha256',
    'hello_scalar_manifest_sha256',
    'scalar_binding_version', 'scalar_binding_kind',
    'scalar_binding_site', 'scalar_binding_element_count',
    'seal_projection_sha256',
    'fork_parent_hex', 'fork_child_hex', 'fork_suffix_sha256',
    'footer_version', 'footer_semantic_count',
    'footer_total_counters', 'footer_lane_counters',
    'footer_instrumented_bitmap', 'footer_owner_offset_bitmap',
    'footer_owner_preprocessing_bitmap', 'footer_scalar_site_bitmap',
    'footer_timed_frame_count', 'footer_first_monotonic_ns',
    'footer_last_monotonic_ns',
)
ATTEMPT_EXACT_FIELDS = (
    'attempt_id', 'retry_ordinal', 'predecessor_attempt_id',
    'start_monotonic_ns', 'end_monotonic_ns', 'outcome', 'failure_code',
    'capture_sha256', 'stream_state', 'partial_tail_length',
    'partial_tail_sha256',
)
TIME_FIELDS = frozenset((
    'monotonic_ns', 'start_monotonic_ns', 'end_monotonic_ns'))
RANK_FIELDS = frozenset((
    'source_order', 'monotonic_ns', 'start_monotonic_ns',
    'end_monotonic_ns'))

FIELD_DISPOSITIONS = {
    'header.magic': {
        'mode': 'CONSTANT_PUBLIC', 'check': 'exact-c03-magic'},
    'header.record_type': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['message-chunk-order']},
    'header.semantic': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['message-chunk-order']},
    'header.direction': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['direction-peer-fork']},
    'header.peer': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['direction-peer-fork']},
    'header.flags': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['message-chunk-order']},
    'header.reserved': {
        'mode': 'CONSTANT_PUBLIC', 'check': 'reserved-header-zero'},
    'header.monotonic_ns': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['monotonic-timing']},
    'header.sequence': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['message-chunk-order']},
    'header.message': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['message-chunk-order']},
    'header.chunk': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['message-chunk-order']},
    'header.payload_length': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['frame-length']},
    'header.fork': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['direction-peer-fork']},
    'header.payload_sha256': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['all-lane-content']},
    'payload.peer_transport': {
        'mode': 'CONSTRAINT_REQUIRED',
        'families': ['mixed-peer-content', 'all-lane-content']},
    'payload.other_lane': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['all-lane-content']},
    'payload.hello.model_preimage_sha256': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['all-lane-content']},
    'payload.hello.query_store_preimage_sha256': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['all-lane-content']},
    'payload.hello.scalar_manifest_sha256': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['all-lane-content']},
    'payload.hello.source_build_launch_role_binding': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['all-lane-content']},
    'payload.scalar_binding.version_kind_site_count': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['all-lane-content']},
    'payload.scalar_binding.reserved': {
        'mode': 'CONSTANT_PUBLIC', 'check': 'scalar-binding-reserved-zero'},
    'payload.projection_seal': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['all-lane-content']},
    'payload.fork_binding': {
        'mode': 'CONSTRAINT_REQUIRED',
        'families': ['direction-peer-fork', 'all-lane-content']},
    'payload.footer.v9_counters_and_bitmaps': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['all-lane-content']},
    'source.query_msm_correspondence_manifest': {
        'mode': 'CONSTANT_PUBLIC',
        'check': 'pinned-query-msm-correspondence-manifest',
        'value_sha256': V9_QUERY_MSM_CORRESPONDENCE_MANIFEST_SHA256},
    'partial.tail': {
        'mode': 'CONSTRAINT_REQUIRED',
        'families': ['frame-length', 'all-lane-content']},
    'attempt.attempt_id': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['abort-retry']},
    'attempt.retry_ordinal': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['abort-retry']},
    'attempt.predecessor_attempt_id': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['abort-retry']},
    'attempt.start_monotonic_ns': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['abort-retry']},
    'attempt.end_monotonic_ns': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['abort-retry']},
    'attempt.outcome': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['abort-retry']},
    'attempt.failure_code': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['abort-retry']},
    'attempt.capture_sha256': {
        'mode': 'CONSTRAINT_REQUIRED', 'families': ['abort-retry']},
}


class EmpiricalRefused(ValueError):
    pass


def _need(condition: bool, category: str) -> None:
    if not condition:
        raise EmpiricalRefused(category)


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True).encode()


def _word(value: object) -> bool:
    return (type(value) is str and
            re.fullmatch('[0-9a-f]{64}', value) is not None)


def _summary(values: list[int]) -> list[int]:
    if not values:
        return [0, 0, 0, 0, 0]
    return [len(values), min(values), max(values), sum(values),
            sum(value * value for value in values)]


def _family(exact, numeric: list[int]) -> dict:
    return {
        'exact_sha256': hashlib.sha256(_canonical(exact)).hexdigest(),
        'numeric': numeric,
    }


def _attempts(value: object, capture_sha256s: list[str],
              stream_complete: list[bool]) -> list[dict]:
    _need(type(value) is dict and set(value) == {'schema', 'attempts'} and
          value['schema'] == 'kpb-p1-passive-attempt-history/v1' and
          type(value['attempts']) is list and value['attempts'] and
          len(value['attempts']) == len(capture_sha256s) ==
              len(stream_complete),
          'p1-empirical-attempt-history-schema')
    required = {
        'attempt_id', 'retry_ordinal', 'predecessor_attempt_id',
        'start_monotonic_ns', 'end_monotonic_ns', 'outcome',
        'failure_code', 'capture_sha256',
    }
    result = []
    previous = None
    outcomes = {'COMPLETE', 'ABORTED', 'ERROR', 'REFUSED', 'CRASHED',
                'PARTIAL'}
    for ordinal, row in enumerate(value['attempts']):
        _need(type(row) is dict and set(row) == required,
              'p1-empirical-attempt-row-fields')
        try:
            attempt_id = str(uuid.UUID(row['attempt_id']))
        except (ValueError, TypeError, AttributeError):
            raise EmpiricalRefused('p1-empirical-attempt-id') from None
        _need(attempt_id == row['attempt_id'] and
              row['retry_ordinal'] == ordinal and
              row['predecessor_attempt_id'] == previous and
              type(row['start_monotonic_ns']) is int and
              type(row['end_monotonic_ns']) is int and
              0 <= row['start_monotonic_ns'] <= row['end_monotonic_ns'] and
              row['outcome'] in outcomes and
              type(row['failure_code']) is str and
              re.fullmatch('[A-Z0-9_-]{1,64}', row['failure_code']) is not None
              and _word(row['capture_sha256']),
              'p1-empirical-attempt-row')
        _need(row['capture_sha256'] == capture_sha256s[ordinal] and
              ((row['outcome'] == 'COMPLETE') ==
               stream_complete[ordinal]),
              'p1-empirical-attempt-capture-binding')
        result.append(dict(row))
        previous = attempt_id
    return result


def _frames(raw: bytes) -> tuple[list[dict], str, bytes, dict]:
    _need(type(raw) is bytes and raw, 'p1-empirical-raw-type')
    frames = []
    at = 0
    expected_sequence = 0
    next_message = 0
    current_message = None
    last_time = 0
    first_time = 0
    state = 'CLOSED_WITHOUT_END'
    tail = b''
    content = {
        'all_exact': [], 'all_lengths': [], 'all_histogram': [0] * 256,
        'mixed_exact': [], 'mixed_lengths': [],
        'mixed_histogram': [0] * 256,
    }
    data_total = [0, 0, 0]
    data_lanes = [[0, 0, 0] for _ in range(MAX_SEMANTIC)]
    projection_sha256 = None
    forks = {bytes(32)}
    while at < len(raw):
        if len(raw) - at < HEADER_BYTES:
            tail = raw[at:]
            state = 'PARTIAL_HEADER'
            break
        header = raw[at:at + HEADER_BYTES]
        at += HEADER_BYTES
        _need(header[:8] == MAGIC and header[13:16] == bytes(3),
              'p1-empirical-frame-constant')
        record_type, semantic, direction, peer, flags = header[8:13]
        monotonic_ns = struct.unpack('>Q', header[16:24])[0]
        sequence = struct.unpack('>Q', header[24:32])[0]
        message = struct.unpack('>Q', header[32:40])[0]
        chunk = struct.unpack('>I', header[40:44])[0]
        size = struct.unpack('>I', header[44:48])[0]
        fork = header[48:80]
        payload_digest = header[80:112]
        _need(record_type in range(1, 7) and
              semantic in range(1, MAX_SEMANTIC + 1) and
              direction in range(1, 4) and flags & ~3 == 0 and
              monotonic_ns > 0 and monotonic_ns >= last_time and
              sequence == expected_sequence and size <= MAX_CHUNK_BYTES,
              'p1-empirical-frame-envelope')
        if len(raw) - at < size:
            tail = header + raw[at:]
            state = 'PARTIAL_PAYLOAD'
            break
        payload = raw[at:at + size]
        at += size
        _need(hashlib.sha256(payload).digest() == payload_digest,
              'p1-empirical-payload-digest')
        first = bool(flags & 1)
        last = bool(flags & 2)
        metadata = {name: None for name in FRAME_EXACT_FIELDS
                    if name.startswith(('hello_', 'scalar_binding_',
                                        'footer_', 'seal_', 'fork_')) and
                    name != 'fork_hex'}
        if record_type == 1:
            _need(semantic == 1 and direction == 3 and peer == 0xff and
                  flags == 3 and sequence == 0 and message == 0 and
                  chunk == 0 and fork == bytes(32) and size == 332,
                  'p1-empirical-v9-hello-shape')
            try:
                attempt_text = payload[4:40].decode('ascii')
                capture_text = payload[104:140].decode('ascii')
                attempt_id = str(uuid.UUID(attempt_text))
                capture_identity = str(uuid.UUID(capture_text))
            except (UnicodeDecodeError, ValueError, TypeError, AttributeError):
                raise EmpiricalRefused('p1-empirical-v9-hello-identity') \
                    from None
            metadata.update({
                'hello_round': payload[0],
                'hello_role': payload[1],
                'hello_configured': payload[2],
                'hello_fixed_fd': payload[3],
                'hello_attempt_id': attempt_id,
                'hello_cohort_sha256': payload[40:72].hex(),
                'hello_financial_run_id': payload[72:104].hex(),
                'hello_capture_identity': capture_identity,
                'hello_source_sha256': payload[140:172].hex(),
                'hello_build_sha256': payload[172:204].hex(),
                'hello_launch_sha256': payload[204:236].hex(),
                'hello_model_preimage_sha256': payload[236:268].hex(),
                'hello_query_store_preimage_sha256': payload[268:300].hex(),
                'hello_scalar_manifest_sha256': payload[300:332].hex(),
            })
            _need(metadata['hello_round'] in (1, 2) and
                  metadata['hello_role'] == 1 and
                  metadata['hello_configured'] == 0 and
                  metadata['hello_fixed_fd'] ==
                  (23 if metadata['hello_round'] == 1 else 28) and
                  attempt_id == attempt_text and
                  capture_identity == capture_text and
                  metadata['hello_scalar_manifest_sha256'] ==
                  V9_SCALAR_CAPTURE_MANIFEST_SHA256,
                  'p1-empirical-v9-hello-binding')
        elif record_type == 2 and semantic == 17:
            _need(direction == 3 and peer == 0xff and flags == 3 and
                  fork == bytes(32) and size == 16,
                  'p1-empirical-v9-scalar-binding-shape')
            version = payload[0]
            kind = payload[1]
            site = int.from_bytes(payload[2:4], 'big')
            element_count = int.from_bytes(payload[4:12], 'big')
            _need(version == 1 and kind in (1, 2) and 1 <= site <= 22 and
                  element_count > 0 and payload[12:16] == bytes(4) and
                  ((site in V9_RANDOMNESS_SITES) == (kind == 2)),
                  'p1-empirical-v9-scalar-binding-shape')
            metadata.update({
                'scalar_binding_version': version,
                'scalar_binding_kind': kind,
                'scalar_binding_site': site,
                'scalar_binding_element_count': element_count,
            })
        elif record_type == 3:
            _need(semantic == 9 and direction == 3 and peer == 0xff and
                  flags == 3 and first and last and fork == bytes(32) and
                  size == 32 and projection_sha256 is not None and
                  payload.hex() == projection_sha256,
                  'p1-empirical-v9-projection-seal')
            metadata['seal_projection_sha256'] = payload.hex()
        elif record_type == 4:
            _need(semantic == 9 and direction == 3 and peer == 0xff and
                  flags == 3 and first and last and
                  fork == bytes(32) and size == 496,
                  'p1-empirical-v9-footer-shape')
            footer = {
                'footer_version': int.from_bytes(payload[0:4], 'big'),
                'footer_semantic_count': int.from_bytes(payload[4:8], 'big'),
                'footer_total_counters': [
                    int.from_bytes(payload[8 + 8 * index:
                                           16 + 8 * index], 'big')
                    for index in range(3)],
                'footer_lane_counters': [[
                    int.from_bytes(payload[
                        32 + 24 * lane + 8 * index:
                        40 + 24 * lane + 8 * index], 'big')
                    for index in range(3)]
                    for lane in range(MAX_SEMANTIC)],
                'footer_instrumented_bitmap':
                    int.from_bytes(payload[440:448], 'big'),
                'footer_owner_offset_bitmap':
                    int.from_bytes(payload[448:456], 'big'),
                'footer_owner_preprocessing_bitmap':
                    int.from_bytes(payload[456:464], 'big'),
                'footer_scalar_site_bitmap':
                    int.from_bytes(payload[464:472], 'big'),
                'footer_timed_frame_count':
                    int.from_bytes(payload[472:480], 'big'),
                'footer_first_monotonic_ns':
                    int.from_bytes(payload[480:488], 'big'),
                'footer_last_monotonic_ns':
                    int.from_bytes(payload[488:496], 'big'),
            }
            _need(footer['footer_version'] == 9 and
                  footer['footer_semantic_count'] == 17 and
                  footer['footer_total_counters'] == data_total and
                  footer['footer_lane_counters'] == data_lanes and
                  footer['footer_instrumented_bitmap'] == 0x1ffff and
                  footer['footer_owner_offset_bitmap'] == 7 and
                  footer['footer_owner_preprocessing_bitmap'] == 7 and
                  footer['footer_scalar_site_bitmap'] ==
                  V9_SCALAR_SITE_BITMAP and
                  footer['footer_timed_frame_count'] == sequence and
                  footer['footer_first_monotonic_ns'] == first_time and
                  footer['footer_last_monotonic_ns'] == last_time,
                  'p1-empirical-v9-footer-binding')
            metadata.update(footer)
        elif record_type == 5:
            _need(semantic == 9 and direction == 3 and peer == 0xff and
                  flags == 3 and first and last and fork == bytes(32) and
                  size == 0,
                  'p1-empirical-v9-end-shape')
        elif record_type == 6:
            parent = payload[:32]
            child = payload[32:64]
            _need(semantic == 2 and direction == 3 and peer == 0xff and
                  flags == 3 and first and last and size == 96 and
                  parent == fork and parent in forks and
                  child != bytes(32) and child not in forks,
                  'p1-empirical-v9-fork-shape')
            forks.add(child)
            metadata.update({
                'fork_parent_hex': parent.hex(),
                'fork_child_hex': child.hex(),
                'fork_suffix_sha256': payload[64:96].hex(),
            })
        if first:
            _need(current_message is None and message == next_message and
                  chunk == 0, 'p1-empirical-message-start')
            current_message = {
                'message': message,
                'record_type': record_type,
                'semantic': semantic,
                'direction': direction,
                'peer': peer,
                'fork': fork,
                'last_chunk': chunk,
                'chunks': 0,
                'bytes': 0,
                'payload': bytearray(),
            }
            next_message += 1
        else:
            _need(current_message is not None and
                  current_message['message'] == message and
                  chunk == current_message['last_chunk'] + 1,
                  'p1-empirical-message-continuation')
            _need((record_type, semantic, direction, peer, fork) ==
                  (current_message['record_type'],
                   current_message['semantic'],
                   current_message['direction'], current_message['peer'],
                   current_message['fork']),
                  'p1-empirical-message-metadata')
            current_message['last_chunk'] = chunk
        current_message['chunks'] += 1
        current_message['bytes'] += size
        current_message['payload'].extend(payload)
        frame_row = {
            'record_type': record_type,
            'semantic': semantic,
            'direction': direction,
            'peer': peer,
            'flags': flags,
            'monotonic_ns': monotonic_ns,
            'sequence': sequence,
            'message': message,
            'chunk': chunk,
            'payload_length': size,
            'fork_hex': fork.hex(),
            'payload_sha256': payload_digest.hex(),
            'payload_class': ('PEER_TRANSPORT' if semantic == 2 else
                              'OTHER_LANE'),
            **metadata,
        }
        frames.append(frame_row)
        exact_content = [semantic, direction, peer, fork.hex(),
                         payload_digest.hex(), size]
        content['all_exact'].append(exact_content)
        content['all_lengths'].append(size)
        for byte in payload:
            content['all_histogram'][byte] += 1
        if semantic == 2:
            content['mixed_exact'].append(exact_content)
            content['mixed_lengths'].append(size)
            for byte in payload:
                content['mixed_histogram'][byte] += 1
        if last:
            if record_type == 2:
                data_total[0] += 1
                data_total[1] += current_message['chunks']
                data_total[2] += current_message['bytes']
                lane = data_lanes[semantic - 1]
                lane[0] += 1
                lane[1] += current_message['chunks']
                lane[2] += current_message['bytes']
                if semantic == 9:
                    _need(projection_sha256 is None,
                          'p1-empirical-v9-projection-duplicate')
                    projection_sha256 = hashlib.sha256(
                        current_message['payload']).hexdigest()
            current_message = None
        if first_time == 0:
            first_time = monotonic_ns
        last_time = monotonic_ns
        expected_sequence += 1
        if record_type == 5:
            _need(last and current_message is None and size == 0 and
                  at == len(raw), 'p1-empirical-end-position')
            state = 'COMPLETE_END'
            break
    if state == 'CLOSED_WITHOUT_END' and current_message is not None:
        state = 'PARTIAL_MESSAGE'
    return frames, state, tail, content


def _retry_family(attempts: list[dict]) -> dict:
    outcome_codes = {
        name: index for index, name in enumerate(
            ('COMPLETE', 'ABORTED', 'ERROR', 'REFUSED', 'CRASHED',
             'PARTIAL'))}
    durations = [row['end_monotonic_ns'] - row['start_monotonic_ns']
                 for row in attempts]
    starts = [row['start_monotonic_ns'] for row in attempts]
    retry_numeric = [len(attempts)]
    retry_numeric.extend(sum(row['outcome'] == name for row in attempts)
                         for name in outcome_codes)
    retry_numeric.extend(_summary(durations))
    retry_numeric.extend(_summary(starts))
    retry_numeric.append(attempts[-1]['end_monotonic_ns'] -
                         attempts[0]['start_monotonic_ns'])
    return _family(attempts, retry_numeric)


def _exact_observation_attempt(attempt: dict, frames: list[dict],
                               stream_state: str, tail: bytes) -> dict:
    result = dict(attempt)
    result.update({
        'stream_state': stream_state,
        'partial_tail_length': len(tail),
        'partial_tail_sha256': hashlib.sha256(tail).hexdigest(),
        'frames': [dict(row) for row in frames],
    })
    return result


def _extract_one_capture(raw: bytes, attempt_history: object) -> dict:
    """Extract one attempt before fixed-width cross-retry aggregation."""
    frames, stream_state, tail, content = _frames(raw)
    capture_sha256 = hashlib.sha256(raw).hexdigest()
    attempts = _attempts(attempt_history, [capture_sha256],
                         [stream_state == 'COMPLETE_END'])
    hello_attempt_ids = [
        row['hello_attempt_id'] for row in frames
        if row['hello_attempt_id'] is not None]
    _need(len(hello_attempt_ids) <= 1 and
          (not hello_attempt_ids or
           hello_attempt_ids[0] == attempts[0]['attempt_id']),
          'p1-empirical-v9-hello-attempt-binding')

    times = [row['monotonic_ns'] for row in frames]
    timing_exact = {
        'absolute': times,
        'deltas': ([0] + [times[index] - times[index - 1]
                          for index in range(1, len(times))]),
    }
    lengths = [row['payload_length'] for row in frames]
    order_exact = [[row[name] for name in
                    ('sequence', 'message', 'chunk', 'flags',
                     'record_type', 'semantic')]
                   for row in frames]
    route_exact = [[row['direction'], row['peer'], row['fork_hex']]
                   for row in frames]
    def content_family(exact: list, lengths: list[int], histogram: list[int],
                       trailing: bytes = b'') -> dict:
        exact = list(exact)
        lengths = list(lengths)
        histogram = list(histogram)
        if trailing:
            exact.append(['PARTIAL-TAIL', hashlib.sha256(trailing).hexdigest(),
                          len(trailing)])
            lengths.append(len(trailing))
            for byte in trailing:
                histogram[byte] += 1
        return _family(exact,
                       _summary(lengths) + histogram)

    result = {
        'schema': FEATURE_SCHEMA,
        'method_sha256': METHOD_ID,
        'observer_scope': OBSERVER_SCOPE,
        'capture_sha256': capture_sha256,
        'attempt_ids': [row['attempt_id'] for row in attempts],
        'stream_state': stream_state,
        'stream_states': [stream_state],
        'frame_monotonic_bounds': ([times[0], times[-1]] if times else None),
        'constants': {
            'magic': MAGIC.decode(),
            'reserved_header_zero': True,
            'sequence_contiguous': True,
            'message_chunk_well_formed': True,
            'payload_digest_checked': True,
            'tail_bytes': len(tail),
            'tail_sha256': hashlib.sha256(tail).hexdigest(),
        },
        'exact_observations': {
            'schema': EXACT_OBSERVATION_SCHEMA,
            'source_id': 'P1_C03',
            'attempts': [_exact_observation_attempt(
                attempts[0], frames, stream_state, tail)],
        },
        'families': {
            'monotonic-timing': _family(timing_exact,
                                        _summary(times) +
                                        _summary(timing_exact['deltas'])),
            'frame-length': _family(
                {'complete_frame_payload_lengths': lengths,
                 'partial_tail_hex': tail.hex()},
                _summary(lengths) + [len(raw), len(tail)]),
            'message-chunk-order': _family(
                order_exact, _summary([value for row in order_exact
                                       for value in row])),
            'direction-peer-fork': _family(
                route_exact,
                _summary([row['direction'] for row in frames]) +
                _summary([row['peer'] for row in frames]) +
                [len({row['fork_hex'] for row in frames})]),
            'abort-retry': _retry_family(attempts),
            'mixed-peer-content': content_family(
                content['mixed_exact'], content['mixed_lengths'],
                content['mixed_histogram']),
            'all-lane-content': content_family(
                content['all_exact'], content['all_lengths'],
                content['all_histogram'], tail),
        },
    }
    return result


def _aggregate_numeric(vectors: list[list[int]]) -> list[int]:
    width = len(vectors[0])
    _need(width > 0 and all(len(row) == width for row in vectors),
          'p1-empirical-retry-feature-width')
    result = [len(vectors)]
    for index in range(width):
        result.extend(_summary([row[index] for row in vectors]))
    return result


def extract_attempt_sequence(raw_captures: object,
                             attempt_history: object) -> dict:
    """Extract every failed/partial retry and the final attempt together."""
    _need(type(raw_captures) is list and raw_captures and
          all(type(raw) is bytes and raw for raw in raw_captures) and
          type(attempt_history) is dict and
          type(attempt_history.get('attempts')) is list and
          len(raw_captures) == len(attempt_history['attempts']),
          'p1-empirical-retry-captures-required')
    individual = []
    for raw, original in zip(raw_captures, attempt_history['attempts']):
        _need(type(original) is dict,
              'p1-empirical-attempt-row-fields')
        normalized = dict(original)
        normalized['retry_ordinal'] = 0
        normalized['predecessor_attempt_id'] = None
        individual.append(_extract_one_capture(raw, {
            'schema': 'kpb-p1-passive-attempt-history/v1',
            'attempts': [normalized],
        }))
    capture_sha256s = [hashlib.sha256(raw).hexdigest()
                       for raw in raw_captures]
    stream_states = [row['stream_state'] for row in individual]
    attempts = _attempts(
        attempt_history, capture_sha256s,
        [state == 'COMPLETE_END' for state in stream_states])
    _need(all(row['outcome'] != 'COMPLETE' for row in attempts[:-1]) and
          all(attempts[index - 1]['end_monotonic_ns'] <=
              attempts[index]['start_monotonic_ns']
              for index in range(1, len(attempts))),
          'p1-empirical-retry-order')
    for attempt, extracted in zip(attempts, individual):
        bounds = extracted['frame_monotonic_bounds']
        _need(bounds is None or
              attempt['start_monotonic_ns'] <= bounds[0] <= bounds[1] <=
              attempt['end_monotonic_ns'],
              'p1-empirical-attempt-frame-time-binding')

    families = {}
    family_names = tuple(sorted(individual[0]['families']))
    _need(all(tuple(sorted(row['families'])) == family_names
              for row in individual), 'p1-empirical-family-catalog')
    for family_name in family_names:
        if family_name == 'abort-retry':
            families[family_name] = _retry_family(attempts)
            continue
        exact = [[attempt['attempt_id'], extracted['stream_state'],
                  extracted['families'][family_name]['exact_sha256']]
                 for attempt, extracted in zip(attempts, individual)]
        numeric = _aggregate_numeric([
            extracted['families'][family_name]['numeric']
            for extracted in individual])
        families[family_name] = _family(exact, numeric)

    exact_attempts = []
    for attempt, extracted in zip(attempts, individual):
        observed = dict(extracted['exact_observations']['attempts'][0])
        for name in (
                'attempt_id', 'retry_ordinal', 'predecessor_attempt_id',
                'start_monotonic_ns', 'end_monotonic_ns', 'outcome',
                'failure_code', 'capture_sha256'):
            observed[name] = attempt[name]
        exact_attempts.append(observed)
    exact_observations = {
        'schema': EXACT_OBSERVATION_SCHEMA,
        'source_id': 'P1_C03',
        'attempts': exact_attempts,
    }
    exact_observations['observation_sha256'] = hashlib.sha256(
        _canonical(exact_observations)).hexdigest()

    bundle_sha256 = hashlib.sha256(_canonical(capture_sha256s)).hexdigest()
    return {
        'schema': FEATURE_SCHEMA,
        'method_sha256': METHOD_ID,
        'observer_scope': OBSERVER_SCOPE,
        'capture_sha256': (capture_sha256s[0] if len(capture_sha256s) == 1
                           else bundle_sha256),
        'capture_sha256s': capture_sha256s,
        'attempt_ids': [row['attempt_id'] for row in attempts],
        'stream_state': (stream_states[0] if len(stream_states) == 1 else
                         'ATTEMPT_SEQUENCE'),
        'stream_states': stream_states,
        'constants': {
            'magic': MAGIC.decode(),
            'reserved_header_zero': True,
            'sequence_contiguous': True,
            'message_chunk_well_formed': True,
            'payload_digest_checked': True,
            'tail_bytes': sum(row['constants']['tail_bytes']
                              for row in individual),
            'tail_sha256': hashlib.sha256(_canonical([
                row['constants']['tail_sha256'] for row in individual
            ])).hexdigest(),
        },
        'exact_observations': exact_observations,
        'families': families,
    }


def extract_c03_features(raw: bytes, attempt_history: object) -> dict:
    """Extract exactly one attempt; retries require all raw capture leaves."""
    _need(type(attempt_history) is dict and
          type(attempt_history.get('attempts')) is list and
          len(attempt_history['attempts']) == 1,
          'p1-empirical-retry-captures-required')
    return extract_attempt_sequence([raw], attempt_history)


def _identifier(value: object) -> bool:
    return (type(value) is str and
            re.fullmatch('[A-Za-z0-9_.:-]{1,128}', value) is not None)


def _structural_identifier(value: object) -> bool:
    return (_identifier(value) and
            re.search('truth|correct|ground[-_]?truth|actual[-_]?owner',
                      value, re.IGNORECASE) is None)


def _ref_key(value: dict) -> str:
    if value['kind'] == 'ATTEMPT':
        return 'ATTEMPT:' + value['attempt_id']
    return 'FRAME:' + value['attempt_id'] + ':' + str(value['sequence'])


def _observation_index(features: object) -> tuple[dict, dict, dict]:
    _need(type(features) is dict and features.get('schema') == FEATURE_SCHEMA
          and features.get('method_sha256') == METHOD_ID and
          type(features.get('exact_observations')) is dict,
          'p1-empirical-exact-observations')
    observations = features['exact_observations']
    _need(set(observations) == {
              'schema', 'source_id', 'attempts', 'observation_sha256'} and
          observations['schema'] == EXACT_OBSERVATION_SCHEMA and
          observations['source_id'] == 'P1_C03' and
          _word(observations['observation_sha256']) and
          type(observations['attempts']) is list and
          observations['attempts'], 'p1-empirical-exact-observations')
    selected = dict(observations)
    digest = selected.pop('observation_sha256')
    _need(hashlib.sha256(_canonical(selected)).hexdigest() == digest,
          'p1-empirical-exact-observation-digest')
    rows = {}
    attempts = {}
    frame_order = {}
    for attempt in observations['attempts']:
        expected = set(ATTEMPT_EXACT_FIELDS) | {'frames'}
        _need(type(attempt) is dict and set(attempt) == expected,
              'p1-empirical-observed-attempt-fields')
        reference = {'kind': 'ATTEMPT', 'attempt_id': attempt['attempt_id']}
        key = _ref_key(reference)
        _need(key not in rows and type(attempt['frames']) is list,
              'p1-empirical-observed-attempt-duplicate')
        rows[key] = attempt
        attempts[attempt['attempt_id']] = attempt
        for index, frame in enumerate(attempt['frames']):
            _need(type(frame) is dict and set(frame) ==
                  set(FRAME_EXACT_FIELDS) | {'payload_class'},
                  'p1-empirical-observed-frame-fields')
            frame_ref = {
                'kind': 'FRAME', 'attempt_id': attempt['attempt_id'],
                'sequence': frame['sequence'],
            }
            frame_key = _ref_key(frame_ref)
            _need(frame_key not in rows and frame['sequence'] == index and
                  frame['payload_class'] in
                  ('PEER_TRANSPORT', 'OTHER_LANE'),
                  'p1-empirical-observed-frame-duplicate')
            rows[frame_key] = frame
            frame_order[frame_key] = (attempt['retry_ordinal'], index)
    return rows, attempts, frame_order


def _valid_event_field(kind: str, name: str, value: object) -> bool:
    frame_integers = {
        'record_type', 'semantic', 'direction', 'peer', 'flags',
        'monotonic_ns', 'sequence', 'message', 'chunk', 'payload_length',
        'hello_round', 'hello_role', 'hello_configured', 'hello_fixed_fd',
        'scalar_binding_version', 'scalar_binding_kind',
        'scalar_binding_site', 'scalar_binding_element_count',
        'footer_version', 'footer_semantic_count',
        'footer_instrumented_bitmap', 'footer_owner_offset_bitmap',
        'footer_owner_preprocessing_bitmap', 'footer_scalar_site_bitmap',
        'footer_timed_frame_count', 'footer_first_monotonic_ns',
        'footer_last_monotonic_ns'}
    if kind == 'FRAME':
        if name == 'footer_total_counters':
            return (type(value) is list and len(value) == 3 and
                    all(type(item) is int and item >= 0 for item in value))
        if name == 'footer_lane_counters':
            return (type(value) is list and len(value) == MAX_SEMANTIC and
                    all(type(row) is list and len(row) == 3 and
                        all(type(item) is int and item >= 0 for item in row)
                        for row in value))
        if name in frame_integers:
            return type(value) is int and value >= 0
        if name in (
                'fork_hex', 'payload_sha256', 'hello_cohort_sha256',
                'hello_financial_run_id', 'hello_source_sha256',
                'hello_build_sha256', 'hello_launch_sha256',
                'hello_model_preimage_sha256',
                'hello_query_store_preimage_sha256',
                'hello_scalar_manifest_sha256',
                'seal_projection_sha256', 'fork_parent_hex',
                'fork_child_hex', 'fork_suffix_sha256'):
            return _word(value)
        if name in ('hello_attempt_id', 'hello_capture_identity'):
            try:
                return (type(value) is str and
                        str(uuid.UUID(value)) == value)
            except (ValueError, TypeError, AttributeError):
                return False
        return name == 'payload_literal_hex' and type(value) is str
    if name == 'attempt_id':
        try:
            return type(value) is str and str(uuid.UUID(value)) == value
        except (ValueError, TypeError, AttributeError):
            return False
    if name == 'predecessor_attempt_id':
        return value is None or _valid_event_field(
            kind, 'attempt_id', value)
    if name in ('retry_ordinal', 'start_monotonic_ns', 'end_monotonic_ns',
                'partial_tail_length'):
        return type(value) is int and value >= 0
    if name in ('capture_sha256', 'partial_tail_sha256'):
        return _word(value)
    if name == 'outcome':
        return value in {
            'COMPLETE', 'ABORTED', 'ERROR', 'REFUSED', 'CRASHED', 'PARTIAL'}
    if name == 'failure_code':
        return (type(value) is str and
                re.fullmatch('[A-Z0-9_-]{1,64}', value) is not None)
    if name == 'stream_state':
        return value in {
            'COMPLETE_END', 'PARTIAL_HEADER', 'PARTIAL_PAYLOAD',
            'PARTIAL_MESSAGE', 'CLOSED_WITHOUT_END'}
    return False


def _event_catalog(value: object, p1_source_id: str,
                   p1_capture_sha256: str) -> dict:
    _need(type(value) is list and value,
          'p1-empirical-within-run-events')
    result = {}
    source_ranks = set()
    source_bindings = {}
    for event in value:
        _need(type(event) is dict and set(event) == {
                  'event_id', 'source_id', 'source_role_kind',
                  'source_round', 'source_record_root_sha256',
                  'structural_identity', 'clock_domain_id', 'source_rank',
                  'kind', 'fields'} and _identifier(event['event_id']) and
              _identifier(event['source_id']) and
              event['source_id'] != p1_source_id and
              event['source_role_kind'] in {
                  'public-projection', 'terminal-history',
                  'dispatcher-capture', 'colluder-wallet-capture'} and
              event['source_round'] in (1, 2) and
              _word(event['source_record_root_sha256']) and
              event['source_record_root_sha256'] != p1_capture_sha256 and
              _structural_identifier(event['structural_identity']) and
              _identifier(event['clock_domain_id']) and
              type(event['source_rank']) is int and
              event['source_rank'] >= 0 and
              event['kind'] in ('FRAME', 'ATTEMPT') and
              type(event['fields']) is dict,
              'p1-empirical-within-run-event')
        binding = (
            event['source_role_kind'], event['source_round'],
            event['source_record_root_sha256'], event['clock_domain_id'])
        if event['source_id'] in source_bindings:
            _need(source_bindings[event['source_id']] == binding,
                  'p1-empirical-within-run-source-binding')
        else:
            source_bindings[event['source_id']] = binding
        allowed = set(FRAME_EXACT_FIELDS if event['kind'] == 'FRAME' else
                      ATTEMPT_EXACT_FIELDS) | {'payload_literal_hex'}
        _need(event['event_id'] not in result and
              set(event['fields']) <= allowed and
              all(_valid_event_field(event['kind'], name, item)
                  for name, item in event['fields'].items()) and
              (event['source_id'], event['source_rank']) not in source_ranks,
              'p1-empirical-within-run-event-duplicate')
        if 'payload_literal_hex' in event['fields']:
            literal = event['fields']['payload_literal_hex']
            _need(event['kind'] == 'FRAME' and type(literal) is str and
                  len(literal) % 2 == 0 and
                  re.fullmatch('[0-9a-f]*', literal) is not None,
                  'p1-empirical-within-run-literal')
            literal_bytes = bytes.fromhex(literal)
            _need(event['fields'].get('payload_length') == len(literal_bytes)
                  and event['fields'].get('payload_sha256') ==
                  hashlib.sha256(literal_bytes).hexdigest(),
                  'p1-empirical-within-run-literal-binding')
        result[event['event_id']] = event
        source_ranks.add((event['source_id'], event['source_rank']))
    return result


def _candidate_catalog(value: object, events: dict, rows: dict,
                       p1_clock_domain_id: str) -> tuple[list[dict], dict]:
    _need(type(value) is list and len(value) == 2,
          'p1-empirical-structural-candidates')
    result = []
    common_signature = None
    mapping_keys = None
    mapping_values = None
    mappings = []
    for candidate in value:
        _need(type(candidate) is dict and set(candidate) == {
                  'mapping_id', 'structural_mapping', 'joins'} and
              _structural_identifier(candidate['mapping_id']) and
              type(candidate['structural_mapping']) is dict and
              candidate['structural_mapping'] and
              all(_structural_identifier(key) and
                  _structural_identifier(item)
                  for key, item in candidate['structural_mapping'].items()) and
              type(candidate['joins']) is list and candidate['joins'],
              'p1-empirical-structural-candidate')
        keys = set(candidate['structural_mapping'])
        values = sorted(candidate['structural_mapping'].values())
        if mapping_keys is None:
            mapping_keys, mapping_values = keys, values
        _need(keys == mapping_keys and values == mapping_values,
              'p1-empirical-structural-mapping-domain')
        mappings.append(candidate['structural_mapping'])
        joins = {}
        signature = []
        for join in candidate['joins']:
            _need(type(join) is dict and set(join) == {
                      'join_id', 'structural_key', 'p1_ref', 'event_id',
                      'exact_fields'} and
                  _identifier(join['join_id']) and
                  _structural_identifier(join['structural_key']) and
                  type(join['p1_ref']) is dict and
                  join['p1_ref'].get('kind') in ('FRAME', 'ATTEMPT') and
                  _identifier(join['p1_ref'].get('attempt_id')) and
                  _identifier(join['event_id']) and
                  type(join['exact_fields']) is list and
                  len(join['exact_fields']) ==
                  len(set(join['exact_fields'])),
                  'p1-empirical-within-run-join')
            expected_ref_fields = ({'kind', 'attempt_id', 'sequence'}
                                   if join['p1_ref']['kind'] == 'FRAME' else
                                   {'kind', 'attempt_id'})
            allowed_fields = (set(FRAME_EXACT_FIELDS)
                              if join['p1_ref']['kind'] == 'FRAME' else
                              set(ATTEMPT_EXACT_FIELDS))
            ref_key = _ref_key(join['p1_ref'])
            _need(set(join['p1_ref']) == expected_ref_fields and
                  ref_key in rows and join['event_id'] in events and
                  events[join['event_id']]['kind'] ==
                  join['p1_ref']['kind'] and
                  set(join['exact_fields']) <= allowed_fields and
                  set(join['exact_fields']) <=
                  set(events[join['event_id']]['fields']) and
                  join['structural_key'] in
                  candidate['structural_mapping'] and
                  candidate['structural_mapping'][join['structural_key']] ==
                  events[join['event_id']]['structural_identity'] and
                  join['join_id'] not in joins,
                  'p1-empirical-within-run-join-binding')
            if set(join['exact_fields']) & TIME_FIELDS:
                _need(events[join['event_id']]['clock_domain_id'] ==
                      p1_clock_domain_id,
                      'p1-empirical-cross-clock-exact-time')
            joins[join['join_id']] = join
            signature.append((join['join_id'], _canonical(join['p1_ref']),
                              join['structural_key'],
                              tuple(sorted(join['exact_fields']))))
        _need({join['structural_key'] for join in joins.values()} == keys,
              'p1-empirical-structural-edge-coverage')
        signature = sorted(signature)
        if common_signature is None:
            common_signature = signature
        _need(signature == common_signature,
              'p1-empirical-candidate-join-asymmetry')
        result.append({**candidate, '_joins': joins})
    _need(result[0]['mapping_id'] != result[1]['mapping_id'] and
          mappings[0] != mappings[1],
          'p1-empirical-structural-candidates-distinct')
    provenance_fields = (
        'source_id', 'source_role_kind', 'source_round',
        'source_record_root_sha256', 'clock_domain_id', 'kind')
    for join_id in result[0]['_joins']:
        left = events[result[0]['_joins'][join_id]['event_id']]
        right = events[result[1]['_joins'][join_id]['event_id']]
        _need(all(left[name] == right[name] for name in provenance_fields),
              'p1-empirical-candidate-source-asymmetry')
    return result, {row[0]: row for row in common_signature}


def _rank_catalog(value: object, join_signature: dict) -> list[dict]:
    _need(type(value) is list and value, 'p1-empirical-rank-tests')
    result = []
    seen = set()
    for row in value:
        _need(type(row) is dict and set(row) == {
                  'rank_id', 'join_ids', 'field'} and
              _identifier(row['rank_id']) and row['rank_id'] not in seen and
              type(row['join_ids']) is list and
              len(row['join_ids']) >= 2 and
              len(row['join_ids']) == len(set(row['join_ids'])) and
              set(row['join_ids']) <= set(join_signature) and
              row['field'] in RANK_FIELDS,
              'p1-empirical-rank-test')
        result.append(row)
        seen.add(row['rank_id'])
    _need(any(row['field'] == 'source_order' for row in result),
          'p1-empirical-source-order-rank-required')
    return result


def _timing_catalog(value: object, join_signature: dict) -> list[dict]:
    _need(type(value) is list and value,
          'p1-empirical-timing-tests')
    result = []
    seen = set()
    for row in value:
        _need(type(row) is dict and set(row) == {
                  'timing_id', 'join_ids', 'field', 'metric'} and
              _identifier(row['timing_id']) and
              row['timing_id'] not in seen and
              type(row['join_ids']) is list and row['join_ids'] and
              len(row['join_ids']) == len(set(row['join_ids'])) and
              set(row['join_ids']) <= set(join_signature) and
              row['field'] in TIME_FIELDS and
              row['metric'] == 'ABSOLUTE_PAIR_DELTA',
              'p1-empirical-timing-test')
        result.append(row)
        seen.add(row['timing_id'])
    return result


def _expected_field_tokens(observations: dict) -> dict[str, set[str]]:
    expected = {name: set() for name in FIELD_DISPOSITIONS}
    direct_frame = {
        'record_type': 'header.record_type',
        'semantic': 'header.semantic',
        'direction': 'header.direction',
        'peer': 'header.peer',
        'flags': 'header.flags',
        'monotonic_ns': 'header.monotonic_ns',
        'sequence': 'header.sequence',
        'message': 'header.message',
        'chunk': 'header.chunk',
        'payload_length': 'header.payload_length',
        'fork_hex': 'header.fork',
        'payload_sha256': 'header.payload_sha256',
        'hello_model_preimage_sha256':
            'payload.hello.model_preimage_sha256',
        'hello_query_store_preimage_sha256':
            'payload.hello.query_store_preimage_sha256',
        'hello_scalar_manifest_sha256':
            'payload.hello.scalar_manifest_sha256',
        'seal_projection_sha256': 'payload.projection_seal',
        'fork_parent_hex': 'payload.fork_binding',
        'fork_child_hex': 'payload.fork_binding',
        'fork_suffix_sha256': 'payload.fork_binding',
    }
    for name in (
            'hello_round', 'hello_role', 'hello_configured',
            'hello_fixed_fd', 'hello_attempt_id', 'hello_cohort_sha256',
            'hello_financial_run_id', 'hello_capture_identity',
            'hello_source_sha256', 'hello_build_sha256',
            'hello_launch_sha256'):
        direct_frame[name] = (
            'payload.hello.source_build_launch_role_binding')
    for name in (
            'scalar_binding_version', 'scalar_binding_kind',
            'scalar_binding_site', 'scalar_binding_element_count'):
        direct_frame[name] = (
            'payload.scalar_binding.version_kind_site_count')
    for name in (
            'footer_version', 'footer_semantic_count',
            'footer_total_counters', 'footer_lane_counters',
            'footer_instrumented_bitmap', 'footer_owner_offset_bitmap',
            'footer_owner_preprocessing_bitmap',
            'footer_scalar_site_bitmap', 'footer_timed_frame_count',
            'footer_first_monotonic_ns', 'footer_last_monotonic_ns'):
        direct_frame[name] = 'payload.footer.v9_counters_and_bitmaps'
    direct_attempt = {
        'attempt_id': 'attempt.attempt_id',
        'retry_ordinal': 'attempt.retry_ordinal',
        'predecessor_attempt_id': 'attempt.predecessor_attempt_id',
        'start_monotonic_ns': 'attempt.start_monotonic_ns',
        'end_monotonic_ns': 'attempt.end_monotonic_ns',
        'outcome': 'attempt.outcome',
        'failure_code': 'attempt.failure_code',
        'capture_sha256': 'attempt.capture_sha256',
    }
    for attempt in observations['attempts']:
        attempt_ref = _ref_key({
            'kind': 'ATTEMPT', 'attempt_id': attempt['attempt_id']})
        for field, path in direct_attempt.items():
            expected[path].add(attempt_ref + ':' + field)
        if attempt['partial_tail_length']:
            for field in ('partial_tail_length', 'partial_tail_sha256'):
                expected['partial.tail'].add(attempt_ref + ':' + field)
        for frame in attempt['frames']:
            frame_ref = _ref_key({
                'kind': 'FRAME', 'attempt_id': attempt['attempt_id'],
                'sequence': frame['sequence']})
            for field, path in direct_frame.items():
                if frame[field] is not None:
                    expected[path].add(frame_ref + ':' + field)
            payload_path = ('payload.peer_transport'
                            if frame['payload_class'] == 'PEER_TRANSPORT' else
                            'payload.other_lane')
            expected[payload_path].add(frame_ref + ':payload_sha256')
    return expected


def _field_paths(row: dict, field: str, ref_key: str) -> list[tuple[str, str]]:
    if field in FRAME_EXACT_FIELDS:
        direct = {
            'record_type': 'header.record_type',
            'semantic': 'header.semantic',
            'direction': 'header.direction', 'peer': 'header.peer',
            'flags': 'header.flags', 'monotonic_ns': 'header.monotonic_ns',
            'sequence': 'header.sequence', 'message': 'header.message',
            'chunk': 'header.chunk', 'payload_length': 'header.payload_length',
            'fork_hex': 'header.fork',
            'payload_sha256': 'header.payload_sha256',
            'hello_model_preimage_sha256':
                'payload.hello.model_preimage_sha256',
            'hello_query_store_preimage_sha256':
                'payload.hello.query_store_preimage_sha256',
            'hello_scalar_manifest_sha256':
                'payload.hello.scalar_manifest_sha256',
            'seal_projection_sha256': 'payload.projection_seal',
            'fork_parent_hex': 'payload.fork_binding',
            'fork_child_hex': 'payload.fork_binding',
            'fork_suffix_sha256': 'payload.fork_binding',
        }
        for name in (
                'hello_round', 'hello_role', 'hello_configured',
                'hello_fixed_fd', 'hello_attempt_id',
                'hello_cohort_sha256', 'hello_financial_run_id',
                'hello_capture_identity', 'hello_source_sha256',
                'hello_build_sha256', 'hello_launch_sha256'):
            direct[name] = (
                'payload.hello.source_build_launch_role_binding')
        for name in (
                'scalar_binding_version', 'scalar_binding_kind',
                'scalar_binding_site', 'scalar_binding_element_count'):
            direct[name] = (
                'payload.scalar_binding.version_kind_site_count')
        for name in (
                'footer_version', 'footer_semantic_count',
                'footer_total_counters', 'footer_lane_counters',
                'footer_instrumented_bitmap', 'footer_owner_offset_bitmap',
                'footer_owner_preprocessing_bitmap',
                'footer_scalar_site_bitmap', 'footer_timed_frame_count',
                'footer_first_monotonic_ns', 'footer_last_monotonic_ns'):
            direct[name] = 'payload.footer.v9_counters_and_bitmaps'
        result = [(direct[field], ref_key + ':' + field)]
        if field == 'payload_sha256':
            result.append((
                'payload.peer_transport'
                if row['payload_class'] == 'PEER_TRANSPORT' else
                'payload.other_lane', ref_key + ':' + field))
        return result
    direct = {
        'attempt_id': 'attempt.attempt_id',
        'retry_ordinal': 'attempt.retry_ordinal',
        'predecessor_attempt_id': 'attempt.predecessor_attempt_id',
        'start_monotonic_ns': 'attempt.start_monotonic_ns',
        'end_monotonic_ns': 'attempt.end_monotonic_ns',
        'outcome': 'attempt.outcome', 'failure_code': 'attempt.failure_code',
        'capture_sha256': 'attempt.capture_sha256',
        'partial_tail_length': 'partial.tail',
        'partial_tail_sha256': 'partial.tail',
    }
    return ([(direct[field], ref_key + ':' + field)]
            if field in direct else [])


def _rank_values(candidate: dict, rank_test: dict, rows: dict,
                 frame_order: dict, events: dict) -> tuple[list, list, str]:
    p1_values = []
    event_values = []
    source_ids = set()
    for join_id in rank_test['join_ids']:
        join = candidate['_joins'][join_id]
        ref_key = _ref_key(join['p1_ref'])
        observed = rows[ref_key]
        event = events[join['event_id']]
        source_ids.add(event['source_id'])
        if rank_test['field'] == 'source_order':
            p1_values.append(
                frame_order[ref_key] if ref_key in frame_order else
                (observed['retry_ordinal'], 0))
            event_values.append(event['source_rank'])
        else:
            _need(rank_test['field'] in observed and
                  rank_test['field'] in event['fields'],
                  'p1-empirical-rank-field')
            p1_values.append(observed[rank_test['field']])
            event_values.append(event['fields'][rank_test['field']])
    _need(len(source_ids) == 1, 'p1-empirical-cross-source-rank')
    return p1_values, event_values, next(iter(source_ids))


def _relative_order(values: list) -> list[int] | None:
    if len(set(values)) != len(values):
        return None
    ordered = {value: index for index, value in enumerate(sorted(values))}
    return [ordered[value] for value in values]


def apply_within_run_constraints(features: object, plan: object) -> dict:
    """Apply source-derived structural joins; a capsule bridge must mint plan.

    This standalone function validates and evaluates a plan but cannot attest
    that its events came from the ten sealed producer leaves.  Consequently
    its receipt is never gate-authorizing without that external capability.
    """
    rows, _, frame_order = _observation_index(features)
    _need(type(plan) is dict and set(plan) == {
              'schema', 'trial_id', 'source_manifest_sha256',
              'p1_capture_sha256', 'p1_source_id', 'p1_clock_domain_id',
              'events', 'rank_tests', 'timing_tests', 'candidates'} and
          plan['schema'] == WITHIN_RUN_PLAN_SCHEMA and
          _word(plan['source_manifest_sha256']) and
          plan['p1_capture_sha256'] == features['capture_sha256'] and
          _identifier(plan['p1_source_id']) and
          _identifier(plan['p1_clock_domain_id']),
          'p1-empirical-within-run-plan')
    try:
        selected_trial = str(uuid.UUID(plan['trial_id']))
    except (ValueError, TypeError, AttributeError):
        raise EmpiricalRefused('p1-empirical-within-run-trial') from None
    _need(selected_trial == plan['trial_id'],
          'p1-empirical-within-run-trial')
    _need(plan['p1_source_id'] ==
          features['exact_observations']['source_id'],
          'p1-empirical-p1-source-binding')
    events = _event_catalog(
        plan['events'], plan['p1_source_id'], features['capture_sha256'])
    candidates, join_signature = _candidate_catalog(
        plan['candidates'], events, rows, plan['p1_clock_domain_id'])
    rank_tests = _rank_catalog(plan['rank_tests'], join_signature)
    timing_tests = _timing_catalog(plan['timing_tests'], join_signature)
    observations = features['exact_observations']
    expected = _expected_field_tokens(observations)
    compared = {name: {candidate['mapping_id']: set()
                       for candidate in candidates}
                for name in FIELD_DISPOSITIONS}
    positive = {name: set() for name in FIELD_DISPOSITIONS}
    mismatches = {name: 0 for name in FIELD_DISPOSITIONS}
    ambiguous = {name: 0 for name in FIELD_DISPOSITIONS}
    modes = {name: set() for name in FIELD_DISPOSITIONS}
    candidate_results = []
    for candidate in candidates:
        result = {
            'mapping_id': candidate['mapping_id'],
            'structural_mapping': candidate['structural_mapping'],
            'exact_results': [], 'rank_results': [], 'timing_results': [],
        }
        retained = True
        for join_id in sorted(candidate['_joins']):
            join = candidate['_joins'][join_id]
            ref_key = _ref_key(join['p1_ref'])
            observed = rows[ref_key]
            event = events[join['event_id']]
            for field in sorted(join['exact_fields']):
                matched = (type(observed[field]) is
                           type(event['fields'][field]) and
                           observed[field] == event['fields'][field])
                mode = ('EXACT_COMMON_CLOCK' if field in TIME_FIELDS else
                        'EXACT_LITERAL_DIGEST'
                        if field == 'payload_sha256' and
                        'payload_literal_hex' in event['fields'] else
                        'EXACT_FIELD')
                paths = _field_paths(observed, field, ref_key)
                for path, token in paths:
                    compared[path][candidate['mapping_id']].add(token)
                    modes[path].add(mode)
                    if matched:
                        positive[path].add((candidate['mapping_id'], token))
                    else:
                        mismatches[path] += 1
                result['exact_results'].append({
                    'join_id': join_id, 'event_id': join['event_id'],
                    'field': field, 'mode': mode, 'matched': matched,
                })
                retained = retained and matched
        for rank_test in rank_tests:
            p1_values, event_values, source_id = _rank_values(
                candidate, rank_test, rows, frame_order, events)
            p1_order = _relative_order(p1_values)
            event_order = _relative_order(event_values)
            if p1_order is None or event_order is None:
                rank_status = 'AMBIGUOUS'
            else:
                rank_status = ('MATCH' if p1_order == event_order else
                               'MISMATCH')
                retained = retained and rank_status == 'MATCH'
            rank_paths = []
            if rank_test['field'] != 'source_order':
                for join_id in rank_test['join_ids']:
                    join = candidate['_joins'][join_id]
                    ref_key = _ref_key(join['p1_ref'])
                    observed = rows[ref_key]
                    for path, token in _field_paths(
                            observed, rank_test['field'], ref_key):
                        compared[path][candidate['mapping_id']].add(token)
                        modes[path].add('RANK_WITHIN_SOURCE')
                        rank_paths.append((path, token))
                        if rank_status == 'MATCH':
                            positive[path].add(
                                (candidate['mapping_id'], token))
                        elif rank_status == 'MISMATCH':
                            mismatches[path] += 1
                        else:
                            ambiguous[path] += 1
            result['rank_results'].append({
                'rank_id': rank_test['rank_id'],
                'field': rank_test['field'], 'source_id': source_id,
                'p1_order': p1_order, 'event_order': event_order,
                'status': rank_status,
                'used_for_candidate_filter': True,
            })
        result['retained'] = retained
        candidate_results.append(result)

    timing_missing = False
    result_by_mapping = {row['mapping_id']: row for row in candidate_results}
    for timing_test in timing_tests:
        timing_rows = {}
        for candidate in candidates:
            signed_deltas = []
            timing_paths = []
            missing_common_clock = False
            for join_id in timing_test['join_ids']:
                join = candidate['_joins'][join_id]
                ref_key = _ref_key(join['p1_ref'])
                observed = rows[ref_key]
                event = events[join['event_id']]
                if (event['clock_domain_id'] !=
                        plan['p1_clock_domain_id'] or
                        timing_test['field'] not in observed or
                        timing_test['field'] not in event['fields']):
                    missing_common_clock = True
                    continue
                signed_deltas.append(
                    event['fields'][timing_test['field']] -
                    observed[timing_test['field']])
                for path, token in _field_paths(
                        observed, timing_test['field'], ref_key):
                    compared[path][candidate['mapping_id']].add(token)
                    modes[path].add('COMMON_CLOCK_ABSOLUTE_DISTANCE')
                    timing_paths.append((path, token))
            timing_rows[candidate['mapping_id']] = {
                'signed_deltas': signed_deltas,
                'absolute_distance': sum(abs(value)
                                         for value in signed_deltas),
                'paths': timing_paths,
                'missing_common_clock': missing_common_clock,
            }
        if any(row['missing_common_clock'] for row in timing_rows.values()):
            timing_missing = True
            for candidate in candidates:
                row = timing_rows[candidate['mapping_id']]
                result_by_mapping[candidate['mapping_id']][
                    'timing_results'].append({
                        'timing_id': timing_test['timing_id'],
                        'field': timing_test['field'],
                        'metric': timing_test['metric'],
                        'signed_deltas': row['signed_deltas'],
                        'absolute_distance': None,
                        'status': 'MISSING_COMMON_CLOCK',
                        'used_for_candidate_filter': False,
                    })
            continue
        distances = {mapping_id: row['absolute_distance']
                     for mapping_id, row in timing_rows.items()}
        minimum = min(distances.values())
        winners = {mapping_id for mapping_id, value in distances.items()
                   if value == minimum}
        unique = len(winners) == 1
        for candidate in candidates:
            mapping_id = candidate['mapping_id']
            row = timing_rows[mapping_id]
            status = ('CLOSER' if unique and mapping_id in winners else
                      'FARTHER' if unique else 'TIE')
            for path, token in row['paths']:
                if status == 'CLOSER':
                    positive[path].add((mapping_id, token))
                elif status == 'FARTHER':
                    mismatches[path] += 1
                else:
                    ambiguous[path] += 1
            if status == 'FARTHER':
                result_by_mapping[mapping_id]['retained'] = False
            result_by_mapping[mapping_id]['timing_results'].append({
                'timing_id': timing_test['timing_id'],
                'field': timing_test['field'],
                'metric': timing_test['metric'],
                'signed_deltas': row['signed_deltas'],
                'absolute_distance': row['absolute_distance'],
                'status': status,
                'used_for_candidate_filter': True,
            })

    field_status = {}
    incomplete = timing_missing
    for path, disposition in FIELD_DISPOSITIONS.items():
        if disposition['mode'] == 'CONSTANT_PUBLIC':
            field_status[path] = {
                'status': 'CONSTANT_PUBLIC',
                'check': disposition['check'],
                'expected_observation_count': 0,
                'compared_per_candidate': 0,
                'positive_match_count': 0,
                'mismatch_count': 0,
                'ambiguous_count': 0,
                'comparison_modes': [],
                'used_for_candidate_filter': False,
            }
            if 'value_sha256' in disposition:
                field_status[path]['value_sha256'] = (
                    disposition['value_sha256'])
            continue
        expected_tokens = expected[path]
        if not expected_tokens:
            field_status[path] = {
                'status': 'NOT_PRESENT_IN_CAPTURE',
                'expected_observation_count': 0,
                'compared_per_candidate': 0,
                'positive_match_count': 0,
                'mismatch_count': 0,
                'ambiguous_count': 0,
                'comparison_modes': [],
                'used_for_candidate_filter': False,
            }
            continue
        candidate_counts = [
            len(compared[path][row['mapping_id']] & expected_tokens)
            for row in candidates]
        full_coverage = all(
            expected_tokens <= compared[path][row['mapping_id']]
            for row in candidates)
        status = ('CONSTRAINT_MODELED' if full_coverage else
                  'UNMODELED')
        incomplete = incomplete or status == 'UNMODELED'
        field_status[path] = {
            'status': status,
            'expected_observation_count': len(expected_tokens),
            'compared_per_candidate': min(candidate_counts),
            'positive_match_count': len(positive[path]),
            'mismatch_count': mismatches[path],
            'ambiguous_count': ambiguous[path],
            'comparison_modes': sorted(modes[path]),
            'used_for_candidate_filter': bool(modes[path]),
        }
    retained_ids = [row['mapping_id'] for row in candidate_results
                    if row['retained']]
    if incomplete:
        status = 'UNQUALIFIED_MISSING_WITHIN_RUN_CONSTRAINT'
    elif not retained_ids:
        status = 'UNQUALIFIED_NO_STRUCTURAL_CANDIDATE'
    elif len(retained_ids) == 1:
        status = 'DETERMINISTIC_UNIQUE_CANDIDATE'
    else:
        status = 'DETERMINISTIC_AMBIGUOUS_CANDIDATES'
    plan_sha256 = hashlib.sha256(_canonical(plan)).hexdigest()
    result = {
        'schema': WITHIN_RUN_RECEIPT_SCHEMA,
        'method_sha256': METHOD_ID,
        'trial_id': plan['trial_id'],
        'capture_sha256': features['capture_sha256'],
        'source_manifest_sha256': plan['source_manifest_sha256'],
        'plan_sha256': plan_sha256,
        'status': status,
        'field_status': field_status,
        'candidate_results': candidate_results,
        'retained_mapping_ids': retained_ids,
        'gate_authorizing_without_capsule_bridge': False,
        'requires_consumed_producer_spool_authority': True,
        'internal_capsule_only': True,
        'public_export_allowed': False,
        'cryptographic_theorem_coverage_claim': False,
        'active_or_host_privacy_claim': False,
    }
    result['receipt_sha256'] = hashlib.sha256(_canonical(result)).hexdigest()
    return result


def calibration_split(calibration_id: str) -> str:
    try:
        selected = str(uuid.UUID(calibration_id))
    except (ValueError, TypeError, AttributeError):
        raise EmpiricalRefused('p1-empirical-calibration-id') from None
    _need(selected == calibration_id, 'p1-empirical-calibration-id')
    digest = hashlib.sha256(SPLIT_DOMAIN + calibration_id.encode()).digest()
    return 'TRAIN' if digest[0] & 1 == 0 else 'HOLDOUT'


def _digest_bits(value: str) -> list[int]:
    _need(_word(value), 'p1-empirical-family-digest')
    raw = bytes.fromhex(value)
    return [(byte >> bit) & 1 for byte in raw for bit in range(7, -1, -1)]


def _feature_family(value: dict, name: str) -> tuple[list[float], list[int]]:
    _need(type(value) is dict and value.get('schema') == FEATURE_SCHEMA and
          value.get('method_sha256') == METHOD_ID and
          type(value.get('families')) is dict and
          name in value['families'], 'p1-empirical-feature-family')
    family = value['families'][name]
    _need(type(family) is dict and set(family) == {
              'exact_sha256', 'numeric'} and type(family['numeric']) is list
          and family['numeric'] and
          all(type(item) is int for item in family['numeric']),
          'p1-empirical-feature-family-shape')
    return [float(item) for item in family['numeric']], _digest_bits(
        family['exact_sha256'])


def _mean_scale(vectors: list[list[float]]) -> tuple[list[float], list[float]]:
    width = len(vectors[0])
    _need(width > 0 and all(len(row) == width for row in vectors),
          'p1-empirical-feature-width')
    means = [sum(row[index] for row in vectors) / len(vectors)
             for index in range(width)]
    scales = []
    for index, mean in enumerate(means):
        variance = sum((row[index] - mean) ** 2 for row in vectors) / len(vectors)
        scales.append(max(math.sqrt(variance), 1.0))
    return means, scales


def _normalized(values: list[float], means: list[float],
                scales: list[float]) -> list[float]:
    _need(len(values) == len(means) == len(scales),
          'p1-empirical-feature-width')
    return [(value - mean) / scale
            for value, mean, scale in zip(values, means, scales)]


def _centroid(rows: list[tuple[list[float], list[int]]],
              means: list[float], scales: list[float]) -> dict:
    numeric = [_normalized(row[0], means, scales) for row in rows]
    return {
        'numeric': [sum(row[index] for row in numeric) / len(numeric)
                    for index in range(len(numeric[0]))],
        'digest_probability': [
            sum(row[1][index] for row in rows) / len(rows)
            for index in range(256)],
    }


def _distance(values: tuple[list[float], list[int]], model: dict,
              label: str) -> float:
    centroid = model['centroids'][label]
    numeric = _normalized(values[0], model['numeric_mean'],
                          model['numeric_scale'])
    numeric_distance = sum(
        (value - expected) ** 2
        for value, expected in zip(numeric, centroid['numeric'])) / len(numeric)
    digest_distance = sum(
        (value - expected) ** 2
        for value, expected in zip(values[1],
                                   centroid['digest_probability'])) / 256
    return ((1 - DIGEST_DISTANCE_WEIGHT) * numeric_distance +
            DIGEST_DISTANCE_WEIGHT * digest_distance)


def _quantile(values: list[float], selected: float) -> float:
    _need(values and 0 < selected <= 1, 'p1-empirical-threshold-samples')
    ordered = sorted(values)
    return ordered[max(0, math.ceil(selected * len(ordered)) - 1)]


def _binomial_tail(successes: int, trials: int, chance: float) -> float:
    _need(0 <= successes <= trials and 0 < chance < 1,
          'p1-empirical-binomial-input')
    return sum(math.comb(trials, count) * chance ** count *
               (1 - chance) ** (trials - count)
               for count in range(successes, trials + 1))


def _classification_power(trials: int, chance: float) -> tuple[int, float]:
    critical = next(
        count for count in range(trials + 1)
        if _binomial_tail(count, trials, chance) <=
           ASSOCIATION_P_THRESHOLD)
    power = _binomial_tail(critical, trials,
                           POWER_ALTERNATIVE_ACCURACY)
    return critical, power


def freeze_calibration(rows: object, mapping_ids: object) -> dict:
    """Freeze an optional study corpus; this never authorizes a gate row."""
    _need(type(mapping_ids) is tuple and len(mapping_ids) == 2 and
          len(set(mapping_ids)) == len(mapping_ids) and
          all(type(value) is str and
              re.fullmatch('[A-Z][A-Z0-9_-]{0,63}', value) is not None
              for value in mapping_ids),
          'p1-empirical-mapping-catalog')
    _need(type(rows) is list and rows,
          'p1-empirical-calibration-rows')
    counts = {(label, split): 0 for label in mapping_ids
              for split in ('TRAIN', 'HOLDOUT')}
    seen = set()
    seen_captures = set()
    seen_attempts = set()
    provenances = set()
    admitted = []
    for row in rows:
        _need(type(row) is dict and set(row) == {
                  'calibration_id', 'mapping_id', 'corpus_provenance', 'raw',
                  'attempt_history'} and
              row['mapping_id'] in mapping_ids and
              row['corpus_provenance'] in (
                  'SYNTHETIC_UNIT_TEST',
                  'EXACT_SELECTED_FULL_RUNTIME_WHOLE_TRIAL') and
              type(row['raw']) is bytes,
              'p1-empirical-calibration-row')
        features = extract_c03_features(row['raw'], row['attempt_history'])
        split = calibration_split(row['calibration_id'])
        _need(row['calibration_id'] not in seen,
              'p1-empirical-calibration-duplicate')
        capture_identities = set(features['capture_sha256s']) | {
            features['capture_sha256']}
        _need(not (capture_identities & seen_captures),
              'p1-empirical-calibration-capture-duplicate')
        _need(not (set(features['attempt_ids']) & seen_attempts),
              'p1-empirical-calibration-attempt-duplicate')
        seen.add(row['calibration_id'])
        seen_captures.update(capture_identities)
        seen_attempts.update(features['attempt_ids'])
        provenances.add(row['corpus_provenance'])
        counts[(row['mapping_id'], split)] += 1
        admitted.append({
            'calibration_id': row['calibration_id'],
            'mapping_id': row['mapping_id'],
            'corpus_provenance': row['corpus_provenance'],
            'split': split,
            'capture_sha256': features['capture_sha256'],
            'capture_sha256s': features['capture_sha256s'],
            'features': features,
        })
    _need(all(counts[(label, 'TRAIN')] >= MIN_TRAIN_PER_LABEL and
              counts[(label, 'HOLDOUT')] >= MIN_HOLDOUT_PER_LABEL
              for label in mapping_ids),
          'p1-empirical-calibration-power')
    family_names = tuple(sorted(admitted[0]['features']['families']))
    _need(all(tuple(sorted(row['features']['families'])) == family_names
              for row in admitted), 'p1-empirical-family-catalog')
    family_models = {}
    family_audits = {}
    for family_name in family_names:
        training = [row for row in admitted if row['split'] == 'TRAIN']
        holdout = [row for row in admitted if row['split'] == 'HOLDOUT']
        training_values = [
            _feature_family(row['features'], family_name)
            for row in training]
        means, scales = _mean_scale([row[0] for row in training_values])
        model = {
            'numeric_mean': means,
            'numeric_scale': scales,
            'centroids': {},
            'thresholds': {},
        }
        for label in mapping_ids:
            selected = [
                _feature_family(row['features'], family_name)
                for row in training if row['mapping_id'] == label]
            model['centroids'][label] = _centroid(selected, means, scales)
        true_distances = {label: [] for label in mapping_ids}
        correct = 0
        for row in holdout:
            values = _feature_family(row['features'], family_name)
            distances = {label: _distance(values, model, label)
                         for label in mapping_ids}
            predicted = min(mapping_ids, key=lambda label:
                            (distances[label], label))
            correct += predicted == row['mapping_id']
            true_distances[row['mapping_id']].append(
                distances[row['mapping_id']])
        for label in mapping_ids:
            model['thresholds'][label] = _quantile(
                true_distances[label], HOLDOUT_THRESHOLD_QUANTILE)
        chance = 1 / len(mapping_ids)
        probability = _binomial_tail(correct, len(holdout), chance)
        critical, power = _classification_power(len(holdout), chance)
        _need(power >= MIN_CLASSIFICATION_POWER,
              'p1-empirical-calibration-power')
        family_models[family_name] = model
        family_audits[family_name] = {
            'holdout_sample_count': len(holdout),
            'correct_count': correct,
            'accuracy': correct / len(holdout),
            'chance_accuracy': chance,
            'binomial_tail_probability': probability,
            'association_detected': probability <= ASSOCIATION_P_THRESHOLD,
            'critical_correct_count': critical,
            'power_alternative_accuracy': POWER_ALTERNATIVE_ACCURACY,
            'power_at_accuracy_0_75': power,
            'no_association_is_not_independence_proof': True,
        }
    result = {
        'schema': CALIBRATION_SCHEMA,
        'method_sha256': METHOD_ID,
        'mapping_ids': list(mapping_ids),
        'corpus_sha256': hashlib.sha256(_canonical(admitted)).hexdigest(),
        'calibration_ids': sorted(seen),
        'capture_sha256s': sorted(seen_captures),
        'attempt_ids': sorted(seen_attempts),
        'corpus_provenance': sorted(provenances),
        'optional_study_only': True,
        'gate_authorizing': False,
        'internal_capsule_only': True,
        'public_export_allowed': False,
        'required_authoritative_corpus_provenance':
            'EXACT_SELECTED_FULL_RUNTIME_WHOLE_TRIAL',
        'split_counts': {
            label: {split: counts[(label, split)]
                    for split in ('TRAIN', 'HOLDOUT')}
            for label in mapping_ids},
        'family_models': family_models,
        'family_audits': family_audits,
    }
    result['model_sha256'] = hashlib.sha256(_canonical(result)).hexdigest()
    return result


def score_candidates(model: object, features: object, actual_trial_id: str,
                     candidates: object) -> dict:
    """Filter pre-truth structural candidates with every frozen family."""
    _need(type(model) is dict and model.get('schema') == CALIBRATION_SCHEMA and
          model.get('method_sha256') == METHOD_ID and
          _word(model.get('model_sha256')),
          'p1-empirical-calibration-model')
    selected_model = dict(model)
    model_sha256 = selected_model.pop('model_sha256')
    _need(hashlib.sha256(_canonical(selected_model)).hexdigest() ==
          model_sha256, 'p1-empirical-calibration-model-digest')
    try:
        selected_trial = str(uuid.UUID(actual_trial_id))
    except (ValueError, TypeError, AttributeError):
        raise EmpiricalRefused('p1-empirical-actual-trial-id') from None
    _need(selected_trial == actual_trial_id and
          actual_trial_id not in model['calibration_ids'] and
          type(features) is dict and features.get('schema') == FEATURE_SCHEMA
          and features.get('method_sha256') == METHOD_ID and
          type(features.get('capture_sha256s')) is list and
          not ((set(features['capture_sha256s']) |
                {features.get('capture_sha256')}) &
               set(model['capture_sha256s'])) and
          type(features.get('attempt_ids')) is list and
          not (set(features['attempt_ids']) & set(model['attempt_ids'])),
          'p1-empirical-actual-calibration-separation')
    _need(type(candidates) is list and candidates and
          all(type(row) is dict and set(row) == {'mapping_id', 'constraints'}
              and type(row['constraints']) is dict for row in candidates) and
          [row['mapping_id'] for row in candidates] == model['mapping_ids'],
          'p1-empirical-candidate-catalog')
    survivor_sets = []
    family_scores = {}
    _need(set(features['families']) == set(model['family_models']),
          'p1-empirical-family-catalog')
    for family_name in sorted(model['family_models']):
        family_model = model['family_models'][family_name]
        values = _feature_family(features, family_name)
        distances = {
            label: _distance(values, family_model, label)
            for label in model['mapping_ids']}
        retained = [
            label for label in model['mapping_ids']
            if distances[label] <= family_model['thresholds'][label]]
        survivor_sets.append(set(retained))
        family_scores[family_name] = {
            'distances': distances,
            'thresholds': family_model['thresholds'],
            'retained_mapping_ids': retained,
            'used_for_candidate_filter': True,
        }
    retained_ids = [
        label for label in model['mapping_ids']
        if all(label in selected for selected in survivor_sets)]
    retained_candidates = [
        row for row in candidates if row['mapping_id'] in retained_ids]
    status = ('OPTIONAL_CLASSIFIER_CANDIDATE_FILTER' if retained_ids else
              'OPTIONAL_CLASSIFIER_OUT_OF_DISTRIBUTION')
    result = {
        'schema': SCORE_SCHEMA,
        'method_sha256': METHOD_ID,
        'model_sha256': model_sha256,
        'actual_trial_id': actual_trial_id,
        'capture_sha256': features['capture_sha256'],
        'status': status,
        'family_scores': family_scores,
        'retained_mapping_ids': retained_ids,
        'retained_candidates': retained_candidates,
        'gate_authorizing': False,
        'optional_study_only': True,
        'internal_capsule_only': True,
        'public_export_allowed': False,
        'active_or_host_privacy_claim': False,
        'cryptographic_theorem_coverage_claim': False,
    }
    result['receipt_sha256'] = hashlib.sha256(_canonical(result)).hexdigest()
    return result
