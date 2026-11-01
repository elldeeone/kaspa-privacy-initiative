"""Exact, non-authorizing parser for the selected observer FD40 archive.

``parse_archive`` accepts bytes for adversarial controls, but its result is
deliberately not evidence authority.  The only capability-producing entrypoint
is ``read_selected_fd40_typed_capture``: it has no arguments, consumes the
sealed read-only inherited descriptor 40 once, and returns a private live
object.  Model code may burn that object; caller dictionaries, hashes and
public receipts are never accepted in its place.

The archive grammar is written by ``ObserverCaptureCapsuleBridge``.  Runtime
stream evidence counts every physical frame and every payload byte.  These
counts intentionally differ from older normalized Python capture closures.
"""

import fcntl
import hashlib
import json
import os
import re
import stat
import struct
import uuid

import privacy_fd40_structural as structural


CAPSULE_FD = 40
PRE_STRUCTURAL_BYTES = 5874
STRUCTURAL_BYTES = 1988
LEAF_COUNT_OFFSET = PRE_STRUCTURAL_BYTES + STRUCTURAL_BYTES
LEAF_HEADER_BYTES = 319
LEAF_COUNT = 10
EVENT_MAGIC = b'KPBCEV01'
EVENT_HEADER_BYTES = 17
P1_MAGIC = b'KPBP1C03'
P1_HEADER_BYTES = 112
P1_CHUNK_BYTES = 1 << 16
P1_STREAM_BY_SEMANTIC = {
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
PROJECTION_BYTES = 10685
MAX_EVENT_PAYLOAD_BYTES = 1 << 20
MAX_EVENT_STREAM_BYTES = 1 << 26
MAX_P1_STREAM_BYTES = 1 << 30
MAX_ARCHIVE_BYTES = (4 << 30) + (1 << 20)
SCALAR_CAPTURE_MANIFEST = bytes.fromhex(
    '5e6903569bc71cbfb5549b369b79a19ecda6686dc4ab25fca0d161c6e1527b6b')
DISPATCHER_POLICY_DOMAIN = b'KPB_DISPATCHER_RELEASE_POLICY_BINDING_V1\n'
DISPATCHER_EXPLICIT_DOMAIN = b'KPB_EXPLICIT_OWNER_PUBLIC_EFFECTS_CAPTURE_V1\n'

KIND_NAMES = (
    'public-projection', 'terminal-history', 'dispatcher-capture',
    'corrupt-server-capture', 'colluder-wallet-capture',
)
KIND_COMPONENTS = (1, 4, 5, 2, 3)
KIND_HELLO_NAMES = (
    'public-projection', 'terminal-history-v2-control',
    'dispatcher-capture', None, 'colluder-wallet-capture',
)
WORKER_FIELDS = (
    'source_identity', 'build_identity', 'runtime_identity',
    'assets_identity', 'pinned_executable_identity', 'launcher_identity',
)
RUN_DIGEST_FIELDS = (
    'comparison_selection', 'run_selection', 'trial', 'attempt', 'cohort',
    'capture', 'method', 'workload', 'source_closure', 'runtime',
)
OUTER_DIGEST_FIELDS = (
    'outer_parent_process', 'outer_parent_executable', 'capture_source',
    'capture_build', 'capture_runtime', 'capture_launcher',
)
ROUND_ARRAY_FIELDS = (
    'financial_runs', 'round_attempts', 'round_cohorts',
    'round_capture_plans', 'projections',
)
LEAF_DIGEST_FIELDS = (
    'source_identity', 'build_identity', 'runtime_identity',
    'launcher_identity', 'process_identity', 'child_exit_identity',
)
LINEAGE_FIELDS = structural.LINEAGE_FIELDS

_REQUIRED_SEALS = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                   fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
_SELECTED_CONSTRUCTOR = object()
_CONSUMED_FD_IDENTITIES = set()
_LIVE_SELECTED_OBJECTS = {}


def _need(value, name):
    if not value:
        raise ValueError('fd40-archive-' + name)


def _digest(value, name='digest'):
    value = bytes(value)
    _need(len(value) == 32 and value != bytes(32), name)
    return value


def _u32le(value):
    value = bytes(value)
    _need(len(value) == 4, 'u32-width')
    return int.from_bytes(value, 'little')


def _u64le(value):
    value = bytes(value)
    _need(len(value) == 8, 'u64-width')
    return int.from_bytes(value, 'little')


def _word(value, name='word'):
    _need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), name)
    return value


def _uuid4(value, name):
    try:
        parsed = uuid.UUID(value) if type(value) is str else None
    except (ValueError, AttributeError, TypeError):
        parsed = None
    _need(parsed is not None and parsed.version == 4 and str(parsed) == value,
          name)
    return value


def _canonical_json(raw, name):
    raw = bytes(raw)
    _need(0 < len(raw) <= MAX_EVENT_PAYLOAD_BYTES, name + '-width')

    def pairs(rows):
        result = {}
        for key, value in rows:
            _need(key not in result, name + '-duplicate-key')
            result[key] = value
        return result

    try:
        value = json.loads(
            raw, object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError('fd40-archive-' + name + '-nonfinite')))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError('fd40-archive-' + name + '-json') from error
    encoded = (json.dumps(value, sort_keys=True, separators=(',', ':'),
                          allow_nan=False) + '\n').encode()
    _need(encoded == raw, name + '-canonical')
    return value


def _exact(value, fields, name):
    _need(type(value) is dict and set(value) == set(fields), name + '-fields')
    return value


class _Cursor:
    __slots__ = ('value', 'at')

    def __init__(self, value):
        _need(isinstance(value, (bytes, bytearray, memoryview)), 'input-type')
        self.value = memoryview(value)
        self.at = 0

    def take(self, size, name):
        _need(type(size) is int and size >= 0 and
              self.at + size <= len(self.value), name + '-truncated')
        result = self.value[self.at:self.at + size]
        self.at += size
        return result

    def digest(self, name):
        return _digest(self.take(32, name), name)

    def u8(self, name):
        return int(self.take(1, name)[0])

    def u32(self, name):
        return _u32le(self.take(4, name))

    def u64(self, name):
        return _u64le(self.take(8, name))


def _worker(cursor, name):
    return {field: cursor.digest(name + '-' + field)
            for field in WORKER_FIELDS}


def _manifest_worker(entry):
    return {field: entry[field] for field in WORKER_FIELDS}


def _run_binding(raw):
    cursor = _Cursor(raw)
    classification = cursor.u8('binding-classification')
    _need(classification in (1, 2), 'binding-classification')
    result = {'classification': classification}
    for field in RUN_DIGEST_FIELDS:
        result[field] = cursor.digest('binding-' + field)
    result['finite_manifest_identity'] = cursor.digest(
        'binding-finite-manifest')
    result['finite_manifest_parent_recomputation_identity'] = cursor.digest(
        'binding-finite-manifest-parent')
    for field in OUTER_DIGEST_FIELDS:
        result[field] = cursor.digest('binding-' + field)
    entries = []
    for component in range(1, 11):
        _need(cursor.u8('binding-manifest-component') == component,
              'binding-manifest-order')
        entry = {'component': component}
        entry.update(_worker(cursor, 'binding-manifest-' + str(component)))
        entries.append(entry)
    result['manifest_entries'] = entries
    result['observer_worker'] = _worker(cursor, 'binding-observer-worker')
    result['score_worker'] = _worker(cursor, 'binding-score-worker')
    result['aggregate_worker'] = _worker(cursor, 'binding-aggregate-worker')
    for field in ROUND_ARRAY_FIELDS:
        result[field] = (
            cursor.digest('binding-' + field + '-1'),
            cursor.digest('binding-' + field + '-2'),
        )
        _need(result[field][0] != result[field][1],
              'binding-distinct-' + field)
    _need(cursor.at == structural.RUN_BINDING_BYTES,
          'binding-width')
    result['wire_bytes'] = bytes(raw)
    return result


def _c03_role_launch_rows(binding, c03_rounds):
    """Rebuild the finite ten-role preimage from the admitted manifest."""
    roles = {
        'public-projection': 'financial-release',
        'terminal-history': 'terminal-controller',
        'dispatcher-capture': 'private-dispatcher',
        'corrupt-server-capture': 'server-P1',
        'colluder-wallet-capture': 'owner-C1',
    }
    rows = []
    for round_number in (1, 2):
        for kind_index, kind in enumerate(KIND_NAMES):
            slot = (round_number - 1) * 5 + kind_index
            component = KIND_COMPONENTS[kind_index]
            manifest = binding['manifest_entries'][component - 1]
            row = {
                'round': round_number,
                'kind': kind,
                'role': roles[kind],
                'source_sha256': manifest['source_identity'].hex(),
                'build_sha256': manifest['build_identity'].hex(),
                'launch_sha256': manifest['launcher_identity'].hex(),
                'fixed_fd': 20 + slot,
            }
            if kind == 'corrupt-server-capture':
                c03 = c03_rounds[round_number - 1]
                row.update({
                    'model_preimage_sha256':
                        c03['model_preimage_identity'].hex(),
                    'query_store_preimage_sha256':
                        c03['query_store_preimage_identity'].hex(),
                    'scalar_capture_manifest_sha256':
                        c03['scalar_capture_manifest_identity'].hex(),
                })
            rows.append(row)
    return rows


def _domain_uuid(domain, value):
    return hashlib.sha256(domain + value.encode()).digest()


def _public_from_projection(round_number, raw):
    raw = bytes(raw)
    _need(len(raw) == PROJECTION_BYTES, 'projection-width')
    body = raw[193:]
    rows = [body[692 + 520 * index:692 + 520 * (index + 1)]
            for index in range(6)]
    return {
        'round': round_number,
        'projection_sha256': hashlib.sha256(raw).hexdigest(),
        'context_sha256': hashlib.sha256(body[8:284]).hexdigest(),
        'nfs_hex32': [body[404 + 96 * index:436 + 96 * index].hex()
                      for index in range(3)],
        'cms_hex32': [row[:32].hex() for row in rows],
        'tuple_sha256': [hashlib.sha256(row).hexdigest() for row in rows],
    }


def _parse_event_wire(raw, round_number, kind, binding):
    raw = bytes(raw)
    _need(0 < len(raw) <= (1 << 15 if kind == 1 else
                           MAX_EVENT_STREAM_BYTES),
          'event-wire-limit')
    cursor = _Cursor(raw)
    frames = []
    while cursor.at < len(raw):
        start = cursor.at
        header = bytes(cursor.take(EVENT_HEADER_BYTES, 'event-header'))
        _need(header[:8] == EVENT_MAGIC and header[8] in (1, 2, 3, 4, 5),
              'event-header')
        size = int.from_bytes(header[9:17], 'big')
        limit = (PROJECTION_BYTES if header[8] == 4 else
                 0 if header[8] == 5 else
                 1 << 12 if header[8] == 1 else
                 1 << 16 if header[8] == 2 else MAX_EVENT_PAYLOAD_BYTES)
        _need(size <= limit, 'event-payload-limit')
        payload = bytes(cursor.take(size, 'event-payload'))
        frames.append((header[8], payload, raw[start:cursor.at]))
    expected = ([1, 4, 5] if kind == 1 else
                [1, 2] + [3] * (len(frames) - 3) + [5])
    _need([tag for tag, _, _ in frames] == expected and
          (kind == 1 or len(frames) >= 4), 'event-state-machine')
    hello = _canonical_json(frames[0][1], 'hello')
    _exact(hello, ('schema', 'round', 'kind', 'attempt_id',
                   'cohort_sha256', 'financial_run_id',
                   'capture_identity'), 'hello')
    expected_kind = KIND_HELLO_NAMES[kind - 1]
    _need(hello['schema'] == 'kpb-capture-event-channel/v1' and
          hello['round'] == round_number and hello['kind'] == expected_kind,
          'hello-binding')
    attempt = _uuid4(hello['attempt_id'], 'hello-attempt')
    capture = _uuid4(hello['capture_identity'], 'hello-capture')
    _word(hello['cohort_sha256'], 'hello-cohort')
    _word(hello['financial_run_id'], 'hello-financial-run')
    index = round_number - 1
    _need(bytes.fromhex(hello['cohort_sha256']) ==
              binding['round_cohorts'][index] and
          bytes.fromhex(hello['financial_run_id']) ==
              binding['financial_runs'][index] and
          _domain_uuid(b'KPB_CAPTURE_ATTEMPT_ID_V1\n', attempt) ==
              binding['round_attempts'][index] and
          _domain_uuid(b'KPB_CAPTURE_IDENTITY_V1\n', capture) ==
              binding['capture'], 'hello-run-binding')
    meta = None
    records = []
    projection = None
    if kind == 1:
        projection = frames[1][1]
        _need(len(projection) == PROJECTION_BYTES and
              hashlib.sha256(projection).digest() ==
                  binding['projections'][index], 'projection-binding')
    else:
        meta = _canonical_json(frames[1][1], 'meta')
        for _, payload, _ in frames[2:-1]:
            row = _canonical_json(payload, 'record')
            _need(type(row) is dict and set(row) in (
                {'stream', 'value'}, {'stream', 'source', 'value'}),
                'record-fields')
            _need(type(row['stream']) is str and row['stream'] and
                  type(row['value']) is dict, 'record-shape')
            records.append(row)
    end = frames[-1]
    _need(end[1] == b'', 'event-empty-end')
    return {
        'hello': hello, 'meta': meta, 'records': records,
        'projection_bytes': projection,
        'record_count': len(frames),
        'payload_bytes': sum(len(payload) for _, payload, _ in frames),
        'end_frame_identity': hashlib.sha256(end[2]).digest(),
    }


def _parse_p1_runtime(raw, round_number, binding, c03, public, projection,
                      role_rows, role_sha256):
    view = memoryview(raw)
    _need(0 < len(view) <= MAX_P1_STREAM_BYTES, 'p1-wire-limit')
    cursor = _Cursor(view)
    sequence = 0
    prior_time = 0
    payload_bytes = 0
    next_message = 0
    message_state = None
    data_message_count = 0
    data_payload_bytes = 0
    data_stream_counts = {}
    hello = None
    end_wire = None
    while cursor.at < len(view):
        start = cursor.at
        header = bytes(cursor.take(P1_HEADER_BYTES, 'p1-header'))
        record_type, semantic, direction, peer, flags = header[8:13]
        message = int.from_bytes(header[32:40], 'big')
        chunk = int.from_bytes(header[40:44], 'big')
        _need(header[:8] == P1_MAGIC and header[13:16] == bytes(3)
              and record_type in (1, 2, 3, 4, 5, 6)
              and semantic in P1_STREAM_BY_SEMANTIC
              and flags & ~3 == 0,
              'p1-header')
        size = int.from_bytes(header[44:48], 'big')
        _need(size <= P1_CHUNK_BYTES and
              int.from_bytes(header[24:32], 'big') == sequence,
              'p1-sequence-size')
        monotonic = int.from_bytes(header[16:24], 'big')
        _need(monotonic > 0 and monotonic >= prior_time,
              'p1-monotonic')
        prior_time = monotonic
        payload = bytes(cursor.take(size, 'p1-payload'))
        _need(hashlib.sha256(payload).digest() == header[80:112],
              'p1-payload-digest')
        if sequence == 0:
            hello = payload
        first = bool(flags & 1)
        last = bool(flags & 2)
        if first:
            _need(message_state is None and message == next_message and
                  chunk == 0, 'p1-message-start')
            next_message += 1
            message_state = {
                'message': message, 'type': record_type,
                'semantic': semantic, 'direction': direction,
                'peer': peer, 'fork': header[48:80],
                'chunk': 0, 'bytes': 0,
            }
        else:
            _need(message_state is not None and
                  message == message_state['message'] and
                  chunk == message_state['chunk'] + 1,
                  'p1-message-continuation')
        _need(message_state is not None and
              record_type == message_state['type'] and
              semantic == message_state['semantic'] and
              direction == message_state['direction'] and
              peer == message_state['peer'] and
              header[48:80] == message_state['fork'],
              'p1-message-metadata')
        message_state['chunk'] = chunk
        message_state['bytes'] += size
        if record_type == 5:
            _need(end_wire is None, 'p1-duplicate-end')
            end_wire = bytes(view[start:cursor.at])
        if last:
            if record_type == 2:
                data_message_count += 1
                data_payload_bytes += message_state['bytes']
                stream = P1_STREAM_BY_SEMANTIC[semantic]
                data_stream_counts[stream] = \
                    data_stream_counts.get(stream, 0) + 1
            message_state = None
        payload_bytes += size
        sequence += 1
    _need(sequence > 0 and message_state is None and hello is not None and
          end_wire is not None and
          end_wire[8] == 5 and len(end_wire) == P1_HEADER_BYTES,
          'p1-state')
    _need(len(hello) == 332 and hello[0] == round_number and
          hello[1:4] == bytes((1, 0, c03['fixed_fd'])), 'p1-hello')
    try:
        attempt = hello[4:40].decode('ascii')
        capture = hello[104:140].decode('ascii')
    except UnicodeDecodeError as error:
        raise ValueError('fd40-archive-p1-hello-ascii') from error
    _uuid4(attempt, 'p1-attempt')
    _uuid4(capture, 'p1-capture')
    index = round_number - 1
    _need(_domain_uuid(b'KPB_CAPTURE_ATTEMPT_ID_V1\n', attempt) ==
              binding['round_attempts'][index] and
          _domain_uuid(b'KPB_CAPTURE_IDENTITY_V1\n', capture) ==
              binding['capture'] and
          hello[40:72] == binding['round_cohorts'][index] and
          hello[72:104] == binding['financial_runs'][index] and
          hello[140:172] == c03['source_identity'] and
          hello[172:204] == c03['build_identity'] and
          hello[204:236] == c03['launcher_identity'] and
          hello[236:268] == c03['model_preimage_identity'] and
          hello[268:300] == c03['query_store_preimage_identity'] and
          hello[300:332] == c03['scalar_capture_manifest_identity'],
          'p1-hello-binding')

    raw_wire_sha256 = hashlib.sha256(view).hexdigest()
    end_frame_identity = hashlib.sha256(end_wire).hexdigest()
    eof_preimage = (b'KPB_CAPTURE_PRODUCER_STREAM_EOF_V1\n'
                    + struct.pack('>IBQQQ', round_number, 4,
                                  data_message_count, data_payload_bytes,
                                  len(view))
                    + bytes.fromhex(raw_wire_sha256)
                    + bytes.fromhex(end_frame_identity))
    normalized_closure = {
        'schema': 'kpb-capture-source-closure/v2',
        'attempt_id': attempt,
        'cohort_sha256': binding['round_cohorts'][index].hex(),
        'producer_record_count': data_message_count,
        'capture_record_count': data_message_count,
        'producer_payload_bytes': data_payload_bytes,
        'capture_payload_bytes': data_payload_bytes,
        'producer_stream_counts': data_stream_counts,
        'capture_stream_counts': data_stream_counts,
        'record_chain_sha256': raw_wire_sha256,
        'unknown_record_count': 0,
        'capture_root_closed': True,
        'producer_fd_closed': True,
        'raw_wire_bytes': len(view),
        'raw_wire_sha256': raw_wire_sha256,
        'end_frame_identity': end_frame_identity,
        'eof_identity': hashlib.sha256(eof_preimage).hexdigest(),
    }
    import privacy_capture_model as capture_model
    authority = {
        'round': round_number,
        'attempt_id': attempt,
        'cohort_sha256': binding['round_cohorts'][index].hex(),
        'financial_run_id': binding['financial_runs'][index].hex(),
        'capture_identity': capture,
        'server_component': 1,
        'fixed_fd': c03['fixed_fd'],
        'source_sha256': c03['source_identity'].hex(),
        'build_sha256': c03['build_identity'].hex(),
        'launch_sha256': c03['launcher_identity'].hex(),
        'model_preimage_sha256': c03['model_preimage_identity'].hex(),
        'query_store_preimage_sha256':
            c03['query_store_preimage_identity'].hex(),
        'scalar_capture_manifest_sha256':
            c03['scalar_capture_manifest_identity'].hex(),
        'closure': normalized_closure,
    }
    model_artifact = capture_model.corrupt_server_c03(
        view, public, projection, authority, role_rows, role_sha256)
    return {
        'hello': {
            'attempt_id': attempt, 'capture_identity': capture,
            'round': round_number,
        },
        'normalized_c03_closure': normalized_closure,
        'nonauthorizing_model_artifact': model_artifact,
        'record_count': sequence,
        'payload_bytes': payload_bytes,
        'end_frame_identity': hashlib.sha256(end_wire).digest(),
    }


def _runtime_eof(round_number, kind, evidence):
    return hashlib.sha256(
        b'KPB_CAPTURE_PRODUCER_STREAM_EOF_V1\n'
        + struct.pack('>IBQQQ', round_number, kind,
                      evidence['record_count'], evidence['payload_bytes'],
                      evidence['raw_wire_bytes'])
        + evidence['record_root'] + evidence['end_frame_identity']).digest()


def _structural_rounds(section):
    cursor = _Cursor(section)
    cursor.take(52, 'structural-header')
    rounds = []
    for _ in range(2):
        lineage = {name: cursor.digest('structural-' + name)
                   for name in structural.LINEAGE_FIELDS}
        cursor.take(15 * 32 + 4 * 4 + 3 * 8,
                    'structural-round-tail')
        rounds.append(lineage)
    _need(cursor.at == structural.STRUCTURAL_BYTES,
          'structural-private-width')
    return rounds


def _validate_terminal_v2(leaf, public, classification):
    meta = leaf['meta']; records = leaf['records']
    _exact(meta, (
        'schema', 'round', 'projection_sha256', 'cohort_sha256', 'mode',
        'amount_observations', 'status', 'scope', 'actual_network_execution',
        'actual_receipt', 'privacy_measurement_usable'), 'terminal-meta')
    _need(meta['schema'] == 'kpb-terminal-observer-history/v2' and
          meta['round'] == public['round'] and
          meta['projection_sha256'] == public['projection_sha256'] and
          meta['mode'] == 'CONFIGURED0_NETWORK_DISABLED' and
          meta['status'] == 'UNQUALIFIED_SOURCE_ONLY' and
          meta['scope'] == 'PAYMENT_TERMINAL_STREAM_CONTROL_ONLY' and
          meta['amount_observations'] == [] and
          meta['actual_network_execution'] is False and
          meta['actual_receipt'] is False and
          meta['privacy_measurement_usable'] is False,
          'terminal-meta-binding')
    groups = [row['value'] for row in records if row['stream'] == 'group']
    mapping = [row['value'] for row in records
               if row['stream'] == 'mapping-complete']
    _need(len(mapping) == 1 and records[-1]['stream'] == 'event',
          'terminal-mapping-presence')
    streams = [row['stream'] for row in records]
    mapping_index = streams.index('mapping-complete')
    _need(all(stream == 'event' for stream in streams[:4]) and
          all(stream == 'group' for stream in streams[4:mapping_index]) and
          mapping_index == len(records) - 2 and streams[-1] == 'event',
          'terminal-record-order')
    events = [row['value'] for row in records if row['stream'] == 'event']
    _need([event.get('kind') for event in events] == [
        'candidate-constructed', 'r0-verified', 'native-full-verified',
        'durable-final', 'pre-network-capture-closed'] and
        [event.get('sequence') for event in events] == list(range(5)) and
        [event.get('monotonic_ns') for event in events] == sorted(
            event.get('monotonic_ns') for event in events) and
        all(event.get('projection_sha256') == public['projection_sha256']
            and event.get('outcome') == 'ok'
            and event.get('transaction_id_hex32') is None
            and event.get('accepted_head_hex32') is None
            and event.get('settlement_sha256') is None
            for event in events), 'terminal-event-chain')
    closure = mapping[0]
    _exact(closure, (
        'cross_round_owner_nf_tuple_export_count',
        'cross_round_owner_nf_tuple_exports_source_complete',
        'grouping_source_complete', 'owner_component_present',
        'privacy_measurement_usable',
        'public_continuity_modeled_separately'), 'terminal-mapping')
    _need(closure == {
        'cross_round_owner_nf_tuple_export_count': 0,
        'cross_round_owner_nf_tuple_exports_source_complete': True,
        'grouping_source_complete': True,
        'owner_component_present': classification == 2,
        'privacy_measurement_usable': False,
        'public_continuity_modeled_separately': True,
    }, 'terminal-mapping-binding')
    if classification == 1:
        _need(len(groups) == 1 and
              set(groups[0]) == {
                  'group_id_sha256', 'nfs_hex32', 'owner_component_absent',
                  'privacy_measurement_usable', 'projection_sha256',
                  'source_complete', 'tuple_sha256'} and
              groups[0]['owner_component_absent'] is True and
              groups[0]['nfs_hex32'] == public['nfs_hex32'] and
              groups[0]['tuple_sha256'] == public['tuple_sha256'],
              'terminal-hidden-group')
    else:
        _need(len(groups) == 3 and
              [group.get('owner_component') for group in groups] == [0, 1, 2]
              and sorted(nf for group in groups for nf in group['nfs_hex32'])
                  == sorted(public['nfs_hex32'])
              and sorted(row for group in groups
                         for row in group['tuple_sha256']) ==
                  sorted(public['tuple_sha256']), 'terminal-baseline-groups')
    for group in groups:
        _word(group['group_id_sha256'], 'terminal-group-id')
        _need(group['projection_sha256'] == public['projection_sha256'] and
              group['source_complete'] is True and
              group['privacy_measurement_usable'] is False,
              'terminal-group-binding')


def _validate_dispatcher(leaf, public, binding):
    meta = leaf['meta']; records = leaf['records']
    _exact(meta, (
        'schema', 'round', 'projection_sha256', 'cohort_sha256',
        'run_sha256', 'construction_attempt_sha256', 'capture_plan_sha256',
        'construction_classification', 'release_order_policy',
        'direct_exports'), 'dispatcher-meta')
    round_number = public['round']; index = round_number - 1
    classification = binding['classification']
    policy = ('SECRET_PERMUTATION_INDEPENDENT' if classification == 1 else
              'EXPLICIT_OWNER_PUBLIC_EFFECTS')
    _need(meta['schema'] == 'kpb-dispatcher-observer-capture/v1' and
          meta['round'] == round_number and
          meta['projection_sha256'] == public['projection_sha256'] and
          meta['cohort_sha256'] == binding['round_cohorts'][index].hex() and
          meta['run_sha256'] == binding['financial_runs'][index].hex() and
          meta['construction_attempt_sha256'] ==
              binding['round_attempts'][index].hex() and
          meta['capture_plan_sha256'] ==
              binding['round_capture_plans'][index].hex() and
          meta['construction_classification'] == classification and
          meta['release_order_policy'] == policy,
          'dispatcher-meta-binding')
    _word(meta['construction_attempt_sha256'],
          'dispatcher-construction-attempt')
    exports = meta['direct_exports']
    _need(type(exports) is list and len(exports) ==
          (0 if classification == 1 else 3), 'dispatcher-export-count')
    for owner, row in enumerate(exports):
        _exact(row, (
            'owner_component', 'owner_contract_sha256', 'nf_hex32',
            'tuple_sha256', 'run_sha256', 'trial_sha256', 'attempt_sha256',
            'cohort_sha256', 'capture_plan_sha256', 'projection_sha256',
            'context_sha256'), 'dispatcher-export')
        _need(row['owner_component'] == owner and
              row['nf_hex32'] == public['nfs_hex32'][owner] and
              row['tuple_sha256'] == sorted(
                  public['tuple_sha256'][2 * owner:2 * owner + 2]) and
              row['run_sha256'] == meta['run_sha256'] and
              row['trial_sha256'] == binding['trial'].hex() and
              row['attempt_sha256'] ==
                  binding['round_attempts'][index].hex() and
              row['cohort_sha256'] == meta['cohort_sha256'] and
              row['capture_plan_sha256'] == meta['capture_plan_sha256'] and
              row['projection_sha256'] == public['projection_sha256'] and
              row['context_sha256'] == public['context_sha256'],
              'dispatcher-export-binding')
        for name in ('owner_contract_sha256', 'trial_sha256',
                     'attempt_sha256'):
            _word(row[name], 'dispatcher-export-' + name)
    events = [row['value'] for row in records if row['stream'] == 'event']
    retries = [row for row in records if row['stream'] == 'retry']
    _need(len(events) == len(records) - len(retries) and
          [event.get('sequence') for event in events] ==
              list(range(len(events))) and
          [event.get('monotonic_ns') for event in events] == sorted(
              event.get('monotonic_ns') for event in events),
          'dispatcher-event-order')
    kinds = [event.get('kind') for event in events]
    _need(kinds[:7] == [
        'listeners-ready', 'owner-connected', 'owner-upload-complete',
        'owner-connected', 'owner-upload-complete', 'owner-connected',
        'owner-upload-complete'] and kinds[-1] == 'outbound-route' and
        kinds.count('aggregate-release') == 1 and
        kinds.count('release-policy-bound') == 1 and
        kinds.count('explicit-owner-public-effects') ==
            (0 if classification == 1 else 1), 'dispatcher-event-kinds')
    aggregate_index = kinds.index('aggregate-release')
    policy_index = kinds.index('release-policy-bound')
    explicit_hash = bytes(32)
    if classification == 2:
        explicit_index = kinds.index('explicit-owner-public-effects')
        _need(explicit_index == aggregate_index + 1 and
              policy_index == explicit_index + 1,
              'dispatcher-explicit-order')
        preimage = bytearray(DISPATCHER_EXPLICIT_DOMAIN)
        preimage.extend(struct.pack('<QQ', 2, round_number))
        for name in ('run_sha256', 'trial_sha256', 'attempt_sha256',
                     'cohort_sha256', 'capture_plan_sha256',
                     'projection_sha256', 'context_sha256'):
            preimage.extend(bytes.fromhex(exports[0][name]))
        for owner, row in enumerate(exports):
            preimage.extend(struct.pack('<Q', owner))
            preimage.extend(bytes.fromhex(row['owner_contract_sha256']))
            preimage.extend(bytes.fromhex(row['nf_hex32']))
            for value in row['tuple_sha256']:
                preimage.extend(bytes.fromhex(value))
        _need(len(preimage) == 693, 'dispatcher-explicit-width')
        explicit_hash = hashlib.sha256(preimage).digest()
        explicit = events[explicit_index]
        _need(explicit.get('bytes') == 693 and
              explicit.get('filename') ==
                  'EXPLICIT-OWNER-PUBLIC-EFFECTS-V1.bin' and
              explicit.get('public_sha256') == explicit_hash.hex() and
              explicit.get('route_sha256') is None,
              'dispatcher-explicit-event')
    else:
        _need(policy_index == aggregate_index + 1,
              'dispatcher-hidden-order')
    policy_code = 1 if classification == 1 else 2
    preimage = bytearray(DISPATCHER_POLICY_DOMAIN)
    for value in (classification, policy_code, round_number, len(exports)):
        preimage.extend(struct.pack('<Q', value))
    for value in (
            meta['run_sha256'], meta['construction_attempt_sha256'],
            meta['cohort_sha256'], meta['capture_plan_sha256'],
            meta['projection_sha256']):
        preimage.extend(bytes.fromhex(value))
    preimage.extend(explicit_hash)
    _need(len(preimage) == 265, 'dispatcher-policy-width')
    policy_event = events[policy_index]
    _need(policy_event.get('bytes') == 265 and
          policy_event.get('filename') == 'RELEASE-ORDER-POLICY-V1.bin' and
          policy_event.get('public_sha256') ==
              hashlib.sha256(preimage).hexdigest() and
          policy_event.get('route_sha256') is None,
          'dispatcher-policy-event')


def _validate_c1_v2(leaf, public, c1):
    meta = leaf['meta']; records = leaf['records']
    _exact(meta, ('schema', 'round', 'projection_sha256', 'cohort_sha256',
                  'owner_component', 'contact_value_authority_sha256'),
           'c1-meta')
    _need(meta['schema'] == 'kpb-colluder-wallet-observer-capture/v2' and
          meta['round'] == public['round'] and meta['owner_component'] == 1
          and meta['projection_sha256'] == public['projection_sha256'] and
          meta['contact_value_authority_sha256'] ==
              c1['contact_value_authority_identity'].hex(),
          'c1-meta-binding')
    stages = ('invoice', 'pay', 'scan')
    stage_rows = {stage: [] for stage in stages}
    for row in records:
        _exact(row, ('stream', 'source', 'value'), 'c1-record')
        source = row['source']
        _exact(source, (
            'schema', 'observer_stage', 'stage_sequence',
            'operation_id_sha256', 'contact_owner_component',
            'contact_binding_qualified', 'source_event_sequence',
            'observed_monotonic_ns', 'value_binding_qualified', 'value_kind',
            'value_sha256', 'stage_config_sha256',
            'contact_value_authority_sha256',
            'source_event_binding_sha256'), 'c1-source')
        stage = source['observer_stage']
        _need(source['schema'] ==
                  'kpb-c1-authenticated-contact-value-source/v1' and
              stage in stages and source['stage_sequence'] == stages.index(stage)
              and source['contact_binding_qualified'] is True and
              source['value_binding_qualified'] is True and
              source['contact_value_authority_sha256'] ==
                  meta['contact_value_authority_sha256'] and
              source['operation_id_sha256'] ==
                  c1['operation_identities'][stages.index(stage)].hex() and
              source['contact_owner_component'] ==
                  c1['contact_owner_components'][stages.index(stage)] and
              source['value_sha256'] == hashlib.sha256(
                  (json.dumps(row['value'], sort_keys=True,
                              separators=(',', ':'), allow_nan=False)
                   + '\n').encode()).hexdigest(), 'c1-source-binding')
        body = row['value']
        expected_stage = None
        expected_kind = None
        if row['stream'] == 'original':
            expected_stage, expected_kind = 'pay', 'ORIGINAL'
        elif row['stream'] == 'invoice':
            expected_stage, expected_kind = {
                'issued': ('invoice', 'ISSUED_INVOICE'),
                'accepted': ('pay', 'ACCEPTED_INVOICE'),
            }.get(body.get('direction'), (None, None))
        elif row['stream'] == 'decrypted-receipt':
            expected_stage, expected_kind = (
                'scan', {'incoming-payment': 'INCOMING_RECEIPT',
                         'change': 'CHANGE_RECEIPT'}.get(body.get('kind')))
        elif row['stream'] == 'retry':
            expected_stage, expected_kind = stage, 'RETRY'
        _need(expected_stage == stage and expected_kind ==
              source['value_kind'], 'c1-source-semantic-binding')
        preimage = {
            'schema': 'kpb-c1-contact-value-event-binding/v1',
            'contact_value_authority_sha256':
                source['contact_value_authority_sha256'],
            'stage_config_sha256': source['stage_config_sha256'],
            'observer_stage': stage,
            'stage_sequence': source['stage_sequence'],
            'operation_id_sha256': source['operation_id_sha256'],
            'contact_owner_component': source['contact_owner_component'],
            'source_event_sequence': source['source_event_sequence'],
            'observed_monotonic_ns': source['observed_monotonic_ns'],
            'stream': row['stream'], 'value_kind': source['value_kind'],
            'value_sha256': source['value_sha256'],
        }
        canonical = (json.dumps(preimage, sort_keys=True, separators=(',', ':'),
                                allow_nan=False) + '\n').encode()
        _need(source['source_event_binding_sha256'] == hashlib.sha256(
            b'KPB_C1_CONTACT_VALUE_EVENT_V1\n' + canonical).hexdigest(),
            'c1-source-event-binding')
        stage_rows[stage].append(source)
    _need([row['stream'] for row in records[:5]] == [
        'original', 'invoice', 'invoice', 'decrypted-receipt',
        'decrypted-receipt'] and all(stage_rows.values()),
        'c1-canonical-record-order')
    previous = 0
    stage_configs = []
    for stage in stages:
        ordered = sorted(stage_rows[stage],
                         key=lambda row: row['source_event_sequence'])
        _need([row['source_event_sequence'] for row in ordered] ==
                  list(range(len(ordered))) and
              [row['observed_monotonic_ns'] for row in ordered] == sorted(
                  row['observed_monotonic_ns'] for row in ordered) and
              ordered[0]['observed_monotonic_ns'] >= previous and
              len({row['stage_config_sha256'] for row in ordered}) == 1,
              'c1-stage-closure')
        previous = ordered[-1]['observed_monotonic_ns']
        stage_configs.append(ordered[0]['stage_config_sha256'])
    _need(len(set(stage_configs)) == 3, 'c1-stage-config-distinct')


def parse_archive(raw):
    """Parse the complete v2 archive without minting coverage authority."""
    _need(isinstance(raw, (bytes, bytearray, memoryview)), 'input-type')
    view = memoryview(raw)
    _need(structural.PREFIX_BYTES + LEAF_COUNT * LEAF_HEADER_BYTES <
          len(view) <= MAX_ARCHIVE_BYTES, 'archive-size')
    cursor = _Cursor(view)
    _need(bytes(cursor.take(8, 'magic')) == structural.CAPSULE_MAGIC and
          cursor.u32('version') == structural.CAPSULE_VERSION,
          'envelope')
    trial_capture_identity = cursor.digest('trial-capture-identity')
    permit_identity = cursor.digest('permit-identity')
    binding_raw = bytes(cursor.take(structural.RUN_BINDING_BYTES,
                                    'run-binding'))
    binding = _run_binding(binding_raw)
    closure_identity = cursor.digest('closure-authority')
    producer_process = cursor.digest('producer-process')
    producer_worker = _worker(cursor, 'producer-worker')
    role_closure = cursor.digest('role-closure')
    manifest_seal = cursor.digest('manifest-seal')
    construction_policy = cursor.u8('construction-policy')
    classification_receipt = cursor.digest('classification-receipt')
    producer_child_exit = cursor.digest('producer-child-exit')
    producer_receipt = cursor.digest('producer-receipt')
    producer_identity = cursor.digest('producer-identity')
    stream_count = cursor.u32('stream-count')
    closed_root_count = cursor.u32('closed-root-count')
    unknown_record_count = cursor.u32('unknown-record-count')
    _need(cursor.at == 3940 and stream_count == closed_root_count == 10 and
          unknown_record_count == 0 and role_closure ==
              binding['source_closure'] and
          producer_worker == _manifest_worker(
              binding['manifest_entries'][5]), 'producer-metadata')
    _need(construction_policy == (2 if binding['classification'] == 1 else 1),
          'construction-policy-classification')

    c03_rounds = []
    for expected_round in (1, 2):
        row = {'round': cursor.u8('c03-round'),
               'fixed_fd': cursor.u8('c03-fd')}
        for field in (
                'financial_run', 'attempt', 'cohort', 'capture_plan',
                'projection', 'source_identity', 'build_identity',
                'runtime_identity', 'launcher_identity', 'process_identity',
                'child_exit_identity', 'model_preimage_identity',
                'query_store_preimage_identity',
                'scalar_capture_manifest_identity'):
            row[field] = cursor.digest('c03-' + field)
        index = expected_round - 1
        manifest = binding['manifest_entries'][1]
        _need(row['round'] == expected_round and
              row['fixed_fd'] == 23 + 5 * index and
              row['financial_run'] == binding['financial_runs'][index] and
              row['attempt'] == binding['round_attempts'][index] and
              row['cohort'] == binding['round_cohorts'][index] and
              row['capture_plan'] == binding['round_capture_plans'][index] and
              row['projection'] == binding['projections'][index] and
              all(row[field] == manifest[field] for field in (
                  'source_identity', 'build_identity', 'runtime_identity',
                  'launcher_identity')) and
              row['scalar_capture_manifest_identity'] ==
                  SCALAR_CAPTURE_MANIFEST, 'c03-metadata-binding')
        c03_rounds.append(row)
    _need(c03_rounds[0]['process_identity'] !=
              c03_rounds[1]['process_identity'] and
          c03_rounds[0]['child_exit_identity'] !=
              c03_rounds[1]['child_exit_identity'], 'c03-round-distinct')

    c1_rounds = []
    for expected_round in (1, 2):
        row = {'round': cursor.u8('c1-round'),
               'fixed_fd': cursor.u8('c1-fd')}
        for field in (
                'contact_value_authority_identity', 'role_launch_identity',
                'route_manifest_identity', 'route_source_identity',
                'stage_plan_identity', 'process_identity',
                'expected_child_exit_identity'):
            row[field] = cursor.digest('c1-' + field)
        row['worker'] = _worker(cursor, 'c1-worker')
        row['contact_owner_components'] = [
            cursor.u8('c1-contact') for _ in range(3)]
        row['operation_identities'] = [
            cursor.digest('c1-operation') for _ in range(3)]
        index = expected_round - 1
        incoming = (1 - expected_round) % 3
        outgoing = (1 + expected_round) % 3
        _need(row['round'] == expected_round and
              row['fixed_fd'] == 24 + 5 * index and
              row['role_launch_identity'] == binding['source_closure'] and
              row['worker'] == _manifest_worker(
                  binding['manifest_entries'][2]) and
              row['contact_owner_components'] ==
                  [incoming, outgoing, incoming] and
              len(set(row['operation_identities'])) == 3,
              'c1-metadata-binding')
        c1_rounds.append(row)
    for field in (
            'contact_value_authority_identity', 'route_manifest_identity',
            'route_source_identity', 'stage_plan_identity',
            'process_identity', 'expected_child_exit_identity'):
        _need(c1_rounds[0][field] != c1_rounds[1][field],
              'c1-distinct-' + field)
    _need(cursor.at == PRE_STRUCTURAL_BYTES, 'pre-structural-width')

    role_rows = _c03_role_launch_rows(binding, c03_rounds)
    role_sha256 = hashlib.sha256((json.dumps(
        role_rows, sort_keys=True, separators=(',', ':'), allow_nan=False)
        + '\n').encode()).hexdigest()

    section = bytes(cursor.take(STRUCTURAL_BYTES, 'structural-section'))
    _need(cursor.u8('leaf-count') == LEAF_COUNT, 'leaf-count')
    leaves = []
    projections = []
    publics = []
    for slot in range(LEAF_COUNT):
        expected_round = slot // 5 + 1
        expected_kind = slot % 5 + 1
        header_start = cursor.at
        row = {
            'round': cursor.u8('leaf-round'),
            'kind': cursor.u8('leaf-kind'),
            'fixed_fd': cursor.u8('leaf-fd'),
            'manifest_component': cursor.u8('leaf-component'),
        }
        for field in LEAF_DIGEST_FIELDS:
            row[field] = cursor.digest('leaf-' + field)
        row['root_closed'] = cursor.u8('leaf-root-closed')
        row['end_observed'] = cursor.u8('leaf-end-observed')
        row['eof_observed'] = cursor.u8('leaf-eof-observed')
        evidence = {
            'record_root': cursor.digest('leaf-record-root'),
            'end_frame_identity': cursor.digest('leaf-end-frame'),
            'eof_identity': cursor.digest('leaf-eof'),
            'record_count': cursor.u64('leaf-record-count'),
            'payload_bytes': cursor.u64('leaf-payload-bytes'),
            'raw_wire_bytes': cursor.u64('leaf-wire-bytes'),
        }
        _need(cursor.at - header_start == LEAF_HEADER_BYTES,
              'leaf-header-width')
        _need(row['round'] == expected_round and
              row['kind'] == expected_kind and
              row['fixed_fd'] == 20 + slot and
              row['manifest_component'] == KIND_COMPONENTS[expected_kind - 1]
              and (row['root_closed'], row['end_observed'],
                   row['eof_observed']) == (1, 1, 1), 'leaf-order-binding')
        manifest = binding['manifest_entries'][
            row['manifest_component'] - 1]
        _need(all(row[field] == manifest[field] for field in (
            'source_identity', 'build_identity', 'runtime_identity',
            'launcher_identity')), 'leaf-manifest-binding')
        limit = MAX_P1_STREAM_BYTES if expected_kind == 4 else (
            1 << 15 if expected_kind == 1 else MAX_EVENT_STREAM_BYTES)
        _need(0 < evidence['raw_wire_bytes'] <= limit,
              'leaf-wire-limit')
        wire = cursor.take(evidence['raw_wire_bytes'], 'leaf-wire')
        _need(hashlib.sha256(wire).digest() == evidence['record_root'],
              'leaf-record-root')
        if expected_kind == 4:
            parsed = _parse_p1_runtime(
                wire, expected_round, binding, c03_rounds[expected_round - 1],
                publics[expected_round - 1],
                projections[expected_round - 1], role_rows, role_sha256)
        else:
            parsed = _parse_event_wire(wire, expected_round, expected_kind,
                                       binding)
        _need(parsed['record_count'] == evidence['record_count'] and
              parsed['payload_bytes'] == evidence['payload_bytes'] and
              parsed['end_frame_identity'] ==
                  evidence['end_frame_identity'] and
              _runtime_eof(expected_round, expected_kind, evidence) ==
                  evidence['eof_identity'], 'leaf-runtime-evidence')
        if expected_kind == 1:
            projection = parsed['projection_bytes']
            public = _public_from_projection(expected_round, projection)
            projections.append(projection); publics.append(public)
        row['runtime_evidence'] = evidence
        row['typed'] = parsed
        leaves.append(row)
    _need(cursor.at == len(view), 'trailing-bytes')

    structural_prefix = bytes(view[:structural.PREFIX_BYTES])
    structural_receipt = structural.parse_prefix(
        structural_prefix, projections, publics)
    structural_lineage = _structural_rounds(section)
    for index in range(2):
        terminal_leaf = leaves[index * 5 + 1]
        _need(terminal_leaf['process_identity'] ==
                  structural_lineage[index]['producer_stream_process'] and
              terminal_leaf['child_exit_identity'] ==
                  structural_lineage[index]['producer_stream_child_exit'],
              'terminal-structural-lineage')
        _validate_terminal_v2(terminal_leaf['typed'], publics[index],
                              binding['classification'])
        _validate_dispatcher(leaves[index * 5 + 2]['typed'], publics[index],
                             binding)
        p1_leaf = leaves[index * 5 + 3]
        c03 = c03_rounds[index]
        _need(p1_leaf['process_identity'] == c03['process_identity'] and
              p1_leaf['child_exit_identity'] == c03['child_exit_identity'],
              'p1-leaf-authority-binding')
        c1_leaf = leaves[index * 5 + 4]
        c1 = c1_rounds[index]
        _need(c1_leaf['process_identity'] == c1['process_identity'] and
              c1_leaf['child_exit_identity'] ==
                  c1['expected_child_exit_identity'],
              'c1-leaf-authority-binding')
        _validate_c1_v2(c1_leaf['typed'], publics[index], c1)
        # Every non-projection event leaf binds the exact public projection.
        for offset in (1, 2, 4):
            meta = leaves[index * 5 + offset]['typed']['meta']
            _need(meta['round'] == index + 1 and
                  meta['projection_sha256'] ==
                      publics[index]['projection_sha256'] and
                  meta['cohort_sha256'] ==
                      binding['round_cohorts'][index].hex(),
                  'event-meta-round-binding')

    return {
        'schema': 'kpb-fd40-typed-archive-parse/v1',
        'classification': binding['classification'],
        'binding': binding,
        'trial_capture_identity': trial_capture_identity,
        'permit_identity': permit_identity,
        'opaque_closure_authority_identity': closure_identity,
        'producer_process_identity': producer_process,
        'manifest_seal': manifest_seal,
        'construction_classification_receipt': classification_receipt,
        'producer_child_exit_identity': producer_child_exit,
        'producer_receipt_identity': producer_receipt,
        'producer_identity': producer_identity,
        'c03_rounds': c03_rounds,
        'c1_rounds': c1_rounds,
        'structural': structural_receipt,
        'public_rounds': publics,
        'projection_bytes': projections,
        'typed_leaves': leaves,
        'leaf_count': LEAF_COUNT,
        'authorizes_coverage': False,
        'requires_consumed_sealed_fd40': True,
    }


def inspect_public_state_transitions(parsed):
    """Verify both exact public transitions without minting coverage.

    This helper deliberately accepts an ordinary parsed value and returns an
    ordinary diagnostic value.  Its result is therefore never authority.  The
    future isolated native worker may run the same finite computation only
    after consuming its non-importable FD40 admission.
    """
    _need(type(parsed) is dict and
          parsed.get('schema') == 'kpb-fd40-typed-archive-parse/v1' and
          parsed.get('authorizes_coverage') is False and
          parsed.get('requires_consumed_sealed_fd40') is True,
          'public-state-parse-input')
    binding = parsed.get('binding')
    projections = parsed.get('projection_bytes')
    publics = parsed.get('public_rounds')
    leaves = parsed.get('typed_leaves')
    _need(type(binding) is dict and type(projections) is list and
          len(projections) == 2 and type(publics) is list and
          len(publics) == 2 and type(leaves) is list and len(leaves) == 10,
          'public-state-parse-shape')

    # Imported lazily so the full archive grammar remains independently
    # usable as a nonauthorizing parser in the finite worker closure.
    import privacy_public_state as public_state

    receipts = []
    edge_rounds = []
    for index, (raw, public) in enumerate(zip(projections, publics)):
        leaf = leaves[index * 5]
        _need(type(raw) is bytes and len(raw) == PROJECTION_BYTES and
              public == _public_from_projection(index + 1, raw) and
              hashlib.sha256(raw).digest() == binding['projections'][index]
              and leaf['round'] == index + 1 and leaf['kind'] == 1 and
              leaf['typed']['projection_bytes'] == raw,
              'public-state-projection-binding')
        receipt = public_state.verify_public_state_transition(raw)
        _need(receipt['projection_sha256'] == public['projection_sha256'] and
              receipt['authorizes_selected_coverage'] is False and
              receipt['privacy_proven'] is False and
              receipt['accepted_chain_currentness_proven'] is False,
              'public-state-receipt-binding')
        body = raw[193:]
        edges = []
        for position in range(3):
            witness = body[3812 + 1160 * position:
                           3812 + 1160 * (position + 1)]
            edges.append({
                'input_nf_hex32':
                    body[404 + 96 * position:
                         436 + 96 * position].hex(),
                'predecessor_index': _u32le(witness[:4]),
                'predecessor_nf_hex32': witness[4:36].hex(),
                'successor_nf_hex32': witness[36:68].hex(),
                'successor_index': _u32le(witness[68:72]),
            })
        receipts.append(receipt)
        edge_rounds.append(edges)
    return {
        'schema': 'kpb-fd40-public-state-transition-inspection/v1',
        'rounds': receipts,
        'nf_history_edges': edge_rounds,
        'projection_bindings_checked': 2,
        'owner_label_fields': 0,
        'authorizes_coverage': False,
        'requires_native_isolated_admission': True,
    }


MULTIATTEMPT_HISTORY_SCHEMA = \
    'kpb-complete-public-multiattempt-history-input/v1'
MULTIATTEMPT_OUTCOMES = (
    'ABORTED_BEFORE_PUBLIC_PROJECTION',
    'PUBLIC_PROJECTION_REFUSED',
    'TERMINAL_PUBLIC_PROJECTION',
)


def _public_attempt_vectors(raw):
    body = raw[193:]
    rows = [body[692 + 520 * index:692 + 520 * (index + 1)]
            for index in range(6)]
    return {
        'nullifier': [body[404 + 96 * index:436 + 96 * index]
                      for index in range(3)],
        'commitment': [row[:32] for row in rows],
        'ciphertext-ephemeral-public-key': [row[96:128] for row in rows],
        'ciphertext-poly1305-tag': [row[128:144] for row in rows],
        'ciphertext-encrypted-receipt': [row[144:360] for row in rows],
        'ciphertext-hash': [row[360:392] for row in rows],
        'output-proof': [row[392:520] for row in rows],
        'aggregate-proof': [body[10364:10492]],
    }


def inspect_complete_public_multiattempt_history_input(value):
    """Validate the future complete-history input grammar, without authority.

    The input lists only attempts that a future native lifecycle capability
    supplies.  This function never invents an omitted attempt and cannot prove
    the list complete: it reports equality edges for exactly the supplied
    projections and keeps both multiattempt ledger rows open.
    """
    _exact(value, ('schema', 'trial_sha256', 'rounds'),
           'multiattempt-history')
    _need(value['schema'] == MULTIATTEMPT_HISTORY_SCHEMA,
          'multiattempt-history-schema')
    _word(value['trial_sha256'], 'multiattempt-trial')
    rounds = value['rounds']
    _need(type(rounds) is list and len(rounds) == 2,
          'multiattempt-two-rounds')
    result_rounds = []
    all_edges = []
    for round_number, row in enumerate(rounds, 1):
        _exact(row, ('round', 'attempts'), 'multiattempt-round')
        attempts = row['attempts']
        _need(row['round'] == round_number and type(attempts) is list and
              attempts, 'multiattempt-round-shape')
        projected = []
        previous_event_end = -1
        seen_attempts = set()
        for sequence, attempt in enumerate(attempts):
            _exact(attempt, (
                'sequence', 'attempt_id', 'attempt_identity_sha256',
                'outcome', 'source_event_start', 'source_event_end',
                'projection_bytes'), 'multiattempt-attempt')
            attempt_id = _uuid4(
                attempt['attempt_id'], 'multiattempt-attempt-id')
            _word(attempt['attempt_identity_sha256'],
                  'multiattempt-attempt-identity')
            _need(attempt['sequence'] == sequence and
                  attempt_id not in seen_attempts and
                  bytes.fromhex(attempt['attempt_identity_sha256']) ==
                      _domain_uuid(b'KPB_CAPTURE_ATTEMPT_ID_V1\n',
                                   attempt_id) and
                  attempt['outcome'] in MULTIATTEMPT_OUTCOMES and
                  type(attempt['source_event_start']) is int and
                  type(attempt['source_event_end']) is int and
                  attempt['source_event_start'] == previous_event_end + 1 and
                  attempt['source_event_end'] >=
                      attempt['source_event_start'],
                  'multiattempt-attempt-binding')
            seen_attempts.add(attempt_id)
            previous_event_end = attempt['source_event_end']
            raw = attempt['projection_bytes']
            if attempt['outcome'] == 'ABORTED_BEFORE_PUBLIC_PROJECTION':
                _need(raw is None, 'multiattempt-abort-no-projection')
            else:
                _need(type(raw) is bytes and len(raw) == PROJECTION_BYTES,
                      'multiattempt-projection-width')
                projected.append({
                    'sequence': sequence,
                    'projection_sha256': hashlib.sha256(raw).hexdigest(),
                    'vectors': _public_attempt_vectors(raw),
                })
        _need(attempts[-1]['outcome'] == 'TERMINAL_PUBLIC_PROJECTION' and
              sum(attempt['outcome'] == 'TERMINAL_PUBLIC_PROJECTION'
                  for attempt in attempts) == 1,
              'multiattempt-exact-terminal-attempt')
        edges = []
        for left_index, left in enumerate(projected):
            for right in projected[left_index + 1:]:
                for family in sorted(left['vectors']):
                    for left_slot, left_value in enumerate(
                            left['vectors'][family]):
                        for right_slot, right_value in enumerate(
                                right['vectors'][family]):
                            if left_value == right_value:
                                edges.append({
                                    'family': family,
                                    'left_attempt_sequence': left['sequence'],
                                    'left_slot': left_slot,
                                    'right_attempt_sequence':
                                        right['sequence'],
                                    'right_slot': right_slot,
                                    'value_sha256': hashlib.sha256(
                                        left_value).hexdigest(),
                                })
        result_rounds.append({
            'round': round_number,
            'attempt_count': len(attempts),
            'projected_attempt_count': len(projected),
            'comparison_pair_count':
                len(projected) * (len(projected) - 1) // 2,
            'equality_edge_count': len(edges),
        })
        all_edges.extend({'round': round_number, **edge} for edge in edges)
    return {
        'schema': 'kpb-public-multiattempt-history-inspection/v1',
        'trial_sha256': value['trial_sha256'],
        'rounds': result_rounds,
        'equality_edges': all_edges,
        'synthetic_attempt_count': 0,
        'complete_history_authority_consumed': False,
        'authorizes_coverage': False,
        'requires_native_complete_history_authority': True,
    }


class _SelectedFd40TypedCapture:
    """One-shot child-private result of consuming the sealed inherited FD40."""
    __slots__ = ('_parsed', '_fd_identity', '_live')

    def __init__(self, constructor, parsed, fd_identity):
        _need(constructor is _SELECTED_CONSTRUCTOR and
              type(parsed) is dict and
              parsed.get('authorizes_coverage') is False,
              'selected-constructor')
        self._parsed = parsed
        self._fd_identity = fd_identity
        self._live = True


def read_selected_fd40_typed_capture():
    """Consume exactly inherited FD40; there is no bytes/path/fd overload."""
    fd = CAPSULE_FD
    private_buffer = None
    try:
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        descriptor_flags = fcntl.fcntl(fd, fcntl.F_GETFD)
        seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        before = os.fstat(fd)
        _need((flags & os.O_ACCMODE) == os.O_RDONLY and
              descriptor_flags & fcntl.FD_CLOEXEC == 0 and
              seals & _REQUIRED_SEALS == _REQUIRED_SEALS and
              stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
              and structural.PREFIX_BYTES +
                  LEAF_COUNT * LEAF_HEADER_BYTES < before.st_size <=
                  MAX_ARCHIVE_BYTES, 'selected-fd40')
        identity = (before.st_dev, before.st_ino, before.st_size)
        _need(identity not in _CONSUMED_FD_IDENTITIES,
              'selected-fd40-replay')
        private_buffer = bytearray()
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(fd, min(1 << 20, before.st_size - offset),
                             offset)
            _need(chunk, 'selected-fd40-truncated-read')
            private_buffer.extend(chunk)
            offset += len(chunk)
        _need(offset == before.st_size, 'selected-fd40-read-width')
        parsed = parse_archive(memoryview(private_buffer))
        after = os.fstat(fd)
        _need((before.st_dev, before.st_ino, before.st_size,
               before.st_mode, before.st_uid, before.st_nlink) ==
              (after.st_dev, after.st_ino, after.st_size,
               after.st_mode, after.st_uid, after.st_nlink) and
              fcntl.fcntl(fd, fcntl.F_GET_SEALS) & _REQUIRED_SEALS ==
                  _REQUIRED_SEALS, 'selected-fd40-stability')
        _CONSUMED_FD_IDENTITIES.add(identity)
        result = _SelectedFd40TypedCapture(
            _SELECTED_CONSTRUCTOR, parsed, identity)
        _LIVE_SELECTED_OBJECTS[id(result)] = result
        return result
    except OSError as error:
        raise ValueError('fd40-archive-selected-fd40-os') from error
    finally:
        if private_buffer is not None:
            zero = bytes(1 << 20)
            for offset in range(0, len(private_buffer), len(zero)):
                size = min(len(zero), len(private_buffer) - offset)
                private_buffer[offset:offset + size] = zero[:size]
        try:
            os.close(fd)
        except OSError:
            pass


def _consume_selected(selected):
    _need(type(selected) is _SelectedFd40TypedCapture,
          'selected-type')
    _need(selected._live and
          _LIVE_SELECTED_OBJECTS.pop(id(selected), None) is selected,
          'selected-replay')
    selected._live = False
    parsed = selected._parsed
    selected._parsed = None
    return parsed

