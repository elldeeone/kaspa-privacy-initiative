#!/usr/bin/env python3
"""Source-level append-only capture producer (not yet launch-authorized).

The engine consumes ten pre-opened, role-specific event streams: five exact
artifacts for each of two financial rounds.  It derives every closure and
writes every artifact itself.  There is deliberately no executable actual
mode yet: the registered dispatcher, server P1, owner C1 and terminal roles do
not expose the selected inherited-FD hooks.  Consequently this source emits a
schema that the actual-capture worker rejects and always records
``launch_authorized: false``.

Synthetic controls call ``source_only_produce`` directly.  That interface is
not evidence authority and cannot emit ``kpb-capture-producer-receipt/v1``.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import struct
import sys
import tempfile
import time
import uuid


MAGIC = b'KPBCEV01'
P1_MAGIC = b'KPBP1C03'
P1_HEADER_BYTES = 112
P1_CHUNK_BYTES = 1 << 16
TAGS = {'hello': 1, 'meta': 2, 'record': 3, 'raw': 4, 'end': 5}
TAG_NAMES = {value: name for name, value in TAGS.items()}
ARTIFACT_ORDER = (
    'public-projection', 'terminal-history', 'dispatcher-capture',
    'corrupt-server-capture', 'colluder-wallet-capture',
)
CHANNEL_ORDER = tuple((round_number, kind) for round_number in (1, 2)
                      for kind in ARTIFACT_ORDER)
ROLE_BY_KIND = {
    'public-projection': 'financial-release',
    'terminal-history': 'terminal-controller',
    'dispatcher-capture': 'private-dispatcher',
    'corrupt-server-capture': 'server-P1',
    'colluder-wallet-capture': 'owner-C1',
}
FILENAME_BY_KIND = {
    'public-projection': 'projection.bin',
    'terminal-history': 'terminal.json',
    'dispatcher-capture': 'dispatcher.json',
    'corrupt-server-capture': 'corrupt-server.json',
    'colluder-wallet-capture': 'colluder-wallet.json',
}
CLASSIFICATIONS = (
    'ACTUAL_TRANSPARENT_BASELINE', 'ACTUAL_HIDDEN_MAPPING_CANDIDATE',
)
BINDING_FIELDS = (
    'method_sha256', 'selection_sha256', 'trial_id', 'phase', 'attempt_id',
)
FINANCIAL_FIELDS = (
    'round', 'financial_run_id', 'financial_artifacts_sha256',
    'financial_result_sha256', 'retained_projection_sha256',
)
ROUND_FIELDS = ('round', 'attempt_id', 'cohort_sha256')
ROLE_FIELDS = (
    'round', 'kind', 'role', 'source_sha256', 'build_sha256',
    'launch_sha256', 'fixed_fd',
)
P1_ROLE_FIELDS = ROLE_FIELDS + (
    'model_preimage_sha256', 'query_store_preimage_sha256',
    'scalar_capture_manifest_sha256',
)
INTEGRATION = {
    'role_hooks_integrated': False,
    'fixed_fd_inheritance_selected': False,
    'launcher_selected': False,
    'actual_receipt_schema_enabled': False,
}

# These are transport refusal bounds, not privacy, completeness, or trial
# readiness claims.  The source-only no-progress guard must be replaced by
# supervised role-process lifetime binding before any launcher is selected.
FRAME_PAYLOAD_LIMIT = {
    'public-projection': {
        'hello': 1 << 12, 'raw': 10685, 'end': 0,
    },
    'terminal-history': {
        'hello': 1 << 12, 'meta': 1 << 16, 'record': 1 << 20, 'end': 0,
    },
    'dispatcher-capture': {
        'hello': 1 << 12, 'meta': 1 << 16, 'record': 1 << 20, 'end': 0,
    },
    'corrupt-server-capture': {
        'hello': 1 << 12, 'meta': 1 << 16, 'record': 1 << 28, 'end': 0,
    },
    'colluder-wallet-capture': {
        'hello': 1 << 12, 'meta': 1 << 16, 'record': 1 << 20, 'end': 0,
    },
}
STREAM_WIRE_LIMIT = {
    'public-projection': 1 << 15,
    'terminal-history': 1 << 26,
    'dispatcher-capture': 1 << 26,
    # The P1 stream is chunk-bounded and disk-spooled. There is no arbitrary
    # whole-transcript cap: a closed/full dependency fails at the fd/filesystem
    # boundary rather than silently truncating a multi-GB proof transcript.
    'corrupt-server-capture': None,
    'colluder-wallet-capture': 1 << 26,
}
STREAM_RECORD_LIMIT = {
    'public-projection': 0,
    'terminal-history': 1 << 16,
    'dispatcher-capture': 1 << 16,
    'corrupt-server-capture': None,
    'colluder-wallet-capture': 1 << 16,
}
AGGREGATE_WIRE_LIMIT = None
AGGREGATE_RECORD_LIMIT = None
READ_CHUNK_BYTES = 1 << 16
SOURCE_ONLY_NO_PROGRESS_SECONDS = 300.0
STREAM_KIND_CODE = {
    'public-projection': 1,
    'terminal-history': 2,
    'dispatcher-capture': 3,
    'corrupt-server-capture': 4,
    'colluder-wallet-capture': 5,
}


def need(condition, category):
    if not condition:
        raise ValueError('privacy-capture-producer-' + category)


def exact(value, names, category='exact-fields'):
    need(type(value) is dict and set(value) == set(names), category)


def word(value, category='word'):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value),
         category)
    return value


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode()


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate-json-field')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(
            ValueError('privacy-capture-producer-nonfinite-number')))
    need(encoded(value) == raw, 'canonical-json')
    return value


def source_sha256():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _uuid(value, category):
    need(type(value) is str and str(uuid.UUID(value)) == value, category)
    return value


def validate_selection(value):
    exact(value, (
        'schema', 'status', 'classification', 'binding',
        'capture_identity', 'producer_source_sha256',
        'producer_build_sha256', 'role_launch_closure',
        'financial_rounds', 'rounds', 'integration'))
    need(value['schema'] == 'kpb-capture-producer-source-selection/v1'
         and value['status'] == 'UNQUALIFIED_SOURCE_ONLY'
         and value['classification'] in CLASSIFICATIONS,
         'source-only-selection')
    exact(value['binding'], BINDING_FIELDS, 'binding-fields')
    for name in ('method_sha256', 'selection_sha256'):
        word(value['binding'][name], 'binding-' + name)
    _uuid(value['binding']['trial_id'], 'binding-trial-id')
    need(value['binding']['phase'] == 'private-batch-privacy'
         and type(value['binding']['attempt_id']) is str
         and re.fullmatch('[A-Za-z0-9_-]{1,128}',
                          value['binding']['attempt_id']), 'binding')
    _uuid(value['capture_identity'], 'capture-identity')
    need(word(value['producer_source_sha256'], 'producer-source') ==
         source_sha256(), 'executing-source')
    word(value['producer_build_sha256'], 'producer-build')
    financial = value['financial_rounds']
    need(type(financial) is list and len(financial) == 2,
         'two-financial-rounds')
    for expected, row in zip((1, 2), financial):
        exact(row, FINANCIAL_FIELDS, 'financial-fields')
        need(row['round'] == expected, 'financial-round-order')
        for name in FINANCIAL_FIELDS[1:]:
            word(row[name], 'financial-' + name)
    need(financial[0]['financial_run_id'] != financial[1]['financial_run_id']
         and financial[0]['retained_projection_sha256'] !=
             financial[1]['retained_projection_sha256'],
         'fresh-financial-rounds')
    rounds = value['rounds']
    need(type(rounds) is list and len(rounds) == 2, 'two-rounds')
    for expected, row in zip((1, 2), rounds):
        exact(row, ROUND_FIELDS, 'round-fields')
        need(row['round'] == expected, 'round-order')
        _uuid(row['attempt_id'], 'round-attempt-id')
        word(row['cohort_sha256'], 'round-cohort')
    need(rounds[0]['attempt_id'] != rounds[1]['attempt_id']
         and rounds[0]['cohort_sha256'] != rounds[1]['cohort_sha256'],
         'fresh-round-attempt-and-cohort')
    roles = value['role_launch_closure']
    need(type(roles) is list and len(roles) == len(CHANNEL_ORDER),
         'role-launch-count')
    for index, (selected, key) in enumerate(zip(roles, CHANNEL_ORDER)):
        exact(selected, P1_ROLE_FIELDS if key[1] ==
              'corrupt-server-capture' else ROLE_FIELDS,
              'role-launch-fields')
        need(selected['round'] == key[0] and selected['kind'] == key[1]
             and selected['role'] == ROLE_BY_KIND[key[1]]
             and selected['fixed_fd'] == 20 + index,
             'fixed-role-fd-map')
        for name in ('source_sha256', 'build_sha256', 'launch_sha256'):
            word(selected[name], 'role-' + name)
        if key[1] == 'corrupt-server-capture':
            for name in ('model_preimage_sha256',
                         'query_store_preimage_sha256',
                         'scalar_capture_manifest_sha256'):
                word(selected[name], 'role-' + name)
            need(selected['scalar_capture_manifest_sha256'] ==
                 '5e6903569bc71cbfb5549b369b79a19ecda6686dc4ab25fca0d161c6e1527b6b',
                 'role-scalar-capture-manifest')
    need(value['integration'] == INTEGRATION,
         'role-hooks-not-integrated-source-only')
    return value


def _read_exact(fd, size):
    chunks = []
    while size:
        chunk = os.read(fd, min(size, 1 << 20))
        if not chunk:
            raise EOFError('privacy-capture-producer-truncated-frame')
        chunks.append(chunk); size -= len(chunk)
    return b''.join(chunks)


def _frame(fd, kind, budget):
    header = _read_exact(fd, 17)
    need(header[:8] == MAGIC and header[8] in TAG_NAMES, 'frame-header')
    size = struct.unpack('>Q', header[9:17])[0]
    tag = TAG_NAMES[header[8]]
    need(tag in FRAME_PAYLOAD_LIMIT[kind]
         and size <= FRAME_PAYLOAD_LIMIT[kind][tag],
         'frame-size-' + kind)
    wire_bytes = 17 + size
    stream_limit = STREAM_WIRE_LIMIT[kind]
    need(stream_limit is None or
         budget['wire_bytes'] + wire_bytes <= stream_limit,
         'stream-bytes-' + kind)
    budget['wire_bytes'] += wire_bytes
    if tag == 'record':
        record_limit = STREAM_RECORD_LIMIT[kind]
        need(record_limit is None or budget['records'] < record_limit,
             'stream-records-' + kind)
        budget['records'] += 1
    payload = _read_exact(fd, size)
    budget['wire_hash'].update(header); budget['wire_hash'].update(payload)
    if tag == 'end':
        need(budget['end_frame_identity'] is None,
             'duplicate-end-frame')
        budget['end_frame_identity'] = hashlib.sha256(
            header + payload).hexdigest()
    return tag, payload


def _bind_eof_closure(closure, budget, round_number, kind):
    need(budget['end_frame_identity'] is not None,
         'missing-end-frame-identity')
    closure['raw_wire_bytes'] = budget['wire_bytes']
    closure['raw_wire_sha256'] = (budget['wire_hash']
        if type(budget['wire_hash']) is str
        else budget['wire_hash'].hexdigest())
    closure['end_frame_identity'] = budget['end_frame_identity']
    preimage = (b'KPB_CAPTURE_PRODUCER_STREAM_EOF_V1\n'
                + struct.pack('>IBQQQ', round_number,
                              STREAM_KIND_CODE[kind],
                              closure['producer_record_count'],
                              closure['producer_payload_bytes'],
                              closure['raw_wire_bytes'])
                + bytes.fromhex(closure['raw_wire_sha256'])
                + bytes.fromhex(closure['end_frame_identity']))
    closure['eof_identity'] = hashlib.sha256(preimage).hexdigest()
    return closure


WIRE_CLOSURE_FIELDS = (
    'raw_wire_bytes', 'raw_wire_sha256',
    'end_frame_identity', 'eof_identity',
)


def _validate_wire_closure(closure, round_number, kind):
    for name in WIRE_CLOSURE_FIELDS[1:]:
        word(closure.get(name), 'wire-closure-' + name)
    need(type(closure.get('raw_wire_bytes')) is int
         and closure['raw_wire_bytes'] >= 0,
         'wire-closure-raw-bytes')
    expected = dict(closure)
    expected.pop('eof_identity')
    _bind_eof_closure(expected, {
        'wire_bytes': closure['raw_wire_bytes'],
        'wire_hash': closure['raw_wire_sha256'],
        'end_frame_identity': closure['end_frame_identity'],
    }, round_number, kind)
    need(expected['eof_identity'] == closure['eof_identity'],
         'wire-closure-eof-identity')


def _event_wire_frame(tag, payload=b''):
    if type(payload) is not bytes:
        payload = encoded(payload)
    return MAGIC + bytes((TAGS[tag],)) + struct.pack('>Q', len(payload)) + payload


def _bind_known_event_wire(closure, wire, round_number, kind):
    end = _event_wire_frame('end')
    need(wire.endswith(end), 'known-event-wire-end')
    return _bind_eof_closure(closure, {
        'wire_bytes': len(wire),
        'wire_hash': hashlib.sha256(wire),
        'end_frame_identity': hashlib.sha256(end).hexdigest(),
    }, round_number, kind)


class _ChannelDrain:
    def __init__(self, key, fd, spool):
        self.key = key
        self.fd = fd
        self.spool = spool
        self.phase = 'hello'
        self.header = bytearray()
        self.tag = None
        self.remaining = None
        self.wire_bytes = 0
        self.records = 0
        self.wire = None
        self.header_target = None
        self.sequence = 0
        self.last_monotonic_ns = 0

    @property
    def kind(self):
        return self.key[1]


def _finish_drain_frame(state):
    if state.wire == 'p1':
        state.phase = 'end' if state.tag == 5 else 'records'
        state.tag = None
        state.remaining = None
        state.header_target = P1_HEADER_BYTES
        return
    if state.tag == 'hello':
        state.phase = 'payload'
    elif state.tag == 'raw':
        state.phase = 'projection-end'
    elif state.tag in ('meta', 'record'):
        state.phase = 'records'
    else:
        need(state.tag == 'end', 'drain-frame-state')
        state.phase = 'end'
    state.tag = None
    state.remaining = None


def _accept_drain_header(state, aggregate):
    header = bytes(state.header); state.header.clear()
    if state.wire == 'p1':
        need(len(header) == P1_HEADER_BYTES and header[:8] == P1_MAGIC
             and header[13:16] == bytes(3), 'p1-frame-header')
        record_type = header[8]
        size = struct.unpack('>I', header[44:48])[0]
        sequence = struct.unpack('>Q', header[24:32])[0]
        monotonic_ns = struct.unpack('>Q', header[16:24])[0]
        need(record_type in (1, 2, 3, 4, 5, 6)
             and size <= P1_CHUNK_BYTES
             and sequence == state.sequence
             and monotonic_ns > 0
             and monotonic_ns >= state.last_monotonic_ns,
             'p1-frame-envelope')
        need((state.phase == 'hello' and record_type == 1)
             or (state.phase == 'records' and record_type != 1),
             'p1-record-state-machine')
        wire_bytes = P1_HEADER_BYTES + size
        stream_limit = STREAM_WIRE_LIMIT[state.kind]
        need(stream_limit is None or
             state.wire_bytes + wire_bytes <= stream_limit,
             'stream-bytes-' + state.kind)
        need(AGGREGATE_WIRE_LIMIT is None or
             aggregate['wire_bytes'] + wire_bytes <= AGGREGATE_WIRE_LIMIT,
             'aggregate-bytes')
        record_limit = STREAM_RECORD_LIMIT[state.kind]
        need(record_limit is None or state.records < record_limit,
             'stream-records-' + state.kind)
        need(AGGREGATE_RECORD_LIMIT is None or
             aggregate['records'] < AGGREGATE_RECORD_LIMIT,
             'aggregate-records')
        state.records += 1; aggregate['records'] += 1
        state.wire_bytes += wire_bytes
        aggregate['wire_bytes'] += wire_bytes
        need(state.spool.write(header) == len(header),
             'complete-spool-write')
        state.sequence += 1; state.last_monotonic_ns = monotonic_ns
        state.tag = record_type; state.remaining = size
        if size == 0:
            _finish_drain_frame(state)
        return
    need(header[:8] == MAGIC and header[8] in TAG_NAMES, 'frame-header')
    tag = TAG_NAMES[header[8]]; size = struct.unpack('>Q', header[9:17])[0]
    allowed = {
        'hello': ('hello',),
        'payload': ('raw',) if state.kind == 'public-projection'
            else ('meta',),
        'projection-end': ('end',),
        'records': ('record', 'end'),
    }
    need(state.phase in allowed and tag in allowed[state.phase],
         'record-state-machine')
    need(tag in FRAME_PAYLOAD_LIMIT[state.kind]
         and size <= FRAME_PAYLOAD_LIMIT[state.kind][tag],
         'frame-size-' + state.kind)
    if tag == 'raw':
        need(size == 10685, 'projection-frame-size')
    elif tag == 'end':
        need(size == 0, 'empty-end-frame')
    else:
        need(size > 0, 'nonempty-' + tag + '-frame')
    wire_bytes = 17 + size
    stream_limit = STREAM_WIRE_LIMIT[state.kind]
    need(stream_limit is None or state.wire_bytes + wire_bytes <= stream_limit,
         'stream-bytes-' + state.kind)
    need(AGGREGATE_WIRE_LIMIT is None or
         aggregate['wire_bytes'] + wire_bytes <= AGGREGATE_WIRE_LIMIT,
         'aggregate-bytes')
    if tag == 'record':
        record_limit = STREAM_RECORD_LIMIT[state.kind]
        need(record_limit is None or state.records < record_limit,
             'stream-records-' + state.kind)
        need(AGGREGATE_RECORD_LIMIT is None or
             aggregate['records'] < AGGREGATE_RECORD_LIMIT,
             'aggregate-records')
        state.records += 1; aggregate['records'] += 1
    state.wire_bytes += wire_bytes
    aggregate['wire_bytes'] += wire_bytes
    need(state.spool.write(header) == len(header), 'complete-spool-write')
    state.tag = tag; state.remaining = size
    if size == 0:
        _finish_drain_frame(state)


def _close_drained_channel(selector, state, channel_fds):
    need(state.phase == 'end' and state.remaining is None
         and not state.header, 'truncated-or-missing-end-' + state.kind)
    selector.unregister(state.fd)
    state.spool.flush(); state.spool.seek(0)
    os.close(state.fd); channel_fds[state.key] = -1; state.fd = -1


def _drain_ready(selector, state, aggregate, channel_fds):
    progressed = False; reads = 0
    # Bound work per readiness notification so a continuously writable large
    # P1 stream cannot starve the other nine pipes.
    while reads < 16:
        if state.phase == 'end':
            wanted = 1
        elif state.remaining is None:
            if state.header_target is None:
                if len(state.header) < 8:
                    wanted = 8 - len(state.header)
                else:
                    prefix = bytes(state.header[:8])
                    if prefix == P1_MAGIC:
                        need(state.kind == 'corrupt-server-capture',
                             'p1-wrong-role-stream')
                        state.wire = 'p1'
                        state.header_target = P1_HEADER_BYTES
                    else:
                        need(prefix == MAGIC, 'frame-header')
                        state.wire = 'event'
                        state.header_target = 17
                    wanted = state.header_target - len(state.header)
            else:
                wanted = state.header_target - len(state.header)
        else:
            wanted = min(state.remaining, READ_CHUNK_BYTES)
        try:
            chunk = os.read(state.fd, wanted)
        except BlockingIOError:
            return progressed
        except InterruptedError:
            continue
        if not chunk:
            _close_drained_channel(selector, state, channel_fds)
            return True
        reads += 1
        progressed = True
        need(state.phase != 'end', 'bytes-after-end')
        if state.remaining is None:
            state.header.extend(chunk)
            if state.header_target is None and len(state.header) == 8:
                continue
            if len(state.header) == state.header_target:
                _accept_drain_header(state, aggregate)
        else:
            need(state.spool.write(chunk) == len(chunk),
                 'complete-spool-write')
            state.remaining -= len(chunk)
            if state.remaining == 0:
                _finish_drain_frame(state)
    return progressed


def _drain_channels(channel_fds, spool_parent):
    """Concurrently drain bounded streams; parse only after every END + EOF."""
    selector = selectors.DefaultSelector(); spools = {}; states = {}
    aggregate = {'wire_bytes': 0, 'records': 0}
    try:
        for key in CHANNEL_ORDER:
            fd = channel_fds[key]
            os.set_blocking(fd, False)
            spool = tempfile.TemporaryFile(
                mode='w+b', prefix='.privacy-capture-', dir=spool_parent)
            state = _ChannelDrain(key, fd, spool)
            spools[key] = spool; states[key] = state
            selector.register(fd, selectors.EVENT_READ, state)
        deadline = time.monotonic() + SOURCE_ONLY_NO_PROGRESS_SECONDS
        while selector.get_map():
            remaining = deadline - time.monotonic()
            need(remaining > 0, 'channel-no-progress-source-only')
            events = selector.select(remaining)
            progressed = False
            for selected, _ in events:
                progressed = (_drain_ready(
                    selector, selected.data, aggregate, channel_fds)
                    or progressed)
            if progressed:
                deadline = time.monotonic() + SOURCE_ONLY_NO_PROGRESS_SECONDS
            elif time.monotonic() >= deadline:
                need(False, 'channel-no-progress-source-only')
        return spools
    except BaseException:
        for spool in spools.values():
            spool.close()
        raise
    finally:
        selector.close()


def _hello(selection, round_number, kind):
    return {
        'schema': 'kpb-capture-event-channel/v1',
        'round': round_number, 'kind': kind,
        'attempt_id': selection['rounds'][round_number - 1]['attempt_id'],
        'cohort_sha256':
            selection['rounds'][round_number - 1]['cohort_sha256'],
        'financial_run_id': selection['financial_rounds'][round_number - 1]
            ['financial_run_id'],
        'capture_identity': selection['capture_identity'],
    }


def _projection_root(raw):
    records = [{'stream': 'projection', 'value': {
        'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}}]
    return records, len(raw)


def _payload_bytes(kind, records):
    if kind == 'dispatcher-capture':
        result = 0
        for row in records:
            if row['stream'] == 'event':
                need(type(row['value']) is dict
                     and type(row['value'].get('bytes')) is int
                     and row['value']['bytes'] >= 0,
                     'dispatcher-event-bytes')
                result += row['value']['bytes']
        return result
    if kind == 'corrupt-server-capture':
        result = 0
        for row in records:
            payload = row['value'].get('payload_hex') \
                if type(row['value']) is dict else None
            need(type(payload) is str and len(payload) % 2 == 0
                 and re.fullmatch('[0-9a-f]*', payload),
                 'corrupt-payload-hex')
            result += len(payload) // 2
        return result
    return sum(len(encoded(row['value'])) for row in records)


def _closure(records, payload_bytes, round_row):
    stream_counts = {}
    for row in records:
        stream_counts[row['stream']] = stream_counts.get(row['stream'], 0) + 1
    return {
        'schema': 'kpb-capture-source-closure/v2',
        'attempt_id': round_row['attempt_id'],
        'cohort_sha256': round_row['cohort_sha256'],
        'producer_record_count': len(records),
        'capture_record_count': len(records),
        'producer_payload_bytes': payload_bytes,
        'capture_payload_bytes': payload_bytes,
        'producer_stream_counts': stream_counts,
        'capture_stream_counts': stream_counts,
        'record_chain_sha256': hashlib.sha256(encoded(records)).hexdigest(),
        'unknown_record_count': 0,
        'capture_root_closed': True,
        'producer_fd_closed': True,
    }


META_FIELDS = {
    'dispatcher-capture': (
        'schema', 'round', 'projection_sha256', 'cohort_sha256',
        'run_sha256', 'construction_attempt_sha256',
        'capture_plan_sha256', 'construction_classification',
        'release_order_policy', 'direct_exports'),
    'corrupt-server-capture': (
        'schema', 'round', 'projection_sha256', 'cohort_sha256',
        'server_component', 'protocol_source_sha256', 'build_policy'),
    'colluder-wallet-capture': (
        'schema', 'round', 'projection_sha256', 'cohort_sha256',
        'owner_component'),
    'terminal-history': (
        'schema', 'round', 'projection_sha256', 'cohort_sha256',
        'mode', 'amount_observations'),
}
DISPATCHER_EVENT_FIELDS = (
    'sequence', 'kind', 'owner_component', 'role', 'monotonic_ns',
    'bytes', 'filename', 'public_sha256', 'route_sha256', 'outcome',
)
DISPATCHER_EXPORT_LINEAGE_FIELDS = (
    'run_sha256', 'trial_sha256', 'attempt_sha256', 'cohort_sha256',
    'capture_plan_sha256', 'projection_sha256', 'context_sha256',
)
DISPATCHER_EXPORT_FIELDS = (
    'owner_component', 'owner_contract_sha256', 'nf_hex32',
    'tuple_sha256', *DISPATCHER_EXPORT_LINEAGE_FIELDS,
)
DISPATCHER_EXPLICIT_LABEL = \
    b'KPB_EXPLICIT_OWNER_PUBLIC_EFFECTS_CAPTURE_V1\n'
DISPATCHER_EXPLICIT_BYTES = 693
DISPATCHER_POLICY_LABEL = \
    b'KPB_DISPATCHER_RELEASE_POLICY_BINDING_V1\n'
DISPATCHER_POLICY_BYTES = 265
SCHEMAS = {
    'dispatcher-capture': 'kpb-dispatcher-observer-capture/v1',
    'corrupt-server-capture': 'kpb-corrupt-server-observer-capture/v1',
    'colluder-wallet-capture': 'kpb-colluder-wallet-observer-capture/v1',
    'terminal-history': 'kpb-terminal-observer-history/v1',
}
ALLOWED_STREAMS = {
    'dispatcher-capture': {'event', 'retry'},
    'corrupt-server-capture': {
        'owner-input-offset', 'owner-input-preprocessing-share',
        'mascot-message',
        'authenticated-share',
        'mac-share', 'randomness-share', 'randomness-mac',
        'mac-key-share',
        'masked-field-intermediate', 'masked-g1-intermediate',
        'authenticated-g1-state', 'authenticated-g2-state',
        'final-proof-g1', 'final-proof-g2', 'field-opening',
        'public-projection'},
    'colluder-wallet-capture': {
        'original', 'invoice', 'decrypted-receipt', 'retry'},
    'terminal-history': {
        'event', 'group', 'retry', 'rejected-or-orphaned', 'reorg',
        'cross-round-link'},
}
COLLUDER_SOURCE_FIELDS = (
    'observer_stage', 'stage_sequence', 'operation_id_sha256',
    'contact_owner_component', 'contact_binding_qualified',
    'source_event_sequence', 'observed_monotonic_ns',
)
COLLUDER_STAGE_SEQUENCE = {'invoice': 0, 'pay': 1, 'scan': 2}


def _dispatcher_explicit_preimage(round_number, exports):
    need(round_number in (1, 2) and type(exports) is list
         and len(exports) == 3, 'dispatcher-explicit-preimage-context')
    result = bytearray(DISPATCHER_EXPLICIT_LABEL)
    result.extend(struct.pack('<QQ', 2, round_number))
    for name in DISPATCHER_EXPORT_LINEAGE_FIELDS:
        result.extend(bytes.fromhex(exports[0][name]))
    for owner, export in enumerate(exports):
        result.extend(struct.pack('<Q', owner))
        result.extend(bytes.fromhex(export['owner_contract_sha256']))
        result.extend(bytes.fromhex(export['nf_hex32']))
        for digest in export['tuple_sha256']:
            result.extend(bytes.fromhex(digest))
    need(len(result) == DISPATCHER_EXPLICIT_BYTES,
         'dispatcher-explicit-preimage-size')
    return bytes(result)


def _dispatcher_policy_preimage(meta, explicit_event_sha256):
    classification = meta['construction_classification']
    policy = meta['release_order_policy']
    need(type(classification) is int and classification in (1, 2)
         and policy in ('SECRET_PERMUTATION_INDEPENDENT',
                        'EXPLICIT_OWNER_PUBLIC_EFFECTS'),
         'dispatcher-release-policy-context')
    policy_code = 1 if policy == 'SECRET_PERMUTATION_INDEPENDENT' else 2
    export_count = len(meta['direct_exports'])
    need(classification == policy_code
         and export_count == (0 if classification == 1 else 3),
         'dispatcher-release-policy-classification')
    explicit = ('00' * 32 if classification == 1
                else word(explicit_event_sha256,
                          'dispatcher-explicit-event-sha256'))
    result = bytearray(DISPATCHER_POLICY_LABEL)
    result.extend(struct.pack(
        '<QQQQ', classification, policy_code, meta['round'], export_count))
    for name in ('run_sha256', 'construction_attempt_sha256',
                 'cohort_sha256', 'capture_plan_sha256',
                 'projection_sha256'):
        result.extend(bytes.fromhex(word(
            meta[name], 'dispatcher-release-policy-' + name)))
    result.extend(bytes.fromhex(explicit))
    need(len(result) == DISPATCHER_POLICY_BYTES,
         'dispatcher-release-policy-preimage-size')
    return bytes(result)


def _validate_dispatcher(meta, records, selection, round_row, financial):
    expected_classification = (
        1 if selection['classification'] ==
             'ACTUAL_HIDDEN_MAPPING_CANDIDATE' else 2)
    expected_policy = (
        'SECRET_PERMUTATION_INDEPENDENT'
        if expected_classification == 1
        else 'EXPLICIT_OWNER_PUBLIC_EFFECTS')
    need(meta['construction_classification'] == expected_classification
         and meta['release_order_policy'] == expected_policy
         and word(meta['run_sha256'], 'dispatcher-run') ==
             financial['financial_run_id']
         and word(meta['construction_attempt_sha256'],
                  'dispatcher-construction-attempt')
         and word(meta['capture_plan_sha256'], 'dispatcher-capture-plan'),
         'dispatcher-selected-policy-binding')

    events = [row['value'] for row in records if row['stream'] == 'event']
    retries = [row['value'] for row in records if row['stream'] == 'retry']
    need(retries == [], 'dispatcher-retries-unmodeled')
    allowed = {
        'listeners-ready', 'owner-connected', 'owner-upload-complete',
        'aggregate-release', 'explicit-owner-public-effects',
        'release-policy-bound', 'outbound-route',
    }
    prior_time = -1
    for sequence, event in enumerate(events):
        exact(event, DISPATCHER_EVENT_FIELDS, 'dispatcher-event-fields')
        need(event['sequence'] == sequence
             and type(event['monotonic_ns']) is int
             and event['monotonic_ns'] >= prior_time
             and event['kind'] in allowed
             and event['outcome'] == 'ok'
             and type(event['bytes']) is int and event['bytes'] >= 0,
             'dispatcher-event-order')
        prior_time = event['monotonic_ns']
    kinds = [event['kind'] for event in events]
    need(kinds.count('listeners-ready') == 1
         and kinds.count('owner-connected') == 3
         and kinds.count('owner-upload-complete') == 3
         and kinds.count('aggregate-release') == 1
         and kinds.count('explicit-owner-public-effects') ==
             (0 if expected_classification == 1 else 1)
         and kinds.count('release-policy-bound') == 1
         and kinds.count('outbound-route') == 1,
         'dispatcher-complete-events')
    need(kinds[0] == 'listeners-ready', 'dispatcher-listener-order')
    listeners = events[0]
    need(listeners['owner_component'] is None
         and listeners['role'] == 'server-roster'
         and listeners['bytes'] == 0 and listeners['filename'] is None
         and listeners['public_sha256'] is None
         and listeners['route_sha256'] is None,
         'dispatcher-listener-shape')

    for owner in range(3):
        connected = [event for event in events
                     if event['kind'] == 'owner-connected'
                     and event['owner_component'] == owner]
        uploaded = [event for event in events
                    if event['kind'] == 'owner-upload-complete'
                    and event['owner_component'] == owner]
        need(len(connected) == len(uploaded) == 1
             and connected[0]['role'] == 'C' + str(owner)
             and connected[0]['bytes'] == 0
             and connected[0]['filename'] is None
             and connected[0]['public_sha256'] is None
             and connected[0]['route_sha256'] is None
             and uploaded[0]['role'] == 'C' + str(owner)
             and uploaded[0]['bytes'] > 0
             and uploaded[0]['filename'] == 'OWNER-PRIVATE-INPUT-V2.bin'
             and uploaded[0]['public_sha256'] is None
             and uploaded[0]['route_sha256'] is None
             and connected[0]['sequence'] < uploaded[0]['sequence'],
             'dispatcher-owner-events')

    aggregate = next(event for event in events
                     if event['kind'] == 'aggregate-release')
    outbound = next(event for event in events
                    if event['kind'] == 'outbound-route')
    policy_event = next(event for event in events
                        if event['kind'] == 'release-policy-bound')
    for event, route_required in ((aggregate, False), (outbound, True)):
        route_ok = (word(event['route_sha256'], 'dispatcher-route')
                    if route_required else event['route_sha256'] is None)
        need(event['owner_component'] is None
             and event['role'] == 'controller'
             and event['bytes'] == 10685
             and event['filename'] == 'released-projection.bin'
             and event['public_sha256'] == meta['projection_sha256']
             and route_ok,
             'dispatcher-projection-event')
    need(aggregate['sequence'] > max(
             event['sequence'] for event in events
             if event['kind'] == 'owner-upload-complete'),
         'dispatcher-aggregate-order')
    need(policy_event['owner_component'] is None
         and policy_event['role'] == 'controller'
         and policy_event['bytes'] == DISPATCHER_POLICY_BYTES
         and policy_event['filename'] == 'RELEASE-ORDER-POLICY-V1.bin'
         and word(policy_event['public_sha256'],
                  'dispatcher-release-policy-event-sha256')
         and policy_event['route_sha256'] is None,
         'dispatcher-release-policy-event')

    exports = meta['direct_exports']
    need(type(exports) is list, 'dispatcher-direct-exports')
    explicit_event_sha256 = ''
    if expected_classification == 1:
        need(exports == []
             and policy_event['sequence'] == aggregate['sequence'] + 1
             and outbound['sequence'] == policy_event['sequence'] + 1,
             'dispatcher-hidden-policy-order')
    else:
        need(len(exports) == 3, 'dispatcher-three-explicit-exports')
        common_lineage = None; contracts = set(); nfs = set(); tuples = set()
        for owner, export in enumerate(exports):
            exact(export, DISPATCHER_EXPORT_FIELDS,
                  'dispatcher-direct-export-fields')
            lineage = tuple(export[name]
                            for name in DISPATCHER_EXPORT_LINEAGE_FIELDS)
            for name, digest in zip(DISPATCHER_EXPORT_LINEAGE_FIELDS,
                                    lineage):
                word(digest, 'dispatcher-export-' + name)
            pair = export['tuple_sha256']
            need(export['owner_component'] == owner
                 and word(export['owner_contract_sha256'],
                          'dispatcher-owner-contract') not in contracts
                 and word(export['nf_hex32'], 'dispatcher-export-nf')
                     not in nfs
                 and type(pair) is list and len(pair) == 2
                 and pair == sorted(pair) and pair[0] != pair[1]
                 and all(word(digest, 'dispatcher-export-tuple')
                         not in tuples for digest in pair)
                 and export['run_sha256'] == meta['run_sha256']
                 and export['attempt_sha256'] ==
                     meta['construction_attempt_sha256']
                 and export['cohort_sha256'] == round_row['cohort_sha256']
                 and export['capture_plan_sha256'] ==
                     meta['capture_plan_sha256']
                 and export['projection_sha256'] ==
                     financial['retained_projection_sha256']
                 and (common_lineage is None or lineage == common_lineage),
                 'dispatcher-direct-export-binding')
            contracts.add(export['owner_contract_sha256'])
            nfs.add(export['nf_hex32']); tuples.update(pair)
            if common_lineage is None:
                common_lineage = lineage
        explicit = next(event for event in events
                        if event['kind'] == 'explicit-owner-public-effects')
        explicit_preimage = _dispatcher_explicit_preimage(
            round_row['round'], exports)
        explicit_event_sha256 = hashlib.sha256(explicit_preimage).hexdigest()
        need(explicit['owner_component'] is None
             and explicit['role'] == 'controller'
             and explicit['bytes'] == DISPATCHER_EXPLICIT_BYTES
             and explicit['filename'] ==
                 'EXPLICIT-OWNER-PUBLIC-EFFECTS-V1.bin'
             and explicit['public_sha256'] == explicit_event_sha256
             and explicit['route_sha256'] is None
             and explicit['sequence'] == aggregate['sequence'] + 1
             and policy_event['sequence'] == explicit['sequence'] + 1
             and outbound['sequence'] == policy_event['sequence'] + 1,
             'dispatcher-explicit-policy-order')

    expected_policy_sha256 = hashlib.sha256(
        _dispatcher_policy_preimage(meta, explicit_event_sha256)).hexdigest()
    need(policy_event['public_sha256'] == expected_policy_sha256,
         'dispatcher-release-policy-binding')


def _validate_colluder_sources(records, round_number):
    incoming = (1 - round_number) % 3
    outgoing = (1 + round_number) % 3
    by_stage = {stage: [] for stage in COLLUDER_STAGE_SEQUENCE}
    for row in records:
        source = row['source']; value = row['value']
        exact(source, COLLUDER_SOURCE_FIELDS, 'colluder-source-fields')
        stage = source['observer_stage']
        need(stage in COLLUDER_STAGE_SEQUENCE
             and type(source['stage_sequence']) is int
             and source['stage_sequence'] ==
                 COLLUDER_STAGE_SEQUENCE[stage]
             and word(source['operation_id_sha256'],
                      'colluder-source-operation')
             and type(source['contact_owner_component']) is int
             and source['contact_owner_component'] ==
                 (outgoing if stage == 'pay' else incoming)
             and source['contact_binding_qualified'] is False
             and type(source['source_event_sequence']) is int
             and 0 <= source['source_event_sequence'] < (1 << 64)
             and type(source['observed_monotonic_ns']) is int
             and 0 < source['observed_monotonic_ns'] < (1 << 64),
             'colluder-source-binding')
        semantic_stage = None
        if row['stream'] == 'original':
            semantic_stage = 'pay'
        elif row['stream'] == 'invoice' and type(value) is dict:
            semantic_stage = {'issued': 'invoice', 'accepted': 'pay'}.get(
                value.get('direction'))
        elif row['stream'] == 'decrypted-receipt':
            semantic_stage = 'scan'
        need(row['stream'] == 'retry' or stage == semantic_stage,
             'colluder-source-semantic-stage')
        by_stage[stage].append(source)
    operation_ids = set()
    previous_stage_time = 0
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
    need(len(operation_ids) == 3,
         'colluder-distinct-stage-operations')
    issued = [row for row in records
              if row['stream'] == 'invoice'
              and row['value'].get('direction') == 'issued']
    accepted = [row for row in records
                if row['stream'] == 'invoice'
                and row['value'].get('direction') == 'accepted']
    need(len(issued) == len(accepted) == 1
         and issued[0]['value'].get('operation_id_sha256') ==
             issued[0]['source']['operation_id_sha256']
         and accepted[0]['value'].get('operation_id_sha256') ==
             issued[0]['source']['operation_id_sha256'],
         'colluder-invoice-operation-binding')

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
P1_SELECTED_RANDOMNESS_SITES = frozenset((1, 7, 20, 21))
P1_SELECTED_SCALAR_SITES = frozenset(range(1, 23))
P1_SELECTED_SCALAR_SITE_BITMAP = (1 << 22) - 1
P1_FQ_MODULUS = int(
    '21888242871839275222246405745257275088696311157297823662689037894645226208583')


def _p1_authenticated_group_state(payload, stage, count, point_bytes):
    need(type(payload) is bytes and point_bytes in (65, 129)
         and len(payload) == 1 + count * 2 * point_bytes
         and payload[0] == stage, 'p1-authenticated-group-state')
    objects = []
    at = 1
    for _ in range(count):
        start = at
        for _ in range(2):
            point = payload[at:at + point_bytes]; at += point_bytes
            need(point[0] in (0, 1), 'p1-authenticated-group-state')
            if point[0] == 0:
                need(point[1:] == bytes(point_bytes - 1),
                     'p1-authenticated-group-state')
            else:
                need(all(int.from_bytes(point[offset:offset + 32], 'little')
                         < P1_FQ_MODULUS
                         for offset in range(1, point_bytes, 32)),
                     'p1-authenticated-group-state')
        objects.append(payload[start:at])
    need(at == len(payload), 'p1-authenticated-group-state')
    return objects

_OPAQUE_P1 = object()


def _p1_binding(selection, round_number):
    round_row = selection['rounds'][round_number - 1]
    financial = selection['financial_rounds'][round_number - 1]
    role = next(row for row in selection['role_launch_closure']
                if row['round'] == round_number
                and row['kind'] == 'corrupt-server-capture')
    return (round_row, financial, role)


def _consume_p1(fd, selection, round_number):
    """Validate C03 incrementally and retain the exact opaque wire artifact."""
    round_row, financial, role = _p1_binding(selection, round_number)
    wire_hash = hashlib.sha256(); raw_wire_bytes = 0
    end_frame_identity = None; sequence = 0; next_message = 0
    last_time = 0; first_time = 0; current = None
    forks = {bytes(32)}; sealed = False; complete = False; ended = False
    projection_hash = hashlib.sha256(); projection_bytes = 0
    projection_messages = 0; stream_counts = {}
    lane = [[0, 0, 0] for _ in range(17)]
    total = [0, 0, 0]
    offset_owners = 0; preprocessing_owners = 0
    offset_bytes = [0, 0, 0]; preprocessing_bytes = [0, 0, 0]
    proof_state_stage = 0
    mac_key_seen = False
    base_a = None; base_b2 = None
    scalar_pending = None; scalar_site_bitmap = 0

    while not ended:
        header = _read_exact(fd, P1_HEADER_BYTES)
        need(header[:8] == P1_MAGIC and header[13:16] == bytes(3),
             'p1-frame-header')
        record_type, semantic, direction, peer, flags = header[8:13]
        monotonic_ns = struct.unpack('>Q', header[16:24])[0]
        selected_sequence = struct.unpack('>Q', header[24:32])[0]
        message = struct.unpack('>Q', header[32:40])[0]
        chunk = struct.unpack('>I', header[40:44])[0]
        size = struct.unpack('>I', header[44:48])[0]
        fork = header[48:80]; expected_digest = header[80:112]
        payload = _read_exact(fd, size)
        wire_hash.update(header); wire_hash.update(payload)
        raw_wire_bytes += len(header) + len(payload)
        need(size <= P1_CHUNK_BYTES
             and selected_sequence == sequence
             and monotonic_ns > 0 and monotonic_ns >= last_time
             and record_type in (1, 2, 3, 4, 5, 6)
             and semantic in P1_STREAM_BY_SEMANTIC
             and flags & ~3 == 0
             and hashlib.sha256(payload).digest() == expected_digest,
             'p1-frame-envelope')
        previous_time = last_time
        if first_time == 0: first_time = monotonic_ns
        last_time = monotonic_ns

        first = bool(flags & 1); last = bool(flags & 2)
        if first:
            need(current is None and message == next_message and chunk == 0,
                 'p1-message-start')
            next_message += 1
            current = {
                'message': message, 'type': record_type,
                'semantic': semantic, 'direction': direction,
                'peer': peer, 'fork': fork, 'chunk': 0,
                'chunks': 0, 'bytes': 0,
            }
            if record_type == 2:
                if scalar_pending is not None:
                    need(semantic == scalar_pending['expected'],
                         'p1-scalar-binding-order')
                elif semantic in (3, 4, 5, 6):
                    need(False, 'p1-scalar-binding-order')
        else:
            need(current is not None and message == current['message']
                 and chunk == current['chunk'] + 1,
                 'p1-message-continuation')
        need(current is not None and record_type == current['type']
             and semantic == current['semantic']
             and direction == current['direction']
             and peer == current['peer'] and fork == current['fork'],
             'p1-message-metadata')
        current['chunk'] = chunk; current['chunks'] += 1
        current['bytes'] += size

        if record_type == 1:
            need(sequence == 0 and first and last and size == 332
                 and semantic == 1 and direction == 3 and peer == 0xff
                 and fork == bytes(32)
                 and payload[0:4] == bytes((round_number, 1, 0,
                                            role['fixed_fd']))
                 and payload[4:40].decode() == round_row['attempt_id']
                 and payload[40:72].hex() == round_row['cohort_sha256']
                 and payload[72:104].hex() == financial['financial_run_id']
                 and payload[104:140].decode() == selection['capture_identity']
                 and payload[140:172].hex() == role['source_sha256']
                 and payload[172:204].hex() == role['build_sha256']
                 and payload[204:236].hex() == role['launch_sha256']
                 and payload[236:268].hex() ==
                     role['model_preimage_sha256']
                 and payload[268:300].hex() ==
                     role['query_store_preimage_sha256']
                 and payload[300:332].hex() ==
                     role['scalar_capture_manifest_sha256'],
                 'p1-hello-binding')
        elif record_type == 2:
            need(not sealed and not complete and fork in forks,
                 'p1-data-state')
            if semantic not in (2, 14):
                need(mac_key_seen, 'p1-mac-key-order')
            if semantic == 2:
                need(direction in (1, 2) and peer in (0, 2),
                     'p1-peer-transport-metadata')
            elif semantic == 1:
                need(direction == 2 and peer in (0, 1, 2)
                     and fork == bytes(32), 'p1-owner-metadata')
            elif semantic == 11:
                need(direction == 1 and peer in (0, 1, 2)
                     and fork == bytes(32),
                     'p1-owner-preprocessing-metadata')
            else:
                need(direction == 3 and peer == 0xff and fork == bytes(32),
                     'p1-local-metadata')
            if semantic == 9:
                projection_hash.update(payload); projection_bytes += size
        else:
            need(first and last and current['chunks'] == 1
                 and direction == 3 and peer == 0xff,
                 'p1-control-frame-shape')
            if record_type == 3:
                need(not sealed and not complete and semantic == 9
                     and fork == bytes(32) and size == 32
                     and projection_messages == 1
                     and projection_bytes == 10685
                     and payload == projection_hash.digest()
                     and payload.hex() == financial['retained_projection_sha256'],
                     'p1-projection-seal')
                sealed = True
            elif record_type == 4:
                need(sealed and not complete and semantic == 9
                     and fork == bytes(32) and size == 496,
                     'p1-completeness-state')
                version, count = struct.unpack('>II', payload[:8])
                reported_total = [struct.unpack('>Q', payload[8 + 8 * i:16 + 8 * i])[0]
                                  for i in range(3)]
                reported_lanes = []
                at = 32
                for _ in range(17):
                    reported_lanes.append([
                        struct.unpack('>Q', payload[at + 8 * i:at + 8 * (i + 1)])[0]
                        for i in range(3)])
                    at += 24
                instrumented, reported_offsets, reported_preprocessing, \
                    reported_scalar_sites, timed_frames, first_ns, last_ns = \
                    struct.unpack('>QQQQQQQ', payload[440:496])
                need(version == 9 and count == 17
                     and reported_total == total
                     and reported_lanes == lane
                     and instrumented == 0x1ffff
                     and reported_offsets == offset_owners == 7
                     and reported_preprocessing == preprocessing_owners == 7
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
                         P1_SELECTED_SCALAR_SITE_BITMAP
                     and mac_key_seen
                     and proof_state_stage == 10
                     and timed_frames == sequence
                     and first_ns == first_time and last_ns == previous_time,
                     'p1-completeness-counters')
                complete = True
            elif record_type == 5:
                need(complete and semantic == 9 and fork == bytes(32)
                     and size == 0, 'p1-end-state')
                need(end_frame_identity is None, 'duplicate-end-frame')
                end_frame_identity = hashlib.sha256(header + payload).hexdigest()
                ended = True
            elif record_type == 6:
                need(not sealed and not complete and semantic == 2
                     and fork in forks and size == 96
                     and payload[:32] == fork
                     and payload[32:64] != bytes(32)
                     and payload[32:64] not in forks,
                     'p1-fork-record')
                forks.add(payload[32:64])
            else:
                need(False, 'p1-control-type')

        if last:
            if record_type == 2:
                if semantic in (1, 3, 4, 5, 6, 10, 11, 13, 14):
                    need(current['bytes'] > 0 and current['bytes'] % 32 == 0,
                         'p1-field-lane-shape')
                elif semantic in (7, 12):
                    need(current['bytes'] > 0 and current['bytes'] % 65 == 0,
                         'p1-g1-lane-shape')
                elif semantic == 8:
                    need(current['bytes'] > 0 and current['bytes'] % 129 == 0,
                         'p1-g2-lane-shape')
                elif semantic in (15, 16):
                    need(current['chunks'] == 1,
                         'p1-authenticated-group-state')
                elif semantic == 17:
                    need(current['chunks'] == 1 and current['bytes'] == 16,
                         'p1-scalar-binding-shape')
                index = semantic - 1
                lane[index][0] += 1
                lane[index][1] += current['chunks']
                lane[index][2] += current['bytes']
                total[0] += 1; total[1] += current['chunks']
                total[2] += current['bytes']
                if semantic == 14:
                    need(not mac_key_seen, 'p1-mac-key-order')
                    mac_key_seen = True
                elif semantic == 17:
                    version = payload[0]
                    kind = payload[1]
                    site = int.from_bytes(payload[2:4], 'big')
                    elements = int.from_bytes(payload[4:12], 'big')
                    need(version == 1 and kind in (1, 2)
                         and site in P1_SELECTED_SCALAR_SITES
                         and elements > 0 and payload[12:16] == bytes(4)
                         and ((site in P1_SELECTED_RANDOMNESS_SITES) ==
                              (kind == 2))
                         and scalar_pending is None,
                         'p1-scalar-binding-shape')
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
                         'p1-scalar-binding-width')
                    scalar_pending['expected'] = scalar_pending['mac']
                elif semantic in (4, 6):
                    need(scalar_pending is not None
                         and semantic == scalar_pending['mac']
                         and current['bytes'] ==
                             32 * scalar_pending['elements'],
                         'p1-scalar-binding-width')
                    scalar_site_bitmap |= 1 << (scalar_pending['site'] - 1)
                    scalar_pending = None
                elif semantic == 1:
                    need(offset_owners & (1 << current['peer']) == 0,
                         'p1-owner-offset-duplicate')
                    offset_owners |= 1 << current['peer']
                    offset_bytes[current['peer']] = current['bytes']
                elif semantic == 11:
                    need(preprocessing_owners & (1 << current['peer']) == 0,
                         'p1-owner-preprocessing-duplicate')
                    preprocessing_owners |= 1 << current['peer']
                    preprocessing_bytes[current['peer']] = current['bytes']
                elif semantic == 13:
                    need(proof_state_stage == 3,
                         'p1-proof-opening-order')
                    proof_state_stage = 4
                elif semantic == 12:
                    need(proof_state_stage == 4,
                         'p1-proof-opening-order')
                    proof_state_stage = 5
                elif semantic == 15:
                    if proof_state_stage == 0:
                        objects = _p1_authenticated_group_state(
                            payload, 1, 4, 65)
                        base_a = objects[0]
                        proof_state_stage = 1
                    elif proof_state_stage == 2:
                        _p1_authenticated_group_state(payload, 2, 6, 65)
                        proof_state_stage = 3
                    elif proof_state_stage == 5:
                        _p1_authenticated_group_state(payload, 3, 2, 65)
                        proof_state_stage = 6
                    else:
                        objects = _p1_authenticated_group_state(
                            payload, 4, 2, 65)
                        need(proof_state_stage == 6 and objects[0] == base_a,
                             'p1-authenticated-group-state')
                        proof_state_stage = 7
                elif semantic == 16:
                    if proof_state_stage == 1:
                        objects = _p1_authenticated_group_state(
                            payload, 1, 1, 129)
                        base_b2 = objects[0]
                        proof_state_stage = 2
                    else:
                        objects = _p1_authenticated_group_state(
                            payload, 4, 1, 129)
                        need(proof_state_stage == 7 and objects[0] == base_b2,
                             'p1-authenticated-group-state')
                        proof_state_stage = 8
                elif semantic == 7:
                    need(proof_state_stage == 8,
                         'p1-proof-opening-order')
                    proof_state_stage = 9
                elif semantic == 8:
                    need(proof_state_stage == 9,
                         'p1-proof-opening-order')
                    proof_state_stage = 10
                stream = P1_STREAM_BY_SEMANTIC[semantic]
                stream_counts[stream] = stream_counts.get(stream, 0) + 1
                if semantic == 9: projection_messages += 1
            current = None
        sequence += 1

    need(current is None and os.read(fd, 1) == b'', 'p1-bytes-after-end')
    record_count = total[0]
    raw_wire_sha256 = wire_hash.hexdigest()
    closure = {
        'schema': 'kpb-capture-source-closure/v2',
        'attempt_id': round_row['attempt_id'],
        'cohort_sha256': round_row['cohort_sha256'],
        'producer_record_count': record_count,
        'capture_record_count': record_count,
        'producer_payload_bytes': total[2],
        'capture_payload_bytes': total[2],
        'producer_stream_counts': stream_counts,
        'capture_stream_counts': stream_counts,
        'record_chain_sha256': raw_wire_sha256,
        'unknown_record_count': 0,
        'capture_root_closed': True,
        'producer_fd_closed': True,
    }
    _bind_eof_closure(closure, {
        'wire_bytes': raw_wire_bytes,
        'wire_hash': raw_wire_sha256,
        'end_frame_identity': end_frame_identity,
    }, round_number, 'corrupt-server-capture')
    os.lseek(fd, 0, os.SEEK_SET)
    return _OPAQUE_P1, closure


def _assemble(kind, meta, records, round_row, financial, selection):
    exact(meta, META_FIELDS[kind], 'meta-fields-' + kind)
    need(meta['schema'] == SCHEMAS[kind]
         and meta['round'] == round_row['round']
         and meta['projection_sha256'] ==
            financial['retained_projection_sha256']
         and meta['cohort_sha256'] == round_row['cohort_sha256'],
         'meta-binding-' + kind)
    for index, row in enumerate(records):
        exact(row, ('stream', 'source', 'value')
              if kind == 'colluder-wallet-capture'
              else ('stream', 'value'), 'record-fields')
        need(row['stream'] in ALLOWED_STREAMS[kind]
             and type(row['value']) is dict, 'record-stream-' + kind)
        if 'sequence' in row['value']:
            need(type(row['value']['sequence']) is int
                 and row['value']['sequence'] == sum(
                     1 for prior in records[:index]
                     if 'sequence' in prior['value']),
                 'record-sequence-' + kind)
    if kind == 'colluder-wallet-capture':
        _validate_colluder_sources(records, round_row['round'])
    elif kind == 'dispatcher-capture':
        _validate_dispatcher(meta, records, selection, round_row, financial)
    value = dict(meta)
    if kind == 'dispatcher-capture':
        value['events'] = [row['value'] for row in records
                           if row['stream'] == 'event']
        value['retry_history'] = [row['value'] for row in records
                                  if row['stream'] == 'retry']
    elif kind == 'corrupt-server-capture':
        need(all(row['stream'] == row['value'].get('semantic')
                 for row in records), 'corrupt-semantic-stream')
        value['records'] = [row['value'] for row in records]
    elif kind == 'colluder-wallet-capture':
        def observed(row):
            return {'source': row['source'], 'value': row['value']}
        originals = [observed(row) for row in records
                     if row['stream'] == 'original']
        need(len(originals) == 1, 'one-colluder-original')
        value['original'] = originals[0]
        value['invoices'] = [observed(row) for row in records
                             if row['stream'] == 'invoice']
        value['decrypted_receipts'] = [observed(row) for row in records
                                      if row['stream'] == 'decrypted-receipt']
        value['retry_history'] = [observed(row) for row in records
                                  if row['stream'] == 'retry']
    else:
        mapping = {
            'events': 'event', 'groups': 'group', 'retry_history': 'retry',
            'rejected_or_orphaned': 'rejected-or-orphaned',
            'reorg_history': 'reorg',
            'cross_round_links': 'cross-round-link',
        }
        for field, stream in mapping.items():
            value[field] = [row['value'] for row in records
                            if row['stream'] == stream]
    payload_bytes = _payload_bytes(kind, records)
    value['closure'] = _closure(records, payload_bytes, round_row)
    return encoded(value), value['closure']


def _consume(fd, selection, round_number, kind):
    start = os.lseek(fd, 0, os.SEEK_CUR)
    prefix = os.read(fd, 8)
    os.lseek(fd, start, os.SEEK_SET)
    if kind == 'corrupt-server-capture' and prefix == P1_MAGIC:
        return _consume_p1(fd, selection, round_number)
    budget = {
        'wire_bytes': 0, 'records': 0,
        'wire_hash': hashlib.sha256(), 'end_frame_identity': None,
    }
    tag, payload = _frame(fd, kind, budget)
    need(tag == 'hello' and parse(payload) ==
         _hello(selection, round_number, kind), 'channel-hello')
    round_row = selection['rounds'][round_number - 1]
    financial = selection['financial_rounds'][round_number - 1]
    if kind == 'public-projection':
        tag, body = _frame(fd, kind, budget)
        need(tag == 'raw' and len(body) == 10685
             and hashlib.sha256(body).hexdigest() ==
                financial['retained_projection_sha256'],
             'projection-frame')
        records, payload_bytes = _projection_root(body)
        closure = _closure(records, payload_bytes, round_row)
    else:
        tag, payload = _frame(fd, kind, budget)
        need(tag == 'meta', 'meta-before-records')
        meta = parse(payload); records = []
        while True:
            tag, payload = _frame(fd, kind, budget)
            if tag == 'end':
                need(payload == b'', 'empty-end-frame')
                break
            need(tag == 'record', 'record-state-machine')
            records.append(parse(payload))
        body, closure = _assemble(
            kind, meta, records, round_row, financial, selection)
    if kind == 'public-projection':
        tag, payload = _frame(fd, kind, budget)
        need(tag == 'end' and payload == b'', 'projection-end')
    need(os.read(fd, 1) == b'', 'bytes-after-end')
    _bind_eof_closure(closure, budget, round_number, kind)
    if kind != 'public-projection':
        value = parse(body)
        value['closure'] = closure
        body = encoded(value)
    return body, closure


def _signature(value):
    return tuple(getattr(value, name) for name in (
        'st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns',
        'st_mode', 'st_nlink', 'st_uid'))


def _read_leaf(path, maximum=1 << 34):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts
         and not any(part.is_symlink() for part in (path, *path.parents)),
         'absolute-nonsymlink-leaf')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd); mode = stat.S_IMODE(before.st_mode)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_uid == os.geteuid() and not mode & 0o022
             and 0 < before.st_size <= maximum, 'stable-private-leaf')
        raw = _read_exact(fd, before.st_size); after = os.fstat(fd)
        need(_signature(before) == _signature(after), 'stable-leaf-read')
        return raw
    finally:
        os.close(fd)


def _verified_p1_leaf(path, selection, round_number):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts
         and not any(part.is_symlink() for part in (path, *path.parents)),
         'absolute-nonsymlink-p1-leaf')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd); mode = stat.S_IMODE(before.st_mode)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_uid == os.geteuid() and not mode & 0o022
             and before.st_size >= P1_HEADER_BYTES,
             'stable-private-p1-leaf')
        prefix = os.read(fd, 8); os.lseek(fd, 0, os.SEEK_SET)
        if prefix != P1_MAGIC: return None
        marker, closure = _consume_p1(fd, selection, round_number)
        need(marker is _OPAQUE_P1 and
             _signature(before) == _signature(os.fstat(fd)),
             'stable-p1-leaf-read')
        return closure
    finally:
        os.close(fd)


def _write(path, raw, mode=0o400):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        at = 0
        while at < len(raw):
            count = os.write(fd, raw[at:]); need(count > 0, 'complete-write')
            at += count
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_from_fd(path, source_fd, mode=0o400):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        os.lseek(source_fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(source_fd, 1 << 20)
            if not chunk: break
            at = 0
            while at < len(chunk):
                count = os.write(fd, chunk[at:])
                need(count > 0, 'complete-spooled-write')
                at += count
        os.fsync(fd)
    finally:
        os.close(fd)


def _artifact_row(kind, closure):
    return {
        'kind': kind,
        'producer_record_count': closure['producer_record_count'],
        'capture_record_count': closure['capture_record_count'],
        'producer_payload_bytes': closure['producer_payload_bytes'],
        'capture_payload_bytes': closure['capture_payload_bytes'],
        'record_chain_sha256': closure['record_chain_sha256'],
        'raw_wire_bytes': closure['raw_wire_bytes'],
        'raw_wire_sha256': closure['raw_wire_sha256'],
        'end_frame_identity': closure['end_frame_identity'],
        'eof_identity': closure['eof_identity'],
        'capture_root_closed': closure['capture_root_closed'],
        'producer_fd_closed': closure['producer_fd_closed'],
    }


def _p1_capture_authority(selection, round_number, closure):
    round_row, financial, role = _p1_binding(selection, round_number)
    return {
        'round': round_number,
        'attempt_id': round_row['attempt_id'],
        'cohort_sha256': round_row['cohort_sha256'],
        'financial_run_id': financial['financial_run_id'],
        'capture_identity': selection['capture_identity'],
        'server_component': 1,
        'fixed_fd': role['fixed_fd'],
        'source_sha256': role['source_sha256'],
        'build_sha256': role['build_sha256'],
        'launch_sha256': role['launch_sha256'],
        'model_preimage_sha256': role['model_preimage_sha256'],
        'query_store_preimage_sha256':
            role['query_store_preimage_sha256'],
        'scalar_capture_manifest_sha256':
            role['scalar_capture_manifest_sha256'],
        'closure': closure,
    }


def source_only_produce(selection, channel_fds, output_root):
    selection = validate_selection(selection)
    need(type(channel_fds) is dict and set(channel_fds) == set(CHANNEL_ORDER)
         and len(set(channel_fds.values())) == len(CHANNEL_ORDER),
         'exact-distinct-channel-map')
    for fd in channel_fds.values():
        need(type(fd) is int and stat.S_ISFIFO(os.fstat(fd).st_mode),
             'source-only-pipe-channel')
    output_root = Path(output_root)
    try:
        need(output_root.is_absolute() and output_root.parent.is_dir()
             and not output_root.exists()
             and not output_root.parent.is_symlink(), 'fresh-output-root')
        output_root.mkdir(mode=0o700)
    except BaseException:
        for fd in channel_fds.values():
            try: os.close(fd)
            except OSError: pass
        raise
    receipt_rounds = []; spools = {}
    try:
        # All ten pipes are drained together.  Artifact parsing/writes start
        # only after every selected role emitted END and then closed its FD.
        spools = _drain_channels(channel_fds, output_root.parent)
        for round_number in (1, 2):
            round_root = output_root / ('round-' + str(round_number))
            round_root.mkdir(mode=0o700)
            artifacts = []
            p1_authority = None
            for kind in ARTIFACT_ORDER:
                key = (round_number, kind)
                body, closure = _consume(
                    spools[key].fileno(), selection, *key)
                target = round_root / FILENAME_BY_KIND[kind]
                if body is _OPAQUE_P1:
                    _write_from_fd(target, spools[key].fileno())
                else:
                    _write(target, body)
                artifacts.append(_artifact_row(kind, closure))
                if kind == 'corrupt-server-capture':
                    p1_authority = _p1_capture_authority(
                        selection, round_number, closure)
            need(p1_authority is not None, 'p1-authority-missing')
            receipt_rounds.append({
                'round': round_number,
                'attempt_id': selection['rounds'][round_number - 1]
                    ['attempt_id'],
                'cohort_sha256': selection['rounds'][round_number - 1]
                    ['cohort_sha256'],
                'p1_capture_authority': p1_authority,
                'artifacts': artifacts,
            })
            directory = os.open(round_root, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_NOFOLLOW | os.O_CLOEXEC)
            try: os.fsync(directory)
            finally: os.close(directory)
    finally:
        for spool in spools.values():
            spool.close()
        for fd in channel_fds.values():
            if type(fd) is int and fd >= 0:
                try: os.close(fd)
                except OSError: pass
    role_launch_sha = hashlib.sha256(
        encoded(selection['role_launch_closure'])).hexdigest()
    receipt = {
        'schema': 'kpb-capture-producer-source-only/v1',
        'status': 'UNQUALIFIED_SOURCE_ONLY',
        'source_selection_sha256': hashlib.sha256(
            encoded(selection)).hexdigest(),
        'binding': selection['binding'],
        'classification': selection['classification'],
        'capture_identity': selection['capture_identity'],
        'producer_source_sha256': selection['producer_source_sha256'],
        'producer_build_sha256': selection['producer_build_sha256'],
        'producer_role_launch_sha256': role_launch_sha,
        'financial_rounds': selection['financial_rounds'],
        'rounds': receipt_rounds,
        'append_only_roots_closed': True,
        'unknown_record_count': 0,
        'role_hooks_integrated': False,
        'fixed_fd_inheritance_selected': False,
        'launcher_selected': False,
        'launch_authorized': False,
        'actual_receipt_emitted': False,
    }
    _write(output_root / 'PRODUCER.json', encoded(receipt))
    directory = os.open(output_root, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW | os.O_CLOEXEC)
    try: os.fsync(directory)
    finally: os.close(directory)
    return receipt


def verify_source_only(root, selection):
    selection = validate_selection(selection); root = Path(root)
    need(root.is_absolute() and root.is_dir() and not root.is_symlink()
         and {entry.name for entry in root.iterdir()} ==
            {'PRODUCER.json', 'round-1', 'round-2'},
         'exact-producer-root')
    receipt = parse(_read_leaf(root / 'PRODUCER.json', 1 << 20))
    exact(receipt, (
        'schema', 'status', 'source_selection_sha256', 'binding',
        'classification', 'capture_identity', 'producer_source_sha256',
        'producer_build_sha256', 'producer_role_launch_sha256',
        'financial_rounds', 'rounds', 'append_only_roots_closed',
        'unknown_record_count', 'role_hooks_integrated',
        'fixed_fd_inheritance_selected', 'launcher_selected',
        'launch_authorized', 'actual_receipt_emitted'),
        'source-only-receipt-fields')
    need(receipt['schema'] == 'kpb-capture-producer-source-only/v1'
         and receipt['status'] == 'UNQUALIFIED_SOURCE_ONLY'
         and receipt['source_selection_sha256'] ==
            hashlib.sha256(encoded(selection)).hexdigest()
         and receipt['binding'] == selection['binding']
         and receipt['classification'] == selection['classification']
         and receipt['capture_identity'] == selection['capture_identity']
         and receipt['producer_source_sha256'] == source_sha256()
         and receipt['producer_build_sha256'] ==
            selection['producer_build_sha256']
         and receipt['producer_role_launch_sha256'] == hashlib.sha256(
            encoded(selection['role_launch_closure'])).hexdigest()
         and receipt['financial_rounds'] == selection['financial_rounds']
         and receipt['append_only_roots_closed'] is True
         and receipt['unknown_record_count'] == 0
         and all(receipt[name] is False for name in (
             'role_hooks_integrated', 'fixed_fd_inheritance_selected',
             'launcher_selected', 'launch_authorized',
             'actual_receipt_emitted')), 'source-only-receipt-binding')
    rebuilt = []
    for round_number, expected_round in zip((1, 2), receipt['rounds']):
        round_root = root / ('round-' + str(round_number))
        need(round_root.is_dir() and not round_root.is_symlink()
             and {entry.name for entry in round_root.iterdir()} ==
                set(FILENAME_BY_KIND.values()), 'exact-round-root')
        artifacts = []; round_row = selection['rounds'][round_number - 1]
        p1_authority = None
        for kind in ARTIFACT_ORDER:
            artifact_path = round_root / FILENAME_BY_KIND[kind]
            p1_closure = (_verified_p1_leaf(
                artifact_path, selection, round_number)
                if kind == 'corrupt-server-capture' else None)
            raw = None if p1_closure is not None else _read_leaf(artifact_path)
            if kind == 'public-projection':
                need(len(raw) == 10685 and hashlib.sha256(raw).hexdigest() ==
                     selection['financial_rounds'][round_number - 1]
                     ['retained_projection_sha256'], 'verify-projection')
                records, payload_bytes = _projection_root(raw)
                closure = _closure(records, payload_bytes, round_row)
                wire = (_event_wire_frame(
                    'hello', _hello(selection, round_number, kind))
                    + _event_wire_frame('raw', raw)
                    + _event_wire_frame('end'))
                _bind_known_event_wire(
                    closure, wire, round_number, kind)
            elif p1_closure is not None:
                closure = p1_closure
            else:
                value = parse(raw); closure = value.get('closure')
                need(type(closure) is dict, 'verify-closure')
                body = dict(value); body.pop('closure')
                # Rebuild the semantic record list through the same public
                # artifact grammar, then independently compare the closure.
                if kind == 'dispatcher-capture':
                    records = ([{'stream': 'event', 'value': row}
                                for row in body['events']]
                               + [{'stream': 'retry', 'value': row}
                                  for row in body['retry_history']])
                elif kind == 'corrupt-server-capture':
                    records = [{'stream': row['semantic'], 'value': row}
                               for row in body['records']]
                elif kind == 'colluder-wallet-capture':
                    def restored(stream, row):
                        exact(row, ('source', 'value'),
                              'verify-colluder-observed-fields')
                        return {'stream': stream, **row}
                    records = ([restored('original', body['original'])]
                               + [restored('invoice', row)
                                  for row in body['invoices']]
                               + [restored('decrypted-receipt', row)
                                  for row in body['decrypted_receipts']]
                               + [restored('retry', row)
                                  for row in body['retry_history']])
                    _validate_colluder_sources(records, round_number)
                else:
                    records = []
                    for field, stream in (
                            ('events', 'event'), ('groups', 'group'),
                            ('retry_history', 'retry'),
                            ('rejected_or_orphaned',
                             'rejected-or-orphaned'),
                            ('reorg_history', 'reorg'),
                            ('cross_round_links', 'cross-round-link')):
                        records.extend({'stream': stream, 'value': row}
                                       for row in body[field])
                rebuilt_closure = _closure(
                    records, _payload_bytes(kind, records), round_row)
                semantic_closure = dict(closure)
                for name in WIRE_CLOSURE_FIELDS:
                    semantic_closure.pop(name, None)
                need(semantic_closure == rebuilt_closure,
                     'verify-derived-closure')
                _validate_wire_closure(closure, round_number, kind)
            artifacts.append(_artifact_row(kind, closure))
            if kind == 'corrupt-server-capture':
                p1_authority = _p1_capture_authority(
                    selection, round_number, closure)
        need(p1_authority is not None, 'verify-p1-authority-missing')
        rebuilt.append({'round': round_number,
                        'attempt_id': round_row['attempt_id'],
                        'cohort_sha256': round_row['cohort_sha256'],
                        'p1_capture_authority': p1_authority,
                        'artifacts': artifacts})
        need(expected_round == rebuilt[-1], 'verify-round-root')
    need(rebuilt == receipt['rounds'], 'verify-all-roots')
    return receipt


def main():
    # Activation requires a reviewed source change plus role hooks and a fixed
    # launcher.  There is intentionally no CLI escape hatch.
    sys.stderr.write('KPB_CAPTURE_PRODUCER_SOURCE_ONLY_REFUSED\n')
    return 78


if __name__ == '__main__':
    raise SystemExit(main())
