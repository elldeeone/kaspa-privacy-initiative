"""Adversarial controls for the source-level capture producer seam.

The fixtures are synthetic. A positive control proves only that the producer
state machine closes every selected stream and derives its own artifact roots;
it is not actual observer evidence.
"""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

import privacy_capture_producer as producer
from test_privacy_capture_model import (
    colluder_fixture, corrupt_fixture, dispatcher_fixture,
    explicit_dispatcher_fixture, projection, terminal_fixture,
)


MAGIC = b'KPBCEV01'
TAGS = {'hello': 1, 'meta': 2, 'record': 3, 'raw': 4, 'end': 5}
P1_MAGIC = b'KPBP1C03'


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode()


def frame(tag, payload=b''):
    if not isinstance(payload, bytes):
        payload = encoded(payload)
    return MAGIC + bytes([TAGS[tag]]) + struct.pack('>Q', len(payload)) + payload


def semantic_parts(kind, value):
    value = copy.deepcopy(value); value.pop('closure')
    if kind == 'dispatcher-capture':
        events = value.pop('events'); retries = value.pop('retry_history')
        records = ([{'stream': 'event', 'value': row} for row in events]
                   + [{'stream': 'retry', 'value': row} for row in retries])
    elif kind == 'corrupt-server-capture':
        rows = value.pop('records')
        records = [{'stream': row['semantic'], 'value': row} for row in rows]
    elif kind == 'colluder-wallet-capture':
        original = value.pop('original'); invoices = value.pop('invoices')
        receipts = value.pop('decrypted_receipts')
        retries = value.pop('retry_history')
        observed_rows = [original, *invoices, *receipts, *retries]
        if observed_rows and all(type(row) is dict
                                 and set(row) == {'source', 'value'}
                                 for row in observed_rows):
            records = ([{'stream': 'original', **original}]
                       + [{'stream': 'invoice', **row}
                          for row in invoices]
                       + [{'stream': 'decrypted-receipt', **row}
                          for row in receipts]
                       + [{'stream': 'retry', **row}
                          for row in retries])
            return value, records
        incoming = (1 - value['round']) % 3
        outgoing = (1 + value['round']) % 3
        operations = {'invoice': invoices[0]['operation_id_sha256'],
                      'pay': '88' * 32, 'scan': '99' * 32}
        contacts = {'invoice': incoming, 'pay': outgoing,
                    'scan': incoming}
        stage_sequence = {'invoice': 0, 'pay': 1, 'scan': 2}
        def observed(stream, body, stage, sequence):
            return {'stream': stream, 'source': {
                'observer_stage': stage,
                'stage_sequence': stage_sequence[stage],
                'operation_id_sha256': operations[stage],
                'contact_owner_component': contacts[stage],
                'contact_binding_qualified': False,
                'source_event_sequence': sequence,
                'observed_monotonic_ns':
                    100 + 100 * stage_sequence[stage] + sequence,
            }, 'value': body}
        records = ([observed('original', original, 'pay', 1),
                    observed('invoice', invoices[0], 'invoice', 0),
                    observed('invoice', invoices[1], 'pay', 0)]
                   + [observed('decrypted-receipt', row, 'scan', index)
                      for index, row in enumerate(receipts)]
                   + [observed('retry', row, 'scan', 2 + index)
                      for index, row in enumerate(retries)])
    elif kind == 'terminal-history':
        records = []
        for field, stream in (
                ('events', 'event'), ('groups', 'group'),
                ('retry_history', 'retry'),
                ('rejected_or_orphaned', 'rejected-or-orphaned'),
                ('reorg_history', 'reorg'),
                ('cross_round_links', 'cross-round-link')):
            records.extend({'stream': stream, 'value': row}
                           for row in value.pop(field))
    else:
        raise AssertionError(kind)
    return value, records


def bind_dispatcher_fixture(round_number, selected, body):
    """Bind the public model fixture to this producer selection independently."""
    body = copy.deepcopy(body)
    round_row = selected['rounds'][round_number - 1]
    financial = selected['financial_rounds'][round_number - 1]
    body['cohort_sha256'] = round_row['cohort_sha256']
    body['run_sha256'] = financial['financial_run_id']
    for export in body['direct_exports']:
        export['run_sha256'] = body['run_sha256']
        export['attempt_sha256'] = body['construction_attempt_sha256']
        export['cohort_sha256'] = body['cohort_sha256']
        export['capture_plan_sha256'] = body['capture_plan_sha256']
        export['projection_sha256'] = body['projection_sha256']

    explicit = next((event for event in body['events']
                     if event['kind'] == 'explicit-owner-public-effects'),
                    None)
    explicit_sha256 = '00' * 32
    if explicit is not None:
        preimage = bytearray(b'KPB_EXPLICIT_OWNER_PUBLIC_EFFECTS_CAPTURE_V1\n')
        preimage += struct.pack('<QQ', 2, round_number)
        for name in producer.DISPATCHER_EXPORT_LINEAGE_FIELDS:
            preimage += bytes.fromhex(body['direct_exports'][0][name])
        for owner, export in enumerate(body['direct_exports']):
            preimage += struct.pack('<Q', owner)
            preimage += bytes.fromhex(export['owner_contract_sha256'])
            preimage += bytes.fromhex(export['nf_hex32'])
            preimage += b''.join(bytes.fromhex(digest)
                                 for digest in export['tuple_sha256'])
        assert len(preimage) == 693
        explicit_sha256 = hashlib.sha256(preimage).hexdigest()
        explicit['public_sha256'] = explicit_sha256

    policy = next(event for event in body['events']
                  if event['kind'] == 'release-policy-bound')
    classification = body['construction_classification']
    policy_code = (1 if body['release_order_policy'] ==
                   'SECRET_PERMUTATION_INDEPENDENT' else 2)
    preimage = bytearray(b'KPB_DISPATCHER_RELEASE_POLICY_BINDING_V1\n')
    preimage += struct.pack(
        '<QQQQ', classification, policy_code, round_number,
        len(body['direct_exports']))
    for name in ('run_sha256', 'construction_attempt_sha256',
                 'cohort_sha256', 'capture_plan_sha256',
                 'projection_sha256'):
        preimage += bytes.fromhex(body[name])
    preimage += bytes.fromhex(explicit_sha256)
    assert len(preimage) == 265
    policy['public_sha256'] = hashlib.sha256(preimage).hexdigest()
    return body


def channel(round_number, kind, selection, body):
    round_row = selection['rounds'][round_number - 1]
    hello = {
        'schema': 'kpb-capture-event-channel/v1', 'round': round_number,
        'kind': kind, 'attempt_id': round_row['attempt_id'],
        'cohort_sha256': round_row['cohort_sha256'],
        'financial_run_id': selection['financial_rounds'][round_number - 1]
            ['financial_run_id'], 'capture_identity': selection['capture_identity'],
    }
    result = frame('hello', hello)
    if kind == 'public-projection':
        result += frame('raw', body)
    else:
        body = copy.deepcopy(body)
        if kind == 'dispatcher-capture':
            body = bind_dispatcher_fixture(round_number, selection, body)
        else:
            body['cohort_sha256'] = round_row['cohort_sha256']
        meta, records = semantic_parts(kind, body)
        result += frame('meta', meta)
        result += b''.join(frame('record', row) for row in records)
    return result + frame('end')


def bound_dispatcher_channel(round_number, selection, body):
    """Encode an already-bound dispatcher body without repairing mutations."""
    round_row = selection['rounds'][round_number - 1]
    hello = {
        'schema': 'kpb-capture-event-channel/v1', 'round': round_number,
        'kind': 'dispatcher-capture',
        'attempt_id': round_row['attempt_id'],
        'cohort_sha256': round_row['cohort_sha256'],
        'financial_run_id': selection['financial_rounds'][round_number - 1]
            ['financial_run_id'],
        'capture_identity': selection['capture_identity'],
    }
    meta, records = semantic_parts('dispatcher-capture', copy.deepcopy(body))
    return (frame('hello', hello) + frame('meta', meta)
            + b''.join(frame('record', row) for row in records)
            + frame('end'))


def p1_channel(round_number, selected, preprocessing_factor=5,
               include_mac_key=True, group_state_mutation=None,
               scalar_mutation=None):
    root = bytes(32); sequence = 0; message = 0; first_time = 1000000
    counters = [[0, 0, 0] for _ in range(17)]
    total = [0, 0, 0]; out = bytearray()

    def emit(record_type, semantic, direction, peer, payload, count=False):
        nonlocal sequence, message
        payload = bytes(payload)
        header = bytearray(112); header[:8] = P1_MAGIC
        header[8:13] = bytes((record_type, semantic, direction, peer, 3))
        header[16:24] = (first_time + sequence).to_bytes(8, 'big')
        header[24:32] = sequence.to_bytes(8, 'big')
        header[32:40] = message.to_bytes(8, 'big')
        header[44:48] = len(payload).to_bytes(4, 'big')
        header[48:80] = root
        header[80:112] = hashlib.sha256(payload).digest()
        out.extend(header); out.extend(payload)
        if count:
            row = counters[semantic - 1]
            row[0] += 1; row[1] += 1; row[2] += len(payload)
            total[0] += 1; total[1] += 1; total[2] += len(payload)
        sequence += 1; message += 1

    round_row = selected['rounds'][round_number - 1]
    financial = selected['financial_rounds'][round_number - 1]
    role = next(row for row in selected['role_launch_closure']
                if row['round'] == round_number
                and row['kind'] == 'corrupt-server-capture')
    hello = (bytes((round_number, 1, 0, role['fixed_fd']))
             + round_row['attempt_id'].encode()
             + bytes.fromhex(round_row['cohort_sha256'])
             + bytes.fromhex(financial['financial_run_id'])
             + selected['capture_identity'].encode()
             + bytes.fromhex(role['source_sha256'])
             + bytes.fromhex(role['build_sha256'])
             + bytes.fromhex(role['launch_sha256'])
             + bytes.fromhex(role['model_preimage_sha256'])
             + bytes.fromhex(role['query_store_preimage_sha256'])
             + bytes.fromhex(role['scalar_capture_manifest_sha256']))
    emit(1, 1, 3, 0xff, hello)
    if include_mac_key:
        emit(2, 14, 3, 0xff, bytes(32), True)
    for owner in range(3):
        emit(2, 11, 1, owner, bytes([owner + 11])
             + bytes(preprocessing_factor * 32 - 1), True)
        emit(2, 1, 2, owner, bytes([owner + 1]) + bytes(31), True)
    emit(2, 2, 1, 2, b'opaque-peer-private', True)
    sites = list(range(1, 23))
    if scalar_mutation == 'missing-site':
        sites.remove(19)
    for site in sites:
        kind = 2 if site in producer.P1_SELECTED_RANDOMNESS_SITES else 1
        if scalar_mutation == 'wrong-kind' and site == 2:
            kind = 2
        elements = (2 if scalar_mutation == 'wrong-count' and site == 2
                    else 6 if site == 22 else 1)
        emit(2, 17, 3, 0xff,
             bytes((1, kind)) + site.to_bytes(2, 'big')
             + elements.to_bytes(8, 'big') + bytes(4), True)
        if scalar_mutation == 'duplicate-binding' and site == 2:
            emit(2, 17, 3, 0xff,
                 bytes((1, kind)) + site.to_bytes(2, 'big')
                 + elements.to_bytes(8, 'big') + bytes(4), True)
        first, second = (5, 6) if kind == 2 else (3, 4)
        order = ((second, first) if scalar_mutation == 'wrong-order'
                 and site == 2 else (first, second))
        for semantic in order:
            payload_elements = (1 if scalar_mutation == 'wrong-count'
                                and site == 2 else elements)
            emit(2, semantic, 3, 0xff,
                 (bytes([semantic]) + bytes(31)) * payload_elements, True)
    base_g1 = bytearray(bytes((1,)) + bytes(4 * 130))
    if group_state_mutation == 'g1-identity-alias':
        base_g1[2] = 1
    base_g2 = bytearray(bytes((1,)) + bytes(258))
    if group_state_mutation == 'g2-fq-range':
        base_g2[1] = 1
        base_g2[2:34] = producer.P1_FQ_MODULUS.to_bytes(32, 'little')
    mixed_stage = 3 if group_state_mutation == 'g1-stage' else 2
    mixed_g1 = bytearray(bytes((mixed_stage,)) + bytes(6 * 130))
    generator = bytes((1,)) + (1).to_bytes(32, 'little') \
        + (2).to_bytes(32, 'little')
    if group_state_mutation == 'equation-d':
        mixed_g1[1 + 2 * 130:1 + 2 * 130 + 65] = generator
    if group_state_mutation == 'g1-width':
        mixed_g1 = mixed_g1[:-1]
    emit(2, 15, 3, 0xff, base_g1, True)
    emit(2, 16, 3, 0xff, base_g2, True)
    emit(2, 15, 3, 0xff, mixed_g1, True)
    emit(2, 13, 3, 0xff, bytes(2 * 32), True)
    emit(2, 12, 3, 0xff, bytes(2 * 65), True)
    products_g1 = bytearray(bytes((3,)) + bytes(2 * 130))
    if group_state_mutation == 'equation-product':
        products_g1[1:66] = generator
    emit(2, 15, 3, 0xff, products_g1, True)
    final_g1 = bytearray(bytes((4,)) + bytes(2 * 130))
    if group_state_mutation == 'g1-final-a-share':
        final_g1[1] = 1
    if group_state_mutation == 'g1-final-a-mac':
        final_g1[1 + 65] = 1
    if group_state_mutation == 'equation-c':
        final_g1[1 + 130:1 + 130 + 65] = generator
    final_g2 = bytearray(bytes((4,)) + bytes(258))
    if group_state_mutation == 'g2-final-share':
        final_g2[1] = 1
    if group_state_mutation == 'g2-final-mac':
        final_g2[1 + 129] = 1
    emit(2, 15, 3, 0xff, final_g1, True)
    emit(2, 16, 3, 0xff, final_g2, True)
    emit(2, 7, 3, 0xff, bytes(2 * 65), True)
    emit(2, 8, 3, 0xff, bytes(129), True)
    projection_raw = projection(round_number)[0]
    emit(2, 9, 3, 0xff, projection_raw, True)
    emit(2, 10, 3, 0xff, bytes(32), True)
    emit(3, 9, 3, 0xff, hashlib.sha256(projection_raw).digest())
    footer = bytearray(struct.pack('>II', 9, 17))
    footer += b''.join(struct.pack('>Q', value) for value in total)
    for row in counters:
        footer += b''.join(struct.pack('>Q', value) for value in row)
    footer += struct.pack('>QQQQQQQ', 0x1ffff, 7, 7, (1 << 22) - 1,
                          sequence, first_time, first_time + sequence - 1)
    emit(4, 9, 3, 0xff, footer)
    emit(5, 9, 3, 0xff, b'')
    return bytes(out)


def selection():
    roles = []
    for index, (round_number, kind) in enumerate(producer.CHANNEL_ORDER):
        role = {
            'round': round_number, 'kind': kind,
            'role': producer.ROLE_BY_KIND[kind],
            'source_sha256': ('%02x' % (40 + index)) * 32,
            'build_sha256': ('%02x' % (60 + index)) * 32,
            'launch_sha256': ('%02x' % (80 + index)) * 32,
            'fixed_fd': 20 + index,
        }
        if kind == 'corrupt-server-capture':
            role.update({
                'model_preimage_sha256': ('%02x' % (100 + index)) * 32,
                'query_store_preimage_sha256': ('%02x' % (120 + index)) * 32,
                'scalar_capture_manifest_sha256':
                    '5e6903569bc71cbfb5549b369b79a19ecda6686dc4ab25fca0d161c6e1527b6b',
            })
        roles.append(role)
    return {
        'schema': 'kpb-capture-producer-source-selection/v1',
        'status': 'UNQUALIFIED_SOURCE_ONLY',
        'classification': 'ACTUAL_HIDDEN_MAPPING_CANDIDATE',
        'binding': {
            'method_sha256': '10' * 32, 'selection_sha256': '11' * 32,
            'trial_id': '11111111-1111-4111-8111-111111111111',
            'phase': 'private-batch-privacy',
            'attempt_id': 'capture-producer-source-only',
        },
        'capture_identity': '22222222-2222-4222-8222-222222222222',
        'producer_source_sha256': producer.source_sha256(),
        'producer_build_sha256': '12' * 32,
        'role_launch_closure': roles,
        'financial_rounds': [
            {'round': number,
             'financial_run_id': ('%02x' % (20 + number)) * 32,
             'financial_artifacts_sha256': ('%02x' % (22 + number)) * 32,
             'financial_result_sha256': ('%02x' % (24 + number)) * 32,
             'retained_projection_sha256': hashlib.sha256(
                 projection(number)[0]).hexdigest()}
            for number in (1, 2)
        ],
        'rounds': [
            {'round': 1, 'attempt_id': '33333333-3333-4333-8333-333333333333',
             'cohort_sha256': '31' * 32},
            {'round': 2, 'attempt_id': '44444444-4444-4444-8444-444444444444',
             'cohort_sha256': '32' * 32},
        ],
        'integration': {
            'role_hooks_integrated': False,
            'fixed_fd_inheritance_selected': False,
            'launcher_selected': False,
            'actual_receipt_schema_enabled': False,
        },
    }


def bodies(selected):
    result = {}
    for number in (1, 2):
        raw_projection, public = projection(number)
        round_row = selected['rounds'][number - 1]
        financial = selected['financial_rounds'][number - 1]
        construction_attempt = hashlib.sha256(
            b'producer-test-construction-attempt-v1\n'
            + round_row['attempt_id'].encode()).hexdigest()
        capture_plan = hashlib.sha256(
            b'producer-test-capture-plan-v1\n'
            + bytes.fromhex(selected['binding']['selection_sha256'])
            + number.to_bytes(4, 'big')
            + bytes.fromhex(financial['financial_run_id'])).hexdigest()
        dispatcher_args = {
            'cohort_sha256': round_row['cohort_sha256'],
            'run_sha256': financial['financial_run_id'],
            'construction_attempt_sha256': construction_attempt,
            'capture_plan_sha256': capture_plan,
        }
        result[(number, 'public-projection')] = raw_projection
        result[(number, 'terminal-history')] = terminal_fixture(public)
        dispatcher = (explicit_dispatcher_fixture(public, **dispatcher_args)
                      if selected['classification'] ==
                         'ACTUAL_TRANSPARENT_BASELINE'
                      else dispatcher_fixture(public, **dispatcher_args))
        result[(number, 'dispatcher-capture')] = dispatcher
        result[(number, 'corrupt-server-capture')] = corrupt_fixture(
            public, raw_projection)
        result[(number, 'colluder-wallet-capture')] = colluder_fixture(public)
    return result


def pipes(raw_streams):
    readers = {}
    for key, raw in raw_streams.items():
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        at = 0
        while at < len(raw):
            count = os.write(write_fd, raw[at:]); at += count
        os.close(write_fd); readers[key] = read_fd
    return readers


def dependency_pipes(raw_streams):
    """Make projection wait for a pipe-capacity P1 write to finish."""
    readers = {}; writers = {}
    p1_key = (1, 'corrupt-server-capture')
    projection_key = (1, 'public-projection')
    for key in raw_streams:
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        if key == p1_key:
            fcntl.fcntl(write_fd, fcntl.F_SETPIPE_SZ, 4096)
            capacity = fcntl.fcntl(write_fd, fcntl.F_GETPIPE_SZ)
            if len(raw_streams[key]) <= capacity:
                raise AssertionError('P1 exploit stream must exceed pipe capacity')
        readers[key] = read_fd; writers[key] = write_fd
    p1_complete = threading.Event(); errors = []

    def write_stream(key):
        fd = writers[key]
        try:
            if key == projection_key and not p1_complete.wait(3):
                return
            raw = raw_streams[key]; at = 0
            while at < len(raw):
                at += os.write(fd, raw[at:])
            if key == p1_key:
                p1_complete.set()
        except BaseException as error:
            errors.append((key, error))
        finally:
            os.close(fd)

    threads = [threading.Thread(target=write_stream, args=(key,), daemon=True)
               for key in raw_streams]
    for thread in threads:
        thread.start()
    return readers, threads, p1_complete, errors


def held_prefix_pipes(raw_streams, held_key, prefix):
    """Write one prefix and keep that writer open until the test releases it."""
    readers = {}; writers = {}
    for key in raw_streams:
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        readers[key] = read_fd; writers[key] = write_fd
    release = threading.Event(); hold_expired = threading.Event(); errors = []

    def write_stream(key):
        fd = writers[key]
        try:
            raw = prefix if key == held_key else raw_streams[key]
            at = 0
            while at < len(raw):
                at += os.write(fd, raw[at:])
            if key == held_key and not release.wait(2):
                hold_expired.set()
        except BaseException as error:
            errors.append((key, error))
        finally:
            os.close(fd)

    threads = [threading.Thread(target=write_stream, args=(key,), daemon=True)
               for key in raw_streams]
    for thread in threads:
        thread.start()
    return readers, threads, release, hold_expired, errors


def streams(selected):
    return {key: channel(key[0], key[1], selected, value)
            for key, value in bodies(selected).items()}


class CaptureProducerControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def produce(self, selected=None, raw_streams=None, name='capture'):
        selected = selection() if selected is None else selected
        raw_streams = streams(selected) if raw_streams is None else raw_streams
        return producer.source_only_produce(
            selected, pipes(raw_streams), self.root / name)

    def test_complete_streams_derive_closed_non_authorizing_receipt(self):
        result = self.produce()
        self.assertEqual(result['status'], 'UNQUALIFIED_SOURCE_ONLY')
        self.assertFalse(result['launch_authorized'])
        self.assertFalse(result['actual_receipt_emitted'])
        self.assertEqual(result['unknown_record_count'], 0)
        self.assertTrue(result['append_only_roots_closed'])
        expected_counts = {
            'public-projection': 1, 'terminal-history': 4,
            'dispatcher-capture': 10, 'corrupt-server-capture': 24,
            'colluder-wallet-capture': 5,
        }
        for round_row in result['rounds']:
            self.assertEqual({row['kind']: row['producer_record_count']
                              for row in round_row['artifacts']},
                             expected_counts)
        self.assertEqual(producer.verify_source_only(
            self.root / 'capture', selection()), result)

    def test_explicit_baseline_policy_and_mapping_are_bound_before_close(self):
        selected = selection()
        selected['classification'] = 'ACTUAL_TRANSPARENT_BASELINE'
        result = self.produce(selected, name='baseline')
        for round_row in result['rounds']:
            dispatcher = next(row for row in round_row['artifacts']
                              if row['kind'] == 'dispatcher-capture')
            self.assertEqual(dispatcher['producer_record_count'], 11)
        self.assertEqual(producer.verify_source_only(
            self.root / 'baseline', selected), result)

    def test_dispatcher_policy_event_omission_order_and_hash_refuse(self):
        selected = selection(); original = bodies(selected)[
            (1, 'dispatcher-capture')]
        mutations = []

        changed = copy.deepcopy(original)
        changed['events'] = [event for event in changed['events']
                             if event['kind'] != 'release-policy-bound']
        for sequence, event in enumerate(changed['events']):
            event['sequence'] = sequence
        mutations.append(('missing', changed, 'dispatcher-complete-events'))

        changed = copy.deepcopy(original)
        policy = next(event for event in changed['events']
                      if event['kind'] == 'release-policy-bound')
        policy['public_sha256'] = 'ff' * 32
        mutations.append(
            ('hash', changed, 'dispatcher-release-policy-binding'))

        changed = copy.deepcopy(original)
        policy_index = next(index for index, event in enumerate(
            changed['events']) if event['kind'] == 'release-policy-bound')
        changed['events'][policy_index], changed['events'][policy_index + 1] = \
            changed['events'][policy_index + 1], changed['events'][policy_index]
        for sequence, event in enumerate(changed['events']):
            event['sequence'] = sequence
            event['monotonic_ns'] = 100 + sequence
        mutations.append(
            ('order', changed, 'dispatcher-hidden-policy-order'))

        changed = copy.deepcopy(original)
        policy = next(event for event in changed['events']
                      if event['kind'] == 'release-policy-bound')
        policy['bytes'] += 1
        mutations.append(
            ('width', changed, 'dispatcher-release-policy-event'))

        for name, body, category in mutations:
            with self.subTest(name=name):
                raw = streams(selected)
                raw[(1, 'dispatcher-capture')] = bound_dispatcher_channel(
                    1, selected, body)
                with self.assertRaisesRegex(ValueError, category):
                    self.produce(selected, raw, 'dispatcher-' + name)

    def test_dispatcher_selected_and_explicit_lineage_refuse(self):
        selected = selection()
        selected['classification'] = 'ACTUAL_TRANSPARENT_BASELINE'
        original = bodies(selected)[(1, 'dispatcher-capture')]
        mutations = []

        changed = copy.deepcopy(original)
        changed['run_sha256'] = 'ff' * 32
        mutations.append(
            ('run', changed, 'dispatcher-selected-policy-binding'))

        for name, field in (('attempt', 'construction_attempt_sha256'),
                            ('plan', 'capture_plan_sha256')):
            changed = copy.deepcopy(original)
            changed[field] = 'fe' * 32
            mutations.append(
                (name, changed, 'dispatcher-direct-export-binding'))

        for name, field in (('trial', 'trial_sha256'),
                            ('context', 'context_sha256')):
            changed = copy.deepcopy(original)
            changed['direct_exports'][1][field] = 'fd' * 32
            mutations.append(
                (name, changed, 'dispatcher-direct-export-binding'))

        changed = copy.deepcopy(original)
        changed['direct_exports'][1]['owner_contract_sha256'] = \
            changed['direct_exports'][0]['owner_contract_sha256']
        mutations.append(
            ('contract', changed, 'dispatcher-direct-export-binding'))

        changed = copy.deepcopy(original)
        changed['construction_classification'] = 1
        mutations.append(
            ('classification', changed,
             'dispatcher-selected-policy-binding'))

        for name, body, category in mutations:
            with self.subTest(name=name):
                raw = streams(selected)
                raw[(1, 'dispatcher-capture')] = bound_dispatcher_channel(
                    1, selected, body)
                with self.assertRaisesRegex(ValueError, category):
                    self.produce(selected, raw, 'explicit-' + name)

    def test_preprojection_p1_backpressure_is_drained_concurrently(self):
        selected = selection(); readers, threads, completed, errors = \
            dependency_pipes(streams(selected))
        result = producer.source_only_produce(
            selected, readers, self.root / 'backpressure')
        for thread in threads:
            thread.join(1)
        self.assertTrue(completed.is_set())
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertFalse(result['launch_authorized'])
        self.assertFalse(result['actual_receipt_emitted'])

    def test_c03_p1_is_strictly_parsed_and_retained_as_opaque_unqualified_wire(self):
        selected = selection(); raw = streams(selected)
        for number in (1, 2):
            raw[(number, 'corrupt-server-capture')] = p1_channel(
                number, selected)
        result = self.produce(selected, raw, 'p1-c03')
        self.assertEqual(result['status'], 'UNQUALIFIED_SOURCE_ONLY')
        self.assertFalse(result['launch_authorized'])
        self.assertFalse(result['actual_receipt_emitted'])
        for number in (1, 2):
            artifact = self.root / f'p1-c03/round-{number}/corrupt-server.json'
            self.assertEqual(artifact.read_bytes()[:8], P1_MAGIC)
            round_result = result['rounds'][number - 1]
            row = next(item for item in round_result['artifacts']
                       if item['kind'] == 'corrupt-server-capture')
            self.assertEqual(row['producer_record_count'], 86)
            role = next(item for item in selected['role_launch_closure']
                        if item['round'] == number
                        and item['kind'] == 'corrupt-server-capture')
            authority = round_result['p1_capture_authority']
            self.assertEqual(authority, {
                'round': number,
                'attempt_id': selected['rounds'][number - 1]['attempt_id'],
                'cohort_sha256': selected['rounds'][number - 1]
                    ['cohort_sha256'],
                'financial_run_id': selected['financial_rounds'][number - 1]
                    ['financial_run_id'],
                'capture_identity': selected['capture_identity'],
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
                'closure': authority['closure'],
            })
            self.assertEqual(authority['closure']['record_chain_sha256'],
                             row['record_chain_sha256'])
            wire = raw[(number, 'corrupt-server-capture')]
            closure = authority['closure']
            self.assertEqual(closure['raw_wire_bytes'], len(wire))
            self.assertEqual(closure['raw_wire_sha256'],
                             hashlib.sha256(wire).hexdigest())
            self.assertEqual(closure['end_frame_identity'],
                             hashlib.sha256(wire[-112:]).hexdigest())
            eof = (b'KPB_CAPTURE_PRODUCER_STREAM_EOF_V1\n'
                   + struct.pack('>IBQQQ', number, 4,
                                 closure['producer_record_count'],
                                 closure['producer_payload_bytes'], len(wire))
                   + hashlib.sha256(wire).digest()
                   + hashlib.sha256(wire[-112:]).digest())
            self.assertEqual(closure['eof_identity'],
                             hashlib.sha256(eof).hexdigest())
        self.assertEqual(producer.verify_source_only(
            self.root / 'p1-c03', selected), result)

    def test_c03_p1_replay_time_footer_and_truncation_refuse(self):
        for mutation in ('replay', 'time', 'footer', 'truncated'):
            with self.subTest(mutation=mutation):
                selected = selection(); raw = streams(selected)
                key = (1, 'corrupt-server-capture')
                value = bytearray(p1_channel(1, selected))
                first_size = int.from_bytes(value[44:48], 'big')
                first_end = 112 + first_size
                if mutation == 'replay':
                    value[first_end:first_end] = value[:first_end]
                elif mutation == 'time':
                    value[first_end + 16:first_end + 24] = (1).to_bytes(8, 'big')
                elif mutation == 'footer':
                    at = 0
                    while value[at + 8] != 4:
                        at += 112 + int.from_bytes(value[at + 44:at + 48], 'big')
                    payload_at = at + 112
                    value[payload_at + 440:payload_at + 448] = bytes(8)
                    size = int.from_bytes(value[at + 44:at + 48], 'big')
                    value[at + 80:at + 112] = hashlib.sha256(
                        value[payload_at:payload_at + size]).digest()
                else:
                    value = value[:-1]
                raw[key] = bytes(value)
                raw[(2, 'corrupt-server-capture')] = p1_channel(2, selected)
                with self.assertRaises((ValueError, EOFError)):
                    self.produce(selected, raw, 'p1-' + mutation)

    def test_c03_p1_hello_binds_fixed_fd_source_build_and_launch(self):
        for name, payload_offset in (
                ('fixed-fd', 3), ('source', 140),
                ('build', 172), ('launch', 204), ('model', 236),
                ('query-store', 268), ('scalar-manifest', 300)):
            with self.subTest(name=name):
                selected = selection(); raw = streams(selected)
                key = (1, 'corrupt-server-capture')
                value = bytearray(p1_channel(1, selected))
                value[112 + payload_offset] ^= 1
                hello_size = int.from_bytes(value[44:48], 'big')
                value[80:112] = hashlib.sha256(
                    value[112:112 + hello_size]).digest()
                raw[key] = bytes(value)
                raw[(2, 'corrupt-server-capture')] = p1_channel(2, selected)
                with self.assertRaisesRegex(ValueError, 'p1-hello-binding'):
                    self.produce(selected, raw, 'p1-binding-' + name)

    def test_c03_p1_requires_exact_five_to_one_owner_preprocessing_view(self):
        selected = selection(); raw = streams(selected)
        raw[(1, 'corrupt-server-capture')] = p1_channel(
            1, selected, preprocessing_factor=4)
        raw[(2, 'corrupt-server-capture')] = p1_channel(2, selected)
        with self.assertRaisesRegex(ValueError, 'p1-completeness-counters'):
            self.produce(selected, raw, 'p1-wrong-owner-preprocessing-width')

    def test_c03_p1_scalar_binding_is_complete_typed_atomic_and_sized(self):
        categories = {
            'missing-site': 'p1-completeness-counters',
            'wrong-kind': 'p1-scalar-binding-shape',
            'wrong-count': 'p1-scalar-binding-width',
            'wrong-order': 'p1-scalar-binding-order',
            'duplicate-binding': 'p1-scalar-binding-order',
        }
        for mutation, category in categories.items():
            with self.subTest(mutation=mutation):
                selected = selection(); raw = streams(selected)
                raw[(1, 'corrupt-server-capture')] = p1_channel(
                    1, selected, scalar_mutation=mutation)
                raw[(2, 'corrupt-server-capture')] = p1_channel(2, selected)
                with self.assertRaisesRegex(ValueError, category):
                    self.produce(selected, raw, 'p1-scalar-' + mutation)

    def test_c03_p1_refuses_missing_local_mac_key_share(self):
        selected = selection(); raw = streams(selected)
        raw[(1, 'corrupt-server-capture')] = p1_channel(
            1, selected, include_mac_key=False)
        raw[(2, 'corrupt-server-capture')] = p1_channel(2, selected)
        with self.assertRaisesRegex(ValueError, 'p1-mac-key-order'):
            self.produce(selected, raw, 'p1-missing-mac-key')

    def test_c03_p1_refuses_group_stage_width_and_repeated_state_tamper(self):
        for mutation in (
                'g1-stage', 'g1-width', 'g1-identity-alias', 'g2-fq-range',
                'g1-final-a-share', 'g1-final-a-mac', 'g2-final-share',
                'g2-final-mac'):
            with self.subTest(mutation=mutation):
                selected = selection(); raw = streams(selected)
                raw[(1, 'corrupt-server-capture')] = p1_channel(
                    1, selected, group_state_mutation=mutation)
                raw[(2, 'corrupt-server-capture')] = p1_channel(2, selected)
                with self.assertRaisesRegex(
                        ValueError, 'p1-authenticated-group-state'):
                    self.produce(selected, raw, 'p1-group-' + mutation)

    def test_uint64_frame_length_refuses_before_payload_read(self):
        selected = selection(); raw = streams(selected)
        held_key = (1, 'corrupt-server-capture')
        huge_header = (MAGIC + bytes([TAGS['hello']])
                       + struct.pack('>Q', (1 << 64) - 1))
        readers, threads, release, hold_expired, _ = held_prefix_pipes(
            raw, held_key, huge_header)
        try:
            with self.assertRaisesRegex(
                    ValueError, 'frame-size-corrupt-server-capture'):
                producer.source_only_produce(
                    selected, readers, self.root / 'huge-frame')
        finally:
            release.set()
            for thread in threads:
                thread.join(1)
        self.assertFalse(hold_expired.is_set())
        self.assertFalse((self.root / 'huge-frame/PRODUCER.json').exists())

    def test_stalled_partial_stream_refuses_without_receipt(self):
        selected = selection(); raw = streams(selected)
        held_key = (1, 'corrupt-server-capture')
        hello_size = struct.unpack('>Q', raw[held_key][9:17])[0]
        prefix = raw[held_key][:17 + hello_size] + MAGIC[:5]
        readers, threads, release, hold_expired, _ = held_prefix_pipes(
            raw, held_key, prefix)
        try:
            with mock.patch.object(
                    producer, 'SOURCE_ONLY_NO_PROGRESS_SECONDS', 0.05):
                with self.assertRaisesRegex(
                        ValueError, 'channel-no-progress-source-only'):
                    producer.source_only_produce(
                        selected, readers, self.root / 'stalled')
        finally:
            release.set()
            for thread in threads:
                thread.join(1)
        self.assertFalse(hold_expired.is_set())
        self.assertFalse((self.root / 'stalled/PRODUCER.json').exists())

    def test_stream_aggregate_and_record_caps_refuse(self):
        controls = (
            ('stream', 'STREAM_WIRE_LIMIT',
             {'corrupt-server-capture': 1000},
             'stream-bytes-corrupt-server-capture'),
            ('aggregate', 'AGGREGATE_WIRE_LIMIT', 1000,
             'aggregate-bytes'),
            ('records', 'STREAM_RECORD_LIMIT',
             {'corrupt-server-capture': 8},
             'stream-records-corrupt-server-capture'),
            ('aggregate-records', 'AGGREGATE_RECORD_LIMIT', 1,
             'aggregate-records'),
        )
        for name, target, value, category in controls:
            with self.subTest(name=name):
                selected = selection()
                patch = (mock.patch.dict(getattr(producer, target), value)
                         if isinstance(value, dict)
                         else mock.patch.object(producer, target, value))
                with patch, self.assertRaisesRegex(ValueError, category):
                    self.produce(selected, name=name + '-cap')
                self.assertFalse(
                    (self.root / (name + '-cap') / 'PRODUCER.json').exists())

    def test_missing_duplicate_out_of_order_truncated_and_extra_refuse(self):
        for mutation in ('missing', 'duplicate', 'out-of-order',
                         'truncated', 'extra'):
            with self.subTest(mutation=mutation):
                selected = selection(); raw = streams(selected)
                key = (1, 'dispatcher-capture'); original = raw[key]
                if mutation == 'missing': raw.pop(key)
                elif mutation == 'duplicate':
                    at = original.index(MAGIC + bytes([TAGS['meta']]))
                    size = struct.unpack('>Q', original[at + 9:at + 17])[0]
                    duplicate = original[at:at + 17 + size]
                    raw[key] = original[:at + len(duplicate)] + duplicate + original[at + len(duplicate):]
                elif mutation == 'out-of-order':
                    first = original.index(MAGIC + bytes([TAGS['record']]))
                    meta = original.index(MAGIC + bytes([TAGS['meta']]))
                    raw[key] = original[:meta] + original[first:]
                elif mutation == 'truncated': raw[key] = original[:-3]
                else: raw[key] = original + b'extra'
                with self.assertRaises((ValueError, EOFError)):
                    self.produce(selected, raw, mutation)

    def test_swapped_role_streams_refuse(self):
        selected = selection(); raw = streams(selected)
        left = (1, 'dispatcher-capture'); right = (1, 'colluder-wallet-capture')
        raw[left], raw[right] = raw[right], raw[left]
        with self.assertRaisesRegex(ValueError, 'channel-hello'):
            self.produce(selected, raw, 'swapped')

    def test_reused_attempt_or_cohort_refuses_before_channels(self):
        for name in ('attempt_id', 'cohort_sha256'):
            with self.subTest(name=name):
                selected = selection(); selected['rounds'][1][name] = selected['rounds'][0][name]
                with self.assertRaisesRegex(ValueError, 'fresh-round'):
                    producer.source_only_produce(selected, {}, self.root / name)

    def test_early_close_refuses(self):
        selected = selection(); raw = streams(selected)
        key = (2, 'corrupt-server-capture'); raw[key] = raw[key][:-17]
        with self.assertRaises((ValueError, EOFError)):
            self.produce(selected, raw, 'early')

    def test_self_authored_receipt_and_source_drift_refuse(self):
        target = self.root / 'capture'; target.mkdir()
        (target / 'PRODUCER.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'fresh-output-root'):
            self.produce(name='capture')
        selected = selection(); selected['producer_source_sha256'] = 'ff' * 32
        with self.assertRaisesRegex(ValueError, 'executing-source'):
            self.produce(selected, name='drift')

    def test_deletion_or_extra_artifact_breaks_verification(self):
        result = self.produce(); target = self.root / 'capture/round-2/terminal.json'
        target.chmod(0o600); target.unlink()
        with self.assertRaises((ValueError, FileNotFoundError)):
            producer.verify_source_only(self.root / 'capture', selection())
        self.assertFalse(result['launch_authorized'])
        other = self.produce(name='extra')
        extra = self.root / 'extra/round-1/unmodeled.bin'
        extra.write_bytes(b'unmodeled'); extra.chmod(0o400)
        with self.assertRaisesRegex(ValueError, 'exact-round-root'):
            producer.verify_source_only(self.root / 'extra', selection())
        self.assertFalse(other['launch_authorized'])

    def test_executable_has_no_source_only_activation_escape_hatch(self):
        result = subprocess.run(
            [sys.executable, '-B', str(Path(producer.__file__))],
            text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 78)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr,
                         'KPB_CAPTURE_PRODUCER_SOURCE_ONLY_REFUSED\n')


if __name__ == '__main__':
    unittest.main()
