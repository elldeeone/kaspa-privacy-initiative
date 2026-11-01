import hashlib
import struct
import unittest
import uuid

import privacy_p1_empirical_observer as empirical


MAGIC = b'KPBP1C03'


def frame(*, record_type, semantic, direction, peer, flags=3,
          monotonic_ns, sequence, message, chunk=0, fork=bytes(32),
          payload=b''):
    header = bytearray(112)
    header[:8] = MAGIC
    header[8:13] = bytes((record_type, semantic, direction, peer, flags))
    header[16:24] = struct.pack('>Q', monotonic_ns)
    header[24:32] = struct.pack('>Q', sequence)
    header[32:40] = struct.pack('>Q', message)
    header[40:44] = struct.pack('>I', chunk)
    header[44:48] = struct.pack('>I', len(payload))
    header[48:80] = fork
    header[80:112] = hashlib.sha256(payload).digest()
    return bytes(header) + payload


def complete_capture(peer_payload=b'peer-opaque', *, base_time=1_000,
                     direction=1, peer=0, fork=bytes(32), extra_peer=False):
    rows = [frame(record_type=2, semantic=2, direction=direction, peer=peer,
                  monotonic_ns=base_time, sequence=0, message=0, fork=fork,
                  payload=peer_payload)]
    sequence = 1
    if extra_peer:
        rows.append(frame(
            record_type=2, semantic=2, direction=direction, peer=peer,
            monotonic_ns=base_time + 40, sequence=sequence,
            message=sequence, fork=fork, payload=peer_payload[::-1]))
        sequence += 1
    rows.append(frame(
        record_type=5, semantic=9, direction=3, peer=0xff,
        monotonic_ns=base_time + 100, sequence=sequence, message=sequence,
        payload=b''))
    return b''.join(rows)


def attempt_history(raw, *, outcome='COMPLETE', failure_code='NONE',
                    attempt_id='11111111-1111-4111-8111-111111111111',
                    start=900, end=1_200):
    return {
        'schema': 'kpb-p1-passive-attempt-history/v1',
        'attempts': [{
            'attempt_id': str(uuid.UUID(attempt_id)),
            'retry_ordinal': 0,
            'predecessor_attempt_id': None,
            'start_monotonic_ns': start,
            'end_monotonic_ns': end,
            'outcome': outcome,
            'failure_code': failure_code,
            'capture_sha256': hashlib.sha256(raw).hexdigest(),
        }],
    }


def v9_hello_payload(attempt_id, capture_identity):
    payload = bytearray(332)
    payload[0:4] = bytes((1, 1, 0, 23))
    payload[4:40] = attempt_id.encode()
    payload[40:72] = bytes.fromhex('11' * 32)
    payload[72:104] = bytes.fromhex('22' * 32)
    payload[104:140] = capture_identity.encode()
    payload[140:172] = bytes.fromhex('33' * 32)
    payload[172:204] = bytes.fromhex('44' * 32)
    payload[204:236] = bytes.fromhex('55' * 32)
    payload[236:268] = bytes.fromhex('66' * 32)
    payload[268:300] = bytes.fromhex('77' * 32)
    payload[300:332] = bytes.fromhex(
        empirical.V9_SCALAR_CAPTURE_MANIFEST_SHA256)
    return bytes(payload)


def v9_footer_payload(*, sequence, first_ns, last_ns,
                      total=(0, 0, 0), lanes=None):
    payload = bytearray(496)
    payload[0:4] = (9).to_bytes(4, 'big')
    payload[4:8] = (17).to_bytes(4, 'big')
    for index, value in enumerate(total):
        payload[8 + 8 * index:16 + 8 * index] = value.to_bytes(8, 'big')
    lanes = {} if lanes is None else lanes
    for semantic in range(1, 18):
        values = lanes.get(semantic, (0, 0, 0))
        at = 32 + 24 * (semantic - 1)
        for index, value in enumerate(values):
            payload[at + 8 * index:at + 8 * (index + 1)] = \
                value.to_bytes(8, 'big')
    payload[440:448] = (0x1ffff).to_bytes(8, 'big')
    payload[448:456] = (7).to_bytes(8, 'big')
    payload[456:464] = (7).to_bytes(8, 'big')
    payload[464:472] = empirical.V9_SCALAR_SITE_BITMAP.to_bytes(8, 'big')
    payload[472:480] = sequence.to_bytes(8, 'big')
    payload[480:488] = first_ns.to_bytes(8, 'big')
    payload[488:496] = last_ns.to_bytes(8, 'big')
    return bytes(payload)


def synthetic_clear_signal_calibration_rows():
    """Classifier mechanics only; these fabricated rows authorize no gate."""
    rows = []
    required = {'HONEST_A': {'TRAIN': 24, 'HOLDOUT': 24},
                'HONEST_B': {'TRAIN': 24, 'HOLDOUT': 24}}
    counts = {label: {'TRAIN': 0, 'HOLDOUT': 0} for label in required}
    index = 0
    while any(counts[label][split] < required[label][split]
              for label in required for split in required[label]):
        for label in required:
            calibration_id = str(uuid.uuid5(
                uuid.NAMESPACE_URL, f'kpb-{label}-{index}'))
            split = empirical.calibration_split(calibration_id)
            if counts[label][split] >= required[label][split]:
                continue
            is_a = label == 'HONEST_A'
            raw = complete_capture(
                (b'A' if is_a else b'B') * (12 if is_a else 28) +
                bytes((index % 251,)),
                base_time=(1_000 if is_a else 10_000) + index,
                direction=1 if is_a else 2,
                peer=0 if is_a else 2,
                fork=bytes(32) if is_a else bytes([7]) * 32,
                extra_peer=not is_a)
            attempt_id = str(uuid.uuid5(
                uuid.NAMESPACE_OID, f'attempt-{label}-{index}'))
            rows.append({
                'calibration_id': calibration_id,
                'mapping_id': label,
                'corpus_provenance': 'SYNTHETIC_UNIT_TEST',
                'raw': raw,
                'attempt_history': attempt_history(
                    raw, attempt_id=attempt_id,
                    start=(800 if is_a else 8_000) + index,
                    end=(1_300 if is_a else 11_000) + index),
            })
            counts[label][split] += 1
        index += 1
    return rows


def exact_constraint_plan(features, *, corrupt_b=False):
    observations = features['exact_observations']
    attempts = observations['attempts']
    events = []
    joins_a = []
    joins_b = []
    frame_join_ids = []
    attempt_join_ids = []
    frame_source_rank = 0
    join_ordinal = 0
    mapping_a = {'public-slot-0': 'candidate-x',
                 'public-slot-1': 'candidate-y'}
    mapping_b = {'public-slot-0': 'candidate-y',
                 'public-slot-1': 'candidate-x'}
    frame_fields = [
        'record_type', 'semantic', 'direction', 'peer', 'flags', 'sequence',
        'message', 'chunk', 'payload_length', 'fork_hex', 'payload_sha256',
    ]
    for attempt in attempts:
        attempt_id = attempt['attempt_id']
        attempt_event = {
            'event_id': f'attempt-a-{attempt_id}',
            'source_id': 'source-attempt-history',
            'source_role_kind': 'dispatcher-capture',
            'source_round': 1,
            'source_record_root_sha256': '2' * 64,
            'structural_identity':
                mapping_a[f'public-slot-{join_ordinal % 2}'],
            'clock_domain_id': 'clock-p1',
            'source_rank': 2 * attempt['retry_ordinal'],
            'kind': 'ATTEMPT',
            'fields': {
                name: attempt[name] for name in (
                    'attempt_id', 'retry_ordinal', 'predecessor_attempt_id',
                    'start_monotonic_ns', 'end_monotonic_ns', 'outcome',
                    'failure_code', 'capture_sha256', 'stream_state',
                    'partial_tail_length', 'partial_tail_sha256')
            },
        }
        events.append(attempt_event)
        duplicate = dict(attempt_event)
        duplicate['event_id'] = f'attempt-b-{attempt_id}'
        duplicate['source_rank'] = 2 * attempt['retry_ordinal'] + 1
        duplicate['structural_identity'] = (
            mapping_b[f'public-slot-{join_ordinal % 2}'])
        duplicate['fields'] = dict(attempt_event['fields'])
        events.append(duplicate)
        join_id = f'attempt-{attempt["retry_ordinal"]}'
        attempt_join_ids.append(join_id)
        structural_key = f'public-slot-{join_ordinal % 2}'
        reference = {'kind': 'ATTEMPT', 'attempt_id': attempt_id}
        exact_fields = list(attempt_event['fields'])
        joins_a.append({
            'join_id': join_id, 'structural_key': structural_key,
            'p1_ref': reference,
            'event_id': attempt_event['event_id'],
            'exact_fields': exact_fields,
        })
        joins_b.append({
            'join_id': join_id, 'structural_key': structural_key,
            'p1_ref': reference,
            'event_id': duplicate['event_id'],
            'exact_fields': exact_fields,
        })
        join_ordinal += 1
        for frame_row in attempt['frames']:
            sequence = frame_row['sequence']
            selected_frame_fields = list(frame_fields) + [
                name for name in empirical.FRAME_EXACT_FIELDS
                if name not in frame_fields and name != 'monotonic_ns' and
                frame_row[name] is not None]
            event_a = {
                'event_id': f'frame-a-{attempt_id}-{sequence}',
                'source_id': 'source-peer-transcript',
                'source_role_kind': 'colluder-wallet-capture',
                'source_round': 1,
                'source_record_root_sha256': '4' * 64,
                'structural_identity':
                    mapping_a[f'public-slot-{join_ordinal % 2}'],
                'clock_domain_id': 'clock-peer',
                'source_rank': 2 * frame_source_rank,
                'kind': 'FRAME',
                'fields': {
                    **{name: frame_row[name]
                       for name in selected_frame_fields},
                    'monotonic_ns': frame_row['monotonic_ns'],
                },
            }
            event_b = dict(event_a)
            event_b['event_id'] = f'frame-b-{attempt_id}-{sequence}'
            event_b['source_rank'] = 2 * frame_source_rank + 1
            event_b['structural_identity'] = (
                mapping_b[f'public-slot-{join_ordinal % 2}'])
            event_b['fields'] = dict(event_a['fields'])
            if corrupt_b and sequence == 0:
                event_b['fields']['payload_sha256'] = 'f' * 64
            events.extend((event_a, event_b))
            join_id = f'frame-{attempt["retry_ordinal"]}-{sequence}'
            frame_join_ids.append(join_id)
            structural_key = f'public-slot-{join_ordinal % 2}'
            reference = {
                'kind': 'FRAME', 'attempt_id': attempt_id,
                'sequence': sequence,
            }
            joins_a.append({
                'join_id': join_id, 'structural_key': structural_key,
                'p1_ref': reference,
                'event_id': event_a['event_id'],
                'exact_fields': list(selected_frame_fields),
            })
            joins_b.append({
                'join_id': join_id, 'structural_key': structural_key,
                'p1_ref': reference,
                'event_id': event_b['event_id'],
                'exact_fields': list(selected_frame_fields),
            })
            frame_source_rank += 1
            join_ordinal += 1
    return {
        'schema': 'kpb-p1-passive-within-run-plan/v2',
        'trial_id': '55555555-5555-4555-8555-555555555555',
        'source_manifest_sha256': '1' * 64,
        'p1_capture_sha256': features['capture_sha256'],
        'p1_source_id': 'P1_C03',
        'p1_clock_domain_id': 'clock-p1',
        'events': events,
        'rank_tests': [{
            'rank_id': 'frame-source-order',
            'join_ids': frame_join_ids,
            'field': 'source_order',
        }, {
            'rank_id': 'frame-monotonic-order',
            'join_ids': frame_join_ids,
            'field': 'monotonic_ns',
        }],
        'timing_tests': [{
            'timing_id': 'attempt-start-distance',
            'join_ids': attempt_join_ids,
            'field': 'start_monotonic_ns',
            'metric': 'ABSOLUTE_PAIR_DELTA',
        }],
        'candidates': [{
            'mapping_id': 'STRUCTURAL_A',
            'structural_mapping': mapping_a,
            'joins': joins_a,
        }, {
            'mapping_id': 'STRUCTURAL_B',
            'structural_mapping': mapping_b,
            'joins': joins_b,
        }],
    }


class P1EmpiricalFeatureControls(unittest.TestCase):
    def test_label_free_extraction_covers_raw_c03_observation_families(self):
        raw = complete_capture()
        value = empirical.extract_c03_features(raw, attempt_history(raw))

        self.assertEqual(value['schema'],
                         'kpb-p1-passive-empirical-features/v2')
        self.assertEqual(value['observer_scope'],
                         'PINNED_INSTRUMENTED_PASSIVE_P1_PROCESS_PLUS_PASSIVE_OWNER1')
        self.assertEqual(set(value['families']), {
            'monotonic-timing', 'frame-length', 'message-chunk-order',
            'direction-peer-fork', 'abort-retry', 'mixed-peer-content',
            'all-lane-content',
        })
        self.assertEqual(value['stream_state'], 'COMPLETE_END')
        self.assertEqual(value['constants']['magic'], 'KPBP1C03')
        self.assertTrue(value['constants']['reserved_header_zero'])
        self.assertTrue(value['constants']['sequence_contiguous'])
        self.assertTrue(value['constants']['message_chunk_well_formed'])
        self.assertNotIn('label', repr(value).lower())
        for family in value['families'].values():
            self.assertRegex(family['exact_sha256'], r'^[0-9a-f]{64}$')
            self.assertTrue(family['numeric'])

    def test_v9_hello_scalar_binding_and_footer_metadata_are_constraints(self):
        attempt_id = '11111111-1111-4111-8111-111111111111'
        capture_id = '99999999-9999-4999-8999-999999999999'
        scalar_binding = bytes((1, 2)) + (1).to_bytes(2, 'big') + \
            (7).to_bytes(8, 'big') + bytes(4)
        raw = b''.join((
            frame(record_type=1, semantic=1, direction=3, peer=0xff,
                  monotonic_ns=1_000, sequence=0, message=0,
                  payload=v9_hello_payload(attempt_id, capture_id)),
            frame(record_type=2, semantic=17, direction=3, peer=0xff,
                  monotonic_ns=1_010, sequence=1, message=1,
                  payload=scalar_binding),
            frame(record_type=4, semantic=9, direction=3, peer=0xff,
                  monotonic_ns=1_020, sequence=2, message=2,
                  payload=v9_footer_payload(
                      sequence=2, first_ns=1_000, last_ns=1_010,
                      total=(1, 1, 16), lanes={17: (1, 1, 16)})),
            frame(record_type=5, semantic=9, direction=3, peer=0xff,
                  monotonic_ns=1_030, sequence=3, message=3, payload=b''),
        ))
        features = empirical.extract_c03_features(
            raw, attempt_history(raw, attempt_id=attempt_id))
        rows = features['exact_observations']['attempts'][0]['frames']

        self.assertEqual(rows[0]['hello_model_preimage_sha256'], '66' * 32)
        self.assertEqual(rows[0]['hello_query_store_preimage_sha256'],
                         '77' * 32)
        self.assertEqual(rows[0]['hello_scalar_manifest_sha256'],
                         empirical.V9_SCALAR_CAPTURE_MANIFEST_SHA256)
        self.assertEqual((rows[1]['scalar_binding_kind'],
                          rows[1]['scalar_binding_site'],
                          rows[1]['scalar_binding_element_count']),
                         (2, 1, 7))
        self.assertEqual(rows[2]['footer_scalar_site_bitmap'],
                         empirical.V9_SCALAR_SITE_BITMAP)
        self.assertEqual(rows[2]['footer_total_counters'], [1, 1, 16])
        self.assertEqual(rows[2]['footer_lane_counters'][16], [1, 1, 16])

        receipt = empirical.apply_within_run_constraints(
            features, exact_constraint_plan(features))
        for path in (
                'payload.hello.model_preimage_sha256',
                'payload.hello.query_store_preimage_sha256',
                'payload.hello.scalar_manifest_sha256',
                'payload.hello.source_build_launch_role_binding',
                'payload.scalar_binding.version_kind_site_count',
                'payload.footer.v9_counters_and_bitmaps'):
            with self.subTest(path=path):
                self.assertEqual(receipt['field_status'][path]['status'],
                                 'CONSTRAINT_MODELED')

    def test_v9_manifest_scalar_site_and_footer_mismatch_refuse(self):
        attempt_id = '11111111-1111-4111-8111-111111111111'
        capture_id = '99999999-9999-4999-8999-999999999999'

        bad_hello = bytearray(v9_hello_payload(attempt_id, capture_id))
        bad_hello[300] ^= 1
        hello_raw = frame(
            record_type=1, semantic=1, direction=3, peer=0xff,
            monotonic_ns=1_000, sequence=0, message=0,
            payload=bytes(bad_hello))
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused,
                'p1-empirical-v9-hello-binding'):
            empirical.extract_c03_features(
                hello_raw,
                attempt_history(hello_raw, outcome='ABORTED',
                                failure_code='HELLO_INVALID',
                                attempt_id=attempt_id))

        bad_scalar = bytes((1, 2)) + (2).to_bytes(2, 'big') + \
            (1).to_bytes(8, 'big') + bytes(4)
        scalar_raw = frame(
            record_type=2, semantic=17, direction=3, peer=0xff,
            monotonic_ns=1_000, sequence=0, message=0,
            payload=bad_scalar)
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused,
                'p1-empirical-v9-scalar-binding-shape'):
            empirical.extract_c03_features(
                scalar_raw,
                attempt_history(scalar_raw, outcome='ABORTED',
                                failure_code='SCALAR_INVALID'))

        canonical_footer = v9_footer_payload(
            sequence=1, first_ns=1_000, last_ns=1_000,
            total=(1, 1, 4), lanes={2: (1, 1, 4)})
        prefix = frame(
            record_type=2, semantic=2, direction=1, peer=0,
            monotonic_ns=1_000, sequence=0, message=0, payload=b'peer')
        for offset in (440, 448, 456, 464, 472, 480, 488):
            bad_footer = bytearray(canonical_footer)
            original = int.from_bytes(bad_footer[offset:offset + 8], 'big')
            bad_footer[offset:offset + 8] = (original ^ 1).to_bytes(8, 'big')
            footer_raw = prefix + frame(
                record_type=4, semantic=9, direction=3, peer=0xff,
                monotonic_ns=1_010, sequence=1, message=1,
                payload=bytes(bad_footer))
            with self.subTest(footer_trailing_u64_offset=offset), \
                    self.assertRaisesRegex(
                        empirical.EmpiricalRefused,
                        'p1-empirical-v9-footer-binding'):
                empirical.extract_c03_features(
                    footer_raw,
                    attempt_history(footer_raw, outcome='ABORTED',
                                    failure_code='FOOTER_TRAILER_INVALID'))

        bad_counts = bytearray(v9_footer_payload(
            sequence=1, first_ns=1_000, last_ns=1_000,
            total=(1, 1, 4), lanes={2: (1, 1, 4)}))
        bad_counts[8:16] = (2).to_bytes(8, 'big')
        counter_raw = prefix + frame(
            record_type=4, semantic=9, direction=3, peer=0xff,
            monotonic_ns=1_010, sequence=1, message=1,
            payload=bytes(bad_counts))
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused,
                'p1-empirical-v9-footer-binding'):
            empirical.extract_c03_features(
                counter_raw,
                attempt_history(counter_raw, outcome='ABORTED',
                                failure_code='FOOTER_COUNTER_INVALID'))

        maximum_count = bytearray(v9_footer_payload(
            sequence=1, first_ns=1_000, last_ns=1_000,
            total=(1, 1, 4), lanes={2: (1, 1, 4)}))
        maximum_count[8:16] = bytes([0xff]) * 8
        maximum_raw = prefix + frame(
            record_type=4, semantic=9, direction=3, peer=0xff,
            monotonic_ns=1_010, sequence=1, message=1,
            payload=bytes(maximum_count))
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused,
                'p1-empirical-v9-footer-binding'):
            empirical.extract_c03_features(
                maximum_raw,
                attempt_history(maximum_raw, outcome='ABORTED',
                                failure_code='FOOTER_COUNTER_MAX'))

        binding = bytes((1, 2)) + (1).to_bytes(2, 'big') + \
            (1).to_bytes(8, 'big') + bytes(4)
        two_data = b''.join((
            prefix,
            frame(record_type=2, semantic=17, direction=3, peer=0xff,
                  monotonic_ns=1_010, sequence=1, message=1,
                  payload=binding),
        ))
        permuted = bytearray(v9_footer_payload(
            sequence=2, first_ns=1_000, last_ns=1_010,
            total=(2, 2, 20),
            lanes={2: (1, 1, 4), 17: (1, 1, 16)}))
        lane_two = bytes(permuted[56:80])
        lane_seventeen = bytes(permuted[416:440])
        permuted[56:80] = lane_seventeen
        permuted[416:440] = lane_two
        permutation_raw = two_data + frame(
            record_type=4, semantic=9, direction=3, peer=0xff,
            monotonic_ns=1_020, sequence=2, message=2,
            payload=bytes(permuted))
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused,
                'p1-empirical-v9-footer-binding'):
            empirical.extract_c03_features(
                permutation_raw,
                attempt_history(permutation_raw, outcome='ABORTED',
                                failure_code='FOOTER_LANE_PERMUTED'))

        extended = v9_footer_payload(
            sequence=1, first_ns=1_000, last_ns=1_000,
            total=(1, 1, 4), lanes={2: (1, 1, 4)}) + b'\0'
        extended_raw = prefix + frame(
            record_type=4, semantic=9, direction=3, peer=0xff,
            monotonic_ns=1_010, sequence=1, message=1,
            payload=extended)
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused,
                'p1-empirical-v9-footer-shape'):
            empirical.extract_c03_features(
                extended_raw,
                attempt_history(extended_raw, outcome='ABORTED',
                                failure_code='FOOTER_NONCANONICAL_WIDTH'))

    def test_v9_projection_fork_and_end_fixed_regions_are_constraints(self):
        projection = b'projection-private-source-preimage'
        projection_sha256 = hashlib.sha256(projection).digest()
        child = bytes.fromhex('88' * 32)
        suffix_sha256 = bytes.fromhex('99' * 32)
        raw = b''.join((
            frame(record_type=2, semantic=9, direction=3, peer=0xff,
                  monotonic_ns=1_000, sequence=0, message=0,
                  payload=projection),
            frame(record_type=3, semantic=9, direction=3, peer=0xff,
                  monotonic_ns=1_010, sequence=1, message=1,
                  payload=projection_sha256),
            frame(record_type=6, semantic=2, direction=3, peer=0xff,
                  monotonic_ns=1_020, sequence=2, message=2,
                  payload=bytes(32) + child + suffix_sha256),
            frame(record_type=5, semantic=9, direction=3, peer=0xff,
                  monotonic_ns=1_030, sequence=3, message=3, payload=b''),
        ))
        features = empirical.extract_c03_features(raw, attempt_history(raw))
        rows = features['exact_observations']['attempts'][0]['frames']

        self.assertEqual(rows[1]['seal_projection_sha256'],
                         projection_sha256.hex())
        self.assertEqual(rows[2]['fork_parent_hex'], '00' * 32)
        self.assertEqual(rows[2]['fork_child_hex'], child.hex())
        self.assertEqual(rows[2]['fork_suffix_sha256'],
                         suffix_sha256.hex())
        receipt = empirical.apply_within_run_constraints(
            features, exact_constraint_plan(features))
        for path in ('payload.projection_seal', 'payload.fork_binding'):
            with self.subTest(path=path):
                self.assertEqual(receipt['field_status'][path]['status'],
                                 'CONSTRAINT_MODELED')

    def test_v9_projection_fork_end_and_hello_attempt_mismatches_refuse(self):
        projection = b'projection-private-source-preimage'
        projection_frame = frame(
            record_type=2, semantic=9, direction=3, peer=0xff,
            monotonic_ns=1_000, sequence=0, message=0,
            payload=projection)
        wrong_seal = projection_frame + frame(
            record_type=3, semantic=9, direction=3, peer=0xff,
            monotonic_ns=1_010, sequence=1, message=1,
            payload=bytes.fromhex('aa' * 32))
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused,
                'p1-empirical-v9-projection-seal'):
            empirical.extract_c03_features(
                wrong_seal,
                attempt_history(wrong_seal, outcome='ABORTED',
                                failure_code='PROJECTION_SEAL_INVALID'))

        child = bytes.fromhex('88' * 32)
        suffix_sha256 = bytes.fromhex('99' * 32)
        bad_fork = frame(
            record_type=6, semantic=2, direction=3, peer=0xff,
            monotonic_ns=1_000, sequence=0, message=0, fork=bytes(32),
            payload=bytes.fromhex('77' * 32) + child + suffix_sha256)
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused, 'p1-empirical-v9-fork-shape'):
            empirical.extract_c03_features(
                bad_fork,
                attempt_history(bad_fork, outcome='ABORTED',
                                failure_code='FORK_PARENT_INVALID'))

        fork_once = frame(
            record_type=6, semantic=2, direction=3, peer=0xff,
            monotonic_ns=1_000, sequence=0, message=0,
            payload=bytes(32) + child + suffix_sha256)
        duplicate_fork = fork_once + frame(
            record_type=6, semantic=2, direction=3, peer=0xff,
            monotonic_ns=1_010, sequence=1, message=1,
            payload=bytes(32) + child + suffix_sha256)
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused, 'p1-empirical-v9-fork-shape'):
            empirical.extract_c03_features(
                duplicate_fork,
                attempt_history(duplicate_fork, outcome='ABORTED',
                                failure_code='FORK_CHILD_REUSED'))

        bad_end = frame(
            record_type=5, semantic=9, direction=3, peer=0,
            monotonic_ns=1_000, sequence=0, message=0, payload=b'')
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused, 'p1-empirical-v9-end-shape'):
            empirical.extract_c03_features(
                bad_end,
                attempt_history(bad_end, outcome='ABORTED',
                                failure_code='END_NONCANONICAL'))

        hello_attempt = '11111111-1111-4111-8111-111111111111'
        history_attempt = '22222222-2222-4222-8222-222222222222'
        capture_id = '99999999-9999-4999-8999-999999999999'
        mismatched_hello = frame(
            record_type=1, semantic=1, direction=3, peer=0xff,
            monotonic_ns=1_000, sequence=0, message=0,
            payload=v9_hello_payload(hello_attempt, capture_id))
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused,
                'p1-empirical-v9-hello-attempt-binding'):
            empirical.extract_c03_features(
                mismatched_hello,
                attempt_history(mismatched_hello, outcome='ABORTED',
                                failure_code='HELLO_ATTEMPT_MISMATCH',
                                attempt_id=history_attempt))

    def test_partial_abort_tail_is_feature_not_sanitized(self):
        first = frame(record_type=2, semantic=2, direction=1, peer=0,
                      monotonic_ns=1_000, sequence=0, message=0,
                      payload=b'peer-opaque')
        partial = bytearray(frame(
            record_type=2, semantic=2, direction=2, peer=2,
            monotonic_ns=1_100, sequence=1, message=1,
            payload=b'never-complete')[:31])
        raw = first + bytes(partial)
        before = empirical.extract_c03_features(
            raw, attempt_history(raw, outcome='ABORTED',
                                 failure_code='PEER_CLOSED'))
        partial[-1] ^= 1
        changed_raw = first + bytes(partial)
        after = empirical.extract_c03_features(
            changed_raw,
            attempt_history(changed_raw, outcome='ABORTED',
                            failure_code='PEER_CLOSED'))

        self.assertEqual(before['stream_state'], 'PARTIAL_HEADER')
        self.assertEqual(before['constants']['tail_bytes'], 31)
        for family in ('frame-length', 'all-lane-content', 'abort-retry'):
            self.assertNotEqual(
                before['families'][family]['exact_sha256'],
                after['families'][family]['exact_sha256'])

    def test_retry_sequence_requires_and_uses_every_partial_capture(self):
        first_id = '66666666-6666-4666-8666-666666666666'
        second_id = '77777777-7777-4777-8777-777777777777'
        failed = frame(
            record_type=2, semantic=2, direction=1, peer=0,
            monotonic_ns=1_000, sequence=0, message=0,
            payload=b'failed-peer-view')
        complete = complete_capture(b'eventual-success', base_time=2_000)
        history = {
            'schema': 'kpb-p1-passive-attempt-history/v1',
            'attempts': [{
                'attempt_id': first_id,
                'retry_ordinal': 0,
                'predecessor_attempt_id': None,
                'start_monotonic_ns': 900,
                'end_monotonic_ns': 1_200,
                'outcome': 'ABORTED',
                'failure_code': 'PEER_CLOSED',
                'capture_sha256': hashlib.sha256(failed).hexdigest(),
            }, {
                'attempt_id': second_id,
                'retry_ordinal': 1,
                'predecessor_attempt_id': first_id,
                'start_monotonic_ns': 1_900,
                'end_monotonic_ns': 2_200,
                'outcome': 'COMPLETE',
                'failure_code': 'NONE',
                'capture_sha256': hashlib.sha256(complete).hexdigest(),
            }],
        }
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused,
                'p1-empirical-retry-captures-required'):
            empirical.extract_c03_features(complete, history)

        value = empirical.extract_attempt_sequence(
            [failed, complete], history)
        self.assertEqual(value['stream_states'],
                         ['CLOSED_WITHOUT_END', 'COMPLETE_END'])
        self.assertEqual(value['attempt_ids'], [first_id, second_id])
        changed_failed = frame(
            record_type=2, semantic=2, direction=1, peer=0,
            monotonic_ns=1_000, sequence=0, message=0,
            payload=b'failed-peer-vief')
        changed_history = {'schema': history['schema'], 'attempts': [
            {**history['attempts'][0],
             'capture_sha256': hashlib.sha256(changed_failed).hexdigest()},
            history['attempts'][1],
        ]}
        changed = empirical.extract_attempt_sequence(
            [changed_failed, complete], changed_history)
        self.assertNotEqual(
            value['families']['all-lane-content']['exact_sha256'],
            changed['families']['all-lane-content']['exact_sha256'])

    def test_multichunk_metadata_change_refuses_instead_of_relabeling(self):
        raw = b''.join((
            frame(record_type=2, semantic=2, direction=1, peer=0, flags=1,
                  monotonic_ns=1_000, sequence=0, message=0, chunk=0,
                  payload=b'first'),
            frame(record_type=2, semantic=3, direction=3, peer=0xff, flags=2,
                  monotonic_ns=1_010, sequence=1, message=0, chunk=1,
                  payload=b'second'),
        ))
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused,
                'p1-empirical-message-metadata'):
            empirical.extract_c03_features(
                raw, attempt_history(raw, outcome='ABORTED',
                                     failure_code='CAPTURE_CLOSED'))

    def test_calibration_refuses_insufficient_pretrial_power(self):
        raw = complete_capture()
        other_raw = complete_capture(b'other-peer')
        rows = [{
            'calibration_id':
                str(uuid.UUID('22222222-2222-4222-8222-222222222222')),
            'mapping_id': 'HONEST_A',
            'corpus_provenance': 'SYNTHETIC_UNIT_TEST',
            'raw': raw,
            'attempt_history': attempt_history(raw),
        }, {
            'calibration_id':
                str(uuid.UUID('33333333-3333-4333-8333-333333333333')),
            'mapping_id': 'HONEST_B',
            'corpus_provenance': 'SYNTHETIC_UNIT_TEST',
            'raw': other_raw,
            'attempt_history': attempt_history(
                other_raw,
                attempt_id='88888888-8888-4888-8888-888888888888'),
        }]
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused,
                'p1-empirical-calibration-power'):
            empirical.freeze_calibration(rows, ('HONEST_A', 'HONEST_B'))

    def test_calibration_capture_cannot_be_duplicated_across_splits_or_labels(self):
        raw = complete_capture()
        rows = [{
            'calibration_id':
                str(uuid.UUID('22222222-2222-4222-8222-222222222222')),
            'mapping_id': 'HONEST_A',
            'corpus_provenance': 'SYNTHETIC_UNIT_TEST',
            'raw': raw,
            'attempt_history': attempt_history(raw),
        }, {
            'calibration_id':
                str(uuid.UUID('33333333-3333-4333-8333-333333333333')),
            'mapping_id': 'HONEST_B',
            'corpus_provenance': 'SYNTHETIC_UNIT_TEST',
            'raw': raw,
            'attempt_history': attempt_history(raw),
        }]
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused,
                'p1-empirical-calibration-capture-duplicate'):
            empirical.freeze_calibration(rows, ('HONEST_A', 'HONEST_B'))

    def test_frozen_calibration_scores_candidate_constraints_pretruth(self):
        model = empirical.freeze_calibration(
            synthetic_clear_signal_calibration_rows(),
            ('HONEST_A', 'HONEST_B'))
        actual_raw = complete_capture(
            b'A' * 12 + b'Z', base_time=1_050, direction=1, peer=0)
        actual_features = empirical.extract_c03_features(
            actual_raw, attempt_history(
                actual_raw,
                attempt_id='44444444-4444-4444-8444-444444444444',
                start=850, end=1_350))
        candidates = [{
            'mapping_id': 'HONEST_A',
            'constraints': {'input_rank_owner': [0, 1, 2]},
        }, {
            'mapping_id': 'HONEST_B',
            'constraints': {'input_rank_owner': [2, 1, 0]},
        }]
        receipt = empirical.score_candidates(
            model, actual_features,
            '55555555-5555-4555-8555-555555555555', candidates)

        self.assertEqual(receipt['status'],
                         'OPTIONAL_CLASSIFIER_CANDIDATE_FILTER')
        self.assertFalse(receipt['gate_authorizing'])
        self.assertTrue(model['optional_study_only'])
        self.assertEqual(model['corpus_provenance'], ['SYNTHETIC_UNIT_TEST'])
        self.assertEqual(receipt['retained_mapping_ids'], ['HONEST_A'])
        self.assertEqual(receipt['retained_candidates'], candidates[:1])
        self.assertEqual(set(receipt['family_scores']),
                         set(actual_features['families']))
        self.assertTrue(all(row['holdout_sample_count'] >= 48
                            and row['association_detected']
                            and row['critical_correct_count'] == 33
                            and row['power_at_accuracy_0_75'] >= 0.80
                            for row in model['family_audits'].values()))

    def test_actual_attempt_identity_cannot_reuse_calibration_corpus(self):
        rows = synthetic_clear_signal_calibration_rows()
        model = empirical.freeze_calibration(
            rows, ('HONEST_A', 'HONEST_B'))
        reused_attempt = rows[0]['attempt_history']['attempts'][0][
            'attempt_id']
        raw = complete_capture(b'new-capture-bytes')
        features = empirical.extract_c03_features(
            raw, attempt_history(raw, attempt_id=reused_attempt))
        candidates = [
            {'mapping_id': 'HONEST_A', 'constraints': {}},
            {'mapping_id': 'HONEST_B', 'constraints': {}},
        ]
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused,
                'p1-empirical-actual-calibration-separation'):
            empirical.score_candidates(
                model, features,
                '55555555-5555-4555-8555-555555555555', candidates)

    def test_exact_within_run_constraints_prune_without_truth_or_classifier(self):
        raw = complete_capture()
        features = empirical.extract_c03_features(raw, attempt_history(raw))
        plan = exact_constraint_plan(features, corrupt_b=True)

        receipt = empirical.apply_within_run_constraints(features, plan)

        self.assertEqual(
            receipt['schema'],
            'kpb-p1-passive-within-run-constraint-receipt/v2')
        self.assertEqual(receipt['status'], 'DETERMINISTIC_UNIQUE_CANDIDATE')
        self.assertEqual(receipt['retained_mapping_ids'], ['STRUCTURAL_A'])
        self.assertFalse(receipt['gate_authorizing_without_capsule_bridge'])
        self.assertFalse(receipt['cryptographic_theorem_coverage_claim'])
        self.assertNotIn('truth', repr(plan).lower())
        self.assertTrue(all(
            row['status'] in (
                'CONSTANT_PUBLIC', 'CONSTRAINT_MODELED',
                'NOT_PRESENT_IN_CAPTURE')
            for row in receipt['field_status'].values()))
        self.assertTrue(all(
            row['expected_observation_count'] ==
            row['compared_per_candidate']
            for row in receipt['field_status'].values()
            if row['status'] == 'CONSTRAINT_MODELED'))
        payload_status = receipt['field_status']['header.payload_sha256']
        self.assertGreater(payload_status['positive_match_count'], 0)
        self.assertGreater(payload_status['mismatch_count'], 0)
        self.assertTrue(payload_status['used_for_candidate_filter'])

    def test_different_clock_domains_use_rank_and_never_exact_timestamp(self):
        raw = complete_capture()
        features = empirical.extract_c03_features(raw, attempt_history(raw))
        plan = exact_constraint_plan(features)
        frame_events = [row for row in plan['events']
                        if row['kind'] == 'FRAME']
        self.assertTrue(all(row['clock_domain_id'] == 'clock-peer'
                            for row in frame_events))

        receipt = empirical.apply_within_run_constraints(features, plan)

        timing = receipt['field_status']['header.monotonic_ns']
        self.assertEqual(timing['comparison_modes'], ['RANK_WITHIN_SOURCE'])
        self.assertGreater(timing['positive_match_count'], 0)
        self.assertEqual(receipt['retained_mapping_ids'],
                         ['STRUCTURAL_A', 'STRUCTURAL_B'])

        reversed_plan = exact_constraint_plan(features)
        b_frame_event_ids = {
            join['event_id'] for join in reversed_plan['candidates'][1][
                'joins'] if join['p1_ref']['kind'] == 'FRAME'}
        reversed_events = [
            row for row in reversed_plan['events']
            if row['event_id'] in b_frame_event_ids]
        self.assertEqual(len(reversed_events), 2)
        reversed_events[0]['source_rank'], reversed_events[1]['source_rank'] = (
            reversed_events[1]['source_rank'],
            reversed_events[0]['source_rank'])
        reversed_receipt = empirical.apply_within_run_constraints(
            features, reversed_plan)
        self.assertEqual(reversed_receipt['retained_mapping_ids'],
                         ['STRUCTURAL_A'])
        self.assertEqual(
            next(row for row in reversed_receipt['candidate_results']
                 if row['mapping_id'] == 'STRUCTURAL_B')['rank_results'][0][
                     'status'],
            'MISMATCH')

        bad = exact_constraint_plan(features)
        for candidate in bad['candidates']:
            candidate['joins'][1]['exact_fields'].append('monotonic_ns')
        for event in bad['events']:
            if event['kind'] == 'FRAME' and event['source_rank'] == 0:
                event['fields']['monotonic_ns'] = 1_000
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused,
                'p1-empirical-cross-clock-exact-time'):
            empirical.apply_within_run_constraints(features, bad)

    def test_common_clock_spacing_prunes_when_order_is_identical(self):
        raw = complete_capture()
        features = empirical.extract_c03_features(raw, attempt_history(raw))
        plan = exact_constraint_plan(features)
        a_frame_event_ids = {
            join['event_id'] for join in plan['candidates'][0]['joins']
            if join['p1_ref']['kind'] == 'FRAME'}
        observed = {
            row['sequence']: row['monotonic_ns']
            for row in features['exact_observations']['attempts'][0][
                'frames']}
        for event in plan['events']:
            if event['kind'] != 'FRAME':
                continue
            event['clock_domain_id'] = 'clock-p1'
            sequence = event['fields']['sequence']
            event['fields']['monotonic_ns'] = (
                observed[sequence] +
                (10 + sequence if event['event_id'] in a_frame_event_ids else
                 1_000 + sequence))
        plan['timing_tests'].append({
            'timing_id': 'frame-common-clock-distance',
            'join_ids': plan['rank_tests'][0]['join_ids'],
            'field': 'monotonic_ns',
            'metric': 'ABSOLUTE_PAIR_DELTA',
        })

        receipt = empirical.apply_within_run_constraints(features, plan)

        self.assertEqual(receipt['retained_mapping_ids'], ['STRUCTURAL_A'])
        by_mapping = {row['mapping_id']: row
                      for row in receipt['candidate_results']}
        self.assertTrue(all(
            rank['status'] == 'MATCH'
            for row in by_mapping.values() for rank in row['rank_results']))
        self.assertEqual(
            by_mapping['STRUCTURAL_A']['timing_results'][-1]['status'],
            'CLOSER')
        self.assertEqual(
            by_mapping['STRUCTURAL_B']['timing_results'][-1]['status'],
            'FARTHER')

    def test_missing_constraint_is_unqualified_not_feature_evidence(self):
        raw = complete_capture()
        features = empirical.extract_c03_features(raw, attempt_history(raw))
        plan = exact_constraint_plan(features)
        for candidate in plan['candidates']:
            for join in candidate['joins']:
                if join['p1_ref']['kind'] == 'FRAME':
                    join['exact_fields'].remove('fork_hex')

        receipt = empirical.apply_within_run_constraints(features, plan)

        self.assertEqual(
            receipt['status'],
            'UNQUALIFIED_MISSING_WITHIN_RUN_CONSTRAINT')
        self.assertEqual(receipt['field_status']['header.fork']['status'],
                         'UNMODELED')
        self.assertEqual(
            receipt['field_status']['header.fork'][
                'compared_per_candidate'], 0)

    def test_candidate_catalog_refuses_truth_markers(self):
        raw = complete_capture()
        features = empirical.extract_c03_features(raw, attempt_history(raw))
        plan = exact_constraint_plan(features)
        plan['candidates'][0]['structural_mapping'][
            'ground-truth-owner'] = 'candidate-x'
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused,
                'p1-empirical-structural-candidate'):
            empirical.apply_within_run_constraints(features, plan)

    def test_self_join_copy_and_cosmetic_mapping_plans_refuse(self):
        raw = complete_capture()
        features = empirical.extract_c03_features(raw, attempt_history(raw))

        self_join = exact_constraint_plan(features)
        self_join['events'][0]['source_id'] = 'P1_C03'
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused,
                'p1-empirical-within-run-event'):
            empirical.apply_within_run_constraints(features, self_join)

        copied_root = exact_constraint_plan(features)
        copied_root['events'][0]['source_record_root_sha256'] = (
            features['capture_sha256'])
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused,
                'p1-empirical-within-run-event'):
            empirical.apply_within_run_constraints(features, copied_root)

        identical_joins = exact_constraint_plan(features)
        joins_a = identical_joins['candidates'][0]['joins']
        joins_b = identical_joins['candidates'][1]['joins']
        for left, right in zip(joins_a, joins_b):
            right['event_id'] = left['event_id']
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused,
                'p1-empirical-within-run-join-binding'):
            empirical.apply_within_run_constraints(features, identical_joins)

        inconsistent = exact_constraint_plan(features)
        target_event_id = inconsistent['candidates'][0]['joins'][0][
            'event_id']
        target = next(row for row in inconsistent['events']
                      if row['event_id'] == target_event_id)
        target['structural_identity'] = 'candidate-y'
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused,
                'p1-empirical-within-run-join-binding'):
            empirical.apply_within_run_constraints(features, inconsistent)

        asymmetric_source = exact_constraint_plan(features)
        event_id = asymmetric_source['candidates'][1]['joins'][0]['event_id']
        event = next(row for row in asymmetric_source['events']
                     if row['event_id'] == event_id)
        event['source_id'] = 'candidate-specific-source'
        event['source_record_root_sha256'] = '8' * 64
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused,
                'p1-empirical-candidate-source-asymmetry'):
            empirical.apply_within_run_constraints(
                features, asymmetric_source)

    def test_exact_metadata_fields_and_literal_digest_act_on_candidates(self):
        raw = complete_capture()
        features = empirical.extract_c03_features(raw, attempt_history(raw))
        mutations = {
            'payload_length': 99,
            'direction': 2,
            'peer': 2,
            'fork_hex': 'a' * 64,
            'payload_sha256': 'b' * 64,
        }
        for field, changed in mutations.items():
            plan = exact_constraint_plan(features)
            target = next(
                event for event in plan['events']
                if event['event_id'].startswith('frame-a-') and
                event['source_rank'] == 0)
            target['fields'][field] = changed
            receipt = empirical.apply_within_run_constraints(features, plan)
            with self.subTest(field=field):
                self.assertEqual(receipt['retained_mapping_ids'],
                                 ['STRUCTURAL_B'])

        literal_plan = exact_constraint_plan(features)
        for event in literal_plan['events']:
            if (event['kind'] == 'FRAME' and event['source_rank'] == 0):
                event['fields']['payload_literal_hex'] = b'peer-opaque'.hex()
        literal_receipt = empirical.apply_within_run_constraints(
            features, literal_plan)
        self.assertIn(
            'EXACT_LITERAL_DIGEST',
            literal_receipt['field_status']['header.payload_sha256'][
                'comparison_modes'])

        bad_literal = exact_constraint_plan(features)
        first = next(event for event in bad_literal['events']
                     if event['kind'] == 'FRAME' and
                     event['source_rank'] == 0)
        first['fields']['payload_literal_hex'] = b'not-the-payload'.hex()
        with self.assertRaisesRegex(
                empirical.EmpiricalRefused,
                'p1-empirical-within-run-literal-binding'):
            empirical.apply_within_run_constraints(features, bad_literal)

    def test_retry_and_partial_tail_constraints_intersect_candidates(self):
        first_id = '66666666-6666-4666-8666-666666666666'
        second_id = '77777777-7777-4777-8777-777777777777'
        failed = frame(
            record_type=2, semantic=2, direction=1, peer=0,
            monotonic_ns=1_000, sequence=0, message=0,
            payload=b'failed-peer-view') + b'partial-tail'
        complete = complete_capture(b'eventual-success', base_time=2_000)
        history = {
            'schema': 'kpb-p1-passive-attempt-history/v1',
            'attempts': [{
                'attempt_id': first_id, 'retry_ordinal': 0,
                'predecessor_attempt_id': None,
                'start_monotonic_ns': 900, 'end_monotonic_ns': 1_200,
                'outcome': 'ABORTED', 'failure_code': 'PEER_CLOSED',
                'capture_sha256': hashlib.sha256(failed).hexdigest(),
            }, {
                'attempt_id': second_id, 'retry_ordinal': 1,
                'predecessor_attempt_id': first_id,
                'start_monotonic_ns': 1_900, 'end_monotonic_ns': 2_200,
                'outcome': 'COMPLETE', 'failure_code': 'NONE',
                'capture_sha256': hashlib.sha256(complete).hexdigest(),
            }],
        }
        features = empirical.extract_attempt_sequence([failed, complete],
                                                      history)
        plan = exact_constraint_plan(features, corrupt_b=True)
        for event in plan['events']:
            if (event['event_id'].startswith('attempt-b-') and
                    event['fields']['retry_ordinal'] == 0):
                event['fields']['partial_tail_sha256'] = 'e' * 64

        receipt = empirical.apply_within_run_constraints(features, plan)

        self.assertEqual(receipt['retained_mapping_ids'], ['STRUCTURAL_A'])
        self.assertEqual(receipt['field_status']['partial.tail']['status'],
                         'CONSTRAINT_MODELED')
        self.assertGreater(
            receipt['field_status']['partial.tail']['mismatch_count'], 0)
        self.assertEqual(
            receipt['field_status']['attempt.retry_ordinal']['status'],
            'CONSTRAINT_MODELED')

    def test_every_available_raw_field_has_frozen_feature_or_constant_status(self):
        expected = {
            'header.magic', 'header.record_type', 'header.semantic',
            'header.direction', 'header.peer', 'header.flags',
            'header.reserved', 'header.monotonic_ns', 'header.sequence',
            'header.message', 'header.chunk', 'header.payload_length',
            'header.fork', 'header.payload_sha256',
            'payload.peer_transport', 'payload.other_lane',
            'payload.hello.model_preimage_sha256',
            'payload.hello.query_store_preimage_sha256',
            'payload.hello.scalar_manifest_sha256',
            'payload.hello.source_build_launch_role_binding',
            'payload.scalar_binding.version_kind_site_count',
            'payload.scalar_binding.reserved',
            'payload.projection_seal', 'payload.fork_binding',
            'payload.footer.v9_counters_and_bitmaps',
            'source.query_msm_correspondence_manifest',
            'partial.tail', 'attempt.attempt_id', 'attempt.retry_ordinal',
            'attempt.predecessor_attempt_id', 'attempt.start_monotonic_ns',
            'attempt.end_monotonic_ns', 'attempt.outcome',
            'attempt.failure_code', 'attempt.capture_sha256',
        }
        self.assertEqual(set(empirical.FIELD_DISPOSITIONS), expected)
        self.assertNotIn(
            'FEATURE_ONLY',
            {row['mode'] for row in empirical.FIELD_DISPOSITIONS.values()})
        used = set()
        for row in empirical.FIELD_DISPOSITIONS.values():
            self.assertIn(row['mode'],
                          ('CONSTRAINT_REQUIRED', 'CONSTANT_PUBLIC'))
            if row['mode'] == 'CONSTRAINT_REQUIRED':
                self.assertTrue(row['families'])
                used.update(row['families'])
            else:
                self.assertRegex(row['check'], r'^[a-z0-9-]+$')
        self.assertEqual(used, {
            'monotonic-timing', 'frame-length', 'message-chunk-order',
            'direction-peer-fork', 'abort-retry', 'mixed-peer-content',
            'all-lane-content',
        })

    def test_each_variable_metadata_family_changes_the_scored_feature(self):
        raw = complete_capture(b'peer-opaque')
        baseline = empirical.extract_c03_features(raw, attempt_history(raw))

        timing_raw = complete_capture(b'peer-opaque', base_time=2_000)
        variants = {
            'monotonic-timing': (
                timing_raw, attempt_history(timing_raw, start=1_900,
                                            end=2_200)),
            'frame-length': (complete_capture(b'peer-opaque-longer'), None),
            'message-chunk-order': (
                complete_capture(b'peer-opaque', extra_peer=True), None),
            'direction-peer-fork': (
                complete_capture(b'peer-opaque', direction=2, peer=2,
                                 fork=bytes([9]) * 32), None),
            'mixed-peer-content': (complete_capture(b'peer-opaqvf'), None),
            'all-lane-content': (complete_capture(b'peer-opaqvf'), None),
        }
        for family, (changed_raw, history) in variants.items():
            changed = empirical.extract_c03_features(
                changed_raw, history or attempt_history(changed_raw))
            with self.subTest(family=family):
                self.assertNotEqual(
                    baseline['families'][family]['exact_sha256'],
                    changed['families'][family]['exact_sha256'])

        changed_history = attempt_history(raw, start=800, end=1_300)
        changed = empirical.extract_c03_features(raw, changed_history)
        self.assertNotEqual(
            baseline['families']['abort-retry']['exact_sha256'],
            changed['families']['abort-retry']['exact_sha256'])

    def test_other_lane_content_cannot_hide_in_the_peer_only_family(self):
        def local_capture(payload):
            return b''.join((
                frame(record_type=2, semantic=3, direction=3, peer=0xff,
                      monotonic_ns=1_000, sequence=0, message=0,
                      payload=payload),
                frame(record_type=5, semantic=9, direction=3, peer=0xff,
                      monotonic_ns=1_100, sequence=1, message=1,
                      payload=b''),
            ))
        raw = local_capture(b'local-secret-state')
        changed_raw = local_capture(b'local-secret-statf')
        before = empirical.extract_c03_features(raw, attempt_history(raw))
        after = empirical.extract_c03_features(
            changed_raw, attempt_history(changed_raw))
        self.assertEqual(
            before['families']['mixed-peer-content']['exact_sha256'],
            after['families']['mixed-peer-content']['exact_sha256'])
        self.assertNotEqual(
            before['families']['all-lane-content']['exact_sha256'],
            after['families']['all-lane-content']['exact_sha256'])

    def test_constant_and_integrity_fields_fail_closed(self):
        raw = bytearray(complete_capture())
        variants = []
        changed = bytearray(raw); changed[0] ^= 1
        variants.append((changed, 'p1-empirical-frame-constant'))
        changed = bytearray(raw); changed[13] = 1
        variants.append((changed, 'p1-empirical-frame-constant'))
        changed = bytearray(raw); changed[24:32] = struct.pack('>Q', 4)
        variants.append((changed, 'p1-empirical-frame-envelope'))
        changed = bytearray(raw); changed[80] ^= 1
        variants.append((changed, 'p1-empirical-payload-digest'))
        for changed, category in variants:
            changed = bytes(changed)
            with self.subTest(category=category), self.assertRaisesRegex(
                    empirical.EmpiricalRefused, category):
                empirical.extract_c03_features(
                    changed,
                    attempt_history(changed, outcome='ABORTED',
                                    failure_code='CAPTURE_INVALID'))


if __name__ == '__main__':
    unittest.main()
