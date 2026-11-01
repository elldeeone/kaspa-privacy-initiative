"""Public-seam controls for the source-only persistent C1 capture path.

These tests use synthetic wallet values.  They prove protocol behavior only;
they are not an actual capture, privacy result, or launch authorization.
"""
import copy
import json
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
import uuid
from unittest import mock

import c1_capture_supervisor as capture
import lifecycle_worker
import privacy_capture_producer as producer


def word(byte):
    return f'{byte:02x}' * 32


def operation():
    return str(uuid.uuid4())


def frames(raw):
    result = []
    at = 0
    while at < len(raw):
        if raw[at:at + 8] != b'KPBCEV01':
            raise AssertionError('bad frame magic')
        tag = raw[at + 8]
        size = struct.unpack('>Q', raw[at + 9:at + 17])[0]
        payload = raw[at + 17:at + 17 + size]
        result.append((tag, payload))
        at += 17 + size
    return result


class C1CaptureSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / 'private-c1-capture'
        self.binding = capture.RunBinding(
            round=1,
            attempt_id=str(uuid.uuid4()),
            cohort_sha256=word(1),
            financial_run_id=word(2),
            capture_identity=str(uuid.uuid4()),
        )
        self.invoice_operation = operation()
        self.pay_operation = operation()
        self.scan_operation = operation()

    def tearDown(self):
        self.temporary.cleanup()

    def emit(self, grant, callback):
        emitter = capture.StageEmitter(
            grant.worker_config,
            capture_root=grant.mount_source,
        )
        callback(emitter)
        emitter.commit()
        grant.finish(0)

    def fixed_fd_capture(self, supervisor, projection_sha256):
        expected = capture.FIXED_FD[self.binding.round]
        read_fd, write_fd = os.pipe()
        try:
            try:
                saved = os.dup(expected)
            except OSError:
                saved = None
            os.dup2(write_fd, expected)
            os.close(write_fd)
            write_fd = -1
            receipt = supervisor.seal(expected, projection_sha256)
            if saved is not None:
                os.dup2(saved, expected)
                os.close(saved)
            raw = bytearray()
            while True:
                part = os.read(read_fd, 65536)
                if not part:
                    break
                raw.extend(part)
            return receipt, bytes(raw)
        finally:
            if write_fd >= 0:
                os.close(write_fd)
            os.close(read_fd)

    def complete_session(self, *, inconsistent=False):
        round_number = self.binding.round
        incoming = (1 - round_number) % 3
        outgoing = (1 + round_number) % 3
        payment_amount = 500_000_000 if round_number == 1 else 200_000_000
        change_amount = 2_000_000_000 - payment_amount - 1
        supervisor = capture.C1CaptureSupervisor(self.root, self.binding)
        issued = supervisor.open_stage(
            'invoice', self.invoice_operation,
            contact_owner_component=incoming)
        def invoice(out):
            out.issued_invoice(payment_amount)
        self.emit(issued, invoice)
        paid = supervisor.open_stage(
            'pay', self.pay_operation,
            target_invoice_operation_id=self.invoice_operation,
            contact_owner_component=outgoing,
        )
        def payment(out):
            out.accepted_invoice(payment_amount)
            out.original(
                bytes.fromhex(word(3)), 2_000_000_000,
                bytes.fromhex(word(4)), payment_amount,
                bytes.fromhex(word(5)), change_amount,
            )
        self.emit(paid, payment)
        scanned = supervisor.open_stage('scan', self.scan_operation)
        def scan(out):
            out.decrypted_receipt(
                'incoming-payment', 2 * round_number - 1,
                bytes.fromhex(word(6)), bytes.fromhex(word(7)),
                payment_amount + 1 if inconsistent else payment_amount,
            )
            out.decrypted_receipt(
                'change', 2 * round_number, bytes.fromhex(word(5)),
                bytes.fromhex(word(8)), change_amount,
            )
        self.emit(scanned, scan)
        return supervisor

    def test_complete_session_emits_exact_late_sealed_channel(self):
        supervisor = self.complete_session()
        receipt, raw = self.fixed_fd_capture(supervisor, word(9))
        channel = frames(raw)
        self.assertEqual([tag for tag, _ in channel], [1, 2, 3, 3, 3, 3, 3, 5])
        records = [json.loads(payload) for tag, payload in channel if tag == 3]
        self.assertEqual(
            [row['stream'] for row in records],
            ['original', 'invoice', 'invoice', 'decrypted-receipt',
             'decrypted-receipt'],
        )
        expected_sources = (
            ('pay', 1, self.pay_operation, 2, 1),
            ('invoice', 0, self.invoice_operation, 0, 0),
            ('pay', 1, self.pay_operation, 2, 0),
            ('scan', 2, self.scan_operation, 0, 0),
            ('scan', 2, self.scan_operation, 0, 1),
        )
        for row, (stage, stage_sequence, operation_id, contact,
                  event_sequence) in zip(records, expected_sources):
            self.assertEqual(row['source'], {
                'observer_stage': stage,
                'stage_sequence': stage_sequence,
                'operation_id_sha256': hashlib.sha256(
                    operation_id.encode()).hexdigest(),
                'contact_owner_component': contact,
                'contact_binding_qualified': False,
                'source_event_sequence': event_sequence,
                'observed_monotonic_ns':
                    row['source']['observed_monotonic_ns'],
            })
            self.assertIs(type(row['source']['observed_monotonic_ns']), int)
            self.assertGreater(row['source']['observed_monotonic_ns'], 0)
        by_stage = {
            stage: sorted(
                (row['source']['source_event_sequence'],
                 row['source']['observed_monotonic_ns'])
                for row in records
                if row['source']['observer_stage'] == stage)
            for stage in ('invoice', 'pay', 'scan')
        }
        for observations in by_stage.values():
            self.assertEqual(
                [time for _, time in observations],
                sorted(time for _, time in observations),
            )
        self.assertEqual(json.loads(channel[0][1]), {
            'schema': 'kpb-capture-event-channel/v1',
            'round': 1,
            'kind': 'colluder-wallet-capture',
            'attempt_id': self.binding.attempt_id,
            'cohort_sha256': self.binding.cohort_sha256,
            'financial_run_id': self.binding.financial_run_id,
            'capture_identity': self.binding.capture_identity,
        })
        self.assertEqual(json.loads(channel[1][1]), {
            'schema': 'kpb-colluder-wallet-observer-capture/v1',
            'round': 1,
            'projection_sha256': word(9),
            'cohort_sha256': self.binding.cohort_sha256,
            'owner_component': 1,
        })
        self.assertEqual(receipt, {
            'schema': 'kpb-c1-capture-source-status/v1',
            'status': 'CONFIGURED0',
            'round': 1,
            'owner_component': 1,
            'committed_stage_count': 3,
            'captured_record_count': 5,
            'launch_authorized': False,
            'actual_receipt_emitted': False,
            'contact_binding_qualified': False,
            'private_bodies_or_hashes_public': False,
        })

    def test_round1_and_round2_channels_are_consumed_by_existing_producer(self):
        for round_number in (1, 2):
            with self.subTest(round=round_number):
                self.root = (Path(self.temporary.name) /
                             f'producer-round-{round_number}')
                self.binding = capture.RunBinding(
                    round=round_number,
                    attempt_id=str(uuid.uuid4()),
                    cohort_sha256=word(30 + round_number),
                    financial_run_id=word(40 + round_number),
                    capture_identity=str(uuid.uuid4()),
                )
                projection = word(50 + round_number)
                supervisor = self.complete_session()
                _, raw = self.fixed_fd_capture(supervisor, projection)
                rounds = [
                    {'round': number, 'attempt_id': str(uuid.uuid4()),
                     'cohort_sha256': word(60 + number)}
                    for number in (1, 2)
                ]
                financial = [
                    {'financial_run_id': word(70 + number),
                     'retained_projection_sha256': word(80 + number)}
                    for number in (1, 2)
                ]
                rounds[round_number - 1] = {
                    'round': round_number,
                    'attempt_id': self.binding.attempt_id,
                    'cohort_sha256': self.binding.cohort_sha256,
                }
                financial[round_number - 1] = {
                    'financial_run_id': self.binding.financial_run_id,
                    'retained_projection_sha256': projection,
                }
                selection = {
                    'capture_identity': self.binding.capture_identity,
                    'rounds': rounds,
                    'financial_rounds': financial,
                }
                with tempfile.TemporaryFile() as channel_file:
                    channel_file.write(raw)
                    channel_file.seek(0)
                    body, closure = producer._consume(
                        channel_file.fileno(), selection, round_number,
                        'colluder-wallet-capture')
                assembled = json.loads(body)
                self.assertEqual(assembled['round'], round_number)
                self.assertEqual(closure['capture_record_count'], 5)
                self.assertTrue(closure['capture_root_closed'])

    def test_producer_rejects_legacy_or_relabelled_source_envelope(self):
        supervisor = self.complete_session()
        projection = word(9)
        _, raw = self.fixed_fd_capture(supervisor, projection)
        channel = frames(raw)
        meta = json.loads(channel[1][1])
        records = [json.loads(payload) for tag, payload in channel if tag == 3]
        round_row = {
            'round': 1, 'attempt_id': self.binding.attempt_id,
            'cohort_sha256': self.binding.cohort_sha256,
        }
        financial = {'retained_projection_sha256': projection}
        selection = {
            'capture_identity': self.binding.capture_identity,
            'rounds': [round_row],
            'financial_rounds': [{
                'financial_run_id': self.binding.financial_run_id,
                **financial,
            }],
        }
        producer._assemble('colluder-wallet-capture', meta, records,
                           round_row, financial, selection)

        legacy = copy.deepcopy(records)
        legacy[0].pop('source')
        with self.assertRaisesRegex(ValueError, 'record-fields'):
            producer._assemble('colluder-wallet-capture', meta, legacy,
                               round_row, financial, selection)

        mutations = (
            ('stage', lambda rows: rows[0]['source'].__setitem__(
                'observer_stage', 'scan')),
            ('stage-sequence', lambda rows: rows[0]['source'].__setitem__(
                'stage_sequence', 0)),
            ('operation', lambda rows: rows[0]['source'].__setitem__(
                'operation_id_sha256', word(29))),
            ('contact', lambda rows: rows[0]['source'].__setitem__(
                'contact_owner_component', 0)),
            ('qualification', lambda rows: rows[0]['source'].__setitem__(
                'contact_binding_qualified', True)),
            ('event-sequence', lambda rows: rows[0]['source'].__setitem__(
                'source_event_sequence', 9)),
            ('time', lambda rows: rows[0]['source'].__setitem__(
                'observed_monotonic_ns', 0)),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                changed = copy.deepcopy(records)
                mutate(changed)
                with self.assertRaisesRegex(ValueError, 'colluder-source'):
                    producer._assemble('colluder-wallet-capture', meta,
                                       changed, round_row, financial,
                                       selection)

        changed = copy.deepcopy(records)
        accepted = next(row for row in changed
                        if row['stream'] == 'invoice'
                        and row['value']['direction'] == 'accepted')
        accepted['value']['operation_id_sha256'] = word(29)
        with self.assertRaisesRegex(
                ValueError, 'colluder-invoice-operation-binding'):
            producer._assemble('colluder-wallet-capture', meta, changed,
                               round_row, financial, selection)

    def test_reorder_missing_crash_replay_and_wrong_uid_fail_closed(self):
        supervisor = capture.C1CaptureSupervisor(self.root, self.binding)
        with self.assertRaisesRegex(capture.CaptureRefused, 'stage-order'):
            supervisor.open_stage('pay', self.pay_operation,
                                  self.invoice_operation,
                                  contact_owner_component=2)
        with self.assertRaisesRegex(capture.CaptureRefused, 'missing-stage'):
            supervisor.seal(capture.FIXED_FD[1], word(9))

        other_root = Path(self.temporary.name) / 'crash'
        crashed = capture.C1CaptureSupervisor(other_root, self.binding)
        grant = crashed.open_stage(
            'invoice', self.invoice_operation, contact_owner_component=0)
        emitter = capture.StageEmitter(grant.worker_config,
                                       capture_root=grant.mount_source)
        emitter.connection.close()
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    'worker-crash|truncated-stage'):
            grant.finish(1)
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    'session-poisoned'):
            crashed.open_stage('invoice', operation(),
                               contact_owner_component=0)

        replay_root = Path(self.temporary.name) / 'replay'
        replayed = capture.C1CaptureSupervisor(replay_root, self.binding)
        grant = replayed.open_stage(
            'invoice', self.invoice_operation, contact_owner_component=0)
        config = grant.worker_config
        self.emit(grant, lambda out: out.issued_invoice(500_000_000))
        with self.assertRaises((capture.CaptureRefused, OSError)):
            capture.StageEmitter(config, capture_root=grant.mount_source)
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    'stage-grant-replay'):
            grant.finish(0)

        uid_root = Path(self.temporary.name) / 'uid'
        wrong_uid = capture.C1CaptureSupervisor(
            uid_root, self.binding, expected_uid=os.getuid() + 1)
        grant = wrong_uid.open_stage(
            'invoice', self.invoice_operation, contact_owner_component=0)
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    'stage-server-refused|stage-receive'):
            capture.StageEmitter(grant.worker_config,
                                 capture_root=grant.mount_source)
        with self.assertRaisesRegex(capture.CaptureRefused, 'wrong-peer-uid'):
            grant.finish(0)

        missing_root = Path(self.temporary.name) / 'missing-worker-stage'
        missing = capture.C1CaptureSupervisor(missing_root, self.binding)
        grant = missing.open_stage(
            'invoice', self.invoice_operation, contact_owner_component=0)
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    'worker-stage-aborted'):
            grant.finish(0)
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    'session-poisoned'):
            missing.open_stage('invoice', operation(),
                               contact_owner_component=0)

    def test_extra_worker_and_in_stage_reorder_poison_one_shot_session(self):
        supervisor = capture.C1CaptureSupervisor(self.root, self.binding)
        grant = supervisor.open_stage(
            'invoice', self.invoice_operation, contact_owner_component=0)
        emitter = capture.StageEmitter(grant.worker_config,
                                       capture_root=grant.mount_source)
        with self.assertRaises((capture.CaptureRefused, OSError)):
            capture.StageEmitter(grant.worker_config,
                                 capture_root=grant.mount_source)
        invalid_original = {
            'input_nf_hex32': word(1),
            'input_amount_sompi': 2_000_000_000,
            'created_outputs': [
                {'kind': 'outgoing-payment', 'tuple_sha256': word(2),
                 'amount_sompi': 500_000_000},
                {'kind': 'change', 'tuple_sha256': word(3),
                 'amount_sompi': 1_499_999_999},
            ],
        }
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    'stage-receive|stage-server-refused'):
            emitter._event('original', invalid_original)
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    'stage-event-order'):
            grant.finish(0)
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    'session-poisoned'):
            supervisor.open_stage('invoice', operation(),
                                  contact_owner_component=0)

    def test_worker_cannot_supply_or_relabel_supervisor_source(self):
        supervisor = capture.C1CaptureSupervisor(self.root, self.binding)
        grant = supervisor.open_stage(
            'invoice', self.invoice_operation, contact_owner_component=0)
        emitter = capture.StageEmitter(grant.worker_config,
                                       capture_root=grant.mount_source)
        value = {
            'direction': 'issued', 'source_owner_component': 0,
            'target_owner_component': 1,
            'operation_id_sha256': hashlib.sha256(
                self.invoice_operation.encode()).hexdigest(),
            'amount_sompi': 500_000_000,
        }
        emitter._send({
            'schema': 'kpb-c1-capture-stage-message/v1',
            'type': 'event', 'event_sequence': 0, 'stream': 'invoice',
            'source': {
                'observer_stage': 'scan',
                'contact_binding_qualified': True,
            },
            'value': value,
        })
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    'stage-server-refused|stage-receive'):
            emitter._receive()
        emitter.connection.close()
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    'event-message-fields'):
            grant.finish(0)

    def test_wrong_fixed_fd_and_cross_stage_mismatch_never_emit_end(self):
        supervisor = self.complete_session()
        with self.assertRaisesRegex(capture.CaptureRefused, 'wrong-fixed-fd'):
            supervisor.seal(23, word(9))

        mismatch_root = Path(self.temporary.name) / 'mismatch'
        self.root = mismatch_root
        mismatch = self.complete_session(inconsistent=True)
        expected = capture.FIXED_FD[1]
        read_fd, write_fd = os.pipe()
        try:
            try:
                saved = os.dup(expected)
            except OSError:
                saved = None
            os.dup2(write_fd, expected)
            os.close(write_fd)
            with self.assertRaisesRegex(capture.CaptureRefused,
                                        'cross-stage-consistency'):
                mismatch.seal(expected, word(9))
            if saved is None:
                os.close(expected)
            else:
                os.dup2(saved, expected)
                os.close(saved)
            self.assertEqual(os.read(read_fd, 1), b'')
        finally:
            os.close(read_fd)

    def test_retry_invalidates_whole_trial_and_retains_private_evidence(self):
        supervisor = capture.C1CaptureSupervisor(self.root, self.binding)
        grant = supervisor.open_stage(
            'invoice', self.invoice_operation, contact_owner_component=0)
        emitter = capture.StageEmitter(
            grant.worker_config, capture_root=grant.mount_source)
        emitter.issued_invoice(500_000_000)
        with self.assertRaisesRegex(
                capture.CaptureRefused, 'stage-server-refused'):
            emitter.retry('invoice_retry_0', 10, 11, 'disconnected')
        emitter.connection.close()
        with self.assertRaisesRegex(
                capture.WholeTrialRetryInvalidated,
                'whole-trial-retry'):
            grant.finish(78)

        retained = self.root / 'WHOLE-TRIAL-INVALIDATION.json'
        self.assertTrue(retained.is_file())
        self.assertEqual(retained.stat().st_mode & 0o777, 0o600)
        evidence = json.loads(retained.read_bytes())
        self.assertEqual(evidence, {
            'schema': 'kpb-c1-whole-trial-retry-invalidation/v1',
            'disposition': 'FRESH_TRIAL_REQUIRED',
            'binding': {
                'round': self.binding.round,
                'attempt_id': self.binding.attempt_id,
                'cohort_sha256': self.binding.cohort_sha256,
                'financial_run_id': self.binding.financial_run_id,
                'capture_identity': self.binding.capture_identity,
            },
            'owner_component': 1,
            'stage': 'invoice',
            'stage_sequence': 0,
            'operation_id_sha256': hashlib.sha256(
                self.invoice_operation.encode()).hexdigest(),
            'source_event_sequence': 1,
            'observed_monotonic_ns':
                evidence['observed_monotonic_ns'],
            'retry': {
                'attempt_id': 'invoice_retry_0',
                'start_monotonic_ns': 10,
                'complete_monotonic_ns': 11,
                'outcome': 'disconnected',
            },
            'retry_message': {
                'schema': 'kpb-c1-capture-stage-message/v1',
                'type': 'event',
                'event_sequence': 1,
                'stream': 'retry',
                'value': {
                    'attempt_id': 'invoice_retry_0',
                    'start_monotonic_ns': 10,
                    'complete_monotonic_ns': 11,
                    'outcome': 'disconnected',
                },
            },
            'retry_envelope_valid': True,
            'retry_claimed_event_sequence': 1,
            'retry_body_valid': True,
            'evidence_scope': 'PRIVATE_TRIAL_HISTORY_ONLY',
            'outer_history_joined': False,
        })
        self.assertGreater(evidence['observed_monotonic_ns'], 0)
        self.assertTrue(
            (self.root / 'spool/0-invoice.partial.jsonl').is_file())
        self.assertFalse(
            (self.root / 'spool/0-invoice.committed.jsonl').exists())
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    'session-poisoned'):
            supervisor.open_stage('invoice', operation(),
                                  contact_owner_component=0)

        malformed_root = Path(self.temporary.name) / 'malformed-retry'
        malformed = capture.C1CaptureSupervisor(
            malformed_root, self.binding)
        grant = malformed.open_stage(
            'invoice', self.invoice_operation, contact_owner_component=0)
        emitter = capture.StageEmitter(
            grant.worker_config, capture_root=grant.mount_source)
        with self.assertRaisesRegex(
                capture.CaptureRefused, 'stage-server-refused'):
            emitter._event('retry', {'caller_authored': True})
        emitter.connection.close()
        with self.assertRaisesRegex(
                capture.WholeTrialRetryInvalidated,
                'whole-trial-retry'):
            grant.finish(0)
        malformed_evidence = json.loads(
            (malformed_root / 'WHOLE-TRIAL-INVALIDATION.json').read_bytes())
        self.assertEqual(malformed_evidence['retry'],
                         {'caller_authored': True})
        self.assertIs(malformed_evidence['retry_envelope_valid'], True)
        self.assertIs(malformed_evidence['retry_body_valid'], False)

        envelope_root = Path(self.temporary.name) / 'malformed-retry-envelope'
        envelope = capture.C1CaptureSupervisor(envelope_root, self.binding)
        grant = envelope.open_stage(
            'invoice', self.invoice_operation, contact_owner_component=0)
        emitter = capture.StageEmitter(
            grant.worker_config, capture_root=grant.mount_source)
        hostile = {
            'schema': 'caller-schema', 'type': 'event',
            'event_sequence': 99, 'stream': 'retry',
            'value': {'caller_authored': True}, 'extra': True,
        }
        emitter._send(hostile)
        with self.assertRaisesRegex(
                capture.CaptureRefused, 'stage-server-refused'):
            emitter._receive()
        emitter.connection.close()
        with self.assertRaisesRegex(
                capture.WholeTrialRetryInvalidated,
                'whole-trial-retry'):
            grant.finish(78)
        envelope_evidence = json.loads((
            envelope_root / 'WHOLE-TRIAL-INVALIDATION.json').read_bytes())
        self.assertEqual(envelope_evidence['retry_message'], hostile)
        self.assertEqual(
            envelope_evidence['retry_claimed_event_sequence'], 99)
        self.assertIs(envelope_evidence['retry_envelope_valid'], False)
        self.assertIs(envelope_evidence['retry_body_valid'], False)

        collision_root = Path(self.temporary.name) / 'retry-collision'
        collision = capture.C1CaptureSupervisor(
            collision_root, self.binding)
        retained = collision_root / 'WHOLE-TRIAL-INVALIDATION.json'
        retained.write_bytes(b'prior-private-trial-evidence\n')
        os.chmod(retained, 0o600)
        grant = collision.open_stage(
            'invoice', self.invoice_operation, contact_owner_component=0)
        emitter = capture.StageEmitter(
            grant.worker_config, capture_root=grant.mount_source)
        with self.assertRaisesRegex(
                capture.CaptureRefused, 'stage-server-refused'):
            emitter.retry('collision', 10, 11, 'refused')
        emitter.connection.close()
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    'retry-invalidation-replay'):
            grant.finish(0)
        self.assertEqual(retained.read_bytes(),
                         b'prior-private-trial-evidence\n')
        self.assertFalse(any(collision.spool_dir.glob('*.committed.jsonl')))

    def test_uint64_time_boundary_is_accepted_and_overflow_is_refused(self):
        overflow = capture.C1CaptureSupervisor(self.root, self.binding)
        grant = overflow.open_stage(
            'invoice', self.invoice_operation, contact_owner_component=0)
        emitter = capture.StageEmitter(
            grant.worker_config, capture_root=grant.mount_source)
        with mock.patch.object(
                capture.time, 'monotonic_ns', return_value=1 << 64):
            with self.assertRaisesRegex(
                    capture.CaptureRefused, 'stage-server-refused'):
                emitter.issued_invoice(500_000_000)
        emitter.connection.close()
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    'observed-monotonic-ns'):
            grant.finish(0)
        partial = self.root / 'spool/0-invoice.partial.jsonl'
        self.assertTrue(partial.is_file())
        self.assertEqual(partial.stat().st_size, 0)
        self.assertFalse(any(overflow.spool_dir.glob('*.committed.jsonl')))

    def test_extra_record_truncation_and_order_never_commit_or_emit_end(self):
        extra_root = Path(self.temporary.name) / 'extra-record'
        extra = capture.C1CaptureSupervisor(extra_root, self.binding)
        grant = extra.open_stage(
            'invoice', self.invoice_operation, contact_owner_component=0)
        emitter = capture.StageEmitter(
            grant.worker_config, capture_root=grant.mount_source)
        emitter.issued_invoice(500_000_000)
        with self.assertRaisesRegex(
                capture.CaptureRefused, 'stage-server-refused'):
            emitter.issued_invoice(500_000_000)
        emitter.connection.close()
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    'stage-event-order'):
            grant.finish(0)
        self.assertFalse(any(extra.spool_dir.glob('*.committed.jsonl')))

        truncated_root = Path(self.temporary.name) / 'truncated-record'
        truncated = capture.C1CaptureSupervisor(
            truncated_root, self.binding)
        grant = truncated.open_stage(
            'invoice', self.invoice_operation, contact_owner_component=0)
        emitter = capture.StageEmitter(
            grant.worker_config, capture_root=grant.mount_source)
        emitter.connection.sendall(b'{"schema":')
        emitter.connection.close()
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    'json|canonical-json'):
            grant.finish(0)
        self.assertFalse(any(truncated.spool_dir.glob('*.committed.jsonl')))

        ordered_root = Path(self.temporary.name) / 'wrong-order'
        ordered = capture.C1CaptureSupervisor(ordered_root, self.binding)
        grant = ordered.open_stage(
            'invoice', self.invoice_operation, contact_owner_component=0)
        emitter = capture.StageEmitter(
            grant.worker_config, capture_root=grant.mount_source)
        with self.assertRaisesRegex(
                capture.CaptureRefused, 'stage-server-refused'):
            emitter._event('original', {
                'input_nf_hex32': word(1),
                'input_amount_sompi': 2_000_000_000,
                'created_outputs': [
                    {'kind': 'outgoing-payment',
                     'tuple_sha256': word(2),
                     'amount_sompi': 500_000_000},
                    {'kind': 'change', 'tuple_sha256': word(3),
                     'amount_sompi': 1_499_999_999},
                ],
            })
        emitter.connection.close()
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    'stage-event-order'):
            grant.finish(0)
        self.assertFalse(any(ordered.spool_dir.glob('*.committed.jsonl')))

    def test_private_seqpacket_channel_survives_real_bubblewrap_namespace(self):
        supervisor = capture.C1CaptureSupervisor(self.root, self.binding)
        grant = supervisor.open_stage(
            'invoice', self.invoice_operation, contact_owner_component=0)
        config_path = Path(self.temporary.name) / 'CONFIG.json'
        config_path.write_bytes(capture.encoded(grant.worker_config))
        os.chmod(config_path, 0o600)
        source = Path(capture.__file__).absolute()
        script = (
            "import json; from pathlib import Path; "
            "import c1_capture_supervisor as c; "
            "e=c.StageEmitter(json.loads(Path('/CONFIG.json').read_bytes())); "
            "e.issued_invoice(500000000); e.commit()"
        )
        command = [
            '/usr/bin/bwrap', '--unshare-all', '--die-with-parent',
            '--new-session', '--clearenv', '--ro-bind', '/usr', '/usr',
            '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc',
            '--dev', '/dev', '--tmpfs', '/tmp',
            '--ro-bind', str(grant.mount_source), '/capture',
            '--ro-bind', str(config_path), '/CONFIG.json',
            '--ro-bind', str(source), '/c1_capture_supervisor.py',
            '--setenv', 'PYTHONPATH', '/', '--setenv', 'PATH', '/usr/bin:/bin',
            '/usr/bin/python3', '-B', '-c', script,
        ]
        result = subprocess.run(command, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        grant.finish(result.returncode)

    def test_controller_mount_and_capability_are_exactly_c1_only(self):
        supervisor = capture.C1CaptureSupervisor(self.root, self.binding)
        grant = supervisor.open_stage(
            'invoice', self.invoice_operation, contact_owner_component=0)
        addition, mounts = capture.controller_stage(
            grant, owner_component=1, operation_name='invoice',
            operation_id=self.invoice_operation,
            target_invoice_operation_id=None,
        )
        self.assertEqual(addition, {'c1_capture': grant.worker_config})
        self.assertEqual(mounts, [
            '--ro-bind', str(grant.mount_source), '/capture',
        ])
        for owner in (0, 2):
            with self.assertRaisesRegex(capture.CaptureRefused,
                                        'only-owner-c1'):
                capture.controller_stage(
                    grant, owner_component=owner,
                    operation_name='invoice',
                    operation_id=self.invoice_operation,
                    target_invoice_operation_id=None,
                )
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    'controller-operation-binding'):
            capture.controller_stage(
                grant, owner_component=1, operation_name='invoice',
                operation_id=operation(),
                target_invoice_operation_id=None,
            )
        self.assertEqual(capture.controller_stage(
            None, owner_component=0, operation_name='invoice',
            operation_id=self.invoice_operation,
            target_invoice_operation_id=None,
        ), ({}, []))

    def test_authenticated_scan_receipts_emit_at_recovery_boundary(self):
        class Receipt:
            def __init__(self, index, amount, cm):
                self.index = index
                self.value_sompi = amount
                self._cm = cm
            def commitment(self):
                return self._cm
        class Claim:
            def __init__(self, position, receipt):
                self.position = position
                self.receipt = receipt
        class Emitter:
            def __init__(self):
                self.calls = []
            def decrypted_receipt(self, *args):
                self.calls.append(args)
        incoming = bytes.fromhex(word(10)) + bytes(488)
        change = bytes.fromhex(word(11)) + bytes(488)
        history = type('History', (), {'rows': (bytes(520), incoming, change)})()
        claims = [
            Claim(1, Receipt(1, 500_000_000, incoming[:32])),
            Claim(2, Receipt(2, 1_499_999_999, change[:32])),
        ]
        emitter = Emitter()
        lifecycle_worker.capture_recovered_receipts(
            emitter, history, claims,
            {'round': 1, 'owner_component': 1},
        )
        self.assertEqual(emitter.calls, [
            ('incoming-payment', 1, incoming, incoming[:32], 500_000_000),
            ('change', 2, change, change[:32], 1_499_999_999),
        ])

    def test_caller_cannot_relabel_creator_after_contact_binding(self):
        supervisor = capture.C1CaptureSupervisor(self.root, self.binding)
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    'prospective-contact-binding'):
            supervisor.open_stage(
                'invoice', self.invoice_operation,
                contact_owner_component=2,
            )
        issued = supervisor.open_stage(
            'invoice', self.invoice_operation, contact_owner_component=0)
        self.emit(issued, lambda out: out.issued_invoice(500_000_000))
        paid = supervisor.open_stage(
            'pay', self.pay_operation,
            target_invoice_operation_id=self.invoice_operation,
            contact_owner_component=2,
        )
        def payment(out):
            out.accepted_invoice(500_000_000)
            out.original(bytes.fromhex(word(3)), 2_000_000_000,
                         bytes.fromhex(word(4)), 500_000_000,
                         bytes.fromhex(word(5)), 1_499_999_999)
        self.emit(paid, payment)
        scanned = supervisor.open_stage('scan', self.scan_operation)
        relabeled = scanned.worker_config
        relabeled['contact_owner_component'] = 2
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    'worker-contact-binding'):
            capture.StageEmitter(relabeled,
                                 capture_root=scanned.mount_source)
        with self.assertRaisesRegex(capture.CaptureRefused, 'worker-crash'):
            scanned.finish(1)


if __name__ == '__main__':
    unittest.main()
