"""Controls for the source-bound C1 contact/value capture envelope.

Synthetic values exercise authority flow only. They are not an actual capture
or privacy qualification.
"""

import hashlib
import fcntl
import json
import os
from pathlib import Path
import copy
import tempfile
import unittest
import uuid
from unittest import mock

import c1_capture_supervisor as capture
from test_c1_capture_supervisor import frames, word


def operation():
    return str(uuid.uuid4())


class C1ContactValueAuthorityControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / 'qualified-c1'
        self.binding = capture.RunBinding(
            round=1,
            attempt_id=str(uuid.uuid4()),
            cohort_sha256=word(1),
            financial_run_id=word(2),
            capture_identity=str(uuid.uuid4()),
        )
        self.operations = (operation(), operation(), operation())

    def tearDown(self):
        self.temporary.cleanup()

    def authority(self):
        contacts = (0, 2, 0)
        fields = {
            'source_sha256': word(20),
            'build_sha256': word(21),
            'runtime_sha256': word(22),
            'assets_sha256': word(23),
            'pinned_executable_sha256': word(24),
            'launcher_sha256': word(25),
            'route_source_sha256': word(26),
            'role_launch_sha256': word(27),
            'process_sha256': word(28),
        }
        fields['stage_plan_sha256'] = capture._stage_plan_sha256(
            self.binding.round, self.operations)
        fields['route_manifest_sha256'] = capture._route_manifest_sha256(
            self.binding.round, contacts, self.operations,
            fields['route_source_sha256'])
        operation_hashes = [hashlib.sha256(value.encode()).hexdigest()
                            for value in self.operations]
        preimage = {
            'schema': 'kpb-c1-contact-value-authority-preimage/v2',
            'round': self.binding.round,
            'financial_run_id': self.binding.financial_run_id,
            'attempt_id': self.binding.attempt_id,
            'cohort_sha256': self.binding.cohort_sha256,
            'capture_identity': self.binding.capture_identity,
            'owner_component': 1,
            'fixed_fd': capture.FIXED_FD[self.binding.round],
            'contact_owner_components': list(contacts),
            **fields,
            'operation_id_sha256': operation_hashes,
        }
        identity = hashlib.sha256(
            capture.AUTHORITY_ID_DOMAIN + capture.encoded(preimage)).digest()
        raw = bytearray(capture.CONTACT_VALUE_OFFER_MAGIC)
        raw.extend((2, self.binding.round, 1,
                    capture.FIXED_FD[self.binding.round],
                    capture.CONTACT_VALUE_OFFER_FIXED_FD, 3,
                    *contacts, 0))
        raw.extend(self.binding.attempt_id.encode())
        raw.extend(self.binding.capture_identity.encode())
        raw.extend(bytes.fromhex(self.binding.cohort_sha256))
        raw.extend(bytes.fromhex(self.binding.financial_run_id))
        for name in (
                'source_sha256', 'build_sha256', 'runtime_sha256',
                'assets_sha256', 'pinned_executable_sha256',
                'launcher_sha256', 'route_manifest_sha256',
                'route_source_sha256', 'role_launch_sha256',
                'process_sha256', 'stage_plan_sha256'):
            raw.extend(bytes.fromhex(fields[name]))
        for value in self.operations:
            raw.extend(value.encode())
        raw.extend(identity)
        self.assertEqual(len(raw), capture.CONTACT_VALUE_OFFER_BYTES)
        fd = os.memfd_create(
            'kpb-c1-contact-value-test',
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        os.fchmod(fd, 0o600)
        os.write(fd, raw)
        seals = (fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK |
                 fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
        if fd != capture.CONTACT_VALUE_OFFER_FIXED_FD:
            os.dup2(fd, capture.CONTACT_VALUE_OFFER_FIXED_FD)
            os.close(fd)
        return capture.CONTACT_VALUE_OFFER_FIXED_FD

    def emit(self, grant, callback):
        emitter = capture.StageEmitter(
            grant.worker_config, capture_root=grant.mount_source)
        callback(emitter)
        emitter.commit()
        grant.finish(0)

    def complete(self, authority):
        supervisor = capture.C1CaptureSupervisor(
            self.root, self.binding, contact_value_offer_fd=authority)
        issued = supervisor.open_stage(
            'invoice', contact_owner_component=None)
        def invoice(out):
            out.issued_invoice(500_000_000)

        self.emit(issued, invoice)
        paid = supervisor.open_stage(
            'pay',
            contact_owner_component=None)

        def payment(out):
            out.accepted_invoice(500_000_000)
            out.original(
                bytes.fromhex(word(3)), 2_000_000_000,
                bytes.fromhex(word(4)), 500_000_000,
                bytes.fromhex(word(5)), 1_499_999_999)

        self.emit(paid, payment)
        scanned = supervisor.open_stage(
            'scan', contact_owner_component=None)

        def scan(out):
            out.decrypted_receipt(
                'incoming-payment', 1, bytes.fromhex(word(6)),
                bytes.fromhex(word(7)), 500_000_000)
            out.decrypted_receipt(
                'change', 2, bytes.fromhex(word(5)),
                bytes.fromhex(word(8)), 1_499_999_999)

        self.emit(scanned, scan)
        return supervisor

    def seal(self, supervisor):
        selected_fd = capture.FIXED_FD[self.binding.round]
        read_fd, write_fd = os.pipe()
        try:
            try:
                saved = os.dup(selected_fd)
            except OSError:
                saved = None
            os.dup2(write_fd, selected_fd)
            os.close(write_fd)
            write_fd = -1
            status = supervisor.seal(selected_fd, word(9))
            if saved is not None:
                os.dup2(saved, selected_fd)
                os.close(saved)
            raw = bytearray()
            while True:
                part = os.read(read_fd, 65536)
                if not part:
                    break
                raw.extend(part)
            return status, bytes(raw)
        finally:
            if write_fd >= 0:
                os.close(write_fd)
            os.close(read_fd)

    def test_qualified_source_binds_every_canonical_value_and_contact(self):
        supervisor = self.complete(self.authority())
        status, raw = self.seal(supervisor)
        channel = frames(raw)
        meta = json.loads(channel[1][1])
        records = [json.loads(payload) for tag, payload in channel
                   if tag == 3]

        self.assertEqual(meta['schema'],
                         'kpb-colluder-wallet-observer-capture/v2')
        self.assertRegex(meta['contact_value_authority_sha256'],
                         r'^[0-9a-f]{64}$')
        expected_kinds = (
            'ORIGINAL', 'ISSUED_INVOICE', 'ACCEPTED_INVOICE',
            'INCOMING_RECEIPT', 'CHANGE_RECEIPT')
        for row, kind in zip(records, expected_kinds):
            source = row['source']
            self.assertEqual(source['schema'],
                             'kpb-c1-authenticated-contact-value-source/v1')
            self.assertIs(source['contact_binding_qualified'], True)
            self.assertIs(source['value_binding_qualified'], True)
            self.assertEqual(source['value_kind'], kind)
            self.assertEqual(source['value_sha256'], hashlib.sha256(
                capture.encoded(row['value'])).hexdigest())
            self.assertEqual(source['contact_value_authority_sha256'],
                             meta['contact_value_authority_sha256'])
            self.assertRegex(source['stage_config_sha256'],
                             r'^[0-9a-f]{64}$')
            self.assertEqual(
                source['source_event_binding_sha256'],
                capture.qualified_source_event_sha256(
                    row['stream'], row['value'], source))

        self.assertIs(status['contact_binding_qualified'], True)
        self.assertIs(status['value_binding_qualified'], True)
        self.assertNotIn('contact_value_authority_sha256', status)
        self.assertNotIn('record_chain_sha256', status)

        producer_evidence = \
            supervisor.take_contact_value_producer_evidence()
        precursor = producer_evidence.consume_for_producer()
        self.assertEqual(precursor['schema'],
                         'kpb-c1-contact-value-authority-precursor/v2')
        self.assertEqual(precursor['owner_component'], 1)
        self.assertEqual(precursor['fixed_fd'], capture.FIXED_FD[1])
        self.assertRegex(precursor['route_manifest_sha256'],
                         r'^[0-9a-f]{64}$')
        self.assertEqual(precursor['contact_value_authority_sha256'],
                         meta['contact_value_authority_sha256'])
        self.assertEqual(len(precursor['operation_id_sha256']), 3)
        self.assertEqual(len(precursor['stage_config_sha256']), 3)
        with self.assertRaisesRegex(
                capture.CaptureRefused, 'producer-evidence-replay'):
            producer_evidence.consume_for_producer()

    def test_retry_invalidates_qualified_trial_before_final_channel(self):
        supervisor = capture.C1CaptureSupervisor(
            self.root, self.binding,
            contact_value_offer_fd=self.authority())
        grant = supervisor.open_stage('invoice', contact_owner_component=None)
        emitter = capture.StageEmitter(
            grant.worker_config, capture_root=grant.mount_source)
        emitter.issued_invoice(500_000_000)
        with self.assertRaisesRegex(
                capture.CaptureRefused, 'stage-server-refused'):
            emitter.retry('invoice_retry', 10, 11, 'disconnected')
        emitter.connection.close()
        with self.assertRaisesRegex(
                capture.WholeTrialRetryInvalidated,
                'whole-trial-retry'):
            grant.finish(0)
        evidence = json.loads(
            (self.root / 'WHOLE-TRIAL-INVALIDATION.json').read_bytes())
        self.assertEqual(evidence['disposition'], 'FRESH_TRIAL_REQUIRED')
        self.assertEqual(evidence['binding']['attempt_id'],
                         self.binding.attempt_id)
        self.assertEqual(evidence['binding']['capture_identity'],
                         self.binding.capture_identity)
        self.assertEqual(
            evidence['contact_value_authority_sha256'],
            grant.worker_config['contact_value_authority_sha256'])
        self.assertFalse(evidence['outer_history_joined'])
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    'session-poisoned'):
            supervisor.open_stage('invoice', contact_owner_component=None)

    def test_qualified_no_retry_schedule_has_exact_source_upper_bounds(self):
        maximum = (1 << 64) - 1
        expected_payloads = (1202, 983, 983, 1060, 1059)
        expected_stage_bytes = (983, 2185, 2119)
        for round_number in (1, 2):
            with self.subTest(round=round_number):
                self.root = Path(self.temporary.name) / (
                    f'qualified-c1-round-{round_number}')
                self.binding = capture.RunBinding(
                    round=round_number,
                    attempt_id=str(uuid.uuid4()),
                    cohort_sha256=word(40 + round_number),
                    financial_run_id=word(50 + round_number),
                    capture_identity=str(uuid.uuid4()),
                )
                self.operations = (operation(), operation(), operation())
                supervisor = capture.C1CaptureSupervisor(
                    self.root, self.binding,
                    contact_value_offer_fd=self.authority())
                payment_amount = (500_000_000 if round_number == 1
                                  else 200_000_000)
                with mock.patch.object(
                        capture.time, 'monotonic_ns',
                        return_value=maximum):
                    issued = supervisor.open_stage(
                        'invoice', contact_owner_component=None)
                    self.emit(issued, lambda out: out.issued_invoice(
                        payment_amount))
                    paid = supervisor.open_stage(
                        'pay', contact_owner_component=None)

                    def payment(out):
                        out.accepted_invoice(payment_amount)
                        out.original(
                            bytes.fromhex(word(3)), maximum,
                            bytes.fromhex(word(4)), payment_amount,
                            bytes.fromhex(word(5)), maximum)

                    self.emit(paid, payment)
                    scanned = supervisor.open_stage(
                        'scan', contact_owner_component=None)

                    def scan(out):
                        out.decrypted_receipt(
                            'incoming-payment', 2 * round_number - 1,
                            bytes.fromhex(word(6)), bytes.fromhex(word(7)),
                            payment_amount)
                        out.decrypted_receipt(
                            'change', 2 * round_number,
                            bytes.fromhex(word(5)), bytes.fromhex(word(8)),
                            maximum)

                    self.emit(scanned, scan)

                status, raw = self.seal(supervisor)
                channel = frames(raw)
                payloads = [len(payload) for tag, payload in channel
                            if tag == 3]
                self.assertEqual(payloads, list(expected_payloads))
                self.assertEqual(len(raw),
                                 capture.QUALIFIED_NO_RETRY_WIRE_MAX_BYTES)
                self.assertEqual(len(raw), 6_140)
                self.assertEqual(
                    [path.stat().st_size for path in sorted(
                        supervisor.spool_dir.glob('*.committed.jsonl'))],
                    list(expected_stage_bytes))
                self.assertEqual(status['captured_record_count'], 5)

    def test_every_event_binding_input_is_fail_closed(self):
        supervisor = self.complete(self.authority())
        _, raw = self.seal(supervisor)
        records = [json.loads(payload) for tag, payload in frames(raw)
                   if tag == 3]
        original = records[0]
        mutations = {
            'contact': lambda row: row['source'].__setitem__(
                'contact_owner_component', 0),
            'stage-config': lambda row: row['source'].__setitem__(
                'stage_config_sha256', word(90)),
            'authority': lambda row: row['source'].__setitem__(
                'contact_value_authority_sha256', word(91)),
            'time': lambda row: row['source'].__setitem__(
                'observed_monotonic_ns',
                row['source']['observed_monotonic_ns'] + 1),
            'body': lambda row: row['value'].__setitem__(
                'input_amount_sompi', 1_999_999_999),
        }
        for name, mutate in mutations.items():
            changed = copy.deepcopy(original)
            mutate(changed)
            with self.subTest(name=name):
                try:
                    recomputed = capture.qualified_source_event_sha256(
                        changed['stream'], changed['value'],
                        changed['source'])
                except capture.CaptureRefused:
                    continue
                self.assertNotEqual(
                    recomputed,
                    changed['source']['source_event_binding_sha256'])

        wrong_kind = copy.deepcopy(original)
        wrong_kind['source']['value_kind'] = 'CHANGE_RECEIPT'
        with self.assertRaisesRegex(
                capture.CaptureRefused, 'qualified-source-value-binding'):
            capture.qualified_source_event_sha256(
                wrong_kind['stream'], wrong_kind['value'],
                wrong_kind['source'])

    def test_authority_is_one_shot_and_caller_cannot_choose_contact_or_stage(self):
        authority = self.authority()
        capture.C1CaptureSupervisor(
            self.root, self.binding, contact_value_offer_fd=authority)

        other = self.authority()
        other_root = Path(self.temporary.name) / 'caller-contact'
        supervisor = capture.C1CaptureSupervisor(
            other_root, self.binding, contact_value_offer_fd=other)
        with self.assertRaisesRegex(
                capture.CaptureRefused, 'qualified-contact-from-authority'):
            supervisor.open_stage(
                'invoice', contact_owner_component=0)
        with self.assertRaisesRegex(
                capture.CaptureRefused, 'qualified-operation-from-authority'):
            supervisor.open_stage(
                'invoice', operation(), contact_owner_component=None)

    def test_cross_run_offer_is_refused_before_source_flags_exist(self):
        authority = self.authority()
        other_binding = capture.RunBinding(
            round=1,
            attempt_id=str(uuid.uuid4()),
            cohort_sha256=word(81),
            financial_run_id=word(82),
            capture_identity=str(uuid.uuid4()),
        )
        with self.assertRaisesRegex(
                capture.CaptureRefused, 'contact-value-offer-run-binding'):
            capture.C1CaptureSupervisor(
                self.root, other_binding,
                contact_value_offer_fd=authority)
        self.assertFalse(self.root.exists())

    def test_no_production_callsite_can_test_mint_qualified_authority(self):
        root = Path(__file__).resolve().parent
        uses = []
        for path in root.glob('*.py'):
            if path.name == Path(__file__).name:
                continue
            if 'ContactValueBindingAuthority' in \
                    path.read_text():
                uses.append(path.name)
        self.assertEqual(uses, [])


if __name__ == '__main__':
    unittest.main()
