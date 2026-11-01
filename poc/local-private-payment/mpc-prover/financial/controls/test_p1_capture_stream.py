#!/usr/bin/env python3
"""Behavior controls for the source-only P1 binary capture stream."""

import hashlib
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


HERE = Path(__file__).resolve().parent
MPC = HERE.parent.parent
ROOT = MPC.parents[2]
MP_SPDZ = ROOT / '.local' / 'mpc-prover-vendor' / 'MP-SPDZ'
PREFIX = ROOT / '.local' / 'mpc-prover-vendor' / 'prefix' / 'usr'
MCL = ROOT / '.local' / 'mpc-prover-vendor' / 'mcl'
HEADER = 112
MAGIC = b'KPBP1C03'


def frames(raw):
    result = []
    at = 0
    sequence = 0
    while at < len(raw):
        if len(raw) - at < HEADER:
            raise ValueError('truncated-header')
        header = raw[at:at + HEADER]
        if header[:8] != MAGIC or header[13:16] != bytes(3):
            raise ValueError('header')
        size = int.from_bytes(header[44:48], 'big')
        payload = raw[at + HEADER:at + HEADER + size]
        if len(payload) != size:
            raise ValueError('truncated-payload')
        if int.from_bytes(header[24:32], 'big') != sequence:
            raise ValueError('sequence')
        if hashlib.sha256(payload).digest() != header[80:112]:
            raise ValueError('payload-digest')
        result.append({
            'type': header[8], 'semantic': header[9],
            'direction': header[10], 'peer': header[11],
            'flags': header[12],
            'monotonic_ns': int.from_bytes(header[16:24], 'big'),
            'sequence': sequence,
            'message': int.from_bytes(header[32:40], 'big'),
            'chunk': int.from_bytes(header[40:44], 'big'),
            'fork': header[48:80], 'payload': payload,
        })
        sequence += 1
        at += HEADER + size
    return result


class P1CaptureStreamControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-p1-capture-stream-controls-')
        cls.binary = Path(cls.temporary.name) / 'controls'
        compiled = subprocess.run([
            'g++', '-std=c++20', '-march=native', '-Wall', '-Wextra',
            '-Werror', '-Wno-overloaded-virtual', '-pedantic',
            '-DNO_MIXED_CIRCUITS', '-DNO_AVX_OT', '-DUSE_GF2N_LONG',
            '-DMCL_USE_GMP=1', '-DMCL_DONT_USE_XBYAK',
            '-DMCL_FP_BIT=384', '-DMCL_FR_BIT=256', '-DMCL_MSM=0',
            '-DKPI_P1_CAPTURE_TEST_SETUP',
            str(HERE / 'p1_capture_stream_test.cpp'),
            str(MPC / 'p1_capture_stream.cpp'),
            '-I', str(MPC), '-I', str(MP_SPDZ),
            '-I', str(PREFIX / 'include'),
            '-I', str(PREFIX / 'include' / 'x86_64-linux-gnu'),
            '-I', str(MCL / 'include'),
            '-L', str(MP_SPDZ), '-Wl,-rpath,' + str(MP_SPDZ),
            '-L', str(PREFIX / 'lib' / 'x86_64-linux-gnu'),
            '-Wl,-rpath,' + str(PREFIX / 'lib' / 'x86_64-linux-gnu'),
            '-L', str(MCL / 'lib'), '-lSPDZ', '-lmcl', '-lcrypto',
            '-lgmpxx', '-lgmp', '-pthread', '-o', str(cls.binary),
        ], capture_output=True, text=True, check=False)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_complete_stream_is_chunked_late_sealed_and_counted(self):
        run = subprocess.run([str(self.binary)], capture_output=True,
                             check=False, timeout=10)
        self.assertEqual((run.returncode, run.stderr), (0, b''))
        decoded = frames(run.stdout)
        self.assertEqual(decoded[0]['type'], 1)  # HELLO
        hello = decoded[0]['payload']
        self.assertEqual(len(hello), 332)
        self.assertEqual(hello[:4], bytes((1, 1, 0, 23)))
        self.assertEqual(hello[140:172], bytes.fromhex('5' * 64))
        self.assertEqual(hello[172:204], bytes.fromhex('6' * 64))
        self.assertEqual(hello[204:236], bytes.fromhex('7' * 64))
        self.assertEqual(hello[236:268], bytes.fromhex('8' * 64))
        self.assertEqual(hello[268:300], bytes.fromhex('9' * 64))
        self.assertEqual(hello[300:332], bytes.fromhex(
            '5e6903569bc71cbfb5549b369b79a19ecda6686dc4ab25fca0d161c6e1527b6b'))
        self.assertEqual(decoded[-2]['type'], 4)  # COMPLETENESS
        self.assertEqual(decoded[-1]['type'], 5)  # END
        self.assertEqual(decoded[-1]['payload'], b'')
        timestamps = [row['monotonic_ns'] for row in decoded]
        self.assertTrue(all(value > 0 for value in timestamps))
        self.assertEqual(timestamps, sorted(timestamps))
        seals = [row for row in decoded if row['type'] == 3]
        self.assertEqual(len(seals), 1)
        projection = bytes(index % 251 for index in range(10685))
        self.assertEqual(seals[0]['payload'], hashlib.sha256(projection).digest())
        projection_rows = [row for row in decoded
                           if row['type'] == 2 and row['semantic'] == 9]
        self.assertTrue(projection_rows)
        self.assertLess(max(row['sequence'] for row in projection_rows),
                        seals[0]['sequence'])
        self.assertNotIn(seals[0]['payload'], decoded[0]['payload'])
        self.assertEqual(len(decoded[-2]['payload']), 496)
        footer = decoded[-2]['payload']
        self.assertEqual(int.from_bytes(footer[:4], 'big'), 9)
        self.assertEqual(int.from_bytes(footer[4:8], 'big'), 17)
        self.assertEqual(int.from_bytes(footer[472:480], 'big'),
                         decoded[-2]['sequence'])
        self.assertEqual(int.from_bytes(footer[480:488], 'big'),
                         timestamps[0])
        self.assertLessEqual(int.from_bytes(footer[488:496], 'big'),
                             decoded[-2]['monotonic_ns'])

    def test_large_transport_is_streamed_in_bounded_chunks(self):
        run = subprocess.run([str(self.binary), 'large'], capture_output=True,
                             check=False, timeout=20)
        self.assertEqual((run.returncode, run.stderr), (0, b''))
        decoded = frames(run.stdout)
        transport = [row for row in decoded
                     if row['type'] == 2 and row['semantic'] == 2]
        self.assertGreater(len(transport), 32)
        self.assertLessEqual(max(len(row['payload']) for row in transport),
                             1 << 16)
        messages = {}
        for row in transport:
            messages.setdefault(row['message'], []).append(row)
        largest = max(messages.values(), key=lambda rows: sum(
            len(row['payload']) for row in rows))
        self.assertEqual(sum(len(row['payload']) for row in largest),
                         3 * (1 << 20) + 17)
        self.assertEqual([row['chunk'] for row in largest],
                         list(range(len(largest))))
        self.assertEqual(largest[0]['flags'] & 1, 1)
        self.assertEqual(largest[-1]['flags'] & 2, 2)

    def test_truncation_replay_and_payload_tamper_are_rejected(self):
        run = subprocess.run([str(self.binary)], capture_output=True,
                             check=False, timeout=10)
        self.assertEqual(run.returncode, 0)
        raw = run.stdout
        with self.assertRaisesRegex(ValueError, 'truncated'):
            frames(raw[:-1])
        first_size = int.from_bytes(raw[44:48], 'big')
        first = raw[:HEADER + first_size]
        with self.assertRaisesRegex(ValueError, 'sequence'):
            frames(first + raw)
        tampered = bytearray(raw)
        tampered[HEADER] ^= 1
        with self.assertRaisesRegex(ValueError, 'payload-digest'):
            frames(tampered)

    def test_delayed_reader_is_lossless_under_backpressure(self):
        started = time.monotonic()
        run = subprocess.run([str(self.binary), 'delayed-reader'],
                             capture_output=True, check=False, timeout=5)
        self.assertEqual((run.returncode, run.stdout, run.stderr),
                         (0, b'', b''))
        self.assertLess(time.monotonic() - started, 4)

    def test_closed_consumer_poisons_stream(self):
        run = subprocess.run([str(self.binary), 'closed-consumer'],
                             capture_output=True, check=False, timeout=5)
        self.assertEqual((run.returncode, run.stdout, run.stderr),
                         (0, b'', b''))

    def test_missing_required_selected_scalar_site_refuses_completion(self):
        run = subprocess.run([str(self.binary), 'missing-scalar-site'],
                             capture_output=True, check=False, timeout=10)
        self.assertEqual(run.returncode, 78)
        self.assertFalse(any(row['type'] == 5 for row in frames(run.stdout)))

    def test_scalar_messages_are_preceded_by_exact_callsite_bindings(self):
        run = subprocess.run([str(self.binary)], capture_output=True,
                             check=False, timeout=10)
        self.assertEqual((run.returncode, run.stderr), (0, b''))
        data = [row for row in frames(run.stdout) if row['type'] == 2]
        bindings = [index for index, row in enumerate(data)
                    if row['semantic'] == 17]
        self.assertEqual(len(bindings), 22)
        first = data[bindings[0]]['payload']
        second = data[bindings[1]]['payload']
        self.assertEqual(first, bytes((1, 2, 0, 1)) +
                         (1).to_bytes(8, 'big') + bytes(4))
        self.assertEqual(second, bytes((1, 1, 0, 2)) +
                         (1).to_bytes(8, 'big') + bytes(4))
        self.assertEqual([data[bindings[0] + offset]['semantic']
                          for offset in (1, 2)], [5, 6])
        self.assertEqual([data[bindings[1] + offset]['semantic']
                          for offset in (1, 2)], [3, 4])
        footer = frames(run.stdout)[-2]['payload']
        self.assertEqual(int.from_bytes(footer[464:472], 'big'),
                         (1 << 22) - 1)

    def test_masked_and_final_group_openings_are_distinct_and_exact(self):
        run = subprocess.run([str(self.binary)], capture_output=True,
                             check=False, timeout=10)
        self.assertEqual((run.returncode, run.stderr), (0, b''))
        data = [row for row in frames(run.stdout) if row['type'] == 2]
        by_semantic = {semantic: [(row['payload'][0], len(row['payload']))
                                  if semantic in (15, 16)
                                  else len(row['payload']) for row in data
                                  if row['semantic'] == semantic]
                       for semantic in (7, 8, 12, 13, 15, 16)}
        self.assertEqual(by_semantic, {
            7: [2 * 65], 8: [129], 12: [2 * 65], 13: [2 * 32],
            15: [(1, 521), (2, 781), (3, 261), (4, 261)],
            16: [(1, 259), (4, 259)]})

    def test_group_state_stage_order_and_repeated_a_are_fail_closed(self):
        for scenario in (
                'wrong-group-stage', 'wrong-final-a', 'wrong-final-a-mac',
                'wrong-final-b2-mac'):
            with self.subTest(scenario=scenario):
                run = subprocess.run([str(self.binary), scenario],
                                     capture_output=True, check=False,
                                     timeout=10)
                self.assertEqual(run.returncode, 78)
                self.assertFalse(any(row['type'] == 5
                                     for row in frames(run.stdout)))

    def test_missing_local_mac_key_share_refuses_completion(self):
        run = subprocess.run([str(self.binary), 'missing-mac-key'],
                             capture_output=True, check=False, timeout=10)
        self.assertEqual(run.returncode, 78)
        self.assertFalse(any(row['type'] == 5 for row in frames(run.stdout)))

    def test_source_has_no_arbitrary_per_message_size_cap(self):
        header = (MPC / 'p1_capture_stream.hpp').read_text()
        source = (MPC / 'p1_capture_stream.cpp').read_text()
        self.assertNotIn('MAX_MESSAGE_BYTES', header + source)

    def test_wrong_role_is_refused_before_any_private_body_is_written(self):
        run = subprocess.run([str(self.binary), 'role-bypass'],
                             capture_output=True, check=False, timeout=5)
        self.assertEqual((run.returncode, run.stdout, run.stderr),
                         (0, b'', b''))


if __name__ == '__main__':
    unittest.main()
