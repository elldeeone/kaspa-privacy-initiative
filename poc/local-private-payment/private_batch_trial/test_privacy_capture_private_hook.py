"""Controls for server-P1, colluder-C1 and terminal source hooks."""
import copy
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

import privacy_capture_model as capture
import privacy_capture_producer as producer
import test_privacy_capture_producer as fixture
from test_privacy_capture_model import (
    colluder_fixture, corrupt_fixture, projection, terminal_fixture,
)


HERE = Path(__file__).absolute().parent


def normalize_colluder_observation_times(raw):
    """Normalize only the intentionally nondeterministic trusted timestamps."""
    result = bytearray(); at = 0
    tags = {1: 'hello', 2: 'meta', 3: 'record', 4: 'raw', 5: 'end'}
    while at < len(raw):
        if raw[at:at + 8] != b'KPBCEV01':
            raise AssertionError('bad capture frame')
        tag = raw[at + 8]
        size = struct.unpack('>Q', raw[at + 9:at + 17])[0]
        payload = raw[at + 17:at + 17 + size]
        if tag == 3:
            value = json.loads(payload)
            source = value.get('source')
            if source is not None:
                normalized_time = (100 + 100 * source['stage_sequence']
                                   + source['source_event_sequence'])
                if source['observed_monotonic_ns'] <= 0:
                    raise AssertionError('nonpositive observation time')
                source['observed_monotonic_ns'] = normalized_time
            result.extend(fixture.frame(tags[tag], value))
        else:
            result.extend(raw[at:at + 17 + size])
        at += 17 + size
    return bytes(result)


class PrivateCaptureHookControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_temp = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.build_temp.name) / 'private-hook-control'
        command = [
            'g++', '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread', str(HERE / 'privacy_capture_hook.cpp'),
            str(HERE / 'privacy_capture_private_hook.cpp'),
            str(HERE / 'privacy_capture_private_hook_control.cpp'),
            '-lcrypto', '-o', str(cls.binary),
        ]
        result = subprocess.run(command, text=True, capture_output=True)
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.build_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def run_hook(self, scenario, body=b''):
        return subprocess.run([str(self.binary), scenario], input=body,
                              capture_output=True, check=False)

    def expected(self, kind, value):
        selected = fixture.selection(); value = copy.deepcopy(value)
        value['cohort_sha256'] = selected['rounds'][0]['cohort_sha256']
        return fixture.channel(1, kind, selected, value)

    def test_all_three_cpp_streams_are_byte_exact(self):
        projection_raw, public = projection(1)
        cases = (
            ('terminal', 'terminal-history', terminal_fixture(public), b''),
            ('corrupt', 'corrupt-server-capture',
             corrupt_fixture(public, projection_raw), projection_raw),
            ('colluder', 'colluder-wallet-capture',
             colluder_fixture(public), b''),
        )
        for scenario, kind, expected, stdin in cases:
            with self.subTest(kind=kind):
                result = self.run_hook(scenario, stdin)
                self.assertEqual((result.returncode, result.stderr), (0, b''))
                actual = result.stdout
                expected_raw = self.expected(kind, expected)
                if kind == 'colluder-wallet-capture':
                    actual = normalize_colluder_observation_times(actual)
                    expected_raw = normalize_colluder_observation_times(
                        expected_raw)
                self.assertEqual(actual, expected_raw)

    def test_all_three_cpp_streams_feed_complete_producer(self):
        selected = fixture.selection(); raw = fixture.streams(selected)
        projection_raw, public = projection(1)
        raw[(1, 'terminal-history')] = self.run_hook('terminal').stdout
        raw[(1, 'corrupt-server-capture')] = self.run_hook(
            'corrupt', projection_raw).stdout
        raw[(1, 'colluder-wallet-capture')] = self.run_hook('colluder').stdout
        result = producer.source_only_produce(
            selected, fixture.pipes(raw), self.root / 'capture')
        self.assertFalse(result['launch_authorized'])
        public_receipt = producer.encoded(result)
        for private_literal in (
                public['nfs_hex32'][1].encode(),
                public['tuple_sha256'][2].encode(), b'4d4153434f54'):
            self.assertNotIn(private_literal, public_receipt)
        terminal = json.loads(
            (self.root / 'capture/round-1/terminal.json').read_text())
        self.assertEqual([group['owner_component']
                          for group in terminal['groups']], [None])

    def test_missing_extra_out_of_order_and_early_close_refuse(self):
        for scenario in (
                'terminal-missing-close', 'terminal-extra-group',
                'corrupt-out-of-order', 'corrupt-early-close',
                'colluder-extra-original', 'colluder-out-of-order',
                'colluder-early-close'):
            with self.subTest(scenario=scenario):
                body = projection(1)[0] if scenario.startswith('corrupt') else b''
                result = self.run_hook(scenario, body)
                self.assertEqual(result.returncode, 78)
                self.assertEqual(result.stderr,
                                 b'KPB_CAPTURE_PRIVATE_HOOK_REFUSED\n')

    def test_wrong_fixed_fd_wrong_role_and_cross_round_replay_refuse(self):
        bad_fd = self.run_hook('wrong-fd')
        self.assertEqual((bad_fd.returncode, bad_fd.stderr),
                         (78, b'KPB_CAPTURE_PRIVATE_HOOK_REFUSED\n'))
        selected = fixture.selection()
        for name, key, stream in (
                ('wrong-role', (1, 'terminal-history'),
                 self.run_hook('colluder').stdout),
                ('cross-round', (2, 'terminal-history'),
                 self.run_hook('terminal').stdout)):
            with self.subTest(name=name):
                raw = fixture.streams(selected); raw[key] = stream
                with self.assertRaisesRegex(ValueError, 'channel-hello'):
                    producer.source_only_produce(
                        selected, fixture.pipes(raw), self.root / name)

    def test_literal_server_leak_is_retained_and_modeled(self):
        selected = fixture.selection(); raw = fixture.streams(selected)
        projection_raw, public = projection(1)
        raw[(1, 'corrupt-server-capture')] = self.run_hook(
            'corrupt-leak', projection_raw).stdout
        producer.source_only_produce(
            selected, fixture.pipes(raw), self.root / 'leak')
        corrupt_raw = (self.root /
            'leak/round-1/corrupt-server.json').read_bytes()
        modeled = capture.corrupt_server(corrupt_raw, public, projection_raw)
        self.assertTrue(modeled['constraints']['input_edges'])
        self.assertEqual(modeled['constraints']['input_edges'][0]
                         ['provenance'], 'direct-export')

    def test_retry_reject_orphan_reorg_are_captured_not_silenced(self):
        selected = fixture.selection(); raw = fixture.streams(selected)
        raw[(1, 'terminal-history')] = self.run_hook(
            'terminal-alternate-history').stdout
        producer.source_only_produce(
            selected, fixture.pipes(raw), self.root / 'alternate')
        terminal_raw = (self.root /
            'alternate/round-1/terminal.json').read_bytes()
        value = json.loads(terminal_raw)
        self.assertEqual(len(value['retry_history']), 3)
        self.assertEqual(len(value['rejected_or_orphaned']), 2)
        self.assertEqual(len(value['reorg_history']), 1)
        with self.assertRaisesRegex(ValueError,
                                    'terminal-alternate-history-unmodeled'):
            capture.terminal(terminal_raw, projection(1)[1])

    def test_colluder_retry_and_terminal_cross_link_are_retained(self):
        selected = fixture.selection()

        raw = fixture.streams(selected)
        raw[(1, 'colluder-wallet-capture')] = self.run_hook(
            'colluder-retry').stdout
        producer.source_only_produce(
            selected, fixture.pipes(raw), self.root / 'colluder-retry')
        colluder_raw = (self.root /
            'colluder-retry/round-1/colluder-wallet.json').read_bytes()
        self.assertEqual(len(json.loads(colluder_raw)['retry_history']), 1)
        modeled = capture.colluder_wallet(colluder_raw, projection(1)[1])
        self.assertEqual(modeled['inventory']['retry_count'], 1)
        self.assertIn({
            'category': 'retry-history',
            'field_path': 'retry_history[].source_and_value',
            'status': 'unmodeled', 'constraint_count': 0,
            'assumption_sha256': None,
        }, modeled['leakage_ledger'])

        raw = fixture.streams(selected)
        raw[(1, 'terminal-history')] = self.run_hook(
            'terminal-cross-link').stdout
        producer.source_only_produce(
            selected, fixture.pipes(raw), self.root / 'terminal-cross')
        terminal_raw = (self.root /
            'terminal-cross/round-1/terminal.json').read_bytes()
        modeled = capture.terminal(terminal_raw, projection(1)[1])
        self.assertEqual(len(modeled['cross_round_links']), 1)


if __name__ == '__main__':
    unittest.main()
