"""Public-seam controls for the source-only terminal capture v2 protocol."""
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

import privacy_capture_model as capture
from test_privacy_capture_model import projection


HERE = Path(__file__).absolute().parent
MAGIC = b'KPBCEV01'


def channel(raw):
    """Decode the documented append-only capture frame boundary."""
    frames = []
    offset = 0
    while offset < len(raw):
        if raw[offset:offset + 8] != MAGIC or offset + 17 > len(raw):
            raise AssertionError('bad capture frame')
        tag = raw[offset + 8]
        size = struct.unpack('>Q', raw[offset + 9:offset + 17])[0]
        offset += 17
        payload = raw[offset:offset + size]
        if len(payload) != size:
            raise AssertionError('truncated capture frame')
        offset += size
        frames.append((tag, payload))
    return frames


class TerminalCaptureV2Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_temp = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.build_temp.name) / 'terminal-v2-control'
        result = subprocess.run([
            'g++', '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread', '-DKPB_TERMINAL_CAPTURE_V2_TEST_SETUP',
            '-DKPB_TERMINAL_MAPPING_SOURCE_TEST_SETUP',
            str(HERE / 'privacy_capture_hook.cpp'),
            str(HERE / 'privacy_terminal_capture_v2.cpp'),
            str(HERE / 'native_terminal_mapping_source.cpp'),
            str(HERE / 'privacy_terminal_capture_v2_control.cpp'),
            '-lcrypto',
            '-o', str(cls.binary),
        ], text=True, capture_output=True)
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.build_temp.cleanup()

    def run_control(self, scenario):
        return subprocess.run([str(self.binary), scenario],
                              capture_output=True, check=False)

    def test_acknowledged_exact_case_resolves_before_trial_close(self):
        result = self.run_control('acknowledged')
        self.assertEqual((result.returncode, result.stderr), (0, b''))
        frames = channel(result.stdout)
        self.assertEqual([tag for tag, _ in frames],
                         [1, 2] + [3] * 11 + [5])
        hello = json.loads(frames[0][1])
        meta = json.loads(frames[1][1])
        records = [json.loads(payload) for _, payload in frames[2:-1]]
        self.assertEqual(hello['kind'], 'terminal-history-v2-control')
        projection_sha256 = meta.pop('projection_sha256')
        self.assertRegex(projection_sha256, r'^[0-9a-f]{64}$')
        self.assertEqual(meta, {
            'actual_network_execution': False,
            'actual_receipt': False,
            'amount_observations': [],
            'cohort_sha256': '31' * 32,
            'mode': 'CONFIGURED0_NETWORK_DISABLED',
            'privacy_measurement_usable': False,
            'round': 1,
            'schema': 'kpb-terminal-observer-history/v2',
            'scope': 'PAYMENT_TERMINAL_STREAM_CONTROL_ONLY',
            'status': 'UNQUALIFIED_SOURCE_ONLY',
        })
        events = [row['value'] for row in records
                  if row['stream'] == 'event']
        self.assertEqual([row['kind'] for row in events], [
            'candidate-constructed', 'r0-verified', 'native-full-verified',
            'durable-final', 'testnet-submit-attempted',
            'testnet-submit-acknowledged', 'accepted-case',
            'durable-settlement-resolved', 'trial-closed',
        ])
        self.assertEqual([row['sequence'] for row in events], list(range(9)))
        self.assertEqual({row['candidate_sha256'] for row in events},
                         {'44' * 32})
        self.assertEqual({row['case_sha256'] for row in events}, {'45' * 32})
        self.assertEqual({row['projection_sha256'] for row in events},
                         {projection_sha256})
        txids = [row['transaction_id_hex32'] for row in events]
        self.assertEqual(txids[:4], [None] * 4)
        self.assertEqual(txids[4:], ['49' * 32] * 5)
        groups = [row['value'] for row in records
                  if row['stream'] == 'group']
        self.assertEqual((len(groups[0]['nfs_hex32']),
                          len(groups[0]['tuple_sha256'])), (3, 6))
        self.assertEqual(groups[0]['projection_sha256'], projection_sha256)
        self.assertNotIn('owner_component', groups[0])
        self.assertTrue(groups[0]['owner_component_absent'])
        self.assertTrue(groups[0]['source_complete'])
        self.assertFalse(groups[0]['privacy_measurement_usable'])
        links = [row['value'] for row in records
                 if row['stream'] == 'cross-round-link']
        self.assertEqual(links, [])
        mapping = [row['value'] for row in records
                   if row['stream'] == 'mapping-complete']
        self.assertEqual(len(mapping), 1)
        self.assertEqual(mapping[0][
            'cross_round_owner_nf_tuple_export_count'], 0)
        self.assertTrue(mapping[0][
            'cross_round_owner_nf_tuple_exports_source_complete'])
        self.assertTrue(mapping[0]['grouping_source_complete'])
        self.assertFalse(mapping[0]['owner_component_present'])
        self.assertTrue(mapping[0]['public_continuity_modeled_separately'])
        self.assertNotIn('cross_round_links_source_complete', mapping[0])

    def test_pre_network_branch_closes_after_durable_final_without_submit(self):
        result = self.run_control('pre-network-close')
        self.assertEqual((result.returncode, result.stderr), (0, b''))
        frames = channel(result.stdout)
        self.assertEqual(frames[-1], (5, b''))
        events = [json.loads(payload)['value'] for tag, payload in frames
                  if tag == 3 and json.loads(payload)['stream'] == 'event']
        self.assertEqual([row['kind'] for row in events], [
            'candidate-constructed', 'r0-verified',
            'native-full-verified', 'durable-final',
            'pre-network-capture-closed'])
        self.assertNotIn('testnet-submit-attempted',
                         [row['kind'] for row in events])

    def test_pre_network_close_token_is_one_shot_and_requires_mapping_source(self):
        replay = self.run_control('pre-network-replay')
        self.assertEqual(
            (replay.returncode, replay.stderr),
            (78, b'KPB_TERMINAL_CAPTURE_V2_REFUSED\n'))
        self.assertEqual(channel(replay.stdout)[-1], (5, b''))
        no_link = self.run_control('pre-network-no-mapping')
        self.assertEqual(
            (no_link.returncode, no_link.stderr),
            (78, b'KPB_TERMINAL_CAPTURE_V2_REFUSED\n'))
        self.assertNotEqual(channel(no_link.stdout)[-1][0], 5)

    def test_mapping_source_is_one_shot_and_exactly_lineage_bound(self):
        for scenario in (
                'mapping-replay', 'mapping-wrong-body',
                'mapping-empty-commitment',
                'mapping-wrong-plan',
                'mapping-wrong-construction-attempt',
                'mapping-candidate-covert-owner',
                'mapping-baseline-zero-owner',
                'mapping-baseline-duplicate-owner'):
            with self.subTest(scenario=scenario):
                result = self.run_control(scenario)
                self.assertEqual(
                    (result.returncode, result.stderr),
                    (78, b'KPB_TERMINAL_CAPTURE_V2_REFUSED\n'))

    def test_private_route_lineage_does_not_label_public_groups_but_rows_do(self):
        def group(scenario):
            result = self.run_control(scenario)
            self.assertEqual((result.returncode, result.stderr), (0, b''))
            records = [json.loads(payload) for tag, payload in
                       channel(result.stdout) if tag == 3]
            groups = [row['value'] for row in records
                      if row['stream'] == 'group']
            self.assertEqual(len(groups), 1)
            return groups[0]

        first = group('group-id-origin-1')
        second = group('group-id-origin-2')
        changed = group('group-id-row-changed')
        self.assertEqual(first['group_id_sha256'],
                         second['group_id_sha256'])
        self.assertEqual(first['nfs_hex32'], second['nfs_hex32'])
        self.assertEqual(first['tuple_sha256'], second['tuple_sha256'])
        self.assertNotEqual(first['group_id_sha256'],
                            changed['group_id_sha256'])
        self.assertNotEqual(first['tuple_sha256'],
                            changed['tuple_sha256'])

    def test_wrong_projection_refuses_before_r0_event(self):
        result = self.run_control('wrong-projection')
        self.assertEqual((result.returncode, result.stderr),
                         (78, b'KPB_TERMINAL_CAPTURE_V2_REFUSED\n'))
        frames = channel(result.stdout)
        self.assertEqual([tag for tag, _ in frames], [1, 2, 3])
        record = json.loads(frames[-1][1])
        self.assertEqual(record['value']['kind'], 'candidate-constructed')

    def test_wrong_case_refuses_before_native_full_event(self):
        result = self.run_control('wrong-case')
        self.assertEqual((result.returncode, result.stderr),
                         (78, b'KPB_TERMINAL_CAPTURE_V2_REFUSED\n'))
        records = [json.loads(payload) for tag, payload in
                   channel(result.stdout) if tag == 3]
        self.assertEqual([row['value']['kind'] for row in records],
                         ['candidate-constructed', 'r0-verified'])

    def test_r0_stage_cannot_be_replayed_out_of_order(self):
        result = self.run_control('r0-replayed')
        self.assertEqual((result.returncode, result.stderr),
                         (78, b'KPB_TERMINAL_CAPTURE_V2_REFUSED\n'))
        records = [json.loads(payload) for tag, payload in
                   channel(result.stdout) if tag == 3]
        self.assertEqual([row['value']['kind'] for row in records],
                         ['candidate-constructed', 'r0-verified'])

    def test_native_full_stage_cannot_be_replayed_out_of_order(self):
        result = self.run_control('native-full-replayed')
        self.assertEqual((result.returncode, result.stderr),
                         (78, b'KPB_TERMINAL_CAPTURE_V2_REFUSED\n'))
        records = [json.loads(payload) for tag, payload in
                   channel(result.stdout) if tag == 3]
        self.assertEqual([row['value']['kind'] for row in records], [
            'candidate-constructed', 'r0-verified', 'native-full-verified'])

    def test_duplicate_submit_refuses_without_second_attempt(self):
        result = self.run_control('duplicate-submit')
        self.assertEqual((result.returncode, result.stderr),
                         (78, b'KPB_TERMINAL_CAPTURE_V2_REFUSED\n'))
        frames = channel(result.stdout)
        self.assertNotEqual(frames[-1][0], 5)
        events = [json.loads(payload)['value'] for tag, payload in frames
                  if tag == 3 and json.loads(payload)['stream'] == 'event']
        self.assertEqual([row['kind'] for row in events].count(
                         'testnet-submit-attempted'), 1)

    def test_unknown_submit_is_terminal_and_cannot_retransmit(self):
        result = self.run_control('unknown-no-retransmit')
        self.assertEqual((result.returncode, result.stderr),
                         (78, b'KPB_TERMINAL_CAPTURE_V2_REFUSED\n'))
        frames = channel(result.stdout)
        self.assertEqual(frames[-1], (5, b''))
        events = [json.loads(payload)['value'] for tag, payload in frames
                  if tag == 3 and json.loads(payload)['stream'] == 'event']
        self.assertEqual([row['kind'] for row in events][-2:],
                         ['testnet-submit-attempted',
                          'testnet-submit-unknown'])
        self.assertNotIn('testnet-submit-acknowledged',
                         [row['kind'] for row in events])
        self.assertNotIn('trial-closed', [row['kind'] for row in events])
        self.assertEqual(events[-1]['transaction_id_hex32'], '49' * 32)

    def test_submit_acknowledgement_txid_mismatch_refuses(self):
        result = self.run_control('txid-mismatch')
        self.assertEqual((result.returncode, result.stderr),
                         (78, b'KPB_TERMINAL_CAPTURE_V2_REFUSED\n'))
        frames = channel(result.stdout)
        self.assertNotEqual(frames[-1][0], 5)
        events = [json.loads(payload)['value'] for tag, payload in frames
                  if tag == 3 and json.loads(payload)['stream'] == 'event']
        self.assertEqual(events[-1]['kind'], 'testnet-submit-attempted')
        self.assertNotIn('testnet-submit-acknowledged',
                         [row['kind'] for row in events])

    def test_accepted_case_must_be_the_exact_constructed_case(self):
        result = self.run_control('accepted-case-mismatch')
        self.assertEqual((result.returncode, result.stderr),
                         (78, b'KPB_TERMINAL_CAPTURE_V2_REFUSED\n'))
        frames = channel(result.stdout)
        self.assertNotEqual(frames[-1][0], 5)
        events = [json.loads(payload)['value'] for tag, payload in frames
                  if tag == 3 and json.loads(payload)['stream'] == 'event']
        self.assertEqual(events[-1]['kind'],
                         'testnet-submit-acknowledged')
        self.assertNotIn('accepted-case', [row['kind'] for row in events])

    def test_reorg_and_orphan_evidence_are_closed_before_refusal(self):
        result = self.run_control('reorg-before-refusal')
        self.assertEqual((result.returncode, result.stderr),
                         (78, b'KPB_TERMINAL_CAPTURE_V2_REFUSED\n'))
        frames = channel(result.stdout)
        self.assertEqual(frames[-1], (5, b''))
        records = [json.loads(payload) for tag, payload in frames if tag == 3]
        self.assertEqual([row['stream'] for row in records][-3:],
                         ['reorg', 'rejected-or-orphaned', 'event'])
        self.assertEqual(records[-2]['value']['status'], 'orphaned')
        self.assertEqual(records[-1]['value']['kind'],
                         'accepted-case-orphaned')
        kinds = [row['value']['kind'] for row in records
                 if row['stream'] == 'event']
        self.assertNotIn('durable-settlement-resolved', kinds)
        self.assertNotIn('trial-closed', kinds)

    def test_rejected_submit_evidence_is_closed_before_refusal(self):
        result = self.run_control('rejected-before-refusal')
        self.assertEqual((result.returncode, result.stderr),
                         (78, b'KPB_TERMINAL_CAPTURE_V2_REFUSED\n'))
        frames = channel(result.stdout)
        self.assertEqual(frames[-1], (5, b''))
        records = [json.loads(payload) for tag, payload in frames if tag == 3]
        self.assertEqual([row['stream'] for row in records][-2:],
                         ['rejected-or-orphaned', 'event'])
        self.assertEqual(records[-2]['value']['status'], 'rejected')
        self.assertEqual(records[-1]['value']['kind'],
                         'testnet-submit-rejected')

    def test_orphaned_accepted_case_is_closed_before_refusal(self):
        result = self.run_control('orphaned-before-refusal')
        self.assertEqual((result.returncode, result.stderr),
                         (78, b'KPB_TERMINAL_CAPTURE_V2_REFUSED\n'))
        frames = channel(result.stdout)
        self.assertEqual(frames[-1], (5, b''))
        records = [json.loads(payload) for tag, payload in frames if tag == 3]
        self.assertNotIn('reorg', [row['stream'] for row in records])
        self.assertEqual([row['stream'] for row in records][-2:],
                         ['rejected-or-orphaned', 'event'])
        self.assertEqual(records[-2]['value']['status'], 'orphaned')
        self.assertEqual(records[-1]['value']['kind'],
                         'accepted-case-orphaned')

    def test_unfunded_native_full_cannot_close_trial(self):
        result = self.run_control('premature-close-after-native-full')
        self.assertEqual((result.returncode, result.stderr),
                         (78, b'KPB_TERMINAL_CAPTURE_V2_REFUSED\n'))
        frames = channel(result.stdout)
        self.assertNotEqual(frames[-1][0], 5)
        events = [json.loads(payload)['value'] for tag, payload in frames
                  if tag == 3 and json.loads(payload)['stream'] == 'event']
        self.assertEqual(events[-1]['kind'], 'native-full-verified')
        self.assertNotIn('durable-final', [row['kind'] for row in events])
        self.assertNotIn('trial-closed', [row['kind'] for row in events])

    def test_accepted_case_without_resolve_cannot_close_trial(self):
        result = self.run_control('premature-close-after-accepted-case')
        self.assertEqual((result.returncode, result.stderr),
                         (78, b'KPB_TERMINAL_CAPTURE_V2_REFUSED\n'))
        frames = channel(result.stdout)
        self.assertNotEqual(frames[-1][0], 5)
        events = [json.loads(payload)['value'] for tag, payload in frames
                  if tag == 3 and json.loads(payload)['stream'] == 'event']
        self.assertEqual(events[-1]['kind'], 'accepted-case')
        self.assertNotIn('durable-settlement-resolved',
                         [row['kind'] for row in events])
        self.assertNotIn('trial-closed', [row['kind'] for row in events])

    def test_configured0_v2_cannot_feed_the_actual_privacy_model(self):
        _, public = projection(1)
        value = {
            'schema': 'kpb-terminal-observer-history/v2',
            'mode': 'CONFIGURED0_NETWORK_DISABLED',
        }
        raw = (json.dumps(value, sort_keys=True, separators=(',', ':'))
               + '\n').encode()
        with self.assertRaisesRegex(
                ValueError,
                'privacy-capture-terminal-v2-configured0-control-not-evidence'):
            capture.terminal(raw, public)


if __name__ == '__main__':
    unittest.main()
