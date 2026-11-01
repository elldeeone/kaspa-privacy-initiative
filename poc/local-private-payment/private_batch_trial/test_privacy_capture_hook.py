"""Compile and exercise the non-activating C++ capture-hook seam."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import struct
import tempfile
import unittest

import privacy_capture_producer as producer
import privacy_capture_model as capture
import test_privacy_capture_producer as fixture
from test_privacy_capture_model import dispatcher_fixture, projection


HERE = Path(__file__).absolute().parent


def frame_tags(raw):
    result = []
    while raw:
        if len(raw) < 17 or raw[:8] != b'KPBCEV01':
            raise AssertionError('invalid independent frame')
        size = struct.unpack('>Q', raw[9:17])[0]
        if len(raw) < 17 + size:
            raise AssertionError('truncated independent frame')
        result.append(raw[8]); raw = raw[17 + size:]
    return result


def frames(raw):
    result = []
    while raw:
        if len(raw) < 17 or raw[:8] != b'KPBCEV01':
            raise AssertionError('invalid independent frame')
        size = struct.unpack('>Q', raw[9:17])[0]
        if len(raw) < 17 + size:
            raise AssertionError('truncated independent frame')
        result.append((raw[8], raw[17:17 + size]))
        raw = raw[17 + size:]
    return result


def release_policy_preimage(metadata, event, explicit_event=None):
    policy = metadata['release_order_policy']
    classification = metadata['construction_classification']
    code = {'SECRET_PERMUTATION_INDEPENDENT': 1,
            'EXPLICIT_OWNER_PUBLIC_EFFECTS': 2}[policy]
    exports = 0 if code == 1 else 3
    result = bytearray(b'KPB_DISPATCHER_RELEASE_POLICY_BINDING_V1\n')
    result.extend(struct.pack('<QQQQ', classification, code,
                              metadata['round'], exports))
    for name in ('run_sha256', 'construction_attempt_sha256',
                 'cohort_sha256', 'capture_plan_sha256',
                 'projection_sha256'):
        result.extend(bytes.fromhex(metadata[name]))
    result.extend(bytes(32) if explicit_event is None else
                  bytes.fromhex(explicit_event['public_sha256']))
    if len(result) != event['bytes']:
        raise AssertionError('release-policy-preimage-size')
    return bytes(result)


class CaptureHookControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_temp = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.build_temp.name) / 'capture-hook-control'
        command = [
            'g++', '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread', str(HERE / 'privacy_capture_hook.cpp'),
            str(HERE / 'privacy_capture_hook_control.cpp'), '-lcrypto', '-o',
            str(cls.binary),
        ]
        result = subprocess.run(command, text=True, capture_output=True)
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.build_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def run_hook(self, scenario, body=b''):
        return subprocess.run([str(self.binary), scenario], input=body,
                              capture_output=True, check=False)

    def expected_dispatcher(self, selected):
        _, public = projection(1)
        value = copy.deepcopy(dispatcher_fixture(public))
        value['cohort_sha256'] = selected['rounds'][0]['cohort_sha256']
        return fixture.channel(1, 'dispatcher-capture', selected, value)

    def test_real_cpp_projection_and_dispatcher_streams_are_exact(self):
        selected = fixture.selection(); projection_raw, _ = projection(1)
        projected = self.run_hook('projection', projection_raw)
        dispatched = self.run_hook('dispatcher')
        self.assertEqual((projected.returncode, projected.stderr), (0, b''))
        self.assertEqual((dispatched.returncode, dispatched.stderr), (0, b''))
        self.assertEqual(projected.stdout, fixture.channel(
            1, 'public-projection', selected, projection_raw))
        self.assertEqual(dispatched.stdout, self.expected_dispatcher(selected))

    def test_deferred_live_dispatcher_seals_to_exact_projection(self):
        selected = fixture.selection()
        immediate = self.run_hook('dispatcher')
        deferred = self.run_hook('deferred-dispatcher')
        self.assertEqual((deferred.returncode, deferred.stderr), (0, b''))
        self.assertEqual(deferred.stdout, immediate.stdout)
        self.assertEqual(frame_tags(deferred.stdout),
                         [1, 2] + [3] * 10 + [5])

        decoded = frames(deferred.stdout)
        metadata = json.loads(next(body for tag, body in decoded if tag == 2))
        events = [json.loads(body)['value'] for tag, body in decoded
                  if tag == 3]
        policy = next(row for row in events
                      if row['kind'] == 'release-policy-bound')
        self.assertEqual(metadata['construction_classification'], 1)
        self.assertEqual(metadata['direct_exports'], [])
        self.assertEqual(policy['bytes'], 265)
        self.assertEqual(policy['filename'],
                         'RELEASE-ORDER-POLICY-V1.bin')
        self.assertEqual(policy['public_sha256'], hashlib.sha256(
            release_policy_preimage(metadata, policy)).hexdigest())

    def test_dispatcher_cannot_release_before_projection_seal(self):
        result = self.run_hook('missing-projection')
        self.assertEqual(result.returncode, 78)
        self.assertEqual(result.stderr, b'KPB_CAPTURE_HOOK_REFUSED\n')
        self.assertEqual(frame_tags(result.stdout), [1])

    def test_explicit_baseline_exports_exact_public_mapping_once(self):
        result = self.run_hook('explicit-dispatcher')
        self.assertEqual((result.returncode, result.stderr), (0, b''))
        decoded = frames(result.stdout)
        self.assertEqual([tag for tag, _ in decoded],
                         [1, 2] + [3] * 11 + [5])
        metadata = json.loads(next(body for tag, body in decoded if tag == 2))
        self.assertEqual(metadata['construction_classification'], 2)
        self.assertEqual(metadata['release_order_policy'],
                         'EXPLICIT_OWNER_PUBLIC_EFFECTS')
        self.assertEqual([row['owner_component']
                          for row in metadata['direct_exports']], [0, 1, 2])
        self.assertEqual(set(metadata['direct_exports'][0]), {
            'owner_component', 'owner_contract_sha256', 'nf_hex32',
            'tuple_sha256', 'run_sha256', 'trial_sha256', 'attempt_sha256',
            'cohort_sha256', 'capture_plan_sha256', 'projection_sha256',
            'context_sha256'})
        events = [json.loads(body)['value'] for tag, body in decoded if tag == 3]
        explicit = [row for row in events
                    if row['kind'] == 'explicit-owner-public-effects']
        policy = [row for row in events
                  if row['kind'] == 'release-policy-bound']
        self.assertEqual(len(explicit), 1)
        self.assertEqual(len(policy), 1)
        self.assertEqual(explicit[0]['bytes'], 693)
        self.assertEqual(explicit[0]['filename'],
                         'EXPLICIT-OWNER-PUBLIC-EFFECTS-V1.bin')
        self.assertRegex(explicit[0]['public_sha256'], r'^[0-9a-f]{64}$')
        self.assertEqual(policy[0]['bytes'], 265)
        self.assertEqual(policy[0]['public_sha256'], hashlib.sha256(
            release_policy_preimage(metadata, policy[0], explicit[0])
        ).hexdigest())
        self.assertLess([row['kind'] for row in events].index(
                            'aggregate-release'),
                        [row['kind'] for row in events].index(
                            'explicit-owner-public-effects'))
        self.assertLess([row['kind'] for row in events].index(
                            'explicit-owner-public-effects'),
                        [row['kind'] for row in events].index(
                            'release-policy-bound'))
        self.assertLess([row['kind'] for row in events].index(
                            'release-policy-bound'),
                        [row['kind'] for row in events].index(
                            'outbound-route'))
        # Private session/certificate/path/body identities never enter the
        # intended public observer leaf.
        text = result.stdout.decode('utf-8', errors='ignore')
        for forbidden in ('logical_owner', 'certificate', 'path_sha256',
                          'body_sha256', 'authenticated_session'):
            self.assertNotIn(forbidden, text)

    def test_explicit_mapping_is_policy_bound_ordered_and_one_shot(self):
        for scenario in ('explicit-on-secret-policy',
                         'missing-explicit-before-route',
                         'duplicate-explicit', 'reversed-explicit-pair',
                         'wrong-explicit-attempt',
                         'wrong-explicit-capture-plan',
                         'hidden-binding-explicit-policy',
                         'baseline-binding-secret-policy'):
            with self.subTest(scenario=scenario):
                result = self.run_hook(scenario)
                self.assertEqual(result.returncode, 78)
                self.assertEqual(result.stderr,
                                 b'KPB_CAPTURE_HOOK_REFUSED\n')

    def test_cpp_streams_feed_the_complete_python_producer(self):
        selected = fixture.selection(); raw = fixture.streams(selected)
        projection_raw, _ = projection(1)
        raw[(1, 'public-projection')] = self.run_hook(
            'projection', projection_raw).stdout
        raw[(1, 'dispatcher-capture')] = self.run_hook('dispatcher').stdout
        result = producer.source_only_produce(
            selected, fixture.pipes(raw), self.root / 'capture')
        self.assertEqual(result['status'], 'UNQUALIFIED_SOURCE_ONLY')
        self.assertFalse(result['launch_authorized'])
        self.assertEqual(producer.verify_source_only(
            self.root / 'capture', fixture.selection()), result)

    def test_cpp_explicit_leaf_cannot_replace_source_owned_model_authority(self):
        selected = fixture.selection()
        selected['classification'] = 'ACTUAL_TRANSPARENT_BASELINE'
        raw_streams = fixture.streams(selected)
        raw_streams[(1, 'dispatcher-capture')] = self.run_hook(
            'explicit-dispatcher').stdout
        producer.source_only_produce(
            selected, fixture.pipes(raw_streams), self.root / 'explicit')
        _, public = projection(1)
        modeled = capture.dispatcher(
            (self.root / 'explicit' / 'round-1' / 'dispatcher.json').read_bytes(),
            public)
        self.assertEqual(modeled['inventory']['release_order_policy'],
                         'EXPLICIT_OWNER_PUBLIC_EFFECTS')
        self.assertFalse(
            modeled['inventory']['source_bound_policy_authority'])
        self.assertEqual(
            modeled['inventory']['release_policy_binding_count'], 0)
        self.assertEqual(
            modeled['inventory']['direct_constraint_count'], 0)
        for name in ('input_edges', 'creator_edges', 'nf_pair_edges'):
            self.assertEqual(modeled['constraints'][name], [])
        policy_ledger = [row for row in modeled['leakage_ledger']
                         if row['field_path'] ==
                         'release_order_policy_and_direct_exports']
        self.assertEqual(len(policy_ledger), 1)
        self.assertEqual(policy_ledger[0]['status'], 'unmodeled')

    def test_wrong_fixed_fd_and_protocol_order_refuse(self):
        for scenario in ('wrong-fd', 'wrong-order'):
            with self.subTest(scenario=scenario):
                result = self.run_hook(scenario)
                self.assertEqual(result.returncode, 78)
                self.assertEqual(result.stderr,
                                 b'KPB_CAPTURE_HOOK_REFUSED\n')

    def test_wrong_role_and_truncation_are_rejected_by_producer(self):
        selected = fixture.selection()
        wrong_role = self.run_hook('dispatcher').stdout
        truncated = self.run_hook('projection', projection(1)[0]).stdout[:-3]
        for name, key, stream in (
                ('wrong-role', (1, 'public-projection'), wrong_role),
                ('truncated', (1, 'public-projection'), truncated)):
            with self.subTest(name=name):
                raw = fixture.streams(selected); raw[key] = stream
                with self.assertRaises((ValueError, EOFError)):
                    producer.source_only_produce(
                        selected, fixture.pipes(raw), self.root / name)

    def test_duplicate_end_and_post_end_extra_event_refuse(self):
        for scenario in ('duplicate-end', 'extra-event'):
            with self.subTest(scenario=scenario):
                result = self.run_hook(scenario)
                self.assertEqual(result.returncode, 78)
                self.assertEqual(result.stderr,
                                 b'KPB_CAPTURE_HOOK_REFUSED\n')
                tags = frame_tags(result.stdout)
                self.assertEqual(tags.count(5), 1)
                self.assertEqual(tags[-1], 5)

    def test_unavailable_consumer_refuses_without_sigpipe_exit(self):
        result = self.run_hook('unavailable-consumer')
        self.assertEqual(result.returncode, 78)
        self.assertEqual(result.stderr, b'KPB_CAPTURE_HOOK_REFUSED\n')


if __name__ == '__main__':
    unittest.main()
