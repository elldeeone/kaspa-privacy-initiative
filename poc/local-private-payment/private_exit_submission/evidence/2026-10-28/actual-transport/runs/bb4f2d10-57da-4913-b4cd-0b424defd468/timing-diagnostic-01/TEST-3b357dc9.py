"""PUBLIC FIXTURES ONLY; no Tor, packet/proof, key or private-state inputs.

The exact public diagnostic is admitted through the externally pinned stdlib
bootstrap before its pure functions are executed. All events/truth below are
deliberately public synthetic values, not Tor13's actual metadata or a privacy
measurement. Runtime, transport, capture and private-role code is never run.
"""
import copy
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
SOURCE = ROOT / '.local/private-exit-submission-proposal-01/timing_diagnostic.py'
SOURCE_SHA = '077e2979541ae839582d0d1c5d9d9d993b4b010797f60b36c25f690a5feef3da'
BOOTSTRAP = ROOT / 'poc/local-private-payment/private_batch_trial/payout_linkage_guard.py'
BOOTSTRAP_SHA = 'ce86998d7ddfe404cc1c194cda064d369ca1bd78c8df674e43b2381da1d3a4b1'


def admitted_diagnostic():
    # The initial entry/bootstrap are the externally selected trust roots. No
    # retained helper or project body runs before its added-root inventory.
    info = BOOTSTRAP.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
    assert not any(path.is_symlink() for path in (BOOTSTRAP, *BOOTSTRAP.parents))
    raw = BOOTSTRAP.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == BOOTSTRAP_SHA
    guard = types.ModuleType('timing_fixture_guard')
    guard.__file__ = str(BOOTSTRAP)
    sys.modules[guard.__name__] = guard
    exec(compile(raw, str(BOOTSTRAP), 'exec'), guard.__dict__)
    raw = guard.load_guard()['read'](SOURCE, SOURCE_SHA)
    module = types.ModuleType('admitted_public_timing_diagnostic')
    module.__file__ = str(SOURCE)
    sys.modules[module.__name__] = module
    exec(compile(raw, str(SOURCE), 'exec'), module.__dict__)
    return module


def windows(bounds):
    return [{'client': client, 'lower_ns': lower, 'upper_ns': upper}
            for client, (lower, upper) in enumerate(bounds)]


def arrivals(stamps):
    return [{'ordinal': index + 1, 'post_handler_monotonic_ns': stamp}
            for index, stamp in enumerate(stamps)]


def fixture_events(bounds=((0, 30), (0, 30), (40, 60))):
    """A complete synthetic typed event stream, with queue-observed statuses."""
    result = []
    for client, (lower, upper) in enumerate(bounds):
        role = 'transport-' + str(client)
        result.extend([
            {'kind': 'pipe-created', 'client': client, 'monotonic_ns': lower - 1,
             'pipe_inode': 9000 + client, 'read_fd': 20 + 2 * client,
             'write_fd': 21 + 2 * client},
            {'kind': 'launch', 'role': role, 'started_ns': lower,
             'monotonic_ns': lower + 1, 'pid': 5000 + client},
            {'kind': 'pipe-write-start', 'client': client, 'monotonic_ns': lower + 2},
            {'kind': 'pipe-write-complete', 'client': client,
             'monotonic_ns': lower + 3, 'bytes': 4096},
            {'kind': 'role-exit', 'role': role, 'monotonic_ns': upper - 1,
             'returncode': 0},
            {'kind': 'role-status', 'role': role, 'monotonic_ns': upper,
             'value': {'schema': 'kpb-exit-transport-status/v1',
                       'transport_receipt': True, 'financial_or_chain_acceptance': False}},
        ])
    # This sort permits overlapping client windows without inventing globally
    # decreasing observer timestamps. Stable ties retain each pipe's causality.
    return sorted(result, key=lambda event: event['monotonic_ns'])


def find_event(events, kind, client):
    return next(event for event in events if event['kind'] == kind
                and event.get('role', 'transport-' + str(event.get('client'))) == 'transport-' + str(client))


def fixture_exports(module, stamps=(10, 20, 50)):
    common = {
        'trial_id': module.RUN_ID, 'clock_qualified': False,
        'privacy_or_financial_qualification': False,
        'source_events_sha256': module.EVENTS_SHA,
        'source_received_sha256': module.RECEIVED_SHA,
        'source_fixture_selection_sha256': module.FIXTURE_SHA,
        'source_launcher_sha256': module.LAUNCHER_SHA,
        'source_receiver_sha256': module.RECEIVER_SHA,
    }
    records = []
    for index, stamp in enumerate(stamps):
        records.append({
            'schema': 'kpb-exit-transport-arrival/v1', 'arrival_sequence': index + 1,
            'received_body_bytes': 4096, 'http_status': 202, 'framing': 'PASS',
            'broadcast': False, 'financial_validation': 'NOT_RUN',
            'accepted_monotonic_ns': stamp - 2, 'handler_monotonic_ns': stamp - 1,
            'post_handler_monotonic_ns': stamp,
            # Deliberately later than all client202 observations: this field
            # must not be substituted for the source's pre-body POST event.
            'recorded_monotonic_ns': stamp + 1000,
        })
    clock = dict(common, schema='kpb-public-receiver-clock-only-export/v1', records=records,
                 source_clock_facts={'time_namespace_ids_captured': False,
                                     'calibration_receipt_captured': False,
                                     'scope': 'PUBLIC_SYNTHETIC_FIXTURE'})
    truth = dict(common, schema='kpb-public-fixture-arrival-client-mapping/v1',
                 mapping=[{'public_fixture_client_index': client, 'arrival_sequence': client + 1}
                          for client in range(3)])
    return clock, truth


class TimingDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = admitted_diagnostic()

    def test_all_bijections_and_order_invariance_preserve_ambiguity(self):
        w = windows(((0, 30), (0, 30), (40, 60)))
        a = arrivals((10, 20, 50))
        result = self.module.enumerate_models(w, a, (0, 0))
        self.assertEqual(result['models'], [[1, 2, 3], [2, 1, 3]])
        self.assertEqual(result['candidate_counts'], [2, 2, 1])
        self.assertEqual(self.module.enumerate_models(w[::-1], a[::-1], (0, 0)), result)

    def test_one_shared_offset_prevents_factorized_false_models(self):
        w = windows(((0, 5), (100, 105), (200, 205)))
        a = arrivals((10, 110, 210))
        # Each of the nine individual edges admits some offset in this range;
        # only one whole matching admits ONE offset shared by all three edges.
        for row in w:
            for arrival in a:
                lower = arrival['post_handler_monotonic_ns'] - row['upper_ns']
                upper = arrival['post_handler_monotonic_ns'] - row['lower_ns']
                self.assertLessEqual(max(-200, lower), min(220, upper))
        result = self.module.enumerate_models(w, a, (-200, 220))
        self.assertEqual(result['models'], [[1, 2, 3]])
        self.assertEqual(result['model_shared_offset_ranges_ns'], [{'lower_ns': 5, 'upper_ns': 10}])
        excluded = self.module.enumerate_models(w, a, (0, 0))
        self.assertEqual(excluded['models'], [])
        empty_score = self.module.score_models(excluded, {0: 1, 1: 2, 2: 3})
        self.assertFalse(empty_score['public_truth_retained'])
        self.assertEqual(empty_score['correct_unique'], 0)
        self.assertEqual(empty_score['wrong_unique'], 0)
        self.assertTrue(all(row['candidate_count'] == 0 and row['rank_interval'] is None
                            and row['ordinal_tie_rank'] is None for row in empty_score['ranks']))

    def test_large_integer_nanoseconds_and_malformed_inputs(self):
        base = 10**20
        w = windows(((base, base + 5), (base + 100, base + 105), (base + 200, base + 205)))
        a = arrivals((base + 3, base + 103, base + 203))
        self.assertEqual(self.module.enumerate_models(w, a, (0, 0))['models'], [[1, 2, 3]])
        for bad in (True, 1.25, '3'):
            with self.subTest(timestamp=bad):
                changed = copy.deepcopy(a)
                changed[0]['post_handler_monotonic_ns'] = bad
                with self.assertRaisesRegex(ValueError, 'integer-nanoseconds'):
                    self.module.enumerate_models(w, changed, (0, 0))
        for offset in ((10, 5), (0,), (False, 5)):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.module.enumerate_models(w, a, offset)
        changed = copy.deepcopy(w)
        changed[0].update(lower_ns=9, upper_ns=8)
        with self.assertRaisesRegex(ValueError, 'causal-host-window'):
            self.module.enumerate_models(changed, a, (0, 0))

    def test_extract_uses_pre_Popen_and_delayed_typed202_observation(self):
        events = fixture_events()
        result = self.module.extract_windows(events)
        self.assertEqual([(row['lower_ns'], row['upper_ns']) for row in result],
                         [(0, 30), (0, 30), (40, 60)])
        self.assertEqual(result[0]['post_Popen_launch_event_ns'], 1)
        self.assertEqual(result[0]['observed_launcher_pid'], 5000)
        self.assertFalse(result[0]['inner_transport_or_curl_pid_observed'])
        self.assertEqual(result[0]['pipe_inode'], 9000)
        # A parent can notice a completed202 arbitrarily late. That may widen
        # compatible models, never justify sharpening by a guessed queue delay.
        short = fixture_events(((0, 15), (0, 30), (40, 60)))
        first = self.module.enumerate_models(self.module.extract_windows(short), arrivals((10, 20, 50)), (0, 0))
        wide = self.module.enumerate_models(result, arrivals((10, 20, 50)), (0, 0))
        self.assertEqual(first['compatible_bijections'], 1)
        self.assertEqual(wide['compatible_bijections'], 2)
        self.assertTrue(set(map(tuple, first['models'])) <= set(map(tuple, wide['models'])))

    def test_post_Popen_and_post_response_values_cannot_tighten_interval(self):
        w = windows(((0, 20), (40, 60), (80, 100)))
        w[0]['post_Popen_launch_event_ns'] = 10
        a = arrivals((5, 50, 90))
        a[0]['recorded_monotonic_ns'] = 30
        result = self.module.enumerate_models(w, a, (0, 0))
        self.assertEqual(result['models'], [[1, 2, 3]])
        incorrect = copy.deepcopy(w)
        incorrect[0]['lower_ns'] = w[0]['post_Popen_launch_event_ns']
        self.assertEqual(self.module.enumerate_models(incorrect, a, (0, 0))['models'], [])

    def test_failed_missing_ACK_and_missing_lower_remain_unbounded(self):
        for mutation in ('failed_exit', 'no_receipt', 'no_status', 'no_lower'):
            with self.subTest(mutation=mutation):
                events = fixture_events()
                if mutation == 'failed_exit':
                    find_event(events, 'role-exit', 0)['returncode'] = 1
                elif mutation == 'no_receipt':
                    find_event(events, 'role-status', 0)['value']['transport_receipt'] = False
                elif mutation == 'no_status':
                    events.remove(find_event(events, 'role-status', 0))
                else:
                    del find_event(events, 'launch', 0)['started_ns']
                result = self.module.extract_windows(events)[0]
                if mutation == 'no_lower':
                    self.assertIsNone(result['lower_ns'])
                    self.assertIsNone(result['spawn_observation_gap_ns'])
                else:
                    self.assertIsNone(result['upper_ns'])
                    self.assertFalse(result['typed_202_and_exit0'])
        unbounded = windows(((0, None), (0, 30), (40, 60)))
        result = self.module.enumerate_models(unbounded, arrivals((20, 50, 1000)), (0, 0))
        self.assertEqual(result['models'], [[3, 1, 2]])

    def test_malformed_duplicate_missing_and_untrusted_role_events_refuse(self):
        mutations = (
            ('duplicate_launch', 'exact-launch-exit-status'),
            ('missing_pipe', 'complete-public-pipe-events'),
            ('short_pipe', 'actual-pipe-before-launch-write-order'),
            ('extra_status', 'finite-transport-status'),
            ('acceptance_status', 'transport-only-status'),
            ('backdated_lower', 'pre-Popen-not-later'),
        )
        for mutation, category in mutations:
            with self.subTest(mutation=mutation):
                events = fixture_events()
                if mutation == 'duplicate_launch':
                    events.append(copy.deepcopy(find_event(events, 'launch', 0)))
                elif mutation == 'missing_pipe':
                    events.remove(find_event(events, 'pipe-write-complete', 0))
                elif mutation == 'short_pipe':
                    find_event(events, 'pipe-write-complete', 0)['bytes'] = 4095
                elif mutation == 'extra_status':
                    find_event(events, 'role-status', 0)['value']['owner_digest'] = 'PUBLIC_DUMMY'
                elif mutation == 'acceptance_status':
                    find_event(events, 'role-status', 0)['value']['financial_or_chain_acceptance'] = True
                else:
                    find_event(events, 'launch', 0)['started_ns'] = 2
                with self.assertRaisesRegex(ValueError, category):
                    self.module.extract_windows(events)

    def test_no_clock_boolean_or_truth_can_promote_or_change_predictions(self):
        events, a = fixture_events(), arrivals((10, 20, 50))
        first = self.module.diagnose(events, a, {0: 1, 1: 2, 2: 3})
        other_truth = self.module.diagnose(events, a, {0: 3, 1: 2, 2: 1})
        for key in ('conditional_zero_offset', 'conditional_one_shared_unbounded_constant_offset'):
            self.assertEqual(first[key]['models'], other_truth[key]['models'])
            self.assertEqual(first[key]['candidate_counts'], other_truth[key]['candidate_counts'])
        self.assertFalse(other_truth['conditional_zero_offset']['public_truth_retained'])
        self.assertEqual(first['status'], 'UNQUALIFIED')
        self.assertEqual(first['classification'], 'PUBLIC_KNOWN_FIXTURE_FUNCTIONALITY_ONLY')
        for key in ('clock_qualified', 'overall_privacy_qualified', 'owner_origin_pipe_mode_qualified',
                    'private_owner_or_full_privacy_view_measured',
                    'receiver_recorded_ns_used_as_pre_ACK_timestamp',
                    'post_Popen_launch_event_used_as_lower_bound'):
            self.assertFalse(first[key])
        with self.assertRaisesRegex(ValueError, 'no-retroactive-clock-qualification'):
            self.module.diagnose(events, a, {0: 1, 1: 2, 2: 3}, clock_qualified=True)

    def test_exact_public_bindings_and_IO_free_analysis(self):
        clock, truth = fixture_exports(self.module)
        with mock.patch('builtins.open', side_effect=AssertionError('no body IO')), \
             mock.patch.object(self.module.os, 'open', side_effect=AssertionError('no descriptor IO')):
            result = self.module.analyze_metadata(fixture_events(), clock, truth)
        self.assertEqual(result['conditional_zero_offset']['candidate_counts'], [2, 2, 1])
        self.assertTrue(result['conditional_zero_offset']['public_truth_retained'])
        self.assertFalse(result['clock_qualified'])
        self.assertEqual(result['status'], 'UNQUALIFIED')
        self.assertFalse(result['raw_received_export_or_packet_bodies_read_by_diagnostic'])
        self.assertEqual(result['source_bindings']['events_sha256'], self.module.EVENTS_SHA)

    def test_stale_run_and_source_bindings_and_qualification_claims_refuse(self):
        keys = ('trial_id', 'source_events_sha256', 'source_received_sha256',
                'source_fixture_selection_sha256', 'source_launcher_sha256', 'source_receiver_sha256',
                'clock_qualified', 'privacy_or_financial_qualification')
        for which in (0, 1):
            for key in keys:
                with self.subTest(export=which, key=key):
                    exports = list(fixture_exports(self.module))
                    exports[which][key] = True if key.endswith('qualified') or key.endswith('qualification') else 'WRONG_PUBLIC_BINDING'
                    with self.assertRaisesRegex(ValueError, 'same-run-exact-source-event-fixture-bindings'):
                        self.module.analyze_metadata(fixture_events(), *exports)

    def test_clock_record_shape_order_and_truth_bijection_refuse(self):
        for mutation in ('raw_packet', 'late_post', 'short_frame', 'duplicate_arrival', 'foreign_truth'):
            with self.subTest(mutation=mutation):
                clock, truth = fixture_exports(self.module)
                if mutation == 'raw_packet':
                    clock['records'][0]['projection_hex'] = 'PUBLIC_DUMMY_ONLY'
                elif mutation == 'late_post':
                    clock['records'][0]['post_handler_monotonic_ns'] = 999999
                elif mutation == 'short_frame':
                    clock['records'][0]['received_body_bytes'] = 4095
                elif mutation == 'duplicate_arrival':
                    clock['records'][1]['arrival_sequence'] = 1
                else:
                    truth['mapping'][0]['arrival_sequence'] = 99
                with self.assertRaises(ValueError):
                    self.module.analyze_metadata(fixture_events(), clock, truth)

    def test_public_output_is_append_only_and_symlink_refuses(self):
        with tempfile.TemporaryDirectory(prefix='public-timing-fixture-') as directory:
            target = Path(directory) / 'RESULT.json'
            row = self.module.write_new(target, {'scope': 'PUBLIC_SYNTHETIC_FIXTURE', 'count': 3})
            before = target.read_bytes()  # Our deliberately public dummy bytes.
            self.assertEqual(hashlib.sha256(before).hexdigest(), row['sha256'])
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o400)
            with self.assertRaises(FileExistsError):
                self.module.write_new(target, {'count': 999})
            self.assertEqual(target.read_bytes(), before)
            alias = Path(directory) / 'alias.json'
            alias.symlink_to(target)
            with self.assertRaisesRegex(ValueError, 'new-public-output-path'):
                self.module.write_new(alias, {'count': 999})


if __name__ == '__main__':
    unittest.main(verbosity=2)
