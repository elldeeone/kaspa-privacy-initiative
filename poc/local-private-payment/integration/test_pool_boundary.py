"""Known-public metadata controls; no actual signal or private file access."""
import copy
from pathlib import Path
from types import SimpleNamespace
import stat
import unittest
from unittest.mock import patch

import pool_boundary as boundary


class BoundaryControls(unittest.TestCase):
    def setUp(self):
        self.proposal = {'watch_id': 'KNOWN-PUBLIC-FIXTURE-ID',
            'qualified_profile': {'path': '/known-public/PROFILE.json', 'sha256': '11' * 32},
            'main_start_monotonic': '12345', 'kernel_start_ticks': '67890'}
        self.marker = SimpleNamespace(st_mode=stat.S_IFREG | 0o400, st_nlink=1)
        self.current = {'MainPID': str(boundary.PID), 'ActiveState': 'active',
                        'ExecMainStartTimestampMonotonic': '12345'}

    def test_only_exact_Root_ready_profile_can_hold(self):
        ready = boundary.ready_value(self.proposal)
        self.assertTrue(boundary.may_hold(self.proposal, ready, self.marker, False, self.current))
        for key, value in [('watch_id', 'old-control'), ('main_pid', 1), ('transaction_id', '22' * 32),
                           ('classification', 'TEMPLATE_ONLY_NOT_READY')]:
            self.assertFalse(boundary.may_hold(self.proposal, dict(ready, **{key: value}),
                                               self.marker, False, self.current))
        bad = copy.deepcopy(ready)
        bad['qualified_profile']['sha256'] = '00' * 32
        self.assertFalse(boundary.may_hold(self.proposal, bad, self.marker, False, self.current))

    def test_no_next_action_or_main_identity_race_is_accepted(self):
        ready = boundary.ready_value(self.proposal)
        self.assertFalse(boundary.may_hold(self.proposal, ready, self.marker, True, self.current))
        self.assertFalse(boundary.may_hold(self.proposal, ready, None, False, self.current))
        for key, value in [('MainPID', '1'), ('ExecMainStartTimestampMonotonic', '12346'),
                           ('ActiveState', 'failed')]:
            self.assertFalse(boundary.may_hold(self.proposal, ready, self.marker, False,
                                               dict(self.current, **{key: value})))
        self.assertFalse(boundary.may_hold(self.proposal, ready,
            SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_nlink=1), False, self.current))

    def test_prepare_cannot_signal_or_create_actual_READY_flag(self):
        saved = []
        output = boundary.PUBLIC / 'control/KNOWN-PUBLIC-BOUNDARY-TEST'
        with patch.object(boundary, 'unit_metadata', return_value=self.current), \
             patch.object(boundary, 'kernel_start_ticks', return_value='67890'), \
             patch.object(Path, 'exists', return_value=False), patch.object(Path, 'mkdir'), \
             patch.object(boundary, 'save', side_effect=lambda p,v: saved.append((p,v)) or {'path':str(p),'sha256':'11'*32}), \
             patch.object(boundary.signal, 'pidfd_send_signal', side_effect=AssertionError('signal-in-prepare')):
            boundary.prepare(boundary.PUBLIC / 'KNOWN-PUBLIC-PROFILE.json', '11' * 32, output)
        self.assertEqual([p.name for p,_ in saved], ['PROPOSAL.json', 'READY-CONTENT-TEMPLATE-ONLY.json'])
        self.assertFalse(any(p.name == 'ROOT-QUALIFIED-PROFILE.READY.json' for p,_ in saved))

    def test_pidfd_must_bind_exact_kernel_start_after_open_before_any_signal(self):
        with patch.object(boundary.os, 'pidfd_open', return_value=123), \
             patch.object(boundary.os, 'close') as close, \
             patch.object(boundary, 'kernel_start_ticks', return_value='67891'), \
             patch.object(boundary, 'unit_metadata', return_value=self.current), \
             patch.object(boundary.signal, 'pidfd_send_signal', side_effect=AssertionError('wrong-process-signal')):
            with self.assertRaisesRegex(ValueError, 'pidfd-open-must-bind'):
                boundary.checked_pidfd(self.proposal)
            close.assert_called_once_with(123)

    def test_post_stop_race_requires_Root_review_without_automatic_resume(self):
        self.assertEqual(boundary.held_status(self.proposal, self.current, '67890', False, True),
                         'MAIN_ONLY_HELD_AWAITING_ROOT_TYPED_ACK_REVIEW')
        for current, ticks, next_exists, stopped in (
            (self.current, '67890', True, True), (self.current, '67891', False, True),
            (dict(self.current, MainPID='1'), '67890', False, True),
            (self.current, '67890', False, False)):
            self.assertEqual(boundary.held_status(self.proposal, current, ticks, next_exists, stopped),
                             'HELD_REQUIRES_ROOT_REVIEW')


if __name__ == '__main__':
    unittest.main()
