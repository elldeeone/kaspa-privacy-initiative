"""Known-public-only controls for pool routing and own-controller head comparison."""
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import campaign_pool as pool


def row(name):
    return {'path': '/known-public/' + name, 'sha256': '11' * 32}


class PoolCallerControls(unittest.TestCase):
    def test_fresh_public_reader_forwards_exact_expected_hash_per_read(self):
        calls = []
        guards = []
        def load(path):
            self.assertEqual(path, '/var/tmp/kpi-root-guard-helper-09.py')
            guards.append(object())
            return {'read': lambda path, expected=None: calls.append((path, expected)) or b'KNOWN PUBLIC'}
        read = pool.fresh_public_reader()
        with patch.object(pool.runpy, 'run_path', side_effect=load):
            read('/known-public/first', '11' * 32)
            read('/known-public/second', '22' * 32)
        self.assertEqual(calls, [('/known-public/first', '11' * 32), ('/known-public/second', '22' * 32)])
        self.assertEqual(len(guards), 2)

    def test_fresh_public_reader_accepts_public_reused_inode_without_clearing_old_guard(self):
        with tempfile.TemporaryDirectory(prefix='known-public-pool-reader-') as directory:
            root = Path(directory)
            dummy = root / 'KNOWN-PUBLIC-DUMMY-NOT-A-SEED'
            dummy.write_bytes(b'KNOWN PUBLIC DUMMY, NO PRIVATE CONTENT')
            s = dummy.stat()
            identity = (s.st_dev, s.st_ino)
            old = pool.runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')
            old['m'].GUARD.inodes.add(identity)
            dummy.unlink()
            value = b'KNOWN PUBLIC NEW RECEIPT, NO PRIVATE CONTENT'
            expected = hashlib.sha256(value).hexdigest()
            reused = None
            for i in range(4096):
                path = root / ('PUBLIC-' + str(i))
                path.write_bytes(value)
                s = path.stat()
                if (s.st_dev, s.st_ino) == identity:
                    reused = path
                    break
                path.unlink()
            self.assertIsNotNone(reused, 'control must demonstrate real public inode reuse')
            with self.assertRaisesRegex(Exception, 'aliases-original-backup'):
                old['read'](str(reused), expected)
            self.assertEqual(pool.fresh_public_reader()(str(reused), expected), value)
            self.assertIn(identity, old['m'].GUARD.inodes)
            with self.assertRaises(Exception):
                pool.fresh_public_reader()(str(reused), '00' * 32)

    def test_fresh_public_reader_refuses_current_alias_before_underlying_read(self):
        with tempfile.TemporaryDirectory(prefix='known-public-pool-reader-') as directory:
            path = Path(directory) / 'KNOWN-PUBLIC-CURRENT-ALIAS-FIXTURE'
            value = b'KNOWN PUBLIC DUMMY, NO PRIVATE CONTENT'
            path.write_bytes(value)
            h = pool.runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')
            s = path.stat()
            h['m'].GUARD.inodes.add((s.st_dev, s.st_ino))
            # Actual unchanged09 must refuse before its earlier byte-reading
            # layer. This control uses known-public dummy metadata only.
            earlier = h['read'].__globals__['h']
            with patch.dict(earlier, {'read': lambda *a, **k: self.fail('alias bytes read')}), \
                 patch.object(pool.runpy, 'run_path', return_value=h):
                with self.assertRaisesRegex(Exception, 'aliases-original-backup'):
                    pool.fresh_public_reader()(str(path), hashlib.sha256(value).hexdigest())

    def test_detached_unit_argv_has_generous_fd_limit_and_once_only_lifecycle_properties(self):
        argv = pool.service_prefix('local-payment-campaign-06')
        self.assertEqual(argv[:4], ['/usr/bin/systemd-run', '--user', '--unit', 'local-payment-campaign-06'])
        for value in ('--property=LimitNOFILE=65536', '--property=KillMode=control-group',
                      '--property=Restart=no', '--property=UMask=0077'):
            self.assertEqual(argv.count(value), 1)

    def test_unix_socket_address_limit_and_unit_specific_short_path(self):
        p = pool.validate_pool_socket('local-payment-campaign-06', '/var/tmp/kpi-local-private-payment-01/pool-ipc-06/p.sock')
        self.assertLessEqual(len(os.fsencode(str(p))), 107)
        with self.assertRaisesRegex(ValueError, 'unix-socket-path-too-long'):
            pool.validate_pool_socket('local-payment-campaign-06', '/var/tmp/' + 'x' * 108)
        with self.assertRaisesRegex(ValueError, 'unit-specific'):
            pool.validate_pool_socket('local-payment-campaign-06', '/var/tmp/kpi-local-private-payment-01/pool-ipc-07/p.sock')

    def test_pool_failure_or_unready_socket_cannot_enter_base_financial_run(self):
        with tempfile.TemporaryDirectory(prefix='known-public-pool-') as directory:
            path = Path(directory) / 'p.sock'
            entered = []
            dead = SimpleNamespace(poll=lambda: 1)
            with self.assertRaisesRegex(ValueError, 'before-financial-consumption'):
                pool.run_after_pool_ready(dead, path, lambda: entered.append(True))
            self.assertEqual(entered, [])
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.bind(str(path))
                os.chmod(path, 0o600)
                alive = SimpleNamespace(poll=lambda: None)
                pool.run_after_pool_ready(alive, path, lambda: entered.append(True))
                self.assertEqual(entered, [True])
            finally:
                sock.close()

    def test_only_explicit_submit_and_confirm_seams_receive_pool_selector(self):
        scripts = {'submit': row('submit_pool.mjs'), 'confirm': row('confirm_pool.py')}
        selected = row('POOL.json')
        suffix = ['--pool-selection', selected['path'], '--pool-selection-sha256', selected['sha256']]
        for argv in (['/known-public/node', scripts['submit']['path'], '--execute'],
                     ['/usr/bin/python3', '-B', scripts['confirm']['path'], '--output', '/known-public/out']):
            self.assertEqual(pool.pool_argv(argv, scripts, selected), argv + suffix)
        owner = ['/usr/bin/python3', '-B', '/known-public/worker.py', 'restore',
                 '--owner', '/known-public-dummy-private-owner', '--unrelated-text', scripts['submit']['path']]
        self.assertEqual(pool.pool_argv(owner, scripts, selected), owner)
        self.assertEqual(pool.pool_argv(['/known-public/node', '/known-public/other.mjs'], scripts, selected),
                         ['/known-public/node', '/known-public/other.mjs'])

    def test_duplicate_selector_refuses_before_child_invocation(self):
        scripts = {'submit': row('submit_pool.mjs'), 'confirm': row('confirm_pool.py')}
        with self.assertRaisesRegex(ValueError, 'single-explicit'):
            pool.pool_argv(['/known-public/node', scripts['submit']['path'], '--pool-selection', 'other'],
                           scripts, row('POOL.json'))

    def test_only_exact_genuine_selected_head_and_resume_branch_are_admitted(self):
        head = {name: row(name) for name in ('fetch.json', 'CACHE.json', 'HISTORY.json', 'CONTEXT.json',
                                           'CURRENT-ENTRY.json', 'RESULTS.json')}
        state = {'schema': 'kpxa-private-campaign-state/v1', 'head': head,
                 'next_action': 3, 'submission_consumed': True, 'qualified_case': row('CASE4.json')}
        profile = {'expected_next_action': 3, 'expected_submission_consumed': True,
                   'expected_qualified_case': row('CASE4.json')}
        seen = []

        def read(path, *, private):
            seen.append((path.name, private))
            return json.dumps(state).encode()

        base = SimpleNamespace(read=read, parse=json.loads)
        before = copy.deepcopy(state)
        pool.protected_head_matches(base, Path('/known-public-dummy-private-caller'), profile,
                                    {'selectors': head})
        self.assertEqual(state, before)
        self.assertEqual(seen, [('STATE.json', True)])
        for change in ('head', 'next', 'consumed', 'case'):
            bad = copy.deepcopy(state)
            if change == 'head':
                bad['head']['fetch.json'] = row('FORGED-OR-OLD-FETCH.json')
            elif change == 'next':
                bad['next_action'] = 4
            elif change == 'consumed':
                bad['submission_consumed'] = False
            else:
                bad['qualified_case'] = row('DIFFERENT-CASE.json')
            base.read = lambda path, **kwargs: json.dumps(bad).encode()
            with self.assertRaises(ValueError):
                pool.protected_head_matches(base, Path('/known-public-dummy-private-caller'), profile,
                                            {'selectors': head})

    def test_unconsumed_confirmed_boundary_does_not_require_or_modify_qualified_case(self):
        head = {'fetch.json': row('FETCH5.json'), 'CACHE.json': row('CACHE5.json')}
        state = {'schema': 'kpxa-private-campaign-state/v1', 'head': head,
                 'next_action': 4, 'submission_consumed': False}
        base = SimpleNamespace(read=lambda path, **kwargs: json.dumps(state).encode(), parse=json.loads)
        profile = {'expected_next_action': 4, 'expected_submission_consumed': False,
                   'expected_qualified_case': None}
        before = copy.deepcopy(state)
        pool.protected_head_matches(base, Path('/known-public-dummy-private-caller'), profile,
                                    {'selectors': head})
        self.assertEqual(state, before)


if __name__ == '__main__':
    unittest.main()
