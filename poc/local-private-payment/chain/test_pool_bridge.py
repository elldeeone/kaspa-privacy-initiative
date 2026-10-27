"""Public synthetic seam controls. No RPC, private input, or financial PASS claim."""
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import pool_bridge as bridge

ROOT = Path('/var/tmp/kpi-local-private-payment-01/review-controls')
HEX = '12' * 32


def args():
    a = SimpleNamespace(mode='lifecycle', stage='action-0004', trial_id='8e9b72ce-ea5f-48e1-a385-ecb14ed4e6ea',
        output=ROOT/'synthetic-role-output', bundle_directory=ROOT/'current-pages',
        baseline_bundle_directory=ROOT/'baseline-pages', trusted_local_cache=True,
        rpc=['wss://example.invalid'], execute=True, journal='/private/never-mounted',
        exclude_private_directory=['/private/never-mounted'], exclude_old_trial=['old'],
        pool_selection=ROOT/'POOL.json', pool_selection_sha256=HEX)
    for name in ('selection', 'descriptor', 'assets', 'parameters', 'codec', 'fetch', 'case',
                 'runtime_source', 'cache_admission', 'baseline_fetch', 'baseline_cache'):
        setattr(a, name, ROOT/(name+'.json'))
        setattr(a, name+'_sha256', HEX)
    for name in bridge.RUNTIME:
        setattr(a, name.replace('-', '_'), None)
    return a


def fetch():
    return {'pages': [{'path': 'a/primary.json.gz', 'gzip_sha256': HEX}],
        'current_view': {'post_query_delta': {'pages': [
            {'path': 'b/post.json.gz', 'gzip_sha256': '34'*32}]}}}


class Guard:
    def __init__(self, values):
        self.values = {str(ROOT/'cache_admission.json'): {'initial_handoff': {
            'path': str(ROOT/'INITIAL-HANDOFF.json'), 'sha256': HEX}}, **values}
    def read(self, path, expected=None):
        value = self.values[str(path)]
        return bridge.encoded(value) + b'\n' if not isinstance(value, bytes) else value


class Controls(unittest.TestCase):
    def test_replay_closed_argv_cannot_carry_host_authority(self):
        a = args()
        argv = bridge.role_argv(a, 'replay')
        self.assertIn('--trusted-local-cache', argv)
        for name in ('--journal', '--execute', '--rpc', '--case', '--pool-selection',
                     '--exclude-private-directory', '--exclude-old-trial'):
            self.assertNotIn(name, argv)
        self.assertEqual(argv.count('--fetch'), 1)
        self.assertEqual(argv[argv.index('--output')+1], str(a.output))

    def test_preflight_preserves_exact_case_stage_and_scope(self):
        a = args()
        argv = bridge.role_argv(a, 'preflight')
        for name in ('mode', 'stage', 'trial-id', 'case', 'case-sha256', 'selection-sha256'):
            self.assertEqual(argv[argv.index('--'+name)+1], str(bridge.value(a, name)))
        self.assertNotIn('--journal', argv)
        self.assertNotIn('--execute', argv)
        with self.assertRaises(ValueError):
            bridge.role_argv(a, 'arbitrary-python')

    def test_complete_current_and_baseline_pages_and_executable_mode(self):
        a = args()
        data = {str(a.fetch): fetch(), str(a.baseline_fetch): fetch()}
        rows = bridge.job_files(a, 'replay', Guard(data))
        by_path = {r['source']: r for r in rows}
        for root in (a.bundle_directory, a.baseline_bundle_directory):
            self.assertIn(str(root/'a/primary.json.gz'), by_path)
            self.assertIn(str(root/'b/post.json.gz'), by_path)
        self.assertEqual(by_path[str(a.codec)]['mode'], 0o500)
        self.assertEqual(by_path[str(a.baseline_cache)]['mode'], 0o400)
        self.assertEqual(by_path[str(ROOT/'INITIAL-HANDOFF.json')], {
            'source': str(ROOT/'INITIAL-HANDOFF.json'), 'sha256': HEX, 'mode': 0o400})
        self.assertEqual(len(rows), len(by_path))

    def test_conflicting_same_path_page_bytes_are_rejected(self):
        a = args()
        a.baseline_bundle_directory = a.bundle_directory
        other = fetch()
        other['pages'][0]['gzip_sha256'] = '56'*32
        with self.assertRaises(ValueError):
            bridge.job_files(a, 'replay', Guard({str(a.fetch): fetch(), str(a.baseline_fetch): other}))

    def test_traversal_alias_and_missing_post_segment_are_rejected(self):
        a = args()
        for relative in ('../other', '/absolute', 'a/../other', 'a//other', './other', 'a/./other'):
            with self.subTest(relative=relative):
                bad = fetch()
                bad['pages'][0]['path'] = relative
                with self.assertRaises(ValueError):
                    bridge.job_files(a, 'replay', Guard({str(a.fetch): bad}))
        bad = fetch()
        del bad['current_view']['post_query_delta']
        with self.assertRaises(KeyError):
            bridge.job_files(a, 'replay', Guard({str(a.fetch): bad}))

    def test_export_provenance_and_result_binding(self):
        ROOT.mkdir(parents=True, exist_ok=True)
        mutations = [None, 'role', 'request', 'pool_selection', 'output', 'stdout_sha256',
                     'network', 'result', 'stderr', 'exit']
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(dir=ROOT, prefix='pool-seam-toy-') as tmp:
                a = args()
                a.output = Path(tmp)/'pool-only'/'result'
                request_path = Path(tmp)/'request.json'
                result = {'submission_performed': False, 'status': 'SYNTHETIC_RESULT'}
                stdout = bridge.encoded(result)+b'\n'
                values = {str(a.pool_selection): {'client': {'path': str(bridge.CLIENT), 'sha256': HEX}},
                          str(bridge.CLIENT): b'synthetic-selected-client',
                          str(a.fetch): fetch(), str(a.baseline_fetch): fetch(),
                          str(a.output/'RESULTS.json'): result}
                def run(command, **kwargs):
                    request_raw = request_path.read_bytes()  # New synthetic file created by this control.
                    provenance = {'schema': 'kpxa-public-offline-pool-provenance/v1',
                        'pool_selection': {'path': str(a.pool_selection), 'sha256': a.pool_selection_sha256},
                        'role': 'replay', 'request': {'path': str(request_path), 'sha256': bridge.digest(request_raw)},
                        'output': str(a.output), 'stdout_sha256': bridge.digest(stdout), 'network': 'none'}
                    if mutation in provenance:
                        provenance[mutation] = 'wrong'
                    if mutation == 'result':
                        values[str(a.output/'RESULTS.json')] = {'submission_performed': False, 'status': 'OTHER'}
                    values[str(a.output/'POOL-PROVENANCE.json')] = provenance
                    return SimpleNamespace(returncode=1 if mutation == 'exit' else 0,
                        stdout=stdout, stderr=b'unexpected' if mutation == 'stderr' else b'')
                guards = []
                class FreshGuard(Guard):
                    def read(self, path, expected=None):
                        if str(path).startswith(str(a.output)+'/') and self is guards[0]:
                            raise ValueError('synthetic-stale-historical-inode')
                        return super().read(path, expected)
                def fresh_guard():
                    guard = FreshGuard(values)
                    guards.append(guard)
                    return guard
                with patch.object(bridge, 'HostPolicy', fresh_guard), patch.object(bridge.subprocess, 'run', run):
                    if mutation is None:
                        self.assertEqual(bridge.invoke(a, 'replay', request_path), result)
                        self.assertEqual(len(guards), 2)
                    else:
                        with self.assertRaises((ValueError, TypeError)):
                            bridge.invoke(a, 'replay', request_path)


if __name__ == '__main__':
    unittest.main()
