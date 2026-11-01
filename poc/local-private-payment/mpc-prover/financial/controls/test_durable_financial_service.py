"""Controls for the disconnect-safe local financial supervisor.

These controls execute only tiny synthetic child programs. They never run the
financial prover and produce no financial or privacy authority.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest import mock
import uuid
import sys

FINANCIAL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FINANCIAL))
import durable_financial_service as durable


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class DurableFinancialServiceControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.units = []

    def tearDown(self):
        for unit in self.units:
            subprocess.run(['systemctl', '--user', 'stop', unit],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            subprocess.run(['systemctl', '--user', 'reset-failed', unit],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        self.temp.cleanup()

    def selection(self, *, exit_code=0, delay=1.5):
        run_id = (uuid.uuid4().hex + uuid.uuid4().hex)[:64]
        unit = 'kpi-durable-financial-' + run_id + '.service'
        self.units.append(unit)
        success = self.root / ('success-' + run_id)
        failure = self.root / ('failure-' + run_id)
        helper = self.root / ('helper-' + run_id + '.py')
        helper.write_text(
            'import pathlib,sys,time\n'
            'time.sleep(float(sys.argv[1]))\n'
            'pathlib.Path(sys.argv[2]).write_text("done\\n")\n'
            'raise SystemExit(int(sys.argv[3]))\n')
        helper.chmod(0o400)
        python = Path('/usr/bin/python3').resolve()
        marker = success if exit_code == 0 else failure
        state = self.root / ('state-' + run_id)
        value = {
            'schema': 'kpb-durable-financial-service-selection/v1',
            'status': 'FRESH_UNEXECUTED',
            'kind': 'DURABILITY_PROBE',
            'run_id': run_id,
            'unit_name': unit,
            'working_directory': str(self.root),
            'state_root': str(state),
            'program': {'path': str(python), 'sha256': sha(python)},
            'argv': [str(python), str(helper), str(delay), str(marker),
                     str(exit_code)],
            'artifacts': [
                {'path': str(python), 'sha256': sha(python),
                 'bytes': python.stat().st_size},
                {'path': str(helper), 'sha256': sha(helper),
                 'bytes': helper.stat().st_size},
            ],
            'public_stage_paths': [],
            'success_marker': str(success),
            'failure_marker': str(failure),
            'resource_policy': durable.RESOURCE_POLICY,
            'minimum_mem_available_bytes': 0,
            'identity': {
                'trial_id': str(uuid.uuid4()),
                'attempt_id': hashlib.sha256(
                    ('attempt-' + run_id).encode()).hexdigest(),
                'cohort_id': hashlib.sha256(
                    ('cohort-' + run_id).encode()).hexdigest(),
                'controller_source_sha256': sha(helper),
                'controller_build_sha256': sha(helper),
                'owner_input_root_identity_sha256': hashlib.sha256(
                    ('root-' + run_id).encode()).hexdigest(),
                'owner_input_identity_sha256': [hashlib.sha256(
                    ('owner-' + str(index) + '-' + run_id).encode()
                ).hexdigest() for index in range(3)],
                'private_owner_input_bodies_read_or_hashed': False,
            },
            'authority': {
                'financial_qualified': False,
                'privacy_qualified': False,
                'native_or_settlement_authorized': False,
            },
        }
        path = self.root / ('selection-' + run_id + '.json')
        path.write_bytes(canonical(value)); path.chmod(0o400)
        return path, value

    def wait_for(self, path, timeout=12):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return json.loads(path.read_text())
            time.sleep(0.05)
        self.fail('timed out waiting for ' + str(path))

    def financialize(self, value, owner_paths, *, run_id=None):
        run_id = value['run_id'] if run_id is None else run_id
        value['run_id'] = run_id
        value['unit_name'] = 'kpi-durable-financial-' + run_id + '.service'
        value['kind'] = 'FINANCIAL_CONTROLLER'
        value['minimum_mem_available_bytes'] = durable.PRODUCTION_MIN_MEM
        root = self.root / run_id / 'public'
        value['public_stage_paths'] = [
            str(root / ('P' + str(index)) / 'PUBLIC-STAGE.json')
            for index in range(3)]
        value['success_marker'] = str(root / 'RESULT.json')
        value['failure_marker'] = str(root / 'FAILED.json')
        value['argv'].extend([
            '--run-id', run_id, '--memory-gib', '64', '--cpu-cores', '12'])
        for owner in owner_paths:
            value['argv'].extend(['--owner-input-file', str(owner)])
        common = Path(os.path.commonpath(
            [str(owner) for owner in owner_paths]))
        value['identity']['owner_input_root_identity_sha256'] = (
            hashlib.sha256(str(common).encode()).hexdigest())

    def test_user_service_survives_launcher_exit_and_records_terminal(self):
        selection, value = self.selection()
        completed = subprocess.run(
            [sys.executable, str(FINANCIAL / 'durable_financial_service.py'),
             '--launch', '--selection', str(selection)],
            capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        state = Path(value['state_root'])
        started = self.wait_for(state / 'public/STARTED.json')
        self.assertEqual(started['unit_name'], value['unit_name'])
        terminal = self.wait_for(state / 'public/TERMINAL.json')
        self.assertEqual(terminal['outcome'],
                         'PROBE_COMPLETE_NOT_FINANCIAL_AUTHORITY')
        self.assertEqual(terminal['child_returncode'], 0)
        self.assertFalse(terminal['financial_qualified'])
        shown = subprocess.run(
            ['systemctl', '--user', 'show', value['unit_name'],
             '-p', 'ActiveState', '-p', 'SubState', '-p', 'OOMScoreAdjust',
             '-p', 'MemoryMax', '-p', 'RuntimeMaxUSec'],
            capture_output=True, text=True, check=True).stdout
        self.assertIn('OOMScoreAdjust=-250', shown)
        self.assertIn('MemoryMax=infinity', shown)
        self.assertIn('RuntimeMaxUSec=infinity', shown)

    def test_nonzero_child_and_reused_identity_are_durably_visible(self):
        selection, value = self.selection(exit_code=7, delay=0.1)
        first = subprocess.run(
            [sys.executable, str(FINANCIAL / 'durable_financial_service.py'),
             '--launch', '--selection', str(selection)],
            capture_output=True, text=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        state = Path(value['state_root'])
        terminal = self.wait_for(state / 'public/TERMINAL.json')
        self.assertEqual(terminal['outcome'],
                         'PROBE_FAILED_NOT_FINANCIAL_AUTHORITY')
        self.assertEqual(terminal['child_returncode'], 7)
        self.assertTrue(terminal['failure_marker_present'])
        second = subprocess.run(
            [sys.executable, str(FINANCIAL / 'durable_financial_service.py'),
             '--launch', '--selection', str(selection)],
            capture_output=True, text=True)
        self.assertEqual(second.returncode, 78)

    def test_financial_launch_refuses_concurrent_heavy_process(self):
        _, value = self.selection(delay=0.1)
        value['kind'] = 'FINANCIAL_CONTROLLER'
        value['minimum_mem_available_bytes'] = 0
        heavy = subprocess.Popen(
            [sys.executable, '-c', 'import time;time.sleep(10)',
             'build_registered_financial.py'])
        try:
            with self.assertRaisesRegex(
                    durable.Refused, 'concurrent-heavy-process'):
                durable.resource_guard(value)
        finally:
            heavy.terminate(); heavy.wait(timeout=5)

    def test_financial_launch_refuses_insufficient_memory_headroom(self):
        _, value = self.selection(delay=0.1)
        value['kind'] = 'FINANCIAL_CONTROLLER'
        value['minimum_mem_available_bytes'] = durable.PRODUCTION_MIN_MEM
        with mock.patch.object(durable, 'mem_available',
                               return_value=durable.PRODUCTION_MIN_MEM - 1), \
                mock.patch.object(durable, 'heavy_processes', return_value=[]), \
                mock.patch.object(durable, 'linger_enabled', return_value=True):
            with self.assertRaisesRegex(
                    durable.Refused, 'insufficient-launch-memory-headroom'):
                durable.resource_guard(value)

    def test_public_receipts_never_export_command_or_private_paths(self):
        selection, value = self.selection(delay=0.1)
        completed = subprocess.run(
            [sys.executable, str(FINANCIAL / 'durable_financial_service.py'),
             '--launch', '--selection', str(selection)],
            capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        state = Path(value['state_root'])
        self.wait_for(state / 'public/TERMINAL.json')
        public = b''.join(path.read_bytes()
                          for path in (state / 'public').iterdir())
        for secret in (str(selection).encode(),
                       str(value['argv'][1]).encode(),
                       str(value['success_marker']).encode(),
                       value['identity']['owner_input_identity_sha256'][0]
                           .encode()):
            self.assertNotIn(secret, public)
        self.assertTrue((state / 'private/controller.stdout').exists())
        self.assertTrue((state / 'private/controller.stderr').exists())

    def test_consumed_registry_rejects_reforged_selection(self):
        first_path, first = self.selection(delay=0.1)
        first_launch = subprocess.run(
            [sys.executable, str(FINANCIAL / 'durable_financial_service.py'),
             '--launch', '--selection', str(first_path)],
            capture_output=True, text=True)
        self.assertEqual(first_launch.returncode, 0, first_launch.stderr)
        self.wait_for(Path(first['state_root']) / 'public/TERMINAL.json')

        second_path, second = self.selection(delay=0.1)
        second['identity']['trial_id'] = first['identity']['trial_id']
        second_path.chmod(0o600); second_path.write_bytes(canonical(second))
        second_path.chmod(0o400)
        refused = subprocess.run(
            [sys.executable, str(FINANCIAL / 'durable_financial_service.py'),
             '--launch', '--selection', str(second_path)],
            capture_output=True, text=True)
        self.assertEqual(refused.returncode, 78)
        self.assertFalse(Path(second['state_root']).exists())

    def test_tombstone_rejects_reforged_selection_after_registry_rollback(self):
        selection_path, _ = self.selection(delay=0.1)
        selection, selection_sha = durable.read_selection(selection_path)
        registry = self.root / 'rollback-registry'
        registry.mkdir(mode=0o700)
        tombstones = registry / 'TOMBSTONES'
        tombstones.mkdir(mode=0o700)
        for name in ('LOCK', 'JOURNAL.jsonl', 'ANCHOR.jsonl'):
            path = registry / name
            path.touch(mode=0o600)
            path.chmod(0o600)
        info = lambda path: (path.stat().st_dev, path.stat().st_ino)
        spec = {
            'root': registry,
            'root_identity': info(registry),
            'journal_identity': info(registry / 'JOURNAL.jsonl'),
            'anchor_identity': info(registry / 'ANCHOR.jsonl'),
            'lock_identity': info(registry / 'LOCK'),
            'tombstones_identity': info(tombstones),
        }
        original = durable.REGISTRIES['DURABILITY_PROBE']
        durable.REGISTRIES['DURABILITY_PROBE'] = spec
        try:
            durable.reserve_identity(selection, selection_sha)
            (registry / 'JOURNAL.jsonl').write_bytes(b'')
            (registry / 'ANCHOR.jsonl').write_bytes(b'')
            with self.assertRaisesRegex(
                    durable.Refused, 'identity-tombstone-already-exists'):
                durable.reserve_identity(selection, selection_sha)
        finally:
            durable.REGISTRIES['DURABILITY_PROBE'] = original

    def test_self_authored_financial_controller_is_hard_disabled(self):
        selection, value = self.selection(delay=0.1)
        owners = [Path('/run/user/1000/fresh-owner-inputs') / str(index) /
                  'OWNER-PRIVATE-INPUT-V2.bin' for index in range(3)]
        self.financialize(value, owners)
        selection.chmod(0o600); selection.write_bytes(canonical(value))
        selection.chmod(0o400)
        with self.assertRaisesRegex(
                durable.Refused,
                'financial-controller-independent-admission-unavailable'):
            durable.read_selection(selection)
        completed = subprocess.run(
            [sys.executable, str(FINANCIAL / 'durable_financial_service.py'),
             '--launch', '--selection', str(selection)],
            capture_output=True, text=True)
        self.assertEqual(completed.returncode, 78)
        self.assertFalse(Path(value['state_root']).exists())

    def test_known_abort_and_consumed_owner_root_refuse(self):
        selection, value = self.selection(delay=0.1)
        old_run = durable.KNOWN_ABORTED_RUN_ID
        owners = [durable.FORBIDDEN_OWNER_ROOT / str(index) /
                  'OWNER-PRIVATE-INPUT.txt' for index in range(3)]
        self.financialize(value, owners, run_id=old_run)
        selection.chmod(0o600); selection.write_bytes(canonical(value))
        selection.chmod(0o400)
        with self.assertRaisesRegex(
                durable.Refused, 'known-abort-or-consumed-source-owner-root'):
            durable.read_selection(selection)
        refused = subprocess.run(
            [sys.executable, str(FINANCIAL / 'durable_financial_service.py'),
             '--launch', '--selection', str(selection)],
            capture_output=True, text=True)
        self.assertEqual(refused.returncode, 78)
        self.assertFalse(Path(value['state_root']).exists())

    def test_one_old_owner_path_cannot_hide_under_a_new_common_root(self):
        selection, value = self.selection(delay=0.1)
        owners = [
            durable.FORBIDDEN_OWNER_ROOT / '0' / 'OWNER-PRIVATE-INPUT.txt',
            Path('/run/user/1000/fresh-owner-inputs/1/input.bin'),
            Path('/run/user/1000/fresh-owner-inputs/2/input.bin'),
        ]
        self.financialize(value, owners)
        selection.chmod(0o600); selection.write_bytes(canonical(value))
        selection.chmod(0o400)
        with self.assertRaisesRegex(
                durable.Refused, 'known-abort-or-consumed-source-owner-root'):
            durable.read_selection(selection)


if __name__ == '__main__':
    unittest.main()
