"""CPU-only regression, including a real Linux zombie; no GPU/prover use."""
import os
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest

from pid_lifecycle import WorkerLifecycle, evaluate_gpu_topology, read_identity


class LifecycleTests(unittest.TestCase):
    def test_real_verified_worker_exit_keeps_identity_and_reported_allocation(self):
        read_fd, write_fd = os.pipe()
        child = subprocess.Popen([sys.executable, '-c',
            'import os,sys; os.read(int(sys.argv[1]),1); os._exit(0)',
            str(read_fd), '--config', 'public-regression-only'], pass_fds=(read_fd,))
        os.close(read_fd)
        try:
            live = read_identity(child.pid)
            self.assertIsNotNone(live)
            tracker = WorkerLifecycle(str(Path(sys.executable).resolve()))
            tracker.register_expected(live, owned=True, role='primary')
            before = tracker.classify(live, owned=True)
            self.assertEqual(before['status'], 'expected_live_worker')
            os.write(write_fd, b'x')
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                dead = read_identity(child.pid)
                if dead and dead['state'] == 'Z':
                    break
                time.sleep(0.005)
            else:
                self.fail('child did not enter zombie state before generous deadline')
            self.assertEqual(dead['start_ticks'], live['start_ticks'])
            self.assertIsNone(dead['exe'])
            self.assertEqual(dead['cmdline'], '')
            outcome = evaluate_gpu_topology([{'pid': child.pid, 'used_mib': 1552}],
                {child.pid: dead}, tracker, owned_pids={child.pid})
            self.assertFalse(outcome['stop_owned_unit'])
            self.assertTrue(outcome['resource_evidence_complete'])
            self.assertEqual(outcome['summed_reported_mib'], 1552)
            self.assertEqual(outcome['classifications'][0]['status'], 'known_exited_stale_gpu_sample')
            print(json.dumps({'regression': 'real_linux_zombie', 'live': live,
                              'exited': dead, 'outcome': outcome}, sort_keys=True))
        finally:
            os.close(write_fd)
            if read_identity(child.pid) and read_identity(child.pid)['state'] != 'Z':
                child.kill()
            child.wait(timeout=10)

    def sample(self, **changes):
        return dict({'pid': 123, 'start_ticks': 456, 'state': 'S',
                     'exe': '/qualified/r0vm', 'cmdline': '/qualified/r0vm --config public.json'}, **changes)

    def test_live_foreign_executable_stops(self):
        result = WorkerLifecycle('/qualified/r0vm').classify(self.sample(exe='/foreign/process'), owned=True)
        self.assertTrue(result['stop_owned_unit'])

    def test_rpc_parent_on_gpu_stops(self):
        result = WorkerLifecycle('/qualified/r0vm').classify(self.sample(cmdline='/qualified/r0vm --rpc'), owned=True)
        self.assertTrue(result['stop_owned_unit'])

    def test_reused_pid_stops(self):
        tracker = WorkerLifecycle('/qualified/r0vm')
        tracker.register_expected(self.sample(), owned=True, role='primary')
        self.assertTrue(tracker.classify(self.sample(start_ticks=457), owned=True)['stop_owned_unit'])

    def test_unregistered_live_worker_is_incomplete(self):
        result = WorkerLifecycle('/qualified/r0vm').classify(self.sample(), owned=True)
        self.assertFalse(result['resource_evidence_complete'])

    def test_unknown_exited_identity_is_incomplete(self):
        result = WorkerLifecycle('/qualified/r0vm').classify(self.sample(state='Z', exe=None, cmdline=''), owned=True)
        self.assertFalse(result['resource_evidence_complete'])

    def test_missing_live_metadata_is_incomplete(self):
        tracker = WorkerLifecycle('/qualified/r0vm')
        for identity in [None, self.sample(exe=None, cmdline='')]:
            self.assertFalse(tracker.classify(identity, owned=True)['resource_evidence_complete'])

    def test_unowned_identity_stops(self):
        self.assertTrue(WorkerLifecycle('/qualified/r0vm').classify(self.sample(), owned=False)['stop_owned_unit'])

    def test_third_gpu_process_stops(self):
        rows = [{'pid': p, 'used_mib': 1} for p in [1, 2, 3]]
        identities = {p: self.sample(pid=p) for p in [1, 2, 3]}
        result = evaluate_gpu_topology(rows, identities, WorkerLifecycle('/qualified/r0vm'), owned_pids={1, 2, 3})
        self.assertTrue(result['stop_owned_unit'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
