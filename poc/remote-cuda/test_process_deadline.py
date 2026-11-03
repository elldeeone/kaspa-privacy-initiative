"""Real process-group controls; no GPU, network, credentials or proving."""
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from process_deadline import command


def dead(pid):
    try:
        return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0] in ('Z', 'X')
    except FileNotFoundError:
        return True


class ProcessDeadline(unittest.TestCase):
    def test_invalid_duration_rejects_without_starting_any_process(self):
        for value in (True, 0, -1, math.inf, -math.inf, math.nan):
            with self.subTest(value=value), self.assertRaises(ValueError):
                command(value, ['sleep', '1'])

    def test_foreign_group_refuses_before_child_creation(self):
        # Its parent is this test, so this Popen is not the session leader.
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'must-not-exist'
            child = [sys.executable, '-c', f'from pathlib import Path;Path({str(marker)!r}).touch()']
            result = subprocess.run(command(1, child), capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('must own a new session', result.stderr)
            self.assertFalse(marker.exists())

    def test_normal_exit_preserves_exact_status(self):
        for status in (0, 7):
            result = subprocess.run(command(3, [sys.executable, '-c', f'raise SystemExit({status})']),
                                    start_new_session=True, timeout=5)
            self.assertEqual(result.returncode, status)

    def test_deadline_kills_nested_group_and_preserves_completed_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pid = root / 'grandchild'
            saved = root / 'completed'
            code = ('import subprocess,time;from pathlib import Path;'
                    'p=subprocess.Popen(["sleep","30"]);'
                    f'Path({str(pid)!r}).write_text(str(p.pid));'
                    f'Path({str(saved)!r}).write_bytes(b"retained");time.sleep(30)')
            guard = subprocess.Popen(command(.8, [sys.executable, '-c', code]), start_new_session=True)
            try:
                self.assertEqual(guard.wait(timeout=4), -signal.SIGKILL)
                self.assertEqual(saved.read_bytes(), b'retained')
                self.assertTrue(dead(int(pid.read_text())))
            finally:
                if guard.poll() is None:
                    os.killpg(guard.pid, signal.SIGKILL)
                    guard.wait()

    def test_early_parent_exit_does_not_leave_background_child(self):
        with tempfile.TemporaryDirectory() as directory:
            pid = Path(directory) / 'child'
            code = ('import subprocess;from pathlib import Path;p=subprocess.Popen(["sleep","30"]);'
                    f'Path({str(pid)!r}).write_text(str(p.pid))')
            guard = subprocess.Popen(command(3, [sys.executable, '-c', code]), start_new_session=True)
            try:
                self.assertEqual(guard.wait(timeout=5), -signal.SIGKILL)
                self.assertTrue(dead(int(pid.read_text())))
            finally:
                if guard.poll() is None:
                    os.killpg(guard.pid, signal.SIGKILL)
                    guard.wait()


if __name__ == '__main__':
    unittest.main()
