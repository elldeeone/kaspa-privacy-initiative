#!/usr/bin/env python3
"""Controls for the irreversible static-worker bootstrap sandbox."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class MeasurementPreexecSandboxControls(unittest.TestCase):
    def test_host_fs_network_introspection_and_exec_substitution_refuse(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-measurement-preexec-') as directory:
            binary = Path(directory) / 'control'
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic',
                str(HERE / 'privacy_measurement_preexec_sandbox_control.cpp'),
                str(HERE / 'privacy_measurement_preexec_sandbox.cpp'),
                '-I', str(HERE), '-o', str(binary),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=10)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_supervisor_installs_bootstrap_filter_before_exact_exec(self):
        source = (HERE / 'privacy_measurement_child_supervisor.cpp').read_text(
            encoding='utf-8')
        self.assertEqual(
            source.count('install_measurement_preexec_sandbox('), 1)
        install_at = source.index('install_measurement_preexec_sandbox(')
        exec_at = source.index('SYS_execveat', install_at)
        self.assertLess(install_at, exec_at)
        between = source[install_at:exec_at]
        self.assertNotIn('open(', between)
        self.assertNotIn('socket(', between)


if __name__ == '__main__':
    unittest.main()
