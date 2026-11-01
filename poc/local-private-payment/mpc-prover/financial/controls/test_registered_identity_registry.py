#!/usr/bin/env python3
"""Compiled adversarial controls for the durable public-identity registry."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent


class RegisteredIdentityRegistryControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-registered-identity-controls-')
        cls.binary = Path(cls.temporary.name) / 'registered-identity-controls'
        compile_result = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-DKPI_REGISTERED_IDENTITY_UNFUNDED_SETUP',
            str(HERE / 'registered_identity_registry_test.cpp'),
            str(FINANCIAL / 'registered_identity_registry.cpp'),
            '-I', str(FINANCIAL), '-lcrypto', '-pthread',
            '-o', str(cls.binary),
        ], capture_output=True, text=True, check=False)
        if compile_result.returncode:
            raise AssertionError(compile_result.stdout + compile_result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_control(self, name):
        result = subprocess.run([str(self.binary), name],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, '')

    def test_fresh_restart(self):
        self.run_control('fresh-restart')

    def test_reuse_and_omission(self):
        self.run_control('reuse-and-omission')

    def test_aborted_run(self):
        self.run_control('aborted-run')

    def test_authority_drift(self):
        self.run_control('authority-drift')

    def test_storage_tamper(self):
        self.run_control('storage-tamper')

    def test_crash_boundaries(self):
        self.run_control('crash-boundaries')

    def test_coordinated_rollback_boundary(self):
        self.run_control('coordinated-rollback-boundary')

    def test_concurrent_consumption(self):
        self.run_control('concurrent-consumption')

    def test_exec_child_fd_isolation(self):
        self.run_control('exec-child-fd-isolation')

    def test_source_boundary(self):
        self.run_control('source-boundary')


if __name__ == '__main__':
    unittest.main()
