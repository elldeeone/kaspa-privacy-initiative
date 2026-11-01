#!/usr/bin/env python3
"""Runtime controls for the one-shot registered P1 capture-plan split."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
MPC = FINANCIAL.parent
ROOT = MPC.parents[2]
VENDOR = ROOT / '.local' / 'mpc-prover-softspoken-vendor'
MP_SPDZ = VENDOR / 'MP-SPDZ'
PREFIX = VENDOR / 'prefix' / 'usr'
MCL = VENDOR / 'mcl'


class RegisteredP1CaptureBridgeControls(unittest.TestCase):
    def test_wrong_role_wrong_plan_and_replay_burn_authorities(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-registered-p1-split-controls-') as temporary:
            binary = Path(temporary) / 'controls'
            command = [
                'g++', '-std=c++20', '-march=native', '-Wall', '-Wextra',
                '-Werror', '-Wno-overloaded-virtual', '-pedantic',
                '-DNO_MIXED_CIRCUITS', '-DNO_AVX_OT', '-DUSE_GF2N_LONG',
                '-DMCL_USE_GMP=1', '-DMCL_DONT_USE_XBYAK',
                '-DMCL_FP_BIT=384', '-DMCL_FR_BIT=256', '-DMCL_MSM=0',
                '-DKPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP',
                str(HERE / 'registered_p1_capture_bridge_test.cpp'),
                str(FINANCIAL / 'registered_p1_capture_bridge.cpp'),
                str(FINANCIAL / 'registered_driver_bridge.cpp'),
                str(FINANCIAL / 'registered_capture_session.cpp'),
                str(FINANCIAL / 'baseline_public_effects_collector.cpp'),
                str(FINANCIAL / 'registered_attempt_supervisor.cpp'),
                str(FINANCIAL / 'registered_identity_registry.cpp'),
                str(FINANCIAL / 'docker_monotonic_anchor_client.cpp'),
                str(MPC / 'p1_capturing_player.cpp'),
                str(MPC / 'p1_capture_stream.cpp'),
                str(MPC.parent / 'private_batch_trial' /
                    'privacy_capture_hook.cpp'),
                '-I', str(MPC), '-I', str(MP_SPDZ),
                '-I', str(MP_SPDZ / 'deps'),
                '-I', str(MP_SPDZ / 'local' / 'include'),
                '-I', str(PREFIX / 'include'),
                '-I', str(PREFIX / 'include' / 'x86_64-linux-gnu'),
                '-I', str(MCL / 'include'),
                '-L', str(MP_SPDZ), '-Wl,-rpath,' + str(MP_SPDZ),
                '-L', str(PREFIX / 'lib' / 'x86_64-linux-gnu'),
                '-Wl,-rpath,' + str(PREFIX / 'lib' /
                                    'x86_64-linux-gnu'),
                '-L', str(MCL / 'lib'), '-lSPDZ', '-lmcl', '-lcrypto',
                '-lgmpxx', '-lgmp', '-pthread', '-o', str(binary),
            ]
            compiled = subprocess.run(
                command, capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            result = subprocess.run(
                [str(binary)], capture_output=True, text=True,
                timeout=20, check=False)
            self.assertEqual(result.returncode, 0,
                             result.stdout + result.stderr)
            self.assertEqual((result.stdout, result.stderr), ('', ''))


if __name__ == '__main__':
    unittest.main()
