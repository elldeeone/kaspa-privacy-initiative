#!/usr/bin/env python3
"""Controls for the compile-selected, never-authoritative P1 qualifier."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest


HERE = Path(__file__).resolve().parent
MPC = HERE.parent.parent
ROOT = MPC.parents[2]
MP_SPDZ = ROOT / '.local' / 'mpc-prover-vendor' / 'MP-SPDZ'
PREFIX = ROOT / '.local' / 'mpc-prover-vendor' / 'prefix' / 'usr'
MCL = ROOT / '.local' / 'mpc-prover-vendor' / 'mcl'
PRIVATE_TRIAL = MPC.parent / 'private_batch_trial'
sys.path.insert(0, str(PRIVATE_TRIAL))

import privacy_acceptance as acceptance
import privacy_capture_bundle as bundle

RUNNER_PATH = MPC / 'financial/run_financial.py'
RUNNER_SPEC = importlib.util.spec_from_file_location(
    'control_only_p1_run_financial', RUNNER_PATH)
runner = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(runner)


def compile_command(binary, *, selected):
    command = [
        'g++', '-std=c++20', '-march=native', '-Wall', '-Wextra',
        '-Werror', '-Wno-overloaded-virtual', '-pedantic',
        '-DNO_MIXED_CIRCUITS', '-DNO_AVX_OT', '-DUSE_GF2N_LONG',
        '-DMCL_USE_GMP=1', '-DMCL_DONT_USE_XBYAK',
        '-DMCL_FP_BIT=384', '-DMCL_FR_BIT=256', '-DMCL_MSM=0',
    ]
    if selected:
        command.append('-DKPI_P1_UNREGISTERED_QUALIFIER=1')
    command += [
        str(HERE / 'unregistered_p1_capture_qualifier_test.cpp'),
        str(MPC / 'financial/unregistered_p1_capture_qualifier.cpp'),
        str(MPC / 'p1_capturing_player.cpp'),
        str(MPC / 'p1_capture_stream.cpp'),
        str(MPC / 'bn254_values.cpp'),
        '-I', str(MPC), '-I', str(MP_SPDZ),
        '-I', str(PREFIX / 'include'),
        '-I', str(PREFIX / 'include/x86_64-linux-gnu'),
        '-I', str(MCL / 'include'),
        '-L', str(MP_SPDZ), '-Wl,-rpath,' + str(MP_SPDZ),
        '-L', str(PREFIX / 'lib/x86_64-linux-gnu'),
        '-Wl,-rpath,' + str(PREFIX / 'lib/x86_64-linux-gnu'),
        '-L', str(MCL / 'lib'), '-lSPDZ', '-lmcl', '-lcrypto',
        '-lgmpxx', '-lgmp', '-pthread', '-o', str(binary),
    ]
    return command


class UnregisteredP1CaptureQualifierControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-unregistered-p1-qualifier-controls-')
        cls.binary = Path(cls.temporary.name) / 'control'

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_compile_selected_capability_is_one_shot_and_control_only(self):
        compiled = subprocess.run(
            compile_command(self.binary, selected=True),
            capture_output=True, text=True, check=False)
        self.assertEqual(compiled.returncode, 0,
                         compiled.stdout + compiled.stderr)
        run = subprocess.run([str(self.binary)], capture_output=True,
                             check=False, timeout=10)
        self.assertEqual((run.returncode, run.stderr), (0, b''))
        self.assertTrue(run.stdout.startswith(b'KPBP1C03'))

    def test_invalid_scope_role_fd_or_actual_request_refuses_before_output(self):
        if not self.binary.exists():
            self.skipTest('selected compile belongs to previous vertical slice')
        for scenario in ('actual', 'scope', 'fd', 'party', 'manifest'):
            with self.subTest(scenario=scenario):
                run = subprocess.run([str(self.binary), scenario],
                                     capture_output=True, check=False,
                                     timeout=5)
                self.assertEqual((run.returncode, run.stdout, run.stderr),
                                 (0, b'', b''))

    def test_normal_build_cannot_link_the_control_only_minter(self):
        binary = Path(self.temporary.name) / 'not-selected'
        compiled = subprocess.run(
            compile_command(binary, selected=False),
            capture_output=True, text=True, check=False)
        self.assertNotEqual(compiled.returncode, 0)
        self.assertFalse(binary.exists())

    def test_financial_build_keeps_capture_in_a_distinct_control_binary(self):
        build = (MPC / 'financial/build_financial.py').read_text()
        gate = (MPC / 'financial/gate_main.cpp').read_text()
        self.assertIn("'mpc-financial-capture-qualification'", build)
        self.assertIn("'-DKPI_P1_UNREGISTERED_QUALIFIER=1'", build)
        self.assertIn("'financial/unregistered_p1_capture_qualifier.cpp'",
                      build)
        self.assertIn("('mpc-financial-qualification',", build)
        self.assertIn('#if KPI_P1_UNREGISTERED_QUALIFIER == 1', gate)
        self.assertIn('ControlOnlyUnregisteredP1Capture::admit', gate)
        self.assertIn('control-only-p1-capture.sock', gate)
        released = gate.index('const auto released =')
        completed = gate.index('context.complete_p1_capture()', released)
        output = gate.index('write_bytes("released-core.bin"', released)
        self.assertLess(released, completed)
        self.assertLess(completed, output)
        self.assertIn(
            '\\"p1_capture_classification\\":\\"CONTROL_ONLY_UNREGISTERED\\"',
            gate)
        self.assertIn('\\"p1_capture_actual_authority\\":false', gate)

    def test_runner_selects_exactly_one_binary_profile_by_digest(self):
        normal = Path(self.temporary.name) / 'normal-profile'
        capture = Path(self.temporary.name) / 'capture-profile'
        normal.write_bytes(b'normal')
        capture.write_bytes(b'capture')
        build = {
            'compile': [
                {'source': 'financial/gate_main.cpp', 'profile': 'normal'},
                {'source': 'financial/gate_main.cpp',
                 'profile': 'control-only-p1'},
                {'source': 'financial/unregistered_p1_capture_qualifier.cpp',
                 'profile': 'control-only-p1'},
            ],
            'link': [
                {'binary': 'mpc-financial-qualification',
                 'sha256': runner.digest(normal),
                 'argv': ['g++', 'financial_gate_main.cpp.o']},
                {'binary': 'mpc-financial-capture-qualification',
                 'sha256': runner.digest(capture),
                 'argv': ['g++', 'financial_gate_main.cpp.control-p1.o',
                          'financial_unregistered_p1_capture_qualifier.cpp.control-p1.o']},
            ],
        }
        self.assertEqual(
            runner.select_binary_profile(build, normal, False)['binary'],
            'mpc-financial-qualification')
        self.assertEqual(
            runner.select_binary_profile(build, capture, True)['binary'],
            'mpc-financial-capture-qualification')
        for path, control_only in ((capture, False), (normal, True)):
            with self.subTest(path=path.name, control_only=control_only):
                with self.assertRaises(RuntimeError):
                    runner.select_binary_profile(build, path, control_only)

    def test_runner_has_no_implicit_or_actual_capture_mode(self):
        source = RUNNER_PATH.read_text()
        self.assertIn("parser.add_argument('--control-only-p1-capture'",
                      source)
        self.assertIn('CONTROL_ONLY_UNREGISTERED', source)
        self.assertIn('capture_raw_body_read_or_hashed_by_controller', source)
        self.assertNotIn('--actual-p1-capture', source)
        self.assertNotIn("payment_privacy_qualified': True", source)

    def test_all_direct_runner_profiles_refuse_before_side_effects(self):
        for control_only in (False, True):
            with self.subTest(control_only=control_only):
                output = (Path(self.temporary.name) /
                          ('must-not-exist-' + str(control_only)))
                command = [
                    sys.executable, str(RUNNER_PATH),
                    '--binary', '/absent/binary',
                    '--owner-client', '/absent/owner-client',
                    '--verifier', '/absent/verifier',
                    '--model', '/absent/model',
                    '--trace', '/absent/trace',
                    '--native-parameters', '/absent/parameters',
                    '--vendor-root', '/absent/vendor',
                    '--output-parent', str(output),
                    '--owner-input-file', '/absent/owner-0',
                    '--owner-input-file', '/absent/owner-1',
                    '--owner-input-file', '/absent/owner-2',
                ]
                if control_only:
                    command.append('--control-only-p1-capture')
                completed = subprocess.run(
                    command, capture_output=True, text=True, check=False)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(
                    'financial-runner-durable-registered-admission-unavailable',
                    completed.stderr)
                self.assertFalse(output.exists())
        source = RUNNER_PATH.read_text()
        refusal = source.index(
            'financial-runner-durable-registered-admission-unavailable')
        self.assertLess(refusal, source.index('.resolve()', refusal))
        self.assertLess(refusal, source.index('FinancialAttempt(args)',
                                              refusal))

    def test_imported_attempt_constructor_cannot_bypass_cli_refusal(self):
        output = Path(self.temporary.name) / 'import-must-not-create'
        args = types.SimpleNamespace(
            output_parent=output,
            run_id='12' * 32,
        )
        with self.assertRaisesRegex(
                RuntimeError,
                'financial-runner-durable-registered-admission-unavailable'):
            runner.FinancialAttempt(args)
        self.assertFalse(output.exists())
        forged = object.__new__(runner.FinancialAttempt)
        with self.assertRaisesRegex(
                RuntimeError,
                'financial-runner-durable-registered-admission-unavailable'):
            forged.execute()

    def test_actual_bundle_and_acceptance_reject_control_receipt(self):
        receipt = {
            'schema': 'kpb-p1-control-only-unregistered-qualifier/v1',
            'scope': 'PUBLIC_UNFUNDED_UNREGISTERED_QUALIFICATION_ONLY',
            'classification': 'CONTROL_ONLY_UNREGISTERED',
            'configured': False,
            'registered_driver_integrated': False,
            'producer_integrated': False,
            'launch_authorized': False,
            'actual_receipt_enabled': False,
            'serialized_receipt_is_authority': False,
        }
        with self.assertRaises((RuntimeError, ValueError)):
            bundle.validate_capture_launch(
                receipt, '00' * 32, '01' * 32, {}, Path('/absent'),
                '02' * 32, {}, '03' * 32)
        with self.assertRaises((RuntimeError, ValueError, KeyError)):
            acceptance.evaluate(receipt, receipt, receipt)
        self.assertNotIn('ACTUAL_', json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    unittest.main()
