#!/usr/bin/env python3
"""Controls for the authenticated outer measurement child supervisor."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class MeasurementChildSupervisorControls(unittest.TestCase):
    def compile(self, output, *sources, definitions=(), static=False):
        command = [
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread',
        ]
        if static:
            command.extend([
                '-static', '-ffunction-sections', '-fdata-sections',
                '-Wl,--gc-sections',
            ])
        command.extend(f'-D{definition}' for definition in definitions)
        command.extend(str(source) for source in sources)
        command.extend(['-I', str(HERE)])
        command.append('-lcrypto')
        command.extend(['-o', str(output)])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def test_authenticated_transport_is_exact_and_fail_closed(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-measurement-child-supervisor-') as directory:
            directory = Path(directory)
            common = (
                HERE / 'privacy_measurement_child_supervisor.cpp',
                HERE / 'privacy_measurement_preexec_sandbox.cpp',
                HERE / 'privacy_measurement_worker_capsule.cpp',
                HERE / 'privacy_measurement_runtime_bridge.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_native_phase_scope_authority.cpp',
                HERE / 'privacy_native_empirical_result_authority.cpp',
            )
            workers = {}
            for name, fault in (
                    ('valid', 0),
                    ('wrong_ack', 1),
                    ('wrong_pid', 2),
                    ('credential_relay', 3),
                    ('wrong_role', 4),
                    ('duplicate_completion', 5),
                    ('no_completion', 6),
                    ('wrong_completion_permit', 7),
                    ('wrong_completion_owner', 8),
                    ('wrong_opaque_authority', 9),
                    ('wrong_capsule_authority', 10),
                    ('invalid_result', 11),
                    ('nonzero_exit', 12),
                    ('zero_ack_before_close', 13),
                    ('zero_completion_before_close', 14)):
                worker = directory / f'worker_{name}'
                compiled = self.compile(
                    worker,
                    HERE / 'privacy_measurement_child_supervisor_test_worker.cpp',
                    *common,
                    definitions=(
                        'KPB_MEASUREMENT_AUTHORITY_TEST_SETUP',
                        'KPB_MEASUREMENT_CHILD_SUPERVISOR_TEST_SETUP',
                        'KPB_MEASUREMENT_OUTPUT_ABI_TEST_SETUP',
                        f'KPB_MEASUREMENT_CHILD_TEST_FAULT={fault}',
                    ), static=True)
                self.assertEqual(compiled.returncode, 0,
                                 compiled.stdout + compiled.stderr)
                workers[name] = worker

            control = directory / 'control'
            compiled = self.compile(
                control,
                HERE / 'privacy_measurement_child_supervisor_control.cpp',
                *common,
                definitions=(
                    'KPB_MEASUREMENT_AUTHORITY_TEST_SETUP',
                    'KPB_MEASUREMENT_CHILD_SUPERVISOR_TEST_SETUP',
                    'KPB_MEASUREMENT_WORKER_CAPSULE_TEST_SETUP',
                    'KPB_NATIVE_EMPIRICAL_RESULT_TEST_SETUP',
                ))
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            static_output = directory / 'static-observer'
            built = subprocess.run([
                '/usr/bin/python3.14',
                str(HERE / 'privacy_observer_runtime_build' /
                    'build_static_observer_runtime.py'),
                '--output', str(static_output),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(built.returncode, 0,
                             built.stdout + built.stderr)
            run = subprocess.run(
                [str(control), *(str(workers[name]) for name in workers),
                 str(static_output / 'kpb-static-observer')],
                capture_output=True, text=True, check=False, timeout=20)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_public_receipts_cannot_mint_transport_evidence(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-measurement-child-no-public-mint-') as directory:
            directory = Path(directory)
            source = directory / 'forbidden.cpp'
            source.write_text(r'''
#include "privacy_measurement_child_supervisor.hpp"
using namespace kpb::measurement;
using namespace kpb::measurement::runtime_bridge;
int main() {
    PublicObserverPermit receipt{};
    auto result = MeasurementChildSupervisor::run_observer(receipt, 3);
    (void)result;
}
''', encoding='utf-8')
            compiled = self.compile(
                directory / 'forbidden', source,
                HERE / 'privacy_measurement_child_supervisor.cpp',
                HERE / 'privacy_measurement_preexec_sandbox.cpp',
                HERE / 'privacy_measurement_worker_capsule.cpp',
                HERE / 'privacy_measurement_runtime_bridge.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_native_phase_scope_authority.cpp',
                HERE / 'privacy_native_empirical_result_authority.cpp')
            self.assertNotEqual(compiled.returncode, 0,
                                'public receipt unexpectedly authorized child')
            self.assertIn('run_observer', compiled.stderr)

    def test_production_surface_has_no_test_transport_or_minter(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-measurement-child-production-') as directory:
            directory = Path(directory)
            source = directory / 'production.cpp'
            source.write_text(r'''
#include "privacy_measurement_runtime_bridge.hpp"
#include <type_traits>
using namespace kpb::measurement::runtime_bridge;
static_assert(!std::is_default_constructible_v<
    ChildCompletionEvidenceAuthority>);
static_assert(!std::is_copy_constructible_v<
    ChildCompletionEvidenceAuthority>);
int main() {
    return (!kRuntimeBridgeSourceStatus.authenticated_child_supervisor ||
            kRuntimeBridgeSourceStatus.registered_transport_integrated ||
            kRuntimeBridgeSourceStatus.configured ||
            kRuntimeBridgeSourceStatus.launch_enabled ||
            kRuntimeBridgeSourceStatus.actual_privacy_pass) ? 1 : 0;
}
''', encoding='utf-8')
            binary = directory / 'production'
            compiled = self.compile(
                binary, source,
                HERE / 'privacy_measurement_child_supervisor.cpp',
                HERE / 'privacy_measurement_preexec_sandbox.cpp',
                HERE / 'privacy_measurement_worker_capsule.cpp',
                HERE / 'privacy_measurement_runtime_bridge.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_native_phase_scope_authority.cpp',
                HERE / 'privacy_native_empirical_result_authority.cpp')
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=10)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            symbols = subprocess.run(
                ['nm', '-C', str(binary)], capture_output=True, text=True,
                check=False, timeout=10)
            self.assertEqual(symbols.returncode, 0,
                             symbols.stdout + symbols.stderr)
            self.assertNotIn('test_only_run_measurement_child',
                             symbols.stdout)
            self.assertNotIn('test_only_mint', symbols.stdout)


if __name__ == '__main__':
    unittest.main()
