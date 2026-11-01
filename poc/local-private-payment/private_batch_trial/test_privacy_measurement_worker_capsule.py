#!/usr/bin/env python3
"""Controls for sealed, role-scoped measurement worker capsules."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class MeasurementWorkerCapsuleControls(unittest.TestCase):
    def compile(self, output, *sources, test_setup=False):
        command = [
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread',
        ]
        if test_setup:
            command.extend([
                '-DKPB_MEASUREMENT_AUTHORITY_TEST_SETUP',
                '-DKPB_MEASUREMENT_WORKER_CAPSULE_TEST_SETUP',
            ])
        command.extend(str(source) for source in sources)
        command.extend(['-I', str(HERE), '-lcrypto', '-o', str(output)])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def test_canonical_capsules_are_role_and_owner_scoped(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-measurement-worker-capsule-') as directory:
            directory = Path(directory)
            fixture = directory / 'static-fixture'
            fixture_compile = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-static', '-s',
                str(HERE / 'privacy_measurement_capsule_static_fixture.cpp'),
                '-o', str(fixture),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(fixture_compile.returncode, 0,
                             fixture_compile.stdout + fixture_compile.stderr)
            binary = directory / 'control'
            compiled = self.compile(
                binary,
                HERE / 'privacy_measurement_worker_capsule_control.cpp',
                HERE / 'privacy_measurement_worker_capsule.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp',
                test_setup=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run(
                [str(binary), str(fixture), str(binary)], capture_output=True,
                                 text=True, check=False, timeout=10)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_production_has_no_raw_input_endpoint_minter(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-measurement-worker-capsule-production-') as directory:
            directory = Path(directory)
            source = directory / 'forbidden.cpp'
            source.write_text(r'''
#include "privacy_measurement_worker_capsule.hpp"
using namespace kpb::measurement::runtime_bridge;
int main() {
    auto endpoint = MeasurementInputEndpointAuthority::test_only_mint(
        MeasurementInputKind::ObserverCapture, NO_OWNER, 3, {});
    (void)endpoint;
}
''', encoding='utf-8')
            compiled = self.compile(
                directory / 'forbidden', source,
                HERE / 'privacy_measurement_worker_capsule.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp')
            self.assertNotEqual(compiled.returncode, 0,
                                'raw endpoint minter compiled in production')
            self.assertIn('test_only_mint', compiled.stderr)


if __name__ == '__main__':
    unittest.main()
