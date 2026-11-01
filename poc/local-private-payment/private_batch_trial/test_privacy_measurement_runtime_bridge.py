#!/usr/bin/env python3
"""Controls for the source-pinned measurement child-completion bridge."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class MeasurementRuntimeBridgeControls(unittest.TestCase):
    def compile(self, output, *sources, test_setup=False):
        command = [
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread',
        ]
        if test_setup:
            command.extend([
                '-DKPB_MEASUREMENT_RUNTIME_BRIDGE_TEST_SETUP',
                '-DKPB_MEASUREMENT_AUTHORITY_TEST_SETUP',
                '-DKPB_MEASUREMENT_CHILD_OUTPUT_TEST_SETUP',
                '-DKPB_MEASUREMENT_OUTPUT_ABI_TEST_SETUP',
                '-DKPB_NATIVE_EMPIRICAL_RESULT_TEST_SETUP',
            ])
        command.extend(str(source) for source in sources)
        command.extend(['-I', str(HERE), '-lcrypto', '-o', str(output)])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def test_child_completion_evidence_is_exact_and_one_shot(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-measurement-runtime-bridge-') as directory:
            binary = Path(directory) / 'controls'
            compiled = self.compile(
                binary,
                HERE / 'privacy_measurement_runtime_bridge_control.cpp',
                HERE / 'privacy_measurement_runtime_bridge.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp',
                HERE / 'privacy_native_phase_scope_authority.cpp',
                HERE / 'privacy_native_empirical_result_authority.cpp',
                test_setup=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=10)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_production_cannot_mint_or_construct_child_evidence(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-measurement-runtime-no-mint-') as directory:
            directory = Path(directory)
            source = directory / 'forbidden.cpp'
            source.write_text(r'''
#include "privacy_measurement_runtime_bridge.hpp"
using namespace kpb::measurement::runtime_bridge;
int main() {
    PublicRuntimeChildCompletion value{};
    auto authority = ChildCompletionEvidenceAuthority::test_only_mint(value);
    (void)authority;
}
''', encoding='utf-8')
            compiled = self.compile(
                directory / 'forbidden', source,
                HERE / 'privacy_measurement_runtime_bridge.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp',
                HERE / 'privacy_native_phase_scope_authority.cpp',
                HERE / 'privacy_native_empirical_result_authority.cpp')
            self.assertNotEqual(compiled.returncode, 0,
                                'test-only evidence mint compiled in production')
            self.assertIn('test_only_mint', compiled.stderr)


if __name__ == '__main__':
    unittest.main()
