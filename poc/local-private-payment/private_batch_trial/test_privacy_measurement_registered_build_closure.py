#!/usr/bin/env python3
"""Registered build closure for retained sealed measurement outputs."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
REGISTERED_BUILD = (
    HERE.parent / 'mpc-prover' / 'financial' /
    'build_registered_financial.py')


class MeasurementRegisteredBuildClosureControls(unittest.TestCase):
    def compile(self, output, *sources):
        return subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread', *(str(source) for source in sources),
            '-I', str(HERE), '-lcrypto', '-o', str(output),
        ], capture_output=True, text=True, check=False)

    def test_both_transitive_units_are_explicit_and_individually_required(self):
        output_unit = (
            '../private_batch_trial/'
            'privacy_measurement_child_output_authority.cpp')
        abi_unit = (
            '../private_batch_trial/privacy_measurement_output_abi.cpp')

        with tempfile.TemporaryDirectory(
                prefix='kpb-measurement-registered-closure-') as directory:
            directory = Path(directory)
            main = directory / 'main.cpp'
            main.write_text(
                '#include "privacy_measurement_authority.hpp"\n'
                'int main() {}\n', encoding='utf-8')
            authority = HERE / 'privacy_measurement_authority.cpp'
            output = HERE / 'privacy_measurement_child_output_authority.cpp'
            abi = HERE / 'privacy_measurement_output_abi.cpp'

            missing_output = self.compile(
                directory / 'missing-output', main, authority, abi)
            self.assertNotEqual(missing_output.returncode, 0)
            self.assertIn('SealedChildOutputAuthority',
                          missing_output.stderr)

            missing_abi = self.compile(
                directory / 'missing-abi', main, authority, output)
            self.assertNotEqual(missing_abi.returncode, 0)
            self.assertIn('measurement_output_abi', missing_abi.stderr)

            complete = self.compile(
                directory / 'complete', main, authority, output, abi)
            self.assertEqual(complete.returncode, 0,
                             complete.stdout + complete.stderr)

        build = REGISTERED_BUILD.read_text(encoding='utf-8')
        self.assertEqual(build.count("'" + output_unit + "'"), 1)
        self.assertEqual(build.count("'" + abi_unit + "'"), 1)


if __name__ == '__main__':
    unittest.main()
