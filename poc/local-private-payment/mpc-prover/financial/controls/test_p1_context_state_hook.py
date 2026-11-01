#!/usr/bin/env python3
"""Focused canonical-state controls for the P1 ContextAndRetry hook."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class P1ContextStateHookControls(unittest.TestCase):
    def test_canonical_snapshot_and_hostile_inputs_under_sanitizers(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-p1-context-state-hook-') as temporary:
            binary = Path(temporary) / 'control'
            command = [
                'g++', '-std=c++20', '-O1', '-g0', '-Wall', '-Wextra',
                '-Werror', '-Wpedantic', '-fsanitize=address,undefined',
                '-fno-omit-frame-pointer',
                '-DKPI_P1_CONTEXT_STATE_HOOK_TEST_SETUP',
                str(HERE / 'p1_context_state_hook_test.cpp'),
                '-o', str(binary),
            ]
            compiled = subprocess.run(
                command, capture_output=True, text=True, check=False)
            self.assertEqual(
                compiled.returncode, 0, compiled.stdout + compiled.stderr)
            environment = dict(os.environ)
            environment['ASAN_OPTIONS'] = (
                'detect_leaks=1:halt_on_error=1:abort_on_error=1')
            environment['UBSAN_OPTIONS'] = (
                'halt_on_error=1:print_stacktrace=1')
            result = subprocess.run(
                [str(binary)], capture_output=True, text=True,
                env=environment, timeout=20, check=False)
            self.assertEqual(
                result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((result.stdout, result.stderr), ('', ''))

    def test_arbitrary_raw_state_sink_cannot_be_constructed(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-p1-context-state-hook-negative-') as temporary:
            binary = Path(temporary) / 'must-not-build'
            command = [
                'g++', '-std=c++20', '-O1', '-g0', '-Wall', '-Wextra',
                '-Werror', '-Wpedantic',
                str(HERE / 'p1_context_state_hook_negative.cpp'),
                '-o', str(binary),
            ]
            compiled = subprocess.run(
                command, capture_output=True, text=True, check=False)
            self.assertNotEqual(compiled.returncode, 0)
            self.assertIn('P1ContextAndRetryStateAdapter', compiled.stderr)
            self.assertIn('redefinition', compiled.stderr)
            self.assertFalse(binary.exists())

    def test_forward_recorder_lookalike_cannot_construct_adapter(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-p1-context-recorder-spoof-') as temporary:
            temporary = Path(temporary)
            source = temporary / 'spoof.cpp'
            source.write_text(r'''
#include "p1_context_state_hook.hpp"
#include <memory>
namespace kpb::measurement::p1_state_capsule {
class P1CorruptStateRecorderAuthority final {
public:
    static std::unique_ptr<P1ContextAndRetryStateAdapter> mint() {
        return std::unique_ptr<P1ContextAndRetryStateAdapter>(
            new P1ContextAndRetryStateAdapter(
                std::unique_ptr<
                    P1ContextAndRetryStateAdapter::Storage>{}));
    }
};
}
int main() {
    auto forged = kpb::measurement::p1_state_capsule::
        P1CorruptStateRecorderAuthority::mint();
    (void)forged;
}
''', encoding='utf-8')
            output = temporary / 'spoof.o'
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-Wpedantic', '-I', str(HERE.parent.parent), '-c',
                str(source), '-o', str(output),
            ], capture_output=True, text=True, check=False)
            self.assertNotEqual(compiled.returncode, 0)
            self.assertIn('Storage', compiled.stderr)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
