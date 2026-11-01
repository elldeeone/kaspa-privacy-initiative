#!/usr/bin/env python3
"""Controls for the terminal-owned final-C03 empirical source."""

from pathlib import Path
import json
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class NativeEmpiricalTerminalSourceControls(unittest.TestCase):
    def test_two_sealed_final_streams_parse_but_cannot_authorize_history(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-native-empirical-terminal-') as directory:
            binary = Path(directory) / 'control'
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-pthread',
                '-DKPB_NATIVE_EMPIRICAL_TERMINAL_SOURCE_TEST_SETUP',
                str(HERE /
                    'privacy_native_empirical_terminal_source_control.cpp'),
                str(HERE /
                    'privacy_native_empirical_terminal_source.cpp'),
                str(HERE / 'privacy_measurement_authority.cpp'),
                str(HERE / 'privacy_measurement_child_output_authority.cpp'),
                str(HERE / 'privacy_measurement_output_abi.cpp'),
                '-I', str(HERE), '-lcrypto', '-o', str(binary),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=20)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_authority_surface_is_opaque_move_only_and_has_no_result_mint(self):
        source = r'''
#include "privacy_native_empirical_terminal_source.hpp"
#include <concepts>
#include <type_traits>
#include <utility>
using namespace kpb::measurement::empirical_terminal_source;
template<class T> concept HasReceipt = requires(const T& v) {
    v.public_receipt();
};
template<class T> concept HasFd = requires(T& v) { v.fd(); };
template<class T> concept HasBody = requires(const T& v) { v.body(); };
template<class T> concept HasHash = requires(const T& v) { v.hash(); };
template<class T> concept HasCount = requires(const T& v) { v.count(); };
template<class T> concept MintsHistory = requires(T&& v) {
    std::forward<T>(v).derive_history();
};
static_assert(!std::copy_constructible<
    TerminalFinalC03ObservationAuthority>);
static_assert(!std::is_copy_assignable_v<
    TerminalFinalC03ObservationAuthority>);
static_assert(std::move_constructible<
    TerminalFinalC03ObservationAuthority>);
static_assert(!HasReceipt<TerminalFinalC03ObservationAuthority>);
static_assert(!HasFd<TerminalFinalC03ObservationAuthority>);
static_assert(!HasBody<TerminalFinalC03ObservationAuthority>);
static_assert(!HasHash<TerminalFinalC03ObservationAuthority>);
static_assert(!HasCount<TerminalFinalC03ObservationAuthority>);
static_assert(!MintsHistory<TerminalFinalC03ObservationAuthority>);
static_assert(kNativeEmpiricalTerminalSourceStatus.exact_final_c03_parser);
static_assert(kNativeEmpiricalTerminalSourceStatus.sealed_two_round_input);
static_assert(kNativeEmpiricalTerminalSourceStatus.opaque_one_shot_final_source);
static_assert(!kNativeEmpiricalTerminalSourceStatus.complete_attempt_history);
static_assert(!kNativeEmpiricalTerminalSourceStatus.empirical_history_minter);
static_assert(!kNativeEmpiricalTerminalSourceStatus.selected_runtime_callsite);
static_assert(!kNativeEmpiricalTerminalSourceStatus.configured);
int main() {}
'''
        with tempfile.TemporaryDirectory(
                prefix='kpb-native-empirical-terminal-surface-') as directory:
            path = Path(directory) / 'surface.cpp'
            path.write_text(source, encoding='utf-8')
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-fsyntax-only', '-I', str(HERE), str(path),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

    def test_complete_bridge_cannot_be_redefined_and_constructor_is_private(self):
        hostile = {
            'bridge.cpp': r'''
#include "privacy_native_empirical_terminal_source.hpp"
namespace kpb::measurement::runtime_bridge {
class ObserverCaptureCapsuleBridge final {};
}
int main() {}
''',
            'constructor.cpp': r'''
#include "privacy_native_empirical_terminal_source.hpp"
#include <array>
using namespace kpb::measurement;
using namespace kpb::measurement::empirical_terminal_source;
int main() {
    RunBinding binding{};
    std::array<FinalC03RoundBinding, 2> rounds{};
    std::array<int, 2> fds{-1, -1};
    TerminalFinalC03ObservationAuthority forged(binding, rounds, fds);
}
''',
        }
        with tempfile.TemporaryDirectory(
                prefix='kpb-native-empirical-terminal-hostile-') as directory:
            for name, value in hostile.items():
                with self.subTest(name=name):
                    path = Path(directory) / name
                    path.write_text(value, encoding='utf-8')
                    compiled = subprocess.run([
                        'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                        '-pedantic', '-fsyntax-only', '-I', str(HERE),
                        str(path),
                    ], capture_output=True, text=True, check=False)
                    self.assertNotEqual(
                        compiled.returncode, 0,
                        'hostile source unexpectedly compiled: ' + name)

    def test_production_object_has_no_test_mint_or_consume_symbol(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-native-empirical-terminal-symbols-') as directory:
            obj = Path(directory) / 'source.o'
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-c',
                str(HERE / 'privacy_native_empirical_terminal_source.cpp'),
                '-I', str(HERE), '-o', str(obj),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            symbols = subprocess.run(
                ['nm', '-C', str(obj)], capture_output=True, text=True,
                check=True).stdout
            self.assertNotIn('test_only_parse', symbols)
            self.assertNotIn('test_only_consume', symbols)

    def test_machine_blocker_names_every_absent_history_fact(self):
        report = json.loads((
            HERE / 'privacy_native_empirical_terminal_missing.json'
        ).read_text(encoding='utf-8'))
        self.assertEqual(set(report), {
            'schema', 'source_status', 'authenticated_final_streams',
            'missing_complete_history_fields', 'blocked_authorities',
        })
        self.assertEqual(
            report['schema'],
            'kpb-native-empirical-terminal-source-missing/v1')
        self.assertEqual(report['source_status'], 'CONFIGURED0')
        self.assertEqual(report['authenticated_final_streams'], [
            {'round': 1, 'fixed_fd': 23, 'archive_slot': 3},
            {'round': 2, 'fixed_fd': 28, 'archive_slot': 8},
        ])
        self.assertEqual(report['missing_complete_history_fields'], [
            'complete_attempt_enumeration',
            'failed_or_partial_c03_raw_streams',
            'retry_ordinal',
            'predecessor_attempt_identity',
            'attempt_start_monotonic_ns',
            'attempt_end_monotonic_ns',
            'attempt_outcome',
            'attempt_failure_code',
            'canonical_five_field_observation_encoding',
            'production_frozen_candidate_set_authority',
        ])
        self.assertEqual(report['blocked_authorities'], [
            'EmpiricalCaptureHistoryAuthority',
            'NativeEmpiricalResultAuthority',
            'ObservationOutputJoinAuthority',
        ])


if __name__ == '__main__':
    unittest.main()
