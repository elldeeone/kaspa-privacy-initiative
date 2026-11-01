#!/usr/bin/env python3
"""Compile-time hostile controls for the native phase-scope boundary."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class NativePhaseScopeAuthorityControls(unittest.TestCase):
    def compile(self, source):
        return subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-fsyntax-only', '-I', str(HERE), str(source),
        ], capture_output=True, text=True, check=False)

    def source(self, directory, name, value):
        path = Path(directory) / name
        path.write_text(value, encoding='utf-8')
        return path

    def test_genuine_v3_output_and_empirical_residual_join_once(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-native-phase-runtime-') as directory:
            binary = Path(directory) / 'control'
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-pthread',
                '-DKPB_MEASUREMENT_CHILD_OUTPUT_TEST_SETUP',
                '-DKPB_MEASUREMENT_OUTPUT_ABI_TEST_SETUP',
                '-DKPB_NATIVE_EMPIRICAL_RESULT_TEST_SETUP',
                str(HERE / 'privacy_native_phase_scope_authority_control.cpp'),
                str(HERE / 'privacy_native_phase_scope_authority.cpp'),
                str(HERE / 'privacy_native_empirical_result_authority.cpp'),
                str(HERE / 'privacy_measurement_child_output_authority.cpp'),
                str(HERE / 'privacy_measurement_output_abi.cpp'),
                str(HERE / 'privacy_measurement_authority.cpp'),
                '-I', str(HERE), '-lcrypto', '-o', str(binary),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=15)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_move_only_surface_has_no_receipt_fd_body_or_hash_getter(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-native-phase-surface-') as directory:
            source = self.source(directory, 'surface.cpp', r'''
#include "privacy_native_phase_scope_authority.hpp"
#include <array>
#include <concepts>
#include <utility>
using namespace kpb::measurement;
using namespace kpb::measurement::phase_scope;
template<class T> concept HasPublicReceipt = requires(const T& value) {
    value.public_receipt();
};
template<class T> concept HasFd = requires(T& value) { value.fd(); };
template<class T> concept HasBody = requires(const T& value) { value.body(); };
template<class T> concept HasHash = requires(const T& value) {
    value.content_hash();
};
template<class T> concept HasPredictionPermit = requires(T&& value) {
    std::move(value).take_prediction_permit();
};
template<class T> concept HasBarrier = requires(T&& value) {
    std::move(value).take_barrier();
};
template<class T> concept HasStep2 = requires(T&& value) {
    std::move(value).take_step2();
};
static_assert(!std::default_initializable<ObservationOutputJoinAuthority>);
static_assert(!std::copy_constructible<ObservationOutputJoinAuthority>);
static_assert(std::move_constructible<ObservationOutputJoinAuthority>);
static_assert(!HasPublicReceipt<ObservationOutputJoinAuthority>);
static_assert(!HasFd<ObservationOutputJoinAuthority>);
static_assert(!HasBody<ObservationOutputJoinAuthority>);
static_assert(!HasHash<ObservationOutputJoinAuthority>);
static_assert(!HasPredictionPermit<ObservationOutputJoinAuthority>);
static_assert(!HasBarrier<ObservationOutputJoinAuthority>);
static_assert(!HasStep2<ObservationOutputJoinAuthority>);
int main() {}
''')
            compiled = self.compile(source)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

    def test_exact_bridge_redefinition_and_receipt_body_substitutes_fail(self):
        hostile_sources = {
            'bridge_redefinition.cpp': r'''
#include "privacy_native_phase_scope_authority.hpp"
namespace kpb::measurement::phase_scope {
class NativePrivacyPhaseScopeBridge final {};
}
int main() {}
''',
            'receipt_substitute.cpp': r'''
#include "privacy_native_phase_scope_authority.hpp"
#include "privacy_measurement_child_output_authority.hpp"
#include <utility>
int main() {
    kpb::measurement::runtime_bridge::PrivateChildOutputCompletion receipt{};
    (void)kpb::measurement::phase_scope::NativePrivacyPhaseScopeBridge::
        validate_for_observation(
        std::move(receipt));
}
''',
            'body_substitute.cpp': r'''
#include "privacy_native_phase_scope_authority.hpp"
#include <utility>
#include <vector>
int main() {
    std::vector<unsigned char> body(151552);
    (void)kpb::measurement::phase_scope::NativePrivacyPhaseScopeBridge::
        validate_for_observation(
        std::move(body));
}
''',
            'direct_permit.cpp': r'''
#include "privacy_native_phase_scope_authority.hpp"
int main() {
    kpb::measurement::phase_scope::ObservationOutputJoinAuthority joined;
}
''',
        }
        with tempfile.TemporaryDirectory(
                prefix='kpb-native-phase-hostile-') as directory:
            for name, value in hostile_sources.items():
                with self.subTest(name=name):
                    compiled = self.compile(self.source(
                        directory, name, value))
                    self.assertNotEqual(
                        compiled.returncode, 0,
                        'hostile source unexpectedly compiled: ' + name)


if __name__ == '__main__':
    unittest.main()
