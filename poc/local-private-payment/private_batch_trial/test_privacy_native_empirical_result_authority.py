#!/usr/bin/env python3
"""Hostile controls for the native empirical-result authority."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class NativeEmpiricalResultAuthorityControls(unittest.TestCase):
    def compile(self, source):
        return subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-fsyntax-only', '-I', str(HERE), str(source),
        ], capture_output=True, text=True, check=False)

    def source(self, directory, name, value):
        path = Path(directory) / name
        path.write_text(value, encoding='utf-8')
        return path

    def test_sealed_history_and_frozen_candidates_derive_once(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-native-empirical-runtime-') as directory:
            binary = Path(directory) / 'control'
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-pthread',
                '-DKPB_NATIVE_EMPIRICAL_RESULT_TEST_SETUP',
                str(HERE /
                    'privacy_native_empirical_result_authority_control.cpp'),
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

    def test_surface_has_no_raw_receipt_body_hash_or_count_input(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-native-empirical-surface-') as directory:
            source = self.source(directory, 'surface.cpp', r'''
#include "privacy_native_empirical_result_authority.hpp"
#include <array>
#include <concepts>
#include <utility>
using namespace kpb::measurement::empirical_result;
template<class T> concept HasReceipt = requires(const T& v) {
    v.public_receipt();
};
template<class T> concept HasFd = requires(T& v) { v.fd(); };
template<class T> concept HasBody = requires(const T& v) { v.body(); };
template<class T> concept HasHash = requires(const T& v) { v.hash(); };
template<class T> concept HasCount = requires(const T& v) { v.count(); };
template<class T> concept DigestDerive = requires(T a, T b) {
    NativeEmpiricalResultDeriver::derive(std::move(a), std::move(b));
};
static_assert(!std::default_initializable<EmpiricalCaptureHistoryAuthority>);
static_assert(!std::copy_constructible<EmpiricalCaptureHistoryAuthority>);
static_assert(std::move_constructible<EmpiricalCaptureHistoryAuthority>);
static_assert(!std::default_initializable<FrozenEmpiricalCandidateSetAuthority>);
static_assert(!std::copy_constructible<FrozenEmpiricalCandidateSetAuthority>);
static_assert(std::move_constructible<FrozenEmpiricalCandidateSetAuthority>);
static_assert(!std::default_initializable<NativeEmpiricalResultAuthority>);
static_assert(!std::copy_constructible<NativeEmpiricalResultAuthority>);
static_assert(std::move_constructible<NativeEmpiricalResultAuthority>);
static_assert(!HasReceipt<NativeEmpiricalResultAuthority>);
static_assert(!HasFd<NativeEmpiricalResultAuthority>);
static_assert(!HasBody<NativeEmpiricalResultAuthority>);
static_assert(!HasHash<NativeEmpiricalResultAuthority>);
static_assert(!HasCount<NativeEmpiricalResultAuthority>);
static_assert(!DigestDerive<std::array<unsigned char, 32>>);
int main() {}
''')
            compiled = self.compile(source)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

    def test_lookalike_bridge_and_direct_construction_fail(self):
        hostile = {
            'bridge.cpp': r'''
#include "privacy_native_empirical_result_authority.hpp"
namespace kpb::measurement::runtime_bridge {
class ObserverCaptureCapsuleBridge final {};
}
int main() {}
''',
            'direct.cpp': r'''
#include "privacy_native_empirical_result_authority.hpp"
int main() {
    kpb::measurement::empirical_result::NativeEmpiricalResultAuthority x;
}
''',
            'raw.cpp': r'''
#include "privacy_native_empirical_result_authority.hpp"
#include <utility>
#include <vector>
int main() {
    std::vector<unsigned char> a, b;
    (void)kpb::measurement::empirical_result::
        NativeEmpiricalResultDeriver::derive(std::move(a), std::move(b));
}
''',
        }
        with tempfile.TemporaryDirectory(
                prefix='kpb-native-empirical-hostile-') as directory:
            for name, value in hostile.items():
                with self.subTest(name=name):
                    compiled = self.compile(self.source(
                        directory, name, value))
                    self.assertNotEqual(
                        compiled.returncode, 0,
                        'hostile source unexpectedly compiled: ' + name)


if __name__ == '__main__':
    unittest.main()
