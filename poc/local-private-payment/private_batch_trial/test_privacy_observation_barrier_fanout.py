#!/usr/bin/env python3
"""Controls for the nonauthorizing sealed Observer-output FD41 fanout."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class ObservationBarrierFanoutControls(unittest.TestCase):
    def test_live_v3_join_yields_only_open_nonauthorizing_fanout(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-observation-fanout-') as directory:
            binary = Path(directory) / 'control'
            sources = [
                'privacy_observation_barrier_fanout_control.cpp',
                'privacy_observation_barrier_fanout_authority.cpp',
                'privacy_observation_barrier_fanout_bridge.cpp',
                'privacy_native_phase_scope_authority.cpp',
                'privacy_native_empirical_result_authority.cpp',
                'privacy_measurement_child_output_authority.cpp',
                'privacy_measurement_worker_capsule.cpp',
                'privacy_measurement_output_abi.cpp',
                'privacy_measurement_authority.cpp',
            ]
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-pthread',
                '-DKPB_MEASUREMENT_CHILD_OUTPUT_TEST_SETUP',
                '-DKPB_MEASUREMENT_OUTPUT_ABI_TEST_SETUP',
                '-DKPB_NATIVE_EMPIRICAL_RESULT_TEST_SETUP',
                '-DKPB_OBSERVATION_BARRIER_FANOUT_TEST_SETUP',
                *(str(HERE / source) for source in sources),
                '-I', str(HERE), '-lcrypto', '-o', str(binary),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=20)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_production_surface_has_no_receipt_fd_hash_barrier_or_permit(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-observation-fanout-surface-') as directory:
            source = Path(directory) / 'surface.cpp'
            source.write_text(r'''
#include "privacy_observation_barrier_fanout_authority.hpp"
#include <concepts>
#include <utility>
using namespace kpb::measurement::observation_fanout;
template<class T> concept HasReceipt = requires(const T& x) {
    x.public_receipt();
};
template<class T> concept HasFd = requires(T& x) { x.fd(); };
template<class T> concept HasHash = requires(const T& x) { x.content_hash(); };
template<class T> concept HasBarrier = requires(T&& x) {
    std::move(x).take_barrier();
};
template<class T> concept HasPermit = requires(T&& x) {
    std::move(x).take_score_permit();
};
template<class T> concept HasEndpoint = requires(T&& x) {
    std::move(x).take_owner_endpoint(0U);
};
static_assert(!std::default_initializable<OpenObservationFanoutAuthority>);
static_assert(!std::copy_constructible<OpenObservationFanoutAuthority>);
static_assert(std::move_constructible<OpenObservationFanoutAuthority>);
static_assert(!HasReceipt<OpenObservationFanoutAuthority>);
static_assert(!HasFd<OpenObservationFanoutAuthority>);
static_assert(!HasHash<OpenObservationFanoutAuthority>);
static_assert(!HasBarrier<OpenObservationFanoutAuthority>);
static_assert(!HasPermit<OpenObservationFanoutAuthority>);
static_assert(!HasEndpoint<OpenObservationFanoutAuthority>);
int main() {}
''', encoding='utf-8')
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-fsyntax-only', '-I', str(HERE), str(source),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

    def test_exact_bridge_name_cannot_be_redefined(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-observation-fanout-hostile-') as directory:
            source = Path(directory) / 'hostile.cpp'
            source.write_text(r'''
#include "privacy_observation_barrier_fanout_authority.hpp"
namespace kpb::measurement::observation_fanout {
class ObservationBarrierFanoutBridge final {};
}
int main() {}
''', encoding='utf-8')
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-fsyntax-only', '-I', str(HERE), str(source),
            ], capture_output=True, text=True, check=False)
            self.assertNotEqual(compiled.returncode, 0)


if __name__ == '__main__':
    unittest.main()
