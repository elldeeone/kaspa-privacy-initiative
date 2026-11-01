#!/usr/bin/env python3
"""Controls for the live observer-admission and immutable-FD40 boundary."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class ObserverCaptureBridgeControls(unittest.TestCase):
    def compile(self, output, *sources, test_setup=False):
        command = [
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread',
        ]
        if test_setup:
            command.extend([
                '-DKPB_MEASUREMENT_AUTHORITY_TEST_SETUP',
                '-DKPB_MEASUREMENT_OBSERVER_CAPTURE_BRIDGE_TEST_SETUP',
                '-DKPB_CAPTURE_PRODUCER_SUPERVISOR_TEST_SETUP',
                '-DKPB_CAPTURE_PRODUCER_ARCHIVE_TEST_SETUP',
                '-DKPB_C1_CONTACT_VALUE_AUTHORITY_TEST_SETUP',
            ])
        command.extend(str(source) for source in sources)
        command.extend(['-I', str(HERE), '-lcrypto', '-o', str(output)])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def test_live_spool_and_c03_are_exact_and_one_shot(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-observer-capture-bridge-') as directory:
            binary = Path(directory) / 'control'
            compiled = self.compile(
                binary,
                HERE / 'privacy_measurement_observer_capture_bridge_control.cpp',
                HERE / 'privacy_measurement_observer_capture_bridge.cpp',
                HERE / 'privacy_capture_producer_supervisor.cpp',
                HERE / 'c1_contact_value_authority.cpp',
                HERE / 'privacy_capture_producer_runtime.cpp',
                HERE / 'privacy_capture_producer_archive.cpp',
                HERE / 'privacy_measurement_worker_capsule.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp',
                test_setup=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=10)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_public_receipts_cannot_build_fd40(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-observer-capture-public-bypass-') as directory:
            directory = Path(directory)
            source = directory / 'bypass.cpp'
            source.write_text(r'''
#include "privacy_measurement_observer_capture_bridge.hpp"
#include "privacy_measurement_authority.hpp"
using namespace kpb::measurement;
using namespace kpb::measurement::runtime_bridge;
int main() {
    PublicObserverPermit permit{};
    PublicTrialCaptureCompletion capture{};
    (void)ObserverCaptureCapsuleBridge::prepare(
        static_cast<PublicObserverPermit&&>(permit), -1, -1, -1);
    (void)capture.stream_count;
    (void)capture.closed_root_count;
    (void)capture.unknown_record_count;
}
''', encoding='utf-8')
            compiled = self.compile(directory / 'bypass', source)
            self.assertNotEqual(compiled.returncode, 0,
                                'copyable public receipt built FD40')
            self.assertIn('ObserverPermitAuthority', compiled.stderr)

    def test_production_has_no_legacy_directory_spool_admit_overload(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-observer-no-legacy-spool-') as directory:
            directory = Path(directory)
            source = directory / 'surface.cpp'
            source.write_text(r'''
#include "privacy_capture_producer_supervisor.hpp"
#include "c1_contact_value_authority.hpp"
using namespace kpb::measurement;
template<class Bridge> concept HasLegacySpoolAdmit = requires(
    producer_supervisor::ProducerSpoolAuthority&& spool,
    producer_supervisor::C03RoleLaunchAdmissionAuthority&& c03,
    c1_capture::C1PostcaptureAdmissionAuthority&& r1,
    c1_capture::C1PostcaptureAdmissionAuthority&& r2) {
    Bridge::admit(
        static_cast<producer_supervisor::ProducerSpoolAuthority&&>(spool),
        static_cast<producer_supervisor::C03RoleLaunchAdmissionAuthority&&>(
            c03),
        static_cast<c1_capture::C1PostcaptureAdmissionAuthority&&>(r1),
        static_cast<c1_capture::C1PostcaptureAdmissionAuthority&&>(r2));
};
static_assert(!HasLegacySpoolAdmit<
    runtime_bridge::ObserverCaptureCapsuleBridge>);
int main() { return 0; }
''', encoding='utf-8')
            compiled = self.compile(directory / 'surface', source)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

    def test_production_has_no_fd40_test_helpers(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-observer-no-fd40-test-helpers-') as directory:
            directory = Path(directory)
            source = directory / 'surface.cpp'
            source.write_text(r'''
#include "privacy_measurement_observer_capture_bridge.hpp"
#include "privacy_measurement_authority.hpp"
using namespace kpb::measurement;
using namespace kpb::measurement::runtime_bridge;
template<class Bridge> concept HasSnapshotHelper = requires(
    ObserverAdmissionAuthority&& admission,
    const PublicObserverPermit& permit) {
    Bridge::test_only_snapshot_archive(
        static_cast<ObserverAdmissionAuthority&&>(admission), permit);
};
template<class Bridge> concept HasPrepareHelper = requires(
    ObserverPermitAuthority&& permit) {
    Bridge::test_only_prepare_archive(
        static_cast<ObserverPermitAuthority&&>(permit));
};
template<class Bridge> concept HasAttachHelper = requires(
    const PublicObserverPermit& permit,
    ObserverAdmissionAuthority&& admission) {
    Bridge::test_only_attach_admission(
        permit, static_cast<ObserverAdmissionAuthority&&>(admission));
};
template<class Bridge> concept HasEntropyControl = requires {
    Bridge::test_only_force_entropy_failure(true);
    Bridge::test_only_force_entropy_short_read(true);
    Bridge::test_only_require_entropy();
};
template<class Bridge> concept HasEndpointIdentityHelper = requires(
    const Digest& digest, const PublicObserverPermit& permit) {
    Bridge::test_only_endpoint_identity(digest, 1, permit, digest);
};
static_assert(!HasSnapshotHelper<ObserverCaptureCapsuleBridge>);
static_assert(!HasPrepareHelper<ObserverCaptureCapsuleBridge>);
static_assert(!HasAttachHelper<ObserverCaptureCapsuleBridge>);
static_assert(!HasEntropyControl<ObserverCaptureCapsuleBridge>);
static_assert(!HasEndpointIdentityHelper<ObserverCaptureCapsuleBridge>);
int main() { return 0; }
''', encoding='utf-8')
            compiled = self.compile(directory / 'surface', source)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

    def test_measurement_forward_friend_names_cannot_mint_admission(self):
        attacks = (
            'TrialCaptureJoiner',
            'TrialCaptureCompletionAuthority',
            'RunMeasurement',
            'ObserverPermitAuthority',
        )
        with tempfile.TemporaryDirectory(
                prefix='kpb-observer-admission-no-forward-friend-') as directory:
            directory = Path(directory)
            for class_name in attacks:
                source = directory / f'{class_name}.cpp'
                source.write_text(f'''
#include "privacy_measurement_observer_capture_bridge.hpp"
#include <memory>
#include <utility>
namespace kpb::measurement {{
class {class_name} final {{
public:
    using Forged = decltype(runtime_bridge::ObserverAdmissionAuthority(
        std::declval<std::unique_ptr<
            runtime_bridge::ObserverAdmissionAuthority::Storage>>()));
}};
}}
int main() {{ return 0; }}
''', encoding='utf-8')
                compiled = subprocess.run([
                    'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                    '-pedantic', '-pthread', '-I', str(HERE), '-c',
                    str(source), '-o', str(directory / f'{class_name}.o'),
                ], capture_output=True, text=True, check=False)
                self.assertNotEqual(
                    compiled.returncode, 0,
                    f'hostile {class_name} definition unexpectedly compiled')


if __name__ == '__main__':
    unittest.main()
