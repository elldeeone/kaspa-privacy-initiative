#!/usr/bin/env python3
"""Controls for the parent-owned ten-stream capture producer runtime."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class CaptureProducerRuntimeControls(unittest.TestCase):
    def compile(self, output, *sources, test_setup=False):
        command = [
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread', '-ffunction-sections',
            '-fdata-sections', '-Wl,--gc-sections',
        ]
        if test_setup:
            command.extend([
                '-DKPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP',
                '-DKPI_REGISTERED_ATTEMPT_HISTORY_TEST_SETUP',
                '-DKPB_ALL_BRANCH_FRESH_TRIAL_OWNER_TEST_SETUP',
            ])
        command.extend(str(source) for source in sources)
        command.extend(['-I', str(HERE), '-lcrypto', '-o', str(output)])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def test_parent_owned_runtime_drains_all_ten_streams(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-capture-producer-runtime-') as directory:
            binary = Path(directory) / 'controls'
            compiled = self.compile(
                binary,
                HERE / 'privacy_capture_producer_runtime_control.cpp',
                HERE / 'privacy_capture_producer_runtime.cpp',
                HERE / 'privacy_capture_producer_archive.cpp',
                HERE / 'privacy_all_branch_fresh_trial_owner_authority.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp',
                HERE.parent / 'mpc-prover' / 'financial' /
                'registered_identity_registry.cpp',
                HERE.parent / 'mpc-prover' / 'financial' /
                'registered_persistent_role_exit_history.cpp',
                HERE.parent / 'mpc-prover' / 'financial' /
                'registered_trial_attempt_history.cpp',
                HERE.parent / 'mpc-prover' / 'financial' /
                'registered_fresh_trial_history_ledger.cpp',
                test_setup=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=30)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_production_surface_has_no_authority_minter(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-capture-producer-runtime-production-') as directory:
            directory = Path(directory)
            source = directory / 'production.cpp'
            source.write_text(r'''
#include "privacy_capture_producer_runtime.hpp"
#include <type_traits>
using namespace kpb::measurement::producer_runtime;
template<class T> concept HasRecordRoot = requires(T value) {
    value.record_root;
};
template<class T> concept HasEndFrameIdentity = requires(T value) {
    value.end_frame_identity;
};
template<class T> concept HasEofIdentity = requires(T value) {
    value.eof_identity;
};
template<class T> concept HasContentReceiptIdentity = requires(T value) {
    value.receipt_identity;
};
template<class T> concept HasContentProducerIdentity = requires(T value) {
    value.producer_identity;
};
template<class T> concept HasRouteIdentity = requires(T value) {
    value.route_identity;
};
template<class T> concept HasRouteTime = requires(T value) {
    value.route_observed_monotonic_ns;
};
template<class T> concept HasRecordCount = requires(T value) {
    value.record_count;
};
template<class T> concept HasPayloadBytes = requires(T value) {
    value.payload_bytes;
};
template<class T> concept HasRawWireBytes = requires(T value) {
    value.raw_wire_bytes;
};
static_assert(!HasRecordRoot<PublicCaptureProducerStreamReceipt>);
static_assert(!HasEndFrameIdentity<PublicCaptureProducerStreamReceipt>);
static_assert(!HasEofIdentity<PublicCaptureProducerStreamReceipt>);
static_assert(!HasRecordCount<PublicCaptureProducerStreamReceipt>);
static_assert(!HasPayloadBytes<PublicCaptureProducerStreamReceipt>);
static_assert(!HasRawWireBytes<PublicCaptureProducerStreamReceipt>);
static_assert(!HasContentReceiptIdentity<PublicCaptureProducerReceiptV1>);
static_assert(!HasContentProducerIdentity<PublicCaptureProducerReceiptV1>);
static_assert(!HasRouteIdentity<
    decltype(PublicCaptureProducerReceiptV1{}.routes)::value_type>);
static_assert(!HasRouteTime<
    decltype(PublicCaptureProducerReceiptV1{}.routes)::value_type>);
static_assert(!std::is_copy_constructible_v<ParentTenReadEndsAuthority>);
static_assert(!std::is_constructible_v<
    ParentTenReadEndsAuthority, PublicProducerLaunchPlan,
    std::array<int, 10>>);
static_assert(!std::is_constructible_v<
    ParentAggregateMailboxRoutesAuthority,
    std::array<PublicAggregateMailboxRouteCompletion, 2>>);
static_assert(!std::is_constructible_v<
    RunningCaptureProducer, PublicProducerLaunchPlan, int, int>);
static_assert(kProducerRuntimeSourceStatus.concurrent_drain_core);
static_assert(kProducerRuntimeSourceStatus.parent_owned_read_authority);
static_assert(kProducerRuntimeSourceStatus.sealed_raw_archive);
static_assert(kProducerRuntimeSourceStatus.strict_archive_scm_rights);
static_assert(kProducerRuntimeSourceStatus.parent_raw_wire_reparse);
static_assert(!kProducerRuntimeSourceStatus.source_derived_stream_byte_bounds);
static_assert(!kProducerRuntimeSourceStatus.disk_reservation_preflight);
static_assert(kProducerRuntimeSourceStatus.wait_failure_invalidation_handoff);
static_assert(!kProducerRuntimeSourceStatus.registered_role0_route_complete);
static_assert(!kProducerRuntimeSourceStatus.selected_main);
static_assert(!kProducerRuntimeSourceStatus.actual_launch_enabled);
int main() { return 0; }
''', encoding='utf-8')
            binary = directory / 'production'
            compiled = self.compile(
                binary, source,
                HERE / 'privacy_capture_producer_runtime.cpp',
                HERE / 'privacy_capture_producer_archive.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp')
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
            self.assertNotIn('test_only_mint', symbols.stdout)

    def test_test_mint_does_not_compile_in_production(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-capture-producer-runtime-no-mint-') as directory:
            directory = Path(directory)
            source = directory / 'forbidden.cpp'
            source.write_text(r'''
#include "privacy_capture_producer_runtime.hpp"
using namespace kpb::measurement::producer_runtime;
int main() {
    PublicProducerLaunchPlan plan{};
    std::array<int, 10> read_ends{};
    auto authority = ParentTenReadEndsAuthority::test_only_mint(
        plan, std::move(read_ends));
    (void)authority;
}
''', encoding='utf-8')
            compiled = self.compile(
                directory / 'forbidden', source,
                HERE / 'privacy_capture_producer_runtime.cpp',
                HERE / 'privacy_capture_producer_archive.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp')
            self.assertNotEqual(compiled.returncode, 0,
                                'test-only mint unexpectedly compiled')
            self.assertIn('test_only_mint', compiled.stderr)

    def test_forward_friend_names_cannot_be_defined_to_mint_authorities(self):
        attacks = {
            'registered-read-ends': r'''
#include "privacy_capture_producer_runtime.hpp"
namespace kpi::mpc::financial::registered_driver {
class RegisteredCaptureProducerParentBridge final {
public:
    static auto forge() {
        kpb::measurement::producer_runtime::PublicProducerLaunchPlan plan{};
        std::array<int, 10> fds{};
        return kpb::measurement::producer_runtime::
            ParentTenReadEndsAuthority(plan, fds);
    }
};
}
int main() { auto value = kpi::mpc::financial::registered_driver::
    RegisteredCaptureProducerParentBridge::forge(); (void)value; }
''',
            'registered-routes': r'''
#include "privacy_capture_producer_runtime.hpp"
namespace kpi::mpc::financial::registered_driver {
class RegisteredAggregateMailboxRouteParentBridge final {
public:
    static auto forge() {
        std::array<kpb::measurement::producer_runtime::
            PublicAggregateMailboxRouteCompletion, 2> rows{};
        return kpb::measurement::producer_runtime::
            ParentAggregateMailboxRoutesAuthority(rows);
    }
};
}
int main() { auto value = kpi::mpc::financial::registered_driver::
    RegisteredAggregateMailboxRouteParentBridge::forge(); (void)value; }
''',
            'c1-read-ends': r'''
#include "privacy_capture_producer_runtime.hpp"
namespace kpb::measurement::c1_capture {
class C1ContactValueAuthorityBridge final {
public:
    static auto forge() {
        producer_runtime::PublicProducerLaunchPlan plan{};
        std::array<int, 10> fds{};
        return producer_runtime::ParentTenReadEndsAuthority(plan, fds);
    }
};
}
int main() { auto value = kpb::measurement::c1_capture::
    C1ContactValueAuthorityBridge::forge(); (void)value; }
''',
        }
        with tempfile.TemporaryDirectory(
                prefix='kpb-capture-producer-no-forward-friend-') as directory:
            directory = Path(directory)
            for name, body in attacks.items():
                source = directory / f'{name}.cpp'
                source.write_text(body, encoding='utf-8')
                compiled = subprocess.run([
                    'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                    '-pedantic', '-pthread', '-I', str(HERE), '-c',
                    str(source), '-o', str(directory / f'{name}.o'),
                ], capture_output=True, text=True, check=False)
                self.assertNotEqual(
                    compiled.returncode, 0,
                    f'hostile definition {name} unexpectedly compiled')


if __name__ == '__main__':
    unittest.main()
