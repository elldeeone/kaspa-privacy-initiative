#!/usr/bin/env python3
"""Compiled adversarial controls for the offline native-terminal supervisor."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class NativeTerminalCompletionControls(unittest.TestCase):
    def compile(self, output, *sources, test_setup=False):
        command = [
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread',
        ]
        if test_setup:
            command.extend([
                '-DKPB_MEASUREMENT_AUTHORITY_TEST_SETUP',
                '-DKPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP',
                '-DKPB_TESTNET_ACTIVATION_AUTHORITY_TEST_SETUP',
                '-DKPB_NATIVE_TERMINAL_COMPLETION_TEST_SETUP',
                '-DKPB_TERMINAL_MAPPING_SOURCE_TEST_SETUP',
                '-DKPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP',
                '-DKPB_NATIVE_TERMINAL_ARCHIVE_INTEGRATION_TEST_SETUP',
                '-DKPB_CAPTURE_PRODUCER_SUPERVISOR_TEST_SETUP',
                '-DKPB_C1_CONTACT_VALUE_AUTHORITY_TEST_SETUP',
                '-DKPB_MEASUREMENT_OBSERVER_CAPTURE_BRIDGE_TEST_SETUP',
                '-DKPB_MEASUREMENT_WORKER_CAPSULE_TEST_SETUP',
                '-DKPB_HONEST_OWNER_MATERIAL_TEST_SETUP',
            ])
        command.extend(str(source) for source in sources)
        command.extend(['-I', str(HERE), '-lcrypto', '-o', str(output)])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def test_authenticated_offline_child_and_adversarial_controls(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-native-terminal-controls-') as directory:
            binary = Path(directory) / 'controls'
            fixture = Path(directory) / 'static-fixture'
            fixture_compile = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-static', '-s',
                str(HERE / 'privacy_measurement_capsule_static_fixture.cpp'),
                '-o', str(fixture),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(fixture_compile.returncode, 0,
                             fixture_compile.stdout + fixture_compile.stderr)
            compiled = self.compile(
                binary,
                HERE / 'native_terminal_completion_control.cpp',
                HERE / 'native_terminal_completion.cpp',
                HERE / 'honest_owner_material_authority.cpp',
                HERE / 'honest_owner_material_test_fixture.cpp',
                HERE / 'native_terminal_mapping_source.cpp',
                HERE / 'native_terminal_projection_intake.cpp',
                HERE / 'privacy_measurement_native_terminal_bridge.cpp',
                HERE / 'privacy_measurement_terminal_v2_admission_bridge.cpp',
                HERE / 'testnet_activation_authority.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp',
                HERE / 'privacy_measurement_runtime_bridge.cpp',
                HERE / 'privacy_native_empirical_result_authority.cpp',
                HERE / 'privacy_native_phase_scope_authority.cpp',
                HERE / 'privacy_observation_barrier_fanout_authority.cpp',
                HERE / 'privacy_measurement_observer_capture_bridge.cpp',
                HERE / 'privacy_measurement_worker_capsule.cpp',
                HERE / 'privacy_capture_producer_runtime.cpp',
                HERE / 'privacy_capture_producer_archive.cpp',
                HERE / 'privacy_capture_producer_supervisor.cpp',
                HERE / 'c1_contact_value_authority.cpp',
                HERE / 'privacy_capture_hook.cpp',
                HERE / 'privacy_terminal_capture_v2.cpp',
                HERE.parent / 'mpc-prover' / 'financial' /
                    'registered_projection_route.cpp',
                HERE.parent / 'mpc-prover' / 'financial' /
                    'registered_identity_registry.cpp',
                HERE.parent.parent / 'future-recipient' / 'v3' /
                    'v3_native_authority.cpp',
                test_setup=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary), str(fixture)], capture_output=True,
                                 text=True, check=False, timeout=90)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_production_surface_has_no_receipt_minter_or_network_adapter(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-native-terminal-production-') as directory:
            directory = Path(directory)
            source = directory / 'production_surface.cpp'
            source.write_text(r'''
#include "native_terminal_completion.hpp"
#include "native_terminal_mapping_source.hpp"
#include "privacy_measurement_observer_capture_bridge.hpp"
#include "../mpc-prover/financial/registered_projection_route.hpp"
#include <concepts>
using namespace kpb::native_terminal;
using namespace kpb::testnet_activation;
using namespace kpb::capture;
using namespace kpb::measurement::runtime_bridge;
using RetainedProjectionAuthority =
    kpi::mpc::financial::registered_driver::projection_route::
        NativeTerminalRetainedProjectionAuthority;
using PublicRetainedProjectionReceipt =
    kpi::mpc::financial::registered_driver::projection_route::
        PublicRetainedProjectionReceipt;
template<class T> concept HasRecordRoot = requires(T value) {
    value.record_root;
};
template<class T> concept HasTerminalRecordRoot = requires(T value) {
    value.terminal_record_root;
};
template<class T> concept HasEnd = requires(T value) { value.end_frame; };
template<class T> concept HasTerminalEnd = requires(T value) {
    value.terminal_end_frame;
};
template<class T> concept HasEof = requires(T value) { value.eof_observed; };
template<class T> concept HasTerminalEof = requires(T value) {
    value.terminal_eof;
};
template<class T> concept HasCount = requires(T value) {
    value.record_count;
};
template<class T> concept HasTerminalCount = requires(T value) {
    value.terminal_record_count;
};
template<class T> concept HasPayload = requires(T value) {
    value.payload_bytes;
};
template<class T> concept HasTerminalPayload = requires(T value) {
    value.terminal_payload_bytes;
};
template<class T> concept HasRaw = requires(T value) {
    value.raw_wire_bytes;
};
template<class T> concept HasTerminalRaw = requires(T value) {
    value.terminal_raw_wire_bytes;
};
template<class T> concept HasGroup = requires(T value) {
    value.group_identity;
};
template<class T> concept HasAuthenticatedPid = requires(T value) {
    value.authenticated_child_pid;
};
template<class T> concept HasWaitedPid = requires(T value) {
    value.waited_child_pid;
};
template<class T> concept HasPublicTokenConsumer = requires(T value) {
    value.consume_for_parent_supervisor();
};
template<class T> concept HasPublicReceipt = requires(const T& value) {
    value.public_receipt();
};
template<class T> concept HasLvalueModelTransfer = requires(T& value) {
    value.transfer_for_terminal_v2_model();
};
template<class T> concept HasNoArgumentRvalueModelTransfer =
    requires(T&& value) {
        std::move(value).transfer_for_terminal_v2_model();
    };
template<class T> concept HasBody = requires(const T& value) {
    value.body();
};
template<class T> concept HasProjection = requires(const T& value) {
    value.projection();
};
template<class T> concept HasRouteIdentity = requires(const T& value) {
    value.route_identity();
};
template<class T> concept HasOwnerRows = requires(const T& value) {
    value.owner_rows();
};
template<class T> concept HasGroups = requires(const T& value) {
    value.groups();
};
template<class T> concept HasHiddenGroup = requires(const T& value) {
    value.hidden_group();
};
template<class T> concept HasCrossRoundLink = requires(const T& value) {
    value.cross_round_link();
};
template<class T> concept HasAcceptedChainContinuity =
    requires(const T& value) { value.accepted_chain_continuity(); };
template<class T> concept HasTakeProducer = requires(T& value) {
    value.take_producer();
};
template<class T> concept HasTakeAdmission = requires(T& value) {
    value.take_admission();
};
static_assert(!std::default_initializable<NativeCandidateCompletionAuthority>);
static_assert(!std::copy_constructible<NativeCandidateCompletionAuthority>);
static_assert(!std::constructible_from<NativeCandidateCompletionAuthority,
                                       PublicNativeCandidateCompletion>);
static_assert(!std::default_initializable<NativeTerminalSupervisor>);
static_assert(!std::constructible_from<MatchedNativeTerminalProducerBundle,
    kpb::measurement::ProducerClosureAuthority,
    PaymentLifecycleCompletionAuthority,
    PaymentLifecycleCompletionAuthority>);
static_assert(!std::default_initializable<TerminalV2ModelAdmissionAuthority>);
static_assert(!std::copy_constructible<TerminalV2ModelAdmissionAuthority>);
static_assert(!HasPublicReceipt<TerminalV2ModelAdmissionAuthority>);
static_assert(!HasRecordRoot<TerminalV2ModelAdmissionAuthority>);
static_assert(!HasEnd<TerminalV2ModelAdmissionAuthority>);
static_assert(!HasEof<TerminalV2ModelAdmissionAuthority>);
static_assert(!HasCount<TerminalV2ModelAdmissionAuthority>);
static_assert(!HasPayload<TerminalV2ModelAdmissionAuthority>);
static_assert(!HasRaw<TerminalV2ModelAdmissionAuthority>);
static_assert(!HasGroup<TerminalV2ModelAdmissionAuthority>);
static_assert(!HasGroups<TerminalV2ModelAdmissionAuthority>);
static_assert(!HasHiddenGroup<TerminalV2ModelAdmissionAuthority>);
static_assert(!HasCrossRoundLink<TerminalV2ModelAdmissionAuthority>);
static_assert(!HasAuthenticatedPid<TerminalV2ModelAdmissionAuthority>);
static_assert(!HasLvalueModelTransfer<MatchedNativeTerminalProducerBundle>);
static_assert(!HasNoArgumentRvalueModelTransfer<
              MatchedNativeTerminalProducerBundle>);
static_assert(!std::default_initializable<NativeTerminalMappingSourceAuthority>);
static_assert(!std::copy_constructible<NativeTerminalMappingSourceAuthority>);
static_assert(!HasPublicReceipt<NativeTerminalMappingSourceAuthority>);
static_assert(!HasBody<NativeTerminalMappingSourceAuthority>);
static_assert(!HasProjection<NativeTerminalMappingSourceAuthority>);
static_assert(!HasRouteIdentity<NativeTerminalMappingSourceAuthority>);
static_assert(!HasOwnerRows<NativeTerminalMappingSourceAuthority>);
static_assert(!HasRecordRoot<NativeTerminalMappingSourceAuthority>);
static_assert(!HasEnd<NativeTerminalMappingSourceAuthority>);
static_assert(!HasEof<NativeTerminalMappingSourceAuthority>);
static_assert(!HasCount<NativeTerminalMappingSourceAuthority>);
static_assert(!HasGroup<NativeTerminalMappingSourceAuthority>);
static_assert(!HasGroups<NativeTerminalMappingSourceAuthority>);
static_assert(!HasHiddenGroup<NativeTerminalMappingSourceAuthority>);
static_assert(!HasCrossRoundLink<NativeTerminalMappingSourceAuthority>);
static_assert(!std::default_initializable<
              StructuralProjectionContinuityAuthority>);
static_assert(!std::copy_constructible<
              StructuralProjectionContinuityAuthority>);
static_assert(!HasPublicReceipt<StructuralProjectionContinuityAuthority>);
static_assert(!HasProjection<StructuralProjectionContinuityAuthority>);
static_assert(!HasRouteIdentity<StructuralProjectionContinuityAuthority>);
static_assert(!HasRecordRoot<StructuralProjectionContinuityAuthority>);
static_assert(!HasCount<StructuralProjectionContinuityAuthority>);
static_assert(!HasGroups<StructuralProjectionContinuityAuthority>);
static_assert(!HasHiddenGroup<StructuralProjectionContinuityAuthority>);
static_assert(!HasCrossRoundLink<StructuralProjectionContinuityAuthority>);
static_assert(!HasAcceptedChainContinuity<
              StructuralProjectionContinuityAuthority>);
static_assert(!std::default_initializable<ObserverTerminalCaptureJoin>);
static_assert(!std::copy_constructible<ObserverTerminalCaptureJoin>);
static_assert(!HasPublicReceipt<ObserverTerminalCaptureJoin>);
static_assert(!HasTakeProducer<ObserverTerminalCaptureJoin>);
static_assert(!HasTakeAdmission<ObserverTerminalCaptureJoin>);
static_assert(!std::default_initializable<RetainedProjectionAuthority>);
static_assert(!std::copy_constructible<RetainedProjectionAuthority>);
static_assert(!std::constructible_from<
              RetainedProjectionAuthority,
              PublicRetainedProjectionReceipt,
              std::array<std::byte, 10685>>);
static_assert(!HasPublicReceipt<RetainedProjectionAuthority>);
static_assert(!HasBody<RetainedProjectionAuthority>);
static_assert(!HasProjection<RetainedProjectionAuthority>);
static_assert(!HasRouteIdentity<RetainedProjectionAuthority>);
static_assert(!HasRecordRoot<PublicPaymentLifecycleCompletion>);
static_assert(!HasTerminalRecordRoot<PublicPaymentLifecycleCompletion>);
static_assert(!HasEnd<PublicPaymentLifecycleCompletion>);
static_assert(!HasTerminalEnd<PublicPaymentLifecycleCompletion>);
static_assert(!HasEof<PublicPaymentLifecycleCompletion>);
static_assert(!HasTerminalEof<PublicPaymentLifecycleCompletion>);
static_assert(!HasCount<PublicPaymentLifecycleCompletion>);
static_assert(!HasTerminalCount<PublicPaymentLifecycleCompletion>);
static_assert(!HasPayload<PublicPaymentLifecycleCompletion>);
static_assert(!HasTerminalPayload<PublicPaymentLifecycleCompletion>);
static_assert(!HasRaw<PublicPaymentLifecycleCompletion>);
static_assert(!HasTerminalRaw<PublicPaymentLifecycleCompletion>);
static_assert(!HasGroup<PublicPaymentLifecycleCompletion>);
static_assert(!HasAuthenticatedPid<PublicPaymentLifecycleCompletion>);
static_assert(!HasWaitedPid<PublicPaymentLifecycleCompletion>);
static_assert(!HasEof<PublicNativeCandidateCompletion>);
static_assert(!HasAuthenticatedPid<PublicNativeCandidateCompletion>);
static_assert(!HasWaitedPid<PublicNativeCandidateCompletion>);
static_assert(!HasPublicTokenConsumer<PreNetworkTerminalClosedV2>);
static_assert(kNativeTerminalSourceStatus.authenticated_child_supervisor);
static_assert(kNativeTerminalSourceStatus.terminal_v2_stage_chain);
static_assert(kNativeTerminalSourceStatus.sole_producer_stream_join);
static_assert(kNativeTerminalSourceStatus.private_terminal_evidence);
static_assert(kNativeTerminalSourceStatus.exact_sompi_conservation);
static_assert(kNativeTerminalSourceStatus.retained_projection_intake);
static_assert(kNativeTerminalSourceStatus.terminal_mapping_source);
static_assert(kNativeTerminalSourceStatus.
              terminal_v2_model_admission_authority);
static_assert(kNativeTerminalSourceStatus.
              structural_projection_continuity);
static_assert(kNativeTerminalSourceStatus.
              honest_owner_production_residual_required);
static_assert(kNativeTerminalSourceStatus.
              exact_honest_owner_nf_output_correspondence);
static_assert(!kNativeTerminalSourceStatus.
              accepted_chain_continuity_authority);
static_assert(!kNativeTerminalSourceStatus.observer_model_admission);
static_assert(!kNativeTerminalSourceStatus.gen3_lifecycle_adapter);
static_assert(!kNativeTerminalSourceStatus.payment_lifecycle_adapter);
static_assert(!kNativeTerminalSourceStatus.accepted_head_producer);
static_assert(!kNativeTerminalSourceStatus.network_namespace);
static_assert(!kNativeTerminalSourceStatus.network_adapter);
static_assert(!kNativeTerminalSourceStatus.configured);
static_assert(!kNativeTerminalSourceStatus.launch_enabled);
static_assert(!kNativeTerminalSourceStatus.network_invoked);
int main() { return 0; }
''', encoding='utf-8')
            binary = directory / 'production_surface'
            compiled = self.compile(
                binary, source,
                HERE / 'native_terminal_completion.cpp',
                HERE / 'honest_owner_material_authority.cpp',
                HERE / 'native_terminal_mapping_source.cpp',
                HERE / 'native_terminal_projection_intake.cpp',
                HERE / 'testnet_activation_authority.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp',
                HERE / 'privacy_measurement_runtime_bridge.cpp',
                HERE / 'privacy_native_empirical_result_authority.cpp',
                HERE / 'privacy_native_phase_scope_authority.cpp',
                HERE / 'privacy_observation_barrier_fanout_authority.cpp',
                HERE / 'privacy_measurement_worker_capsule.cpp',
                HERE / 'privacy_capture_hook.cpp',
                HERE / 'privacy_terminal_capture_v2.cpp',
                HERE.parent.parent / 'future-recipient' / 'v3' /
                    'v3_native_authority.cpp')
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            symbols = subprocess.run(
                ['nm', '-C', str(binary)], capture_output=True, text=True,
                check=False, timeout=10)
            self.assertEqual(symbols.returncode, 0,
                             symbols.stdout + symbols.stderr)
            self.assertNotIn('test_only_mint', symbols.stdout)
            self.assertNotIn('test_only_candidate', symbols.stdout)
            self.assertNotIn('funding_network', symbols.stdout)
            self.assertNotIn('broadcast', symbols.stdout.lower())

    def test_serialized_completion_cannot_become_authority(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-native-terminal-no-receipt-mint-') as directory:
            directory = Path(directory)
            source = directory / 'forbidden.cpp'
            source.write_text(r'''
#include "native_terminal_completion.hpp"
#include "../mpc-prover/financial/registered_projection_route.hpp"
using namespace kpb::testnet_activation;
using namespace kpb::native_terminal;
int main() {
    PublicNativeCandidateCompletion receipt{};
    auto direct = NativeCandidateCompletionAuthority(receipt);
    auto test_mint =
        NativeCandidateCompletionAuthority::test_only_mint(receipt);
    PublicPaymentLifecycleCompletion round1{}, round2{};
    kpb::measurement::PublicProducerClosure producer{};
    auto direct_model = TerminalV2ModelAdmissionAuthority(
        producer, round1, round2);
    auto direct_continuity = StructuralProjectionContinuityAuthority(
        round1, round2);
    auto test_continuity =
        StructuralProjectionContinuityAuthority::test_only_mint(
            round1, round2);
    using namespace
        kpi::mpc::financial::registered_driver::projection_route;
    PublicRetainedProjectionReceipt retained_receipt{};
    std::array<std::byte, PUBLIC_PROJECTION_BYTES> projection{};
    auto direct_retained = NativeTerminalRetainedProjectionAuthority(
        retained_receipt, projection);
    (void)direct; (void)test_mint;
    (void)direct_model; (void)direct_continuity;
    (void)test_continuity; (void)direct_retained;
}
''', encoding='utf-8')
            compiled = self.compile(
                directory / 'forbidden', source,
                HERE / 'native_terminal_completion.cpp',
                HERE / 'honest_owner_material_authority.cpp',
                HERE / 'testnet_activation_authority.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp',
                HERE / 'privacy_capture_hook.cpp',
                HERE / 'privacy_terminal_capture_v2.cpp',
                HERE.parent.parent / 'future-recipient' / 'v3' /
                    'v3_native_authority.cpp')
            self.assertNotEqual(compiled.returncode, 0,
                                'serialized receipt unexpectedly minted authority')
            self.assertIn('private', compiled.stderr)
            self.assertIn('test_only_mint', compiled.stderr)

    def test_hostile_friend_names_are_already_complete(self):
        attacks = {
            'supervisor': r'''
#include "testnet_activation_authority.hpp"
namespace kpb::native_terminal {
class NativeTerminalSupervisor final {};
}
int main() { return 0; }
''',
            'producer_join': r'''
#include "testnet_activation_authority.hpp"
namespace kpb::native_terminal {
class NativeTerminalProducerJoin final {};
}
int main() { return 0; }
''',
            'projection_intake': r'''
#include "native_terminal_mapping_source.hpp"
namespace kpb::native_terminal {
class NativeTerminalProjectionIntake final {};
}
int main() { return 0; }
''',
            'terminal_capture': r'''
#include "native_terminal_mapping_source.hpp"
namespace kpb::capture {
class TerminalCaptureV2 final {};
}
int main() { return 0; }
''',
            'observer_bridge': r'''
#include "privacy_measurement_observer_capture_bridge_contract.hpp"
namespace kpb::measurement::runtime_bridge {
class ObserverCaptureCapsuleBridge final {};
}
int main() { return 0; }
''',
        }
        with tempfile.TemporaryDirectory(
                prefix='kpb-native-terminal-hostile-friend-') as directory:
            directory = Path(directory)
            for name, body in attacks.items():
                with self.subTest(name=name):
                    source = directory / f'{name}.cpp'
                    source.write_text(body, encoding='utf-8')
                    compiled = self.compile(directory / name, source)
                    self.assertNotEqual(
                        compiled.returncode, 0,
                        f'hostile TU defined friend class {name}')
                    self.assertIn('redefinition', compiled.stderr.lower())


if __name__ == '__main__':
    unittest.main()
