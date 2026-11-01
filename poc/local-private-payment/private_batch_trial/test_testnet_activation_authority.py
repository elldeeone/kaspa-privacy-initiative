#!/usr/bin/env python3
"""Compiled controls for the source-only Testnet activation conjunction."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class TestnetActivationAuthorityControls(unittest.TestCase):
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
                '-DKPB_NATIVE_TERMINAL_FIXTURE_NO_MAIN',
                '-DKPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP',
                '-DKPB_HONEST_OWNER_MATERIAL_TEST_SETUP',
            ])
        command.extend(str(source) for source in sources)
        command.extend(['-I', str(HERE), '-lcrypto', '-o', str(output)])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def test_live_conjunction_exact_bindings_and_replay_controls(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-testnet-activation-controls-') as directory:
            binary = Path(directory) / 'controls'
            compiled = self.compile(
                binary,
                HERE / 'testnet_activation_authority_control.cpp',
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
                HERE / 'privacy_capture_producer_runtime.cpp',
                HERE / 'privacy_capture_producer_archive.cpp',
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
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=120)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_production_surface_has_no_minter_launcher_or_network_effect(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-testnet-activation-production-') as directory:
            directory = Path(directory)
            source = directory / 'production_surface.cpp'
            source.write_text(r'''
#include "testnet_activation_authority.hpp"
#include <concepts>
#include <utility>
using namespace kpb::testnet_activation;
static_assert(!std::default_initializable<PreNetworkSafetyAuthority>);
static_assert(!std::constructible_from<PreNetworkSafetyAuthority,
                                       CandidateActivationBinding>);
static_assert(!std::constructible_from<PreNetworkSafetyAuthority,
                                       PublicPreNetworkSafety>);
static_assert(!std::copy_constructible<PreNetworkSafetyAuthority>);
static_assert(!std::default_initializable<PreNetworkSafetyJoin>);
static_assert(!std::copy_constructible<PreNetworkSafetyJoin>);
static_assert(!std::default_initializable<TestnetActivationPermit>);
static_assert(!std::constructible_from<TestnetActivationPermit,
                                       PublicTestnetActivationPermit>);
static_assert(!std::copy_constructible<TestnetActivationPermit>);
static_assert(!std::default_initializable<
              GlobalPaymentCaptureCompletionAuthority>);
static_assert(!std::copy_constructible<
              GlobalPaymentCaptureCompletionAuthority>);
static_assert(!std::constructible_from<
              GlobalPaymentCaptureCompletionAuthority,
              PublicGlobalPaymentCaptureCompletion>);
static_assert(!std::default_initializable<
              NativeCandidateCompletionAuthority>);
static_assert(!std::copy_constructible<
              NativeCandidateCompletionAuthority>);
static_assert(!std::constructible_from<
              NativeCandidateCompletionAuthority,
              PublicNativeCandidateCompletion>);
static_assert(!std::default_initializable<SelectedParentAuthority>);
static_assert(!std::copy_constructible<SelectedParentAuthority>);
static_assert(!std::constructible_from<SelectedParentAuthority,
                                       PublicSelectedParent>);
static_assert(!std::default_initializable<FirstRpcBoundaryAuthority>);
static_assert(!std::copy_constructible<FirstRpcBoundaryAuthority>);
static_assert(!std::constructible_from<FirstRpcBoundaryAuthority,
                                       PublicFirstRpcBoundary>);
template<class Capture, class Native>
concept ReceiptSafetyFactory = requires(
        kpb::measurement::PublicBatchPrivacyPass privacy,
        Capture capture, Native native) {
    PreNetworkSafetyFactory::join(
        privacy, std::move(capture), std::move(native));
};
static_assert(!ReceiptSafetyFactory<
              PublicGlobalPaymentCaptureCompletion,
              std::array<PublicNativeCandidateCompletion, 3>>);
template<class Capture, class Native>
concept PublicPrivacyPassSafetyFactory = requires(
        kpb::measurement::PublicBatchPrivacyPass privacy,
        Capture capture, Native native) {
    PreNetworkSafetyFactory::join(
        privacy, std::move(capture), std::move(native));
};
static_assert(!PublicPrivacyPassSafetyFactory<
              GlobalPaymentCaptureCompletionAuthority,
              std::array<NativeCandidateCompletionAuthority, 3>>);
template<class Privacy, class Safety>
concept DetachableActivationJoin = requires(Privacy privacy, Safety safety) {
    ActivationJoiner::conjoin(
        std::move(privacy), std::move(safety));
};
static_assert(!DetachableActivationJoin<
              kpb::measurement::BatchPrivacyPassAuthority,
              PreNetworkSafetyAuthority>);
template<class T> concept PrePermitRpc = requires(T& value) {
    value.authorize_first_rpc();
};
static_assert(!PrePermitRpc<SelectedParentNetworkBoundary>);
static_assert(!kSourceStatus.global_capture_evidence_producer);
static_assert(!kSourceStatus.native_candidate_evidence_producer);
static_assert(!kSourceStatus.selected_parent_authority_producer);
static_assert(kSourceStatus.pre_network_safety_factory);
static_assert(kSourceStatus.activation_conjunction);
static_assert(kSourceStatus.selected_parent_permit_consumer);
static_assert(kSourceStatus.first_rpc_boundary_authority);
static_assert(!kSourceStatus.network_namespace_factory);
static_assert(!kSourceStatus.network_adapter);
static_assert(!kSourceStatus.configured);
static_assert(!kSourceStatus.launch_enabled);
static_assert(!kSourceStatus.network_invoked);
int main() { return 0; }
''', encoding='utf-8')
            binary = directory / 'production_surface'
            compiled = self.compile(
                binary, source,
                HERE / 'testnet_activation_authority.cpp',
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

    def test_serialized_receipts_and_test_minter_do_not_compile_in_production(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-testnet-activation-no-receipt-authority-') as directory:
            directory = Path(directory)
            source = directory / 'forbidden.cpp'
            source.write_text(r'''
#include "testnet_activation_authority.hpp"
using namespace kpb::testnet_activation;
int main() {
    CandidateActivationBinding binding{};
    PublicPreNetworkSafety receipt{};
    auto from_binding = PreNetworkSafetyAuthority(binding);
    auto from_receipt = PreNetworkSafetyAuthority(receipt);
    auto test_mint = PreNetworkSafetyAuthority::test_only_mint(binding);
    PublicGlobalPaymentCaptureCompletion capture{};
    PublicNativeCandidateCompletion native{};
    PublicSelectedParent selected{};
    auto capture_authority =
        GlobalPaymentCaptureCompletionAuthority::test_only_mint(capture);
    auto native_authority =
        NativeCandidateCompletionAuthority::test_only_mint(native);
    auto parent_authority = SelectedParentAuthority::test_only_mint(selected);
    auto direct_capture =
        GlobalPaymentCaptureCompletionAuthority(capture);
    auto direct_native = NativeCandidateCompletionAuthority(native);
    auto direct_parent = SelectedParentAuthority(selected);
    (void)from_binding; (void)from_receipt; (void)test_mint;
    (void)capture_authority; (void)native_authority; (void)parent_authority;
    (void)direct_capture; (void)direct_native; (void)direct_parent;
}
''', encoding='utf-8')
            compiled = self.compile(
                directory / 'forbidden', source,
                HERE / 'testnet_activation_authority.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp')
            self.assertNotEqual(compiled.returncode, 0,
                                'serialized receipt unexpectedly became authority')
            self.assertIn('private', compiled.stderr)
            self.assertIn('test_only_mint', compiled.stderr)

    def test_forged_valid_public_pass_cannot_enter_safety_factory(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-testnet-activation-forged-pass-') as directory:
            directory = Path(directory)
            source = directory / 'forged_pass.cpp'
            source.write_text(r'''
#include "testnet_activation_authority.hpp"
#include <array>
#include <utility>
using namespace kpb::measurement;
using namespace kpb::testnet_activation;
void attack(
        PublicBatchPrivacyPass forged_valid_public_pass,
        GlobalPaymentCaptureCompletionAuthority&& capture,
        std::array<NativeCandidateCompletionAuthority, 3>&& native) {
    (void)PreNetworkSafetyFactory::join(
        forged_valid_public_pass, std::move(capture), std::move(native));
}
int main() { return 0; }
''', encoding='utf-8')
            compiled = self.compile(directory / 'forged_pass', source)
            self.assertNotEqual(
                compiled.returncode, 0,
                'caller-authored public privacy pass entered safety factory')
            self.assertIn('BatchPrivacyPassAuthority', compiled.stderr)


if __name__ == '__main__':
    unittest.main()
