#!/usr/bin/env python3
"""Compile/run controls for the network-off V3 native authority layer."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
TRIAL = HERE.parents[1] / "local-private-payment" / "private_batch_trial"
FINANCIAL = TRIAL.parent / "mpc-prover" / "financial"
MPC = FINANCIAL.parent
VENDOR = HERE.parents[2] / ".local" / "mpc-prover-vendor" / "MP-SPDZ"
PREFIX = VENDOR.parent / "prefix" / "usr" / "include"


class V3NativeAuthorityControls(unittest.TestCase):
    def sources(self):
        return (
            HERE / "v3_native_authority.cpp",
            TRIAL / "privacy_measurement_authority.cpp",
            TRIAL / "privacy_measurement_child_output_authority.cpp",
            TRIAL / "privacy_measurement_output_abi.cpp",
        )

    def compile(self, output, *sources, test_setup=False):
        command = [
            "g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
            "-pedantic", "-pthread",
        ]
        if test_setup:
            command.append("-DKPB_V3_NATIVE_AUTHORITY_TEST_SETUP")
        command.extend(str(source) for source in sources)
        command.extend((
            "-I", str(HERE), "-I", str(TRIAL), "-lcrypto",
            "-o", str(output),
        ))
        return subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=60)

    def test_native_fd_route_durable_edges_crashes_and_tamper(self):
        with (
            tempfile.TemporaryDirectory(
                prefix="kpb-v3-native-authority-build-") as build,
            tempfile.TemporaryDirectory(
                prefix="kpb-v3-native-authority-run-") as run,
        ):
            binary = Path(build) / "control"
            compiled = self.compile(
                binary, HERE / "v3_native_authority_control.cpp",
                *self.sources(), test_setup=True)
            self.assertEqual(
                compiled.returncode, 0, compiled.stdout + compiled.stderr)
            executed = subprocess.run(
                [str(binary), run], capture_output=True, text=True,
                check=False, timeout=30)
            self.assertEqual(
                executed.returncode, 0, executed.stdout + executed.stderr)
            self.assertEqual((executed.stdout, executed.stderr), ("", ""))

    def test_issuance_validated_history_mints_one_shot_source_controller(self):
        with (
            tempfile.TemporaryDirectory(
                prefix="kpb-v3-lifecycle-controller-build-") as build,
            tempfile.TemporaryDirectory(
                prefix="kpb-v3-lifecycle-controller-run-") as run,
        ):
            binary = Path(build) / "controller"
            command = [
                "g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
                "-pedantic", "-Wno-overloaded-virtual", "-Wno-psabi",
                "-Wno-unused-function",
                "-march=native", "-pthread",
                "-DKPI_FRESH_OWNER_ISSUANCE_TEST_SETUP",
                "-DKPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP",
                "-DKPI_FRESH_OWNER_ARM_ISOLATION_TEST_SETUP",
                "-DKPB_MEASUREMENT_AUTHORITY_TEST_SETUP",
                "-DKPB_V3_NATIVE_AUTHORITY_TEST_SETUP",
                str(HERE / "v3_lifecycle_controller_control.cpp"),
                str(HERE / "v3_lifecycle_controller.cpp"),
                str(HERE / "v3_native_authority.cpp"),
                str(FINANCIAL / "fresh_owner_arm_isolation.cpp"),
                str(FINANCIAL /
                    "candidate_owner_truth_post_barrier_bridge.cpp"),
                str(FINANCIAL / "fresh_owner_process_adapter.cpp"),
                str(FINANCIAL / "fresh_owner_trial_issuance.cpp"),
                str(FINANCIAL / "registered_identity_registry.cpp"),
                str(TRIAL / "testnet_accepted_history_authority.cpp"),
                str(TRIAL / "privacy_measurement_authority.cpp"),
                str(TRIAL / "privacy_measurement_child_output_authority.cpp"),
                str(TRIAL / "privacy_measurement_output_abi.cpp"),
                "-I", str(HERE), "-I", str(FINANCIAL),
                "-I", str(MPC), "-I", str(TRIAL),
                "-I", str(VENDOR), "-I", str(PREFIX),
                "-I", str(PREFIX / "x86_64-linux-gnu"),
                str(VENDOR / "libSPDZ.so"),
                "-Wl,-rpath," + str(VENDOR), "-lcrypto", "-pthread",
                "-o", str(binary),
            ]
            compiled = subprocess.run(
                command, capture_output=True, text=True, check=False,
                timeout=90)
            self.assertEqual(
                compiled.returncode, 0,
                compiled.stdout + compiled.stderr)
            executed = subprocess.run(
                [str(binary), run], capture_output=True, text=True,
                check=False, timeout=45)
            self.assertEqual(
                executed.returncode, 0,
                executed.stdout + executed.stderr)
            self.assertEqual((executed.stdout, executed.stderr), ("", ""))

    def test_production_surface_has_no_minter_or_qualification_accessor(self):
        with tempfile.TemporaryDirectory(
                prefix="kpb-v3-native-production-") as directory:
            directory = Path(directory)
            source = directory / "production.cpp"
            source.write_text(r'''
#include "v3_native_authority.hpp"
#include <type_traits>
using namespace kpb::future_recipient::v3_native;
template<class T> concept HasTestMint = requires {
    T::test_only_mint(Invoice208{});
};
template<class T> concept HasInvoice = requires(const T& value) {
    value.invoice_;
};
template<class T> concept CanBypassLifecycleController = requires(
    ParentLedgerDescriptorsAuthority descriptors, T latest,
    const kpb::measurement::RunBinding& binding) {
    V3NativeAuthorityBridge::open_existing(
        std::move(descriptors), std::move(latest), binding);
};
static_assert(!std::is_constructible_v<InvoiceMaterialAuthority, Invoice208>);
static_assert(!std::is_constructible_v<LatestHeadAuthority,
    Digest, std::uint64_t, Digest>);
static_assert(!std::is_constructible_v<ExternalLatestHeadUpdaterAuthority,
    int, int, Digest>);
static_assert(!std::is_constructible_v<ParentLedgerDescriptorsAuthority,
    int, int, int, int>);
static_assert(!HasTestMint<InvoiceMaterialAuthority>);
static_assert(!HasInvoice<InvoiceMaterialAuthority>);
static_assert(!CanBypassLifecycleController<LatestHeadAuthority>);
static_assert(!CanBypassLifecycleController<
    ExternalLatestHeadUpdaterAuthority>);
static_assert(kV3NativeAuthoritySourceStatus.parent_owned_descriptors);
static_assert(kV3NativeAuthoritySourceStatus.sealed_invoice208_fd);
static_assert(kV3NativeAuthoritySourceStatus.exact_run_binding_fd);
static_assert(kV3NativeAuthoritySourceStatus.one_use_os_accept_capability);
static_assert(kV3NativeAuthoritySourceStatus.authenticated_append_only_edges);
static_assert(kV3NativeAuthoritySourceStatus.file_and_directory_fsync);
static_assert(kV3NativeAuthoritySourceStatus.exact_inode_mode_checks);
static_assert(kV3NativeAuthoritySourceStatus.missing_latest_head_refuses);
static_assert(kV3NativeAuthoritySourceStatus.external_latest_head_updater);
static_assert(kV3NativeAuthoritySourceStatus.external_head_file_and_directory_fsync);
static_assert(kV3NativeAuthoritySourceStatus.external_one_side_rollback_refusal);
static_assert(kV3NativeAuthoritySourceStatus.external_cross_trial_refusal);
static_assert(!kV3NativeAuthoritySourceStatus.external_joint_rollback_protection_integrated);
static_assert(kV3NativeAuthoritySourceStatus.typed_lifecycle_controller_source_seam);
static_assert(kV3NativeAuthoritySourceStatus.production_open_requires_lifecycle_controller);
static_assert(kV3NativeAuthoritySourceStatus.invoice_material_bound_to_parent_history);
static_assert(kV3NativeAuthoritySourceStatus.per_open_instance_bound_lifecycle);
static_assert(kV3NativeAuthoritySourceStatus.opaque_source_generation_bound_through_accept);
static_assert(!kV3NativeAuthoritySourceStatus.production_ledger_descriptor_minter_available);
static_assert(!kV3NativeAuthoritySourceStatus.production_external_updater_minter_available);
static_assert(!kV3NativeAuthoritySourceStatus.production_invoice_material_minter_available);
static_assert(!kV3NativeAuthoritySourceStatus.production_accepted_history_minter_available);
static_assert(!kV3NativeAuthoritySourceStatus.lifecycle_controller_minter_integrated);
static_assert(!kV3NativeAuthoritySourceStatus.selected_owner_launcher_integrated);
static_assert(!kV3NativeAuthoritySourceStatus.accepted_public_history_join_integrated);
static_assert(!kV3NativeAuthoritySourceStatus.configured);
int main() { return 0; }
''', encoding="utf-8")
            binary = directory / "production"
            compiled = self.compile(binary, source, *self.sources())
            self.assertEqual(
                compiled.returncode, 0, compiled.stdout + compiled.stderr)
            symbols = subprocess.run(
                ["nm", "-C", str(binary)], capture_output=True, text=True,
                check=False, timeout=10)
            self.assertEqual(
                symbols.returncode, 0, symbols.stdout + symbols.stderr)
            self.assertNotIn("test_only_mint", symbols.stdout)
            self.assertNotIn("initialize_fresh", symbols.stdout)
            self.assertNotIn("test_only_latest", symbols.stdout)
            self.assertNotIn("test_only_open_existing", symbols.stdout)

            controller_syntax = subprocess.run([
                "g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
                "-pedantic", "-Wno-overloaded-virtual", "-Wno-psabi",
                "-march=native", "-fsyntax-only",
                str(HERE / "v3_lifecycle_controller.cpp"),
                "-I", str(HERE), "-I", str(FINANCIAL),
                "-I", str(MPC), "-I", str(TRIAL),
                "-I", str(VENDOR), "-I", str(PREFIX),
                "-I", str(PREFIX / "x86_64-linux-gnu"),
            ], capture_output=True, text=True, check=False, timeout=60)
            self.assertEqual(
                controller_syntax.returncode, 0,
                controller_syntax.stdout + controller_syntax.stderr)

    def test_test_mints_and_complete_bridge_redefinition_fail_production(self):
        with tempfile.TemporaryDirectory(
                prefix="kpb-v3-native-forgery-") as directory:
            directory = Path(directory)
            mint = directory / "mint.cpp"
            mint.write_text(r'''
#include "v3_native_authority.hpp"
using namespace kpb::future_recipient::v3_native;
int main() {
    auto invoice = InvoiceMaterialAuthority::test_only_mint({});
    auto latest = LatestHeadAuthority::test_only_mint({}, 0, {});
    auto setup = V3NativeAuthorityTestSetup::initialize_fresh("/tmp", {}, {});
    (void)invoice; (void)latest; (void)setup;
}
''', encoding="utf-8")
            compiled = self.compile(
                directory / "mint", mint, *self.sources())
            self.assertNotEqual(compiled.returncode, 0)
            self.assertIn("test_only_mint", compiled.stderr)

            redefine = directory / "redefine.cpp"
            redefine.write_text(r'''
#include "v3_native_authority.hpp"
namespace kpb::future_recipient::v3_native {
class V3NativeAuthorityBridge final {
public:
    static InvoiceMaterialAuthority mint() {
        return InvoiceMaterialAuthority(Invoice208{});
    }
};
}
int main() { return 0; }
''', encoding="utf-8")
            result = subprocess.run([
                "g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
                "-pedantic", "-I", str(HERE), "-I", str(TRIAL),
                "-c", str(redefine), "-o", str(directory / "redefine.o"),
            ], capture_output=True, text=True, check=False, timeout=30)
            self.assertNotEqual(
                result.returncode, 0,
                "complete native authority bridge unexpectedly redefined")

    def test_native_layer_does_not_select_a_ciphertext_profile(self):
        source = (HERE / "v3_native_authority.cpp").read_text()
        header = (HERE / "v3_native_authority.hpp").read_text()
        controller = (HERE / "v3_lifecycle_controller.cpp").read_text()
        for forbidden in (
                "crypto_box", "ChaCha20", "Orchard", "ciphertext264",
                "Receipt216"):
            self.assertNotIn(forbidden, source + header + controller)
        self.assertIn("Invoice208", header)

    def test_invoice_material_constructor_callsites_are_closed(self):
        expected = sorted([
            ("v3_native_authority.cpp",
             "InvoiceMaterialAuthority::InvoiceMaterialAuthority("),
            ("v3_native_authority.cpp",
             "InvoiceMaterialAuthority::InvoiceMaterialAuthority("),
            ("v3_native_authority.cpp",
             "return InvoiceMaterialAuthority("),
            ("honest_owner_material_authority.cpp",
             "return v3_native::InvoiceMaterialAuthority("),
        ])
        observed = []
        roots = (HERE, TRIAL)
        for root in roots:
            for path in root.rglob("*.cpp"):
                for line in path.read_text(encoding="utf-8").splitlines():
                    stripped = line.strip()
                    if "InvoiceMaterialAuthority(" in stripped:
                        observed.append((path.name, stripped))
        self.assertEqual(sorted(observed), expected)

        header = (HERE / "v3_native_authority.hpp").read_text(
            encoding="utf-8")
        material = header.split(
            "class InvoiceMaterialAuthority final {", 1)[1].split(
                "class LatestHeadAuthority final {", 1)[0]
        self.assertNotIn("friend class V3NativeAuthorityBridge", material)
        self.assertNotIn("friend class V3NativeAuthorityTestSetup", material)


if __name__ == "__main__":
    unittest.main(verbosity=2)
