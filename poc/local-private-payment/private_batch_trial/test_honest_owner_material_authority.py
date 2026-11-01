#!/usr/bin/env python3
"""Compiled controls for the source-owned honest-owner lifecycle seam."""

from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
V3 = HERE.parents[1] / "future-recipient" / "v3"
FINANCIAL = HERE.parent / "mpc-prover" / "financial"
MPC = FINANCIAL.parent
VENDOR = HERE.parents[2] / ".local" / "mpc-prover-vendor" / "MP-SPDZ"
PREFIX = VENDOR.parent / "prefix" / "usr" / "include"


class HonestOwnerMaterialAuthorityControls(unittest.TestCase):
    def test_exact_v3_lifecycle_and_adversarial_controls(self):
        with (tempfile.TemporaryDirectory(prefix="kpb-honest-owner-build-") as build,
              tempfile.TemporaryDirectory(prefix="kpb-honest-owner-run-") as run):
            binary = Path(build) / "control"
            command = [
                "g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
                "-pedantic", "-Wno-overloaded-virtual", "-Wno-psabi",
                "-Wno-unused-function", "-march=native", "-pthread",
                "-DKPI_FRESH_OWNER_ISSUANCE_TEST_SETUP",
                "-DKPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP",
                "-DKPI_FRESH_OWNER_ARM_ISOLATION_TEST_SETUP",
                "-DKPB_MEASUREMENT_AUTHORITY_TEST_SETUP",
                "-DKPB_V3_NATIVE_AUTHORITY_TEST_SETUP",
                "-DKPB_HONEST_OWNER_MATERIAL_TEST_SETUP",
                str(HERE / "honest_owner_material_authority_control.cpp"),
                str(HERE / "honest_owner_material_authority.cpp"),
                str(HERE / "honest_owner_material_test_fixture.cpp"),
                str(V3 / "v3_lifecycle_controller.cpp"),
                str(V3 / "v3_native_authority.cpp"),
                str(FINANCIAL / "fresh_owner_arm_isolation.cpp"),
                str(FINANCIAL / "candidate_owner_truth_post_barrier_bridge.cpp"),
                str(FINANCIAL / "fresh_owner_process_adapter.cpp"),
                str(FINANCIAL / "fresh_owner_trial_issuance.cpp"),
                str(FINANCIAL / "registered_identity_registry.cpp"),
                str(HERE / "privacy_measurement_authority.cpp"),
                str(HERE / "privacy_measurement_child_output_authority.cpp"),
                str(HERE / "privacy_measurement_output_abi.cpp"),
                str(HERE / "testnet_accepted_history_authority.cpp"),
                "-I", str(V3), "-I", str(FINANCIAL), "-I", str(MPC),
                "-I", str(HERE), "-I", str(VENDOR), "-I", str(PREFIX),
                "-I", str(PREFIX / "x86_64-linux-gnu"),
                str(VENDOR / "libSPDZ.so"),
                "-Wl,-rpath," + str(VENDOR), "-lcrypto", "-pthread",
                "-o", str(binary),
            ]
            compiled = subprocess.run(command, capture_output=True, text=True,
                                      check=False, timeout=120)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            executed = subprocess.run([str(binary), run], capture_output=True,
                                      text=True, check=False, timeout=60)
            self.assertEqual(executed.returncode, 0,
                             executed.stdout + executed.stderr)
            self.assertEqual((executed.stdout, executed.stderr), ("", ""))

    def test_production_surface_is_opaque_and_test_source_is_absent(self):
        with tempfile.TemporaryDirectory(prefix="kpb-honest-owner-production-") as directory:
            directory = Path(directory)
            source = directory / "production.cpp"
            source.write_text(r'''
#include "honest_owner_material_authority.hpp"
#include "native_terminal_completion.hpp"
#include <concepts>
#include <utility>
using namespace kpb::honest_owner_material;
using namespace kpb::native_terminal;
template<class T> concept HasOutput = requires(const T& value) { value.output_; };
template<class T> concept HasNullifier = requires(const T& value) { value.public_nullifier_; };
template<class T> concept HasInvoice = requires(const T& value) { value.invoice_; };
template<class T> concept HasOldTerminalFactory = requires(T&& value) {
    std::move(value).transfer_for_terminal_v2_model();
};
template<class T> concept HasBoundTerminalFactory = requires(
        T&& value, HonestOwnerTwoRoundProductionAuthority&& honest) {
    std::move(value).transfer_for_terminal_v2_model(std::move(honest));
};
static_assert(!std::default_initializable<HonestInvoiceSourceAuthority>);
static_assert(!std::copy_constructible<HonestInvoiceSourceAuthority>);
static_assert(!std::default_initializable<HonestOwnerOutputAuthority>);
static_assert(!std::copy_constructible<HonestOwnerOutputAuthority>);
static_assert(!std::default_initializable<HonestOwnerProductionAuthority>);
static_assert(!std::copy_constructible<HonestOwnerProductionAuthority>);
static_assert(!std::default_initializable<HonestOwnerTwoRoundProductionAuthority>);
static_assert(!std::copy_constructible<HonestOwnerTwoRoundProductionAuthority>);
static_assert(!HasOutput<HonestOwnerOutputAuthority>);
static_assert(!HasNullifier<HonestOwnerOutputAuthority>);
static_assert(!HasInvoice<HonestInvoiceSourceAuthority>);
static_assert(!HasOutput<HonestOwnerTwoRoundProductionAuthority>);
static_assert(!HasOldTerminalFactory<MatchedNativeTerminalProducerBundle>);
static_assert(HasBoundTerminalFactory<MatchedNativeTerminalProducerBundle>);
static_assert(kHonestOwnerMaterialSourceStatus.exact_run_binding_before_generation);
static_assert(kHonestOwnerMaterialSourceStatus.round_owner_slot_index_before_generation);
static_assert(kHonestOwnerMaterialSourceStatus.v3_accepted_history_join);
static_assert(kHonestOwnerMaterialSourceStatus.live_parent_exactly_matches_accepted_authority);
static_assert(kHonestOwnerMaterialSourceStatus.accepted_invoice_exact_match);
static_assert(kHonestOwnerMaterialSourceStatus.cm_cv_ciphertext_proof_exact_row_match);
static_assert(kHonestOwnerMaterialSourceStatus.public_nullifier_exact_match);
static_assert(kHonestOwnerMaterialSourceStatus.move_only_terminal_residual);
static_assert(kHonestOwnerMaterialSourceStatus.terminal_v2_factory_requires_residual);
static_assert(kHonestOwnerMaterialSourceStatus.no_public_secret_or_row_getter);
static_assert(!kHonestOwnerMaterialSourceStatus.production_invoice_source_minter_available);
static_assert(!kHonestOwnerMaterialSourceStatus.production_output_source_minter_available);
static_assert(!kHonestOwnerMaterialSourceStatus.selected_owner_worker_integrated);
static_assert(!kHonestOwnerMaterialSourceStatus.selected_lifecycle_callsite_integrated);
static_assert(!kHonestOwnerMaterialSourceStatus.configured);
int main() { return 0; }
''', encoding="utf-8")
            binary = directory / "production"
            command = [
                "g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
                "-pedantic", "-pthread", str(source),
                str(HERE / "honest_owner_material_authority.cpp"),
                str(V3 / "v3_native_authority.cpp"),
                str(HERE / "privacy_measurement_authority.cpp"),
                str(HERE / "privacy_measurement_child_output_authority.cpp"),
                str(HERE / "privacy_measurement_output_abi.cpp"),
                "-I", str(HERE), "-I", str(V3), "-lcrypto",
                "-o", str(binary),
            ]
            compiled = subprocess.run(command, capture_output=True, text=True,
                                      check=False, timeout=60)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            symbols = subprocess.run(["nm", "-C", str(binary)],
                                     capture_output=True, text=True,
                                     check=False, timeout=10)
            self.assertEqual(symbols.returncode, 0,
                             symbols.stdout + symbols.stderr)
            self.assertNotIn("test_only_bind_to_parent", symbols.stdout)
            self.assertNotIn("HonestOwnerMaterialTestFixture", symbols.stdout)

    def test_complete_friend_contract_cannot_be_redefined(self):
        with tempfile.TemporaryDirectory(prefix="kpb-honest-owner-friend-") as directory:
            source = Path(directory) / "hostile.cpp"
            source.write_text(r'''
#include "honest_owner_material_authority.hpp"
namespace kpb::honest_owner_material { class V3InvoiceMaterialMinter final {}; }
int main() { return 0; }
''', encoding="utf-8")
            compiled = subprocess.run([
                "g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
                "-pedantic", "-fsyntax-only", str(source), "-I", str(HERE),
            ], capture_output=True, text=True, check=False, timeout=30)
            self.assertNotEqual(compiled.returncode, 0)
            self.assertIn("redefinition", compiled.stderr)


if __name__ == "__main__":
    unittest.main()
