#!/usr/bin/env python3
"""Typed-source and fail-closed controls for the P1 capsule compiler."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
MPC = HERE.parent / "mpc-prover"
FINANCIAL = MPC / "financial"
HEADER = HERE / "privacy_p1_state_capsule_prelaunch_compiler_contract.hpp"
ACTIVATION_HEADER = (
    FINANCIAL / "registered_selected_producer_activation_contract.hpp"
)
CONTROL = HERE / "privacy_p1_state_capsule_prelaunch_compiler_contract_control.cpp"
SOURCES = [
    HERE / "privacy_p1_state_capsule_prelaunch_compiler_contract.cpp",
    HERE / "privacy_p1_corrupt_state_capsule_authority.cpp",
    HERE / "privacy_p1_mascot_fresh_prep_directory_authority.cpp",
    HERE / "privacy_p1_mascot_two_round_manifest_authority.cpp",
    HERE / "privacy_p1_mascot_abort_terminal_manifest_authority.cpp",
    HERE / "privacy_prelaunch_policy_domain_authority.cpp",
    FINANCIAL / "registered_selected_producer_run_binding.cpp",
    MPC / "p1_mascot_secret_state_hook.cpp",
]


class P1StateCapsulePrelaunchCompilerContractControls(unittest.TestCase):
    def compile_control(self, output, *, sanitize=False):
        command = [
            "c++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
            "-pedantic", "-ffunction-sections", "-fdata-sections",
            "-I", str(HERE), "-I", str(MPC), "-I", str(FINANCIAL),
        ]
        if sanitize:
            command.extend([
                "-O1", "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
            ])
        command.extend([str(CONTROL), *(str(value) for value in SOURCES)])
        command.extend(["-Wl,--gc-sections", "-lcrypto", "-pthread",
                        "-o", str(output)])
        return subprocess.run(
            command, capture_output=True, text=True, check=False,
        )

    def run_control(self, binary):
        run = subprocess.run(
            [str(binary)], capture_output=True, text=True, check=False,
        )
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_fail_closed_surface_and_status_control(self):
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-plan-compiler-") as raw:
            binary = Path(raw) / "control"
            built = self.compile_control(binary)
            self.assertEqual(
                built.returncode, 0, built.stdout + built.stderr,
            )
            self.run_control(binary)

    def test_control_is_clean_under_asan_and_ubsan(self):
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-plan-compiler-sanitize-") as raw:
            binary = Path(raw) / "control"
            built = self.compile_control(binary, sanitize=True)
            self.assertEqual(
                built.returncode, 0, built.stdout + built.stderr,
            )
            self.run_control(binary)

    def hostile_source_fails(self, source_text):
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-plan-compiler-hostile-") as raw:
            root = Path(raw)
            source = root / "hostile.cpp"
            source.write_text(
                source_text,
                encoding="utf-8",
            )
            output = root / "hostile.o"
            command = [
                "c++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
                "-pedantic", "-I", str(HERE), "-c", str(source),
                "-o", str(output),
            ]
            built = subprocess.run(
                command, capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(
                built.returncode, 0, built.stdout + built.stderr,
            )

    def hostile_compile_fails(self, body):
        self.hostile_source_fails(
            '#include "privacy_p1_state_capsule_prelaunch_compiler_contract.hpp"\n'
            + body,
        )

    def test_macro_free_compiler_has_no_raw_plan_digest_fd_event_or_manifest_mint(self):
        for body in (
            """
using namespace kpb::measurement::p1_state;
int main() {
  return P1StateCapsulePrelaunchCompilerBridge::compile(7, 8, 9, 10);
}
""",
            """
#include <array>
using namespace kpb::measurement::p1_state;
int main() {
  std::array<unsigned char, 32> digest{};
  return P1StateCapsulePrelaunchCompilerBridge::compile(digest);
}
""",
            """
using namespace kpb::measurement::p1_state;
int main() {
  P1HookSerializerManifestAuthority value;
  return value.fd();
}
""",
            """
using namespace kpb::measurement::p1_state;
int main() {
  P1AbortTerminalManifestAuthority value;
  return value.event_factory();
}
""",
            """
using namespace kpb::measurement::p1_state;
int main() {
  return P1HookSerializerManifestSourceBridge::mint({});
}
""",
            """
using namespace kpb::measurement::p1_state;
int main() {
  return P1StateCapsulePrelaunchCompilerBridge::test_only_compile({});
}
""",
            """
#include "../mpc-prover/financial/registered_selected_producer_run_binding.hpp"
#include "privacy_p1_mascot_fresh_prep_directory_authority.hpp"
using namespace kpb::measurement::p1_state;
using namespace kpi::mpc::financial::registered_driver;
using Bad = P1StateCapsulePrelaunchUnavailableAuthority (*)(
    RegisteredSelectedProducerPrelaunchBindingAuthority&&,
    P1MascotFreshPrepDirectoryAuthority&&);
Bad bad = &P1StateCapsulePrelaunchCompilerBridge::compile;
int main() { return bad == nullptr; }
""",
            """
using namespace kpb::measurement::p1_state;
using Leak = P1HookSerializerManifestAuthority::Storage;
int main() { return sizeof(Leak); }
""",
            """
using namespace kpb::measurement::p1_state;
using Leak = P1AbortTerminalManifestAuthority::Storage;
int main() { return sizeof(Leak); }
""",
            """
using namespace kpb::measurement::p1_state;
using Leak = P1StateCapsulePrelaunchUnavailableAuthority::Storage;
int main() { return sizeof(Leak); }
""",
        ):
            with self.subTest(body=body):
                self.hostile_compile_fails(body)

    def test_hostile_bridge_redefinition_is_rejected(self):
        self.hostile_compile_fails("""
namespace kpb::measurement::p1_state {
class P1StateCapsulePrelaunchCompilerBridge final {
public:
  static int compile(int) { return 1; }
};
}
int main() { return 0; }
""")

    def test_hostile_activation_result_substitution_is_rejected(self):
        self.hostile_compile_fails("""
#include <utility>
namespace kpi::mpc::financial::registered_driver {
class RegisteredSelectedProducerActivationResult final {
public:
  RegisteredSelectedProducerActivationResult() = default;
};
}
int main() {
  using R = kpi::mpc::financial::registered_driver::
      RegisteredSelectedProducerActivationResult;
  R forged;
  auto unavailable = kpb::measurement::p1_state::
      P1StateCapsulePrelaunchCompilerBridge::compile(std::move(forged));
  (void)unavailable;
}
""")

    def test_hostile_unavailable_output_substitution_is_rejected(self):
        self.hostile_source_fails("""
#include "../mpc-prover/financial/registered_selected_producer_activation_contract.hpp"
namespace kpb::measurement::p1_state {
class P1StateCapsulePrelaunchUnavailableAuthority final {
  unsigned forged{};
};
}
int main() { return 0; }
""")

    def test_every_granting_header_forces_the_privileged_definition(self):
        for header in (
            "../mpc-prover/financial/registered_selected_producer_run_binding.hpp",
            "../mpc-prover/financial/registered_selected_producer_activation_contract.hpp",
            "privacy_prelaunch_policy_domain_authority.hpp",
        ):
            with self.subTest(header=header):
                self.hostile_source_fails(f"""
#include "{header}"
namespace kpb::measurement::p1_state {{
class P1StateCapsulePrelaunchCompilerBridge final {{
public:
  static int compile(int) {{ return 1; }}
}};
}}
int main() {{ return 0; }}
""")

    def test_new_cross_file_accessors_remain_private(self):
        for body in (
            """
#include "../mpc-prover/financial/registered_selected_producer_run_binding.hpp"
using T = kpi::mpc::financial::registered_driver::
    RegisteredSelectedProducerPrelaunchBindingAuthority;
auto leak = &T::inspect_for_state_capsule_compiler;
int main() { return 0; }
""",
            """
#include "../mpc-prover/financial/registered_selected_producer_run_binding.hpp"
using T = kpi::mpc::financial::registered_driver::
    RegisteredSelectedProducerPrelaunchBindingAuthority;
int main() { (void)T::test_only_state_capsule_binding({}); }
""",
            """
#include "../mpc-prover/financial/registered_selected_producer_activation_contract.hpp"
using T = kpi::mpc::financial::registered_driver::
    RegisteredSelectedProducerActivationAuthority;
auto leak = &T::claim_mascot_for_state_capsule_compiler;
int main() { return 0; }
""",
            """
#include "../mpc-prover/financial/registered_selected_producer_activation_contract.hpp"
using T = kpi::mpc::financial::registered_driver::
    RegisteredSelectedProducerActivationCapsuleTestBridge;
int main() { (void)sizeof(T); }
""",
            """
#include "privacy_prelaunch_policy_domain_authority.hpp"
using T = kpb::measurement::prelaunch_policy_domain::
    RegisteredPrelaunchPolicyDomainAuthority;
auto leak = &T::consume_for_selected_activation;
int main() { return 0; }
""",
            """
#include "privacy_p1_corrupt_state_capsule_authority.hpp"
using T = kpb::measurement::p1_state_capsule::
    P1CorruptStateCapsuleSourceBridge;
auto leak = &T::mint_from_prelaunch_compiler;
int main() { return 0; }
""",
            """
#include "privacy_p1_corrupt_state_capsule_authority.hpp"
using T = kpb::measurement::p1_state_capsule::
    P1CorruptStateCapsulePlanAuthority;
auto leak = &T::inspect_for_prelaunch_compiler;
int main() { return 0; }
""",
            """
#include "privacy_p1_mascot_two_round_manifest_authority.hpp"
using T = kpb::measurement::p1_state::
    P1MascotTwoRoundManifestAuthority;
auto leak = &T::inspect_for_capsule_compiler;
int main() { return 0; }
""",
            """
#include "privacy_p1_mascot_abort_terminal_manifest_authority.hpp"
using T = kpb::measurement::p1_state::
    P1MascotAbortTerminalManifestAuthority;
auto leak = &T::claim_for_capsule_compiler;
int main() { return 0; }
""",
        ):
            with self.subTest(body=body):
                self.hostile_compile_fails(body)

    def test_macro_cannot_add_privileged_test_members(self):
        self.hostile_source_fails(r'''
#define KPB_P1_STATE_CAPSULE_COMPILER_TEST_SETUP
#include "../mpc-prover/financial/registered_selected_producer_run_binding.hpp"
#include <utility>
namespace kpi::mpc::financial::registered_driver {
RegisteredSelectedProducerPrelaunchBindingAuthority
RegisteredSelectedProducerPrelaunchBindingAuthority::
test_only_state_capsule_binding(
        RegisteredSelectedProducerPrelaunchPlan plan) {
    identity_registry::Digest attacker_chosen{};
    attacker_chosen[0] = 1;
    return RegisteredSelectedProducerPrelaunchBindingAuthority(
        std::move(plan), attacker_chosen);
}
}
int main() { return 0; }
''')
        self.hostile_source_fails(r'''
#define KPB_P1_STATE_CAPSULE_COMPILER_TEST_SETUP
#include "privacy_p1_state_capsule_prelaunch_compiler_contract.hpp"
namespace kpb::measurement::p1_state {
P1StateCapsulePrelaunchUnavailableAuthority
P1StateCapsulePrelaunchCompilerBridge::test_only_compile() {
    __builtin_unreachable();
}
}
int main() { return 0; }
''')

    def test_production_header_exposes_only_typed_linear_compile(self):
        text = HEADER.read_text(encoding="utf-8")
        activation_text = ACTIVATION_HEADER.read_text(encoding="utf-8")
        self.assertLess(
            activation_text.index(
                "class RegisteredSelectedProducerActivationResult final",
            ),
            activation_text.index(
                "class P1StateCapsulePrelaunchCompilerBridge final",
            ),
        )
        self.assertTrue(
            text.lstrip().startswith("#pragma once"),
        )
        self.assertLess(
            text.index(
                '#include "../mpc-prover/financial/'
                'registered_selected_producer_activation_contract.hpp"',
            ),
            text.index("friend class P1StateCapsulePrelaunchCompilerBridge"),
        )
        self.assertIn(
            "static P1StateCapsulePrelaunchUnavailableAuthority compile",
            activation_text,
        )
        self.assertIn(
            "RegisteredSelectedProducerActivationResult&&", activation_text,
        )
        compile_start = activation_text.index(
            "static P1StateCapsulePrelaunchUnavailableAuthority compile",
        )
        compile_end = activation_text.index("};", compile_start)
        production_compile = activation_text[compile_start:compile_end]
        self.assertNotIn(
            "P1MascotFreshPrepDirectoryAuthority&&", production_compile,
        )
        self.assertNotIn("StaticStateCapsulePlan", text)
        self.assertNotIn("PolicyDigest", text)
        self.assertNotIn(" int fd", text)
        self.assertNotIn("std::span", text)
        self.assertNotIn(
            "KPB_P1_STATE_CAPSULE_COMPILER_TEST_SETUP", activation_text,
        )
        self.assertNotIn(
            "test_only_state_capsule_binding",
            (FINANCIAL / "registered_selected_producer_run_binding.hpp")
            .read_text(encoding="utf-8"),
        )
        for required in (
            "P1HookSerializerManifestAuthority",
            "P1AbortTerminalManifestAuthority",
            "P1CorruptStateCapsulePlanAuthority",
            "P1StateCapsulePrelaunchUnavailableAuthority",
            "P1StateCapsulePrelaunchSplit",
        ):
            self.assertIn(required, text)

        source_text = SOURCES[0].read_text(encoding="utf-8")
        self.assertNotIn(".persistent_child_epoch = 1", source_text)
        self.assertNotIn(".context_allocation_epoch = 1", source_text)
        self.assertNotIn("mint_from_prelaunch_compiler", source_text)
        self.assertNotIn("StaticStateCapsulePlan", source_text)
        capsule_header = (
            HERE / "privacy_p1_corrupt_state_capsule_authority.hpp"
        ).read_text(encoding="utf-8")
        capsule_source = SOURCES[1].read_text(encoding="utf-8")
        self.assertNotIn("mint_from_prelaunch_compiler", capsule_header)
        self.assertNotIn("mint_from_prelaunch_compiler", capsule_source)


if __name__ == "__main__":
    unittest.main()
