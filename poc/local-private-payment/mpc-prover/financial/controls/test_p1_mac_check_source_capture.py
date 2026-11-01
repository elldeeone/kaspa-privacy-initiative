#!/usr/bin/env python3
"""No-network controls for the typed corrupt-P1 field MAC-check seam."""

from pathlib import Path
import hashlib
import os
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
MPC = HERE.parent.parent
REPO = MPC.parents[2]
HOOK = MPC / "p1_mac_check_state_hook.hpp"
SOURCE_HPP = MPC / "p1_mac_check_source_capture.hpp"
SOURCE_CPP = MPC / "p1_mac_check_source_capture.cpp"
CONTROL = HERE / "p1_mac_check_source_capture_control.cpp"
MAC_CHECK = (
    REPO / ".local/mpc-prover-vendor/MP-SPDZ/Protocols/MAC_Check.hpp")
MAC_CHECK_SHA256 = (
    "6aa24821e6dae6370cd89832f407523dc046d4648dcc281f36dd054d7cb723b8")


class MacCheckSourceControls(unittest.TestCase):
    @staticmethod
    def _compile(root: Path, sanitizers: bool) -> Path:
        binary = root / "control"
        command = [
            "g++", "-std=c++20", "-O1", "-g0", "-Wall", "-Wextra",
            "-Werror", "-Wpedantic",
            "-DKPI_P1_MAC_CHECK_STATE_HOOK_TEST_SETUP",
        ]
        if sanitizers:
            command.extend([
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            ])
        command.extend([
            "-I", str(MPC), str(SOURCE_CPP), str(CONTROL), "-pthread",
            "-o", str(binary),
        ])
        result = subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=120)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        return binary

    def _compile_and_run(self, sanitizers: bool):
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-mac-check-source-") as raw:
            binary = self._compile(Path(raw), sanitizers)
            environment = dict(os.environ)
            if sanitizers:
                environment["ASAN_OPTIONS"] = (
                    "detect_leaks=1:halt_on_error=1:abort_on_error=1")
                environment["UBSAN_OPTIONS"] = (
                    "halt_on_error=1:print_stacktrace=1")
            result = subprocess.run(
                [str(binary)], capture_output=True, text=True, check=False,
                timeout=30, env=environment)
            self.assertEqual(
                result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((result.stdout, result.stderr), ("", ""))

    def test_exact_sequence_and_fail_stop_normal(self):
        self._compile_and_run(False)

    def test_exact_sequence_and_fail_stop_sanitized(self):
        self._compile_and_run(True)

    def test_hook_factory_attempt_and_edges_cannot_be_forged(self):
        probes = {
            "hook": r'''
#include "p1_mac_check_state_hook.hpp"
using namespace kpi::mpc::p1_private_state;
struct Forged final : MacCheckStateHook {
  bool record_mac_check_begin(const MacCheckBeginView&) noexcept override { return true; }
  bool record_mac_check_collective_seed(const MacCheckCollectiveSeedView&) noexcept override { return true; }
  bool record_mac_check_local_tau(const MacCheckLocalTauView&) noexcept override { return true; }
  bool record_mac_check_success_reset(const MacCheckSuccessResetView&) noexcept override { return true; }
  bool record_mac_check_unavailable(const MacCheckUnavailableView&) noexcept override { return true; }
  bool mac_check_capture_terminal_noexcept() noexcept override { return true; }
};
int main() { Forged value; (void)value; }
''',
            "factory": r'''
#include "p1_mac_check_source_capture.hpp"
namespace kpi::mpc::p1_private_state {
class MacCheckScopeFactoryBridge final {};
}
int main() {}
''',
            "direct_install": r'''
#include "p1_mac_check_source_capture.hpp"
using namespace kpi::mpc::p1_private_state;
MacCheckSourceScope steal(MacCheckStateHook& hook) {
  return MacCheckScopeFactoryBridge::install(hook, 1, 1, 1, 1, 3);
}
int main() {}
''',
            "attempt": r'''
#include "p1_mac_check_source_capture.hpp"
using namespace kpi::mpc::p1_private_state;
int main() { MacCheckAttemptScope forged(1, 1, true, true); }
''',
            "source_edge": r'''
#include "p1_mac_check_source_capture.hpp"
#include <array>
using namespace kpi::mpc::p1_private_state;
int main() {
  std::array<unsigned char, 32> value{};
  (void)MacCheckSourceBridge::check_begin_noexcept(
      1, 3, 1, value, value, value);
}
''',
        }
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-mac-check-forge-") as raw:
            root = Path(raw)
            for name, body in probes.items():
                source = root / f"{name}.cpp"
                source.write_text(body, encoding="utf-8")
                result = subprocess.run(
                    ["g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
                     "-Wpedantic", "-fsyntax-only", str(source),
                     "-I", str(MPC)],
                    capture_output=True, text=True, check=False, timeout=30)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertTrue(
                    "private" in result.stderr or
                    "redefinition" in result.stderr or
                    "deleted" in result.stderr,
                    result.stderr)

    def test_selected_source_trace_and_runtime_claim_are_separate(self):
        raw = MAC_CHECK.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), MAC_CHECK_SHA256)
        source = raw.decode("utf-8")
        ordered = (
            "Create_Random_Seed(seed,P,SEED_SIZE);",
            "G.SetSeed(seed);",
            "h.almost_randomize(G);",
            "tau[P.my_num()] = (gami - temp);",
            "Commit_And_Open(tau, P, *this->coordinator);",
            "reset();",
        )
        cursor = 0
        positions = []
        for value in ordered:
            cursor = source.index(value, cursor)
            positions.append(cursor)
            cursor += len(value)
        self.assertEqual(positions, sorted(positions))
        batched = (MPC / "batched_assignment.cpp").read_text(
            encoding="utf-8")
        self.assertEqual(
            batched.count("Create_Random(contribution, context.player());"),
            1)

        selected = (
            REPO / ".local/registered-financial-gate-build-12/"
            "mpc-registered-financial-gate")
        self.assertTrue(selected.is_file())
        symbols = subprocess.run(
            ["nm", "-D", "-C", str(selected)], capture_output=True,
            text=True, check=True, timeout=30).stdout
        self.assertIn(
            " U Commit(octetStream&, octetStream&, octetStream const&, int)",
            symbols)

        status = HOOK.read_text(encoding="utf-8")
        for required in (
                ".source_patch_selected = false",
                ".capsule_family_adapter = false",
                ".selected_role1_installation = false",
                ".complete_mac_check_family = false",
                ".complete_corrupt_p1_view = false",
                ".configured = false"):
            self.assertIn(required, status)
        self.assertNotIn("__builtin_return_address", SOURCE_CPP.read_text())
        self.assertNotIn("pthread_self", SOURCE_CPP.read_text())


if __name__ == "__main__":
    unittest.main()
