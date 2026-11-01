#!/usr/bin/env python3
"""Hostile controls for the source-owned P1 MASCOT abort manifest."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
MPC = HERE.parent / "mpc-prover"
HEADER = HERE / "privacy_p1_mascot_abort_terminal_manifest_authority.hpp"
IMPLEMENTATION = HERE / "privacy_p1_mascot_abort_terminal_manifest_authority.cpp"
CONTROL = HERE / "privacy_p1_mascot_abort_terminal_manifest_authority_control.cpp"
CAPSULE = HERE / "privacy_p1_corrupt_state_capsule_authority.cpp"
HOOK = MPC / "p1_mascot_secret_state_hook.cpp"
PATCH = MPC / "vendor-patches" / "mp-spdz-p1-mascot-secret-state-v2.patch"
PRISTINE = HERE.parents[2] / ".local" / "mpc-prover-vendor" / "MP-SPDZ"


class P1MascotAbortTerminalManifestControls(unittest.TestCase):
    def compile_and_run(self, sanitized: bool):
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-mascot-abort-manifest-") as raw:
            binary = Path(raw) / "control"
            command = [
                "g++", "-std=c++20", "-O1", "-g0", "-Wall", "-Wextra",
                "-Werror", "-Wpedantic", "-pthread",
                "-DKPB_P1_MASCOT_ABORT_TERMINAL_MANIFEST_TEST_SETUP",
                "-DKPB_P1_STATE_CAPSULE_TEST_SETUP",
            ]
            if sanitized:
                command.extend([
                    "-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer",
                ])
            command.extend([
                str(CONTROL), str(IMPLEMENTATION), str(CAPSULE), str(HOOK),
                str(HERE / "privacy_measurement_authority.cpp"),
                str(HERE / "privacy_measurement_child_output_authority.cpp"),
                str(HERE / "privacy_measurement_output_abi.cpp"),
                "-I", str(HERE), "-I", str(MPC), "-lcrypto",
                "-o", str(binary),
            ])
            compiled = subprocess.run(
                command, capture_output=True, text=True, check=False,
                timeout=90)
            self.assertEqual(
                compiled.returncode, 0, compiled.stdout + compiled.stderr)
            environment = dict(os.environ)
            if sanitized:
                environment["ASAN_OPTIONS"] = (
                    "detect_leaks=1:halt_on_error=1:abort_on_error=1")
                environment["UBSAN_OPTIONS"] = (
                    "halt_on_error=1:print_stacktrace=1")
            run = subprocess.run(
                [str(binary)], capture_output=True, text=True, check=False,
                timeout=30, env=environment)
            self.assertEqual(
                (run.returncode, run.stdout, run.stderr), (0, "", ""))

    def test_canonical_manifest_normal(self):
        self.compile_and_run(False)

    def test_canonical_manifest_sanitized(self):
        self.compile_and_run(True)

    def test_production_caller_cannot_compile_or_construct(self):
        probes = {
            "compile": r'''
#include "privacy_p1_mascot_abort_terminal_manifest_authority.hpp"
int main() {
  auto value = kpb::measurement::p1_state::
      P1MascotAbortTerminalManifestCompilerBridge::compile();
  (void)value;
}
''',
            "construct": r'''
#include "privacy_p1_mascot_abort_terminal_manifest_authority.hpp"
#include <memory>
int main() {
  using A = kpb::measurement::p1_state::
      P1MascotAbortTerminalManifestAuthority;
  A value(std::unique_ptr<A::Storage>{});
  (void)value;
}
''',
        }
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-mascot-abort-forge-") as raw:
            root = Path(raw)
            for name, body in probes.items():
                source = root / f"{name}.cpp"
                source.write_text(body, encoding="utf-8")
                result = subprocess.run([
                    "g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
                    "-Wpedantic", "-I", str(HERE), "-I", str(MPC),
                    "-fsyntax-only", str(source),
                ], capture_output=True, text=True, check=False, timeout=30)
                self.assertNotEqual(result.returncode, 0, name)

    def test_patch_and_surface_are_source_bound_and_honest(self):
        patch = PATCH.read_text(encoding="utf-8")
        for required in (
                "register_ot_worker_noexcept",
                "ot_worker_failure_published_noexcept",
                "root_worker_failure_observed_noexcept",
                "ot_worker_joined_noexcept",
                "stop_and_join_multipliers",
                "unlink_cache_for_abort"):
            self.assertIn(required, patch)
        applied = subprocess.run([
            "patch", "--dry-run", "--fuzz=0", "-p1", "-d", str(PRISTINE),
            "-i", str(PATCH),
        ], capture_output=True, text=True, check=False, timeout=30)
        self.assertEqual(
            applied.returncode, 0, applied.stdout + applied.stderr)
        header = HEADER.read_text(encoding="utf-8")
        self.assertNotIn("get_manifest", header)
        self.assertNotIn("std::span", header)
        implementation = IMPLEMENTATION.read_text(encoding="utf-8")
        self.assertIn("unbounded_stuck_worker_terminal_closure = false",
                      implementation)
        self.assertIn("selected_role_child_callsite = false", implementation)
        self.assertIn("configured = false", implementation)


if __name__ == "__main__":
    unittest.main()
