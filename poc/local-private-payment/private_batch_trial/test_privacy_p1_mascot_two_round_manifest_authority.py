#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


HERE = Path(__file__).resolve().parent
CAPSULE = HERE / "privacy_p1_corrupt_state_capsule_authority.cpp"
HOOK = HERE.parent / "mpc-prover" / "p1_mascot_secret_state_hook.cpp"
FRESH = HERE / "privacy_p1_mascot_fresh_prep_directory_authority.cpp"
SOURCE = HERE / "privacy_p1_mascot_two_round_manifest_authority.cpp"
CONTROL = HERE / "privacy_p1_mascot_two_round_manifest_authority_control.cpp"
MEASUREMENT = HERE / "privacy_measurement_authority.cpp"
CHILD_OUTPUT = HERE / "privacy_measurement_child_output_authority.cpp"
OUTPUT_ABI = HERE / "privacy_measurement_output_abi.cpp"


class MascotTwoRoundManifestControl(unittest.TestCase):
    def build_and_run(self, sanitize: bool) -> None:
        with tempfile.TemporaryDirectory(prefix="kpb-mascot-two-round-") as raw:
            binary = Path(raw) / "control"
            command = [
                "c++", "-std=c++20", "-O1", "-g", "-Wall", "-Wextra",
                "-Werror", "-DKPB_P1_STATE_CAPSULE_TEST_SETUP=1",
                "-DKPB_P1_MASCOT_SECRET_STATE_HOOK_TEST_SETUP=1",
                "-DKPB_P1_MASCOT_FRESH_PREP_DIRECTORY_TEST_SETUP=1",
                "-DKPB_P1_MASCOT_TWO_ROUND_MANIFEST_TEST_SETUP=1",
                str(SOURCE), str(FRESH), str(CAPSULE), str(HOOK),
                str(MEASUREMENT), str(CHILD_OUTPUT), str(OUTPUT_ABI),
                str(CONTROL), "-I", str(HERE), "-lcrypto", "-lpthread",
                "-o", str(binary),
            ]
            if sanitize:
                command[1:1] = [
                    "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                ]
            built = subprocess.run(command, text=True, capture_output=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            environment = os.environ.copy()
            if sanitize:
                environment["ASAN_OPTIONS"] = "detect_leaks=1:abort_on_error=1"
                environment["UBSAN_OPTIONS"] = "halt_on_error=1"
            run = subprocess.run(
                [str(binary)], text=True, capture_output=True, env=environment,
            )
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_normal(self) -> None:
        self.build_and_run(False)

    def test_asan_ubsan(self) -> None:
        self.build_and_run(True)

    def hostile_compile(self, body: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="kpb-mascot-two-round-negative-") as raw:
            source = Path(raw) / "negative.cpp"
            source.write_text(textwrap.dedent(body))
            return subprocess.run(
                ["c++", "-std=c++20", "-fsyntax-only", str(source),
                 "-I", str(HERE)], text=True, capture_output=True,
            )

    def test_production_compile_is_private(self) -> None:
        result = self.hostile_compile(
            """
            #include "privacy_p1_mascot_two_round_manifest_authority.hpp"
            int main() {
              using namespace kpb::measurement::p1_state;
              P1MascotFreshPrepDirectoryAuthority value;
              auto manifest = P1MascotTwoRoundManifestCompilerBridge::compile(
                std::move(value));
              (void)manifest;
            }
            """
        )
        self.assertNotEqual(result.returncode, 0)

    def test_no_caller_manifest_arguments(self) -> None:
        header = (
            HERE / "privacy_p1_mascot_fresh_prep_directory_authority.hpp"
        ).read_text()
        declaration = header.split(
            "class P1MascotTwoRoundManifestCompilerBridge final", 1
        )[1].split("};", 1)[0]
        for forbidden in (
            "MascotCacheBranch", "FamilyHookInventory", "Digest",
            "std::string", "std::span", "int fd", "path",
        ):
            self.assertNotIn(forbidden, declaration)


if __name__ == "__main__":
    unittest.main()
