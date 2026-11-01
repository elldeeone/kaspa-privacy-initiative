#!/usr/bin/env python3
from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import textwrap
import unittest


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SOURCE = HERE / "privacy_p1_mascot_fresh_prep_directory_authority.cpp"
CONTROL = HERE / "privacy_p1_mascot_fresh_prep_directory_authority_control.cpp"


class FreshPrepDirectoryAuthorityControl(unittest.TestCase):
    def compile_and_run(self, sanitize: bool) -> None:
        with tempfile.TemporaryDirectory(prefix="kpb-mascot-prep-control-") as tmp:
            binary = pathlib.Path(tmp) / "control"
            command = [
                "c++", "-std=c++20", "-O1", "-g", "-Wall", "-Wextra",
                "-Werror", "-DKPB_P1_MASCOT_FRESH_PREP_DIRECTORY_TEST_SETUP=1",
                str(SOURCE), str(CONTROL), "-I", str(ROOT), "-lcrypto",
                "-o", str(binary),
            ]
            if sanitize:
                command[1:1] = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            subprocess.run(command, check=True, cwd=ROOT)
            environment = os.environ.copy()
            if sanitize:
                environment["ASAN_OPTIONS"] = "detect_leaks=1:abort_on_error=1"
                environment["UBSAN_OPTIONS"] = "halt_on_error=1"
            subprocess.run([str(binary)], check=True, cwd=ROOT, env=environment)

    def test_normal(self) -> None:
        self.compile_and_run(False)

    def test_asan_ubsan(self) -> None:
        self.compile_and_run(True)

    def test_direct_production_mint_is_private(self) -> None:
        source = textwrap.dedent(
            """
            #include "poc/local-private-payment/private_batch_trial/privacy_p1_mascot_fresh_prep_directory_authority.hpp"
            int main() {
              auto value = kpb::measurement::p1_state::
                P1MascotFreshPrepDirectorySourceBridge::mint_for_selected_activation();
              (void)value;
            }
            """
        )
        with tempfile.TemporaryDirectory(prefix="kpb-mascot-prep-negative-") as tmp:
            unit = pathlib.Path(tmp) / "negative.cpp"
            unit.write_text(source)
            result = subprocess.run(
                ["c++", "-std=c++20", "-fsyntax-only", str(unit), "-I", str(ROOT)],
                cwd=ROOT, text=True, capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("private", result.stderr)

    def test_no_production_test_surface(self) -> None:
        source = textwrap.dedent(
            """
            #include "poc/local-private-payment/private_batch_trial/privacy_p1_mascot_fresh_prep_directory_authority.hpp"
            int main() {
              auto value = kpb::measurement::p1_state::
                P1MascotFreshPrepDirectorySourceBridge::test_only_mint();
              (void)value;
            }
            """
        )
        with tempfile.TemporaryDirectory(prefix="kpb-mascot-prep-negative-") as tmp:
            unit = pathlib.Path(tmp) / "negative.cpp"
            unit.write_text(source)
            result = subprocess.run(
                ["c++", "-std=c++20", "-fsyntax-only", str(unit), "-I", str(ROOT)],
                cwd=ROOT, text=True, capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
