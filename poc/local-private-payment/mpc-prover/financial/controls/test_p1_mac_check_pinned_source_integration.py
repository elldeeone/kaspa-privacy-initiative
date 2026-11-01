#!/usr/bin/env python3
"""Offline controls for the exact pinned MP-SPDZ MAC-check source patch."""

from pathlib import Path
import hashlib
import json
import os
import resource
import shutil
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
MPC = HERE.parent.parent
REPO = MPC.parents[2]
VENDOR = REPO / ".local/mpc-prover-vendor"
MP = VENDOR / "MP-SPDZ"
MCL = VENDOR / "mcl"
PREFIX = VENDOR / "prefix/usr"
CXX = Path("/usr/bin/x86_64-linux-gnu-g++-15")
UPSTREAM = MP / "Protocols/MAC_Check.hpp"
PATCH = MPC / "vendor-patches/mp-spdz-p1-mac-check-state-v1.patch"
MANIFEST = MPC / "vendor-patches/mp-spdz-p1-mac-check-state-v1.manifest.json"
CAPTURE = MPC / "p1_mac_check_source_capture.cpp"
CONTROL = HERE / "p1_mac_check_pinned_source_compile_control.cpp"
BUILD = MPC / "financial/build_registered_financial.py"
HOOK = MPC / "p1_mac_check_state_hook.hpp"

PINNED_COMMIT = "113c4e47dd94bca9ecab029d2f0abe649bea5c52"
UPSTREAM_SHA256 = "6aa24821e6dae6370cd89832f407523dc046d4648dcc281f36dd054d7cb723b8"
PATCHED_SHA256 = "19ef2863526a22488e4eada07a30f325bde0fb1d3a1c33899f05aacd13fb006c"
PATCH_SHA256 = "c6ebd990d1ce060708e5c707b19b994d0f9b794e315adf20fea5c4359d718c5b"

FLAGS = [
    "-std=c++20", "-O1", "-g0", "-march=native", "-pthread",
    "-Wall", "-Wextra", "-Werror", "-Wpedantic",
    "-Wno-overloaded-virtual", "-DNO_MIXED_CIRCUITS", "-DNO_AVX_OT",
    "-DUSE_GF2N_LONG", "-DMCL_USE_GMP=1", "-DMCL_DONT_USE_XBYAK",
    "-DMCL_FP_BIT=384", "-DMCL_FR_BIT=256", "-DMCL_MSM=0",
    "-DKPI_P1_MAC_CHECK_STATE_CAPTURE",
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def disable_core() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class MacCheckPinnedSourceIntegration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            prefix="kpb-p1-mac-check-pinned-")
        self.root = Path(self.temp.name)
        (self.root / "Protocols").mkdir()
        shutil.copy2(UPSTREAM, self.root / "Protocols/MAC_Check.hpp")

    def tearDown(self):
        self.temp.cleanup()

    def apply_exact_patch(self) -> Path:
        selected = self.root / "Protocols/MAC_Check.hpp"
        self.assertEqual(sha256(selected), UPSTREAM_SHA256)
        result = subprocess.run(
            ["patch", "--batch", "--forward", "--fuzz=0", "-p1",
             "-d", str(self.root), "-i", str(PATCH)],
            capture_output=True, text=True, check=False, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sha256(selected), PATCHED_SHA256)
        return selected

    def compile_link_run(self, *, sanitizers: bool) -> None:
        self.apply_exact_patch()
        output = self.root / (
            "mac-check-source-sanitized" if sanitizers
            else "mac-check-source-normal")
        command = [str(CXX), *FLAGS]
        if sanitizers:
            command.extend([
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            ])
        for include in (
                self.root, MPC, MP, MP / "Protocols", MP / "deps",
                MP / "local/include", MCL / "include", PREFIX / "include",
                PREFIX / "include/x86_64-linux-gnu"):
            command.extend(["-I", str(include)])
        command.extend([
            str(CAPTURE), str(CONTROL), "-L" + str(MP), "-lSPDZ",
            "-Wl,-rpath," + str(MP),
            "-L" + str(PREFIX / "lib/x86_64-linux-gnu"),
            "-Wl,-rpath," + str(PREFIX / "lib/x86_64-linux-gnu"),
            "-lgmpxx", "-lgmp", "-lsodium", "-lssl", "-lcrypto",
            "-lboost_filesystem", "-lboost_iostreams", "-lboost_thread",
            "-lrt", "-lz", "-ldl", "-z", "noexecstack",
            "-o", str(output),
        ])
        built = subprocess.run(
            command, capture_output=True, text=True, check=False,
            timeout=180)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        environment = {"PATH": "/usr/bin:/bin"}
        if sanitizers:
            environment.update({
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
            })
        ran = subprocess.run(
            [str(output)], capture_output=True, text=True, check=False,
            timeout=30, env=environment, preexec_fn=disable_core)
        self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
        self.assertEqual((ran.stdout, ran.stderr), ("", ""))

    def test_exact_patch_applies_and_callsites_are_ordered(self):
        selected = self.apply_exact_patch()
        source = selected.read_text(encoding="utf-8")
        ordered = (
            "check_begin_noexcept(",
            "Create_Random_Seed(seed,P,SEED_SIZE);",
            "collective_seed_noexcept(",
            "h.almost_randomize(G);",
            "h.pack(kpb_coefficients);",
            "local_tau_noexcept(",
            "Commit_And_Open(tau, P, *this->coordinator);",
            "{ t += tau[i]; }",
            "reset();",
            "failure_reset_noexcept(",
            "success_reset_noexcept(",
        )
        cursor = 0
        for token in ordered:
            cursor = source.index(token, cursor) + len(token)
        self.assertEqual(source.count("source_serialization_failure_noexcept()"), 4)
        self.assertEqual(source.count("debug_branch_noexcept()"), 1)

    def test_tampered_upstream_is_not_an_exact_input(self):
        selected = self.root / "Protocols/MAC_Check.hpp"
        selected.write_bytes(
            selected.read_bytes().replace(
                b"Create_Random_Seed(seed,P,SEED_SIZE);",
                b"Create_Random_Seed(seed, P, SEED_SIZE);", 1))
        self.assertNotEqual(sha256(selected), UPSTREAM_SHA256)
        result = subprocess.run(
            ["patch", "--batch", "--forward", "--fuzz=0", "--dry-run",
             "-p1", "-d", str(self.root), "-i", str(PATCH)],
            capture_output=True, text=True, check=False, timeout=30)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_patched_template_compiles_and_links_normal(self):
        self.compile_link_run(sanitizers=False)

    def test_patched_template_compiles_and_links_sanitized(self):
        self.compile_link_run(sanitizers=True)

    def test_source_integration_is_not_selected_runtime(self):
        dependency = (MPC / "DEPENDENCIES.json").read_text(encoding="utf-8")
        self.assertIn(PINNED_COMMIT, dependency)
        self.assertEqual(sha256(UPSTREAM), UPSTREAM_SHA256)
        self.assertEqual(sha256(PATCH), PATCH_SHA256)
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema"],
                         "kpb-p1-mac-check-source-patch-manifest/v1")
        self.assertEqual(manifest["upstream"]["commit"], PINNED_COMMIT)
        self.assertEqual(manifest["upstream"]["sha256"], UPSTREAM_SHA256)
        self.assertEqual(manifest["patch"]["sha256"], PATCH_SHA256)
        self.assertEqual(manifest["patched_source_sha256"], PATCHED_SHA256)
        self.assertEqual(len(manifest["callsites"]), 10)
        self.assertEqual(manifest["claims"], {
            "exact_patch_input_and_output_bound": True,
            "patched_template_compiled_and_linked_offline": True,
            "selected_financial_build": False,
            "capsule_family_adapter": False,
            "selected_role1_installation": False,
            "complete_mac_check_family": False,
            "complete_corrupt_p1_view": False,
            "configured": False,
            "runtime_exercised": False,
            "privacy_proven": False,
        })
        build = BUILD.read_text(encoding="utf-8")
        self.assertNotIn("KPI_P1_MAC_CHECK_STATE_CAPTURE", build)
        status = HOOK.read_text(encoding="utf-8")
        for required in (
                ".source_patch_selected = false",
                ".capsule_family_adapter = false",
                ".selected_role1_installation = false",
                ".complete_mac_check_family = false",
                ".complete_corrupt_p1_view = false",
                ".configured = false"):
            self.assertIn(required, status)


if __name__ == "__main__":
    unittest.main()
