#!/usr/bin/env python3
"""Hostile controls for source-owned MP-SPDZ commitment randomness."""

from pathlib import Path
import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
MPC = HERE.parent.parent
REPO = MPC.parents[2]
PRISTINE = REPO / ".local" / "mpc-prover-vendor" / "MP-SPDZ"
VENDOR = REPO / ".local" / "mpc-prover-softspoken-vendor"
MP = VENDOR / "MP-SPDZ"
PREFIX = VENDOR / "prefix" / "usr"
MCL = VENDOR / "mcl"
PATCH = MPC / "vendor-patches" / "mp-spdz-p1-commitment-entropy-v1.patch"
HEADER = MPC / "p1_commitment_entropy_state_hook.hpp"
SOURCE = MPC / "p1_commitment_entropy_source_capture.hpp"
CONTROL = HERE / "p1_commitment_entropy_source_capture_control.cpp"
UPSTREAM_SHA256 = (
    "3f99027fc0c31b847617d63043f3dfab1f8dc70e4337c8f1491032e7d8bcce8d"
)


class CommitmentEntropyControls(unittest.TestCase):
    @staticmethod
    def _patched_commit(root: Path) -> Path:
        tools = root / "Tools"
        tools.mkdir(parents=True)
        target = tools / "Commit.cpp"
        shutil.copy2(PRISTINE / "Tools/Commit.cpp", target)
        applied = subprocess.run(
            ["patch", "--batch", "--fuzz=0", "-p1", "-d", str(root),
             "-i", str(PATCH)],
            capture_output=True, text=True, check=False, timeout=30)
        if applied.returncode:
            raise AssertionError(applied.stdout + applied.stderr)
        return target

    @staticmethod
    def _compile(root: Path, sanitizers: bool) -> tuple[Path, Path]:
        patched = CommitmentEntropyControls._patched_commit(root / "overlay")
        binary = root / "control"
        shared = root / "libKpiP1CommitmentEntropyProbe.so"
        common = [
            "g++", "-std=c++20", "-O1", "-g0", "-Wall", "-Wextra",
            "-Werror", "-Wpedantic", "-Wno-overloaded-virtual",
            "-DKPI_P1_COMMITMENT_ENTROPY_STATE_HOOK_TEST_SETUP",
        ]
        if sanitizers:
            common.extend([
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            ])
        includes = []
        for include in (
                MPC, MP, MP / "Tools", MP / "deps", MP / "local/include",
                MCL / "include", PREFIX / "include",
                PREFIX / "include/x86_64-linux-gnu"):
            includes.extend(["-I", str(include)])
        dependency_links = [
            "-L", str(MP), "-Wl,-rpath," + str(MP), "-lSPDZ",
            "-L", str(PREFIX / "lib/x86_64-linux-gnu"),
            "-Wl,-rpath," + str(PREFIX / "lib/x86_64-linux-gnu"),
            "-L", str(MCL / "lib"), "-lmcl", "-lgmpxx", "-lgmp",
            "-lsodium", "-lssl", "-lcrypto", "-ldl", "-pthread",
        ]
        commands = (
            common + ["-fPIC", "-shared", str(patched)] + includes +
            dependency_links + [
                "-Wl,-z,defs",
                "-Wl,-soname,libKpiP1CommitmentEntropyProbe.so",
                "-o", str(shared),
            ],
            common + [str(CONTROL)] + includes + [
                "-L", str(root), "-Wl,-rpath," + str(root),
                "-lKpiP1CommitmentEntropyProbe",
            ] + dependency_links + ["-o", str(binary)],
        )
        for command in commands:
            compiled = subprocess.run(
                command, capture_output=True, text=True, check=False,
                timeout=120)
            if compiled.returncode:
                raise AssertionError(compiled.stdout + compiled.stderr)
        return binary, shared

    def _compile_and_run(self, sanitizers: bool):
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-commitment-entropy-") as raw:
            root = Path(raw)
            binary, shared = self._compile(root, sanitizers)
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
            symbols = subprocess.run(
                ["nm", "-D", "-C", str(shared)], capture_output=True,
                text=True,
                check=True, timeout=30).stdout
            self.assertIn(
                "CommitmentEntropySourceBridge::record_legacy_commit_noexcept",
                symbols)
            self.assertIn(
                "CommitmentEntropySourceBridge::record_object_commit_noexcept",
                symbols)
            self.assertIn(" T Commit(octetStream&", symbols)
            dynamic = subprocess.run(
                ["readelf", "-d", str(binary)], capture_output=True,
                text=True, check=True, timeout=30).stdout
            self.assertIn(
                "Shared library: [libKpiP1CommitmentEntropyProbe.so]",
                dynamic)

    def test_exact_sources_and_hostile_lifecycle_normal(self):
        self._compile_and_run(False)

    def test_exact_sources_and_hostile_lifecycle_sanitized(self):
        self._compile_and_run(True)

    def test_patch_is_exact_for_pinned_upstream_and_semantic_sites(self):
        raw = (PRISTINE / "Tools/Commit.cpp").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), UPSTREAM_SHA256)
        dry = subprocess.run(
            ["patch", "--dry-run", "--fuzz=0", "-p1", "-d",
             str(PRISTINE), "-i", str(PATCH)],
            capture_output=True, text=True, check=False, timeout=30)
        self.assertEqual(dry.returncode, 0, dry.stdout + dry.stderr)

        patch = PATCH.read_text(encoding="utf-8")
        self.assertEqual(patch.count("entropy_offset"), 4)
        self.assertEqual(patch.count("record_legacy_commit_noexcept"), 1)
        self.assertEqual(patch.count("record_object_commit_noexcept"), 1)
        self.assertIn(
            "KPI_P1_COMMITMENT_ENTROPY_SOURCE_IMPLEMENTATION", patch)
        self.assertNotIn("__builtin_return_address", patch)
        self.assertNotIn("pthread_self", patch)
        self.assertNotIn("randombytes_buf(", patch)

    def test_patch_and_source_drift_refuse(self):
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-commitment-drift-") as raw:
            root = Path(raw)
            (root / "Tools").mkdir(parents=True)
            target = root / "Tools/Commit.cpp"
            shutil.copy2(PRISTINE / "Tools/Commit.cpp", target)
            original = target.read_text(encoding="utf-8")
            drifted = original.replace(
                "open.append_random(SEED_SIZE);",
                "open.append_random_DRIFT(SEED_SIZE);", 1)
            self.assertNotEqual(original, drifted)
            target.write_text(drifted, encoding="utf-8")
            result = subprocess.run(
                ["patch", "--dry-run", "--fuzz=0", "-p1", "-d",
                 str(root), "-i", str(PATCH)],
                capture_output=True, text=True, check=False, timeout=30)
            self.assertNotEqual(
                hashlib.sha256(target.read_bytes()).hexdigest(),
                UPSTREAM_SHA256)
            self.assertNotEqual(
                result.returncode, 0, result.stdout + result.stderr)

            changed = root / "changed.patch"
            changed.write_bytes(PATCH.read_bytes() + b"\n")
            self.assertNotEqual(
                hashlib.sha256(changed.read_bytes()).hexdigest(),
                hashlib.sha256(PATCH.read_bytes()).hexdigest())

    def test_hook_factory_and_scope_cannot_be_forged(self):
        probes = {
            "hook": r'''
#include "p1_commitment_entropy_state_hook.hpp"
struct Forged final : kpi::mpc::p1_private_state::CommitmentEntropyStateHook {
  bool record_commitment_entropy(
      const kpi::mpc::p1_private_state::CommitmentEntropyView&) noexcept override
      { return true; }
  bool commitment_entropy_terminal_noexcept() noexcept override { return true; }
  void commitment_entropy_unavailable_noexcept() noexcept override {}
};
int main() { Forged value; (void)value; }
''',
            "factory": r'''
#include "p1_commitment_entropy_source_capture.hpp"
namespace kpi::mpc::p1_private_state {
class CommitmentEntropyScopeFactoryBridge final {};
}
int main() {}
''',
            "direct_install": r'''
#include "p1_commitment_entropy_source_capture.hpp"
using namespace kpi::mpc::p1_private_state;
CommitmentEntropySourceScope steal(CommitmentEntropyStateHook& hook) {
  return CommitmentEntropyScopeFactoryBridge::install(hook, 1, 1);
}
int main() {}
''',
            "generic_record": r'''
#include "p1_commitment_entropy_source_capture.hpp"
#include <array>
using namespace kpi::mpc::p1_private_state;
int main() {
  std::array<unsigned char, COMMITMENT_ENTROPY_BYTES> value{};
  (void)CommitmentEntropySourceBridge::record_legacy_commit_noexcept(1, value);
}
''',
        }
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-commitment-forge-") as raw:
            root = Path(raw)
            for name, body in probes.items():
                source = root / f"{name}.cpp"
                source.write_text(body, encoding="utf-8")
                result = subprocess.run(
                    ["g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
                     "-Wpedantic", "-fsyntax-only", str(source), "-I",
                     str(MPC)],
                    capture_output=True, text=True, check=False, timeout=30)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertTrue(
                    "private" in result.stderr or
                    "redefinition" in result.stderr,
                    result.stderr)

    def test_status_and_selected_boundary_remain_honest(self):
        state = HEADER.read_text(encoding="utf-8")
        source = SOURCE.read_text(encoding="utf-8")
        for required in (
                ".source_patch_selected = false",
                ".capsule_family_adapter = false",
                ".selected_role1_installation = false",
                ".complete_mp_spdz_prng_family = false",
                ".complete_corrupt_p1_view = false",
                ".configured = false"):
            self.assertIn(required, state)
        self.assertNotIn("callsite_rva", state)
        self.assertNotIn("next_thread_epoch", source)
        self.assertIn("logical_thread_epoch", source)
        build = (MPC / "financial/build_registered_financial.py").read_text(
            encoding="utf-8")
        self.assertNotIn("mp-spdz-p1-commitment-entropy-v1.patch", build)


if __name__ == "__main__":
    unittest.main()
