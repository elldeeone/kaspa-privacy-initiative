#!/usr/bin/env python3
"""Hostile controls for the private OnDemandOT map/source state slice."""

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
MCL = VENDOR / "mcl"
PREFIX = VENDOR / "prefix" / "usr"
PATCH = MPC / "vendor-patches" / "mp-spdz-p1-ondemand-ot-state-v1.patch"
HEADER = MPC / "p1_ondemand_ot_state_hook.hpp"
IMPLEMENTATION = MPC / "p1_ondemand_ot_state_hook.cpp"
SOURCE_HEADER = MPC / "p1_ondemand_ot_source_capture.hpp"
HOOK_CONTROL = HERE / "p1_ondemand_ot_state_hook_test.cpp"
SOURCE_CONTROL = HERE / "p1_ondemand_ot_source_capture_test.cpp"

PATCHED_FILES = (
    "OT/BaseOT.h",
    "OT/OTTripleSetup.cpp",
    "OT/OTTripleSetup.h",
    "Tools/random.h",
    "Tools/time-func.h",
)

PREIMAGES = {
    "OT/BaseOT.h":
        "7927264ca7a5c9dfb9e01524384ad4646a8fd61ab69161d3ab1e03c891e7db4c",
    "OT/OTTripleSetup.cpp":
        "05d1988b32947701965a4e6fa891c285637c40678d2267828f7bf0ca355a61aa",
    "OT/OTTripleSetup.h":
        "93e71b45a31f1f5f17abde80d069ea559789bbf7d28555a2f4a44252c25f7c1b",
    "Tools/random.h":
        "6c49878e56256484f543166bb88419119688140188f1a08467329e6321d16989",
    "Tools/time-func.h":
        "ee3a79dd33147c1a911e406cb23670339579ddb7993b498a6c0656a77fa633bb",
}

TRANSITIVE_PREIMAGES = {
    "OT/BaseOT.cpp":
        "a5c8dde6a916ba26a65057fd965cebcddac568e18b48351cea257de0f8604f14",
    "Tools/random.cpp":
        "2ae51e81e57dc4f1a005d597485b9fbc8e93fa8fa799615d555402cfe5a5ced9",
    "Tools/BitVector.h":
        "41c00045fd9566fe9940b7e49e55d5ba6cd9fb8dfd04cbbb001da4b68ff3eb30",
    "Tools/BitVector.cpp":
        "29a1e752f9b5591a2d329600969a943ceebe28baa49de7fb66b7b93f79ac6395",
    "Tools/time-func.cpp":
        "1b33d15d7808454f85832520250cee0b33e5b7f368c1769403994a888bb5e367",
    "Processor/BaseMachine.h":
        "05dfe4f0c2f7c9b91390f385281874ff1df757367322cbbdc7e107faa17e09e5",
    "Processor/BaseMachine.cpp":
        "b32593e6233d64a44545393ea019b01f49a7f7bdf028e9880231f6f0f9c9ea3c",
}

POSTIMAGES = {
    "OT/BaseOT.h":
        "680451fbe66ade706176ecb985c63d4894df3f92de5b2d5b48388c05b275e300",
    "OT/OTTripleSetup.cpp":
        "a67a1dc732cfc08ec3d33ce44f74b8de2029f58267621d05eb7e7c59c9601f57",
    "OT/OTTripleSetup.h":
        "7c327d038eecd1cf6e39d6caa24675a933dc419ef26c02a82099e4eb6aebcb36",
    "Tools/random.h":
        "c589e08172acb762c7d32fb245b5aad0b9f9926cc0b4ee1df2ce8d855d2cdbea",
    "Tools/time-func.h":
        "d948b6d8aa6bc6766be32f5246cd70a727c34fce775b3aa297509568ff75463a",
}

MODES = (
    "normal", "replay", "wrong-player", "partial", "rollback",
    "substitution", "cross-thread", "duplicate-worker", "peer-swap", "drop",
    "hook-reject",
    "terminal-reject", "abort",
)


class P1OnDemandOtStateControls(unittest.TestCase):
    @staticmethod
    def _prepare_overlay(root: Path) -> Path:
        for name in PATCHED_FILES:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(PRISTINE / name, target)
        applied = subprocess.run(
            ["patch", "--batch", "--fuzz=0", "-p1", "-d", str(root),
             "-i", str(PATCH)],
            capture_output=True, text=True, check=False, timeout=30)
        if applied.returncode:
            raise AssertionError(applied.stdout + applied.stderr)
        return root

    @staticmethod
    def _run(binary: Path, arguments: list[str], sanitizers: bool):
        environment = dict(os.environ)
        if sanitizers:
            environment["ASAN_OPTIONS"] = (
                "detect_leaks=1:halt_on_error=1:abort_on_error=1")
            environment["UBSAN_OPTIONS"] = (
                "halt_on_error=1:print_stacktrace=1")
        result = subprocess.run(
            [str(binary), *arguments], capture_output=True, text=True,
            check=False, timeout=60, env=environment)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        if result.stdout or result.stderr:
            raise AssertionError(result.stdout + result.stderr)

    def _compile_hook_and_run(self, sanitizers: bool):
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-ondemand-hook-") as raw:
            binary = Path(raw) / "control"
            command = [
                "g++", "-std=c++20", "-O1", "-g0", "-Wall", "-Wextra",
                "-Werror", "-Wpedantic",
                "-DKPI_P1_ONDEMAND_OT_STATE_HOOK_TEST_SETUP",
            ]
            if sanitizers:
                command.extend([
                    "-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer",
                ])
            command.extend([
                str(HOOK_CONTROL), str(IMPLEMENTATION), "-pthread",
                "-o", str(binary),
            ])
            compiled = subprocess.run(
                command, capture_output=True, text=True, check=False,
                timeout=60)
            self.assertEqual(
                compiled.returncode, 0, compiled.stdout + compiled.stderr)
            for mode in MODES:
                self._run(binary, [mode], sanitizers)

    def _compile_source_and_run(self, sanitizers: bool):
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-ondemand-source-") as raw:
            root = Path(raw)
            overlay = self._prepare_overlay(root / "overlay")
            binary = root / "source-control"
            command = [
                "g++", "-std=c++20", "-O1", "-g0", "-march=native",
                "-pthread", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
                "-Wno-overloaded-virtual", "-DNO_MIXED_CIRCUITS",
                "-DNO_AVX_OT", "-DUSE_GF2N_LONG", "-DMCL_USE_GMP=1",
                "-DMCL_DONT_USE_XBYAK", "-DMCL_FP_BIT=384",
                "-DMCL_FR_BIT=256", "-DMCL_MSM=0",
                "-DKPI_P1_ONDEMAND_OT_SOURCE_CAPTURE_TEST_SETUP",
                "-DKPI_P1_ONDEMAND_OT_STATE_HOOK_TEST_SETUP",
            ]
            if sanitizers:
                command.extend([
                    "-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer",
                ])
            command.extend([
                str(SOURCE_CONTROL), str(IMPLEMENTATION),
                str(MP / "OT/BaseOT.o"),
            ])
            for include in (
                    MPC, overlay, MP, MP / "deps", MP / "local/include",
                    MCL / "include", PREFIX / "include",
                    PREFIX / "include/x86_64-linux-gnu"):
                command.extend(["-I", str(include)])
            command.extend([
                "-L", str(MP), "-Wl,-rpath," + str(MP), "-lSPDZ",
                str(MP / "deps/SimplestOT_C/ref10/libSimplestOT.a"),
                "-L", str(PREFIX / "lib/x86_64-linux-gnu"),
                "-lcrypto", "-lgmp", "-lsodium", "-o", str(binary),
            ])
            compiled = subprocess.run(
                command, capture_output=True, text=True, check=False,
                timeout=120)
            self.assertEqual(
                compiled.returncode, 0, compiled.stdout + compiled.stderr)
            self._run(binary, [], sanitizers)

    def test_hook_grammar_and_hostile_controls_normal(self):
        self._compile_hook_and_run(False)

    def test_hook_grammar_and_hostile_controls_sanitized(self):
        self._compile_hook_and_run(True)

    def test_source_fieldwise_prng_and_base_state_normal(self):
        self._compile_source_and_run(False)

    def test_source_fieldwise_prng_and_base_state_sanitized(self):
        self._compile_source_and_run(True)

    def test_exact_patch_preimages_postimages_and_callsites(self):
        for name, digest in PREIMAGES.items():
            self.assertEqual(
                hashlib.sha256((PRISTINE / name).read_bytes()).hexdigest(),
                digest, name)
        for name, digest in TRANSITIVE_PREIMAGES.items():
            self.assertEqual(
                hashlib.sha256((PRISTINE / name).read_bytes()).hexdigest(),
                digest, name)
        dry = subprocess.run(
            ["patch", "--dry-run", "--fuzz=0", "-p1", "-d",
             str(PRISTINE), "-i", str(PATCH)],
            capture_output=True, text=True, check=False, timeout=30)
        self.assertEqual(dry.returncode, 0, dry.stdout + dry.stderr)
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-ondemand-postimage-") as raw:
            overlay = self._prepare_overlay(Path(raw))
            for name, digest in POSTIMAGES.items():
                self.assertEqual(
                    hashlib.sha256((overlay / name).read_bytes()).hexdigest(),
                    digest, name)

        patch = PATCH.read_text(encoding="utf-8")
        for required in (
                "prng_before_choices", "prng_after_choices",
                "worker_begin", "worker_end", "std::current_exception",
                "create_error", "started",
                "get_base_before", "seeded_initial_advance",
                "stored_advance", "returned_advance",
                "map_destructor_begin", "setups.clear()",
                "map_destructor_terminal"):
            self.assertIn(required, patch)
        self.assertLess(
            patch.index("seeded_initial_advance"),
            patch.index("stored_advance"))
        self.assertLess(
            patch.index("stored_advance"),
            patch.index("returned_advance"))

    def test_applied_patch_translation_unit_compiles(self):
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-ondemand-syntax-") as raw:
            overlay = self._prepare_overlay(Path(raw) / "overlay")
            command = [
                "g++", "-std=c++20", "-O1", "-g0", "-march=native",
                "-pthread", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
                "-Wno-overloaded-virtual", "-DNO_MIXED_CIRCUITS",
                "-DNO_AVX_OT", "-DUSE_GF2N_LONG", "-DMCL_USE_GMP=1",
                "-DMCL_DONT_USE_XBYAK", "-DMCL_FP_BIT=384",
                "-DMCL_FR_BIT=256", "-DMCL_MSM=0", "-fsyntax-only",
                str(overlay / "OT/OTTripleSetup.cpp"),
                str(IMPLEMENTATION),
            ]
            for include in (
                    MPC, overlay, MP, MP / "deps", MP / "local/include",
                    MCL / "include", PREFIX / "include",
                    PREFIX / "include/x86_64-linux-gnu"):
                command.extend(["-I", str(include)])
            compiled = subprocess.run(
                command, capture_output=True, text=True, check=False,
                timeout=120)
            self.assertEqual(
                compiled.returncode, 0, compiled.stdout + compiled.stderr)

    def test_patch_and_source_drift_refuse(self):
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-ondemand-drift-") as raw:
            root = Path(raw)
            for name in PATCHED_FILES:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(PRISTINE / name, target)
            target = root / "OT/OTTripleSetup.cpp"
            original = target.read_text(encoding="utf-8")
            drifted = original.replace("G.ReSeed();", "G.ReSeed_DRIFT();", 1)
            self.assertNotEqual(original, drifted)
            target.write_text(drifted, encoding="utf-8")
            result = subprocess.run(
                ["patch", "--dry-run", "--fuzz=0", "-p1", "-d",
                 str(root), "-i", str(PATCH)],
                capture_output=True, text=True, check=False, timeout=30)
            self.assertNotEqual(result.returncode, 0,
                                result.stdout + result.stderr)
            self.assertNotEqual(
                hashlib.sha256(target.read_bytes()).hexdigest(),
                PREIMAGES["OT/OTTripleSetup.cpp"])

    def test_private_factory_scope_and_hook_cannot_be_forged(self):
        probes = {
            "hook": r'''
#include "p1_ondemand_ot_state_hook.hpp"
using namespace kpi::mpc::p1_private_state;
struct Forged final : OnDemandOtStateHook {
  bool record_ondemand_ot_event(const OnDemandOtEventView&) noexcept override
    { return true; }
  bool bind_ondemand_ot_worker_epoch(
      std::uint64_t, std::uint64_t, std::uint64_t&) noexcept override
    { return true; }
  bool ondemand_ot_terminal_noexcept() noexcept override { return true; }
  void ondemand_ot_unavailable_noexcept() noexcept override {}
};
int main() { Forged value; (void)value; }
''',
            "factory": r'''
#include "p1_ondemand_ot_state_hook.hpp"
using namespace kpb::measurement::p1_state_capsule;
int main() {
  (void)&P1OnDemandOtMapStateAdapterFactoryBridge::install_source_scope;
}
''',
            "factory-redefinition": r'''
#include "p1_ondemand_ot_state_hook.hpp"
namespace kpb::measurement::p1_state_capsule {
class P1OnDemandOtMapStateAdapterFactoryBridge final {};
}
int main() {}
''',
            "scope": r'''
#include "p1_ondemand_ot_state_hook.hpp"
using namespace kpi::mpc::p1_private_state;
OnDemandOtStateScope* steal(OnDemandOtStateHook& hook) {
  return new OnDemandOtStateScope(hook, (void*)1, 1, 1, 1, 1, 3);
}
int main() {}
''',
        }
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-ondemand-forge-") as raw:
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
                    "redefinition" in result.stderr or
                    "deleted" in result.stderr,
                    result.stderr)

    def test_manifest_is_exact_and_no_status_scaffold_or_selection_claim(self):
        manifest = (
            "KPI_P1_ONDEMAND_OT_MAP_SOURCE_MANIFEST_V3\n"
            "commit=113c4e47dd94bca9ecab029d2f0abe649bea5c52\n"
            "OT/OTTripleSetup.h=93e71b45a31f1f5f17abde80d069ea559789bbf7d28555a2f4a44252c25f7c1b\n"
            "OT/OTTripleSetup.cpp=05d1988b32947701965a4e6fa891c285637c40678d2267828f7bf0ca355a61aa\n"
            "OT/BaseOT.h=7927264ca7a5c9dfb9e01524384ad4646a8fd61ab69161d3ab1e03c891e7db4c\n"
            "OT/BaseOT.cpp=a5c8dde6a916ba26a65057fd965cebcddac568e18b48351cea257de0f8604f14\n"
            "Tools/random.h=6c49878e56256484f543166bb88419119688140188f1a08467329e6321d16989\n"
            "Tools/random.cpp=2ae51e81e57dc4f1a005d597485b9fbc8e93fa8fa799615d555402cfe5a5ced9\n"
            "Tools/BitVector.h=41c00045fd9566fe9940b7e49e55d5ba6cd9fb8dfd04cbbb001da4b68ff3eb30\n"
            "Tools/BitVector.cpp=29a1e752f9b5591a2d329600969a943ceebe28baa49de7fb66b7b93f79ac6395\n"
            "Tools/time-func.h=ee3a79dd33147c1a911e406cb23670339579ddb7993b498a6c0656a77fa633bb\n"
            "Tools/time-func.cpp=1b33d15d7808454f85832520250cee0b33e5b7f368c1769403994a888bb5e367\n"
            "Processor/BaseMachine.h=05dfe4f0c2f7c9b91390f385281874ff1df757367322cbbdc7e107faa17e09e5\n"
            "Processor/BaseMachine.cpp=b32593e6233d64a44545393ea019b01f49a7f7bdf028e9880231f6f0f9c9ea3c\n"
            "overlay/p1_ondemand_ot_state_hook.cpp=001e5f101e0734d23d319a3844af359179540f0122d0859f6fbd21fef84b0189\n"
            "overlay/p1_ondemand_ot_source_capture.hpp=e21db07dc768ea4120a56cfa122af0df0b0143c8be047f8e90ddf795bf2b0e20\n"
            "overlay/mp-spdz-p1-ondemand-ot-state-v1.patch=62d21405210da6f16ad16407137e061b4ec9cd9818067a4c743e0da0b16aa2bd\n"
            "post/OT/BaseOT.h=680451fbe66ade706176ecb985c63d4894df3f92de5b2d5b48388c05b275e300\n"
            "post/OT/OTTripleSetup.cpp=a67a1dc732cfc08ec3d33ce44f74b8de2029f58267621d05eb7e7c59c9601f57\n"
            "post/OT/OTTripleSetup.h=7c327d038eecd1cf6e39d6caa24675a933dc419ef26c02a82099e4eb6aebcb36\n"
            "post/Tools/random.h=c589e08172acb762c7d32fb245b5aad0b9f9926cc0b4ee1df2ce8d855d2cdbea\n"
            "post/Tools/time-func.h=d948b6d8aa6bc6766be32f5246cd70a727c34fce775b3aa297509568ff75463a\n"
        )
        self.assertEqual(
            hashlib.sha256(manifest.encode()).hexdigest(),
            "ffc655846a92274beb88fea846ecdbf499a051e5e801b6dbd9866d29d2bfd5ab")
        for path, digest in {
                IMPLEMENTATION:
                    "001e5f101e0734d23d319a3844af359179540f0122d0859f6fbd21fef84b0189",
                SOURCE_HEADER:
                    "e21db07dc768ea4120a56cfa122af0df0b0143c8be047f8e90ddf795bf2b0e20",
                PATCH:
                    "62d21405210da6f16ad16407137e061b4ec9cd9818067a4c743e0da0b16aa2bd",
        }.items():
            self.assertEqual(
                hashlib.sha256(path.read_bytes()).hexdigest(), digest,
                str(path))
        combined = (
            HEADER.read_text(encoding="utf-8") +
            IMPLEMENTATION.read_text(encoding="utf-8") +
            SOURCE_HEADER.read_text(encoding="utf-8"))
        for forbidden in (
                "OnDemandOtStateSourceStatus", ".configured =",
                ".actual_run_receipt =", "selected_role1_installation = true",
                "complete_corrupt_p1_view = true", "raw_recorder", "raw_fd"):
            self.assertNotIn(forbidden, combined)
        build = (MPC / "financial/build_registered_financial.py").read_text(
            encoding="utf-8")
        self.assertNotIn(PATCH.name, build)


if __name__ == "__main__":
    unittest.main()
