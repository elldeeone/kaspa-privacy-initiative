#!/usr/bin/env python3
"""Hostile controls for the private corrupt-P1 MASCOT secret-state hook."""

from pathlib import Path
import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
MPC = HERE.parent.parent
FIXTURE = HERE / "p1_mascot_secret_state_hook_test.cpp"
IMPLEMENTATION = MPC / "p1_mascot_secret_state_hook.cpp"
HEADER = MPC / "p1_mascot_secret_state_hook.hpp"
SOURCE_HEADER = MPC / "p1_mascot_secret_source_capture.hpp"
SOURCE_FIXTURE = HERE / "p1_mascot_secret_source_capture_test.cpp"
VENDOR = MPC.parents[2] / ".local" / "mpc-prover-softspoken-vendor"
PRISTINE_VENDOR = MPC.parents[2] / ".local" / "mpc-prover-vendor"
PATCH = MPC / "vendor-patches" / "mp-spdz-p1-mascot-secret-state-v2.patch"


class P1MascotSecretStateHookControls(unittest.TestCase):
    def compile_and_run(self, sanitizers: bool):
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-mascot-state-") as raw:
            binary = Path(raw) / "control"
            command = [
                "g++", "-std=c++20", "-O1", "-g0", "-Wall", "-Wextra",
                "-Werror", "-Wpedantic",
                "-DKPI_P1_MASCOT_SECRET_STATE_HOOK_TEST_SETUP",
            ]
            if sanitizers:
                command.extend([
                    "-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer",
                ])
            command.extend([
                str(FIXTURE), str(IMPLEMENTATION), "-pthread",
                "-o", str(binary),
            ])
            compiled = subprocess.run(
                command, capture_output=True, text=True, check=False,
                timeout=60)
            self.assertEqual(
                compiled.returncode, 0, compiled.stdout + compiled.stderr)
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

    def test_branch_grammars_and_hostile_inputs_normal(self):
        self.compile_and_run(False)

    def test_branch_grammars_and_hostile_inputs_sanitized(self):
        self.compile_and_run(True)

    def test_exact_file_capture_under_sanitizers(self):
        mp = VENDOR / "MP-SPDZ"
        prefix = VENDOR / "prefix" / "usr"
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-mascot-file-") as raw:
            root = Path(raw)
            binary = root / "capture"
            command = [
                "g++", "-std=c++20", "-O1", "-g0", "-Wall", "-Wextra",
                "-Werror", "-Wpedantic", "-mavx2", "-maes", "-mpclmul",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                "-DKPI_P1_MASCOT_SECRET_SOURCE_CAPTURE_TEST_SETUP",
                "-DKPI_P1_MASCOT_SECRET_STATE_HOOK_TEST_SETUP",
                str(SOURCE_FIXTURE), str(IMPLEMENTATION), "-pthread",
                "-L", str(mp), "-Wl,-rpath," + str(mp), "-lSPDZ",
                "-L", str(prefix / "lib" / "x86_64-linux-gnu"),
                "-lcrypto", "-lgmp",
                "-o", str(binary),
            ]
            for include in (
                    MPC, mp, mp / "deps", mp / "local" / "include",
                    prefix / "include",
                    prefix / "include" / "x86_64-linux-gnu"):
                command.extend(["-I", str(include)])
            compiled = subprocess.run(
                command, capture_output=True, text=True, check=False,
                timeout=60)
            self.assertEqual(
                compiled.returncode, 0, compiled.stdout + compiled.stderr)
            work = root / "work"
            work.mkdir(mode=0o700)
            environment = dict(os.environ)
            environment["ASAN_OPTIONS"] = (
                "detect_leaks=1:halt_on_error=1:abort_on_error=1")
            environment["UBSAN_OPTIONS"] = (
                "halt_on_error=1:print_stacktrace=1")
            result = subprocess.run(
                [str(binary), str(work)], capture_output=True, text=True,
                check=False, timeout=30, env=environment)
            self.assertEqual(
                result.returncode, 0, result.stdout + result.stderr)

    def test_patch_is_exact_for_pinned_upstream_sources(self):
        result = subprocess.run([
            "patch", "--dry-run", "--fuzz=0", "-p1", "-d",
            str(PRISTINE_VENDOR / "MP-SPDZ"), "-i", str(PATCH),
        ], capture_output=True, text=True, check=False, timeout=30)
        self.assertEqual(
            result.returncode, 0, result.stdout + result.stderr)
        expected = {
            "OT/NPartyTripleGenerator.h":
                "294a0d5f132efe7d3b5bcc1856c511ba64dbce9921cae46e4534add184fff1c3",
            "OT/NPartyTripleGenerator.hpp":
                "a2bd22f3a6df91f04d2ff4c8cd54628731665068000916a46a8013775e4101a6",
            "OT/MascotMacKey.hpp":
                "155a8848fb253ce2bead8e9f03df703337ce6a94e97db18a9593c1383e5d2a0c",
            "Protocols/MascotPrep.h":
                "579541d2ec20cdfdf44cd75e0098eb4635c8c61bf4439d20494d6e395f800d8e",
            "OT/OTMultiplier.h":
                "b9784a784781b305f75626494ad2907fca49bdfbfcc1f8d27c035851a629891b",
            "OT/OTMultiplier.hpp":
                "12429b0c5a81c17e02c80b36b5636d763efa679086e5244dabe1838792b25eb4",
            "Protocols/MAC_Check.hpp":
                "6aa24821e6dae6370cd89832f407523dc046d4648dcc281f36dd054d7cb723b8",
        }
        for name, digest in expected.items():
            raw = (PRISTINE_VENDOR / "MP-SPDZ" / name).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
        patch = PATCH.read_text(encoding="utf-8")
        for required in (
                "capture_required_noexcept", "capture_cache_file",
                "record_local_validation", "record_peer_validation",
                "record_regeneration", "begin_write_candidate",
                "write_file_and_record", "record_scalar_state_begin",
                "begin_prep_static_install",
                "write_prep_mac_file_and_record",
                "begin_bit_prep_derivation", "capture_derived",
                "record_static_installed", "begin_teardown",
                "unlink_cache_for_abort", "register_ot_worker_noexcept",
                "ot_worker_failure_published_noexcept",
                "root_worker_failure_observed_noexcept",
                "ot_worker_joined_noexcept", "std::is_same",
                "std::current_exception", "std::rethrow_exception"):
            self.assertIn(required, patch)
        self.assertLess(
            patch.index("if (not reason.empty())"),
            patch.index("record_regeneration(key)"))
        self.assertLess(
            patch.index("begin_bit_prep_derivation"),
            patch.index("auto derived_bit_prep_key = mac_key.get_fresh()"))
        self.assertLess(
            patch.index("capture_derived(derived_bit_prep_key)"),
            patch.index("std::move(derived_bit_prep_key)"))
        dependencies = {
            "Protocols/fake-stuff.hpp":
                "4b3f41798f961a417d255f69ac973c309b40c2e0ff64f4767d42d15b832bf5e0",
            "Protocols/Share.hpp":
                "7ce9e81184a3b31545fd137730fd3f0c35b5881fb41b981600a644aa68fd8d09",
            "Protocols/Share.h":
                "e657f7d39b6d9bf8f5b4e07123157c0d34b02619f162104801da00b9ea136520",
            "Math/gfp.h":
                "3b9af0a4a83abeda72d8e48a5c90f88b2497368d964b829d50f6ef8e0092e912",
            "OT/MascotMacKey.h":
                "4485bc99b8ec3727c1dfb95baf7d2fcfe7b85e3112631cc885162eb3c4054a55",
            "OT/OTTripleSetup.cpp":
                "05d1988b32947701965a4e6fa891c285637c40678d2267828f7bf0ca355a61aa",
        }
        for name, digest in dependencies.items():
            raw = (PRISTINE_VENDOR / "MP-SPDZ" / name).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
            self.assertIn(digest, IMPLEMENTATION.read_text(encoding="utf-8"))

    def test_source_drift_refuses_patch_and_pinned_identity(self):
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-mascot-drift-") as raw:
            root = Path(raw)
            (root / "OT").mkdir()
            (root / "Protocols").mkdir()
            for name in (
                    "OT/NPartyTripleGenerator.h",
                    "OT/NPartyTripleGenerator.hpp",
                    "OT/MascotMacKey.hpp",
                    "Protocols/MascotPrep.h", "OT/OTMultiplier.h",
                    "OT/OTMultiplier.hpp", "Protocols/MAC_Check.hpp"):
                shutil.copy2(PRISTINE_VENDOR / "MP-SPDZ" / name,
                             root / name)
            target = root / "OT" / "NPartyTripleGenerator.hpp"
            original = target.read_text(encoding="utf-8")
            drifted = original.replace(
                "typename OTTripleGenerator<T>::mac_key_type "
                "OTTripleGenerator<T>::get_mac_key(",
                "typename OTTripleGenerator<T>::mac_key_type "
                "OTTripleGenerator<T>::get_mac_key_DRIFT(", 1)
            self.assertNotEqual(original, drifted)
            target.write_text(drifted, encoding="utf-8")
            self.assertNotEqual(
                hashlib.sha256(target.read_bytes()).hexdigest(),
                "a2bd22f3a6df91f04d2ff4c8cd54628731665068000916a46a8013775e4101a6")
            result = subprocess.run([
                "patch", "--dry-run", "--fuzz=0", "-p1", "-d", str(root),
                "-i", str(PATCH),
            ], capture_output=True, text=True, check=False, timeout=30)
            self.assertNotEqual(result.returncode, 0,
                                result.stdout + result.stderr)

    def test_applied_patch_matches_and_selected_tus_compile(self):
        names = (
            "OT/NPartyTripleGenerator.h",
            "OT/NPartyTripleGenerator.hpp",
            "OT/MascotMacKey.hpp",
            "Protocols/MascotPrep.h",
            "OT/OTMultiplier.h",
            "OT/OTMultiplier.hpp",
            "Protocols/MAC_Check.hpp",
        )
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-mascot-applied-") as raw:
            root = Path(raw)
            for name in names:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(PRISTINE_VENDOR / "MP-SPDZ" / name, target)
            applied = subprocess.run([
                "patch", "--fuzz=0", "-p1", "-d", str(root),
                "-i", str(PATCH),
            ], capture_output=True, text=True, check=False, timeout=30)
            self.assertEqual(
                applied.returncode, 0, applied.stdout + applied.stderr)
            for name in names:
                self.assertEqual(
                    (root / name).read_bytes(),
                    (VENDOR / "MP-SPDZ" / name).read_bytes(), name)

        mp = VENDOR / "MP-SPDZ"
        mcl = VENDOR / "mcl"
        prefix = VENDOR / "prefix" / "usr"
        command = [
            "g++", "-std=c++20", "-O1", "-g0", "-march=native",
            "-pthread", "-Wall", "-Wextra", "-Werror",
            "-Wno-overloaded-virtual", "-DNO_MIXED_CIRCUITS",
            "-DNO_AVX_OT", "-DUSE_GF2N_LONG", "-DMCL_USE_GMP=1",
            "-DMCL_DONT_USE_XBYAK", "-DMCL_FP_BIT=384",
            "-DMCL_FR_BIT=256", "-DMCL_MSM=0", "-fsyntax-only",
            str(MPC / "auth_field.cpp"), str(IMPLEMENTATION),
        ]
        for include in (
                MPC, mp, mp / "deps", mp / "local/include",
                mcl / "include", prefix / "include",
                prefix / "include" / "x86_64-linux-gnu"):
            command.extend(["-I", str(include)])
        compiled = subprocess.run(
            command, capture_output=True, text=True, check=False,
            timeout=180)
        self.assertEqual(
            compiled.returncode, 0, compiled.stdout + compiled.stderr)

        probe = subprocess.run(
            command + ["-x", "c++", "-"],
            input='''
#include "auth_field.hpp"
#include <type_traits>
using SelectedPrep = kpi::mpc::AuthScalar::prep_type;
static_assert(std::is_same_v<SelectedPrep, SelectedPrep::bit_prep_type>);
''', capture_output=True, text=True, check=False, timeout=180)
        self.assertEqual(
            probe.returncode, 0, probe.stdout + probe.stderr)

        header = (mp / "OT/NPartyTripleGenerator.h").read_text(
            encoding="utf-8")
        implementation = (mp / "OT/NPartyTripleGenerator.hpp").read_text(
            encoding="utf-8")
        self.assertIn(
            "static complete_mac_key_type& get_mac_key() { return mac_key; }",
            header)
        self.assertIn(
            "const bool complete_mac_key_initialized = not (mac_key == 0);",
            implementation)
        worker = implementation[
            implementation.index("void* run_ot_thread"):
            implementation.index("typename OTTripleGenerator<T>::mac_key_type")]
        self.assertIn("if (not p1_mascot_capture)", worker)
        self.assertIn("exit(1)", worker)
        self.assertIn("std::current_exception()", worker)
        self.assertIn("multiplier->outbox.push({});", worker)
        self.assertIn("ot_worker_terminal_noexcept", worker)
        self.assertLess(
            worker.index("exit(1)"),
            worker.index("multiplier->failure = std::current_exception()"))

    def test_adapter_and_hook_cannot_be_forged_from_standalone_header(self):
        probes = {
            "hook": r'''
#include "p1_mascot_secret_state_hook.hpp"
struct Forged final : kpi::mpc::p1_private_state::MascotSecretStateHook {
  bool record_mascot_secret_event(
      const kpi::mpc::p1_private_state::MascotSecretEventView&) noexcept override
      { return true; }
  void mascot_secret_unavailable_noexcept() noexcept override {}
};
int main() { Forged forged; (void)forged; }
''',
            "factory": r'''
#include "p1_mascot_secret_state_hook.hpp"
namespace kpb::measurement::p1_state_capsule {
class P1MascotSecretStateAdapterFactoryBridge final {};
}
int main() {}
''',
            "scope_factory": r'''
#include "p1_mascot_secret_state_hook.hpp"
namespace kpi::mpc::p1_private_state {
class MascotSecretStateScopeFactoryBridge final {};
}
int main() {}
''',
            "context_spoof": r'''
#include "p1_mascot_secret_state_hook.hpp"
namespace kpi::mpc {
class MascotContext final {
public:
  static p1_private_state::MascotSecretStateHookScope* steal(
      p1_private_state::MascotSecretStateHook& hook) {
    return new p1_private_state::MascotSecretStateHookScope(
        hook, 1, 3, true, "P1", "17");
  }
};
}
int main() {}
''',
            "direct_scope_install": r'''
#include "p1_mascot_secret_state_hook.hpp"
using namespace kpi::mpc::p1_private_state;
std::unique_ptr<MascotSecretStateHookScope> steal(
    MascotSecretStateHook& hook) {
  return MascotSecretStateScopeFactoryBridge::install(
      hook, 1, 3, true, MASCOT_SELECTED_PLAYER_ID,
      MASCOT_SELECTED_FIELD_MODULUS);
}
int main() {}
''',
            "recorder": r'''
#include "p1_mascot_secret_state_hook.hpp"
namespace kpb::measurement::p1_state_capsule {
class P1CorruptStateRecorderAuthority final {
public:
  static P1MascotSecretStateAdapter* forge() {
    return new P1MascotSecretStateAdapter(
        std::unique_ptr<P1MascotSecretStateAdapter::Storage>{});
  }
};
}
int main() {}
''',
        }
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-mascot-forge-") as raw:
            root = Path(raw)
            for name, body in probes.items():
                source = root / f"{name}.cpp"
                source.write_text(body, encoding="utf-8")
                result = subprocess.run([
                    "g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
                    "-Wpedantic", "-fsyntax-only", str(source),
                    "-I", str(MPC),
                ], capture_output=True, text=True, check=False, timeout=30)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertTrue(
                    "private" in result.stderr or
                    "redefinition" in result.stderr,
                    result.stderr)

    def test_status_is_honest_and_secret_temporaries_are_scrubbed(self):
        header = HEADER.read_text(encoding="utf-8")
        implementation = IMPLEMENTATION.read_text(encoding="utf-8")
        source = SOURCE_HEADER.read_text(encoding="utf-8")
        for false_status in (
                ".pinned_mp_spdz_source_sites = false",
                ".exact_cache_file_and_complete_key_bytes = false",
                ".typed_branch_specific_lifecycle = false",
                ".selected_role1_installation = false",
                ".complete_corrupt_p1_view = false",
                ".configured = false"):
            self.assertIn(false_status, header)
        self.assertIn(".capsule_family_adapter = true", header)
        self.assertNotIn("get_raw", header)
        self.assertNotIn("record_raw", header)
        self.assertIn("volatile unsigned char*", implementation)
        self.assertGreaterEqual(
            implementation.count("cleanse(state->write_candidate)"), 1)
        self.assertIn("next = Next::Unavailable;\n        cleanse(write_candidate);",
                      implementation)
        self.assertIn("~Storage() {", implementation)
        for retained_secret in (
                "cleanse(write_candidate);",
                "cleanse(current_complete_key);",
                "cleanse(installed_scalar_key);"):
            self.assertGreaterEqual(
                implementation.count(retained_secret), 2,
                retained_secret)
        self.assertIn("::fsync(descriptor)", source)
        self.assertIn("::lstat(path.c_str()", source)
        self.assertIn("reopened_descriptor", source)
        self.assertIn("rename_result", source)
        self.assertIn("unlink_result", source)
        self.assertIn("TestFault::ShortRead", source)
        self.assertIn("TestFault::ReopenMismatch", source)
        self.assertIn("TestFault::FsyncFailure", source)
        self.assertIn("SYS_openat2", source)
        self.assertIn("RESOLVE_NO_SYMLINKS", source)
        self.assertIn("ensure_relative_directory_no_symlinks", source)
        self.assertIn("capture_prep_mac_write", source)
        self.assertIn("unlink_cache_for_abort", source)
        self.assertNotIn("if (key == 0) return {};", source)
        self.assertGreaterEqual(source.count("~SecretBytes() { cleanse"), 1)


if __name__ == "__main__":
    unittest.main()
