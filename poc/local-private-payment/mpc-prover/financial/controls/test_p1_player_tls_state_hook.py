import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
MPC = HERE.parent.parent
REPO = MPC.parents[2]
VENDOR_ROOT = REPO / ".local" / "mpc-prover-softspoken-vendor"
MP = VENDOR_ROOT / "MP-SPDZ"
PREFIX = VENDOR_ROOT / "prefix" / "usr" / "include"
PREFIX_ROOT = VENDOR_ROOT / "prefix" / "usr"
MCL = VENDOR_ROOT / "mcl"
PATCH = MPC / "vendor-patches" / "mp-spdz-p1-player-tls-state-v1.patch"
sys.path.insert(0, str(MPC / "financial"))
import p1_tls_overlay_build


class P1PlayerTlsStateHookControls(unittest.TestCase):
    @staticmethod
    def _apply_overlay(root: Path) -> Path:
        networking = root / "Networking"
        networking.mkdir(parents=True)
        for name in ("CryptoPlayer.cpp", "CryptoPlayer.h", "ssl_sockets.h"):
            shutil.copy2(MP / "Networking" / name, networking / name)
        applied = subprocess.run(
            ["patch", "--batch", "-p1", "-d", str(root),
             "-i", str(PATCH)],
            capture_output=True, text=True, check=False, timeout=30)
        if applied.returncode:
            raise AssertionError(applied.stdout + applied.stderr)
        return networking

    def test_patch_applies_to_pinned_source_and_strict_syntax_compiles(self):
        self.assertTrue(MP.is_dir(), "pinned MP-SPDZ source is required")
        with tempfile.TemporaryDirectory(prefix="kpb-p1-tls-overlay-") as raw:
            overlay = Path(raw)
            networking = self._apply_overlay(overlay)
            self.assertNotIn(
                "exit(1);",
                (networking / "CryptoPlayer.cpp").read_text(
                    encoding="utf-8"))

            includes = [
                f"-I{overlay}", f"-I{networking}", f"-I{MP}",
                f"-I{MP / 'Networking'}", f"-I{MPC}",
                f"-I{PREFIX}", f"-I{PREFIX / 'x86_64-linux-gnu'}",
            ]
            compiled = subprocess.run(
                ["g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
                 "-fsyntax-only", str(networking / "CryptoPlayer.cpp"),
                 str(MPC / "financial" / "registered_roster_crypto_player.cpp"),
                 *includes, "-DNO_MIXED_CIRCUITS", "-pthread"],
                capture_output=True, text=True, check=False, timeout=90)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

    def test_source_identity_overlay_refuses_patch_and_preimage_drift(self):
        with tempfile.TemporaryDirectory(prefix="kpb-p1-tls-identity-") as raw:
            root = Path(raw)
            overlay = root / "overlay"
            record = p1_tls_overlay_build.materialize(
                vendor_mp=MP, patch_path=PATCH, output=overlay)
            self.assertEqual(
                record["schema"], p1_tls_overlay_build.SCHEMA)
            self.assertFalse(record["complete_tls_process_view"])
            self.assertFalse(record["configured"])
            self.assertEqual(
                sorted(record["postimage_sha256"]),
                sorted(str(path.relative_to(overlay))
                       for path in overlay.rglob("*") if path.is_file()))

            bad_patch = root / "bad.patch"
            bad_patch.write_bytes(PATCH.read_bytes() + b"\n")
            with self.assertRaisesRegex(
                    p1_tls_overlay_build.TlsOverlayRefused,
                    "patch-drift"):
                p1_tls_overlay_build.materialize(
                    vendor_mp=MP, patch_path=bad_patch,
                    output=root / "bad-patch-overlay")

            bad_vendor = root / "bad-vendor"
            (bad_vendor / "Networking").mkdir(parents=True)
            for relative in p1_tls_overlay_build.PREIMAGE_SHA256:
                target = bad_vendor / relative
                shutil.copyfile(MP / relative, target)
            with (bad_vendor / "Networking/CryptoPlayer.h").open("ab") as f:
                f.write(b"\n")
            with self.assertRaisesRegex(
                    p1_tls_overlay_build.TlsOverlayRefused,
                    "preimage-drift"):
                p1_tls_overlay_build.materialize(
                    vendor_mp=bad_vendor, patch_path=PATCH,
                    output=root / "bad-vendor-overlay")

    def test_all_four_live_lanes_reject_missing_duplicate_and_substitution(self):
        with tempfile.TemporaryDirectory(prefix="kpb-p1-tls-lanes-") as raw:
            root = Path(raw)
            overlay = root / "overlay"
            networking = self._apply_overlay(overlay)
            player_data = root / "Player-Data"
            player_data.mkdir(mode=0o700)

            def run(command, cwd=root):
                result = subprocess.run(
                    command, cwd=cwd, capture_output=True, text=True,
                    check=False, timeout=90)
                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)

            run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-nodes", "-days", "1", "-subj", "/CN=KPB Test CA",
                "-keyout", "ca.key", "-out", "ca.pem",
            ], player_data)
            for role in range(3):
                name = f"P{role}"
                run([
                    "openssl", "req", "-newkey", "rsa:2048", "-nodes",
                    "-subj", f"/CN={name}", "-keyout", f"{name}.key",
                    "-out", f"{name}.csr",
                ], player_data)
                run([
                    "openssl", "x509", "-req", "-days", "1",
                    "-in", f"{name}.csr", "-CA", "ca.pem",
                    "-CAkey", "ca.key", "-CAcreateserial",
                    "-out", f"{name}.pem",
                ], player_data)
            run(["c_rehash", "."], player_data)

            binary = root / "tls-lane-controls"
            link_stub = root / "measurement-link-stub.cpp"
            link_stub.write_text(r'''
#include "privacy_measurement_authority.hpp"
#include "privacy_p1_corrupt_state_capsule_authority.hpp"
#include "financial/registered_p1_state_archive_scm.hpp"
#include <openssl/sha.h>
#include <vector>
namespace kpb::measurement {
const char* Refused::what() const noexcept {
    return "KPB_MEASUREMENT_AUTHORITY_REFUSED";
}
Digest recompute_finite_manifest_identity(
        const std::array<ManifestEntry, 10>& entries) {
    static constexpr char tag[] =
        "KPB_FINITE_MULTILANGUAGE_MANIFEST_V1\n";
    std::vector<unsigned char> bytes(tag, tag + sizeof(tag) - 1);
    const auto append = [&](const Digest& value) {
        bytes.insert(bytes.end(), value.begin(), value.end());
    };
    for (const auto& entry : entries) {
        bytes.push_back(static_cast<unsigned char>(entry.component));
        append(entry.source_identity);
        append(entry.build_identity);
        append(entry.runtime_identity);
        append(entry.assets_identity);
        append(entry.pinned_executable_identity);
        append(entry.launcher_identity);
    }
    Digest result{};
    if (SHA256(bytes.data(), bytes.size(), result.data()) == nullptr)
        throw Refused();
    return result;
}
}

namespace kpi::mpc::financial::registered_driver {
std::unique_ptr<kpb::measurement::p1_state_capsule::
    P1PlayerTlsStateAdapter>
RegisteredRole1P1StateRecorderFacade::take_player_tls_state_adapter(
        const kpb::measurement::p1_state_capsule::
            P1StateThreadEpochAuthority&) {
    throw kpb::measurement::Refused();
}
void RegisteredRole1P1StateRecorderFacade::advance_phase(
        kpb::measurement::p1_state_capsule::SourcePhase) {
    throw kpb::measurement::Refused();
}
}
''', encoding="utf-8")
            compiled = subprocess.run([
                "g++", "-std=c++20", "-march=native", "-Wall", "-Wextra",
                "-Werror", "-Wno-overloaded-virtual", "-pedantic",
                "-DNO_MIXED_CIRCUITS", "-DNO_AVX_OT", "-DUSE_GF2N_LONG",
                "-DMCL_USE_GMP=1", "-DMCL_DONT_USE_XBYAK",
                "-DMCL_FP_BIT=384", "-DMCL_FR_BIT=256", "-DMCL_MSM=0",
                "-DKPI_REGISTERED_ROSTER_TEST_SETUP",
                str(HERE / "registered_roster_crypto_player_test.cpp"),
                str(MPC / "financial" / "registered_roster_crypto_player.cpp"),
                str(networking / "CryptoPlayer.cpp"),
                str(MPC.parent / "private_batch_trial" /
                    "privacy_p1_corrupt_state_capsule_authority.cpp"),
                str(MPC / "p1_mascot_secret_state_hook.cpp"),
                str(link_stub),
                str(MPC / "history" / "epoch_journal.cpp"),
                "-I", str(overlay), "-I", str(networking),
                "-I", str(MPC), "-I", str(MP),
                "-I", str(MPC.parent / "private_batch_trial"),
                "-I", str(MP / "Networking"), "-I", str(MP / "deps"),
                "-I", str(MP / "local" / "include"),
                "-I", str(PREFIX),
                "-I", str(PREFIX / "x86_64-linux-gnu"),
                "-I", str(MCL / "include"),
                "-L", str(MP), "-Wl,-rpath," + str(MP),
                "-L", str(PREFIX_ROOT / "lib" / "x86_64-linux-gnu"),
                "-Wl,-rpath," + str(PREFIX_ROOT / "lib" / "x86_64-linux-gnu"),
                "-L", str(MCL / "lib"), "-lSPDZ", "-lmcl", "-lssl",
                "-lcrypto", "-lgmpxx", "-lgmp", "-pthread",
                "-o", str(binary),
            ], capture_output=True, text=True, check=False, timeout=120)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

            def free_port_base():
                for base in range(24000, 50000, 7):
                    reserved = []
                    try:
                        for port in range(base - 1, base + 3):
                            current = socket.socket()
                            current.setsockopt(
                                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                            current.bind(("127.0.0.1", port))
                            reserved.append(current)
                        return base
                    except OSError:
                        pass
                    finally:
                        for current in reserved:
                            current.close()
                self.fail("no four-port range available")

            for scenario in (
                    "missing-secondary-lane", "duplicate-secondary-lane",
                    "substituted-secondary-lane"):
                port = free_port_base()
                processes = [subprocess.Popen(
                    [str(binary), str(role), str(port), scenario], cwd=root,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True) for role in range(3)]
                outputs = []
                try:
                    for process in processes:
                        outputs.append(process.communicate(timeout=30))
                finally:
                    for process in processes:
                        if process.poll() is None:
                            process.kill()
                            process.wait()
                self.assertEqual(
                    [process.returncode for process in processes], [0, 0, 0],
                    "\n".join(out + err for out, err in outputs))

    def test_patch_uses_raw_source_callbacks_and_keeps_missing_state_explicit(self):
        patch = PATCH.read_text(encoding="utf-8")
        for required in (
                "SSL_CTX_get0_privatekey", "i2d_PrivateKey",
                "SSL_CTX_set_keylog_callback", "SSL_set_msg_callback",
                "SSL_set_info_callback", "SSL_get_client_random",
                "SSL_get_server_random", "SSL_SESSION_get_master_key",
                "SSL_get0_verified_chain", "TlsHandshakeFailed"):
            self.assertIn(required, patch)
        capture_source = patch.split(
            "+++ b/Networking/p1_tls_state_capture.h", 1)[1].split(
                "--- a/Networking/ssl_sockets.h", 1)[0]
        self.assertNotIn("DEBUG_NETWORKING", capture_source)

        hook = (MPC / "p1_player_tls_state_hook.hpp").read_text(
            encoding="utf-8")
        for required_false in (
                ".openssl_drbg_internal_state = false",
                ".openssl_record_layer_internal_state = false",
                ".deterministic_replay_verified = false",
                ".complete_tls_process_view = false",
                ".configured = false"):
            self.assertIn(required_false, hook)

    def test_standalone_hook_header_cannot_forge_recorder_or_factory(self):
        with tempfile.TemporaryDirectory(prefix="kpb-p1-tls-friend-") as raw:
            root = Path(raw)
            probes = {
                "recorder": r'''
#include "p1_player_tls_state_hook.hpp"
namespace kpb::measurement::p1_state_capsule {
class P1CorruptStateRecorderAuthority {
public:
  static P1PlayerTlsStateAdapter steal() {
    return P1PlayerTlsStateAdapter(nullptr);
  }
};
}
int main() {}
''',
                "factory": r'''
#include "p1_player_tls_state_hook.hpp"
namespace kpb::measurement::p1_state_capsule {
class P1PlayerTlsStateAdapterFactoryBridge final {};
}
int main() {}
''',
            }
            for name, body in probes.items():
                source = root / f"{name}.cpp"
                source.write_text(body, encoding="utf-8")
                result = subprocess.run([
                    "g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
                    "-pedantic", "-fsyntax-only", str(source),
                    "-I", str(MPC),
                ], capture_output=True, text=True, check=False, timeout=30)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertTrue(
                    "private" in result.stderr or
                    "redefinition" in result.stderr,
                    result.stderr)


if __name__ == "__main__":
    unittest.main()
