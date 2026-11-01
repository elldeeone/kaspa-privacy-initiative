#!/usr/bin/env python3
"""Real TLS failure must close the authenticated P1 state channel."""

import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
MPC = FINANCIAL.parent
TRIAL = MPC.parent / "private_batch_trial"
REPO = MPC.parents[2]
VENDOR_ROOT = REPO / ".local" / "mpc-prover-softspoken-vendor"
MP = VENDOR_ROOT / "MP-SPDZ"
PREFIX = VENDOR_ROOT / "prefix" / "usr"
MCL = VENDOR_ROOT / "mcl"
PATCH = MPC / "vendor-patches" / "mp-spdz-p1-player-tls-state-v1.patch"
sys.path.insert(0, str(FINANCIAL))
import p1_tls_overlay_build


class RegisteredRoleChildP1UnavailableIntegration(unittest.TestCase):
    @staticmethod
    def run_checked(command, cwd):
        result = subprocess.run(
            command, cwd=cwd, capture_output=True, text=True,
            check=False, timeout=90)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    def certificates(self, root: Path, *, hostile: bool):
        player_data = root / "Player-Data"
        player_data.mkdir(mode=0o700)
        self.run_checked([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-nodes", "-days", "1", "-subj", "/CN=KPB Test CA",
            "-keyout", "ca.key", "-out", "ca.pem",
        ], player_data)
        for role in range(3):
            name = f"P{role}"
            common_name = name if role != 2 or not hostile else "WrongP2"
            self.run_checked([
                "openssl", "req", "-newkey", "rsa:2048", "-nodes",
                "-subj", f"/CN={common_name}",
                "-keyout", f"{name}.key", "-out", f"{name}.csr",
            ], player_data)
            self.run_checked([
                "openssl", "x509", "-req", "-days", "1",
                "-in", f"{name}.csr", "-CA", "ca.pem",
                "-CAkey", "ca.key", "-CAcreateserial",
                "-out", f"{name}.pem",
            ], player_data)
        self.run_checked(["c_rehash", "."], player_data)

    @staticmethod
    def free_port_base():
        for base in range(26000, 50000, 7):
            held = []
            try:
                for port in range(base - 1, base + 3):
                    current = socket.socket()
                    current.setsockopt(
                        socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    current.bind(("127.0.0.1", port))
                    held.append(current)
                return base
            except OSError:
                pass
            finally:
                for current in held:
                    current.close()
        raise AssertionError("no test port range available")

    def compile(self, root: Path, overlay: Path) -> Path:
        binary = root / "p1-tls-unavailable-integration"
        sources = [
            HERE / "registered_role_child_p1_unavailable_integration_test.cpp",
            FINANCIAL / "registered_p1_state_archive_scm.cpp",
            FINANCIAL / "registered_parent_role_fork.cpp",
            FINANCIAL / "registered_projection_route.cpp",
            FINANCIAL / "registered_roster_crypto_player.cpp",
            overlay / "Networking/CryptoPlayer.cpp",
            MPC / "history/epoch_journal.cpp",
            TRIAL / "privacy_registered_fresh_trial_capture_topology_reservation.cpp",
            TRIAL / "privacy_p1_corrupt_state_capsule_authority.cpp",
            MPC / "p1_mascot_secret_state_hook.cpp",
            TRIAL / "privacy_p1_corrupt_state_capsule_authority_control.cpp",
            TRIAL / "privacy_measurement_authority.cpp",
            TRIAL / "privacy_measurement_child_output_authority.cpp",
            TRIAL / "privacy_measurement_output_abi.cpp",
        ]
        command = [
            "g++", "-std=c++20", "-march=native", "-Wall", "-Wextra",
            "-Werror", "-Wno-overloaded-virtual", "-pedantic", "-pthread",
            "-ffunction-sections", "-fdata-sections",
            "-DNO_MIXED_CIRCUITS", "-DNO_AVX_OT", "-DUSE_GF2N_LONG",
            "-DMCL_USE_GMP=1", "-DMCL_DONT_USE_XBYAK",
            "-DMCL_FP_BIT=384", "-DMCL_FR_BIT=256", "-DMCL_MSM=0",
            "-DKPI_REGISTERED_ROSTER_TEST_SETUP",
            "-DKPI_REGISTERED_P1_STATE_ARCHIVE_SCM_TEST_SETUP",
            "-DKPI_FRESH_TRIAL_CAPTURE_TOPOLOGY_RESERVATION_TEST_SETUP",
            "-DKPB_P1_STATE_CAPSULE_TEST_SETUP",
            "-DKPB_P1_STATE_CAPSULE_FIXTURE_LIBRARY",
            *(str(source) for source in sources),
            "-I", str(overlay), "-I", str(overlay / "Networking"),
            "-I", str(FINANCIAL), "-I", str(MPC), "-I", str(TRIAL),
            "-I", str(MP), "-I", str(MP / "Networking"),
            "-I", str(MP / "deps"), "-I", str(MP / "local/include"),
            "-I", str(PREFIX / "include"),
            "-I", str(PREFIX / "include/x86_64-linux-gnu"),
            "-I", str(MCL / "include"),
            "-L", str(MP), "-Wl,-rpath," + str(MP), "-lSPDZ",
            "-L", str(PREFIX / "lib/x86_64-linux-gnu"),
            "-Wl,-rpath," + str(PREFIX / "lib/x86_64-linux-gnu"),
            "-L", str(MCL / "lib"), "-lmcl", "-lssl", "-lcrypto",
            "-lgmpxx", "-lgmp", "-lboost_filesystem",
            "-lboost_iostreams", "-lboost_thread", "-lrt", "-lz", "-ldl",
            "-Wl,--gc-sections", "-z", "noexecstack", "-o", str(binary),
        ]
        compiled = subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=180)
        self.assertEqual(
            compiled.returncode, 0, compiled.stdout + compiled.stderr)
        return binary

    def run_case(self, *, hostile: bool):
        with tempfile.TemporaryDirectory(prefix="kpb-p1-tls-unavailable-") as raw:
            root = Path(raw)
            overlay = root / "overlay"
            p1_tls_overlay_build.materialize(
                vendor_mp=MP, patch_path=PATCH, output=overlay)
            self.certificates(root, hostile=hostile)
            binary = self.compile(root, overlay)
            symbols = subprocess.run(
                ["nm", "-C", str(binary)], capture_output=True, text=True,
                check=True, timeout=30).stdout
            self.assertNotIn(
                "RegisteredPartyCompletionTransport::submit", symbols)

            port = self.free_port_base()
            peers = [subprocess.Popen(
                [str(binary), "peer", str(role), str(port)], cwd=root,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                for role in (0, 2)]
            result = subprocess.run(
                [str(binary),
                 "integration-failure" if hostile else "integration-success",
                 str(port)], cwd=root,
                capture_output=True, text=True, check=False, timeout=60)
            peer_results = []
            try:
                for process in peers:
                    peer_results.append(process.communicate(timeout=30))
            finally:
                for process in peers:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            if hostile:
                self.assertIn("SSL error:", result.stderr)
                self.assertIn("handshake", result.stderr.lower())
                self.assertTrue(
                    any(process.returncode == 78 for process in peers),
                    peer_results)
            else:
                self.assertIn("KPB_TLS_FOUR_LANE_ATTACHED", result.stderr)
                self.assertEqual([process.returncode for process in peers],
                                 [0, 0], peer_results)

    def test_real_tls_failure_reaches_authenticated_unavailable_ack(self):
        self.run_case(hostile=True)

    def test_successful_four_lane_attachment_still_closes_unavailable(self):
        self.run_case(hostile=False)


if __name__ == "__main__":
    unittest.main()

