#!/usr/bin/env python3
"""Hostile controls for the CONFIGURED0 P1 state-archive SCM bridge."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
MPC = FINANCIAL.parent
TRIAL = MPC.parent / "private_batch_trial"


class RegisteredP1StateArchiveScmControls(unittest.TestCase):
    def compile_snippet(self, source):
        return subprocess.run([
            "g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
            "-pedantic", "-fsyntax-only", "-x", "c++", "-",
            "-I", str(FINANCIAL), "-I", str(MPC), "-I", str(TRIAL),
        ], input=source, capture_output=True, text=True, check=False)

    def compile(self, output, *, sanitize=False):
        command = [
            "g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
            "-pedantic", "-pthread", "-ffunction-sections",
            "-fdata-sections",
            "-DKPI_REGISTERED_P1_STATE_ARCHIVE_SCM_TEST_SETUP",
            "-DKPI_FRESH_TRIAL_CAPTURE_TOPOLOGY_RESERVATION_TEST_SETUP",
            "-DKPB_P1_STATE_CAPSULE_TEST_SETUP",
            "-DKPB_P1_STATE_CAPSULE_FIXTURE_LIBRARY",
        ]
        if sanitize:
            command.extend([
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            ])
        command.extend(str(source) for source in (
            HERE / "registered_p1_state_archive_scm_test.cpp",
            FINANCIAL / "registered_p1_state_archive_scm.cpp",
            FINANCIAL / "registered_parent_role_fork.cpp",
            FINANCIAL / "registered_projection_route.cpp",
            TRIAL / "privacy_registered_fresh_trial_capture_topology_reservation.cpp",
            TRIAL / "privacy_p1_corrupt_state_capsule_authority.cpp",
            MPC / "p1_mascot_secret_state_hook.cpp",
            TRIAL / "privacy_p1_corrupt_state_capsule_authority_control.cpp",
            TRIAL / "privacy_measurement_authority.cpp",
            TRIAL / "privacy_measurement_child_output_authority.cpp",
            TRIAL / "privacy_measurement_output_abi.cpp",
        ))
        command.extend([
            "-I", str(FINANCIAL), "-I", str(MPC), "-I", str(TRIAL),
            "-lcrypto", "-Wl,--gc-sections", "-o", str(output),
        ])
        return subprocess.run(
            command, capture_output=True, text=True, check=False)

    def build_and_run(self, *, sanitize=False):
        with tempfile.TemporaryDirectory(prefix="kpi-p1-state-scm-") as d:
            binary = Path(d) / "control"
            compiled = self.compile(binary, sanitize=sanitize)
            self.assertEqual(
                compiled.returncode, 0, compiled.stdout + compiled.stderr)
            run = subprocess.run(
                [str(binary)], capture_output=True, text=True,
                check=False, timeout=90)
            self.assertEqual(
                (run.returncode, run.stdout, run.stderr), (0, "", ""))

    def test_wrong_role_fd_replay_truncation_and_child_death(self):
        self.build_and_run()

    def test_asan_ubsan(self):
        self.build_and_run(sanitize=True)

    def test_production_surface_remains_unconfigured(self):
        contract = (FINANCIAL /
                    "registered_p1_state_archive_scm_contract.hpp").read_text(
                        encoding="utf-8")
        header = (FINANCIAL /
                  "registered_p1_state_archive_scm.hpp").read_text(
                      encoding="utf-8")
        implementation = (FINANCIAL /
                          "registered_p1_state_archive_scm.cpp").read_text(
                              encoding="utf-8")
        self.assertIn("extract_state_channels", contract)
        self.assertIn("prepare_writer_adoption", contract)
        self.assertIn("attach_role1_prelaunch", contract)
        self.assertIn("begin_role1_prelaunch", contract)
        self.assertIn("finish_unavailable_noexcept", header)
        self.assertNotIn("finish_success_noexcept", header)
        self.assertIn("RegisteredRole1P1StateRecorderFacade& recorder()",
                      header)
        self.assertNotIn("P1CorruptStateRecorderAuthority& recorder()",
                         header)
        self.assertNotIn("int fd", contract)
        self.assertNotIn("Digest", contract)
        self.assertIn("SCM_RIGHTS", implementation)
        self.assertIn("SCM_CREDENTIALS", implementation)
        self.assertIn("MSG_CMSG_CLOEXEC", implementation)
        self.assertIn("TerminalReplay", header)
        self.assertIn("bool configured", header)
        self.assertIn("kRegisteredP1StateArchiveScmSourceStatus{}", header)
        self.assertIn("privacy_measurement_sha256.hpp", implementation)
        self.assertIn("result->unavailable = true", implementation)
        self.assertNotIn("result->complete", implementation)
        self.assertNotIn("::kill", implementation)
        self.assertNotIn("SYS_kill", implementation)
        self.assertIn("const int owned = std::exchange(fd, -1)",
                      implementation)
        self.assertNotIn("while (::close", implementation)

        extract_begin = implementation.index(
            "RegisteredP1StateArchiveScmBridge::extract_state_channels")
        extract_end = implementation.index(
            "RegisteredP1StateArchiveScmBridge::prepare_writer_adoption",
            extract_begin)
        extract = implementation[extract_begin:extract_end]
        extraction_claim = extract.index(
            "std::exchange(topology.p1_state_parent_read_fds_")
        self.assertLess(extract.index("std::array<FileFingerprint, 2> parents"),
                        extraction_claim)
        self.assertLess(extract.index("result->inodes[0] != "
                                      "result->inodes[1]"),
                        extraction_claim)
        self.assertNotIn("regular_file(", extract[extraction_claim:])
        self.assertIn(
            "test_only_round2_extraction_failure_retains_all", contract)

        self.assertIn(
            "get_digest(packet, 176) == endpoint->expected_trial_identity",
            implementation)
        self.assertIn(
            "endpoint->expected_prelaunch_binding_identity", implementation)
        self.assertIn("get_digest(packet, 416)", implementation)

        begin = implementation.index(
            "RegisteredP1StateArchiveScmBridge::prepare_writer_adoption")
        end = implementation.index(
            "void RegisteredP1StateArchiveScmBridge::"
            "attach_role1_prelaunch", begin)
        prepare = implementation[begin:end]
        claim = prepare.index("auto source = std::move(selected.storage_)")
        for operation in (
                "std::make_unique<", "require_seqpacket(inspected->channel)",
                "::fcntl(inspected->writer", "::lseek(inspected->writer",
                "regular_file(inspected->writer"):
            self.assertLess(prepare.index(operation), claim)
        after_claim = prepare[claim:]
        self.assertNotIn("::fcntl", after_claim)
        self.assertNotIn("::lseek", after_claim)
        self.assertNotIn("::fstat", after_claim)
        self.assertNotIn("std::make_unique", after_claim)

        attach_begin = implementation.index(
            "RegisteredP1StateArchiveScmBridge::attach_role1_prelaunch")
        attach_end = implementation.index(
            "} // namespace kpi::mpc::financial::registered_driver",
            attach_begin)
        attach = implementation[attach_begin:attach_end]
        attach_claim = attach.index(
            "joined->child_round.emplace(std::move(child_round))")
        for operation in (
                "std::make_unique<", "new RegisteredRole1P1StatePrelaunch"):
            self.assertLess(attach.index(operation), attach_claim)
        for operation in (
                "require_seqpacket(child->channel)",
                "::fcntl(child->writer", "::lseek(child->writer",
                "regular_file(child->writer",
                "validate_for_role1_prelaunch_attachment"):
            self.assertGreater(attach.index(operation), attach_claim)
        attach_after_claim = attach[attach_claim:]
        self.assertNotIn("std::make_unique", attach_after_claim)
        self.assertNotIn("new ", attach_after_claim)

        runtime_begin = implementation.index(
            "RegisteredP1StateArchiveScmBridge::begin_role1_prelaunch")
        runtime_end = implementation.index(
            "} // namespace kpi::mpc::financial::registered_driver",
            runtime_begin)
        runtime = implementation[runtime_begin:runtime_end]
        allocation = runtime.index(
            "std::make_unique<RegisteredRole1P1StateRuntimeAuthority::"
            "Storage>()")
        writer_allocation = runtime.index(
            "std::make_unique<P1StateArchiveWriterAdoptionAuthority::"
            "Storage>()")
        terminal_allocation = runtime.index(
            "RegisteredP1StateArchiveChildTerminalAuthority::Storage>()")
        claim = runtime.index("auto source = std::move(selected.storage_)")
        self.assertLess(allocation, claim)
        self.assertLess(writer_allocation, claim)
        self.assertLess(terminal_allocation, claim)
        facade_allocation = runtime.index(
            "new RegisteredRole1P1StateRecorderFacade(nullptr)")
        self.assertLess(facade_allocation, claim)
        self.assertIn("begin_before_player_and_protocol_setup", runtime)
        self.assertIn("send_pre_recorder_unavailable", runtime)
        self.assertIn("unavailable_trial_identity", runtime)
        self.assertNotIn("std::make_unique", runtime[claim:])
        self.assertNotIn("int fd", runtime)
        self.assertIn("finish_unavailable_noexcept(storage_.get())",
                      implementation)
        self.assertIn("send_terminal_noexcept", implementation)
        self.assertIn("storage->recorder_facade.reset()", implementation)

    def test_complete_consumer_bridge_and_private_writer_cannot_be_forged(self):
        redefined = self.compile_snippet(r'''
#include "registered_p1_state_archive_writer_adoption_contract.hpp"
namespace kpi::mpc::financial::registered_driver {
class P1StateArchiveWriterAdoptionConsumerBridge final {};
}
''')
        self.assertNotEqual(redefined.returncode, 0)
        direct = self.compile_snippet(r'''
#include "registered_p1_state_archive_writer_adoption_contract.hpp"
#include <memory>
#include <utility>
using A = kpi::mpc::financial::registered_driver::
    P1StateArchiveWriterAdoptionAuthority;
int main() {
    std::unique_ptr<A::Storage> storage;
    A value(std::move(storage));
    (void)value;
}
''')
        self.assertNotEqual(direct.returncode, 0)
        contract = (FINANCIAL /
                    "registered_p1_state_archive_writer_adoption_contract.hpp"
                    ).read_text(encoding="utf-8")
        self.assertIn(
            "class P1StateArchiveWriterAdoptionConsumerBridge final",
            contract)
        self.assertNotIn("friend class ::kpb::measurement", contract)


if __name__ == "__main__":
    unittest.main()
