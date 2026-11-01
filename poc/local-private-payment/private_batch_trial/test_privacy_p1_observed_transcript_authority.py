#!/usr/bin/env python3
"""Controls for the CONFIGURED0 actual-P1-transcript authority."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
MPC = HERE.parent / "mpc-prover"


class P1ObservedTranscriptAuthorityControls(unittest.TestCase):
    def compile(self, output, *sources, test_setup=False):
        command = [
            "g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
            "-pedantic", "-pthread",
        ]
        if test_setup:
            command.append("-DKPB_P1_OBSERVED_TRANSCRIPT_TEST_SETUP")
        command.extend(str(source) for source in sources)
        command.extend([
            "-I", str(HERE), "-I", str(MPC), "-lcrypto",
            "-o", str(output),
        ])
        return subprocess.run(
            command, capture_output=True, text=True, check=False)

    def production_sources(self):
        return (
            HERE / "privacy_p1_observed_transcript_authority.cpp",
            HERE / "privacy_measurement_authority.cpp",
            HERE / "privacy_measurement_child_output_authority.cpp",
            HERE / "privacy_measurement_output_abi.cpp",
        )

    def test_actual_unbounded_transcript_is_parsed_and_writer_closed(self):
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-observed-transcript-") as directory:
            binary = Path(directory) / "control"
            compiled = self.compile(
                binary,
                HERE / "privacy_p1_observed_transcript_authority_control.cpp",
                *self.production_sources(), test_setup=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run(
                [str(binary)], capture_output=True, text=True, check=False,
                timeout=20)
            self.assertEqual(
                (run.returncode, run.stdout, run.stderr), (0, "", ""))

    def test_production_surface_has_no_minter_fd_hash_or_summary(self):
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-observed-surface-") as directory:
            directory = Path(directory)
            source = directory / "surface.cpp"
            source.write_text(r'''
#include "privacy_p1_observed_transcript_authority.hpp"
#include <concepts>
using namespace kpb::measurement::p1_observed_transcript;
template<class T> concept HasTestMint = requires {
    T::test_only_mint({});
};
template<class T> concept HasSummary = requires(const T& value) {
    value.test_only_summary();
};
template<class T> concept HasRead = requires(const T& value) {
    value.test_only_read_all();
};
template<class T> concept HasFd = requires(const T& value) { value.fd(); };
template<class T> concept HasHash = requires(const T& value) {
    value.raw_wire_sha256();
};
template<class T> concept HasReceipt = requires(const T& value) {
    value.public_receipt();
};
static_assert(!HasTestMint<ObservedTranscriptPlanAuthority>);
static_assert(!HasSummary<ObservedTranscriptCompletionAuthority>);
static_assert(!HasRead<ObservedTranscriptCompletionAuthority>);
static_assert(!HasFd<ObservedTranscriptCompletionAuthority>);
static_assert(!HasHash<ObservedTranscriptCompletionAuthority>);
static_assert(!HasReceipt<ObservedTranscriptCompletionAuthority>);
static_assert(!std::copy_constructible<ObservedTranscriptPlanAuthority>);
static_assert(!std::copy_constructible<ObservedTranscriptWriterAuthority>);
static_assert(!std::copy_constructible<ObservedTranscriptCompletionAuthority>);
static_assert(std::move_constructible<ObservedTranscriptCompletionAuthority>);
static_assert(kSourceStatus.source_only_prototype);
static_assert(kSourceStatus.no_operational_byte_cap);
static_assert(kSourceStatus.actual_peer_and_fork_vector);
static_assert(!kSourceStatus.preopened_topology_archive_consumed);
static_assert(!kSourceStatus.internal_random_state_capture);
static_assert(!kSourceStatus.complete_passive_p1_view);
static_assert(!kSourceStatus.genuine_prelaunch_minter);
static_assert(!kSourceStatus.selected_runtime_eof_callsite);
static_assert(!kSourceStatus.observer_transfer);
static_assert(!kSourceStatus.configured);
int main() {}
''', encoding="utf-8")
            binary = directory / "surface"
            compiled = self.compile(binary, source, *self.production_sources())
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

    def test_storage_is_anonymous_disk_backed_and_has_no_operational_cap(self):
        header = (HERE / (
            "privacy_p1_observed_transcript_authority.hpp"
        )).read_text(encoding="utf-8")
        source = (HERE / (
            "privacy_p1_observed_transcript_authority.cpp"
        )).read_text(encoding="utf-8")
        combined = header + source
        self.assertIn("O_TMPFILE", source)
        self.assertIn("O_NOFOLLOW", source)
        self.assertIn("fstatfs", source)
        self.assertIn("TMPFS_MAGIC", source)
        self.assertIn("::fsync(", source)
        self.assertNotIn("memfd_create(", source)
        self.assertNotIn("fallocate(", source)
        self.assertNotIn("posix_fallocate(", source)
        self.assertNotIn("max_wire_bytes", combined)
        self.assertNotIn("MAX_ARCHIVE", combined)
        self.assertNotIn("MAX_TRANSCRIPT", combined)

    def test_selected_player_virtual_surface_has_no_production_peer_bypass(self):
        contract = (MPC / "p1_capturing_player_contract.hpp").read_text(
            encoding="utf-8")
        player = (MPC / "p1_capturing_player.cpp").read_text(
            encoding="utf-8")
        context = (MPC / "financial" / "registered_p1_context.cpp").read_text(
            encoding="utf-8")
        self.assertIn("class P1CapturingPlayer final : public Player", contract)
        required = (
            "send_long", "receive_long", "send_to_no_stats",
            "receive_player_no_stats", "send_no_stats", "recv_no_stats",
            "exchange_no_stats", "pass_around_no_stats",
            "Broadcast_Receive_no_stats", "send_receive_all_no_stats",
            "partial_broadcast_no_stats", "request_receive",
            "wait_receive", "fresh_fork",
        )
        for name in required:
            with self.subTest(name=name):
                self.assertIn(name, contract)
                self.assertIn(f"P1CapturingPlayer::{name}", player)
        self.assertLess(
            context.index("P1CapturingPlayer::begin("),
            context.index("std::make_unique<MascotContext>("))
        self.assertIn("capture_->register_fork(fork_, suffix)", player)
        self.assertIn("new P1CapturingPlayer(", player)

        bypasses = []
        for path in MPC.rglob("*.cpp"):
            if "evidence" in path.parts or "controls" in path.parts:
                continue
            text = path.read_text(encoding="utf-8")
            if "->peer_transport(" in text or ".peer_transport(" in text:
                bypasses.append(path.relative_to(MPC).as_posix())
        self.assertEqual(bypasses, [])


if __name__ == "__main__":
    unittest.main()
