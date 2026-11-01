#!/usr/bin/env python3
"""Controls for the source-derived producer byte-schedule blocker."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class SelectedProducerByteScheduleAuthorityControls(unittest.TestCase):
    def compile(self, output, *sources, test_setup=False, compile_only=False):
        command = [
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread',
        ]
        if test_setup:
            command.append(
                '-DKPB_SELECTED_PRODUCER_BYTE_SCHEDULE_TEST_SETUP')
        if compile_only:
            command.append('-c')
        command.extend(str(source) for source in sources)
        if compile_only:
            command.extend(['-I', str(HERE), '-o', str(output)])
        else:
            command.extend(['-I', str(HERE), '-lcrypto', '-o', str(output)])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def test_eight_source_bounds_and_missing_p1_are_exact(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-producer-byte-schedule-') as directory:
            binary = Path(directory) / 'control'
            compiled = self.compile(
                binary,
                HERE / 'privacy_selected_producer_byte_schedule_authority_control.cpp',
                HERE / 'privacy_selected_producer_byte_schedule_authority.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp',
                test_setup=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=20)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_complete_authority_has_no_public_or_test_mint_surface(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-producer-byte-schedule-surface-') as directory:
            directory = Path(directory)
            source = directory / 'surface.cpp'
            source.write_text(r'''
#include "privacy_selected_producer_byte_schedule_authority.hpp"
#include <concepts>
#include <type_traits>
using namespace kpb::measurement::producer_schedule;
template<class T> concept HasReceipt = requires(const T& value) {
    value.public_receipt();
};
template<class T> concept HasEntries = requires(const T& value) {
    value.entries();
};
template<class T> concept HasBytes = requires(const T& value) {
    value.bytes();
};
static_assert(!std::default_initializable<
    SelectedProducerByteScheduleAuthority>);
static_assert(!std::copy_constructible<
    SelectedProducerByteScheduleAuthority>);
static_assert(std::move_constructible<
    SelectedProducerByteScheduleAuthority>);
static_assert(!HasReceipt<SelectedProducerByteScheduleAuthority>);
static_assert(!HasEntries<SelectedProducerByteScheduleAuthority>);
static_assert(!HasBytes<SelectedProducerByteScheduleAuthority>);
static_assert(sizeof(ProducerArchiveReservationBridge) > 0);
static_assert(!kProducerByteScheduleSourceStatus.complete_authority_minter);
static_assert(!kProducerByteScheduleSourceStatus.archive_consumer);
static_assert(!kProducerByteScheduleSourceStatus.configured);
int main() {}
''', encoding='utf-8')
            compiled = self.compile(
                directory / 'surface.o', source, compile_only=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

            forbidden = directory / 'forbidden.cpp'
            forbidden.write_text(r'''
#include "privacy_selected_producer_byte_schedule_authority.hpp"
using namespace kpb::measurement::producer_schedule;
int main() {
    auto authority = SelectedProducerByteScheduleAuthority::test_only_mint();
    (void)authority;
}
''', encoding='utf-8')
            refused = self.compile(
                directory / 'forbidden.o', forbidden, compile_only=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn('test_only_mint', refused.stderr)

    def test_complete_consumer_name_cannot_be_redefined(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-producer-byte-schedule-friend-') as directory:
            directory = Path(directory)
            source = directory / 'hostile.cpp'
            source.write_text(r'''
#include "privacy_selected_producer_byte_schedule_authority.hpp"
namespace kpb::measurement::producer_schedule {
class ProducerArchiveReservationBridge final {};
}
int main() {}
''', encoding='utf-8')
            compiled = self.compile(
                directory / 'hostile.o', source, compile_only=True)
            self.assertNotEqual(compiled.returncode, 0)
            self.assertIn('redefinition', compiled.stderr)

    def test_source_has_no_archive_fork_network_or_raw_count_mint(self):
        header = (
            HERE / 'privacy_selected_producer_byte_schedule_authority.hpp'
        ).read_text(encoding='utf-8')
        source = (
            HERE / 'privacy_selected_producer_byte_schedule_authority.cpp'
        ).read_text(encoding='utf-8')
        joined = header + source
        for forbidden in (
                'fallocate(', 'posix_fallocate(', 'statvfs(', 'fork(',
                'execve(', 'socket(', 'connect(', 'broadcast', 'funding'):
            self.assertNotIn(forbidden, joined)
        self.assertNotIn('test_only_mint', joined)
        private_bound = source.split(
            'enum class CompleteProducerByteBoundKind', 1)[1].split('};', 1)[0]
        self.assertIn('ExactBytes', private_bound)
        self.assertIn('ProtocolUpperBound', private_bound)
        self.assertNotIn('OperationalCapEvidence', private_bound)
        self.assertNotIn('Missing', private_bound)
        self.assertNotIn('OperationalCapEvidence', joined)
        self.assertIn('schedule_derivation_source_identity{}', source)
        self.assertIn('schedule_derivation_build_identity{}', source)
        self.assertIn('eight_source_bounded_slots = true', header)
        self.assertIn('c1_source_frozen_no_retry_schedule = true', header)
        self.assertIn('c1_retry_invalidates_whole_trial = true', header)
        self.assertIn(
            'c1_retry_evidence_retained_under_trial = true', header)
        self.assertIn('c1_retry_outer_history_join = false', header)
        self.assertNotIn('805\'843\'802', source)
        self.assertNotIn('MAX_RETRIES', joined)
        self.assertIn('schedule_derivation_source_artifact = false', header)
        self.assertIn('schedule_derivation_build_artifact = false', header)
        self.assertIn('complete_authority_minter = false', header)
        self.assertIn('p1_round1_schedule = false', header)
        self.assertIn('p1_round2_schedule = false', header)


if __name__ == '__main__':
    unittest.main()
