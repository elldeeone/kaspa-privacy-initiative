#!/usr/bin/env python3
"""Controls for exact sole-reader raw-wire retention in anonymous files."""

from pathlib import Path
import json
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class ProducerSealedArchiveControls(unittest.TestCase):
    def compile(self, output, *sources, test_setup=False):
        command = [
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread',
        ]
        if test_setup:
            command.append('-DKPB_CAPTURE_PRODUCER_ARCHIVE_TEST_SETUP')
        command.extend(str(source) for source in sources)
        command.extend(['-I', str(HERE), '-lcrypto', '-o', str(output)])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def test_exact_ten_streams_are_sealed_and_one_shot(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-producer-sealed-archive-') as directory:
            binary = Path(directory) / 'control'
            compiled = self.compile(
                binary,
                HERE / 'privacy_capture_producer_archive_control.cpp',
                HERE / 'privacy_capture_producer_archive.cpp',
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

    def test_production_has_no_archive_factory_or_private_evidence_surface(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-producer-archive-surface-') as directory:
            directory = Path(directory)
            source = directory / 'surface.cpp'
            source.write_text(r'''
#include "privacy_capture_producer_archive.hpp"
#include <concepts>
using namespace kpb::measurement::producer_archive;
template<class T> concept HasTestBegin = requires {
    T::test_only_begin({}, {});
};
template<class T> concept HasTransportFds = requires(const T& x) {
    x.test_only_duplicate_transport_fds();
};
template<class T> concept HasPublicReceipt = requires(const T& x) {
    x.public_receipt();
};
template<class T> concept HasFd = requires(const T& x) { x.fd(); };
template<class T> concept HasHash = requires(const T& x) { x.record_root(); };
template<class T> concept HasObserverTransfer = requires(T&& x) {
    static_cast<T&&>(x).consume_for_observer();
};
template<class T> concept HasPartialSeal = requires(T&& x) {
    static_cast<T&&>(x).seal_partial_c03_for_runtime();
};
template<class T> concept HasPartialTransport = requires(const T& x) {
    x.duplicate_for_transport();
};
template<class T> concept HasQuarantine = requires(T&& x) {
    static_cast<T&&>(x).quarantine_for_runtime(
        ProducerArchiveQuarantineStage::Internal, 1);
};
template<class T> concept HasPreidentityAdoption = requires {
    T::adopt_preidentity_reservation({}, {}, {}, {}, {}, {}, {}, {}, {});
};
template<class T> concept HasStage = requires(const T& x) { x.stage(); };
template<class T> concept HasError = requires(const T& x) {
    x.error_number();
};
static_assert(!HasTestBegin<ProducerSealedArchiveBuilder>);
static_assert(!HasTransportFds<ProducerSealedArchiveAuthority>);
static_assert(!HasPublicReceipt<ProducerSealedArchiveAuthority>);
static_assert(!HasFd<ProducerSealedArchiveAuthority>);
static_assert(!HasHash<ProducerSealedArchiveAuthority>);
static_assert(!HasObserverTransfer<ProducerSealedArchiveAuthority>);
static_assert(!HasPartialSeal<ProducerSealedArchiveBuilder>);
static_assert(!HasQuarantine<ProducerSealedArchiveBuilder>);
static_assert(!HasPreidentityAdoption<ProducerSealedArchiveBuilder>);
static_assert(!HasPublicReceipt<ProducerPartialC03ArchiveAuthority>);
static_assert(!HasFd<ProducerPartialC03ArchiveAuthority>);
static_assert(!HasHash<ProducerPartialC03ArchiveAuthority>);
static_assert(!HasPartialTransport<ProducerPartialC03ArchiveAuthority>);
static_assert(!std::copy_constructible<
    ProducerPartialC03ArchiveAuthority>);
static_assert(std::move_constructible<
    ProducerPartialC03ArchiveAuthority>);
static_assert(!HasPublicReceipt<ProducerArchiveQuarantineAuthority>);
static_assert(!HasFd<ProducerArchiveQuarantineAuthority>);
static_assert(!HasHash<ProducerArchiveQuarantineAuthority>);
static_assert(!HasStage<ProducerArchiveQuarantineAuthority>);
static_assert(!HasError<ProducerArchiveQuarantineAuthority>);
static_assert(!std::copy_constructible<
    ProducerArchiveQuarantineAuthority>);
static_assert(std::move_constructible<
    ProducerArchiveQuarantineAuthority>);
int main() {}
''', encoding='utf-8')
            compiled = self.compile(directory / 'surface', source)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

    def test_operational_byte_caps_cannot_discard_partial_c03_history(self):
        header = (HERE / 'privacy_capture_producer_archive.hpp').read_text(
            encoding='utf-8')
        source = (HERE / 'privacy_capture_producer_archive.cpp').read_text(
            encoding='utf-8')
        self.assertNotIn('MAX_PRODUCER_ARCHIVE_STREAM_BYTES', header + source)
        self.assertNotIn('MAX_PRODUCER_ARCHIVE_TOTAL_BYTES', header + source)
        self.assertNotIn('1ULL << 30', header + source)
        self.assertNotIn('4ULL << 30', header + source)

    def test_archive_bytes_are_anonymous_disk_backed_not_ram_backed(self):
        source = (HERE / 'privacy_capture_producer_archive.cpp').read_text(
            encoding='utf-8')
        self.assertNotIn('memfd_create(', source)
        self.assertIn('O_TMPFILE', source)
        self.assertIn('O_NOFOLLOW', source)
        self.assertIn('fstatfs', source)
        self.assertIn('TMPFS_MAGIC', source)
        self.assertIn('::fsync(', source)

    def test_prelaunch_reservation_remains_blocked_without_source_bound(self):
        blocker = json.loads((
            HERE / 'privacy_capture_archive_reservation_blocker.json'
        ).read_text(encoding='utf-8'))
        self.assertFalse(blocker['configured'])
        self.assertEqual(
            blocker['selected_program_byte_schedule_authority'], 'MISSING')
        self.assertFalse(blocker['reservation_before_trial_identity_use'])
        self.assertFalse(blocker['typed_archive_failure_invalidation'])
        self.assertFalse(blocker['no_drop_quarantine_primitive'])
        self.assertTrue(blocker['live_process_linear_quarantine_owner'])
        self.assertFalse(blocker['allocation_failure_no_drop'])
        self.assertFalse(blocker['process_crash_durable'])
        self.assertFalse(blocker['power_loss_durable'])
        self.assertTrue(blocker['post_partial_inspection_quarantine'])
        self.assertFalse(blocker['typed_unavailable_terminal'])
        self.assertFalse(
            blocker['retry_after_incomplete_capture_permitted'])
        self.assertFalse(blocker['observed_or_fixture_sizes_admissible'])
        self.assertEqual(len(blocker['entries']), 10)
        self.assertEqual(
            [row['slot'] for row in blocker['entries']], list(range(10)))
        self.assertEqual(
            [row['fixed_fd'] for row in blocker['entries']],
            list(range(20, 30)))
        self.assertTrue(all(row['bound'] == 'MISSING'
                            for row in blocker['entries']))

    def test_quarantine_claim_is_live_process_only(self):
        header = (HERE / 'privacy_capture_producer_archive.hpp').read_text(
            encoding='utf-8')
        self.assertIn('live_process_linear_quarantine_owner{}', header)
        self.assertIn('allocation_failure_no_drop{}', header)
        self.assertIn('process_crash_durable{}', header)
        self.assertIn('power_loss_durable{}', header)
        self.assertIn('.live_process_linear_quarantine_owner = true', header)
        self.assertIn('.allocation_failure_no_drop = false', header)
        self.assertIn('.process_crash_durable = false', header)
        self.assertIn('.power_loss_durable = false', header)


if __name__ == '__main__':
    unittest.main()
