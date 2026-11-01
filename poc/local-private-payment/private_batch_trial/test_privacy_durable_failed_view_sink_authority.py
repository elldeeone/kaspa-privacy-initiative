#!/usr/bin/env python3
"""Controls for the isolated durable failed-view sink primitive."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class DurableFailedViewSinkControls(unittest.TestCase):
    def compile(self, output, *sources, test_setup=False, sanitize=False):
        command = [
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread',
        ]
        if test_setup:
            command.append('-DKPB_DURABLE_FAILED_VIEW_SINK_TEST_SETUP')
        if sanitize:
            command.extend([
                '-g', '-O1', '-fno-omit-frame-pointer',
                '-fsanitize=address,undefined',
            ])
        command.extend(str(source) for source in sources)
        command.extend(['-I', str(HERE), '-lcrypto', '-o', str(output)])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def test_named_private_sink_is_crash_retained_and_fail_closed(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-durable-failed-view-sink-') as raw:
            binary = Path(raw) / 'control'
            compiled = self.compile(
                binary,
                HERE / 'privacy_durable_failed_view_sink_control.cpp',
                HERE / 'privacy_durable_failed_view_sink_authority.cpp',
                test_setup=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=20)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_control_is_asan_ubsan_clean(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-durable-failed-view-sanitized-') as raw:
            binary = Path(raw) / 'control'
            compiled = self.compile(
                binary,
                HERE / 'privacy_durable_failed_view_sink_control.cpp',
                HERE / 'privacy_durable_failed_view_sink_authority.cpp',
                test_setup=True, sanitize=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            environment = os.environ.copy()
            environment['ASAN_OPTIONS'] = 'detect_leaks=1'
            environment['UBSAN_OPTIONS'] = 'halt_on_error=1'
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=20,
                                 env=environment)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_production_surface_is_opaque_and_unconfigured(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-durable-failed-view-surface-') as raw:
            root = Path(raw)
            source = root / 'surface.cpp'
            source.write_text(r'''
#include "privacy_durable_failed_view_sink_authority.hpp"
#include <concepts>
using namespace kpb::measurement::durable_failed_view;
using ExpectedPersistSignature = DurableFailedViewSinkAuthority (*)(
    kpb::measurement::fresh_trial_owner::AllBranchFreshTrialStepAuthority&&,
    SelectedDurableFailedViewSinkRootAuthority&&,
    SelectedDurableFailedViewByteScheduleAuthority&&);
template<class T> concept HasTestReserve = requires {
    T::test_only_reserve("/tmp", 4096);
};
template<class T> concept HasPublicReceipt = requires(const T& value) {
    value.public_receipt();
};
template<class T> concept HasPath = requires(const T& value) {
    value.path();
};
template<class T> concept HasFd = requires(const T& value) { value.fd(); };
template<class T> concept HasHash = requires(const T& value) {
    value.sha256();
};
template<class T> concept HasStage = requires(const T& value) {
    value.failure_stage();
};
template<class T> concept HasError = requires(const T& value) {
    value.error_number();
};
template<class T> concept HasCommit = requires(T&& value) {
    static_cast<T&&>(value).commit();
};
static_assert(!std::copy_constructible<
    DurableFailedViewSinkReservationAuthority>);
static_assert(std::move_constructible<
    DurableFailedViewSinkReservationAuthority>);
static_assert(!std::default_initializable<
    DurableFailedViewSinkReservationAuthority>);
static_assert(!std::copy_constructible<DurableFailedViewSinkAuthority>);
static_assert(std::move_constructible<DurableFailedViewSinkAuthority>);
static_assert(!std::default_initializable<DurableFailedViewSinkAuthority>);
static_assert(!std::copy_constructible<
    DurableFailedViewSinkUnavailableAuthority>);
static_assert(std::move_constructible<
    DurableFailedViewSinkUnavailableAuthority>);
static_assert(!std::default_initializable<
    DurableFailedViewSinkUnavailableAuthority>);
static_assert(!HasTestReserve<DurableFailedViewSinkReservationAuthority>);
static_assert(!HasPublicReceipt<DurableFailedViewSinkAuthority>);
static_assert(!HasPath<DurableFailedViewSinkAuthority>);
static_assert(!HasFd<DurableFailedViewSinkAuthority>);
static_assert(!HasHash<DurableFailedViewSinkAuthority>);
static_assert(!HasPublicReceipt<DurableFailedViewSinkUnavailableAuthority>);
static_assert(!HasPath<DurableFailedViewSinkUnavailableAuthority>);
static_assert(!HasFd<DurableFailedViewSinkUnavailableAuthority>);
static_assert(!HasHash<DurableFailedViewSinkUnavailableAuthority>);
static_assert(!HasStage<DurableFailedViewSinkUnavailableAuthority>);
static_assert(!HasError<DurableFailedViewSinkUnavailableAuthority>);
static_assert(!HasCommit<DurableFailedViewSinkReservationAuthority>);
static_assert(std::same_as<
    decltype(&DurableFailedViewSinkBridge::persist_failed_view),
    ExpectedPersistSignature>);
static_assert(kDurableFailedViewSinkSourceStatus
    .diagnostic_named_sink_primitive);
static_assert(kDurableFailedViewSinkSourceStatus
    .diagnostic_preallocated_payload_blocks);
static_assert(kDurableFailedViewSinkSourceStatus
    .diagnostic_same_inode_read_only_reopen);
static_assert(kDurableFailedViewSinkSourceStatus
    .diagnostic_file_and_directory_fsync);
static_assert(kDurableFailedViewSinkSourceStatus
    .diagnostic_partial_survives_process_exit);
static_assert(kDurableFailedViewSinkSourceStatus
    .diagnostic_fault_unavailable_retains_inodes);
static_assert(!kDurableFailedViewSinkSourceStatus.source_owned_root);
static_assert(!kDurableFailedViewSinkSourceStatus
    .source_owned_exact_byte_schedule);
static_assert(!kDurableFailedViewSinkSourceStatus
    .canonical_failed_view_serializer);
static_assert(!kDurableFailedViewSinkSourceStatus.outer_owner_integration);
static_assert(!kDurableFailedViewSinkSourceStatus.mandatory_sink);
static_assert(!kDurableFailedViewSinkSourceStatus.configured);
int main() {}
''', encoding='utf-8')
            compiled = self.compile(root / 'surface', source)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

    def test_complete_contract_name_cannot_be_redefined(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-durable-failed-view-contract-') as raw:
            root = Path(raw)
            source = root / 'hostile.cpp'
            source.write_text(r'''
#include "privacy_durable_failed_view_sink_contract.hpp"
namespace kpb::measurement::durable_failed_view {
class DurableFailedViewSinkBridge final {};
}
int main() {}
''', encoding='utf-8')
            compiled = self.compile(root / 'hostile', source)
            self.assertNotEqual(compiled.returncode, 0)
            self.assertIn('redefinition', compiled.stderr)


if __name__ == '__main__':
    unittest.main()
