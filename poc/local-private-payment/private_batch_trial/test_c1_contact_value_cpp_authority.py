#!/usr/bin/env python3
"""Compile/run controls for the move-only C1 contact/value authority."""

from pathlib import Path
import fcntl
import os
import subprocess
import tempfile
import unittest

import c1_capture_supervisor as capture


HERE = Path(__file__).resolve().parent


class C1ContactValueCppAuthorityControls(unittest.TestCase):
    def compile(self, output, *sources, test_setup=False):
        command = [
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread',
        ]
        if test_setup:
            command.extend((
                '-DKPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP',
                '-DKPB_C1_CONTACT_VALUE_AUTHORITY_TEST_SETUP',
            ))
        command.extend(str(source) for source in sources)
        command.extend(('-I', str(HERE), '-lcrypto', '-o', str(output)))
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def sources(self):
        return (
            HERE / 'c1_contact_value_authority.cpp',
            HERE / 'privacy_capture_producer_runtime.cpp',
            HERE / 'privacy_capture_producer_archive.cpp',
            HERE / 'privacy_measurement_authority.cpp',
            HERE / 'privacy_measurement_child_output_authority.cpp',
            HERE / 'privacy_measurement_output_abi.cpp',
        )

    def test_move_only_split_replay_cross_binding_and_sealed_fd(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-c1-contact-value-authority-') as directory:
            binary = Path(directory) / 'control'
            compiled = self.compile(
                binary,
                HERE / 'c1_contact_value_authority_control.cpp',
                *self.sources(), test_setup=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=20)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_cpp_offer_is_accepted_by_exact_python_fd31_parser(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-c1-contact-value-interop-') as directory:
            directory = Path(directory)
            binary = directory / 'control'
            compiled = self.compile(
                binary,
                HERE / 'c1_contact_value_authority_control.cpp',
                *self.sources(), test_setup=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            emitted = subprocess.run(
                [str(binary), '--emit-offer'], capture_output=True,
                check=False, timeout=20)
            self.assertEqual(emitted.returncode, 0, emitted.stderr.decode())
            self.assertEqual(len(emitted.stdout),
                             capture.CONTACT_VALUE_OFFER_BYTES)

            fd = os.memfd_create(
                'kpb-c1-cpp-python-interop',
                os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            os.fchmod(fd, 0o600)
            os.write(fd, emitted.stdout)
            seals = (fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK |
                     fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            try:
                try:
                    saved = os.dup(capture.CONTACT_VALUE_OFFER_FIXED_FD)
                except OSError:
                    saved = None
                if fd != capture.CONTACT_VALUE_OFFER_FIXED_FD:
                    os.dup2(fd, capture.CONTACT_VALUE_OFFER_FIXED_FD)
                    os.close(fd)
                fd = -1
                binding = capture.RunBinding(
                    round=1,
                    attempt_id='11111111-1111-4111-8111-111111111111',
                    cohort_sha256='24' * 32,
                    financial_run_id='20' * 32,
                    capture_identity=
                        '22222222-2222-4222-8222-222222222222')
                supervisor = capture.C1CaptureSupervisor(
                    directory / 'capture', binding,
                    contact_value_offer_fd=
                        capture.CONTACT_VALUE_OFFER_FIXED_FD)
                self.assertTrue(supervisor.root.is_dir())
            finally:
                if fd >= 0:
                    os.close(fd)
                if saved is not None:
                    os.dup2(saved, capture.CONTACT_VALUE_OFFER_FIXED_FD)
                    os.close(saved)

    def test_production_surface_cannot_mint_or_read_residual(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-c1-contact-value-production-') as directory:
            directory = Path(directory)
            source = directory / 'production.cpp'
            source.write_text(r'''
#include "c1_contact_value_authority.hpp"
#include <type_traits>
using namespace kpb::measurement;
using namespace kpb::measurement::c1_capture;
template<class T> concept HasTestMatch = requires(const T& value) {
    value.test_only_matches(
        RunBinding{}, 1, Digest{}, Digest{}, std::array<Digest, 3>{});
};
template<class T> concept HasBinding = requires(const T& value) {
    value.binding;
};
template<class T> concept HasAuthorityIdentity = requires(const T& value) {
    value.contact_value_authority_identity;
};
static_assert(!std::is_copy_constructible_v<C1LifecycleStagePlanAuthority>);
static_assert(!std::is_copy_constructible_v<C1InvoiceRouteAuthority>);
static_assert(!std::is_copy_constructible_v<C1ContactValueOfferAuthority>);
static_assert(!std::is_copy_constructible_v<C1PostcaptureAdmissionAuthority>);
static_assert(!std::is_constructible_v<
    C1LifecycleStagePlanAuthority, PublicC1LifecycleStagePlan>);
static_assert(!std::is_constructible_v<
    C1InvoiceRouteAuthority, PublicC1InvoiceRoute>);
static_assert(!HasTestMatch<C1PostcaptureAdmissionAuthority>);
static_assert(!HasBinding<C1PostcaptureAdmissionAuthority>);
static_assert(!HasAuthorityIdentity<C1PostcaptureAdmissionAuthority>);
static_assert(kC1ContactValueAuthoritySourceStatus.
    live_parent_producer_authority_required);
static_assert(kC1ContactValueAuthoritySourceStatus.
    immutable_sealed_fixed_fd_offer);
static_assert(kC1ContactValueAuthoritySourceStatus.
    caller_contact_fields_forbidden);
static_assert(kC1ContactValueAuthoritySourceStatus.
    move_only_postcapture_residual);
static_assert(!kC1ContactValueAuthoritySourceStatus.
    controller_stage_plan_authority_integrated);
static_assert(!kC1ContactValueAuthoritySourceStatus.
    authenticated_invoice_route_authority_integrated);
static_assert(!kC1ContactValueAuthoritySourceStatus.
    selected_launcher_consumes_offer);
static_assert(kC1ContactValueAuthoritySourceStatus.
    observer_admission_join_implemented);
static_assert(!kC1ContactValueAuthoritySourceStatus.actual_launch_enabled);
int main() { return 0; }
''', encoding='utf-8')
            binary = directory / 'production'
            compiled = self.compile(binary, source, *self.sources())
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            symbols = subprocess.run(
                ['nm', '-C', str(binary)], capture_output=True, text=True,
                check=False, timeout=10)
            self.assertEqual(symbols.returncode, 0,
                             symbols.stdout + symbols.stderr)
            self.assertNotIn('test_only_mint', symbols.stdout)
            self.assertNotIn('test_only_matches', symbols.stdout)

    def test_test_mints_do_not_compile_in_production(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-c1-contact-value-no-test-mint-') as directory:
            directory = Path(directory)
            source = directory / 'forbidden.cpp'
            source.write_text(r'''
#include "c1_contact_value_authority.hpp"
using namespace kpb::measurement::c1_capture;
int main() {
    auto stage = C1LifecycleStagePlanAuthority::test_only_mint({});
    auto route = C1InvoiceRouteAuthority::test_only_mint({});
    (void)stage; (void)route;
}
''', encoding='utf-8')
            compiled = self.compile(
                directory / 'forbidden', source, *self.sources())
            self.assertNotEqual(compiled.returncode, 0,
                                'test-only C1 mint unexpectedly compiled')
            self.assertIn('test_only_mint', compiled.stderr)

    def test_undefined_lifecycle_controller_friend_cannot_be_defined(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-c1-no-controller-forgery-') as directory:
            directory = Path(directory)
            source = directory / 'forgery.cpp'
            source.write_text(r'''
#include "c1_contact_value_authority.hpp"
namespace kpb::measurement::c1_capture {
class C1LifecycleControllerBridge final {
public:
    static auto stage() {
        return C1LifecycleStagePlanAuthority(
            PublicC1LifecycleStagePlan{});
    }
    static auto route() {
        return C1InvoiceRouteAuthority(PublicC1InvoiceRoute{});
    }
};
}
int main() { return 0; }
''', encoding='utf-8')
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-pthread', '-I', str(HERE), '-c',
                str(source), '-o', str(directory / 'forgery.o'),
            ], capture_output=True, text=True, check=False)
            self.assertNotEqual(
                compiled.returncode, 0,
                'undefined lifecycle controller friend unexpectedly forged')

    def test_complete_c1_bridge_friend_cannot_be_redefined(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-c1-no-bridge-redefinition-') as directory:
            directory = Path(directory)
            source = directory / 'forgery.cpp'
            source.write_text(r'''
#include "c1_contact_value_authority.hpp"
#include <utility>
namespace kpb::measurement::c1_capture {
class C1ContactValueAuthorityBridge final {
public:
    static auto stage() {
        return C1LifecycleStagePlanAuthority(
            PublicC1LifecycleStagePlan{});
    }
    static auto route() {
        return C1InvoiceRouteAuthority(PublicC1InvoiceRoute{});
    }
    static auto offer() {
        return C1ContactValueOfferAuthority(-1);
    }
    static auto split(
            C1ContactValueOfferAuthority&& offer,
            C1PostcaptureAdmissionAuthority&& residual) {
        return C1ContactValueAuthoritySplit(
            std::move(offer), std::move(residual));
    }
};
}
int main() { return 0; }
''', encoding='utf-8')
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-pthread', '-I', str(HERE), '-c',
                str(source), '-o', str(directory / 'forgery.o'),
            ], capture_output=True, text=True, check=False)
            self.assertNotEqual(
                compiled.returncode, 0,
                'complete C1 bridge friend unexpectedly redefined')
            self.assertIn('redefinition', compiled.stderr)
            self.assertIn('C1ContactValueAuthorityBridge', compiled.stderr)

    def test_complete_observer_bridge_friend_cannot_be_redefined(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-c1-no-observer-redefinition-') as directory:
            directory = Path(directory)
            source = directory / 'forgery.cpp'
            source.write_text(r'''
#include "c1_contact_value_authority.hpp"
namespace kpb::measurement::runtime_bridge {
class ObserverCaptureCapsuleBridge final {
public:
    static auto residual() {
        return c1_capture::C1PostcaptureAdmissionAuthority(
            RunBinding{}, 1, 31, Digest{}, Digest{}, Digest{}, Digest{},
            Digest{}, Digest{}, Digest{}, WorkerBinding{},
            std::array<unsigned, 3>{}, std::array<Digest, 3>{});
    }
};
}
int main() { return 0; }
''', encoding='utf-8')
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-pthread', '-I', str(HERE), '-c',
                str(source), '-o', str(directory / 'forgery.o'),
            ], capture_output=True, text=True, check=False)
            self.assertNotEqual(
                compiled.returncode, 0,
                'complete observer bridge friend unexpectedly redefined')
            self.assertIn('redefinition', compiled.stderr)
            self.assertIn('ObserverCaptureCapsuleBridge', compiled.stderr)


if __name__ == '__main__':
    unittest.main()
