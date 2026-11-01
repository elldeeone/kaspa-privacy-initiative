#!/usr/bin/env python3
"""Controls for the private producer-to-observer spool capability."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class ProducerSpoolAuthorityControls(unittest.TestCase):
    def compile(self, output, *sources, test_setup=False):
        command = [
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread',
        ]
        if test_setup:
            command.append('-DKPB_CAPTURE_PRODUCER_SUPERVISOR_TEST_SETUP')
        command.extend(str(source) for source in sources)
        command.extend(['-I', str(HERE), '-lcrypto', '-o', str(output)])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def test_move_only_private_spool_capability(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-producer-spool-authority-') as directory:
            binary = Path(directory) / 'control'
            compiled = self.compile(
                binary,
                HERE / 'privacy_capture_producer_supervisor_control.cpp',
                HERE / 'privacy_capture_producer_supervisor.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp',
                test_setup=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=10)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_production_has_no_spool_minter_or_fd_accessor(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-producer-spool-production-') as directory:
            directory = Path(directory)
            source = directory / 'production.cpp'
            source.write_text(r'''
#include "privacy_capture_producer_supervisor.hpp"
#include <type_traits>
using namespace kpb::measurement::producer_supervisor;
static_assert(!std::is_copy_constructible_v<ProducerSpoolAuthority>);
static_assert(!std::is_copy_assignable_v<ProducerSpoolAuthority>);
static_assert(!std::is_copy_constructible_v<C03RoleLaunchAdmissionAuthority>);
static_assert(std::is_move_constructible_v<C03RoleLaunchAdmissionAuthority>);
static_assert(!std::is_constructible_v<
    ProducerSpoolAuthority, kpb::measurement::RunBinding,
    kpb::measurement::Digest, kpb::measurement::Digest, int>);
static_assert(kProducerSupervisorSourceStatus.move_only_spool_authority);
static_assert(kProducerSupervisorSourceStatus.private_directory_capability);
static_assert(kProducerSupervisorSourceStatus.observer_only_consumer);
static_assert(kProducerSupervisorSourceStatus.writer_alias_closure_bound);
static_assert(kProducerSupervisorSourceStatus.finite_ten_leaf_manifest_bound);
static_assert(kProducerSupervisorSourceStatus.c03_role_launch_admission);
static_assert(!kProducerSupervisorSourceStatus.authenticated_exec_supervisor);
static_assert(!kProducerSupervisorSourceStatus.python_runtime_closure_sealed);
static_assert(!kProducerSupervisorSourceStatus.selected_main);
static_assert(!kProducerSupervisorSourceStatus.actual_launch_enabled);
int main() { return 0; }
''', encoding='utf-8')
            binary = directory / 'production'
            compiled = self.compile(
                binary, source,
                HERE / 'privacy_capture_producer_supervisor.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp')
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            symbols = subprocess.run(
                ['nm', '-C', str(binary)], capture_output=True, text=True,
                check=False, timeout=10)
            self.assertEqual(symbols.returncode, 0,
                             symbols.stdout + symbols.stderr)
            self.assertNotIn('test_only_mint', symbols.stdout)
            self.assertNotIn('test_only_take_directory', symbols.stdout)

    def test_test_bridge_does_not_compile_in_production(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-producer-spool-no-test-bridge-') as directory:
            directory = Path(directory)
            source = directory / 'forbidden.cpp'
            source.write_text(r'''
#include "privacy_capture_producer_supervisor.hpp"
using namespace kpb::measurement::producer_supervisor;
int main() {
    kpb::measurement::RunBinding binding{};
    kpb::measurement::Digest receipt{};
    auto value = ProducerSpoolAuthority::test_only_mint(
        binding, receipt, receipt, -1);
    (void)value;
}
''', encoding='utf-8')
            compiled = self.compile(
                directory / 'forbidden', source,
                HERE / 'privacy_capture_producer_supervisor.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp')
            self.assertNotEqual(compiled.returncode, 0,
                                'test-only spool mint unexpectedly compiled')
            self.assertIn('test_only_mint', compiled.stderr)

    def test_lookalike_cannot_define_the_spool_friend(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-producer-spool-no-lookalike-') as directory:
            directory = Path(directory)
            source = directory / 'lookalike.cpp'
            source.write_text(r'''
#include "privacy_capture_producer_supervisor.hpp"
namespace kpb::measurement::runtime_bridge {
class MeasurementChildSupervisor final {
public:
    static int steal(
        producer_supervisor::ProducerSpoolAuthority&& authority) {
        return authority.directory_fd_;
    }
};
}
int main() { return 0; }
''', encoding='utf-8')
            compiled = self.compile(
                directory / 'lookalike', source,
                HERE / 'privacy_capture_producer_supervisor.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp')
            self.assertNotEqual(compiled.returncode, 0,
                                'lookalike spool friend unexpectedly compiled')
            self.assertIn('redefinition', compiled.stderr)

    def test_undefined_parent_supervisor_friend_cannot_be_defined(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-producer-spool-no-parent-forgery-') as directory:
            directory = Path(directory)
            source = directory / 'forgery.cpp'
            source.write_text(r'''
#include "privacy_capture_producer_supervisor.hpp"
namespace kpb::measurement::producer_supervisor {
class ParentOwnedProducerCapsuleSupervisor final {
public:
    static auto spool() {
        return ProducerSpoolAuthority(
            RunBinding{}, Digest{}, Digest{}, Digest{}, Digest{}, Digest{},
            ProducerClosureEvidence{}, -1);
    }
    static auto c03() {
        return C03RoleLaunchAdmissionAuthority(
            RunBinding{}, Digest{}, Digest{}, Digest{}, Digest{},
            std::array<C03RoleLaunchRoundBinding, 2>{});
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
                'undefined parent supervisor friend unexpectedly forged')


if __name__ == '__main__':
    unittest.main()
