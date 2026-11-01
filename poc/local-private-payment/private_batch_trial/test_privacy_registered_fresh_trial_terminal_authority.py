#!/usr/bin/env python3
"""Whole-fresh-trial terminal-history authority controls."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent / 'mpc-prover' / 'financial'
SOURCES = (
    HERE / 'privacy_registered_fresh_trial_terminal_control.cpp',
    HERE / 'privacy_registered_fresh_trial_terminal_authority.cpp',
    HERE / 'privacy_registered_fresh_trial_terminal_bridge.cpp',
    HERE / 'privacy_measurement_authority.cpp',
    FINANCIAL / 'registered_driver_bridge.cpp',
    FINANCIAL / 'registered_identity_registry.cpp',
    FINANCIAL / 'registered_persistent_role_exit_history.cpp',
    FINANCIAL / 'registered_trial_attempt_history.cpp',
    FINANCIAL / 'registered_fresh_trial_history_ledger.cpp',
)


class RegisteredFreshTrialTerminalControls(unittest.TestCase):
    def compile(self, output, *sources, test_setup=False, sanitize=False):
        command = [
            'c++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread', '-ffunction-sections',
            '-fdata-sections', '-I', str(HERE),
            '-I', str(FINANCIAL),
        ]
        if test_setup:
            command.extend([
                '-DKPB_REGISTERED_FRESH_TRIAL_TERMINAL_TEST_SETUP',
                '-DKPI_REGISTERED_ATTEMPT_HISTORY_TEST_SETUP',
            ])
        if sanitize:
            command.extend([
                '-fsanitize=address,undefined',
                # This focused closure links only the two pure UUID identity
                # methods from registered_driver_bridge.cpp. UBSan vptr emits
                # typeinfo references for unrelated discarded driver classes;
                # all exercised terminal code remains under ASan and the
                # remaining undefined-behaviour checks.
                '-fno-sanitize=vptr',
                '-fno-omit-frame-pointer',
            ])
        command.extend(str(source) for source in sources)
        command.extend(['-Wl,--gc-sections', '-lcrypto', '-o', str(output)])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def run_control(self, binary, *, sanitize=False):
        environment = os.environ.copy()
        if sanitize:
            environment['ASAN_OPTIONS'] = (
                'detect_leaks=1:halt_on_error=1:abort_on_error=1')
            environment['UBSAN_OPTIONS'] = (
                'halt_on_error=1:print_stacktrace=1')
        return subprocess.run([str(binary)], capture_output=True,
                              text=True, check=False, timeout=30,
                              env=environment)

    def test_linear_unbounded_ledger_consumer_is_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix='kpb-fresh-terminal-') as raw:
            binary = Path(raw) / 'control'
            compiled = self.compile(binary, *SOURCES, test_setup=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = self.run_control(binary)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_control_is_asan_ubsan_clean(self):
        with tempfile.TemporaryDirectory(prefix='kpb-fresh-terminal-san-') as raw:
            binary = Path(raw) / 'control'
            compiled = self.compile(binary, *SOURCES, test_setup=True,
                                    sanitize=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = self.run_control(binary, sanitize=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_production_has_no_fd_digest_or_legacy_v1_factory(self):
        with tempfile.TemporaryDirectory(prefix='kpb-fresh-terminal-prod-') as raw:
            root = Path(raw)
            source = root / 'forbidden.cpp'
            source.write_text(r'''
#include "privacy_registered_fresh_trial_terminal_authority.hpp"
using namespace kpb::measurement::empirical_result;
template<class T> concept FdFactory = requires(int fd) { T(fd); };
template<class T> concept DigestFactory = requires(kpb::measurement::Digest d) {
    T(d);
};
template<class T> concept TestAccept = requires {
    &T::test_only_accept_storage;
};
static_assert(!FdFactory<RegisteredFreshTrialTerminalHistoryAuthority>);
static_assert(!DigestFactory<RegisteredFreshTrialTerminalHistoryAuthority>);
static_assert(!TestAccept<RegisteredTerminalAttemptHistoryJoiner>);
int main() {}
''', encoding='utf-8')
            compiled = self.compile(root / 'forbidden', source)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

    def test_exact_registered_consumer_name_cannot_be_redefined(self):
        with tempfile.TemporaryDirectory(prefix='kpb-fresh-terminal-hostile-') as raw:
            root = Path(raw)
            for name, source_text in {
                'before': r'''
namespace kpi::mpc::financial::registered_driver::attempt_history {
class RegisteredTrialAttemptHistoryTerminalBridge final {};
}
#include "privacy_registered_fresh_trial_terminal_authority.hpp"
''',
                'after': r'''
#include "privacy_registered_fresh_trial_terminal_authority.hpp"
namespace kpi::mpc::financial::registered_driver::attempt_history {
class RegisteredTrialAttemptHistoryTerminalBridge final {};
}
''',
            }.items():
                with self.subTest(name=name):
                    source = root / f'{name}.cpp'
                    source.write_text(source_text + '\nint main() {}\n',
                                      encoding='utf-8')
                    compiled = subprocess.run([
                        'c++', '-std=c++20', '-I', str(HERE),
                        '-I', str(FINANCIAL), '-fsyntax-only', str(source),
                    ], capture_output=True, text=True, check=False)
                    self.assertNotEqual(compiled.returncode, 0,
                                        'hostile exact consumer compiled')


if __name__ == '__main__':
    unittest.main()
