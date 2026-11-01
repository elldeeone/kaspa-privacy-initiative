#!/usr/bin/env python3
"""Compile controls for the complete all-branch owner friend contract."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class AllBranchFreshTrialOwnerContractControls(unittest.TestCase):
    def compile(self, name, source):
        with tempfile.TemporaryDirectory(
                prefix='kpb-all-branch-owner-contract-') as raw:
            root = Path(raw)
            path = root / f'{name}.cpp'
            path.write_text(source, encoding='utf-8')
            return subprocess.run([
                'c++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-I', str(HERE), '-fsyntax-only', str(path),
            ], capture_output=True, text=True, check=False)

    def test_contract_is_complete_and_exact_name_cannot_be_redefined(self):
        valid = self.compile('valid', r'''
#include "privacy_all_branch_fresh_trial_owner_contract.hpp"
#include <concepts>
#include <type_traits>
using kpb::measurement::fresh_trial_owner::
    AllBranchFreshTrialOwnerBridge;
using ActivationStopSignature =
    kpb::measurement::fresh_trial_owner::AllBranchFreshTrialStepAuthority (*)(
        kpb::measurement::fresh_trial_owner::
            AllBranchFreshTrialOwnerAuthority&&,
        kpi::mpc::financial::registered_driver::
            RegisteredPersistentRoleActivationFailureResidual&&);
static_assert(std::is_class_v<AllBranchFreshTrialOwnerBridge>);
static_assert(std::same_as<
    decltype(&AllBranchFreshTrialOwnerBridge::stop_after_activation_failure),
    ActivationStopSignature>);
int main() {}
''')
        self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)

        for name, source in {
            'before': r'''
namespace kpb::measurement::fresh_trial_owner {
class AllBranchFreshTrialOwnerBridge final {};
}
#include "privacy_all_branch_fresh_trial_owner_contract.hpp"
''',
            'after': r'''
#include "privacy_all_branch_fresh_trial_owner_contract.hpp"
namespace kpb::measurement::fresh_trial_owner {
class AllBranchFreshTrialOwnerBridge final {};
}
''',
        }.items():
            with self.subTest(name=name):
                hostile = self.compile(name, source + '\nint main() {}\n')
                self.assertNotEqual(hostile.returncode, 0)
                self.assertIn('redefinition', hostile.stderr)

    def test_contract_has_no_receipt_digest_fd_or_boolean_overload(self):
        source = (HERE /
            'privacy_all_branch_fresh_trial_owner_contract.hpp'
        ).read_text(encoding='utf-8')
        for forbidden in (
                'public_receipt', 'Digest', ' int ', ' bool ',
                'std::span', 'std::string'):
            self.assertNotIn(forbidden, source)
        self.assertIn('AllBranchFreshTrialOwnerAuthority&&', source)
        self.assertIn(
            'RegisteredAttemptHistoryAppendOutcomeAuthority&&', source)
        self.assertIn(
            'RegisteredPersistentRoleActivationFailureResidual&&', source)


if __name__ == '__main__':
    unittest.main()
