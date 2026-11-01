#!/usr/bin/env python3
"""Controls for the isolated transactional owner-replay core."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class FreshOwnerTransactionalReplayControls(unittest.TestCase):
    def compile(self, output, *sources, test_setup=False, sanitize=False):
        command = [
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread',
        ]
        if test_setup:
            command.append(
                '-DKPB_FRESH_OWNER_TRANSACTIONAL_REPLAY_TEST_SETUP')
        if sanitize:
            command.extend([
                '-g', '-O1', '-fno-omit-frame-pointer',
                '-fsanitize=address,undefined',
            ])
        command.extend(str(source) for source in sources)
        command.extend(['-I', str(HERE), '-o', str(output)])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def test_prepare_commit_and_adversarial_dispositions_are_fail_closed(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-fresh-owner-transactional-replay-') as raw:
            binary = Path(raw) / 'control'
            compiled = self.compile(
                binary,
                HERE /
                    'privacy_fresh_owner_transactional_replay_control.cpp',
                HERE /
                    'privacy_fresh_owner_transactional_replay_authority.cpp',
                test_setup=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=20)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_control_is_asan_ubsan_clean(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-fresh-owner-transactional-replay-san-') as raw:
            binary = Path(raw) / 'control'
            compiled = self.compile(
                binary,
                HERE /
                    'privacy_fresh_owner_transactional_replay_control.cpp',
                HERE /
                    'privacy_fresh_owner_transactional_replay_authority.cpp',
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
                prefix='kpb-fresh-owner-transactional-replay-surface-') as raw:
            root = Path(raw)
            source = root / 'surface.cpp'
            source.write_text(r'''
#include "privacy_fresh_owner_transactional_replay_authority.hpp"
#include <concepts>
using namespace kpb::measurement::fresh_owner_transactional_replay;
using PrepareSignature = FreshOwnerReplayPrepareAuthority (*)(
    SelectedOwnerReplayRegistryAuthority&&,
    const ExactOwnerReplaySet&);
using CommitSignature = FreshOwnerReplayOutcomeAuthority (*)(
    FreshOwnerReplayPrepareAuthority&&) noexcept;
template<class T> concept HasTestMint = requires {
    T::test_only_mint(nullptr);
};
template<class T> concept HasReceipt = requires(const T& value) {
    value.public_receipt();
};
template<class T> concept HasIdentities = requires(const T& value) {
    value.identities();
};
template<class T> concept HasCommitted = requires(const T& value) {
    value.committed();
};
template<class T> concept HasUnavailable = requires(const T& value) {
    value.unavailable();
};
template<class T> concept HasState = requires(const T& value) {
    value.state();
};
template<class T> concept HasTransfer = requires(T&& value) {
    static_cast<T&&>(value).transfer_for_transactional_issuance();
};
template<class T> concept HasRegistryIdentity = requires(const T& value) {
    value.registry_identity_for_transactional_issuance();
};
template<class T> concept HasReplayPolicyIdentity =
    requires(const T& value) {
        value.replay_policy_identity_for_transactional_issuance();
    };
template<class T> concept HasPrepareRegistryIdentity =
    requires(const T& value) {
        value.registry_identity_for_transactional_prepare();
    };
template<class T> concept HasPrepareReplayPolicyIdentity =
    requires(const T& value) {
        value.replay_policy_identity_for_transactional_prepare();
    };
static_assert(!std::copy_constructible<
    SelectedOwnerReplayRegistryAuthority>);
static_assert(std::move_constructible<
    SelectedOwnerReplayRegistryAuthority>);
static_assert(!std::default_initializable<
    SelectedOwnerReplayRegistryAuthority>);
static_assert(!std::copy_constructible<FreshOwnerReplayPrepareAuthority>);
static_assert(std::move_constructible<FreshOwnerReplayPrepareAuthority>);
static_assert(!std::default_initializable<FreshOwnerReplayPrepareAuthority>);
static_assert(!std::copy_constructible<FreshOwnerReplayOutcomeAuthority>);
static_assert(std::move_constructible<FreshOwnerReplayOutcomeAuthority>);
static_assert(!std::default_initializable<FreshOwnerReplayOutcomeAuthority>);
static_assert(!std::copy_constructible<FreshOwnerReplayOutcomeTransfer>);
static_assert(std::move_constructible<FreshOwnerReplayOutcomeTransfer>);
static_assert(!std::default_initializable<FreshOwnerReplayOutcomeTransfer>);
static_assert(EXACT_OWNER_REPLAY_IDENTITY_COUNT == 56);
static_assert(!HasTestMint<SelectedOwnerReplayRegistryAuthority>);
static_assert(!HasReceipt<FreshOwnerReplayOutcomeAuthority>);
static_assert(!HasIdentities<FreshOwnerReplayOutcomeAuthority>);
static_assert(!HasCommitted<FreshOwnerReplayOutcomeAuthority>);
static_assert(!HasUnavailable<FreshOwnerReplayOutcomeAuthority>);
static_assert(!HasState<FreshOwnerReplayOutcomeAuthority>);
static_assert(!HasTransfer<FreshOwnerReplayOutcomeAuthority>);
static_assert(!HasReceipt<FreshOwnerReplayOutcomeTransfer>);
static_assert(!HasIdentities<FreshOwnerReplayOutcomeTransfer>);
static_assert(!HasCommitted<FreshOwnerReplayOutcomeTransfer>);
static_assert(!HasUnavailable<FreshOwnerReplayOutcomeTransfer>);
static_assert(!HasState<FreshOwnerReplayOutcomeTransfer>);
static_assert(!HasRegistryIdentity<FreshOwnerReplayOutcomeTransfer>);
static_assert(!HasReplayPolicyIdentity<FreshOwnerReplayOutcomeTransfer>);
static_assert(!HasPrepareRegistryIdentity<
    SelectedOwnerReplayRegistryAuthority>);
static_assert(!HasPrepareReplayPolicyIdentity<
    SelectedOwnerReplayRegistryAuthority>);
static_assert(std::same_as<
    decltype(&FreshOwnerTransactionalReplayBridge::prepare),
    PrepareSignature>);
static_assert(std::same_as<
    decltype(&FreshOwnerTransactionalReplayBridge::commit_after_claim),
    CommitSignature>);
static_assert(kFreshOwnerTransactionalReplaySourceStatus
    .transactional_registry_core);
static_assert(kFreshOwnerTransactionalReplaySourceStatus
    .prepare_before_claim_core);
static_assert(kFreshOwnerTransactionalReplaySourceStatus
    .preallocated_commit_outcome_core);
static_assert(kFreshOwnerTransactionalReplaySourceStatus
    .noexcept_commit_core);
static_assert(kFreshOwnerTransactionalReplaySourceStatus
    .typed_unavailable_core);
static_assert(!kFreshOwnerTransactionalReplaySourceStatus
    .source_owned_registry);
static_assert(!kFreshOwnerTransactionalReplaySourceStatus
    .ready_three_owner_verifier_join);
static_assert(!kFreshOwnerTransactionalReplaySourceStatus
    .fresh_owner_result_factory);
static_assert(!kFreshOwnerTransactionalReplaySourceStatus
    .composite_stop_retains_all_inputs);
static_assert(!kFreshOwnerTransactionalReplaySourceStatus.selected_callsite);
static_assert(!kFreshOwnerTransactionalReplaySourceStatus.configured);
int main() {}
''', encoding='utf-8')
            compiled = self.compile(root / 'surface', source)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

    def test_complete_contract_name_and_pinned_methods_cannot_be_replaced(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-fresh-owner-transactional-replay-contract-') as raw:
            root = Path(raw)
            hostile = root / 'hostile.cpp'
            hostile.write_text(r'''
#include "privacy_fresh_owner_transactional_replay_contract.hpp"
namespace kpb::measurement::fresh_owner_transactional_replay {
class FreshOwnerTransactionalReplayBridge final {};
}
int main() {}
''', encoding='utf-8')
            compiled = self.compile(root / 'hostile', hostile)
            self.assertNotEqual(compiled.returncode, 0)
            self.assertIn('redefinition', compiled.stderr)

            issuance_hostile = root / 'issuance_hostile.cpp'
            issuance_hostile.write_text(r'''
#include "privacy_fresh_owner_transactional_issuance_contract.hpp"
namespace kpi::mpc::financial::fresh_owner_issuance {
class FreshOwnerTransactionalIssuanceBridge final {};
}
int main() {}
''', encoding='utf-8')
            compiled = self.compile(root / 'issuance_hostile',
                                    issuance_hostile)
            self.assertNotEqual(compiled.returncode, 0)
            self.assertIn('redefinition', compiled.stderr)

            alternate = root / 'alternate.cpp'
            alternate.write_text(r'''
#include "privacy_fresh_owner_transactional_replay_authority.hpp"
namespace kpb::measurement::fresh_owner_transactional_replay {
FreshOwnerReplayOutcomeAuthority
FreshOwnerTransactionalReplayBridge::commit_after_claim(
        FreshOwnerReplayPrepareAuthority&&) noexcept {
    __builtin_trap();
}
}
''', encoding='utf-8')
            pinned = root / 'pinned.o'
            alt = root / 'alternate.o'
            main = root / 'main.cpp'
            main.write_text('int main() {}\n', encoding='utf-8')
            for output, source in (
                    (pinned, HERE /
                        'privacy_fresh_owner_transactional_replay_authority.cpp'),
                    (alt, alternate)):
                result = subprocess.run([
                    'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                    '-pedantic', '-I', str(HERE), '-c', str(source),
                    '-o', str(output),
                ], capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)
            linked = subprocess.run([
                'g++', str(main), str(pinned), str(alt),
                '-o', str(root / 'duplicate'),
            ], capture_output=True, text=True, check=False)
            self.assertNotEqual(linked.returncode, 0)
            self.assertIn('multiple definition', linked.stderr)


if __name__ == '__main__':
    unittest.main()
