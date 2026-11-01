#!/usr/bin/env python3
"""Fail-closed Round-1 attempt outcome consumer contract controls."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
MPC = HERE.parent / 'mpc-prover'
VENDOR = MPC.parents[2] / '.local' / 'mpc-prover-vendor' / 'MP-SPDZ'
PREFIX = VENDOR.parent / 'prefix' / 'usr' / 'include'


class FreshOwnerRound1OutcomeConsumerControls(unittest.TestCase):
    def compile(self, output, *sources, extra=()):
        command = [
            'c++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-Wno-overloaded-virtual', '-march=native',
            '-I', str(HERE), '-I', str(MPC), '-I', str(VENDOR),
            '-I', str(PREFIX), '-I', str(PREFIX / 'x86_64-linux-gnu'),
            *extra,
        ]
        command.extend(str(source) for source in sources)
        command.extend(['-o', str(output)])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def test_contract_signature_is_exact_and_complete(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-round1-consumer-contract-') as raw:
            root = Path(raw)
            valid = root / 'valid.cpp'
            valid.write_text(r'''
#include "privacy_fresh_owner_round1_outcome_consumer_contract.hpp"
#include <concepts>
#include <type_traits>
using namespace kpb::measurement::fresh_trial_owner;
using Source = kpi::mpc::financial::fresh_owner_issuance::
    FreshOwnerRound1AttemptOutcomeAuthority;
using Signature = FreshOwnerRound1AttemptStepAuthority (*)(
    AllBranchFreshTrialOwnerAuthority&&, Source&&);
static_assert(std::is_class_v<FreshOwnerRound1AttemptConsumerBridge>);
static_assert(std::same_as<
    decltype(&FreshOwnerRound1AttemptConsumerBridge::append), Signature>);
int main() {}
''', encoding='utf-8')
            compiled = self.compile(root / 'valid.o', valid, extra=('-c',))
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            for order in ('before', 'after'):
                hostile = root / f'{order}.cpp'
                fake = r'''
namespace kpb::measurement::fresh_trial_owner {
class FreshOwnerRound1AttemptConsumerBridge final {};
}
'''
                include = (
                    '#include '
                    '"privacy_fresh_owner_round1_outcome_consumer_contract.hpp"\n')
                hostile.write_text(
                    (fake + include if order == 'before'
                     else include + fake) + 'int main() {}\n',
                    encoding='utf-8')
                refused = self.compile(
                    root / f'{order}.o', hostile, extra=('-c',))
                self.assertNotEqual(refused.returncode, 0)

    def test_step_is_opaque_move_only_and_unfinished_statuses_stay_false(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-round1-consumer-surface-') as raw:
            root = Path(raw)
            source = root / 'surface.cpp'
            source.write_text(r'''
#include "privacy_fresh_owner_round1_outcome_consumer_authority.hpp"
#include <concepts>
using namespace kpb::measurement::fresh_trial_owner;
template<class T> concept HasReceipt = requires(const T& value) {
    value.public_receipt();
};
template<class T> concept HasState = requires(const T& value) {
    value.state();
};
template<class T> concept HasSuccess = requires(T&& value) {
    static_cast<T&&>(value).take_success();
};
template<class T> concept HasStop = requires(T&& value) {
    static_cast<T&&>(value).take_stop();
};
template<class T> concept HasTestMint = requires { T::test_only_mint(); };
static_assert(!std::default_initializable<
    FreshOwnerRound1AttemptStepAuthority>);
static_assert(!std::copy_constructible<
    FreshOwnerRound1AttemptStepAuthority>);
static_assert(std::move_constructible<
    FreshOwnerRound1AttemptStepAuthority>);
static_assert(!HasReceipt<FreshOwnerRound1AttemptStepAuthority>);
static_assert(!HasState<FreshOwnerRound1AttemptStepAuthority>);
static_assert(!HasSuccess<FreshOwnerRound1AttemptStepAuthority>);
static_assert(!HasStop<FreshOwnerRound1AttemptStepAuthority>);
static_assert(!HasTestMint<FreshOwnerRound1AttemptStepAuthority>);
static_assert(kFreshOwnerRound1OutcomeConsumerSourceStatus
    .complete_neutral_contract);
static_assert(kFreshOwnerRound1OutcomeConsumerSourceStatus
    .opaque_indivisible_step);
static_assert(kFreshOwnerRound1OutcomeConsumerSourceStatus
    .fresh_owner_friend_grant);
static_assert(kFreshOwnerRound1OutcomeConsumerSourceStatus
    .atomic_outcome_claim);
static_assert(kFreshOwnerRound1OutcomeConsumerSourceStatus
    .success_continuation_retained);
static_assert(kFreshOwnerRound1OutcomeConsumerSourceStatus
    .stop_outcome_retained);
static_assert(!kFreshOwnerRound1OutcomeConsumerSourceStatus
    .mandatory_durable_sink);
static_assert(kFreshOwnerRound1OutcomeConsumerSourceStatus
    .selected_callsite);
static_assert(!kFreshOwnerRound1OutcomeConsumerSourceStatus.configured);
int main() {}
''', encoding='utf-8')
            compiled = self.compile(
                root / 'surface.o', source, extra=('-c',))
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

    def test_official_definition_pins_the_only_member_symbol(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-round1-consumer-link-') as raw:
            root = Path(raw)
            official = root / 'official.o'
            compiled = self.compile(
                official,
                HERE /
                    'privacy_fresh_owner_round1_outcome_consumer_authority.cpp',
                extra=('-c',))
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            hostile_source = root / 'hostile.cpp'
            hostile_source.write_text(r'''
#include "privacy_fresh_owner_round1_outcome_consumer_authority.hpp"
namespace kpb::measurement::fresh_trial_owner {
FreshOwnerRound1AttemptStepAuthority
FreshOwnerRound1AttemptConsumerBridge::append(
        AllBranchFreshTrialOwnerAuthority&&,
        kpi::mpc::financial::fresh_owner_issuance::
            FreshOwnerRound1AttemptOutcomeAuthority&&) {
    throw 1;
}
}
''', encoding='utf-8')
            hostile = root / 'hostile.o'
            hostile_compile = self.compile(
                hostile, hostile_source, extra=('-c',))
            self.assertEqual(hostile_compile.returncode, 0,
                             hostile_compile.stdout +
                             hostile_compile.stderr)
            linked = subprocess.run([
                'c++', '-r', str(official), str(hostile),
                '-o', str(root / 'combined.o'),
            ], capture_output=True, text=True, check=False)
            self.assertNotEqual(linked.returncode, 0)
            self.assertIn('multiple definition', linked.stderr)

    def test_contract_has_no_public_value_or_arm_overload(self):
        source = (HERE /
            'privacy_fresh_owner_round1_outcome_consumer_contract.hpp'
        ).read_text(encoding='utf-8')
        for forbidden in (
                'public_receipt', 'Digest', 'std::string', 'std::span',
                ' bool ', ' int ', 'take_success', 'take_stop'):
            self.assertNotIn(forbidden, source)
        self.assertIn('AllBranchFreshTrialOwnerAuthority&&', source)
        self.assertIn('FreshOwnerRound1AttemptOutcomeAuthority&&', source)
        self.assertIn('FreshOwnerRound1AttemptStepAuthority', source)

    def test_append_claims_both_arms_without_post_outcome_allocation(self):
        source = (HERE /
            'privacy_fresh_owner_round1_outcome_consumer_authority.cpp'
        ).read_text(encoding='utf-8')
        append = source[source.index(
            'FreshOwnerRound1AttemptConsumerBridge::append('):]
        for forbidden in ('make_unique', 'make_shared', 'operator new'):
            self.assertNotIn(forbidden, append)
        for required in (
                'std::is_nothrow_move_constructible_v<',
                'noexcept(std::declval<std::optional<',
                'FreshOwnerRound1AttemptStepAuthority result(',
                'std::move(supplied_owner)',
                'std::move(supplied_outcome)',
                'valid_for_outer_consumer()'):
            self.assertIn(required, append)


if __name__ == '__main__':
    unittest.main()
