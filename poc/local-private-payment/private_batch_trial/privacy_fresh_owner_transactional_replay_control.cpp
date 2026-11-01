#include "privacy_fresh_owner_transactional_replay_authority.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <new>
#include <stdexcept>
#include <thread>
#include <utility>

namespace {

std::atomic_bool fail_allocations{false};

[[noreturn]] void fail() { std::abort(); }
void need(bool value) { if (!value) fail(); }

} // namespace

void* operator new(std::size_t size) {
    if (fail_allocations.load()) throw std::bad_alloc();
    if (void* result = std::malloc(size == 0 ? 1 : size)) return result;
    throw std::bad_alloc();
}
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete(void* value) noexcept { std::free(value); }
void operator delete[](void* value) noexcept { std::free(value); }
void operator delete(void* value, std::size_t) noexcept { std::free(value); }
void operator delete[](void* value, std::size_t) noexcept {
    std::free(value);
}

namespace kpb::measurement::fresh_owner_transactional_replay {
namespace {

enum class Behavior : unsigned char {
    Atomic,
    InfrastructureUnavailable,
    AmbiguousAfterWrite,
    InvalidDisposition,
    ThrowOnPrepare,
    NullPrepare,
};

class FakeRegistry;

class FakePrepared final : public OwnerReplayPreparedOperation {
    std::shared_ptr<FakeRegistry> registry_;
    ExactOwnerReplaySet identities_{};
    Behavior behavior_;
public:
    FakePrepared(
        std::shared_ptr<FakeRegistry>,
        const ExactOwnerReplaySet&,
        Behavior);
    OwnerReplayBackendCommitDisposition commit_prepared() noexcept override;
};

class FakeRegistry final :
        public TransactionalOwnerReplayRegistry,
        public std::enable_shared_from_this<FakeRegistry> {
    friend class FakePrepared;
    std::mutex mutex_;
    std::array<ReplayIdentity, EXACT_OWNER_REPLAY_IDENTITY_COUNT * 4>
        committed_{};
    std::size_t committed_count_{};
public:
    Behavior behavior{Behavior::Atomic};
    unsigned prepare_calls{};
    unsigned commit_calls{};

    std::unique_ptr<OwnerReplayPreparedOperation> prepare(
            const ExactOwnerReplaySet& identities) override {
        ++prepare_calls;
        if (behavior == Behavior::ThrowOnPrepare)
            throw std::runtime_error("prepare fault");
        if (behavior == Behavior::NullPrepare) return nullptr;
        return std::make_unique<FakePrepared>(
            shared_from_this(), identities, behavior);
    }
};

FakePrepared::FakePrepared(
        std::shared_ptr<FakeRegistry> registry,
        const ExactOwnerReplaySet& identities,
        Behavior behavior)
    : registry_(std::move(registry)), identities_(identities),
      behavior_(behavior) {}

OwnerReplayBackendCommitDisposition
FakePrepared::commit_prepared() noexcept {
    std::scoped_lock lock(registry_->mutex_);
    ++registry_->commit_calls;
    if (behavior_ == Behavior::InfrastructureUnavailable)
        return OwnerReplayBackendCommitDisposition::
            InfrastructureUnavailable;
    if (behavior_ == Behavior::InvalidDisposition)
        return static_cast<OwnerReplayBackendCommitDisposition>(0xff);

    bool overlap{};
    for (const auto& candidate : identities_)
        for (std::size_t index = 0;
             index < registry_->committed_count_; ++index)
            overlap = overlap || candidate == registry_->committed_[index];
    if (overlap)
        return OwnerReplayBackendCommitDisposition::ReplayOrConflict;

    if (registry_->committed_count_ + identities_.size() >
        registry_->committed_.size())
        return OwnerReplayBackendCommitDisposition::
            InfrastructureUnavailable;
    for (const auto& value : identities_)
        registry_->committed_[registry_->committed_count_++] = value;

    if (behavior_ == Behavior::AmbiguousAfterWrite)
        return OwnerReplayBackendCommitDisposition::AmbiguousAfterWrite;
    return OwnerReplayBackendCommitDisposition::Committed;
}

ReplayIdentity identity(unsigned value) {
    ReplayIdentity result{};
    result[0] = static_cast<unsigned char>((value >> 8) & 0xff);
    result[1] = static_cast<unsigned char>(value & 0xff);
    result[31] = 0xa5;
    return result;
}

ExactOwnerReplaySet identities(unsigned base = 1) {
    ExactOwnerReplaySet result{};
    for (std::size_t index = 0; index < result.size(); ++index)
        result[index] = identity(base + static_cast<unsigned>(index));
    return result;
}

ReplayIdentity selected_registry_authority_identity() {
    return identity(60'000);
}

ReplayIdentity selected_replay_policy_identity() {
    return identity(60'001);
}

using TestBridge = FreshOwnerTransactionalReplayTestBridge;

template<class Outcome>
void expect(
        const Outcome& outcome,
        TestFreshOwnerReplayOutcome expected) {
    need(TestBridge::inspect(outcome) == expected);
}

template<class Outcome>
void expect_disposition(
        const Outcome& outcome,
        TestFreshOwnerReplayDisposition expected) {
    need(TestBridge::disposition(outcome) == expected);
}

FreshOwnerReplayPrepareAuthority prepare(
        const std::shared_ptr<FakeRegistry>& backend,
        const ExactOwnerReplaySet& values) {
    auto registry = TestBridge::mint_registry(
        backend, selected_registry_authority_identity(),
        selected_replay_policy_identity());
    return FreshOwnerTransactionalReplayBridge::prepare(
        std::move(registry), values);
}

void committed_without_commit_allocation() {
    auto backend = std::make_shared<FakeRegistry>();
    auto prepared = prepare(backend, identities());
    need(backend->prepare_calls == 1 && backend->commit_calls == 0);

    fail_allocations.store(true);
    auto outcome = FreshOwnerTransactionalReplayBridge::commit_after_claim(
        std::move(prepared));
    fail_allocations.store(false);
    expect(outcome, TestFreshOwnerReplayOutcome::Committed);

    fail_allocations.store(true);
    auto transfer = TestBridge::transfer(std::move(outcome));
    fail_allocations.store(false);
    expect(transfer, TestFreshOwnerReplayOutcome::Committed);
    expect_disposition(
        transfer, TestFreshOwnerReplayDisposition::Committed);
    need(TestBridge::registry_identity(transfer) ==
             selected_registry_authority_identity() &&
         TestBridge::replay_policy_identity(transfer) ==
             selected_replay_policy_identity());

    auto stale_transfer = TestBridge::transfer(std::move(outcome));
    expect(stale_transfer, TestFreshOwnerReplayOutcome::Unavailable);
    expect_disposition(
        stale_transfer,
        TestFreshOwnerReplayDisposition::StaleOrMissingPrepared);

    auto replay = FreshOwnerTransactionalReplayBridge::commit_after_claim(
        std::move(prepared));
    expect(replay, TestFreshOwnerReplayOutcome::Unavailable);
    expect_disposition(
        replay, TestFreshOwnerReplayDisposition::StaleOrMissingPrepared);
    need(backend->prepare_calls == 1 && backend->commit_calls == 1);
}

void prepare_failure_does_not_claim_registry() {
    auto backend = std::make_shared<FakeRegistry>();
    backend->behavior = Behavior::ThrowOnPrepare;
    auto registry = TestBridge::mint_registry(
        backend, selected_registry_authority_identity(),
        selected_replay_policy_identity());
    const auto values = identities();
    bool refused{};
    try {
        (void)FreshOwnerTransactionalReplayBridge::prepare(
            std::move(registry), values);
    } catch (...) { refused = true; }
    need(refused && backend->prepare_calls == 1);

    backend->behavior = Behavior::Atomic;
    auto prepared = FreshOwnerTransactionalReplayBridge::prepare(
        std::move(registry), values);
    auto outcome = FreshOwnerTransactionalReplayBridge::commit_after_claim(
        std::move(prepared));
    expect(outcome, TestFreshOwnerReplayOutcome::Committed);
    need(backend->prepare_calls == 2);
}

void invalid_identity_sets_do_not_claim_registry() {
    auto backend = std::make_shared<FakeRegistry>();
    auto registry = TestBridge::mint_registry(
        backend, selected_registry_authority_identity(),
        selected_replay_policy_identity());
    auto values = identities();
    values[2] = values[1];
    bool duplicate_refused{};
    try {
        (void)FreshOwnerTransactionalReplayBridge::prepare(
            std::move(registry), values);
    } catch (...) { duplicate_refused = true; }
    need(duplicate_refused && backend->prepare_calls == 0);

    values = identities();
    values[0] = ReplayIdentity{};
    bool zero_refused{};
    try {
        (void)FreshOwnerTransactionalReplayBridge::prepare(
            std::move(registry), values);
    } catch (...) { zero_refused = true; }
    need(zero_refused && backend->prepare_calls == 0);

    values = identities();
    values[0] = selected_registry_authority_identity();
    bool lineage_collision_refused{};
    try {
        (void)FreshOwnerTransactionalReplayBridge::prepare(
            std::move(registry), values);
    } catch (...) { lineage_collision_refused = true; }
    need(lineage_collision_refused && backend->prepare_calls == 0);

    values = identities();
    auto prepared = FreshOwnerTransactionalReplayBridge::prepare(
        std::move(registry), values);
    auto outcome = FreshOwnerTransactionalReplayBridge::commit_after_claim(
        std::move(prepared));
    expect(outcome, TestFreshOwnerReplayOutcome::Committed);
}

void invalid_registry_lineage_refuses_at_mint() {
    auto backend = std::make_shared<FakeRegistry>();
    bool zero_refused{};
    try {
        (void)TestBridge::mint_registry(
            backend, ReplayIdentity{}, selected_replay_policy_identity());
    } catch (...) { zero_refused = true; }
    need(zero_refused);

    bool equal_refused{};
    try {
        const auto same = selected_registry_authority_identity();
        (void)TestBridge::mint_registry(backend, same, same);
    } catch (...) { equal_refused = true; }
    need(equal_refused && backend->prepare_calls == 0);
}

void null_prepare_does_not_claim_registry() {
    auto backend = std::make_shared<FakeRegistry>();
    backend->behavior = Behavior::NullPrepare;
    auto registry = TestBridge::mint_registry(
        backend, selected_registry_authority_identity(),
        selected_replay_policy_identity());
    const auto values = identities();
    bool refused{};
    try {
        (void)FreshOwnerTransactionalReplayBridge::prepare(
            std::move(registry), values);
    } catch (...) { refused = true; }
    need(refused && backend->prepare_calls == 1);
    backend->behavior = Behavior::Atomic;
    auto prepared = FreshOwnerTransactionalReplayBridge::prepare(
        std::move(registry), values);
    auto outcome = FreshOwnerTransactionalReplayBridge::commit_after_claim(
        std::move(prepared));
    expect(outcome, TestFreshOwnerReplayOutcome::Committed);
}

void dropped_prepare_does_not_mutate_registry() {
    auto backend = std::make_shared<FakeRegistry>();
    {
        auto prepared = prepare(backend, identities());
        (void)prepared;
    }
    need(backend->prepare_calls == 1 && backend->commit_calls == 0);
    auto prepared = prepare(backend, identities());
    auto outcome = FreshOwnerTransactionalReplayBridge::commit_after_claim(
        std::move(prepared));
    expect(outcome, TestFreshOwnerReplayOutcome::Committed);
}

void same_set_concurrency_commits_exactly_once() {
    auto backend = std::make_shared<FakeRegistry>();
    const auto values = identities();
    auto first = prepare(backend, values);
    auto second = prepare(backend, values);
    TestFreshOwnerReplayOutcome results[2]{
        TestFreshOwnerReplayOutcome::Unavailable,
        TestFreshOwnerReplayOutcome::Unavailable,
    };
    std::thread a([&] {
        auto outcome =
            FreshOwnerTransactionalReplayBridge::commit_after_claim(
                std::move(first));
        results[0] = TestBridge::inspect(outcome);
    });
    std::thread b([&] {
        auto outcome =
            FreshOwnerTransactionalReplayBridge::commit_after_claim(
                std::move(second));
        results[1] = TestBridge::inspect(outcome);
    });
    a.join();
    b.join();
    need((results[0] == TestFreshOwnerReplayOutcome::Committed) !=
         (results[1] == TestFreshOwnerReplayOutcome::Committed));
    need(backend->commit_calls == 2);
}

void one_identity_overlap_refuses_whole_set() {
    auto backend = std::make_shared<FakeRegistry>();
    const auto first_values = identities(1);
    auto first = prepare(backend, first_values);
    auto first_outcome =
        FreshOwnerTransactionalReplayBridge::commit_after_claim(
            std::move(first));
    expect(first_outcome, TestFreshOwnerReplayOutcome::Committed);

    auto overlap = identities(1000);
    overlap[17] = first_values[31];
    auto second = prepare(backend, overlap);
    auto second_outcome =
        FreshOwnerTransactionalReplayBridge::commit_after_claim(
            std::move(second));
    expect(second_outcome, TestFreshOwnerReplayOutcome::Unavailable);
    expect_disposition(
        second_outcome,
        TestFreshOwnerReplayDisposition::ReplayOrConflict);
}

void unavailable_and_ambiguous_never_authorize() {
    auto unavailable_backend = std::make_shared<FakeRegistry>();
    unavailable_backend->behavior = Behavior::InfrastructureUnavailable;
    auto unavailable = prepare(unavailable_backend, identities());
    auto unavailable_outcome =
        FreshOwnerTransactionalReplayBridge::commit_after_claim(
            std::move(unavailable));
    expect(unavailable_outcome, TestFreshOwnerReplayOutcome::Unavailable);
    expect_disposition(
        unavailable_outcome,
        TestFreshOwnerReplayDisposition::InfrastructureUnavailable);

    auto invalid_backend = std::make_shared<FakeRegistry>();
    invalid_backend->behavior = Behavior::InvalidDisposition;
    auto invalid = prepare(invalid_backend, identities(500));
    auto invalid_outcome =
        FreshOwnerTransactionalReplayBridge::commit_after_claim(
            std::move(invalid));
    expect(invalid_outcome, TestFreshOwnerReplayOutcome::Unavailable);
    expect_disposition(
        invalid_outcome,
        TestFreshOwnerReplayDisposition::InvalidBackendDisposition);

    auto ambiguous_backend = std::make_shared<FakeRegistry>();
    ambiguous_backend->behavior = Behavior::AmbiguousAfterWrite;
    const auto values = identities();
    auto ambiguous = prepare(ambiguous_backend, values);
    auto ambiguous_outcome =
        FreshOwnerTransactionalReplayBridge::commit_after_claim(
            std::move(ambiguous));
    expect(ambiguous_outcome, TestFreshOwnerReplayOutcome::Unavailable);
    expect_disposition(
        ambiguous_outcome,
        TestFreshOwnerReplayDisposition::AmbiguousAfterWrite);

    ambiguous_backend->behavior = Behavior::Atomic;
    auto replay = prepare(ambiguous_backend, values);
    auto replay_outcome =
        FreshOwnerTransactionalReplayBridge::commit_after_claim(
            std::move(replay));
    expect(replay_outcome, TestFreshOwnerReplayOutcome::Unavailable);
    expect_disposition(
        replay_outcome,
        TestFreshOwnerReplayDisposition::ReplayOrConflict);
}

} // namespace
} // namespace kpb::measurement::fresh_owner_transactional_replay

int main() {
    using namespace kpb::measurement::fresh_owner_transactional_replay;
    committed_without_commit_allocation();
    prepare_failure_does_not_claim_registry();
    invalid_identity_sets_do_not_claim_registry();
    invalid_registry_lineage_refuses_at_mint();
    null_prepare_does_not_claim_registry();
    dropped_prepare_does_not_mutate_registry();
    same_set_concurrency_commits_exactly_once();
    one_identity_overlap_refuses_whole_set();
    unavailable_and_ambiguous_never_authorize();
}
