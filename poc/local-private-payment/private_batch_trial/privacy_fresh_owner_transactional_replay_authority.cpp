#include "privacy_fresh_owner_transactional_replay_authority.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace kpb::measurement::fresh_owner_transactional_replay {
namespace {

[[noreturn]] void refuse() {
    throw std::runtime_error("fresh-owner transactional replay refused");
}

bool zero(const ReplayIdentity& value) noexcept {
    return std::ranges::all_of(value, [](unsigned char byte) {
        return byte == 0;
    });
}

void validate_identities(const ExactOwnerReplaySet& identities) {
    for (std::size_t index = 0; index < identities.size(); ++index) {
        if (zero(identities[index])) refuse();
        for (std::size_t prior = 0; prior < index; ++prior)
            if (identities[index] == identities[prior]) refuse();
    }
}

enum class OutcomeDisposition : unsigned char {
    Committed,
    ReplayOrConflict,
    InfrastructureUnavailable,
    AmbiguousAfterWrite,
    InvalidBackendDisposition,
    StaleOrMissingPrepared,
};

OutcomeDisposition normalize(
        OwnerReplayBackendCommitDisposition disposition) noexcept {
    switch (disposition) {
    case OwnerReplayBackendCommitDisposition::Committed:
        return OutcomeDisposition::Committed;
    case OwnerReplayBackendCommitDisposition::ReplayOrConflict:
        return OutcomeDisposition::ReplayOrConflict;
    case OwnerReplayBackendCommitDisposition::InfrastructureUnavailable:
        return OutcomeDisposition::InfrastructureUnavailable;
    case OwnerReplayBackendCommitDisposition::AmbiguousAfterWrite:
        return OutcomeDisposition::AmbiguousAfterWrite;
    }
    return OutcomeDisposition::InvalidBackendDisposition;
}

} // namespace

struct FreshOwnerReplayOutcomeStorage final {
    ExactOwnerReplaySet identities{};
    ReplayIdentity registry_authority_identity{};
    ReplayIdentity replay_policy_identity{};
    OutcomeDisposition disposition{
        OutcomeDisposition::StaleOrMissingPrepared};
};

struct FreshOwnerReplayPrepareStorage final {
    ExactOwnerReplaySet identities{};
    ReplayIdentity registry_authority_identity{};
    ReplayIdentity replay_policy_identity{};
    std::shared_ptr<TransactionalOwnerReplayRegistry> registry;
    std::unique_ptr<OwnerReplayPreparedOperation> operation;
    std::unique_ptr<FreshOwnerReplayOutcomeStorage> reserved_outcome;
};

SelectedOwnerReplayRegistryAuthority::
SelectedOwnerReplayRegistryAuthority(
        std::shared_ptr<TransactionalOwnerReplayRegistry> registry,
        ReplayIdentity registry_authority_identity,
        ReplayIdentity replay_policy_identity)
    : registry_(std::move(registry)),
      registry_authority_identity_(registry_authority_identity),
      replay_policy_identity_(replay_policy_identity) {
    if (registry_ == nullptr || zero(registry_authority_identity_) ||
        zero(replay_policy_identity_) ||
        registry_authority_identity_ == replay_policy_identity_)
        refuse();
}

SelectedOwnerReplayRegistryAuthority::
SelectedOwnerReplayRegistryAuthority(
        SelectedOwnerReplayRegistryAuthority&& other) noexcept
    : registry_(std::move(other.registry_)),
      registry_authority_identity_(other.registry_authority_identity_),
      replay_policy_identity_(other.replay_policy_identity_),
      live_(other.live_.exchange(false)) {}

SelectedOwnerReplayRegistryAuthority::
~SelectedOwnerReplayRegistryAuthority() = default;

ReplayIdentity SelectedOwnerReplayRegistryAuthority::
registry_identity_for_transactional_prepare() const noexcept {
    return live_.load() ? registry_authority_identity_ : ReplayIdentity{};
}

ReplayIdentity SelectedOwnerReplayRegistryAuthority::
replay_policy_identity_for_transactional_prepare() const noexcept {
    return live_.load() ? replay_policy_identity_ : ReplayIdentity{};
}

FreshOwnerReplayPrepareAuthority::FreshOwnerReplayPrepareAuthority(
        std::unique_ptr<FreshOwnerReplayPrepareStorage>&& storage) noexcept
    : storage_(std::move(storage)) {}

FreshOwnerReplayPrepareAuthority::FreshOwnerReplayPrepareAuthority(
        FreshOwnerReplayPrepareAuthority&&) noexcept = default;

FreshOwnerReplayPrepareAuthority::~FreshOwnerReplayPrepareAuthority() =
    default;

FreshOwnerReplayOutcomeTransfer::FreshOwnerReplayOutcomeTransfer(
        std::unique_ptr<FreshOwnerReplayOutcomeStorage>&& storage) noexcept
    : storage_(std::move(storage)) {}

FreshOwnerReplayOutcomeTransfer::FreshOwnerReplayOutcomeTransfer(
        FreshOwnerReplayOutcomeTransfer&&) noexcept = default;

FreshOwnerReplayOutcomeTransfer::~FreshOwnerReplayOutcomeTransfer() = default;

bool FreshOwnerReplayOutcomeTransfer::
committed_for_transactional_issuance() const noexcept {
    return storage_ != nullptr &&
           storage_->disposition == OutcomeDisposition::Committed;
}

ReplayIdentity FreshOwnerReplayOutcomeTransfer::
registry_identity_for_transactional_issuance() const noexcept {
    return storage_ == nullptr
        ? ReplayIdentity{}
        : storage_->registry_authority_identity;
}

ReplayIdentity FreshOwnerReplayOutcomeTransfer::
replay_policy_identity_for_transactional_issuance() const noexcept {
    return storage_ == nullptr
        ? ReplayIdentity{}
        : storage_->replay_policy_identity;
}

FreshOwnerReplayOutcomeAuthority::FreshOwnerReplayOutcomeAuthority(
        std::unique_ptr<FreshOwnerReplayOutcomeStorage>&& storage) noexcept
    : storage_(std::move(storage)) {}

FreshOwnerReplayOutcomeAuthority::FreshOwnerReplayOutcomeAuthority(
        FreshOwnerReplayOutcomeAuthority&&) noexcept = default;

FreshOwnerReplayOutcomeAuthority::~FreshOwnerReplayOutcomeAuthority() =
    default;

FreshOwnerReplayOutcomeTransfer
FreshOwnerReplayOutcomeAuthority::
transfer_for_transactional_issuance() && noexcept {
    return FreshOwnerReplayOutcomeTransfer(std::move(storage_));
}

FreshOwnerReplayPrepareAuthority
FreshOwnerTransactionalReplayBridge::prepare(
        SelectedOwnerReplayRegistryAuthority&& supplied_registry,
        const ExactOwnerReplaySet& identities) {
    // Everything that can allocate is complete before the selected registry
    // capability is claimed. A prepared backend object must be rollback-safe
    // until commit.
    if (!supplied_registry.live_.load() ||
        supplied_registry.registry_ == nullptr)
        refuse();
    validate_identities(identities);
    for (const auto& identity : identities)
        if (identity == supplied_registry.registry_authority_identity_ ||
            identity == supplied_registry.replay_policy_identity_)
            refuse();

    auto storage = std::make_unique<FreshOwnerReplayPrepareStorage>();
    storage->identities = identities;
    storage->registry_authority_identity =
        supplied_registry.registry_authority_identity_;
    storage->replay_policy_identity =
        supplied_registry.replay_policy_identity_;
    storage->registry = supplied_registry.registry_;
    storage->reserved_outcome =
        std::make_unique<FreshOwnerReplayOutcomeStorage>();
    storage->operation = storage->registry->prepare(storage->identities);
    if (storage->operation == nullptr) refuse();

    if (!supplied_registry.live_.exchange(false)) refuse();
    supplied_registry.registry_.reset();
    return FreshOwnerReplayPrepareAuthority(std::move(storage));
}

FreshOwnerReplayOutcomeAuthority
FreshOwnerTransactionalReplayBridge::commit_after_claim(
        FreshOwnerReplayPrepareAuthority&& supplied) noexcept {
    // Move-claim first. A stale/replayed authority yields an opaque
    // unavailable residual and cannot call the registry twice.
    auto storage = std::move(supplied.storage_);
    if (storage == nullptr || storage->reserved_outcome == nullptr)
        return FreshOwnerReplayOutcomeAuthority(nullptr);

    auto outcome = std::move(storage->reserved_outcome);
    outcome->identities = std::move(storage->identities);
    outcome->registry_authority_identity =
        storage->registry_authority_identity;
    outcome->replay_policy_identity = storage->replay_policy_identity;
    const auto disposition = storage->operation == nullptr
        ? OwnerReplayBackendCommitDisposition::InfrastructureUnavailable
        : storage->operation->commit_prepared();
    outcome->disposition = normalize(disposition);
    return FreshOwnerReplayOutcomeAuthority(std::move(outcome));
}

#ifdef KPB_FRESH_OWNER_TRANSACTIONAL_REPLAY_TEST_SETUP
SelectedOwnerReplayRegistryAuthority
FreshOwnerTransactionalReplayTestBridge::mint_registry(
        std::shared_ptr<TransactionalOwnerReplayRegistry> registry,
        ReplayIdentity registry_authority_identity,
        ReplayIdentity replay_policy_identity) {
    return SelectedOwnerReplayRegistryAuthority(
        std::move(registry), registry_authority_identity,
        replay_policy_identity);
}

TestFreshOwnerReplayOutcome
FreshOwnerTransactionalReplayTestBridge::inspect(
        const FreshOwnerReplayOutcomeAuthority& outcome) noexcept {
    return outcome.storage_ != nullptr &&
           outcome.storage_->disposition == OutcomeDisposition::Committed
        ? TestFreshOwnerReplayOutcome::Committed
        : TestFreshOwnerReplayOutcome::Unavailable;
}

namespace {

TestFreshOwnerReplayDisposition test_disposition(
        const FreshOwnerReplayOutcomeStorage* storage) noexcept {
    if (storage == nullptr)
        return TestFreshOwnerReplayDisposition::StaleOrMissingPrepared;
    switch (storage->disposition) {
    case OutcomeDisposition::Committed:
        return TestFreshOwnerReplayDisposition::Committed;
    case OutcomeDisposition::ReplayOrConflict:
        return TestFreshOwnerReplayDisposition::ReplayOrConflict;
    case OutcomeDisposition::InfrastructureUnavailable:
        return TestFreshOwnerReplayDisposition::InfrastructureUnavailable;
    case OutcomeDisposition::AmbiguousAfterWrite:
        return TestFreshOwnerReplayDisposition::AmbiguousAfterWrite;
    case OutcomeDisposition::InvalidBackendDisposition:
        return TestFreshOwnerReplayDisposition::InvalidBackendDisposition;
    case OutcomeDisposition::StaleOrMissingPrepared:
        return TestFreshOwnerReplayDisposition::StaleOrMissingPrepared;
    }
    return TestFreshOwnerReplayDisposition::InvalidBackendDisposition;
}

} // namespace

TestFreshOwnerReplayDisposition
FreshOwnerTransactionalReplayTestBridge::disposition(
        const FreshOwnerReplayOutcomeAuthority& outcome) noexcept {
    return test_disposition(outcome.storage_.get());
}

FreshOwnerReplayOutcomeTransfer
FreshOwnerTransactionalReplayTestBridge::transfer(
        FreshOwnerReplayOutcomeAuthority&& outcome) noexcept {
    return std::move(outcome).transfer_for_transactional_issuance();
}

TestFreshOwnerReplayOutcome
FreshOwnerTransactionalReplayTestBridge::inspect(
        const FreshOwnerReplayOutcomeTransfer& outcome) noexcept {
    return outcome.committed_for_transactional_issuance()
        ? TestFreshOwnerReplayOutcome::Committed
        : TestFreshOwnerReplayOutcome::Unavailable;
}

TestFreshOwnerReplayDisposition
FreshOwnerTransactionalReplayTestBridge::disposition(
        const FreshOwnerReplayOutcomeTransfer& outcome) noexcept {
    return test_disposition(outcome.storage_.get());
}

ReplayIdentity FreshOwnerTransactionalReplayTestBridge::registry_identity(
        const FreshOwnerReplayOutcomeTransfer& outcome) noexcept {
    return outcome.registry_identity_for_transactional_issuance();
}

ReplayIdentity
FreshOwnerTransactionalReplayTestBridge::replay_policy_identity(
        const FreshOwnerReplayOutcomeTransfer& outcome) noexcept {
    return outcome.replay_policy_identity_for_transactional_issuance();
}
#endif

} // namespace kpb::measurement::fresh_owner_transactional_replay
