#pragma once

// Isolated two-phase replay-registry core for the future FreshOwner join.
// The selected registry factory and Ready+three-owner integration do not
// exist, so this module cannot mint a FreshOwner issuance authority.

#include "privacy_fresh_owner_transactional_replay_contract.hpp"
#include "privacy_fresh_owner_transactional_issuance_contract.hpp"

#include <atomic>
#include <memory>

namespace kpb::measurement::fresh_owner_transactional_replay {

enum class OwnerReplayBackendCommitDisposition : unsigned char {
    Committed,
    ReplayOrConflict,
    InfrastructureUnavailable,
    AmbiguousAfterWrite,
};

class OwnerReplayPreparedOperation {
public:
    OwnerReplayPreparedOperation() = default;
    OwnerReplayPreparedOperation(const OwnerReplayPreparedOperation&) = delete;
    OwnerReplayPreparedOperation& operator=(
        const OwnerReplayPreparedOperation&) = delete;
    virtual ~OwnerReplayPreparedOperation() = default;

    // The selected backend must implement one atomic compare-and-insert over
    // the exact 56 identities. Every result except Committed is terminally
    // unavailable to the FreshOwner join.
    virtual OwnerReplayBackendCommitDisposition commit_prepared() noexcept = 0;
};

class TransactionalOwnerReplayRegistry {
public:
    TransactionalOwnerReplayRegistry() = default;
    TransactionalOwnerReplayRegistry(
        const TransactionalOwnerReplayRegistry&) = delete;
    TransactionalOwnerReplayRegistry& operator=(
        const TransactionalOwnerReplayRegistry&) = delete;
    virtual ~TransactionalOwnerReplayRegistry() = default;

    // This is the only allocating/throwing backend phase. Returning nullptr
    // refuses without consuming the selected registry capability.
    virtual std::unique_ptr<OwnerReplayPreparedOperation> prepare(
        const ExactOwnerReplaySet&) = 0;
};

class SelectedOwnerReplayRegistryAuthority final {
    std::shared_ptr<TransactionalOwnerReplayRegistry> registry_;
    ReplayIdentity registry_authority_identity_{};
    ReplayIdentity replay_policy_identity_{};
    std::atomic_bool live_{true};
    explicit SelectedOwnerReplayRegistryAuthority(
        std::shared_ptr<TransactionalOwnerReplayRegistry>,
        ReplayIdentity registry_authority_identity,
        ReplayIdentity replay_policy_identity);
    ReplayIdentity registry_identity_for_transactional_prepare()
        const noexcept;
    ReplayIdentity replay_policy_identity_for_transactional_prepare()
        const noexcept;
    friend class FreshOwnerTransactionalReplayBridge;
    friend class kpi::mpc::financial::fresh_owner_issuance::
        FreshOwnerTransactionalIssuanceBridge;
#ifdef KPB_FRESH_OWNER_TRANSACTIONAL_REPLAY_TEST_SETUP
    friend class FreshOwnerTransactionalReplayTestBridge;
#endif
public:
    SelectedOwnerReplayRegistryAuthority(
        const SelectedOwnerReplayRegistryAuthority&) = delete;
    SelectedOwnerReplayRegistryAuthority& operator=(
        const SelectedOwnerReplayRegistryAuthority&) = delete;
    SelectedOwnerReplayRegistryAuthority(
        SelectedOwnerReplayRegistryAuthority&&) noexcept;
    SelectedOwnerReplayRegistryAuthority& operator=(
        SelectedOwnerReplayRegistryAuthority&&) = delete;
    ~SelectedOwnerReplayRegistryAuthority();
};

struct FreshOwnerReplayPrepareStorage;
struct FreshOwnerReplayOutcomeStorage;

class FreshOwnerReplayOutcomeTransfer final {
    std::unique_ptr<FreshOwnerReplayOutcomeStorage> storage_;
    explicit FreshOwnerReplayOutcomeTransfer(
        std::unique_ptr<FreshOwnerReplayOutcomeStorage>&&) noexcept;
    bool committed_for_transactional_issuance() const noexcept;
    ReplayIdentity registry_identity_for_transactional_issuance()
        const noexcept;
    ReplayIdentity replay_policy_identity_for_transactional_issuance()
        const noexcept;
    friend class FreshOwnerReplayOutcomeAuthority;
    friend class kpi::mpc::financial::fresh_owner_issuance::
        FreshOwnerTransactionalIssuanceBridge;
#ifdef KPB_FRESH_OWNER_TRANSACTIONAL_REPLAY_TEST_SETUP
    friend class FreshOwnerTransactionalReplayTestBridge;
#endif
public:
    FreshOwnerReplayOutcomeTransfer(
        const FreshOwnerReplayOutcomeTransfer&) = delete;
    FreshOwnerReplayOutcomeTransfer& operator=(
        const FreshOwnerReplayOutcomeTransfer&) = delete;
    FreshOwnerReplayOutcomeTransfer(
        FreshOwnerReplayOutcomeTransfer&&) noexcept;
    FreshOwnerReplayOutcomeTransfer& operator=(
        FreshOwnerReplayOutcomeTransfer&&) = delete;
    ~FreshOwnerReplayOutcomeTransfer();
};

class FreshOwnerReplayPrepareAuthority final {
    std::unique_ptr<FreshOwnerReplayPrepareStorage> storage_;
    explicit FreshOwnerReplayPrepareAuthority(
        std::unique_ptr<FreshOwnerReplayPrepareStorage>&&) noexcept;
    friend class FreshOwnerTransactionalReplayBridge;
public:
    FreshOwnerReplayPrepareAuthority(
        const FreshOwnerReplayPrepareAuthority&) = delete;
    FreshOwnerReplayPrepareAuthority& operator=(
        const FreshOwnerReplayPrepareAuthority&) = delete;
    FreshOwnerReplayPrepareAuthority(
        FreshOwnerReplayPrepareAuthority&&) noexcept;
    FreshOwnerReplayPrepareAuthority& operator=(
        FreshOwnerReplayPrepareAuthority&&) = delete;
    ~FreshOwnerReplayPrepareAuthority();
};

class FreshOwnerReplayOutcomeAuthority final {
    std::unique_ptr<FreshOwnerReplayOutcomeStorage> storage_;
    explicit FreshOwnerReplayOutcomeAuthority(
        std::unique_ptr<FreshOwnerReplayOutcomeStorage>&&) noexcept;
    FreshOwnerReplayOutcomeTransfer
        transfer_for_transactional_issuance() && noexcept;
    friend class FreshOwnerTransactionalReplayBridge;
    friend class kpi::mpc::financial::fresh_owner_issuance::
        FreshOwnerTransactionalIssuanceBridge;
#ifdef KPB_FRESH_OWNER_TRANSACTIONAL_REPLAY_TEST_SETUP
    friend class FreshOwnerTransactionalReplayTestBridge;
#endif
public:
    FreshOwnerReplayOutcomeAuthority(
        const FreshOwnerReplayOutcomeAuthority&) = delete;
    FreshOwnerReplayOutcomeAuthority& operator=(
        const FreshOwnerReplayOutcomeAuthority&) = delete;
    FreshOwnerReplayOutcomeAuthority(
        FreshOwnerReplayOutcomeAuthority&&) noexcept;
    FreshOwnerReplayOutcomeAuthority& operator=(
        FreshOwnerReplayOutcomeAuthority&&) = delete;
    ~FreshOwnerReplayOutcomeAuthority();
};

struct FreshOwnerTransactionalReplaySourceStatus {
    bool transactional_registry_core;
    bool prepare_before_claim_core;
    bool preallocated_commit_outcome_core;
    bool noexcept_commit_core;
    bool typed_unavailable_core;
    bool source_owned_registry;
    bool ready_three_owner_verifier_join;
    bool fresh_owner_result_factory;
    bool composite_stop_retains_all_inputs;
    bool selected_callsite;
    bool configured;
};

inline constexpr FreshOwnerTransactionalReplaySourceStatus
    kFreshOwnerTransactionalReplaySourceStatus{
        .transactional_registry_core = true,
        .prepare_before_claim_core = true,
        .preallocated_commit_outcome_core = true,
        .noexcept_commit_core = true,
        .typed_unavailable_core = true,
        .source_owned_registry = false,
        .ready_three_owner_verifier_join = false,
        .fresh_owner_result_factory = false,
        .composite_stop_retains_all_inputs = false,
        .selected_callsite = false,
        .configured = false,
    };

#ifdef KPB_FRESH_OWNER_TRANSACTIONAL_REPLAY_TEST_SETUP
enum class TestFreshOwnerReplayOutcome : unsigned char {
    Committed,
    Unavailable,
};

enum class TestFreshOwnerReplayDisposition : unsigned char {
    Committed,
    ReplayOrConflict,
    InfrastructureUnavailable,
    AmbiguousAfterWrite,
    InvalidBackendDisposition,
    StaleOrMissingPrepared,
};

class FreshOwnerTransactionalReplayTestBridge final {
    FreshOwnerTransactionalReplayTestBridge() = delete;
public:
    static SelectedOwnerReplayRegistryAuthority mint_registry(
        std::shared_ptr<TransactionalOwnerReplayRegistry>,
        ReplayIdentity registry_authority_identity,
        ReplayIdentity replay_policy_identity);
    static TestFreshOwnerReplayOutcome inspect(
        const FreshOwnerReplayOutcomeAuthority&) noexcept;
    static FreshOwnerReplayOutcomeTransfer transfer(
        FreshOwnerReplayOutcomeAuthority&&) noexcept;
    static TestFreshOwnerReplayOutcome inspect(
        const FreshOwnerReplayOutcomeTransfer&) noexcept;
    static TestFreshOwnerReplayDisposition disposition(
        const FreshOwnerReplayOutcomeAuthority&) noexcept;
    static TestFreshOwnerReplayDisposition disposition(
        const FreshOwnerReplayOutcomeTransfer&) noexcept;
    static ReplayIdentity registry_identity(
        const FreshOwnerReplayOutcomeTransfer&) noexcept;
    static ReplayIdentity replay_policy_identity(
        const FreshOwnerReplayOutcomeTransfer&) noexcept;
};
#endif

} // namespace kpb::measurement::fresh_owner_transactional_replay
