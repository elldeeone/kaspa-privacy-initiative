#pragma once

#include "privacy_fresh_owner_round1_outcome_consumer_contract.hpp"
#include "privacy_all_branch_fresh_trial_owner_authority.hpp"
#include "../mpc-prover/financial/fresh_owner_process_adapter.hpp"

#include <optional>

namespace kpb::measurement::fresh_trial_owner {

// Indivisible result. The success arm retains the same outer owner plus
// the exact FreshOwnerRound1IssuedAuthority. The STOP arm retains the same
// outer owner plus the complete Round-1 STOP storage. No caller may identify,
// detach, discard, or rebuild either arm.
class FreshOwnerRound1AttemptStepAuthority final {
    // Declaration order is deliberate: destruction runs in reverse order, so
    // an unconsumed source outcome fail-stops before the outer ledger owner
    // could ever be silently dropped.
    std::optional<AllBranchFreshTrialOwnerAuthority> owner_;
    std::optional<kpi::mpc::financial::fresh_owner_issuance::
        FreshOwnerRound1AttemptOutcomeAuthority> outcome_;
    explicit FreshOwnerRound1AttemptStepAuthority(
        AllBranchFreshTrialOwnerAuthority&&,
        kpi::mpc::financial::fresh_owner_issuance::
            FreshOwnerRound1AttemptOutcomeAuthority&&) noexcept;
    friend class FreshOwnerRound1AttemptConsumerBridge;
public:
    FreshOwnerRound1AttemptStepAuthority(
        const FreshOwnerRound1AttemptStepAuthority&) = delete;
    FreshOwnerRound1AttemptStepAuthority& operator=(
        const FreshOwnerRound1AttemptStepAuthority&) = delete;
    FreshOwnerRound1AttemptStepAuthority(
        FreshOwnerRound1AttemptStepAuthority&&) noexcept;
    FreshOwnerRound1AttemptStepAuthority& operator=(
        FreshOwnerRound1AttemptStepAuthority&&) = delete;
    ~FreshOwnerRound1AttemptStepAuthority();
};

struct FreshOwnerRound1OutcomeConsumerSourceStatus final {
    bool complete_neutral_contract{};
    bool opaque_indivisible_step{};
    bool fresh_owner_friend_grant{};
    bool atomic_outcome_claim{};
    bool success_continuation_retained{};
    bool stop_outcome_retained{};
    bool mandatory_durable_sink{};
    bool selected_callsite{};
    bool configured{};
};

inline constexpr FreshOwnerRound1OutcomeConsumerSourceStatus
kFreshOwnerRound1OutcomeConsumerSourceStatus{
    .complete_neutral_contract = true,
    .opaque_indivisible_step = true,
    .fresh_owner_friend_grant = true,
    .atomic_outcome_claim = true,
    .success_continuation_retained = true,
    .stop_outcome_retained = true,
    .mandatory_durable_sink = false,
    .selected_callsite = true,
    .configured = false,
};

} // namespace kpb::measurement::fresh_trial_owner
