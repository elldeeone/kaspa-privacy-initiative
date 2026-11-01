#include "privacy_fresh_owner_round1_outcome_consumer_authority.hpp"

#include <exception>
#include <type_traits>
#include <utility>

namespace kpb::measurement::fresh_trial_owner {

FreshOwnerRound1AttemptStepAuthority::
FreshOwnerRound1AttemptStepAuthority(
        AllBranchFreshTrialOwnerAuthority&& owner,
        kpi::mpc::financial::fresh_owner_issuance::
            FreshOwnerRound1AttemptOutcomeAuthority&& outcome) noexcept {
    owner_.emplace(std::move(owner));
    outcome_.emplace(std::move(outcome));
}

FreshOwnerRound1AttemptStepAuthority::
FreshOwnerRound1AttemptStepAuthority(
        FreshOwnerRound1AttemptStepAuthority&&) noexcept = default;

FreshOwnerRound1AttemptStepAuthority::
~FreshOwnerRound1AttemptStepAuthority() = default;

FreshOwnerRound1AttemptStepAuthority
FreshOwnerRound1AttemptConsumerBridge::append(
        AllBranchFreshTrialOwnerAuthority&& supplied_owner,
        kpi::mpc::financial::fresh_owner_issuance::
            FreshOwnerRound1AttemptOutcomeAuthority&& supplied_outcome) {
    using Outcome = kpi::mpc::financial::fresh_owner_issuance::
        FreshOwnerRound1AttemptOutcomeAuthority;
    static_assert(std::is_nothrow_move_constructible_v<
        AllBranchFreshTrialOwnerAuthority>);
    static_assert(std::is_nothrow_move_constructible_v<Outcome>);
    static_assert(noexcept(std::declval<std::optional<
        AllBranchFreshTrialOwnerAuthority>&>().emplace(
            std::declval<AllBranchFreshTrialOwnerAuthority&&>())));
    static_assert(noexcept(std::declval<std::optional<Outcome>&>().emplace(
        std::declval<Outcome&&>())));

    // The outer owner preallocates its ledger/STOP shells before trial
    // identity. This constructor performs only proven-noexcept moves, so the
    // mandatory outcome has no post-issuance allocation/failure window.
    FreshOwnerRound1AttemptStepAuthority result(
        std::move(supplied_owner), std::move(supplied_outcome));
    if (!result.owner_.has_value() ||
        result.owner_->ledger_ == nullptr ||
        result.owner_->reserved_stop_ == nullptr ||
        !result.outcome_.has_value() ||
        !result.outcome_->valid_for_outer_consumer())
        std::terminate();
    return result;
}

} // namespace kpb::measurement::fresh_trial_owner
