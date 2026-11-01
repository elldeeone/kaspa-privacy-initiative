#pragma once

// Complete dependency-neutral contract for the sole selected-path consumer
// of the source-owned Round-1 attempt closed sum. No public receipt, state selector,
// arm extractor, text, bytes, descriptor, or digest may substitute for either
// linear input.

namespace kpi::mpc::financial::fresh_owner_issuance {
class FreshOwnerRound1AttemptOutcomeAuthority;
}

namespace kpb::measurement::fresh_trial_owner {

class AllBranchFreshTrialOwnerAuthority;
class FreshOwnerRound1AttemptStepAuthority;

class FreshOwnerRound1AttemptConsumerBridge final {
public:
    FreshOwnerRound1AttemptConsumerBridge() = delete;

    static FreshOwnerRound1AttemptStepAuthority append(
        AllBranchFreshTrialOwnerAuthority&&,
        kpi::mpc::financial::fresh_owner_issuance::
            FreshOwnerRound1AttemptOutcomeAuthority&&);
};

} // namespace kpb::measurement::fresh_trial_owner
