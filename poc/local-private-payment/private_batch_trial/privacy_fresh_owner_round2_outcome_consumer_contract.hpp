#pragma once

// Complete dependency-neutral contract for the future causal Round-2
// transition.  The selected parent must first produce an opaque continuation
// proving genuine Round-1 execution; a raw Round-1 receipt or issued wrapper
// is deliberately insufficient.

namespace kpi::mpc::financial::fresh_owner_issuance {
class AcceptedRound1SuccessorHistoryAuthority;
}

namespace kpi::mpc::financial::registered_driver {
class RegisteredFreshOwnerAfterRound1Authority;
}

namespace kpb::measurement::fresh_trial_owner {

class FreshOwnerRound2AttemptStepAuthority;

class FreshOwnerRound2AttemptConsumerBridge final {
public:
    FreshOwnerRound2AttemptConsumerBridge() = delete;

    static FreshOwnerRound2AttemptStepAuthority advance(
        kpi::mpc::financial::registered_driver::
            RegisteredFreshOwnerAfterRound1Authority&&,
        kpi::mpc::financial::fresh_owner_issuance::
            AcceptedRound1SuccessorHistoryAuthority&&);
};

} // namespace kpb::measurement::fresh_trial_owner
