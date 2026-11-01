#pragma once

// Complete dependency-neutral grant for the only consumer of one registered
// attempt append outcome. The concrete owner and result remain opaque here;
// this header exists so granting authorities never friend a forward-declared
// class name that a hostile translation unit could define.

namespace kpi::mpc::financial::registered_driver::attempt_history {
class RegisteredAttemptHistoryAppendOutcomeAuthority;
}
namespace kpi::mpc::financial::registered_driver {
class RegisteredPersistentRoleActivationFailureResidual;
}

namespace kpb::measurement::fresh_trial_owner {

class AllBranchFreshTrialOwnerAuthority;
class AllBranchFreshTrialStepAuthority;

class AllBranchFreshTrialOwnerBridge final {
    AllBranchFreshTrialOwnerBridge() = delete;
public:
    // Both rvalues are move-claimed before validation. The returned opaque
    // step owns exactly one source-minted arm: complete failed view -> fresh
    // full-trial continuation, final complete view -> terminal success, or
    // unavailable/incomplete view -> run-invalidating STOP terminal.
    static AllBranchFreshTrialStepAuthority append(
        AllBranchFreshTrialOwnerAuthority&&,
        kpi::mpc::financial::registered_driver::attempt_history::
            RegisteredAttemptHistoryAppendOutcomeAuthority&&);
    static AllBranchFreshTrialStepAuthority stop_after_activation_failure(
        AllBranchFreshTrialOwnerAuthority&&,
        kpi::mpc::financial::registered_driver::
            RegisteredPersistentRoleActivationFailureResidual&&);
};

} // namespace kpb::measurement::fresh_trial_owner
