#pragma once

// Neutral, unimplemented chronology contract.  The pre-setup source owner
// must define W1PreSetupTrialAuthority from a live registered pre-key trial
// reservation.  The current fresh-owner issuance is ineligible because its
// contracts already bind PK/VK identities.  No digest, receipt, path,
// manifest, PK/VK, proof or post-run value can call either transition below.

namespace kpb::measurement::counterfactual_feasibility {
class W1PreSetupTrialAuthority;
}

namespace kpb::bounded_setup {

class SetupCompletionAuthority;
class W1PreSetupSplitAuthority;
class W1SetupBindingContinuationAuthority;
class W1PostSetupReceiptAuthority;

class BoundedSetupChronologyBridge final {
    BoundedSetupChronologyBridge() = delete;
public:
    // Future source-owned transition only.  It burns the live pre-run trial
    // authority and atomically retains both the frozen setup plan and a
    // same-trial continuation inside W1PreSetupSplitAuthority.  Only the
    // future source-owned launcher may split those two linear capabilities.
    static W1PreSetupSplitAuthority freeze(
        ::kpb::measurement::counterfactual_feasibility::
            W1PreSetupTrialAuthority&&);

    // Future post-setup transition only.  It burns both the genuine worker
    // completion and its matching continuation after independently measuring
    // all four exact PK/VK byte streams.  A receipt or artifact hash cannot
    // reconstruct either input.
    static W1PostSetupReceiptAuthority join_measured_keys(
        SetupCompletionAuthority&&,
        W1SetupBindingContinuationAuthority&&);
};

} // namespace kpb::bounded_setup
