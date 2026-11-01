#pragma once

// Complete, dependency-neutral declaration of the only bridge that may derive
// the producer runtime's two-round aggregate-route capability from a genuine
// registered parent trial.  It accepts no public receipt, digest, timestamp,
// body or caller-authored route metadata.

namespace kpb::measurement::producer_runtime {
class ParentAggregateMailboxRoutesAuthority;
}

namespace kpi::mpc::financial::registered_driver {

class RegisteredParentTrialCompletionAuthority;

class RegisteredProducerRouteBridge final {
    RegisteredProducerRouteBridge() = delete;
public:
    static kpb::measurement::producer_runtime::
        ParentAggregateMailboxRoutesAuthority take_once(
            RegisteredParentTrialCompletionAuthority&);
};

} // namespace kpi::mpc::financial::registered_driver
