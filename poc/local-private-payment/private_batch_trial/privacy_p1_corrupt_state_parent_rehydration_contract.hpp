#pragma once

// Dependency-neutral contract for the future parent-side observer-v5 join.
// Possession of a parent read description is intentionally insufficient. The
// bridge must atomically burn two authenticated child dispositions, the exact
// parent-held two-archive topology residual, and pidfd-bound persistent child
// exit evidence before it independently parses/replays either archive.

namespace kpb::measurement::p1_state_capsule {
class P1AuthenticatedChildStateDispositionAuthority;
class P1ParentRehydratedStateCapsuleAuthority;
}

namespace kpi::mpc::financial::registered_driver {
class FreshTrialP1StateArchiveResidual;
namespace detail { class PersistentRoleExitEvidence; }

class RegisteredP1StateCapsuleParentRehydrationBridge final {
public:
    RegisteredP1StateCapsuleParentRehydrationBridge() = delete;

    static kpb::measurement::p1_state_capsule::
        P1ParentRehydratedStateCapsuleAuthority
    rehydrate_and_replay(
        FreshTrialP1StateArchiveResidual&&,
        kpb::measurement::p1_state_capsule::
            P1AuthenticatedChildStateDispositionAuthority&& round1,
        kpb::measurement::p1_state_capsule::
            P1AuthenticatedChildStateDispositionAuthority&& round2,
        detail::PersistentRoleExitEvidence&&);
};

} // namespace kpi::mpc::financial::registered_driver
