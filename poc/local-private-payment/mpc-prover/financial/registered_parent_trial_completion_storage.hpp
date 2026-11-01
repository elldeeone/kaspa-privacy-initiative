#pragma once

// Private cross-module storage shared only with the complete measurement
// bridge. The nested type remains private to the authority: including this
// header does not expose storage_, a constructor, a receipt or a split route.

#include "authenticated_baseline_owner_receiver.hpp"
#include "registered_party_completion_transport.hpp"
#include "registered_selected_parent_orchestrator.hpp"

#include <array>
#include <atomic>
#include <optional>
#include <string>

namespace kpi::mpc::financial::registered_driver {

struct RegisteredParentTrialCompletionAuthority::Storage final {
    std::array<projection_route::ParentRetainedProjectionAuthority, 2>
        retained_projections;
    std::array<std::array<ParentObservedPartyCompletionAuthority, 3>, 2>
        party_completions;
    std::array<std::array<std::optional<
        baseline_disclosure::PartyBaselineOwnerEffectsAuthority>, 3>, 2>
        baseline_effects;
    std::string capture_trial_id;
    // Source-owned pidfd/wait capability.  Do not flatten this into caller
    // booleans or copied PIDs: the measurement/terminal chain must retain and
    // consume the exact evidence minted by the persistent process owner.
    detail::PersistentRoleExitEvidence exit_evidence;
    std::atomic_bool producer_routes_taken{false};
    std::atomic_bool exit_history_residual_taken{false};

    Storage(
        std::array<projection_route::ParentRetainedProjectionAuthority, 2>&&,
        std::array<std::array<ParentObservedPartyCompletionAuthority, 3>, 2>&&,
        std::array<std::array<std::optional<
            baseline_disclosure::PartyBaselineOwnerEffectsAuthority>, 3>, 2>&&,
        std::string capture_trial_id,
        detail::PersistentRoleExitEvidence&&);
};

} // namespace kpi::mpc::financial::registered_driver
