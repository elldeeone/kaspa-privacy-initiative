#pragma once

// Complete dependency-neutral contract for the future atomic FreshOwner join.
// The implementation must derive the exact 56 replay identities from the
// three genuine owner authorities, prepare the selected registry before any
// owner/Ready claim, and return one opaque committed-or-STOP capability.  No
// caller-supplied replay set, public receipt, digest, enum, or boolean can
// substitute for this bridge.

#include <array>

namespace kpb::measurement::fresh_owner_transactional_replay {
class SelectedOwnerReplayRegistryAuthority;
class FreshOwnerReplayOutcomeTransfer;
}

namespace kpi::mpc::financial::registered_driver {
class RegisteredPreidentityReadyAuthority;
class RegisteredPreidentityReadyIssuanceResidual;
}

namespace kpi::mpc::financial::fresh_owner_issuance {

class OwnerLocalIssuanceAuthority;
class AuthenticatedOwnerProcessBundle;
class FreshOwnerTransactionalIssuanceOutcomeAuthority;

class FreshOwnerTransactionalIssuanceBridge final {
    FreshOwnerTransactionalIssuanceBridge() = delete;
public:
    static FreshOwnerTransactionalIssuanceOutcomeAuthority
        join_authenticated_exact_three(
            registered_driver::RegisteredPreidentityReadyAuthority&&,
            AuthenticatedOwnerProcessBundle&& owner0,
            AuthenticatedOwnerProcessBundle&& owner1,
            AuthenticatedOwnerProcessBundle&& owner2,
            kpb::measurement::fresh_owner_transactional_replay::
                SelectedOwnerReplayRegistryAuthority&&,
            const std::array<unsigned char, 32>&
                roster_authority_identity);

    // Fixture/integration seam for already authenticated owner authorities.
    // The selected owner-process path must use the bundle overload above so
    // constructing owners cannot occur after Ready is claimed.
    static FreshOwnerTransactionalIssuanceOutcomeAuthority join_exact_three(
        registered_driver::RegisteredPreidentityReadyIssuanceResidual&&,
        OwnerLocalIssuanceAuthority&& owner0,
        OwnerLocalIssuanceAuthority&& owner1,
        OwnerLocalIssuanceAuthority&& owner2,
        kpb::measurement::fresh_owner_transactional_replay::
            SelectedOwnerReplayRegistryAuthority&&,
        const std::array<unsigned char, 32>& roster_authority_identity);
};

} // namespace kpi::mpc::financial::fresh_owner_issuance
