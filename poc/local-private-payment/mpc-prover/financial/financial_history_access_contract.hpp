#pragma once

// Complete declaration of the only financial-history bridge allowed to mint
// PREPARED and durable-EGRESS authorities.  History headers include this
// contract before granting friendship, preventing hostile translation units
// from defining a same-named FinancialHistoryAccess class.

namespace kpi::mpc {

class MascotContext;

namespace history {
class LockedAttempt;
class PreparedEpochTicket;
class EgressRelease;
}

namespace financial {

class FinancialConstruction;
class FinancialValidatedAssignment;
class VerifiedFinancialProof;

namespace registered_driver {
class RegisteredCaptureSession;
class PartyDriverCompletionAuthority;
class ChildRoleCompletionEndpointAuthority;
namespace projection_route { class Role0ProjectionRouteWriterAuthority; }
namespace baseline_disclosure {
class PartyBaselineOwnerEffectsAuthority;
}
}

namespace fresh_owner_issuance {
class BaselineOwnerRosterReceiverAuthority;
}

class FinancialHistoryAccess final {
    FinancialHistoryAccess() = delete;
    static history::EgressRelease release_verified_impl(
        MascotContext&, VerifiedFinancialProof&&,
        history::PreparedEpochTicket&&,
        registered_driver::RegisteredCaptureSession*);
public:
    static history::PreparedEpochTicket prepare(
        MascotContext&, const FinancialConstruction&,
        FinancialValidatedAssignment&);
    static history::EgressRelease release_verified(
        MascotContext&, VerifiedFinancialProof&&,
        history::PreparedEpochTicket&&);
    static history::EgressRelease release_verified_registered(
        MascotContext&, VerifiedFinancialProof&&,
        history::PreparedEpochTicket&&);
    static registered_driver::PartyDriverCompletionAuthority
    complete_registered_egress(
        MascotContext&, const FinancialConstruction&,
        const history::EgressRelease&);
    static void await_registered_release_barrier(
        MascotContext&, const FinancialConstruction&,
        const history::EgressRelease&,
        registered_driver::ChildRoleCompletionEndpointAuthority&);
    static void route_registered_projection(
        MascotContext&, const FinancialConstruction&,
        const history::EgressRelease&,
        registered_driver::projection_route::
            Role0ProjectionRouteWriterAuthority&&);
    static registered_driver::baseline_disclosure::
        PartyBaselineOwnerEffectsAuthority
    baseline_owner_scoring(
        MascotContext&, const FinancialConstruction&,
        const history::EgressRelease&,
        fresh_owner_issuance::BaselineOwnerRosterReceiverAuthority&&);
};

} // namespace financial
} // namespace kpi::mpc
