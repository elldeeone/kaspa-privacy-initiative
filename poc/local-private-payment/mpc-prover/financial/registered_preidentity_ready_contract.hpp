#pragma once

#include "../../private_batch_trial/privacy_fresh_owner_transactional_issuance_contract.hpp"

// Complete neutral contract for the causal preidentity join. Both resource
// reservations must exist before the owner/trial issuance factory may run.

namespace kpi::mpc::financial::fresh_owner_issuance {
class OwnerLocalIssuanceAuthority;
}

namespace kpi::mpc::financial::registered_driver {

class FreshTrialCaptureTopologyReservation;
class RegisteredPersistentRoleProcessReservation;
class RegisteredPreidentityReadyAuthority;
class RegisteredPreidentityReadyIssuanceResidual;
class RegisteredPreidentityReadyOwnerIssuanceSession;
class RegisteredOwnerIssuancePermit;

class RegisteredPreidentityReadyBridge final {
    RegisteredPreidentityReadyBridge() = delete;
public:
    static RegisteredPreidentityReadyAuthority join(
        FreshTrialCaptureTopologyReservation&&,
        RegisteredPersistentRoleProcessReservation&&);
};

// Complete neutral consumer contract. The owner issuance bridge validates a
// Ready capability before touching owner/replay authorities, then converts it
// once to the opaque residual embedded in the fresh-owner issuance.
class RegisteredPreidentityReadyIssuanceBridge final {
    RegisteredPreidentityReadyIssuanceBridge() = delete;
    static const void* validate_for_transactional_staging(
        const RegisteredPreidentityReadyAuthority&);
    static RegisteredPreidentityReadyIssuanceResidual
        consume_for_transactional_issuance(
            RegisteredPreidentityReadyAuthority&&) noexcept;
    friend class ::kpi::mpc::financial::fresh_owner_issuance::
        FreshOwnerTransactionalIssuanceBridge;
public:
    static RegisteredPreidentityReadyOwnerIssuanceSession begin(
        RegisteredPreidentityReadyAuthority&&);
    static RegisteredOwnerIssuancePermit take_owner_permit(
        RegisteredPreidentityReadyOwnerIssuanceSession&, unsigned owner);
    static RegisteredPreidentityReadyIssuanceResidual finish(
        RegisteredPreidentityReadyOwnerIssuanceSession&&);
    static void validate_owner_lineage(
        const RegisteredPreidentityReadyIssuanceResidual&,
        const fresh_owner_issuance::OwnerLocalIssuanceAuthority&,
        const fresh_owner_issuance::OwnerLocalIssuanceAuthority&,
        const fresh_owner_issuance::OwnerLocalIssuanceAuthority&);
};

} // namespace kpi::mpc::financial::registered_driver
