#include "registered_driver_bridge.hpp"

#include "../history/epoch_ticket.hpp"

namespace kpi::mpc::financial::registered_driver {

VerifiedEgressAuthority VerifiedEgressAuthorityBridge::from_release(
        const history::EgressRelease& release) {
    try {
        const auto& packet = release.packet();
        PublicVerifiedEgress value{
            .binding_identity = release.binding_identity(),
            .effects_identity = packet.effects,
            .core_identity = packet.core,
            .proof_identity = packet.aggregate_proof,
            .projection_identity = packet.projection,
        };
        for (const auto* field : {
                 &value.binding_identity, &value.effects_identity,
                 &value.core_identity, &value.proof_identity,
                 &value.projection_identity})
            if (*field == Digest{}) throw identity_registry::Refused();
        return VerifiedEgressAuthority(std::move(value));
    } catch (...) {
        throw identity_registry::Refused();
    }
}

void RegisteredConstructionAuthorityBridge::claim_owner_intake(
        AuthorizedDriverAttempt& attempt, MascotContext& context,
        history::LockedAttempt& locked,
        const history::AttemptBinding& binding) {
    attempt.claim_owner_intake(context, locked, binding);
}

void AuthorizedDriverAttempt::claim_owner_intake(
    MascotContext& context, history::LockedAttempt& locked,
    const history::AttemptBinding& binding) {
    std::lock_guard guard(mutex_);
    try {
        if (state_ != State::AwaitingIntake ||
            receipt_.role >= 3 ||
            receipt_.accepted_head != binding.admitted_head ||
            receipt_.durable_lock != locked.binding_identity())
            throw identity_registry::Refused();
        state_ = State::Poisoned;
        const auto expected = permit_.public_receipt();
        history::RegisteredOwnerIntakeBridge::claim_owner_intake(
            locked, context, binding, receipt_.role, std::move(permit_));
        if (expected.role != receipt_.role ||
            expected.authority_identity != receipt_.authority_identity ||
            expected.selection_identity != receipt_.selection_identity ||
            expected.accepted_head != receipt_.accepted_head ||
            expected.durable_lock != receipt_.durable_lock)
            throw identity_registry::Refused();
        intake_ = expected;
        state_ = State::IntakeConsumed;
    } catch (...) {
        context.poison();
        throw identity_registry::Refused();
    }
}

} // namespace kpi::mpc::financial::registered_driver
