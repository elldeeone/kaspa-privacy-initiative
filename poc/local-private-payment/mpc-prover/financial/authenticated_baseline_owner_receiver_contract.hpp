#pragma once

// Complete declaration of the sole consumer allowed to inspect a consumed
// owner-effects source.  This header is intentionally dependency-light so the
// recipe can include it before granting friendship.

namespace kpi::mpc {

class MascotContext;
namespace history { class EgressRelease; }

namespace financial {

class FinancialConstruction;
namespace fresh_owner_issuance {
class BaselineOwnerRosterReceiverAuthority;
}

namespace registered_driver::baseline_disclosure {

class BaselineEffectsPlanAuthority;
class PartyBaselineOwnerEffectsAuthority;

class AuthenticatedBaselineOwnerReceiver final {
    AuthenticatedBaselineOwnerReceiver() = delete;
public:
    static PartyBaselineOwnerEffectsAuthority receive(
        MascotContext&, const FinancialConstruction&,
        const history::EgressRelease&, BaselineEffectsPlanAuthority&&,
        fresh_owner_issuance::BaselineOwnerRosterReceiverAuthority&&);
};

} // namespace registered_driver::baseline_disclosure
} // namespace financial
} // namespace kpi::mpc
