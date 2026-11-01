#include "privacy_all_branch_fresh_trial_owner_authority.hpp"
#include "../mpc-prover/financial/registered_parent_role_fork.hpp"

#include <new>
#include <utility>

namespace kpb::measurement::fresh_trial_owner {
namespace {

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

using ActivationFailure = kpi::mpc::financial::registered_driver::
    RegisteredPersistentRoleActivationFailureResidual;

void destroy_activation_failure(void* storage) noexcept {
    static_cast<ActivationFailure*>(storage)->~ActivationFailure();
}

} // namespace

AllBranchFreshTrialStepAuthority
AllBranchFreshTrialOwnerBridge::stop_after_activation_failure(
        AllBranchFreshTrialOwnerAuthority&& supplied_owner,
        ActivationFailure&& supplied_failure) {
    // Burn both capabilities before the first validating transfer. A stale
    // activation residual therefore burns a fresh ledger owner, and a stale
    // owner burns the genuine composite failure residual.
    auto ledger = std::move(supplied_owner.ledger_);
    auto stop = std::move(supplied_owner.reserved_stop_);
    auto failure = std::move(supplied_failure)
        .transfer_for_all_branch_stop();
    need(ledger != nullptr && stop != nullptr &&
         !stop->unavailable_.has_value() &&
         !stop->activation_failure_live_ &&
         stop->activation_failure_storage_ != nullptr &&
         stop->destroy_activation_failure_ == nullptr);
    ::new (stop->activation_failure_storage_)
        ActivationFailure(std::move(failure));
    stop->destroy_activation_failure_ = destroy_activation_failure;
    stop->activation_failure_live_ = true;
    stop->ledger_ = std::move(ledger);
    return AllBranchFreshTrialStepAuthority(std::move(stop));
}

} // namespace kpb::measurement::fresh_trial_owner
