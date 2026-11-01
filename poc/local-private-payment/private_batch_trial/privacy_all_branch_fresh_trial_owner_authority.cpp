#include "privacy_all_branch_fresh_trial_owner_authority.hpp"
#include "privacy_capture_producer_runtime.hpp"
#include "../mpc-prover/financial/registered_parent_role_fork.hpp"

#include <new>
#include <utility>

namespace kpb::measurement::fresh_trial_owner {
namespace {

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

} // namespace

AllBranchFreshTrialUnavailableStopAuthority::
AllBranchFreshTrialUnavailableStopAuthority()
    : activation_failure_storage_(::operator new(
          sizeof(kpi::mpc::financial::registered_driver::
              RegisteredPersistentRoleActivationFailureResidual),
          std::align_val_t{alignof(kpi::mpc::financial::registered_driver::
              RegisteredPersistentRoleActivationFailureResidual)})) {}
AllBranchFreshTrialUnavailableStopAuthority::
AllBranchFreshTrialUnavailableStopAuthority(
        AllBranchFreshTrialUnavailableStopAuthority&& other) noexcept
    : ledger_(std::move(other.ledger_)),
      unavailable_(std::move(other.unavailable_)),
      activation_failure_storage_(
          std::exchange(other.activation_failure_storage_, nullptr)),
      destroy_activation_failure_(
          std::exchange(other.destroy_activation_failure_, nullptr)),
      activation_failure_live_(
          std::exchange(other.activation_failure_live_, false)) {}
AllBranchFreshTrialUnavailableStopAuthority::
~AllBranchFreshTrialUnavailableStopAuthority() {
    if (activation_failure_live_ && destroy_activation_failure_ != nullptr)
        destroy_activation_failure_(activation_failure_storage_);
    if (activation_failure_storage_ != nullptr)
        ::operator delete(
            activation_failure_storage_,
            std::align_val_t{alignof(kpi::mpc::financial::registered_driver::
                RegisteredPersistentRoleActivationFailureResidual)});
}

AllBranchFreshTrialOwnerAuthority::AllBranchFreshTrialOwnerAuthority(
        registered_history::RegisteredFreshTrialHistoryLedgerRecorder&& ledger)
    : ledger_(std::make_unique<registered_history::
          RegisteredFreshTrialHistoryLedgerRecorder>(std::move(ledger))),
      reserved_stop_(new AllBranchFreshTrialUnavailableStopAuthority()) {
    need(ledger_ != nullptr && reserved_stop_ != nullptr);
}

AllBranchFreshTrialOwnerAuthority::AllBranchFreshTrialOwnerAuthority(
        AllBranchFreshTrialOwnerAuthority&&) noexcept = default;
AllBranchFreshTrialOwnerAuthority::~AllBranchFreshTrialOwnerAuthority() =
    default;

AllBranchFreshTrialStepAuthority::AllBranchFreshTrialStepAuthority(
        std::unique_ptr<AllBranchFreshTrialUnavailableStopAuthority>&& stop)
        noexcept
    : stop_(std::move(stop)) {}

AllBranchFreshTrialStepAuthority::AllBranchFreshTrialStepAuthority(
        AllBranchFreshTrialStepAuthority&&) noexcept = default;
AllBranchFreshTrialStepAuthority::~AllBranchFreshTrialStepAuthority() =
    default;

AllBranchFreshTrialStepAuthority AllBranchFreshTrialOwnerBridge::append(
        AllBranchFreshTrialOwnerAuthority&& supplied_owner,
        registered_history::
            RegisteredAttemptHistoryAppendOutcomeAuthority&& supplied_outcome) {
    // Claim both linear inputs before inspecting either one. A stale outcome
    // therefore burns a fresh ledger owner, and a stale owner burns a fresh
    // outcome. No branch can be retried with the surviving half.
    auto ledger = std::move(supplied_owner.ledger_);
    auto stop = std::move(supplied_owner.reserved_stop_);
    auto complete_history = std::move(supplied_outcome.complete_history_);
    auto completion = std::move(supplied_outcome.completion_);
    auto failed_history = std::move(supplied_outcome.failed_history_);
    auto unavailable = std::move(supplied_outcome.unavailable_);

    need(ledger != nullptr && stop != nullptr &&
         complete_history == nullptr &&
         completion == nullptr && failed_history == nullptr &&
         unavailable.has_value() && !stop->activation_failure_live_);
    stop->ledger_ = std::move(ledger);
    stop->unavailable_.emplace(std::move(*unavailable));
    return AllBranchFreshTrialStepAuthority(std::move(stop));
}

#ifdef KPB_ALL_BRANCH_FRESH_TRIAL_OWNER_TEST_SETUP
AllBranchFreshTrialOwnerAuthority
AllBranchFreshTrialOwnerAuthority::test_only_begin() {
    return AllBranchFreshTrialOwnerAuthority(
        registered_history::RegisteredFreshTrialHistoryLedgerTestBridge::
            begin());
}

bool AllBranchFreshTrialStepAuthority::
test_only_is_unavailable_stop() const noexcept {
    return stop_ != nullptr && stop_->unavailable_.has_value() &&
        !stop_->activation_failure_live_;
}

bool AllBranchFreshTrialStepAuthority::
test_only_is_activation_failure_stop() const noexcept {
    return stop_ != nullptr && !stop_->unavailable_.has_value() &&
        stop_->activation_failure_live_;
}
#endif

} // namespace kpb::measurement::fresh_trial_owner
