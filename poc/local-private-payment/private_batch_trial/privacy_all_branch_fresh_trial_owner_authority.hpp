#pragma once

// Fail-closed owner of the outer fresh-trial ledger.  The selected factory,
// observer-v5 P1 state capsule and mandatory abort sink do not exist yet, so
// the only implemented transition is an opaque run-invalidating STOP.

#include "privacy_all_branch_fresh_trial_owner_contract.hpp"
#include "privacy_fresh_owner_round1_outcome_consumer_contract.hpp"
#include "../mpc-prover/financial/registered_fresh_trial_history_ledger.hpp"

#include <memory>
#include <optional>

namespace kpb::measurement::fresh_trial_owner {

namespace registered_history =
    kpi::mpc::financial::registered_driver::attempt_history;

class AllBranchFreshTrialUnavailableStopAuthority final {
    std::unique_ptr<registered_history::
        RegisteredFreshTrialHistoryLedgerRecorder> ledger_;
    std::optional<registered_history::
        RegisteredUnavailableTrialAttemptHistoryAuthority> unavailable_;
    void* activation_failure_storage_{};
    void (*destroy_activation_failure_)(void*) noexcept{};
    bool activation_failure_live_{};
    AllBranchFreshTrialUnavailableStopAuthority();
    friend class AllBranchFreshTrialOwnerAuthority;
    friend class AllBranchFreshTrialOwnerBridge;
    friend class AllBranchFreshTrialStepAuthority;
public:
    AllBranchFreshTrialUnavailableStopAuthority(
        const AllBranchFreshTrialUnavailableStopAuthority&) = delete;
    AllBranchFreshTrialUnavailableStopAuthority& operator=(
        const AllBranchFreshTrialUnavailableStopAuthority&) = delete;
    AllBranchFreshTrialUnavailableStopAuthority(
        AllBranchFreshTrialUnavailableStopAuthority&&) noexcept;
    AllBranchFreshTrialUnavailableStopAuthority& operator=(
        AllBranchFreshTrialUnavailableStopAuthority&&) = delete;
    ~AllBranchFreshTrialUnavailableStopAuthority();
};

class AllBranchFreshTrialOwnerAuthority final {
    std::unique_ptr<registered_history::
        RegisteredFreshTrialHistoryLedgerRecorder> ledger_;
    std::unique_ptr<AllBranchFreshTrialUnavailableStopAuthority>
        reserved_stop_;
    explicit AllBranchFreshTrialOwnerAuthority(
        registered_history::RegisteredFreshTrialHistoryLedgerRecorder&&);
    friend class AllBranchFreshTrialOwnerBridge;
    friend class FreshOwnerRound1AttemptConsumerBridge;
public:
    AllBranchFreshTrialOwnerAuthority(
        const AllBranchFreshTrialOwnerAuthority&) = delete;
    AllBranchFreshTrialOwnerAuthority& operator=(
        const AllBranchFreshTrialOwnerAuthority&) = delete;
    AllBranchFreshTrialOwnerAuthority(
        AllBranchFreshTrialOwnerAuthority&&) noexcept;
    AllBranchFreshTrialOwnerAuthority& operator=(
        AllBranchFreshTrialOwnerAuthority&&) = delete;
    ~AllBranchFreshTrialOwnerAuthority();
#ifdef KPB_ALL_BRANCH_FRESH_TRIAL_OWNER_TEST_SETUP
    static AllBranchFreshTrialOwnerAuthority test_only_begin();
#endif
};

class AllBranchFreshTrialStepAuthority final {
    std::unique_ptr<AllBranchFreshTrialUnavailableStopAuthority> stop_;
    explicit AllBranchFreshTrialStepAuthority(
        std::unique_ptr<AllBranchFreshTrialUnavailableStopAuthority>&&) noexcept;
    friend class AllBranchFreshTrialOwnerBridge;
public:
    AllBranchFreshTrialStepAuthority(
        const AllBranchFreshTrialStepAuthority&) = delete;
    AllBranchFreshTrialStepAuthority& operator=(
        const AllBranchFreshTrialStepAuthority&) = delete;
    AllBranchFreshTrialStepAuthority(
        AllBranchFreshTrialStepAuthority&&) noexcept;
    AllBranchFreshTrialStepAuthority& operator=(
        AllBranchFreshTrialStepAuthority&&) = delete;
    ~AllBranchFreshTrialStepAuthority();
#ifdef KPB_ALL_BRANCH_FRESH_TRIAL_OWNER_TEST_SETUP
    bool test_only_is_unavailable_stop() const noexcept;
    bool test_only_is_activation_failure_stop() const noexcept;
#endif
};

struct AllBranchFreshTrialOwnerSourceStatus final {
    bool ledger_acquired_before_trial_identity{};
    bool atomic_outcome_and_ledger_claim{};
    bool unavailable_is_run_invalidating_stop{};
    bool postissuance_activation_failure_stop{};
    bool live_process_linear_quarantine_owner{};
    bool allocation_failure_no_drop{};
    bool process_crash_durable{};
    bool power_loss_durable{};
    bool observer_v5_p1_state_capsule{};
    bool complete_failed_view_continuation{};
    bool final_success_terminal{};
    bool mandatory_abort_sink{};
    bool selected_factory{};
    bool configured{};
};

inline constexpr AllBranchFreshTrialOwnerSourceStatus
    kAllBranchFreshTrialOwnerSourceStatus{
        .ledger_acquired_before_trial_identity = false,
        .atomic_outcome_and_ledger_claim = true,
        .unavailable_is_run_invalidating_stop = true,
        .postissuance_activation_failure_stop = false,
        .live_process_linear_quarantine_owner = true,
        .allocation_failure_no_drop = false,
        .process_crash_durable = false,
        .power_loss_durable = false,
        .observer_v5_p1_state_capsule = false,
        .complete_failed_view_continuation = false,
        .final_success_terminal = false,
        .mandatory_abort_sink = false,
        .selected_factory = false,
        .configured = false,
    };

} // namespace kpb::measurement::fresh_trial_owner
