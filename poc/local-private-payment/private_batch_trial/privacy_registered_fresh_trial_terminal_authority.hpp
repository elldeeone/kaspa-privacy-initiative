#pragma once

// Opaque terminal form of the registered outer fresh-trial ledger.  It keeps
// every failed fresh trial and exactly one final success (or an all-failed
// abort) as live typed storage.  KPBEMPH1/KPBEMPC1 bytes, caller digests and
// reconstructed attempt lists are deliberately not accepted here.

#include "privacy_measurement_authority.hpp"
#include "../mpc-prover/financial/registered_trial_attempt_history_contract.hpp"

#include <atomic>
#include <cstddef>
#include <memory>

namespace kpi::mpc::financial::registered_driver::attempt_history {
struct RegisteredFreshTrialHistoryLedgerStorage;
}

namespace kpb::measurement::empirical_result {

class RegisteredFreshTrialTerminalHistoryAuthority final {
    using Storage = kpi::mpc::financial::registered_driver::attempt_history::
        RegisteredFreshTrialHistoryLedgerStorage;
    std::unique_ptr<Storage> storage_;
    Digest private_identity_{};
    RegisteredFreshTrialTerminalHistoryAuthority(
        std::unique_ptr<Storage>, Digest);
    friend class RegisteredTerminalAttemptHistoryJoiner;
public:
    RegisteredFreshTrialTerminalHistoryAuthority(
        const RegisteredFreshTrialTerminalHistoryAuthority&) = delete;
    RegisteredFreshTrialTerminalHistoryAuthority& operator=(
        const RegisteredFreshTrialTerminalHistoryAuthority&) = delete;
    RegisteredFreshTrialTerminalHistoryAuthority(
        RegisteredFreshTrialTerminalHistoryAuthority&&) noexcept;
    RegisteredFreshTrialTerminalHistoryAuthority& operator=(
        RegisteredFreshTrialTerminalHistoryAuthority&&) = delete;
    ~RegisteredFreshTrialTerminalHistoryAuthority();
};

class RegisteredAbortedFreshTrialTerminalHistoryAuthority final {
    using Storage = kpi::mpc::financial::registered_driver::attempt_history::
        RegisteredFreshTrialHistoryLedgerStorage;
    std::unique_ptr<Storage> storage_;
    Digest private_identity_{};
    RegisteredAbortedFreshTrialTerminalHistoryAuthority(
        std::unique_ptr<Storage>, Digest);
    friend class RegisteredTerminalAttemptHistoryJoiner;
public:
    RegisteredAbortedFreshTrialTerminalHistoryAuthority(
        const RegisteredAbortedFreshTrialTerminalHistoryAuthority&) = delete;
    RegisteredAbortedFreshTrialTerminalHistoryAuthority& operator=(
        const RegisteredAbortedFreshTrialTerminalHistoryAuthority&) = delete;
    RegisteredAbortedFreshTrialTerminalHistoryAuthority(
        RegisteredAbortedFreshTrialTerminalHistoryAuthority&&) noexcept;
    RegisteredAbortedFreshTrialTerminalHistoryAuthority& operator=(
        RegisteredAbortedFreshTrialTerminalHistoryAuthority&&) = delete;
    ~RegisteredAbortedFreshTrialTerminalHistoryAuthority();
};

class RegisteredTerminalAttemptHistoryJoiner final {
    using Storage = kpi::mpc::financial::registered_driver::attempt_history::
        RegisteredFreshTrialHistoryLedgerStorage;
    enum class Mode : unsigned char { Success, Aborted };
    Mode mode_;
    std::unique_ptr<Storage> storage_;
    Digest private_identity_{};
    std::atomic_bool accepting_{true};
    std::atomic_bool finish_live_{true};
    bool poisoned_{};
    explicit RegisteredTerminalAttemptHistoryJoiner(Mode);
    void accept(std::unique_ptr<Storage>, bool complete);
    friend class kpi::mpc::financial::registered_driver::attempt_history::
        RegisteredTrialAttemptHistoryTerminalBridge;
public:
    static RegisteredTerminalAttemptHistoryJoiner for_final_success();
    static RegisteredTerminalAttemptHistoryJoiner for_aborted_run();
    RegisteredTerminalAttemptHistoryJoiner(
        const RegisteredTerminalAttemptHistoryJoiner&) = delete;
    RegisteredTerminalAttemptHistoryJoiner& operator=(
        const RegisteredTerminalAttemptHistoryJoiner&) = delete;
    RegisteredTerminalAttemptHistoryJoiner(
        RegisteredTerminalAttemptHistoryJoiner&&) noexcept;
    RegisteredTerminalAttemptHistoryJoiner& operator=(
        RegisteredTerminalAttemptHistoryJoiner&&) = delete;
    ~RegisteredTerminalAttemptHistoryJoiner();

    RegisteredFreshTrialTerminalHistoryAuthority finish_success() &&;
    RegisteredAbortedFreshTrialTerminalHistoryAuthority finish_aborted() &&;

#ifdef KPB_REGISTERED_FRESH_TRIAL_TERMINAL_TEST_SETUP
    // Exercises the exact validator without minting a financial ledger
    // capability. Absent from production and never accepted by TrialCapture.
    static void test_only_accept_storage(
        RegisteredTerminalAttemptHistoryJoiner&,
        std::unique_ptr<Storage>, bool complete);
#endif
};

struct RegisteredFreshTrialTerminalSourceStatus final {
    bool ordered_unbounded_fresh_trials{};
    bool exactly_two_actual_c03_rows_per_trial{};
    bool full_producer_residual_retained{};
    bool sealed_c03_revalidated{};
    bool pidfd_wait_failure_preserved{};
    bool typed_pidfd_exit_evidence{};
    bool fresh_trial_bound_closure_authority{};
    bool legacy_kpbemph1_accepted{};
    bool final_observer_archive_join{};
    bool selected_runtime_callsite{};
    bool configured{};
};

inline constexpr RegisteredFreshTrialTerminalSourceStatus
kRegisteredFreshTrialTerminalSourceStatus{
    .ordered_unbounded_fresh_trials = true,
    .exactly_two_actual_c03_rows_per_trial = true,
    .full_producer_residual_retained = true,
    .sealed_c03_revalidated = true,
    .pidfd_wait_failure_preserved = true,
    // The validator now requires the exact move-only pidfd exit residual and
    // refuses the former boolean/status-only fixture. Keep this false until a
    // genuine persistent-parent -> recorder -> ledger -> terminal control also
    // covers missing, moved and replayed residuals.
    .typed_pidfd_exit_evidence = false,
    // The current producer launch plan still carries a caller-supplied
    // opaque closure identity. Distinctness is checked below, but it is not
    // authority until the parent mints and linearly binds it to a fresh trial.
    .fresh_trial_bound_closure_authority = false,
    .legacy_kpbemph1_accepted = false,
};

} // namespace kpb::measurement::empirical_result
