#include "privacy_registered_fresh_trial_terminal_authority.hpp"

#include "../mpc-prover/financial/registered_fresh_trial_history_ledger.hpp"
#include "../mpc-prover/financial/registered_fresh_trial_history_ledger_storage.hpp"

#include <utility>

namespace kpi::mpc::financial::registered_driver::attempt_history {

void RegisteredTrialAttemptHistoryTerminalBridge::submit(
        kpb::measurement::empirical_result::
            RegisteredTerminalAttemptHistoryJoiner& joiner,
        RegisteredFreshTrialHistoryLedgerAuthority&& supplied) {
    // Move-claim the outer ledger before the first validation.  A mismatch
    // cannot leave a replayable success ledger behind.
    auto storage = std::move(supplied.storage_);
    joiner.accept(std::move(storage), true);
}

void RegisteredTrialAttemptHistoryTerminalBridge::submit_aborted(
        kpb::measurement::empirical_result::
            RegisteredTerminalAttemptHistoryJoiner& joiner,
        RegisteredAbortedFreshTrialHistoryLedgerAuthority&& supplied) {
    // The aborted ledger is a distinct terminal capability and can never be
    // converted into a successful observer admission.
    auto storage = std::move(supplied.storage_);
    joiner.accept(std::move(storage), false);
}

} // namespace kpi::mpc::financial::registered_driver::attempt_history
