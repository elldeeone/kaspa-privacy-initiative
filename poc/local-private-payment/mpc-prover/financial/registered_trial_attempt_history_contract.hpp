#pragma once

// Complete neutral consumer contract.  The terminal/observer implementation
// may consume the private history only through this exact class; keeping the
// definition here prevents an external TU from defining a lookalike friend.

namespace kpb::measurement::empirical_result {
class RegisteredTerminalAttemptHistoryJoiner;
}

namespace kpi::mpc::financial::registered_driver::attempt_history {

class RegisteredFreshTrialHistoryLedgerAuthority;
class RegisteredAbortedFreshTrialHistoryLedgerAuthority;

class RegisteredTrialAttemptHistoryTerminalBridge final {
    RegisteredTrialAttemptHistoryTerminalBridge() = delete;
public:
    static void submit(
        kpb::measurement::empirical_result::
            RegisteredTerminalAttemptHistoryJoiner&,
        RegisteredFreshTrialHistoryLedgerAuthority&&);
    static void submit_aborted(
        kpb::measurement::empirical_result::
            RegisteredTerminalAttemptHistoryJoiner&,
        RegisteredAbortedFreshTrialHistoryLedgerAuthority&&);
};

} // namespace kpi::mpc::financial::registered_driver::attempt_history
