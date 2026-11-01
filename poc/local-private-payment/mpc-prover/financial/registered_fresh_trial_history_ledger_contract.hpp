#pragma once

// Complete neutral bridge contract. Keeping the exact friend type complete in
// this header prevents an external translation unit from defining a lookalike
// class to extract or reconstruct private trial-history authorities.

#include <memory>

namespace kpi::mpc::financial::registered_driver::attempt_history {

class RegisteredTrialAttemptHistoryAuthority;
class RegisteredFailedTrialAttemptHistoryAuthority;
class RegisteredFreshTrialHistoryLedgerRecorder;
class RegisteredFreshTrialHistoryLedgerAuthority;
class RegisteredAbortedFreshTrialHistoryLedgerAuthority;
struct RegisteredTrialAttemptHistoryStorage;

class RegisteredFreshTrialHistoryLedgerBridge final {
    RegisteredFreshTrialHistoryLedgerBridge() = delete;
    static void append(
        RegisteredFreshTrialHistoryLedgerRecorder&,
        std::unique_ptr<RegisteredTrialAttemptHistoryStorage>, bool);
public:
    static void append_failed(
        RegisteredFreshTrialHistoryLedgerRecorder&,
        RegisteredFailedTrialAttemptHistoryAuthority&&);
    static void append_complete(
        RegisteredFreshTrialHistoryLedgerRecorder&,
        RegisteredTrialAttemptHistoryAuthority&&);
    static RegisteredFreshTrialHistoryLedgerAuthority seal(
        RegisteredFreshTrialHistoryLedgerRecorder&&);
    static RegisteredAbortedFreshTrialHistoryLedgerAuthority seal_aborted(
        RegisteredFreshTrialHistoryLedgerRecorder&&);
};

} // namespace kpi::mpc::financial::registered_driver::attempt_history
