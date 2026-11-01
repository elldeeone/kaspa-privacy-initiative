#pragma once

// Parent-owned ledger retaining every failed fresh registered trial followed
// by exactly one successful fresh trial. No production metadata/path/JSON
// factory exists in this source state.

#include "registered_fresh_trial_history_ledger_contract.hpp"
#include "registered_trial_attempt_history.hpp"

#include <atomic>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

namespace kpi::mpc::financial::registered_driver::attempt_history {

struct RegisteredFreshTrialHistoryLedgerStorage;

#ifdef KPI_REGISTERED_ATTEMPT_HISTORY_TEST_SETUP
struct TestOnlyFreshTrialLedgerSummary final {
    std::vector<std::string> capture_trial_ids;
    std::vector<bool> failed;
    Digest ledger_identity{};
};

class RegisteredFreshTrialHistoryLedgerTestBridge final {
    RegisteredFreshTrialHistoryLedgerTestBridge() = delete;
public:
    static RegisteredFreshTrialHistoryLedgerRecorder begin();
    static TestOnlyFreshTrialLedgerSummary consume(
        RegisteredFreshTrialHistoryLedgerAuthority&&);
    static TestOnlyFreshTrialLedgerSummary consume_aborted(
        RegisteredAbortedFreshTrialHistoryLedgerAuthority&&);
};
#endif

class RegisteredFreshTrialHistoryLedgerRecorder final {
    std::unique_ptr<RegisteredFreshTrialHistoryLedgerStorage> storage_;
    std::atomic_bool live_{true};
    explicit RegisteredFreshTrialHistoryLedgerRecorder(
        std::unique_ptr<RegisteredFreshTrialHistoryLedgerStorage>);
    friend class RegisteredFreshTrialHistoryLedgerBridge;
#ifdef KPI_REGISTERED_ATTEMPT_HISTORY_TEST_SETUP
    friend class RegisteredFreshTrialHistoryLedgerTestBridge;
#endif
public:
    RegisteredFreshTrialHistoryLedgerRecorder(
        const RegisteredFreshTrialHistoryLedgerRecorder&) = delete;
    RegisteredFreshTrialHistoryLedgerRecorder& operator=(
        const RegisteredFreshTrialHistoryLedgerRecorder&) = delete;
    RegisteredFreshTrialHistoryLedgerRecorder(
        RegisteredFreshTrialHistoryLedgerRecorder&&) noexcept;
    RegisteredFreshTrialHistoryLedgerRecorder& operator=(
        RegisteredFreshTrialHistoryLedgerRecorder&&) = delete;
    ~RegisteredFreshTrialHistoryLedgerRecorder();
};

class RegisteredFreshTrialHistoryLedgerAuthority final {
    std::unique_ptr<RegisteredFreshTrialHistoryLedgerStorage> storage_;
    explicit RegisteredFreshTrialHistoryLedgerAuthority(
        std::unique_ptr<RegisteredFreshTrialHistoryLedgerStorage>);
    friend class RegisteredFreshTrialHistoryLedgerBridge;
    friend class RegisteredTrialAttemptHistoryTerminalBridge;
#ifdef KPI_REGISTERED_ATTEMPT_HISTORY_TEST_SETUP
    friend class RegisteredFreshTrialHistoryLedgerTestBridge;
#endif
public:
    RegisteredFreshTrialHistoryLedgerAuthority(
        const RegisteredFreshTrialHistoryLedgerAuthority&) = delete;
    RegisteredFreshTrialHistoryLedgerAuthority& operator=(
        const RegisteredFreshTrialHistoryLedgerAuthority&) = delete;
    RegisteredFreshTrialHistoryLedgerAuthority(
        RegisteredFreshTrialHistoryLedgerAuthority&&) noexcept;
    RegisteredFreshTrialHistoryLedgerAuthority& operator=(
        RegisteredFreshTrialHistoryLedgerAuthority&&) = delete;
    ~RegisteredFreshTrialHistoryLedgerAuthority();
};

class RegisteredAbortedFreshTrialHistoryLedgerAuthority final {
    std::unique_ptr<RegisteredFreshTrialHistoryLedgerStorage> storage_;
    explicit RegisteredAbortedFreshTrialHistoryLedgerAuthority(
        std::unique_ptr<RegisteredFreshTrialHistoryLedgerStorage>);
    friend class RegisteredFreshTrialHistoryLedgerBridge;
    friend class RegisteredTrialAttemptHistoryTerminalBridge;
#ifdef KPI_REGISTERED_ATTEMPT_HISTORY_TEST_SETUP
    friend class RegisteredFreshTrialHistoryLedgerTestBridge;
#endif
public:
    RegisteredAbortedFreshTrialHistoryLedgerAuthority(
        const RegisteredAbortedFreshTrialHistoryLedgerAuthority&) = delete;
    RegisteredAbortedFreshTrialHistoryLedgerAuthority& operator=(
        const RegisteredAbortedFreshTrialHistoryLedgerAuthority&) = delete;
    RegisteredAbortedFreshTrialHistoryLedgerAuthority(
        RegisteredAbortedFreshTrialHistoryLedgerAuthority&&) noexcept;
    RegisteredAbortedFreshTrialHistoryLedgerAuthority& operator=(
        RegisteredAbortedFreshTrialHistoryLedgerAuthority&&) = delete;
    ~RegisteredAbortedFreshTrialHistoryLedgerAuthority();
};

} // namespace kpi::mpc::financial::registered_driver::attempt_history
