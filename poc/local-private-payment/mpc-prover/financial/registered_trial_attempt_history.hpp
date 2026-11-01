#pragma once

// Parent-owned, source-only history for every registered C03 attempt.  The
// selected parent factory and terminal consumer deliberately remain absent:
// CONFIGURED0 cannot mint or consume this authority in production yet.

#include "registered_trial_attempt_history_contract.hpp"
#include "registered_fresh_trial_history_ledger_contract.hpp"
#include "registered_trial_attempt_history_storage.hpp"
#include "registered_persistent_role_exit_history.hpp"
#include "../../private_batch_trial/privacy_capture_producer_runtime.hpp"
#include "../../private_batch_trial/privacy_registered_attempt_history_bridge_contract.hpp"
#include "../../private_batch_trial/privacy_all_branch_fresh_trial_owner_contract.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace kpi::mpc::financial::registered_driver::attempt_history {

class RegisteredTrialAttemptHistoryRecorder;
class RegisteredTrialAttemptHistoryAuthority;
class RegisteredFailedTrialAttemptHistoryAuthority;
class RegisteredUnavailableTrialAttemptHistoryAuthority;
class RegisteredAttemptHistoryAppendOutcomeAuthority;

class AttemptHistoryRefused final : public std::exception {
public:
    const char* what() const noexcept override;
};

#ifdef KPI_REGISTERED_ATTEMPT_HISTORY_TEST_SETUP
struct TestOnlyTrialBinding {
    CaptureClassification classification{};
    std::string capture_trial_id;
    Digest trial_identity{};
};

enum class TestOnlySealedC03Fault : std::uint8_t {
    None = 0,
    RetainWritable = 1,
    SubstituteInode = 2,
};

struct TestOnlyAttemptBinding {
    unsigned round{};
    std::string attempt_uuid;
    Digest financial_run{};
    Digest cohort{};
    Digest capture_plan{};
    Digest projection{};
    Digest capture_source{};
    Digest capture_build{};
    Digest capture_runtime{};
    Digest capture_launcher{};
    Digest route_requirement{};
    Digest route_completion{};
    TestOnlySealedC03Fault sealed_c03_fault{};
};

enum class TestOnlyChildDisposition : std::uint8_t {
    ExitZero = 1,
    ExitNonzero = 2,
    Signal = 3,
};

struct TestOnlyAttemptSummary {
    unsigned round{};
    std::uint32_t ordinal{};
    std::uint32_t retry_ordinal{};
    std::string attempt_uuid;
    Digest attempt_identity{};
    Digest predecessor{};
    Digest trial_predecessor{};
    std::uint64_t start_monotonic_ns{};
    std::uint64_t end_monotonic_ns{};
    AttemptOutcome outcome{};
    AttemptFailure failure{};
    AttemptStreamState stream_state{};
    std::int32_t wait_exit_code{-1};
    std::int32_t wait_signal{};
    std::uint64_t partial_tail_bytes{};
    Digest partial_tail_sha256{};
    Digest c03_sha256{};
    std::uint64_t c03_bytes{};
    std::uint64_t sealed_c03_device{};
    std::uint64_t sealed_c03_inode{};
    std::int32_t sealed_c03_seals{};
    std::int32_t sealed_c03_access_mode{-1};
    Digest route_requirement{};
    Digest route_completion{};
    Digest process_identity{};
    Digest child_exit_identity{};
};

struct TestOnlyHistorySummary {
    std::vector<TestOnlyAttemptSummary> rows;
    std::array<std::size_t, 2> final_indices{};
    Digest history_identity{};
};

class RegisteredTrialAttemptHistoryTestBridge final {
    RegisteredTrialAttemptHistoryTestBridge() = delete;
public:
    static RegisteredTrialAttemptHistoryRecorder begin(
        TestOnlyTrialBinding);
    static void observe(
        RegisteredTrialAttemptHistoryRecorder&, TestOnlyAttemptBinding,
        std::span<const unsigned char> bytes, std::size_t bytes_to_write,
        TestOnlyChildDisposition, int value);
    static TestOnlyHistorySummary consume(
        RegisteredTrialAttemptHistoryAuthority&&);
    static TestOnlyHistorySummary consume_failed(
        RegisteredFailedTrialAttemptHistoryAuthority&&);
};
#endif

class RegisteredTrialAttemptHistoryRecorder final {
    std::unique_ptr<RegisteredTrialAttemptHistoryStorage> storage_;
    std::atomic_bool live_{true};
    std::mutex mutex_;
    explicit RegisteredTrialAttemptHistoryRecorder(
        std::unique_ptr<RegisteredTrialAttemptHistoryStorage>);
    friend class RegisteredCaptureAttemptHistoryBridge;
    friend class RegisteredUnavailableTrialAttemptHistoryAuthority;
    friend class RegisteredParentTrialHistoryBridge;
#ifdef KPI_REGISTERED_ATTEMPT_HISTORY_TEST_SETUP
    friend class RegisteredTrialAttemptHistoryTestBridge;
#endif
public:
    RegisteredTrialAttemptHistoryRecorder(
        const RegisteredTrialAttemptHistoryRecorder&) = delete;
    RegisteredTrialAttemptHistoryRecorder& operator=(
        const RegisteredTrialAttemptHistoryRecorder&) = delete;
    RegisteredTrialAttemptHistoryRecorder(
        RegisteredTrialAttemptHistoryRecorder&&) noexcept;
    RegisteredTrialAttemptHistoryRecorder& operator=(
        RegisteredTrialAttemptHistoryRecorder&&) = delete;
    ~RegisteredTrialAttemptHistoryRecorder();

    static RegisteredTrialAttemptHistoryAuthority seal(
        RegisteredTrialAttemptHistoryRecorder&&);
    static RegisteredFailedTrialAttemptHistoryAuthority seal_failed(
        RegisteredTrialAttemptHistoryRecorder&&);
};

class RegisteredTrialAttemptHistoryAuthority final {
    std::unique_ptr<RegisteredTrialAttemptHistoryStorage> storage_;
    explicit RegisteredTrialAttemptHistoryAuthority(
        std::unique_ptr<RegisteredTrialAttemptHistoryStorage>);
    friend class RegisteredTrialAttemptHistoryRecorder;
    friend class RegisteredFreshTrialHistoryLedgerBridge;
#ifdef KPI_REGISTERED_ATTEMPT_HISTORY_TEST_SETUP
    friend class RegisteredTrialAttemptHistoryTestBridge;
#endif
public:
    RegisteredTrialAttemptHistoryAuthority(
        const RegisteredTrialAttemptHistoryAuthority&) = delete;
    RegisteredTrialAttemptHistoryAuthority& operator=(
        const RegisteredTrialAttemptHistoryAuthority&) = delete;
    RegisteredTrialAttemptHistoryAuthority(
        RegisteredTrialAttemptHistoryAuthority&&) noexcept;
    RegisteredTrialAttemptHistoryAuthority& operator=(
        RegisteredTrialAttemptHistoryAuthority&&) = delete;
    ~RegisteredTrialAttemptHistoryAuthority();
};

// Whole-trial failure evidence. It retains every C03 object observed by the
// sole producer attempt and cannot be converted into a successful history.
class RegisteredFailedTrialAttemptHistoryAuthority final {
    std::unique_ptr<RegisteredTrialAttemptHistoryStorage> storage_;
    explicit RegisteredFailedTrialAttemptHistoryAuthority(
        std::unique_ptr<RegisteredTrialAttemptHistoryStorage>);
    friend class RegisteredTrialAttemptHistoryRecorder;
    friend class RegisteredFreshTrialHistoryLedgerBridge;
#ifdef KPI_REGISTERED_ATTEMPT_HISTORY_TEST_SETUP
    friend class RegisteredTrialAttemptHistoryTestBridge;
#endif
public:
    RegisteredFailedTrialAttemptHistoryAuthority(
        const RegisteredFailedTrialAttemptHistoryAuthority&) = delete;
    RegisteredFailedTrialAttemptHistoryAuthority& operator=(
        const RegisteredFailedTrialAttemptHistoryAuthority&) = delete;
    RegisteredFailedTrialAttemptHistoryAuthority(
        RegisteredFailedTrialAttemptHistoryAuthority&&) noexcept;
    RegisteredFailedTrialAttemptHistoryAuthority& operator=(
        RegisteredFailedTrialAttemptHistoryAuthority&&) = delete;
    ~RegisteredFailedTrialAttemptHistoryAuthority();
};

// Run-invalidating owner of an attempt that cannot truthfully become a
// complete success or complete-failed view. It retains both the unsealed
// recorder context and the entire opaque producer outcome (including archive
// quarantine). There is no receipt or state accessor.
class RegisteredUnavailableTrialAttemptHistoryAuthority final {
    std::unique_ptr<RegisteredTrialAttemptHistoryStorage> recorder_storage_;
    std::optional<kpb::measurement::producer_runtime::
        ProducerAttemptRegisteredOutcomeTransfer> outcome_;
    RegisteredUnavailableTrialAttemptHistoryAuthority(
        RegisteredTrialAttemptHistoryRecorder&&,
        kpb::measurement::producer_runtime::
            ProducerAttemptRegisteredOutcomeTransfer&&);
    friend class RegisteredCaptureAttemptHistoryBridge;
    friend class ::kpb::measurement::fresh_trial_owner::
        AllBranchFreshTrialOwnerBridge;
public:
    RegisteredUnavailableTrialAttemptHistoryAuthority(
        const RegisteredUnavailableTrialAttemptHistoryAuthority&) = delete;
    RegisteredUnavailableTrialAttemptHistoryAuthority& operator=(
        const RegisteredUnavailableTrialAttemptHistoryAuthority&) = delete;
    RegisteredUnavailableTrialAttemptHistoryAuthority(
        RegisteredUnavailableTrialAttemptHistoryAuthority&&) noexcept;
    RegisteredUnavailableTrialAttemptHistoryAuthority& operator=(
        RegisteredUnavailableTrialAttemptHistoryAuthority&&) = delete;
    ~RegisteredUnavailableTrialAttemptHistoryAuthority();
};

// Closed sum returned by the atomic recorder/outcome bridge. Only the
// complete all-branch owner can inspect or consume its arm. Until the typed
// observer-v5 child-state capsule exists, the bridge deliberately emits only
// the unavailable/STOP arm.
class RegisteredAttemptHistoryAppendOutcomeAuthority final {
    std::unique_ptr<RegisteredTrialAttemptHistoryAuthority>
        complete_history_;
    std::unique_ptr<kpb::measurement::producer_runtime::
        ProducerRuntimeCompletion> completion_;
    std::unique_ptr<RegisteredFailedTrialAttemptHistoryAuthority>
        failed_history_;
    std::optional<RegisteredUnavailableTrialAttemptHistoryAuthority>
        unavailable_;
    explicit RegisteredAttemptHistoryAppendOutcomeAuthority(
        RegisteredUnavailableTrialAttemptHistoryAuthority&&);
    friend class RegisteredCaptureAttemptHistoryBridge;
    friend class ::kpb::measurement::fresh_trial_owner::
        AllBranchFreshTrialOwnerBridge;
public:
    RegisteredAttemptHistoryAppendOutcomeAuthority(
        const RegisteredAttemptHistoryAppendOutcomeAuthority&) = delete;
    RegisteredAttemptHistoryAppendOutcomeAuthority& operator=(
        const RegisteredAttemptHistoryAppendOutcomeAuthority&) = delete;
    RegisteredAttemptHistoryAppendOutcomeAuthority(
        RegisteredAttemptHistoryAppendOutcomeAuthority&&) noexcept;
    RegisteredAttemptHistoryAppendOutcomeAuthority& operator=(
        RegisteredAttemptHistoryAppendOutcomeAuthority&&) = delete;
    ~RegisteredAttemptHistoryAppendOutcomeAuthority();
};

struct RegisteredTrialAttemptHistorySourceStatus {
    bool os_derived_monotonic_and_wait{};
    bool exact_sealed_c03_per_attempt{};
    bool immutable_linear_failures{};
    bool two_independent_round_chains{};
    bool global_parent_sequence{};
    bool unique_terminal_complete_attempt{};
    bool producer_atomic_append_bridge{};
    bool recorder_factory{};
    bool failed_fresh_trial_authority{};
    bool outer_fresh_trial_ledger{};
    bool outer_fresh_trial_ledger_factory{};
    bool fresh_attempt_authority_bridge{};
    bool selected_parent_callsite{};
    bool terminal_capture_consumer{};
    bool configured{};
};

inline constexpr RegisteredTrialAttemptHistorySourceStatus
    kRegisteredTrialAttemptHistorySourceStatus{
        .os_derived_monotonic_and_wait = true,
        .exact_sealed_c03_per_attempt = true,
        .immutable_linear_failures = true,
        .two_independent_round_chains = true,
        .global_parent_sequence = true,
        .unique_terminal_complete_attempt = true,
        .producer_atomic_append_bridge = true,
        .recorder_factory = false,
        .failed_fresh_trial_authority = true,
        .outer_fresh_trial_ledger = true,
        .outer_fresh_trial_ledger_factory = false,
        .fresh_attempt_authority_bridge = false,
        .selected_parent_callsite = false,
        .terminal_capture_consumer = false,
        .configured = false,
    };

} // namespace kpi::mpc::financial::registered_driver::attempt_history
