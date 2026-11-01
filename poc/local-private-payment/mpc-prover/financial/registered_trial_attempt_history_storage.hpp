#pragma once

#include "registered_identity_registry.hpp"
#include "registered_persistent_role_exit_history.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace kpb::measurement { struct RunBinding; }

namespace kpi::mpc::financial::registered_driver {
enum class CaptureClassification : std::uint8_t;
}

namespace kpi::mpc::financial::registered_driver::attempt_history {

using Digest = identity_registry::Digest;

// C03 is allowed to be multi-gigabyte.  The source-owned producer accounts
// exact bytes and refuses only uint64 overflow; no operational cap may abort
// a trial or make a valid retained stream unrepresentable.
inline constexpr std::uint64_t MAX_REGISTERED_ATTEMPT_C03_BYTES =
    std::numeric_limits<std::uint64_t>::max();

enum class AttemptOutcome : std::uint8_t {
    Complete = 1,
    Aborted = 2,
    Error = 3,
    Refused = 4,
    Crashed = 5,
    Partial = 6,
};

enum class AttemptStreamState : std::uint8_t {
    CompleteEnd = 1,
    ClosedWithoutEnd = 2,
    PartialHeader = 3,
    PartialPayload = 4,
    Empty = 5,
    Invalid = 6,
};

enum class AttemptFailure : std::uint8_t {
    None = 0,
    EmptyStream = 1,
    PartialHeader = 2,
    PartialPayload = 3,
    MissingEnd = 4,
    InvalidHeader = 5,
    PayloadDigestMismatch = 6,
    DuplicateEnd = 7,
    TrailingAfterEnd = 8,
    CaptureReadFailed = 9,
    ChildExitedNonzero = 10,
    ChildSignaled = 11,
    PipeCreationFailed = 12,
    ForkFailed = 13,
    RouteUnavailable = 14,
    ProducerTransportInvalid = 15,
    WaitStatusUnavailable = 16,
};

struct OwnedSealedC03Fd final {
    int value{-1};
    OwnedSealedC03Fd() = default;
    explicit OwnedSealedC03Fd(int supplied) : value(supplied) {}
    OwnedSealedC03Fd(const OwnedSealedC03Fd&) = delete;
    OwnedSealedC03Fd& operator=(const OwnedSealedC03Fd&) = delete;
    OwnedSealedC03Fd(OwnedSealedC03Fd&&) noexcept;
    OwnedSealedC03Fd& operator=(OwnedSealedC03Fd&&) = delete;
    ~OwnedSealedC03Fd();
};

struct RegisteredAttemptHistoryRowStorage final {
    unsigned round{};
    std::uint32_t ordinal{}; // Global parent observation order.
    // Frozen wire compatibility: always zero because a failed trial is never
    // retried under the same trial identity.
    std::uint32_t retry_ordinal{};
    std::string attempt_uuid;
    Digest attempt_identity{};
    Digest predecessor{}; // Always zero; same-trial retry is forbidden.
    Digest trial_predecessor{}; // Global parent sequence predecessor.
    std::uint64_t start_monotonic_ns{};
    std::uint64_t end_monotonic_ns{};
    AttemptOutcome outcome{};
    AttemptFailure failure{};
    AttemptStreamState stream_state{};
    std::int32_t wait_status{};
    std::int32_t wait_exit_code{-1};
    std::int32_t wait_signal{};
    std::uint64_t partial_tail_bytes{};
    Digest partial_tail_sha256{};
    Digest c03_sha256{};
    std::uint64_t c03_bytes{};
    std::uint64_t sealed_c03_device{};
    std::uint64_t sealed_c03_inode{};
    std::uint32_t sealed_c03_mode{};
    std::int32_t sealed_c03_seals{};
    std::int32_t sealed_c03_access_mode{-1};
    OwnedSealedC03Fd sealed_c03;
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
    Digest process_identity{};
    Digest child_exit_identity{};

    RegisteredAttemptHistoryRowStorage() = default;
    RegisteredAttemptHistoryRowStorage(
        const RegisteredAttemptHistoryRowStorage&) = delete;
    RegisteredAttemptHistoryRowStorage& operator=(
        const RegisteredAttemptHistoryRowStorage&) = delete;
    RegisteredAttemptHistoryRowStorage(
        RegisteredAttemptHistoryRowStorage&&) noexcept = default;
    RegisteredAttemptHistoryRowStorage& operator=(
        RegisteredAttemptHistoryRowStorage&&) = delete;
    ~RegisteredAttemptHistoryRowStorage() = default;
};

struct RegisteredTrialAttemptHistoryStorage final {
    CaptureClassification classification{};
    std::string capture_trial_id;
    Digest trial_identity{};
    std::vector<RegisteredAttemptHistoryRowStorage> rows;
    std::array<std::size_t, 2> final_indices{};
    Digest history_identity{};
    std::array<bool, 2> terminal_seen{};
    // Exact source-owned producer residual. The terminal consumer uses this
    // instead of reconstructing a weaker binding from row digests.
    std::unique_ptr<kpb::measurement::RunBinding> producer_binding;
    Digest producer_closure_identity{};
    Digest producer_archive_reservation_identity{};
    std::array<unsigned, 2> producer_source_slots{};
    std::array<unsigned, 2> producer_fixed_fds{};
    bool producer_writer_aliases_closed{};
    bool producer_wait_observed{};
    bool producer_pidfd_exit_observed{};
    std::int64_t producer_pid{};
    std::int32_t producer_wait_status{};
    Digest producer_child_exit_identity{};
    bool retry_closed{};
    bool failed_trial{};
    std::unique_ptr<PersistentRoleExitHistoryAuthority>
        persistent_role_exit;

    RegisteredTrialAttemptHistoryStorage();
    RegisteredTrialAttemptHistoryStorage(
        const RegisteredTrialAttemptHistoryStorage&) = delete;
    RegisteredTrialAttemptHistoryStorage& operator=(
        const RegisteredTrialAttemptHistoryStorage&) = delete;
    ~RegisteredTrialAttemptHistoryStorage();
};

} // namespace kpi::mpc::financial::registered_driver::attempt_history
