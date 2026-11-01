#pragma once

// Native, opaque result for the ten exact within-run empirical rows.
// Production construction is reserved to the complete observer capsule
// bridge after it owns the terminal-attached observer conjunction.  There is
// no raw fd/body/digest/count constructor or selected runtime callsite yet.

#include "privacy_measurement_authority.hpp"
#include "privacy_measurement_observer_capture_bridge_contract.hpp"
#include "privacy_native_phase_scope_bridge_contract.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>

namespace kpb::measurement::empirical_result {

inline constexpr std::size_t EMPIRICAL_ROUNDS = 2;
inline constexpr std::size_t EMPIRICAL_FIELDS = 5;
inline constexpr std::size_t EMPIRICAL_CANDIDATES = 2;
inline constexpr std::size_t EMPIRICAL_OCCURRENCES =
    EMPIRICAL_ROUNDS * EMPIRICAL_FIELDS;
inline constexpr std::size_t MAX_EMPIRICAL_ATTEMPTS_PER_ROUND = 64;
inline constexpr std::uint16_t EMPIRICAL_EVIDENCE_FAMILY_CODE = 24;
inline constexpr std::uint16_t EMPIRICAL_OCCURRENCE_MASK = 0x03ff;
inline constexpr std::array<std::uint8_t, 2> EMPIRICAL_VIEW_CODES{3, 4};
inline constexpr std::array<std::string_view, EMPIRICAL_FIELDS>
    EMPIRICAL_FIELD_PATHS{
        "attempt.abort_retry_partial_transcript",
        "wire.frames[].direction_peer_fork",
        "wire.frames[].monotonic_ns",
        "wire.frames[].payload_length",
        "wire.frames[].sequence_message_chunk_order",
    };
inline constexpr Digest FROZEN_EVIDENCE_REGISTRY_IDENTITY{
    0xee, 0x70, 0x00, 0x75, 0x72, 0x0d, 0xa6, 0x29,
    0xec, 0xfe, 0xd7, 0xbc, 0x43, 0xf9, 0x72, 0x5d,
    0x14, 0x82, 0x6f, 0xc2, 0xd0, 0xec, 0xd2, 0x01,
    0x87, 0x8a, 0x1c, 0x2d, 0x6b, 0xf8, 0x67, 0x08,
};

enum class EmpiricalField : std::uint8_t {
    AbortRetryPartialTranscript = 1,
    DirectionPeerFork = 2,
    MonotonicTime = 3,
    PayloadLength = 4,
    SequenceMessageChunkOrder = 5,
};

enum class EmpiricalAttemptOutcome : std::uint8_t {
    Complete = 1,
    Aborted = 2,
    Error = 3,
    Refused = 4,
    Crashed = 5,
    Partial = 6,
};

enum class EmpiricalStreamState : std::uint8_t {
    CompleteEnd = 1,
    ClosedWithoutEnd = 2,
    PartialHeader = 3,
    PartialPayload = 4,
};

class EmpiricalCaptureHistoryAuthority;
class FrozenEmpiricalCandidateSetAuthority;
class NativeEmpiricalResultAuthority;

#ifdef KPB_NATIVE_EMPIRICAL_RESULT_TEST_SETUP
struct TestOnlyNativeEmpiricalResultSummary {
    std::array<std::uint8_t, EMPIRICAL_OCCURRENCES>
        candidate_match_masks{};
    std::uint8_t retained_candidate_mask{};
    std::array<std::uint8_t, 2> bound_view_codes{};
};
#endif

class NativeEmpiricalResultDeriver final {
    NativeEmpiricalResultDeriver() = delete;
public:
    static NativeEmpiricalResultAuthority derive(
        EmpiricalCaptureHistoryAuthority&&,
        FrozenEmpiricalCandidateSetAuthority&&);
#ifdef KPB_NATIVE_EMPIRICAL_RESULT_TEST_SETUP
    // Control-only factories consume sealed read-only memfds. They are absent
    // from production and cannot establish a selected callsite.
    static EmpiricalCaptureHistoryAuthority test_only_admit_history(
        const RunBinding&, int sealed_read_fd);
    static FrozenEmpiricalCandidateSetAuthority
        test_only_admit_candidate_set(
            const RunBinding&, int sealed_read_fd);
    static TestOnlyNativeEmpiricalResultSummary test_only_consume(
        NativeEmpiricalResultAuthority&&);
#endif
};

class EmpiricalCaptureHistoryAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    EmpiricalCaptureHistoryAuthority(const RunBinding&, int sealed_read_fd);
    friend class NativeEmpiricalResultDeriver;
    friend class runtime_bridge::ObserverCaptureCapsuleBridge;
public:
    EmpiricalCaptureHistoryAuthority(
        const EmpiricalCaptureHistoryAuthority&) = delete;
    EmpiricalCaptureHistoryAuthority& operator=(
        const EmpiricalCaptureHistoryAuthority&) = delete;
    EmpiricalCaptureHistoryAuthority(
        EmpiricalCaptureHistoryAuthority&&) noexcept;
    EmpiricalCaptureHistoryAuthority& operator=(
        EmpiricalCaptureHistoryAuthority&&) = delete;
    ~EmpiricalCaptureHistoryAuthority();
};

class FrozenEmpiricalCandidateSetAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    FrozenEmpiricalCandidateSetAuthority(
        const RunBinding&, int sealed_read_fd);
    friend class NativeEmpiricalResultDeriver;
    friend class runtime_bridge::ObserverCaptureCapsuleBridge;
public:
    FrozenEmpiricalCandidateSetAuthority(
        const FrozenEmpiricalCandidateSetAuthority&) = delete;
    FrozenEmpiricalCandidateSetAuthority& operator=(
        const FrozenEmpiricalCandidateSetAuthority&) = delete;
    FrozenEmpiricalCandidateSetAuthority(
        FrozenEmpiricalCandidateSetAuthority&&) noexcept;
    FrozenEmpiricalCandidateSetAuthority& operator=(
        FrozenEmpiricalCandidateSetAuthority&&) = delete;
    ~FrozenEmpiricalCandidateSetAuthority();
};

class NativeEmpiricalResultAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit NativeEmpiricalResultAuthority(std::unique_ptr<Storage>);
    NativeEmpiricalResultAuthority transfer_for_observation_output_join(
        const RunBinding&) &&;
    friend class NativeEmpiricalResultDeriver;
    friend class phase_scope::NativePrivacyPhaseScopeBridge;
public:
    NativeEmpiricalResultAuthority(
        const NativeEmpiricalResultAuthority&) = delete;
    NativeEmpiricalResultAuthority& operator=(
        const NativeEmpiricalResultAuthority&) = delete;
    NativeEmpiricalResultAuthority(
        NativeEmpiricalResultAuthority&&) noexcept;
    NativeEmpiricalResultAuthority& operator=(
        NativeEmpiricalResultAuthority&&) = delete;
    ~NativeEmpiricalResultAuthority();
};

struct NativeEmpiricalResultSourceStatus {
    bool exact_two_round_five_field_registry{};
    bool sealed_history_and_candidate_inputs{};
    bool derives_candidate_effect_internally{};
    bool opaque_one_shot_residual{};
    bool terminal_attached_observer_minter{};
    bool fd62_v3_join{};
    bool selected_runtime_callsite{};
    bool configured{};
};

inline constexpr NativeEmpiricalResultSourceStatus
    kNativeEmpiricalResultStatus{
        .exact_two_round_five_field_registry = true,
        .sealed_history_and_candidate_inputs = true,
        .derives_candidate_effect_internally = true,
        .opaque_one_shot_residual = true,
    };

} // namespace kpb::measurement::empirical_result
