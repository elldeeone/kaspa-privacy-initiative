#pragma once

// Source-owned fixed output ABI table.  This header does not install FD62 or
// mint an output authority; selected supervisor integration remains false.

#include "privacy_measurement_runtime_types.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace kpb::measurement::runtime_bridge {

inline constexpr int MEASUREMENT_CHILD_OUTPUT_FD = 62;

inline constexpr std::uint64_t OUTPUT_ABI_PAGE_BYTES = 4096;
inline constexpr std::uint64_t OUTPUT_ABI_MAX_WORKLOAD_CANDIDATES = 291600;
inline constexpr std::uint64_t OUTPUT_ABI_WORKLOAD_BITMAP_BYTES = 36450;
// Exact union of the selected five typed artifact category manifests.
inline constexpr std::uint64_t OUTPUT_ABI_CATEGORY_ROWS = 32;
inline constexpr std::uint64_t OBSERVER_PHASE_V2_OFFSET = 151049;
inline constexpr std::uint64_t OBSERVER_PHASE_V2_BYTES = 144;
inline constexpr std::uint64_t OBSERVER_PHASE_V2_HEADER_BYTES = 16;
inline constexpr std::uint64_t OBSERVER_PHASE_V2_VIEW_BYTES = 32;
inline constexpr std::uint64_t OBSERVER_PHASE_V2_RECORD_BYTES = 6;
inline constexpr std::array<unsigned char, 8> OBSERVER_PHASE_V2_MAGIC{
    'K', 'P', 'B', 'P', 'H', 'V', '0', '1'};
inline constexpr std::uint64_t OBSERVER_STEP2_V3_OFFSET = 151193;
inline constexpr std::uint64_t OBSERVER_STEP2_V3_BYTES = 256;
inline constexpr std::array<unsigned char, 8> OBSERVER_STEP2_V3_MAGIC{
    'K', 'P', 'B', 'S', 'T', 'P', '2', '1'};
inline constexpr std::array<std::uint16_t, 4> OBSERVER_STEP2_VIEW_TOTALS{
    42, 56, 108, 122};
inline constexpr std::array<unsigned char, 4>
    OBSERVER_STEP2_DEFERRED_STEP3_COUNTS{4, 4, 4, 4};
inline constexpr std::uint16_t OBSERVER_STEP2_EMPIRICAL_OPEN_MASK = 0x03ff;

enum class ObserverStep2Disposition : unsigned char {
    MissingAuthorityOpen = 1,
    SourceAssumptionOpen = 2,
    EmpiricalOpen = 3,
};
struct ObserverStep2FamilyRow {
    unsigned char code{};
    std::array<unsigned char, 4> counts{};
    ObserverStep2Disposition disposition{};
    bool operator==(const ObserverStep2FamilyRow&) const = default;
};
inline constexpr std::array<std::string_view, 26>
    OBSERVER_STEP2_FAMILY_NAMES{{
        "AUTHENTICATED_C1_CONTACT_AND_VALUE_BINDING",
        "AUTHENTICATED_C1_SOURCE_PROVENANCE",
        "AUTHENTICATED_CONSTRUCTION_POLICY_MAPPING",
        "AUTHENTICATED_DISPATCHER_EVENT_CANDIDATE_CONSTRAINT",
        "AUTHENTICATED_HONEST_OUTPUT_ENCRYPTION_PRODUCER_AUTHORITY",
        "AUTHENTICATED_ROLE_BLIND_ROUTE_HANDOFF",
        "COMPLETE_PUBLIC_MULTIATTEMPT_HISTORY_EQUALITY_JOIN",
        "COMPLETE_PUBLIC_MULTIATTEMPT_NF_EQUALITY_JOIN",
        "LIVE_STRUCTURAL_PROJECTION_CONTINUITY_RESIDUAL_AND_WORKLOAD_JOIN",
        "MATCHED_NATIVE_TERMINAL_PRODUCER_AUTHORITY_AND_PRIVATE_V2_LEAF",
        "MATCHED_NATIVE_TERMINAL_PRODUCER_AUTHORITY_AND_PUBLIC_CONTINUITY_JOIN",
        "PINNED_AUTHENTICATED_GROUP_VIEW_ASSUMPTION",
        "PINNED_DDNNT_5N_OWNER_INPUT_ASSUMPTION",
        "PINNED_GROTH16_PUBLIC_PROOF_ZK_ASSUMPTION",
        "PINNED_MIXED_PROTOCOL_JOINT_VIEW_ASSUMPTION",
        "PINNED_NULLIFIER_PRF_AND_UNLINKABILITY_ASSUMPTION",
        "PINNED_OUTPUT_CIPHERTEXT_JOINT_CONFIDENTIALITY_ASSUMPTION",
        "PINNED_PEDERSEN_CV_JOINT_VIEW_ASSUMPTION",
        "PINNED_SHA256_NOTE_COMMITMENT_HIDING_ASSUMPTION",
        "PINNED_STOCK_MASCOT_JOINT_VIEW_ASSUMPTION",
        "PUBLIC_NF_HISTORY_EDGE_CANDIDATE_FILTER",
        "PUBLIC_STATE_TRANSITION_CANDIDATE_CONSTRAINT",
        "TYPED_GROUP_CORRESPONDENCE_CHECK",
        "WITHIN_RUN_EMPIRICAL_CANDIDATE_FILTER",
        "WITHIN_RUN_PUBLIC_CIPHERTEXT_CANDIDATE_FILTER",
        "WITHIN_RUN_PUBLIC_CV_RESIDUAL_CANDIDATE_FILTER",
    }};
inline constexpr std::array<ObserverStep2FamilyRow, 26>
    OBSERVER_STEP2_FAMILY_ROWS{{
        {1, {0, 0, 4, 4}, ObserverStep2Disposition::MissingAuthorityOpen},
        {2, {0, 0, 6, 6}, ObserverStep2Disposition::MissingAuthorityOpen},
        {3, {0, 2, 0, 2}, ObserverStep2Disposition::MissingAuthorityOpen},
        {4, {0, 10, 0, 10}, ObserverStep2Disposition::MissingAuthorityOpen},
        {5, {2, 2, 2, 2}, ObserverStep2Disposition::MissingAuthorityOpen},
        {6, {0, 2, 0, 2}, ObserverStep2Disposition::MissingAuthorityOpen},
        {7, {2, 2, 2, 2}, ObserverStep2Disposition::MissingAuthorityOpen},
        {8, {2, 2, 2, 2}, ObserverStep2Disposition::MissingAuthorityOpen},
        {9, {4, 4, 4, 4}, ObserverStep2Disposition::MissingAuthorityOpen},
        {10, {2, 2, 2, 2}, ObserverStep2Disposition::MissingAuthorityOpen},
        {11, {2, 2, 2, 2}, ObserverStep2Disposition::MissingAuthorityOpen},
        {12, {0, 0, 20, 20}, ObserverStep2Disposition::SourceAssumptionOpen},
        {13, {0, 0, 4, 4}, ObserverStep2Disposition::SourceAssumptionOpen},
        {14, {4, 4, 4, 4}, ObserverStep2Disposition::SourceAssumptionOpen},
        {15, {0, 0, 2, 2}, ObserverStep2Disposition::SourceAssumptionOpen},
        {16, {2, 2, 2, 2}, ObserverStep2Disposition::SourceAssumptionOpen},
        {17, {2, 2, 2, 2}, ObserverStep2Disposition::SourceAssumptionOpen},
        {18, {2, 2, 2, 2}, ObserverStep2Disposition::SourceAssumptionOpen},
        {19, {2, 2, 2, 2}, ObserverStep2Disposition::SourceAssumptionOpen},
        {20, {0, 0, 18, 18}, ObserverStep2Disposition::SourceAssumptionOpen},
        {21, {2, 2, 2, 2}, ObserverStep2Disposition::MissingAuthorityOpen},
        {22, {4, 4, 4, 4}, ObserverStep2Disposition::MissingAuthorityOpen},
        {23, {0, 0, 2, 2}, ObserverStep2Disposition::MissingAuthorityOpen},
        {24, {0, 0, 10, 10}, ObserverStep2Disposition::EmpiricalOpen},
        {25, {8, 8, 8, 8}, ObserverStep2Disposition::MissingAuthorityOpen},
        {26, {2, 2, 2, 2}, ObserverStep2Disposition::MissingAuthorityOpen},
    }};

consteval bool observer_step2_registry_is_exact() {
    std::array<std::uint16_t, 4> totals{};
    for (std::size_t index = 0;
         index < OBSERVER_STEP2_FAMILY_ROWS.size(); ++index) {
        const auto& row = OBSERVER_STEP2_FAMILY_ROWS[index];
        if (row.code != index + 1) return false;
        const auto expected = row.code >= 12 && row.code <= 20 ?
            ObserverStep2Disposition::SourceAssumptionOpen :
            row.code == 24 ? ObserverStep2Disposition::EmpiricalOpen :
            ObserverStep2Disposition::MissingAuthorityOpen;
        if (row.disposition != expected) return false;
        for (std::size_t view = 0; view < totals.size(); ++view)
            totals[view] += row.counts[view];
    }
    return totals == OBSERVER_STEP2_VIEW_TOTALS;
}
static_assert(observer_step2_registry_is_exact());

struct ObserverStep2EmpiricalOccurrence {
    unsigned char round{};
    std::string_view field;
    bool operator==(const ObserverStep2EmpiricalOccurrence&) const = default;
};
inline constexpr std::array<ObserverStep2EmpiricalOccurrence, 10>
    OBSERVER_STEP2_EMPIRICAL_OCCURRENCES{{
        {1, "attempt.abort_retry_partial_transcript"},
        {1, "wire.frames[].direction_peer_fork"},
        {1, "wire.frames[].monotonic_ns"},
        {1, "wire.frames[].payload_length"},
        {1, "wire.frames[].sequence_message_chunk_order"},
        {2, "attempt.abort_retry_partial_transcript"},
        {2, "wire.frames[].direction_peer_fork"},
        {2, "wire.frames[].monotonic_ns"},
        {2, "wire.frames[].payload_length"},
        {2, "wire.frames[].sequence_message_chunk_order"},
    }};

enum class ObserverPhaseView : unsigned char {
    Public = 1,
    Dispatcher = 2,
    CorruptServerPlusWallet = 3,
    Union = 4,
};
enum class ObserverPhaseArtifact : unsigned char {
    PublicProjection = 1,
};
enum class ObserverPhaseFamily : unsigned char {
    AcceptedChainContextOutpointExternalHistory = 1,
    AcceptedChainStateOutpointContinuity = 2,
};
enum class ObserverPhaseResolution : unsigned char {
    DirectConstraintPendingSourceAuthority = 1,
};
enum class ObserverPhaseEvidence : unsigned char {
    Step3AcceptedChainStateAndOutpointHistoryAuthority = 1,
};
struct ObserverPhaseRecord {
    unsigned char round{};
    ObserverPhaseFamily family{};
    bool operator==(const ObserverPhaseRecord&) const = default;
};
inline constexpr std::array<ObserverPhaseRecord, 4>
    OBSERVER_PHASE_V2_RECORDS{{
        {1, ObserverPhaseFamily::AcceptedChainContextOutpointExternalHistory},
        {1, ObserverPhaseFamily::AcceptedChainStateOutpointContinuity},
        {2, ObserverPhaseFamily::AcceptedChainContextOutpointExternalHistory},
        {2, ObserverPhaseFamily::AcceptedChainStateOutpointContinuity},
    }};

struct MeasurementOutputAbiDescriptor {
    RuntimeChildRole role{};
    std::uint32_t version{};
    std::array<unsigned char, 8> magic{};
    Digest identity{};
    std::uint64_t used_bytes{};
    std::uint64_t exact_bytes{};
    bool operator==(const MeasurementOutputAbiDescriptor&) const = default;
};

consteval unsigned char output_abi_hex_nibble(char value) {
    return value >= '0' && value <= '9' ?
        static_cast<unsigned char>(value - '0') :
        value >= 'a' && value <= 'f' ?
        static_cast<unsigned char>(value - 'a' + 10) : 255;
}

consteval Digest output_abi_digest(std::string_view value) {
    Digest result{};
    if (value.size() != 64) return result;
    for (std::size_t index = 0; index < result.size(); ++index) {
        const auto high = output_abi_hex_nibble(value[index * 2]);
        const auto low = output_abi_hex_nibble(value[index * 2 + 1]);
        if (high > 15 || low > 15) return {};
        result[index] = static_cast<unsigned char>(high << 4 | low);
    }
    return result;
}

inline constexpr Digest OBSERVER_STEP2_REGISTRY_IDENTITY = output_abi_digest(
    "ee700075720da629ecfed7bc43f9725d14826fc2d0ecd201878a1c2d6bf86708");
inline constexpr Digest OBSERVER_STEP2_MODEL_IDENTITY = output_abi_digest(
    "3e22997c8932709496c843929e4a0752b3bc7f001690c2119a6692b6388a645a");

inline constexpr MeasurementOutputAbiDescriptor OBSERVER_OUTPUT_ABI{
    .role = RuntimeChildRole::Observer,
    .version = 3,
    .magic = {'K', 'P', 'B', 'O', 'A', 'B', 'I', '3'},
    .identity = output_abi_digest(
        "1e28e13affa3c23b39cf781bb003b69827ec37154514180f012e44bc072fa16f"),
    .used_bytes = 151449,
    .exact_bytes = 151552,
};

inline constexpr MeasurementOutputAbiDescriptor OWNER_SCORE_OUTPUT_ABI{
    .role = RuntimeChildRole::OwnerScore,
    .version = 1,
    .magic = {'K', 'P', 'B', 'S', 'A', 'B', 'I', '1'},
    .identity = output_abi_digest(
        "895fb9dc9ba2fb8f510620bdb6bfc2a71b9d749eae847b76f98b381a1f897d02"),
    .used_bytes = 293466,
    .exact_bytes = 294912,
};

// Exact compact lineage encoded at the start of every OwnerScore body.  This
// is a value shape, not an authority.  A future source-owned bridge must mint
// the opaque authority that binds one expectation per owner to a live
// RunBinding; callers cannot authorize a score by supplying this struct.
struct OwnerScoreOutputBindingExpectation {
    Digest method_sha256{};
    Digest selection_sha256{};
    std::array<unsigned char, 16> trial_id{};
    unsigned char attempt_length{};
    std::array<unsigned char, 128> attempt_id{};
    Digest run_selection_sha256{};
    unsigned owner{NO_OWNER};
    bool operator==(
        const OwnerScoreOutputBindingExpectation&) const = default;
};

constexpr const MeasurementOutputAbiDescriptor* measurement_output_abi(
        RuntimeChildRole role) noexcept {
    switch (role) {
    case RuntimeChildRole::Observer: return &OBSERVER_OUTPUT_ABI;
    case RuntimeChildRole::OwnerScore: return &OWNER_SCORE_OUTPUT_ABI;
    case RuntimeChildRole::Aggregate:
    case RuntimeChildRole::OwnerComparison: return nullptr;
    }
    return nullptr;
}

bool validate_measurement_output_abi(
    RuntimeChildRole, std::span<const unsigned char>) noexcept;
bool validate_owner_score_output_abi_for_expected_lineage(
    std::span<const unsigned char>,
    const OwnerScoreOutputBindingExpectation&) noexcept;
bool validate_observer_phase_v2_section(
    std::span<const unsigned char>) noexcept;
bool validate_observer_step2_v3_section(
    std::span<const unsigned char>) noexcept;

#ifdef KPB_MEASUREMENT_OUTPUT_ABI_TEST_SETUP
// Canonical minimal bodies for transport/sandbox controls. Production workers
// must use the Python source-owned encoder over the genuine private result.
std::vector<unsigned char> test_only_measurement_output_abi_body(
    RuntimeChildRole, unsigned owner = NO_OWNER);
std::vector<unsigned char> test_only_owner_score_output_abi_body(
    const OwnerScoreOutputBindingExpectation&);
#endif

struct MeasurementOutputAbiSourceStatus {
    bool observer_schema_frozen{};
    bool observer_phase_inventory_v2{};
    bool observer_step2_inventory_v3{};
    bool owner_score_schema_frozen{};
    bool owner_score_exact_lineage_parser{};
    bool python_cpp_drift_control{};
    bool selected_output_plane{};
    bool fd62_installed{};
    bool configured{};
};

inline constexpr MeasurementOutputAbiSourceStatus kMeasurementOutputAbiStatus{
    .observer_schema_frozen = true,
    .observer_phase_inventory_v2 = true,
    .observer_step2_inventory_v3 = true,
    .owner_score_schema_frozen = true,
    .owner_score_exact_lineage_parser = true,
    .python_cpp_drift_control = true,
};

static_assert(OBSERVER_OUTPUT_ABI.used_bytes <
              OBSERVER_OUTPUT_ABI.exact_bytes);
static_assert(OBSERVER_STEP2_V3_OFFSET ==
              OBSERVER_PHASE_V2_OFFSET + OBSERVER_PHASE_V2_BYTES);
static_assert(OBSERVER_OUTPUT_ABI.used_bytes ==
              OBSERVER_STEP2_V3_OFFSET + OBSERVER_STEP2_V3_BYTES);
static_assert(OWNER_SCORE_OUTPUT_ABI.used_bytes <
              OWNER_SCORE_OUTPUT_ABI.exact_bytes);
static_assert(OBSERVER_OUTPUT_ABI.exact_bytes % OUTPUT_ABI_PAGE_BYTES == 0);
static_assert(OWNER_SCORE_OUTPUT_ABI.exact_bytes % OUTPUT_ABI_PAGE_BYTES == 0);
static_assert(measurement_output_abi(RuntimeChildRole::Aggregate) == nullptr);
static_assert(measurement_output_abi(
    RuntimeChildRole::OwnerComparison) == nullptr);

} // namespace kpb::measurement::runtime_bridge
