#pragma once

#include "privacy_measurement_authority.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <string>

namespace kpb::measurement::producer_schedule {

enum class ProducerWireGrammar : std::uint8_t {
    PublicProjectionEventV1 = 1,
    TerminalHistoryV2 = 2,
    DispatcherEventV1 = 3,
    P1ChunkV9 = 4,
    C1CaptureV2 = 5,
};

enum class ProducerByteBoundKind : std::uint8_t {
    ExactBytes = 1,
    ProtocolUpperBound = 2,
    Missing = 3,
};

// This report is deliberately non-authorizing. A caller-authored RunBinding can
// expose eight formulas fixed by source while P1 remains missing, but it cannot
// reserve, launch, or become the complete authority.
struct NonAuthorizingProducerByteScheduleSlot {
    unsigned ordinal{};
    unsigned round{};
    CaptureKind kind{};
    unsigned fixed_fd{};
    ProducerWireGrammar grammar{};
    ProducerByteBoundKind bound_kind{};
    std::uint64_t max_wire_bytes{};
    WorkerBinding writer;
    Digest source_derivation_identity{};
    bool operator==(const NonAuthorizingProducerByteScheduleSlot&) const =
        default;
};

struct NonAuthorizingProducerByteScheduleBlocker {
    std::string schema;
    RunBinding binding;
    Digest trial{};
    Classification classification{};
    Digest workload{};
    WorkerBinding producer_worker;
    Digest producer_executable_identity{};
    Digest producer_launcher_identity{};
    Digest schedule_derivation_formula_identity{};
    Digest schedule_derivation_source_identity{};
    Digest schedule_derivation_build_identity{};
    std::array<NonAuthorizingProducerByteScheduleSlot, 10> slots{};
    Digest schedule_identity{};
    unsigned source_bounded_slot_count{};
    unsigned missing_slot_count{};
    bool schedule_derivation_source_bound{};
    bool schedule_derivation_build_bound{};
    bool complete{};
};

NonAuthorizingProducerByteScheduleBlocker
derive_non_authorizing_source_bounded_schedule(const RunBinding&);

class SelectedProducerByteScheduleAuthority;

// Complete now, before friendship is granted. A hostile translation unit cannot
// define this exact name and use it to construct the future complete authority.
// The reservation operation itself remains absent until all ten slots exist.
class ProducerArchiveReservationBridge final {
public:
    ProducerArchiveReservationBridge() = delete;
};

// This is the future ten-slot capability. It has no production or test mint and
// no getter while P1 and this derivation module's own exact source/build
// artifact identities remain missing.
class SelectedProducerByteScheduleAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit SelectedProducerByteScheduleAuthority(std::unique_ptr<Storage>);
    friend class ProducerArchiveReservationBridge;
public:
    SelectedProducerByteScheduleAuthority(
        const SelectedProducerByteScheduleAuthority&) = delete;
    SelectedProducerByteScheduleAuthority& operator=(
        const SelectedProducerByteScheduleAuthority&) = delete;
    SelectedProducerByteScheduleAuthority(
        SelectedProducerByteScheduleAuthority&&) noexcept;
    SelectedProducerByteScheduleAuthority& operator=(
        SelectedProducerByteScheduleAuthority&&) = delete;
    ~SelectedProducerByteScheduleAuthority();
};

struct ProducerByteScheduleSourceStatus {
    bool eight_source_bounded_slots{};
    bool c1_source_frozen_no_retry_schedule{};
    bool c1_retry_invalidates_whole_trial{};
    bool c1_retry_evidence_retained_under_trial{};
    bool c1_retry_outer_history_join{};
    bool p1_round1_schedule{};
    bool p1_round2_schedule{};
    bool schedule_derivation_source_artifact{};
    bool schedule_derivation_build_artifact{};
    bool complete_authority_minter{};
    bool archive_consumer{};
    bool configured{};
};

inline constexpr ProducerByteScheduleSourceStatus
kProducerByteScheduleSourceStatus{
    .eight_source_bounded_slots = true,
    .c1_source_frozen_no_retry_schedule = true,
    .c1_retry_invalidates_whole_trial = true,
    .c1_retry_evidence_retained_under_trial = true,
    .c1_retry_outer_history_join = false,
    .p1_round1_schedule = false,
    .p1_round2_schedule = false,
    .schedule_derivation_source_artifact = false,
    .schedule_derivation_build_artifact = false,
    .complete_authority_minter = false,
    .archive_consumer = false,
    .configured = false,
};

#ifdef KPB_SELECTED_PRODUCER_BYTE_SCHEDULE_TEST_SETUP
void test_only_verify_formula_overflow_controls();
#endif

} // namespace kpb::measurement::producer_schedule
