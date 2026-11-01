#pragma once

// Parent-owned runtime seam for the ten append-only privacy capture streams.
// No production constructor or selected main exists in this source state.

#include "privacy_measurement_authority.hpp"
#include "c1_contact_value_authority_bridge_contract.hpp"
#include "c1_registered_plan_route_bridge_contract.hpp"
#include "privacy_capture_producer_runtime_contract.hpp"
#include "privacy_registered_fresh_trial_producer_closure_contract.hpp"
#include "privacy_registered_attempt_history_bridge_contract.hpp"
#include "../mpc-prover/financial/registered_producer_route_bridge_contract.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <string>

namespace kpb::measurement::producer_archive {
class ProducerSealedArchiveAuthority;
class ProducerPartialC03ArchiveAuthority;
class ProducerArchiveQuarantineAuthority;
class ProducerSealedArchiveBuilder;
enum class ProducerArchiveQuarantineStage : unsigned char;
}

namespace kpb::measurement::producer_runtime {

struct PublicAggregateMailboxRouteRequirement {
    unsigned round{};
    Digest projection_identity{};
    std::uint64_t projection_bytes{};
    unsigned route_endpoint_count{};
    unsigned owner_ack_count{};
    bool role_blind_required{};
    bool after_full_cohort_barrier_required{};
    bool owner_socket_or_path_derivation_forbidden{};
    bool operator==(const PublicAggregateMailboxRouteRequirement&) const =
        default;
};

struct PublicAggregateMailboxRouteCompletion {
    unsigned round{};
    Digest route_identity{};
    Digest full_cohort_barrier_identity{};
    Digest projection_identity{};
    std::uint64_t projection_bytes{};
    std::uint64_t full_cohort_barrier_observed_monotonic_ns{};
    std::uint64_t route_observed_monotonic_ns{};
    unsigned route_endpoint_count{};
    unsigned owner_ack_count{};
    bool role_blind{};
    bool after_full_cohort_barrier{};
    bool owner_socket_or_path_derived{};
    bool operator==(const PublicAggregateMailboxRouteCompletion&) const =
        default;
};

struct PublicProducerStreamPlan {
    unsigned round{};
    CaptureKind kind{};
    unsigned fixed_fd{};
    Digest process_identity{};
    Digest child_exit_identity{};
    bool operator==(const PublicProducerStreamPlan&) const = default;
};

#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
enum class TestProducerArchiveTransportFault : unsigned char {
    None,
    MissingFd,
    ExtraFd,
    SplitRights,
    SwappedFdOrder,
    SwappedFdAndEvidence,
    WritableFd,
    UnsealedFd,
    DuplicateFd,
    WrongBinding,
    WrongClosure,
    SecondPacket,
    NonzeroExit,
};
enum class TestProducerDrainFault : unsigned char {
    None,
    SigkillAfterFirstC03Write,
    SigsegvAfterFirstC03Write,
    SigkillAfterSecondC03Write,
    SigsegvAfterSecondC03Write,
    FailC03InspectionAfterSeal,
    FailAllocationAfterClaim,
    FailAllocationAfterPartialSeal,
    FailAllocationAfterC03Inspection,
};
enum class TestProducerWaitFault : unsigned char {
    None,
    FailFirstWaitpid,
    FailAllWaitpid,
};
#endif

struct PublicProducerLaunchPlan {
    RunBinding binding;
    std::string capture_trial_id;
    std::array<std::string, 2> capture_attempt_ids;
    Digest producer_process_identity{};
    Digest role_closure_identity{};
    Digest manifest_seal{};
    ConstructionPolicy construction_policy{};
    Digest construction_classification_receipt{};
    Digest opaque_closure_authority_identity{};
    std::array<PublicAggregateMailboxRouteRequirement, 2>
        route_requirements{};
    std::array<PublicProducerStreamPlan, 10> streams{};
#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
    bool test_only_send_zero_record_before_close{};
    TestProducerArchiveTransportFault test_only_archive_fault{};
    TestProducerDrainFault test_only_drain_fault{};
    TestProducerWaitFault test_only_wait_fault{};
#endif
};

struct PublicCaptureProducerStreamReceipt {
    unsigned round{};
    CaptureKind kind{};
    unsigned fixed_fd{};
    bool root_closed{};
    bool end_observed{};
    bool eof_observed{};
    bool operator==(const PublicCaptureProducerStreamReceipt&) const =
        default;
};

struct PublicCaptureProducerReceiptV1 {
    std::string schema;
    RunBinding binding;
    Digest opaque_closure_authority_identity{};
    WorkerBinding producer_worker;
    Digest producer_process_identity{};
    Digest role_closure_identity{};
    Digest manifest_seal{};
    ConstructionPolicy construction_policy{};
    Digest construction_classification_receipt{};
    std::array<PublicAggregateMailboxRouteRequirement, 2> routes{};
    std::array<PublicCaptureProducerStreamReceipt, 10> streams{};
    unsigned stream_count{};
    unsigned closed_root_count{};
    unsigned unknown_record_count{};
    bool role_hooks_integrated{};
    bool fixed_fd_inheritance_selected{};
    bool launcher_selected{};
    bool launch_authorized{};
    bool actual_receipt_emitted{};
};

enum class ProducerAttemptC03StreamState : std::uint8_t {
    CompleteEnd = 1,
    Empty = 2,
    PartialHeader = 3,
    PartialPayload = 4,
    ClosedWithoutEnd = 5,
    Invalid = 6,
};

enum class ProducerAttemptDrainFailure : std::uint8_t {
    None = 0,
    Empty = 1,
    PartialHeader = 2,
    PartialPayload = 3,
    MissingEnd = 4,
    ParserRefused = 5,
    OtherStreamRefused = 6,
    CaptureReadFailed = 7,
    ProducerChildExitedNonzero = 8,
    ProducerChildSignaled = 9,
    RouteUnavailable = 10,
    WaitStatusUnavailable = 11,
};

class ParentTenReadEndsAuthority final {
    PublicProducerLaunchPlan plan_;
    std::array<int, 10> read_ends_{};
    std::array<std::uint64_t, 10> devices_{};
    std::array<std::uint64_t, 10> inodes_{};
    std::array<std::uint32_t, 10> file_types_{};
    std::array<std::atomic_bool, 2> c1_contact_value_prepared_{};
    std::atomic_bool live_{true};

    ParentTenReadEndsAuthority(PublicProducerLaunchPlan,
                               std::array<int, 10>);
    friend class ParentOwnedCaptureProducer;
    friend class ::kpb::measurement::c1_capture::
        C1ContactValueAuthorityBridge;
    friend class ::kpb::measurement::c1_capture::
        RegisteredC1PlanRouteBridge;
    friend class ::kpi::mpc::financial::registered_driver::
        RegisteredFreshTrialProducerClosureBridge;
public:
    ParentTenReadEndsAuthority(const ParentTenReadEndsAuthority&) = delete;
    ParentTenReadEndsAuthority& operator=(
        const ParentTenReadEndsAuthority&) = delete;
    ParentTenReadEndsAuthority(ParentTenReadEndsAuthority&&) noexcept;
    ParentTenReadEndsAuthority& operator=(
        ParentTenReadEndsAuthority&&) = delete;
    ~ParentTenReadEndsAuthority();

#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
    static ParentTenReadEndsAuthority test_only_mint(
        PublicProducerLaunchPlan, std::array<int, 10>&&);
#endif
};

class ProducerRuntimeCompletion final {
    PublicCaptureProducerReceiptV1 receipt_;
    std::optional<ProducerClosureAuthority> authority_;
    std::unique_ptr<producer_archive::ProducerSealedArchiveAuthority>
        archive_;
    ProducerRuntimeCompletion(PublicCaptureProducerReceiptV1,
                              ProducerClosureAuthority&&,
                              producer_archive::
                                  ProducerSealedArchiveAuthority&&);
    friend class ParentOwnedCaptureProducer;
public:
    ProducerRuntimeCompletion(const ProducerRuntimeCompletion&) = delete;
    ProducerRuntimeCompletion& operator=(
        const ProducerRuntimeCompletion&) = delete;
    ProducerRuntimeCompletion(ProducerRuntimeCompletion&&) noexcept;
    ProducerRuntimeCompletion& operator=(ProducerRuntimeCompletion&&) = delete;
    ~ProducerRuntimeCompletion();
    const PublicCaptureProducerReceiptV1& public_receipt() const {
        return receipt_;
    }
    ProducerClosureAuthority take_authority();
    producer_archive::ProducerSealedArchiveAuthority take_archive();
};

class ProducerAttemptRegisteredHistoryTransfer;
class ProducerAttemptRegisteredOutcomeTransfer;

class ProducerAttemptC03HistoryAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit ProducerAttemptC03HistoryAuthority(std::unique_ptr<Storage>);
    ProducerAttemptRegisteredHistoryTransfer
        consume_for_registered_history() &&;
    friend class ParentOwnedCaptureProducer;
    friend class ProducerAttemptOutcomeAuthority;
    friend class ::kpi::mpc::financial::registered_driver::attempt_history::
        RegisteredCaptureAttemptHistoryBridge;
public:
    ProducerAttemptC03HistoryAuthority(
        const ProducerAttemptC03HistoryAuthority&) = delete;
    ProducerAttemptC03HistoryAuthority& operator=(
        const ProducerAttemptC03HistoryAuthority&) = delete;
    ProducerAttemptC03HistoryAuthority(
        ProducerAttemptC03HistoryAuthority&&) noexcept;
    ProducerAttemptC03HistoryAuthority& operator=(
        ProducerAttemptC03HistoryAuthority&&) = delete;
    ~ProducerAttemptC03HistoryAuthority();
#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
    struct TestSummary {
        RunBinding binding;
        std::string capture_trial_id;
        std::array<std::string, 2> capture_attempt_ids;
        Digest archive_reservation_identity{};
        std::array<ProducerAttemptC03StreamState, 2> states{};
        std::array<ProducerAttemptDrainFailure, 2> failures{};
        ProducerAttemptDrainFailure attempt_failure{};
        std::uint8_t first_failed_slot{0xff};
        std::array<std::uint64_t, 2> sizes{};
        std::array<std::uint64_t, 2> devices{};
        std::array<std::uint64_t, 2> inodes{};
        std::array<int, 2> seals{};
        std::array<Digest, 2> sha256{};
        std::array<bool, 2> read_only{};
        std::array<Digest, 2> route_requirements{};
        std::array<Digest, 2> route_completions{};
        bool writer_aliases_closed{};
        std::uint64_t start_monotonic_ns{};
        std::uint64_t end_monotonic_ns{};
        std::int64_t producer_pid{};
        std::int32_t producer_wait_status{};
        bool wait_observed{};
        bool pidfd_exit_observed{};
        Digest producer_child_exit_identity{};
    };
    static TestSummary test_only_consume(
        ProducerAttemptC03HistoryAuthority&&);
#endif
};

// Opaque one-shot handoff to the complete registered-history bridge. It has
// no public descriptor, hash, body, JSON, or receipt accessors.
class ProducerAttemptRegisteredHistoryTransfer final {
    RunBinding binding_;
    std::string capture_trial_id_;
    std::array<std::string, 2> capture_attempt_ids_;
    Digest closure_identity_{};
    Digest archive_reservation_identity_{};
    std::array<unsigned, 2> source_slots_{};
    std::array<unsigned, 2> fixed_fds_{};
    std::array<int, 2> fds_{};
    std::array<std::uint64_t, 2> devices_{};
    std::array<std::uint64_t, 2> inodes_{};
    std::array<std::uint64_t, 2> sizes_{};
    std::array<int, 2> seals_{};
    std::array<Digest, 2> sha256_{};
    std::array<Digest, 2> route_requirements_{};
    std::array<Digest, 2> route_completions_{};
    bool writer_aliases_closed_{};
    std::array<ProducerAttemptC03StreamState, 2> states_{};
    std::array<ProducerAttemptDrainFailure, 2> failures_{};
    ProducerAttemptDrainFailure attempt_failure_{};
    std::uint8_t first_failed_slot_{0xff};
    std::uint64_t start_monotonic_ns_{};
    std::uint64_t end_monotonic_ns_{};
    std::int64_t producer_pid_{};
    std::int32_t producer_wait_status_{};
    bool wait_observed_{};
    bool pidfd_exit_observed_{};
    Digest producer_child_exit_identity_{};
    ProducerAttemptRegisteredHistoryTransfer();
    friend class ProducerAttemptC03HistoryAuthority;
    friend class ::kpi::mpc::financial::registered_driver::attempt_history::
        RegisteredCaptureAttemptHistoryBridge;
public:
    ProducerAttemptRegisteredHistoryTransfer(
        const ProducerAttemptRegisteredHistoryTransfer&) = delete;
    ProducerAttemptRegisteredHistoryTransfer& operator=(
        const ProducerAttemptRegisteredHistoryTransfer&) = delete;
    ProducerAttemptRegisteredHistoryTransfer(
        ProducerAttemptRegisteredHistoryTransfer&&) noexcept;
    ProducerAttemptRegisteredHistoryTransfer& operator=(
        ProducerAttemptRegisteredHistoryTransfer&&) = delete;
    ~ProducerAttemptRegisteredHistoryTransfer();
};

// Indivisible parent result: history always exists, while the ordinary
// producer completion exists only for an exact ten-stream END+EOF attempt.
class ProducerAttemptDrainResult final {
    std::unique_ptr<ProducerAttemptC03HistoryAuthority> history_;
    std::unique_ptr<ProducerRuntimeCompletion> completion_;
    ProducerAttemptDrainResult(
        ProducerAttemptC03HistoryAuthority&&,
        std::unique_ptr<ProducerRuntimeCompletion>);
    friend class ParentOwnedCaptureProducer;
    friend class ::kpi::mpc::financial::registered_driver::attempt_history::
        RegisteredCaptureAttemptHistoryBridge;
public:
    ProducerAttemptDrainResult(const ProducerAttemptDrainResult&) = delete;
    ProducerAttemptDrainResult& operator=(
        const ProducerAttemptDrainResult&) = delete;
    ProducerAttemptDrainResult(ProducerAttemptDrainResult&&) noexcept;
    ProducerAttemptDrainResult& operator=(ProducerAttemptDrainResult&&) =
        delete;
    ~ProducerAttemptDrainResult();
    bool complete() const noexcept { return completion_ != nullptr; }
#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
    ProducerAttemptC03HistoryAuthority take_history();
    ProducerRuntimeCompletion take_completion();
#endif
};

// No-drop terminal outcome for one source-owned producer attempt. A normal
// arm retains the exact C03 history plus optional complete producer result.
// An unavailable arm retains the parent O_TMPFILE quarantine (and, if the
// failure occurred after the C03 transition, that typed partial authority).
// It has no public enum, descriptor, digest or extraction API.
class ProducerAttemptOutcomeAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit ProducerAttemptOutcomeAuthority(std::unique_ptr<Storage>);
    ProducerAttemptRegisteredOutcomeTransfer
        consume_for_registered_history() &&;
    friend class ParentOwnedCaptureProducer;
    friend class ProducerAttemptRegisteredOutcomeTransfer;
    friend class ::kpi::mpc::financial::registered_driver::attempt_history::
        RegisteredCaptureAttemptHistoryBridge;
public:
    ProducerAttemptOutcomeAuthority(
        const ProducerAttemptOutcomeAuthority&) = delete;
    ProducerAttemptOutcomeAuthority& operator=(
        const ProducerAttemptOutcomeAuthority&) = delete;
    ProducerAttemptOutcomeAuthority(
        ProducerAttemptOutcomeAuthority&&) noexcept;
    ProducerAttemptOutcomeAuthority& operator=(
        ProducerAttemptOutcomeAuthority&&) = delete;
    ~ProducerAttemptOutcomeAuthority();
#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
    struct TestOnlyUnavailableSummary final {
        bool unavailable{};
        bool retained_quarantine{};
        bool retained_partial_c03{};
        producer_archive::ProducerArchiveQuarantineStage stage{};
        int error_number{};
        std::int64_t producer_pid{-1};
        bool wait_observed{};
        bool pidfd_exit_observed{};
    };
    static TestOnlyUnavailableSummary test_only_consume_unavailable(
        ProducerAttemptOutcomeAuthority&&);
#endif
};

// Opaque cross-TU handoff of the complete source-owned attempt outcome.  The
// registered bridge can retain it but cannot reconstruct any arm from public
// fields.  Destruction closes every still-owned descriptor.
class ProducerAttemptRegisteredOutcomeTransfer final {
    std::unique_ptr<ProducerAttemptOutcomeAuthority::Storage> storage_;
    explicit ProducerAttemptRegisteredOutcomeTransfer(
        std::unique_ptr<ProducerAttemptOutcomeAuthority::Storage>) noexcept;
    friend class ProducerAttemptOutcomeAuthority;
    friend class ::kpi::mpc::financial::registered_driver::attempt_history::
        RegisteredCaptureAttemptHistoryBridge;
public:
    ProducerAttemptRegisteredOutcomeTransfer(
        const ProducerAttemptRegisteredOutcomeTransfer&) = delete;
    ProducerAttemptRegisteredOutcomeTransfer& operator=(
        const ProducerAttemptRegisteredOutcomeTransfer&) = delete;
    ProducerAttemptRegisteredOutcomeTransfer(
        ProducerAttemptRegisteredOutcomeTransfer&&) noexcept;
    ProducerAttemptRegisteredOutcomeTransfer& operator=(
        ProducerAttemptRegisteredOutcomeTransfer&&) = delete;
    ~ProducerAttemptRegisteredOutcomeTransfer();
};

class ParentAggregateMailboxRoutesAuthority final {
    std::array<PublicAggregateMailboxRouteCompletion, 2> routes_{};
    std::atomic_bool live_{true};
    explicit ParentAggregateMailboxRoutesAuthority(
        std::array<PublicAggregateMailboxRouteCompletion, 2>);
    friend class ParentOwnedCaptureProducer;
    friend class ::kpi::mpc::financial::registered_driver::
        RegisteredProducerRouteBridge;
public:
    ParentAggregateMailboxRoutesAuthority(
        const ParentAggregateMailboxRoutesAuthority&) = delete;
    ParentAggregateMailboxRoutesAuthority& operator=(
        const ParentAggregateMailboxRoutesAuthority&) = delete;
    ParentAggregateMailboxRoutesAuthority(
        ParentAggregateMailboxRoutesAuthority&&) noexcept;
    ParentAggregateMailboxRoutesAuthority& operator=(
        ParentAggregateMailboxRoutesAuthority&&) = delete;
#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
    static ParentAggregateMailboxRoutesAuthority test_only_mint(
        std::array<PublicAggregateMailboxRouteCompletion, 2>);
#endif
};

class RunningCaptureProducer final {
    PublicProducerLaunchPlan plan_;
    int child_pid_{-1};
    int child_pidfd_{-1};
    int packet_fd_{-1};
    std::uint64_t start_monotonic_ns_{};
    std::unique_ptr<producer_archive::ProducerSealedArchiveBuilder>
        retained_archive_builder_;
    std::array<std::uint64_t, 10> archive_devices_{};
    std::array<std::uint64_t, 10> archive_inodes_{};
    bool active_{true};
    RunningCaptureProducer(PublicProducerLaunchPlan, int, int, int,
                           std::uint64_t start_monotonic_ns,
                           std::unique_ptr<producer_archive::
                               ProducerSealedArchiveBuilder>,
                           std::array<std::uint64_t, 10>,
                           std::array<std::uint64_t, 10>);
    friend class ParentOwnedCaptureProducer;
public:
    RunningCaptureProducer(const RunningCaptureProducer&) = delete;
    RunningCaptureProducer& operator=(const RunningCaptureProducer&) = delete;
    RunningCaptureProducer(RunningCaptureProducer&&) noexcept;
    RunningCaptureProducer& operator=(RunningCaptureProducer&&) = delete;
    ~RunningCaptureProducer();
};

struct ProducerRuntimeSourceStatus {
    bool concurrent_drain_core{};
    bool parent_owned_read_authority{};
    bool end_then_eof_enforced{};
    bool sealed_raw_archive{};
    bool strict_archive_scm_rights{};
    bool parent_raw_wire_reparse{};
    bool source_build_runtime_launch_bound{};
    bool role_blind_aggregate_route_enforced{};
    bool typed_receipt_core{};
    bool source_derived_stream_byte_bounds{};
    bool disk_reservation_preflight{};
    bool wait_failure_invalidation_handoff{};
    bool no_drop_attempt_outcome{};
    bool registered_role0_route_complete{};
    bool selected_main{};
    bool public_actual_receipt_adapter{};
    bool actual_launch_enabled{};
};

inline constexpr ProducerRuntimeSourceStatus kProducerRuntimeSourceStatus{
    .concurrent_drain_core = true,
    .parent_owned_read_authority = true,
    .end_then_eof_enforced = true,
    .sealed_raw_archive = true,
    .strict_archive_scm_rights = true,
    .parent_raw_wire_reparse = true,
    .source_build_runtime_launch_bound = true,
    .role_blind_aggregate_route_enforced = true,
    .typed_receipt_core = true,
    .source_derived_stream_byte_bounds = false,
    .disk_reservation_preflight = false,
    .wait_failure_invalidation_handoff = true,
    .no_drop_attempt_outcome = false,
    .registered_role0_route_complete = false,
    .selected_main = false,
    .public_actual_receipt_adapter = false,
    .actual_launch_enabled = false,
};

} // namespace kpb::measurement::producer_runtime
