#pragma once

// Pre-identity resource reservation for one future ten-stream capture trial
// plus two P1-private state archives. It owns no trial UUID, RunBinding,
// capture plan, or launch authority.

#include "privacy_measurement_authority.hpp"
#include "privacy_registered_fresh_trial_capture_topology_reservation_contract.hpp"
#include "privacy_registered_fresh_trial_producer_closure_contract.hpp"
#include "../mpc-prover/financial/registered_preidentity_ready_contract.hpp"
#include "../mpc-prover/financial/registered_p1_state_archive_scm_contract.hpp"
#include "../mpc-prover/financial/registered_persistent_fresh_trial_activation_contract.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>

namespace kpi::mpc::financial::registered_driver {

namespace detail {
struct PersistentProcessReservationEpoch;
}

struct PublicUnboundCaptureWriterContract {
    unsigned source_slot{};
    unsigned round{};
    kpb::measurement::CaptureKind kind{};
    unsigned fixed_fd{};
    bool operator==(const PublicUnboundCaptureWriterContract&) const =
        default;
};

inline constexpr std::array<PublicUnboundCaptureWriterContract, 10>
    kFreshTrialCaptureWriterContracts{{
        {0, 1, kpb::measurement::CaptureKind::PublicProjection, 20},
        {1, 1, kpb::measurement::CaptureKind::TerminalHistory, 21},
        {2, 1, kpb::measurement::CaptureKind::Dispatcher, 22},
        {3, 1, kpb::measurement::CaptureKind::CorruptServer, 23},
        {4, 1, kpb::measurement::CaptureKind::ColluderWallet, 24},
        {5, 2, kpb::measurement::CaptureKind::PublicProjection, 25},
        {6, 2, kpb::measurement::CaptureKind::TerminalHistory, 26},
        {7, 2, kpb::measurement::CaptureKind::Dispatcher, 27},
        {8, 2, kpb::measurement::CaptureKind::CorruptServer, 28},
        {9, 2, kpb::measurement::CaptureKind::ColluderWallet, 29},
    }};

inline constexpr std::array<unsigned, 6> kPersistentRoleWriterSlots{
    0, 2, 3, 5, 7, 8};
inline constexpr std::array<unsigned, 4> kExternalWriterSlots{1, 4, 6, 9};

struct PublicUnboundP1StateArchiveContract {
    unsigned state_slot{};
    unsigned round{};
    unsigned manifest_semantic{};
    bool fixed_child_fd_required{};
    bool operator==(const PublicUnboundP1StateArchiveContract&) const =
        default;
};

// These are authenticated SCM_RIGHTS manifest labels, not descriptor numbers.
// The child consumes the received description directly; no FD32/33 assumption
// is part of this topology identity.
inline constexpr std::array<PublicUnboundP1StateArchiveContract, 2>
    kFreshTrialP1StateArchiveContracts{{
        {0, 1, 1, false},
        {1, 2, 1, false},
    }};

class FreshTrialCaptureTopologyReservation;
class FreshTrialCaptureTopologyActivationTransfer;
class FreshTrialCaptureProducerTopologyResidual;
class FreshTrialCaptureExternalWriterResidual;
class FreshTrialCaptureTopologyQuarantineResidual;
class FreshTrialP1StateArchiveResidual;

// Opaque phase-2 handoff. It carries the reserved resources into the complete
// persistent activation bridge without exposing descriptors or fingerprints
// to an ordinary caller. Any descriptors not transferred onward are closed by
// its destructor.
class FreshTrialCaptureTopologyActivationTransfer final {
    std::array<int, 10> read_ends_{};
    std::array<int, 10> writer_aliases_{};
    std::array<std::uint64_t, 10> endpoint_devices_{};
    std::array<std::uint64_t, 10> endpoint_inodes_{};
    std::array<std::uint32_t, 10> endpoint_types_{};
    std::array<int, 10> archive_fds_{};
    std::array<std::uint64_t, 10> archive_devices_{};
    std::array<std::uint64_t, 10> archive_inodes_{};
    std::array<std::uint32_t, 10> archive_modes_{};
    std::array<std::uint64_t, 10> archive_nlinks_{};
    std::array<std::uint64_t, 10> archive_sizes_{};
    std::array<int, 2> p1_state_parent_read_fds_{};
    std::array<int, 2> p1_state_child_writer_aliases_{};
    std::array<std::uint64_t, 2> p1_state_devices_{};
    std::array<std::uint64_t, 2> p1_state_inodes_{};
    std::array<std::uint32_t, 2> p1_state_modes_{};
    std::array<std::uint64_t, 2> p1_state_nlinks_{};
    std::array<std::uint64_t, 2> p1_state_sizes_{};
    kpb::measurement::Digest reservation_identity_{};
    std::atomic_bool live_{true};
    FreshTrialCaptureTopologyActivationTransfer(
        std::array<int, 10>, std::array<int, 10>,
        std::array<std::uint64_t, 10>,
        std::array<std::uint64_t, 10>,
        std::array<std::uint32_t, 10>, std::array<int, 10>,
        std::array<std::uint64_t, 10>,
        std::array<std::uint64_t, 10>,
        std::array<std::uint32_t, 10>,
        std::array<std::uint64_t, 10>,
        std::array<std::uint64_t, 10>, std::array<int, 2>,
        std::array<int, 2>, std::array<std::uint64_t, 2>,
        std::array<std::uint64_t, 2>,
        std::array<std::uint32_t, 2>,
        std::array<std::uint64_t, 2>,
        std::array<std::uint64_t, 2>, kpb::measurement::Digest);
    FreshTrialCaptureTopologyQuarantineResidual
        quarantine_after_activation_failure() &&;
    friend class FreshTrialCaptureTopologyReservation;
    friend class RegisteredPersistentFreshTrialActivationBridge;
    friend class RegisteredP1StateArchiveScmBridge;
public:
    FreshTrialCaptureTopologyActivationTransfer(
        const FreshTrialCaptureTopologyActivationTransfer&) = delete;
    FreshTrialCaptureTopologyActivationTransfer& operator=(
        const FreshTrialCaptureTopologyActivationTransfer&) = delete;
    FreshTrialCaptureTopologyActivationTransfer(
        FreshTrialCaptureTopologyActivationTransfer&&) noexcept;
    FreshTrialCaptureTopologyActivationTransfer& operator=(
        FreshTrialCaptureTopologyActivationTransfer&&) = delete;
    ~FreshTrialCaptureTopologyActivationTransfer();
};

// No-drop owner used only after a post-issuance activation failure. It keeps
// the exact ten sole-reader ends, exact ten preopened archives, and every
// writer alias that was not already transferred and closed. It exposes no
// descriptor, digest, body, or public outcome claim.
class FreshTrialCaptureTopologyQuarantineResidual final {
    std::array<int, 10> read_ends_{};
    std::array<int, 10> writer_aliases_{};
    std::array<std::uint64_t, 10> endpoint_devices_{};
    std::array<std::uint64_t, 10> endpoint_inodes_{};
    std::array<std::uint32_t, 10> endpoint_types_{};
    std::array<int, 10> archive_fds_{};
    std::array<std::uint64_t, 10> archive_devices_{};
    std::array<std::uint64_t, 10> archive_inodes_{};
    std::array<std::uint32_t, 10> archive_modes_{};
    std::array<std::uint64_t, 10> archive_nlinks_{};
    std::array<std::uint64_t, 10> archive_sizes_{};
    std::array<int, 2> p1_state_parent_read_fds_{};
    std::array<int, 2> p1_state_child_writer_aliases_{};
    std::array<std::uint64_t, 2> p1_state_devices_{};
    std::array<std::uint64_t, 2> p1_state_inodes_{};
    std::array<std::uint32_t, 2> p1_state_modes_{};
    std::array<std::uint64_t, 2> p1_state_nlinks_{};
    std::array<std::uint64_t, 2> p1_state_sizes_{};
    kpb::measurement::Digest reservation_identity_{};
    std::atomic_bool live_{true};
    FreshTrialCaptureTopologyQuarantineResidual(
        std::array<int, 10>, std::array<int, 10>,
        std::array<std::uint64_t, 10>,
        std::array<std::uint64_t, 10>,
        std::array<std::uint32_t, 10>, std::array<int, 10>,
        std::array<std::uint64_t, 10>,
        std::array<std::uint64_t, 10>,
        std::array<std::uint32_t, 10>,
        std::array<std::uint64_t, 10>,
        std::array<std::uint64_t, 10>, std::array<int, 2>,
        std::array<int, 2>, std::array<std::uint64_t, 2>,
        std::array<std::uint64_t, 2>,
        std::array<std::uint32_t, 2>,
        std::array<std::uint64_t, 2>,
        std::array<std::uint64_t, 2>, kpb::measurement::Digest);
    friend class FreshTrialCaptureTopologyActivationTransfer;
    friend class RegisteredPersistentFreshTrialActivationBridge;
public:
    FreshTrialCaptureTopologyQuarantineResidual(
        const FreshTrialCaptureTopologyQuarantineResidual&) = delete;
    FreshTrialCaptureTopologyQuarantineResidual& operator=(
        const FreshTrialCaptureTopologyQuarantineResidual&) = delete;
    FreshTrialCaptureTopologyQuarantineResidual(
        FreshTrialCaptureTopologyQuarantineResidual&&) noexcept;
    FreshTrialCaptureTopologyQuarantineResidual& operator=(
        FreshTrialCaptureTopologyQuarantineResidual&&) = delete;
    ~FreshTrialCaptureTopologyQuarantineResidual();
#ifdef KPI_FRESH_TRIAL_CAPTURE_TOPOLOGY_RESERVATION_TEST_SETUP
    struct TestSummary {
        std::array<bool, 10> read_ends_retained{};
        std::array<bool, 10> writer_aliases_retained{};
        std::array<bool, 10> archives_retained{};
        std::array<std::uint64_t, 10> archive_devices{};
        std::array<std::uint64_t, 10> archive_inodes{};
        std::array<bool, 2> p1_state_parent_reads_retained{};
        std::array<bool, 2> p1_state_writers_retained{};
        std::array<std::uint64_t, 2> p1_state_devices{};
        std::array<std::uint64_t, 2> p1_state_inodes{};
        kpb::measurement::Digest reservation_identity{};
    };
    TestSummary test_only_summary() const;
#endif
};

// Successful activation's parent-held half of the P1 private-state channel.
// It owns two independent read-only descriptions of the direct anonymous
// archives; the authenticated activation bridge must have transferred and
// closed the two sole writable descriptions before constructing it.
class FreshTrialP1StateArchiveResidual final {
    std::array<int, 2> parent_read_fds_{};
    std::array<std::uint64_t, 2> devices_{};
    std::array<std::uint64_t, 2> inodes_{};
    std::array<std::uint32_t, 2> modes_{};
    std::array<std::uint64_t, 2> nlinks_{};
    std::array<std::uint64_t, 2> sizes_{};
    kpb::measurement::Digest reservation_identity_{};
    std::atomic_bool live_{true};
    FreshTrialP1StateArchiveResidual(
        std::array<int, 2>, std::array<std::uint64_t, 2>,
        std::array<std::uint64_t, 2>,
        std::array<std::uint32_t, 2>,
        std::array<std::uint64_t, 2>,
        std::array<std::uint64_t, 2>, kpb::measurement::Digest);
    friend class RegisteredPersistentFreshTrialActivationBridge;
    friend class RegisteredP1StateArchiveScmBridge;
    friend class FreshTrialCaptureTopologyReservation;
public:
    FreshTrialP1StateArchiveResidual(
        const FreshTrialP1StateArchiveResidual&) = delete;
    FreshTrialP1StateArchiveResidual& operator=(
        const FreshTrialP1StateArchiveResidual&) = delete;
    FreshTrialP1StateArchiveResidual(
        FreshTrialP1StateArchiveResidual&&) noexcept;
    FreshTrialP1StateArchiveResidual& operator=(
        FreshTrialP1StateArchiveResidual&&) = delete;
    ~FreshTrialP1StateArchiveResidual();
#ifdef KPI_FRESH_TRIAL_CAPTURE_TOPOLOGY_RESERVATION_TEST_SETUP
    struct TestSummary {
        std::array<bool, 2> parent_reads_retained{};
        std::array<std::uint64_t, 2> devices{};
        std::array<std::uint64_t, 2> inodes{};
        kpb::measurement::Digest reservation_identity{};
    };
    TestSummary test_only_summary() const;
#endif
};

// Post-activation producer half: all ten sole-reader ends and all ten
// preopened archive files. It contains no writer alias and no public FD path.
class FreshTrialCaptureProducerTopologyResidual final {
    std::array<int, 10> read_ends_{};
    std::array<std::uint64_t, 10> endpoint_devices_{};
    std::array<std::uint64_t, 10> endpoint_inodes_{};
    std::array<std::uint32_t, 10> endpoint_types_{};
    std::array<int, 10> archive_fds_{};
    std::array<std::uint64_t, 10> archive_devices_{};
    std::array<std::uint64_t, 10> archive_inodes_{};
    std::array<std::uint32_t, 10> archive_modes_{};
    std::array<std::uint64_t, 10> archive_nlinks_{};
    std::array<std::uint64_t, 10> archive_sizes_{};
    std::array<std::uint64_t, 2> p1_state_devices_{};
    std::array<std::uint64_t, 2> p1_state_inodes_{};
    std::array<std::uint32_t, 2> p1_state_modes_{};
    std::array<std::uint64_t, 2> p1_state_nlinks_{};
    std::array<std::uint64_t, 2> p1_state_sizes_{};
    kpb::measurement::Digest reservation_identity_{};
    std::atomic_bool live_{true};
    void require_resources_valid() const;
    FreshTrialCaptureProducerTopologyResidual(
        std::array<int, 10>, std::array<std::uint64_t, 10>,
        std::array<std::uint64_t, 10>,
        std::array<std::uint32_t, 10>, std::array<int, 10>,
        std::array<std::uint64_t, 10>,
        std::array<std::uint64_t, 10>,
        std::array<std::uint32_t, 10>,
        std::array<std::uint64_t, 10>,
        std::array<std::uint64_t, 10>,
        std::array<std::uint64_t, 2>,
        std::array<std::uint64_t, 2>,
        std::array<std::uint32_t, 2>,
        std::array<std::uint64_t, 2>,
        std::array<std::uint64_t, 2>, kpb::measurement::Digest);
    friend class RegisteredPersistentFreshTrialActivationBridge;
    friend class RegisteredFreshTrialProducerClosureBridge;
    friend class FreshTrialCaptureTopologyReservation;
public:
    FreshTrialCaptureProducerTopologyResidual(
        const FreshTrialCaptureProducerTopologyResidual&) = delete;
    FreshTrialCaptureProducerTopologyResidual& operator=(
        const FreshTrialCaptureProducerTopologyResidual&) = delete;
    FreshTrialCaptureProducerTopologyResidual(
        FreshTrialCaptureProducerTopologyResidual&&) noexcept;
    FreshTrialCaptureProducerTopologyResidual& operator=(
        FreshTrialCaptureProducerTopologyResidual&&) = delete;
    ~FreshTrialCaptureProducerTopologyResidual();
#ifdef KPI_FRESH_TRIAL_CAPTURE_TOPOLOGY_RESERVATION_TEST_SETUP
    void test_only_corrupt_archive_inode(unsigned);
#endif
};

// Post-activation external-producer half. Only terminal-history and C1 writer
// slots 1/4/6/9 may remain live; P0/P1 role writers must already be consumed
// and closed by the authenticated activation bridge.
class FreshTrialCaptureExternalWriterResidual final {
    std::array<int, 10> writer_aliases_{};
    std::array<std::uint64_t, 10> endpoint_devices_{};
    std::array<std::uint64_t, 10> endpoint_inodes_{};
    std::array<std::uint32_t, 10> endpoint_types_{};
    kpb::measurement::Digest reservation_identity_{};
    std::atomic_bool live_{true};
    FreshTrialCaptureExternalWriterResidual(
        std::array<int, 10>, std::array<std::uint64_t, 10>,
        std::array<std::uint64_t, 10>,
        std::array<std::uint32_t, 10>, kpb::measurement::Digest);
    friend class RegisteredPersistentFreshTrialActivationBridge;
public:
    FreshTrialCaptureExternalWriterResidual(
        const FreshTrialCaptureExternalWriterResidual&) = delete;
    FreshTrialCaptureExternalWriterResidual& operator=(
        const FreshTrialCaptureExternalWriterResidual&) = delete;
    FreshTrialCaptureExternalWriterResidual(
        FreshTrialCaptureExternalWriterResidual&&) noexcept;
    FreshTrialCaptureExternalWriterResidual& operator=(
        FreshTrialCaptureExternalWriterResidual&&) = delete;
    ~FreshTrialCaptureExternalWriterResidual();
};

class FreshTrialCaptureTopologyReservation final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit FreshTrialCaptureTopologyReservation(std::unique_ptr<Storage>);
    FreshTrialCaptureTopologyActivationTransfer
        consume_for_activation() &&;
    void validate_for_activation() const;
    const void* preidentity_epoch_token() const noexcept;
    void bind_preidentity_epoch(
        std::shared_ptr<const detail::PersistentProcessReservationEpoch>);
    friend class FreshTrialCaptureTopologyReservationBridge;
    friend class RegisteredFreshTrialProducerClosureBridge;
    friend class RegisteredPreidentityReadyBridge;
    friend class RegisteredPreidentityReadyIssuanceBridge;
    friend class RegisteredPersistentFreshTrialActivationBridge;
public:
    FreshTrialCaptureTopologyReservation(
        const FreshTrialCaptureTopologyReservation&) = delete;
    FreshTrialCaptureTopologyReservation& operator=(
        const FreshTrialCaptureTopologyReservation&) = delete;
    FreshTrialCaptureTopologyReservation(
        FreshTrialCaptureTopologyReservation&&) noexcept;
    FreshTrialCaptureTopologyReservation& operator=(
        FreshTrialCaptureTopologyReservation&&) = delete;
    ~FreshTrialCaptureTopologyReservation();

#ifdef KPI_FRESH_TRIAL_CAPTURE_TOPOLOGY_RESERVATION_TEST_SETUP
    struct TestSummary {
        std::array<PublicUnboundCaptureWriterContract, 10> contracts{};
        std::array<bool, 10> read_ends_valid{};
        std::array<bool, 10> writer_aliases_valid{};
        std::array<bool, 10> archives_valid{};
        std::array<std::uint64_t, 10> endpoint_devices{};
        std::array<std::uint64_t, 10> endpoint_inodes{};
        std::array<std::uint64_t, 10> archive_devices{};
        std::array<std::uint64_t, 10> archive_inodes{};
        std::array<std::uint32_t, 10> archive_modes{};
        std::array<std::uint64_t, 10> archive_nlinks{};
        std::array<std::uint64_t, 10> archive_sizes{};
        std::array<PublicUnboundP1StateArchiveContract, 2>
            p1_state_contracts{};
        std::array<bool, 2> p1_state_parent_reads_valid{};
        std::array<bool, 2> p1_state_writer_aliases_valid{};
        std::array<std::uint64_t, 2> p1_state_devices{};
        std::array<std::uint64_t, 2> p1_state_inodes{};
        std::array<std::uint32_t, 2> p1_state_modes{};
        std::array<std::uint64_t, 2> p1_state_nlinks{};
        std::array<std::uint64_t, 2> p1_state_sizes{};
        kpb::measurement::Digest reservation_identity{};
    };
    TestSummary test_only_summary() const;
    FreshTrialCaptureProducerTopologyResidual
        test_only_take_producer_residual() &&;
    FreshTrialCaptureTopologyQuarantineResidual
        test_only_take_quarantine_residual(
            std::array<bool, 10> transferred_writers) &&;
    FreshTrialP1StateArchiveResidual
        test_only_take_p1_state_archive_residual() &&;
    FreshTrialCaptureTopologyActivationTransfer
        test_only_take_activation_transfer() &&;
#endif
};

struct FreshTrialCaptureTopologyReservationSourceStatus {
    bool no_trial_identity_input{};
    bool exact_ten_read_end_reservation{};
    bool exact_ten_writer_alias_reservation{};
    bool exact_ten_anonymous_disk_archives{};
    bool private_resource_schedule_identity{};
    bool archive_mode_nlink_size_bound{};
    bool corrupt_server_slots_3_8_and_fds_23_28{};
    bool descriptor_fingerprints_revalidated{};
    bool exact_two_p1_state_archives{};
    bool p1_state_parent_read_descriptions{};
    bool p1_state_sole_writer_aliases{};
    bool p1_state_labeled_scm_contract{};
    bool p1_state_fixed_child_fds_absent{};
    bool p1_state_scm_activation_integration{};
    bool p1_state_capsule_source_bridge{};
    bool p1_state_terminal_disposition_bound{};
    bool p1_state_parent_rehydration{};
    bool p1_state_completion_authority{};
    bool unbound_production_reserve_absent{};
    bool process_derived_reservation_permit_contract{};
    bool process_derived_reservation_permit_consumed{};
    bool hidden_process_epoch_bound{};
    bool child_postfork_fd_enumeration_control{};
    bool postclaim_quarantine_residual{};
    bool no_allocation_unavailable_composite{};
    bool launch_authority_absent{};
    bool all_three_pidfds_reserved_before_issuance{};
    bool selected_run_binding_factory{};
    bool fresh_trial_bind_integration{};
    bool selected_parent_callsite{};
    bool configured{};
};

inline constexpr FreshTrialCaptureTopologyReservationSourceStatus
    kFreshTrialCaptureTopologyReservationSourceStatus{
        .no_trial_identity_input = true,
        .exact_ten_read_end_reservation = true,
        .exact_ten_writer_alias_reservation = true,
        .exact_ten_anonymous_disk_archives = true,
        .private_resource_schedule_identity = true,
        .archive_mode_nlink_size_bound = true,
        .corrupt_server_slots_3_8_and_fds_23_28 = true,
        .descriptor_fingerprints_revalidated = true,
        .exact_two_p1_state_archives = true,
        .p1_state_parent_read_descriptions = true,
        .p1_state_sole_writer_aliases = true,
        .p1_state_labeled_scm_contract = true,
        .p1_state_fixed_child_fds_absent = true,
        .p1_state_scm_activation_integration = false,
        .p1_state_capsule_source_bridge = false,
        .p1_state_terminal_disposition_bound = false,
        .p1_state_parent_rehydration = false,
        .p1_state_completion_authority = false,
        .unbound_production_reserve_absent = true,
        .process_derived_reservation_permit_contract = true,
        .process_derived_reservation_permit_consumed = true,
        .hidden_process_epoch_bound = true,
        // The persistent-process reservation closes every inherited
        // descriptor except stdio and its authenticated channels before it
        // enumerates /proc/self/fd and can emit abort 121. Topology allocation
        // occurs only later under that process-derived permit.
        .child_postfork_fd_enumeration_control = true,
        .postclaim_quarantine_residual = true,
        .no_allocation_unavailable_composite = false,
        .launch_authority_absent = true,
        .all_three_pidfds_reserved_before_issuance = false,
        .selected_run_binding_factory = false,
        .fresh_trial_bind_integration = false,
        .selected_parent_callsite = false,
        .configured = false,
    };

} // namespace kpi::mpc::financial::registered_driver
