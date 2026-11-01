#pragma once

// Source-only architecture-A process topology. One selected outer parent forks
// exactly three internally assigned MPC roles before threads exist. The parent
// delivers each role over an inherited AF_UNIX SOCK_SEQPACKET capability
// channel; every packet is authenticated with kernel SCM_CREDENTIALS. This
// module does not select a plan, start the registered gate, or authorize launch.

#include "registered_driver_bridge.hpp"
#include "registered_parent_bootstrap.hpp"
#include "registered_parent_round_completion_contract.hpp"
#include "registered_preidentity_ready_contract.hpp"
#include "registered_persistent_fresh_trial_activation_contract.hpp"
#include "registered_persistent_role_session_contract.hpp"
#include "registered_p1_state_archive_scm_contract.hpp"
#include "registered_selected_producer_activation_contract.hpp"
#include "../../private_batch_trial/privacy_all_branch_fresh_trial_owner_contract.hpp"
#include "../../private_batch_trial/privacy_registered_fresh_trial_capture_topology_reservation_contract.hpp"
#include "baseline_owner_scoring_parent_transport.hpp"
#include "registered_party_completion_transport.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace kpi::mpc::financial::registered_driver {

namespace projection_route {
class Role0ProjectionRouteWriterAuthority;
class ParentProjectionRouteEndpointAuthority;
} // namespace projection_route

enum class InheritedCaptureKind : std::uint8_t {
    Projection = 1,
    Dispatcher = 2,
    CorruptServer = 3,
};

struct PublicInheritedCaptureEndpoint {
    InheritedCaptureKind kind{};
    unsigned role{};
    unsigned round{};
    int fixed_fd{-1};
    Digest authority_identity{};
    Digest capture_plan_identity{};
};

struct PublicParentRoleBinding {
    unsigned role{};
    Digest party_session{};
    Digest service_identity{};
    Digest driver_selection_identity{};
};

struct PublicParentRoleForkPlan {
    CaptureClassification classification{};
    unsigned round{};
    std::string capture_trial_id;
    Digest trial{};
    Digest financial_run{};
    Digest attempt{};
    Digest cohort{};
    // Opaque trial issuance identity: it binds the same private logical owner
    // roster across R1/R2 without revealing owner IDs or roots.
    Digest fresh_owner_issuance_identity{};
    Digest authority_identity{};
    Digest supervisor_session{};
    Digest capture_plan_identity{};
    Digest capture_source_identity{};
    Digest capture_build_identity{};
    Digest capture_launcher_identity{};
    std::array<PublicParentRoleBinding, 3> roles{};
};

class ParentRoleForkPlanAuthority;
class RegisteredParentRoleFork;
class RegisteredPersistentRoleActivationResult;
struct RegisteredSelectedProducerPrelaunchPlan;

// A selected capture supervisor must eventually mint these from three distinct
// pipe/socket write ends. Raw descriptors have no production constructor.
class InheritedCaptureEndpointAuthority final {
    PublicInheritedCaptureEndpoint value_;
    std::uint64_t device_{};
    std::uint64_t inode_{};
    std::uint32_t file_type_{};
    int source_fd_{-1};
    std::atomic_bool live_{true};
    InheritedCaptureEndpointAuthority(
        PublicInheritedCaptureEndpoint, int source_fd);
    friend class ParentRoleForkPlanAuthority;
    friend class RegisteredParentRoleFork;
public:
    InheritedCaptureEndpointAuthority(
        const InheritedCaptureEndpointAuthority&) = delete;
    InheritedCaptureEndpointAuthority& operator=(
        const InheritedCaptureEndpointAuthority&) = delete;
    InheritedCaptureEndpointAuthority(
        InheritedCaptureEndpointAuthority&&) noexcept;
    InheritedCaptureEndpointAuthority& operator=(
        InheritedCaptureEndpointAuthority&&) = delete;
    ~InheritedCaptureEndpointAuthority();
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
    static InheritedCaptureEndpointAuthority test_only_mint(
        PublicInheritedCaptureEndpoint, int source_fd);
    const PublicInheritedCaptureEndpoint& test_only_public_receipt() const {
        return value_;
    }
#endif
};

// The one-shot plan owns the only inherited write aliases. Minting it consumes
// exact typed projection/dispatcher/P1 endpoint authorities.
class ParentRoleForkPlanAuthority final {
    PublicParentRoleForkPlan value_;
    std::array<PublicInheritedCaptureEndpoint, 3> endpoints_{};
    std::array<std::uint64_t, 3> devices_{};
    std::array<std::uint64_t, 3> inodes_{};
    std::array<std::uint32_t, 3> file_types_{};
    std::array<int, 3> source_fds_{{-1, -1, -1}};
    std::unique_ptr<
        projection_route::Role0ProjectionRouteWriterAuthority>
        projection_route_writer_;
    Digest projection_route_identity_{};
    bool projection_route_join_attempted_{};
    Digest identity_{};
    std::atomic_bool live_{true};
    ParentRoleForkPlanAuthority(
        PublicParentRoleForkPlan,
        std::array<InheritedCaptureEndpointAuthority, 3>&&);
    static bool close_inherited_projection_route_parent_alias(
        projection_route::Role0ProjectionRouteWriterAuthority&,
        std::uint8_t test_fault, unsigned role);
    void claim_for_persistent_activation();
    friend class RegisteredParentRoleFork;
    friend class RegisteredParentPersistentRoleFork;
    friend class RegisteredPersistentFreshTrialActivationBridge;
public:
    ParentRoleForkPlanAuthority(const ParentRoleForkPlanAuthority&) = delete;
    ParentRoleForkPlanAuthority& operator=(
        const ParentRoleForkPlanAuthority&) = delete;
    ParentRoleForkPlanAuthority(ParentRoleForkPlanAuthority&&) noexcept;
    ParentRoleForkPlanAuthority& operator=(
        ParentRoleForkPlanAuthority&&) = delete;
    ~ParentRoleForkPlanAuthority();
    const PublicParentRoleForkPlan& public_plan() const { return value_; }
    const Digest& identity() const { return identity_; }
    // Possession of both typed capabilities authorizes this one-shot join.
    // There is no descriptor, PID, digest, argv, or environment overload.
    void consume_projection_route_writer(
        projection_route::Role0ProjectionRouteWriterAuthority&&);
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
    static ParentRoleForkPlanAuthority test_only_mint(
        PublicParentRoleForkPlan,
        std::array<InheritedCaptureEndpointAuthority, 3>&&);
#endif
};

struct PublicParentAuthenticatedPartyDelivery {
    unsigned role{};
    unsigned round{};
    std::int64_t parent_pid{};
    std::int64_t child_pid{};
    Digest authority_identity{};
    Digest supervisor_session{};
    Digest party_session{};
    Digest service_identity{};
    Digest driver_selection_identity{};
    Digest fresh_owner_issuance_identity{};
    Digest capture_plan_identity{};
    Digest capture_source_identity{};
    Digest capture_build_identity{};
    Digest capture_launcher_identity{};
    Digest fork_plan_identity{};
    Digest offer_identity{};
    Digest ack_identity{};
    std::array<int, 2> fixed_capture_fds{{-1, -1}};
    std::uint8_t fixed_capture_fd_count{};
    bool projection_route_parent_peer_alias_closed{};
};

class ParentAuthenticatedPartyDeliveryAuthority;

// Sealed role dispatch.  A role-specialized wrapper owns the same exact
// delivery and can yield it once to the existing generic bootstrap flow.
// Only the Role1 wrapper exposes the separately typed chronology-valid P1
// prelaunch residual; Role0/Role2 can never acquire that method by
// construction.
class ParentAuthenticatedRole0Delivery final {
    std::unique_ptr<ParentAuthenticatedPartyDeliveryAuthority> delivery_;
    explicit ParentAuthenticatedRole0Delivery(
        std::unique_ptr<ParentAuthenticatedPartyDeliveryAuthority>) noexcept;
    friend class ParentAuthenticatedPartyDeliveryAuthority;
public:
    ParentAuthenticatedRole0Delivery(
        const ParentAuthenticatedRole0Delivery&) = delete;
    ParentAuthenticatedRole0Delivery& operator=(
        const ParentAuthenticatedRole0Delivery&) = delete;
    ParentAuthenticatedRole0Delivery(
        ParentAuthenticatedRole0Delivery&&) noexcept;
    ParentAuthenticatedRole0Delivery& operator=(
        ParentAuthenticatedRole0Delivery&&) = delete;
    ~ParentAuthenticatedRole0Delivery();
    ParentAuthenticatedPartyDeliveryAuthority take_delivery() &&;
};

class ParentAuthenticatedRole1Delivery final {
    std::unique_ptr<ParentAuthenticatedPartyDeliveryAuthority> delivery_;
    explicit ParentAuthenticatedRole1Delivery(
        std::unique_ptr<ParentAuthenticatedPartyDeliveryAuthority>) noexcept;
    friend class ParentAuthenticatedPartyDeliveryAuthority;
public:
    ParentAuthenticatedRole1Delivery(
        const ParentAuthenticatedRole1Delivery&) = delete;
    ParentAuthenticatedRole1Delivery& operator=(
        const ParentAuthenticatedRole1Delivery&) = delete;
    ParentAuthenticatedRole1Delivery(
        ParentAuthenticatedRole1Delivery&&) noexcept;
    ParentAuthenticatedRole1Delivery& operator=(
        ParentAuthenticatedRole1Delivery&&) = delete;
    ~ParentAuthenticatedRole1Delivery();
    RegisteredRole1P1StatePrelaunchAuthority
        take_p1_state_prelaunch();
    ParentAuthenticatedPartyDeliveryAuthority take_delivery() &&;
};

class ParentAuthenticatedRole2Delivery final {
    std::unique_ptr<ParentAuthenticatedPartyDeliveryAuthority> delivery_;
    explicit ParentAuthenticatedRole2Delivery(
        std::unique_ptr<ParentAuthenticatedPartyDeliveryAuthority>) noexcept;
    friend class ParentAuthenticatedPartyDeliveryAuthority;
public:
    ParentAuthenticatedRole2Delivery(
        const ParentAuthenticatedRole2Delivery&) = delete;
    ParentAuthenticatedRole2Delivery& operator=(
        const ParentAuthenticatedRole2Delivery&) = delete;
    ParentAuthenticatedRole2Delivery(
        ParentAuthenticatedRole2Delivery&&) noexcept;
    ParentAuthenticatedRole2Delivery& operator=(
        ParentAuthenticatedRole2Delivery&&) = delete;
    ~ParentAuthenticatedRole2Delivery();
    ParentAuthenticatedPartyDeliveryAuthority take_delivery() &&;
};

using ParentAuthenticatedRoleDispatch = std::variant<
    ParentAuthenticatedRole0Delivery,
    ParentAuthenticatedRole1Delivery,
    ParentAuthenticatedRole2Delivery>;

// Minted in a role child only after it validates the parent's kernel
// credentials, exact offer, fixed descriptors and successfully sends its ACK.
class ParentAuthenticatedPartyDeliveryAuthority final {
    PublicParentAuthenticatedPartyDelivery value_;
    Digest channel_nonce_{};
    std::unique_ptr<
        projection_route::Role0ProjectionRouteWriterAuthority>
        projection_route_writer_;
    // Type-erased solely to keep the generic fork/delivery object free of a
    // link-time dependency on the optional P1 state-channel implementation.
    // Only the complete SCM bridge can install or recover the typed object.
    void* role1_p1_state_prelaunch_{};
    void (*role1_p1_state_prelaunch_destroy_)(void*) noexcept {};
    bool role1_p1_state_prelaunch_attached_{};
    bool role1_p1_state_prelaunch_taken_{};
    std::atomic_bool live_{true};
    explicit ParentAuthenticatedPartyDeliveryAuthority(
        PublicParentAuthenticatedPartyDelivery, Digest channel_nonce,
        std::unique_ptr<
            projection_route::Role0ProjectionRouteWriterAuthority>);
    friend class RegisteredParentRoleFork;
    friend class RegisteredParentPersistentRoleFork;
    friend class attempt_supervisor::RegisteredProposalBridge;
    friend class RegisteredParentBootstrapTransport;
    friend class RegisteredP1StateArchiveScmBridge;
    friend class ParentAuthenticatedRole0Delivery;
    friend class ParentAuthenticatedRole1Delivery;
    friend class ParentAuthenticatedRole2Delivery;
public:
    ParentAuthenticatedPartyDeliveryAuthority(
        const ParentAuthenticatedPartyDeliveryAuthority&) = delete;
    ParentAuthenticatedPartyDeliveryAuthority& operator=(
        const ParentAuthenticatedPartyDeliveryAuthority&) = delete;
    ParentAuthenticatedPartyDeliveryAuthority(
        ParentAuthenticatedPartyDeliveryAuthority&&) noexcept;
    ParentAuthenticatedPartyDeliveryAuthority& operator=(
        ParentAuthenticatedPartyDeliveryAuthority&&) = delete;
    ~ParentAuthenticatedPartyDeliveryAuthority();
    const PublicParentAuthenticatedPartyDelivery& public_receipt() const {
        return value_;
    }
    projection_route::Role0ProjectionRouteWriterAuthority
    take_projection_route_writer();
    ParentAuthenticatedRoleDispatch dispatch_role() &&;
};

namespace detail {
struct ParentRoleCompletionState {
    std::mutex mutex;
    std::array<bool, 3> completed{};
    bool poisoned{};
};
struct RoleCompletionBinding {
    unsigned role{};
    unsigned round{};
    CaptureClassification classification{};
    std::string capture_trial_id;
    Digest run{};
    Digest trial{};
    Digest attempt{};
    Digest cohort{};
    Digest fresh_owner_issuance_identity{};
    std::int64_t parent_pid{};
    std::int64_t child_pid{};
    Digest fork_plan_identity{};
    Digest offer_identity{};
    Digest ack_identity{};
    Digest channel_nonce{};
    Digest authority_identity{};
    Digest supervisor_session{};
    Digest party_session{};
    Digest service_identity{};
    Digest driver_selection_identity{};
    Digest capture_plan_identity{};
    Digest capture_source_identity{};
    Digest capture_build_identity{};
    Digest capture_launcher_identity{};
};
struct ChildProcessSet;
struct PersistentProcessReservationEpoch;
class PersistentRoleExitEvidence;
} // namespace detail

// These endpoint capabilities retain the already authenticated role channel.
// They expose no descriptor or packet operation. The fully-defined baseline
// transport friend consumes the child endpoint with the genuine party result
// and consumes the parent endpoint while validating the fixed binary reply.
class ChildRoleCompletionEndpointAuthority final {
    detail::RoleCompletionBinding binding_;
    int fd_{-1};
    std::uint8_t supervisor_phase_{};
    std::atomic_bool live_{true};
    ChildRoleCompletionEndpointAuthority(
        detail::RoleCompletionBinding, int fd);
    void send_fixed(
        const Digest& payload_type,
        std::span<const unsigned char> payload);
#ifdef KPI_REGISTERED_PARTY_COMPLETION_TRANSPORT_TEST_SETUP
    void test_only_send_fixed_duplicate(
        const Digest& payload_type,
        std::span<const unsigned char> payload);
#endif
    void send_role_packet(
        std::uint8_t expected_phase, std::uint8_t next_phase,
        std::span<const unsigned char> packet);
    std::vector<unsigned char> receive_role_packet(
        std::uint8_t expected_phase, std::uint8_t next_phase,
        std::size_t exact_bytes);
    void poison_role_channel() noexcept;
    friend class RegisteredParentRoleFork;
    friend class RegisteredParentPersistentRoleFork;
    friend class baseline_disclosure::BaselineOwnerScoringParentTransport;
    friend class RegisteredPartyCompletionTransport;
    friend class RegisteredSupervisorParentTransport;
    friend class RegisteredParentBootstrapTransport;
    friend class RegisteredChildBootstrapPending;
    friend class RegisteredFullCohortReleaseBarrier;
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
    friend class ParentRoleForkTestCompletionBridge;
#endif
public:
    ChildRoleCompletionEndpointAuthority(
        const ChildRoleCompletionEndpointAuthority&) = delete;
    ChildRoleCompletionEndpointAuthority& operator=(
        const ChildRoleCompletionEndpointAuthority&) = delete;
    ChildRoleCompletionEndpointAuthority(
        ChildRoleCompletionEndpointAuthority&&) noexcept;
    ChildRoleCompletionEndpointAuthority& operator=(
        ChildRoleCompletionEndpointAuthority&&) = delete;
    ~ChildRoleCompletionEndpointAuthority();
};

class ParentRoleCompletionEndpointAuthority final {
    detail::RoleCompletionBinding binding_;
    int fd_{-1};
    std::uint8_t supervisor_phase_{};
    std::shared_ptr<detail::ParentRoleCompletionState> state_;
    std::atomic_bool live_{true};
    ParentRoleCompletionEndpointAuthority(
        detail::RoleCompletionBinding, int fd,
        std::shared_ptr<detail::ParentRoleCompletionState>,
        std::uint8_t supervisor_phase);
    std::vector<unsigned char> receive_fixed(
        const Digest& payload_type, std::size_t exact_payload_bytes);
    friend class ParentRoleChildren;
    friend class baseline_disclosure::BaselineOwnerScoringParentTransport;
    friend class RegisteredPartyCompletionTransport;
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
    friend class ParentRoleForkTestCompletionBridge;
#endif
public:
    ParentRoleCompletionEndpointAuthority(
        const ParentRoleCompletionEndpointAuthority&) = delete;
    ParentRoleCompletionEndpointAuthority& operator=(
        const ParentRoleCompletionEndpointAuthority&) = delete;
    ParentRoleCompletionEndpointAuthority(
        ParentRoleCompletionEndpointAuthority&&) noexcept;
    ParentRoleCompletionEndpointAuthority& operator=(
        ParentRoleCompletionEndpointAuthority&&) = delete;
    ~ParentRoleCompletionEndpointAuthority();
};

#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
class ParentRoleForkTestCompletionBridge final {
public:
    static void submit(
        ChildRoleCompletionEndpointAuthority&&, const Digest& payload_type,
        std::span<const unsigned char> payload);
    static std::vector<unsigned char> receive(
        ParentRoleCompletionEndpointAuthority&&, const Digest& payload_type,
        std::size_t exact_payload_bytes);
    // Adversarial control only: queue a zero-length SOCK_SEQPACKET record and
    // deliberately keep the peer open.  A receiver must not mistake this for
    // authenticated child closure.
    static void submit_zero_record_then_hold(
        ChildRoleCompletionEndpointAuthority&&, const Digest& payload_type,
        std::span<const unsigned char> payload);
};
#endif

class RegisteredRoleChildProgram {
public:
    virtual ~RegisteredRoleChildProgram() = default;
    virtual int run(
        ParentAuthenticatedPartyDeliveryAuthority&&,
        ChildRoleCompletionEndpointAuthority&&) = 0;
};

// The persistent parent forks once. Each child executes the two existing
// one-round programs in order on separate authenticated capability channels;
// no child PID or process session can be substituted between rounds.
class RegisteredPersistentRoleChildProgram {
public:
    virtual ~RegisteredPersistentRoleChildProgram() = default;
    virtual RegisteredRoleChildProgram& round_program(unsigned round) = 0;
};

// Phase-1 child code must be constructed before any trial UUID, fresh-owner
// issuance, round plan or capture topology is consumed. It is inherited only
// as generic executable behavior; activation delivers all trial-bound state
// later over the authenticated reservation channels.
class RegisteredPreIdentityPersistentRoleChildProgram {
public:
    virtual ~RegisteredPreIdentityPersistentRoleChildProgram() = default;
    virtual RegisteredRoleChildProgram& round_program(unsigned round) = 0;
};

struct PublicParentRoleAcknowledgement {
    unsigned role{};
    unsigned round{};
    std::int64_t parent_pid{};
    std::int64_t child_pid{};
    Digest fork_plan_identity{};
    Digest offer_identity{};
    Digest ack_identity{};
};

struct PublicParentRoleForkCompletion {
    Digest fork_plan_identity{};
    std::array<PublicParentRoleAcknowledgement, 3> acknowledgements{};
    bool all_children_exited_zero{};
};

namespace detail {
class PersistentRoleExitEvidence final {
    // Qualification will additionally require exactly two ordered opaque
    // p1_state_capsule::P1CorruptStateCapsuleAuthority residuals (R1 then
    // R2). They are deliberately absent until that source-owned type and its
    // complete join bridge land; no optional/bool/raw substitute is accepted.
    std::array<std::int64_t, 3> child_pids{{-1, -1, -1}};
    std::array<bool, 3> pidfd_exit_observed{};
    std::array<bool, 3> wait_status_available{};
    std::array<bool, 3> pid_identity_exact{};
    std::array<int, 3> exit_codes{{-1, -1, -1}};
    std::array<int, 3> term_signals{};
    std::array<PublicParentRoleForkCompletion, 2> round_channels{};
    Digest process_session_identity{};
    bool live_{true};
    PersistentRoleExitEvidence(
        std::array<std::int64_t, 3>,
        std::array<bool, 3> pidfd_exit_observed,
        std::array<bool, 3> wait_status_available,
        std::array<bool, 3> pid_identity_exact,
        std::array<int, 3> exit_codes,
        std::array<int, 3> term_signals,
        std::array<PublicParentRoleForkCompletion, 2>, Digest);
    friend class ::kpi::mpc::financial::registered_driver::
        RegisteredPersistentRoleSession;
public:
    PersistentRoleExitEvidence(const PersistentRoleExitEvidence&) = delete;
    PersistentRoleExitEvidence& operator=(
        const PersistentRoleExitEvidence&) = delete;
    PersistentRoleExitEvidence(PersistentRoleExitEvidence&&) noexcept;
    PersistentRoleExitEvidence& operator=(
        PersistentRoleExitEvidence&&) = delete;
    ~PersistentRoleExitEvidence();
    const std::array<std::int64_t, 3>& child_pids_value() const noexcept {
        return child_pids;
    }
    const std::array<bool, 3>& pidfd_exit_observed_value() const noexcept {
        return pidfd_exit_observed;
    }
    const std::array<bool, 3>& wait_status_available_value() const noexcept {
        return wait_status_available;
    }
    const std::array<bool, 3>& pid_identity_exact_value() const noexcept {
        return pid_identity_exact;
    }
    const std::array<int, 3>& exit_codes_value() const noexcept {
        return exit_codes;
    }
    const std::array<int, 3>& term_signals_value() const noexcept {
        return term_signals;
    }
    const std::array<PublicParentRoleForkCompletion, 2>&
    round_channels_value() const noexcept { return round_channels; }
    const Digest& process_session_identity_value() const noexcept {
        return process_session_identity;
    }
    bool all_children_exited_zero_value() const noexcept;
};

class PersistentRoleReservationAbortEvidence final {
    std::array<std::int64_t, 3> child_pids{{-1, -1, -1}};
    std::array<bool, 3> pidfd_exit_observed{};
    std::array<bool, 3> wait_status_available{};
    std::array<bool, 3> pid_identity_exact{};
    std::array<int, 3> exit_codes{{-1, -1, -1}};
    std::array<int, 3> term_signals{};
    std::array<std::array<bool, 3>, 2>
        topology_preflight_acknowledged{};
    std::array<bool, 3> topology_retention_acknowledged{};
    bool pidfd_signal_used{};
    bool live_{true};
    PersistentRoleReservationAbortEvidence(
        std::array<std::int64_t, 3>,
        std::array<bool, 3> pidfd_exit_observed,
        std::array<bool, 3> wait_status_available,
        std::array<bool, 3> pid_identity_exact,
        std::array<int, 3> exit_codes,
        std::array<int, 3> term_signals,
        std::array<std::array<bool, 3>, 2>
            topology_preflight_acknowledged,
        std::array<bool, 3> topology_retention_acknowledged,
        bool pidfd_signal_used);
    friend class ::kpi::mpc::financial::registered_driver::
        RegisteredParentPersistentRoleFork;
public:
    PersistentRoleReservationAbortEvidence(
        const PersistentRoleReservationAbortEvidence&) = delete;
    PersistentRoleReservationAbortEvidence& operator=(
        const PersistentRoleReservationAbortEvidence&) = delete;
    PersistentRoleReservationAbortEvidence(
        PersistentRoleReservationAbortEvidence&&) noexcept;
    PersistentRoleReservationAbortEvidence& operator=(
        PersistentRoleReservationAbortEvidence&&) = delete;
    ~PersistentRoleReservationAbortEvidence();
    const std::array<std::int64_t, 3>& child_pids_value() const noexcept {
        return child_pids;
    }
    const std::array<int, 3>& exit_codes_value() const noexcept {
        return exit_codes;
    }
    const std::array<int, 3>& term_signals_value() const noexcept {
        return term_signals;
    }
    bool pidfd_signal_used_value() const noexcept {
        return live_ && pidfd_signal_used;
    }
    const std::array<std::array<bool, 3>, 2>&
    topology_preflight_acknowledged_value() const noexcept {
        return topology_preflight_acknowledged;
    }
    const std::array<bool, 3>&
    topology_retention_acknowledged_value() const noexcept {
        return topology_retention_acknowledged;
    }
    bool topology_preflight_complete_value() const noexcept;
    bool all_children_settled_value() const noexcept;
};
} // namespace detail

class ParentRoleChildren final {
    std::shared_ptr<detail::ChildProcessSet> child_processes_;
    std::array<int, 3> completion_fds_{{-1, -1, -1}};
    std::array<detail::RoleCompletionBinding, 3> completion_bindings_{};
    std::array<bool, 3> completion_endpoints_taken_{};
    std::array<std::uint8_t, 3> supervisor_phases_{};
    std::shared_ptr<detail::ParentRoleCompletionState> completion_state_;
    std::array<PublicParentRoleAcknowledgement, 3> acknowledgements_{};
    Digest fork_plan_identity_{};
    Digest projection_route_identity_{};
    bool projection_route_parent_binding_attempted_{};
    bool projection_route_parent_bound_{};
    std::array<Digest, 3> release_ready_identities_{};
    Digest full_cohort_barrier_identity_{};
    std::uint64_t full_cohort_barrier_monotonic_ns_{};
    bool full_cohort_release_authorized_{};
    mutable std::mutex mutex_;
    bool process_owner_{true};
    bool live_{true};
    ParentRoleChildren(
        std::shared_ptr<detail::ChildProcessSet>,
        std::array<int, 3>,
        std::array<detail::RoleCompletionBinding, 3>,
        std::shared_ptr<detail::ParentRoleCompletionState>,
        std::array<PublicParentRoleAcknowledgement, 3>, Digest,
        Digest projection_route_identity, bool process_owner = true);
    std::vector<unsigned char> receive_role_packet(
        unsigned role, std::uint8_t expected_phase,
        std::uint8_t next_phase, std::size_t exact_bytes);
    void send_role_packet(
        unsigned role, std::uint8_t expected_phase,
        std::uint8_t next_phase,
        std::span<const unsigned char> packet);
    void poison_role_channels() noexcept;
    std::int64_t child_pid(unsigned role) const;
    friend class RegisteredParentRoleFork;
    friend class RegisteredParentPersistentRoleFork;
    friend class RegisteredPersistentRoleSession;
    friend class RegisteredParentRoundCompletionBridge;
    friend class RegisteredParentTrialCompletionBridge;
    friend class RegisteredSupervisorParentTransport;
    friend class RegisteredParentBootstrapTransport;
    friend class RegisteredFullCohortReleaseBarrier;
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
    friend class ParentRoleForkTestProcessBridge;
#endif
public:
    ParentRoleChildren(const ParentRoleChildren&) = delete;
    ParentRoleChildren& operator=(const ParentRoleChildren&) = delete;
    ParentRoleChildren(ParentRoleChildren&&) noexcept;
    ParentRoleChildren& operator=(ParentRoleChildren&&) = delete;
    ~ParentRoleChildren();
    const std::array<PublicParentRoleAcknowledgement, 3>&
    public_acknowledgements() const { return acknowledgements_; }
    ParentRoleCompletionEndpointAuthority take_completion_endpoint(
        unsigned role);
    projection_route::ParentProjectionRouteEndpointAuthority
    bind_projection_route_parent(
        projection_route::ParentProjectionRouteEndpointAuthority&&);
    PublicParentRoleForkCompletion wait();
};

class RegisteredPersistentRoleProcessReservation;

// Source-owned proof that the exact generic three-child process reservation
// already exists.  The topology opener consumes this one-shot value before it
// creates any pipe or archive descriptor, so those descriptors cannot be
// inherited by the already-forked children.
class RegisteredTopologyReservationPermit final {
    std::shared_ptr<const detail::PersistentProcessReservationEpoch> epoch_;
    bool live_{true};
    explicit RegisteredTopologyReservationPermit(
        std::shared_ptr<const detail::PersistentProcessReservationEpoch>)
        noexcept;
    void validate_for_topology_reservation() const;
    std::shared_ptr<const detail::PersistentProcessReservationEpoch>
        consume_for_topology_reservation() &&;
    friend class RegisteredPersistentRoleProcessReservation;
    friend class FreshTrialCaptureTopologyReservationBridge;
public:
    RegisteredTopologyReservationPermit(
        const RegisteredTopologyReservationPermit&) = delete;
    RegisteredTopologyReservationPermit& operator=(
        const RegisteredTopologyReservationPermit&) = delete;
    RegisteredTopologyReservationPermit(
        RegisteredTopologyReservationPermit&&) noexcept;
    RegisteredTopologyReservationPermit& operator=(
        RegisteredTopologyReservationPermit&&) = delete;
    ~RegisteredTopologyReservationPermit();
};

class RegisteredPersistentRoleProcessReservation final {
    struct Storage;
    struct TopologyPreflightState final {
        std::array<int, 2> child_state_writers{{-1, -1}};
        std::array<int, 2> child_terminal_fds{{-1, -1}};
        std::array<std::uint64_t, 2> state_devices{};
        std::array<std::uint64_t, 2> state_inodes{};
        std::array<std::uint32_t, 2> state_modes{};
        std::array<std::uint64_t, 2> state_nlinks{};
        std::array<std::uint64_t, 2> state_sizes{};
        std::array<std::uint64_t, 2> terminal_devices{};
        std::array<std::uint64_t, 2> terminal_inodes{};
        std::array<std::uint32_t, 2> terminal_types{};
        Digest reservation_identity{};
        Digest activation_identity{};
        Digest trial_identity{};
        std::array<std::array<Digest, 3>, 2> command_identities{};
        std::array<bool, 3> retention_acknowledged{};
    };
    std::unique_ptr<Storage> storage_;
    explicit RegisteredPersistentRoleProcessReservation(
        std::unique_ptr<Storage>);
    void preflight_capture_topology(
        std::array<int, 10>& writer_aliases,
        const std::array<std::uint64_t, 10>& endpoint_devices,
        const std::array<std::uint64_t, 10>& endpoint_inodes,
        const std::array<std::uint32_t, 10>& endpoint_types,
        TopologyPreflightState&);
    void validate_for_preidentity_ready() const;
    const void* preidentity_epoch_token() const noexcept;
    std::int64_t child_pid_for_activation(unsigned role) const;
    friend class RegisteredParentPersistentRoleFork;
    friend class RegisteredPreidentityReadyBridge;
    friend class RegisteredPreidentityReadyIssuanceBridge;
    friend class RegisteredPersistentFreshTrialActivationBridge;
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
    friend class ParentRoleForkTestProcessBridge;
#endif
public:
    RegisteredPersistentRoleProcessReservation(
        const RegisteredPersistentRoleProcessReservation&) = delete;
    RegisteredPersistentRoleProcessReservation& operator=(
        const RegisteredPersistentRoleProcessReservation&) = delete;
    RegisteredPersistentRoleProcessReservation(
        RegisteredPersistentRoleProcessReservation&&) noexcept;
    RegisteredPersistentRoleProcessReservation& operator=(
        RegisteredPersistentRoleProcessReservation&&) = delete;
    ~RegisteredPersistentRoleProcessReservation();
    RegisteredTopologyReservationPermit
        issue_topology_reservation_permit();
};

// Source-owned round policy with deliberately no writer capability.  Its
// eventual production minter must authenticate the selected round lineage;
// the persistent activation bridge then binds that policy to the only writer
// descriptions already retained by the reserved children.  The legacy
// ParentRoleForkPlanAuthority, which owns a second endpoint set, is not
// accepted by this path.
class RegisteredPersistentWriterlessRoundPlanAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredPersistentWriterlessRoundPlanAuthority(
        std::unique_ptr<Storage>) noexcept;
    friend class RegisteredPersistentFreshTrialActivationBridge;
public:
    RegisteredPersistentWriterlessRoundPlanAuthority(
        const RegisteredPersistentWriterlessRoundPlanAuthority&) = delete;
    RegisteredPersistentWriterlessRoundPlanAuthority& operator=(
        const RegisteredPersistentWriterlessRoundPlanAuthority&) = delete;
    RegisteredPersistentWriterlessRoundPlanAuthority(
        RegisteredPersistentWriterlessRoundPlanAuthority&&) noexcept;
    RegisteredPersistentWriterlessRoundPlanAuthority& operator=(
        RegisteredPersistentWriterlessRoundPlanAuthority&&) = delete;
    ~RegisteredPersistentWriterlessRoundPlanAuthority();
};

// Successful phase-2 resource activation, before any round plan or role
// program can run.  It owns the exact process reservation, issuance lineage,
// topology readers/archives/external writers, and the two unbound parent
// terminal endpoints.  Destruction safely settles the pidfd-pinned children.
class RegisteredPersistentTopologyActivationAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredPersistentTopologyActivationAuthority(
        std::unique_ptr<Storage>) noexcept;
    void bind_selected_prelaunch_plan(
        RegisteredSelectedProducerPrelaunchPlan&) const;
    friend class RegisteredPersistentRoleActivationResult;
    friend class RegisteredPersistentFreshTrialActivationBridge;
    friend class RegisteredSelectedProducerActivationBridge;
public:
    RegisteredPersistentTopologyActivationAuthority(
        const RegisteredPersistentTopologyActivationAuthority&) = delete;
    RegisteredPersistentTopologyActivationAuthority& operator=(
        const RegisteredPersistentTopologyActivationAuthority&) = delete;
    RegisteredPersistentTopologyActivationAuthority(
        RegisteredPersistentTopologyActivationAuthority&&) noexcept;
    RegisteredPersistentTopologyActivationAuthority& operator=(
        RegisteredPersistentTopologyActivationAuthority&&) = delete;
    ~RegisteredPersistentTopologyActivationAuthority();
#ifdef KPI_REGISTERED_PERSISTENT_FRESH_ACTIVATION_TEST_SETUP
    struct TestSummary final {
        bool process_reservation_retained{};
        bool issuance_lineage_retained{};
        bool topology_transfer_retained{};
        std::array<std::array<bool, 3>, 2> command_acknowledged{};
        std::array<bool, 3> retention_acknowledged{};
        std::array<bool, 2> parent_terminal_endpoints_retained{};
        std::array<std::uint64_t, 2> state_devices{};
        std::array<std::uint64_t, 2> state_inodes{};
        std::array<Digest, 2> role1_activation_identities{};
    };
    TestSummary test_only_summary() const;
#endif
};

class RegisteredPersistentRoleActivationFailureResidual final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredPersistentRoleActivationFailureResidual(
        std::unique_ptr<Storage>);
    RegisteredPersistentRoleActivationFailureResidual
        transfer_for_all_branch_stop() &&;
    friend class RegisteredPersistentRoleActivationResult;
    friend class RegisteredPersistentFreshTrialActivationBridge;
    friend class ::kpb::measurement::fresh_trial_owner::
        AllBranchFreshTrialOwnerBridge;
public:
    RegisteredPersistentRoleActivationFailureResidual(
        const RegisteredPersistentRoleActivationFailureResidual&) = delete;
    RegisteredPersistentRoleActivationFailureResidual& operator=(
        const RegisteredPersistentRoleActivationFailureResidual&) = delete;
    RegisteredPersistentRoleActivationFailureResidual(
        RegisteredPersistentRoleActivationFailureResidual&&) noexcept;
    RegisteredPersistentRoleActivationFailureResidual& operator=(
        RegisteredPersistentRoleActivationFailureResidual&&) = delete;
    ~RegisteredPersistentRoleActivationFailureResidual();
#ifdef KPI_REGISTERED_PERSISTENT_FRESH_ACTIVATION_TEST_SETUP
    struct TestSummary {
        bool process_abort_retained{};
        bool activation_authority_retained{};
        bool round1_plan_retained{};
        bool topology_reservation_retained{};
        bool topology_quarantine_retained{};
        std::array<bool, 10> read_ends_retained{};
        std::array<bool, 10> writer_aliases_retained{};
        std::array<bool, 10> archives_retained{};
        std::array<bool, 2> p1_state_parent_reads_retained{};
        std::array<bool, 2> p1_state_writers_retained{};
        std::array<bool, 2> parent_terminal_endpoints_retained{};
        std::array<std::uint64_t, 2> p1_state_devices{};
        std::array<std::uint64_t, 2> p1_state_inodes{};
    };
    TestSummary test_only_summary() const;
    detail::PersistentRoleReservationAbortEvidence
        test_only_take_process_abort_evidence();
#endif
};

class RegisteredPersistentRoleActivationResult final {
    std::unique_ptr<
        RegisteredPersistentRoleActivationFailureResidual::Storage>
        failure_;
    std::unique_ptr<RegisteredPersistentTopologyActivationAuthority>
        topology_activation_;
    explicit RegisteredPersistentRoleActivationResult(
        std::unique_ptr<
            RegisteredPersistentRoleActivationFailureResidual::Storage>);
    explicit RegisteredPersistentRoleActivationResult(
        std::unique_ptr<RegisteredPersistentTopologyActivationAuthority>)
        noexcept;
    friend class RegisteredPersistentFreshTrialActivationBridge;
public:
    RegisteredPersistentRoleActivationResult(
        const RegisteredPersistentRoleActivationResult&) = delete;
    RegisteredPersistentRoleActivationResult& operator=(
        const RegisteredPersistentRoleActivationResult&) = delete;
    RegisteredPersistentRoleActivationResult(
        RegisteredPersistentRoleActivationResult&&) noexcept;
    RegisteredPersistentRoleActivationResult& operator=(
        RegisteredPersistentRoleActivationResult&&) = delete;
    ~RegisteredPersistentRoleActivationResult();
    bool activated() const noexcept { return false; }
    bool topology_prepared() const noexcept {
        return topology_activation_ != nullptr;
    }
    RegisteredPersistentTopologyActivationAuthority
        take_topology_activation() &&;
    RegisteredPersistentRoleActivationFailureResidual
        take_failure_residual() &&;
};

class RegisteredPersistentRoleSession final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredPersistentRoleSession(std::unique_ptr<Storage>);
    void claim_trial_join();
    detail::PersistentRoleExitEvidence finish_wait_for_trial();
    friend class RegisteredParentPersistentRoleFork;
    friend class RegisteredParentTrialCompletionBridge;
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
    friend class ParentRoleForkTestProcessBridge;
#endif
public:
    RegisteredPersistentRoleSession(
        const RegisteredPersistentRoleSession&) = delete;
    RegisteredPersistentRoleSession& operator=(
        const RegisteredPersistentRoleSession&) = delete;
    RegisteredPersistentRoleSession(
        RegisteredPersistentRoleSession&&) noexcept;
    RegisteredPersistentRoleSession& operator=(
        RegisteredPersistentRoleSession&&) = delete;
    ~RegisteredPersistentRoleSession();
};

#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
enum class ParentRoleForkTestFault : std::uint8_t {
    None = 0,
    SwapRoleZeroAndOneOffers = 1,
    SwapProjectionAndCorruptServerSources = 2,
    ParentSelfAcknowledgement = 3,
    WrongProjectionRouteParentPeerFingerprintRole0 = 4,
    ClosedProjectionRouteParentPeerRole1 = 5,
    ReusedProjectionRouteParentPeerFdRole2 = 6,
    FailBeforeRole2Fork = 7,
    FailPidfdOpenRole1 = 8,
};

enum class ParentRoleReservationRetentionTestFault : std::uint8_t {
    None = 0,
    WrongParentReport = 1,
    ReplayActivationCommand = 2,
    SwappedCaptureSlot = 3,
    SwappedRound = 4,
    SameFdWrongMetadata = 5,
    DropMetadataAfterAck = 6,
};

// Hostile controls may corrupt only the redundant raw-PID metadata or force
// idempotent cleanup. They cannot mint a plan, session or completion.
class ParentRoleForkTestProcessBridge final {
public:
    static void replace_raw_pid_metadata(
        RegisteredPersistentRoleSession&, unsigned role,
        std::int64_t replacement);
    static void terminate_and_settle(RegisteredPersistentRoleSession&);
    static void poison_role_channels(ParentRoleChildren&);
    static void close_reservation_channel(
        RegisteredPersistentRoleProcessReservation&, unsigned round,
        unsigned role);
    static void fail_reservation_ack_receive(
        RegisteredPersistentRoleProcessReservation&, unsigned round,
        unsigned role);
    static void set_reservation_retention_fault(
        RegisteredPersistentRoleProcessReservation&,
        ParentRoleReservationRetentionTestFault);
};
#endif

class RegisteredParentRoleFork final {
    static ParentRoleChildren launch_impl(
        ParentRoleForkPlanAuthority&&, RegisteredRoleChildProgram&,
        std::uint8_t test_fault);
public:
    // Must be the selected parent's first process action, before any thread or
    // MP-SPDZ context exists. No argv, environment, path or caller role enters.
    static ParentRoleChildren launch(
        ParentRoleForkPlanAuthority&&, RegisteredRoleChildProgram&);
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
    static ParentRoleChildren test_only_launch(
        ParentRoleForkPlanAuthority&&, RegisteredRoleChildProgram&,
        ParentRoleForkTestFault);
#endif
};

struct ParentRoleForkSourceStatus {
    std::string schema;
    std::string status;
    bool exact_three_internal_roles;
    bool inherited_seqpacket_capability_channels;
    bool kernel_sender_credentials_each_packet;
    bool parent_self_ack_refused;
    bool fixed_capture_fd_role_partition;
    bool role0_projection_route_fixed_fd30;
    bool projection_route_exact_fork_binding;
    bool projection_route_parent_alias_closed_before_offer;
    bool typed_parent_bootstrap_transport;
    bool inherited_parent_sealed_query_artifact;
    bool child_full_query_admission_binding;
    bool parent_supervisor_proposal_approval_transport;
    bool pidfd_exact_process_identity;
    bool pidfd_only_child_signaling;
    bool unavailable_wait_status_refused;
    bool persistent_same_pid_two_round_exit_evidence;
    bool p1_two_round_observer_v5_capsule_residual;
    bool pre_identity_process_reservation;
    bool preidentity_child_descriptor_allowlist;
    bool process_first_topology_reservation_permit;
    bool post_reservation_trial_activation;
    bool process_settled_abort_noalloc;
    bool typed_complete_activation_abort;
    bool selected_plan_factory_integration;
    bool selected_gate_callsite_integration;
    bool registered_driver_configured;
    bool launch_authorized;
};

ParentRoleForkSourceStatus parent_role_fork_source_status();

} // namespace kpi::mpc::financial::registered_driver
