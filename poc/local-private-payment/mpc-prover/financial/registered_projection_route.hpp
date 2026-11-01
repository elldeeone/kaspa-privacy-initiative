#pragma once

// Parent-owned, role-blind public projection handoff.  The endpoint pair is
// minted before intake, but no projection body or owner mapping participates
// in its route identity.  The role-0 writer can complete only after receiving
// a typed post-EGRESS delivery authority.  The parent retains the exact public
// bytes only after a complete read and kernel EOF, then acknowledges that
// retained evidence over the same capability channel.

#include "registered_parent_role_fork.hpp"
#include "registered_parent_round_completion_contract.hpp"
#include "registered_producer_route_bridge_contract.hpp"
#include "registered_projection_route_capture_bridge.hpp"
#include "../../private_batch_trial/native_terminal_projection_intake_bridge.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace kpi::mpc::financial::registered_driver {
namespace projection_route {

inline constexpr std::size_t PUBLIC_PROJECTION_BYTES = 10685;
inline constexpr int ROLE0_PROJECTION_ROUTE_FIXED_FD = 30;

struct PublicProjectionRoutePlan {
    CaptureClassification classification{};
    unsigned round{};
    unsigned computing_role{};
    Digest trial{};
    Digest attempt{};
    Digest cohort{};
    Digest financial_run{};
    Digest capture_plan_identity{};
    Digest producer_process_authority{};
    Digest producer_exit_authority{};
    Digest dispatcher_process_authority{};
    Digest dispatcher_exit_authority{};
};

// This deliberately omits projection bytes, projection identity, route
// identity, timestamps and PIDs.  Those remain private evidence for the later
// authority-to-authority native-terminal join.
struct PublicRetainedProjectionReceipt {
    unsigned round{};
    Digest trial{};
    Digest attempt{};
    Digest cohort{};
    Digest financial_run{};
    Digest producer_process_authority{};
    Digest producer_exit_authority{};
    Digest dispatcher_process_authority{};
    Digest dispatcher_exit_authority{};
    bool exact_size{};
    bool read_complete{};
    bool kernel_eof{};
    bool clean{};
};

struct PublicRole0ProjectionRouteCompletion {
    unsigned round{};
    CaptureClassification classification{};
    Digest trial{};
    Digest attempt{};
    Digest cohort{};
    Digest financial_run{};
    Digest capture_plan_identity{};
    bool exact_size{};
    bool parent_read_complete{};
    bool parent_kernel_eof{};
    bool parent_acknowledged{};
    bool parent_writer_closed{};
};

// Public metadata for the one writer capability consumed by the registered
// parent fork.  The authority identity is fresh before intake and independent
// of the eventual projection body.  Only role 0 receives FD30.
struct PublicProjectionRouteWriter {
    unsigned role{};
    unsigned round{};
    int fixed_fd{-1};
    Digest capture_plan_identity{};
    Digest authority_identity{};
};

class ProjectionRoutePlanAuthority final {
    PublicProjectionRoutePlan plan_;
    std::atomic_bool live_{true};
    explicit ProjectionRoutePlanAuthority(PublicProjectionRoutePlan);
    friend class RegisteredProjectionRoute;
public:
    ProjectionRoutePlanAuthority(const ProjectionRoutePlanAuthority&) = delete;
    ProjectionRoutePlanAuthority& operator=(
        const ProjectionRoutePlanAuthority&) = delete;
    ProjectionRoutePlanAuthority(ProjectionRoutePlanAuthority&&) noexcept;
    ProjectionRoutePlanAuthority& operator=(
        ProjectionRoutePlanAuthority&&) = delete;
#ifdef KPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP
    static ProjectionRoutePlanAuthority test_only_mint(
        PublicProjectionRoutePlan);
#endif
};

// This authority owns exact EGRESS bytes.  There is no span/digest overload
// in production.  Candidate and baseline bridges will mint it only at their
// distinct genuine call sites.
class ProjectionDeliveryAuthority final {
    PublicProjectionRoutePlan plan_;
    std::array<std::byte, PUBLIC_PROJECTION_BYTES> projection_{};
    Digest projection_identity_{};
    std::atomic_bool live_{true};
    ProjectionDeliveryAuthority(
        PublicProjectionRoutePlan,
        std::array<std::byte, PUBLIC_PROJECTION_BYTES>);
    friend class RegisteredProjectionRoute;
    friend class ::kpi::mpc::financial::registered_driver::
        RegisteredProjectionRouteCaptureBridge;
public:
    ProjectionDeliveryAuthority(const ProjectionDeliveryAuthority&) = delete;
    ProjectionDeliveryAuthority& operator=(
        const ProjectionDeliveryAuthority&) = delete;
    ProjectionDeliveryAuthority(ProjectionDeliveryAuthority&&) noexcept;
    ProjectionDeliveryAuthority& operator=(
        ProjectionDeliveryAuthority&&) = delete;
#ifdef KPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP
    static ProjectionDeliveryAuthority test_only_mint(
        PublicProjectionRoutePlan,
        std::array<std::byte, PUBLIC_PROJECTION_BYTES>);
#endif
};

class ParentProjectionRouteEndpointAuthority final {
    int fd_{-1};
    PublicProjectionRoutePlan plan_;
    Digest route_identity_{};
    std::int64_t expected_parent_pid_{};
    std::int64_t expected_role0_pid_{};
    Digest fork_binding_identity_{};
    std::atomic_bool live_{true};
    ParentProjectionRouteEndpointAuthority(
        int, PublicProjectionRoutePlan, Digest, std::int64_t);
    friend class ProjectionRouteEndpoints;
    friend class RegisteredProjectionRoute;
    friend class RegisteredProjectionRouteForkBridge;
    friend class ::kpi::mpc::financial::registered_driver::ParentRoleChildren;
public:
    ParentProjectionRouteEndpointAuthority(
        const ParentProjectionRouteEndpointAuthority&) = delete;
    ParentProjectionRouteEndpointAuthority& operator=(
        const ParentProjectionRouteEndpointAuthority&) = delete;
    ParentProjectionRouteEndpointAuthority(
        ParentProjectionRouteEndpointAuthority&&) noexcept;
    ParentProjectionRouteEndpointAuthority& operator=(
        ParentProjectionRouteEndpointAuthority&&) = delete;
    ~ParentProjectionRouteEndpointAuthority();
    void discard() &&;
#ifdef KPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP
    void test_only_bind_role0_process(
        unsigned role, unsigned round, std::int64_t role0_pid,
        Digest fork_plan, Digest offer, Digest ack, Digest channel_nonce);
#endif
};

class Role0ProjectionRouteWriterAuthority final {
    int fd_{-1};
    // Non-owning description of the parent endpoint at pre-fork mint.  Every
    // role child inherits that descriptor.  The fork boundary must verify and
    // close this exact socket alias before it decodes an offer or enters role
    // code; otherwise a sibling could drain or hold the parent endpoint.
    int parent_peer_fd_{-1};
    std::uint64_t parent_peer_device_{};
    std::uint64_t parent_peer_inode_{};
    std::uint32_t parent_peer_file_type_{};
    PublicProjectionRoutePlan plan_;
    PublicProjectionRouteWriter public_writer_;
    Digest route_identity_{};
    std::int64_t expected_parent_pid_{};
    std::int64_t expected_role0_pid_{};
    Digest fork_binding_identity_{};
    std::atomic_bool live_{true};
    Role0ProjectionRouteWriterAuthority(
        int, int parent_peer_fd, PublicProjectionRoutePlan,
        PublicProjectionRouteWriter,
        Digest, std::int64_t);
    bool parent_peer_alias_matches() const noexcept;
    void close_inherited_parent_peer_alias();
    friend class ProjectionRouteEndpoints;
    friend class RegisteredProjectionRoute;
    friend class RegisteredProjectionRouteForkBridge;
    friend class ::kpi::mpc::financial::registered_driver::
        RegisteredProjectionRouteCaptureBridge;
    friend class ::kpi::mpc::financial::registered_driver::
        ParentRoleForkPlanAuthority;
    friend class ::kpi::mpc::financial::registered_driver::
        ParentAuthenticatedPartyDeliveryAuthority;
public:
    Role0ProjectionRouteWriterAuthority(
        const Role0ProjectionRouteWriterAuthority&) = delete;
    Role0ProjectionRouteWriterAuthority& operator=(
        const Role0ProjectionRouteWriterAuthority&) = delete;
    Role0ProjectionRouteWriterAuthority(
        Role0ProjectionRouteWriterAuthority&&) noexcept;
    Role0ProjectionRouteWriterAuthority& operator=(
        Role0ProjectionRouteWriterAuthority&&) = delete;
    ~Role0ProjectionRouteWriterAuthority();
    void discard() &&;
#ifdef KPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP
    const PublicProjectionRouteWriter& test_only_public_writer() const {
        return public_writer_;
    }
    bool test_only_parent_peer_alias_open() const {
        return parent_peer_alias_matches();
    }
    void test_only_close_inherited_parent_peer_alias() {
        close_inherited_parent_peer_alias();
    }
    void test_only_bind_role0_process(
        unsigned role, unsigned round, std::int64_t role0_pid,
        Digest fork_plan, Digest offer, Digest ack, Digest channel_nonce);
#endif
};

class ProjectionRouteEndpoints final {
    ParentProjectionRouteEndpointAuthority parent_;
    Role0ProjectionRouteWriterAuthority writer_;
    bool parent_taken_{};
    bool writer_taken_{};
    ProjectionRouteEndpoints(
        ParentProjectionRouteEndpointAuthority&&,
        Role0ProjectionRouteWriterAuthority&&);
    friend class RegisteredProjectionRoute;
public:
    ProjectionRouteEndpoints(const ProjectionRouteEndpoints&) = delete;
    ProjectionRouteEndpoints& operator=(const ProjectionRouteEndpoints&) =
        delete;
    ProjectionRouteEndpoints(ProjectionRouteEndpoints&&) = delete;
    ProjectionRouteEndpoints& operator=(ProjectionRouteEndpoints&&) = delete;
    ParentProjectionRouteEndpointAuthority take_parent();
    Role0ProjectionRouteWriterAuthority take_role0_writer();
};

// Complete before either private friendship is consumed: an adversarial TU
// cannot define a lookalike bridge.  Every operation requires existing typed
// fork authorities; no descriptor, PID, digest, or caller role is accepted.
class RegisteredProjectionRouteForkBridge final {
    RegisteredProjectionRouteForkBridge() = delete;
    static Digest binding_identity(
        const PublicProjectionRoutePlan&, const Digest& route,
        std::int64_t parent_pid, std::int64_t role0_pid,
        const Digest& fork_plan, const Digest& offer,
        const Digest& ack, const Digest& channel_nonce);
    friend class ::kpi::mpc::financial::registered_driver::
        ParentAuthenticatedPartyDeliveryAuthority;
    friend class ::kpi::mpc::financial::registered_driver::ParentRoleChildren;
public:
    static void consume_writer_for_parent_fork(
        Role0ProjectionRouteWriterAuthority&&,
        ParentRoleForkPlanAuthority&);
    static Role0ProjectionRouteWriterAuthority take_role0_writer(
        ParentAuthenticatedPartyDeliveryAuthority&);
    static ParentProjectionRouteEndpointAuthority bind_parent_after_fork(
        ParentProjectionRouteEndpointAuthority&&, ParentRoleChildren&);
};

class Role0ProjectionRouteCompletionAuthority final {
    PublicRole0ProjectionRouteCompletion receipt_;
    Digest route_identity_{};
    Digest projection_identity_{};
    Digest retained_identity_{};
    Digest fork_binding_identity_{};
    std::atomic_bool live_{true};
    Role0ProjectionRouteCompletionAuthority(
        PublicRole0ProjectionRouteCompletion, Digest, Digest, Digest, Digest);
    friend class RegisteredProjectionRoute;
    friend class ::kpi::mpc::financial::registered_driver::
        RegisteredProjectionRouteCaptureBridge;
public:
    Role0ProjectionRouteCompletionAuthority(
        const Role0ProjectionRouteCompletionAuthority&) = delete;
    Role0ProjectionRouteCompletionAuthority& operator=(
        const Role0ProjectionRouteCompletionAuthority&) = delete;
    Role0ProjectionRouteCompletionAuthority(
        Role0ProjectionRouteCompletionAuthority&&) noexcept;
    Role0ProjectionRouteCompletionAuthority& operator=(
        Role0ProjectionRouteCompletionAuthority&&) = delete;
    const PublicRole0ProjectionRouteCompletion& public_receipt() const {
        return receipt_;
    }
#ifdef KPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP
    Digest test_only_route_identity() const { return route_identity_; }
    Digest test_only_projection_identity() const {
        return projection_identity_;
    }
#endif
};

class NativeTerminalRetainedProjectionAuthority;

class ParentRetainedProjectionAuthority final {
    PublicRetainedProjectionReceipt receipt_;
    PublicProjectionRoutePlan plan_;
    std::array<std::byte, PUBLIC_PROJECTION_BYTES> projection_{};
    Digest projection_identity_{};
    Digest route_identity_{};
    Digest retained_identity_{};
    Digest fork_binding_identity_{};
    std::uint64_t route_observed_monotonic_ns_{};
    std::atomic_bool live_{true};
    ParentRetainedProjectionAuthority(
        PublicRetainedProjectionReceipt, PublicProjectionRoutePlan,
        std::array<std::byte, PUBLIC_PROJECTION_BYTES>,
        Digest, Digest, Digest, Digest, std::uint64_t);
    friend class RegisteredProjectionRoute;
    friend class ::kpi::mpc::financial::registered_driver::
        RegisteredParentRoundCompletionBridge;
    friend class ::kpi::mpc::financial::registered_driver::
        RegisteredProducerRouteBridge;
public:
    ParentRetainedProjectionAuthority(
        const ParentRetainedProjectionAuthority&) = delete;
    ParentRetainedProjectionAuthority& operator=(
        const ParentRetainedProjectionAuthority&) = delete;
    ParentRetainedProjectionAuthority(
        ParentRetainedProjectionAuthority&&) noexcept;
    ParentRetainedProjectionAuthority& operator=(
        ParentRetainedProjectionAuthority&&) = delete;
    const PublicRetainedProjectionReceipt& public_receipt() const {
        return receipt_;
    }
#ifdef KPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP
    std::span<const std::byte> test_only_projection() const {
        return projection_;
    }
    Digest test_only_projection_identity() const {
        return projection_identity_;
    }
#endif
};

// Same private evidence, transferred without a public body/digest accessor.
class NativeTerminalRetainedProjectionAuthority final {
    PublicRetainedProjectionReceipt receipt_;
    PublicProjectionRoutePlan plan_;
    std::array<std::byte, PUBLIC_PROJECTION_BYTES> projection_{};
    Digest projection_identity_{};
    Digest route_identity_{};
    Digest retained_identity_{};
    Digest fork_binding_identity_{};
    std::uint64_t route_observed_monotonic_ns_{};
    std::atomic_bool live_{true};
    NativeTerminalRetainedProjectionAuthority(
        PublicRetainedProjectionReceipt, PublicProjectionRoutePlan,
        std::array<std::byte, PUBLIC_PROJECTION_BYTES>,
        Digest, Digest, Digest, Digest, std::uint64_t);
    friend class ParentRetainedProjectionAuthority;
    friend class RegisteredProjectionRoute;
    friend class ::kpb::native_terminal::NativeTerminalProjectionIntake;
public:
    NativeTerminalRetainedProjectionAuthority(
        const NativeTerminalRetainedProjectionAuthority&) = delete;
    NativeTerminalRetainedProjectionAuthority& operator=(
        const NativeTerminalRetainedProjectionAuthority&) = delete;
    NativeTerminalRetainedProjectionAuthority(
        NativeTerminalRetainedProjectionAuthority&&) noexcept;
    NativeTerminalRetainedProjectionAuthority& operator=(
        NativeTerminalRetainedProjectionAuthority&&) = delete;
#ifdef KPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP
    std::span<const std::byte> test_only_projection() const {
        return projection_;
    }
#endif
};

#ifdef KPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP
enum class ProjectionRouteTestFault : std::uint8_t {
    None = 0,
    ExtraFrameBeforeEof = 1,
    OversizedAcknowledgement = 2,
    ZeroLengthRecordBeforeChildEof = 3,
    ZeroLengthRecordBeforeParentEof = 4,
    ZeroLengthChildRecordWhileOpen = 5,
};
#endif

class RegisteredProjectionRoute final {
    RegisteredProjectionRoute() = delete;
    static Role0ProjectionRouteCompletionAuthority
        deliver_after_release_impl(
            Role0ProjectionRouteWriterAuthority&&,
            ProjectionDeliveryAuthority&&, std::uint8_t fault);
    static ParentRetainedProjectionAuthority receive_and_retain_impl(
        ParentProjectionRouteEndpointAuthority&&, std::uint8_t fault);
public:
    static ProjectionRouteEndpoints mint_pre_intake(
        ProjectionRoutePlanAuthority&&);
    static Role0ProjectionRouteCompletionAuthority deliver_after_release(
        Role0ProjectionRouteWriterAuthority&&,
        ProjectionDeliveryAuthority&&);
    static ParentRetainedProjectionAuthority receive_and_retain(
        ParentProjectionRouteEndpointAuthority&&);
#ifdef KPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP
    static Role0ProjectionRouteCompletionAuthority
        test_only_deliver_after_release(
            Role0ProjectionRouteWriterAuthority&&,
            ProjectionDeliveryAuthority&&, ProjectionRouteTestFault);
    static ParentRetainedProjectionAuthority test_only_receive_and_retain(
        ParentProjectionRouteEndpointAuthority&&, ProjectionRouteTestFault);
    // Isolated native-terminal controls only. Production has no standalone
    // retained-route transfer: the selected path must keep it inside the
    // parent round composite until the future exact six-party/global join.
    static NativeTerminalRetainedProjectionAuthority
        test_only_transfer_for_native_terminal(
            ParentRetainedProjectionAuthority&&);
#endif
};

struct ProjectionRouteSourceStatus {
    std::string schema;
    std::string status;
    bool parent_minted_pre_intake_pair{};
    bool role0_only_writer{};
    bool exact_projection_bytes{};
    bool kernel_eof_before_ack{};
    bool retained_body_private{};
    bool route_identity_body_independent{};
    bool candidate_egress_callsite{};
    bool baseline_post_disclosure_callsite{};
    bool parent_bootstrap_mint_integration{};
    bool dispatcher_close_integration{};
    bool native_terminal_retention_integration{};
    bool registered_driver_configured{};
    bool launch_authorized{};
};

ProjectionRouteSourceStatus projection_route_source_status();

} // namespace projection_route
} // namespace kpi::mpc::financial::registered_driver
