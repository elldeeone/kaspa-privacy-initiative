#include "registered_driver_bridge.hpp"
#include "registered_capture_session.hpp"
#include "../p1_scalar_capture_manifest.hpp"

#include <span>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::registered_driver {
namespace {
using Bytes = std::vector<unsigned char>;

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) { return value != Digest{}; }
void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add(Bytes& out, const char* value) {
    while (*value) out.push_back(static_cast<unsigned char>(*value++));
}
void integer(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}
void add_string(Bytes& out, const std::string& value) {
    integer(out, value.size());
    add(out, std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
}
bool lowercase_uuid_v4(const std::string& value) {
    if (value.size() != 36 || value[8] != '-' || value[13] != '-' ||
        value[18] != '-' || value[23] != '-' || value[14] != '4' ||
        std::string("89ab").find(value[19]) == std::string::npos)
        return false;
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (index == 8 || index == 13 || index == 18 || index == 23) continue;
        const char byte = value[index];
        if (!((byte >= '0' && byte <= '9') ||
              (byte >= 'a' && byte <= 'f'))) return false;
    }
    return true;
}
Digest trial_uuid_identity(std::string_view value) {
    need(lowercase_uuid_v4(std::string(value)));
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_TRIAL_UUID_IDENTITY_V1\n");
    integer(bytes, value.size());
    add(bytes, std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
    return identity_registry::digest(bytes);
}
Digest capture_attempt_uuid_identity(std::string_view value) {
    need(lowercase_uuid_v4(std::string(value)));
    Bytes bytes;
    add(bytes, "KPB_CAPTURE_ATTEMPT_ID_V1\n");
    add(bytes, std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
    return identity_registry::digest(bytes);
}
Digest driver_identity(const PublicDriverSelection& value) {
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_DRIVER_SELECTION_V2\n");
    integer(bytes, value.role);
    for (const auto* field : {
             &value.authority_identity, &value.selection_identity,
             &value.service_identity, &value.source_identity,
             &value.build_identity, &value.roster_identity,
             &value.capture_source_identity, &value.capture_build_identity,
             &value.capture_launcher_identity,
             &value.model_preimage_identity,
             &value.query_store_preimage_identity,
             &value.scalar_capture_manifest_identity}) add(bytes, *field);
    integer(bytes, static_cast<std::uint64_t>(value.owner_port));
    integer(bytes, value.multiplication_batch);
    return identity_registry::digest(bytes);
}
Digest capture_identity(const PublicCapturePlan& value) {
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_CAPTURE_PLAN_V4\n");
    integer(bytes, static_cast<std::uint8_t>(value.classification));
    integer(bytes, value.round);
    add_string(bytes, value.capture_trial_id);
    add_string(bytes, value.capture_attempt_id);
    add_string(bytes, value.capture_identity);
    for (const auto* field : {&value.run, &value.trial,
             &value.attempt, &value.cohort,
             &value.source_identity, &value.build_identity,
             &value.launcher_identity, &value.model_preimage_identity,
             &value.query_store_preimage_identity,
             &value.scalar_capture_manifest_identity}) add(bytes, *field);
    for (const auto fd : value.fixed_fds)
        integer(bytes, static_cast<std::uint64_t>(fd));
    return identity_registry::digest(bytes);
}
void valid(const PublicDriverSelection& value) {
    need(value.role < 3 && value.owner_port >= 1024 &&
         value.owner_port <= 65533 && value.multiplication_batch > 0);
    for (const auto* field : {
             &value.authority_identity, &value.selection_identity,
             &value.service_identity, &value.source_identity,
             &value.build_identity, &value.roster_identity,
             &value.capture_source_identity, &value.capture_build_identity,
             &value.capture_launcher_identity,
             &value.model_preimage_identity,
             &value.query_store_preimage_identity,
             &value.scalar_capture_manifest_identity}) need(nonzero(*field));
    need(identity_registry::hex(value.scalar_capture_manifest_identity) ==
         p1_capture::SCALAR_CAPTURE_MANIFEST_SHA256);
}
void valid(const PublicCapturePlan& value) {
    need((value.classification == CaptureClassification::HiddenCandidate ||
          value.classification ==
              CaptureClassification::ExplicitOwnerPublicEffectsBaseline) &&
         (value.round == 1 || value.round == 2) &&
         lowercase_uuid_v4(value.capture_trial_id) &&
         lowercase_uuid_v4(value.capture_attempt_id) &&
         lowercase_uuid_v4(value.capture_identity) &&
         value.capture_trial_id != value.capture_attempt_id &&
         value.capture_trial_id != value.capture_identity &&
         value.capture_attempt_id != value.capture_identity &&
         value.trial == trial_uuid_identity(value.capture_trial_id) &&
         value.attempt ==
             capture_attempt_uuid_identity(value.capture_attempt_id));
    for (const auto* field : {&value.run, &value.trial,
             &value.attempt, &value.cohort,
             &value.source_identity, &value.build_identity,
             &value.launcher_identity, &value.model_preimage_identity,
             &value.query_store_preimage_identity,
             &value.scalar_capture_manifest_identity}) need(nonzero(*field));
    need(identity_registry::hex(value.scalar_capture_manifest_identity) ==
         p1_capture::SCALAR_CAPTURE_MANIFEST_SHA256);
    constexpr std::array<int, 10> expected{
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29};
    need(value.fixed_fds == expected);
}
void valid(const PublicVerifiedEgress& value) {
    for (const auto* field : {&value.binding_identity, &value.effects_identity,
             &value.core_identity, &value.proof_identity,
             &value.projection_identity}) need(nonzero(*field));
}
Digest authorization_identity(
    const PublicDriverSelection& driver, const Digest& driver_id,
    const Digest& capture_id,
    const attempt_supervisor::PublicFreshAttempt& fresh,
    const attempt_supervisor::PublicIntakePermit& intake) {
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_DRIVER_AUTHORIZATION_V1\n");
    integer(bytes, driver.role);
    add(bytes, driver_id); add(bytes, capture_id);
    add(bytes, fresh.authority_identity); add(bytes, fresh.selection_identity);
    add(bytes, fresh.accepted_head); add(bytes, fresh.attempt_identity);
    add(bytes, intake.durable_lock); add(bytes, intake.permit_identity);
    return identity_registry::digest(bytes);
}
void add_authorized(Bytes& bytes, const PublicAuthorizedAttempt& value) {
    integer(bytes, value.role);
    integer(bytes, value.round);
    integer(bytes, static_cast<std::uint8_t>(value.classification));
    add_string(bytes, value.capture_trial_id);
    for (const auto* field : {
             &value.authority_identity, &value.driver_selection_identity,
             &value.selection_identity, &value.run, &value.trial,
             &value.attempt, &value.cohort, &value.accepted_head,
             &value.postlock_accepted_head, &value.attempt_identity,
             &value.proposal_identity, &value.durable_lock,
             &value.capture_plan_identity, &value.capture_source_identity,
             &value.capture_build_identity, &value.capture_launcher_identity,
             &value.authorization_identity})
        add(bytes, *field);
    for (const auto& owner : value.owner_contracts) add(bytes, owner);
}
void add_egress(Bytes& bytes, const PublicVerifiedEgress& value) {
    for (const auto* field : {
             &value.binding_identity, &value.effects_identity,
             &value.core_identity, &value.proof_identity,
             &value.projection_identity})
        add(bytes, *field);
}
bool same_authorized(
        const PublicAuthorizedAttempt& left,
        const PublicAuthorizedAttempt& right) {
    return left.role == right.role && left.round == right.round &&
           left.classification == right.classification &&
           left.capture_trial_id == right.capture_trial_id &&
           left.authority_identity == right.authority_identity &&
           left.driver_selection_identity == right.driver_selection_identity &&
           left.selection_identity == right.selection_identity &&
           left.run == right.run && left.trial == right.trial &&
           left.attempt == right.attempt && left.cohort == right.cohort &&
           left.accepted_head == right.accepted_head &&
           left.postlock_accepted_head == right.postlock_accepted_head &&
           left.attempt_identity == right.attempt_identity &&
           left.proposal_identity == right.proposal_identity &&
           left.durable_lock == right.durable_lock &&
           left.owner_contracts == right.owner_contracts &&
           left.capture_plan_identity == right.capture_plan_identity &&
           left.capture_source_identity == right.capture_source_identity &&
           left.capture_build_identity == right.capture_build_identity &&
           left.capture_launcher_identity == right.capture_launcher_identity &&
           left.authorization_identity == right.authorization_identity;
}
bool same_egress(
        const PublicVerifiedEgress& left,
        const PublicVerifiedEgress& right) {
    return left.binding_identity == right.binding_identity &&
           left.effects_identity == right.effects_identity &&
           left.core_identity == right.core_identity &&
           left.proof_identity == right.proof_identity &&
           left.projection_identity == right.projection_identity;
}
Digest release_ready_identity(
        const PublicAuthorizedAttempt& attempt,
        const PublicVerifiedEgress& egress) {
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_PARTY_RELEASE_READY_V1\n");
    add_authorized(bytes, attempt);
    add_egress(bytes, egress);
    return identity_registry::digest(bytes);
}
Digest completion_identity(const PublicPartyDriverCompletion& value) {
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_PARTY_DRIVER_COMPLETION_V3\n");
    integer(bytes, value.role); integer(bytes, value.round);
    integer(bytes, static_cast<std::uint8_t>(value.classification));
    add_string(bytes, value.capture_trial_id);
    for (const auto* field : {
             &value.authority_identity, &value.driver_selection_identity,
             &value.selection_identity, &value.run, &value.trial,
             &value.attempt, &value.cohort, &value.accepted_head,
             &value.postlock_accepted_head, &value.attempt_identity,
             &value.proposal_identity,
             &value.durable_lock, &value.capture_plan_identity,
             &value.capture_source_identity, &value.capture_build_identity,
             &value.capture_launcher_identity,
             &value.authorization_identity,
             &value.egress_binding_identity, &value.effects_identity,
             &value.core_identity, &value.proof_identity,
             &value.projection_identity,
             &value.full_cohort_barrier_identity}) add(bytes, *field);
    for (const auto& owner : value.owner_contracts) add(bytes, owner);
    integer(bytes, value.full_cohort_barrier_observed_monotonic_ns);
    return identity_registry::digest(bytes);
}
} // namespace

Digest RegisteredCapturePlanRosterBridge::trial_identity(
        std::string_view value) {
    return trial_uuid_identity(value);
}

Digest RegisteredCapturePlanRosterBridge::attempt_identity(
        std::string_view value) {
    return capture_attempt_uuid_identity(value);
}

CompiledDriverSelection::CompiledDriverSelection(PublicDriverSelection value)
    : value_(std::move(value)), identity_(driver_identity(value_)) {}

#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
CompiledDriverSelection CompiledDriverSelection::test_only_mint(
    PublicDriverSelection value) {
    return CompiledDriverSelection(std::move(value));
}
#endif

CompiledFreshAttemptAuthority::CompiledFreshAttemptAuthority(
    PublicCompiledFreshAttempt value) : value_(std::move(value)) {}
CompiledFreshAttemptAuthority::CompiledFreshAttemptAuthority(
    CompiledFreshAttemptAuthority&& other) noexcept
    : value_(other.value_), live_(other.live_.exchange(false)) {}
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
CompiledFreshAttemptAuthority CompiledFreshAttemptAuthority::test_only_mint(
    PublicCompiledFreshAttempt value) {
    return CompiledFreshAttemptAuthority(std::move(value));
}
#endif

AuthenticatedPartyDeliveryAuthority::AuthenticatedPartyDeliveryAuthority(
    PublicAuthenticatedPartyDelivery value) : value_(std::move(value)) {}
AuthenticatedPartyDeliveryAuthority::AuthenticatedPartyDeliveryAuthority(
    AuthenticatedPartyDeliveryAuthority&& other) noexcept
    : value_(other.value_), live_(other.live_.exchange(false)) {}
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
AuthenticatedPartyDeliveryAuthority
AuthenticatedPartyDeliveryAuthority::test_only_mint(
    PublicAuthenticatedPartyDelivery value) {
    return AuthenticatedPartyDeliveryAuthority(std::move(value));
}
#endif

CompiledOuterSupervisorSelection::CompiledOuterSupervisorSelection(
    PublicOuterSupervisorSelection value) : value_(std::move(value)) {}
CompiledOuterSupervisorSelection::CompiledOuterSupervisorSelection(
    CompiledOuterSupervisorSelection&& other) noexcept
    : value_(std::move(other.value_)),
      live_(other.live_.exchange(false)) {}
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
CompiledOuterSupervisorSelection
CompiledOuterSupervisorSelection::test_only_mint(
    PublicOuterSupervisorSelection value) {
    return CompiledOuterSupervisorSelection(std::move(value));
}
#endif

OuterSupervisorAuthority::OuterSupervisorAuthority(
    std::unique_ptr<identity_registry::Registry> registry,
    std::shared_ptr<docker_anchor::Client> anchor,
    std::unique_ptr<attempt_supervisor::Supervisor> supervisor)
    : registry_(std::move(registry)), anchor_(std::move(anchor)),
      supervisor_(std::move(supervisor)) {
    need(registry_ && anchor_ && supervisor_);
}

void OuterSupervisorAuthority::submit(
    const attempt_supervisor::Proposal& proposal) {
    need(supervisor_ != nullptr);
    supervisor_->submit(proposal);
}

bool OuterSupervisorAuthority::ready() const {
    need(supervisor_ != nullptr);
    return supervisor_->ready();
}

attempt_supervisor::ApprovalBatch OuterSupervisorAuthority::approve(
    identity_registry::FailureOnlyHook registry_hook,
    attempt_supervisor::Supervisor::SupervisorFailureOnlyHook supervisor_hook) {
    need(supervisor_ != nullptr);
    return supervisor_->approve(std::move(registry_hook),
                                std::move(supervisor_hook));
}

CapturePlanAuthority::CapturePlanAuthority(PublicCapturePlan value)
    : value_(std::move(value)), identity_(capture_identity(value_)) {}
CapturePlanAuthority::CapturePlanAuthority(
        PublicCapturePlan value, Scope scope, unsigned computing_role)
    : value_(std::move(value)), identity_(capture_identity(value_)),
      scope_(scope), computing_role_(computing_role) {}
CapturePlanAuthority::CapturePlanAuthority(CapturePlanAuthority&& other) noexcept
    : value_(other.value_), identity_(other.identity_),
      scope_(other.scope_), computing_role_(other.computing_role_),
      live_(other.live_.exchange(false)) {}

void CapturePlanAuthorityBridge::require_valid(
        const CapturePlanAuthority& authority) {
    valid(authority.value_);
    need(authority.identity_ == capture_identity(authority.value_));
}

void CapturePlanAuthorityBridge::require_valid(
        const CompiledDriverSelection& driver) {
    valid(driver.value_);
    need(driver.identity_ == driver_identity(driver.value_));
}

ConsumedCapturePlan CapturePlanAuthorityBridge::consume_session(
        CapturePlanAuthority&& authority, unsigned computing_role) {
    try {
        need(authority.live_.exchange(false));
        require_valid(authority);
        need(computing_role < 3 &&
             authority.scope_ == CapturePlanAuthority::Scope::SessionResidual &&
             authority.computing_role_ == computing_role);
        return ConsumedCapturePlan{authority.value_, authority.identity_};
    } catch (...) { refuse(); }
}
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
CapturePlanAuthority CapturePlanAuthority::test_only_mint(
    PublicCapturePlan value) {
    return CapturePlanAuthority(std::move(value));
}
CapturePlanAuthority CapturePlanAuthority::test_only_session_residual(
        PublicCapturePlan value, unsigned computing_role) {
    return CapturePlanAuthority(
        std::move(value), Scope::SessionResidual, computing_role);
}
#endif

VerifiedEgressAuthority::VerifiedEgressAuthority(PublicVerifiedEgress value)
    : value_(std::move(value)) {}
VerifiedEgressAuthority::VerifiedEgressAuthority(
    VerifiedEgressAuthority&& other) noexcept
    : value_(other.value_), live_(other.live_.exchange(false)) {}
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
VerifiedEgressAuthority VerifiedEgressAuthority::test_only_mint(
    PublicVerifiedEgress value) {
    return VerifiedEgressAuthority(std::move(value));
}
#endif

PartyReleaseReadyAuthority::PartyReleaseReadyAuthority(
        PublicPartyReleaseReady value) : value_(std::move(value)) {}
PartyReleaseReadyAuthority::PartyReleaseReadyAuthority(
        PartyReleaseReadyAuthority&& other) noexcept
    : value_(other.value_), live_(other.live_.exchange(false)) {}
#ifdef KPI_REGISTERED_FULL_COHORT_RELEASE_BARRIER_TEST_SETUP
PartyReleaseReadyAuthority PartyReleaseReadyAuthority::test_only_mint(
        PublicAuthorizedAttempt attempt, PublicVerifiedEgress egress) {
    valid(egress);
    PublicPartyReleaseReady value{
        .attempt = std::move(attempt),
        .egress = std::move(egress),
    };
    value.readiness_identity = release_ready_identity(
        value.attempt, value.egress);
    return PartyReleaseReadyAuthority(std::move(value));
}
#endif

PartyReleaseAuthorizationAuthority::PartyReleaseAuthorizationAuthority(
        PublicAuthorizedAttempt attempt, PublicVerifiedEgress egress,
        Digest readiness_identity, Digest barrier_identity,
        std::uint64_t barrier_monotonic_ns)
    : attempt_(std::move(attempt)), egress_(std::move(egress)),
      readiness_identity_(readiness_identity),
      barrier_identity_(barrier_identity),
      barrier_monotonic_ns_(barrier_monotonic_ns) {}
PartyReleaseAuthorizationAuthority::PartyReleaseAuthorizationAuthority(
        PartyReleaseAuthorizationAuthority&& other) noexcept
    : attempt_(other.attempt_), egress_(other.egress_),
      readiness_identity_(other.readiness_identity_),
      barrier_identity_(other.barrier_identity_),
      barrier_monotonic_ns_(other.barrier_monotonic_ns_),
      live_(other.live_.exchange(false)) {}
#ifdef KPI_REGISTERED_FULL_COHORT_RELEASE_BARRIER_TEST_SETUP
void PartyReleaseAuthorizationAuthority::test_only_bind_completion(
        PublicPartyDriverCompletion& value) {
    need(live_.exchange(false) &&
         value.role == attempt_.role && value.round == attempt_.round &&
         value.classification == attempt_.classification &&
         value.capture_trial_id == attempt_.capture_trial_id &&
         value.authority_identity == attempt_.authority_identity &&
         value.driver_selection_identity ==
             attempt_.driver_selection_identity &&
         value.selection_identity == attempt_.selection_identity &&
         value.run == attempt_.run && value.trial == attempt_.trial &&
         value.attempt == attempt_.attempt &&
         value.cohort == attempt_.cohort &&
         value.accepted_head == attempt_.accepted_head &&
         value.postlock_accepted_head == attempt_.postlock_accepted_head &&
         value.attempt_identity == attempt_.attempt_identity &&
         value.proposal_identity == attempt_.proposal_identity &&
         value.durable_lock == attempt_.durable_lock &&
         value.owner_contracts == attempt_.owner_contracts &&
         value.capture_plan_identity == attempt_.capture_plan_identity &&
         value.capture_source_identity == attempt_.capture_source_identity &&
         value.capture_build_identity == attempt_.capture_build_identity &&
         value.capture_launcher_identity ==
             attempt_.capture_launcher_identity &&
         value.authorization_identity == attempt_.authorization_identity &&
         value.egress_binding_identity == egress_.binding_identity &&
         value.effects_identity == egress_.effects_identity &&
         value.core_identity == egress_.core_identity &&
         value.proof_identity == egress_.proof_identity &&
         value.projection_identity == egress_.projection_identity &&
         nonzero(readiness_identity_) && nonzero(barrier_identity_) &&
         barrier_monotonic_ns_ > 0);
    value.full_cohort_barrier_identity = barrier_identity_;
    value.full_cohort_barrier_observed_monotonic_ns =
        barrier_monotonic_ns_;
}
#endif

PartyDriverCompletionAuthority::PartyDriverCompletionAuthority(
    PublicPartyDriverCompletion receipt) : receipt_(std::move(receipt)) {}
PartyDriverCompletionAuthority::PartyDriverCompletionAuthority(
    PartyDriverCompletionAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}

DriverAttempt::DriverAttempt(
    CompiledDriverSelection driver, Digest capture_identity,
    PublicCapturePlan capture_plan,
    std::unique_ptr<RegisteredCaptureSession> capture_session,
    attempt_supervisor::Proposal proposal,
    attempt_supervisor::PartyApproval&& approval)
    : driver_(std::move(driver)), capture_identity_(capture_identity),
      capture_plan_(std::move(capture_plan)),
      capture_session_(std::move(capture_session)),
      proposal_(std::move(proposal)),
      approval_(std::move(approval)) {}

DriverAttempt::~DriverAttempt() = default;

DriverAttempt DriverAttempt::admit_authority(
    CompiledDriverSelection driver, CapturePlanAuthority&& capture,
    attempt_supervisor::PartyApproval&& approval,
    const attempt_supervisor::Proposal& local) {
    try {
        valid(driver.value_); valid(capture.value_);
        need(capture.live_.load() && local.role() == driver.value_.role &&
             local.authority_identity() == driver.value_.authority_identity &&
             identity_registry::selection_identity(
                 local.public_selection_hashes()) ==
                 driver.value_.selection_identity &&
             capture.value_.run == local.public_selection_hashes().run &&
             capture.value_.trial == local.public_selection_hashes().trial &&
             capture.value_.attempt == local.public_selection_hashes().attempt &&
             capture.value_.cohort == local.public_selection_hashes().cohort &&
             capture.value_.source_identity ==
                 driver.value_.capture_source_identity &&
             capture.value_.build_identity ==
                 driver.value_.capture_build_identity &&
             capture.value_.launcher_identity ==
                 driver.value_.capture_launcher_identity &&
             capture.value_.model_preimage_identity ==
                 driver.value_.model_preimage_identity &&
             capture.value_.query_store_preimage_identity ==
                 driver.value_.query_store_preimage_identity &&
             capture.value_.scalar_capture_manifest_identity ==
                 driver.value_.scalar_capture_manifest_identity);
        const auto expected_capture_identity = capture.identity_;
        const auto selected_capture_plan = capture.value_;
        auto capture_session = RegisteredCaptureSession::begin(
            std::move(capture), driver.value_.role);
        need(capture_session &&
             capture_session->plan_identity() == expected_capture_identity);
        return DriverAttempt(std::move(driver), expected_capture_identity,
                             selected_capture_plan,
                             std::move(capture_session), local,
                             std::move(approval));
    } catch (...) { refuse(); }
}

void DriverAttempt::recheck_before_lock(
    attempt_supervisor::DirectAcceptedHeadCommitment&& head) {
    std::lock_guard guard(mutex_);
    try {
        need(state_ == State::Admitted && approval_.has_value() &&
             !fresh_.has_value());
        state_ = State::Poisoned;
        auto fresh = approval_->recheck_before_lock(proposal_, std::move(head));
        const auto& receipt = fresh.public_receipt();
        need(receipt.role == driver_.value_.role &&
             receipt.authority_identity == driver_.value_.authority_identity &&
             receipt.selection_identity == driver_.value_.selection_identity);
        fresh_.emplace(std::move(fresh));
        approval_.reset();
        state_ = State::HeadRechecked;
    } catch (...) { refuse(); }
}

std::unique_ptr<AuthorizedDriverAttempt> DriverAttempt::after_durable_lock(
    attempt_supervisor::DirectAcceptedHeadCommitment&& head,
    attempt_supervisor::DurableLockCommitment&& lock) {
    std::lock_guard guard(mutex_);
    try {
        need(state_ == State::HeadRechecked && fresh_.has_value() &&
             capture_session_ != nullptr);
        state_ = State::Poisoned;
        const auto fresh_receipt = fresh_->public_receipt();
        auto permit = fresh_->burn_immediately_before_owner_intake(
            driver_.value_.role, std::move(head), std::move(lock));
        const auto intake = permit.public_receipt();
        need(intake.role == driver_.value_.role &&
             intake.authority_identity == driver_.value_.authority_identity &&
             intake.selection_identity == driver_.value_.selection_identity &&
             intake.accepted_head == fresh_receipt.accepted_head);
        PublicAuthorizedAttempt receipt{
            .role = driver_.value_.role,
            .round = capture_plan_.round,
            .classification = capture_plan_.classification,
            .capture_trial_id = capture_plan_.capture_trial_id,
            .authority_identity = driver_.value_.authority_identity,
            .driver_selection_identity = driver_.identity_,
            .selection_identity = driver_.value_.selection_identity,
            .run = proposal_.public_selection_hashes().run,
            .trial = proposal_.public_selection_hashes().trial,
            .attempt = proposal_.public_selection_hashes().attempt,
            .cohort = proposal_.public_selection_hashes().cohort,
            .accepted_head = fresh_receipt.accepted_head,
            .postlock_accepted_head = intake.accepted_head,
            .attempt_identity = fresh_receipt.attempt_identity,
            .proposal_identity =
                attempt_supervisor::proposal_identity(proposal_),
            .durable_lock = intake.durable_lock,
            .owner_contracts = proposal_.public_selection_hashes().owner_contracts,
            .capture_plan_identity = capture_identity_,
            .capture_source_identity = capture_plan_.source_identity,
            .capture_build_identity = capture_plan_.build_identity,
            .capture_launcher_identity = capture_plan_.launcher_identity,
        };
        receipt.authorization_identity = authorization_identity(
            driver_.value_, driver_.identity_, capture_identity_,
            fresh_receipt, intake);
        auto authorized = std::unique_ptr<AuthorizedDriverAttempt>(
            new AuthorizedDriverAttempt(std::move(receipt), std::move(permit),
                                        std::move(capture_session_)));
        fresh_.reset();
        state_ = State::Authorized;
        return authorized;
    } catch (...) { refuse(); }
}

const PublicDriverSelection& DriverAttempt::selected_driver() const {
    return driver_.value_;
}

const attempt_supervisor::Proposal& DriverAttempt::proposal() const {
    return proposal_;
}

AuthorizedDriverAttempt::AuthorizedDriverAttempt(
    PublicAuthorizedAttempt receipt,
    attempt_supervisor::OwnerIntakePermit&& permit,
    std::unique_ptr<RegisteredCaptureSession> capture_session)
    : receipt_(std::move(receipt)), permit_(std::move(permit)),
      capture_session_(std::move(capture_session)) {
    need(capture_session_ &&
         capture_session_->plan_identity() == receipt_.capture_plan_identity);
}

AuthorizedDriverAttempt::~AuthorizedDriverAttempt() = default;

AuthorizedDriverAttempt::BaselineEffectsClaim::BaselineEffectsClaim(
        PublicAuthorizedAttempt receipt) : receipt_(std::move(receipt)) {}

AuthorizedDriverAttempt::BaselineEffectsClaim::BaselineEffectsClaim(
        BaselineEffectsClaim&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}

PublicAuthorizedAttempt
AuthorizedDriverAttempt::BaselineEffectsClaim::consume() {
    if (!live_.exchange(false)) refuse();
    return receipt_;
}

#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
void AuthorizedDriverAttempt::test_only_capture_lifecycle(
    std::span<const unsigned char> projection,
    std::size_t fixed_frame_bytes) {
    std::lock_guard guard(mutex_);
    need(state_ == State::IntakeConsumed && capture_session_);
    capture_session_->listeners_ready();
    for (unsigned owner = 0; owner < 3; ++owner) {
        capture_session_->owner_authenticated(owner);
        capture_session_->owner_upload_complete(owner, fixed_frame_bytes);
    }
    capture_session_->released_projection(projection);
}
#endif

attempt_supervisor::PublicIntakePermit
AuthorizedDriverAttempt::consume_owner_intake(unsigned role) {
    std::lock_guard guard(mutex_);
    try {
        need(state_ == State::AwaitingIntake && role == receipt_.role);
        state_ = State::Poisoned;
        auto consumed = permit_.consume_for_claim(role);
        need(consumed.authority_identity == receipt_.authority_identity &&
             consumed.selection_identity == receipt_.selection_identity &&
             consumed.accepted_head == receipt_.accepted_head &&
             consumed.durable_lock == receipt_.durable_lock);
        intake_ = consumed;
        state_ = State::IntakeConsumed;
        return consumed;
    } catch (...) { refuse(); }
}

RegisteredCaptureSession& AuthorizedDriverAttempt::capture_session() {
    std::lock_guard guard(mutex_);
    need((state_ == State::IntakeConsumed || state_ == State::ReleaseReady ||
          state_ == State::ReleaseAuthorized) && capture_session_ != nullptr);
    return *capture_session_;
}

PartyReleaseReadyAuthority AuthorizedDriverAttempt::begin_release_ready(
        VerifiedEgressAuthority&& egress) {
    std::lock_guard guard(mutex_);
    try {
        if (state_ != State::IntakeConsumed || !intake_.has_value()) {
            if (state_ != State::Completed) state_ = State::Poisoned;
            refuse();
        }
        state_ = State::Poisoned;
        const bool egress_live = egress.live_.exchange(false);
        need(egress_live);
        valid(egress.value_);
        need(egress.value_.binding_identity == receipt_.durable_lock &&
             capture_session_ &&
             capture_session_->plan_identity() ==
                 receipt_.capture_plan_identity &&
             capture_session_->projection_identity() ==
                 egress.value_.projection_identity);
        const auto readiness = release_ready_identity(receipt_, egress.value_);
        need(nonzero(readiness));
        verified_egress_ = egress.value_;
        state_ = State::ReleaseReady;
        return PartyReleaseReadyAuthority(PublicPartyReleaseReady{
            .attempt = receipt_,
            .egress = egress.value_,
            .readiness_identity = readiness,
        });
    } catch (...) { refuse(); }
}

void AuthorizedDriverAttempt::authorize_release(
        PartyReleaseAuthorizationAuthority&& authorization) {
    std::lock_guard guard(mutex_);
    try {
        need(state_ == State::ReleaseReady && intake_.has_value() &&
             verified_egress_.has_value());
        state_ = State::Poisoned;
        need(authorization.live_.exchange(false) &&
             same_authorized(authorization.attempt_, receipt_) &&
             same_egress(authorization.egress_, *verified_egress_) &&
             authorization.readiness_identity_ ==
                 release_ready_identity(receipt_, *verified_egress_) &&
             nonzero(authorization.barrier_identity_) &&
             authorization.barrier_monotonic_ns_ > 0);
        full_cohort_barrier_identity_ = authorization.barrier_identity_;
        full_cohort_barrier_monotonic_ns_ =
            authorization.barrier_monotonic_ns_;
        state_ = State::ReleaseAuthorized;
    } catch (...) { refuse(); }
}

void AuthorizedDriverAttempt::require_release_authorized() {
    std::lock_guard guard(mutex_);
    need(state_ == State::ReleaseAuthorized && verified_egress_.has_value() &&
         nonzero(full_cohort_barrier_identity_) &&
         full_cohort_barrier_monotonic_ns_ > 0);
}

PartyDriverCompletionAuthority AuthorizedDriverAttempt::complete_egress() {
    std::lock_guard guard(mutex_);
    try {
        if (state_ != State::ReleaseAuthorized || !intake_.has_value() ||
            !verified_egress_.has_value()) {
            if (state_ != State::Completed) state_ = State::Poisoned;
            refuse();
        }
        state_ = State::Poisoned;
        const auto egress = *verified_egress_;
        valid(egress);
        capture_session_->require_egress_completion_ready();
        PublicPartyDriverCompletion result{
            .role = receipt_.role,
            .round = receipt_.round,
            .classification = receipt_.classification,
            .capture_trial_id = receipt_.capture_trial_id,
            .authority_identity = receipt_.authority_identity,
            .driver_selection_identity = receipt_.driver_selection_identity,
            .selection_identity = receipt_.selection_identity,
            .run = receipt_.run,
            .trial = receipt_.trial,
            .attempt = receipt_.attempt,
            .cohort = receipt_.cohort,
            .accepted_head = receipt_.accepted_head,
            .postlock_accepted_head = receipt_.postlock_accepted_head,
            .attempt_identity = receipt_.attempt_identity,
            .proposal_identity = receipt_.proposal_identity,
            .durable_lock = receipt_.durable_lock,
            .owner_contracts = receipt_.owner_contracts,
            .capture_plan_identity = receipt_.capture_plan_identity,
            .capture_source_identity = receipt_.capture_source_identity,
            .capture_build_identity = receipt_.capture_build_identity,
            .capture_launcher_identity = receipt_.capture_launcher_identity,
            .authorization_identity = receipt_.authorization_identity,
            .egress_binding_identity = egress.binding_identity,
            .effects_identity = egress.effects_identity,
            .core_identity = egress.core_identity,
            .proof_identity = egress.proof_identity,
            .projection_identity = egress.projection_identity,
            .full_cohort_barrier_identity =
                full_cohort_barrier_identity_,
            .full_cohort_barrier_observed_monotonic_ns =
                full_cohort_barrier_monotonic_ns_,
        };
        result.completion_identity = completion_identity(result);
        verified_egress_.reset();
        state_ = State::Completed;
        return PartyDriverCompletionAuthority(std::move(result));
    } catch (...) { refuse(); }
}

#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
void AuthorizedDriverAttempt::test_only_authorize_release(
        VerifiedEgressAuthority&& egress, Digest barrier_identity,
        std::uint64_t barrier_monotonic_ns) {
    auto ready = begin_release_ready(std::move(egress));
    need(ready.live_.exchange(false));
    authorize_release(PartyReleaseAuthorizationAuthority(
        ready.value_.attempt, ready.value_.egress,
        ready.value_.readiness_identity, barrier_identity,
        barrier_monotonic_ns));
}
#endif

AuthorizedDriverAttempt::BaselineEffectsClaim
AuthorizedDriverAttempt::claim_baseline_effects() {
    std::lock_guard guard(mutex_);
    try {
        need(state_ == State::IntakeConsumed && !baseline_effects_claimed_ &&
             receipt_.classification ==
                 CaptureClassification::ExplicitOwnerPublicEffectsBaseline &&
             capture_session_ &&
             capture_session_->plan_identity() ==
                 receipt_.capture_plan_identity);
        capture_session_->require_baseline_effects_ready();
        baseline_effects_claimed_ = true;
        return BaselineEffectsClaim(receipt_);
    } catch (...) { refuse(); }
}

DriverAttempt RegisteredConstructionAuthorityBridge::admit(
        CompiledDriverSelection selected,
        CapturePlanAuthority&& capture,
        attempt_supervisor::PartyApproval&& approval,
        const attempt_supervisor::Proposal& proposal) {
    return DriverAttempt::admit_authority(
        std::move(selected), std::move(capture), std::move(approval),
        proposal);
}

const PublicDriverSelection&
RegisteredConstructionAuthorityBridge::selected_driver(
        const DriverAttempt& attempt) {
    return attempt.selected_driver();
}

const attempt_supervisor::Proposal&
RegisteredConstructionAuthorityBridge::proposal(const DriverAttempt& attempt) {
    return attempt.proposal();
}

void RegisteredConstructionAuthorityBridge::recheck_before_lock(
        DriverAttempt& attempt,
        attempt_supervisor::DirectAcceptedHeadCommitment&& head) {
    attempt.recheck_before_lock(std::move(head));
}

std::unique_ptr<AuthorizedDriverAttempt>
RegisteredConstructionAuthorityBridge::after_durable_lock(
        DriverAttempt& attempt,
        attempt_supervisor::DirectAcceptedHeadCommitment&& head,
        attempt_supervisor::DurableLockCommitment&& lock) {
    return attempt.after_durable_lock(std::move(head), std::move(lock));
}

RegisteredCaptureSession&
RegisteredConstructionAuthorityBridge::capture_session(
        AuthorizedDriverAttempt& attempt) {
    return attempt.capture_session();
}

SourceStatus source_status() {
    return SourceStatus{
        .schema = "kpb-registered-driver-bridge-source-only/v1",
        .status = "UNQUALIFIED_SOURCE_ONLY",
        .accepts_argv_or_environment = false,
        .registry_lifetime_owned_by_driver = true,
        .docker_anchor_client_bridge = true,
        .party_can_access_registry_anchor_path_or_fd = false,
        .capture_classification_bound = true,
        .raw_trial_uuid_roster_bridge = true,
        .production_capture_plan_minter = false,
        .p1_capture_plan_split_authority = true,
        .p1_capturing_player_callsite_integration = false,
        .parent_role_fork_topology = true,
        .parent_role_completion_transport = true,
        .parent_role_fork_selected_callsite_integration = false,
        .authenticated_per_role_ipc_delivery = false,
        .durable_lock_minted_from_locked_attempt = true,
        .genuine_head_and_owner_factory_integrated = true,
        .construct_registered_integration = true,
        .proof_verification_integration = true,
        .verified_release_integration = true,
        .verified_egress_pre_route_barrier = true,
        .party_egress_completion_authority = true,
        .actual_capture_completion_integration = false,
        .global_capture_supervisor_integration = false,
        .parent_durable_completion_integration = false,
        .downstream_completion_authority = false,
        .downstream_completion_integration = false,
        .registered_driver_configured = false,
        .launch_authorized = false,
    };
}

} // namespace kpi::mpc::financial::registered_driver

namespace kpi::mpc::financial::attempt_supervisor {

registered_driver::OuterSupervisorAuthority
RegisteredProposalBridge::open_outer(
    registered_driver::CompiledOuterSupervisorSelection&& selected,
    docker_anchor::SupervisorCapability&& capability) {
    using registered_driver::Digest;
    const auto nonzero = [](const Digest& value) { return value != Digest{}; };
    try {
        if (!selected.live_.exchange(false)) throw identity_registry::Refused();
        const auto& value = selected.value_;
        const auto authority = identity_registry::authority_identity(
            value.registry_authority);
        if (!value.registry_journal_directory.is_absolute() ||
            !value.registry_anchor_directory.is_absolute() ||
            value.registry_journal_directory !=
                value.registry_journal_directory.lexically_normal() ||
            value.registry_anchor_directory !=
                value.registry_anchor_directory.lexically_normal() ||
            value.registry_journal_directory == value.registry_anchor_directory ||
            !nonzero(authority) || !nonzero(value.anchor_policy_identity) ||
            !nonzero(value.supervisor_session) ||
            value.supervisor_session == authority ||
            value.docker_anchor.authority_identity != authority)
            throw identity_registry::Refused();
        auto registry = std::unique_ptr<identity_registry::Registry>(
            new identity_registry::Registry(
                identity_registry::Registry::open_existing(
                    value.registry_journal_directory,
                    value.registry_anchor_directory,
                    value.registry_authority)));
        if (registry->snapshot().authority_identity != authority)
            throw identity_registry::Refused();
        auto anchor = std::shared_ptr<docker_anchor::Client>(
            new docker_anchor::Client(
                value.docker_anchor, std::move(capability)));
        std::shared_ptr<ExternalMonotonicAnchor> external = anchor;
        SupervisorAnchorPolicy policy(
            PublicAnchorPolicy{
                .policy_identity = value.anchor_policy_identity,
                .permission_separated = true,
                .monotonic = true,
                .child_path_exposed = false,
                .child_fd_exposed = false,
            }, external);
        auto supervisor = std::unique_ptr<Supervisor>(new Supervisor(
            *registry, value.supervisor_session, std::move(policy)));
        return registered_driver::OuterSupervisorAuthority(
            std::move(registry), std::move(anchor),
            std::move(supervisor));
    } catch (...) {
        throw identity_registry::Refused();
    }
}

} // namespace kpi::mpc::financial::attempt_supervisor
