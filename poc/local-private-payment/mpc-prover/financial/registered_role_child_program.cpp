#include "registered_role_child_program.hpp"

#include "accepted_head.hpp"
#include "construction.hpp"
#include "financial_assignment.hpp"
#include "registered_p1_context.hpp"
#include "registered_p1_state_archive_scm.hpp"
#include "registered_projection_route.hpp"
#include "registered_selection.hpp"
#include "registered_service.hpp"
#include "../p1_entropy_ingress_capture.hpp"
#include "../../private_batch_trial/privacy_p1_corrupt_state_capsule_authority.hpp"

#include <optional>
#include <utility>

namespace kpi::mpc::financial::registered_driver {
namespace {

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }

template<class Authority>
Authority take_role_authority(
        std::array<std::optional<Authority>, 3>& values, unsigned role) {
    need(role < values.size() && values[role].has_value());
    Authority selected(std::move(*values[role]));
    values[role].reset();
    for (unsigned other = 0; other < values.size(); ++other)
        if (other != role) values[other].reset();
    return selected;
}

std::array<OwnerInputContract, 3> owner_contracts(
        RegisteredOwnerContractsBootstrap&& authority) {
    const auto values = authority.contracts();
    need(values.size() == 3);
    return {values[0], values[1], values[2]};
}

} // namespace

struct SelectedRegisteredRoleChildProgram::BaselineRosterState final {
    fresh_owner_issuance::BaselineOwnerRosterReceiverSplit receivers;
    explicit BaselineRosterState(
            fresh_owner_issuance::BaselineOwnerRosterAuthority&& authority)
        : receivers(fresh_owner_issuance::BaselineOwnerRosterBridge::split(
              std::move(authority))) {}
};

SelectedRegisteredRoleChildProgram::SelectedRegisteredRoleChildProgram(
        InheritedSealedQueryArtifact inherited_query_artifact,
        RoleModelConfigurationAuthorities&& model_configurations,
        RoleRosterAuthorities&& rosters,
        std::optional<fresh_owner_issuance::BaselineOwnerRosterAuthority>&&
            baseline_roster)
    : inherited_query_artifact_(std::move(inherited_query_artifact)),
      model_configurations_(std::move(model_configurations)),
      rosters_(std::move(rosters)) {
    for (unsigned role = 0; role < 3; ++role)
        need(model_configurations_[role].has_value() &&
             rosters_[role].has_value());
    if (baseline_roster.has_value())
        baseline_roster_ = std::make_unique<BaselineRosterState>(
            std::move(*baseline_roster));
}

SelectedRegisteredRoleChildProgram::~SelectedRegisteredRoleChildProgram() =
    default;

SelectedRegisteredPersistentRoleChildProgram::
SelectedRegisteredPersistentRoleChildProgram(
        std::unique_ptr<SelectedRegisteredRoleChildProgram> round1,
        std::unique_ptr<SelectedRegisteredRoleChildProgram> round2)
    : rounds_{std::move(round1), std::move(round2)} {
    need(rounds_[0] != nullptr && rounds_[1] != nullptr &&
         rounds_[0].get() != rounds_[1].get());
}

RegisteredRoleChildProgram&
SelectedRegisteredPersistentRoleChildProgram::round_program(unsigned round) {
    need(round == 1 || round == 2);
    const auto index = round - 1;
    need((round == 1 || round_claimed_[0].load()) &&
         !round_claimed_[index].exchange(true) && rounds_[index] != nullptr);
    return *rounds_[index];
}

int SelectedRegisteredRoleChildProgram::run(
        ParentAuthenticatedPartyDeliveryAuthority&& delivery,
        ChildRoleCompletionEndpointAuthority&& completion_endpoint) {
    need(!run_claimed_.exchange(true));
    const auto delivered = delivery.public_receipt();
    const unsigned role = delivered.role;
    need(role < 3);

    auto role_dispatch = std::move(delivery).dispatch_role();
    need(role_dispatch.index() == role);
    std::optional<ParentAuthenticatedPartyDeliveryAuthority> role_delivery;
    std::optional<RegisteredRole1P1StateRuntimeAuthority> p1_state_runtime;
    if (role == 0) {
        auto selected = std::get<ParentAuthenticatedRole0Delivery>(
            std::move(role_dispatch));
        role_delivery.emplace(std::move(selected).take_delivery());
    } else if (role == 1) {
        auto selected = std::get<ParentAuthenticatedRole1Delivery>(
            std::move(role_dispatch));
        auto p1_state_prelaunch = selected.take_p1_state_prelaunch();
        p1_state_runtime.emplace(
            RegisteredP1StateArchiveScmBridge::begin_role1_prelaunch(
                std::move(p1_state_prelaunch)));
        role_delivery.emplace(std::move(selected).take_delivery());
    } else {
        auto selected = std::get<ParentAuthenticatedRole2Delivery>(
            std::move(role_dispatch));
        role_delivery.emplace(std::move(selected).take_delivery());
    }
    need(role_delivery.has_value() == true &&
         p1_state_runtime.has_value() == (role == 1));
    auto& selected_delivery = *role_delivery;

    // The lambda is a destruction barrier. On the current role-1 path every
    // TLS/context/protocol object and the entropy hook disappear before the
    // outer state runtime sends its authenticated UNAVAILABLE disposition.
    const bool role1_state_unavailable = [&]() -> bool {
        using kpb::measurement::p1_state_capsule::
            P1StateThreadEpochAuthority;
        using kpi::mpc::p1_private_state::EntropyIngressCapture;
        std::optional<P1StateThreadEpochAuthority> root_thread;
        std::optional<EntropyIngressCapture> entropy_capture;
        if (role == 1) {
            auto& recorder = p1_state_runtime->recorder();
            root_thread.emplace(recorder.take_root_thread_epoch());
            auto entropy_adapter =
                recorder.take_entropy_state_adapter(*root_thread);
            entropy_capture.emplace(EntropyIngressCapture::begin(
                std::move(entropy_adapter)));
        }

        const auto finish_entropy = [&]() {
            if (role != 1) return true;
            need(entropy_capture.has_value());
            const bool healthy =
                std::move(*entropy_capture).finish_noexcept();
            entropy_capture.reset();
            return healthy;
        };

        // This must precede the conversion that burns selected_delivery.
        // P1/P2 never receive or touch the FD30 writer capability.
        std::optional<projection_route::Role0ProjectionRouteWriterAuthority>
            route_writer;
        if (role == 0)
            route_writer.emplace(
                selected_delivery.take_projection_route_writer());
        else
            need(!route_writer.has_value());

        initialize_bn254_field();
        initialize_bn254_groups();

        auto pending = RegisteredParentBootstrapTransport::receive(
            completion_endpoint, selected_delivery,
            inherited_query_artifact_);
        auto selected_model_configuration = take_role_authority(
            model_configurations_, role);
        auto admitted_model = RegisteredRoleModelAdmission::admit(
            std::move(selected_model_configuration), pending);
        auto bootstrap =
            RegisteredParentBootstrapTransport::authorize_admitted_model(
                std::move(pending), admitted_model.model());
        const auto bootstrap_receipt = bootstrap.public_receipt();
        need(bootstrap_receipt.role == role &&
             bootstrap_receipt.round == delivered.round &&
             bootstrap_receipt.driver_selection_identity ==
                 delivered.driver_selection_identity &&
             bootstrap_receipt.capture_plan_identity ==
                 delivered.capture_plan_identity);

        auto fresh = bootstrap.take_fresh_attempt();
        auto driver = bootstrap.take_driver_selection();
        auto capture = bootstrap.take_capture_plan();
        auto jobs = owner_contracts(bootstrap.take_owner_contracts());
        const auto& selected_driver = driver.public_selection();
        const auto& config = admitted_model.configuration();
        need(selected_driver.role == role &&
             selected_driver.owner_port == config.owner_port_base +
                 static_cast<int>(role) &&
             selected_driver.multiplication_batch ==
                 config.multiplication_batch);

        auto roster_authority = take_role_authority(rosters_, role);
#ifndef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
        // The unpatched upstream Player cannot account for private TLS state.
        // Stop with an authenticated UNAVAILABLE record before CryptoPlayer.
        if (role == 1) {
            need(finish_entropy());
            return true;
        }
#endif
        std::unique_ptr<RegisteredRosterPlayerRuntime> roster;
#ifdef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
        if (role == 1) {
            roster = RegisteredRosterPlayerRuntime::begin_after_fork(
                std::move(roster_authority), p1_state_runtime->recorder(),
                *root_thread);
        } else
#endif
        {
            roster = RegisteredRosterPlayerRuntime::begin_after_fork(
                std::move(roster_authority));
        }

        std::unique_ptr<RegisteredP1Context> p1_context;
        if (role == 1) {
            p1_context = RegisteredP1Context::begin(
                roster->player(), driver, std::move(capture),
                p1_state_runtime->recorder(), *root_thread);
        } else {
            p1_context = RegisteredP1Context::begin(
                roster->player(), driver, std::move(capture));
        }
        auto& context = p1_context->context();
        auto session_capture = p1_context->take_session();

        auto service = RegisteredService::open_selected(context);
        auto accepted_head = AcceptedFinancialHead::acquire_fresh(
            context, service);
        auto authenticated_delivery =
            attempt_supervisor::RegisteredProposalBridge::
                authenticated_party_delivery(
                    std::move(selected_delivery), driver);
        auto proposal =
            attempt_supervisor::RegisteredProposalBridge::proposal(
                std::move(fresh), std::move(authenticated_delivery), driver,
                service, accepted_head, jobs);
        auto approval = RegisteredSupervisorParentTransport::submit_and_wait(
            proposal, completion_endpoint);
        auto selection = RegisteredFinancialSelection::admit(
            context, service, std::move(accepted_head),
            admitted_model.model());
        const auto binding = selection.attempt_binding(
            context, jobs, bootstrap_receipt.attempt,
            bootstrap_receipt.cohort);
        auto driver_attempt = RegisteredConstructionAuthorityBridge::admit(
            std::move(driver), std::move(session_capture),
            std::move(approval), proposal);
        const auto construction =
            FinancialConstruction::construct_registered(
                context, std::move(selection), jobs, binding,
                std::move(driver_attempt));
        auto validated = FinancialValidatedAssignment::validate(
            context, construction, config.multiplication_batch);
        auto prepared = FinancialHistoryAccess::prepare(
            context, construction, validated);
        auto verified = prove_and_verify_financial(
            context, std::move(validated), std::move(prepared),
            config.model_metadata, config.verifying_key,
            config.independent_verifier,
            admitted_model.private_candidate_path(
                bootstrap_receipt.attempt));
        const auto release =
            FinancialHistoryAccess::release_verified_registered(
                context, std::move(verified), std::move(prepared));

        std::optional<
            baseline_disclosure::PartyBaselineOwnerEffectsAuthority>
            baseline_effects;
        if (bootstrap_receipt.classification ==
                CaptureClassification::
                    ExplicitOwnerPublicEffectsBaseline) {
            need(baseline_roster_ != nullptr);
            baseline_effects.emplace(
                FinancialHistoryAccess::baseline_owner_scoring(
                    context, construction, release,
                    baseline_roster_->receivers.take(
                        bootstrap_receipt.round, role)));
        } else {
            need(bootstrap_receipt.classification ==
                     CaptureClassification::HiddenCandidate &&
                 baseline_roster_ == nullptr);
        }

        // All three children must have reached genuine verified EGRESS before
        // the parent authorizes the sole role-0 public route.
        FinancialHistoryAccess::await_registered_release_barrier(
            context, construction, release, completion_endpoint);

        if (role == 0) {
            need(route_writer.has_value());
            FinancialHistoryAccess::route_registered_projection(
                context, construction, release, std::move(*route_writer));
            route_writer.reset();
        } else {
            need(!route_writer.has_value());
        }

        auto party_completion =
            FinancialHistoryAccess::complete_registered_egress(
                context, construction, release);
        if (role == 1) {
            // Structural completeness is still false. Do not flatten a typed
            // private-state failure into a successful party completion.
            need(finish_entropy());
            return true;
        }
        if (baseline_effects.has_value()) {
            RegisteredPartyCompletionTransport::submit_baseline(
                std::move(party_completion), std::move(*baseline_effects),
                std::move(completion_endpoint));
            baseline_effects.reset();
        } else {
            RegisteredPartyCompletionTransport::submit_hidden(
                std::move(party_completion),
                std::move(completion_endpoint));
        }
        return false;
    }();

    if (role1_state_unavailable) {
        need(role == 1 && p1_state_runtime.has_value());
        std::move(*p1_state_runtime).finish_unavailable_noexcept();
        p1_state_runtime.reset();
        refuse();
    }
    need(role != 1 && !p1_state_runtime.has_value());
    return 0;
}

RegisteredRoleChildProgramSourceStatus
registered_role_child_program_source_status() {
    return {
        .schema = "kpb-registered-role-child-program-source-only/v1",
        .status = "UNQUALIFIED_SOURCE_ONLY",
        .typed_parent_bootstrap = true,
        .actual_model_admission = true,
        .immutable_roster_player = true,
        .genuine_registered_construction = true,
        .genuine_independent_proof_verification = true,
        .genuine_verified_release = true,
        .pre_route_full_cohort_release_barrier = true,
        .baseline_only_owner_disclosure = true,
        .role0_only_projection_route = true,
        .fixed_terminal_composite = true,
        .concrete_persistent_child_program = true,
        .role1_p1_state_prelaunch_callsite = true,
        .role1_p1_state_completion_qualified = false,
        .production_model_configuration_minter = false,
        .production_roster_authority_minter = false,
        .production_selected_parent_callsite = false,
        .registered_driver_configured = false,
        .launch_authorized = false,
    };
}

} // namespace kpi::mpc::financial::registered_driver
