#include "registered_selected_producer_activation_contract.hpp"

#include "fresh_owner_trial_issuance.hpp"
#include "registered_parent_role_fork.hpp"
#include "registered_selected_producer_run_binding.hpp"
#include "../../private_batch_trial/privacy_owner_score_lineage_source_authority.hpp"
#include "../../private_batch_trial/privacy_p1_mascot_fresh_prep_directory_authority.hpp"
#include "../../private_batch_trial/privacy_prelaunch_policy_domain_authority.hpp"

#include <memory>
#include <optional>
#include <stdexcept>
#include <utility>

namespace kpi::mpc::financial::registered_driver {

namespace source =
    kpb::measurement::score_output_lineage_source;
namespace policy = kpb::measurement::prelaunch_policy_domain;

namespace {
[[noreturn]] void refuse_capsule_compiler_transfer() {
    throw std::runtime_error(
        "registered-selected-activation-capsule-transfer-refused");
}
void need_capsule_compiler_transfer(bool value) {
    if (!value) refuse_capsule_compiler_transfer();
}
} // namespace

struct RegisteredSelectedProducerActivationAuthority::Storage final {
    // Declared before topology so reverse destruction settles the persistent
    // children first and only then removes their source-owned PREP_DIR.
    std::unique_ptr<kpb::measurement::p1_state::
        P1MascotFreshPrepDirectoryAuthority> mascot_prep_directory;
    std::optional<RegisteredPersistentTopologyActivationAuthority> topology;
    std::optional<RegisteredSelectedProducerPrelaunchBindingAuthority>
        prelaunch;
    std::optional<source::SelectedOwnerScoreLineageSourceTransferAuthority>
        lineage;
    bool capsule_compiler_claimed{};
};

struct RegisteredSelectedProducerActivationFailureAuthority::Storage final {
    // If failure follows PREP_DIR creation, keep it until the retained
    // topology/abort residual has settled every persistent child.
    std::unique_ptr<kpb::measurement::p1_state::
        P1MascotFreshPrepDirectoryAuthority> mascot_prep_directory;
    std::optional<RegisteredPersistentRoleActivationFailureResidual>
        persistent_failure;
    std::optional<policy::RegisteredPrelaunchPolicyDomainAuthority>
        policy_source;
    std::optional<source::SelectedOwnerScoreLineagePrelaunchSourceAuthority>
        lineage_source;
    std::optional<RegisteredPersistentTopologyActivationAuthority>
        retained_topology_failure;
};

RegisteredSelectedProducerActivationAuthority::
RegisteredSelectedProducerActivationAuthority(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {}
RegisteredSelectedProducerActivationAuthority::
RegisteredSelectedProducerActivationAuthority(
        RegisteredSelectedProducerActivationAuthority&&) noexcept = default;
RegisteredSelectedProducerActivationAuthority::
~RegisteredSelectedProducerActivationAuthority() = default;

const RegisteredSelectedProducerPrelaunchBindingAuthority&
RegisteredSelectedProducerActivationAuthority::
inspect_for_state_capsule_compiler() const {
    need_capsule_compiler_transfer(
        storage_ != nullptr && !storage_->capsule_compiler_claimed &&
        storage_->mascot_prep_directory != nullptr &&
        storage_->prelaunch.has_value());
    need_capsule_compiler_transfer(
        storage_->topology.has_value() && storage_->lineage.has_value());
    return *storage_->prelaunch;
}

kpb::measurement::p1_state::P1MascotFreshPrepDirectoryAuthority
RegisteredSelectedProducerActivationAuthority::
claim_mascot_for_state_capsule_compiler() {
    (void)inspect_for_state_capsule_compiler();
    storage_->capsule_compiler_claimed = true;
    auto result = std::move(*storage_->mascot_prep_directory);
    storage_->mascot_prep_directory.reset();
    return result;
}

RegisteredSelectedProducerActivationFailureAuthority::
RegisteredSelectedProducerActivationFailureAuthority(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {}
RegisteredSelectedProducerActivationFailureAuthority::
RegisteredSelectedProducerActivationFailureAuthority(
        RegisteredSelectedProducerActivationFailureAuthority&&) noexcept =
    default;
RegisteredSelectedProducerActivationFailureAuthority::
~RegisteredSelectedProducerActivationFailureAuthority() = default;

RegisteredSelectedProducerActivationResult::
RegisteredSelectedProducerActivationResult(
        std::unique_ptr<RegisteredSelectedProducerActivationAuthority>
            success) noexcept
    : success_(std::move(success)) {}
RegisteredSelectedProducerActivationResult::
RegisteredSelectedProducerActivationResult(
        std::unique_ptr<RegisteredSelectedProducerActivationFailureAuthority>
            failure) noexcept
    : failure_(std::move(failure)) {}
RegisteredSelectedProducerActivationResult::
RegisteredSelectedProducerActivationResult(
        RegisteredSelectedProducerActivationResult&&) noexcept = default;
RegisteredSelectedProducerActivationResult::
~RegisteredSelectedProducerActivationResult() = default;

RegisteredSelectedProducerActivationAuthority
RegisteredSelectedProducerActivationResult::
claim_success_for_state_capsule_compiler() && {
    need_capsule_compiler_transfer(
        success_ != nullptr && failure_ == nullptr);
    auto success = std::move(success_);
    return std::move(*success);
}

RegisteredSelectedProducerActivationResult
RegisteredSelectedProducerActivationBridge::activate(
        fresh_owner_issuance::FreshOwnerPersistentActivationAuthority&&
            activation,
        policy::RegisteredPrelaunchPolicyDomainAuthority&& policy_source,
        source::SelectedOwnerScoreLineagePrelaunchSourceAuthority&&
            lineage_source) {
    // Allocate both closed-sum shells before claiming any of the three
    // one-shot inputs. Later failures can retain the exact Stage-1 abort
    // residual without allocating an outcome wrapper after claim.
    auto success_storage =
        std::make_unique<RegisteredSelectedProducerActivationAuthority::
            Storage>();
    auto failure_storage =
        std::make_unique<RegisteredSelectedProducerActivationFailureAuthority::
            Storage>();
    auto success =
        std::unique_ptr<RegisteredSelectedProducerActivationAuthority>(
            new RegisteredSelectedProducerActivationAuthority(
                std::move(success_storage)));
    auto failure =
        std::unique_ptr<RegisteredSelectedProducerActivationFailureAuthority>(
            new RegisteredSelectedProducerActivationFailureAuthority(
                std::move(failure_storage)));

    failure->storage_->policy_source.emplace(std::move(policy_source));
    failure->storage_->lineage_source.emplace(std::move(lineage_source));

    auto stage = RegisteredPersistentFreshTrialActivationBridge::activate(
        std::move(activation));
    if (!stage.topology_prepared()) {
        failure->storage_->persistent_failure.emplace(
            std::move(stage).take_failure_residual());
        return RegisteredSelectedProducerActivationResult(
            std::move(failure));
    }

    std::optional<RegisteredPersistentTopologyActivationAuthority> topology;
    topology.emplace(std::move(stage).take_topology_activation());
    try {
        success->storage_->mascot_prep_directory = std::make_unique<
            kpb::measurement::p1_state::
                P1MascotFreshPrepDirectoryAuthority>(
            kpb::measurement::p1_state::
                P1MascotFreshPrepDirectorySourceBridge::
                    mint_for_selected_activation());
        auto source_bundle =
            std::move(*failure->storage_->lineage_source)
                .consume_for_selected_activation();
        failure->storage_->lineage_source.reset();

        policy::PolicyDigest accepted_policy{};
        policy::PolicyDigest selected_policy{};
        policy::PolicyDigest policy_manifest{};
        std::move(*failure->storage_->policy_source)
            .consume_for_selected_activation(
                accepted_policy, selected_policy, policy_manifest);
        failure->storage_->policy_source.reset();

        auto plan = std::move(source_bundle.plan);
        plan.accepted_head_policy_identity = accepted_policy;
        plan.selected_main_policy_identity = selected_policy;
        plan.prelaunch_policy_manifest_identity = policy_manifest;
        topology->bind_selected_prelaunch_plan(plan);

        RegisteredSelectedProducerPrelaunchInputAuthority input(
            std::move(plan));
        auto binding =
            RegisteredSelectedProducerPrelaunchBindingFactory::compile(
                std::move(input));
        binding.lineage_selection_fd_ =
            std::exchange(source_bundle.selection_fd, -1);
        binding.lineage_worker_fd_ =
            std::exchange(source_bundle.worker_fd, -1);
        binding.lineage_worker_sha256_ = source_bundle.worker_sha256;
        binding.lineage_receiver_live_.store(true);
        binding.lineage_worker_selected_ = true;

        auto authenticated =
            source::PrivacyLaunchLineageSourceReceiverBridge::receive(
                binding);
        auto admitted =
            source::SelectedOwnerScoreLineageAdmissionBridge::admit(
                std::move(authenticated));
        success->storage_->topology.emplace(std::move(*topology));
        topology.reset();
        success->storage_->prelaunch.emplace(std::move(binding));
        success->storage_->lineage.emplace(std::move(admitted));
        return RegisteredSelectedProducerActivationResult(
            std::move(success));
    } catch (...) {
        failure->storage_->mascot_prep_directory = std::move(
            success->storage_->mascot_prep_directory);
        if (topology.has_value()) {
            try {
                failure->storage_->persistent_failure.emplace(
                    RegisteredPersistentFreshTrialActivationBridge::
                        abort_topology(std::move(*topology)));
                topology.reset();
            } catch (...) {
                failure->storage_->retained_topology_failure.emplace(
                    std::move(*topology));
                topology.reset();
            }
        }
        return RegisteredSelectedProducerActivationResult(
            std::move(failure));
    }
}

} // namespace kpi::mpc::financial::registered_driver
