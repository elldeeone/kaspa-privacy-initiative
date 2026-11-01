#pragma once

// Concrete role callback for the parent-fork topology.  Every usable input is
// a move-only compiled or parent-delivered capability.  This class contains no
// production factory for those inputs and therefore remains unreachable while
// the selected registered build is CONFIGURED0.

#include "fresh_owner_trial_issuance.hpp"
#include "registered_parent_role_fork.hpp"
#include "registered_role_model_admission.hpp"
#include "registered_roster_crypto_player.hpp"

#include <array>
#include <atomic>
#include <memory>
#include <optional>
#include <string>

namespace kpi::mpc::financial::registered_driver {

using RoleModelConfigurationAuthorities = std::array<
    std::optional<CompiledRoleModelConfigurationAuthority>, 3>;
using RoleRosterAuthorities = std::array<
    std::optional<ImmutableRegisteredRosterAuthority>, 3>;

class SelectedRegisteredRoleChildProgram final
    : public RegisteredRoleChildProgram {
    struct BaselineRosterState;
    InheritedSealedQueryArtifact inherited_query_artifact_;
    RoleModelConfigurationAuthorities model_configurations_;
    RoleRosterAuthorities rosters_;
    std::unique_ptr<BaselineRosterState> baseline_roster_;
    std::atomic_bool run_claimed_{false};
public:
    SelectedRegisteredRoleChildProgram(
        InheritedSealedQueryArtifact,
        RoleModelConfigurationAuthorities&&,
        RoleRosterAuthorities&&,
        std::optional<fresh_owner_issuance::
            BaselineOwnerRosterAuthority>&& = std::nullopt);
    ~SelectedRegisteredRoleChildProgram() override;
    SelectedRegisteredRoleChildProgram(
        const SelectedRegisteredRoleChildProgram&) = delete;
    SelectedRegisteredRoleChildProgram& operator=(
        const SelectedRegisteredRoleChildProgram&) = delete;
    SelectedRegisteredRoleChildProgram(
        SelectedRegisteredRoleChildProgram&&) = delete;
    SelectedRegisteredRoleChildProgram& operator=(
        SelectedRegisteredRoleChildProgram&&) = delete;

    int run(
        ParentAuthenticatedPartyDeliveryAuthority&&,
        ChildRoleCompletionEndpointAuthority&&) override;
};

// One concrete persistent callback for the fork-once topology. The two
// already-constructed round programs retain disjoint move-only authorities;
// children may claim them only in R1 then R2 order.
class SelectedRegisteredPersistentRoleChildProgram final
    : public RegisteredPersistentRoleChildProgram {
    std::array<std::unique_ptr<SelectedRegisteredRoleChildProgram>, 2>
        rounds_;
    std::array<std::atomic_bool, 2> round_claimed_{};
public:
    SelectedRegisteredPersistentRoleChildProgram(
        std::unique_ptr<SelectedRegisteredRoleChildProgram> round1,
        std::unique_ptr<SelectedRegisteredRoleChildProgram> round2);
    SelectedRegisteredPersistentRoleChildProgram(
        const SelectedRegisteredPersistentRoleChildProgram&) = delete;
    SelectedRegisteredPersistentRoleChildProgram& operator=(
        const SelectedRegisteredPersistentRoleChildProgram&) = delete;
    SelectedRegisteredPersistentRoleChildProgram(
        SelectedRegisteredPersistentRoleChildProgram&&) = delete;
    SelectedRegisteredPersistentRoleChildProgram& operator=(
        SelectedRegisteredPersistentRoleChildProgram&&) = delete;

    RegisteredRoleChildProgram& round_program(unsigned round) override;
};

struct RegisteredRoleChildProgramSourceStatus {
    std::string schema;
    std::string status;
    bool typed_parent_bootstrap{};
    bool actual_model_admission{};
    bool immutable_roster_player{};
    bool genuine_registered_construction{};
    bool genuine_independent_proof_verification{};
    bool genuine_verified_release{};
    bool pre_route_full_cohort_release_barrier{};
    bool baseline_only_owner_disclosure{};
    bool role0_only_projection_route{};
    bool fixed_terminal_composite{};
    bool concrete_persistent_child_program{};
    bool role1_p1_state_prelaunch_callsite{};
    bool role1_p1_state_completion_qualified{};
    bool production_model_configuration_minter{};
    bool production_roster_authority_minter{};
    bool production_selected_parent_callsite{};
    bool registered_driver_configured{};
    bool launch_authorized{};
};

RegisteredRoleChildProgramSourceStatus
registered_role_child_program_source_status();

} // namespace kpi::mpc::financial::registered_driver
