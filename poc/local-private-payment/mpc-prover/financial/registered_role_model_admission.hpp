#pragma once

// Real public-model admission for one registered role.  The capability below
// is deliberately not minted by production while the ROOT-owned selected
// driver header is absent.  Once selected, it still has to admit every sealed
// query point and every R1CS row; no caller-supplied PackedModel can cross this
// boundary.

#include "registered_driver_config.hpp"
#include "registered_parent_bootstrap.hpp"

#include <atomic>
#include <filesystem>
#include <string>

namespace kpi::mpc::financial::registered_driver {

struct PublicCompiledRoleModelConfiguration {
    unsigned role{};
    Digest driver_selection_identity{};
    Digest source_identity{};
    Digest build_identity{};
    registered_detail::DriverConfiguration configuration;
};

class CompiledRoleModelConfigurationAuthority final {
    PublicCompiledRoleModelConfiguration value_;
    Digest identity_{};
    std::atomic_bool live_{true};
    explicit CompiledRoleModelConfigurationAuthority(
        PublicCompiledRoleModelConfiguration);
    friend class RegisteredRoleModelAdmission;
public:
    CompiledRoleModelConfigurationAuthority(
        const CompiledRoleModelConfigurationAuthority&) = delete;
    CompiledRoleModelConfigurationAuthority& operator=(
        const CompiledRoleModelConfigurationAuthority&) = delete;
    CompiledRoleModelConfigurationAuthority(
        CompiledRoleModelConfigurationAuthority&&) noexcept;
    CompiledRoleModelConfigurationAuthority& operator=(
        CompiledRoleModelConfigurationAuthority&&) = delete;
#ifdef KPI_REGISTERED_ROLE_MODEL_ADMISSION_TEST_SETUP
    static CompiledRoleModelConfigurationAuthority test_only_mint(
        PublicCompiledRoleModelConfiguration);
#endif
};

struct PublicRegisteredRoleModelAdmission {
    unsigned role{};
    Digest driver_selection_identity{};
    Digest configuration_identity{};
    Digest inherited_query_artifact_identity{};
    Digest model_preimage_identity{};
    Digest query_store_preimage_identity{};
};

class RegisteredRoleModelAdmission final {
    PublicRegisteredRoleModelAdmission receipt_;
    registered_detail::DriverConfiguration configuration_;
    packed::PackedModel model_;
    RegisteredRoleModelAdmission(
        PublicRegisteredRoleModelAdmission,
        registered_detail::DriverConfiguration,
        packed::PackedModel);
public:
    RegisteredRoleModelAdmission(const RegisteredRoleModelAdmission&) = delete;
    RegisteredRoleModelAdmission& operator=(
        const RegisteredRoleModelAdmission&) = delete;
    RegisteredRoleModelAdmission(RegisteredRoleModelAdmission&&) noexcept =
        default;
    RegisteredRoleModelAdmission& operator=(
        RegisteredRoleModelAdmission&&) = delete;

    static RegisteredRoleModelAdmission admit(
        CompiledRoleModelConfigurationAuthority&&,
        const RegisteredChildBootstrapPending&);

    const PublicRegisteredRoleModelAdmission& public_receipt() const {
        return receipt_;
    }
    const packed::PackedModel& model() const { return model_; }
    const registered_detail::DriverConfiguration& configuration() const {
        return configuration_;
    }
    std::filesystem::path private_candidate_path(
        const Digest& attempt) const;
};

struct RegisteredRoleModelAdmissionSourceStatus {
    std::string schema;
    std::string status;
    bool inherited_sealed_query_artifact_consumed{};
    bool full_query_point_admission{};
    bool full_r1cs_row_admission{};
    bool actual_model_and_query_identity_join{};
    bool caller_packed_model_factory{};
    bool production_compiled_configuration_minter{};
    bool selected_child_callsite{};
    bool registered_driver_configured{};
    bool launch_authorized{};
};

RegisteredRoleModelAdmissionSourceStatus
registered_role_model_admission_source_status();

} // namespace kpi::mpc::financial::registered_driver
