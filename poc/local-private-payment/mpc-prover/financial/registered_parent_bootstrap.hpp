#pragma once

// Typed source-only bootstrap for one registered financial round. The outer
// parent consumes a fresh-owner/history authority and one capture plan, then
// distributes exact per-role capabilities over the retained authenticated
// channels. Each role must admit the inherited sealed public model/query store
// before any proposal, driver, or capture capability becomes available.

#include "registered_driver_bridge.hpp"
#include "registered_parent_bootstrap_contract.hpp"

#include <array>
#include <cstdint>
#include <istream>
#include <memory>
#include <span>
#include <string>

namespace kpi::mpc::financial::registered_driver {

struct PublicInheritedSealedQueryArtifact {
    Digest artifact_identity{};
    Digest container_sha256{};
    Digest canonical_pk_sha256{};
    Digest decoder_identity{};
    std::uint64_t container_bytes{};
    std::uint64_t canonical_pk_bytes{};
    std::uint64_t snapshot_device{};
    std::uint64_t snapshot_inode{};
};

// Copying this handle only shares one immutable sealed public inode. Every
// stream returned by SealedTraceArtifact is an independent pread cursor.
class InheritedSealedQueryArtifact final {
    PublicInheritedSealedQueryArtifact receipt_;
    std::shared_ptr<const SealedTraceArtifact> artifact_;
    InheritedSealedQueryArtifact(
        PublicInheritedSealedQueryArtifact,
        std::shared_ptr<const SealedTraceArtifact>);
    friend class RegisteredParentBootstrapTransport;
public:
    InheritedSealedQueryArtifact(
        const InheritedSealedQueryArtifact&) = default;
    InheritedSealedQueryArtifact& operator=(
        const InheritedSealedQueryArtifact&) = default;
    const PublicInheritedSealedQueryArtifact& public_receipt() const {
        return receipt_;
    }
};

struct PublicRegisteredRoleBootstrap {
    unsigned role{};
    unsigned round{};
    CaptureClassification classification{};
    std::string capture_trial_id;
    Digest bootstrap_identity{};
    Digest fork_plan_identity{};
    Digest offer_identity{};
    Digest delivery_ack_identity{};
    Digest channel_nonce{};
    Digest authority_identity{};
    Digest supervisor_session{};
    Digest party_session{};
    Digest registration_identity{};
    Digest service_identity{};
    Digest driver_selection_identity{};
    Digest selection_identity{};
    Digest run{};
    Digest trial{};
    Digest attempt{};
    Digest cohort{};
    Digest accepted_input_head_identity{};
    Digest history_gate_identity{};
    Digest fresh_owner_issuance_identity{};
    std::array<Digest, 3> owner_contract_identities{};
    Digest capture_plan_identity{};
    Digest capture_source_identity{};
    Digest capture_build_identity{};
    Digest capture_launcher_identity{};
    Digest model_preimage_identity{};
    Digest query_store_preimage_identity{};
    Digest scalar_capture_manifest_identity{};
    Digest inherited_query_artifact_identity{};
};

class ParentBootstrapPlanAuthority final {
public:
    struct Storage;
private:
    std::unique_ptr<Storage> storage_;
    explicit ParentBootstrapPlanAuthority(std::unique_ptr<Storage>);
    friend class RegisteredParentBootstrapTransport;
public:
    ParentBootstrapPlanAuthority(
        const ParentBootstrapPlanAuthority&) = delete;
    ParentBootstrapPlanAuthority& operator=(
        const ParentBootstrapPlanAuthority&) = delete;
    ParentBootstrapPlanAuthority(ParentBootstrapPlanAuthority&&) noexcept;
    ParentBootstrapPlanAuthority& operator=(
        ParentBootstrapPlanAuthority&&) = delete;
    ~ParentBootstrapPlanAuthority();
};

// A pending child can read the inherited public artifact, but holds no usable
// proposal/driver/capture authority. Destroying it before model admission
// poisons the retained role channel.
class RegisteredChildBootstrapPending final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredChildBootstrapPending(std::unique_ptr<Storage>);
    friend class RegisteredParentBootstrapTransport;
public:
    RegisteredChildBootstrapPending(
        const RegisteredChildBootstrapPending&) = delete;
    RegisteredChildBootstrapPending& operator=(
        const RegisteredChildBootstrapPending&) = delete;
    RegisteredChildBootstrapPending(
        RegisteredChildBootstrapPending&&) noexcept;
    RegisteredChildBootstrapPending& operator=(
        RegisteredChildBootstrapPending&&) = delete;
    ~RegisteredChildBootstrapPending();
    const PublicRegisteredRoleBootstrap& public_receipt() const;
};

class RegisteredOwnerContractsBootstrap final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredOwnerContractsBootstrap(std::unique_ptr<Storage>);
    friend class RegisteredParentBootstrapTransport;
    friend class RegisteredAdmittedRoleBootstrap;
public:
    RegisteredOwnerContractsBootstrap(
        const RegisteredOwnerContractsBootstrap&) = delete;
    RegisteredOwnerContractsBootstrap& operator=(
        const RegisteredOwnerContractsBootstrap&) = delete;
    RegisteredOwnerContractsBootstrap(
        RegisteredOwnerContractsBootstrap&&) noexcept;
    RegisteredOwnerContractsBootstrap& operator=(
        RegisteredOwnerContractsBootstrap&&) = delete;
    ~RegisteredOwnerContractsBootstrap();
    std::span<const OwnerInputContract> contracts() const;
};

class RegisteredAdmittedRoleBootstrap final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredAdmittedRoleBootstrap(std::unique_ptr<Storage>);
    friend class RegisteredParentBootstrapTransport;
public:
    RegisteredAdmittedRoleBootstrap(
        const RegisteredAdmittedRoleBootstrap&) = delete;
    RegisteredAdmittedRoleBootstrap& operator=(
        const RegisteredAdmittedRoleBootstrap&) = delete;
    RegisteredAdmittedRoleBootstrap(
        RegisteredAdmittedRoleBootstrap&&) noexcept;
    RegisteredAdmittedRoleBootstrap& operator=(
        RegisteredAdmittedRoleBootstrap&&) = delete;
    ~RegisteredAdmittedRoleBootstrap();

    const PublicRegisteredRoleBootstrap& public_receipt() const;
    CompiledFreshAttemptAuthority take_fresh_attempt();
    CompiledDriverSelection take_driver_selection();
    CapturePlanAuthority take_capture_plan();
    RegisteredOwnerContractsBootstrap take_owner_contracts();
};

struct ParentBootstrapSourceStatus {
    std::string schema;
    std::string status;
    bool typed_fresh_owner_history_consumption;
    bool exact_three_role_authenticated_transport;
    bool one_parent_sealed_query_artifact;
    bool independent_child_pread_streams;
    bool child_full_model_and_query_admission_gate;
    bool caller_digest_or_json_authority_route;
    bool production_selected_driver_factory;
    bool production_round1_history_minter;
    bool production_round2_successor_history_minter;
    bool selected_gate_callsite_integration;
    bool registered_driver_configured;
    bool launch_authorized;
};

ParentBootstrapSourceStatus parent_bootstrap_source_status();

} // namespace kpi::mpc::financial::registered_driver

