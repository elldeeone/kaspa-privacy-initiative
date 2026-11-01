#pragma once

#include "registered_preidentity_ready_contract.hpp"
#include "registered_persistent_fresh_trial_activation_contract.hpp"

#include <array>
#include <memory>

namespace kpi::mpc::financial::registered_driver {

struct RegisteredPreidentityReadyStorage;
class FreshTrialCaptureTopologyReservation;
class RegisteredPersistentRoleProcessReservation;
class RegisteredPreidentityActivationPair;

class RegisteredOwnerIssuancePermit final {
    const void* epoch_token_{};
    unsigned owner_{};
    bool live_{};
    RegisteredOwnerIssuancePermit(const void*, unsigned) noexcept;
    friend class RegisteredPreidentityReadyIssuanceBridge;
    friend class ::kpi::mpc::financial::fresh_owner_issuance::
        FreshOwnerTransactionalIssuanceBridge;
public:
    RegisteredOwnerIssuancePermit(
        const RegisteredOwnerIssuancePermit&) = delete;
    RegisteredOwnerIssuancePermit& operator=(
        const RegisteredOwnerIssuancePermit&) = delete;
    RegisteredOwnerIssuancePermit(
        RegisteredOwnerIssuancePermit&&) noexcept;
    RegisteredOwnerIssuancePermit& operator=(
        RegisteredOwnerIssuancePermit&&) = delete;
};

// Opaque owner of the exact topology and persistent-process reservations.
// It has no public receipt, identity, raw descriptor, PID, or split method.
class RegisteredPreidentityReadyAuthority final {
    std::unique_ptr<RegisteredPreidentityReadyStorage> storage_;
    explicit RegisteredPreidentityReadyAuthority(
        std::unique_ptr<RegisteredPreidentityReadyStorage>);
    friend class RegisteredPreidentityReadyBridge;
    friend class RegisteredPreidentityReadyIssuanceBridge;
public:
    RegisteredPreidentityReadyAuthority(
        const RegisteredPreidentityReadyAuthority&) = delete;
    RegisteredPreidentityReadyAuthority& operator=(
        const RegisteredPreidentityReadyAuthority&) = delete;
    RegisteredPreidentityReadyAuthority(
        RegisteredPreidentityReadyAuthority&&) noexcept;
    RegisteredPreidentityReadyAuthority& operator=(
        RegisteredPreidentityReadyAuthority&&) = delete;
    ~RegisteredPreidentityReadyAuthority();
};

class RegisteredPreidentityReadyOwnerIssuanceSession final {
    std::unique_ptr<RegisteredPreidentityReadyStorage> storage_;
    std::array<bool, 3> owner_permits_taken_{};
    explicit RegisteredPreidentityReadyOwnerIssuanceSession(
        std::unique_ptr<RegisteredPreidentityReadyStorage>);
    friend class RegisteredPreidentityReadyIssuanceBridge;
public:
    RegisteredPreidentityReadyOwnerIssuanceSession(
        const RegisteredPreidentityReadyOwnerIssuanceSession&) = delete;
    RegisteredPreidentityReadyOwnerIssuanceSession& operator=(
        const RegisteredPreidentityReadyOwnerIssuanceSession&) = delete;
    RegisteredPreidentityReadyOwnerIssuanceSession(
        RegisteredPreidentityReadyOwnerIssuanceSession&&) noexcept;
    RegisteredPreidentityReadyOwnerIssuanceSession& operator=(
        RegisteredPreidentityReadyOwnerIssuanceSession&&) = delete;
    ~RegisteredPreidentityReadyOwnerIssuanceSession();
};

// Opaque causal residual embedded inside the genuine fresh-owner issuance.
// It retains both reservations unchanged and can be consumed only by the
// complete persistent activation bridge after accepted R1 history exists.
class RegisteredPreidentityReadyIssuanceResidual final {
    std::unique_ptr<RegisteredPreidentityReadyStorage> storage_;
    explicit RegisteredPreidentityReadyIssuanceResidual(
        std::unique_ptr<RegisteredPreidentityReadyStorage>) noexcept;
    RegisteredPreidentityActivationPair extract_for_activation() &&;
    friend class RegisteredPreidentityReadyIssuanceBridge;
    friend class RegisteredPersistentFreshTrialActivationBridge;
public:
    RegisteredPreidentityReadyIssuanceResidual(
        const RegisteredPreidentityReadyIssuanceResidual&) = delete;
    RegisteredPreidentityReadyIssuanceResidual& operator=(
        const RegisteredPreidentityReadyIssuanceResidual&) = delete;
    RegisteredPreidentityReadyIssuanceResidual(
        RegisteredPreidentityReadyIssuanceResidual&&) noexcept;
    RegisteredPreidentityReadyIssuanceResidual& operator=(
        RegisteredPreidentityReadyIssuanceResidual&&) = delete;
    ~RegisteredPreidentityReadyIssuanceResidual();
};

// Private phase-2 pair. Extraction validates the shared epoch before burning
// the issuance residual; after that validation both capability moves are
// no-throw and the activation bridge retains them in its preallocated result.
class RegisteredPreidentityActivationPair final {
    std::unique_ptr<RegisteredPreidentityReadyStorage> storage_;
    explicit RegisteredPreidentityActivationPair(
        std::unique_ptr<RegisteredPreidentityReadyStorage>);
    void validate_for_activation() const;
    FreshTrialCaptureTopologyReservation take_topology() && noexcept;
    RegisteredPersistentRoleProcessReservation take_process() && noexcept;
    friend class RegisteredPreidentityReadyIssuanceResidual;
    friend class RegisteredPersistentFreshTrialActivationBridge;
public:
    RegisteredPreidentityActivationPair(
        const RegisteredPreidentityActivationPair&) = delete;
    RegisteredPreidentityActivationPair& operator=(
        const RegisteredPreidentityActivationPair&) = delete;
    RegisteredPreidentityActivationPair(
        RegisteredPreidentityActivationPair&&) noexcept;
    RegisteredPreidentityActivationPair& operator=(
        RegisteredPreidentityActivationPair&&) = delete;
    ~RegisteredPreidentityActivationPair();
};

struct RegisteredPreidentityReadySourceStatus final {
    bool topology_and_process_join_core{};
    bool causal_owner_issuance_consumer{};
    bool phase2_activation_extraction{};
    bool postissuance_failure_composite{};
    bool selected_parent_callsite{};
    bool configured{};
};

inline constexpr RegisteredPreidentityReadySourceStatus
    kRegisteredPreidentityReadySourceStatus{
        .topology_and_process_join_core = true,
        .causal_owner_issuance_consumer = false,
        .phase2_activation_extraction = false,
        .postissuance_failure_composite = false,
        .selected_parent_callsite = false,
        .configured = false,
    };

} // namespace kpi::mpc::financial::registered_driver
