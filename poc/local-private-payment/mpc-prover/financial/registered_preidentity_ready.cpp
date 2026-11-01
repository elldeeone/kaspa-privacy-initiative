#include "registered_preidentity_ready.hpp"

#include "fresh_owner_trial_issuance.hpp"
#include "registered_parent_role_fork.hpp"
#include "../../private_batch_trial/privacy_registered_fresh_trial_capture_topology_reservation.hpp"

#include <optional>
#include <exception>
#include <ranges>
#include <utility>

namespace kpi::mpc::financial::registered_driver {
namespace {

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }

} // namespace

struct RegisteredPreidentityReadyStorage final {
    std::optional<FreshTrialCaptureTopologyReservation> topology;
    std::optional<RegisteredPersistentRoleProcessReservation> process;
    const void* epoch_token{};
};

RegisteredOwnerIssuancePermit::RegisteredOwnerIssuancePermit(
        const void* epoch_token, unsigned owner) noexcept
    : epoch_token_(epoch_token), owner_(owner), live_(true) {}

RegisteredOwnerIssuancePermit::RegisteredOwnerIssuancePermit(
        RegisteredOwnerIssuancePermit&& other) noexcept
    : epoch_token_(std::exchange(other.epoch_token_, nullptr)),
      owner_(std::exchange(other.owner_, 0)),
      live_(std::exchange(other.live_, false)) {}

RegisteredPreidentityReadyAuthority::RegisteredPreidentityReadyAuthority(
        std::unique_ptr<RegisteredPreidentityReadyStorage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }

RegisteredPreidentityReadyAuthority::RegisteredPreidentityReadyAuthority(
        RegisteredPreidentityReadyAuthority&& other) noexcept
    : storage_(std::move(other.storage_)) {}

RegisteredPreidentityReadyAuthority::~RegisteredPreidentityReadyAuthority() =
    default;

RegisteredPreidentityReadyOwnerIssuanceSession::
RegisteredPreidentityReadyOwnerIssuanceSession(
        std::unique_ptr<RegisteredPreidentityReadyStorage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }

RegisteredPreidentityReadyOwnerIssuanceSession::
RegisteredPreidentityReadyOwnerIssuanceSession(
        RegisteredPreidentityReadyOwnerIssuanceSession&& other) noexcept
    : storage_(std::move(other.storage_)),
      owner_permits_taken_(other.owner_permits_taken_) {
    other.owner_permits_taken_.fill(false);
}

RegisteredPreidentityReadyOwnerIssuanceSession::
~RegisteredPreidentityReadyOwnerIssuanceSession() = default;

RegisteredPreidentityReadyIssuanceResidual::
RegisteredPreidentityReadyIssuanceResidual(
        std::unique_ptr<RegisteredPreidentityReadyStorage> storage) noexcept
    : storage_(std::move(storage)) {
    if (storage_ == nullptr) std::terminate();
}

RegisteredPreidentityReadyIssuanceResidual::
RegisteredPreidentityReadyIssuanceResidual(
        RegisteredPreidentityReadyIssuanceResidual&& other) noexcept
    : storage_(std::move(other.storage_)) {}

RegisteredPreidentityReadyIssuanceResidual::
~RegisteredPreidentityReadyIssuanceResidual() = default;

RegisteredPreidentityActivationPair::RegisteredPreidentityActivationPair(
        std::unique_ptr<RegisteredPreidentityReadyStorage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }

RegisteredPreidentityActivationPair::RegisteredPreidentityActivationPair(
        RegisteredPreidentityActivationPair&& other) noexcept
    : storage_(std::move(other.storage_)) {}

RegisteredPreidentityActivationPair::~RegisteredPreidentityActivationPair() =
    default;

void RegisteredPreidentityActivationPair::validate_for_activation() const {
    try {
        need(storage_ != nullptr && storage_->topology.has_value() &&
             storage_->process.has_value() &&
             storage_->epoch_token != nullptr);
    } catch (...) { refuse(); }
}

FreshTrialCaptureTopologyReservation
RegisteredPreidentityActivationPair::take_topology() && noexcept {
    FreshTrialCaptureTopologyReservation result(
        std::move(*storage_->topology));
    storage_->topology.reset();
    return result;
}

RegisteredPersistentRoleProcessReservation
RegisteredPreidentityActivationPair::take_process() && noexcept {
    RegisteredPersistentRoleProcessReservation result(
        std::move(*storage_->process));
    storage_->process.reset();
    return result;
}

RegisteredPreidentityActivationPair
RegisteredPreidentityReadyIssuanceResidual::extract_for_activation() && {
    try {
        need(storage_ != nullptr && storage_->topology.has_value() &&
             storage_->process.has_value() &&
             storage_->epoch_token != nullptr);
        return RegisteredPreidentityActivationPair(std::move(storage_));
    } catch (...) { refuse(); }
}

RegisteredPreidentityReadyAuthority RegisteredPreidentityReadyBridge::join(
        FreshTrialCaptureTopologyReservation&& topology,
        RegisteredPersistentRoleProcessReservation&& process) {
    // Allocate the shell and validate both caller-owned reservations before
    // claiming either one.  A refusal therefore leaves both capabilities
    // available to their source-owned abort paths.  Optional emplacement then
    // performs only noexcept capability moves.
    auto storage = std::make_unique<RegisteredPreidentityReadyStorage>();
    try {
        topology.validate_for_activation();
        process.validate_for_preidentity_ready();
        const void* topology_epoch = topology.preidentity_epoch_token();
        const void* process_epoch = process.preidentity_epoch_token();
        need(topology_epoch != nullptr && process_epoch != nullptr &&
             topology_epoch == process_epoch);
        storage->epoch_token = process_epoch;
        storage->topology.emplace(std::move(topology));
        storage->process.emplace(std::move(process));
        return RegisteredPreidentityReadyAuthority(std::move(storage));
    } catch (...) { refuse(); }
}

RegisteredPreidentityReadyOwnerIssuanceSession
RegisteredPreidentityReadyIssuanceBridge::begin(
        RegisteredPreidentityReadyAuthority&& ready) {
    try {
        need(ready.storage_ != nullptr &&
             ready.storage_->topology.has_value() &&
             ready.storage_->process.has_value() &&
             ready.storage_->epoch_token != nullptr);
    } catch (...) { refuse(); }
    return RegisteredPreidentityReadyOwnerIssuanceSession(
        std::move(ready.storage_));
}

const void*
RegisteredPreidentityReadyIssuanceBridge::
validate_for_transactional_staging(
        const RegisteredPreidentityReadyAuthority& ready) {
    try {
        need(ready.storage_ != nullptr &&
             ready.storage_->topology.has_value() &&
             ready.storage_->process.has_value() &&
             ready.storage_->epoch_token != nullptr);
        return ready.storage_->epoch_token;
    } catch (...) { refuse(); }
}

RegisteredPreidentityReadyIssuanceResidual
RegisteredPreidentityReadyIssuanceBridge::
consume_for_transactional_issuance(
        RegisteredPreidentityReadyAuthority&& ready) noexcept {
    if (ready.storage_ == nullptr ||
        ready.storage_->epoch_token == nullptr)
        std::terminate();
    return RegisteredPreidentityReadyIssuanceResidual(
        std::move(ready.storage_));
}

RegisteredOwnerIssuancePermit
RegisteredPreidentityReadyIssuanceBridge::take_owner_permit(
        RegisteredPreidentityReadyOwnerIssuanceSession& session,
        unsigned owner) {
    try {
        need(session.storage_ != nullptr && owner < 3 &&
             session.storage_->epoch_token != nullptr &&
             !session.owner_permits_taken_[owner]);
        session.owner_permits_taken_[owner] = true;
        return RegisteredOwnerIssuancePermit(
            session.storage_->epoch_token, owner);
    } catch (...) { refuse(); }
}

RegisteredPreidentityReadyIssuanceResidual
RegisteredPreidentityReadyIssuanceBridge::finish(
        RegisteredPreidentityReadyOwnerIssuanceSession&& session) {
    try {
        need(session.storage_ != nullptr &&
             std::ranges::all_of(
                 session.owner_permits_taken_,
                 [](bool taken) { return taken; }));
        return RegisteredPreidentityReadyIssuanceResidual(
            std::move(session.storage_));
    } catch (...) { refuse(); }
}

void RegisteredPreidentityReadyIssuanceBridge::validate_owner_lineage(
        const RegisteredPreidentityReadyIssuanceResidual& residual,
        const fresh_owner_issuance::OwnerLocalIssuanceAuthority& owner0,
        const fresh_owner_issuance::OwnerLocalIssuanceAuthority& owner1,
        const fresh_owner_issuance::OwnerLocalIssuanceAuthority& owner2) {
    try {
        need(residual.storage_ != nullptr &&
             residual.storage_->epoch_token != nullptr);
        const std::array<const fresh_owner_issuance::
                             OwnerLocalIssuanceAuthority*, 3> owners{
            &owner0, &owner1, &owner2};
        for (unsigned owner = 0; owner < owners.size(); ++owner) {
            const auto& authority = *owners[owner];
            need(authority.live_.load() &&
                 authority.preidentity_permit_.has_value());
            const auto& permit = *authority.preidentity_permit_;
            need(permit.live_ && permit.owner_ == owner &&
                 permit.epoch_token_ == residual.storage_->epoch_token);
        }
    } catch (...) { refuse(); }
}

} // namespace kpi::mpc::financial::registered_driver
