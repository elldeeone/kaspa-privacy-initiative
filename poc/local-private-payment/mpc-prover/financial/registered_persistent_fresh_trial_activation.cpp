#include "registered_parent_role_fork.hpp"

#include "fresh_owner_trial_issuance.hpp"
#include "registered_selected_producer_run_binding.hpp"
#include "../../private_batch_trial/privacy_registered_fresh_trial_capture_topology_reservation.hpp"

#include <array>
#include <cerrno>
#include <fcntl.h>
#include <optional>
#include <span>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::registered_driver {

namespace {

using kpb::measurement::Digest;

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) { return value != Digest{}; }

void add(std::vector<unsigned char>& output, const Digest& value) {
    output.insert(output.end(), value.begin(), value.end());
}
void add(std::vector<unsigned char>& output, std::string_view value) {
    output.insert(output.end(), value.begin(), value.end());
}
void add(std::vector<unsigned char>& output, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        output.push_back(static_cast<unsigned char>(value >> shift));
}
Digest process_reservation_identity(
        const Digest& topology_reservation,
        const Digest& issuance_identity,
        const std::array<std::int64_t, 3>& child_pids) {
    std::vector<unsigned char> bytes;
    add(bytes, "KPB_REGISTERED_PRELAUNCH_PROCESS_RESERVATION_V1\n");
    add(bytes, topology_reservation);
    add(bytes, issuance_identity);
    for (const auto pid : child_pids)
        add(bytes, static_cast<std::uint64_t>(pid));
    const auto result = identity_registry::digest(
        std::span<const unsigned char>(bytes));
    need(nonzero(result));
    return result;
}
Digest process_session_identity(
        const Digest& reservation_identity,
        const std::array<std::array<Digest, 3>, 2>& commands) {
    std::vector<unsigned char> bytes;
    add(bytes, "KPB_REGISTERED_PRELAUNCH_PROCESS_SESSION_V1\n");
    add(bytes, reservation_identity);
    for (const auto& round : commands)
        for (const auto& command : round) add(bytes, command);
    const auto result = identity_registry::digest(
        std::span<const unsigned char>(bytes));
    need(nonzero(result) && result != reservation_identity);
    return result;
}

void close_once(int& fd) noexcept {
    const int selected = std::exchange(fd, -1);
    if (selected >= 0) (void)::close(selected);
}

struct SocketFingerprint final {
    std::uint64_t device{};
    std::uint64_t inode{};
    std::uint32_t type{};
};

SocketFingerprint socket_fingerprint(int fd) {
    struct stat state{};
    int type = 0;
    socklen_t type_bytes = sizeof(type);
    int pass_credentials = 0;
    socklen_t pass_bytes = sizeof(pass_credentials);
    const int flags = ::fcntl(fd, F_GETFD);
    need(fd >= 0 && ::fstat(fd, &state) == 0 &&
         (state.st_mode & S_IFMT) == S_IFSOCK && flags >= 0 &&
         (flags & FD_CLOEXEC) != 0 &&
         ::getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_bytes) == 0 &&
         type_bytes == sizeof(type) && type == SOCK_SEQPACKET &&
         ::getsockopt(fd, SOL_SOCKET, SO_PASSCRED, &pass_credentials,
                      &pass_bytes) == 0 &&
         pass_bytes == sizeof(pass_credentials) && pass_credentials == 1);
    return {
        static_cast<std::uint64_t>(state.st_dev),
        static_cast<std::uint64_t>(state.st_ino),
        static_cast<std::uint32_t>(state.st_mode & S_IFMT),
    };
}

std::array<int, 2> state_terminal_channel() {
    std::array<int, 2> result{{-1, -1}};
    need(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0,
                      result.data()) == 0);
    try {
        const int enabled = 1;
        for (const int fd : result)
            need(::setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &enabled,
                              sizeof(enabled)) == 0);
        (void)socket_fingerprint(result[0]);
        (void)socket_fingerprint(result[1]);
        return result;
    } catch (...) {
        close_once(result[0]);
        close_once(result[1]);
        throw;
    }
}

} // namespace

#ifdef KPI_REGISTERED_PERSISTENT_FRESH_ACTIVATION_TEST_SETUP
namespace {
void (*post_storage_test_hook)() = nullptr;
void (*process_test_hook)(RegisteredPersistentRoleProcessReservation&) =
    nullptr;
void (*post_settle_test_hook)() = nullptr;
}

void RegisteredPersistentFreshTrialActivationBridge::
test_only_set_post_storage_hook(void (*hook)()) {
    post_storage_test_hook = hook;
}

void RegisteredPersistentFreshTrialActivationBridge::
test_only_set_process_hook(
        void (*hook)(RegisteredPersistentRoleProcessReservation&)) {
    process_test_hook = hook;
}

void RegisteredPersistentFreshTrialActivationBridge::
test_only_set_post_settle_hook(void (*hook)()) {
    post_settle_test_hook = hook;
}

#endif

struct RegisteredPersistentWriterlessRoundPlanAuthority::Storage final {};

RegisteredPersistentWriterlessRoundPlanAuthority::
RegisteredPersistentWriterlessRoundPlanAuthority(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {}
RegisteredPersistentWriterlessRoundPlanAuthority::
RegisteredPersistentWriterlessRoundPlanAuthority(
        RegisteredPersistentWriterlessRoundPlanAuthority&&) noexcept =
    default;
RegisteredPersistentWriterlessRoundPlanAuthority::
~RegisteredPersistentWriterlessRoundPlanAuthority() = default;

struct RegisteredPersistentTopologyActivationAuthority::Storage final {
    std::optional<fresh_owner_issuance::
        FreshOwnerPersistentActivationAuthority> issuance_lineage;
    std::optional<RegisteredPersistentRoleProcessReservation> process;
    std::optional<FreshTrialCaptureTopologyActivationTransfer> topology;
    std::array<int, 2> parent_terminal_fds{{-1, -1}};
    std::array<std::uint64_t, 2> parent_terminal_devices{};
    std::array<std::uint64_t, 2> parent_terminal_inodes{};
    std::array<std::uint32_t, 2> parent_terminal_types{};
    std::array<std::int64_t, 2> role1_child_pids{{-1, -1}};
    std::array<std::array<Digest, 3>, 2> command_identities{};
    std::array<std::array<bool, 3>, 2> command_acknowledged{};
    std::array<bool, 3> retention_acknowledged{};
    std::array<std::uint64_t, 2> state_devices{};
    std::array<std::uint64_t, 2> state_inodes{};
    CaptureClassification classification{};
    Digest trial_identity{};
    Digest fresh_owner_issuance_identity{};
    Digest topology_reservation_identity{};
    Digest process_reservation_identity{};
    Digest process_session_identity{};
    bool live{true};
    ~Storage() {
        for (auto& fd : parent_terminal_fds) close_once(fd);
    }
};

RegisteredPersistentTopologyActivationAuthority::
RegisteredPersistentTopologyActivationAuthority(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {}
RegisteredPersistentTopologyActivationAuthority::
RegisteredPersistentTopologyActivationAuthority(
        RegisteredPersistentTopologyActivationAuthority&&) noexcept =
    default;
RegisteredPersistentTopologyActivationAuthority::
~RegisteredPersistentTopologyActivationAuthority() = default;

void RegisteredPersistentTopologyActivationAuthority::
bind_selected_prelaunch_plan(
        RegisteredSelectedProducerPrelaunchPlan& plan) const {
    try {
        need(storage_ != nullptr && storage_->live &&
             storage_->issuance_lineage.has_value() &&
             storage_->process.has_value() && storage_->topology.has_value() &&
             nonzero(storage_->trial_identity) &&
             nonzero(storage_->fresh_owner_issuance_identity) &&
             nonzero(storage_->topology_reservation_identity) &&
             nonzero(storage_->process_reservation_identity) &&
             nonzero(storage_->process_session_identity));
        const auto selected_classification =
            storage_->classification == CaptureClassification::HiddenCandidate
                ? kpb::measurement::Classification::HiddenCandidate
                : storage_->classification == CaptureClassification::
                      ExplicitOwnerPublicEffectsBaseline
                    ? kpb::measurement::Classification::TransparentBaseline
                    : throw identity_registry::Refused();
        need(RegisteredCapturePlanRosterBridge::trial_identity(
                 plan.capture_trial_id) == storage_->trial_identity);
        plan.classification = selected_classification;
        plan.trial = storage_->trial_identity;
        plan.process_reservation_identity =
            storage_->process_reservation_identity;
        plan.persistent_process_session_identity =
            storage_->process_session_identity;
    } catch (...) { refuse(); }
}

#ifdef KPI_REGISTERED_PERSISTENT_FRESH_ACTIVATION_TEST_SETUP
RegisteredPersistentTopologyActivationAuthority::TestSummary
RegisteredPersistentTopologyActivationAuthority::test_only_summary() const {
    need(storage_ != nullptr && storage_->live);
    return {
        .process_reservation_retained = storage_->process.has_value(),
        .issuance_lineage_retained =
            storage_->issuance_lineage.has_value(),
        .topology_transfer_retained = storage_->topology.has_value(),
        .command_acknowledged = storage_->command_acknowledged,
        .retention_acknowledged = storage_->retention_acknowledged,
        .parent_terminal_endpoints_retained = {
            storage_->parent_terminal_fds[0] >= 0,
            storage_->parent_terminal_fds[1] >= 0},
        .state_devices = storage_->state_devices,
        .state_inodes = storage_->state_inodes,
        .role1_activation_identities = {
            storage_->command_identities[0][1],
            storage_->command_identities[1][1]},
    };
}

#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
void RegisteredPersistentFreshTrialActivationBridge::
test_only_close_pending_reservation_channel(
        RegisteredPersistentTopologyActivationAuthority& activation,
        unsigned round, unsigned role) {
    need(activation.storage_ != nullptr && activation.storage_->live &&
         activation.storage_->process.has_value());
    ParentRoleForkTestProcessBridge::close_reservation_channel(
        *activation.storage_->process, round, role);
}
#endif
#endif

struct RegisteredPersistentRoleActivationFailureResidual::Storage final {
    std::optional<detail::PersistentRoleReservationAbortEvidence>
        process_abort;
    std::optional<fresh_owner_issuance::
        FreshOwnerPersistentActivationAuthority> activation;
    std::optional<RegisteredPreidentityActivationPair> preidentity_pair;
    std::optional<RegisteredPersistentRoleProcessReservation>
        process_reservation;
    std::optional<FreshTrialCaptureTopologyReservation>
        topology_reservation;
    std::optional<FreshTrialCaptureTopologyActivationTransfer>
        topology_transfer;
    std::optional<FreshTrialCaptureTopologyQuarantineResidual>
        topology_quarantine;
    std::array<int, 2> untransferred_state_writers{{-1, -1}};
    std::array<int, 2> untransferred_state_terminals{{-1, -1}};
    std::array<int, 2> parent_terminal_fds{{-1, -1}};
    std::array<std::array<Digest, 3>, 2> command_identities{};
    ~Storage() {
        for (auto& fd : untransferred_state_writers) close_once(fd);
        for (auto& fd : untransferred_state_terminals) close_once(fd);
        for (auto& fd : parent_terminal_fds) close_once(fd);
    }
};

RegisteredPersistentRoleActivationFailureResidual::
RegisteredPersistentRoleActivationFailureResidual(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) {}
RegisteredPersistentRoleActivationFailureResidual::
RegisteredPersistentRoleActivationFailureResidual(
        RegisteredPersistentRoleActivationFailureResidual&&) noexcept =
    default;
RegisteredPersistentRoleActivationFailureResidual::
~RegisteredPersistentRoleActivationFailureResidual() = default;

RegisteredPersistentRoleActivationFailureResidual
RegisteredPersistentRoleActivationFailureResidual::
transfer_for_all_branch_stop() && {
    auto storage = std::move(storage_);
    if (storage == nullptr) throw identity_registry::Refused();
    return RegisteredPersistentRoleActivationFailureResidual(
        std::move(storage));
}

RegisteredPersistentRoleActivationResult::
RegisteredPersistentRoleActivationResult(
        std::unique_ptr<
            RegisteredPersistentRoleActivationFailureResidual::Storage>
            failure)
    : failure_(std::move(failure)) {}
RegisteredPersistentRoleActivationResult::
RegisteredPersistentRoleActivationResult(
        std::unique_ptr<RegisteredPersistentTopologyActivationAuthority>
            topology_activation) noexcept
    : topology_activation_(std::move(topology_activation)) {}
RegisteredPersistentRoleActivationResult::
RegisteredPersistentRoleActivationResult(
        RegisteredPersistentRoleActivationResult&&) noexcept = default;
RegisteredPersistentRoleActivationResult::
~RegisteredPersistentRoleActivationResult() = default;

RegisteredPersistentRoleActivationFailureResidual
RegisteredPersistentRoleActivationResult::take_failure_residual() && {
    if (failure_ == nullptr) throw identity_registry::Refused();
    return RegisteredPersistentRoleActivationFailureResidual(
        std::move(failure_));
}

RegisteredPersistentTopologyActivationAuthority
RegisteredPersistentRoleActivationResult::take_topology_activation() && {
    if (topology_activation_ == nullptr)
        throw identity_registry::Refused();
    RegisteredPersistentTopologyActivationAuthority result(
        std::move(*topology_activation_));
    topology_activation_.reset();
    return result;
}

#ifdef KPI_REGISTERED_PERSISTENT_FRESH_ACTIVATION_TEST_SETUP
RegisteredPersistentRoleActivationFailureResidual::TestSummary
RegisteredPersistentRoleActivationFailureResidual::test_only_summary()
        const {
    if (storage_ == nullptr) throw identity_registry::Refused();
    TestSummary result{
        .process_abort_retained = storage_->process_abort.has_value(),
        .activation_authority_retained =
            storage_->activation.has_value(),
        .round1_plan_retained = false,
        .topology_reservation_retained =
            storage_->topology_reservation.has_value(),
        .topology_quarantine_retained =
            storage_->topology_quarantine.has_value(),
        .parent_terminal_endpoints_retained = {
            storage_->parent_terminal_fds[0] >= 0,
            storage_->parent_terminal_fds[1] >= 0},
    };
    if (storage_->topology_quarantine.has_value()) {
        const auto topology =
            storage_->topology_quarantine->test_only_summary();
        result.read_ends_retained = topology.read_ends_retained;
        result.writer_aliases_retained = topology.writer_aliases_retained;
        result.archives_retained = topology.archives_retained;
        result.p1_state_parent_reads_retained =
            topology.p1_state_parent_reads_retained;
        result.p1_state_writers_retained =
            topology.p1_state_writers_retained;
        result.p1_state_devices = topology.p1_state_devices;
        result.p1_state_inodes = topology.p1_state_inodes;
    } else if (storage_->topology_reservation.has_value()) {
        try {
            const auto topology =
                storage_->topology_reservation->test_only_summary();
            result.read_ends_retained = topology.read_ends_valid;
            result.writer_aliases_retained = topology.writer_aliases_valid;
            result.archives_retained = topology.archives_valid;
            result.p1_state_parent_reads_retained =
                topology.p1_state_parent_reads_valid;
            result.p1_state_writers_retained =
                topology.p1_state_writer_aliases_valid;
            result.p1_state_devices = topology.p1_state_devices;
            result.p1_state_inodes = topology.p1_state_inodes;
        } catch (...) {
            // Invalid reservations are intentionally retained rather than
            // reinterpreted as a valid topology test summary.
        }
    }
    return result;
}

detail::PersistentRoleReservationAbortEvidence
RegisteredPersistentRoleActivationFailureResidual::
test_only_take_process_abort_evidence() {
    if (storage_ == nullptr || !storage_->process_abort.has_value())
        throw identity_registry::Refused();
    detail::PersistentRoleReservationAbortEvidence result(
        std::move(*storage_->process_abort));
    storage_->process_abort.reset();
    return result;
}
#endif

RegisteredPersistentRoleActivationResult
RegisteredPersistentFreshTrialActivationBridge::activate(
        fresh_owner_issuance::FreshOwnerPersistentActivationAuthority&&
            activation) {
    // Allocate the opaque failure owner before consuming any linear input or
    // settling any process.  The phase-2 success owner and its wrapper are
    // also allocated now: after the first authenticated writer ACK, every
    // remaining operation is a no-throw capability move or pidfd settlement.
    auto failure = std::make_unique<
        RegisteredPersistentRoleActivationFailureResidual::Storage>();
    auto topology_storage = std::make_unique<
        RegisteredPersistentTopologyActivationAuthority::Storage>();
    auto topology_activation =
        std::unique_ptr<RegisteredPersistentTopologyActivationAuthority>(
            new RegisteredPersistentTopologyActivationAuthority(
                std::move(topology_storage)));
#ifdef KPI_REGISTERED_PERSISTENT_FRESH_ACTIVATION_TEST_SETUP
    if (post_storage_test_hook != nullptr) post_storage_test_hook();
#endif
    failure->activation.emplace(std::move(activation));

    RegisteredPersistentRoleProcessReservation::TopologyPreflightState
        preflight;
    bool prepared = false;

    try {
        auto& claimed_activation = *failure->activation;
        if (!claimed_activation.live_.exchange(false) ||
            claimed_activation.receipt_ == nullptr)
            throw identity_registry::Refused();
        const auto issuance = claimed_activation.receipt_;
        failure->preidentity_pair.emplace(
            std::move(claimed_activation.ready_)
                .extract_for_activation());
        failure->preidentity_pair->validate_for_activation();
        failure->topology_reservation.emplace(
            std::move(*failure->preidentity_pair).take_topology());
        failure->process_reservation.emplace(
            std::move(*failure->preidentity_pair).take_process());
        failure->preidentity_pair.reset();

        failure->topology_reservation->validate_for_activation();
        failure->process_reservation->validate_for_preidentity_ready();
#ifdef KPI_REGISTERED_PERSISTENT_FRESH_ACTIVATION_TEST_SETUP
        if (process_test_hook != nullptr)
            process_test_hook(*failure->process_reservation);
#endif
        need((issuance->classification ==
                  CaptureClassification::HiddenCandidate ||
              issuance->classification == CaptureClassification::
                  ExplicitOwnerPublicEffectsBaseline) &&
             nonzero(issuance->trial) &&
             nonzero(issuance->issuance_identity));
        failure->topology_transfer.emplace(
            std::move(*failure->topology_reservation)
                .consume_for_activation());
        failure->topology_reservation.reset();

        auto& topology = *failure->topology_transfer;
        preflight.reservation_identity = topology.reservation_identity_;
        preflight.activation_identity = issuance->issuance_identity;
        preflight.trial_identity = issuance->trial;
        preflight.state_devices = topology.p1_state_devices_;
        preflight.state_inodes = topology.p1_state_inodes_;
        preflight.state_modes = topology.p1_state_modes_;
        preflight.state_nlinks = topology.p1_state_nlinks_;
        preflight.state_sizes = topology.p1_state_sizes_;
        for (unsigned round = 0; round < 2; ++round) {
            preflight.child_state_writers[round] = std::exchange(
                topology.p1_state_child_writer_aliases_[round], -1);
            auto terminal = state_terminal_channel();
            const auto parent_terminal = socket_fingerprint(terminal[0]);
            const auto child_terminal = socket_fingerprint(terminal[1]);
            failure->parent_terminal_fds[round] =
                std::exchange(terminal[0], -1);
            preflight.child_terminal_fds[round] =
                std::exchange(terminal[1], -1);
            preflight.terminal_devices[round] = child_terminal.device;
            preflight.terminal_inodes[round] = child_terminal.inode;
            preflight.terminal_types[round] = child_terminal.type;
            topology_activation->storage_->
                parent_terminal_devices[round] = parent_terminal.device;
            topology_activation->storage_->
                parent_terminal_inodes[round] = parent_terminal.inode;
            topology_activation->storage_->
                parent_terminal_types[round] = parent_terminal.type;
        }
        failure->process_reservation->preflight_capture_topology(
            topology.writer_aliases_, topology.endpoint_devices_,
            topology.endpoint_inodes_, topology.endpoint_types_,
            preflight);

        for (unsigned round = 0; round < 2; ++round)
            for (unsigned role = 0; role < 3; ++role)
                need(nonzero(preflight.command_identities[round][role]));
        for (const bool retained : preflight.retention_acknowledged)
            need(retained);

        auto* const retained = topology_activation->storage_.get();
        const std::array<std::int64_t, 3> child_pids{{
            failure->process_reservation->child_pid_for_activation(0),
            failure->process_reservation->child_pid_for_activation(1),
            failure->process_reservation->child_pid_for_activation(2),
        }};
        const auto selected_process_reservation =
            process_reservation_identity(
                topology.reservation_identity_, issuance->issuance_identity,
                child_pids);
        const auto selected_process_session = process_session_identity(
            selected_process_reservation, preflight.command_identities);
        retained->classification = issuance->classification;
        retained->trial_identity = issuance->trial;
        retained->fresh_owner_issuance_identity =
            issuance->issuance_identity;
        retained->topology_reservation_identity =
            topology.reservation_identity_;
        retained->process_reservation_identity =
            selected_process_reservation;
        retained->process_session_identity = selected_process_session;
        retained->issuance_lineage.emplace(
            std::move(*failure->activation));
        failure->activation.reset();
        retained->process.emplace(
            std::move(*failure->process_reservation));
        failure->process_reservation.reset();
        retained->topology.emplace(
            std::move(*failure->topology_transfer));
        failure->topology_transfer.reset();
        retained->command_identities = preflight.command_identities;
        for (auto& round : retained->command_acknowledged)
            round.fill(true);
        retained->retention_acknowledged =
            preflight.retention_acknowledged;
        retained->state_devices = preflight.state_devices;
        retained->state_inodes = preflight.state_inodes;
        for (unsigned round = 0; round < 2; ++round) {
            retained->parent_terminal_fds[round] = std::exchange(
                failure->parent_terminal_fds[round], -1);
            retained->role1_child_pids[round] =
                retained->process->child_pid_for_activation(1);
        }
        prepared = true;
    } catch (...) {
        // Every claimed object remains inside the preallocated failure owner.
    }

    if (prepared)
        return RegisteredPersistentRoleActivationResult(
            std::move(topology_activation));

    for (unsigned round = 0; round < 2; ++round) {
        failure->untransferred_state_writers[round] = std::exchange(
            preflight.child_state_writers[round], -1);
        failure->untransferred_state_terminals[round] = std::exchange(
            preflight.child_terminal_fds[round], -1);
    }
    failure->command_identities = preflight.command_identities;

    if (failure->topology_transfer.has_value()) {
        try {
            failure->topology_quarantine.emplace(
                std::move(*failure->topology_transfer)
                    .quarantine_after_activation_failure());
            failure->topology_transfer.reset();
        } catch (...) {
            // The opaque transfer itself still owns every descriptor if its
            // internal live-state invariant is unexpectedly unavailable.
        }
    }

    if (failure->process_reservation.has_value()) {
        auto abort = RegisteredParentPersistentRoleFork::abort(
            std::move(*failure->process_reservation));
        failure->process_reservation.reset();
        failure->process_abort.emplace(std::move(abort));
#ifdef KPI_REGISTERED_PERSISTENT_FRESH_ACTIVATION_TEST_SETUP
        if (post_settle_test_hook != nullptr) post_settle_test_hook();
#endif
    }
    return RegisteredPersistentRoleActivationResult(std::move(failure));
}

RegisteredPersistentRoleActivationFailureResidual
RegisteredPersistentFreshTrialActivationBridge::abort_topology(
        RegisteredPersistentTopologyActivationAuthority&& selected) {
    // The failure shell is allocated while the caller still owns the live
    // topology activation.  Once selected.storage_ is moved, every transfer,
    // quarantine and pidfd settlement below is allocation-free.
    auto failure = std::make_unique<
        RegisteredPersistentRoleActivationFailureResidual::Storage>();
    auto storage = std::move(selected.storage_);
    need(storage != nullptr && storage->live &&
         storage->issuance_lineage.has_value() &&
         storage->process.has_value() && storage->topology.has_value());
    storage->live = false;

    failure->activation.emplace(
        std::move(*storage->issuance_lineage));
    storage->issuance_lineage.reset();
    failure->process_reservation.emplace(std::move(*storage->process));
    storage->process.reset();
    failure->topology_transfer.emplace(std::move(*storage->topology));
    storage->topology.reset();
    failure->command_identities = storage->command_identities;
    for (unsigned round = 0; round < 2; ++round)
        failure->parent_terminal_fds[round] = std::exchange(
            storage->parent_terminal_fds[round], -1);

    failure->topology_quarantine.emplace(
        std::move(*failure->topology_transfer)
            .quarantine_after_activation_failure());
    failure->topology_transfer.reset();
    auto abort = RegisteredParentPersistentRoleFork::abort(
        std::move(*failure->process_reservation));
    failure->process_reservation.reset();
    failure->process_abort.emplace(std::move(abort));
#ifdef KPI_REGISTERED_PERSISTENT_FRESH_ACTIVATION_TEST_SETUP
    if (post_settle_test_hook != nullptr) post_settle_test_hook();
#endif
    return RegisteredPersistentRoleActivationFailureResidual(
        std::move(failure));
}

} // namespace kpi::mpc::financial::registered_driver
