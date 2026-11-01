#include "privacy_registered_fresh_trial_producer_closure.hpp"

#include "privacy_capture_producer_archive.hpp"
#include "privacy_measurement_run_binding_wire.hpp"
#include "privacy_registered_fresh_trial_capture_topology_reservation.hpp"

#include <algorithm>
#include <array>
#include <fcntl.h>
#include <set>
#include <span>
#include <string_view>
#include <sys/stat.h>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::registered_driver {
namespace {

using Digest = identity_registry::Digest;
namespace producer_runtime = kpb::measurement::producer_runtime;
namespace producer_archive = kpb::measurement::producer_archive;
#ifdef KPI_REGISTERED_FRESH_TRIAL_PRODUCER_CLOSURE_TEST_SETUP
using Bytes = std::vector<unsigned char>;
namespace wire = kpb::measurement::wire;

constexpr std::array<unsigned, 2> CORRUPT_SERVER_SOURCE_SLOTS{3, 8};
constexpr std::array<unsigned, 2> CORRUPT_SERVER_FIXED_FDS{23, 28};
#endif

[[noreturn]] void refuse() { throw kpb::measurement::Refused(); }
void need(bool value) { if (!value) refuse(); }

#ifdef KPI_REGISTERED_FRESH_TRIAL_PRODUCER_CLOSURE_TEST_SETUP
bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add(Bytes& out, const Digest& value) { add(out, std::span(value)); }
void add(Bytes& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add_u64(Bytes& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}
void add_string(Bytes& out, std::string_view value) {
    add_u64(out, value.size());
    add(out, value);
}

void require_fresh_trial_matches(
        const fresh_owner_issuance::PublicFreshOwnerTrialIssuanceReceipt&
            fresh,
        const producer_runtime::PublicProducerLaunchPlan& plan) {
    kpb::measurement::validate_measurement_run_binding(plan.binding);
    const bool hidden =
        fresh.classification == CaptureClassification::HiddenCandidate &&
        plan.binding.classification ==
            kpb::measurement::Classification::HiddenCandidate &&
        plan.construction_policy ==
            kpb::measurement::ConstructionPolicy::
                SecretPermutationIndependent;
    const bool baseline =
        fresh.classification ==
            CaptureClassification::ExplicitOwnerPublicEffectsBaseline &&
        plan.binding.classification ==
            kpb::measurement::Classification::TransparentBaseline &&
        plan.construction_policy ==
            kpb::measurement::ConstructionPolicy::
                ExplicitOwnerPublicEffects;
    need((hidden || baseline) && fresh.trial == plan.binding.trial &&
         nonzero(fresh.issuance_identity));
    for (unsigned round = 0; round < 2; ++round) {
        const auto& selected = fresh.owners[0].rounds[round];
        need(selected.round == round + 1 &&
             selected.attempt == plan.binding.round_attempts[round] &&
             selected.cohort == plan.binding.round_cohorts[round]);
        for (unsigned owner = 0; owner < fresh.owners.size(); ++owner) {
            const auto& candidate = fresh.owners[owner];
            need(candidate.owner_component == owner &&
                 nonzero(candidate.issuance_identity) &&
                 candidate.rounds[round].round == round + 1 &&
                 candidate.rounds[round].attempt == selected.attempt &&
                 candidate.rounds[round].cohort == selected.cohort);
        }
    }
    for (unsigned round = 0; round < CORRUPT_SERVER_SOURCE_SLOTS.size();
         ++round) {
        const auto slot = CORRUPT_SERVER_SOURCE_SLOTS[round];
        const auto& stream = plan.streams[slot];
        need(stream.round == round + 1 &&
             stream.kind == kpb::measurement::CaptureKind::CorruptServer &&
             stream.fixed_fd == CORRUPT_SERVER_FIXED_FDS[round]);
    }
}

void require_exact_topology(
        const std::array<int, 10>& read_ends,
        const std::array<std::uint64_t, 10>& devices,
        const std::array<std::uint64_t, 10>& inodes,
        const std::array<std::uint32_t, 10>& file_types) {
    std::set<std::pair<std::uint64_t, std::uint64_t>> identities;
    for (unsigned index = 0; index < read_ends.size(); ++index) {
        struct stat value{};
        const int fd = read_ends[index];
        const int flags = fd >= 0 ? ::fcntl(fd, F_GETFL) : -1;
        need(fd >= 0 && flags >= 0 &&
             (flags & O_ACCMODE) == O_RDONLY &&
             ::fstat(fd, &value) == 0);
        const auto device = static_cast<std::uint64_t>(value.st_dev);
        const auto inode = static_cast<std::uint64_t>(value.st_ino);
        const auto type = static_cast<std::uint32_t>(value.st_mode & S_IFMT);
        need((type == S_IFIFO || type == S_IFSOCK) &&
             device == devices[index] &&
             inode == inodes[index] &&
             type == file_types[index] &&
             identities.emplace(device, inode).second);
    }
}

Digest closure_identity(
        const fresh_owner_issuance::PublicFreshOwnerTrialIssuanceReceipt&
            fresh,
        const producer_runtime::PublicProducerLaunchPlan& plan,
        const std::array<std::uint64_t, 10>& devices,
        const std::array<std::uint64_t, 10>& inodes,
        const std::array<std::uint32_t, 10>& file_types) {
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_FRESH_TRIAL_PRODUCER_CLOSURE_V1\n");
    const auto binding = wire::canonical_run_binding_bytes(plan.binding);
    add_u64(bytes, binding.size());
    add(bytes, binding);

    bytes.push_back(static_cast<unsigned char>(fresh.classification));
    for (const auto* field : {
             &fresh.authority_identity, &fresh.registration_identity,
             &fresh.service_identity, &fresh.controller_source_identity,
             &fresh.controller_build_identity,
             &fresh.owner_issuer_source_identity,
             &fresh.owner_issuer_build_identity, &fresh.run, &fresh.trial,
             &fresh.root_identity, &fresh.baseline_policy_identity,
             &fresh.roster_authority_identity,
             &fresh.replay_policy_identity, &fresh.issuance_identity})
        add(bytes, *field);
    for (const auto& owner : fresh.owners)
        add(bytes, owner.issuance_identity);

    add_string(bytes, plan.capture_trial_id);
    for (const auto& attempt : plan.capture_attempt_ids)
        add_string(bytes, attempt);
    for (const auto* field : {
             &plan.producer_process_identity, &plan.role_closure_identity,
             &plan.manifest_seal,
             &plan.construction_classification_receipt})
        add(bytes, *field);
    bytes.push_back(static_cast<unsigned char>(plan.construction_policy));
    for (const auto& route : plan.route_requirements) {
        add_u64(bytes, route.round);
        add(bytes, route.projection_identity);
        add_u64(bytes, route.projection_bytes);
        add_u64(bytes, route.route_endpoint_count);
        add_u64(bytes, route.owner_ack_count);
        bytes.push_back(route.role_blind_required ? 1 : 0);
        bytes.push_back(route.after_full_cohort_barrier_required ? 1 : 0);
        bytes.push_back(
            route.owner_socket_or_path_derivation_forbidden ? 1 : 0);
    }
    for (unsigned index = 0; index < plan.streams.size(); ++index) {
        const auto& stream = plan.streams[index];
        add_u64(bytes, index);
        add_u64(bytes, stream.round);
        bytes.push_back(static_cast<unsigned char>(stream.kind));
        add_u64(bytes, stream.fixed_fd);
        add(bytes, stream.process_identity);
        add(bytes, stream.child_exit_identity);
        add_u64(bytes, devices[index]);
        add_u64(bytes, inodes[index]);
        add_u64(bytes, file_types[index]);
    }
    for (const auto slot : CORRUPT_SERVER_SOURCE_SLOTS) add_u64(bytes, slot);
    for (const auto fd : CORRUPT_SERVER_FIXED_FDS) add_u64(bytes, fd);
    const auto result = identity_registry::digest(bytes);
    need(nonzero(result));
    return result;
}

Digest reserved_closure_identity(
        const fresh_owner_issuance::PublicFreshOwnerTrialIssuanceReceipt&
            fresh,
        const producer_runtime::PublicProducerLaunchPlan& plan,
        const std::array<std::uint64_t, 10>& endpoint_devices,
        const std::array<std::uint64_t, 10>& endpoint_inodes,
        const std::array<std::uint32_t, 10>& endpoint_types,
        const Digest& reservation_identity,
        const std::array<std::uint64_t, 10>& archive_devices,
        const std::array<std::uint64_t, 10>& archive_inodes,
        const std::array<std::uint32_t, 10>& archive_modes,
        const std::array<std::uint64_t, 10>& archive_nlinks,
        const std::array<std::uint64_t, 10>& archive_sizes) {
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_FRESH_TRIAL_PRODUCER_CLOSURE_V2\n");
    // The v1 commitment already binds the complete RunBinding, fresh-owner
    // lineage, plan, ten stream schedule, and sole-reader fingerprints.
    add(bytes, closure_identity(
        fresh, plan, endpoint_devices, endpoint_inodes, endpoint_types));
    add(bytes, reservation_identity);
    for (unsigned slot = 0; slot < archive_devices.size(); ++slot) {
        add_u64(bytes, slot);
        add_u64(bytes, archive_devices[slot]);
        add_u64(bytes, archive_inodes[slot]);
        add_u64(bytes, archive_modes[slot]);
        add_u64(bytes, archive_nlinks[slot]);
        add_u64(bytes, archive_sizes[slot]);
    }
    const auto result = identity_registry::digest(bytes);
    need(nonzero(result));
    return result;
}
#endif

} // namespace

struct RegisteredFreshTrialProducerClosureAuthority::Storage {
    producer_runtime::ParentTenReadEndsAuthority topology;
    std::unique_ptr<producer_archive::ProducerSealedArchiveBuilder>
        preidentity_archive_builder;
    Digest closure_identity{};
    Digest reservation_identity{};
    kpb::measurement::RunBinding binding;
    std::string capture_trial_id;
    std::array<std::string, 2> capture_attempt_ids;
    std::array<std::uint64_t, 10> devices{};
    std::array<std::uint64_t, 10> inodes{};
    std::array<std::uint32_t, 10> file_types{};
    std::array<std::uint64_t, 10> archive_devices{};
    std::array<std::uint64_t, 10> archive_inodes{};
    Storage(producer_runtime::ParentTenReadEndsAuthority&& value,
            std::unique_ptr<producer_archive::ProducerSealedArchiveBuilder>
                archive_builder,
            Digest identity, kpb::measurement::RunBinding selected_binding,
            std::string trial, std::array<std::string, 2> attempts,
            std::array<std::uint64_t, 10> selected_devices,
            std::array<std::uint64_t, 10> selected_inodes,
            std::array<std::uint32_t, 10> selected_file_types,
            Digest selected_reservation_identity = {},
            std::array<std::uint64_t, 10> selected_archive_devices = {},
            std::array<std::uint64_t, 10> selected_archive_inodes = {})
        : topology(std::move(value)),
          preidentity_archive_builder(std::move(archive_builder)),
          closure_identity(identity),
          reservation_identity(selected_reservation_identity),
          binding(std::move(selected_binding)),
          capture_trial_id(std::move(trial)),
          capture_attempt_ids(std::move(attempts)),
          devices(selected_devices), inodes(selected_inodes),
          file_types(selected_file_types),
          archive_devices(selected_archive_devices),
          archive_inodes(selected_archive_inodes) {}
};

RegisteredFreshTrialProducerClosureAuthority::
RegisteredFreshTrialProducerClosureAuthority(std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }

RegisteredFreshTrialProducerClosureAuthority::
RegisteredFreshTrialProducerClosureAuthority(
        RegisteredFreshTrialProducerClosureAuthority&& other) noexcept
    : storage_(std::move(other.storage_)) {}

RegisteredFreshTrialProducerClosureAuthority::
~RegisteredFreshTrialProducerClosureAuthority() = default;

#ifdef KPI_REGISTERED_FRESH_TRIAL_PRODUCER_CLOSURE_TEST_SETUP
RegisteredFreshTrialProducerClosureAuthority::TestSummary
RegisteredFreshTrialProducerClosureAuthority::test_only_summary() const {
    need(storage_ != nullptr);
    return TestSummary{
        .closure_identity = storage_->closure_identity,
        .binding = storage_->binding,
        .capture_trial_id = storage_->capture_trial_id,
        .capture_attempt_ids = storage_->capture_attempt_ids,
        .corrupt_server_source_slots = CORRUPT_SERVER_SOURCE_SLOTS,
        .corrupt_server_fixed_fds = CORRUPT_SERVER_FIXED_FDS,
        .devices = storage_->devices,
        .inodes = storage_->inodes,
        .file_types = storage_->file_types,
        .reservation_identity = storage_->reservation_identity,
        .archive_devices = storage_->archive_devices,
        .archive_inodes = storage_->archive_inodes,
    };
}
#endif

#ifdef KPI_REGISTERED_FRESH_TRIAL_PRODUCER_CLOSURE_TEST_SETUP
fresh_owner_issuance::FreshOwnerProducerClosureAuthority
RegisteredFreshTrialProducerClosureBridge::test_only_mint_fresh_owner_child(
        fresh_owner_issuance::PublicFreshOwnerTrialIssuanceReceipt receipt) {
    auto immutable = std::make_shared<const
        fresh_owner_issuance::PublicFreshOwnerTrialIssuanceReceipt>(
            std::move(receipt));
    return fresh_owner_issuance::FreshOwnerProducerClosureAuthority(
        std::move(immutable));
}

RegisteredFreshTrialProducerClosureAuthority
RegisteredFreshTrialProducerClosureBridge::bind_reserved_impl(
        FreshTrialCaptureProducerTopologyResidual&& residual,
        fresh_owner_issuance::FreshOwnerProducerClosureAuthority&& fresh,
        producer_runtime::PublicProducerLaunchPlan plan) {
    // Move every capability before checking any of them. A stale residual or
    // mismatched fresh-trial child therefore burns both and closes every
    // descriptor. The whole issuance authority is never consumed or returned.
    FreshTrialCaptureProducerTopologyResidual claimed_residual(
        std::move(residual));
    fresh_owner_issuance::FreshOwnerProducerClosureAuthority claimed_fresh(
        std::move(fresh));
    const bool residual_live = claimed_residual.live_.exchange(false);
    const bool fresh_live = claimed_fresh.live_.exchange(false);
    try {
        need(residual_live && fresh_live &&
             claimed_fresh.receipt_ != nullptr);
        claimed_residual.require_resources_valid();
        require_fresh_trial_matches(*claimed_fresh.receipt_, plan);
        require_exact_topology(
            claimed_residual.read_ends_,
            claimed_residual.endpoint_devices_,
            claimed_residual.endpoint_inodes_,
            claimed_residual.endpoint_types_);
        const auto identity = reserved_closure_identity(
            *claimed_fresh.receipt_, plan,
            claimed_residual.endpoint_devices_,
            claimed_residual.endpoint_inodes_,
            claimed_residual.endpoint_types_,
            claimed_residual.reservation_identity_,
            claimed_residual.archive_devices_,
            claimed_residual.archive_inodes_,
            claimed_residual.archive_modes_,
            claimed_residual.archive_nlinks_,
            claimed_residual.archive_sizes_);
        plan.opaque_closure_authority_identity = identity;

        const auto binding = plan.binding;
        const auto capture_trial_id = plan.capture_trial_id;
        const auto capture_attempt_ids = plan.capture_attempt_ids;
        const auto endpoint_devices = claimed_residual.endpoint_devices_;
        const auto endpoint_inodes = claimed_residual.endpoint_inodes_;
        const auto endpoint_types = claimed_residual.endpoint_types_;
        const auto reservation_identity =
            claimed_residual.reservation_identity_;
        const auto archive_devices = claimed_residual.archive_devices_;
        const auto archive_inodes = claimed_residual.archive_inodes_;

        auto read_ends = claimed_residual.read_ends_;
        claimed_residual.read_ends_.fill(-1);
        producer_runtime::ParentTenReadEndsAuthority topology(
            std::move(plan), read_ends);

        auto archive_fds = claimed_residual.archive_fds_;
        claimed_residual.archive_fds_.fill(-1);
        auto archive = producer_archive::ProducerSealedArchiveBuilder::
            adopt_preidentity_reservation(
                binding, identity, reservation_identity,
                std::move(archive_fds),
                claimed_residual.archive_devices_,
                claimed_residual.archive_inodes_,
                claimed_residual.archive_modes_,
                claimed_residual.archive_nlinks_,
                claimed_residual.archive_sizes_);
        return RegisteredFreshTrialProducerClosureAuthority(
            std::make_unique<
                RegisteredFreshTrialProducerClosureAuthority::Storage>(
                    std::move(topology),
                    std::make_unique<
                        producer_archive::ProducerSealedArchiveBuilder>(
                            std::move(archive)),
                    identity, binding, capture_trial_id,
                    capture_attempt_ids, endpoint_devices,
                    endpoint_inodes, endpoint_types,
                    reservation_identity, archive_devices,
                    archive_inodes));
    } catch (...) { refuse(); }
}

RegisteredFreshTrialProducerClosureAuthority
RegisteredFreshTrialProducerClosureBridge::test_only_bind_reserved(
        FreshTrialCaptureProducerTopologyResidual&& residual,
        fresh_owner_issuance::FreshOwnerProducerClosureAuthority&& fresh,
        producer_runtime::PublicProducerLaunchPlan plan) {
    return bind_reserved_impl(
        std::move(residual), std::move(fresh), std::move(plan));
}

RegisteredFreshTrialProducerClosureAuthority
RegisteredFreshTrialProducerClosureBridge::test_only_bind_prebound(
        fresh_owner_issuance::FreshOwnerProducerClosureAuthority&& fresh,
        producer_runtime::ParentTenReadEndsAuthority&& topology) {
    // Claim both rvalues before checking either.  A stale or mismatched input
    // therefore burns the other capability and closes all ten read ends.
    fresh_owner_issuance::FreshOwnerProducerClosureAuthority claimed_fresh(
        std::move(fresh));
    producer_runtime::ParentTenReadEndsAuthority claimed_topology(
        std::move(topology));
    const bool fresh_live = claimed_fresh.live_.exchange(false);
    try {
        need(fresh_live &&
             claimed_fresh.receipt_ != nullptr &&
             claimed_topology.live_.load());
        require_fresh_trial_matches(
            *claimed_fresh.receipt_, claimed_topology.plan_);
        require_exact_topology(
            claimed_topology.read_ends_, claimed_topology.devices_,
            claimed_topology.inodes_, claimed_topology.file_types_);
        const auto identity = closure_identity(
            *claimed_fresh.receipt_, claimed_topology.plan_,
            claimed_topology.devices_, claimed_topology.inodes_,
            claimed_topology.file_types_);
        // The caller-supplied placeholder is never retained.  Only this
        // source-derived identity reaches producer runtime/history/terminal.
        claimed_topology.plan_.opaque_closure_authority_identity = identity;
        const auto binding = claimed_topology.plan_.binding;
        const auto capture_trial_id =
            claimed_topology.plan_.capture_trial_id;
        const auto capture_attempt_ids =
            claimed_topology.plan_.capture_attempt_ids;
        const auto devices = claimed_topology.devices_;
        const auto inodes = claimed_topology.inodes_;
        const auto file_types = claimed_topology.file_types_;
        return RegisteredFreshTrialProducerClosureAuthority(
            std::make_unique<
                RegisteredFreshTrialProducerClosureAuthority::Storage>(
                    std::move(claimed_topology), nullptr, identity,
                    binding, capture_trial_id, capture_attempt_ids,
                    devices, inodes, file_types));
    } catch (...) { refuse(); }
}
#endif

producer_runtime::RunningCaptureProducer
RegisteredFreshTrialProducerClosureBridge::start(
        RegisteredFreshTrialProducerClosureAuthority&& authority) {
    auto storage = std::move(authority.storage_);
    need(storage != nullptr);
    if (storage->preidentity_archive_builder != nullptr)
        return producer_runtime::ParentOwnedCaptureProducer::start_prebuilt(
            std::move(storage->topology),
            std::move(*storage->preidentity_archive_builder));
    return producer_runtime::ParentOwnedCaptureProducer::start(
        std::move(storage->topology));
}

} // namespace kpi::mpc::financial::registered_driver
