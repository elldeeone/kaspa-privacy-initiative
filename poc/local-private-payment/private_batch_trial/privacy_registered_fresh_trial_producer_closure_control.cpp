#include "privacy_registered_fresh_trial_producer_closure.hpp"
#include "privacy_registered_fresh_trial_capture_topology_reservation.hpp"

#include <array>
#include <cassert>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <cstdlib>
#include <limits>
#include <memory>
#include <openssl/sha.h>
#include <span>
#include <set>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using namespace kpb::measurement;
using namespace kpb::measurement::producer_runtime;
using namespace kpi::mpc::financial;
using namespace kpi::mpc::financial::fresh_owner_issuance;
using namespace kpi::mpc::financial::registered_driver;
using kpi::mpc::OwnerInputContract;

namespace {

constexpr std::string_view TRIAL =
    "6f87aef8-106f-4d0f-9ee8-35ab56885be7";
constexpr std::array<std::string_view, 2> ATTEMPTS{
    "a3647d17-b5d7-46bc-86ac-8421f93cdb46",
    "7be6fa9e-1604-4d30-bc1d-29553a8b4607",
};

template<class Function>
void refuses(Function&& function) {
    bool did_refuse = false;
    try { function(); }
    catch (const std::exception&) { did_refuse = true; }
    assert(did_refuse);
}

Digest id(unsigned value) {
    Digest result{};
    result[0] = static_cast<unsigned char>(value);
    result[1] = static_cast<unsigned char>(value >> 8);
    result[31] = static_cast<unsigned char>(value ^ 0xa7U);
    return result;
}

Digest sha256(std::span<const unsigned char> value) {
    Digest result{};
    assert(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}

Digest text_identity(std::string_view domain, std::string_view value) {
    std::vector<unsigned char> bytes(domain.begin(), domain.end());
    bytes.insert(bytes.end(), value.begin(), value.end());
    return sha256(bytes);
}

Digest trial_identity(std::string_view value) {
    constexpr std::string_view domain =
        "KPB_REGISTERED_TRIAL_UUID_IDENTITY_V1\n";
    std::vector<unsigned char> bytes(domain.begin(), domain.end());
    const auto size = static_cast<std::uint64_t>(value.size());
    for (unsigned shift = 0; shift < 64; shift += 8)
        bytes.push_back(static_cast<unsigned char>(size >> shift));
    bytes.insert(bytes.end(), value.begin(), value.end());
    return sha256(bytes);
}

WorkerBinding worker(const ManifestEntry& entry) {
    return {
        .source_identity = entry.source_identity,
        .build_identity = entry.build_identity,
        .runtime_identity = entry.runtime_identity,
        .assets_identity = entry.assets_identity,
        .pinned_executable_identity = entry.pinned_executable_identity,
        .launcher_identity = entry.launcher_identity,
    };
}

RunBinding binding() {
    std::array<ManifestEntry, 10> entries{};
    for (unsigned index = 0; index < entries.size(); ++index) {
        const auto seed = static_cast<unsigned char>(0xb0 + index * 6);
        entries[index] = ManifestEntry{
            .component = static_cast<ManifestComponent>(index + 1),
            .source_identity = id(seed),
            .build_identity = id(seed + 1),
            .runtime_identity = id(seed + 2),
            .assets_identity = id(seed + 3),
            .pinned_executable_identity = id(seed + 4),
            .launcher_identity = id(seed + 5),
        };
    }
    FiniteManifestBinding manifest{
        .manifest_identity = recompute_finite_manifest_identity(entries),
        .parent_recomputation_identity = id(0xaf),
        .entries = entries,
    };
    const auto& capture = manifest.entries[1];
    return RunBinding{
        .classification = Classification::HiddenCandidate,
        .comparison_selection = id(0x10),
        .run_selection = id(0x11),
        .trial = trial_identity(TRIAL),
        .attempt = id(0x13),
        .cohort = id(0x14),
        .capture = id(0x15),
        .method = id(0x16),
        .workload = id(0x17),
        .source_closure = id(0x18),
        .runtime = id(0x19),
        .finite_manifest = manifest,
        .outer_parent_process = id(0x1a),
        .outer_parent_executable = id(0x1b),
        .capture_source = capture.source_identity,
        .capture_build = capture.build_identity,
        .capture_runtime = capture.runtime_identity,
        .capture_launcher = capture.launcher_identity,
        .observer_worker = worker(manifest.entries[6]),
        .score_worker = worker(manifest.entries[7]),
        .aggregate_worker = worker(manifest.entries[8]),
        .financial_runs = {id(0x20), id(0x21)},
        .round_attempts = {
            text_identity("KPB_CAPTURE_ATTEMPT_ID_V1\n", ATTEMPTS[0]),
            text_identity("KPB_CAPTURE_ATTEMPT_ID_V1\n", ATTEMPTS[1]),
        },
        .round_cohorts = {id(0x24), id(0x25)},
        .round_capture_plans = {id(0x26), id(0x27)},
        .projections = {id(0x28), id(0x29)},
    };
}

PublicProducerLaunchPlan plan() {
    const auto selected = binding();
    PublicProducerLaunchPlan result{
        .binding = selected,
        .capture_trial_id = std::string(TRIAL),
        .capture_attempt_ids = {
            std::string(ATTEMPTS[0]), std::string(ATTEMPTS[1])},
        .producer_process_identity = selected.outer_parent_process,
        .role_closure_identity = selected.source_closure,
        .manifest_seal = selected.finite_manifest.manifest_identity,
        .construction_policy =
            ConstructionPolicy::SecretPermutationIndependent,
        .construction_classification_receipt = id(0x30),
        // This is a deliberately caller-selected placeholder. The bridge
        // must replace it and must never bind it into the derived identity.
        .opaque_closure_authority_identity = id(0x35),
        .route_requirements = {
            PublicAggregateMailboxRouteRequirement{
                .round = 1,
                .projection_identity = selected.projections[0],
                .projection_bytes = 10685,
                .route_endpoint_count = 1,
                .owner_ack_count = 0,
                .role_blind_required = true,
                .after_full_cohort_barrier_required = true,
                .owner_socket_or_path_derivation_forbidden = true,
            },
            PublicAggregateMailboxRouteRequirement{
                .round = 2,
                .projection_identity = selected.projections[1],
                .projection_bytes = 10685,
                .route_endpoint_count = 1,
                .owner_ack_count = 0,
                .role_blind_required = true,
                .after_full_cohort_barrier_required = true,
                .owner_socket_or_path_derivation_forbidden = true,
            },
        },
    };
    for (unsigned index = 0; index < result.streams.size(); ++index) {
        result.streams[index] = PublicProducerStreamPlan{
            .round = index / 5 + 1,
            .kind = static_cast<CaptureKind>(index % 5 + 1),
            .fixed_fd = 20 + index,
            .process_identity = id(0x40 + index),
            .child_exit_identity = id(0x50 + index),
        };
    }
    return result;
}

OwnerInputContract contract(
        unsigned owner, unsigned round, const RunBinding& selected) {
    const unsigned base = round == 1 ? 0x100 : 0x200;
    return OwnerInputContract{
        .run_nonce = identity_registry::hex(
            selected.round_attempts[round - 1]),
        .model_identity = identity_registry::hex(id(0x300)),
        .source_identity = identity_registry::hex(id(0x301)),
        .proving_key_identity = identity_registry::hex(id(0x302)),
        .verifying_key_identity = identity_registry::hex(id(0x303)),
        .cohort_identity = identity_registry::hex(
            selected.round_cohorts[round - 1]),
        .owner_id = static_cast<int>(owner),
        .input_count = 2'635'409,
        .server_certificate_sha256 = {
            identity_registry::hex(id(base + 10)),
            identity_registry::hex(id(base + 11)),
            identity_registry::hex(id(base + 12))},
        .owner_certificate_sha256 =
            identity_registry::hex(id(base + 20 + owner)),
        .trace_identity = identity_registry::hex(id(0x304)),
        .layout_identity = identity_registry::hex(id(0x305)),
    };
}

PublicOwnerIssuanceReceipt owner_receipt(
        unsigned owner, const RunBinding& selected,
        bool wrong_trial = false) {
    PublicOwnerIssuanceReceipt value{
        .classification = CaptureClassification::HiddenCandidate,
        .authority_identity = id(1),
        .registration_identity = id(2),
        .service_identity = id(3),
        .controller_source_identity = id(4),
        .controller_build_identity = id(5),
        .owner_issuer_source_identity = id(6),
        .owner_issuer_build_identity = id(7),
        .run = id(8),
        .trial = wrong_trial ? id(0x990) : selected.trial,
        .root_identity = id(10),
        .baseline_policy_identity = {},
        .owner_component = owner,
        .owner_process_identity = id(20 + owner),
    };
    for (unsigned round = 1; round <= 2; ++round) {
        const unsigned base = round == 1 ? 0x100 : 0x200;
        auto& item = value.rounds[round - 1];
        item.round = round;
        item.attempt = selected.round_attempts[round - 1];
        item.cohort = selected.round_cohorts[round - 1];
        item.accepted_input_head_identity = id(base + 3);
        item.history_gate_identity = id(base + 4);
        item.contract = contract(owner, round, selected);
        item.file_identity = id(base + 30 + owner);
        item.file_metadata_identity = id(base + 40 + owner);
        item.file_bytes = OWNER_PRIVATE_INPUT_V2_BYTES;
        item.owner_tls_spki_identity = id(base + 50 + owner);
        item.server_tls_spki_identities = {
            id(base + 60), id(base + 61), id(base + 62)};
    }
    return value;
}

PublicFreshOwnerTrialIssuanceReceipt fresh_receipt(
        const RunBinding& selected, bool wrong_trial = false) {
    std::array<PublicOwnerIssuanceReceipt, 3> owners{};
    for (unsigned owner = 0; owner < owners.size(); ++owner) {
        owners[owner] = owner_receipt(owner, selected, wrong_trial);
        owners[owner].logical_owner_binding = id(0x400 + owner);
        owners[owner].issuance_identity = id(0x410 + owner);
    }
    const auto& first = owners[0];
    return PublicFreshOwnerTrialIssuanceReceipt{
        .classification = first.classification,
        .authority_identity = first.authority_identity,
        .registration_identity = first.registration_identity,
        .service_identity = first.service_identity,
        .controller_source_identity = first.controller_source_identity,
        .controller_build_identity = first.controller_build_identity,
        .owner_issuer_source_identity = first.owner_issuer_source_identity,
        .owner_issuer_build_identity = first.owner_issuer_build_identity,
        .run = first.run,
        .trial = first.trial,
        .root_identity = first.root_identity,
        .baseline_policy_identity = first.baseline_policy_identity,
        .roster_authority_identity = {},
        .replay_policy_identity = id(0x501),
        .owners = std::move(owners),
        .issuance_identity = id(0x502),
    };
}

FreshOwnerProducerClosureAuthority fresh_trial(
        const RunBinding& selected, bool wrong_trial = false) {
    return RegisteredFreshTrialProducerClosureBridge::
        test_only_mint_fresh_owner_child(
            fresh_receipt(selected, wrong_trial));
}

void close_fd(int& fd) {
    if (fd < 0) return;
    while (::close(fd) != 0 && errno == EINTR) {}
    fd = -1;
}

struct PipeSet {
    std::array<int, 10> reads{};
    std::array<int, 10> writes{};
    PipeSet() {
        reads.fill(-1);
        writes.fill(-1);
        for (unsigned index = 0; index < reads.size(); ++index) {
            int pair[2]{};
            assert(::pipe2(pair, O_CLOEXEC) == 0);
            reads[index] = pair[0];
            writes[index] = pair[1];
        }
    }
    ~PipeSet() {
        for (auto& fd : reads) close_fd(fd);
        for (auto& fd : writes) close_fd(fd);
    }
};

ParentTenReadEndsAuthority topology(
        PipeSet& pipes, const PublicProducerLaunchPlan& selected) {
    auto result = ParentTenReadEndsAuthority::test_only_mint(
        selected, std::move(pipes.reads));
    pipes.reads.fill(-1);
    return result;
}

void happy_and_linear() {
    const auto selected = plan();
    PipeSet pipes;
    auto fresh = fresh_trial(selected.binding);
    auto parent = topology(pipes, selected);
    auto closure = RegisteredFreshTrialProducerClosureBridge::
        test_only_bind_prebound(
        std::move(fresh), std::move(parent));
    const auto summary = closure.test_only_summary();
    constexpr std::array<unsigned, 2> source_slots{3, 8};
    constexpr std::array<unsigned, 2> fixed_fds{23, 28};
    assert(summary.closure_identity != Digest{} &&
           summary.closure_identity != id(0x35) &&
           summary.binding == selected.binding &&
           summary.capture_trial_id == TRIAL &&
           summary.capture_attempt_ids[0] == ATTEMPTS[0] &&
           summary.capture_attempt_ids[1] == ATTEMPTS[1] &&
           summary.corrupt_server_source_slots == source_slots &&
           summary.corrupt_server_fixed_fds == fixed_fds);
    PipeSet replay_pipes;
    auto replay_topology = topology(replay_pipes, selected);
    refuses([&] {
        (void)RegisteredFreshTrialProducerClosureBridge::
            test_only_bind_prebound(
                std::move(fresh), std::move(replay_topology));
    });

    auto moved = std::move(closure);
    (void)moved.test_only_summary();
    refuses([&] { (void)closure.test_only_summary(); });
}

void cross_trial_burns_both() {
    const auto selected = plan();
    PipeSet first_pipes;
    auto wrong = fresh_trial(selected.binding, true);
    auto first_topology = topology(first_pipes, selected);
    refuses([&] {
        (void)RegisteredFreshTrialProducerClosureBridge::
            test_only_bind_prebound(
            std::move(wrong), std::move(first_topology));
    });

    PipeSet second_pipes;
    auto second_topology = topology(second_pipes, selected);
    refuses([&] {
        (void)RegisteredFreshTrialProducerClosureBridge::
            test_only_bind_prebound(
            std::move(wrong), std::move(second_topology));
    });
    auto valid_fresh = fresh_trial(selected.binding);
    refuses([&] {
        (void)RegisteredFreshTrialProducerClosureBridge::
            test_only_bind_prebound(
            std::move(valid_fresh), std::move(second_topology));
    });
}

void topology_is_identity_bound() {
    const auto selected = plan();
    PipeSet shared_pipes;
    std::array<int, 10> duplicate_reads{};
    duplicate_reads.fill(-1);
    for (unsigned index = 0; index < duplicate_reads.size(); ++index) {
        duplicate_reads[index] = ::fcntl(
            shared_pipes.reads[index], F_DUPFD_CLOEXEC, 100);
        assert(duplicate_reads[index] >= 0);
    }
    auto first_shared_topology = topology(shared_pipes, selected);
    auto changed_placeholder = selected;
    changed_placeholder.opaque_closure_authority_identity = id(0x777);
    auto second_shared_topology =
        ParentTenReadEndsAuthority::test_only_mint(
            changed_placeholder, std::move(duplicate_reads));
    duplicate_reads.fill(-1);
    auto first_shared = RegisteredFreshTrialProducerClosureBridge::
        test_only_bind_prebound(
        fresh_trial(selected.binding), std::move(first_shared_topology));
    auto second_shared = RegisteredFreshTrialProducerClosureBridge::
        test_only_bind_prebound(
        fresh_trial(selected.binding), std::move(second_shared_topology));
    assert(first_shared.test_only_summary().closure_identity ==
           second_shared.test_only_summary().closure_identity);

    PipeSet first_pipes;
    auto first_closure = RegisteredFreshTrialProducerClosureBridge::
        test_only_bind_prebound(
        fresh_trial(selected.binding), topology(first_pipes, selected));
    const auto first = first_closure.test_only_summary();

    PipeSet second_pipes;
    auto second_closure = RegisteredFreshTrialProducerClosureBridge::
        test_only_bind_prebound(
        fresh_trial(selected.binding), topology(second_pipes, selected));
    const auto second = second_closure.test_only_summary();
    const std::array<std::uint64_t, 10> zero_devices{};
    assert(first.closure_identity != second.closure_identity &&
           first.devices != zero_devices && second.devices != zero_devices);

    auto wrong_slot = selected;
    wrong_slot.streams[3].fixed_fd = 24;
    PipeSet wrong_pipes;
    refuses([&] {
        (void)topology(wrong_pipes, wrong_slot);
    });
}

void runtime_start_is_one_shot() {
    const auto selected = plan();
    PipeSet pipes;
    auto closure = RegisteredFreshTrialProducerClosureBridge::
        test_only_bind_prebound(
        fresh_trial(selected.binding), topology(pipes, selected));
    for (auto& fd : pipes.writes) close_fd(fd);
    auto running = RegisteredFreshTrialProducerClosureBridge::start(
        std::move(closure));
    refuses([&] {
        (void)RegisteredFreshTrialProducerClosureBridge::start(
            std::move(closure));
    });
    (void)running;
}

std::size_t open_reserved_archives(
    const FreshTrialCaptureTopologyReservation::TestSummary&);

void reserved_runtime_uses_same_archives() {
    const auto selected = plan();
    auto reservation =
        FreshTrialCaptureTopologyReservationBridge::
            test_only_reserve_unbound();
    const auto reserved = reservation.test_only_summary();
    auto residual = std::move(reservation)
        .test_only_take_producer_residual();
    auto closure = RegisteredFreshTrialProducerClosureBridge::
        test_only_bind_reserved(
            std::move(residual), fresh_trial(selected.binding), selected);
    const auto summary = closure.test_only_summary();
    assert(summary.reservation_identity == reserved.reservation_identity &&
           summary.archive_devices == reserved.archive_devices &&
           summary.archive_inodes == reserved.archive_inodes);
    {
        auto running = RegisteredFreshTrialProducerClosureBridge::start(
            std::move(closure));
        const auto actual = producer_runtime::ParentOwnedCaptureProducer::
            test_only_archive_identity(running);
        assert(actual.devices == reserved.archive_devices &&
               actual.inodes == reserved.archive_inodes);
        assert(open_reserved_archives(reserved) == 10);
    }
    assert(open_reserved_archives(reserved) == 0);
}

std::size_t open_reserved_archives(
        const FreshTrialCaptureTopologyReservation::TestSummary& summary) {
    std::set<std::pair<std::uint64_t, std::uint64_t>> selected;
    for (unsigned slot = 0; slot < summary.archive_inodes.size(); ++slot)
        selected.emplace(
            summary.archive_devices[slot], summary.archive_inodes[slot]);
    std::size_t count = 0;
    DIR* directory = ::opendir("/proc/self/fd");
    assert(directory != nullptr);
    const int directory_fd = ::dirfd(directory);
    while (auto* entry = ::readdir(directory)) {
        char* end = nullptr;
        const long raw = std::strtol(entry->d_name, &end, 10);
        if (end == entry->d_name || *end != '\0' || raw < 0 ||
            raw > std::numeric_limits<int>::max() || raw == directory_fd)
            continue;
        struct stat value{};
        if (::fstat(static_cast<int>(raw), &value) == 0 &&
            selected.contains({
                static_cast<std::uint64_t>(value.st_dev),
                static_cast<std::uint64_t>(value.st_ino)}))
            ++count;
    }
    ::closedir(directory);
    return count;
}

void corrupt_reserved_archive_burns_all() {
    const auto selected = plan();
    auto reservation =
        FreshTrialCaptureTopologyReservationBridge::
            test_only_reserve_unbound();
    const auto summary = reservation.test_only_summary();
    assert(open_reserved_archives(summary) == 10);
    auto residual = std::move(reservation)
        .test_only_take_producer_residual();
    residual.test_only_corrupt_archive_inode(4);
    refuses([&] {
        (void)RegisteredFreshTrialProducerClosureBridge::
            test_only_bind_reserved(
                std::move(residual), fresh_trial(selected.binding),
                selected);
    });
    assert(open_reserved_archives(summary) == 0);
}

void status_is_configured_zero() {
    static_assert(kRegisteredFreshTrialProducerClosureSourceStatus
        .dedicated_fresh_owner_closure_child_contract);
    static_assert(!kRegisteredFreshTrialProducerClosureSourceStatus
        .dedicated_fresh_owner_closure_child_consumed);
    static_assert(!kRegisteredFreshTrialProducerClosureSourceStatus
        .full_run_binding_bound);
    static_assert(!kRegisteredFreshTrialProducerClosureSourceStatus
        .raw_trial_and_attempt_ids_bound);
    static_assert(!kRegisteredFreshTrialProducerClosureSourceStatus
        .exact_ten_read_end_topology_bound);
    static_assert(!kRegisteredFreshTrialProducerClosureSourceStatus
        .corrupt_server_slots_3_8_bound);
    static_assert(!kRegisteredFreshTrialProducerClosureSourceStatus
        .corrupt_server_fds_23_28_bound);
    static_assert(!kRegisteredFreshTrialProducerClosureSourceStatus
        .linear_split_and_start);
    static_assert(!kRegisteredFreshTrialProducerClosureSourceStatus
        .preissuance_topology_reservation);
    static_assert(!kRegisteredFreshTrialProducerClosureSourceStatus
        .all_three_pidfds_bound_before_issuance);
    static_assert(!kRegisteredFreshTrialProducerClosureSourceStatus
        .registered_build_closure);
    static_assert(!kRegisteredFreshTrialProducerClosureSourceStatus
        .production_topology_factory);
    static_assert(!kRegisteredFreshTrialProducerClosureSourceStatus
        .prelaunch_authority_consumed);
    static_assert(kRegisteredFreshTrialProducerClosureSourceStatus
        .same_ten_archive_runtime_start);
    static_assert(!kRegisteredFreshTrialProducerClosureSourceStatus
        .postrun_projection_exit_join);
    static_assert(!kRegisteredFreshTrialProducerClosureSourceStatus
        .reservation_identity_in_final_history);
    static_assert(!kRegisteredFreshTrialProducerClosureSourceStatus
        .selected_parent_callsite);
    static_assert(!kRegisteredFreshTrialProducerClosureSourceStatus
        .configured);
    static_assert(!kRegisteredFreshTrialProducerClosureSourceStatus
        .launch_enabled);
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::string_view scenario(argv[1]);
    if (scenario == "happy") happy_and_linear();
    else if (scenario == "cross-trial") cross_trial_burns_both();
    else if (scenario == "topology") topology_is_identity_bound();
    else if (scenario == "start") runtime_start_is_one_shot();
    else if (scenario == "reserved-start")
        reserved_runtime_uses_same_archives();
    else if (scenario == "reserved-corrupt")
        corrupt_reserved_archive_burns_all();
    else if (scenario == "status") status_is_configured_zero();
    else assert(false);
}
