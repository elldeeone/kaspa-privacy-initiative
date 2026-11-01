#include "../fresh_owner_trial_issuance.hpp"
#include "../registered_parent_role_fork.hpp"
#include "../registered_preidentity_ready.hpp"
#include "../registered_selected_producer_activation_contract.hpp"
#include "../registered_selected_parent_orchestrator.hpp"
#include "../registered_selected_producer_run_binding.hpp"
#include "../../../private_batch_trial/privacy_owner_score_lineage_source_authority.hpp"
#include "../../../private_batch_trial/privacy_p1_state_capsule_prelaunch_compiler_contract.hpp"
#include "../../../private_batch_trial/privacy_prelaunch_policy_domain_authority.hpp"
#include "../../../private_batch_trial/privacy_registered_fresh_trial_capture_topology_reservation.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace kpi::mpc;
using namespace kpi::mpc::financial;
using namespace kpi::mpc::financial::fresh_owner_issuance;
using namespace kpi::mpc::financial::registered_driver;

namespace { std::atomic_bool fail_allocations{}; }

void* operator new(std::size_t size) {
    if (fail_allocations.load()) throw std::bad_alloc();
    if (void* value = std::malloc(size == 0 ? 1 : size)) return value;
    throw std::bad_alloc();
}
void operator delete(void* value) noexcept { std::free(value); }
void operator delete[](void* value) noexcept { std::free(value); }
void operator delete(void* value, std::size_t) noexcept {
    std::free(value);
}
void operator delete[](void* value, std::size_t) noexcept {
    std::free(value);
}

namespace {

constexpr std::string_view TRIAL_UUID =
    "11111111-1111-4111-8111-111111111111";

Digest id(unsigned value) {
    Digest result{};
    result[0] = static_cast<unsigned char>(value);
    result[1] = static_cast<unsigned char>(value >> 8);
    result[31] = static_cast<unsigned char>(value ^ 0xa7U);
    return result;
}

std::string hex(unsigned value) { return identity_registry::hex(id(value)); }

LogicalOwnerIdentity logical_id(unsigned owner) {
    LogicalOwnerIdentity result{};
    result[0] = static_cast<unsigned char>(0x30 + owner);
    result[31] = static_cast<unsigned char>(0xd0 + owner);
    return result;
}

class TestVerifier final : public LongLivedOwnerProofVerifier {
    LogicalOwnerIdentity identity_;
public:
    explicit TestVerifier(LogicalOwnerIdentity identity)
        : identity_(identity) {}
private:
    LogicalOwnerIdentity logical_identity() const override {
        return identity_;
    }
    bool verify(std::span<const unsigned char>,
                std::span<const unsigned char>) const override {
        return false;
    }
};

OwnerInputContract owner_contract(unsigned owner, unsigned round) {
    const unsigned base = round == 1 ? 0x100 : 0x200;
    return OwnerInputContract{
        .run_nonce = hex(base + 1), .model_identity = hex(0x300),
        .source_identity = hex(0x301),
        .proving_key_identity = hex(0x302),
        .verifying_key_identity = hex(0x303),
        .cohort_identity = hex(base + 2),
        .owner_id = static_cast<int>(owner), .input_count = 2'635'409,
        .server_certificate_sha256 = {
            hex(base + 10), hex(base + 11), hex(base + 12)},
        .owner_certificate_sha256 = hex(base + 20 + owner),
        .trace_identity = hex(0x304), .layout_identity = hex(0x305),
    };
}

PublicOwnerIssuanceReceipt owner_receipt(unsigned owner) {
    PublicOwnerIssuanceReceipt value{
        .classification = CaptureClassification::HiddenCandidate,
        .authority_identity = id(1), .registration_identity = id(2),
        .service_identity = id(3), .controller_source_identity = id(4),
        .controller_build_identity = id(5),
        .owner_issuer_source_identity = id(6),
        .owner_issuer_build_identity = id(7), .run = id(8),
        .trial = RegisteredCapturePlanRosterBridge::trial_identity(
            TRIAL_UUID),
        .root_identity = id(10), .owner_component = owner,
        .owner_process_identity = id(20 + owner),
    };
    for (unsigned round = 1; round <= 2; ++round) {
        const unsigned base = round == 1 ? 0x100 : 0x200;
        auto& item = value.rounds[round - 1];
        item.round = round;
        item.attempt = id(base + 1);
        item.cohort = id(base + 2);
        item.accepted_input_head_identity = id(base + 3);
        item.history_gate_identity = id(base + 4);
        item.contract = owner_contract(owner, round);
        item.file_identity = id(base + 30 + owner);
        item.file_metadata_identity = id(base + 40 + owner);
        item.file_bytes = OWNER_PRIVATE_INPUT_V2_BYTES;
        item.owner_tls_spki_identity = id(base + 50 + owner);
        item.server_tls_spki_identities = {
            id(base + 60), id(base + 61), id(base + 62)};
    }
    return value;
}

OwnerLocalIssuanceAuthority owner_authority(
        unsigned owner, RegisteredOwnerIssuancePermit&& permit) {
    return OwnerLocalIssuanceAuthority::test_only_mint(
        owner_receipt(owner),
        std::make_shared<TestVerifier>(logical_id(owner)),
        id(0x400 + owner), std::move(permit));
}

class MemoryReplayRegistry final :
        public ExternalOwnerIssuanceReplayRegistry {
    std::vector<Digest> consumed_;
public:
    void consume(std::span<const Digest> values) override {
        for (const auto& value : values)
            for (const auto& prior : consumed_)
                if (value == prior) throw identity_registry::Refused();
        consumed_.insert(consumed_.end(), values.begin(), values.end());
    }
};

class UnreachableRoundProgram final : public RegisteredRoleChildProgram {
public:
    int run(ParentAuthenticatedPartyDeliveryAuthority&&,
            ChildRoleCompletionEndpointAuthority&&) override { return 99; }
};

class GenericPreIdentityProgram final :
        public RegisteredPreIdentityPersistentRoleChildProgram {
    std::array<UnreachableRoundProgram, 2> rounds_;
public:
    RegisteredRoleChildProgram& round_program(unsigned round) override {
        assert(round == 1 || round == 2);
        return rounds_[round - 1];
    }
};

OwnerIssuanceReplayGuardAuthority replay_guard() {
    return OwnerIssuanceReplayGuardAuthority::test_only_mint(
        PublicOwnerIssuanceReplayPolicy{
            .authority_identity = id(0x500), .policy_identity = id(0x501),
            .permission_separated = true, .monotonic = true,
            .child_path_exposed = false, .child_fd_exposed = false,
        }, std::make_shared<MemoryReplayRegistry>());
}

FreshOwnerPersistentActivationAuthority genuine_causal_activation() {
    GenericPreIdentityProgram program;
    auto process = RegisteredParentPersistentRoleFork::reserve(program);
    auto permit = process.issue_topology_reservation_permit();
    auto topology = FreshTrialCaptureTopologyReservationBridge::reserve(
        std::move(permit));
    auto ready = RegisteredPreidentityReadyBridge::join(
        std::move(topology), std::move(process));
    auto session = RegisteredPreidentityReadyIssuanceBridge::begin(
        std::move(ready));
    std::array<RegisteredOwnerIssuancePermit, 3> permits{
        RegisteredPreidentityReadyIssuanceBridge::take_owner_permit(
            session, 0),
        RegisteredPreidentityReadyIssuanceBridge::take_owner_permit(
            session, 1),
        RegisteredPreidentityReadyIssuanceBridge::take_owner_permit(
            session, 2),
    };
    auto residual = RegisteredPreidentityReadyIssuanceBridge::finish(
        std::move(session));
    auto issuance = FreshOwnerTrialIssuanceBridge::join_exact_three(
        std::move(residual),
        std::array<OwnerLocalIssuanceAuthority, 3>{
            owner_authority(0, std::move(permits[0])),
            owner_authority(1, std::move(permits[1])),
            owner_authority(2, std::move(permits[2]))},
        replay_guard(), {});
    auto split = FreshOwnerTrialIssuanceBridge::split(std::move(issuance));
    return split.take_persistent_activation();
}

template<class Callable>
void refuses(Callable&& callable) {
    bool did_refuse = false;
    try { callable(); }
    catch (const identity_registry::Refused&) { did_refuse = true; }
    assert(did_refuse);
}

unsigned open_descriptor_count() {
    DIR* directory = ::opendir("/proc/self/fd");
    assert(directory != nullptr);
    unsigned result = 0;
    errno = 0;
    while (const auto* entry = ::readdir(directory))
        if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') ++result;
    const int saved = errno;
    assert(::closedir(directory) == 0 && saved == 0);
    return result;
}

void require_complete_abort(
        detail::PersistentRoleReservationAbortEvidence& evidence,
        bool expected_preflight) {
    assert(evidence.all_children_settled_value());
    assert(!evidence.pidfd_signal_used_value());
    assert(evidence.topology_preflight_complete_value() ==
           expected_preflight);
    if (expected_preflight)
        for (const auto& round :
             evidence.topology_preflight_acknowledged_value())
            for (const bool value : round) assert(value);
    if (expected_preflight)
        for (const bool value :
             evidence.topology_retention_acknowledged_value())
            assert(value);
    const auto& pids = evidence.child_pids_value();
    for (unsigned role = 0; role < 3; ++role) {
        assert(pids[role] > 1);
        assert(evidence.term_signals_value()[role] == 0);
    }
    assert(pids[0] != pids[1] && pids[0] != pids[2] &&
           pids[1] != pids[2]);
}

void arm_allocation_failure() { fail_allocations = true; }

void close_round2_role0(RegisteredPersistentRoleProcessReservation& process) {
    ParentRoleForkTestProcessBridge::close_reservation_channel(
        process, 2, 0);
}

void fail_round2_role1_ack(
        RegisteredPersistentRoleProcessReservation& process) {
    ParentRoleForkTestProcessBridge::fail_reservation_ack_receive(
        process, 2, 1);
}

ParentRoleReservationRetentionTestFault selected_retention_fault =
    ParentRoleReservationRetentionTestFault::None;

void apply_selected_retention_fault(
        RegisteredPersistentRoleProcessReservation& process) {
    ParentRoleForkTestProcessBridge::set_reservation_retention_fault(
        process, selected_retention_fault);
}

void prepared_topology_retains_exact_state_and_aborts_typed() {
    const unsigned before = open_descriptor_count();
    {
        auto activation = genuine_causal_activation();
        auto result = RegisteredPersistentFreshTrialActivationBridge::
            activate(std::move(activation));
        assert(!result.activated() && result.topology_prepared());
        auto pending = std::move(result).take_topology_activation();
        const auto summary = pending.test_only_summary();
        assert(summary.process_reservation_retained);
        assert(summary.issuance_lineage_retained);
        assert(summary.topology_transfer_retained);
        for (const auto& round : summary.command_acknowledged)
            for (const bool value : round) assert(value);
        for (const bool value : summary.retention_acknowledged)
            assert(value);
        for (unsigned round = 0; round < 2; ++round) {
            assert(summary.parent_terminal_endpoints_retained[round]);
            assert(summary.state_devices[round] != 0);
            assert(summary.state_inodes[round] != 0);
            assert(summary.role1_activation_identities[round] != Digest{});
        }
        assert(summary.state_inodes[0] != summary.state_inodes[1]);
        auto failure = RegisteredPersistentFreshTrialActivationBridge::
            abort_topology(std::move(pending));
        const auto retained = failure.test_only_summary();
        assert(retained.process_abort_retained);
        assert(retained.activation_authority_retained);
        assert(retained.topology_quarantine_retained);
        assert(retained.parent_terminal_endpoints_retained[0]);
        assert(retained.parent_terminal_endpoints_retained[1]);
        assert(retained.p1_state_parent_reads_retained[0]);
        assert(retained.p1_state_parent_reads_retained[1]);
        assert(!retained.p1_state_writers_retained[0]);
        assert(!retained.p1_state_writers_retained[1]);
        auto evidence = failure.test_only_take_process_abort_evidence();
        require_complete_abort(evidence, true);
        for (const int code : evidence.exit_codes_value())
            assert(code == 121);
        refuses([&] {
            (void)RegisteredPersistentFreshTrialActivationBridge::
                abort_topology(std::move(pending));
        });
    }
    assert(open_descriptor_count() == before);
}

void retained_command_fault_returns_typed_settled_failure(
        ParentRoleReservationRetentionTestFault fault,
        bool first_acknowledgements_complete) {
    const unsigned before = open_descriptor_count();
    {
        selected_retention_fault = fault;
        RegisteredPersistentFreshTrialActivationBridge::
            test_only_set_process_hook(apply_selected_retention_fault);
        auto result = RegisteredPersistentFreshTrialActivationBridge::
            activate(genuine_causal_activation());
        RegisteredPersistentFreshTrialActivationBridge::
            test_only_set_process_hook(nullptr);
        selected_retention_fault =
            ParentRoleReservationRetentionTestFault::None;
        assert(!result.activated() && !result.topology_prepared());
        auto failure = std::move(result).take_failure_residual();
        auto evidence = failure.test_only_take_process_abort_evidence();
        require_complete_abort(evidence, false);
        if (first_acknowledgements_complete) {
            for (const auto& round :
                 evidence.topology_preflight_acknowledged_value())
                for (const bool value : round) assert(value);
            assert(!std::all_of(
                evidence.topology_retention_acknowledged_value().begin(),
                evidence.topology_retention_acknowledged_value().end(),
                [](bool value) { return value; }));
        }
    }
    assert(open_descriptor_count() == before);
}

void swapped_topology_writer_refuses_before_issuance_claim() {
    const unsigned before = open_descriptor_count();
    {
        GenericPreIdentityProgram program;
        auto process = RegisteredParentPersistentRoleFork::reserve(program);
        auto permit = process.issue_topology_reservation_permit();
        auto topology = FreshTrialCaptureTopologyReservationBridge::reserve(
            std::move(permit));
        FreshTrialCaptureTopologyReservationBridge::
            test_only_swap_writer_aliases(topology, 0, 2);
        refuses([&] {
            (void)RegisteredPreidentityReadyBridge::join(
                std::move(topology), std::move(process));
        });
        auto evidence = RegisteredParentPersistentRoleFork::abort(
            std::move(process));
        require_complete_abort(evidence, false);
        for (const int code : evidence.exit_codes_value())
            assert(code == 121);
    }
    assert(open_descriptor_count() == before);
}

void post_ack_channel_close_settles_every_pidfd_child() {
    const unsigned before = open_descriptor_count();
    {
        auto result = RegisteredPersistentFreshTrialActivationBridge::
            activate(genuine_causal_activation());
        auto pending = std::move(result).take_topology_activation();
        RegisteredPersistentFreshTrialActivationBridge::
            test_only_close_pending_reservation_channel(pending, 1, 1);
        auto failure = RegisteredPersistentFreshTrialActivationBridge::
            abort_topology(std::move(pending));
        auto evidence = failure.test_only_take_process_abort_evidence();
        require_complete_abort(evidence, true);
        assert(evidence.exit_codes_value()[1] == 122 ||
               evidence.exit_codes_value()[1] == 121);
    }
    assert(open_descriptor_count() == before);
}

void moved_pending_and_result_replay_refuse() {
    const unsigned before = open_descriptor_count();
    {
        auto result = RegisteredPersistentFreshTrialActivationBridge::
            activate(genuine_causal_activation());
        RegisteredPersistentRoleActivationResult moved(std::move(result));
        auto pending = std::move(moved).take_topology_activation();
        refuses([&] { (void)std::move(moved).take_topology_activation(); });
        RegisteredPersistentTopologyActivationAuthority retained(
            std::move(pending));
        auto failure = RegisteredPersistentFreshTrialActivationBridge::
            abort_topology(std::move(retained));
        auto evidence = failure.test_only_take_process_abort_evidence();
        require_complete_abort(evidence, true);
        refuses([&] {
            (void)RegisteredPersistentFreshTrialActivationBridge::
                abort_topology(std::move(retained));
        });
    }
    assert(open_descriptor_count() == before);
}

void post_settle_bad_alloc_keeps_abort_evidence() {
    const unsigned before = open_descriptor_count();
    {
        auto result = RegisteredPersistentFreshTrialActivationBridge::
            activate(genuine_causal_activation());
        auto pending = std::move(result).take_topology_activation();
        RegisteredPersistentFreshTrialActivationBridge::
            test_only_set_post_settle_hook(arm_allocation_failure);
        try {
            auto failure = RegisteredPersistentFreshTrialActivationBridge::
                abort_topology(std::move(pending));
            fail_allocations = false;
            RegisteredPersistentFreshTrialActivationBridge::
                test_only_set_post_settle_hook(nullptr);
            auto evidence = failure.test_only_take_process_abort_evidence();
            require_complete_abort(evidence, true);
        } catch (...) {
            fail_allocations = false;
            RegisteredPersistentFreshTrialActivationBridge::
                test_only_set_post_settle_hook(nullptr);
            throw;
        }
    }
    assert(open_descriptor_count() == before);
}

void partial_scm_send_returns_typed_settled_failure() {
    const unsigned before = open_descriptor_count();
    {
        RegisteredPersistentFreshTrialActivationBridge::
            test_only_set_process_hook(close_round2_role0);
        auto result = RegisteredPersistentFreshTrialActivationBridge::
            activate(genuine_causal_activation());
        RegisteredPersistentFreshTrialActivationBridge::
            test_only_set_process_hook(nullptr);
        assert(!result.topology_prepared());
        auto failure = std::move(result).take_failure_residual();
        auto evidence = failure.test_only_take_process_abort_evidence();
        require_complete_abort(evidence, false);
    }
    assert(open_descriptor_count() == before);
}

void partial_scm_ack_returns_typed_settled_failure() {
    const unsigned before = open_descriptor_count();
    {
        RegisteredPersistentFreshTrialActivationBridge::
            test_only_set_process_hook(fail_round2_role1_ack);
        auto result = RegisteredPersistentFreshTrialActivationBridge::
            activate(genuine_causal_activation());
        RegisteredPersistentFreshTrialActivationBridge::
            test_only_set_process_hook(nullptr);
        assert(!result.topology_prepared());
        auto failure = std::move(result).take_failure_residual();
        auto evidence = failure.test_only_take_process_abort_evidence();
        require_complete_abort(evidence, false);
    }
    assert(open_descriptor_count() == before);
}

void status_remains_closed() {
    const auto status = parent_role_fork_source_status();
    assert(status.pre_identity_process_reservation);
    assert(status.process_settled_abort_noalloc);
    assert(!status.typed_complete_activation_abort);
    assert(!status.post_reservation_trial_activation);
    assert(!status.registered_driver_configured);
    assert(!status.launch_authorized);
    assert(!kFreshTrialCaptureTopologyReservationSourceStatus.
               selected_parent_callsite);
    static_assert(!std::is_invocable_v<
        decltype(&RegisteredPersistentFreshTrialActivationBridge::activate),
        FreshOwnerPersistentActivationAuthority&&,
        ParentRoleForkPlanAuthority&&>);
}

int sealed_source(std::string_view bytes, bool executable) {
    const int writer = ::memfd_create(
        executable ? "kpb-selected-worker" : "kpb-selected-source",
        MFD_CLOEXEC | MFD_ALLOW_SEALING);
    assert(writer >= 0);
    std::size_t offset{};
    while (offset < bytes.size()) {
        const auto count = ::write(writer, bytes.data() + offset,
                                   bytes.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        assert(count > 0);
        offset += static_cast<std::size_t>(count);
    }
    assert(::fchmod(writer, executable ? 0500 : 0400) == 0);
    assert(::fcntl(writer, F_ADD_SEALS,
                   F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK |
                       F_SEAL_SEAL) == 0);
    const auto path = std::string("/proc/self/fd/") +
        std::to_string(writer);
    const int reader = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    assert(reader >= 0);
    ::close(writer);
    return reader;
}

void selected_activation_burns_invalid_full_plan_and_aborts_stage1() {
    const unsigned before = open_descriptor_count();
    {
        static constexpr std::string_view selection{
            "exact-selected-diagnostic-source\n"};
        RegisteredSelectedProducerPrelaunchPlan plan;
        plan.capture_trial_id = std::string(TRIAL_UUID);
        plan.comparison_selection = identity_registry::digest(
            std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(selection.data()),
                selection.size()));
        const int selection_fd = sealed_source(selection, false);
        const int worker_fd = sealed_source("not-reached-worker", true);
        auto source = kpb::measurement::score_output_lineage_source::
            SelectedOwnerScoreLineagePrelaunchSourceTestBridge::mint(
                std::move(plan), selection_fd, worker_fd);
        auto policy = kpb::measurement::prelaunch_policy_domain::
            RegisteredPrelaunchPolicyDomainSourceBridge::acquire();
        auto result = RegisteredSelectedParentOrchestrator::
            activate_selected_prelaunch(
            genuine_causal_activation(), std::move(policy),
            std::move(source));
        bool refused{};
        try {
            (void)kpb::measurement::p1_state::
                P1StateCapsulePrelaunchCompilerBridge::compile(
                    std::move(result));
        } catch (...) {
            refused = true;
        }
        assert(refused);
    }
    assert(open_descriptor_count() == before);
}

Digest hash_text(std::string_view value) {
    return identity_registry::digest(std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(value.data()),
        value.size()));
}

kpb::measurement::WorkerBinding manifest_worker(
        const kpb::measurement::ManifestEntry& entry) {
    return {
        .source_identity = entry.source_identity,
        .build_identity = entry.build_identity,
        .runtime_identity = entry.runtime_identity,
        .assets_identity = entry.assets_identity,
        .pinned_executable_identity = entry.pinned_executable_identity,
        .launcher_identity = entry.launcher_identity,
    };
}

RegisteredSelectedProducerPrelaunchPlan selected_plan(
        std::string_view selection) {
    using kpb::measurement::ManifestComponent;
    RegisteredSelectedProducerPrelaunchPlan plan;
    plan.comparison_selection = hash_text(selection);
    plan.run_selection = hash_text(
        "{\"schema\":\"kpb-source-owned-diagnostic-run/v1\","
        "\"selected\":true}\n");
    plan.capture_trial_id = std::string(TRIAL_UUID);
    plan.measurement_attempt =
        kpb::measurement::score_output_lineage_source::
            measurement_attempt_from_outer_ascii(
                "actual-candidate-attempt-01");
    plan.measurement_cohort = id(0x601);
    plan.capture = id(0x602);
    plan.method = hash_text("frozen-method");
    plan.workload = id(0x603);
    plan.source_closure = hash_text("source-closure");
    plan.runtime = hash_text("runtime-closure");
    for (unsigned index = 0; index < plan.finite_manifest.entries.size();
         ++index) {
        const unsigned seed = 0x700 + index * 10;
        plan.finite_manifest.entries[index] = {
            .component = static_cast<ManifestComponent>(index + 1),
            .source_identity = id(seed),
            .build_identity = id(seed + 1),
            .runtime_identity = id(seed + 2),
            .assets_identity = id(seed + 3),
            .pinned_executable_identity = id(seed + 4),
            .launcher_identity = id(seed + 5),
        };
    }
    plan.finite_manifest.manifest_identity =
        kpb::measurement::recompute_finite_manifest_identity(
            plan.finite_manifest.entries);
    plan.finite_manifest.parent_recomputation_identity = id(0x604);
    plan.outer_parent_process = id(0x605);
    plan.outer_parent_executable = id(0x606);
    const auto& p1 = plan.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::P1Capture) - 1];
    plan.capture_source = p1.source_identity;
    plan.capture_build = p1.build_identity;
    plan.capture_runtime = p1.runtime_identity;
    plan.capture_launcher = p1.launcher_identity;
    plan.observer_worker = manifest_worker(plan.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Observer) - 1]);
    plan.score_worker = manifest_worker(plan.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::OwnerScore) - 1]);
    plan.aggregate_worker = manifest_worker(plan.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Aggregate) - 1]);
    plan.financial_runs = {id(0x610), id(0x611)};
    plan.capture_attempt_ids = {
        "33333333-3333-4333-8333-333333333333",
        "44444444-4444-4444-8444-444444444444",
    };
    for (unsigned round = 0; round < 2; ++round) {
        plan.round_attempts[round] =
            RegisteredCapturePlanRosterBridge::attempt_identity(
                plan.capture_attempt_ids[round]);
        plan.round_cohorts[round] = id(0x620 + round);
        plan.round_capture_plans[round] = id(0x630 + round);
        plan.fork_plan_identities[round] = id(0x640 + round);
        plan.route_policies[round] = {
            .round = round + 1,
            .route_capability_identity = id(0x650 + round),
            .projection_bytes = 10685,
            .route_endpoint_count = 1,
            .owner_ack_count = 0,
            .role_blind_required = true,
            .after_full_cohort_barrier_required = true,
            .owner_socket_or_path_derivation_forbidden = true,
        };
    }
    plan.producer_process_identity = plan.outer_parent_process;
    plan.role_closure_identity = id(0x660);
    plan.manifest_seal = plan.finite_manifest.manifest_identity;
    plan.construction_policy =
        kpb::measurement::ConstructionPolicy::SecretPermutationIndependent;
    plan.construction_classification_receipt = id(0x661);
    for (unsigned slot = 0; slot < plan.streams.size(); ++slot) {
        plan.streams[slot] = {
            .round = slot / 5 + 1,
            .kind = static_cast<kpb::measurement::CaptureKind>(slot % 5 + 1),
            .fixed_fd = slot + 20,
            .process_identity = id(0x680 + slot),
            .expected_exit_policy_identity = id(0x690 + slot),
        };
    }
    return plan;
}

void selected_activation_owns_topology_policy_source_prep_and_lineage(
        const char* worker_path) {
    const unsigned before = open_descriptor_count();
    {
        static constexpr std::string_view selection{
            "exact-diagnostic-selection\n"};
        const int selection_fd = sealed_source(selection, false);
        const int worker_source = ::open(worker_path, O_RDONLY | O_CLOEXEC);
        assert(worker_source >= 0);
        struct stat worker_info{};
        assert(::fstat(worker_source, &worker_info) == 0 &&
               worker_info.st_size > 0);
        std::string worker_bytes(
            static_cast<std::size_t>(worker_info.st_size), '\0');
        std::size_t at{};
        while (at < worker_bytes.size()) {
            const auto count = ::pread(
                worker_source, worker_bytes.data() + at,
                worker_bytes.size() - at, static_cast<off_t>(at));
            if (count < 0 && errno == EINTR) continue;
            assert(count > 0);
            at += static_cast<std::size_t>(count);
        }
        ::close(worker_source);
        const int worker_fd = sealed_source(worker_bytes, true);
        auto source = kpb::measurement::score_output_lineage_source::
            SelectedOwnerScoreLineagePrelaunchSourceTestBridge::mint(
                selected_plan(selection), selection_fd, worker_fd);
        auto policy = kpb::measurement::prelaunch_policy_domain::
            RegisteredPrelaunchPolicyDomainSourceBridge::acquire();
        auto result = RegisteredSelectedParentOrchestrator::
            activate_selected_prelaunch(
            genuine_causal_activation(), std::move(policy),
            std::move(source));
        auto unavailable = kpb::measurement::p1_state::
            P1StateCapsulePrelaunchCompilerBridge::compile(
                std::move(result));
        bool replay_refused{};
        try {
            (void)kpb::measurement::p1_state::
                P1StateCapsulePrelaunchCompilerBridge::compile(
                    std::move(result));
        } catch (...) {
            replay_refused = true;
        }
        assert(replay_refused);
        (void)unavailable;
    }
    assert(open_descriptor_count() == before);
}

kpb::measurement::score_output_lineage_source::
SelectedOwnerScoreLineagePrelaunchSourceAuthority selected_source(
        RegisteredSelectedProducerPrelaunchPlan plan,
        std::string_view selection) {
    return kpb::measurement::score_output_lineage_source::
        SelectedOwnerScoreLineagePrelaunchSourceTestBridge::mint(
            std::move(plan), sealed_source(selection, false),
            sealed_source("not-reached-worker", true));
}

void selected_activation_cross_trial_refuses_and_aborts_stage1() {
    const unsigned before = open_descriptor_count();
    {
        static constexpr std::string_view selection{
            "exact-diagnostic-selection\n"};
        auto plan = selected_plan(selection);
        plan.capture_trial_id =
            "22222222-2222-4222-8222-222222222222";
        auto source = selected_source(std::move(plan), selection);
        auto policy = kpb::measurement::prelaunch_policy_domain::
            RegisteredPrelaunchPolicyDomainSourceBridge::acquire();
        auto result = RegisteredSelectedParentOrchestrator::
            activate_selected_prelaunch(
                genuine_causal_activation(), std::move(policy),
                std::move(source));
        bool refused{};
        try {
            (void)kpb::measurement::p1_state::
                P1StateCapsulePrelaunchCompilerBridge::compile(
                    std::move(result));
        } catch (...) {
            refused = true;
        }
        assert(refused);
    }
    assert(open_descriptor_count() == before);
}

void selected_activation_replay_burns_each_linear_half() {
    const unsigned before = open_descriptor_count();
    {
        static constexpr std::string_view selection{
            "replay-diagnostic-selection\n"};
        RegisteredSelectedProducerPrelaunchPlan invalid;
        invalid.capture_trial_id = std::string(TRIAL_UUID);
        invalid.comparison_selection = hash_text(selection);
        auto source = selected_source(std::move(invalid), selection);
        auto policy = kpb::measurement::prelaunch_policy_domain::
            RegisteredPrelaunchPolicyDomainSourceBridge::acquire();
        auto first = RegisteredSelectedParentOrchestrator::
            activate_selected_prelaunch(
                genuine_causal_activation(), std::move(policy),
                std::move(source));
        bool first_refused{};
        try {
            (void)kpb::measurement::p1_state::
                P1StateCapsulePrelaunchCompilerBridge::compile(
                    std::move(first));
        } catch (...) {
            first_refused = true;
        }
        assert(first_refused);

        auto second = RegisteredSelectedParentOrchestrator::
            activate_selected_prelaunch(
                genuine_causal_activation(), std::move(policy),
                std::move(source));
        bool second_refused{};
        try {
            (void)kpb::measurement::p1_state::
                P1StateCapsulePrelaunchCompilerBridge::compile(
                    std::move(second));
        } catch (...) {
            second_refused = true;
        }
        assert(second_refused);
    }
    assert(open_descriptor_count() == before);
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 3);
    const std::string_view selected = argv[1];
    if (selected == "prepared-abort")
        prepared_topology_retains_exact_state_and_aborts_typed();
    else if (selected == "mismatched-writer")
        swapped_topology_writer_refuses_before_issuance_claim();
    else if (selected == "post-ack-close")
        post_ack_channel_close_settles_every_pidfd_child();
    else if (selected == "residual-replay")
        moved_pending_and_result_replay_refuse();
    else if (selected == "post-settle-bad-alloc")
        post_settle_bad_alloc_keeps_abort_evidence();
    else if (selected == "partial-scm-rights")
        partial_scm_send_returns_typed_settled_failure();
    else if (selected == "partial-scm-ack")
        partial_scm_ack_returns_typed_settled_failure();
    else if (selected == "parent-re-report")
        retained_command_fault_returns_typed_settled_failure(
            ParentRoleReservationRetentionTestFault::WrongParentReport,
            true);
    else if (selected == "replayed-command")
        retained_command_fault_returns_typed_settled_failure(
            ParentRoleReservationRetentionTestFault::
                ReplayActivationCommand,
            true);
    else if (selected == "swapped-slot")
        retained_command_fault_returns_typed_settled_failure(
            ParentRoleReservationRetentionTestFault::SwappedCaptureSlot,
            false);
    else if (selected == "swapped-round")
        retained_command_fault_returns_typed_settled_failure(
            ParentRoleReservationRetentionTestFault::SwappedRound,
            false);
    else if (selected == "same-fd-wrong-metadata")
        retained_command_fault_returns_typed_settled_failure(
            ParentRoleReservationRetentionTestFault::SameFdWrongMetadata,
            false);
    else if (selected == "metadata-drop-after-ack")
        retained_command_fault_returns_typed_settled_failure(
            ParentRoleReservationRetentionTestFault::DropMetadataAfterAck,
            true);
    else if (selected == "status")
        status_remains_closed();
    else if (selected == "selected-invalid-plan")
        selected_activation_burns_invalid_full_plan_and_aborts_stage1();
    else if (selected == "selected-source-success")
        selected_activation_owns_topology_policy_source_prep_and_lineage(
            argv[2]);
    else if (selected == "selected-cross-trial")
        selected_activation_cross_trial_refuses_and_aborts_stage1();
    else if (selected == "selected-replay")
        selected_activation_replay_burns_each_linear_half();
    else
        return 2;
    return 0;
}
