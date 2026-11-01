#include "privacy_p1_state_capsule_prelaunch_compiler_contract.hpp"

#include "privacy_p1_corrupt_state_capsule_authority.hpp"
#include "privacy_p1_mascot_abort_terminal_manifest_authority.hpp"
#include "privacy_p1_mascot_fresh_prep_directory_authority.hpp"
#include "privacy_p1_mascot_two_round_manifest_authority.hpp"
#include "privacy_prelaunch_policy_domain_authority.hpp"
#include "../mpc-prover/financial/registered_selected_producer_activation_contract.hpp"
#include "../mpc-prover/financial/registered_selected_producer_run_binding.hpp"

#include <algorithm>
#include <optional>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace kpb::measurement::p1_state {

namespace capsule = kpb::measurement::p1_state_capsule;
namespace policy = kpb::measurement::prelaunch_policy_domain;
namespace registered = kpi::mpc::financial::registered_driver;
using Digest = kpb::measurement::Digest;
using Family = capsule::StateFamily;
using Disposition = capsule::SourceFamilyDisposition;
using SelectedPlan = registered::RegisteredSelectedProducerPrelaunchPlan;

struct P1HookSerializerManifestAuthority::Storage final {
    std::array<std::array<Disposition, capsule::STATE_FAMILY_COUNT>, 2>
        dispositions{};
    std::array<std::array<Digest, capsule::STATE_FAMILY_COUNT>, 2>
        serializers{};
    std::array<std::array<capsule::FamilyHookInventory,
                          capsule::STATE_FAMILY_COUNT>, 2> inventories{};
    std::array<Digest, 2> manifest_identities{};
    P1MascotTwoRoundCompilerBinding mascot_binding{};
    std::optional<P1MascotTwoRoundManifestAuthority> mascot;
    bool compiler_consumed{};
};

struct P1AbortTerminalManifestAuthority::Storage final {
    std::array<std::vector<capsule::AbortTerminalHookInventory>, 2>
        terminals{};
    std::array<Digest, 2> hook_manifest_identities{};
    std::array<Digest, 2> manifest_identities{};
    P1MascotAbortTerminalCompilerBinding mascot_binding{};
    std::optional<P1MascotAbortTerminalManifestAuthority> mascot;
    bool compiler_consumed{};
};

struct P1StateCapsulePrelaunchUnavailableAuthority::Storage final {
    // The fresh directory can occupy any one of the first three fields while
    // compilation advances. The activation is declared last so reverse
    // destruction always settles its persistent topology before any holder
    // can recursively remove PREP_DIR, including every exception path.
    std::optional<P1MascotFreshPrepDirectoryAuthority> pending_fresh;
    std::optional<P1MascotTwoRoundManifestAuthority> pending_mascot;
    std::optional<P1HookSerializerManifestAuthority> hook_manifest;
    std::optional<P1MascotAbortTerminalManifestAuthority> pending_abort;
    std::optional<P1AbortTerminalManifestAuthority> abort_manifest;
    Digest prelaunch_binding_identity{};
    std::uint8_t missing_epoch_authority_bitmap{};
    std::optional<registered::RegisteredSelectedProducerActivationAuthority>
        activation;
};

namespace {

constexpr std::uint8_t MISSING_PERSISTENT_CHILD_EPOCH_AUTHORITY = 1U << 0;
constexpr std::uint8_t MISSING_CONTEXT_ALLOCATION_EPOCH_AUTHORITY = 1U << 1;
constexpr std::uint8_t ALL_MISSING_EPOCH_AUTHORITIES =
    MISSING_PERSISTENT_CHILD_EPOCH_AUTHORITY |
    MISSING_CONTEXT_ALLOCATION_EPOCH_AUTHORITY;

[[noreturn]] void refuse() {
    throw std::runtime_error("P1-state-capsule-prelaunch-compiler-refused");
}
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
        [](unsigned char byte) { return byte != 0; });
}

void append_u64(std::vector<unsigned char>& output, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        output.push_back(static_cast<unsigned char>(value >> shift));
}
void append_bytes(
        std::vector<unsigned char>& output,
        std::span<const unsigned char> value) {
    append_u64(output, value.size());
    output.insert(output.end(), value.begin(), value.end());
}
void append_text(std::vector<unsigned char>& output, std::string_view value) {
    append_bytes(output, std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
}
void append_digest(std::vector<unsigned char>& output, const Digest& value) {
    append_bytes(output, value);
}
Digest finish_hash(std::vector<unsigned char>& bytes) {
    Digest result{};
    const bool complete = ::SHA256(
        bytes.data(), bytes.size(), result.data()) != nullptr;
    if (!bytes.empty()) OPENSSL_cleanse(bytes.data(), bytes.size());
    need(complete && nonzero(result));
    return result;
}
Digest domain_hash(
        std::string_view domain, const Digest& value,
        std::uint64_t ordinal = 0) {
    std::vector<unsigned char> bytes;
    append_text(bytes, domain);
    append_digest(bytes, value);
    append_u64(bytes, ordinal);
    return finish_hash(bytes);
}

void append_inventory(
        std::vector<unsigned char>& bytes,
        const capsule::FamilyHookInventory& value) {
    append_u64(bytes, value.exact_object_count);
    append_u64(bytes, value.exact_event_count);
    append_u64(bytes, value.exact_transition_count);
    append_u64(bytes, value.required_transition_bitmap);
    append_digest(bytes, value.ordered_hook_manifest_identity);
    append_digest(bytes, value.expected_event_sequence_identity);
    append_digest(bytes, value.expected_transition_sequence_identity);
}

Digest hook_manifest_identity(
        unsigned round,
        const P1MascotTwoRoundCompilerBinding& mascot,
        const std::array<Disposition, capsule::STATE_FAMILY_COUNT>&
            dispositions,
        const std::array<Digest, capsule::STATE_FAMILY_COUNT>& serializers,
        const std::array<capsule::FamilyHookInventory,
                         capsule::STATE_FAMILY_COUNT>& inventories) {
    std::vector<unsigned char> bytes;
    append_text(bytes, "KPB_P1_HOOK_SERIALIZER_SOURCE_MANIFEST_V1\n");
    append_u64(bytes, round);
    append_digest(bytes, mascot.two_round_manifest_identity);
    append_u64(bytes, mascot.abort_unlink_terminal_manifest_complete);
    append_u64(bytes, mascot.ot_worker_terminal_manifest_complete);
    for (unsigned index = 0; index < capsule::STATE_FAMILY_COUNT; ++index) {
        append_u64(bytes, index + 1);
        append_u64(bytes, static_cast<unsigned>(dispositions[index]));
        append_digest(bytes, serializers[index]);
        append_inventory(bytes, inventories[index]);
    }
    return finish_hash(bytes);
}

capsule::AbortFamilyHookInventory not_constructed(Family family) {
    return {
        .disposition = capsule::AbortFamilyDisposition::NotConstructed,
        .expected_event_sequence_identity =
            capsule::recompute_family_event_sequence_identity(family, {}),
        .expected_transition_sequence_identity =
            capsule::recompute_family_transition_sequence_identity(
                family, {}),
    };
}

Digest construction_policy_identity(const SelectedPlan& selected) {
    std::vector<unsigned char> bytes;
    append_text(bytes, "KPB_P1_CONSTRUCTION_POLICY_BINDING_V1\n");
    append_u64(bytes, static_cast<unsigned>(selected.classification));
    append_u64(bytes, static_cast<unsigned>(selected.construction_policy));
    append_digest(bytes, selected.construction_classification_receipt);
    return finish_hash(bytes);
}

Digest route_policy_identity(const SelectedPlan& selected) {
    std::vector<unsigned char> bytes;
    append_text(bytes, "KPB_P1_ROUTE_POLICY_BINDING_V1\n");
    for (const auto& route : selected.route_policies) {
        append_u64(bytes, route.round);
        append_digest(bytes, route.route_capability_identity);
        append_u64(bytes, route.projection_bytes);
        append_u64(bytes, route.route_endpoint_count);
        append_u64(bytes, route.owner_ack_count);
        append_u64(bytes, route.role_blind_required);
        append_u64(bytes, route.after_full_cohort_barrier_required);
        append_u64(bytes,
            route.owner_socket_or_path_derivation_forbidden);
    }
    return finish_hash(bytes);
}

Digest stream_policy_identity(const SelectedPlan& selected) {
    std::vector<unsigned char> bytes;
    append_text(bytes, "KPB_P1_STREAM_POLICY_BINDING_V1\n");
    for (const auto& stream : selected.streams) {
        append_u64(bytes, stream.round);
        append_u64(bytes, static_cast<unsigned>(stream.kind));
        append_u64(bytes, stream.fixed_fd);
        append_digest(bytes, stream.process_identity);
        append_digest(bytes, stream.expected_exit_policy_identity);
    }
    return finish_hash(bytes);
}

capsule::P1StateCapsulePrelaunchBinding prelaunch_binding(
        const SelectedPlan& selected) {
    capsule::P1StateCapsulePrelaunchBinding result{
        .classification = selected.classification,
        .comparison_selection = selected.comparison_selection,
        .run_selection = selected.run_selection,
        .capture_trial_id = selected.capture_trial_id,
        .trial = selected.trial,
        .measurement_attempt = selected.measurement_attempt,
        .measurement_cohort = selected.measurement_cohort,
        .capture = selected.capture,
        .method = selected.method,
        .workload = selected.workload,
        .source_closure = selected.source_closure,
        .runtime = selected.runtime,
        .finite_manifest = selected.finite_manifest,
        .outer_parent_process = selected.outer_parent_process,
        .outer_parent_executable = selected.outer_parent_executable,
        .capture_source = selected.capture_source,
        .capture_build = selected.capture_build,
        .capture_runtime = selected.capture_runtime,
        .capture_launcher = selected.capture_launcher,
        .observer_worker = selected.observer_worker,
        .score_worker = selected.score_worker,
        .aggregate_worker = selected.aggregate_worker,
        .financial_runs = selected.financial_runs,
        .capture_attempt_ids = selected.capture_attempt_ids,
        .round_attempts = selected.round_attempts,
        .round_cohorts = selected.round_cohorts,
        .round_capture_plans = selected.round_capture_plans,
        .process_reservation_identity =
            selected.process_reservation_identity,
        .persistent_process_session_identity =
            selected.persistent_process_session_identity,
        .fork_plan_identities = selected.fork_plan_identities,
        .producer_process_identity = selected.producer_process_identity,
        .role_closure_identity = selected.role_closure_identity,
        .manifest_seal = selected.manifest_seal,
        .construction_policy_identity =
            construction_policy_identity(selected),
        .construction_classification_receipt =
            selected.construction_classification_receipt,
        .route_policy_identity = route_policy_identity(selected),
        .stream_policy_identity = stream_policy_identity(selected),
    };
    result.binding_identity =
        capsule::recompute_p1_state_capsule_prelaunch_binding_identity(
            result);
    return result;
}

template<class HookStorage>
void validate_hook_manifest_schema(const HookStorage& storage) {
    need(!storage.compiler_consumed &&
         storage.mascot_binding.two_round_manifest_identity != Digest{} &&
         storage.mascot_binding.branches[0] ==
             kpi::mpc::p1_private_state::MascotCacheBranch::
                 RegeneratedAfterMissing &&
         storage.mascot_binding.branches[1] ==
             kpi::mpc::p1_private_state::MascotCacheBranch::CacheHit &&
         !storage.mascot_binding.abort_unlink_terminal_manifest_complete &&
         !storage.mascot_binding.ot_worker_terminal_manifest_complete);
    for (unsigned round = 0; round < 2; ++round) {
        for (unsigned index = 0; index < capsule::STATE_FAMILY_COUNT;
             ++index) {
            const auto family = static_cast<Family>(index + 1);
            need(storage.dispositions[round][index] ==
                     Disposition::Missing &&
                 storage.serializers[round][index] ==
                     capsule::canonical_missing_family_serializer_identity(
                         family) &&
                 storage.inventories[round][index] ==
                     capsule::canonical_missing_family_hook_inventory(
                         family));
        }
        need(storage.manifest_identities[round] == hook_manifest_identity(
            round + 1, storage.mascot_binding,
            storage.dispositions[round], storage.serializers[round],
            storage.inventories[round]));
    }
}

template<class HookStorage>
void validate_hook_manifest(const HookStorage& storage) {
    need(storage.mascot.has_value());
    validate_hook_manifest_schema(storage);
}

template<class AbortStorage, class HookStorage>
void validate_abort_manifest_schema(
        const AbortStorage& storage, const HookStorage& hook) {
    need(!storage.compiler_consumed &&
         storage.mascot_binding.combined_manifest_identity != Digest{} &&
         storage.mascot_binding.exact_unlink_outcome &&
         storage.mascot_binding.exact_returned_worker_epochs &&
         storage.mascot_binding.constructor_failure_join &&
         !storage.mascot_binding.stuck_worker_terminal_closure &&
         !storage.mascot_binding.selected_callsite);
    for (unsigned round = 0; round < 2; ++round) {
        need(storage.hook_manifest_identities[round] ==
                 hook.manifest_identities[round] &&
             storage.terminals[round].size() == 1 &&
             capsule::recompute_abort_terminal_manifest_identity(
                 storage.terminals[round]) ==
                 storage.manifest_identities[round]);
        const auto& terminal = storage.terminals[round].front();
        need(terminal.phase == capsule::SourcePhase::RecorderStarted &&
             terminal.abort_class == capsule::AbortClass::Resource);
        for (unsigned index = 0; index < capsule::STATE_FAMILY_COUNT;
             ++index)
            need(terminal.families[index] == not_constructed(
                static_cast<Family>(index + 1)));
    }
}

template<class AbortStorage, class HookStorage>
void validate_abort_manifest(
        const AbortStorage& storage, const HookStorage& hook) {
    need(storage.mascot.has_value());
    validate_abort_manifest_schema(storage, hook);
}

} // namespace

P1HookSerializerManifestAuthority::P1HookSerializerManifestAuthority(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {}
P1HookSerializerManifestAuthority::P1HookSerializerManifestAuthority(
        P1HookSerializerManifestAuthority&&) noexcept = default;
P1HookSerializerManifestAuthority::~P1HookSerializerManifestAuthority() =
    default;

P1AbortTerminalManifestAuthority::P1AbortTerminalManifestAuthority(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {}
P1AbortTerminalManifestAuthority::P1AbortTerminalManifestAuthority(
        P1AbortTerminalManifestAuthority&&) noexcept = default;
P1AbortTerminalManifestAuthority::~P1AbortTerminalManifestAuthority() =
    default;

P1StateCapsulePrelaunchUnavailableAuthority::
P1StateCapsulePrelaunchUnavailableAuthority(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {}
P1StateCapsulePrelaunchUnavailableAuthority::
P1StateCapsulePrelaunchUnavailableAuthority(
        P1StateCapsulePrelaunchUnavailableAuthority&&) noexcept = default;
P1StateCapsulePrelaunchUnavailableAuthority::
~P1StateCapsulePrelaunchUnavailableAuthority() = default;

P1HookSerializerManifestAuthority
P1HookSerializerManifestSourceBridge::mint(
        P1MascotTwoRoundManifestAuthority&& mascot) {
    auto storage =
        std::make_unique<P1HookSerializerManifestAuthority::Storage>();
    storage->mascot_binding = mascot.inspect_for_capsule_compiler();
    for (unsigned round = 0; round < 2; ++round) {
        for (unsigned index = 0; index < capsule::STATE_FAMILY_COUNT;
             ++index) {
            const auto family = static_cast<Family>(index + 1);
            storage->dispositions[round][index] = Disposition::Missing;
            storage->serializers[round][index] =
                capsule::canonical_missing_family_serializer_identity(
                    family);
            storage->inventories[round][index] =
                capsule::canonical_missing_family_hook_inventory(family);
        }
        storage->manifest_identities[round] = hook_manifest_identity(
            round + 1, storage->mascot_binding,
            storage->dispositions[round], storage->serializers[round],
            storage->inventories[round]);
    }
    validate_hook_manifest_schema(*storage);
    mascot.claim_for_capsule_compiler(storage->mascot_binding);
    storage->mascot.emplace(std::move(mascot));
    return P1HookSerializerManifestAuthority(std::move(storage));
}

P1AbortTerminalManifestAuthority
P1AbortTerminalManifestSourceBridge::mint(
        P1MascotAbortTerminalManifestAuthority&& mascot,
        const P1HookSerializerManifestAuthority& hook) {
    need(hook.storage_ != nullptr);
    validate_hook_manifest(*hook.storage_);
    auto storage =
        std::make_unique<P1AbortTerminalManifestAuthority::Storage>();
    storage->mascot_binding = mascot.inspect_for_capsule_compiler();
    for (unsigned round = 0; round < 2; ++round) {
        capsule::AbortTerminalHookInventory terminal{
            .terminal_site_identity = domain_hash(
                "KPB_P1_CAPSULE_SOURCE_UNAVAILABLE_TERMINAL_V1\n",
                hook.storage_->manifest_identities[round], round + 1),
            .exception_type_identity = domain_hash(
                "KPB_P1_CAPSULE_SOURCE_UNAVAILABLE_EXCEPTION_V1\n",
                storage->mascot_binding.combined_manifest_identity,
                round + 1),
            .phase = capsule::SourcePhase::RecorderStarted,
            .abort_class = capsule::AbortClass::Resource,
        };
        for (unsigned index = 0; index < capsule::STATE_FAMILY_COUNT;
             ++index)
            terminal.families[index] = not_constructed(
                static_cast<Family>(index + 1));
        storage->terminals[round].push_back(std::move(terminal));
        storage->hook_manifest_identities[round] =
            hook.storage_->manifest_identities[round];
        storage->manifest_identities[round] =
            capsule::recompute_abort_terminal_manifest_identity(
                storage->terminals[round]);
    }
    validate_abort_manifest_schema(*storage, *hook.storage_);
    mascot.claim_for_capsule_compiler(storage->mascot_binding);
    storage->mascot.emplace(std::move(mascot));
    return P1AbortTerminalManifestAuthority(std::move(storage));
}

P1StateCapsulePrelaunchUnavailableAuthority
P1StateCapsulePrelaunchCompilerBridge::compile(
        registered::RegisteredSelectedProducerActivationResult&& result) {
    // The full activation is claimed before inspection. Its topology and
    // selected binding can neither be cross-paired with another PREP_DIR nor
    // outlive that directory on any success or failure path.
    auto storage = std::make_unique<
        P1StateCapsulePrelaunchUnavailableAuthority::Storage>();
    auto retained_result = std::move(result);
    storage->activation.emplace(
        std::move(retained_result)
            .claim_success_for_state_capsule_compiler());
    const auto& retained_selected =
        storage->activation->inspect_for_state_capsule_compiler();
    const auto& selected_plan =
        retained_selected.inspect_for_state_capsule_compiler();
    auto policy_source =
        policy::RegisteredPrelaunchPolicyDomainSourceBridge::acquire();
    policy::PolicyDigest accepted_policy{};
    policy::PolicyDigest selected_policy{};
    policy::PolicyDigest policy_manifest{};
    std::move(policy_source).consume_for_selected_activation(
        accepted_policy, selected_policy, policy_manifest);
    need(selected_plan.accepted_head_policy_identity == accepted_policy &&
         selected_plan.selected_main_policy_identity == selected_policy &&
         selected_plan.prelaunch_policy_manifest_identity ==
             policy_manifest);
    const auto prelaunch = prelaunch_binding(selected_plan);

    storage->pending_fresh.emplace(
        storage->activation->claim_mascot_for_state_capsule_compiler());
    storage->pending_mascot.emplace(
        P1MascotTwoRoundManifestCompilerBridge::compile(
            std::move(*storage->pending_fresh)));
    storage->pending_fresh.reset();
    storage->hook_manifest.emplace(
        P1HookSerializerManifestSourceBridge::mint(
            std::move(*storage->pending_mascot)));
    storage->pending_mascot.reset();
    storage->pending_abort.emplace(
        P1MascotAbortTerminalManifestCompilerBridge::compile());
    storage->abort_manifest.emplace(
        P1AbortTerminalManifestSourceBridge::mint(
            std::move(*storage->pending_abort),
            *storage->hook_manifest));
    storage->pending_abort.reset();
    auto& hook = *storage->hook_manifest;
    auto& abort = *storage->abort_manifest;

    validate_hook_manifest(*hook.storage_);
    validate_abort_manifest(*abort.storage_, *hook.storage_);

    // Both epoch values are mandatory for a real capsule plan, but neither
    // currently has a typed source in the selected activation. Preserve the
    // exact Missing manifests and the activation; never substitute a numeric
    // placeholder or mint a plan authority.
    need(nonzero(prelaunch.binding_identity));
    storage->prelaunch_binding_identity = prelaunch.binding_identity;
    storage->missing_epoch_authority_bitmap =
        ALL_MISSING_EPOCH_AUTHORITIES;
    hook.storage_->compiler_consumed = true;
    abort.storage_->compiler_consumed = true;
    return P1StateCapsulePrelaunchUnavailableAuthority(
        std::move(storage));
}

P1StateCapsulePrelaunchCompilerStatus
p1_state_capsule_prelaunch_compiler_status() noexcept {
    return {
        .hostile_bridge_substitution_rejected = true,
        .exact_future_type_vocabulary = true,
        .selected_prelaunch_required = true,
        .source_policy_domain_required = true,
        .fourteen_family_hook_serializer_manifest_required = true,
        .abort_terminal_manifest_required = true,
        .retained_producer_plus_two_round_plans_required = true,
        .role1_round1_round2_only_required = true,
        .writerless_before_topology_transfer_required = true,
        .stale_swapped_partial_replay_burn_controls_required = true,
        .macro_free_production_caller_static_plan_or_event_factory = false,
        .caller_defined_test_macro_unforgeability = false,
        .exact_macro_free_build_closure_required = true,
        .caller_digest_path_bytes_or_fd_input = false,
        .hook_serializer_manifest_source_minter = true,
        .abort_terminal_manifest_source_minter = true,
        .capsule_plan_compiler_implemented = false,
        .atomic_activation_split_implemented = false,
        .fail_closed_unavailable_authority_implemented = true,
        .missing_epoch_authorities_recorded = true,
        .stale_lineage_control = false,
        .swapped_round_control = false,
        .partial_manifest_control = false,
        .replay_burn_control = true,
        .selected_parent_callsite = false,
        .configured = false,
        .actual_plan_mint = false,
    };
}

} // namespace kpb::measurement::p1_state
