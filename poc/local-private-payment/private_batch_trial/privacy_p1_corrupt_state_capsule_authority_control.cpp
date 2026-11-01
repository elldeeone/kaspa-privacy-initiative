#include "privacy_p1_corrupt_state_capsule_authority.hpp"
#include "privacy_p1_corrupt_state_capsule_test_fixture.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <concepts>
#include <span>
#include <sys/stat.h>
#include <thread>
#include <utility>
#include <vector>

using namespace kpb::measurement;
using namespace kpb::measurement::p1_state_capsule;

namespace {

template<class Function>
void expect_refused(Function&& function) {
    bool refused = false;
    try { function(); } catch (const Refused&) { refused = true; }
    assert(refused);
}

Digest digest(unsigned char value) {
    Digest result{};
    result.fill(value);
    return result;
}

P1StateCapsulePrelaunchBinding binding(unsigned char offset = 0) {
    P1StateCapsulePrelaunchBinding result{};
    result.classification = Classification::HiddenCandidate;
    result.comparison_selection = digest(0x10 + offset);
    result.run_selection = digest(0x11 + offset);
    result.capture_trial_id =
        "00000000-0000-4000-8000-000000000001";
    result.trial = digest(0x12 + offset);
    result.measurement_attempt = digest(0x13 + offset);
    result.measurement_cohort = digest(0x14 + offset);
    result.capture = digest(0x15 + offset);
    result.method = digest(0x16 + offset);
    result.workload = digest(0x17 + offset);
    result.source_closure = digest(0x18 + offset);
    result.runtime = digest(0x19 + offset);
    result.outer_parent_process = digest(0x1a + offset);
    result.outer_parent_executable = digest(0x1b + offset);
    result.financial_runs = {
        digest(static_cast<unsigned char>(0x20 + offset)),
        digest(static_cast<unsigned char>(0x21 + offset))};
    result.round_attempts = {
        digest(static_cast<unsigned char>(0x22 + offset)),
        digest(static_cast<unsigned char>(0x23 + offset))};
    result.round_cohorts = {
        digest(static_cast<unsigned char>(0x24 + offset)),
        digest(static_cast<unsigned char>(0x25 + offset))};
    result.round_capture_plans = {
        digest(static_cast<unsigned char>(0x26 + offset)),
        digest(static_cast<unsigned char>(0x27 + offset))};
    result.capture_attempt_ids = {
        "00000000-0000-4000-8000-000000000002",
        "00000000-0000-4000-8000-000000000003"};
    result.process_reservation_identity = digest(0x28 + offset);
    result.persistent_process_session_identity = digest(0x29 + offset);
    result.fork_plan_identities = {
        digest(static_cast<unsigned char>(0x2a + offset)),
        digest(static_cast<unsigned char>(0x2b + offset))};
    result.producer_process_identity = digest(0x2c + offset);
    result.role_closure_identity = digest(0x2d + offset);
    result.manifest_seal = digest(0x2e + offset);
    result.construction_policy_identity = digest(0x2f + offset);
    result.construction_classification_receipt = digest(0x30 + offset);
    result.route_policy_identity = digest(0x31 + offset);
    result.stream_policy_identity = digest(0x32 + offset);
    for (unsigned index = 0;
         index < result.finite_manifest.entries.size(); ++index) {
        const auto seed = static_cast<unsigned char>(
            0x40 + offset + index * 7);
        result.finite_manifest.entries[index] = {
            .component = static_cast<ManifestComponent>(index + 1),
            .source_identity = digest(seed),
            .build_identity = digest(static_cast<unsigned char>(seed + 1)),
            .runtime_identity = digest(static_cast<unsigned char>(seed + 2)),
            .assets_identity = digest(static_cast<unsigned char>(seed + 3)),
            .pinned_executable_identity =
                digest(static_cast<unsigned char>(seed + 4)),
            .launcher_identity = digest(static_cast<unsigned char>(seed + 5)),
        };
    }
    result.finite_manifest.manifest_identity =
        recompute_finite_manifest_identity(result.finite_manifest.entries);
    result.finite_manifest.parent_recomputation_identity =
        digest(static_cast<unsigned char>(0xfc - offset));
    const auto worker = [](const ManifestEntry& entry) {
        return WorkerBinding{
            .source_identity = entry.source_identity,
            .build_identity = entry.build_identity,
            .runtime_identity = entry.runtime_identity,
            .assets_identity = entry.assets_identity,
            .pinned_executable_identity = entry.pinned_executable_identity,
            .launcher_identity = entry.launcher_identity,
        };
    };
    const auto& p1 = result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::P1Capture) - 1];
    result.capture_source = p1.source_identity;
    result.capture_build = p1.build_identity;
    result.capture_runtime = p1.runtime_identity;
    result.capture_launcher = p1.launcher_identity;
    result.observer_worker = worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Observer) - 1]);
    result.score_worker = worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::OwnerScore) - 1]);
    result.aggregate_worker = worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Aggregate) - 1]);
    result.binding_identity =
        recompute_p1_state_capsule_prelaunch_binding_identity(result);
    return result;
}

WorkerBinding p1_worker(const P1StateCapsulePrelaunchBinding& selected) {
    const auto& entry = selected.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::P1Capture) - 1];
    return {
        .source_identity = entry.source_identity,
        .build_identity = entry.build_identity,
        .runtime_identity = entry.runtime_identity,
        .assets_identity = entry.assets_identity,
        .pinned_executable_identity = entry.pinned_executable_identity,
        .launcher_identity = entry.launcher_identity,
    };
}

TransitionKind transition_for(StateFamily family);

Digest abort_site(
        unsigned char offset, SourcePhase phase, AbortClass abort_class) {
    return digest(static_cast<unsigned char>(
        0x30 + offset + 9 * static_cast<unsigned>(phase) +
        static_cast<unsigned>(abort_class)));
}

Digest abort_exception(
        unsigned char offset, SourcePhase phase, AbortClass abort_class) {
    return digest(static_cast<unsigned char>(
        0x70 + offset + 7 * static_cast<unsigned>(phase) +
        static_cast<unsigned>(abort_class)));
}

AbortFamilyHookInventory closed_abort_family(
        const FamilyHookInventory& value) {
    return {
        .disposition = AbortFamilyDisposition::Closed,
        .exact_object_count = value.exact_object_count,
        .exact_event_count = value.exact_event_count,
        .exact_transition_count = value.exact_transition_count,
        .required_transition_bitmap = value.required_transition_bitmap,
        .expected_event_sequence_identity =
            value.expected_event_sequence_identity,
        .expected_transition_sequence_identity =
            value.expected_transition_sequence_identity,
    };
}

AbortFamilyHookInventory not_constructed_abort_family(StateFamily family) {
    return {
        .disposition = AbortFamilyDisposition::NotConstructed,
        .expected_event_sequence_identity =
            recompute_family_event_sequence_identity(
                family, std::span<const HookEventDescriptor>{}),
        .expected_transition_sequence_identity =
            recompute_family_transition_sequence_identity(
                family, std::span<const HookTransitionDescriptor>{}),
    };
}

StaticStateCapsulePlan plan(unsigned char offset = 0) {
    auto selected = binding(offset);
    StaticStateCapsulePlan result{
        .prelaunch = selected,
        .round = 1,
        .role = 1,
        .p1_worker = p1_worker(selected),
        .accepted_head_plan_identity = digest(0x91 + offset),
        .selected_main_plan_identity = digest(0x92 + offset),
        .persistent_child_identity = digest(0x93 + offset),
        .persistent_child_epoch = static_cast<std::uint64_t>(10 + offset),
        .context_allocation_epoch = static_cast<std::uint64_t>(20 + offset),
        .source_hook_manifest_identity = digest(0x94 + offset),
        .mp_spdz_source_identity = digest(0x95 + offset),
        .simplest_ot_source_identity = digest(0x96 + offset),
        .libote_source_identity = digest(0x97 + offset),
        .crypto_tools_source_identity = digest(0x98 + offset),
        .openssl_source_identity = digest(0x99 + offset),
        .online_options_identity = digest(0x9a + offset),
        .mascot_secrets_policy_identity = digest(0x9b + offset),
        .topology_reservation_identity = digest(0x9c + offset),
        .archive_filesystem_identity = digest(0x9d + offset),
        .abort_terminals = {},
    };
    for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index) {
        result.source_family_dispositions[index] =
            SourceFamilyDisposition::Captured;
        result.serializer_identities[index] = digest(
            static_cast<unsigned char>(0xc0 + index + offset));
        const auto family = static_cast<StateFamily>(index + 1);
        const auto kind = transition_for(family);
        const auto counter_after =
            family == StateFamily::PlayerAllocation ? 1U : index + 1;
        const std::array events{HookTransitionDescriptor{
            .object_ordinal = 1,
            .kind = kind,
            .counter_before = 0,
            .counter_after = counter_after,
        }};
        const std::array hook_events{
            HookEventDescriptor{
                .object_ordinal = 1,
                .event_kind = HookEventKind::Construct,
            },
            HookEventDescriptor{
                .object_ordinal = 1,
                .event_kind = HookEventKind::Transition,
                .transition_kind = kind,
                .counter_before = 0,
                .counter_after = counter_after,
            },
            HookEventDescriptor{
                .object_ordinal = 1,
                .event_kind = HookEventKind::TerminalSnapshot,
                .counter_before = counter_after,
                .counter_after = counter_after,
            },
        };
        result.hook_inventory[index] = {
            .exact_object_count = 1,
            .exact_event_count = hook_events.size(),
            .exact_transition_count = 1,
            .required_transition_bitmap =
                std::uint64_t{1} << (static_cast<unsigned>(kind) - 1),
            .ordered_hook_manifest_identity = digest(
                static_cast<unsigned char>(0xe0 + index + offset)),
            .expected_event_sequence_identity =
                recompute_family_event_sequence_identity(
                    family, hook_events),
            .expected_transition_sequence_identity =
                recompute_family_transition_sequence_identity(family, events),
        };
    }
    {
        const auto family = StateFamily::MascotSecrets;
        const auto index = static_cast<unsigned>(family) - 1;
        const std::array transitions{
            HookTransitionDescriptor{
                .object_ordinal = 1,
                .kind = TransitionKind::ProtocolSetup,
                .counter_before = 0,
                .counter_after = 1,
            },
            HookTransitionDescriptor{
                .object_ordinal = 1,
                .kind = TransitionKind::ProtocolSetup,
                .counter_before = 1,
                .counter_after = 2,
            },
        };
        const std::array events{
            HookEventDescriptor{1, HookEventKind::Construct,
                                TransitionKind{}, 0, 0},
            HookEventDescriptor{1, HookEventKind::Transition,
                                TransitionKind::ProtocolSetup, 0, 1},
            HookEventDescriptor{1, HookEventKind::Transition,
                                TransitionKind::ProtocolSetup, 1, 2},
            HookEventDescriptor{1, HookEventKind::TerminalSnapshot,
                                TransitionKind{}, 2, 2},
        };
        result.hook_inventory[index] = {
            .exact_object_count = 1,
            .exact_event_count = events.size(),
            .exact_transition_count = transitions.size(),
            .required_transition_bitmap =
                std::uint64_t{1} <<
                    (static_cast<unsigned>(TransitionKind::ProtocolSetup) - 1),
            .ordered_hook_manifest_identity =
                recompute_mascot_secret_branch_manifest_identity(
                    kpi::mpc::p1_private_state::
                        MascotCacheBranch::StaticReuse),
            .expected_event_sequence_identity =
                recompute_family_event_sequence_identity(family, events),
            .expected_transition_sequence_identity =
                recompute_family_transition_sequence_identity(
                    family, transitions),
        };
    }
    for (const auto abort_class : {
             AbortClass::Protocol,
             AbortClass::Transport,
             AbortClass::Resource}) {
        AbortTerminalHookInventory terminal{
            .terminal_site_identity = abort_site(
                offset, SourcePhase::TlsAndPlayerBound, abort_class),
            .exception_type_identity = abort_exception(
                offset, SourcePhase::TlsAndPlayerBound, abort_class),
            .phase = SourcePhase::TlsAndPlayerBound,
            .abort_class = abort_class,
        };
        for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index) {
            const auto family = static_cast<StateFamily>(index + 1);
            terminal.families[index] =
                family == StateFamily::PlayerAllocation ||
                        family == StateFamily::TlsChannelState
                    ? closed_abort_family(result.hook_inventory[index])
                    : not_constructed_abort_family(family);
        }
        result.abort_terminals.push_back(std::move(terminal));
    }
    AbortTerminalHookInventory complete_terminal{
        .terminal_site_identity = abort_site(
            offset, SourcePhase::TerminalEgress, AbortClass::MacCheck),
        .exception_type_identity = abort_exception(
            offset, SourcePhase::TerminalEgress, AbortClass::MacCheck),
        .phase = SourcePhase::TerminalEgress,
        .abort_class = AbortClass::MacCheck,
    };
    for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index)
        complete_terminal.families[index] =
            closed_abort_family(result.hook_inventory[index]);
    result.abort_terminals.push_back(std::move(complete_terminal));
    result.abort_terminal_manifest_identity =
        recompute_abort_terminal_manifest_identity(result.abort_terminals);
    return result;
}

void refresh_closed_abort_families(StaticStateCapsulePlan& value) {
    for (auto& terminal : value.abort_terminals) {
        for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index) {
            if (terminal.families[index].disposition ==
                    AbortFamilyDisposition::Closed)
                terminal.families[index] =
                    closed_abort_family(value.hook_inventory[index]);
        }
    }
    value.abort_terminal_manifest_identity =
        recompute_abort_terminal_manifest_identity(value.abort_terminals);
}

Digest late_abort_site(unsigned char offset) {
    return digest(static_cast<unsigned char>(0x0f + offset));
}

Digest late_abort_exception(unsigned char offset) {
    return digest(static_cast<unsigned char>(0xa0 + offset));
}

P1AbortTerminalAuthority prepare_test_abort_terminal(
        P1CorruptStateRecorderAuthority& recorder,
        const Digest& terminal_site_identity, AbortClass abort_class,
        const Digest& exception_type_identity) {
    auto source_terminal = recorder.test_only_mint_abort_terminal_site(
        terminal_site_identity, abort_class, exception_type_identity);
    return recorder.prepare_abort_terminal(std::move(source_terminal));
}

StaticStateCapsulePlan late_abort_plan(unsigned char offset) {
    auto result = plan(offset);
    const auto index =
        static_cast<unsigned>(StateFamily::ContextAndRetry) - 1;
    const std::array transitions{
        HookTransitionDescriptor{
            .object_ordinal = 1,
            .kind = TransitionKind::ContextValidate,
            .counter_before = 0,
            .counter_after = 10,
        },
        HookTransitionDescriptor{
            .object_ordinal = 1,
            .kind = TransitionKind::ContextRetry,
            .counter_before = 10,
            .counter_after = 11,
        },
    };
    const std::array events{
        HookEventDescriptor{1, HookEventKind::Construct,
                            TransitionKind{}, 0, 0},
        HookEventDescriptor{1, HookEventKind::Transition,
                            TransitionKind::ContextValidate, 0, 10},
        HookEventDescriptor{1, HookEventKind::Transition,
                            TransitionKind::ContextRetry, 10, 11},
        HookEventDescriptor{1, HookEventKind::TerminalSnapshot,
                            TransitionKind{}, 11, 11},
    };
    auto& success = result.hook_inventory[index];
    success.exact_event_count = events.size();
    success.exact_transition_count = transitions.size();
    success.required_transition_bitmap =
        (std::uint64_t{1} <<
         (static_cast<unsigned>(TransitionKind::ContextValidate) - 1)) |
        (std::uint64_t{1} <<
         (static_cast<unsigned>(TransitionKind::ContextRetry) - 1));
    success.expected_event_sequence_identity =
        recompute_family_event_sequence_identity(
            StateFamily::ContextAndRetry, events);
    success.expected_transition_sequence_identity =
        recompute_family_transition_sequence_identity(
            StateFamily::ContextAndRetry, transitions);
    refresh_closed_abort_families(result);

    AbortTerminalHookInventory terminal{
        .terminal_site_identity = late_abort_site(offset),
        .exception_type_identity = late_abort_exception(offset),
        .phase = SourcePhase::ProtocolSetupStarted,
        .abort_class = AbortClass::Protocol,
    };
    for (unsigned family_index = 0;
         family_index < STATE_FAMILY_COUNT; ++family_index) {
        const auto family = static_cast<StateFamily>(family_index + 1);
        terminal.families[family_index] =
            family == StateFamily::Beaver ||
                    family == StateFamily::QueryMsmCheckerTemporaries
                ? not_constructed_abort_family(family)
                : closed_abort_family(result.hook_inventory[family_index]);
    }
    const std::array prefix_transitions{HookTransitionDescriptor{
        .object_ordinal = 1,
        .kind = TransitionKind::ContextValidate,
        .counter_before = 0,
        .counter_after = 10,
    }};
    const std::array prefix_events{
        HookEventDescriptor{1, HookEventKind::Construct,
                            TransitionKind{}, 0, 0},
        HookEventDescriptor{1, HookEventKind::Transition,
                            TransitionKind::ContextValidate, 0, 10},
        HookEventDescriptor{1, HookEventKind::TerminalSnapshot,
                            TransitionKind{}, 10, 10},
    };
    terminal.families[index] = {
        .disposition = AbortFamilyDisposition::TerminalPrefix,
        .exact_object_count = 1,
        .exact_event_count = prefix_events.size(),
        .exact_transition_count = prefix_transitions.size(),
        .required_transition_bitmap =
            std::uint64_t{1} <<
            (static_cast<unsigned>(TransitionKind::ContextValidate) - 1),
        .expected_event_sequence_identity =
            recompute_family_event_sequence_identity(
                StateFamily::ContextAndRetry, prefix_events),
        .expected_transition_sequence_identity =
            recompute_family_transition_sequence_identity(
                StateFamily::ContextAndRetry, prefix_transitions),
    };
    result.abort_terminals.push_back(std::move(terminal));
    result.abort_terminal_manifest_identity =
        recompute_abort_terminal_manifest_identity(result.abort_terminals);
    return result;
}

StaticStateCapsulePlan context_adapter_plan(unsigned char offset) {
    auto result = plan(offset);
    const auto index =
        static_cast<unsigned>(StateFamily::ContextAndRetry) - 1;
    const std::array transitions{
        HookTransitionDescriptor{1, TransitionKind::ContextValidate, 0, 1},
        HookTransitionDescriptor{1, TransitionKind::ContextRetry, 1, 2},
        HookTransitionDescriptor{1, TransitionKind::ContextPoison, 2, 3},
    };
    const std::array events{
        HookEventDescriptor{1, HookEventKind::Construct,
                            TransitionKind{}, 0, 0},
        HookEventDescriptor{1, HookEventKind::Transition,
                            TransitionKind::ContextValidate, 0, 1},
        HookEventDescriptor{1, HookEventKind::Transition,
                            TransitionKind::ContextRetry, 1, 2},
        HookEventDescriptor{1, HookEventKind::Transition,
                            TransitionKind::ContextPoison, 2, 3},
        HookEventDescriptor{1, HookEventKind::TerminalSnapshot,
                            TransitionKind{}, 3, 3},
    };
    auto& inventory = result.hook_inventory[index];
    inventory.exact_event_count = events.size();
    inventory.exact_transition_count = transitions.size();
    inventory.required_transition_bitmap =
        (std::uint64_t{1} <<
         (static_cast<unsigned>(TransitionKind::ContextValidate) - 1)) |
        (std::uint64_t{1} <<
         (static_cast<unsigned>(TransitionKind::ContextRetry) - 1)) |
        (std::uint64_t{1} <<
         (static_cast<unsigned>(TransitionKind::ContextPoison) - 1));
    inventory.expected_event_sequence_identity =
        recompute_family_event_sequence_identity(
            StateFamily::ContextAndRetry, events);
    inventory.expected_transition_sequence_identity =
        recompute_family_transition_sequence_identity(
            StateFamily::ContextAndRetry, transitions);
    refresh_closed_abort_families(result);
    return result;
}

StaticStateCapsulePlan mascot_adapter_plan(
        unsigned char offset,
        kpi::mpc::p1_private_state::MascotCacheBranch branch) {
    using Branch = kpi::mpc::p1_private_state::MascotCacheBranch;
    assert(branch != Branch::Undecided);
    auto result = context_adapter_plan(offset);
    const auto index = static_cast<unsigned>(StateFamily::MascotSecrets) - 1;
    result.hook_inventory[index] =
        recompute_mascot_secret_branch_inventory(branch);
    refresh_closed_abort_families(result);
    return result;
}

StaticStateCapsulePlan entropy_adapter_plan(unsigned char offset) {
    auto result = plan(offset);
    for (const auto family : {
             StateFamily::MpSpdzPrng,
             StateFamily::SimplestOtBase,
             StateFamily::CryptoToolsPrng}) {
        const auto index = static_cast<unsigned>(family) - 1;
        const std::array transitions{HookTransitionDescriptor{
            .object_ordinal = 1,
            .kind = TransitionKind::EntropySeed,
            .counter_before = 0,
            .counter_after = 1,
        }};
        const std::array events{
            HookEventDescriptor{1, HookEventKind::Construct,
                                TransitionKind{}, 0, 0},
            HookEventDescriptor{1, HookEventKind::Transition,
                                TransitionKind::EntropySeed, 0, 1},
            HookEventDescriptor{1, HookEventKind::TerminalSnapshot,
                                TransitionKind{}, 1, 1},
        };
        auto& inventory = result.hook_inventory[index];
        inventory.exact_object_count = 1;
        inventory.exact_event_count = events.size();
        inventory.exact_transition_count = transitions.size();
        inventory.required_transition_bitmap =
            std::uint64_t{1} <<
                (static_cast<unsigned>(TransitionKind::EntropySeed) - 1);
        inventory.expected_event_sequence_identity =
            recompute_family_event_sequence_identity(family, events);
        inventory.expected_transition_sequence_identity =
            recompute_family_transition_sequence_identity(
                family, transitions);
    }
    refresh_closed_abort_families(result);
    return result;
}

std::array<unsigned char, 48> snapshot(unsigned char value) {
    std::array<unsigned char, 48> result{};
    result.fill(value);
    return result;
}

void complete_static_mascot_family(
        P1CorruptStateRecorderAuthority& recorder,
        const P1StateThreadEpochAuthority& thread) {
    using namespace kpi::mpc::p1_private_state;
    auto adapter = recorder.take_mascot_secret_state_adapter(thread);
    const auto key = snapshot(0x39);
    const auto reset_key = snapshot(0x00);
    const auto scalar = snapshot(0x3a);
    constexpr std::string_view domain = "3-p-254/P1";
    constexpr std::string_view path = "Player-Data//Mascot-Secrets-p-P1";
    assert(MascotSecretStateSourceBridge::scalar_state_begin(
        domain, path, 1024, 4, 40, true, true, scalar, scalar));
    assert(MascotSecretStateSourceBridge::setup_begin(
        domain, path, 1024, 4, 40, true, true, true, key));
    assert(MascotSecretStateSourceBridge::static_installed(
        true, key, scalar, scalar, scalar));
    assert(MascotSecretStateSourceBridge::teardown(
        true, key, scalar, false, reset_key, scalar, scalar, scalar));
    adapter.reset();
}

kpi::mpc::p1_private_state::MascotFileMetadataView mascot_metadata(
        std::uint64_t size, std::uint64_t inode) {
    return {
        .present = true,
        .device = 7,
        .inode = inode,
        .mode = S_IFREG | S_IRUSR | S_IWUSR,
        .uid = 1000,
        .gid = 1000,
        .link_count = 1,
        .size = size,
        .mtime_seconds = 1,
        .mtime_nanoseconds = 2,
        .ctime_seconds = 3,
        .ctime_nanoseconds = 4,
    };
}

kpi::mpc::p1_private_state::MascotFileSnapshotView mascot_read_file(
        std::span<const unsigned char> bytes, std::uint64_t inode) {
    using namespace kpi::mpc::p1_private_state;
    const auto metadata = mascot_metadata(bytes.size(), inode);
    return {
        .result = MascotFileResult::Captured,
        .open_flags = 1,
        .no_follow = true,
        .bytes_transferred = bytes.size(),
        .path_lstat_before = metadata,
        .descriptor_before = metadata,
        .descriptor_after = metadata,
        .path_lstat_after = metadata,
        .reopened_descriptor = metadata,
        .exact_file_bytes = bytes,
    };
}

kpi::mpc::p1_private_state::MascotFileSnapshotView mascot_write_file(
        std::span<const unsigned char> bytes, std::uint64_t inode) {
    using namespace kpi::mpc::p1_private_state;
    const auto metadata = mascot_metadata(bytes.size(), inode);
    return {
        .result = MascotFileResult::Captured,
        .open_flags = 1,
        .no_follow = true,
        .bytes_transferred = bytes.size(),
        .fsync_result = MascotStepResult::Succeeded,
        .path_lstat_before = {},
        .descriptor_before = metadata,
        .descriptor_after = metadata,
        .path_lstat_after = metadata,
        .reopened_descriptor = metadata,
        .exact_file_bytes = bytes,
    };
}

kpi::mpc::p1_private_state::MascotFileSnapshotView mascot_missing_file() {
    using namespace kpi::mpc::p1_private_state;
    return {
        .result = MascotFileResult::Missing,
        .operation_errno = ENOENT,
        .open_flags = 1,
        .no_follow = true,
        .path_lstat_before = {},
        .descriptor_before = {},
        .descriptor_after = {},
        .path_lstat_after = {},
        .reopened_descriptor = {},
        .exact_file_bytes = {},
    };
}

bool emit_mascot_cache_branch(
        kpi::mpc::p1_private_state::MascotCacheBranch branch) {
    using namespace kpi::mpc::p1_private_state;
    assert(branch == MascotCacheBranch::CacheHit ||
           branch == MascotCacheBranch::RegeneratedAfterMissing);
    constexpr std::string_view domain = "3-p-254/P1";
    constexpr std::string_view cache_path =
        "Player-Data//Mascot-Secrets-p-P1";
    constexpr std::string_view prep_path =
        "Player-Data/3-p-254/Player-MAC-Keys-p-P1";
    const auto reset_key = snapshot(0x00);
    const auto cache_key = snapshot(0x41);
    const auto regenerated_key = snapshot(0x42);
    const auto first_fresh = snapshot(0x43);
    const auto second_fresh = snapshot(0x44);
    const auto scalar_before = snapshot(0x45);
    const auto alpha = snapshot(0x46);
    const auto cache_bytes = snapshot(0x47);
    const auto candidate = snapshot(0x48);
    const auto prep_candidate = snapshot(0x49);

    assert(MascotSecretStateSourceBridge::scalar_state_begin(
        domain, cache_path, 1024, 4, 40, true, true,
        scalar_before, scalar_before));
    assert(MascotSecretStateSourceBridge::setup_begin(
        domain, cache_path, 1024, 4, 40, true, true, false, reset_key));
    if (branch == MascotCacheBranch::CacheHit) {
        const auto opened = mascot_read_file(cache_bytes, 71);
        assert(MascotSecretStateSourceBridge::cache_opened(
            cache_path, opened));
        assert(MascotSecretStateSourceBridge::cache_local_validation(
            MascotStepResult::Succeeded, true, cache_key, {}));
        assert(MascotSecretStateSourceBridge::cache_peer_validation(
            MascotStepResult::Succeeded, {}));
    } else {
        const auto missing = mascot_missing_file();
        assert(MascotSecretStateSourceBridge::cache_opened(
            cache_path, missing));
        assert(MascotSecretStateSourceBridge::cache_local_validation(
            MascotStepResult::Failed, false, reset_key,
            "cache-missing"));
        assert(MascotSecretStateSourceBridge::cache_peer_validation(
            MascotStepResult::Succeeded, {}));
        assert(MascotSecretStateSourceBridge::regeneration(
            true, regenerated_key));
    }
    const auto& current = branch == MascotCacheBranch::CacheHit
        ? cache_key : regenerated_key;
    assert(MascotSecretStateSourceBridge::write_candidate(
        true, current, true, first_fresh, candidate));
    const auto written = mascot_write_file(candidate, 72);
    assert(MascotSecretStateSourceBridge::writeback(
        cache_path, MascotStepResult::Succeeded, written, {}));
    assert(MascotSecretStateSourceBridge::prep_static_installed(
        scalar_before, alpha, alpha));
    const auto prep_written = mascot_write_file(prep_candidate, 73);
    assert(MascotSecretStateSourceBridge::prep_mac_file_write(
        prep_path, MascotStepResult::Succeeded, prep_written,
        prep_candidate, {}));
    assert(MascotSecretStateSourceBridge::bit_prep_derived(
        first_fresh, second_fresh, second_fresh, true));
    assert(MascotSecretStateSourceBridge::static_installed(
        true, second_fresh, scalar_before, alpha, alpha));
    return MascotSecretStateSourceBridge::teardown(
        true, second_fresh, alpha, false, reset_key, alpha, alpha, alpha);
}

bool fixture_reserved_family(StateFamily family) {
    return family == StateFamily::MpSpdzPrng ||
        family == StateFamily::CryptoToolsPrng ||
        family == StateFamily::SimplestOtBase ||
        family == StateFamily::PlayerAllocation ||
        family == StateFamily::TlsChannelState;
}

P1StateObjectEpochAuthority fixture_construct_object(
        P1CorruptStateRecorderAuthority& recorder, StateFamily family,
        const P1StateThreadEpochAuthority& thread,
        std::span<const unsigned char> value) {
    if (fixture_reserved_family(family))
        return recorder.test_only_construct_reserved_family(
            family, thread, value);
    return recorder.construct_object(family, thread, value);
}

void fixture_close_family(
        P1CorruptStateRecorderAuthority& recorder, StateFamily family) {
    if (fixture_reserved_family(family))
        recorder.test_only_close_reserved_family(family);
    else
        recorder.close_family(family);
}

TransitionKind transition_for(StateFamily family) {
    switch (family) {
    case StateFamily::MpSpdzPrng:
    case StateFamily::CryptoToolsPrng:
        return TransitionKind::PrngConsume;
    case StateFamily::MascotSecrets:
        return TransitionKind::CacheLoad;
    case StateFamily::SimplestOtBase:
        return TransitionKind::OtSetup;
    case StateFamily::SoftSpokenExtended:
        return TransitionKind::OtExtend;
    case StateFamily::OnDemandOtMap:
        return TransitionKind::OtSetup;
    case StateFamily::TripleAndInputCache:
        return TransitionKind::TripleGenerate;
    case StateFamily::Beaver:
        return TransitionKind::BeaverPrepare;
    case StateFamily::MacCheck:
        return TransitionKind::MacPrepare;
    case StateFamily::ContextAndRetry:
        return TransitionKind::ContextValidate;
    case StateFamily::ProtocolSetup:
        return TransitionKind::ProtocolSetup;
    case StateFamily::PlayerAllocation:
        return TransitionKind::PlayerTraffic;
    case StateFamily::TlsChannelState:
        return TransitionKind::TlsHandshake;
    case StateFamily::QueryMsmCheckerTemporaries:
        return TransitionKind::QueryMsmStage;
    }
    assert(false);
    return TransitionKind::ContextPoison;
}

struct CompleteFixture {
    P1CorruptStateRecorderAuthority recorder;
    P1StateThreadEpochAuthority root_thread;
    P1PlayerAllocationEpochAuthority root_player;
    std::vector<P1StateObjectEpochAuthority> objects;
};

struct LateAbortFixture {
    P1CorruptStateRecorderAuthority recorder;
    P1StateThreadEpochAuthority root_thread;
    P1PlayerAllocationEpochAuthority root_player;
    std::vector<P1StateObjectEpochAuthority> objects;
};

struct ContextAdapterFixture {
    P1CorruptStateRecorderAuthority recorder;
    P1StateThreadEpochAuthority root_thread;
    P1PlayerAllocationEpochAuthority root_player;
    P1StateObjectEpochAuthority tls;
};

struct EntropyAdapterFixture {
    P1CorruptStateRecorderAuthority recorder;
    P1StateThreadEpochAuthority root_thread;
    std::unique_ptr<P1EntropyStateAdapter> adapter;
    P1PlayerAllocationEpochAuthority root_player;
    P1StateObjectEpochAuthority tls;
};

EntropyAdapterFixture prepare_entropy_adapter(
        unsigned char offset, bool take_adapter = true) {
    auto recorder = P1CorruptStateCapsulePlanAuthority::test_only_mint(
        entropy_adapter_plan(offset)).begin_before_player_and_protocol_setup();
    auto thread = recorder.take_root_thread_epoch();
    std::unique_ptr<P1EntropyStateAdapter> adapter;
    if (take_adapter) {
        adapter = recorder.take_entropy_state_adapter(thread);
        std::array<unsigned char, 16> early_seed{};
        early_seed.fill(0x31);
        const kpi::mpc::p1_private_state::EntropyIngressView early{
            .source = kpi::mpc::p1_private_state::EntropySource::
                MpSpdzPrngReseed,
            .callsite_rva = 0x1001,
            .object_epoch = 1,
            .thread_epoch = 1,
            .allocation_epoch = 1,
            .counter_before = 0,
            .counter_after = 1,
            .exact_entropy = early_seed,
        };
        assert(adapter->record_entropy_ingress(early));
    }
    auto player = recorder.bind_root_player(thread, snapshot(0x41));
    recorder.player_transition(
        player, TransitionKind::PlayerTraffic, 0, 1, snapshot(0x42));
    recorder.player_terminal_snapshot(player, snapshot(0x43));
    recorder.test_only_close_reserved_family(StateFamily::PlayerAllocation);
    auto tls = fixture_construct_object(
        recorder, StateFamily::TlsChannelState, thread, snapshot(0x44));
    recorder.transition(
        tls, TransitionKind::TlsHandshake, 0, 13, snapshot(0x45));
    recorder.terminal_snapshot(tls, snapshot(0x46));
    recorder.test_only_close_reserved_family(StateFamily::TlsChannelState);
    recorder.advance_phase(SourcePhase::TlsAndPlayerBound);
    recorder.advance_phase(SourcePhase::ProtocolSetupStarted);
    return {
        .recorder = std::move(recorder),
        .root_thread = std::move(thread),
        .adapter = std::move(adapter),
        .root_player = std::move(player),
        .tls = std::move(tls),
    };
}

ContextAdapterFixture prepare_context_adapter_with_plan(
        StaticStateCapsulePlan selected) {
    auto recorder = P1CorruptStateCapsulePlanAuthority::test_only_mint(
        std::move(selected)).begin_before_player_and_protocol_setup();
    auto thread = recorder.take_root_thread_epoch();
    expect_refused([&] {
        auto early = recorder.take_context_and_retry_adapter(thread);
        (void)early;
    });
    auto player = recorder.bind_root_player(thread, snapshot(0x51));
    recorder.player_transition(
        player, TransitionKind::PlayerTraffic, 0, 1, snapshot(0x52));
    recorder.player_terminal_snapshot(player, snapshot(0x53));
    expect_refused([&] {
        recorder.close_family(StateFamily::PlayerAllocation);
    });
    recorder.test_only_close_reserved_family(StateFamily::PlayerAllocation);
    auto tls = fixture_construct_object(
        recorder, StateFamily::TlsChannelState, thread, snapshot(0x54));
    recorder.transition(
        tls, TransitionKind::TlsHandshake, 0, 13, snapshot(0x55));
    recorder.terminal_snapshot(tls, snapshot(0x56));
    expect_refused([&] {
        recorder.close_family(StateFamily::TlsChannelState);
    });
    recorder.test_only_close_reserved_family(StateFamily::TlsChannelState);
    recorder.advance_phase(SourcePhase::TlsAndPlayerBound);
    recorder.advance_phase(SourcePhase::ProtocolSetupStarted);
    return {
        .recorder = std::move(recorder),
        .root_thread = std::move(thread),
        .root_player = std::move(player),
        .tls = std::move(tls),
    };
}

ContextAdapterFixture prepare_context_adapter(unsigned char offset) {
    return prepare_context_adapter_with_plan(context_adapter_plan(offset));
}

LateAbortFixture prepare_late_abort(
        unsigned char offset, unsigned context_variant = 0) {
    auto selected = late_abort_plan(offset);
    auto plan_authority =
        P1CorruptStateCapsulePlanAuthority::test_only_mint(
            std::move(selected));
    auto recorder =
        std::move(plan_authority).begin_before_player_and_protocol_setup();
    auto thread = recorder.take_root_thread_epoch();
    auto player = recorder.bind_root_player(thread, snapshot(0x35));
    recorder.player_transition(
        player, TransitionKind::PlayerTraffic, 0, 1, snapshot(0x36));
    recorder.player_terminal_snapshot(player, snapshot(0x37));
    recorder.test_only_close_reserved_family(StateFamily::PlayerAllocation);

    std::vector<P1StateObjectEpochAuthority> objects;
    const auto add_complete = [&](StateFamily family) {
        if (family == StateFamily::MascotSecrets) {
            complete_static_mascot_family(recorder, thread);
            return;
        }
        const auto index = static_cast<unsigned>(family) - 1;
        auto object = fixture_construct_object(
            recorder, family, thread,
            snapshot(static_cast<unsigned char>(0x41 + index)));
        recorder.transition(
            object, transition_for(family), 0, index + 1,
            snapshot(static_cast<unsigned char>(0x61 + index)));
        recorder.terminal_snapshot(
            object, snapshot(static_cast<unsigned char>(0x81 + index)));
        fixture_close_family(recorder, family);
        objects.push_back(std::move(object));
    };
    add_complete(StateFamily::TlsChannelState);
    recorder.advance_phase(SourcePhase::TlsAndPlayerBound);
    recorder.advance_phase(SourcePhase::ProtocolSetupStarted);
    for (const auto family : {
             StateFamily::MpSpdzPrng,
             StateFamily::CryptoToolsPrng,
             StateFamily::MascotSecrets,
             StateFamily::SimplestOtBase,
             StateFamily::SoftSpokenExtended,
             StateFamily::OnDemandOtMap,
             StateFamily::TripleAndInputCache,
             StateFamily::MacCheck})
        add_complete(family);
    auto context = recorder.take_context_and_retry_adapter(thread);
    context->test_only_constructed(snapshot(0xa1));
    if (context_variant == 2) {
        context->test_only_transition(
            kpi::mpc::p1_private_state::ContextTransition::Retry,
            0, 10, snapshot(0xa2));
    } else {
        context->test_only_transition(
            kpi::mpc::p1_private_state::ContextTransition::Validate,
            0, 10, snapshot(0xa2));
        if (context_variant == 1)
            context->test_only_transition(
                kpi::mpc::p1_private_state::ContextTransition::Retry,
                10, 11, snapshot(0xa3));
    }
    context->test_only_terminal(
        snapshot(static_cast<unsigned char>(0xa4 + context_variant)));
    context.reset();
    add_complete(StateFamily::ProtocolSetup);
    recorder.mark_family_not_constructed_before_abort(StateFamily::Beaver);
    recorder.mark_family_not_constructed_before_abort(
        StateFamily::QueryMsmCheckerTemporaries);
    return {
        .recorder = std::move(recorder),
        .root_thread = std::move(thread),
        .root_player = std::move(player),
        .objects = std::move(objects),
    };
}

CompleteFixture prepare_complete(unsigned char offset = 0) {
    auto recorder = P1CorruptStateCapsulePlanAuthority::test_only_mint(
        plan(offset)).begin_before_player_and_protocol_setup();
    auto thread = recorder.take_root_thread_epoch();
    auto player = recorder.bind_root_player(thread, snapshot(0x31));
    recorder.player_transition(
        player, TransitionKind::PlayerTraffic, 0, 1, snapshot(0x32));
    recorder.player_terminal_snapshot(player, snapshot(0x33));
    recorder.test_only_close_reserved_family(StateFamily::PlayerAllocation);

    std::vector<P1StateObjectEpochAuthority> objects;
    const auto add = [&](StateFamily family) {
        if (family == StateFamily::MascotSecrets) {
            complete_static_mascot_family(recorder, thread);
            return;
        }
        const auto index = static_cast<unsigned>(family) - 1;
        auto object = fixture_construct_object(
            recorder, family, thread,
            snapshot(static_cast<unsigned char>(0x40 + index)));
        recorder.transition(
            object, transition_for(family), 0, index + 1,
            snapshot(static_cast<unsigned char>(0x60 + index)));
        recorder.terminal_snapshot(
            object, snapshot(static_cast<unsigned char>(0x80 + index)));
        fixture_close_family(recorder, family);
        objects.push_back(std::move(object));
    };
    add(StateFamily::TlsChannelState);
    recorder.advance_phase(SourcePhase::TlsAndPlayerBound);
    recorder.advance_phase(SourcePhase::ProtocolSetupStarted);
    for (const auto family : {
             StateFamily::MpSpdzPrng,
             StateFamily::CryptoToolsPrng,
             StateFamily::MascotSecrets,
             StateFamily::SimplestOtBase,
             StateFamily::SoftSpokenExtended,
             StateFamily::OnDemandOtMap,
             StateFamily::TripleAndInputCache,
             StateFamily::MacCheck,
             StateFamily::ProtocolSetup})
        add(family);
    auto context = recorder.take_context_and_retry_adapter(thread);
    context->test_only_constructed(snapshot(0x49));
    context->test_only_transition(
        kpi::mpc::p1_private_state::ContextTransition::Validate,
        0, 10, snapshot(0x69));
    context->test_only_terminal(snapshot(0x89));
    context.reset();
    recorder.advance_phase(SourcePhase::ProtocolSetupComplete);
    add(StateFamily::Beaver);
    recorder.advance_phase(SourcePhase::Construction);
    add(StateFamily::QueryMsmCheckerTemporaries);
    recorder.advance_phase(SourcePhase::Proof);
    recorder.advance_phase(SourcePhase::Release);
    recorder.advance_phase(SourcePhase::TerminalEgress);
    return {
        .recorder = std::move(recorder),
        .root_thread = std::move(thread),
        .root_player = std::move(player),
        .objects = std::move(objects),
    };
}

void complete_success_and_abort() {
    {
        auto fixture = prepare_complete();
        fixture.recorder.join_thread(
            std::move(fixture.root_thread), snapshot(0x91));
        auto capsule =
            std::move(fixture.recorder).close_success_noexcept();
        const auto summary = capsule.test_only_summary();
        assert(summary.manifest_structurally_complete && !summary.aborted && summary.read_only &&
               summary.anonymous_disk_backed && summary.writer_closed &&
               summary.missing_family_bitmap == 0 &&
               summary.closed_family_bitmap ==
                   ((std::uint64_t{1} << STATE_FAMILY_COUNT) - 1) &&
               summary.archive_bytes > 0 && summary.sequence > 0 &&
               summary.archive_sha256 != Digest{});
        for (const auto count : summary.event_counts) assert(count >= 3);
    }
    {
        auto recorder = P1CorruptStateCapsulePlanAuthority::test_only_mint(
            plan(1)).begin_before_player_and_protocol_setup();
        auto thread = recorder.take_root_thread_epoch();
        auto player = recorder.bind_root_player(thread, snapshot(0x21));
        recorder.player_transition(
            player, TransitionKind::PlayerTraffic, 0, 1, snapshot(0x20));
        auto tls = fixture_construct_object(
            recorder, StateFamily::TlsChannelState, thread, snapshot(0x22));
        recorder.transition(tls, TransitionKind::TlsHandshake,
                            0, 13, snapshot(0x23));
        recorder.terminal_snapshot(tls, snapshot(0x24));
        recorder.test_only_close_reserved_family(
            StateFamily::TlsChannelState);
        recorder.player_terminal_snapshot(player, snapshot(0x22));
        recorder.test_only_close_reserved_family(
            StateFamily::PlayerAllocation);
        recorder.advance_phase(SourcePhase::TlsAndPlayerBound);
        for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index) {
            const auto family = static_cast<StateFamily>(index + 1);
            if (family == StateFamily::PlayerAllocation ||
                family == StateFamily::TlsChannelState)
                continue;
            recorder.mark_family_not_constructed_before_abort(family);
        }
        recorder.join_thread(std::move(thread), snapshot(0x25));
        auto terminal = prepare_test_abort_terminal(
            recorder,
            abort_site(1, SourcePhase::TlsAndPlayerBound,
                       AbortClass::Protocol),
            AbortClass::Protocol,
            abort_exception(1, SourcePhase::TlsAndPlayerBound,
                            AbortClass::Protocol));
        auto capsule = std::move(recorder).close_abort_noexcept(
            std::move(terminal));
        const auto summary = capsule.test_only_summary();
        assert(summary.manifest_structurally_complete && summary.aborted && summary.read_only &&
               summary.missing_family_bitmap == 0);
    }
}

void adversarial_state_machine() {
    auto selected1 = plan(2);
    auto& player_inventory = selected1.hook_inventory[
        static_cast<unsigned>(StateFamily::PlayerAllocation) - 1];
    player_inventory.exact_object_count = 2;
    const std::array player_events{
        HookEventDescriptor{1, HookEventKind::Construct,
                            TransitionKind{}, 0, 0},
        HookEventDescriptor{1, HookEventKind::Transition,
                            TransitionKind::PlayerTraffic, 0, 1},
        HookEventDescriptor{2, HookEventKind::Construct,
                            TransitionKind{}, 0, 0},
        HookEventDescriptor{2, HookEventKind::TerminalSnapshot,
                            TransitionKind{}, 0, 0},
        HookEventDescriptor{1, HookEventKind::TerminalSnapshot,
                            TransitionKind{}, 1, 1},
    };
    player_inventory.exact_event_count = player_events.size();
    player_inventory.expected_event_sequence_identity =
        recompute_family_event_sequence_identity(
            StateFamily::PlayerAllocation, player_events);
    refresh_closed_abort_families(selected1);
    auto recorder1 = P1CorruptStateCapsulePlanAuthority::test_only_mint(
        std::move(selected1)).begin_before_player_and_protocol_setup();
    auto thread1 = recorder1.take_root_thread_epoch();
    auto player1 = recorder1.bind_root_player(thread1, snapshot(0x11));
    recorder1.player_transition(
        player1, TransitionKind::PlayerTraffic, 0, 1, snapshot(0x10));
    auto tls1 = fixture_construct_object(
        recorder1, StateFamily::TlsChannelState, thread1, snapshot(0x12));
    expect_refused([&] {
        recorder1.transition(tls1, TransitionKind::MacVerify,
                             0, 1, snapshot(0x13));
    });
    recorder1.transition(tls1, TransitionKind::TlsHandshake,
                         0, 13, snapshot(0x14));
    expect_refused([&] {
        recorder1.transition(tls1, TransitionKind::TlsReadWrite,
                             0, 14, snapshot(0x15));
    });

    auto fork_thread = recorder1.fork_thread(thread1, digest(0xa1));
    auto fork_player = recorder1.allocate_player_fork(
        player1, fork_thread, digest(0xa2), snapshot(0x16));
    expect_refused([&] {
        auto duplicate = recorder1.allocate_player_fork(
            player1, fork_thread, digest(0xa2), snapshot(0x17));
        (void)duplicate;
    });

    auto recorder2 = P1CorruptStateCapsulePlanAuthority::test_only_mint(
        plan(3)).begin_before_player_and_protocol_setup();
    auto thread2 = recorder2.take_root_thread_epoch();
    expect_refused([&] {
        recorder2.transition(tls1, TransitionKind::TlsReadWrite,
                             13, 14, snapshot(0x18));
    });
    expect_refused([&] {
        auto wrong = recorder2.bind_root_player(thread1, snapshot(0x19));
        (void)wrong;
    });
    auto player2 = recorder2.bind_root_player(thread2, snapshot(0x1d));
    recorder2.player_transition(
        player2, TransitionKind::PlayerTraffic, 0, 1, snapshot(0x1c));
    auto tls2 = fixture_construct_object(
        recorder2, StateFamily::TlsChannelState, thread2, snapshot(0x1e));
    recorder2.transition(
        tls2, TransitionKind::TlsHandshake, 0, 13, snapshot(0x1f));

    recorder1.player_terminal_snapshot(fork_player, snapshot(0x1a));
    recorder1.player_terminal_snapshot(player1, snapshot(0x1b));
    recorder1.terminal_snapshot(tls1, snapshot(0x1c));
    recorder1.test_only_close_reserved_family(
        StateFamily::PlayerAllocation);
    recorder1.test_only_close_reserved_family(StateFamily::TlsChannelState);
    recorder1.advance_phase(SourcePhase::TlsAndPlayerBound);
    for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index) {
        const auto family = static_cast<StateFamily>(index + 1);
        if (family != StateFamily::PlayerAllocation &&
            family != StateFamily::TlsChannelState)
            recorder1.mark_family_not_constructed_before_abort(family);
    }
    recorder1.join_thread(std::move(fork_thread), snapshot(0x1f));
    recorder1.join_thread(std::move(thread1), snapshot(0x20));
    auto terminal1 = prepare_test_abort_terminal(
        recorder1,
        abort_site(2, SourcePhase::TlsAndPlayerBound,
                   AbortClass::Transport),
        AbortClass::Transport,
        abort_exception(2, SourcePhase::TlsAndPlayerBound,
                        AbortClass::Transport));
    auto first = std::move(recorder1).close_abort_noexcept(
        std::move(terminal1));
    assert(first.test_only_summary().manifest_structurally_complete);
    auto replay = std::move(recorder1).close_success_noexcept();
    assert(!replay.test_only_summary().manifest_structurally_complete);

    recorder2.terminal_snapshot(tls2, snapshot(0x21));
    recorder2.test_only_close_reserved_family(StateFamily::TlsChannelState);
    recorder2.player_terminal_snapshot(player2, snapshot(0x22));
    recorder2.test_only_close_reserved_family(
        StateFamily::PlayerAllocation);
    recorder2.advance_phase(SourcePhase::TlsAndPlayerBound);
    for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index) {
        const auto family = static_cast<StateFamily>(index + 1);
        if (family != StateFamily::PlayerAllocation &&
            family != StateFamily::TlsChannelState)
            recorder2.mark_family_not_constructed_before_abort(family);
    }
    recorder2.join_thread(std::move(thread2), snapshot(0x23));
    auto terminal2 = prepare_test_abort_terminal(
        recorder2,
        abort_site(3, SourcePhase::TlsAndPlayerBound,
                   AbortClass::Protocol),
        AbortClass::Protocol,
        abort_exception(3, SourcePhase::TlsAndPlayerBound,
                        AbortClass::Protocol));
    auto second = std::move(recorder2).close_abort_noexcept(
        std::move(terminal2));
    assert(second.test_only_summary().manifest_structurally_complete);
}

void terminal_prefix_controls() {
    {
        auto fixture = prepare_late_abort(16);
        fixture.recorder.join_thread(
            std::move(fixture.root_thread), snapshot(0xd0));
        auto source_terminal =
            fixture.recorder.test_only_mint_abort_terminal_site(
                late_abort_site(16), AbortClass::Protocol,
                late_abort_exception(16));
        expect_refused([&] {
            auto duplicate =
                fixture.recorder.test_only_mint_abort_terminal_site(
                    late_abort_site(16), AbortClass::Protocol,
                    late_abort_exception(16));
            (void)duplicate;
        });
        auto terminal = fixture.recorder.prepare_abort_terminal(
            std::move(source_terminal));
        auto capsule = std::move(fixture.recorder).close_abort_noexcept(
            std::move(terminal));
        const auto summary = capsule.test_only_summary();
        const auto context_bit = std::uint64_t{1} <<
            (static_cast<unsigned>(StateFamily::ContextAndRetry) - 1);
        assert(summary.manifest_structurally_complete && summary.aborted &&
               summary.missing_family_bitmap == 0 &&
               summary.abort_prefix_bitmap == context_bit &&
               summary.abort_terminal_site_identity == late_abort_site(16));
    }
    {
        auto fixture = prepare_late_abort(17);
        fixture.recorder.join_thread(
            std::move(fixture.root_thread), snapshot(0xd2));
        auto capsule =
            std::move(fixture.recorder).close_success_noexcept();
        assert(!capsule.test_only_summary().manifest_structurally_complete);
    }
    {
        auto fixture = prepare_late_abort(18);
        fixture.recorder.join_thread(
            std::move(fixture.root_thread), snapshot(0xd3));
        expect_refused([&] {
            auto wrong = prepare_test_abort_terminal(
                fixture.recorder, late_abort_site(18),
                AbortClass::MacCheck, late_abort_exception(18));
            (void)wrong;
        });
        expect_refused([&] {
            auto wrong = prepare_test_abort_terminal(
                fixture.recorder, late_abort_site(18),
                AbortClass::Protocol, digest(0xfe));
            (void)wrong;
        });
        expect_refused([&] {
            auto wrong = prepare_test_abort_terminal(
                fixture.recorder,
                abort_site(18, SourcePhase::TlsAndPlayerBound,
                           AbortClass::Protocol),
                AbortClass::Protocol,
                abort_exception(18, SourcePhase::TlsAndPlayerBound,
                                AbortClass::Protocol));
            (void)wrong;
        });
        auto terminal = prepare_test_abort_terminal(
            fixture.recorder, late_abort_site(18), AbortClass::Protocol,
            late_abort_exception(18));
        auto capsule = std::move(fixture.recorder).close_abort_noexcept(
            std::move(terminal));
        assert(capsule.test_only_summary().manifest_structurally_complete);
    }
    for (unsigned variant = 1; variant <= 2; ++variant) {
        const auto offset = static_cast<unsigned char>(10 + variant);
        auto fixture = prepare_late_abort(offset, variant);
        fixture.recorder.join_thread(
            std::move(fixture.root_thread),
            snapshot(static_cast<unsigned char>(0xd6 + variant)));
        expect_refused([&] {
            auto terminal = prepare_test_abort_terminal(
                fixture.recorder,
                late_abort_site(offset), AbortClass::Protocol,
                late_abort_exception(offset));
            (void)terminal;
        });
        auto capsule =
            std::move(fixture.recorder).close_unavailable_abort_noexcept(
                AbortClass::Protocol,
                digest(static_cast<unsigned char>(0xd8 + variant)));
        assert(!capsule.test_only_summary().manifest_structurally_complete);
    }
    {
        auto retuned = late_abort_plan(12);
        auto& context = retuned.abort_terminals.back().families[
            static_cast<unsigned>(StateFamily::ContextAndRetry) - 1];
        ++context.exact_event_count;
        expect_refused([&] {
            auto forged = P1CorruptStateCapsulePlanAuthority::test_only_mint(
                std::move(retuned));
            (void)forged;
        });
    }
    {
        auto retuned = late_abort_plan(13);
        retuned.abort_terminals.back().exception_type_identity = digest(0xfd);
        expect_refused([&] {
            auto forged = P1CorruptStateCapsulePlanAuthority::test_only_mint(
                std::move(retuned));
            (void)forged;
        });
    }
}

void context_adapter_controls() {
    {
        auto fixture = prepare_context_adapter(12);
        expect_refused([&] {
            auto forged = fixture.recorder.construct_object(
                StateFamily::ContextAndRetry, fixture.root_thread,
                snapshot(0xe0));
            (void)forged;
        });
        expect_refused([&] {
            fixture.recorder.close_family(StateFamily::ContextAndRetry);
        });
        auto adapter = fixture.recorder.take_context_and_retry_adapter(
            fixture.root_thread);
        expect_refused([&] {
            auto duplicate = fixture.recorder.take_context_and_retry_adapter(
                fixture.root_thread);
            (void)duplicate;
        });
        adapter->test_only_constructed(snapshot(0xe1));
        adapter->test_only_transition(
            kpi::mpc::p1_private_state::ContextTransition::Validate,
            0, 1, snapshot(0xe2));
        adapter->test_only_transition(
            kpi::mpc::p1_private_state::ContextTransition::Retry,
            1, 2, snapshot(0xe3));
        adapter->test_only_transition(
            kpi::mpc::p1_private_state::ContextTransition::Poison,
            2, 3, snapshot(0xe4));
        adapter->test_only_terminal(snapshot(0xe5));
        adapter.reset();
        fixture.recorder.join_thread(
            std::move(fixture.root_thread), snapshot(0xe6));
        auto capsule =
            std::move(fixture.recorder).close_unavailable_abort_noexcept(
                AbortClass::Protocol, digest(0xe7));
        const auto summary = capsule.test_only_summary();
        const auto context_bit = std::uint64_t{1} <<
            (static_cast<unsigned>(StateFamily::ContextAndRetry) - 1);
        assert(!summary.manifest_structurally_complete &&
               (summary.closed_family_bitmap & context_bit) != 0 &&
               summary.event_counts[
                   static_cast<unsigned>(StateFamily::ContextAndRetry) - 1] >=
                   6);
    }
    {
        auto fixture = prepare_context_adapter(13);
        auto dropped = fixture.recorder.take_context_and_retry_adapter(
            fixture.root_thread);
        dropped.reset();
        fixture.recorder.join_thread(
            std::move(fixture.root_thread), snapshot(0xe8));
        auto capsule =
            std::move(fixture.recorder).close_unavailable_abort_noexcept(
                AbortClass::Protocol, digest(0xe9));
        const auto missing = capsule.test_only_summary().missing_family_bitmap;
        assert((missing & (std::uint64_t{1} <<
                (static_cast<unsigned>(StateFamily::ContextAndRetry) - 1))) !=
               0);
    }
    {
        auto first = prepare_context_adapter(14);
        auto second = prepare_context_adapter(15);
        expect_refused([&] {
            auto cross = first.recorder.take_context_and_retry_adapter(
                second.root_thread);
            (void)cross;
        });
    }
    {
        std::unique_ptr<P1ContextAndRetryStateAdapter> retained;
        {
            auto fixture = prepare_context_adapter(16);
            retained = fixture.recorder.take_context_and_retry_adapter(
                fixture.root_thread);
            retained->test_only_constructed(snapshot(0xea));
        }
        // The adapter retains shared Ledger ownership. Recorder/thread token
        // destruction poisons availability but cannot leave a dangling sink.
        retained->test_only_unavailable_noexcept();
        retained.reset();
    }
}

void mascot_adapter_controls() {
    using namespace kpi::mpc::p1_private_state;
    const auto mascot_bit = std::uint64_t{1} <<
        (static_cast<unsigned>(StateFamily::MascotSecrets) - 1);
    const auto finish = [&](ContextAdapterFixture& fixture,
                            unsigned char exception) {
        fixture.recorder.join_thread(
            std::move(fixture.root_thread), snapshot(exception));
        return std::move(fixture.recorder).close_unavailable_abort_noexcept(
            AbortClass::Protocol, digest(exception));
    };

    for (const auto [offset, branch] : {
             std::pair{static_cast<unsigned char>(40),
                       MascotCacheBranch::StaticReuse},
             std::pair{static_cast<unsigned char>(41),
                       MascotCacheBranch::CacheHit},
             std::pair{static_cast<unsigned char>(42),
                       MascotCacheBranch::RegeneratedAfterMissing}}) {
        auto fixture = prepare_context_adapter_with_plan(
            mascot_adapter_plan(offset, branch));
        expect_refused([&] {
            auto forged = fixture.recorder.construct_object(
                StateFamily::MascotSecrets, fixture.root_thread,
                snapshot(0xb0));
            (void)forged;
        });
        expect_refused([&] {
            auto forged = fixture.recorder.test_only_construct_reserved_family(
                StateFamily::MascotSecrets, fixture.root_thread,
                snapshot(0xb1));
            (void)forged;
        });
        expect_refused([&] {
            fixture.recorder.close_family(StateFamily::MascotSecrets);
        });
        expect_refused([&] {
            fixture.recorder.test_only_close_reserved_family(
                StateFamily::MascotSecrets);
        });
        auto adapter = fixture.recorder.take_mascot_secret_state_adapter(
            fixture.root_thread);
        expect_refused([&] {
            auto duplicate =
                fixture.recorder.take_mascot_secret_state_adapter(
                    fixture.root_thread);
            (void)duplicate;
        });
        if (branch == MascotCacheBranch::StaticReuse) {
            const auto key = snapshot(0xb2);
            const auto reset = snapshot(0x00);
            const auto scalar = snapshot(0xb3);
            constexpr std::string_view domain = "3-p-254/P1";
            constexpr std::string_view path =
                "Player-Data//Mascot-Secrets-p-P1";
            assert(MascotSecretStateSourceBridge::scalar_state_begin(
                domain, path, 1024, 4, 40, true, true, scalar, scalar));
            assert(MascotSecretStateSourceBridge::setup_begin(
                domain, path, 1024, 4, 40, true, true, true, key));
            assert(MascotSecretStateSourceBridge::static_installed(
                true, key, scalar, scalar, scalar));
            assert(MascotSecretStateSourceBridge::teardown(
                true, key, scalar, false, reset, scalar, scalar, scalar));
        } else {
            assert(emit_mascot_cache_branch(branch));
        }
        adapter.reset();
        auto capsule = finish(fixture, static_cast<unsigned char>(0xc0 + offset));
        const auto summary = capsule.test_only_summary();
        assert((summary.closed_family_bitmap & mascot_bit) != 0 &&
               (summary.missing_family_bitmap & mascot_bit) == 0);
    }

    // A source-authenticated MAC-check abort preserves the exact unlink and
    // teardown prefix, but it can only terminalize MascotSecrets as MISSING.
    {
        auto fixture = prepare_context_adapter_with_plan(
            mascot_adapter_plan(50, MascotCacheBranch::StaticReuse));
        auto adapter = fixture.recorder.take_mascot_secret_state_adapter(
            fixture.root_thread);
        const auto key = snapshot(0xdb);
        const auto reset = snapshot(0x00);
        const auto scalar = snapshot(0xdc);
        constexpr std::string_view domain = "3-p-254/P1";
        constexpr std::string_view path =
            "Player-Data//Mascot-Secrets-p-P1";
        assert(MascotSecretStateSourceBridge::scalar_state_begin(
            domain, path, 1024, 4, 40, true, true, scalar, scalar));
        assert(MascotSecretStateSourceBridge::setup_begin(
            domain, path, 1024, 4, 40, true, true, true, key));
        assert(MascotSecretStateSourceBridge::static_installed(
            true, key, scalar, scalar, scalar));
        const auto before = mascot_metadata(48, 90);
        assert(MascotSecretStateSourceBridge::abort_cache_unlink_noexcept(
            MascotSecretAbortClass::MacCheckFailure, path,
            true, 0, before, {}));
        assert(MascotSecretStateSourceBridge::teardown(
            true, key, scalar, false, reset, scalar, scalar, scalar));
        adapter.reset();
        auto capsule = finish(fixture, 0xdd);
        const auto summary = capsule.test_only_summary();
        assert((summary.missing_family_bitmap & mascot_bit) != 0 &&
               (summary.closed_family_bitmap & mascot_bit) == 0);
    }
    // Path substitution is refused before it can be confused with the
    // source-derived cache identity.
    {
        auto fixture = prepare_context_adapter_with_plan(
            mascot_adapter_plan(17, MascotCacheBranch::StaticReuse));
        auto adapter = fixture.recorder.take_mascot_secret_state_adapter(
            fixture.root_thread);
        const auto key = snapshot(0xde);
        const auto scalar = snapshot(0xdf);
        constexpr std::string_view domain = "3-p-254/P1";
        constexpr std::string_view path =
            "Player-Data//Mascot-Secrets-p-P1";
        assert(MascotSecretStateSourceBridge::scalar_state_begin(
            domain, path, 1024, 4, 40, true, true, scalar, scalar));
        assert(MascotSecretStateSourceBridge::setup_begin(
            domain, path, 1024, 4, 40, true, true, true, key));
        assert(MascotSecretStateSourceBridge::static_installed(
            true, key, scalar, scalar, scalar));
        const auto before = mascot_metadata(48, 91);
        assert(!MascotSecretStateSourceBridge::abort_cache_unlink_noexcept(
            MascotSecretAbortClass::MacCheckFailure,
            "Player-Data//Mascot-Secrets-substituted-P1", true, 0,
            before, {}));
        adapter.reset();
        auto capsule = finish(fixture, 0xe0);
        assert((capsule.test_only_summary().missing_family_bitmap &
                mascot_bit) != 0);
    }

    {
        auto selected = mascot_adapter_plan(
            43, MascotCacheBranch::CacheHit);
        selected.hook_inventory[
            static_cast<unsigned>(StateFamily::MascotSecrets) - 1]
            .ordered_hook_manifest_identity = digest(0xfd);
        refresh_closed_abort_families(selected);
        auto fixture = prepare_context_adapter_with_plan(std::move(selected));
        auto adapter = fixture.recorder.take_mascot_secret_state_adapter(
            fixture.root_thread);
        assert(!emit_mascot_cache_branch(MascotCacheBranch::CacheHit));
        adapter.reset();
        auto capsule = finish(fixture, 0xd1);
        assert((capsule.test_only_summary().missing_family_bitmap &
                mascot_bit) != 0);
    }
    {
        auto fixture = prepare_context_adapter_with_plan(
            mascot_adapter_plan(44, MascotCacheBranch::StaticReuse));
        auto adapter = fixture.recorder.take_mascot_secret_state_adapter(
            fixture.root_thread);
        const auto key = snapshot(0xd2);
        assert(!MascotSecretStateSourceBridge::setup_begin(
            "3-p-254/P1", "Player-Data//Mascot-Secrets-p-P1",
            1024, 4, 40, true, true, true, key));
        adapter.reset();
        auto capsule = finish(fixture, 0xd3);
        assert((capsule.test_only_summary().missing_family_bitmap &
                mascot_bit) != 0);
    }
    {
        auto fixture = prepare_context_adapter_with_plan(
            mascot_adapter_plan(45, MascotCacheBranch::CacheHit));
        auto adapter = fixture.recorder.take_mascot_secret_state_adapter(
            fixture.root_thread);
        std::thread wrong([&] {
            assert(MascotSecretStateSourceBridge::capture_required_noexcept());
        });
        wrong.join();
        adapter.reset();
        auto capsule = finish(fixture, 0xd4);
        assert((capsule.test_only_summary().missing_family_bitmap &
                mascot_bit) != 0);
    }
    {
        auto fixture = prepare_context_adapter_with_plan(
            mascot_adapter_plan(46, MascotCacheBranch::CacheHit));
        auto dropped = fixture.recorder.take_mascot_secret_state_adapter(
            fixture.root_thread);
        dropped.reset();
        auto capsule = finish(fixture, 0xd5);
        assert((capsule.test_only_summary().missing_family_bitmap &
                mascot_bit) != 0);
    }
    {
        auto first = prepare_context_adapter_with_plan(
            mascot_adapter_plan(47, MascotCacheBranch::CacheHit));
        auto second = prepare_context_adapter_with_plan(
            mascot_adapter_plan(48, MascotCacheBranch::CacheHit));
        auto retained = first.recorder.take_mascot_secret_state_adapter(
            first.root_thread);
        expect_refused([&] {
            auto cross = second.recorder.take_mascot_secret_state_adapter(
                second.root_thread);
            (void)cross;
        });
        retained.reset();
        (void)finish(first, 0xd6);
        (void)finish(second, 0xd7);
    }
    {
        auto fixture = prepare_context_adapter_with_plan(
            mascot_adapter_plan(49, MascotCacheBranch::StaticReuse));
        auto adapter = fixture.recorder.take_mascot_secret_state_adapter(
            fixture.root_thread);
        const auto key = snapshot(0xd8);
        const auto reset = snapshot(0x00);
        const auto scalar = snapshot(0xd9);
        constexpr std::string_view domain = "3-p-254/P1";
        constexpr std::string_view path =
            "Player-Data//Mascot-Secrets-p-P1";
        assert(MascotSecretStateSourceBridge::scalar_state_begin(
            domain, path, 1024, 4, 40, true, true, scalar, scalar));
        assert(MascotSecretStateSourceBridge::setup_begin(
            domain, path, 1024, 4, 40, true, true, true, key));
        assert(MascotSecretStateSourceBridge::static_installed(
            true, key, scalar, scalar, scalar));
        assert(MascotSecretStateSourceBridge::teardown(
            true, key, scalar, false, reset, scalar, scalar, scalar));
        assert(!MascotSecretStateSourceBridge::teardown(
            true, key, scalar, false, reset, scalar, scalar, scalar));
        adapter.reset();
        auto capsule = finish(fixture, 0xda);
        assert((capsule.test_only_summary().missing_family_bitmap &
                mascot_bit) != 0);
    }
}

void fail_closed_controls() {
    {
        auto fixture = prepare_complete(4);
        expect_refused([&] {
            auto late = fixture.recorder.fork_thread(
                fixture.root_thread, digest(0xaf));
            (void)late;
        });
        expect_refused([&] {
            auto late = fixture.recorder.allocate_player_fork(
                fixture.root_player, fixture.root_thread,
                digest(0xb0), snapshot(0xb1));
            (void)late;
        });
        fixture.recorder.mark_hook_unavailable(StateFamily::MacCheck);
        fixture.recorder.join_thread(
            std::move(fixture.root_thread), snapshot(0xb2));
        auto terminal = prepare_test_abort_terminal(
            fixture.recorder,
            abort_site(4, SourcePhase::TerminalEgress,
                       AbortClass::MacCheck),
            AbortClass::MacCheck,
            abort_exception(4, SourcePhase::TerminalEgress,
                            AbortClass::MacCheck));
        auto capsule = std::move(fixture.recorder).close_abort_noexcept(
            std::move(terminal));
        const auto summary = capsule.test_only_summary();
        assert(!summary.manifest_structurally_complete &&
               (summary.missing_family_bitmap &
                (std::uint64_t{1} <<
                 (static_cast<unsigned>(StateFamily::MacCheck) - 1))) != 0);
    }
    {
        auto fixture = prepare_complete(5);
        fixture.recorder.join_thread(
            std::move(fixture.root_thread), snapshot(0xb3));
        fixture.recorder.test_only_force_fd_substitution();
        auto capsule =
            std::move(fixture.recorder).close_success_noexcept();
        const auto summary = capsule.test_only_summary();
        assert(!summary.manifest_structurally_complete && summary.descriptor_retained &&
               summary.anonymous_disk_backed);
    }
    {
        auto fixture = prepare_complete(6);
        fixture.recorder.join_thread(
            std::move(fixture.root_thread), snapshot(0xb4));
        fixture.recorder.test_only_force_write_failure();
        auto capsule =
            std::move(fixture.recorder).close_success_noexcept();
        const auto summary = capsule.test_only_summary();
        assert(!summary.manifest_structurally_complete && summary.descriptor_retained &&
               summary.anonymous_disk_backed);
    }
    for (unsigned fault = 0; fault < 3; ++fault) {
        auto fixture = prepare_complete(
            static_cast<unsigned char>(9 + fault));
        fixture.recorder.join_thread(
            std::move(fixture.root_thread),
            snapshot(static_cast<unsigned char>(0xb5 + fault)));
        if (fault == 0)
            fixture.recorder.test_only_force_fsync_failure();
        else if (fault == 1)
            fixture.recorder.test_only_force_reopen_failure();
        else
            fixture.recorder.test_only_force_hash_failure();
        auto capsule =
            std::move(fixture.recorder).close_success_noexcept();
        const auto summary = capsule.test_only_summary();
        assert(!summary.manifest_structurally_complete && summary.descriptor_retained &&
               summary.anonymous_disk_backed &&
               !summary.writer_closed && !summary.read_only);
    }
    for (unsigned fault = 0; fault < 2; ++fault) {
        auto recorder = P1CorruptStateCapsulePlanAuthority::test_only_mint(
            plan(static_cast<unsigned char>(13 + fault)))
                .begin_before_player_and_protocol_setup();
        auto thread = recorder.take_root_thread_epoch();
        auto player = recorder.bind_root_player(thread, snapshot(0xc1));
        recorder.player_transition(
            player, TransitionKind::PlayerTraffic, 0, 1, snapshot(0xc0));
        auto tls = fixture_construct_object(
            recorder, StateFamily::TlsChannelState, thread, snapshot(0xc2));
        recorder.transition(
            tls, TransitionKind::TlsHandshake, 0, 13, snapshot(0xc6));
        recorder.terminal_snapshot(tls, snapshot(0xc3));
        recorder.test_only_close_reserved_family(
            StateFamily::TlsChannelState);
        recorder.player_terminal_snapshot(player, snapshot(0xc4));
        recorder.test_only_close_reserved_family(
            StateFamily::PlayerAllocation);
        recorder.advance_phase(SourcePhase::TlsAndPlayerBound);
        for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index) {
            const auto family = static_cast<StateFamily>(index + 1);
            if (family != StateFamily::PlayerAllocation &&
                family != StateFamily::TlsChannelState)
                recorder.mark_family_not_constructed_before_abort(family);
        }
        recorder.join_thread(std::move(thread), snapshot(0xc5));
        if (fault == 0)
            recorder.test_only_force_abort_token_preallocation_loss();
        else
            recorder.test_only_force_write_failure();
        expect_refused([&] {
            auto terminal = prepare_test_abort_terminal(
                recorder,
                abort_site(
                    static_cast<unsigned char>(13 + fault),
                    SourcePhase::TlsAndPlayerBound, AbortClass::Resource),
                AbortClass::Resource,
                abort_exception(
                    static_cast<unsigned char>(13 + fault),
                    SourcePhase::TlsAndPlayerBound,
                    AbortClass::Resource));
            (void)terminal;
        });
        auto capsule =
            std::move(recorder).close_unavailable_abort_noexcept(
                AbortClass::Resource, digest(0xe0 + fault));
        const auto summary = capsule.test_only_summary();
        assert(!summary.manifest_structurally_complete && summary.descriptor_retained &&
               summary.anonymous_disk_backed);
    }
    {
        auto recorder = P1CorruptStateCapsulePlanAuthority::test_only_mint(
            plan(7)).begin_before_player_and_protocol_setup();
        auto thread = recorder.take_root_thread_epoch();
        auto player = recorder.bind_root_player(thread, snapshot(0x71));
        recorder.player_transition(
            player, TransitionKind::PlayerTraffic, 0, 1, snapshot(0x70));
        recorder.player_terminal_snapshot(player, snapshot(0x72));
        recorder.test_only_close_reserved_family(
            StateFamily::PlayerAllocation);
        recorder.mark_hook_unavailable(StateFamily::TlsChannelState);
        for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index) {
            const auto family = static_cast<StateFamily>(index + 1);
            if (family != StateFamily::PlayerAllocation &&
                family != StateFamily::TlsChannelState)
                recorder.mark_family_not_constructed_before_abort(family);
        }
        recorder.join_thread(std::move(thread), snapshot(0x73));
        auto capsule = std::move(recorder).close_unavailable_abort_noexcept(
            AbortClass::Transport, digest(0xd7));
        assert(!capsule.test_only_summary().manifest_structurally_complete);
    }
    {
        auto recorder = P1CorruptStateCapsulePlanAuthority::test_only_mint(
            plan(8)).begin_before_player_and_protocol_setup();
        auto thread = recorder.take_root_thread_epoch();
        auto player = recorder.bind_root_player(thread, snapshot(0x81));
        recorder.player_transition(
            player, TransitionKind::PlayerTraffic, 0, 1, snapshot(0x80));
        recorder.player_terminal_snapshot(player, snapshot(0x82));
        recorder.test_only_close_reserved_family(
            StateFamily::PlayerAllocation);
        {
            auto dropped = fixture_construct_object(
                recorder, StateFamily::TlsChannelState, thread,
                snapshot(0x83));
            (void)dropped;
        }
        for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index) {
            const auto family = static_cast<StateFamily>(index + 1);
            if (family != StateFamily::PlayerAllocation &&
                family != StateFamily::TlsChannelState)
                recorder.mark_family_not_constructed_before_abort(family);
        }
        recorder.join_thread(std::move(thread), snapshot(0x84));
        auto capsule = std::move(recorder).close_unavailable_abort_noexcept(
            AbortClass::Transport, digest(0xd8));
        assert(!capsule.test_only_summary().manifest_structurally_complete);
    }
}

void entropy_adapter_controls() {
    using kpi::mpc::p1_private_state::EntropyIngressView;
    using kpi::mpc::p1_private_state::EntropySource;
    std::array<unsigned char, 16> mp_seed{};
    std::array<unsigned char, 32> simplest_seed{};
    std::array<unsigned char, 16> crypto_seed{};
    mp_seed.fill(0x31);
    simplest_seed.fill(0x52);
    crypto_seed.fill(0x73);
    const auto event = [](
            EntropySource source, std::uint64_t ordinal,
            std::span<const unsigned char> bytes,
            std::uint64_t thread = 1,
            std::uint64_t before = 0) {
        return EntropyIngressView{
            .source = source,
            .callsite_rva = 0x1000 + ordinal,
            .object_epoch = ordinal,
            .thread_epoch = thread,
            .allocation_epoch = ordinal,
            .counter_before = before,
            .counter_after = before + 1,
            .exact_entropy = bytes,
        };
    };

    auto positive = prepare_entropy_adapter(16);
    expect_refused([&] {
        auto forged = positive.recorder.construct_object(
            StateFamily::MpSpdzPrng, positive.root_thread,
            snapshot(0x91));
        (void)forged;
    });
    auto adapter = std::move(positive.adapter);
    expect_refused([&] {
        auto duplicate = positive.recorder.take_entropy_state_adapter(
            positive.root_thread);
        (void)duplicate;
    });

    auto other = prepare_entropy_adapter(17, false);
    expect_refused([&] {
        auto cross = other.recorder.take_entropy_state_adapter(
            positive.root_thread);
        (void)cross;
    });
    other.recorder.join_thread(
        std::move(other.root_thread), snapshot(0x92));
    auto other_capsule = std::move(other.recorder).
        close_unavailable_abort_noexcept(
            AbortClass::Transport, digest(0x93));
    assert(!other_capsule.test_only_summary().manifest_structurally_complete);

    assert(adapter->record_entropy_ingress(event(
        EntropySource::SimplestOtRandomBytes, 2, simplest_seed)));
    assert(adapter->record_entropy_ingress(event(
        EntropySource::CryptoToolsSystemSeed, 3, crypto_seed)));
    assert(adapter->entropy_capture_terminal_noexcept());
    assert(!adapter->entropy_capture_terminal_noexcept());
    adapter.reset();
    positive.recorder.join_thread(
        std::move(positive.root_thread), snapshot(0x94));
    auto captured = std::move(positive.recorder).
        close_unavailable_abort_noexcept(
            AbortClass::Transport, digest(0x95));
    const auto summary = captured.test_only_summary();
    const auto entropy_bits =
        (std::uint64_t{1} <<
         (static_cast<unsigned>(StateFamily::MpSpdzPrng) - 1)) |
        (std::uint64_t{1} <<
         (static_cast<unsigned>(StateFamily::SimplestOtBase) - 1)) |
        (std::uint64_t{1} <<
         (static_cast<unsigned>(StateFamily::CryptoToolsPrng) - 1));
    assert(!summary.manifest_structurally_complete &&
           (summary.closed_family_bitmap & entropy_bits) == entropy_bits);
    const auto archive = captured.test_only_read_all();
    assert(std::search(
        archive.begin(), archive.end(), mp_seed.begin(), mp_seed.end()) !=
        archive.end());
    assert(std::search(
        archive.begin(), archive.end(), simplest_seed.begin(),
        simplest_seed.end()) != archive.end());
    assert(std::search(
        archive.begin(), archive.end(), crypto_seed.begin(),
        crypto_seed.end()) != archive.end());

    auto wrong_counter = prepare_entropy_adapter(18);
    auto wrong_counter_adapter = std::move(wrong_counter.adapter);
    assert(!wrong_counter_adapter->record_entropy_ingress(event(
        EntropySource::MpSpdzPrngReseed, 2, mp_seed, 1, 0)));
    wrong_counter_adapter.reset();
    wrong_counter.recorder.join_thread(
        std::move(wrong_counter.root_thread), snapshot(0x96));
    auto wrong_counter_capsule = std::move(wrong_counter.recorder).
        close_unavailable_abort_noexcept(
            AbortClass::Transport, digest(0x97));
    assert((wrong_counter_capsule.test_only_summary().missing_family_bitmap &
            entropy_bits) == entropy_bits);

    auto wrong_thread = prepare_entropy_adapter(4);
    auto wrong_thread_adapter = std::move(wrong_thread.adapter);
    assert(!wrong_thread_adapter->record_entropy_ingress(event(
        EntropySource::SimplestOtRandomBytes, 2, simplest_seed, 2)));
    wrong_thread_adapter.reset();
    wrong_thread.recorder.join_thread(
        std::move(wrong_thread.root_thread), snapshot(0x98));
    (void)std::move(wrong_thread.recorder).
        close_unavailable_abort_noexcept(
            AbortClass::Transport, digest(0x99));

    auto dropped = prepare_entropy_adapter(5);
    auto dropped_adapter = std::move(dropped.adapter);
    dropped_adapter.reset();
    dropped.recorder.join_thread(
        std::move(dropped.root_thread), snapshot(0x9a));
    auto dropped_capsule = std::move(dropped.recorder).
        close_unavailable_abort_noexcept(
            AbortClass::Transport, digest(0x9b));
    assert((dropped_capsule.test_only_summary().missing_family_bitmap &
            entropy_bits) == entropy_bits);
}

kpi::mpc::p1_private_state::PlayerTlsEventView player_event(
        kpi::mpc::p1_private_state::PlayerTlsEventKind kind) {
    kpi::mpc::p1_private_state::PlayerTlsEventView result{};
    result.kind = kind;
    result.local_role = 1;
    result.player_count = 3;
    result.player_id = "registered-roster";
    return result;
}

kpi::mpc::p1_private_state::PlayerTlsEventView channel_event(
        kpi::mpc::p1_private_state::PlayerTlsEventKind kind,
        std::uint64_t peer, std::uint64_t lane) {
    auto result = player_event(kind);
    result.peer_role = peer;
    result.lane = lane;
    result.client = peer < 1;
    return result;
}

void player_tls_prefix_adapter_controls() {
    const std::array<unsigned char, 5> certificate{1, 2, 3, 4, 5};
    const std::array<unsigned char, 7> private_key{
        0xfa, 0xce, 0xb0, 0x0c, 0x11, 0x22, 0x33};
    const std::array<unsigned char, 4> client_random{1, 1, 1, 1};
    const std::array<unsigned char, 4> server_random{2, 2, 2, 2};
    const std::array<unsigned char, 4> master_key{3, 3, 3, 3};
    const std::array<unsigned char, 2> session_id{4, 4};
    const std::array<unsigned char, 3> local_certificate{5, 5, 5};
    const std::array<unsigned char, 3> verified_chain{6, 6, 6};

    auto recorder = P1CorruptStateCapsulePlanAuthority::test_only_mint(
        plan(9)).begin_before_player_and_protocol_setup();
    auto thread = recorder.take_root_thread_epoch();
    auto adapter = recorder.take_player_tls_state_adapter(thread);
    assert(adapter->record_player_tls_event(player_event(
        kpi::mpc::p1_private_state::PlayerTlsEventKind::
            PlayerConstructionStarted)));
    auto context = player_event(
        kpi::mpc::p1_private_state::PlayerTlsEventKind::TlsContextLoaded);
    context.payloads[0] = certificate;
    context.payloads[1] = private_key;
    assert(adapter->record_player_tls_event(context));
    for (const std::uint64_t peer : {0U, 2U}) {
        for (std::uint64_t lane = 0; lane < 2; ++lane) {
            assert(adapter->record_player_tls_event(channel_event(
                kpi::mpc::p1_private_state::PlayerTlsEventKind::
                    TlsChannelStarted,
                peer, lane)));
            auto complete = channel_event(
                kpi::mpc::p1_private_state::PlayerTlsEventKind::
                    TlsHandshakeComplete,
                peer, lane);
            complete.protocol_name = "TLSv1.2";
            complete.cipher_name = "TEST-CIPHER";
            complete.payloads[0] = client_random;
            complete.payloads[1] = server_random;
            complete.payloads[2] = master_key;
            complete.payloads[3] = session_id;
            complete.payloads[4] = local_certificate;
            complete.payloads[5] = verified_chain;
            assert(adapter->record_player_tls_event(complete));
            assert(!adapter->record_player_tls_event(complete));
            if (lane == 0 && peer == 0) break;
        }
        if (peer == 0) break;
    }
    adapter.reset();
    recorder.join_thread(std::move(thread), snapshot(0xd0));
    auto duplicate = std::move(recorder).close_unavailable_abort_noexcept(
        AbortClass::Transport, digest(0xd1));
    assert(!duplicate.test_only_summary().manifest_structurally_complete);

    auto positive_recorder =
        P1CorruptStateCapsulePlanAuthority::test_only_mint(
            plan(10)).begin_before_player_and_protocol_setup();
    auto positive_thread = positive_recorder.take_root_thread_epoch();
    auto positive = positive_recorder.take_player_tls_state_adapter(
        positive_thread);
    assert(positive->record_player_tls_event(player_event(
        kpi::mpc::p1_private_state::PlayerTlsEventKind::
            PlayerConstructionStarted)));
    assert(positive->record_player_tls_event(context));
    for (const std::uint64_t peer : {0U, 2U}) {
        for (std::uint64_t lane = 0; lane < 2; ++lane) {
            assert(positive->record_player_tls_event(channel_event(
                kpi::mpc::p1_private_state::PlayerTlsEventKind::
                    TlsChannelStarted,
                peer, lane)));
            auto complete = channel_event(
                kpi::mpc::p1_private_state::PlayerTlsEventKind::
                    TlsHandshakeComplete,
                peer, lane);
            complete.protocol_name = "TLSv1.2";
            complete.cipher_name = "TEST-CIPHER";
            complete.payloads[0] = client_random;
            complete.payloads[1] = server_random;
            complete.payloads[2] = master_key;
            complete.payloads[3] = session_id;
            complete.payloads[4] = local_certificate;
            complete.payloads[5] = verified_chain;
            assert(positive->record_player_tls_event(complete));
            if (peer == 0 && lane == 0) {
                auto post_handshake = channel_event(
                    kpi::mpc::p1_private_state::PlayerTlsEventKind::TlsInfo,
                    peer, lane);
                post_handshake.info_where = 0x20;
                assert(positive->record_player_tls_event(post_handshake));
            }
        }
    }
    assert(positive->record_player_tls_event(player_event(
        kpi::mpc::p1_private_state::PlayerTlsEventKind::
            PlayerConstructed)));
    positive_recorder.advance_phase(SourcePhase::TlsAndPlayerBound);
    positive_recorder.advance_phase(SourcePhase::ProtocolSetupStarted);

    auto fork_started = player_event(
        kpi::mpc::p1_private_state::PlayerTlsEventKind::
            PlayerConstructionStarted);
    fork_started.player_id = "registered-roster-soft";
    fork_started.parent_player_id = "registered-roster";
    assert(positive->record_player_tls_event(fork_started));
    auto fork_context = context;
    fork_context.player_id = "registered-roster-soft";
    assert(positive->record_player_tls_event(fork_context));
    for (const std::uint64_t peer : {0U, 2U}) {
        for (std::uint64_t lane = 0; lane < 2; ++lane) {
            auto fork_channel = channel_event(
                kpi::mpc::p1_private_state::PlayerTlsEventKind::
                    TlsChannelStarted,
                peer, lane);
            fork_channel.player_id = "registered-roster-soft";
            assert(positive->record_player_tls_event(fork_channel));
            auto fork_complete = channel_event(
                kpi::mpc::p1_private_state::PlayerTlsEventKind::
                    TlsHandshakeComplete,
                peer, lane);
            fork_complete.player_id = "registered-roster-soft";
            fork_complete.protocol_name = "TLSv1.2";
            fork_complete.cipher_name = "TEST-CIPHER";
            fork_complete.payloads[0] = client_random;
            fork_complete.payloads[1] = server_random;
            fork_complete.payloads[2] = master_key;
            fork_complete.payloads[3] = session_id;
            fork_complete.payloads[4] = local_certificate;
            fork_complete.payloads[5] = verified_chain;
            assert(positive->record_player_tls_event(fork_complete));
        }
    }
    auto fork_constructed = player_event(
        kpi::mpc::p1_private_state::PlayerTlsEventKind::PlayerConstructed);
    fork_constructed.player_id = "registered-roster-soft";
    fork_constructed.parent_player_id = "registered-roster";
    assert(positive->record_player_tls_event(fork_constructed));
    positive.reset();
    positive_recorder.join_thread(
        std::move(positive_thread), snapshot(0xd2));
    auto captured = std::move(positive_recorder).
        close_unavailable_abort_noexcept(
            AbortClass::Transport, digest(0xd3));
    const auto summary = captured.test_only_summary();
    assert(!summary.manifest_structurally_complete);
    const auto missing =
        (std::uint64_t{1} <<
         (static_cast<unsigned>(StateFamily::PlayerAllocation) - 1)) |
        (std::uint64_t{1} <<
         (static_cast<unsigned>(StateFamily::TlsChannelState) - 1));
    assert((summary.missing_family_bitmap & missing) == missing);
    const auto archive = captured.test_only_read_all();
    assert(std::search(
        archive.begin(), archive.end(), private_key.begin(),
        private_key.end()) != archive.end());

    auto wrong_recorder = P1CorruptStateCapsulePlanAuthority::test_only_mint(
        plan(11)).begin_before_player_and_protocol_setup();
    auto wrong_thread = wrong_recorder.take_root_thread_epoch();
    auto wrong = wrong_recorder.take_player_tls_state_adapter(wrong_thread);
    auto wrong_role = player_event(
        kpi::mpc::p1_private_state::PlayerTlsEventKind::
            PlayerConstructionStarted);
    wrong_role.local_role = 0;
    assert(!wrong->record_player_tls_event(wrong_role));
    wrong.reset();
    wrong_recorder.join_thread(std::move(wrong_thread), snapshot(0xd4));
    auto wrong_capsule = std::move(wrong_recorder).
        close_unavailable_abort_noexcept(
            AbortClass::Transport, digest(0xd5));
    assert(!wrong_capsule.test_only_summary().manifest_structurally_complete);

    auto wrong_client_recorder =
        P1CorruptStateCapsulePlanAuthority::test_only_mint(
            plan(6)).begin_before_player_and_protocol_setup();
    auto wrong_client_thread =
        wrong_client_recorder.take_root_thread_epoch();
    auto wrong_client = wrong_client_recorder.take_player_tls_state_adapter(
        wrong_client_thread);
    assert(wrong_client->record_player_tls_event(player_event(
        kpi::mpc::p1_private_state::PlayerTlsEventKind::
            PlayerConstructionStarted)));
    assert(wrong_client->record_player_tls_event(context));
    auto bad_channel = channel_event(
        kpi::mpc::p1_private_state::PlayerTlsEventKind::TlsChannelStarted,
        0, 0);
    bad_channel.client = 0;
    assert(!wrong_client->record_player_tls_event(bad_channel));
    wrong_client.reset();
    wrong_client_recorder.join_thread(
        std::move(wrong_client_thread), snapshot(0xda));
    auto wrong_client_capsule = std::move(wrong_client_recorder).
        close_unavailable_abort_noexcept(
            AbortClass::Transport, digest(0xdb));
    assert(!wrong_client_capsule.test_only_summary().
        manifest_structurally_complete);

    auto flipped_recorder = P1CorruptStateCapsulePlanAuthority::test_only_mint(
        plan(7)).begin_before_player_and_protocol_setup();
    auto flipped_thread = flipped_recorder.take_root_thread_epoch();
    auto flipped = flipped_recorder.take_player_tls_state_adapter(
        flipped_thread);
    assert(flipped->record_player_tls_event(player_event(
        kpi::mpc::p1_private_state::PlayerTlsEventKind::
            PlayerConstructionStarted)));
    assert(flipped->record_player_tls_event(context));
    assert(flipped->record_player_tls_event(channel_event(
        kpi::mpc::p1_private_state::PlayerTlsEventKind::TlsChannelStarted,
        0, 0)));
    auto flipped_info = channel_event(
        kpi::mpc::p1_private_state::PlayerTlsEventKind::TlsInfo, 0, 0);
    flipped_info.client = 0;
    assert(!flipped->record_player_tls_event(flipped_info));
    flipped.reset();
    flipped_recorder.join_thread(
        std::move(flipped_thread), snapshot(0xdc));
    (void)std::move(flipped_recorder).close_unavailable_abort_noexcept(
        AbortClass::Transport, digest(0xdd));

    auto no_op_recorder = P1CorruptStateCapsulePlanAuthority::test_only_mint(
        plan(12)).begin_before_player_and_protocol_setup();
    auto no_op_thread = no_op_recorder.take_root_thread_epoch();
    auto no_op = no_op_recorder.take_player_tls_state_adapter(no_op_thread);
    no_op.reset();
    no_op_recorder.join_thread(std::move(no_op_thread), snapshot(0xd6));
    auto no_op_capsule = std::move(no_op_recorder).
        close_unavailable_abort_noexcept(
            AbortClass::Transport, digest(0xd7));
    assert(!no_op_capsule.test_only_summary().manifest_structurally_complete);

    // Closing while the sole adapter is still live must retain both reserved
    // families as missing. A later adapter destructor cannot retroactively
    // change or promote the detached capsule result.
    auto live_recorder = P1CorruptStateCapsulePlanAuthority::test_only_mint(
        plan(13)).begin_before_player_and_protocol_setup();
    auto live_thread = live_recorder.take_root_thread_epoch();
    auto live = live_recorder.take_player_tls_state_adapter(live_thread);
    live_recorder.join_thread(std::move(live_thread), snapshot(0xd8));
    auto live_capsule = std::move(live_recorder).
        close_unavailable_abort_noexcept(
            AbortClass::Transport, digest(0xd9));
    const auto before_drop = live_capsule.test_only_summary();
    assert(!before_drop.manifest_structurally_complete &&
           (before_drop.missing_family_bitmap & missing) == missing);
    live.reset();
    const auto after_drop = live_capsule.test_only_summary();
    assert(after_drop.missing_family_bitmap ==
           before_drop.missing_family_bitmap);
}

} // namespace

P1CorruptStateCapsulePlanAuthority
kpb::measurement::p1_state_capsule::test_fixture::
matching_plan_for_adoption(
        const kpi::mpc::financial::registered_driver::
            P1StateArchiveWriterAdoptionAuthority& adoption) {
    return P1CorruptStateCapsulePlanAuthority::
        test_only_mint_matching_writer_adoption(plan(13), adoption);
}

P1CorruptStateCapsuleAuthority
kpb::measurement::p1_state_capsule::test_fixture::closed_unavailable(
        unsigned round) {
    if (round != 1 && round != 2) throw Refused();
    auto selected = plan(static_cast<unsigned char>(round));
    selected.round = round;
    auto recorder = P1CorruptStateCapsulePlanAuthority::test_only_mint(
        std::move(selected)).begin_before_player_and_protocol_setup();
    auto thread = recorder.take_root_thread_epoch();
    auto player = recorder.bind_root_player(thread, snapshot(0xf1));
    recorder.player_transition(
        player, TransitionKind::PlayerTraffic, 0, 1, snapshot(0xf2));
    recorder.player_terminal_snapshot(player, snapshot(0xf3));
    recorder.test_only_close_reserved_family(StateFamily::PlayerAllocation);
    recorder.mark_hook_unavailable(StateFamily::TlsChannelState);
    for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index) {
        const auto family = static_cast<StateFamily>(index + 1);
        if (family != StateFamily::PlayerAllocation &&
            family != StateFamily::TlsChannelState)
            recorder.mark_family_not_constructed_before_abort(family);
    }
    recorder.join_thread(std::move(thread), snapshot(0xf4));
    return std::move(recorder).close_unavailable_abort_noexcept(
        AbortClass::Transport, digest(0xf5));
}

P1CorruptStateCapsuleAuthority
kpb::measurement::p1_state_capsule::test_fixture::
closed_unavailable_adopting(
        kpi::mpc::financial::registered_driver::
            P1StateArchiveWriterAdoptionAuthority&& adoption) {
    auto plan_authority = P1CorruptStateCapsulePlanAuthority::
        test_only_mint_matching_writer_adoption(plan(13), adoption);
    auto recorder = std::move(plan_authority).
        begin_before_player_and_protocol_setup(std::move(adoption));
    auto thread = recorder.take_root_thread_epoch();
    auto adapter = recorder.take_player_tls_state_adapter(thread);
    auto started = player_event(
        kpi::mpc::p1_private_state::PlayerTlsEventKind::
            PlayerConstructionStarted);
    assert(adapter->record_player_tls_event(started));
    adapter.reset();
    for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index) {
        const auto family = static_cast<StateFamily>(index + 1);
        if (family != StateFamily::PlayerAllocation &&
            family != StateFamily::TlsChannelState)
            recorder.mark_family_not_constructed_before_abort(family);
    }
    recorder.join_thread(std::move(thread), snapshot(0xf6));
    return std::move(recorder).close_unavailable_abort_noexcept(
        AbortClass::Transport, digest(0xf7));
}

bool kpb::measurement::p1_state_capsule::test_fixture::
wrong_round_adoption_refused(
        kpi::mpc::financial::registered_driver::
            P1StateArchiveWriterAdoptionAuthority&& adoption) {
    try {
        auto selected = P1CorruptStateCapsulePlanAuthority::
            test_only_mint_wrong_writer_adoption(
                plan(14), adoption, true);
        (void)std::move(selected).begin_before_player_and_protocol_setup(
            std::move(adoption));
    } catch (const Refused&) { return true; }
    return false;
}

bool kpb::measurement::p1_state_capsule::test_fixture::
wrong_reservation_adoption_refused(
        kpi::mpc::financial::registered_driver::
            P1StateArchiveWriterAdoptionAuthority&& adoption) {
    try {
        auto selected = P1CorruptStateCapsulePlanAuthority::
            test_only_mint_wrong_writer_adoption(
                plan(15), adoption, false);
        (void)std::move(selected).begin_before_player_and_protocol_setup(
            std::move(adoption));
    } catch (const Refused&) { return true; }
    return false;
}

void prelaunch_binding_controls() {
    const auto refuse_plan = [](StaticStateCapsulePlan selected) {
        expect_refused([&] {
            (void)P1CorruptStateCapsulePlanAuthority::test_only_mint(
                std::move(selected));
        });
    };

    auto selected = plan(0);
    assert(selected.prelaunch.binding_identity ==
           recompute_p1_state_capsule_prelaunch_binding_identity(
               selected.prelaunch));

    auto substituted = selected;
    substituted.prelaunch.route_policy_identity[0] ^= 0x01;
    refuse_plan(std::move(substituted));

    auto reordered_attempts = selected;
    std::swap(reordered_attempts.prelaunch.capture_attempt_ids[0],
              reordered_attempts.prelaunch.capture_attempt_ids[1]);
    refuse_plan(std::move(reordered_attempts));

    auto reordered_rounds = selected;
    std::swap(reordered_rounds.prelaunch.round_attempts[0],
              reordered_rounds.prelaunch.round_attempts[1]);
    refuse_plan(std::move(reordered_rounds));

    auto wrong_manifest = selected;
    wrong_manifest.prelaunch.finite_manifest.entries[0].source_identity[0] ^=
        0x01;
    refuse_plan(std::move(wrong_manifest));

    const auto mark_missing = [](StaticStateCapsulePlan& value,
                                 StateFamily family) {
        const auto index = static_cast<unsigned>(family) - 1;
        value.source_family_dispositions[index] =
            SourceFamilyDisposition::Missing;
        value.serializer_identities[index] =
            canonical_missing_family_serializer_identity(family);
        value.hook_inventory[index] =
            canonical_missing_family_hook_inventory(family);
        for (auto& terminal : value.abort_terminals)
            terminal.families[index] =
                not_constructed_abort_family(family);
        value.abort_terminal_manifest_identity =
            recompute_abort_terminal_manifest_identity(
                value.abort_terminals);
    };
    constexpr auto missing_family = StateFamily::OnDemandOtMap;
    constexpr auto missing_index =
        static_cast<unsigned>(missing_family) - 1;

    auto canonical_missing = plan(1);
    mark_missing(canonical_missing, missing_family);
    auto missing_authority =
        P1CorruptStateCapsulePlanAuthority::test_only_mint(
            std::move(canonical_missing));
    auto missing_recorder =
        std::move(missing_authority).begin_before_player_and_protocol_setup();
    auto missing_thread = missing_recorder.take_root_thread_epoch();
    expect_refused([&] {
        (void)missing_recorder.construct_object(
            missing_family, missing_thread, snapshot(0xf1));
    });
    expect_refused([&] {
        missing_recorder.close_family(missing_family);
    });
    missing_recorder.mark_family_not_constructed_before_abort(
        missing_family);
    missing_recorder.join_thread(std::move(missing_thread), snapshot(0xf2));
    auto missing_capsule =
        std::move(missing_recorder).close_unavailable_abort_noexcept(
            AbortClass::Transport, digest(0xf3));
    const auto missing_summary = missing_capsule.test_only_summary();
    assert(!missing_summary.manifest_structurally_complete &&
           (missing_summary.missing_family_bitmap &
            (std::uint64_t{1} << missing_index)) != 0 &&
           (missing_summary.not_constructed_bitmap &
            (std::uint64_t{1} << missing_index)) != 0);

    // The test-only all-Missing grammar must still have a reachable typed
    // pre-player abort. No production plan minter exists. In particular,
    // PlayerAllocation and TLS can be marked NotConstructed while the
    // recorder remains in RecorderStarted.
    auto all_missing = plan(7);
    for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index)
        mark_missing(all_missing, static_cast<StateFamily>(index + 1));
    all_missing.mp_spdz_source_identity =
        canonical_missing_prelaunch_dependency_identity(
            PrelaunchDependency::MpSpdzSource);
    all_missing.simplest_ot_source_identity =
        canonical_missing_prelaunch_dependency_identity(
            PrelaunchDependency::SimplestOtSource);
    all_missing.libote_source_identity =
        canonical_missing_prelaunch_dependency_identity(
            PrelaunchDependency::LibOteSource);
    all_missing.crypto_tools_source_identity =
        canonical_missing_prelaunch_dependency_identity(
            PrelaunchDependency::CryptoToolsSource);
    all_missing.openssl_source_identity =
        canonical_missing_prelaunch_dependency_identity(
            PrelaunchDependency::OpenSslSource);
    all_missing.online_options_identity =
        canonical_missing_prelaunch_dependency_identity(
            PrelaunchDependency::OnlineOptions);
    all_missing.mascot_secrets_policy_identity =
        canonical_missing_prelaunch_dependency_identity(
            PrelaunchDependency::MascotSecretsPolicy);
    all_missing.archive_filesystem_identity =
        canonical_missing_prelaunch_dependency_identity(
            PrelaunchDependency::ArchiveFilesystem);
    AbortTerminalHookInventory unavailable_terminal{
        .terminal_site_identity = digest(0x74),
        .exception_type_identity = digest(0x75),
        .phase = SourcePhase::RecorderStarted,
        .abort_class = AbortClass::Resource,
    };
    for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index)
        unavailable_terminal.families[index] =
            not_constructed_abort_family(
                static_cast<StateFamily>(index + 1));
    all_missing.abort_terminals = {unavailable_terminal};
    all_missing.abort_terminal_manifest_identity =
        recompute_abort_terminal_manifest_identity(
            all_missing.abort_terminals);
    auto false_captured_dependency = all_missing;
    false_captured_dependency.openssl_source_identity = digest(0x77);
    refuse_plan(std::move(false_captured_dependency));
    auto all_missing_recorder =
        P1CorruptStateCapsulePlanAuthority::test_only_mint(
            std::move(all_missing))
            .begin_before_player_and_protocol_setup();
    auto all_missing_thread =
        all_missing_recorder.take_root_thread_epoch();
    for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index)
        all_missing_recorder.mark_family_not_constructed_before_abort(
            static_cast<StateFamily>(index + 1));
    all_missing_recorder.join_thread(
        std::move(all_missing_thread), snapshot(0x76));
    auto all_missing_terminal = prepare_test_abort_terminal(
        all_missing_recorder, digest(0x74), AbortClass::Resource,
        digest(0x75));
    auto all_missing_capsule =
        std::move(all_missing_recorder).close_abort_noexcept(
            std::move(all_missing_terminal));
    const auto all_missing_summary =
        all_missing_capsule.test_only_summary();
    constexpr std::uint64_t all_family_bits =
        (std::uint64_t{1} << STATE_FAMILY_COUNT) - 1;
    assert(all_missing_summary.not_constructed_bitmap == all_family_bits &&
           all_missing_summary.missing_family_bitmap == all_family_bits &&
           !all_missing_summary.manifest_structurally_complete);

    auto missing_bad_inventory = plan(2);
    mark_missing(missing_bad_inventory, missing_family);
    ++missing_bad_inventory.hook_inventory[missing_index].exact_object_count;
    refuse_plan(std::move(missing_bad_inventory));

    auto missing_bad_serializer = plan(3);
    mark_missing(missing_bad_serializer, missing_family);
    missing_bad_serializer.serializer_identities[missing_index] = digest(0xf4);
    refuse_plan(std::move(missing_bad_serializer));

    auto caller_promoted = plan(4);
    mark_missing(caller_promoted, missing_family);
    caller_promoted.source_family_dispositions[missing_index] =
        SourceFamilyDisposition::Captured;
    refuse_plan(std::move(caller_promoted));

    auto missing_bad_abort = plan(5);
    mark_missing(missing_bad_abort, missing_family);
    missing_bad_abort.abort_terminals.back().families[missing_index] =
        closed_abort_family(plan(5).hook_inventory[missing_index]);
    missing_bad_abort.abort_terminal_manifest_identity =
        recompute_abort_terminal_manifest_identity(
            missing_bad_abort.abort_terminals);
    refuse_plan(std::move(missing_bad_abort));

    auto invalid_disposition = plan(6);
    invalid_disposition.source_family_dispositions[missing_index] =
        SourceFamilyDisposition{};
    refuse_plan(std::move(invalid_disposition));

    auto impossible_captured_counts = plan(8);
    impossible_captured_counts.hook_inventory[0].exact_transition_count = 100;
    refuse_plan(std::move(impossible_captured_counts));

    auto cross_family_transition = plan(9);
    cross_family_transition.hook_inventory[0].required_transition_bitmap =
        std::uint64_t{1} <<
        (static_cast<unsigned>(TransitionKind::TlsHandshake) - 1);
    refuse_plan(std::move(cross_family_transition));

    auto replay = P1CorruptStateCapsulePlanAuthority::test_only_mint(
        std::move(selected));
    auto recorder = std::move(replay).begin_before_player_and_protocol_setup();
    expect_refused([&] {
        (void)std::move(replay).begin_before_player_and_protocol_setup();
    });
    auto thread = recorder.take_root_thread_epoch();
    recorder.join_thread(std::move(thread), snapshot(0xfa));
    (void)std::move(recorder).close_unavailable_abort_noexcept(
        AbortClass::Transport, digest(0xfb));
}

int p1_corrupt_state_capsule_control_main() {
    static_assert(!std::copy_constructible<P1CorruptStateCapsulePlanAuthority>);
    static_assert(!std::copy_constructible<P1CorruptStateRecorderAuthority>);
    static_assert(!std::copy_constructible<P1StateThreadEpochAuthority>);
    static_assert(!std::copy_constructible<P1StateObjectEpochAuthority>);
    static_assert(!std::copy_constructible<P1PlayerAllocationEpochAuthority>);
    static_assert(!std::copy_constructible<P1CorruptStateCapsuleAuthority>);
    static_assert(p1_state_capsule::kSourceStatus.source_only_capsule_authority);
    static_assert(
        p1_state_capsule::kSourceStatus.chronology_correct_prelaunch_binding);
    static_assert(
        p1_state_capsule::kSourceStatus.
            source_family_missing_disposition_grammar);
    static_assert(
        p1_state_capsule::kSourceStatus.missing_family_cannot_complete);
    static_assert(
        !p1_state_capsule::kSourceStatus.source_owned_prelaunch_minter);
    static_assert(!p1_state_capsule::kSourceStatus.role1_activation_attachment);
    static_assert(
        p1_state_capsule::kSourceStatus.role0_role2_compiletime_absence);
    static_assert(
        !p1_state_capsule::kSourceStatus.postrun_projection_exit_residual);
    static_assert(!p1_state_capsule::kSourceStatus.success_and_abort_close);
    static_assert(p1_state_capsule::kSourceStatus.tls_private_state_family);
    static_assert(
        p1_state_capsule::kSourceStatus.player_tls_prefix_capsule_adapter);
    static_assert(
        p1_state_capsule::kSourceStatus.entropy_ingress_capsule_adapter);
    static_assert(
        p1_state_capsule::kSourceStatus.query_msm_checker_temporary_family);
    static_assert(
        !p1_state_capsule::kSourceStatus.begins_before_player_construction);
    static_assert(!p1_state_capsule::kSourceStatus.pinned_upstream_serializers);
    static_assert(!p1_state_capsule::kSourceStatus.replay_sufficiency_verified);
    static_assert(!p1_state_capsule::kSourceStatus.complete_passive_p1_view);
    static_assert(!p1_state_capsule::kSourceStatus.configured);
    complete_success_and_abort();
    adversarial_state_machine();
    terminal_prefix_controls();
    context_adapter_controls();
    mascot_adapter_controls();
    entropy_adapter_controls();
    player_tls_prefix_adapter_controls();
    fail_closed_controls();
    prelaunch_binding_controls();
    auto unavailable_round1 =
        p1_state_capsule::test_fixture::closed_unavailable(1);
    auto unavailable_round2 =
        p1_state_capsule::test_fixture::closed_unavailable(2);
    assert(!unavailable_round1.test_only_summary().manifest_structurally_complete);
    assert(!unavailable_round2.test_only_summary().manifest_structurally_complete);
    return 0;
}

#ifndef KPB_P1_STATE_CAPSULE_FIXTURE_LIBRARY
int main() { return p1_corrupt_state_capsule_control_main(); }
#endif
