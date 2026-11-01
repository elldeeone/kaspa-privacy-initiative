#include "privacy_p1_corrupt_state_capsule_authority.hpp"
#include "privacy_p1_corrupt_state_capsule_child_disposition_internal.hpp"
#include "../mpc-prover/financial/registered_p1_state_archive_writer_adoption_internal.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <cstdio>
#include <ctime>
#include <fcntl.h>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <set>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <thread>
#include <unistd.h>
#include <tuple>
#include <utility>
#include <vector>

namespace kpb::measurement::p1_state_capsule {
namespace {

constexpr std::array<unsigned char, 8> MAGIC{
    'K', 'P', 'B', 'P', '1', 'S', '0', '6'};
constexpr std::uint32_t SCHEMA_VERSION = 2;
constexpr std::size_t HEADER_BYTES = 176;
constexpr std::uint64_t FULL_FAMILY_BITMAP =
    (std::uint64_t{1} << STATE_FAMILY_COUNT) - 1;

enum class RecordType : std::uint8_t {
    Construct = 1,
    Transition = 2,
    TerminalSnapshot = 3,
    Release = 4,
    FamilyClosed = 5,
    NotConstructed = 6,
    Missing = 7,
    ThreadEpoch = 8,
    Terminal = 9,
    Phase = 10,
    AbortTerminal = 11,
    AbortPrefixClosed = 12,
    AbortEvent = 13,
};

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

bool transition_allowed(StateFamily, TransitionKind);

void need_allowed_transition_bitmap(
        StateFamily family, std::uint64_t bitmap) {
    for (unsigned value = 1;
         value <= static_cast<unsigned>(TransitionKind::CheckerStage);
         ++value) {
        const auto bit = std::uint64_t{1} << (value - 1);
        if ((bitmap & bit) != 0)
            need(transition_allowed(
                family, static_cast<TransitionKind>(value)));
    }
}

void close_fd(int& fd) noexcept {
    if (fd < 0) return;
    while (::close(fd) != 0 && errno == EINTR) {}
    fd = -1;
}

void put_u32(unsigned char* out, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8)
        *out++ = static_cast<unsigned char>(value >> shift);
}

void put_u64(unsigned char* out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        *out++ = static_cast<unsigned char>(value >> shift);
}

void append_u64(std::vector<unsigned char>& out, std::uint64_t value) {
    const auto old = out.size();
    out.resize(old + 8);
    put_u64(out.data() + old, value);
}

void append_digest(std::vector<unsigned char>& out, const Digest& value) {
    out.insert(out.end(), value.begin(), value.end());
}

Digest hash(std::span<const unsigned char> bytes) {
    Digest result{};
    need(SHA256(bytes.data(), bytes.size(), result.data()) != nullptr &&
         nonzero(result));
    return result;
}

class HashState final {
    struct Deleter {
        void operator()(EVP_MD_CTX* value) const { EVP_MD_CTX_free(value); }
    };
    std::unique_ptr<EVP_MD_CTX, Deleter> context_{EVP_MD_CTX_new()};

public:
    HashState() {
        need(context_ != nullptr &&
             EVP_DigestInit_ex(context_.get(), EVP_sha256(), nullptr) == 1);
    }
    void update(std::span<const unsigned char> bytes) {
        need(EVP_DigestUpdate(
                 context_.get(), bytes.data(), bytes.size()) == 1);
    }
    Digest finish() {
        Digest result{};
        unsigned size = 0;
        need(EVP_DigestFinal_ex(context_.get(), result.data(), &size) == 1 &&
             size == result.size() && nonzero(result));
        return result;
    }
};

void write_all_at(int fd, std::span<const unsigned char> bytes,
                  std::uint64_t offset) {
    need(fd >= 0 &&
         offset <= static_cast<std::uint64_t>(
             std::numeric_limits<off_t>::max()) &&
         bytes.size() <= static_cast<std::uint64_t>(
             std::numeric_limits<off_t>::max()) - offset);
    std::size_t written = 0;
    while (written < bytes.size()) {
        ssize_t count;
        do {
            count = ::pwrite(
                fd, bytes.data() + written, bytes.size() - written,
                static_cast<off_t>(offset + written));
        } while (count < 0 && errno == EINTR);
        need(count > 0);
        written += static_cast<std::size_t>(count);
    }
}

Digest hash_fd(int fd, std::uint64_t size) {
    HashState state;
    std::array<unsigned char, 1U << 16> buffer{};
    std::uint64_t offset = 0;
    while (offset < size) {
        const auto request = static_cast<std::size_t>(
            std::min<std::uint64_t>(buffer.size(), size - offset));
        ssize_t count;
        do {
            count = ::pread(fd, buffer.data(), request,
                            static_cast<off_t>(offset));
        } while (count < 0 && errno == EINTR);
        need(count > 0);
        state.update({buffer.data(), static_cast<std::size_t>(count)});
        offset += static_cast<std::uint64_t>(count);
    }
    return state.finish();
}

std::uint64_t monotonic_ns() {
    struct timespec value{};
    need(::clock_gettime(CLOCK_MONOTONIC, &value) == 0 &&
         value.tv_sec >= 0 && value.tv_nsec >= 0);
    return static_cast<std::uint64_t>(value.tv_sec) * 1'000'000'000ULL +
           static_cast<std::uint64_t>(value.tv_nsec);
}

void need_worker(const WorkerBinding& worker) {
    for (const auto* value : {
             &worker.source_identity, &worker.build_identity,
             &worker.runtime_identity, &worker.assets_identity,
             &worker.pinned_executable_identity, &worker.launcher_identity})
        need(nonzero(*value));
}

WorkerBinding worker_from_entry(const ManifestEntry& entry) {
    return {
        .source_identity = entry.source_identity,
        .build_identity = entry.build_identity,
        .runtime_identity = entry.runtime_identity,
        .assets_identity = entry.assets_identity,
        .pinned_executable_identity = entry.pinned_executable_identity,
        .launcher_identity = entry.launcher_identity,
    };
}

WorkerBinding p1_worker(const P1StateCapsulePrelaunchBinding& binding) {
    const auto index = static_cast<unsigned>(ManifestComponent::P1Capture) - 1;
    need(index < binding.finite_manifest.entries.size());
    const auto& entry = binding.finite_manifest.entries[index];
    need(entry.component == ManifestComponent::P1Capture);
    return worker_from_entry(entry);
}

void validate_prelaunch_binding(
        const P1StateCapsulePrelaunchBinding& binding) {
    need(binding.classification == Classification::TransparentBaseline ||
         binding.classification == Classification::HiddenCandidate);
    for (const auto* value : {
             &binding.comparison_selection, &binding.run_selection,
             &binding.trial, &binding.measurement_attempt,
             &binding.measurement_cohort, &binding.capture, &binding.method,
             &binding.workload, &binding.source_closure, &binding.runtime,
             &binding.outer_parent_process,
             &binding.outer_parent_executable, &binding.capture_source,
             &binding.capture_build, &binding.capture_runtime,
             &binding.capture_launcher, &binding.financial_runs[0],
             &binding.financial_runs[1], &binding.round_attempts[0],
             &binding.round_attempts[1], &binding.round_cohorts[0],
             &binding.round_cohorts[1], &binding.round_capture_plans[0],
             &binding.round_capture_plans[1],
             &binding.process_reservation_identity,
             &binding.persistent_process_session_identity,
             &binding.fork_plan_identities[0],
             &binding.fork_plan_identities[1],
             &binding.producer_process_identity,
             &binding.role_closure_identity, &binding.manifest_seal,
             &binding.construction_policy_identity,
             &binding.construction_classification_receipt,
             &binding.route_policy_identity, &binding.stream_policy_identity,
             &binding.binding_identity})
        need(nonzero(*value));
    need(!binding.capture_trial_id.empty() &&
         !binding.capture_attempt_ids[0].empty() &&
         !binding.capture_attempt_ids[1].empty() &&
         binding.capture_attempt_ids[0] != binding.capture_attempt_ids[1] &&
         binding.run_selection != binding.comparison_selection &&
         binding.trial != binding.measurement_attempt &&
         binding.measurement_attempt != binding.measurement_cohort &&
         binding.financial_runs[0] != binding.financial_runs[1] &&
         binding.round_attempts[0] != binding.round_attempts[1] &&
         binding.round_cohorts[0] != binding.round_cohorts[1] &&
         binding.round_capture_plans[0] !=
             binding.round_capture_plans[1]);
    need(nonzero(binding.finite_manifest.manifest_identity) &&
         nonzero(binding.finite_manifest.parent_recomputation_identity) &&
         binding.finite_manifest.manifest_identity !=
             binding.finite_manifest.parent_recomputation_identity &&
         binding.finite_manifest.manifest_identity ==
             recompute_finite_manifest_identity(
                 binding.finite_manifest.entries));
    for (unsigned index = 0;
         index < binding.finite_manifest.entries.size(); ++index) {
        const auto& entry = binding.finite_manifest.entries[index];
        need(entry.component == static_cast<ManifestComponent>(index + 1));
        for (const auto* value : {
                 &entry.source_identity, &entry.build_identity,
                 &entry.runtime_identity, &entry.assets_identity,
                 &entry.pinned_executable_identity,
                 &entry.launcher_identity})
            need(nonzero(*value));
    }
    need_worker(binding.observer_worker);
    need_worker(binding.score_worker);
    need_worker(binding.aggregate_worker);
    const auto& observer = binding.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Observer) - 1];
    const auto& score = binding.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::OwnerScore) - 1];
    const auto& aggregate = binding.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Aggregate) - 1];
    need(binding.observer_worker == worker_from_entry(observer) &&
         binding.score_worker == worker_from_entry(score) &&
         binding.aggregate_worker == worker_from_entry(aggregate));
    const auto selected_p1 = p1_worker(binding);
    need(binding.capture_source == selected_p1.source_identity &&
         binding.capture_build == selected_p1.build_identity &&
         binding.capture_runtime == selected_p1.runtime_identity &&
         binding.capture_launcher == selected_p1.launcher_identity &&
         binding.binding_identity ==
             recompute_p1_state_capsule_prelaunch_binding_identity(binding));
}

void validate_plan(const StaticStateCapsulePlan& plan) {
    validate_prelaunch_binding(plan.prelaunch);
    need((plan.round == 1 || plan.round == 2) && plan.role == 1 &&
         plan.persistent_child_epoch > 0 &&
         plan.context_allocation_epoch > 0);
    need_worker(plan.p1_worker);
    need(plan.p1_worker == p1_worker(plan.prelaunch) &&
         plan.p1_worker.source_identity == plan.prelaunch.capture_source &&
         plan.p1_worker.build_identity == plan.prelaunch.capture_build &&
         plan.p1_worker.runtime_identity == plan.prelaunch.capture_runtime &&
         plan.p1_worker.launcher_identity ==
             plan.prelaunch.capture_launcher);
    for (const auto* value : {
             &plan.accepted_head_plan_identity,
             &plan.selected_main_plan_identity,
             &plan.persistent_child_identity,
             &plan.source_hook_manifest_identity,
             &plan.mp_spdz_source_identity,
             &plan.simplest_ot_source_identity,
             &plan.libote_source_identity,
             &plan.crypto_tools_source_identity,
             &plan.openssl_source_identity,
             &plan.online_options_identity,
             &plan.mascot_secrets_policy_identity,
             &plan.topology_reservation_identity,
             &plan.archive_filesystem_identity,
             &plan.abort_terminal_manifest_identity})
        need(nonzero(*value));
    std::set<Digest> canonical_missing_serializers;
    for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index)
        canonical_missing_serializers.insert(
            canonical_missing_family_serializer_identity(
                static_cast<StateFamily>(index + 1)));
    need(canonical_missing_serializers.size() == STATE_FAMILY_COUNT);
    std::set<Digest> serializers;
    bool all_families_missing = true;
    for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index) {
        const auto family = static_cast<StateFamily>(index + 1);
        const auto disposition = plan.source_family_dispositions[index];
        const auto& serializer = plan.serializer_identities[index];
        const auto& inventory = plan.hook_inventory[index];
        need(disposition == SourceFamilyDisposition::Captured ||
             disposition == SourceFamilyDisposition::Missing);
        need(nonzero(serializer) && serializers.insert(serializer).second);
        if (disposition == SourceFamilyDisposition::Missing) {
            need(serializer ==
                     canonical_missing_family_serializer_identity(family) &&
                 inventory ==
                     canonical_missing_family_hook_inventory(family));
        } else {
            all_families_missing = false;
            need(!canonical_missing_serializers.contains(serializer) &&
                 inventory.exact_object_count > 0 &&
                 inventory.exact_object_count <=
                     (std::numeric_limits<std::uint64_t>::max() -
                      inventory.exact_transition_count) / 2 &&
                 inventory.exact_event_count ==
                     inventory.exact_transition_count +
                         2 * inventory.exact_object_count &&
                 inventory.exact_transition_count > 0 &&
                 inventory.required_transition_bitmap > 0 &&
                 (inventory.required_transition_bitmap >>
                  static_cast<unsigned>(TransitionKind::CheckerStage)) == 0 &&
                 static_cast<std::uint64_t>(std::popcount(
                     inventory.required_transition_bitmap)) <=
                     inventory.exact_transition_count &&
                 nonzero(inventory.ordered_hook_manifest_identity) &&
                 nonzero(inventory.expected_event_sequence_identity) &&
                 nonzero(inventory.expected_transition_sequence_identity));
            need_allowed_transition_bitmap(
                family, inventory.required_transition_bitmap);
        }
    }
    if (all_families_missing) {
        need(plan.mp_spdz_source_identity ==
                 canonical_missing_prelaunch_dependency_identity(
                     PrelaunchDependency::MpSpdzSource) &&
             plan.simplest_ot_source_identity ==
                 canonical_missing_prelaunch_dependency_identity(
                     PrelaunchDependency::SimplestOtSource) &&
             plan.libote_source_identity ==
                 canonical_missing_prelaunch_dependency_identity(
                     PrelaunchDependency::LibOteSource) &&
             plan.crypto_tools_source_identity ==
                 canonical_missing_prelaunch_dependency_identity(
                     PrelaunchDependency::CryptoToolsSource) &&
             plan.openssl_source_identity ==
                 canonical_missing_prelaunch_dependency_identity(
                     PrelaunchDependency::OpenSslSource) &&
             plan.online_options_identity ==
                 canonical_missing_prelaunch_dependency_identity(
                     PrelaunchDependency::OnlineOptions) &&
             plan.mascot_secrets_policy_identity ==
                 canonical_missing_prelaunch_dependency_identity(
                     PrelaunchDependency::MascotSecretsPolicy) &&
             plan.archive_filesystem_identity ==
                 canonical_missing_prelaunch_dependency_identity(
                     PrelaunchDependency::ArchiveFilesystem));
    }
    need(!plan.abort_terminals.empty() &&
         recompute_abort_terminal_manifest_identity(plan.abort_terminals) ==
             plan.abort_terminal_manifest_identity);
    std::set<Digest> terminal_sites;
    for (const auto& terminal : plan.abort_terminals) {
        need(nonzero(terminal.terminal_site_identity) &&
             nonzero(terminal.exception_type_identity) &&
             terminal_sites.insert(terminal.terminal_site_identity).second &&
             static_cast<unsigned>(terminal.phase) >=
                 static_cast<unsigned>(SourcePhase::RecorderStarted) &&
             static_cast<unsigned>(terminal.phase) <=
                 static_cast<unsigned>(SourcePhase::TerminalEgress) &&
             static_cast<unsigned>(terminal.abort_class) >=
                 static_cast<unsigned>(AbortClass::Transport) &&
             static_cast<unsigned>(terminal.abort_class) <=
                 static_cast<unsigned>(AbortClass::Resource));
        for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index) {
            const auto family = static_cast<StateFamily>(index + 1);
            const auto& expected = terminal.families[index];
            const auto empty_events =
                recompute_family_event_sequence_identity(family, {});
            const auto empty_transitions =
                recompute_family_transition_sequence_identity(family, {});
            need(static_cast<unsigned>(expected.disposition) >=
                     static_cast<unsigned>(
                         AbortFamilyDisposition::Closed) &&
                 static_cast<unsigned>(expected.disposition) <=
                     static_cast<unsigned>(
                         AbortFamilyDisposition::TerminalPrefix));
            if (expected.disposition ==
                    AbortFamilyDisposition::NotConstructed) {
                need(expected.exact_object_count == 0 &&
                     expected.exact_event_count == 0 &&
                     expected.exact_transition_count == 0 &&
                     expected.required_transition_bitmap == 0 &&
                     expected.expected_event_sequence_identity ==
                         empty_events &&
                     expected.expected_transition_sequence_identity ==
                         empty_transitions);
            } else {
                need(expected.exact_object_count > 0 &&
                     expected.exact_event_count >=
                         expected.exact_object_count &&
                     expected.exact_transition_count <=
                         expected.exact_event_count &&
                     (expected.required_transition_bitmap >>
                      static_cast<unsigned>(
                          TransitionKind::CheckerStage)) == 0 &&
                     static_cast<std::uint64_t>(std::popcount(
                         expected.required_transition_bitmap)) <=
                         expected.exact_transition_count &&
                     nonzero(expected.expected_event_sequence_identity) &&
                     nonzero(
                         expected.expected_transition_sequence_identity));
                need_allowed_transition_bitmap(
                    family, expected.required_transition_bitmap);
            }
            if (plan.source_family_dispositions[index] ==
                    SourceFamilyDisposition::Missing)
                need(expected.disposition ==
                     AbortFamilyDisposition::NotConstructed);
            if (expected.disposition == AbortFamilyDisposition::Closed) {
                const auto& success = plan.hook_inventory[index];
                need(expected.exact_object_count ==
                         success.exact_object_count &&
                     expected.exact_event_count ==
                         success.exact_event_count &&
                     expected.exact_transition_count ==
                         success.exact_transition_count &&
                     expected.required_transition_bitmap ==
                         success.required_transition_bitmap &&
                     expected.expected_event_sequence_identity ==
                         success.expected_event_sequence_identity &&
                     expected.expected_transition_sequence_identity ==
                         success.expected_transition_sequence_identity);
            }
        }
    }
}

unsigned family_index(StateFamily family) {
    const auto value = static_cast<unsigned>(family);
    need(value >= 1 && value <= STATE_FAMILY_COUNT);
    return value - 1;
}

std::uint64_t family_bit(StateFamily family) {
    return std::uint64_t{1} << family_index(family);
}

Digest hook_sequence_initial(StateFamily family) {
    std::vector<unsigned char> bytes;
    static constexpr std::string_view domain =
        "KPB_P1_STATE_HOOK_SEQUENCE_V1_INIT\n";
    bytes.insert(bytes.end(), domain.begin(), domain.end());
    append_u64(bytes, static_cast<unsigned>(family));
    return hash(bytes);
}

Digest hook_sequence_next(
        StateFamily family, const Digest& previous,
        const HookTransitionDescriptor& event) {
    std::vector<unsigned char> bytes;
    static constexpr std::string_view domain =
        "KPB_P1_STATE_HOOK_SEQUENCE_V1_NEXT\n";
    bytes.insert(bytes.end(), domain.begin(), domain.end());
    append_digest(bytes, previous);
    append_u64(bytes, static_cast<unsigned>(family));
    append_u64(bytes, event.object_ordinal);
    append_u64(bytes, static_cast<unsigned>(event.kind));
    append_u64(bytes, event.counter_before);
    append_u64(bytes, event.counter_after);
    return hash(bytes);
}

Digest hook_event_sequence_initial(StateFamily family) {
    std::vector<unsigned char> bytes;
    static constexpr std::string_view domain =
        "KPB_P1_STATE_HOOK_EVENT_SEQUENCE_V1_INIT\n";
    bytes.insert(bytes.end(), domain.begin(), domain.end());
    append_u64(bytes, static_cast<unsigned>(family));
    return hash(bytes);
}

Digest hook_event_sequence_next(
        StateFamily family, const Digest& previous,
        const HookEventDescriptor& event) {
    std::vector<unsigned char> bytes;
    static constexpr std::string_view domain =
        "KPB_P1_STATE_HOOK_EVENT_SEQUENCE_V1_NEXT\n";
    bytes.insert(bytes.end(), domain.begin(), domain.end());
    append_digest(bytes, previous);
    append_u64(bytes, static_cast<unsigned>(family));
    append_u64(bytes, event.object_ordinal);
    append_u64(bytes, static_cast<unsigned>(event.event_kind));
    append_u64(bytes, static_cast<unsigned>(event.transition_kind));
    append_u64(bytes, event.counter_before);
    append_u64(bytes, event.counter_after);
    return hash(bytes);
}

bool transition_allowed(StateFamily family, TransitionKind kind) {
    switch (family) {
    case StateFamily::MpSpdzPrng:
    case StateFamily::CryptoToolsPrng:
        return kind == TransitionKind::EntropySeed ||
               kind == TransitionKind::PrngConsume;
    case StateFamily::MascotSecrets:
        return kind == TransitionKind::CacheLoad ||
               kind == TransitionKind::CacheGenerate ||
               kind == TransitionKind::CacheWrite ||
               kind == TransitionKind::CacheUnlink ||
               kind == TransitionKind::OtSetup ||
               kind == TransitionKind::ProtocolSetup;
    case StateFamily::SimplestOtBase:
        return kind == TransitionKind::EntropySeed ||
               kind == TransitionKind::OtSetup ||
               kind == TransitionKind::OtCheck;
    case StateFamily::SoftSpokenExtended:
        return kind == TransitionKind::EntropySeed ||
               kind == TransitionKind::PrngConsume ||
               kind == TransitionKind::OtExtend ||
               kind == TransitionKind::OtCheck;
    case StateFamily::OnDemandOtMap:
        return kind == TransitionKind::OtSetup ||
               kind == TransitionKind::OtExtend ||
               kind == TransitionKind::CacheLoad ||
               kind == TransitionKind::CacheWrite;
    case StateFamily::TripleAndInputCache:
        return kind == TransitionKind::TripleGenerate ||
               kind == TransitionKind::TripleConsume ||
               kind == TransitionKind::InputTupleConsume ||
               kind == TransitionKind::CollectiveSeed ||
               kind == TransitionKind::CacheLoad ||
               kind == TransitionKind::CacheWrite;
    case StateFamily::Beaver:
        return kind == TransitionKind::TripleConsume ||
               kind == TransitionKind::BeaverPrepare ||
               kind == TransitionKind::BeaverExchange ||
               kind == TransitionKind::BeaverFinalize;
    case StateFamily::MacCheck:
        return kind == TransitionKind::PrngConsume ||
               kind == TransitionKind::MacPrepare ||
               kind == TransitionKind::MacCoefficient ||
               kind == TransitionKind::MacTau ||
               kind == TransitionKind::MacVerify;
    case StateFamily::ContextAndRetry:
        return kind == TransitionKind::ContextPoison ||
               kind == TransitionKind::ContextRetry ||
               kind == TransitionKind::ContextValidate;
    case StateFamily::ProtocolSetup:
        return kind == TransitionKind::ProtocolSetup ||
               kind == TransitionKind::ContextValidate;
    case StateFamily::PlayerAllocation:
        return kind == TransitionKind::PlayerFork ||
               kind == TransitionKind::PlayerTraffic;
    case StateFamily::TlsChannelState:
        return kind == TransitionKind::EntropySeed ||
               kind == TransitionKind::PrngConsume ||
               kind == TransitionKind::TlsHandshake ||
               kind == TransitionKind::TlsReadWrite;
    case StateFamily::QueryMsmCheckerTemporaries:
        return kind == TransitionKind::QueryMsmStage ||
               kind == TransitionKind::CheckerStage ||
               kind == TransitionKind::ContextValidate;
    }
    return false;
}

SourcePhase first_construction_phase(StateFamily family) {
    switch (family) {
    case StateFamily::PlayerAllocation:
    case StateFamily::TlsChannelState:
        return SourcePhase::RecorderStarted;
    case StateFamily::MpSpdzPrng:
    case StateFamily::CryptoToolsPrng:
    case StateFamily::MascotSecrets:
    case StateFamily::SimplestOtBase:
    case StateFamily::SoftSpokenExtended:
    case StateFamily::OnDemandOtMap:
    case StateFamily::TripleAndInputCache:
    case StateFamily::MacCheck:
    case StateFamily::ContextAndRetry:
    case StateFamily::ProtocolSetup:
        return SourcePhase::ProtocolSetupStarted;
    case StateFamily::Beaver:
        return SourcePhase::ProtocolSetupComplete;
    case StateFamily::QueryMsmCheckerTemporaries:
        return SourcePhase::Construction;
    }
    refuse();
}

SourcePhase not_constructed_deadline_phase(StateFamily family) {
    if (family == StateFamily::PlayerAllocation ||
        family == StateFamily::TlsChannelState) {
        // These may be constructed during RecorderStarted, but are only
        // required before crossing into TlsAndPlayerBound. This preserves a
        // genuine pre-player NotConstructed abort without delaying their
        // valid construction window.
        return SourcePhase::TlsAndPlayerBound;
    }
    return first_construction_phase(family);
}

void need_anonymous_disk_file(const struct stat& value) {
    need(S_ISREG(value.st_mode) && value.st_nlink == 0 &&
         (value.st_mode & 0777) == 0600 && value.st_size >= 0);
}

struct OpenedFile {
    int fd{-1};
    std::uint64_t device{};
    std::uint64_t inode{};
};

#ifdef KPB_P1_STATE_CAPSULE_TEST_SETUP
OpenedFile open_anonymous_disk_file() {
    int directory = ::open(
        "/var/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    need(directory >= 0);
    try {
        struct stat root{};
        struct statfs filesystem{};
        need(::fstat(directory, &root) == 0 && S_ISDIR(root.st_mode) &&
             ::fstatfs(directory, &filesystem) == 0 &&
             filesystem.f_type != TMPFS_MAGIC &&
             filesystem.f_type != RAMFS_MAGIC);
        int fd = ::openat(directory, ".",
                          O_TMPFILE | O_RDWR | O_CLOEXEC | O_NOFOLLOW,
                          0600);
        need(fd >= 0);
        struct stat value{};
        try {
            need(::fstat(fd, &value) == 0);
            need_anonymous_disk_file(value);
            need(value.st_size == 0 && value.st_dev == root.st_dev &&
                 (::fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDWR &&
                 (::fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);
        } catch (...) {
            close_fd(fd);
            throw;
        }
        close_fd(directory);
        return {
            .fd = fd,
            .device = static_cast<std::uint64_t>(value.st_dev),
            .inode = static_cast<std::uint64_t>(value.st_ino),
        };
    } catch (...) {
        close_fd(directory);
        throw;
    }
}
#endif

int reopen_read_only(int fd) {
    std::array<char, 64> path{};
    const int size = std::snprintf(
        path.data(), path.size(), "/proc/self/fd/%d", fd);
    need(size > 0 && static_cast<std::size_t>(size) < path.size());
    // /proc/self/fd/N is intentionally a kernel-owned magic symlink. Identity
    // is checked with fstat before and after the writer is closed.
    int result = ::open(path.data(), O_RDONLY | O_CLOEXEC);
    need(result >= 0 && (::fcntl(result, F_GETFL) & O_ACCMODE) == O_RDONLY &&
         (::fcntl(result, F_GETFD) & FD_CLOEXEC) != 0);
    return result;
}

struct ObjectState {
    StateFamily family{};
    std::uint64_t thread_epoch{};
    std::uint64_t parent_epoch{};
    std::uint64_t family_ordinal{};
    std::uint64_t counter{};
    bool player{};
    bool terminal_snapshot{};
    bool released{};
};

struct ThreadState {
    std::uint64_t parent_epoch{};
    Digest fork_identity{};
    bool joined{};
};

struct Ledger {
    StaticStateCapsulePlan plan;
    int fd{-1};
    std::uint64_t device{};
    std::uint64_t inode{};
    std::uint64_t offset{};
    std::uint64_t sequence{};
    std::uint64_t last_monotonic{};
    std::uint64_t next_thread_epoch{2};
    std::uint64_t next_object_epoch{1};
    bool root_thread_taken{};
    bool root_player_bound{};
    bool context_retry_adapter_issued{};
    bool entropy_adapter_issued{};
    bool entropy_adapter_finalized{};
    bool mascot_secret_adapter_issued{};
    bool mascot_secret_adapter_finalized{};
    bool player_tls_adapter_issued{};
    bool player_tls_adapter_finalized{};
    bool abort_terminal_site_issued{};
    bool abort_terminal_prepared{};
    bool sealed{};
    bool poisoned{};
    bool io_failed{};
    bool test_fail_fsync{};
    bool test_fail_reopen{};
    bool test_fail_hash{};
    std::uint64_t closed_family_bitmap{};
    std::uint64_t not_constructed_bitmap{};
    std::uint64_t abort_prefix_bitmap{};
    std::uint64_t missing_family_bitmap{};
    SourcePhase phase{SourcePhase::RecorderStarted};
    AbortClass abort_class{};
    Digest abort_exception_type_identity{};
    std::array<std::uint64_t, STATE_FAMILY_COUNT> event_counts{};
    std::array<std::uint64_t, STATE_FAMILY_COUNT> object_counts{};
    std::array<std::uint64_t, STATE_FAMILY_COUNT> hook_event_counts{};
    std::array<std::uint64_t, STATE_FAMILY_COUNT> transition_counts{};
    std::array<std::uint64_t, STATE_FAMILY_COUNT> transition_bitmaps{};
    std::array<Digest, STATE_FAMILY_COUNT> hook_event_sequence_identities{};
    std::array<Digest, STATE_FAMILY_COUNT> transition_sequence_identities{};
    Digest abort_terminal_site_identity{};
    Digest previous_record_hash{};
    std::map<std::uint64_t, ThreadState> threads{
        {1, ThreadState{}}};
    std::map<std::uint64_t, ObjectState> objects;
    std::set<Digest> player_fork_identities;
    std::mutex mutex;

    ~Ledger() { close_fd(fd); }
};

std::vector<unsigned char> family_payload(
        const Ledger& ledger, StateFamily family,
        std::span<const unsigned char> snapshot) {
    need(!snapshot.empty());
    std::vector<unsigned char> result;
    result.reserve(Digest{}.size() + snapshot.size());
    append_digest(result, ledger.plan.serializer_identities[
        family_index(family)]);
    result.insert(result.end(), snapshot.begin(), snapshot.end());
    return result;
}

void append_record(
        Ledger& ledger, RecordType type, StateFamily family,
        std::uint8_t operation, std::uint8_t terminal_outcome,
        std::uint64_t thread_epoch, std::uint64_t object_epoch,
        std::uint64_t parent_epoch, std::uint64_t counter_before,
        std::uint64_t counter_after,
        std::span<const unsigned char> payload) {
    need(!ledger.sealed && !ledger.io_failed && ledger.fd >= 0 &&
         ledger.sequence < std::numeric_limits<std::uint64_t>::max());
    std::array<unsigned char, HEADER_BYTES> header{};
    std::copy(MAGIC.begin(), MAGIC.end(), header.begin());
    put_u32(header.data() + 8, SCHEMA_VERSION);
    header[12] = static_cast<unsigned char>(type);
    header[13] = static_cast<unsigned char>(family);
    header[14] = operation;
    header[15] = terminal_outcome;
    put_u64(header.data() + 16, ledger.sequence);
    auto timestamp = monotonic_ns();
    need(timestamp >= ledger.last_monotonic);
    ledger.last_monotonic = timestamp;
    put_u64(header.data() + 24, timestamp);
    put_u64(header.data() + 32, thread_epoch);
    put_u64(header.data() + 40, object_epoch);
    put_u64(header.data() + 48, parent_epoch);
    put_u64(header.data() + 56, counter_before);
    put_u64(header.data() + 64, counter_after);
    put_u64(header.data() + 72, payload.size());
    const auto payload_hash = hash(payload);
    std::copy(payload_hash.begin(), payload_hash.end(), header.begin() + 80);
    std::copy(ledger.previous_record_hash.begin(),
              ledger.previous_record_hash.end(), header.begin() + 112);
    HashState record;
    record.update(std::span(header).first(144));
    record.update(payload);
    const auto record_hash = record.finish();
    std::copy(record_hash.begin(), record_hash.end(), header.begin() + 144);
    write_all_at(ledger.fd, header, ledger.offset);
    ledger.offset += header.size();
    write_all_at(ledger.fd, payload, ledger.offset);
    ledger.offset += payload.size();
    ledger.previous_record_hash = record_hash;
    ++ledger.sequence;
    if (family != StateFamily{})
        ++ledger.event_counts[family_index(family)];
}

void advance_hook_event(
        Ledger& ledger, StateFamily family, std::uint64_t object_ordinal,
        HookEventKind event_kind, TransitionKind transition_kind,
        std::uint64_t counter_before, std::uint64_t counter_after) {
    const auto index = family_index(family);
    need(ledger.hook_event_counts[index] <
             std::numeric_limits<std::uint64_t>::max());
    const HookEventDescriptor event{
        .object_ordinal = object_ordinal,
        .event_kind = event_kind,
        .transition_kind = transition_kind,
        .counter_before = counter_before,
        .counter_after = counter_after,
    };
    const auto next = hook_event_sequence_next(
        family, ledger.hook_event_sequence_identities[index], event);
    ledger.hook_event_sequence_identities[index] = next;
    ++ledger.hook_event_counts[index];
}

void poison_dropped_token(
        const std::shared_ptr<Ledger>& ledger,
        StateFamily family = StateFamily{}) noexcept {
    if (!ledger) return;
    try {
        std::lock_guard lock(ledger->mutex);
        if (ledger->sealed) return;
        ledger->poisoned = true;
        if (family != StateFamily{})
            ledger->missing_family_bitmap |= family_bit(family);
        else
            ledger->missing_family_bitmap |= FULL_FAMILY_BITMAP;
    } catch (...) {}
}

void need_thread(
        const std::shared_ptr<Ledger>& ledger,
        const P1StateThreadEpochAuthority::Storage* token);
void need_object(
        const std::shared_ptr<Ledger>& ledger,
        const P1StateObjectEpochAuthority::Storage* token);
#ifdef KPB_P1_STATE_CAPSULE_TEST_SETUP
void need_player(
        const std::shared_ptr<Ledger>& ledger,
        const P1PlayerAllocationEpochAuthority::Storage* token);
#endif

} // namespace

Digest recompute_p1_state_capsule_prelaunch_binding_identity(
        const P1StateCapsulePrelaunchBinding& binding) {
    std::vector<unsigned char> bytes;
    static constexpr std::string_view domain =
        "KPB_P1_STATE_CAPSULE_PRELAUNCH_BINDING_V1\n";
    bytes.insert(bytes.end(), domain.begin(), domain.end());
    const auto append_string = [&](const std::string& value) {
        append_u64(bytes, value.size());
        bytes.insert(bytes.end(), value.begin(), value.end());
    };
    const auto append_worker = [&](const WorkerBinding& worker) {
        for (const auto* value : {
                 &worker.source_identity, &worker.build_identity,
                 &worker.runtime_identity, &worker.assets_identity,
                 &worker.pinned_executable_identity,
                 &worker.launcher_identity})
            append_digest(bytes, *value);
    };

    append_u64(bytes, static_cast<unsigned>(binding.classification));
    append_digest(bytes, binding.comparison_selection);
    append_digest(bytes, binding.run_selection);
    append_string(binding.capture_trial_id);
    for (const auto* value : {
             &binding.trial, &binding.measurement_attempt,
             &binding.measurement_cohort, &binding.capture, &binding.method,
             &binding.workload, &binding.source_closure, &binding.runtime})
        append_digest(bytes, *value);
    append_digest(bytes, binding.finite_manifest.manifest_identity);
    append_digest(
        bytes, binding.finite_manifest.parent_recomputation_identity);
    for (const auto& entry : binding.finite_manifest.entries) {
        append_u64(bytes, static_cast<unsigned>(entry.component));
        for (const auto* value : {
                 &entry.source_identity, &entry.build_identity,
                 &entry.runtime_identity, &entry.assets_identity,
                 &entry.pinned_executable_identity,
                 &entry.launcher_identity})
            append_digest(bytes, *value);
    }
    for (const auto* value : {
             &binding.outer_parent_process,
             &binding.outer_parent_executable, &binding.capture_source,
             &binding.capture_build, &binding.capture_runtime,
             &binding.capture_launcher})
        append_digest(bytes, *value);
    append_worker(binding.observer_worker);
    append_worker(binding.score_worker);
    append_worker(binding.aggregate_worker);
    for (const auto& value : binding.financial_runs)
        append_digest(bytes, value);
    for (const auto& value : binding.capture_attempt_ids)
        append_string(value);
    for (const auto& value : binding.round_attempts)
        append_digest(bytes, value);
    for (const auto& value : binding.round_cohorts)
        append_digest(bytes, value);
    for (const auto& value : binding.round_capture_plans)
        append_digest(bytes, value);
    append_digest(bytes, binding.process_reservation_identity);
    append_digest(bytes, binding.persistent_process_session_identity);
    for (const auto& value : binding.fork_plan_identities)
        append_digest(bytes, value);
    for (const auto* value : {
             &binding.producer_process_identity,
             &binding.role_closure_identity, &binding.manifest_seal,
             &binding.construction_policy_identity,
             &binding.construction_classification_receipt,
             &binding.route_policy_identity,
             &binding.stream_policy_identity})
        append_digest(bytes, *value);
    return hash(bytes);
}

Digest recompute_family_transition_sequence_identity(
        StateFamily family,
        std::span<const HookTransitionDescriptor> events) {
    (void)family_index(family);
    auto result = hook_sequence_initial(family);
    for (const auto& event : events) {
        need(event.object_ordinal > 0 &&
             static_cast<unsigned>(event.kind) >= 1 &&
             static_cast<unsigned>(event.kind) <=
                 static_cast<unsigned>(TransitionKind::CheckerStage) &&
             event.counter_after > event.counter_before);
        result = hook_sequence_next(family, result, event);
    }
    return result;
}

Digest recompute_family_event_sequence_identity(
        StateFamily family, std::span<const HookEventDescriptor> events) {
    (void)family_index(family);
    auto result = hook_event_sequence_initial(family);
    for (const auto& event : events) {
        need(event.object_ordinal > 0 &&
             static_cast<unsigned>(event.event_kind) >=
                 static_cast<unsigned>(HookEventKind::Construct) &&
             static_cast<unsigned>(event.event_kind) <=
                 static_cast<unsigned>(HookEventKind::Release));
        if (event.event_kind == HookEventKind::Transition) {
            need(static_cast<unsigned>(event.transition_kind) >= 1 &&
                 static_cast<unsigned>(event.transition_kind) <=
                     static_cast<unsigned>(TransitionKind::CheckerStage) &&
                 event.counter_after > event.counter_before);
        } else {
            need(event.transition_kind == TransitionKind{} &&
                 event.counter_after == event.counter_before);
        }
        result = hook_event_sequence_next(family, result, event);
    }
    return result;
}

Digest canonical_missing_family_serializer_identity(StateFamily family) {
    (void)family_index(family);
    std::vector<unsigned char> bytes;
    static constexpr std::string_view domain =
        "KPB_P1_STATE_MISSING_FAMILY_SERIALIZER_V1\n";
    bytes.insert(bytes.end(), domain.begin(), domain.end());
    append_u64(bytes, static_cast<unsigned>(family));
    return hash(bytes);
}

Digest canonical_missing_prelaunch_dependency_identity(
        PrelaunchDependency dependency) {
    const auto ordinal = static_cast<unsigned>(dependency);
    need(ordinal >= static_cast<unsigned>(
             PrelaunchDependency::MpSpdzSource) &&
         ordinal <= static_cast<unsigned>(
             PrelaunchDependency::ArchiveFilesystem));
    std::vector<unsigned char> bytes;
    static constexpr std::string_view domain =
        "KPB_P1_STATE_MISSING_PRELAUNCH_DEPENDENCY_V1\n";
    bytes.insert(bytes.end(), domain.begin(), domain.end());
    append_u64(bytes, ordinal);
    return hash(bytes);
}

FamilyHookInventory canonical_missing_family_hook_inventory(
        StateFamily family) {
    (void)family_index(family);
    std::vector<unsigned char> bytes;
    static constexpr std::string_view domain =
        "KPB_P1_STATE_MISSING_FAMILY_HOOK_MANIFEST_V1\n";
    bytes.insert(bytes.end(), domain.begin(), domain.end());
    append_u64(bytes, static_cast<unsigned>(family));
    return {
        .ordered_hook_manifest_identity = hash(bytes),
        .expected_event_sequence_identity =
            hook_event_sequence_initial(family),
        .expected_transition_sequence_identity =
            hook_sequence_initial(family),
    };
}

namespace {

using MascotBranch = kpi::mpc::p1_private_state::MascotCacheBranch;
using MascotKind = kpi::mpc::p1_private_state::MascotSecretEventKind;

std::vector<MascotKind> mascot_branch_events(MascotBranch branch) {
    using Branch = MascotBranch;
    using Kind = MascotKind;
    need(static_cast<unsigned>(branch) >=
             static_cast<unsigned>(Branch::StaticReuse) &&
         static_cast<unsigned>(branch) <=
             static_cast<unsigned>(Branch::RegeneratedAfterPeerReject));
    std::vector<Kind> events{
        Kind::ScalarStateBegin,
        Kind::SetupBegin,
    };
    if (branch == Branch::StaticReuse) {
        events.push_back(Kind::StaticInstalled);
    } else {
        events.insert(events.end(), {
            Kind::CacheOpened,
            Kind::CacheLocalValidation,
            Kind::CachePeerValidation,
        });
        if (branch != Branch::CacheHit)
            events.push_back(Kind::Regeneration);
        events.insert(events.end(), {
            Kind::WriteCandidate,
            Kind::Writeback,
            Kind::PrepStaticInstalled,
            Kind::PrepMacFileWrite,
            Kind::BitPrepDerived,
            Kind::StaticInstalled,
        });
    }
    events.push_back(Kind::Teardown);
    return events;
}

TransitionKind mascot_transition_kind(MascotKind kind) {
    using Kind = MascotKind;
    switch (kind) {
    case Kind::SetupBegin:
    case Kind::PrepStaticInstalled:
    case Kind::StaticInstalled:
        return TransitionKind::ProtocolSetup;
    case Kind::CacheOpened:
    case Kind::CacheLocalValidation:
    case Kind::CachePeerValidation:
        return TransitionKind::CacheLoad;
    case Kind::Regeneration:
        return TransitionKind::CacheGenerate;
    case Kind::WriteCandidate:
    case Kind::Writeback:
    case Kind::PrepMacFileWrite:
        return TransitionKind::CacheWrite;
    case Kind::BitPrepDerived:
        return TransitionKind::OtSetup;
    case Kind::ScalarStateBegin:
    case Kind::Teardown:
        break;
    }
    refuse();
}

} // namespace

Digest recompute_mascot_secret_branch_manifest_identity(
        kpi::mpc::p1_private_state::MascotCacheBranch branch) {
    using Kind = MascotKind;
    const auto events = mascot_branch_events(branch);

    std::vector<unsigned char> bytes;
    static constexpr std::string_view domain =
        "KPB_P1_MASCOT_SECRET_BRANCH_MANIFEST_V2\n";
    const auto append_string = [&](std::string_view value) {
        append_u64(bytes, value.size());
        bytes.insert(bytes.end(), value.begin(), value.end());
    };
    append_string(domain);
    append_string(
        kpi::mpc::p1_private_state::MASCOT_SECRET_EVENT_ENCODING_DOMAIN);
    append_string(kpi::mpc::p1_private_state::MASCOT_SECRETS_MP_SPDZ_COMMIT);
    append_u64(bytes, static_cast<unsigned>(branch));
    append_u64(bytes, events.size());
    for (const auto kind : events) {
        append_u64(bytes, static_cast<unsigned>(kind));
        append_string(kpi::mpc::p1_private_state::mascot_secret_source_site(
            kind));
        append_string(
            kpi::mpc::p1_private_state::
                mascot_secret_upstream_file_sha256(kind));
        const std::uint64_t transition =
            kind == Kind::ScalarStateBegin || kind == Kind::Teardown
                ? 0 : static_cast<unsigned>(mascot_transition_kind(kind));
        append_u64(bytes, transition);
    }
    return hash(bytes);
}

FamilyHookInventory recompute_mascot_secret_branch_inventory(
        kpi::mpc::p1_private_state::MascotCacheBranch branch) {
    using Kind = MascotKind;
    const auto source_events = mascot_branch_events(branch);
    std::vector<HookTransitionDescriptor> transitions;
    std::vector<HookEventDescriptor> events;
    std::uint64_t counter = 0;
    std::uint64_t bitmap = 0;
    for (const auto kind : source_events) {
        if (kind == Kind::ScalarStateBegin) {
            need(events.empty() && transitions.empty() && counter == 0);
            events.push_back({
                .object_ordinal = 1,
                .event_kind = HookEventKind::Construct,
                .transition_kind = TransitionKind{},
                .counter_before = 0,
                .counter_after = 0,
            });
        } else if (kind == Kind::Teardown) {
            need(!events.empty());
            events.push_back({
                .object_ordinal = 1,
                .event_kind = HookEventKind::TerminalSnapshot,
                .transition_kind = TransitionKind{},
                .counter_before = counter,
                .counter_after = counter,
            });
        } else {
            need(counter < std::numeric_limits<std::uint64_t>::max());
            const auto transition = mascot_transition_kind(kind);
            transitions.push_back({
                .object_ordinal = 1,
                .kind = transition,
                .counter_before = counter,
                .counter_after = counter + 1,
            });
            events.push_back({
                .object_ordinal = 1,
                .event_kind = HookEventKind::Transition,
                .transition_kind = transition,
                .counter_before = counter,
                .counter_after = counter + 1,
            });
            bitmap |= std::uint64_t{1} <<
                (static_cast<unsigned>(transition) - 1);
            ++counter;
        }
    }
    need(events.size() == source_events.size() &&
         !events.empty() &&
         events.front().event_kind == HookEventKind::Construct &&
         events.back().event_kind == HookEventKind::TerminalSnapshot);
    return {
        .exact_object_count = 1,
        .exact_event_count = events.size(),
        .exact_transition_count = transitions.size(),
        .required_transition_bitmap = bitmap,
        .ordered_hook_manifest_identity =
            recompute_mascot_secret_branch_manifest_identity(branch),
        .expected_event_sequence_identity =
            recompute_family_event_sequence_identity(
                StateFamily::MascotSecrets, events),
        .expected_transition_sequence_identity =
            recompute_family_transition_sequence_identity(
                StateFamily::MascotSecrets, transitions),
    };
}

AbortFamilyHookInventory recompute_mascot_secret_abort_prefix_inventory(
        kpi::mpc::p1_private_state::MascotCacheBranch branch) {
    using Kind = MascotKind;
    auto source_events = mascot_branch_events(branch);
    need(!source_events.empty() && source_events.back() == Kind::Teardown);
    source_events.pop_back();
    std::vector<HookTransitionDescriptor> transitions;
    std::vector<HookEventDescriptor> events;
    std::uint64_t counter = 0;
    std::uint64_t bitmap = 0;
    for (const auto kind : source_events) {
        if (kind == Kind::ScalarStateBegin) {
            need(events.empty() && transitions.empty() && counter == 0);
            events.push_back({
                .object_ordinal = 1,
                .event_kind = HookEventKind::Construct,
                .transition_kind = TransitionKind{},
                .counter_before = 0,
                .counter_after = 0,
            });
            continue;
        }
        need(kind != Kind::Teardown &&
             counter < std::numeric_limits<std::uint64_t>::max());
        const auto transition = mascot_transition_kind(kind);
        transitions.push_back({
            .object_ordinal = 1,
            .kind = transition,
            .counter_before = counter,
            .counter_after = counter + 1,
        });
        events.push_back({
            .object_ordinal = 1,
            .event_kind = HookEventKind::Transition,
            .transition_kind = transition,
            .counter_before = counter,
            .counter_after = counter + 1,
        });
        bitmap |= std::uint64_t{1} <<
            (static_cast<unsigned>(transition) - 1);
        ++counter;
    }
    need(events.size() == source_events.size() && !events.empty() &&
         events.front().event_kind == HookEventKind::Construct &&
         events.back().event_kind == HookEventKind::Transition);
    return {
        .disposition = AbortFamilyDisposition::TerminalPrefix,
        .exact_object_count = 1,
        .exact_event_count = events.size(),
        .exact_transition_count = transitions.size(),
        .required_transition_bitmap = bitmap,
        .expected_event_sequence_identity =
            recompute_family_event_sequence_identity(
                StateFamily::MascotSecrets, events),
        .expected_transition_sequence_identity =
            recompute_family_transition_sequence_identity(
                StateFamily::MascotSecrets, transitions),
    };
}

Digest recompute_abort_terminal_manifest_identity(
        std::span<const AbortTerminalHookInventory> entries) {
    need(!entries.empty());
    std::vector<unsigned char> bytes;
    static constexpr std::string_view domain =
        "KPB_P1_STATE_ABORT_TERMINAL_MANIFEST_V1\n";
    bytes.insert(bytes.end(), domain.begin(), domain.end());
    append_u64(bytes, entries.size());
    for (const auto& entry : entries) {
        append_digest(bytes, entry.terminal_site_identity);
        append_digest(bytes, entry.exception_type_identity);
        append_u64(bytes, static_cast<unsigned>(entry.phase));
        append_u64(bytes, static_cast<unsigned>(entry.abort_class));
        for (const auto& family : entry.families) {
            append_u64(bytes, static_cast<unsigned>(family.disposition));
            append_u64(bytes, family.exact_object_count);
            append_u64(bytes, family.exact_event_count);
            append_u64(bytes, family.exact_transition_count);
            append_u64(bytes, family.required_transition_bitmap);
            append_digest(bytes, family.expected_event_sequence_identity);
            append_digest(
                bytes, family.expected_transition_sequence_identity);
        }
    }
    return hash(bytes);
}

struct P1CorruptStateCapsulePlanAuthority::Storage {
    StaticStateCapsulePlan plan;
};

struct P1StateThreadEpochAuthority::Storage {
    std::shared_ptr<Ledger> ledger;
    std::uint64_t epoch{};
    bool live{true};
};

struct P1StateObjectEpochAuthority::Storage {
    std::shared_ptr<Ledger> ledger;
    std::uint64_t epoch{};
    bool live{true};
};

struct P1PlayerAllocationEpochAuthority::Storage {
    std::shared_ptr<Ledger> ledger;
    std::uint64_t epoch{};
    bool live{true};
};

struct P1AbortTerminalSiteAuthority::Storage {
    std::shared_ptr<Ledger> ledger;
    Digest terminal_site_identity{};
    Digest exception_type_identity{};
    SourcePhase phase{};
    AbortClass abort_class{};
    bool live{true};
};

struct P1AbortTerminalAuthority::Storage {
    std::shared_ptr<Ledger> ledger;
    Digest terminal_site_identity{};
    SourcePhase phase{};
    AbortClass abort_class{};
    Digest exception_type_identity{};
    bool live{true};
};

struct P1ContextAndRetryStateAdapter::Storage {
    std::shared_ptr<Ledger> ledger;
    std::uint64_t thread_epoch{};
    std::uint64_t object_epoch{};
    bool constructed{};
    bool terminal{};
    bool unavailable{};
};

struct P1EntropyStateAdapter::Storage {
    std::shared_ptr<Ledger> ledger;
    std::uint64_t thread_epoch{};
    std::uint64_t next_source_object_epoch{1};
    std::uint64_t next_source_allocation_epoch{1};
    std::array<std::uint64_t, 3> counters{};
    std::set<std::uint64_t> source_object_epochs;
    std::set<std::uint64_t> source_allocation_epochs;
    bool terminal{};
    bool unavailable{};
};

struct P1MascotSecretStateAdapter::Storage {
    enum class Next : std::uint8_t {
        ScalarStateBegin,
        SetupBegin,
        CacheOpened,
        CacheLocalValidation,
        CachePeerValidation,
        Regeneration,
        WriteCandidate,
        Writeback,
        PrepStaticInstalled,
        PrepMacFileWrite,
        BitPrepDerived,
        StaticInstalled,
        Teardown,
        Abort,
        FailureTerminal,
        Complete,
        Unavailable,
    };

    std::shared_ptr<Ledger> ledger;
    std::unique_ptr<kpi::mpc::p1_private_state::
        MascotSecretStateHookScope> scope;
    std::uint64_t thread_epoch{};
    std::uint64_t object_epoch{};
    std::uint64_t counter{};
    std::uint64_t next_sequence{1};
    Next next{Next::ScalarStateBegin};
    kpi::mpc::p1_private_state::MascotCacheBranch branch{
        kpi::mpc::p1_private_state::MascotCacheBranch::Undecided};
    kpi::mpc::p1_private_state::MascotFileResult cache_file_result{
        kpi::mpc::p1_private_state::MascotFileResult::NotAttempted};
    std::uint64_t local_role{};
    std::uint64_t player_count{};
    bool encrypted_player{};
    std::uint64_t batch_size{};
    std::uint64_t bucket_size{};
    std::uint64_t statistical_security{};
    bool uses_security_parameter{};
    bool uses_kos{};
    std::uint64_t native_size_width{};
    std::uint64_t native_byte_order{};
    std::string player_id;
    std::string field_modulus;
    std::string canonical_cache_domain;
    std::string cache_diagnostic_path;
    std::thread::id owner_thread;
    std::uint64_t next_abort_sequence{1};
    std::uint64_t registered_worker_count{};
    kpi::mpc::p1_private_state::MascotSecretAbortClass abort_class{
        kpi::mpc::p1_private_state::
            MascotSecretAbortClass::OtMultiplierFailure};
    std::set<std::uint64_t> abort_worker_failures;
    std::set<std::uint64_t> abort_worker_terminals;
    std::set<std::uint64_t> abort_worker_observed;
    std::set<std::uint64_t> abort_worker_joined;
    std::map<std::uint64_t, std::uint64_t> abort_worker_by_ordinal;
    bool abort_started{};
    bool abort_teardown{};
    bool constructed{};
    bool terminal{};
    bool unavailable{};
};

struct P1PlayerTlsStateAdapter::Storage {
    struct Channel final {
        std::uint64_t epoch{};
        std::uint64_t client{};
        SourcePhase construction_phase{};
        bool handshake_complete{};
    };
    std::shared_ptr<Ledger> ledger;
    std::uint64_t thread_epoch{};
    std::map<std::string, std::uint64_t> player_epochs;
    std::map<std::string, SourcePhase> player_construction_phases;
    std::map<std::string, std::uint64_t> tls_context_epochs;
    std::map<std::tuple<std::string, std::uint64_t, std::uint64_t>,
             Channel> tls_channels;
    std::set<std::string> constructed_players;
    std::set<std::string> destroying_players;
    bool unavailable{};
};

struct P1CorruptStateCapsuleAuthority::Storage {
    StaticStateCapsulePlan plan;
    std::unique_ptr<
        P1CorruptStateCapsuleChildDispositionResidual::Storage>
        child_disposition_result;
    int fd{-1};
    std::uint64_t device{};
    std::uint64_t inode{};
    bool manifest_structurally_complete{};
    bool aborted{};
    bool read_only{};
    bool anonymous_disk_backed{};
    bool writer_closed{};
    bool descriptor_retained{};
    SourcePhase terminal_phase{};
    AbortClass abort_class{};
    std::uint64_t sequence{};
    std::uint64_t archive_bytes{};
    std::uint64_t missing_family_bitmap{};
    std::uint64_t closed_family_bitmap{};
    std::uint64_t not_constructed_bitmap{};
    std::uint64_t abort_prefix_bitmap{};
    Digest abort_terminal_site_identity{};
    std::array<std::uint64_t, STATE_FAMILY_COUNT> event_counts{};
    Digest archive_sha256{};

    ~Storage() { close_fd(fd); }
};

struct P1CorruptStateRecorderAuthority::Storage {
    std::shared_ptr<Ledger> ledger;
    std::unique_ptr<P1CorruptStateCapsuleAuthority::Storage> close_result;
    std::unique_ptr<P1AbortTerminalSiteAuthority::Storage>
        abort_terminal_site_result;
    std::unique_ptr<P1AbortTerminalAuthority::Storage> abort_terminal_result;
};

namespace {

void need_thread(
        const std::shared_ptr<Ledger>& ledger,
        const P1StateThreadEpochAuthority::Storage* token) {
    need(ledger != nullptr && token != nullptr && token->live &&
         token->ledger == ledger && token->epoch > 0 &&
         ledger->threads.contains(token->epoch));
}

void need_object(
        const std::shared_ptr<Ledger>& ledger,
        const P1StateObjectEpochAuthority::Storage* token) {
    need(ledger != nullptr && token != nullptr && token->live &&
         token->ledger == ledger && token->epoch > 0 &&
         ledger->objects.contains(token->epoch) &&
         !ledger->objects.at(token->epoch).player);
}

#ifdef KPB_P1_STATE_CAPSULE_TEST_SETUP
void need_player(
        const std::shared_ptr<Ledger>& ledger,
        const P1PlayerAllocationEpochAuthority::Storage* token) {
    need(ledger != nullptr && token != nullptr && token->live &&
         token->ledger == ledger && token->epoch > 0 &&
         ledger->objects.contains(token->epoch) &&
         ledger->objects.at(token->epoch).player);
}
#endif

} // namespace

P1CorruptStateCapsulePlanAuthority::P1CorruptStateCapsulePlanAuthority(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {}
P1CorruptStateCapsulePlanAuthority::P1CorruptStateCapsulePlanAuthority(
        P1CorruptStateCapsulePlanAuthority&&) noexcept = default;
P1CorruptStateCapsulePlanAuthority::~P1CorruptStateCapsulePlanAuthority() =
    default;

void P1CorruptStateCapsulePlanAuthority::
validate_for_role1_prelaunch_attachment(
        unsigned round, const Digest& topology_reservation_identity,
        const Digest& capture_plan_identity) const {
    need(storage_ != nullptr && (round == 1 || round == 2));
    validate_plan(storage_->plan);
    need(storage_->plan.role == 1 && storage_->plan.round == round &&
         storage_->plan.topology_reservation_identity ==
             topology_reservation_identity &&
         storage_->plan.prelaunch.round_capture_plans[round - 1] ==
             capture_plan_identity);
}

Digest P1CorruptStateCapsulePlanAuthority::
unavailable_trial_identity_for_role1_prelaunch() const {
    need(storage_ != nullptr);
    validate_plan(storage_->plan);
    need(storage_->plan.role == 1);
    return storage_->plan.prelaunch.trial;
}

Digest P1CorruptStateCapsulePlanAuthority::
unavailable_prelaunch_binding_identity_for_role1_prelaunch() const {
    need(storage_ != nullptr);
    validate_plan(storage_->plan);
    need(storage_->plan.role == 1);
    return storage_->plan.prelaunch.binding_identity;
}

Digest P1CorruptStateCapsulePlanAuthority::
capture_plan_identity_for_role1_prelaunch(unsigned round) const {
    need(storage_ != nullptr && (round == 1 || round == 2));
    validate_plan(storage_->plan);
    need(storage_->plan.role == 1 && storage_->plan.round == round);
    return storage_->plan.prelaunch.round_capture_plans[round - 1];
}

#ifdef KPB_P1_STATE_CAPSULE_TEST_SETUP
P1CorruptStateCapsulePlanAuthority
P1CorruptStateCapsulePlanAuthority::test_only_mint(
        StaticStateCapsulePlan plan) {
    validate_plan(plan);
    auto storage = std::make_unique<Storage>();
    storage->plan = std::move(plan);
    return P1CorruptStateCapsulePlanAuthority(std::move(storage));
}

P1CorruptStateCapsulePlanAuthority
P1CorruptStateCapsulePlanAuthority::test_only_mint_matching_writer_adoption(
        StaticStateCapsulePlan plan,
        const kpi::mpc::financial::registered_driver::
            P1StateArchiveWriterAdoptionAuthority& adoption) {
    return kpi::mpc::financial::registered_driver::
        P1StateArchiveWriterAdoptionConsumerBridge::test_only_bind_plan(
            std::move(plan), adoption, false, false);
}

P1CorruptStateCapsulePlanAuthority
P1CorruptStateCapsulePlanAuthority::test_only_mint_wrong_writer_adoption(
        StaticStateCapsulePlan plan,
        const kpi::mpc::financial::registered_driver::
            P1StateArchiveWriterAdoptionAuthority& adoption,
        bool wrong_round) {
    return kpi::mpc::financial::registered_driver::
        P1StateArchiveWriterAdoptionConsumerBridge::test_only_bind_plan(
            std::move(plan), adoption, wrong_round, !wrong_round);
}
#endif

P1CorruptStateRecorderAuthority
P1CorruptStateCapsulePlanAuthority::begin_before_player_and_protocol_setup(
        kpi::mpc::financial::registered_driver::
            P1StateArchiveWriterAdoptionAuthority&& adoption) && {
    return kpi::mpc::financial::registered_driver::
        P1StateArchiveWriterAdoptionConsumerBridge::begin(
            std::move(*this), std::move(adoption));
}

#ifdef KPB_P1_STATE_CAPSULE_TEST_SETUP
P1CorruptStateRecorderAuthority
P1CorruptStateCapsulePlanAuthority::
begin_before_player_and_protocol_setup() && {
    need(storage_ != nullptr);
    validate_plan(storage_->plan);
    auto close_result =
        std::make_unique<P1CorruptStateCapsuleAuthority::Storage>();
    auto child_disposition_result =
        P1CorruptStateCapsuleAuthority::preallocate_child_disposition(
            storage_->plan);
    auto abort_terminal_site_result =
        std::make_unique<P1AbortTerminalSiteAuthority::Storage>();
    auto abort_terminal_result =
        std::make_unique<P1AbortTerminalAuthority::Storage>();
    auto recorder =
        std::make_unique<P1CorruptStateRecorderAuthority::Storage>();
    auto ledger = std::make_shared<Ledger>();
    close_result->plan = storage_->plan;
    close_result->child_disposition_result =
        std::move(child_disposition_result);
    ledger->plan = storage_->plan;
    const auto opened = open_anonymous_disk_file();
    ledger->fd = opened.fd;
    ledger->device = opened.device;
    ledger->inode = opened.inode;
    for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index) {
        ledger->hook_event_sequence_identities[index] =
            hook_event_sequence_initial(
                static_cast<StateFamily>(index + 1));
        ledger->transition_sequence_identities[index] =
            hook_sequence_initial(static_cast<StateFamily>(index + 1));
        if (ledger->plan.source_family_dispositions[index] ==
                SourceFamilyDisposition::Missing)
            ledger->missing_family_bitmap |= std::uint64_t{1} << index;
    }
    recorder->ledger = std::move(ledger);
    recorder->close_result = std::move(close_result);
    recorder->abort_terminal_site_result =
        std::move(abort_terminal_site_result);
    recorder->abort_terminal_result = std::move(abort_terminal_result);
    storage_.reset();
    return P1CorruptStateRecorderAuthority(std::move(recorder));
}
#endif

P1StateThreadEpochAuthority::P1StateThreadEpochAuthority(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {}
P1StateThreadEpochAuthority::P1StateThreadEpochAuthority(
        P1StateThreadEpochAuthority&&) noexcept = default;
P1StateThreadEpochAuthority::~P1StateThreadEpochAuthority() {
    if (storage_ && storage_->live)
        poison_dropped_token(storage_->ledger);
}

P1StateObjectEpochAuthority::P1StateObjectEpochAuthority(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {}
P1StateObjectEpochAuthority::P1StateObjectEpochAuthority(
        P1StateObjectEpochAuthority&&) noexcept = default;
P1StateObjectEpochAuthority::~P1StateObjectEpochAuthority() {
    if (storage_ && storage_->live) {
        StateFamily family{};
        try {
            std::lock_guard lock(storage_->ledger->mutex);
            if (const auto found = storage_->ledger->objects.find(
                    storage_->epoch);
                found != storage_->ledger->objects.end())
                family = found->second.family;
        } catch (...) {}
        poison_dropped_token(storage_->ledger, family);
    }
}

P1PlayerAllocationEpochAuthority::P1PlayerAllocationEpochAuthority(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {}
P1PlayerAllocationEpochAuthority::P1PlayerAllocationEpochAuthority(
        P1PlayerAllocationEpochAuthority&&) noexcept = default;
P1PlayerAllocationEpochAuthority::~P1PlayerAllocationEpochAuthority() {
    if (storage_ && storage_->live)
        poison_dropped_token(
            storage_->ledger, StateFamily::PlayerAllocation);
}

P1AbortTerminalSiteAuthority::P1AbortTerminalSiteAuthority(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {}
P1AbortTerminalSiteAuthority::P1AbortTerminalSiteAuthority(
        P1AbortTerminalSiteAuthority&&) noexcept = default;
P1AbortTerminalSiteAuthority::~P1AbortTerminalSiteAuthority() {
    if (storage_ && storage_->live)
        poison_dropped_token(storage_->ledger);
}

P1AbortTerminalAuthority::P1AbortTerminalAuthority(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {}
P1AbortTerminalAuthority::P1AbortTerminalAuthority(
        P1AbortTerminalAuthority&&) noexcept = default;
P1AbortTerminalAuthority::~P1AbortTerminalAuthority() {
    if (storage_ && storage_->live)
        poison_dropped_token(
            storage_->ledger, StateFamily::ContextAndRetry);
}

P1ContextAndRetryStateAdapter::P1ContextAndRetryStateAdapter(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {
    need(storage_ != nullptr && storage_->ledger != nullptr &&
         storage_->thread_epoch == 1);
}

P1ContextAndRetryStateAdapter::~P1ContextAndRetryStateAdapter() {
    if (storage_ && !storage_->terminal && !storage_->unavailable)
        context_unavailable_noexcept();
}

void P1ContextAndRetryStateAdapter::context_constructed(
        std::span<const unsigned char> snapshot) {
    need(storage_ != nullptr && storage_->ledger != nullptr &&
         !storage_->constructed && !storage_->terminal &&
         !storage_->unavailable);
    auto ledger = storage_->ledger;
    const auto family = StateFamily::ContextAndRetry;
    auto payload = family_payload(*ledger, family, snapshot);
    std::lock_guard lock(ledger->mutex);
    const auto bit = family_bit(family);
    need(ledger->phase == SourcePhase::ProtocolSetupStarted &&
         ledger->context_retry_adapter_issued &&
         !ledger->abort_terminal_prepared &&
         (ledger->closed_family_bitmap & bit) == 0 &&
         (ledger->not_constructed_bitmap & bit) == 0 &&
         (ledger->missing_family_bitmap & bit) == 0 &&
         ledger->next_object_epoch <
             std::numeric_limits<std::uint64_t>::max());
    const auto epoch = ledger->next_object_epoch++;
    const auto index = family_index(family);
    need(ledger->object_counts[index] == 0);
    const auto family_ordinal = ++ledger->object_counts[index];
    need(family_ordinal == 1 && ledger->objects.emplace(epoch, ObjectState{
        .family = family,
        .thread_epoch = storage_->thread_epoch,
        .parent_epoch = 0,
        .family_ordinal = family_ordinal,
        .counter = 0,
        .player = false,
    }).second);
    append_record(*ledger, RecordType::Construct, family, 0, 0,
                  storage_->thread_epoch, epoch, 0, 0, 0, payload);
    advance_hook_event(
        *ledger, family, family_ordinal, HookEventKind::Construct,
        TransitionKind{}, 0, 0);
    storage_->object_epoch = epoch;
    storage_->constructed = true;
}

void P1ContextAndRetryStateAdapter::context_transition(
        kpi::mpc::p1_private_state::ContextTransition transition,
        std::uint64_t counter_before, std::uint64_t counter_after,
        std::span<const unsigned char> snapshot) {
    need(storage_ != nullptr && storage_->ledger != nullptr &&
         storage_->constructed && !storage_->terminal &&
         !storage_->unavailable);
    TransitionKind kind{};
    switch (transition) {
    case kpi::mpc::p1_private_state::ContextTransition::Validate:
        kind = TransitionKind::ContextValidate;
        break;
    case kpi::mpc::p1_private_state::ContextTransition::Retry:
        kind = TransitionKind::ContextRetry;
        break;
    case kpi::mpc::p1_private_state::ContextTransition::Poison:
        kind = TransitionKind::ContextPoison;
        break;
    }
    need(kind != TransitionKind{});
    auto ledger = storage_->ledger;
    std::lock_guard lock(ledger->mutex);
    auto found = ledger->objects.find(storage_->object_epoch);
    need(found != ledger->objects.end());
    auto& object = found->second;
    need(object.family == StateFamily::ContextAndRetry &&
         !ledger->abort_terminal_prepared &&
         !object.terminal_snapshot && !object.released &&
         counter_before == object.counter &&
         counter_after > counter_before);
    const auto payload = family_payload(
        *ledger, StateFamily::ContextAndRetry, snapshot);
    const auto index = family_index(StateFamily::ContextAndRetry);
    need(ledger->transition_counts[index] <
         std::numeric_limits<std::uint64_t>::max());
    const HookTransitionDescriptor descriptor{
        .object_ordinal = object.family_ordinal,
        .kind = kind,
        .counter_before = counter_before,
        .counter_after = counter_after,
    };
    const auto sequence = hook_sequence_next(
        StateFamily::ContextAndRetry,
        ledger->transition_sequence_identities[index], descriptor);
    append_record(
        *ledger, RecordType::Transition, StateFamily::ContextAndRetry,
        static_cast<std::uint8_t>(kind), 0, object.thread_epoch,
        storage_->object_epoch, 0, counter_before, counter_after, payload);
    advance_hook_event(
        *ledger, StateFamily::ContextAndRetry, object.family_ordinal,
        HookEventKind::Transition, kind, counter_before, counter_after);
    object.counter = counter_after;
    ++ledger->transition_counts[index];
    ledger->transition_bitmaps[index] |=
        std::uint64_t{1} << (static_cast<unsigned>(kind) - 1);
    ledger->transition_sequence_identities[index] = sequence;
}

void P1ContextAndRetryStateAdapter::context_terminal(
        std::span<const unsigned char> snapshot) {
    need(storage_ != nullptr && storage_->ledger != nullptr &&
         storage_->constructed && !storage_->terminal &&
         !storage_->unavailable);
    auto ledger = storage_->ledger;
    std::lock_guard lock(ledger->mutex);
    auto found = ledger->objects.find(storage_->object_epoch);
    need(found != ledger->objects.end());
    auto& object = found->second;
    need(object.family == StateFamily::ContextAndRetry &&
         !ledger->abort_terminal_prepared &&
         !object.terminal_snapshot && !object.released);
    const auto payload = family_payload(
        *ledger, StateFamily::ContextAndRetry, snapshot);
    append_record(
        *ledger, RecordType::TerminalSnapshot,
        StateFamily::ContextAndRetry, 0, 0, object.thread_epoch,
        storage_->object_epoch, 0, object.counter, object.counter, payload);
    advance_hook_event(
        *ledger, StateFamily::ContextAndRetry, object.family_ordinal,
        HookEventKind::TerminalSnapshot, TransitionKind{}, object.counter,
        object.counter);
    object.terminal_snapshot = true;
    storage_->terminal = true;

    const auto index = family_index(StateFamily::ContextAndRetry);
    const auto& inventory = ledger->plan.hook_inventory[index];
    const bool exact_success =
        ledger->object_counts[index] == inventory.exact_object_count &&
        ledger->hook_event_counts[index] == inventory.exact_event_count &&
        ledger->transition_counts[index] ==
            inventory.exact_transition_count &&
        ledger->transition_bitmaps[index] ==
            inventory.required_transition_bitmap &&
        ledger->hook_event_sequence_identities[index] ==
            inventory.expected_event_sequence_identity &&
        ledger->transition_sequence_identities[index] ==
            inventory.expected_transition_sequence_identity;
    if (exact_success) {
        std::vector<unsigned char> closed;
        append_digest(closed, ledger->plan.serializer_identities[index]);
        append_digest(closed, inventory.ordered_hook_manifest_identity);
        append_digest(closed, inventory.expected_event_sequence_identity);
        append_digest(
            closed, inventory.expected_transition_sequence_identity);
        append_u64(closed, ledger->object_counts[index]);
        append_u64(closed, ledger->hook_event_counts[index]);
        append_u64(closed, ledger->transition_counts[index]);
        append_u64(closed, ledger->transition_bitmaps[index]);
        append_u64(closed, ledger->event_counts[index]);
        append_record(
            *ledger, RecordType::FamilyClosed,
            StateFamily::ContextAndRetry, 0, 0, 0, 0, 0, 0, 0, closed);
        ledger->closed_family_bitmap |=
            family_bit(StateFamily::ContextAndRetry);
    }
}

void P1ContextAndRetryStateAdapter::context_unavailable_noexcept() noexcept {
    if (!storage_ || !storage_->ledger || storage_->unavailable) return;
    storage_->unavailable = true;
    auto ledger = storage_->ledger;
    try {
        std::lock_guard lock(ledger->mutex);
        ledger->poisoned = true;
        ledger->missing_family_bitmap |=
            family_bit(StateFamily::ContextAndRetry);
        if (!ledger->sealed && !ledger->io_failed && ledger->fd >= 0) {
            std::vector<unsigned char> payload;
            append_digest(payload, ledger->plan.serializer_identities[
                family_index(StateFamily::ContextAndRetry)]);
            append_record(
                *ledger, RecordType::Missing, StateFamily::ContextAndRetry,
                0, 0, storage_->thread_epoch, storage_->object_epoch, 0, 0,
                0, payload);
        }
    } catch (...) {
        try {
            std::lock_guard lock(ledger->mutex);
            ledger->poisoned = true;
            ledger->io_failed = true;
            ledger->missing_family_bitmap |=
                family_bit(StateFamily::ContextAndRetry);
        } catch (...) {}
    }
}

namespace {

void cleanse_mascot_bytes(std::vector<unsigned char>& value) noexcept {
    if (!value.empty()) OPENSSL_cleanse(value.data(), value.size());
    value.clear();
}

} // namespace

P1MascotSecretStateAdapter::P1MascotSecretStateAdapter(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {
    need(storage_ != nullptr && storage_->ledger != nullptr &&
         storage_->thread_epoch == 1);
}

P1MascotSecretStateAdapter::~P1MascotSecretStateAdapter() {
    if (storage_) storage_->scope.reset();
    if (storage_ && !storage_->terminal && !storage_->unavailable)
        mascot_secret_unavailable_noexcept();
}

bool P1MascotSecretStateAdapter::record_mascot_secret_event(
        const kpi::mpc::p1_private_state::MascotSecretEventView& view)
        noexcept {
    using Branch = kpi::mpc::p1_private_state::MascotCacheBranch;
    using FileResult = kpi::mpc::p1_private_state::MascotFileResult;
    using Kind = kpi::mpc::p1_private_state::MascotSecretEventKind;
    using Step = kpi::mpc::p1_private_state::MascotStepResult;
    std::vector<unsigned char> snapshot;
    std::vector<unsigned char> payload;
    try {
        need(storage_ != nullptr && storage_->ledger != nullptr &&
             !storage_->terminal && !storage_->unavailable &&
             storage_->owner_thread == std::this_thread::get_id() &&
             storage_->next != Storage::Next::Complete &&
             storage_->next != Storage::Next::FailureTerminal &&
             view.sequence == storage_->next_sequence);

        snapshot =
            kpi::mpc::p1_private_state::encode_mascot_secret_event(view);
        auto ledger = storage_->ledger;

        const bool first = storage_->next == Storage::Next::ScalarStateBegin;
        if (!first) {
            need(view.local_role == storage_->local_role &&
                 view.player_count == storage_->player_count &&
                 view.encrypted_player == storage_->encrypted_player &&
                 view.batch_size == storage_->batch_size &&
                 view.bucket_size == storage_->bucket_size &&
                 view.statistical_security ==
                     storage_->statistical_security &&
                 view.uses_security_parameter ==
                     storage_->uses_security_parameter &&
                 view.uses_kos == storage_->uses_kos &&
                 view.native_size_width == storage_->native_size_width &&
                 view.native_byte_order == storage_->native_byte_order &&
                 view.player_id == storage_->player_id &&
                 view.field_modulus == storage_->field_modulus &&
                 view.canonical_cache_domain ==
                     storage_->canonical_cache_domain &&
                 (view.kind == Kind::PrepMacFileWrite ||
                  view.diagnostic_path == storage_->cache_diagnostic_path));
        }

        auto next = storage_->next;
        auto branch = storage_->branch;
        auto cache_file_result = storage_->cache_file_result;
        switch (storage_->next) {
        case Storage::Next::ScalarStateBegin:
            need(view.kind == Kind::ScalarStateBegin &&
                 view.branch == Branch::Undecided);
            next = Storage::Next::SetupBegin;
            break;
        case Storage::Next::SetupBegin:
            need(view.kind == Kind::SetupBegin &&
                 (view.branch == Branch::Undecided ||
                  view.branch == Branch::StaticReuse));
            branch = view.branch;
            next = view.branch == Branch::StaticReuse
                ? Storage::Next::StaticInstalled
                : Storage::Next::CacheOpened;
            break;
        case Storage::Next::CacheOpened:
            need(view.kind == Kind::CacheOpened &&
                 view.branch == Branch::Undecided &&
                 view.file.result != FileResult::NotAttempted);
            cache_file_result = view.file.result;
            next = Storage::Next::CacheLocalValidation;
            break;
        case Storage::Next::CacheLocalValidation: {
            need(view.kind == Kind::CacheLocalValidation);
            Branch expected{};
            if (view.local_validation == Step::Succeeded)
                expected = Branch::CacheHit;
            else if (cache_file_result == FileResult::Missing)
                expected = Branch::RegeneratedAfterMissing;
            else
                expected = Branch::RegeneratedAfterLocalReject;
            need(view.branch == expected);
            branch = expected;
            next = Storage::Next::CachePeerValidation;
            break;
        }
        case Storage::Next::CachePeerValidation:
            need(view.kind == Kind::CachePeerValidation);
            if (view.peer_validation == Step::Failed)
                branch = Branch::RegeneratedAfterPeerReject;
            need(view.branch == branch);
            next = branch == Branch::CacheHit
                ? Storage::Next::WriteCandidate
                : Storage::Next::Regeneration;
            break;
        case Storage::Next::Regeneration:
            need(view.kind == Kind::Regeneration && view.branch == branch &&
                 branch != Branch::Undecided &&
                 branch != Branch::StaticReuse &&
                 branch != Branch::CacheHit);
            next = Storage::Next::WriteCandidate;
            break;
        case Storage::Next::WriteCandidate:
            need(view.kind == Kind::WriteCandidate && view.branch == branch);
            next = Storage::Next::Writeback;
            break;
        case Storage::Next::Writeback:
            need(view.kind == Kind::Writeback && view.branch == branch);
            next = view.writeback == Step::Succeeded
                ? Storage::Next::PrepStaticInstalled
                : Storage::Next::FailureTerminal;
            break;
        case Storage::Next::PrepStaticInstalled:
            need(view.kind == Kind::PrepStaticInstalled &&
                 view.branch == branch);
            next = Storage::Next::PrepMacFileWrite;
            break;
        case Storage::Next::PrepMacFileWrite:
            need(view.kind == Kind::PrepMacFileWrite &&
                 view.branch == branch);
            next = view.prep_mac_write == Step::Succeeded
                ? Storage::Next::BitPrepDerived
                : Storage::Next::FailureTerminal;
            break;
        case Storage::Next::BitPrepDerived:
            need(view.kind == Kind::BitPrepDerived && view.branch == branch &&
                 view.bit_prep_aliases_main);
            next = Storage::Next::StaticInstalled;
            break;
        case Storage::Next::StaticInstalled:
            need(view.kind == Kind::StaticInstalled &&
                 view.branch == branch);
            next = Storage::Next::Teardown;
            break;
        case Storage::Next::Teardown:
            need(view.kind == Kind::Teardown && view.branch == branch);
            next = Storage::Next::Complete;
            break;
        case Storage::Next::FailureTerminal:
        case Storage::Next::Abort:
        case Storage::Next::Complete:
        case Storage::Next::Unavailable:
            refuse();
        }

        const auto family = StateFamily::MascotSecrets;
        payload = family_payload(*ledger, family, snapshot);
        std::lock_guard lock(ledger->mutex);
        const auto bit = family_bit(family);
        const auto index = family_index(family);
        need(!ledger->sealed && !ledger->abort_terminal_prepared &&
             ledger->mascot_secret_adapter_issued &&
             !ledger->mascot_secret_adapter_finalized &&
             ledger->plan.role == 1 && view.local_role == ledger->plan.role &&
             !ledger->threads.at(storage_->thread_epoch).joined &&
             (ledger->closed_family_bitmap & bit) == 0 &&
             (ledger->not_constructed_bitmap & bit) == 0 &&
             (ledger->missing_family_bitmap & bit) == 0);

        if (view.kind == Kind::ScalarStateBegin) {
            need(ledger->phase == SourcePhase::ProtocolSetupStarted &&
                 !storage_->constructed &&
                 ledger->object_counts[index] == 0 &&
                 ledger->next_object_epoch <
                     std::numeric_limits<std::uint64_t>::max());
            const auto epoch = ledger->next_object_epoch++;
            const auto ordinal = ++ledger->object_counts[index];
            need(ordinal == 1 && ledger->objects.emplace(epoch, ObjectState{
                .family = family,
                .thread_epoch = storage_->thread_epoch,
                .parent_epoch = 0,
                .family_ordinal = ordinal,
                .counter = 0,
                .player = false,
            }).second);
            append_record(
                *ledger, RecordType::Construct, family, 0, 0,
                storage_->thread_epoch, epoch, 0, 0, 0, payload);
            advance_hook_event(
                *ledger, family, ordinal, HookEventKind::Construct,
                TransitionKind{}, 0, 0);
            storage_->object_epoch = epoch;
            storage_->constructed = true;
        } else if (view.kind == Kind::Teardown) {
            need(storage_->constructed);
            auto found = ledger->objects.find(storage_->object_epoch);
            need(found != ledger->objects.end());
            auto& object = found->second;
            need(object.family == family && !object.terminal_snapshot &&
                 !object.released && object.counter == storage_->counter);
            append_record(
                *ledger, RecordType::TerminalSnapshot, family, 0, 0,
                object.thread_epoch, storage_->object_epoch, 0,
                object.counter, object.counter, payload);
            advance_hook_event(
                *ledger, family, object.family_ordinal,
                HookEventKind::TerminalSnapshot, TransitionKind{},
                object.counter, object.counter);
            object.terminal_snapshot = true;

            const auto& inventory = ledger->plan.hook_inventory[index];
            need(ledger->object_counts[index] ==
                     inventory.exact_object_count &&
                 ledger->hook_event_counts[index] ==
                     inventory.exact_event_count &&
                 ledger->transition_counts[index] ==
                     inventory.exact_transition_count &&
                 ledger->transition_bitmaps[index] ==
                     inventory.required_transition_bitmap &&
                 ledger->hook_event_sequence_identities[index] ==
                     inventory.expected_event_sequence_identity &&
                 ledger->transition_sequence_identities[index] ==
                     inventory.expected_transition_sequence_identity &&
                 inventory.ordered_hook_manifest_identity ==
                     recompute_mascot_secret_branch_manifest_identity(branch));
            std::vector<unsigned char> closed;
            append_digest(closed, ledger->plan.serializer_identities[index]);
            append_digest(closed, inventory.ordered_hook_manifest_identity);
            append_digest(
                closed, inventory.expected_event_sequence_identity);
            append_digest(
                closed, inventory.expected_transition_sequence_identity);
            append_u64(closed, ledger->object_counts[index]);
            append_u64(closed, ledger->hook_event_counts[index]);
            append_u64(closed, ledger->transition_counts[index]);
            append_u64(closed, ledger->transition_bitmaps[index]);
            append_u64(closed, ledger->event_counts[index]);
            append_record(
                *ledger, RecordType::FamilyClosed, family, 0, 0,
                0, 0, 0, 0, 0, closed);
            ledger->closed_family_bitmap |= bit;
            ledger->mascot_secret_adapter_finalized = true;
            storage_->terminal = true;
        } else {
            need(storage_->constructed &&
                 storage_->counter <
                     std::numeric_limits<std::uint64_t>::max());
            auto found = ledger->objects.find(storage_->object_epoch);
            need(found != ledger->objects.end());
            auto& object = found->second;
            const auto transition = mascot_transition_kind(view.kind);
            const auto before = storage_->counter;
            const auto after = before + 1;
            need(object.family == family && !object.terminal_snapshot &&
                 !object.released && object.counter == before &&
                 transition_allowed(family, transition) &&
                 ledger->transition_counts[index] <
                     std::numeric_limits<std::uint64_t>::max());
            const HookTransitionDescriptor descriptor{
                .object_ordinal = object.family_ordinal,
                .kind = transition,
                .counter_before = before,
                .counter_after = after,
            };
            const auto sequence = hook_sequence_next(
                family, ledger->transition_sequence_identities[index],
                descriptor);
            append_record(
                *ledger, RecordType::Transition, family,
                static_cast<std::uint8_t>(transition), 0,
                object.thread_epoch, storage_->object_epoch, 0,
                before, after, payload);
            advance_hook_event(
                *ledger, family, object.family_ordinal,
                HookEventKind::Transition, transition, before, after);
            object.counter = after;
            ++ledger->transition_counts[index];
            ledger->transition_bitmaps[index] |=
                std::uint64_t{1} <<
                    (static_cast<unsigned>(transition) - 1);
            ledger->transition_sequence_identities[index] = sequence;
            storage_->counter = after;
        }

        if (first) {
            storage_->local_role = view.local_role;
            storage_->player_count = view.player_count;
            storage_->encrypted_player = view.encrypted_player;
            storage_->batch_size = view.batch_size;
            storage_->bucket_size = view.bucket_size;
            storage_->statistical_security = view.statistical_security;
            storage_->uses_security_parameter = view.uses_security_parameter;
            storage_->uses_kos = view.uses_kos;
            storage_->native_size_width = view.native_size_width;
            storage_->native_byte_order = view.native_byte_order;
            storage_->player_id.assign(view.player_id);
            storage_->field_modulus.assign(view.field_modulus);
            storage_->canonical_cache_domain.assign(
                view.canonical_cache_domain);
            storage_->cache_diagnostic_path.assign(view.diagnostic_path);
        }
        storage_->branch = branch;
        storage_->cache_file_result = cache_file_result;
        storage_->next = next;
        ++storage_->next_sequence;
        cleanse_mascot_bytes(payload);
        cleanse_mascot_bytes(snapshot);
        return true;
    } catch (...) {
        cleanse_mascot_bytes(payload);
        cleanse_mascot_bytes(snapshot);
        mascot_secret_unavailable_noexcept();
        return false;
    }
}

bool P1MascotSecretStateAdapter::record_mascot_secret_abort_event(
        const kpi::mpc::p1_private_state::MascotSecretAbortEventView& view)
        noexcept {
    using AbortClass =
        kpi::mpc::p1_private_state::MascotSecretAbortClass;
    using Kind =
        kpi::mpc::p1_private_state::MascotSecretAbortEventKind;
    std::vector<unsigned char> snapshot;
    std::vector<unsigned char> payload;
    try {
        need(storage_ != nullptr && storage_->ledger != nullptr &&
             !storage_->terminal && !storage_->unavailable &&
             view.sequence == storage_->next_abort_sequence &&
             view.success_next_sequence == storage_->next_sequence &&
             view.success_counter == storage_->counter &&
             view.local_role == storage_->local_role &&
             view.player_count == storage_->player_count &&
             view.encrypted_player == storage_->encrypted_player &&
             view.branch == storage_->branch &&
             view.canonical_cache_domain ==
                 storage_->canonical_cache_domain &&
             view.diagnostic_path == storage_->cache_diagnostic_path);
        snapshot =
            kpi::mpc::p1_private_state::encode_mascot_secret_abort_event(
                view);

        const bool first = !storage_->abort_started;
        if (first) {
            need(storage_->next == Storage::Next::Teardown &&
                 view.kind == Kind::CacheUnlink);
            storage_->abort_started = true;
            storage_->abort_class = view.abort_class;
            storage_->registered_worker_count =
                view.registered_worker_count;
            storage_->next = Storage::Next::Abort;
        } else {
            need(storage_->next == Storage::Next::Abort &&
                 view.kind != Kind::CacheUnlink &&
                 view.abort_class == storage_->abort_class &&
                 view.registered_worker_count ==
                     storage_->registered_worker_count);
        }

        const auto remember_worker = [&]() {
            need(view.source_worker_epoch != 0 &&
                 view.source_worker_ordinal <
                     storage_->registered_worker_count);
            const auto found = storage_->abort_worker_by_ordinal.find(
                view.source_worker_ordinal);
            if (found == storage_->abort_worker_by_ordinal.end()) {
                need(std::none_of(
                    storage_->abort_worker_by_ordinal.begin(),
                    storage_->abort_worker_by_ordinal.end(),
                    [&](const auto& item) {
                        return item.second == view.source_worker_epoch;
                    }));
                storage_->abort_worker_by_ordinal.emplace(
                    view.source_worker_ordinal, view.source_worker_epoch);
            } else {
                need(found->second == view.source_worker_epoch);
            }
        };
        const auto require_worker = [&]() {
            const auto found = storage_->abort_worker_by_ordinal.find(
                view.source_worker_ordinal);
            need(found != storage_->abort_worker_by_ordinal.end() &&
                 found->second == view.source_worker_epoch);
        };

        switch (view.kind) {
        case Kind::CacheUnlink:
            if (view.abort_class == AbortClass::OtMultiplierFailure)
                remember_worker();
            break;
        case Kind::WorkerFailurePublished:
            require_worker();
            need(storage_->abort_worker_failures.insert(
                     view.source_worker_epoch).second);
            break;
        case Kind::WorkerTerminal:
            remember_worker();
            need((!view.worker_failed ||
                  storage_->abort_worker_failures.contains(
                      view.source_worker_epoch)) &&
                 storage_->abort_worker_terminals.insert(
                     view.source_worker_epoch).second);
            break;
        case Kind::RootFailureObserved:
            require_worker();
            need(storage_->abort_worker_failures.contains(
                     view.source_worker_epoch) &&
                 storage_->abort_worker_terminals.contains(
                     view.source_worker_epoch) &&
                 storage_->abort_worker_observed.insert(
                     view.source_worker_epoch).second);
            break;
        case Kind::WorkerJoined:
            require_worker();
            need(storage_->abort_worker_terminals.contains(
                     view.source_worker_epoch) &&
                 (!view.worker_failed ||
                  storage_->abort_worker_observed.contains(
                      view.source_worker_epoch)) &&
                 storage_->abort_worker_joined.insert(
                     view.source_worker_epoch).second);
            break;
        case Kind::Teardown:
            need(!storage_->abort_teardown);
            storage_->abort_teardown = true;
            break;
        case Kind::AbortTerminal:
            need(storage_->abort_teardown && view.all_workers_terminal &&
                 view.all_workers_joined &&
                 storage_->abort_worker_terminals.size() ==
                     storage_->registered_worker_count &&
                 storage_->abort_worker_joined.size() ==
                     storage_->registered_worker_count &&
                 storage_->abort_worker_by_ordinal.size() ==
                     storage_->registered_worker_count &&
                 (storage_->abort_class !=
                      AbortClass::OtMultiplierFailure ||
                  (!storage_->abort_worker_failures.empty() &&
                   storage_->abort_worker_failures ==
                       storage_->abort_worker_observed)));
            break;
        case Kind::AbortUnavailable:
            need(!view.all_workers_terminal || !view.all_workers_joined ||
                 !storage_->abort_teardown ||
                 storage_->abort_worker_terminals.size() !=
                     storage_->registered_worker_count ||
                 storage_->abort_worker_joined.size() !=
                     storage_->registered_worker_count ||
                 (storage_->abort_class ==
                      AbortClass::OtMultiplierFailure &&
                  (storage_->abort_worker_failures.empty() ||
                   storage_->abort_worker_failures !=
                       storage_->abort_worker_observed)));
            break;
        }

        auto ledger = storage_->ledger;
        const auto family = StateFamily::MascotSecrets;
        payload = family_payload(*ledger, family, snapshot);
        std::lock_guard lock(ledger->mutex);
        const auto bit = family_bit(family);
        need(!ledger->sealed && !ledger->abort_terminal_prepared &&
             ledger->mascot_secret_adapter_issued &&
             !ledger->mascot_secret_adapter_finalized &&
             ledger->plan.role == 1 &&
             !ledger->threads.at(storage_->thread_epoch).joined &&
             (ledger->closed_family_bitmap & bit) == 0 &&
             (ledger->not_constructed_bitmap & bit) == 0);
        append_record(
            *ledger, RecordType::AbortEvent, family,
            static_cast<std::uint8_t>(view.kind),
            static_cast<std::uint8_t>(view.abort_class),
            storage_->thread_epoch, storage_->object_epoch, 0,
            storage_->counter, storage_->counter, payload);

        ++storage_->next_abort_sequence;
        if (view.kind == Kind::AbortTerminal ||
            view.kind == Kind::AbortUnavailable) {
            ledger->mascot_secret_adapter_finalized = true;
            storage_->terminal = view.kind == Kind::AbortTerminal;
            storage_->unavailable = view.kind == Kind::AbortUnavailable;
        }
        cleanse_mascot_bytes(payload);
        cleanse_mascot_bytes(snapshot);
        return true;
    } catch (...) {
        cleanse_mascot_bytes(payload);
        cleanse_mascot_bytes(snapshot);
        mascot_secret_unavailable_noexcept();
        return false;
    }
}

void P1MascotSecretStateAdapter::mascot_secret_unavailable_noexcept()
        noexcept {
    if (!storage_ || !storage_->ledger || storage_->unavailable) return;
    storage_->unavailable = true;
    storage_->next = Storage::Next::Unavailable;
    auto ledger = storage_->ledger;
    try {
        std::lock_guard lock(ledger->mutex);
        ledger->poisoned = true;
        ledger->missing_family_bitmap |= family_bit(StateFamily::MascotSecrets);
        if (!ledger->sealed && !ledger->io_failed && ledger->fd >= 0) {
            std::vector<unsigned char> payload;
            append_digest(payload, ledger->plan.serializer_identities[
                family_index(StateFamily::MascotSecrets)]);
            append_u64(payload, storage_->next_sequence);
            append_record(
                *ledger, RecordType::Missing, StateFamily::MascotSecrets,
                0, 0, storage_->thread_epoch, storage_->object_epoch,
                0, storage_->counter, storage_->counter, payload);
        }
    } catch (...) {
        try {
            std::lock_guard lock(ledger->mutex);
            ledger->poisoned = true;
            ledger->io_failed = true;
            ledger->missing_family_bitmap |=
                family_bit(StateFamily::MascotSecrets);
        } catch (...) {}
    }
}

namespace {

StateFamily entropy_family(
        kpi::mpc::p1_private_state::EntropySource source) {
    using kpi::mpc::p1_private_state::EntropySource;
    switch (source) {
    case EntropySource::MpSpdzPrngReseed:
        return StateFamily::MpSpdzPrng;
    case EntropySource::SimplestOtRandomBytes:
        return StateFamily::SimplestOtBase;
    case EntropySource::CryptoToolsSystemSeed:
        return StateFamily::CryptoToolsPrng;
    }
    refuse();
}

unsigned entropy_counter_index(
        kpi::mpc::p1_private_state::EntropySource source) {
    const auto value = static_cast<unsigned>(source);
    need(value >= 1 && value <= 3);
    return value - 1;
}

constexpr std::array<StateFamily, 3> ENTROPY_FAMILIES{
    StateFamily::MpSpdzPrng,
    StateFamily::SimplestOtBase,
    StateFamily::CryptoToolsPrng,
};

} // namespace

P1EntropyStateAdapter::P1EntropyStateAdapter(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {
    need(storage_ != nullptr && storage_->ledger != nullptr &&
         storage_->thread_epoch == 1);
}

P1EntropyStateAdapter::~P1EntropyStateAdapter() {
    if (storage_ && !storage_->terminal && !storage_->unavailable)
        entropy_unavailable_noexcept(
            kpi::mpc::p1_private_state::EntropySource::MpSpdzPrngReseed);
}

bool P1EntropyStateAdapter::record_entropy_ingress(
        const kpi::mpc::p1_private_state::EntropyIngressView& view)
        noexcept {
    std::vector<unsigned char> snapshot;
    std::vector<unsigned char> payload;
    try {
        need(storage_ != nullptr && storage_->ledger != nullptr &&
             !storage_->terminal && !storage_->unavailable);
        snapshot = kpi::mpc::p1_private_state::encode_entropy_ingress(view);
        const auto family = entropy_family(view.source);
        const auto counter_index = entropy_counter_index(view.source);
        auto ledger = storage_->ledger;
        std::lock_guard lock(ledger->mutex);
        const auto bit = family_bit(family);
        need(!ledger->sealed && !ledger->abort_terminal_prepared &&
             ledger->entropy_adapter_issued &&
             !ledger->entropy_adapter_finalized &&
             static_cast<unsigned>(ledger->phase) >=
                 static_cast<unsigned>(SourcePhase::RecorderStarted) &&
             static_cast<unsigned>(ledger->phase) <
                 static_cast<unsigned>(SourcePhase::TerminalEgress) &&
             !ledger->threads.at(storage_->thread_epoch).joined &&
             // The first source slice is root-thread exact. Any entropy from
             // an unbound worker thread makes the family unavailable until a
             // source-owned thread-epoch bridge is selected.
             view.thread_epoch == storage_->thread_epoch &&
             view.object_epoch == storage_->next_source_object_epoch &&
             view.allocation_epoch ==
                 storage_->next_source_allocation_epoch &&
             view.counter_before == storage_->counters[counter_index] &&
             view.counter_after == view.counter_before + 1 &&
             storage_->source_object_epochs.insert(
                 view.object_epoch).second &&
             storage_->source_allocation_epochs.insert(
                 view.allocation_epoch).second &&
             (ledger->closed_family_bitmap & bit) == 0 &&
             (ledger->not_constructed_bitmap & bit) == 0 &&
             (ledger->missing_family_bitmap & bit) == 0 &&
             ledger->next_object_epoch <
                 std::numeric_limits<std::uint64_t>::max());

        const auto epoch = ledger->next_object_epoch++;
        const auto index = family_index(family);
        need(ledger->object_counts[index] <
             std::numeric_limits<std::uint64_t>::max());
        const auto ordinal = ++ledger->object_counts[index];
        need(ledger->objects.emplace(epoch, ObjectState{
            .family = family,
            .thread_epoch = storage_->thread_epoch,
            .parent_epoch = 0,
            .family_ordinal = ordinal,
            .counter = 0,
            .player = false,
        }).second);
        payload = family_payload(*ledger, family, snapshot);
        append_record(
            *ledger, RecordType::Construct, family, 0, 0,
            storage_->thread_epoch, epoch, 0, 0, 0, payload);
        advance_hook_event(
            *ledger, family, ordinal, HookEventKind::Construct,
            TransitionKind{}, 0, 0);

        const HookTransitionDescriptor descriptor{
            .object_ordinal = ordinal,
            .kind = TransitionKind::EntropySeed,
            .counter_before = 0,
            .counter_after = 1,
        };
        const auto sequence = hook_sequence_next(
            family, ledger->transition_sequence_identities[index],
            descriptor);
        append_record(
            *ledger, RecordType::Transition, family,
            static_cast<std::uint8_t>(TransitionKind::EntropySeed), 0,
            storage_->thread_epoch, epoch, 0, 0, 1, payload);
        advance_hook_event(
            *ledger, family, ordinal, HookEventKind::Transition,
            TransitionKind::EntropySeed, 0, 1);
        auto& object = ledger->objects.at(epoch);
        object.counter = 1;
        ++ledger->transition_counts[index];
        ledger->transition_bitmaps[index] |=
            std::uint64_t{1} <<
                (static_cast<unsigned>(TransitionKind::EntropySeed) - 1);
        ledger->transition_sequence_identities[index] = sequence;

        append_record(
            *ledger, RecordType::TerminalSnapshot, family, 0, 0,
            storage_->thread_epoch, epoch, 0, 1, 1, payload);
        advance_hook_event(
            *ledger, family, ordinal, HookEventKind::TerminalSnapshot,
            TransitionKind{}, 1, 1);
        object.terminal_snapshot = true;
        storage_->counters[counter_index] = view.counter_after;
        ++storage_->next_source_object_epoch;
        ++storage_->next_source_allocation_epoch;
        OPENSSL_cleanse(payload.data(), payload.size());
        OPENSSL_cleanse(snapshot.data(), snapshot.size());
        return true;
    } catch (...) {
        OPENSSL_cleanse(payload.data(), payload.size());
        OPENSSL_cleanse(snapshot.data(), snapshot.size());
        entropy_unavailable_noexcept(view.source);
        return false;
    }
}

bool P1EntropyStateAdapter::entropy_capture_terminal_noexcept() noexcept {
    if (!storage_ || !storage_->ledger || storage_->terminal ||
        storage_->unavailable)
        return false;
    auto ledger = storage_->ledger;
    try {
        std::lock_guard lock(ledger->mutex);
        need(ledger->entropy_adapter_issued &&
             !ledger->entropy_adapter_finalized &&
             !ledger->sealed && !ledger->abort_terminal_prepared);
        for (const auto family : ENTROPY_FAMILIES) {
            const auto bit = family_bit(family);
            need((ledger->closed_family_bitmap & bit) == 0 &&
                 (ledger->not_constructed_bitmap & bit) == 0 &&
                 (ledger->missing_family_bitmap & bit) == 0);
            bool found = false;
            for (const auto& [epoch, object] : ledger->objects) {
                (void)epoch;
                if (object.family != family) continue;
                found = true;
                need(object.terminal_snapshot && !object.released);
            }
            need(found);
            const auto index = family_index(family);
            const auto& inventory = ledger->plan.hook_inventory[index];
            need(ledger->object_counts[index] ==
                     inventory.exact_object_count &&
                 ledger->hook_event_counts[index] ==
                     inventory.exact_event_count &&
                 ledger->transition_counts[index] ==
                     inventory.exact_transition_count &&
                 ledger->transition_bitmaps[index] ==
                     inventory.required_transition_bitmap &&
                 ledger->hook_event_sequence_identities[index] ==
                     inventory.expected_event_sequence_identity &&
                 ledger->transition_sequence_identities[index] ==
                     inventory.expected_transition_sequence_identity);
            std::vector<unsigned char> closed;
            append_digest(
                closed, ledger->plan.serializer_identities[index]);
            append_digest(
                closed, inventory.ordered_hook_manifest_identity);
            append_digest(
                closed, inventory.expected_event_sequence_identity);
            append_digest(
                closed, inventory.expected_transition_sequence_identity);
            append_u64(closed, ledger->object_counts[index]);
            append_u64(closed, ledger->hook_event_counts[index]);
            append_u64(closed, ledger->transition_counts[index]);
            append_u64(closed, ledger->transition_bitmaps[index]);
            append_u64(closed, ledger->event_counts[index]);
            append_record(
                *ledger, RecordType::FamilyClosed, family, 0, 0,
                0, 0, 0, 0, 0, closed);
            ledger->closed_family_bitmap |= bit;
        }
        ledger->entropy_adapter_finalized = true;
        storage_->terminal = true;
        return true;
    } catch (...) {
        entropy_unavailable_noexcept(
            kpi::mpc::p1_private_state::EntropySource::MpSpdzPrngReseed);
        return false;
    }
}

void P1EntropyStateAdapter::entropy_unavailable_noexcept(
        kpi::mpc::p1_private_state::EntropySource) noexcept {
    if (!storage_ || !storage_->ledger || storage_->unavailable) return;
    storage_->unavailable = true;
    auto ledger = storage_->ledger;
    try {
        std::lock_guard lock(ledger->mutex);
        ledger->poisoned = true;
        ledger->entropy_adapter_finalized = true;
        for (const auto family : ENTROPY_FAMILIES) {
            const auto bit = family_bit(family);
            if ((ledger->missing_family_bitmap & bit) != 0) continue;
            ledger->missing_family_bitmap |= bit;
            if (!ledger->sealed && !ledger->io_failed && ledger->fd >= 0) {
                std::vector<unsigned char> missing;
                append_digest(
                    missing, ledger->plan.serializer_identities[
                        family_index(family)]);
                append_record(
                    *ledger, RecordType::Missing, family, 0, 0,
                    storage_->thread_epoch, 0, 0, 0, 0, missing);
            }
        }
    } catch (...) {
        try {
            std::lock_guard lock(ledger->mutex);
            ledger->poisoned = true;
            ledger->io_failed = true;
            ledger->entropy_adapter_finalized = true;
            for (const auto family : ENTROPY_FAMILIES)
                ledger->missing_family_bitmap |= family_bit(family);
        } catch (...) {}
    }
}

P1PlayerTlsStateAdapter::P1PlayerTlsStateAdapter(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {
    need(storage_ != nullptr && storage_->ledger != nullptr &&
         storage_->thread_epoch == 1);
}

P1PlayerTlsStateAdapter::~P1PlayerTlsStateAdapter() {
    // This first vertical slice deliberately records only the documented
    // construction/handshake prefix. OpenSSL DRBG internals and live
    // record-layer buffers are not serialized, so destruction cannot close
    // either family as complete.
    player_tls_unavailable_noexcept();
}

bool P1PlayerTlsStateAdapter::record_player_tls_event(
        const kpi::mpc::p1_private_state::PlayerTlsEventView& view)
        noexcept {
    std::vector<unsigned char> snapshot;
    std::vector<unsigned char> payload;
    try {
        need(storage_ != nullptr && storage_->ledger != nullptr &&
             !storage_->unavailable);
        snapshot = kpi::mpc::p1_private_state::encode_player_tls_event(view);
        auto ledger = storage_->ledger;
        std::lock_guard lock(ledger->mutex);
        need(!ledger->sealed && !ledger->abort_terminal_prepared &&
             ledger->player_tls_adapter_issued &&
             ledger->plan.role == 1 && view.local_role == ledger->plan.role &&
             !ledger->threads.at(storage_->thread_epoch).joined);

        const auto create = [&](StateFamily family,
                                std::uint64_t parent_epoch,
                                bool player) {
            const auto bit = family_bit(family);
            need((ledger->closed_family_bitmap & bit) == 0 &&
                 (ledger->not_constructed_bitmap & bit) == 0 &&
                 (ledger->missing_family_bitmap & bit) == 0 &&
                 ledger->next_object_epoch <
                     std::numeric_limits<std::uint64_t>::max());
            const auto epoch = ledger->next_object_epoch++;
            const auto index = family_index(family);
            need(ledger->object_counts[index] <
                 std::numeric_limits<std::uint64_t>::max());
            const auto ordinal = ++ledger->object_counts[index];
            need(ledger->objects.emplace(epoch, ObjectState{
                .family = family,
                .thread_epoch = storage_->thread_epoch,
                .parent_epoch = parent_epoch,
                .family_ordinal = ordinal,
                .counter = 0,
                .player = player,
            }).second);
            payload = family_payload(*ledger, family, snapshot);
            append_record(*ledger, RecordType::Construct, family, 0, 0,
                          storage_->thread_epoch, epoch, parent_epoch,
                          0, 0, payload);
            advance_hook_event(
                *ledger, family, ordinal, HookEventKind::Construct,
                TransitionKind{}, 0, 0);
            OPENSSL_cleanse(payload.data(), payload.size());
            payload.clear();
            return epoch;
        };

        const auto update = [&](StateFamily family, std::uint64_t epoch,
                                TransitionKind kind) {
            auto found = ledger->objects.find(epoch);
            need(found != ledger->objects.end());
            auto& object = found->second;
            need(object.family == family && !object.terminal_snapshot &&
                 !object.released && transition_allowed(family, kind) &&
                 object.counter < std::numeric_limits<std::uint64_t>::max());
            const auto before = object.counter;
            const auto after = before + 1;
            const auto index = family_index(family);
            need(ledger->transition_counts[index] <
                 std::numeric_limits<std::uint64_t>::max());
            const HookTransitionDescriptor descriptor{
                .object_ordinal = object.family_ordinal,
                .kind = kind,
                .counter_before = before,
                .counter_after = after,
            };
            const auto sequence = hook_sequence_next(
                family, ledger->transition_sequence_identities[index],
                descriptor);
            payload = family_payload(*ledger, family, snapshot);
            append_record(
                *ledger, RecordType::Transition, family,
                static_cast<std::uint8_t>(kind), 0, object.thread_epoch,
                epoch, object.parent_epoch, before, after, payload);
            advance_hook_event(
                *ledger, family, object.family_ordinal,
                HookEventKind::Transition, kind, before, after);
            object.counter = after;
            ++ledger->transition_counts[index];
            ledger->transition_bitmaps[index] |=
                std::uint64_t{1} << (static_cast<unsigned>(kind) - 1);
            ledger->transition_sequence_identities[index] = sequence;
            OPENSSL_cleanse(payload.data(), payload.size());
            payload.clear();
        };

        const std::string player_id(view.player_id);
        switch (view.kind) {
        case kpi::mpc::p1_private_state::PlayerTlsEventKind::
                PlayerConstructionStarted: {
            need(ledger->phase != SourcePhase::TerminalEgress &&
                 !storage_->player_epochs.contains(player_id));
            std::uint64_t parent_epoch = 0;
            if (view.parent_player_id.empty()) {
                need(ledger->phase == SourcePhase::RecorderStarted &&
                     storage_->player_epochs.empty() &&
                     !ledger->root_player_bound);
                ledger->root_player_bound = true;
            } else {
                const auto parent = storage_->player_epochs.find(
                    std::string(view.parent_player_id));
                need(parent != storage_->player_epochs.end() &&
                     storage_->constructed_players.contains(
                         std::string(view.parent_player_id)) &&
                     !storage_->destroying_players.contains(
                         std::string(view.parent_player_id)));
                parent_epoch = parent->second;
            }
            const auto epoch = create(
                StateFamily::PlayerAllocation, parent_epoch, true);
            need(storage_->player_epochs.emplace(player_id, epoch).second &&
                 storage_->player_construction_phases.emplace(
                     player_id, ledger->phase).second);
            break;
        }
        case kpi::mpc::p1_private_state::PlayerTlsEventKind::
                PlayerConstructed:
        case kpi::mpc::p1_private_state::PlayerTlsEventKind::
                PlayerDestructionStarted: {
            const auto found = storage_->player_epochs.find(player_id);
            need(found != storage_->player_epochs.end());
            if (view.kind == kpi::mpc::p1_private_state::
                    PlayerTlsEventKind::PlayerConstructed) {
                need(storage_->player_construction_phases.at(player_id) ==
                         ledger->phase &&
                     storage_->tls_context_epochs.contains(player_id) &&
                     !storage_->constructed_players.contains(player_id));
                std::size_t channels = 0;
                std::size_t handshakes = 0;
                for (const auto& [key, state] : storage_->tls_channels) {
                    if (std::get<0>(key) != player_id) continue;
                    ++channels;
                    if (state.handshake_complete) ++handshakes;
                }
                need(channels == 4 && handshakes == 4);
                for (std::uint64_t peer = 0; peer < 3; ++peer) {
                    if (peer == view.local_role) continue;
                    for (std::uint64_t lane = 0; lane < 2; ++lane) {
                        const auto key =
                            std::make_tuple(player_id, peer, lane);
                        need(storage_->tls_channels.contains(key) &&
                             storage_->tls_channels.at(key)
                                 .handshake_complete);
                    }
                }
                need(storage_->constructed_players.insert(
                    player_id).second);
            } else {
                need(storage_->constructed_players.contains(player_id) &&
                     storage_->destroying_players.insert(player_id).second);
            }
            update(StateFamily::PlayerAllocation, found->second,
                   TransitionKind::PlayerTraffic);
            break;
        }
        case kpi::mpc::p1_private_state::PlayerTlsEventKind::
                TlsContextLoaded: {
            need(storage_->player_construction_phases.at(player_id) ==
                     ledger->phase &&
                 !storage_->tls_context_epochs.contains(player_id));
            const auto player = storage_->player_epochs.find(player_id);
            need(player != storage_->player_epochs.end());
            const auto epoch = create(
                StateFamily::TlsChannelState, player->second, false);
            need(storage_->tls_context_epochs.emplace(
                player_id, epoch).second);
            break;
        }
        case kpi::mpc::p1_private_state::PlayerTlsEventKind::
                TlsChannelStarted: {
            need(storage_->player_construction_phases.at(player_id) ==
                 ledger->phase);
            const auto context = storage_->tls_context_epochs.find(player_id);
            need(context != storage_->tls_context_epochs.end());
            const auto key = std::make_tuple(
                player_id, view.peer_role, view.lane);
            need(!storage_->tls_channels.contains(key));
            const auto epoch = create(
                StateFamily::TlsChannelState, context->second, false);
            need(storage_->tls_channels.emplace(key, Storage::Channel{
                .epoch = epoch,
                .client = view.client,
                .construction_phase = ledger->phase,
            }).second);
            break;
        }
        case kpi::mpc::p1_private_state::PlayerTlsEventKind::TlsInfo:
        case kpi::mpc::p1_private_state::PlayerTlsEventKind::TlsMessage:
        case kpi::mpc::p1_private_state::PlayerTlsEventKind::TlsKeyLog:
        case kpi::mpc::p1_private_state::PlayerTlsEventKind::
                TlsHandshakeComplete:
        case kpi::mpc::p1_private_state::PlayerTlsEventKind::
                TlsHandshakeFailed: {
            const auto channel = storage_->tls_channels.find(
                std::make_tuple(player_id, view.peer_role, view.lane));
            need(channel != storage_->tls_channels.end() &&
                 view.client == channel->second.client &&
                 static_cast<unsigned>(ledger->phase) >=
                     static_cast<unsigned>(
                         channel->second.construction_phase) &&
                 ledger->phase != SourcePhase::TerminalEgress);
            if (view.kind == kpi::mpc::p1_private_state::
                    PlayerTlsEventKind::TlsHandshakeComplete)
                need(!channel->second.handshake_complete);
            update(StateFamily::TlsChannelState, channel->second.epoch,
                   TransitionKind::TlsHandshake);
            if (view.kind == kpi::mpc::p1_private_state::
                    PlayerTlsEventKind::TlsHandshakeComplete)
                channel->second.handshake_complete = true;
            if (view.kind == kpi::mpc::p1_private_state::
                    PlayerTlsEventKind::TlsHandshakeFailed)
                throw Refused();
            break;
        }
        }
        OPENSSL_cleanse(snapshot.data(), snapshot.size());
        return true;
    } catch (...) {
        OPENSSL_cleanse(payload.data(), payload.size());
        OPENSSL_cleanse(snapshot.data(), snapshot.size());
        player_tls_unavailable_noexcept();
        return false;
    }
}

void P1PlayerTlsStateAdapter::player_tls_unavailable_noexcept() noexcept {
    if (!storage_ || !storage_->ledger || storage_->unavailable) return;
    storage_->unavailable = true;
    auto ledger = storage_->ledger;
    try {
        std::lock_guard lock(ledger->mutex);
        ledger->poisoned = true;
        ledger->player_tls_adapter_finalized = true;
        for (const auto family : {
                 StateFamily::PlayerAllocation,
                 StateFamily::TlsChannelState}) {
            const auto bit = family_bit(family);
            if ((ledger->missing_family_bitmap & bit) != 0) continue;
            ledger->missing_family_bitmap |= bit;
            if (!ledger->sealed && !ledger->io_failed && ledger->fd >= 0) {
                std::vector<unsigned char> missing;
                append_digest(missing, ledger->plan.serializer_identities[
                    family_index(family)]);
                append_record(*ledger, RecordType::Missing, family, 0, 0,
                              storage_->thread_epoch, 0, 0, 0, 0, missing);
            }
        }
    } catch (...) {
        try {
            std::lock_guard lock(ledger->mutex);
            ledger->poisoned = true;
            ledger->io_failed = true;
            ledger->player_tls_adapter_finalized = true;
            ledger->missing_family_bitmap |=
                family_bit(StateFamily::PlayerAllocation) |
                family_bit(StateFamily::TlsChannelState);
        } catch (...) {}
    }
}

P1CorruptStateRecorderAuthority::P1CorruptStateRecorderAuthority(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {}
P1CorruptStateRecorderAuthority::P1CorruptStateRecorderAuthority(
        P1CorruptStateRecorderAuthority&&) noexcept = default;
P1CorruptStateRecorderAuthority::~P1CorruptStateRecorderAuthority() {
    if (storage_ && storage_->ledger) {
        try {
            std::lock_guard lock(storage_->ledger->mutex);
            if (!storage_->ledger->sealed) {
                storage_->ledger->poisoned = true;
                storage_->ledger->missing_family_bitmap |=
                    FULL_FAMILY_BITMAP;
            }
        } catch (...) {}
    }
}

P1StateThreadEpochAuthority
P1CorruptStateRecorderAuthority::take_root_thread_epoch() {
    need(storage_ != nullptr && storage_->ledger != nullptr);
    auto ledger = storage_->ledger;
    std::lock_guard lock(ledger->mutex);
    need(!ledger->sealed && !ledger->root_thread_taken);
    ledger->root_thread_taken = true;
    std::vector<unsigned char> payload;
    append_digest(payload, ledger->plan.source_hook_manifest_identity);
    append_digest(payload, ledger->plan.persistent_child_identity);
    append_u64(payload, ledger->plan.persistent_child_epoch);
    append_u64(payload, ledger->plan.context_allocation_epoch);
    append_record(*ledger, RecordType::ThreadEpoch,
                  StateFamily{}, 0, 0, 1, 0, 0, 0, 0,
                  payload);
    auto token = std::make_unique<P1StateThreadEpochAuthority::Storage>();
    token->ledger = ledger;
    token->epoch = 1;
    return P1StateThreadEpochAuthority(std::move(token));
}

std::unique_ptr<P1ContextAndRetryStateAdapter>
P1ContextAndRetryStateAdapterFactoryBridge::take(
        P1CorruptStateRecorderAuthority& recorder,
        const P1StateThreadEpochAuthority& root_thread) {
    need(recorder.storage_ != nullptr && recorder.storage_->ledger != nullptr);
    auto ledger = recorder.storage_->ledger;
    std::lock_guard lock(ledger->mutex);
    need_thread(ledger, root_thread.storage_.get());
    const auto bit = family_bit(StateFamily::ContextAndRetry);
    need(root_thread.storage_->epoch == 1 &&
         ledger->phase == SourcePhase::ProtocolSetupStarted &&
         !ledger->context_retry_adapter_issued &&
         !ledger->threads.at(1).joined &&
         !ledger->abort_terminal_prepared &&
         (ledger->closed_family_bitmap & bit) == 0 &&
         (ledger->not_constructed_bitmap & bit) == 0 &&
         (ledger->missing_family_bitmap & bit) == 0 &&
         ledger->object_counts[family_index(
             StateFamily::ContextAndRetry)] == 0);
    auto state = std::make_unique<P1ContextAndRetryStateAdapter::Storage>();
    state->ledger = ledger;
    state->thread_epoch = root_thread.storage_->epoch;
    ledger->context_retry_adapter_issued = true;
    return std::unique_ptr<P1ContextAndRetryStateAdapter>(
        new P1ContextAndRetryStateAdapter(std::move(state)));
}

std::unique_ptr<P1ContextAndRetryStateAdapter>
P1CorruptStateRecorderAuthority::take_context_and_retry_adapter(
        const P1StateThreadEpochAuthority& root_thread) {
    return P1ContextAndRetryStateAdapterFactoryBridge::take(
        *this, root_thread);
}

std::unique_ptr<P1MascotSecretStateAdapter>
P1MascotSecretStateAdapterFactoryBridge::take(
        P1CorruptStateRecorderAuthority& recorder,
        const P1StateThreadEpochAuthority& root_thread) {
    need(recorder.storage_ != nullptr && recorder.storage_->ledger != nullptr);
    auto ledger = recorder.storage_->ledger;
    auto state = std::make_unique<P1MascotSecretStateAdapter::Storage>();
    {
        std::lock_guard lock(ledger->mutex);
        need_thread(ledger, root_thread.storage_.get());
        const auto family = StateFamily::MascotSecrets;
        const auto bit = family_bit(family);
        need(root_thread.storage_->epoch == 1 && ledger->plan.role == 1 &&
             ledger->phase == SourcePhase::ProtocolSetupStarted &&
             !ledger->mascot_secret_adapter_issued &&
             !ledger->threads.at(1).joined &&
             !ledger->abort_terminal_prepared &&
             (ledger->closed_family_bitmap & bit) == 0 &&
             (ledger->not_constructed_bitmap & bit) == 0 &&
             (ledger->missing_family_bitmap & bit) == 0 &&
             ledger->object_counts[family_index(family)] == 0);
        state->ledger = ledger;
        state->thread_epoch = root_thread.storage_->epoch;
        state->owner_thread = std::this_thread::get_id();
        ledger->mascot_secret_adapter_issued = true;
    }
    try {
        auto result = std::unique_ptr<P1MascotSecretStateAdapter>(
            new P1MascotSecretStateAdapter(std::move(state)));
        result->storage_->scope =
            kpi::mpc::p1_private_state::
                MascotSecretStateScopeFactoryBridge::install(
                    *result, 1, 3, true,
                    kpi::mpc::p1_private_state::MASCOT_SELECTED_PLAYER_ID,
                    kpi::mpc::p1_private_state::
                        MASCOT_SELECTED_FIELD_MODULUS);
        return result;
    } catch (...) {
        poison_dropped_token(ledger, StateFamily::MascotSecrets);
        refuse();
    }
}

std::unique_ptr<P1MascotSecretStateAdapter>
P1CorruptStateRecorderAuthority::take_mascot_secret_state_adapter(
        const P1StateThreadEpochAuthority& root_thread) {
    return P1MascotSecretStateAdapterFactoryBridge::take(
        *this, root_thread);
}

std::unique_ptr<P1EntropyStateAdapter>
P1EntropyStateAdapterFactoryBridge::take(
        P1CorruptStateRecorderAuthority& recorder,
        const P1StateThreadEpochAuthority& root_thread) {
    need(recorder.storage_ != nullptr && recorder.storage_->ledger != nullptr);
    auto ledger = recorder.storage_->ledger;
    std::lock_guard lock(ledger->mutex);
    need_thread(ledger, root_thread.storage_.get());
    std::uint64_t bits = 0;
    for (const auto family : ENTROPY_FAMILIES)
        bits |= family_bit(family);
    need(root_thread.storage_->epoch == 1 &&
         ledger->phase == SourcePhase::RecorderStarted &&
         !ledger->entropy_adapter_issued &&
         !ledger->threads.at(1).joined &&
         !ledger->abort_terminal_prepared &&
         ((ledger->closed_family_bitmap |
           ledger->not_constructed_bitmap |
           ledger->missing_family_bitmap) & bits) == 0);
    for (const auto family : ENTROPY_FAMILIES)
        need(ledger->object_counts[family_index(family)] == 0);
    auto state = std::make_unique<P1EntropyStateAdapter::Storage>();
    state->ledger = ledger;
    state->thread_epoch = root_thread.storage_->epoch;
    ledger->entropy_adapter_issued = true;
    return std::unique_ptr<P1EntropyStateAdapter>(
        new P1EntropyStateAdapter(std::move(state)));
}

std::unique_ptr<P1EntropyStateAdapter>
P1CorruptStateRecorderAuthority::take_entropy_state_adapter(
        const P1StateThreadEpochAuthority& root_thread) {
    return P1EntropyStateAdapterFactoryBridge::take(*this, root_thread);
}

std::unique_ptr<P1PlayerTlsStateAdapter>
P1PlayerTlsStateAdapterFactoryBridge::take(
        P1CorruptStateRecorderAuthority& recorder,
        const P1StateThreadEpochAuthority& root_thread) {
    need(recorder.storage_ != nullptr && recorder.storage_->ledger != nullptr);
    auto ledger = recorder.storage_->ledger;
    std::lock_guard lock(ledger->mutex);
    need_thread(ledger, root_thread.storage_.get());
    const auto player_bit = family_bit(StateFamily::PlayerAllocation);
    const auto tls_bit = family_bit(StateFamily::TlsChannelState);
    need(root_thread.storage_->epoch == 1 &&
         ledger->phase == SourcePhase::RecorderStarted &&
         !ledger->player_tls_adapter_issued &&
         !ledger->threads.at(1).joined &&
         !ledger->abort_terminal_prepared &&
         ((ledger->closed_family_bitmap |
           ledger->not_constructed_bitmap |
           ledger->missing_family_bitmap) &
             (player_bit | tls_bit)) == 0 &&
         ledger->object_counts[family_index(
             StateFamily::PlayerAllocation)] == 0 &&
         ledger->object_counts[family_index(
             StateFamily::TlsChannelState)] == 0);
    auto state = std::make_unique<P1PlayerTlsStateAdapter::Storage>();
    state->ledger = ledger;
    state->thread_epoch = root_thread.storage_->epoch;
    ledger->player_tls_adapter_issued = true;
    return std::unique_ptr<P1PlayerTlsStateAdapter>(
        new P1PlayerTlsStateAdapter(std::move(state)));
}

std::unique_ptr<P1PlayerTlsStateAdapter>
P1CorruptStateRecorderAuthority::take_player_tls_state_adapter(
        const P1StateThreadEpochAuthority& root_thread) {
    return P1PlayerTlsStateAdapterFactoryBridge::take(*this, root_thread);
}

P1StateThreadEpochAuthority P1CorruptStateRecorderAuthority::fork_thread(
        const P1StateThreadEpochAuthority& parent,
        const Digest& source_fork_identity) {
    need(storage_ != nullptr && storage_->ledger != nullptr &&
         nonzero(source_fork_identity));
    auto ledger = storage_->ledger;
    std::lock_guard lock(ledger->mutex);
    need_thread(ledger, parent.storage_.get());
    need(!ledger->threads.at(parent.storage_->epoch).joined &&
         !ledger->abort_terminal_prepared);
    const auto protocol_bit = family_bit(StateFamily::ProtocolSetup);
    need(!ledger->sealed &&
         (ledger->closed_family_bitmap & protocol_bit) == 0 &&
         (ledger->not_constructed_bitmap & protocol_bit) == 0 &&
         (ledger->missing_family_bitmap & protocol_bit) == 0 &&
         ledger->next_thread_epoch <
             std::numeric_limits<std::uint64_t>::max());
    const auto epoch = ledger->next_thread_epoch++;
    need(ledger->threads.emplace(
        epoch, ThreadState{parent.storage_->epoch, source_fork_identity}
    ).second);
    std::vector<unsigned char> payload;
    append_digest(payload, ledger->plan.source_hook_manifest_identity);
    append_digest(payload, source_fork_identity);
    append_record(*ledger, RecordType::ThreadEpoch,
                  StateFamily{},
                  static_cast<std::uint8_t>(TransitionKind::PlayerFork), 0,
                  epoch, 0, parent.storage_->epoch, 0, 0, payload);
    auto token = std::make_unique<P1StateThreadEpochAuthority::Storage>();
    token->ledger = ledger;
    token->epoch = epoch;
    return P1StateThreadEpochAuthority(std::move(token));
}

void P1CorruptStateRecorderAuthority::join_thread(
        P1StateThreadEpochAuthority&& token,
        std::span<const unsigned char> terminal_state) {
    need(storage_ != nullptr && storage_->ledger != nullptr &&
         !terminal_state.empty());
    auto ledger = storage_->ledger;
    std::lock_guard lock(ledger->mutex);
    need_thread(ledger, token.storage_.get());
    auto& thread = ledger->threads.at(token.storage_->epoch);
    need(!thread.joined && !ledger->abort_terminal_prepared &&
         std::none_of(
             ledger->threads.begin(), ledger->threads.end(),
             [&](const auto& entry) {
                 return entry.second.parent_epoch == token.storage_->epoch &&
                        !entry.second.joined;
             }));
    const auto payload = family_payload(
        *ledger, StateFamily::ProtocolSetup, terminal_state);
    append_record(*ledger, RecordType::ThreadEpoch,
                  StateFamily{},
                  static_cast<std::uint8_t>(TransitionKind::ContextValidate),
                  0, token.storage_->epoch, 0, thread.parent_epoch,
                  0, 0, payload);
    thread.joined = true;
    token.storage_->live = false;
    token.storage_.reset();
}

void P1CorruptStateRecorderAuthority::advance_phase(SourcePhase next) {
    need(storage_ != nullptr && storage_->ledger != nullptr);
    auto ledger = storage_->ledger;
    std::lock_guard lock(ledger->mutex);
    const auto current = static_cast<unsigned>(ledger->phase);
    need(!ledger->sealed && !ledger->abort_terminal_prepared &&
         static_cast<unsigned>(next) == current + 1);
    const auto has_family = [&](StateFamily family) {
        return std::any_of(
            ledger->objects.begin(), ledger->objects.end(),
            [family](const auto& entry) {
                return entry.second.family == family;
            });
    };
    if (next == SourcePhase::TlsAndPlayerBound)
        need(ledger->root_player_bound &&
             has_family(StateFamily::TlsChannelState));
    if (next == SourcePhase::ProtocolSetupComplete) {
        for (const auto family : {
                 StateFamily::MpSpdzPrng,
                 StateFamily::CryptoToolsPrng,
                 StateFamily::MascotSecrets,
                 StateFamily::SimplestOtBase,
                 StateFamily::SoftSpokenExtended,
                 StateFamily::OnDemandOtMap,
                 StateFamily::TripleAndInputCache,
                 StateFamily::MacCheck,
                 StateFamily::ContextAndRetry,
                 StateFamily::ProtocolSetup})
            need(has_family(family));
    }
    if (next == SourcePhase::Construction)
        need(has_family(StateFamily::Beaver));
    if (next == SourcePhase::Proof)
        need(has_family(StateFamily::QueryMsmCheckerTemporaries));
    std::vector<unsigned char> payload;
    append_digest(payload, ledger->plan.source_hook_manifest_identity);
    append_u64(payload, current);
    append_u64(payload, static_cast<unsigned>(next));
    append_record(*ledger, RecordType::Phase, StateFamily{}, 0, 0,
                  0, 0, 0, current, static_cast<unsigned>(next), payload);
    ledger->phase = next;
}

P1StateObjectEpochAuthority
P1CorruptStateRecorderAuthority::construct_object_impl(
        StateFamily family, const P1StateThreadEpochAuthority& thread,
        std::span<const unsigned char> snapshot,
        bool allow_test_reserved_family) {
    need(storage_ != nullptr && storage_->ledger != nullptr);
    auto ledger = storage_->ledger;
    auto payload = family_payload(*ledger, family, snapshot);
    std::lock_guard lock(ledger->mutex);
    need_thread(ledger, thread.storage_.get());
    const auto bit = family_bit(family);
    const bool entropy_family_reserved =
        family == StateFamily::MpSpdzPrng ||
        family == StateFamily::CryptoToolsPrng ||
        family == StateFamily::SimplestOtBase;
    need(family != StateFamily::PlayerAllocation &&
         family != StateFamily::ContextAndRetry &&
         family != StateFamily::MascotSecrets &&
         (allow_test_reserved_family ||
          (!entropy_family_reserved &&
           family != StateFamily::TlsChannelState)) &&
         !ledger->abort_terminal_prepared &&
         static_cast<unsigned>(ledger->phase) >=
             static_cast<unsigned>(first_construction_phase(family)) &&
         (ledger->closed_family_bitmap & bit) == 0 &&
         (ledger->not_constructed_bitmap & bit) == 0 &&
         (ledger->missing_family_bitmap & bit) == 0 &&
         ledger->next_object_epoch <
             std::numeric_limits<std::uint64_t>::max());
    const auto epoch = ledger->next_object_epoch++;
    const auto index = family_index(family);
    need(ledger->object_counts[index] <
         std::numeric_limits<std::uint64_t>::max());
    const auto family_ordinal = ++ledger->object_counts[index];
    need(ledger->objects.emplace(epoch, ObjectState{
        .family = family,
        .thread_epoch = thread.storage_->epoch,
        .parent_epoch = 0,
        .family_ordinal = family_ordinal,
        .counter = 0,
        .player = false,
    }).second);
    append_record(*ledger, RecordType::Construct, family, 0, 0,
                  thread.storage_->epoch, epoch, 0, 0, 0, payload);
    advance_hook_event(
        *ledger, family, family_ordinal, HookEventKind::Construct,
        TransitionKind{}, 0, 0);
    auto token = std::make_unique<P1StateObjectEpochAuthority::Storage>();
    token->ledger = ledger;
    token->epoch = epoch;
    return P1StateObjectEpochAuthority(std::move(token));
}

P1StateObjectEpochAuthority P1CorruptStateRecorderAuthority::construct_object(
        StateFamily family, const P1StateThreadEpochAuthority& thread,
        std::span<const unsigned char> snapshot) {
    return construct_object_impl(family, thread, snapshot, false);
}

#ifdef KPB_P1_STATE_CAPSULE_TEST_SETUP
P1StateObjectEpochAuthority
P1CorruptStateRecorderAuthority::test_only_construct_reserved_family(
        StateFamily family, const P1StateThreadEpochAuthority& thread,
        std::span<const unsigned char> snapshot) {
    need(family == StateFamily::MpSpdzPrng ||
         family == StateFamily::CryptoToolsPrng ||
         family == StateFamily::SimplestOtBase ||
         family == StateFamily::TlsChannelState);
    return construct_object_impl(family, thread, snapshot, true);
}
#endif

void P1CorruptStateRecorderAuthority::transition(
        P1StateObjectEpochAuthority& token, TransitionKind kind,
        std::uint64_t counter_before, std::uint64_t counter_after,
        std::span<const unsigned char> snapshot) {
    need(storage_ != nullptr && storage_->ledger != nullptr);
    auto ledger = storage_->ledger;
    std::lock_guard lock(ledger->mutex);
    need_object(ledger, token.storage_.get());
    auto& object = ledger->objects.at(token.storage_->epoch);
    need(object.family != StateFamily::ContextAndRetry &&
         object.family != StateFamily::MascotSecrets &&
         !ledger->abort_terminal_prepared &&
         !object.terminal_snapshot && !object.released &&
         transition_allowed(object.family, kind) &&
         counter_before == object.counter && counter_after > counter_before);
    const auto payload = family_payload(*ledger, object.family, snapshot);
    const auto index = family_index(object.family);
    need(ledger->transition_counts[index] <
         std::numeric_limits<std::uint64_t>::max());
    const HookTransitionDescriptor descriptor{
        .object_ordinal = object.family_ordinal,
        .kind = kind,
        .counter_before = counter_before,
        .counter_after = counter_after,
    };
    const auto sequence = hook_sequence_next(
        object.family, ledger->transition_sequence_identities[index],
        descriptor);
    append_record(*ledger, RecordType::Transition, object.family,
                  static_cast<std::uint8_t>(kind), 0,
                  object.thread_epoch, token.storage_->epoch,
                  object.parent_epoch, counter_before, counter_after, payload);
    advance_hook_event(
        *ledger, object.family, object.family_ordinal,
        HookEventKind::Transition, kind, counter_before, counter_after);
    object.counter = counter_after;
    ++ledger->transition_counts[index];
    ledger->transition_bitmaps[index] |=
        std::uint64_t{1} << (static_cast<unsigned>(kind) - 1);
    ledger->transition_sequence_identities[index] = sequence;
}

void P1CorruptStateRecorderAuthority::terminal_snapshot(
        P1StateObjectEpochAuthority& token,
        std::span<const unsigned char> snapshot) {
    need(storage_ != nullptr && storage_->ledger != nullptr);
    auto ledger = storage_->ledger;
    std::lock_guard lock(ledger->mutex);
    need_object(ledger, token.storage_.get());
    auto& object = ledger->objects.at(token.storage_->epoch);
    need(object.family != StateFamily::ContextAndRetry &&
         object.family != StateFamily::MascotSecrets &&
         !ledger->abort_terminal_prepared &&
         !object.terminal_snapshot && !object.released);
    const auto payload = family_payload(*ledger, object.family, snapshot);
    append_record(*ledger, RecordType::TerminalSnapshot, object.family, 0, 0,
                  object.thread_epoch, token.storage_->epoch,
                  object.parent_epoch, object.counter, object.counter,
                  payload);
    advance_hook_event(
        *ledger, object.family, object.family_ordinal,
        HookEventKind::TerminalSnapshot, TransitionKind{}, object.counter,
        object.counter);
    object.terminal_snapshot = true;
}

void P1CorruptStateRecorderAuthority::release_object(
        P1StateObjectEpochAuthority&& token,
        std::span<const unsigned char> snapshot) {
    need(storage_ != nullptr && storage_->ledger != nullptr);
    auto ledger = storage_->ledger;
    std::lock_guard lock(ledger->mutex);
    need_object(ledger, token.storage_.get());
    auto& object = ledger->objects.at(token.storage_->epoch);
    need(object.family != StateFamily::ContextAndRetry &&
         object.family != StateFamily::MascotSecrets &&
         !ledger->abort_terminal_prepared &&
         !object.terminal_snapshot && !object.released);
    const auto payload = family_payload(*ledger, object.family, snapshot);
    append_record(*ledger, RecordType::Release, object.family, 0, 0,
                  object.thread_epoch, token.storage_->epoch,
                  object.parent_epoch, object.counter, object.counter,
                  payload);
    advance_hook_event(
        *ledger, object.family, object.family_ordinal,
        HookEventKind::Release, TransitionKind{}, object.counter,
        object.counter);
    object.released = true;
    token.storage_->live = false;
    token.storage_.reset();
}

#ifdef KPB_P1_STATE_CAPSULE_TEST_SETUP
P1PlayerAllocationEpochAuthority
P1CorruptStateRecorderAuthority::bind_root_player(
        const P1StateThreadEpochAuthority& thread,
        std::span<const unsigned char> snapshot) {
    need(storage_ != nullptr && storage_->ledger != nullptr);
    auto ledger = storage_->ledger;
    auto payload = family_payload(
        *ledger, StateFamily::PlayerAllocation, snapshot);
    std::lock_guard lock(ledger->mutex);
    need_thread(ledger, thread.storage_.get());
    const auto bit = family_bit(StateFamily::PlayerAllocation);
    need(!ledger->root_player_bound && !ledger->abort_terminal_prepared &&
         (ledger->closed_family_bitmap & bit) == 0 &&
         (ledger->missing_family_bitmap & bit) == 0);
    ledger->root_player_bound = true;
    const auto epoch = ledger->next_object_epoch++;
    const auto index = family_index(StateFamily::PlayerAllocation);
    need(ledger->object_counts[index] <
         std::numeric_limits<std::uint64_t>::max());
    const auto family_ordinal = ++ledger->object_counts[index];
    need(ledger->objects.emplace(epoch, ObjectState{
        .family = StateFamily::PlayerAllocation,
        .thread_epoch = thread.storage_->epoch,
        .parent_epoch = 0,
        .family_ordinal = family_ordinal,
        .counter = 0,
        .player = true,
    }).second);
    append_record(*ledger, RecordType::Construct,
                  StateFamily::PlayerAllocation, 0, 0,
                  thread.storage_->epoch, epoch, 0, 0, 0, payload);
    advance_hook_event(
        *ledger, StateFamily::PlayerAllocation, family_ordinal,
        HookEventKind::Construct, TransitionKind{}, 0, 0);
    auto token =
        std::make_unique<P1PlayerAllocationEpochAuthority::Storage>();
    token->ledger = ledger;
    token->epoch = epoch;
    return P1PlayerAllocationEpochAuthority(std::move(token));
}

P1PlayerAllocationEpochAuthority
P1CorruptStateRecorderAuthority::allocate_player_fork(
        const P1PlayerAllocationEpochAuthority& parent,
        const P1StateThreadEpochAuthority& thread,
        const Digest& source_fork_identity,
        std::span<const unsigned char> snapshot) {
    need(storage_ != nullptr && storage_->ledger != nullptr &&
         nonzero(source_fork_identity));
    auto ledger = storage_->ledger;
    std::vector<unsigned char> combined;
    append_digest(combined, source_fork_identity);
    combined.insert(combined.end(), snapshot.begin(), snapshot.end());
    auto payload = family_payload(
        *ledger, StateFamily::PlayerAllocation, combined);
    std::lock_guard lock(ledger->mutex);
    need_thread(ledger, thread.storage_.get());
    need_player(ledger, parent.storage_.get());
    const auto player_bit = family_bit(StateFamily::PlayerAllocation);
    const auto& parent_state = ledger->objects.at(parent.storage_->epoch);
    need(!parent_state.terminal_snapshot && !parent_state.released &&
         !ledger->abort_terminal_prepared &&
         (ledger->closed_family_bitmap & player_bit) == 0 &&
         (ledger->not_constructed_bitmap & player_bit) == 0 &&
         (ledger->missing_family_bitmap & player_bit) == 0 &&
         ledger->player_fork_identities.insert(source_fork_identity).second);
    const auto epoch = ledger->next_object_epoch++;
    const auto index = family_index(StateFamily::PlayerAllocation);
    need(ledger->object_counts[index] <
         std::numeric_limits<std::uint64_t>::max());
    const auto family_ordinal = ++ledger->object_counts[index];
    need(ledger->objects.emplace(epoch, ObjectState{
        .family = StateFamily::PlayerAllocation,
        .thread_epoch = thread.storage_->epoch,
        .parent_epoch = parent.storage_->epoch,
        .family_ordinal = family_ordinal,
        .counter = 0,
        .player = true,
    }).second);
    append_record(*ledger, RecordType::Construct,
                  StateFamily::PlayerAllocation,
                  static_cast<std::uint8_t>(TransitionKind::PlayerFork), 0,
                  thread.storage_->epoch, epoch, parent.storage_->epoch,
                  0, 0, payload);
    advance_hook_event(
        *ledger, StateFamily::PlayerAllocation, family_ordinal,
        HookEventKind::Construct, TransitionKind{}, 0, 0);
    auto token =
        std::make_unique<P1PlayerAllocationEpochAuthority::Storage>();
    token->ledger = ledger;
    token->epoch = epoch;
    return P1PlayerAllocationEpochAuthority(std::move(token));
}

void P1CorruptStateRecorderAuthority::player_transition(
        P1PlayerAllocationEpochAuthority& token, TransitionKind kind,
        std::uint64_t counter_before, std::uint64_t counter_after,
        std::span<const unsigned char> snapshot) {
    need(storage_ != nullptr && storage_->ledger != nullptr);
    auto ledger = storage_->ledger;
    std::lock_guard lock(ledger->mutex);
    need_player(ledger, token.storage_.get());
    auto& object = ledger->objects.at(token.storage_->epoch);
    need(!ledger->abort_terminal_prepared &&
         !object.terminal_snapshot && !object.released &&
         transition_allowed(StateFamily::PlayerAllocation, kind) &&
         counter_before == object.counter && counter_after > counter_before);
    const auto payload = family_payload(
        *ledger, StateFamily::PlayerAllocation, snapshot);
    const auto index = family_index(StateFamily::PlayerAllocation);
    need(ledger->transition_counts[index] <
         std::numeric_limits<std::uint64_t>::max());
    const HookTransitionDescriptor descriptor{
        .object_ordinal = object.family_ordinal,
        .kind = kind,
        .counter_before = counter_before,
        .counter_after = counter_after,
    };
    const auto sequence = hook_sequence_next(
        StateFamily::PlayerAllocation,
        ledger->transition_sequence_identities[index], descriptor);
    append_record(*ledger, RecordType::Transition,
                  StateFamily::PlayerAllocation,
                  static_cast<std::uint8_t>(kind), 0,
                  object.thread_epoch, token.storage_->epoch,
                  object.parent_epoch, counter_before, counter_after, payload);
    advance_hook_event(
        *ledger, StateFamily::PlayerAllocation, object.family_ordinal,
        HookEventKind::Transition, kind, counter_before, counter_after);
    object.counter = counter_after;
    ++ledger->transition_counts[index];
    ledger->transition_bitmaps[index] |=
        std::uint64_t{1} << (static_cast<unsigned>(kind) - 1);
    ledger->transition_sequence_identities[index] = sequence;
}

void P1CorruptStateRecorderAuthority::player_terminal_snapshot(
        P1PlayerAllocationEpochAuthority& token,
        std::span<const unsigned char> snapshot) {
    need(storage_ != nullptr && storage_->ledger != nullptr);
    auto ledger = storage_->ledger;
    std::lock_guard lock(ledger->mutex);
    need_player(ledger, token.storage_.get());
    auto& object = ledger->objects.at(token.storage_->epoch);
    need(!ledger->abort_terminal_prepared &&
         !object.terminal_snapshot && !object.released);
    const auto payload = family_payload(
        *ledger, StateFamily::PlayerAllocation, snapshot);
    append_record(*ledger, RecordType::TerminalSnapshot,
                  StateFamily::PlayerAllocation, 0, 0,
                  object.thread_epoch, token.storage_->epoch,
                  object.parent_epoch, object.counter, object.counter,
                  payload);
    advance_hook_event(
        *ledger, StateFamily::PlayerAllocation, object.family_ordinal,
        HookEventKind::TerminalSnapshot, TransitionKind{}, object.counter,
        object.counter);
    object.terminal_snapshot = true;
}

void P1CorruptStateRecorderAuthority::release_player(
        P1PlayerAllocationEpochAuthority&& token,
        std::span<const unsigned char> snapshot) {
    need(storage_ != nullptr && storage_->ledger != nullptr);
    auto ledger = storage_->ledger;
    std::lock_guard lock(ledger->mutex);
    need_player(ledger, token.storage_.get());
    auto& object = ledger->objects.at(token.storage_->epoch);
    need(!ledger->abort_terminal_prepared &&
         !object.terminal_snapshot && !object.released);
    const auto payload = family_payload(
        *ledger, StateFamily::PlayerAllocation, snapshot);
    append_record(*ledger, RecordType::Release,
                  StateFamily::PlayerAllocation, 0, 0,
                  object.thread_epoch, token.storage_->epoch,
                  object.parent_epoch, object.counter, object.counter,
                  payload);
    advance_hook_event(
        *ledger, StateFamily::PlayerAllocation, object.family_ordinal,
        HookEventKind::Release, TransitionKind{}, object.counter,
        object.counter);
    object.released = true;
    token.storage_->live = false;
    token.storage_.reset();
}
#endif

void P1CorruptStateRecorderAuthority::close_family_impl(
        StateFamily family, bool allow_test_reserved_family) {
    need(storage_ != nullptr && storage_->ledger != nullptr);
    auto ledger = storage_->ledger;
    std::lock_guard lock(ledger->mutex);
    const auto bit = family_bit(family);
    const bool entropy_family_reserved =
        family == StateFamily::MpSpdzPrng ||
        family == StateFamily::CryptoToolsPrng ||
        family == StateFamily::SimplestOtBase;
    need(family != StateFamily::ContextAndRetry &&
         family != StateFamily::MascotSecrets &&
         (allow_test_reserved_family ||
          (!entropy_family_reserved &&
           family != StateFamily::PlayerAllocation &&
           family != StateFamily::TlsChannelState)) &&
         !ledger->abort_terminal_prepared &&
         (ledger->closed_family_bitmap & bit) == 0 &&
         (ledger->not_constructed_bitmap & bit) == 0 &&
         (ledger->missing_family_bitmap & bit) == 0);
    bool found = false;
    for (const auto& [epoch, object] : ledger->objects) {
        (void)epoch;
        if (object.family != family) continue;
        found = true;
        need(object.terminal_snapshot || object.released);
    }
    need(found);
    const auto index = family_index(family);
    const auto& inventory = ledger->plan.hook_inventory[index];
    need(ledger->object_counts[index] == inventory.exact_object_count &&
         ledger->hook_event_counts[index] == inventory.exact_event_count &&
         ledger->transition_counts[index] ==
             inventory.exact_transition_count &&
         ledger->transition_bitmaps[index] ==
             inventory.required_transition_bitmap &&
         ledger->hook_event_sequence_identities[index] ==
             inventory.expected_event_sequence_identity &&
         ledger->transition_sequence_identities[index] ==
             inventory.expected_transition_sequence_identity);
    std::vector<unsigned char> payload;
    append_digest(payload, ledger->plan.serializer_identities[index]);
    append_digest(payload, inventory.ordered_hook_manifest_identity);
    append_digest(payload, inventory.expected_event_sequence_identity);
    append_digest(payload, inventory.expected_transition_sequence_identity);
    append_u64(payload, ledger->object_counts[index]);
    append_u64(payload, ledger->hook_event_counts[index]);
    append_u64(payload, ledger->transition_counts[index]);
    append_u64(payload, ledger->transition_bitmaps[index]);
    append_u64(payload, ledger->event_counts[index]);
    append_record(*ledger, RecordType::FamilyClosed, family, 0, 0,
                  0, 0, 0, 0, 0, payload);
    ledger->closed_family_bitmap |= bit;
}

void P1CorruptStateRecorderAuthority::close_family(StateFamily family) {
    close_family_impl(family, false);
}

#ifdef KPB_P1_STATE_CAPSULE_TEST_SETUP
void P1CorruptStateRecorderAuthority::test_only_close_reserved_family(
        StateFamily family) {
    need(family == StateFamily::MpSpdzPrng ||
         family == StateFamily::CryptoToolsPrng ||
         family == StateFamily::SimplestOtBase ||
         family == StateFamily::PlayerAllocation ||
         family == StateFamily::TlsChannelState);
    close_family_impl(family, true);
}
#endif

void P1CorruptStateRecorderAuthority::
mark_family_not_constructed_before_abort(StateFamily family) {
    need(storage_ != nullptr && storage_->ledger != nullptr);
    auto ledger = storage_->ledger;
    std::lock_guard lock(ledger->mutex);
    const auto bit = family_bit(family);
    const auto index = family_index(family);
    const bool source_missing =
        ledger->plan.source_family_dispositions[index] ==
            SourceFamilyDisposition::Missing;
    need(!ledger->abort_terminal_prepared &&
         static_cast<unsigned>(ledger->phase) <
             static_cast<unsigned>(
                 not_constructed_deadline_phase(family)) &&
         (ledger->closed_family_bitmap & bit) == 0 &&
         (ledger->not_constructed_bitmap & bit) == 0 &&
         ((ledger->missing_family_bitmap & bit) == 0 || source_missing) &&
         std::none_of(
             ledger->objects.begin(), ledger->objects.end(),
             [family](const auto& entry) {
                 return entry.second.family == family;
             }));
    std::vector<unsigned char> payload;
    append_digest(payload, ledger->plan.serializer_identities[index]);
    append_record(*ledger, RecordType::NotConstructed, family, 0, 0,
                  0, 0, 0, 0, 0, payload);
    ledger->not_constructed_bitmap |= bit;
}

void P1CorruptStateRecorderAuthority::mark_hook_unavailable(
        StateFamily family) noexcept {
    if (!storage_ || !storage_->ledger) return;
    auto ledger = storage_->ledger;
    try {
        std::lock_guard lock(ledger->mutex);
        const auto bit = family_bit(family);
        ledger->poisoned = true;
        ledger->missing_family_bitmap |= bit;
        std::vector<unsigned char> payload;
        append_digest(payload, ledger->plan.serializer_identities[
            family_index(family)]);
        append_record(*ledger, RecordType::Missing, family, 0, 0,
                      0, 0, 0, 0, 0, payload);
    } catch (...) {
        try {
            std::lock_guard lock(ledger->mutex);
            ledger->poisoned = true;
            ledger->io_failed = true;
            ledger->missing_family_bitmap |= family_bit(family);
        } catch (...) {}
    }
}

#ifdef KPB_P1_STATE_CAPSULE_TEST_SETUP
P1AbortTerminalSiteAuthority
P1CorruptStateRecorderAuthority::test_only_mint_abort_terminal_site(
        const Digest& terminal_site_identity, AbortClass abort_class,
        const Digest& exception_type_identity) {
    need(storage_ != nullptr && storage_->ledger != nullptr &&
         nonzero(terminal_site_identity) &&
         nonzero(exception_type_identity));
    auto ledger = storage_->ledger;
    std::lock_guard lock(ledger->mutex);
    const auto found = std::find_if(
        ledger->plan.abort_terminals.begin(),
        ledger->plan.abort_terminals.end(),
        [&](const auto& entry) {
            return entry.terminal_site_identity == terminal_site_identity;
        });
    need(!ledger->sealed && !ledger->abort_terminal_site_issued &&
         !ledger->abort_terminal_prepared &&
         found != ledger->plan.abort_terminals.end() &&
         found->phase == ledger->phase &&
         found->abort_class == abort_class &&
         found->exception_type_identity == exception_type_identity);
    need(storage_->abort_terminal_site_result != nullptr);
    auto token = std::move(storage_->abort_terminal_site_result);
    token->ledger = ledger;
    token->terminal_site_identity = terminal_site_identity;
    token->exception_type_identity = exception_type_identity;
    token->phase = ledger->phase;
    token->abort_class = abort_class;
    ledger->abort_terminal_site_issued = true;
    return P1AbortTerminalSiteAuthority(std::move(token));
}
#endif

P1AbortTerminalAuthority
P1CorruptStateRecorderAuthority::prepare_abort_terminal(
        P1AbortTerminalSiteAuthority&& terminal_site) {
    need(terminal_site.storage_ != nullptr);
    auto claimed = std::move(terminal_site.storage_);
    auto claimed_ledger = claimed->ledger;
    const auto terminal_site_identity = claimed->terminal_site_identity;
    const auto exception_type_identity = claimed->exception_type_identity;
    const auto abort_class = claimed->abort_class;
    try {
        need(storage_ != nullptr && storage_->ledger != nullptr &&
             storage_->abort_terminal_result != nullptr &&
             claimed->live && claimed_ledger == storage_->ledger &&
             nonzero(terminal_site_identity) &&
             nonzero(exception_type_identity) &&
             static_cast<unsigned>(abort_class) >=
                 static_cast<unsigned>(AbortClass::Transport) &&
             static_cast<unsigned>(abort_class) <=
                 static_cast<unsigned>(AbortClass::Resource));
        auto ledger = storage_->ledger;
        std::lock_guard lock(ledger->mutex);
        need(!ledger->sealed && !ledger->abort_terminal_prepared &&
             claimed->phase == ledger->phase &&
             std::all_of(
                 ledger->threads.begin(), ledger->threads.end(),
                 [](const auto& entry) { return entry.second.joined; }));
        const auto found = std::find_if(
            ledger->plan.abort_terminals.begin(),
            ledger->plan.abort_terminals.end(),
            [&](const auto& entry) {
                return entry.terminal_site_identity ==
                    terminal_site_identity;
            });
        need(found != ledger->plan.abort_terminals.end() &&
             found->phase == ledger->phase &&
             found->abort_class == abort_class &&
             found->exception_type_identity == exception_type_identity);
        std::uint64_t prefix_bitmap = 0;
        for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index) {
        const auto family = static_cast<StateFamily>(index + 1);
        const auto bit = family_bit(family);
        const auto& expected = found->families[index];
        need(ledger->object_counts[index] == expected.exact_object_count &&
             ledger->hook_event_counts[index] == expected.exact_event_count &&
             ledger->transition_counts[index] ==
                 expected.exact_transition_count &&
             ledger->transition_bitmaps[index] ==
                 expected.required_transition_bitmap &&
             ledger->hook_event_sequence_identities[index] ==
                 expected.expected_event_sequence_identity &&
             ledger->transition_sequence_identities[index] ==
                 expected.expected_transition_sequence_identity);
        if (expected.disposition == AbortFamilyDisposition::Closed) {
            need((ledger->closed_family_bitmap & bit) != 0 &&
                 (ledger->not_constructed_bitmap & bit) == 0);
        } else if (expected.disposition ==
                       AbortFamilyDisposition::NotConstructed) {
            need((ledger->not_constructed_bitmap & bit) != 0 &&
                 (ledger->closed_family_bitmap & bit) == 0);
        } else {
            need(expected.disposition ==
                     AbortFamilyDisposition::TerminalPrefix &&
                 (ledger->closed_family_bitmap & bit) == 0 &&
                 (ledger->not_constructed_bitmap & bit) == 0);
            for (const auto& [epoch, object] : ledger->objects) {
                (void)epoch;
                if (object.family == family)
                    need(object.terminal_snapshot || object.released);
            }
            prefix_bitmap |= bit;
        }
        }
        for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index) {
            const auto bit = std::uint64_t{1} << index;
            if ((prefix_bitmap & bit) == 0) continue;
            const auto family = static_cast<StateFamily>(index + 1);
            const auto& expected = found->families[index];
            std::vector<unsigned char> prefix;
            append_digest(prefix, terminal_site_identity);
            append_digest(
                prefix, ledger->plan.abort_terminal_manifest_identity);
            append_digest(prefix, expected.expected_event_sequence_identity);
            append_digest(
                prefix, expected.expected_transition_sequence_identity);
            append_u64(prefix, expected.exact_object_count);
            append_u64(prefix, expected.exact_event_count);
            append_u64(prefix, expected.exact_transition_count);
            append_u64(prefix, expected.required_transition_bitmap);
            append_record(
                *ledger, RecordType::AbortPrefixClosed, family, 0,
                static_cast<std::uint8_t>(abort_class), 0, 0, 0, 0, 0,
                prefix);
        }
        std::vector<unsigned char> payload;
        append_digest(payload, ledger->plan.source_hook_manifest_identity);
        append_digest(payload, ledger->plan.abort_terminal_manifest_identity);
        append_digest(payload, terminal_site_identity);
        append_digest(payload, exception_type_identity);
        append_u64(payload, prefix_bitmap);
        append_u64(payload, static_cast<unsigned>(ledger->phase));
        append_u64(payload, static_cast<unsigned>(abort_class));
        append_record(*ledger, RecordType::AbortTerminal, StateFamily{}, 0,
                      static_cast<std::uint8_t>(abort_class), 0, 0, 0,
                      static_cast<unsigned>(ledger->phase),
                      static_cast<unsigned>(ledger->phase), payload);
        ledger->abort_terminal_prepared = true;
        ledger->abort_prefix_bitmap = prefix_bitmap;
        ledger->abort_terminal_site_identity = terminal_site_identity;
        ledger->abort_class = abort_class;
        ledger->abort_exception_type_identity = exception_type_identity;
        auto token = std::move(storage_->abort_terminal_result);
        token->ledger = ledger;
        token->terminal_site_identity = terminal_site_identity;
        token->phase = ledger->phase;
        token->abort_class = abort_class;
        token->exception_type_identity = exception_type_identity;
        claimed->live = false;
        return P1AbortTerminalAuthority(std::move(token));
    } catch (...) {
        claimed->live = false;
        poison_dropped_token(claimed_ledger);
        throw;
    }
}

P1CorruptStateCapsuleAuthority
P1CorruptStateRecorderAuthority::close_noexcept(bool aborted) && noexcept {
    if (!storage_ || !storage_->ledger || !storage_->close_result)
        return P1CorruptStateCapsuleAuthority(nullptr);
    auto result = std::move(storage_->close_result);
    auto ledger = storage_->ledger;
    result->aborted = aborted;
    result->terminal_phase = ledger->phase;
    result->abort_class = ledger->abort_class;
    bool terminal_written = false;
    try {
        std::lock_guard lock(ledger->mutex);
        need(!ledger->sealed);
        for (const auto& [epoch, object] : ledger->objects) {
            (void)epoch;
            if (!object.terminal_snapshot && !object.released)
                ledger->missing_family_bitmap |= family_bit(object.family);
        }
        const auto covered = ledger->closed_family_bitmap |
                             ledger->not_constructed_bitmap |
                             ledger->abort_prefix_bitmap;
        const auto uncovered = FULL_FAMILY_BITMAP & ~covered;
        ledger->missing_family_bitmap |= uncovered;
        if (!ledger->root_thread_taken || !ledger->root_player_bound) {
            ledger->missing_family_bitmap |=
                family_bit(StateFamily::PlayerAllocation) |
                family_bit(StateFamily::ProtocolSetup);
        }
        if (ledger->player_tls_adapter_issued &&
            !ledger->player_tls_adapter_finalized)
            ledger->missing_family_bitmap |=
                family_bit(StateFamily::PlayerAllocation) |
                family_bit(StateFamily::TlsChannelState);
        if (ledger->mascot_secret_adapter_issued &&
            !ledger->mascot_secret_adapter_finalized)
            ledger->missing_family_bitmap |=
                family_bit(StateFamily::MascotSecrets);
        if (!aborted && ledger->not_constructed_bitmap != 0)
            ledger->missing_family_bitmap |= ledger->not_constructed_bitmap;
        const bool all_threads_joined = std::all_of(
            ledger->threads.begin(), ledger->threads.end(),
            [](const auto& entry) { return entry.second.joined; });
        if (!all_threads_joined)
            ledger->missing_family_bitmap |=
                family_bit(StateFamily::ProtocolSetup);
        const bool structurally_complete =
            !ledger->poisoned && !ledger->io_failed &&
            ledger->missing_family_bitmap == 0 &&
            all_threads_joined &&
            ((aborted && ledger->abort_terminal_prepared &&
              ledger->abort_class != AbortClass{} &&
              nonzero(ledger->abort_exception_type_identity)) ||
             (!aborted && !ledger->abort_terminal_prepared &&
              ledger->phase == SourcePhase::TerminalEgress)) &&
            ((aborted && covered == FULL_FAMILY_BITMAP) ||
             (!aborted && ledger->closed_family_bitmap ==
                              FULL_FAMILY_BITMAP &&
              ledger->not_constructed_bitmap == 0));

        // Preserve the already-written prefix if an earlier hook observed an
        // I/O failure. Do not turn a failed terminal append into archive loss.
        if (!ledger->io_failed && ledger->fd >= 0) {
            for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index) {
                const auto bit = std::uint64_t{1} << index;
                if ((ledger->missing_family_bitmap & bit) == 0) continue;
                const auto family = static_cast<StateFamily>(index + 1);
                std::vector<unsigned char> payload;
                append_digest(payload, ledger->plan.serializer_identities[
                    index]);
                append_record(*ledger, RecordType::Missing, family, 0, 0,
                              0, 0, 0, 0, 0, payload);
            }
            std::vector<unsigned char> terminal;
            append_digest(terminal, ledger->plan.source_hook_manifest_identity);
            append_u64(terminal, ledger->closed_family_bitmap);
            append_u64(terminal, ledger->not_constructed_bitmap);
            append_u64(terminal, ledger->abort_prefix_bitmap);
            append_u64(terminal, ledger->missing_family_bitmap);
            append_u64(terminal, structurally_complete ? 1 : 0);
            append_u64(terminal, ledger->sequence);
            append_u64(terminal, static_cast<unsigned>(ledger->phase));
            append_u64(terminal, static_cast<unsigned>(ledger->abort_class));
            append_digest(terminal, ledger->abort_terminal_site_identity);
            append_digest(terminal, ledger->abort_exception_type_identity);
            for (const auto count : ledger->event_counts)
                append_u64(terminal, count);
            append_record(*ledger, RecordType::Terminal, StateFamily{}, 0,
                          aborted ? 2 : 1, 0, 0, 0, 0, 0, terminal);
            terminal_written = true;
        }
        ledger->sealed = true;
        result->manifest_structurally_complete = structurally_complete && terminal_written;
        result->sequence = ledger->sequence;
        result->archive_bytes = ledger->offset;
        result->missing_family_bitmap = ledger->missing_family_bitmap;
        result->closed_family_bitmap = ledger->closed_family_bitmap;
        result->not_constructed_bitmap = ledger->not_constructed_bitmap;
        result->abort_prefix_bitmap = ledger->abort_prefix_bitmap;
        result->abort_terminal_site_identity =
            ledger->abort_terminal_site_identity;
        result->event_counts = ledger->event_counts;
    } catch (...) {
        // No allocation or exception may prevent the recorder from being
        // burned. Keep the exact prefix descriptor for observer quarantine.
        try {
            std::lock_guard lock(ledger->mutex);
            ledger->poisoned = true;
            ledger->io_failed = true;
            ledger->missing_family_bitmap |= FULL_FAMILY_BITMAP;
            ledger->sealed = true;
            result->manifest_structurally_complete = false;
            result->sequence = ledger->sequence;
            result->archive_bytes = ledger->offset;
            result->missing_family_bitmap = ledger->missing_family_bitmap;
            result->closed_family_bitmap = ledger->closed_family_bitmap;
            result->not_constructed_bitmap =
                ledger->not_constructed_bitmap;
            result->abort_prefix_bitmap = ledger->abort_prefix_bitmap;
            result->abort_terminal_site_identity =
                ledger->abort_terminal_site_identity;
            result->event_counts = ledger->event_counts;
        } catch (...) {
            result->manifest_structurally_complete = false;
            result->missing_family_bitmap = FULL_FAMILY_BITMAP;
        }
    }

    int read_only = -1;
    try {
        struct stat before{};
        need(!ledger->test_fail_fsync && ledger->fd >= 0 &&
             ::fsync(ledger->fd) == 0 &&
             ::fstat(ledger->fd, &before) == 0);
        need_anonymous_disk_file(before);
        need(static_cast<std::uint64_t>(before.st_dev) == ledger->device &&
             static_cast<std::uint64_t>(before.st_ino) == ledger->inode &&
             static_cast<std::uint64_t>(before.st_size) ==
                 result->archive_bytes);
        need(!ledger->test_fail_hash);
        const auto writable_hash = hash_fd(
            ledger->fd, result->archive_bytes);
        need(!ledger->test_fail_reopen);
        read_only = reopen_read_only(ledger->fd);
        struct stat reopened{};
        need(::fstat(read_only, &reopened) == 0);
        need_anonymous_disk_file(reopened);
        need(reopened.st_dev == before.st_dev &&
             reopened.st_ino == before.st_ino &&
             reopened.st_size == before.st_size &&
             hash_fd(read_only, result->archive_bytes) == writable_hash);
        close_fd(ledger->fd);
        struct stat after{};
        need(::fstat(read_only, &after) == 0 &&
             after.st_dev == before.st_dev &&
             after.st_ino == before.st_ino &&
             after.st_size == before.st_size &&
             hash_fd(read_only, result->archive_bytes) == writable_hash);
        result->fd = std::exchange(read_only, -1);
        result->device = static_cast<std::uint64_t>(after.st_dev);
        result->inode = static_cast<std::uint64_t>(after.st_ino);
        result->archive_sha256 = writable_hash;
        result->read_only = true;
        result->anonymous_disk_backed = true;
        result->writer_closed = true;
        result->descriptor_retained = true;
    } catch (...) {
        result->manifest_structurally_complete = false;
        // Prefer the still-open original writer: it is the only guaranteed
        // handle to a partially written anonymous inode. If the writer had
        // already closed, retain the verified/reopened reader instead.
        if (ledger->fd >= 0) {
            close_fd(read_only);
            result->fd = std::exchange(ledger->fd, -1);
            result->read_only = false;
            result->writer_closed = false;
        } else if (read_only >= 0) {
            result->fd = std::exchange(read_only, -1);
            result->read_only = true;
            result->writer_closed = true;
        }
        if (result->fd >= 0) {
            struct stat retained{};
            if (::fstat(result->fd, &retained) == 0 &&
                S_ISREG(retained.st_mode) && retained.st_nlink == 0) {
                result->descriptor_retained = true;
                result->anonymous_disk_backed = true;
                result->device = static_cast<std::uint64_t>(retained.st_dev);
                result->inode = static_cast<std::uint64_t>(retained.st_ino);
                if (retained.st_size >= 0) {
                    result->archive_bytes =
                        static_cast<std::uint64_t>(retained.st_size);
                    try {
                        need(!ledger->test_fail_hash);
                        result->archive_sha256 = hash_fd(
                            result->fd, result->archive_bytes);
                    } catch (...) {}
                }
            }
        }
    }
    storage_.reset();
    return P1CorruptStateCapsuleAuthority(std::move(result));
}

P1CorruptStateCapsuleAuthority
P1CorruptStateRecorderAuthority::close_success_noexcept() && noexcept {
    return std::move(*this).close_noexcept(false);
}

P1CorruptStateCapsuleAuthority
P1CorruptStateRecorderAuthority::close_abort_noexcept(
        P1AbortTerminalAuthority&& terminal) && noexcept {
    bool valid = false;
    if (storage_ && storage_->ledger && terminal.storage_) {
        try {
            std::lock_guard lock(storage_->ledger->mutex);
            valid = terminal.storage_->live &&
                terminal.storage_->ledger == storage_->ledger &&
                storage_->ledger->abort_terminal_prepared &&
                terminal.storage_->terminal_site_identity ==
                    storage_->ledger->abort_terminal_site_identity &&
                terminal.storage_->phase == storage_->ledger->phase &&
                terminal.storage_->abort_class ==
                    storage_->ledger->abort_class &&
                terminal.storage_->exception_type_identity ==
                    storage_->ledger->abort_exception_type_identity;
            if (valid) terminal.storage_->live = false;
        } catch (...) {}
    }
    if (!valid)
        mark_hook_unavailable(StateFamily::ContextAndRetry);
    terminal.storage_.reset();
    return std::move(*this).close_noexcept(true);
}

P1CorruptStateCapsuleAuthority
P1CorruptStateRecorderAuthority::close_unavailable_abort_noexcept(
        AbortClass abort_class,
        const Digest& exception_type_identity) && noexcept {
    if (storage_ && storage_->ledger) {
        try {
            std::lock_guard lock(storage_->ledger->mutex);
            storage_->ledger->abort_class = abort_class;
            storage_->ledger->abort_exception_type_identity =
                exception_type_identity;
            storage_->ledger->poisoned = true;
            storage_->ledger->missing_family_bitmap |=
                family_bit(StateFamily::ContextAndRetry);
        } catch (...) {}
        mark_hook_unavailable(StateFamily::ContextAndRetry);
    }
    return std::move(*this).close_noexcept(true);
}

#ifdef KPB_P1_STATE_CAPSULE_TEST_SETUP
void P1CorruptStateRecorderAuthority::test_only_force_fd_substitution() {
    need(storage_ != nullptr && storage_->ledger != nullptr);
    auto ledger = storage_->ledger;
    std::lock_guard lock(ledger->mutex);
    // Simulate a TOCTOU/descriptor-identity mismatch while retaining the exact
    // original inode so unavailable close can quarantine it.
    ++ledger->inode;
}

void P1CorruptStateRecorderAuthority::test_only_force_write_failure() {
    need(storage_ != nullptr && storage_->ledger != nullptr);
    auto ledger = storage_->ledger;
    std::lock_guard lock(ledger->mutex);
    ledger->io_failed = true;
}

void P1CorruptStateRecorderAuthority::test_only_force_fsync_failure() {
    need(storage_ != nullptr && storage_->ledger != nullptr);
    std::lock_guard lock(storage_->ledger->mutex);
    storage_->ledger->test_fail_fsync = true;
}

void P1CorruptStateRecorderAuthority::test_only_force_reopen_failure() {
    need(storage_ != nullptr && storage_->ledger != nullptr);
    std::lock_guard lock(storage_->ledger->mutex);
    storage_->ledger->test_fail_reopen = true;
}

void P1CorruptStateRecorderAuthority::test_only_force_hash_failure() {
    need(storage_ != nullptr && storage_->ledger != nullptr);
    std::lock_guard lock(storage_->ledger->mutex);
    storage_->ledger->test_fail_hash = true;
}

void P1CorruptStateRecorderAuthority::
test_only_force_abort_token_preallocation_loss() {
    need(storage_ != nullptr && storage_->abort_terminal_result != nullptr);
    storage_->abort_terminal_result.reset();
}
#endif

P1CorruptStateCapsuleAuthority::P1CorruptStateCapsuleAuthority(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {}

std::unique_ptr<P1CorruptStateCapsuleChildDispositionResidual::Storage>
P1CorruptStateCapsuleAuthority::preallocate_child_disposition(
        const StaticStateCapsulePlan& plan) {
    auto result = std::make_unique<
        P1CorruptStateCapsuleChildDispositionResidual::Storage>();
    result->plan = plan;
    return result;
}

P1CorruptStateCapsuleAuthority::P1CorruptStateCapsuleAuthority(
        P1CorruptStateCapsuleAuthority&&) noexcept = default;
P1CorruptStateCapsuleAuthority::~P1CorruptStateCapsuleAuthority() = default;

P1CorruptStateCapsuleChildDispositionResidual::
P1CorruptStateCapsuleChildDispositionResidual(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {}
P1CorruptStateCapsuleChildDispositionResidual::
P1CorruptStateCapsuleChildDispositionResidual(
        P1CorruptStateCapsuleChildDispositionResidual&&) noexcept = default;
P1CorruptStateCapsuleChildDispositionResidual::~
P1CorruptStateCapsuleChildDispositionResidual() {
    if (storage_) close_fd(storage_->fd);
}

P1CorruptStateCapsuleChildDispositionResidual
P1CorruptStateCapsuleAuthority::consume_for_child_disposition() && {
    need(storage_ != nullptr && storage_->child_disposition_result != nullptr);
    auto result = std::move(storage_->child_disposition_result);
    need(result->plan == storage_->plan);
    result->fd = std::exchange(storage_->fd, -1);
    result->device = storage_->device;
    result->inode = storage_->inode;
    result->manifest_structurally_complete =
        storage_->manifest_structurally_complete;
    // Structural agreement with the caller-supplied hook manifest is not a
    // complete corrupt-P1 process view.  Until the source-owned manifest,
    // every pinned serializer, and deterministic parent replay are selected,
    // every child disposition remains explicitly unavailable.
    result->unavailable = true;
    result->aborted = storage_->aborted;
    result->read_only = storage_->read_only;
    result->anonymous_disk_backed = storage_->anonymous_disk_backed;
    result->writer_closed = storage_->writer_closed;
    result->descriptor_retained = storage_->descriptor_retained;
    result->terminal_phase = storage_->terminal_phase;
    result->abort_class = storage_->abort_class;
    result->sequence = storage_->sequence;
    result->archive_bytes = storage_->archive_bytes;
    result->missing_family_bitmap = storage_->missing_family_bitmap;
    result->closed_family_bitmap = storage_->closed_family_bitmap;
    result->not_constructed_bitmap = storage_->not_constructed_bitmap;
    result->abort_prefix_bitmap = storage_->abort_prefix_bitmap;
    result->abort_terminal_site_identity =
        storage_->abort_terminal_site_identity;
    result->event_counts = storage_->event_counts;
    result->archive_sha256 = storage_->archive_sha256;
    storage_.reset();
    return P1CorruptStateCapsuleChildDispositionResidual(std::move(result));
}

#ifdef KPB_P1_STATE_CAPSULE_TEST_SETUP
P1CorruptStateCapsuleAuthority::TestOnlySummary
P1CorruptStateCapsuleAuthority::test_only_summary() const {
    if (!storage_) return {};
    return {
        .plan = storage_->plan,
        .manifest_structurally_complete = storage_->manifest_structurally_complete,
        .aborted = storage_->aborted,
        .read_only = storage_->read_only,
        .anonymous_disk_backed = storage_->anonymous_disk_backed,
        .writer_closed = storage_->writer_closed,
        .descriptor_retained = storage_->descriptor_retained,
        .terminal_phase = storage_->terminal_phase,
        .abort_class = storage_->abort_class,
        .sequence = storage_->sequence,
        .archive_bytes = storage_->archive_bytes,
        .missing_family_bitmap = storage_->missing_family_bitmap,
        .closed_family_bitmap = storage_->closed_family_bitmap,
        .not_constructed_bitmap = storage_->not_constructed_bitmap,
        .abort_prefix_bitmap = storage_->abort_prefix_bitmap,
        .abort_terminal_site_identity =
            storage_->abort_terminal_site_identity,
        .event_counts = storage_->event_counts,
        .archive_sha256 = storage_->archive_sha256,
    };
}

std::vector<unsigned char>
P1CorruptStateCapsuleAuthority::test_only_read_all() const {
    need(storage_ != nullptr && storage_->fd >= 0 && storage_->read_only &&
         storage_->archive_bytes <=
             static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()));
    std::vector<unsigned char> result(
        static_cast<std::size_t>(storage_->archive_bytes));
    std::size_t offset = 0;
    while (offset < result.size()) {
        ssize_t count;
        do {
            count = ::pread(storage_->fd, result.data() + offset,
                            result.size() - offset,
                            static_cast<off_t>(offset));
        } while (count < 0 && errno == EINTR);
        need(count > 0);
        offset += static_cast<std::size_t>(count);
    }
    need(hash(result) == storage_->archive_sha256);
    return result;
}
#endif

} // namespace kpb::measurement::p1_state_capsule

namespace kpi::mpc::financial::registered_driver {

using namespace kpb::measurement::p1_state_capsule;

P1CorruptStateRecorderAuthority
P1StateArchiveWriterAdoptionConsumerBridge::begin(
        P1CorruptStateCapsulePlanAuthority&& plan,
        P1StateArchiveWriterAdoptionAuthority&& adoption) {
    // Claim both rvalues before inspecting either. A stale, substituted, or
    // replayed plan therefore burns the authenticated writer as well, and a
    // stale writer burns the plan. No failed join can be retried with the
    // surviving half.
    StaticStateCapsulePlan selected_plan{};
    const bool plan_live = plan.storage_ != nullptr;
    if (plan_live) {
        selected_plan = std::move(plan.storage_->plan);
        plan.storage_.reset();
    }
    auto* adoption_storage = adoption.storage_.get();
    const bool adoption_live = adoption_storage != nullptr &&
        std::exchange(adoption_storage->live, false);
    try {
    need(plan_live && adoption_live && adoption_storage->writer >= 0);
    validate_plan(selected_plan);
    need(adoption_storage->round == selected_plan.round &&
         selected_plan.role == 1 &&
         adoption_storage->parent_pid > 0 &&
         adoption_storage->child_pid > 0 &&
         adoption_storage->parent_pid != adoption_storage->child_pid &&
         nonzero(adoption_storage->reservation_identity) &&
         nonzero(adoption_storage->activation_identity) &&
         adoption_storage->reservation_identity ==
             selected_plan.topology_reservation_identity &&
         adoption_storage->nlink == 0 && adoption_storage->size == 0);

    const auto validate_writer = [&] {
        struct stat current{};
        const int flags = ::fcntl(adoption_storage->writer, F_GETFL);
        const int descriptor_flags =
            ::fcntl(adoption_storage->writer, F_GETFD);
        need(flags >= 0 && descriptor_flags >= 0 &&
             (flags & O_ACCMODE) == O_WRONLY &&
             (flags & O_APPEND) == 0 &&
             (descriptor_flags & FD_CLOEXEC) != 0 &&
             ::fstat(adoption_storage->writer, &current) == 0);
        need_anonymous_disk_file(current);
        need(static_cast<std::uint64_t>(current.st_dev) ==
                 adoption_storage->device &&
             static_cast<std::uint64_t>(current.st_ino) ==
                 adoption_storage->inode &&
             static_cast<std::uint32_t>(current.st_mode) ==
                 adoption_storage->mode &&
             static_cast<std::uint64_t>(current.st_nlink) ==
                 adoption_storage->nlink &&
             static_cast<std::uint64_t>(current.st_size) ==
                 adoption_storage->size &&
             ::lseek(adoption_storage->writer, 0, SEEK_CUR) == 0);
        return current;
    };
    (void)validate_writer();

    // Allocation failure is fail-closed after the paired claim and burns both
    // halves; it cannot leave a reusable plan or writer.
    auto close_result =
        std::make_unique<P1CorruptStateCapsuleAuthority::Storage>();
    auto child_disposition_result =
        P1CorruptStateCapsuleAuthority::preallocate_child_disposition(
            selected_plan);
    auto abort_terminal_site_result =
        std::make_unique<P1AbortTerminalSiteAuthority::Storage>();
    auto abort_terminal_result =
        std::make_unique<P1AbortTerminalAuthority::Storage>();
    auto recorder =
        std::make_unique<P1CorruptStateRecorderAuthority::Storage>();
    auto ledger = std::make_shared<Ledger>();
    close_result->plan = selected_plan;
    close_result->child_disposition_result =
        std::move(child_disposition_result);
    ledger->plan = selected_plan;
    for (unsigned index = 0; index < STATE_FAMILY_COUNT; ++index) {
        ledger->hook_event_sequence_identities[index] =
            hook_event_sequence_initial(
                static_cast<StateFamily>(index + 1));
        ledger->transition_sequence_identities[index] =
            hook_sequence_initial(static_cast<StateFamily>(index + 1));
        if (ledger->plan.source_family_dispositions[index] ==
                SourceFamilyDisposition::Missing)
            ledger->missing_family_bitmap |= std::uint64_t{1} << index;
    }

    // Re-stat immediately before the no-throw exchange. No allocation follows
    // this point, and no state byte can precede the exact writer installation.
    const auto current = validate_writer();
    ledger->fd = adoption_storage->writer;
    ledger->device = static_cast<std::uint64_t>(current.st_dev);
    ledger->inode = static_cast<std::uint64_t>(current.st_ino);
    adoption_storage->writer = -1;
    recorder->ledger = std::move(ledger);
    recorder->close_result = std::move(close_result);
    recorder->abort_terminal_site_result =
        std::move(abort_terminal_site_result);
    recorder->abort_terminal_result = std::move(abort_terminal_result);
    return P1CorruptStateRecorderAuthority(std::move(recorder));
    } catch (...) {
        if (adoption_storage != nullptr) close_fd(adoption_storage->writer);
        throw;
    }
}

#ifdef KPB_P1_STATE_CAPSULE_TEST_SETUP
P1CorruptStateCapsulePlanAuthority
P1StateArchiveWriterAdoptionConsumerBridge::test_only_bind_plan(
        StaticStateCapsulePlan plan,
        const P1StateArchiveWriterAdoptionAuthority& adoption,
        bool wrong_round, bool wrong_reservation) {
    need(!(wrong_round && wrong_reservation));
    need(adoption.storage_ != nullptr && adoption.storage_->live &&
         adoption.storage_->writer >= 0 &&
         (adoption.storage_->round == 1 || adoption.storage_->round == 2) &&
         nonzero(adoption.storage_->reservation_identity));
    plan.role = 1;
    plan.round = wrong_round
        ? (adoption.storage_->round == 1 ? 2 : 1)
        : adoption.storage_->round;
    plan.topology_reservation_identity =
        adoption.storage_->reservation_identity;
    if (wrong_reservation) {
        plan.topology_reservation_identity[0] ^= 0x5a;
        need(nonzero(plan.topology_reservation_identity) &&
             plan.topology_reservation_identity !=
                 adoption.storage_->reservation_identity);
    }
    return P1CorruptStateCapsulePlanAuthority::test_only_mint(
        std::move(plan));
}
#endif

} // namespace kpi::mpc::financial::registered_driver
