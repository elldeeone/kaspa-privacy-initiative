#include "privacy_p1_mascot_abort_terminal_manifest_authority.hpp"

#include <openssl/crypto.h>
#include <openssl/sha.h>

#include <limits>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace kpb::measurement::p1_state {
namespace {

using AbortClass = kpi::mpc::p1_private_state::MascotSecretAbortClass;
using AbortKind = kpi::mpc::p1_private_state::MascotSecretAbortEventKind;
using Branch = kpi::mpc::p1_private_state::MascotCacheBranch;
using Prefix = p1_state_capsule::AbortFamilyHookInventory;

constexpr std::uint64_t ROOT = std::numeric_limits<std::uint64_t>::max();

struct Descriptor final {
    AbortKind kind{};
    bool source_worker{};
    std::uint64_t worker_ordinal{ROOT};
};

using Variant = std::vector<Descriptor>;
using Variants = std::vector<Variant>;

[[noreturn]] void refuse() {
    throw std::runtime_error("P1-MASCOT-abort-manifest-refused");
}
void need(bool value) { if (!value) refuse(); }

void cleanse(std::vector<unsigned char>& value) noexcept {
    if (!value.empty()) OPENSSL_cleanse(value.data(), value.size());
    value.clear();
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

void append_text(
        std::vector<unsigned char>& output, std::string_view value) {
    append_bytes(output, std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
}

void append_digest(std::vector<unsigned char>& output, const Digest& value) {
    append_bytes(output, value);
}

void append_prefix(std::vector<unsigned char>& output, const Prefix& value) {
    append_u64(output, static_cast<unsigned>(value.disposition));
    append_u64(output, value.exact_object_count);
    append_u64(output, value.exact_event_count);
    append_u64(output, value.exact_transition_count);
    append_u64(output, value.required_transition_bitmap);
    append_digest(output, value.expected_event_sequence_identity);
    append_digest(output, value.expected_transition_sequence_identity);
}

Digest hash(std::vector<unsigned char>& bytes) {
    Digest result{};
    const bool retained = ::SHA256(
        bytes.data(), bytes.size(), result.data()) != nullptr;
    cleanse(bytes);
    need(retained && result != Digest{});
    return result;
}

Descriptor descriptor(
        AbortKind kind, bool source_worker,
        std::uint64_t worker_ordinal = ROOT) {
    return {kind, source_worker, worker_ordinal};
}

Variants ot_variants() {
    const auto prefix = [](std::uint64_t failed) {
        return Variant{
            descriptor(AbortKind::CacheUnlink, true, failed),
            descriptor(AbortKind::WorkerFailurePublished, true, failed),
            descriptor(AbortKind::WorkerTerminal, true, failed),
            descriptor(AbortKind::RootFailureObserved, false, failed),
        };
    };
    const auto suffix = [](Variant value) {
        value.push_back(descriptor(AbortKind::Teardown, false));
        value.push_back(descriptor(AbortKind::AbortTerminal, false));
        return value;
    };
    auto failed_zero_a = prefix(0);
    failed_zero_a.push_back(descriptor(AbortKind::WorkerTerminal, true, 1));
    failed_zero_a.push_back(descriptor(AbortKind::WorkerJoined, false, 0));
    failed_zero_a.push_back(descriptor(AbortKind::WorkerJoined, false, 1));
    auto failed_zero_b = prefix(0);
    failed_zero_b.push_back(descriptor(AbortKind::WorkerJoined, false, 0));
    failed_zero_b.push_back(descriptor(AbortKind::WorkerTerminal, true, 1));
    failed_zero_b.push_back(descriptor(AbortKind::WorkerJoined, false, 1));
    auto failed_one = prefix(1);
    failed_one.push_back(descriptor(AbortKind::WorkerTerminal, true, 0));
    failed_one.push_back(descriptor(AbortKind::WorkerJoined, false, 0));
    failed_one.push_back(descriptor(AbortKind::WorkerJoined, false, 1));
    return {
        suffix(std::move(failed_zero_a)),
        suffix(std::move(failed_zero_b)),
        suffix(std::move(failed_one)),
    };
}

Variants mac_variants() {
    const auto make = [](std::array<unsigned, 4> order) {
        Variant result{descriptor(AbortKind::CacheUnlink, false)};
        for (const auto edge : order) {
            const bool terminal = edge < 2;
            result.push_back(descriptor(
                terminal ? AbortKind::WorkerTerminal
                         : AbortKind::WorkerJoined,
                terminal, terminal ? edge : edge - 2));
        }
        result.push_back(descriptor(AbortKind::Teardown, false));
        result.push_back(descriptor(AbortKind::AbortTerminal, false));
        return result;
    };
    return {
        make({0, 1, 2, 3}),
        make({0, 2, 1, 3}),
        make({1, 0, 2, 3}),
    };
}

void validate_variant(AbortClass abort_class, const Variant& value) {
    need(!value.empty() && value.front().kind == AbortKind::CacheUnlink &&
         value[value.size() - 2].kind == AbortKind::Teardown &&
         value.back().kind == AbortKind::AbortTerminal);
    for (const auto& item : value) {
        const auto site =
            kpi::mpc::p1_private_state::mascot_secret_abort_source_site(
                item.kind, abort_class);
        const auto source = kpi::mpc::p1_private_state::
            mascot_secret_abort_upstream_file_sha256(
                item.kind, abort_class);
        need(!site.empty() && source.size() == 64 &&
             (item.worker_ordinal == ROOT || item.worker_ordinal < 2));
    }
}

Digest variant_manifest_identity(
        unsigned round, Branch branch, AbortClass abort_class,
        const Prefix& prefix, const Variants& variants) {
    std::vector<unsigned char> bytes;
    append_text(bytes, "KPB_P1_MASCOT_ABORT_TERMINAL_MANIFEST_V1\n");
    append_text(bytes,
        kpi::mpc::p1_private_state::
            MASCOT_SECRET_ABORT_EVENT_ENCODING_DOMAIN);
    append_text(bytes,
        kpi::mpc::p1_private_state::MASCOT_SECRETS_MP_SPDZ_COMMIT);
    append_u64(bytes, round);
    append_u64(bytes, static_cast<unsigned>(branch));
    append_u64(bytes, static_cast<unsigned>(abort_class));
    append_prefix(bytes, prefix);
    append_u64(bytes, variants.size());
    for (const auto& variant : variants) {
        validate_variant(abort_class, variant);
        append_u64(bytes, variant.size());
        for (const auto& item : variant) {
            append_u64(bytes, static_cast<unsigned>(item.kind));
            append_u64(bytes, item.source_worker ? 1 : 0);
            append_u64(bytes, item.worker_ordinal);
            append_text(bytes,
                kpi::mpc::p1_private_state::
                    mascot_secret_abort_source_site(
                        item.kind, abort_class));
            append_text(bytes,
                kpi::mpc::p1_private_state::
                    mascot_secret_abort_upstream_file_sha256(
                        item.kind, abort_class));
        }
    }
    // A source-stuck worker has no safe in-process terminal edge. This fact is
    // part of the manifest instead of being silently treated as complete.
    append_u64(bytes, 0);
    return hash(bytes);
}

Digest combined_identity(
        const std::array<Branch, 2>& branches,
        const std::array<Prefix, 2>& prefixes,
        const std::array<std::array<Digest, 2>, 2>& identities) {
    std::vector<unsigned char> bytes;
    append_text(bytes, "KPB_P1_MASCOT_ABORT_MANIFEST_JOIN_V1\n");
    for (unsigned round = 0; round < branches.size(); ++round) {
        append_u64(bytes, round + 1);
        append_u64(bytes, static_cast<unsigned>(branches[round]));
        append_prefix(bytes, prefixes[round]);
        for (const auto& value : identities[round])
            append_digest(bytes, value);
    }
    return hash(bytes);
}

} // namespace

struct P1MascotAbortTerminalManifestAuthority::Storage final {
    std::array<Branch, 2> branches{};
    std::array<Prefix, 2> round_prefixes{};
    std::array<std::array<std::uint64_t, 2>, 2> variant_counts{};
    std::array<std::array<Digest, 2>, 2> manifest_identities{};
    Digest combined_manifest_identity{};
    bool exact_unlink_outcome{};
    bool exact_returned_worker_epochs{};
    bool constructor_failure_join{};
    bool stuck_worker_terminal_closure{};
    bool selected_callsite{};
    bool compiler_consumed{};
};

P1MascotAbortTerminalManifestAuthority::
P1MascotAbortTerminalManifestAuthority(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {}
P1MascotAbortTerminalManifestAuthority::
P1MascotAbortTerminalManifestAuthority(
        P1MascotAbortTerminalManifestAuthority&&) noexcept = default;
P1MascotAbortTerminalManifestAuthority::~
P1MascotAbortTerminalManifestAuthority() = default;

P1MascotAbortTerminalCompilerBinding
P1MascotAbortTerminalManifestAuthority::
inspect_for_capsule_compiler() const {
    need(storage_ != nullptr && !storage_->compiler_consumed &&
         storage_->combined_manifest_identity != Digest{});
    return {
        .round_prefixes = storage_->round_prefixes,
        .variant_counts = storage_->variant_counts,
        .manifest_identities = storage_->manifest_identities,
        .combined_manifest_identity = storage_->combined_manifest_identity,
        .exact_unlink_outcome = storage_->exact_unlink_outcome,
        .exact_returned_worker_epochs =
            storage_->exact_returned_worker_epochs,
        .constructor_failure_join = storage_->constructor_failure_join,
        .stuck_worker_terminal_closure =
            storage_->stuck_worker_terminal_closure,
        .selected_callsite = storage_->selected_callsite,
    };
}

void P1MascotAbortTerminalManifestAuthority::claim_for_capsule_compiler(
        const P1MascotAbortTerminalCompilerBinding& expected) {
    need(inspect_for_capsule_compiler() == expected);
    storage_->compiler_consumed = true;
}

P1MascotAbortTerminalManifestAuthority
P1MascotAbortTerminalManifestCompilerBridge::compile() {
    auto storage =
        std::make_unique<P1MascotAbortTerminalManifestAuthority::Storage>();
    storage->branches = {
        Branch::RegeneratedAfterMissing,
        Branch::CacheHit,
    };
    const auto ot = ot_variants();
    const auto mac = mac_variants();
    need(ot.size() == 3 && mac.size() == 3);
    for (unsigned round = 0; round < storage->branches.size(); ++round) {
        storage->round_prefixes[round] =
            p1_state_capsule::
                recompute_mascot_secret_abort_prefix_inventory(
                    storage->branches[round]);
        need(storage->round_prefixes[round].disposition ==
                 p1_state_capsule::
                     AbortFamilyDisposition::TerminalPrefix &&
             storage->round_prefixes[round].exact_object_count == 1);
        storage->variant_counts[round] = {ot.size(), mac.size()};
        storage->manifest_identities[round][0] =
            variant_manifest_identity(
                round + 1, storage->branches[round],
                AbortClass::OtMultiplierFailure,
                storage->round_prefixes[round], ot);
        storage->manifest_identities[round][1] =
            variant_manifest_identity(
                round + 1, storage->branches[round],
                AbortClass::MacCheckFailure,
                storage->round_prefixes[round], mac);
    }
    need(storage->round_prefixes[0].exact_event_count == 12 &&
         storage->round_prefixes[0].exact_transition_count == 11 &&
         storage->round_prefixes[1].exact_event_count == 11 &&
         storage->round_prefixes[1].exact_transition_count == 10);
    storage->combined_manifest_identity = combined_identity(
        storage->branches, storage->round_prefixes,
        storage->manifest_identities);
    storage->exact_unlink_outcome = true;
    storage->exact_returned_worker_epochs = true;
    storage->constructor_failure_join = true;
    storage->stuck_worker_terminal_closure = false;
    storage->selected_callsite = false;
    return P1MascotAbortTerminalManifestAuthority(std::move(storage));
}

P1MascotAbortTerminalManifestSourceStatus
p1_mascot_abort_terminal_manifest_source_status() noexcept {
    return {
        .canonical_abort_v1_encoding = true,
        .exact_selected_source_identities = true,
        .exact_round1_regeneration_prefix = true,
        .exact_round2_cache_hit_prefix = true,
        .exact_ot_failure_variants = true,
        .exact_mac_failure_variants = true,
        .no_caller_branch_count_digest_path_or_bytes = true,
        .returned_worker_failure_publication_and_join = true,
        .constructor_failure_cleanup_and_join = true,
        .unbounded_stuck_worker_terminal_closure = false,
        .all_family_compiler_consumes_authority = true,
        .selected_role_child_callsite = false,
        .postrun_exact_abort_match = false,
        .configured = false,
        .actual_abort_manifest_mint = true,
    };
}

} // namespace kpb::measurement::p1_state
