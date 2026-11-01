#include "privacy_p1_mascot_two_round_manifest_authority.hpp"

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace kpb::measurement::p1_state {
namespace {

using Branch = kpi::mpc::p1_private_state::MascotCacheBranch;
using Inventory = p1_state_capsule::FamilyHookInventory;

[[noreturn]] void refuse() { throw std::runtime_error(
    "P1-MASCOT-two-round-manifest-refused"); }
void need(bool value) { if (!value) refuse(); }

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

void append_inventory(
        std::vector<unsigned char>& output, const Inventory& value) {
    append_u64(output, value.exact_object_count);
    append_u64(output, value.exact_event_count);
    append_u64(output, value.exact_transition_count);
    append_u64(output, value.required_transition_bitmap);
    append_digest(output, value.ordered_hook_manifest_identity);
    append_digest(output, value.expected_event_sequence_identity);
    append_digest(output, value.expected_transition_sequence_identity);
}

Digest identity(
        const P1MascotFreshPrepDirectorySourceBinding& prep,
        const std::array<Branch, 2>& branches,
        const std::array<Inventory, 2>& inventories) {
    std::vector<unsigned char> bytes;
    append_text(bytes, "KPB_P1_MASCOT_TWO_ROUND_MANIFEST_V1\n");
    append_text(bytes,
        kpi::mpc::p1_private_state::MASCOT_SECRET_EVENT_ENCODING_DOMAIN);
    append_text(bytes,
        kpi::mpc::p1_private_state::MASCOT_SECRETS_MP_SPDZ_COMMIT);
    for (const auto value : {
             prep.parent_device, prep.parent_inode,
             prep.directory_device, prep.directory_inode,
             prep.directory_mode, prep.directory_uid, prep.directory_gid,
             prep.directory_link_count})
        append_u64(bytes, value);
    append_bytes(bytes, prep.source_nonce);
    for (unsigned index = 0; index < branches.size(); ++index) {
        append_u64(bytes, index + 1);
        append_u64(bytes, static_cast<unsigned>(branches[index]));
        append_inventory(bytes, inventories[index]);
    }
    Digest result{};
    const bool complete = ::SHA256(
        bytes.data(), bytes.size(), result.data()) != nullptr;
    if (!bytes.empty()) OPENSSL_cleanse(bytes.data(), bytes.size());
    need(complete && result != Digest{});
    return result;
}

struct CleanBinding final {
    P1MascotFreshPrepDirectorySourceBinding value;
    ~CleanBinding() { OPENSSL_cleanse(&value, sizeof(value)); }
};

} // namespace

struct P1MascotTwoRoundManifestAuthority::Storage final {
    std::optional<P1MascotFreshPrepDirectoryAuthority> fresh_directory;
    std::array<Branch, 2> branches{};
    std::array<Inventory, 2> inventories{};
    Digest two_round_manifest_identity{};
    bool abort_unlink_terminal_manifest_complete{};
    bool ot_worker_terminal_manifest_complete{};
    bool compiler_consumed{};
};

P1MascotTwoRoundManifestAuthority::P1MascotTwoRoundManifestAuthority(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {}
P1MascotTwoRoundManifestAuthority::P1MascotTwoRoundManifestAuthority(
        P1MascotTwoRoundManifestAuthority&&) noexcept = default;
P1MascotTwoRoundManifestAuthority::~P1MascotTwoRoundManifestAuthority() =
    default;

P1MascotTwoRoundCompilerBinding
P1MascotTwoRoundManifestAuthority::inspect_for_capsule_compiler() const {
    need(storage_ != nullptr && storage_->fresh_directory.has_value() &&
         !storage_->compiler_consumed &&
         storage_->two_round_manifest_identity != Digest{});
    return {
        .branches = storage_->branches,
        .inventories = storage_->inventories,
        .two_round_manifest_identity = storage_->two_round_manifest_identity,
        .abort_unlink_terminal_manifest_complete =
            storage_->abort_unlink_terminal_manifest_complete,
        .ot_worker_terminal_manifest_complete =
            storage_->ot_worker_terminal_manifest_complete,
    };
}

void P1MascotTwoRoundManifestAuthority::claim_for_capsule_compiler(
        const P1MascotTwoRoundCompilerBinding& expected) {
    need(inspect_for_capsule_compiler() == expected);
    storage_->compiler_consumed = true;
}

P1MascotTwoRoundManifestAuthority
P1MascotTwoRoundManifestCompilerBridge::compile(
        P1MascotFreshPrepDirectoryAuthority&& fresh) {
    CleanBinding selected{fresh.inspect_for_manifest_compiler()};
    auto storage = std::make_unique<
        P1MascotTwoRoundManifestAuthority::Storage>();
    storage->branches = {
        Branch::RegeneratedAfterMissing,
        Branch::CacheHit,
    };
    for (unsigned index = 0; index < storage->branches.size(); ++index)
        storage->inventories[index] =
            p1_state_capsule::recompute_mascot_secret_branch_inventory(
                storage->branches[index]);
    need(storage->inventories[0].exact_object_count == 1 &&
         storage->inventories[0].exact_event_count == 13 &&
         storage->inventories[0].exact_transition_count == 11 &&
         storage->inventories[1].exact_object_count == 1 &&
         storage->inventories[1].exact_event_count == 12 &&
         storage->inventories[1].exact_transition_count == 10);
    storage->two_round_manifest_identity = identity(
        selected.value, storage->branches, storage->inventories);
    // Abort unlink and OT-worker terminal closure remain explicitly missing.
    storage->abort_unlink_terminal_manifest_complete = false;
    storage->ot_worker_terminal_manifest_complete = false;
    fresh.claim_for_manifest_compiler(selected.value);
    storage->fresh_directory.emplace(std::move(fresh));
    return P1MascotTwoRoundManifestAuthority(std::move(storage));
}

P1MascotTwoRoundManifestSourceStatus
p1_mascot_two_round_manifest_source_status() noexcept {
    return {
        .source_owned_fresh_prep_required = true,
        .exact_round1_missing_regeneration = true,
        .exact_round2_pinned_cache_hit = true,
        .canonical_v2_inventory_recomputation = true,
        .source_directory_one_use_consumed = true,
        .caller_branch_digest_count_path_or_fd = false,
        .abort_unlink_terminal_manifest_complete = false,
        .ot_worker_terminal_manifest_complete = false,
        .all_family_capsule_compiler_consumes_authority = true,
        .selected_persistent_child_callsite = false,
        .postrun_observed_branch_match = false,
        .configured = false,
        .actual_two_round_manifest_mint = true,
    };
}

} // namespace kpb::measurement::p1_state
