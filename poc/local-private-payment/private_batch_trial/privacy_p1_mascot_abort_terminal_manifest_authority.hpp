#pragma once

// Opaque, source-derived manifest for the selected MASCOT abort-prefix lane.
// It fixes the expected non-abort prefixes, typed abort event schema, upstream
// source identities, and every ordering permitted by the selected two-worker
// implementation. It does not claim a selected terminal callsite or stuck-
// worker closure. It accepts no caller branch, count, digest, path, or bytes.

#include "privacy_p1_corrupt_state_capsule_authority.hpp"
#include "privacy_p1_state_capsule_prelaunch_compiler_contract.hpp"

#include <array>
#include <cstdint>
#include <memory>

namespace kpb::measurement::p1_state {

class P1MascotAbortTerminalManifestAuthority;

struct P1MascotAbortTerminalCompilerBinding final {
    std::array<p1_state_capsule::AbortFamilyHookInventory, 2>
        round_prefixes{};
    std::array<std::array<std::uint64_t, 2>, 2> variant_counts{};
    std::array<std::array<Digest, 2>, 2> manifest_identities{};
    Digest combined_manifest_identity{};
    bool exact_unlink_outcome{};
    bool exact_returned_worker_epochs{};
    bool constructor_failure_join{};
    bool stuck_worker_terminal_closure{};
    bool selected_callsite{};
    bool operator==(
        const P1MascotAbortTerminalCompilerBinding&) const = default;
};

// Complete before friendship. Only the complete all-family compiler may ask
// this bridge to derive the source manifest.
class P1MascotAbortTerminalManifestCompilerBridge final {
    P1MascotAbortTerminalManifestCompilerBridge() = delete;
    friend class P1StateCapsulePrelaunchCompilerBridge;
    static P1MascotAbortTerminalManifestAuthority compile();
};

class P1MascotAbortTerminalManifestAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit P1MascotAbortTerminalManifestAuthority(
        std::unique_ptr<Storage>) noexcept;
    P1MascotAbortTerminalCompilerBinding
    inspect_for_capsule_compiler() const;
    void claim_for_capsule_compiler(
        const P1MascotAbortTerminalCompilerBinding&);
    friend class P1MascotAbortTerminalManifestCompilerBridge;
    friend class P1AbortTerminalManifestSourceBridge;
    friend class P1StateCapsulePrelaunchCompilerBridge;
public:
    P1MascotAbortTerminalManifestAuthority(
        const P1MascotAbortTerminalManifestAuthority&) = delete;
    P1MascotAbortTerminalManifestAuthority& operator=(
        const P1MascotAbortTerminalManifestAuthority&) = delete;
    P1MascotAbortTerminalManifestAuthority(
        P1MascotAbortTerminalManifestAuthority&&) noexcept;
    P1MascotAbortTerminalManifestAuthority& operator=(
        P1MascotAbortTerminalManifestAuthority&&) = delete;
    ~P1MascotAbortTerminalManifestAuthority();
};

struct P1MascotAbortTerminalManifestSourceStatus final {
    bool canonical_abort_v1_encoding{};
    bool exact_selected_source_identities{};
    bool exact_round1_regeneration_prefix{};
    bool exact_round2_cache_hit_prefix{};
    bool exact_ot_failure_variants{};
    bool exact_mac_failure_variants{};
    bool no_caller_branch_count_digest_path_or_bytes{};
    bool returned_worker_failure_publication_and_join{};
    bool constructor_failure_cleanup_and_join{};
    bool unbounded_stuck_worker_terminal_closure{};
    bool all_family_compiler_consumes_authority{};
    bool selected_role_child_callsite{};
    bool postrun_exact_abort_match{};
    bool configured{};
    bool actual_abort_manifest_mint{};
};

P1MascotAbortTerminalManifestSourceStatus
p1_mascot_abort_terminal_manifest_source_status() noexcept;

} // namespace kpb::measurement::p1_state
