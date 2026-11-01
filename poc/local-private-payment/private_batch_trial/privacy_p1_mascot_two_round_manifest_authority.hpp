#pragma once

// Opaque source manifest for the selected persistent P1's two MASCOT setup
// rounds. It consumes the source-owned fresh PREP_DIR capability and derives,
// rather than accepts, the only admissible successful branch sequence:
// round 1 regenerates after a missing cache; round 2 reuses that exact cache.

#include "privacy_p1_corrupt_state_capsule_authority.hpp"
#include "privacy_p1_mascot_fresh_prep_directory_authority.hpp"

#include <array>
#include <cstdint>
#include <memory>

namespace kpb::measurement::p1_state {

class P1MascotTwoRoundManifestAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit P1MascotTwoRoundManifestAuthority(
        std::unique_ptr<Storage>) noexcept;
    friend class P1MascotTwoRoundManifestCompilerBridge;
    friend class P1StateCapsulePrelaunchCompilerBridge;
public:
    P1MascotTwoRoundManifestAuthority(
        const P1MascotTwoRoundManifestAuthority&) = delete;
    P1MascotTwoRoundManifestAuthority& operator=(
        const P1MascotTwoRoundManifestAuthority&) = delete;
    P1MascotTwoRoundManifestAuthority(
        P1MascotTwoRoundManifestAuthority&&) noexcept;
    P1MascotTwoRoundManifestAuthority& operator=(
        P1MascotTwoRoundManifestAuthority&&) = delete;
    ~P1MascotTwoRoundManifestAuthority();

#ifdef KPB_P1_MASCOT_TWO_ROUND_MANIFEST_TEST_SETUP
    struct TestOnlySummary final {
        std::array<kpi::mpc::p1_private_state::MascotCacheBranch, 2>
            branches{};
        std::array<p1_state_capsule::FamilyHookInventory, 2>
            inventories{};
        Digest two_round_manifest_identity{};
        bool fresh_directory_retained{};
        bool abort_unlink_terminal_manifest_complete{};
        bool ot_worker_terminal_manifest_complete{};
        bool compiler_consumed{};
    };
    TestOnlySummary test_only_summary() const;
#endif
};

struct P1MascotTwoRoundManifestSourceStatus final {
    bool source_owned_fresh_prep_required{};
    bool exact_round1_missing_regeneration{};
    bool exact_round2_pinned_cache_hit{};
    bool canonical_v2_inventory_recomputation{};
    bool source_directory_one_use_consumed{};
    bool caller_branch_digest_count_path_or_fd{};
    bool abort_unlink_terminal_manifest_complete{};
    bool ot_worker_terminal_manifest_complete{};
    bool all_family_capsule_compiler_consumes_authority{};
    bool selected_persistent_child_callsite{};
    bool postrun_observed_branch_match{};
    bool configured{};
    bool actual_two_round_manifest_mint{};
};

P1MascotTwoRoundManifestSourceStatus
p1_mascot_two_round_manifest_source_status() noexcept;

} // namespace kpb::measurement::p1_state
