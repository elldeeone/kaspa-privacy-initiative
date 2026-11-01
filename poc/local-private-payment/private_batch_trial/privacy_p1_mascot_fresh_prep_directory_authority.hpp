#pragma once

// Source-owned fresh filesystem capability for the selected persistent P1
// MASCOT setup. The selected activation creates the directory only after the
// role processes have been reserved, so no child inherits an ambient alias.
// A later capsule compiler may transfer the opaque capability to role 1. No
// path, branch, digest, event count, or caller-owned descriptor is accepted.

#include "../mpc-prover/financial/registered_selected_producer_activation_contract.hpp"
#include "privacy_p1_state_capsule_prelaunch_compiler_contract.hpp"

#include <array>
#include <cstdint>
#include <memory>

namespace kpb::measurement::p1_state {

class P1MascotFreshPrepDirectoryAuthority;
class P1MascotTwoRoundManifestAuthority;

struct P1MascotFreshPrepDirectorySourceBinding final {
    std::uint64_t parent_device{};
    std::uint64_t parent_inode{};
    std::uint64_t directory_device{};
    std::uint64_t directory_inode{};
    std::uint64_t directory_mode{};
    std::uint64_t directory_uid{};
    std::uint64_t directory_gid{};
    std::uint64_t directory_link_count{};
    std::array<unsigned char, 32> source_nonce{};
    bool operator==(
        const P1MascotFreshPrepDirectorySourceBinding&) const = default;
};

// The complete compiler bridge is the only consumer of the fresh directory
// capability. Its production entry is private to the complete all-family
// capsule compiler; controls may exercise the same one-use join explicitly.
class P1MascotTwoRoundManifestCompilerBridge final {
    P1MascotTwoRoundManifestCompilerBridge() = delete;
    static P1MascotTwoRoundManifestAuthority compile(
        P1MascotFreshPrepDirectoryAuthority&&);
    friend class P1StateCapsulePrelaunchCompilerBridge;
public:
#ifdef KPB_P1_MASCOT_TWO_ROUND_MANIFEST_TEST_SETUP
    static P1MascotTwoRoundManifestAuthority test_only_compile(
        P1MascotFreshPrepDirectoryAuthority&&);
#endif
};

// Both privileged names are complete before friendship is granted below.
// The production mint is private to the already-complete selected activation
// bridge, preventing a standalone include from defining a same-name friend.
class P1MascotFreshPrepDirectorySourceBridge final {
    P1MascotFreshPrepDirectorySourceBridge() = delete;
    static P1MascotFreshPrepDirectoryAuthority
    mint_for_selected_activation();
    friend class kpi::mpc::financial::registered_driver::
        RegisteredSelectedProducerActivationBridge;
public:
#ifdef KPB_P1_MASCOT_FRESH_PREP_DIRECTORY_TEST_SETUP
    static P1MascotFreshPrepDirectoryAuthority test_only_mint();
#endif
};

class P1MascotFreshPrepDirectoryAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit P1MascotFreshPrepDirectoryAuthority(
        std::unique_ptr<Storage>) noexcept;
    P1MascotFreshPrepDirectorySourceBinding
    inspect_for_manifest_compiler() const;
    void claim_for_manifest_compiler(
        const P1MascotFreshPrepDirectorySourceBinding&);
    friend class P1MascotFreshPrepDirectorySourceBridge;
    friend class P1MascotTwoRoundManifestCompilerBridge;
    friend class P1StateCapsulePrelaunchCompilerBridge;
public:
    P1MascotFreshPrepDirectoryAuthority(
        const P1MascotFreshPrepDirectoryAuthority&) = delete;
    P1MascotFreshPrepDirectoryAuthority& operator=(
        const P1MascotFreshPrepDirectoryAuthority&) = delete;
    P1MascotFreshPrepDirectoryAuthority(
        P1MascotFreshPrepDirectoryAuthority&&) noexcept;
    P1MascotFreshPrepDirectoryAuthority& operator=(
        P1MascotFreshPrepDirectoryAuthority&&) = delete;
    ~P1MascotFreshPrepDirectoryAuthority();

#ifdef KPB_P1_MASCOT_FRESH_PREP_DIRECTORY_TEST_SETUP
    struct TestOnlySummary final {
        std::uint64_t parent_device{};
        std::uint64_t parent_inode{};
        std::uint64_t directory_device{};
        std::uint64_t directory_inode{};
        std::uint64_t directory_mode{};
        std::uint64_t directory_uid{};
        std::uint64_t directory_gid{};
        std::uint64_t directory_link_count{};
        std::array<unsigned char, 32> source_nonce{};
        bool parent_and_directory_cloexec{};
        bool parent_name_matches_open_descriptor{};
        bool source_created_empty{};
        bool compiler_claimed{};
    };
    TestOnlySummary test_only_summary() const;
    int test_only_duplicate_directory_fd() const;
    void test_only_mark_compiler_claimed();
#endif
};

struct P1MascotFreshPrepDirectorySourceStatus final {
    bool complete_activation_bridge_before_friendship{};
    bool source_generated_name_and_nonce{};
    bool mode_0700_empty_directory{};
    bool no_symlink_parent_name_descriptor_coherence{};
    bool no_caller_path_digest_branch_count_or_fd{};
    bool no_public_path_descriptor_or_nonce_getter{};
    bool recursive_no_follow_cleanup{};
    bool activation_success_retains_authority{};
    bool capsule_compiler_consumes_authority{};
    bool selected_role1_scm_transfer{};
    bool persistent_round1_round2_same_directory{};
    bool observed_branch_postrun_match{};
    bool configured{};
};

P1MascotFreshPrepDirectorySourceStatus
p1_mascot_fresh_prep_directory_source_status() noexcept;

} // namespace kpb::measurement::p1_state
