#define KPB_P1_MASCOT_FRESH_PREP_DIRECTORY_TEST_SETUP 1
#define KPB_P1_MASCOT_TWO_ROUND_MANIFEST_TEST_SETUP 1
#include "privacy_p1_mascot_two_round_manifest_authority.hpp"

#include <cassert>
#include <concepts>
#include <fcntl.h>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>

namespace p1 = kpb::measurement::p1_state;
namespace capsule = kpb::measurement::p1_state_capsule;
using Branch = kpi::mpc::p1_private_state::MascotCacheBranch;

template<class T> concept HasPlan = requires(T& value) { value.plan(); };
template<class T> concept HasDigest = requires(T& value) { value.digest(); };
template<class T> concept HasPath = requires(T& value) { value.path(); };
template<class T> concept HasFd = requires(T& value) { value.fd(); };
template<class T> concept HasBranch = requires(T& value) { value.branch(); };

static_assert(!std::default_initializable<
              p1::P1MascotTwoRoundManifestAuthority>);
static_assert(!std::copy_constructible<
              p1::P1MascotTwoRoundManifestAuthority>);
static_assert(std::move_constructible<
              p1::P1MascotTwoRoundManifestAuthority>);
static_assert(!HasPlan<p1::P1MascotTwoRoundManifestAuthority>);
static_assert(!HasDigest<p1::P1MascotTwoRoundManifestAuthority>);
static_assert(!HasPath<p1::P1MascotTwoRoundManifestAuthority>);
static_assert(!HasFd<p1::P1MascotTwoRoundManifestAuthority>);
static_assert(!HasBranch<p1::P1MascotTwoRoundManifestAuthority>);

int main() {
    const auto status = p1::p1_mascot_two_round_manifest_source_status();
    assert(status.source_owned_fresh_prep_required);
    assert(status.exact_round1_missing_regeneration);
    assert(status.exact_round2_pinned_cache_hit);
    assert(status.canonical_v2_inventory_recomputation);
    assert(status.source_directory_one_use_consumed);
    assert(!status.caller_branch_digest_count_path_or_fd);
    assert(!status.abort_unlink_terminal_manifest_complete);
    assert(!status.ot_worker_terminal_manifest_complete);
    assert(!status.all_family_capsule_compiler_consumes_authority);
    assert(!status.selected_persistent_child_callsite);
    assert(!status.postrun_observed_branch_match);
    assert(!status.configured);
    assert(!status.actual_two_round_manifest_mint);

    auto fresh = p1::P1MascotFreshPrepDirectorySourceBridge::
        test_only_mint();
    auto manifest = p1::P1MascotTwoRoundManifestCompilerBridge::
        test_only_compile(std::move(fresh));
    const auto summary = manifest.test_only_summary();
    assert(summary.fresh_directory_retained);
    assert(summary.branches[0] == Branch::RegeneratedAfterMissing);
    assert(summary.branches[1] == Branch::CacheHit);
    assert(summary.inventories[0] ==
           capsule::recompute_mascot_secret_branch_inventory(
               Branch::RegeneratedAfterMissing));
    assert(summary.inventories[1] ==
           capsule::recompute_mascot_secret_branch_inventory(
               Branch::CacheHit));
    assert(summary.inventories[0].exact_event_count == 13);
    assert(summary.inventories[0].exact_transition_count == 11);
    assert(summary.inventories[1].exact_event_count == 12);
    assert(summary.inventories[1].exact_transition_count == 10);
    assert(summary.two_round_manifest_identity != kpb::measurement::Digest{});
    assert(!summary.abort_unlink_terminal_manifest_complete);
    assert(!summary.ot_worker_terminal_manifest_complete);

    bool replay_refused = false;
    try {
        auto replay = p1::P1MascotTwoRoundManifestCompilerBridge::
            test_only_compile(std::move(fresh));
        (void)replay;
    } catch (...) { replay_refused = true; }
    assert(replay_refused);

    auto distinct_fresh = p1::P1MascotFreshPrepDirectorySourceBridge::
        test_only_mint();
    auto distinct = p1::P1MascotTwoRoundManifestCompilerBridge::
        test_only_compile(std::move(distinct_fresh));
    assert(distinct.test_only_summary().two_round_manifest_identity !=
           summary.two_round_manifest_identity);

    auto nonempty = p1::P1MascotFreshPrepDirectorySourceBridge::
        test_only_mint();
    const int directory = nonempty.test_only_duplicate_directory_fd();
    const int intruder = ::openat(
        directory, "intruder", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
        0600);
    assert(intruder >= 0 && ::close(intruder) == 0 &&
           ::close(directory) == 0);
    bool nonempty_refused = false;
    try {
        auto invalid = p1::P1MascotTwoRoundManifestCompilerBridge::
            test_only_compile(std::move(nonempty));
        (void)invalid;
    } catch (...) { nonempty_refused = true; }
    assert(nonempty_refused);

    auto wrong_mode = p1::P1MascotFreshPrepDirectorySourceBridge::
        test_only_mint();
    const int mode_fd = wrong_mode.test_only_duplicate_directory_fd();
    assert(::fchmod(mode_fd, 0755) == 0 && ::close(mode_fd) == 0);
    bool mode_refused = false;
    try {
        auto invalid = p1::P1MascotTwoRoundManifestCompilerBridge::
            test_only_compile(std::move(wrong_mode));
        (void)invalid;
    } catch (...) { mode_refused = true; }
    assert(mode_refused);
}
