#include "privacy_p1_mascot_two_round_manifest_authority.hpp"

#include <cassert>
#include <concepts>

namespace p1 = kpb::measurement::p1_state;

template<class T> concept HasPlan = requires(T& value) { value.plan(); };
template<class T> concept HasDigest = requires(T& value) { value.digest(); };
template<class T> concept HasPath = requires(T& value) { value.path(); };
template<class T> concept HasFd = requires(T& value) { value.fd(); };
template<class T> concept HasBranch = requires(T& value) { value.branch(); };
template<class T> concept HasTestOnlySummary = requires(T& value) {
    value.test_only_summary();
};
template<class T> concept HasTestOnlyCompile = requires(
        p1::P1MascotFreshPrepDirectoryAuthority&& fresh) {
    T::test_only_compile(
        static_cast<p1::P1MascotFreshPrepDirectoryAuthority&&>(fresh));
};

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
static_assert(!HasTestOnlySummary<
              p1::P1MascotTwoRoundManifestAuthority>);
static_assert(!HasTestOnlyCompile<
              p1::P1MascotTwoRoundManifestCompilerBridge>);

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
    assert(status.all_family_capsule_compiler_consumes_authority);
    assert(!status.selected_persistent_child_callsite);
    assert(!status.postrun_observed_branch_match);
    assert(!status.configured);
    assert(status.actual_two_round_manifest_mint);
}
