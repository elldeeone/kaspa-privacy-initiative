#include "privacy_p1_mascot_fresh_prep_directory_authority.hpp"

#include <cassert>
#include <concepts>

namespace p1 = kpb::measurement::p1_state;

template<class T> concept HasPath = requires(T& value) { value.path(); };
template<class T> concept HasFd = requires(T& value) { value.fd(); };
template<class T> concept HasDigest = requires(T& value) { value.digest(); };
template<class T> concept HasBranch = requires(T& value) { value.branch(); };
template<class T> concept HasTestOnlySummary = requires(T& value) {
    value.test_only_summary();
};
template<class T> concept HasTestOnlyDuplicateDirectoryFd =
    requires(T& value) { value.test_only_duplicate_directory_fd(); };
template<class T> concept HasTestOnlyMarkCompilerClaimed =
    requires(T& value) { value.test_only_mark_compiler_claimed(); };
template<class T> concept HasTestOnlyMint = requires { T::test_only_mint(); };

static_assert(!std::default_initializable<
              p1::P1MascotFreshPrepDirectoryAuthority>);
static_assert(!std::copy_constructible<
              p1::P1MascotFreshPrepDirectoryAuthority>);
static_assert(std::move_constructible<
              p1::P1MascotFreshPrepDirectoryAuthority>);
static_assert(!HasPath<p1::P1MascotFreshPrepDirectoryAuthority>);
static_assert(!HasFd<p1::P1MascotFreshPrepDirectoryAuthority>);
static_assert(!HasDigest<p1::P1MascotFreshPrepDirectoryAuthority>);
static_assert(!HasBranch<p1::P1MascotFreshPrepDirectoryAuthority>);
static_assert(!HasTestOnlySummary<
              p1::P1MascotFreshPrepDirectoryAuthority>);
static_assert(!HasTestOnlyDuplicateDirectoryFd<
              p1::P1MascotFreshPrepDirectoryAuthority>);
static_assert(!HasTestOnlyMarkCompilerClaimed<
              p1::P1MascotFreshPrepDirectoryAuthority>);
static_assert(!HasTestOnlyMint<
              p1::P1MascotFreshPrepDirectorySourceBridge>);

int main() {
    const auto status =
        p1::p1_mascot_fresh_prep_directory_source_status();
    assert(status.complete_activation_bridge_before_friendship);
    assert(status.source_generated_name_and_nonce);
    assert(status.mode_0700_empty_directory);
    assert(status.no_symlink_parent_name_descriptor_coherence);
    assert(status.no_caller_path_digest_branch_count_or_fd);
    assert(status.no_public_path_descriptor_or_nonce_getter);
    assert(status.recursive_no_follow_cleanup);
    assert(status.activation_success_retains_authority);
    assert(status.capsule_compiler_consumes_authority);
    assert(!status.selected_role1_scm_transfer);
    assert(status.persistent_round1_round2_same_directory);
    assert(!status.observed_branch_postrun_match);
    assert(!status.configured);
}
