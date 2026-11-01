#define KPB_P1_MASCOT_FRESH_PREP_DIRECTORY_TEST_SETUP 1
#include "privacy_p1_mascot_fresh_prep_directory_authority.hpp"

#include <cassert>
#include <concepts>
#include <fcntl.h>
#include <limits.h>
#include <string>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>

namespace p1 = kpb::measurement::p1_state;

template<class T> concept HasPath = requires(T& value) { value.path(); };
template<class T> concept HasFd = requires(T& value) { value.fd(); };
template<class T> concept HasDigest = requires(T& value) { value.digest(); };
template<class T> concept HasBranch = requires(T& value) { value.branch(); };

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
    assert(!status.activation_success_retains_authority);
    assert(!status.capsule_compiler_consumes_authority);
    assert(!status.selected_role1_scm_transfer);
    assert(!status.persistent_round1_round2_same_directory);
    assert(!status.observed_branch_postrun_match);
    assert(!status.configured);

    auto first = p1::P1MascotFreshPrepDirectorySourceBridge::
        test_only_mint();
    auto second = p1::P1MascotFreshPrepDirectorySourceBridge::
        test_only_mint();
    const auto first_summary = first.test_only_summary();
    const auto second_summary = second.test_only_summary();
    assert(first_summary.source_created_empty);
    assert(first_summary.parent_and_directory_cloexec);
    assert(first_summary.parent_name_matches_open_descriptor);
    assert((first_summary.directory_mode & S_IFMT) == S_IFDIR);
    assert((first_summary.directory_mode & 07777) == 0700);
    assert(first_summary.directory_uid == static_cast<unsigned>(::geteuid()));
    assert(first_summary.directory_gid == static_cast<unsigned>(::getegid()));
    assert(first_summary.source_nonce != second_summary.source_nonce);
    assert(first_summary.directory_device != second_summary.directory_device ||
           first_summary.directory_inode != second_summary.directory_inode);

    first.test_only_mark_compiler_claimed();
    assert(first.test_only_summary().compiler_claimed);
    bool duplicate_claim_refused = false;
    try { first.test_only_mark_compiler_claimed(); }
    catch (...) { duplicate_claim_refused = true; }
    assert(duplicate_claim_refused);

    // Populate a nested tree plus a symlink. Destruction must unlink the
    // symlink itself and never traverse it.
    const int directory = second.test_only_duplicate_directory_fd();
    std::string proc_path = "/proc/self/fd/" + std::to_string(directory);
    char selected_path[PATH_MAX + 1]{};
    const auto selected_path_size = ::readlink(
        proc_path.c_str(), selected_path, PATH_MAX);
    assert(selected_path_size > 0 && selected_path_size <= PATH_MAX);
    selected_path[selected_path_size] = '\0';
    assert(::mkdirat(directory, "nested", 0700) == 0);
    const int nested = ::openat(
        directory, "nested",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    assert(nested >= 0);
    const int secret = ::openat(
        nested, "secret", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(secret >= 0);
    static constexpr char body[] = "secret-state";
    assert(::write(secret, body, sizeof(body)) ==
           static_cast<ssize_t>(sizeof(body)));
    assert(::close(secret) == 0);
    assert(::symlinkat("/etc", nested, "do-not-follow") == 0);
    assert(::close(nested) == 0);
    assert(::close(directory) == 0);

    // Move preserves the one source capability without opening a second mint.
    {
        auto moved = std::move(second);
        assert(moved.test_only_summary().parent_name_matches_open_descriptor);
    }
    struct stat removed{};
    assert(::lstat(selected_path, &removed) != 0 && errno == ENOENT);
    struct stat external{};
    assert(::stat("/etc", &external) == 0 &&
           (external.st_mode & S_IFMT) == S_IFDIR);
}
