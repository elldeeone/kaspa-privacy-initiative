#include "privacy_p1_mascot_fresh_prep_directory_authority.hpp"

#include <array>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <openssl/crypto.h>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <utility>

namespace kpb::measurement::p1_state {
namespace {

[[noreturn]] void refuse() { throw std::runtime_error(
    "P1-MASCOT-fresh-PREP-DIR-refused"); }
void need(bool value) { if (!value) refuse(); }

void close_once(int& descriptor) noexcept {
    const int selected = std::exchange(descriptor, -1);
    if (selected >= 0) (void)::close(selected);
}

void fill_random(std::span<unsigned char> output) {
    std::size_t offset = 0;
    while (offset < output.size()) {
        const auto count = ::getrandom(
            output.data() + offset, output.size() - offset, 0);
        if (count < 0 && errno == EINTR) continue;
        need(count > 0);
        offset += static_cast<std::size_t>(count);
    }
}

std::string directory_name(std::span<const unsigned char> nonce) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result = ".kpb-p1-mascot-";
    result.reserve(result.size() + nonce.size() * 2);
    for (const auto byte : nonce) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 0x0f]);
    }
    return result;
}

bool regular_directory(const struct stat& value) noexcept {
    return (value.st_mode & S_IFMT) == S_IFDIR;
}

bool same_object(const struct stat& left, const struct stat& right) noexcept {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
        left.st_mode == right.st_mode && left.st_uid == right.st_uid &&
        left.st_gid == right.st_gid && left.st_nlink == right.st_nlink;
}

bool same_inode(const struct stat& left, const struct stat& right) noexcept {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
        (left.st_mode & S_IFMT) == (right.st_mode & S_IFMT);
}

bool same_directory_anchor(
        const struct stat& left, const struct stat& right) noexcept {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
        left.st_mode == right.st_mode && left.st_uid == right.st_uid &&
        left.st_gid == right.st_gid && regular_directory(left) &&
        regular_directory(right);
}

bool cloexec(int descriptor) noexcept {
    const int flags = ::fcntl(descriptor, F_GETFD);
    return flags >= 0 && (flags & FD_CLOEXEC) != 0;
}

int reopen_directory(int descriptor) noexcept {
    int result;
    do {
        result = ::openat(
            descriptor, ".",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    } while (result < 0 && errno == EINTR);
    return result;
}

bool directory_empty(int descriptor) noexcept {
    int duplicate = reopen_directory(descriptor);
    if (duplicate < 0) return false;
    DIR* directory = ::fdopendir(duplicate);
    if (directory == nullptr) {
        close_once(duplicate);
        return false;
    }
    bool empty = true;
    errno = 0;
    while (const auto* entry = ::readdir(directory)) {
        const std::string_view name(entry->d_name);
        if (name != "." && name != "..") {
            empty = false;
            break;
        }
        errno = 0;
    }
    const bool complete = errno == 0;
    (void)::closedir(directory);
    return empty && complete;
}

// Called only after the persistent children have terminated. Every lookup is
// descriptor-relative and AT_SYMLINK_NOFOLLOW; a symlink is unlinked as an
// entry and is never traversed. Failure leaves the private 0700 root in place
// rather than deleting any substituted object.
int open_child_directory_no_mount(
        int directory, const std::string& name) noexcept {
    struct open_how how{};
    how.flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW |
        O_NONBLOCK;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
        RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;
    int result;
    do {
        result = static_cast<int>(::syscall(
            SYS_openat2, directory, name.c_str(), &how, sizeof(how)));
    } while (result < 0 && errno == EINTR);
    return result;
}

bool remove_tree_contents(int directory, dev_t expected_device) noexcept {
    struct stat selected{};
    if (::fstat(directory, &selected) != 0 ||
        !regular_directory(selected) || selected.st_dev != expected_device)
        return false;
    int duplicate = reopen_directory(directory);
    if (duplicate < 0) return false;
    DIR* stream = ::fdopendir(duplicate);
    if (stream == nullptr) {
        close_once(duplicate);
        return false;
    }
    bool complete = true;
    errno = 0;
    while (const auto* entry = ::readdir(stream)) {
        const std::string_view view(entry->d_name);
        if (view == "." || view == "..") {
            errno = 0;
            continue;
        }
        const std::string name(view);
        struct stat state{};
        if (::fstatat(directory, name.c_str(), &state,
                      AT_SYMLINK_NOFOLLOW) != 0) {
            complete = false;
            errno = 0;
            continue;
        }
        if ((state.st_mode & S_IFMT) == S_IFDIR) {
            const int child = state.st_dev == expected_device
                ? open_child_directory_no_mount(directory, name) : -1;
            if (child < 0 ||
                !remove_tree_contents(child, expected_device))
                complete = false;
            int owned_child = child;
            close_once(owned_child);
            if (child >= 0 &&
                ::unlinkat(directory, name.c_str(), AT_REMOVEDIR) != 0)
                complete = false;
        } else if (::unlinkat(directory, name.c_str(), 0) != 0) {
            complete = false;
        }
        errno = 0;
    }
    if (errno != 0) complete = false;
    (void)::closedir(stream);
    return complete;
}

} // namespace

struct P1MascotFreshPrepDirectoryAuthority::Storage final {
    int parent_fd{-1};
    int directory_fd{-1};
    std::string name;
    std::array<unsigned char, 32> source_nonce{};
    struct stat parent_state{};
    struct stat directory_state{};
    bool source_created_empty{};
    bool compiler_claimed{};

    ~Storage() {
        if (parent_fd >= 0 && directory_fd >= 0 && !name.empty()) {
            struct stat named{};
            const bool still_selected =
                ::fstatat(parent_fd, name.c_str(), &named,
                          AT_SYMLINK_NOFOLLOW) == 0 &&
                same_inode(named, directory_state) &&
                regular_directory(named);
            if (still_selected && remove_tree_contents(
                    directory_fd, directory_state.st_dev))
                (void)::unlinkat(parent_fd, name.c_str(), AT_REMOVEDIR);
        }
        close_once(directory_fd);
        close_once(parent_fd);
        if (!name.empty()) OPENSSL_cleanse(name.data(), name.size());
        OPENSSL_cleanse(source_nonce.data(), source_nonce.size());
    }
};

P1MascotFreshPrepDirectoryAuthority::
P1MascotFreshPrepDirectoryAuthority(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {}
P1MascotFreshPrepDirectoryAuthority::
P1MascotFreshPrepDirectoryAuthority(
        P1MascotFreshPrepDirectoryAuthority&&) noexcept = default;
P1MascotFreshPrepDirectoryAuthority::
~P1MascotFreshPrepDirectoryAuthority() = default;

P1MascotFreshPrepDirectorySourceBinding
P1MascotFreshPrepDirectoryAuthority::inspect_for_manifest_compiler() const {
    need(storage_ != nullptr && storage_->parent_fd >= 0 &&
         storage_->directory_fd >= 0 && storage_->source_created_empty &&
         !storage_->compiler_claimed && cloexec(storage_->parent_fd) &&
         cloexec(storage_->directory_fd));
    struct stat parent_now{};
    struct stat directory_now{};
    struct stat named{};
    need(::fstat(storage_->parent_fd, &parent_now) == 0 &&
         ::fstat(storage_->directory_fd, &directory_now) == 0 &&
         ::fstatat(storage_->parent_fd, storage_->name.c_str(), &named,
                   AT_SYMLINK_NOFOLLOW) == 0 &&
         same_directory_anchor(parent_now, storage_->parent_state) &&
         same_object(directory_now, storage_->directory_state) &&
         same_object(named, directory_now) &&
         regular_directory(directory_now) &&
         directory_now.st_uid == ::geteuid() &&
         directory_now.st_gid == ::getegid() &&
         (directory_now.st_mode & 07777) == 0700 &&
         directory_empty(storage_->directory_fd));
    return {
        .parent_device = static_cast<std::uint64_t>(parent_now.st_dev),
        .parent_inode = static_cast<std::uint64_t>(parent_now.st_ino),
        .directory_device = static_cast<std::uint64_t>(
            directory_now.st_dev),
        .directory_inode = static_cast<std::uint64_t>(
            directory_now.st_ino),
        .directory_mode = static_cast<std::uint64_t>(
            directory_now.st_mode),
        .directory_uid = static_cast<std::uint64_t>(
            directory_now.st_uid),
        .directory_gid = static_cast<std::uint64_t>(
            directory_now.st_gid),
        .directory_link_count = static_cast<std::uint64_t>(
            directory_now.st_nlink),
        .source_nonce = storage_->source_nonce,
    };
}

void P1MascotFreshPrepDirectoryAuthority::claim_for_manifest_compiler(
        const P1MascotFreshPrepDirectorySourceBinding& expected) {
    const auto current = inspect_for_manifest_compiler();
    need(current == expected);
    storage_->compiler_claimed = true;
}

P1MascotFreshPrepDirectoryAuthority
P1MascotFreshPrepDirectorySourceBridge::mint_for_selected_activation() {
    auto storage = std::make_unique<
        P1MascotFreshPrepDirectoryAuthority::Storage>();
    fill_random(storage->source_nonce);
    storage->name = directory_name(storage->source_nonce);

    do {
        storage->parent_fd = ::open(
            "/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW |
                O_NONBLOCK);
    } while (storage->parent_fd < 0 && errno == EINTR);
    need(storage->parent_fd >= 0 && cloexec(storage->parent_fd) &&
         ::fstat(storage->parent_fd, &storage->parent_state) == 0 &&
         regular_directory(storage->parent_state));

    int made;
    do {
        made = ::mkdirat(storage->parent_fd, storage->name.c_str(), 0700);
    } while (made != 0 && errno == EINTR);
    need(made == 0);

    do {
        storage->directory_fd = ::openat(
            storage->parent_fd, storage->name.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    } while (storage->directory_fd < 0 && errno == EINTR);
    need(storage->directory_fd >= 0 && cloexec(storage->directory_fd) &&
         ::fstat(storage->directory_fd, &storage->directory_state) == 0 &&
         regular_directory(storage->directory_state));
    struct stat named{};
    need(::fstatat(storage->parent_fd, storage->name.c_str(), &named,
                   AT_SYMLINK_NOFOLLOW) == 0 &&
         same_object(named, storage->directory_state) &&
         storage->directory_state.st_uid == ::geteuid() &&
         storage->directory_state.st_gid == ::getegid() &&
         (storage->directory_state.st_mode & 07777) == 0700 &&
         directory_empty(storage->directory_fd));
    storage->source_created_empty = true;
    return P1MascotFreshPrepDirectoryAuthority(std::move(storage));
}

#ifdef KPB_P1_MASCOT_FRESH_PREP_DIRECTORY_TEST_SETUP
P1MascotFreshPrepDirectoryAuthority
P1MascotFreshPrepDirectorySourceBridge::test_only_mint() {
    return mint_for_selected_activation();
}

P1MascotFreshPrepDirectoryAuthority::TestOnlySummary
P1MascotFreshPrepDirectoryAuthority::test_only_summary() const {
    need(storage_ != nullptr && storage_->parent_fd >= 0 &&
         storage_->directory_fd >= 0);
    struct stat named{};
    const bool matches =
        ::fstatat(storage_->parent_fd, storage_->name.c_str(), &named,
                  AT_SYMLINK_NOFOLLOW) == 0 &&
        same_inode(named, storage_->directory_state);
    return {
        .parent_device = static_cast<std::uint64_t>(
            storage_->parent_state.st_dev),
        .parent_inode = static_cast<std::uint64_t>(
            storage_->parent_state.st_ino),
        .directory_device = static_cast<std::uint64_t>(
            storage_->directory_state.st_dev),
        .directory_inode = static_cast<std::uint64_t>(
            storage_->directory_state.st_ino),
        .directory_mode = static_cast<std::uint64_t>(
            storage_->directory_state.st_mode),
        .directory_uid = static_cast<std::uint64_t>(
            storage_->directory_state.st_uid),
        .directory_gid = static_cast<std::uint64_t>(
            storage_->directory_state.st_gid),
        .directory_link_count = static_cast<std::uint64_t>(
            storage_->directory_state.st_nlink),
        .source_nonce = storage_->source_nonce,
        .parent_and_directory_cloexec =
            cloexec(storage_->parent_fd) && cloexec(storage_->directory_fd),
        .parent_name_matches_open_descriptor = matches,
        .source_created_empty = storage_->source_created_empty &&
            directory_empty(storage_->directory_fd),
        .compiler_claimed = storage_->compiler_claimed,
    };
}

int P1MascotFreshPrepDirectoryAuthority::
test_only_duplicate_directory_fd() const {
    need(storage_ != nullptr && storage_->directory_fd >= 0);
    const int result = ::fcntl(storage_->directory_fd, F_DUPFD_CLOEXEC, 3);
    need(result >= 0);
    return result;
}

void P1MascotFreshPrepDirectoryAuthority::
test_only_mark_compiler_claimed() {
    need(storage_ != nullptr && !storage_->compiler_claimed &&
         storage_->source_created_empty &&
         directory_empty(storage_->directory_fd));
    storage_->compiler_claimed = true;
}
#endif

P1MascotFreshPrepDirectorySourceStatus
p1_mascot_fresh_prep_directory_source_status() noexcept {
    return {
        .complete_activation_bridge_before_friendship = true,
        .source_generated_name_and_nonce = true,
        .mode_0700_empty_directory = true,
        .no_symlink_parent_name_descriptor_coherence = true,
        .no_caller_path_digest_branch_count_or_fd = true,
        .no_public_path_descriptor_or_nonce_getter = true,
        .recursive_no_follow_cleanup = true,
        .activation_success_retains_authority = false,
        .capsule_compiler_consumes_authority = false,
        .selected_role1_scm_transfer = false,
        .persistent_round1_round2_same_directory = false,
        .observed_branch_postrun_match = false,
        .configured = false,
    };
}

} // namespace kpb::measurement::p1_state
