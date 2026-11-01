#pragma once

// Source-owned MP-SPDZ adapter for the exact Mascot-Secrets lifecycle. This
// file is included only by the pinned MASCOT callsites. It never exposes a
// recorder or a persistent raw-secret getter.

#include "p1_mascot_secret_state_hook.hpp"
#include "OT/OTExtensionWithMatrix.h"
#include "Processor/OnlineOptions.h"
#include "Tools/Exceptions.h"
#include "Tools/octetStream.h"

#include <array>
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <linux/openat2.h>
#include <span>
#include <ostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

namespace kpb_mp_spdz_p1_mascot {
namespace state = kpi::mpc::p1_private_state;

using AbortClass = state::MascotSecretAbortClass;

struct AbortUnlinkOutcome final {
    AbortClass abort_class{};
    bool succeeded{};
    std::uint64_t operation_errno{};
    state::MascotFileMetadataView path_lstat_before;
    state::MascotFileMetadataView path_lstat_after;
};

namespace detail {

#ifdef KPI_P1_MASCOT_SECRET_SOURCE_CAPTURE_TEST_SETUP
enum class TestFault : std::uint8_t {
    None,
    ShortRead,
    ReopenMismatch,
    FsyncFailure,
};
inline TestFault test_fault = TestFault::None;
inline void set_test_fault(TestFault fault) noexcept { test_fault = fault; }
inline bool consume_test_fault(TestFault fault) noexcept {
    if (test_fault != fault) return false;
    test_fault = TestFault::None;
    return true;
}
#endif

inline void cleanse(std::vector<unsigned char>& value) noexcept {
    volatile unsigned char* cursor = value.data();
    for (std::size_t index = 0; index < value.size(); ++index)
        cursor[index] = 0;
    value.clear();
}

class SecretBytes final {
    std::vector<unsigned char> value_;
public:
    SecretBytes() = default;
    explicit SecretBytes(std::vector<unsigned char> value)
        : value_(std::move(value)) {}
    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;
    SecretBytes(SecretBytes&& other) noexcept
        : value_(std::move(other.value_)) {}
    SecretBytes& operator=(SecretBytes&& other) noexcept {
        if (this != &other) {
            cleanse(value_);
            value_ = std::move(other.value_);
        }
        return *this;
    }
    ~SecretBytes() { cleanse(value_); }
    std::span<const unsigned char> source_view() const noexcept {
        return value_;
    }
};

class SecretVectorStreamBuf final : public std::streambuf {
    std::vector<unsigned char> value_;
protected:
    std::streamsize xsputn(
            const char* source, std::streamsize count) override {
        if (count <= 0) return 0;
        const auto size = static_cast<std::size_t>(count);
        if (size > value_.max_size() - value_.size()) return 0;
        const auto* bytes =
            reinterpret_cast<const unsigned char*>(source);
        value_.insert(value_.end(), bytes, bytes + size);
        return count;
    }
    int_type overflow(int_type character) override {
        if (traits_type::eq_int_type(character, traits_type::eof()))
            return traits_type::not_eof(character);
        if (value_.size() == value_.max_size())
            return traits_type::eof();
        value_.push_back(static_cast<unsigned char>(
            traits_type::to_char_type(character)));
        return character;
    }
public:
    SecretVectorStreamBuf() = default;
    SecretVectorStreamBuf(const SecretVectorStreamBuf&) = delete;
    SecretVectorStreamBuf& operator=(const SecretVectorStreamBuf&) = delete;
    ~SecretVectorStreamBuf() override { cleanse(value_); }
    std::span<const unsigned char> source_view() const noexcept {
        return value_;
    }
};

inline state::MascotFileMetadataView metadata(const struct stat& value) {
    return {
        .present = true,
        .device = static_cast<std::uint64_t>(value.st_dev),
        .inode = static_cast<std::uint64_t>(value.st_ino),
        .mode = static_cast<std::uint64_t>(value.st_mode),
        .uid = static_cast<std::uint64_t>(value.st_uid),
        .gid = static_cast<std::uint64_t>(value.st_gid),
        .link_count = static_cast<std::uint64_t>(value.st_nlink),
        .size = value.st_size < 0 ? 0U
                                 : static_cast<std::uint64_t>(value.st_size),
        .mtime_seconds = static_cast<std::int64_t>(value.st_mtim.tv_sec),
        .mtime_nanoseconds =
            static_cast<std::uint64_t>(value.st_mtim.tv_nsec),
        .ctime_seconds = static_cast<std::int64_t>(value.st_ctim.tv_sec),
        .ctime_nanoseconds =
            static_cast<std::uint64_t>(value.st_ctim.tv_nsec),
    };
}

inline bool lstat_path(
        const std::string& path, state::MascotFileMetadataView& output,
        int& error) noexcept {
    struct stat value{};
    if (::lstat(path.c_str(), &value) == 0) {
        output = metadata(value);
        error = 0;
        return true;
    }
    error = errno;
    output = {};
    return false;
}

inline bool fstat_fd(
        int descriptor, state::MascotFileMetadataView& output,
        int& error) noexcept {
    struct stat value{};
    if (::fstat(descriptor, &value) == 0) {
        output = metadata(value);
        error = 0;
        return true;
    }
    error = errno;
    output = {};
    return false;
}

inline bool regular_file(
        const state::MascotFileMetadataView& value) noexcept {
    return value.present && (value.mode & S_IFMT) == S_IFREG;
}

inline bool same_identity(
        const state::MascotFileMetadataView& left,
        const state::MascotFileMetadataView& right) noexcept {
    return left.present && right.present && left.device == right.device &&
        left.inode == right.inode && left.mode == right.mode &&
        left.uid == right.uid && left.gid == right.gid &&
        left.link_count == right.link_count;
}

inline void close_fd(int& descriptor) noexcept {
    if (descriptor < 0) return;
    (void)::close(descriptor);
    descriptor = -1;
}

inline bool valid_relative_path(std::string_view path) noexcept {
    if (path.empty() || path.front() == '/' || path.back() == '/')
        return false;
    std::size_t start = 0;
    while (start < path.size()) {
        const auto end = path.find('/', start);
        const auto component = path.substr(
            start, end == std::string_view::npos ? path.size() - start
                                                 : end - start);
        // The pinned get_ot_secrets_filename() concatenates PREP_DIR (which
        // already ends in '/') with another '/'. Repeated separators are
        // therefore legitimate source output. Dot components remain invalid.
        if (component == "." || component == "..")
            return false;
        if (end == std::string_view::npos) return true;
        start = end + 1;
    }
    return false;
}

inline int open_no_symlinks(
        const std::string& path, int flags, mode_t mode = 0) noexcept {
    if (!valid_relative_path(path)) {
        errno = EINVAL;
        return -1;
    }
    struct open_how how{};
    how.flags = static_cast<std::uint64_t>(flags | O_NOFOLLOW);
    how.mode = static_cast<std::uint64_t>(mode);
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
        RESOLVE_NO_MAGICLINKS;
    return static_cast<int>(::syscall(
        SYS_openat2, AT_FDCWD, path.c_str(), &how, sizeof(how)));
}

inline bool split_relative_path(
        std::string_view path, std::string& parent,
        std::string& basename) {
    if (!valid_relative_path(path)) return false;
    std::vector<std::string_view> components;
    std::size_t start = 0;
    while (start < path.size()) {
        const auto end = path.find('/', start);
        const auto component = path.substr(
            start, end == std::string_view::npos ? path.size() - start
                                                 : end - start);
        if (!component.empty()) components.push_back(component);
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    if (components.empty()) return false;
    basename.assign(components.back());
    parent.clear();
    for (std::size_t index = 0; index + 1 < components.size(); ++index) {
        if (!parent.empty()) parent.push_back('/');
        parent.append(components[index]);
    }
    return true;
}

inline bool ensure_relative_directory_no_symlinks(
        std::string_view directory, int& error) {
    if (directory.empty() || directory.front() == '/') {
        error = EINVAL;
        return false;
    }
    int current;
    do {
        current = ::open(
            ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NONBLOCK |
                O_NOFOLLOW);
    } while (current < 0 && errno == EINTR);
    if (current < 0) {
        error = errno;
        return false;
    }
    bool saw_component = false;
    std::size_t start = 0;
    while (start < directory.size()) {
        const auto end = directory.find('/', start);
        const auto component = directory.substr(
            start, end == std::string_view::npos
                ? directory.size() - start : end - start);
        if (!component.empty()) {
            saw_component = true;
            if (component == "." || component == "..") {
                close_fd(current);
                error = EINVAL;
                return false;
            }
            const std::string name(component);
            int mkdir_result;
            do {
                mkdir_result = ::mkdirat(current, name.c_str(), 0777);
            } while (mkdir_result != 0 && errno == EINTR);
            if (mkdir_result != 0 && errno != EEXIST) {
                error = errno;
                close_fd(current);
                return false;
            }
            int next;
            do {
                next = ::openat(
                    current, name.c_str(),
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NONBLOCK |
                        O_NOFOLLOW);
            } while (next < 0 && errno == EINTR);
            if (next < 0) {
                error = errno;
                close_fd(current);
                return false;
            }
            struct stat directory_metadata{};
            if (::fstat(next, &directory_metadata) != 0 ||
                (directory_metadata.st_mode & S_IFMT) != S_IFDIR) {
                error = errno == 0 ? ENOTDIR : errno;
                close_fd(next);
                close_fd(current);
                return false;
            }
            close_fd(current);
            current = next;
        }
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    close_fd(current);
    if (!saw_component) {
        error = EINVAL;
        return false;
    }
    error = 0;
    return true;
}

inline bool fstatat_path(
        int directory, const std::string& basename,
        state::MascotFileMetadataView& output, int& error) noexcept {
    struct stat value{};
    if (::fstatat(
            directory, basename.c_str(), &value,
            AT_SYMLINK_NOFOLLOW) == 0) {
        output = metadata(value);
        error = 0;
        return true;
    }
    error = errno;
    output = {};
    return false;
}

inline bool read_to_end(
        int descriptor, std::vector<unsigned char>& output,
        int& error) {
    std::array<unsigned char, 1U << 16> buffer{};
    while (true) {
        ssize_t count;
        do {
            count = ::read(descriptor, buffer.data(), buffer.size());
        } while (count < 0 && errno == EINTR);
        if (count < 0) {
            error = errno;
            return false;
        }
        if (count == 0) {
            error = 0;
            return true;
        }
        const auto size = static_cast<std::size_t>(count);
        if (size > output.max_size() - output.size()) {
            error = EOVERFLOW;
            return false;
        }
        output.insert(output.end(), buffer.begin(), buffer.begin() + size);
#ifdef KPI_P1_MASCOT_SECRET_SOURCE_CAPTURE_TEST_SETUP
        if (consume_test_fault(TestFault::ShortRead)) {
            output.pop_back();
            error = EIO;
            return false;
        }
#endif
    }
}

struct OwnedSnapshot final {
    state::MascotFileResult result{state::MascotFileResult::NotAttempted};
    std::uint64_t operation_errno{};
    std::uint64_t open_flags{};
    bool no_follow{};
    std::uint64_t bytes_transferred{};
    state::MascotStepResult parent_directory_result{
        state::MascotStepResult::NotAttempted};
    std::uint64_t parent_directory_errno{};
    state::MascotStepResult fsync_result{
        state::MascotStepResult::NotAttempted};
    std::uint64_t fsync_errno{};
    state::MascotStepResult rename_result{
        state::MascotStepResult::NotAttempted};
    std::uint64_t rename_errno{};
    state::MascotStepResult unlink_result{
        state::MascotStepResult::NotAttempted};
    std::uint64_t unlink_errno{};
    state::MascotFileMetadataView path_lstat_before;
    state::MascotFileMetadataView descriptor_before;
    state::MascotFileMetadataView descriptor_after;
    state::MascotFileMetadataView path_lstat_after;
    state::MascotFileMetadataView reopened_descriptor;
    std::vector<unsigned char> bytes;

    OwnedSnapshot() = default;
    OwnedSnapshot(const OwnedSnapshot&) = delete;
    OwnedSnapshot& operator=(const OwnedSnapshot&) = delete;
    OwnedSnapshot(OwnedSnapshot&&) = default;
    OwnedSnapshot& operator=(OwnedSnapshot&&) = delete;
    ~OwnedSnapshot() { cleanse(bytes); }

    state::MascotFileSnapshotView source_view() const noexcept {
        return {
            .result = result,
            .operation_errno = operation_errno,
            .open_flags = open_flags,
            .no_follow = no_follow,
            .bytes_transferred = bytes_transferred,
            .parent_directory_result = parent_directory_result,
            .parent_directory_errno = parent_directory_errno,
            .fsync_result = fsync_result,
            .fsync_errno = fsync_errno,
            .rename_result = rename_result,
            .rename_errno = rename_errno,
            .unlink_result = unlink_result,
            .unlink_errno = unlink_errno,
            .path_lstat_before = path_lstat_before,
            .descriptor_before = descriptor_before,
            .descriptor_after = descriptor_after,
            .path_lstat_after = path_lstat_after,
            .reopened_descriptor = reopened_descriptor,
            .exact_file_bytes = bytes,
        };
    }
};

inline OwnedSnapshot capture_read(const std::string& path) {
    OwnedSnapshot result;
    result.open_flags = static_cast<std::uint64_t>(
        O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
    result.no_follow = true;
    int error = 0;
    (void)lstat_path(path, result.path_lstat_before, error);
    if (result.path_lstat_before.present &&
        !regular_file(result.path_lstat_before)) {
        result.operation_errno = EINVAL;
        result.result = state::MascotFileResult::Failed;
        result.path_lstat_after = result.path_lstat_before;
        return result;
    }
    int descriptor;
    do {
        descriptor = open_no_symlinks(
            path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    } while (descriptor < 0 && errno == EINTR);
    if (descriptor < 0) {
        result.operation_errno = static_cast<std::uint64_t>(errno);
        result.result = errno == ENOENT || errno == ENOTDIR
            ? state::MascotFileResult::Missing
            : state::MascotFileResult::Failed;
        (void)lstat_path(path, result.path_lstat_after, error);
        return result;
    }
    if (!fstat_fd(descriptor, result.descriptor_before, error) ||
        !regular_file(result.descriptor_before)) {
        result.operation_errno = static_cast<std::uint64_t>(
            error == 0 ? EINVAL : error);
        result.result = state::MascotFileResult::Failed;
        close_fd(descriptor);
        (void)lstat_path(path, result.path_lstat_after, error);
        return result;
    }
    if (!read_to_end(descriptor, result.bytes, error)) {
        result.operation_errno = static_cast<std::uint64_t>(error);
        result.bytes_transferred = result.bytes.size();
        result.result = state::MascotFileResult::Partial;
        (void)fstat_fd(descriptor, result.descriptor_after, error);
        close_fd(descriptor);
        (void)lstat_path(path, result.path_lstat_after, error);
        return result;
    }
    result.bytes_transferred = result.bytes.size();
    if (!fstat_fd(descriptor, result.descriptor_after, error)) {
        result.operation_errno = static_cast<std::uint64_t>(error);
        result.result = state::MascotFileResult::Failed;
        close_fd(descriptor);
        (void)lstat_path(path, result.path_lstat_after, error);
        return result;
    }
    close_fd(descriptor);
    if (!lstat_path(path, result.path_lstat_after, error)) {
        result.operation_errno = static_cast<std::uint64_t>(error);
        result.result = state::MascotFileResult::Failed;
        return result;
    }

    int reopened;
    do {
        reopened = open_no_symlinks(
            path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    } while (reopened < 0 && errno == EINTR);
    if (reopened < 0 ||
        !fstat_fd(reopened, result.reopened_descriptor, error) ||
        !regular_file(result.reopened_descriptor)) {
        result.operation_errno = static_cast<std::uint64_t>(
            reopened < 0 ? errno : error);
        result.result = state::MascotFileResult::Failed;
        close_fd(reopened);
        return result;
    }
    std::vector<unsigned char> verified;
    const bool read_again = read_to_end(reopened, verified, error);
    close_fd(reopened);
#ifdef KPI_P1_MASCOT_SECRET_SOURCE_CAPTURE_TEST_SETUP
    if (read_again && !verified.empty() &&
        consume_test_fault(TestFault::ReopenMismatch))
        verified.back() ^= 1U;
#endif
    const bool stable =
        result.path_lstat_before == result.descriptor_before &&
        result.descriptor_before == result.descriptor_after &&
        result.descriptor_after == result.reopened_descriptor &&
        result.reopened_descriptor == result.path_lstat_after &&
        result.path_lstat_before == result.path_lstat_after &&
        read_again && verified == result.bytes;
    cleanse(verified);
    if (!stable) {
        result.operation_errno = static_cast<std::uint64_t>(
            error == 0 ? EIO : error);
        result.result = state::MascotFileResult::Failed;
        return result;
    }
    result.result = state::MascotFileResult::Captured;
    return result;
}

} // namespace detail

// Preserve the exact no-symlink unlink outcome before the source exception
// unwinds. The hook records this in the versioned abort-prefix lane and keeps
// the success family MISSING; it never upgrades an abort to a family close.
inline AbortUnlinkOutcome unlink_cache_for_abort(
        const std::string& path, AbortClass abort_class) noexcept {
    AbortUnlinkOutcome outcome{
        .abort_class = abort_class,
        .succeeded = false,
        .operation_errno = 0,
        .path_lstat_before = {},
        .path_lstat_after = {},
    };
    const auto retain = [&]() noexcept {
        (void)state::MascotSecretStateSourceBridge::
            abort_cache_unlink_noexcept(
                abort_class, path, outcome.succeeded,
                outcome.operation_errno, outcome.path_lstat_before,
                outcome.path_lstat_after);
        return outcome;
    };
    int directory = AT_FDCWD;
    bool close_directory = false;
    try {
        std::string parent;
        std::string basename;
        if (!detail::split_relative_path(path, parent, basename)) {
            outcome.operation_errno = EINVAL;
            return retain();
        }
        if (!parent.empty()) {
            do {
                directory = detail::open_no_symlinks(
                    parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                        O_NONBLOCK);
            } while (directory < 0 && errno == EINTR);
            if (directory < 0) {
                outcome.operation_errno = static_cast<std::uint64_t>(errno);
                return retain();
            }
            close_directory = true;
        }
        int before_error = 0;
        const bool before_present = detail::fstatat_path(
            directory, basename, outcome.path_lstat_before, before_error);
        if (before_present &&
            !detail::regular_file(outcome.path_lstat_before)) {
            outcome.operation_errno = EINVAL;
            if (close_directory) detail::close_fd(directory);
            return retain();
        }
        int unlink_result;
        do {
            unlink_result = ::unlinkat(directory, basename.c_str(), 0);
        } while (unlink_result != 0 && errno == EINTR);
        const int unlink_error = unlink_result == 0 ? 0 : errno;
        int after_error = 0;
        const bool after_present = detail::fstatat_path(
            directory, basename, outcome.path_lstat_after, after_error);
        if (close_directory) detail::close_fd(directory);
        outcome.succeeded = unlink_result == 0 && !after_present &&
            after_error == ENOENT;
        outcome.operation_errno = static_cast<std::uint64_t>(
            outcome.succeeded ? 0 :
            (unlink_error != 0 ? unlink_error :
             (after_error != 0 ? after_error : EIO)));
        return retain();
    } catch (...) {
        if (close_directory) detail::close_fd(directory);
        outcome.operation_errno = ENOMEM;
        return retain();
    }
}

namespace detail {
SecretBytes octet_file_bytes(const octetStream&);
OwnedSnapshot capture_write(
    const std::string&, std::span<const unsigned char>);
OwnedSnapshot capture_prep_mac_write(
    const std::string&, std::string_view,
    std::span<const unsigned char>);
} // namespace detail

inline void require_recorded(bool retained) {
    if (retained) return;
    state::MascotSecretStateSourceBridge::unavailable_noexcept();
    throw std::runtime_error("P1-MASCOT-secret-state-capture-failed");
}

template<class Value>
detail::SecretBytes packed_secret(const Value& value) {
    octetStream packed;
    value.pack(packed);
    std::vector<unsigned char> bytes(packed.get_length());
    if (!bytes.empty())
        std::memcpy(bytes.data(), packed.get_data(), bytes.size());
    return detail::SecretBytes(std::move(bytes));
}

template<class CompleteKey>
detail::SecretBytes packed_complete_key(const CompleteKey& key) {
    // MP-SPDZ's inherited-scalar comparison chooses static reuse, but a zero
    // scalar does not prove that OTTripleSetup has no live bytes. Preserve the
    // whole object and carry the source branch/presence bit separately.
    return packed_secret(key);
}

template<class Share>
std::string canonical_cache_domain() {
    octetStream specification;
    Share::specification(specification);
    static constexpr char digits[] = "0123456789abcdef";
    std::string result = "Mascot-Secrets/" +
        std::string(Share::clear::type_short()) + "/" +
        std::to_string(Share::clear::length()) + "/specification=";
    result.reserve(result.size() + 2 * specification.get_length());
    for (std::size_t index = 0; index < specification.get_length(); ++index) {
        const auto byte = specification.get_data()[index];
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 15]);
    }
    return result;
}

template<class Share, class CompleteKey>
void record_setup_begin(
        std::string_view diagnostic_path, bool initialized,
        const CompleteKey& key) {
    auto packed = packed_complete_key(key);
    require_recorded(state::MascotSecretStateSourceBridge::setup_begin(
        canonical_cache_domain<Share>(), diagnostic_path,
        static_cast<std::uint64_t>(OnlineOptions::singleton.batch_size),
        static_cast<std::uint64_t>(OnlineOptions::singleton.bucket_size),
        static_cast<std::uint64_t>(
            OnlineOptions::singleton.security_parameter),
        OnlineOptions::singleton.use_security_parameter,
        OTExtensionWithMatrix(0).use_kos(), initialized,
        packed.source_view()));
}

template<class OnlineShare, class PrepScalar, class OnlineScalar>
void record_scalar_state_begin(
        std::string_view diagnostic_path,
        const PrepScalar& prep_scalar_before,
        const OnlineScalar& online_scalar_before) {
    auto packed_prep = packed_secret(prep_scalar_before);
    auto packed_online = packed_secret(online_scalar_before);
    require_recorded(state::MascotSecretStateSourceBridge::scalar_state_begin(
        canonical_cache_domain<typename OnlineShare::prep_type>(),
        diagnostic_path,
        static_cast<std::uint64_t>(OnlineOptions::singleton.batch_size),
        static_cast<std::uint64_t>(OnlineOptions::singleton.bucket_size),
        static_cast<std::uint64_t>(
            OnlineOptions::singleton.security_parameter),
        OnlineOptions::singleton.use_security_parameter,
        OTExtensionWithMatrix(0).use_kos(), packed_prep.source_view(),
        packed_online.source_view()));
}

template<class CompleteKey>
void record_local_validation(
        const CompleteKey& key, std::string_view reason) {
    auto packed = packed_complete_key(key);
    require_recorded(
        state::MascotSecretStateSourceBridge::cache_local_validation(
            reason.empty() ? state::MascotStepResult::Succeeded
                           : state::MascotStepResult::Failed,
            reason.empty(), packed.source_view(), reason));
}

inline void record_peer_validation(
        bool succeeded, std::string_view reason) {
    require_recorded(
        state::MascotSecretStateSourceBridge::cache_peer_validation(
            succeeded ? state::MascotStepResult::Succeeded
                      : state::MascotStepResult::Failed,
            reason));
}

template<class CompleteKey>
void record_regeneration(const CompleteKey& key) {
    auto packed = packed_complete_key(key);
    require_recorded(
        state::MascotSecretStateSourceBridge::regeneration(
            true, packed.source_view()));
}

template<class CompleteKey>
void record_write_candidate(
        const CompleteKey& before, const CompleteKey& after,
        const octetStream& file) {
    auto packed_before = packed_complete_key(before);
    auto packed_after = packed_complete_key(after);
    auto raw = detail::octet_file_bytes(file);
    require_recorded(
        state::MascotSecretStateSourceBridge::write_candidate(
            true, packed_before.source_view(), true,
            packed_after.source_view(), raw.source_view()));
}

template<class CompleteKey>
class PendingWriteCandidate final {
    detail::SecretBytes packed_before_;
    bool finished_{};
public:
    explicit PendingWriteCandidate(const CompleteKey& before)
        : packed_before_(packed_complete_key(before)) {}
    PendingWriteCandidate(const PendingWriteCandidate&) = delete;
    PendingWriteCandidate& operator=(const PendingWriteCandidate&) = delete;
    ~PendingWriteCandidate() {
        if (!finished_)
            state::MascotSecretStateSourceBridge::unavailable_noexcept();
    }
    void finish(const CompleteKey& after, const octetStream& file) {
        auto packed_after = packed_complete_key(after);
        auto raw = detail::octet_file_bytes(file);
        require_recorded(
            state::MascotSecretStateSourceBridge::write_candidate(
                true, packed_before_.source_view(), true,
                packed_after.source_view(), raw.source_view()));
        finished_ = true;
    }
};

template<class CompleteKey>
PendingWriteCandidate<CompleteKey> begin_write_candidate(
        const CompleteKey& before) {
    return PendingWriteCandidate<CompleteKey>(before);
}

template<class CompleteKey>
class PendingBitPrepDerivation final {
    detail::SecretBytes packed_before_;
    detail::SecretBytes packed_derived_;
    bool aliases_main_{};
    bool derived_captured_{};
    bool finished_{};
public:
    PendingBitPrepDerivation(
            const CompleteKey& before, bool aliases_main)
        : packed_before_(packed_complete_key(before)),
          aliases_main_(aliases_main) {}
    PendingBitPrepDerivation(const PendingBitPrepDerivation&) = delete;
    PendingBitPrepDerivation& operator=(
        const PendingBitPrepDerivation&) = delete;
    ~PendingBitPrepDerivation() {
        if (!finished_)
            state::MascotSecretStateSourceBridge::unavailable_noexcept();
    }
    void capture_derived(const CompleteKey& derived) {
        if (derived_captured_) {
            state::MascotSecretStateSourceBridge::unavailable_noexcept();
            throw std::runtime_error(
                "P1-MASCOT-bit-prep-derived-duplicate");
        }
        packed_derived_ = packed_complete_key(derived);
        derived_captured_ = true;
    }
    void finish(const CompleteKey& assigned_main_after) {
        if (!derived_captured_) {
            state::MascotSecretStateSourceBridge::unavailable_noexcept();
            throw std::runtime_error(
                "P1-MASCOT-bit-prep-derived-omitted");
        }
        auto packed_after = packed_complete_key(assigned_main_after);
        require_recorded(
            state::MascotSecretStateSourceBridge::bit_prep_derived(
                packed_before_.source_view(), packed_after.source_view(),
                packed_derived_.source_view(), aliases_main_));
        finished_ = true;
    }
};

template<class CompleteKey>
PendingBitPrepDerivation<CompleteKey> begin_bit_prep_derivation(
        const CompleteKey& before, bool aliases_main) {
    return PendingBitPrepDerivation<CompleteKey>(before, aliases_main);
}

inline void write_file_and_record(
        const std::string& path, const octetStream& file) {
    auto raw = detail::octet_file_bytes(file);
    auto snapshot = detail::capture_write(path, raw.source_view());
    const bool succeeded =
        snapshot.result == state::MascotFileResult::Captured;
    const std::string reason = succeeded ? std::string() :
        "writeback-errno-" + std::to_string(snapshot.operation_errno);
    const bool retained = state::MascotSecretStateSourceBridge::writeback(
        path, succeeded ? state::MascotStepResult::Succeeded
                        : state::MascotStepResult::Failed,
        snapshot.source_view(), reason);
    if (!retained || !succeeded) {
        state::MascotSecretStateSourceBridge::unavailable_noexcept();
        throw file_error("cannot write to " + path);
    }
}

template<class ScalarKey>
class PendingPrepStaticInstall final {
    detail::SecretBytes packed_before_;
    detail::SecretBytes packed_expected_;
    bool finished_{};
public:
    PendingPrepStaticInstall(
            const ScalarKey& before, const ScalarKey& expected)
        : packed_before_(packed_secret(before)),
          packed_expected_(packed_secret(expected)) {}
    PendingPrepStaticInstall(const PendingPrepStaticInstall&) = delete;
    PendingPrepStaticInstall& operator=(
        const PendingPrepStaticInstall&) = delete;
    ~PendingPrepStaticInstall() {
        if (!finished_)
            state::MascotSecretStateSourceBridge::unavailable_noexcept();
    }
    void finish(const ScalarKey& after) {
        auto packed_after = packed_secret(after);
        require_recorded(
            state::MascotSecretStateSourceBridge::prep_static_installed(
                packed_before_.source_view(), packed_after.source_view(),
                packed_expected_.source_view()));
        finished_ = true;
    }
};

template<class ScalarKey>
PendingPrepStaticInstall<ScalarKey> begin_prep_static_install(
        const ScalarKey& before, const ScalarKey& expected) {
    return PendingPrepStaticInstall<ScalarKey>(before, expected);
}

template<class PrepShare>
void write_prep_mac_file_and_record(
        const Names& names,
        const typename PrepShare::mac_key_type& key) {
    using ScalarKey = typename PrepShare::mac_key_type;
    const std::string directory =
        get_prep_sub_dir<PrepShare>(names.num_players());
    const std::string path = (directory.empty() ? std::string(".") : directory)
        + "/Player-MAC-Keys-" + ScalarKey::type_short() + "-P" +
        std::to_string(names.my_num());
    detail::SecretVectorStreamBuf buffer;
    std::ostream output(&buffer);
    output << names.num_players() << std::endl;
    key.output(output, true);
    if (output.fail()) {
        state::MascotSecretStateSourceBridge::unavailable_noexcept();
        throw IO_Error("cannot serialize " + path);
    }
    auto snapshot = detail::capture_prep_mac_write(
        path, directory, buffer.source_view());
    const bool succeeded =
        snapshot.result == state::MascotFileResult::Captured;
    const std::string reason = succeeded ? std::string() :
        "prep-mac-write-errno-" +
            std::to_string(snapshot.operation_errno);
    const bool retained = state::MascotSecretStateSourceBridge::
        prep_mac_file_write(
            path, succeeded ? state::MascotStepResult::Succeeded
                            : state::MascotStepResult::Failed,
            snapshot.source_view(), buffer.source_view(), reason);
    if (!retained || !succeeded) {
        state::MascotSecretStateSourceBridge::unavailable_noexcept();
        throw IO_Error("cannot write to " + path);
    }
}

template<class CompleteKey, class ScalarKey>
void record_static_installed(
        const CompleteKey& complete, const ScalarKey& scalar_before,
        const ScalarKey& scalar_after, const ScalarKey& expected_scalar) {
    auto packed_complete = packed_complete_key(complete);
    auto packed_scalar_before = packed_secret(scalar_before);
    auto packed_scalar_after = packed_secret(scalar_after);
    auto packed_expected = packed_secret(expected_scalar);
    require_recorded(
        state::MascotSecretStateSourceBridge::static_installed(
            true, packed_complete.source_view(),
            packed_scalar_before.source_view(),
            packed_scalar_after.source_view(), packed_expected.source_view()));
}

template<class CompleteKey, class ScalarKey, class PrepScalarKey>
void record_teardown(
        const CompleteKey& complete_before, const ScalarKey& scalar_before,
        const CompleteKey& complete_after, const ScalarKey& scalar_after,
        const PrepScalarKey& prep_scalar_before,
        const PrepScalarKey& prep_scalar_after) {
    auto packed_complete_before = packed_complete_key(complete_before);
    auto packed_scalar_before = packed_secret(scalar_before);
    auto packed_complete_after = packed_complete_key(complete_after);
    auto packed_scalar_after = packed_secret(scalar_after);
    auto packed_prep_before = packed_secret(prep_scalar_before);
    auto packed_prep_after = packed_secret(prep_scalar_after);
    require_recorded(state::MascotSecretStateSourceBridge::teardown(
        true, packed_complete_before.source_view(),
        packed_scalar_before.source_view(), false,
        packed_complete_after.source_view(), packed_scalar_after.source_view(),
        packed_prep_before.source_view(), packed_prep_after.source_view()));
}

template<class CompleteKey, class ScalarKey, class PrepScalarKey>
class PendingTeardown final {
    detail::SecretBytes complete_before_;
    detail::SecretBytes scalar_before_;
    detail::SecretBytes prep_scalar_before_;
    bool finished_{};
public:
    PendingTeardown(
            const CompleteKey& complete_before,
            const ScalarKey& scalar_before,
            const PrepScalarKey& prep_scalar_before)
        : complete_before_(packed_complete_key(complete_before)),
          scalar_before_(packed_secret(scalar_before)),
          prep_scalar_before_(packed_secret(prep_scalar_before)) {}
    PendingTeardown(const PendingTeardown&) = delete;
    PendingTeardown& operator=(const PendingTeardown&) = delete;
    ~PendingTeardown() {
        if (!finished_)
            state::MascotSecretStateSourceBridge::unavailable_noexcept();
    }
    void finish(
            const CompleteKey& complete_after,
            const ScalarKey& scalar_after,
            const PrepScalarKey& prep_scalar_after) {
        auto packed_complete_after = packed_complete_key(complete_after);
        auto packed_scalar_after = packed_secret(scalar_after);
        auto packed_prep_after = packed_secret(prep_scalar_after);
        require_recorded(state::MascotSecretStateSourceBridge::teardown(
            true, complete_before_.source_view(), scalar_before_.source_view(),
            false, packed_complete_after.source_view(),
            packed_scalar_after.source_view(),
            prep_scalar_before_.source_view(),
            packed_prep_after.source_view()));
        finished_ = true;
    }
};

template<class CompleteKey, class ScalarKey, class PrepScalarKey>
PendingTeardown<CompleteKey, ScalarKey, PrepScalarKey> begin_teardown(
        const CompleteKey& complete_before, const ScalarKey& scalar_before,
        const PrepScalarKey& prep_scalar_before) {
    return PendingTeardown<CompleteKey, ScalarKey, PrepScalarKey>(
        complete_before, scalar_before, prep_scalar_before);
}

} // namespace kpb_mp_spdz_p1_mascot

namespace kpb_mp_spdz_p1_mascot {

class CapturedCacheFile final {
    std::string path_;
    detail::OwnedSnapshot snapshot_;
public:
    CapturedCacheFile(std::string path, detail::OwnedSnapshot snapshot)
        : path_(std::move(path)), snapshot_(std::move(snapshot)) {}
    CapturedCacheFile(const CapturedCacheFile&) = delete;
    CapturedCacheFile& operator=(const CapturedCacheFile&) = delete;
    CapturedCacheFile(CapturedCacheFile&&) = default;
    CapturedCacheFile& operator=(CapturedCacheFile&&) = delete;

    bool record_open() const noexcept {
        return state::MascotSecretStateSourceBridge::cache_opened(
            path_, snapshot_.source_view());
    }

    void input(octetStream& output) const {
        if (snapshot_.result != state::MascotFileResult::Captured)
            throw file_error("cannot read from " + path_);
        if (snapshot_.bytes.size() < sizeof(std::size_t))
            throw IO_Error("not enough data");
        std::size_t declared = 0;
        std::memcpy(&declared, snapshot_.bytes.data(), sizeof(declared));
        if (declared > snapshot_.bytes.size() - sizeof(declared))
            throw IO_Error("not enough data");
        output.reset_write_head();
        output.append(
            snapshot_.bytes.data() + sizeof(declared), declared);
        output.reset_read_head();
    }
};

inline CapturedCacheFile capture_cache_file(const std::string& path) {
    return CapturedCacheFile(path, detail::capture_read(path));
}

namespace detail {

inline SecretBytes octet_file_bytes(const octetStream& stream) {
    const auto length = stream.get_length();
    if (length > std::vector<unsigned char>().max_size() - sizeof(length))
        throw std::length_error("P1-MASCOT-octet-file-too-large");
    std::vector<unsigned char> bytes(sizeof(length) + length);
    std::memcpy(bytes.data(), &length, sizeof(length));
    if (length != 0)
        std::memcpy(
            bytes.data() + sizeof(length), stream.get_data(), length);
    return SecretBytes(std::move(bytes));
}

inline bool write_all(
        int descriptor, std::span<const unsigned char> bytes,
        std::uint64_t& written, int& error) noexcept {
    while (written < bytes.size()) {
        ssize_t count;
        do {
            count = ::write(
                descriptor, bytes.data() + written,
                bytes.size() - static_cast<std::size_t>(written));
        } while (count < 0 && errno == EINTR);
        if (count <= 0) {
            error = count < 0 ? errno : EIO;
            return false;
        }
        written += static_cast<std::uint64_t>(count);
    }
    error = 0;
    return true;
}

inline OwnedSnapshot capture_write(
        const std::string& path,
        std::span<const unsigned char> exact_bytes) {
    OwnedSnapshot result;
    constexpr int flags = O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
        O_NONBLOCK | O_NOFOLLOW;
    result.open_flags = static_cast<std::uint64_t>(flags);
    result.no_follow = true;
    int error = 0;
    (void)lstat_path(path, result.path_lstat_before, error);
    if (result.path_lstat_before.present &&
        !regular_file(result.path_lstat_before)) {
        result.operation_errno = EINVAL;
        result.result = state::MascotFileResult::Failed;
        result.path_lstat_after = result.path_lstat_before;
        return result;
    }
    int descriptor;
    do {
        descriptor = open_no_symlinks(path, flags, 0666);
    } while (descriptor < 0 && errno == EINTR);
    if (descriptor < 0) {
        result.operation_errno = static_cast<std::uint64_t>(errno);
        result.result = state::MascotFileResult::Failed;
        (void)lstat_path(path, result.path_lstat_after, error);
        return result;
    }
    if (!fstat_fd(descriptor, result.descriptor_before, error) ||
        !regular_file(result.descriptor_before)) {
        result.operation_errno = static_cast<std::uint64_t>(error);
        if (result.operation_errno == 0) result.operation_errno = EINVAL;
        result.result = state::MascotFileResult::Failed;
        close_fd(descriptor);
        (void)lstat_path(path, result.path_lstat_after, error);
        return result;
    }
    std::uint64_t written = 0;
    const bool complete = write_all(descriptor, exact_bytes, written, error);
    result.bytes_transferred = written;
    if (!fstat_fd(descriptor, result.descriptor_after, error) && complete) {
        result.operation_errno = static_cast<std::uint64_t>(error);
        result.result = state::MascotFileResult::Failed;
    }
    if (complete && result.result != state::MascotFileResult::Failed) {
        int fsync_result;
#ifdef KPI_P1_MASCOT_SECRET_SOURCE_CAPTURE_TEST_SETUP
        if (consume_test_fault(TestFault::FsyncFailure)) {
            fsync_result = -1;
            errno = EIO;
        }
        else
#endif
        do {
            fsync_result = ::fsync(descriptor);
        } while (fsync_result != 0 && errno == EINTR);
        if (fsync_result == 0)
            result.fsync_result = state::MascotStepResult::Succeeded;
        else {
            result.fsync_result = state::MascotStepResult::Failed;
            result.fsync_errno = static_cast<std::uint64_t>(errno);
            result.operation_errno = result.fsync_errno;
            result.result = state::MascotFileResult::Failed;
        }
    } else if (!complete) {
        result.operation_errno = static_cast<std::uint64_t>(error);
        result.result = state::MascotFileResult::Partial;
    }
    close_fd(descriptor);
    (void)lstat_path(path, result.path_lstat_after, error);

    int reopened;
    do {
        reopened = open_no_symlinks(
            path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    } while (reopened < 0 && errno == EINTR);
    if (reopened >= 0) {
        (void)fstat_fd(reopened, result.reopened_descriptor, error);
        if (!regular_file(result.reopened_descriptor) &&
            result.operation_errno == 0)
            result.operation_errno = EINVAL;
        if (!read_to_end(reopened, result.bytes, error) &&
            result.operation_errno == 0)
            result.operation_errno = static_cast<std::uint64_t>(error);
        close_fd(reopened);
    } else if (result.operation_errno == 0) {
        result.operation_errno = static_cast<std::uint64_t>(errno);
    }
    const bool stable_identity =
        same_identity(result.descriptor_before, result.descriptor_after) &&
        same_identity(result.descriptor_after, result.path_lstat_after) &&
        same_identity(result.path_lstat_after, result.reopened_descriptor) &&
        (!result.path_lstat_before.present ||
         same_identity(result.path_lstat_before, result.descriptor_before));
    if (complete && result.operation_errno == 0 && stable_identity &&
        result.bytes.size() == exact_bytes.size() &&
        std::equal(result.bytes.begin(), result.bytes.end(),
                   exact_bytes.begin()))
        result.result = state::MascotFileResult::Captured;
    else if (result.result == state::MascotFileResult::NotAttempted)
        result.result = state::MascotFileResult::Failed;
    return result;
}

inline OwnedSnapshot capture_prep_mac_write(
        const std::string& path, std::string_view directory,
        std::span<const unsigned char> exact_bytes) {
    int directory_error = 0;
    bool directory_ready = false;
    try {
        directory_ready =
            ensure_relative_directory_no_symlinks(directory, directory_error);
    } catch (...) {
        directory_error = ENOMEM;
    }
    if (!directory_ready) {
        OwnedSnapshot result;
        result.result = state::MascotFileResult::Failed;
        result.operation_errno = static_cast<std::uint64_t>(
            directory_error == 0 ? EIO : directory_error);
        result.open_flags = static_cast<std::uint64_t>(
            O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NONBLOCK |
                O_NOFOLLOW);
        result.no_follow = true;
        result.parent_directory_result = state::MascotStepResult::Failed;
        result.parent_directory_errno = result.operation_errno;
        int ignored = 0;
        (void)lstat_path(path, result.path_lstat_before, ignored);
        result.path_lstat_after = result.path_lstat_before;
        return result;
    }
    auto result = capture_write(path, exact_bytes);
    result.parent_directory_result = state::MascotStepResult::Succeeded;
    result.parent_directory_errno = 0;
    return result;
}

} // namespace detail

} // namespace kpb_mp_spdz_p1_mascot
