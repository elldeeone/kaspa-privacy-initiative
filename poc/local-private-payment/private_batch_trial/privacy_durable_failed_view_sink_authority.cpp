#include "privacy_durable_failed_view_sink_authority.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstring>
#include <fcntl.h>
#include <linux/falloc.h>
#include <limits>
#include <openssl/sha.h>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpb::measurement::durable_failed_view {
namespace {

constexpr char SINK_DIRECTORY[] = "failed-view";
constexpr char PAYLOAD_NAME[] = "payload.kpb";
constexpr char MARKER_NAME[] = "commit.kpb";
constexpr std::size_t MARKER_BYTES = 104;
constexpr long TMPFS_MAGIC = 0x01021994;
constexpr long RAMFS_MAGIC = 0x858458f6;

[[noreturn]] void refuse() {
    throw std::runtime_error("durable-failed-view-sink-refused");
}
void need(bool value) { if (!value) refuse(); }

void close_fd(int& fd) noexcept {
    if (fd >= 0) {
        while (::close(fd) < 0 && errno == EINTR) {}
        fd = -1;
    }
}

bool private_directory(const struct stat& value) {
    return S_ISDIR(value.st_mode) && value.st_uid == ::getuid() &&
        (value.st_mode & 07777) == 0700;
}

bool private_regular(const struct stat& value) {
    return S_ISREG(value.st_mode) && value.st_uid == ::getuid() &&
        (value.st_mode & 07777) == 0600 && value.st_nlink == 1;
}

bool disk_backed(int fd) {
    struct statfs filesystem{};
    return ::fstatfs(fd, &filesystem) == 0 &&
        filesystem.f_type != TMPFS_MAGIC &&
        filesystem.f_type != RAMFS_MAGIC;
}

void write_exact(int fd, std::span<const unsigned char> value) {
    std::size_t offset = 0;
    while (offset < value.size()) {
        const auto written = ::pwrite(
            fd, value.data() + offset, value.size() - offset,
            static_cast<off_t>(offset));
        if (written < 0 && errno == EINTR) continue;
        need(written > 0);
        offset += static_cast<std::size_t>(written);
    }
}

std::vector<unsigned char> read_exact(int fd, std::uint64_t size) {
    need(size <= static_cast<std::uint64_t>(
        std::numeric_limits<std::size_t>::max()));
    std::vector<unsigned char> result(static_cast<std::size_t>(size));
    std::size_t offset = 0;
    while (offset < result.size()) {
        const auto received = ::pread(
            fd, result.data() + offset, result.size() - offset,
            static_cast<off_t>(offset));
        if (received < 0 && errno == EINTR) continue;
        need(received > 0);
        offset += static_cast<std::size_t>(received);
    }
    unsigned char trailing{};
    need(::pread(fd, &trailing, 1, static_cast<off_t>(size)) == 0);
    return result;
}

std::array<unsigned char, 32> hash(
        std::span<const unsigned char> value) {
    std::array<unsigned char, 32> result{};
    need(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}

void put_le(std::span<unsigned char> output, std::size_t offset,
            std::uint64_t value, unsigned bytes) {
    need(offset + bytes <= output.size());
    for (unsigned index = 0; index < bytes; ++index)
        output[offset + index] = static_cast<unsigned char>(value >> (8 * index));
}

std::array<unsigned char, MARKER_BYTES> marker_bytes(
        std::uint64_t payload_size,
        const std::array<unsigned char, 32>& payload_hash,
        const struct stat& directory,
        const struct stat& payload,
        const struct stat& marker) {
    std::array<unsigned char, MARKER_BYTES> result{};
    constexpr std::array<unsigned char, 8> magic{
        'K', 'P', 'B', 'D', 'F', 'V', '1', 0};
    std::copy(magic.begin(), magic.end(), result.begin());
    put_le(result, 8, 1, 4);
    put_le(result, 16, payload_size, 8);
    std::copy(payload_hash.begin(), payload_hash.end(), result.begin() + 24);
    put_le(result, 56, static_cast<std::uint64_t>(payload.st_dev), 8);
    put_le(result, 64, static_cast<std::uint64_t>(payload.st_ino), 8);
    put_le(result, 72, static_cast<std::uint64_t>(marker.st_dev), 8);
    put_le(result, 80, static_cast<std::uint64_t>(marker.st_ino), 8);
    put_le(result, 88, static_cast<std::uint64_t>(directory.st_dev), 8);
    put_le(result, 96, static_cast<std::uint64_t>(directory.st_ino), 8);
    return result;
}

int open_read_only_named(int directory, const char* name) {
    const int fd = ::openat(
        directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    need(fd >= 0 && (::fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDONLY &&
         (::fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);
    return fd;
}

} // namespace

struct DurableFailedViewSinkReservationAuthority::Storage final {
    int directory_fd{-1};
    int payload_writer_fd{-1};
    int marker_writer_fd{-1};
    std::uint64_t directory_device{};
    std::uint64_t directory_inode{};
    std::uint64_t payload_device{};
    std::uint64_t payload_inode{};
    std::uint64_t marker_device{};
    std::uint64_t marker_inode{};
    std::uint64_t reserved_payload_bytes{};
    std::uint64_t prefix_bytes{};
    ~Storage() {
        close_fd(payload_writer_fd);
        close_fd(marker_writer_fd);
        close_fd(directory_fd);
    }
};

struct DurableFailedViewSinkAuthority::Storage final {
    int directory_fd{-1};
    int payload_read_fd{-1};
    int marker_read_fd{-1};
    std::uint64_t directory_device{};
    std::uint64_t directory_inode{};
    std::uint64_t payload_device{};
    std::uint64_t payload_inode{};
    std::uint64_t marker_device{};
    std::uint64_t marker_inode{};
    std::uint64_t payload_size{};
    std::array<unsigned char, 32> payload_hash{};
    std::array<unsigned char, MARKER_BYTES> marker{};
    ~Storage() {
        close_fd(payload_read_fd);
        close_fd(marker_read_fd);
        close_fd(directory_fd);
    }
};

DurableFailedViewSinkReservationAuthority::
DurableFailedViewSinkReservationAuthority(std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }
DurableFailedViewSinkReservationAuthority::
DurableFailedViewSinkReservationAuthority(
        DurableFailedViewSinkReservationAuthority&&) noexcept = default;
DurableFailedViewSinkReservationAuthority::
~DurableFailedViewSinkReservationAuthority() = default;

DurableFailedViewSinkAuthority::DurableFailedViewSinkAuthority(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }
DurableFailedViewSinkAuthority::DurableFailedViewSinkAuthority(
        DurableFailedViewSinkAuthority&&) noexcept = default;
DurableFailedViewSinkAuthority::~DurableFailedViewSinkAuthority() = default;

DurableFailedViewSinkUnavailableAuthority::
DurableFailedViewSinkUnavailableAuthority(
        std::unique_ptr<
            DurableFailedViewSinkReservationAuthority::Storage> storage,
        unsigned char failure_stage, int error_number) noexcept
    : storage_(std::move(storage)),
      failure_stage_(failure_stage),
      error_number_(error_number) {}
DurableFailedViewSinkUnavailableAuthority::
DurableFailedViewSinkUnavailableAuthority(
        DurableFailedViewSinkUnavailableAuthority&&) noexcept = default;
DurableFailedViewSinkUnavailableAuthority::
~DurableFailedViewSinkUnavailableAuthority() = default;

#ifdef KPB_DURABLE_FAILED_VIEW_SINK_TEST_SETUP
std::unique_ptr<DurableFailedViewSinkReservationAuthority::Storage>
DurableFailedViewSinkTestBridge::reserve_storage(
        const std::string& parent_directory,
        std::uint64_t exact_reserved_payload_bytes,
        bool inject_fallocate_failure) {
    need(!parent_directory.empty() && exact_reserved_payload_bytes > 0 &&
         exact_reserved_payload_bytes <= static_cast<std::uint64_t>(LLONG_MAX));
    auto storage =
        std::make_unique<DurableFailedViewSinkReservationAuthority::Storage>();
    int parent_fd = -1;
    try {
        parent_fd = ::open(parent_directory.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        struct stat parent{};
        need(parent_fd >= 0 && ::fstat(parent_fd, &parent) == 0 &&
             private_directory(parent) && disk_backed(parent_fd));
        need(::mkdirat(parent_fd, SINK_DIRECTORY, 0700) == 0);
        need(::fsync(parent_fd) == 0);
        storage->directory_fd = ::openat(parent_fd, SINK_DIRECTORY,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        close_fd(parent_fd);
        struct stat directory{};
        need(storage->directory_fd >= 0 &&
             ::fstat(storage->directory_fd, &directory) == 0 &&
             private_directory(directory) &&
             disk_backed(storage->directory_fd));
        storage->directory_device =
            static_cast<std::uint64_t>(directory.st_dev);
        storage->directory_inode =
            static_cast<std::uint64_t>(directory.st_ino);

        storage->payload_writer_fd = ::openat(
            storage->directory_fd, PAYLOAD_NAME,
            O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
        storage->marker_writer_fd = ::openat(
            storage->directory_fd, MARKER_NAME,
            O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
        need(storage->payload_writer_fd >= 0 &&
             storage->marker_writer_fd >= 0);
        // Make both names durable before any capacity reservation.  If
        // fallocate fails, the typed unavailable arm still owns the two exact
        // precreated inodes instead of losing them in an exception.
        need(::fsync(storage->directory_fd) == 0);
        struct stat payload_preallocation{};
        struct stat marker_preallocation{};
        need(::fstat(storage->payload_writer_fd, &payload_preallocation) == 0 &&
             ::fstat(storage->marker_writer_fd, &marker_preallocation) == 0 &&
             private_regular(payload_preallocation) &&
             private_regular(marker_preallocation));
        storage->payload_device =
            static_cast<std::uint64_t>(payload_preallocation.st_dev);
        storage->payload_inode =
            static_cast<std::uint64_t>(payload_preallocation.st_ino);
        storage->marker_device =
            static_cast<std::uint64_t>(marker_preallocation.st_dev);
        storage->marker_inode =
            static_cast<std::uint64_t>(marker_preallocation.st_ino);
        storage->reserved_payload_bytes = exact_reserved_payload_bytes;
        if (inject_fallocate_failure) return storage;
        need(::fallocate(storage->payload_writer_fd, FALLOC_FL_KEEP_SIZE, 0,
                         static_cast<off_t>(exact_reserved_payload_bytes)) == 0);
        need(::fallocate(storage->marker_writer_fd, FALLOC_FL_KEEP_SIZE, 0,
                         static_cast<off_t>(MARKER_BYTES)) == 0);

        struct stat payload{};
        struct stat marker{};
        need(::fstat(storage->payload_writer_fd, &payload) == 0 &&
             ::fstat(storage->marker_writer_fd, &marker) == 0 &&
             private_regular(payload) && private_regular(marker) &&
             payload.st_size == 0 && marker.st_size == 0 &&
             static_cast<std::uint64_t>(payload.st_blocks) * 512 >=
                 exact_reserved_payload_bytes &&
             static_cast<std::uint64_t>(marker.st_blocks) * 512 >=
                 MARKER_BYTES &&
             (payload.st_dev != marker.st_dev ||
              payload.st_ino != marker.st_ino));
        need(static_cast<std::uint64_t>(payload.st_dev) ==
                 storage->payload_device &&
             static_cast<std::uint64_t>(payload.st_ino) ==
                 storage->payload_inode &&
             static_cast<std::uint64_t>(marker.st_dev) ==
                 storage->marker_device &&
             static_cast<std::uint64_t>(marker.st_ino) ==
                 storage->marker_inode);
        need(::fsync(storage->payload_writer_fd) == 0 &&
             ::fsync(storage->marker_writer_fd) == 0 &&
             ::fsync(storage->directory_fd) == 0);
        return storage;
    } catch (...) {
        close_fd(parent_fd);
        throw;
    }
}

DurableFailedViewSinkReservationAuthority
DurableFailedViewSinkTestBridge::reserve(
        const std::string& parent_directory,
        std::uint64_t exact_reserved_payload_bytes) {
    return DurableFailedViewSinkReservationAuthority(reserve_storage(
        parent_directory, exact_reserved_payload_bytes, false));
}

DurableFailedViewSinkUnavailableAuthority
DurableFailedViewSinkTestBridge::reserve_unavailable(
        const std::string& parent_directory,
        std::uint64_t exact_reserved_payload_bytes,
        TestOnlyDurableFailedViewSinkFault fault) {
    need(fault == TestOnlyDurableFailedViewSinkFault::Fallocate);
    return DurableFailedViewSinkUnavailableAuthority(
        reserve_storage(parent_directory, exact_reserved_payload_bytes, true),
        static_cast<unsigned char>(fault), ENOSPC);
}

void DurableFailedViewSinkTestBridge::write_prefix_and_sync(
        DurableFailedViewSinkReservationAuthority& supplied,
        std::span<const unsigned char> prefix) {
    auto* storage = supplied.storage_.get();
    need(storage != nullptr && storage->prefix_bytes == 0 && !prefix.empty() &&
         prefix.size() <= storage->reserved_payload_bytes);
    struct stat payload{};
    need(::fstat(storage->payload_writer_fd, &payload) == 0 &&
         private_regular(payload) && payload.st_size == 0 &&
         static_cast<std::uint64_t>(payload.st_dev) ==
             storage->payload_device &&
         static_cast<std::uint64_t>(payload.st_ino) ==
             storage->payload_inode);
    write_exact(storage->payload_writer_fd, prefix);
    need(::fsync(storage->payload_writer_fd) == 0 &&
         ::fsync(storage->directory_fd) == 0);
    storage->prefix_bytes = prefix.size();
}

DurableFailedViewSinkAuthority DurableFailedViewSinkTestBridge::commit(
        DurableFailedViewSinkReservationAuthority&& supplied,
        std::span<const unsigned char> payload_bytes) {
    auto output = std::make_unique<DurableFailedViewSinkAuthority::Storage>();
    auto storage = std::move(supplied.storage_);
    need(storage != nullptr && storage->prefix_bytes == 0 &&
         !payload_bytes.empty() &&
         payload_bytes.size() <= storage->reserved_payload_bytes);
    int payload_read = -1;
    int marker_read = -1;
    try {
        struct stat directory{};
        struct stat payload_before{};
        struct stat marker_before{};
        need(::fstat(storage->directory_fd, &directory) == 0 &&
             ::fstat(storage->payload_writer_fd, &payload_before) == 0 &&
             ::fstat(storage->marker_writer_fd, &marker_before) == 0 &&
             private_directory(directory) && private_regular(payload_before) &&
             private_regular(marker_before) && payload_before.st_size == 0 &&
             marker_before.st_size == 0 &&
             static_cast<std::uint64_t>(directory.st_dev) ==
                 storage->directory_device &&
             static_cast<std::uint64_t>(directory.st_ino) ==
                 storage->directory_inode &&
             static_cast<std::uint64_t>(payload_before.st_dev) ==
                 storage->payload_device &&
             static_cast<std::uint64_t>(payload_before.st_ino) ==
                 storage->payload_inode &&
             static_cast<std::uint64_t>(marker_before.st_dev) ==
                 storage->marker_device &&
             static_cast<std::uint64_t>(marker_before.st_ino) ==
                 storage->marker_inode);

        write_exact(storage->payload_writer_fd, payload_bytes);
        need(::fsync(storage->payload_writer_fd) == 0);
        struct stat payload_after{};
        struct stat marker_after{};
        need(::fstat(storage->payload_writer_fd, &payload_after) == 0 &&
             ::fstat(storage->marker_writer_fd, &marker_after) == 0 &&
             payload_after.st_size ==
                 static_cast<off_t>(payload_bytes.size()));
        const auto payload_hash = hash(payload_bytes);
        const auto marker = marker_bytes(
            payload_bytes.size(), payload_hash, directory,
            payload_after, marker_after);
        write_exact(storage->marker_writer_fd, marker);
        need(::fsync(storage->marker_writer_fd) == 0 &&
             ::fsync(storage->directory_fd) == 0);

        payload_read = open_read_only_named(storage->directory_fd, PAYLOAD_NAME);
        marker_read = open_read_only_named(storage->directory_fd, MARKER_NAME);
        struct stat payload_named{};
        struct stat marker_named{};
        need(::fstat(payload_read, &payload_named) == 0 &&
             ::fstat(marker_read, &marker_named) == 0 &&
             private_regular(payload_named) && private_regular(marker_named) &&
             static_cast<std::uint64_t>(payload_named.st_dev) ==
                 storage->payload_device &&
             static_cast<std::uint64_t>(payload_named.st_ino) ==
                 storage->payload_inode &&
             static_cast<std::uint64_t>(marker_named.st_dev) ==
                 storage->marker_device &&
             static_cast<std::uint64_t>(marker_named.st_ino) ==
                 storage->marker_inode &&
             payload_named.st_size ==
                 static_cast<off_t>(payload_bytes.size()) &&
             marker_named.st_size == static_cast<off_t>(MARKER_BYTES));

        close_fd(storage->payload_writer_fd);
        close_fd(storage->marker_writer_fd);
        need(read_exact(payload_read, payload_bytes.size()) ==
                 std::vector<unsigned char>(payload_bytes.begin(),
                                            payload_bytes.end()) &&
             read_exact(marker_read, MARKER_BYTES) ==
                 std::vector<unsigned char>(marker.begin(), marker.end()));

        output->directory_fd = std::exchange(storage->directory_fd, -1);
        output->payload_read_fd = std::exchange(payload_read, -1);
        output->marker_read_fd = std::exchange(marker_read, -1);
        output->directory_device = storage->directory_device;
        output->directory_inode = storage->directory_inode;
        output->payload_device = storage->payload_device;
        output->payload_inode = storage->payload_inode;
        output->marker_device = storage->marker_device;
        output->marker_inode = storage->marker_inode;
        output->payload_size = payload_bytes.size();
        output->payload_hash = payload_hash;
        output->marker = marker;
        return DurableFailedViewSinkAuthority(std::move(output));
    } catch (...) {
        close_fd(payload_read);
        close_fd(marker_read);
        throw;
    }
}

DurableFailedViewSinkUnavailableAuthority
DurableFailedViewSinkTestBridge::commit_unavailable(
        DurableFailedViewSinkReservationAuthority&& supplied,
        std::span<const unsigned char> payload_bytes,
        TestOnlyDurableFailedViewSinkFault fault) {
    auto storage = std::move(supplied.storage_);
    need(storage != nullptr && storage->prefix_bytes == 0 &&
         !payload_bytes.empty() &&
         payload_bytes.size() <= storage->reserved_payload_bytes &&
         fault != TestOnlyDurableFailedViewSinkFault::Fallocate);
    int error_number = EIO;
    try {
        struct stat directory{};
        struct stat payload_before{};
        struct stat marker_before{};
        need(::fstat(storage->directory_fd, &directory) == 0 &&
             ::fstat(storage->payload_writer_fd, &payload_before) == 0 &&
             ::fstat(storage->marker_writer_fd, &marker_before) == 0 &&
             private_directory(directory) && private_regular(payload_before) &&
             private_regular(marker_before) && payload_before.st_size == 0 &&
             marker_before.st_size == 0 &&
             static_cast<std::uint64_t>(payload_before.st_dev) ==
                 storage->payload_device &&
             static_cast<std::uint64_t>(payload_before.st_ino) ==
                 storage->payload_inode &&
             static_cast<std::uint64_t>(marker_before.st_dev) ==
                 storage->marker_device &&
             static_cast<std::uint64_t>(marker_before.st_ino) ==
                 storage->marker_inode);

        if (fault == TestOnlyDurableFailedViewSinkFault::WriteShort ||
            fault == TestOnlyDurableFailedViewSinkFault::Enospc) {
            const std::size_t partial_size =
                fault == TestOnlyDurableFailedViewSinkFault::WriteShort
                    ? std::max<std::size_t>(1, payload_bytes.size() / 2)
                    : std::max<std::size_t>(1, payload_bytes.size() / 4);
            write_exact(storage->payload_writer_fd,
                        payload_bytes.first(partial_size));
            // The failure path preserves the exact observed prefix when the
            // filesystem still permits a recovery fsync. It never writes the
            // success marker for a partial payload.
            need(::fsync(storage->payload_writer_fd) == 0 &&
                 ::fsync(storage->directory_fd) == 0);
            error_number = fault == TestOnlyDurableFailedViewSinkFault::Enospc
                ? ENOSPC : EIO;
            return DurableFailedViewSinkUnavailableAuthority(
                std::move(storage), static_cast<unsigned char>(fault),
                error_number);
        }

        write_exact(storage->payload_writer_fd, payload_bytes);
        if (fault == TestOnlyDurableFailedViewSinkFault::FsyncPayload)
            return DurableFailedViewSinkUnavailableAuthority(
                std::move(storage), static_cast<unsigned char>(fault), EIO);

        need(::fsync(storage->payload_writer_fd) == 0);
        struct stat payload_after{};
        struct stat marker_after{};
        need(::fstat(storage->payload_writer_fd, &payload_after) == 0 &&
             ::fstat(storage->marker_writer_fd, &marker_after) == 0 &&
             payload_after.st_size ==
                 static_cast<off_t>(payload_bytes.size()));
        const auto payload_hash = hash(payload_bytes);
        const auto marker = marker_bytes(
            payload_bytes.size(), payload_hash, directory,
            payload_after, marker_after);
        write_exact(storage->marker_writer_fd, marker);
        need(::fsync(storage->marker_writer_fd) == 0);

        if (fault == TestOnlyDurableFailedViewSinkFault::FsyncDirectory)
            return DurableFailedViewSinkUnavailableAuthority(
                std::move(storage), static_cast<unsigned char>(fault), EIO);
        need(fault == TestOnlyDurableFailedViewSinkFault::Reopen);
        need(::fsync(storage->directory_fd) == 0);
        return DurableFailedViewSinkUnavailableAuthority(
            std::move(storage), static_cast<unsigned char>(fault), EIO);
    } catch (...) {
        return DurableFailedViewSinkUnavailableAuthority(
            std::move(storage), static_cast<unsigned char>(fault),
            error_number);
    }
}

TestOnlyDurableFailedViewUnavailableSummary
DurableFailedViewSinkTestBridge::summarize_unavailable(
        const DurableFailedViewSinkUnavailableAuthority& supplied) {
    const auto* storage = supplied.storage_.get();
    need(storage != nullptr);
    struct stat payload{};
    struct stat marker{};
    need(::fstat(storage->payload_writer_fd, &payload) == 0 &&
         ::fstat(storage->marker_writer_fd, &marker) == 0 &&
         private_regular(payload) && private_regular(marker));
    int named_payload = -1;
    int named_marker = -1;
    try {
        named_payload = open_read_only_named(storage->directory_fd, PAYLOAD_NAME);
        named_marker = open_read_only_named(storage->directory_fd, MARKER_NAME);
        struct stat named_payload_stat{};
        struct stat named_marker_stat{};
        need(::fstat(named_payload, &named_payload_stat) == 0 &&
             ::fstat(named_marker, &named_marker_stat) == 0);
        const auto fault = static_cast<TestOnlyDurableFailedViewSinkFault>(
            supplied.failure_stage_);
        const bool before_payload_durability =
            fault == TestOnlyDurableFailedViewSinkFault::Fallocate ||
            fault == TestOnlyDurableFailedViewSinkFault::WriteShort ||
            fault == TestOnlyDurableFailedViewSinkFault::Enospc ||
            fault == TestOnlyDurableFailedViewSinkFault::FsyncPayload;
        TestOnlyDurableFailedViewUnavailableSummary result{
            .typed_unavailable = true,
            .payload_inode_retained =
                static_cast<std::uint64_t>(payload.st_dev) ==
                    storage->payload_device &&
                static_cast<std::uint64_t>(payload.st_ino) ==
                    storage->payload_inode &&
                payload.st_dev == named_payload_stat.st_dev &&
                payload.st_ino == named_payload_stat.st_ino,
            .marker_inode_retained =
                static_cast<std::uint64_t>(marker.st_dev) ==
                    storage->marker_device &&
                static_cast<std::uint64_t>(marker.st_ino) ==
                    storage->marker_inode &&
                marker.st_dev == named_marker_stat.st_dev &&
                marker.st_ino == named_marker_stat.st_ino,
            .distinct_inodes = payload.st_dev != marker.st_dev ||
                payload.st_ino != marker.st_ino,
            .no_success_marker_before_payload_durability =
                !before_payload_durability || marker.st_size == 0,
            .payload_device = storage->payload_device,
            .payload_inode = storage->payload_inode,
            .marker_device = storage->marker_device,
            .marker_inode = storage->marker_inode,
            .payload_size = static_cast<std::uint64_t>(payload.st_size),
            .marker_size = static_cast<std::uint64_t>(marker.st_size),
            .fault = fault,
            .error_number = supplied.error_number_,
        };
        close_fd(named_payload);
        close_fd(named_marker);
        return result;
    } catch (...) {
        close_fd(named_payload);
        close_fd(named_marker);
        throw;
    }
}

TestOnlyDurableFailedViewSinkSummary
DurableFailedViewSinkTestBridge::summarize(
        const DurableFailedViewSinkAuthority& supplied,
        std::span<const unsigned char> expected_payload) {
    const auto* storage = supplied.storage_.get();
    need(storage != nullptr);
    struct stat directory{};
    struct stat payload{};
    struct stat marker{};
    need(::fstat(storage->directory_fd, &directory) == 0 &&
         ::fstat(storage->payload_read_fd, &payload) == 0 &&
         ::fstat(storage->marker_read_fd, &marker) == 0);
    int named_payload = -1;
    int named_marker = -1;
    try {
        named_payload = open_read_only_named(storage->directory_fd, PAYLOAD_NAME);
        named_marker = open_read_only_named(storage->directory_fd, MARKER_NAME);
        struct stat named_payload_stat{};
        struct stat named_marker_stat{};
        need(::fstat(named_payload, &named_payload_stat) == 0 &&
             ::fstat(named_marker, &named_marker_stat) == 0);
        const auto actual_payload =
            read_exact(storage->payload_read_fd, storage->payload_size);
        const auto actual_marker = read_exact(storage->marker_read_fd, MARKER_BYTES);
        TestOnlyDurableFailedViewSinkSummary result{
            .private_directory = private_directory(directory),
            .payload_named_and_linked = private_regular(named_payload_stat),
            .marker_named_and_linked = private_regular(named_marker_stat),
            .payload_read_only =
                (::fcntl(storage->payload_read_fd, F_GETFL) & O_ACCMODE) ==
                    O_RDONLY,
            .marker_read_only =
                (::fcntl(storage->marker_read_fd, F_GETFL) & O_ACCMODE) ==
                    O_RDONLY,
            .same_payload_inode =
                payload.st_dev == named_payload_stat.st_dev &&
                payload.st_ino == named_payload_stat.st_ino &&
                static_cast<std::uint64_t>(payload.st_dev) ==
                    storage->payload_device &&
                static_cast<std::uint64_t>(payload.st_ino) ==
                    storage->payload_inode,
            .same_marker_inode =
                marker.st_dev == named_marker_stat.st_dev &&
                marker.st_ino == named_marker_stat.st_ino &&
                static_cast<std::uint64_t>(marker.st_dev) ==
                    storage->marker_device &&
                static_cast<std::uint64_t>(marker.st_ino) ==
                    storage->marker_inode,
            .payload_exact =
                actual_payload == std::vector<unsigned char>(
                    expected_payload.begin(), expected_payload.end()) &&
                hash(actual_payload) == storage->payload_hash,
            .marker_exact = actual_marker == std::vector<unsigned char>(
                storage->marker.begin(), storage->marker.end()),
            .payload_device = storage->payload_device,
            .payload_inode = storage->payload_inode,
            .marker_device = storage->marker_device,
            .marker_inode = storage->marker_inode,
        };
        close_fd(named_payload);
        close_fd(named_marker);
        return result;
    } catch (...) {
        close_fd(named_payload);
        close_fd(named_marker);
        throw;
    }
}
#endif

} // namespace kpb::measurement::durable_failed_view
