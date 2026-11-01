#include "privacy_durable_failed_view_sink_authority.hpp"

#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fcntl.h>
#include <span>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace kpb::measurement::durable_failed_view;

namespace {

std::string temporary_root() {
    std::array<char, 64> pattern{};
    const int written = std::snprintf(
        pattern.data(), pattern.size(), "/tmp/kpb-durable-sink-XXXXXX");
    assert(written > 0 && static_cast<std::size_t>(written) < pattern.size());
    char* result = ::mkdtemp(pattern.data());
    assert(result != nullptr);
    return result;
}

void cleanup(const std::string& root) {
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
}

template<class Function>
void expect_refused(Function&& function) {
    bool refused = false;
    try { function(); }
    catch (...) { refused = true; }
    assert(refused);
}

std::vector<unsigned char> body() {
    std::vector<unsigned char> result(1537);
    for (std::size_t index = 0; index < result.size(); ++index)
        result[index] = static_cast<unsigned char>((index * 29 + 7) & 0xff);
    return result;
}

std::vector<unsigned char> read_file(const std::string& path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0);
    struct stat value{};
    assert(::fstat(fd, &value) == 0 && value.st_size >= 0);
    std::vector<unsigned char> result(static_cast<std::size_t>(value.st_size));
    std::size_t offset = 0;
    while (offset < result.size()) {
        const auto received = ::read(fd, result.data() + offset,
                                     result.size() - offset);
        if (received < 0 && errno == EINTR) continue;
        assert(received > 0);
        offset += static_cast<std::size_t>(received);
    }
    assert(::close(fd) == 0);
    return result;
}

void committed_sink_is_private_reopened_and_one_shot() {
    const auto root = temporary_root();
    const auto payload = body();
    auto reservation = DurableFailedViewSinkTestBridge::reserve(root, 4096);
    auto committed = DurableFailedViewSinkTestBridge::commit(
        std::move(reservation), payload);
    const auto summary = DurableFailedViewSinkTestBridge::summarize(
        committed, payload);
    assert(summary.private_directory && summary.payload_named_and_linked &&
           summary.marker_named_and_linked && summary.payload_read_only &&
           summary.marker_read_only && summary.same_payload_inode &&
           summary.same_marker_inode && summary.payload_exact &&
           summary.marker_exact && summary.payload_device != 0 &&
           summary.payload_inode != 0 && summary.marker_device != 0 &&
           summary.marker_inode != 0 &&
           (summary.payload_device != summary.marker_device ||
            summary.payload_inode != summary.marker_inode));
    expect_refused([&] {
        (void)DurableFailedViewSinkTestBridge::commit(
            std::move(reservation), payload);
    });
    cleanup(root);
}

void crash_after_synced_prefix_retains_actual_partial_bytes() {
    const auto root = temporary_root();
    const std::vector<unsigned char> prefix{
        0x4b, 0x50, 0x42, 0x2d, 0x50, 0x41, 0x52, 0x54, 0x49, 0x41, 0x4c};
    {
        // The parent creates and durably links both files before forking the
        // writer. After the child exits, the parent closes its retained writer
        // descriptions before reopening by name below.
        auto reservation =
            DurableFailedViewSinkTestBridge::reserve(root, 4096);
        const pid_t child = ::fork();
        assert(child >= 0);
        if (child == 0) {
            try {
                DurableFailedViewSinkTestBridge::write_prefix_and_sync(
                    reservation, prefix);
                ::_exit(47);
            } catch (...) {
                ::_exit(111);
            }
        }
        int status = 0;
        assert(::waitpid(child, &status, 0) == child && WIFEXITED(status) &&
               WEXITSTATUS(status) == 47);
    }
    const auto sink = root + "/failed-view";
    struct stat directory{};
    struct stat payload_stat{};
    struct stat marker_stat{};
    assert(::lstat(sink.c_str(), &directory) == 0 &&
           S_ISDIR(directory.st_mode) && (directory.st_mode & 07777) == 0700);
    assert(::lstat((sink + "/payload.kpb").c_str(), &payload_stat) == 0 &&
           S_ISREG(payload_stat.st_mode) &&
           (payload_stat.st_mode & 07777) == 0600 &&
           payload_stat.st_nlink == 1);
    assert(::lstat((sink + "/commit.kpb").c_str(), &marker_stat) == 0 &&
           S_ISREG(marker_stat.st_mode) &&
           (marker_stat.st_mode & 07777) == 0600 &&
           marker_stat.st_nlink == 1 && marker_stat.st_size == 0);
    assert(read_file(sink + "/payload.kpb") == prefix);
    cleanup(root);
}

void path_substitution_and_unsafe_roots_refuse() {
    const auto root = temporary_root();
    const auto payload = body();
    auto reservation = DurableFailedViewSinkTestBridge::reserve(root, 4096);
    const auto directory = root + "/failed-view";
    assert(::rename((directory + "/payload.kpb").c_str(),
                    (directory + "/payload.original").c_str()) == 0);
    int substitute = ::open((directory + "/payload.kpb").c_str(),
        O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    assert(substitute >= 0 && ::close(substitute) == 0);
    expect_refused([&] {
        (void)DurableFailedViewSinkTestBridge::commit(
            std::move(reservation), payload);
    });
    cleanup(root);

    const auto unsafe = temporary_root();
    assert(::chmod(unsafe.c_str(), 0755) == 0);
    expect_refused([&] {
        (void)DurableFailedViewSinkTestBridge::reserve(unsafe, 4096);
    });
    cleanup(unsafe);

    const auto actual = temporary_root();
    const auto link = actual + "-link";
    assert(::symlink(actual.c_str(), link.c_str()) == 0);
    expect_refused([&] {
        (void)DurableFailedViewSinkTestBridge::reserve(link, 4096);
    });
    assert(::unlink(link.c_str()) == 0);
    cleanup(actual);
}

void durability_stage_failures_retain_typed_unavailable() {
    constexpr std::array faults{
        TestOnlyDurableFailedViewSinkFault::Fallocate,
        TestOnlyDurableFailedViewSinkFault::WriteShort,
        TestOnlyDurableFailedViewSinkFault::Enospc,
        TestOnlyDurableFailedViewSinkFault::FsyncPayload,
        TestOnlyDurableFailedViewSinkFault::FsyncDirectory,
        TestOnlyDurableFailedViewSinkFault::Reopen,
    };
    const auto payload = body();
    for (const auto fault : faults) {
        const auto root = temporary_root();
        DurableFailedViewSinkUnavailableAuthority unavailable =
            fault == TestOnlyDurableFailedViewSinkFault::Fallocate
                ? DurableFailedViewSinkTestBridge::reserve_unavailable(
                      root, 4096, fault)
                : DurableFailedViewSinkTestBridge::commit_unavailable(
                      DurableFailedViewSinkTestBridge::reserve(root, 4096),
                      payload, fault);
        const auto summary =
            DurableFailedViewSinkTestBridge::summarize_unavailable(
                unavailable);
        assert(summary.payload_inode_retained &&
               summary.marker_inode_retained &&
               summary.distinct_inodes && summary.typed_unavailable &&
               summary.fault == fault &&
               summary.error_number ==
                   (fault == TestOnlyDurableFailedViewSinkFault::Fallocate ||
                    fault == TestOnlyDurableFailedViewSinkFault::Enospc
                        ? ENOSPC : EIO) &&
               summary.payload_device != 0 && summary.payload_inode != 0 &&
               summary.marker_device != 0 && summary.marker_inode != 0);
        if (fault == TestOnlyDurableFailedViewSinkFault::Fallocate ||
            fault == TestOnlyDurableFailedViewSinkFault::WriteShort ||
            fault == TestOnlyDurableFailedViewSinkFault::Enospc ||
            fault == TestOnlyDurableFailedViewSinkFault::FsyncPayload)
            assert(summary.marker_size == 0 &&
                   summary.no_success_marker_before_payload_durability);
        if (fault == TestOnlyDurableFailedViewSinkFault::Fallocate)
            assert(summary.payload_size == 0);
        if (fault == TestOnlyDurableFailedViewSinkFault::WriteShort ||
            fault == TestOnlyDurableFailedViewSinkFault::Enospc)
            assert(summary.payload_size > 0 &&
                   summary.payload_size < payload.size());
        if (fault == TestOnlyDurableFailedViewSinkFault::FsyncPayload)
            assert(summary.payload_size == payload.size());
        if (fault == TestOnlyDurableFailedViewSinkFault::FsyncDirectory ||
            fault == TestOnlyDurableFailedViewSinkFault::Reopen)
            assert(summary.payload_size == payload.size() &&
                   summary.marker_size == 104);
        cleanup(root);
    }
}

} // namespace

int main() {
    committed_sink_is_private_reopened_and_one_shot();
    crash_after_synced_prefix_retains_actual_partial_bytes();
    path_substitution_and_unsafe_roots_refuse();
    durability_stage_failures_retain_typed_unavailable();
}
