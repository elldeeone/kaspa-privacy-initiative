#include "privacy_owner_score_lineage_source_authority.hpp"
#include "privacy_owner_score_lineage_source_receiver_protocol.hpp"
#include "../mpc-prover/financial/registered_selected_producer_run_binding.hpp"

#include "privacy_measurement_sha256.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <poll.h>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpb::measurement::score_output_lineage_source {
namespace {

using Binding = kpi::mpc::financial::registered_driver::
    RegisteredSelectedProducerPrelaunchBindingAuthority;
using Plan = kpi::mpc::financial::registered_driver::
    RegisteredSelectedProducerPrelaunchPlan;

[[noreturn]] void refuse(const char* category = "lineage-receiver-refused") {
    throw std::runtime_error(category);
}
void need(bool value, const char* category = "lineage-receiver-refused") {
    if (!value) refuse(category);
}
bool nonzero(const SourceDigest& value) {
    return std::any_of(value.begin(), value.end(),
        [](unsigned char byte) { return byte != 0; });
}

class OwnedFd final {
    int value_{-1};
public:
    explicit OwnedFd(int value = -1) noexcept : value_(value) {}
    OwnedFd(const OwnedFd&) = delete;
    OwnedFd& operator=(const OwnedFd&) = delete;
    OwnedFd(OwnedFd&& other) noexcept
        : value_(std::exchange(other.value_, -1)) {}
    OwnedFd& operator=(OwnedFd&& other) noexcept {
        if (this != &other) {
            if (value_ >= 0) ::close(value_);
            value_ = std::exchange(other.value_, -1);
        }
        return *this;
    }
    ~OwnedFd() { if (value_ >= 0) ::close(value_); }
    int get() const noexcept { return value_; }
    int release() noexcept { return std::exchange(value_, -1); }
};

struct FileIdentity final {
    std::uint64_t device{};
    std::uint64_t inode{};
    std::uint64_t size{};
    std::uint32_t mode{};
    SourceDigest sha256{};
};

std::vector<unsigned char> read_exact_file(int fd, std::uint64_t size) {
    need(size > 0 && size <= std::numeric_limits<std::size_t>::max());
    std::vector<unsigned char> result(static_cast<std::size_t>(size));
    std::size_t offset{};
    while (offset < result.size()) {
        const auto count = ::pread(fd, result.data() + offset,
            result.size() - offset, static_cast<off_t>(offset));
        if (count < 0 && errno == EINTR) continue;
        need(count > 0);
        offset += static_cast<std::size_t>(count);
    }
    return result;
}

FileIdentity exact_regular(int fd, bool executable) {
    const auto flags = ::fcntl(fd, F_GETFL);
    const auto descriptor_flags = ::fcntl(fd, F_GETFD);
    const auto seals = ::fcntl(fd, F_GET_SEALS);
    struct stat before{};
    need(fd >= 0 && flags >= 0 && (flags & O_ACCMODE) == O_RDONLY &&
         descriptor_flags >= 0 && (descriptor_flags & FD_CLOEXEC) != 0 &&
         seals >= 0 &&
         (seals & (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK |
                   F_SEAL_SEAL)) ==
             (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) &&
         ::fstat(fd, &before) == 0 && S_ISREG(before.st_mode) &&
         before.st_uid == ::getuid() && before.st_nlink == 0 &&
         before.st_size > 0 &&
         (before.st_mode & 0777) == (executable ? 0500 : 0400));
    auto bytes = read_exact_file(
        fd, static_cast<std::uint64_t>(before.st_size));
    struct stat after{};
    need(::fstat(fd, &after) == 0 && before.st_dev == after.st_dev &&
         before.st_ino == after.st_ino && before.st_size == after.st_size &&
         before.st_mode == after.st_mode && before.st_nlink == after.st_nlink &&
         before.st_uid == after.st_uid && before.st_gid == after.st_gid &&
         before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
         before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
         before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
         before.st_ctim.tv_nsec == after.st_ctim.tv_nsec);
    return {
        .device = static_cast<std::uint64_t>(before.st_dev),
        .inode = static_cast<std::uint64_t>(before.st_ino),
        .size = static_cast<std::uint64_t>(before.st_size),
        .mode = static_cast<std::uint32_t>(before.st_mode),
        .sha256 = detail::sha256(bytes),
    };
}

bool child_exact_regular(int fd, const FileIdentity& expected,
                         bool executable) noexcept {
    const auto flags = ::fcntl(fd, F_GETFL);
    const auto descriptor_flags = ::fcntl(fd, F_GETFD);
    const auto seals = ::fcntl(fd, F_GET_SEALS);
    struct stat info{};
    return fd >= 0 && flags >= 0 &&
        (flags & O_ACCMODE) == O_RDONLY && descriptor_flags >= 0 &&
        (descriptor_flags & FD_CLOEXEC) != 0 && seals >= 0 &&
        (seals & (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK |
                  F_SEAL_SEAL)) ==
            (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) &&
        ::fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
        info.st_uid == ::getuid() && info.st_nlink == 0 &&
        info.st_size > 0 &&
        (info.st_mode & 0777) == (executable ? 0500 : 0400) &&
        static_cast<std::uint64_t>(info.st_dev) == expected.device &&
        static_cast<std::uint64_t>(info.st_ino) == expected.inode &&
        static_cast<std::uint64_t>(info.st_size) == expected.size &&
        static_cast<std::uint32_t>(info.st_mode) == expected.mode;
}

void random_exact(std::span<unsigned char> output) {
    std::size_t offset{};
    while (offset < output.size()) {
        const auto count = ::getrandom(
            output.data() + offset, output.size() - offset, 0);
        if (count < 0 && errno == EINTR) continue;
        need(count > 0, "lineage-receiver-entropy");
        offset += static_cast<std::size_t>(count);
    }
}

void add(std::vector<unsigned char>& output,
         std::span<const unsigned char> value) {
    output.insert(output.end(), value.begin(), value.end());
}
void add(std::vector<unsigned char>& output, const SourceDigest& value) {
    add(output, std::span(value));
}
void add_u64(std::vector<unsigned char>& output, std::uint64_t value) {
    for (unsigned index = 0; index < 8; ++index)
        output.push_back(static_cast<unsigned char>(value >> (8 * index)));
}
SourceDigest identity(std::string_view domain,
                      std::span<const unsigned char> session,
                      pid_t pid, const FileIdentity& selection,
                      const FileIdentity& worker, int status = -1) {
    std::vector<unsigned char> bytes(domain.begin(), domain.end());
    add(bytes, session);
    add_u64(bytes, static_cast<std::uint64_t>(pid));
    for (const auto value : {selection.device, selection.inode,
                             selection.size, worker.device,
                             worker.inode, worker.size})
        add_u64(bytes, value);
    add(bytes, selection.sha256);
    add(bytes, worker.sha256);
    if (status >= 0) add_u64(bytes, static_cast<unsigned>(status));
    const auto result = detail::sha256(bytes);
    need(nonzero(result));
    return result;
}

std::uint64_t read_u64(std::span<const unsigned char> input,
                       std::size_t offset) {
    need(offset + 8 <= input.size());
    std::uint64_t result{};
    for (unsigned index = 0; index < 8; ++index)
        result |= static_cast<std::uint64_t>(input[offset + index]) <<
            (8 * index);
    return result;
}

void send_exact_packet(int fd, std::span<const unsigned char> bytes) {
    const auto count = ::send(fd, bytes.data(), bytes.size(), MSG_NOSIGNAL);
    need(count == static_cast<ssize_t>(bytes.size()));
}

class ChildGuard final {
    pid_t pid_{-1};
public:
    explicit ChildGuard(pid_t pid) noexcept : pid_(pid) {}
    ChildGuard(const ChildGuard&) = delete;
    ChildGuard& operator=(const ChildGuard&) = delete;
    ~ChildGuard() {
        if (pid_ > 0) {
            (void)::kill(pid_, SIGKILL);
            int ignored{};
            while (::waitpid(pid_, &ignored, 0) < 0 && errno == EINTR) {}
        }
    }
    int wait() {
        int status{};
        pid_t result;
        do { result = ::waitpid(pid_, &status, 0); }
        while (result < 0 && errno == EINTR);
        need(result == pid_);
        pid_ = -1;
        return status;
    }
};

void close_child_aliases() noexcept {
#ifdef SYS_close_range
    (void)::syscall(SYS_close_range, 3U, 59U, 0U);
    (void)::syscall(SYS_close_range, 62U, 62U, 0U);
    (void)::syscall(SYS_close_range, 64U, ~0U, 0U);
#else
    for (int fd = 3; fd < 4096; ++fd)
        if (fd != receiver_protocol::SELECTION_FD &&
            fd != 61 && fd != receiver_protocol::CONTROL_FD)
            (void)::close(fd);
#endif
}

[[noreturn]] void exec_worker(int selection_fd, int worker_fd,
                              int control_fd,
                              const FileIdentity& selection_identity,
                              const FileIdentity& worker_identity) noexcept {
    // Stage every source above the fixed descriptor range first.  Direct
    // dup3 installs can otherwise clobber a later source when inherited
    // descriptors already occupy FD60/61/63.
    const int selection_stage =
        ::fcntl(selection_fd, F_DUPFD_CLOEXEC, 64);
    const int worker_stage = ::fcntl(worker_fd, F_DUPFD_CLOEXEC, 64);
    const int control_stage = ::fcntl(control_fd, F_DUPFD_CLOEXEC, 64);
    if (selection_stage < 0 || worker_stage < 0 || control_stage < 0 ||
        !child_exact_regular(selection_stage, selection_identity, false) ||
        !child_exact_regular(worker_stage, worker_identity, true) ||
        ::dup3(selection_stage, receiver_protocol::SELECTION_FD, 0) < 0 ||
        ::dup3(worker_stage, 61, O_CLOEXEC) < 0 ||
        ::dup3(control_stage, receiver_protocol::CONTROL_FD, 0) < 0)
        ::_exit(126);
    close_child_aliases();
    char name[] = "kpb-owner-score-lineage-worker";
    char* argv[]{name, nullptr};
    char path[] = "PATH=/usr/bin:/bin";
    char* environment[]{path, nullptr};
    (void)::syscall(SYS_execveat, 61, "", argv, environment,
                    AT_EMPTY_PATH);
    ::_exit(127);
}

struct Received final {
    OwnedFd archive;
    std::array<unsigned char, receiver_protocol::RESPONSE_BYTES> packet{};
};

Received receive_packet(int fd, pid_t child,
                        std::span<const unsigned char, 32> session) {
    pollfd ready{.fd = fd, .events = POLLIN | POLLHUP, .revents = 0};
    need(::poll(&ready, 1, 5000) > 0 && (ready.revents & POLLIN) != 0);
    Received result;
    alignas(cmsghdr) std::array<unsigned char,
        CMSG_SPACE(sizeof(ucred)) + CMSG_SPACE(2 * sizeof(int))> control{};
    iovec vector{.iov_base = result.packet.data(),
                 .iov_len = result.packet.size()};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    const auto count = ::recvmsg(fd, &message, MSG_CMSG_CLOEXEC);
    need(count == static_cast<ssize_t>(result.packet.size()) &&
         (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0);
    unsigned credential_count{};
    std::array<int, 2> received_descriptors{-1, -1};
    unsigned descriptor_count{};
    for (auto* item = CMSG_FIRSTHDR(&message); item != nullptr;
         item = CMSG_NXTHDR(&message, item)) {
        need(item->cmsg_level == SOL_SOCKET);
        if (item->cmsg_type == SCM_CREDENTIALS) {
            need(item->cmsg_len == CMSG_LEN(sizeof(ucred)) &&
                 ++credential_count == 1);
            ucred credentials{};
            std::memcpy(&credentials, CMSG_DATA(item), sizeof(credentials));
            need(credentials.pid == child && credentials.uid == ::getuid() &&
                 credentials.gid == ::getgid());
        } else if (item->cmsg_type == SCM_RIGHTS) {
            const auto payload = item->cmsg_len - CMSG_LEN(0);
            need(payload > 0 && payload % sizeof(int) == 0 &&
                 descriptor_count + payload / sizeof(int) <=
                    received_descriptors.size());
            const auto count = payload / sizeof(int);
            std::memcpy(received_descriptors.data() + descriptor_count,
                        CMSG_DATA(item), payload);
            descriptor_count += static_cast<unsigned>(count);
        } else {
            refuse();
        }
    }
    if (descriptor_count != 1) {
        for (unsigned index = 0; index < descriptor_count; ++index)
            if (received_descriptors[index] >= 0)
                ::close(received_descriptors[index]);
        refuse();
    }
    result.archive = OwnedFd(received_descriptors[0]);
    need(credential_count == 1 && result.archive.get() >= 0 &&
         std::equal(receiver_protocol::RESPONSE_MAGIC.begin(),
                    receiver_protocol::RESPONSE_MAGIC.end(),
                    result.packet.begin()) &&
         std::equal(session.begin(), session.end(), result.packet.begin() + 8));
    return result;
}

void exact_eof(int fd) {
    pollfd ready{.fd = fd, .events = POLLIN | POLLHUP, .revents = 0};
    need(::poll(&ready, 1, 5000) > 0 && (ready.revents & POLLHUP) != 0);
    unsigned char byte{};
    alignas(cmsghdr) std::array<unsigned char,
        CMSG_SPACE(sizeof(ucred)) + CMSG_SPACE(sizeof(int))> control{};
    iovec vector{.iov_base = &byte, .iov_len = 1};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    const auto count = ::recvmsg(
        fd, &message, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
    // A credentialed zero-length SOCK_SEQPACKET record is a packet, not EOF.
    need(count == 0 && CMSG_FIRSTHDR(&message) == nullptr &&
         (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0);
}

OwnerScoreSourceClassification classification(
        kpb::measurement::Classification value) {
    if (value == kpb::measurement::Classification::HiddenCandidate)
        return OwnerScoreSourceClassification::HiddenCandidate;
    if (value == kpb::measurement::Classification::TransparentBaseline)
        return OwnerScoreSourceClassification::TransparentBaseline;
    refuse();
}

} // namespace

AuthenticatedPrivacyLaunchLineageSourceAuthority
PrivacyLaunchLineageSourceReceiverBridge::receive(Binding& supplied) {
    const bool receiver_live = supplied.lineage_receiver_live_.exchange(false);
    OwnedFd selection(std::exchange(supplied.lineage_selection_fd_, -1));
    OwnedFd worker(std::exchange(supplied.lineage_worker_fd_, -1));
    const bool selected_worker =
        std::exchange(supplied.lineage_worker_selected_, false);
    const auto expected_worker =
        std::exchange(supplied.lineage_worker_sha256_, {});
    const auto plan = supplied.plan_;
    const auto prelaunch_identity = supplied.authority_identity_;
    const bool binding_live = supplied.live_.load();
    try {
        need(receiver_live && selected_worker && binding_live &&
             selection.get() >= 0 && worker.get() >= 0,
             "outer-attempt-source-authority-missing");
        need(nonzero(prelaunch_identity) && nonzero(plan.measurement_attempt) &&
             nonzero(plan.method) && nonzero(plan.run_selection) &&
             nonzero(plan.comparison_selection) &&
             nonzero(plan.source_closure) && nonzero(plan.runtime) &&
             plan.run_selection != plan.comparison_selection);
        const auto selected_file = exact_regular(selection.get(), false);
        const auto worker_file = exact_regular(worker.get(), true);
        need(selected_file.sha256 == plan.comparison_selection &&
             worker_file.sha256 == expected_worker);

        int raw_sockets[2]{-1, -1};
        need(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0,
                          raw_sockets) == 0);
        OwnedFd parent_socket(raw_sockets[0]);
        OwnedFd child_socket(raw_sockets[1]);
        int enabled = 1;
        need(::setsockopt(parent_socket.get(), SOL_SOCKET, SO_PASSCRED,
                          &enabled, sizeof(enabled)) == 0 &&
             ::setsockopt(child_socket.get(), SOL_SOCKET, SO_PASSCRED,
                          &enabled, sizeof(enabled)) == 0);
        std::array<unsigned char, 32> session{};
        random_exact(session);
        const auto child = ::fork();
        need(child >= 0);
        if (child == 0) {
            (void)::close(parent_socket.release());
            exec_worker(selection.get(), worker.get(), child_socket.get(),
                        selected_file, worker_file);
        }
        ChildGuard child_guard(child);
        child_socket = OwnedFd();
        selection = OwnedFd();
        worker = OwnedFd();

        std::array<unsigned char, receiver_protocol::OFFER_BYTES> offer{};
        std::copy(receiver_protocol::OFFER_MAGIC.begin(),
                  receiver_protocol::OFFER_MAGIC.end(), offer.begin());
        std::copy(session.begin(), session.end(), offer.begin() + 8);
        std::copy(plan.comparison_selection.begin(),
                  plan.comparison_selection.end(), offer.begin() + 40);
        send_exact_packet(parent_socket.get(), offer);

        auto received = receive_packet(parent_socket.get(), child, session);
        exact_eof(parent_socket.get());
        const auto status = child_guard.wait();
        need(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        const auto declared_size = read_u64(received.packet, 40);
        SourceDigest declared_sha{};
        std::copy_n(received.packet.begin() + 48, 32,
                    declared_sha.begin());
        struct stat archive_info{};
        need(::fstat(received.archive.get(), &archive_info) == 0 &&
             archive_info.st_size > 0 &&
             static_cast<std::uint64_t>(archive_info.st_size) ==
                declared_size);

        const auto session_identity = detail::sha256(session);
        const auto process_identity = identity(
            "KPB_OWNER_SCORE_LINEAGE_RECEIVER_PROCESS_V1\n",
            session, child, selected_file, worker_file);
        const auto exit_identity = identity(
            "KPB_OWNER_SCORE_LINEAGE_RECEIVER_EXIT_V1\n",
            session, child, selected_file, worker_file, status);
        return AuthenticatedPrivacyLaunchLineageSourceAuthority::
            adopt_received_archive(
                received.archive.release(), {
                    .method_sha256 = plan.method,
                    .run_selection_sha256 = plan.run_selection,
                    .diagnostic_selection_sha256 =
                        plan.comparison_selection,
                    .source_closure_sha256 = plan.source_closure,
                    .runtime_identity_sha256 = plan.runtime,
                    .registered_prelaunch_identity = prelaunch_identity,
                    .measurement_attempt_identity =
                        plan.measurement_attempt,
                    .receiver_session_identity = session_identity,
                    .receiver_process_identity = process_identity,
                    .receiver_exit_identity = exit_identity,
                    .trial_id = plan.capture_trial_id,
                    .classification = classification(plan.classification),
                    .exact_archive_sha256 = declared_sha,
                });
    } catch (...) {
        refuse();
    }
}

} // namespace kpb::measurement::score_output_lineage_source
