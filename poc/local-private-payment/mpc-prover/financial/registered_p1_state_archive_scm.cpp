#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "registered_p1_state_archive_scm.hpp"
#include "registered_p1_state_archive_writer_adoption_internal.hpp"
#include "registered_parent_role_fork.hpp"
#include "registered_projection_route.hpp"

#include "../../private_batch_trial/privacy_p1_corrupt_state_capsule_child_disposition_internal.hpp"
#include "../../private_batch_trial/privacy_p1_corrupt_state_parent_rehydration.hpp"
#include "../../private_batch_trial/privacy_measurement_sha256.hpp"
namespace kpi::mpc::financial::registered_driver {
class RegisteredPreidentityReadyAuthority;
}
#include "../../private_batch_trial/privacy_registered_fresh_trial_capture_topology_reservation.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <optional>
#include <poll.h>
#include <signal.h>
#include <span>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

namespace kpi::mpc::financial::registered_driver {
namespace {

using kpb::measurement::Digest;
using kpb::measurement::p1_state_capsule::AbortClass;
using kpb::measurement::p1_state_capsule::SourcePhase;

constexpr std::array<unsigned char, 8> TERMINAL_MAGIC{
    'K', 'P', 'B', 'P', '1', 'S', 'T', '5'};
constexpr std::array<unsigned char, 8> ACK_MAGIC{
    'K', 'P', 'B', 'P', '1', 'A', 'C', 'K'};
constexpr std::size_t TERMINAL_BYTES = 512;
constexpr std::size_t TERMINAL_IDENTITY_OFFSET = 448;
constexpr std::size_t ACK_BYTES = 96;
constexpr std::size_t ACK_IDENTITY_OFFSET = 56;
constexpr int TERMINAL_TIMEOUT_MS = 30000;

[[noreturn]] void refuse() {
    throw std::runtime_error("registered P1 state archive SCM refused");
}

void need(bool value) { if (!value) refuse(); }

void close_fd(int& fd) noexcept {
    const int owned = std::exchange(fd, -1);
    if (owned >= 0) (void)::close(owned);
}

bool nonzero(const Digest& value) noexcept {
    for (const auto byte : value) if (byte != 0) return true;
    return false;
}

Digest hash(std::span<const unsigned char> bytes) {
    const auto result = kpb::measurement::detail::sha256(bytes);
    need(nonzero(result));
    return result;
}

Digest role1_runtime_unwind_identity() noexcept {
    // Source-owned, versioned identity for the generic C++ unwind fallback.
    // It is intentionally not accepted from the role program or environment.
    return Digest{
        0x0c, 0x81, 0x5e, 0x8e, 0x7c, 0x65, 0x32, 0x29,
        0xd3, 0x94, 0x88, 0x70, 0x0d, 0x32, 0xd8, 0x66,
        0xdc, 0x1d, 0xa9, 0xff, 0xd1, 0xd7, 0x8f, 0xe5,
        0xa5, 0xdd, 0x4c, 0x41, 0x20, 0x7c, 0x9d, 0x5b,
    };
}

void put_u32(std::span<unsigned char> out, std::size_t at,
             std::uint32_t value) {
    need(at <= out.size() && sizeof(value) <= out.size() - at);
    for (unsigned index = 0; index < sizeof(value); ++index)
        out[at + index] = static_cast<unsigned char>(value >> (8 * index));
}

std::uint32_t get_u32(std::span<const unsigned char> in, std::size_t at) {
    need(at <= in.size() && sizeof(std::uint32_t) <= in.size() - at);
    std::uint32_t result = 0;
    for (unsigned index = 0; index < sizeof(result); ++index)
        result |= std::uint32_t(in[at + index]) << (8 * index);
    return result;
}

void put_u64(std::span<unsigned char> out, std::size_t at,
             std::uint64_t value) {
    need(at <= out.size() && sizeof(value) <= out.size() - at);
    for (unsigned index = 0; index < sizeof(value); ++index)
        out[at + index] = static_cast<unsigned char>(value >> (8 * index));
}

std::uint64_t get_u64(std::span<const unsigned char> in, std::size_t at) {
    need(at <= in.size() && sizeof(std::uint64_t) <= in.size() - at);
    std::uint64_t result = 0;
    for (unsigned index = 0; index < sizeof(result); ++index)
        result |= std::uint64_t(in[at + index]) << (8 * index);
    return result;
}

void put_digest(std::span<unsigned char> out, std::size_t at,
                const Digest& value) {
    need(at <= out.size() && value.size() <= out.size() - at);
    std::copy(value.begin(), value.end(), out.begin() + at);
}

Digest get_digest(std::span<const unsigned char> in, std::size_t at) {
    Digest result{};
    need(at <= in.size() && result.size() <= in.size() - at);
    std::copy_n(in.begin() + at, result.size(), result.begin());
    return result;
}

struct FileFingerprint {
    std::uint64_t device{};
    std::uint64_t inode{};
    std::uint32_t mode{};
    std::uint64_t nlink{};
    std::uint64_t size{};
};

struct OpenFileFingerprint {
    FileFingerprint value{};
    int access{-1};
};

OpenFileFingerprint regular_file_any(int fd, bool require_empty) {
    struct stat value{};
    const int flags = fd >= 0 ? ::fcntl(fd, F_GETFL) : -1;
    const int descriptor_flags = fd >= 0 ? ::fcntl(fd, F_GETFD) : -1;
    const int access = flags >= 0 ? flags & O_ACCMODE : -1;
    need(fd >= 0 && flags >= 0 && descriptor_flags >= 0 &&
         (access == O_RDONLY || access == O_WRONLY || access == O_RDWR) &&
         (descriptor_flags & FD_CLOEXEC) != 0 &&
         ::fstat(fd, &value) == 0 && S_ISREG(value.st_mode) &&
         value.st_nlink == 0 && (value.st_mode & 0777U) == 0600U &&
         value.st_size >= 0 &&
         (!require_empty || value.st_size == 0));
    return {{
        static_cast<std::uint64_t>(value.st_dev),
        static_cast<std::uint64_t>(value.st_ino),
        static_cast<std::uint32_t>(value.st_mode),
        static_cast<std::uint64_t>(value.st_nlink),
        static_cast<std::uint64_t>(value.st_size),
    }, access};
}

FileFingerprint regular_file(
        int fd, int expected_access, bool require_empty) {
    const auto selected = regular_file_any(fd, require_empty);
    need(selected.access == expected_access);
    return selected.value;
}

void require_seqpacket(int fd) {
    int type = 0;
    socklen_t type_bytes = sizeof(type);
    int passcred = 0;
    socklen_t passcred_bytes = sizeof(passcred);
    const int descriptor_flags = fd >= 0 ? ::fcntl(fd, F_GETFD) : -1;
    need(descriptor_flags >= 0 && (descriptor_flags & FD_CLOEXEC) != 0 &&
         ::getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_bytes) == 0 &&
         type_bytes == sizeof(type) && type == SOCK_SEQPACKET &&
         ::getsockopt(fd, SOL_SOCKET, SO_PASSCRED, &passcred,
                      &passcred_bytes) == 0 &&
         passcred_bytes == sizeof(passcred) && passcred == 1);
}

template<std::size_t Size>
struct AuthenticatedPacket {
    std::array<unsigned char, Size> bytes{};
    struct ucred credentials{};
};

template<std::size_t Size>
AuthenticatedPacket<Size> receive_authenticated(
        int fd, std::int64_t expected_pid) {
    need(fd >= 0 && expected_pid > 1 &&
         expected_pid <= std::numeric_limits<pid_t>::max());
    struct pollfd watched{fd, POLLIN | POLLRDHUP, 0};
    int ready;
    do { ready = ::poll(&watched, 1, TERMINAL_TIMEOUT_MS); }
    while (ready < 0 && errno == EINTR);
    need(ready == 1 &&
         (watched.revents & (POLLIN | POLLHUP | POLLRDHUP)) != 0 &&
         (watched.revents & (POLLERR | POLLNVAL)) == 0);

    AuthenticatedPacket<Size> result;
    std::array<unsigned char, CMSG_SPACE(sizeof(struct ucred))> control{};
    struct iovec iov{result.bytes.data(), result.bytes.size()};
    struct msghdr message{};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t count;
    do { count = ::recvmsg(fd, &message, MSG_CMSG_CLOEXEC); }
    while (count < 0 && errno == EINTR);
    need(count == static_cast<ssize_t>(result.bytes.size()) &&
         (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0);

    unsigned credential_count = 0;
    for (auto* item = CMSG_FIRSTHDR(&message); item != nullptr;
         item = CMSG_NXTHDR(&message, item)) {
        need(item->cmsg_level == SOL_SOCKET &&
             item->cmsg_type == SCM_CREDENTIALS &&
             item->cmsg_len == CMSG_LEN(sizeof(struct ucred)));
        std::memcpy(&result.credentials, CMSG_DATA(item),
                    sizeof(result.credentials));
        ++credential_count;
    }
    need(credential_count == 1 &&
         result.credentials.pid == expected_pid &&
         result.credentials.uid == ::geteuid() &&
         result.credentials.gid == ::getegid());
    return result;
}

void send_exact(int fd, std::span<const unsigned char> bytes) {
    ssize_t count;
    do { count = ::send(fd, bytes.data(), bytes.size(), MSG_NOSIGNAL); }
    while (count < 0 && errno == EINTR);
    need(count == static_cast<ssize_t>(bytes.size()));
}

void require_peer_eof(int fd) {
    struct pollfd watched{fd, POLLIN | POLLRDHUP, 0};
    int ready;
    do { ready = ::poll(&watched, 1, TERMINAL_TIMEOUT_MS); }
    while (ready < 0 && errno == EINTR);
    need(ready == 1 &&
         (watched.revents & (POLLHUP | POLLRDHUP)) != 0 &&
         (watched.revents & (POLLERR | POLLNVAL)) == 0);
    unsigned char byte = 0;
    std::array<unsigned char, CMSG_SPACE(sizeof(struct ucred))> control{};
    struct iovec iov{&byte, 1};
    struct msghdr message{};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t count;
    do { count = ::recvmsg(fd, &message, MSG_CMSG_CLOEXEC); }
    while (count < 0 && errno == EINTR);
    // A credentialed zero-length seqpacket is a real replay frame, not EOF.
    need(count == 0 && CMSG_FIRSTHDR(&message) == nullptr &&
         (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0);
}

} // namespace

struct RegisteredP1StateArchiveScmTransfer::Storage {
    std::array<int, 2> parent_reads{{-1, -1}};
    std::array<int, 2> child_writers{{-1, -1}};
    std::array<std::uint64_t, 2> devices{};
    std::array<std::uint64_t, 2> inodes{};
    std::array<std::uint32_t, 2> modes{};
    std::array<std::uint64_t, 2> nlinks{};
    std::array<std::uint64_t, 2> sizes{};
    Digest reservation_identity{};
    bool live{true};
    ~Storage() {
        for (auto& fd : parent_reads) close_fd(fd);
        for (auto& fd : child_writers) close_fd(fd);
    }
};

struct RegisteredP1StateArchiveChildRoundAuthority::Storage {
    int channel{-1};
    int writer{-1};
    unsigned round{};
    std::int64_t parent_pid{-1};
    std::int64_t child_pid{-1};
    FileFingerprint archive{};
    Digest reservation_identity{};
    Digest activation_identity{};
    bool live{true};
#ifdef KPI_REGISTERED_P1_STATE_ARCHIVE_SCM_TEST_SETUP
    RegisteredP1StateArchiveScmTestFault test_fault{
        RegisteredP1StateArchiveScmTestFault::None};
#endif
    ~Storage() { close_fd(channel); close_fd(writer); }
};

struct RegisteredRole1P1StatePrelaunchAuthority::Storage {
    std::optional<RegisteredP1StateArchiveChildRoundAuthority> child_round;
    std::optional<kpb::measurement::p1_state_capsule::
        P1CorruptStateCapsulePlanAuthority> capsule_plan;
    Digest unavailable_trial_identity{};
    Digest unavailable_prelaunch_binding_identity{};
#ifdef KPI_REGISTERED_P1_STATE_ARCHIVE_SCM_TEST_SETUP
    bool deny_recorder_begin_allocation{};
    void (*allocation_gate)(bool) noexcept {};
#endif
    bool live{true};
};

struct RegisteredRole1P1StateRuntimeAuthority::Storage {
    std::optional<kpb::measurement::p1_state_capsule::
        P1CorruptStateRecorderAuthority> recorder;
    std::unique_ptr<RegisteredRole1P1StateRecorderFacade> recorder_facade;
    std::optional<RegisteredP1StateArchiveChildTerminalAuthority> terminal;
    bool live{true};
};

struct RegisteredP1StateArchiveParentRoundAuthority::Storage {
    int channel{-1};
    unsigned round{};
    std::int64_t parent_pid{-1};
    std::int64_t child_pid{-1};
    FileFingerprint archive{};
    Digest reservation_identity{};
    Digest activation_identity{};
    Digest expected_trial_identity{};
    Digest expected_prelaunch_binding_identity{};
    bool live{true};
#ifdef KPI_REGISTERED_P1_STATE_ARCHIVE_SCM_TEST_SETUP
    unsigned* test_same_inode_count{};
#endif
    ~Storage() { close_fd(channel); }
};

struct RegisteredP1StateArchiveChildTerminalAuthority::Storage {
    int channel{-1};
    unsigned round{};
    std::int64_t parent_pid{-1};
    std::int64_t child_pid{-1};
    FileFingerprint archive{};
    Digest reservation_identity{};
    Digest activation_identity{};
    bool live{true};
#ifdef KPI_REGISTERED_P1_STATE_ARCHIVE_SCM_TEST_SETUP
    RegisteredP1StateArchiveScmTestFault test_fault{
        RegisteredP1StateArchiveScmTestFault::None};
#endif
    ~Storage() { close_fd(channel); }
};

P1StateArchiveWriterAdoptionAuthority::Storage::~Storage() {
    close_fd(writer);
}

RegisteredP1StateArchiveScmTransfer::RegisteredP1StateArchiveScmTransfer(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {}
RegisteredP1StateArchiveScmTransfer::RegisteredP1StateArchiveScmTransfer(
        RegisteredP1StateArchiveScmTransfer&&) noexcept = default;
RegisteredP1StateArchiveScmTransfer::~RegisteredP1StateArchiveScmTransfer() =
    default;

RegisteredP1StateArchiveChildRoundAuthority::
RegisteredP1StateArchiveChildRoundAuthority(std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) {}
RegisteredP1StateArchiveChildRoundAuthority::
RegisteredP1StateArchiveChildRoundAuthority(
        RegisteredP1StateArchiveChildRoundAuthority&&) noexcept = default;
RegisteredP1StateArchiveChildRoundAuthority::
~RegisteredP1StateArchiveChildRoundAuthority() = default;

RegisteredRole1P1StatePrelaunchAuthority::
RegisteredRole1P1StatePrelaunchAuthority(std::unique_ptr<Storage> storage)
        noexcept : storage_(std::move(storage)) {}
RegisteredRole1P1StatePrelaunchAuthority::
RegisteredRole1P1StatePrelaunchAuthority(
        RegisteredRole1P1StatePrelaunchAuthority&&) noexcept = default;
RegisteredRole1P1StatePrelaunchAuthority::
~RegisteredRole1P1StatePrelaunchAuthority() = default;

RegisteredRole1P1StateRecorderFacade::
RegisteredRole1P1StateRecorderFacade(
        kpb::measurement::p1_state_capsule::
            P1CorruptStateRecorderAuthority* recorder) noexcept
    : recorder_(recorder) {}

kpb::measurement::p1_state_capsule::P1StateThreadEpochAuthority
RegisteredRole1P1StateRecorderFacade::take_root_thread_epoch() {
    need(recorder_ != nullptr);
    return recorder_->take_root_thread_epoch();
}

std::unique_ptr<kpb::measurement::p1_state_capsule::
    P1ContextAndRetryStateAdapter>
RegisteredRole1P1StateRecorderFacade::take_context_and_retry_adapter(
        const kpb::measurement::p1_state_capsule::
            P1StateThreadEpochAuthority& root_thread) {
    need(recorder_ != nullptr);
    return recorder_->take_context_and_retry_adapter(root_thread);
}

std::unique_ptr<kpb::measurement::p1_state_capsule::P1EntropyStateAdapter>
RegisteredRole1P1StateRecorderFacade::take_entropy_state_adapter(
        const kpb::measurement::p1_state_capsule::
            P1StateThreadEpochAuthority& root_thread) {
    need(recorder_ != nullptr);
    return recorder_->take_entropy_state_adapter(root_thread);
}

std::unique_ptr<kpb::measurement::p1_state_capsule::
    P1MascotSecretStateAdapter>
RegisteredRole1P1StateRecorderFacade::take_mascot_secret_state_adapter(
        const kpb::measurement::p1_state_capsule::
            P1StateThreadEpochAuthority& root_thread) {
    need(recorder_ != nullptr);
    return recorder_->take_mascot_secret_state_adapter(root_thread);
}

std::unique_ptr<kpb::measurement::p1_state_capsule::
    P1PlayerTlsStateAdapter>
RegisteredRole1P1StateRecorderFacade::take_player_tls_state_adapter(
        const kpb::measurement::p1_state_capsule::
            P1StateThreadEpochAuthority& root_thread) {
    need(recorder_ != nullptr);
    return recorder_->take_player_tls_state_adapter(root_thread);
}

void RegisteredRole1P1StateRecorderFacade::advance_phase(
        kpb::measurement::p1_state_capsule::SourcePhase next) {
    need(recorder_ != nullptr);
    recorder_->advance_phase(next);
}

RegisteredRole1P1StateRuntimeAuthority::
RegisteredRole1P1StateRuntimeAuthority(std::unique_ptr<Storage> storage)
        noexcept : storage_(std::move(storage)) {}
RegisteredRole1P1StateRuntimeAuthority::
RegisteredRole1P1StateRuntimeAuthority(
        RegisteredRole1P1StateRuntimeAuthority&&) noexcept = default;

void RegisteredRole1P1StateRuntimeAuthority::
finish_unavailable_noexcept(Storage* storage) noexcept {
    if (storage == nullptr || !std::exchange(storage->live, false)) return;
    storage->recorder_facade.reset();
    if (storage->recorder.has_value()) {
        auto capsule = std::move(*storage->recorder)
            .close_unavailable_abort_noexcept(
                AbortClass::Resource, role1_runtime_unwind_identity());
        storage->recorder.reset();
        if (storage->terminal.has_value()) {
            RegisteredP1StateCapsuleChildDispositionBridge::
                send_terminal_noexcept(
                    std::move(*storage->terminal), std::move(capsule));
            storage->terminal.reset();
        }
    } else {
        storage->terminal.reset();
    }
}

RegisteredRole1P1StateRuntimeAuthority::
~RegisteredRole1P1StateRuntimeAuthority() {
    finish_unavailable_noexcept(storage_.get());
}

RegisteredRole1P1StateRecorderFacade&
RegisteredRole1P1StateRuntimeAuthority::recorder() {
    need(storage_ != nullptr && storage_->live &&
         storage_->recorder.has_value() &&
         storage_->recorder_facade != nullptr &&
         storage_->terminal.has_value());
    return *storage_->recorder_facade;
}

void RegisteredRole1P1StateRuntimeAuthority::finish_unavailable_noexcept()
        && noexcept {
    auto storage = std::move(storage_);
    finish_unavailable_noexcept(storage.get());
}

RegisteredRole1P1StatePrelaunchAuthority
ParentAuthenticatedRole1Delivery::take_p1_state_prelaunch() {
    need(delivery_ != nullptr &&
         delivery_->role1_p1_state_prelaunch_attached_ &&
         !delivery_->role1_p1_state_prelaunch_taken_ &&
         delivery_->role1_p1_state_prelaunch_ != nullptr &&
         delivery_->role1_p1_state_prelaunch_destroy_ != nullptr);
    auto* const retained = static_cast<
        RegisteredRole1P1StatePrelaunchAuthority*>(std::exchange(
            delivery_->role1_p1_state_prelaunch_, nullptr));
    delivery_->role1_p1_state_prelaunch_destroy_ = nullptr;
    delivery_->role1_p1_state_prelaunch_taken_ = true;
    std::unique_ptr<RegisteredRole1P1StatePrelaunchAuthority> owner(retained);
    return std::move(*owner);
}

RegisteredP1StateArchiveParentRoundAuthority::
RegisteredP1StateArchiveParentRoundAuthority(std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) {}
RegisteredP1StateArchiveParentRoundAuthority::
RegisteredP1StateArchiveParentRoundAuthority(
        RegisteredP1StateArchiveParentRoundAuthority&&) noexcept = default;
RegisteredP1StateArchiveParentRoundAuthority::
~RegisteredP1StateArchiveParentRoundAuthority() = default;

P1StateArchiveWriterAdoptionAuthority::
P1StateArchiveWriterAdoptionAuthority(std::unique_ptr<Storage> storage)
        noexcept : storage_(std::move(storage)) {}
P1StateArchiveWriterAdoptionAuthority::
P1StateArchiveWriterAdoptionAuthority(
        P1StateArchiveWriterAdoptionAuthority&&) noexcept = default;
P1StateArchiveWriterAdoptionAuthority::
~P1StateArchiveWriterAdoptionAuthority() = default;

RegisteredP1StateArchiveChildTerminalAuthority::
RegisteredP1StateArchiveChildTerminalAuthority(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {}
RegisteredP1StateArchiveChildTerminalAuthority::
RegisteredP1StateArchiveChildTerminalAuthority(
        RegisteredP1StateArchiveChildTerminalAuthority&&) noexcept = default;
RegisteredP1StateArchiveChildTerminalAuthority::
~RegisteredP1StateArchiveChildTerminalAuthority() = default;

P1StateArchiveWriterAdoptionBundle::P1StateArchiveWriterAdoptionBundle(
        P1StateArchiveWriterAdoptionAuthority&& writer,
        RegisteredP1StateArchiveChildTerminalAuthority&& terminal) noexcept
    : writer_(std::move(writer)), terminal_(std::move(terminal)) {}
P1StateArchiveWriterAdoptionBundle::P1StateArchiveWriterAdoptionBundle(
        P1StateArchiveWriterAdoptionBundle&& other) noexcept
    : writer_(std::move(other.writer_)), terminal_(std::move(other.terminal_)),
      live_(std::exchange(other.live_, false)) {}
P1StateArchiveWriterAdoptionBundle::~P1StateArchiveWriterAdoptionBundle() =
    default;

std::optional<std::pair<P1StateArchiveWriterAdoptionAuthority,
                        RegisteredP1StateArchiveChildTerminalAuthority>>
P1StateArchiveWriterAdoptionBundle::split() && noexcept {
    if (!live_ || !writer_.has_value() || !terminal_.has_value())
        return std::nullopt;
    std::optional<std::pair<P1StateArchiveWriterAdoptionAuthority,
                            RegisteredP1StateArchiveChildTerminalAuthority>>
        result(std::in_place, std::move(*writer_), std::move(*terminal_));
    live_ = false;
    writer_.reset();
    terminal_.reset();
    return result;
}

RegisteredP1StateArchiveScmTransfer
RegisteredP1StateArchiveScmBridge::extract_state_channels(
        FreshTrialCaptureTopologyActivationTransfer& topology) {
    need(topology.live_.load() &&
         nonzero(topology.reservation_identity_));

    // Snapshot every capture-owned field and prove that extracting state
    // channels mutates none of them.
    const auto capture_reads = topology.read_ends_;
    const auto capture_writers = topology.writer_aliases_;
    const auto capture_archives = topology.archive_fds_;
    const auto capture_devices = topology.endpoint_devices_;
    const auto capture_inodes = topology.endpoint_inodes_;
    const auto archive_devices = topology.archive_devices_;
    const auto archive_inodes = topology.archive_inodes_;

    auto result = std::make_unique<
        RegisteredP1StateArchiveScmTransfer::Storage>();
    std::array<FileFingerprint, 2> parents{};
    std::array<FileFingerprint, 2> children{};
    for (unsigned round = 0; round < 2; ++round) {
        parents[round] = regular_file(
            topology.p1_state_parent_read_fds_[round], O_RDONLY, true);
        children[round] = regular_file(
            topology.p1_state_child_writer_aliases_[round], O_WRONLY, true);
        const auto& parent = parents[round];
        const auto& child = children[round];
        need(parent.device == child.device &&
             parent.inode == child.inode && parent.mode == child.mode &&
             parent.nlink == child.nlink && parent.size == child.size &&
             parent.device == topology.p1_state_devices_[round] &&
             parent.inode == topology.p1_state_inodes_[round] &&
             parent.mode == topology.p1_state_modes_[round] &&
             parent.nlink == topology.p1_state_nlinks_[round] &&
             parent.size == topology.p1_state_sizes_[round] &&
             kFreshTrialP1StateArchiveContracts[round].state_slot == round &&
             kFreshTrialP1StateArchiveContracts[round].round == round + 1 &&
             !kFreshTrialP1StateArchiveContracts[round]
                  .fixed_child_fd_required);
        result->devices[round] = parent.device;
        result->inodes[round] = parent.inode;
        result->modes[round] = parent.mode;
        result->nlinks[round] = parent.nlink;
        result->sizes[round] = parent.size;
    }
    need(result->inodes[0] != result->inodes[1]);
    result->reservation_identity = topology.reservation_identity_;

    // Every validation, comparison and possible exception precedes the
    // all-four-descriptor claim. A round-2 refusal cannot consume round 1.
    need(topology.read_ends_ == capture_reads &&
         topology.writer_aliases_ == capture_writers &&
         topology.archive_fds_ == capture_archives &&
         topology.endpoint_devices_ == capture_devices &&
         topology.endpoint_inodes_ == capture_inodes &&
         topology.archive_devices_ == archive_devices &&
         topology.archive_inodes_ == archive_inodes);
    for (unsigned round = 0; round < 2; ++round) {
        result->parent_reads[round] =
            std::exchange(topology.p1_state_parent_read_fds_[round], -1);
        result->child_writers[round] = std::exchange(
            topology.p1_state_child_writer_aliases_[round], -1);
    }
    return RegisteredP1StateArchiveScmTransfer(std::move(result));
}

P1StateArchiveWriterAdoptionBundle
RegisteredP1StateArchiveScmBridge::prepare_writer_adoption(
        RegisteredP1StateArchiveChildRoundAuthority&& selected) {
    // Allocate both residual owners, then complete every syscall and identity
    // check through the still-live caller authority.  Only the final block
    // claims storage, and everything after that claim is a no-throw move or
    // exchange.
    auto writer = std::make_unique<
        P1StateArchiveWriterAdoptionAuthority::Storage>();
    auto terminal = std::make_unique<
        RegisteredP1StateArchiveChildTerminalAuthority::Storage>();
    const auto* inspected = selected.storage_.get();
    need(inspected != nullptr && inspected->live &&
         (inspected->round == 1 || inspected->round == 2) &&
         inspected->parent_pid > 1 && inspected->child_pid == ::getpid() &&
         nonzero(inspected->reservation_identity) &&
         nonzero(inspected->activation_identity));
    require_seqpacket(inspected->channel);
    const int writer_flags = ::fcntl(inspected->writer, F_GETFL);
    const off_t writer_offset = ::lseek(inspected->writer, 0, SEEK_CUR);
    need(writer_flags >= 0 && (writer_flags & O_APPEND) == 0 &&
         writer_offset == 0);
    const auto archive = regular_file(inspected->writer, O_WRONLY, true);
    need(archive.device == inspected->archive.device &&
         archive.inode == inspected->archive.inode &&
         archive.mode == inspected->archive.mode &&
         archive.nlink == inspected->archive.nlink && archive.size == 0);

    writer->round = inspected->round;
    writer->parent_pid = inspected->parent_pid;
    writer->child_pid = inspected->child_pid;
    writer->device = archive.device;
    writer->inode = archive.inode;
    writer->mode = archive.mode;
    writer->nlink = archive.nlink;
    writer->size = archive.size;
    writer->reservation_identity = inspected->reservation_identity;
    writer->activation_identity = inspected->activation_identity;

    terminal->round = inspected->round;
    terminal->parent_pid = inspected->parent_pid;
    terminal->child_pid = inspected->child_pid;
    terminal->archive = archive;
    terminal->reservation_identity = inspected->reservation_identity;
    terminal->activation_identity = inspected->activation_identity;
#ifdef KPI_REGISTERED_P1_STATE_ARCHIVE_SCM_TEST_SETUP
    terminal->test_fault = inspected->test_fault;
#endif

    auto source = std::move(selected.storage_);
    source->live = false;
    writer->writer = std::exchange(source->writer, -1);
    terminal->channel = std::exchange(source->channel, -1);
    return P1StateArchiveWriterAdoptionBundle(
        P1StateArchiveWriterAdoptionAuthority(std::move(writer)),
        RegisteredP1StateArchiveChildTerminalAuthority(
            std::move(terminal)));
}

void RegisteredP1StateArchiveScmBridge::attach_role1_prelaunch(
        ParentAuthenticatedPartyDeliveryAuthority& delivery,
        RegisteredP1StateArchiveChildRoundAuthority&& child_round,
        kpb::measurement::p1_state_capsule::
            P1CorruptStateCapsulePlanAuthority&& capsule_plan) {
    // Allocate both retained layers before claiming either linear input.
    // The paired claim precedes validation: a stale/substituted plan burns
    // the child endpoint, and a stale/substituted endpoint burns the plan.
    // The joined owner makes every subsequent refusal resource-safe.
    auto joined_storage =
        std::make_unique<RegisteredRole1P1StatePrelaunchAuthority::Storage>();
    auto* const joined = joined_storage.get();
    auto joined_authority =
        std::unique_ptr<RegisteredRole1P1StatePrelaunchAuthority>(
            new RegisteredRole1P1StatePrelaunchAuthority(
                std::move(joined_storage)));

    static_assert(noexcept(joined->child_round.emplace(
        std::declval<RegisteredP1StateArchiveChildRoundAuthority&&>())));
    static_assert(noexcept(joined->capsule_plan.emplace(
        std::declval<kpb::measurement::p1_state_capsule::
            P1CorruptStateCapsulePlanAuthority&&>())));

    // Paired one-shot claim. No allocation follows.
    joined->child_round.emplace(std::move(child_round));
    joined->capsule_plan.emplace(std::move(capsule_plan));

    const auto* const child = joined->child_round->storage_.get();
    need(delivery.live_.load() && delivery.value_.role == 1 &&
         (delivery.value_.round == 1 || delivery.value_.round == 2) &&
         delivery.value_.parent_pid > 1 &&
         delivery.value_.child_pid == ::getpid() &&
         nonzero(delivery.value_.capture_plan_identity) &&
         !delivery.role1_p1_state_prelaunch_attached_ &&
         !delivery.role1_p1_state_prelaunch_taken_ &&
         delivery.role1_p1_state_prelaunch_ == nullptr &&
         child != nullptr && child->live &&
         child->round == delivery.value_.round &&
         child->parent_pid == delivery.value_.parent_pid &&
         child->child_pid == delivery.value_.child_pid &&
         nonzero(child->reservation_identity) &&
         nonzero(child->activation_identity));

    require_seqpacket(child->channel);
    const int writer_flags = ::fcntl(child->writer, F_GETFL);
    const off_t writer_offset = ::lseek(child->writer, 0, SEEK_CUR);
    need(writer_flags >= 0 && (writer_flags & O_APPEND) == 0 &&
         writer_offset == 0);
    const auto archive = regular_file(child->writer, O_WRONLY, true);
    need(archive.device == child->archive.device &&
         archive.inode == child->archive.inode &&
         archive.mode == child->archive.mode &&
         archive.nlink == child->archive.nlink && archive.size == 0);

    joined->capsule_plan->validate_for_role1_prelaunch_attachment(
        child->round, child->reservation_identity,
        delivery.value_.capture_plan_identity);
    joined->unavailable_trial_identity = joined->capsule_plan->
        unavailable_trial_identity_for_role1_prelaunch();
    joined->unavailable_prelaunch_binding_identity =
        joined->capsule_plan->
            unavailable_prelaunch_binding_identity_for_role1_prelaunch();
    need(nonzero(joined->unavailable_trial_identity) &&
         nonzero(joined->unavailable_prelaunch_binding_identity));

    delivery.role1_p1_state_prelaunch_ = joined_authority.release();
    delivery.role1_p1_state_prelaunch_destroy_ = [](void* raw) noexcept {
        delete static_cast<RegisteredRole1P1StatePrelaunchAuthority*>(raw);
    };
    delivery.role1_p1_state_prelaunch_attached_ = true;
}

} // namespace kpi::mpc::financial::registered_driver

namespace kpb::measurement::p1_state_capsule {

struct P1AuthenticatedChildStateDispositionAuthority::Storage {
    unsigned round{};
    std::int64_t child_pid{-1};
    bool manifest_structurally_complete{};
    bool unavailable{};
    bool aborted{};
    std::uint64_t topology_device{};
    std::uint64_t topology_inode{};
    std::uint64_t capsule_device{};
    std::uint64_t capsule_inode{};
    std::uint64_t archive_bytes{};
    std::uint64_t sequence{};
    std::uint64_t missing_family_bitmap{};
    std::uint64_t closed_family_bitmap{};
    std::uint64_t not_constructed_bitmap{};
    std::uint64_t abort_prefix_bitmap{};
    SourcePhase terminal_phase{};
    AbortClass abort_class{};
    Digest reservation_identity{};
    Digest capsule_topology_identity{};
    Digest trial_identity{};
    Digest archive_sha256{};
    Digest activation_identity{};
    Digest terminal_identity{};
    Digest prelaunch_binding_identity{};
    bool live{true};
};

P1AuthenticatedChildStateDispositionAuthority::
P1AuthenticatedChildStateDispositionAuthority(std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) {}
P1AuthenticatedChildStateDispositionAuthority::
P1AuthenticatedChildStateDispositionAuthority(
        P1AuthenticatedChildStateDispositionAuthority&&) noexcept = default;
P1AuthenticatedChildStateDispositionAuthority::
~P1AuthenticatedChildStateDispositionAuthority() = default;

} // namespace kpb::measurement::p1_state_capsule

namespace kpi::mpc::financial::registered_driver {
namespace {

struct TerminalFields final {
    unsigned round{};
    std::int64_t parent_pid{-1};
    std::int64_t child_pid{-1};
    FileFingerprint topology{};
    FileFingerprint capsule_file{};
    bool manifest_structurally_complete{};
    bool aborted{};
    SourcePhase terminal_phase{};
    AbortClass abort_class{};
    std::uint64_t archive_bytes{};
    std::uint64_t sequence{};
    std::uint64_t missing_family_bitmap{};
    std::uint64_t closed_family_bitmap{};
    std::uint64_t not_constructed_bitmap{};
    std::uint64_t abort_prefix_bitmap{};
    Digest reservation_identity{};
    Digest capsule_topology_identity{};
    Digest trial_identity{};
    Digest archive_sha256{};
    Digest activation_identity{};
    Digest abort_terminal_site_identity{};
    Digest prelaunch_binding_identity{};
    std::array<std::uint64_t,
        kpb::measurement::p1_state_capsule::STATE_FAMILY_COUNT>
        event_counts{};
};

std::array<unsigned char, TERMINAL_BYTES> make_terminal_packet(
        const TerminalFields& fields) {
    need(fields.round == 1 || fields.round == 2);
    std::array<unsigned char, TERMINAL_BYTES> result{};
    std::copy(TERMINAL_MAGIC.begin(), TERMINAL_MAGIC.end(), result.begin());
    result[8] = 1;
    result[9] = 2;
    result[10] = 1;
    result[11] = static_cast<unsigned char>(fields.round);
    // This bit binds only the capsule's structural manifest.  It is never an
    // observer-completeness or acceptance bit; the parent disposition remains
    // UNAVAILABLE until the source recorder, serializers and replay join exist.
    result[12] = fields.manifest_structurally_complete ? 1 : 2;
    result[13] = fields.aborted ? 1 : 0;
    result[14] = static_cast<unsigned char>(fields.terminal_phase);
    result[15] = static_cast<unsigned char>(fields.abort_class);
    put_u32(result, 16, static_cast<std::uint32_t>(fields.parent_pid));
    put_u32(result, 20, static_cast<std::uint32_t>(fields.child_pid));
    put_u64(result, 24, fields.topology.device);
    put_u64(result, 32, fields.topology.inode);
    put_u64(result, 40, fields.capsule_file.device);
    put_u64(result, 48, fields.capsule_file.inode);
    put_u64(result, 56, fields.archive_bytes);
    put_u64(result, 64, fields.sequence);
    put_u64(result, 72, fields.missing_family_bitmap);
    put_u64(result, 80, fields.closed_family_bitmap);
    put_u64(result, 88, fields.not_constructed_bitmap);
    put_u64(result, 96, fields.abort_prefix_bitmap);
    put_digest(result, 112, fields.reservation_identity);
    put_digest(result, 144, fields.capsule_topology_identity);
    put_digest(result, 176, fields.trial_identity);
    put_digest(result, 208, fields.archive_sha256);
    put_digest(result, 240, fields.activation_identity);
    put_digest(result, 272, fields.abort_terminal_site_identity);
    for (unsigned index = 0; index < fields.event_counts.size(); ++index)
        put_u64(result, 304 + 8 * index, fields.event_counts[index]);
    put_digest(result, 416, fields.prelaunch_binding_identity);
    put_digest(result, TERMINAL_IDENTITY_OFFSET,
               hash(std::span<const unsigned char>(
                   result.data(), TERMINAL_IDENTITY_OFFSET)));
    return result;
}

std::array<unsigned char, ACK_BYTES> make_terminal_ack(
        unsigned round, std::int64_t parent_pid, std::int64_t child_pid,
        const Digest& terminal_identity) {
    std::array<unsigned char, ACK_BYTES> result{};
    std::copy(ACK_MAGIC.begin(), ACK_MAGIC.end(), result.begin());
    result[8] = 1;
    result[9] = 3;
    result[10] = 1;
    result[11] = static_cast<unsigned char>(round);
    put_u32(result, 12, static_cast<std::uint32_t>(parent_pid));
    put_u32(result, 16, static_cast<std::uint32_t>(child_pid));
    put_digest(result, 20, terminal_identity);
    put_digest(result, ACK_IDENTITY_OFFSET,
               hash(std::span<const unsigned char>(
                   result.data(), ACK_IDENTITY_OFFSET)));
    return result;
}

void validate_terminal_ack(
        const std::array<unsigned char, ACK_BYTES>& value,
        unsigned round, std::int64_t parent_pid, std::int64_t child_pid,
        const Digest& terminal_identity) {
    need(std::equal(ACK_MAGIC.begin(), ACK_MAGIC.end(), value.begin()) &&
         value[8] == 1 && value[9] == 3 && value[10] == 1 &&
         value[11] == round &&
         get_u32(value, 12) == parent_pid &&
         get_u32(value, 16) == child_pid &&
         get_digest(value, 20) == terminal_identity &&
         get_digest(value, ACK_IDENTITY_OFFSET) ==
             hash(std::span<const unsigned char>(
                 value.data(), ACK_IDENTITY_OFFSET)));
}

} // namespace

void RegisteredP1StateCapsuleChildDispositionBridge::send_terminal_noexcept(
        RegisteredP1StateArchiveChildTerminalAuthority&& selected_endpoint,
        kpb::measurement::p1_state_capsule::
            P1CorruptStateCapsuleAuthority&& selected_capsule) noexcept {
    auto endpoint = std::move(selected_endpoint.storage_);
    try {
        need(endpoint != nullptr && endpoint->live &&
             endpoint->round >= 1 && endpoint->round <= 2 &&
             endpoint->parent_pid > 1 && endpoint->child_pid == ::getpid() &&
             nonzero(endpoint->reservation_identity) &&
             nonzero(endpoint->activation_identity));
        endpoint->live = false;
        require_seqpacket(endpoint->channel);

        auto residual = std::move(selected_capsule)
            .consume_for_child_disposition();
        auto capsule = std::move(residual.storage_);
        need(capsule != nullptr);
        FileFingerprint capsule_file{};
        int capsule_access = -1;
        if (capsule->fd >= 0) {
            try {
                const auto selected = regular_file_any(capsule->fd, false);
                capsule_file = selected.value;
                capsule_access = selected.access;
            } catch (...) {
                capsule_file = {};
                capsule_access = -1;
            }
        }
        const bool manifest_structurally_complete =
            capsule->manifest_structurally_complete &&
            capsule->read_only && capsule->anonymous_disk_backed &&
            capsule->writer_closed && capsule->descriptor_retained &&
            capsule_access == O_RDONLY &&
            capsule->plan.role == 1 &&
            capsule->plan.round == endpoint->round &&
            capsule->plan.topology_reservation_identity ==
                endpoint->reservation_identity &&
            capsule_file.device == endpoint->archive.device &&
            capsule_file.inode == endpoint->archive.inode &&
            capsule_file.size == capsule->archive_bytes;

        const TerminalFields fields{
            .round = endpoint->round,
            .parent_pid = endpoint->parent_pid,
            .child_pid = endpoint->child_pid,
            .topology = endpoint->archive,
            .capsule_file = capsule_file,
            .manifest_structurally_complete =
                manifest_structurally_complete,
            .aborted = capsule->aborted,
            .terminal_phase =
                capsule->terminal_phase >= SourcePhase::RecorderStarted &&
                        capsule->terminal_phase <= SourcePhase::TerminalEgress
                    ? capsule->terminal_phase
                    : SourcePhase::RecorderStarted,
            .abort_class =
                capsule->abort_class >= AbortClass::Transport &&
                        capsule->abort_class <= AbortClass::Resource
                    ? capsule->abort_class
                    : AbortClass::Resource,
            .archive_bytes = capsule->archive_bytes,
            .sequence = capsule->sequence,
            .missing_family_bitmap = capsule->missing_family_bitmap,
            .closed_family_bitmap = capsule->closed_family_bitmap,
            .not_constructed_bitmap = capsule->not_constructed_bitmap,
            .abort_prefix_bitmap = capsule->abort_prefix_bitmap,
            .reservation_identity = endpoint->reservation_identity,
            .capsule_topology_identity =
                capsule->plan.topology_reservation_identity,
            .trial_identity = capsule->plan.prelaunch.trial,
            .archive_sha256 = capsule->archive_sha256,
            .activation_identity = endpoint->activation_identity,
            .abort_terminal_site_identity =
                capsule->abort_terminal_site_identity,
            .prelaunch_binding_identity =
                capsule->plan.prelaunch.binding_identity,
            .event_counts = capsule->event_counts,
        };
        const auto packet = make_terminal_packet(fields);
        const auto terminal_identity = get_digest(
            packet, TERMINAL_IDENTITY_OFFSET);
#ifdef KPI_REGISTERED_P1_STATE_ARCHIVE_SCM_TEST_SETUP
        if (endpoint->test_fault ==
                RegisteredP1StateArchiveScmTestFault::TerminalTruncated) {
            send_exact(endpoint->channel,
                       std::span<const unsigned char>(
                           packet.data(), packet.size() / 2));
            return;
        }
#endif
        send_exact(endpoint->channel, packet);
#ifdef KPI_REGISTERED_P1_STATE_ARCHIVE_SCM_TEST_SETUP
        if (endpoint->test_fault ==
            RegisteredP1StateArchiveScmTestFault::TerminalReplay)
            send_exact(endpoint->channel, packet);
#endif
        const auto ack = receive_authenticated<ACK_BYTES>(
            endpoint->channel, endpoint->parent_pid);
        validate_terminal_ack(
            ack.bytes, endpoint->round, endpoint->parent_pid,
            endpoint->child_pid, terminal_identity);
    } catch (...) {
        // This is a terminal child path.  Both opaque inputs are burned and
        // their descriptors close even if the parent refuses or disappears.
    }
}

kpb::measurement::p1_state_capsule::
P1AuthenticatedChildStateDispositionAuthority
RegisteredP1StateCapsuleChildDispositionBridge::receive_terminal(
        RegisteredP1StateArchiveParentRoundAuthority&& selected_endpoint) {
    using Result = kpb::measurement::p1_state_capsule::
        P1AuthenticatedChildStateDispositionAuthority;
    // Preallocate the only semantic result before consuming a packet.
    auto result = std::make_unique<Result::Storage>();
    auto endpoint = std::move(selected_endpoint.storage_);
    need(endpoint != nullptr && endpoint->live &&
         endpoint->round >= 1 && endpoint->round <= 2 &&
         endpoint->parent_pid == ::getpid() && endpoint->child_pid > 1 &&
         nonzero(endpoint->reservation_identity) &&
         nonzero(endpoint->activation_identity));
    endpoint->live = false;
    require_seqpacket(endpoint->channel);
    const auto received = receive_authenticated<TERMINAL_BYTES>(
        endpoint->channel, endpoint->child_pid);
    const auto& packet = received.bytes;
    need(std::equal(
             TERMINAL_MAGIC.begin(), TERMINAL_MAGIC.end(), packet.begin()) &&
         packet[8] == 1 && packet[9] == 2 && packet[10] == 1 &&
         packet[11] == endpoint->round &&
         (packet[12] == 1 || packet[12] == 2) && packet[13] <= 1 &&
         packet[14] >= static_cast<unsigned char>(
                           SourcePhase::RecorderStarted) &&
         packet[14] <= static_cast<unsigned char>(
                           SourcePhase::TerminalEgress) &&
         packet[15] >= static_cast<unsigned char>(AbortClass::Transport) &&
         packet[15] <= static_cast<unsigned char>(AbortClass::Resource) &&
         get_u32(packet, 16) == endpoint->parent_pid &&
         get_u32(packet, 20) == endpoint->child_pid &&
         get_u64(packet, 24) == endpoint->archive.device &&
         get_u64(packet, 32) == endpoint->archive.inode &&
         get_digest(packet, 112) == endpoint->reservation_identity &&
         get_digest(packet, 240) == endpoint->activation_identity &&
         get_digest(packet, 176) == endpoint->expected_trial_identity &&
         get_digest(packet, 416) ==
             endpoint->expected_prelaunch_binding_identity &&
         nonzero(endpoint->expected_trial_identity) &&
         nonzero(endpoint->expected_prelaunch_binding_identity));
    const auto terminal_identity = get_digest(
        packet, TERMINAL_IDENTITY_OFFSET);
    need(nonzero(terminal_identity) && terminal_identity ==
         hash(std::span<const unsigned char>(
             packet.data(), TERMINAL_IDENTITY_OFFSET)) &&
         std::all_of(packet.begin() + 480, packet.end(),
                     [](unsigned char value) { return value == 0; }));
    const bool manifest_structurally_complete = packet[12] == 1;
    need(!manifest_structurally_complete ||
         (get_u64(packet, 40) == endpoint->archive.device &&
          get_u64(packet, 48) == endpoint->archive.inode &&
          get_digest(packet, 144) == endpoint->reservation_identity &&
          nonzero(get_digest(packet, 208))));
#ifdef KPI_REGISTERED_P1_STATE_ARCHIVE_SCM_TEST_SETUP
    if (endpoint->test_same_inode_count != nullptr &&
        get_u64(packet, 40) == endpoint->archive.device &&
        get_u64(packet, 48) == endpoint->archive.inode)
        ++*endpoint->test_same_inode_count;
#endif

    const auto ack = make_terminal_ack(
        endpoint->round, endpoint->parent_pid, endpoint->child_pid,
        terminal_identity);
    send_exact(endpoint->channel, ack);
    // Exact one-shot close is part of acceptance: a replayed second packet is
    // observed instead of EOF and refuses the semantic token.
    require_peer_eof(endpoint->channel);

    result->round = endpoint->round;
    result->child_pid = endpoint->child_pid;
    result->manifest_structurally_complete =
        manifest_structurally_complete;
    result->unavailable = true;
    result->aborted = packet[13] == 1;
    result->terminal_phase = static_cast<SourcePhase>(packet[14]);
    result->abort_class = static_cast<AbortClass>(packet[15]);
    result->topology_device = get_u64(packet, 24);
    result->topology_inode = get_u64(packet, 32);
    result->capsule_device = get_u64(packet, 40);
    result->capsule_inode = get_u64(packet, 48);
    result->archive_bytes = get_u64(packet, 56);
    result->sequence = get_u64(packet, 64);
    result->missing_family_bitmap = get_u64(packet, 72);
    result->closed_family_bitmap = get_u64(packet, 80);
    result->not_constructed_bitmap = get_u64(packet, 88);
    result->abort_prefix_bitmap = get_u64(packet, 96);
    result->reservation_identity = get_digest(packet, 112);
    result->capsule_topology_identity = get_digest(packet, 144);
    result->trial_identity = get_digest(packet, 176);
    result->archive_sha256 = get_digest(packet, 208);
    result->activation_identity = get_digest(packet, 240);
    result->terminal_identity = terminal_identity;
    result->prelaunch_binding_identity = get_digest(packet, 416);
    return Result(std::move(result));
}

RegisteredRole1P1StateRuntimeAuthority
RegisteredP1StateArchiveScmBridge::begin_role1_prelaunch(
        RegisteredRole1P1StatePrelaunchAuthority&& selected) {
    // Every allocation needed to retain the recorder, writer, and terminal
    // endpoint occurs before the joined prelaunch capability is claimed.
    auto runtime =
        std::make_unique<RegisteredRole1P1StateRuntimeAuthority::Storage>();
    auto writer =
        std::make_unique<P1StateArchiveWriterAdoptionAuthority::Storage>();
    auto terminal = std::make_unique<
        RegisteredP1StateArchiveChildTerminalAuthority::Storage>();
    auto recorder_facade =
        std::unique_ptr<RegisteredRole1P1StateRecorderFacade>(
            new RegisteredRole1P1StateRecorderFacade(nullptr));

    auto source = std::move(selected.storage_);
    need(source != nullptr && std::exchange(source->live, false) &&
         source->child_round.has_value() &&
         source->capsule_plan.has_value() &&
         nonzero(source->unavailable_trial_identity) &&
         nonzero(source->unavailable_prelaunch_binding_identity));
    const Digest unavailable_trial_identity =
        source->unavailable_trial_identity;
    const Digest unavailable_prelaunch_binding_identity =
        source->unavailable_prelaunch_binding_identity;
#ifdef KPI_REGISTERED_P1_STATE_ARCHIVE_SCM_TEST_SETUP
    const bool deny_recorder_begin_allocation =
        source->deny_recorder_begin_allocation;
    auto* const allocation_gate = source->allocation_gate;
    need(!deny_recorder_begin_allocation || allocation_gate != nullptr);
#endif

    auto* child = source->child_round->storage_.get();
    need(child != nullptr && child->live && child->channel >= 0 &&
         child->writer >= 0 &&
         (child->round == 1 || child->round == 2) &&
         child->parent_pid > 1 && child->child_pid == ::getpid() &&
         nonzero(child->reservation_identity) &&
         nonzero(child->activation_identity));

    // Claim the exact terminal endpoint first. From this instruction onward,
    // every fallible recorder-start operation can emit an authenticated,
    // structural=false UNAVAILABLE packet with the exact trial/topology.
    terminal->round = child->round;
    terminal->parent_pid = child->parent_pid;
    terminal->child_pid = child->child_pid;
    terminal->archive = child->archive;
    terminal->reservation_identity = child->reservation_identity;
    terminal->activation_identity = child->activation_identity;
#ifdef KPI_REGISTERED_P1_STATE_ARCHIVE_SCM_TEST_SETUP
    terminal->test_fault = child->test_fault;
#endif
    terminal->channel = std::exchange(child->channel, -1);
    auto terminal_authority =
        RegisteredP1StateArchiveChildTerminalAuthority(
            std::move(terminal));

    const auto send_pre_recorder_unavailable = [&]() noexcept {
        auto endpoint = std::move(terminal_authority.storage_);
        try {
            need(endpoint != nullptr && endpoint->live &&
                 (endpoint->round == 1 || endpoint->round == 2) &&
                 endpoint->parent_pid > 1 &&
                 endpoint->child_pid == ::getpid() &&
                 nonzero(endpoint->reservation_identity) &&
                 nonzero(endpoint->activation_identity) &&
                 nonzero(unavailable_trial_identity));
            endpoint->live = false;
            require_seqpacket(endpoint->channel);
            static_assert(
                kpb::measurement::p1_state_capsule::STATE_FAMILY_COUNT < 64);
            constexpr std::uint64_t all_families =
                (std::uint64_t{1} <<
                 kpb::measurement::p1_state_capsule::STATE_FAMILY_COUNT) - 1;
            const TerminalFields fields{
                .round = endpoint->round,
                .parent_pid = endpoint->parent_pid,
                .child_pid = endpoint->child_pid,
                .topology = endpoint->archive,
                .capsule_file = {},
                .manifest_structurally_complete = false,
                .aborted = true,
                .terminal_phase = SourcePhase::RecorderStarted,
                .abort_class = AbortClass::Resource,
                .archive_bytes = 0,
                .sequence = 0,
                .missing_family_bitmap = all_families,
                .closed_family_bitmap = 0,
                .not_constructed_bitmap = 0,
                .abort_prefix_bitmap = 0,
                .reservation_identity = endpoint->reservation_identity,
                // No recorder/capsule was minted. These capsule-derived
                // fields stay absent rather than borrowing topology lineage.
                .capsule_topology_identity = {},
                .trial_identity = unavailable_trial_identity,
                .archive_sha256 = {},
                .activation_identity = endpoint->activation_identity,
                .abort_terminal_site_identity = {},
                .prelaunch_binding_identity =
                    unavailable_prelaunch_binding_identity,
                .event_counts = {},
            };
            const auto packet = make_terminal_packet(fields);
            const auto terminal_identity = get_digest(
                packet, TERMINAL_IDENTITY_OFFSET);
            send_exact(endpoint->channel, packet);
            const auto ack = receive_authenticated<ACK_BYTES>(
                endpoint->channel, endpoint->parent_pid);
            validate_terminal_ack(
                ack.bytes, endpoint->round, endpoint->parent_pid,
                endpoint->child_pid, terminal_identity);
        } catch (...) {
            // A dead/substituted terminal channel cannot be made live by a
            // raw-PID fallback. Parent pidfd/EOF handling remains fail-closed.
        }
    };

    try {
        require_seqpacket(terminal_authority.storage_->channel);
        const int writer_flags = ::fcntl(child->writer, F_GETFL);
        const off_t writer_offset = ::lseek(child->writer, 0, SEEK_CUR);
        need(writer_flags >= 0 && (writer_flags & O_APPEND) == 0 &&
             writer_offset == 0);
        const auto archive = regular_file(child->writer, O_WRONLY, true);
        need(archive.device == child->archive.device &&
             archive.inode == child->archive.inode &&
             archive.mode == child->archive.mode &&
             archive.nlink == child->archive.nlink && archive.size == 0);

        writer->round = child->round;
        writer->parent_pid = child->parent_pid;
        writer->child_pid = child->child_pid;
        writer->device = archive.device;
        writer->inode = archive.inode;
        writer->mode = archive.mode;
        writer->nlink = archive.nlink;
        writer->size = archive.size;
        writer->reservation_identity = child->reservation_identity;
        writer->activation_identity = child->activation_identity;

        auto child_storage = std::move(source->child_round->storage_);
        child_storage->live = false;
        writer->writer = std::exchange(child_storage->writer, -1);
        source->child_round.reset();
        auto adoption = P1StateArchiveWriterAdoptionAuthority(
            std::move(writer));

#ifdef KPI_REGISTERED_P1_STATE_ARCHIVE_SCM_TEST_SETUP
        if (deny_recorder_begin_allocation) allocation_gate(true);
#endif
        auto recorder = std::move(*source->capsule_plan)
            .begin_before_player_and_protocol_setup(
                std::move(adoption));
#ifdef KPI_REGISTERED_P1_STATE_ARCHIVE_SCM_TEST_SETUP
        if (deny_recorder_begin_allocation) allocation_gate(false);
#endif
        source->capsule_plan.reset();

        static_assert(noexcept(runtime->recorder.emplace(
            std::declval<kpb::measurement::p1_state_capsule::
                P1CorruptStateRecorderAuthority&&>())));
        static_assert(noexcept(runtime->terminal.emplace(
            std::declval<
                RegisteredP1StateArchiveChildTerminalAuthority&&>())));
        runtime->recorder.emplace(std::move(recorder));
        recorder_facade->recorder_ = &*runtime->recorder;
        runtime->recorder_facade = std::move(recorder_facade);
        runtime->terminal.emplace(std::move(terminal_authority));
        return RegisteredRole1P1StateRuntimeAuthority(std::move(runtime));
    } catch (...) {
#ifdef KPI_REGISTERED_P1_STATE_ARCHIVE_SCM_TEST_SETUP
        if (deny_recorder_begin_allocation) allocation_gate(false);
#endif
        send_pre_recorder_unavailable();
        throw;
    }
}

} // namespace kpi::mpc::financial::registered_driver

#ifdef KPI_REGISTERED_P1_STATE_ARCHIVE_SCM_TEST_SETUP
namespace kpi::mpc::financial::registered_driver {
namespace {

constexpr std::array<unsigned char, 8> ACTIVATION_MAGIC{
    'K', 'P', 'B', 'P', '1', 'S', 'A', '5'};
constexpr std::array<unsigned char, 8> ACTIVATION_ACK_MAGIC{
    'K', 'P', 'B', 'P', '1', 'S', 'K', '5'};
constexpr std::size_t ACTIVATION_BYTES = 192;
constexpr std::size_t ACTIVATION_IDENTITY_OFFSET = 128;
constexpr std::size_t ACTIVATION_ACK_BYTES = 96;
constexpr std::size_t ACTIVATION_ACK_IDENTITY_OFFSET = 56;

struct ScopedFd final {
    int value{-1};
    ScopedFd() = default;
    explicit ScopedFd(int selected) : value(selected) {}
    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;
    ScopedFd(ScopedFd&& other) noexcept
        : value(std::exchange(other.value, -1)) {}
    ScopedFd& operator=(ScopedFd&& other) noexcept {
        if (this != &other) {
            close_fd(value);
            value = std::exchange(other.value, -1);
        }
        return *this;
    }
    ~ScopedFd() { close_fd(value); }
    int release() noexcept { return std::exchange(value, -1); }
};

void pass_credentials(int fd) {
    const int one = 1;
    need(::setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) == 0);
}

std::array<ScopedFd, 2> seqpacket_pair() {
    int raw[2]{-1, -1};
    need(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, raw) == 0);
    try {
        pass_credentials(raw[0]);
        pass_credentials(raw[1]);
        return {ScopedFd(raw[0]), ScopedFd(raw[1])};
    } catch (...) {
        close_fd(raw[0]);
        close_fd(raw[1]);
        throw;
    }
}

void install_control_child_allowlist(int inherited) {
    constexpr int CONTROL_FD = 63;
    int duplicated;
    do { duplicated = ::dup3(inherited, CONTROL_FD, O_CLOEXEC); }
    while (duplicated < 0 && errno == EINTR);
    need(duplicated == CONTROL_FD);
#ifdef SYS_close_range
    long first;
    do { first = ::syscall(SYS_close_range, 3U, 62U, 0U); }
    while (first < 0 && errno == EINTR);
    long second;
    do {
        second = ::syscall(
            SYS_close_range, 64U,
            std::numeric_limits<unsigned>::max(), 0U);
    } while (second < 0 && errno == EINTR);
    if (first == 0 && second == 0) return;
    need(errno == ENOSYS);
#endif
    for (int fd = 3; fd < 4096; ++fd)
        if (fd != CONTROL_FD) {
            int selected = fd;
            close_fd(selected);
        }
}

std::array<unsigned char, ACTIVATION_BYTES> activation_packet(
        unsigned round, unsigned role, std::int64_t parent_pid,
        std::int64_t child_pid, const FileFingerprint& archive,
        const Digest& reservation_identity) {
    std::array<unsigned char, ACTIVATION_BYTES> result{};
    std::copy(ACTIVATION_MAGIC.begin(), ACTIVATION_MAGIC.end(),
              result.begin());
    result[8] = 1;
    result[9] = 1;
    result[10] = static_cast<unsigned char>(role);
    result[11] = static_cast<unsigned char>(round);
    put_u32(result, 12, static_cast<std::uint32_t>(parent_pid));
    put_u32(result, 16, static_cast<std::uint32_t>(child_pid));
    put_u64(result, 24, archive.device);
    put_u64(result, 32, archive.inode);
    put_u32(result, 40, archive.mode);
    put_u64(result, 48, archive.nlink);
    put_u64(result, 56, archive.size);
    put_digest(result, 64, reservation_identity);
    put_digest(result, ACTIVATION_IDENTITY_OFFSET,
               hash(std::span<const unsigned char>(
                   result.data(), ACTIVATION_IDENTITY_OFFSET)));
    return result;
}

void send_activation_with_fds(
        int channel, std::span<const unsigned char> bytes,
        const std::array<int, 2>& descriptors) {
    std::array<unsigned char, CMSG_SPACE(2 * sizeof(int))> control{};
    struct iovec iov{const_cast<unsigned char*>(bytes.data()), bytes.size()};
    struct msghdr message{};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    auto* item = CMSG_FIRSTHDR(&message);
    need(item != nullptr);
    item->cmsg_level = SOL_SOCKET;
    item->cmsg_type = SCM_RIGHTS;
    item->cmsg_len = CMSG_LEN(2 * sizeof(int));
    std::memcpy(CMSG_DATA(item), descriptors.data(), 2 * sizeof(int));
    ssize_t count;
    do { count = ::sendmsg(channel, &message, MSG_NOSIGNAL); }
    while (count < 0 && errno == EINTR);
    need(count == static_cast<ssize_t>(bytes.size()));
}

struct ReceivedActivation final {
    std::array<unsigned char, ACTIVATION_BYTES> bytes{};
    std::array<ScopedFd, 2> descriptors{};
};

ReceivedActivation receive_activation(int channel, std::int64_t parent_pid) {
    struct pollfd watched{channel, POLLIN | POLLRDHUP, 0};
    int ready;
    do { ready = ::poll(&watched, 1, TERMINAL_TIMEOUT_MS); }
    while (ready < 0 && errno == EINTR);
    need(ready == 1 && (watched.revents & POLLIN) != 0 &&
         (watched.revents & (POLLERR | POLLNVAL)) == 0);
    ReceivedActivation result;
    std::array<unsigned char,
        CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(2 * sizeof(int))>
        control{};
    struct iovec iov{result.bytes.data(), result.bytes.size()};
    struct msghdr message{};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t count;
    do { count = ::recvmsg(channel, &message, MSG_CMSG_CLOEXEC); }
    while (count < 0 && errno == EINTR);
    need(count == static_cast<ssize_t>(result.bytes.size()) &&
         (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0);
    unsigned credentials = 0;
    unsigned rights = 0;
    unsigned descriptor_count = 0;
    for (auto* item = CMSG_FIRSTHDR(&message); item != nullptr;
         item = CMSG_NXTHDR(&message, item)) {
        if (item->cmsg_level == SOL_SOCKET &&
            item->cmsg_type == SCM_CREDENTIALS) {
            need(item->cmsg_len == CMSG_LEN(sizeof(struct ucred)));
            struct ucred selected{};
            std::memcpy(&selected, CMSG_DATA(item), sizeof(selected));
            need(selected.pid == parent_pid &&
                 selected.uid == ::geteuid() &&
                 selected.gid == ::getegid());
            ++credentials;
        } else {
            need(item->cmsg_level == SOL_SOCKET &&
                 item->cmsg_type == SCM_RIGHTS &&
                 item->cmsg_len == CMSG_LEN(2 * sizeof(int)));
            const auto* selected = reinterpret_cast<const int*>(
                CMSG_DATA(item));
            result.descriptors[0] = ScopedFd(selected[0]);
            result.descriptors[1] = ScopedFd(selected[1]);
            descriptor_count = 2;
            ++rights;
        }
    }
    need(credentials == 1 && rights == 1 && descriptor_count == 2);
    return result;
}

Digest validate_activation(
        const ReceivedActivation& received, unsigned round,
        std::int64_t parent_pid, std::int64_t child_pid) {
    const auto& value = received.bytes;
    need(std::equal(ACTIVATION_MAGIC.begin(), ACTIVATION_MAGIC.end(),
                    value.begin()) &&
         value[8] == 1 && value[9] == 1 && value[10] == 1 &&
         value[11] == round && get_u32(value, 12) == parent_pid &&
         get_u32(value, 16) == child_pid);
    const auto writer = regular_file(
        received.descriptors[0].value, O_WRONLY, true);
    need(writer.device == get_u64(value, 24) &&
         writer.inode == get_u64(value, 32) &&
         writer.mode == get_u32(value, 40) &&
         writer.nlink == get_u64(value, 48) &&
         writer.size == get_u64(value, 56));
    require_seqpacket(received.descriptors[1].value);
    const auto reservation_identity = get_digest(value, 64);
    const auto activation_identity = get_digest(
        value, ACTIVATION_IDENTITY_OFFSET);
    need(nonzero(reservation_identity) && nonzero(activation_identity) &&
         activation_identity == hash(std::span<const unsigned char>(
             value.data(), ACTIVATION_IDENTITY_OFFSET)) &&
         std::all_of(value.begin() + 160, value.end(),
                     [](unsigned char byte) { return byte == 0; }));
    return activation_identity;
}

std::array<unsigned char, ACTIVATION_ACK_BYTES> activation_ack(
        unsigned round, std::int64_t parent_pid, std::int64_t child_pid,
        const Digest& activation_identity) {
    std::array<unsigned char, ACTIVATION_ACK_BYTES> result{};
    std::copy(ACTIVATION_ACK_MAGIC.begin(), ACTIVATION_ACK_MAGIC.end(),
              result.begin());
    result[8] = 1;
    result[9] = 2;
    result[10] = 1;
    result[11] = static_cast<unsigned char>(round);
    put_u32(result, 12, static_cast<std::uint32_t>(parent_pid));
    put_u32(result, 16, static_cast<std::uint32_t>(child_pid));
    put_digest(result, 20, activation_identity);
    put_digest(result, ACTIVATION_ACK_IDENTITY_OFFSET,
               hash(std::span<const unsigned char>(
                   result.data(), ACTIVATION_ACK_IDENTITY_OFFSET)));
    return result;
}

void validate_activation_ack(
        const std::array<unsigned char, ACTIVATION_ACK_BYTES>& value,
        unsigned round, std::int64_t parent_pid, std::int64_t child_pid,
        const Digest& activation_identity) {
    need(std::equal(ACTIVATION_ACK_MAGIC.begin(),
                    ACTIVATION_ACK_MAGIC.end(), value.begin()) &&
         value[8] == 1 && value[9] == 2 && value[10] == 1 &&
         value[11] == round && get_u32(value, 12) == parent_pid &&
         get_u32(value, 16) == child_pid &&
         get_digest(value, 20) == activation_identity &&
         get_digest(value, ACTIVATION_ACK_IDENTITY_OFFSET) ==
             hash(std::span<const unsigned char>(
                 value.data(), ACTIVATION_ACK_IDENTITY_OFFSET)));
}

int open_pidfd(pid_t pid) {
#ifdef SYS_pidfd_open
    int result;
    do { result = static_cast<int>(::syscall(SYS_pidfd_open, pid, 0U)); }
    while (result < 0 && errno == EINTR);
    need(result >= 0);
    const int flags = ::fcntl(result, F_GETFD);
    need(flags >= 0 && ::fcntl(result, F_SETFD, flags | FD_CLOEXEC) == 0);
    return result;
#else
    (void)pid;
    refuse();
#endif
}

void wait_exact_child(pid_t child, int pidfd, int& status) {
    struct pollfd watched{pidfd, POLLIN, 0};
    int ready;
    do { ready = ::poll(&watched, 1, TERMINAL_TIMEOUT_MS); }
    while (ready < 0 && errno == EINTR);
    if (!(ready == 1 && (watched.revents & POLLIN) != 0 &&
          (watched.revents & (POLLERR | POLLNVAL)) == 0)) {
#ifdef SYS_pidfd_send_signal
        long signaled;
        do {
            signaled = ::syscall(
                SYS_pidfd_send_signal, pidfd, SIGKILL, nullptr, 0U);
        } while (signaled < 0 && errno == EINTR);
        need(signaled == 0 || errno == ESRCH);
        watched.revents = 0;
        do { ready = ::poll(&watched, 1, TERMINAL_TIMEOUT_MS); }
        while (ready < 0 && errno == EINTR);
#endif
    }
    need(ready == 1 && (watched.revents & POLLIN) != 0 &&
         (watched.revents & (POLLERR | POLLNVAL)) == 0);
    siginfo_t observed{};
    int waited_by_pidfd;
    do {
        waited_by_pidfd = ::waitid(
            P_PIDFD, static_cast<id_t>(pidfd), &observed,
            WEXITED | WNOWAIT);
    } while (waited_by_pidfd < 0 && errno == EINTR);
    need(waited_by_pidfd == 0 && observed.si_pid == child &&
         (observed.si_code == CLD_EXITED ||
          observed.si_code == CLD_KILLED ||
          observed.si_code == CLD_DUMPED));
    pid_t waited;
    do { waited = ::waitpid(child, &status, 0); }
    while (waited < 0 && errno == EINTR);
    need(waited == child &&
         ((observed.si_code == CLD_EXITED && WIFEXITED(status) &&
           WEXITSTATUS(status) == observed.si_status) ||
          ((observed.si_code == CLD_KILLED ||
            observed.si_code == CLD_DUMPED) &&
           WIFSIGNALED(status) &&
           WTERMSIG(status) == observed.si_status)));
}

} // namespace

bool RegisteredP1StateArchiveScmBridge::
test_only_round2_extraction_failure_retains_all(
        FreshTrialCaptureTopologyActivationTransfer& topology) {
    const auto parent_fds = topology.p1_state_parent_read_fds_;
    const auto writer_fds = topology.p1_state_child_writer_aliases_;
    const auto expected_inodes = topology.p1_state_inodes_;
    bool refused = false;
    topology.p1_state_inodes_[1] ^= 1U;
    try {
        (void)extract_state_channels(topology);
    } catch (...) {
        refused = true;
    }
    topology.p1_state_inodes_ = expected_inodes;
    if (!refused || topology.p1_state_parent_read_fds_ != parent_fds ||
        topology.p1_state_child_writer_aliases_ != writer_fds)
        return false;
    for (unsigned round = 0; round < 2; ++round) {
        const auto parent = regular_file(
            topology.p1_state_parent_read_fds_[round], O_RDONLY, true);
        const auto writer = regular_file(
            topology.p1_state_child_writer_aliases_[round], O_WRONLY, true);
        if (parent.device != writer.device ||
            parent.inode != writer.inode ||
            parent.inode != expected_inodes[round])
            return false;
    }
    return true;
}

RegisteredP1StateArchiveScmTestSummary
RegisteredP1StateArchiveScmBridge::test_only_run(
        FreshTrialCaptureTopologyActivationTransfer& topology,
        RegisteredP1StateArchiveScmTestFault fault,
        kpb::measurement::p1_state_capsule::
            P1CorruptStateCapsuleAuthority (*capsule_factory)(
                P1StateArchiveWriterAdoptionAuthority&&),
        bool (*wrong_round_probe)(
            P1StateArchiveWriterAdoptionAuthority&&),
        bool (*wrong_reservation_probe)(
            P1StateArchiveWriterAdoptionAuthority&&),
        kpb::measurement::p1_state_capsule::
            P1CorruptStateCapsulePlanAuthority (*plan_factory)(
                const P1StateArchiveWriterAdoptionAuthority&),
        void (*allocation_gate)(bool) noexcept,
        void (*runtime_failure_probe)(
            RegisteredRole1P1StateRecorderFacade&)) {
    need(capsule_factory != nullptr && wrong_round_probe != nullptr &&
         wrong_reservation_probe != nullptr && plan_factory != nullptr &&
         allocation_gate != nullptr && runtime_failure_probe != nullptr);
    auto bootstrap = seqpacket_pair();
    const auto parent_pid = static_cast<std::int64_t>(::getpid());
    const pid_t child = ::fork();
    need(child >= 0);
    if (child == 0) {
        int code = 91;
        try {
            const int inherited = bootstrap[1].release();
            close_fd(bootstrap[0].value);
            code = 100;
            install_control_child_allowlist(inherited);
            code = 101;
            int control_fd = 63;
            std::array<std::unique_ptr<
                RegisteredP1StateArchiveChildRoundAuthority::Storage>, 2>
                endpoints;
            for (unsigned round = 0; round < 2; ++round) {
                auto received = receive_activation(control_fd, parent_pid);
                code = 102 + static_cast<int>(round) * 4;
                const auto activation_identity = validate_activation(
                    received, round + 1, parent_pid,
                    static_cast<std::int64_t>(::getpid()));
                code = 103 + static_cast<int>(round) * 4;
                auto endpoint = std::make_unique<
                    RegisteredP1StateArchiveChildRoundAuthority::Storage>();
                endpoint->writer = received.descriptors[0].release();
                endpoint->channel = received.descriptors[1].release();
                endpoint->round = round + 1;
                endpoint->parent_pid = parent_pid;
                endpoint->child_pid = static_cast<std::int64_t>(::getpid());
                endpoint->archive = regular_file(
                    endpoint->writer, O_WRONLY, true);
                endpoint->reservation_identity = get_digest(
                    received.bytes, 64);
                endpoint->activation_identity = activation_identity;
                if (round == 0 &&
                    (fault == RegisteredP1StateArchiveScmTestFault::
                                  TerminalReplay ||
                     fault == RegisteredP1StateArchiveScmTestFault::
                                  TerminalTruncated))
                    endpoint->test_fault = fault;
                endpoints[round] = std::move(endpoint);
                code = 104 + static_cast<int>(round) * 4;
                const auto ack = activation_ack(
                    round + 1, parent_pid,
                    static_cast<std::int64_t>(::getpid()),
                    activation_identity);
                send_exact(control_fd, ack);
                code = 105 + static_cast<int>(round) * 4;
            }
            close_fd(control_fd);
            if (fault == RegisteredP1StateArchiveScmTestFault::ChildDeath)
                ::_exit(92);
            for (unsigned round = 0; round < 2; ++round) {
                if (round == 0 && fault ==
                        RegisteredP1StateArchiveScmTestFault::
                            AdoptionAppendMode) {
                    const int flags = ::fcntl(
                        endpoints[round]->writer, F_GETFL);
                    need(flags >= 0 && ::fcntl(
                        endpoints[round]->writer, F_SETFL,
                        flags | O_APPEND) == 0);
                }
                if (round == 0 && fault ==
                        RegisteredP1StateArchiveScmTestFault::
                            AdoptionNonzeroSize) {
                    constexpr unsigned char byte = 0xa5;
                    need(::write(endpoints[round]->writer, &byte, 1) == 1 &&
                         ::lseek(endpoints[round]->writer, 0, SEEK_SET) == 0);
                }
                auto selected = RegisteredP1StateArchiveChildRoundAuthority(
                    std::move(endpoints[round]));
                const bool expect_preclaim_refusal = round == 0 &&
                    (fault == RegisteredP1StateArchiveScmTestFault::
                                  AdoptionAppendMode ||
                     fault == RegisteredP1StateArchiveScmTestFault::
                                  AdoptionNonzeroSize ||
                     fault == RegisteredP1StateArchiveScmTestFault::
                                  PreAdoptionAllocationDenied);
                if (expect_preclaim_refusal) {
                    const bool deny_allocation = fault ==
                        RegisteredP1StateArchiveScmTestFault::
                            PreAdoptionAllocationDenied;
                    if (deny_allocation) allocation_gate(true);
                    bool refused = false;
                    try {
                        (void)RegisteredP1StateArchiveScmBridge::
                            prepare_writer_adoption(std::move(selected));
                    } catch (...) { refused = true; }
                    if (deny_allocation) allocation_gate(false);
                    need(refused && selected.storage_ != nullptr &&
                         selected.storage_->live &&
                         ::fcntl(selected.storage_->writer, F_GETFD) >= 0 &&
                         ::fcntl(selected.storage_->channel, F_GETFD) >= 0);
                    break;
                }
                auto bundle = RegisteredP1StateArchiveScmBridge::
                    prepare_writer_adoption(std::move(selected));
                auto split = std::move(bundle).split();
                need(split.has_value() &&
                     !std::move(bundle).split().has_value());
                if (round == 0 && fault ==
                        RegisteredP1StateArchiveScmTestFault::
                            WrongAdoptionRound) {
                    need(wrong_round_probe(std::move(split->first)));
                    break;
                }
                if (round == 0 && fault ==
                        RegisteredP1StateArchiveScmTestFault::
                            WrongAdoptionReservation) {
                    need(wrong_reservation_probe(std::move(split->first)));
                    break;
                }

                const bool exercise_runtime =
                    fault == RegisteredP1StateArchiveScmTestFault::None ||
                    fault == RegisteredP1StateArchiveScmTestFault::
                                 PostCapsuleAllocationDenied ||
                    fault == RegisteredP1StateArchiveScmTestFault::
                                 RuntimeBeginAllocationDenied ||
                    fault == RegisteredP1StateArchiveScmTestFault::
                                 RuntimeFailureProbeThrows ||
                    (round == 0 &&
                     (fault == RegisteredP1StateArchiveScmTestFault::
                                   StalePlanFreshChild ||
                      fault == RegisteredP1StateArchiveScmTestFault::
                                   StaleChildFreshPlan));
                if (exercise_runtime) {
                    auto plan = plan_factory(split->first);
                    const auto unavailable_trial_identity = plan.
                        unavailable_trial_identity_for_role1_prelaunch();
                    const auto unavailable_prelaunch_binding_identity =
                        plan.
                            unavailable_prelaunch_binding_identity_for_role1_prelaunch();
                    need(nonzero(unavailable_trial_identity) &&
                         nonzero(unavailable_prelaunch_binding_identity));

                    // Control-only exact inverse of the production split.
                    // It reuses the same authenticated channel and sole
                    // writer description; no descriptor is duplicated and
                    // no caller supplies identity metadata.
                    auto rejoined_storage = std::make_unique<
                        RegisteredP1StateArchiveChildRoundAuthority::
                            Storage>();
                    const auto* writer = split->first.storage_.get();
                    const auto* terminal = split->second.storage_.get();
                    need(writer != nullptr && writer->live &&
                         terminal != nullptr && terminal->live &&
                         writer->round == terminal->round &&
                         writer->parent_pid == terminal->parent_pid &&
                         writer->child_pid == terminal->child_pid &&
                         writer->device == terminal->archive.device &&
                         writer->inode == terminal->archive.inode &&
                         writer->mode == terminal->archive.mode &&
                         writer->nlink == terminal->archive.nlink &&
                         writer->size == terminal->archive.size &&
                         writer->reservation_identity ==
                             terminal->reservation_identity &&
                         writer->activation_identity ==
                             terminal->activation_identity);
                    auto writer_storage = std::move(split->first.storage_);
                    auto terminal_storage =
                        std::move(split->second.storage_);
                    writer_storage->live = false;
                    terminal_storage->live = false;
                    rejoined_storage->writer =
                        std::exchange(writer_storage->writer, -1);
                    rejoined_storage->channel =
                        std::exchange(terminal_storage->channel, -1);
                    rejoined_storage->round = writer_storage->round;
                    rejoined_storage->parent_pid =
                        writer_storage->parent_pid;
                    rejoined_storage->child_pid = writer_storage->child_pid;
                    rejoined_storage->archive = terminal_storage->archive;
                    rejoined_storage->reservation_identity =
                        writer_storage->reservation_identity;
                    rejoined_storage->activation_identity =
                        writer_storage->activation_identity;
                    auto rejoined =
                        RegisteredP1StateArchiveChildRoundAuthority(
                            std::move(rejoined_storage));

                    const auto capture_plan_identity = plan.
                        capture_plan_identity_for_role1_prelaunch(
                            round + 1);
                    need(nonzero(capture_plan_identity));
                    PublicParentAuthenticatedPartyDelivery delivery_value{};
                    delivery_value.role = 1;
                    delivery_value.round = round + 1;
                    delivery_value.parent_pid = writer_storage->parent_pid;
                    delivery_value.child_pid = writer_storage->child_pid;
                    delivery_value.capture_plan_identity =
                        capture_plan_identity;
                    auto delivery =
                        ParentAuthenticatedPartyDeliveryAuthority(
                            delivery_value,
                            writer_storage->activation_identity, nullptr);

                    if (fault == RegisteredP1StateArchiveScmTestFault::
                                     StalePlanFreshChild) {
                        auto consumed_plan = std::move(plan);
                        bool refused = false;
                        try {
                            attach_role1_prelaunch(
                                delivery, std::move(rejoined),
                                std::move(plan));
                        } catch (...) { refused = true; }
                        need(refused &&
                             !delivery.role1_p1_state_prelaunch_attached_ &&
                             delivery.role1_p1_state_prelaunch_ == nullptr);
                        (void)consumed_plan;
                        break;
                    }
                    if (fault == RegisteredP1StateArchiveScmTestFault::
                                     StaleChildFreshPlan) {
                        auto consumed_child = std::move(rejoined);
                        bool refused = false;
                        try {
                            attach_role1_prelaunch(
                                delivery, std::move(rejoined),
                                std::move(plan));
                        } catch (...) { refused = true; }
                        need(refused &&
                             !delivery.role1_p1_state_prelaunch_attached_ &&
                             delivery.role1_p1_state_prelaunch_ == nullptr);
                        (void)consumed_child;
                        break;
                    }

                    attach_role1_prelaunch(
                        delivery, std::move(rejoined), std::move(plan));
                    auto dispatched = std::move(delivery).dispatch_role();
                    need(dispatched.index() == 1);
                    auto role1 = std::get<ParentAuthenticatedRole1Delivery>(
                        std::move(dispatched));
                    bool early_delivery_refused = false;
                    try {
                        (void)std::move(role1).take_delivery();
                    } catch (...) { early_delivery_refused = true; }
                    need(early_delivery_refused);
                    auto prelaunch = role1.take_p1_state_prelaunch();
                    bool prelaunch_replay_refused = false;
                    try {
                        (void)role1.take_p1_state_prelaunch();
                    } catch (...) { prelaunch_replay_refused = true; }
                    need(prelaunch_replay_refused);
                    auto generic_delivery =
                        std::move(role1).take_delivery();
                    need(generic_delivery.public_receipt().role == 1 &&
                         generic_delivery.public_receipt().round ==
                             round + 1 &&
                         generic_delivery.public_receipt().
                             capture_plan_identity == capture_plan_identity);
                    if (fault == RegisteredP1StateArchiveScmTestFault::
                                     RuntimeBeginAllocationDenied) {
                        prelaunch.storage_->deny_recorder_begin_allocation =
                            true;
                        prelaunch.storage_->allocation_gate = allocation_gate;
                    }
                    std::optional<RegisteredRole1P1StateRuntimeAuthority>
                        runtime;
                    bool begin_refused = false;
                    try {
                        runtime.emplace(begin_role1_prelaunch(
                            std::move(prelaunch)));
                    } catch (...) { begin_refused = true; }
                    if (fault == RegisteredP1StateArchiveScmTestFault::
                                     RuntimeBeginAllocationDenied) {
                        need(begin_refused && !runtime.has_value());
                        continue;
                    }
                    need(!begin_refused && runtime.has_value());
                    if (fault == RegisteredP1StateArchiveScmTestFault::
                                     RuntimeFailureProbeThrows) {
                        runtime_failure_probe(runtime->recorder());
                        need(false);
                    }
                    bool replay_refused = false;
                    try {
                        (void)begin_role1_prelaunch(
                            std::move(prelaunch));
                    } catch (...) { replay_refused = true; }
                    need(replay_refused);
                    const bool deny_allocations =
                        fault == RegisteredP1StateArchiveScmTestFault::
                                     PostCapsuleAllocationDenied;
                    if (deny_allocations) allocation_gate(true);
                    std::move(*runtime).finish_unavailable_noexcept();
                    runtime.reset();
                    if (deny_allocations) allocation_gate(false);
                    continue;
                }
                auto terminal = std::move(split->second);
                auto capsule = capsule_factory(std::move(split->first));
                const bool deny_allocations =
                    fault == RegisteredP1StateArchiveScmTestFault::
                                 PostCapsuleAllocationDenied;
                if (deny_allocations) allocation_gate(true);
                RegisteredP1StateCapsuleChildDispositionBridge::
                    send_terminal_noexcept(
                        std::move(terminal), std::move(capsule));
                if (deny_allocations) allocation_gate(false);
                if (fault == RegisteredP1StateArchiveScmTestFault::
                                 TerminalReplay ||
                    fault == RegisteredP1StateArchiveScmTestFault::
                                 TerminalTruncated)
                    break;
            }
            code = 0;
        } catch (...) {}
        ::_exit(code);
    }

    close_fd(bootstrap[1].value);
    const ScopedFd pidfd(open_pidfd(child));
    auto resources = extract_state_channels(topology);
    Digest expected_trial_identity{};
    Digest expected_prelaunch_binding_identity{};
    {
        // The parent fixture independently derives its expectation from the
        // source-owned plan factory before any child terminal packet exists.
        // Exact writer ownership moves into and back out of the temporary;
        // no alias or raw identity getter is introduced.
        auto expected_writer = std::make_unique<
            P1StateArchiveWriterAdoptionAuthority::Storage>();
        expected_writer->writer =
            std::exchange(resources.storage_->child_writers[0], -1);
        expected_writer->round = 1;
        expected_writer->parent_pid = parent_pid;
        expected_writer->child_pid = child;
        expected_writer->device = resources.storage_->devices[0];
        expected_writer->inode = resources.storage_->inodes[0];
        expected_writer->mode = resources.storage_->modes[0];
        expected_writer->nlink = resources.storage_->nlinks[0];
        expected_writer->size = resources.storage_->sizes[0];
        expected_writer->reservation_identity =
            resources.storage_->reservation_identity;
        expected_writer->activation_identity =
            resources.storage_->reservation_identity;
        auto expected_authority = P1StateArchiveWriterAdoptionAuthority(
            std::move(expected_writer));
        auto expected_plan = plan_factory(expected_authority);
        expected_trial_identity = expected_plan.
            unavailable_trial_identity_for_role1_prelaunch();
        expected_prelaunch_binding_identity = expected_plan.
            unavailable_prelaunch_binding_identity_for_role1_prelaunch();
        resources.storage_->child_writers[0] = std::exchange(
            expected_authority.storage_->writer, -1);
        need(nonzero(expected_trial_identity) &&
             nonzero(expected_prelaunch_binding_identity) &&
             resources.storage_->child_writers[0] >= 0);
    }
    RegisteredP1StateArchiveScmTestSummary summary{};
    const bool expect_success =
        fault == RegisteredP1StateArchiveScmTestFault::None ||
        fault == RegisteredP1StateArchiveScmTestFault::
                     PostCapsuleAllocationDenied;
    const bool expect_pre_recorder_unavailable =
        fault == RegisteredP1StateArchiveScmTestFault::
                     RuntimeBeginAllocationDenied;
    try {
        std::array<std::unique_ptr<
            RegisteredP1StateArchiveParentRoundAuthority::Storage>, 2>
            endpoints;
        for (unsigned round = 0; round < 2; ++round) {
            auto state_channel = seqpacket_pair();
            const FileFingerprint archive{
                resources.storage_->devices[round],
                resources.storage_->inodes[round],
                resources.storage_->modes[round],
                resources.storage_->nlinks[round],
                resources.storage_->sizes[round],
            };
            unsigned role = 1;
            int writer = resources.storage_->child_writers[round];
            if (round == 0 &&
                fault == RegisteredP1StateArchiveScmTestFault::WrongRole)
                role = 0;
            if (round == 0 && fault ==
                    RegisteredP1StateArchiveScmTestFault::SubstitutedWriter)
                writer = resources.storage_->parent_reads[round];
            const auto activation = activation_packet(
                round + 1, role, parent_pid, child, archive,
                resources.storage_->reservation_identity);
            const std::array<int, 2> descriptors{
                writer, state_channel[1].value};
            send_activation_with_fds(
                bootstrap[0].value, activation, descriptors);
            close_fd(resources.storage_->child_writers[round]);
            // SCM_RIGHTS created the child's independent description.  The
            // parent must close its source alias immediately or peer EOF can
            // never prove one-shot terminal closure.
            close_fd(state_channel[1].value);
            auto endpoint = std::make_unique<
                RegisteredP1StateArchiveParentRoundAuthority::Storage>();
            endpoint->channel = state_channel[0].release();
            endpoint->round = round + 1;
            endpoint->parent_pid = parent_pid;
            endpoint->child_pid = child;
            endpoint->archive = archive;
            endpoint->reservation_identity =
                resources.storage_->reservation_identity;
            endpoint->activation_identity = get_digest(
                activation, ACTIVATION_IDENTITY_OFFSET);
            endpoint->expected_trial_identity = expected_trial_identity;
            endpoint->expected_prelaunch_binding_identity =
                expected_prelaunch_binding_identity;
            if (round == 0 &&
                fault == RegisteredP1StateArchiveScmTestFault::
                             SubstitutedParentTrialExpectation) {
                endpoint->expected_trial_identity[0] ^= 0x5aU;
                need(nonzero(endpoint->expected_trial_identity) &&
                     endpoint->expected_trial_identity !=
                         expected_trial_identity);
            }
            if (round == 0 &&
                fault == RegisteredP1StateArchiveScmTestFault::
                             SubstitutedParentPrelaunchExpectation) {
                endpoint->expected_prelaunch_binding_identity[0] ^= 0xa5U;
                need(nonzero(
                         endpoint->expected_prelaunch_binding_identity) &&
                     endpoint->expected_prelaunch_binding_identity !=
                         expected_prelaunch_binding_identity);
            }
            endpoint->test_same_inode_count =
                &summary.typed_same_inode_dispositions;
            endpoints[round] = std::move(endpoint);
            const auto ack = receive_authenticated<ACTIVATION_ACK_BYTES>(
                bootstrap[0].value, child);
            validate_activation_ack(
                ack.bytes, round + 1, parent_pid, child,
                get_digest(activation, ACTIVATION_IDENTITY_OFFSET));
            ++summary.authenticated_activation_acks;
        }
        need(resources.storage_->child_writers[0] < 0 &&
             resources.storage_->child_writers[1] < 0);
        auto parent_reads = resources.storage_->parent_reads;
        summary.exact_two_parent_reads_empty = true;
        for (unsigned round = 0; round < 2; ++round) {
            struct stat observed{};
            summary.exact_two_parent_reads_empty =
                summary.exact_two_parent_reads_empty &&
                ::fstat(parent_reads[round], &observed) == 0 &&
                observed.st_size == 0;
        }
        resources.storage_->parent_reads.fill(-1);
        FreshTrialP1StateArchiveResidual selected_parent_residual(
            parent_reads, resources.storage_->devices,
            resources.storage_->inodes, resources.storage_->modes,
            resources.storage_->nlinks, resources.storage_->sizes,
            resources.storage_->reservation_identity);
        std::optional<FreshTrialP1StateArchiveResidual> parent_residual;
        parent_residual.emplace(std::move(selected_parent_residual));
        const auto parent_summary = parent_residual->test_only_summary();
        summary.exact_two_parent_reads_retained =
            parent_summary.parent_reads_retained[0] &&
            parent_summary.parent_reads_retained[1] &&
            parent_summary.devices == resources.storage_->devices &&
            parent_summary.inodes == resources.storage_->inodes &&
            parent_summary.reservation_identity ==
                resources.storage_->reservation_identity;
        close_fd(bootstrap[0].value);
        if (fault != RegisteredP1StateArchiveScmTestFault::ChildDeath) {
            for (unsigned round = 0; round < 2; ++round) {
                auto disposition =
                    RegisteredP1StateCapsuleChildDispositionBridge::
                        receive_terminal(
                            RegisteredP1StateArchiveParentRoundAuthority(
                                std::move(endpoints[round])));
                (void)disposition;
                ++summary.typed_authenticated_dispositions;
                if (fault == RegisteredP1StateArchiveScmTestFault::
                                 TerminalReplay ||
                    fault == RegisteredP1StateArchiveScmTestFault::
                                 TerminalTruncated)
                    break;
            }
        }
        summary.expected_result = expect_success ||
            expect_pre_recorder_unavailable ||
            fault == RegisteredP1StateArchiveScmTestFault::ChildDeath;
        summary.post_capsule_allocation_denial_control =
            fault != RegisteredP1StateArchiveScmTestFault::
                         PostCapsuleAllocationDenied ||
            (summary.typed_authenticated_dispositions == 2 &&
             summary.typed_same_inode_dispositions == 2);
    } catch (...) {
        close_fd(bootstrap[0].value);
        summary.expected_result = !expect_success;
    }
    if (!summary.exact_two_parent_reads_retained &&
        resources.storage_ != nullptr)
        summary.exact_two_parent_reads_retained =
            resources.storage_->parent_reads[0] >= 0 &&
            resources.storage_->parent_reads[1] >= 0 &&
            ::fcntl(resources.storage_->parent_reads[0], F_GETFD) >= 0 &&
            ::fcntl(resources.storage_->parent_reads[1], F_GETFD) >= 0;
    if (!summary.exact_two_parent_reads_empty &&
        resources.storage_ != nullptr &&
        resources.storage_->parent_reads[0] >= 0 &&
        resources.storage_->parent_reads[1] >= 0) {
        struct stat first{};
        struct stat second{};
        summary.exact_two_parent_reads_empty =
            ::fstat(resources.storage_->parent_reads[0], &first) == 0 &&
            ::fstat(resources.storage_->parent_reads[1], &second) == 0 &&
            first.st_size == 0 && second.st_size == 0;
    }
    int status = 0;
    // receive_terminal returns only after its authenticated ACK is sent and
    // peer EOF proves the child consumed the one-shot terminal channel.
    summary.terminal_ack_before_pidfd_wait =
        summary.typed_authenticated_dispositions != 0;
    wait_exact_child(child, pidfd.value, status);
    summary.child_exited = WIFEXITED(status);
    summary.child_exit_code = summary.child_exited
        ? WEXITSTATUS(status) : -1;
    const bool expected_child_status = expect_success
        ? summary.child_exit_code == 0
        : fault == RegisteredP1StateArchiveScmTestFault::ChildDeath
            ? summary.child_exit_code == 92
            : fault == RegisteredP1StateArchiveScmTestFault::
                           RuntimeFailureProbeThrows
                ? summary.child_exit_code != 0
            : (fault == RegisteredP1StateArchiveScmTestFault::WrongRole ||
               fault == RegisteredP1StateArchiveScmTestFault::
                            SubstitutedWriter)
                ? summary.child_exit_code != 0
                : summary.child_exit_code == 0;
    need(summary.expected_result && summary.exact_two_parent_reads_retained &&
         summary.child_exited &&
         expected_child_status &&
         (fault != RegisteredP1StateArchiveScmTestFault::
                       PostCapsuleAllocationDenied ||
          summary.post_capsule_allocation_denial_control) &&
         (expect_success
              ? summary.authenticated_activation_acks == 2 &&
                    summary.typed_authenticated_dispositions == 2 &&
                    summary.typed_same_inode_dispositions == 2 &&
                    summary.child_exit_code == 0
              : expect_pre_recorder_unavailable
                  ? summary.authenticated_activation_acks == 2 &&
                        summary.typed_authenticated_dispositions == 2 &&
                        summary.typed_same_inode_dispositions == 0 &&
                        summary.child_exit_code == 0
                  : true));
    return summary;
}

} // namespace kpi::mpc::financial::registered_driver
#endif
