#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "privacy_registered_fresh_trial_capture_topology_reservation.hpp"

#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <linux/magic.h>
#include <openssl/sha.h>
#include <set>
#include <span>
#include <stdexcept>
#include <string_view>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::registered_driver {
namespace {

[[noreturn]] void refuse() {
    throw std::runtime_error("fresh trial capture topology refused");
}
void need(bool value) { if (!value) refuse(); }

void close_fd(int& fd) noexcept {
    if (fd < 0) return;
    while (::close(fd) != 0 && errno == EINTR) {}
    fd = -1;
}

struct Fingerprint {
    std::uint64_t device{};
    std::uint64_t inode{};
    std::uint32_t type{};
    bool operator==(const Fingerprint&) const = default;
};

Fingerprint fingerprint(int fd, int expected_access, std::uint32_t type) {
    struct stat value{};
    const int flags = fd >= 0 ? ::fcntl(fd, F_GETFL) : -1;
    const int descriptor_flags = fd >= 0 ? ::fcntl(fd, F_GETFD) : -1;
    need(fd >= 0 && flags >= 0 && descriptor_flags >= 0 &&
         (flags & O_ACCMODE) == expected_access &&
         (descriptor_flags & FD_CLOEXEC) != 0 &&
         ::fstat(fd, &value) == 0 &&
         static_cast<std::uint32_t>(value.st_mode & S_IFMT) == type);
    return {
        static_cast<std::uint64_t>(value.st_dev),
        static_cast<std::uint64_t>(value.st_ino), type};
}

int reopen_description(int fd, int access) {
    need(fd >= 0 && (access == O_RDONLY || access == O_WRONLY));
    char path[64]{};
    const int written = std::snprintf(
        path, sizeof(path), "/proc/self/fd/%d", fd);
    need(written > 0 && static_cast<std::size_t>(written) < sizeof(path));
    const int result = ::open(path, access | O_CLOEXEC);
    need(result >= 0);
    return result;
}

void need_anonymous_disk_file(const struct stat& value) {
    need(S_ISREG(value.st_mode) && value.st_nlink == 0 &&
         value.st_size == 0 && (value.st_mode & 0777U) == 0600U);
}

using Bytes = std::vector<unsigned char>;
void add(Bytes& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add_u64(Bytes& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}
kpb::measurement::Digest resource_identity(
        const std::array<std::uint64_t, 10>& endpoint_devices,
        const std::array<std::uint64_t, 10>& endpoint_inodes,
        const std::array<std::uint32_t, 10>& endpoint_types,
        const std::array<std::uint64_t, 10>& archive_devices,
        const std::array<std::uint64_t, 10>& archive_inodes,
        const std::array<std::uint32_t, 10>& archive_modes,
        const std::array<std::uint64_t, 10>& archive_nlinks,
        const std::array<std::uint64_t, 10>& archive_sizes,
        const std::array<std::uint64_t, 2>& p1_state_devices,
        const std::array<std::uint64_t, 2>& p1_state_inodes,
        const std::array<std::uint32_t, 2>& p1_state_modes,
        const std::array<std::uint64_t, 2>& p1_state_nlinks,
        const std::array<std::uint64_t, 2>& p1_state_sizes) {
    Bytes bytes;
    add(bytes, "KPB_FRESH_TRIAL_CAPTURE_TOPOLOGY_RESERVATION_V2\n");
    for (unsigned slot = 0; slot < 10; ++slot) {
        const auto& contract = kFreshTrialCaptureWriterContracts[slot];
        add_u64(bytes, contract.source_slot);
        add_u64(bytes, contract.round);
        add_u64(bytes, static_cast<unsigned>(contract.kind));
        add_u64(bytes, contract.fixed_fd);
        add_u64(bytes, endpoint_devices[slot]);
        add_u64(bytes, endpoint_inodes[slot]);
        add_u64(bytes, endpoint_types[slot]);
        add_u64(bytes, archive_devices[slot]);
        add_u64(bytes, archive_inodes[slot]);
        add_u64(bytes, archive_modes[slot]);
        add_u64(bytes, archive_nlinks[slot]);
        add_u64(bytes, archive_sizes[slot]);
    }
    for (unsigned slot = 0; slot < p1_state_devices.size(); ++slot) {
        const auto& contract = kFreshTrialP1StateArchiveContracts[slot];
        add_u64(bytes, contract.state_slot);
        add_u64(bytes, contract.round);
        add_u64(bytes, contract.manifest_semantic);
        add_u64(bytes, contract.fixed_child_fd_required ? 1U : 0U);
        add_u64(bytes, p1_state_devices[slot]);
        add_u64(bytes, p1_state_inodes[slot]);
        add_u64(bytes, p1_state_modes[slot]);
        add_u64(bytes, p1_state_nlinks[slot]);
        add_u64(bytes, p1_state_sizes[slot]);
    }
    kpb::measurement::Digest result{};
    need(SHA256(bytes.data(), bytes.size(), result.data()) != nullptr &&
         result != kpb::measurement::Digest{});
    return result;
}

} // namespace

struct FreshTrialCaptureTopologyReservation::Storage {
    std::shared_ptr<const detail::PersistentProcessReservationEpoch>
        process_epoch;
    bool diagnostic_unbound{};
    std::array<int, 10> read_ends{};
    std::array<int, 10> writer_aliases{};
    std::array<std::uint64_t, 10> endpoint_devices{};
    std::array<std::uint64_t, 10> endpoint_inodes{};
    std::array<std::uint32_t, 10> endpoint_types{};
    std::array<int, 10> archive_fds{};
    std::array<std::uint64_t, 10> archive_devices{};
    std::array<std::uint64_t, 10> archive_inodes{};
    std::array<std::uint32_t, 10> archive_modes{};
    std::array<std::uint64_t, 10> archive_nlinks{};
    std::array<std::uint64_t, 10> archive_sizes{};
    std::array<int, 2> p1_state_parent_read_fds{};
    std::array<int, 2> p1_state_child_writer_aliases{};
    std::array<std::uint64_t, 2> p1_state_devices{};
    std::array<std::uint64_t, 2> p1_state_inodes{};
    std::array<std::uint32_t, 2> p1_state_modes{};
    std::array<std::uint64_t, 2> p1_state_nlinks{};
    std::array<std::uint64_t, 2> p1_state_sizes{};
    kpb::measurement::Digest reservation_identity{};
    std::atomic_bool live{true};

    Storage() {
        read_ends.fill(-1);
        writer_aliases.fill(-1);
        archive_fds.fill(-1);
        p1_state_parent_read_fds.fill(-1);
        p1_state_child_writer_aliases.fill(-1);
    }
    ~Storage() {
        for (auto& fd : read_ends) close_fd(fd);
        for (auto& fd : writer_aliases) close_fd(fd);
        for (auto& fd : archive_fds) close_fd(fd);
        for (auto& fd : p1_state_parent_read_fds) close_fd(fd);
        for (auto& fd : p1_state_child_writer_aliases) close_fd(fd);
    }

    void require_resources_valid() const {
        std::set<std::pair<std::uint64_t, std::uint64_t>> endpoints;
        std::set<std::pair<std::uint64_t, std::uint64_t>> archives;
        std::uint64_t selected_archive_device = 0;
        long selected_filesystem = 0;
        for (unsigned slot = 0; slot < read_ends.size(); ++slot) {
            const auto reader = fingerprint(
                read_ends[slot], O_RDONLY, S_IFIFO);
            const auto writer = fingerprint(
                writer_aliases[slot], O_WRONLY, S_IFIFO);
            need(reader == writer &&
                 reader.device == endpoint_devices[slot] &&
                 reader.inode == endpoint_inodes[slot] &&
                 reader.type == endpoint_types[slot] &&
                 endpoints.emplace(reader.device, reader.inode).second);

            struct stat value{};
            const auto archive = fingerprint(
                archive_fds[slot], O_RDWR, S_IFREG);
            struct statfs filesystem{};
            need(::fstat(archive_fds[slot], &value) == 0 &&
                 ::fstatfs(archive_fds[slot], &filesystem) == 0);
            need_anonymous_disk_file(value);
            need(filesystem.f_type != TMPFS_MAGIC &&
                 filesystem.f_type != RAMFS_MAGIC &&
                 archive.device == archive_devices[slot] &&
                 archive.inode == archive_inodes[slot] &&
                 static_cast<std::uint32_t>(value.st_mode) ==
                     archive_modes[slot] &&
                 static_cast<std::uint64_t>(value.st_nlink) ==
                     archive_nlinks[slot] &&
                 static_cast<std::uint64_t>(value.st_size) ==
                     archive_sizes[slot] &&
                 archives.emplace(archive.device, archive.inode).second);
            if (slot == 0) {
                selected_archive_device = archive.device;
                selected_filesystem = filesystem.f_type;
            } else {
                need(archive.device == selected_archive_device &&
                     filesystem.f_type == selected_filesystem);
            }

            const auto& contract = kFreshTrialCaptureWriterContracts[slot];
            need(contract.source_slot == slot &&
                 contract.round == slot / 5 + 1 &&
                 contract.kind == static_cast<
                     kpb::measurement::CaptureKind>(slot % 5 + 1) &&
                 contract.fixed_fd == 20 + slot);
        }
        for (unsigned slot = 0;
             slot < p1_state_parent_read_fds.size(); ++slot) {
            const auto parent = fingerprint(
                p1_state_parent_read_fds[slot], O_RDONLY, S_IFREG);
            const auto child = fingerprint(
                p1_state_child_writer_aliases[slot], O_WRONLY, S_IFREG);
            struct stat parent_value{};
            struct stat child_value{};
            struct statfs filesystem{};
            need(parent == child &&
                 ::fstat(p1_state_parent_read_fds[slot],
                         &parent_value) == 0 &&
                 ::fstat(p1_state_child_writer_aliases[slot],
                         &child_value) == 0 &&
                 ::fstatfs(p1_state_parent_read_fds[slot],
                           &filesystem) == 0);
            need_anonymous_disk_file(parent_value);
            need_anonymous_disk_file(child_value);
            need(parent.device == selected_archive_device &&
                 filesystem.f_type == selected_filesystem &&
                 parent.device == p1_state_devices[slot] &&
                 parent.inode == p1_state_inodes[slot] &&
                 static_cast<std::uint32_t>(parent_value.st_mode) ==
                     p1_state_modes[slot] &&
                 static_cast<std::uint64_t>(parent_value.st_nlink) ==
                     p1_state_nlinks[slot] &&
                 static_cast<std::uint64_t>(parent_value.st_size) ==
                     p1_state_sizes[slot] &&
                 parent_value.st_mode == child_value.st_mode &&
                 parent_value.st_nlink == child_value.st_nlink &&
                 parent_value.st_size == child_value.st_size &&
                 archives.emplace(parent.device, parent.inode).second);
            const auto& contract = kFreshTrialP1StateArchiveContracts[slot];
            need(contract.state_slot == slot &&
                 contract.round == slot + 1 &&
                 contract.manifest_semantic == 1 &&
                 !contract.fixed_child_fd_required);
        }
        need(kFreshTrialCaptureWriterContracts[3].kind ==
                 kpb::measurement::CaptureKind::CorruptServer &&
             kFreshTrialCaptureWriterContracts[3].fixed_fd == 23 &&
             kFreshTrialCaptureWriterContracts[8].kind ==
                 kpb::measurement::CaptureKind::CorruptServer &&
             kFreshTrialCaptureWriterContracts[8].fixed_fd == 28 &&
             reservation_identity == resource_identity(
                 endpoint_devices, endpoint_inodes, endpoint_types,
                 archive_devices, archive_inodes, archive_modes,
                 archive_nlinks, archive_sizes, p1_state_devices,
                 p1_state_inodes, p1_state_modes, p1_state_nlinks,
                 p1_state_sizes));
    }

    void require_valid() const {
        need(live.load() &&
             (process_epoch != nullptr || diagnostic_unbound));
        require_resources_valid();
    }
};

FreshTrialCaptureTopologyActivationTransfer::
FreshTrialCaptureTopologyActivationTransfer(
        std::array<int, 10> read_ends,
        std::array<int, 10> writer_aliases,
        std::array<std::uint64_t, 10> endpoint_devices,
        std::array<std::uint64_t, 10> endpoint_inodes,
        std::array<std::uint32_t, 10> endpoint_types,
        std::array<int, 10> archive_fds,
        std::array<std::uint64_t, 10> archive_devices,
        std::array<std::uint64_t, 10> archive_inodes,
        std::array<std::uint32_t, 10> archive_modes,
        std::array<std::uint64_t, 10> archive_nlinks,
        std::array<std::uint64_t, 10> archive_sizes,
        std::array<int, 2> p1_state_parent_read_fds,
        std::array<int, 2> p1_state_child_writer_aliases,
        std::array<std::uint64_t, 2> p1_state_devices,
        std::array<std::uint64_t, 2> p1_state_inodes,
        std::array<std::uint32_t, 2> p1_state_modes,
        std::array<std::uint64_t, 2> p1_state_nlinks,
        std::array<std::uint64_t, 2> p1_state_sizes,
        kpb::measurement::Digest reservation_identity)
    : read_ends_(read_ends), writer_aliases_(writer_aliases),
      endpoint_devices_(endpoint_devices),
      endpoint_inodes_(endpoint_inodes), endpoint_types_(endpoint_types),
      archive_fds_(archive_fds), archive_devices_(archive_devices),
      archive_inodes_(archive_inodes), archive_modes_(archive_modes),
      archive_nlinks_(archive_nlinks), archive_sizes_(archive_sizes),
      p1_state_parent_read_fds_(p1_state_parent_read_fds),
      p1_state_child_writer_aliases_(p1_state_child_writer_aliases),
      p1_state_devices_(p1_state_devices),
      p1_state_inodes_(p1_state_inodes),
      p1_state_modes_(p1_state_modes),
      p1_state_nlinks_(p1_state_nlinks),
      p1_state_sizes_(p1_state_sizes),
      reservation_identity_(reservation_identity) {}

FreshTrialCaptureTopologyActivationTransfer::
FreshTrialCaptureTopologyActivationTransfer(
        FreshTrialCaptureTopologyActivationTransfer&& other) noexcept
    : read_ends_(other.read_ends_),
      writer_aliases_(other.writer_aliases_),
      endpoint_devices_(other.endpoint_devices_),
      endpoint_inodes_(other.endpoint_inodes_),
      endpoint_types_(other.endpoint_types_),
      archive_fds_(other.archive_fds_),
      archive_devices_(other.archive_devices_),
      archive_inodes_(other.archive_inodes_),
      archive_modes_(other.archive_modes_),
      archive_nlinks_(other.archive_nlinks_),
      archive_sizes_(other.archive_sizes_),
      p1_state_parent_read_fds_(other.p1_state_parent_read_fds_),
      p1_state_child_writer_aliases_(
          other.p1_state_child_writer_aliases_),
      p1_state_devices_(other.p1_state_devices_),
      p1_state_inodes_(other.p1_state_inodes_),
      p1_state_modes_(other.p1_state_modes_),
      p1_state_nlinks_(other.p1_state_nlinks_),
      p1_state_sizes_(other.p1_state_sizes_),
      reservation_identity_(other.reservation_identity_),
      live_(other.live_.exchange(false)) {
    other.read_ends_.fill(-1);
    other.writer_aliases_.fill(-1);
    other.archive_fds_.fill(-1);
    other.p1_state_parent_read_fds_.fill(-1);
    other.p1_state_child_writer_aliases_.fill(-1);
}

FreshTrialCaptureTopologyActivationTransfer::
~FreshTrialCaptureTopologyActivationTransfer() {
    for (auto& fd : read_ends_) close_fd(fd);
    for (auto& fd : writer_aliases_) close_fd(fd);
    for (auto& fd : archive_fds_) close_fd(fd);
    for (auto& fd : p1_state_parent_read_fds_) close_fd(fd);
    for (auto& fd : p1_state_child_writer_aliases_) close_fd(fd);
}

FreshTrialCaptureTopologyQuarantineResidual
FreshTrialCaptureTopologyActivationTransfer::
quarantine_after_activation_failure() && {
    need(live_.exchange(false));
    auto read_ends = read_ends_;
    auto writer_aliases = writer_aliases_;
    auto archive_fds = archive_fds_;
    auto p1_state_parent_read_fds = p1_state_parent_read_fds_;
    auto p1_state_child_writer_aliases =
        p1_state_child_writer_aliases_;
    read_ends_.fill(-1);
    writer_aliases_.fill(-1);
    archive_fds_.fill(-1);
    p1_state_parent_read_fds_.fill(-1);
    p1_state_child_writer_aliases_.fill(-1);
    return FreshTrialCaptureTopologyQuarantineResidual(
        read_ends, writer_aliases, endpoint_devices_, endpoint_inodes_,
        endpoint_types_, archive_fds, archive_devices_, archive_inodes_,
        archive_modes_, archive_nlinks_, archive_sizes_,
        p1_state_parent_read_fds, p1_state_child_writer_aliases,
        p1_state_devices_, p1_state_inodes_, p1_state_modes_,
        p1_state_nlinks_, p1_state_sizes_,
        reservation_identity_);
}

FreshTrialCaptureTopologyQuarantineResidual::
FreshTrialCaptureTopologyQuarantineResidual(
        std::array<int, 10> read_ends,
        std::array<int, 10> writer_aliases,
        std::array<std::uint64_t, 10> endpoint_devices,
        std::array<std::uint64_t, 10> endpoint_inodes,
        std::array<std::uint32_t, 10> endpoint_types,
        std::array<int, 10> archive_fds,
        std::array<std::uint64_t, 10> archive_devices,
        std::array<std::uint64_t, 10> archive_inodes,
        std::array<std::uint32_t, 10> archive_modes,
        std::array<std::uint64_t, 10> archive_nlinks,
        std::array<std::uint64_t, 10> archive_sizes,
        std::array<int, 2> p1_state_parent_read_fds,
        std::array<int, 2> p1_state_child_writer_aliases,
        std::array<std::uint64_t, 2> p1_state_devices,
        std::array<std::uint64_t, 2> p1_state_inodes,
        std::array<std::uint32_t, 2> p1_state_modes,
        std::array<std::uint64_t, 2> p1_state_nlinks,
        std::array<std::uint64_t, 2> p1_state_sizes,
        kpb::measurement::Digest reservation_identity)
    : read_ends_(read_ends), writer_aliases_(writer_aliases),
      endpoint_devices_(endpoint_devices),
      endpoint_inodes_(endpoint_inodes), endpoint_types_(endpoint_types),
      archive_fds_(archive_fds), archive_devices_(archive_devices),
      archive_inodes_(archive_inodes), archive_modes_(archive_modes),
      archive_nlinks_(archive_nlinks), archive_sizes_(archive_sizes),
      p1_state_parent_read_fds_(p1_state_parent_read_fds),
      p1_state_child_writer_aliases_(p1_state_child_writer_aliases),
      p1_state_devices_(p1_state_devices),
      p1_state_inodes_(p1_state_inodes),
      p1_state_modes_(p1_state_modes),
      p1_state_nlinks_(p1_state_nlinks),
      p1_state_sizes_(p1_state_sizes),
      reservation_identity_(reservation_identity) {}

FreshTrialCaptureTopologyQuarantineResidual::
FreshTrialCaptureTopologyQuarantineResidual(
        FreshTrialCaptureTopologyQuarantineResidual&& other) noexcept
    : read_ends_(other.read_ends_),
      writer_aliases_(other.writer_aliases_),
      endpoint_devices_(other.endpoint_devices_),
      endpoint_inodes_(other.endpoint_inodes_),
      endpoint_types_(other.endpoint_types_),
      archive_fds_(other.archive_fds_),
      archive_devices_(other.archive_devices_),
      archive_inodes_(other.archive_inodes_),
      archive_modes_(other.archive_modes_),
      archive_nlinks_(other.archive_nlinks_),
      archive_sizes_(other.archive_sizes_),
      p1_state_parent_read_fds_(other.p1_state_parent_read_fds_),
      p1_state_child_writer_aliases_(
          other.p1_state_child_writer_aliases_),
      p1_state_devices_(other.p1_state_devices_),
      p1_state_inodes_(other.p1_state_inodes_),
      p1_state_modes_(other.p1_state_modes_),
      p1_state_nlinks_(other.p1_state_nlinks_),
      p1_state_sizes_(other.p1_state_sizes_),
      reservation_identity_(other.reservation_identity_),
      live_(other.live_.exchange(false)) {
    other.read_ends_.fill(-1);
    other.writer_aliases_.fill(-1);
    other.archive_fds_.fill(-1);
    other.p1_state_parent_read_fds_.fill(-1);
    other.p1_state_child_writer_aliases_.fill(-1);
}

FreshTrialCaptureTopologyQuarantineResidual::
~FreshTrialCaptureTopologyQuarantineResidual() {
    for (auto& fd : read_ends_) close_fd(fd);
    for (auto& fd : writer_aliases_) close_fd(fd);
    for (auto& fd : archive_fds_) close_fd(fd);
    for (auto& fd : p1_state_parent_read_fds_) close_fd(fd);
    for (auto& fd : p1_state_child_writer_aliases_) close_fd(fd);
}

#ifdef KPI_FRESH_TRIAL_CAPTURE_TOPOLOGY_RESERVATION_TEST_SETUP
FreshTrialCaptureTopologyQuarantineResidual::TestSummary
FreshTrialCaptureTopologyQuarantineResidual::test_only_summary() const {
    need(live_.load() && reservation_identity_ != kpb::measurement::Digest{});
    TestSummary result{
        .archive_devices = archive_devices_,
        .archive_inodes = archive_inodes_,
        .p1_state_devices = p1_state_devices_,
        .p1_state_inodes = p1_state_inodes_,
        .reservation_identity = reservation_identity_,
    };
    for (unsigned slot = 0; slot < read_ends_.size(); ++slot) {
        result.read_ends_retained[slot] =
            read_ends_[slot] >= 0 && ::fcntl(read_ends_[slot], F_GETFD) >= 0;
        result.writer_aliases_retained[slot] =
            writer_aliases_[slot] >= 0 &&
            ::fcntl(writer_aliases_[slot], F_GETFD) >= 0;
        result.archives_retained[slot] =
            archive_fds_[slot] >= 0 &&
            ::fcntl(archive_fds_[slot], F_GETFD) >= 0;
    }
    for (unsigned slot = 0;
         slot < p1_state_parent_read_fds_.size(); ++slot) {
        result.p1_state_parent_reads_retained[slot] =
            p1_state_parent_read_fds_[slot] >= 0 &&
            ::fcntl(p1_state_parent_read_fds_[slot], F_GETFD) >= 0;
        result.p1_state_writers_retained[slot] =
            p1_state_child_writer_aliases_[slot] >= 0 &&
            ::fcntl(p1_state_child_writer_aliases_[slot], F_GETFD) >= 0;
    }
    return result;
}
#endif

FreshTrialP1StateArchiveResidual::FreshTrialP1StateArchiveResidual(
        std::array<int, 2> parent_read_fds,
        std::array<std::uint64_t, 2> devices,
        std::array<std::uint64_t, 2> inodes,
        std::array<std::uint32_t, 2> modes,
        std::array<std::uint64_t, 2> nlinks,
        std::array<std::uint64_t, 2> sizes,
        kpb::measurement::Digest reservation_identity)
    : parent_read_fds_(parent_read_fds), devices_(devices),
      inodes_(inodes), modes_(modes), nlinks_(nlinks), sizes_(sizes),
      reservation_identity_(reservation_identity) {}

FreshTrialP1StateArchiveResidual::FreshTrialP1StateArchiveResidual(
        FreshTrialP1StateArchiveResidual&& other) noexcept
    : parent_read_fds_(other.parent_read_fds_), devices_(other.devices_),
      inodes_(other.inodes_), modes_(other.modes_),
      nlinks_(other.nlinks_), sizes_(other.sizes_),
      reservation_identity_(other.reservation_identity_),
      live_(other.live_.exchange(false)) {
    other.parent_read_fds_.fill(-1);
}

FreshTrialP1StateArchiveResidual::~FreshTrialP1StateArchiveResidual() {
    for (auto& fd : parent_read_fds_) close_fd(fd);
}

#ifdef KPI_FRESH_TRIAL_CAPTURE_TOPOLOGY_RESERVATION_TEST_SETUP
FreshTrialP1StateArchiveResidual::TestSummary
FreshTrialP1StateArchiveResidual::test_only_summary() const {
    need(live_.load() && reservation_identity_ != kpb::measurement::Digest{});
    TestSummary result{
        .devices = devices_,
        .inodes = inodes_,
        .reservation_identity = reservation_identity_,
    };
    for (unsigned slot = 0; slot < parent_read_fds_.size(); ++slot)
        result.parent_reads_retained[slot] =
            parent_read_fds_[slot] >= 0 &&
            ::fcntl(parent_read_fds_[slot], F_GETFD) >= 0;
    return result;
}
#endif

FreshTrialCaptureProducerTopologyResidual::
FreshTrialCaptureProducerTopologyResidual(
        std::array<int, 10> read_ends,
        std::array<std::uint64_t, 10> endpoint_devices,
        std::array<std::uint64_t, 10> endpoint_inodes,
        std::array<std::uint32_t, 10> endpoint_types,
        std::array<int, 10> archive_fds,
        std::array<std::uint64_t, 10> archive_devices,
        std::array<std::uint64_t, 10> archive_inodes,
        std::array<std::uint32_t, 10> archive_modes,
        std::array<std::uint64_t, 10> archive_nlinks,
        std::array<std::uint64_t, 10> archive_sizes,
        std::array<std::uint64_t, 2> p1_state_devices,
        std::array<std::uint64_t, 2> p1_state_inodes,
        std::array<std::uint32_t, 2> p1_state_modes,
        std::array<std::uint64_t, 2> p1_state_nlinks,
        std::array<std::uint64_t, 2> p1_state_sizes,
        kpb::measurement::Digest reservation_identity)
    : read_ends_(read_ends), endpoint_devices_(endpoint_devices),
      endpoint_inodes_(endpoint_inodes), endpoint_types_(endpoint_types),
      archive_fds_(archive_fds), archive_devices_(archive_devices),
      archive_inodes_(archive_inodes), archive_modes_(archive_modes),
      archive_nlinks_(archive_nlinks), archive_sizes_(archive_sizes),
      p1_state_devices_(p1_state_devices),
      p1_state_inodes_(p1_state_inodes),
      p1_state_modes_(p1_state_modes),
      p1_state_nlinks_(p1_state_nlinks),
      p1_state_sizes_(p1_state_sizes),
      reservation_identity_(reservation_identity) {}

FreshTrialCaptureProducerTopologyResidual::
FreshTrialCaptureProducerTopologyResidual(
        FreshTrialCaptureProducerTopologyResidual&& other) noexcept
    : read_ends_(other.read_ends_),
      endpoint_devices_(other.endpoint_devices_),
      endpoint_inodes_(other.endpoint_inodes_),
      endpoint_types_(other.endpoint_types_),
      archive_fds_(other.archive_fds_),
      archive_devices_(other.archive_devices_),
      archive_inodes_(other.archive_inodes_),
      archive_modes_(other.archive_modes_),
      archive_nlinks_(other.archive_nlinks_),
      archive_sizes_(other.archive_sizes_),
      p1_state_devices_(other.p1_state_devices_),
      p1_state_inodes_(other.p1_state_inodes_),
      p1_state_modes_(other.p1_state_modes_),
      p1_state_nlinks_(other.p1_state_nlinks_),
      p1_state_sizes_(other.p1_state_sizes_),
      reservation_identity_(other.reservation_identity_),
      live_(other.live_.exchange(false)) {
    other.read_ends_.fill(-1);
    other.archive_fds_.fill(-1);
}

void FreshTrialCaptureProducerTopologyResidual::
require_resources_valid() const {
    need(reservation_identity_ != kpb::measurement::Digest{});
    std::set<std::pair<std::uint64_t, std::uint64_t>> endpoints;
    std::set<std::pair<std::uint64_t, std::uint64_t>> archives;
    std::uint64_t selected_archive_device = 0;
    long selected_filesystem = 0;
    for (unsigned slot = 0; slot < read_ends_.size(); ++slot) {
        const auto reader = fingerprint(read_ends_[slot], O_RDONLY, S_IFIFO);
        need(reader.device == endpoint_devices_[slot] &&
             reader.inode == endpoint_inodes_[slot] &&
             reader.type == endpoint_types_[slot] &&
             endpoints.emplace(reader.device, reader.inode).second);

        const auto archive = fingerprint(
            archive_fds_[slot], O_RDWR, S_IFREG);
        struct stat value{};
        struct statfs filesystem{};
        need(::fstat(archive_fds_[slot], &value) == 0 &&
             ::fstatfs(archive_fds_[slot], &filesystem) == 0);
        need_anonymous_disk_file(value);
        need(filesystem.f_type != TMPFS_MAGIC &&
             filesystem.f_type != RAMFS_MAGIC &&
             archive.device == archive_devices_[slot] &&
             archive.inode == archive_inodes_[slot] &&
             static_cast<std::uint32_t>(value.st_mode) ==
                 archive_modes_[slot] &&
             static_cast<std::uint64_t>(value.st_nlink) ==
                 archive_nlinks_[slot] &&
             static_cast<std::uint64_t>(value.st_size) ==
                 archive_sizes_[slot] &&
             archive_sizes_[slot] == 0 && archive_nlinks_[slot] == 0 &&
             archives.emplace(archive.device, archive.inode).second);
        if (slot == 0) {
            selected_archive_device = archive.device;
            selected_filesystem = filesystem.f_type;
        } else {
            need(archive.device == selected_archive_device &&
                 filesystem.f_type == selected_filesystem);
        }
    }
    need(reservation_identity_ == resource_identity(
        endpoint_devices_, endpoint_inodes_, endpoint_types_,
        archive_devices_, archive_inodes_, archive_modes_,
        archive_nlinks_, archive_sizes_, p1_state_devices_,
        p1_state_inodes_, p1_state_modes_, p1_state_nlinks_,
        p1_state_sizes_));
}

FreshTrialCaptureProducerTopologyResidual::
~FreshTrialCaptureProducerTopologyResidual() {
    for (auto& fd : read_ends_) close_fd(fd);
    for (auto& fd : archive_fds_) close_fd(fd);
}

#ifdef KPI_FRESH_TRIAL_CAPTURE_TOPOLOGY_RESERVATION_TEST_SETUP
void FreshTrialCaptureProducerTopologyResidual::
test_only_corrupt_archive_inode(unsigned slot) {
    need(slot < archive_inodes_.size());
    archive_inodes_[slot] ^= 1U;
}
#endif

FreshTrialCaptureExternalWriterResidual::
FreshTrialCaptureExternalWriterResidual(
        std::array<int, 10> writer_aliases,
        std::array<std::uint64_t, 10> endpoint_devices,
        std::array<std::uint64_t, 10> endpoint_inodes,
        std::array<std::uint32_t, 10> endpoint_types,
        kpb::measurement::Digest reservation_identity)
    : writer_aliases_(writer_aliases),
      endpoint_devices_(endpoint_devices),
      endpoint_inodes_(endpoint_inodes), endpoint_types_(endpoint_types),
      reservation_identity_(reservation_identity) {}

FreshTrialCaptureExternalWriterResidual::
FreshTrialCaptureExternalWriterResidual(
        FreshTrialCaptureExternalWriterResidual&& other) noexcept
    : writer_aliases_(other.writer_aliases_),
      endpoint_devices_(other.endpoint_devices_),
      endpoint_inodes_(other.endpoint_inodes_),
      endpoint_types_(other.endpoint_types_),
      reservation_identity_(other.reservation_identity_),
      live_(other.live_.exchange(false)) {
    other.writer_aliases_.fill(-1);
}

FreshTrialCaptureExternalWriterResidual::
~FreshTrialCaptureExternalWriterResidual() {
    for (auto& fd : writer_aliases_) close_fd(fd);
}

FreshTrialCaptureTopologyReservation::FreshTrialCaptureTopologyReservation(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) {
    need(storage_ != nullptr);
    storage_->require_resources_valid();
}

FreshTrialCaptureTopologyReservation::FreshTrialCaptureTopologyReservation(
        FreshTrialCaptureTopologyReservation&& other) noexcept
    : storage_(std::move(other.storage_)) {}

FreshTrialCaptureTopologyReservation::~
FreshTrialCaptureTopologyReservation() = default;

void FreshTrialCaptureTopologyReservation::validate_for_activation() const {
    need(storage_ != nullptr);
    storage_->require_valid();
}

const void* FreshTrialCaptureTopologyReservation::
preidentity_epoch_token() const noexcept {
    if (storage_ == nullptr || !storage_->live.load() ||
        storage_->process_epoch == nullptr)
        return nullptr;
    return storage_->process_epoch.get();
}

void FreshTrialCaptureTopologyReservation::bind_preidentity_epoch(
        std::shared_ptr<const detail::PersistentProcessReservationEpoch>
            epoch) {
    need(storage_ != nullptr && storage_->live.load() &&
         storage_->process_epoch == nullptr && epoch != nullptr);
    storage_->process_epoch = std::move(epoch);
    storage_->require_valid();
}

FreshTrialCaptureTopologyActivationTransfer
FreshTrialCaptureTopologyReservation::consume_for_activation() && {
    auto storage = std::move(storage_);
    need(storage != nullptr);
    storage->require_valid();
    need(storage->live.exchange(false));
    storage->require_resources_valid();
    auto read_ends = storage->read_ends;
    auto writer_aliases = storage->writer_aliases;
    auto archive_fds = storage->archive_fds;
    auto p1_state_parent_read_fds = storage->p1_state_parent_read_fds;
    auto p1_state_child_writer_aliases =
        storage->p1_state_child_writer_aliases;
    storage->read_ends.fill(-1);
    storage->writer_aliases.fill(-1);
    storage->archive_fds.fill(-1);
    storage->p1_state_parent_read_fds.fill(-1);
    storage->p1_state_child_writer_aliases.fill(-1);
    return FreshTrialCaptureTopologyActivationTransfer(
        read_ends, writer_aliases, storage->endpoint_devices,
        storage->endpoint_inodes, storage->endpoint_types, archive_fds,
        storage->archive_devices, storage->archive_inodes,
        storage->archive_modes, storage->archive_nlinks,
        storage->archive_sizes, p1_state_parent_read_fds,
        p1_state_child_writer_aliases, storage->p1_state_devices,
        storage->p1_state_inodes, storage->p1_state_modes,
        storage->p1_state_nlinks, storage->p1_state_sizes,
        storage->reservation_identity);
}

FreshTrialCaptureTopologyReservation
FreshTrialCaptureTopologyReservationBridge::open_unbound_resources(
        bool diagnostic_unbound) {
    auto storage = std::make_unique<
        FreshTrialCaptureTopologyReservation::Storage>();
    storage->diagnostic_unbound = diagnostic_unbound;
    try {
        for (unsigned slot = 0; slot < storage->read_ends.size(); ++slot) {
            int pair[2]{-1, -1};
            need(::pipe2(pair, O_CLOEXEC) == 0);
            storage->read_ends[slot] = pair[0];
            storage->writer_aliases[slot] = pair[1];
            const auto selected = fingerprint(pair[0], O_RDONLY, S_IFIFO);
            need(fingerprint(pair[1], O_WRONLY, S_IFIFO) == selected);
            storage->endpoint_devices[slot] = selected.device;
            storage->endpoint_inodes[slot] = selected.inode;
            storage->endpoint_types[slot] = selected.type;
        }

        int directory = ::open(
            "/var/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        need(directory >= 0);
        struct stat directory_stat{};
        struct statfs filesystem{};
        try {
            need(::fstat(directory, &directory_stat) == 0 &&
                 S_ISDIR(directory_stat.st_mode) &&
                 ::fstatfs(directory, &filesystem) == 0 &&
                 filesystem.f_type != TMPFS_MAGIC &&
                 filesystem.f_type != RAMFS_MAGIC);
            for (unsigned slot = 0; slot < storage->archive_fds.size();
                 ++slot) {
                int fd = ::openat(
                    directory, ".",
                    O_TMPFILE | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
                need(fd >= 0);
                storage->archive_fds[slot] = fd;
                struct stat value{};
                need(::fstat(fd, &value) == 0 &&
                     value.st_dev == directory_stat.st_dev);
                need_anonymous_disk_file(value);
                storage->archive_devices[slot] =
                    static_cast<std::uint64_t>(value.st_dev);
                storage->archive_inodes[slot] =
                    static_cast<std::uint64_t>(value.st_ino);
                storage->archive_modes[slot] =
                    static_cast<std::uint32_t>(value.st_mode);
                storage->archive_nlinks[slot] =
                    static_cast<std::uint64_t>(value.st_nlink);
                storage->archive_sizes[slot] =
                    static_cast<std::uint64_t>(value.st_size);
            }
            for (unsigned slot = 0;
                 slot < storage->p1_state_parent_read_fds.size(); ++slot) {
                int initial = ::openat(
                    directory, ".",
                    O_TMPFILE | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
                need(initial >= 0);
                try {
                    storage->p1_state_parent_read_fds[slot] =
                        reopen_description(initial, O_RDONLY);
                    storage->p1_state_child_writer_aliases[slot] =
                        reopen_description(initial, O_WRONLY);
                    const auto parent = fingerprint(
                        storage->p1_state_parent_read_fds[slot],
                        O_RDONLY, S_IFREG);
                    need(fingerprint(
                        storage->p1_state_child_writer_aliases[slot],
                        O_WRONLY, S_IFREG) == parent);
                    struct stat value{};
                    need(::fstat(initial, &value) == 0 &&
                         value.st_dev == directory_stat.st_dev);
                    need_anonymous_disk_file(value);
                    storage->p1_state_devices[slot] =
                        static_cast<std::uint64_t>(value.st_dev);
                    storage->p1_state_inodes[slot] =
                        static_cast<std::uint64_t>(value.st_ino);
                    storage->p1_state_modes[slot] =
                        static_cast<std::uint32_t>(value.st_mode);
                    storage->p1_state_nlinks[slot] =
                        static_cast<std::uint64_t>(value.st_nlink);
                    storage->p1_state_sizes[slot] =
                        static_cast<std::uint64_t>(value.st_size);
                    close_fd(initial);
                } catch (...) {
                    close_fd(initial);
                    throw;
                }
            }
            close_fd(directory);
        } catch (...) {
            close_fd(directory);
            throw;
        }
        storage->reservation_identity = resource_identity(
            storage->endpoint_devices, storage->endpoint_inodes,
            storage->endpoint_types, storage->archive_devices,
            storage->archive_inodes, storage->archive_modes,
            storage->archive_nlinks, storage->archive_sizes,
            storage->p1_state_devices, storage->p1_state_inodes,
            storage->p1_state_modes, storage->p1_state_nlinks,
            storage->p1_state_sizes);
        storage->require_resources_valid();
        return FreshTrialCaptureTopologyReservation(std::move(storage));
    } catch (...) { refuse(); }
}

#ifdef KPI_FRESH_TRIAL_CAPTURE_TOPOLOGY_RESERVATION_TEST_SETUP
FreshTrialCaptureTopologyReservation
FreshTrialCaptureTopologyReservationBridge::test_only_reserve_unbound() {
    auto reservation = open_unbound_resources(true);
    need(reservation.storage_ != nullptr);
    reservation.storage_->require_valid();
    return reservation;
}

FreshTrialCaptureTopologyReservation::TestSummary
FreshTrialCaptureTopologyReservation::test_only_summary() const {
    need(storage_ != nullptr);
    storage_->require_valid();
    TestSummary result{
        .contracts = kFreshTrialCaptureWriterContracts,
        .endpoint_devices = storage_->endpoint_devices,
        .endpoint_inodes = storage_->endpoint_inodes,
        .archive_devices = storage_->archive_devices,
        .archive_inodes = storage_->archive_inodes,
        .archive_modes = storage_->archive_modes,
        .archive_nlinks = storage_->archive_nlinks,
        .archive_sizes = storage_->archive_sizes,
        .p1_state_contracts = kFreshTrialP1StateArchiveContracts,
        .p1_state_devices = storage_->p1_state_devices,
        .p1_state_inodes = storage_->p1_state_inodes,
        .p1_state_modes = storage_->p1_state_modes,
        .p1_state_nlinks = storage_->p1_state_nlinks,
        .p1_state_sizes = storage_->p1_state_sizes,
        .reservation_identity = storage_->reservation_identity,
    };
    result.read_ends_valid.fill(true);
    result.writer_aliases_valid.fill(true);
    result.archives_valid.fill(true);
    result.p1_state_parent_reads_valid.fill(true);
    result.p1_state_writer_aliases_valid.fill(true);
    return result;
}

FreshTrialCaptureTopologyActivationTransfer
FreshTrialCaptureTopologyReservation::test_only_take_activation_transfer()
        && {
    return std::move(*this).consume_for_activation();
}

FreshTrialCaptureProducerTopologyResidual
FreshTrialCaptureTopologyReservation::test_only_take_producer_residual() && {
    auto transfer = std::move(*this).consume_for_activation();
    need(transfer.live_.exchange(false));
    for (auto& fd : transfer.writer_aliases_) close_fd(fd);
    auto read_ends = transfer.read_ends_;
    auto archive_fds = transfer.archive_fds_;
    transfer.read_ends_.fill(-1);
    transfer.archive_fds_.fill(-1);
    FreshTrialCaptureProducerTopologyResidual result(
        read_ends, transfer.endpoint_devices_, transfer.endpoint_inodes_,
        transfer.endpoint_types_, archive_fds, transfer.archive_devices_,
        transfer.archive_inodes_, transfer.archive_modes_,
        transfer.archive_nlinks_, transfer.archive_sizes_,
        transfer.p1_state_devices_, transfer.p1_state_inodes_,
        transfer.p1_state_modes_, transfer.p1_state_nlinks_,
        transfer.p1_state_sizes_,
        transfer.reservation_identity_);
    result.require_resources_valid();
    return result;
}

FreshTrialCaptureTopologyQuarantineResidual
FreshTrialCaptureTopologyReservation::test_only_take_quarantine_residual(
        std::array<bool, 10> transferred_writers) && {
    auto transfer = std::move(*this).consume_for_activation();
    for (unsigned slot = 0; slot < transferred_writers.size(); ++slot)
        if (transferred_writers[slot])
            close_fd(transfer.writer_aliases_[slot]);
    return std::move(transfer).quarantine_after_activation_failure();
}

FreshTrialP1StateArchiveResidual
FreshTrialCaptureTopologyReservation::
test_only_take_p1_state_archive_residual() && {
    auto transfer = std::move(*this).consume_for_activation();
    need(transfer.live_.exchange(false));
    for (auto& fd : transfer.read_ends_) close_fd(fd);
    for (auto& fd : transfer.writer_aliases_) close_fd(fd);
    for (auto& fd : transfer.archive_fds_) close_fd(fd);
    for (auto& fd : transfer.p1_state_child_writer_aliases_) close_fd(fd);
    auto parent_reads = transfer.p1_state_parent_read_fds_;
    transfer.p1_state_parent_read_fds_.fill(-1);
    return FreshTrialP1StateArchiveResidual(
        parent_reads, transfer.p1_state_devices_,
        transfer.p1_state_inodes_, transfer.p1_state_modes_,
        transfer.p1_state_nlinks_, transfer.p1_state_sizes_,
        transfer.reservation_identity_);
}

void FreshTrialCaptureTopologyReservationBridge::test_only_require_valid(
        const FreshTrialCaptureTopologyReservation& value) {
    need(value.storage_ != nullptr);
    value.storage_->require_valid();
}

void FreshTrialCaptureTopologyReservationBridge::test_only_close_read_end(
        FreshTrialCaptureTopologyReservation& value, unsigned slot) {
    need(value.storage_ != nullptr && slot < value.storage_->read_ends.size());
    close_fd(value.storage_->read_ends[slot]);
}

void FreshTrialCaptureTopologyReservationBridge::
test_only_close_writer_alias(
        FreshTrialCaptureTopologyReservation& value, unsigned slot) {
    need(value.storage_ != nullptr &&
         slot < value.storage_->writer_aliases.size());
    close_fd(value.storage_->writer_aliases[slot]);
}

void FreshTrialCaptureTopologyReservationBridge::
test_only_swap_writer_aliases(
        FreshTrialCaptureTopologyReservation& value, unsigned first,
        unsigned second) {
    need(value.storage_ != nullptr && first != second &&
         first < value.storage_->writer_aliases.size() &&
         second < value.storage_->writer_aliases.size() &&
         value.storage_->writer_aliases[first] >= 0 &&
         value.storage_->writer_aliases[second] >= 0);
    std::swap(value.storage_->writer_aliases[first],
              value.storage_->writer_aliases[second]);
}

void FreshTrialCaptureTopologyReservationBridge::test_only_close_archive(
        FreshTrialCaptureTopologyReservation& value, unsigned slot) {
    need(value.storage_ != nullptr &&
         slot < value.storage_->archive_fds.size());
    close_fd(value.storage_->archive_fds[slot]);
}

void FreshTrialCaptureTopologyReservationBridge::
test_only_close_p1_state_parent_read(
        FreshTrialCaptureTopologyReservation& value, unsigned slot) {
    need(value.storage_ != nullptr &&
         slot < value.storage_->p1_state_parent_read_fds.size());
    close_fd(value.storage_->p1_state_parent_read_fds[slot]);
}

void FreshTrialCaptureTopologyReservationBridge::
test_only_close_p1_state_writer_alias(
        FreshTrialCaptureTopologyReservation& value, unsigned slot) {
    need(value.storage_ != nullptr &&
         slot < value.storage_->p1_state_child_writer_aliases.size());
    close_fd(value.storage_->p1_state_child_writer_aliases[slot]);
}
#endif

} // namespace kpi::mpc::financial::registered_driver
