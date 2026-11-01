#include "privacy_capture_producer_archive.hpp"
#include "privacy_measurement_run_binding_wire.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <set>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpb::measurement::producer_archive {
namespace {

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

void close_fd(int& fd) noexcept {
    if (fd < 0) return;
    while (::close(fd) != 0 && errno == EINTR) {}
    fd = -1;
}

void close_all(std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT>& fds) {
    for (auto& fd : fds) close_fd(fd);
}

void close_all(std::array<int, 2>& fds) {
    for (auto& fd : fds) close_fd(fd);
}

void valid_binding(const RunBinding& binding) {
    validate_measurement_run_binding(binding);
}

void valid_evidence(const ProducerStreamClosureEvidence& evidence) {
    need(nonzero(evidence.record_root) &&
         nonzero(evidence.end_frame_identity) &&
         nonzero(evidence.eof_identity) &&
         evidence.record_count > 0 && evidence.payload_bytes > 0 &&
         evidence.raw_wire_bytes > evidence.payload_bytes);
}

void add(std::vector<unsigned char>& out, const Digest& value) {
    out.insert(out.end(), value.begin(), value.end());
}

void big_integer(std::vector<unsigned char>& out, std::uint64_t value,
                 unsigned width) {
    for (int shift = static_cast<int>((width - 1) * 8);
         shift >= 0; shift -= 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

Digest hash(std::span<const unsigned char> bytes) {
    Digest result{};
    need(SHA256(bytes.data(), bytes.size(), result.data()) != nullptr &&
         nonzero(result));
    return result;
}

Digest hash_fd(int fd, std::uint64_t size) {
    struct ContextDeleter {
        void operator()(EVP_MD_CTX* value) const { EVP_MD_CTX_free(value); }
    };
    std::unique_ptr<EVP_MD_CTX, ContextDeleter> context(EVP_MD_CTX_new());
    need(context != nullptr &&
         EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) == 1);
    std::array<unsigned char, 1U << 16> bytes{};
    std::uint64_t at = 0;
    while (at < size) {
        const auto target = static_cast<std::size_t>(
            std::min<std::uint64_t>(bytes.size(), size - at));
        ssize_t count;
        do {
            count = ::pread(fd, bytes.data(), target,
                            static_cast<off_t>(at));
        } while (count < 0 && errno == EINTR);
        need(count > 0);
        need(EVP_DigestUpdate(
                 context.get(), bytes.data(),
                 static_cast<std::size_t>(count)) == 1);
        at += static_cast<std::uint64_t>(count);
    }
    Digest result{};
    unsigned length = 0;
    need(EVP_DigestFinal_ex(
             context.get(), result.data(), &length) == 1 &&
         length == result.size() && nonzero(result));
    return result;
}

Digest expected_eof(
        unsigned slot, const ProducerStreamClosureEvidence& evidence) {
    static constexpr char label[] =
        "KPB_CAPTURE_PRODUCER_STREAM_EOF_V1\n";
    std::vector<unsigned char> bytes(label, label + sizeof(label) - 1);
    big_integer(bytes, slot / 5 + 1, 4);
    bytes.push_back(static_cast<unsigned char>(slot % 5 + 1));
    big_integer(bytes, evidence.record_count, 8);
    big_integer(bytes, evidence.payload_bytes, 8);
    big_integer(bytes, evidence.raw_wire_bytes, 8);
    add(bytes, evidence.record_root);
    add(bytes, evidence.end_frame_identity);
    return hash(bytes);
}

int reopen_read_only(int fd) {
    std::array<char, 64> path{};
    const int count = std::snprintf(
        path.data(), path.size(), "/proc/self/fd/%d", fd);
    need(count > 0 && static_cast<std::size_t>(count) < path.size());
    const int result = ::open(path.data(), O_RDONLY | O_CLOEXEC);
    need(result >= 0 &&
         (::fcntl(result, F_GETFL) & O_ACCMODE) == O_RDONLY &&
         (::fcntl(result, F_GETFD) & FD_CLOEXEC) != 0);
    return result;
}

int reopen_read_only_at_least(int fd, int minimum) {
    int reopened = reopen_read_only(fd);
    if (reopened >= minimum) return reopened;
    const int result = ::fcntl(reopened, F_DUPFD_CLOEXEC, minimum);
    close_fd(reopened);
    need(result >= minimum &&
         (::fcntl(result, F_GETFL) & O_ACCMODE) == O_RDONLY &&
         (::fcntl(result, F_GETFD) & FD_CLOEXEC) != 0);
    return result;
}

void need_anonymous_disk_file(const struct stat& value) {
    need(S_ISREG(value.st_mode) && value.st_nlink == 0 &&
         (value.st_mode & 0777) == 0600 && value.st_size >= 0);
}

void need_exact_file(int fd, int access_mode, std::uint64_t device,
                     std::uint64_t inode, std::uint64_t size) {
    struct stat value{};
    need(fd >= 0 &&
         (::fcntl(fd, F_GETFL) & O_ACCMODE) == access_mode &&
         (::fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0 &&
         ::fstat(fd, &value) == 0);
    need_anonymous_disk_file(value);
    need(static_cast<std::uint64_t>(value.st_dev) == device &&
         static_cast<std::uint64_t>(value.st_ino) == inode &&
         static_cast<std::uint64_t>(value.st_size) == size);
}

int close_writer_and_reopen_read_only(int& writer, std::uint64_t device,
                                      std::uint64_t inode,
                                      std::uint64_t size,
                                      const Digest& expected_hash) {
    int read_fd = -1;
    try {
        need_exact_file(writer, O_RDWR, device, inode, size);
        need(::fsync(writer) == 0 && hash_fd(writer, size) == expected_hash);
        read_fd = reopen_read_only(writer);
        need_exact_file(read_fd, O_RDONLY, device, inode, size);
        need(hash_fd(read_fd, size) == expected_hash);
        close_fd(writer);
        return std::exchange(read_fd, -1);
    } catch (...) {
        close_fd(read_fd);
        throw;
    }
}

constexpr std::array<unsigned, 2> PARTIAL_C03_SOURCE_SLOTS{3, 8};
constexpr std::array<unsigned, 2> PARTIAL_C03_FIXED_FDS{23, 28};

} // namespace

struct ProducerSealedArchiveBuilder::Storage {
    struct Slot {
        int fd{-1};
        std::uint64_t device{};
        std::uint64_t inode{};
        std::uint64_t size{};
        bool finished{};
        ProducerStreamClosureEvidence evidence;
    };
    RunBinding binding;
    Digest closure_identity{};
    Digest reservation_identity{};
    std::array<Slot, PRODUCER_ARCHIVE_STREAM_COUNT> slots{};
    std::uint64_t total_size{};
    std::atomic_bool live{true};
    bool poisoned{};
#ifdef KPB_CAPTURE_PRODUCER_ARCHIVE_TEST_SETUP
    bool test_only_fail_partial_after_first_transition{};
#endif
    ~Storage() { for (auto& slot : slots) close_fd(slot.fd); }
};

struct ProducerSealedArchiveAuthority::Storage {
    struct Slot {
        int fd{-1};
        std::uint64_t device{};
        std::uint64_t inode{};
        std::uint64_t size{};
        ProducerStreamClosureEvidence evidence;
    };
    RunBinding binding;
    Digest closure_identity{};
    Digest reservation_identity{};
    std::array<Slot, PRODUCER_ARCHIVE_STREAM_COUNT> slots{};
    std::atomic_bool live{true};
    mutable std::atomic_bool transport_issued{false};
    mutable std::atomic_bool c03_history_issued{false};
    ~Storage() { for (auto& slot : slots) close_fd(slot.fd); }
};

struct ProducerPartialC03ArchiveAuthority::Storage {
    struct Slot {
        int fd{-1};
        std::uint64_t device{};
        std::uint64_t inode{};
        std::uint64_t size{};
        int seals{};
        bool writer_aliases_closed{};
        Digest sha256{};
        bool complete_end_and_eof{};
        ProducerStreamClosureEvidence evidence;
    };
    RunBinding binding;
    Digest closure_identity{};
    Digest reservation_identity{};
    std::array<Slot, 2> slots{};
    std::atomic_bool live{true};
    mutable std::atomic_bool transport_issued{false};
    ~Storage() { for (auto& slot : slots) close_fd(slot.fd); }
};

ProducerSealedArchiveBuilder::ProducerSealedArchiveBuilder(
        RunBinding binding, Digest closure_identity)
    : storage_(std::make_unique<Storage>()) {
    try {
        valid_binding(binding);
        need(nonzero(closure_identity));
        storage_->binding = std::move(binding);
        storage_->closure_identity = closure_identity;
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
        } catch (...) {
            close_fd(directory);
            throw;
        }
        std::set<std::pair<std::uint64_t, std::uint64_t>> identities;
        try {
            for (auto& selected : storage_->slots) {
                selected.fd = ::openat(
                    directory, ".",
                    O_TMPFILE | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
                need(selected.fd >= 0);
                struct stat value{};
                need(::fstat(selected.fd, &value) == 0);
                need_anonymous_disk_file(value);
                need(value.st_size == 0 &&
                     value.st_dev == directory_stat.st_dev &&
                     identities.emplace(
                         static_cast<std::uint64_t>(value.st_dev),
                         static_cast<std::uint64_t>(value.st_ino)).second);
                selected.device = static_cast<std::uint64_t>(value.st_dev);
                selected.inode = static_cast<std::uint64_t>(value.st_ino);
            }
            static constexpr char reservation_domain[] =
                "KPB_CAPTURE_PRODUCER_ARCHIVE_RESERVATION_V1\n";
            std::vector<unsigned char> reservation(
                reservation_domain,
                reservation_domain + sizeof(reservation_domain) - 1);
            const auto binding_bytes =
                wire::canonical_run_binding_bytes(storage_->binding);
            reservation.insert(
                reservation.end(), binding_bytes.begin(), binding_bytes.end());
            add(reservation, storage_->closure_identity);
            for (unsigned slot = 0; slot < storage_->slots.size(); ++slot) {
                const auto& selected = storage_->slots[slot];
                struct stat value{};
                need(::fstat(selected.fd, &value) == 0);
                big_integer(reservation, slot, 4);
                big_integer(reservation, selected.device, 8);
                big_integer(reservation, selected.inode, 8);
                big_integer(
                    reservation, static_cast<std::uint32_t>(value.st_mode), 4);
                big_integer(
                    reservation, static_cast<std::uint64_t>(value.st_nlink), 8);
                big_integer(
                    reservation, static_cast<std::uint64_t>(value.st_size), 8);
            }
            storage_->reservation_identity = hash(reservation);
            close_fd(directory);
        } catch (...) {
            close_fd(directory);
            throw;
        }
    } catch (...) {
        storage_->poisoned = true;
        throw;
    }
}

ProducerSealedArchiveBuilder::ProducerSealedArchiveBuilder(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) {
    need(storage_ != nullptr);
}

ProducerSealedArchiveBuilder
ProducerSealedArchiveBuilder::adopt_preidentity_reservation(
        RunBinding binding, Digest closure_identity,
        Digest reservation_identity,
        std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT>&& archive_fds,
        const std::array<std::uint64_t,
                         PRODUCER_ARCHIVE_STREAM_COUNT>& devices,
        const std::array<std::uint64_t,
                         PRODUCER_ARCHIVE_STREAM_COUNT>& inodes,
        const std::array<std::uint32_t,
                         PRODUCER_ARCHIVE_STREAM_COUNT>& modes,
        const std::array<std::uint64_t,
                         PRODUCER_ARCHIVE_STREAM_COUNT>& nlinks,
        const std::array<std::uint64_t,
                         PRODUCER_ARCHIVE_STREAM_COUNT>& sizes) {
    std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT> received = archive_fds;
    archive_fds.fill(-1);
    try {
        valid_binding(binding);
        need(nonzero(closure_identity) && nonzero(reservation_identity));
        auto storage = std::make_unique<Storage>();
        storage->binding = std::move(binding);
        storage->closure_identity = closure_identity;
        storage->reservation_identity = reservation_identity;
        std::set<std::pair<std::uint64_t, std::uint64_t>> identities;
        std::uint64_t selected_device = 0;
        long selected_filesystem = 0;
        for (unsigned slot = 0; slot < received.size(); ++slot) {
            struct stat value{};
            struct statfs filesystem{};
            need(received[slot] >= 0 &&
                 (::fcntl(received[slot], F_GETFL) & O_ACCMODE) == O_RDWR &&
                 (::fcntl(received[slot], F_GETFD) & FD_CLOEXEC) != 0 &&
                 ::fstat(received[slot], &value) == 0 &&
                 ::fstatfs(received[slot], &filesystem) == 0);
            need_anonymous_disk_file(value);
            need(filesystem.f_type != TMPFS_MAGIC &&
                 filesystem.f_type != RAMFS_MAGIC && value.st_size == 0 &&
                 static_cast<std::uint64_t>(value.st_dev) == devices[slot] &&
                 static_cast<std::uint64_t>(value.st_ino) == inodes[slot] &&
                 static_cast<std::uint32_t>(value.st_mode) == modes[slot] &&
                 static_cast<std::uint64_t>(value.st_nlink) == nlinks[slot] &&
                 static_cast<std::uint64_t>(value.st_size) == sizes[slot] &&
                 sizes[slot] == 0 && nlinks[slot] == 0 &&
                 identities.emplace(devices[slot], inodes[slot]).second);
            if (slot == 0) {
                selected_device = devices[slot];
                selected_filesystem = filesystem.f_type;
            } else {
                need(devices[slot] == selected_device &&
                     filesystem.f_type == selected_filesystem);
            }
            auto& output = storage->slots[slot];
            output.fd = std::exchange(received[slot], -1);
            output.device = devices[slot];
            output.inode = inodes[slot];
            output.size = 0;
        }
        return ProducerSealedArchiveBuilder(std::move(storage));
    } catch (...) {
        close_all(received);
        refuse();
    }
}

ProducerSealedArchiveBuilder::ProducerSealedArchiveBuilder(
        ProducerSealedArchiveBuilder&& other) noexcept
    : storage_(std::move(other.storage_)) {}

ProducerSealedArchiveBuilder::~ProducerSealedArchiveBuilder() = default;

std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT>
ProducerSealedArchiveBuilder::inherited_writer_fds_for_runtime() const {
    need(storage_ != nullptr && storage_->live.load() &&
         !storage_->poisoned);
    std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT> result{};
    for (unsigned slot = 0; slot < result.size(); ++slot) {
        const auto& selected = storage_->slots[slot];
        struct stat value{};
        need(selected.fd >= 0 && ::fstat(selected.fd, &value) == 0 &&
             (::fcntl(selected.fd, F_GETFL) & O_ACCMODE) == O_RDWR &&
             (::fcntl(selected.fd, F_GETFD) & FD_CLOEXEC) != 0);
        need_anonymous_disk_file(value);
        need(value.st_size == 0 &&
             static_cast<std::uint64_t>(value.st_dev) == selected.device &&
             static_cast<std::uint64_t>(value.st_ino) == selected.inode);
        result[slot] = selected.fd;
    }
    return result;
}

void ProducerSealedArchiveBuilder::append(
        unsigned slot, std::span<const unsigned char> bytes) {
    need(storage_ != nullptr && storage_->live.load() &&
         !storage_->poisoned && slot < storage_->slots.size() &&
         !bytes.empty());
    auto& selected = storage_->slots[slot];
    need(!selected.finished && selected.fd >= 0);
    std::size_t at = 0;
    while (at < bytes.size()) {
        const auto count = ::write(
            selected.fd, bytes.data() + at, bytes.size() - at);
        if (count < 0 && errno == EINTR) continue;
        need(count > 0);
        const auto amount = static_cast<std::uint64_t>(count);
        constexpr auto maximum =
            std::numeric_limits<std::uint64_t>::max();
        need(selected.size <= maximum - amount &&
             storage_->total_size <= maximum - amount);
        selected.size += amount;
        storage_->total_size += amount;
        at += static_cast<std::size_t>(count);
    }
}

void ProducerSealedArchiveBuilder::finish_after_end_and_eof(
        unsigned slot, const ProducerStreamClosureEvidence& evidence) {
    need(storage_ != nullptr && storage_->live.load() &&
         !storage_->poisoned && slot < storage_->slots.size());
    auto& selected = storage_->slots[slot];
    try {
        valid_evidence(evidence);
        need(!selected.finished && selected.fd >= 0 &&
             selected.size == evidence.raw_wire_bytes &&
             hash_fd(selected.fd, selected.size) == evidence.record_root &&
             expected_eof(slot, evidence) == evidence.eof_identity);
        selected.fd = close_writer_and_reopen_read_only(
            selected.fd, selected.device, selected.inode, selected.size,
            evidence.record_root);
        selected.evidence = evidence;
        selected.finished = true;
    } catch (...) {
        storage_->poisoned = true;
        refuse();
    }
}

ProducerSealedArchiveAuthority ProducerSealedArchiveBuilder::finish() && {
    need(storage_ != nullptr && storage_->live.exchange(false) &&
         !storage_->poisoned);
    try {
        std::set<std::pair<std::uint64_t, std::uint64_t>> identities;
        for (unsigned slot = 0; slot < storage_->slots.size(); ++slot) {
            const auto& input = storage_->slots[slot];
            need(input.finished && input.fd >= 0);
            valid_evidence(input.evidence);
            need_exact_file(input.fd, O_RDONLY, input.device, input.inode,
                            input.size);
            need(input.size == input.evidence.raw_wire_bytes &&
                 hash_fd(input.fd, input.size) == input.evidence.record_root &&
                 expected_eof(slot, input.evidence) ==
                     input.evidence.eof_identity &&
                 identities.emplace(input.device, input.inode).second);
        }

        auto authority =
            std::make_unique<ProducerSealedArchiveAuthority::Storage>();
        authority->binding = storage_->binding;
        authority->closure_identity = storage_->closure_identity;
        authority->reservation_identity = storage_->reservation_identity;
        for (unsigned slot = 0; slot < storage_->slots.size(); ++slot) {
            auto& input = storage_->slots[slot];
            auto& output = authority->slots[slot];
            output.fd = std::exchange(input.fd, -1);
            output.device = input.device;
            output.inode = input.inode;
            output.size = input.size;
            output.evidence = input.evidence;
        }
        return ProducerSealedArchiveAuthority(std::move(authority));
    } catch (...) {
        storage_->poisoned = true;
        refuse();
    }
}

ProducerPartialC03ArchiveAuthority
ProducerSealedArchiveBuilder::seal_partial_c03_for_runtime() && {
    need(storage_ != nullptr);
    const bool claimed = storage_->live.exchange(false);
    need(claimed);
    try {
        valid_binding(storage_->binding);
        need(nonzero(storage_->closure_identity));
        std::array<Digest, 2> selected_hashes{};
        std::set<std::pair<std::uint64_t, std::uint64_t>> identities;
        for (unsigned index = 0; index < PARTIAL_C03_SOURCE_SLOTS.size();
             ++index) {
            const unsigned source_slot = PARTIAL_C03_SOURCE_SLOTS[index];
            auto& input = storage_->slots[source_slot];
            need(input.fd >= 0);

            if (!input.finished) {
                struct stat before{};
                need(::fstat(input.fd, &before) == 0 &&
                     (::fcntl(input.fd, F_GETFL) & O_ACCMODE) == O_RDWR);
                need_anonymous_disk_file(before);
                need(
                     static_cast<std::uint64_t>(before.st_dev) ==
                         input.device &&
                     static_cast<std::uint64_t>(before.st_ino) ==
                         input.inode);
                // The parent retained this alias before fork, so its COW
                // metadata intentionally does not observe the child writer's
                // counters. The inode size is authoritative only after the
                // exact writer has exited.
                input.size = static_cast<std::uint64_t>(before.st_size);
                const Digest selected_hash = hash_fd(input.fd, input.size);
                input.fd = close_writer_and_reopen_read_only(
                    input.fd, input.device, input.inode, input.size,
                    selected_hash);
            } else {
                valid_evidence(input.evidence);
                need(input.size == input.evidence.raw_wire_bytes &&
                     input.evidence.record_root ==
                         hash_fd(input.fd, input.size) &&
                     expected_eof(source_slot, input.evidence) ==
                         input.evidence.eof_identity);
            }

            need_exact_file(input.fd, O_RDONLY, input.device, input.inode,
                            input.size);
            need(identities.emplace(input.device, input.inode).second);
            selected_hashes[index] = hash_fd(input.fd, input.size);
            if (input.finished) {
                need(selected_hashes[index] == input.evidence.record_root);
            }
#ifdef KPB_CAPTURE_PRODUCER_ARCHIVE_TEST_SETUP
            if (index == 0 &&
                storage_->test_only_fail_partial_after_first_transition)
                refuse();
#endif
        }

        auto authority =
            std::make_unique<ProducerPartialC03ArchiveAuthority::Storage>();
        authority->binding = storage_->binding;
        authority->closure_identity = storage_->closure_identity;
        authority->reservation_identity = storage_->reservation_identity;
        for (unsigned index = 0; index < PARTIAL_C03_SOURCE_SLOTS.size();
             ++index) {
            const unsigned source_slot = PARTIAL_C03_SOURCE_SLOTS[index];
            auto& input = storage_->slots[source_slot];
            auto& output = authority->slots[index];
            // Retain the original read-only description in the all-ten
            // builder until the runtime has independently parsed both C03
            // objects.  The partial authority receives a separate file
            // description over the same anonymous inode; a later inspection
            // failure can therefore quarantine every original slot instead
            // of dropping the other eight streams.
            output.fd = reopen_read_only(input.fd);
            output.device = input.device;
            output.inode = input.inode;
            output.size = input.size;
            output.seals = 0;
            output.writer_aliases_closed = true;
            output.sha256 = selected_hashes[index];
            output.complete_end_and_eof = input.finished;
            if (input.finished) output.evidence = input.evidence;
        }
        return ProducerPartialC03ArchiveAuthority(std::move(authority));
    } catch (...) {
        storage_->poisoned = true;
        refuse();
    }
}

ProducerArchiveQuarantineAuthority
ProducerSealedArchiveBuilder::quarantine_for_runtime(
        ProducerArchiveQuarantineStage stage, int error_number) && noexcept {
    const auto raw_stage = static_cast<unsigned char>(stage);
    if (raw_stage < static_cast<unsigned char>(
                        ProducerArchiveQuarantineStage::Append) ||
        raw_stage > static_cast<unsigned char>(
                        ProducerArchiveQuarantineStage::Internal))
        stage = ProducerArchiveQuarantineStage::Internal;
    if (error_number <= 0) error_number = EPROTO;
    if (storage_ != nullptr) {
        storage_->live.store(false);
        storage_->poisoned = true;
    }
    return ProducerArchiveQuarantineAuthority(
        std::move(storage_), stage, error_number);
}

ProducerArchiveQuarantineAuthority::ProducerArchiveQuarantineAuthority(
        std::unique_ptr<ProducerSealedArchiveBuilder::Storage> storage,
        ProducerArchiveQuarantineStage stage, int error_number) noexcept
    : storage_(std::move(storage)), stage_(stage),
      error_number_(error_number) {}

ProducerArchiveQuarantineAuthority::ProducerArchiveQuarantineAuthority(
        ProducerArchiveQuarantineAuthority&& other) noexcept
    : storage_(std::move(other.storage_)), stage_(other.stage_),
      error_number_(other.error_number_) {
    other.stage_ = {};
    other.error_number_ = 0;
}

ProducerArchiveQuarantineAuthority::~ProducerArchiveQuarantineAuthority() =
    default;

ProducerSealedArchiveAuthority::ProducerSealedArchiveAuthority(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }

ProducerSealedArchiveAuthority::ProducerSealedArchiveAuthority(
        ProducerSealedArchiveAuthority&& other) noexcept
    : storage_(std::move(other.storage_)) {}

ProducerSealedArchiveAuthority::~ProducerSealedArchiveAuthority() = default;

ProducerPartialC03ArchiveAuthority
ProducerSealedArchiveAuthority::duplicate_c03_for_runtime() const {
    need(storage_ != nullptr && storage_->live.load());
    const bool already_issued = storage_->c03_history_issued.exchange(true);
    need(!already_issued);
    try {
        auto partial =
            std::make_unique<ProducerPartialC03ArchiveAuthority::Storage>();
        partial->binding = storage_->binding;
        partial->closure_identity = storage_->closure_identity;
        partial->reservation_identity = storage_->reservation_identity;
        std::set<std::pair<std::uint64_t, std::uint64_t>> identities;
        for (unsigned index = 0; index < PARTIAL_C03_SOURCE_SLOTS.size();
             ++index) {
            const unsigned source_slot = PARTIAL_C03_SOURCE_SLOTS[index];
            const auto& input = storage_->slots[source_slot];
            valid_evidence(input.evidence);
            need_exact_file(input.fd, O_RDONLY, input.device, input.inode,
                            input.size);
            need(input.size == input.evidence.raw_wire_bytes &&
                 hash_fd(input.fd, input.size) == input.evidence.record_root &&
                 expected_eof(source_slot, input.evidence) ==
                     input.evidence.eof_identity &&
                 identities.emplace(input.device, input.inode).second);
            auto& output = partial->slots[index];
            output.fd = reopen_read_only(input.fd);
            output.device = input.device;
            output.inode = input.inode;
            output.size = input.size;
            output.seals = 0;
            output.writer_aliases_closed = true;
            output.sha256 = input.evidence.record_root;
            output.complete_end_and_eof = true;
            output.evidence = input.evidence;
        }
        return ProducerPartialC03ArchiveAuthority(std::move(partial));
    } catch (...) {
        refuse();
    }
}

ProducerPartialC03ArchiveAuthority::ProducerPartialC03ArchiveAuthority(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) {
    need(storage_ != nullptr);
}

ProducerPartialC03ArchiveAuthority::ProducerPartialC03ArchiveAuthority(
        ProducerPartialC03ArchiveAuthority&& other) noexcept
    : storage_(std::move(other.storage_)) {}

ProducerPartialC03ArchiveAuthority::~ProducerPartialC03ArchiveAuthority() =
    default;

ProducerPartialC03ArchiveRuntimeTransfer::
ProducerPartialC03ArchiveRuntimeTransfer() {
    fds_.fill(-1);
}

ProducerPartialC03ArchiveRuntimeTransfer::
ProducerPartialC03ArchiveRuntimeTransfer(
        ProducerPartialC03ArchiveRuntimeTransfer&& other) noexcept
    : binding_(other.binding_), closure_identity_(other.closure_identity_),
      reservation_identity_(other.reservation_identity_),
      source_slots_(other.source_slots_), fixed_fds_(other.fixed_fds_),
      fds_(other.fds_), devices_(other.devices_), inodes_(other.inodes_),
      sizes_(other.sizes_), seals_(other.seals_), sha256_(other.sha256_),
      complete_end_and_eof_(other.complete_end_and_eof_),
      evidence_(other.evidence_) {
    other.fds_.fill(-1);
}

ProducerPartialC03ArchiveRuntimeTransfer::
~ProducerPartialC03ArchiveRuntimeTransfer() {
    close_all(fds_);
}

ProducerPartialC03ArchiveRuntimeTransfer
ProducerPartialC03ArchiveAuthority::duplicate_for_runtime_transport() && {
    need(storage_ != nullptr);
    const bool claimed = storage_->live.exchange(false);
    const bool already_issued = storage_->transport_issued.exchange(true);
    need(claimed && !already_issued);
    ProducerPartialC03ArchiveRuntimeTransfer result;
    try {
        valid_binding(storage_->binding);
        need(nonzero(storage_->closure_identity));
        result.binding_ = storage_->binding;
        result.closure_identity_ = storage_->closure_identity;
        result.reservation_identity_ = storage_->reservation_identity;
        result.source_slots_ = PARTIAL_C03_SOURCE_SLOTS;
        result.fixed_fds_ = PARTIAL_C03_FIXED_FDS;
        std::set<std::pair<std::uint64_t, std::uint64_t>> identities;
        for (unsigned index = 0; index < storage_->slots.size(); ++index) {
            const auto& selected = storage_->slots[index];
            need_exact_file(selected.fd, O_RDONLY, selected.device,
                            selected.inode, selected.size);
            need(selected.seals == 0 && selected.writer_aliases_closed &&
                 nonzero(selected.sha256) &&
                 hash_fd(selected.fd, selected.size) == selected.sha256 &&
                 identities.emplace(selected.device, selected.inode).second);
            if (selected.complete_end_and_eof) {
                valid_evidence(selected.evidence);
                need(selected.evidence.raw_wire_bytes == selected.size &&
                     selected.evidence.record_root == selected.sha256 &&
                     expected_eof(PARTIAL_C03_SOURCE_SLOTS[index],
                                  selected.evidence) ==
                         selected.evidence.eof_identity);
            } else {
                need(selected.evidence == ProducerStreamClosureEvidence{});
            }
            result.fds_[index] = reopen_read_only(selected.fd);
            result.devices_[index] = selected.device;
            result.inodes_[index] = selected.inode;
            result.sizes_[index] = selected.size;
            result.seals_[index] = selected.seals;
            result.sha256_[index] = selected.sha256;
            result.complete_end_and_eof_[index] =
                selected.complete_end_and_eof;
            result.evidence_[index] = selected.evidence;
        }
        return result;
    } catch (...) {
        refuse();
    }
}

ProducerPartialC03ArchiveAuthority
ProducerPartialC03ArchiveAuthority::adopt_runtime_transport(
        ProducerPartialC03ArchiveRuntimeTransfer&& supplied) {
    std::array<int, 2> received = supplied.fds_;
    supplied.fds_.fill(-1);
    std::array<int, 2> reopened{};
    reopened.fill(-1);
    try {
        valid_binding(supplied.binding_);
        need(nonzero(supplied.closure_identity_) &&
             supplied.source_slots_ == PARTIAL_C03_SOURCE_SLOTS &&
             supplied.fixed_fds_ == PARTIAL_C03_FIXED_FDS);
        auto storage = std::make_unique<Storage>();
        storage->binding = supplied.binding_;
        storage->closure_identity = supplied.closure_identity_;
        storage->reservation_identity = supplied.reservation_identity_;
        std::set<std::pair<std::uint64_t, std::uint64_t>> identities;
        for (unsigned index = 0; index < received.size(); ++index) {
            need_exact_file(received[index], O_RDONLY,
                            supplied.devices_[index],
                            supplied.inodes_[index],
                            supplied.sizes_[index]);
            need(supplied.seals_[index] == 0 &&
                 nonzero(supplied.sha256_[index]) &&
                 hash_fd(received[index], supplied.sizes_[index]) ==
                     supplied.sha256_[index] &&
                 identities.emplace(supplied.devices_[index],
                                    supplied.inodes_[index]).second);
            if (supplied.complete_end_and_eof_[index]) {
                valid_evidence(supplied.evidence_[index]);
                need(supplied.evidence_[index].raw_wire_bytes ==
                         supplied.sizes_[index] &&
                     supplied.evidence_[index].record_root ==
                         supplied.sha256_[index] &&
                     expected_eof(PARTIAL_C03_SOURCE_SLOTS[index],
                                  supplied.evidence_[index]) ==
                         supplied.evidence_[index].eof_identity);
            } else {
                need(supplied.evidence_[index] ==
                     ProducerStreamClosureEvidence{});
            }
            reopened[index] = reopen_read_only(received[index]);
            auto& output = storage->slots[index];
            output.fd = std::exchange(reopened[index], -1);
            output.device = supplied.devices_[index];
            output.inode = supplied.inodes_[index];
            output.size = supplied.sizes_[index];
            output.seals = supplied.seals_[index];
            output.writer_aliases_closed = true;
            output.sha256 = supplied.sha256_[index];
            output.complete_end_and_eof =
                supplied.complete_end_and_eof_[index];
            output.evidence = supplied.evidence_[index];
        }
        close_all(received);
        return ProducerPartialC03ArchiveAuthority(std::move(storage));
    } catch (...) {
        close_all(reopened);
        close_all(received);
        refuse();
    }
}

ProducerArchiveObserverTransfer::ProducerArchiveObserverTransfer() {
    fds_.fill(-1);
}

ProducerArchiveObserverTransfer::ProducerArchiveObserverTransfer(
        ProducerArchiveObserverTransfer&& other) noexcept
    : binding_(other.binding_), closure_identity_(other.closure_identity_),
      reservation_identity_(other.reservation_identity_),
      fds_(other.fds_), devices_(other.devices_), inodes_(other.inodes_),
      sizes_(other.sizes_), evidence_(other.evidence_) {
    other.fds_.fill(-1);
}

ProducerArchiveObserverTransfer::~ProducerArchiveObserverTransfer() {
    close_all(fds_);
}

ProducerArchiveObserverTransfer
ProducerSealedArchiveAuthority::consume_for_observer() && {
    need(storage_ != nullptr && storage_->live.exchange(false));
    ProducerArchiveObserverTransfer result;
    try {
        valid_binding(storage_->binding);
        need(nonzero(storage_->closure_identity));
        result.binding_ = storage_->binding;
        result.closure_identity_ = storage_->closure_identity;
        result.reservation_identity_ = storage_->reservation_identity;
        std::set<std::pair<std::uint64_t, std::uint64_t>> identities;
        for (unsigned slot = 0; slot < storage_->slots.size(); ++slot) {
            auto& selected = storage_->slots[slot];
            valid_evidence(selected.evidence);
            need_exact_file(selected.fd, O_RDONLY, selected.device,
                            selected.inode, selected.size);
            need(
                 selected.size == selected.evidence.raw_wire_bytes &&
                 hash_fd(selected.fd, selected.size) ==
                     selected.evidence.record_root &&
                 expected_eof(slot, selected.evidence) ==
                     selected.evidence.eof_identity &&
                 identities.emplace(selected.device, selected.inode).second);
            result.fds_[slot] = std::exchange(selected.fd, -1);
            result.devices_[slot] = selected.device;
            result.inodes_[slot] = selected.inode;
            result.sizes_[slot] = selected.size;
            result.evidence_[slot] = selected.evidence;
        }
        return result;
    } catch (...) {
        refuse();
    }
}

std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT>
ProducerSealedArchiveAuthority::duplicate_for_transport() const {
    need(storage_ != nullptr && storage_->live.load() &&
         !storage_->transport_issued.exchange(true));
    std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT> result{};
    result.fill(-1);
    try {
        for (unsigned slot = 0; slot < result.size(); ++slot) {
            const auto& selected = storage_->slots[slot];
            need_exact_file(selected.fd, O_RDONLY, selected.device,
                            selected.inode, selected.size);
            result[slot] = reopen_read_only_at_least(selected.fd, 80);
        }
        return result;
    } catch (...) {
        close_all(result);
        refuse();
    }
}

ProducerSealedArchiveAuthority
ProducerSealedArchiveAuthority::adopt_received(
        RunBinding binding, Digest closure_identity,
        std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT>&& supplied,
        std::array<ProducerStreamClosureEvidence,
                   PRODUCER_ARCHIVE_STREAM_COUNT> evidence) {
    std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT> received = supplied;
    supplied.fill(-1);
    std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT> reopened{};
    reopened.fill(-1);
    try {
        valid_binding(binding);
        need(nonzero(closure_identity));
        auto storage = std::make_unique<Storage>();
        storage->binding = std::move(binding);
        storage->closure_identity = closure_identity;
        std::set<std::pair<std::uint64_t, std::uint64_t>> identities;
        for (unsigned slot = 0; slot < received.size(); ++slot) {
            valid_evidence(evidence[slot]);
            struct stat value{};
            need(received[slot] >= 0 && ::fstat(received[slot], &value) == 0);
            need_anonymous_disk_file(value);
            need((::fcntl(received[slot], F_GETFL) & O_ACCMODE) == O_RDONLY &&
                 (::fcntl(received[slot], F_GETFD) & FD_CLOEXEC) != 0 &&
                 expected_eof(slot, evidence[slot]) ==
                     evidence[slot].eof_identity);
            need(static_cast<std::uint64_t>(value.st_size) ==
                     evidence[slot].raw_wire_bytes &&
                 identities.emplace(
                     static_cast<std::uint64_t>(value.st_dev),
                     static_cast<std::uint64_t>(value.st_ino)).second &&
                 hash_fd(received[slot], evidence[slot].raw_wire_bytes) ==
                     evidence[slot].record_root);
            reopened[slot] = reopen_read_only(received[slot]);
            auto& output = storage->slots[slot];
            output.fd = std::exchange(reopened[slot], -1);
            output.device = static_cast<std::uint64_t>(value.st_dev);
            output.inode = static_cast<std::uint64_t>(value.st_ino);
            output.size = static_cast<std::uint64_t>(value.st_size);
            output.evidence = evidence[slot];
        }
        close_all(received);
        return ProducerSealedArchiveAuthority(std::move(storage));
    } catch (...) {
        close_all(reopened);
        close_all(received);
        refuse();
    }
}

#ifdef KPB_CAPTURE_PRODUCER_ARCHIVE_TEST_SETUP
ProducerSealedArchiveBuilder ProducerSealedArchiveBuilder::test_only_begin(
        RunBinding binding, Digest closure_identity) {
    return ProducerSealedArchiveBuilder(
        std::move(binding), closure_identity);
}

std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT>
ProducerSealedArchiveBuilder::test_only_inherited_writer_fds(
        const ProducerSealedArchiveBuilder& builder) {
    return builder.inherited_writer_fds_for_runtime();
}

ProducerPartialC03ArchiveAuthority
ProducerSealedArchiveBuilder::test_only_seal_partial_c03(
        ProducerSealedArchiveBuilder&& builder) {
    return std::move(builder).seal_partial_c03_for_runtime();
}

void ProducerSealedArchiveBuilder::
test_only_fail_partial_after_first_transition(
        ProducerSealedArchiveBuilder& builder) {
    need(builder.storage_ != nullptr && builder.storage_->live.load());
    builder.storage_->test_only_fail_partial_after_first_transition = true;
}

ProducerArchiveQuarantineAuthority
ProducerSealedArchiveBuilder::test_only_quarantine(
        ProducerSealedArchiveBuilder&& builder,
        ProducerArchiveQuarantineStage stage, int error_number) noexcept {
    return std::move(builder).quarantine_for_runtime(stage, error_number);
}

ProducerArchiveQuarantineAuthority::TestOnlySummary
ProducerArchiveQuarantineAuthority::test_only_summary() const {
    need(storage_ != nullptr);
    TestOnlySummary result{
        .binding = storage_->binding,
        .closure_identity = storage_->closure_identity,
        .reservation_identity = storage_->reservation_identity,
        .stage = stage_,
        .error_number = error_number_,
    };
    for (unsigned slot = 0; slot < storage_->slots.size(); ++slot) {
        const auto& selected = storage_->slots[slot];
        struct stat value{};
        need(selected.fd >= 0 && ::fstat(selected.fd, &value) == 0 &&
             S_ISREG(value.st_mode) && value.st_nlink == 0 &&
             (value.st_mode & 0777) == 0600 && value.st_size >= 0 &&
             (::fcntl(selected.fd, F_GETFD) & FD_CLOEXEC) != 0 &&
             static_cast<std::uint64_t>(value.st_dev) == selected.device &&
             static_cast<std::uint64_t>(value.st_ino) == selected.inode);
        result.descriptor_retained[slot] = true;
        result.devices[slot] = selected.device;
        result.inodes[slot] = selected.inode;
        result.sizes[slot] = static_cast<std::uint64_t>(value.st_size);
        result.access_modes[slot] =
            ::fcntl(selected.fd, F_GETFL) & O_ACCMODE;
        result.finished[slot] = selected.finished;
    }
    return result;
}

ProducerPartialC03ArchiveAuthority::TestOnlySummary
ProducerPartialC03ArchiveAuthority::test_only_summary() const {
    need(storage_ != nullptr && storage_->live.load());
    TestOnlySummary result{
        .binding = storage_->binding,
        .closure_identity = storage_->closure_identity,
        .reservation_identity = storage_->reservation_identity,
        .source_slots = PARTIAL_C03_SOURCE_SLOTS,
        .fixed_fds = PARTIAL_C03_FIXED_FDS,
    };
    for (unsigned index = 0; index < storage_->slots.size(); ++index) {
        const auto& selected = storage_->slots[index];
        result.devices[index] = selected.device;
        result.inodes[index] = selected.inode;
        result.sizes[index] = selected.size;
        result.seals[index] = selected.seals;
        result.read_only[index] =
            selected.fd >= 0 &&
            (::fcntl(selected.fd, F_GETFL) & O_ACCMODE) == O_RDONLY;
        result.writer_aliases_closed[index] =
            selected.writer_aliases_closed;
        result.sha256[index] = selected.sha256;
        result.complete_end_and_eof[index] =
            selected.complete_end_and_eof;
    }
    return result;
}

ProducerPartialC03ArchiveAuthority
ProducerPartialC03ArchiveAuthority::test_only_transport_roundtrip(
        TestOnlyTransportFault fault) && {
    auto transfer = std::move(*this).duplicate_for_runtime_transport();
    switch (fault) {
    case TestOnlyTransportFault::None:
        break;
    case TestOnlyTransportFault::MissingFd:
        close_fd(transfer.fds_[0]);
        break;
    case TestOnlyTransportFault::WritableFd:
        {
            std::array<char, 64> path{};
            const int count = std::snprintf(
                path.data(), path.size(), "/proc/self/fd/%d",
                transfer.fds_[0]);
            need(count > 0 &&
                 static_cast<std::size_t>(count) < path.size());
            const int writable = ::open(path.data(), O_RDWR | O_CLOEXEC);
            need(writable >= 0);
            close_fd(transfer.fds_[0]);
            transfer.fds_[0] = writable;
        }
        break;
    case TestOnlyTransportFault::DuplicateInode:
        close_fd(transfer.fds_[1]);
        transfer.fds_[1] = ::fcntl(
            transfer.fds_[0], F_DUPFD_CLOEXEC, 80);
        need(transfer.fds_[1] >= 80);
        transfer.devices_[1] = transfer.devices_[0];
        transfer.inodes_[1] = transfer.inodes_[0];
        transfer.sizes_[1] = transfer.sizes_[0];
        transfer.sha256_[1] = transfer.sha256_[0];
        break;
    case TestOnlyTransportFault::WrongSourceSlot:
        transfer.source_slots_[0] = 2;
        break;
    case TestOnlyTransportFault::WrongSize:
        ++transfer.sizes_[0];
        break;
    case TestOnlyTransportFault::WrongHash:
        transfer.sha256_[0][0] ^= 0xff;
        break;
    case TestOnlyTransportFault::FalseComplete:
        transfer.complete_end_and_eof_[0] = true;
        break;
    }
    return adopt_runtime_transport(std::move(transfer));
}

std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT>
ProducerSealedArchiveAuthority::test_only_duplicate_transport_fds() const {
    return duplicate_for_transport();
}

ProducerSealedArchiveAuthority
ProducerSealedArchiveAuthority::test_only_adopt_received(
        RunBinding binding, Digest closure_identity,
        std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT>&& fds,
        std::array<ProducerStreamClosureEvidence,
                   PRODUCER_ARCHIVE_STREAM_COUNT> evidence) {
    return adopt_received(
        std::move(binding), closure_identity, std::move(fds),
        std::move(evidence));
}

bool ProducerSealedArchiveAuthority::test_only_matches(
        const RunBinding& binding, const Digest& closure_identity,
        const std::array<ProducerStreamClosureEvidence,
                         PRODUCER_ARCHIVE_STREAM_COUNT>& evidence) const {
    if (storage_ == nullptr || storage_->binding != binding ||
        storage_->closure_identity != closure_identity)
        return false;
    for (unsigned slot = 0; slot < storage_->slots.size(); ++slot) {
        const auto& selected = storage_->slots[slot];
        if (selected.fd < 0 || selected.evidence != evidence[slot] ||
            (::fcntl(selected.fd, F_GETFL) & O_ACCMODE) != O_RDONLY)
            return false;
        struct stat value{};
        if (::fstat(selected.fd, &value) != 0 ||
            !S_ISREG(value.st_mode) || value.st_nlink != 0 ||
            (value.st_mode & 0777) != 0600)
            return false;
    }
    return true;
}

ProducerPartialC03ArchiveAuthority
ProducerSealedArchiveAuthority::test_only_duplicate_c03_for_runtime() const {
    return duplicate_c03_for_runtime();
}
#endif

} // namespace kpb::measurement::producer_archive
