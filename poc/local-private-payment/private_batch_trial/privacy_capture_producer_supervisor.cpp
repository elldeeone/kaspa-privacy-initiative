#include "privacy_capture_producer_supervisor.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <set>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace kpb::measurement::producer_supervisor {
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

void validate_binding(const RunBinding& value) {
    need(nonzero(value.capture) && nonzero(value.run_selection) &&
         nonzero(value.finite_manifest.manifest_identity) &&
         nonzero(value.round_capture_plans[0]) &&
         nonzero(value.round_capture_plans[1]) &&
         value.round_capture_plans[0] != value.round_capture_plans[1]);
}

std::set<std::string> directory_names(int fd) {
    const int duplicate = ::fcntl(fd, F_DUPFD_CLOEXEC, 0);
    need(duplicate >= 0);
    DIR* directory = ::fdopendir(duplicate);
    if (directory == nullptr) {
        int copy = duplicate;
        close_fd(copy);
        refuse();
    }
    std::set<std::string> result;
    errno = 0;
    while (auto* entry = ::readdir(directory)) {
        const std::string name(entry->d_name);
        if (name != "." && name != "..")
            need(result.insert(name).second);
        errno = 0;
    }
    const int saved = errno;
    need(::closedir(directory) == 0 && saved == 0);
    return result;
}

struct FileEvidence {
    std::uint64_t device{};
    std::uint64_t inode{};
    std::uint64_t size{};
    std::uint32_t mode{};
    std::uint32_t uid{};
    std::uint32_t link_count{};
};

FileEvidence regular_leaf(int directory_fd, const char* name) {
    struct stat before{};
    need(::fstatat(directory_fd, name, &before, AT_SYMLINK_NOFOLLOW) == 0 &&
         S_ISREG(before.st_mode) && before.st_uid == ::geteuid() &&
         (before.st_mode & 0777) == 0400 && before.st_nlink == 1 &&
         before.st_size > 0 && before.st_dev != 0 && before.st_ino != 0);
    int fd = ::openat(directory_fd, name,
                      O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    need(fd >= 0);
    struct stat after{};
    const bool valid = (::fstat(fd, &after) == 0 &&
                        before.st_dev == after.st_dev &&
                        before.st_ino == after.st_ino &&
                        before.st_mode == after.st_mode &&
                        before.st_uid == after.st_uid &&
                        before.st_nlink == after.st_nlink &&
                        before.st_size == after.st_size);
    close_fd(fd);
    need(valid);
    return {
        .device = static_cast<std::uint64_t>(before.st_dev),
        .inode = static_cast<std::uint64_t>(before.st_ino),
        .size = static_cast<std::uint64_t>(before.st_size),
        .mode = static_cast<std::uint32_t>(before.st_mode),
        .uid = static_cast<std::uint32_t>(before.st_uid),
        .link_count = static_cast<std::uint32_t>(before.st_nlink),
    };
}

int private_round_directory(int root_fd, const char* name) {
    int fd = ::openat(root_fd, name,
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    need(fd >= 0);
    struct stat value{};
    if (::fstat(fd, &value) != 0 || !S_ISDIR(value.st_mode) ||
        value.st_uid != ::geteuid() || (value.st_mode & 0777) != 0700) {
        close_fd(fd);
        refuse();
    }
    return fd;
}

void validate_private_closure(
        const ProducerClosureEvidence& value,
        const Digest& opaque_closure_authority_identity) {
    need(value.opaque_closure_authority_identity ==
             opaque_closure_authority_identity &&
         nonzero(value.producer_child_exit) &&
         nonzero(value.producer_receipt) &&
         nonzero(value.producer_identity));
    for (const auto& stream : value.streams)
        need(nonzero(stream.record_root) &&
             nonzero(stream.end_frame_identity) &&
             nonzero(stream.eof_identity) && stream.record_count > 0 &&
             stream.payload_bytes > 0 && stream.raw_wire_bytes > 0);
}

} // namespace

ProducerSpoolAuthority::ProducerSpoolAuthority(
        RunBinding binding, Digest opaque_closure_authority_identity,
        Digest spool_identity, Digest producer_process_identity,
        Digest writer_alias_closure_identity,
        Digest path_alias_closure_identity,
        ProducerClosureEvidence producer_closure_evidence, int directory_fd)
    : binding_(std::move(binding)),
      opaque_closure_authority_identity_(opaque_closure_authority_identity),
      spool_identity_(spool_identity),
      producer_process_identity_(producer_process_identity),
      writer_alias_closure_identity_(writer_alias_closure_identity),
      path_alias_closure_identity_(path_alias_closure_identity),
      producer_closure_evidence_(std::move(producer_closure_evidence)),
      directory_fd_(directory_fd) {
    try {
        struct stat status{};
        const int flags = ::fcntl(directory_fd_, F_GETFL);
        const int descriptor_flags = ::fcntl(directory_fd_, F_GETFD);
        need(directory_fd_ >= 0 && flags >= 0 && descriptor_flags >= 0 &&
             (flags & O_ACCMODE) == O_RDONLY && (flags & O_PATH) == 0 &&
             (descriptor_flags & FD_CLOEXEC) != 0 &&
             ::fstat(directory_fd_, &status) == 0 &&
             S_ISDIR(status.st_mode) && status.st_uid == ::geteuid() &&
             (status.st_mode & 0777) == 0700 &&
             nonzero(opaque_closure_authority_identity_) &&
             nonzero(spool_identity_) &&
             nonzero(producer_process_identity_) &&
             nonzero(writer_alias_closure_identity_) &&
             nonzero(path_alias_closure_identity_) &&
             writer_alias_closure_identity_ != path_alias_closure_identity_);
        validate_binding(binding_);
        validate_private_closure(producer_closure_evidence_,
                                 opaque_closure_authority_identity_);
        device_ = static_cast<std::uint64_t>(status.st_dev);
        inode_ = static_cast<std::uint64_t>(status.st_ino);
        need(device_ != 0 && inode_ != 0);

        need(directory_names(directory_fd_) ==
             std::set<std::string>{"PRODUCER.json", "round-1", "round-2"});
        const auto receipt = regular_leaf(directory_fd_, "PRODUCER.json");
        producer_receipt_leaf_ = {
            .round = 0, .kind = CaptureKind::PublicProjection,
            .fixed_fd = 0, .device = receipt.device,
            .inode = receipt.inode, .size = receipt.size,
            .mode = receipt.mode, .uid = receipt.uid,
            .link_count = receipt.link_count,
        };
        std::set<std::pair<std::uint64_t, std::uint64_t>> identities;
        need(identities.emplace(receipt.device, receipt.inode).second);
        constexpr std::array<const char*, 5> filenames{
            "projection.bin", "terminal.json", "dispatcher.json",
            "corrupt-server.json", "colluder-wallet.json",
        };
        const std::set<std::string> expected_names{
            filenames.begin(), filenames.end()};
        for (unsigned round = 1; round <= 2; ++round) {
            const char* round_name = round == 1 ? "round-1" : "round-2";
            int round_fd = private_round_directory(directory_fd_, round_name);
            try {
                need(directory_names(round_fd) == expected_names);
                for (unsigned kind = 0; kind < filenames.size(); ++kind) {
                    const auto evidence = regular_leaf(
                        round_fd, filenames[kind]);
                    need(identities.emplace(
                        evidence.device, evidence.inode).second);
                    const unsigned index = (round - 1) * 5 + kind;
                    leaves_[index] = {
                        .round = round,
                        .kind = static_cast<CaptureKind>(kind + 1),
                        .fixed_fd = 20 + index,
                        .device = evidence.device,
                        .inode = evidence.inode,
                        .size = evidence.size,
                        .mode = evidence.mode,
                        .uid = evidence.uid,
                        .link_count = evidence.link_count,
                    };
                }
            } catch (...) {
                close_fd(round_fd);
                throw;
            }
            close_fd(round_fd);
        }
        need(identities.size() == 11);
    } catch (...) {
        close_fd(directory_fd_);
        throw;
    }
}

ProducerSpoolAuthority::ProducerSpoolAuthority(
        ProducerSpoolAuthority&& other) noexcept
    : binding_(std::move(other.binding_)),
      opaque_closure_authority_identity_(
          other.opaque_closure_authority_identity_),
      spool_identity_(other.spool_identity_),
      producer_process_identity_(other.producer_process_identity_),
      writer_alias_closure_identity_(other.writer_alias_closure_identity_),
      path_alias_closure_identity_(other.path_alias_closure_identity_),
      producer_closure_evidence_(other.producer_closure_evidence_),
      leaves_(other.leaves_),
      producer_receipt_leaf_(other.producer_receipt_leaf_),
      device_(other.device_), inode_(other.inode_),
      directory_fd_(other.directory_fd_),
      live_(other.live_.exchange(false)) {
    other.directory_fd_ = -1;
}

ProducerSpoolAuthority::~ProducerSpoolAuthority() {
    close_fd(directory_fd_);
}

#ifdef KPB_CAPTURE_PRODUCER_SUPERVISOR_TEST_SETUP
ProducerSpoolAuthority ProducerSpoolAuthority::test_only_mint(
        RunBinding binding, Digest opaque_closure_authority_identity,
        Digest spool_identity, Digest producer_process_identity,
        Digest writer_alias_closure_identity,
        Digest path_alias_closure_identity,
        ProducerClosureEvidence producer_closure_evidence,
        int directory_fd) {
    return ProducerSpoolAuthority(
        std::move(binding), opaque_closure_authority_identity, spool_identity,
        producer_process_identity, writer_alias_closure_identity,
        path_alias_closure_identity, std::move(producer_closure_evidence),
        directory_fd);
}

bool ProducerSpoolAuthority::test_only_matches(
        const RunBinding& binding,
        const Digest& opaque_closure_authority_identity,
        const Digest& spool_identity,
        const Digest& producer_process_identity,
        const ProducerClosureEvidence& producer_closure_evidence) const {
    return live_.load() && binding_ == binding &&
           opaque_closure_authority_identity_ ==
               opaque_closure_authority_identity &&
           spool_identity_ == spool_identity &&
           producer_process_identity_ == producer_process_identity &&
           producer_closure_evidence_ == producer_closure_evidence &&
           directory_fd_ >= 0;
}

int ProducerSpoolAuthority::test_only_take_directory() {
    need(live_.exchange(false) && directory_fd_ >= 0);
    const int result = directory_fd_;
    directory_fd_ = -1;
    return result;
}
#endif

C03RoleLaunchAdmissionAuthority::C03RoleLaunchAdmissionAuthority(
        RunBinding binding, Digest opaque_closure_authority_identity,
        Digest producer_process_identity,
        Digest producer_child_exit_identity,
        Digest producer_receipt_identity,
        std::array<C03RoleLaunchRoundBinding, 2> rounds)
    : binding_(std::move(binding)),
      opaque_closure_authority_identity_(opaque_closure_authority_identity),
      producer_process_identity_(producer_process_identity),
      producer_child_exit_identity_(producer_child_exit_identity),
      producer_receipt_identity_(producer_receipt_identity),
      rounds_(std::move(rounds)) {
    validate_binding(binding_);
    need(nonzero(opaque_closure_authority_identity_) &&
         nonzero(producer_process_identity_) &&
         nonzero(producer_child_exit_identity_) &&
         nonzero(producer_receipt_identity_));
    for (unsigned index = 0; index < rounds_.size(); ++index) {
        const auto& round = rounds_[index];
        need(round.round == index + 1 && round.fixed_fd == 23 + 5 * index &&
             round.financial_run == binding_.financial_runs[index] &&
             round.attempt == binding_.round_attempts[index] &&
             round.cohort == binding_.round_cohorts[index] &&
             round.capture_plan == binding_.round_capture_plans[index] &&
             round.projection == binding_.projections[index]);
        for (const auto* identity : {
                 &round.financial_run, &round.attempt, &round.cohort,
                 &round.capture_plan, &round.projection,
                 &round.source_identity, &round.build_identity,
                 &round.runtime_identity, &round.launcher_identity,
                 &round.process_identity, &round.child_exit_identity,
                 &round.model_preimage_identity,
                 &round.query_store_preimage_identity,
                 &round.scalar_capture_manifest_identity})
            need(nonzero(*identity));
    }
    need(rounds_[0].process_identity != rounds_[1].process_identity &&
         rounds_[0].child_exit_identity != rounds_[1].child_exit_identity);
}

C03RoleLaunchAdmissionAuthority::C03RoleLaunchAdmissionAuthority(
        C03RoleLaunchAdmissionAuthority&& other) noexcept
    : binding_(std::move(other.binding_)),
      opaque_closure_authority_identity_(
          other.opaque_closure_authority_identity_),
      producer_process_identity_(other.producer_process_identity_),
      producer_child_exit_identity_(other.producer_child_exit_identity_),
      producer_receipt_identity_(other.producer_receipt_identity_),
      rounds_(other.rounds_), live_(other.live_.exchange(false)) {}

#ifdef KPB_CAPTURE_PRODUCER_SUPERVISOR_TEST_SETUP
C03RoleLaunchAdmissionAuthority
C03RoleLaunchAdmissionAuthority::test_only_mint(
        RunBinding binding, Digest opaque_closure_authority_identity,
        Digest producer_process_identity,
        Digest producer_child_exit_identity,
        Digest producer_receipt_identity,
        std::array<C03RoleLaunchRoundBinding, 2> rounds) {
    return C03RoleLaunchAdmissionAuthority(
        std::move(binding), opaque_closure_authority_identity,
        producer_process_identity, producer_child_exit_identity,
        producer_receipt_identity, std::move(rounds));
}

bool C03RoleLaunchAdmissionAuthority::test_only_matches(
        const RunBinding& binding,
        const Digest& opaque_closure_authority_identity,
        const Digest& producer_process_identity,
        const Digest& producer_child_exit_identity,
        const Digest& producer_receipt_identity,
        const std::array<C03RoleLaunchRoundBinding, 2>& rounds) const {
    return live_.load() && binding_ == binding &&
           opaque_closure_authority_identity_ ==
               opaque_closure_authority_identity &&
           producer_process_identity_ == producer_process_identity &&
           producer_child_exit_identity_ == producer_child_exit_identity &&
           producer_receipt_identity_ == producer_receipt_identity &&
           rounds_ == rounds;
}

void C03RoleLaunchAdmissionAuthority::test_only_consume() {
    need(live_.exchange(false));
}
#endif

} // namespace kpb::measurement::producer_supervisor
