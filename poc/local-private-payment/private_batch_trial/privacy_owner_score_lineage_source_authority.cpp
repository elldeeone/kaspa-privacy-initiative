#include "privacy_owner_score_lineage_source_authority.hpp"

#include "privacy_measurement_sha256.hpp"

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <limits>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <utility>

namespace kpb::measurement::score_output_lineage_source {
namespace {

[[noreturn]] void refuse() { throw std::runtime_error("lineage-refused"); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const SourceDigest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

std::uint16_t le16(std::span<const unsigned char> bytes, std::size_t at) {
    need(at + 2 <= bytes.size());
    return static_cast<std::uint16_t>(bytes[at]) |
        static_cast<std::uint16_t>(bytes[at + 1]) << 8;
}

std::uint32_t le32(std::span<const unsigned char> bytes, std::size_t at) {
    need(at + 4 <= bytes.size());
    std::uint32_t result{};
    for (unsigned index = 0; index < 4; ++index)
        result |= static_cast<std::uint32_t>(bytes[at + index]) <<
            (8 * index);
    return result;
}

std::uint64_t le64(std::span<const unsigned char> bytes, std::size_t at) {
    need(at + 8 <= bytes.size());
    std::uint64_t result{};
    for (unsigned index = 0; index < 8; ++index)
        result |= static_cast<std::uint64_t>(bytes[at + index]) <<
            (8 * index);
    return result;
}

SourceDigest digest_at(
        std::span<const unsigned char> bytes, std::size_t at) {
    need(at + 32 <= bytes.size());
    SourceDigest result{};
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(at), 32,
                result.begin());
    return result;
}

bool lower_hex(unsigned char value) {
    return (value >= '0' && value <= '9') ||
           (value >= 'a' && value <= 'f');
}

bool canonical_uuid(std::string_view value) {
    if (value.size() != 36) return false;
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (index == 8 || index == 13 || index == 18 || index == 23) {
            if (value[index] != '-') return false;
        } else if (!lower_hex(static_cast<unsigned char>(value[index]))) {
            return false;
        }
    }
    return true;
}

struct ParsedArchive final {
    SourceDigest method_sha256{};
    SourceDigest run_selection_sha256{};
    SourceDigest diagnostic_selection_sha256{};
    SourceDigest source_closure_sha256{};
    SourceDigest runtime_identity_sha256{};
    SourceDigest measurement_attempt_identity{};
    std::string trial_id;
    std::string attempt_id;
    OwnerScoreSourceClassification classification{
        OwnerScoreSourceClassification::HiddenCandidate};
    std::uint64_t run_selection_bytes{};
    SourceDigest archive_sha256{};
};
static_assert(std::is_nothrow_move_assignable_v<ParsedArchive>);

ParsedArchive parse_archive(
        std::span<const unsigned char> bytes) {
    need(bytes.size() > OWNER_SCORE_LINEAGE_ARCHIVE_HEADER_BYTES);
    need(std::equal(OWNER_SCORE_LINEAGE_ARCHIVE_MAGIC.begin(),
                    OWNER_SCORE_LINEAGE_ARCHIVE_MAGIC.end(), bytes.begin()));
    need(le32(bytes, 8) == OWNER_SCORE_LINEAGE_ARCHIVE_VERSION);
    need(le32(bytes, 12) == OWNER_SCORE_LINEAGE_ARCHIVE_HEADER_BYTES);
    need(le64(bytes, 16) == bytes.size());

    ParsedArchive result;
    result.method_sha256 = digest_at(bytes, 24);
    result.run_selection_sha256 = digest_at(bytes, 56);
    result.diagnostic_selection_sha256 = digest_at(bytes, 88);
    result.source_closure_sha256 = digest_at(bytes, 120);
    result.runtime_identity_sha256 = digest_at(bytes, 152);
    result.measurement_attempt_identity = digest_at(bytes, 232);
    need(nonzero(result.method_sha256) &&
         nonzero(result.run_selection_sha256) &&
         nonzero(result.diagnostic_selection_sha256) &&
         nonzero(result.source_closure_sha256) &&
         nonzero(result.runtime_identity_sha256) &&
         nonzero(result.measurement_attempt_identity));
    result.trial_id.assign(
        reinterpret_cast<const char*>(bytes.data() + 184), 36);
    need(canonical_uuid(result.trial_id));
    const auto raw_classification = bytes[220];
    need(raw_classification == static_cast<unsigned char>(
             OwnerScoreSourceClassification::HiddenCandidate) ||
         raw_classification == static_cast<unsigned char>(
             OwnerScoreSourceClassification::TransparentBaseline));
    result.classification =
        static_cast<OwnerScoreSourceClassification>(raw_classification);
    need(bytes[221] == 1);
    const auto attempt_bytes = le16(bytes, 222);
    need(attempt_bytes >= 1 && attempt_bytes <= 128);
    result.run_selection_bytes = le64(bytes, 224);
    need(result.run_selection_bytes > 0 &&
         result.run_selection_bytes <=
            std::numeric_limits<std::size_t>::max() &&
         OWNER_SCORE_LINEAGE_ARCHIVE_HEADER_BYTES +
            static_cast<std::size_t>(result.run_selection_bytes) ==
            bytes.size());
    result.attempt_id.assign(
        reinterpret_cast<const char*>(bytes.data() + 264), attempt_bytes);
    need(canonical_outer_attempt_ascii(result.attempt_id) &&
         measurement_attempt_from_outer_ascii(result.attempt_id) ==
             result.measurement_attempt_identity);
    need(std::all_of(bytes.begin() + 264 + attempt_bytes,
                     bytes.begin() + 416,
                     [](unsigned char byte) { return byte == 0; }));
    const auto run = bytes.subspan(OWNER_SCORE_LINEAGE_ARCHIVE_HEADER_BYTES);
    need(detail::sha256(run) == result.run_selection_sha256);
    result.archive_sha256 = detail::sha256(bytes);
    return result;
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

std::vector<unsigned char> exact_read(int fd, std::size_t size) {
    std::vector<unsigned char> result(size);
    std::size_t offset = 0;
    while (offset < size) {
        const auto read = ::pread(fd, result.data() + offset,
                                  size - offset,
                                  static_cast<off_t>(offset));
        if (read < 0 && errno == EINTR) continue;
        need(read > 0);
        offset += static_cast<std::size_t>(read);
    }
    return result;
}

#ifdef KPB_OWNER_SCORE_LINEAGE_SOURCE_TEST_SETUP

void exact_write(int fd, std::span<const unsigned char> bytes) {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto wrote = ::write(fd, bytes.data() + offset,
                                   bytes.size() - offset);
        if (wrote < 0 && errno == EINTR) continue;
        need(wrote > 0);
        offset += static_cast<std::size_t>(wrote);
    }
}

void require_expected(
        const ParsedArchive& parsed,
        const TestOnlyPrivacyLaunchLineageExpected& expected) {
    need(parsed.method_sha256 == expected.method_sha256 &&
         parsed.run_selection_sha256 == expected.run_selection_sha256 &&
         parsed.diagnostic_selection_sha256 ==
            expected.diagnostic_selection_sha256 &&
         parsed.source_closure_sha256 == expected.source_closure_sha256 &&
         parsed.runtime_identity_sha256 ==
            expected.runtime_identity_sha256 &&
         parsed.measurement_attempt_identity ==
            expected.measurement_attempt_identity &&
         parsed.trial_id == expected.trial_id &&
         parsed.attempt_id == expected.attempt_id &&
         parsed.classification == expected.classification);
}
#endif

} // namespace

struct AuthenticatedPrivacyLaunchLineageSourceAuthority::Storage final {
    int archive_fd{-1};
    std::uint64_t archive_device{};
    std::uint64_t archive_inode{};
    ParsedArchive parsed;
    SourceDigest registered_prelaunch_identity{};
    SourceDigest measurement_attempt_identity{};
    SourceDigest receiver_session_identity{};
    SourceDigest receiver_process_identity{};
    SourceDigest receiver_exit_identity{};
    ~Storage() { if (archive_fd >= 0) ::close(archive_fd); }
};

struct SelectedOwnerScoreLineageSourceTransferAuthority::Storage final {
    int archive_fd{-1};
    std::uint64_t archive_device{};
    std::uint64_t archive_inode{};
    ParsedArchive parsed;
    SourceDigest registered_prelaunch_identity{};
    SourceDigest measurement_attempt_identity{};
    SourceDigest receiver_session_identity{};
    SourceDigest receiver_process_identity{};
    SourceDigest receiver_exit_identity{};
    ~Storage() { if (archive_fd >= 0) ::close(archive_fd); }
};

AuthenticatedPrivacyLaunchLineageSourceAuthority::
AuthenticatedPrivacyLaunchLineageSourceAuthority(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {}
AuthenticatedPrivacyLaunchLineageSourceAuthority::
AuthenticatedPrivacyLaunchLineageSourceAuthority(
        AuthenticatedPrivacyLaunchLineageSourceAuthority&&) noexcept = default;
AuthenticatedPrivacyLaunchLineageSourceAuthority::
~AuthenticatedPrivacyLaunchLineageSourceAuthority() = default;

AuthenticatedPrivacyLaunchLineageSourceAuthority
AuthenticatedPrivacyLaunchLineageSourceAuthority::adopt_received_archive(
        int supplied_fd, ReceiverExpectation expected) {
    OwnedFd reader(supplied_fd);
    need(reader.get() >= 0);
    const auto flags = ::fcntl(reader.get(), F_GETFL);
    const auto descriptor_flags = ::fcntl(reader.get(), F_GETFD);
    const auto seals = ::fcntl(reader.get(), F_GET_SEALS);
    struct stat info{};
    need(flags >= 0 && (flags & O_ACCMODE) == O_RDONLY &&
         descriptor_flags >= 0 && (descriptor_flags & FD_CLOEXEC) != 0 &&
         seals >= 0 &&
         (seals & (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK |
                   F_SEAL_SEAL)) ==
            (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) &&
         ::fstat(reader.get(), &info) == 0 && S_ISREG(info.st_mode) &&
         (info.st_mode & 0777) == 0400 && info.st_nlink == 0 &&
         info.st_size > 0 &&
         static_cast<std::uint64_t>(info.st_size) <=
            std::numeric_limits<std::size_t>::max());
    const auto bytes = exact_read(
        reader.get(), static_cast<std::size_t>(info.st_size));
    auto parsed = parse_archive(bytes);
    need(parsed.archive_sha256 == expected.exact_archive_sha256 &&
         parsed.method_sha256 == expected.method_sha256 &&
         parsed.run_selection_sha256 == expected.run_selection_sha256 &&
         parsed.diagnostic_selection_sha256 ==
            expected.diagnostic_selection_sha256 &&
         parsed.source_closure_sha256 == expected.source_closure_sha256 &&
         parsed.runtime_identity_sha256 ==
            expected.runtime_identity_sha256 &&
         parsed.measurement_attempt_identity ==
            expected.measurement_attempt_identity &&
         parsed.trial_id == expected.trial_id &&
         parsed.classification == expected.classification &&
         nonzero(expected.registered_prelaunch_identity) &&
         nonzero(expected.measurement_attempt_identity) &&
         nonzero(expected.receiver_session_identity) &&
         nonzero(expected.receiver_process_identity) &&
         nonzero(expected.receiver_exit_identity));
    struct stat after{};
    need(::fstat(reader.get(), &after) == 0 &&
         after.st_dev == info.st_dev && after.st_ino == info.st_ino &&
         after.st_size == info.st_size && after.st_mode == info.st_mode &&
         after.st_nlink == info.st_nlink);
    auto storage = std::make_unique<Storage>();
    storage->archive_fd = reader.release();
    storage->archive_device = static_cast<std::uint64_t>(info.st_dev);
    storage->archive_inode = static_cast<std::uint64_t>(info.st_ino);
    storage->parsed = std::move(parsed);
    storage->registered_prelaunch_identity =
        expected.registered_prelaunch_identity;
    storage->measurement_attempt_identity =
        expected.measurement_attempt_identity;
    storage->receiver_session_identity = expected.receiver_session_identity;
    storage->receiver_process_identity = expected.receiver_process_identity;
    storage->receiver_exit_identity = expected.receiver_exit_identity;
    return AuthenticatedPrivacyLaunchLineageSourceAuthority(
        std::move(storage));
}

SelectedOwnerScoreLineageSourceTransferAuthority::
SelectedOwnerScoreLineageSourceTransferAuthority(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {}
SelectedOwnerScoreLineageSourceTransferAuthority::
SelectedOwnerScoreLineageSourceTransferAuthority(
        SelectedOwnerScoreLineageSourceTransferAuthority&&) noexcept = default;
SelectedOwnerScoreLineageSourceTransferAuthority::
~SelectedOwnerScoreLineageSourceTransferAuthority() = default;

SelectedOwnerScoreLineageSourceTransferAuthority
SelectedOwnerScoreLineageAdmissionBridge::admit(
        AuthenticatedPrivacyLaunchLineageSourceAuthority&& supplied) {
    auto output = std::make_unique<
        SelectedOwnerScoreLineageSourceTransferAuthority::Storage>();
    need(supplied.storage_ != nullptr);
    auto input = std::move(supplied.storage_);
    output->archive_fd = std::exchange(input->archive_fd, -1);
    output->archive_device = input->archive_device;
    output->archive_inode = input->archive_inode;
    output->parsed = std::move(input->parsed);
    output->registered_prelaunch_identity =
        input->registered_prelaunch_identity;
    output->measurement_attempt_identity =
        input->measurement_attempt_identity;
    output->receiver_session_identity = input->receiver_session_identity;
    output->receiver_process_identity = input->receiver_process_identity;
    output->receiver_exit_identity = input->receiver_exit_identity;
    return SelectedOwnerScoreLineageSourceTransferAuthority(
        std::move(output));
}

RegisteredOwnerScorePrelaunchResidualAuthority::
RegisteredOwnerScorePrelaunchResidualAuthority(
        void* storage, void (*destroy)(void*) noexcept) noexcept
    : storage_(storage), destroy_storage_(destroy) {}
RegisteredOwnerScorePrelaunchResidualAuthority::
RegisteredOwnerScorePrelaunchResidualAuthority(
        RegisteredOwnerScorePrelaunchResidualAuthority&& other) noexcept
    : storage_(std::exchange(other.storage_, nullptr)),
      destroy_storage_(std::exchange(other.destroy_storage_, nullptr)) {}
RegisteredOwnerScorePrelaunchResidualAuthority::
~RegisteredOwnerScorePrelaunchResidualAuthority() {
    if (storage_ != nullptr && destroy_storage_ != nullptr)
        destroy_storage_(storage_);
}

RegisteredOwnerScoreTrialResidualAuthority::
RegisteredOwnerScoreTrialResidualAuthority(
        void* storage, void (*destroy)(void*) noexcept) noexcept
    : storage_(storage), destroy_storage_(destroy) {}
RegisteredOwnerScoreTrialResidualAuthority::
RegisteredOwnerScoreTrialResidualAuthority(
        RegisteredOwnerScoreTrialResidualAuthority&& other) noexcept
    : storage_(std::exchange(other.storage_, nullptr)),
      destroy_storage_(std::exchange(other.destroy_storage_, nullptr)) {}
RegisteredOwnerScoreTrialResidualAuthority::
~RegisteredOwnerScoreTrialResidualAuthority() {
    if (storage_ != nullptr && destroy_storage_ != nullptr)
        destroy_storage_(storage_);
}

#ifdef KPB_OWNER_SCORE_LINEAGE_SOURCE_TEST_SETUP
AuthenticatedPrivacyLaunchLineageSourceAuthority
AuthenticatedPrivacyLaunchLineageSourceAuthority::test_only_mint(
        const std::vector<unsigned char>& archive,
        const TestOnlyPrivacyLaunchLineageExpected& expected,
        TestOnlyPrivacyLaunchSourceFault fault) {
    OwnedFd writer(::memfd_create(
        "kpb-owner-score-lineage-source", MFD_CLOEXEC | MFD_ALLOW_SEALING));
    need(writer.get() >= 0);
    exact_write(writer.get(), archive);
    need(::fchmod(writer.get(), 0400) == 0);
    if (fault != TestOnlyPrivacyLaunchSourceFault::MissingSeals) {
        need(::fcntl(writer.get(), F_ADD_SEALS,
                     F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK |
                     F_SEAL_SEAL) == 0);
    }
    OwnedFd reader;
    if (fault == TestOnlyPrivacyLaunchSourceFault::WritableDescriptor) {
        reader = OwnedFd(writer.release());
    } else {
        const auto path = std::string("/proc/self/fd/") +
            std::to_string(writer.get());
        reader = OwnedFd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
        need(reader.get() >= 0);
    }
    const auto flags = ::fcntl(reader.get(), F_GETFL);
    const auto descriptor_flags = ::fcntl(reader.get(), F_GETFD);
    const auto seals = ::fcntl(reader.get(), F_GET_SEALS);
    struct stat info{};
    need(flags >= 0 && (flags & O_ACCMODE) == O_RDONLY &&
         descriptor_flags >= 0 && (descriptor_flags & FD_CLOEXEC) != 0 &&
         seals >= 0 &&
         (seals & (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK |
                   F_SEAL_SEAL)) ==
            (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) &&
         ::fstat(reader.get(), &info) == 0 && S_ISREG(info.st_mode) &&
         (info.st_mode & 0777) == 0400 && info.st_nlink == 0 &&
         info.st_size > 0);
    const auto bytes = exact_read(
        reader.get(), static_cast<std::size_t>(info.st_size));
    auto parsed = parse_archive(bytes);
    require_expected(parsed, expected);
    struct stat after{};
    need(::fstat(reader.get(), &after) == 0 &&
         after.st_dev == info.st_dev && after.st_ino == info.st_ino &&
         after.st_size == info.st_size && after.st_mode == info.st_mode &&
         after.st_nlink == info.st_nlink);
    writer = OwnedFd();
    auto storage = std::make_unique<Storage>();
    storage->archive_fd = reader.release();
    storage->archive_device = static_cast<std::uint64_t>(info.st_dev);
    storage->archive_inode = static_cast<std::uint64_t>(info.st_ino);
    storage->parsed = std::move(parsed);
    return AuthenticatedPrivacyLaunchLineageSourceAuthority(
        std::move(storage));
}

SelectedOwnerScoreLineageSourceTransferAuthority
SelectedOwnerScoreLineageAdmissionBridge::test_only_admit(
        AuthenticatedPrivacyLaunchLineageSourceAuthority&& supplied,
        TestOnlyLineageAdmissionFault fault) {
    if (fault == TestOnlyLineageAdmissionFault::AllocationBeforeClaim)
        throw std::bad_alloc();
    return admit(std::move(supplied));
}

TestOnlyOwnerScoreLineageSummary
SelectedOwnerScoreLineageAdmissionBridge::test_only_consume(
        SelectedOwnerScoreLineageSourceTransferAuthority&& supplied) {
    need(supplied.storage_ != nullptr);
    auto storage = std::move(supplied.storage_);
    return TestOnlyOwnerScoreLineageSummary{
        .method_sha256 = storage->parsed.method_sha256,
        .run_selection_sha256 = storage->parsed.run_selection_sha256,
        .diagnostic_selection_sha256 =
            storage->parsed.diagnostic_selection_sha256,
        .source_closure_sha256 = storage->parsed.source_closure_sha256,
        .runtime_identity_sha256 = storage->parsed.runtime_identity_sha256,
        .measurement_attempt_identity =
            storage->parsed.measurement_attempt_identity,
        .trial_id = storage->parsed.trial_id,
        .attempt_id = storage->parsed.attempt_id,
        .classification = storage->parsed.classification,
        .run_selection_bytes = storage->parsed.run_selection_bytes,
        .archive_device = storage->archive_device,
        .archive_inode = storage->archive_inode,
    };
}

SourceDigest test_only_digest(std::string_view value) {
    return detail::sha256(std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
}
#endif

} // namespace kpb::measurement::score_output_lineage_source
