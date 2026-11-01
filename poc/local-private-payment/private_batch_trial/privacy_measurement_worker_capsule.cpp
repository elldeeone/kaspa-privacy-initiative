#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "privacy_measurement_worker_capsule.hpp"
#include "privacy_measurement_sha256.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <limits>
#include <set>
#include <span>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpb::measurement::runtime_bridge {
namespace {

using Bytes = std::vector<unsigned char>;

constexpr std::array<unsigned char, 8> SOURCE_MAGIC{
    'K', 'P', 'B', 'S', 'R', 'C', '1', 0};
constexpr std::array<unsigned char, 8> ASSET_MAGIC{
    'K', 'P', 'B', 'A', 'S', 'T', '1', 0};

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}

void add(Bytes& out, const char* value) {
    while (*value) out.push_back(static_cast<unsigned char>(*value++));
}

void integer(Bytes& out, std::uint64_t value, unsigned width = 8) {
    for (unsigned offset = 0; offset < width; ++offset)
        out.push_back(static_cast<unsigned char>(value >> (8 * offset)));
}

Digest hash(std::span<const unsigned char> value) {
    return detail::sha256(value);
}

void add_worker(Bytes& out, const WorkerBinding& worker) {
    for (const auto* value : {
             &worker.source_identity, &worker.build_identity,
             &worker.runtime_identity, &worker.assets_identity,
             &worker.pinned_executable_identity,
             &worker.launcher_identity})
        add(out, *value);
}

void valid_role_owner(RuntimeChildRole role, unsigned owner) {
    need(role == RuntimeChildRole::Observer ||
         role == RuntimeChildRole::OwnerScore ||
         role == RuntimeChildRole::Aggregate ||
         role == RuntimeChildRole::OwnerComparison);
    if (role == RuntimeChildRole::OwnerScore)
        need(owner < 3);
    else
        need(owner == NO_OWNER);
}

void valid_lineage(
        const PublicMeasurementInputEndpoint::PublicLineage& lineage) {
    need(lineage.classification == Classification::TransparentBaseline ||
         lineage.classification == Classification::HiddenCandidate);
    for (const auto* value : {
             &lineage.trial,
             &lineage.capture_plan_identities[0],
             &lineage.capture_plan_identities[1],
             &lineage.financial_runs[0], &lineage.financial_runs[1],
             &lineage.round_attempts[0], &lineage.round_attempts[1],
             &lineage.round_cohorts[0], &lineage.round_cohorts[1],
             &lineage.projections[0], &lineage.projections[1]})
        need(nonzero(*value));
    need(lineage.capture_plan_identities[0] !=
             lineage.capture_plan_identities[1] &&
         lineage.financial_runs[0] != lineage.financial_runs[1] &&
         lineage.round_attempts[0] != lineage.round_attempts[1] &&
         lineage.round_cohorts[0] != lineage.round_cohorts[1] &&
         lineage.projections[0] != lineage.projections[1]);
}

int endpoint_fd(MeasurementInputKind kind, unsigned owner) {
    switch (kind) {
    case MeasurementInputKind::ObserverCapture:
        need(owner == NO_OWNER);
        return MEASUREMENT_OBSERVER_INPUT_FD;
    case MeasurementInputKind::ScoreObservation:
        need(owner == NO_OWNER);
        return MEASUREMENT_SCORE_OBSERVATION_FD;
    case MeasurementInputKind::OwnerTruth:
        need(owner < 3);
        return MEASUREMENT_SCORE_OWNER_TRUTH_FD;
    case MeasurementInputKind::AggregateOwnerScore:
        need(owner < 3);
        return MEASUREMENT_AGGREGATE_OWNER0_FD + static_cast<int>(owner);
    case MeasurementInputKind::ComparisonBaselineOwnerScore:
        need(owner < 3);
        return MEASUREMENT_COMPARISON_BASELINE0_FD +
               static_cast<int>(owner);
    case MeasurementInputKind::ComparisonCandidateOwnerScore:
        need(owner < 3);
        return MEASUREMENT_COMPARISON_CANDIDATE0_FD +
               static_cast<int>(owner);
    }
    refuse();
}

std::vector<PublicMeasurementInputEndpoint> expected_inputs(
        RuntimeChildRole role, unsigned owner, bool schema_only) {
    valid_role_owner(role, owner);
    std::vector<PublicMeasurementInputEndpoint> result;
    const auto add_endpoint = [&](MeasurementInputKind kind,
                                  unsigned endpoint_owner) {
        const unsigned actual_owner =
            schema_only && kind == MeasurementInputKind::OwnerTruth
                ? 0 : endpoint_owner;
        result.push_back(PublicMeasurementInputEndpoint{
            .kind = kind,
            .owner = actual_owner,
            .fixed_fd = endpoint_fd(kind, actual_owner),
            .identity = {},
            .lineage = {},
        });
    };
    switch (role) {
    case RuntimeChildRole::Observer:
        add_endpoint(MeasurementInputKind::ObserverCapture, NO_OWNER);
        break;
    case RuntimeChildRole::OwnerScore:
        add_endpoint(MeasurementInputKind::ScoreObservation, NO_OWNER);
        add_endpoint(MeasurementInputKind::OwnerTruth, owner);
        break;
    case RuntimeChildRole::Aggregate:
        for (unsigned index = 0; index < 3; ++index)
            add_endpoint(MeasurementInputKind::AggregateOwnerScore, index);
        break;
    case RuntimeChildRole::OwnerComparison:
        for (unsigned index = 0; index < 3; ++index)
            add_endpoint(
                MeasurementInputKind::ComparisonBaselineOwnerScore, index);
        for (unsigned index = 0; index < 3; ++index)
            add_endpoint(
                MeasurementInputKind::ComparisonCandidateOwnerScore, index);
        break;
    }
    return result;
}

void valid_role_lineage(const PublicMeasurementWorkerCapsule& capsule) {
    const auto& inputs = capsule.inputs;
    switch (capsule.role) {
    case RuntimeChildRole::Observer:
        need(capsule.input_count == 1 &&
             !nonzero(inputs[0].lineage.barrier));
        break;
    case RuntimeChildRole::OwnerScore:
        need(capsule.input_count == 2 &&
             nonzero(inputs[0].lineage.barrier) &&
             inputs[0].lineage == inputs[1].lineage &&
             inputs[1].kind == MeasurementInputKind::OwnerTruth &&
             inputs[1].owner == capsule.owner);
        break;
    case RuntimeChildRole::Aggregate:
        need(capsule.input_count == 3 &&
             nonzero(inputs[0].lineage.barrier));
        for (unsigned index = 1; index < 3; ++index)
            need(inputs[index].lineage == inputs[0].lineage);
        break;
    case RuntimeChildRole::OwnerComparison:
        need(capsule.input_count == 6);
        for (unsigned index = 1; index < 3; ++index)
            need(inputs[index].lineage == inputs[0].lineage);
        for (unsigned index = 4; index < 6; ++index)
            need(inputs[index].lineage == inputs[3].lineage);
        need(inputs[0].lineage.classification ==
                 Classification::TransparentBaseline &&
             inputs[3].lineage.classification ==
                 Classification::HiddenCandidate &&
             nonzero(inputs[0].lineage.barrier) &&
             nonzero(inputs[3].lineage.barrier) &&
             inputs[0].lineage.barrier !=
                 inputs[3].lineage.barrier &&
             inputs[0].lineage != inputs[3].lineage);
        break;
    }
}

Digest descriptor_manifest(RuntimeChildRole role) {
    const unsigned owner = role == RuntimeChildRole::OwnerScore ? 0 : NO_OWNER;
    const auto inputs = expected_inputs(role, owner, true);
    Bytes bytes;
    add(bytes, "KPB_MEASUREMENT_FIXED_DESCRIPTOR_MANIFEST_V1\n");
    integer(bytes, static_cast<unsigned char>(role), 1);
    integer(bytes, MEASUREMENT_SOURCE_CAPSULE_FD, 4);
    integer(bytes, MEASUREMENT_ASSET_CAPSULE_FD, 4);
    integer(bytes, MEASUREMENT_CHILD_FIXED_FD, 4);
    integer(bytes, inputs.size(), 1);
    for (const auto& input : inputs) {
        integer(bytes, static_cast<unsigned char>(input.kind), 1);
        integer(bytes,
                input.kind == MeasurementInputKind::OwnerTruth
                    ? NO_OWNER : input.owner,
                4);
        integer(bytes, input.fixed_fd, 4);
    }
    return hash(bytes);
}

struct Fingerprint {
    std::uint64_t device{};
    std::uint64_t inode{};
    std::uint32_t type{};
};

Fingerprint fingerprint(int fd, bool require_regular = false) {
    struct stat state{};
    need(fd >= 0 && ::fstat(fd, &state) == 0);
    const auto type = static_cast<std::uint32_t>(state.st_mode & S_IFMT);
    need((require_regular && type == S_IFREG) ||
         (!require_regular &&
          (type == S_IFREG || type == S_IFIFO || type == S_IFSOCK)));
    return {
        .device = static_cast<std::uint64_t>(state.st_dev),
        .inode = static_cast<std::uint64_t>(state.st_ino),
        .type = type,
    };
}

void close_fd(int& fd) noexcept {
    if (fd >= 0) {
        while (::close(fd) != 0 && errno == EINTR) {}
        fd = -1;
    }
}

int duplicate_high(int fd) {
    int result;
    do {
        result = ::fcntl(fd, F_DUPFD_CLOEXEC, 80);
    } while (result < 0 && errno == EINTR);
    need(result >= 80);
    return result;
}

Bytes read_regular(int fd) {
    struct stat state{};
    need(fd >= 0 && ::fstat(fd, &state) == 0 &&
         S_ISREG(state.st_mode) && state.st_size > 0 &&
         static_cast<std::uintmax_t>(state.st_size) <=
             static_cast<std::uintmax_t>(
                 std::numeric_limits<std::size_t>::max()));
    Bytes bytes(static_cast<std::size_t>(state.st_size));
    std::size_t at = 0;
    while (at < bytes.size()) {
        const auto count = ::pread(fd, bytes.data() + at,
                                   bytes.size() - at,
                                   static_cast<off_t>(at));
        if (count < 0 && errno == EINTR) continue;
        need(count > 0);
        at += static_cast<std::size_t>(count);
    }
    return bytes;
}

class ArchiveReader final {
    std::span<const unsigned char> bytes_;
    std::size_t at_{};
public:
    explicit ArchiveReader(std::span<const unsigned char> bytes)
        : bytes_(bytes) {}

    void magic(std::span<const unsigned char> expected) {
        need(at_ + expected.size() <= bytes_.size() &&
             std::equal(expected.begin(), expected.end(),
                        bytes_.begin() + static_cast<std::ptrdiff_t>(at_)));
        at_ += expected.size();
    }

    std::uint64_t integer(unsigned width) {
        need(width <= 8 && at_ + width <= bytes_.size());
        std::uint64_t result = 0;
        for (unsigned offset = 0; offset < width; ++offset)
            result |= static_cast<std::uint64_t>(bytes_[at_++]) <<
                      (8 * offset);
        return result;
    }

    std::span<const unsigned char> take(std::size_t size) {
        need(at_ + size <= bytes_.size());
        const auto result = bytes_.subspan(at_, size);
        at_ += size;
        return result;
    }

    void finish() const { need(at_ == bytes_.size()); }
};

bool canonical_path(std::span<const unsigned char> path) {
    if (path.empty() || path.front() == '/' || path.back() == '/')
        return false;
    bool segment_start = true;
    unsigned segment_length = 0;
    unsigned char first = 0;
    unsigned char second = 0;
    for (const unsigned char byte : path) {
        if (byte == '/') {
            if (segment_start ||
                (segment_length == 1 && first == '.') ||
                (segment_length == 2 && first == '.' && second == '.'))
                return false;
            segment_start = true;
            segment_length = 0;
            first = second = 0;
            continue;
        }
        const bool admitted =
            (byte >= 'a' && byte <= 'z') ||
            (byte >= 'A' && byte <= 'Z') ||
            (byte >= '0' && byte <= '9') || byte == '.' || byte == '_' ||
            byte == '-';
        if (!admitted) return false;
        if (segment_length == 0) first = byte;
        if (segment_length == 1) second = byte;
        ++segment_length;
        segment_start = false;
    }
    return !segment_start &&
           !(segment_length == 1 && first == '.') &&
           !(segment_length == 2 && first == '.' && second == '.');
}

void validate_archive(const Bytes& bytes,
                      std::span<const unsigned char> magic) {
    ArchiveReader reader(bytes);
    reader.magic(magic);
    const auto count = reader.integer(4);
    need(count > 0);
    Bytes previous;
    for (std::uint64_t index = 0; index < count; ++index) {
        const auto path_size = reader.integer(2);
        const auto content_size = reader.integer(8);
        need(path_size > 0 && content_size > 0 &&
             path_size <= std::numeric_limits<std::size_t>::max() &&
             content_size <= std::numeric_limits<std::size_t>::max());
        const auto path = reader.take(static_cast<std::size_t>(path_size));
        need(canonical_path(path) &&
             (previous.empty() ||
              std::lexicographical_compare(
                  previous.begin(), previous.end(),
                  path.begin(), path.end())));
        previous.assign(path.begin(), path.end());
        const auto wanted = reader.take(32);
        const auto content = reader.take(
            static_cast<std::size_t>(content_size));
        const auto actual = hash(content);
        need(std::equal(wanted.begin(), wanted.end(), actual.begin()));
    }
    reader.finish();
}

void write_all(int fd, std::span<const unsigned char> bytes) {
    std::size_t at = 0;
    while (at < bytes.size()) {
        const auto count = ::write(fd, bytes.data() + at,
                                   bytes.size() - at);
        if (count < 0 && errno == EINTR) continue;
        need(count > 0);
        at += static_cast<std::size_t>(count);
    }
}

int sealed_bytes(std::span<const unsigned char> bytes, mode_t mode) {
    const int raw = ::memfd_create(
        "kpb-measurement-capsule", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    need(raw >= 0);
    int temporary = raw;
    try {
        write_all(temporary, bytes);
        need(::fchmod(temporary, mode) == 0);
        constexpr int seals =
            F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
        need(::fcntl(temporary, F_ADD_SEALS, seals) == 0 &&
             (::fcntl(temporary, F_GET_SEALS) & seals) == seals);
        std::array<char, 64> proc_path{};
        const int path_size = std::snprintf(
            proc_path.data(), proc_path.size(), "/proc/self/fd/%d",
            temporary);
        need(path_size > 0 &&
             static_cast<std::size_t>(path_size) < proc_path.size());
        const int readonly = ::open(
            proc_path.data(), O_RDONLY | O_CLOEXEC);
        need(readonly >= 0 &&
             (::fcntl(readonly, F_GETFL) & O_ACCMODE) == O_RDONLY &&
             (::fcntl(readonly, F_GET_SEALS) & seals) == seals);
        const int result = duplicate_high(readonly);
        int selected = readonly;
        close_fd(selected);
        close_fd(temporary);
        return result;
    } catch (...) {
        close_fd(temporary);
        throw;
    }
}

void require_static_elf(std::span<const unsigned char> bytes) {
    need(bytes.size() >= sizeof(Elf64_Ehdr));
    Elf64_Ehdr header{};
    std::memcpy(&header, bytes.data(), sizeof(header));
    need(std::equal(std::begin(header.e_ident),
                    std::begin(header.e_ident) + SELFMAG, ELFMAG) &&
         header.e_ident[EI_CLASS] == ELFCLASS64 &&
         header.e_ident[EI_DATA] == ELFDATA2LSB &&
         header.e_phentsize == sizeof(Elf64_Phdr) &&
         header.e_phnum > 0 &&
         header.e_phoff <= bytes.size() &&
         static_cast<std::uint64_t>(header.e_phnum) * sizeof(Elf64_Phdr) <=
             bytes.size() - header.e_phoff);
#if defined(__x86_64__)
    need(header.e_machine == EM_X86_64);
#elif defined(__aarch64__)
    need(header.e_machine == EM_AARCH64);
#else
#error Unsupported native worker architecture
#endif
    for (unsigned index = 0; index < header.e_phnum; ++index) {
        Elf64_Phdr program{};
        const auto offset = static_cast<std::size_t>(header.e_phoff) +
                            index * sizeof(program);
        std::memcpy(&program, bytes.data() + offset, sizeof(program));
        need(program.p_type != PT_INTERP &&
             program.p_offset <= bytes.size() &&
             program.p_filesz <= bytes.size() - program.p_offset);
        if (program.p_type != PT_DYNAMIC) continue;
        need(program.p_filesz % sizeof(Elf64_Dyn) == 0);
        for (std::uint64_t at = 0; at < program.p_filesz;
             at += sizeof(Elf64_Dyn)) {
            Elf64_Dyn dynamic{};
            std::memcpy(&dynamic,
                        bytes.data() + program.p_offset + at,
                        sizeof(dynamic));
            need(dynamic.d_tag != DT_NEEDED);
        }
    }
}

} // namespace

WorkerBinding recompute_native_worker_binding(
        RuntimeChildRole role, const Digest& pinned_runtime,
        const Digest& canonical_source, const Digest& canonical_assets) {
    valid_role_owner(role,
        role == RuntimeChildRole::OwnerScore ? 0 : NO_OWNER);
    need(nonzero(pinned_runtime) && nonzero(canonical_source) &&
         nonzero(canonical_assets));
    Bytes runtime_bytes;
    add(runtime_bytes, "KPB_MEASUREMENT_STATIC_NATIVE_RUNTIME_V1\n");
    add(runtime_bytes, pinned_runtime);
    const auto runtime = hash(runtime_bytes);
    const auto launcher = descriptor_manifest(role);
    Bytes build_bytes;
    add(build_bytes, "KPB_MEASUREMENT_WORKER_BUILD_V1\n");
    integer(build_bytes, static_cast<unsigned char>(role), 1);
    add(build_bytes, canonical_source);
    add(build_bytes, runtime);
    add(build_bytes, canonical_assets);
    add(build_bytes, pinned_runtime);
    add(build_bytes, launcher);
    return {
        .source_identity = canonical_source,
        .build_identity = hash(build_bytes),
        .runtime_identity = runtime,
        .assets_identity = canonical_assets,
        .pinned_executable_identity = pinned_runtime,
        .launcher_identity = launcher,
    };
}

Digest recompute_worker_capsule_identity(
        const PublicMeasurementWorkerCapsule& capsule) {
    valid_role_owner(capsule.role, capsule.owner);
    need(capsule.input_count <= capsule.inputs.size() &&
         capsule.descriptor_manifest_identity ==
             descriptor_manifest(capsule.role));
    const auto expected = expected_inputs(
        capsule.role, capsule.owner, false);
    need(expected.size() == capsule.input_count &&
         capsule.worker == recompute_native_worker_binding(
             capsule.role, capsule.worker.pinned_executable_identity,
             capsule.worker.source_identity,
             capsule.worker.assets_identity));
    Bytes bytes;
    add(bytes, "KPB_MEASUREMENT_WORKER_CAPSULE_V1\n");
    integer(bytes, static_cast<unsigned char>(capsule.role), 1);
    integer(bytes, capsule.owner, 4);
    add_worker(bytes, capsule.worker);
    add(bytes, capsule.descriptor_manifest_identity);
    integer(bytes, capsule.input_count, 1);
    for (unsigned index = 0; index < capsule.inputs.size(); ++index) {
        const auto& input = capsule.inputs[index];
        if (index < capsule.input_count) {
            need(input.kind == expected[index].kind &&
                 input.owner == expected[index].owner &&
                 input.fixed_fd == expected[index].fixed_fd &&
                 nonzero(input.identity));
            valid_lineage(input.lineage);
            integer(bytes, static_cast<unsigned char>(input.kind), 1);
            integer(bytes, input.owner, 4);
            integer(bytes, input.fixed_fd, 4);
            add(bytes, input.identity);
            integer(bytes,
                    static_cast<unsigned char>(input.lineage.classification),
                    1);
            add(bytes, input.lineage.trial);
            add(bytes, input.lineage.barrier);
            add(bytes, input.lineage.capture_plan_identities[0]);
            add(bytes, input.lineage.capture_plan_identities[1]);
            for (const auto* values : {
                     &input.lineage.financial_runs,
                     &input.lineage.round_attempts,
                     &input.lineage.round_cohorts,
                     &input.lineage.projections})
                for (const auto& value : *values) add(bytes, value);
        } else {
            need(input == PublicMeasurementInputEndpoint{});
        }
    }
    valid_role_lineage(capsule);
    return hash(bytes);
}

MeasurementInputEndpointAuthority::MeasurementInputEndpointAuthority(
        MeasurementInputKind kind, unsigned owner, int source_fd,
        Digest identity,
        PublicMeasurementInputEndpoint::PublicLineage lineage,
        std::int64_t feeder_pid, Digest feeder_session,
        Digest feeder_exit_identity) {
    need(nonzero(identity) && feeder_pid > 1 &&
         nonzero(feeder_session) && nonzero(feeder_exit_identity));
    valid_lineage(lineage);
    if (kind == MeasurementInputKind::ObserverCapture)
        need(!nonzero(lineage.barrier));
    else
        need(nonzero(lineage.barrier));
    const int fixed = endpoint_fd(kind, owner);
    const int flags = ::fcntl(source_fd, F_GETFL);
    need(flags >= 0 && (flags & O_ACCMODE) != O_WRONLY);
    const auto original = fingerprint(source_fd);
    if (original.type == S_IFREG || original.type == S_IFIFO)
        need((flags & O_ACCMODE) == O_RDONLY);
    fd_ = duplicate_high(source_fd);
    if (original.type == S_IFSOCK)
        need(::shutdown(fd_, SHUT_WR) == 0 || errno == ENOTCONN);
    const auto duplicate = fingerprint(fd_);
    need(original.device == duplicate.device &&
         original.inode == duplicate.inode &&
         original.type == duplicate.type);
    receipt_ = {
        .kind = kind,
        .owner = owner,
        .fixed_fd = fixed,
        .identity = identity,
        .lineage = lineage,
    };
    device_ = original.device;
    inode_ = original.inode;
    file_type_ = original.type;
    feeder_pid_ = feeder_pid;
    feeder_session_ = feeder_session;
    feeder_exit_identity_ = feeder_exit_identity;
}

MeasurementInputEndpointAuthority::MeasurementInputEndpointAuthority(
        MeasurementInputEndpointAuthority&& other) noexcept
    : receipt_(other.receipt_), device_(other.device_), inode_(other.inode_),
      file_type_(other.file_type_), feeder_pid_(other.feeder_pid_),
      feeder_session_(other.feeder_session_),
      feeder_exit_identity_(other.feeder_exit_identity_),
      fd_(std::exchange(other.fd_, -1)),
      live_(other.live_.exchange(false)) {}

MeasurementInputEndpointAuthority::~MeasurementInputEndpointAuthority() {
    close_fd(fd_);
}

#ifdef KPB_MEASUREMENT_WORKER_CAPSULE_TEST_SETUP
MeasurementInputEndpointAuthority
MeasurementInputEndpointAuthority::test_only_mint(
        MeasurementInputKind kind, unsigned owner, int source_fd,
        Digest identity,
        PublicMeasurementInputEndpoint::PublicLineage lineage,
        std::int64_t feeder_pid, Digest feeder_session,
        Digest feeder_exit_identity) {
    return MeasurementInputEndpointAuthority(
        kind, owner, source_fd, std::move(identity), std::move(lineage),
        feeder_pid, std::move(feeder_session),
        std::move(feeder_exit_identity));
}
#endif

MeasurementWorkerCapsuleAuthority::MeasurementWorkerCapsuleAuthority(
        MeasurementWorkerCapsuleAuthority&& other) noexcept
    : receipt_(other.receipt_),
      runtime_fd_(std::exchange(other.runtime_fd_, -1)),
      source_fd_(std::exchange(other.source_fd_, -1)),
      assets_fd_(std::exchange(other.assets_fd_, -1)),
      inputs_(other.inputs_), live_(other.live_.exchange(false)) {
    for (auto& input : other.inputs_) input.fd = -1;
}

void MeasurementWorkerCapsuleAuthority::close_fds() noexcept {
    close_fd(runtime_fd_);
    close_fd(source_fd_);
    close_fd(assets_fd_);
    for (auto& input : inputs_) close_fd(input.fd);
}

MeasurementWorkerCapsuleAuthority::~MeasurementWorkerCapsuleAuthority() {
    close_fds();
}

#ifdef KPB_MEASUREMENT_WORKER_CAPSULE_TEST_SETUP
void MeasurementWorkerCapsuleAuthority::test_only_verify_seals_and_read_only()
        const {
    constexpr int seals =
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    for (const int fd : {runtime_fd_, source_fd_, assets_fd_})
        need(fd >= 0 && (::fcntl(fd, F_GET_SEALS) & seals) == seals);
    for (unsigned index = 0; index < receipt_.input_count; ++index) {
        const auto& input = inputs_[index];
        const int flags = ::fcntl(input.fd, F_GETFL);
        need(flags >= 0);
        if (input.file_type == S_IFREG || input.file_type == S_IFIFO)
            need((flags & O_ACCMODE) == O_RDONLY);
        const auto actual = fingerprint(input.fd);
        need(actual.device == input.device && actual.inode == input.inode &&
             actual.type == input.file_type && input.feeder_pid > 1 &&
             nonzero(input.feeder_session) &&
             nonzero(input.feeder_exit_identity));
    }
}
#endif

MeasurementWorkerCapsuleAuthority
MeasurementWorkerCapsuleAuthority::seal_native(
        RuntimeChildRole role, unsigned owner, int runtime_fd,
        int canonical_source_fd, int canonical_assets_fd,
        std::vector<MeasurementInputEndpointAuthority>&& supplied) {
    MeasurementWorkerCapsuleAuthority result;
    try {
        valid_role_owner(role, owner);
        const auto runtime_bytes = read_regular(runtime_fd);
        require_static_elf(runtime_bytes);
        const auto source_bytes = read_regular(canonical_source_fd);
        const auto assets_bytes = read_regular(canonical_assets_fd);
        validate_archive(source_bytes, SOURCE_MAGIC);
        validate_archive(assets_bytes, ASSET_MAGIC);
        const auto runtime_identity = hash(runtime_bytes);
        const auto source_identity = hash(source_bytes);
        const auto assets_identity = hash(assets_bytes);
        result.runtime_fd_ = sealed_bytes(runtime_bytes, 0500);
        result.source_fd_ = sealed_bytes(source_bytes, 0400);
        result.assets_fd_ = sealed_bytes(assets_bytes, 0400);

        const auto expected = expected_inputs(role, owner, false);
        need(supplied.size() == expected.size());
        std::set<std::pair<std::uint64_t, std::uint64_t>> objects;
        std::set<Digest> identities;
        std::set<std::int64_t> feeder_pids;
        std::set<Digest> feeder_sessions;
        std::set<Digest> feeder_exits;
        for (unsigned index = 0; index < supplied.size(); ++index) {
            auto& input = supplied[index];
            need(input.live_.exchange(false));
            const auto actual = fingerprint(input.fd_);
            need(input.receipt_.kind == expected[index].kind &&
                 input.receipt_.owner == expected[index].owner &&
                 input.receipt_.fixed_fd == expected[index].fixed_fd &&
                 actual.device == input.device_ &&
                 actual.inode == input.inode_ &&
                 actual.type == input.file_type_ &&
                 identities.insert(input.receipt_.identity).second &&
                 objects.emplace(actual.device, actual.inode).second &&
                 input.feeder_pid_ > 1 &&
                 nonzero(input.feeder_session_) &&
                 nonzero(input.feeder_exit_identity_) &&
                 feeder_pids.insert(input.feeder_pid_).second &&
                 feeder_sessions.insert(input.feeder_session_).second &&
                 feeder_exits.insert(input.feeder_exit_identity_).second);
            result.receipt_.inputs[index] = input.receipt_;
            result.inputs_[index] = RetainedInput{
                .receipt = input.receipt_,
                .device = actual.device,
                .inode = actual.inode,
                .file_type = actual.type,
                .feeder_pid = input.feeder_pid_,
                .feeder_session = input.feeder_session_,
                .feeder_exit_identity = input.feeder_exit_identity_,
                .fd = std::exchange(input.fd_, -1),
            };
        }
        result.receipt_.role = role;
        result.receipt_.owner = owner;
        result.receipt_.worker = recompute_native_worker_binding(
            role, runtime_identity, source_identity, assets_identity);
        result.receipt_.descriptor_manifest_identity =
            descriptor_manifest(role);
        result.receipt_.input_count =
            static_cast<unsigned>(expected.size());
        result.receipt_.capsule_identity =
            recompute_worker_capsule_identity(result.receipt_);
        return result;
    } catch (...) {
        result.close_fds();
        refuse();
    }
}

} // namespace kpb::measurement::runtime_bridge
