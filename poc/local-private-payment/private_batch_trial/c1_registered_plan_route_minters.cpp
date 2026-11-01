#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "c1_registered_plan_route_minters.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <limits>
#include <openssl/sha.h>
#include <span>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpb::measurement::c1_capture {
namespace {

using Bytes = std::vector<unsigned char>;

constexpr std::string_view CAPTURE_DOMAIN =
    "KPB_CAPTURE_IDENTITY_V1\n";
constexpr std::string_view SELECTION_STAGE_DOMAIN =
    "KPB_C1_CONTROLLER_SELECTION_STAGE_SOURCE_V1\n";
constexpr std::string_view SELECTION_HISTORY_DOMAIN =
    "KPB_C1_CONTROLLER_SELECTION_HISTORY_SOURCE_V1\n";
constexpr std::string_view CONTROLLER_RESULT_DOMAIN =
    "KPB_C1_CONTROLLER_RESULT_SOURCE_V1\n";
constexpr std::string_view EMPTY_RETRY_HISTORY_DOMAIN =
    "KPB_C1_CONTROLLER_EMPTY_RETRY_HISTORY_V1\n";
constexpr std::string_view FD31_EVENT_DOMAIN =
    "KPB_C1_FD31_RUNTIME_EVENT_V1\n";
constexpr std::string_view TERMINAL_HISTORY_DOMAIN =
    "KPB_C1_CONTROLLER_TERMINAL_HISTORY_V1\n";
constexpr std::string_view ROUTE_ARTIFACT_DOMAIN =
    "KPB_C1_OBSERVED_INVOICE_ROUTE_ARTIFACT_V1\n";
constexpr std::string_view ROUND_EVIDENCE_DOMAIN =
    "KPB_C1_ADMITTED_ROUND_ROUTE_EVIDENCE_V1\n";
constexpr std::string_view TWO_ROUND_EVIDENCE_DOMAIN =
    "KPB_C1_ADMITTED_TWO_ROUND_ROUTE_EVIDENCE_V1\n";

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
        [](unsigned char byte) { return byte != 0; });
}

bool uuid4(std::string_view value) {
    if (value.size() != 36 || value[8] != '-' || value[13] != '-' ||
        value[18] != '-' || value[23] != '-' || value[14] != '4' ||
        std::string_view("89ab").find(value[19]) == std::string_view::npos)
        return false;
    for (unsigned index = 0; index < value.size(); ++index) {
        if (index == 8 || index == 13 || index == 18 || index == 23)
            continue;
        const char byte = value[index];
        if (!((byte >= '0' && byte <= '9') ||
              (byte >= 'a' && byte <= 'f')))
            return false;
    }
    return true;
}

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add(Bytes& out, const Digest& value) { add(out, std::span(value)); }
void add(Bytes& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add_u64(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}
void add_text(Bytes& out, std::string_view value) {
    add_u64(out, value.size());
    add(out, value);
}
void add_worker(Bytes& out, const WorkerBinding& value) {
    add(out, value.source_identity);
    add(out, value.build_identity);
    add(out, value.runtime_identity);
    add(out, value.assets_identity);
    add(out, value.pinned_executable_identity);
    add(out, value.launcher_identity);
}

Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    need(SHA256(value.data(), value.size(), result.data()) != nullptr &&
         nonzero(result));
    return result;
}

Digest domain_hash(std::string_view domain, std::string_view value) {
    Bytes bytes(domain.begin(), domain.end());
    add(bytes, value);
    return hash(bytes);
}

void require_worker(const WorkerBinding& value) {
    for (const auto* field : {
             &value.source_identity, &value.build_identity,
             &value.runtime_identity, &value.assets_identity,
             &value.pinned_executable_identity, &value.launcher_identity})
        need(nonzero(*field));
}

WorkerBinding manifest_worker(
        const PublicRegisteredC1RoundLineage& lineage,
        ManifestComponent component) {
    const auto index = static_cast<unsigned>(component) - 1;
    need(index < lineage.finite_manifest.entries.size());
    const auto& entry = lineage.finite_manifest.entries[index];
    need(entry.component == component);
    WorkerBinding result{
        .source_identity = entry.source_identity,
        .build_identity = entry.build_identity,
        .runtime_identity = entry.runtime_identity,
        .assets_identity = entry.assets_identity,
        .pinned_executable_identity = entry.pinned_executable_identity,
        .launcher_identity = entry.launcher_identity,
    };
    require_worker(result);
    return result;
}

unsigned stage_index(C1ControllerStage stage) {
    const auto result = static_cast<unsigned>(stage);
    need(result < 3);
    return result;
}

std::array<unsigned, 3> expected_contacts(unsigned round) {
    need(round == 1 || round == 2);
    return round == 1 ? std::array<unsigned, 3>{0, 2, 0}
                      : std::array<unsigned, 3>{2, 0, 2};
}

#ifdef KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP
std::uint64_t monotonic_after(std::uint64_t prior) {
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        const auto now = std::chrono::steady_clock::now()
            .time_since_epoch();
        const auto count = std::chrono::duration_cast<
            std::chrono::nanoseconds>(now).count();
        need(count > 0);
        const auto value = static_cast<std::uint64_t>(count);
        if (value > prior) return value;
    }
    refuse();
}
#endif

struct FileSummary final {
    Digest raw_sha256{};
    std::uint64_t device{};
    std::uint64_t inode{};
    std::uint64_t byte_count{};
    bool operator==(const FileSummary&) const = default;
};

bool same_file(const FileSummary& left, const FileSummary& right) {
    return left.device == right.device && left.inode == right.inode;
}

void add_file(Bytes& out, const FileSummary& value) {
    add(out, value.raw_sha256);
    add_u64(out, value.device);
    add_u64(out, value.inode);
    add_u64(out, value.byte_count);
}

struct SourceFileBinding final {
    int fd{-1};
    FileSummary summary{};

    SourceFileBinding() = default;
    SourceFileBinding(int selected_fd, FileSummary selected_summary)
        : fd(selected_fd), summary(selected_summary) {}
    SourceFileBinding(const SourceFileBinding&) = delete;
    SourceFileBinding& operator=(const SourceFileBinding&) = delete;
    SourceFileBinding(SourceFileBinding&& other) noexcept
        : fd(std::exchange(other.fd, -1)), summary(other.summary) {}
    SourceFileBinding& operator=(SourceFileBinding&& other) noexcept {
        if (this == &other) return *this;
        if (fd >= 0) (void)::close(fd);
        fd = std::exchange(other.fd, -1);
        summary = other.summary;
        return *this;
    }
    ~SourceFileBinding() {
        if (fd >= 0) (void)::close(fd);
    }
};

FileSummary read_regular_source(int fd) {
    struct stat before{};
    need(fd >= 0 && ::fstat(fd, &before) == 0 &&
         S_ISREG(before.st_mode) && before.st_uid == ::geteuid() &&
         (before.st_mode & 077) == 0 &&
         (before.st_nlink == 0 || before.st_nlink == 1) &&
         before.st_size > 0);
    const auto unsigned_size = static_cast<std::uintmax_t>(before.st_size);
    need(unsigned_size <= std::numeric_limits<std::size_t>::max() &&
         unsigned_size <= std::numeric_limits<std::uint64_t>::max());
    const auto size = static_cast<std::size_t>(unsigned_size);
    Bytes bytes(size);
    std::size_t at = 0;
    while (at < bytes.size()) {
        const auto count = ::pread(
            fd, bytes.data() + at, bytes.size() - at,
            static_cast<off_t>(at));
        if (count < 0 && errno == EINTR) continue;
        need(count > 0);
        at += static_cast<std::size_t>(count);
    }
    unsigned char extra{};
    need(::pread(fd, &extra, 1, static_cast<off_t>(bytes.size())) == 0);
    struct stat after{};
    need(::fstat(fd, &after) == 0 &&
         before.st_dev == after.st_dev &&
         before.st_ino == after.st_ino &&
         before.st_size == after.st_size &&
         before.st_mode == after.st_mode &&
         before.st_uid == after.st_uid &&
         before.st_nlink == after.st_nlink);
    return {
        .raw_sha256 = hash(bytes),
        .device = static_cast<std::uint64_t>(before.st_dev),
        .inode = static_cast<std::uint64_t>(before.st_ino),
        .byte_count = static_cast<std::uint64_t>(unsigned_size),
    };
}

#ifdef KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP
SourceFileBinding bind_source_file(int source_fd) {
    const auto first = read_regular_source(source_fd);
    Bytes bytes(static_cast<std::size_t>(first.byte_count));
    std::size_t at = 0;
    while (at < bytes.size()) {
        const auto count = ::pread(
            source_fd, bytes.data() + at, bytes.size() - at,
            static_cast<off_t>(at));
        if (count < 0 && errno == EINTR) continue;
        need(count > 0);
        at += static_cast<std::size_t>(count);
    }
    unsigned char extra{};
    need(::pread(
             source_fd, &extra, 1,
             static_cast<off_t>(bytes.size())) == 0 &&
         hash(bytes) == first.raw_sha256 &&
         read_regular_source(source_fd) == first);
    int temporary = ::memfd_create(
        "kpb-c1-source-snapshot", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    need(temporary >= 0);
    int snapshot = -1;
    try {
        need(::fchmod(temporary, 0600) == 0);
        at = 0;
        while (at < bytes.size()) {
            const auto count = ::write(
                temporary, bytes.data() + at, bytes.size() - at);
            if (count < 0 && errno == EINTR) continue;
            need(count > 0);
            at += static_cast<std::size_t>(count);
        }
        need(::lseek(temporary, 0, SEEK_SET) == 0);
        constexpr int seals = F_SEAL_SEAL | F_SEAL_SHRINK |
                              F_SEAL_GROW | F_SEAL_WRITE;
        need(::fcntl(temporary, F_ADD_SEALS, seals) == 0);
        const auto observed_seals = ::fcntl(temporary, F_GET_SEALS);
        need(observed_seals >= 0 &&
             (observed_seals & seals) == seals);
        snapshot = ::fcntl(temporary, F_DUPFD_CLOEXEC, 64);
        need(snapshot >= 0);
        (void)::close(temporary);
        temporary = -1;
        const auto snapshot_summary = read_regular_source(snapshot);
        need(snapshot_summary.raw_sha256 == first.raw_sha256 &&
             snapshot_summary.byte_count == first.byte_count);
        return SourceFileBinding(snapshot, first);
    } catch (...) {
        if (snapshot >= 0) (void)::close(snapshot);
        if (temporary >= 0) (void)::close(temporary);
        throw;
    }
}
#endif

void revalidate(const SourceFileBinding& value) {
    constexpr int seals = F_SEAL_SEAL | F_SEAL_SHRINK |
                          F_SEAL_GROW | F_SEAL_WRITE;
    need(value.fd >= 0);
    const auto observed_seals = ::fcntl(value.fd, F_GET_SEALS);
    need(observed_seals >= 0 &&
         (observed_seals & seals) == seals);
    const auto snapshot = read_regular_source(value.fd);
    need(snapshot.raw_sha256 == value.summary.raw_sha256 &&
         snapshot.byte_count == value.summary.byte_count);
}

template<std::size_t Count>
void require_distinct_files(
        const std::array<SourceFileBinding, Count>& values,
        unsigned populated) {
    need(populated <= Count);
    for (unsigned left = 0; left < populated; ++left) {
        need(values[left].fd >= 0);
        for (unsigned right = left + 1; right < populated; ++right)
            need(!same_file(values[left].summary, values[right].summary));
    }
}

template<std::size_t LeftCount, std::size_t RightCount>
void require_no_file_overlap(
        const std::array<SourceFileBinding, LeftCount>& left,
        unsigned left_populated,
        const std::array<SourceFileBinding, RightCount>& right,
        unsigned right_populated) {
    need(left_populated <= LeftCount && right_populated <= RightCount);
    for (unsigned a = 0; a < left_populated; ++a)
        for (unsigned b = 0; b < right_populated; ++b)
            need(!same_file(left[a].summary, right[b].summary));
}

Digest selection_stage_identity(
        const PublicRegisteredC1RoundLineage& lineage,
        unsigned stage, std::string_view operation,
        unsigned contact, const FileSummary& file) {
    Bytes bytes(SELECTION_STAGE_DOMAIN.begin(),
                SELECTION_STAGE_DOMAIN.end());
    bytes.push_back(static_cast<unsigned char>(lineage.round));
    bytes.push_back(static_cast<unsigned char>(stage));
    add(bytes, lineage.registered_prelaunch_identity);
    add(bytes, lineage.round_capture_plan);
    add_text(bytes, operation);
    bytes.push_back(static_cast<unsigned char>(contact));
    add_file(bytes, file);
    return hash(bytes);
}

Digest selection_history_identity(
        const PublicRegisteredC1RoundLineage& lineage,
        std::string_view capture_identity,
        const std::array<std::string, 3>& operations,
        const std::array<unsigned, 3>& contacts,
        const std::array<Digest, 3>& stages) {
    Bytes bytes(SELECTION_HISTORY_DOMAIN.begin(),
                SELECTION_HISTORY_DOMAIN.end());
    bytes.push_back(static_cast<unsigned char>(lineage.round));
    add(bytes, lineage.registered_prelaunch_identity);
    add(bytes, lineage.round_capture_plan);
    add_text(bytes, capture_identity);
    for (unsigned index = 0; index < stages.size(); ++index) {
        bytes.push_back(static_cast<unsigned char>(index));
        add_text(bytes, operations[index]);
        bytes.push_back(static_cast<unsigned char>(contacts[index]));
        add(bytes, stages[index]);
    }
    return hash(bytes);
}

Digest controller_result_identity(
        const Digest& selection_identity, unsigned round, unsigned stage,
        std::string_view operation, const FileSummary& file) {
    Bytes bytes(CONTROLLER_RESULT_DOMAIN.begin(),
                CONTROLLER_RESULT_DOMAIN.end());
    bytes.push_back(static_cast<unsigned char>(round));
    bytes.push_back(static_cast<unsigned char>(stage));
    add(bytes, selection_identity);
    add_text(bytes, operation);
    add_file(bytes, file);
    add_u64(bytes, 0);
    return hash(bytes);
}

Digest empty_retry_history_identity(
        const Digest& selection_identity, unsigned round) {
    Bytes bytes(EMPTY_RETRY_HISTORY_DOMAIN.begin(),
                EMPTY_RETRY_HISTORY_DOMAIN.end());
    bytes.push_back(static_cast<unsigned char>(round));
    add(bytes, selection_identity);
    add_u64(bytes, 0);
    return hash(bytes);
}

Digest fd31_event_identity(
        std::string_view event, const Digest& selection_identity,
        const Digest& contact_value_identity,
        const Digest& offer_sha256, std::uint64_t offer_device,
        std::uint64_t offer_inode, std::uint64_t monotonic_ns,
        const Digest* prior = nullptr,
        std::span<const Digest> attached = {}) {
    Bytes bytes(FD31_EVENT_DOMAIN.begin(), FD31_EVENT_DOMAIN.end());
    add_text(bytes, event);
    add(bytes, selection_identity);
    add(bytes, contact_value_identity);
    add(bytes, offer_sha256);
    add_u64(bytes, offer_device);
    add_u64(bytes, offer_inode);
    add_u64(bytes, monotonic_ns);
    if (prior != nullptr) add(bytes, *prior);
    for (const auto& value : attached) add(bytes, value);
    return hash(bytes);
}

Digest route_artifact_identity(
        unsigned round, const PublicC1ObservedRouteArtifact& value) {
    Bytes bytes(ROUTE_ARTIFACT_DOMAIN.begin(),
                ROUTE_ARTIFACT_DOMAIN.end());
    bytes.push_back(static_cast<unsigned char>(round));
    bytes.push_back(static_cast<unsigned char>(value.source_owner_component));
    bytes.push_back(static_cast<unsigned char>(value.target_owner_component));
    add_u64(bytes, value.source_operation_id.size());
    add(bytes, value.source_operation_id);
    add_u64(bytes, value.target_invoice_operation_id.size());
    add(bytes, value.target_invoice_operation_id);
    add(bytes, value.raw_bytes_sha256);
    add_u64(bytes, value.device);
    add_u64(bytes, value.inode);
    add_u64(bytes, value.byte_count);
    return hash(bytes);
}

Digest terminal_history_identity(
        const PublicC1AcceptedControllerResult& result) {
    Bytes bytes(TERMINAL_HISTORY_DOMAIN.begin(),
                TERMINAL_HISTORY_DOMAIN.end());
    bytes.push_back(static_cast<unsigned char>(result.round));
    add(bytes, result.accepted_selection_identity);
    add(bytes, result.fd31_authenticated_completion_identity);
    add(bytes, result.retry_history_identity);
    for (const auto& identity : result.controller_result_identities)
        add(bytes, identity);
    add_u64(bytes, result.completed_stage_count);
    add_u64(bytes, result.retry_count);
    return hash(bytes);
}

void require_file_summary(const FileSummary& value) {
    need(nonzero(value.raw_sha256) && value.device > 0 && value.inode > 0 &&
         value.byte_count > 0);
}

template<std::size_t Count>
void require_distinct_summaries(
        const std::array<FileSummary, Count>& values) {
    for (unsigned left = 0; left < Count; ++left) {
        require_file_summary(values[left]);
        for (unsigned right = left + 1; right < Count; ++right)
            need(!same_file(values[left], values[right]));
    }
}

} // namespace

struct C1ControllerSelectionSourceAuthority::Storage final {
    unsigned round{};
    std::string capture_trial_id;
    std::string capture_attempt_id;
    std::string capture_identity;
    Digest registered_prelaunch_identity{};
    Digest round_capture_plan_identity{};
    WorkerBinding generator_worker{};
    C1ControllerStage stage{};
    std::string operation_id;
    unsigned contact_owner_component{};
    SourceFileBinding file;
    bool live{true};
};

struct C1Fd31OfferParseSourceAuthority::Storage final {
    Digest selection_identity{};
    Digest contact_value_authority_identity{};
    FileSummary offer_file{};
    Digest c1_process_identity{};
    Digest expected_exit_policy_identity{};
    WorkerBinding supervisor_worker{};
    std::uint64_t parse_monotonic_ns{};
    bool live{true};
};

struct C1ControllerTerminalSourceAuthority::Storage final {
    Digest selection_identity{};
    unsigned round{};
    C1ControllerStage stage{};
    std::string operation_id;
    WorkerBinding generator_worker{};
    int normalized_worker_exit_code{};
    SourceFileBinding file;
    bool live{true};
};

struct C1ObservedRouteSourceAuthority::Storage final {
    Digest selection_identity{};
    unsigned round{};
    unsigned source_owner_component{};
    unsigned target_owner_component{};
    std::string source_operation_id;
    std::string target_invoice_operation_id;
    int normalized_worker_exit_code{};
    SourceFileBinding file;
    bool live{true};
};

struct C1Fd31CompletionSourceAuthority::Storage final {
    Digest selection_identity{};
    Digest contact_value_authority_identity{};
    FileSummary offer_file{};
    Digest c1_process_identity{};
    Digest expected_exit_policy_identity{};
    WorkerBinding supervisor_worker{};
    std::uint64_t completion_monotonic_ns{};
    std::uint64_t writer_close_monotonic_ns{};
    std::uint64_t eof_monotonic_ns{};
    std::uint64_t exit_join_monotonic_ns{};
    int normalized_supervisor_exit_code{};
    unsigned observed_retry_count{};
    bool live{true};
};

struct RegisteredC1SelectedRound::Storage final {
    std::optional<RegisteredC1RoundLineageAuthority> lineage;
    std::optional<C1AcceptedControllerSelectionAuthority> selection;
    std::array<SourceFileBinding, 3> selection_files;
    bool live{true};

    Storage(
            RegisteredC1RoundLineageAuthority&& selected_lineage,
            C1AcceptedControllerSelectionAuthority&& selected_selection,
            std::array<SourceFileBinding, 3>&& files)
        : lineage(std::in_place, std::move(selected_lineage)),
          selection(std::in_place, std::move(selected_selection)),
          selection_files(std::move(files)) {}
};

struct RegisteredC1ControllerSelectionCallsite::Storage final {
    std::optional<RegisteredC1RoundLineageAuthority> lineage;
    PublicRegisteredC1RoundLineage source_lineage;
    std::string capture_identity;
    std::array<std::string, 3> operations{};
    std::array<Digest, 3> stage_identities{};
    std::array<SourceFileBinding, 3> files;
    unsigned stage_count{};
    bool poisoned{};
    bool live{true};

    Storage(RegisteredC1RoundLineageAuthority&& selected_lineage,
            PublicRegisteredC1RoundLineage selected_source_lineage,
            std::string selected_capture)
        : lineage(std::in_place, std::move(selected_lineage)),
          source_lineage(std::move(selected_source_lineage)),
          capture_identity(std::move(selected_capture)) {}
};

struct RegisteredC1SelectedLaunchCallsite::Storage final {
    std::optional<C1ContactValueOfferAuthority> offer;
    std::optional<RegisteredC1PendingTerminalAuthority> pending;
    std::array<SourceFileBinding, 3> selection_files;
    bool offer_taken{};
    bool poisoned{};
    bool live{true};

    Storage(C1ContactValueOfferAuthority&& selected_offer,
            RegisteredC1PendingTerminalAuthority&& selected_pending,
            std::array<SourceFileBinding, 3>&& files)
        : offer(std::in_place, std::move(selected_offer)),
          pending(std::in_place, std::move(selected_pending)),
          selection_files(std::move(files)) {}
};

struct RegisteredC1TerminalCallsite::Storage final {
    std::optional<RegisteredC1PendingTerminalAuthority> pending;
    PublicC1AcceptedControllerSelection source_selection;
    Digest source_selection_identity{};
    Digest source_contact_value_authority_identity{};
    Digest source_offer_file_sha256{};
    std::uint64_t source_offer_device{};
    std::uint64_t source_offer_inode{};
    Digest source_c1_process_identity{};
    Digest source_c1_exit_policy_identity{};
    std::array<SourceFileBinding, 3> selection_files;
    std::array<SourceFileBinding, 3> result_files;
    std::array<SourceFileBinding, 3> route_files;
    std::array<Digest, 3> result_identities{};
    std::array<PublicC1ObservedRouteArtifact, 3> route_artifacts{};
    unsigned result_count{};
    unsigned route_count{};
    Digest parse_identity{};
    Digest completion_identity{};
    Digest writer_close_identity{};
    Digest eof_identity{};
    Digest exit_identity{};
    std::uint64_t parse_ns{};
    std::uint64_t completion_ns{};
    std::uint64_t writer_close_ns{};
    std::uint64_t eof_ns{};
    std::uint64_t exit_ns{};
    bool parse_observed{};
    bool completion_observed{};
    bool writer_close_observed{};
    bool eof_observed{};
    bool exit_observed{};
    bool poisoned{};
    bool live{true};

    Storage(RegisteredC1PendingTerminalAuthority&& selected_pending,
            std::array<SourceFileBinding, 3>&& files)
        : pending(std::in_place, std::move(selected_pending)),
          selection_files(std::move(files)) {}
};

struct RegisteredC1RoundRouteEvidenceAuthority::Storage final {
    unsigned round{};
    std::string capture_trial_id;
    std::string capture_attempt_id;
    std::string capture_identity;
    std::array<std::string, 3> operation_ids{};
    std::array<unsigned, 3> contacts{};
    Digest registered_prelaunch_identity{};
    Digest round_capture_plan_identity{};
    Digest selection_identity{};
    Digest contact_value_authority_identity{};
    Digest offer_file_sha256{};
    std::uint64_t offer_device{};
    std::uint64_t offer_inode{};
    Digest c1_process_identity{};
    Digest expected_exit_policy_identity{};
    Digest parse_identity{};
    Digest completion_identity{};
    Digest writer_close_identity{};
    Digest eof_identity{};
    Digest exit_identity{};
    std::array<Digest, 3> result_identities{};
    Digest retry_history_identity{};
    Digest terminal_history_identity{};
    Digest projection_identity{};
    WorkerBinding generator_worker{};
    WorkerBinding validator_worker{};
    std::array<PublicC1ObservedRouteArtifact, 3> route_artifacts{};
    std::array<FileSummary, 3> selection_files{};
    std::array<FileSummary, 3> result_files{};
    std::array<FileSummary, 3> route_files{};
    Digest identity{};
    bool live{true};
};

struct RegisteredC1TwoRoundRouteEvidenceAuthority::Storage final {
    std::array<
        std::unique_ptr<RegisteredC1RoundRouteEvidenceAuthority::Storage>,
        2> rounds;
    Digest identity{};
};

struct RegisteredC1TwoRoundRouteEvidenceJoiner::Storage final {
    std::array<
        std::unique_ptr<RegisteredC1RoundRouteEvidenceAuthority::Storage>,
        2> rounds;
    unsigned count{};
    bool poisoned{};
    bool live{true};
};

namespace {

Digest round_evidence_identity(
        const RegisteredC1RoundRouteEvidenceAuthority::Storage& value) {
    Bytes bytes(ROUND_EVIDENCE_DOMAIN.begin(), ROUND_EVIDENCE_DOMAIN.end());
    bytes.push_back(static_cast<unsigned char>(value.round));
    add_text(bytes, value.capture_trial_id);
    add_text(bytes, value.capture_attempt_id);
    add_text(bytes, value.capture_identity);
    add(bytes, value.registered_prelaunch_identity);
    add(bytes, value.round_capture_plan_identity);
    add(bytes, value.selection_identity);
    add(bytes, value.contact_value_authority_identity);
    add(bytes, value.offer_file_sha256);
    add_u64(bytes, value.offer_device);
    add_u64(bytes, value.offer_inode);
    add(bytes, value.c1_process_identity);
    add(bytes, value.expected_exit_policy_identity);
    add(bytes, value.parse_identity);
    add(bytes, value.completion_identity);
    add(bytes, value.writer_close_identity);
    add(bytes, value.eof_identity);
    add(bytes, value.exit_identity);
    add(bytes, value.retry_history_identity);
    add(bytes, value.terminal_history_identity);
    add(bytes, value.projection_identity);
    add_worker(bytes, value.generator_worker);
    add_worker(bytes, value.validator_worker);
    for (unsigned index = 0; index < 3; ++index) {
        bytes.push_back(static_cast<unsigned char>(index));
        add_text(bytes, value.operation_ids[index]);
        bytes.push_back(static_cast<unsigned char>(value.contacts[index]));
        add(bytes, value.result_identities[index]);
        add(bytes, value.route_artifacts[index].record_identity);
        add_file(bytes, value.selection_files[index]);
        add_file(bytes, value.result_files[index]);
        add_file(bytes, value.route_files[index]);
    }
    return hash(bytes);
}

void validate_round_evidence(
        const RegisteredC1RoundRouteEvidenceAuthority::Storage& value) {
    need((value.round == 1 || value.round == 2) &&
         uuid4(value.capture_trial_id) &&
         uuid4(value.capture_attempt_id) &&
         uuid4(value.capture_identity) &&
         value.contacts == expected_contacts(value.round));
    for (const auto& operation : value.operation_ids)
        need(uuid4(operation));
    need(value.operation_ids[0] != value.operation_ids[1] &&
         value.operation_ids[0] != value.operation_ids[2] &&
         value.operation_ids[1] != value.operation_ids[2]);
    for (const auto* field : {
             &value.registered_prelaunch_identity,
             &value.round_capture_plan_identity, &value.selection_identity,
             &value.contact_value_authority_identity,
             &value.offer_file_sha256, &value.c1_process_identity,
             &value.expected_exit_policy_identity, &value.parse_identity,
             &value.completion_identity, &value.writer_close_identity,
             &value.eof_identity, &value.exit_identity,
             &value.retry_history_identity, &value.terminal_history_identity,
             &value.projection_identity, &value.identity})
        need(nonzero(*field));
    need(value.offer_device > 0 && value.offer_inode > 0);
    require_worker(value.generator_worker);
    require_worker(value.validator_worker);
    need(value.generator_worker != value.validator_worker);
    for (unsigned index = 0; index < 3; ++index) {
        need(nonzero(value.result_identities[index]));
        const auto& route = value.route_artifacts[index];
        need(route.source_owner_component == index &&
             route.target_owner_component == (index + value.round) % 3 &&
             route.source_operation_id == value.operation_ids[1] &&
             route.target_invoice_operation_id == value.operation_ids[0] &&
             route.record_identity == route_artifact_identity(
                 value.round, route));
    }
    require_distinct_summaries(value.selection_files);
    require_distinct_summaries(value.result_files);
    require_distinct_summaries(value.route_files);
    for (const auto& left : value.selection_files) {
        for (const auto& right : value.result_files)
            need(!same_file(left, right));
        for (const auto& right : value.route_files)
            need(!same_file(left, right));
    }
    for (const auto& left : value.result_files)
        for (const auto& right : value.route_files)
            need(!same_file(left, right));
    need(value.identity == round_evidence_identity(value));
}

void validate_two_round_pair(
        const RegisteredC1RoundRouteEvidenceAuthority::Storage& first,
        const RegisteredC1RoundRouteEvidenceAuthority::Storage& second) {
    need(first.round == 1 && second.round == 2 &&
         first.capture_trial_id == second.capture_trial_id &&
         first.capture_attempt_id != second.capture_attempt_id &&
         first.capture_identity == second.capture_identity &&
         first.registered_prelaunch_identity ==
             second.registered_prelaunch_identity &&
         first.round_capture_plan_identity !=
             second.round_capture_plan_identity &&
         first.selection_identity != second.selection_identity &&
         first.contact_value_authority_identity !=
             second.contact_value_authority_identity &&
         first.offer_file_sha256 != second.offer_file_sha256 &&
         (first.offer_device != second.offer_device ||
          first.offer_inode != second.offer_inode) &&
         first.c1_process_identity != second.c1_process_identity &&
         first.expected_exit_policy_identity !=
             second.expected_exit_policy_identity &&
         first.parse_identity != second.parse_identity &&
         first.completion_identity != second.completion_identity &&
         first.writer_close_identity != second.writer_close_identity &&
         first.eof_identity != second.eof_identity &&
         first.exit_identity != second.exit_identity &&
         first.retry_history_identity != second.retry_history_identity &&
         first.terminal_history_identity != second.terminal_history_identity &&
         first.projection_identity != second.projection_identity &&
         first.generator_worker == second.generator_worker &&
         first.validator_worker == second.validator_worker);
    for (const auto& left : first.operation_ids)
        for (const auto& right : second.operation_ids)
            need(left != right);
    for (const auto& left : first.result_identities)
        for (const auto& right : second.result_identities)
            need(left != right);
    for (const auto& left : first.route_artifacts)
        for (const auto& right : second.route_artifacts)
            need(left.record_identity != right.record_identity &&
                 !same_file(
                     FileSummary{left.raw_bytes_sha256, left.device,
                                 left.inode, left.byte_count},
                     FileSummary{right.raw_bytes_sha256, right.device,
                                 right.inode, right.byte_count}));
    const std::array<const std::array<FileSummary, 3>*, 3> first_files{
        &first.selection_files, &first.result_files, &first.route_files};
    const std::array<const std::array<FileSummary, 3>*, 3> second_files{
        &second.selection_files, &second.result_files, &second.route_files};
    for (const auto* left_group : first_files)
        for (const auto* right_group : second_files)
            for (const auto& left : *left_group)
                for (const auto& right : *right_group)
                    need(!same_file(left, right));
}

} // namespace

C1ControllerSelectionSourceAuthority::
C1ControllerSelectionSourceAuthority(std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }
C1ControllerSelectionSourceAuthority::
C1ControllerSelectionSourceAuthority(
        C1ControllerSelectionSourceAuthority&&) noexcept = default;
C1ControllerSelectionSourceAuthority::~
C1ControllerSelectionSourceAuthority() = default;

C1Fd31OfferParseSourceAuthority::C1Fd31OfferParseSourceAuthority(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {
    need(storage_ != nullptr);
}
C1Fd31OfferParseSourceAuthority::C1Fd31OfferParseSourceAuthority(
        C1Fd31OfferParseSourceAuthority&&) noexcept = default;
C1Fd31OfferParseSourceAuthority::~C1Fd31OfferParseSourceAuthority() = default;

C1ControllerTerminalSourceAuthority::C1ControllerTerminalSourceAuthority(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {
    need(storage_ != nullptr);
}
C1ControllerTerminalSourceAuthority::C1ControllerTerminalSourceAuthority(
        C1ControllerTerminalSourceAuthority&&) noexcept = default;
C1ControllerTerminalSourceAuthority::~
C1ControllerTerminalSourceAuthority() = default;

C1ObservedRouteSourceAuthority::C1ObservedRouteSourceAuthority(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {
    need(storage_ != nullptr);
}
C1ObservedRouteSourceAuthority::C1ObservedRouteSourceAuthority(
        C1ObservedRouteSourceAuthority&&) noexcept = default;
C1ObservedRouteSourceAuthority::~C1ObservedRouteSourceAuthority() = default;

C1Fd31CompletionSourceAuthority::C1Fd31CompletionSourceAuthority(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {
    need(storage_ != nullptr);
}
C1Fd31CompletionSourceAuthority::C1Fd31CompletionSourceAuthority(
        C1Fd31CompletionSourceAuthority&&) noexcept = default;
C1Fd31CompletionSourceAuthority::~C1Fd31CompletionSourceAuthority() =
    default;

RegisteredC1SelectedRound::RegisteredC1SelectedRound(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {
    need(storage_ != nullptr);
}
RegisteredC1SelectedRound::RegisteredC1SelectedRound(
        RegisteredC1SelectedRound&&) noexcept = default;
RegisteredC1SelectedRound::~RegisteredC1SelectedRound() = default;

RegisteredC1ControllerSelectionCallsite::
RegisteredC1ControllerSelectionCallsite(std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }
RegisteredC1ControllerSelectionCallsite::
RegisteredC1ControllerSelectionCallsite(
        RegisteredC1ControllerSelectionCallsite&&) noexcept = default;
RegisteredC1ControllerSelectionCallsite::~
RegisteredC1ControllerSelectionCallsite() = default;

RegisteredC1ControllerSelectionCallsite
RegisteredC1RuntimeCallsiteBridge::begin_controller_selection(
        RegisteredC1RoundLineageAuthority&& supplied_lineage,
        std::string capture_identity) {
    RegisteredC1RoundLineageAuthority lineage(std::move(supplied_lineage));
    try {
        need(lineage.live_.load() && uuid4(capture_identity) &&
             domain_hash(CAPTURE_DOMAIN, capture_identity) ==
                 lineage.value_.capture);
        auto source_lineage = lineage.value_;
        return RegisteredC1ControllerSelectionCallsite(
            std::make_unique<
                RegisteredC1ControllerSelectionCallsite::Storage>(
                    std::move(lineage), std::move(source_lineage),
                    std::move(capture_identity)));
    } catch (...) { refuse(); }
}

void RegisteredC1ControllerSelectionCallsite::observe_selected_stage(
        C1ControllerSelectionSourceAuthority&& supplied_source) {
    try {
        need(storage_ != nullptr && storage_->live && !storage_->poisoned &&
             storage_->lineage.has_value() &&
             supplied_source.storage_ != nullptr);
        auto source = std::move(supplied_source.storage_);
        need(source->live);
        source->live = false;
        const auto index = stage_index(source->stage);
        need(index == storage_->stage_count);
        const auto& lineage = storage_->lineage->value_;
        const auto contacts = expected_contacts(lineage.round);
        const auto generator = manifest_worker(
            lineage, ManifestComponent::C1Supervisor);
        need(source->round == lineage.round &&
             source->capture_trial_id == lineage.capture_trial_id &&
             source->capture_attempt_id == lineage.capture_attempt_id &&
             source->capture_identity == storage_->capture_identity &&
             source->registered_prelaunch_identity ==
                 lineage.registered_prelaunch_identity &&
             source->round_capture_plan_identity ==
                 lineage.round_capture_plan &&
             source->generator_worker == generator &&
             source->contact_owner_component == contacts[index] &&
             uuid4(source->operation_id));
        revalidate(source->file);
        for (unsigned prior = 0; prior < index; ++prior)
            need(storage_->operations[prior] != source->operation_id);
        require_distinct_files(storage_->files, index);
        for (unsigned prior = 0; prior < index; ++prior)
            need(!same_file(
                storage_->files[prior].summary, source->file.summary));
        storage_->stage_identities[index] = selection_stage_identity(
            lineage, index, source->operation_id, contacts[index],
            source->file.summary);
        storage_->operations[index] = std::move(source->operation_id);
        storage_->files[index] = std::move(source->file);
        ++storage_->stage_count;
    } catch (...) {
        if (storage_ != nullptr) storage_->poisoned = true;
        refuse();
    }
}

RegisteredC1SelectedRound
RegisteredC1ControllerSelectionCallsite::finish() && {
    try {
        need(storage_ != nullptr && storage_->live);
        storage_->live = false;
        need(!storage_->poisoned && storage_->stage_count == 3 &&
             storage_->lineage.has_value());
        require_distinct_files(storage_->files, 3);
        for (const auto& file : storage_->files) revalidate(file);
        auto& lineage = storage_->lineage->value_;
        const auto contacts = expected_contacts(lineage.round);
        const auto generator = manifest_worker(
            lineage, ManifestComponent::C1Supervisor);
        const auto history = selection_history_identity(
            lineage, storage_->capture_identity, storage_->operations,
            contacts, storage_->stage_identities);
        C1AcceptedControllerSelectionAuthority selection(
            PublicC1AcceptedControllerSelection{
                .round = lineage.round,
                .capture_trial_id = lineage.capture_trial_id,
                .capture_attempt_id = lineage.capture_attempt_id,
                .capture_identity = storage_->capture_identity,
                .operation_ids = storage_->operations,
                .contact_owner_components = contacts,
                .registered_prelaunch_identity =
                    lineage.registered_prelaunch_identity,
                .round_capture_plan_identity = lineage.round_capture_plan,
                .generator_worker = generator,
                .accepted_stage_selection_identities =
                    storage_->stage_identities,
                .accepted_selection_history_identity = history,
            });
        auto selected = std::make_unique<RegisteredC1SelectedRound::Storage>(
            std::move(*storage_->lineage), std::move(selection),
            std::move(storage_->files));
        storage_->lineage.reset();
        storage_.reset();
        return RegisteredC1SelectedRound(std::move(selected));
    } catch (...) {
        if (storage_ != nullptr) storage_->poisoned = true;
        refuse();
    }
}

RegisteredC1SelectedLaunchCallsite::RegisteredC1SelectedLaunchCallsite(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {
    need(storage_ != nullptr);
}
RegisteredC1SelectedLaunchCallsite::RegisteredC1SelectedLaunchCallsite(
        RegisteredC1SelectedLaunchCallsite&&) noexcept = default;
RegisteredC1SelectedLaunchCallsite::~RegisteredC1SelectedLaunchCallsite() =
    default;

RegisteredC1SelectedLaunchCallsite
RegisteredC1RuntimeCallsiteBridge::prepare_selected(
        producer_runtime::ParentTenReadEndsAuthority& parent,
        RegisteredC1SelectedRound&& supplied) {
    try {
        need(supplied.storage_ != nullptr && supplied.storage_->live &&
             supplied.storage_->lineage.has_value() &&
             supplied.storage_->selection.has_value());
        supplied.storage_->live = false;
        for (const auto& file : supplied.storage_->selection_files)
            revalidate(file);
        auto prepared = RegisteredC1PlanRouteBridge::prepare(
            parent, std::move(*supplied.storage_->lineage),
            std::move(*supplied.storage_->selection));
        supplied.storage_->lineage.reset();
        supplied.storage_->selection.reset();
        auto offer = prepared.take_offer();
        auto pending = prepared.take_pending_terminal();
        auto storage =
            std::make_unique<RegisteredC1SelectedLaunchCallsite::Storage>(
                std::move(offer), std::move(pending),
                std::move(supplied.storage_->selection_files));
        supplied.storage_.reset();
        return RegisteredC1SelectedLaunchCallsite(std::move(storage));
    } catch (...) { refuse(); }
}

C1ContactValueOfferAuthority
RegisteredC1SelectedLaunchCallsite::take_fd31_offer() {
    try {
        need(storage_ != nullptr && storage_->live && !storage_->poisoned &&
             !storage_->offer_taken && storage_->offer.has_value());
        storage_->offer_taken = true;
        C1ContactValueOfferAuthority result(std::move(*storage_->offer));
        storage_->offer.reset();
        return result;
    } catch (...) {
        if (storage_ != nullptr) storage_->poisoned = true;
        refuse();
    }
}

RegisteredC1TerminalCallsite
RegisteredC1SelectedLaunchCallsite::take_terminal_callsite() {
    try {
        need(storage_ != nullptr && storage_->live && !storage_->poisoned &&
             storage_->offer_taken && !storage_->offer.has_value() &&
             storage_->pending.has_value());
        storage_->live = false;
        auto terminal = std::make_unique<RegisteredC1TerminalCallsite::Storage>(
            std::move(*storage_->pending),
            std::move(storage_->selection_files));
        storage_->pending.reset();
        storage_.reset();
        return RegisteredC1TerminalCallsite(std::move(terminal));
    } catch (...) {
        if (storage_ != nullptr) storage_->poisoned = true;
        refuse();
    }
}

RegisteredC1TerminalCallsite::RegisteredC1TerminalCallsite(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {
    need(storage_ != nullptr && storage_->pending.has_value());
    const auto& pending = *storage_->pending;
    storage_->source_selection = pending.selection_;
    storage_->source_selection_identity = pending.selection_identity_;
    storage_->source_contact_value_authority_identity =
        pending.expected_contact_value_authority_identity_;
    storage_->source_offer_file_sha256 = pending.expected_offer_file_sha256_;
    storage_->source_offer_device = pending.expected_offer_device_;
    storage_->source_offer_inode = pending.expected_offer_inode_;
    storage_->source_c1_process_identity =
        pending.expected_c1_process_identity_;
    storage_->source_c1_exit_policy_identity =
        pending.expected_c1_exit_policy_identity_;
}
RegisteredC1TerminalCallsite::RegisteredC1TerminalCallsite(
        RegisteredC1TerminalCallsite&&) noexcept = default;
RegisteredC1TerminalCallsite::~RegisteredC1TerminalCallsite() = default;

#ifdef KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP
C1ControllerSelectionSourceAuthority
RegisteredC1RouteMinterTestFixture::selection_source(
        RegisteredC1ControllerSelectionCallsite& callsite,
        C1ControllerStage stage, std::string operation_id,
        int controller_selection_fd) {
    need(callsite.storage_ != nullptr && callsite.storage_->live &&
         callsite.storage_->lineage.has_value());
    const auto& lineage = callsite.storage_->source_lineage;
    const auto index = stage_index(stage);
    const auto contacts = expected_contacts(lineage.round);
    auto storage =
        std::make_unique<C1ControllerSelectionSourceAuthority::Storage>();
    storage->round = lineage.round;
    storage->capture_trial_id = lineage.capture_trial_id;
    storage->capture_attempt_id = lineage.capture_attempt_id;
    storage->capture_identity = callsite.storage_->capture_identity;
    storage->registered_prelaunch_identity =
        lineage.registered_prelaunch_identity;
    storage->round_capture_plan_identity = lineage.round_capture_plan;
    storage->generator_worker = manifest_worker(
        lineage, ManifestComponent::C1Supervisor);
    storage->stage = stage;
    storage->operation_id = std::move(operation_id);
    storage->contact_owner_component = contacts[index];
    storage->file = bind_source_file(controller_selection_fd);
    return C1ControllerSelectionSourceAuthority(std::move(storage));
}

C1Fd31OfferParseSourceAuthority
RegisteredC1RouteMinterTestFixture::fd31_parse_source(
        RegisteredC1TerminalCallsite& callsite) {
    bool close_fd31 = true;
    try {
        need(callsite.storage_ != nullptr && callsite.storage_->live &&
             callsite.storage_->pending.has_value());
        struct stat state{};
        constexpr int required_seals = F_SEAL_SEAL | F_SEAL_SHRINK |
                                       F_SEAL_GROW | F_SEAL_WRITE;
        const auto observed_seals = ::fcntl(
            C1_CONTACT_VALUE_OFFER_FIXED_FD, F_GET_SEALS);
        need(::fstat(C1_CONTACT_VALUE_OFFER_FIXED_FD, &state) == 0 &&
             S_ISREG(state.st_mode) && state.st_uid == ::geteuid() &&
             (state.st_mode & 077) == 0 &&
             state.st_size ==
                 static_cast<off_t>(C1_CONTACT_VALUE_OFFER_BYTES) &&
             observed_seals >= 0 &&
             (observed_seals & required_seals) == required_seals);
        const auto summary = read_regular_source(
            C1_CONTACT_VALUE_OFFER_FIXED_FD);
        auto storage =
            std::make_unique<C1Fd31OfferParseSourceAuthority::Storage>();
        storage->selection_identity =
            callsite.storage_->source_selection_identity;
        storage->contact_value_authority_identity =
            callsite.storage_->source_contact_value_authority_identity;
        storage->offer_file = summary;
        storage->c1_process_identity =
            callsite.storage_->source_c1_process_identity;
        storage->expected_exit_policy_identity =
            callsite.storage_->source_c1_exit_policy_identity;
        storage->supervisor_worker =
            callsite.storage_->source_selection.generator_worker;
        storage->parse_monotonic_ns = monotonic_after(0);
        need(::close(C1_CONTACT_VALUE_OFFER_FIXED_FD) == 0);
        close_fd31 = false;
        return C1Fd31OfferParseSourceAuthority(std::move(storage));
    } catch (...) {
        if (close_fd31) (void)::close(C1_CONTACT_VALUE_OFFER_FIXED_FD);
        refuse();
    }
}

C1ControllerTerminalSourceAuthority
RegisteredC1RouteMinterTestFixture::terminal_source(
        RegisteredC1TerminalCallsite& callsite,
        C1ControllerStage stage, int controller_result_fd,
        int normalized_worker_exit_code) {
    need(callsite.storage_ != nullptr && callsite.storage_->live &&
         callsite.storage_->pending.has_value());
    const auto& selection = callsite.storage_->source_selection;
    const auto index = stage_index(stage);
    auto storage =
        std::make_unique<C1ControllerTerminalSourceAuthority::Storage>();
    storage->selection_identity =
        callsite.storage_->source_selection_identity;
    storage->round = selection.round;
    storage->stage = stage;
    storage->operation_id = selection.operation_ids[index];
    storage->generator_worker = selection.generator_worker;
    storage->normalized_worker_exit_code = normalized_worker_exit_code;
    storage->file = bind_source_file(controller_result_fd);
    return C1ControllerTerminalSourceAuthority(std::move(storage));
}

C1ObservedRouteSourceAuthority
RegisteredC1RouteMinterTestFixture::route_source(
        RegisteredC1TerminalCallsite& callsite,
        unsigned source_owner_component, int observed_route_fd,
        int normalized_worker_exit_code) {
    need(callsite.storage_ != nullptr && callsite.storage_->live &&
         callsite.storage_->pending.has_value() &&
         source_owner_component < 3);
    const auto& selection = callsite.storage_->source_selection;
    auto storage =
        std::make_unique<C1ObservedRouteSourceAuthority::Storage>();
    storage->selection_identity =
        callsite.storage_->source_selection_identity;
    storage->round = selection.round;
    storage->source_owner_component = source_owner_component;
    storage->target_owner_component =
        (source_owner_component + selection.round) % 3;
    storage->source_operation_id = selection.operation_ids[1];
    storage->target_invoice_operation_id =
        selection.operation_ids[0];
    storage->normalized_worker_exit_code = normalized_worker_exit_code;
    storage->file = bind_source_file(observed_route_fd);
    return C1ObservedRouteSourceAuthority(std::move(storage));
}

C1Fd31CompletionSourceAuthority
RegisteredC1RouteMinterTestFixture::completion_source(
        RegisteredC1TerminalCallsite& callsite,
        int normalized_supervisor_exit_code,
        unsigned observed_retry_count) {
    need(callsite.storage_ != nullptr && callsite.storage_->live &&
         callsite.storage_->pending.has_value() &&
         callsite.storage_->parse_observed);
    auto storage =
        std::make_unique<C1Fd31CompletionSourceAuthority::Storage>();
    storage->selection_identity =
        callsite.storage_->source_selection_identity;
    storage->contact_value_authority_identity =
        callsite.storage_->source_contact_value_authority_identity;
    storage->offer_file = {
        .raw_sha256 = callsite.storage_->source_offer_file_sha256,
        .device = callsite.storage_->source_offer_device,
        .inode = callsite.storage_->source_offer_inode,
        .byte_count = C1_CONTACT_VALUE_OFFER_BYTES,
    };
    storage->c1_process_identity =
        callsite.storage_->source_c1_process_identity;
    storage->expected_exit_policy_identity =
        callsite.storage_->source_c1_exit_policy_identity;
    storage->supervisor_worker =
        callsite.storage_->source_selection.generator_worker;
    storage->completion_monotonic_ns = monotonic_after(
        callsite.storage_->parse_ns);
    storage->writer_close_monotonic_ns = monotonic_after(
        storage->completion_monotonic_ns);
    storage->eof_monotonic_ns = monotonic_after(
        storage->writer_close_monotonic_ns);
    storage->exit_join_monotonic_ns = monotonic_after(
        storage->eof_monotonic_ns);
    storage->normalized_supervisor_exit_code =
        normalized_supervisor_exit_code;
    storage->observed_retry_count = observed_retry_count;
    return C1Fd31CompletionSourceAuthority(std::move(storage));
}
#endif

void RegisteredC1TerminalCallsite::observe_fd31_offer_parse(
        C1Fd31OfferParseSourceAuthority&& supplied_source) {
    try {
        need(storage_ != nullptr && storage_->live && !storage_->poisoned &&
             storage_->pending.has_value() &&
             !storage_->parse_observed && storage_->result_count == 0 &&
             storage_->route_count == 0 &&
             supplied_source.storage_ != nullptr);
        auto source = std::move(supplied_source.storage_);
        need(source->live);
        source->live = false;
        const auto& pending = *storage_->pending;
        need(source->selection_identity == pending.selection_identity_ &&
             source->contact_value_authority_identity ==
                 pending.expected_contact_value_authority_identity_ &&
             source->offer_file.raw_sha256 ==
                 pending.expected_offer_file_sha256_ &&
             source->offer_file.device == pending.expected_offer_device_ &&
             source->offer_file.inode == pending.expected_offer_inode_ &&
             source->offer_file.byte_count ==
                 C1_CONTACT_VALUE_OFFER_BYTES &&
             source->c1_process_identity ==
                 pending.expected_c1_process_identity_ &&
             source->expected_exit_policy_identity ==
                 pending.expected_c1_exit_policy_identity_ &&
             source->supervisor_worker ==
                 pending.selection_.generator_worker &&
             source->parse_monotonic_ns > 0);
        storage_->parse_ns = source->parse_monotonic_ns;
        storage_->parse_identity = fd31_event_identity(
            "offer-parse", pending.selection_identity_,
            pending.expected_contact_value_authority_identity_,
            pending.expected_offer_file_sha256_,
            pending.expected_offer_device_, pending.expected_offer_inode_,
            storage_->parse_ns);
        storage_->parse_observed = true;
    } catch (...) {
        if (storage_ != nullptr) storage_->poisoned = true;
        refuse();
    }
}

void RegisteredC1TerminalCallsite::observe_controller_terminal(
        C1ControllerTerminalSourceAuthority&& supplied_source) {
    try {
        need(storage_ != nullptr && storage_->live && !storage_->poisoned &&
             storage_->pending.has_value() && storage_->parse_observed &&
             !storage_->completion_observed &&
             supplied_source.storage_ != nullptr);
        auto source = std::move(supplied_source.storage_);
        need(source->live);
        source->live = false;
        const auto index = stage_index(source->stage);
        need(index == storage_->result_count &&
             source->normalized_worker_exit_code == 0);
        if (index == 2) need(storage_->route_count == 3);
        const auto& pending = *storage_->pending;
        need(source->selection_identity == pending.selection_identity_ &&
             source->round == pending.selection_.round &&
             source->operation_id ==
                 pending.selection_.operation_ids[index] &&
             source->generator_worker ==
                 pending.selection_.generator_worker);
        revalidate(source->file);
        require_distinct_files(storage_->result_files, index);
        require_no_file_overlap(
            storage_->selection_files, 3, storage_->result_files, index);
        for (const auto& file : storage_->selection_files)
            need(!same_file(file.summary, source->file.summary));
        for (unsigned prior = 0; prior < index; ++prior)
            need(!same_file(
                storage_->result_files[prior].summary,
                source->file.summary));
        for (unsigned prior = 0; prior < storage_->route_count; ++prior)
            need(!same_file(
                storage_->route_files[prior].summary,
                source->file.summary));
        storage_->result_identities[index] = controller_result_identity(
            pending.selection_identity_, pending.selection_.round, index,
            pending.selection_.operation_ids[index], source->file.summary);
        storage_->result_files[index] = std::move(source->file);
        ++storage_->result_count;
    } catch (...) {
        if (storage_ != nullptr) storage_->poisoned = true;
        refuse();
    }
}

void RegisteredC1TerminalCallsite::observe_route_artifact(
        C1ObservedRouteSourceAuthority&& supplied_source) {
    try {
        need(storage_ != nullptr && storage_->live && !storage_->poisoned &&
             storage_->pending.has_value() && storage_->parse_observed &&
             !storage_->completion_observed &&
             storage_->result_count == 2 && storage_->route_count < 3 &&
             supplied_source.storage_ != nullptr);
        auto source = std::move(supplied_source.storage_);
        need(source->live);
        source->live = false;
        const auto& selection = storage_->pending->selection_;
        need(source->selection_identity ==
                 storage_->pending->selection_identity_ &&
             source->round == selection.round &&
             source->source_owner_component == storage_->route_count &&
             source->target_owner_component ==
                 (source->source_owner_component + selection.round) % 3 &&
             source->source_operation_id == selection.operation_ids[1] &&
             source->target_invoice_operation_id ==
                 selection.operation_ids[0] &&
             source->normalized_worker_exit_code == 0);
        revalidate(source->file);
        for (const auto& file : storage_->selection_files)
            need(!same_file(file.summary, source->file.summary));
        for (unsigned prior = 0; prior < storage_->result_count; ++prior)
            need(!same_file(
                storage_->result_files[prior].summary,
                source->file.summary));
        for (unsigned prior = 0; prior < storage_->route_count; ++prior)
            need(!same_file(
                storage_->route_files[prior].summary,
                source->file.summary));
        PublicC1ObservedRouteArtifact artifact{
            .source_owner_component = source->source_owner_component,
            .target_owner_component = source->target_owner_component,
            .source_operation_id = source->source_operation_id,
            .target_invoice_operation_id =
                source->target_invoice_operation_id,
            .raw_bytes_sha256 = source->file.summary.raw_sha256,
            .device = source->file.summary.device,
            .inode = source->file.summary.inode,
            .byte_count = source->file.summary.byte_count,
        };
        artifact.record_identity =
            route_artifact_identity(selection.round, artifact);
        storage_->route_artifacts[storage_->route_count] =
            std::move(artifact);
        storage_->route_files[storage_->route_count] =
            std::move(source->file);
        ++storage_->route_count;
    } catch (...) {
        if (storage_ != nullptr) storage_->poisoned = true;
        refuse();
    }
}

void RegisteredC1TerminalCallsite::observe_authenticated_completion(
        C1Fd31CompletionSourceAuthority&& supplied_source) {
    try {
        need(storage_ != nullptr && storage_->live && !storage_->poisoned &&
             storage_->pending.has_value() && storage_->parse_observed &&
             !storage_->completion_observed &&
             storage_->result_count == 3 && storage_->route_count == 3 &&
             supplied_source.storage_ != nullptr);
        auto source = std::move(supplied_source.storage_);
        need(source->live);
        source->live = false;
        for (const auto& file : storage_->selection_files) revalidate(file);
        for (const auto& file : storage_->result_files) revalidate(file);
        for (const auto& file : storage_->route_files) revalidate(file);
        const auto& pending = *storage_->pending;
        need(source->selection_identity == pending.selection_identity_ &&
             source->contact_value_authority_identity ==
                 pending.expected_contact_value_authority_identity_ &&
             source->offer_file.raw_sha256 ==
                 pending.expected_offer_file_sha256_ &&
             source->offer_file.device == pending.expected_offer_device_ &&
             source->offer_file.inode == pending.expected_offer_inode_ &&
             source->offer_file.byte_count ==
                 C1_CONTACT_VALUE_OFFER_BYTES &&
             source->c1_process_identity ==
                 pending.expected_c1_process_identity_ &&
             source->expected_exit_policy_identity ==
                 pending.expected_c1_exit_policy_identity_ &&
             source->supervisor_worker ==
                 pending.selection_.generator_worker &&
             source->completion_monotonic_ns > storage_->parse_ns &&
             source->writer_close_monotonic_ns >
                 source->completion_monotonic_ns &&
             source->eof_monotonic_ns >
                 source->writer_close_monotonic_ns &&
             source->exit_join_monotonic_ns >
                 source->eof_monotonic_ns &&
             source->normalized_supervisor_exit_code == 0 &&
             source->observed_retry_count == 0);
        std::array<Digest, 6> attached{};
        std::copy(storage_->result_identities.begin(),
                  storage_->result_identities.end(), attached.begin());
        for (unsigned index = 0; index < 3; ++index)
            attached[index + 3] =
                storage_->route_artifacts[index].record_identity;
        storage_->completion_ns = source->completion_monotonic_ns;
        storage_->completion_identity = fd31_event_identity(
            "authenticated-completion", pending.selection_identity_,
            pending.expected_contact_value_authority_identity_,
            pending.expected_offer_file_sha256_,
            pending.expected_offer_device_, pending.expected_offer_inode_,
            storage_->completion_ns, &storage_->parse_identity, attached);
        storage_->writer_close_ns = source->writer_close_monotonic_ns;
        storage_->writer_close_identity = fd31_event_identity(
            "writer-close", pending.selection_identity_,
            pending.expected_contact_value_authority_identity_,
            pending.expected_offer_file_sha256_,
            pending.expected_offer_device_, pending.expected_offer_inode_,
            storage_->writer_close_ns, &storage_->completion_identity);
        storage_->eof_ns = source->eof_monotonic_ns;
        storage_->eof_identity = fd31_event_identity(
            "eof", pending.selection_identity_,
            pending.expected_contact_value_authority_identity_,
            pending.expected_offer_file_sha256_,
            pending.expected_offer_device_, pending.expected_offer_inode_,
            storage_->eof_ns, &storage_->writer_close_identity);
        storage_->exit_ns = source->exit_join_monotonic_ns;
        std::array<Digest, 1> exit_attached{
            pending.expected_c1_exit_policy_identity_};
        storage_->exit_identity = fd31_event_identity(
            "expected-exit", pending.selection_identity_,
            pending.expected_contact_value_authority_identity_,
            pending.expected_offer_file_sha256_,
            pending.expected_offer_device_, pending.expected_offer_inode_,
            storage_->exit_ns, &storage_->eof_identity, exit_attached);
        storage_->completion_observed = true;
        storage_->writer_close_observed = true;
        storage_->eof_observed = true;
        storage_->exit_observed = true;
    } catch (...) {
        if (storage_ != nullptr) storage_->poisoned = true;
        refuse();
    }
}

RegisteredC1RoundRouteEvidenceAuthority::
RegisteredC1RoundRouteEvidenceAuthority(std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }
RegisteredC1RoundRouteEvidenceAuthority::
RegisteredC1RoundRouteEvidenceAuthority(
        RegisteredC1RoundRouteEvidenceAuthority&&) noexcept = default;
RegisteredC1RoundRouteEvidenceAuthority::~
RegisteredC1RoundRouteEvidenceAuthority() = default;

RegisteredC1TerminalAdmissionSplit::RegisteredC1TerminalAdmissionSplit(
        C1PostcaptureAdmissionAuthority&& admission,
        RegisteredC1RoundRouteEvidenceAuthority&& evidence)
    : admission_(std::in_place, std::move(admission)),
      route_evidence_(std::in_place, std::move(evidence)) {}

C1PostcaptureAdmissionAuthority
RegisteredC1TerminalAdmissionSplit::take_admission() {
    need(admission_.has_value());
    C1PostcaptureAdmissionAuthority result(std::move(*admission_));
    admission_.reset();
    return result;
}

RegisteredC1RoundRouteEvidenceAuthority
RegisteredC1TerminalAdmissionSplit::take_route_evidence() {
    need(route_evidence_.has_value());
    RegisteredC1RoundRouteEvidenceAuthority result(
        std::move(*route_evidence_));
    route_evidence_.reset();
    return result;
}

RegisteredC1TerminalAdmissionSplit
RegisteredC1TerminalCallsite::finish() && {
    try {
        need(storage_ != nullptr && storage_->live);
        storage_->live = false;
        need(!storage_->poisoned && storage_->pending.has_value() &&
             storage_->parse_observed && storage_->completion_observed &&
             storage_->writer_close_observed && storage_->eof_observed &&
             storage_->exit_observed && storage_->result_count == 3 &&
             storage_->route_count == 3);
        for (const auto& file : storage_->selection_files) revalidate(file);
        for (const auto& file : storage_->result_files) revalidate(file);
        for (const auto& file : storage_->route_files) revalidate(file);
        auto& pending = *storage_->pending;
        const auto selection = pending.selection_;
        PublicC1Fd31QualifiedCompletionAck ack{
            .round = selection.round,
            .capture_trial_id = selection.capture_trial_id,
            .capture_attempt_id = selection.capture_attempt_id,
            .capture_identity = selection.capture_identity,
            .operation_ids = selection.operation_ids,
            .contact_owner_components = selection.contact_owner_components,
            .registered_prelaunch_identity =
                selection.registered_prelaunch_identity,
            .round_capture_plan_identity =
                selection.round_capture_plan_identity,
            .accepted_selection_identity = pending.selection_identity_,
            .contact_value_authority_identity =
                pending.expected_contact_value_authority_identity_,
            .offer_file_sha256 = pending.expected_offer_file_sha256_,
            .offer_device = pending.expected_offer_device_,
            .offer_inode = pending.expected_offer_inode_,
            .offer_byte_count = C1_CONTACT_VALUE_OFFER_BYTES,
            .fixed_fd = C1_CONTACT_VALUE_OFFER_FIXED_FD,
            .c1_process_identity = pending.expected_c1_process_identity_,
            .expected_exit_policy_identity =
                pending.expected_c1_exit_policy_identity_,
            .supervisor_worker = selection.generator_worker,
            .exact_offer_parse_identity = storage_->parse_identity,
            .authenticated_completion_identity =
                storage_->completion_identity,
            .writer_close_identity = storage_->writer_close_identity,
            .eof_identity = storage_->eof_identity,
            .exit_join_identity = storage_->exit_identity,
            .offer_parse_monotonic_ns = storage_->parse_ns,
            .completion_ack_monotonic_ns = storage_->completion_ns,
            .writer_close_monotonic_ns = storage_->writer_close_ns,
            .eof_monotonic_ns = storage_->eof_ns,
            .exit_join_monotonic_ns = storage_->exit_ns,
            .exact_fd31_read = true,
            .fallback_offer_absent = true,
            .authenticated_completion = true,
            .writer_closed = true,
            .eof_observed = true,
            .expected_exit_observed = true,
        };
        PublicC1AcceptedControllerResult terminal{
            .round = selection.round,
            .capture_trial_id = selection.capture_trial_id,
            .capture_attempt_id = selection.capture_attempt_id,
            .capture_identity = selection.capture_identity,
            .operation_ids = selection.operation_ids,
            .registered_prelaunch_identity =
                selection.registered_prelaunch_identity,
            .round_capture_plan_identity =
                selection.round_capture_plan_identity,
            .accepted_selection_identity = pending.selection_identity_,
            .fd31_authenticated_completion_identity =
                storage_->completion_identity,
            .controller_result_identities = storage_->result_identities,
            .retry_history_identity = empty_retry_history_identity(
                pending.selection_identity_, selection.round),
            .generator_worker = selection.generator_worker,
            .completed_stage_count = 3,
            .retry_count = 0,
        };
        terminal.terminal_history_identity =
            terminal_history_identity(terminal);
        PublicC1ObservedInvoiceRoute route{
            .round = selection.round,
            .capture_trial_id = selection.capture_trial_id,
            .capture_attempt_id = selection.capture_attempt_id,
            .capture_identity = selection.capture_identity,
            .operation_ids = selection.operation_ids,
            .contact_owner_components = selection.contact_owner_components,
            .registered_prelaunch_identity =
                selection.registered_prelaunch_identity,
            .round_capture_plan_identity =
                selection.round_capture_plan_identity,
            .accepted_selection_identity = pending.selection_identity_,
            .fd31_authenticated_completion_identity =
                storage_->completion_identity,
            .invoice_result_identity = storage_->result_identities[0],
            .pay_result_identity = storage_->result_identities[1],
            .route_artifacts = storage_->route_artifacts,
            .retry_history_identity = terminal.retry_history_identity,
            .terminal_history_identity =
                terminal.terminal_history_identity,
            .projection_identity = pending.expected_projection_identity_,
            .generator_worker = selection.generator_worker,
            .validator_worker = pending.expected_validator_worker_,
            .worker_returncodes = {0, 0, 0},
        };

        auto evidence =
            std::make_unique<RegisteredC1RoundRouteEvidenceAuthority::Storage>();
        evidence->round = selection.round;
        evidence->capture_trial_id = selection.capture_trial_id;
        evidence->capture_attempt_id = selection.capture_attempt_id;
        evidence->capture_identity = selection.capture_identity;
        evidence->operation_ids = selection.operation_ids;
        evidence->contacts = selection.contact_owner_components;
        evidence->registered_prelaunch_identity =
            selection.registered_prelaunch_identity;
        evidence->round_capture_plan_identity =
            selection.round_capture_plan_identity;
        evidence->selection_identity = pending.selection_identity_;
        evidence->contact_value_authority_identity =
            pending.expected_contact_value_authority_identity_;
        evidence->offer_file_sha256 = pending.expected_offer_file_sha256_;
        evidence->offer_device = pending.expected_offer_device_;
        evidence->offer_inode = pending.expected_offer_inode_;
        evidence->c1_process_identity = pending.expected_c1_process_identity_;
        evidence->expected_exit_policy_identity =
            pending.expected_c1_exit_policy_identity_;
        evidence->parse_identity = storage_->parse_identity;
        evidence->completion_identity = storage_->completion_identity;
        evidence->writer_close_identity = storage_->writer_close_identity;
        evidence->eof_identity = storage_->eof_identity;
        evidence->exit_identity = storage_->exit_identity;
        evidence->result_identities = storage_->result_identities;
        evidence->retry_history_identity = terminal.retry_history_identity;
        evidence->terminal_history_identity =
            terminal.terminal_history_identity;
        evidence->projection_identity = pending.expected_projection_identity_;
        evidence->generator_worker = selection.generator_worker;
        evidence->validator_worker = pending.expected_validator_worker_;
        evidence->route_artifacts = storage_->route_artifacts;
        for (unsigned index = 0; index < 3; ++index) {
            evidence->selection_files[index] =
                storage_->selection_files[index].summary;
            evidence->result_files[index] =
                storage_->result_files[index].summary;
            evidence->route_files[index] =
                storage_->route_files[index].summary;
        }
        evidence->identity = round_evidence_identity(*evidence);
        validate_round_evidence(*evidence);

        C1Fd31QualifiedCompletionAckAuthority ack_authority(std::move(ack));
        C1AcceptedControllerResultAuthority terminal_authority(
            std::move(terminal));
        C1ObservedInvoiceRouteAuthority route_authority(std::move(route));
        auto admission = RegisteredC1PlanRouteBridge::admit_terminal(
            std::move(pending), std::move(ack_authority),
            std::move(terminal_authority), std::move(route_authority));
        storage_->pending.reset();
        auto route_evidence = RegisteredC1RoundRouteEvidenceAuthority(
            std::move(evidence));
        storage_.reset();
        return RegisteredC1TerminalAdmissionSplit(
            std::move(admission), std::move(route_evidence));
    } catch (...) {
        if (storage_ != nullptr) storage_->poisoned = true;
        refuse();
    }
}

RegisteredC1TwoRoundRouteEvidenceAuthority::
RegisteredC1TwoRoundRouteEvidenceAuthority(std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }
RegisteredC1TwoRoundRouteEvidenceAuthority::
RegisteredC1TwoRoundRouteEvidenceAuthority(
        RegisteredC1TwoRoundRouteEvidenceAuthority&&) noexcept = default;
RegisteredC1TwoRoundRouteEvidenceAuthority::~
RegisteredC1TwoRoundRouteEvidenceAuthority() = default;

RegisteredC1TwoRoundRouteEvidenceJoiner::
RegisteredC1TwoRoundRouteEvidenceJoiner()
    : storage_(std::make_unique<Storage>()) {}
RegisteredC1TwoRoundRouteEvidenceJoiner::
RegisteredC1TwoRoundRouteEvidenceJoiner(
        RegisteredC1TwoRoundRouteEvidenceJoiner&&) noexcept = default;
RegisteredC1TwoRoundRouteEvidenceJoiner::~
RegisteredC1TwoRoundRouteEvidenceJoiner() = default;

void RegisteredC1TwoRoundRouteEvidenceJoiner::accept(
        RegisteredC1RoundRouteEvidenceAuthority&& supplied) {
    try {
        need(storage_ != nullptr && storage_->live && !storage_->poisoned &&
             storage_->count < 2 && supplied.storage_ != nullptr);
        auto evidence = std::move(supplied.storage_);
        need(evidence->live);
        evidence->live = false;
        validate_round_evidence(*evidence);
        need(evidence->round == storage_->count + 1);
        if (storage_->count == 1)
            validate_two_round_pair(*storage_->rounds[0], *evidence);
        storage_->rounds[storage_->count] = std::move(evidence);
        ++storage_->count;
    } catch (...) {
        if (storage_ != nullptr) storage_->poisoned = true;
        refuse();
    }
}

RegisteredC1TwoRoundRouteEvidenceAuthority
RegisteredC1TwoRoundRouteEvidenceJoiner::finish() && {
    try {
        need(storage_ != nullptr && storage_->live);
        storage_->live = false;
        need(!storage_->poisoned && storage_->count == 2 &&
             storage_->rounds[0] != nullptr &&
             storage_->rounds[1] != nullptr);
        validate_two_round_pair(
            *storage_->rounds[0], *storage_->rounds[1]);
        Bytes bytes(TWO_ROUND_EVIDENCE_DOMAIN.begin(),
                    TWO_ROUND_EVIDENCE_DOMAIN.end());
        add(bytes, storage_->rounds[0]->identity);
        add(bytes, storage_->rounds[1]->identity);
        auto result =
            std::make_unique<RegisteredC1TwoRoundRouteEvidenceAuthority::Storage>();
        result->rounds = std::move(storage_->rounds);
        result->identity = hash(bytes);
        need(result->rounds[0] != nullptr && result->rounds[1] != nullptr &&
             nonzero(result->identity));
        storage_.reset();
        return RegisteredC1TwoRoundRouteEvidenceAuthority(
            std::move(result));
    } catch (...) {
        if (storage_ != nullptr) storage_->poisoned = true;
        refuse();
    }
}

} // namespace kpb::measurement::c1_capture
