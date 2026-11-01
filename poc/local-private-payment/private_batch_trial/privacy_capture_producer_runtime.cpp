#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "privacy_capture_producer_runtime.hpp"
#include "privacy_capture_producer_archive.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <exception>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <new>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <poll.h>
#include <set>
#include <signal.h>
#include <span>
#include <string_view>
#include <type_traits>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpb::measurement::producer_runtime {
namespace {

using Bytes = std::vector<unsigned char>;
constexpr std::array<unsigned char, 8> EVENT_MAGIC{
    'K', 'P', 'B', 'C', 'E', 'V', '0', '1'};
constexpr std::array<unsigned char, 8> P1_MAGIC{
    'K', 'P', 'B', 'P', '1', 'C', '0', '3'};
constexpr std::array<unsigned char, 8> PACKET_MAGIC{
    'K', 'P', 'B', 'P', 'R', 'D', '0', '1'};
constexpr std::size_t EVENT_HEADER_BYTES = 17;
constexpr std::size_t P1_HEADER_BYTES = 112;
constexpr std::uint64_t PROJECTION_BYTES = 10685;
constexpr std::uint64_t P1_CHUNK_BYTES = 1U << 16;
constexpr std::uint64_t EVENT_RECORD_BYTES = 1U << 20;
constexpr std::uint64_t EVENT_RECORDS = 1U << 16;

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}
bool lowercase_uuid_v4(const std::string& value) {
    if (value.size() != 36 || value[14] != '4' ||
        std::string_view("89ab").find(value[19]) ==
            std::string_view::npos)
        return false;
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (index == 8 || index == 13 || index == 18 || index == 23) {
            if (value[index] != '-') return false;
        } else if (!((value[index] >= '0' && value[index] <= '9') ||
                     (value[index] >= 'a' && value[index] <= 'f'))) {
            return false;
        }
    }
    return true;
}
void close_if_open(int& fd) noexcept {
    if (fd < 0) return;
    while (::close(fd) != 0 && errno == EINTR) {}
    fd = -1;
}

int open_pidfd(pid_t pid) {
#ifdef SYS_pidfd_open
    const auto result = static_cast<int>(::syscall(SYS_pidfd_open, pid, 0));
    need(result >= 0 &&
         (::fcntl(result, F_GETFD) & FD_CLOEXEC) != 0);
    return result;
#else
    (void)pid;
    refuse();
#endif
}

void signal_pidfd(int pidfd, int signal) {
#ifdef SYS_pidfd_send_signal
    need(pidfd >= 0);
    const auto result =
        ::syscall(SYS_pidfd_send_signal, pidfd, signal, nullptr, 0);
    need(result == 0 || (result < 0 && errno == ESRCH));
#else
    (void)pidfd;
    (void)signal;
    refuse();
#endif
}

bool observe_pidfd_exit(int pidfd) {
    if (pidfd < 0) return false;
    struct pollfd selected{
        .fd = pidfd,
        .events = static_cast<short>(POLLIN),
        .revents = 0,
    };
    int result;
    do { result = ::poll(&selected, 1, -1); }
    while (result < 0 && errno == EINTR);
    return result == 1 &&
        (selected.revents & (POLLIN | POLLHUP)) != 0 &&
        (selected.revents & (POLLERR | POLLNVAL)) == 0;
}

struct ReceivedArchiveFds final {
    std::array<int, producer_archive::PRODUCER_ARCHIVE_STREAM_COUNT> values{};
    ReceivedArchiveFds() { values.fill(-1); }
    ReceivedArchiveFds(const ReceivedArchiveFds&) = delete;
    ReceivedArchiveFds& operator=(const ReceivedArchiveFds&) = delete;
    ~ReceivedArchiveFds() {
        for (auto& fd : values) close_if_open(fd);
    }
};
void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add(Bytes& out, const char* value) {
    while (*value) out.push_back(static_cast<unsigned char>(*value++));
}
void integer(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}
void add_string(Bytes& out, const std::string& value) {
    integer(out, value.size());
    add(out, {reinterpret_cast<const unsigned char*>(value.data()),
              value.size()});
}
void big_integer(Bytes& out, std::uint64_t value, unsigned width) {
    need(width > 0 && width <= 8);
    for (unsigned offset = 0; offset < width; ++offset)
        out.push_back(static_cast<unsigned char>(
            value >> (8 * (width - offset - 1))));
}
Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    need(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}

Digest registered_trial_identity(std::string_view value) {
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_TRIAL_UUID_IDENTITY_V1\n");
    integer(bytes, value.size());
    add(bytes, std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
    return hash(bytes);
}

Digest capture_attempt_identity(std::string_view value) {
    Bytes bytes;
    add(bytes, "KPB_CAPTURE_ATTEMPT_ID_V1\n");
    add(bytes, std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
    return hash(bytes);
}

std::uint64_t observed_monotonic_ns() {
    timespec now{};
    need(::clock_gettime(CLOCK_MONOTONIC, &now) == 0 &&
         now.tv_sec >= 0 && now.tv_nsec >= 0 && now.tv_nsec < 1000000000L);
    const auto seconds = static_cast<std::uint64_t>(now.tv_sec);
    need(seconds <= (std::numeric_limits<std::uint64_t>::max() -
                     static_cast<std::uint64_t>(now.tv_nsec)) /
                        1000000000ULL);
    return seconds * 1000000000ULL +
        static_cast<std::uint64_t>(now.tv_nsec);
}

class HashState final {
    EVP_MD_CTX* context_{EVP_MD_CTX_new()};
    bool finished_{};
public:
    HashState() {
        need(context_ != nullptr &&
             EVP_DigestInit_ex(context_, EVP_sha256(), nullptr) == 1);
    }
    HashState(const HashState&) = delete;
    HashState& operator=(const HashState&) = delete;
    ~HashState() { EVP_MD_CTX_free(context_); }
    void update(std::span<const unsigned char> value) {
        need(!finished_ && EVP_DigestUpdate(
            context_, value.data(), value.size()) == 1);
    }
    Digest finish() {
        need(!finished_); finished_ = true;
        Digest result{}; unsigned length = 0;
        need(EVP_DigestFinal_ex(context_, result.data(), &length) == 1 &&
             length == result.size());
        return result;
    }
};

std::uint64_t be64(const unsigned char* value) {
    std::uint64_t result = 0;
    for (unsigned index = 0; index < 8; ++index)
        result = (result << 8) | value[index];
    return result;
}
std::uint32_t be32(const unsigned char* value) {
    std::uint32_t result = 0;
    for (unsigned index = 0; index < 4; ++index)
        result = (result << 8) | value[index];
    return result;
}

const ManifestEntry& manifest_entry(const RunBinding& binding,
                                    ManifestComponent component) {
    const auto index = static_cast<unsigned>(component) - 1;
    need(index < binding.finite_manifest.entries.size());
    const auto& result = binding.finite_manifest.entries[index];
    need(result.component == component);
    return result;
}
WorkerBinding worker(const ManifestEntry& value) {
    return {
        .source_identity = value.source_identity,
        .build_identity = value.build_identity,
        .runtime_identity = value.runtime_identity,
        .assets_identity = value.assets_identity,
        .pinned_executable_identity = value.pinned_executable_identity,
        .launcher_identity = value.launcher_identity,
    };
}
ManifestComponent component(CaptureKind kind) {
    switch (kind) {
    case CaptureKind::PublicProjection:
        return ManifestComponent::FinancialCore;
    case CaptureKind::TerminalHistory:
        return ManifestComponent::TerminalCapture;
    case CaptureKind::Dispatcher:
        return ManifestComponent::Dispatcher;
    case CaptureKind::CorruptServer:
        return ManifestComponent::P1Capture;
    case CaptureKind::ColluderWallet:
        return ManifestComponent::C1Supervisor;
    }
    refuse();
}

void validate_requirement(
        const PublicAggregateMailboxRouteRequirement& route,
        const RunBinding& binding, unsigned round) {
    need(route.round == round &&
         route.projection_identity == binding.projections[round - 1] &&
         route.projection_bytes == PROJECTION_BYTES &&
         route.route_endpoint_count == 1 && route.owner_ack_count == 0 &&
         route.role_blind_required &&
         route.after_full_cohort_barrier_required &&
         route.owner_socket_or_path_derivation_forbidden);
}

void validate_route(const PublicAggregateMailboxRouteCompletion& route,
                    const PublicAggregateMailboxRouteRequirement& requirement,
                    const RunBinding& binding, unsigned round) {
    validate_requirement(requirement, binding, round);
    need(route.round == round && nonzero(route.route_identity) &&
         nonzero(route.full_cohort_barrier_identity) &&
         route.projection_identity == requirement.projection_identity &&
         route.projection_bytes == requirement.projection_bytes &&
         route.full_cohort_barrier_observed_monotonic_ns > 0 &&
         route.route_observed_monotonic_ns >
             route.full_cohort_barrier_observed_monotonic_ns &&
         route.route_endpoint_count == requirement.route_endpoint_count &&
         route.owner_ack_count == requirement.owner_ack_count &&
         route.role_blind && route.after_full_cohort_barrier &&
         !route.owner_socket_or_path_derived);
}

Digest route_requirement_identity(
        const PublicAggregateMailboxRouteRequirement& route) {
    Bytes value;
    add(value, "kpb-capture-producer-route-requirement/v1");
    integer(value, route.round);
    add(value, route.projection_identity);
    integer(value, route.projection_bytes);
    integer(value, route.route_endpoint_count);
    integer(value, route.owner_ack_count);
    value.push_back(route.role_blind_required ? 1 : 0);
    value.push_back(route.after_full_cohort_barrier_required ? 1 : 0);
    value.push_back(
        route.owner_socket_or_path_derivation_forbidden ? 1 : 0);
    return hash(value);
}

void validate_plan(const PublicProducerLaunchPlan& value) {
    validate_measurement_run_binding(value.binding);
    need(lowercase_uuid_v4(value.capture_trial_id) &&
         lowercase_uuid_v4(value.capture_attempt_ids[0]) &&
         lowercase_uuid_v4(value.capture_attempt_ids[1]) &&
         value.capture_trial_id != value.capture_attempt_ids[0] &&
         value.capture_trial_id != value.capture_attempt_ids[1] &&
         value.capture_attempt_ids[0] != value.capture_attempt_ids[1] &&
         value.binding.trial ==
             registered_trial_identity(value.capture_trial_id) &&
         value.binding.round_attempts[0] ==
             capture_attempt_identity(value.capture_attempt_ids[0]) &&
         value.binding.round_attempts[1] ==
             capture_attempt_identity(value.capture_attempt_ids[1]));
    for (const auto* digest : {
             &value.producer_process_identity,
             &value.role_closure_identity, &value.manifest_seal,
             &value.construction_classification_receipt,
             &value.opaque_closure_authority_identity})
        need(nonzero(*digest));
    const auto& producer = manifest_entry(
        value.binding, ManifestComponent::Producer);
    for (const auto* digest : {
             &producer.source_identity, &producer.build_identity,
             &producer.runtime_identity, &producer.assets_identity,
             &producer.pinned_executable_identity,
             &producer.launcher_identity})
        need(nonzero(*digest));
    need((value.binding.classification == Classification::TransparentBaseline &&
          value.construction_policy ==
              ConstructionPolicy::ExplicitOwnerPublicEffects) ||
         (value.binding.classification == Classification::HiddenCandidate &&
          value.construction_policy ==
              ConstructionPolicy::SecretPermutationIndependent));
    validate_requirement(value.route_requirements[0], value.binding, 1);
    validate_requirement(value.route_requirements[1], value.binding, 2);
    for (unsigned index = 0; index < value.streams.size(); ++index) {
        const auto& stream = value.streams[index];
        need(stream.round == index / 5 + 1 &&
             stream.kind == static_cast<CaptureKind>(index % 5 + 1) &&
             stream.fixed_fd == 20 + index &&
             nonzero(stream.process_identity) &&
             nonzero(stream.child_exit_identity));
        const auto& selected = manifest_entry(
            value.binding, component(stream.kind));
        for (const auto* digest : {
                 &selected.source_identity, &selected.build_identity,
                 &selected.runtime_identity, &selected.launcher_identity})
            need(nonzero(*digest));
    need(value.producer_process_identity ==
             value.binding.outer_parent_process &&
         value.role_closure_identity == value.binding.source_closure &&
         value.manifest_seal ==
             value.binding.finite_manifest.manifest_identity);
    }
}

struct Fingerprint {
    std::uint64_t device{};
    std::uint64_t inode{};
    std::uint32_t type{};
};
Fingerprint fingerprint(int fd) {
    struct stat value{};
    need(fd >= 0 && ::fstat(fd, &value) == 0);
    const int flags = ::fcntl(fd, F_GETFL);
    const auto type = static_cast<std::uint32_t>(value.st_mode & S_IFMT);
    need(flags >= 0 && (flags & O_ACCMODE) == O_RDONLY &&
         (type == S_IFIFO || type == S_IFSOCK));
    return {static_cast<std::uint64_t>(value.st_dev),
            static_cast<std::uint64_t>(value.st_ino), type};
}

struct WireStreamResult {
    std::uint64_t record_count{};
    std::uint64_t payload_bytes{};
    std::uint64_t raw_wire_bytes{};
    Digest record_root{};
    Digest end_frame_identity{};
    Digest eof_identity{};
    bool operator==(const WireStreamResult&) const = default;
};
struct ChildPacket {
    std::array<unsigned char, 8> magic{};
    RunBinding binding;
    Digest opaque_closure_authority_identity{};
    std::array<WireStreamResult, 10> streams{};
    std::uint8_t attempt_complete{};
    std::uint8_t first_failed_slot{0xff};
    ProducerAttemptDrainFailure attempt_failure{};
    std::array<ProducerAttemptC03StreamState, 2> c03_states{};
    std::array<ProducerAttemptDrainFailure, 2> c03_failures{};
    std::array<unsigned, 2> partial_source_slots{};
    std::array<unsigned, 2> partial_fixed_fds{};
    std::array<std::uint64_t, 2> partial_devices{};
    std::array<std::uint64_t, 2> partial_inodes{};
    std::array<std::uint64_t, 2> partial_sizes{};
    std::array<int, 2> partial_seals{};
    std::array<Digest, 2> partial_sha256{};
    std::array<bool, 2> partial_complete_end_and_eof{};
    std::array<ProducerStreamClosureEvidence, 2> partial_evidence{};
    Digest identity{};
};
static_assert(std::is_trivially_copyable_v<ChildPacket>);

struct DrainedCapture {
    ChildPacket packet;
    std::unique_ptr<producer_archive::ProducerSealedArchiveAuthority> archive;
    std::unique_ptr<producer_archive::ProducerSealedArchiveBuilder>
        partial_builder;
};
Digest packet_identity(const ChildPacket& value) {
    return hash({reinterpret_cast<const unsigned char*>(&value),
                 offsetof(ChildPacket, identity)});
}

enum class WireKind : unsigned char { Unknown, Event, P1 };
enum class EventPhase : unsigned char {
    Hello, Payload, ProjectionEnd, Records, P1Seal, P1Completeness, End,
};

class StreamParser final {
    unsigned round_;
    CaptureKind kind_;
    WireKind wire_{WireKind::Unknown};
    EventPhase phase_{EventPhase::Hello};
    Bytes header_;
    std::size_t header_target_{8};
    Bytes payload_;
    std::uint64_t payload_target_{};
    std::uint8_t tag_{};
    std::uint64_t sequence_{};
    std::uint64_t last_monotonic_ns_{};
    bool saw_event_record_{};
    bool saw_p1_data_{};
    bool eof_{};
    HashState wire_hash_;
    WireStreamResult result_{};

    bool projection() const {
        return kind_ == CaptureKind::PublicProjection;
    }

    void start_event() {
        need(kind_ != CaptureKind::CorruptServer);
        need(header_.size() == EVENT_HEADER_BYTES &&
             std::equal(EVENT_MAGIC.begin(), EVENT_MAGIC.end(),
                        header_.begin()));
        tag_ = header_[8];
        payload_target_ = be64(header_.data() + 9);
        need(tag_ >= 1 && tag_ <= 5);
        switch (phase_) {
        case EventPhase::Hello:
            need(tag_ == 1 && payload_target_ > 0 &&
                 payload_target_ <= (1U << 12));
            break;
        case EventPhase::Payload:
            if (projection())
                need(tag_ == 4 && payload_target_ == PROJECTION_BYTES);
            else
                need(tag_ == 2 && payload_target_ > 0 &&
                     payload_target_ <= (1U << 16));
            break;
        case EventPhase::ProjectionEnd:
            need(tag_ == 5 && payload_target_ == 0);
            break;
        case EventPhase::Records:
            need((tag_ == 3 && payload_target_ > 0 &&
                  payload_target_ <= EVENT_RECORD_BYTES) ||
                 (tag_ == 5 && payload_target_ == 0 &&
                  saw_event_record_));
            break;
        default:
            refuse();
        }
        payload_.clear();
        need(payload_target_ <= std::numeric_limits<std::size_t>::max());
        payload_.reserve(static_cast<std::size_t>(payload_target_));
    }

    void start_p1() {
        need(kind_ == CaptureKind::CorruptServer &&
             header_.size() == P1_HEADER_BYTES &&
             std::equal(P1_MAGIC.begin(), P1_MAGIC.end(), header_.begin()) &&
             header_[13] == 0 && header_[14] == 0 && header_[15] == 0);
        tag_ = header_[8];
        const auto semantic = header_[9];
        const auto direction = header_[10];
        const auto peer = header_[11];
        const auto flags = header_[12];
        const auto monotonic_ns = be64(header_.data() + 16);
        const auto sequence = be64(header_.data() + 24);
        payload_target_ = be32(header_.data() + 44);
        need(tag_ >= 1 && tag_ <= 6 && semantic >= 1 && semantic <= 17 &&
             direction >= 1 && direction <= 3 && flags <= 3 &&
             payload_target_ <= P1_CHUNK_BYTES && sequence == sequence_ &&
             monotonic_ns > 0 && monotonic_ns >= last_monotonic_ns_ &&
             ((direction == 3 && peer == 0xff) ||
              (direction != 3 && peer <= 2)));
        last_monotonic_ns_ = monotonic_ns;
        ++sequence_;
        if (phase_ == EventPhase::Hello) {
            need(tag_ == 1 && semantic == 1 && direction == 3 &&
                 peer == 0xff && flags == 3 && payload_target_ == 332);
        } else if (phase_ == EventPhase::Records) {
            if (tag_ == 2 || tag_ == 6) {
                need(payload_target_ > 0);
                saw_p1_data_ = true;
            } else {
                need(tag_ == 3 && saw_p1_data_ && semantic == 9 &&
                     direction == 3 && peer == 0xff && flags == 3 &&
                     payload_target_ == 32);
            }
        } else if (phase_ == EventPhase::P1Completeness) {
            need(tag_ == 4 && semantic == 9 && direction == 3 &&
                 peer == 0xff && flags == 3 && payload_target_ == 496);
        } else if (phase_ == EventPhase::P1Seal) {
            need(tag_ == 5 && semantic == 9 && direction == 3 &&
                 peer == 0xff && flags == 3 && payload_target_ == 0);
        } else {
            refuse();
        }
        payload_.clear();
        payload_.reserve(static_cast<std::size_t>(payload_target_));
    }

    void finish_frame() {
        need(payload_.size() == payload_target_);
        if (wire_ == WireKind::P1) {
            const auto expected = hash(payload_);
            need(std::equal(expected.begin(), expected.end(),
                            header_.begin() + 80));
        }
        ++result_.record_count;
        result_.payload_bytes += payload_target_;
        if (tag_ == 5) {
            Bytes end = header_;
            add(end, payload_);
            result_.end_frame_identity = hash(end);
        }
        if (wire_ == WireKind::Event) {
            switch (tag_) {
            case 1: phase_ = EventPhase::Payload; break;
            case 2: phase_ = EventPhase::Records; break;
            case 3:
                saw_event_record_ = true;
                phase_ = EventPhase::Records;
                break;
            case 4: phase_ = EventPhase::ProjectionEnd; break;
            case 5: phase_ = EventPhase::End; break;
            default: refuse();
            }
        } else {
            switch (tag_) {
            case 1: phase_ = EventPhase::Records; break;
            case 2: case 6: phase_ = EventPhase::Records; break;
            case 3: phase_ = EventPhase::P1Completeness; break;
            case 4: phase_ = EventPhase::P1Seal; break;
            case 5: phase_ = EventPhase::End; break;
            default: refuse();
            }
        }
        header_.clear();
        payload_.clear();
        payload_target_ = 0;
        header_target_ = wire_ == WireKind::P1 ? P1_HEADER_BYTES
                                                : EVENT_HEADER_BYTES;
    }

public:
    StreamParser(unsigned round, CaptureKind kind)
        : round_(round), kind_(kind) {
        need(round_ == 1 || round_ == 2);
    }

    void consume(std::span<const unsigned char> input) {
        need(!eof_ && phase_ != EventPhase::End && !input.empty());
        wire_hash_.update(input);
        result_.raw_wire_bytes += input.size();
        std::size_t offset = 0;
        while (offset < input.size()) {
            if (header_.size() < header_target_) {
                const auto amount = std::min(
                    header_target_ - header_.size(), input.size() - offset);
                header_.insert(header_.end(), input.begin() + offset,
                               input.begin() + offset + amount);
                offset += amount;
                if (wire_ == WireKind::Unknown && header_.size() == 8) {
                    if (std::equal(EVENT_MAGIC.begin(), EVENT_MAGIC.end(),
                                   header_.begin())) {
                        need(kind_ != CaptureKind::CorruptServer);
                        wire_ = WireKind::Event;
                        header_target_ = EVENT_HEADER_BYTES;
                    } else {
                        need(std::equal(P1_MAGIC.begin(), P1_MAGIC.end(),
                                        header_.begin()) &&
                             kind_ == CaptureKind::CorruptServer);
                        wire_ = WireKind::P1;
                        header_target_ = P1_HEADER_BYTES;
                    }
                }
                if (header_.size() == header_target_) {
                    if (wire_ == WireKind::Event) start_event();
                    else start_p1();
                    if (payload_target_ == 0) finish_frame();
                }
                continue;
            }
            need(payload_.size() < payload_target_);
            const auto amount = std::min<std::uint64_t>(
                payload_target_ - payload_.size(), input.size() - offset);
            payload_.insert(payload_.end(), input.begin() + offset,
                            input.begin() + offset + amount);
            offset += static_cast<std::size_t>(amount);
            if (payload_.size() == payload_target_) finish_frame();
        }
    }

    WireStreamResult finish_eof() {
        need(!eof_ && phase_ == EventPhase::End && header_.empty() &&
             payload_.empty() && result_.raw_wire_bytes > 0 &&
             result_.record_count > 0 && nonzero(result_.end_frame_identity));
        eof_ = true;
        result_.record_root = wire_hash_.finish();
        Bytes receipt;
        add(receipt, "KPB_CAPTURE_PRODUCER_STREAM_EOF_V1\n");
        big_integer(receipt, round_, 4);
        receipt.push_back(static_cast<unsigned char>(kind_));
        big_integer(receipt, result_.record_count, 8);
        big_integer(receipt, result_.payload_bytes, 8);
        big_integer(receipt, result_.raw_wire_bytes, 8);
        add(receipt, result_.record_root);
        add(receipt, result_.end_frame_identity);
        result_.eof_identity = hash(receipt);
        return result_;
    }

    ProducerAttemptC03StreamState incomplete_state() const noexcept {
        if (result_.raw_wire_bytes == 0)
            return ProducerAttemptC03StreamState::Empty;
        if (!header_.empty() && header_.size() < header_target_)
            return ProducerAttemptC03StreamState::PartialHeader;
        if (header_.size() == header_target_ &&
            payload_.size() < payload_target_)
            return ProducerAttemptC03StreamState::PartialPayload;
        if (phase_ != EventPhase::End)
            return ProducerAttemptC03StreamState::ClosedWithoutEnd;
        return ProducerAttemptC03StreamState::Invalid;
    }
};

void close_unselected_fds(
        const std::array<int, 10>& selected, int packet_fd,
        const std::array<int, 10>& archive_writers) {
    std::set<int> retained(selected.begin(), selected.end());
    retained.insert(packet_fd);
    retained.insert(archive_writers.begin(), archive_writers.end());
    DIR* directory = ::opendir("/proc/self/fd");
    need(directory != nullptr);
    const int directory_fd = ::dirfd(directory);
    while (auto* item = ::readdir(directory)) {
        char* end = nullptr;
        errno = 0;
        const long candidate = std::strtol(item->d_name, &end, 10);
        if (errno != 0 || end == item->d_name || *end != '\0' ||
            candidate < 0 || candidate > std::numeric_limits<int>::max())
            continue;
        const int fd = static_cast<int>(candidate);
        if (fd != directory_fd && !retained.contains(fd)) {
            int selected_fd = fd;
            close_if_open(selected_fd);
        }
    }
    ::closedir(directory);
}

DrainedCapture drain_all(
        std::array<int, 10> read_ends,
        const PublicProducerLaunchPlan& plan,
        producer_archive::ProducerSealedArchiveBuilder archive) {
    std::array<StreamParser, 10> parsers{
        StreamParser(plan.streams[0].round, plan.streams[0].kind),
        StreamParser(plan.streams[1].round, plan.streams[1].kind),
        StreamParser(plan.streams[2].round, plan.streams[2].kind),
        StreamParser(plan.streams[3].round, plan.streams[3].kind),
        StreamParser(plan.streams[4].round, plan.streams[4].kind),
        StreamParser(plan.streams[5].round, plan.streams[5].kind),
        StreamParser(plan.streams[6].round, plan.streams[6].kind),
        StreamParser(plan.streams[7].round, plan.streams[7].kind),
        StreamParser(plan.streams[8].round, plan.streams[8].kind),
        StreamParser(plan.streams[9].round, plan.streams[9].kind),
    };
    std::array<bool, 10> open{};
    open.fill(true);
    std::array<bool, 10> parser_failed{};
    std::array<bool, 10> stream_complete{};
    std::array<ProducerAttemptDrainFailure, 10> stream_failures{};
    for (int fd : read_ends) {
        const int flags = ::fcntl(fd, F_GETFL);
        need(flags >= 0 && ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
    }
    unsigned remaining = 10;
    ChildPacket packet{};
    packet.magic = PACKET_MAGIC;
    packet.binding = plan.binding;
    packet.opaque_closure_authority_identity =
        plan.opaque_closure_authority_identity;
    std::array<unsigned char, 1U << 16> buffer{};
    while (remaining > 0) {
        std::array<struct pollfd, 10> polls{};
        for (unsigned index = 0; index < polls.size(); ++index) {
            polls[index].fd = open[index] ? read_ends[index] : -1;
            polls[index].events = POLLIN | POLLHUP | POLLERR;
        }
        int ready;
        do { ready = ::poll(polls.data(), polls.size(), -1); }
        while (ready < 0 && errno == EINTR);
        need(ready > 0);
        for (unsigned index = 0; index < polls.size(); ++index) {
            if (!open[index] || polls[index].revents == 0) continue;
            if ((polls[index].revents & POLLNVAL) != 0) {
                parser_failed[index] = true;
                stream_failures[index] =
                    ProducerAttemptDrainFailure::CaptureReadFailed;
                close_if_open(read_ends[index]);
                open[index] = false;
                --remaining;
                continue;
            }
            ssize_t count;
            do { count = ::read(read_ends[index], buffer.data(),
                                buffer.size()); }
            while (count < 0 && errno == EINTR);
            if (count > 0) {
                const std::span<const unsigned char> raw{
                    buffer.data(), static_cast<std::size_t>(count)};
                archive.append(index, raw);
#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
                const bool first_c03_fault = index == 3 &&
                    (plan.test_only_drain_fault ==
                         TestProducerDrainFault::SigkillAfterFirstC03Write ||
                     plan.test_only_drain_fault ==
                         TestProducerDrainFault::SigsegvAfterFirstC03Write);
                const bool second_c03_fault = index == 8 &&
                    (plan.test_only_drain_fault ==
                         TestProducerDrainFault::SigkillAfterSecondC03Write ||
                     plan.test_only_drain_fault ==
                         TestProducerDrainFault::SigsegvAfterSecondC03Write);
                if (first_c03_fault || second_c03_fault) {
                    const int signal =
                        plan.test_only_drain_fault ==
                            TestProducerDrainFault::SigkillAfterFirstC03Write ||
                        plan.test_only_drain_fault ==
                            TestProducerDrainFault::SigkillAfterSecondC03Write
                        ? SIGKILL : SIGSEGV;
                    (void)::raise(signal);
                    _exit(119);
                }
#endif
                if (!parser_failed[index]) {
                    try { parsers[index].consume(raw); }
                    catch (const Refused&) {
                        parser_failed[index] = true;
                        stream_failures[index] =
                            ProducerAttemptDrainFailure::ParserRefused;
                    }
                }
            } else if (count == 0) {
                if (!parser_failed[index]) {
                    try {
                        packet.streams[index] =
                            parsers[index].finish_eof();
                        const auto& result = packet.streams[index];
                        archive.finish_after_end_and_eof(index, {
                            .record_root = result.record_root,
                            .end_frame_identity = result.end_frame_identity,
                            .eof_identity = result.eof_identity,
                            .record_count = result.record_count,
                            .payload_bytes = result.payload_bytes,
                            .raw_wire_bytes = result.raw_wire_bytes,
                        });
                        stream_complete[index] = true;
                    } catch (const Refused&) {
                        parser_failed[index] = true;
                        const auto state = parsers[index].incomplete_state();
                        stream_failures[index] =
                            state == ProducerAttemptC03StreamState::Empty
                            ? ProducerAttemptDrainFailure::Empty
                            : state == ProducerAttemptC03StreamState::
                                  PartialHeader
                            ? ProducerAttemptDrainFailure::PartialHeader
                            : state == ProducerAttemptC03StreamState::
                                  PartialPayload
                            ? ProducerAttemptDrainFailure::PartialPayload
                            : state == ProducerAttemptC03StreamState::
                                  ClosedWithoutEnd
                            ? ProducerAttemptDrainFailure::MissingEnd
                            : ProducerAttemptDrainFailure::ParserRefused;
                    }
                }
                close_if_open(read_ends[index]);
                open[index] = false;
                --remaining;
            } else {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    parser_failed[index] = true;
                    stream_failures[index] =
                        ProducerAttemptDrainFailure::CaptureReadFailed;
                    close_if_open(read_ends[index]);
                    open[index] = false;
                    --remaining;
                }
            }
        }
    }
    packet.attempt_complete = static_cast<std::uint8_t>(
        std::all_of(stream_complete.begin(), stream_complete.end(),
                    [](bool value) { return value; }));
    packet.first_failed_slot = 0xff;
    packet.attempt_failure = ProducerAttemptDrainFailure::None;
    for (unsigned index = 0; index < stream_complete.size(); ++index)
        if (!stream_complete[index] && packet.first_failed_slot == 0xff) {
            packet.first_failed_slot = static_cast<std::uint8_t>(index);
            packet.attempt_failure =
                stream_failures[index] == ProducerAttemptDrainFailure::None
                ? ProducerAttemptDrainFailure::OtherStreamRefused
                : stream_failures[index];
        }
    constexpr std::array<unsigned, 2> c03_slots{3, 8};
    for (unsigned selected = 0; selected < c03_slots.size(); ++selected) {
        const unsigned slot = c03_slots[selected];
        if (stream_complete[slot]) {
            packet.c03_states[selected] =
                ProducerAttemptC03StreamState::CompleteEnd;
            packet.c03_failures[selected] =
                ProducerAttemptDrainFailure::None;
        } else {
            packet.c03_states[selected] = parsers[slot].incomplete_state();
            packet.c03_failures[selected] =
                stream_failures[slot] == ProducerAttemptDrainFailure::None
                ? ProducerAttemptDrainFailure::OtherStreamRefused
                : stream_failures[slot];
        }
    }
    packet.identity = packet_identity(packet);
    DrainedCapture result;
    result.packet = packet;
    if (packet.attempt_complete)
        result.archive = std::make_unique<
            producer_archive::ProducerSealedArchiveAuthority>(
                std::move(archive).finish());
    else
        result.partial_builder = std::make_unique<
            producer_archive::ProducerSealedArchiveBuilder>(
                std::move(archive));
    return result;
}

WireStreamResult reparse_retained_stream(
        int fd, const PublicProducerStreamPlan& plan) {
    struct stat value{};
    need(fd >= 0 && ::fstat(fd, &value) == 0 &&
         S_ISREG(value.st_mode) && value.st_size > 0);
    StreamParser parser(plan.round, plan.kind);
    std::array<unsigned char, 1U << 16> buffer{};
    std::uint64_t at = 0;
    const auto size = static_cast<std::uint64_t>(value.st_size);
    while (at < size) {
        const auto target = static_cast<std::size_t>(
            std::min<std::uint64_t>(buffer.size(), size - at));
        ssize_t count;
        do {
            count = ::pread(fd, buffer.data(), target,
                            static_cast<off_t>(at));
        } while (count < 0 && errno == EINTR);
        need(count > 0);
        parser.consume({buffer.data(), static_cast<std::size_t>(count)});
        at += static_cast<std::uint64_t>(count);
    }
    return parser.finish_eof();
}

struct PartialC03Inspection final {
    ProducerAttemptC03StreamState state{};
    ProducerAttemptDrainFailure failure{};
};

PartialC03Inspection inspect_partial_c03(
        int fd, const PublicProducerStreamPlan& plan) {
    struct stat value{};
    need(fd >= 0 && ::fstat(fd, &value) == 0 &&
         S_ISREG(value.st_mode) && value.st_size >= 0 &&
         (::fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDONLY);
    StreamParser parser(plan.round, plan.kind);
    std::array<unsigned char, 1U << 16> buffer{};
    std::uint64_t at = 0;
    const auto size = static_cast<std::uint64_t>(value.st_size);
    try {
        while (at < size) {
            const auto target = static_cast<std::size_t>(
                std::min<std::uint64_t>(buffer.size(), size - at));
            ssize_t count;
            do {
                count = ::pread(fd, buffer.data(), target,
                                static_cast<off_t>(at));
            } while (count < 0 && errno == EINTR);
            need(count > 0);
            parser.consume({buffer.data(), static_cast<std::size_t>(count)});
            at += static_cast<std::uint64_t>(count);
        }
        (void)parser.finish_eof();
        return {
            .state = ProducerAttemptC03StreamState::CompleteEnd,
            .failure = ProducerAttemptDrainFailure::None,
        };
    } catch (const Refused&) {
        const auto state = parser.incomplete_state();
        return {
            .state = state,
            .failure = state == ProducerAttemptC03StreamState::Empty
                ? ProducerAttemptDrainFailure::Empty
                : state == ProducerAttemptC03StreamState::PartialHeader
                ? ProducerAttemptDrainFailure::PartialHeader
                : state == ProducerAttemptC03StreamState::PartialPayload
                ? ProducerAttemptDrainFailure::PartialPayload
                : state == ProducerAttemptC03StreamState::ClosedWithoutEnd
                ? ProducerAttemptDrainFailure::MissingEnd
                : ProducerAttemptDrainFailure::ParserRefused,
        };
    }
}

#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
int reopen_descriptor(int fd, int flags) {
    std::array<char, 64> path{};
    const int count = std::snprintf(
        path.data(), path.size(), "/proc/self/fd/%d", fd);
    need(count > 0 && static_cast<std::size_t>(count) < path.size());
    const int result = ::open(path.data(), flags | O_CLOEXEC);
    need(result >= 0);
    return result;
}

int unsealed_copy(int source) {
    struct stat value{};
    need(::fstat(source, &value) == 0 && value.st_size > 0);
    int writable = ::memfd_create(
        "kpb-test-unsealed-archive", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    need(writable >= 0);
    int result = -1;
    try {
        std::array<unsigned char, 1U << 16> bytes{};
        std::uint64_t at = 0;
        const auto size = static_cast<std::uint64_t>(value.st_size);
        while (at < size) {
            const auto target = static_cast<std::size_t>(
                std::min<std::uint64_t>(bytes.size(), size - at));
            ssize_t count;
            do {
                count = ::pread(source, bytes.data(), target,
                                static_cast<off_t>(at));
            } while (count < 0 && errno == EINTR);
            need(count > 0);
            std::size_t written = 0;
            while (written < static_cast<std::size_t>(count)) {
                const auto amount = ::write(
                    writable, bytes.data() + written,
                    static_cast<std::size_t>(count) - written);
                if (amount < 0 && errno == EINTR) continue;
                need(amount > 0);
                written += static_cast<std::size_t>(amount);
            }
            at += static_cast<std::uint64_t>(count);
        }
        result = reopen_descriptor(writable, O_RDONLY);
        close_if_open(writable);
        return result;
    } catch (...) {
        close_if_open(result);
        close_if_open(writable);
        throw;
    }
}
#endif

Digest child_exit_identity(const PublicProducerLaunchPlan& plan,
                           const ChildPacket& packet, pid_t pid,
                           int status, bool packet_present,
                           bool packet_authenticated,
                           bool wait_status_observed,
                           bool pidfd_exit_observed) {
    Bytes value;
    add(value, "kpb-capture-producer-child-exit/v1");
    add(value, plan.producer_process_identity);
    add_string(value, plan.capture_trial_id);
    add_string(value, plan.capture_attempt_ids[0]);
    add_string(value, plan.capture_attempt_ids[1]);
    value.push_back(packet_present ? 1 : 0);
    value.push_back(packet_authenticated ? 1 : 0);
    value.push_back(wait_status_observed ? 1 : 0);
    value.push_back(pidfd_exit_observed ? 1 : 0);
    add(value, packet.identity);
    integer(value, static_cast<std::uint64_t>(pid));
    integer(value, static_cast<std::uint64_t>(status));
    return hash(value);
}

Digest producer_identity(const PublicProducerLaunchPlan& plan,
                         const ChildPacket& packet,
                         const std::array<
                             PublicAggregateMailboxRouteCompletion, 2>& routes,
                         const Digest& child_exit) {
    Bytes value;
    add(value, "kpb-capture-producer-identity/v1");
    value.push_back(static_cast<unsigned char>(plan.binding.classification));
    add(value, plan.binding.capture);
    add(value, plan.binding.finite_manifest.manifest_identity);
    add(value, plan.producer_process_identity);
    add(value, plan.role_closure_identity);
    add(value, plan.manifest_seal);
    value.push_back(static_cast<unsigned char>(plan.construction_policy));
    add(value, plan.construction_classification_receipt);
    add(value, plan.opaque_closure_authority_identity);
    for (const auto& route : routes) {
        integer(value, route.round);
        add(value, route.route_identity);
        add(value, route.full_cohort_barrier_identity);
        add(value, route.projection_identity);
        integer(value, route.projection_bytes);
        integer(value, route.full_cohort_barrier_observed_monotonic_ns);
        integer(value, route.route_observed_monotonic_ns);
    }
    add(value, packet.identity);
    add(value, child_exit);
    return hash(value);
}

Digest receipt_identity(const PublicProducerLaunchPlan& plan,
                        const ChildPacket& packet,
                        const Digest& producer,
                        const Digest& child_exit) {
    Bytes value;
    add(value, "kpb-capture-producer-receipt/v1");
    add(value, producer);
    add(value, child_exit);
    for (unsigned index = 0; index < packet.streams.size(); ++index) {
        const auto& stream = plan.streams[index];
        const auto& result = packet.streams[index];
        integer(value, stream.round);
        value.push_back(static_cast<unsigned char>(stream.kind));
        integer(value, stream.fixed_fd);
        add(value, stream.process_identity);
        add(value, stream.child_exit_identity);
        integer(value, result.record_count);
        integer(value, result.payload_bytes);
        integer(value, result.raw_wire_bytes);
        add(value, result.record_root);
        add(value, result.end_frame_identity);
        add(value, result.eof_identity);
    }
    return hash(value);
}

PublicProducerClosure closure_receipt(
        const PublicProducerLaunchPlan& plan) {
    PublicProducerClosure result{
        .binding = plan.binding,
        .opaque_closure_authority_identity =
            plan.opaque_closure_authority_identity,
        .producer_worker = worker(manifest_entry(
            plan.binding, ManifestComponent::Producer)),
        .producer_process_identity = plan.producer_process_identity,
        .role_closure_identity = plan.role_closure_identity,
        .manifest_seal = plan.manifest_seal,
        .construction_policy = plan.construction_policy,
        .construction_classification_receipt =
            plan.construction_classification_receipt,
        .stream_count = 10,
        .closed_root_count = 10,
        .unknown_record_count = 0,
    };
    for (unsigned index = 0; index < result.streams.size(); ++index) {
        const auto& selected = manifest_entry(
            plan.binding, component(plan.streams[index].kind));
        result.streams[index] = PublicStreamClosure{
            .round = plan.streams[index].round,
            .kind = plan.streams[index].kind,
            .fixed_fd = plan.streams[index].fixed_fd,
            .manifest_component = component(plan.streams[index].kind),
            .source_identity = selected.source_identity,
            .build_identity = selected.build_identity,
            .runtime_identity = selected.runtime_identity,
            .launcher_identity = selected.launcher_identity,
            .process_identity = plan.streams[index].process_identity,
            .child_exit_identity = plan.streams[index].child_exit_identity,
            .root_closed = true,
            .end_observed = true,
            .eof_observed = true,
        };
    }
    return result;
}

ProducerClosureEvidence closure_evidence(
        const PublicProducerLaunchPlan& plan, const ChildPacket& packet,
        const Digest& producer, const Digest& receipt,
        const Digest& child_exit) {
    ProducerClosureEvidence result{
        .opaque_closure_authority_identity =
            plan.opaque_closure_authority_identity,
        .producer_child_exit = child_exit,
        .producer_receipt = receipt,
        .producer_identity = producer,
    };
    for (unsigned index = 0; index < result.streams.size(); ++index) {
        result.streams[index] = ProducerStreamClosureEvidence{
            .record_root = packet.streams[index].record_root,
            .end_frame_identity = packet.streams[index].end_frame_identity,
            .eof_identity = packet.streams[index].eof_identity,
            .record_count = packet.streams[index].record_count,
            .payload_bytes = packet.streams[index].payload_bytes,
            .raw_wire_bytes = packet.streams[index].raw_wire_bytes,
        };
    }
    return result;
}

PublicCaptureProducerReceiptV1 public_receipt(
        const PublicProducerLaunchPlan& plan) {
    PublicCaptureProducerReceiptV1 result{
        .schema = "kpb-capture-producer-receipt/v1",
        .binding = plan.binding,
        .opaque_closure_authority_identity =
            plan.opaque_closure_authority_identity,
        .producer_worker = worker(manifest_entry(
            plan.binding, ManifestComponent::Producer)),
        .producer_process_identity = plan.producer_process_identity,
        .role_closure_identity = plan.role_closure_identity,
        .manifest_seal = plan.manifest_seal,
        .construction_policy = plan.construction_policy,
        .construction_classification_receipt =
            plan.construction_classification_receipt,
        .routes = plan.route_requirements,
        .stream_count = 10,
        .closed_root_count = 10,
        .unknown_record_count = 0,
        .role_hooks_integrated = true,
        .fixed_fd_inheritance_selected = true,
        .launcher_selected = true,
        .launch_authorized = true,
        .actual_receipt_emitted = true,
    };
    for (unsigned index = 0; index < result.streams.size(); ++index) {
        result.streams[index] = PublicCaptureProducerStreamReceipt{
            .round = plan.streams[index].round,
            .kind = plan.streams[index].kind,
            .fixed_fd = plan.streams[index].fixed_fd,
            .root_closed = true,
            .end_observed = true,
            .eof_observed = true,
        };
    }
    return result;
}

} // namespace

struct ProducerAttemptC03HistoryAuthority::Storage final {
    RunBinding binding;
    std::string capture_trial_id;
    std::array<std::string, 2> capture_attempt_ids;
    Digest closure_identity{};
    Digest archive_reservation_identity{};
    std::array<unsigned, 2> source_slots{};
    std::array<unsigned, 2> fixed_fds{};
    std::array<int, 2> fds{};
    std::array<std::uint64_t, 2> devices{};
    std::array<std::uint64_t, 2> inodes{};
    std::array<std::uint64_t, 2> sizes{};
    std::array<int, 2> seals{};
    std::array<Digest, 2> sha256{};
    std::array<Digest, 2> route_requirements{};
    std::array<Digest, 2> route_completions{};
    bool writer_aliases_closed{};
    std::array<bool, 2> complete_end_and_eof{};
    std::array<ProducerStreamClosureEvidence, 2> evidence{};
    std::array<ProducerAttemptC03StreamState, 2> states{};
    std::array<ProducerAttemptDrainFailure, 2> failures{};
    ProducerAttemptDrainFailure attempt_failure{};
    std::uint8_t first_failed_slot{0xff};
    std::uint64_t start_monotonic_ns{};
    std::uint64_t end_monotonic_ns{};
    std::int64_t producer_pid{};
    std::int32_t producer_wait_status{};
    bool wait_observed{};
    bool pidfd_exit_observed{};
    Digest producer_child_exit_identity{};
    std::atomic_bool live{true};

    Storage() { fds.fill(-1); }
    Storage(const Storage&) = delete;
    Storage& operator=(const Storage&) = delete;
    ~Storage() {
        for (auto& fd : fds) close_if_open(fd);
    }
};

ParentTenReadEndsAuthority::ParentTenReadEndsAuthority(
        PublicProducerLaunchPlan plan, std::array<int, 10> read_ends)
    : plan_(std::move(plan)), read_ends_(read_ends) {
    try {
        validate_plan(plan_);
        std::set<std::pair<std::uint64_t, std::uint64_t>> identities;
        for (unsigned index = 0; index < read_ends_.size(); ++index) {
            const auto selected = fingerprint(read_ends_[index]);
            need(identities.emplace(selected.device, selected.inode).second);
            devices_[index] = selected.device;
            inodes_[index] = selected.inode;
            file_types_[index] = selected.type;
        }
    } catch (...) {
        for (auto& fd : read_ends_) close_if_open(fd);
        throw;
    }
}

ParentTenReadEndsAuthority::ParentTenReadEndsAuthority(
        ParentTenReadEndsAuthority&& other) noexcept
    : plan_(std::move(other.plan_)), read_ends_(other.read_ends_),
      devices_(other.devices_), inodes_(other.inodes_),
      file_types_(other.file_types_),
      live_(other.live_.exchange(false)) {
    for (unsigned index = 0; index < c1_contact_value_prepared_.size();
         ++index)
        c1_contact_value_prepared_[index].store(
            other.c1_contact_value_prepared_[index].load());
    other.read_ends_.fill(-1);
}

ParentTenReadEndsAuthority::~ParentTenReadEndsAuthority() {
    for (auto& fd : read_ends_) close_if_open(fd);
}

#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
ParentTenReadEndsAuthority ParentTenReadEndsAuthority::test_only_mint(
        PublicProducerLaunchPlan plan, std::array<int, 10>&& read_ends) {
    return ParentTenReadEndsAuthority(std::move(plan), read_ends);
}
#endif

ProducerRuntimeCompletion::ProducerRuntimeCompletion(
        PublicCaptureProducerReceiptV1 receipt,
        ProducerClosureAuthority&& authority,
        producer_archive::ProducerSealedArchiveAuthority&& archive)
    : receipt_(std::move(receipt)), authority_(std::move(authority)),
      archive_(std::make_unique<
          producer_archive::ProducerSealedArchiveAuthority>(
              std::move(archive))) {}

ProducerRuntimeCompletion::ProducerRuntimeCompletion(
        ProducerRuntimeCompletion&& other) noexcept
    : receipt_(std::move(other.receipt_)),
      authority_(std::move(other.authority_)),
      archive_(std::move(other.archive_)) {}

ProducerRuntimeCompletion::~ProducerRuntimeCompletion() = default;

ProducerClosureAuthority ProducerRuntimeCompletion::take_authority() {
    need(authority_.has_value());
    ProducerClosureAuthority result(std::move(*authority_));
    authority_.reset();
    return result;
}

producer_archive::ProducerSealedArchiveAuthority
ProducerRuntimeCompletion::take_archive() {
    need(archive_ != nullptr);
    producer_archive::ProducerSealedArchiveAuthority result(
        std::move(*archive_));
    archive_.reset();
    return result;
}

ProducerAttemptC03HistoryAuthority::ProducerAttemptC03HistoryAuthority(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) {
    need(storage_ != nullptr);
}

ProducerAttemptC03HistoryAuthority::ProducerAttemptC03HistoryAuthority(
        ProducerAttemptC03HistoryAuthority&& other) noexcept
    : storage_(std::move(other.storage_)) {}

ProducerAttemptC03HistoryAuthority::~ProducerAttemptC03HistoryAuthority() =
    default;

ProducerAttemptRegisteredHistoryTransfer::
ProducerAttemptRegisteredHistoryTransfer() {
    fds_.fill(-1);
}

ProducerAttemptRegisteredHistoryTransfer::
ProducerAttemptRegisteredHistoryTransfer(
        ProducerAttemptRegisteredHistoryTransfer&& other) noexcept
    : binding_(other.binding_),
      capture_trial_id_(std::move(other.capture_trial_id_)),
      capture_attempt_ids_(std::move(other.capture_attempt_ids_)),
      closure_identity_(other.closure_identity_),
      archive_reservation_identity_(
          std::exchange(other.archive_reservation_identity_, {})),
      source_slots_(other.source_slots_), fixed_fds_(other.fixed_fds_),
      fds_(other.fds_), devices_(other.devices_), inodes_(other.inodes_),
      sizes_(other.sizes_), seals_(other.seals_), sha256_(other.sha256_),
      route_requirements_(other.route_requirements_),
      route_completions_(other.route_completions_),
      writer_aliases_closed_(other.writer_aliases_closed_),
      states_(other.states_), failures_(other.failures_),
      attempt_failure_(other.attempt_failure_),
      first_failed_slot_(other.first_failed_slot_),
      start_monotonic_ns_(other.start_monotonic_ns_),
      end_monotonic_ns_(other.end_monotonic_ns_),
      producer_pid_(other.producer_pid_),
      producer_wait_status_(other.producer_wait_status_),
      wait_observed_(other.wait_observed_),
      pidfd_exit_observed_(other.pidfd_exit_observed_),
      producer_child_exit_identity_(other.producer_child_exit_identity_) {
    other.fds_.fill(-1);
}

ProducerAttemptRegisteredHistoryTransfer::
~ProducerAttemptRegisteredHistoryTransfer() {
    for (auto& fd : fds_) close_if_open(fd);
}

ProducerAttemptRegisteredHistoryTransfer
ProducerAttemptC03HistoryAuthority::consume_for_registered_history() && {
    auto storage = std::move(storage_);
    need(storage != nullptr && storage->live.exchange(false));
    ProducerAttemptRegisteredHistoryTransfer result;
    result.binding_ = storage->binding;
    result.capture_trial_id_ = std::move(storage->capture_trial_id);
    result.capture_attempt_ids_ = std::move(storage->capture_attempt_ids);
    result.closure_identity_ = storage->closure_identity;
    result.archive_reservation_identity_ =
        storage->archive_reservation_identity;
    result.source_slots_ = storage->source_slots;
    result.fixed_fds_ = storage->fixed_fds;
    result.devices_ = storage->devices;
    result.inodes_ = storage->inodes;
    result.sizes_ = storage->sizes;
    result.seals_ = storage->seals;
    result.sha256_ = storage->sha256;
    result.route_requirements_ = storage->route_requirements;
    result.route_completions_ = storage->route_completions;
    result.writer_aliases_closed_ = storage->writer_aliases_closed;
    result.states_ = storage->states;
    result.failures_ = storage->failures;
    result.attempt_failure_ = storage->attempt_failure;
    result.first_failed_slot_ = storage->first_failed_slot;
    result.start_monotonic_ns_ = storage->start_monotonic_ns;
    result.end_monotonic_ns_ = storage->end_monotonic_ns;
    result.producer_pid_ = storage->producer_pid;
    result.producer_wait_status_ = storage->producer_wait_status;
    result.wait_observed_ = storage->wait_observed;
    result.pidfd_exit_observed_ = storage->pidfd_exit_observed;
    result.producer_child_exit_identity_ =
        storage->producer_child_exit_identity;
    for (unsigned index = 0; index < result.fds_.size(); ++index)
        result.fds_[index] = std::exchange(storage->fds[index], -1);
    return result;
}

#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
ProducerAttemptC03HistoryAuthority::TestSummary
ProducerAttemptC03HistoryAuthority::test_only_consume(
        ProducerAttemptC03HistoryAuthority&& supplied) {
    auto storage = std::move(supplied.storage_);
    need(storage != nullptr && storage->live.exchange(false));
    return {
        .binding = storage->binding,
        .capture_trial_id = storage->capture_trial_id,
        .capture_attempt_ids = storage->capture_attempt_ids,
        .archive_reservation_identity =
            storage->archive_reservation_identity,
        .states = storage->states,
        .failures = storage->failures,
        .attempt_failure = storage->attempt_failure,
        .first_failed_slot = storage->first_failed_slot,
        .sizes = storage->sizes,
        .devices = storage->devices,
        .inodes = storage->inodes,
        .seals = storage->seals,
        .sha256 = storage->sha256,
        .read_only = {
            storage->fds[0] >= 0 &&
                (::fcntl(storage->fds[0], F_GETFL) & O_ACCMODE) == O_RDONLY,
            storage->fds[1] >= 0 &&
                (::fcntl(storage->fds[1], F_GETFL) & O_ACCMODE) == O_RDONLY,
        },
        .route_requirements = storage->route_requirements,
        .route_completions = storage->route_completions,
        .writer_aliases_closed = storage->writer_aliases_closed,
        .start_monotonic_ns = storage->start_monotonic_ns,
        .end_monotonic_ns = storage->end_monotonic_ns,
        .producer_pid = storage->producer_pid,
        .producer_wait_status = storage->producer_wait_status,
        .wait_observed = storage->wait_observed,
        .pidfd_exit_observed = storage->pidfd_exit_observed,
        .producer_child_exit_identity =
            storage->producer_child_exit_identity,
    };
}
#endif

ProducerAttemptDrainResult::ProducerAttemptDrainResult(
        ProducerAttemptC03HistoryAuthority&& history,
        std::unique_ptr<ProducerRuntimeCompletion> completion)
    : history_(std::make_unique<ProducerAttemptC03HistoryAuthority>(
          std::move(history))),
      completion_(std::move(completion)) {}

ProducerAttemptDrainResult::ProducerAttemptDrainResult(
        ProducerAttemptDrainResult&& other) noexcept
    : history_(std::move(other.history_)),
      completion_(std::move(other.completion_)) {}

ProducerAttemptDrainResult::~ProducerAttemptDrainResult() = default;

struct ProducerAttemptOutcomeAuthority::Storage final {
    std::unique_ptr<ProducerAttemptC03HistoryAuthority::Storage> history;
    std::unique_ptr<ProducerRuntimeCompletion> completion;
    std::optional<producer_archive::ProducerArchiveQuarantineAuthority>
        quarantine;
    std::optional<producer_archive::ProducerPartialC03ArchiveAuthority>
        partial;
    PublicProducerLaunchPlan plan;
    std::int64_t producer_pid{-1};
    std::int32_t wait_status{-1};
    std::uint64_t start_monotonic_ns{};
    std::uint64_t end_monotonic_ns{};
    bool wait_observed{};
    bool pidfd_exit_observed{};
    bool route_claimed{};
    bool route_valid{};
    producer_archive::ProducerArchiveQuarantineStage quarantine_stage{
        producer_archive::ProducerArchiveQuarantineStage::Internal};
    int error_number{};
    std::exception_ptr failure;
};

ProducerAttemptOutcomeAuthority::ProducerAttemptOutcomeAuthority(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }

ProducerAttemptOutcomeAuthority::ProducerAttemptOutcomeAuthority(
        ProducerAttemptOutcomeAuthority&&) noexcept = default;
ProducerAttemptOutcomeAuthority::~ProducerAttemptOutcomeAuthority() =
    default;

ProducerAttemptRegisteredOutcomeTransfer::
ProducerAttemptRegisteredOutcomeTransfer(
        std::unique_ptr<ProducerAttemptOutcomeAuthority::Storage> storage)
        noexcept
    : storage_(std::move(storage)) {}

ProducerAttemptRegisteredOutcomeTransfer::
ProducerAttemptRegisteredOutcomeTransfer(
        ProducerAttemptRegisteredOutcomeTransfer&& other) noexcept
    : storage_(std::move(other.storage_)) {}

ProducerAttemptRegisteredOutcomeTransfer::
~ProducerAttemptRegisteredOutcomeTransfer() = default;

ProducerAttemptRegisteredOutcomeTransfer
ProducerAttemptOutcomeAuthority::consume_for_registered_history() && {
    auto storage = std::move(storage_);
    need(storage != nullptr);
    const bool normal = storage->history != nullptr &&
        !storage->quarantine.has_value() && storage->failure == nullptr;
    const bool unavailable = storage->history == nullptr &&
        storage->completion == nullptr && storage->quarantine.has_value() &&
        storage->failure != nullptr && storage->error_number != 0;
    need(normal != unavailable);
    return ProducerAttemptRegisteredOutcomeTransfer(std::move(storage));
}

#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
ProducerAttemptOutcomeAuthority::TestOnlyUnavailableSummary
ProducerAttemptOutcomeAuthority::test_only_consume_unavailable(
        ProducerAttemptOutcomeAuthority&& supplied) {
    auto storage = std::move(supplied.storage_);
    need(storage != nullptr && storage->history == nullptr &&
         storage->completion == nullptr && storage->quarantine.has_value() &&
         storage->failure != nullptr && storage->error_number != 0);
    return {
        .unavailable = true,
        .retained_quarantine = storage->quarantine.has_value(),
        .retained_partial_c03 = storage->partial.has_value(),
        .stage = storage->quarantine_stage,
        .error_number = storage->error_number,
        .producer_pid = storage->producer_pid,
        .wait_observed = storage->wait_observed,
        .pidfd_exit_observed = storage->pidfd_exit_observed,
    };
}
#endif

#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
ProducerAttemptC03HistoryAuthority
ProducerAttemptDrainResult::take_history() {
    need(history_ != nullptr);
    ProducerAttemptC03HistoryAuthority result(std::move(*history_));
    history_.reset();
    return result;
}

ProducerRuntimeCompletion ProducerAttemptDrainResult::take_completion() {
    need(completion_ != nullptr);
    ProducerRuntimeCompletion result(std::move(*completion_));
    completion_.reset();
    return result;
}
#endif

RunningCaptureProducer ParentOwnedCaptureProducer::start(
        ParentTenReadEndsAuthority&& authority) {
    return start_impl(std::move(authority), nullptr);
}

RunningCaptureProducer ParentOwnedCaptureProducer::start_prebuilt(
        ParentTenReadEndsAuthority&& authority,
        producer_archive::ProducerSealedArchiveBuilder&& archive) {
    auto retained_archive_builder = std::make_unique<
        producer_archive::ProducerSealedArchiveBuilder>(
            std::move(archive));
    return start_impl(
        std::move(authority), std::move(retained_archive_builder));
}

RunningCaptureProducer ParentOwnedCaptureProducer::start_impl(
        ParentTenReadEndsAuthority&& authority,
        std::unique_ptr<producer_archive::ProducerSealedArchiveBuilder>
            retained_archive_builder) {
    const auto start_monotonic_ns = observed_monotonic_ns();
    need(authority.live_.exchange(false));
    validate_plan(authority.plan_);
    auto read_ends = authority.read_ends_;
    authority.read_ends_.fill(-1);
    std::array<int, producer_archive::PRODUCER_ARCHIVE_STREAM_COUNT>
        archive_writer_fds{};
    std::array<std::uint64_t, producer_archive::PRODUCER_ARCHIVE_STREAM_COUNT>
        archive_devices{};
    std::array<std::uint64_t, producer_archive::PRODUCER_ARCHIVE_STREAM_COUNT>
        archive_inodes{};
    try {
        if (retained_archive_builder == nullptr)
            retained_archive_builder.reset(
                new producer_archive::ProducerSealedArchiveBuilder(
                    authority.plan_.binding,
                    authority.plan_.opaque_closure_authority_identity));
        archive_writer_fds = retained_archive_builder
            ->inherited_writer_fds_for_runtime();
        for (unsigned index = 0; index < archive_writer_fds.size(); ++index) {
            struct stat value{};
            need(::fstat(archive_writer_fds[index], &value) == 0 &&
                 S_ISREG(value.st_mode));
            archive_devices[index] =
                static_cast<std::uint64_t>(value.st_dev);
            archive_inodes[index] =
                static_cast<std::uint64_t>(value.st_ino);
        }
    } catch (...) {
        for (auto& fd : read_ends) close_if_open(fd);
        throw;
    }

    int sockets[2]{-1, -1};
    if (::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0) {
        for (auto& fd : read_ends) close_if_open(fd);
        refuse();
    }
    int enabled = 1;
    if (::setsockopt(sockets[0], SOL_SOCKET, SO_PASSCRED,
                     &enabled, sizeof(enabled)) != 0) {
        close_if_open(sockets[0]); close_if_open(sockets[1]);
        for (auto& fd : read_ends) close_if_open(fd);
        refuse();
    }
    const pid_t child = ::fork();
    if (child < 0) {
        close_if_open(sockets[0]); close_if_open(sockets[1]);
        for (auto& fd : read_ends) close_if_open(fd);
        refuse();
    }
    if (child == 0) {
        close_if_open(sockets[0]);
        try {
            close_unselected_fds(
                read_ends, sockets[1], archive_writer_fds);
            auto drained = drain_all(
                read_ends, authority.plan_,
                std::move(*retained_archive_builder));
            std::array<int,
                producer_archive::PRODUCER_ARCHIVE_STREAM_COUNT>
                archive_fds{};
            archive_fds.fill(-1);
            std::size_t rights_fd_count = 0;
            if (drained.packet.attempt_complete) {
                need(drained.archive != nullptr &&
                     drained.partial_builder == nullptr);
                archive_fds = drained.archive->duplicate_for_transport();
                rights_fd_count = archive_fds.size();
            } else {
                need(drained.archive == nullptr &&
                     drained.partial_builder != nullptr);
                auto partial = std::move(*drained.partial_builder)
                    .seal_partial_c03_for_runtime();
                auto transfer = std::move(partial)
                    .duplicate_for_runtime_transport();
                need(transfer.binding_ == authority.plan_.binding &&
                     transfer.closure_identity_ ==
                         authority.plan_.opaque_closure_authority_identity);
                for (unsigned index = 0; index < 2; ++index) {
                    archive_fds[index] =
                        std::exchange(transfer.fds_[index], -1);
                    drained.packet.partial_source_slots[index] =
                        transfer.source_slots_[index];
                    drained.packet.partial_fixed_fds[index] =
                        transfer.fixed_fds_[index];
                    drained.packet.partial_devices[index] =
                        transfer.devices_[index];
                    drained.packet.partial_inodes[index] =
                        transfer.inodes_[index];
                    drained.packet.partial_sizes[index] =
                        transfer.sizes_[index];
                    drained.packet.partial_seals[index] =
                        transfer.seals_[index];
                    drained.packet.partial_sha256[index] =
                        transfer.sha256_[index];
                    drained.packet.partial_complete_end_and_eof[index] =
                        transfer.complete_end_and_eof_[index];
                    drained.packet.partial_evidence[index] =
                        transfer.evidence_[index];
                }
                rights_fd_count = 2;
                drained.packet.identity = packet_identity(drained.packet);
            }
            bool split_rights = false;
            int extra_fd = -1;
#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
            const auto archive_fault =
                authority.plan_.test_only_archive_fault;
            if (drained.packet.attempt_complete) switch (archive_fault) {
            case TestProducerArchiveTransportFault::None:
            case TestProducerArchiveTransportFault::SecondPacket:
            case TestProducerArchiveTransportFault::NonzeroExit:
                break;
            case TestProducerArchiveTransportFault::MissingFd:
                rights_fd_count = archive_fds.size() - 1;
                break;
            case TestProducerArchiveTransportFault::ExtraFd:
                extra_fd = ::fcntl(
                    archive_fds[0], F_DUPFD_CLOEXEC, 100);
                need(extra_fd >= 100);
                rights_fd_count = archive_fds.size() + 1;
                break;
            case TestProducerArchiveTransportFault::SplitRights:
                split_rights = true;
                break;
            case TestProducerArchiveTransportFault::SwappedFdOrder:
                std::swap(archive_fds[0], archive_fds[1]);
                break;
            case TestProducerArchiveTransportFault::SwappedFdAndEvidence:
                std::swap(archive_fds[0], archive_fds[1]);
                std::swap(
                    drained.packet.streams[0], drained.packet.streams[1]);
                drained.packet.identity = packet_identity(drained.packet);
                break;
            case TestProducerArchiveTransportFault::WritableFd:
                {
                    const int replacement = reopen_descriptor(
                        archive_fds[0], O_RDWR);
                    close_if_open(archive_fds[0]);
                    archive_fds[0] = replacement;
                }
                break;
            case TestProducerArchiveTransportFault::UnsealedFd:
                {
                    const int replacement = unsealed_copy(archive_fds[0]);
                    close_if_open(archive_fds[0]);
                    archive_fds[0] = replacement;
                }
                break;
            case TestProducerArchiveTransportFault::DuplicateFd:
                close_if_open(archive_fds[1]);
                archive_fds[1] = ::fcntl(
                    archive_fds[0], F_DUPFD_CLOEXEC, 100);
                need(archive_fds[1] >= 100);
                break;
            case TestProducerArchiveTransportFault::WrongBinding:
                drained.packet.binding.run_selection = Digest{};
                drained.packet.identity = packet_identity(drained.packet);
                break;
            case TestProducerArchiveTransportFault::WrongClosure:
                drained.packet.opaque_closure_authority_identity =
                    Digest{};
                drained.packet.identity = packet_identity(drained.packet);
                break;
            }
#endif
            struct iovec io{
                .iov_base = &drained.packet,
                .iov_len = sizeof(drained.packet),
            };
            std::array<unsigned char,
                CMSG_SPACE(sizeof(int) *
                           (producer_archive::PRODUCER_ARCHIVE_STREAM_COUNT +
                            1)) +
                CMSG_SPACE(sizeof(int) * 5)>
                control{};
            struct msghdr message{};
            message.msg_iov = &io;
            message.msg_iovlen = 1;
            message.msg_control = control.data();
            message.msg_controllen = split_rights
                ? CMSG_SPACE(sizeof(int) * 5) * 2
                : CMSG_SPACE(sizeof(int) * rights_fd_count);
            auto* rights = CMSG_FIRSTHDR(&message);
            need(rights != nullptr);
            rights->cmsg_level = SOL_SOCKET;
            rights->cmsg_type = SCM_RIGHTS;
            if (split_rights) {
                rights->cmsg_len = CMSG_LEN(sizeof(int) * 5);
                std::memcpy(
                    CMSG_DATA(rights), archive_fds.data(),
                    sizeof(int) * 5);
                auto* second = CMSG_NXTHDR(&message, rights);
                need(second != nullptr);
                second->cmsg_level = SOL_SOCKET;
                second->cmsg_type = SCM_RIGHTS;
                second->cmsg_len = CMSG_LEN(sizeof(int) * 5);
                std::memcpy(
                    CMSG_DATA(second), archive_fds.data() + 5,
                    sizeof(int) * 5);
            } else {
                rights->cmsg_len = CMSG_LEN(
                    sizeof(int) * rights_fd_count);
                std::array<int,
                    producer_archive::PRODUCER_ARCHIVE_STREAM_COUNT + 1>
                    supplied{};
                std::copy(
                    archive_fds.begin(), archive_fds.end(),
                    supplied.begin());
                if (rights_fd_count > archive_fds.size())
                    supplied.back() = extra_fd;
                std::memcpy(
                    CMSG_DATA(rights), supplied.data(),
                    sizeof(int) * rights_fd_count);
            }
            const auto count = ::sendmsg(
                sockets[1], &message, MSG_NOSIGNAL);
            for (auto& fd : archive_fds) close_if_open(fd);
            close_if_open(extra_fd);
            if (count != static_cast<ssize_t>(sizeof(drained.packet)))
                _exit(112);
#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
            if (authority.plan_.test_only_send_zero_record_before_close) {
                const auto zero = ::send(sockets[1], nullptr, 0,
                                         MSG_NOSIGNAL);
                if (zero != 0) _exit(113);
            }
            if (archive_fault ==
                    TestProducerArchiveTransportFault::SecondPacket) {
                const auto second = ::send(
                    sockets[1], &drained.packet,
                    sizeof(drained.packet), MSG_NOSIGNAL);
                if (second != static_cast<ssize_t>(sizeof(drained.packet)))
                    _exit(114);
            }
#endif
            close_if_open(sockets[1]);
#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
            if (archive_fault ==
                    TestProducerArchiveTransportFault::NonzeroExit)
                _exit(17);
#endif
            _exit(0);
        } catch (...) {
            _exit(111);
        }
    }

    close_if_open(sockets[1]);
    for (auto& fd : read_ends) close_if_open(fd);
    int child_pidfd = -1;
    try {
        child_pidfd = open_pidfd(child);
    } catch (...) {
        (void)::kill(child, SIGKILL);
        int status = 0;
        while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {}
        close_if_open(sockets[0]);
        throw;
    }
    return RunningCaptureProducer(
        std::move(authority.plan_), static_cast<int>(child), child_pidfd,
        sockets[0], start_monotonic_ns,
        std::move(retained_archive_builder), archive_devices,
        archive_inodes);
}

ParentAggregateMailboxRoutesAuthority::
ParentAggregateMailboxRoutesAuthority(
        std::array<PublicAggregateMailboxRouteCompletion, 2> routes)
    : routes_(std::move(routes)) {
    for (unsigned index = 0; index < routes_.size(); ++index) {
        const auto& route = routes_[index];
        need(route.round == index + 1 && nonzero(route.route_identity) &&
             nonzero(route.full_cohort_barrier_identity) &&
             nonzero(route.projection_identity) &&
             route.projection_bytes == PROJECTION_BYTES &&
             route.full_cohort_barrier_observed_monotonic_ns > 0 &&
             route.route_observed_monotonic_ns >
                 route.full_cohort_barrier_observed_monotonic_ns &&
             route.route_endpoint_count == 1 &&
             route.owner_ack_count == 0 && route.role_blind &&
             route.after_full_cohort_barrier &&
             !route.owner_socket_or_path_derived);
    }
    need(routes_[0].route_identity != routes_[1].route_identity &&
         routes_[0].full_cohort_barrier_identity !=
             routes_[1].full_cohort_barrier_identity);
}

ParentAggregateMailboxRoutesAuthority::
ParentAggregateMailboxRoutesAuthority(
        ParentAggregateMailboxRoutesAuthority&& other) noexcept
    : routes_(other.routes_), live_(other.live_.exchange(false)) {}

#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
ParentAggregateMailboxRoutesAuthority
ParentAggregateMailboxRoutesAuthority::test_only_mint(
        std::array<PublicAggregateMailboxRouteCompletion, 2> routes) {
    return ParentAggregateMailboxRoutesAuthority(std::move(routes));
}
#endif

RunningCaptureProducer::RunningCaptureProducer(
        PublicProducerLaunchPlan plan, int child_pid, int child_pidfd,
        int packet_fd,
        std::uint64_t start_monotonic_ns,
        std::unique_ptr<producer_archive::ProducerSealedArchiveBuilder>
            retained_archive_builder,
        std::array<std::uint64_t, 10> archive_devices,
        std::array<std::uint64_t, 10> archive_inodes)
    : plan_(std::move(plan)), child_pid_(child_pid),
      child_pidfd_(child_pidfd), packet_fd_(packet_fd),
      start_monotonic_ns_(start_monotonic_ns),
      retained_archive_builder_(std::move(retained_archive_builder)),
      archive_devices_(archive_devices), archive_inodes_(archive_inodes) {
    need(child_pid_ > 1 && child_pidfd_ >= 0 && packet_fd_ >= 0 &&
         start_monotonic_ns_ > 0 && retained_archive_builder_ != nullptr);
}

RunningCaptureProducer::RunningCaptureProducer(
        RunningCaptureProducer&& other) noexcept
    : plan_(std::move(other.plan_)), child_pid_(other.child_pid_),
      child_pidfd_(other.child_pidfd_),
      packet_fd_(other.packet_fd_),
      start_monotonic_ns_(other.start_monotonic_ns_),
      retained_archive_builder_(
          std::move(other.retained_archive_builder_)),
      archive_devices_(other.archive_devices_),
      archive_inodes_(other.archive_inodes_),
      active_(other.active_) {
    other.child_pid_ = -1;
    other.child_pidfd_ = -1;
    other.packet_fd_ = -1;
    other.start_monotonic_ns_ = 0;
    other.active_ = false;
}

RunningCaptureProducer::~RunningCaptureProducer() {
    if (!active_) {
        close_if_open(child_pidfd_);
        return;
    }
    close_if_open(packet_fd_);
    if (child_pid_ > 0) {
        if (child_pidfd_ >= 0) {
            try { signal_pidfd(child_pidfd_, SIGKILL); }
            catch (...) {}
        } else {
            (void)::kill(static_cast<pid_t>(child_pid_), SIGKILL);
        }
        int status = 0;
        while (::waitpid(static_cast<pid_t>(child_pid_), &status, 0) < 0 &&
               errno == EINTR) {}
    }
    close_if_open(child_pidfd_);
    child_pid_ = -1;
    active_ = false;
}

#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
ProducerRuntimeCompletion ParentOwnedCaptureProducer::finish(
        RunningCaptureProducer&& running,
        ParentAggregateMailboxRoutesAuthority&& route_authority) {
    const bool running_live = running.active_;
    const bool route_live = route_authority.live_.exchange(false);
    running.active_ = false;
    const pid_t child = static_cast<pid_t>(running.child_pid_);
    int socket = running.packet_fd_;
    running.child_pid_ = -1;
    running.packet_fd_ = -1;
    try {
        need(running_live && route_live && child > 1 && socket >= 0);
        for (unsigned index = 0;
             index < route_authority.routes_.size(); ++index)
            validate_route(route_authority.routes_[index],
                           running.plan_.route_requirements[index],
                           running.plan_.binding, index + 1);
        need(route_authority.routes_[0].route_identity !=
                 route_authority.routes_[1].route_identity &&
             route_authority.routes_[0].full_cohort_barrier_identity !=
                 route_authority.routes_[1]
                     .full_cohort_barrier_identity);
    } catch (...) {
        close_if_open(socket);
        if (child > 1) {
            (void)::kill(child, SIGKILL);
            int selected_status = 0;
            while (::waitpid(child, &selected_status, 0) < 0 &&
                   errno == EINTR) {}
        }
        refuse();
    }

    ChildPacket packet{};
    struct iovec io{.iov_base = &packet, .iov_len = sizeof(packet)};
    std::array<unsigned char,
        CMSG_SPACE(sizeof(struct ucred)) +
        CMSG_SPACE(sizeof(int) *
                   producer_archive::PRODUCER_ARCHIVE_STREAM_COUNT)>
        control{};
    struct msghdr message{};
    message.msg_iov = &io;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t received;
    do { received = ::recvmsg(socket, &message, MSG_CMSG_CLOEXEC); }
    while (received < 0 && errno == EINTR);

    int status = 0;
    pid_t waited;
#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
    if (running.plan_.test_only_wait_fault ==
            TestProducerWaitFault::FailFirstWaitpid) {
        waited = -1;
        errno = EIO;
    } else
#endif
    do { waited = ::waitpid(child, &status, 0); }
    while (waited < 0 && errno == EINTR);

    struct pollfd closure_poll{
        .fd = socket,
        .events = static_cast<short>(POLLIN | POLLHUP),
        .revents = 0,
    };
    int polled;
    do { polled = ::poll(&closure_poll, 1, -1); }
    while (polled < 0 && errno == EINTR);

    unsigned char trailing{};
    struct iovec trailing_io{.iov_base = &trailing, .iov_len = 1};
    std::array<unsigned char,
        CMSG_SPACE(sizeof(struct ucred)) +
        CMSG_SPACE(sizeof(int) *
                   producer_archive::PRODUCER_ARCHIVE_STREAM_COUNT)>
        trailing_control{};
    struct msghdr trailing_message{};
    trailing_message.msg_iov = &trailing_io;
    trailing_message.msg_iovlen = 1;
    trailing_message.msg_control = trailing_control.data();
    trailing_message.msg_controllen = trailing_control.size();
    ssize_t eof;
    do {
        eof = ::recvmsg(
            socket, &trailing_message,
            MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    }
    while (eof < 0 && errno == EINTR);
    close_if_open(socket);

    bool trailing_ancillary = false;
    if (eof >= 0) {
        for (auto* item = CMSG_FIRSTHDR(&trailing_message);
             item != nullptr;
             item = CMSG_NXTHDR(&trailing_message, item)) {
            trailing_ancillary = true;
            if (item->cmsg_level != SOL_SOCKET ||
                item->cmsg_type != SCM_RIGHTS ||
                item->cmsg_len < CMSG_LEN(0))
                continue;
            const auto payload = item->cmsg_len - CMSG_LEN(0);
            if (payload % sizeof(int) != 0) continue;
            const auto count = payload / sizeof(int);
            const auto* supplied = reinterpret_cast<const int*>(
                CMSG_DATA(item));
            for (std::size_t index = 0; index < count; ++index) {
                int extra = supplied[index];
                close_if_open(extra);
            }
        }
    }

    unsigned credential_count = 0;
    unsigned rights_count = 0;
    bool unexpected_ancillary = false;
    struct ucred credential{};
    ReceivedArchiveFds archive_fds;
    const bool primary_exact =
        received == static_cast<ssize_t>(sizeof(packet)) &&
        (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0;
    if (received >= 0) {
        for (auto* item = CMSG_FIRSTHDR(&message); item != nullptr;
             item = CMSG_NXTHDR(&message, item)) {
            if (item->cmsg_level == SOL_SOCKET &&
                item->cmsg_type == SCM_CREDENTIALS &&
                item->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {
                if (primary_exact) {
                    std::memcpy(
                        &credential, CMSG_DATA(item), sizeof(credential));
                    ++credential_count;
                } else {
                    unexpected_ancillary = true;
                }
            } else if (item->cmsg_level == SOL_SOCKET &&
                       item->cmsg_type == SCM_RIGHTS &&
                       item->cmsg_len >= CMSG_LEN(0)) {
                const auto payload = item->cmsg_len - CMSG_LEN(0);
                if (payload % sizeof(int) != 0) {
                    unexpected_ancillary = true;
                    continue;
                }
                const auto count = payload / sizeof(int);
                const auto* supplied = reinterpret_cast<const int*>(
                    CMSG_DATA(item));
                if (primary_exact &&
                    count == archive_fds.values.size() &&
                    rights_count == 0) {
                    std::copy(
                        supplied, supplied + count,
                        archive_fds.values.begin());
                } else {
                    unexpected_ancillary = true;
                    for (std::size_t index = 0; index < count; ++index) {
                        int extra = supplied[index];
                        close_if_open(extra);
                    }
                }
                ++rights_count;
            } else {
                unexpected_ancillary = true;
            }
        }
    }
    need(primary_exact && waited == child && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0 &&
         polled == 1 && (closure_poll.revents & POLLHUP) != 0 &&
         (closure_poll.revents & (POLLERR | POLLNVAL)) == 0 &&
         eof == 0 &&
         (trailing_message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0 &&
         trailing_message.msg_controllen == 0 && !trailing_ancillary &&
         credential_count == 1 && credential.pid == child &&
         credential.uid == ::getuid() && credential.gid == ::getgid() &&
         rights_count == 1 && !unexpected_ancillary &&
         packet.magic == PACKET_MAGIC &&
         packet.binding == running.plan_.binding &&
         packet.opaque_closure_authority_identity ==
             running.plan_.opaque_closure_authority_identity &&
         packet.identity == packet_identity(packet));

    for (unsigned index = 0; index < archive_fds.values.size(); ++index) {
        need(archive_fds.values[index] >= 0 &&
             (::fcntl(archive_fds.values[index], F_GETFD) & FD_CLOEXEC) != 0 &&
             reparse_retained_stream(
                 archive_fds.values[index], running.plan_.streams[index]) ==
                 packet.streams[index]);
    }

    const auto child_exit = child_exit_identity(
        running.plan_, packet, child, status, true, true, true, false);
    const auto producer = producer_identity(
        running.plan_, packet, route_authority.routes_, child_exit);
    const auto receipt = receipt_identity(
        running.plan_, packet, producer, child_exit);
    auto closure = closure_receipt(running.plan_);
    auto evidence = closure_evidence(
        running.plan_, packet, producer, receipt, child_exit);
    auto archive = producer_archive::ProducerSealedArchiveAuthority::
        adopt_received(
            running.plan_.binding,
            running.plan_.opaque_closure_authority_identity,
            std::move(archive_fds.values), evidence.streams);
    auto public_value = public_receipt(running.plan_);
    ProducerClosureAuthority closure_authority(
        std::move(closure), std::move(evidence));
    return ProducerRuntimeCompletion(
        std::move(public_value), std::move(closure_authority),
        std::move(archive));
}
#endif

ProducerAttemptOutcomeAuthority ParentOwnedCaptureProducer::finish_outcome(
        RunningCaptureProducer&& running) {
    return finish_outcome_impl(std::move(running), nullptr);
}

ProducerAttemptOutcomeAuthority ParentOwnedCaptureProducer::finish_outcome(
        RunningCaptureProducer&& running,
        ParentAggregateMailboxRoutesAuthority&& route_authority) {
    return finish_outcome_impl(std::move(running), &route_authority);
}

ProducerAttemptOutcomeAuthority ParentOwnedCaptureProducer::finish_outcome_impl(
        RunningCaptureProducer&& running,
        ParentAggregateMailboxRoutesAuthority* route_authority) {
    // Reserve the return capsule before claiming any linear input.  Once a
    // genuine running attempt is claimed, every subsequent source failure is
    // converted into this capsule instead of unwinding through the owner.
    auto outcome_storage =
        std::make_unique<ProducerAttemptOutcomeAuthority::Storage>();
    outcome_storage->plan = running.plan_;
    // A stale/moved-from handle has no source archive to preserve. Refuse it
    // before burning a fresh route capability. Every malformed live handle
    // that still owns the ten parent files is claimed below and converted to
    // the preallocated unavailable/quarantine arm.
    need(running.active_ &&
         running.retained_archive_builder_ != nullptr);
    const bool running_live = running.active_;
    const bool route_live = route_authority != nullptr &&
        route_authority->live_.exchange(false);
    running.active_ = false;
    const pid_t child = static_cast<pid_t>(running.child_pid_);
    int child_pidfd = std::exchange(running.child_pidfd_, -1);
    int socket = std::exchange(running.packet_fd_, -1);
    running.child_pid_ = -1;
    auto retained_builder =
        std::move(running.retained_archive_builder_);

    outcome_storage->producer_pid = child;
    outcome_storage->start_monotonic_ns = running.start_monotonic_ns_;
    outcome_storage->route_claimed = route_authority != nullptr;

    bool route_valid = false;
    int status = -1;
    pid_t waited = -1;
    bool wait_observed = false;
    bool pidfd_exit_observed = false;
    std::uint64_t end_monotonic_ns = running.start_monotonic_ns_;
    auto quarantine_stage =
        producer_archive::ProducerArchiveQuarantineStage::Transport;
    std::unique_ptr<producer_archive::ProducerPartialC03ArchiveAuthority>
        history_archive;
    std::unique_ptr<
        producer_archive::ProducerPartialC03ArchiveRuntimeTransfer>
        history_transfer;
    std::unique_ptr<ProducerAttemptC03HistoryAuthority::Storage>
        history_storage;
    std::unique_ptr<ProducerRuntimeCompletion> completion;

    try {
    need(running_live && child > 1 && child_pidfd >= 0 && socket >= 0 &&
         running.start_monotonic_ns_ > 0 && retained_builder != nullptr);
#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
    if (running.plan_.test_only_drain_fault ==
            TestProducerDrainFault::FailAllocationAfterClaim)
        throw std::bad_alloc();
#endif
    if (route_live) {
        try {
            for (unsigned index = 0;
                 index < route_authority->routes_.size(); ++index)
                validate_route(route_authority->routes_[index],
                               running.plan_.route_requirements[index],
                               running.plan_.binding, index + 1);
            need(route_authority->routes_[0].route_identity !=
                     route_authority->routes_[1].route_identity &&
                 route_authority->routes_[0]
                         .full_cohort_barrier_identity !=
                     route_authority->routes_[1]
                         .full_cohort_barrier_identity);
            route_valid = true;
        } catch (const Refused&) {
            route_valid = false;
        }
    }
    outcome_storage->route_valid = route_valid;

    ChildPacket packet{};
    struct iovec io{.iov_base = &packet, .iov_len = sizeof(packet)};
    std::array<unsigned char,
        CMSG_SPACE(sizeof(struct ucred)) +
        CMSG_SPACE(sizeof(int) *
                   producer_archive::PRODUCER_ARCHIVE_STREAM_COUNT)>
        control{};
    struct msghdr message{};
    message.msg_iov = &io;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t received;
    do { received = ::recvmsg(socket, &message, MSG_CMSG_CLOEXEC); }
    while (received < 0 && errno == EINTR);

    status = 0;
#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
    const bool fail_first_wait =
        running.plan_.test_only_wait_fault ==
            TestProducerWaitFault::FailFirstWaitpid ||
        running.plan_.test_only_wait_fault ==
            TestProducerWaitFault::FailAllWaitpid;
    const bool fail_all_wait =
        running.plan_.test_only_wait_fault ==
            TestProducerWaitFault::FailAllWaitpid;
    if (fail_first_wait) {
        waited = -1;
        errno = EIO;
    } else
#endif
    {
        do { waited = ::waitpid(child, &status, 0); }
        while (waited < 0 && errno == EINTR);
    }
    if (waited != child) {
        signal_pidfd(child_pidfd, SIGKILL);
        pidfd_exit_observed = observe_pidfd_exit(child_pidfd);
        int recovered_status = 0;
        pid_t recovered;
        do { recovered = ::waitpid(child, &recovered_status, 0); }
        while (recovered < 0 && errno == EINTR);
#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
        if (fail_all_wait) {
            waited = -1;
            status = -1;
        } else
#endif
        if (recovered == child) {
            waited = recovered;
            status = recovered_status;
        }
    }
    wait_observed = waited == child;
    if (wait_observed && !pidfd_exit_observed)
        pidfd_exit_observed = observe_pidfd_exit(child_pidfd);
    close_if_open(child_pidfd);
    end_monotonic_ns = observed_monotonic_ns();

    struct pollfd closure_poll{
        .fd = socket,
        .events = static_cast<short>(POLLIN | POLLHUP),
        .revents = 0,
    };
    int polled;
    do { polled = ::poll(&closure_poll, 1, -1); }
    while (polled < 0 && errno == EINTR);

    unsigned char trailing{};
    struct iovec trailing_io{.iov_base = &trailing, .iov_len = 1};
    std::array<unsigned char,
        CMSG_SPACE(sizeof(struct ucred)) +
        CMSG_SPACE(sizeof(int) *
                   producer_archive::PRODUCER_ARCHIVE_STREAM_COUNT)>
        trailing_control{};
    struct msghdr trailing_message{};
    trailing_message.msg_iov = &trailing_io;
    trailing_message.msg_iovlen = 1;
    trailing_message.msg_control = trailing_control.data();
    trailing_message.msg_controllen = trailing_control.size();
    ssize_t eof;
    do {
        eof = ::recvmsg(socket, &trailing_message,
                        MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    } while (eof < 0 && errno == EINTR);
    close_if_open(socket);

    bool trailing_ancillary = false;
    if (eof >= 0) {
        for (auto* item = CMSG_FIRSTHDR(&trailing_message);
             item != nullptr;
             item = CMSG_NXTHDR(&trailing_message, item)) {
            trailing_ancillary = true;
            if (item->cmsg_level != SOL_SOCKET ||
                item->cmsg_type != SCM_RIGHTS ||
                item->cmsg_len < CMSG_LEN(0))
                continue;
            const auto payload = item->cmsg_len - CMSG_LEN(0);
            if (payload % sizeof(int) != 0) continue;
            const auto count = payload / sizeof(int);
            const auto* supplied = reinterpret_cast<const int*>(
                CMSG_DATA(item));
            for (std::size_t index = 0; index < count; ++index) {
                int extra = supplied[index];
                close_if_open(extra);
            }
        }
    }

    unsigned credential_count = 0;
    unsigned rights_messages = 0;
    std::size_t rights_count = 0;
    bool unexpected_ancillary = false;
    struct ucred credential{};
    ReceivedArchiveFds received_fds;
    const bool primary_exact =
        received == static_cast<ssize_t>(sizeof(packet)) &&
        (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0;
    if (received >= 0) {
        for (auto* item = CMSG_FIRSTHDR(&message); item != nullptr;
             item = CMSG_NXTHDR(&message, item)) {
            if (item->cmsg_level == SOL_SOCKET &&
                item->cmsg_type == SCM_CREDENTIALS &&
                item->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {
                if (primary_exact) {
                    std::memcpy(&credential, CMSG_DATA(item),
                                sizeof(credential));
                    ++credential_count;
                } else {
                    unexpected_ancillary = true;
                }
            } else if (item->cmsg_level == SOL_SOCKET &&
                       item->cmsg_type == SCM_RIGHTS &&
                       item->cmsg_len >= CMSG_LEN(0)) {
                ++rights_messages;
                const auto payload = item->cmsg_len - CMSG_LEN(0);
                if (payload % sizeof(int) != 0) {
                    unexpected_ancillary = true;
                    continue;
                }
                const auto count = payload / sizeof(int);
                const auto* supplied = reinterpret_cast<const int*>(
                    CMSG_DATA(item));
                if (!primary_exact || rights_messages != 1 ||
                    count > received_fds.values.size()) {
                    unexpected_ancillary = true;
                    for (std::size_t index = 0; index < count; ++index) {
                        int extra = supplied[index];
                        close_if_open(extra);
                    }
                    continue;
                }
                rights_count = count;
                std::copy(supplied, supplied + count,
                          received_fds.values.begin());
            } else {
                unexpected_ancillary = true;
            }
        }
    }

    const bool clean_transport =
        wait_observed && polled == 1 &&
        (closure_poll.revents & POLLHUP) != 0 &&
        (closure_poll.revents & (POLLERR | POLLNVAL)) == 0 &&
        eof == 0 &&
        (trailing_message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0 &&
        trailing_message.msg_controllen == 0 && !trailing_ancillary;
    const bool authenticated_packet =
        primary_exact && clean_transport && credential_count == 1 &&
        credential.pid == child && credential.uid == ::getuid() &&
        credential.gid == ::getgid() && rights_messages == 1 &&
        !unexpected_ancillary && packet.magic == PACKET_MAGIC &&
        packet.binding == running.plan_.binding &&
        packet.opaque_closure_authority_identity ==
            running.plan_.opaque_closure_authority_identity &&
        packet.identity == packet_identity(packet) &&
        (packet.attempt_complete == 0 || packet.attempt_complete == 1);

    // A missing wait status is accepted only after the exact forked process
    // has signaled exit on its pidfd. It can never produce a completion.
    need(wait_observed || pidfd_exit_observed);
    quarantine_stage =
        producer_archive::ProducerArchiveQuarantineStage::PartialC03Seal;
    history_archive = std::make_unique<
            producer_archive::ProducerPartialC03ArchiveAuthority>(
                std::move(*retained_builder)
                    .seal_partial_c03_for_runtime());
#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
    if (running.plan_.test_only_drain_fault ==
            TestProducerDrainFault::FailAllocationAfterPartialSeal)
        throw std::bad_alloc();
#endif
    bool complete_attempt = false;
    if (authenticated_packet && packet.attempt_complete == 1 &&
        rights_count == producer_archive::PRODUCER_ARCHIVE_STREAM_COUNT &&
        wait_observed && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
        route_valid) {
        try {
            for (unsigned index = 0;
                 index < received_fds.values.size(); ++index) {
                struct stat selected{};
                need(received_fds.values[index] >= 0 &&
                     ::fstat(received_fds.values[index], &selected) == 0 &&
                     static_cast<std::uint64_t>(selected.st_dev) ==
                         running.archive_devices_[index] &&
                     static_cast<std::uint64_t>(selected.st_ino) ==
                         running.archive_inodes_[index] &&
                     reparse_retained_stream(
                         received_fds.values[index],
                         running.plan_.streams[index]) ==
                         packet.streams[index]);
            }
            const auto selected_child_exit = child_exit_identity(
                running.plan_, packet, child, status, true, true,
                wait_observed, pidfd_exit_observed);
            const auto producer = producer_identity(
                running.plan_, packet, route_authority->routes_,
                selected_child_exit);
            const auto receipt = receipt_identity(
                running.plan_, packet, producer, selected_child_exit);
            auto closure = closure_receipt(running.plan_);
            auto evidence = closure_evidence(
                running.plan_, packet, producer, receipt,
                selected_child_exit);
            auto archive =
                producer_archive::ProducerSealedArchiveAuthority::
                    adopt_received(
                        running.plan_.binding,
                        running.plan_.opaque_closure_authority_identity,
                        std::move(received_fds.values), evidence.streams);
            auto public_value = public_receipt(running.plan_);
            ProducerClosureAuthority closure_authority(
                std::move(closure), std::move(evidence));
            completion.reset(new ProducerRuntimeCompletion(
                std::move(public_value), std::move(closure_authority),
                std::move(archive)));
            complete_attempt = true;
        } catch (const Refused&) {
            completion.reset();
        }
    }

    quarantine_stage =
        producer_archive::ProducerArchiveQuarantineStage::Transport;
    history_transfer = std::unique_ptr<
        producer_archive::ProducerPartialC03ArchiveRuntimeTransfer>(
            new producer_archive::ProducerPartialC03ArchiveRuntimeTransfer(
                std::move(*history_archive)
                    .duplicate_for_runtime_transport()));
    history_archive.reset();
    quarantine_stage =
        producer_archive::ProducerArchiveQuarantineStage::Inspection;
    history_storage =
        std::make_unique<ProducerAttemptC03HistoryAuthority::Storage>();
    need(history_transfer->binding_ == running.plan_.binding &&
         history_transfer->closure_identity_ ==
             running.plan_.opaque_closure_authority_identity &&
         nonzero(history_transfer->reservation_identity_));
    history_storage->binding = history_transfer->binding_;
    history_storage->capture_trial_id = running.plan_.capture_trial_id;
    history_storage->capture_attempt_ids =
        running.plan_.capture_attempt_ids;
    history_storage->closure_identity = history_transfer->closure_identity_;
    history_storage->archive_reservation_identity =
        history_transfer->reservation_identity_;
    history_storage->writer_aliases_closed = true;
    for (unsigned round = 0; round < 2; ++round) {
        history_storage->route_requirements[round] =
            route_requirement_identity(
                running.plan_.route_requirements[round]);
        if (route_valid)
            history_storage->route_completions[round] =
                route_authority->routes_[round].route_identity;
    }
    history_storage->source_slots = history_transfer->source_slots_;
    history_storage->fixed_fds = history_transfer->fixed_fds_;
    for (unsigned index = 0; index < 2; ++index) {
        history_storage->devices[index] = history_transfer->devices_[index];
        history_storage->inodes[index] = history_transfer->inodes_[index];
        history_storage->sizes[index] = history_transfer->sizes_[index];
        history_storage->seals[index] = history_transfer->seals_[index];
        history_storage->sha256[index] = history_transfer->sha256_[index];
        history_storage->complete_end_and_eof[index] =
            history_transfer->complete_end_and_eof_[index];
        history_storage->evidence[index] = history_transfer->evidence_[index];
        const auto inspection = inspect_partial_c03(
            history_transfer->fds_[index],
            running.plan_.streams[history_transfer->source_slots_[index]]);
        history_storage->states[index] = inspection.state;
        history_storage->failures[index] = inspection.failure;
#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
        if (index == 0 && running.plan_.test_only_drain_fault ==
                TestProducerDrainFault::FailC03InspectionAfterSeal)
            refuse();
#endif
    }
#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
    if (running.plan_.test_only_drain_fault ==
            TestProducerDrainFault::FailAllocationAfterC03Inspection)
        throw std::bad_alloc();
#endif
    history_storage->start_monotonic_ns = running.start_monotonic_ns_;
    history_storage->end_monotonic_ns = end_monotonic_ns;
    history_storage->producer_pid = child;
    history_storage->producer_wait_status = status;
    history_storage->wait_observed = wait_observed;
    history_storage->pidfd_exit_observed = pidfd_exit_observed;
    history_storage->first_failed_slot = authenticated_packet
        ? packet.first_failed_slot : 0xff;
    history_storage->producer_child_exit_identity = child_exit_identity(
        running.plan_, packet, child, status, primary_exact,
        authenticated_packet, wait_observed, pidfd_exit_observed);
    if (complete_attempt) {
        history_storage->attempt_failure =
            ProducerAttemptDrainFailure::None;
    } else if (!wait_observed && pidfd_exit_observed) {
        history_storage->attempt_failure =
            ProducerAttemptDrainFailure::WaitStatusUnavailable;
    } else if (WIFSIGNALED(status)) {
        history_storage->attempt_failure =
            ProducerAttemptDrainFailure::ProducerChildSignaled;
    } else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        history_storage->attempt_failure =
            ProducerAttemptDrainFailure::ProducerChildExitedNonzero;
    } else if (authenticated_packet && packet.attempt_complete == 0 &&
               rights_count == 2) {
        history_storage->attempt_failure = packet.attempt_failure;
    } else if (!route_valid && authenticated_packet &&
               packet.attempt_complete == 1) {
        history_storage->attempt_failure =
            ProducerAttemptDrainFailure::RouteUnavailable;
    } else {
        history_storage->attempt_failure =
            ProducerAttemptDrainFailure::CaptureReadFailed;
    }

    // Descriptor transfer is the final fallible-history transition. All
    // validation, hashing, parsing and identity construction above still had
    // the independent partial authority available for quarantine recovery.
    for (unsigned index = 0; index < history_storage->fds.size(); ++index)
        history_storage->fds[index] =
            std::exchange(history_transfer->fds_[index], -1);
    history_transfer.reset();
    outcome_storage->history = std::move(history_storage);
    outcome_storage->completion = std::move(completion);
    retained_builder.reset();
    return ProducerAttemptOutcomeAuthority(std::move(outcome_storage));
    } catch (...) {
        const auto failure = std::current_exception();
        const int failure_errno = errno > 0 ? errno : EPROTO;

        // The pidfd is the only process identity accepted after the running
        // capability is claimed. Never fall back to signaling a raw PID.
        if (child_pidfd >= 0 && !pidfd_exit_observed) {
            try {
                signal_pidfd(child_pidfd, SIGKILL);
                pidfd_exit_observed = observe_pidfd_exit(child_pidfd);
            } catch (...) {
                // The opaque unavailable result retains the fact that exact
                // exit could not be established; it cannot be scored.
            }
        }
        if (!wait_observed && pidfd_exit_observed) {
            int recovered_status = -1;
            pid_t recovered;
            do { recovered = ::waitpid(child, &recovered_status, 0); }
            while (recovered < 0 && errno == EINTR);
            if (recovered == child) {
                waited = recovered;
                status = recovered_status;
                wait_observed = true;
            }
        }
        close_if_open(socket);
        close_if_open(child_pidfd);
        if (end_monotonic_ns <= running.start_monotonic_ns_) {
            try { end_monotonic_ns = observed_monotonic_ns(); }
            catch (...) { end_monotonic_ns = running.start_monotonic_ns_; }
        }

        // Recover the independent two-C03 authority if the transport handoff
        // had already begun. The all-ten originals remain separately owned by
        // retained_builder until the quarantine transition below.
        if (history_archive != nullptr) {
            outcome_storage->partial.emplace(std::move(*history_archive));
            history_archive.reset();
        } else if (history_transfer != nullptr) {
            try {
                outcome_storage->partial.emplace(
                    producer_archive::ProducerPartialC03ArchiveAuthority::
                        adopt_runtime_transport(
                            std::move(*history_transfer)));
            } catch (...) {
                // The all-ten source originals below remain authoritative.
            }
        }
        history_storage.reset();
        completion.reset();

        outcome_storage->quarantine.emplace(
            std::move(*retained_builder).quarantine_for_runtime(
                quarantine_stage, failure_errno));
        retained_builder.reset();
        outcome_storage->producer_pid = child;
        outcome_storage->wait_status = status;
        outcome_storage->start_monotonic_ns =
            running.start_monotonic_ns_;
        outcome_storage->end_monotonic_ns = end_monotonic_ns;
        outcome_storage->wait_observed = wait_observed;
        outcome_storage->pidfd_exit_observed = pidfd_exit_observed;
        outcome_storage->route_claimed = route_authority != nullptr;
        outcome_storage->route_valid = route_valid;
        outcome_storage->quarantine_stage = quarantine_stage;
        outcome_storage->error_number = failure_errno;
        outcome_storage->failure = failure;
        return ProducerAttemptOutcomeAuthority(std::move(outcome_storage));
    }
}

#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
ProducerAttemptDrainResult ParentOwnedCaptureProducer::finish_attempt(
        RunningCaptureProducer&& running) {
    auto outcome = finish_outcome(std::move(running));
    need(outcome.storage_ != nullptr &&
         outcome.storage_->history != nullptr &&
         !outcome.storage_->quarantine.has_value());
    ProducerAttemptC03HistoryAuthority history(
        std::move(outcome.storage_->history));
    return ProducerAttemptDrainResult(
        std::move(history), std::move(outcome.storage_->completion));
}

ProducerAttemptDrainResult ParentOwnedCaptureProducer::finish_attempt(
        RunningCaptureProducer&& running,
        ParentAggregateMailboxRoutesAuthority&& route_authority) {
    auto outcome = finish_outcome(
        std::move(running), std::move(route_authority));
    need(outcome.storage_ != nullptr &&
         outcome.storage_->history != nullptr &&
         !outcome.storage_->quarantine.has_value());
    ProducerAttemptC03HistoryAuthority history(
        std::move(outcome.storage_->history));
    return ProducerAttemptDrainResult(
        std::move(history), std::move(outcome.storage_->completion));
}

void ParentOwnedCaptureProducer::test_only_invalidate_running_packet_fd(
        RunningCaptureProducer& running) {
    close_if_open(running.packet_fd_);
}

ParentOwnedCaptureProducer::TestOnlyArchiveIdentity
ParentOwnedCaptureProducer::test_only_archive_identity(
        const RunningCaptureProducer& running) {
    need(running.active_ && running.retained_archive_builder_ != nullptr);
    return {
        .devices = running.archive_devices_,
        .inodes = running.archive_inodes_,
    };
}
#endif

} // namespace kpb::measurement::producer_runtime

