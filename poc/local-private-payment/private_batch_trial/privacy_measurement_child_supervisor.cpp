#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "privacy_measurement_runtime_bridge.hpp"
#include "privacy_measurement_child_output_authority.hpp"
#include "privacy_measurement_preexec_sandbox.hpp"
#include "privacy_measurement_sha256.hpp"
#include "privacy_native_empirical_result_authority.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <span>
#include <set>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpb::measurement::runtime_bridge {
namespace {

using Bytes = std::vector<unsigned char>;

constexpr std::array<unsigned char, 8> OFFER_MAGIC{
    'K', 'P', 'B', 'M', 'O', 'F', '2', 0};
constexpr std::array<unsigned char, 8> ACK_MAGIC{
    'K', 'P', 'B', 'M', 'A', 'K', '2', 0};
constexpr std::array<unsigned char, 8> COMPLETION_MAGIC{
    'K', 'P', 'B', 'M', 'C', 'P', '2', 0};

constexpr std::size_t WORKER_BYTES = 6 * 32;
constexpr std::size_t INPUT_OFFER_BYTES =
    1 + 4 + 4 + 32 + 1 + 12 * 32 + 8 + 32 + 32;
constexpr std::size_t OFFER_BYTES =
    8 + 1 + 4 + 8 + 8 + 32 + WORKER_BYTES + 32 + 32 + 32 + 32 + 32 + 32 + 1 +
    32 + 32 + 8 + MAX_MEASUREMENT_INPUTS * INPUT_OFFER_BYTES + 32 + 32;
constexpr std::size_t ACK_BYTES =
    8 + 1 + 4 + 8 + 8 + 32 + 32 + 32 + 32;
constexpr std::size_t COMPLETION_BYTES =
    8 + 1 + 4 + 32 + 32 + 32 + 32 + 32 + 32 + 1 + 1 + 32 + 32;

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
    return kpb::measurement::detail::sha256(value);
}

void add_worker(Bytes& out, const WorkerBinding& worker) {
    for (const auto* value : {
             &worker.source_identity, &worker.build_identity,
             &worker.runtime_identity, &worker.assets_identity,
             &worker.pinned_executable_identity,
             &worker.launcher_identity})
        add(out, *value);
}

void add_lineage(
        Bytes& out,
        const PublicMeasurementInputEndpoint::PublicLineage& lineage) {
    integer(out, static_cast<unsigned char>(lineage.classification), 1);
    add(out, lineage.trial);
    add(out, lineage.barrier);
    for (const auto* values : {
             &lineage.capture_plan_identities, &lineage.financial_runs,
             &lineage.round_attempts, &lineage.round_cohorts,
             &lineage.projections})
        for (const auto& value : *values) add(out, value);
}

void add_input(Bytes& out, const RuntimeInputOffer& input) {
    integer(out, static_cast<unsigned char>(input.endpoint.kind), 1);
    integer(out, input.endpoint.owner, 4);
    integer(out, static_cast<std::uint32_t>(input.endpoint.fixed_fd), 4);
    add(out, input.endpoint.identity);
    add_lineage(out, input.endpoint.lineage);
    integer(out, static_cast<std::uint64_t>(input.feeder_pid));
    add(out, input.feeder_session);
    add(out, input.feeder_exit_identity);
}

void valid_worker(const WorkerBinding& worker) {
    for (const auto* value : {
             &worker.source_identity, &worker.build_identity,
             &worker.runtime_identity, &worker.assets_identity,
             &worker.pinned_executable_identity,
             &worker.launcher_identity})
        need(nonzero(*value));
}

void valid_offer_capsule(const PublicRuntimeChildOffer& offer) {
    const auto* output_abi = measurement_output_abi(offer.role);
    need(offer.input_count <= offer.inputs.size() &&
         nonzero(offer.capsule_identity) &&
         nonzero(offer.descriptor_manifest_identity) &&
         nonzero(offer.opaque_completion_authority_identity) &&
         ((offer.role == RuntimeChildRole::OwnerScore &&
           nonzero(offer.opaque_capsule_authority_identity) &&
           offer.opaque_capsule_authority_identity !=
               offer.opaque_completion_authority_identity) ||
          (offer.role != RuntimeChildRole::OwnerScore &&
           !nonzero(offer.opaque_capsule_authority_identity))) &&
         ((output_abi != nullptr &&
           nonzero(offer.output_authority_identity) &&
           offer.output_abi_identity == output_abi->identity &&
           offer.output_exact_size == output_abi->exact_bytes) ||
          (output_abi == nullptr &&
           !nonzero(offer.output_authority_identity) &&
           !nonzero(offer.output_abi_identity) &&
           offer.output_exact_size == 0)));
    PublicMeasurementWorkerCapsule capsule{
        .role = offer.role,
        .owner = offer.owner,
        .worker = offer.worker,
        .descriptor_manifest_identity = offer.descriptor_manifest_identity,
        .input_count = offer.input_count,
        .capsule_identity = offer.capsule_identity,
    };
    for (unsigned index = 0; index < offer.inputs.size(); ++index) {
        const auto& input = offer.inputs[index];
        if (index < offer.input_count) {
            need(input.feeder_pid > 1 &&
                 nonzero(input.feeder_session) &&
                 nonzero(input.feeder_exit_identity));
            capsule.inputs[index] = input.endpoint;
        } else {
            need(input == RuntimeInputOffer{});
        }
    }
    need(recompute_worker_capsule_identity(capsule) ==
         offer.capsule_identity);
}

void validate_inherited_capsule(const PublicRuntimeChildOffer& offer) {
    constexpr int required_seals =
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    std::set<std::pair<std::uint64_t, std::uint64_t>> objects;
    const auto inspect = [&](int fd, bool sealed_regular) {
        struct stat state{};
        need(fd >= 0 && ::fstat(fd, &state) == 0 &&
             objects.emplace(
                 static_cast<std::uint64_t>(state.st_dev),
                 static_cast<std::uint64_t>(state.st_ino)).second);
        const int flags = ::fcntl(fd, F_GETFL);
        need(flags >= 0);
        if (S_ISREG(state.st_mode) || S_ISFIFO(state.st_mode) ||
            S_ISDIR(state.st_mode))
            need((flags & O_ACCMODE) == O_RDONLY);
        if (sealed_regular)
            need(S_ISREG(state.st_mode) &&
                 (::fcntl(fd, F_GET_SEALS) & required_seals) ==
                     required_seals);
    };
    inspect(MEASUREMENT_SOURCE_CAPSULE_FD, true);
    inspect(MEASUREMENT_ASSET_CAPSULE_FD, true);
    inspect(MEASUREMENT_CHILD_FIXED_FD, false);
    std::set<int> admitted{
        MEASUREMENT_SOURCE_CAPSULE_FD,
        MEASUREMENT_ASSET_CAPSULE_FD,
        MEASUREMENT_CHILD_FIXED_FD,
    };
    if (measurement_output_abi(offer.role) != nullptr) {
        struct stat output{};
        need(::fstat(MEASUREMENT_CHILD_OUTPUT_FD, &output) == 0 &&
             S_ISREG(output.st_mode) && output.st_size == 0 &&
             (::fcntl(MEASUREMENT_CHILD_OUTPUT_FD, F_GETFL) & O_ACCMODE) ==
                 O_WRONLY &&
             ::fcntl(MEASUREMENT_CHILD_OUTPUT_FD, F_GET_SEALS) == 0 &&
             objects.emplace(
                 static_cast<std::uint64_t>(output.st_dev),
                 static_cast<std::uint64_t>(output.st_ino)).second &&
             admitted.insert(MEASUREMENT_CHILD_OUTPUT_FD).second);
    }
    for (unsigned index = 0; index < offer.input_count; ++index) {
        const int fd = offer.inputs[index].endpoint.fixed_fd;
        need(admitted.insert(fd).second);
        inspect(fd, false);
    }
    const long maximum = ::sysconf(_SC_OPEN_MAX);
    need(maximum > MEASUREMENT_CHILD_FIXED_FD);
    for (int fd = 0; fd <= 2; ++fd) {
        errno = 0;
        need(::fcntl(fd, F_GETFD) < 0 && errno == EBADF);
    }
    for (int fd = 3; fd < maximum; ++fd) {
        errno = 0;
        const int state = ::fcntl(fd, F_GETFD);
        need(state >= 0 || errno == EBADF);
        if (state >= 0) need(admitted.contains(fd));
    }
}

void require_lineage(
        const RunBinding& binding,
        const PublicMeasurementInputEndpoint::PublicLineage& lineage) {
    need(lineage.classification == binding.classification &&
         lineage.trial == binding.trial &&
         lineage.capture_plan_identities ==
             binding.round_capture_plans &&
         lineage.financial_runs == binding.financial_runs &&
         lineage.round_attempts == binding.round_attempts &&
         lineage.round_cohorts == binding.round_cohorts &&
         lineage.projections == binding.projections);
}

void require_capsule_binding(
        const PublicMeasurementWorkerCapsule& capsule,
        const RunBinding& binding) {
    for (unsigned index = 0; index < capsule.input_count; ++index)
        require_lineage(binding, capsule.inputs[index].lineage);
}

bool selected_role(RuntimeChildRole role) {
    return role == RuntimeChildRole::Observer ||
           role == RuntimeChildRole::OwnerScore ||
           role == RuntimeChildRole::Aggregate ||
           role == RuntimeChildRole::OwnerComparison;
}

void valid_role_owner(RuntimeChildRole role, unsigned owner) {
    need(selected_role(role));
    if (role == RuntimeChildRole::OwnerScore)
        need(owner < 3);
    else
        need(owner == NO_OWNER);
}

void valid_result(RuntimeChildRole role, unsigned owner,
                  const RuntimeChildResult& result) {
    valid_role_owner(role, owner);
    const auto aggregate = static_cast<unsigned char>(
        result.aggregate_outcome);
    const auto comparison = static_cast<unsigned char>(
        result.comparison_outcome);
    const bool private_output = measurement_output_abi(role) != nullptr;
    need(nonzero(result.private_output_content_hash) == private_output);
    if (role == RuntimeChildRole::OwnerScore) {
        need(aggregate == 0 && comparison == 0);
    } else {
        if (role == RuntimeChildRole::Aggregate) {
            need((result.aggregate_outcome ==
                      AggregateOutcome::BaselineControlDetected ||
                  result.aggregate_outcome == AggregateOutcome::CandidatePass ||
                  result.aggregate_outcome == AggregateOutcome::Fail ||
                  result.aggregate_outcome == AggregateOutcome::Unqualified) &&
                 comparison == 0);
        } else if (role == RuntimeChildRole::OwnerComparison) {
            need(aggregate == 0 &&
                 (result.comparison_outcome ==
                      OwnerComparisonOutcome::NonRegressionPass ||
                  result.comparison_outcome == OwnerComparisonOutcome::Fail ||
                  result.comparison_outcome ==
                      OwnerComparisonOutcome::Unqualified));
        } else {
            need(aggregate == 0 && comparison == 0);
        }
    }
}

class Reader final {
    std::span<const unsigned char> bytes_;
    std::size_t at_{};
public:
    explicit Reader(std::span<const unsigned char> bytes) : bytes_(bytes) {}

    void magic(std::span<const unsigned char> expected) {
        need(at_ + expected.size() <= bytes_.size() &&
             std::equal(expected.begin(), expected.end(),
                        bytes_.begin() + static_cast<std::ptrdiff_t>(at_)));
        at_ += expected.size();
    }

    std::uint64_t integer(unsigned width = 8) {
        need(width <= 8 && at_ + width <= bytes_.size());
        std::uint64_t result = 0;
        for (unsigned offset = 0; offset < width; ++offset)
            result |= static_cast<std::uint64_t>(bytes_[at_++]) <<
                      (8 * offset);
        return result;
    }

    Digest digest() {
        need(at_ + 32 <= bytes_.size());
        Digest result{};
        std::copy_n(bytes_.begin() + static_cast<std::ptrdiff_t>(at_),
                    result.size(), result.begin());
        at_ += result.size();
        return result;
    }

    WorkerBinding worker() {
        return {
            .source_identity = digest(),
            .build_identity = digest(),
            .runtime_identity = digest(),
            .assets_identity = digest(),
            .pinned_executable_identity = digest(),
            .launcher_identity = digest(),
        };
    }

    PublicMeasurementInputEndpoint::PublicLineage lineage() {
        PublicMeasurementInputEndpoint::PublicLineage result{};
        result.classification = static_cast<Classification>(integer(1));
        result.trial = digest();
        result.barrier = digest();
        for (auto* values : {
                 &result.capture_plan_identities, &result.financial_runs,
                 &result.round_attempts, &result.round_cohorts,
                 &result.projections})
            for (auto& value : *values) value = digest();
        return result;
    }

    RuntimeInputOffer input() {
        RuntimeInputOffer result{};
        result.endpoint.kind =
            static_cast<MeasurementInputKind>(integer(1));
        result.endpoint.owner = static_cast<unsigned>(integer(4));
        result.endpoint.fixed_fd = static_cast<int>(integer(4));
        result.endpoint.identity = digest();
        result.endpoint.lineage = lineage();
        result.feeder_pid = static_cast<std::int64_t>(integer());
        result.feeder_session = digest();
        result.feeder_exit_identity = digest();
        return result;
    }

    void finish() const { need(at_ == bytes_.size()); }
};

Digest offer_identity(const PublicRuntimeChildOffer& offer) {
    Bytes bytes;
    add(bytes, "KPB_MEASUREMENT_CHILD_OFFER_V2\n");
    integer(bytes, static_cast<unsigned char>(offer.role), 1);
    integer(bytes, offer.owner, 4);
    integer(bytes, offer.parent_pid);
    integer(bytes, offer.child_pid);
    add(bytes, offer.permit_identity);
    add_worker(bytes, offer.worker);
    add(bytes, offer.outer_parent_process);
    add(bytes, offer.outer_parent_executable);
    add(bytes, offer.capsule_identity);
    add(bytes, offer.descriptor_manifest_identity);
    add(bytes, offer.opaque_completion_authority_identity);
    add(bytes, offer.opaque_capsule_authority_identity);
    add(bytes, offer.output_authority_identity);
    add(bytes, offer.output_abi_identity);
    integer(bytes, offer.output_exact_size);
    integer(bytes, offer.input_count, 1);
    for (const auto& input : offer.inputs) add_input(bytes, input);
    add(bytes, offer.transport_session);
    return hash(bytes);
}

Bytes encode_offer(const PublicRuntimeChildOffer& offer) {
    Bytes bytes;
    add(bytes, OFFER_MAGIC);
    integer(bytes, static_cast<unsigned char>(offer.role), 1);
    integer(bytes, offer.owner, 4);
    integer(bytes, offer.parent_pid);
    integer(bytes, offer.child_pid);
    add(bytes, offer.permit_identity);
    add_worker(bytes, offer.worker);
    add(bytes, offer.outer_parent_process);
    add(bytes, offer.outer_parent_executable);
    add(bytes, offer.capsule_identity);
    add(bytes, offer.descriptor_manifest_identity);
    add(bytes, offer.opaque_completion_authority_identity);
    add(bytes, offer.opaque_capsule_authority_identity);
    add(bytes, offer.output_authority_identity);
    add(bytes, offer.output_abi_identity);
    integer(bytes, offer.output_exact_size);
    integer(bytes, offer.input_count, 1);
    for (const auto& input : offer.inputs) add_input(bytes, input);
    add(bytes, offer.transport_session);
    add(bytes, offer.offer_identity);
    need(bytes.size() == OFFER_BYTES);
    return bytes;
}

PublicRuntimeChildOffer decode_offer(std::span<const unsigned char> bytes) {
    need(bytes.size() == OFFER_BYTES);
    Reader reader(bytes);
    reader.magic(OFFER_MAGIC);
    PublicRuntimeChildOffer result{};
    result.role = static_cast<RuntimeChildRole>(reader.integer(1));
    result.owner = static_cast<unsigned>(reader.integer(4));
    result.parent_pid = reader.integer();
    result.child_pid = reader.integer();
    result.permit_identity = reader.digest();
    result.worker = reader.worker();
    result.outer_parent_process = reader.digest();
    result.outer_parent_executable = reader.digest();
    result.capsule_identity = reader.digest();
    result.descriptor_manifest_identity = reader.digest();
    result.opaque_completion_authority_identity = reader.digest();
    result.opaque_capsule_authority_identity = reader.digest();
    result.output_authority_identity = reader.digest();
    result.output_abi_identity = reader.digest();
    result.output_exact_size = reader.integer();
    result.input_count = static_cast<unsigned>(reader.integer(1));
    for (auto& input : result.inputs) input = reader.input();
    result.transport_session = reader.digest();
    result.offer_identity = reader.digest();
    reader.finish();
    return result;
}

struct Ack {
    RuntimeChildRole role{};
    unsigned owner{NO_OWNER};
    std::uint64_t parent_pid{};
    std::uint64_t child_pid{};
    Digest permit_identity{};
    Digest transport_session{};
    Digest offer_identity{};
    Digest ack_identity{};
};

Digest ack_identity(const Ack& ack) {
    Bytes bytes;
    add(bytes, "KPB_MEASUREMENT_CHILD_ACK_V2\n");
    integer(bytes, static_cast<unsigned char>(ack.role), 1);
    integer(bytes, ack.owner, 4);
    integer(bytes, ack.parent_pid);
    integer(bytes, ack.child_pid);
    add(bytes, ack.permit_identity);
    add(bytes, ack.transport_session);
    add(bytes, ack.offer_identity);
    return hash(bytes);
}

Bytes encode_ack(const Ack& ack) {
    Bytes bytes;
    add(bytes, ACK_MAGIC);
    integer(bytes, static_cast<unsigned char>(ack.role), 1);
    integer(bytes, ack.owner, 4);
    integer(bytes, ack.parent_pid);
    integer(bytes, ack.child_pid);
    add(bytes, ack.permit_identity);
    add(bytes, ack.transport_session);
    add(bytes, ack.offer_identity);
    add(bytes, ack.ack_identity);
    need(bytes.size() == ACK_BYTES);
    return bytes;
}

Ack decode_ack(std::span<const unsigned char> bytes) {
    need(bytes.size() == ACK_BYTES);
    Reader reader(bytes);
    reader.magic(ACK_MAGIC);
    Ack result{};
    result.role = static_cast<RuntimeChildRole>(reader.integer(1));
    result.owner = static_cast<unsigned>(reader.integer(4));
    result.parent_pid = reader.integer();
    result.child_pid = reader.integer();
    result.permit_identity = reader.digest();
    result.transport_session = reader.digest();
    result.offer_identity = reader.digest();
    result.ack_identity = reader.digest();
    reader.finish();
    return result;
}

struct Completion {
    RuntimeChildRole role{};
    unsigned owner{NO_OWNER};
    Digest permit_identity{};
    Digest transport_session{};
    Digest offer_identity{};
    Digest ack_identity{};
    Digest opaque_completion_authority_identity{};
    Digest opaque_capsule_authority_identity{};
    RuntimeChildResult result{};
    Digest completion_identity{};
};

Digest completion_identity(const Completion& completion) {
    Bytes bytes;
    add(bytes, "KPB_MEASUREMENT_CHILD_COMPLETION_PACKET_V2\n");
    integer(bytes, static_cast<unsigned char>(completion.role), 1);
    integer(bytes, completion.owner, 4);
    add(bytes, completion.permit_identity);
    add(bytes, completion.transport_session);
    add(bytes, completion.offer_identity);
    add(bytes, completion.ack_identity);
    add(bytes, completion.opaque_completion_authority_identity);
    add(bytes, completion.opaque_capsule_authority_identity);
    integer(bytes, static_cast<unsigned char>(
        completion.result.aggregate_outcome), 1);
    integer(bytes, static_cast<unsigned char>(
        completion.result.comparison_outcome), 1);
    add(bytes, completion.result.private_output_content_hash);
    return hash(bytes);
}

Bytes encode_completion(const Completion& completion) {
    Bytes bytes;
    add(bytes, COMPLETION_MAGIC);
    integer(bytes, static_cast<unsigned char>(completion.role), 1);
    integer(bytes, completion.owner, 4);
    add(bytes, completion.permit_identity);
    add(bytes, completion.transport_session);
    add(bytes, completion.offer_identity);
    add(bytes, completion.ack_identity);
    add(bytes, completion.opaque_completion_authority_identity);
    add(bytes, completion.opaque_capsule_authority_identity);
    integer(bytes, static_cast<unsigned char>(
        completion.result.aggregate_outcome), 1);
    integer(bytes, static_cast<unsigned char>(
        completion.result.comparison_outcome), 1);
    add(bytes, completion.result.private_output_content_hash);
    add(bytes, completion.completion_identity);
    need(bytes.size() == COMPLETION_BYTES);
    return bytes;
}

Completion decode_completion(std::span<const unsigned char> bytes) {
    need(bytes.size() == COMPLETION_BYTES);
    Reader reader(bytes);
    reader.magic(COMPLETION_MAGIC);
    Completion result{};
    result.role = static_cast<RuntimeChildRole>(reader.integer(1));
    result.owner = static_cast<unsigned>(reader.integer(4));
    result.permit_identity = reader.digest();
    result.transport_session = reader.digest();
    result.offer_identity = reader.digest();
    result.ack_identity = reader.digest();
    result.opaque_completion_authority_identity = reader.digest();
    result.opaque_capsule_authority_identity = reader.digest();
    result.result.aggregate_outcome =
        static_cast<AggregateOutcome>(reader.integer(1));
    result.result.comparison_outcome =
        static_cast<OwnerComparisonOutcome>(reader.integer(1));
    result.result.private_output_content_hash = reader.digest();
    result.completion_identity = reader.digest();
    reader.finish();
    return result;
}

Digest exit_identity(const PublicRuntimeChildOffer& offer, const Ack& ack,
                     const Completion& completion, int exit_code,
                     int term_signal) {
    Bytes bytes;
    add(bytes, "KPB_MEASUREMENT_CHILD_EXIT_V2\n");
    integer(bytes, offer.parent_pid);
    integer(bytes, offer.child_pid);
    add(bytes, offer.transport_session);
    add(bytes, offer.offer_identity);
    add(bytes, ack.ack_identity);
    add(bytes, completion.completion_identity);
    integer(bytes, static_cast<std::uint64_t>(exit_code));
    integer(bytes, static_cast<std::uint64_t>(term_signal));
    return hash(bytes);
}

class UniqueFd final {
    int value_{-1};
public:
    UniqueFd() = default;
    explicit UniqueFd(int value) : value_(value) {}
    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
    UniqueFd(UniqueFd&& other) noexcept
        : value_(std::exchange(other.value_, -1)) {}
    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this != &other) {
            reset();
            value_ = std::exchange(other.value_, -1);
        }
        return *this;
    }
    ~UniqueFd() { reset(); }
    int get() const { return value_; }
    int release() { return std::exchange(value_, -1); }
    void reset() noexcept {
        if (value_ >= 0) {
            while (::close(value_) != 0 && errno == EINTR) {}
            value_ = -1;
        }
    }
};

std::array<UniqueFd, 2> channel_pair() {
    int raw[2]{-1, -1};
    need(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC,
                      0, raw) == 0);
    std::array<UniqueFd, 2> result{UniqueFd(raw[0]), UniqueFd(raw[1])};
    const int enabled = 1;
    need(::setsockopt(result[0].get(), SOL_SOCKET, SO_PASSCRED,
                      &enabled, sizeof(enabled)) == 0 &&
         ::setsockopt(result[1].get(), SOL_SOCKET, SO_PASSCRED,
                      &enabled, sizeof(enabled)) == 0);
    return result;
}

Digest random_digest() {
    Digest result{};
    std::size_t at = 0;
    while (at < result.size()) {
        const auto count = ::getrandom(
            result.data() + at, result.size() - at, 0);
        if (count < 0 && errno == EINTR) continue;
        need(count > 0);
        at += static_cast<std::size_t>(count);
    }
    need(nonzero(result));
    return result;
}

void send_packet(int fd, std::span<const unsigned char> bytes) {
    ssize_t count;
    do {
        count = ::send(fd, bytes.data(), bytes.size(), MSG_NOSIGNAL);
    } while (count < 0 && errno == EINTR);
    need(count == static_cast<ssize_t>(bytes.size()));
}

struct ReceivedPacket {
    Bytes bytes;
    struct ucred credentials{};
    bool eof{};
};

ReceivedPacket receive_packet(int fd, std::size_t exact_size) {
    struct pollfd ready{
        .fd = fd,
        .events = POLLIN | POLLHUP,
        .revents = 0,
    };
    int polled;
    do { polled = ::poll(&ready, 1, -1); }
    while (polled < 0 && errno == EINTR);
    need(polled == 1 &&
         (ready.revents & (POLLERR | POLLNVAL)) == 0 &&
         (ready.revents & (POLLIN | POLLHUP)) != 0);
    ReceivedPacket result{};
    result.bytes.resize(exact_size + 1);
    struct iovec iov{
        .iov_base = result.bytes.data(),
        .iov_len = result.bytes.size(),
    };
    std::array<unsigned char, CMSG_SPACE(sizeof(struct ucred))> control{};
    struct msghdr message{};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t count;
    do {
        count = ::recvmsg(fd, &message, 0);
    } while (count < 0 && errno == EINTR);
    need(count >= 0 &&
         (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0);
    unsigned credential_count = 0;
    for (auto* item = CMSG_FIRSTHDR(&message); item != nullptr;
         item = CMSG_NXTHDR(&message, item)) {
        if (item->cmsg_level == SOL_SOCKET &&
            item->cmsg_type == SCM_CREDENTIALS &&
            item->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {
            std::memcpy(&result.credentials, CMSG_DATA(item),
                        sizeof(result.credentials));
            ++credential_count;
        }
    }
    if (count == 0) {
        need(credential_count == 0 &&
             (ready.revents & POLLHUP) != 0);
        result.bytes.clear();
        result.eof = true;
        return result;
    }
    need(count == static_cast<ssize_t>(exact_size));
    need(credential_count == 1 && result.credentials.pid > 1);
    result.bytes.resize(exact_size);
    return result;
}

bool exact_eof(int fd) {
    try {
        return receive_packet(fd, 1).eof;
    } catch (const Refused&) {
        return false;
    }
}

void close_range_or_loop(unsigned first, unsigned last,
                         long maximum) noexcept {
    if (first > last) return;
#ifdef SYS_close_range
    if (::syscall(SYS_close_range, first, last, 0) == 0) return;
#endif
    const auto upper = std::min<std::uint64_t>(
        last, maximum > 0 ? static_cast<std::uint64_t>(maximum - 1) : last);
    for (std::uint64_t fd = first; fd <= upper; ++fd)
        while (::close(static_cast<int>(fd)) != 0 && errno == EINTR) {}
}

bool install_fd(int source, int target) noexcept {
    if (source == target)
        return ::fcntl(target, F_SETFD, 0) == 0;
    return ::dup3(source, target, 0) == target;
}

struct ExecCapsule {
    struct Input { int source{-1}; int target{-1}; };
    RuntimeChildRole role{};
    int runtime{-1};
    int source{-1};
    int assets{-1};
    int output{-1};
    std::array<Input, MAX_MEASUREMENT_INPUTS> inputs{};
    unsigned input_count{};
};

[[noreturn]] void exec_child(
        int channel_fd, const ExecCapsule& capsule,
        pid_t expected_parent, long maximum_fd) noexcept {
    if (::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 ||
        ::getppid() != expected_parent ||
        ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        ::_exit(126);
    if (!install_fd(channel_fd, MEASUREMENT_CHILD_FIXED_FD) ||
        !install_fd(capsule.source, MEASUREMENT_SOURCE_CAPSULE_FD) ||
        !install_fd(capsule.assets, MEASUREMENT_ASSET_CAPSULE_FD) ||
        (capsule.output >= 0 &&
         !install_fd(capsule.output, MEASUREMENT_CHILD_OUTPUT_FD)))
        ::_exit(126);
    std::vector<unsigned> retained{
        static_cast<unsigned>(capsule.runtime),
        static_cast<unsigned>(MEASUREMENT_SOURCE_CAPSULE_FD),
        static_cast<unsigned>(MEASUREMENT_ASSET_CAPSULE_FD),
        static_cast<unsigned>(MEASUREMENT_CHILD_FIXED_FD),
    };
    if (capsule.output >= 0)
        retained.push_back(static_cast<unsigned>(MEASUREMENT_CHILD_OUTPUT_FD));
    for (unsigned index = 0; index < capsule.input_count; ++index) {
        const auto& input = capsule.inputs[index];
        if (!install_fd(input.source, input.target)) ::_exit(126);
        retained.push_back(static_cast<unsigned>(input.target));
    }
    for (int fd = 0; fd <= 2; ++fd)
        while (::close(fd) != 0 && errno == EINTR) {}
    std::sort(retained.begin(), retained.end());
    retained.erase(std::unique(retained.begin(), retained.end()),
                   retained.end());
    unsigned next = 3;
    for (const unsigned keep : retained) {
        if (keep > next)
            close_range_or_loop(next, keep - 1, maximum_fd);
        if (keep == std::numeric_limits<unsigned>::max()) break;
        next = keep + 1;
    }
    close_range_or_loop(next, std::numeric_limits<unsigned>::max(),
                        maximum_fd);
    static constexpr char empty_path[]{'\0'};
    char name[] = "kpb-measurement-child";
    char* const arguments[]{name, nullptr};
    char* const environment[]{nullptr};
    if (!detail::install_measurement_preexec_sandbox(
            capsule.runtime, empty_path, capsule.role))
        ::_exit(126);
    (void)::syscall(SYS_execveat, capsule.runtime, empty_path, arguments,
                    environment, AT_EMPTY_PATH);
    ::_exit(126);
}

class ChildGuard final {
    pid_t pid_{-1};
    bool waited_{};
public:
    explicit ChildGuard(pid_t pid) : pid_(pid) {}
    ChildGuard(const ChildGuard&) = delete;
    ChildGuard& operator=(const ChildGuard&) = delete;
    ~ChildGuard() {
        if (pid_ > 1 && !waited_) {
            (void)::kill(pid_, SIGKILL);
            int status = 0;
            while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {}
        }
    }
    int wait() {
        need(pid_ > 1 && !waited_);
        int status = 0;
        pid_t result;
        do {
            result = ::waitpid(pid_, &status, 0);
        } while (result < 0 && errno == EINTR);
        need(result == pid_);
        waited_ = true;
        return status;
    }
};

bool install_landlock(RuntimeChildRole role) noexcept {
#if defined(SYS_landlock_create_ruleset) && \
    defined(SYS_landlock_add_rule) && \
    defined(SYS_landlock_restrict_self)
    const int abi = static_cast<int>(::syscall(
        SYS_landlock_create_ruleset, nullptr, 0,
        LANDLOCK_CREATE_RULESET_VERSION));
    if (abi < 1) return false;
    std::uint64_t handled =
        LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
        LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
        LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
        LANDLOCK_ACCESS_FS_MAKE_SYM;
    if (abi >= 2) handled |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) handled |= LANDLOCK_ACCESS_FS_TRUNCATE;
    struct landlock_ruleset_attr ruleset_attr{
        .handled_access_fs = handled,
        .handled_access_net = 0,
        .scoped = 0,
    };
    const int ruleset = static_cast<int>(::syscall(
        SYS_landlock_create_ruleset, &ruleset_attr,
        sizeof(ruleset_attr), 0));
    if (ruleset < 0) return false;
    (void)role;
    const bool okay =
        ::syscall(SYS_landlock_restrict_self, ruleset, 0) == 0;
    while (::close(ruleset) != 0 && errno == EINTR) {}
    return okay;
#else
    (void)role;
    return false;
#endif
}

sock_filter statement(unsigned short code, std::uint32_t value) {
    return sock_filter{code, 0, 0, value};
}

sock_filter branch(unsigned short code, std::uint32_t value,
                   unsigned char yes, unsigned char no) {
    return sock_filter{code, yes, no, value};
}

bool install_seccomp(RuntimeChildRole role) noexcept {
    constexpr std::uint32_t denied =
        SECCOMP_RET_ERRNO | static_cast<std::uint32_t>(EPERM);
    std::vector<sock_filter> filter;
    filter.reserve(256);
    filter.push_back(statement(
        BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)));
#if defined(__x86_64__)
    constexpr std::uint32_t native_arch = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
    constexpr std::uint32_t native_arch = AUDIT_ARCH_AARCH64;
#else
    return false;
#endif
    filter.push_back(branch(BPF_JMP | BPF_JEQ | BPF_K,
                            native_arch, 1, 0));
    filter.push_back(statement(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    filter.push_back(statement(
        BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)));

    const auto deny_call = [&](int number) {
        filter.push_back(branch(BPF_JMP | BPF_JEQ | BPF_K,
                                static_cast<std::uint32_t>(number), 0, 1));
        filter.push_back(statement(BPF_RET | BPF_K, denied));
    };

#ifdef SYS_open
    deny_call(SYS_open);
#endif
#ifdef SYS_openat2
    deny_call(SYS_openat2);
#endif
#ifdef SYS_creat
    deny_call(SYS_creat);
#endif
#ifdef SYS_socket
    deny_call(SYS_socket);
#endif
#ifdef SYS_socketpair
    deny_call(SYS_socketpair);
#endif
#ifdef SYS_connect
    deny_call(SYS_connect);
#endif
#ifdef SYS_bind
    deny_call(SYS_bind);
#endif
#ifdef SYS_listen
    deny_call(SYS_listen);
#endif
#ifdef SYS_accept
    deny_call(SYS_accept);
#endif
#ifdef SYS_accept4
    deny_call(SYS_accept4);
#endif
#ifdef SYS_sendto
    deny_call(SYS_sendto);
#endif
#ifdef SYS_recvfrom
    deny_call(SYS_recvfrom);
#endif
#ifdef SYS_sendmsg
    deny_call(SYS_sendmsg);
#endif
#ifdef SYS_sendmmsg
    deny_call(SYS_sendmmsg);
#endif
#ifdef SYS_recvmmsg
    deny_call(SYS_recvmmsg);
#endif
#ifdef SYS_sendfile
    deny_call(SYS_sendfile);
#endif
#ifdef SYS_splice
    deny_call(SYS_splice);
#endif
#ifdef SYS_vmsplice
    deny_call(SYS_vmsplice);
#endif
#ifdef SYS_tee
    deny_call(SYS_tee);
#endif
#ifdef SYS_copy_file_range
    deny_call(SYS_copy_file_range);
#endif
#ifdef SYS_pwrite64
    if (const auto* abi = measurement_output_abi(role); abi != nullptr) {
        // fd, count and offset are checked as full 64-bit arguments.  The
        // parent later parses and seals the complete source-owned ABI body.
        filter.push_back(branch(BPF_JMP | BPF_JEQ | BPF_K,
                                SYS_pwrite64, 0, 19));
        for (const auto [argument, expected] :
             std::array<std::pair<unsigned, std::uint64_t>, 3>{
                 std::pair{0U, static_cast<std::uint64_t>(
                                   MEASUREMENT_CHILD_OUTPUT_FD)},
                 std::pair{2U, abi->exact_bytes},
                 std::pair{3U, std::uint64_t{0}},
             }) {
            filter.push_back(statement(
                BPF_LD | BPF_W | BPF_ABS,
                offsetof(struct seccomp_data, args[argument])));
            filter.push_back(branch(BPF_JMP | BPF_JEQ | BPF_K,
                                    static_cast<std::uint32_t>(expected),
                                    1, 0));
            filter.push_back(statement(BPF_RET | BPF_K, denied));
            filter.push_back(statement(
                BPF_LD | BPF_W | BPF_ABS,
                offsetof(struct seccomp_data, args[argument]) + 4));
            filter.push_back(branch(BPF_JMP | BPF_JEQ | BPF_K,
                                    static_cast<std::uint32_t>(expected >> 32),
                                    1, 0));
            filter.push_back(statement(BPF_RET | BPF_K, denied));
        }
        filter.push_back(statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    } else {
        deny_call(SYS_pwrite64);
    }
#endif
#ifdef SYS_pwritev
    deny_call(SYS_pwritev);
#endif
#ifdef SYS_pwritev2
    deny_call(SYS_pwritev2);
#endif
#ifdef SYS_ptrace
    deny_call(SYS_ptrace);
#endif
#ifdef SYS_process_vm_readv
    deny_call(SYS_process_vm_readv);
#endif
#ifdef SYS_process_vm_writev
    deny_call(SYS_process_vm_writev);
#endif
#ifdef SYS_bpf
    deny_call(SYS_bpf);
#endif
#ifdef SYS_mount
    deny_call(SYS_mount);
#endif
#ifdef SYS_umount2
    deny_call(SYS_umount2);
#endif
#ifdef SYS_clone
    deny_call(SYS_clone);
#endif
#ifdef SYS_clone3
    deny_call(SYS_clone3);
#endif
#ifdef SYS_fork
    deny_call(SYS_fork);
#endif
#ifdef SYS_vfork
    deny_call(SYS_vfork);
#endif
#ifdef SYS_execve
    deny_call(SYS_execve);
#endif
#ifdef SYS_execveat
    deny_call(SYS_execveat);
#endif
#ifdef SYS_pidfd_open
    deny_call(SYS_pidfd_open);
#endif
#ifdef SYS_pidfd_getfd
    deny_call(SYS_pidfd_getfd);
#endif
#ifdef SYS_kcmp
    deny_call(SYS_kcmp);
#endif
#ifdef SYS_perf_event_open
    deny_call(SYS_perf_event_open);
#endif
#ifdef SYS_userfaultfd
    deny_call(SYS_userfaultfd);
#endif
#ifdef SYS_io_uring_setup
    deny_call(SYS_io_uring_setup);
#endif
#ifdef SYS_io_uring_enter
    deny_call(SYS_io_uring_enter);
#endif
#ifdef SYS_io_uring_register
    deny_call(SYS_io_uring_register);
#endif
#ifdef SYS_process_madvise
    deny_call(SYS_process_madvise);
#endif
#ifdef SYS_readlink
    deny_call(SYS_readlink);
#endif
#ifdef SYS_readlinkat
    deny_call(SYS_readlinkat);
#endif
#ifdef SYS_stat
    deny_call(SYS_stat);
#endif
#ifdef SYS_lstat
    deny_call(SYS_lstat);
#endif
#ifdef SYS_newfstatat
    deny_call(SYS_newfstatat);
#endif
#ifdef SYS_statx
    deny_call(SYS_statx);
#endif
#ifdef SYS_access
    deny_call(SYS_access);
#endif
#ifdef SYS_faccessat
    deny_call(SYS_faccessat);
#endif
#ifdef SYS_faccessat2
    deny_call(SYS_faccessat2);
#endif
#ifdef SYS_name_to_handle_at
    deny_call(SYS_name_to_handle_at);
#endif
#ifdef SYS_open_by_handle_at
    deny_call(SYS_open_by_handle_at);
#endif
#ifdef SYS_chdir
    deny_call(SYS_chdir);
#endif
#ifdef SYS_fchdir
    deny_call(SYS_fchdir);
#endif
#ifdef SYS_getcwd
    deny_call(SYS_getcwd);
#endif
#ifdef SYS_kill
    deny_call(SYS_kill);
#endif
#ifdef SYS_tkill
    deny_call(SYS_tkill);
#endif
#ifdef SYS_tgkill
    deny_call(SYS_tgkill);
#endif
#ifdef SYS_dup
    deny_call(SYS_dup);
#endif
#ifdef SYS_dup2
    deny_call(SYS_dup2);
#endif
#ifdef SYS_dup3
    deny_call(SYS_dup3);
#endif
#ifdef SYS_fcntl
    deny_call(SYS_fcntl);
#endif
#ifdef SYS_writev
    deny_call(SYS_writev);
#endif

#ifdef SYS_openat
    deny_call(SYS_openat);
#endif

#ifdef SYS_getdents
    deny_call(SYS_getdents);
#endif
#ifdef SYS_getdents64
    deny_call(SYS_getdents64);
#endif

#ifdef SYS_recvmsg
    if (role == RuntimeChildRole::OwnerScore) {
        filter.push_back(branch(BPF_JMP | BPF_JEQ | BPF_K,
                                SYS_recvmsg, 0, 4));
        filter.push_back(statement(
            BPF_LD | BPF_W | BPF_ABS,
            offsetof(struct seccomp_data, args[0])));
        filter.push_back(branch(BPF_JMP | BPF_JEQ | BPF_K,
                                MEASUREMENT_SCORE_OWNER_TRUTH_FD, 1, 0));
        filter.push_back(statement(BPF_RET | BPF_K, denied));
        filter.push_back(statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    } else {
        deny_call(SYS_recvmsg);
    }
#endif

#ifdef SYS_read
    filter.push_back(branch(BPF_JMP | BPF_JEQ | BPF_K,
                            SYS_read, 0, 4));
    filter.push_back(statement(
        BPF_LD | BPF_W | BPF_ABS,
        offsetof(struct seccomp_data, args[0])));
    filter.push_back(branch(BPF_JMP | BPF_JEQ | BPF_K,
                            MEASUREMENT_CHILD_FIXED_FD, 0, 1));
    filter.push_back(statement(BPF_RET | BPF_K, denied));
    filter.push_back(statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
#endif

#ifdef SYS_write
    filter.push_back(branch(BPF_JMP | BPF_JEQ | BPF_K,
                            SYS_write, 0, 7));
    filter.push_back(statement(
        BPF_LD | BPF_W | BPF_ABS,
        offsetof(struct seccomp_data, args[0])));
    filter.push_back(branch(BPF_JMP | BPF_JEQ | BPF_K,
                            MEASUREMENT_CHILD_FIXED_FD, 1, 0));
    filter.push_back(statement(BPF_RET | BPF_K, denied));
    filter.push_back(statement(
        BPF_LD | BPF_W | BPF_ABS,
        offsetof(struct seccomp_data, args[2])));
    filter.push_back(branch(BPF_JMP | BPF_JEQ | BPF_K,
                            COMPLETION_BYTES, 1, 0));
    filter.push_back(statement(BPF_RET | BPF_K, denied));
    filter.push_back(statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
#endif

    filter.push_back(statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    struct sock_fprog program{
        .len = static_cast<unsigned short>(filter.size()),
        .filter = filter.data(),
    };
    return ::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0;
}

bool install_child_sandbox(RuntimeChildRole role) noexcept {
    return install_landlock(role) && install_seccomp(role);
}

void write_packet(int fd, std::span<const unsigned char> bytes) {
    ssize_t count;
    do { count = ::write(fd, bytes.data(), bytes.size()); }
    while (count < 0 && errno == EINTR);
    need(count == static_cast<ssize_t>(bytes.size()));
}

int run_child_impl(MeasurementChildProgram& program,
                   TestChildProtocolFault fault) noexcept {
    try {
        UniqueFd endpoint(MEASUREMENT_CHILD_FIXED_FD);
        const auto offered = receive_packet(endpoint.get(), OFFER_BYTES);
        need(!offered.eof);
        const auto offer = decode_offer(offered.bytes);
        valid_role_owner(offer.role, offer.owner);
        valid_worker(offer.worker);
        valid_offer_capsule(offer);
        validate_inherited_capsule(offer);
        need(nonzero(offer.permit_identity) &&
             nonzero(offer.outer_parent_process) &&
             nonzero(offer.outer_parent_executable) &&
             nonzero(offer.transport_session) &&
             offer.parent_pid > 1 && offer.child_pid > 1 &&
             offer.parent_pid != offer.child_pid &&
             offered.credentials.pid ==
                 static_cast<pid_t>(offer.parent_pid) &&
             static_cast<std::uint64_t>(::getpid()) == offer.child_pid &&
             static_cast<std::uint64_t>(::getppid()) == offer.parent_pid &&
             offer.offer_identity == offer_identity(offer));

        Ack ack{
            .role = offer.role,
            .owner = offer.owner,
            .parent_pid = offer.parent_pid,
            .child_pid = offer.child_pid,
            .permit_identity = offer.permit_identity,
            .transport_session = offer.transport_session,
            .offer_identity = offer.offer_identity,
        };
        if (fault == TestChildProtocolFault::WrongAckOffer)
            ack.offer_identity = random_digest();
        if (fault == TestChildProtocolFault::WrongAckPid)
            ++ack.child_pid;
        ack.ack_identity = ack_identity(ack);
        const auto encoded_ack = encode_ack(ack);
        if (fault == TestChildProtocolFault::CredentialRelay) {
            const pid_t relay = ::fork();
            need(relay >= 0);
            if (relay == 0) {
                try {
                    send_packet(endpoint.get(), encoded_ack);
                    ::_exit(0);
                } catch (...) {
                    ::_exit(125);
                }
            }
            int status = 0;
            while (::waitpid(relay, &status, 0) < 0 && errno == EINTR) {}
            return 113;
        }
        if (fault == TestChildProtocolFault::ZeroAckBeforeClose) {
            send_packet(endpoint.get(), {});
            return 114;
        }
        send_packet(endpoint.get(), encoded_ack);
        if (fault ==
                TestChildProtocolFault::ZeroCompletionBeforeClose) {
            send_packet(endpoint.get(), {});
            return 115;
        }
        need(install_child_sandbox(offer.role));
        if (fault == TestChildProtocolFault::NoCompletion) return 0;

        Completion completion{
            .role = offer.role,
            .owner = offer.owner,
            .permit_identity = offer.permit_identity,
            .transport_session = offer.transport_session,
            .offer_identity = offer.offer_identity,
            .ack_identity = ack.ack_identity,
            .opaque_completion_authority_identity =
                offer.opaque_completion_authority_identity,
            .opaque_capsule_authority_identity =
                offer.opaque_capsule_authority_identity,
            .result = program.execute(offer),
        };
        valid_result(completion.role, completion.owner, completion.result);
        if (fault == TestChildProtocolFault::WrongCompletionRole) {
            completion.role = completion.role == RuntimeChildRole::Observer
                ? RuntimeChildRole::Aggregate
                : RuntimeChildRole::Observer;
            if (completion.role == RuntimeChildRole::Aggregate)
                completion.result.aggregate_outcome =
                    AggregateOutcome::CandidatePass;
            else
                completion.result.aggregate_outcome =
                    static_cast<AggregateOutcome>(0);
        }
        if (fault == TestChildProtocolFault::WrongCompletionPermit)
            completion.permit_identity = random_digest();
        if (fault == TestChildProtocolFault::WrongCompletionOwner)
            completion.owner = completion.owner < 3
                ? (completion.owner + 1) % 3 : 0;
        if (fault == TestChildProtocolFault::WrongCompletionOpaqueAuthority)
            completion.opaque_completion_authority_identity =
                random_digest();
        if (fault == TestChildProtocolFault::WrongCapsuleOpaqueAuthority)
            completion.opaque_capsule_authority_identity = random_digest();
        completion.completion_identity = completion_identity(completion);
        const auto encoded = encode_completion(completion);
        write_packet(endpoint.get(), encoded);
        if (fault == TestChildProtocolFault::DuplicateCompletion)
            write_packet(endpoint.get(), encoded);
        endpoint.reset();
        return 0;
    } catch (...) {
        return 112;
    }
}

} // namespace

int run_measurement_child(MeasurementChildProgram& program) noexcept {
    return run_child_impl(program, TestChildProtocolFault::None);
}

#ifdef KPB_MEASUREMENT_CHILD_SUPERVISOR_TEST_SETUP
int test_only_run_measurement_child(
        MeasurementChildProgram& program,
        TestChildProtocolFault fault) noexcept {
    return run_child_impl(program, fault);
}

bool test_only_zero_offer_record_refused(int endpoint_fd) noexcept {
    try {
        (void)receive_packet(endpoint_fd, OFFER_BYTES);
        return false;
    } catch (const Refused&) {
        return true;
    }
}
#endif

ChildCompletionEvidenceAuthority MeasurementChildSupervisor::supervise(
        const PublicRuntimeChildOffer& selected,
        MeasurementWorkerCapsuleAuthority&& supplied_capsule,
        const RunBinding* output_binding,
        std::unique_ptr<SealedChildOutputAuthority>* sealed_output) {
    MeasurementWorkerCapsuleAuthority capsule(
        std::move(supplied_capsule));
    valid_role_owner(selected.role, selected.owner);
    valid_worker(selected.worker);
    const auto* output_abi = measurement_output_abi(selected.role);
    need((output_abi != nullptr && output_binding != nullptr &&
          sealed_output != nullptr && *sealed_output == nullptr) ||
         (output_abi == nullptr && output_binding == nullptr &&
          sealed_output == nullptr));
    need(nonzero(selected.permit_identity) &&
         nonzero(selected.outer_parent_process) &&
         nonzero(selected.outer_parent_executable) &&
         capsule.live_.exchange(false) &&
         capsule.receipt_.role == selected.role &&
         capsule.receipt_.owner == selected.owner &&
         capsule.receipt_.worker == selected.worker &&
         capsule.receipt_.capsule_identity ==
             recompute_worker_capsule_identity(capsule.receipt_) &&
         capsule.runtime_fd_ >= 0 && capsule.source_fd_ >= 0 &&
         capsule.assets_fd_ >= 0);
    const auto session = random_digest();
    std::unique_ptr<PendingChildOutputAuthority> pending_output;
    UniqueFd output_child;
    PrivateChildOutputOffer private_output_offer{};
    if (output_abi != nullptr) {
        private_output_offer = PrivateChildOutputOffer{
            .binding = *output_binding,
            .role = selected.role,
            .owner = selected.owner,
            .permit_identity = selected.permit_identity,
            .worker = selected.worker,
            .transport_session = session,
            .output_authority_identity = random_digest(),
            .output_abi_identity = output_abi->identity,
            .exact_size = output_abi->exact_bytes,
        };
        pending_output = std::make_unique<PendingChildOutputAuthority>(
            MeasurementChildOutputPlane::begin(private_output_offer));
        output_child = UniqueFd(pending_output->take_child_fd());
    }
    ExecCapsule exec{
        .role = selected.role,
        .runtime = capsule.runtime_fd_,
        .source = capsule.source_fd_,
        .assets = capsule.assets_fd_,
        .output = output_child.get(),
        .input_count = capsule.receipt_.input_count,
    };
    for (unsigned index = 0; index < exec.input_count; ++index)
        exec.inputs[index] = {
            .source = capsule.inputs_[index].fd,
            .target = capsule.inputs_[index].receipt.fixed_fd,
        };
    auto channels = channel_pair();
    const pid_t parent_pid = ::getpid();
    need(parent_pid > 1);
    const long maximum_fd = ::sysconf(_SC_OPEN_MAX);
    need(maximum_fd > exec.runtime);
    const pid_t child_pid = ::fork();
    need(child_pid >= 0);
    if (child_pid == 0) {
        channels[0].reset();
        exec_child(channels[1].release(), exec, parent_pid, maximum_fd);
    }
    ChildGuard child(child_pid);
    channels[1].reset();
    output_child.reset();

    auto offer = selected;
    offer.capsule_identity = capsule.receipt_.capsule_identity;
    offer.descriptor_manifest_identity =
        capsule.receipt_.descriptor_manifest_identity;
    offer.opaque_completion_authority_identity = random_digest();
    if (offer.role == RuntimeChildRole::OwnerScore)
        offer.opaque_capsule_authority_identity = random_digest();
    if (output_abi != nullptr) {
        offer.output_authority_identity =
            private_output_offer.output_authority_identity;
        offer.output_abi_identity = private_output_offer.output_abi_identity;
        offer.output_exact_size = private_output_offer.exact_size;
    }
    offer.input_count = capsule.receipt_.input_count;
    for (unsigned index = 0; index < offer.input_count; ++index) {
        offer.inputs[index] = RuntimeInputOffer{
            .endpoint = capsule.inputs_[index].receipt,
            .feeder_pid = capsule.inputs_[index].feeder_pid,
            .feeder_session = capsule.inputs_[index].feeder_session,
            .feeder_exit_identity =
                capsule.inputs_[index].feeder_exit_identity,
        };
    }
    capsule.close_fds();
    offer.transport_session = session;
    offer.parent_pid = static_cast<std::uint64_t>(parent_pid);
    offer.child_pid = static_cast<std::uint64_t>(child_pid);
    valid_offer_capsule(offer);
    offer.offer_identity = offer_identity(offer);
    const auto encoded_offer = encode_offer(offer);
    send_packet(channels[0].get(), encoded_offer);

    const auto acknowledged = receive_packet(channels[0].get(), ACK_BYTES);
    need(!acknowledged.eof &&
         acknowledged.credentials.pid == child_pid);
    const auto ack = decode_ack(acknowledged.bytes);
    need(ack.role == offer.role && ack.owner == offer.owner &&
         ack.parent_pid == offer.parent_pid &&
         ack.child_pid == offer.child_pid &&
         ack.permit_identity == offer.permit_identity &&
         ack.transport_session == offer.transport_session &&
         ack.offer_identity == offer.offer_identity &&
         ack.ack_identity == ack_identity(ack));

    const auto completed = receive_packet(
        channels[0].get(), COMPLETION_BYTES);
    need(!completed.eof && completed.credentials.pid == child_pid);
    const auto completion = decode_completion(completed.bytes);
    valid_result(completion.role, completion.owner, completion.result);
    need(completion.role == offer.role &&
         completion.owner == offer.owner &&
         completion.permit_identity == offer.permit_identity &&
         completion.transport_session == offer.transport_session &&
         completion.offer_identity == offer.offer_identity &&
         completion.ack_identity == ack.ack_identity &&
         completion.opaque_completion_authority_identity ==
             offer.opaque_completion_authority_identity &&
         completion.opaque_capsule_authority_identity ==
             offer.opaque_capsule_authority_identity &&
         completion.completion_identity ==
             completion_identity(completion) &&
         exact_eof(channels[0].get()));
    channels[0].reset();

    const int wait_status = child.wait();
    const int exit_code = WIFEXITED(wait_status)
        ? WEXITSTATUS(wait_status) : -1;
    const int term_signal = WIFSIGNALED(wait_status)
        ? WTERMSIG(wait_status) : 0;
    need(WIFEXITED(wait_status) && exit_code == 0 && term_signal == 0);
    PublicRuntimeChildCompletion receipt{
        .role = offer.role,
        .owner = offer.owner,
        .permit_identity = offer.permit_identity,
        .worker = offer.worker,
        .outer_parent_process = offer.outer_parent_process,
        .outer_parent_executable = offer.outer_parent_executable,
        .transport_session = offer.transport_session,
        .offer_identity = offer.offer_identity,
        .child_exit_identity = exit_identity(
            offer, ack, completion, exit_code, term_signal),
        .opaque_completion_authority_identity =
            offer.opaque_completion_authority_identity,
        .opaque_capsule_authority_identity =
            offer.opaque_capsule_authority_identity,
        .authenticated_pid = static_cast<std::uint64_t>(child_pid),
        .waited_pid = static_cast<std::uint64_t>(child_pid),
        .exit_code = exit_code,
        .term_signal = term_signal,
        .credentials_verified = true,
        .offer_acknowledged = true,
        .eof_observed = true,
        .aggregate_outcome = completion.result.aggregate_outcome,
        .comparison_outcome = completion.result.comparison_outcome,
    };
    receipt.process_identity = recompute_process_identity(receipt);
    if (output_abi != nullptr) {
        AuthenticatedChildOutputCompletionAuthority authenticated_output(
            PrivateChildOutputCompletion{
                .offer = private_output_offer,
                .content_hash = completion.result.private_output_content_hash,
                .process_identity = receipt.process_identity,
                .child_exit_identity = receipt.child_exit_identity,
                .authenticated_pid = receipt.authenticated_pid,
                .waited_pid = receipt.waited_pid,
                .exit_code = receipt.exit_code,
                .term_signal = receipt.term_signal,
                .credentials_verified = receipt.credentials_verified,
                .eof_observed = receipt.eof_observed,
            });
        *sealed_output = std::make_unique<SealedChildOutputAuthority>(
            MeasurementChildOutputPlane::finish(
                std::move(*pending_output),
                std::move(authenticated_output)));
    }
    return ChildCompletionEvidenceAuthority(std::move(receipt));
}

ObservationRuntimeCompletion MeasurementChildSupervisor::run_observer(
        ObserverExecutionPermitAuthority&& supplied,
        MeasurementWorkerCapsuleAuthority&& supplied_capsule,
        empirical_result::NativeEmpiricalResultAuthority&&
            supplied_empirical) {
    ObserverExecutionPermitAuthority permit(std::move(supplied));
    MeasurementWorkerCapsuleAuthority capsule(std::move(supplied_capsule));
    empirical_result::NativeEmpiricalResultAuthority empirical(
        std::move(supplied_empirical));
    const auto& selected = permit.public_receipt();
    require_capsule_binding(capsule.public_receipt(), selected.binding);
    std::unique_ptr<SealedChildOutputAuthority> output;
    auto evidence = supervise(PublicRuntimeChildOffer{
        .role = RuntimeChildRole::Observer,
        .owner = NO_OWNER,
        .permit_identity = selected.permit_identity,
        .worker = selected.binding.observer_worker,
        .outer_parent_process = selected.binding.outer_parent_process,
        .outer_parent_executable = selected.binding.outer_parent_executable,
    }, std::move(capsule), &selected.binding, &output);
    need(output != nullptr);
    return RuntimeCompletionBridge::observation(
        std::move(permit), std::move(evidence), std::move(*output),
        std::move(empirical));
}

OwnerScoreRuntimeCompletion MeasurementChildSupervisor::run_owner_score(
        OwnerScoreExecutionPermitAuthority&& supplied,
        MeasurementWorkerCapsuleAuthority&& capsule) {
    OwnerScoreExecutionPermitAuthority permit(std::move(supplied));
    const auto& selected = permit.public_receipt();
    require_capsule_binding(capsule.public_receipt(), selected.binding);
    need(capsule.public_receipt().input_count == 2 &&
         capsule.public_receipt().inputs[0].lineage.barrier ==
             selected.barrier &&
         capsule.public_receipt().inputs[1].lineage.barrier ==
             selected.barrier);
    std::unique_ptr<SealedChildOutputAuthority> output;
    auto evidence = supervise(PublicRuntimeChildOffer{
        .role = RuntimeChildRole::OwnerScore,
        .owner = selected.owner,
        .permit_identity = selected.permit_identity,
        .worker = selected.binding.score_worker,
        .outer_parent_process = selected.binding.outer_parent_process,
        .outer_parent_executable = selected.binding.outer_parent_executable,
    }, std::move(capsule), &selected.binding, &output);
    need(output != nullptr);
    return RuntimeCompletionBridge::owner_score(
        std::move(permit), std::move(evidence), std::move(*output));
}

AggregateRuntimeCompletion MeasurementChildSupervisor::run_aggregate(
        AggregatePermitAuthority&& supplied,
        MeasurementWorkerCapsuleAuthority&& capsule) {
    AggregatePermitAuthority permit(std::move(supplied));
    const auto& selected = permit.public_receipt();
    require_capsule_binding(capsule.public_receipt(), selected.binding);
    need(capsule.public_receipt().input_count == 3);
    for (unsigned index = 0; index < 3; ++index)
        need(capsule.public_receipt().inputs[index].lineage.barrier ==
             selected.barrier);
    auto evidence = supervise(PublicRuntimeChildOffer{
        .role = RuntimeChildRole::Aggregate,
        .owner = NO_OWNER,
        .permit_identity = selected.permit_identity,
        .worker = selected.binding.aggregate_worker,
        .outer_parent_process = selected.binding.outer_parent_process,
        .outer_parent_executable = selected.binding.outer_parent_executable,
    }, std::move(capsule), nullptr, nullptr);
    return RuntimeCompletionBridge::aggregate(
        std::move(permit), std::move(evidence));
}

OwnerComparisonRuntimeCompletion
MeasurementChildSupervisor::run_owner_comparison(
        OwnerComparisonPermitAuthority&& supplied,
        MeasurementWorkerCapsuleAuthority&& capsule) {
    OwnerComparisonPermitAuthority permit(std::move(supplied));
    const auto& selected = permit.public_receipt();
    auto evidence = supervise(PublicRuntimeChildOffer{
        .role = RuntimeChildRole::OwnerComparison,
        .owner = NO_OWNER,
        .permit_identity = selected.permit_identity,
        .worker = selected.selection.comparison_worker,
        .outer_parent_process = selected.selection.outer_parent_process,
        .outer_parent_executable =
            selected.selection.outer_parent_executable,
    }, std::move(capsule), nullptr, nullptr);
    return RuntimeCompletionBridge::owner_comparison(
        std::move(permit), std::move(evidence));
}

} // namespace kpb::measurement::runtime_bridge
