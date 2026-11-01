#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "native_terminal_completion.hpp"
#include "native_terminal_mapping_source.hpp"
#include "privacy_measurement_run_binding_wire.hpp"
#include "../mpc-prover/financial/baseline_public_effects_collector.hpp"
#include "../mpc-prover/financial/registered_projection_route.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <poll.h>
#include <signal.h>
#include <span>
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

namespace kpb::native_terminal {
namespace {

using Bytes = std::vector<unsigned char>;
using measurement::CaptureKind;
using measurement::Classification;
using measurement::Refused;
using RouteClassification =
    kpi::mpc::financial::registered_driver::CaptureClassification;
using ProjectionBody = std::array<std::byte, 10685>;

constexpr std::size_t MAX_PACKET = 1U << 16;

enum class Message : unsigned char {
    GenesisOffer = 1,
    PaymentOffer = 2,
    Ack = 3,
    GenesisCompletion = 4,
    PaymentCompletion = 5,
};

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add(Bytes& out, const Digest& value) { add(out, std::span(value)); }
void text(Bytes& out, const char* value) {
    while (*value) out.push_back(static_cast<unsigned char>(*value++));
}
void little(Bytes& out, std::uint64_t value, unsigned width = 8) {
    need(width > 0 && width <= 8);
    for (unsigned index = 0; index < width; ++index)
        out.push_back(static_cast<unsigned char>(value >> (8 * index)));
}
void big(Bytes& out, std::uint64_t value, unsigned width = 8) {
    need(width > 0 && width <= 8);
    for (unsigned index = 0; index < width; ++index)
        out.push_back(static_cast<unsigned char>(
            value >> (8 * (width - index - 1))));
}

Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    need(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}
Digest hash_domain(const char* domain, std::span<const unsigned char> value) {
    Bytes bytes;
    text(bytes, domain);
    add(bytes, value);
    return hash(bytes);
}
Digest string_identity(const char* domain, const std::string& value) {
    return hash_domain(domain, {reinterpret_cast<const unsigned char*>(
        value.data()), value.size()});
}

std::string hex(const Digest& value) {
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (const auto byte : value) {
        result.push_back(alphabet[byte >> 4]);
        result.push_back(alphabet[byte & 0x0f]);
    }
    return result;
}
unsigned nibble(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    refuse();
}
Digest unhex(std::string_view value) {
    need(value.size() == 64);
    Digest result{};
    for (unsigned index = 0; index < result.size(); ++index)
        result[index] = static_cast<unsigned char>(
            (nibble(value[index * 2]) << 4) |
            nibble(value[index * 2 + 1]));
    return result;
}
bool uuid(std::string_view value) {
    if (value.size() != 36 || value[8] != '-' || value[13] != '-' ||
        value[18] != '-' || value[23] != '-' || value[14] != '4' ||
        std::string_view("89ab").find(value[19]) == std::string_view::npos)
        return false;
    for (unsigned index = 0; index < value.size(); ++index) {
        if (index == 8 || index == 13 || index == 18 || index == 23)
            continue;
        if (!((value[index] >= '0' && value[index] <= '9') ||
              (value[index] >= 'a' && value[index] <= 'f')))
            return false;
    }
    return true;
}

void worker_bytes(Bytes& out, const measurement::WorkerBinding& value) {
    for (const auto* field : {
             &value.source_identity, &value.build_identity,
             &value.runtime_identity, &value.assets_identity,
             &value.pinned_executable_identity, &value.launcher_identity})
        add(out, *field);
}
void run_binding_bytes(Bytes& out, const measurement::RunBinding& value) {
    const auto canonical =
        measurement::wire::canonical_run_binding_bytes(value);
    out.insert(out.end(), canonical.begin(), canonical.end());
}
void selection_bytes(Bytes& out, const NativeTerminalSelection& value) {
    out.push_back(static_cast<unsigned char>(value.network));
    out.push_back(static_cast<unsigned char>(value.kind));
    little(out, value.ordinal, 4);
    for (const auto* field : {
             &value.trial, &value.funding_identity,
             &value.component_profile, &value.immutable_tail,
             &value.accepted_input_head, &value.successor_head,
             &value.projection, &value.core, &value.proof,
             &value.case_identity, &value.durable_final_checkpoint,
             &value.signed_case_completion,
             &value.native_full_completion, &value.r0_completion,
             &value.value_conservation_completion})
        add(out, *field);
    little(out, value.input_value_sompi);
    little(out, value.successor_value_sompi);
    little(out, value.fee_sompi);
    worker_bytes(out, value.worker);
    add(out, value.outer_parent_process);
    add(out, value.outer_parent_executable);
}
void string_bytes(Bytes& out, const std::string& value) {
    need(value.size() <= 4096);
    little(out, value.size(), 4);
    out.insert(out.end(), value.begin(), value.end());
}
void capture_binding_bytes(Bytes& out, const capture::Binding& value) {
    string_bytes(out, value.attempt_id);
    string_bytes(out, value.cohort_sha256);
    string_bytes(out, value.financial_run_id);
    string_bytes(out, value.capture_identity);
    string_bytes(out, value.projection_sha256);
    little(out, value.construction_classification, 4);
    string_bytes(out, value.construction_attempt_sha256);
    string_bytes(out, value.capture_plan_sha256);
}

class Decoder final {
    std::span<const unsigned char> bytes_;
    std::size_t offset_{};
public:
    explicit Decoder(std::span<const unsigned char> bytes) : bytes_(bytes) {}
    unsigned char byte() {
        need(offset_ < bytes_.size());
        return bytes_[offset_++];
    }
    std::uint64_t little(unsigned width = 8) {
        need(width > 0 && width <= 8 && bytes_.size() - offset_ >= width);
        std::uint64_t result = 0;
        for (unsigned index = 0; index < width; ++index)
            result |= static_cast<std::uint64_t>(bytes_[offset_++]) <<
                (8 * index);
        return result;
    }
    Digest digest() {
        need(bytes_.size() - offset_ >= 32);
        Digest result{};
        std::copy_n(bytes_.begin() + static_cast<std::ptrdiff_t>(offset_),
                    result.size(), result.begin());
        offset_ += result.size();
        return result;
    }
    std::string string() {
        const auto size = little(4);
        need(size <= 4096 && bytes_.size() - offset_ >= size);
        std::string result(
            reinterpret_cast<const char*>(bytes_.data() + offset_), size);
        offset_ += size;
        return result;
    }
    void fixed(std::span<unsigned char> out) {
        need(bytes_.size() - offset_ >= out.size());
        std::copy_n(bytes_.begin() + static_cast<std::ptrdiff_t>(offset_),
                    out.size(), out.begin());
        offset_ += out.size();
    }
    void finished() const { need(offset_ == bytes_.size()); }
};

measurement::WorkerBinding decode_worker(Decoder& in) {
    return {
        .source_identity = in.digest(), .build_identity = in.digest(),
        .runtime_identity = in.digest(), .assets_identity = in.digest(),
        .pinned_executable_identity = in.digest(),
        .launcher_identity = in.digest(),
    };
}
NativeTerminalSelection decode_selection(Decoder& in) {
    NativeTerminalSelection result{
        .network = static_cast<NetworkScope>(in.byte()),
        .kind = static_cast<NativeCandidateKind>(in.byte()),
        .ordinal = static_cast<unsigned>(in.little(4)),
    };
    result.trial = in.digest();
    result.funding_identity = in.digest();
    result.component_profile = in.digest();
    result.immutable_tail = in.digest();
    result.accepted_input_head = in.digest();
    result.successor_head = in.digest();
    result.projection = in.digest();
    result.core = in.digest();
    result.proof = in.digest();
    result.case_identity = in.digest();
    result.durable_final_checkpoint = in.digest();
    result.signed_case_completion = in.digest();
    result.native_full_completion = in.digest();
    result.r0_completion = in.digest();
    result.value_conservation_completion = in.digest();
    result.input_value_sompi = in.little();
    result.successor_value_sompi = in.little();
    result.fee_sompi = in.little();
    result.worker = decode_worker(in);
    result.outer_parent_process = in.digest();
    result.outer_parent_executable = in.digest();
    return result;
}
capture::Binding decode_capture_binding(Decoder& in) {
    return {in.string(), in.string(), in.string(), in.string(), in.string(),
            static_cast<unsigned>(in.little(4)), in.string(), in.string()};
}

void valid_worker(const measurement::WorkerBinding& value) {
    for (const auto* field : {
             &value.source_identity, &value.build_identity,
             &value.runtime_identity, &value.assets_identity,
             &value.pinned_executable_identity, &value.launcher_identity})
        need(nonzero(*field));
}
void valid_selection(const NativeTerminalSelection& value) {
    need(value.network == NetworkScope::KaspaTestnet10 &&
         value.ordinal < 3 &&
         value.kind == static_cast<NativeCandidateKind>(value.ordinal + 1));
    for (const auto* field : {
             &value.trial, &value.funding_identity,
             &value.component_profile, &value.immutable_tail,
             &value.accepted_input_head, &value.successor_head,
             &value.projection, &value.core, &value.proof,
             &value.case_identity, &value.durable_final_checkpoint,
             &value.signed_case_completion,
             &value.native_full_completion, &value.r0_completion,
             &value.value_conservation_completion,
             &value.outer_parent_process, &value.outer_parent_executable})
        need(nonzero(*field));
    valid_worker(value.worker);
    need(value.accepted_input_head != value.successor_head &&
         value.input_value_sompi > 0 && value.successor_value_sompi > 0 &&
         value.fee_sompi > 0 && value.fee_sompi < value.input_value_sompi &&
         value.input_value_sompi - value.fee_sompi ==
             value.successor_value_sompi);
    const std::array<Digest, 8> distinct{
        value.core, value.proof, value.case_identity,
        value.durable_final_checkpoint, value.signed_case_completion,
        value.native_full_completion, value.r0_completion,
        value.value_conservation_completion};
    for (unsigned left = 0; left < distinct.size(); ++left)
        for (unsigned right = left + 1; right < distinct.size(); ++right)
            need(distinct[left] != distinct[right]);
}
void valid_capture_binding(const capture::Binding& value) {
    need(uuid(value.attempt_id) && uuid(value.capture_identity));
    (void)unhex(value.cohort_sha256);
    (void)unhex(value.financial_run_id);
    (void)unhex(value.projection_sha256);
    need(value.construction_classification == 1 ||
         value.construction_classification == 2);
    (void)unhex(value.construction_attempt_sha256);
    (void)unhex(value.capture_plan_sha256);
}

bool same_capture_binding(
        const capture::Binding& left,
        const capture::Binding& right) noexcept {
    return left.attempt_id == right.attempt_id &&
        left.cohort_sha256 == right.cohort_sha256 &&
        left.financial_run_id == right.financial_run_id &&
        left.capture_identity == right.capture_identity &&
        left.projection_sha256 == right.projection_sha256 &&
        left.construction_classification ==
            right.construction_classification &&
        left.construction_attempt_sha256 ==
            right.construction_attempt_sha256 &&
        left.capture_plan_sha256 == right.capture_plan_sha256;
}

measurement::WorkerBinding worker(const measurement::ManifestEntry& entry) {
    return {.source_identity = entry.source_identity,
            .build_identity = entry.build_identity,
            .runtime_identity = entry.runtime_identity,
            .assets_identity = entry.assets_identity,
            .pinned_executable_identity = entry.pinned_executable_identity,
            .launcher_identity = entry.launcher_identity};
}

Digest random_digest() {
    Digest result{};
    std::size_t offset = 0;
    while (offset < result.size()) {
        const auto count = ::getrandom(result.data() + offset,
                                       result.size() - offset, 0);
        if (count < 0 && errno == EINTR) continue;
        need(count > 0);
        offset += static_cast<std::size_t>(count);
    }
    need(nonzero(result));
    return result;
}

class Fd final {
    int value_{-1};
public:
    Fd() = default;
    explicit Fd(int value) : value_(value) {}
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : value_(other.release()) {}
    Fd& operator=(Fd&&) = delete;
    ~Fd() { reset(); }
    int get() const { return value_; }
    int release() { const int result = value_; value_ = -1; return result; }
    void reset(int replacement = -1) noexcept {
        if (value_ >= 0) {
            int result;
            do { result = ::close(value_); }
            while (result != 0 && errno == EINTR);
        }
        value_ = replacement;
    }
};

Digest hash_fd(int fd) {
    struct stat stat{};
    need(fd >= 0 && ::fstat(fd, &stat) == 0 && S_ISREG(stat.st_mode) &&
         stat.st_size > 0);
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    need(context != nullptr);
    struct Guard { EVP_MD_CTX* value; ~Guard() { EVP_MD_CTX_free(value); } }
        guard{context};
    need(EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1);
    std::array<unsigned char, 1U << 16> buffer{};
    off_t offset = 0;
    while (offset < stat.st_size) {
        const auto wanted = static_cast<std::size_t>(
            std::min<off_t>(buffer.size(), stat.st_size - offset));
        ssize_t count;
        do { count = ::pread(fd, buffer.data(), wanted, offset); }
        while (count < 0 && errno == EINTR);
        need(count > 0 && EVP_DigestUpdate(
            context, buffer.data(), static_cast<std::size_t>(count)) == 1);
        offset += count;
    }
    Digest result{};
    unsigned length = 0;
    need(EVP_DigestFinal_ex(context, result.data(), &length) == 1 &&
         length == result.size());
    return result;
}
Digest current_executable_identity() {
    Fd executable(::open("/proc/self/exe", O_RDONLY | O_CLOEXEC));
    need(executable.get() >= 0);
    return hash_fd(executable.get());
}

void close_except(std::span<const int> retained) noexcept {
    DIR* directory = ::opendir("/proc/self/fd");
    if (directory == nullptr) _exit(125);
    const int directory_fd = ::dirfd(directory);
    while (auto* entry = ::readdir(directory)) {
        char* end = nullptr;
        const long candidate = std::strtol(entry->d_name, &end, 10);
        if (end == entry->d_name || *end != '\0' || candidate < 0 ||
            candidate == directory_fd)
            continue;
        const int fd = static_cast<int>(candidate);
        if (std::find(retained.begin(), retained.end(), fd) ==
            retained.end())
            (void)::close(fd);
    }
    ::closedir(directory);
}

void pass_credentials(int fd) {
    int enabled = 1;
    need(::setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &enabled,
                      sizeof(enabled)) == 0);
}
struct ReceivedPacket { Bytes bytes; pid_t sender{}; };
void send_packet(int fd, std::span<const unsigned char> packet) {
    need(!packet.empty() && packet.size() <= MAX_PACKET);
    struct iovec io{const_cast<unsigned char*>(packet.data()), packet.size()};
    struct msghdr message{};
    message.msg_iov = &io;
    message.msg_iovlen = 1;
    ssize_t sent;
    do { sent = ::sendmsg(fd, &message, MSG_NOSIGNAL); }
    while (sent < 0 && errno == EINTR);
    need(sent == static_cast<ssize_t>(packet.size()));
}
ReceivedPacket receive_packet(int fd, pid_t expected_sender) {
    ReceivedPacket result;
    result.bytes.resize(MAX_PACKET);
    std::array<unsigned char, CMSG_SPACE(sizeof(struct ucred))> control{};
    struct iovec io{result.bytes.data(), result.bytes.size()};
    struct msghdr message{};
    message.msg_iov = &io;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t count;
    do { count = ::recvmsg(fd, &message, MSG_CMSG_CLOEXEC); }
    while (count < 0 && errno == EINTR);
    need(count > 0 && (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0);
    bool credential = false;
    for (auto* item = CMSG_FIRSTHDR(&message); item != nullptr;
         item = CMSG_NXTHDR(&message, item)) {
        if (item->cmsg_level != SOL_SOCKET ||
            item->cmsg_type != SCM_CREDENTIALS)
            continue;
        need(!credential && item->cmsg_len >= CMSG_LEN(sizeof(struct ucred)));
        struct ucred supplied{};
        std::memcpy(&supplied, CMSG_DATA(item), sizeof(supplied));
        result.sender = supplied.pid;
        credential = true;
    }
    need(credential && result.sender == expected_sender);
    result.bytes.resize(static_cast<std::size_t>(count));
    return result;
}
void expect_control_eof(int fd) {
    struct pollfd watched{
        .fd = fd, .events = POLLIN | POLLHUP | POLLERR, .revents = 0};
    int ready;
    do { ready = ::poll(&watched, 1, -1); }
    while (ready < 0 && errno == EINTR);
    need(ready == 1 && (watched.revents & POLLNVAL) == 0);

    unsigned char byte = 0;
    std::array<unsigned char, CMSG_SPACE(sizeof(struct ucred))> control{};
    struct iovec io{&byte, 1};
    struct msghdr message{};
    message.msg_iov = &io;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t count;
    do { count = ::recvmsg(fd, &message, MSG_CMSG_CLOEXEC); }
    while (count < 0 && errno == EINTR);
    need(count == 0 &&
         (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0);
    // A zero-length SOCK_SEQPACKET record carries sender credentials. It is
    // data, not kernel EOF, even though recvmsg also returns zero.
    need(CMSG_FIRSTHDR(&message) == nullptr);
    watched.revents = 0;
    do { ready = ::poll(&watched, 1, 0); }
    while (ready < 0 && errno == EINTR);
    need(ready == 1 && (watched.revents & POLLHUP) != 0 &&
         (watched.revents & (POLLERR | POLLNVAL)) == 0);
}

} // namespace

bool exact_capture_lineage(
        const measurement::RunBinding& binding, unsigned round,
        const capture::Binding& selected) noexcept {
    try {
        if (round < 1 || round > 2 || !uuid(selected.attempt_id) ||
            !uuid(selected.capture_identity))
            return false;
        const auto index = round - 1;
        return binding.round_attempts[index] == string_identity(
                   "KPB_CAPTURE_ATTEMPT_ID_V1\n", selected.attempt_id) &&
               binding.round_cohorts[index] ==
                   unhex(selected.cohort_sha256) &&
               binding.financial_runs[index] ==
                   unhex(selected.financial_run_id) &&
               binding.capture == string_identity(
                   "KPB_CAPTURE_IDENTITY_V1\n",
                   selected.capture_identity) &&
               binding.projections[index] ==
                   unhex(selected.projection_sha256) &&
               selected.construction_classification ==
                   static_cast<unsigned>(binding.classification) &&
               binding.attempt ==
                   unhex(selected.construction_attempt_sha256) &&
               binding.round_capture_plans[index] ==
                   unhex(selected.capture_plan_sha256);
    } catch (...) { return false; }
}

namespace {

void valid_payment_selection(const PaymentTerminalSelection& value) {
    valid_selection(value.native);
    const auto round = value.native.ordinal;
    need(round == 1 || round == 2);
    const auto& binding = value.producer_binding;
    need((binding.classification == Classification::HiddenCandidate ||
          binding.classification == Classification::TransparentBaseline) &&
         binding.trial == value.native.trial &&
         binding.outer_parent_process == value.native.outer_parent_process &&
         binding.outer_parent_executable ==
             value.native.outer_parent_executable &&
         binding.projections[round - 1] == value.native.projection &&
         exact_capture_lineage(binding, round, value.capture_binding));
    for (const auto* field : {
             &binding.comparison_selection, &binding.run_selection,
             &binding.trial, &binding.attempt, &binding.cohort,
             &binding.capture, &binding.method, &binding.workload,
             &binding.source_closure, &binding.runtime,
             &binding.outer_parent_process,
             &binding.outer_parent_executable,
             &binding.round_capture_plans[0],
             &binding.round_capture_plans[1]})
        need(nonzero(*field));
    need(binding.finite_manifest.manifest_identity ==
             measurement::recompute_finite_manifest_identity(
                 binding.finite_manifest.entries) &&
         nonzero(binding.finite_manifest.parent_recomputation_identity));
    for (unsigned index = 0;
         index < binding.finite_manifest.entries.size(); ++index)
        need(binding.finite_manifest.entries[index].component ==
             static_cast<measurement::ManifestComponent>(index + 1));
    need(value.native.worker == worker(binding.finite_manifest.entries[0]));
    need(binding.round_capture_plans[0] !=
         binding.round_capture_plans[1]);
    valid_capture_binding(value.capture_binding);
}

Digest stream_identity(const char* domain,
                       const PaymentTerminalSelection& value) {
    Bytes bytes;
    text(bytes, domain);
    selection_bytes(bytes, value.native);
    add(bytes, value.producer_binding.run_selection);
    add(bytes, value.producer_binding.round_attempts[value.native.ordinal - 1]);
    add(bytes, value.producer_binding.round_cohorts[value.native.ordinal - 1]);
    add(bytes,
        value.producer_binding.round_capture_plans[value.native.ordinal - 1]);
    capture_binding_bytes(bytes, value.capture_binding);
    return hash(bytes);
}

} // namespace

Digest recompute_terminal_stream_process_identity(
        const PaymentTerminalSelection& value) {
    valid_payment_selection(value);
    return stream_identity("KPB_NATIVE_TERMINAL_STREAM_PROCESS_V1\n", value);
}
Digest recompute_terminal_stream_child_exit_identity(
        const PaymentTerminalSelection& value) {
    valid_payment_selection(value);
    return stream_identity("KPB_NATIVE_TERMINAL_STREAM_CHILD_EXIT_V1\n",
                           value);
}

namespace {

Digest terminal_eof_identity(
        unsigned round, std::uint64_t records, std::uint64_t payload,
        std::uint64_t raw, const Digest& root, const Digest& end) {
    Bytes bytes;
    text(bytes, "KPB_CAPTURE_PRODUCER_STREAM_EOF_V1\n");
    big(bytes, round, 4);
    bytes.push_back(static_cast<unsigned char>(CaptureKind::TerminalHistory));
    big(bytes, records);
    big(bytes, payload);
    big(bytes, raw);
    add(bytes, root);
    add(bytes, end);
    return hash(bytes);
}

Digest offer_identity(const char* domain,
                      const NativeTerminalSelection& selection,
                      const capture::Binding* capture_binding,
                      const Digest* projection_intake_identity,
                      const Digest& session, std::uint64_t parent_pid,
                      std::uint64_t child_pid) {
    Bytes bytes;
    text(bytes, domain);
    selection_bytes(bytes, selection);
    if (capture_binding != nullptr)
        capture_binding_bytes(bytes, *capture_binding);
    if (projection_intake_identity != nullptr)
        add(bytes, *projection_intake_identity);
    add(bytes, session);
    little(bytes, parent_pid);
    little(bytes, child_pid);
    return hash(bytes);
}

Digest process_identity(const char* domain, const Digest& executable,
                        const Digest& session, const Digest& offer,
                        std::uint64_t pid) {
    Bytes bytes;
    text(bytes, domain);
    add(bytes, executable);
    add(bytes, session);
    add(bytes, offer);
    little(bytes, pid);
    return hash(bytes);
}
Digest exit_identity(const Digest& process, int status) {
    Bytes bytes;
    text(bytes, "KPB_NATIVE_TERMINAL_CHILD_EXIT_V1\n");
    add(bytes, process);
    little(bytes, static_cast<std::uint64_t>(status));
    return hash(bytes);
}

void encode_genesis_result(Bytes& out,
                           const GenesisTerminalChildResult& value) {
    for (const auto* field : {
             &value.accepted_input_head, &value.successor_head,
             &value.projection, &value.core, &value.proof,
             &value.case_identity, &value.durable_final_checkpoint,
             &value.signed_case_completion,
             &value.native_full_completion, &value.r0_completion,
             &value.value_conservation_completion})
        add(out, *field);
    little(out, value.input_value_sompi);
    little(out, value.successor_value_sompi);
    little(out, value.fee_sompi);
}
GenesisTerminalChildResult decode_genesis_result(Decoder& in) {
    GenesisTerminalChildResult result{};
    result.accepted_input_head = in.digest();
    result.successor_head = in.digest();
    result.projection = in.digest();
    result.core = in.digest();
    result.proof = in.digest();
    result.case_identity = in.digest();
    result.durable_final_checkpoint = in.digest();
    result.signed_case_completion = in.digest();
    result.native_full_completion = in.digest();
    result.r0_completion = in.digest();
    result.value_conservation_completion = in.digest();
    result.input_value_sompi = in.little();
    result.successor_value_sompi = in.little();
    result.fee_sompi = in.little();
    return result;
}
GenesisTerminalChildResult expected_result(
        const NativeTerminalSelection& value) {
    return {
        .accepted_input_head = value.accepted_input_head,
        .successor_head = value.successor_head,
        .projection = value.projection,
        .core = value.core,
        .proof = value.proof,
        .case_identity = value.case_identity,
        .durable_final_checkpoint = value.durable_final_checkpoint,
        .signed_case_completion = value.signed_case_completion,
        .native_full_completion = value.native_full_completion,
        .r0_completion = value.r0_completion,
        .value_conservation_completion =
            value.value_conservation_completion,
        .input_value_sompi = value.input_value_sompi,
        .successor_value_sompi = value.successor_value_sompi,
        .fee_sompi = value.fee_sompi,
    };
}
void mutate_result(GenesisTerminalChildResult& value,
                   TestNativeTerminalFault fault) {
    const auto flip = [](Digest& digest) { digest[0] ^= 0xff; };
    switch (fault) {
    case TestNativeTerminalFault::WrongInputHead:
        flip(value.accepted_input_head); break;
    case TestNativeTerminalFault::WrongProjection:
        flip(value.projection); break;
    case TestNativeTerminalFault::WrongCore:
        flip(value.core); break;
    case TestNativeTerminalFault::WrongProof:
        flip(value.proof); break;
    case TestNativeTerminalFault::WrongR0:
        flip(value.r0_completion); break;
    case TestNativeTerminalFault::WrongNativeFull:
        flip(value.native_full_completion); break;
    case TestNativeTerminalFault::WrongConservation:
        flip(value.value_conservation_completion); break;
    case TestNativeTerminalFault::WrongAmounts:
        ++value.successor_value_sompi; break;
    default: break;
    }
}

struct ProjectionOfferEvidence {
    ProjectionBody projection{};
    Digest projection_identity{};
    Digest retained_identity{};
    Digest fork_binding_identity{};
    Digest intake_identity{};
    Digest owner_mapping_authority_identity{};
    std::array<Digest, 3> owner_nullifiers{};
    std::array<std::array<Digest, 2>, 3> owner_tuple_hashes{};
    unsigned round{};
    RouteClassification classification{};
    bool owner_mapping_present{};
};

void encode_projection_offer(Bytes& out, ProjectionOfferEvidence value,
                             TestNativeTerminalFault fault) {
    if (fault == TestNativeTerminalFault::WrongProjectionRoute)
        value.retained_identity[0] ^= 0xff;
    little(out, value.round, 4);
    out.push_back(static_cast<unsigned char>(value.classification));
    out.push_back(value.owner_mapping_present ? 1 : 0);
    add(out, value.projection_identity);
    add(out, value.retained_identity);
    add(out, value.fork_binding_identity);
    add(out, value.intake_identity);
    add(out, value.owner_mapping_authority_identity);
    for (const auto& owner : value.owner_nullifiers) add(out, owner);
    for (const auto& owner : value.owner_tuple_hashes)
        for (const auto& tuple : owner) add(out, tuple);
    add(out, {reinterpret_cast<const unsigned char*>(value.projection.data()),
              value.projection.size()});
}

ProjectionOfferEvidence decode_projection_offer(Decoder& in) {
    ProjectionOfferEvidence result{};
    result.round = static_cast<unsigned>(in.little(4));
    result.classification = static_cast<RouteClassification>(in.byte());
    result.owner_mapping_present = in.byte() == 1;
    result.projection_identity = in.digest();
    result.retained_identity = in.digest();
    result.fork_binding_identity = in.digest();
    result.intake_identity = in.digest();
    result.owner_mapping_authority_identity = in.digest();
    for (auto& owner : result.owner_nullifiers) owner = in.digest();
    for (auto& owner : result.owner_tuple_hashes)
        for (auto& tuple : owner) tuple = in.digest();
    in.fixed({reinterpret_cast<unsigned char*>(result.projection.data()),
              result.projection.size()});
    return result;
}

Bytes make_genesis_offer(const PublicGenesisTerminalOffer& offer,
                         TestNativeTerminalFault fault) {
    Bytes packet{static_cast<unsigned char>(Message::GenesisOffer)};
    selection_bytes(packet, offer.selection);
    add(packet, offer.transport_session);
    add(packet, offer.offer_identity);
    little(packet, offer.parent_pid);
    little(packet, offer.child_pid);
    packet.push_back(static_cast<unsigned char>(fault));
    return packet;
}
Bytes make_payment_offer(const PublicPaymentTerminalOffer& offer,
                         const ProjectionOfferEvidence& projection,
                         TestNativeTerminalFault fault) {
    Bytes packet{static_cast<unsigned char>(Message::PaymentOffer)};
    selection_bytes(packet, offer.native);
    capture_binding_bytes(packet, offer.capture_binding);
    add(packet, offer.transport_session);
    add(packet, offer.offer_identity);
    little(packet, offer.parent_pid);
    little(packet, offer.child_pid);
    encode_projection_offer(packet, projection, fault);
    packet.push_back(static_cast<unsigned char>(fault));
    return packet;
}

struct DecodedGenesisOffer {
    PublicGenesisTerminalOffer offer;
    TestNativeTerminalFault fault{};
};
struct DecodedPaymentOffer {
    PublicPaymentTerminalOffer offer;
    ProjectionOfferEvidence projection;
    TestNativeTerminalFault fault{};
};
DecodedGenesisOffer decode_genesis_offer(
        std::span<const unsigned char> packet) {
    Decoder in(packet);
    need(in.byte() == static_cast<unsigned char>(Message::GenesisOffer));
    DecodedGenesisOffer result{};
    result.offer.selection = decode_selection(in);
    result.offer.transport_session = in.digest();
    result.offer.offer_identity = in.digest();
    result.offer.parent_pid = in.little();
    result.offer.child_pid = in.little();
    result.fault = static_cast<TestNativeTerminalFault>(in.byte());
    in.finished();
    need(static_cast<unsigned>(result.fault) <=
         static_cast<unsigned>(
             TestNativeTerminalFault::ZeroLengthRecordBeforeClose));
    return result;
}
DecodedPaymentOffer decode_payment_offer(
        std::span<const unsigned char> packet) {
    Decoder in(packet);
    need(in.byte() == static_cast<unsigned char>(Message::PaymentOffer));
    DecodedPaymentOffer result{};
    result.offer.native = decode_selection(in);
    result.offer.capture_binding = decode_capture_binding(in);
    result.offer.transport_session = in.digest();
    result.offer.offer_identity = in.digest();
    result.offer.parent_pid = in.little();
    result.offer.child_pid = in.little();
    result.projection = decode_projection_offer(in);
    result.fault = static_cast<TestNativeTerminalFault>(in.byte());
    in.finished();
    need(static_cast<unsigned>(result.fault) <=
         static_cast<unsigned>(
             TestNativeTerminalFault::WrongProjectionRoute));
    return result;
}

Bytes ack_packet(Digest offer, TestNativeTerminalFault fault) {
    if (fault == TestNativeTerminalFault::WrongAckOffer) offer[0] ^= 0xff;
    Bytes packet{static_cast<unsigned char>(Message::Ack)};
    add(packet, offer);
    return packet;
}
void validate_ack(std::span<const unsigned char> packet,
                  const Digest& expected) {
    Decoder in(packet);
    need(in.byte() == static_cast<unsigned char>(Message::Ack) &&
         in.digest() == expected);
    in.finished();
}
int relay_ack(int fd, const Digest& offer) {
    const pid_t relay = ::fork();
    if (relay < 0) return 97;
    if (relay == 0) {
        try {
            send_packet(fd, ack_packet(offer,
                        TestNativeTerminalFault::None));
        } catch (...) { _exit(98); }
        _exit(0);
    }
    int status = 0;
    while (::waitpid(relay, &status, 0) < 0 && errno == EINTR) {}
    return 96;
}

void send_zero_length_record(int fd) {
    ssize_t count;
    do { count = ::send(fd, nullptr, 0, MSG_NOSIGNAL); }
    while (count < 0 && errno == EINTR);
    need(count == 0);
}

struct PrivatePaymentPacket {
    GenesisTerminalChildResult native;
    unsigned round{};
    capture::Binding binding;
    std::string candidate;
    std::string case_identity;
    std::string r0;
    std::string native_full;
    std::string final_checkpoint;
    std::string mapping_source_identity;
    Digest record_root{};
    Digest end_frame{};
    std::uint64_t record_count{};
    std::uint64_t payload_bytes{};
    std::uint64_t raw_wire_bytes{};
    unsigned explicit_owner_mapping_export_count{};
    bool owner_mapping_present{};
    bool grouping_source_complete{};
    bool explicit_owner_mapping_export_source_complete{};
    bool public_continuity_modeled_separately{};
    bool end_written{};
    bool writer_closed{};
};
PrivatePaymentPacket decode_payment_completion(
        std::span<const unsigned char> packet) {
    Decoder in(packet);
    need(in.byte() == static_cast<unsigned char>(
        Message::PaymentCompletion));
    PrivatePaymentPacket result{};
    result.native = decode_genesis_result(in);
    result.round = static_cast<unsigned>(in.little(4));
    result.binding = decode_capture_binding(in);
    result.candidate = in.string();
    result.case_identity = in.string();
    result.r0 = in.string();
    result.native_full = in.string();
    result.final_checkpoint = in.string();
    result.mapping_source_identity = in.string();
    result.record_root = in.digest();
    result.end_frame = in.digest();
    result.record_count = in.little();
    result.payload_bytes = in.little();
    result.raw_wire_bytes = in.little();
    result.explicit_owner_mapping_export_count =
        static_cast<unsigned>(in.little(4));
    result.owner_mapping_present = in.byte() == 1;
    result.grouping_source_complete = in.byte() == 1;
    result.explicit_owner_mapping_export_source_complete = in.byte() == 1;
    result.public_continuity_modeled_separately = in.byte() == 1;
    result.end_written = in.byte() == 1;
    result.writer_closed = in.byte() == 1;
    in.finished();
    return result;
}

} // namespace

int run_genesis_terminal_child(GenesisTerminalChildProgram& program) noexcept {
    try {
        const std::array<int, 1> keep{NATIVE_TERMINAL_CHILD_FIXED_FD};
        close_except(keep);
        const auto received = receive_packet(
            NATIVE_TERMINAL_CHILD_FIXED_FD, ::getppid());
        const auto decoded = decode_genesis_offer(received.bytes);
        const auto& offer = decoded.offer;
        valid_selection(offer.selection);
        need(offer.selection.kind == NativeCandidateKind::Genesis &&
             offer.parent_pid == static_cast<std::uint64_t>(received.sender) &&
             offer.parent_pid == static_cast<std::uint64_t>(::getppid()) &&
             offer.child_pid == static_cast<std::uint64_t>(::getpid()) &&
             offer.offer_identity == offer_identity(
                 "KPB_NATIVE_GENESIS_OFFER_V1\n", offer.selection, nullptr,
             nullptr,
                 offer.transport_session, offer.parent_pid,
                 offer.child_pid));
        if (decoded.fault == TestNativeTerminalFault::CredentialRelay)
            return relay_ack(NATIVE_TERMINAL_CHILD_FIXED_FD,
                             offer.offer_identity);
        send_packet(NATIVE_TERMINAL_CHILD_FIXED_FD,
                    ack_packet(offer.offer_identity, decoded.fault));
        auto result = program.execute(offer);
        mutate_result(result, decoded.fault);
        if (decoded.fault == TestNativeTerminalFault::NoCompletion)
            return 0;
        Bytes packet{static_cast<unsigned char>(
            decoded.fault == TestNativeTerminalFault::WrongCompletionKind
                ? Message::PaymentCompletion
                : Message::GenesisCompletion)};
        encode_genesis_result(packet, result);
        send_packet(NATIVE_TERMINAL_CHILD_FIXED_FD, packet);
        if (decoded.fault == TestNativeTerminalFault::DuplicateCompletion)
            send_packet(NATIVE_TERMINAL_CHILD_FIXED_FD, packet);
        if (decoded.fault ==
            TestNativeTerminalFault::ZeroLengthRecordBeforeClose)
            send_zero_length_record(NATIVE_TERMINAL_CHILD_FIXED_FD);
        return decoded.fault == TestNativeTerminalFault::NonzeroExit ? 91 : 0;
    } catch (...) { return 78; }
}

int run_payment_terminal_child(PaymentTerminalChildProgram& program) noexcept {
    try {
        const std::array<int, 3> keep{
            NATIVE_TERMINAL_CHILD_FIXED_FD, 21, 26};
        close_except(keep);
        const auto received = receive_packet(
            NATIVE_TERMINAL_CHILD_FIXED_FD, ::getppid());
        const auto decoded = decode_payment_offer(received.bytes);
        const auto& offer = decoded.offer;
        valid_selection(offer.native);
        valid_capture_binding(offer.capture_binding);
        need((offer.native.kind == NativeCandidateKind::PaymentRound1 ||
              offer.native.kind == NativeCandidateKind::PaymentRound2) &&
             offer.native.ordinal >= 1 && offer.native.ordinal <= 2 &&
             offer.parent_pid == static_cast<std::uint64_t>(received.sender) &&
             offer.parent_pid == static_cast<std::uint64_t>(::getppid()) &&
             offer.child_pid == static_cast<std::uint64_t>(::getpid()) &&
             offer.offer_identity == offer_identity(
                 "KPB_NATIVE_PAYMENT_OFFER_V1\n", offer.native,
                 &offer.capture_binding, &decoded.projection.intake_identity,
                 offer.transport_session,
                 offer.parent_pid, offer.child_pid));
        NativeTerminalChildProjectionEvidence retained;
        retained.projection = decoded.projection.projection;
        retained.projection_identity = decoded.projection.projection_identity;
        retained.retained_identity = decoded.projection.retained_identity;
        retained.fork_binding_identity =
            decoded.projection.fork_binding_identity;
        retained.intake_identity = decoded.projection.intake_identity;
        retained.owner_mapping_authority_identity =
            decoded.projection.owner_mapping_authority_identity;
        retained.owner_nullifiers = decoded.projection.owner_nullifiers;
        retained.owner_tuple_hashes = decoded.projection.owner_tuple_hashes;
        retained.round = decoded.projection.round;
        retained.classification = decoded.projection.classification;
        retained.owner_mapping_present =
            decoded.projection.owner_mapping_present;
        auto mapping =
            NativeTerminalProjectionIntake::admit_authenticated_child(
                std::move(retained), offer);
        if (decoded.fault == TestNativeTerminalFault::CredentialRelay)
            return relay_ack(NATIVE_TERMINAL_CHILD_FIXED_FD,
                             offer.offer_identity);
        send_packet(NATIVE_TERMINAL_CHILD_FIXED_FD,
                    ack_packet(offer.offer_identity, decoded.fault));
        const int terminal_fd = offer.native.ordinal == 1 ? 21 : 26;
        capture::TerminalCaptureV2 terminal(
            terminal_fd, offer.native.ordinal, offer.capture_binding);
        auto child = program.execute(
            offer, terminal, std::move(mapping));
        mutate_result(child.native, decoded.fault);
        auto evidence = NativeTerminalChildEvidenceBridge::consume(
            std::move(child.terminal));
        need(evidence.round == offer.native.ordinal &&
             evidence.binding.attempt_id == offer.capture_binding.attempt_id &&
             evidence.binding.cohort_sha256 ==
                 offer.capture_binding.cohort_sha256 &&
             evidence.binding.financial_run_id ==
                 offer.capture_binding.financial_run_id &&
             evidence.binding.capture_identity ==
                 offer.capture_binding.capture_identity &&
             evidence.binding.projection_sha256 ==
                 offer.capture_binding.projection_sha256 &&
             evidence.binding.construction_classification ==
                 offer.capture_binding.construction_classification &&
             evidence.binding.construction_attempt_sha256 ==
                 offer.capture_binding.construction_attempt_sha256 &&
             evidence.binding.capture_plan_sha256 ==
                 offer.capture_binding.capture_plan_sha256 &&
             evidence.candidate_sha256 == hex(offer.native.successor_head) &&
             evidence.case_sha256 == hex(offer.native.case_identity) &&
             evidence.r0_receipt_sha256 == hex(offer.native.r0_completion) &&
             evidence.native_full_sha256 ==
                 hex(offer.native.native_full_completion) &&
             evidence.final_checkpoint_sha256 ==
                 hex(offer.native.durable_final_checkpoint));
        if (decoded.fault == TestNativeTerminalFault::NoCompletion)
            return 0;
        Bytes packet{static_cast<unsigned char>(
            decoded.fault == TestNativeTerminalFault::WrongCompletionKind
                ? Message::GenesisCompletion
                : Message::PaymentCompletion)};
        encode_genesis_result(packet, child.native);
        little(packet, evidence.round, 4);
        capture_binding_bytes(packet, evidence.binding);
        string_bytes(packet, evidence.candidate_sha256);
        string_bytes(packet, evidence.case_sha256);
        string_bytes(packet, evidence.r0_receipt_sha256);
        string_bytes(packet, evidence.native_full_sha256);
        string_bytes(packet, evidence.final_checkpoint_sha256);
        string_bytes(packet, evidence.mapping_source_identity);
        auto root = unhex(evidence.record_root_sha256);
        auto end = unhex(evidence.end_frame_sha256);
        auto records = evidence.record_count;
        if (decoded.fault == TestNativeTerminalFault::WrongTerminalRoot)
            root[0] ^= 0xff;
        if (decoded.fault == TestNativeTerminalFault::WrongTerminalEnd)
            end[0] ^= 0xff;
        if (decoded.fault == TestNativeTerminalFault::WrongTerminalCount)
            ++records;
        add(packet, root);
        add(packet, end);
        little(packet, records);
        little(packet, evidence.payload_bytes);
        little(packet, evidence.raw_wire_bytes);
        little(packet, evidence.explicit_owner_mapping_export_count, 4);
        packet.push_back(evidence.owner_mapping_present ? 1 : 0);
        packet.push_back(
            evidence.grouping_source_complete ? 1 : 0);
        packet.push_back(
            evidence.explicit_owner_mapping_export_source_complete ? 1 : 0);
        packet.push_back(
            evidence.public_continuity_modeled_separately ? 1 : 0);
        packet.push_back(evidence.end_written ? 1 : 0);
        packet.push_back(evidence.writer_closed ? 1 : 0);
        send_packet(NATIVE_TERMINAL_CHILD_FIXED_FD, packet);
        if (decoded.fault == TestNativeTerminalFault::DuplicateCompletion)
            send_packet(NATIVE_TERMINAL_CHILD_FIXED_FD, packet);
        if (decoded.fault ==
            TestNativeTerminalFault::ZeroLengthRecordBeforeClose)
            send_zero_length_record(NATIVE_TERMINAL_CHILD_FIXED_FD);
        return decoded.fault == TestNativeTerminalFault::NonzeroExit ? 91 : 0;
    } catch (...) { return 78; }
}

#ifdef KPB_NATIVE_TERMINAL_COMPLETION_TEST_SETUP
int test_only_run_genesis_terminal_child(
        GenesisTerminalChildProgram& program) noexcept {
    return run_genesis_terminal_child(program);
}
int test_only_run_payment_terminal_child(
        PaymentTerminalChildProgram& program) noexcept {
    return run_payment_terminal_child(program);
}
#endif

namespace {

void valid_outer_parent(const NativeTerminalSelection& value) {
    const auto executable = current_executable_identity();
    need(value.outer_parent_executable == executable);
    Bytes bytes;
    text(bytes, "KPB_NATIVE_TERMINAL_OUTER_PARENT_V1\n");
    add(bytes, executable);
    little(bytes, static_cast<std::uint64_t>(::getpid()));
    need(value.outer_parent_process == hash(bytes));
}
void valid_sealed_executable(int fd,
                             const NativeTerminalSelection& selection) {
    const int seals = ::fcntl(fd, F_GET_SEALS);
    constexpr int REQUIRED =
        F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
    need(seals >= 0 && (seals & REQUIRED) == REQUIRED &&
         hash_fd(fd) == selection.worker.pinned_executable_identity);
}
void valid_terminal_writer(int fd) {
    struct stat selected{};
    need(fd >= 0 && ::fstat(fd, &selected) == 0 &&
         S_ISFIFO(selected.st_mode));
    const int flags = ::fcntl(fd, F_GETFL);
    need(flags >= 0 && (flags & O_ACCMODE) == O_WRONLY);
    DIR* directory = ::opendir("/proc/self/fd");
    need(directory != nullptr);
    struct Guard { DIR* value; ~Guard() { ::closedir(value); } }
        guard{directory};
    const int directory_fd = ::dirfd(directory);
    unsigned writers = 0;
    while (auto* entry = ::readdir(directory)) {
        char* end = nullptr;
        errno = 0;
        const long candidate = std::strtol(entry->d_name, &end, 10);
        if (errno != 0 || end == entry->d_name || *end != '\0' ||
            candidate < 0 || candidate == directory_fd)
            continue;
        struct stat observed{};
        if (::fstat(static_cast<int>(candidate), &observed) != 0 ||
            observed.st_dev != selected.st_dev ||
            observed.st_ino != selected.st_ino)
            continue;
        const int observed_flags = ::fcntl(
            static_cast<int>(candidate), F_GETFL);
        if (observed_flags >= 0 &&
            ((observed_flags & O_ACCMODE) == O_WRONLY ||
             (observed_flags & O_ACCMODE) == O_RDWR))
            ++writers;
    }
    need(writers == 1);
}

struct SpawnedChild { pid_t pid{}; Fd control; };
SpawnedChild spawn_child(const char* mode, int executable_fd,
                         int terminal_writer_fd, int terminal_fixed_fd) {
    Fd executable(::fcntl(executable_fd, F_DUPFD_CLOEXEC, 100));
    need(executable.get() >= 100);
    int sockets[2]{-1, -1};
    need(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC,
                      0, sockets) == 0);
    Fd parent(sockets[0]);
    Fd child(sockets[1]);
    pass_credentials(parent.get());
    pass_credentials(child.get());
    const pid_t pid = ::fork();
    need(pid >= 0);
    if (pid == 0) {
        if (::dup2(child.get(), NATIVE_TERMINAL_CHILD_FIXED_FD) !=
            NATIVE_TERMINAL_CHILD_FIXED_FD)
            _exit(121);
        if (terminal_writer_fd >= 0 &&
            ::dup2(terminal_writer_fd, terminal_fixed_fd) !=
                terminal_fixed_fd)
            _exit(122);
        const int control_flags = ::fcntl(
            NATIVE_TERMINAL_CHILD_FIXED_FD, F_GETFD);
        if (control_flags < 0 || ::fcntl(
                NATIVE_TERMINAL_CHILD_FIXED_FD, F_SETFD,
                control_flags & ~FD_CLOEXEC) != 0)
            _exit(123);
        if (terminal_writer_fd >= 0) {
            const int terminal_flags = ::fcntl(terminal_fixed_fd, F_GETFD);
            if (terminal_flags < 0 || ::fcntl(
                    terminal_fixed_fd, F_SETFD,
                    terminal_flags & ~FD_CLOEXEC) != 0)
                _exit(124);
        }
        const std::array<int, 3> retained{
            executable.get(), NATIVE_TERMINAL_CHILD_FIXED_FD,
            terminal_writer_fd >= 0 ? terminal_fixed_fd : -1};
        close_except(retained);
        char argument0[] = "kpb-native-terminal-child";
        char* arguments[]{argument0, nullptr};
        std::string variable = std::string("KPB_NATIVE_TERMINAL_CHILD=") +
            mode;
        char* environment[]{variable.data(), nullptr};
        (void)::syscall(SYS_execveat, executable.get(), "", arguments,
                        environment, AT_EMPTY_PATH);
        _exit(126);
    }
    child.reset();
    executable.reset();
    return {.pid = pid, .control = std::move(parent)};
}

class ChildGuard final {
    pid_t pid_;
    bool waited_{};
public:
    explicit ChildGuard(pid_t pid) : pid_(pid) {}
    ChildGuard(const ChildGuard&) = delete;
    ChildGuard& operator=(const ChildGuard&) = delete;
    ~ChildGuard() {
        if (waited_) return;
        (void)::kill(pid_, SIGKILL);
        int status = 0;
        while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {}
    }
    int wait() {
        need(!waited_);
        int status = 0;
        pid_t result;
        do { result = ::waitpid(pid_, &status, 0); }
        while (result < 0 && errno == EINTR);
        need(result == pid_);
        waited_ = true;
        return status;
    }
};

struct GenesisObserved {
    PublicGenesisTerminalOffer offer;
    GenesisTerminalChildResult result;
    Digest child_process{};
    Digest child_exit{};
    std::uint64_t authenticated_pid{};
    std::uint64_t waited_pid{};
    bool control_closed{};
};
GenesisObserved supervise_genesis(
        const NativeTerminalSelection& selection, int executable_fd,
        TestNativeTerminalFault fault) {
    valid_selection(selection);
    need(selection.kind == NativeCandidateKind::Genesis);
    valid_outer_parent(selection);
    valid_sealed_executable(executable_fd, selection);
    auto child = spawn_child("GENESIS", executable_fd, -1, -1);
    ChildGuard guard(child.pid);
    PublicGenesisTerminalOffer offer{
        .selection = selection,
        .transport_session = random_digest(),
        .parent_pid = static_cast<std::uint64_t>(::getpid()),
        .child_pid = static_cast<std::uint64_t>(child.pid),
    };
    offer.offer_identity = offer_identity(
        "KPB_NATIVE_GENESIS_OFFER_V1\n", selection, nullptr,
        nullptr,
        offer.transport_session, offer.parent_pid, offer.child_pid);
    send_packet(child.control.get(), make_genesis_offer(offer, fault));
    const auto ack = receive_packet(child.control.get(), child.pid);
    validate_ack(ack.bytes, offer.offer_identity);
    const auto completion = receive_packet(child.control.get(), child.pid);
    Decoder in(completion.bytes);
    need(in.byte() == static_cast<unsigned char>(Message::GenesisCompletion));
    const auto result = decode_genesis_result(in);
    in.finished();
    need(result == expected_result(selection));
    expect_control_eof(child.control.get());
    const int status = guard.wait();
    need(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    const auto process = process_identity(
        "KPB_NATIVE_GENESIS_CHILD_PROCESS_V1\n",
        selection.worker.pinned_executable_identity,
        offer.transport_session, offer.offer_identity, offer.child_pid);
    return {.offer = offer, .result = result,
            .child_process = process,
            .child_exit = exit_identity(process, status),
            .authenticated_pid = static_cast<std::uint64_t>(completion.sender),
            .waited_pid = static_cast<std::uint64_t>(child.pid),
            .control_closed = true};
}

struct PaymentObserved {
    PublicPaymentTerminalOffer offer;
    PrivatePaymentPacket packet;
    Digest child_process{};
    Digest child_exit{};
    Digest retained_projection{};
    Digest projection_fork_binding{};
    Digest projection_intake{};
    std::uint64_t authenticated_pid{};
    std::uint64_t waited_pid{};
    bool control_closed{};
};
PaymentObserved supervise_payment(
        const PaymentTerminalSelection& selection, int executable_fd,
        Fd& terminal_writer, ProjectionOfferEvidence projection,
        TestNativeTerminalFault fault) {
    valid_payment_selection(selection);
    valid_outer_parent(selection.native);
    valid_sealed_executable(executable_fd, selection.native);
    valid_terminal_writer(terminal_writer.get());
    const int fixed_fd = selection.native.ordinal == 1 ? 21 : 26;
    auto child = spawn_child("PAYMENT", executable_fd,
                             terminal_writer.get(), fixed_fd);
    terminal_writer.reset();
    ChildGuard guard(child.pid);
    PublicPaymentTerminalOffer offer{
        .native = selection.native,
        .capture_binding = selection.capture_binding,
        .transport_session = random_digest(),
        .parent_pid = static_cast<std::uint64_t>(::getpid()),
        .child_pid = static_cast<std::uint64_t>(child.pid),
    };
    offer.offer_identity = offer_identity(
        "KPB_NATIVE_PAYMENT_OFFER_V1\n", selection.native,
        &selection.capture_binding, &projection.intake_identity,
        offer.transport_session,
        offer.parent_pid, offer.child_pid);
    send_packet(child.control.get(), make_payment_offer(
        offer, projection, fault));
    const auto ack = receive_packet(child.control.get(), child.pid);
    validate_ack(ack.bytes, offer.offer_identity);
    const auto completion = receive_packet(child.control.get(), child.pid);
    const auto packet = decode_payment_completion(completion.bytes);
    need(packet.native == expected_result(selection.native) &&
         packet.round == selection.native.ordinal &&
         packet.binding.attempt_id == selection.capture_binding.attempt_id &&
         packet.binding.cohort_sha256 ==
             selection.capture_binding.cohort_sha256 &&
         packet.binding.financial_run_id ==
             selection.capture_binding.financial_run_id &&
         packet.binding.capture_identity ==
             selection.capture_binding.capture_identity &&
         packet.binding.projection_sha256 ==
             selection.capture_binding.projection_sha256 &&
         packet.binding.construction_classification ==
             selection.capture_binding.construction_classification &&
         packet.binding.construction_attempt_sha256 ==
             selection.capture_binding.construction_attempt_sha256 &&
         packet.binding.capture_plan_sha256 ==
             selection.capture_binding.capture_plan_sha256 &&
         packet.candidate == hex(selection.native.successor_head) &&
         packet.case_identity == hex(selection.native.case_identity) &&
         packet.r0 == hex(selection.native.r0_completion) &&
         packet.native_full == hex(selection.native.native_full_completion) &&
         packet.final_checkpoint ==
             hex(selection.native.durable_final_checkpoint) &&
         nonzero(unhex(packet.mapping_source_identity)) &&
         nonzero(packet.record_root) && nonzero(packet.end_frame) &&
         packet.record_root != packet.end_frame &&
         packet.record_count >= 8 && packet.payload_bytes > 0 &&
         packet.raw_wire_bytes > packet.payload_bytes &&
         packet.explicit_owner_mapping_export_count == 0 &&
         packet.grouping_source_complete &&
         packet.explicit_owner_mapping_export_source_complete &&
         packet.public_continuity_modeled_separately &&
         packet.owner_mapping_present ==
             (selection.producer_binding.classification ==
              Classification::TransparentBaseline) &&
         packet.end_written &&
         packet.writer_closed);
    expect_control_eof(child.control.get());
    const int status = guard.wait();
    need(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    const auto process = process_identity(
        "KPB_NATIVE_PAYMENT_CHILD_PROCESS_V1\n",
        selection.native.worker.pinned_executable_identity,
        offer.transport_session, offer.offer_identity, offer.child_pid);
    return {.offer = offer, .packet = packet,
            .child_process = process,
            .child_exit = exit_identity(process, status),
            .retained_projection = projection.retained_identity,
            .projection_fork_binding = projection.fork_binding_identity,
            .projection_intake = projection.intake_identity,
            .authenticated_pid = static_cast<std::uint64_t>(completion.sender),
            .waited_pid = static_cast<std::uint64_t>(child.pid),
            .control_closed = true};
}

Digest private_lifecycle_identity(
        const PublicPaymentLifecycleCompletion& receipt,
        const capture::Binding& binding,
        const Digest& structural_projection_identity,
        const Digest& record_root,
        const Digest& end_frame, const Digest& eof_identity,
        const Digest& retained_projection,
        const Digest& projection_fork_binding,
        const Digest& projection_intake,
        const Digest& terminal_mapping_source,
        std::uint64_t record_count, std::uint64_t payload_bytes,
        std::uint64_t raw_wire_bytes, std::uint64_t authenticated_pid,
        std::uint64_t waited_pid,
        unsigned explicit_owner_mapping_export_count,
        bool owner_mapping_present, bool owner_mapping_absent,
        bool grouping_source_complete,
        bool explicit_owner_mapping_export_source_complete,
        bool public_continuity_modeled_separately,
        bool end_written, bool writer_closed) {
    Bytes bytes;
    text(bytes, "KPB_NATIVE_PAYMENT_PRIVATE_LIFECYCLE_V2\n");
    selection_bytes(bytes, receipt.native);
    for (const auto* field : {
             &receipt.producer_binding.run_selection,
             &receipt.producer_binding.attempt,
             &receipt.producer_binding.cohort,
             &receipt.producer_binding.capture,
             &receipt.producer_binding.round_capture_plans[
                 receipt.native.ordinal - 1],
             &receipt.producer_binding.finite_manifest.manifest_identity,
             &receipt.stream_process_identity,
             &receipt.stream_child_exit_identity,
             &receipt.transport_session, &receipt.offer_identity,
             &receipt.child_process_observation,
             &receipt.child_exit_observation,
             &receipt.opaque_lifecycle_authority_identity})
        add(bytes, *field);
    capture_binding_bytes(bytes, binding);
    add(bytes, structural_projection_identity);
    add(bytes, record_root);
    add(bytes, end_frame);
    add(bytes, eof_identity);
    add(bytes, retained_projection);
    add(bytes, projection_fork_binding);
    add(bytes, projection_intake);
    add(bytes, terminal_mapping_source);
    little(bytes, record_count);
    little(bytes, payload_bytes);
    little(bytes, raw_wire_bytes);
    little(bytes, authenticated_pid);
    little(bytes, waited_pid);
    little(bytes, explicit_owner_mapping_export_count, 4);
    bytes.push_back(owner_mapping_present ? 1 : 0);
    bytes.push_back(owner_mapping_absent ? 1 : 0);
    bytes.push_back(grouping_source_complete ? 1 : 0);
    bytes.push_back(
        explicit_owner_mapping_export_source_complete ? 1 : 0);
    bytes.push_back(public_continuity_modeled_separately ? 1 : 0);
    bytes.push_back(end_written ? 1 : 0);
    bytes.push_back(writer_closed ? 1 : 0);
    return hash(bytes);
}

} // namespace

PaymentLifecycleCompletionAuthority::PrivateStructuralProjectionEvidence
PaymentLifecycleCompletionAuthority::parse_structural_projection(
        std::span<const std::byte> projection) {
    need(projection.size() == 10685);
    const auto* raw = reinterpret_cast<const unsigned char*>(
        projection.data());
    const auto* body = raw + 193;
    need(std::memcmp(raw, "KPBAFX01\x01\0\x01\0", 12) == 0 &&
         std::memcmp(body, "KPBAEF01", 8) == 0);
    const auto digest_at = [](const unsigned char* value) {
        Digest result{};
        std::copy_n(value, result.size(), result.begin());
        return result;
    };
    const auto u32_at = [](const unsigned char* value) {
        std::uint32_t result{};
        for (unsigned index = 0; index < 4; ++index)
            result |= static_cast<std::uint32_t>(value[index]) <<
                (8 * index);
        return result;
    };
    const auto u64_at = [](const unsigned char* value) {
        std::uint64_t result{};
        for (unsigned index = 0; index < 8; ++index)
            result |= static_cast<std::uint64_t>(value[index]) <<
                (8 * index);
        return result;
    };
    const auto hash_bytes = [](const unsigned char* value,
                               std::size_t size) {
        return hash({value, size});
    };
    Bytes old_state; text(old_state, "KPBAST01");
    add(old_state, {body + 104, 32});
    add(old_state, {body + 204, 32});
    add(old_state, {body + 268, 4});
    add(old_state, {body + 236, 32});
    add(old_state, {body + 272, 4});
    Bytes successor_state; text(successor_state, "KPBAST01");
    add(successor_state, {body + 104, 32});
    add(successor_state, {body + 284, 32});
    add(successor_state, {body + 348, 4});
    add(successor_state, {body + 316, 32});
    add(successor_state, {body + 352, 4});
    need(old_state.size() == 112 && successor_state.size() == 112);

    PrivateStructuralProjectionEvidence result{
        .projection_identity = hash_bytes(raw, projection.size()),
        .profile_context_identity = hash_bytes(body + 8, 160),
        .old_context_identity = hash_bytes(body + 8, 276),
        .old_reserve_outpoint_identity = hash_bytes(body + 168, 36),
        .old_cm_root = digest_at(body + 204),
        .old_nf_root = digest_at(body + 236),
        .old_cm_count = u32_at(body + 268),
        .old_nf_count = u32_at(body + 272),
        .old_reserve_sompi = u64_at(body + 276),
        .new_cm_root = digest_at(body + 284),
        .new_nf_root = digest_at(body + 316),
        .new_cm_count = u32_at(body + 348),
        .new_nf_count = u32_at(body + 352),
        .new_reserve_sompi = u64_at(body + 356),
        .fee_sompi = u64_at(body + 364),
        .old_state_identity = hash(old_state),
        .successor_state_identity = hash(successor_state),
        .old_script_identity = hash_bytes(raw + 66, 37),
        .successor_script_identity = hash_bytes(raw + 115, 37),
    };
    for (unsigned index = 0; index < result.public_nullifiers.size(); ++index)
        result.public_nullifiers[index] = digest_at(body + 404 + index * 96);
    for (unsigned index = 0; index < result.public_outputs.size(); ++index)
        std::copy_n(
            body + 692 + index * result.public_outputs[index].size(),
            result.public_outputs[index].size(),
            result.public_outputs[index].begin());
    Bytes old_context;
    text(old_context, "KPB_STRUCTURAL_PROJECTION_CONTEXT_V1\n");
    add(old_context, {body + 8, 160});
    add(old_context, result.old_cm_root);
    add(old_context, result.old_nf_root);
    little(old_context, result.old_cm_count, 4);
    little(old_context, result.old_nf_count, 4);
    little(old_context, result.old_reserve_sompi);
    add(old_context, {raw + 66, 37});
    result.structural_old_context_identity = hash(old_context);
    Bytes successor_context;
    text(successor_context, "KPB_STRUCTURAL_PROJECTION_CONTEXT_V1\n");
    add(successor_context, {body + 8, 160});
    add(successor_context, result.new_cm_root);
    add(successor_context, result.new_nf_root);
    little(successor_context, result.new_cm_count, 4);
    little(successor_context, result.new_nf_count, 4);
    little(successor_context, result.new_reserve_sompi);
    add(successor_context, {raw + 115, 37});
    result.structural_successor_context_identity = hash(successor_context);
    result.structural_projection_identity =
        recompute_structural_projection_identity(result);
    validate_structural_projection(result);
    return result;
}

Digest PaymentLifecycleCompletionAuthority::
recompute_structural_projection_identity(
        const PrivateStructuralProjectionEvidence& value) {
    Bytes bytes;
    text(bytes, "KPB_PRIVATE_STRUCTURAL_PROJECTION_EVIDENCE_V1\n");
    for (const auto* field : {
             &value.projection_identity,
             &value.profile_context_identity,
             &value.old_context_identity,
             &value.old_reserve_outpoint_identity,
             &value.old_cm_root, &value.old_nf_root,
             &value.new_cm_root, &value.new_nf_root,
             &value.old_state_identity,
             &value.successor_state_identity,
             &value.old_script_identity,
             &value.successor_script_identity,
             &value.structural_old_context_identity,
             &value.structural_successor_context_identity})
        add(bytes, *field);
    for (const auto& nullifier : value.public_nullifiers)
        add(bytes, nullifier);
    for (const auto& output : value.public_outputs)
        add(bytes, output);
    little(bytes, value.old_cm_count, 4);
    little(bytes, value.old_nf_count, 4);
    little(bytes, value.old_reserve_sompi);
    little(bytes, value.new_cm_count, 4);
    little(bytes, value.new_nf_count, 4);
    little(bytes, value.new_reserve_sompi);
    little(bytes, value.fee_sompi);
    return hash(bytes);
}

void PaymentLifecycleCompletionAuthority::validate_structural_projection(
        const PrivateStructuralProjectionEvidence& value) {
    for (const auto* field : {
             &value.projection_identity,
             &value.profile_context_identity,
             &value.old_context_identity,
             &value.old_reserve_outpoint_identity,
             &value.old_cm_root, &value.old_nf_root,
             &value.new_cm_root, &value.new_nf_root,
             &value.old_state_identity,
             &value.successor_state_identity,
             &value.old_script_identity,
             &value.successor_script_identity,
             &value.structural_old_context_identity,
             &value.structural_successor_context_identity,
             &value.structural_projection_identity})
        need(nonzero(*field));
    need(value.old_cm_count >= 3 && value.old_cm_count <= 65536 &&
         value.old_nf_count >= 1 && value.old_nf_count <= 131072 &&
         value.new_cm_count == value.old_cm_count + 6 &&
         value.new_nf_count == value.old_nf_count + 3 &&
         value.new_cm_count <= 65536 &&
         value.new_nf_count <= 131072 &&
         value.old_reserve_sompi >= 60'000'000 &&
         value.new_reserve_sompi >= 60'000'000 &&
         value.fee_sompi > 0 &&
         value.new_reserve_sompi + value.fee_sompi ==
             value.old_reserve_sompi &&
         value.old_state_identity != value.successor_state_identity &&
         value.old_script_identity != value.successor_script_identity &&
         value.structural_projection_identity ==
             recompute_structural_projection_identity(value));
    const auto little_less = [](const Digest& left, const Digest& right) {
        return std::lexicographical_compare(
            left.rbegin(), left.rend(), right.rbegin(), right.rend());
    };
    for (unsigned index = 0; index < value.public_nullifiers.size(); ++index) {
        need(nonzero(value.public_nullifiers[index]));
        if (index > 0)
            need(little_less(value.public_nullifiers[index - 1],
                             value.public_nullifiers[index]));
    }
    for (unsigned index = 0; index < value.public_outputs.size(); ++index) {
        const auto& output = value.public_outputs[index];
        need(std::any_of(output.begin(), output.begin() + 32,
                         [](unsigned char byte) { return byte != 0; }) &&
             std::any_of(output.begin() + 32, output.begin() + 96,
                         [](unsigned char byte) { return byte != 0; }) &&
             std::any_of(output.begin() + 96, output.begin() + 128,
                         [](unsigned char byte) { return byte != 0; }) &&
             std::any_of(output.begin() + 392, output.end(),
                         [](unsigned char byte) { return byte != 0; }));
        const auto ciphertext_hash = hash(
            {output.data() + 96, 264});
        need(std::equal(ciphertext_hash.begin(), ciphertext_hash.end(),
                        output.begin() + 360));
        for (unsigned previous = 0; previous < index; ++previous)
            need(value.public_outputs[previous] != output &&
                 !std::equal(value.public_outputs[previous].begin(),
                             value.public_outputs[previous].begin() + 32,
                             output.begin()));
    }
}

PaymentLifecycleCompletionAuthority::PaymentLifecycleCompletionAuthority(
        PublicPaymentLifecycleCompletion receipt,
        PrivateTerminalStreamEvidence evidence)
    : receipt_(std::move(receipt)), evidence_(std::move(evidence)) {
    validate_for_native_terminal_join();
}

void PaymentLifecycleCompletionAuthority::
validate_for_native_terminal_join() const {
    validate_structural_projection(evidence_.structural_projection);
    need(receipt_.native.kind == NativeCandidateKind::PaymentRound1 ||
         receipt_.native.kind == NativeCandidateKind::PaymentRound2);
    const PaymentTerminalSelection selected{
        .native = receipt_.native,
        .producer_binding = receipt_.producer_binding,
        .capture_binding = evidence_.capture_binding,
    };
    valid_payment_selection(selected);
    need(receipt_.stream_process_identity ==
             recompute_terminal_stream_process_identity(selected) &&
         receipt_.stream_child_exit_identity ==
             recompute_terminal_stream_child_exit_identity(selected));
    for (const auto* field : {
             &receipt_.stream_process_identity,
             &receipt_.stream_child_exit_identity,
             &receipt_.transport_session, &receipt_.offer_identity,
             &receipt_.child_process_observation,
             &receipt_.child_exit_observation,
             &receipt_.opaque_lifecycle_authority_identity,
             &evidence_.record_root, &evidence_.end_frame_identity,
             &evidence_.expected_eof_identity,
             &evidence_.retained_projection_identity,
             &evidence_.projection_fork_binding_identity,
             &evidence_.projection_intake_identity,
             &evidence_.terminal_mapping_source_identity,
             &evidence_.private_completion_identity})
        need(nonzero(*field));
    need(receipt_.credentials_verified && receipt_.offer_acknowledged &&
         receipt_.child_control_closed && receipt_.clean_exit &&
         evidence_.record_root != evidence_.end_frame_identity &&
         evidence_.record_count >= 8 && evidence_.payload_bytes > 0 &&
         evidence_.raw_wire_bytes > evidence_.payload_bytes &&
         evidence_.authenticated_child_pid > 1 &&
         evidence_.authenticated_child_pid == evidence_.waited_child_pid &&
         evidence_.explicit_owner_mapping_export_count == 0 &&
         evidence_.owner_mapping_present !=
             evidence_.owner_mapping_absent &&
         evidence_.owner_mapping_present ==
             (receipt_.producer_binding.classification ==
              Classification::TransparentBaseline) &&
         evidence_.grouping_source_complete &&
         evidence_.explicit_owner_mapping_export_source_complete &&
         evidence_.public_continuity_modeled_separately &&
         evidence_.end_written && evidence_.writer_closed &&
         evidence_.expected_eof_identity == terminal_eof_identity(
             receipt_.native.ordinal, evidence_.record_count,
             evidence_.payload_bytes, evidence_.raw_wire_bytes,
             evidence_.record_root, evidence_.end_frame_identity) &&
         evidence_.private_completion_identity ==
             private_lifecycle_identity(
                 receipt_, evidence_.capture_binding,
                 evidence_.structural_projection.
                     structural_projection_identity,
                 evidence_.record_root, evidence_.end_frame_identity,
                 evidence_.expected_eof_identity,
                 evidence_.retained_projection_identity,
                 evidence_.projection_fork_binding_identity,
                 evidence_.projection_intake_identity,
                 evidence_.terminal_mapping_source_identity,
                 evidence_.record_count,
                 evidence_.payload_bytes, evidence_.raw_wire_bytes,
                 evidence_.authenticated_child_pid,
                 evidence_.waited_child_pid,
                 evidence_.explicit_owner_mapping_export_count,
                 evidence_.owner_mapping_present,
                 evidence_.owner_mapping_absent,
                 evidence_.grouping_source_complete,
                 evidence_.explicit_owner_mapping_export_source_complete,
                 evidence_.public_continuity_modeled_separately,
                 evidence_.end_written,
                 evidence_.writer_closed));
}

PaymentLifecycleCompletionAuthority::PaymentLifecycleCompletionAuthority(
        PaymentLifecycleCompletionAuthority&& other) noexcept
    : receipt_(other.receipt_), evidence_(other.evidence_),
      live_(other.live_.exchange(false)) {}

namespace {

PublicNativeCandidateCompletion native_receipt(
        const NativeTerminalSelection& selection,
        const PublicGenesisTerminalOffer& offer,
        const Digest& child_process, const Digest& child_exit) {
    PublicNativeCandidateCompletion receipt{
        .network = selection.network,
        .kind = selection.kind,
        .ordinal = selection.ordinal,
        .trial = selection.trial,
        .funding_identity = selection.funding_identity,
        .component_profile = selection.component_profile,
        .immutable_tail = selection.immutable_tail,
        .input_head = selection.accepted_input_head,
        .successor_head = selection.successor_head,
        .projection = selection.projection,
        .core = selection.core,
        .proof = selection.proof,
        .signed_case_completion = selection.signed_case_completion,
        .native_full_completion = selection.native_full_completion,
        .r0_completion = selection.r0_completion,
        .value_conservation_completion =
            selection.value_conservation_completion,
        .worker = selection.worker,
        .outer_parent_process = selection.outer_parent_process,
        .outer_parent_executable = selection.outer_parent_executable,
        .transport_session = offer.transport_session,
        .offer_identity = offer.offer_identity,
        .child_process_identity = child_process,
        .child_exit_identity = child_exit,
        .input_value_sompi = selection.input_value_sompi,
        .successor_value_sompi = selection.successor_value_sompi,
        .fee_sompi = selection.fee_sompi,
        .credentials_verified = true,
        .offer_acknowledged = true,
        .clean_exit = true,
    };
    receipt.completion_identity =
        testnet_activation::recompute_native_candidate_completion_identity(
            receipt);
    return receipt;
}

} // namespace

NativeCandidateCompletionAuthority
NativeTerminalSupervisor::run_genesis_with_fault(
        const NativeTerminalSelection& selection, int executable_fd,
        TestNativeTerminalFault fault) {
    const auto observed = supervise_genesis(selection, executable_fd, fault);
    auto receipt = native_receipt(
        selection, observed.offer, observed.child_process,
        observed.child_exit);
    return NativeCandidateCompletionAuthority(
        std::move(receipt), observed.authenticated_pid,
        observed.waited_pid, observed.control_closed);
}

PaymentLifecycleCompletionAuthority
NativeTerminalSupervisor::run_payment_with_projection(
        const PaymentTerminalSelection& selection, int executable_fd,
        int terminal_writer_fd,
        NativeTerminalChildProjectionEvidence&& projection,
        TestNativeTerminalFault fault) {
    Fd terminal_writer(terminal_writer_fd);
    const auto structural_projection =
        PaymentLifecycleCompletionAuthority::parse_structural_projection(
            projection.projection);
    need(structural_projection.projection_identity ==
         selection.native.projection);
    ProjectionOfferEvidence offered{
        .projection = projection.projection,
        .projection_identity = projection.projection_identity,
        .retained_identity = projection.retained_identity,
        .fork_binding_identity = projection.fork_binding_identity,
        .intake_identity = projection.intake_identity,
        .owner_mapping_authority_identity =
            projection.owner_mapping_authority_identity,
        .owner_nullifiers = projection.owner_nullifiers,
        .owner_tuple_hashes = projection.owner_tuple_hashes,
        .round = projection.round,
        .classification = projection.classification,
        .owner_mapping_present = projection.owner_mapping_present,
    };
    const auto observed = supervise_payment(
        selection, executable_fd, terminal_writer, offered, fault);
    PublicPaymentLifecycleCompletion receipt{
        .native = selection.native,
        .producer_binding = selection.producer_binding,
        .stream_process_identity =
            recompute_terminal_stream_process_identity(selection),
        .stream_child_exit_identity =
            recompute_terminal_stream_child_exit_identity(selection),
        .transport_session = observed.offer.transport_session,
        .offer_identity = observed.offer.offer_identity,
        .child_process_observation = observed.child_process,
        .child_exit_observation = observed.child_exit,
        .opaque_lifecycle_authority_identity = random_digest(),
        .credentials_verified = true,
        .offer_acknowledged = true,
        .child_control_closed = observed.control_closed,
        .clean_exit = true,
    };
    PaymentLifecycleCompletionAuthority::PrivateTerminalStreamEvidence
        evidence{
            .capture_binding = selection.capture_binding,
            .structural_projection = structural_projection,
            .record_root = observed.packet.record_root,
            .end_frame_identity = observed.packet.end_frame,
            .expected_eof_identity = terminal_eof_identity(
                selection.native.ordinal, observed.packet.record_count,
                observed.packet.payload_bytes,
                observed.packet.raw_wire_bytes,
                observed.packet.record_root, observed.packet.end_frame),
            .retained_projection_identity = observed.retained_projection,
            .projection_fork_binding_identity =
                observed.projection_fork_binding,
            .projection_intake_identity = observed.projection_intake,
            .terminal_mapping_source_identity =
                unhex(observed.packet.mapping_source_identity),
            .record_count = observed.packet.record_count,
            .payload_bytes = observed.packet.payload_bytes,
            .raw_wire_bytes = observed.packet.raw_wire_bytes,
            .authenticated_child_pid = observed.authenticated_pid,
            .waited_child_pid = observed.waited_pid,
            .explicit_owner_mapping_export_count =
                observed.packet.explicit_owner_mapping_export_count,
            .owner_mapping_present =
                observed.packet.owner_mapping_present,
            .owner_mapping_absent =
                !observed.packet.owner_mapping_present,
            .grouping_source_complete =
                observed.packet.grouping_source_complete,
            .explicit_owner_mapping_export_source_complete =
                observed.packet.
                    explicit_owner_mapping_export_source_complete,
            .public_continuity_modeled_separately =
                observed.packet.public_continuity_modeled_separately,
            .end_written = observed.packet.end_written,
            .writer_closed = observed.packet.writer_closed,
        };
    evidence.private_completion_identity = private_lifecycle_identity(
        receipt, evidence.capture_binding,
        evidence.structural_projection.structural_projection_identity,
        evidence.record_root,
        evidence.end_frame_identity, evidence.expected_eof_identity,
        evidence.retained_projection_identity,
        evidence.projection_fork_binding_identity,
        evidence.projection_intake_identity,
        evidence.terminal_mapping_source_identity,
        evidence.record_count, evidence.payload_bytes,
        evidence.raw_wire_bytes, evidence.authenticated_child_pid,
        evidence.waited_child_pid,
        evidence.explicit_owner_mapping_export_count,
        evidence.owner_mapping_present, evidence.owner_mapping_absent,
        evidence.grouping_source_complete,
        evidence.explicit_owner_mapping_export_source_complete,
        evidence.public_continuity_modeled_separately,
        evidence.end_written,
        evidence.writer_closed);
    return PaymentLifecycleCompletionAuthority(
        std::move(receipt), std::move(evidence));
}

PaymentLifecycleCompletionAuthority
NativeTerminalSupervisor::run_payment_with_fault(
        const PaymentTerminalSelection& selection, int executable_fd,
        int terminal_writer_fd,
        kpi::mpc::financial::registered_driver::projection_route::
            NativeTerminalRetainedProjectionAuthority&& retained,
        TestNativeTerminalFault fault) {
    Fd terminal_writer(terminal_writer_fd);
    auto projection = NativeTerminalProjectionIntake::consume_candidate(
        std::move(retained), selection);
    return run_payment_with_projection(
        selection, executable_fd, terminal_writer.release(),
        std::move(projection), fault);
}

NativeCandidateCompletionAuthority NativeTerminalSupervisor::run_genesis(
        const NativeTerminalSelection& selection, int executable_fd) {
    return run_genesis_with_fault(
        selection, executable_fd, TestNativeTerminalFault::None);
}
PaymentLifecycleCompletionAuthority NativeTerminalSupervisor::run_payment(
        const PaymentTerminalSelection& selection, int executable_fd,
        int terminal_writer_fd,
        kpi::mpc::financial::registered_driver::projection_route::
            NativeTerminalRetainedProjectionAuthority&& retained) {
    return run_payment_with_fault(
        selection, executable_fd, terminal_writer_fd, std::move(retained),
        TestNativeTerminalFault::None);
}

PaymentLifecycleCompletionAuthority NativeTerminalSupervisor::run_payment(
        const PaymentTerminalSelection& selection, int executable_fd,
        int terminal_writer_fd,
        kpi::mpc::financial::registered_driver::projection_route::
            NativeTerminalRetainedProjectionAuthority&& retained,
        kpi::mpc::financial::registered_driver::baseline_disclosure::
            BaselineTerminalOwnerMappingAuthority&& mapping) {
    Fd terminal_writer(terminal_writer_fd);
    auto projection = NativeTerminalProjectionIntake::consume_baseline(
        std::move(retained), std::move(mapping), selection);
    return run_payment_with_projection(
        selection, executable_fd, terminal_writer.release(),
        std::move(projection), TestNativeTerminalFault::None);
}

#ifdef KPB_NATIVE_TERMINAL_COMPLETION_TEST_SETUP
NativeCandidateCompletionAuthority
NativeTerminalSupervisor::test_only_run_genesis(
        const NativeTerminalSelection& selection, int executable_fd,
        TestNativeTerminalFault fault) {
    return run_genesis_with_fault(selection, executable_fd, fault);
}
PaymentLifecycleCompletionAuthority
NativeTerminalSupervisor::test_only_run_payment(
        const PaymentTerminalSelection& selection, int executable_fd,
        int terminal_writer_fd,
        kpi::mpc::financial::registered_driver::projection_route::
            NativeTerminalRetainedProjectionAuthority&& retained,
        TestNativeTerminalFault fault) {
    return run_payment_with_fault(
        selection, executable_fd, terminal_writer_fd,
        std::move(retained), fault);
}
#endif

MatchedNativeTerminalProducerBundle::MatchedNativeTerminalProducerBundle(
        measurement::ProducerClosureAuthority&& producer,
        PaymentLifecycleCompletionAuthority&& round1,
        PaymentLifecycleCompletionAuthority&& round2)
    : producer_(std::in_place, std::move(producer)),
      lifecycle_{
          std::optional<PaymentLifecycleCompletionAuthority>(
              std::in_place, std::move(round1)),
          std::optional<PaymentLifecycleCompletionAuthority>(
              std::in_place, std::move(round2)),
      } {}

MatchedNativeTerminalProducerBundle::MatchedNativeTerminalProducerBundle(
        MatchedNativeTerminalProducerBundle&& other) noexcept
    : producer_(std::move(other.producer_)),
      lifecycle_(std::move(other.lifecycle_)),
      live_(other.live_.exchange(false)) {}

Digest StructuralProjectionContinuityAuthority::recompute_identity(
        const PrivateEvidence& value) {
    Bytes bytes;
    text(bytes, "KPB_STRUCTURAL_PROJECTION_CONTINUITY_AUTHORITY_V1\n");
    run_binding_bytes(bytes, value.binding);
    bytes.push_back(static_cast<unsigned char>(value.classification));
    for (const auto& round : value.rounds) {
        for (const auto* field : {
                 &round.projection, &round.accepted_input_head,
                 &round.successor_head, &round.retained_projection,
                 &round.fork_binding, &round.intake,
                 &round.mapping_source, &round.stream_process,
                 &round.stream_child_exit, &round.child_process,
                 &round.child_exit, &round.producer_stream_process,
                 &round.producer_stream_child_exit,
                 &round.private_completion,
                 &round.structural.structural_projection_identity})
            add(bytes, *field);
    }
    bytes.push_back(value.structural_projection_continuity ? 1 : 0);
    bytes.push_back(value.accepted_chain_continuity ? 1 : 0);
    return hash(bytes);
}

StructuralProjectionContinuityAuthority::
StructuralProjectionContinuityAuthority(PrivateEvidence evidence)
    : evidence_(std::move(evidence)) {
    validate();
}

StructuralProjectionContinuityAuthority::
StructuralProjectionContinuityAuthority(
        StructuralProjectionContinuityAuthority&& other) noexcept
    : evidence_(std::move(other.evidence_)),
      live_(other.live_.exchange(false)) {}

void StructuralProjectionContinuityAuthority::validate() const {
    validate_state(true);
}

void StructuralProjectionContinuityAuthority::validate_consumed() const {
    validate_state(false);
}

void StructuralProjectionContinuityAuthority::validate_state(
        bool authority_live) const {
    need(live_.load() == authority_live &&
         (evidence_.classification == Classification::HiddenCandidate ||
          evidence_.classification == Classification::TransparentBaseline) &&
         evidence_.binding.classification == evidence_.classification &&
         evidence_.structural_projection_continuity &&
         !evidence_.accepted_chain_continuity &&
         nonzero(evidence_.continuity_identity) &&
         evidence_.continuity_identity == recompute_identity(evidence_));
    for (unsigned index = 0; index < 2; ++index) {
        const auto& round = evidence_.rounds[index];
        PaymentLifecycleCompletionAuthority::
            validate_structural_projection(round.structural);
        for (const auto* field : {
                 &round.projection, &round.accepted_input_head,
                 &round.successor_head, &round.retained_projection,
                 &round.fork_binding, &round.intake,
                 &round.mapping_source, &round.stream_process,
                 &round.stream_child_exit, &round.child_process,
                 &round.child_exit, &round.producer_stream_process,
                 &round.producer_stream_child_exit,
                 &round.private_completion})
            need(nonzero(*field));
        need(round.projection == evidence_.binding.projections[index] &&
             round.projection == round.structural.projection_identity &&
             round.accepted_input_head != round.successor_head &&
             round.stream_process == round.producer_stream_process &&
             round.stream_child_exit ==
                 round.producer_stream_child_exit);
    }
    const auto& first = evidence_.rounds[0].structural;
    const auto& second = evidence_.rounds[1].structural;
    need(first.profile_context_identity ==
             second.profile_context_identity &&
         first.new_cm_root == second.old_cm_root &&
         first.new_nf_root == second.old_nf_root &&
         first.new_cm_count == second.old_cm_count &&
         first.new_nf_count == second.old_nf_count &&
         first.new_reserve_sompi == second.old_reserve_sompi &&
         first.successor_state_identity == second.old_state_identity &&
         first.successor_script_identity == second.old_script_identity &&
         first.structural_successor_context_identity ==
             second.structural_old_context_identity &&
         evidence_.rounds[0].successor_head ==
             evidence_.rounds[1].accepted_input_head &&
         evidence_.rounds[0].projection !=
             evidence_.rounds[1].projection &&
         evidence_.rounds[0].retained_projection !=
             evidence_.rounds[1].retained_projection &&
         evidence_.rounds[0].fork_binding !=
             evidence_.rounds[1].fork_binding &&
         evidence_.rounds[0].intake != evidence_.rounds[1].intake &&
         evidence_.rounds[0].mapping_source !=
             evidence_.rounds[1].mapping_source &&
         evidence_.rounds[0].stream_process !=
             evidence_.rounds[1].stream_process &&
         evidence_.rounds[0].stream_child_exit !=
             evidence_.rounds[1].stream_child_exit &&
         evidence_.rounds[0].child_process !=
             evidence_.rounds[1].child_process &&
         evidence_.rounds[0].child_exit !=
             evidence_.rounds[1].child_exit &&
         evidence_.rounds[0].private_completion !=
             evidence_.rounds[1].private_completion);
}

TerminalV2ModelAdmissionAuthority::TerminalV2ModelAdmissionAuthority(
        measurement::ProducerClosureAuthority&& producer,
        PaymentLifecycleCompletionAuthority&& round1,
        PaymentLifecycleCompletionAuthority&& round2,
        StructuralProjectionContinuityAuthority&& structural_continuity,
        honest_owner_material::HonestOwnerTwoRoundProductionAuthority&&
            honest_owner_production,
        PrivateEvidence evidence)
    : producer_(std::in_place, std::move(producer)),
      lifecycle_{
          std::optional<PaymentLifecycleCompletionAuthority>(
              std::in_place, std::move(round1)),
          std::optional<PaymentLifecycleCompletionAuthority>(
              std::in_place, std::move(round2)),
      },
      structural_continuity_(
          std::make_unique<StructuralProjectionContinuityAuthority>(
              std::move(structural_continuity))),
      honest_owner_production_(
          std::in_place, std::move(honest_owner_production)),
      evidence_(std::move(evidence)) {
    validate_for_model_join();
}

TerminalV2ModelAdmissionAuthority::TerminalV2ModelAdmissionAuthority(
        TerminalV2ModelAdmissionAuthority&& other) noexcept
    : producer_(std::move(other.producer_)),
      lifecycle_(std::move(other.lifecycle_)),
      structural_continuity_(std::move(other.structural_continuity_)),
      honest_owner_production_(std::move(other.honest_owner_production_)),
      evidence_(std::move(other.evidence_)),
      live_(other.live_.exchange(false)) {}

TerminalV2ModelAdmissionAuthority::~TerminalV2ModelAdmissionAuthority() =
    default;

void TerminalV2ModelAdmissionAuthority::validate_for_model_join() const {
    validate_model_state(true, true);
}

void TerminalV2ModelAdmissionAuthority::
validate_consumed_for_observer_join() const {
    validate_model_state(false, false);
}

void TerminalV2ModelAdmissionAuthority::validate_model_state(
        bool authority_live, bool continuity_live) const {
    need(live_.load() == authority_live && producer_.has_value() &&
         lifecycle_[0].has_value() && lifecycle_[1].has_value() &&
         structural_continuity_ != nullptr &&
         honest_owner_production_.has_value());
    honest_owner_production_->validate_retained();
    if (continuity_live)
        structural_continuity_->validate();
    else
        structural_continuity_->validate_consumed();
    const auto& producer = producer_->public_receipt();
    need(producer.binding == evidence_.binding &&
         producer.binding.classification == evidence_.classification &&
         nonzero(evidence_.producer_closure_authority_identity) &&
         producer.opaque_closure_authority_identity ==
             evidence_.producer_closure_authority_identity &&
         producer.stream_count == 10 && producer.closed_root_count == 10 &&
         producer.unknown_record_count == 0);

    constexpr std::array<unsigned, 2> stream_indexes{1, 6};
    for (unsigned index = 0; index < 2; ++index) {
        const auto& lifecycle = *lifecycle_[index];
        const auto& round = evidence_.rounds[index];
        lifecycle.validate_for_native_terminal_join();
        need(lifecycle.live_.load() &&
             lifecycle.receipt_ == round.lifecycle &&
             same_capture_binding(
                 lifecycle.evidence_.capture_binding,
                 round.capture_binding) &&
             lifecycle.evidence_.structural_projection ==
                 round.structural_projection &&
             producer.streams[stream_indexes[index]] ==
                 round.producer_stream &&
             round.lifecycle.producer_binding == evidence_.binding &&
             round.lifecycle.native.ordinal == index + 1 &&
             round.lifecycle.native.kind ==
                 (index == 0 ? NativeCandidateKind::PaymentRound1
                             : NativeCandidateKind::PaymentRound2) &&
             round.lifecycle.native.trial == evidence_.binding.trial &&
             round.lifecycle.native.projection ==
                 evidence_.binding.projections[index] &&
             round.producer_stream.round == index + 1 &&
             round.producer_stream.kind ==
                 measurement::CaptureKind::TerminalHistory &&
             round.producer_stream.fixed_fd == (index == 0 ? 21U : 26U) &&
             round.producer_stream.process_identity ==
                 round.lifecycle.stream_process_identity &&
             round.producer_stream.child_exit_identity ==
                 round.lifecycle.stream_child_exit_identity &&
             round.producer_stream.root_closed &&
             round.producer_stream.end_observed &&
             round.producer_stream.eof_observed &&
             lifecycle.evidence_.record_root == round.record_root &&
             lifecycle.evidence_.end_frame_identity ==
                 round.end_frame_identity &&
             lifecycle.evidence_.expected_eof_identity ==
                 round.expected_eof_identity &&
             lifecycle.evidence_.retained_projection_identity ==
                 round.retained_projection_identity &&
             lifecycle.evidence_.projection_fork_binding_identity ==
                 round.projection_fork_binding_identity &&
             lifecycle.evidence_.projection_intake_identity ==
                 round.projection_intake_identity &&
             lifecycle.evidence_.terminal_mapping_source_identity ==
                 round.terminal_mapping_source_identity &&
             lifecycle.evidence_.private_completion_identity ==
                 round.private_completion_identity &&
             lifecycle.evidence_.record_count == round.record_count &&
             lifecycle.evidence_.payload_bytes == round.payload_bytes &&
             lifecycle.evidence_.raw_wire_bytes == round.raw_wire_bytes &&
             lifecycle.evidence_.authenticated_child_pid ==
                 round.authenticated_child_pid &&
             lifecycle.evidence_.waited_child_pid ==
                 round.waited_child_pid &&
             lifecycle.evidence_.explicit_owner_mapping_export_count ==
                 round.explicit_owner_mapping_export_count &&
             lifecycle.evidence_.owner_mapping_present ==
                 round.owner_mapping_present &&
             lifecycle.evidence_.owner_mapping_absent ==
                 round.owner_mapping_absent &&
             lifecycle.evidence_.grouping_source_complete ==
                 round.grouping_source_complete &&
             lifecycle.evidence_.
                     explicit_owner_mapping_export_source_complete ==
                 round.explicit_owner_mapping_export_source_complete &&
             lifecycle.evidence_.public_continuity_modeled_separately ==
                 round.public_continuity_modeled_separately &&
             lifecycle.evidence_.end_written == round.end_written &&
             lifecycle.evidence_.writer_closed == round.writer_closed &&
             nonzero(round.record_root) &&
             nonzero(round.end_frame_identity) &&
             nonzero(round.expected_eof_identity) &&
             nonzero(round.terminal_mapping_source_identity) &&
             round.explicit_owner_mapping_export_count == 0 &&
             round.owner_mapping_present != round.owner_mapping_absent &&
             round.owner_mapping_present ==
                 (evidence_.classification ==
                  measurement::Classification::TransparentBaseline) &&
             round.grouping_source_complete &&
             round.explicit_owner_mapping_export_source_complete &&
             round.public_continuity_modeled_separately &&
             round.end_written && round.writer_closed);
    }
    need(evidence_.rounds[0].terminal_mapping_source_identity !=
             evidence_.rounds[1].terminal_mapping_source_identity &&
         evidence_.rounds[0].record_root !=
             evidence_.rounds[1].record_root &&
         evidence_.rounds[0].lifecycle.native.successor_head ==
             evidence_.rounds[1].lifecycle.native.accepted_input_head);
}

TerminalV2ModelAdmissionAuthority
MatchedNativeTerminalProducerBundle::transfer_for_terminal_v2_model(
        honest_owner_material::HonestOwnerTwoRoundProductionAuthority&&
            honest_owner_production) && {
    honest_owner_material::HonestOwnerTwoRoundProductionAuthority
        claimed_honest_owner(std::move(honest_owner_production));
    need(live_.exchange(false) && producer_.has_value() &&
         lifecycle_[0].has_value() && lifecycle_[1].has_value());
    const auto& producer_receipt = producer_->public_receipt();
    TerminalV2ModelAdmissionAuthority::PrivateEvidence evidence{
        .binding = producer_receipt.binding,
        .classification = producer_receipt.binding.classification,
        .producer_closure_authority_identity =
            producer_receipt.opaque_closure_authority_identity,
    };
    constexpr std::array<unsigned, 2> stream_indexes{1, 6};
    for (unsigned index = 0; index < 2; ++index) {
        auto& lifecycle = *lifecycle_[index];
        lifecycle.validate_for_native_terminal_join();
        const auto& private_stream = lifecycle.evidence_;
        evidence.rounds[index] = TerminalV2ModelAdmissionAuthority::
            RoundEvidence{
                .lifecycle = lifecycle.receipt_,
                .capture_binding = private_stream.capture_binding,
                .structural_projection =
                    private_stream.structural_projection,
                .producer_stream =
                    producer_receipt.streams[stream_indexes[index]],
                .record_root = private_stream.record_root,
                .end_frame_identity = private_stream.end_frame_identity,
                .expected_eof_identity = private_stream.expected_eof_identity,
                .retained_projection_identity =
                    private_stream.retained_projection_identity,
                .projection_fork_binding_identity =
                    private_stream.projection_fork_binding_identity,
                .projection_intake_identity =
                    private_stream.projection_intake_identity,
                .terminal_mapping_source_identity =
                    private_stream.terminal_mapping_source_identity,
                .private_completion_identity =
                    private_stream.private_completion_identity,
                .record_count = private_stream.record_count,
                .payload_bytes = private_stream.payload_bytes,
                .raw_wire_bytes = private_stream.raw_wire_bytes,
                .authenticated_child_pid =
                    private_stream.authenticated_child_pid,
                .waited_child_pid = private_stream.waited_child_pid,
                .explicit_owner_mapping_export_count =
                    private_stream.explicit_owner_mapping_export_count,
                .owner_mapping_present =
                    private_stream.owner_mapping_present,
                .owner_mapping_absent =
                    private_stream.owner_mapping_absent,
                .grouping_source_complete =
                    private_stream.grouping_source_complete,
                .explicit_owner_mapping_export_source_complete =
                    private_stream.
                        explicit_owner_mapping_export_source_complete,
                .public_continuity_modeled_separately =
                    private_stream.public_continuity_modeled_separately,
                .end_written = private_stream.end_written,
                .writer_closed = private_stream.writer_closed,
            };
    }
    std::array<std::array<Digest, 3>, 2> public_nullifiers{};
    std::array<std::array<honest_owner_material::Output520, 6>, 2>
        public_outputs{};
    for (unsigned index = 0; index < 2; ++index) {
        public_nullifiers[index] =
            evidence.rounds[index].structural_projection.public_nullifiers;
        public_outputs[index] =
            evidence.rounds[index].structural_projection.public_outputs;
    }
    claimed_honest_owner.validate_for_terminal(
        producer_receipt.binding, producer_receipt.binding.classification,
        public_nullifiers, public_outputs);
    StructuralProjectionContinuityAuthority::PrivateEvidence continuity{
        .binding = producer_receipt.binding,
        .classification = producer_receipt.binding.classification,
        .structural_projection_continuity = true,
        .accepted_chain_continuity = false,
    };
    for (unsigned index = 0; index < 2; ++index) {
        const auto& round = evidence.rounds[index];
        continuity.rounds[index] =
            StructuralProjectionContinuityAuthority::RoundLineage{
                .projection = round.lifecycle.native.projection,
                .accepted_input_head =
                    round.lifecycle.native.accepted_input_head,
                .successor_head = round.lifecycle.native.successor_head,
                .retained_projection =
                    round.retained_projection_identity,
                .fork_binding =
                    round.projection_fork_binding_identity,
                .intake = round.projection_intake_identity,
                .mapping_source =
                    round.terminal_mapping_source_identity,
                .stream_process =
                    round.lifecycle.stream_process_identity,
                .stream_child_exit =
                    round.lifecycle.stream_child_exit_identity,
                .child_process =
                    round.lifecycle.child_process_observation,
                .child_exit = round.lifecycle.child_exit_observation,
                .producer_stream_process =
                    round.producer_stream.process_identity,
                .producer_stream_child_exit =
                    round.producer_stream.child_exit_identity,
                .private_completion = round.private_completion_identity,
                .structural = round.structural_projection,
            };
    }
    continuity.continuity_identity =
        StructuralProjectionContinuityAuthority::recompute_identity(
            continuity);
    StructuralProjectionContinuityAuthority structural_continuity(
        std::move(continuity));
    return TerminalV2ModelAdmissionAuthority(
        std::move(*producer_), std::move(*lifecycle_[0]),
        std::move(*lifecycle_[1]), std::move(structural_continuity),
        std::move(claimed_honest_owner),
        std::move(evidence));
}

NativeTerminalProducerBundle::NativeTerminalProducerBundle(
        measurement::ProducerClosureAuthority&& producer,
        std::array<NativeCandidateCompletionAuthority, 2>&& native)
    : producer_(std::in_place, std::move(producer)),
      native_{
          std::optional<NativeCandidateCompletionAuthority>(
              std::in_place, std::move(native[0])),
          std::optional<NativeCandidateCompletionAuthority>(
              std::in_place, std::move(native[1])),
      } {}

NativeTerminalProducerBundle::NativeTerminalProducerBundle(
        NativeTerminalProducerBundle&& other) noexcept
    : producer_(std::move(other.producer_)),
      native_(std::move(other.native_)),
      producer_live_(other.producer_live_.exchange(false)),
      native_live_(other.native_live_.exchange(false)) {}

measurement::ProducerClosureAuthority
NativeTerminalProducerBundle::take_producer() {
    need(producer_live_.exchange(false) && producer_.has_value());
    return std::move(*producer_);
}

std::array<NativeCandidateCompletionAuthority, 2>
NativeTerminalProducerBundle::take_native() {
    need(native_live_.exchange(false) && native_[0].has_value() &&
         native_[1].has_value());
    return {std::move(*native_[0]), std::move(*native_[1])};
}

namespace {

PublicNativeCandidateCompletion payment_native_receipt(
        const PublicPaymentLifecycleCompletion& lifecycle) {
    const auto& selection = lifecycle.native;
    PublicNativeCandidateCompletion receipt{
        .network = selection.network,
        .kind = selection.kind,
        .ordinal = selection.ordinal,
        .trial = selection.trial,
        .funding_identity = selection.funding_identity,
        .component_profile = selection.component_profile,
        .immutable_tail = selection.immutable_tail,
        .input_head = selection.accepted_input_head,
        .successor_head = selection.successor_head,
        .projection = selection.projection,
        .core = selection.core,
        .proof = selection.proof,
        .signed_case_completion = selection.signed_case_completion,
        .native_full_completion = selection.native_full_completion,
        .r0_completion = selection.r0_completion,
        .value_conservation_completion =
            selection.value_conservation_completion,
        .worker = selection.worker,
        .outer_parent_process = selection.outer_parent_process,
        .outer_parent_executable = selection.outer_parent_executable,
        .transport_session = lifecycle.transport_session,
        .offer_identity = lifecycle.offer_identity,
        .child_process_identity = lifecycle.child_process_observation,
        .child_exit_identity = lifecycle.child_exit_observation,
        .input_value_sompi = selection.input_value_sompi,
        .successor_value_sompi = selection.successor_value_sompi,
        .fee_sompi = selection.fee_sompi,
        .credentials_verified = lifecycle.credentials_verified,
        .offer_acknowledged = lifecycle.offer_acknowledged,
        .clean_exit = lifecycle.clean_exit,
    };
    receipt.completion_identity =
        testnet_activation::recompute_native_candidate_completion_identity(
            receipt);
    return receipt;
}

} // namespace

NativeTerminalProducerBundle NativeTerminalProducerJoin::mint_from_matched(
        MatchedNativeTerminalProducerBundle&& matched) {
    need(matched.live_.exchange(false) && matched.producer_.has_value() &&
         matched.lifecycle_[0].has_value() &&
         matched.lifecycle_[1].has_value());
    auto& round1 = *matched.lifecycle_[0];
    auto& round2 = *matched.lifecycle_[1];
    const bool round1_live = round1.live_.exchange(false);
    const bool round2_live = round2.live_.exchange(false);
    need(round1_live && round2_live);
    round1.validate_for_native_terminal_join();
    round2.validate_for_native_terminal_join();
    const auto& first = round1.receipt_;
    const auto& second = round2.receipt_;
    need(first.native.kind == NativeCandidateKind::PaymentRound1 &&
         first.native.ordinal == 1 &&
         second.native.kind == NativeCandidateKind::PaymentRound2 &&
         second.native.ordinal == 2 &&
         first.producer_binding == second.producer_binding &&
         first.native.trial == second.native.trial &&
         first.native.funding_identity == second.native.funding_identity &&
         first.native.component_profile ==
             second.native.component_profile &&
         first.native.immutable_tail == second.native.immutable_tail &&
         first.native.outer_parent_process ==
             second.native.outer_parent_process &&
         first.native.outer_parent_executable ==
             second.native.outer_parent_executable &&
         first.native.successor_head == second.native.accepted_input_head &&
         first.native.successor_value_sompi ==
             second.native.input_value_sompi &&
         first.stream_process_identity != second.stream_process_identity &&
         first.stream_child_exit_identity !=
             second.stream_child_exit_identity &&
         first.opaque_lifecycle_authority_identity !=
             second.opaque_lifecycle_authority_identity);
    auto first_receipt = payment_native_receipt(first);
    auto second_receipt = payment_native_receipt(second);
    std::array<NativeCandidateCompletionAuthority, 2> native{
        NativeCandidateCompletionAuthority(
            std::move(first_receipt),
            round1.evidence_.authenticated_child_pid,
            round1.evidence_.waited_child_pid,
            first.child_control_closed),
        NativeCandidateCompletionAuthority(
            std::move(second_receipt),
            round2.evidence_.authenticated_child_pid,
            round2.evidence_.waited_child_pid,
            second.child_control_closed),
    };
    return NativeTerminalProducerBundle(
        std::move(*matched.producer_), std::move(native));
}

} // namespace kpb::native_terminal
