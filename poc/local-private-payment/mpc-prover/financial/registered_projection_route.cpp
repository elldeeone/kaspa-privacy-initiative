#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "registered_projection_route.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <openssl/sha.h>
#include <poll.h>
#include <stdexcept>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::registered_driver::projection_route {
namespace {

using Bytes = std::vector<unsigned char>;
constexpr std::array<unsigned char, 8> OFFER_MAGIC{
    'K', 'P', 'B', 'P', 'R', 'T', '0', '1'};
constexpr std::array<unsigned char, 8> ACK_MAGIC{
    'K', 'P', 'B', 'R', 'A', 'K', '0', '1'};
constexpr std::size_t OFFER_BYTES = 400;
constexpr std::size_t ACK_BYTES = 136;

[[noreturn]] void refuse() {
    throw std::runtime_error("registered-projection-route-refused");
}
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) { return value != Digest{}; }

void close_noexcept(int& fd) noexcept {
    if (fd >= 0) {
        const int selected = std::exchange(fd, -1);
        (void)::close(selected);
    }
}

struct DescriptorFingerprint {
    std::uint64_t device{};
    std::uint64_t inode{};
    std::uint32_t file_type{};
};

DescriptorFingerprint fingerprint(int fd) {
    need(fd >= 0);
    struct stat value {};
    int result;
    do { result = ::fstat(fd, &value); }
    while (result < 0 && errno == EINTR);
    need(result == 0);
    return {
        static_cast<std::uint64_t>(value.st_dev),
        static_cast<std::uint64_t>(value.st_ino),
        static_cast<std::uint32_t>(value.st_mode & S_IFMT),
    };
}

bool matches_fingerprint(
        int fd, std::uint64_t device, std::uint64_t inode,
        std::uint32_t file_type) noexcept {
    if (fd < 0 || file_type != S_IFSOCK) return false;
    struct stat value {};
    int result;
    do { result = ::fstat(fd, &value); }
    while (result < 0 && errno == EINTR);
    return result == 0 &&
        static_cast<std::uint64_t>(value.st_dev) == device &&
        static_cast<std::uint64_t>(value.st_ino) == inode &&
        static_cast<std::uint32_t>(value.st_mode & S_IFMT) == file_type;
}

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add(Bytes& out, const Digest& value) { add(out, std::span(value)); }
void add_u64(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}
void add_u32be(Bytes& out, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}
std::uint32_t read_u32be(std::span<const unsigned char> value) {
    need(value.size() == 4);
    std::uint32_t result{};
    for (const auto byte : value) result = (result << 8) | byte;
    return result;
}

Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    need(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}
Digest hash(std::span<const std::byte> value) {
    return hash({reinterpret_cast<const unsigned char*>(value.data()),
                 value.size()});
}

std::uint64_t monotonic_ns() {
    const auto count = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    need(count > 0);
    return static_cast<std::uint64_t>(count);
}

void add_plan(Bytes& out, const PublicProjectionRoutePlan& value) {
    add_u64(out, static_cast<std::uint8_t>(value.classification));
    add_u64(out, value.round);
    add_u64(out, value.computing_role);
    for (const auto* field : {
             &value.trial, &value.attempt, &value.cohort,
             &value.financial_run, &value.capture_plan_identity,
             &value.producer_process_authority,
             &value.producer_exit_authority,
             &value.dispatcher_process_authority,
             &value.dispatcher_exit_authority})
        add(out, *field);
}

void validate(const PublicProjectionRoutePlan& value) {
    need((value.classification == CaptureClassification::HiddenCandidate ||
          value.classification ==
              CaptureClassification::ExplicitOwnerPublicEffectsBaseline) &&
         (value.round == 1 || value.round == 2) &&
         value.computing_role == 0);
    for (const auto* field : {
             &value.trial, &value.attempt, &value.cohort,
             &value.financial_run, &value.capture_plan_identity,
             &value.producer_process_authority,
             &value.producer_exit_authority,
             &value.dispatcher_process_authority,
             &value.dispatcher_exit_authority})
        need(nonzero(*field));
    need(value.producer_process_authority != value.producer_exit_authority &&
         value.dispatcher_process_authority !=
             value.dispatcher_exit_authority &&
         value.producer_process_authority !=
             value.dispatcher_process_authority);
}

bool same_plan(const PublicProjectionRoutePlan& left,
               const PublicProjectionRoutePlan& right) {
    return left.classification == right.classification &&
        left.round == right.round &&
        left.computing_role == right.computing_role &&
        left.trial == right.trial && left.attempt == right.attempt &&
        left.cohort == right.cohort &&
        left.financial_run == right.financial_run &&
        left.capture_plan_identity == right.capture_plan_identity &&
        left.producer_process_authority ==
            right.producer_process_authority &&
        left.producer_exit_authority == right.producer_exit_authority &&
        left.dispatcher_process_authority ==
            right.dispatcher_process_authority &&
        left.dispatcher_exit_authority == right.dispatcher_exit_authority;
}

std::array<unsigned char, 32> fresh_nonce() {
    std::array<unsigned char, 32> result{};
    std::size_t at = 0;
    while (at < result.size()) {
        const auto count = ::getrandom(result.data() + at,
                                       result.size() - at, 0);
        if (count < 0 && errno == EINTR) continue;
        need(count > 0);
        at += static_cast<std::size_t>(count);
    }
    return result;
}

Digest route_identity(const PublicProjectionRoutePlan& plan) {
    Bytes value;
    static constexpr char label[] =
        "KPB_REGISTERED_PUBLIC_PROJECTION_ROUTE_V1\n";
    add(value, {reinterpret_cast<const unsigned char*>(label),
                sizeof(label) - 1});
    add_plan(value, plan);
    const auto nonce = fresh_nonce();
    add(value, nonce);
    return hash(value);
}

Digest fork_binding_identity(
        const PublicProjectionRoutePlan& plan, const Digest& route,
        std::int64_t expected_parent_pid, unsigned role, unsigned round,
        std::int64_t expected_role0_pid, const Digest& fork_plan,
        const Digest& offer_identity, const Digest& ack_identity,
        const Digest& channel_nonce) {
    need(expected_parent_pid > 1 && expected_role0_pid > 1 &&
         expected_parent_pid != expected_role0_pid && role == 0 &&
         round == plan.round && nonzero(route));
    for (const auto* field : {
             &fork_plan, &offer_identity, &ack_identity, &channel_nonce})
        need(nonzero(*field));
    Bytes value;
    static constexpr char label[] =
        "KPB_REGISTERED_PROJECTION_ROUTE_FORK_BINDING_V1\n";
    add(value, {reinterpret_cast<const unsigned char*>(label),
                sizeof(label) - 1});
    add_plan(value, plan);
    add(value, route);
    add_u64(value, static_cast<std::uint64_t>(expected_parent_pid));
    add_u64(value, role);
    add_u64(value, round);
    add_u64(value, static_cast<std::uint64_t>(expected_role0_pid));
    add(value, fork_plan);
    add(value, offer_identity);
    add(value, ack_identity);
    add(value, channel_nonce);
    const auto result = hash(value);
    need(nonzero(result));
    return result;
}

Digest retained_identity(const PublicProjectionRoutePlan& plan,
                         const Digest& route,
                         const Digest& fork_binding,
                         const Digest& projection_identity,
                         std::span<const std::byte> projection) {
    Bytes value;
    static constexpr char label[] =
        "KPB_PARENT_RETAINED_PUBLIC_PROJECTION_V1\n";
    add(value, {reinterpret_cast<const unsigned char*>(label),
                sizeof(label) - 1});
    add_plan(value, plan); add(value, route); add(value, fork_binding);
    add(value, projection_identity);
    add(value, {reinterpret_cast<const unsigned char*>(projection.data()),
                projection.size()});
    return hash(value);
}

Bytes offer(const PublicProjectionRoutePlan& plan, const Digest& route,
            const Digest& fork_binding,
            const Digest& projection_identity) {
    Bytes value;
    add(value, OFFER_MAGIC);
    value.push_back(1);
    value.push_back(static_cast<unsigned char>(plan.classification));
    value.push_back(static_cast<unsigned char>(plan.round));
    value.push_back(0);
    add(value, route);
    add(value, fork_binding);
    for (const auto* field : {
             &plan.trial, &plan.attempt, &plan.cohort,
             &plan.financial_run, &plan.capture_plan_identity,
             &plan.producer_process_authority,
             &plan.producer_exit_authority,
             &plan.dispatcher_process_authority,
             &plan.dispatcher_exit_authority})
        add(value, *field);
    add(value, projection_identity);
    add_u32be(value, PUBLIC_PROJECTION_BYTES);
    need(value.size() == OFFER_BYTES);
    return value;
}

void validate_offer(std::span<const unsigned char> value,
                    const PublicProjectionRoutePlan& plan,
                    const Digest& route,
                    const Digest& fork_binding,
                    const Digest& projection_identity) {
    need(value.size() == OFFER_BYTES &&
         std::equal(OFFER_MAGIC.begin(), OFFER_MAGIC.end(), value.begin()) &&
         value[8] == 1 &&
         value[9] == static_cast<unsigned char>(plan.classification) &&
         value[10] == plan.round && value[11] == 0 &&
         std::equal(route.begin(), route.end(), value.begin() + 12) &&
         std::equal(fork_binding.begin(), fork_binding.end(),
                    value.begin() + 44));
    std::size_t at = 76;
    for (const auto* field : {
             &plan.trial, &plan.attempt, &plan.cohort,
             &plan.financial_run, &plan.capture_plan_identity,
             &plan.producer_process_authority,
             &plan.producer_exit_authority,
             &plan.dispatcher_process_authority,
             &plan.dispatcher_exit_authority}) {
        need(std::equal(field->begin(), field->end(), value.begin() + at));
        at += field->size();
    }
    need(std::equal(projection_identity.begin(), projection_identity.end(),
                    value.begin() + at));
    at += projection_identity.size();
    need(read_u32be(value.subspan(at, 4)) == PUBLIC_PROJECTION_BYTES &&
         at + 4 == value.size());
}

Bytes acknowledgment(const Digest& route, const Digest& fork_binding,
                     const Digest& projection, const Digest& retained) {
    Bytes value;
    add(value, ACK_MAGIC); add(value, route); add(value, fork_binding);
    add(value, projection); add(value, retained);
    need(value.size() == ACK_BYTES); return value;
}

void send_packet(int fd, std::span<const unsigned char> value) {
    ssize_t count;
    do { count = ::send(fd, value.data(), value.size(), MSG_NOSIGNAL); }
    while (count < 0 && errno == EINTR);
    need(count == static_cast<ssize_t>(value.size()));
}
void send_packet(int fd, std::span<const std::byte> value) {
    send_packet(fd, {reinterpret_cast<const unsigned char*>(value.data()),
                     value.size()});
}

struct ReceivedPacket {
    std::size_t bytes{};
    pid_t pid{};
    uid_t uid{};
    gid_t gid{};
    bool eof{};
};

ReceivedPacket receive_packet(int fd, std::span<unsigned char> buffer) {
    struct iovec io{.iov_base = buffer.data(), .iov_len = buffer.size()};
    std::array<unsigned char, CMSG_SPACE(sizeof(struct ucred))> control{};
    struct msghdr message{};
    message.msg_iov = &io; message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t count;
    do { count = ::recvmsg(fd, &message, MSG_CMSG_CLOEXEC); }
    while (count < 0 && errno == EINTR);
    need(count >= 0 && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)));
    struct ucred credentials{};
    bool found = false;
    for (auto* item = CMSG_FIRSTHDR(&message); item != nullptr;
         item = CMSG_NXTHDR(&message, item)) {
        need(!found && item->cmsg_level == SOL_SOCKET &&
             item->cmsg_type == SCM_CREDENTIALS &&
             item->cmsg_len == CMSG_LEN(sizeof(struct ucred)));
        std::memcpy(&credentials, CMSG_DATA(item), sizeof(credentials));
        found = true;
    }
    // With SO_PASSCRED, a peer-sent zero-length record still carries kernel
    // credentials.  It is a message, not orderly EOF, and callers requiring
    // EOF will reject the returned non-EOF zero-byte packet.
    if (count == 0 && !found) {
        struct pollfd state{
            .fd = fd, .events = POLLHUP | POLLRDHUP, .revents = 0};
        int ready;
        do { ready = ::poll(&state, 1, 0); }
        while (ready < 0 && errno == EINTR);
        need(ready == 1 &&
             (state.revents & (POLLHUP | POLLRDHUP)) != 0 &&
             (state.revents & (POLLERR | POLLNVAL)) == 0);
        return {.eof = true};
    }
    need(found && credentials.pid > 0 && credentials.uid == ::geteuid() &&
         credentials.gid == ::getegid());
    return {.bytes = static_cast<std::size_t>(count),
            .pid = credentials.pid, .uid = credentials.uid,
            .gid = credentials.gid, .eof = false};
}

PublicRetainedProjectionReceipt public_receipt(
        const PublicProjectionRoutePlan& plan) {
    return PublicRetainedProjectionReceipt{
        .round = plan.round,
        .trial = plan.trial,
        .attempt = plan.attempt,
        .cohort = plan.cohort,
        .financial_run = plan.financial_run,
        .producer_process_authority = plan.producer_process_authority,
        .producer_exit_authority = plan.producer_exit_authority,
        .dispatcher_process_authority = plan.dispatcher_process_authority,
        .dispatcher_exit_authority = plan.dispatcher_exit_authority,
        .exact_size = true,
        .read_complete = true,
        .kernel_eof = true,
        .clean = true,
    };
}

} // namespace

Digest RegisteredProjectionRouteForkBridge::binding_identity(
        const PublicProjectionRoutePlan& plan, const Digest& route,
        std::int64_t parent_pid, std::int64_t role0_pid,
        const Digest& fork_plan, const Digest& offer_identity,
        const Digest& ack_identity, const Digest& channel_nonce) {
    return fork_binding_identity(
        plan, route, parent_pid, 0, plan.round, role0_pid,
        fork_plan, offer_identity, ack_identity, channel_nonce);
}

ProjectionRoutePlanAuthority::ProjectionRoutePlanAuthority(
        PublicProjectionRoutePlan plan) : plan_(std::move(plan)) {
    validate(plan_);
}
ProjectionRoutePlanAuthority::ProjectionRoutePlanAuthority(
        ProjectionRoutePlanAuthority&& other) noexcept
    : plan_(other.plan_), live_(other.live_.exchange(false)) {}
#ifdef KPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP
ProjectionRoutePlanAuthority ProjectionRoutePlanAuthority::test_only_mint(
        PublicProjectionRoutePlan plan) {
    return ProjectionRoutePlanAuthority(std::move(plan));
}
#endif

ProjectionDeliveryAuthority::ProjectionDeliveryAuthority(
        PublicProjectionRoutePlan plan,
        std::array<std::byte, PUBLIC_PROJECTION_BYTES> projection)
    : plan_(std::move(plan)), projection_(projection),
      projection_identity_(hash(std::span(projection_))) {
    validate(plan_); need(nonzero(projection_identity_));
}
ProjectionDeliveryAuthority::ProjectionDeliveryAuthority(
        ProjectionDeliveryAuthority&& other) noexcept
    : plan_(other.plan_), projection_(other.projection_),
      projection_identity_(other.projection_identity_),
      live_(other.live_.exchange(false)) {}
#ifdef KPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP
ProjectionDeliveryAuthority ProjectionDeliveryAuthority::test_only_mint(
        PublicProjectionRoutePlan plan,
        std::array<std::byte, PUBLIC_PROJECTION_BYTES> projection) {
    return ProjectionDeliveryAuthority(std::move(plan), projection);
}
#endif

ParentProjectionRouteEndpointAuthority::
ParentProjectionRouteEndpointAuthority(
        int fd, PublicProjectionRoutePlan plan, Digest route,
        std::int64_t expected_parent_pid)
    : fd_(fd), plan_(std::move(plan)), route_identity_(route),
      expected_parent_pid_(expected_parent_pid) {}
ParentProjectionRouteEndpointAuthority::
ParentProjectionRouteEndpointAuthority(
        ParentProjectionRouteEndpointAuthority&& other) noexcept
    : fd_(std::exchange(other.fd_, -1)), plan_(other.plan_),
      route_identity_(other.route_identity_),
      expected_parent_pid_(other.expected_parent_pid_),
      expected_role0_pid_(other.expected_role0_pid_),
      fork_binding_identity_(other.fork_binding_identity_),
      live_(other.live_.exchange(false)) {}
ParentProjectionRouteEndpointAuthority::
~ParentProjectionRouteEndpointAuthority() { close_noexcept(fd_); }
void ParentProjectionRouteEndpointAuthority::discard() && {
    need(live_.exchange(false));
    close_noexcept(fd_);
}
#ifdef KPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP
void ParentProjectionRouteEndpointAuthority::test_only_bind_role0_process(
        unsigned role, unsigned round, std::int64_t role0_pid,
        Digest fork_plan, Digest offer_identity, Digest ack_identity,
        Digest channel_nonce) {
    need(live_.load() && expected_role0_pid_ == 0 &&
         expected_parent_pid_ == ::getpid());
    expected_role0_pid_ = role0_pid;
    fork_binding_identity_ = fork_binding_identity(
        plan_, route_identity_, expected_parent_pid_, role, round,
        expected_role0_pid_, fork_plan, offer_identity, ack_identity,
        channel_nonce);
}
#endif

Role0ProjectionRouteWriterAuthority::Role0ProjectionRouteWriterAuthority(
        int fd, int parent_peer_fd, PublicProjectionRoutePlan plan,
        PublicProjectionRouteWriter public_writer, Digest route,
        std::int64_t expected_parent_pid)
    : fd_(fd), parent_peer_fd_(parent_peer_fd), plan_(std::move(plan)),
      public_writer_(std::move(public_writer)), route_identity_(route),
      expected_parent_pid_(expected_parent_pid) {
    need(fd_ >= 0 && parent_peer_fd_ >= 0 && fd_ != parent_peer_fd_);
    const auto selected = fingerprint(parent_peer_fd_);
    need(selected.file_type == S_IFSOCK);
    parent_peer_device_ = selected.device;
    parent_peer_inode_ = selected.inode;
    parent_peer_file_type_ = selected.file_type;
}
Role0ProjectionRouteWriterAuthority::Role0ProjectionRouteWriterAuthority(
        Role0ProjectionRouteWriterAuthority&& other) noexcept
    : fd_(std::exchange(other.fd_, -1)),
      parent_peer_fd_(std::exchange(other.parent_peer_fd_, -1)),
      parent_peer_device_(other.parent_peer_device_),
      parent_peer_inode_(other.parent_peer_inode_),
      parent_peer_file_type_(other.parent_peer_file_type_),
      plan_(other.plan_),
      public_writer_(other.public_writer_),
      route_identity_(other.route_identity_),
      expected_parent_pid_(other.expected_parent_pid_),
      expected_role0_pid_(other.expected_role0_pid_),
      fork_binding_identity_(other.fork_binding_identity_),
      live_(other.live_.exchange(false)) {}
bool Role0ProjectionRouteWriterAuthority::
parent_peer_alias_matches() const noexcept {
    return matches_fingerprint(
        parent_peer_fd_, parent_peer_device_, parent_peer_inode_,
        parent_peer_file_type_);
}
void Role0ProjectionRouteWriterAuthority::
close_inherited_parent_peer_alias() {
    need(live_.load() && parent_peer_alias_matches());
    const int selected = std::exchange(parent_peer_fd_, -1);
    need(::close(selected) == 0);
}
Role0ProjectionRouteWriterAuthority::~Role0ProjectionRouteWriterAuthority() {
    close_noexcept(fd_);
}
void Role0ProjectionRouteWriterAuthority::discard() && {
    need(live_.exchange(false));
    close_noexcept(fd_);
}
#ifdef KPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP
void Role0ProjectionRouteWriterAuthority::test_only_bind_role0_process(
        unsigned role, unsigned round, std::int64_t role0_pid,
        Digest fork_plan, Digest offer_identity, Digest ack_identity,
        Digest channel_nonce) {
    need(live_.load() && expected_role0_pid_ == 0 &&
         role0_pid == ::getpid() && expected_parent_pid_ == ::getppid());
    expected_role0_pid_ = role0_pid;
    fork_binding_identity_ = fork_binding_identity(
        plan_, route_identity_, expected_parent_pid_, role, round,
        expected_role0_pid_, fork_plan, offer_identity, ack_identity,
        channel_nonce);
}
#endif

ProjectionRouteEndpoints::ProjectionRouteEndpoints(
        ParentProjectionRouteEndpointAuthority&& parent,
        Role0ProjectionRouteWriterAuthority&& writer)
    : parent_(std::move(parent)), writer_(std::move(writer)) {}

ParentProjectionRouteEndpointAuthority
ProjectionRouteEndpoints::take_parent() {
    need(!parent_taken_);
    parent_taken_ = true;
    return std::move(parent_);
}
Role0ProjectionRouteWriterAuthority
ProjectionRouteEndpoints::take_role0_writer() {
    need(!writer_taken_);
    writer_taken_ = true;
    return std::move(writer_);
}

Role0ProjectionRouteCompletionAuthority::
Role0ProjectionRouteCompletionAuthority(
        PublicRole0ProjectionRouteCompletion receipt, Digest route,
        Digest projection, Digest retained, Digest fork_binding)
    : receipt_(std::move(receipt)), route_identity_(route),
      projection_identity_(projection), retained_identity_(retained),
      fork_binding_identity_(fork_binding) {}
Role0ProjectionRouteCompletionAuthority::
Role0ProjectionRouteCompletionAuthority(
        Role0ProjectionRouteCompletionAuthority&& other) noexcept
    : receipt_(other.receipt_), route_identity_(other.route_identity_),
      projection_identity_(other.projection_identity_),
      retained_identity_(other.retained_identity_),
      fork_binding_identity_(other.fork_binding_identity_),
      live_(other.live_.exchange(false)) {}

ParentRetainedProjectionAuthority::ParentRetainedProjectionAuthority(
        PublicRetainedProjectionReceipt receipt,
        PublicProjectionRoutePlan plan,
        std::array<std::byte, PUBLIC_PROJECTION_BYTES> projection,
        Digest projection_identity, Digest route_identity,
        Digest retained_identity, Digest fork_binding_identity,
        std::uint64_t route_observed_monotonic_ns)
    : receipt_(std::move(receipt)), plan_(std::move(plan)),
      projection_(projection), projection_identity_(projection_identity),
      route_identity_(route_identity), retained_identity_(retained_identity),
      fork_binding_identity_(fork_binding_identity),
      route_observed_monotonic_ns_(route_observed_monotonic_ns) {
    need(route_observed_monotonic_ns_ > 0);
}
ParentRetainedProjectionAuthority::ParentRetainedProjectionAuthority(
        ParentRetainedProjectionAuthority&& other) noexcept
    : receipt_(other.receipt_), plan_(other.plan_),
      projection_(other.projection_),
      projection_identity_(other.projection_identity_),
      route_identity_(other.route_identity_),
      retained_identity_(other.retained_identity_),
      fork_binding_identity_(other.fork_binding_identity_),
      route_observed_monotonic_ns_(
          std::exchange(other.route_observed_monotonic_ns_, 0)),
      live_(other.live_.exchange(false)) {}

NativeTerminalRetainedProjectionAuthority::
NativeTerminalRetainedProjectionAuthority(
        PublicRetainedProjectionReceipt receipt,
        PublicProjectionRoutePlan plan,
        std::array<std::byte, PUBLIC_PROJECTION_BYTES> projection,
        Digest projection_identity, Digest route_identity,
        Digest retained_identity, Digest fork_binding_identity,
        std::uint64_t route_observed_monotonic_ns)
    : receipt_(std::move(receipt)), plan_(std::move(plan)),
      projection_(projection), projection_identity_(projection_identity),
      route_identity_(route_identity), retained_identity_(retained_identity),
      fork_binding_identity_(fork_binding_identity),
      route_observed_monotonic_ns_(route_observed_monotonic_ns) {
    need(route_observed_monotonic_ns_ > 0);
}
NativeTerminalRetainedProjectionAuthority::
NativeTerminalRetainedProjectionAuthority(
        NativeTerminalRetainedProjectionAuthority&& other) noexcept
    : receipt_(other.receipt_), plan_(other.plan_),
      projection_(other.projection_),
      projection_identity_(other.projection_identity_),
      route_identity_(other.route_identity_),
      retained_identity_(other.retained_identity_),
      fork_binding_identity_(other.fork_binding_identity_),
      route_observed_monotonic_ns_(
          std::exchange(other.route_observed_monotonic_ns_, 0)),
      live_(other.live_.exchange(false)) {}

#ifdef KPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP
NativeTerminalRetainedProjectionAuthority
RegisteredProjectionRoute::test_only_transfer_for_native_terminal(
        ParentRetainedProjectionAuthority&& retained) {
    need(retained.live_.exchange(false) && retained.receipt_.exact_size &&
         retained.receipt_.read_complete && retained.receipt_.kernel_eof &&
         retained.receipt_.clean && nonzero(retained.projection_identity_) &&
         nonzero(retained.route_identity_) &&
         nonzero(retained.retained_identity_) &&
         nonzero(retained.fork_binding_identity_) &&
         retained.projection_identity_ ==
             hash(std::span(retained.projection_)) &&
         retained.retained_identity_ == retained_identity(
             retained.plan_, retained.route_identity_,
             retained.fork_binding_identity_, retained.projection_identity_,
             retained.projection_));
    return NativeTerminalRetainedProjectionAuthority(
        retained.receipt_, retained.plan_, retained.projection_,
        retained.projection_identity_, retained.route_identity_,
        retained.retained_identity_, retained.fork_binding_identity_,
        retained.route_observed_monotonic_ns_);
}
#endif

ProjectionRouteEndpoints RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority&& authority) {
    need(authority.live_.exchange(false)); validate(authority.plan_);
    std::array<int, 2> sockets{-1, -1};
    need(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0,
                      sockets.data()) == 0);
    try {
        int enabled = 1;
        for (const int fd : sockets)
            need(::setsockopt(fd, SOL_SOCKET, SO_PASSCRED,
                              &enabled, sizeof(enabled)) == 0);
        const auto route = route_identity(authority.plan_);
        const auto parent_pid = static_cast<std::int64_t>(::getpid());
        need(nonzero(route) && parent_pid > 1);
        const PublicProjectionRouteWriter writer{
            .role = 0,
            .round = authority.plan_.round,
            .fixed_fd = ROLE0_PROJECTION_ROUTE_FIXED_FD,
            .capture_plan_identity = authority.plan_.capture_plan_identity,
            .authority_identity = route,
        };
        return ProjectionRouteEndpoints(
            ParentProjectionRouteEndpointAuthority(
                sockets[0], authority.plan_, route, parent_pid),
            Role0ProjectionRouteWriterAuthority(
                sockets[1], sockets[0], authority.plan_, writer, route,
                parent_pid));
    } catch (...) {
        close_noexcept(sockets[0]); close_noexcept(sockets[1]); throw;
    }
}

Role0ProjectionRouteCompletionAuthority
RegisteredProjectionRoute::deliver_after_release(
        Role0ProjectionRouteWriterAuthority&& writer,
        ProjectionDeliveryAuthority&& delivery) {
    return deliver_after_release_impl(
        std::move(writer), std::move(delivery), 0);
}

Role0ProjectionRouteCompletionAuthority
RegisteredProjectionRoute::deliver_after_release_impl(
        Role0ProjectionRouteWriterAuthority&& writer,
        ProjectionDeliveryAuthority&& delivery, std::uint8_t fault) {
    const bool writer_live = writer.live_.exchange(false);
    const bool delivery_live = delivery.live_.exchange(false);
    need(writer_live && delivery_live);
    int fd = std::exchange(writer.fd_, -1);
    try {
        need(fault == 0 || fault == 1 || fault == 3 || fault == 5);
        need(fd >= 0 && same_plan(writer.plan_, delivery.plan_) &&
             !writer.parent_peer_alias_matches() &&
             writer.plan_.computing_role == 0 &&
             writer.public_writer_.role == 0 &&
             writer.public_writer_.round == writer.plan_.round &&
             writer.public_writer_.fixed_fd ==
                 ROLE0_PROJECTION_ROUTE_FIXED_FD &&
             writer.public_writer_.capture_plan_identity ==
                 writer.plan_.capture_plan_identity &&
             writer.public_writer_.authority_identity ==
                 writer.route_identity_ &&
             writer.expected_parent_pid_ > 1 &&
             writer.expected_role0_pid_ == ::getpid() &&
             writer.expected_parent_pid_ == ::getppid() &&
             nonzero(writer.route_identity_) &&
             nonzero(writer.fork_binding_identity_) &&
             delivery.projection_identity_ ==
                 hash(std::span(delivery.projection_)));
        const auto selected_offer = offer(
            writer.plan_, writer.route_identity_,
            writer.fork_binding_identity_,
            delivery.projection_identity_);
        send_packet(fd, selected_offer);
        send_packet(fd, std::span(delivery.projection_));
        if (fault == 1) {
            static constexpr std::array<unsigned char, 1> extra{0x7f};
            send_packet(fd, extra);
        } else if (fault == 3 || fault == 5) {
            send_packet(fd, std::span<const unsigned char>{});
        }
        if (fault != 5) need(::shutdown(fd, SHUT_WR) == 0);

        std::array<unsigned char, ACK_BYTES> ack{};
        const auto received_ack = receive_packet(fd, ack);
        need(!received_ack.eof && received_ack.bytes == ack.size() &&
             received_ack.pid == writer.expected_parent_pid_);
        const auto retained = retained_identity(
            writer.plan_, writer.route_identity_,
            writer.fork_binding_identity_,
            delivery.projection_identity_, delivery.projection_);
        need(acknowledgment(writer.route_identity_,
                            writer.fork_binding_identity_,
                            delivery.projection_identity_, retained) ==
             Bytes(ack.begin(), ack.end()));
        unsigned char trailing{};
        need(receive_packet(fd, std::span(&trailing, 1)).eof);
        close_noexcept(fd);
        PublicRole0ProjectionRouteCompletion receipt{
            .round = writer.plan_.round,
            .classification = writer.plan_.classification,
            .trial = writer.plan_.trial,
            .attempt = writer.plan_.attempt,
            .cohort = writer.plan_.cohort,
            .financial_run = writer.plan_.financial_run,
            .capture_plan_identity = writer.plan_.capture_plan_identity,
            .exact_size = true,
            .parent_read_complete = true,
            .parent_kernel_eof = true,
            .parent_acknowledged = true,
            .parent_writer_closed = true,
        };
        return Role0ProjectionRouteCompletionAuthority(
            std::move(receipt), writer.route_identity_,
            delivery.projection_identity_, retained,
            writer.fork_binding_identity_);
    } catch (...) { close_noexcept(fd); throw; }
}

ParentRetainedProjectionAuthority
RegisteredProjectionRoute::receive_and_retain(
        ParentProjectionRouteEndpointAuthority&& parent) {
    return receive_and_retain_impl(std::move(parent), 0);
}

ParentRetainedProjectionAuthority
RegisteredProjectionRoute::receive_and_retain_impl(
        ParentProjectionRouteEndpointAuthority&& parent,
        std::uint8_t fault) {
    need(parent.live_.exchange(false));
    int fd = std::exchange(parent.fd_, -1);
    try {
        need(fault == 0 || fault == 2 || fault == 4);
        need(fd >= 0 && parent.plan_.computing_role == 0 &&
             parent.expected_parent_pid_ == ::getpid() &&
             parent.expected_role0_pid_ > 1 &&
             parent.expected_role0_pid_ != parent.expected_parent_pid_ &&
             nonzero(parent.fork_binding_identity_));
        std::array<unsigned char, PUBLIC_PROJECTION_BYTES> packet{};
        auto first = receive_packet(fd, packet);
        need(!first.eof && first.bytes == OFFER_BYTES &&
             first.pid == parent.expected_role0_pid_);
        Digest selected_projection{};
        std::copy_n(packet.begin() + 364, selected_projection.size(),
                    selected_projection.begin());
        validate_offer(std::span(packet).first(first.bytes), parent.plan_,
                       parent.route_identity_,
                       parent.fork_binding_identity_, selected_projection);

        auto second = receive_packet(fd, packet);
        need(!second.eof && second.bytes == PUBLIC_PROJECTION_BYTES &&
             second.pid == first.pid && second.uid == first.uid &&
             second.gid == first.gid);
        std::array<std::byte, PUBLIC_PROJECTION_BYTES> projection{};
        std::transform(packet.begin(), packet.end(), projection.begin(),
                       [](unsigned char value) {
                           return static_cast<std::byte>(value);
                       });
        need(hash(std::span(projection)) == selected_projection);
        auto eof = receive_packet(fd, packet);
        need(eof.eof);
        const auto route_observed_monotonic_ns = monotonic_ns();

        const auto retained = retained_identity(
            parent.plan_, parent.route_identity_,
            parent.fork_binding_identity_, selected_projection, projection);
        const auto ack = acknowledgment(parent.route_identity_,
                                        parent.fork_binding_identity_,
                                        selected_projection, retained);
        if (fault == 2) {
            auto oversized = ack;
            oversized.push_back(0x7f);
            send_packet(fd, oversized);
        } else {
            send_packet(fd, ack);
        }
        if (fault == 4)
            send_packet(fd, std::span<const unsigned char>{});
        need(::shutdown(fd, SHUT_WR) == 0);
        close_noexcept(fd);
        return ParentRetainedProjectionAuthority(
            public_receipt(parent.plan_), parent.plan_, projection,
            selected_projection, parent.route_identity_, retained,
            parent.fork_binding_identity_, route_observed_monotonic_ns);
    } catch (...) { close_noexcept(fd); throw; }
}

#ifdef KPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP
Role0ProjectionRouteCompletionAuthority
RegisteredProjectionRoute::test_only_deliver_after_release(
        Role0ProjectionRouteWriterAuthority&& writer,
        ProjectionDeliveryAuthority&& delivery, ProjectionRouteTestFault fault) {
    return deliver_after_release_impl(
        std::move(writer), std::move(delivery),
        static_cast<std::uint8_t>(fault));
}

ParentRetainedProjectionAuthority
RegisteredProjectionRoute::test_only_receive_and_retain(
        ParentProjectionRouteEndpointAuthority&& parent,
        ProjectionRouteTestFault fault) {
    return receive_and_retain_impl(
        std::move(parent), static_cast<std::uint8_t>(fault));
}
#endif

ProjectionRouteSourceStatus projection_route_source_status() {
    return ProjectionRouteSourceStatus{
        .schema = "kpb-registered-projection-route-source-only/v1",
        .status = "UNQUALIFIED_SOURCE_ONLY",
        .parent_minted_pre_intake_pair = true,
        .role0_only_writer = true,
        .exact_projection_bytes = true,
        .kernel_eof_before_ack = true,
        .retained_body_private = true,
        .route_identity_body_independent = true,
        .candidate_egress_callsite = false,
        .baseline_post_disclosure_callsite = false,
        .parent_bootstrap_mint_integration = false,
        .dispatcher_close_integration = false,
        .native_terminal_retention_integration = false,
        .registered_driver_configured = false,
        .launch_authorized = false,
    };
}

} // namespace kpi::mpc::financial::registered_driver::projection_route
