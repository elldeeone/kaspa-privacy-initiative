#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "registered_parent_role_fork.hpp"
#include "registered_projection_route.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <limits>
#include <poll.h>
#include <set>
#include <span>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::registered_driver {

namespace {

using Bytes = std::vector<unsigned char>;
constexpr std::size_t ROLE_COUNT = 3;
constexpr std::size_t OFFER_BYTES = 408;
constexpr std::size_t OFFER_IDENTITY_OFFSET = 376;
constexpr std::size_t ACK_BYTES = 124;
constexpr std::size_t ACK_IDENTITY_OFFSET = 92;
constexpr std::size_t COMPLETION_HEADER_BYTES = 252;
constexpr std::size_t COMPLETION_IDENTITY_OFFSET = 220;
constexpr std::size_t MAX_COMPLETION_PAYLOAD_BYTES = 4096;
constexpr std::size_t RESERVATION_COMMAND_BYTES = 320;
constexpr std::size_t RESERVATION_IDENTITY_OFFSET = 280;
constexpr std::size_t RESERVATION_ACK_BYTES = 88;
constexpr std::size_t RESERVATION_ACK_IDENTITY_OFFSET = 56;
constexpr std::size_t RESERVATION_RETENTION_PROBE_BYTES = 160;
constexpr std::size_t RESERVATION_RETENTION_PROBE_IDENTITY_OFFSET = 116;
constexpr std::size_t RESERVATION_RETENTION_ACK_BYTES = 160;
constexpr std::size_t RESERVATION_RETENTION_ACK_IDENTITY_OFFSET = 120;
constexpr int RESERVATION_ABORT_EXIT = 121;
constexpr int RESERVATION_CHANNEL_CLOSED_EXIT = 122;
constexpr std::array<unsigned char, 8> OFFER_MAGIC{
    'K', 'P', 'B', 'R', 'F', 'O', '1', 0};
constexpr std::array<unsigned char, 8> ACK_MAGIC{
    'K', 'P', 'B', 'R', 'F', 'A', '1', 0};
constexpr std::array<unsigned char, 8> COMPLETION_MAGIC{
    'K', 'P', 'B', 'R', 'F', 'C', '1', 0};
constexpr std::array<unsigned char, 8> RESERVATION_MAGIC{
    'K', 'P', 'B', 'R', 'S', 'V', '1', 0};
constexpr std::array<unsigned char, 8> RESERVATION_ACK_MAGIC{
    'K', 'P', 'B', 'R', 'S', 'A', '1', 0};
constexpr std::array<unsigned char, 8> RESERVATION_RETENTION_PROBE_MAGIC{
    'K', 'P', 'B', 'R', 'S', 'P', '2', 0};
constexpr std::array<unsigned char, 8> RESERVATION_RETENTION_ACK_MAGIC{
    'K', 'P', 'B', 'R', 'S', 'K', '2', 0};

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) { return value != Digest{}; }

void close_if_open(int& fd) noexcept {
    if (fd >= 0) {
        while (::close(fd) != 0 && errno == EINTR) {}
        fd = -1;
    }
}

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
void string(Bytes& out, const std::string& value) {
    integer(out, value.size());
    add(out, std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
}

struct Fingerprint {
    std::uint64_t device;
    std::uint64_t inode;
    std::uint32_t file_type;
};

struct StateArchiveFingerprint final {
    std::uint64_t device{};
    std::uint64_t inode{};
    std::uint32_t mode{};
    std::uint64_t nlink{};
    std::uint64_t size{};
};

StateArchiveFingerprint state_archive_fingerprint(int fd) {
    struct stat state{};
    need(fd >= 0 && ::fstat(fd, &state) == 0 &&
         (state.st_mode & S_IFMT) == S_IFREG &&
         state.st_nlink == 0 && state.st_size == 0);
    const int descriptor_flags = ::fcntl(fd, F_GETFD);
    const int status_flags = ::fcntl(fd, F_GETFL);
    const off_t offset = ::lseek(fd, 0, SEEK_CUR);
    need(descriptor_flags >= 0 &&
         (descriptor_flags & FD_CLOEXEC) != 0 &&
         status_flags >= 0 && (status_flags & O_ACCMODE) == O_WRONLY &&
         (status_flags & O_APPEND) == 0 && offset == 0);
    return {
        static_cast<std::uint64_t>(state.st_dev),
        static_cast<std::uint64_t>(state.st_ino),
        static_cast<std::uint32_t>(state.st_mode),
        static_cast<std::uint64_t>(state.st_nlink),
        static_cast<std::uint64_t>(state.st_size),
    };
}

Fingerprint terminal_socket_fingerprint(int fd) {
    struct stat state{};
    int socket_type = 0;
    socklen_t type_bytes = sizeof(socket_type);
    int pass_credentials = 0;
    socklen_t pass_bytes = sizeof(pass_credentials);
    const int descriptor_flags = ::fcntl(fd, F_GETFD);
    need(fd >= 0 && ::fstat(fd, &state) == 0 &&
         (state.st_mode & S_IFMT) == S_IFSOCK &&
         descriptor_flags >= 0 &&
         (descriptor_flags & FD_CLOEXEC) != 0 &&
         ::getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type,
                      &type_bytes) == 0 &&
         type_bytes == sizeof(socket_type) &&
         socket_type == SOCK_SEQPACKET &&
         ::getsockopt(fd, SOL_SOCKET, SO_PASSCRED, &pass_credentials,
                      &pass_bytes) == 0 &&
         pass_bytes == sizeof(pass_credentials) && pass_credentials == 1);
    return {
        static_cast<std::uint64_t>(state.st_dev),
        static_cast<std::uint64_t>(state.st_ino),
        static_cast<std::uint32_t>(state.st_mode & S_IFMT),
    };
}

struct PlanState {
    PublicParentRoleForkPlan value{};
    std::array<PublicInheritedCaptureEndpoint, 3> endpoints{};
    std::array<std::uint64_t, 3> devices{};
    std::array<std::uint64_t, 3> inodes{};
    std::array<std::uint32_t, 3> file_types{};
    std::array<int, 3> source_fds{{-1, -1, -1}};
    std::unique_ptr<
        projection_route::Role0ProjectionRouteWriterAuthority>
        projection_route_writer;
    Digest projection_route_identity{};
    Digest identity{};
};

static_assert(std::is_nothrow_move_constructible_v<
              PublicParentRoleForkPlan>);
static_assert(std::is_nothrow_move_constructible_v<
              std::array<PublicInheritedCaptureEndpoint, 3>>);
static_assert(std::is_nothrow_move_constructible_v<
              std::array<int, 3>>);

Fingerprint fingerprint(int fd) {
    struct stat state{};
    need(fd >= 0 && ::fstat(fd, &state) == 0);
    const auto type = static_cast<std::uint32_t>(state.st_mode & S_IFMT);
    need(type == S_IFIFO || type == S_IFSOCK);
    const int flags = ::fcntl(fd, F_GETFL);
    need(flags >= 0 && (flags & O_ACCMODE) != O_RDONLY);
    return {
        static_cast<std::uint64_t>(state.st_dev),
        static_cast<std::uint64_t>(state.st_ino),
        type,
    };
}

int duplicate_high(int fd) {
    need(fd >= 0);
    int result;
    do {
        result = ::fcntl(fd, F_DUPFD_CLOEXEC, 64);
    } while (result < 0 && errno == EINTR);
    need(result >= 64);
    return result;
}

std::array<int, 2> fixed_fds(unsigned round, unsigned role,
                             std::uint8_t& count) {
    need((round == 1 || round == 2) && role < ROLE_COUNT);
    const int offset = round == 1 ? 0 : 5;
    if (role == 0) {
        count = 2;
        return {20 + offset, 22 + offset};
    }
    if (role == 1) {
        count = 1;
        return {23 + offset, -1};
    }
    count = 0;
    return {-1, -1};
}

void valid_plan(const PublicParentRoleForkPlan& value) {
    need((value.classification == CaptureClassification::HiddenCandidate ||
          value.classification ==
              CaptureClassification::ExplicitOwnerPublicEffectsBaseline) &&
         (value.round == 1 || value.round == 2) &&
         value.trial == RegisteredCapturePlanRosterBridge::trial_identity(
             value.capture_trial_id));
    for (const auto* field : {
             &value.trial, &value.financial_run, &value.attempt,
             &value.cohort, &value.fresh_owner_issuance_identity,
             &value.authority_identity, &value.supervisor_session,
             &value.capture_plan_identity, &value.capture_source_identity,
             &value.capture_build_identity,
             &value.capture_launcher_identity}) need(nonzero(*field));
    need(value.authority_identity != value.supervisor_session);
    std::set<Digest> party_sessions;
    std::set<Digest> driver_selections;
    for (unsigned role = 0; role < ROLE_COUNT; ++role) {
        const auto& binding = value.roles[role];
        need(binding.role == role && nonzero(binding.party_session) &&
             nonzero(binding.service_identity) &&
             nonzero(binding.driver_selection_identity) &&
             binding.party_session != value.supervisor_session &&
             binding.party_session != value.authority_identity);
        party_sessions.insert(binding.party_session);
        driver_selections.insert(binding.driver_selection_identity);
    }
    need(party_sessions.size() == ROLE_COUNT &&
         driver_selections.size() == ROLE_COUNT &&
         value.roles[0].service_identity == value.roles[1].service_identity &&
         value.roles[1].service_identity == value.roles[2].service_identity);
}

void valid_endpoints(
        const PublicParentRoleForkPlan& plan,
        const std::array<PublicInheritedCaptureEndpoint, 3>& endpoints,
        const std::array<std::uint64_t, 3>& devices,
        const std::array<std::uint64_t, 3>& inodes,
        const std::array<std::uint32_t, 3>& file_types) {
    const int offset = plan.round == 1 ? 0 : 5;
    const std::array<PublicInheritedCaptureEndpoint, 3> expected{
        PublicInheritedCaptureEndpoint{
            .kind = InheritedCaptureKind::Projection, .role = 0,
            .round = plan.round, .fixed_fd = 20 + offset,
            .authority_identity = endpoints[0].authority_identity,
            .capture_plan_identity = plan.capture_plan_identity,
        },
        PublicInheritedCaptureEndpoint{
            .kind = InheritedCaptureKind::Dispatcher, .role = 0,
            .round = plan.round, .fixed_fd = 22 + offset,
            .authority_identity = endpoints[1].authority_identity,
            .capture_plan_identity = plan.capture_plan_identity,
        },
        PublicInheritedCaptureEndpoint{
            .kind = InheritedCaptureKind::CorruptServer, .role = 1,
            .round = plan.round, .fixed_fd = 23 + offset,
            .authority_identity = endpoints[2].authority_identity,
            .capture_plan_identity = plan.capture_plan_identity,
        },
    };
    std::set<Digest> authorities;
    std::set<std::pair<std::uint64_t, std::uint64_t>> objects;
    for (std::size_t index = 0; index < endpoints.size(); ++index) {
        const auto& actual = endpoints[index];
        const auto& wanted = expected[index];
        need(actual.kind == wanted.kind && actual.role == wanted.role &&
             actual.round == wanted.round &&
             actual.fixed_fd == wanted.fixed_fd &&
             nonzero(actual.authority_identity) &&
             actual.capture_plan_identity == wanted.capture_plan_identity &&
             devices[index] != 0 && inodes[index] != 0 &&
             (file_types[index] == S_IFIFO ||
              file_types[index] == S_IFSOCK));
        authorities.insert(actual.authority_identity);
        objects.emplace(devices[index], inodes[index]);
    }
    need(authorities.size() == endpoints.size() &&
         objects.size() == endpoints.size());
}

Digest plan_identity(
        const PublicParentRoleForkPlan& plan,
        const std::array<PublicInheritedCaptureEndpoint, 3>& endpoints,
        const std::array<std::uint64_t, 3>& devices,
        const std::array<std::uint64_t, 3>& inodes,
        const std::array<std::uint32_t, 3>& file_types,
        const Digest& projection_route_identity) {
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_PARENT_ROLE_FORK_PLAN_V4\n");
    integer(bytes, static_cast<std::uint8_t>(plan.classification));
    integer(bytes, plan.round);
    string(bytes, plan.capture_trial_id);
    for (const auto* field : {
             &plan.trial, &plan.financial_run, &plan.attempt, &plan.cohort,
             &plan.fresh_owner_issuance_identity})
        add(bytes, *field);
    for (const auto* field : {
             &plan.authority_identity, &plan.supervisor_session,
             &plan.capture_plan_identity, &plan.capture_source_identity,
             &plan.capture_build_identity,
             &plan.capture_launcher_identity}) add(bytes, *field);
    for (const auto& binding : plan.roles) {
        integer(bytes, binding.role);
        add(bytes, binding.party_session);
        add(bytes, binding.service_identity);
        add(bytes, binding.driver_selection_identity);
    }
    for (std::size_t index = 0; index < endpoints.size(); ++index) {
        const auto& endpoint = endpoints[index];
        integer(bytes, static_cast<std::uint8_t>(endpoint.kind));
        integer(bytes, endpoint.role);
        integer(bytes, endpoint.round);
        integer(bytes, static_cast<std::uint64_t>(endpoint.fixed_fd));
        add(bytes, endpoint.authority_identity);
        add(bytes, endpoint.capture_plan_identity);
        integer(bytes, devices[index]);
        integer(bytes, inodes[index]);
        integer(bytes, file_types[index]);
    }
    integer(bytes, nonzero(projection_route_identity) ? 1 : 0);
    if (nonzero(projection_route_identity)) {
        integer(bytes, 0);
        integer(bytes, plan.round);
        integer(bytes, projection_route::ROLE0_PROJECTION_ROUTE_FIXED_FD);
        add(bytes, plan.capture_plan_identity);
        add(bytes, projection_route_identity);
    }
    return identity_registry::digest(bytes);
}

void validate_source_fds(const PlanState& plan) {
    std::set<int> descriptors;
    for (std::size_t index = 0; index < plan.source_fds.size(); ++index) {
        const int fd = plan.source_fds[index];
        need(fd >= 64 && descriptors.insert(fd).second);
        const auto actual = fingerprint(fd);
        need(actual.device == plan.devices[index] &&
             actual.inode == plan.inodes[index] &&
             actual.file_type == plan.file_types[index]);
    }
}

void require_single_thread() {
    DIR* directory = ::opendir("/proc/self/task");
    need(directory != nullptr);
    unsigned count = 0;
    errno = 0;
    while (const auto* entry = ::readdir(directory)) {
        if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') ++count;
    }
    const int saved = errno;
    need(::closedir(directory) == 0 && saved == 0 && count == 1);
}

void require_waitable_children() {
    struct sigaction action{};
    need(::sigaction(SIGCHLD, nullptr, &action) == 0 &&
         action.sa_handler == SIG_DFL &&
         (action.sa_flags & SA_NOCLDWAIT) == 0);
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
            close_if_open(value_);
            value_ = std::exchange(other.value_, -1);
        }
        return *this;
    }
    ~UniqueFd() { close_if_open(value_); }
    int get() const { return value_; }
    int release() { return std::exchange(value_, -1); }
    void reset() { close_if_open(value_); }
};

std::array<UniqueFd, 2> capability_channel() {
    int raw[2]{-1, -1};
    need(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, raw) == 0);
    try {
        std::array<UniqueFd, 2> result{
            UniqueFd(duplicate_high(raw[0])),
            UniqueFd(duplicate_high(raw[1])),
        };
        close_if_open(raw[0]);
        close_if_open(raw[1]);
        const int enabled = 1;
        for (const auto& endpoint : result)
            need(::setsockopt(endpoint.get(), SOL_SOCKET, SO_PASSCRED,
                              &enabled, sizeof(enabled)) == 0);
        return result;
    } catch (...) {
        close_if_open(raw[0]);
        close_if_open(raw[1]);
        throw;
    }
}

constexpr std::array<int, 2> RESERVATION_CHILD_CHANNEL_FDS{{60, 61}};

int parse_open_fd_name(const char* name) noexcept {
    if (name == nullptr || *name == '\0') return -1;
    int value = 0;
    for (const char* at = name; *at != '\0'; ++at) {
        if (*at < '0' || *at > '9') return -1;
        if (value > (std::numeric_limits<int>::max() - 9) / 10)
            return -1;
        value = value * 10 + (*at - '0');
    }
    return value;
}

void close_descriptor_range(unsigned first, unsigned last) {
    if (first > last) return;
#ifdef SYS_close_range
    long result;
    do {
        result = ::syscall(SYS_close_range, first, last, 0U);
    } while (result < 0 && errno == EINTR);
    if (result == 0) return;
    need(errno == ENOSYS);
#endif
    DIR* directory = ::opendir("/proc/self/fd");
    need(directory != nullptr);
    const int directory_fd = ::dirfd(directory);
    std::vector<int> selected;
    errno = 0;
    while (const auto* entry = ::readdir(directory)) {
        const int fd = parse_open_fd_name(entry->d_name);
        if (fd >= 0 && fd != directory_fd &&
            static_cast<unsigned>(fd) >= first &&
            static_cast<unsigned>(fd) <= last)
            selected.push_back(fd);
    }
    const int saved = errno;
    need(::closedir(directory) == 0 && saved == 0);
    for (int fd : selected) close_if_open(fd);
}

void require_only_reservation_child_descriptors(
        const std::array<int, 2>& endpoints) {
    for (const int fd : endpoints) {
        const int flags = ::fcntl(fd, F_GETFD);
        int type = 0;
        socklen_t type_bytes = sizeof(type);
        int pass_credentials = 0;
        socklen_t pass_bytes = sizeof(pass_credentials);
        need(flags >= 0 && (flags & FD_CLOEXEC) != 0 &&
             ::getsockopt(fd, SOL_SOCKET, SO_TYPE, &type,
                          &type_bytes) == 0 &&
             type_bytes == sizeof(type) && type == SOCK_SEQPACKET &&
             ::getsockopt(fd, SOL_SOCKET, SO_PASSCRED,
                          &pass_credentials, &pass_bytes) == 0 &&
             pass_bytes == sizeof(pass_credentials) &&
             pass_credentials == 1);
    }
    DIR* directory = ::opendir("/proc/self/fd");
    need(directory != nullptr);
    const int directory_fd = ::dirfd(directory);
    errno = 0;
    while (const auto* entry = ::readdir(directory)) {
        const int fd = parse_open_fd_name(entry->d_name);
        if (fd < 0) continue;
        need(fd == STDIN_FILENO || fd == STDOUT_FILENO ||
             fd == STDERR_FILENO || fd == endpoints[0] ||
             fd == endpoints[1] || fd == directory_fd);
    }
    const int saved = errno;
    need(::closedir(directory) == 0 && saved == 0);
}

std::array<int, 2> install_reservation_child_channel_allowlist(
        const std::array<int, 2>& inherited) {
    need(inherited[0] >= 64 && inherited[1] >= 64 &&
         inherited[0] != inherited[1]);
    for (unsigned round = 0; round < inherited.size(); ++round) {
        int result;
        do {
            result = ::dup3(
                inherited[round], RESERVATION_CHILD_CHANNEL_FDS[round],
                O_CLOEXEC);
        } while (result < 0 && errno == EINTR);
        need(result == RESERVATION_CHILD_CHANNEL_FDS[round]);
    }
    close_descriptor_range(3, RESERVATION_CHILD_CHANNEL_FDS[0] - 1);
    close_descriptor_range(
        RESERVATION_CHILD_CHANNEL_FDS[1] + 1,
        std::numeric_limits<unsigned>::max());
    require_only_reservation_child_descriptors(
        RESERVATION_CHILD_CHANNEL_FDS);
    return RESERVATION_CHILD_CHANNEL_FDS;
}

Digest random_nonce() {
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

void put_u32(std::span<unsigned char> out, std::size_t at,
             std::uint32_t value) {
    need(at <= out.size() && 4 <= out.size() - at);
    for (unsigned index = 0; index < 4; ++index)
        out[at + index] = static_cast<unsigned char>(value >> (8 * index));
}

std::uint32_t get_u32(std::span<const unsigned char> in, std::size_t at) {
    need(at <= in.size() && 4 <= in.size() - at);
    std::uint32_t result = 0;
    for (unsigned index = 0; index < 4; ++index)
        result |= std::uint32_t(in[at + index]) << (8 * index);
    return result;
}

void put_u64(std::span<unsigned char> out, std::size_t at,
             std::uint64_t value) {
    need(at <= out.size() && 8 <= out.size() - at);
    for (unsigned index = 0; index < 8; ++index)
        out[at + index] = static_cast<unsigned char>(value >> (8 * index));
}

std::uint64_t get_u64(std::span<const unsigned char> in, std::size_t at) {
    need(at <= in.size() && 8 <= in.size() - at);
    std::uint64_t result = 0;
    for (unsigned index = 0; index < 8; ++index)
        result |= std::uint64_t(in[at + index]) << (8 * index);
    return result;
}

void put_digest(std::span<unsigned char> out, std::size_t at,
                const Digest& value) {
    need(at <= out.size() && value.size() <= out.size() - at);
    std::copy(value.begin(), value.end(), out.begin() + at);
}

Digest get_digest(std::span<const unsigned char> in, std::size_t at) {
    Digest result{};
    need(at <= in.size() && result.size() <= in.size() - at);
    std::copy_n(in.begin() + at, result.size(), result.begin());
    return result;
}

std::array<unsigned char, RESERVATION_COMMAND_BYTES>
reservation_abort_command() {
    std::array<unsigned char, RESERVATION_COMMAND_BYTES> result{};
    std::copy(
        RESERVATION_MAGIC.begin(), RESERVATION_MAGIC.end(), result.begin());
    result[8] = 1;
    result[9] = 1;
    return result;
}

bool is_reservation_abort_command(
        const std::array<unsigned char, RESERVATION_COMMAND_BYTES>& value) {
    return std::equal(
               RESERVATION_MAGIC.begin(), RESERVATION_MAGIC.end(),
               value.begin()) &&
        value[8] == 1 && value[9] == 1 &&
        std::all_of(value.begin() + 10, value.end(),
                    [](unsigned char byte) { return byte == 0; });
}

std::array<unsigned, 2> reservation_topology_slots(
        unsigned round, unsigned role, std::uint8_t& count) {
    need((round == 1 || round == 2) && role < ROLE_COUNT);
    const unsigned base = round == 1 ? 0U : 5U;
    if (role == 0) {
        count = 2;
        return {base, base + 2};
    }
    if (role == 1) {
        count = 1;
        return {base + 3, 0};
    }
    count = 0;
    return {0, 0};
}

struct ReservationActivationCommand final {
    std::array<unsigned char, RESERVATION_COMMAND_BYTES> bytes{};
    std::array<int, 4> descriptors{{-1, -1, -1, -1}};
    std::uint8_t capture_descriptor_count{};
    std::uint8_t state_descriptor_count{};
    Digest identity{};
};

ReservationActivationCommand make_reservation_activation_command(
        unsigned round, unsigned role,
        const std::array<int, 10>& writer_aliases,
        const std::array<std::uint64_t, 10>& endpoint_devices,
        const std::array<std::uint64_t, 10>& endpoint_inodes,
        const std::array<std::uint32_t, 10>& endpoint_types,
        std::int64_t parent_pid, std::int64_t child_pid,
        const std::array<int, 2>& state_writers,
        const std::array<int, 2>& state_terminals,
        const std::array<std::uint64_t, 2>& state_devices,
        const std::array<std::uint64_t, 2>& state_inodes,
        const std::array<std::uint32_t, 2>& state_modes,
        const std::array<std::uint64_t, 2>& state_nlinks,
        const std::array<std::uint64_t, 2>& state_sizes,
        const std::array<std::uint64_t, 2>& terminal_devices,
        const std::array<std::uint64_t, 2>& terminal_inodes,
        const std::array<std::uint32_t, 2>& terminal_types,
        const Digest& reservation_identity,
        const Digest& activation_identity,
        const Digest& trial_identity) {
    need(parent_pid > 1 && child_pid > 1 &&
         parent_pid <= std::numeric_limits<std::uint32_t>::max() &&
         child_pid <= std::numeric_limits<std::uint32_t>::max() &&
         nonzero(reservation_identity) && nonzero(activation_identity) &&
         nonzero(trial_identity));
    ReservationActivationCommand result;
    std::copy(
        RESERVATION_MAGIC.begin(), RESERVATION_MAGIC.end(),
        result.bytes.begin());
    result.bytes[8] = 2;
    result.bytes[9] = 2;
    result.bytes[10] = static_cast<unsigned char>(role);
    result.bytes[11] = static_cast<unsigned char>(round);
    const auto slots = reservation_topology_slots(
        round, role, result.capture_descriptor_count);
    result.state_descriptor_count = role == 1 ? 2 : 0;
    result.bytes[12] = result.capture_descriptor_count;
    result.bytes[13] = result.state_descriptor_count;
    put_u32(result.bytes, 16, static_cast<std::uint32_t>(parent_pid));
    put_u32(result.bytes, 20, static_cast<std::uint32_t>(child_pid));
    for (unsigned index = 0;
         index < result.capture_descriptor_count; ++index) {
        const unsigned slot = slots[index];
        need(slot < writer_aliases.size() && writer_aliases[slot] >= 0);
        const auto actual = fingerprint(writer_aliases[slot]);
        const int descriptor_flags = ::fcntl(
            writer_aliases[slot], F_GETFD);
        need(actual.device == endpoint_devices[slot] &&
             actual.inode == endpoint_inodes[slot] &&
             actual.file_type == endpoint_types[slot] &&
             actual.file_type == S_IFIFO && descriptor_flags >= 0 &&
             (descriptor_flags & FD_CLOEXEC) != 0);
        const std::size_t at = 24 + 32 * index;
        put_u32(result.bytes, at, slot);
        put_u32(result.bytes, at + 4, 20 + slot);
        put_u64(result.bytes, at + 8, endpoint_devices[slot]);
        put_u64(result.bytes, at + 16, endpoint_inodes[slot]);
        put_u32(result.bytes, at + 24, endpoint_types[slot]);
        result.descriptors[index] = writer_aliases[slot];
    }

    const unsigned state_slot = round - 1;
    if (role == 1) {
        need(state_slot < state_writers.size() &&
             state_writers[state_slot] >= 0 &&
             state_terminals[state_slot] >= 0);
        const auto archive = state_archive_fingerprint(
            state_writers[state_slot]);
        const auto terminal = terminal_socket_fingerprint(
            state_terminals[state_slot]);
        need(archive.device == state_devices[state_slot] &&
             archive.inode == state_inodes[state_slot] &&
             archive.mode == state_modes[state_slot] &&
             archive.nlink == state_nlinks[state_slot] &&
             archive.size == state_sizes[state_slot] &&
             terminal.device == terminal_devices[state_slot] &&
             terminal.inode == terminal_inodes[state_slot] &&
             terminal.file_type == terminal_types[state_slot]);
        put_u32(result.bytes, 88, state_slot);
        put_u32(result.bytes, 92, archive.mode);
        put_u64(result.bytes, 96, archive.device);
        put_u64(result.bytes, 104, archive.inode);
        put_u64(result.bytes, 112, archive.nlink);
        put_u64(result.bytes, 120, archive.size);
        put_u32(result.bytes, 128, terminal.file_type);
        put_u64(result.bytes, 136, terminal.device);
        put_u64(result.bytes, 144, terminal.inode);
        result.descriptors[result.capture_descriptor_count] =
            state_writers[state_slot];
        result.descriptors[result.capture_descriptor_count + 1] =
            state_terminals[state_slot];
    }
    put_digest(result.bytes, 152, reservation_identity);
    const auto nonce = random_nonce();
    put_digest(result.bytes, 184, nonce);
    put_digest(result.bytes, 216, activation_identity);
    put_digest(result.bytes, 248, trial_identity);
    result.identity = identity_registry::digest(
        std::span<const unsigned char>(
            result.bytes.data(), RESERVATION_IDENTITY_OFFSET));
    need(nonzero(result.identity));
    put_digest(
        result.bytes, RESERVATION_IDENTITY_OFFSET, result.identity);
    return result;
}

#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
void rebind_reservation_activation_command(
        ReservationActivationCommand& command) {
    command.identity = identity_registry::digest(
        std::span<const unsigned char>(
            command.bytes.data(), RESERVATION_IDENTITY_OFFSET));
    need(nonzero(command.identity));
    put_digest(
        command.bytes, RESERVATION_IDENTITY_OFFSET, command.identity);
}

void inject_reservation_retention_fault(
        std::array<std::array<ReservationActivationCommand, 3>, 2>&
            commands,
        ParentRoleReservationRetentionTestFault fault) {
    switch (fault) {
    case ParentRoleReservationRetentionTestFault::None:
    case ParentRoleReservationRetentionTestFault::WrongParentReport:
    case ParentRoleReservationRetentionTestFault::ReplayActivationCommand:
        return;
    case ParentRoleReservationRetentionTestFault::SwappedCaptureSlot: {
        auto& command = commands[0][0];
        const auto first_slot = get_u32(command.bytes, 24);
        const auto first_fixed = get_u32(command.bytes, 28);
        put_u32(command.bytes, 24, get_u32(command.bytes, 56));
        put_u32(command.bytes, 28, get_u32(command.bytes, 60));
        put_u32(command.bytes, 56, first_slot);
        put_u32(command.bytes, 60, first_fixed);
        rebind_reservation_activation_command(command);
        return;
    }
    case ParentRoleReservationRetentionTestFault::SwappedRound: {
        auto& command = commands[1][1];
        command.bytes[11] = 1;
        rebind_reservation_activation_command(command);
        return;
    }
    case ParentRoleReservationRetentionTestFault::SameFdWrongMetadata: {
        auto& command = commands[0][1];
        put_u64(command.bytes, 104, get_u64(command.bytes, 104) ^ 1U);
        rebind_reservation_activation_command(command);
        return;
    }
    case ParentRoleReservationRetentionTestFault::DropMetadataAfterAck: {
        auto& command = commands[0][1];
        command.bytes[15] = 1;
        rebind_reservation_activation_command(command);
        return;
    }
    }
    refuse();
}
#endif

struct ParsedReservationActivationCommand final {
    Digest identity{};
    Digest reservation_identity{};
    Digest channel_nonce{};
    Digest activation_identity{};
    Digest trial_identity{};
    unsigned round{};
    unsigned role{};
    std::uint8_t capture_descriptor_count{};
    std::uint8_t state_descriptor_count{};
    bool drop_metadata_after_ack{};
    bool operator==(const ParsedReservationActivationCommand&) const =
        default;
};

ParsedReservationActivationCommand parse_reservation_activation_command(
        const std::array<unsigned char, RESERVATION_COMMAND_BYTES>& bytes,
        unsigned expected_round, unsigned expected_role,
        std::int64_t expected_parent_pid,
        std::int64_t expected_child_pid,
        std::span<const int> descriptors) {
    need(std::equal(
             RESERVATION_MAGIC.begin(), RESERVATION_MAGIC.end(),
             bytes.begin()) &&
         bytes[8] == 2 && bytes[9] == 2 &&
         bytes[10] == expected_role && bytes[11] == expected_round &&
         bytes[14] == 0 &&
         get_u32(bytes, 16) == expected_parent_pid &&
         get_u32(bytes, 20) == expected_child_pid);
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
    need(bytes[15] <= 1);
    const bool drop_metadata_after_ack = bytes[15] == 1;
#else
    need(bytes[15] == 0);
    constexpr bool drop_metadata_after_ack = false;
#endif
    std::uint8_t expected_count = 0;
    const auto slots = reservation_topology_slots(
        expected_round, expected_role, expected_count);
    const std::uint8_t expected_state_count =
        expected_role == 1 ? 2 : 0;
    need(bytes[12] == expected_count &&
         bytes[13] == expected_state_count &&
         descriptors.size() == expected_count + expected_state_count);
    for (unsigned index = 0; index < expected_count; ++index) {
        const auto slot = slots[index];
        const auto at = 24 + 32 * index;
        need(get_u32(bytes, at) == slot &&
             get_u32(bytes, at + 4) == 20 + slot &&
             get_u32(bytes, at + 24) == S_IFIFO);
        const auto actual = fingerprint(descriptors[index]);
        const int descriptor_flags = ::fcntl(descriptors[index], F_GETFD);
        need(actual.device == get_u64(bytes, at + 8) &&
             actual.inode == get_u64(bytes, at + 16) &&
             actual.file_type == get_u32(bytes, at + 24) &&
             descriptor_flags >= 0 &&
             (descriptor_flags & FD_CLOEXEC) != 0);
    }
    if (expected_role == 1) {
        const unsigned state_slot = expected_round - 1;
        need(get_u32(bytes, 88) == state_slot);
        const auto archive = state_archive_fingerprint(
            descriptors[expected_count]);
        const auto terminal = terminal_socket_fingerprint(
            descriptors[expected_count + 1]);
        need(archive.mode == get_u32(bytes, 92) &&
             archive.device == get_u64(bytes, 96) &&
             archive.inode == get_u64(bytes, 104) &&
             archive.nlink == get_u64(bytes, 112) &&
             archive.size == get_u64(bytes, 120) &&
             terminal.file_type == get_u32(bytes, 128) &&
             get_u32(bytes, 132) == 0 &&
             terminal.device == get_u64(bytes, 136) &&
             terminal.inode == get_u64(bytes, 144));
    } else {
        need(std::all_of(bytes.begin() + 88, bytes.begin() + 152,
                         [](unsigned char value) { return value == 0; }));
    }
    const auto reservation_identity = get_digest(bytes, 152);
    const auto nonce = get_digest(bytes, 184);
    const auto activation_identity = get_digest(bytes, 216);
    const auto trial_identity = get_digest(bytes, 248);
    const auto identity = get_digest(bytes, RESERVATION_IDENTITY_OFFSET);
    need(nonzero(reservation_identity) && nonzero(nonce) &&
         nonzero(activation_identity) && nonzero(trial_identity) &&
         nonzero(identity) &&
         identity == identity_registry::digest(
             std::span<const unsigned char>(
                 bytes.data(), RESERVATION_IDENTITY_OFFSET)) &&
         std::all_of(bytes.begin() + 312, bytes.end(),
                     [](unsigned char value) { return value == 0; }));
    return {
        .identity = identity,
        .reservation_identity = reservation_identity,
        .channel_nonce = nonce,
        .activation_identity = activation_identity,
        .trial_identity = trial_identity,
        .round = expected_round,
        .role = expected_role,
        .capture_descriptor_count = expected_count,
        .state_descriptor_count = expected_state_count,
        .drop_metadata_after_ack = drop_metadata_after_ack,
    };
}

std::array<unsigned char, RESERVATION_ACK_BYTES>
make_reservation_activation_ack(
        unsigned round, unsigned role,
        std::uint8_t capture_descriptor_count,
        std::uint8_t state_descriptor_count,
        std::int64_t parent_pid, std::int64_t child_pid,
        const Digest& command_identity) {
    need((round == 1 || round == 2) && role < ROLE_COUNT &&
         parent_pid > 1 && child_pid > 1 &&
         parent_pid <= std::numeric_limits<std::uint32_t>::max() &&
         child_pid <= std::numeric_limits<std::uint32_t>::max() &&
         nonzero(command_identity));
    std::array<unsigned char, RESERVATION_ACK_BYTES> result{};
    std::copy(
        RESERVATION_ACK_MAGIC.begin(), RESERVATION_ACK_MAGIC.end(),
        result.begin());
    result[8] = 2;
    result[9] = 3;
    result[10] = static_cast<unsigned char>(role);
    result[11] = static_cast<unsigned char>(round);
    result[12] = static_cast<unsigned char>(
        capture_descriptor_count + state_descriptor_count);
    result[13] = capture_descriptor_count;
    result[14] = state_descriptor_count;
    put_u32(result, 16, static_cast<std::uint32_t>(parent_pid));
    put_u32(result, 20, static_cast<std::uint32_t>(child_pid));
    put_digest(result, 24, command_identity);
    put_digest(
        result, RESERVATION_ACK_IDENTITY_OFFSET,
        identity_registry::digest(std::span<const unsigned char>(
            result.data(), RESERVATION_ACK_IDENTITY_OFFSET)));
    return result;
}

void parse_reservation_activation_ack(
        const std::array<unsigned char, RESERVATION_ACK_BYTES>& bytes,
        unsigned expected_round, unsigned expected_role,
        std::uint8_t expected_capture_descriptor_count,
        std::uint8_t expected_state_descriptor_count,
        std::int64_t expected_parent_pid, std::int64_t expected_child_pid,
        const Digest& expected_command_identity) {
    need(std::equal(
             RESERVATION_ACK_MAGIC.begin(), RESERVATION_ACK_MAGIC.end(),
             bytes.begin()) &&
         bytes[8] == 2 && bytes[9] == 3 &&
         bytes[10] == expected_role && bytes[11] == expected_round &&
         bytes[12] == expected_capture_descriptor_count +
                          expected_state_descriptor_count &&
         bytes[13] == expected_capture_descriptor_count &&
         bytes[14] == expected_state_descriptor_count && bytes[15] == 0 &&
         get_u32(bytes, 16) == expected_parent_pid &&
         get_u32(bytes, 20) == expected_child_pid &&
         get_digest(bytes, 24) == expected_command_identity);
    const auto identity = get_digest(
        bytes, RESERVATION_ACK_IDENTITY_OFFSET);
    need(nonzero(identity) &&
         identity == identity_registry::digest(
             std::span<const unsigned char>(
                 bytes.data(), RESERVATION_ACK_IDENTITY_OFFSET)));
}

struct ReservationRetentionProbe final {
    std::array<unsigned char, RESERVATION_RETENTION_PROBE_BYTES> bytes{};
    Digest nonce{};
    Digest identity{};
};

ReservationRetentionProbe make_reservation_retention_probe(
        unsigned role, std::int64_t parent_pid, std::int64_t child_pid,
        const std::array<Digest, 2>& command_identities) {
    need(role < ROLE_COUNT && parent_pid > 1 && child_pid > 1 &&
         parent_pid <= std::numeric_limits<std::uint32_t>::max() &&
         child_pid <= std::numeric_limits<std::uint32_t>::max() &&
         nonzero(command_identities[0]) &&
         nonzero(command_identities[1]) &&
         command_identities[0] != command_identities[1]);
    ReservationRetentionProbe result;
    std::copy(RESERVATION_RETENTION_PROBE_MAGIC.begin(),
              RESERVATION_RETENTION_PROBE_MAGIC.end(),
              result.bytes.begin());
    result.bytes[8] = 2;
    result.bytes[9] = 4;
    result.bytes[10] = static_cast<unsigned char>(role);
    result.bytes[11] = 2;
    put_u32(result.bytes, 12, static_cast<std::uint32_t>(parent_pid));
    put_u32(result.bytes, 16, static_cast<std::uint32_t>(child_pid));
    put_digest(result.bytes, 20, command_identities[0]);
    put_digest(result.bytes, 52, command_identities[1]);
    result.nonce = random_nonce();
    put_digest(result.bytes, 84, result.nonce);
    result.identity = identity_registry::digest(
        std::span<const unsigned char>(
            result.bytes.data(),
            RESERVATION_RETENTION_PROBE_IDENTITY_OFFSET));
    need(nonzero(result.nonce) && nonzero(result.identity));
    put_digest(result.bytes, RESERVATION_RETENTION_PROBE_IDENTITY_OFFSET,
               result.identity);
    return result;
}

Digest parse_reservation_retention_probe(
        const std::array<unsigned char,
            RESERVATION_RETENTION_PROBE_BYTES>& bytes,
        unsigned expected_role, std::int64_t expected_parent_pid,
        std::int64_t expected_child_pid,
        const std::array<Digest, 2>& expected_command_identities) {
    need(std::equal(RESERVATION_RETENTION_PROBE_MAGIC.begin(),
                    RESERVATION_RETENTION_PROBE_MAGIC.end(),
                    bytes.begin()) &&
         bytes[8] == 2 && bytes[9] == 4 &&
         bytes[10] == expected_role && bytes[11] == 2 &&
         get_u32(bytes, 12) == expected_parent_pid &&
         get_u32(bytes, 16) == expected_child_pid &&
         get_digest(bytes, 20) == expected_command_identities[0] &&
         get_digest(bytes, 52) == expected_command_identities[1] &&
         nonzero(get_digest(bytes, 84)) &&
         std::all_of(bytes.begin() + 148, bytes.end(),
                     [](unsigned char value) { return value == 0; }));
    const auto identity = get_digest(
        bytes, RESERVATION_RETENTION_PROBE_IDENTITY_OFFSET);
    need(nonzero(identity) &&
         identity == identity_registry::digest(
             std::span<const unsigned char>(
                 bytes.data(),
                 RESERVATION_RETENTION_PROBE_IDENTITY_OFFSET)));
    return identity;
}

std::array<unsigned char, RESERVATION_RETENTION_ACK_BYTES>
make_reservation_retention_ack(
        unsigned role, std::int64_t parent_pid, std::int64_t child_pid,
        const std::array<Digest, 2>& command_identities,
        const std::array<std::uint8_t, 2>& descriptor_counts,
        const Digest& probe_identity) {
    need(role < ROLE_COUNT && parent_pid > 1 && child_pid > 1 &&
         nonzero(command_identities[0]) &&
         nonzero(command_identities[1]) && nonzero(probe_identity));
    std::array<unsigned char, RESERVATION_RETENTION_ACK_BYTES> result{};
    std::copy(RESERVATION_RETENTION_ACK_MAGIC.begin(),
              RESERVATION_RETENTION_ACK_MAGIC.end(), result.begin());
    result[8] = 2;
    result[9] = 5;
    result[10] = static_cast<unsigned char>(role);
    result[11] = 2;
    put_u32(result, 12, static_cast<std::uint32_t>(parent_pid));
    put_u32(result, 16, static_cast<std::uint32_t>(child_pid));
    put_digest(result, 20, command_identities[0]);
    put_digest(result, 52, command_identities[1]);
    result[84] = descriptor_counts[0];
    result[85] = descriptor_counts[1];
    put_digest(result, 88, probe_identity);
    put_digest(result, RESERVATION_RETENTION_ACK_IDENTITY_OFFSET,
               identity_registry::digest(std::span<const unsigned char>(
                   result.data(),
                   RESERVATION_RETENTION_ACK_IDENTITY_OFFSET)));
    return result;
}

void parse_reservation_retention_ack(
        const std::array<unsigned char,
            RESERVATION_RETENTION_ACK_BYTES>& bytes,
        unsigned expected_role, std::int64_t expected_parent_pid,
        std::int64_t expected_child_pid,
        const std::array<Digest, 2>& expected_command_identities,
        const std::array<std::uint8_t, 2>& expected_descriptor_counts,
        const Digest& expected_probe_identity) {
    need(std::equal(RESERVATION_RETENTION_ACK_MAGIC.begin(),
                    RESERVATION_RETENTION_ACK_MAGIC.end(),
                    bytes.begin()) &&
         bytes[8] == 2 && bytes[9] == 5 &&
         bytes[10] == expected_role && bytes[11] == 2 &&
         get_u32(bytes, 12) == expected_parent_pid &&
         get_u32(bytes, 16) == expected_child_pid &&
         get_digest(bytes, 20) == expected_command_identities[0] &&
         get_digest(bytes, 52) == expected_command_identities[1] &&
         bytes[84] == expected_descriptor_counts[0] &&
         bytes[85] == expected_descriptor_counts[1] &&
         bytes[86] == 0 && bytes[87] == 0 &&
         get_digest(bytes, 88) == expected_probe_identity &&
         std::all_of(bytes.begin() + 152, bytes.end(),
                     [](unsigned char value) { return value == 0; }));
    const auto identity = get_digest(
        bytes, RESERVATION_RETENTION_ACK_IDENTITY_OFFSET);
    need(nonzero(identity) &&
         identity == identity_registry::digest(
             std::span<const unsigned char>(
                 bytes.data(),
                 RESERVATION_RETENTION_ACK_IDENTITY_OFFSET)));
}

struct Offer {
    std::array<unsigned char, OFFER_BYTES> bytes{};
    Digest nonce{};
    Digest identity{};
};

Offer make_offer(const PlanState& plan, unsigned role,
                 std::int64_t parent_pid) {
    need(role < ROLE_COUNT && parent_pid > 1 &&
         parent_pid <= std::numeric_limits<std::uint32_t>::max());
    Offer result;
    std::copy(OFFER_MAGIC.begin(), OFFER_MAGIC.end(), result.bytes.begin());
    result.bytes[8] = 1;
    result.bytes[9] = static_cast<unsigned char>(role);
    result.bytes[10] = static_cast<unsigned char>(plan.value.round);
    std::uint8_t count = 0;
    const auto descriptors = fixed_fds(plan.value.round, role, count);
    result.bytes[11] = count;
    put_u32(result.bytes, 12, static_cast<std::uint32_t>(parent_pid));
    put_u32(result.bytes, 16, static_cast<std::uint32_t>(descriptors[0]));
    put_u32(result.bytes, 20, static_cast<std::uint32_t>(descriptors[1]));
    const auto& binding = plan.value.roles[role];
    put_digest(result.bytes, 24, plan.value.authority_identity);
    put_digest(result.bytes, 56, plan.value.supervisor_session);
    put_digest(result.bytes, 88, binding.party_session);
    put_digest(result.bytes, 120, binding.service_identity);
    put_digest(result.bytes, 152, binding.driver_selection_identity);
    put_digest(result.bytes, 184, plan.value.capture_plan_identity);
    put_digest(result.bytes, 216, plan.value.capture_source_identity);
    put_digest(result.bytes, 248, plan.value.capture_build_identity);
    put_digest(result.bytes, 280, plan.value.capture_launcher_identity);
    put_digest(result.bytes, 312, plan.identity);
    result.nonce = random_nonce();
    put_digest(result.bytes, 344, result.nonce);
    result.identity = identity_registry::digest(
        std::span<const unsigned char>(result.bytes.data(),
                                       OFFER_IDENTITY_OFFSET));
    put_digest(result.bytes, OFFER_IDENTITY_OFFSET, result.identity);
    return result;
}

struct ParsedOffer {
    unsigned role;
    unsigned round;
    std::int64_t parent_pid;
    std::array<int, 2> fixed_descriptors;
    std::uint8_t fixed_count;
    Digest nonce;
    Digest identity;
};

ParsedOffer parse_offer(
        const std::array<unsigned char, OFFER_BYTES>& bytes,
        const PlanState& plan, unsigned expected_role,
        std::int64_t expected_parent_pid) {
    need(std::equal(OFFER_MAGIC.begin(), OFFER_MAGIC.end(), bytes.begin()) &&
         bytes[8] == 1 && bytes[9] == expected_role &&
         bytes[10] == plan.value.round && expected_role < ROLE_COUNT &&
         get_u32(bytes, 12) == expected_parent_pid);
    std::uint8_t count = 0;
    const auto descriptors = fixed_fds(plan.value.round, expected_role, count);
    need(bytes[11] == count &&
         static_cast<int>(get_u32(bytes, 16)) == descriptors[0] &&
         static_cast<int>(get_u32(bytes, 20)) == descriptors[1]);
    const auto& binding = plan.value.roles[expected_role];
    need(get_digest(bytes, 24) == plan.value.authority_identity &&
         get_digest(bytes, 56) == plan.value.supervisor_session &&
         get_digest(bytes, 88) == binding.party_session &&
         get_digest(bytes, 120) == binding.service_identity &&
         get_digest(bytes, 152) == binding.driver_selection_identity &&
         get_digest(bytes, 184) == plan.value.capture_plan_identity &&
         get_digest(bytes, 216) == plan.value.capture_source_identity &&
         get_digest(bytes, 248) == plan.value.capture_build_identity &&
         get_digest(bytes, 280) == plan.value.capture_launcher_identity &&
         get_digest(bytes, 312) == plan.identity);
    const auto nonce = get_digest(bytes, 344);
    const auto identity = get_digest(bytes, OFFER_IDENTITY_OFFSET);
    need(nonzero(nonce) && nonzero(identity) &&
         identity == identity_registry::digest(
             std::span<const unsigned char>(bytes.data(),
                                             OFFER_IDENTITY_OFFSET)));
    return {expected_role, plan.value.round, expected_parent_pid,
            descriptors, count, nonce, identity};
}

std::array<unsigned char, ACK_BYTES> make_ack(
        const ParsedOffer& offer, std::int64_t child_pid) {
    need(child_pid > 1 &&
         child_pid <= std::numeric_limits<std::uint32_t>::max());
    std::array<unsigned char, ACK_BYTES> result{};
    std::copy(ACK_MAGIC.begin(), ACK_MAGIC.end(), result.begin());
    result[8] = 2;
    result[9] = static_cast<unsigned char>(offer.role);
    result[10] = static_cast<unsigned char>(offer.round);
    result[11] = offer.fixed_count;
    put_u32(result, 12, static_cast<std::uint32_t>(offer.parent_pid));
    put_u32(result, 16, static_cast<std::uint32_t>(child_pid));
    put_u32(result, 20,
            static_cast<std::uint32_t>(offer.fixed_descriptors[0]));
    put_u32(result, 24,
            static_cast<std::uint32_t>(offer.fixed_descriptors[1]));
    put_digest(result, 28, offer.identity);
    put_digest(result, 60, offer.nonce);
    const auto identity = identity_registry::digest(
        std::span<const unsigned char>(result.data(), ACK_IDENTITY_OFFSET));
    put_digest(result, ACK_IDENTITY_OFFSET, identity);
    return result;
}

void send_packet(int fd, std::span<const unsigned char> bytes) {
    ssize_t count;
    do {
        count = ::send(fd, bytes.data(), bytes.size(), MSG_NOSIGNAL);
    } while (count < 0 && errno == EINTR);
    need(count == static_cast<ssize_t>(bytes.size()));
}

void send_packet_with_fds(
        int fd, std::span<const unsigned char> bytes,
        std::span<const int> descriptors) {
    need(!descriptors.empty() && descriptors.size() <= 4);
    std::array<unsigned char, CMSG_SPACE(4 * sizeof(int))> control{};
    struct iovec iov{
        const_cast<unsigned char*>(bytes.data()), bytes.size()};
    struct msghdr message{};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = CMSG_SPACE(
        descriptors.size() * sizeof(int));
    auto* header = CMSG_FIRSTHDR(&message);
    need(header != nullptr);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(descriptors.size() * sizeof(int));
    std::memcpy(
        CMSG_DATA(header), descriptors.data(),
        descriptors.size() * sizeof(int));
    ssize_t count;
    do {
        count = ::sendmsg(fd, &message, MSG_NOSIGNAL);
    } while (count < 0 && errno == EINTR);
    need(count == static_cast<ssize_t>(bytes.size()));
}

struct ReceivedReservationPacket final {
    std::array<unsigned char, RESERVATION_COMMAND_BYTES> bytes{};
    std::array<UniqueFd, 4> descriptors{};
    std::uint8_t descriptor_count{};
    pid_t sender_pid{-1};
    uid_t sender_uid{};
    gid_t sender_gid{};
};

ReceivedReservationPacket receive_reservation_packet(
        int fd, std::int64_t expected_pid) {
    need(fd >= 0 && expected_pid > 1);
    struct pollfd watched{fd, POLLIN, 0};
    int ready;
    do {
        ready = ::poll(&watched, 1, 30000);
    } while (ready < 0 && errno == EINTR);
    need(ready == 1 && (watched.revents & (POLLIN | POLLHUP)) != 0 &&
         (watched.revents & (POLLERR | POLLNVAL)) == 0);

    ReceivedReservationPacket result;
    std::array<unsigned char,
        CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(4 * sizeof(int))>
        control{};
    struct iovec iov{result.bytes.data(), result.bytes.size()};
    struct msghdr message{};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t count;
    do {
        count = ::recvmsg(fd, &message, MSG_CMSG_CLOEXEC);
    } while (count < 0 && errno == EINTR);

    const struct ucred* credentials = nullptr;
    unsigned credential_count = 0;
    unsigned rights_header_count = 0;
    for (auto* header = CMSG_FIRSTHDR(&message); header != nullptr;
         header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level == SOL_SOCKET &&
            header->cmsg_type == SCM_CREDENTIALS) {
            need(header->cmsg_len == CMSG_LEN(sizeof(struct ucred)));
            credentials = reinterpret_cast<const struct ucred*>(
                CMSG_DATA(header));
            ++credential_count;
            continue;
        }
        need(header->cmsg_level == SOL_SOCKET &&
             header->cmsg_type == SCM_RIGHTS &&
             header->cmsg_len >= CMSG_LEN(sizeof(int)));
        ++rights_header_count;
        const std::size_t descriptor_bytes =
            header->cmsg_len - CMSG_LEN(0);
        need(descriptor_bytes % sizeof(int) == 0);
        const auto descriptor_count = descriptor_bytes / sizeof(int);
        need(descriptor_count > 0 &&
             descriptor_count <= result.descriptors.size() &&
             result.descriptor_count + descriptor_count <=
                 result.descriptors.size());
        const auto* received = reinterpret_cast<const int*>(
            CMSG_DATA(header));
        for (std::size_t index = 0; index < descriptor_count; ++index)
            result.descriptors[result.descriptor_count++] =
                UniqueFd(received[index]);
    }
    need(count == static_cast<ssize_t>(result.bytes.size()) &&
         (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0 &&
         credential_count == 1 && credentials != nullptr &&
         credentials->pid == expected_pid &&
         credentials->uid == ::geteuid() &&
         credentials->gid == ::getegid() &&
         rights_header_count <= 1);
    result.sender_pid = credentials->pid;
    result.sender_uid = credentials->uid;
    result.sender_gid = credentials->gid;
    return result;
}

struct RetainedReservationActivation final {
    std::array<unsigned char, RESERVATION_COMMAND_BYTES> command_bytes{};
    std::array<UniqueFd, 4> descriptors{};
    std::uint8_t descriptor_count{};
    ParsedReservationActivationCommand parsed{};
    pid_t sender_pid{-1};
    uid_t sender_uid{};
    gid_t sender_gid{};
    std::int64_t parent_pid{-1};
    std::int64_t child_pid{-1};
    unsigned round{};
    unsigned role{};
};

ParsedReservationActivationCommand validate_retained_reservation_activation(
        const RetainedReservationActivation& retained) {
    need(retained.parent_pid > 1 && retained.child_pid > 1 &&
         (retained.round == 1 || retained.round == 2) &&
         retained.role < ROLE_COUNT &&
         retained.sender_pid == retained.parent_pid &&
         retained.sender_uid == ::geteuid() &&
         retained.sender_gid == ::getegid() &&
         retained.descriptor_count ==
             retained.parsed.capture_descriptor_count +
                 retained.parsed.state_descriptor_count);
    std::array<int, 4> raw{{-1, -1, -1, -1}};
    for (unsigned index = 0; index < retained.descriptor_count; ++index) {
        raw[index] = retained.descriptors[index].get();
        need(raw[index] >= 0);
    }
    const auto reparsed = parse_reservation_activation_command(
        retained.command_bytes, retained.round, retained.role,
        retained.parent_pid, retained.child_pid,
        std::span<const int>(raw.data(), retained.descriptor_count));
    need(reparsed == retained.parsed);
    return reparsed;
}

RetainedReservationActivation retain_reservation_activation(
        ReceivedReservationPacket&& packet, unsigned round, unsigned role,
        std::int64_t parent_pid, std::int64_t child_pid) {
    RetainedReservationActivation retained;
    retained.command_bytes = packet.bytes;
    retained.descriptor_count = packet.descriptor_count;
    retained.sender_pid = packet.sender_pid;
    retained.sender_uid = packet.sender_uid;
    retained.sender_gid = packet.sender_gid;
    retained.parent_pid = parent_pid;
    retained.child_pid = child_pid;
    retained.round = round;
    retained.role = role;
    for (unsigned index = 0; index < packet.descriptor_count; ++index)
        retained.descriptors[index] = std::move(packet.descriptors[index]);
    std::array<int, 4> raw{{-1, -1, -1, -1}};
    for (unsigned index = 0; index < retained.descriptor_count; ++index)
        raw[index] = retained.descriptors[index].get();
    retained.parsed = parse_reservation_activation_command(
        retained.command_bytes, round, role, parent_pid, child_pid,
        std::span<const int>(raw.data(), retained.descriptor_count));
    (void)validate_retained_reservation_activation(retained);
    return retained;
}

template<std::size_t Size>
std::array<unsigned char, Size> receive_packet(
        int fd, std::int64_t expected_pid) {
    need(fd >= 0 && expected_pid > 1);
    struct pollfd watched{fd, POLLIN, 0};
    int ready;
    do {
        ready = ::poll(&watched, 1, 30000);
    } while (ready < 0 && errno == EINTR);
    need(ready == 1 && (watched.revents & (POLLIN | POLLHUP)) != 0 &&
         (watched.revents & (POLLERR | POLLNVAL)) == 0);

    std::array<unsigned char, Size> result{};
    std::array<unsigned char, CMSG_SPACE(sizeof(struct ucred))> control{};
    struct iovec iov{result.data(), result.size()};
    struct msghdr message{};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t count;
    do {
        count = ::recvmsg(fd, &message, 0);
    } while (count < 0 && errno == EINTR);
    need(count == static_cast<ssize_t>(result.size()) &&
         (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0);

    const struct ucred* credentials = nullptr;
    unsigned credential_count = 0;
    for (auto* header = CMSG_FIRSTHDR(&message); header != nullptr;
         header = CMSG_NXTHDR(&message, header)) {
        need(header->cmsg_level == SOL_SOCKET &&
             header->cmsg_type == SCM_CREDENTIALS &&
             header->cmsg_len == CMSG_LEN(sizeof(struct ucred)));
        credentials = reinterpret_cast<const struct ucred*>(
            CMSG_DATA(header));
        ++credential_count;
    }
    need(credential_count == 1 && credentials != nullptr &&
         credentials->pid == expected_pid &&
         credentials->uid == ::geteuid() &&
         credentials->gid == ::getegid());
    return result;
}

std::vector<unsigned char> receive_packet(
        int fd, std::size_t exact_bytes, std::int64_t expected_pid) {
    need(fd >= 0 && expected_pid > 1 && exact_bytes > 0 &&
         exact_bytes <= COMPLETION_HEADER_BYTES +
                            MAX_COMPLETION_PAYLOAD_BYTES);
    struct pollfd watched{fd, POLLIN, 0};
    int ready;
    do {
        ready = ::poll(&watched, 1, 30000);
    } while (ready < 0 && errno == EINTR);
    need(ready == 1 && (watched.revents & (POLLIN | POLLHUP)) != 0 &&
         (watched.revents & (POLLERR | POLLNVAL)) == 0);

    std::vector<unsigned char> result(exact_bytes);
    std::array<unsigned char, CMSG_SPACE(sizeof(struct ucred))> control{};
    struct iovec iov{result.data(), result.size()};
    struct msghdr message{};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t count;
    do {
        count = ::recvmsg(fd, &message, 0);
    } while (count < 0 && errno == EINTR);
    need(count == static_cast<ssize_t>(result.size()) &&
         (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0);

    const struct ucred* credentials = nullptr;
    unsigned credential_count = 0;
    for (auto* header = CMSG_FIRSTHDR(&message); header != nullptr;
         header = CMSG_NXTHDR(&message, header)) {
        need(header->cmsg_level == SOL_SOCKET &&
             header->cmsg_type == SCM_CREDENTIALS &&
             header->cmsg_len == CMSG_LEN(sizeof(struct ucred)));
        credentials = reinterpret_cast<const struct ucred*>(
            CMSG_DATA(header));
        ++credential_count;
    }
    need(credential_count == 1 && credentials != nullptr &&
         credentials->pid == expected_pid &&
         credentials->uid == ::geteuid() &&
         credentials->gid == ::getegid());
    return result;
}

void require_completion_eof(int fd) {
    struct pollfd watched{fd, POLLIN | POLLRDHUP, 0};
    int ready;
    do {
        ready = ::poll(&watched, 1, 30000);
    } while (ready < 0 && errno == EINTR);
    need(ready == 1 &&
         (watched.revents & (POLLHUP | POLLRDHUP)) != 0 &&
         (watched.revents & (POLLERR | POLLNVAL)) == 0);

    unsigned char extra = 0;
    std::array<unsigned char, CMSG_SPACE(sizeof(struct ucred))> control{};
    struct iovec iov{&extra, 1};
    struct msghdr message{};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t count;
    do {
        count = ::recvmsg(fd, &message, 0);
    } while (count < 0 && errno == EINTR);
    // A zero-length SOCK_SEQPACKET record also returns zero.  SO_PASSCRED
    // attaches SCM_CREDENTIALS to such a record, whereas genuine peer closure
    // has no record and therefore no ancillary sender.  Require both kernel
    // hangup state and the absence of any credentialed frame.
    need(count == 0 &&
         (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0 &&
         CMSG_FIRSTHDR(&message) == nullptr);
}

std::vector<unsigned char> completion_packet(
        const detail::RoleCompletionBinding& binding,
        const Digest& payload_type,
        std::span<const unsigned char> payload) {
    need(binding.role < ROLE_COUNT &&
         (binding.round == 1 || binding.round == 2) &&
         binding.trial ==
             RegisteredCapturePlanRosterBridge::trial_identity(
                 binding.capture_trial_id) &&
         binding.parent_pid > 1 && binding.child_pid > 1 &&
         binding.parent_pid != binding.child_pid && nonzero(payload_type) &&
         !payload.empty() && payload.size() <= MAX_COMPLETION_PAYLOAD_BYTES);
    for (const auto* field : {
             &binding.fork_plan_identity, &binding.offer_identity,
             &binding.ack_identity, &binding.channel_nonce,
             &binding.fresh_owner_issuance_identity,
             &binding.authority_identity, &binding.supervisor_session,
             &binding.party_session, &binding.service_identity,
             &binding.driver_selection_identity})
        need(nonzero(*field));
    std::vector<unsigned char> result(
        COMPLETION_HEADER_BYTES + payload.size());
    std::copy(
        COMPLETION_MAGIC.begin(), COMPLETION_MAGIC.end(), result.begin());
    result[8] = 3;
    result[9] = static_cast<unsigned char>(binding.role);
    result[10] = static_cast<unsigned char>(binding.round);
    result[11] = 0;
    put_u32(result, 12, static_cast<std::uint32_t>(binding.parent_pid));
    put_u32(result, 16, static_cast<std::uint32_t>(binding.child_pid));
    put_u32(result, 20, 1);
    put_u32(result, 24, static_cast<std::uint32_t>(payload.size()));
    put_digest(result, 28, payload_type);
    put_digest(result, 60, binding.fork_plan_identity);
    put_digest(result, 92, binding.offer_identity);
    put_digest(result, 124, binding.ack_identity);
    put_digest(result, 156, binding.channel_nonce);
    const auto payload_identity = identity_registry::digest(payload);
    put_digest(result, 188, payload_identity);
    std::copy(payload.begin(), payload.end(),
              result.begin() + COMPLETION_HEADER_BYTES);
    Bytes identity_input(
        result.begin(), result.begin() + COMPLETION_IDENTITY_OFFSET);
    add(identity_input, payload);
    put_digest(result, COMPLETION_IDENTITY_OFFSET,
               identity_registry::digest(identity_input));
    return result;
}

std::vector<unsigned char> parse_completion_packet(
        std::span<const unsigned char> packet,
        const detail::RoleCompletionBinding& binding,
        const Digest& expected_payload_type,
        std::size_t exact_payload_bytes) {
    need(packet.size() == COMPLETION_HEADER_BYTES + exact_payload_bytes &&
         exact_payload_bytes > 0 &&
         exact_payload_bytes <= MAX_COMPLETION_PAYLOAD_BYTES &&
         std::equal(COMPLETION_MAGIC.begin(), COMPLETION_MAGIC.end(),
                    packet.begin()) &&
         packet[8] == 3 && packet[9] == binding.role &&
         packet[10] == binding.round && packet[11] == 0 &&
         get_u32(packet, 12) == binding.parent_pid &&
         get_u32(packet, 16) == binding.child_pid &&
         get_u32(packet, 20) == 1 &&
         get_u32(packet, 24) == exact_payload_bytes &&
         get_digest(packet, 28) == expected_payload_type &&
         get_digest(packet, 60) == binding.fork_plan_identity &&
         get_digest(packet, 92) == binding.offer_identity &&
         get_digest(packet, 124) == binding.ack_identity &&
         get_digest(packet, 156) == binding.channel_nonce);
    const auto payload = packet.subspan(COMPLETION_HEADER_BYTES);
    need(get_digest(packet, 188) == identity_registry::digest(payload));
    Bytes identity_input(
        packet.begin(), packet.begin() + COMPLETION_IDENTITY_OFFSET);
    add(identity_input, payload);
    need(get_digest(packet, COMPLETION_IDENTITY_OFFSET) ==
         identity_registry::digest(identity_input));
    return {payload.begin(), payload.end()};
}

void poison_completion_state(
        const std::shared_ptr<detail::ParentRoleCompletionState>& state)
        noexcept {
    if (!state) return;
    try {
        std::lock_guard guard(state->mutex);
        state->poisoned = true;
    } catch (...) {
    }
}

void mark_completion(
        const std::shared_ptr<detail::ParentRoleCompletionState>& state,
        unsigned role) {
    need(state != nullptr && role < ROLE_COUNT);
    std::lock_guard guard(state->mutex);
    need(!state->poisoned && !state->completed[role]);
    state->completed[role] = true;
}

PublicParentRoleAcknowledgement parse_ack(
        const std::array<unsigned char, ACK_BYTES>& bytes,
        const Offer& offer, const PlanState& plan,
        unsigned role, std::int64_t parent_pid, std::int64_t child_pid) {
    need(std::equal(ACK_MAGIC.begin(), ACK_MAGIC.end(), bytes.begin()) &&
         bytes[8] == 2 && bytes[9] == role &&
         bytes[10] == plan.value.round &&
         get_u32(bytes, 12) == parent_pid &&
         get_u32(bytes, 16) == child_pid);
    std::uint8_t count = 0;
    const auto descriptors = fixed_fds(plan.value.round, role, count);
    need(bytes[11] == count &&
         static_cast<int>(get_u32(bytes, 20)) == descriptors[0] &&
         static_cast<int>(get_u32(bytes, 24)) == descriptors[1] &&
         get_digest(bytes, 28) == offer.identity &&
         get_digest(bytes, 60) == offer.nonce);
    const auto ack_identity = get_digest(bytes, ACK_IDENTITY_OFFSET);
    need(nonzero(ack_identity) &&
         ack_identity == identity_registry::digest(
             std::span<const unsigned char>(bytes.data(),
                                             ACK_IDENTITY_OFFSET)));
    return {
        .role = role,
        .round = plan.value.round,
        .parent_pid = parent_pid,
        .child_pid = child_pid,
        .fork_plan_identity = plan.identity,
        .offer_identity = offer.identity,
        .ack_identity = ack_identity,
    };
}

void close_fixed_capture_descriptors() noexcept {
    for (int fd = 20;
         fd <= projection_route::ROLE0_PROJECTION_ROUTE_FIXED_FD; ++fd) {
        int copy = fd;
        close_if_open(copy);
    }
}

void install_role_descriptors(
        PlanState& plan, unsigned role) {
    validate_source_fds(plan);
    close_fixed_capture_descriptors();
    if (role == 0) {
        need(::dup2(plan.source_fds[0], plan.endpoints[0].fixed_fd) ==
                 plan.endpoints[0].fixed_fd &&
             ::dup2(plan.source_fds[1], plan.endpoints[1].fixed_fd) ==
                 plan.endpoints[1].fixed_fd);
    } else if (role == 1) {
        need(::dup2(plan.source_fds[2], plan.endpoints[2].fixed_fd) ==
             plan.endpoints[2].fixed_fd);
    } else {
        need(role == 2);
    }
    for (auto& source : plan.source_fds) close_if_open(source);
}

int open_pidfd(pid_t pid) {
#ifdef SYS_pidfd_open
    int result;
    do {
        result = static_cast<int>(::syscall(SYS_pidfd_open, pid, 0));
    } while (result < 0 && errno == EINTR);
    need(result >= 0);
    const int descriptor_flags = ::fcntl(result, F_GETFD);
    if (descriptor_flags < 0 ||
        (descriptor_flags & FD_CLOEXEC) == 0) {
        close_if_open(result);
        refuse();
    }
    return result;
#else
    (void)pid;
    refuse();
#endif
}

bool signal_pidfd(int pidfd, int signal) noexcept {
#ifdef SYS_pidfd_send_signal
    if (pidfd < 0) return false;
    long result;
    do {
        result = ::syscall(
            SYS_pidfd_send_signal, pidfd, signal, nullptr, 0);
    } while (result < 0 && errno == EINTR);
    return result == 0 || (result < 0 && errno == ESRCH);
#else
    (void)pidfd;
    (void)signal;
    return false;
#endif
}

bool observe_pidfd_exit(int pidfd) noexcept {
    if (pidfd < 0) return false;
    struct pollfd selected{
        .fd = pidfd,
        .events = static_cast<short>(POLLIN),
        .revents = 0,
    };
    int result;
    do {
        result = ::poll(&selected, 1, -1);
    } while (result < 0 && errno == EINTR);
    return result == 1 &&
        (selected.revents & (POLLIN | POLLHUP)) != 0 &&
        (selected.revents & (POLLERR | POLLNVAL)) == 0;
}

enum class WaitIdResult : std::uint8_t { Success, NoChild, Error };

WaitIdResult waitid_pidfd(
        int pidfd, siginfo_t& information, int options) noexcept {
    std::memset(&information, 0, sizeof(information));
    int result;
    do {
        result = ::waitid(
            P_PIDFD, static_cast<id_t>(pidfd), &information, options);
    } while (result < 0 && errno == EINTR);
    if (result == 0) return WaitIdResult::Success;
    if (errno == ECHILD) return WaitIdResult::NoChild;
    return WaitIdResult::Error;
}

struct NormalizedChildExit final {
    bool pidfd_exit_observed{};
    bool wait_status_available{};
    bool pid_identity_exact{};
    int exit_code{-1};
    int term_signal{};
};

bool normalize_siginfo(
        const siginfo_t& information,
        NormalizedChildExit& result) noexcept {
    if (information.si_code == CLD_EXITED) {
        result.exit_code = information.si_status;
        result.term_signal = 0;
        return information.si_status >= 0;
    }
    if (information.si_code == CLD_KILLED ||
        information.si_code == CLD_DUMPED) {
        result.exit_code = -1;
        result.term_signal = information.si_status;
        return information.si_status > 0;
    }
    return false;
}

bool status_matches_siginfo(
        int status, const siginfo_t& information) noexcept {
    if (information.si_code == CLD_EXITED)
        return WIFEXITED(status) &&
            WEXITSTATUS(status) == information.si_status;
    if (information.si_code == CLD_KILLED)
        return WIFSIGNALED(status) &&
            WTERMSIG(status) == information.si_status
#ifdef WCOREDUMP
            && !WCOREDUMP(status)
#endif
            ;
    if (information.si_code == CLD_DUMPED)
        return WIFSIGNALED(status) &&
            WTERMSIG(status) == information.si_status
#ifdef WCOREDUMP
            && WCOREDUMP(status)
#endif
            ;
    return false;
}

NormalizedChildExit settle_pidfd_child(
        int pidfd, std::int64_t fork_pid) noexcept {
    NormalizedChildExit result;
    result.pidfd_exit_observed = observe_pidfd_exit(pidfd);
    if (!result.pidfd_exit_observed) return result;

    siginfo_t observed{};
    if (waitid_pidfd(pidfd, observed, WEXITED | WNOWAIT) !=
            WaitIdResult::Success)
        return result;

    NormalizedChildExit normalized = result;
    if (!normalize_siginfo(observed, normalized)) return result;
    normalized.pid_identity_exact = fork_pid > 1 &&
        observed.si_pid == static_cast<pid_t>(fork_pid);

    if (!normalized.pid_identity_exact) {
        // The pidfd still names the exact child. Reap through that handle and
        // never consult a substituted raw PID.
        siginfo_t consumed{};
        if (waitid_pidfd(pidfd, consumed, WEXITED) ==
                WaitIdResult::Success &&
            consumed.si_pid == observed.si_pid &&
            consumed.si_code == observed.si_code &&
            consumed.si_status == observed.si_status)
            normalized.wait_status_available = true;
        return normalized;
    }

    int status = 0;
    pid_t waited;
    do {
        waited = ::waitpid(static_cast<pid_t>(fork_pid), &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited == static_cast<pid_t>(fork_pid) &&
        status_matches_siginfo(status, observed)) {
        normalized.wait_status_available = true;
        return normalized;
    }

    // waitid(WNOWAIT) proved the exact target, but a failed cross-check is not
    // exact exit evidence. Attempt an exact pidfd reap and retain unavailable.
    siginfo_t consumed{};
    (void)waitid_pidfd(pidfd, consumed, WEXITED);
    normalized.wait_status_available = false;
    normalized.exit_code = -1;
    normalized.term_signal = 0;
    return normalized;
}

void reap_unpinned_children(
        std::array<std::int64_t, 3>& pids) noexcept {
    for (auto& raw_pid : pids) {
        if (raw_pid > 1) {
            int status = 0;
            pid_t waited;
            do {
                waited = ::waitpid(
                    static_cast<pid_t>(raw_pid), &status, 0);
            } while (waited < 0 && errno == EINTR);
        }
        raw_pid = -1;
    }
}

void settle_partially_pinned_children(
        std::array<std::int64_t, 3>& pids,
        std::array<UniqueFd, 3>& pidfds) noexcept {
    for (const auto& pidfd : pidfds)
        if (pidfd.get() >= 0)
            (void)signal_pidfd(pidfd.get(), SIGKILL);
    for (unsigned role = 0; role < ROLE_COUNT; ++role) {
        if (pidfds[role].get() >= 0) {
            (void)settle_pidfd_child(pidfds[role].get(), pids[role]);
            pidfds[role].reset();
            pids[role] = -1;
        } else if (pids[role] > 1) {
            int status = 0;
            pid_t waited;
            do {
                waited = ::waitpid(
                    static_cast<pid_t>(pids[role]), &status, 0);
            } while (waited < 0 && errno == EINTR);
            pids[role] = -1;
        }
    }
}

} // namespace

namespace detail {

struct ChildProcessSet final {
    struct Record final {
        std::int64_t fork_pid{-1};
        int pidfd{-1};
        NormalizedChildExit exit{};
    };

    std::array<Record, 3> records_{};
    std::mutex mutex_;
    bool settled_{};

    ChildProcessSet(
            const std::array<std::int64_t, 3>& pids,
            const std::array<int, 3>& borrowed_pidfds) noexcept {
        for (unsigned role = 0; role < ROLE_COUNT; ++role) {
            records_[role].fork_pid = pids[role];
            records_[role].pidfd = borrowed_pidfds[role];
        }
    }
    ChildProcessSet(const ChildProcessSet&) = delete;
    ChildProcessSet& operator=(const ChildProcessSet&) = delete;
    ~ChildProcessSet() { (void)settle(true); }

    std::int64_t fork_pid(unsigned role) const noexcept {
        return role < ROLE_COUNT ? records_[role].fork_pid : -1;
    }
    std::array<std::int64_t, 3> fork_pids() const noexcept {
        return {
            records_[0].fork_pid,
            records_[1].fork_pid,
            records_[2].fork_pid,
        };
    }

    bool preidentity_ready() noexcept {
        std::lock_guard guard(mutex_);
        if (settled_) return false;
        std::set<std::int64_t> pids;
        for (const auto& record : records_) {
            if (record.fork_pid <= 1 || record.pidfd < 0 ||
                !pids.insert(record.fork_pid).second)
                return false;
            const int flags = ::fcntl(record.pidfd, F_GETFD);
            if (flags < 0 || (flags & FD_CLOEXEC) == 0) return false;
            struct pollfd watched{record.pidfd, POLLIN, 0};
            int ready;
            do {
                ready = ::poll(&watched, 1, 0);
            } while (ready < 0 && errno == EINTR);
            if (ready != 0) return false;
        }
        return true;
    }

    std::array<NormalizedChildExit, 3> settle(bool terminate) noexcept {
        std::lock_guard guard(mutex_);
        if (settled_) return {
            records_[0].exit, records_[1].exit, records_[2].exit};
        if (terminate)
            for (const auto& record : records_)
                if (record.pidfd >= 0)
                    (void)signal_pidfd(record.pidfd, SIGKILL);
        for (auto& record : records_) {
            if (record.pidfd >= 0)
                record.exit = settle_pidfd_child(
                    record.pidfd, record.fork_pid);
            close_if_open(record.pidfd);
        }
        settled_ = true;
        return {records_[0].exit, records_[1].exit, records_[2].exit};
    }

#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
    void replace_raw_pid_metadata(
            unsigned role, std::int64_t replacement) noexcept {
        std::lock_guard guard(mutex_);
        if (!settled_ && role < ROLE_COUNT && replacement > 1)
            records_[role].fork_pid = replacement;
    }
#endif
};

struct PersistentProcessReservationEpoch final {
    std::weak_ptr<ChildProcessSet> child_processes;

    explicit PersistentProcessReservationEpoch(
            const std::shared_ptr<ChildProcessSet>& selected)
        : child_processes(selected) {}
};

PersistentRoleExitEvidence::PersistentRoleExitEvidence(
        std::array<std::int64_t, 3> selected_child_pids,
        std::array<bool, 3> selected_pidfd_exit_observed,
        std::array<bool, 3> selected_wait_status_available,
        std::array<bool, 3> selected_pid_identity_exact,
        std::array<int, 3> selected_exit_codes,
        std::array<int, 3> selected_term_signals,
        std::array<PublicParentRoleForkCompletion, 2> selected_round_channels,
        Digest selected_process_session_identity)
    : child_pids(selected_child_pids),
      pidfd_exit_observed(selected_pidfd_exit_observed),
      wait_status_available(selected_wait_status_available),
      pid_identity_exact(selected_pid_identity_exact),
      exit_codes(selected_exit_codes),
      term_signals(selected_term_signals),
      round_channels(std::move(selected_round_channels)),
      process_session_identity(selected_process_session_identity) {
    const bool clean = all_children_exited_zero_value();
    for (auto& channel : round_channels)
        channel.all_children_exited_zero = clean;
}

PersistentRoleExitEvidence::PersistentRoleExitEvidence(
        PersistentRoleExitEvidence&& other) noexcept
    : child_pids(std::exchange(
          other.child_pids,
          std::array<std::int64_t, 3>{{-1, -1, -1}})),
      pidfd_exit_observed(std::exchange(
          other.pidfd_exit_observed, std::array<bool, 3>{})),
      wait_status_available(std::exchange(
          other.wait_status_available, std::array<bool, 3>{})),
      pid_identity_exact(std::exchange(
          other.pid_identity_exact, std::array<bool, 3>{})),
      exit_codes(std::exchange(
          other.exit_codes, std::array<int, 3>{{-1, -1, -1}})),
      term_signals(std::exchange(
          other.term_signals, std::array<int, 3>{})),
      round_channels(std::exchange(
          other.round_channels,
          std::array<PublicParentRoleForkCompletion, 2>{})),
      process_session_identity(std::exchange(
          other.process_session_identity, Digest{})),
      live_(std::exchange(other.live_, false)) {}
PersistentRoleExitEvidence::~PersistentRoleExitEvidence() = default;

bool PersistentRoleExitEvidence::all_children_exited_zero_value()
        const noexcept {
    if (!live_) return false;
    for (unsigned role = 0; role < ROLE_COUNT; ++role)
        if (!pidfd_exit_observed[role] ||
            !wait_status_available[role] ||
            !pid_identity_exact[role] || exit_codes[role] != 0 ||
            term_signals[role] != 0)
            return false;
    return true;
}

PersistentRoleReservationAbortEvidence::
PersistentRoleReservationAbortEvidence(
        std::array<std::int64_t, 3> selected_child_pids,
        std::array<bool, 3> selected_pidfd_exit_observed,
        std::array<bool, 3> selected_wait_status_available,
        std::array<bool, 3> selected_pid_identity_exact,
        std::array<int, 3> selected_exit_codes,
        std::array<int, 3> selected_term_signals,
        std::array<std::array<bool, 3>, 2>
            selected_topology_preflight_acknowledged,
        std::array<bool, 3> selected_topology_retention_acknowledged,
        bool selected_pidfd_signal_used)
    : child_pids(selected_child_pids),
      pidfd_exit_observed(selected_pidfd_exit_observed),
      wait_status_available(selected_wait_status_available),
      pid_identity_exact(selected_pid_identity_exact),
      exit_codes(selected_exit_codes),
      term_signals(selected_term_signals),
      topology_preflight_acknowledged(
          selected_topology_preflight_acknowledged),
      topology_retention_acknowledged(
          selected_topology_retention_acknowledged),
      pidfd_signal_used(selected_pidfd_signal_used) {}

PersistentRoleReservationAbortEvidence::
PersistentRoleReservationAbortEvidence(
        PersistentRoleReservationAbortEvidence&& other) noexcept
    : child_pids(std::exchange(
          other.child_pids,
          std::array<std::int64_t, 3>{{-1, -1, -1}})),
      pidfd_exit_observed(std::exchange(
          other.pidfd_exit_observed, std::array<bool, 3>{})),
      wait_status_available(std::exchange(
          other.wait_status_available, std::array<bool, 3>{})),
      pid_identity_exact(std::exchange(
          other.pid_identity_exact, std::array<bool, 3>{})),
      exit_codes(std::exchange(
          other.exit_codes, std::array<int, 3>{{-1, -1, -1}})),
      term_signals(std::exchange(
          other.term_signals, std::array<int, 3>{})),
      topology_preflight_acknowledged(std::exchange(
          other.topology_preflight_acknowledged,
          std::array<std::array<bool, 3>, 2>{})),
      topology_retention_acknowledged(std::exchange(
          other.topology_retention_acknowledged,
          std::array<bool, 3>{})),
      pidfd_signal_used(std::exchange(other.pidfd_signal_used, false)),
      live_(std::exchange(other.live_, false)) {}

PersistentRoleReservationAbortEvidence::
~PersistentRoleReservationAbortEvidence() = default;

bool PersistentRoleReservationAbortEvidence::
topology_preflight_complete_value() const noexcept {
    if (!live_) return false;
    for (const auto& round : topology_preflight_acknowledged)
        if (!std::all_of(round.begin(), round.end(),
                         [](bool acknowledged) { return acknowledged; }))
            return false;
    return std::all_of(
        topology_retention_acknowledged.begin(),
        topology_retention_acknowledged.end(),
        [](bool acknowledged) { return acknowledged; });
}

bool PersistentRoleReservationAbortEvidence::all_children_settled_value()
        const noexcept {
    if (!live_) return false;
    for (unsigned role = 0; role < ROLE_COUNT; ++role)
        if (child_pids[role] <= 1 || !pidfd_exit_observed[role] ||
            !wait_status_available[role] || !pid_identity_exact[role] ||
            (exit_codes[role] < 0 && term_signals[role] <= 0))
            return false;
    return child_pids[0] != child_pids[1] &&
        child_pids[0] != child_pids[2] &&
        child_pids[1] != child_pids[2];
}

} // namespace detail

RegisteredTopologyReservationPermit::RegisteredTopologyReservationPermit(
        std::shared_ptr<const detail::PersistentProcessReservationEpoch>
            epoch) noexcept
    : epoch_(std::move(epoch)) {}

RegisteredTopologyReservationPermit::RegisteredTopologyReservationPermit(
        RegisteredTopologyReservationPermit&& other) noexcept
    : epoch_(std::move(other.epoch_)),
      live_(std::exchange(other.live_, false)) {}

RegisteredTopologyReservationPermit::~RegisteredTopologyReservationPermit() =
    default;

void RegisteredTopologyReservationPermit::
validate_for_topology_reservation() const {
    try {
        need(live_ && epoch_ != nullptr);
        const auto child_processes = epoch_->child_processes.lock();
        need(child_processes != nullptr &&
             child_processes->preidentity_ready());
    } catch (...) { refuse(); }
}

std::shared_ptr<const detail::PersistentProcessReservationEpoch>
RegisteredTopologyReservationPermit::
consume_for_topology_reservation() && {
    validate_for_topology_reservation();
    need(live_);
    live_ = false;
    return std::move(epoch_);
}

struct RegisteredPersistentRoleProcessReservation::Storage final {
    std::shared_ptr<detail::ChildProcessSet> child_processes;
    std::shared_ptr<const detail::PersistentProcessReservationEpoch>
        preidentity_epoch;
    std::array<std::array<int, 3>, 2> parent_fds{{
        {{-1, -1, -1}}, {{-1, -1, -1}}}};
    std::array<std::array<bool, 3>, 2>
        topology_preflight_acknowledged{};
    std::array<bool, 3> topology_retention_acknowledged{};
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
    int fail_ack_round{-1};
    int fail_ack_role{-1};
    ParentRoleReservationRetentionTestFault retention_fault{
        ParentRoleReservationRetentionTestFault::None};
#endif
    bool topology_preflight_attempted{};
    bool topology_permit_issued{};
    bool claimed{};

    ~Storage() {
        for (auto& round : parent_fds)
            for (auto& fd : round) close_if_open(fd);
        if (child_processes != nullptr)
            (void)child_processes->settle(true);
    }
};

RegisteredPersistentRoleProcessReservation::
RegisteredPersistentRoleProcessReservation(std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }
RegisteredPersistentRoleProcessReservation::
RegisteredPersistentRoleProcessReservation(
        RegisteredPersistentRoleProcessReservation&&) noexcept = default;
RegisteredPersistentRoleProcessReservation::
~RegisteredPersistentRoleProcessReservation() = default;

void RegisteredPersistentRoleProcessReservation::
validate_for_preidentity_ready() const {
    try {
        need(storage_ != nullptr && storage_->child_processes != nullptr &&
             storage_->preidentity_epoch != nullptr &&
             !storage_->claimed &&
             !storage_->topology_preflight_attempted &&
             storage_->topology_permit_issued &&
             storage_->child_processes->preidentity_ready());
        std::set<int> descriptors;
        for (const auto& round : storage_->parent_fds) {
            for (const int fd : round) {
                need(fd >= 64 && descriptors.insert(fd).second);
                const int flags = ::fcntl(fd, F_GETFD);
                int type = 0;
                socklen_t type_bytes = sizeof(type);
                int pass_credentials = 0;
                socklen_t pass_bytes = sizeof(pass_credentials);
                need(flags >= 0 && (flags & FD_CLOEXEC) != 0 &&
                     ::getsockopt(fd, SOL_SOCKET, SO_TYPE, &type,
                                  &type_bytes) == 0 &&
                     type_bytes == sizeof(type) &&
                     type == SOCK_SEQPACKET &&
                     ::getsockopt(fd, SOL_SOCKET, SO_PASSCRED,
                                  &pass_credentials, &pass_bytes) == 0 &&
                     pass_bytes == sizeof(pass_credentials) &&
                     pass_credentials == 1);
            }
        }
    } catch (...) { refuse(); }
}

const void* RegisteredPersistentRoleProcessReservation::
preidentity_epoch_token() const noexcept {
    if (storage_ == nullptr || storage_->claimed ||
        !storage_->topology_permit_issued)
        return nullptr;
    return storage_->preidentity_epoch.get();
}

std::int64_t RegisteredPersistentRoleProcessReservation::
child_pid_for_activation(unsigned role) const {
    try {
        need(storage_ != nullptr && storage_->child_processes != nullptr &&
             !storage_->claimed && role < ROLE_COUNT);
        return storage_->child_processes->fork_pid(role);
    } catch (...) { refuse(); }
}

RegisteredTopologyReservationPermit
RegisteredPersistentRoleProcessReservation::
issue_topology_reservation_permit() {
    try {
        need(storage_ != nullptr && storage_->child_processes != nullptr &&
             storage_->preidentity_epoch != nullptr &&
             !storage_->claimed &&
             !storage_->topology_preflight_attempted &&
             !storage_->topology_permit_issued &&
             storage_->child_processes->preidentity_ready());
        std::set<int> descriptors;
        for (const auto& round : storage_->parent_fds) {
            for (const int fd : round) {
                need(fd >= 64 && descriptors.insert(fd).second);
                const int flags = ::fcntl(fd, F_GETFD);
                int type = 0;
                socklen_t type_bytes = sizeof(type);
                int pass_credentials = 0;
                socklen_t pass_bytes = sizeof(pass_credentials);
                need(flags >= 0 && (flags & FD_CLOEXEC) != 0 &&
                     ::getsockopt(fd, SOL_SOCKET, SO_TYPE, &type,
                                  &type_bytes) == 0 &&
                     type_bytes == sizeof(type) &&
                     type == SOCK_SEQPACKET &&
                     ::getsockopt(fd, SOL_SOCKET, SO_PASSCRED,
                                  &pass_credentials, &pass_bytes) == 0 &&
                     pass_bytes == sizeof(pass_credentials) &&
                     pass_credentials == 1);
            }
        }
        RegisteredTopologyReservationPermit result(
            storage_->preidentity_epoch);
        storage_->topology_permit_issued = true;
        return result;
    } catch (...) { refuse(); }
}

void RegisteredPersistentRoleProcessReservation::preflight_capture_topology(
        std::array<int, 10>& writer_aliases,
        const std::array<std::uint64_t, 10>& endpoint_devices,
        const std::array<std::uint64_t, 10>& endpoint_inodes,
        const std::array<std::uint32_t, 10>& endpoint_types,
        TopologyPreflightState& state) {
    try {
        need(storage_ != nullptr && storage_->child_processes != nullptr &&
             !storage_->claimed &&
             !storage_->topology_preflight_attempted &&
             nonzero(state.reservation_identity) &&
             nonzero(state.activation_identity) &&
             nonzero(state.trial_identity));
        for (unsigned round = 0; round < 2; ++round) {
            need(state.child_state_writers[round] >= 0 &&
                 state.child_terminal_fds[round] >= 0 &&
                 state.state_devices[round] != 0 &&
                 state.state_inodes[round] != 0 &&
                 state.state_modes[round] != 0 &&
                 state.terminal_devices[round] != 0 &&
                 state.terminal_inodes[round] != 0 &&
                 state.terminal_types[round] == S_IFSOCK);
        }
        storage_->topology_preflight_attempted = true;
        std::array<std::array<ReservationActivationCommand, 3>, 2>
            commands{};
        const auto parent_pid = static_cast<std::int64_t>(::getpid());
        for (unsigned round = 0; round < 2; ++round)
            for (unsigned role = 0; role < ROLE_COUNT; ++role)
                commands[round][role] =
                    make_reservation_activation_command(
                        round + 1, role, writer_aliases,
                        endpoint_devices, endpoint_inodes, endpoint_types,
                        parent_pid,
                        storage_->child_processes->fork_pid(role),
                        state.child_state_writers,
                        state.child_terminal_fds,
                        state.state_devices, state.state_inodes,
                        state.state_modes, state.state_nlinks,
                        state.state_sizes, state.terminal_devices,
                        state.terminal_inodes, state.terminal_types,
                        state.reservation_identity,
                        state.activation_identity,
                        state.trial_identity);

#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
        inject_reservation_retention_fault(
            commands, storage_->retention_fault);
#endif

        for (unsigned round = 0; round < 2; ++round) {
            for (unsigned role = 0; role < ROLE_COUNT; ++role) {
                auto& command = commands[round][role];
                const auto descriptor_count = static_cast<unsigned>(
                    command.capture_descriptor_count +
                    command.state_descriptor_count);
                if (descriptor_count == 0) {
                    send_packet(
                        storage_->parent_fds[round][role], command.bytes);
                } else {
                    send_packet_with_fds(
                        storage_->parent_fds[round][role], command.bytes,
                        std::span<const int>(
                            command.descriptors.data(),
                            descriptor_count));
                    std::uint8_t count = 0;
                    const auto slots = reservation_topology_slots(
                        round + 1, role, count);
                    need(count == command.capture_descriptor_count);
                    for (unsigned index = 0; index < count; ++index)
                        close_if_open(writer_aliases[slots[index]]);
                    if (role == 1) {
                        close_if_open(state.child_state_writers[round]);
                        close_if_open(state.child_terminal_fds[round]);
                    }
                }
            }
        }

#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
        if (storage_->fail_ack_round >= 0 &&
            storage_->fail_ack_role >= 0)
            close_if_open(storage_->parent_fds[
                static_cast<unsigned>(storage_->fail_ack_round)][
                static_cast<unsigned>(storage_->fail_ack_role)]);
#endif

        for (unsigned round = 0; round < 2; ++round) {
            for (unsigned role = 0; role < ROLE_COUNT; ++role) {
                const auto ack = receive_packet<RESERVATION_ACK_BYTES>(
                    storage_->parent_fds[round][role],
                    storage_->child_processes->fork_pid(role));
                const auto& command = commands[round][role];
                parse_reservation_activation_ack(
                    ack, round + 1, role,
                    command.capture_descriptor_count,
                    command.state_descriptor_count,
                    parent_pid,
                    storage_->child_processes->fork_pid(role),
                    command.identity);
                storage_->topology_preflight_acknowledged[round][role] =
                    true;
                state.command_identities[round][role] = command.identity;
            }
        }

        std::array<ReservationRetentionProbe, 3> retention_probes{};
        for (unsigned role = 0; role < ROLE_COUNT; ++role) {
            std::array<Digest, 2> reported_command_identities{{
                commands[0][role].identity,
                commands[1][role].identity,
            }};
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
            if (storage_->retention_fault ==
                    ParentRoleReservationRetentionTestFault::
                        WrongParentReport &&
                role == 1)
                reported_command_identities[0] =
                    commands[0][0].identity;
#endif
            retention_probes[role] = make_reservation_retention_probe(
                role, parent_pid,
                storage_->child_processes->fork_pid(role),
                reported_command_identities);
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
            if (storage_->retention_fault ==
                    ParentRoleReservationRetentionTestFault::
                        ReplayActivationCommand &&
                role == 1) {
                send_packet(storage_->parent_fds[0][role],
                            commands[0][role].bytes);
                continue;
            }
#endif
            send_packet(storage_->parent_fds[0][role],
                        retention_probes[role].bytes);
        }

        for (unsigned role = 0; role < ROLE_COUNT; ++role) {
            const auto ack = receive_packet<
                RESERVATION_RETENTION_ACK_BYTES>(
                    storage_->parent_fds[0][role],
                    storage_->child_processes->fork_pid(role));
            const std::array<Digest, 2> command_identities{{
                commands[0][role].identity,
                commands[1][role].identity,
            }};
            const std::array<std::uint8_t, 2> descriptor_counts{{
                static_cast<std::uint8_t>(
                    commands[0][role].capture_descriptor_count +
                    commands[0][role].state_descriptor_count),
                static_cast<std::uint8_t>(
                    commands[1][role].capture_descriptor_count +
                    commands[1][role].state_descriptor_count),
            }};
            parse_reservation_retention_ack(
                ack, role, parent_pid,
                storage_->child_processes->fork_pid(role),
                command_identities, descriptor_counts,
                retention_probes[role].identity);
            state.retention_acknowledged[role] = true;
            storage_->topology_retention_acknowledged[role] = true;
        }
    } catch (...) { refuse(); }
}

struct RegisteredPersistentRoleSession::Storage final {
    std::shared_ptr<detail::ChildProcessSet> child_processes;
    std::unique_ptr<ParentRoleChildren> round1;
    std::unique_ptr<ParentRoleChildren> round2;
    std::array<int, 3> round2_parent_fds{{-1, -1, -1}};
    std::array<Offer, 3> round2_offers{};
    PublicParentRoleForkPlan round2_plan{};
    Digest round2_fork_plan_identity{};
    Digest round2_projection_route_identity{};
    Digest process_session_identity{};
    bool round2_activated{};
    bool trial_join_claimed{};
    bool waited{};

    ~Storage() {
        for (auto& fd : round2_parent_fds) close_if_open(fd);
        if (!waited && child_processes != nullptr)
            (void)child_processes->settle(true);
    }
};

RegisteredPersistentRoleSession::RegisteredPersistentRoleSession(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }
RegisteredPersistentRoleSession::RegisteredPersistentRoleSession(
        RegisteredPersistentRoleSession&&) noexcept = default;
RegisteredPersistentRoleSession::~RegisteredPersistentRoleSession() =
    default;

#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
void ParentRoleForkTestProcessBridge::replace_raw_pid_metadata(
        RegisteredPersistentRoleSession& session, unsigned role,
        std::int64_t replacement) {
    need(session.storage_ != nullptr &&
         session.storage_->child_processes != nullptr &&
         role < ROLE_COUNT && replacement > 1);
    session.storage_->child_processes->replace_raw_pid_metadata(
        role, replacement);
}

void ParentRoleForkTestProcessBridge::terminate_and_settle(
        RegisteredPersistentRoleSession& session) {
    need(session.storage_ != nullptr &&
         session.storage_->child_processes != nullptr);
    (void)session.storage_->child_processes->settle(true);
}

void ParentRoleForkTestProcessBridge::poison_role_channels(
        ParentRoleChildren& children) {
    children.poison_role_channels();
}

void ParentRoleForkTestProcessBridge::close_reservation_channel(
        RegisteredPersistentRoleProcessReservation& reservation,
        unsigned round, unsigned role) {
    need(reservation.storage_ != nullptr && round >= 1 && round <= 2 &&
         role < ROLE_COUNT && !reservation.storage_->claimed);
    close_if_open(reservation.storage_->parent_fds[round - 1][role]);
}

void ParentRoleForkTestProcessBridge::fail_reservation_ack_receive(
        RegisteredPersistentRoleProcessReservation& reservation,
        unsigned round, unsigned role) {
    need(reservation.storage_ != nullptr && round >= 1 && round <= 2 &&
         role < ROLE_COUNT && !reservation.storage_->claimed &&
         reservation.storage_->fail_ack_round < 0 &&
         reservation.storage_->fail_ack_role < 0);
    reservation.storage_->fail_ack_round = static_cast<int>(round - 1);
    reservation.storage_->fail_ack_role = static_cast<int>(role);
}

void ParentRoleForkTestProcessBridge::set_reservation_retention_fault(
        RegisteredPersistentRoleProcessReservation& reservation,
        ParentRoleReservationRetentionTestFault fault) {
    need(reservation.storage_ != nullptr &&
         !reservation.storage_->claimed &&
         !reservation.storage_->topology_preflight_attempted &&
         reservation.storage_->retention_fault ==
             ParentRoleReservationRetentionTestFault::None);
    reservation.storage_->retention_fault = fault;
}
#endif

InheritedCaptureEndpointAuthority::InheritedCaptureEndpointAuthority(
        PublicInheritedCaptureEndpoint value, int source_fd)
    : value_(std::move(value)), source_fd_(duplicate_high(source_fd)) {
    const auto actual = fingerprint(source_fd_);
    device_ = actual.device;
    inode_ = actual.inode;
    file_type_ = actual.file_type;
}

InheritedCaptureEndpointAuthority::InheritedCaptureEndpointAuthority(
        InheritedCaptureEndpointAuthority&& other) noexcept
    : value_(other.value_), device_(other.device_), inode_(other.inode_),
      file_type_(other.file_type_),
      source_fd_(std::exchange(other.source_fd_, -1)),
      live_(other.live_.exchange(false)) {}

InheritedCaptureEndpointAuthority::~InheritedCaptureEndpointAuthority() {
    close_if_open(source_fd_);
}

#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
InheritedCaptureEndpointAuthority
InheritedCaptureEndpointAuthority::test_only_mint(
        PublicInheritedCaptureEndpoint value, int source_fd) {
    return InheritedCaptureEndpointAuthority(std::move(value), source_fd);
}
#endif

ParentRoleForkPlanAuthority::ParentRoleForkPlanAuthority(
        PublicParentRoleForkPlan value,
        std::array<InheritedCaptureEndpointAuthority, 3>&& endpoints)
    : value_(std::move(value)) {
    try {
        std::array<bool, 3> were_live{};
        for (std::size_t index = 0; index < endpoints.size(); ++index)
            were_live[index] = endpoints[index].live_.exchange(false);
        for (std::size_t index = 0; index < endpoints.size(); ++index) {
            auto& endpoint = endpoints[index];
            endpoints_[index] = endpoint.value_;
            devices_[index] = endpoint.device_;
            inodes_[index] = endpoint.inode_;
            file_types_[index] = endpoint.file_type_;
            source_fds_[index] = std::exchange(endpoint.source_fd_, -1);
        }
        need(std::all_of(
            were_live.begin(), were_live.end(), [](bool value) {
                return value;
            }));
        valid_plan(value_);
        valid_endpoints(
            value_, endpoints_, devices_, inodes_, file_types_);
        validate_source_fds(PlanState{
            value_, endpoints_, devices_, inodes_, file_types_,
            source_fds_, nullptr, {}, {}});
        identity_ = plan_identity(
            value_, endpoints_, devices_, inodes_, file_types_, {});
        need(nonzero(identity_));
    } catch (...) {
        for (auto& fd : source_fds_) close_if_open(fd);
        refuse();
    }
}

ParentRoleForkPlanAuthority::ParentRoleForkPlanAuthority(
        ParentRoleForkPlanAuthority&& other) noexcept
    : value_(std::move(other.value_)),
      endpoints_(std::move(other.endpoints_)),
      devices_(std::move(other.devices_)),
      inodes_(std::move(other.inodes_)),
      file_types_(std::move(other.file_types_)),
      source_fds_(std::move(other.source_fds_)),
      projection_route_writer_(
          std::move(other.projection_route_writer_)),
      projection_route_identity_(other.projection_route_identity_),
      projection_route_join_attempted_(
          other.projection_route_join_attempted_),
      identity_(other.identity_), live_(other.live_.exchange(false)) {
    other.source_fds_ = {-1, -1, -1};
}

ParentRoleForkPlanAuthority::~ParentRoleForkPlanAuthority() {
    for (auto& fd : source_fds_) close_if_open(fd);
}

void ParentRoleForkPlanAuthority::claim_for_persistent_activation() {
    try {
        need(live_.exchange(false));
        valid_plan(value_);
        valid_endpoints(
            value_, endpoints_, devices_, inodes_, file_types_);
        validate_source_fds(PlanState{
            value_, endpoints_, devices_, inodes_, file_types_,
            source_fds_, nullptr, {}, {}});
    } catch (...) { refuse(); }
}

void ParentRoleForkPlanAuthority::consume_projection_route_writer(
        projection_route::Role0ProjectionRouteWriterAuthority&& writer) {
    auto retained = std::make_unique<
        projection_route::Role0ProjectionRouteWriterAuthority>(
            std::move(writer));
    try {
        need(live_.load() && !projection_route_join_attempted_);
        projection_route_join_attempted_ = true;
        need(retained->live_.load() && retained->fd_ >= 0 &&
             projection_route_writer_ == nullptr &&
             !nonzero(projection_route_identity_) &&
             retained->plan_.classification == value_.classification &&
             retained->plan_.computing_role == 0 &&
             retained->plan_.round == value_.round &&
             retained->plan_.trial == value_.trial &&
             retained->plan_.financial_run == value_.financial_run &&
             retained->plan_.attempt == value_.attempt &&
             retained->plan_.cohort == value_.cohort &&
             retained->plan_.capture_plan_identity ==
                 value_.capture_plan_identity &&
             retained->public_writer_.role == 0 &&
             retained->public_writer_.round == value_.round &&
             retained->public_writer_.fixed_fd ==
                 projection_route::ROLE0_PROJECTION_ROUTE_FIXED_FD &&
             retained->public_writer_.capture_plan_identity ==
                 value_.capture_plan_identity &&
             retained->public_writer_.authority_identity ==
                 retained->route_identity_ &&
             retained->expected_parent_pid_ ==
                 static_cast<std::int64_t>(::getpid()) &&
             retained->expected_role0_pid_ == 0 &&
             !nonzero(retained->fork_binding_identity_) &&
             nonzero(retained->route_identity_));
        const auto before = fingerprint(retained->fd_);
        need(before.file_type == S_IFSOCK);
        const int source = duplicate_high(retained->fd_);
        close_if_open(retained->fd_);
        retained->fd_ = source;
        const auto after = fingerprint(retained->fd_);
        need(after.device == before.device && after.inode == before.inode &&
             after.file_type == before.file_type);
        projection_route_identity_ = retained->route_identity_;
        identity_ = plan_identity(
            value_, endpoints_, devices_, inodes_, file_types_,
            projection_route_identity_);
        need(nonzero(identity_));
        projection_route_writer_ = std::move(retained);
    } catch (...) {
        live_ = false;
        projection_route_writer_.reset();
        projection_route_identity_ = {};
        refuse();
    }
}

bool ParentRoleForkPlanAuthority::
close_inherited_projection_route_parent_alias(
        projection_route::Role0ProjectionRouteWriterAuthority& writer,
        std::uint8_t test_fault, unsigned role) {
    need(role < ROLE_COUNT && writer.live_.load() &&
         writer.parent_peer_fd_ >= 0 &&
         writer.parent_peer_device_ != 0 &&
         writer.parent_peer_inode_ != 0 &&
         writer.parent_peer_file_type_ == S_IFSOCK);
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
    const auto fault = static_cast<ParentRoleForkTestFault>(test_fault);
    if (role == 0 && fault == ParentRoleForkTestFault::
            WrongProjectionRouteParentPeerFingerprintRole0) {
        writer.parent_peer_inode_ ^= 1U;
    } else if (role == 1 && fault == ParentRoleForkTestFault::
            ClosedProjectionRouteParentPeerRole1) {
        need(::close(writer.parent_peer_fd_) == 0);
    } else if (role == 2 && fault == ParentRoleForkTestFault::
            ReusedProjectionRouteParentPeerFdRole2) {
        const int target = writer.parent_peer_fd_;
        need(::close(target) == 0);
        const int replacement = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
        need(replacement >= 0);
        if (replacement != target) {
            need(::dup3(replacement, target, O_CLOEXEC) == target);
            int selected = replacement;
            close_if_open(selected);
        }
    }
#else
    need(test_fault == 0);
#endif
    writer.close_inherited_parent_peer_alias();
    need(writer.parent_peer_fd_ == -1 &&
         !writer.parent_peer_alias_matches());
    return true;
}

void projection_route::RegisteredProjectionRouteForkBridge::
consume_writer_for_parent_fork(
        Role0ProjectionRouteWriterAuthority&& writer,
        ParentRoleForkPlanAuthority& plan) {
    plan.consume_projection_route_writer(std::move(writer));
}

#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
ParentRoleForkPlanAuthority ParentRoleForkPlanAuthority::test_only_mint(
        PublicParentRoleForkPlan value,
        std::array<InheritedCaptureEndpointAuthority, 3>&& endpoints) {
    return ParentRoleForkPlanAuthority(
        std::move(value), std::move(endpoints));
}
#endif

ParentAuthenticatedPartyDeliveryAuthority::
ParentAuthenticatedPartyDeliveryAuthority(
        PublicParentAuthenticatedPartyDelivery value, Digest channel_nonce,
        std::unique_ptr<
            projection_route::Role0ProjectionRouteWriterAuthority> writer)
    : value_(std::move(value)), channel_nonce_(channel_nonce),
      projection_route_writer_(std::move(writer)) {
    need(nonzero(channel_nonce_));
}

ParentAuthenticatedPartyDeliveryAuthority::
ParentAuthenticatedPartyDeliveryAuthority(
        ParentAuthenticatedPartyDeliveryAuthority&& other) noexcept
    : value_(other.value_), channel_nonce_(other.channel_nonce_),
      projection_route_writer_(
          std::move(other.projection_route_writer_)),
      role1_p1_state_prelaunch_(std::exchange(
          other.role1_p1_state_prelaunch_, nullptr)),
      role1_p1_state_prelaunch_destroy_(std::exchange(
          other.role1_p1_state_prelaunch_destroy_, nullptr)),
      role1_p1_state_prelaunch_attached_(std::exchange(
          other.role1_p1_state_prelaunch_attached_, false)),
      role1_p1_state_prelaunch_taken_(std::exchange(
          other.role1_p1_state_prelaunch_taken_, false)),
      live_(other.live_.exchange(false)) {}

ParentAuthenticatedPartyDeliveryAuthority::
~ParentAuthenticatedPartyDeliveryAuthority() {
    if (role1_p1_state_prelaunch_ != nullptr &&
        role1_p1_state_prelaunch_destroy_ != nullptr) {
        role1_p1_state_prelaunch_destroy_(role1_p1_state_prelaunch_);
    }
    role1_p1_state_prelaunch_ = nullptr;
    role1_p1_state_prelaunch_destroy_ = nullptr;
}

ParentAuthenticatedRole0Delivery::ParentAuthenticatedRole0Delivery(
        std::unique_ptr<ParentAuthenticatedPartyDeliveryAuthority> delivery)
        noexcept : delivery_(std::move(delivery)) {}
ParentAuthenticatedRole0Delivery::ParentAuthenticatedRole0Delivery(
        ParentAuthenticatedRole0Delivery&&) noexcept = default;
ParentAuthenticatedRole0Delivery::~ParentAuthenticatedRole0Delivery() =
    default;

ParentAuthenticatedRole1Delivery::ParentAuthenticatedRole1Delivery(
        std::unique_ptr<ParentAuthenticatedPartyDeliveryAuthority> delivery)
        noexcept : delivery_(std::move(delivery)) {}
ParentAuthenticatedRole1Delivery::ParentAuthenticatedRole1Delivery(
        ParentAuthenticatedRole1Delivery&&) noexcept = default;
ParentAuthenticatedRole1Delivery::~ParentAuthenticatedRole1Delivery() =
    default;

ParentAuthenticatedRole2Delivery::ParentAuthenticatedRole2Delivery(
        std::unique_ptr<ParentAuthenticatedPartyDeliveryAuthority> delivery)
        noexcept : delivery_(std::move(delivery)) {}
ParentAuthenticatedRole2Delivery::ParentAuthenticatedRole2Delivery(
        ParentAuthenticatedRole2Delivery&&) noexcept = default;
ParentAuthenticatedRole2Delivery::~ParentAuthenticatedRole2Delivery() =
    default;

namespace {
ParentAuthenticatedPartyDeliveryAuthority take_dispatched_delivery(
        std::unique_ptr<ParentAuthenticatedPartyDeliveryAuthority>& retained,
        unsigned expected_role) {
    need(retained != nullptr &&
         retained->public_receipt().role == expected_role);
    auto selected = std::move(retained);
    return std::move(*selected);
}
} // namespace

ParentAuthenticatedPartyDeliveryAuthority
ParentAuthenticatedRole0Delivery::take_delivery() && {
    need(delivery_ != nullptr &&
         !delivery_->role1_p1_state_prelaunch_attached_ &&
         !delivery_->role1_p1_state_prelaunch_taken_ &&
         delivery_->role1_p1_state_prelaunch_ == nullptr &&
         delivery_->role1_p1_state_prelaunch_destroy_ == nullptr);
    return take_dispatched_delivery(delivery_, 0);
}

ParentAuthenticatedPartyDeliveryAuthority
ParentAuthenticatedRole1Delivery::take_delivery() && {
    need(delivery_ != nullptr &&
         (!delivery_->role1_p1_state_prelaunch_attached_ ||
          (delivery_->role1_p1_state_prelaunch_taken_ &&
           delivery_->role1_p1_state_prelaunch_ == nullptr &&
           delivery_->role1_p1_state_prelaunch_destroy_ == nullptr)));
    return take_dispatched_delivery(delivery_, 1);
}

ParentAuthenticatedPartyDeliveryAuthority
ParentAuthenticatedRole2Delivery::take_delivery() && {
    need(delivery_ != nullptr &&
         !delivery_->role1_p1_state_prelaunch_attached_ &&
         !delivery_->role1_p1_state_prelaunch_taken_ &&
         delivery_->role1_p1_state_prelaunch_ == nullptr &&
         delivery_->role1_p1_state_prelaunch_destroy_ == nullptr);
    return take_dispatched_delivery(delivery_, 2);
}

ParentAuthenticatedRoleDispatch
ParentAuthenticatedPartyDeliveryAuthority::dispatch_role() && {
    // Allocation precedes the linear move; allocation failure leaves the
    // caller's delivery untouched.  Variant construction then moves only
    // noexcept wrappers.
    auto retained = std::make_unique<
        ParentAuthenticatedPartyDeliveryAuthority>(std::move(*this));
    need(retained->live_.load() && retained->value_.role < ROLE_COUNT);
    switch (retained->value_.role) {
    case 0: {
        ParentAuthenticatedRole0Delivery selected(std::move(retained));
        return ParentAuthenticatedRoleDispatch(
            std::in_place_type<ParentAuthenticatedRole0Delivery>,
            std::move(selected));
    }
    case 1: {
        ParentAuthenticatedRole1Delivery selected(std::move(retained));
        return ParentAuthenticatedRoleDispatch(
            std::in_place_type<ParentAuthenticatedRole1Delivery>,
            std::move(selected));
    }
    case 2: {
        ParentAuthenticatedRole2Delivery selected(std::move(retained));
        return ParentAuthenticatedRoleDispatch(
            std::in_place_type<ParentAuthenticatedRole2Delivery>,
            std::move(selected));
    }
    }
    refuse();
}

projection_route::Role0ProjectionRouteWriterAuthority
ParentAuthenticatedPartyDeliveryAuthority::
take_projection_route_writer() {
    auto retained = std::move(projection_route_writer_);
    try {
        need(live_.load() && retained != nullptr &&
             retained->live_.load() && retained->fd_ >= 64 &&
             value_.role == 0 && value_.child_pid == ::getpid() &&
             value_.parent_pid == ::getppid() &&
             retained->expected_parent_pid_ == value_.parent_pid &&
             retained->expected_role0_pid_ == 0 &&
             !nonzero(retained->fork_binding_identity_) &&
             retained->plan_.computing_role == 0 &&
             retained->plan_.round == value_.round &&
             retained->plan_.capture_plan_identity ==
                 value_.capture_plan_identity &&
             retained->public_writer_.role == 0 &&
             retained->public_writer_.round == value_.round &&
             retained->public_writer_.fixed_fd ==
                 projection_route::ROLE0_PROJECTION_ROUTE_FIXED_FD &&
             retained->public_writer_.capture_plan_identity ==
                 value_.capture_plan_identity &&
             retained->public_writer_.authority_identity ==
                 retained->route_identity_ &&
             nonzero(retained->route_identity_) &&
             nonzero(channel_nonce_));
        errno = 0;
        need(::fcntl(
                 projection_route::ROLE0_PROJECTION_ROUTE_FIXED_FD,
                 F_GETFD) == -1 && errno == EBADF);
        need(::dup3(
                 retained->fd_,
                 projection_route::ROLE0_PROJECTION_ROUTE_FIXED_FD,
                 O_CLOEXEC) ==
             projection_route::ROLE0_PROJECTION_ROUTE_FIXED_FD);
        close_if_open(retained->fd_);
        retained->fd_ =
            projection_route::ROLE0_PROJECTION_ROUTE_FIXED_FD;
        retained->expected_role0_pid_ = value_.child_pid;
        retained->fork_binding_identity_ =
            projection_route::RegisteredProjectionRouteForkBridge::
                binding_identity(
                    retained->plan_, retained->route_identity_,
                    value_.parent_pid, value_.child_pid,
                    value_.fork_plan_identity, value_.offer_identity,
                    value_.ack_identity, channel_nonce_);
        need(nonzero(retained->fork_binding_identity_));
        return std::move(*retained);
    } catch (...) {
        retained.reset();
        refuse();
    }
}

projection_route::Role0ProjectionRouteWriterAuthority
projection_route::RegisteredProjectionRouteForkBridge::take_role0_writer(
        ParentAuthenticatedPartyDeliveryAuthority& delivery) {
    return delivery.take_projection_route_writer();
}

ChildRoleCompletionEndpointAuthority::
ChildRoleCompletionEndpointAuthority(
        detail::RoleCompletionBinding binding, int fd)
    : binding_(std::move(binding)), fd_(fd) {
    need(fd_ >= 64);
}

ChildRoleCompletionEndpointAuthority::
ChildRoleCompletionEndpointAuthority(
        ChildRoleCompletionEndpointAuthority&& other) noexcept
    : binding_(other.binding_), fd_(std::exchange(other.fd_, -1)),
      supervisor_phase_(other.supervisor_phase_),
      live_(other.live_.exchange(false)) {}

ChildRoleCompletionEndpointAuthority::~
ChildRoleCompletionEndpointAuthority() {
    close_if_open(fd_);
}

void ChildRoleCompletionEndpointAuthority::send_fixed(
        const Digest& payload_type,
        std::span<const unsigned char> payload) {
    try {
        bool supervisor_ready = supervisor_phase_ == 9;
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
        supervisor_ready = supervisor_ready || supervisor_phase_ == 0 ||
            supervisor_phase_ == 2 || supervisor_phase_ == 5;
#endif
        need(supervisor_ready && live_.exchange(false));
        const auto packet = completion_packet(
            binding_, payload_type, payload);
        send_packet(fd_, packet);
        close_if_open(fd_);
    } catch (...) {
        close_if_open(fd_);
        refuse();
    }
}

#ifdef KPI_REGISTERED_PARTY_COMPLETION_TRANSPORT_TEST_SETUP
void ChildRoleCompletionEndpointAuthority::test_only_send_fixed_duplicate(
        const Digest& payload_type,
        std::span<const unsigned char> payload) {
    try {
        bool supervisor_ready = supervisor_phase_ == 9;
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
        supervisor_ready = supervisor_ready || supervisor_phase_ == 0 ||
            supervisor_phase_ == 2 || supervisor_phase_ == 5;
#endif
        need(supervisor_ready && live_.exchange(false));
        const auto packet = completion_packet(
            binding_, payload_type, payload);
        send_packet(fd_, packet);
        send_packet(fd_, packet);
        close_if_open(fd_);
    } catch (...) {
        close_if_open(fd_);
        refuse();
    }
}
#endif

void ChildRoleCompletionEndpointAuthority::send_role_packet(
        std::uint8_t expected_phase, std::uint8_t next_phase,
        std::span<const unsigned char> packet) {
    try {
        need(live_ && fd_ >= 64 && supervisor_phase_ == expected_phase &&
             next_phase >= expected_phase && !packet.empty());
        send_packet(fd_, packet);
        supervisor_phase_ = next_phase;
    } catch (...) {
        poison_role_channel();
        refuse();
    }
}

std::vector<unsigned char>
ChildRoleCompletionEndpointAuthority::receive_role_packet(
        std::uint8_t expected_phase, std::uint8_t next_phase,
        std::size_t exact_bytes) {
    try {
        need(live_ && fd_ >= 64 && supervisor_phase_ == expected_phase &&
             next_phase > expected_phase && exact_bytes > 0);
        auto packet = receive_packet(fd_, exact_bytes, binding_.parent_pid);
        supervisor_phase_ = next_phase;
        return packet;
    } catch (...) {
        poison_role_channel();
        refuse();
    }
}

void ChildRoleCompletionEndpointAuthority::poison_role_channel()
        noexcept {
    live_ = false;
    close_if_open(fd_);
}

ParentRoleCompletionEndpointAuthority::
ParentRoleCompletionEndpointAuthority(
        detail::RoleCompletionBinding binding, int fd,
        std::shared_ptr<detail::ParentRoleCompletionState> state,
        std::uint8_t supervisor_phase)
    : binding_(std::move(binding)), fd_(fd),
      supervisor_phase_(supervisor_phase), state_(std::move(state)) {
    need(fd_ >= 64 && state_ != nullptr);
}

ParentRoleCompletionEndpointAuthority::
ParentRoleCompletionEndpointAuthority(
        ParentRoleCompletionEndpointAuthority&& other) noexcept
    : binding_(other.binding_), fd_(std::exchange(other.fd_, -1)),
      supervisor_phase_(other.supervisor_phase_),
      state_(std::move(other.state_)),
      live_(other.live_.exchange(false)) {}

ParentRoleCompletionEndpointAuthority::~
ParentRoleCompletionEndpointAuthority() {
    if (live_) poison_completion_state(state_);
    close_if_open(fd_);
}

std::vector<unsigned char>
ParentRoleCompletionEndpointAuthority::receive_fixed(
        const Digest& payload_type, std::size_t exact_payload_bytes) {
    try {
        bool supervisor_ready = supervisor_phase_ == 9;
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
        supervisor_ready = supervisor_ready || supervisor_phase_ == 0 ||
            supervisor_phase_ == 2 || supervisor_phase_ == 5;
#endif
        need(supervisor_ready && live_.exchange(false) &&
             nonzero(payload_type));
        const auto packet = receive_packet(
            fd_, COMPLETION_HEADER_BYTES + exact_payload_bytes,
            binding_.child_pid);
        auto result = parse_completion_packet(
            packet, binding_, payload_type, exact_payload_bytes);
        require_completion_eof(fd_);
        close_if_open(fd_);
        mark_completion(state_, binding_.role);
        return result;
    } catch (...) {
        close_if_open(fd_);
        poison_completion_state(state_);
        refuse();
    }
}

#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
void ParentRoleForkTestCompletionBridge::submit(
        ChildRoleCompletionEndpointAuthority&& endpoint,
        const Digest& payload_type,
        std::span<const unsigned char> payload) {
    endpoint.send_fixed(payload_type, payload);
}

std::vector<unsigned char>
ParentRoleForkTestCompletionBridge::receive(
        ParentRoleCompletionEndpointAuthority&& endpoint,
        const Digest& payload_type, std::size_t exact_payload_bytes) {
    return endpoint.receive_fixed(payload_type, exact_payload_bytes);
}

void ParentRoleForkTestCompletionBridge::submit_zero_record_then_hold(
        ChildRoleCompletionEndpointAuthority&& endpoint,
        const Digest& payload_type,
        std::span<const unsigned char> payload) {
    try {
        bool supervisor_ready = endpoint.supervisor_phase_ == 7;
        supervisor_ready = supervisor_ready ||
            endpoint.supervisor_phase_ == 0 ||
            endpoint.supervisor_phase_ == 2 ||
            endpoint.supervisor_phase_ == 5;
        need(supervisor_ready && endpoint.live_.exchange(false));
        const auto packet = completion_packet(
            endpoint.binding_, payload_type, payload);
        send_packet(endpoint.fd_, packet);
        ssize_t count;
        do {
            count = ::send(endpoint.fd_, nullptr, 0, MSG_NOSIGNAL);
        } while (count < 0 && errno == EINTR);
        need(count == 0);
        // Keep the endpoint live long enough for the parent to observe the
        // credentialed empty record without POLLHUP.
        need(::poll(nullptr, 0, 500) == 0);
        close_if_open(endpoint.fd_);
    } catch (...) {
        close_if_open(endpoint.fd_);
        refuse();
    }
}
#endif

ParentRoleChildren::ParentRoleChildren(
        std::shared_ptr<detail::ChildProcessSet> child_processes,
        std::array<int, 3> completion_fds,
        std::array<detail::RoleCompletionBinding, 3> completion_bindings,
        std::shared_ptr<detail::ParentRoleCompletionState> completion_state,
        std::array<PublicParentRoleAcknowledgement, 3> acknowledgements,
        Digest fork_plan_identity, Digest projection_route_identity,
        bool process_owner)
    : child_processes_(std::move(child_processes)),
      completion_fds_(completion_fds),
      completion_bindings_(std::move(completion_bindings)),
      completion_state_(std::move(completion_state)),
      acknowledgements_(std::move(acknowledgements)),
      fork_plan_identity_(fork_plan_identity),
      projection_route_identity_(projection_route_identity),
      process_owner_(process_owner) {
    need(child_processes_ != nullptr);
}

ParentRoleChildren::ParentRoleChildren(ParentRoleChildren&& other) noexcept
    : child_processes_(std::move(other.child_processes_)),
      completion_fds_(other.completion_fds_),
      completion_bindings_(other.completion_bindings_),
      completion_endpoints_taken_(other.completion_endpoints_taken_),
      supervisor_phases_(other.supervisor_phases_),
      completion_state_(std::move(other.completion_state_)),
      acknowledgements_(other.acknowledgements_),
      fork_plan_identity_(other.fork_plan_identity_),
      projection_route_identity_(other.projection_route_identity_),
      projection_route_parent_binding_attempted_(
          other.projection_route_parent_binding_attempted_),
      projection_route_parent_bound_(
          other.projection_route_parent_bound_),
      release_ready_identities_(other.release_ready_identities_),
      full_cohort_barrier_identity_(other.full_cohort_barrier_identity_),
      full_cohort_barrier_monotonic_ns_(
          other.full_cohort_barrier_monotonic_ns_),
      full_cohort_release_authorized_(
          other.full_cohort_release_authorized_),
      process_owner_(other.process_owner_),
      live_(std::exchange(other.live_, false)) {
    other.completion_fds_ = {-1, -1, -1};
}

ParentRoleChildren::~ParentRoleChildren() {
    for (auto& fd : completion_fds_) close_if_open(fd);
    if (live_ && child_processes_ != nullptr)
        (void)child_processes_->settle(true);
}

std::vector<unsigned char> ParentRoleChildren::receive_role_packet(
        unsigned role, std::uint8_t expected_phase,
        std::uint8_t next_phase, std::size_t exact_bytes) {
    std::lock_guard guard(mutex_);
    try {
        need(live_ && role < ROLE_COUNT &&
             !completion_endpoints_taken_[role] &&
             completion_fds_[role] >= 64 &&
             supervisor_phases_[role] == expected_phase &&
             next_phase >= expected_phase && exact_bytes > 0 &&
             exact_bytes <= 4096);
        auto packet = receive_packet(
            completion_fds_[role], exact_bytes,
            child_processes_->fork_pid(role));
        supervisor_phases_[role] = next_phase;
        return packet;
    } catch (...) { refuse(); }
}

void ParentRoleChildren::send_role_packet(
        unsigned role, std::uint8_t expected_phase,
        std::uint8_t next_phase,
        std::span<const unsigned char> packet) {
    std::lock_guard guard(mutex_);
    try {
        need(live_ && role < ROLE_COUNT &&
             !completion_endpoints_taken_[role] &&
             completion_fds_[role] >= 64 &&
             supervisor_phases_[role] == expected_phase &&
             next_phase > expected_phase && !packet.empty() &&
             packet.size() <= 4096);
        send_packet(completion_fds_[role], packet);
        supervisor_phases_[role] = next_phase;
    } catch (...) { refuse(); }
}

void ParentRoleChildren::poison_role_channels() noexcept {
    bool terminate = false;
    try {
        {
            std::lock_guard guard(mutex_);
            terminate = live_;
            live_ = false;
            for (auto& fd : completion_fds_) close_if_open(fd);
        }
        poison_completion_state(completion_state_);
        if (terminate && child_processes_ != nullptr)
            (void)child_processes_->settle(true);
    } catch (...) {
        for (auto& fd : completion_fds_) close_if_open(fd);
        if (child_processes_ != nullptr)
            (void)child_processes_->settle(true);
    }
}

std::int64_t ParentRoleChildren::child_pid(unsigned role) const {
    try {
        need(role < ROLE_COUNT && child_processes_ != nullptr);
        return child_processes_->fork_pid(role);
    } catch (...) { refuse(); }
}

ParentRoleCompletionEndpointAuthority
ParentRoleChildren::take_completion_endpoint(unsigned role) {
    std::lock_guard guard(mutex_);
    try {
        need(live_ && role < ROLE_COUNT &&
             !completion_endpoints_taken_[role] &&
             completion_fds_[role] >= 64 && completion_state_ != nullptr);
        completion_endpoints_taken_[role] = true;
        const int fd = std::exchange(completion_fds_[role], -1);
        return ParentRoleCompletionEndpointAuthority(
            completion_bindings_[role], fd, completion_state_,
            supervisor_phases_[role]);
    } catch (...) { refuse(); }
}

projection_route::ParentProjectionRouteEndpointAuthority
ParentRoleChildren::bind_projection_route_parent(
        projection_route::ParentProjectionRouteEndpointAuthority&& parent) {
    auto retained =
        projection_route::ParentProjectionRouteEndpointAuthority(
            std::move(parent));
    try {
        std::lock_guard guard(mutex_);
        need(live_ && !projection_route_parent_binding_attempted_);
        projection_route_parent_binding_attempted_ = true;
        const auto& binding = completion_bindings_[0];
        const auto& acknowledgment = acknowledgements_[0];
        need(nonzero(projection_route_identity_) &&
             retained.live_.load() && retained.fd_ >= 0 &&
             retained.expected_parent_pid_ == ::getpid() &&
             retained.expected_role0_pid_ == 0 &&
             !nonzero(retained.fork_binding_identity_) &&
             retained.plan_.computing_role == 0 &&
             retained.plan_.round == binding.round &&
             retained.plan_.capture_plan_identity ==
                 binding.capture_plan_identity &&
             retained.route_identity_ == projection_route_identity_ &&
             binding.role == 0 && binding.parent_pid == ::getpid() &&
             binding.child_pid == child_processes_->fork_pid(0) &&
             binding.fork_plan_identity == fork_plan_identity_ &&
             acknowledgment.role == 0 &&
             acknowledgment.parent_pid == binding.parent_pid &&
             acknowledgment.child_pid == binding.child_pid &&
             acknowledgment.fork_plan_identity ==
                 binding.fork_plan_identity &&
             acknowledgment.offer_identity == binding.offer_identity &&
             acknowledgment.ack_identity == binding.ack_identity &&
             nonzero(binding.channel_nonce));
        retained.expected_role0_pid_ = binding.child_pid;
        retained.fork_binding_identity_ =
            projection_route::RegisteredProjectionRouteForkBridge::
                binding_identity(
                    retained.plan_, retained.route_identity_,
                    binding.parent_pid, binding.child_pid,
                    binding.fork_plan_identity, binding.offer_identity,
                    binding.ack_identity, binding.channel_nonce);
        need(nonzero(retained.fork_binding_identity_));
        projection_route_parent_bound_ = true;
        return retained;
    } catch (...) {
        projection_route_parent_bound_ = false;
        refuse();
    }
}

projection_route::ParentProjectionRouteEndpointAuthority
projection_route::RegisteredProjectionRouteForkBridge::
bind_parent_after_fork(
        ParentProjectionRouteEndpointAuthority&& parent,
        ParentRoleChildren& children) {
    return children.bind_projection_route_parent(std::move(parent));
}

PublicParentRoleForkCompletion ParentRoleChildren::wait() {
    bool all_taken = false;
    {
        std::lock_guard guard(mutex_);
        need(live_ && process_owner_);
        live_ = false;
        all_taken = std::all_of(
            completion_endpoints_taken_.begin(),
            completion_endpoints_taken_.end(),
            [](bool value) { return value; }) &&
            (!nonzero(projection_route_identity_) ||
             projection_route_parent_bound_);
    }
    if (!all_taken) {
        for (auto& fd : completion_fds_) close_if_open(fd);
        poison_completion_state(completion_state_);
        if (child_processes_ != nullptr)
            (void)child_processes_->settle(true);
        refuse();
    }
    bool all_zero = true;
    need(child_processes_ != nullptr);
    const auto exits = child_processes_->settle(false);
    for (const auto& exit : exits)
        all_zero = all_zero && exit.pidfd_exit_observed &&
            exit.wait_status_available && exit.pid_identity_exact &&
            exit.exit_code == 0 && exit.term_signal == 0;
    bool all_completed = false;
    {
        need(completion_state_ != nullptr);
        std::lock_guard guard(completion_state_->mutex);
        all_completed = !completion_state_->poisoned && std::all_of(
            completion_state_->completed.begin(),
            completion_state_->completed.end(),
            [](bool value) { return value; });
    }
    need(all_zero && all_completed);
    return {
        .fork_plan_identity = fork_plan_identity_,
        .acknowledgements = acknowledgements_,
        .all_children_exited_zero = true,
    };
}

ParentRoleChildren RegisteredParentRoleFork::launch(
        ParentRoleForkPlanAuthority&& plan,
        RegisteredRoleChildProgram& program) {
    return launch_impl(std::move(plan), program, 0);
}

#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
ParentRoleChildren RegisteredParentRoleFork::test_only_launch(
        ParentRoleForkPlanAuthority&& plan,
        RegisteredRoleChildProgram& program,
        ParentRoleForkTestFault fault) {
    return launch_impl(
        std::move(plan), program, static_cast<std::uint8_t>(fault));
}
#endif

ParentRoleChildren RegisteredParentRoleFork::launch_impl(
        ParentRoleForkPlanAuthority&& plan,
        RegisteredRoleChildProgram& program, std::uint8_t test_fault) {
    std::array<std::int64_t, 3> pids{{-1, -1, -1}};
    std::array<UniqueFd, 3> pidfds;
    std::shared_ptr<detail::ChildProcessSet> child_processes;
    std::array<std::array<UniqueFd, 2>, 3> channels;
    PlanState state;
    try {
        need(plan.live_.exchange(false));
        require_single_thread();
        require_waitable_children();
        valid_plan(plan.value_);
        valid_endpoints(
            plan.value_, plan.endpoints_, plan.devices_, plan.inodes_,
            plan.file_types_);
        const bool has_projection_route =
            plan.projection_route_writer_ != nullptr;
        need(has_projection_route ==
                 nonzero(plan.projection_route_identity_) &&
             (!plan.projection_route_join_attempted_ ||
              has_projection_route));
#ifndef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
        need(has_projection_route);
#endif
        state = PlanState{
            plan.value_, plan.endpoints_, plan.devices_, plan.inodes_,
            plan.file_types_, plan.source_fds_,
            std::move(plan.projection_route_writer_),
            plan.projection_route_identity_, plan.identity_};
        plan.source_fds_ = {-1, -1, -1};
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
        if (test_fault == static_cast<std::uint8_t>(
                ParentRoleForkTestFault::SwapProjectionAndCorruptServerSources))
            std::swap(state.source_fds[0], state.source_fds[2]);
#else
        need(test_fault == 0);
#endif
        validate_source_fds(state);
        for (auto& channel : channels) channel = capability_channel();

        const auto parent_pid = static_cast<std::int64_t>(::getpid());
        need(parent_pid > 1);
        for (unsigned role = 0; role < ROLE_COUNT; ++role) {
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
            if (role == 2 && test_fault == static_cast<std::uint8_t>(
                    ParentRoleForkTestFault::FailBeforeRole2Fork))
                refuse();
#endif
            const pid_t child = ::fork();
            need(child >= 0);
            if (child == 0) {
                int code = 120;
                try {
                    need(::getppid() == parent_pid);
                    bool projection_route_parent_peer_alias_closed = false;
                    if (state.projection_route_writer != nullptr) {
                        // This is the child's first descriptor mutation.  The
                        // exact inherited parent endpoint must be fingerprint-
                        // checked and closed before fixed-FD installation,
                        // offer decoding, ACK, or any role callback.
                        projection_route_parent_peer_alias_closed =
                            ParentRoleForkPlanAuthority::
                                close_inherited_projection_route_parent_alias(
                                    *state.projection_route_writer,
                                    test_fault, role);
                    }
                    if (role != 0)
                        state.projection_route_writer.reset();
                    const int own_endpoint = channels[role][1].get();
                    for (unsigned channel_role = 0;
                         channel_role < ROLE_COUNT; ++channel_role) {
                        int parent_endpoint =
                            channels[channel_role][0].release();
                        close_if_open(parent_endpoint);
                        if (channel_role != role) {
                            int child_endpoint =
                                channels[channel_role][1].release();
                            close_if_open(child_endpoint);
                        }
                    }
                    const auto offer_bytes = receive_packet<OFFER_BYTES>(
                        own_endpoint, parent_pid);
                    const auto offer = parse_offer(
                        offer_bytes, state, role, parent_pid);
                    install_role_descriptors(state, role);
                    const auto child_pid =
                        static_cast<std::int64_t>(::getpid());
                    const auto ack = make_ack(offer, child_pid);
                    send_packet(own_endpoint, ack);
                    std::unique_ptr<
                        projection_route::Role0ProjectionRouteWriterAuthority>
                        role0_projection_route_writer;
                    if (role == 0)
                        role0_projection_route_writer =
                            std::move(state.projection_route_writer);
                    else
                        need(state.projection_route_writer == nullptr);
                    auto authority =
                        ParentAuthenticatedPartyDeliveryAuthority(
                            PublicParentAuthenticatedPartyDelivery{
                                .role = role,
                                .round = state.value.round,
                                .parent_pid = parent_pid,
                                .child_pid = child_pid,
                                .authority_identity =
                                    state.value.authority_identity,
                                .supervisor_session =
                                    state.value.supervisor_session,
                                .party_session =
                                    state.value.roles[role].party_session,
                                .service_identity =
                                    state.value.roles[role].service_identity,
                                .driver_selection_identity =
                                    state.value.roles[role]
                                        .driver_selection_identity,
                                .fresh_owner_issuance_identity =
                                    state.value.fresh_owner_issuance_identity,
                                .capture_plan_identity =
                                    state.value.capture_plan_identity,
                                .capture_source_identity =
                                    state.value.capture_source_identity,
                                .capture_build_identity =
                                    state.value.capture_build_identity,
                                .capture_launcher_identity =
                                    state.value.capture_launcher_identity,
                                .fork_plan_identity = state.identity,
                                .offer_identity = offer.identity,
                                .ack_identity = get_digest(
                                    ack, ACK_IDENTITY_OFFSET),
                                .fixed_capture_fds =
                                    offer.fixed_descriptors,
                                .fixed_capture_fd_count = offer.fixed_count,
                                .projection_route_parent_peer_alias_closed =
                                    projection_route_parent_peer_alias_closed,
                            }, offer.nonce,
                            std::move(role0_projection_route_writer));
                    auto completion_endpoint =
                        ChildRoleCompletionEndpointAuthority(
                            detail::RoleCompletionBinding{
                                .role = role,
                                .round = state.value.round,
                                .classification =
                                    state.value.classification,
                                .capture_trial_id =
                                    state.value.capture_trial_id,
                                .run = state.value.financial_run,
                                .trial = state.value.trial,
                                .attempt = state.value.attempt,
                                .cohort = state.value.cohort,
                                .fresh_owner_issuance_identity =
                                    state.value.fresh_owner_issuance_identity,
                                .parent_pid = parent_pid,
                                .child_pid = child_pid,
                                .fork_plan_identity = state.identity,
                                .offer_identity = offer.identity,
                                .ack_identity = get_digest(
                                    ack, ACK_IDENTITY_OFFSET),
                                .channel_nonce = offer.nonce,
                                .authority_identity =
                                    state.value.authority_identity,
                                .supervisor_session =
                                    state.value.supervisor_session,
                                .party_session =
                                    state.value.roles[role].party_session,
                                .service_identity =
                                    state.value.roles[role].service_identity,
                                .driver_selection_identity =
                                    state.value.roles[role]
                                        .driver_selection_identity,
                                .capture_plan_identity =
                                    state.value.capture_plan_identity,
                                .capture_source_identity =
                                    state.value.capture_source_identity,
                                .capture_build_identity =
                                    state.value.capture_build_identity,
                                .capture_launcher_identity =
                                    state.value.capture_launcher_identity,
                            },
                            channels[role][1].release());
                    code = program.run(
                        std::move(authority),
                        std::move(completion_endpoint));
                    if (code < 0 || code > 119) code = 119;
                } catch (...) {
                    code = 120;
                }
                ::_exit(code);
            }
            pids[role] = child;
        }

        // No offer has been sent, so all three children are blocked on their
        // inherited channels. SIGCHLD is default/waitable and the parent is
        // single-threaded, so a child that failed early remains a non-reused
        // zombie until each CLOEXEC pidfd pins its exact process identity.
        for (unsigned role = 0; role < ROLE_COUNT; ++role) {
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
            if (role == 1 && test_fault == static_cast<std::uint8_t>(
                    ParentRoleForkTestFault::FailPidfdOpenRole1))
                refuse();
#endif
            pidfds[role] = UniqueFd(open_pidfd(
                static_cast<pid_t>(pids[role])));
        }
        const std::array<int, 3> borrowed_pidfds{
            pidfds[0].get(), pidfds[1].get(), pidfds[2].get()};
        child_processes = std::make_shared<detail::ChildProcessSet>(
            pids, borrowed_pidfds);
        for (auto& pidfd : pidfds) (void)pidfd.release();

        // The only surviving writer alias is now in the role-0 child.  The
        // parent must not retain a source alias while forking or supervising.
        state.projection_route_writer.reset();

        bool retain_role_zero_child_endpoint = false;
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
        retain_role_zero_child_endpoint =
            test_fault == static_cast<std::uint8_t>(
                ParentRoleForkTestFault::ParentSelfAcknowledgement);
#endif
        for (unsigned role = 0; role < ROLE_COUNT; ++role) {
            if (!(retain_role_zero_child_endpoint && role == 0))
                channels[role][1].reset();
        }
        for (auto& source : state.source_fds) close_if_open(source);

        std::array<Offer, 3> offers{
            make_offer(state, 0, parent_pid),
            make_offer(state, 1, parent_pid),
            make_offer(state, 2, parent_pid),
        };

#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
        if (test_fault == static_cast<std::uint8_t>(
                ParentRoleForkTestFault::SwapRoleZeroAndOneOffers)) {
            send_packet(channels[0][0].get(), offers[1].bytes);
            send_packet(channels[1][0].get(), offers[0].bytes);
            send_packet(channels[2][0].get(), offers[2].bytes);
        } else if (retain_role_zero_child_endpoint) {
            std::uint8_t forged_count = 0;
            const ParsedOffer forged_offer{
                0, state.value.round, parent_pid,
                fixed_fds(state.value.round, 0, forged_count),
                forged_count, offers[0].nonce, offers[0].identity};
            const auto forged = make_ack(forged_offer, pids[0]);
            send_packet(channels[0][1].get(), forged);
            send_packet(channels[1][0].get(), offers[1].bytes);
            send_packet(channels[2][0].get(), offers[2].bytes);
        } else
#endif
        {
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
            const auto selected_fault =
                static_cast<ParentRoleForkTestFault>(test_fault);
            need(selected_fault == ParentRoleForkTestFault::None ||
                 selected_fault == ParentRoleForkTestFault::
                     WrongProjectionRouteParentPeerFingerprintRole0 ||
                 selected_fault == ParentRoleForkTestFault::
                     ClosedProjectionRouteParentPeerRole1 ||
                 selected_fault == ParentRoleForkTestFault::
                     ReusedProjectionRouteParentPeerFdRole2);
#else
            need(test_fault == 0);
#endif
            for (unsigned role = 0; role < ROLE_COUNT; ++role)
                send_packet(channels[role][0].get(), offers[role].bytes);
        }

        std::array<PublicParentRoleAcknowledgement, 3> acknowledgements{};
        for (unsigned role = 0; role < ROLE_COUNT; ++role) {
            const auto ack = receive_packet<ACK_BYTES>(
                channels[role][0].get(), pids[role]);
            acknowledgements[role] = parse_ack(
                ack, offers[role], state, role, parent_pid, pids[role]);
        }
        channels[0][1].reset();
        std::array<int, 3> completion_fds{{-1, -1, -1}};
        std::array<detail::RoleCompletionBinding, 3> completion_bindings{};
        for (unsigned role = 0; role < ROLE_COUNT; ++role) {
            completion_fds[role] = channels[role][0].release();
            completion_bindings[role] = detail::RoleCompletionBinding{
                .role = role,
                .round = state.value.round,
                .classification = state.value.classification,
                .capture_trial_id = state.value.capture_trial_id,
                .run = state.value.financial_run,
                .trial = state.value.trial,
                .attempt = state.value.attempt,
                .cohort = state.value.cohort,
                .fresh_owner_issuance_identity =
                    state.value.fresh_owner_issuance_identity,
                .parent_pid = parent_pid,
                .child_pid = pids[role],
                .fork_plan_identity = state.identity,
                .offer_identity = offers[role].identity,
                .ack_identity = acknowledgements[role].ack_identity,
                .channel_nonce = offers[role].nonce,
                .authority_identity = state.value.authority_identity,
                .supervisor_session = state.value.supervisor_session,
                .party_session = state.value.roles[role].party_session,
                .service_identity = state.value.roles[role].service_identity,
                .driver_selection_identity =
                    state.value.roles[role].driver_selection_identity,
                .capture_plan_identity = state.value.capture_plan_identity,
                .capture_source_identity = state.value.capture_source_identity,
                .capture_build_identity = state.value.capture_build_identity,
                .capture_launcher_identity =
                    state.value.capture_launcher_identity,
            };
        }
        return ParentRoleChildren(
            child_processes, completion_fds, completion_bindings,
            std::make_shared<detail::ParentRoleCompletionState>(),
            acknowledgements, state.identity,
            state.projection_route_identity);
    } catch (...) {
        for (auto& channel : channels)
            for (auto& endpoint : channel) endpoint.reset();
        for (auto& source : state.source_fds) close_if_open(source);
        for (auto& source : plan.source_fds_) close_if_open(source);
        if (child_processes != nullptr)
            (void)child_processes->settle(true);
        else {
            const bool any_pidfd = std::any_of(
                pidfds.begin(), pidfds.end(),
                [](const UniqueFd& pidfd) { return pidfd.get() >= 0; });
            if (any_pidfd)
                settle_partially_pinned_children(pids, pidfds);
            else
                reap_unpinned_children(pids);
        }
        refuse();
    }
}

RegisteredPersistentRoleProcessReservation
RegisteredParentPersistentRoleFork::reserve(
        RegisteredPreIdentityPersistentRoleChildProgram& program) {
    std::array<std::int64_t, 3> pids{{-1, -1, -1}};
    std::array<UniqueFd, 3> pidfds;
    std::shared_ptr<detail::ChildProcessSet> child_processes;
    std::array<std::array<std::array<UniqueFd, 2>, 3>, 2> channels;
    try {
        // The virtual program is inherited only as generic code. No method is
        // invoked and no trial/round/topology authority enters phase 1.
        (void)&program;
        require_single_thread();
        require_waitable_children();
        for (auto& round_channels : channels)
            for (auto& channel : round_channels)
                channel = capability_channel();

        const auto parent_pid = static_cast<std::int64_t>(::getpid());
        need(parent_pid > 1);
        for (unsigned role = 0; role < ROLE_COUNT; ++role) {
            const pid_t child = ::fork();
            need(child >= 0);
            if (child == 0) {
                int code = RESERVATION_CHANNEL_CLOSED_EXIT;
                try {
                    need(::getppid() == parent_pid);
                    // Preserve only the two authenticated activation channels
                    // at reserved descriptors, then close and enumerate every
                    // other inherited descriptor before blocking.  This also
                    // removes unrelated parent descriptors that were open
                    // before this module was entered.
                    auto own_endpoints =
                        install_reservation_child_channel_allowlist({
                            channels[0][role][1].get(),
                            channels[1][role][1].get(),
                        });
                    auto first = receive_reservation_packet(
                        own_endpoints[0], parent_pid);
                    if (first.descriptor_count == 0 &&
                        is_reservation_abort_command(first.bytes)) {
                        code = RESERVATION_ABORT_EXIT;
                    } else {
                        std::array<RetainedReservationActivation, 2>
                            retained_activations;
                        const auto handle_preflight = [&](
                                ReceivedReservationPacket&& packet,
                                unsigned round) {
                            auto retained = retain_reservation_activation(
                                std::move(packet), round, role, parent_pid,
                                static_cast<std::int64_t>(::getpid()));
                            retained_activations[round - 1] =
                                std::move(retained);
                            const auto& parsed =
                                retained_activations[round - 1].parsed;
                            const auto ack =
                                make_reservation_activation_ack(
                                    round, role,
                                    parsed.capture_descriptor_count,
                                    parsed.state_descriptor_count,
                                    parent_pid,
                                    static_cast<std::int64_t>(::getpid()),
                                    parsed.identity);
                            send_packet(
                                own_endpoints[round - 1], ack);
                        };
                        handle_preflight(std::move(first), 1);
                        auto second = receive_reservation_packet(
                            own_endpoints[1], parent_pid);
                        handle_preflight(std::move(second), 2);
                        const auto probe = receive_packet<
                            RESERVATION_RETENTION_PROBE_BYTES>(
                                own_endpoints[0], parent_pid);
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
                        for (auto& retained : retained_activations)
                            if (retained.parsed.drop_metadata_after_ack)
                                retained.command_bytes.fill(0);
#endif
                        // The parent emits this probe only after authenticating
                        // all six first ACKs. Reparse the exact stored command
                        // bytes against the still-owned descriptors now, not
                        // merely before the global ACK barrier.
                        const auto retained_round1 =
                            validate_retained_reservation_activation(
                                retained_activations[0]);
                        const auto retained_round2 =
                            validate_retained_reservation_activation(
                                retained_activations[1]);
                        const std::array<Digest, 2> command_identities{{
                            retained_round1.identity,
                            retained_round2.identity,
                        }};
                        const auto probe_identity =
                            parse_reservation_retention_probe(
                                probe, role, parent_pid,
                                static_cast<std::int64_t>(::getpid()),
                                command_identities);
                        const std::array<std::uint8_t, 2>
                            descriptor_counts{{
                                retained_activations[0].descriptor_count,
                                retained_activations[1].descriptor_count,
                            }};
                        const auto retention_ack =
                            make_reservation_retention_ack(
                                role, parent_pid,
                                static_cast<std::int64_t>(::getpid()),
                                command_identities, descriptor_counts,
                                probe_identity);
                        send_packet(own_endpoints[0], retention_ack);
                        const auto final_command =
                            receive_reservation_packet(
                                own_endpoints[0], parent_pid);
                        need(final_command.descriptor_count == 0 &&
                             is_reservation_abort_command(
                                 final_command.bytes));
                        code = RESERVATION_ABORT_EXIT;
                    }
                    for (auto& endpoint : own_endpoints)
                        close_if_open(endpoint);
                } catch (...) {
                    code = RESERVATION_CHANNEL_CLOSED_EXIT;
                }
                ::_exit(code);
            }
            pids[role] = child;
        }

        // All children are blocked before any activation packet. Pin exact
        // process identity only after the final fork, so no sibling inherits
        // another child's pidfd.
        for (unsigned role = 0; role < ROLE_COUNT; ++role)
            pidfds[role] = UniqueFd(open_pidfd(
                static_cast<pid_t>(pids[role])));
        const std::array<int, 3> borrowed_pidfds{
            pidfds[0].get(), pidfds[1].get(), pidfds[2].get()};
        child_processes = std::make_shared<detail::ChildProcessSet>(
            pids, borrowed_pidfds);
        for (auto& pidfd : pidfds) (void)pidfd.release();

        auto storage = std::make_unique<
            RegisteredPersistentRoleProcessReservation::Storage>();
        storage->child_processes = child_processes;
        storage->preidentity_epoch = std::make_shared<
            detail::PersistentProcessReservationEpoch>(child_processes);
        for (unsigned round = 0; round < 2; ++round)
            for (unsigned role = 0; role < ROLE_COUNT; ++role) {
                channels[round][role][1].reset();
                storage->parent_fds[round][role] =
                    channels[round][role][0].release();
            }
        return RegisteredPersistentRoleProcessReservation(
            std::move(storage));
    } catch (...) {
        for (auto& round_channels : channels)
            for (auto& channel : round_channels)
                for (auto& endpoint : channel) endpoint.reset();
        if (child_processes != nullptr)
            (void)child_processes->settle(true);
        else {
            const bool any_pidfd = std::any_of(
                pidfds.begin(), pidfds.end(),
                [](const UniqueFd& pidfd) { return pidfd.get() >= 0; });
            if (any_pidfd)
                settle_partially_pinned_children(pids, pidfds);
            else
                reap_unpinned_children(pids);
        }
        refuse();
    }
}

detail::PersistentRoleReservationAbortEvidence
RegisteredParentPersistentRoleFork::abort(
        RegisteredPersistentRoleProcessReservation&& reservation) {
    auto storage = std::move(reservation.storage_);
    try {
        need(storage != nullptr && !storage->claimed &&
             storage->child_processes != nullptr);
        storage->claimed = true;
        const auto command = reservation_abort_command();
        for (unsigned role = 0; role < ROLE_COUNT; ++role) {
            try {
                send_packet(storage->parent_fds[0][role], command);
            } catch (...) {
                // Closing the sole parent endpoint below converts a failed
                // graceful abort into authenticated EOF, never a raw signal.
            }
        }
        for (auto& round : storage->parent_fds)
            for (auto& fd : round) close_if_open(fd);

        const auto pids = storage->child_processes->fork_pids();
        const auto exits = storage->child_processes->settle(false);
        return detail::PersistentRoleReservationAbortEvidence(
            pids,
            {exits[0].pidfd_exit_observed,
             exits[1].pidfd_exit_observed,
             exits[2].pidfd_exit_observed},
            {exits[0].wait_status_available,
             exits[1].wait_status_available,
             exits[2].wait_status_available},
            {exits[0].pid_identity_exact,
             exits[1].pid_identity_exact,
             exits[2].pid_identity_exact},
            {exits[0].exit_code,
             exits[1].exit_code,
             exits[2].exit_code},
            {exits[0].term_signal,
             exits[1].term_signal,
             exits[2].term_signal},
            storage->topology_preflight_acknowledged,
            storage->topology_retention_acknowledged,
            false);
    } catch (...) { refuse(); }
}

RegisteredPersistentRoleSession RegisteredParentPersistentRoleFork::launch(
        ParentRoleForkPlanAuthority&& round1,
        ParentRoleForkPlanAuthority&& round2,
        RegisteredPersistentRoleChildProgram& program) {
    std::array<std::int64_t, 3> pids{{-1, -1, -1}};
    std::array<UniqueFd, 3> pidfds;
    std::shared_ptr<detail::ChildProcessSet> child_processes;
    std::array<std::array<std::array<UniqueFd, 2>, 3>, 2> channels;
    std::array<PlanState, 2> states;
    try {
        const bool round1_was_live = round1.live_.exchange(false);
        const bool round2_was_live = round2.live_.exchange(false);
        need(round1_was_live && round2_was_live);
        require_single_thread();
        require_waitable_children();

        auto consume_plan = [](ParentRoleForkPlanAuthority& plan) {
            valid_plan(plan.value_);
            valid_endpoints(
                plan.value_, plan.endpoints_, plan.devices_, plan.inodes_,
                plan.file_types_);
            need(plan.projection_route_writer_ != nullptr &&
                 nonzero(plan.projection_route_identity_) &&
                 plan.projection_route_join_attempted_);
            PlanState state{
                plan.value_, plan.endpoints_, plan.devices_, plan.inodes_,
                plan.file_types_, plan.source_fds_,
                std::move(plan.projection_route_writer_),
                plan.projection_route_identity_, plan.identity_};
            plan.source_fds_ = {-1, -1, -1};
            validate_source_fds(state);
            return state;
        };
        states[0] = consume_plan(round1);
        states[1] = consume_plan(round2);
        const auto& first = states[0].value;
        const auto& second = states[1].value;
        need(first.round == 1 && second.round == 2 &&
             first.classification == second.classification &&
             first.capture_trial_id == second.capture_trial_id &&
             first.trial == second.trial &&
             first.fresh_owner_issuance_identity ==
                 second.fresh_owner_issuance_identity &&
             first.supervisor_session == second.supervisor_session &&
             first.capture_source_identity ==
                 second.capture_source_identity &&
             first.capture_build_identity == second.capture_build_identity &&
             first.capture_launcher_identity ==
                 second.capture_launcher_identity &&
             first.roles[0].service_identity ==
                 second.roles[0].service_identity &&
             first.financial_run != second.financial_run &&
             first.attempt != second.attempt &&
             first.cohort != second.cohort &&
             first.authority_identity != second.authority_identity &&
             first.capture_plan_identity !=
                 second.capture_plan_identity &&
             states[0].identity != states[1].identity &&
             states[0].projection_route_identity !=
                 states[1].projection_route_identity);
        for (unsigned role = 0; role < ROLE_COUNT; ++role)
            need(first.roles[role].role == role &&
                 second.roles[role].role == role);

        for (auto& round_channels : channels)
            for (auto& channel : round_channels)
                channel = capability_channel();

        const auto parent_pid = static_cast<std::int64_t>(::getpid());
        need(parent_pid > 1);
        for (unsigned role = 0; role < ROLE_COUNT; ++role) {
            const pid_t child = ::fork();
            need(child >= 0);
            if (child == 0) {
                int code = 120;
                try {
                    need(::getppid() == parent_pid);
                    std::array<bool, 2> parent_alias_closed{};
                    // These are the child's first descriptor mutations. Both
                    // parent route aliases are fingerprint-checked and closed
                    // before any offer, fixed-FD installation or callback.
                    for (unsigned round = 0; round < 2; ++round)
                        parent_alias_closed[round] =
                            ParentRoleForkPlanAuthority::
                                close_inherited_projection_route_parent_alias(
                                    *states[round].projection_route_writer,
                                    0, role);
                    if (role != 0)
                        for (auto& state : states)
                            state.projection_route_writer.reset();

                    std::array<int, 2> own_endpoints{
                        channels[0][role][1].get(),
                        channels[1][role][1].get()};
                    for (unsigned round = 0; round < 2; ++round) {
                        for (unsigned channel_role = 0;
                             channel_role < ROLE_COUNT; ++channel_role) {
                            int parent_endpoint =
                                channels[round][channel_role][0].release();
                            close_if_open(parent_endpoint);
                            if (channel_role != role) {
                                int child_endpoint =
                                    channels[round][channel_role][1].release();
                                close_if_open(child_endpoint);
                            }
                        }
                    }

                    for (unsigned round = 0; round < 2; ++round) {
                        const auto offer_bytes = receive_packet<OFFER_BYTES>(
                            own_endpoints[round], parent_pid);
                        const auto offer = parse_offer(
                            offer_bytes, states[round], role, parent_pid);
                        install_role_descriptors(states[round], role);
                        const auto child_pid =
                            static_cast<std::int64_t>(::getpid());
                        const auto ack = make_ack(offer, child_pid);
                        send_packet(own_endpoints[round], ack);
                        std::unique_ptr<projection_route::
                            Role0ProjectionRouteWriterAuthority> writer;
                        if (role == 0)
                            writer = std::move(
                                states[round].projection_route_writer);
                        else
                            need(states[round].projection_route_writer ==
                                 nullptr);
                        auto delivery =
                            ParentAuthenticatedPartyDeliveryAuthority(
                                PublicParentAuthenticatedPartyDelivery{
                                    .role = role,
                                    .round = states[round].value.round,
                                    .parent_pid = parent_pid,
                                    .child_pid = child_pid,
                                    .authority_identity = states[round]
                                        .value.authority_identity,
                                    .supervisor_session = states[round]
                                        .value.supervisor_session,
                                    .party_session = states[round]
                                        .value.roles[role].party_session,
                                    .service_identity = states[round]
                                        .value.roles[role].service_identity,
                                    .driver_selection_identity = states[round]
                                        .value.roles[role]
                                        .driver_selection_identity,
                                    .fresh_owner_issuance_identity =
                                        states[round].value
                                            .fresh_owner_issuance_identity,
                                    .capture_plan_identity = states[round]
                                        .value.capture_plan_identity,
                                    .capture_source_identity = states[round]
                                        .value.capture_source_identity,
                                    .capture_build_identity = states[round]
                                        .value.capture_build_identity,
                                    .capture_launcher_identity = states[round]
                                        .value.capture_launcher_identity,
                                    .fork_plan_identity =
                                        states[round].identity,
                                    .offer_identity = offer.identity,
                                    .ack_identity = get_digest(
                                        ack, ACK_IDENTITY_OFFSET),
                                    .fixed_capture_fds =
                                        offer.fixed_descriptors,
                                    .fixed_capture_fd_count =
                                        offer.fixed_count,
                                    .projection_route_parent_peer_alias_closed =
                                        parent_alias_closed[round],
                                }, offer.nonce, std::move(writer));
                        auto endpoint = ChildRoleCompletionEndpointAuthority(
                            detail::RoleCompletionBinding{
                                .role = role,
                                .round = states[round].value.round,
                                .classification = states[round]
                                    .value.classification,
                                .capture_trial_id = states[round]
                                    .value.capture_trial_id,
                                .run = states[round].value.financial_run,
                                .trial = states[round].value.trial,
                                .attempt = states[round].value.attempt,
                                .cohort = states[round].value.cohort,
                                .fresh_owner_issuance_identity = states[round]
                                    .value.fresh_owner_issuance_identity,
                                .parent_pid = parent_pid,
                                .child_pid = child_pid,
                                .fork_plan_identity = states[round].identity,
                                .offer_identity = offer.identity,
                                .ack_identity = get_digest(
                                    ack, ACK_IDENTITY_OFFSET),
                                .channel_nonce = offer.nonce,
                                .authority_identity = states[round]
                                    .value.authority_identity,
                                .supervisor_session = states[round]
                                    .value.supervisor_session,
                                .party_session = states[round]
                                    .value.roles[role].party_session,
                                .service_identity = states[round]
                                    .value.roles[role].service_identity,
                                .driver_selection_identity = states[round]
                                    .value.roles[role]
                                    .driver_selection_identity,
                                .capture_plan_identity = states[round]
                                    .value.capture_plan_identity,
                                .capture_source_identity = states[round]
                                    .value.capture_source_identity,
                                .capture_build_identity = states[round]
                                    .value.capture_build_identity,
                                .capture_launcher_identity = states[round]
                                    .value.capture_launcher_identity,
                            }, channels[round][role][1].release());
                        code = program.round_program(round + 1).run(
                            std::move(delivery), std::move(endpoint));
                        need(code == 0);
                    }
                    code = 0;
                } catch (...) { code = 120; }
                ::_exit(code);
            }
            pids[role] = child;
        }

        // Pin every exact child before either round receives an offer. Opening
        // after the final fork also proves no child inherited a sibling pidfd.
        for (unsigned role = 0; role < ROLE_COUNT; ++role)
            pidfds[role] = UniqueFd(open_pidfd(
                static_cast<pid_t>(pids[role])));
        const std::array<int, 3> borrowed_pidfds{
            pidfds[0].get(), pidfds[1].get(), pidfds[2].get()};
        child_processes = std::make_shared<detail::ChildProcessSet>(
            pids, borrowed_pidfds);
        for (auto& pidfd : pidfds) (void)pidfd.release();

        for (auto& state : states) {
            state.projection_route_writer.reset();
            for (auto& source : state.source_fds) close_if_open(source);
        }
        for (unsigned round = 0; round < 2; ++round)
            for (unsigned role = 0; role < ROLE_COUNT; ++role)
                channels[round][role][1].reset();

        std::array<std::array<Offer, 3>, 2> offers{};
        for (unsigned round = 0; round < 2; ++round)
            for (unsigned role = 0; role < ROLE_COUNT; ++role)
                offers[round][role] = make_offer(
                    states[round], role, parent_pid);

        std::array<PublicParentRoleAcknowledgement, 3> acknowledgements{};
        for (unsigned role = 0; role < ROLE_COUNT; ++role)
            send_packet(channels[0][role][0].get(), offers[0][role].bytes);
        for (unsigned role = 0; role < ROLE_COUNT; ++role) {
            const auto ack = receive_packet<ACK_BYTES>(
                channels[0][role][0].get(), pids[role]);
            acknowledgements[role] = parse_ack(
                ack, offers[0][role], states[0], role, parent_pid,
                pids[role]);
        }

        auto bindings = [&](unsigned round,
                            const std::array<PublicParentRoleAcknowledgement,
                                             3>& acks) {
            std::array<detail::RoleCompletionBinding, 3> result{};
            for (unsigned role = 0; role < ROLE_COUNT; ++role) {
                const auto& state = states[round];
                result[role] = detail::RoleCompletionBinding{
                    .role = role,
                    .round = state.value.round,
                    .classification = state.value.classification,
                    .capture_trial_id = state.value.capture_trial_id,
                    .run = state.value.financial_run,
                    .trial = state.value.trial,
                    .attempt = state.value.attempt,
                    .cohort = state.value.cohort,
                    .fresh_owner_issuance_identity =
                        state.value.fresh_owner_issuance_identity,
                    .parent_pid = parent_pid,
                    .child_pid = pids[role],
                    .fork_plan_identity = state.identity,
                    .offer_identity = offers[round][role].identity,
                    .ack_identity = acks[role].ack_identity,
                    .channel_nonce = offers[round][role].nonce,
                    .authority_identity = state.value.authority_identity,
                    .supervisor_session = state.value.supervisor_session,
                    .party_session = state.value.roles[role].party_session,
                    .service_identity = state.value.roles[role]
                        .service_identity,
                    .driver_selection_identity = state.value.roles[role]
                        .driver_selection_identity,
                    .capture_plan_identity =
                        state.value.capture_plan_identity,
                    .capture_source_identity =
                        state.value.capture_source_identity,
                    .capture_build_identity =
                        state.value.capture_build_identity,
                    .capture_launcher_identity =
                        state.value.capture_launcher_identity,
                };
            }
            return result;
        };

        std::array<int, 3> round1_fds{{-1, -1, -1}};
        std::array<int, 3> round2_fds{{-1, -1, -1}};
        for (unsigned role = 0; role < ROLE_COUNT; ++role) {
            round1_fds[role] = channels[0][role][0].release();
            round2_fds[role] = channels[1][role][0].release();
        }
        auto round1_children = std::unique_ptr<ParentRoleChildren>(
            new ParentRoleChildren(
                child_processes, round1_fds,
                bindings(0, acknowledgements),
                std::make_shared<detail::ParentRoleCompletionState>(),
                acknowledgements, states[0].identity,
                states[0].projection_route_identity, false));

        Bytes session_bytes;
        add(session_bytes, "KPB_REGISTERED_PERSISTENT_ROLE_SESSION_V1\n");
        add(session_bytes, states[0].identity);
        add(session_bytes, states[1].identity);
        for (const auto pid : pids) integer(session_bytes, pid);
        const auto session_identity = identity_registry::digest(session_bytes);
        need(nonzero(session_identity));
        auto storage = std::make_unique<RegisteredPersistentRoleSession::
            Storage>();
        storage->child_processes = child_processes;
        storage->round1 = std::move(round1_children);
        storage->round2_parent_fds = round2_fds;
        storage->round2_offers = offers[1];
        storage->round2_plan = states[1].value;
        storage->round2_fork_plan_identity = states[1].identity;
        storage->round2_projection_route_identity =
            states[1].projection_route_identity;
        storage->process_session_identity = session_identity;
        return RegisteredPersistentRoleSession(std::move(storage));
    } catch (...) {
        for (auto& round_channels : channels)
            for (auto& channel : round_channels)
                for (auto& endpoint : channel) endpoint.reset();
        for (auto& state : states)
            for (auto& source : state.source_fds) close_if_open(source);
        for (auto& source : round1.source_fds_) close_if_open(source);
        for (auto& source : round2.source_fds_) close_if_open(source);
        if (child_processes != nullptr)
            (void)child_processes->settle(true);
        else {
            const bool any_pidfd = std::any_of(
                pidfds.begin(), pidfds.end(),
                [](const UniqueFd& pidfd) { return pidfd.get() >= 0; });
            if (any_pidfd)
                settle_partially_pinned_children(pids, pidfds);
            else
                reap_unpinned_children(pids);
        }
        refuse();
    }
}

ParentRoleChildren& RegisteredParentPersistentRoleFork::round1(
        RegisteredPersistentRoleSession& session) {
    try {
        need(session.storage_ != nullptr && !session.storage_->waited &&
             session.storage_->round1 != nullptr);
        return *session.storage_->round1;
    } catch (...) { refuse(); }
}

ParentRoleChildren& RegisteredParentPersistentRoleFork::activate_round2(
        RegisteredPersistentRoleSession& session) {
    try {
        auto& storage = *session.storage_;
        need(!storage.waited && !storage.round2_activated &&
             storage.round1 != nullptr && !storage.round1->live_ &&
             storage.round2 == nullptr);
        storage.round2_activated = true;
        const auto parent_pid = static_cast<std::int64_t>(::getpid());
        std::array<PublicParentRoleAcknowledgement, 3> acknowledgements{};
        for (unsigned role = 0; role < ROLE_COUNT; ++role)
            send_packet(storage.round2_parent_fds[role],
                        storage.round2_offers[role].bytes);
        for (unsigned role = 0; role < ROLE_COUNT; ++role) {
            const auto ack = receive_packet<ACK_BYTES>(
                storage.round2_parent_fds[role],
                storage.child_processes->fork_pid(role));
            PlanState public_state;
            public_state.value = storage.round2_plan;
            public_state.projection_route_identity =
                storage.round2_projection_route_identity;
            public_state.identity = storage.round2_fork_plan_identity;
            acknowledgements[role] = parse_ack(
                ack, storage.round2_offers[role], public_state, role,
                parent_pid, storage.child_processes->fork_pid(role));
        }
        std::array<detail::RoleCompletionBinding, 3> bindings{};
        for (unsigned role = 0; role < ROLE_COUNT; ++role) {
            const auto& value = storage.round2_plan;
            bindings[role] = detail::RoleCompletionBinding{
                .role = role,
                .round = value.round,
                .classification = value.classification,
                .capture_trial_id = value.capture_trial_id,
                .run = value.financial_run,
                .trial = value.trial,
                .attempt = value.attempt,
                .cohort = value.cohort,
                .fresh_owner_issuance_identity =
                    value.fresh_owner_issuance_identity,
                .parent_pid = parent_pid,
                .child_pid = storage.child_processes->fork_pid(role),
                .fork_plan_identity = storage.round2_fork_plan_identity,
                .offer_identity = storage.round2_offers[role].identity,
                .ack_identity = acknowledgements[role].ack_identity,
                .channel_nonce = storage.round2_offers[role].nonce,
                .authority_identity = value.authority_identity,
                .supervisor_session = value.supervisor_session,
                .party_session = value.roles[role].party_session,
                .service_identity = value.roles[role].service_identity,
                .driver_selection_identity =
                    value.roles[role].driver_selection_identity,
                .capture_plan_identity = value.capture_plan_identity,
                .capture_source_identity = value.capture_source_identity,
                .capture_build_identity = value.capture_build_identity,
                .capture_launcher_identity = value.capture_launcher_identity,
            };
        }
        auto fds = storage.round2_parent_fds;
        storage.round2_parent_fds = {-1, -1, -1};
        storage.round2 = std::unique_ptr<ParentRoleChildren>(
            new ParentRoleChildren(
                storage.child_processes, fds, bindings,
                std::make_shared<detail::ParentRoleCompletionState>(),
                acknowledgements, storage.round2_fork_plan_identity,
                storage.round2_projection_route_identity, false));
        return *storage.round2;
    } catch (...) {
        if (session.storage_ != nullptr &&
            session.storage_->child_processes != nullptr)
            (void)session.storage_->child_processes->settle(true);
        refuse();
    }
}

detail::PersistentRoleExitEvidence
RegisteredPersistentRoleSession::finish_wait_for_trial() {
    try {
        auto& storage = *storage_;
        need(!storage.waited && storage.trial_join_claimed &&
             storage.round2_activated &&
             storage.round1 != nullptr && storage.round2 != nullptr &&
             !storage.round1->live_ && !storage.round2->live_);
        need(storage.child_processes != nullptr);
        const auto original_pids = storage.child_processes->fork_pids();
        const auto exits = storage.child_processes->settle(false);
        for (unsigned round = 0; round < 2; ++round) {
            const auto& children = round == 0
                ? *storage.round1 : *storage.round2;
            for (unsigned role = 0; role < ROLE_COUNT; ++role)
                need(children.acknowledgements_[role].child_pid ==
                         original_pids[role] &&
                     children.acknowledgements_[role].round == round + 1);
        }
        storage.waited = true;
        return detail::PersistentRoleExitEvidence(
            original_pids,
            {
                exits[0].pidfd_exit_observed,
                exits[1].pidfd_exit_observed,
                exits[2].pidfd_exit_observed,
            },
            {
                exits[0].wait_status_available,
                exits[1].wait_status_available,
                exits[2].wait_status_available,
            },
            {
                exits[0].pid_identity_exact,
                exits[1].pid_identity_exact,
                exits[2].pid_identity_exact,
            },
            {
                exits[0].exit_code,
                exits[1].exit_code,
                exits[2].exit_code,
            },
            {
                exits[0].term_signal,
                exits[1].term_signal,
                exits[2].term_signal,
            },
            std::array<PublicParentRoleForkCompletion, 2>{
                PublicParentRoleForkCompletion{
                    .fork_plan_identity =
                        storage.round1->fork_plan_identity_,
                    .acknowledgements =
                        storage.round1->acknowledgements_,
                },
                PublicParentRoleForkCompletion{
                    .fork_plan_identity =
                        storage.round2->fork_plan_identity_,
                    .acknowledgements =
                        storage.round2->acknowledgements_,
                },
            },
            storage.process_session_identity);
    } catch (...) { refuse(); }
}

void RegisteredPersistentRoleSession::claim_trial_join() {
    try {
        need(storage_ != nullptr && !storage_->waited &&
             !storage_->trial_join_claimed);
        storage_->trial_join_claimed = true;
    } catch (...) { refuse(); }
}

ParentRoleForkSourceStatus parent_role_fork_source_status() {
    return {
        .schema = "kpb-registered-parent-role-fork-source-only/v5",
        .status = "UNQUALIFIED_SOURCE_ONLY",
        .exact_three_internal_roles = true,
        .inherited_seqpacket_capability_channels = true,
        .kernel_sender_credentials_each_packet = true,
        .parent_self_ack_refused = true,
        .fixed_capture_fd_role_partition = true,
        .role0_projection_route_fixed_fd30 = true,
        .projection_route_exact_fork_binding = true,
        .projection_route_parent_alias_closed_before_offer = true,
        .typed_parent_bootstrap_transport = true,
        .inherited_parent_sealed_query_artifact = true,
        .child_full_query_admission_binding = true,
        .parent_supervisor_proposal_approval_transport = true,
        .pidfd_exact_process_identity = true,
        .pidfd_only_child_signaling = true,
        .unavailable_wait_status_refused = true,
        .persistent_same_pid_two_round_exit_evidence = true,
        .p1_two_round_observer_v5_capsule_residual = false,
        .pre_identity_process_reservation = true,
        .preidentity_child_descriptor_allowlist = true,
        .process_first_topology_reservation_permit = true,
        .post_reservation_trial_activation = false,
        .process_settled_abort_noalloc = true,
        .typed_complete_activation_abort = false,
        .selected_plan_factory_integration = false,
        .selected_gate_callsite_integration = false,
        .registered_driver_configured = false,
        .launch_authorized = false,
    };
}

} // namespace kpi::mpc::financial::registered_driver
