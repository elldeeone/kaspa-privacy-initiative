#include "docker_monotonic_anchor_client.hpp"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <openssl/crypto.h>
#include <span>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::docker_anchor {
namespace {
using Bytes = std::vector<unsigned char>;
using Snapshot = attempt_supervisor::ExternalAnchorSnapshot;

constexpr std::string_view PROTOCOL = "KPBANCHOR1";
constexpr std::size_t MAX_RESPONSE = 4096;

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) { return value != Digest{}; }

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add(Bytes& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}
void integer(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

std::uint64_t natural(const std::string& value) {
    need(!value.empty() && (value == "0" || value.front() != '0'));
    std::uint64_t result = 0;
    const auto parsed = std::from_chars(
        value.data(), value.data() + value.size(), result, 10);
    need(parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size());
    return result;
}

std::vector<std::string> exact_tokens(const std::string& line) {
    need(!line.empty() && line.back() == '\n');
    const auto raw = std::string_view(line).substr(0, line.size() - 1);
    need(!raw.empty() && raw.front() != ' ' && raw.back() != ' ' &&
         raw.find("  ") == std::string_view::npos &&
         std::all_of(raw.begin(), raw.end(), [](unsigned char character) {
             return character == 0x20 ||
                    (character >= 0x21 && character <= 0x7e);
         }));
    std::vector<std::string> result;
    std::size_t at = 0;
    while (at < raw.size()) {
        const auto end = raw.find(' ', at);
        if (end == std::string_view::npos) {
            result.emplace_back(raw.substr(at));
            break;
        }
        result.emplace_back(raw.substr(at, end - at));
        at = end + 1;
    }
    return result;
}

void checked_socket_path(const PublicConfiguration& configuration) {
    const auto& path = configuration.socket_path;
    need(path.is_absolute() && path == path.lexically_normal());
    for (auto current = path.parent_path(); !current.empty();
         current = current.parent_path()) {
        struct stat component {};
        need(::lstat(current.c_str(), &component) == 0 &&
             !S_ISLNK(component.st_mode));
        if (current == current.root_path()) break;
    }
    struct stat directory {}, socket_file {};
    need(::lstat(path.parent_path().c_str(), &directory) == 0 &&
         S_ISDIR(directory.st_mode) &&
         directory.st_uid == configuration.service_uid &&
         (directory.st_mode & 07777) == 0750 &&
         ::lstat(path.c_str(), &socket_file) == 0 &&
         S_ISSOCK(socket_file.st_mode) &&
         socket_file.st_uid == configuration.service_uid &&
         socket_file.st_nlink == 1 &&
         (socket_file.st_mode & 07777) == 0660);
}

struct FileDescriptor {
    int value = -1;
    explicit FileDescriptor(int fd) : value(fd) { need(value >= 0); }
    ~FileDescriptor() { if (value >= 0) (void)::close(value); }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
};

void send_all(int fd, std::string_view request) {
    std::size_t sent = 0;
    while (sent < request.size()) {
        const auto result = ::send(fd, request.data() + sent,
                                   request.size() - sent, MSG_NOSIGNAL);
        if (result < 0 && errno == EINTR) continue;
        need(result > 0);
        sent += static_cast<std::size_t>(result);
    }
}

std::string exchange(const PublicConfiguration& configuration,
                     const std::array<unsigned char, 32>& capability,
                     const std::string& operation) {
    need(operation.size() <= 2048 &&
         operation.find('\n') == std::string::npos);
    checked_socket_path(configuration);
    FileDescriptor socket_fd(::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
    timeval timeout{.tv_sec = 5, .tv_usec = 0};
    need(::setsockopt(socket_fd.value, SOL_SOCKET, SO_RCVTIMEO,
                      &timeout, sizeof(timeout)) == 0 &&
         ::setsockopt(socket_fd.value, SOL_SOCKET, SO_SNDTIMEO,
                      &timeout, sizeof(timeout)) == 0);
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    const auto path = configuration.socket_path.string();
    need(path.size() < sizeof(address.sun_path));
    std::copy(path.begin(), path.end(), address.sun_path);
    address.sun_path[path.size()] = '\0';
    need(::connect(socket_fd.value, reinterpret_cast<sockaddr*>(&address),
                   sizeof(address)) == 0);
    struct {
        pid_t pid;
        uid_t uid;
        gid_t gid;
    } credentials{};
    socklen_t credential_bytes = sizeof(credentials);
    need(::getsockopt(socket_fd.value, SOL_SOCKET, SO_PEERCRED,
                      &credentials, &credential_bytes) == 0 &&
         credential_bytes == sizeof(credentials) && credentials.pid > 0 &&
         credentials.uid == configuration.service_uid &&
         configuration.service_uid != ::geteuid());

    const auto separator = operation.find(' ');
    const auto verb = operation.substr(0, separator);
    const auto arguments = separator == std::string::npos
        ? std::string{} : operation.substr(separator + 1);
    need((verb == "STATUS" && arguments.empty()) ||
         (verb == "ADVANCE" && !arguments.empty()));
    const auto request = std::string(PROTOCOL) + " " + verb + " " +
        identity_registry::hex(capability) +
        (arguments.empty() ? "" : " " + arguments) + "\n";
    send_all(socket_fd.value, request);
    need(::shutdown(socket_fd.value, SHUT_WR) == 0);
    std::string response;
    std::array<char, 256> buffer{};
    while (response.find('\n') == std::string::npos) {
        const auto count = ::recv(socket_fd.value, buffer.data(), buffer.size(), 0);
        if (count < 0 && errno == EINTR) continue;
        need(count > 0);
        response.append(buffer.data(), static_cast<std::size_t>(count));
        need(response.size() <= MAX_RESPONSE);
    }
    need(response.back() == '\n' &&
         response.find('\n') == response.size() - 1);
    return response;
}

struct Response {
    Snapshot snapshot;
    Digest configuration;
    Digest instance;
};

Response parse_response(const std::string& line,
                        const PublicConfiguration& expected) {
    const auto tokens = exact_tokens(line);
    if (tokens.size() == 2 && tokens[0] == PROTOCOL && tokens[1] == "REFUSED")
        refuse();
    need(tokens.size() == 14 && tokens[0] == PROTOCOL && tokens[1] == "OK" &&
         tokens[2] == "READY" && tokens[10] == "NONE" &&
         tokens[11] == "0" && tokens[12] == "0" && tokens[13] == "1");
    const auto authority = identity_registry::unhex(tokens[3]);
    const auto configuration = identity_registry::unhex(tokens[4]);
    const auto instance = identity_registry::unhex(tokens[5]);
    const auto sequence = natural(tokens[6]);
    const auto checkpoint = identity_registry::unhex(tokens[7]);
    const auto record = identity_registry::unhex(tokens[8]);
    const auto runtime_uid = natural(tokens[9]);
    need(authority == expected.authority_identity &&
         configuration == expected.configuration_identity &&
         instance == expected.instance_identity && nonzero(checkpoint) &&
         nonzero(record) && runtime_uid == expected.service_uid);
    return Response{
        .snapshot = Snapshot{
            .authority_identity = authority,
            .sequence = sequence,
            .checkpoint = checkpoint,
        },
        .configuration = configuration,
        .instance = instance,
    };
}

std::string status_operation() { return "STATUS"; }

Digest transition_identity(const PublicConfiguration& configuration,
                           const Snapshot& expected,
                           const Snapshot& next) {
    Bytes bytes;
    add(bytes, "KPB_DOCKER_ANCHOR_TRANSITION_V1\n");
    add(bytes, configuration.configuration_identity);
    add(bytes, configuration.instance_identity);
    add(bytes, expected.authority_identity);
    integer(bytes, expected.sequence);
    add(bytes, expected.checkpoint);
    integer(bytes, next.sequence);
    add(bytes, next.checkpoint);
    return identity_registry::digest(bytes);
}

std::string advance_operation(const PublicConfiguration& configuration,
                              const Snapshot& expected,
                              const Snapshot& next) {
    return "ADVANCE " + identity_registry::hex(configuration.authority_identity) +
        " " + identity_registry::hex(configuration.configuration_identity) +
        " " + identity_registry::hex(configuration.instance_identity) +
        " " + std::to_string(expected.sequence) +
        " " + identity_registry::hex(expected.checkpoint) +
        " " + std::to_string(next.sequence) +
        " " + identity_registry::hex(next.checkpoint) +
        " " + identity_registry::hex(
            transition_identity(configuration, expected, next));
}
} // namespace

SupervisorCapability::SupervisorCapability(
    std::array<unsigned char, 32> value) : value_(value) {}

SupervisorCapability::~SupervisorCapability() {
    OPENSSL_cleanse(value_.data(), value_.size());
}

SupervisorCapability::SupervisorCapability(
    SupervisorCapability&& other) noexcept
    : value_(other.value_), live_(other.live_.exchange(false)) {
    OPENSSL_cleanse(other.value_.data(), other.value_.size());
}

#ifdef KPI_DOCKER_ANCHOR_CLIENT_TEST_SETUP
SupervisorCapability SupervisorCapability::test_only_mint(
    const std::string& value) {
    return SupervisorCapability(identity_registry::unhex(value));
}
#endif

Client::Client(PublicConfiguration configuration,
               SupervisorCapability&& capability)
    : configuration_(std::move(configuration)), capability_(capability.value_) {
    const bool live = capability.live_.exchange(false);
    OPENSSL_cleanse(capability.value_.data(), capability.value_.size());
    need(live && configuration_.service_uid > 0 &&
         configuration_.service_uid != ::geteuid() &&
         nonzero(configuration_.authority_identity) &&
         nonzero(configuration_.configuration_identity) &&
         nonzero(configuration_.instance_identity) &&
         configuration_.authority_identity != configuration_.configuration_identity &&
         configuration_.authority_identity != configuration_.instance_identity &&
         configuration_.configuration_identity != configuration_.instance_identity &&
         nonzero(capability_));
}

Client::~Client() {
    OPENSSL_cleanse(capability_.data(), capability_.size());
}

#ifdef KPI_DOCKER_ANCHOR_CLIENT_TEST_SETUP
Client Client::test_only_connect(PublicConfiguration configuration,
                                 SupervisorCapability&& capability) {
    return Client(std::move(configuration), std::move(capability));
}
#endif

Snapshot Client::snapshot_unlocked() {
    need(!poisoned_);
    return parse_response(
        exchange(configuration_, capability_, status_operation()),
        configuration_).snapshot;
}

Snapshot Client::snapshot() {
    std::lock_guard guard(mutex_);
    try {
        return snapshot_unlocked();
    } catch (...) {
        poisoned_ = true;
        refuse();
    }
}

void Client::compare_and_advance(const Snapshot& expected,
                                 const Snapshot& next) {
    std::lock_guard guard(mutex_);
    try {
        need(!poisoned_ && expected.authority_identity == configuration_.authority_identity &&
             next.authority_identity == configuration_.authority_identity &&
             nonzero(expected.checkpoint) && nonzero(next.checkpoint) &&
             expected.sequence != std::numeric_limits<std::uint64_t>::max() &&
             next.sequence == expected.sequence + 1);
        const auto response = parse_response(
            exchange(configuration_, capability_,
                     advance_operation(configuration_, expected, next)),
            configuration_);
        need(response.snapshot == next);
    } catch (...) {
        poisoned_ = true;
        refuse();
    }
}

SourceStatus source_status() {
    return SourceStatus{
        .schema = "kpb-docker-monotonic-anchor-client-source-only/v1",
        .status = "BOUNDED_DOCKER_RESEARCH_ONLY",
        .real_docker_controls = true,
        .mutual_peer_credentials = true,
        .selected_bridge_integration = false,
        .selected_party_namespace_integration = false,
        .docker_operator_can_rollback = true,
        .registered_driver_configured = false,
        .launch_authorized = false,
    };
}

} // namespace kpi::mpc::financial::docker_anchor
