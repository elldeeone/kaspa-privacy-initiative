#include "privacy_measurement_parent_manifest.hpp"
#include "privacy_measurement_selected_parent_fixture_table_schema.hpp"
#include "privacy_measurement_selected_parent_launcher_wire.hpp"

#ifdef KPB_MEASUREMENT_SELECTED_PARENT_LAUNCHER_TEST_SETUP
#ifndef KPB_MEASUREMENT_SELECTED_PARENT_FIXTURE_TABLE_HEADER
#error "diagnostic selected-parent launcher requires its compiled table"
#endif
#include KPB_MEASUREMENT_SELECTED_PARENT_FIXTURE_TABLE_HEADER
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <linux/openat2.h>
#include <linux/memfd.h>
#include <memory>
#include <openssl/evp.h>
#include <poll.h>
#include <signal.h>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpb::measurement {
#ifdef KPB_MEASUREMENT_SELECTED_PARENT_LAUNCHER_TEST_SETUP
namespace {

namespace wire = selected_parent_wire;

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

constexpr int REQUIRED_SEALS =
    F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
        [](unsigned char byte) { return byte != 0; });
}

class Fd final {
    int value_{-1};
public:
    Fd() = default;
    explicit Fd(int value) : value_(value) {}
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept
        : value_(std::exchange(other.value_, -1)) {}
    Fd& operator=(Fd&& other) noexcept {
        if (this == &other) return *this;
        reset();
        value_ = std::exchange(other.value_, -1);
        return *this;
    }
    ~Fd() { reset(); }
    int get() const { return value_; }
    int release() { return std::exchange(value_, -1); }
    void reset(int value = -1) {
        if (value_ >= 0) {
            while (::close(value_) != 0 && errno == EINTR) {}
        }
        value_ = value;
    }
};

struct Fingerprint final {
    std::uint64_t device{};
    std::uint64_t inode{};
    std::uint64_t size{};
    std::uint32_t mode{};
    std::int64_t modified_seconds{};
    std::int64_t modified_nanoseconds{};
    std::int64_t changed_seconds{};
    std::int64_t changed_nanoseconds{};
    bool operator==(const Fingerprint&) const = default;
};

Fingerprint fingerprint(int fd, bool sealed) {
    struct stat status{};
    const int flags = ::fcntl(fd, F_GETFL);
    const int descriptor_flags = ::fcntl(fd, F_GETFD);
    need(flags >= 0 && descriptor_flags >= 0 &&
         (flags & O_ACCMODE) == O_RDONLY &&
         (descriptor_flags & FD_CLOEXEC) != 0 &&
         ::fstat(fd, &status) == 0 && S_ISREG(status.st_mode) &&
         status.st_size > 0);
    if (sealed)
        need((::fcntl(fd, F_GET_SEALS) & REQUIRED_SEALS) ==
             REQUIRED_SEALS);
    return {
        .device = static_cast<std::uint64_t>(status.st_dev),
        .inode = static_cast<std::uint64_t>(status.st_ino),
        .size = static_cast<std::uint64_t>(status.st_size),
        .mode = static_cast<std::uint32_t>(status.st_mode),
        .modified_seconds = status.st_mtim.tv_sec,
        .modified_nanoseconds = status.st_mtim.tv_nsec,
        .changed_seconds = status.st_ctim.tv_sec,
        .changed_nanoseconds = status.st_ctim.tv_nsec,
    };
}

Digest hash_fd(int fd, std::uint64_t size) {
    struct Deleter final {
        void operator()(EVP_MD_CTX* value) const { EVP_MD_CTX_free(value); }
    };
    std::unique_ptr<EVP_MD_CTX, Deleter> context(EVP_MD_CTX_new());
    need(context != nullptr &&
         EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) == 1);
    std::array<unsigned char, 1U << 15> buffer{};
    std::uint64_t at = 0;
    while (at < size) {
        const auto wanted = static_cast<std::size_t>(
            std::min<std::uint64_t>(buffer.size(), size - at));
        ssize_t count;
        do {
            count = ::pread(fd, buffer.data(), wanted,
                            static_cast<off_t>(at));
        } while (count < 0 && errno == EINTR);
        need(count > 0 && static_cast<std::size_t>(count) <= wanted &&
             EVP_DigestUpdate(context.get(), buffer.data(),
                              static_cast<std::size_t>(count)) == 1);
        at += static_cast<std::uint64_t>(count);
    }
    unsigned char trailing{};
    ssize_t count;
    do {
        count = ::pread(fd, &trailing, 1, static_cast<off_t>(size));
    } while (count < 0 && errno == EINTR);
    need(count == 0);
    Digest result{};
    unsigned output_size = 0;
    need(EVP_DigestFinal_ex(context.get(), result.data(), &output_size) == 1 &&
         output_size == result.size() && nonzero(result));
    return result;
}

Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    need(EVP_Digest(value.data(), value.size(), result.data(), nullptr,
                    EVP_sha256(), nullptr) == 1 && nonzero(result));
    return result;
}

Fd open_exact_source(std::string_view path) {
#ifdef SYS_openat2
    std::string terminated(path);
    struct open_how how{};
    how.flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW;
    how.resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
    int fd;
    do {
        fd = static_cast<int>(::syscall(
            SYS_openat2, AT_FDCWD, terminated.c_str(), &how, sizeof(how)));
    } while (fd < 0 && errno == EINTR);
    need(fd >= 0);
    return Fd(fd);
#else
    (void)path;
    refuse();
#endif
}

void write_all(int fd, std::span<const unsigned char> value) {
    std::size_t at = 0;
    while (at < value.size()) {
        ssize_t count;
        do {
            count = ::write(fd, value.data() + at, value.size() - at);
        } while (count < 0 && errno == EINTR);
        need(count > 0);
        at += static_cast<std::size_t>(count);
    }
}

Fd sealed_copy(int source, const Fingerprint& original, bool executable,
               const Digest& expected) {
    Fd writable(::memfd_create(
        "kpb-selected-parent-artifact",
        MFD_CLOEXEC | MFD_ALLOW_SEALING |
            (executable ? MFD_EXEC : MFD_NOEXEC_SEAL)));
    need(writable.get() >= 0);
    std::array<unsigned char, 1U << 15> buffer{};
    std::uint64_t at = 0;
    while (at < original.size) {
        const auto wanted = static_cast<std::size_t>(
            std::min<std::uint64_t>(buffer.size(), original.size - at));
        ssize_t count;
        do {
            count = ::pread(source, buffer.data(), wanted,
                            static_cast<off_t>(at));
        } while (count < 0 && errno == EINTR);
        need(count > 0 && static_cast<std::size_t>(count) <= wanted);
        write_all(writable.get(), std::span(
            buffer.data(), static_cast<std::size_t>(count)));
        at += static_cast<std::uint64_t>(count);
    }
    need(fingerprint(source, false) == original &&
         ::fchmod(writable.get(), executable ? 0500 : 0400) == 0 &&
         ::fcntl(writable.get(), F_ADD_SEALS, REQUIRED_SEALS) == 0);
    std::array<char, 64> path{};
    const int length = std::snprintf(
        path.data(), path.size(), "/proc/self/fd/%d", writable.get());
    need(length > 0 && static_cast<std::size_t>(length) < path.size());
    Fd readonly(::open(path.data(), O_RDONLY | O_CLOEXEC));
    need(readonly.get() >= 0);
    const auto sealed = fingerprint(readonly.get(), true);
    need(sealed.size == original.size &&
         hash_fd(readonly.get(), sealed.size) == expected);
    return readonly;
}

void put_u32(std::span<unsigned char> out, std::size_t at,
             std::uint32_t value) {
    for (unsigned index = 0; index < 4; ++index)
        out[at + index] = static_cast<unsigned char>(value >> (8 * index));
}

std::uint32_t get_u32(std::span<const unsigned char> in, std::size_t at) {
    std::uint32_t result = 0;
    for (unsigned index = 0; index < 4; ++index)
        result |= static_cast<std::uint32_t>(in[at + index]) << (8 * index);
    return result;
}

std::uint64_t get_u64(std::span<const unsigned char> in, std::size_t at) {
    std::uint64_t result = 0;
    for (unsigned index = 0; index < 8; ++index)
        result |= static_cast<std::uint64_t>(in[at + index]) << (8 * index);
    return result;
}

Digest random_digest() {
    Digest result{};
    ssize_t count;
    do {
        count = ::getrandom(result.data(), result.size(), 0);
    } while (count < 0 && errno == EINTR);
    need(count == static_cast<ssize_t>(result.size()) && nonzero(result));
    return result;
}

void pass_credentials(int fd) {
    const int enabled = 1;
    need(::setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &enabled,
                      sizeof(enabled)) == 0);
}

void close_child_unselected_fds() {
#ifdef SYS_close_range
    need(::syscall(SYS_close_range, 3U,
                   static_cast<unsigned>(wire::CONTROL_FD - 1), 0U) == 0);
    need(::syscall(SYS_close_range,
                   static_cast<unsigned>(wire::CONTROL_FD + 1),
                   static_cast<unsigned>(wire::ARTIFACT_FD_BASE - 1),
                   0U) == 0);
    need(::syscall(SYS_close_range,
                   static_cast<unsigned>(wire::ARTIFACT_FD_BASE +
                                         wire::ARTIFACTS),
                   UINT_MAX, 0U) == 0);
#else
    refuse();
#endif
}

using ArtifactFds = std::array<std::array<Fd, wire::FIELDS>,
                               wire::COMPONENTS>;

void child_exec(
        int socket, const ArtifactFds& artifacts,
        unsigned executable_component, unsigned executable_field) {
    Fd null(::open("/dev/null", O_RDWR | O_CLOEXEC));
    need(null.get() >= 0);
    for (int fd = 0; fd <= 2; ++fd) {
        if (null.get() == fd)
            need(::fcntl(fd, F_SETFD, 0) == 0);
        else
            need(::dup3(null.get(), fd, 0) == fd);
    }
    need(::dup3(socket, wire::CONTROL_FD, 0) == wire::CONTROL_FD);
    std::array<int, wire::ARTIFACTS> preserved{};
    preserved.fill(-1);
    for (unsigned component = 0; component < wire::COMPONENTS; ++component)
        for (unsigned field = 0; field < wire::FIELDS; ++field) {
            const unsigned index = component * wire::FIELDS + field;
            int duplicate;
            do {
                duplicate = ::fcntl(
                    artifacts[component][field].get(), F_DUPFD_CLOEXEC,
                    256);
            } while (duplicate < 0 && errno == EINTR);
            need(duplicate >= 256);
            preserved[index] = duplicate;
        }
    for (unsigned component = 0; component < wire::COMPONENTS; ++component)
        for (unsigned field = 0; field < wire::FIELDS; ++field) {
            const unsigned index = component * wire::FIELDS + field;
            const int target = wire::ARTIFACT_FD_BASE +
                static_cast<int>(index);
            need(::dup3(preserved[index], target, 0) ==
                 target);
        }
    close_child_unselected_fds();
    const int executable = wire::ARTIFACT_FD_BASE +
        static_cast<int>(executable_component * wire::FIELDS +
                         executable_field);
    char name[] = "kpb-selected-parent-fixture";
    char* const arguments[]{name, nullptr};
    char* const environment[]{nullptr};
#ifdef SYS_execveat
    (void)::syscall(SYS_execveat, executable, "", arguments, environment,
                    AT_EMPTY_PATH);
#endif
    _exit(127);
}

struct ChildCompletion final {
    std::int64_t pid{-1};
    Digest session{};
    Digest exit_identity{};
};

ChildCompletion launch_and_verify_child(
        const ArtifactFds& artifacts,
        const std::array<std::array<Digest, wire::FIELDS>,
                         wire::COMPONENTS>& expected,
        unsigned executable_component, unsigned executable_field,
        bool child_nonzero) {
    int sockets[2]{-1, -1};
    need(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0,
                      sockets) == 0);
    Fd parent(sockets[0]);
    Fd child(sockets[1]);
    pass_credentials(parent.get());
    pass_credentials(child.get());
    const auto session = random_digest();
    pid_t pid = ::fork();
    need(pid >= 0);
    if (pid == 0) {
        parent.reset();
        child_exec(child.get(), artifacts, executable_component,
                   executable_field);
    }
    child.reset();
    bool reaped = false;
    try {
        std::array<unsigned char, wire::OFFER_BYTES> offer{};
        std::copy(wire::OFFER_MAGIC.begin(), wire::OFFER_MAGIC.end(),
                  offer.begin());
        put_u32(offer, 8, wire::VERSION);
        std::copy(session.begin(), session.end(), offer.begin() + 12);
        put_u32(offer, 44, child_nonzero ? 1U : 0U);
        ssize_t sent;
        do {
            sent = ::send(parent.get(), offer.data(), offer.size(),
                          MSG_NOSIGNAL);
        } while (sent < 0 && errno == EINTR);
        need(sent == static_cast<ssize_t>(offer.size()));

        std::array<unsigned char, wire::COMPLETION_BYTES> packet{};
        std::array<unsigned char, CMSG_SPACE(sizeof(struct ucred))> control{};
        struct iovec vector{packet.data(), packet.size()};
        struct msghdr message{};
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        message.msg_control = control.data();
        message.msg_controllen = control.size();
        ssize_t received;
        do {
            received = ::recvmsg(parent.get(), &message, MSG_CMSG_CLOEXEC);
        } while (received < 0 && errno == EINTR);
        need(received == static_cast<ssize_t>(packet.size()) &&
             (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0);
        unsigned credentials = 0;
        for (auto* header = CMSG_FIRSTHDR(&message); header != nullptr;
             header = CMSG_NXTHDR(&message, header)) {
            need(header->cmsg_level == SOL_SOCKET &&
                 header->cmsg_type == SCM_CREDENTIALS &&
                 header->cmsg_len == CMSG_LEN(sizeof(struct ucred)));
            const auto* value = reinterpret_cast<const struct ucred*>(
                CMSG_DATA(header));
            need(value->pid == pid && value->uid == ::geteuid() &&
                 value->gid == ::getegid());
            ++credentials;
        }
        need(credentials == 1 &&
             std::equal(wire::COMPLETION_MAGIC.begin(),
                        wire::COMPLETION_MAGIC.end(), packet.begin()) &&
             get_u32(packet, 8) == wire::VERSION &&
             std::equal(session.begin(), session.end(), packet.begin() + 12) &&
             get_u64(packet, 44) == static_cast<std::uint64_t>(pid));
        std::size_t at = 52;
        for (unsigned component = 0; component < wire::COMPONENTS;
             ++component)
            for (unsigned field = 0; field < wire::FIELDS; ++field) {
                const auto local = fingerprint(
                    artifacts[component][field].get(), true);
                need(get_u64(packet, at) == local.device &&
                     get_u64(packet, at + 8) == local.inode &&
                     get_u64(packet, at + 16) == local.size &&
                     std::equal(expected[component][field].begin(),
                                expected[component][field].end(),
                                packet.begin() +
                                    static_cast<std::ptrdiff_t>(at + 24)));
                at += wire::SLOT_BYTES;
            }
        need(at == packet.size());

        struct pollfd polled{parent.get(), POLLIN | POLLHUP, 0};
        int ready;
        do { ready = ::poll(&polled, 1, 5000); }
        while (ready < 0 && errno == EINTR);
        need(ready == 1 && (polled.revents & POLLHUP) != 0);
        unsigned char trailing{};
        std::array<unsigned char, CMSG_SPACE(sizeof(struct ucred))>
            eof_control{};
        struct iovec eof_vector{&trailing, 1};
        struct msghdr eof_message{};
        eof_message.msg_iov = &eof_vector;
        eof_message.msg_iovlen = 1;
        eof_message.msg_control = eof_control.data();
        eof_message.msg_controllen = eof_control.size();
        ssize_t eof;
        do { eof = ::recvmsg(parent.get(), &eof_message, MSG_DONTWAIT); }
        while (eof < 0 && errno == EINTR);
        need(eof == 0 && CMSG_FIRSTHDR(&eof_message) == nullptr &&
             (eof_message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0);

        int status = 0;
        pid_t waited;
        do { waited = ::waitpid(pid, &status, 0); }
        while (waited < 0 && errno == EINTR);
        reaped = true;
        need(waited == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        std::vector<unsigned char> exit_bytes;
        constexpr std::string_view domain =
            "KPB_SELECTED_PARENT_CHILD_EXIT_V1\n";
        exit_bytes.insert(exit_bytes.end(), domain.begin(), domain.end());
        exit_bytes.insert(exit_bytes.end(), session.begin(), session.end());
        for (unsigned index = 0; index < 8; ++index)
            exit_bytes.push_back(static_cast<unsigned char>(
                static_cast<std::uint64_t>(pid) >> (8 * index)));
        const auto& executable = expected[executable_component]
            [executable_field];
        exit_bytes.insert(exit_bytes.end(), executable.begin(),
                          executable.end());
        return {
            .pid = pid,
            .session = session,
            .exit_identity = hash(exit_bytes),
        };
    } catch (...) {
        if (!reaped) {
            (void)::kill(pid, SIGKILL);
            int status = 0;
            while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        }
        refuse();
    }
}

} // namespace

#ifdef KPB_MEASUREMENT_SELECTED_PARENT_LAUNCHER_TEST_SETUP
ParentManifestRecomputationAuthority
SelectedParentArtifactLauncher::test_only_launch_compiled_fixture(
        SelectedParentLauncherTestFault fault) {
    using namespace selected_parent_fixture;
    static_assert(kArtifacts.size() == wire::COMPONENTS);
    static_assert(kExecutableComponent < wire::COMPONENTS);
    static_assert(kExecutableField < wire::FIELDS);
    std::array<std::array<Fd, wire::FIELDS>, wire::COMPONENTS> sources;
    ArtifactFds sealed;
    std::array<std::array<Digest, wire::FIELDS>, wire::COMPONENTS> expected{};
    try {
        for (unsigned component = 0; component < wire::COMPONENTS;
             ++component)
            for (unsigned field = 0; field < wire::FIELDS; ++field) {
                const auto& spec = kArtifacts[component][field];
                const auto path =
                    fault == SelectedParentLauncherTestFault::SymlinkSource &&
                            component == 0 && field == 0
                        ? kSymlinkPath : spec.path;
                sources[component][field] = open_exact_source(path);
                const auto before = fingerprint(
                    sources[component][field].get(), false);
                need(hash_fd(sources[component][field].get(), before.size) ==
                     spec.expected_sha256 &&
                     fingerprint(sources[component][field].get(), false) ==
                         before);
                expected[component][field] = spec.expected_sha256;
            }
        if (fault == SelectedParentLauncherTestFault::SwapPathAfterOpen)
            need(::rename(std::string(kSwapReplacementPath).c_str(),
                          std::string(kSwapTargetPath).c_str()) == 0);
        for (unsigned component = 0; component < wire::COMPONENTS;
             ++component)
            for (unsigned field = 0; field < wire::FIELDS; ++field) {
                const auto before = fingerprint(
                    sources[component][field].get(), false);
                sealed[component][field] = sealed_copy(
                    sources[component][field].get(), before,
                    component == kExecutableComponent &&
                        field == kExecutableField,
                    expected[component][field]);
            }
        std::set<std::pair<std::uint64_t, std::uint64_t>> unique;
        for (const auto& component : sealed)
            for (const auto& artifact : component) {
                const auto value = fingerprint(artifact.get(), true);
                need(unique.insert({value.device, value.inode}).second);
            }
        const auto completion = launch_and_verify_child(
            sealed, expected, kExecutableComponent, kExecutableField,
            fault == SelectedParentLauncherTestFault::ChildNonzeroExit);

        std::array<ParentManifestComponentArtifacts, wire::COMPONENTS>
            selected{};
        for (unsigned component = 0; component < wire::COMPONENTS;
             ++component)
            for (unsigned field = 0; field < wire::FIELDS; ++field)
                selected[component].fds[field] =
                    sealed[component][field].release();
        auto selection = ParentManifestArtifactSelector::source_owned_select(
            std::move(selected));
        selection.bind_verified_selected_child(
            kExecutableComponent,
            expected[kExecutableComponent][kExecutableField],
            completion.session, completion.exit_identity, completion.pid);
        return ParentManifestRecomputationFactory::recompute(
            std::move(selection));
    } catch (...) {
        refuse();
    }
}
#endif

#endif // KPB_MEASUREMENT_SELECTED_PARENT_LAUNCHER_TEST_SETUP

} // namespace kpb::measurement
