#include "privacy_measurement_selected_parent_launcher_wire.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <memory>
#include <openssl/evp.h>
#include <span>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

namespace wire = kpb::measurement::selected_parent_wire;
using Digest = std::array<unsigned char, 32>;

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
        [](unsigned char byte) { return byte != 0; });
}

std::uint32_t get_u32(std::span<const unsigned char> in, std::size_t at) {
    std::uint32_t result = 0;
    for (unsigned index = 0; index < 4; ++index)
        result |= static_cast<std::uint32_t>(in[at + index]) << (8 * index);
    return result;
}

void put_u32(std::span<unsigned char> out, std::size_t at,
             std::uint32_t value) {
    for (unsigned index = 0; index < 4; ++index)
        out[at + index] = static_cast<unsigned char>(value >> (8 * index));
}

void put_u64(std::span<unsigned char> out, std::size_t at,
             std::uint64_t value) {
    for (unsigned index = 0; index < 8; ++index)
        out[at + index] = static_cast<unsigned char>(value >> (8 * index));
}

Digest hash_fd(int fd, std::uint64_t size) {
    struct Deleter final {
        void operator()(EVP_MD_CTX* value) const { EVP_MD_CTX_free(value); }
    };
    std::unique_ptr<EVP_MD_CTX, Deleter> context(EVP_MD_CTX_new());
    if (context == nullptr ||
        EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1)
        return {};
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
        if (count <= 0 || static_cast<std::size_t>(count) > wanted ||
            EVP_DigestUpdate(context.get(), buffer.data(),
                             static_cast<std::size_t>(count)) != 1)
            return {};
        at += static_cast<std::uint64_t>(count);
    }
    unsigned char trailing{};
    ssize_t count;
    do {
        count = ::pread(fd, &trailing, 1, static_cast<off_t>(size));
    } while (count < 0 && errno == EINTR);
    if (count != 0) return {};
    Digest result{};
    unsigned output_size = 0;
    if (EVP_DigestFinal_ex(context.get(), result.data(), &output_size) != 1 ||
        output_size != result.size() || !nonzero(result))
        return {};
    return result;
}

int run() {
    std::array<unsigned char, wire::OFFER_BYTES> offer{};
    std::array<unsigned char, CMSG_SPACE(sizeof(struct ucred))> control{};
    struct iovec vector{offer.data(), offer.size()};
    struct msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t received;
    do {
        received = ::recvmsg(wire::CONTROL_FD, &message, MSG_CMSG_CLOEXEC);
    } while (received < 0 && errno == EINTR);
    if (received != static_cast<ssize_t>(offer.size()) ||
        (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 ||
        !std::equal(wire::OFFER_MAGIC.begin(), wire::OFFER_MAGIC.end(),
                    offer.begin()) || get_u32(offer, 8) != wire::VERSION)
        return 2;
    unsigned credentials = 0;
    for (auto* header = CMSG_FIRSTHDR(&message); header != nullptr;
         header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level != SOL_SOCKET ||
            header->cmsg_type != SCM_CREDENTIALS ||
            header->cmsg_len != CMSG_LEN(sizeof(struct ucred)))
            return 3;
        const auto* value = reinterpret_cast<const struct ucred*>(
            CMSG_DATA(header));
        if (value->pid != ::getppid() || value->uid != ::geteuid() ||
            value->gid != ::getegid())
            return 4;
        ++credentials;
    }
    if (credentials != 1) return 5;
    if (get_u32(offer, 44) != 0) return 7;

    std::array<unsigned char, wire::COMPLETION_BYTES> packet{};
    std::copy(wire::COMPLETION_MAGIC.begin(), wire::COMPLETION_MAGIC.end(),
              packet.begin());
    put_u32(packet, 8, wire::VERSION);
    std::copy(offer.begin() + 12, offer.begin() + 44,
              packet.begin() + 12);
    put_u64(packet, 44, static_cast<std::uint64_t>(::getpid()));
    std::size_t at = 52;
    constexpr int seals =
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    for (unsigned index = 0; index < wire::ARTIFACTS; ++index) {
        const int fd = wire::ARTIFACT_FD_BASE + static_cast<int>(index);
        struct stat status{};
        const int flags = ::fcntl(fd, F_GETFL);
        if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY ||
            ::fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
            status.st_size <= 0 ||
            (::fcntl(fd, F_GET_SEALS) & seals) != seals)
            return 8;
        const auto digest = hash_fd(
            fd, static_cast<std::uint64_t>(status.st_size));
        if (!nonzero(digest)) return 9;
        put_u64(packet, at, static_cast<std::uint64_t>(status.st_dev));
        put_u64(packet, at + 8, static_cast<std::uint64_t>(status.st_ino));
        put_u64(packet, at + 16,
                static_cast<std::uint64_t>(status.st_size));
        std::copy(digest.begin(), digest.end(), packet.begin() +
                  static_cast<std::ptrdiff_t>(at + 24));
        at += wire::SLOT_BYTES;
    }
    if (at != packet.size()) return 10;
    ssize_t sent;
    do {
        sent = ::send(wire::CONTROL_FD, packet.data(), packet.size(),
                      MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent != static_cast<ssize_t>(packet.size())) return 11;
    for (unsigned index = 0; index < wire::ARTIFACTS; ++index)
        (void)::close(wire::ARTIFACT_FD_BASE + static_cast<int>(index));
    (void)::close(wire::CONTROL_FD);
    return 0;
}

} // namespace

int main() { return run(); }
