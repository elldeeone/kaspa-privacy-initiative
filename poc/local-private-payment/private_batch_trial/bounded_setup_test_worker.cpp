#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "bounded_setup_wire.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <signal.h>
#include <span>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

namespace {
namespace wire = kpb::bounded_setup::wire;

#ifndef KPB_BOUNDED_SETUP_WORKER_BEHAVIOR
#define KPB_BOUNDED_SETUP_WORKER_BEHAVIOR 0
#endif

std::uint64_t get_u64(std::span<const unsigned char> input, std::size_t at) {
    std::uint64_t result = 0;
    for (unsigned i = 0; i < 8; ++i)
        result |= static_cast<std::uint64_t>(input[at + i]) << (8 * i);
    return result;
}

void put_u64(std::span<unsigned char> output, std::size_t at,
             std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i)
        output[at + i] = static_cast<unsigned char>(value >> (8 * i));
}

bool read_exact(int fd, std::span<unsigned char> output) {
    std::size_t at = 0;
    while (at < output.size()) {
        ssize_t count;
        do {
            count = ::pread(fd, output.data() + at, output.size() - at,
                            static_cast<off_t>(at));
        } while (count < 0 && errno == EINTR);
        if (count <= 0) return false;
        at += static_cast<std::size_t>(count);
    }
    unsigned char trailing{};
    return ::pread(fd, &trailing, 1, static_cast<off_t>(output.size())) == 0;
}

constexpr std::uint32_t rotate_right(std::uint32_t value, unsigned bits) {
    return (value >> bits) | (value << (32 - bits));
}

std::array<unsigned char, 32> hash(std::span<const unsigned char> input) {
    static constexpr std::array<std::uint32_t, 64> round{
        0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
        0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
        0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
        0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
        0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
        0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
        0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
        0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U};
    if (input.size() > 695) _exit(80);
    std::array<unsigned char, 704> padded{};
    std::copy(input.begin(), input.end(), padded.begin());
    padded[input.size()] = 0x80;
    const std::size_t blocks = (input.size() + 9 + 63) / 64;
    const std::uint64_t bits = static_cast<std::uint64_t>(input.size()) * 8;
    for (unsigned i = 0; i < 8; ++i)
        padded[blocks * 64 - 1 - i] =
            static_cast<unsigned char>(bits >> (8 * i));
    std::array<std::uint32_t, 8> state{
        0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
        0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U};
    for (std::size_t block = 0; block < blocks; ++block) {
        std::array<std::uint32_t, 64> words{};
        for (unsigned i = 0; i < 16; ++i) {
            const std::size_t at = block * 64 + i * 4;
            words[i] = static_cast<std::uint32_t>(padded[at]) << 24 |
                       static_cast<std::uint32_t>(padded[at + 1]) << 16 |
                       static_cast<std::uint32_t>(padded[at + 2]) << 8 |
                       padded[at + 3];
        }
        for (unsigned i = 16; i < 64; ++i) {
            const auto s0 = rotate_right(words[i - 15], 7) ^
                            rotate_right(words[i - 15], 18) ^
                            (words[i - 15] >> 3);
            const auto s1 = rotate_right(words[i - 2], 17) ^
                            rotate_right(words[i - 2], 19) ^
                            (words[i - 2] >> 10);
            words[i] = words[i - 16] + s0 + words[i - 7] + s1;
        }
        auto [a,b,c,d,e,f,g,h] = state;
        for (unsigned i = 0; i < 64; ++i) {
            const auto sum1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^
                              rotate_right(e, 25);
            const auto choice = (e & f) ^ (~e & g);
            const auto t1 = h + sum1 + choice + round[i] + words[i];
            const auto sum0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^
                              rotate_right(a, 22);
            const auto majority = (a & b) ^ (a & c) ^ (b & c);
            const auto t2 = sum0 + majority;
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }
    std::array<unsigned char, 32> result{};
    for (unsigned i = 0; i < state.size(); ++i)
        for (unsigned j = 0; j < 4; ++j)
            result[4 * i + j] =
                static_cast<unsigned char>(state[i] >> (24 - 8 * j));
    return result;
}

bool write_pattern(int fd, std::uint64_t bytes, unsigned char tag) {
    std::array<unsigned char, 1024> body{};
    for (std::size_t i = 0; i < body.size(); ++i)
        body[i] = static_cast<unsigned char>(tag + i);
    std::uint64_t at = 0;
    while (at < bytes) {
        const auto wanted = static_cast<std::size_t>(
            std::min<std::uint64_t>(body.size(), bytes - at));
        ssize_t count;
        do {
            count = ::pwrite(fd, body.data(), wanted, static_cast<off_t>(at));
        } while (count < 0 && errno == EINTR);
        if (count <= 0) return false;
        at += static_cast<std::uint64_t>(count);
    }
    return ::fsync(fd) == 0;
}

bool swap_zero() {
    std::array<char, 8> value{};
    return ::pread(wire::SWAP_MAX_FD, value.data(), value.size(), 0) == 2 &&
           value[0] == '0' && value[1] == '\n';
}

template<std::size_t N>
bool erase(std::array<unsigned char, N>& value) {
    volatile unsigned char* at = value.data();
    for (std::size_t i = 0; i < value.size(); ++i) at[i] = 0;
    return std::all_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte == 0; });
}

} // namespace

int main() {
    // The execute-only memfd prevents user-dumpable exec startup.  Set the
    // stable post-loader state before reading any circuit/setup material.
    const bool dumpable = ::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0;
    if (!dumpable) return 69;
    std::array<unsigned char, wire::CLOSURE_BYTES> closure{};
    std::array<unsigned char, wire::PLAN_BYTES> plan{};
    if (!read_exact(wire::CIRCUIT_CLOSURE_FD, closure) ||
        !read_exact(wire::PLAN_FD, plan))
        return 70;
    const unsigned char role = closure[8];
    const std::size_t plan_at = role == 1
        ? wire::PLAN_OUTPUT_CLOSURE_AT
        : wire::PLAN_AGGREGATE_CLOSURE_AT;
    bool closures = (role == 1 || role == 2) &&
        std::equal(wire::CLOSURE_MAGIC.begin(), wire::CLOSURE_MAGIC.end(),
                   closure.begin()) &&
        std::equal(closure.begin() + 16, closure.begin() + 80,
                   plan.begin() + plan_at) &&
        get_u64(closure, 80) == get_u64(plan, plan_at + 64) &&
        get_u64(closure, 88) == get_u64(plan, plan_at + 72) &&
        get_u64(closure, 96) == get_u64(plan, plan_at + 80) &&
        get_u64(closure, 104) == get_u64(plan, plan_at + 88);
    bool plan_exact = std::equal(wire::PLAN_MAGIC.begin(), wire::PLAN_MAGIC.end(),
                                 plan.begin());
    const auto plan_identity = hash(plan);

    struct rlimit core{};
    const bool core_zero = ::getrlimit(RLIMIT_CORE, &core) == 0 &&
                           core.rlim_cur == 0 && core.rlim_max == 0;
    const bool environment_empty = environ != nullptr && environ[0] == nullptr;
    errno = 0;
    const bool unknown_closed = ::fcntl(200, F_GETFD) == -1 && errno == EBADF;
    errno = 0;
    const int network = ::socket(AF_INET, SOCK_STREAM, 0);
    const bool network_denied = network == -1 && errno == EPERM;
    if (network >= 0) ::close(network);
    errno = 0;
    const int source = ::open("/etc/passwd", O_RDONLY | O_CLOEXEC);
    const bool source_opens_denied = source == -1 && errno == EPERM;
    if (source >= 0) ::close(source);
    errno = 0;
    const pid_t descendant = ::fork();
    const bool descendants_denied = descendant == -1 && errno == EPERM;
    if (descendant == 0) _exit(68);
    if (descendant > 0) {
        int ignored{};
        while (::waitpid(descendant, &ignored, 0) < 0 && errno == EINTR) {}
    }

    if (KPB_BOUNDED_SETUP_WORKER_BEHAVIOR == 3) {
        __builtin_trap();
    }
    if (KPB_BOUNDED_SETUP_WORKER_BEHAVIOR == 4) {
        const int extra = ::open("/tmp/kpb-bounded-setup-forbidden-output",
                                 O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (extra >= 0) ::close(extra);
        return 72;
    }
    if (KPB_BOUNDED_SETUP_WORKER_BEHAVIOR == 5) {
        const unsigned char leak = 1;
        if (::write(2, &leak, 1) < 0 && errno != EPERM) return 77;
        return 73;
    }

    std::array<std::uint64_t, 2> sizes{
        get_u64(closure, 96), get_u64(closure, 104)};
    if (KPB_BOUNDED_SETUP_WORKER_BEHAVIOR == 1) sizes[0] /= 2;
    for (std::size_t i = 0; i < sizes.size(); ++i)
        if (!write_pattern(wire::OUTPUT_FDS[i], sizes[i],
                           static_cast<unsigned char>(0x31 +
                               (role - 1) * 34 + i * 17)))
            return 74;

    const bool erased_closure = erase(closure);
    const bool erased_plan = erase(plan);
    const bool erasure_attempted = erased_closure && erased_plan;

    std::array<unsigned char, wire::STATUS_BYTES> status{};
    std::copy(wire::STATUS_MAGIC.begin(), wire::STATUS_MAGIC.end(), status.begin());
    std::copy(plan_identity.begin(), plan_identity.end(), status.begin() + 8);
    if (KPB_BOUNDED_SETUP_WORKER_BEHAVIOR == 6) status[8] ^= 1;
    unsigned long long flags = 0;
    if (dumpable) flags |= wire::POLICY_DUMPABLE_DISABLED;
    if (core_zero) flags |= wire::POLICY_CORE_DISABLED;
    if (environment_empty) flags |= wire::POLICY_ENVIRONMENT_EMPTY;
    if (unknown_closed) flags |= wire::POLICY_UNKNOWN_FDS_CLOSED;
    if (network_denied) flags |= wire::POLICY_NETWORK_DENIED;
    if (swap_zero()) flags |= wire::POLICY_SWAP_ZERO;
    if (closures) flags |= wire::POLICY_CLOSURES_EXACT;
    if (plan_exact) flags |= wire::POLICY_PLAN_EXACT;
    if (source_opens_denied) flags |= wire::POLICY_SOURCE_OPENS_DENIED;
    if (descendants_denied) flags |= wire::POLICY_DESCENDANTS_DENIED;
    if (erasure_attempted) flags |= wire::POLICY_ERASURE_ATTEMPTED;
    if (KPB_BOUNDED_SETUP_WORKER_BEHAVIOR == 8)
        flags &= ~wire::POLICY_ENVIRONMENT_EMPTY;
    put_u64(status, 40, flags);
    if (::write(wire::STATUS_FD, status.data(), status.size()) !=
        static_cast<ssize_t>(status.size()))
        return 75;
    if (KPB_BOUNDED_SETUP_WORKER_BEHAVIOR == 7 &&
        ::write(wire::STATUS_FD, status.data(), status.size()) !=
            static_cast<ssize_t>(status.size()))
        return 76;
    return KPB_BOUNDED_SETUP_WORKER_BEHAVIOR == 2 ? 7 : 0;
}
