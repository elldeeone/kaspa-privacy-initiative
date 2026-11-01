#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "bounded_setup_authority.hpp"
#include "bounded_setup_wire.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/magic.h>
#include <linux/memfd.h>
#include <linux/openat2.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <memory>
#include <openssl/evp.h>
#include <signal.h>
#include <span>
#include <string>
#include <string_view>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpb::bounded_setup {
namespace {

[[noreturn]] void refuse() { throw SetupRefused(); }
void need(bool value) { if (!value) refuse(); }

constexpr int REQUIRED_SEALS =
    F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;

class Fd final {
    int value_{-1};
public:
    Fd() = default;
    explicit Fd(int value) : value_(value) {}
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : value_(std::exchange(other.value_, -1)) {}
    Fd& operator=(Fd&& other) noexcept {
        if (this == &other) return *this;
        reset();
        value_ = std::exchange(other.value_, -1);
        return *this;
    }
    ~Fd() { reset(); }
    int get() const noexcept { return value_; }
    int release() noexcept { return std::exchange(value_, -1); }
    void reset(int value = -1) noexcept {
        if (value_ >= 0)
            while (::close(value_) != 0 && errno == EINTR) {}
        value_ = value;
    }
};

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
        [](unsigned char byte) { return byte != 0; });
}

Digest decode_hex(std::string_view value) {
    need(value.size() == 64);
    Digest result{};
    const auto nibble = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a' + 10);
        refuse();
    };
    for (std::size_t i = 0; i < result.size(); ++i)
        result[i] = static_cast<unsigned char>(
            (nibble(value[2 * i]) << 4) | nibble(value[2 * i + 1]));
    need(nonzero(result));
    return result;
}

struct EvpDeleter final {
    void operator()(EVP_MD_CTX* value) const noexcept { EVP_MD_CTX_free(value); }
};

[[maybe_unused]] Digest hash_bytes(std::span<const unsigned char> value) {
    Digest result{};
    unsigned size = 0;
    need(EVP_Digest(value.data(), value.size(), result.data(), &size,
                    EVP_sha256(), nullptr) == 1 && size == result.size() &&
         nonzero(result));
    return result;
}

Digest hash_fd(int fd, std::uint64_t expected_size) {
    std::unique_ptr<EVP_MD_CTX, EvpDeleter> context(EVP_MD_CTX_new());
    need(context != nullptr &&
         EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) == 1);
    std::array<unsigned char, 1U << 16> buffer{};
    std::uint64_t at = 0;
    while (at < expected_size) {
        const auto wanted = static_cast<std::size_t>(
            std::min<std::uint64_t>(buffer.size(), expected_size - at));
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
        count = ::pread(fd, &trailing, 1, static_cast<off_t>(expected_size));
    } while (count < 0 && errno == EINTR);
    need(count == 0);
    Digest result{};
    unsigned size = 0;
    need(EVP_DigestFinal_ex(context.get(), result.data(), &size) == 1 &&
         size == result.size() && nonzero(result));
    return result;
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

Fd sealed_memfd(std::string_view name, std::span<const unsigned char> body,
                bool executable) {
    unsigned flags = MFD_CLOEXEC | MFD_ALLOW_SEALING;
#ifdef MFD_EXEC
    flags |= executable ? MFD_EXEC : MFD_NOEXEC_SEAL;
#endif
    Fd fd(static_cast<int>(::syscall(
        SYS_memfd_create, std::string(name).c_str(), flags)));
    need(fd.get() >= 0);
    write_all(fd.get(), body);
    // An execute-only worker keeps Linux's post-exec dumpable state disabled;
    // a readable executable would reset PR_SET_DUMPABLE to one at exec.
    need(::fchmod(fd.get(), executable ? 0100 : 0400) == 0 &&
         ::fcntl(fd.get(), F_ADD_SEALS, REQUIRED_SEALS) == 0 &&
         (::fcntl(fd.get(), F_GET_SEALS) & REQUIRED_SEALS) == REQUIRED_SEALS);
    return fd;
}

[[maybe_unused]] std::vector<unsigned char> read_regular(
        std::string_view path, std::uint64_t maximum) {
#ifdef SYS_openat2
    std::string terminated(path);
    struct open_how how{};
    how.flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW;
    how.resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
    int raw;
    do {
        raw = static_cast<int>(::syscall(
            SYS_openat2, AT_FDCWD, terminated.c_str(), &how, sizeof(how)));
    } while (raw < 0 && errno == EINTR);
    Fd fd(raw);
#else
    (void)path; (void)maximum; refuse();
#endif
    struct stat status{};
    need(fd.get() >= 0 && ::fstat(fd.get(), &status) == 0 &&
         S_ISREG(status.st_mode) && status.st_size > 0 &&
         static_cast<std::uint64_t>(status.st_size) <= maximum);
    std::vector<unsigned char> body(static_cast<std::size_t>(status.st_size));
    std::size_t at = 0;
    while (at < body.size()) {
        ssize_t count;
        do {
            count = ::pread(fd.get(), body.data() + at, body.size() - at,
                            static_cast<off_t>(at));
        } while (count < 0 && errno == EINTR);
        need(count > 0);
        at += static_cast<std::size_t>(count);
    }
    return body;
}

[[maybe_unused]] bool source_closed_static_elf(
        std::span<const unsigned char> body) {
    if (body.size() < sizeof(Elf64_Ehdr)) return false;
    Elf64_Ehdr header{};
    std::memcpy(&header, body.data(), sizeof(header));
    if (std::memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 ||
        header.e_ident[EI_CLASS] != ELFCLASS64 ||
        header.e_ident[EI_DATA] != ELFDATA2LSB ||
        header.e_ident[EI_VERSION] != EV_CURRENT ||
        header.e_version != EV_CURRENT || header.e_type != ET_EXEC ||
        header.e_ehsize != sizeof(Elf64_Ehdr) ||
        header.e_phentsize != sizeof(Elf64_Phdr) || header.e_phnum == 0 ||
        header.e_phoff > body.size()) return false;
#if defined(__x86_64__)
    if (header.e_machine != EM_X86_64) return false;
#elif defined(__aarch64__)
    if (header.e_machine != EM_AARCH64) return false;
#else
    return false;
#endif
    const auto table_bytes = static_cast<std::uint64_t>(header.e_phnum) *
                             sizeof(Elf64_Phdr);
    if (table_bytes > body.size() - header.e_phoff) return false;
    bool executable_load = false;
    for (std::size_t i = 0; i < header.e_phnum; ++i) {
        Elf64_Phdr program{};
        const auto at = static_cast<std::size_t>(header.e_phoff) +
                        i * sizeof(program);
        std::memcpy(&program, body.data() + at, sizeof(program));
        if (program.p_offset > body.size() ||
            program.p_filesz > body.size() - program.p_offset ||
            program.p_type == PT_INTERP || program.p_type == PT_DYNAMIC ||
            (program.p_type == PT_LOAD &&
             (program.p_flags & (PF_W | PF_X)) == (PF_W | PF_X)) ||
            (program.p_type == PT_GNU_STACK &&
             (program.p_flags & PF_X) != 0))
            return false;
        if (program.p_type == PT_LOAD && (program.p_flags & PF_X) != 0)
            executable_load = true;
    }
    return executable_load && header.e_entry != 0;
}

void put_u64(std::span<unsigned char> out, std::size_t at,
             std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i)
        out[at + i] = static_cast<unsigned char>(value >> (8 * i));
}

std::uint64_t get_u64(std::span<const unsigned char> in, std::size_t at) {
    std::uint64_t result = 0;
    for (unsigned i = 0; i < 8; ++i)
        result |= static_cast<std::uint64_t>(in[at + i]) << (8 * i);
    return result;
}

CircuitClosureReceipt output_spec() {
#ifdef KPB_BOUNDED_SETUP_TEST_SMALL_OUTPUTS
    constexpr std::uint64_t pk = 4096, vk = 328;
#else
    constexpr std::uint64_t pk = 85578096, vk = 328;
#endif
    return {
        .role = CircuitRole::Output,
        .source_identity = decode_hex(
            "ccd4e28a728cbf8ffd6db0dd0fa81a6200c0c6e4ecb20242435f00e5b6aae19e"),
        .matrix_identity = decode_hex(
            "d8e94558a7b9e3a5cc6187a894cb7f141d85d3c6d862b6a628561a24c4bfdd31"),
        .constraints = 217807,
        .variables = 215001,
        .proving_key_bytes = pk,
        .verifying_key_bytes = vk,
    };
}

CircuitClosureReceipt aggregate_spec() {
#ifdef KPB_BOUNDED_SETUP_TEST_SMALL_OUTPUTS
    constexpr std::uint64_t pk = 8192, vk = 328;
#else
    constexpr std::uint64_t pk = 2608842576ULL, vk = 328;
#endif
    return {
        .role = CircuitRole::Aggregate,
        .source_identity = decode_hex(
            "04adfd77d3b97f60efe6c4547cda583856ea7f7be4c9538f4237330ac137a9d7"),
        .matrix_identity = decode_hex(
            "c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab"),
        .constraints = 13093029,
        .variables = 12949821,
        .proving_key_bytes = pk,
        .verifying_key_bytes = vk,
    };
}

bool exact_spec(const CircuitClosureReceipt& value,
                const CircuitClosureReceipt& expected) {
    return value.role == expected.role &&
           value.source_identity == expected.source_identity &&
           value.matrix_identity == expected.matrix_identity &&
           value.constraints == expected.constraints &&
           value.variables == expected.variables &&
           value.proving_key_bytes == expected.proving_key_bytes &&
           value.verifying_key_bytes == expected.verifying_key_bytes;
}

Digest precommit_child(const Digest& trial, unsigned char kind,
                       unsigned char round) {
    need(nonzero(trial) && kind >= wire::PRECOMMIT_FINANCIAL_RUN &&
         kind <= wire::PRECOMMIT_ROUND_COHORT && round >= 1 && round <= 2);
    std::array<unsigned char,
               wire::PRECOMMIT_DOMAIN.size() + Digest{}.size() + 2> body{};
    auto at = std::copy(wire::PRECOMMIT_DOMAIN.begin(),
                        wire::PRECOMMIT_DOMAIN.end(), body.begin());
    at = std::copy(trial.begin(), trial.end(), at);
    *at++ = kind;
    *at = round;
    return hash_bytes(body);
}

FrozenSetupPlanBinding pre_setup_plan(const Digest& trial) {
    FrozenSetupPlanBinding result{.trial = trial};
    for (unsigned round = 0; round < 2; ++round) {
        result.financial_runs[round] = precommit_child(
            trial, wire::PRECOMMIT_FINANCIAL_RUN,
            static_cast<unsigned char>(round + 1));
        result.round_attempts[round] = precommit_child(
            trial, wire::PRECOMMIT_ROUND_ATTEMPT,
            static_cast<unsigned char>(round + 1));
        result.round_cohorts[round] = precommit_child(
            trial, wire::PRECOMMIT_ROUND_COHORT,
            static_cast<unsigned char>(round + 1));
    }
    return result;
}

std::array<unsigned char, wire::CLOSURE_BYTES> closure_wire(
        const CircuitClosureReceipt& value) {
    std::array<unsigned char, wire::CLOSURE_BYTES> out{};
    std::copy(wire::CLOSURE_MAGIC.begin(), wire::CLOSURE_MAGIC.end(), out.begin());
    out[8] = static_cast<unsigned char>(value.role);
    std::copy(value.source_identity.begin(), value.source_identity.end(),
              out.begin() + 16);
    std::copy(value.matrix_identity.begin(), value.matrix_identity.end(),
              out.begin() + 48);
    put_u64(out, 80, value.constraints);
    put_u64(out, 88, value.variables);
    put_u64(out, 96, value.proving_key_bytes);
    put_u64(out, 104, value.verifying_key_bytes);
    return out;
}

bool valid_plan_binding(const FrozenSetupPlanBinding& value) {
    const std::array<Digest, 7> identities{
        value.trial,
        value.financial_runs[0], value.financial_runs[1],
        value.round_attempts[0], value.round_attempts[1],
        value.round_cohorts[0], value.round_cohorts[1]};
    for (std::size_t left = 0; left < identities.size(); ++left) {
        if (!nonzero(identities[left])) return false;
        for (std::size_t right = left + 1; right < identities.size(); ++right)
            if (identities[left] == identities[right]) return false;
    }
    return value == pre_setup_plan(value.trial);
}

[[maybe_unused]] std::array<unsigned char, wire::PLAN_BYTES> plan_wire(
        const FrozenSetupPlanBinding& binding,
        const CircuitClosureReceipt& output,
        const CircuitClosureReceipt& aggregate) {
    std::array<unsigned char, wire::PLAN_BYTES> out{};
    std::copy(wire::PLAN_MAGIC.begin(), wire::PLAN_MAGIC.end(), out.begin());
    const auto copy_digest = [&](const Digest& identity, std::size_t at) {
        std::copy(identity.begin(), identity.end(), out.begin() + at);
    };
    const auto copy_pair = [&](const std::array<Digest, 2>& identities,
                               std::size_t at) {
        copy_digest(identities[0], at);
        copy_digest(identities[1], at + 32);
    };
    copy_digest(binding.trial, wire::PLAN_TRIAL_AT);
    copy_pair(binding.financial_runs, wire::PLAN_FINANCIAL_RUNS_AT);
    copy_pair(binding.round_attempts, wire::PLAN_ROUND_ATTEMPTS_AT);
    copy_pair(binding.round_cohorts, wire::PLAN_ROUND_COHORTS_AT);
    const auto copy_closure = [&](const CircuitClosureReceipt& value,
                                  std::size_t at) {
        copy_digest(value.source_identity, at);
        copy_digest(value.matrix_identity, at + 32);
        put_u64(out, at + 64, value.constraints);
        put_u64(out, at + 72, value.variables);
        put_u64(out, at + 80, value.proving_key_bytes);
        put_u64(out, at + 88, value.verifying_key_bytes);
    };
    copy_closure(output, wire::PLAN_OUTPUT_CLOSURE_AT);
    copy_closure(aggregate, wire::PLAN_AGGREGATE_CLOSURE_AT);
    return out;
}

struct SwapPolicy final {
    Fd fd;
    std::uint64_t device{};
    std::uint64_t inode{};
};

std::string read_small_path(const char* path) {
    Fd fd(::open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    need(fd.get() >= 0);
    std::array<char, 4096> body{};
    ssize_t count;
    do { count = ::read(fd.get(), body.data(), body.size() - 1); }
    while (count < 0 && errno == EINTR);
    need(count > 0 && static_cast<std::size_t>(count) < body.size());
    return std::string(body.data(), static_cast<std::size_t>(count));
}

std::uint64_t decimal_body(std::string_view body) {
    while (!body.empty() && (body.back() == '\n' || body.back() == '\r'))
        body.remove_suffix(1);
    need(!body.empty());
    std::uint64_t result = 0;
    for (const char c : body) {
        need(c >= '0' && c <= '9');
        const auto digit = static_cast<std::uint64_t>(c - '0');
        need(result <= (UINT64_MAX - digit) / 10);
        result = result * 10 + digit;
    }
    return result;
}

std::string current_cgroup_root() {
    const auto cgroup = read_small_path("/proc/self/cgroup");
    std::string relative;
    std::size_t at = 0;
    while (at < cgroup.size()) {
        const auto end = cgroup.find('\n', at);
        const auto line = cgroup.substr(at,
            end == std::string::npos ? std::string::npos : end - at);
        if (line.starts_with("0::")) relative = line.substr(3);
        if (end == std::string::npos) break;
        at = end + 1;
    }
    need(!relative.empty() && relative[0] == '/' &&
         relative.find("..") == std::string::npos);
    std::string path = "/sys/fs/cgroup" + relative;
    if (!path.ends_with('/')) path.push_back('/');
    return path;
}

std::uint64_t cgroup_decimal(std::string_view name) {
    const auto root = current_cgroup_root();
    const auto path = root + std::string(name);
    Fd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    struct stat status{};
    struct statfs fs{};
    need(fd.get() >= 0 && ::fstat(fd.get(), &status) == 0 &&
         ::fstatfs(fd.get(), &fs) == 0 && S_ISREG(status.st_mode) &&
         static_cast<unsigned long>(fs.f_type) ==
             static_cast<unsigned long>(CGROUP2_SUPER_MAGIC));
    std::array<char, 64> body{};
    ssize_t count;
    do { count = ::pread(fd.get(), body.data(), body.size(), 0); }
    while (count < 0 && errno == EINTR);
    need(count > 0 && static_cast<std::size_t>(count) < body.size());
    return decimal_body(std::string_view(body.data(),
                                        static_cast<std::size_t>(count)));
}

std::uint64_t host_memory_available() {
    const auto body = read_small_path("/proc/meminfo");
    constexpr std::string_view field = "MemAvailable:";
    const auto start = body.find(field);
    need(start != std::string::npos);
    auto at = start + field.size();
    while (at < body.size() && (body[at] == ' ' || body[at] == '\t')) ++at;
    const auto first = at;
    while (at < body.size() && body[at] >= '0' && body[at] <= '9') ++at;
    need(at > first && body.substr(at, 3) == " kB");
    const auto kib = decimal_body(std::string_view(body).substr(first, at - first));
    need(kib <= UINT64_MAX / 1024);
    return kib * 1024;
}

std::string fixed_under_root(std::string_view root, std::string_view suffix) {
    need(!root.empty() && root.front() == '/' && suffix.starts_with('/') &&
         root.find("/../") == std::string_view::npos &&
         !root.ends_with("/.."));
    std::string result(root);
    while (result.size() > 1 && result.back() == '/') result.pop_back();
    result.append(suffix);
    return result;
}

bool supervisor_untraced() {
    const auto status = read_small_path("/proc/self/status");
    constexpr std::string_view prefix = "TracerPid:\t";
    const auto at = status.find(prefix);
    if (at == std::string::npos) return false;
    const auto value = at + prefix.size();
    return value + 2 <= status.size() && status[value] == '0' &&
           status[value + 1] == '\n';
}

bool supervisor_single_threaded() {
    DIR* raw = ::opendir("/proc/self/task");
    if (raw == nullptr) return false;
    unsigned tasks = 0;
    errno = 0;
    while (auto* item = ::readdir(raw)) {
        if (item->d_name[0] == '.') continue;
        ++tasks;
    }
    const bool exact = errno == 0 && tasks == 1;
    return ::closedir(raw) == 0 && exact;
}

bool swap_zero_fd(int fd) {
    std::array<char, 32> body{};
    ssize_t count;
    do { count = ::pread(fd, body.data(), body.size(), 0); }
    while (count < 0 && errno == EINTR);
    return count == 2 && body[0] == '0' && body[1] == '\n';
}

SwapPolicy current_swap_policy() {
    std::string path = current_cgroup_root() + "memory.swap.max";
    Fd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    struct stat status{};
    struct statfs fs{};
    need(fd.get() >= 0 && ::fstat(fd.get(), &status) == 0 &&
         ::fstatfs(fd.get(), &fs) == 0 &&
         static_cast<unsigned long>(fs.f_type) ==
             static_cast<unsigned long>(CGROUP2_SUPER_MAGIC) &&
         S_ISREG(status.st_mode) && swap_zero_fd(fd.get()));
    return {
        .fd = std::move(fd),
        .device = static_cast<std::uint64_t>(status.st_dev),
        .inode = static_cast<std::uint64_t>(status.st_ino),
    };
}

bool same_swap_policy(const SwapPolicy& policy) {
    struct stat status{};
    if (::fstat(policy.fd.get(), &status) != 0 ||
        static_cast<std::uint64_t>(status.st_dev) != policy.device ||
        static_cast<std::uint64_t>(status.st_ino) != policy.inode ||
        !swap_zero_fd(policy.fd.get())) return false;
    const auto current = current_swap_policy();
    return current.device == policy.device && current.inode == policy.inode;
}

constexpr std::uint32_t DENIED =
    SECCOMP_RET_ERRNO | static_cast<std::uint32_t>(EPERM);

class Seccomp final {
    std::vector<sock_filter> rows_;
public:
    void statement(unsigned short code, std::uint32_t value) {
        rows_.push_back(sock_filter{code, 0, 0, value});
    }
    void branch(unsigned short code, std::uint32_t value,
                unsigned char yes, unsigned char no) {
        rows_.push_back(sock_filter{code, yes, no, value});
    }
    void deny(int number) {
        branch(BPF_JMP | BPF_JEQ | BPF_K,
               static_cast<std::uint32_t>(number), 0, 1);
        statement(BPF_RET | BPF_K, DENIED);
    }
    void restrict_write(int number) {
        // Mismatch skips the complete nine-row argument block.
        branch(BPF_JMP | BPF_JEQ | BPF_K,
               static_cast<std::uint32_t>(number), 0, 9);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[0]) + 4);
        branch(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0);
        statement(BPF_RET | BPF_K, DENIED);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[0]));
        branch(BPF_JMP | BPF_JEQ | BPF_K, 50, 2, 0);
        branch(BPF_JMP | BPF_JEQ | BPF_K, 51, 1, 0);
        branch(BPF_JMP | BPF_JEQ | BPF_K, 54, 0, 1);
        statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
        statement(BPF_RET | BPF_K, DENIED);
    }
    void restrict_clone(int number) {
        constexpr std::uint32_t required =
            CLONE_VM | CLONE_SIGHAND | CLONE_THREAD;
        // Only same-process threads may be created; descendant processes
        // could retain output descriptors after the waited worker exits.
        branch(BPF_JMP | BPF_JEQ | BPF_K,
               static_cast<std::uint32_t>(number), 0, 7);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[0]) + 4);
        branch(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0);
        statement(BPF_RET | BPF_K, DENIED);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[0]));
        statement(BPF_ALU | BPF_AND | BPF_K, required);
        branch(BPF_JMP | BPF_JEQ | BPF_K, required, 1, 0);
        statement(BPF_RET | BPF_K, DENIED);
    }
    void restrict_prctl() {
        // The worker may only reassert non-dumpability after exec.  It cannot
        // make itself dumpable or change another prctl policy.
        branch(BPF_JMP | BPF_JEQ | BPF_K, SYS_prctl, 0, 12);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[0]) + 4);
        branch(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0);
        statement(BPF_RET | BPF_K, DENIED);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[0]));
        branch(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_DUMPABLE, 1, 0);
        statement(BPF_RET | BPF_K, DENIED);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[1]) + 4);
        branch(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0);
        statement(BPF_RET | BPF_K, DENIED);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[1]));
        branch(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0);
        statement(BPF_RET | BPF_K, DENIED);
    }
    void exact_execveat(int fd) {
        branch(BPF_JMP | BPF_JEQ | BPF_K, SYS_execveat, 0, 10);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[0]) + 4);
        branch(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0);
        statement(BPF_RET | BPF_K, DENIED);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[0]));
        branch(BPF_JMP | BPF_JEQ | BPF_K,
               static_cast<std::uint32_t>(fd), 1, 0);
        statement(BPF_RET | BPF_K, DENIED);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[4]));
        branch(BPF_JMP | BPF_JEQ | BPF_K, AT_EMPTY_PATH, 1, 0);
        statement(BPF_RET | BPF_K, DENIED);
        statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    }
    bool install() {
        statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
        sock_fprog program{
            .len = static_cast<unsigned short>(rows_.size()),
            .filter = rows_.data(),
        };
        return rows_.size() <= USHRT_MAX &&
               ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 &&
               ::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0;
    }
};

bool install_child_policy() {
    Seccomp filter;
    filter.statement(BPF_LD | BPF_W | BPF_ABS,
                     offsetof(struct seccomp_data, arch));
#if defined(__x86_64__)
    constexpr std::uint32_t arch = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
    constexpr std::uint32_t arch = AUDIT_ARCH_AARCH64;
#else
    return false;
#endif
    filter.branch(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0);
    filter.statement(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    filter.statement(BPF_LD | BPF_W | BPF_ABS,
                     offsetof(struct seccomp_data, nr));
#if defined(__x86_64__)
    filter.branch(BPF_JMP | BPF_JSET | BPF_K, 0x40000000U, 0, 1);
    filter.statement(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
#endif
    filter.exact_execveat(wire::RUNTIME_FD);
    filter.restrict_prctl();
#ifdef SYS_execve
    filter.deny(SYS_execve);
#endif
    filter.restrict_write(SYS_write);
#ifdef SYS_pwrite64
    filter.restrict_write(SYS_pwrite64);
#endif
#ifdef SYS_writev
    filter.deny(SYS_writev);
#endif
#ifdef SYS_open
    filter.deny(SYS_open);
#endif
#ifdef SYS_openat
    filter.deny(SYS_openat);
#endif
#ifdef SYS_openat2
    filter.deny(SYS_openat2);
#endif
#ifdef SYS_creat
    filter.deny(SYS_creat);
#endif
#ifdef SYS_clone
    filter.restrict_clone(SYS_clone);
#endif
#ifdef SYS_clone3
    filter.deny(SYS_clone3);
#endif
#ifdef SYS_fork
    filter.deny(SYS_fork);
#endif
#ifdef SYS_vfork
    filter.deny(SYS_vfork);
#endif
#ifdef SYS_ptrace
    filter.deny(SYS_ptrace);
#endif
#ifdef SYS_process_vm_readv
    filter.deny(SYS_process_vm_readv);
#endif
#ifdef SYS_process_vm_writev
    filter.deny(SYS_process_vm_writev);
#endif
#ifdef SYS_pidfd_open
    filter.deny(SYS_pidfd_open);
#endif
#ifdef SYS_pidfd_getfd
    filter.deny(SYS_pidfd_getfd);
#endif
#ifdef SYS_io_uring_setup
    filter.deny(SYS_io_uring_setup);
#endif
#ifdef SYS_io_uring_enter
    filter.deny(SYS_io_uring_enter);
#endif
#ifdef SYS_io_uring_register
    filter.deny(SYS_io_uring_register);
#endif
#ifdef SYS_msgget
    filter.deny(SYS_msgget);
#endif
#ifdef SYS_msgsnd
    filter.deny(SYS_msgsnd);
#endif
#ifdef SYS_msgrcv
    filter.deny(SYS_msgrcv);
#endif
#ifdef SYS_shmget
    filter.deny(SYS_shmget);
#endif
#ifdef SYS_shmat
    filter.deny(SYS_shmat);
#endif
#ifdef SYS_semget
    filter.deny(SYS_semget);
#endif
#ifdef SYS_semop
    filter.deny(SYS_semop);
#endif
#ifdef SYS_mq_open
    filter.deny(SYS_mq_open);
#endif
#ifdef SYS_mq_timedsend
    filter.deny(SYS_mq_timedsend);
#endif
#ifdef SYS_bpf
    filter.deny(SYS_bpf);
#endif
#ifdef SYS_perf_event_open
    filter.deny(SYS_perf_event_open);
#endif
#ifdef SYS_keyctl
    filter.deny(SYS_keyctl);
#endif
#ifdef SYS_add_key
    filter.deny(SYS_add_key);
#endif
#ifdef SYS_request_key
    filter.deny(SYS_request_key);
#endif
    // The worker has no reason to contact or control another process through
    // signals. Self-failure uses exit_group; the hostile signal control traps
    // without needing a signal-delivery syscall.
#ifdef SYS_kill
    filter.deny(SYS_kill);
#endif
#ifdef SYS_tkill
    filter.deny(SYS_tkill);
#endif
#ifdef SYS_tgkill
    filter.deny(SYS_tgkill);
#endif
#ifdef SYS_rt_sigqueueinfo
    filter.deny(SYS_rt_sigqueueinfo);
#endif
#ifdef SYS_rt_tgsigqueueinfo
    filter.deny(SYS_rt_tgsigqueueinfo);
#endif
#ifdef SYS_pidfd_send_signal
    filter.deny(SYS_pidfd_send_signal);
#endif
#ifdef SYS_inotify_init
    filter.deny(SYS_inotify_init);
#endif
#ifdef SYS_inotify_init1
    filter.deny(SYS_inotify_init1);
#endif
#ifdef SYS_inotify_add_watch
    filter.deny(SYS_inotify_add_watch);
#endif
#ifdef SYS_fanotify_init
    filter.deny(SYS_fanotify_init);
#endif
    for (int call : std::array<int, 12>{
#ifdef SYS_socket
             SYS_socket,
#else
             -1,
#endif
#ifdef SYS_socketpair
             SYS_socketpair,
#else
             -1,
#endif
#ifdef SYS_connect
             SYS_connect,
#else
             -1,
#endif
#ifdef SYS_bind
             SYS_bind,
#else
             -1,
#endif
#ifdef SYS_listen
             SYS_listen,
#else
             -1,
#endif
#ifdef SYS_accept
             SYS_accept,
#else
             -1,
#endif
#ifdef SYS_accept4
             SYS_accept4,
#else
             -1,
#endif
#ifdef SYS_sendto
             SYS_sendto,
#else
             -1,
#endif
#ifdef SYS_sendmsg
             SYS_sendmsg,
#else
             -1,
#endif
#ifdef SYS_recvfrom
             SYS_recvfrom,
#else
             -1,
#endif
#ifdef SYS_recvmsg
             SYS_recvmsg,
#else
             -1,
#endif
#ifdef SYS_shutdown
             SYS_shutdown,
#else
             -1,
#endif
         }) if (call >= 0) filter.deny(call);
    for (int call : std::array<int, 11>{
#ifdef SYS_unlink
             SYS_unlink,
#else
             -1,
#endif
#ifdef SYS_unlinkat
             SYS_unlinkat,
#else
             -1,
#endif
#ifdef SYS_rename
             SYS_rename,
#else
             -1,
#endif
#ifdef SYS_renameat
             SYS_renameat,
#else
             -1,
#endif
#ifdef SYS_renameat2
             SYS_renameat2,
#else
             -1,
#endif
#ifdef SYS_mkdir
             SYS_mkdir,
#else
             -1,
#endif
#ifdef SYS_mkdirat
             SYS_mkdirat,
#else
             -1,
#endif
#ifdef SYS_link
             SYS_link,
#else
             -1,
#endif
#ifdef SYS_linkat
             SYS_linkat,
#else
             -1,
#endif
#ifdef SYS_symlink
             SYS_symlink,
#else
             -1,
#endif
#ifdef SYS_symlinkat
             SYS_symlinkat,
#else
             -1,
#endif
         }) if (call >= 0) filter.deny(call);
    return filter.install();
}

void duplicate_to(int source, int target, bool cloexec) {
    if (source == target) {
        const int flags = ::fcntl(source, F_GETFD);
        need(flags >= 0 && ::fcntl(source, F_SETFD,
             cloexec ? (flags | FD_CLOEXEC) : (flags & ~FD_CLOEXEC)) == 0);
        return;
    }
    need(::dup3(source, target, cloexec ? O_CLOEXEC : 0) == target);
}

struct OutputFiles final {
    Fd directory;
    std::array<Fd, 4> files;
    std::array<bool, 4> linked{};
    bool cleanup{true};

    OutputFiles() = default;
    OutputFiles(const OutputFiles&) = delete;
    OutputFiles& operator=(const OutputFiles&) = delete;
    OutputFiles(OutputFiles&& other) noexcept
        : directory(std::move(other.directory)), files(std::move(other.files)),
          linked(std::exchange(other.linked, {})),
          cleanup(std::exchange(other.cleanup, false)) {}
    OutputFiles& operator=(OutputFiles&&) = delete;
    ~OutputFiles();
    void preserve() noexcept { cleanup = false; }
};

constexpr std::array<const char*, 4> OUTPUT_NAMES{
    "OUTPUT-PK.bin", "OUTPUT-VK.bin",
    "AGGREGATE-PK.bin", "AGGREGATE-VK.bin"};

struct DirectoryCloser final {
    void operator()(DIR* value) const noexcept {
        if (value != nullptr && ::closedir(value) != 0) {}
    }
};

bool directory_empty(int fd) {
    Fd scan(::openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (scan.get() < 0) return false;
    DIR* raw = ::fdopendir(scan.release());
    if (raw == nullptr) return false;
    std::unique_ptr<DIR, DirectoryCloser> directory(raw);
    errno = 0;
    while (auto* item = ::readdir(directory.get())) {
        if (std::strcmp(item->d_name, ".") != 0 &&
            std::strcmp(item->d_name, "..") != 0)
            return false;
    }
    return errno == 0;
}

OutputFiles create_outputs(std::string_view path) {
    std::string terminated(path);
    Fd directory(::open(terminated.c_str(),
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    struct stat status{};
    need(directory.get() >= 0 && ::fstat(directory.get(), &status) == 0 &&
         S_ISDIR(status.st_mode) && status.st_uid == ::geteuid() &&
         (status.st_mode & 07777) == 0700 && directory_empty(directory.get()));
    OutputFiles result;
    result.directory = std::move(directory);
    for (std::size_t i = 0; i < result.files.size(); ++i) {
        result.files[i].reset(::openat(
            result.directory.get(), ".",
            O_RDWR | O_TMPFILE | O_CLOEXEC, 0600));
        struct stat file_status{};
        need(result.files[i].get() >= 0 &&
             ::fchmod(result.files[i].get(), 0600) == 0 &&
             ::fstat(result.files[i].get(), &file_status) == 0 &&
             S_ISREG(file_status.st_mode) &&
             file_status.st_uid == ::geteuid() && file_status.st_nlink == 0 &&
             (file_status.st_mode & 07777) == 0600);
    }
    return result;
}

void poison_outputs(OutputFiles& output) noexcept {
    for (std::size_t i = 0; i < output.files.size(); ++i) {
        if (output.files[i].get() >= 0) {
            if (::ftruncate(output.files[i].get(), 0) != 0) {}
            if (::fsync(output.files[i].get()) != 0) {}
            output.files[i].reset();
        }
        if (output.directory.get() >= 0 && output.linked[i])
            if (::unlinkat(output.directory.get(), OUTPUT_NAMES[i], 0) != 0) {}
    }
    if (output.directory.get() >= 0 && ::fsync(output.directory.get()) != 0) {}
}

bool directory_exact(int fd);

void publish_outputs(OutputFiles& output) {
    need(directory_empty(output.directory.get()));
    for (std::size_t i = 0; i < output.files.size(); ++i) {
        need(!output.linked[i] &&
             ::linkat(output.files[i].get(), "", output.directory.get(),
                      OUTPUT_NAMES[i], AT_EMPTY_PATH) == 0);
        output.linked[i] = true;
    }
    need(directory_exact(output.directory.get()));
    for (const auto& file : output.files) {
        struct stat status{};
        need(::fstat(file.get(), &status) == 0 && status.st_nlink == 1);
    }
}

OutputFiles::~OutputFiles() {
    if (cleanup) poison_outputs(*this);
}

bool directory_exact(int fd) {
    Fd scan(::openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (scan.get() < 0) return false;
    DIR* raw = ::fdopendir(scan.release());
    if (raw == nullptr) return false;
    std::unique_ptr<DIR, DirectoryCloser> directory(raw);
    std::array<bool, 4> found{};
    errno = 0;
    while (auto* item = ::readdir(directory.get())) {
        if (std::strcmp(item->d_name, ".") == 0 ||
            std::strcmp(item->d_name, "..") == 0) continue;
        bool matched = false;
        for (std::size_t i = 0; i < OUTPUT_NAMES.size(); ++i) {
            if (std::strcmp(item->d_name, OUTPUT_NAMES[i]) == 0 && !found[i]) {
                found[i] = true;
                matched = true;
                break;
            }
        }
        if (!matched) return false;
    }
    return errno == 0 &&
           std::all_of(found.begin(), found.end(), [](bool v) { return v; });
}

void inspect_resource_guard(BoundedSetupPreflightReceipt& receipt,
                            int output_directory_fd) {
    constexpr std::uint64_t GIB = 1ULL << 30;
#ifdef KPB_BOUNDED_SETUP_TEST_SMALL_OUTPUTS
    constexpr std::uint64_t MIB = 1ULL << 20;
    constexpr std::uint64_t MINIMUM_MEMORY_HEADROOM = 256ULL * MIB;
    constexpr std::uint64_t MAXIMUM_MEMORY_CGROUP = 4ULL * GIB;
    constexpr std::uint64_t MINIMUM_OUTPUT_HEADROOM = 16ULL * MIB;
#else
    // The frozen aggregate setup previously peaked at about 10.14 GiB.  This
    // gate requires a finite cgroup and at least 16 GiB of both cgroup and host
    // headroom; it does not lower the limit to make a run pass.
    constexpr std::uint64_t MINIMUM_MEMORY_HEADROOM = 16ULL * GIB;
    constexpr std::uint64_t MAXIMUM_MEMORY_CGROUP = 24ULL * GIB;
    constexpr std::uint64_t MINIMUM_OUTPUT_HEADROOM = 8ULL * GIB;
#endif
    receipt.cgroup_memory_limit_bytes = cgroup_decimal("memory.max");
    receipt.cgroup_memory_current_bytes = cgroup_decimal("memory.current");
    receipt.host_memory_available_bytes = host_memory_available();
    receipt.cgroup_memory_finite_and_bounded =
        receipt.cgroup_memory_limit_bytes >= MINIMUM_MEMORY_HEADROOM &&
        receipt.cgroup_memory_limit_bytes <= MAXIMUM_MEMORY_CGROUP;
    receipt.memory_headroom_sufficient =
        receipt.cgroup_memory_finite_and_bounded &&
        receipt.cgroup_memory_current_bytes <=
            receipt.cgroup_memory_limit_bytes &&
        receipt.cgroup_memory_limit_bytes -
            receipt.cgroup_memory_current_bytes >= MINIMUM_MEMORY_HEADROOM &&
        receipt.host_memory_available_bytes >= MINIMUM_MEMORY_HEADROOM;
    struct statvfs filesystem{};
    need(::fstatvfs(output_directory_fd, &filesystem) == 0);
    const auto blocks = static_cast<std::uint64_t>(filesystem.f_bavail);
    const auto block_size = static_cast<std::uint64_t>(filesystem.f_frsize);
    need(block_size > 0 && blocks <= UINT64_MAX / block_size);
    receipt.output_filesystem_available_bytes = blocks * block_size;
    receipt.output_filesystem_headroom_sufficient =
        receipt.output_filesystem_available_bytes >= MINIMUM_OUTPUT_HEADROOM;
}

bool resource_guard_green(const BoundedSetupPreflightReceipt& value) {
    return value.cgroup_memory_finite_and_bounded &&
           value.memory_headroom_sufficient &&
           value.output_filesystem_headroom_sufficient &&
           value.anonymous_private_outputs_supported;
}

std::array<std::uint64_t, 4> expected_sizes(
        const CircuitClosureReceipt& output,
        const CircuitClosureReceipt& aggregate) {
    return {output.proving_key_bytes, output.verifying_key_bytes,
            aggregate.proving_key_bytes, aggregate.verifying_key_bytes};
}

struct ChildGuard final {
    pid_t pid{-1};
    bool waited{};
    ~ChildGuard() {
        if (pid > 0 && !waited) {
            (void)::kill(pid, SIGKILL);
            int status{};
            while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        }
    }
};

struct StatusRead final {
    std::array<unsigned char, wire::STATUS_BYTES> body{};
    bool exact{};
    bool eof{};
    pid_t sender{-1};
};

StatusRead read_status(int fd) {
    StatusRead result;
    std::array<unsigned char, CMSG_SPACE(sizeof(struct ucred))> control{};
    struct iovec io{.iov_base = result.body.data(), .iov_len = result.body.size()};
    struct msghdr message{};
    message.msg_iov = &io;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t count;
    do { count = ::recvmsg(fd, &message, 0); } while (count < 0 && errno == EINTR);
    if (count == static_cast<ssize_t>(result.body.size()) &&
        !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
        for (auto* item = CMSG_FIRSTHDR(&message); item;
             item = CMSG_NXTHDR(&message, item)) {
            if (item->cmsg_level == SOL_SOCKET && item->cmsg_type == SCM_CREDENTIALS &&
                item->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {
                struct ucred credentials{};
                std::memcpy(&credentials, CMSG_DATA(item), sizeof(credentials));
                result.sender = credentials.pid;
            }
        }
        result.exact = result.sender > 0;
    }
    control.fill(0);
    unsigned char trailing{};
    io = {.iov_base = &trailing, .iov_len = 1};
    message = {};
    message.msg_iov = &io;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    do { count = ::recvmsg(fd, &message, 0); } while (count < 0 && errno == EINTR);
    result.eof = count == 0 && CMSG_FIRSTHDR(&message) == nullptr;
    return result;
}

} // namespace

struct FrozenTwoRunPlanAuthority::Storage final {
    FrozenSetupPlanBinding binding{};
    Digest identity{};
    std::array<CircuitClosureReceipt, 2> circuits{};
    Fd fd;
};

struct SetupWorkerSelectionAuthority::Storage final {
    Digest identity{};
    Digest aggregate_context_identity{};
    Digest aggregate_signature_identity{};
    std::uint64_t worker_bytes{};
    Fd executable;
    Fd aggregate_context;
    Fd aggregate_signature;
};

FrozenTwoRunPlanAuthority::FrozenTwoRunPlanAuthority(std::unique_ptr<Storage> value)
    : storage_(std::move(value)) { need(storage_ != nullptr); }
FrozenTwoRunPlanAuthority::FrozenTwoRunPlanAuthority(
        FrozenTwoRunPlanAuthority&& other) noexcept
    : storage_(std::move(other.storage_)),
      live_(other.live_.exchange(false)) {}
FrozenTwoRunPlanAuthority::~FrozenTwoRunPlanAuthority() {
    live_.store(false); storage_.reset();
}

SetupWorkerSelectionAuthority::SetupWorkerSelectionAuthority(
        std::unique_ptr<Storage> value)
    : storage_(std::move(value)) { need(storage_ != nullptr); }
SetupWorkerSelectionAuthority::SetupWorkerSelectionAuthority(
        SetupWorkerSelectionAuthority&& other) noexcept
    : storage_(std::move(other.storage_)),
      live_(other.live_.exchange(false)) {}
SetupWorkerSelectionAuthority::~SetupWorkerSelectionAuthority() {
    live_.store(false); storage_.reset();
}

SetupWorkerSelectionAuthority SourceOwnedBoundedSetupLauncher::select_worker(
        std::string_view workspace_root) {
    constexpr std::string_view WORKER_PATH =
        "/poc/local-private-payment/private_batch_trial/bounded_setup_worker/"
        "target/x86_64-unknown-linux-musl/release/kpb-bounded-setup-worker";
    constexpr std::string_view CONTEXT_PATH =
        "/.local/private-batch-full-matrix-probe-20261028-01/"
        "PUBLIC-CONTEXT-HISTORY.json";
    constexpr std::string_view SIGNATURE_PATH =
        "/.local/registered-financial-relation-candidate-20261029/"
        "SIGNATURE-MATRIX.json";
    const auto expected_worker = decode_hex(
        "5754490a8649fe9f287d3e3f7f40d3abcdcbc515afb39e8122b8dd17e6adcd0d");
    const auto expected_context = decode_hex(
        "ae20c64f7ea90bea3c00b060abe4d3e3c2766955a0b3ad8cfe12b9d8630b7411");
    const auto expected_signature = decode_hex(
        "b573a68be539426b1165e4f1b1d01f054a3ca275c7d7a1811ece99280bf17d11");
    auto worker = read_regular(fixed_under_root(workspace_root, WORKER_PATH),
                               8ULL << 20);
    auto context = read_regular(fixed_under_root(workspace_root, CONTEXT_PATH),
                                4096);
    auto signature = read_regular(
        fixed_under_root(workspace_root, SIGNATURE_PATH), 4ULL << 20);
    need(worker.size() == 1745168 && source_closed_static_elf(worker) &&
         hash_bytes(worker) == expected_worker && context.size() == 1260 &&
         hash_bytes(context) == expected_context &&
         signature.size() == 2711586 &&
         hash_bytes(signature) == expected_signature);
    auto storage = std::make_unique<SetupWorkerSelectionAuthority::Storage>();
    storage->identity = expected_worker;
    storage->aggregate_context_identity = expected_context;
    storage->aggregate_signature_identity = expected_signature;
    storage->worker_bytes = worker.size();
    storage->executable = sealed_memfd(
        "kpb-source-owned-bounded-setup-worker", worker, true);
    storage->aggregate_context = sealed_memfd(
        "kpb-source-owned-aggregate-context", context, false);
    storage->aggregate_signature = sealed_memfd(
        "kpb-source-owned-aggregate-signature", signature, false);
    return SetupWorkerSelectionAuthority(std::move(storage));
}

BoundedSetupPreflightReceipt SourceOwnedBoundedSetupLauncher::preflight(
        std::string_view workspace_root,
        std::string_view fresh_output_directory) {
    auto selected = select_worker(workspace_root);
    need(selected.storage_ != nullptr);
    BoundedSetupPreflightReceipt receipt{
        .worker_identity = selected.storage_->identity,
        .aggregate_context_identity =
            selected.storage_->aggregate_context_identity,
        .aggregate_signature_identity =
            selected.storage_->aggregate_signature_identity,
        .worker_bytes = selected.storage_->worker_bytes,
    };
    receipt.source_closed_static_worker_exact = true;
    receipt.aggregate_public_inputs_exact = true;
    SwapPolicy swap = current_swap_policy();
    receipt.swap_max_zero = same_swap_policy(swap);
    OutputFiles output_probe = create_outputs(fresh_output_directory);
    receipt.anonymous_private_outputs_supported = true;
    inspect_resource_guard(receipt, output_probe.directory.get());
    receipt.production_plan_selected = false;
    receipt.missing_parent_artifacts =
        kBoundedSetupPlanBlocker.missing_parent_artifacts;
    // Even a resource-green host is not launch-ready without the canonical
    // source-owned plan; this cannot be overridden by a caller.
    receipt.full_setup_ready = false;
    receipt.s4_selected = false;
    receipt.s12_selected = false;
    receipt.configured = false;
    return receipt;
}

SetupCompletionAuthority::SetupCompletionAuthority(BoundedSetupReceipt value)
    : receipt_(std::make_unique<BoundedSetupReceipt>(std::move(value))) {}
SetupCompletionAuthority::SetupCompletionAuthority(
        SetupCompletionAuthority&& other) noexcept
    : receipt_(std::move(other.receipt_)),
      live_(other.live_.exchange(false)) {}
SetupCompletionAuthority::~SetupCompletionAuthority() {
    live_.store(false); receipt_.reset();
}
const BoundedSetupReceipt& SetupCompletionAuthority::receipt() const {
    need(live_.load() && receipt_ != nullptr);
    return *receipt_;
}
#ifdef KPB_BOUNDED_SETUP_TEST_SETUP
BoundedSetupReceipt SetupCompletionAuthority::consume_for_test() {
    need(live_.exchange(false) && receipt_ != nullptr);
    auto result = *receipt_;
    receipt_.reset();
    return result;
}
#endif

SetupCompletionAuthority BoundedSetupSupervisor::execute(
        SetupWorkerSelectionAuthority&& selected,
        FrozenTwoRunPlanAuthority&& frozen,
        std::string_view output_path) {
    need(selected.live_.exchange(false) && selected.storage_ != nullptr &&
         frozen.live_.exchange(false) && frozen.storage_ != nullptr);
    auto worker = std::move(selected.storage_);
    auto plan = std::move(frozen.storage_);
    need(exact_spec(plan->circuits[0], output_spec()) &&
         exact_spec(plan->circuits[1], aggregate_spec()) &&
         valid_plan_binding(plan->binding) &&
         nonzero(plan->identity) && nonzero(worker->identity));
    need(supervisor_untraced() && supervisor_single_threaded() &&
         ::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0);

    const auto output_record = closure_wire(plan->circuits[0]);
    const auto aggregate_record = closure_wire(plan->circuits[1]);
    std::array<Fd, 2> closures{
        sealed_memfd("kpb-output-closure", output_record, false),
        sealed_memfd("kpb-aggregate-closure", aggregate_record, false)};
    SwapPolicy swap = current_swap_policy();
    OutputFiles outputs = create_outputs(output_path);
    BoundedSetupPreflightReceipt resource{};
    resource.anonymous_private_outputs_supported = true;
    inspect_resource_guard(resource, outputs.directory.get());
    need(resource_guard_green(resource));
    BoundedSetupReceipt receipt{};

    for (std::size_t circuit = 0; circuit < closures.size(); ++circuit) {
        int sockets[2]{-1, -1};
        need(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC,
                          0, sockets) == 0);
        Fd parent_socket(sockets[0]), child_socket(sockets[1]);
        int enabled = 1;
        need(::setsockopt(parent_socket.get(), SOL_SOCKET, SO_PASSCRED,
                          &enabled, sizeof(enabled)) == 0);

        ChildGuard child;
        const pid_t supervisor_pid = ::getpid();
        child.pid = ::fork();
        need(child.pid >= 0);
        if (child.pid == 0) {
            if (::prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0 ||
                ::getppid() != supervisor_pid ||
                ::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
                _exit(119);
            parent_socket.reset();
            Fd null(::open("/dev/null", O_RDWR | O_CLOEXEC));
            if (null.get() < 0) _exit(120);
#ifdef SYS_close_range
            if (::syscall(SYS_close_range, 3U, ~0U,
                          CLOSE_RANGE_CLOEXEC) != 0)
                _exit(121);
#else
            _exit(121);
#endif
            try {
                duplicate_to(null.get(), 0, false);
                duplicate_to(null.get(), 1, false);
                duplicate_to(null.get(), 2, false);
                duplicate_to(worker->executable.get(), wire::RUNTIME_FD, true);
                duplicate_to(closures[circuit].get(),
                             wire::CIRCUIT_CLOSURE_FD, false);
                duplicate_to(plan->fd.get(), wire::PLAN_FD, false);
                if (circuit == 1) {
                    duplicate_to(worker->aggregate_context.get(),
                                 wire::AGGREGATE_CONTEXT_FD, false);
                    duplicate_to(worker->aggregate_signature.get(),
                                 wire::AGGREGATE_SIGNATURE_FD, false);
                }
                duplicate_to(swap.fd.get(), wire::SWAP_MAX_FD, false);
                for (std::size_t i = 0; i < wire::OUTPUT_FDS.size(); ++i)
                    duplicate_to(outputs.files[circuit * 2 + i].get(),
                                 wire::OUTPUT_FDS[i], false);
                duplicate_to(child_socket.get(), wire::STATUS_FD, false);
                struct rlimit core{.rlim_cur = 0, .rlim_max = 0};
                if (::setrlimit(RLIMIT_CORE, &core) != 0 ||
                    ::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 ||
                    !install_child_policy())
                    _exit(122);
                static constexpr char empty_path[] = "";
                char name[] = "kpb-bounded-setup-worker";
                char* arguments[]{name, nullptr};
                char* environment[]{nullptr};
                (void)::syscall(SYS_execveat, wire::RUNTIME_FD, empty_path,
                                arguments, environment, AT_EMPTY_PATH);
            } catch (...) {}
            _exit(123);
        }
        child_socket.reset();

        const auto status = read_status(parent_socket.get());
        parent_socket.reset();
        int wait_status{};
        pid_t waited;
        do { waited = ::waitpid(child.pid, &wait_status, 0); }
        while (waited < 0 && errno == EINTR);
        child.waited = waited == child.pid;

        const bool valid_worker =
            child.waited && WIFEXITED(wait_status) &&
            WEXITSTATUS(wait_status) == 0 && status.exact && status.eof &&
            status.sender == child.pid &&
            std::equal(wire::STATUS_MAGIC.begin(), wire::STATUS_MAGIC.end(),
                       status.body.begin()) &&
            std::equal(plan->identity.begin(), plan->identity.end(),
                       status.body.begin() + 8) &&
            get_u64(status.body, 40) == wire::REQUIRED_POLICY &&
            same_swap_policy(swap) && directory_empty(outputs.directory.get());
        if (!valid_worker) {
            poison_outputs(outputs);
            refuse();
        }
        receipt.worker_pids[circuit] = child.pid;
    }

    bool valid = true;
    if (valid) {
        const auto sizes = expected_sizes(plan->circuits[0], plan->circuits[1]);
        for (std::size_t i = 0; i < outputs.files.size(); ++i) {
            struct stat file_status{};
            if (::fstat(outputs.files[i].get(), &file_status) != 0 ||
                !S_ISREG(file_status.st_mode) ||
                file_status.st_uid != ::geteuid() || file_status.st_nlink != 0 ||
                static_cast<std::uint64_t>(file_status.st_size) != sizes[i]) {
                valid = false;
                break;
            }
            receipt.artifacts[i] = {
                .role = i < 2 ? CircuitRole::Output : CircuitRole::Aggregate,
                .proving_key = (i % 2) == 0,
                .bytes = sizes[i],
                .sha256 = hash_fd(outputs.files[i].get(), sizes[i]),
            };
            if (::fsync(outputs.files[i].get()) != 0 ||
                ::fchmod(outputs.files[i].get(), 0400) != 0 ||
                ::fsync(outputs.files[i].get()) != 0) {
                valid = false;
                break;
            }
        }
        if (valid) {
            try {
                publish_outputs(outputs);
                if (::fsync(outputs.directory.get()) != 0) valid = false;
            } catch (const SetupRefused&) {
                valid = false;
            }
        }
    }
    if (!valid) {
        poison_outputs(outputs);
        refuse();
    }
    receipt.selected_plan = plan->binding;
    receipt.plan_identity = plan->identity;
    receipt.worker_identity = worker->identity;
    receipt.circuits = plan->circuits;
    receipt.source_and_matrix_bound = true;
    receipt.exact_two_run_plan = true;
    receipt.pre_setup_only_plan = true;
    receipt.post_setup_artifacts_excluded_from_plan = true;
    receipt.dedicated_one_shot_process_per_circuit = true;
    receipt.single_threaded_controller = true;
    receipt.inherited_private_output_fds = true;
    receipt.exact_allowed_outputs = true;
    receipt.environment_empty = true;
    receipt.unknown_descriptors_closed = true;
    receipt.network_syscalls_denied = true;
    receipt.source_opens_denied = true;
    receipt.descendant_processes_denied = true;
    receipt.debugger_attachment_denied = true;
    receipt.core_dumps_disabled = true;
    receipt.swap_max_zero_before_and_after = true;
    receipt.finite_memory_and_disk_guard_satisfied = true;
    receipt.eof_observed = true;
    receipt.wait_status_zero = true;
    receipt.outputs_fsynced = true;
    receipt.directory_fsynced = true;
    receipt.process_terminated = true;
    receipt.parent_death_kills_worker = true;
    receipt.worker_reported_erasure_attempt = true;
    receipt.best_effort_erasure_only = true;
    receipt.erasure_cryptographically_proven = false;
    receipt.setup_honesty_cryptographically_proven = false;
    receipt.ceremony_claimed = false;
    receipt.s4_selected = false;
    receipt.s12_selected = false;
    receipt.configured = false;
    SetupCompletionAuthority completion(std::move(receipt));
    outputs.preserve();
    return completion;
}

#ifdef KPB_BOUNDED_SETUP_TEST_SETUP
Digest BoundedSetupTestFixture::digest(std::string_view value) {
    return decode_hex(value);
}
FrozenSetupPlanBinding BoundedSetupTestFixture::pre_setup_plan(Digest trial) {
    return ::kpb::bounded_setup::pre_setup_plan(trial);
}
CircuitClosureReceipt BoundedSetupTestFixture::output_closure() {
    return output_spec();
}
CircuitClosureReceipt BoundedSetupTestFixture::aggregate_closure() {
    return aggregate_spec();
}
FrozenTwoRunPlanAuthority BoundedSetupTestFixture::freeze_plan(
        FrozenSetupPlanBinding binding,
        CircuitClosureReceipt output, CircuitClosureReceipt aggregate) {
    need(valid_plan_binding(binding) && exact_spec(output, output_spec()) &&
         exact_spec(aggregate, aggregate_spec()));
    const auto body = plan_wire(binding, output, aggregate);
    auto storage = std::make_unique<FrozenTwoRunPlanAuthority::Storage>();
    storage->binding = binding;
    storage->identity = hash_bytes(body);
    storage->circuits = {output, aggregate};
    storage->fd = sealed_memfd("kpb-bounded-two-run-plan", body, false);
    return FrozenTwoRunPlanAuthority(std::move(storage));
}
SetupWorkerSelectionAuthority BoundedSetupTestFixture::select_worker(
        std::string_view executable, Digest expected) {
    need(nonzero(expected));
    const auto body = read_regular(executable, 64ULL << 20);
    need(source_closed_static_elf(body));
    const auto identity = hash_bytes(body);
    need(identity == expected);
    auto storage = std::make_unique<SetupWorkerSelectionAuthority::Storage>();
    storage->identity = identity;
    storage->executable = sealed_memfd("kpb-bounded-setup-worker", body, true);
    const std::array<unsigned char, 1> fixture_input{0x5a};
    storage->aggregate_context = sealed_memfd(
        "kpb-bounded-aggregate-context-test", fixture_input, false);
    storage->aggregate_signature = sealed_memfd(
        "kpb-bounded-aggregate-signature-test", fixture_input, false);
    return SetupWorkerSelectionAuthority(std::move(storage));
}
SetupCompletionAuthority BoundedSetupTestFixture::execute(
        SetupWorkerSelectionAuthority&& worker,
        FrozenTwoRunPlanAuthority&& plan,
        std::string_view output_directory) {
    return BoundedSetupSupervisor::execute(
        std::move(worker), std::move(plan), output_directory);
}
#endif

} // namespace kpb::bounded_setup
