#pragma once
// ADR0081: one explicitly selected fixed-width owner-local file codec.
// The controller never calls this reader. There is no legacy text fallback.
#include "../auth_field.hpp"
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <vector>

namespace kpi::mpc::financial {
inline constexpr std::array<unsigned char, 16> OWNER_FR32_MAGIC{
    'K','P','B','_','O','W','N','E','R','_','F','R','3','2','V','2'};
inline uint64_t owner_fr32_file_bytes(size_t count) {
    if (!count || count > (std::numeric_limits<uint64_t>::max() - 32) / 32)
        throw std::runtime_error("owner-fr32-selected-count");
    return 32 + uint64_t(count) * 32;
}
namespace owner_fr32_detail {
inline bool stable(const struct stat& a, const struct stat& b) {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size
        && a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec
        && a.st_ctim.tv_sec == b.st_ctim.tv_sec && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec
        && a.st_mode == b.st_mode && a.st_nlink == b.st_nlink && a.st_uid == b.st_uid;
}
inline void read_exact(std::FILE* file, std::span<unsigned char> output) {
    size_t at = 0;
    while (at < output.size()) {
        const auto n = std::fread(output.data() + at, 1, output.size() - at, file);
        at += n;
        if (at == output.size()) return;
        if (std::ferror(file) && errno == EINTR) { std::clearerr(file); continue; }
        throw std::runtime_error("owner-fr32-truncated-or-read-failure");
    }
}
inline uint64_t number(std::FILE* file) {
    std::array<unsigned char, 8> bytes{}; read_exact(file, bytes);
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= uint64_t(bytes[i]) << (8 * i);
    return value;
}
inline void require_eof(std::FILE* file) {
    for (;;) {
        const auto c = std::fgetc(file);
        if (c != EOF) throw std::runtime_error("owner-fr32-trailing-bytes");
        if (std::ferror(file) && errno == EINTR) { std::clearerr(file); continue; }
        if (std::ferror(file)) throw std::runtime_error("owner-fr32-read-failure");
        return;
    }
}
}

// Canonical range is enforced HERE before conversion. The production caller
// converts that bounded bigint directly to the unchanged selected Fr type.
// The callback is not a validation/success flag and cannot admit a Fr alias.
// Retaining conversion injection permits deterministic file-drift controls.
template<class ParseField>
auto load_owner_fr32_input_file(const std::filesystem::path& path, int owner,
                               size_t expected_count, ParseField parse_field) {
    using Scalar = std::invoke_result_t<ParseField, const bigint&>;
    const auto expected_bytes = owner_fr32_file_bytes(expected_count);
    if (owner < 0 || owner > 2 || expected_bytes > std::numeric_limits<size_t>::max())
        throw std::runtime_error("owner-fr32-selected-shape");
    const auto absolute = std::filesystem::absolute(path);
    if (absolute.native().find('\0') != std::string::npos)
        throw std::runtime_error("owner-fr32-path-nul");
    std::filesystem::path current;
    for (const auto& part : absolute) {
        if (part == "..") throw std::runtime_error("owner-fr32-path-traversal");
        current /= part;
        if (std::filesystem::is_symlink(std::filesystem::symlink_status(current)))
            throw std::runtime_error("owner-fr32-symlink-component");
    }
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) throw std::runtime_error("owner-fr32-open");
    struct stat before{};
    if (::fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_nlink != 1
        || (before.st_mode & 07777) != 0600 || before.st_uid != ::geteuid()
        || before.st_size < 0 || uint64_t(before.st_size) != expected_bytes) {
        ::close(fd);
        throw std::runtime_error("owner-fr32-owned-single-leaf-exact-size");
    }
    std::FILE* stream = ::fdopen(fd, "rb");
    if (!stream) { ::close(fd); throw std::runtime_error("owner-fr32-stream"); }
    const auto close_file = [](std::FILE* f) { std::fclose(f); };
    std::unique_ptr<std::FILE, decltype(close_file)> file(stream, close_file);
    std::array<unsigned char, 16> magic{}; owner_fr32_detail::read_exact(stream, magic);
    if (magic != OWNER_FR32_MAGIC || owner_fr32_detail::number(stream) != uint64_t(owner)
        || owner_fr32_detail::number(stream) != uint64_t(expected_count))
        throw std::runtime_error("owner-fr32-version-role-or-count");
    std::vector<Scalar> values; values.reserve(expected_count);
    for (size_t i = 0; i < expected_count; ++i) {
        std::array<unsigned char, 32> bytes{}; owner_fr32_detail::read_exact(stream, bytes);
        bigint canonical;
        mpz_import(canonical.get_mpz_t(), bytes.size(), -1, 1, 0, 0, bytes.data());
        if (canonical < 0 || canonical >= fr_modulus())
            throw std::runtime_error("owner-fr32-noncanonical-field");
        values.push_back(parse_field(canonical));
    }
    owner_fr32_detail::require_eof(stream);
    struct stat after{};
    if (::fstat(fd, &after) || !owner_fr32_detail::stable(before, after))
        throw std::runtime_error("owner-fr32-mutated-during-read");
    return values;
}
} // namespace kpi::mpc::financial
