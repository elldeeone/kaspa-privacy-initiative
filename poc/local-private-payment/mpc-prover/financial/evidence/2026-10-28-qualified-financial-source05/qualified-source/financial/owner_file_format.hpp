#pragma once

// The controller never calls this reader. It runs only inside the isolated
// owner process with one selected read-only owner-input leaf mounted.
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <vector>

namespace kpi::mpc::financial {
namespace owner_file_detail {
inline bool space(int c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

inline std::string token(std::FILE* file) {
    int c;
    do { c = std::fgetc(file); } while (space(c));
    if (c == EOF) throw std::runtime_error("owner-file-truncated");
    std::string out;
    do {
        if (c <= 0 || c > 127 || out.size() >= 128)
            throw std::runtime_error("owner-file-token-format");
        out.push_back(static_cast<char>(c));
        c = std::fgetc(file);
    } while (c != EOF && !space(c));
    if (std::ferror(file)) throw std::runtime_error("owner-file-read-failure");
    return out;
}

inline void tag(std::FILE* file, const std::string& expected) {
    if (token(file) != expected) throw std::runtime_error("owner-file-frame");
}

inline bool stable(const struct stat& a, const struct stat& b) {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size
        && a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec
        && a.st_ctim.tv_sec == b.st_ctim.tv_sec && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec
        && a.st_mode == b.st_mode && a.st_nlink == b.st_nlink && a.st_uid == b.st_uid;
}
}  // namespace owner_file_detail

template<class ParseField>
auto load_owner_input_file(const std::filesystem::path& path, int owner,
                          size_t expected_count, ParseField parse_field) {
    using Scalar = std::invoke_result_t<ParseField, const std::string&>;
    if (owner < 0 || owner > 2 || expected_count == 0 ||
        expected_count > std::numeric_limits<size_t>::max() / 2)
        throw std::runtime_error("owner-file-selected-shape");
    std::filesystem::path current;
    for (const auto& part : std::filesystem::absolute(path)) {
        if (part == "..") throw std::runtime_error("owner-file-path-traversal");
        current /= part;
        if (std::filesystem::is_symlink(std::filesystem::symlink_status(current)))
            throw std::runtime_error("owner-file-symlink-component");
    }
    // O_NONBLOCK prevents a substituted FIFO from blocking before fstat.
    // The isolated launcher supplies a flat path with no other private mount.
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) throw std::runtime_error("owner-file-open");
    struct stat before{};
    if (::fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_nlink != 1
        || (before.st_mode & 07777) != 0600 || before.st_uid != ::geteuid()
        || before.st_size < 0 || static_cast<uintmax_t>(before.st_size) < 2 * expected_count) {
        ::close(fd);
        throw std::runtime_error("owner-file-owned-single-leaf");
    }
    std::FILE* stream = ::fdopen(fd, "rb");
    if (!stream) { ::close(fd); throw std::runtime_error("owner-file-stream"); }
    const auto close_file = [](std::FILE* file) { std::fclose(file); };
    std::unique_ptr<std::FILE, decltype(close_file)> file(stream, close_file);
    using namespace owner_file_detail;
    tag(stream, "KPB_OWNER_INPUT_V1");
    tag(stream, "OWNER"); tag(stream, "owner" + std::to_string(owner));
    tag(stream, "COUNT");
    // Exact equality to the agreed contract count rejects signs, overflow,
    // leading-zero and whitespace aliases without parsing a caller length.
    tag(stream, std::to_string(expected_count));
    tag(stream, "VALUES");
    std::vector<Scalar> values;
    values.reserve(expected_count);
    for (size_t i = 0; i < expected_count; ++i) {
        const auto text = token(stream);
        if (text.empty() || (text.size() > 1 && text[0] == '0')
            || text.find_first_not_of("0123456789") != std::string::npos)
            throw std::runtime_error("owner-file-noncanonical-field");
        // Reuse the actual selected BN254 Fr parser; never reduce aliases.
        values.push_back(parse_field(text));
    }
    tag(stream, "END");
    int c;
    do { c = std::fgetc(stream); } while (space(c));
    if (c != EOF || std::ferror(stream)) throw std::runtime_error("owner-file-trailing-data");
    struct stat after{};
    if (::fstat(fd, &after) || !stable(before, after))
        throw std::runtime_error("owner-file-mutated-during-read");
    return values;
}
}  // namespace kpi::mpc::financial
