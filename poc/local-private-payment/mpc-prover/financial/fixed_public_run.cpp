#include "fixed_public_run.hpp"
#include <algorithm>
#include <cerrno>
#include <climits>
#include <fcntl.h>
#include <map>
#include <set>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace kpi::mpc::financial {
namespace {
using Bytes = std::vector<unsigned char>;
using Path = std::filesystem::path;
using Digest = history::Digest;
void need(bool value) { if (!value) throw history::Refused(); }
bool inside(const Path& a, const Path& b) {
    auto i = a.begin();
    for (auto j = b.begin(); j != b.end(); ++j, ++i)
        if (i == a.end() || *i != *j) return false;
    return true;
}
void plain(const Path& path) {
    need(path.is_absolute() && path == path.lexically_normal() &&
         path.string().find('\0') == std::string::npos);
    for (auto p = path; !p.empty(); p = p.parent_path()) {
        need(!std::filesystem::is_symlink(std::filesystem::symlink_status(p)));
        if (p == p.root_path()) break;
    }
}
bool stable(const struct stat& a, const struct stat& b) {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size &&
        a.st_uid == b.st_uid && a.st_mode == b.st_mode && a.st_nlink == b.st_nlink &&
        a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec &&
        a.st_ctim.tv_sec == b.st_ctim.tv_sec && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
}
struct Fd {
    int value;
    explicit Fd(int fd) : value(fd) { need(fd >= 0); }
    Fd(Fd&& other) noexcept : value(other.value) { other.value = -1; }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    ~Fd() { if (value >= 0) ::close(value); }
};
void write_all(int fd, std::span<const unsigned char> bytes) {
    size_t at = 0;
    while (at < bytes.size()) {
        auto n = ::write(fd, bytes.data() + at, bytes.size() - at);
        if (n < 0 && errno == EINTR) continue;
        need(n > 0); at += static_cast<size_t>(n);
    }
}
void sync(int fd) {
    int result; do { result = ::fsync(fd); } while (result < 0 && errno == EINTR);
    need(result == 0);
}
struct Exclusions {
    std::vector<Path> roots;
    std::set<std::pair<dev_t, ino_t>> inodes;
    explicit Exclusions(const RegisteredService& service) : roots(service.private_directories()) {
        need(!roots.empty());
        roots.push_back(service.journal_directory()); roots.push_back(service.anchor_directory());
        // Metadata only. A missing/inaccessible private inventory refuses; this
        // code never opens a private body or follows a directory symlink.
        for (const auto& root : roots) {
            plain(root); need(std::filesystem::is_directory(root));
            for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
                struct stat s{}; need(::lstat(entry.path().c_str(), &s) == 0);
                if (S_ISREG(s.st_mode)) inodes.emplace(s.st_dev, s.st_ino);
            }
        }
    }
    void public_path(const Path& path, bool directory = false) const {
        plain(path);
        for (const auto& root : roots)
            need(!inside(path, root) && (!directory || !inside(root, path)));
    }
};
Bytes read_public(const Path& path, const Exclusions& excluded) {
    excluded.public_path(path); struct stat named{}, opened{}, after{}, named_after{};
    need(::lstat(path.c_str(), &named) == 0 && S_ISREG(named.st_mode) &&
         named.st_nlink == 1 && named.st_size >= 0 &&
         !excluded.inodes.contains({named.st_dev, named.st_ino}));
    Fd fd(::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
    need(::fstat(fd.value, &opened) == 0 && stable(named, opened));
    Bytes bytes(static_cast<size_t>(opened.st_size)); size_t at = 0;
    while (at < bytes.size()) {
        auto n = ::pread(fd.value, bytes.data() + at, bytes.size() - at, at);
        if (n < 0 && errno == EINTR) continue;
        need(n > 0); at += static_cast<size_t>(n);
    }
    need(::fstat(fd.value, &after) == 0 && ::lstat(path.c_str(), &named_after) == 0 &&
         stable(opened, after) && stable(opened, named_after));
    return bytes;
}
Bytes admitted(const Path& path, const Digest& expected, const Exclusions& excluded) {
    need(expected != Digest{}); auto bytes = read_public(path, excluded);
    need(history::digest(bytes) == expected); return bytes;
}
Fd sealed(std::span<const unsigned char> bytes, bool executable) {
    Fd fd(static_cast<int>(::syscall(SYS_memfd_create, "kpb-fixed-public", MFD_CLOEXEC | MFD_ALLOW_SEALING)));
    write_all(fd.value, bytes); need(::fchmod(fd.value, executable ? 0500 : 0400) == 0);
    need(::fcntl(fd.value, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == 0);
    need(::lseek(fd.value, 0, SEEK_SET) == 0); return fd;
}
Fd installed_namespace_tool(const FixedPublicProgram& program, const Exclusions& excluded) {
    excluded.public_path(program.namespace_tool);
    // The installed namespace tool's actual inode/path carries the kernel's
    // AppArmor user-namespace profile. An anonymous copy loses that profile.
    // Admit this ROOT-owned OS tool in place; every ancestor is ROOT-owned and
    // unwritable by the service uid. Other selected leaves remain sealed copies.
    struct stat named{}, opened{}, after{}, named_after{};
    need(::lstat(program.namespace_tool.c_str(), &named) == 0 && S_ISREG(named.st_mode) &&
         named.st_uid == 0 && named.st_nlink == 1 && (named.st_mode & 0022) == 0 &&
         (named.st_mode & 0111) != 0 && !excluded.inodes.contains({named.st_dev, named.st_ino}));
    for (auto p = program.namespace_tool.parent_path(); !p.empty(); p = p.parent_path()) {
        struct stat info{}; need(::lstat(p.c_str(), &info) == 0 && S_ISDIR(info.st_mode) &&
            info.st_uid == 0 && (info.st_mode & 0022) == 0);
        if (p == p.root_path()) break;
    }
    Fd fd(::open(program.namespace_tool.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
    need(::fstat(fd.value, &opened) == 0 && stable(named, opened));
    (void)admitted(program.namespace_tool, program.namespace_tool_sha256, excluded);
    need(::fstat(fd.value, &after) == 0 && ::lstat(program.namespace_tool.c_str(), &named_after) == 0 &&
         stable(opened, after) && stable(opened, named_after));
    return fd;
}
void owned_directory(const Path& path, const Exclusions& excluded) {
    excluded.public_path(path, true); struct stat s{};
    need(::lstat(path.c_str(), &s) == 0 && S_ISDIR(s.st_mode) &&
         s.st_uid == ::getuid() && (s.st_mode & 07777) == 0700);
}
void create_file(const Path& path, std::span<const unsigned char> bytes) {
    Fd fd(::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0400));
    write_all(fd.value, bytes); sync(fd.value);
}
void add(Bytes& bytes, std::span<const unsigned char> value) {
    bytes.insert(bytes.end(), value.begin(), value.end());
}
void add(Bytes& bytes, const std::string& value) {
    add(bytes, std::span(reinterpret_cast<const unsigned char*>(value.data()), value.size()));
}
} // namespace

FixedPublicResult run_fixed_public_program(const RegisteredService& service,
    const FixedPublicProgram& program, std::span<const unsigned char> input) {
    // A copied caller-authored FixedPublicProgram is not a selected program.
    const bool acquisition = &program == &service.acquisition();
    need(acquisition || &program == &service.exporter());
    struct stat marker{}; need(::lstat("/kpb-public-only", &marker) < 0 && errno == ENOENT);
    const Exclusions excluded(service);
    owned_directory(program.work_parent, excluded);
    need(!program.namespace_tool.empty() && program.namespace_tool_sha256 != Digest{});
    auto namespace_fd = installed_namespace_tool(program, excluded);
    struct File { Path path; Digest identity; Fd fd; bool executable; };
    std::vector<File> files;
    std::map<Path, Digest> selected;
    const std::array<Path, 4> reserved{"/proc", "/kpb-output", "/kpb-input.json", "/kpb-public-only"};
    auto select = [&](const Path& path, const Digest& sha, bool executable) {
        excluded.public_path(path);
        for (const auto& root : reserved) need(!inside(path, root) && !inside(root, path));
        // Established SDK leaves have fixed /dev/shm paths. Materialize only
        // their individually admitted sealed bytes in the fresh /dev mount;
        // no host shared-memory directory or device leaf is exposed.
        if (inside(path, "/dev")) need(inside(path, "/dev/shm") && path != "/dev/shm");
        if (const auto old = selected.find(path); old != selected.end()) { need(old->second == sha); return; }
        auto bytes = admitted(path, sha, excluded);
        selected.emplace(path, sha); files.push_back({path, sha, sealed(bytes, executable), executable});
    };
    select(program.executable, program.executable_sha256, program.interpreter.empty());
    select(program.source_closure, program.source_closure_sha256, false);
    select(program.specification, program.specification_sha256, false);
    need(program.interpreter.empty() == (program.interpreter_sha256 == Digest{}));
    if (!program.interpreter.empty()) select(program.interpreter, program.interpreter_sha256, true);
    for (const auto& file : program.runtime_files) {
        excluded.public_path(file.path); struct stat metadata{};
        need(::lstat(file.path.c_str(), &metadata) == 0 && S_ISREG(metadata.st_mode));
        // Selected node/verifier/helper tools are runtime leaves too. Preserve
        // only the execute/read distinction; never preserve special/write bits.
        select(file.path, file.sha256, (metadata.st_mode & 0111) != 0);
    }
    std::set<Path> aliases;
    for (const auto& alias : program.runtime_aliases) {
        need(alias.path.is_absolute() && alias.path == alias.path.lexically_normal() &&
             alias.path.string().find('\0') == std::string::npos && selected.contains(alias.target) &&
             !selected.contains(alias.path) && aliases.insert(alias.path).second);
        for (const auto& root : excluded.roots) need(!inside(alias.path, root) && !inside(root, alias.path));
        for (const auto& root : reserved) need(!inside(alias.path, root) && !inside(root, alias.path));
        need(!inside(alias.path, "/dev") && !inside(alias.path, "/bin"));
        for (const auto& file : files) need(!inside(file.path, alias.path) && !inside(alias.path, file.path));
        for (const auto& other : aliases)
            if (other != alias.path) need(!inside(other, alias.path) && !inside(alias.path, other));
    }

    std::string pattern = (program.work_parent / "fixed-public-XXXXXX").string();
    std::vector<char> fresh(pattern.begin(), pattern.end()); fresh.push_back(0);
    need(::mkdtemp(fresh.data()) != nullptr); const Path workspace(fresh.data());
    owned_directory(workspace, excluded); const Path output = workspace / "output";
    need(::mkdir(output.c_str(), 0700) == 0); owned_directory(output, excluded);
    create_file(workspace / "INPUT.json", input);
    auto input_fd = sealed(input, false); const Digest input_identity = history::digest(input);
    const std::string marker_text = "KPB_FIXED_PUBLIC_NAMESPACE_V1\n";
    auto marker_fd = sealed(std::span(reinterpret_cast<const unsigned char*>(marker_text.data()), marker_text.size()), false);
    Fd out(::open((workspace / "stdout.public").c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
    Fd errors(::open((workspace / "stderr.public").c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
    Fd null(::open("/dev/null", O_RDONLY | O_CLOEXEC));

    std::vector<std::string> args{program.namespace_tool.string(), "--unshare-all"};
    if (acquisition) args.push_back("--share-net"); // Fixed read-only Tor acquisition only.
    auto append = [&](std::initializer_list<std::string> values) { args.insert(args.end(), values); };
    append({"--die-with-parent", "--new-session", "--cap-drop", "ALL", "--clearenv",
        "--tmpfs", "/", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
        "--dir", "/usr", "--dir", "/usr/bin", "--dir", "/etc", "--dir", "/etc/ssl"});
    // System runtime/CA data are trusted installed OS dependencies, not claimed
    // archive-authenticated source. No home, /run, keys or host /proc are bound.
    for (const Path& root : {Path("/usr/lib"), Path("/usr/lib64"), Path("/etc/ssl/certs"), Path("/usr/share/ca-certificates")}) {
        if (!std::filesystem::exists(root)) continue;
        for (const auto& secret : excluded.roots) need(!inside(root, secret) && !inside(secret, root));
        append({"--ro-bind", root.string(), root.string()});
    }
    append({"--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64"});
    std::set<Path> directories;
    for (const auto& file : files)
        for (auto p = file.path.parent_path(); p != p.root_path(); p = p.parent_path()) directories.insert(p);
    for (const auto& alias : program.runtime_aliases)
        for (auto p = alias.path.parent_path(); p != p.root_path(); p = p.parent_path()) directories.insert(p);
    for (const auto& path : directories) {
        if (inside(path, "/usr/lib") || inside(path, "/usr/lib64") || inside(path, "/etc/ssl/certs")) continue;
        append({"--dir", path.string()});
    }
    for (size_t i = 0; i < files.size(); ++i)
        append({"--perms", files[i].executable ? "0500" : "0400", "--ro-bind-data", std::to_string(4 + i), files[i].path.string()});
    // Explicit namespace aliases to already selected bytes, never host
    // symlink admission. Legacy shebangs and SDK bridges use these names.
    append({"--symlink", "usr/bin", "/bin"});
    for (const auto& alias : program.runtime_aliases)
        append({"--symlink", alias.target.string(), alias.path.string()});
    append({"--perms", "0400", "--ro-bind-data", std::to_string(4 + files.size()), "/kpb-input.json",
        "--perms", "0400", "--ro-bind-data", std::to_string(5 + files.size()), "/kpb-public-only",
        "--bind", output.string(), "/kpb-output",
        "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "LANG", "C.UTF-8",
        "--setenv", "PYTHONDONTWRITEBYTECODE", "1", "--chdir", "/tmp", "--remount-ro", "/", "--"});
    if (!program.interpreter.empty()) append({program.interpreter.string(), "-I", "-B"});
    append({program.executable.string(), "--specification", program.specification.string(),
        "--input", "/kpb-input.json", "--output", "/kpb-output/result"});
    std::vector<char*> argv; for (auto& arg : args) argv.push_back(arg.data()); argv.push_back(nullptr);

    std::vector<int> originals{null.value, out.value, errors.value, namespace_fd.value};
    for (const auto& file : files) originals.push_back(file.fd.value);
    originals.push_back(input_fd.value);
    originals.push_back(marker_fd.value);
    std::vector<Fd> held;
    const int first_held = static_cast<int>(originals.size()) + 1024;
    for (int fd : originals) held.emplace_back(::fcntl(fd, F_DUPFD_CLOEXEC, first_held));
    const pid_t pid = ::fork(); need(pid >= 0);
    if (pid == 0) {
        for (size_t i = 0; i < held.size(); ++i)
            if (::dup2(held[i].value, static_cast<int>(i)) < 0) ::_exit(126);
        if (::fcntl(3, F_SETFD, FD_CLOEXEC) != 0 ||
            ::syscall(SYS_close_range, static_cast<unsigned>(held.size()), UINT_MAX, 0U) != 0) ::_exit(126);
        char env0[] = "PATH=/usr/bin:/bin", env1[] = "LANG=C.UTF-8";
        char* env[]{env0, env1, nullptr}; ::fexecve(3, argv.data(), env); ::_exit(127);
    }
    int status = 0; pid_t waited;
    do { waited = ::waitpid(pid, &status, 0); } while (waited < 0 && errno == EINTR);
    sync(out.value); sync(errors.value);
    need(waited == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    const Exclusions after(service);
    auto stdout_bytes = read_public(workspace / "stdout.public", after);
    Bytes execution; add(execution, "KPB_FIXED_PUBLIC_EXECUTION_V1\n");
    add(execution, service.identity()); add(execution, program.executable_sha256);
    add(execution, program.source_closure_sha256); add(execution, program.specification_sha256);
    add(execution, program.namespace_tool_sha256); add(execution, input_identity);
    add(execution, history::digest(stdout_bytes));
    return {workspace, output / "result", std::move(stdout_bytes), input_identity, history::digest(execution)};
}

std::vector<unsigned char> read_fixed_public_result(const RegisteredService& service,
    const FixedPublicResult& result, const Path& relative_name) {
    const auto path = check_fixed_public_result_path(service, result, relative_name);
    const Exclusions excluded(service); return read_public(path, excluded);
}

std::filesystem::path check_fixed_public_result_path(const RegisteredService& service,
    const FixedPublicResult& result, const Path& relative_name) {
    need(!relative_name.empty() && relative_name.is_relative() &&
         relative_name == relative_name.lexically_normal());
    for (const auto& part : relative_name) need(part != ".." && part != ".");
    const Exclusions excluded(service);
    need((result.workspace.parent_path() == service.acquisition().work_parent ||
          result.workspace.parent_path() == service.exporter().work_parent) &&
         result.workspace.filename().string().starts_with("fixed-public-"));
    owned_directory(result.workspace, excluded); owned_directory(result.workspace / "output", excluded);
    need(result.output_directory == result.workspace / "output" / "result");
    const Path path = result.output_directory / relative_name;
    excluded.public_path(path); struct stat info{};
    need(::lstat(path.c_str(), &info) == 0 && S_ISREG(info.st_mode) && info.st_uid == ::getuid() &&
         info.st_nlink == 1 && !excluded.inodes.contains({info.st_dev, info.st_ino}));
    return path;
}

std::vector<unsigned char> read_registered_native_tail(const RegisteredService& service) {
    const Exclusions excluded(service);
    return admitted(service.native_tail_path(), service.native_tail_identity(), excluded);
}
} // namespace kpi::mpc::financial
