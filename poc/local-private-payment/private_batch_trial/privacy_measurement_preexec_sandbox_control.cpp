#include "privacy_measurement_preexec_sandbox.hpp"

#include <cerrno>
#include <fcntl.h>
#include <linux/openat2.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace {

bool denied(long result) {
    return result == -1 && errno == EPERM;
}

} // namespace

int main() {
    static constexpr char empty_path[]{'\0'};
    static char other_empty_path[]{'\0'};
    const int runtime = ::open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    const int proc = ::open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (proc < 0 || ::dup2(proc, 40) != 40) return 1;
    if (proc != 40) (void)::close(proc);
    if (runtime < 0 ||
        !kpb::measurement::runtime_bridge::detail::
            install_measurement_preexec_sandbox(
                runtime, empty_path,
                kpb::measurement::runtime_bridge::RuntimeChildRole::Aggregate))
        return 1;

    char byte{};
    errno = 0;
    if (!denied(::readlinkat(
            AT_FDCWD, "/proc/self/exe", &byte, sizeof(byte))))
        return 2;
    errno = 0;
    if (!denied(::openat(
            AT_FDCWD, "/proc/sys/vm/overcommit_memory", O_RDONLY)))
        return 3;
    errno = 0;
    if (!denied(::openat(40, "../etc/passwd", O_RDONLY))) return 4;
    struct open_how how{
        .flags = O_RDONLY,
        .mode = 0,
        .resolve = 0,
    };
    errno = 0;
    if (!denied(::syscall(
            SYS_openat2, AT_FDCWD, "/etc/passwd", &how, sizeof(how))))
        return 5;
    errno = 0;
    if (!denied(::socket(AF_UNIX, SOCK_STREAM, 0))) return 6;
    errno = 0;
    if (!denied(::ptrace(PTRACE_PEEKDATA, ::getppid(), nullptr, nullptr)))
        return 7;
#if defined(__x86_64__)
    errno = 0;
    if (!denied(::syscall(SYS_getpid | 0x40000000U))) return 8;
#endif
    errno = 0;
    if (!denied(::syscall(SYS_memfd_create, "replacement", 0))) return 9;
    errno = 0;
    if (!denied(::dup2(40, runtime))) return 10;
    errno = 0;
    if (!denied(::fcntl(40, F_DUPFD, runtime))) return 11;
    errno = 0;
    if (!denied(::unlinkat(40, "not-present", 0))) return 12;
    errno = 0;
    if (!denied(::mkdirat(40, "not-created", 0700))) return 13;
    errno = 0;
    if (!denied(::kill(::getpid(), 0))) return 14;

    char name[] = "forbidden";
    char* const arguments[]{name, nullptr};
    char* const environment[]{nullptr};
    errno = 0;
    if (!denied(::syscall(
            SYS_execveat, runtime + 1, "", arguments, environment,
            AT_EMPTY_PATH)))
        return 15;
    errno = 0;
    if (!denied(::syscall(
            SYS_execveat, runtime, "", arguments, environment, 0)))
        return 16;
    errno = 0;
    if (!denied(::syscall(
            SYS_execveat, runtime, other_empty_path, arguments, environment,
            AT_EMPTY_PATH)))
        return 17;
    errno = 0;
    if (!denied(::execve("/proc/self/exe", arguments, environment)))
        return 18;
    return 0;
}
