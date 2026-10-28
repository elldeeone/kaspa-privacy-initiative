// Deterministic PUBLIC-control-only race: append and seal between the tested
// loader's first fstat and its F_GET_SEALS. Never loaded by an MPC worker.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int fcntl(int fd, int command, ...) {
    int argument = 0;
    if (command != F_GETFD && command != F_GETFL && command != F_GET_SEALS) {
        if (command != F_DUPFD && command != F_DUPFD_CLOEXEC && command != F_ADD_SEALS &&
            command != F_SETFD && command != F_SETFL) { errno = EINVAL; return -1; }
        va_list arguments; va_start(arguments, command);
        argument = va_arg(arguments, int); va_end(arguments);
    }
    static int changed = 0;
    if (command == F_GET_SEALS && !changed) {
        char path[64], name[256];
        const int length = snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
        const ssize_t size = length > 0 ? readlink(path, name, sizeof(name) - 1) : -1;
        if (size >= 0) {
            name[size] = 0;
            if (strstr(name, "memfd:public-adoption-race")) {
                const off_t end = lseek(fd, 0, SEEK_END);
                if (end < 0 || pwrite(fd, "TRAIL", 5, end) != 5) return -1;
                const int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
                if (syscall(SYS_fcntl, fd, F_ADD_SEALS, seals) < 0) return -1;
                changed = 1;
            }
        }
    }
    return (int) syscall(SYS_fcntl, fd, command, argument);
}
