#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "privacy_measurement_preexec_sandbox.hpp"
#include "privacy_measurement_output_abi.hpp"
#include "privacy_measurement_worker_capsule.hpp"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <utility>

namespace kpb::measurement::runtime_bridge::detail {
namespace {

constexpr std::uint32_t DENIED =
    SECCOMP_RET_ERRNO | static_cast<std::uint32_t>(EPERM);

class Filter final {
    std::array<sock_filter, 512> rows_{};
    unsigned size_{};
    bool overflow_{};
public:
    void statement(unsigned short code, std::uint32_t value) noexcept {
        if (size_ >= rows_.size()) {
            overflow_ = true;
            return;
        }
        rows_[size_++] = sock_filter{code, 0, 0, value};
    }

    void branch(unsigned short code, std::uint32_t value,
                unsigned char yes, unsigned char no) noexcept {
        if (size_ >= rows_.size()) {
            overflow_ = true;
            return;
        }
        rows_[size_++] = sock_filter{code, yes, no, value};
    }

    void deny_call(int number) noexcept {
        branch(BPF_JMP | BPF_JEQ | BPF_K,
               static_cast<std::uint32_t>(number), 0, 1);
        statement(BPF_RET | BPF_K, DENIED);
    }

    void allow_one_fd_call(int number, int fd) noexcept {
        // Non-matches skip the complete six-row argument block.
        branch(BPF_JMP | BPF_JEQ | BPF_K,
               static_cast<std::uint32_t>(number), 0, 6);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[0]));
        branch(BPF_JMP | BPF_JEQ | BPF_K,
               static_cast<std::uint32_t>(fd), 0, 3);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[0]) + 4);
        branch(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1);
        statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
        statement(BPF_RET | BPF_K, DENIED);
    }

    void allow_two_fd_call(int number, int first, int second) noexcept {
        // Existing authenticated capability sockets only.  This cannot create
        // or address a network endpoint.
        branch(BPF_JMP | BPF_JEQ | BPF_K,
               static_cast<std::uint32_t>(number), 0, 7);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[0]) + 4);
        branch(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 3);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[0]));
        branch(BPF_JMP | BPF_JEQ | BPF_K,
               static_cast<std::uint32_t>(first), 2, 0);
        branch(BPF_JMP | BPF_JEQ | BPF_K,
               static_cast<std::uint32_t>(second), 1, 0);
        statement(BPF_RET | BPF_K, DENIED);
        statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    }

    void allow_exact_pwrite64(int fd, std::uint64_t count) noexcept {
        // fd, count, and offset are all checked as full 64-bit arguments.
        // The body is accepted only after exit by the parent ABI parser.
        branch(BPF_JMP | BPF_JEQ | BPF_K, SYS_pwrite64, 0, 19);
        for (const auto [argument, expected] :
             std::array<std::pair<unsigned, std::uint64_t>, 3>{
                 std::pair{0U, static_cast<std::uint64_t>(fd)},
                 std::pair{2U, count},
                 std::pair{3U, std::uint64_t{0}},
             }) {
            statement(BPF_LD | BPF_W | BPF_ABS,
                      offsetof(struct seccomp_data, args[argument]));
            branch(BPF_JMP | BPF_JEQ | BPF_K,
                   static_cast<std::uint32_t>(expected), 1, 0);
            statement(BPF_RET | BPF_K, DENIED);
            statement(BPF_LD | BPF_W | BPF_ABS,
                      offsetof(struct seccomp_data, args[argument]) + 4);
            branch(BPF_JMP | BPF_JEQ | BPF_K,
                   static_cast<std::uint32_t>(expected >> 32), 1, 0);
            statement(BPF_RET | BPF_K, DENIED);
        }
        statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    }

    void exact_execveat(int runtime_fd,
                        const char* empty_path) noexcept {
        const auto path = reinterpret_cast<std::uintptr_t>(empty_path);
        // fd, immutable empty-path pointer, and flags are checked as full
        // 64-bit seccomp arguments.  The filter cannot dereference memory;
        // binding the pointer to this read-only byte closes that ambiguity.
        branch(BPF_JMP | BPF_JEQ | BPF_K, SYS_execveat, 0, 14);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[0]));
        branch(BPF_JMP | BPF_JEQ | BPF_K,
               static_cast<std::uint32_t>(runtime_fd), 0, 11);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[0]) + 4);
        branch(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 9);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[1]));
        branch(BPF_JMP | BPF_JEQ | BPF_K,
               static_cast<std::uint32_t>(path), 0, 7);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[1]) + 4);
        branch(BPF_JMP | BPF_JEQ | BPF_K,
               static_cast<std::uint32_t>(path >> 32), 0, 5);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[4]));
        branch(BPF_JMP | BPF_JEQ | BPF_K, AT_EMPTY_PATH, 0, 3);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[4]) + 4);
        branch(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1);
        statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
        statement(BPF_RET | BPF_K, DENIED);
    }

    void deny_fcntl_duplication() noexcept {
        // Capsule validation still needs F_GETFD/F_GETFL/F_GET_SEALS before
        // the role filter is stacked.  Only descriptor-minting commands are
        // forbidden at this bootstrap layer.
        branch(BPF_JMP | BPF_JEQ | BPF_K, SYS_fcntl, 0, 6);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[1]) + 4);
        branch(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 3);
        statement(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[1]));
        branch(BPF_JMP | BPF_JEQ | BPF_K, F_DUPFD, 1, 0);
        branch(BPF_JMP | BPF_JEQ | BPF_K, F_DUPFD_CLOEXEC, 0, 1);
        statement(BPF_RET | BPF_K, DENIED);
    }

    bool install() noexcept {
        if (overflow_ || size_ == 0 || size_ > rows_.size()) return false;
        sock_fprog program{
            .len = static_cast<unsigned short>(size_),
            .filter = rows_.data(),
        };
        return ::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0;
    }
};

} // namespace

bool install_measurement_preexec_sandbox(
        int exact_runtime_fd, const char* exact_empty_path,
        RuntimeChildRole role) noexcept {
    const int descriptor_flags = ::fcntl(exact_runtime_fd, F_GETFD);
    if (exact_runtime_fd <= 2 || exact_empty_path == nullptr ||
        exact_empty_path[0] != '\0' || descriptor_flags < 0 ||
        (descriptor_flags & FD_CLOEXEC) == 0)
        return false;
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return false;

    Filter filter;
    filter.statement(BPF_LD | BPF_W | BPF_ABS,
                     offsetof(struct seccomp_data, arch));
#if defined(__x86_64__)
    constexpr std::uint32_t native_arch = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
    constexpr std::uint32_t native_arch = AUDIT_ARCH_AARCH64;
#else
    return false;
#endif
    filter.branch(BPF_JMP | BPF_JEQ | BPF_K, native_arch, 1, 0);
    filter.statement(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    filter.statement(BPF_LD | BPF_W | BPF_ABS,
                     offsetof(struct seccomp_data, nr));
#if defined(__x86_64__)
    // x32 ORs this bit into an otherwise familiar syscall number.  Reject it
    // before any native-number dispatch so a deny rule cannot be bypassed.
    filter.branch(BPF_JMP | BPF_JSET | BPF_K, 0x40000000U, 0, 1);
    filter.statement(BPF_RET | BPF_K, DENIED);
#endif

    filter.exact_execveat(exact_runtime_fd, exact_empty_path);
#ifdef SYS_execve
    filter.deny_call(SYS_execve);
#endif

#ifdef SYS_open
    filter.deny_call(SYS_open);
#endif
#ifdef SYS_openat
    filter.deny_call(SYS_openat);
#endif
#ifdef SYS_openat2
    filter.deny_call(SYS_openat2);
#endif
#ifdef SYS_creat
    filter.deny_call(SYS_creat);
#endif
#ifdef SYS_readlink
    filter.deny_call(SYS_readlink);
#endif
#ifdef SYS_readlinkat
    filter.deny_call(SYS_readlinkat);
#endif
#ifdef SYS_stat
    filter.deny_call(SYS_stat);
#endif
#ifdef SYS_lstat
    filter.deny_call(SYS_lstat);
#endif
#ifdef SYS_newfstatat
    filter.deny_call(SYS_newfstatat);
#endif
#ifdef SYS_statx
    filter.deny_call(SYS_statx);
#endif
#ifdef SYS_statfs
    filter.deny_call(SYS_statfs);
#endif
#ifdef SYS_access
    filter.deny_call(SYS_access);
#endif
#ifdef SYS_faccessat
    filter.deny_call(SYS_faccessat);
#endif
#ifdef SYS_faccessat2
    filter.deny_call(SYS_faccessat2);
#endif
#ifdef SYS_name_to_handle_at
    filter.deny_call(SYS_name_to_handle_at);
#endif
#ifdef SYS_open_by_handle_at
    filter.deny_call(SYS_open_by_handle_at);
#endif
#ifdef SYS_chdir
    filter.deny_call(SYS_chdir);
#endif
#ifdef SYS_fchdir
    filter.deny_call(SYS_fchdir);
#endif
#ifdef SYS_getcwd
    filter.deny_call(SYS_getcwd);
#endif
#ifdef SYS_memfd_create
    filter.deny_call(SYS_memfd_create);
#endif
#ifdef SYS_dup
    filter.deny_call(SYS_dup);
#endif
#ifdef SYS_dup2
    filter.deny_call(SYS_dup2);
#endif
#ifdef SYS_dup3
    filter.deny_call(SYS_dup3);
#endif
#ifdef SYS_fcntl
    filter.deny_fcntl_duplication();
#endif
#ifdef SYS_mkdir
    filter.deny_call(SYS_mkdir);
#endif
#ifdef SYS_mkdirat
    filter.deny_call(SYS_mkdirat);
#endif
#ifdef SYS_rmdir
    filter.deny_call(SYS_rmdir);
#endif
#ifdef SYS_unlink
    filter.deny_call(SYS_unlink);
#endif
#ifdef SYS_unlinkat
    filter.deny_call(SYS_unlinkat);
#endif
#ifdef SYS_rename
    filter.deny_call(SYS_rename);
#endif
#ifdef SYS_renameat
    filter.deny_call(SYS_renameat);
#endif
#ifdef SYS_renameat2
    filter.deny_call(SYS_renameat2);
#endif
#ifdef SYS_link
    filter.deny_call(SYS_link);
#endif
#ifdef SYS_linkat
    filter.deny_call(SYS_linkat);
#endif
#ifdef SYS_symlink
    filter.deny_call(SYS_symlink);
#endif
#ifdef SYS_symlinkat
    filter.deny_call(SYS_symlinkat);
#endif
#ifdef SYS_mknod
    filter.deny_call(SYS_mknod);
#endif
#ifdef SYS_mknodat
    filter.deny_call(SYS_mknodat);
#endif
#ifdef SYS_chmod
    filter.deny_call(SYS_chmod);
#endif
#ifdef SYS_fchmod
    filter.deny_call(SYS_fchmod);
#endif
#ifdef SYS_fchmodat
    filter.deny_call(SYS_fchmodat);
#endif
#ifdef SYS_chown
    filter.deny_call(SYS_chown);
#endif
#ifdef SYS_lchown
    filter.deny_call(SYS_lchown);
#endif
#ifdef SYS_fchown
    filter.deny_call(SYS_fchown);
#endif
#ifdef SYS_fchownat
    filter.deny_call(SYS_fchownat);
#endif
#ifdef SYS_truncate
    filter.deny_call(SYS_truncate);
#endif
#ifdef SYS_ftruncate
    filter.deny_call(SYS_ftruncate);
#endif
#ifdef SYS_utime
    filter.deny_call(SYS_utime);
#endif
#ifdef SYS_utimes
    filter.deny_call(SYS_utimes);
#endif
#ifdef SYS_futimesat
    filter.deny_call(SYS_futimesat);
#endif
#ifdef SYS_utimensat
    filter.deny_call(SYS_utimensat);
#endif
#ifdef SYS_setxattr
    filter.deny_call(SYS_setxattr);
#endif
#ifdef SYS_lsetxattr
    filter.deny_call(SYS_lsetxattr);
#endif
#ifdef SYS_fsetxattr
    filter.deny_call(SYS_fsetxattr);
#endif
#ifdef SYS_getxattr
    filter.deny_call(SYS_getxattr);
#endif
#ifdef SYS_lgetxattr
    filter.deny_call(SYS_lgetxattr);
#endif
#ifdef SYS_fgetxattr
    filter.deny_call(SYS_fgetxattr);
#endif
#ifdef SYS_listxattr
    filter.deny_call(SYS_listxattr);
#endif
#ifdef SYS_llistxattr
    filter.deny_call(SYS_llistxattr);
#endif
#ifdef SYS_flistxattr
    filter.deny_call(SYS_flistxattr);
#endif
#ifdef SYS_removexattr
    filter.deny_call(SYS_removexattr);
#endif
#ifdef SYS_lremovexattr
    filter.deny_call(SYS_lremovexattr);
#endif
#ifdef SYS_fremovexattr
    filter.deny_call(SYS_fremovexattr);
#endif

#ifdef SYS_socket
    filter.deny_call(SYS_socket);
#endif
#ifdef SYS_socketpair
    filter.deny_call(SYS_socketpair);
#endif
#ifdef SYS_connect
    filter.deny_call(SYS_connect);
#endif
#ifdef SYS_bind
    filter.deny_call(SYS_bind);
#endif
#ifdef SYS_listen
    filter.deny_call(SYS_listen);
#endif
#ifdef SYS_accept
    filter.deny_call(SYS_accept);
#endif
#ifdef SYS_accept4
    filter.deny_call(SYS_accept4);
#endif
#ifdef SYS_shutdown
    filter.deny_call(SYS_shutdown);
#endif
#ifdef SYS_getsockname
    filter.deny_call(SYS_getsockname);
#endif
#ifdef SYS_getpeername
    filter.deny_call(SYS_getpeername);
#endif
#ifdef SYS_setsockopt
    filter.deny_call(SYS_setsockopt);
#endif
#ifdef SYS_getsockopt
    filter.deny_call(SYS_getsockopt);
#endif
#ifdef SYS_sendto
    filter.allow_one_fd_call(SYS_sendto, MEASUREMENT_CHILD_FIXED_FD);
#endif
#ifdef SYS_recvfrom
    filter.deny_call(SYS_recvfrom);
#endif
#ifdef SYS_sendmmsg
    filter.deny_call(SYS_sendmmsg);
#endif
#ifdef SYS_recvmmsg
    filter.deny_call(SYS_recvmmsg);
#endif
#ifdef SYS_sendfile
    filter.deny_call(SYS_sendfile);
#endif
#ifdef SYS_splice
    filter.deny_call(SYS_splice);
#endif
#ifdef SYS_vmsplice
    filter.deny_call(SYS_vmsplice);
#endif
#ifdef SYS_tee
    filter.deny_call(SYS_tee);
#endif
#ifdef SYS_copy_file_range
    filter.deny_call(SYS_copy_file_range);
#endif
#ifdef SYS_pwrite64
    if (const auto* abi = measurement_output_abi(role); abi != nullptr)
        filter.allow_exact_pwrite64(
            MEASUREMENT_CHILD_OUTPUT_FD, abi->exact_bytes);
    else
        filter.deny_call(SYS_pwrite64);
#endif
#ifdef SYS_pwritev
    filter.deny_call(SYS_pwritev);
#endif
#ifdef SYS_pwritev2
    filter.deny_call(SYS_pwritev2);
#endif
#ifdef SYS_sendmsg
    filter.allow_one_fd_call(SYS_sendmsg, MEASUREMENT_CHILD_FIXED_FD);
#endif
#ifdef SYS_recvmsg
    filter.allow_two_fd_call(
        SYS_recvmsg, MEASUREMENT_CHILD_FIXED_FD,
        MEASUREMENT_SCORE_OWNER_TRUTH_FD);
#endif

#ifdef SYS_ptrace
    filter.deny_call(SYS_ptrace);
#endif
#ifdef SYS_process_vm_readv
    filter.deny_call(SYS_process_vm_readv);
#endif
#ifdef SYS_process_vm_writev
    filter.deny_call(SYS_process_vm_writev);
#endif
#ifdef SYS_kill
    filter.deny_call(SYS_kill);
#endif
#ifdef SYS_tkill
    filter.deny_call(SYS_tkill);
#endif
#ifdef SYS_tgkill
    filter.deny_call(SYS_tgkill);
#endif
#ifdef SYS_kcmp
    filter.deny_call(SYS_kcmp);
#endif
#ifdef SYS_pidfd_open
    filter.deny_call(SYS_pidfd_open);
#endif
#ifdef SYS_pidfd_getfd
    filter.deny_call(SYS_pidfd_getfd);
#endif
#ifdef SYS_perf_event_open
    filter.deny_call(SYS_perf_event_open);
#endif
#ifdef SYS_bpf
    filter.deny_call(SYS_bpf);
#endif
#ifdef SYS_userfaultfd
    filter.deny_call(SYS_userfaultfd);
#endif
#ifdef SYS_io_uring_setup
    filter.deny_call(SYS_io_uring_setup);
#endif
#ifdef SYS_io_uring_enter
    filter.deny_call(SYS_io_uring_enter);
#endif
#ifdef SYS_io_uring_register
    filter.deny_call(SYS_io_uring_register);
#endif
#ifdef SYS_process_madvise
    filter.deny_call(SYS_process_madvise);
#endif
#ifdef SYS_keyctl
    filter.deny_call(SYS_keyctl);
#endif
#ifdef SYS_add_key
    filter.deny_call(SYS_add_key);
#endif
#ifdef SYS_request_key
    filter.deny_call(SYS_request_key);
#endif
#ifdef SYS_syslog
    filter.deny_call(SYS_syslog);
#endif
#ifdef SYS_mount
    filter.deny_call(SYS_mount);
#endif
#ifdef SYS_umount2
    filter.deny_call(SYS_umount2);
#endif
#ifdef SYS_open_tree
    filter.deny_call(SYS_open_tree);
#endif
#ifdef SYS_move_mount
    filter.deny_call(SYS_move_mount);
#endif
#ifdef SYS_fsopen
    filter.deny_call(SYS_fsopen);
#endif
#ifdef SYS_fsconfig
    filter.deny_call(SYS_fsconfig);
#endif
#ifdef SYS_fsmount
    filter.deny_call(SYS_fsmount);
#endif
#ifdef SYS_fspick
    filter.deny_call(SYS_fspick);
#endif
#ifdef SYS_mount_setattr
    filter.deny_call(SYS_mount_setattr);
#endif
#ifdef SYS_unshare
    filter.deny_call(SYS_unshare);
#endif
#ifdef SYS_setns
    filter.deny_call(SYS_setns);
#endif
#ifdef SYS_setuid
    filter.deny_call(SYS_setuid);
#endif
#ifdef SYS_setgid
    filter.deny_call(SYS_setgid);
#endif
#ifdef SYS_setreuid
    filter.deny_call(SYS_setreuid);
#endif
#ifdef SYS_setregid
    filter.deny_call(SYS_setregid);
#endif
#ifdef SYS_setresuid
    filter.deny_call(SYS_setresuid);
#endif
#ifdef SYS_setresgid
    filter.deny_call(SYS_setresgid);
#endif
#ifdef SYS_setfsuid
    filter.deny_call(SYS_setfsuid);
#endif
#ifdef SYS_setfsgid
    filter.deny_call(SYS_setfsgid);
#endif
#ifdef SYS_setgroups
    filter.deny_call(SYS_setgroups);
#endif
#ifdef SYS_capset
    filter.deny_call(SYS_capset);
#endif
#ifdef SYS_personality
    filter.deny_call(SYS_personality);
#endif
#ifdef SYS_iopl
    filter.deny_call(SYS_iopl);
#endif
#ifdef SYS_ioperm
    filter.deny_call(SYS_ioperm);
#endif
#ifdef SYS_sethostname
    filter.deny_call(SYS_sethostname);
#endif
#ifdef SYS_setdomainname
    filter.deny_call(SYS_setdomainname);
#endif
#ifdef SYS_reboot
    filter.deny_call(SYS_reboot);
#endif
#ifdef SYS_swapon
    filter.deny_call(SYS_swapon);
#endif
#ifdef SYS_swapoff
    filter.deny_call(SYS_swapoff);
#endif
#ifdef SYS_acct
    filter.deny_call(SYS_acct);
#endif
#ifdef SYS_init_module
    filter.deny_call(SYS_init_module);
#endif
#ifdef SYS_finit_module
    filter.deny_call(SYS_finit_module);
#endif
#ifdef SYS_delete_module
    filter.deny_call(SYS_delete_module);
#endif
#ifdef SYS_kexec_load
    filter.deny_call(SYS_kexec_load);
#endif
#ifdef SYS_kexec_file_load
    filter.deny_call(SYS_kexec_file_load);
#endif
#ifdef SYS_fanotify_init
    filter.deny_call(SYS_fanotify_init);
#endif
#ifdef SYS_inotify_init
    filter.deny_call(SYS_inotify_init);
#endif
#ifdef SYS_inotify_init1
    filter.deny_call(SYS_inotify_init1);
#endif
#ifdef SYS_quotactl
    filter.deny_call(SYS_quotactl);
#endif
#ifdef SYS_quotactl_fd
    filter.deny_call(SYS_quotactl_fd);
#endif
#ifdef SYS_clone
    filter.deny_call(SYS_clone);
#endif
#ifdef SYS_clone3
    filter.deny_call(SYS_clone3);
#endif
#ifdef SYS_fork
    filter.deny_call(SYS_fork);
#endif
#ifdef SYS_vfork
    filter.deny_call(SYS_vfork);
#endif

    filter.statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    return filter.install();
}

} // namespace kpb::measurement::runtime_bridge::detail
