#include "privacy_measurement_child_supervisor.hpp"
#include "privacy_measurement_output_abi.hpp"
#include "privacy_measurement_sha256.hpp"

#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <linux/bpf.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef KPB_MEASUREMENT_CHILD_TEST_FAULT
#define KPB_MEASUREMENT_CHILD_TEST_FAULT 0
#endif

using namespace kpb::measurement;
using namespace kpb::measurement::runtime_bridge;

namespace {

bool preexec_self_link_refused{};
bool preexec_overcommit_refused{};

__attribute__((constructor(101))) void probe_preexec_sandbox() {
    char byte{};
    errno = 0;
    preexec_self_link_refused =
        ::readlinkat(AT_FDCWD, "/proc/self/exe", &byte, sizeof(byte)) < 0 &&
        errno == EPERM;
    errno = 0;
    const int fd = ::openat(
        AT_FDCWD, "/proc/sys/vm/overcommit_memory", O_RDONLY | O_CLOEXEC);
    preexec_overcommit_refused = fd < 0 && errno == EPERM;
    if (fd >= 0) (void)::close(fd);
}

bool refused(long result) {
    return result == -1 && (errno == EPERM || errno == EACCES);
}

bool sandbox_is_enforced(const PublicRuntimeChildOffer& offer) {
    bool standard_fds_closed = true;
    for (int fd = 0; fd <= 2; ++fd) {
        struct stat state{};
        errno = 0;
        standard_fds_closed = standard_fds_closed &&
            ::fstat(fd, &state) < 0 && errno == EBADF;
    }
    errno = 0;
    const bool no_open = refused(::open("/etc/passwd", O_RDONLY));
    errno = 0;
    const bool no_openat = refused(::openat(
        AT_FDCWD, "/etc/passwd", O_RDONLY));
    errno = 0;
    const bool no_proc_alias = refused(::open(
        "/proc/self/fd/40", O_RDONLY));
    char link_byte{};
    errno = 0;
    const bool no_readlink = refused(::readlink(
        "/proc/self/fd/40", &link_byte, sizeof(link_byte)));
    errno = 0;
    const bool no_socket = refused(::socket(AF_UNIX, SOCK_STREAM, 0));
    errno = 0;
    const bool no_connect = refused(::syscall(
        SYS_connect, MEASUREMENT_CHILD_FIXED_FD, nullptr, 0));
    errno = 0;
    const bool no_recvfrom = refused(::syscall(
        SYS_recvfrom, MEASUREMENT_CHILD_FIXED_FD, nullptr, 0, 0,
        nullptr, nullptr));
    errno = 0;
    const bool no_sendmmsg = refused(::syscall(
        SYS_sendmmsg, MEASUREMENT_CHILD_FIXED_FD, nullptr, 0, 0));
    errno = 0;
    const bool no_recvmmsg = refused(::syscall(
        SYS_recvmmsg, MEASUREMENT_CHILD_FIXED_FD, nullptr, 0, 0, nullptr));
    errno = 0;
    const bool no_sendfile = refused(::syscall(
        SYS_sendfile, MEASUREMENT_CHILD_FIXED_FD,
        MEASUREMENT_OBSERVER_INPUT_FD, nullptr, 1));
    errno = 0;
    const bool no_splice = refused(::syscall(
        SYS_splice, MEASUREMENT_OBSERVER_INPUT_FD, nullptr,
        MEASUREMENT_CHILD_FIXED_FD, nullptr, 1, 0));
    errno = 0;
    const bool no_vmsplice = refused(::syscall(
        SYS_vmsplice, MEASUREMENT_CHILD_FIXED_FD, nullptr, 0, 0));
    errno = 0;
    const bool no_tee = refused(::syscall(
        SYS_tee, MEASUREMENT_OBSERVER_INPUT_FD,
        MEASUREMENT_CHILD_FIXED_FD, 1, 0));
    errno = 0;
    const bool no_copy_file_range = refused(::syscall(
        SYS_copy_file_range, MEASUREMENT_OBSERVER_INPUT_FD, nullptr,
        MEASUREMENT_CHILD_FIXED_FD, nullptr, 1, 0));
    const unsigned char byte = 0;
    errno = 0;
    const bool no_pwrite = refused(::syscall(
        SYS_pwrite64, MEASUREMENT_CHILD_FIXED_FD, &byte, 1, 0));
    const auto* output_abi = measurement_output_abi(offer.role);
    bool exact_output_surface = true;
    if (output_abi != nullptr) {
        errno = 0;
        const bool wrong_fd = refused(::syscall(
            SYS_pwrite64, MEASUREMENT_CHILD_OUTPUT_FD - 1, nullptr,
            output_abi->exact_bytes, 0));
        errno = 0;
        const bool wrong_count = refused(::syscall(
            SYS_pwrite64, MEASUREMENT_CHILD_OUTPUT_FD, nullptr,
            output_abi->exact_bytes - 1, 0));
        errno = 0;
        const bool wrong_offset = refused(::syscall(
            SYS_pwrite64, MEASUREMENT_CHILD_OUTPUT_FD, nullptr,
            output_abi->exact_bytes, 1));
        exact_output_surface = wrong_fd && wrong_count && wrong_offset;
    } else {
        errno = 0;
        exact_output_surface = refused(::syscall(
            SYS_pwrite64, MEASUREMENT_CHILD_OUTPUT_FD, &byte, 1, 0));
    }
    errno = 0;
    const bool no_ptrace = refused(::ptrace(
        PTRACE_PEEKDATA, ::getppid(), nullptr, nullptr));
    errno = 0;
    const bool no_process_vm = refused(::syscall(
        SYS_process_vm_readv, ::getppid(), nullptr, 0, nullptr, 0, 0));
    errno = 0;
    const bool no_bpf = refused(::syscall(
        SYS_bpf, BPF_MAP_CREATE, nullptr, 0));
    errno = 0;
    const bool no_mount = refused(::mount(
        nullptr, nullptr, nullptr, 0, nullptr));
    errno = 0;
    const pid_t fork_result = ::fork();
    if (fork_result == 0) ::_exit(99);
    if (fork_result > 0) {
        int status = 0;
        while (::waitpid(fork_result, &status, 0) < 0 && errno == EINTR) {}
    }
    const bool no_fork = fork_result < 0 && errno == EPERM;
    bool no_spool_escape = true;
    if (offer.role == RuntimeChildRole::Observer) {
        errno = 0;
        no_spool_escape = refused(::openat(
            MEASUREMENT_OBSERVER_INPUT_FD, "/etc/passwd", O_RDONLY));
    }
    return preexec_self_link_refused && preexec_overcommit_refused &&
           standard_fds_closed && no_open && no_openat && no_proc_alias &&
           no_readlink && no_socket && no_connect && no_recvfrom &&
           no_sendmmsg && no_recvmmsg && no_sendfile && no_splice &&
           no_vmsplice && no_tee && no_copy_file_range && no_pwrite &&
           exact_output_surface &&
           no_ptrace && no_process_vm && no_bpf && no_mount && no_fork &&
           no_spool_escape;
}

class Program final : public MeasurementChildProgram {
public:
    RuntimeChildResult execute(
            const PublicRuntimeChildOffer& offer) override {
        RuntimeChildResult result{};
        if (!sandbox_is_enforced(offer) ||
            KPB_MEASUREMENT_CHILD_TEST_FAULT == 11) {
            result.aggregate_outcome = AggregateOutcome::CandidatePass;
            result.comparison_outcome =
                OwnerComparisonOutcome::NonRegressionPass;
            return result;
        }
        if (offer.role == RuntimeChildRole::Aggregate)
            result.aggregate_outcome = AggregateOutcome::CandidatePass;
        if (offer.role == RuntimeChildRole::OwnerComparison)
            result.comparison_outcome =
                OwnerComparisonOutcome::NonRegressionPass;
        if (measurement_output_abi(offer.role) != nullptr) {
            const auto body = test_only_measurement_output_abi_body(
                offer.role, offer.owner);
            const auto count = ::syscall(
                SYS_pwrite64, MEASUREMENT_CHILD_OUTPUT_FD,
                body.data(), body.size(), 0);
            if (count != static_cast<long>(body.size())) {
                result.aggregate_outcome = AggregateOutcome::CandidatePass;
                return result;
            }
            result.private_output_content_hash =
                kpb::measurement::detail::sha256(body);
        }
        return result;
    }
};

} // namespace

int main() {
    Program program;
    int result = 0;
    if constexpr (KPB_MEASUREMENT_CHILD_TEST_FAULT <= 10 ||
                  KPB_MEASUREMENT_CHILD_TEST_FAULT == 13 ||
                  KPB_MEASUREMENT_CHILD_TEST_FAULT == 14) {
        result = test_only_run_measurement_child(
            program, static_cast<TestChildProtocolFault>(
                KPB_MEASUREMENT_CHILD_TEST_FAULT));
    } else {
        result = run_measurement_child(program);
    }
    if constexpr (KPB_MEASUREMENT_CHILD_TEST_FAULT == 12)
        return result == 0 ? 17 : result;
    return result;
}
