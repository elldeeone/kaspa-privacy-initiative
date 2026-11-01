#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fresh_owner_process_adapter.hpp"
#include "../../private_batch_trial/privacy_fresh_owner_transactional_replay_authority.hpp"
#include "../../private_batch_trial/testnet_accepted_history_authority.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <csignal>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <new>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <set>
#include <stdexcept>
#include <string_view>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::fresh_owner_issuance {
namespace {

using Bytes = std::vector<unsigned char>;

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
FreshOwnerRound1AttemptTestFault round1_attempt_fault{
    FreshOwnerRound1AttemptTestFault::None};
FreshOwnerRound2AttemptTestFault round2_attempt_fault{
    FreshOwnerRound2AttemptTestFault::None};
FreshOwnerOwnerPidfdWaitTestFault owner_pidfd_wait_fault{
    FreshOwnerOwnerPidfdWaitTestFault::None};

void inject_round1_attempt_fault(
        FreshOwnerRound1AttemptTestFault selected) {
    if (round1_attempt_fault == selected) throw std::bad_alloc();
}

void inject_round2_attempt_fault(
        FreshOwnerRound2AttemptTestFault selected) {
    if (round2_attempt_fault == selected) throw std::bad_alloc();
}
#endif

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
bool zero(const Digest& value) { return value == Digest{}; }

void add(Bytes& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add(Bytes& out, const Digest& value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add(Bytes& out, unsigned value) {
    for (unsigned index = 0; index < 4; ++index)
        out.push_back(static_cast<unsigned char>(value >> (8 * index)));
}
void add(Bytes& out, std::uint64_t value) {
    for (unsigned index = 0; index < 8; ++index)
        out.push_back(static_cast<unsigned char>(value >> (8 * index)));
}
Digest hash(const Bytes& value) { return identity_registry::digest(value); }

template<std::size_t Capacity>
class FixedHashInput final {
    std::array<unsigned char, Capacity> bytes_{};
    std::size_t size_{};
public:
    void append(std::span<const unsigned char> value) noexcept {
        if (value.size() > Capacity - size_) std::terminate();
        std::copy(value.begin(), value.end(), bytes_.begin() + size_);
        size_ += value.size();
    }
    void append(std::string_view value) noexcept {
        append(std::span(
            reinterpret_cast<const unsigned char*>(value.data()),
            value.size()));
    }
    void append(const Digest& value) noexcept { append(std::span(value)); }
    void append(unsigned value) noexcept {
        std::array<unsigned char, 4> encoded{};
        for (std::size_t index = 0; index < encoded.size(); ++index)
            encoded[index] = static_cast<unsigned char>(value >> (8 * index));
        append(std::span(encoded));
    }
    Digest digest() const noexcept {
        Digest result{};
        SHA256_CTX context{};
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        const bool complete =
            ::SHA256_Init(&context) == 1 &&
            ::SHA256_Update(&context, bytes_.data(), size_) == 1 &&
            ::SHA256_Final(result.data(), &context) == 1;
#pragma GCC diagnostic pop
        if (!complete)
            std::terminate();
        return result;
    }
};

Digest random_digest() {
    Digest result{};
    std::size_t offset = 0;
    while (offset < result.size()) {
        const auto count = ::getrandom(
            result.data() + offset, result.size() - offset, 0);
        if (count < 0 && errno == EINTR) continue;
        need(count > 0);
        offset += static_cast<std::size_t>(count);
    }
    need(!zero(result));
    return result;
}

enum class WireKind : std::uint32_t {
    Bootstrap = 1,
    BootstrapAck = 2,
    IssueRound = 3,
    RoundResult = 4,
    Stop = 5,
    Abort = 6,
    ReleaseTruth = 7,
    TruthReleased = 8,
};

struct WirePacket {
    std::array<unsigned char, 8> magic{};
    std::uint32_t version{};
    WireKind kind{};
    std::uint32_t owner{};
    std::uint32_t round{};
    Digest supervisor_session{};
    Digest child_session{};
    Digest command_identity{};
    Digest accepted_input_head_identity{};
    Digest history_gate_identity{};
    Digest file_identity{};
    Digest file_metadata_identity{};
    Digest second_file_identity{};
    Digest second_file_metadata_identity{};
    Digest input_lineage_identity{};
    Digest second_input_lineage_identity{};
    Digest truth_endpoint_identity{};
    Digest truth_feeder_session{};
    Digest truth_barrier_identity{};
    std::array<Digest, 2> truth_financial_runs{};
    std::array<Digest, 2> truth_capture_plans{};
    std::array<Digest, 2> truth_projections{};
    std::array<Digest, 2> truth_contexts{};
    LogicalOwnerIdentity logical_owner_identity{};
    Digest binding_nonce{};
    std::array<unsigned char, 64> verifier_record{};
    Digest packet_identity{};
};

static_assert(std::is_trivially_copyable_v<WirePacket>);

Digest wire_identity(const WirePacket& packet) noexcept {
    FixedHashInput<1024> bytes;
    bytes.append("KPB_FRESH_OWNER_PROCESS_PACKET_V1\n");
    bytes.append(static_cast<unsigned>(packet.kind));
    bytes.append(packet.owner);
    bytes.append(packet.round);
    for (const auto* value : {
             &packet.supervisor_session, &packet.child_session,
             &packet.command_identity,
             &packet.accepted_input_head_identity,
             &packet.history_gate_identity, &packet.file_identity,
             &packet.file_metadata_identity,
             &packet.second_file_identity,
             &packet.second_file_metadata_identity,
             &packet.input_lineage_identity,
             &packet.second_input_lineage_identity,
             &packet.truth_endpoint_identity,
             &packet.truth_feeder_session,
             &packet.truth_barrier_identity,
             &packet.logical_owner_identity, &packet.binding_nonce})
        bytes.append(*value);
    for (const auto* values : {
             &packet.truth_financial_runs, &packet.truth_capture_plans,
             &packet.truth_projections, &packet.truth_contexts})
        for (const auto& value : *values) bytes.append(value);
    bytes.append(std::span(packet.verifier_record));
    return bytes.digest();
}

WirePacket packet(
        WireKind kind, unsigned owner, unsigned round,
        const Digest& supervisor, const Digest& child,
        const Digest& command = {}) {
    WirePacket result{};
    result.magic = {'K', 'P', 'B', 'O', 'W', 'N', 'R', '1'};
    result.version = 1;
    result.kind = kind;
    result.owner = owner;
    result.round = round;
    result.supervisor_session = supervisor;
    result.child_session = child;
    result.command_identity = command;
    result.packet_identity = wire_identity(result);
    return result;
}

void finish_packet(WirePacket& value) {
    value.packet_identity = {};
    value.packet_identity = wire_identity(value);
}

void set_passcred(int fd) {
    const int one = 1;
    need(::setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) == 0);
}

void send_packet(int fd, const WirePacket& value) {
    std::array<unsigned char, CMSG_SPACE(sizeof(struct ucred))> control{};
    struct iovec iov{
        .iov_base = const_cast<WirePacket*>(&value),
        .iov_len = sizeof(value),
    };
    struct msghdr message{};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    auto* header = CMSG_FIRSTHDR(&message);
    need(header != nullptr);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_CREDENTIALS;
    header->cmsg_len = CMSG_LEN(sizeof(struct ucred));
    const struct ucred credentials{
        .pid = ::getpid(), .uid = ::getuid(), .gid = ::getgid()};
    std::memcpy(CMSG_DATA(header), &credentials, sizeof(credentials));
    message.msg_controllen = header->cmsg_len;
    ssize_t sent;
    do { sent = ::sendmsg(fd, &message, MSG_NOSIGNAL); }
    while (sent < 0 && errno == EINTR);
    need(sent == static_cast<ssize_t>(sizeof(value)));
}

WirePacket receive_packet(int fd, pid_t expected_pid) {
    WirePacket result{};
    std::array<unsigned char, CMSG_SPACE(sizeof(struct ucred))> control{};
    struct iovec iov{.iov_base = &result, .iov_len = sizeof(result)};
    struct msghdr message{};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t received;
    do { received = ::recvmsg(fd, &message, MSG_CMSG_CLOEXEC); }
    while (received < 0 && errno == EINTR);
    need(received == static_cast<ssize_t>(sizeof(result)) &&
         (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0);
    const struct ucred* credentials = nullptr;
    unsigned credential_count = 0;
    for (auto* header = CMSG_FIRSTHDR(&message); header != nullptr;
         header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level == SOL_SOCKET &&
            header->cmsg_type == SCM_CREDENTIALS &&
            header->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {
            credentials = reinterpret_cast<const struct ucred*>(
                CMSG_DATA(header));
            ++credential_count;
        }
    }
    need(credential_count == 1 && credentials != nullptr &&
         credentials->pid == expected_pid &&
         credentials->uid == ::getuid() && credentials->gid == ::getgid() &&
         result.magic ==
             std::array<unsigned char, 8>{'K','P','B','O','W','N','R','1'} &&
         result.version == 1 &&
         result.packet_identity == wire_identity(result));
    return result;
}

void close_fd(int& fd) noexcept {
    if (fd >= 0) (void)::close(fd);
    fd = -1;
}

void require_owner_fork_environment() {
    struct sigaction child_action{};
    need(::sigaction(SIGCHLD, nullptr, &child_action) == 0 &&
         child_action.sa_handler == SIG_DFL &&
         (child_action.sa_flags & SA_NOCLDWAIT) == 0);
    DIR* tasks = ::opendir("/proc/self/task");
    need(tasks != nullptr);
    unsigned task_count = 0;
    errno = 0;
    while (const auto* entry = ::readdir(tasks)) {
        const unsigned char first =
            static_cast<unsigned char>(entry->d_name[0]);
        if (first >= static_cast<unsigned char>('0') &&
            first <= static_cast<unsigned char>('9'))
            ++task_count;
    }
    const int read_errno = errno;
    const int close_result = ::closedir(tasks);
    need(read_errno == 0 && close_result == 0 && task_count == 1);
}

int open_owner_pidfd(pid_t pid) {
#ifdef SYS_pidfd_open
    int result;
    do {
        result = static_cast<int>(::syscall(SYS_pidfd_open, pid, 0));
    } while (result < 0 && errno == EINTR);
    need(result >= 0);
    const int flags = ::fcntl(result, F_GETFD);
    if (flags < 0 || (flags & FD_CLOEXEC) == 0) {
        close_fd(result);
        refuse();
    }
    return result;
#else
    (void)pid;
    refuse();
#endif
}

bool signal_owner_pidfd(int pidfd, int signal) noexcept {
#ifdef SYS_pidfd_send_signal
    if (pidfd < 0) return false;
    long result;
    do {
        result = ::syscall(
            SYS_pidfd_send_signal, pidfd, signal, nullptr, 0);
    } while (result < 0 && errno == EINTR);
    return result == 0 || (result < 0 && errno == ESRCH);
#else
    (void)pidfd;
    (void)signal;
    return false;
#endif
}

bool settle_owner_pidfd(
        int& pidfd, pid_t& pid, int& exit_code, int& term_signal)
        noexcept {
    if (pidfd < 0 || pid <= 1) return false;
    siginfo_t information{};
    int result;
    do {
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
        if (owner_pidfd_wait_fault ==
            FreshOwnerOwnerPidfdWaitTestFault::FirstInterrupted) {
            owner_pidfd_wait_fault =
                FreshOwnerOwnerPidfdWaitTestFault::None;
            errno = EINTR;
            result = -1;
        } else if (owner_pidfd_wait_fault ==
                   FreshOwnerOwnerPidfdWaitTestFault::
                       PersistentChildUnavailable) {
            errno = ECHILD;
            result = -1;
        } else
#endif
        result = ::waitid(
            P_PIDFD, static_cast<id_t>(pidfd), &information, WEXITED);
    } while (result < 0 && errno == EINTR);
    if (result != 0 || information.si_pid != pid) return false;
    if (information.si_code == CLD_EXITED) {
        exit_code = information.si_status;
        term_signal = 0;
    } else if (information.si_code == CLD_KILLED ||
               information.si_code == CLD_DUMPED) {
        exit_code = -1;
        term_signal = information.si_status;
    } else {
        return false;
    }
    close_fd(pidfd);
    pid = -1;
    return true;
}

void close_unrelated_child_fds(bool keep_truth) {
#ifdef SYS_close_range
    const long first = ::syscall(
        SYS_close_range, 3U,
        static_cast<unsigned>(FRESH_OWNER_FIXED_CONTROL_FD - 1), 0U);
    if (first == 0) {
        const long middle = keep_truth ? ::syscall(
            SYS_close_range,
            static_cast<unsigned>(FRESH_OWNER_FIXED_ROOT_FD + 1),
            static_cast<unsigned>(FRESH_OWNER_FIXED_TRUTH_FD - 1), 0U) : 0;
        const long second = ::syscall(
            SYS_close_range,
            static_cast<unsigned>(keep_truth
                ? FRESH_OWNER_FIXED_TRUTH_FD + 1
                : FRESH_OWNER_FIXED_ROOT_FD + 1), UINT_MAX, 0U);
        if (middle == 0 && second == 0) return;
    }
#endif
    const long raw_limit = ::sysconf(_SC_OPEN_MAX);
    const int limit = raw_limit > 0 && raw_limit < INT_MAX
        ? static_cast<int>(raw_limit) : 65536;
    for (int fd = 3; fd < limit; ++fd)
        if (fd != FRESH_OWNER_FIXED_CONTROL_FD &&
            fd != FRESH_OWNER_FIXED_ROOT_FD &&
            !(keep_truth && fd == FRESH_OWNER_FIXED_TRUTH_FD))
            (void)::close(fd);
}

Digest command_identity(
        const Digest& supervisor, const Digest& child,
        unsigned owner, unsigned round,
        const Digest& head, const Digest& history) noexcept {
    FixedHashInput<256> bytes;
    bytes.append("KPB_FRESH_OWNER_PROCESS_COMMAND_V1\n");
    bytes.append(supervisor); bytes.append(child);
    bytes.append(owner); bytes.append(round);
    bytes.append(head); bytes.append(history);
    return bytes.digest();
}

Digest process_identity(
        const PublicFreshOwnerProcessPlan& plan,
        unsigned owner, pid_t parent, pid_t child,
        const Digest& child_session, const Digest& root_metadata) {
    Bytes bytes;
    add(bytes, "KPB_FRESH_OWNER_PROCESS_IDENTITY_V1\n");
    add(bytes, plan.process_authority_identity);
    add(bytes, plan.owner_issuer_source_identity);
    add(bytes, plan.owner_issuer_build_identity);
    add(bytes, plan.owner_runtime_identity);
    add(bytes, owner);
    add(bytes, static_cast<std::uint64_t>(parent));
    add(bytes, static_cast<std::uint64_t>(child));
    add(bytes, child_session); add(bytes, root_metadata);
    return hash(bytes);
}

Digest continuation_identity(
        const PublicFreshOwnerProcessLaunch& launch,
        std::span<const PublicOwnerIssuanceReceipt, 3> owners) {
    Bytes bytes;
    add(bytes, "KPB_OWNER_PROCESS_ROUND1_CONTINUATION_V1\n");
    add(bytes, launch.supervisor_session_identity);
    for (const auto& owner : owners) {
        add(bytes, owner.owner_process_identity);
        add(bytes, owner.rounds[0].file_identity);
    }
    return hash(bytes);
}

Digest truth_feeder_exit_identity(
        const Digest& supervisor, const Digest& child_session,
        const Digest& endpoint, std::int64_t pid) {
    Bytes bytes;
    add(bytes, "KPB_CANDIDATE_OWNER_TRUTH_FEEDER_EXIT_V1\n");
    add(bytes, supervisor); add(bytes, child_session); add(bytes, endpoint);
    add(bytes, static_cast<std::uint64_t>(pid));
    add(bytes, static_cast<unsigned>(0));
    return hash(bytes);
}

Digest owner_contract_identity(const OwnerInputContract& contract) {
    const auto canonical =
        std::string("KPB_FRESH_OWNER_CONTRACT_METADATA_V1\n") +
        contract.run_nonce + "\n" + contract.model_identity + "\n" +
        contract.source_identity + "\n" + contract.proving_key_identity +
        "\n" + contract.verifying_key_identity + "\n" +
        contract.trace_identity + "\n" + contract.layout_identity + "\n" +
        contract.cohort_identity + "\n" +
        std::to_string(contract.owner_id) + "\n" +
        std::to_string(contract.input_count) + "\n" +
        contract.server_certificate_sha256[0] + "\n" +
        contract.server_certificate_sha256[1] + "\n" +
        contract.server_certificate_sha256[2] + "\n" +
        contract.owner_certificate_sha256 + "\n";
    return identity_registry::digest(std::span(
        reinterpret_cast<const unsigned char*>(canonical.data()),
        canonical.size()));
}

Digest checked_identity_hex(const std::string& value) {
    Digest result{};
    try {
        result = identity_registry::unhex(value);
    } catch (...) {
        refuse();
    }
    need(identity_registry::hex(result) == value && !zero(result));
    return result;
}

template<class Evidence>
void require_private_arm_evidence(const Evidence& value) {
    using registered_driver::CaptureClassification;
    need(value.classification == CaptureClassification::HiddenCandidate ||
         value.classification ==
             CaptureClassification::ExplicitOwnerPublicEffectsBaseline);
    need(!zero(value.process_authority_identity) &&
         !zero(value.supervisor_session_identity));
    std::set<std::int64_t> pids;
    std::set<Digest> sessions, logical_ids, contracts;
    std::set<std::pair<std::uint64_t, std::uint64_t>> roots;
    for (unsigned owner = 0; owner < 3; ++owner) {
        need(value.child_pids[owner] > 1 &&
             pids.insert(value.child_pids[owner]).second &&
             !zero(value.child_sessions[owner]) &&
             sessions.insert(value.child_sessions[owner]).second &&
             value.root_slots[owner][0] != 0 &&
             value.root_slots[owner][1] != 0 &&
             roots.emplace(value.root_slots[owner][0],
                           value.root_slots[owner][1]).second &&
             !zero(value.logical_owner_ids[owner]) &&
             logical_ids.insert(value.logical_owner_ids[owner]).second);
    }
    std::set<Digest> owner_certificates, owner_spkis;
    std::set<Digest> server_certificates, server_spkis;
    for (unsigned slot = 0; slot < 6; ++slot) {
        need(!zero(value.contract_ids[slot]) &&
             contracts.insert(value.contract_ids[slot]).second &&
             !zero(value.owner_tls_cert_ids[slot]) &&
             owner_certificates.insert(
                 value.owner_tls_cert_ids[slot]).second &&
             !zero(value.owner_tls_spki_ids[slot]) &&
             owner_spkis.insert(value.owner_tls_spki_ids[slot]).second);
        std::set<Digest> slot_certificates, slot_spkis;
        for (unsigned role = 0; role < 3; ++role) {
            need(!zero(value.server_tls_cert_ids[slot][role]) &&
                 slot_certificates.insert(
                     value.server_tls_cert_ids[slot][role]).second &&
                 !zero(value.server_tls_spki_ids[slot][role]) &&
                 slot_spkis.insert(
                     value.server_tls_spki_ids[slot][role]).second);
            server_certificates.insert(
                value.server_tls_cert_ids[slot][role]);
            server_spkis.insert(value.server_tls_spki_ids[slot][role]);
        }
    }
    need(owner_certificates.size() == 6 && owner_spkis.size() == 6 &&
         server_certificates.size() == 6 && server_spkis.size() == 6);
}

void require_plan(const PublicFreshOwnerProcessPlan& plan) {
    using registered_driver::CaptureClassification;
    need(plan.classification == CaptureClassification::HiddenCandidate ||
         plan.classification ==
             CaptureClassification::ExplicitOwnerPublicEffectsBaseline);
    for (const auto* value : {
             &plan.process_authority_identity, &plan.registration_identity,
             &plan.service_identity, &plan.controller_source_identity,
             &plan.controller_build_identity,
             &plan.owner_issuer_source_identity,
             &plan.owner_issuer_build_identity, &plan.owner_runtime_identity,
             &plan.run, &plan.trial, &plan.root_identity})
        need(!zero(*value) &&
             *value != identity_registry::mandatory_aborted_run() &&
             *value != mandatory_consumed_owner_root_identity());
    if (plan.classification ==
        CaptureClassification::ExplicitOwnerPublicEffectsBaseline) {
        need(!zero(plan.baseline_policy_identity) &&
             !zero(plan.roster_authority_identity) &&
             zero(plan.measurement_run_binding_identity) &&
             zero(plan.candidate_truth_financial_runs[0]) &&
             zero(plan.candidate_truth_financial_runs[1]) &&
             zero(plan.candidate_truth_capture_plan_identities[0]) &&
             zero(plan.candidate_truth_capture_plan_identities[1]) &&
             zero(plan.candidate_truth_projection_identities[0]) &&
             zero(plan.candidate_truth_projection_identities[1]) &&
             zero(plan.candidate_truth_context_identities[0]) &&
             zero(plan.candidate_truth_context_identities[1]));
    } else {
        need(zero(plan.baseline_policy_identity) &&
             zero(plan.roster_authority_identity) &&
             !zero(plan.measurement_run_binding_identity));
        for (const auto* values : {
                 &plan.candidate_truth_financial_runs,
                 &plan.candidate_truth_capture_plan_identities,
                 &plan.candidate_truth_projection_identities,
                 &plan.candidate_truth_context_identities})
            need(!zero((*values)[0]) && !zero((*values)[1]) &&
                 (*values)[0] != (*values)[1]);
    }

    std::set<std::string> certificates;
    std::set<Digest> spkis;
    for (unsigned owner = 0; owner < 3; ++owner) {
        const auto& selected = plan.owners[owner];
        need(selected.owner_component == owner);
        for (unsigned index = 0; index < 2; ++index) {
            const auto& round = selected.rounds[index];
            need(round.round == index + 1 &&
                 round.contract.owner_id == static_cast<int>(owner) &&
                 round.contract.run_nonce ==
                     identity_registry::hex(round.attempt) &&
                 round.contract.cohort_identity ==
                     identity_registry::hex(round.cohort) &&
                 round.contract.input_count == 2'635'409 &&
                 round.file_bytes == OWNER_PRIVATE_INPUT_V2_BYTES &&
                 zero(round.file_identity) &&
                 zero(round.file_metadata_identity) &&
                 !zero(round.attempt) && !zero(round.cohort) &&
                 !zero(round.owner_tls_spki_identity));
            if (index == 0)
                need(!zero(round.accepted_input_head_identity) &&
                     !zero(round.history_gate_identity));
            else
                need(!zero(round.accepted_input_head_identity) &&
                     !zero(round.history_gate_identity));
            need(certificates.insert(
                     round.contract.owner_certificate_sha256).second &&
                 spkis.insert(round.owner_tls_spki_identity).second);
            for (const auto& value : round.server_tls_spki_identities)
                need(!zero(value));
            if (owner != 0) {
                need(round.attempt == plan.owners[0].rounds[index].attempt &&
                     round.cohort == plan.owners[0].rounds[index].cohort &&
                     round.accepted_input_head_identity ==
                         plan.owners[0].rounds[index]
                             .accepted_input_head_identity &&
                     round.history_gate_identity ==
                         plan.owners[0].rounds[index]
                             .history_gate_identity &&
                     round.contract.server_certificate_sha256 ==
                         plan.owners[0].rounds[index]
                             .contract.server_certificate_sha256 &&
                     round.server_tls_spki_identities ==
                         plan.owners[0].rounds[index]
                             .server_tls_spki_identities);
            }
        }
    }
    need(plan.owners[0].rounds[0].attempt !=
             plan.owners[0].rounds[1].attempt &&
         plan.owners[0].rounds[0].cohort !=
             plan.owners[0].rounds[1].cohort);
    for (unsigned round = 0; round < 2; ++round) {
        for (const auto& value :
             plan.owners[0].rounds[round]
                 .contract.server_certificate_sha256)
            need(certificates.insert(value).second);
        for (const auto& value :
             plan.owners[0].rounds[round].server_tls_spki_identities)
            need(spkis.insert(value).second);
    }
    need(certificates.size() == 12 && spkis.size() == 12);
}

void require_private_lineages(const std::array<Digest, 3>& values) {
    need(std::ranges::none_of(values, zero) &&
         std::set<Digest>(values.begin(), values.end()).size() ==
             values.size());
}

void require_candidate_truth(const PrivateOwnerCandidateRoundTruth& value) {
    need(!zero(value.actual_public_nullifier) &&
         !zero(value.created_row_sha256s[0]) &&
         !zero(value.created_row_sha256s[1]) &&
         value.created_row_sha256s[0] != value.created_row_sha256s[1] &&
         !zero(value.created_commitments[0]) &&
         !zero(value.created_commitments[1]) &&
         value.created_commitments[0] != value.created_commitments[1]);
}

template<std::size_t N>
void truth_put(std::array<unsigned char, N>& out, std::size_t& at,
               std::span<const unsigned char> value) {
    need(at <= out.size() && value.size() <= out.size() - at);
    std::copy(value.begin(), value.end(), out.begin() +
              static_cast<std::ptrdiff_t>(at));
    at += value.size();
}

template<std::size_t N>
void truth_byte(std::array<unsigned char, N>& out, std::size_t& at,
                unsigned value) {
    need(value <= 255 && at < out.size());
    out[at++] = static_cast<unsigned char>(value);
}

void emit_candidate_truth(
        int fd, unsigned owner, const Digest& trial,
        const PublicOwnerProcessSelection& selected,
        const std::array<PrivateOwnerCandidateRoundTruth, 2>& truths,
        const WirePacket& release) {
    using namespace candidate_truth_schema;
    static_assert(static_cast<unsigned>(
        registered_driver::CaptureClassification::HiddenCandidate) ==
        HIDDEN_CANDIDATE_CLASSIFICATION);
    std::array<unsigned char, PACKET_BYTES> packet_bytes{};
    std::size_t at = 0;
    truth_put(packet_bytes, at, MAGIC);
    truth_byte(packet_bytes, at, VERSION);
    truth_byte(packet_bytes, at, HIDDEN_CANDIDATE_CLASSIFICATION);
    truth_byte(packet_bytes, at, owner);
    truth_put(packet_bytes, at, release.truth_endpoint_identity);
    truth_put(packet_bytes, at, release.truth_feeder_session);
    truth_put(packet_bytes, at, trial);
    for (unsigned index = 0; index < 2; ++index) {
        const auto& round = selected.rounds[index];
        const auto& truth = truths[index];
        truth_byte(packet_bytes, at, index + 1);
        for (const auto* value : {
                 &release.truth_financial_runs[index], &round.attempt,
                 &round.cohort, &release.truth_capture_plans[index],
                 &release.truth_projections[index],
                 &release.truth_contexts[index],
                 &truth.actual_public_nullifier,
                 &truth.created_row_sha256s[0],
                 &truth.created_row_sha256s[1],
                 &truth.created_commitments[0],
                 &truth.created_commitments[1]})
            truth_put(packet_bytes, at, *value);
    }
    need(at == packet_bytes.size());
    ssize_t sent;
    do {
        sent = ::send(fd, packet_bytes.data(), packet_bytes.size(),
                      MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    OPENSSL_cleanse(packet_bytes.data(), packet_bytes.size());
    need(sent == static_cast<ssize_t>(packet_bytes.size()));
}

int child_main(
        unsigned owner, int control_fd, int root_fd, int truth_fd,
        std::uint64_t expected_root_device,
        std::uint64_t expected_root_inode,
        pid_t parent_pid, const Digest& supervisor_session,
        const Digest& child_session, const Digest& trial,
        registered_driver::CaptureClassification classification,
        PublicOwnerProcessSelection selected,
        const std::shared_ptr<PrivateLifecycleOwnerChildProgram>& program) {
    std::array<PrivateOwnerCandidateRoundTruth, 2> truths{};
    try {
        // Copy both inherited sources above the fixed targets before either
        // target is replaced. Otherwise a root inherited on fd 39 (or a
        // control socket on fd 40) can be destroyed by the first dup3.
        const int safe_control = ::fcntl(
            control_fd, F_DUPFD_CLOEXEC, FRESH_OWNER_FIXED_TRUTH_FD + 1);
        need(safe_control > FRESH_OWNER_FIXED_TRUTH_FD);
        const int safe_root = ::fcntl(
            root_fd, F_DUPFD_CLOEXEC, FRESH_OWNER_FIXED_TRUTH_FD + 1);
        if (safe_root <= FRESH_OWNER_FIXED_TRUTH_FD) {
            (void)::close(safe_control);
            refuse();
        }
        const bool candidate = classification ==
            registered_driver::CaptureClassification::HiddenCandidate;
        int safe_truth = -1;
        if (candidate) {
            safe_truth = ::fcntl(
                truth_fd, F_DUPFD_CLOEXEC, FRESH_OWNER_FIXED_TRUTH_FD + 1);
            need(safe_truth > FRESH_OWNER_FIXED_TRUTH_FD);
        } else {
            need(truth_fd < 0);
        }
        need(::dup3(safe_control, FRESH_OWNER_FIXED_CONTROL_FD, O_CLOEXEC) ==
                 FRESH_OWNER_FIXED_CONTROL_FD &&
             ::dup3(safe_root, FRESH_OWNER_FIXED_ROOT_FD, O_CLOEXEC) ==
                 FRESH_OWNER_FIXED_ROOT_FD &&
             (!candidate ||
              ::dup3(safe_truth, FRESH_OWNER_FIXED_TRUTH_FD, O_CLOEXEC) ==
                  FRESH_OWNER_FIXED_TRUTH_FD));
        (void)::close(safe_control);
        (void)::close(safe_root);
        if (safe_truth >= 0) (void)::close(safe_truth);
        close_unrelated_child_fds(candidate);
        struct stat root_info{};
        struct stat control_info{};
        int socket_type = 0;
        socklen_t socket_type_bytes = sizeof(socket_type);
        need(::fstat(FRESH_OWNER_FIXED_ROOT_FD, &root_info) == 0 &&
             S_ISDIR(root_info.st_mode) &&
             static_cast<std::uint64_t>(root_info.st_dev) ==
                 expected_root_device &&
             static_cast<std::uint64_t>(root_info.st_ino) ==
                 expected_root_inode &&
             ::fstat(FRESH_OWNER_FIXED_CONTROL_FD, &control_info) == 0 &&
             S_ISSOCK(control_info.st_mode) &&
             ::getsockopt(FRESH_OWNER_FIXED_CONTROL_FD, SOL_SOCKET, SO_TYPE,
                          &socket_type, &socket_type_bytes) == 0 &&
             socket_type_bytes == sizeof(socket_type) &&
             socket_type == SOCK_SEQPACKET);
        if (candidate) {
            struct stat truth_info{};
            int truth_type = 0;
            socklen_t truth_type_bytes = sizeof(truth_type);
            need(::fstat(FRESH_OWNER_FIXED_TRUTH_FD, &truth_info) == 0 &&
                 S_ISSOCK(truth_info.st_mode) &&
                 ::getsockopt(FRESH_OWNER_FIXED_TRUTH_FD, SOL_SOCKET, SO_TYPE,
                              &truth_type, &truth_type_bytes) == 0 &&
                 truth_type_bytes == sizeof(truth_type) &&
                 truth_type == SOCK_SEQPACKET);
        }
        set_passcred(FRESH_OWNER_FIXED_CONTROL_FD);

        const auto bootstrap = receive_packet(
            FRESH_OWNER_FIXED_CONTROL_FD, parent_pid);
        need(bootstrap.kind == WireKind::Bootstrap &&
             bootstrap.owner == owner && bootstrap.round == 0 &&
             bootstrap.supervisor_session == supervisor_session &&
             bootstrap.child_session == child_session);
        const auto identity = program->owner_identity(owner);
        auto acknowledgment = packet(
            WireKind::BootstrapAck, owner, 0,
            supervisor_session, child_session);
        acknowledgment.logical_owner_identity =
            identity.logical_owner_identity;
        acknowledgment.binding_nonce = identity.binding_nonce;
        acknowledgment.file_identity = identity.file_identities[0];
        acknowledgment.file_metadata_identity =
            identity.file_metadata_identities[0];
        acknowledgment.second_file_identity = identity.file_identities[1];
        acknowledgment.second_file_metadata_identity =
            identity.file_metadata_identities[1];
        acknowledgment.input_lineage_identity =
            identity.input_lineage_identities[0];
        acknowledgment.second_input_lineage_identity =
            identity.input_lineage_identities[1];
        acknowledgment.verifier_record = identity.verifier_record;
        finish_packet(acknowledgment);
        send_packet(FRESH_OWNER_FIXED_CONTROL_FD, acknowledgment);

        bool round1 = false;
        bool round2 = false;
        bool truth_released = false;
        while (true) {
            const auto command = receive_packet(
                FRESH_OWNER_FIXED_CONTROL_FD, parent_pid);
            need(command.owner == owner &&
                 command.supervisor_session == supervisor_session &&
                 command.child_session == child_session);
            if (command.kind == WireKind::Abort) {
                OPENSSL_cleanse(truths.data(), sizeof(truths));
                return 111;
            }
            if (command.kind == WireKind::Stop) {
                need(round1 && round2 && command.round == 0 &&
                     (truth_released || !candidate));
                OPENSSL_cleanse(truths.data(), sizeof(truths));
                return program->exit_code_after_round2(owner);
            }
            if (command.kind == WireKind::ReleaseTruth) {
                need(candidate && round1 && round2 && !truth_released &&
                     command.round == 0 &&
                     !zero(command.truth_endpoint_identity) &&
                     !zero(command.truth_feeder_session) &&
                     !zero(command.truth_barrier_identity));
                for (const auto* values : {
                         &command.truth_financial_runs,
                         &command.truth_capture_plans,
                         &command.truth_projections,
                         &command.truth_contexts})
                    need((*values)[0] != (*values)[1] &&
                         !zero((*values)[0]) && !zero((*values)[1]));
                emit_candidate_truth(
                    FRESH_OWNER_FIXED_TRUTH_FD, owner,
                    trial, selected, truths, command);
                truth_released = true;
                auto acknowledgment = command;
                acknowledgment.kind = WireKind::TruthReleased;
                finish_packet(acknowledgment);
                send_packet(FRESH_OWNER_FIXED_CONTROL_FD, acknowledgment);
                continue;
            }
            need(command.kind == WireKind::IssueRound &&
                 (command.round == 1 || command.round == 2));
            const unsigned index = command.round - 1;
            auto round = selected.rounds[index];
            need(command.command_identity == command_identity(
                     supervisor_session, child_session, owner,
                     command.round,
                     command.accepted_input_head_identity,
                     command.history_gate_identity));
            if (command.round == 1) {
                need(!round1 && !round2 &&
                     command.accepted_input_head_identity ==
                         round.accepted_input_head_identity &&
                     command.history_gate_identity ==
                         round.history_gate_identity);
                round1 = true;
            } else {
                need(round1 && !round2 &&
                     !zero(command.accepted_input_head_identity) &&
                     !zero(command.history_gate_identity));
                round.accepted_input_head_identity =
                    command.accepted_input_head_identity;
                round.history_gate_identity = command.history_gate_identity;
                round2 = true;
            }
            const auto result = program->issue_round(
                owner, command.round, FRESH_OWNER_FIXED_ROOT_FD, round);
            if (candidate) {
                require_candidate_truth(result.candidate_truth);
                truths[index] = result.candidate_truth;
            } else {
                need(result.candidate_truth ==
                     PrivateOwnerCandidateRoundTruth{});
            }
            auto response = packet(
                WireKind::RoundResult, owner, command.round,
                supervisor_session, child_session,
                command.command_identity);
            response.accepted_input_head_identity =
                round.accepted_input_head_identity;
            response.history_gate_identity = round.history_gate_identity;
            response.file_identity = result.file_identity;
            response.file_metadata_identity = result.file_metadata_identity;
            response.input_lineage_identity = result.input_lineage_identity;
            response.logical_owner_identity = result.logical_owner_identity;
            response.binding_nonce = result.binding_nonce;
            response.verifier_record = result.verifier_record;
            finish_packet(response);
            send_packet(FRESH_OWNER_FIXED_CONTROL_FD, response);
        }
    } catch (...) {
        OPENSSL_cleanse(truths.data(), sizeof(truths));
        return 120;
    }
}

} // namespace

struct PrivateFreshOwnerContinuityRecord {
    registered_driver::CaptureClassification classification{};
    unsigned round{};
    Digest run{}, trial{}, attempt{}, cohort{};
    Digest root_identity{};
    Digest supervisor_session{}, arm_isolation_identity{};
    Digest round_issuance_identity{};
    std::array<std::int64_t, 3> child_pids{};
    std::array<Digest, 3> child_sessions{};
    std::array<std::pair<std::uint64_t, std::uint64_t>, 3> root_objects{};
    std::array<LogicalOwnerIdentity, 3> logical_owner_ids{};
    std::array<Digest, 3> input_lineages{};
    std::array<Digest, 3> file_identities{};
    std::array<Digest, 3> file_metadata_identities{};
    std::array<Digest, 3> contract_identities{};
};

struct FreshOwnerRoundContinuityAuthority::Storage {
    PrivateFreshOwnerContinuityRecord record;
};

struct FreshOwnerSameRoundRetryAuthority::Storage {
    PrivateFreshOwnerContinuityRecord record;
};

struct FreshOwnerProcessSupervisor::Storage {
    PublicFreshOwnerProcessPlan plan;
    std::shared_ptr<PrivateLifecycleOwnerChildProgram> program;
    PublicFreshOwnerProcessLaunch launch;
    PublicFreshOwnerProcessCompletion completion;
    std::array<int, 3> channels{{-1, -1, -1}};
    // Hidden-candidate receiver ends. They remain opaque in the parent and
    // move directly into the post-barrier endpoint capabilities.
    std::array<int, 3> truth_channels{{-1, -1, -1}};
    std::array<pid_t, 3> pids{{-1, -1, -1}};
    std::array<int, 3> pidfds{{-1, -1, -1}};
    std::array<PublicOwnerIssuanceReceipt, 3> receipts{};
    std::array<PrivateOwnerChildRoundResult, 3> round1_results{};
    std::array<std::array<Digest, 2>, 3> input_lineages{};
    std::array<std::pair<std::uint64_t, std::uint64_t>, 3> root_objects{};
    std::array<LogicalOwnerIdentity, 3> logical_owner_ids{};
    std::array<std::shared_ptr<const LongLivedOwnerProofVerifier>, 3>
        verifiers{};
    std::optional<FreshOwnerTransactionalIssuanceOutcomeAuthority>
        transactional_issuance;
    std::optional<FreshOwnerTrialIssuanceAuthority> reserved_trial;
    std::optional<FreshOwnerRoundAuthority> reserved_round1_driver;
    std::optional<FreshOwnerRoundAuthority> reserved_round2;
    std::optional<BaselineOwnerRosterAuthority> reserved_roster;
    std::optional<FreshOwnerPersistentActivationAuthority>
        reserved_persistent_activation;
    std::optional<FreshOwnerProducerClosureAuthority>
        reserved_producer_closure;
    Digest continuation{};
    Digest arm_isolation_identity{};
    bool round1_issued{};
    bool round2_issued{};
    bool truth_released{};
    bool private_arm_launch_taken{};
    bool round1_transaction_committed{};
    bool completed{};
    bool poisoned{};
    std::array<bool, 3> termination_wait_observed{};
    std::array<int, 3> termination_exit_codes{{-1, -1, -1}};
    std::array<int, 3> termination_signals{};

    PrivateFreshOwnerContinuityRecord continuity_record(
            unsigned round, const Digest& issuance_identity) const {
        need(round == 1 || round == 2);
        const unsigned index = round - 1;
        PrivateFreshOwnerContinuityRecord result{
            .classification = plan.classification,
            .round = round,
            .run = plan.run,
            .trial = plan.trial,
            .attempt = receipts[0].rounds[index].attempt,
            .cohort = receipts[0].rounds[index].cohort,
            .root_identity = plan.root_identity,
            .supervisor_session = launch.supervisor_session_identity,
            .arm_isolation_identity = arm_isolation_identity,
            .round_issuance_identity = issuance_identity,
            .root_objects = root_objects,
            .logical_owner_ids = logical_owner_ids,
        };
        for (unsigned owner = 0; owner < 3; ++owner) {
            result.child_pids[owner] = launch.children[owner].child_pid;
            result.child_sessions[owner] =
                launch.children[owner].child_session_identity;
            result.input_lineages[owner] = input_lineages[owner][index];
            result.file_identities[owner] =
                receipts[owner].rounds[index].file_identity;
            result.file_metadata_identities[owner] =
                receipts[owner].rounds[index].file_metadata_identity;
            result.contract_identities[owner] = owner_contract_identity(
                receipts[owner].rounds[index].contract);
        }
        return result;
    }

    void terminate() noexcept {
        if (completed) return;
        std::array<bool, 3> may_settle{};
        for (unsigned owner = 0; owner < 3; ++owner) {
            if (channels[owner] >= 0) {
                try {
                    send_packet(channels[owner], packet(
                        WireKind::Abort, owner, 0,
                        launch.supervisor_session_identity,
                        launch.children[owner].child_session_identity));
                } catch (...) {}
            }
        }
        for (unsigned owner = 0; owner < pids.size(); ++owner) {
            if (pidfds[owner] >= 0)
                may_settle[owner] =
                    signal_owner_pidfd(pidfds[owner], SIGKILL);
            else if (pids[owner] > 1) {
                (void)::kill(pids[owner], SIGKILL);
                may_settle[owner] = true;
            }
        }
        for (unsigned owner = 0; owner < pids.size(); ++owner) {
            auto& pid = pids[owner];
            if (pidfds[owner] >= 0 && may_settle[owner]) {
                if (settle_owner_pidfd(
                        pidfds[owner], pid,
                        termination_exit_codes[owner],
                        termination_signals[owner]))
                    termination_wait_observed[owner] = true;
            } else if (pid > 1) {
                int status = 0;
                pid_t waited = -1;
                do { waited = ::waitpid(pid, &status, 0); }
                while (waited < 0 && errno == EINTR);
                if (waited == pid) {
                    termination_wait_observed[owner] = true;
                    if (WIFEXITED(status))
                        termination_exit_codes[owner] = WEXITSTATUS(status);
                    else if (WIFSIGNALED(status))
                        termination_signals[owner] = WTERMSIG(status);
                    pid = -1;
                }
            }
        }
        for (auto& fd : channels) close_fd(fd);
        for (auto& fd : truth_channels) close_fd(fd);
        poisoned = true;
    }

    ~Storage() {
        terminate();
        for (auto& pidfd : pidfds) close_fd(pidfd);
    }
};

enum class FreshOwnerRound1AttemptOutcomeState : unsigned char {
    Pending,
    Success,
    UnavailableStop,
};

struct FreshOwnerRound1AttemptOutcomeStorage final {
    FreshOwnerRound1AttemptOutcomeState state{
        FreshOwnerRound1AttemptOutcomeState::Pending};
    std::optional<FreshOwnerRound1IssuedAuthority> issued;
    std::optional<FreshOwnerProcessSupervisor> stopped_supervisor;
    std::optional<FreshOwnerRound1ConsumedGateResidual> consumed_gate;
    std::optional<AcceptedRound1InputHistoryAuthority> unclaimed_history;
    std::optional<FreshOwnerArmIsolationResidualAuthority>
        unclaimed_isolation;
    std::optional<registered_driver::RegisteredPreidentityReadyAuthority>
        unclaimed_ready;
    std::optional<kpb::measurement::fresh_owner_transactional_replay::
        SelectedOwnerReplayRegistryAuthority> unclaimed_registry;
};

enum class FreshOwnerRound2AttemptOutcomeState : unsigned char {
    Pending,
    Success,
    UnavailableStop,
};

struct FreshOwnerRound2ConsumedSuccessorResidual final {
    PublicAcceptedRound1SuccessorHistory successor{};
    std::array<Digest, 3> successor_input_lineages{};
    Digest supervisor_session{};
    Digest continuation{};
    bool live{true};
};

struct FreshOwnerRound2AttemptOutcomeStorage final {
    FreshOwnerRound2AttemptOutcomeState state{
        FreshOwnerRound2AttemptOutcomeState::Pending};
    std::optional<FreshOwnerRound2IssuedAuthority> issued;
    std::optional<FreshOwnerProcessSupervisor> stopped_supervisor;
    std::optional<FreshOwnerRound1IssuedAuthority> retained_round1;
    std::optional<FreshOwnerRound2ConsumedSuccessorResidual>
        consumed_successor;
    std::optional<AcceptedRound1SuccessorHistoryBootstrapAuthority>
        prepared_bootstrap;
    std::optional<FreshOwnerRoundContinuityAuthority>
        prepared_continuity;
    std::optional<FreshOwnerSameRoundRetryAuthority> prepared_retry;
    std::optional<CandidateOwnerTruthPendingAuthority>
        prepared_candidate_truth;
    std::optional<V3AcceptedRound1HistoryResidualAuthority>
        prepared_v3_history;
    std::array<bool, 3> command_sent{};
    std::array<bool, 3> response_authenticated{};
    std::array<bool, 3> stop_sent{};
    std::array<Digest, 3> command_identities{};
    std::array<Digest, 3> response_packet_identities{};
    unsigned failure_stage{};
    int failure_errno{};
    bool baseline{};
};

OwnerPrivateRootAuthority::OwnerPrivateRootAuthority(
        PublicOwnerPrivateRoot receipt, int owned_fd)
    : receipt_(receipt), fd_(owned_fd) {
    struct stat info{};
    need(receipt_.owner_component < 3 && !zero(receipt_.root_identity) &&
         !zero(receipt_.owner_root_metadata_identity) && fd_ >= 0 &&
         ::fstat(fd_, &info) == 0 && S_ISDIR(info.st_mode));
    device_ = static_cast<std::uint64_t>(info.st_dev);
    inode_ = static_cast<std::uint64_t>(info.st_ino);
}

OwnerPrivateRootAuthority::OwnerPrivateRootAuthority(
        OwnerPrivateRootAuthority&& other) noexcept
    : receipt_(other.receipt_), device_(other.device_), inode_(other.inode_),
      fd_(std::exchange(other.fd_, -1)),
      live_(other.live_.exchange(false)) {}

OwnerPrivateRootAuthority::~OwnerPrivateRootAuthority() { close_fd(fd_); }

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
OwnerPrivateRootAuthority OwnerPrivateRootAuthority::test_only_mint(
        PublicOwnerPrivateRoot receipt, int owned_fd) {
    return OwnerPrivateRootAuthority(receipt, owned_fd);
}
#endif

FreshOwnerPrivateArmLaunchAuthority::FreshOwnerPrivateArmLaunchAuthority(
        Evidence evidence)
    : evidence_(std::move(evidence)) {
    static_assert(std::is_trivially_copyable_v<Evidence>);
    require_private_arm_evidence(evidence_);
}

FreshOwnerPrivateArmLaunchAuthority::FreshOwnerPrivateArmLaunchAuthority(
        FreshOwnerPrivateArmLaunchAuthority&& other) noexcept
    : evidence_(other.evidence_), live_(other.live_.exchange(false)) {
    OPENSSL_cleanse(&other.evidence_, sizeof(other.evidence_));
}

FreshOwnerPrivateArmLaunchAuthority::~FreshOwnerPrivateArmLaunchAuthority() {
    OPENSSL_cleanse(&evidence_, sizeof(evidence_));
}

#ifdef KPI_FRESH_OWNER_ARM_ISOLATION_TEST_SETUP
FreshOwnerPrivateArmLaunchAuthority
FreshOwnerPrivateArmLaunchAuthority::test_only_mint(
        PrivateArmIsolationTestEvidence value) {
    return FreshOwnerPrivateArmLaunchAuthority(Evidence{
        .classification = value.classification,
        .process_authority_identity = value.process_authority_identity,
        .supervisor_session_identity = value.supervisor_session_identity,
        .child_pids = value.child_pids,
        .child_sessions = value.child_sessions,
        .root_slots = value.root_slots,
        .logical_owner_ids = value.logical_owner_ids,
        .contract_ids = value.contract_ids,
        .owner_tls_cert_ids = value.owner_tls_cert_ids,
        .owner_tls_spki_ids = value.owner_tls_spki_ids,
        .server_tls_cert_ids = value.server_tls_cert_ids,
        .server_tls_spki_ids = value.server_tls_spki_ids,
    });
}
#endif

FreshOwnerArmIsolationResidualAuthority::
FreshOwnerArmIsolationResidualAuthority(
        registered_driver::CaptureClassification classification,
        Digest isolation, Digest process, Digest supervisor)
    : classification_(classification),
      isolation_authority_identity_(isolation),
      process_authority_identity_(process),
      supervisor_session_identity_(supervisor) {
    using registered_driver::CaptureClassification;
    need((classification_ == CaptureClassification::HiddenCandidate ||
          classification_ ==
              CaptureClassification::ExplicitOwnerPublicEffectsBaseline) &&
         !zero(isolation_authority_identity_) &&
         !zero(process_authority_identity_) &&
         !zero(supervisor_session_identity_));
}

FreshOwnerArmIsolationResidualAuthority::
FreshOwnerArmIsolationResidualAuthority(
        FreshOwnerArmIsolationResidualAuthority&& other) noexcept
    : classification_(other.classification_),
      isolation_authority_identity_(other.isolation_authority_identity_),
      process_authority_identity_(other.process_authority_identity_),
      supervisor_session_identity_(other.supervisor_session_identity_),
      live_(other.live_.exchange(false)) {
    other.classification_ = {};
    OPENSSL_cleanse(other.isolation_authority_identity_.data(),
                    other.isolation_authority_identity_.size());
    OPENSSL_cleanse(other.process_authority_identity_.data(),
                    other.process_authority_identity_.size());
    OPENSSL_cleanse(other.supervisor_session_identity_.data(),
                    other.supervisor_session_identity_.size());
}

FreshOwnerArmIsolationResidualAuthority::
~FreshOwnerArmIsolationResidualAuthority() {
    classification_ = {};
    OPENSSL_cleanse(isolation_authority_identity_.data(),
                    isolation_authority_identity_.size());
    OPENSSL_cleanse(process_authority_identity_.data(),
                    process_authority_identity_.size());
    OPENSSL_cleanse(supervisor_session_identity_.data(),
                    supervisor_session_identity_.size());
}

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
FreshOwnerArmIsolationResidualAuthority
FreshOwnerArmIsolationResidualAuthority::test_only_mint(
        PrivateArmIsolationResidualTestEvidence value) {
    return FreshOwnerArmIsolationResidualAuthority(
        value.classification, value.isolation_authority_identity,
        value.process_authority_identity,
        value.supervisor_session_identity);
}
#endif

CompiledPrivateLifecycleOwnerProgramAuthority::
CompiledPrivateLifecycleOwnerProgramAuthority(
        PublicFreshOwnerProcessPlan plan,
        std::shared_ptr<PrivateLifecycleOwnerChildProgram> program)
    : plan_(std::move(plan)), program_(std::move(program)) {
    need(program_ != nullptr);
    require_plan(plan_);
}

CompiledPrivateLifecycleOwnerProgramAuthority::
CompiledPrivateLifecycleOwnerProgramAuthority(
        CompiledPrivateLifecycleOwnerProgramAuthority&& other) noexcept
    : plan_(std::move(other.plan_)), program_(std::move(other.program_)),
      live_(other.live_.exchange(false)) {}

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
CompiledPrivateLifecycleOwnerProgramAuthority
CompiledPrivateLifecycleOwnerProgramAuthority::test_only_mint(
        PublicFreshOwnerProcessPlan plan,
        std::shared_ptr<PrivateLifecycleOwnerChildProgram> program) {
    return CompiledPrivateLifecycleOwnerProgramAuthority(
        std::move(plan), std::move(program));
}
#endif

AcceptedRound1InputHistoryAuthority::AcceptedRound1InputHistoryAuthority(
        PublicAcceptedRound1InputHistory receipt,
        std::array<Digest, 3> input_lineages)
    : receipt_(receipt), input_lineages_(input_lineages) {
    for (const auto* value : {
             &receipt_.authority_identity, &receipt_.run, &receipt_.trial,
             &receipt_.round1_attempt, &receipt_.round1_cohort,
             &receipt_.accepted_input_head_identity,
             &receipt_.history_gate_identity})
        need(!zero(*value));
    require_private_lineages(input_lineages_);
}

AcceptedRound1InputHistoryAuthority::AcceptedRound1InputHistoryAuthority(
        AcceptedRound1InputHistoryAuthority&& other) noexcept
    : receipt_(other.receipt_), input_lineages_(other.input_lineages_),
      live_(other.live_.exchange(false)) {}

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
AcceptedRound1InputHistoryAuthority
AcceptedRound1InputHistoryAuthority::test_only_mint(
        PublicAcceptedRound1InputHistory receipt,
        std::array<Digest, 3> input_lineages) {
    return AcceptedRound1InputHistoryAuthority(
        receipt, input_lineages);
}
#endif

AcceptedRound1InputHistoryBootstrapAuthority::
AcceptedRound1InputHistoryBootstrapAuthority(
        PublicAcceptedRound1InputHistory receipt) noexcept
    : receipt_(receipt) {}

AcceptedRound1InputHistoryBootstrapAuthority::
AcceptedRound1InputHistoryBootstrapAuthority(
        AcceptedRound1InputHistoryBootstrapAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}

AcceptedRound1SuccessorHistoryAuthority::
AcceptedRound1SuccessorHistoryAuthority(
        PublicAcceptedRound1SuccessorHistory receipt,
        std::array<Digest, 3> successor_input_lineages)
    : receipt_(receipt),
      successor_input_lineages_(successor_input_lineages) {
    for (const auto* value : {
             &receipt_.authority_identity, &receipt_.run, &receipt_.trial,
             &receipt_.round1_attempt, &receipt_.round1_cohort,
             &receipt_.accepted_successor_head_identity,
             &receipt_.history_gate_identity})
        need(!zero(*value));
    require_private_lineages(successor_input_lineages_);
}

AcceptedRound1SuccessorHistoryAuthority::
AcceptedRound1SuccessorHistoryAuthority(
        AcceptedRound1SuccessorHistoryAuthority&& other) noexcept
    : receipt_(other.receipt_),
      successor_input_lineages_(other.successor_input_lineages_),
      live_(other.live_.exchange(false)) {}

Digest V3AcceptedRound1HistoryResidualAuthority::recompute_identity(
        const PublicAcceptedRound1InputHistory& input,
        const PublicAcceptedRound1SuccessorHistory& successor,
        const std::array<Digest, 3>& input_lineages,
        const std::array<Digest, 3>& successor_lineages,
        const Digest& measurement_binding,
        const std::array<Digest, 2>& financial_runs,
        const std::array<Digest, 2>& capture_plans,
        const std::array<Digest, 2>& projections,
        const std::array<Digest, 2>& contexts,
        const Digest& supervisor, const Digest& continuation) {
    Bytes bytes;
    add(bytes, "KPB_V3_ACCEPTED_R1_HISTORY_RESIDUAL_V1\n");
    for (const auto* value : {
             &input.authority_identity, &input.run, &input.trial,
             &input.round1_attempt, &input.round1_cohort,
             &input.accepted_input_head_identity,
             &input.history_gate_identity,
             &successor.authority_identity, &successor.run,
             &successor.trial, &successor.round1_attempt,
             &successor.round1_cohort,
             &successor.accepted_successor_head_identity,
             &successor.history_gate_identity})
        add(bytes, *value);
    for (const auto& value : input_lineages) add(bytes, value);
    for (const auto& value : successor_lineages) add(bytes, value);
    add(bytes, measurement_binding);
    for (const auto* values : {
             &financial_runs, &capture_plans, &projections, &contexts})
        for (const auto& value : *values) add(bytes, value);
    add(bytes, supervisor);
    add(bytes, continuation);
    return hash(bytes);
}

V3AcceptedRound1HistoryResidualAuthority::
V3AcceptedRound1HistoryResidualAuthority(
        PublicAcceptedRound1InputHistory input,
        PublicAcceptedRound1SuccessorHistory successor,
        std::array<Digest, 3> input_lineages,
        std::array<Digest, 3> successor_lineages,
        Digest measurement_binding,
        std::array<Digest, 2> financial_runs,
        std::array<Digest, 2> capture_plans,
        std::array<Digest, 2> projections,
        std::array<Digest, 2> contexts,
        Digest supervisor, Digest continuation)
    : input_(input), successor_(successor),
      input_lineages_(input_lineages),
      successor_lineages_(successor_lineages),
      measurement_run_binding_identity_(measurement_binding),
      financial_runs_(financial_runs), capture_plans_(capture_plans),
      projections_(projections), contexts_(contexts),
      supervisor_session_identity_(supervisor),
      continuation_identity_(continuation),
      residual_identity_(recompute_identity(
          input_, successor_, input_lineages_, successor_lineages_,
          measurement_run_binding_identity_, financial_runs_, capture_plans_,
          projections_, contexts_, supervisor_session_identity_,
          continuation_identity_)) {
    need(input_.run == successor_.run &&
         input_.trial == successor_.trial &&
         input_.round1_attempt == successor_.round1_attempt &&
         input_.round1_cohort == successor_.round1_cohort &&
         input_.authority_identity != successor_.authority_identity &&
         input_.accepted_input_head_identity !=
             successor_.accepted_successor_head_identity &&
         input_.history_gate_identity != successor_.history_gate_identity &&
         !zero(measurement_run_binding_identity_) &&
         !zero(supervisor_session_identity_) &&
         !zero(continuation_identity_) && !zero(residual_identity_));
    require_private_lineages(input_lineages_);
    require_private_lineages(successor_lineages_);
    for (const auto* values : {
             &financial_runs_, &capture_plans_, &projections_, &contexts_})
        need(!zero((*values)[0]) && !zero((*values)[1]) &&
             (*values)[0] != (*values)[1]);
}

V3AcceptedRound1HistoryResidualAuthority::
V3AcceptedRound1HistoryResidualAuthority(
        V3AcceptedRound1HistoryResidualAuthority&& other) noexcept
    : input_(other.input_), successor_(other.successor_),
      input_lineages_(other.input_lineages_),
      successor_lineages_(other.successor_lineages_),
      measurement_run_binding_identity_(
          other.measurement_run_binding_identity_),
      financial_runs_(other.financial_runs_),
      capture_plans_(other.capture_plans_), projections_(other.projections_),
      contexts_(other.contexts_),
      supervisor_session_identity_(other.supervisor_session_identity_),
      continuation_identity_(other.continuation_identity_),
      residual_identity_(other.residual_identity_),
      live_(other.live_.exchange(false)) {}

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
V3AcceptedRound1HistoryResidualAuthority
V3AcceptedRound1HistoryResidualAuthority::
test_only_corrupt_successor_head(
        V3AcceptedRound1HistoryResidualAuthority&& other) {
    V3AcceptedRound1HistoryResidualAuthority result(std::move(other));
    result.successor_.accepted_successor_head_identity[0] ^= 0x80;
    return result;
}
#endif

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
AcceptedRound1SuccessorHistoryAuthority
AcceptedRound1SuccessorHistoryAuthority::test_only_mint(
        PublicAcceptedRound1SuccessorHistory receipt,
        std::array<Digest, 3> successor_input_lineages) {
    return AcceptedRound1SuccessorHistoryAuthority(
        receipt, successor_input_lineages);
}
#endif

AcceptedRound1SuccessorHistoryBootstrapAuthority::
AcceptedRound1SuccessorHistoryBootstrapAuthority(
        PublicAcceptedRound1SuccessorHistory receipt)
    : receipt_(receipt) {}

AcceptedRound1SuccessorHistoryBootstrapAuthority::
AcceptedRound1SuccessorHistoryBootstrapAuthority(
        AcceptedRound1SuccessorHistoryBootstrapAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}

ConsumedFreshOwnerRoundBootstrap::ConsumedFreshOwnerRoundBootstrap(
        PublicFreshOwnerRoundReceipt receipt,
        std::array<OwnerInputContract, 3> contracts)
    : receipt_(std::move(receipt)), contracts_(std::move(contracts)) {}

ConsumedFreshOwnerRoundBootstrap::ConsumedFreshOwnerRoundBootstrap(
        ConsumedFreshOwnerRoundBootstrap&& other) noexcept
    : receipt_(std::move(other.receipt_)),
      contracts_(std::move(other.contracts_)),
      live_(other.live_.exchange(false)) {}

FreshOwnerRoundContinuityAuthority::FreshOwnerRoundContinuityAuthority(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {
    if (storage_ == nullptr) std::terminate();
}

FreshOwnerRoundContinuityAuthority::FreshOwnerRoundContinuityAuthority(
        FreshOwnerRoundContinuityAuthority&& other) noexcept
    : storage_(std::move(other.storage_)),
      live_(other.live_.exchange(false)) {}

FreshOwnerRoundContinuityAuthority::~FreshOwnerRoundContinuityAuthority() =
    default;

FreshOwnerSameRoundRetryAuthority::FreshOwnerSameRoundRetryAuthority(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {
    if (storage_ == nullptr) std::terminate();
}

FreshOwnerSameRoundRetryAuthority::FreshOwnerSameRoundRetryAuthority(
        FreshOwnerSameRoundRetryAuthority&& other) noexcept
    : storage_(std::move(other.storage_)),
      live_(other.live_.exchange(false)) {}

FreshOwnerSameRoundRetryAuthority::~FreshOwnerSameRoundRetryAuthority() =
    default;

CandidateOwnerTruthPostBarrierAuthority::
CandidateOwnerTruthPostBarrierAuthority(
        PublicCandidateOwnerTruthPostBarrier receipt)
    : receipt_(receipt) {
    using registered_driver::CaptureClassification;
    need(receipt_.classification == CaptureClassification::HiddenCandidate &&
         !zero(receipt_.authority_identity) && !zero(receipt_.trial) &&
         !zero(receipt_.barrier_identity));
    for (const auto* values : {
             &receipt_.financial_runs, &receipt_.attempts,
             &receipt_.cohorts, &receipt_.capture_plan_identities,
             &receipt_.projection_identities,
             &receipt_.context_identities})
        need(!zero((*values)[0]) && !zero((*values)[1]) &&
             (*values)[0] != (*values)[1]);
}

CandidateOwnerTruthPostBarrierAuthority::
CandidateOwnerTruthPostBarrierAuthority(
        PublicCandidateOwnerTruthPostBarrier receipt,
        Digest supervisor, Digest continuation)
    : CandidateOwnerTruthPostBarrierAuthority(std::move(receipt)) {
    need(!zero(supervisor) && !zero(continuation));
    supervisor_session_ = supervisor;
    continuation_identity_ = continuation;
}

CandidateOwnerTruthPostBarrierAuthority::
CandidateOwnerTruthPostBarrierAuthority(
        CandidateOwnerTruthPostBarrierAuthority&& other) noexcept
    : receipt_(other.receipt_),
      supervisor_session_(other.supervisor_session_),
      continuation_identity_(other.continuation_identity_),
      live_(other.live_.exchange(false)) {}

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
CandidateOwnerTruthPostBarrierAuthority
CandidateOwnerTruthPostBarrierAuthority::test_only_mint(
        PublicCandidateOwnerTruthPostBarrier receipt) {
    return CandidateOwnerTruthPostBarrierAuthority(receipt);
}
#endif

CandidateOwnerTruthPendingAuthority::CandidateOwnerTruthPendingAuthority(
        Digest supervisor, Digest continuation,
        std::array<Digest, 2> financial_runs,
        std::array<Digest, 2> capture_plans,
        std::array<Digest, 2> projections,
        std::array<Digest, 2> contexts)
    : supervisor_session_(supervisor),
      continuation_identity_(continuation),
      financial_runs_(financial_runs),
      capture_plan_identities_(capture_plans),
      projection_identities_(projections),
      context_identities_(contexts) {
    need(!zero(supervisor_session_) && !zero(continuation_identity_));
    for (const auto* values : {
             &financial_runs_, &capture_plan_identities_,
             &projection_identities_, &context_identities_})
        need(!zero((*values)[0]) && !zero((*values)[1]) &&
             (*values)[0] != (*values)[1]);
}

CandidateOwnerTruthPendingAuthority::CandidateOwnerTruthPendingAuthority(
        CandidateOwnerTruthPendingAuthority&& other) noexcept
    : supervisor_session_(other.supervisor_session_),
      continuation_identity_(other.continuation_identity_),
      financial_runs_(other.financial_runs_),
      capture_plan_identities_(other.capture_plan_identities_),
      projection_identities_(other.projection_identities_),
      context_identities_(other.context_identities_),
      live_(other.live_.exchange(false)) {}

CandidateOwnerTruthEndpointAuthority::CandidateOwnerTruthEndpointAuthority(
        PublicCandidateOwnerTruthEndpoint receipt, int owned_fd)
    : receipt_(receipt), fd_(owned_fd) {
    try {
        using registered_driver::CaptureClassification;
        struct stat info{};
        int socket_type = 0;
        socklen_t socket_type_bytes = sizeof(socket_type);
        need(receipt_.classification ==
                 CaptureClassification::HiddenCandidate &&
             receipt_.owner_component < 3 &&
             receipt_.fixed_fd == FRESH_OWNER_FIXED_TRUTH_FD &&
             !zero(receipt_.endpoint_identity) &&
             !zero(receipt_.feeder_session_identity) &&
             !zero(receipt_.trial) && !zero(receipt_.barrier_identity) &&
             receipt_.feeder_pid > 1 &&
             !zero(receipt_.feeder_exit_identity) && fd_ >= 0 &&
             ::fstat(fd_, &info) == 0 && S_ISSOCK(info.st_mode) &&
             ::getsockopt(fd_, SOL_SOCKET, SO_TYPE, &socket_type,
                          &socket_type_bytes) == 0 &&
             socket_type_bytes == sizeof(socket_type) &&
             socket_type == SOCK_SEQPACKET);
        device_ = static_cast<std::uint64_t>(info.st_dev);
        inode_ = static_cast<std::uint64_t>(info.st_ino);
    } catch (...) {
        close_fd(fd_);
        throw;
    }
}

CandidateOwnerTruthEndpointAuthority::CandidateOwnerTruthEndpointAuthority(
        CandidateOwnerTruthEndpointAuthority&& other) noexcept
    : receipt_(other.receipt_), device_(other.device_), inode_(other.inode_),
      fd_(std::exchange(other.fd_, -1)) {}

CandidateOwnerTruthEndpointAuthority::~CandidateOwnerTruthEndpointAuthority() {
    close_fd(fd_);
}

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
CandidateOwnerTruthEndpointAuthority
CandidateOwnerTruthEndpointAuthority::test_only_mint(
        PublicCandidateOwnerTruthEndpoint receipt, int owned_fd) {
    return CandidateOwnerTruthEndpointAuthority(receipt, owned_fd);
}

std::array<unsigned char, candidate_truth_schema::PACKET_BYTES>
CandidateOwnerTruthEndpointAuthority::test_only_receive_packet() {
    using namespace candidate_truth_schema;
    need(fd_ >= 0);
    struct stat current{};
    need(::fstat(fd_, &current) == 0 &&
         static_cast<std::uint64_t>(current.st_dev) == device_ &&
         static_cast<std::uint64_t>(current.st_ino) == inode_);
    std::array<unsigned char, PACKET_BYTES> result{};
    std::array<unsigned char, CMSG_SPACE(sizeof(struct ucred))> control{};
    struct iovec iov{.iov_base = result.data(), .iov_len = result.size()};
    struct msghdr message{};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t received;
    do { received = ::recvmsg(fd_, &message, MSG_CMSG_CLOEXEC); }
    while (received < 0 && errno == EINTR);
    close_fd(fd_);
    need(received == static_cast<ssize_t>(result.size()) &&
         (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0);
    const struct ucred* credentials = nullptr;
    unsigned credential_count = 0;
    for (auto* header = CMSG_FIRSTHDR(&message); header != nullptr;
         header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level == SOL_SOCKET &&
            header->cmsg_type == SCM_CREDENTIALS &&
            header->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {
            credentials = reinterpret_cast<const struct ucred*>(
                CMSG_DATA(header));
            ++credential_count;
        }
    }
    need(credential_count == 1 && credentials != nullptr &&
         credentials->pid == receipt_.feeder_pid &&
         credentials->uid == ::getuid() && credentials->gid == ::getgid() &&
         std::equal(MAGIC.begin(), MAGIC.end(),
                    result.begin() + MAGIC_OFFSET) &&
         result[VERSION_OFFSET] == VERSION &&
         result[CLASSIFICATION_OFFSET] == HIDDEN_CANDIDATE_CLASSIFICATION &&
         result[OWNER_OFFSET] == receipt_.owner_component);
    const auto matches = [&](std::size_t offset, const Digest& expected) {
        return std::equal(expected.begin(), expected.end(),
                          result.begin() +
                              static_cast<std::ptrdiff_t>(offset));
    };
    need(matches(ENDPOINT_IDENTITY_OFFSET, receipt_.endpoint_identity) &&
         matches(FEEDER_SESSION_OFFSET, receipt_.feeder_session_identity) &&
         matches(TRIAL_OFFSET, receipt_.trial));
    for (unsigned index = 0; index < 2; ++index) {
        need(result[round_offset(index)] == index + 1 &&
             matches(round_digest_offset(index,
                         RoundDigestField::FinancialRun),
                     receipt_.financial_runs[index]) &&
             matches(round_digest_offset(index,
                         RoundDigestField::Attempt),
                     receipt_.attempts[index]) &&
             matches(round_digest_offset(index,
                         RoundDigestField::Cohort),
                     receipt_.cohorts[index]) &&
             matches(round_digest_offset(index,
                         RoundDigestField::CapturePlan),
                     receipt_.capture_plan_identities[index]) &&
             matches(round_digest_offset(index,
                         RoundDigestField::Projection),
                     receipt_.projection_identities[index]) &&
             matches(round_digest_offset(index,
                         RoundDigestField::Context),
                     receipt_.context_identities[index]));
    }
    return result;
}
#endif

CandidateOwnerTruthEndpointSplit::CandidateOwnerTruthEndpointSplit(
        std::array<CandidateOwnerTruthEndpointAuthority, 3>&& endpoints) {
    for (unsigned owner = 0; owner < 3; ++owner)
        endpoints_[owner].emplace(std::move(endpoints[owner]));
}

CandidateOwnerTruthEndpointAuthority
CandidateOwnerTruthEndpointSplit::take(unsigned owner) {
    need(owner < 3 && endpoints_[owner].has_value());
    CandidateOwnerTruthEndpointAuthority result(
        std::move(*endpoints_[owner]));
    endpoints_[owner].reset();
    return result;
}

namespace {

void require_continuity(
        const PublicFreshOwnerRoundReceipt& round,
        const std::array<OwnerInputContract, 3>& contracts,
        const PrivateFreshOwnerContinuityRecord& value) {
    need(value.classification == round.classification &&
         value.round == round.round && value.run == round.run &&
         value.trial == round.trial && value.attempt == round.attempt &&
         value.cohort == round.cohort &&
         value.root_identity == round.root_identity &&
         value.round_issuance_identity == round.issuance_identity &&
         !zero(value.supervisor_session) &&
         !zero(value.arm_isolation_identity));
    std::set<std::int64_t> pids;
    std::set<Digest> sessions, lineages, files, metadata, contract_ids;
    std::set<std::pair<std::uint64_t, std::uint64_t>> roots;
    std::set<LogicalOwnerIdentity> logical_ids;
    for (unsigned owner = 0; owner < 3; ++owner) {
        need(value.child_pids[owner] > 1 &&
             pids.insert(value.child_pids[owner]).second &&
             !zero(value.child_sessions[owner]) &&
             sessions.insert(value.child_sessions[owner]).second &&
             value.root_objects[owner].first != 0 &&
             value.root_objects[owner].second != 0 &&
             roots.insert(value.root_objects[owner]).second &&
             !zero(value.logical_owner_ids[owner]) &&
             logical_ids.insert(value.logical_owner_ids[owner]).second &&
             !zero(value.input_lineages[owner]) &&
             lineages.insert(value.input_lineages[owner]).second &&
             !zero(value.file_identities[owner]) &&
             files.insert(value.file_identities[owner]).second &&
             !zero(value.file_metadata_identities[owner]) &&
             metadata.insert(value.file_metadata_identities[owner]).second &&
             value.contract_identities[owner] ==
                 owner_contract_identity(contracts[owner]) &&
             contract_ids.insert(value.contract_identities[owner]).second);
    }
}

} // namespace

ConsumedFreshOwnerRoundBootstrap FreshOwnerRoundBootstrapBridge::consume(
        FreshOwnerRoundAuthority&& round,
        AcceptedRound1InputHistoryBootstrapAuthority&& history,
        FreshOwnerRoundContinuityAuthority&& continuity) {
    const bool round_live = round.live_.exchange(false);
    const bool history_live = history.live_.exchange(false);
    const bool continuity_live = continuity.live_.exchange(false);
    need(round_live && history_live && continuity_live &&
         continuity.storage_ != nullptr);
    const auto& selected = round.receipt_;
    const auto& gate = history.receipt_;
    need(selected.round == 1 && selected.run == gate.run &&
         selected.trial == gate.trial &&
         selected.attempt == gate.round1_attempt &&
         selected.cohort == gate.round1_cohort &&
         selected.accepted_input_head_identity ==
             gate.accepted_input_head_identity &&
         selected.history_gate_identity == gate.history_gate_identity &&
         !zero(gate.authority_identity));
    require_continuity(
        selected, round.contracts_, continuity.storage_->record);
    return ConsumedFreshOwnerRoundBootstrap(
        std::move(round.receipt_), std::move(round.contracts_));
}

ConsumedFreshOwnerRoundBootstrap FreshOwnerRoundBootstrapBridge::consume(
        FreshOwnerRoundAuthority&& round,
        AcceptedRound1SuccessorHistoryBootstrapAuthority&& history,
        FreshOwnerRoundContinuityAuthority&& continuity) {
    const bool round_live = round.live_.exchange(false);
    const bool history_live = history.live_.exchange(false);
    const bool continuity_live = continuity.live_.exchange(false);
    need(round_live && history_live && continuity_live &&
         continuity.storage_ != nullptr);
    const auto& selected = round.receipt_;
    const auto& gate = history.receipt_;
    need(selected.round == 2 && selected.run == gate.run &&
         selected.trial == gate.trial &&
         selected.accepted_input_head_identity ==
             gate.accepted_successor_head_identity &&
         selected.history_gate_identity == gate.history_gate_identity &&
         !zero(gate.authority_identity));
    require_continuity(
        selected, round.contracts_, continuity.storage_->record);
    return ConsumedFreshOwnerRoundBootstrap(
        std::move(round.receipt_), std::move(round.contracts_));
}

AuthenticatedOwnerProcessBundle::AuthenticatedOwnerProcessBundle(
        PublicOwnerIssuanceReceipt receipt,
        std::shared_ptr<const LongLivedOwnerProofVerifier> verifier,
        LogicalOwnerIdentity logical_owner_identity, Digest binding_nonce)
    : receipt_(std::move(receipt)), verifier_(std::move(verifier)),
      logical_owner_identity_(logical_owner_identity),
      binding_nonce_(binding_nonce) {}

AuthenticatedOwnerProcessBundle::AuthenticatedOwnerProcessBundle(
        AuthenticatedOwnerProcessBundle&& other) noexcept
    : receipt_(std::move(other.receipt_)),
      verifier_(std::move(other.verifier_)),
      logical_owner_identity_(other.logical_owner_identity_),
      binding_nonce_(other.binding_nonce_),
      live_(other.live_.exchange(false)) {}

OwnerLocalIssuanceAuthority FreshOwnerProcessMintBridge::mint_owner(
        AuthenticatedOwnerProcessBundle&& bundle,
        registered_driver::RegisteredOwnerIssuancePermit&& permit) {
    need(bundle.live_.exchange(false) && bundle.verifier_ != nullptr);
    auto result = OwnerLocalIssuanceAuthority(
        std::move(bundle.receipt_), std::move(bundle.verifier_),
        bundle.binding_nonce_, std::move(permit));
    need(result.logical_owner_identity_ == bundle.logical_owner_identity_);
    return result;
}

#if defined(KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP) && \
    defined(KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP)
OwnerLocalIssuanceAuthority FreshOwnerProcessMintBridge::mint_owner(
        AuthenticatedOwnerProcessBundle&& bundle) {
    need(bundle.live_.exchange(false) && bundle.verifier_ != nullptr);
    auto result = OwnerLocalIssuanceAuthority(
        std::move(bundle.receipt_), std::move(bundle.verifier_),
        bundle.binding_nonce_);
    need(result.logical_owner_identity_ == bundle.logical_owner_identity_);
    return result;
}
#endif

FreshOwnerRound1ConsumedGateResidual::
FreshOwnerRound1ConsumedGateResidual(
        PublicAcceptedRound1InputHistory history,
        std::array<Digest, 3> input_lineages,
        registered_driver::CaptureClassification classification,
        Digest isolation, Digest process, Digest supervisor) noexcept
    : history_(history), input_lineages_(input_lineages),
      classification_(classification),
      isolation_authority_identity_(isolation),
      process_authority_identity_(process),
      supervisor_session_identity_(supervisor) {}

FreshOwnerRound1ConsumedGateResidual::
FreshOwnerRound1ConsumedGateResidual(
        FreshOwnerRound1ConsumedGateResidual&& other) noexcept
    : history_(other.history_), input_lineages_(other.input_lineages_),
      classification_(other.classification_),
      isolation_authority_identity_(other.isolation_authority_identity_),
      process_authority_identity_(other.process_authority_identity_),
      supervisor_session_identity_(other.supervisor_session_identity_),
      live_(other.live_.exchange(false)) {
    other.history_ = {};
    other.input_lineages_ = {};
    other.classification_ = {};
    other.isolation_authority_identity_ = {};
    other.process_authority_identity_ = {};
    other.supervisor_session_identity_ = {};
}

FreshOwnerRound1AttemptOutcomeAuthority::
FreshOwnerRound1AttemptOutcomeAuthority(
        std::unique_ptr<FreshOwnerRound1AttemptOutcomeStorage>&& storage)
        noexcept
    : storage_(std::move(storage)) {}

FreshOwnerRound1AttemptOutcomeAuthority::
FreshOwnerRound1AttemptOutcomeAuthority(
        FreshOwnerRound1AttemptOutcomeAuthority&&) noexcept = default;

FreshOwnerRound1AttemptOutcomeAuthority::
~FreshOwnerRound1AttemptOutcomeAuthority() {
    // A caller may move this authority into the mandatory outer history sink,
    // or a test bridge may explicitly consume it. Silent destruction would
    // erase either the sole issued continuation or the sole STOP evidence.
    if (storage_ != nullptr) std::terminate();
}

bool FreshOwnerRound1AttemptOutcomeAuthority::
valid_for_outer_consumer() const noexcept {
    if (storage_ == nullptr) return false;
    const auto& outer = *storage_;
    const auto exact_gate = [](const FreshOwnerRound1ConsumedGateResidual& gate) {
        if (!gate.live_.load() ||
            zero(gate.history_.authority_identity) ||
            zero(gate.isolation_authority_identity_) ||
            zero(gate.process_authority_identity_) ||
            zero(gate.supervisor_session_identity_))
            return false;
        for (const auto& lineage : gate.input_lineages_)
            if (zero(lineage)) return false;
        return true;
    };

    if (outer.state == FreshOwnerRound1AttemptOutcomeState::Success) {
        return outer.issued.has_value() &&
            outer.consumed_gate.has_value() &&
            exact_gate(*outer.consumed_gate) &&
            !outer.stopped_supervisor.has_value() &&
            !outer.unclaimed_history.has_value() &&
            !outer.unclaimed_isolation.has_value() &&
            !outer.unclaimed_ready.has_value() &&
            !outer.unclaimed_registry.has_value();
    }
    if (outer.state !=
            FreshOwnerRound1AttemptOutcomeState::UnavailableStop ||
        outer.issued.has_value() ||
        !outer.stopped_supervisor.has_value())
        return false;

    const auto& supervisor = *outer.stopped_supervisor;
    if (supervisor.storage_ == nullptr || !supervisor.storage_->poisoned)
        return false;
    const auto& stopped = *supervisor.storage_;

    if (outer.consumed_gate.has_value()) {
        if (!exact_gate(*outer.consumed_gate) ||
            outer.unclaimed_history.has_value() ||
            outer.unclaimed_isolation.has_value())
            return false;
        const auto& gate = *outer.consumed_gate;
        if (gate.history_.run != stopped.plan.run ||
            gate.history_.trial != stopped.plan.trial ||
            gate.classification_ != stopped.plan.classification ||
            gate.isolation_authority_identity_ !=
                stopped.arm_isolation_identity ||
            gate.process_authority_identity_ !=
                stopped.plan.process_authority_identity ||
            gate.supervisor_session_identity_ !=
                stopped.launch.supervisor_session_identity)
            return false;
        for (unsigned owner = 0; owner < 3; ++owner)
            if (gate.input_lineages_[owner] !=
                stopped.input_lineages[owner][0])
                return false;
    } else {
        if (!outer.unclaimed_history.has_value() ||
            !outer.unclaimed_isolation.has_value())
            return false;
        const auto& history = *outer.unclaimed_history;
        const auto& isolation = *outer.unclaimed_isolation;
        if (!history.live_.load() || !isolation.live_.load() ||
            zero(history.receipt_.authority_identity) ||
            history.receipt_.run != stopped.plan.run ||
            history.receipt_.trial != stopped.plan.trial ||
            isolation.classification_ != stopped.plan.classification ||
            isolation.process_authority_identity_ !=
                stopped.plan.process_authority_identity ||
            isolation.supervisor_session_identity_ !=
                stopped.launch.supervisor_session_identity ||
            zero(isolation.isolation_authority_identity_))
            return false;
        for (unsigned owner = 0; owner < 3; ++owner)
            if (history.input_lineages_[owner] !=
                stopped.input_lineages[owner][0])
                return false;
    }

    const bool transactional_retained =
        stopped.transactional_issuance.has_value() &&
        supervisor.retains_transactional_round1_lineage();
    const bool caller_inputs_retained =
        !stopped.transactional_issuance.has_value() &&
        outer.unclaimed_ready.has_value() &&
        outer.unclaimed_registry.has_value();
    if (!transactional_retained && !caller_inputs_retained) return false;
    if (transactional_retained &&
        (outer.unclaimed_ready.has_value() ||
         outer.unclaimed_registry.has_value()))
        return false;

    for (unsigned owner = 0; owner < 3; ++owner)
        if (!stopped.termination_wait_observed[owner] &&
            !(stopped.pidfds[owner] >= 0 && stopped.pids[owner] > 1))
            return false;

    if (!stopped.round1_transaction_committed)
        return !stopped.reserved_trial.has_value() &&
            !stopped.reserved_round1_driver.has_value() &&
            !stopped.reserved_round2.has_value() &&
            !stopped.reserved_persistent_activation.has_value() &&
            !stopped.reserved_producer_closure.has_value();

    const bool before_split = stopped.reserved_trial.has_value() &&
        !stopped.reserved_round1_driver.has_value() &&
        !stopped.reserved_round2.has_value() &&
        !stopped.reserved_persistent_activation.has_value() &&
        !stopped.reserved_producer_closure.has_value();
    const bool after_split = !stopped.reserved_trial.has_value() &&
        stopped.reserved_round1_driver.has_value() &&
        stopped.reserved_round2.has_value() &&
        stopped.reserved_persistent_activation.has_value() &&
        stopped.reserved_producer_closure.has_value();
    return before_split || after_split;
}

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
TestFreshOwnerRound1AttemptOutcome
FreshOwnerRound1AttemptOutcomeTestBridge::inspect(
        const FreshOwnerRound1AttemptOutcomeAuthority& outcome) noexcept {
    if (!outcome.valid_for_outer_consumer())
        return TestFreshOwnerRound1AttemptOutcome::Invalid;
    const auto& storage = *outcome.storage_;
    if (storage.state == FreshOwnerRound1AttemptOutcomeState::Success)
        return TestFreshOwnerRound1AttemptOutcome::Success;
    if (storage.state == FreshOwnerRound1AttemptOutcomeState::UnavailableStop)
        return TestFreshOwnerRound1AttemptOutcome::UnavailableStop;
    return TestFreshOwnerRound1AttemptOutcome::Invalid;
}

FreshOwnerRound1IssuedAuthority
FreshOwnerRound1AttemptOutcomeTestBridge::take_success(
        FreshOwnerRound1AttemptOutcomeAuthority&& outcome) {
    need(inspect(outcome) == TestFreshOwnerRound1AttemptOutcome::Success);
    FreshOwnerRound1IssuedAuthority result(
        std::move(*outcome.storage_->issued));
    outcome.storage_->issued.reset();
    outcome.storage_.reset();
    return result;
}

bool FreshOwnerRound1AttemptOutcomeTestBridge::
stop_retains_claimed_lineage(
        const FreshOwnerRound1AttemptOutcomeAuthority& outcome) noexcept {
    return inspect(outcome) ==
        TestFreshOwnerRound1AttemptOutcome::UnavailableStop;
}

bool FreshOwnerRound1AttemptOutcomeTestBridge::
stop_retains_unsettled_pidfds(
        const FreshOwnerRound1AttemptOutcomeAuthority& outcome) noexcept {
    if (inspect(outcome) !=
        TestFreshOwnerRound1AttemptOutcome::UnavailableStop)
        return false;
    const auto& outer = *outcome.storage_;
    if (!outer.stopped_supervisor.has_value() ||
        outer.stopped_supervisor->storage_ == nullptr)
        return false;
    const auto& supervisor = *outer.stopped_supervisor->storage_;
    for (unsigned owner = 0; owner < 3; ++owner)
        if (supervisor.termination_wait_observed[owner] ||
            supervisor.pidfds[owner] < 0 || supervisor.pids[owner] <= 1)
            return false;
    return true;
}

void FreshOwnerRound1AttemptOutcomeTestBridge::discard_stop_for_test(
        FreshOwnerRound1AttemptOutcomeAuthority&& outcome) noexcept {
    if (inspect(outcome) !=
        TestFreshOwnerRound1AttemptOutcome::UnavailableStop)
        std::terminate();
    outcome.storage_.reset();
}

void FreshOwnerRound1AttemptOutcomeTestBridge::set_fault(
        FreshOwnerRound1AttemptTestFault fault) noexcept {
    round1_attempt_fault = fault;
}


void FreshOwnerRound1AttemptOutcomeTestBridge::set_pidfd_wait_fault(
        FreshOwnerOwnerPidfdWaitTestFault fault) noexcept {
    owner_pidfd_wait_fault = fault;
}
#endif

FreshOwnerRound1IssuedAuthority::FreshOwnerRound1IssuedAuthority(
        FreshOwnerRoundAuthority&& driver,
        AcceptedRound1InputHistoryBootstrapAuthority&& bootstrap_history,
        FreshOwnerRoundContinuityAuthority&& continuity,
        FreshOwnerSameRoundRetryAuthority&& retry,
        FreshOwnerPersistentActivationAuthority&& persistent_activation,
        FreshOwnerProducerClosureAuthority&& producer_closure,
        Digest supervisor, Digest continuation,
        PublicAcceptedRound1InputHistory v3_input_history,
        std::array<Digest, 3> v3_input_lineages,
        Digest v3_measurement_binding,
        std::array<Digest, 2> v3_financial_runs,
        std::array<Digest, 2> v3_capture_plans,
        std::array<Digest, 2> v3_projections,
        std::array<Digest, 2> v3_contexts)
        noexcept
    : supervisor_session_identity_(supervisor),
      continuation_identity_(continuation),
      v3_input_history_(v3_input_history),
      v3_input_lineages_(v3_input_lineages),
      v3_measurement_run_binding_identity_(v3_measurement_binding),
      v3_financial_runs_(v3_financial_runs),
      v3_capture_plans_(v3_capture_plans),
      v3_projections_(v3_projections), v3_contexts_(v3_contexts) {
    driver_round_.emplace(std::move(driver));
    bootstrap_history_.emplace(std::move(bootstrap_history));
    continuity_.emplace(std::move(continuity));
    retry_.emplace(std::move(retry));
    persistent_activation_.emplace(std::move(persistent_activation));
    producer_closure_.emplace(std::move(producer_closure));
}

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
FreshOwnerRound1IssuedAuthority::FreshOwnerRound1IssuedAuthority(
        FreshOwnerRoundAuthority&& driver,
        AcceptedRound1InputHistoryBootstrapAuthority&& bootstrap_history,
        FreshOwnerRoundContinuityAuthority&& continuity,
        FreshOwnerSameRoundRetryAuthority&& retry,
        Digest supervisor, Digest continuation,
        PublicAcceptedRound1InputHistory v3_input_history,
        std::array<Digest, 3> v3_input_lineages,
        Digest v3_measurement_binding,
        std::array<Digest, 2> v3_financial_runs,
        std::array<Digest, 2> v3_capture_plans,
        std::array<Digest, 2> v3_projections,
        std::array<Digest, 2> v3_contexts)
        noexcept
    : supervisor_session_identity_(supervisor),
      continuation_identity_(continuation),
      v3_input_history_(v3_input_history),
      v3_input_lineages_(v3_input_lineages),
      v3_measurement_run_binding_identity_(v3_measurement_binding),
      v3_financial_runs_(v3_financial_runs),
      v3_capture_plans_(v3_capture_plans),
      v3_projections_(v3_projections), v3_contexts_(v3_contexts) {
    driver_round_.emplace(std::move(driver));
    bootstrap_history_.emplace(std::move(bootstrap_history));
    continuity_.emplace(std::move(continuity));
    retry_.emplace(std::move(retry));
}
#endif

FreshOwnerRound1IssuedAuthority::FreshOwnerRound1IssuedAuthority(
        FreshOwnerRound1IssuedAuthority&& other) noexcept
    : driver_round_(std::move(other.driver_round_)),
      bootstrap_history_(std::move(other.bootstrap_history_)),
      continuity_(std::move(other.continuity_)),
      retry_(std::move(other.retry_)),
      persistent_activation_(std::move(other.persistent_activation_)),
      producer_closure_(std::move(other.producer_closure_)),
      supervisor_session_identity_(other.supervisor_session_identity_),
      continuation_identity_(other.continuation_identity_),
      v3_input_history_(other.v3_input_history_),
      v3_input_lineages_(other.v3_input_lineages_),
      v3_measurement_run_binding_identity_(
          other.v3_measurement_run_binding_identity_),
      v3_financial_runs_(other.v3_financial_runs_),
      v3_capture_plans_(other.v3_capture_plans_),
      v3_projections_(other.v3_projections_),
      v3_contexts_(other.v3_contexts_),
      live_(other.live_.exchange(false)) {}

FreshOwnerRoundAuthority
FreshOwnerRound1IssuedAuthority::take_driver_round() {
    need(driver_round_.has_value());
    FreshOwnerRoundAuthority result(std::move(*driver_round_));
    driver_round_.reset();
    return result;
}

AcceptedRound1InputHistoryBootstrapAuthority
FreshOwnerRound1IssuedAuthority::take_bootstrap_history() {
    need(bootstrap_history_.has_value());
    AcceptedRound1InputHistoryBootstrapAuthority result(
        std::move(*bootstrap_history_));
    bootstrap_history_.reset();
    return result;
}

FreshOwnerRoundContinuityAuthority
FreshOwnerRound1IssuedAuthority::take_continuity() {
    need(continuity_.has_value());
    FreshOwnerRoundContinuityAuthority result(std::move(*continuity_));
    continuity_.reset();
    return result;
}

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
FreshOwnerSameRoundRetryAuthority
FreshOwnerRound1IssuedAuthority::take_same_round_retry() {
    need(retry_.has_value());
    FreshOwnerSameRoundRetryAuthority result(std::move(*retry_));
    retry_.reset();
    return result;
}
#endif

FreshOwnerPersistentActivationAuthority
FreshOwnerRound1IssuedAuthority::take_persistent_activation() {
    need(persistent_activation_.has_value());
    FreshOwnerPersistentActivationAuthority result(
        std::move(*persistent_activation_));
    persistent_activation_.reset();
    return result;
}

FreshOwnerProducerClosureAuthority
FreshOwnerRound1IssuedAuthority::take_producer_closure() {
    need(producer_closure_.has_value());
    FreshOwnerProducerClosureAuthority result(
        std::move(*producer_closure_));
    producer_closure_.reset();
    return result;
}

FreshOwnerRound2AttemptOutcomeAuthority::
FreshOwnerRound2AttemptOutcomeAuthority(
        std::unique_ptr<FreshOwnerRound2AttemptOutcomeStorage>&& storage)
        noexcept
    : storage_(std::move(storage)) {}

FreshOwnerRound2AttemptOutcomeAuthority::
FreshOwnerRound2AttemptOutcomeAuthority(
        FreshOwnerRound2AttemptOutcomeAuthority&&) noexcept = default;

FreshOwnerRound2AttemptOutcomeAuthority::
~FreshOwnerRound2AttemptOutcomeAuthority() {
    if (storage_ != nullptr) std::terminate();
}

bool FreshOwnerRound2AttemptOutcomeAuthority::
valid_for_outer_consumer() const noexcept {
    if (storage_ == nullptr || !storage_->retained_round1.has_value() ||
        !storage_->consumed_successor.has_value())
        return false;
    const auto& outer = *storage_;
    const auto& round1 = *outer.retained_round1;
    const auto& successor = *outer.consumed_successor;
    if (round1.live_.load() || !successor.live ||
        round1.driver_round_.has_value() ||
        round1.bootstrap_history_.has_value() ||
        round1.continuity_.has_value() ||
        round1.persistent_activation_.has_value() ||
        round1.producer_closure_.has_value() ||
        zero(round1.supervisor_session_identity_) ||
        zero(round1.continuation_identity_) ||
        successor.supervisor_session !=
            round1.supervisor_session_identity_ ||
        successor.continuation != round1.continuation_identity_ ||
        zero(successor.successor.authority_identity) ||
        successor.successor.run != round1.v3_input_history_.run ||
        successor.successor.trial != round1.v3_input_history_.trial ||
        successor.successor.round1_attempt !=
            round1.v3_input_history_.round1_attempt ||
        successor.successor.round1_cohort !=
            round1.v3_input_history_.round1_cohort)
        return false;
    for (unsigned owner = 0; owner < 3; ++owner) {
        if (zero(successor.successor_input_lineages[owner]) ||
            zero(outer.command_identities[owner]) ||
            (outer.response_authenticated[owner] &&
             !outer.command_sent[owner]) ||
            (outer.stop_sent[owner] &&
             !outer.response_authenticated[owner]) ||
            (outer.response_authenticated[owner] &&
             zero(outer.response_packet_identities[owner])))
            return false;
    }

    if (outer.state == FreshOwnerRound2AttemptOutcomeState::Success) {
        if (!outer.issued.has_value() ||
            outer.stopped_supervisor.has_value() ||
            outer.prepared_bootstrap.has_value() ||
            outer.prepared_continuity.has_value() ||
            outer.prepared_retry.has_value() ||
            outer.prepared_candidate_truth.has_value() ||
            outer.prepared_v3_history.has_value() ||
            outer.failure_stage != 0)
            return false;
        for (unsigned owner = 0; owner < 3; ++owner) {
            if (!outer.command_sent[owner] ||
                !outer.response_authenticated[owner] ||
                (outer.baseline && !outer.stop_sent[owner]) ||
                (!outer.baseline && outer.stop_sent[owner]))
                return false;
        }
        const auto& issued = *outer.issued;
        return issued.driver_round_.has_value() &&
            issued.bootstrap_history_.has_value() &&
            issued.continuity_.has_value() && issued.retry_.has_value() &&
            (outer.baseline
                ? issued.roster_.has_value() &&
                    !issued.candidate_truth_.has_value() &&
                    !issued.v3_history_.has_value()
                : !issued.roster_.has_value() &&
                    issued.candidate_truth_.has_value() &&
                    issued.v3_history_.has_value());
    }

    if (outer.state !=
            FreshOwnerRound2AttemptOutcomeState::UnavailableStop ||
        outer.issued.has_value() ||
        !outer.stopped_supervisor.has_value() ||
        !outer.prepared_bootstrap.has_value() ||
        !outer.prepared_continuity.has_value() ||
        !outer.prepared_retry.has_value() || outer.failure_stage == 0)
        return false;
    const auto& supervisor = *outer.stopped_supervisor;
    if (supervisor.storage_ == nullptr || !supervisor.storage_->poisoned)
        return false;
    const auto& stopped = *supervisor.storage_;
    if (stopped.plan.run != successor.successor.run ||
        stopped.plan.trial != successor.successor.trial ||
        stopped.launch.supervisor_session_identity !=
            successor.supervisor_session ||
        stopped.continuation != successor.continuation ||
        stopped.round2_issued || !stopped.reserved_round2.has_value())
        return false;
    for (unsigned owner = 0; owner < 3; ++owner)
        if (successor.successor_input_lineages[owner] !=
            stopped.input_lineages[owner][1])
            return false;
    const bool stopped_baseline = stopped.plan.classification ==
        registered_driver::CaptureClassification::
            ExplicitOwnerPublicEffectsBaseline;
    if (outer.baseline != stopped_baseline)
        return false;
    if (outer.baseline)
        return !outer.prepared_candidate_truth.has_value() &&
            !outer.prepared_v3_history.has_value() &&
            stopped.reserved_roster.has_value();
    return outer.prepared_candidate_truth.has_value() &&
        outer.prepared_v3_history.has_value() &&
        !stopped.reserved_roster.has_value();
}

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
TestFreshOwnerRound2AttemptOutcome
FreshOwnerRound2AttemptOutcomeTestBridge::inspect(
        const FreshOwnerRound2AttemptOutcomeAuthority& outcome) noexcept {
    if (!outcome.valid_for_outer_consumer())
        return TestFreshOwnerRound2AttemptOutcome::Invalid;
    return outcome.storage_->state ==
            FreshOwnerRound2AttemptOutcomeState::Success
        ? TestFreshOwnerRound2AttemptOutcome::Success
        : TestFreshOwnerRound2AttemptOutcome::UnavailableStop;
}

FreshOwnerRound2IssuedAuthority
FreshOwnerRound2AttemptOutcomeTestBridge::take_success(
        FreshOwnerRound2AttemptOutcomeAuthority&& outcome) {
    need(inspect(outcome) == TestFreshOwnerRound2AttemptOutcome::Success);
    FreshOwnerRound2IssuedAuthority result(
        std::move(*outcome.storage_->issued));
    outcome.storage_->issued.reset();
    outcome.storage_.reset();
    return result;
}

bool FreshOwnerRound2AttemptOutcomeTestBridge::
stop_retains_claimed_lineage(
        const FreshOwnerRound2AttemptOutcomeAuthority& outcome) noexcept {
    return inspect(outcome) ==
        TestFreshOwnerRound2AttemptOutcome::UnavailableStop;
}

void FreshOwnerRound2AttemptOutcomeTestBridge::discard_stop_for_test(
        FreshOwnerRound2AttemptOutcomeAuthority&& outcome) noexcept {
    if (inspect(outcome) !=
        TestFreshOwnerRound2AttemptOutcome::UnavailableStop)
        std::terminate();
    outcome.storage_.reset();
}

void FreshOwnerRound2AttemptOutcomeTestBridge::set_fault(
        FreshOwnerRound2AttemptTestFault fault) noexcept {
    round2_attempt_fault = fault;
}
#endif

FreshOwnerRound2IssuedAuthority::FreshOwnerRound2IssuedAuthority(
        FreshOwnerRoundAuthority&& driver,
        AcceptedRound1SuccessorHistoryBootstrapAuthority&& bootstrap_history,
        FreshOwnerRoundContinuityAuthority&& continuity,
        FreshOwnerSameRoundRetryAuthority&& retry,
        std::optional<BaselineOwnerRosterAuthority>&& roster,
        std::optional<CandidateOwnerTruthPendingAuthority>&& candidate_truth,
        std::optional<V3AcceptedRound1HistoryResidualAuthority>&& v3_history)
        noexcept
    : roster_(std::move(roster)),
      candidate_truth_(std::move(candidate_truth)),
      v3_history_(std::move(v3_history)) {
    driver_round_.emplace(std::move(driver));
    bootstrap_history_.emplace(std::move(bootstrap_history));
    continuity_.emplace(std::move(continuity));
    retry_.emplace(std::move(retry));
}

FreshOwnerRound2IssuedAuthority::FreshOwnerRound2IssuedAuthority(
        FreshOwnerRound2IssuedAuthority&& other) noexcept
    : driver_round_(std::move(other.driver_round_)),
      bootstrap_history_(std::move(other.bootstrap_history_)),
      continuity_(std::move(other.continuity_)),
      retry_(std::move(other.retry_)), roster_(std::move(other.roster_)),
      candidate_truth_(std::move(other.candidate_truth_)),
      v3_history_(std::move(other.v3_history_)) {}

FreshOwnerRoundAuthority
FreshOwnerRound2IssuedAuthority::take_driver_round() {
    need(driver_round_.has_value());
    FreshOwnerRoundAuthority result(std::move(*driver_round_));
    driver_round_.reset();
    return result;
}

AcceptedRound1SuccessorHistoryBootstrapAuthority
FreshOwnerRound2IssuedAuthority::take_bootstrap_history() {
    need(bootstrap_history_.has_value());
    AcceptedRound1SuccessorHistoryBootstrapAuthority result(
        std::move(*bootstrap_history_));
    bootstrap_history_.reset();
    return result;
}

FreshOwnerRoundContinuityAuthority
FreshOwnerRound2IssuedAuthority::take_continuity() {
    need(continuity_.has_value());
    FreshOwnerRoundContinuityAuthority result(std::move(*continuity_));
    continuity_.reset();
    return result;
}

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
FreshOwnerSameRoundRetryAuthority
FreshOwnerRound2IssuedAuthority::take_same_round_retry() {
    need(retry_.has_value());
    FreshOwnerSameRoundRetryAuthority result(std::move(*retry_));
    retry_.reset();
    return result;
}
#endif

BaselineOwnerRosterAuthority
FreshOwnerRound2IssuedAuthority::take_baseline_roster() {
    need(roster_.has_value());
    BaselineOwnerRosterAuthority result(std::move(*roster_));
    roster_.reset();
    return result;
}

CandidateOwnerTruthPendingAuthority
FreshOwnerRound2IssuedAuthority::take_candidate_truth_pending() {
    need(candidate_truth_.has_value());
    CandidateOwnerTruthPendingAuthority result(
        std::move(*candidate_truth_));
    candidate_truth_.reset();
    return result;
}

V3AcceptedRound1HistoryResidualAuthority
FreshOwnerRound2IssuedAuthority::take_v3_history_residual() {
    need(v3_history_.has_value());
    V3AcceptedRound1HistoryResidualAuthority result(
        std::move(*v3_history_));
    v3_history_.reset();
    return result;
}

FreshOwnerProcessSupervisor::FreshOwnerProcessSupervisor(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) {}

FreshOwnerProcessSupervisor::FreshOwnerProcessSupervisor(
        FreshOwnerProcessSupervisor&& other) noexcept
    : storage_(std::move(other.storage_)) {}

FreshOwnerProcessSupervisor::~FreshOwnerProcessSupervisor() {
    if (storage_ != nullptr) storage_->terminate();
}

bool FreshOwnerProcessSupervisor::
retains_transactional_round1_lineage() const noexcept {
    return storage_ != nullptr &&
        storage_->transactional_issuance.has_value() &&
        storage_->transactional_issuance->retains_round1_process_lineage();
}

FreshOwnerProcessSupervisor
FreshOwnerProcessSupervisor::launch_exact_three(
        CompiledPrivateLifecycleOwnerProgramAuthority&& selected,
        std::array<OwnerPrivateRootAuthority, 3>&& roots) {
    auto storage = std::make_unique<Storage>();
    std::array<std::array<int, 2>, 3> sockets{{
        {-1, -1}, {-1, -1}, {-1, -1}}};
    std::array<std::array<int, 2>, 3> truth_sockets{{
        {-1, -1}, {-1, -1}, {-1, -1}}};
    // pidfd_open happens immediately after each fork. The precondition makes
    // the narrow pre-pidfd cleanup fallback safe: no handler or second waiter
    // can reap the still-owned child and permit PID reuse in that interval.
    require_owner_fork_environment();
    try {
        need(selected.live_.exchange(false) && selected.program_ != nullptr);
        storage->plan = std::move(selected.plan_);
        storage->program = std::move(selected.program_);
        const auto parent_pid = ::getpid();
        need(parent_pid > 1);
        storage->launch = PublicFreshOwnerProcessLaunch{
            .parent_pid = static_cast<std::int64_t>(parent_pid),
            .process_authority_identity =
                storage->plan.process_authority_identity,
            .supervisor_session_identity = random_digest(),
            .run = storage->plan.run,
            .trial = storage->plan.trial,
            .root_identity = storage->plan.root_identity,
        };

        std::set<std::pair<std::uint64_t, std::uint64_t>> root_objects;
        std::set<Digest> root_metadata;
        for (unsigned owner = 0; owner < 3; ++owner) {
            auto& root = roots[owner];
            struct stat current_root{};
            need(root.live_.exchange(false) &&
                 root.receipt_.owner_component == owner &&
                 root.receipt_.root_identity == storage->plan.root_identity &&
                 root.fd_ >= 0 &&
                 ::fstat(root.fd_, &current_root) == 0 &&
                 S_ISDIR(current_root.st_mode) &&
                 static_cast<std::uint64_t>(current_root.st_dev) ==
                     root.device_ &&
                 static_cast<std::uint64_t>(current_root.st_ino) ==
                     root.inode_ &&
                 root_objects.emplace(root.device_, root.inode_).second &&
                 root_metadata.insert(
                     root.receipt_.owner_root_metadata_identity).second);
            storage->root_objects[owner] = {root.device_, root.inode_};
            need(::socketpair(
                AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0,
                sockets[owner].data()) == 0);
            set_passcred(sockets[owner][0]);
            set_passcred(sockets[owner][1]);
            if (storage->plan.classification ==
                registered_driver::CaptureClassification::HiddenCandidate) {
                need(::socketpair(
                    AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0,
                    truth_sockets[owner].data()) == 0);
                set_passcred(truth_sockets[owner][0]);
                set_passcred(truth_sockets[owner][1]);
            }
            storage->launch.children[owner] = PublicOwnerProcessChild{
                .owner_component = owner,
                .child_session_identity = random_digest(),
                .root_metadata_identity =
                    root.receipt_.owner_root_metadata_identity,
            };
        }

        for (unsigned owner = 0; owner < 3; ++owner) {
            const pid_t pid = ::fork();
            need(pid >= 0);
            if (pid == 0) {
                const int code = child_main(
                    owner, sockets[owner][1], roots[owner].fd_,
                    truth_sockets[owner][1], roots[owner].device_,
                    roots[owner].inode_, parent_pid,
                    storage->launch.supervisor_session_identity,
                    storage->launch.children[owner].child_session_identity,
                    storage->plan.trial, storage->plan.classification,
                    storage->plan.owners[owner], storage->program);
                ::_exit(code);
            }
            storage->pids[owner] = pid;
            storage->pidfds[owner] = open_owner_pidfd(pid);
            storage->channels[owner] = sockets[owner][0];
            sockets[owner][0] = -1;
            storage->truth_channels[owner] = truth_sockets[owner][0];
            truth_sockets[owner][0] = -1;
            storage->launch.children[owner].child_pid = pid;
            storage->launch.children[owner].owner_process_identity =
                process_identity(
                    storage->plan, owner, parent_pid, pid,
                    storage->launch.children[owner].child_session_identity,
                    storage->launch.children[owner].root_metadata_identity);
        }
        for (auto& pair : sockets) close_fd(pair[1]);
        for (auto& pair : truth_sockets) close_fd(pair[1]);

        for (unsigned owner = 0; owner < 3; ++owner) {
            const auto& child = storage->launch.children[owner];
            send_packet(storage->channels[owner], packet(
                WireKind::Bootstrap, owner, 0,
                storage->launch.supervisor_session_identity,
                child.child_session_identity));
        }
        std::set<LogicalOwnerIdentity> logical_owner_ids;
        std::set<Digest> binding_nonces;
        std::set<Digest> file_identities;
        std::set<Digest> file_metadata_identities;
        std::set<Digest> input_lineages;
        for (unsigned owner = 0; owner < 3; ++owner) {
            const auto reply = receive_packet(
                storage->channels[owner], storage->pids[owner]);
            need(reply.kind == WireKind::BootstrapAck &&
                 reply.owner == owner && reply.round == 0 &&
                 reply.supervisor_session ==
                     storage->launch.supervisor_session_identity &&
                 reply.child_session ==
                     storage->launch.children[owner]
                         .child_session_identity &&
                 !zero(reply.logical_owner_identity) &&
                 !zero(reply.binding_nonce) &&
                 !zero(reply.file_identity) &&
                 !zero(reply.file_metadata_identity) &&
                 !zero(reply.second_file_identity) &&
                 !zero(reply.second_file_metadata_identity) &&
                 !zero(reply.input_lineage_identity) &&
                 !zero(reply.second_input_lineage_identity) &&
                 logical_owner_ids.insert(
                     reply.logical_owner_identity).second &&
                 binding_nonces.insert(reply.binding_nonce).second &&
                 file_identities.insert(reply.file_identity).second &&
                 file_identities.insert(
                     reply.second_file_identity).second &&
                 file_metadata_identities.insert(
                     reply.file_metadata_identity).second &&
                 file_metadata_identities.insert(
                     reply.second_file_metadata_identity).second &&
                 input_lineages.insert(
                     reply.input_lineage_identity).second &&
                 input_lineages.insert(
                     reply.second_input_lineage_identity).second);
            storage->logical_owner_ids[owner] =
                reply.logical_owner_identity;
            storage->input_lineages[owner] = {
                reply.input_lineage_identity,
                reply.second_input_lineage_identity};
            storage->plan.owners[owner].rounds[0].file_identity =
                reply.file_identity;
            storage->plan.owners[owner].rounds[0].file_metadata_identity =
                reply.file_metadata_identity;
            storage->plan.owners[owner].rounds[1].file_identity =
                reply.second_file_identity;
            storage->plan.owners[owner].rounds[1].file_metadata_identity =
                reply.second_file_metadata_identity;
            storage->round1_results[owner] = PrivateOwnerChildRoundResult{
                .file_identity = reply.file_identity,
                .file_metadata_identity = reply.file_metadata_identity,
                .input_lineage_identity = reply.input_lineage_identity,
                .logical_owner_identity = reply.logical_owner_identity,
                .binding_nonce = reply.binding_nonce,
                .verifier_record = reply.verifier_record,
            };
            storage->verifiers[owner] =
                storage->program->admit_parent_verifier(
                    owner, reply.verifier_record);
            need(storage->verifiers[owner] != nullptr);
        }
        // ACK proves each fixed child retained its own transferred root.  The
        // parent now closes every alias before returning the supervisor.
        for (auto& root : roots) close_fd(root.fd_);

        for (unsigned owner = 0; owner < 3; ++owner) {
            const auto& process = storage->plan.owners[owner];
            storage->receipts[owner] = PublicOwnerIssuanceReceipt{
                .classification = storage->plan.classification,
                .authority_identity =
                    storage->plan.process_authority_identity,
                .registration_identity = storage->plan.registration_identity,
                .service_identity = storage->plan.service_identity,
                .controller_source_identity =
                    storage->plan.controller_source_identity,
                .controller_build_identity =
                    storage->plan.controller_build_identity,
                .owner_issuer_source_identity =
                    storage->plan.owner_issuer_source_identity,
                .owner_issuer_build_identity =
                    storage->plan.owner_issuer_build_identity,
                .run = storage->plan.run,
                .trial = storage->plan.trial,
                .root_identity = storage->plan.root_identity,
                .baseline_policy_identity =
                    storage->plan.baseline_policy_identity,
                .owner_component = owner,
                .owner_process_identity =
                    storage->launch.children[owner]
                        .owner_process_identity,
                .rounds = process.rounds,
            };
        }
        return FreshOwnerProcessSupervisor(std::move(storage));
    } catch (...) {
        for (auto& pair : sockets) {
            close_fd(pair[0]); close_fd(pair[1]);
        }
        for (auto& pair : truth_sockets) {
            close_fd(pair[0]); close_fd(pair[1]);
        }
        for (auto& root : roots) close_fd(root.fd_);
        storage->terminate();
        refuse();
    }
}

const PublicFreshOwnerProcessLaunch&
FreshOwnerProcessSupervisor::public_receipt() const {
    need(storage_ != nullptr);
    return storage_->launch;
}

FreshOwnerPrivateArmLaunchAuthority
FreshOwnerProcessSupervisor::take_private_arm_launch() {
    try {
        need(storage_ != nullptr && !storage_->poisoned &&
             !storage_->completed && !storage_->round1_issued &&
             !storage_->private_arm_launch_taken);
        FreshOwnerPrivateArmLaunchAuthority::Evidence evidence{
            .classification = storage_->plan.classification,
            .process_authority_identity =
                storage_->plan.process_authority_identity,
            .supervisor_session_identity =
                storage_->launch.supervisor_session_identity,
            .logical_owner_ids = storage_->logical_owner_ids,
        };
        const bool candidate = storage_->plan.classification ==
            registered_driver::CaptureClassification::HiddenCandidate;
        for (unsigned owner = 0; owner < 3; ++owner) {
            const auto& child = storage_->launch.children[owner];
            need(storage_->pids[owner] == child.child_pid &&
                 storage_->pids[owner] > 1 &&
                 ::kill(storage_->pids[owner], 0) == 0 &&
                 storage_->channels[owner] >= 0 &&
                 ((candidate && storage_->truth_channels[owner] >= 0) ||
                  (!candidate && storage_->truth_channels[owner] < 0)));
            evidence.child_pids[owner] = child.child_pid;
            evidence.child_sessions[owner] = child.child_session_identity;
            evidence.root_slots[owner] = {
                storage_->root_objects[owner].first,
                storage_->root_objects[owner].second};
            for (unsigned index = 0; index < 2; ++index) {
                const unsigned slot = index * 3 + owner;
                const auto& round = storage_->receipts[owner].rounds[index];
                evidence.contract_ids[slot] =
                    owner_contract_identity(round.contract);
                evidence.owner_tls_cert_ids[slot] = checked_identity_hex(
                    round.contract.owner_certificate_sha256);
                evidence.owner_tls_spki_ids[slot] =
                    round.owner_tls_spki_identity;
                for (unsigned role = 0; role < 3; ++role) {
                    evidence.server_tls_cert_ids[slot][role] =
                        checked_identity_hex(
                            round.contract.server_certificate_sha256[role]);
                    evidence.server_tls_spki_ids[slot][role] =
                        round.server_tls_spki_identities[role];
                }
            }
        }
        FreshOwnerPrivateArmLaunchAuthority result(std::move(evidence));
        storage_->private_arm_launch_taken = true;
        return result;
    } catch (...) {
        if (storage_ != nullptr) storage_->terminate();
        refuse();
    }
}

FreshOwnerRound1IssuedAuthority
FreshOwnerProcessSupervisor::issue_round1_from_testnet_history(
        const kpb::testnet_history::PublicAcceptedHistoryStage& confirmed,
        registered_driver::RegisteredPreidentityReadyAuthority* ready,
        OwnerIssuanceReplayGuardAuthority&& replay,
        FreshOwnerArmIsolationResidualAuthority&& isolation) {
    auto owned_replay = std::move(replay);
    auto owned_isolation = std::move(isolation);
    try {
        need(storage_ != nullptr && !storage_->poisoned &&
             !storage_->round1_issued && !storage_->completed);
        const auto& planned = storage_->receipts[0].rounds[0];
        need(confirmed.network ==
                 kpb::testnet_activation::NetworkScope::KaspaTestnet10 &&
             confirmed.stage == kpb::testnet_history::
                 AcceptedHistoryStage::GenesisRound1Input &&
             confirmed.run == storage_->plan.run &&
             confirmed.trial == storage_->plan.trial &&
             confirmed.round1_attempt == planned.attempt &&
             confirmed.round1_cohort == planned.cohort &&
             confirmed.accepted_head_identity ==
                 planned.accepted_input_head_identity &&
             confirmed.history_gate_identity ==
                 planned.history_gate_identity &&
             zero(confirmed.predecessor_confirmation_identity) &&
             !zero(confirmed.source_session_identity) &&
             !zero(confirmed.confirmation_identity));
        const PublicAcceptedRound1InputHistory receipt{
            .authority_identity = confirmed.confirmation_identity,
            .run = confirmed.run,
            .trial = confirmed.trial,
            .round1_attempt = confirmed.round1_attempt,
            .round1_cohort = confirmed.round1_cohort,
            .accepted_input_head_identity =
                confirmed.accepted_head_identity,
            .history_gate_identity = confirmed.history_gate_identity,
        };
        const std::array<Digest, 3> lineages{
            storage_->input_lineages[0][0],
            storage_->input_lineages[1][0],
            storage_->input_lineages[2][0],
        };
        return issue_round1_impl(
            AcceptedRound1InputHistoryAuthority(receipt, lineages),
            ready,
            std::move(owned_replay), std::move(owned_isolation));
    } catch (...) {
        if (storage_ != nullptr) storage_->terminate();
        refuse();
    }
}

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
FreshOwnerRound1IssuedAuthority
FreshOwnerProcessSupervisor::issue_round1(
        AcceptedRound1InputHistoryAuthority&& history,
        registered_driver::RegisteredPreidentityReadyAuthority&& ready,
        OwnerIssuanceReplayGuardAuthority&& replay,
        FreshOwnerArmIsolationResidualAuthority&& isolation) {
    return issue_round1_impl(
        std::move(history), &ready, std::move(replay),
        std::move(isolation));
}
#endif

#ifndef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
FreshOwnerRound1AttemptOutcomeAuthority
FreshOwnerProcessSupervisor::issue_round1(
        AcceptedRound1InputHistoryAuthority&& history,
        registered_driver::RegisteredPreidentityReadyAuthority&& ready,
        kpb::measurement::fresh_owner_transactional_replay::
            SelectedOwnerReplayRegistryAuthority&& replay,
        FreshOwnerArmIsolationResidualAuthority&& isolation) {
    return issue_round1_transactional_impl(
        std::move(history), std::move(ready), std::move(replay),
        std::move(isolation));
}
#else
FreshOwnerRound1AttemptOutcomeAuthority
FreshOwnerProcessSupervisor::issue_round1_transactional(
        AcceptedRound1InputHistoryAuthority&& history,
        registered_driver::RegisteredPreidentityReadyAuthority&& ready,
        kpb::measurement::fresh_owner_transactional_replay::
            SelectedOwnerReplayRegistryAuthority&& replay,
        FreshOwnerArmIsolationResidualAuthority&& isolation) {
    return issue_round1_transactional_impl(
        std::move(history), std::move(ready), std::move(replay),
        std::move(isolation));
}
#endif

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
FreshOwnerRound1IssuedAuthority
FreshOwnerProcessSupervisor::issue_round1(
        AcceptedRound1InputHistoryAuthority&& history,
        OwnerIssuanceReplayGuardAuthority&& replay,
        FreshOwnerArmIsolationResidualAuthority&& isolation) {
    return issue_round1_impl(
        std::move(history), nullptr, std::move(replay),
        std::move(isolation));
}
#endif

FreshOwnerRound1AttemptOutcomeAuthority
FreshOwnerProcessSupervisor::issue_round1_transactional_impl(
        AcceptedRound1InputHistoryAuthority&& history,
        registered_driver::RegisteredPreidentityReadyAuthority&& ready,
        kpb::measurement::fresh_owner_transactional_replay::
            SelectedOwnerReplayRegistryAuthority&& replay,
        FreshOwnerArmIsolationResidualAuthority&& isolation) {
    auto outcome =
        std::make_unique<FreshOwnerRound1AttemptOutcomeStorage>();
    auto continuity_storage =
        std::make_unique<FreshOwnerRoundContinuityAuthority::Storage>();
    auto retry_storage =
        std::make_unique<FreshOwnerSameRoundRetryAuthority::Storage>();

    static_assert(std::is_nothrow_move_constructible_v<
        AcceptedRound1InputHistoryAuthority>);
    static_assert(std::is_nothrow_move_constructible_v<
        FreshOwnerArmIsolationResidualAuthority>);
    static_assert(std::is_nothrow_move_constructible_v<
        registered_driver::RegisteredPreidentityReadyAuthority>);
    static_assert(std::is_nothrow_move_constructible_v<
        kpb::measurement::fresh_owner_transactional_replay::
            SelectedOwnerReplayRegistryAuthority>);
    static_assert(std::is_nothrow_move_constructible_v<
        FreshOwnerProcessSupervisor>);
    static_assert(std::is_nothrow_move_constructible_v<
        FreshOwnerRound1ConsumedGateResidual>);
    static_assert(std::is_nothrow_move_constructible_v<
        FreshOwnerTransactionalIssuanceOutcomeAuthority>);
    static_assert(std::is_nothrow_move_constructible_v<
        FreshOwnerTrialIssuanceAuthority>);
    static_assert(noexcept(std::declval<std::optional<
        AcceptedRound1InputHistoryAuthority>&>().emplace(
            std::declval<AcceptedRound1InputHistoryAuthority&&>())));
    static_assert(noexcept(std::declval<std::optional<
        FreshOwnerArmIsolationResidualAuthority>&>().emplace(
            std::declval<FreshOwnerArmIsolationResidualAuthority&&>())));
    static_assert(noexcept(std::declval<std::optional<registered_driver::
        RegisteredPreidentityReadyAuthority>&>().emplace(
            std::declval<registered_driver::
                RegisteredPreidentityReadyAuthority&&>())));
    static_assert(noexcept(std::declval<std::optional<
        kpb::measurement::fresh_owner_transactional_replay::
            SelectedOwnerReplayRegistryAuthority>&>().emplace(
                std::declval<kpb::measurement::
                    fresh_owner_transactional_replay::
                        SelectedOwnerReplayRegistryAuthority&&>())));
    static_assert(noexcept(std::declval<std::optional<
        FreshOwnerProcessSupervisor>&>().emplace(
            std::declval<FreshOwnerProcessSupervisor&&>())));
    static_assert(noexcept(std::declval<std::optional<
        FreshOwnerTransactionalIssuanceOutcomeAuthority>&>().emplace(
            std::declval<
                FreshOwnerTransactionalIssuanceOutcomeAuthority&&>())));
    static_assert(noexcept(std::declval<std::optional<
        FreshOwnerTrialIssuanceAuthority>&>().emplace(
            std::declval<FreshOwnerTrialIssuanceAuthority&&>())));
    static_assert(std::is_nothrow_move_constructible_v<
        FreshOwnerRound1IssuedAuthority>);
    static_assert(noexcept(std::declval<std::optional<
        FreshOwnerRound1IssuedAuthority>&>().emplace(
            std::declval<FreshOwnerRound1IssuedAuthority&&>())));
    static_assert(noexcept(std::declval<std::optional<
        FreshOwnerRound1ConsumedGateResidual>&>().emplace(
            std::declval<FreshOwnerRound1ConsumedGateResidual&&>())));

    auto stop = [&]() noexcept {
        if (!outcome->consumed_gate.has_value()) {
            outcome->unclaimed_history.emplace(std::move(history));
            outcome->unclaimed_isolation.emplace(std::move(isolation));
        }
        if (storage_ == nullptr ||
            !storage_->transactional_issuance.has_value()) {
            outcome->unclaimed_ready.emplace(std::move(ready));
            outcome->unclaimed_registry.emplace(std::move(replay));
        }
        if (storage_ != nullptr) storage_->terminate();
        outcome->stopped_supervisor.emplace(std::move(*this));
        outcome->state =
            FreshOwnerRound1AttemptOutcomeState::UnavailableStop;
        return FreshOwnerRound1AttemptOutcomeAuthority(
            std::move(outcome));
    };

    try {
        // All checks and allocations before the transactional join leave the
        // four caller capabilities live. Once the join returns, every later
        // failure is caught by the no-allocation STOP path above.
        need(storage_ != nullptr && !storage_->poisoned &&
             !storage_->round1_issued && !storage_->completed &&
             storage_->private_arm_launch_taken && history.live_.load() &&
             isolation.live_.load() &&
             isolation.classification_ == storage_->plan.classification &&
             isolation.process_authority_identity_ ==
                 storage_->plan.process_authority_identity &&
             isolation.supervisor_session_identity_ ==
                 storage_->launch.supervisor_session_identity &&
             !zero(isolation.isolation_authority_identity_));
        const auto input_history = history.receipt_;
        const auto input_lineages = history.input_lineages_;
        const auto& planned_round = storage_->receipts[0].rounds[0];
        need(input_history.run == storage_->plan.run &&
             input_history.trial == storage_->plan.trial &&
             input_history.round1_attempt == planned_round.attempt &&
             input_history.round1_cohort == planned_round.cohort &&
             input_history.accepted_input_head_identity ==
                 planned_round.accepted_input_head_identity &&
             input_history.history_gate_identity ==
                 planned_round.history_gate_identity &&
             !zero(input_history.authority_identity));
        for (unsigned owner = 0; owner < 3; ++owner)
            need(input_lineages[owner] ==
                 storage_->input_lineages[owner][0]);
        AcceptedRound1InputHistoryBootstrapAuthority prepared_bootstrap(
            input_history);

        const Digest prepared_continuation = continuation_identity(
            storage_->launch, storage_->receipts);
        AuthenticatedOwnerProcessBundle owner0(
            storage_->receipts[0], storage_->verifiers[0],
            storage_->round1_results[0].logical_owner_identity,
            storage_->round1_results[0].binding_nonce);
        AuthenticatedOwnerProcessBundle owner1(
            storage_->receipts[1], storage_->verifiers[1],
            storage_->round1_results[1].logical_owner_identity,
            storage_->round1_results[1].binding_nonce);
        AuthenticatedOwnerProcessBundle owner2(
            storage_->receipts[2], storage_->verifiers[2],
            storage_->round1_results[2].logical_owner_identity,
            storage_->round1_results[2].binding_nonce);

        auto transactional =
            FreshOwnerTransactionalIssuanceBridge::
                join_authenticated_exact_three(
                    std::move(ready), std::move(owner0),
                    std::move(owner1), std::move(owner2),
                    std::move(replay),
                    storage_->plan.roster_authority_identity);
        if (!transactional.committed_for_round1_process()) {
            storage_->transactional_issuance.emplace(
                std::move(transactional));
            return stop();
        }
        auto reservation =
            transactional.take_committed_for_round1_process();
        storage_->transactional_issuance.emplace(
            std::move(transactional));
        storage_->reserved_trial.emplace(std::move(reservation));
        storage_->round1_transaction_committed = true;
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
        inject_round1_attempt_fault(
            FreshOwnerRound1AttemptTestFault::AfterTransactionalJoin);
#endif

        if (!history.live_.exchange(false) ||
            !isolation.live_.exchange(false))
            std::terminate();
        outcome->consumed_gate.emplace(
            FreshOwnerRound1ConsumedGateResidual(
                input_history, input_lineages, isolation.classification_,
                isolation.isolation_authority_identity_,
                isolation.process_authority_identity_,
                isolation.supervisor_session_identity_));
        storage_->arm_isolation_identity =
            isolation.isolation_authority_identity_;

        for (unsigned owner = 0; owner < 3; ++owner) {
            const auto& child = storage_->launch.children[owner];
            auto command = packet(
                WireKind::IssueRound, owner, 1,
                storage_->launch.supervisor_session_identity,
                child.child_session_identity);
            command.accepted_input_head_identity =
                storage_->receipts[owner].rounds[0]
                    .accepted_input_head_identity;
            command.history_gate_identity =
                storage_->receipts[owner].rounds[0]
                    .history_gate_identity;
            command.command_identity = command_identity(
                command.supervisor_session, command.child_session,
                owner, 1, command.accepted_input_head_identity,
                command.history_gate_identity);
            finish_packet(command);
            send_packet(storage_->channels[owner], command);
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
            if (owner == 0)
                inject_round1_attempt_fault(
                    FreshOwnerRound1AttemptTestFault::
                        AfterFirstChildSend);
#endif
        }

        std::array<Digest, 3> files{}, metadata{}, logical_ids{};
        for (unsigned owner = 0; owner < 3; ++owner) {
            const auto response = receive_packet(
                storage_->channels[owner], storage_->pids[owner]);
            const auto& child = storage_->launch.children[owner];
            const auto& selected = storage_->receipts[owner].rounds[0];
            const auto bootstrap_identity =
                storage_->round1_results[owner];
            const auto expected_command = command_identity(
                storage_->launch.supervisor_session_identity,
                child.child_session_identity, owner, 1,
                selected.accepted_input_head_identity,
                selected.history_gate_identity);
            need(response.kind == WireKind::RoundResult &&
                 response.owner == owner && response.round == 1 &&
                 response.command_identity == expected_command &&
                 response.accepted_input_head_identity ==
                     selected.accepted_input_head_identity &&
                 response.history_gate_identity ==
                     selected.history_gate_identity &&
                 response.file_identity == selected.file_identity &&
                 response.file_metadata_identity ==
                     selected.file_metadata_identity &&
                 response.input_lineage_identity ==
                     storage_->input_lineages[owner][0] &&
                 response.logical_owner_identity ==
                     bootstrap_identity.logical_owner_identity &&
                 response.binding_nonce ==
                     bootstrap_identity.binding_nonce &&
                 response.verifier_record ==
                     bootstrap_identity.verifier_record);
            for (unsigned prior = 0; prior < owner; ++prior)
                need(response.file_identity != files[prior] &&
                     response.file_metadata_identity != metadata[prior] &&
                     response.logical_owner_identity != logical_ids[prior]);
            files[owner] = response.file_identity;
            metadata[owner] = response.file_metadata_identity;
            logical_ids[owner] = response.logical_owner_identity;
            storage_->round1_results[owner] = PrivateOwnerChildRoundResult{
                .file_identity = response.file_identity,
                .file_metadata_identity = response.file_metadata_identity,
                .input_lineage_identity =
                    response.input_lineage_identity,
                .logical_owner_identity =
                    response.logical_owner_identity,
                .binding_nonce = response.binding_nonce,
                .verifier_record = response.verifier_record,
            };
            storage_->receipts[owner].rounds[0].file_identity =
                response.file_identity;
            storage_->receipts[owner].rounds[0].file_metadata_identity =
                response.file_metadata_identity;
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
            if (owner == 0)
                inject_round1_attempt_fault(
                    FreshOwnerRound1AttemptTestFault::
                        AfterFirstChildResponse);
#endif
        }

        storage_->round1_issued = true;
        storage_->continuation = prepared_continuation;
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
        inject_round1_attempt_fault(
            FreshOwnerRound1AttemptTestFault::AfterAllChildResponses);
        inject_round1_attempt_fault(
            FreshOwnerRound1AttemptTestFault::BeforeIssuanceSplit);
#endif
        auto split = FreshOwnerTrialIssuanceBridge::split(
            std::move(*storage_->reserved_trial));
        storage_->reserved_trial.reset();
        if (!split.rounds_[0].has_value() ||
            !split.rounds_[1].has_value() ||
            !split.persistent_activation_.has_value() ||
            !split.producer_closure_.has_value())
            std::terminate();
        storage_->reserved_round1_driver.emplace(
            std::move(*split.rounds_[0]));
        split.rounds_[0].reset();
        storage_->reserved_round2.emplace(
            std::move(*split.rounds_[1]));
        split.rounds_[1].reset();
        storage_->reserved_persistent_activation.emplace(
            std::move(*split.persistent_activation_));
        split.persistent_activation_.reset();
        storage_->reserved_producer_closure.emplace(
            std::move(*split.producer_closure_));
        split.producer_closure_.reset();
        if (split.roster_.has_value()) {
            storage_->reserved_roster.emplace(
                std::move(*split.roster_));
            split.roster_.reset();
        }
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
        inject_round1_attempt_fault(
            FreshOwnerRound1AttemptTestFault::
                AfterSplitDescendantsRetained);
#endif

        auto& driver = *storage_->reserved_round1_driver;
        const auto continuity_record = storage_->continuity_record(
            1, driver.public_receipt().issuance_identity);
        continuity_storage->record = continuity_record;
        retry_storage->record = continuity_record;
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
        inject_round1_attempt_fault(
            FreshOwnerRound1AttemptTestFault::AfterContinuityPrepared);
#endif
        FreshOwnerRoundContinuityAuthority prepared_continuity(
            std::move(continuity_storage));
        FreshOwnerSameRoundRetryAuthority prepared_retry(
            std::move(retry_storage));
        FreshOwnerRound1IssuedAuthority prepared_issued(
            std::move(*storage_->reserved_round1_driver),
            std::move(prepared_bootstrap), std::move(prepared_continuity),
            std::move(prepared_retry),
            std::move(*storage_->reserved_persistent_activation),
            std::move(*storage_->reserved_producer_closure),
            storage_->launch.supervisor_session_identity,
            storage_->continuation, input_history, input_lineages,
            storage_->plan.measurement_run_binding_identity,
            storage_->plan.candidate_truth_financial_runs,
            storage_->plan.candidate_truth_capture_plan_identities,
            storage_->plan.candidate_truth_projection_identities,
            storage_->plan.candidate_truth_context_identities);
        outcome->issued.emplace(std::move(prepared_issued));
        storage_->reserved_round1_driver.reset();
        storage_->reserved_persistent_activation.reset();
        storage_->reserved_producer_closure.reset();
        outcome->state = FreshOwnerRound1AttemptOutcomeState::Success;
        return FreshOwnerRound1AttemptOutcomeAuthority(
            std::move(outcome));
    } catch (...) {
        return stop();
    }
}

FreshOwnerRound1IssuedAuthority
FreshOwnerProcessSupervisor::issue_round1_impl(
        AcceptedRound1InputHistoryAuthority&& history,
        registered_driver::RegisteredPreidentityReadyAuthority* ready,
        OwnerIssuanceReplayGuardAuthority&& replay,
        FreshOwnerArmIsolationResidualAuthority&& isolation) {
    try {
        need(storage_ != nullptr && !storage_->poisoned &&
             !storage_->round1_issued && !storage_->completed &&
             storage_->private_arm_launch_taken &&
             history.live_.exchange(false) &&
             isolation.live_.exchange(false) &&
             isolation.classification_ == storage_->plan.classification &&
             isolation.process_authority_identity_ ==
                 storage_->plan.process_authority_identity &&
             isolation.supervisor_session_identity_ ==
                 storage_->launch.supervisor_session_identity &&
             !zero(isolation.isolation_authority_identity_));
        storage_->arm_isolation_identity =
            isolation.isolation_authority_identity_;
        const auto input_history = history.receipt_;
        const auto& planned_round = storage_->receipts[0].rounds[0];
        need(input_history.run == storage_->plan.run &&
             input_history.trial == storage_->plan.trial &&
             input_history.round1_attempt == planned_round.attempt &&
             input_history.round1_cohort == planned_round.cohort &&
             input_history.accepted_input_head_identity ==
                 planned_round.accepted_input_head_identity &&
             input_history.history_gate_identity ==
                 planned_round.history_gate_identity &&
             !zero(input_history.authority_identity));
        for (unsigned owner = 0; owner < 3; ++owner)
            need(history.input_lineages_[owner] ==
                 storage_->input_lineages[owner][0]);

        std::optional<registered_driver::
            RegisteredPreidentityReadyOwnerIssuanceSession>
                issuance_session;
        auto authorities = [&]() {
            if (ready != nullptr) {
                issuance_session.emplace(
                    registered_driver::
                        RegisteredPreidentityReadyIssuanceBridge::begin(
                            std::move(*ready)));
                return std::array<OwnerLocalIssuanceAuthority, 3>{
                    FreshOwnerProcessMintBridge::mint_owner(
                        AuthenticatedOwnerProcessBundle(
                            storage_->receipts[0], storage_->verifiers[0],
                            storage_->round1_results[0]
                                .logical_owner_identity,
                            storage_->round1_results[0].binding_nonce),
                        registered_driver::
                            RegisteredPreidentityReadyIssuanceBridge::
                                take_owner_permit(*issuance_session, 0)),
                    FreshOwnerProcessMintBridge::mint_owner(
                        AuthenticatedOwnerProcessBundle(
                            storage_->receipts[1], storage_->verifiers[1],
                            storage_->round1_results[1]
                                .logical_owner_identity,
                            storage_->round1_results[1].binding_nonce),
                        registered_driver::
                            RegisteredPreidentityReadyIssuanceBridge::
                                take_owner_permit(*issuance_session, 1)),
                    FreshOwnerProcessMintBridge::mint_owner(
                        AuthenticatedOwnerProcessBundle(
                            storage_->receipts[2], storage_->verifiers[2],
                            storage_->round1_results[2]
                                .logical_owner_identity,
                            storage_->round1_results[2].binding_nonce),
                        registered_driver::
                            RegisteredPreidentityReadyIssuanceBridge::
                                take_owner_permit(*issuance_session, 2)),
                };
            }
#if defined(KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP) && \
    defined(KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP)
            return std::array<OwnerLocalIssuanceAuthority, 3>{
                FreshOwnerProcessMintBridge::mint_owner(
                    AuthenticatedOwnerProcessBundle(
                        storage_->receipts[0], storage_->verifiers[0],
                        storage_->round1_results[0].logical_owner_identity,
                        storage_->round1_results[0].binding_nonce)),
                FreshOwnerProcessMintBridge::mint_owner(
                    AuthenticatedOwnerProcessBundle(
                        storage_->receipts[1], storage_->verifiers[1],
                        storage_->round1_results[1].logical_owner_identity,
                        storage_->round1_results[1].binding_nonce)),
                FreshOwnerProcessMintBridge::mint_owner(
                    AuthenticatedOwnerProcessBundle(
                        storage_->receipts[2], storage_->verifiers[2],
                        storage_->round1_results[2].logical_owner_identity,
                        storage_->round1_results[2].binding_nonce)),
            };
#else
            refuse();
#endif
        }();
        auto reservation = [&]() {
            if (issuance_session.has_value()) {
                auto issuance_ready = registered_driver::
                    RegisteredPreidentityReadyIssuanceBridge::finish(
                        std::move(*issuance_session));
                issuance_session.reset();
                return FreshOwnerTrialIssuanceBridge::join_exact_three(
                    std::move(issuance_ready), std::move(authorities),
                    std::move(replay),
                    storage_->plan.roster_authority_identity);
            }
#ifdef KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP
            return FreshOwnerTrialIssuanceBridge::join_exact_three(
                std::move(authorities), std::move(replay),
                storage_->plan.roster_authority_identity);
#else
            refuse();
#endif
        }();
        storage_->reserved_trial.emplace(std::move(reservation));
        for (unsigned owner = 0; owner < 3; ++owner) {
            const auto& child = storage_->launch.children[owner];
            auto command = packet(
                WireKind::IssueRound, owner, 1,
                storage_->launch.supervisor_session_identity,
                child.child_session_identity);
            command.accepted_input_head_identity =
                storage_->receipts[owner].rounds[0]
                    .accepted_input_head_identity;
            command.history_gate_identity =
                storage_->receipts[owner].rounds[0].history_gate_identity;
            command.command_identity = command_identity(
                command.supervisor_session, command.child_session,
                owner, 1, command.accepted_input_head_identity,
                command.history_gate_identity);
            finish_packet(command);
            send_packet(storage_->channels[owner], command);
        }
        std::set<Digest> files, metadata, logical_ids;
        for (unsigned owner = 0; owner < 3; ++owner) {
            const auto response = receive_packet(
                storage_->channels[owner], storage_->pids[owner]);
            const auto& child = storage_->launch.children[owner];
            const auto& selected = storage_->receipts[owner].rounds[0];
            const auto bootstrap_identity = storage_->round1_results[owner];
            const auto expected_command = command_identity(
                storage_->launch.supervisor_session_identity,
                child.child_session_identity, owner, 1,
                selected.accepted_input_head_identity,
                selected.history_gate_identity);
            need(response.kind == WireKind::RoundResult &&
                 response.owner == owner && response.round == 1 &&
                 response.command_identity == expected_command &&
                 response.accepted_input_head_identity ==
                     selected.accepted_input_head_identity &&
                 response.history_gate_identity ==
                     selected.history_gate_identity &&
                 response.file_identity == selected.file_identity &&
                 response.file_metadata_identity ==
                     selected.file_metadata_identity &&
                 response.input_lineage_identity ==
                     storage_->input_lineages[owner][0] &&
                 response.logical_owner_identity ==
                     bootstrap_identity.logical_owner_identity &&
                 response.binding_nonce ==
                     bootstrap_identity.binding_nonce &&
                 response.verifier_record ==
                     bootstrap_identity.verifier_record &&
                 files.insert(response.file_identity).second &&
                 metadata.insert(response.file_metadata_identity).second &&
                 logical_ids.insert(
                     response.logical_owner_identity).second);
            storage_->round1_results[owner] = PrivateOwnerChildRoundResult{
                .file_identity = response.file_identity,
                .file_metadata_identity = response.file_metadata_identity,
                .input_lineage_identity =
                    response.input_lineage_identity,
                .logical_owner_identity =
                    response.logical_owner_identity,
                .binding_nonce = response.binding_nonce,
                .verifier_record = response.verifier_record,
            };
            storage_->receipts[owner].rounds[0].file_identity =
                response.file_identity;
            storage_->receipts[owner].rounds[0].file_metadata_identity =
                response.file_metadata_identity;
        }
        storage_->round1_issued = true;
        storage_->continuation = continuation_identity(
            storage_->launch, storage_->receipts);
        auto split = FreshOwnerTrialIssuanceBridge::split(
            std::move(*storage_->reserved_trial));
        storage_->reserved_trial.reset();
        auto driver = split.take_round(1);
        std::optional<FreshOwnerPersistentActivationAuthority>
            persistent_activation;
        std::optional<FreshOwnerProducerClosureAuthority> producer_closure;
        if (ready != nullptr)
            persistent_activation.emplace(
                split.take_persistent_activation());
        if (ready != nullptr)
            producer_closure.emplace(split.take_producer_closure());
        storage_->reserved_round2.emplace(split.take_round(2));
        if (storage_->plan.classification ==
            registered_driver::CaptureClassification::
                ExplicitOwnerPublicEffectsBaseline)
            storage_->reserved_roster.emplace(
                split.take_baseline_roster());

        const auto continuity_record = storage_->continuity_record(
            1, driver.public_receipt().issuance_identity);
        auto continuity_storage =
            std::make_unique<FreshOwnerRoundContinuityAuthority::Storage>();
        continuity_storage->record = continuity_record;
        auto retry_storage =
            std::make_unique<FreshOwnerSameRoundRetryAuthority::Storage>();
        retry_storage->record = continuity_record;
        if (persistent_activation.has_value()) {
            need(producer_closure.has_value());
            return FreshOwnerRound1IssuedAuthority(
                std::move(driver),
                AcceptedRound1InputHistoryBootstrapAuthority(input_history),
                FreshOwnerRoundContinuityAuthority(
                    std::move(continuity_storage)),
                FreshOwnerSameRoundRetryAuthority(
                    std::move(retry_storage)),
                std::move(*persistent_activation),
                std::move(*producer_closure),
                storage_->launch.supervisor_session_identity,
                storage_->continuation, input_history,
                history.input_lineages_,
                storage_->plan.measurement_run_binding_identity,
                storage_->plan.candidate_truth_financial_runs,
                storage_->plan.candidate_truth_capture_plan_identities,
                storage_->plan.candidate_truth_projection_identities,
                storage_->plan.candidate_truth_context_identities);
        }
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
        return FreshOwnerRound1IssuedAuthority(
            std::move(driver),
            AcceptedRound1InputHistoryBootstrapAuthority(input_history),
            FreshOwnerRoundContinuityAuthority(
                std::move(continuity_storage)),
            FreshOwnerSameRoundRetryAuthority(std::move(retry_storage)),
            storage_->launch.supervisor_session_identity,
            storage_->continuation, input_history,
            history.input_lineages_,
            storage_->plan.measurement_run_binding_identity,
            storage_->plan.candidate_truth_financial_runs,
            storage_->plan.candidate_truth_capture_plan_identities,
            storage_->plan.candidate_truth_projection_identities,
            storage_->plan.candidate_truth_context_identities);
#else
        refuse();
#endif
    } catch (...) {
        if (storage_ != nullptr) storage_->terminate();
        refuse();
    }
}

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
FreshOwnerRound2IssuedAuthority
FreshOwnerProcessSupervisor::issue_round2_from_testnet_history(
        FreshOwnerRound1IssuedAuthority&& round1,
        const kpb::testnet_history::PublicAcceptedHistoryStage& confirmed) {
    auto owned_round1 = std::move(round1);
    try {
        need(storage_ != nullptr && !storage_->poisoned &&
             storage_->round1_issued && !storage_->round2_issued &&
             !storage_->completed);
        const auto& first = storage_->receipts[0];
        need(confirmed.network ==
                 kpb::testnet_activation::NetworkScope::KaspaTestnet10 &&
             confirmed.stage == kpb::testnet_history::
                 AcceptedHistoryStage::PaymentRound1Successor &&
             confirmed.run == storage_->plan.run &&
             confirmed.trial == storage_->plan.trial &&
             confirmed.round1_attempt == first.rounds[0].attempt &&
             confirmed.round1_cohort == first.rounds[0].cohort &&
             confirmed.accepted_head_identity ==
                 first.rounds[1].accepted_input_head_identity &&
             confirmed.history_gate_identity ==
                 first.rounds[1].history_gate_identity &&
             confirmed.predecessor_confirmation_identity ==
                 owned_round1.v3_input_history_.authority_identity &&
             confirmed.source_session_identity != Digest{} &&
             confirmed.confirmation_identity != Digest{} &&
             confirmed.confirmation_identity !=
                 confirmed.predecessor_confirmation_identity);
        const PublicAcceptedRound1SuccessorHistory receipt{
            .authority_identity = confirmed.confirmation_identity,
            .run = confirmed.run,
            .trial = confirmed.trial,
            .round1_attempt = confirmed.round1_attempt,
            .round1_cohort = confirmed.round1_cohort,
            .accepted_successor_head_identity =
                confirmed.accepted_head_identity,
            .history_gate_identity = confirmed.history_gate_identity,
        };
        const std::array<Digest, 3> lineages{
            storage_->input_lineages[0][1],
            storage_->input_lineages[1][1],
            storage_->input_lineages[2][1],
        };
        return issue_round2(
            std::move(owned_round1),
            AcceptedRound1SuccessorHistoryAuthority(receipt, lineages));
    } catch (...) {
        if (storage_ != nullptr) storage_->terminate();
        refuse();
    }
}

void FreshOwnerProcessSupervisor::poison_testnet_history_admission() noexcept {
    if (storage_ != nullptr) storage_->terminate();
}
#endif

FreshOwnerRound2AttemptOutcomeAuthority
FreshOwnerProcessSupervisor::issue_round2_transactional_impl(
        FreshOwnerRound1IssuedAuthority&& round1,
        AcceptedRound1SuccessorHistoryAuthority&& history) {
    // Allocate and build every derived authority before either linear input
    // is claimed. A preclaim failure therefore leaves both caller-owned
    // capabilities live. After the paired claim, only fixed storage, system
    // calls, and proven-noexcept moves remain.
    auto outcome = std::make_unique<FreshOwnerRound2AttemptOutcomeStorage>();
    auto continuity_storage =
        std::make_unique<FreshOwnerRoundContinuityAuthority::Storage>();
    auto retry_storage =
        std::make_unique<FreshOwnerSameRoundRetryAuthority::Storage>();

    need(storage_ != nullptr && !storage_->poisoned &&
         storage_->round1_issued && !storage_->round2_issued &&
         !storage_->completed && round1.live_.load() &&
         history.live_.load() &&
         !round1.driver_round_.has_value() &&
         !round1.bootstrap_history_.has_value() &&
         !round1.continuity_.has_value() &&
         !round1.persistent_activation_.has_value() &&
         !round1.producer_closure_.has_value() &&
         round1.supervisor_session_identity_ ==
             storage_->launch.supervisor_session_identity &&
         round1.continuation_identity_ == storage_->continuation &&
         storage_->reserved_round2.has_value());
    const auto gate = history.receipt_;
    const auto successor_lineages = history.successor_input_lineages_;
    const auto& first = storage_->receipts[0];
    need(gate.run == storage_->plan.run &&
         gate.trial == storage_->plan.trial &&
         gate.round1_attempt == first.rounds[0].attempt &&
         gate.round1_cohort == first.rounds[0].cohort &&
         gate.accepted_successor_head_identity ==
             first.rounds[1].accepted_input_head_identity &&
         gate.history_gate_identity ==
             first.rounds[1].history_gate_identity &&
         !zero(gate.authority_identity) &&
         !zero(gate.accepted_successor_head_identity) &&
         !zero(gate.history_gate_identity));
    for (unsigned owner = 0; owner < 3; ++owner)
        need(successor_lineages[owner] ==
             storage_->input_lineages[owner][1]);

    const bool candidate = storage_->plan.classification ==
        registered_driver::CaptureClassification::HiddenCandidate;
    outcome->baseline = !candidate;
    need(candidate
        ? !storage_->reserved_roster.has_value()
        : storage_->plan.classification ==
              registered_driver::CaptureClassification::
                  ExplicitOwnerPublicEffectsBaseline &&
              storage_->reserved_roster.has_value());

    std::array<WirePacket, 3> commands{};
    std::array<WirePacket, 3> stops{};
    for (unsigned owner = 0; owner < 3; ++owner) {
        const auto& child = storage_->launch.children[owner];
        auto command = packet(
            WireKind::IssueRound, owner, 2,
            storage_->launch.supervisor_session_identity,
            child.child_session_identity);
        command.accepted_input_head_identity =
            gate.accepted_successor_head_identity;
        command.history_gate_identity = gate.history_gate_identity;
        command.command_identity = command_identity(
            command.supervisor_session, command.child_session,
            owner, 2, command.accepted_input_head_identity,
            command.history_gate_identity);
        finish_packet(command);
        outcome->command_identities[owner] = command.command_identity;
        commands[owner] = command;
        if (!candidate)
            stops[owner] = packet(
                WireKind::Stop, owner, 0,
                storage_->launch.supervisor_session_identity,
                child.child_session_identity);
    }

    const auto continuity_record = storage_->continuity_record(
        2, storage_->reserved_round2->public_receipt().issuance_identity);
    continuity_storage->record = continuity_record;
    retry_storage->record = continuity_record;
    outcome->prepared_bootstrap.emplace(
        AcceptedRound1SuccessorHistoryBootstrapAuthority(gate));
    outcome->prepared_continuity.emplace(
        FreshOwnerRoundContinuityAuthority(
            std::move(continuity_storage)));
    outcome->prepared_retry.emplace(
        FreshOwnerSameRoundRetryAuthority(std::move(retry_storage)));

    if (candidate) {
        need(round1.v3_input_history_.run == storage_->plan.run &&
             round1.v3_input_history_.trial == storage_->plan.trial &&
             round1.v3_input_history_.round1_attempt ==
                 storage_->receipts[0].rounds[0].attempt &&
             round1.v3_input_history_.round1_cohort ==
                 storage_->receipts[0].rounds[0].cohort &&
             round1.v3_measurement_run_binding_identity_ ==
                 storage_->plan.measurement_run_binding_identity &&
             round1.v3_financial_runs_ ==
                 storage_->plan.candidate_truth_financial_runs &&
             round1.v3_capture_plans_ ==
                 storage_->plan.candidate_truth_capture_plan_identities &&
             round1.v3_projections_ ==
                 storage_->plan.candidate_truth_projection_identities &&
             round1.v3_contexts_ ==
                 storage_->plan.candidate_truth_context_identities);
        outcome->prepared_candidate_truth.emplace(
            CandidateOwnerTruthPendingAuthority(
                storage_->launch.supervisor_session_identity,
                storage_->continuation,
                storage_->plan.candidate_truth_financial_runs,
                storage_->plan.candidate_truth_capture_plan_identities,
                storage_->plan.candidate_truth_projection_identities,
                storage_->plan.candidate_truth_context_identities));
        outcome->prepared_v3_history.emplace(
            V3AcceptedRound1HistoryResidualAuthority(
                round1.v3_input_history_, gate,
                round1.v3_input_lineages_, successor_lineages,
                round1.v3_measurement_run_binding_identity_,
                round1.v3_financial_runs_, round1.v3_capture_plans_,
                round1.v3_projections_, round1.v3_contexts_,
                storage_->launch.supervisor_session_identity,
                storage_->continuation));
    }

    static_assert(noexcept(outcome->retained_round1.emplace(
        std::declval<FreshOwnerRound1IssuedAuthority&&>())));
    static_assert(noexcept(outcome->stopped_supervisor.emplace(
        std::declval<FreshOwnerProcessSupervisor&&>())));
    static_assert(noexcept(outcome->issued.emplace(
        std::declval<FreshOwnerRound2IssuedAuthority&&>())));
    static_assert(std::is_nothrow_move_constructible_v<
        FreshOwnerRoundAuthority>);
    static_assert(std::is_nothrow_move_constructible_v<
        BaselineOwnerRosterAuthority>);
    static_assert(std::is_nothrow_move_constructible_v<
        CandidateOwnerTruthPendingAuthority>);
    static_assert(std::is_nothrow_move_constructible_v<
        V3AcceptedRound1HistoryResidualAuthority>);
    static_assert(std::is_nothrow_move_constructible_v<
        AcceptedRound1SuccessorHistoryBootstrapAuthority>);
    static_assert(std::is_nothrow_move_constructible_v<
        FreshOwnerRoundContinuityAuthority>);
    static_assert(std::is_nothrow_move_constructible_v<
        FreshOwnerSameRoundRetryAuthority>);

    outcome->retained_round1.emplace(std::move(round1));
    outcome->consumed_successor.emplace(
        FreshOwnerRound2ConsumedSuccessorResidual{
            .successor = gate,
            .successor_input_lineages = successor_lineages,
            .supervisor_session =
                storage_->launch.supervisor_session_identity,
            .continuation = storage_->continuation,
            .live = true,
        });
    auto& owned_round1 = *outcome->retained_round1;
    if (!owned_round1.live_.exchange(false) ||
        !history.live_.exchange(false))
        std::terminate();
    outcome->failure_stage = 1;

    const auto stop = [&]() noexcept {
        outcome->failure_errno = errno;
        if (storage_ != nullptr) storage_->terminate();
        outcome->stopped_supervisor.emplace(std::move(*this));
        outcome->state =
            FreshOwnerRound2AttemptOutcomeState::UnavailableStop;
        return FreshOwnerRound2AttemptOutcomeAuthority(
            std::move(outcome));
    };

    try {
        for (unsigned owner = 0; owner < 3; ++owner) {
            storage_->receipts[owner].rounds[1]
                .accepted_input_head_identity =
                    gate.accepted_successor_head_identity;
            storage_->receipts[owner].rounds[1].history_gate_identity =
                gate.history_gate_identity;
        }
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
        inject_round2_attempt_fault(
            FreshOwnerRound2AttemptTestFault::AfterInputClaim);
#endif
        for (unsigned owner = 0; owner < 3; ++owner) {
            outcome->failure_stage = 10 + owner;
            send_packet(storage_->channels[owner], commands[owner]);
            outcome->command_sent[owner] = true;
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
            if (owner == 0)
                inject_round2_attempt_fault(
                    FreshOwnerRound2AttemptTestFault::
                        AfterFirstChildSend);
#endif
        }

        std::array<Digest, 6> files{}, metadata{};
        for (unsigned owner = 0; owner < 3; ++owner) {
            files[owner] =
                storage_->receipts[owner].rounds[0].file_identity;
            metadata[owner] = storage_->receipts[owner].rounds[0]
                .file_metadata_identity;
        }
        const auto unique_prefix = [](
                const std::array<Digest, 6>& values, unsigned count,
                const Digest& candidate_value) {
            if (zero(candidate_value)) return false;
            for (unsigned index = 0; index < count; ++index)
                if (values[index] == candidate_value) return false;
            return true;
        };
        for (unsigned owner = 0; owner < 3; ++owner) {
            outcome->failure_stage = 20 + owner;
            const auto response = receive_packet(
                storage_->channels[owner], storage_->pids[owner]);
            const auto& prior = storage_->round1_results[owner];
            need(response.kind == WireKind::RoundResult &&
                 response.owner == owner && response.round == 2 &&
                 response.command_identity ==
                     outcome->command_identities[owner] &&
                 response.accepted_input_head_identity ==
                     gate.accepted_successor_head_identity &&
                 response.history_gate_identity ==
                     gate.history_gate_identity &&
                 response.logical_owner_identity ==
                     prior.logical_owner_identity &&
                 response.binding_nonce == prior.binding_nonce &&
                 response.verifier_record == prior.verifier_record &&
                 response.input_lineage_identity ==
                     storage_->input_lineages[owner][1] &&
                 response.file_identity ==
                     storage_->receipts[owner].rounds[1].file_identity &&
                 response.file_metadata_identity ==
                     storage_->receipts[owner].rounds[1]
                         .file_metadata_identity &&
                 unique_prefix(
                     files, 3 + owner, response.file_identity) &&
                 unique_prefix(
                     metadata, 3 + owner,
                     response.file_metadata_identity));
            files[3 + owner] = response.file_identity;
            metadata[3 + owner] = response.file_metadata_identity;
            storage_->receipts[owner].rounds[1].file_identity =
                response.file_identity;
            storage_->receipts[owner].rounds[1].file_metadata_identity =
                response.file_metadata_identity;
            outcome->response_authenticated[owner] = true;
            outcome->response_packet_identities[owner] =
                response.packet_identity;
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
            if (owner == 0)
                inject_round2_attempt_fault(
                    FreshOwnerRound2AttemptTestFault::
                        AfterFirstChildResponse);
#endif
        }
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
        inject_round2_attempt_fault(
            FreshOwnerRound2AttemptTestFault::AfterAllChildResponses);
#endif

        if (!candidate) {
            for (unsigned owner = 0; owner < 3; ++owner) {
                outcome->failure_stage = 30 + owner;
                send_packet(storage_->channels[owner], stops[owner]);
                outcome->stop_sent[owner] = true;
            }
            bool all_zero = true;
            for (unsigned owner = 0; owner < 3; ++owner) {
                outcome->failure_stage = 40 + owner;
                const bool observed = settle_owner_pidfd(
                    storage_->pidfds[owner], storage_->pids[owner],
                    storage_->termination_exit_codes[owner],
                    storage_->termination_signals[owner]);
                storage_->termination_wait_observed[owner] = observed;
                need(observed);
                all_zero = all_zero &&
                    storage_->termination_exit_codes[owner] == 0 &&
                    storage_->termination_signals[owner] == 0;
                close_fd(storage_->channels[owner]);
            }
            storage_->completion = PublicFreshOwnerProcessCompletion{
                .supervisor_session_identity =
                    storage_->launch.supervisor_session_identity,
                .children = storage_->launch.children,
                .all_children_exited_zero = all_zero,
            };
            need(all_zero);
        }
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
        inject_round2_attempt_fault(
            FreshOwnerRound2AttemptTestFault::BeforeCommit);
#endif
        outcome->failure_stage = 50;

        FreshOwnerRoundAuthority driver(
            std::move(*storage_->reserved_round2));
        std::optional<BaselineOwnerRosterAuthority> roster;
        if (!candidate)
            roster.emplace(std::move(*storage_->reserved_roster));
        std::optional<CandidateOwnerTruthPendingAuthority> candidate_truth;
        std::optional<V3AcceptedRound1HistoryResidualAuthority> v3_history;
        if (candidate) {
            candidate_truth.emplace(
                std::move(*outcome->prepared_candidate_truth));
            v3_history.emplace(std::move(*outcome->prepared_v3_history));
        }
        FreshOwnerRound2IssuedAuthority issued(
            std::move(driver),
            std::move(*outcome->prepared_bootstrap),
            std::move(*outcome->prepared_continuity),
            std::move(*outcome->prepared_retry),
            std::move(roster), std::move(candidate_truth),
            std::move(v3_history));
        storage_->reserved_round2.reset();
        if (!candidate) storage_->reserved_roster.reset();
        outcome->prepared_bootstrap.reset();
        outcome->prepared_continuity.reset();
        outcome->prepared_retry.reset();
        outcome->prepared_candidate_truth.reset();
        outcome->prepared_v3_history.reset();
        outcome->issued.emplace(std::move(issued));
        storage_->round2_issued = true;
        storage_->completed = !candidate;
        outcome->failure_stage = 0;
        outcome->state = FreshOwnerRound2AttemptOutcomeState::Success;
        return FreshOwnerRound2AttemptOutcomeAuthority(
            std::move(outcome));
    } catch (...) {
        return stop();
    }
}

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
FreshOwnerRound2AttemptOutcomeAuthority
FreshOwnerProcessSupervisor::issue_round2_transactional(
        FreshOwnerRound1IssuedAuthority&& round1,
        AcceptedRound1SuccessorHistoryAuthority&& history) {
    return issue_round2_transactional_impl(
        std::move(round1), std::move(history));
}

FreshOwnerRound2IssuedAuthority FreshOwnerProcessSupervisor::issue_round2(
        FreshOwnerRound1IssuedAuthority&& round1,
        AcceptedRound1SuccessorHistoryAuthority&& history) {
    auto outcome = issue_round2_transactional_impl(
        std::move(round1), std::move(history));
    if (FreshOwnerRound2AttemptOutcomeTestBridge::inspect(outcome) ==
        TestFreshOwnerRound2AttemptOutcome::Success)
        return FreshOwnerRound2AttemptOutcomeTestBridge::take_success(
            std::move(outcome));
    FreshOwnerRound2AttemptOutcomeTestBridge::discard_stop_for_test(
        std::move(outcome));
    refuse();
}
#endif

CandidateOwnerTruthEndpointSplit
FreshOwnerProcessSupervisor::release_candidate_truth(
        CandidateOwnerTruthPostBarrierAuthority&& barrier) {
    try {
        const bool barrier_live = barrier.live_.exchange(false);
        need(storage_ != nullptr && barrier_live &&
             !storage_->poisoned && !storage_->completed &&
             storage_->round1_issued && storage_->round2_issued &&
             !storage_->truth_released &&
             storage_->plan.classification ==
                 registered_driver::CaptureClassification::HiddenCandidate &&
             barrier.supervisor_session_ ==
                 storage_->launch.supervisor_session_identity &&
             barrier.continuation_identity_ == storage_->continuation);
        const auto gate = barrier.receipt_;
        need(gate.classification ==
                 registered_driver::CaptureClassification::HiddenCandidate &&
             gate.trial == storage_->plan.trial &&
             gate.financial_runs ==
                 storage_->plan.candidate_truth_financial_runs &&
             gate.capture_plan_identities ==
                 storage_->plan.candidate_truth_capture_plan_identities &&
             gate.projection_identities ==
                 storage_->plan.candidate_truth_projection_identities &&
             gate.context_identities ==
                 storage_->plan.candidate_truth_context_identities);
        for (unsigned index = 0; index < 2; ++index) {
            const auto& selected = storage_->receipts[0].rounds[index];
            need(gate.attempts[index] == selected.attempt &&
                 gate.cohorts[index] == selected.cohort);
        }

        std::array<Digest, 3> endpoint_identities{
            random_digest(), random_digest(), random_digest()};
        std::array<Digest, 3> feeder_sessions{
            random_digest(), random_digest(), random_digest()};
        need(std::set<Digest>(endpoint_identities.begin(),
                              endpoint_identities.end()).size() == 3 &&
             std::set<Digest>(feeder_sessions.begin(),
                              feeder_sessions.end()).size() == 3);

        for (unsigned owner = 0; owner < 3; ++owner) {
            need(storage_->channels[owner] >= 0 &&
                 storage_->truth_channels[owner] >= 0 &&
                 storage_->pids[owner] ==
                     storage_->launch.children[owner].child_pid);
            const auto& child = storage_->launch.children[owner];
            auto command = packet(
                WireKind::ReleaseTruth, owner, 0,
                storage_->launch.supervisor_session_identity,
                child.child_session_identity);
            command.truth_endpoint_identity = endpoint_identities[owner];
            command.truth_feeder_session = feeder_sessions[owner];
            command.truth_barrier_identity = gate.barrier_identity;
            command.truth_financial_runs = gate.financial_runs;
            command.truth_capture_plans = gate.capture_plan_identities;
            command.truth_projections = gate.projection_identities;
            command.truth_contexts = gate.context_identities;
            finish_packet(command);
            send_packet(storage_->channels[owner], command);
        }

        for (unsigned owner = 0; owner < 3; ++owner) {
            const auto response = receive_packet(
                storage_->channels[owner], storage_->pids[owner]);
            need(response.kind == WireKind::TruthReleased &&
                 response.owner == owner && response.round == 0 &&
                 response.supervisor_session ==
                     storage_->launch.supervisor_session_identity &&
                 response.child_session ==
                     storage_->launch.children[owner]
                         .child_session_identity &&
                 response.truth_endpoint_identity ==
                     endpoint_identities[owner] &&
                 response.truth_feeder_session == feeder_sessions[owner] &&
                 response.truth_barrier_identity == gate.barrier_identity &&
                 response.truth_financial_runs == gate.financial_runs &&
                 response.truth_capture_plans ==
                     gate.capture_plan_identities &&
                 response.truth_projections ==
                     gate.projection_identities &&
                 response.truth_contexts == gate.context_identities);
        }

        for (unsigned owner = 0; owner < 3; ++owner) {
            const auto& child = storage_->launch.children[owner];
            send_packet(storage_->channels[owner], packet(
                WireKind::Stop, owner, 0,
                storage_->launch.supervisor_session_identity,
                child.child_session_identity));
        }
        bool all_zero = true;
        for (unsigned owner = 0; owner < 3; ++owner) {
            const bool observed = settle_owner_pidfd(
                storage_->pidfds[owner], storage_->pids[owner],
                storage_->termination_exit_codes[owner],
                storage_->termination_signals[owner]);
            storage_->termination_wait_observed[owner] = observed;
            need(observed);
            all_zero = all_zero &&
                storage_->termination_exit_codes[owner] == 0 &&
                storage_->termination_signals[owner] == 0;
            close_fd(storage_->channels[owner]);
        }
        storage_->completion = PublicFreshOwnerProcessCompletion{
            .supervisor_session_identity =
                storage_->launch.supervisor_session_identity,
            .children = storage_->launch.children,
            .all_children_exited_zero = all_zero,
        };
        need(all_zero);

        std::array<PublicCandidateOwnerTruthEndpoint, 3> receipts{};
        for (unsigned owner = 0; owner < 3; ++owner) {
            const auto& child = storage_->launch.children[owner];
            receipts[owner] = PublicCandidateOwnerTruthEndpoint{
                .classification =
                    registered_driver::CaptureClassification::HiddenCandidate,
                .owner_component = owner,
                .fixed_fd = FRESH_OWNER_FIXED_TRUTH_FD,
                .endpoint_identity = endpoint_identities[owner],
                .feeder_session_identity = feeder_sessions[owner],
                .trial = gate.trial,
                .barrier_identity = gate.barrier_identity,
                .financial_runs = gate.financial_runs,
                .attempts = gate.attempts,
                .cohorts = gate.cohorts,
                .capture_plan_identities = gate.capture_plan_identities,
                .projection_identities = gate.projection_identities,
                .context_identities = gate.context_identities,
                .feeder_pid = child.child_pid,
                .feeder_exit_identity = truth_feeder_exit_identity(
                    storage_->launch.supervisor_session_identity,
                    child.child_session_identity,
                    endpoint_identities[owner], child.child_pid),
            };
        }
        std::array<CandidateOwnerTruthEndpointAuthority, 3> endpoints{
            CandidateOwnerTruthEndpointAuthority(
                receipts[0], std::exchange(storage_->truth_channels[0], -1)),
            CandidateOwnerTruthEndpointAuthority(
                receipts[1], std::exchange(storage_->truth_channels[1], -1)),
            CandidateOwnerTruthEndpointAuthority(
                receipts[2], std::exchange(storage_->truth_channels[2], -1)),
        };
        std::set<std::pair<std::uint64_t, std::uint64_t>> endpoint_objects;
        for (const auto& endpoint : endpoints)
            need(endpoint_objects.emplace(
                     endpoint.device_, endpoint.inode_).second);
        storage_->truth_released = true;
        storage_->completed = true;
        return CandidateOwnerTruthEndpointSplit(std::move(endpoints));
    } catch (...) {
        if (storage_ != nullptr) storage_->terminate();
        refuse();
    }
}

void FreshOwnerProcessSupervisor::poison_candidate_truth_release() noexcept {
    if (storage_ != nullptr) storage_->terminate();
}

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
CandidateOwnerTruthEndpointSplit
FreshOwnerProcessSupervisor::test_only_release_candidate_truth(
        CandidateOwnerTruthPendingAuthority&& pending,
        CandidateOwnerTruthPostBarrierAuthority&& barrier) {
    try {
        need(pending.live_.exchange(false) &&
             barrier.receipt_.financial_runs == pending.financial_runs_ &&
             barrier.receipt_.capture_plan_identities ==
                 pending.capture_plan_identities_ &&
             barrier.receipt_.projection_identities ==
                 pending.projection_identities_ &&
             barrier.receipt_.context_identities ==
                 pending.context_identities_);
        barrier.supervisor_session_ = pending.supervisor_session_;
        barrier.continuation_identity_ = pending.continuation_identity_;
        return release_candidate_truth(std::move(barrier));
    } catch (...) {
        poison_candidate_truth_release();
        refuse();
    }
}
#endif

bool FreshOwnerProcessSupervisor::completed() const {
    return storage_ != nullptr && storage_->completed;
}

const PublicFreshOwnerProcessCompletion&
FreshOwnerProcessSupervisor::public_completion() const {
    need(storage_ != nullptr && storage_->completed);
    return storage_->completion;
}

FreshOwnerProcessAdapterSourceStatus
fresh_owner_process_adapter_source_status() {
    return {
        .schema = "kpi-fresh-owner-process-adapter-source-status/v3",
        .status = "SOURCE_ONLY_CONFIGURED0",
        .exact_three_long_lived_children = true,
        .inherited_seqpacket_scm_credentials = true,
        .fixed_private_root_descriptors = true,
        .parent_root_aliases_after_ack = false,
        .round2_requires_typed_accepted_history = true,
        .round2_typed_attempt_outcome = true,
        .round2_postclaim_typed_stop = true,
        .production_round2_consumer = false,
        .path_body_or_body_hash_export = false,
        .selected_private_lifecycle_program = false,
        .production_root_authority_minter = false,
        .production_history_authority_minter = false,
        .typed_testnet_history_adapter = true,
        .issuance_validated_v3_history_residual = true,
        .production_v3_lifecycle_controller_minter = false,
        .production_replay_store_minter = false,
        .same_round_retry_minter = false,
        .hidden_candidate_fd42_truth_endpoint = true,
        .production_post_barrier_truth_minter = false,
        .registered_driver_configured = false,
        .launch_authorized = false,
    };
}

} // namespace kpi::mpc::financial::fresh_owner_issuance
