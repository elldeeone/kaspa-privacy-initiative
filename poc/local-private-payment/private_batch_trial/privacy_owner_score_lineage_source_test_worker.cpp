#include "privacy_owner_score_lineage_source_authority.hpp"
#include "privacy_owner_score_lineage_source_receiver_protocol.hpp"
#include "privacy_measurement_sha256.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <span>
#include <string>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#ifndef KPB_LINEAGE_TEST_WORKER_FAULT
#define KPB_LINEAGE_TEST_WORKER_FAULT 0
#endif

namespace source =
    kpb::measurement::score_output_lineage_source;
namespace protocol = source::receiver_protocol;

namespace {

[[noreturn]] void fail(int code) { ::_exit(code); }
void need(bool value, int code) { if (!value) fail(code); }

std::vector<unsigned char> read_file(int fd) {
    struct stat info{};
    need(::fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
         info.st_size > 0, 101);
    std::vector<unsigned char> result(static_cast<std::size_t>(info.st_size));
    std::size_t offset{};
    while (offset < result.size()) {
        const auto count = ::pread(fd, result.data() + offset,
            result.size() - offset, static_cast<off_t>(offset));
        if (count < 0 && errno == EINTR) continue;
        need(count > 0, 102);
        offset += static_cast<std::size_t>(count);
    }
    return result;
}

void put_u32(std::span<unsigned char> out, std::size_t at,
             std::uint32_t value) {
    for (unsigned index = 0; index < 4; ++index)
        out[at + index] = static_cast<unsigned char>(value >> (8 * index));
}
void put_u64(std::span<unsigned char> out, std::size_t at,
             std::uint64_t value) {
    for (unsigned index = 0; index < 8; ++index)
        out[at + index] = static_cast<unsigned char>(value >> (8 * index));
}

void exact_write(int fd, std::span<const unsigned char> bytes) {
    std::size_t offset{};
    while (offset < bytes.size()) {
        const auto count = ::write(fd, bytes.data() + offset,
                                   bytes.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        need(count > 0, 103);
        offset += static_cast<std::size_t>(count);
    }
}

std::vector<unsigned char> archive(
        const source::SourceDigest& diagnostic_selection) {
    static constexpr std::string_view run{
        "{\"schema\":\"kpb-source-owned-diagnostic-run/v1\","
        "\"selected\":true}\n"};
    const auto method = kpb::measurement::detail::sha256(
        std::span(reinterpret_cast<const unsigned char*>("frozen-method"),
                  std::size_t{13}));
    const auto source_closure = kpb::measurement::detail::sha256(
        std::span(reinterpret_cast<const unsigned char*>("source-closure"),
                  std::size_t{14}));
    const auto runtime = kpb::measurement::detail::sha256(
        std::span(reinterpret_cast<const unsigned char*>("runtime-closure"),
                  std::size_t{15}));
    const auto run_digest = kpb::measurement::detail::sha256(
        std::span(reinterpret_cast<const unsigned char*>(run.data()),
                  run.size()));
    const std::string_view trial{
        "22222222-2222-4222-8222-222222222222"};
    const std::string_view attempt{"actual-candidate-attempt-01"};
    const auto measurement_attempt =
        source::measurement_attempt_from_outer_ascii(attempt);
    std::vector<unsigned char> result(
        source::OWNER_SCORE_LINEAGE_ARCHIVE_HEADER_BYTES + run.size());
    std::copy(source::OWNER_SCORE_LINEAGE_ARCHIVE_MAGIC.begin(),
              source::OWNER_SCORE_LINEAGE_ARCHIVE_MAGIC.end(),
              result.begin());
    put_u32(result, 8, source::OWNER_SCORE_LINEAGE_ARCHIVE_VERSION);
    put_u32(result, 12, source::OWNER_SCORE_LINEAGE_ARCHIVE_HEADER_BYTES);
    put_u64(result, 16, result.size());
    std::copy(method.begin(), method.end(), result.begin() + 24);
    std::copy(run_digest.begin(), run_digest.end(), result.begin() + 56);
    std::copy(diagnostic_selection.begin(), diagnostic_selection.end(),
              result.begin() + 88);
    std::copy(source_closure.begin(), source_closure.end(),
              result.begin() + 120);
    std::copy(runtime.begin(), runtime.end(), result.begin() + 152);
    std::copy(trial.begin(), trial.end(), result.begin() + 184);
    result[220] = static_cast<unsigned char>(
        source::OwnerScoreSourceClassification::HiddenCandidate);
    result[221] = 1;
    result[222] = static_cast<unsigned char>(attempt.size());
    put_u64(result, 224, run.size());
    std::copy(measurement_attempt.begin(), measurement_attempt.end(),
              result.begin() + 232);
    std::copy(attempt.begin(), attempt.end(), result.begin() + 264);
    std::copy(run.begin(), run.end(),
              result.begin() + source::OWNER_SCORE_LINEAGE_ARCHIVE_HEADER_BYTES);
    if constexpr (KPB_LINEAGE_TEST_WORKER_FAULT == 1) result[24] ^= 1;
    return result;
}

std::array<unsigned char, protocol::OFFER_BYTES> receive_offer() {
    std::array<unsigned char, protocol::OFFER_BYTES> result{};
    alignas(cmsghdr) std::array<unsigned char,
        CMSG_SPACE(sizeof(ucred))> control{};
    iovec vector{.iov_base = result.data(), .iov_len = result.size()};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    const auto count = ::recvmsg(protocol::CONTROL_FD, &message, 0);
    need(count == static_cast<ssize_t>(result.size()) &&
         (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0, 104);
    auto* item = CMSG_FIRSTHDR(&message);
    need(item != nullptr && item->cmsg_level == SOL_SOCKET &&
         item->cmsg_type == SCM_CREDENTIALS &&
         item->cmsg_len == CMSG_LEN(sizeof(ucred)) &&
         CMSG_NXTHDR(&message, item) == nullptr, 105);
    ucred credentials{};
    std::memcpy(&credentials, CMSG_DATA(item), sizeof(credentials));
    need(credentials.pid == ::getppid() && credentials.uid == ::getuid() &&
         credentials.gid == ::getgid() &&
         std::equal(protocol::OFFER_MAGIC.begin(),
                    protocol::OFFER_MAGIC.end(), result.begin()), 106);
    return result;
}

} // namespace

int main() {
    const auto offer = receive_offer();
    const auto selection = read_file(protocol::SELECTION_FD);
    const auto selection_sha = kpb::measurement::detail::sha256(selection);
    need(std::equal(selection_sha.begin(), selection_sha.end(),
                    offer.begin() + 40), 107);
    auto body = archive(selection_sha);
    const auto body_sha = kpb::measurement::detail::sha256(body);
    int writer = ::memfd_create(
        "kpb-owner-score-lineage-test-worker",
        MFD_CLOEXEC | MFD_ALLOW_SEALING);
    need(writer >= 0, 108);
    exact_write(writer, body);
    need(::fchmod(writer, 0400) == 0, 109);
    if constexpr (KPB_LINEAGE_TEST_WORKER_FAULT != 5)
        need(::fcntl(writer, F_ADD_SEALS,
            F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == 0,
            110);
    int reader = writer;
    if constexpr (KPB_LINEAGE_TEST_WORKER_FAULT != 4) {
        const auto path = std::string("/proc/self/fd/") +
            std::to_string(writer);
        reader = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
        need(reader >= 0, 111);
    }
    std::array<unsigned char, protocol::RESPONSE_BYTES> response{};
    std::copy(protocol::RESPONSE_MAGIC.begin(),
              protocol::RESPONSE_MAGIC.end(), response.begin());
    std::copy_n(offer.begin() + 8, 32, response.begin() + 8);
    put_u64(response, 40, body.size());
    std::copy(body_sha.begin(), body_sha.end(), response.begin() + 48);

    if constexpr (KPB_LINEAGE_TEST_WORKER_FAULT == 2)
        need(::send(protocol::CONTROL_FD, "", 0, MSG_NOSIGNAL) == 0, 112);

    std::array<int, 2> descriptors{reader, reader};
    const std::size_t descriptor_count =
        KPB_LINEAGE_TEST_WORKER_FAULT == 3 ? 2 : 1;
    alignas(cmsghdr) std::array<unsigned char,
        CMSG_SPACE(2 * sizeof(int))> control{};
    iovec vector{.iov_base = response.data(), .iov_len = response.size()};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = CMSG_SPACE(descriptor_count * sizeof(int));
    auto* item = CMSG_FIRSTHDR(&message);
    item->cmsg_level = SOL_SOCKET;
    item->cmsg_type = SCM_RIGHTS;
    item->cmsg_len = CMSG_LEN(descriptor_count * sizeof(int));
    std::memcpy(CMSG_DATA(item), descriptors.data(),
                descriptor_count * sizeof(int));
    need(::sendmsg(protocol::CONTROL_FD, &message, MSG_NOSIGNAL) ==
         static_cast<ssize_t>(response.size()), 113);
    if constexpr (KPB_LINEAGE_TEST_WORKER_FAULT == 6)
        need(::send(protocol::CONTROL_FD, "x", 1, MSG_NOSIGNAL) == 1, 114);
    ::close(reader);
    if (reader != writer) ::close(writer);
    ::close(protocol::CONTROL_FD);
    if constexpr (KPB_LINEAGE_TEST_WORKER_FAULT == 7) return 7;
    return 0;
}
