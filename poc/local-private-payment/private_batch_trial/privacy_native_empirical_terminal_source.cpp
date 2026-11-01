#include "privacy_native_empirical_terminal_source.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <limits>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <set>
#include <span>
#include <string_view>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpb::measurement::empirical_terminal_source {
namespace {

constexpr std::array<unsigned char, 8> P1_MAGIC{
    'K', 'P', 'B', 'P', '1', 'C', '0', '3'};
constexpr std::size_t P1_HEADER_BYTES = 112;
constexpr std::size_t P1_HELLO_BYTES = 332;
constexpr std::size_t P1_COMPLETENESS_BYTES = 496;
constexpr std::uint32_t P1_MAX_CHUNK_BYTES = 1U << 16;
constexpr std::uint8_t P1_SEMANTIC_COUNT = 17;
constexpr std::uint8_t P1_CORRUPT_SERVER_KIND = 4;
constexpr std::uint8_t FLAG_FIRST = 1;
constexpr std::uint8_t FLAG_LAST = 2;
constexpr int REQUIRED_SEALS =
    F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

void close_fd(int& fd) noexcept {
    if (fd < 0) return;
    while (::close(fd) != 0 && errno == EINTR) {}
    fd = -1;
}

std::uint32_t be32(const unsigned char* value) {
    std::uint32_t result = 0;
    for (unsigned index = 0; index < 4; ++index)
        result = (result << 8U) | value[index];
    return result;
}

std::uint64_t be64(const unsigned char* value) {
    std::uint64_t result = 0;
    for (unsigned index = 0; index < 8; ++index)
        result = (result << 8U) | value[index];
    return result;
}

void add_big(std::vector<unsigned char>& out, std::uint64_t value,
             unsigned width) {
    need(width > 0 && width <= 8);
    for (unsigned index = 0; index < width; ++index)
        out.push_back(static_cast<unsigned char>(
            value >> (8U * (width - index - 1))));
}

void add(std::vector<unsigned char>& out, const Digest& value) {
    out.insert(out.end(), value.begin(), value.end());
}

void add(std::vector<unsigned char>& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}

Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    need(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}

class HashState final {
    EVP_MD_CTX* context_{EVP_MD_CTX_new()};
    bool finished_{};
public:
    HashState() {
        need(context_ != nullptr &&
             EVP_DigestInit_ex(context_, EVP_sha256(), nullptr) == 1);
    }
    HashState(const HashState&) = delete;
    HashState& operator=(const HashState&) = delete;
    ~HashState() { EVP_MD_CTX_free(context_); }
    void update(std::span<const unsigned char> value) {
        need(!finished_ && EVP_DigestUpdate(
            context_, value.data(), value.size()) == 1);
    }
    Digest finish() {
        need(!finished_);
        finished_ = true;
        Digest result{};
        unsigned length = 0;
        need(EVP_DigestFinal_ex(context_, result.data(), &length) == 1 &&
             length == result.size());
        return result;
    }
};

void read_exact(int fd, std::span<unsigned char> target,
                std::uint64_t offset) {
    need(offset <= static_cast<std::uint64_t>(
        std::numeric_limits<off_t>::max()));
    std::size_t at = 0;
    while (at < target.size()) {
        ssize_t count;
        do {
            count = ::pread(fd, target.data() + at, target.size() - at,
                            static_cast<off_t>(offset + at));
        } while (count < 0 && errno == EINTR);
        need(count > 0);
        at += static_cast<std::size_t>(count);
    }
}

bool lower_hex(unsigned char value) {
    return (value >= '0' && value <= '9') ||
           (value >= 'a' && value <= 'f');
}

void exact_uuid(std::span<const unsigned char> value) {
    need(value.size() == 36);
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (index == 8 || index == 13 || index == 18 || index == 23)
            need(value[index] == '-');
        else
            need(lower_hex(value[index]));
    }
    need(value[14] == '4' &&
         std::string_view("89ab").find(
             static_cast<char>(value[19])) != std::string_view::npos);
}

Digest uuid_identity(std::string_view domain,
                     std::span<const unsigned char> uuid) {
    exact_uuid(uuid);
    std::vector<unsigned char> preimage;
    preimage.reserve(domain.size() + uuid.size());
    add(preimage, domain);
    preimage.insert(preimage.end(), uuid.begin(), uuid.end());
    return hash(preimage);
}

void safe_add(std::uint64_t& target, std::uint64_t amount) {
    need(amount <= std::numeric_limits<std::uint64_t>::max() - target);
    target += amount;
}

struct Counter {
    std::uint64_t messages{};
    std::uint64_t chunks{};
    std::uint64_t bytes{};
};

struct ParsedFinalC03 {
    ProducerStreamClosureEvidence closure{};
    std::uint64_t frame_count{};
    std::uint64_t raw_wire_bytes{};
};

void exact_hello(std::span<const unsigned char> hello,
                 const RunBinding& binding,
                 const FinalC03RoundBinding& expected) {
    need(hello.size() == P1_HELLO_BYTES &&
         hello[0] == expected.round && hello[1] == 1 &&
         hello[2] == 0 && hello[3] == expected.fixed_fd);
    const auto attempt = hello.subspan(4, 36);
    const auto capture = hello.subspan(104, 36);
    need(uuid_identity("KPB_CAPTURE_ATTEMPT_ID_V1\n", attempt) ==
             expected.attempt &&
         uuid_identity("KPB_CAPTURE_IDENTITY_V1\n", capture) ==
             binding.capture &&
         std::equal(expected.cohort.begin(), expected.cohort.end(),
                    hello.begin() + 40) &&
         std::equal(expected.financial_run.begin(),
                    expected.financial_run.end(), hello.begin() + 72) &&
         std::equal(expected.source_identity.begin(),
                    expected.source_identity.end(), hello.begin() + 140) &&
         std::equal(expected.build_identity.begin(),
                    expected.build_identity.end(), hello.begin() + 172) &&
         std::equal(expected.launcher_identity.begin(),
                    expected.launcher_identity.end(), hello.begin() + 204) &&
         std::equal(expected.model_preimage_identity.begin(),
                    expected.model_preimage_identity.end(),
                    hello.begin() + 236) &&
         std::equal(expected.query_store_preimage_identity.begin(),
                    expected.query_store_preimage_identity.end(),
                    hello.begin() + 268) &&
         std::equal(expected.scalar_capture_manifest_identity.begin(),
                    expected.scalar_capture_manifest_identity.end(),
                    hello.begin() + 300));
}

void exact_completeness(
        std::span<const unsigned char> payload,
        const Counter& total, const std::array<Counter, 17>& lanes,
        std::uint64_t frame_sequence, std::uint64_t first_monotonic,
        std::uint64_t last_monotonic_before_completeness) {
    need(payload.size() == P1_COMPLETENESS_BYTES &&
         be32(payload.data()) == 9 &&
         be32(payload.data() + 4) == P1_SEMANTIC_COUNT &&
         be64(payload.data() + 8) == total.messages &&
         be64(payload.data() + 16) == total.chunks &&
         be64(payload.data() + 24) == total.bytes);
    std::size_t at = 32;
    for (const auto& lane : lanes) {
        need(be64(payload.data() + at) == lane.messages &&
             be64(payload.data() + at + 8) == lane.chunks &&
             be64(payload.data() + at + 16) == lane.bytes);
        at += 24;
    }
    need(at == 440 && be64(payload.data() + 440) ==
             ((std::uint64_t{1} << P1_SEMANTIC_COUNT) - 1) &&
         be64(payload.data() + 448) == 7 &&
         be64(payload.data() + 456) == 7 &&
         be64(payload.data() + 464) != 0 &&
         be64(payload.data() + 472) == frame_sequence &&
         be64(payload.data() + 480) == first_monotonic &&
         be64(payload.data() + 488) ==
             last_monotonic_before_completeness);
}

ParsedFinalC03 parse_final_c03(
        int fd, std::uint64_t exact_size, const RunBinding& binding,
        const FinalC03RoundBinding& expected) {
    need(fd >= 0 && exact_size >= 5 * P1_HEADER_BYTES &&
         exact_size <= static_cast<std::uint64_t>(
             std::numeric_limits<off_t>::max()));
    HashState wire_hash;
    std::uint64_t offset = 0;
    std::uint64_t frames = 0;
    std::uint64_t payload_bytes = 0;
    std::uint64_t first_monotonic = 0;
    std::uint64_t prior_monotonic = 0;
    std::uint64_t next_message = 0;
    bool open_message = false;
    std::uint8_t open_type = 0;
    std::uint8_t open_semantic = 0;
    std::uint8_t open_direction = 0;
    std::uint8_t open_peer = 0;
    Digest open_fork{};
    std::uint64_t open_message_identity = 0;
    std::uint32_t open_chunk = 0;
    bool saw_data = false;
    bool saw_projection_seal = false;
    bool saw_completeness = false;
    bool saw_end = false;
    Counter total;
    std::array<Counter, 17> lanes{};
    std::set<Digest> forks{Digest{}};
    Digest end_identity{};

    while (offset < exact_size) {
        need(!saw_end && exact_size - offset >= P1_HEADER_BYTES);
        std::array<unsigned char, P1_HEADER_BYTES> header{};
        read_exact(fd, header, offset);
        wire_hash.update(header);
        offset += header.size();
        const auto type = header[8];
        const auto semantic = header[9];
        const auto direction = header[10];
        const auto peer = header[11];
        const auto flags = header[12];
        const auto monotonic = be64(header.data() + 16);
        const auto sequence = be64(header.data() + 24);
        const auto message = be64(header.data() + 32);
        const auto chunk = be32(header.data() + 40);
        const auto size = be32(header.data() + 44);
        Digest fork{};
        std::copy_n(header.begin() + 48, fork.size(), fork.begin());
        need(header[13] == 0 && header[14] == 0 && header[15] == 0 &&
             std::equal(P1_MAGIC.begin(), P1_MAGIC.end(), header.begin()) &&
             type >= 1 && type <= 6 && semantic >= 1 && semantic <= 17 &&
             direction >= 1 && direction <= 3 && flags <= 3 &&
             size <= P1_MAX_CHUNK_BYTES && sequence == frames &&
             monotonic > 0 && monotonic >= prior_monotonic &&
             ((direction == 3 && peer == 0xff) ||
              (direction != 3 && peer <= 2)) &&
             forks.contains(fork) && size <= exact_size - offset);
        const auto monotonic_before = prior_monotonic;
        if (first_monotonic == 0) first_monotonic = monotonic;
        prior_monotonic = monotonic;

        std::vector<unsigned char> payload(size);
        if (!payload.empty()) read_exact(fd, payload, offset);
        wire_hash.update(payload);
        offset += payload.size();
        safe_add(payload_bytes, payload.size());
        Digest supplied_payload_hash{};
        std::copy_n(header.begin() + 80, supplied_payload_hash.size(),
                    supplied_payload_hash.begin());
        need(hash(payload) == supplied_payload_hash);

        const bool first = (flags & FLAG_FIRST) != 0;
        const bool last = (flags & FLAG_LAST) != 0;
        if (first) {
            need(!open_message && message == next_message && chunk == 0);
            open_message = true;
            open_type = type;
            open_semantic = semantic;
            open_direction = direction;
            open_peer = peer;
            open_fork = fork;
            open_message_identity = message;
            open_chunk = 0;
            ++next_message;
        } else {
            need(open_message && message == open_message_identity &&
                 chunk == open_chunk + 1);
            open_chunk = chunk;
        }
        need(open_message && type == open_type &&
             semantic == open_semantic && direction == open_direction &&
             peer == open_peer && fork == open_fork);

        if (frames == 0) {
            need(type == 1 && semantic == 1 && direction == 3 &&
                 peer == 0xff && flags == 3 && fork == Digest{});
            exact_hello(payload, binding, expected);
        } else if (type == 2) {
            need(!saw_projection_seal && !saw_completeness && !saw_end &&
                 !payload.empty());
            saw_data = true;
            auto& lane = lanes[semantic - 1];
            safe_add(lane.chunks, 1);
            safe_add(lane.bytes, payload.size());
            safe_add(total.chunks, 1);
            safe_add(total.bytes, payload.size());
            if (last) {
                safe_add(lane.messages, 1);
                safe_add(total.messages, 1);
            }
        } else if (type == 6) {
            need(!saw_projection_seal && !saw_completeness && !saw_end &&
                 flags == 3 && semantic == 2 && direction == 3 &&
                 peer == 0xff && payload.size() == 96 &&
                 std::equal(fork.begin(), fork.end(), payload.begin()));
            Digest child{};
            std::copy_n(payload.begin() + 32, child.size(), child.begin());
            need(nonzero(child) && forks.insert(child).second);
        } else if (type == 3) {
            need(saw_data && !saw_projection_seal && !saw_completeness &&
                 !saw_end && flags == 3 && semantic == 9 &&
                 direction == 3 && peer == 0xff && fork == Digest{} &&
                 payload.size() == expected.projection.size() &&
                 std::equal(expected.projection.begin(),
                            expected.projection.end(), payload.begin()));
            saw_projection_seal = true;
        } else if (type == 4) {
            need(saw_projection_seal && !saw_completeness && !saw_end &&
                 flags == 3 && semantic == 9 && direction == 3 &&
                 peer == 0xff && fork == Digest{});
            exact_completeness(payload, total, lanes, sequence,
                               first_monotonic, monotonic_before);
            saw_completeness = true;
        } else if (type == 5) {
            need(saw_completeness && !saw_end && flags == 3 &&
                 semantic == 9 && direction == 3 && peer == 0xff &&
                 fork == Digest{} && payload.empty() &&
                 offset == exact_size);
            std::vector<unsigned char> end(header.begin(), header.end());
            end_identity = hash(end);
            saw_end = true;
        } else {
            refuse();
        }

        if (last) open_message = false;
        ++frames;
    }

    need(saw_data && saw_projection_seal && saw_completeness && saw_end &&
         !open_message && frames > 0 && offset == exact_size &&
         nonzero(end_identity));
    ParsedFinalC03 result;
    result.frame_count = frames;
    result.raw_wire_bytes = exact_size;
    result.closure.record_count = frames;
    result.closure.payload_bytes = payload_bytes;
    result.closure.raw_wire_bytes = exact_size;
    result.closure.record_root = wire_hash.finish();
    result.closure.end_frame_identity = end_identity;
    std::vector<unsigned char> eof;
    add(eof, "KPB_CAPTURE_PRODUCER_STREAM_EOF_V1\n");
    add_big(eof, expected.round, 4);
    eof.push_back(P1_CORRUPT_SERVER_KIND);
    add_big(eof, frames, 8);
    add_big(eof, payload_bytes, 8);
    add_big(eof, exact_size, 8);
    add(eof, result.closure.record_root);
    add(eof, result.closure.end_frame_identity);
    result.closure.eof_identity = hash(eof);
    return result;
}

const ManifestEntry& p1_manifest(const RunBinding& binding) {
    const auto index = static_cast<unsigned>(ManifestComponent::P1Capture) - 1;
    need(index < binding.finite_manifest.entries.size());
    const auto& result = binding.finite_manifest.entries[index];
    need(result.component == ManifestComponent::P1Capture);
    return result;
}

void validate_round_binding(const RunBinding& binding,
                            const FinalC03RoundBinding& round,
                            unsigned index) {
    const auto& manifest = p1_manifest(binding);
    need(index < FINAL_C03_ROUNDS && round.round == index + 1 &&
         round.fixed_fd == FINAL_C03_FIXED_FDS[index] &&
         round.financial_run == binding.financial_runs[index] &&
         round.attempt == binding.round_attempts[index] &&
         round.cohort == binding.round_cohorts[index] &&
         round.capture_plan == binding.round_capture_plans[index] &&
         round.projection == binding.projections[index] &&
         round.source_identity == manifest.source_identity &&
         round.build_identity == manifest.build_identity &&
         round.runtime_identity == manifest.runtime_identity &&
         round.launcher_identity == manifest.launcher_identity &&
         round.source_identity == binding.capture_source &&
         round.build_identity == binding.capture_build &&
         round.runtime_identity == binding.capture_runtime &&
         round.launcher_identity == binding.capture_launcher &&
         nonzero(round.process_identity) &&
         nonzero(round.child_exit_identity) &&
         nonzero(round.model_preimage_identity) &&
         nonzero(round.query_store_preimage_identity) &&
         nonzero(round.scalar_capture_manifest_identity));
    const auto& closure = round.closure_evidence;
    need(nonzero(closure.record_root) &&
         nonzero(closure.end_frame_identity) &&
         nonzero(closure.eof_identity) && closure.record_count > 0 &&
         closure.payload_bytes > 0 && closure.raw_wire_bytes > 0);
}

} // namespace

struct TerminalFinalC03ObservationAuthority::Storage {
    RunBinding binding;
    std::array<FinalC03RoundBinding, FINAL_C03_ROUNDS> rounds{};
    std::array<int, FINAL_C03_ROUNDS> fds{-1, -1};
    std::array<std::uint64_t, FINAL_C03_ROUNDS> devices{};
    std::array<std::uint64_t, FINAL_C03_ROUNDS> inodes{};
    std::array<std::uint64_t, FINAL_C03_ROUNDS> sizes{};
    std::array<std::uint64_t, FINAL_C03_ROUNDS> frame_counts{};

    Storage(const RunBinding& selected,
            const std::array<FinalC03RoundBinding, FINAL_C03_ROUNDS>&
                selected_rounds,
            std::array<int, FINAL_C03_ROUNDS> selected_fds)
        : binding(selected), rounds(selected_rounds), fds(selected_fds) {}

    ~Storage() {
        for (auto& fd : fds) close_fd(fd);
        static_assert(std::is_trivially_copyable_v<RunBinding>);
        static_assert(std::is_trivially_copyable_v<FinalC03RoundBinding>);
        OPENSSL_cleanse(&binding, sizeof(binding));
        OPENSSL_cleanse(rounds.data(), sizeof(rounds));
    }
};

TerminalFinalC03ObservationAuthority::TerminalFinalC03ObservationAuthority(
        const RunBinding& binding,
        const std::array<FinalC03RoundBinding, FINAL_C03_ROUNDS>& rounds,
        std::array<int, FINAL_C03_ROUNDS> fds)
    : storage_(std::make_unique<Storage>(binding, rounds, fds)) {
    try {
        validate_measurement_run_binding(binding);
        need(rounds[0].process_identity != rounds[1].process_identity &&
             rounds[0].child_exit_identity !=
                 rounds[1].child_exit_identity);
        for (unsigned index = 0; index < FINAL_C03_ROUNDS; ++index) {
            validate_round_binding(binding, rounds[index], index);
            struct stat before{};
            const int flags = ::fcntl(storage_->fds[index], F_GETFL);
            const int fd_flags = ::fcntl(storage_->fds[index], F_GETFD);
            const int seals = ::fcntl(storage_->fds[index], F_GET_SEALS);
            need(storage_->fds[index] >= 0 &&
                 ::fstat(storage_->fds[index], &before) == 0 &&
                 S_ISREG(before.st_mode) && before.st_uid == ::geteuid() &&
                 before.st_size > 0 && flags >= 0 &&
                 (flags & O_ACCMODE) == O_RDONLY && fd_flags >= 0 &&
                 (fd_flags & FD_CLOEXEC) != 0 && seals >= 0 &&
                 (seals & REQUIRED_SEALS) == REQUIRED_SEALS &&
                 static_cast<std::uint64_t>(before.st_size) ==
                     rounds[index].closure_evidence.raw_wire_bytes);
            storage_->devices[index] = before.st_dev;
            storage_->inodes[index] = before.st_ino;
            storage_->sizes[index] = before.st_size;
            const auto parsed = parse_final_c03(
                storage_->fds[index], storage_->sizes[index], binding,
                rounds[index]);
            need(parsed.closure == rounds[index].closure_evidence);
            storage_->frame_counts[index] = parsed.frame_count;
            struct stat after{};
            need(::fstat(storage_->fds[index], &after) == 0 &&
                 before.st_dev == after.st_dev &&
                 before.st_ino == after.st_ino &&
                 before.st_size == after.st_size &&
                 before.st_mode == after.st_mode &&
                 before.st_uid == after.st_uid &&
                 ::fcntl(storage_->fds[index], F_GET_SEALS) == seals);
        }
        need(storage_->devices[0] != storage_->devices[1] ||
             storage_->inodes[0] != storage_->inodes[1]);
    } catch (...) {
        storage_.reset();
        refuse();
    }
}

TerminalFinalC03ObservationAuthority::
TerminalFinalC03ObservationAuthority(
        TerminalFinalC03ObservationAuthority&& other) noexcept
    : storage_(std::move(other.storage_)) {}

TerminalFinalC03ObservationAuthority::~TerminalFinalC03ObservationAuthority()
    = default;

#ifdef KPB_NATIVE_EMPIRICAL_TERMINAL_SOURCE_TEST_SETUP
TerminalFinalC03ObservationAuthority
NativeEmpiricalTerminalSourceParser::test_only_parse(
        const RunBinding& binding,
        const std::array<FinalC03RoundBinding, FINAL_C03_ROUNDS>& rounds,
        std::array<int, FINAL_C03_ROUNDS> fds) {
    return TerminalFinalC03ObservationAuthority(binding, rounds, fds);
}

TestOnlyFinalC03Summary
NativeEmpiricalTerminalSourceParser::test_only_consume(
        TerminalFinalC03ObservationAuthority&& supplied) {
    need(supplied.storage_ != nullptr);
    auto storage = std::move(supplied.storage_);
    return {
        .frame_counts = storage->frame_counts,
        .raw_wire_bytes = storage->sizes,
        .complete_attempt_history = false,
    };
}
#endif

} // namespace kpb::measurement::empirical_terminal_source
