#include "privacy_native_empirical_result_authority.hpp"

#include "privacy_measurement_run_binding_wire.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <span>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpb::measurement::empirical_result {
namespace {

constexpr std::array<unsigned char, 8> HISTORY_MAGIC{
    'K', 'P', 'B', 'E', 'M', 'P', 'H', '1'};
constexpr std::array<unsigned char, 8> CANDIDATE_MAGIC{
    'K', 'P', 'B', 'E', 'M', 'P', 'C', '1'};
constexpr std::array<unsigned char, 40> FIELD_AGGREGATE_DOMAIN{
    'K','P','B','_','N','A','T','I','V','E','_','E','M','P','I','R','I','C','A','L',
    '_','F','I','E','L','D','_','A','G','G','R','E','G','A','T','E','_','V','1','\n'};
constexpr std::size_t COMMON_HEADER_BYTES = 16 + wire::RUN_BINDING_BYTES + 4;
constexpr std::size_t ATTEMPT_BYTES = 264;
constexpr std::size_t ROUND_HEADER_BYTES = 8;
constexpr std::size_t CANDIDATE_BYTES =
    32 + EMPIRICAL_OCCURRENCES * 32;
constexpr std::size_t CANDIDATE_FILE_BYTES =
    COMMON_HEADER_BYTES + EMPIRICAL_CANDIDATES * CANDIDATE_BYTES;
constexpr std::size_t MIN_HISTORY_FILE_BYTES =
    COMMON_HEADER_BYTES + EMPIRICAL_ROUNDS *
        (ROUND_HEADER_BYTES + ATTEMPT_BYTES);
constexpr std::size_t MAX_HISTORY_FILE_BYTES =
    COMMON_HEADER_BYTES + EMPIRICAL_ROUNDS *
        (ROUND_HEADER_BYTES +
         MAX_EMPIRICAL_ATTEMPTS_PER_ROUND * ATTEMPT_BYTES);

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

std::uint32_t u32le(std::span<const unsigned char> value) {
    need(value.size() == 4);
    return static_cast<std::uint32_t>(value[0]) |
        (static_cast<std::uint32_t>(value[1]) << 8U) |
        (static_cast<std::uint32_t>(value[2]) << 16U) |
        (static_cast<std::uint32_t>(value[3]) << 24U);
}

void append_u32le(std::vector<unsigned char>& out, std::uint32_t value) {
    for (unsigned shift : {0U, 8U, 16U, 24U})
        out.push_back(static_cast<unsigned char>(value >> shift));
}

Digest digest(std::span<const unsigned char> value) {
    Digest result{};
    need(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}

struct Cursor {
    std::span<const unsigned char> value;
    std::size_t at{};

    std::span<const unsigned char> take(std::size_t count) {
        need(at <= value.size() && count <= value.size() - at);
        auto result = value.subspan(at, count);
        at += count;
        return result;
    }
    std::uint8_t u8() { return take(1)[0]; }
    std::uint32_t u32() { return u32le(take(4)); }
    Digest word() {
        Digest result{};
        const auto selected = take(result.size());
        std::copy(selected.begin(), selected.end(), result.begin());
        return result;
    }
};

struct SealedBytes {
    std::vector<unsigned char> value;
    dev_t device{};
    ino_t inode{};
    SealedBytes() = default;
    SealedBytes(const SealedBytes&) = delete;
    SealedBytes& operator=(const SealedBytes&) = delete;
    SealedBytes(SealedBytes&&) noexcept = default;
    SealedBytes& operator=(SealedBytes&&) = delete;
    ~SealedBytes() {
        if (!value.empty()) OPENSSL_cleanse(value.data(), value.size());
    }
};

SealedBytes consume_sealed_fd(int& fd, std::size_t minimum,
                              std::size_t maximum) {
    try {
        struct stat selected{};
        constexpr int required_seals =
            F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
        const int flags = ::fcntl(fd, F_GETFL);
        const int seals = ::fcntl(fd, F_GET_SEALS);
        need(fd >= 0 && ::fstat(fd, &selected) == 0 &&
             S_ISREG(selected.st_mode) && selected.st_uid == ::geteuid() &&
             selected.st_size >= 0 &&
             static_cast<std::uint64_t>(selected.st_size) >= minimum &&
             static_cast<std::uint64_t>(selected.st_size) <= maximum &&
             flags >= 0 && (flags & O_ACCMODE) == O_RDONLY && seals >= 0 &&
             (seals & required_seals) == required_seals);
        SealedBytes result;
        result.device = selected.st_dev;
        result.inode = selected.st_ino;
        result.value.resize(static_cast<std::size_t>(selected.st_size));
        std::size_t at = 0;
        while (at < result.value.size()) {
            ssize_t amount;
            do {
                amount = ::pread(fd, result.value.data() + at,
                                 result.value.size() - at,
                                 static_cast<off_t>(at));
            } while (amount < 0 && errno == EINTR);
            need(amount > 0);
            at += static_cast<std::size_t>(amount);
        }
        struct stat after{};
        need(::fstat(fd, &after) == 0 &&
             selected.st_dev == after.st_dev &&
             selected.st_ino == after.st_ino &&
             selected.st_size == after.st_size &&
             selected.st_mode == after.st_mode &&
             selected.st_uid == after.st_uid &&
             ::fcntl(fd, F_GET_SEALS) == seals);
        close_fd(fd);
        return result;
    } catch (...) {
        close_fd(fd);
        refuse();
    }
}

void exact_binding(Cursor& cursor, const RunBinding& binding) {
    const auto expected = wire::canonical_run_binding_bytes(binding);
    const auto supplied = cursor.take(expected.size());
    need(std::equal(supplied.begin(), supplied.end(), expected.begin()));
}

void exact_header(Cursor& cursor,
                  const std::array<unsigned char, 8>& magic,
                  std::size_t size, const RunBinding& binding) {
    const auto supplied_magic = cursor.take(magic.size());
    need(std::equal(supplied_magic.begin(), supplied_magic.end(),
                    magic.begin()) &&
         cursor.u32() == 1 && cursor.u32() == size);
    exact_binding(cursor, binding);
    need(cursor.u8() == EMPIRICAL_ROUNDS &&
         cursor.u8() == EMPIRICAL_FIELDS && cursor.u8() == 0 &&
         cursor.u8() == 0);
}

struct ParsedHistory {
    std::array<std::array<Digest, EMPIRICAL_FIELDS>, EMPIRICAL_ROUNDS>
        aggregates{};
    Digest source_identity{};
};

ParsedHistory parse_history(std::span<const unsigned char> raw,
                            const RunBinding& binding) {
    Cursor cursor{raw};
    exact_header(cursor, HISTORY_MAGIC, raw.size(), binding);
    ParsedHistory result;
    for (std::size_t round = 0; round < EMPIRICAL_ROUNDS; ++round) {
        need(cursor.u8() == round + 1 && cursor.u8() == 0 &&
             cursor.u8() == 0 && cursor.u8() == 0);
        const auto attempts = cursor.u32();
        need(attempts > 0 && attempts <= MAX_EMPIRICAL_ATTEMPTS_PER_ROUND);
        std::array<std::vector<unsigned char>, EMPIRICAL_FIELDS> preimages;
        Digest previous{};
        std::vector<Digest> seen_attempts;
        seen_attempts.reserve(attempts);
        for (std::uint32_t attempt = 0; attempt < attempts; ++attempt) {
            need(cursor.u32() == attempt);
            const Digest identity = cursor.word();
            const Digest predecessor = cursor.word();
            const auto outcome = static_cast<EmpiricalAttemptOutcome>(
                cursor.u8());
            const auto state = static_cast<EmpiricalStreamState>(
                cursor.u8());
            need(cursor.u8() == 0 && cursor.u8() == 0);
            const Digest capture = cursor.word();
            need(static_cast<unsigned>(outcome) >= 1 &&
                 static_cast<unsigned>(outcome) <= 6 &&
                 static_cast<unsigned>(state) >= 1 &&
                 static_cast<unsigned>(state) <= 4);
            need(nonzero(identity) && nonzero(capture) &&
                 predecessor == (attempt == 0 ? Digest{} : previous) &&
                 std::find(seen_attempts.begin(), seen_attempts.end(),
                           identity) == seen_attempts.end());
            const bool final = attempt + 1 == attempts;
            need((final && outcome == EmpiricalAttemptOutcome::Complete &&
                  state == EmpiricalStreamState::CompleteEnd) ||
                 (!final && outcome != EmpiricalAttemptOutcome::Complete &&
                  state != EmpiricalStreamState::CompleteEnd));
            for (std::size_t field = 0; field < EMPIRICAL_FIELDS; ++field) {
                const Digest observed = cursor.word();
                need(nonzero(observed));
                auto& preimage = preimages[field];
                preimage.insert(preimage.end(),
                                FIELD_AGGREGATE_DOMAIN.begin(),
                                FIELD_AGGREGATE_DOMAIN.end());
                preimage.push_back(static_cast<unsigned char>(round + 1));
                preimage.push_back(static_cast<unsigned char>(field + 1));
                append_u32le(preimage, attempt);
                preimage.insert(preimage.end(), identity.begin(),
                                identity.end());
                preimage.insert(preimage.end(), predecessor.begin(),
                                predecessor.end());
                preimage.push_back(static_cast<unsigned char>(outcome));
                preimage.push_back(static_cast<unsigned char>(state));
                preimage.insert(preimage.end(), capture.begin(),
                                capture.end());
                preimage.insert(preimage.end(), observed.begin(),
                                observed.end());
            }
            seen_attempts.push_back(identity);
            previous = identity;
        }
        for (std::size_t field = 0; field < EMPIRICAL_FIELDS; ++field)
            result.aggregates[round][field] = digest(preimages[field]);
    }
    need(cursor.at == raw.size());
    result.source_identity = digest(raw);
    return result;
}

struct ParsedCandidates {
    std::array<Digest, EMPIRICAL_CANDIDATES> mapping_identities{};
    std::array<std::array<std::array<Digest, EMPIRICAL_FIELDS>,
                          EMPIRICAL_ROUNDS>, EMPIRICAL_CANDIDATES>
        predicted{};
    Digest source_identity{};
};

ParsedCandidates parse_candidates(std::span<const unsigned char> raw,
                                  const RunBinding& binding) {
    Cursor cursor{raw};
    exact_header(cursor, CANDIDATE_MAGIC, raw.size(), binding);
    ParsedCandidates result;
    for (std::size_t candidate = 0;
         candidate < EMPIRICAL_CANDIDATES; ++candidate) {
        result.mapping_identities[candidate] = cursor.word();
        need(nonzero(result.mapping_identities[candidate]));
        for (std::size_t round = 0; round < EMPIRICAL_ROUNDS; ++round)
            for (std::size_t field = 0; field < EMPIRICAL_FIELDS; ++field) {
                result.predicted[candidate][round][field] = cursor.word();
                need(nonzero(result.predicted[candidate][round][field]));
            }
    }
    need(cursor.at == raw.size() &&
         result.mapping_identities[0] != result.mapping_identities[1]);
    result.source_identity = digest(raw);
    return result;
}

} // namespace

struct EmpiricalCaptureHistoryAuthority::Storage {
    RunBinding binding;
    int fd{-1};
    Storage(const RunBinding& selected, int supplied)
        : binding(selected), fd(supplied) {}
    ~Storage() { close_fd(fd); }
};

struct FrozenEmpiricalCandidateSetAuthority::Storage {
    RunBinding binding;
    int fd{-1};
    Storage(const RunBinding& selected, int supplied)
        : binding(selected), fd(supplied) {}
    ~Storage() { close_fd(fd); }
};

struct NativeEmpiricalResultAuthority::Storage {
    RunBinding binding;
    Digest history_identity{};
    Digest candidate_set_identity{};
    std::array<std::uint8_t, EMPIRICAL_OCCURRENCES> match_masks{};
    std::uint8_t retained_mask{};
    std::array<std::uint8_t, 2> views = EMPIRICAL_VIEW_CODES;

    ~Storage() {
        static_assert(std::is_trivially_copyable_v<RunBinding>);
        OPENSSL_cleanse(&binding, sizeof(binding));
        OPENSSL_cleanse(history_identity.data(), history_identity.size());
        OPENSSL_cleanse(candidate_set_identity.data(),
                        candidate_set_identity.size());
        OPENSSL_cleanse(match_masks.data(), match_masks.size());
        retained_mask = 0;
        OPENSSL_cleanse(views.data(), views.size());
    }
};

EmpiricalCaptureHistoryAuthority::EmpiricalCaptureHistoryAuthority(
        const RunBinding& binding, int fd)
    : storage_(std::make_unique<Storage>(binding, fd)) {
    try { validate_measurement_run_binding(binding); }
    catch (...) { storage_.reset(); refuse(); }
    need(fd >= 0);
}

EmpiricalCaptureHistoryAuthority::EmpiricalCaptureHistoryAuthority(
        EmpiricalCaptureHistoryAuthority&& other) noexcept
    : storage_(std::move(other.storage_)) {}

EmpiricalCaptureHistoryAuthority::~EmpiricalCaptureHistoryAuthority() =
    default;

FrozenEmpiricalCandidateSetAuthority::FrozenEmpiricalCandidateSetAuthority(
        const RunBinding& binding, int fd)
    : storage_(std::make_unique<Storage>(binding, fd)) {
    try { validate_measurement_run_binding(binding); }
    catch (...) { storage_.reset(); refuse(); }
    need(fd >= 0);
}

FrozenEmpiricalCandidateSetAuthority::FrozenEmpiricalCandidateSetAuthority(
        FrozenEmpiricalCandidateSetAuthority&& other) noexcept
    : storage_(std::move(other.storage_)) {}

FrozenEmpiricalCandidateSetAuthority::~FrozenEmpiricalCandidateSetAuthority() =
    default;

NativeEmpiricalResultAuthority::NativeEmpiricalResultAuthority(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }

NativeEmpiricalResultAuthority::NativeEmpiricalResultAuthority(
        NativeEmpiricalResultAuthority&& other) noexcept
    : storage_(std::move(other.storage_)) {}

NativeEmpiricalResultAuthority::~NativeEmpiricalResultAuthority() = default;

NativeEmpiricalResultAuthority
NativeEmpiricalResultAuthority::transfer_for_observation_output_join(
        const RunBinding& expected) && {
    need(storage_ != nullptr);
    auto storage = std::move(storage_);
    validate_measurement_run_binding(expected);
    validate_measurement_run_binding(storage->binding);
    need(storage->binding == expected &&
         nonzero(storage->history_identity) &&
         nonzero(storage->candidate_set_identity) &&
         storage->history_identity != storage->candidate_set_identity &&
         storage->views == EMPIRICAL_VIEW_CODES &&
         storage->retained_mask > 0 && storage->retained_mask <= 0x3);
    for (const auto mask : storage->match_masks)
        need(mask > 0 && mask <= 0x3 &&
             (mask & storage->retained_mask) == storage->retained_mask);
    return NativeEmpiricalResultAuthority(std::move(storage));
}

NativeEmpiricalResultAuthority NativeEmpiricalResultDeriver::derive(
        EmpiricalCaptureHistoryAuthority&& supplied_history,
        FrozenEmpiricalCandidateSetAuthority&& supplied_candidates) {
    auto history = std::move(supplied_history.storage_);
    auto candidates = std::move(supplied_candidates.storage_);
    // Claim both linear inputs before the first throwing check. A stale first
    // input must never leave a fresh second input reusable by the caller.
    need(history != nullptr && candidates != nullptr);
    need(history->binding == candidates->binding);
    auto history_bytes = consume_sealed_fd(
        history->fd, MIN_HISTORY_FILE_BYTES, MAX_HISTORY_FILE_BYTES);
    auto candidate_bytes = consume_sealed_fd(
        candidates->fd, CANDIDATE_FILE_BYTES, CANDIDATE_FILE_BYTES);
    need(history_bytes.device != candidate_bytes.device ||
         history_bytes.inode != candidate_bytes.inode);
    const auto parsed_history = parse_history(
        history_bytes.value, history->binding);
    const auto parsed_candidates = parse_candidates(
        candidate_bytes.value, candidates->binding);
    auto result = std::make_unique<NativeEmpiricalResultAuthority::Storage>();
    result->binding = history->binding;
    result->history_identity = parsed_history.source_identity;
    result->candidate_set_identity = parsed_candidates.source_identity;
    result->retained_mask = 0x3;
    std::size_t occurrence = 0;
    for (std::size_t round = 0; round < EMPIRICAL_ROUNDS; ++round) {
        for (std::size_t field = 0; field < EMPIRICAL_FIELDS; ++field) {
            std::uint8_t mask = 0;
            for (std::size_t candidate = 0;
                 candidate < EMPIRICAL_CANDIDATES; ++candidate)
                if (parsed_history.aggregates[round][field] ==
                        parsed_candidates.predicted[candidate][round][field])
                    mask |= static_cast<std::uint8_t>(1U << candidate);
            result->match_masks[occurrence++] = mask;
            result->retained_mask &= mask;
        }
    }
    need(occurrence == EMPIRICAL_OCCURRENCES &&
         result->retained_mask != 0);
    return NativeEmpiricalResultAuthority(std::move(result));
}

#ifdef KPB_NATIVE_EMPIRICAL_RESULT_TEST_SETUP
EmpiricalCaptureHistoryAuthority
NativeEmpiricalResultDeriver::test_only_admit_history(
        const RunBinding& binding, int fd) {
    return EmpiricalCaptureHistoryAuthority(binding, fd);
}

FrozenEmpiricalCandidateSetAuthority
NativeEmpiricalResultDeriver::test_only_admit_candidate_set(
        const RunBinding& binding, int fd) {
    return FrozenEmpiricalCandidateSetAuthority(binding, fd);
}

TestOnlyNativeEmpiricalResultSummary
NativeEmpiricalResultDeriver::test_only_consume(
        NativeEmpiricalResultAuthority&& supplied) {
    need(supplied.storage_ != nullptr);
    auto storage = std::move(supplied.storage_);
    return {
        .candidate_match_masks = storage->match_masks,
        .retained_candidate_mask = storage->retained_mask,
        .bound_view_codes = storage->views,
    };
}
#endif

} // namespace kpb::measurement::empirical_result
