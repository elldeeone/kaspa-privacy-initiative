#include "registered_trial_attempt_history.hpp"
#include "../../private_batch_trial/privacy_capture_producer_runtime.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <openssl/evp.h>
#include <span>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::registered_driver::attempt_history {
namespace {

constexpr std::array<unsigned char, 8> C03_MAGIC{
    'K', 'P', 'B', 'P', '1', 'C', '0', '3'};
constexpr std::size_t C03_HEADER_BYTES = 112;
constexpr std::uint32_t C03_MAX_CHUNK_BYTES = 1U << 16;
constexpr std::string_view ATTEMPT_ID_DOMAIN =
    "KPB_REGISTERED_TRIAL_ATTEMPT_HISTORY_ATTEMPT_V1\n";
constexpr std::string_view PROCESS_ID_DOMAIN =
    "KPB_REGISTERED_TRIAL_ATTEMPT_HISTORY_PROCESS_V1\n";
constexpr std::string_view EXIT_ID_DOMAIN =
    "KPB_REGISTERED_TRIAL_ATTEMPT_HISTORY_CHILD_EXIT_V1\n";
constexpr std::string_view HISTORY_ID_DOMAIN =
    "KPB_REGISTERED_TRIAL_ATTEMPT_HISTORY_V1\n";

[[noreturn]] void refuse() { throw AttemptHistoryRefused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

bool lower_hex(char value) {
    return (value >= '0' && value <= '9') ||
           (value >= 'a' && value <= 'f');
}

void uuid(const std::string& value) {
    need(value.size() == 36);
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (index == 8 || index == 13 || index == 18 || index == 23)
            need(value[index] == '-');
        else
            need(lower_hex(value[index]));
    }
    need(value[14] == '4' &&
         std::string_view("89ab").find(value[19]) != std::string_view::npos);
}

std::uint32_t read_be32(const unsigned char* in) {
    std::uint32_t value = 0;
    for (unsigned index = 0; index < 4; ++index)
        value = static_cast<std::uint32_t>((value << 8) | in[index]);
    return value;
}

std::uint64_t read_be64(const unsigned char* in) {
    std::uint64_t value = 0;
    for (unsigned index = 0; index < 8; ++index)
        value = (value << 8) | in[index];
    return value;
}

void append_u32(std::vector<unsigned char>& out, std::uint32_t value) {
    for (unsigned index = 0; index < 4; ++index)
        out.push_back(static_cast<unsigned char>(value >> (8 * index)));
}

void append_u64(std::vector<unsigned char>& out, std::uint64_t value) {
    for (unsigned index = 0; index < 8; ++index)
        out.push_back(static_cast<unsigned char>(value >> (8 * index)));
}

void append_i32(std::vector<unsigned char>& out, std::int32_t value) {
    append_u32(out, static_cast<std::uint32_t>(value));
}

void append(std::vector<unsigned char>& out,
            std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}

void append_text(std::vector<unsigned char>& out, std::string_view value) {
    append_u64(out, value.size());
    append(out, {reinterpret_cast<const unsigned char*>(value.data()),
                 value.size()});
}

void append_worker_binding(
        std::vector<unsigned char>& out,
        const kpb::measurement::WorkerBinding& value) {
    for (const auto* field : {
             &value.source_identity, &value.build_identity,
             &value.runtime_identity, &value.assets_identity,
             &value.pinned_executable_identity, &value.launcher_identity})
        append(out, *field);
}

void append_run_binding(
        std::vector<unsigned char>& out,
        const kpb::measurement::RunBinding& value) {
    append_u32(out, static_cast<std::uint8_t>(value.classification));
    for (const auto* field : {
             &value.comparison_selection, &value.run_selection,
             &value.trial, &value.attempt, &value.cohort, &value.capture,
             &value.method, &value.workload, &value.source_closure,
             &value.runtime})
        append(out, *field);
    append(out, value.finite_manifest.manifest_identity);
    append(out, value.finite_manifest.parent_recomputation_identity);
    for (const auto& entry : value.finite_manifest.entries) {
        append_u32(out, static_cast<std::uint8_t>(entry.component));
        for (const auto* field : {
                 &entry.source_identity, &entry.build_identity,
                 &entry.runtime_identity, &entry.assets_identity,
                 &entry.pinned_executable_identity,
                 &entry.launcher_identity})
            append(out, *field);
    }
    for (const auto* field : {
             &value.outer_parent_process, &value.outer_parent_executable,
             &value.capture_source, &value.capture_build,
             &value.capture_runtime, &value.capture_launcher})
        append(out, *field);
    append_worker_binding(out, value.observer_worker);
    append_worker_binding(out, value.score_worker);
    append_worker_binding(out, value.aggregate_worker);
    for (const auto& values : {
             value.financial_runs, value.round_attempts,
             value.round_cohorts, value.round_capture_plans,
             value.projections})
        for (const auto& field : values) append(out, field);
}

class HashAccumulator final {
    EVP_MD_CTX* context_{EVP_MD_CTX_new()};
    bool finished_{};
public:
    HashAccumulator() {
        need(context_ != nullptr &&
             EVP_DigestInit_ex(context_, EVP_sha256(), nullptr) == 1);
    }
    HashAccumulator(const HashAccumulator&) = delete;
    HashAccumulator& operator=(const HashAccumulator&) = delete;
    ~HashAccumulator() { EVP_MD_CTX_free(context_); }
    void update(std::span<const unsigned char> value) {
        need(!finished_ &&
             (value.empty() || EVP_DigestUpdate(
                 context_, value.data(), value.size()) == 1));
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

Digest digest(std::span<const unsigned char> value) {
    HashAccumulator hash;
    hash.update(value);
    return hash.finish();
}

Digest registered_trial_identity(std::string_view value) {
    std::vector<unsigned char> preimage;
    constexpr std::string_view domain =
        "KPB_REGISTERED_TRIAL_UUID_IDENTITY_V1\n";
    append(preimage, {reinterpret_cast<const unsigned char*>(domain.data()),
                      domain.size()});
    append_u64(preimage, value.size());
    append(preimage, {reinterpret_cast<const unsigned char*>(value.data()),
                      value.size()});
    return digest(preimage);
}

Digest capture_attempt_identity(std::string_view value) {
    std::vector<unsigned char> preimage;
    constexpr std::string_view domain =
        "KPB_CAPTURE_ATTEMPT_ID_V1\n";
    append(preimage, {reinterpret_cast<const unsigned char*>(domain.data()),
                      domain.size()});
    append(preimage, {reinterpret_cast<const unsigned char*>(value.data()),
                      value.size()});
    return digest(preimage);
}

Digest digest_fd(int fd, std::uint64_t size) {
    HashAccumulator hash;
    std::array<unsigned char, 1U << 20> buffer{};
    std::uint64_t offset = 0;
    while (offset < size) {
        const auto wanted = static_cast<std::size_t>(std::min<std::uint64_t>(
            buffer.size(), size - offset));
        ssize_t count;
        do {
            count = ::pread(fd, buffer.data(), wanted,
                            static_cast<off_t>(offset));
        } while (count < 0 && errno == EINTR);
        need(count > 0 && static_cast<std::size_t>(count) <= wanted);
        hash.update({buffer.data(), static_cast<std::size_t>(count)});
        offset += static_cast<std::uint64_t>(count);
    }
    return hash.finish();
}

std::uint64_t monotonic_ns() {
    timespec now{};
    need(::clock_gettime(CLOCK_MONOTONIC, &now) == 0 &&
         now.tv_sec >= 0 && now.tv_nsec >= 0 && now.tv_nsec < 1000000000L);
    const auto seconds = static_cast<std::uint64_t>(now.tv_sec);
    need(seconds <= (std::numeric_limits<std::uint64_t>::max() -
                     static_cast<std::uint64_t>(now.tv_nsec)) /
                        1000000000ULL);
    return seconds * 1000000000ULL +
        static_cast<std::uint64_t>(now.tv_nsec);
}

struct SourceAttemptBinding final {
    unsigned round{};
    std::string attempt_uuid;
    Digest financial_run{};
    Digest cohort{};
    Digest capture_plan{};
    Digest projection{};
    Digest capture_source{};
    Digest capture_build{};
    Digest capture_runtime{};
    Digest capture_launcher{};
    Digest route_requirement{};
    Digest route_completion{};
    std::uint8_t sealed_c03_fault{};
};

enum class SourceChildDisposition : std::uint8_t {
    ExitZero = 1,
    ExitNonzero = 2,
    Signal = 3,
};

struct RuntimeHistoryMaterial final {
    kpb::measurement::RunBinding binding;
    std::string capture_trial_id;
    std::array<std::string, 2> capture_attempt_ids;
    Digest closure_identity{};
    Digest archive_reservation_identity{};
    std::array<unsigned, 2> source_slots{};
    std::array<unsigned, 2> fixed_fds{};
    std::array<OwnedSealedC03Fd, 2> fds;
    std::array<std::uint64_t, 2> devices{};
    std::array<std::uint64_t, 2> inodes{};
    std::array<std::uint64_t, 2> sizes{};
    std::array<std::int32_t, 2> seals{};
    std::array<Digest, 2> sha256{};
    std::array<Digest, 2> route_requirements{};
    std::array<Digest, 2> route_completions{};
    bool writer_aliases_closed{};
    std::array<kpb::measurement::producer_runtime::
        ProducerAttemptC03StreamState, 2> states{};
    std::array<kpb::measurement::producer_runtime::
        ProducerAttemptDrainFailure, 2> failures{};
    kpb::measurement::producer_runtime::ProducerAttemptDrainFailure
        attempt_failure{};
    std::uint8_t first_failed_slot{0xff};
    std::uint64_t start_monotonic_ns{};
    std::uint64_t end_monotonic_ns{};
    std::int64_t producer_pid{};
    std::int32_t producer_wait_status{};
    bool wait_observed{};
    bool pidfd_exit_observed{};
    Digest producer_child_exit_identity{};
};

AttemptStreamState stream_state(
        kpb::measurement::producer_runtime::
            ProducerAttemptC03StreamState value) {
    using Input = kpb::measurement::producer_runtime::
        ProducerAttemptC03StreamState;
    switch (value) {
    case Input::CompleteEnd: return AttemptStreamState::CompleteEnd;
    case Input::Empty: return AttemptStreamState::Empty;
    case Input::PartialHeader: return AttemptStreamState::PartialHeader;
    case Input::PartialPayload: return AttemptStreamState::PartialPayload;
    case Input::ClosedWithoutEnd:
        return AttemptStreamState::ClosedWithoutEnd;
    case Input::Invalid: return AttemptStreamState::Invalid;
    }
    refuse();
}

AttemptFailure attempt_failure(
        kpb::measurement::producer_runtime::ProducerAttemptDrainFailure value) {
    using Input = kpb::measurement::producer_runtime::
        ProducerAttemptDrainFailure;
    switch (value) {
    case Input::None: return AttemptFailure::None;
    case Input::Empty: return AttemptFailure::EmptyStream;
    case Input::PartialHeader: return AttemptFailure::PartialHeader;
    case Input::PartialPayload: return AttemptFailure::PartialPayload;
    case Input::MissingEnd: return AttemptFailure::MissingEnd;
    case Input::ParserRefused: return AttemptFailure::InvalidHeader;
    case Input::OtherStreamRefused:
        return AttemptFailure::ProducerTransportInvalid;
    case Input::CaptureReadFailed: return AttemptFailure::CaptureReadFailed;
    case Input::ProducerChildExitedNonzero:
        return AttemptFailure::ChildExitedNonzero;
    case Input::ProducerChildSignaled: return AttemptFailure::ChildSignaled;
    case Input::RouteUnavailable: return AttemptFailure::RouteUnavailable;
    case Input::WaitStatusUnavailable:
        return AttemptFailure::WaitStatusUnavailable;
    }
    refuse();
}

Digest runtime_child_exit_identity(
        const Digest& process, const Digest& producer_exit,
        int wait_status, bool wait_observed, bool pidfd_exit_observed,
        std::uint64_t end) {
    std::vector<unsigned char> preimage;
    append_text(preimage,
                "KPB_REGISTERED_TRIAL_ATTEMPT_RUNTIME_CHILD_EXIT_V1\n");
    append(preimage, process);
    append(preimage, producer_exit);
    preimage.push_back(wait_observed ? 1 : 0);
    preimage.push_back(pidfd_exit_observed ? 1 : 0);
    append_i32(preimage, wait_status);
    append_u64(preimage, end);
    return digest(preimage);
}

Digest attempt_identity(
        const SourceAttemptBinding& binding, std::uint32_t ordinal,
        std::uint32_t retry_ordinal, const Digest& predecessor,
        const Digest& trial_predecessor) {
    std::vector<unsigned char> preimage;
    append_text(preimage, ATTEMPT_ID_DOMAIN);
    append_u32(preimage, binding.round);
    append_u32(preimage, ordinal);
    append_u32(preimage, retry_ordinal);
    append(preimage, predecessor);
    append(preimage, trial_predecessor);
    append_text(preimage, binding.attempt_uuid);
    append(preimage, binding.financial_run);
    append(preimage, binding.cohort);
    append(preimage, binding.capture_plan);
    append(preimage, binding.projection);
    append(preimage, binding.capture_source);
    append(preimage, binding.capture_build);
    append(preimage, binding.capture_runtime);
    append(preimage, binding.capture_launcher);
    append(preimage, binding.route_requirement);
    return digest(preimage);
}

Digest process_identity(
        const Digest& attempt, pid_t parent, pid_t child,
        std::uint64_t start) {
    std::vector<unsigned char> preimage;
    append_text(preimage, PROCESS_ID_DOMAIN);
    append(preimage, attempt);
    append_u64(preimage, static_cast<std::uint64_t>(parent));
    append_u64(preimage, static_cast<std::uint64_t>(child));
    append_u64(preimage, start);
    return digest(preimage);
}

Digest child_exit_identity(
        const Digest& process, int wait_status, std::uint64_t end) {
    std::vector<unsigned char> preimage;
    append_text(preimage, EXIT_ID_DOMAIN);
    append(preimage, process);
    append_i32(preimage, wait_status);
    append_u64(preimage, end);
    return digest(preimage);
}

struct ParsedStream {
    AttemptStreamState state{AttemptStreamState::Empty};
    AttemptFailure failure{AttemptFailure::EmptyStream};
    std::uint64_t partial_tail_bytes{};
    Digest partial_tail_sha256{};
};

class C03StreamParser final {
    std::array<unsigned char, C03_HEADER_BYTES> header_{};
    std::size_t header_at_{};
    std::uint32_t payload_bytes_{};
    std::uint32_t payload_at_{};
    std::uint64_t sequence_{};
    unsigned char record_type_{};
    Digest expected_payload_{};
    std::unique_ptr<HashAccumulator> payload_hash_;
    std::unique_ptr<HashAccumulator> tail_hash_;
    std::uint64_t tail_bytes_{};
    bool any_frame_{};
    bool end_seen_{};
    bool invalid_{};
    AttemptFailure invalid_failure_{AttemptFailure::InvalidHeader};

    void tail(std::span<const unsigned char> value) {
        if (!tail_hash_) tail_hash_ = std::make_unique<HashAccumulator>();
        tail_hash_->update(value);
        need(value.size() <=
             std::numeric_limits<std::uint64_t>::max() - tail_bytes_);
        tail_bytes_ += value.size();
    }

    void reset_frame() {
        header_at_ = 0;
        payload_bytes_ = 0;
        payload_at_ = 0;
        payload_hash_.reset();
        tail_hash_.reset();
        tail_bytes_ = 0;
    }

    void invalidate(AttemptFailure failure) {
        invalid_ = true;
        invalid_failure_ = failure;
    }

    void finish_frame() {
        need(payload_hash_ != nullptr);
        const auto observed = payload_hash_->finish();
        if (observed != expected_payload_) {
            invalidate(AttemptFailure::PayloadDigestMismatch);
            return;
        }
        any_frame_ = true;
        if (record_type_ == 5) {
            if (end_seen_) {
                invalidate(AttemptFailure::DuplicateEnd);
                return;
            }
            end_seen_ = true;
        }
        ++sequence_;
        reset_frame();
    }

    void header_complete() {
        if (!std::equal(C03_MAGIC.begin(), C03_MAGIC.end(),
                        header_.begin()) ||
            header_[8] < 1 || header_[8] > 6 ||
            read_be64(header_.data() + 24) != sequence_) {
            invalidate(AttemptFailure::InvalidHeader);
            return;
        }
        record_type_ = header_[8];
        payload_bytes_ = read_be32(header_.data() + 44);
        if (payload_bytes_ > C03_MAX_CHUNK_BYTES ||
            (record_type_ == 5 &&
             (payload_bytes_ != 0 || header_[12] != 3))) {
            invalidate(AttemptFailure::InvalidHeader);
            return;
        }
        std::copy_n(header_.begin() + 80, expected_payload_.size(),
                    expected_payload_.begin());
        payload_hash_ = std::make_unique<HashAccumulator>();
        if (payload_bytes_ == 0) finish_frame();
    }

public:
    void feed(std::span<const unsigned char> value) {
        std::size_t at = 0;
        while (at < value.size()) {
            if (invalid_) {
                tail(value.subspan(at));
                return;
            }
            if (end_seen_) {
                invalidate(AttemptFailure::TrailingAfterEnd);
                tail(value.subspan(at));
                return;
            }
            if (header_at_ < C03_HEADER_BYTES) {
                const auto count = std::min(
                    C03_HEADER_BYTES - header_at_, value.size() - at);
                const auto part = value.subspan(at, count);
                tail(part);
                std::copy(part.begin(), part.end(),
                          header_.begin() + header_at_);
                header_at_ += count;
                at += count;
                if (header_at_ == C03_HEADER_BYTES) header_complete();
                continue;
            }
            need(payload_hash_ != nullptr && payload_at_ < payload_bytes_);
            const auto count = std::min<std::size_t>(
                payload_bytes_ - payload_at_, value.size() - at);
            const auto part = value.subspan(at, count);
            tail(part);
            payload_hash_->update(part);
            payload_at_ += count;
            at += count;
            if (payload_at_ == payload_bytes_) finish_frame();
        }
    }

    ParsedStream finish(bool read_failed) {
        ParsedStream result;
        if (read_failed) {
            result.state = AttemptStreamState::Invalid;
            result.failure = AttemptFailure::CaptureReadFailed;
        } else if (invalid_) {
            result.state = AttemptStreamState::Invalid;
            result.failure = invalid_failure_;
        } else if (header_at_ > 0 && header_at_ < C03_HEADER_BYTES) {
            result.state = AttemptStreamState::PartialHeader;
            result.failure = AttemptFailure::PartialHeader;
        } else if (header_at_ == C03_HEADER_BYTES &&
                   payload_at_ < payload_bytes_) {
            result.state = AttemptStreamState::PartialPayload;
            result.failure = AttemptFailure::PartialPayload;
        } else if (end_seen_) {
            result.state = AttemptStreamState::CompleteEnd;
            result.failure = AttemptFailure::None;
        } else if (any_frame_) {
            result.state = AttemptStreamState::ClosedWithoutEnd;
            result.failure = AttemptFailure::MissingEnd;
        } else {
            result.state = AttemptStreamState::Empty;
            result.failure = AttemptFailure::EmptyStream;
        }
        result.partial_tail_bytes = tail_bytes_;
        if (tail_hash_) result.partial_tail_sha256 = tail_hash_->finish();
        return result;
    }
};

void write_all(int fd, std::span<const unsigned char> value) {
    std::size_t at = 0;
    while (at < value.size()) {
        const auto count = ::write(fd, value.data() + at, value.size() - at);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) _exit(120);
        at += static_cast<std::size_t>(count);
    }
}

void write_memfd(int fd, std::span<const unsigned char> value) {
    std::size_t at = 0;
    while (at < value.size()) {
        const auto count = ::write(fd, value.data() + at, value.size() - at);
        if (count < 0 && errno == EINTR) continue;
        need(count > 0);
        at += static_cast<std::size_t>(count);
    }
}

void close_noexcept(int& fd) noexcept {
    if (fd >= 0) {
        const int old = fd;
        fd = -1;
        (void)::close(old);
    }
}

int reopen_read_only(int source, const struct stat& expected) {
    std::array<char, 64> path{};
    const int count = std::snprintf(
        path.data(), path.size(), "/proc/self/fd/%d", source);
    need(count > 0 && static_cast<std::size_t>(count) < path.size());
    const int result = ::open(path.data(), O_RDONLY | O_CLOEXEC);
    need(result >= 0);
    try {
        struct stat observed{};
        need((::fcntl(result, F_GETFL) & O_ACCMODE) == O_RDONLY &&
             (::fcntl(result, F_GETFD) & FD_CLOEXEC) != 0 &&
             ::fstat(result, &observed) == 0 &&
             observed.st_dev == expected.st_dev &&
             observed.st_ino == expected.st_ino &&
             observed.st_size == expected.st_size &&
             (observed.st_mode & S_IFMT) == (expected.st_mode & S_IFMT));
        return result;
    } catch (...) {
        int selected = result;
        close_noexcept(selected);
        throw;
    }
}

void validate(const SourceAttemptBinding& value) {
    need((value.round == 1 || value.round == 2));
    uuid(value.attempt_uuid);
    for (const auto* word : {
             &value.financial_run, &value.cohort, &value.capture_plan,
             &value.projection, &value.capture_source, &value.capture_build,
             &value.capture_runtime, &value.capture_launcher,
             &value.route_requirement})
        need(nonzero(*word));
}

void append_runtime_material(
        RegisteredTrialAttemptHistoryStorage& storage,
        RuntimeHistoryMaterial material) {
    using RuntimeFailure = kpb::measurement::producer_runtime::
        ProducerAttemptDrainFailure;
    need(material.writer_aliases_closed &&
         (material.wait_observed || material.pidfd_exit_observed) &&
         material.producer_pid > 1 &&
         material.start_monotonic_ns > 0 &&
         material.end_monotonic_ns >= material.start_monotonic_ns &&
         nonzero(material.closure_identity) &&
         nonzero(material.archive_reservation_identity) &&
         nonzero(material.producer_child_exit_identity) &&
         material.source_slots == std::array<unsigned, 2>{3, 8} &&
         material.fixed_fds == std::array<unsigned, 2>{23, 28} &&
         material.binding.trial == storage.trial_identity &&
         material.capture_trial_id == storage.capture_trial_id &&
         material.binding.trial ==
             registered_trial_identity(material.capture_trial_id) &&
         material.binding.round_attempts[0] ==
             capture_attempt_identity(material.capture_attempt_ids[0]) &&
         material.binding.round_attempts[1] ==
             capture_attempt_identity(material.capture_attempt_ids[1]) &&
         material.capture_attempt_ids[0] != material.capture_trial_id &&
         material.capture_attempt_ids[1] != material.capture_trial_id &&
         material.capture_attempt_ids[0] !=
             material.capture_attempt_ids[1] &&
         static_cast<std::uint8_t>(material.binding.classification) ==
             static_cast<std::uint8_t>(storage.classification));
    for (unsigned round = 0; round < 2; ++round)
        need(nonzero(material.route_requirements[round]));

    const bool wait_success = material.wait_observed &&
        WIFEXITED(material.producer_wait_status) &&
        WEXITSTATUS(material.producer_wait_status) == 0;
    const bool complete_attempt =
        wait_success && material.attempt_failure == RuntimeFailure::None &&
        material.states[0] == kpb::measurement::producer_runtime::
            ProducerAttemptC03StreamState::CompleteEnd &&
        material.states[1] == kpb::measurement::producer_runtime::
            ProducerAttemptC03StreamState::CompleteEnd &&
        nonzero(material.route_completions[0]) &&
        nonzero(material.route_completions[1]);
    // A failed registered trial is never retried under the same trial
    // identity. One fixed ten-stream producer attempt contributes exactly
    // one immutable C03 row per round, including empty pre-HELLO evidence.
    need(!storage.retry_closed && storage.rows.empty());
    storage.producer_binding =
        std::make_unique<kpb::measurement::RunBinding>(material.binding);
    storage.producer_closure_identity = material.closure_identity;
    storage.producer_archive_reservation_identity =
        material.archive_reservation_identity;
    storage.producer_source_slots = material.source_slots;
    storage.producer_fixed_fds = material.fixed_fds;
    storage.producer_writer_aliases_closed = material.writer_aliases_closed;
    storage.producer_wait_observed = material.wait_observed;
    storage.producer_pidfd_exit_observed = material.pidfd_exit_observed;
    storage.producer_pid = material.producer_pid;
    storage.producer_wait_status = material.producer_wait_status;
    storage.producer_child_exit_identity =
        material.producer_child_exit_identity;

    for (unsigned round_index = 0; round_index < 2; ++round_index) {
        const auto state = stream_state(material.states[round_index]);
        const bool terminal = complete_attempt;
        const auto ordinal =
            static_cast<std::uint32_t>(storage.rows.size());
        constexpr std::uint32_t retry_ordinal = 0;
        const Digest predecessor{};
        const Digest trial_predecessor = storage.rows.empty()
            ? Digest{} : storage.rows.back().attempt_identity;
        SourceAttemptBinding binding{
            .round = round_index + 1,
            .attempt_uuid = material.capture_attempt_ids[round_index],
            .financial_run = material.binding.financial_runs[round_index],
            .cohort = material.binding.round_cohorts[round_index],
            .capture_plan =
                material.binding.round_capture_plans[round_index],
            .projection = material.binding.projections[round_index],
            .capture_source = material.binding.capture_source,
            .capture_build = material.binding.capture_build,
            .capture_runtime = material.binding.capture_runtime,
            .capture_launcher = material.binding.capture_launcher,
            .route_requirement = material.route_requirements[round_index],
            .route_completion = material.route_completions[round_index],
        };
        validate(binding);
        const auto selected_attempt = attempt_identity(
            binding, ordinal, retry_ordinal, predecessor,
            trial_predecessor);

        struct stat information{};
        need(material.fds[round_index].value >= 0 &&
             (::fcntl(material.fds[round_index].value, F_GETFL) &
              O_ACCMODE) == O_RDONLY &&
             ::fstat(material.fds[round_index].value, &information) == 0 &&
             S_ISREG(information.st_mode) &&
             information.st_nlink == 0 &&
             (information.st_mode & 0777) == 0600 &&
             material.seals[round_index] == 0 &&
             static_cast<std::uint64_t>(information.st_dev) ==
                 material.devices[round_index] &&
             static_cast<std::uint64_t>(information.st_ino) ==
                 material.inodes[round_index] &&
             information.st_size >= 0 &&
             static_cast<std::uint64_t>(information.st_size) ==
                 material.sizes[round_index] &&
             nonzero(material.sha256[round_index]));

        RegisteredAttemptHistoryRowStorage row;
        row.round = round_index + 1;
        row.ordinal = ordinal;
        row.retry_ordinal = retry_ordinal;
        row.attempt_uuid = binding.attempt_uuid;
        row.attempt_identity = selected_attempt;
        row.predecessor = predecessor;
        row.trial_predecessor = trial_predecessor;
        row.start_monotonic_ns = material.start_monotonic_ns;
        row.end_monotonic_ns = material.end_monotonic_ns;
        row.stream_state = state;
        row.wait_status = material.wait_observed
            ? material.producer_wait_status : -1;
        row.wait_exit_code = material.wait_observed &&
            WIFEXITED(material.producer_wait_status)
            ? WEXITSTATUS(material.producer_wait_status) : -1;
        row.wait_signal = material.wait_observed &&
            WIFSIGNALED(material.producer_wait_status)
            ? WTERMSIG(material.producer_wait_status) : 0;
        if (terminal) {
            row.outcome = AttemptOutcome::Complete;
            row.failure = AttemptFailure::None;
        } else if (!material.wait_observed &&
                   material.pidfd_exit_observed) {
            row.outcome = AttemptOutcome::Error;
            row.failure = AttemptFailure::WaitStatusUnavailable;
        } else if (WIFSIGNALED(material.producer_wait_status)) {
            row.outcome = AttemptOutcome::Crashed;
            row.failure = AttemptFailure::ChildSignaled;
        } else if (!wait_success) {
            row.outcome = AttemptOutcome::Refused;
            row.failure = AttemptFailure::ChildExitedNonzero;
        } else if (material.attempt_failure ==
                       RuntimeFailure::RouteUnavailable ||
                   (!nonzero(material.route_completions[round_index]) &&
                    state == AttemptStreamState::CompleteEnd)) {
            row.outcome = AttemptOutcome::Refused;
            row.failure = AttemptFailure::RouteUnavailable;
        } else if (state == AttemptStreamState::PartialHeader ||
                   state == AttemptStreamState::PartialPayload ||
                   state == AttemptStreamState::ClosedWithoutEnd ||
                   state == AttemptStreamState::Empty) {
            row.outcome = AttemptOutcome::Partial;
            row.failure = attempt_failure(material.failures[round_index]);
        } else {
            row.outcome = AttemptOutcome::Error;
            row.failure = attempt_failure(material.attempt_failure);
            if (row.failure == AttemptFailure::None)
                row.failure = AttemptFailure::ProducerTransportInvalid;
        }
        row.partial_tail_bytes = terminal ? 0 : material.sizes[round_index];
        row.partial_tail_sha256 = terminal
            ? Digest{} : material.sha256[round_index];
        row.c03_sha256 = material.sha256[round_index];
        row.c03_bytes = material.sizes[round_index];
        row.sealed_c03_device = material.devices[round_index];
        row.sealed_c03_inode = material.inodes[round_index];
        row.sealed_c03_mode = information.st_mode;
        row.sealed_c03_seals = material.seals[round_index];
        row.sealed_c03_access_mode = O_RDONLY;
        row.sealed_c03.value =
            std::exchange(material.fds[round_index].value, -1);
        row.financial_run = binding.financial_run;
        row.cohort = binding.cohort;
        row.capture_plan = binding.capture_plan;
        row.projection = binding.projection;
        row.capture_source = binding.capture_source;
        row.capture_build = binding.capture_build;
        row.capture_runtime = binding.capture_runtime;
        row.capture_launcher = binding.capture_launcher;
        row.route_requirement = binding.route_requirement;
        row.route_completion = binding.route_completion;
        row.process_identity = process_identity(
            selected_attempt, ::getpid(),
            static_cast<pid_t>(material.producer_pid),
            material.start_monotonic_ns);
        row.child_exit_identity = runtime_child_exit_identity(
            row.process_identity, material.producer_child_exit_identity,
            material.producer_wait_status, material.wait_observed,
            material.pidfd_exit_observed, material.end_monotonic_ns);
        storage.terminal_seen[round_index] = terminal;
        storage.rows.push_back(std::move(row));
    }
    storage.retry_closed = true;
    storage.failed_trial = !complete_attempt;
}

Digest history_identity(const RegisteredTrialAttemptHistoryStorage& value) {
    std::vector<unsigned char> preimage;
    append_text(preimage, HISTORY_ID_DOMAIN);
    append_u32(preimage, static_cast<std::uint8_t>(value.classification));
    append_text(preimage, value.capture_trial_id);
    append(preimage, value.trial_identity);
    preimage.push_back(value.failed_trial ? 1 : 0);
    preimage.push_back(value.persistent_role_exit ? 1 : 0);
    if (value.persistent_role_exit) {
        need(value.persistent_role_exit->live_and_clean());
        append(preimage,
               value.persistent_role_exit->authority_identity());
    }
    preimage.push_back(value.producer_binding ? 1 : 0);
    if (value.producer_binding) {
        append_run_binding(preimage, *value.producer_binding);
        append(preimage, value.producer_closure_identity);
        append(preimage, value.producer_archive_reservation_identity);
        for (const auto slot : value.producer_source_slots)
            append_u32(preimage, slot);
        for (const auto fd : value.producer_fixed_fds)
            append_u32(preimage, fd);
        preimage.push_back(value.producer_writer_aliases_closed ? 1 : 0);
        preimage.push_back(value.producer_wait_observed ? 1 : 0);
        preimage.push_back(value.producer_pidfd_exit_observed ? 1 : 0);
        append_u64(preimage,
                   static_cast<std::uint64_t>(value.producer_pid));
        append_i32(preimage, value.producer_wait_status);
        append(preimage, value.producer_child_exit_identity);
    }
    append_u64(preimage, value.rows.size());
    for (const auto& row : value.rows) {
        append_u32(preimage, row.round);
        append_u32(preimage, row.ordinal);
        append_u32(preimage, row.retry_ordinal);
        append_text(preimage, row.attempt_uuid);
        append(preimage, row.attempt_identity);
        append(preimage, row.predecessor);
        append(preimage, row.trial_predecessor);
        append_u64(preimage, row.start_monotonic_ns);
        append_u64(preimage, row.end_monotonic_ns);
        preimage.push_back(static_cast<unsigned char>(row.outcome));
        preimage.push_back(static_cast<unsigned char>(row.failure));
        preimage.push_back(static_cast<unsigned char>(row.stream_state));
        append_i32(preimage, row.wait_status);
        append_i32(preimage, row.wait_exit_code);
        append_i32(preimage, row.wait_signal);
        append_u64(preimage, row.partial_tail_bytes);
        append(preimage, row.partial_tail_sha256);
        append(preimage, row.c03_sha256);
        append_u64(preimage, row.c03_bytes);
        append_u64(preimage, row.sealed_c03_device);
        append_u64(preimage, row.sealed_c03_inode);
        append_u32(preimage, row.sealed_c03_mode);
        append_i32(preimage, row.sealed_c03_seals);
        append_i32(preimage, row.sealed_c03_access_mode);
        for (const auto* word : {
                 &row.financial_run, &row.cohort, &row.capture_plan,
                 &row.projection, &row.capture_source, &row.capture_build,
                 &row.capture_runtime, &row.capture_launcher,
                 &row.route_requirement,
                 &row.route_completion, &row.process_identity,
                 &row.child_exit_identity})
            append(preimage, *word);
    }
    return digest(preimage);
}

[[maybe_unused]] void observe_source_attempt(
        RegisteredTrialAttemptHistoryStorage& storage,
        SourceAttemptBinding binding,
        std::span<const unsigned char> bytes, std::size_t bytes_to_write,
        SourceChildDisposition disposition, int disposition_value) {
    validate(binding);
    const std::size_t round_index = binding.round - 1;
    need(!storage.retry_closed && storage.rows.size() < 2 &&
         binding.round == storage.rows.size() + 1 &&
         (binding.round == 1 ||
          storage.rows.front().outcome == AttemptOutcome::Complete) &&
         bytes_to_write <= bytes.size() &&
         storage.rows.size() < std::numeric_limits<std::uint32_t>::max());
    const auto ordinal = static_cast<std::uint32_t>(storage.rows.size());
    constexpr std::uint32_t retry_ordinal = 0;
    const Digest predecessor{};
    const Digest trial_predecessor = storage.rows.empty() ? Digest{} :
        storage.rows.back().attempt_identity;
    if (!storage.rows.empty()) {
        const auto& first = storage.rows.front();
        need(binding.capture_source == first.capture_source &&
             binding.capture_build == first.capture_build &&
             binding.capture_runtime == first.capture_runtime &&
             binding.capture_launcher == first.capture_launcher);
    }
    const auto attempt = attempt_identity(
        binding, ordinal, retry_ordinal, predecessor, trial_predecessor);
    const auto start = monotonic_ns();

    OwnedSealedC03Fd owned_capture(::memfd_create(
        "kpb-registered-attempt-c03", MFD_CLOEXEC | MFD_ALLOW_SEALING));
    int& capture_fd = owned_capture.value;
    need(capture_fd >= 0);
    int pipes[2]{-1, -1};
    if (::pipe2(pipes, O_CLOEXEC) != 0) {
        refuse();
    }
    const pid_t child = ::fork();
    if (child < 0) {
        close_noexcept(pipes[0]);
        close_noexcept(pipes[1]);
        refuse();
    }
    if (child == 0) {
        close_noexcept(pipes[0]);
        write_all(pipes[1], bytes.first(bytes_to_write));
        close_noexcept(pipes[1]);
        if (disposition == SourceChildDisposition::Signal) {
            (void)::raise(disposition_value);
            _exit(121);
        }
        _exit(disposition == SourceChildDisposition::ExitZero ? 0 :
              disposition_value);
    }

    close_noexcept(pipes[1]);
    HashAccumulator c03_hash;
    C03StreamParser parser;
    std::uint64_t total = 0;
    bool read_failed = false;
    std::array<unsigned char, 65536> buffer{};
    for (;;) {
        const auto count = ::read(pipes[0], buffer.data(), buffer.size());
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { read_failed = true; break; }
        if (count == 0) break;
        const auto part = std::span<const unsigned char>(
            buffer.data(), static_cast<std::size_t>(count));
        need(part.size() <= MAX_REGISTERED_ATTEMPT_C03_BYTES - total);
        total += part.size();
        write_memfd(capture_fd, part);
        c03_hash.update(part);
        parser.feed(part);
    }
    close_noexcept(pipes[0]);
    int wait_status = 0;
    pid_t waited;
    do { waited = ::waitpid(child, &wait_status, 0); }
    while (waited < 0 && errno == EINTR);
    need(waited == child);
    const auto end = monotonic_ns();
    const auto parsed = parser.finish(read_failed);
    const auto c03_identity = c03_hash.finish();
    need(::lseek(capture_fd, 0, SEEK_SET) == 0);
    constexpr int seals =
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    need(::fcntl(capture_fd, F_ADD_SEALS, seals) == 0 &&
         ::fcntl(capture_fd, F_GET_SEALS) == seals);
    struct stat information{};
    need(::fstat(capture_fd, &information) == 0 &&
         S_ISREG(information.st_mode) && information.st_nlink == 0 &&
         static_cast<std::uint64_t>(information.st_size) == total);
    int read_only_fd = -1;
#ifdef KPI_REGISTERED_ATTEMPT_HISTORY_TEST_SETUP
    if (binding.sealed_c03_fault ==
            static_cast<std::uint8_t>(
                TestOnlySealedC03Fault::RetainWritable)) {
        read_only_fd = ::fcntl(capture_fd, F_DUPFD_CLOEXEC, 80);
        need(read_only_fd >= 80);
    } else if (binding.sealed_c03_fault ==
                   static_cast<std::uint8_t>(
                       TestOnlySealedC03Fault::SubstituteInode)) {
        int substitute = ::memfd_create(
            "kpb-registered-attempt-c03-substitute",
            MFD_CLOEXEC | MFD_ALLOW_SEALING);
        need(substitute >= 0 &&
             ::fcntl(substitute, F_ADD_SEALS, seals) == 0);
        struct stat substitute_information{};
        need(::fstat(substitute, &substitute_information) == 0);
        read_only_fd = reopen_read_only(substitute, substitute_information);
        close_noexcept(substitute);
    } else
#endif
    {
        read_only_fd = reopen_read_only(capture_fd, information);
    }
    close_noexcept(capture_fd);
    capture_fd = read_only_fd;
    read_only_fd = -1;
    struct stat read_only_information{};
    need(::fstat(capture_fd, &read_only_information) == 0 &&
         read_only_information.st_dev == information.st_dev &&
         read_only_information.st_ino == information.st_ino &&
         read_only_information.st_size == information.st_size &&
         (::fcntl(capture_fd, F_GETFL) & O_ACCMODE) == O_RDONLY &&
         ::fcntl(capture_fd, F_GET_SEALS) == seals);

    RegisteredAttemptHistoryRowStorage row;
    row.round = binding.round;
    row.ordinal = ordinal;
    row.retry_ordinal = retry_ordinal;
    row.attempt_uuid = std::move(binding.attempt_uuid);
    row.attempt_identity = attempt;
    row.predecessor = predecessor;
    row.trial_predecessor = trial_predecessor;
    row.start_monotonic_ns = start;
    row.end_monotonic_ns = end;
    row.failure = parsed.failure;
    row.stream_state = parsed.state;
    row.wait_status = wait_status;
    row.wait_exit_code = WIFEXITED(wait_status) ? WEXITSTATUS(wait_status) : -1;
    row.wait_signal = WIFSIGNALED(wait_status) ? WTERMSIG(wait_status) : 0;
    if (WIFSIGNALED(wait_status)) {
        row.outcome = AttemptOutcome::Crashed;
        if (row.failure == AttemptFailure::None)
            row.failure = AttemptFailure::ChildSignaled;
    } else if (!WIFEXITED(wait_status)) {
        row.outcome = AttemptOutcome::Error;
        if (row.failure == AttemptFailure::None)
            row.failure = AttemptFailure::CaptureReadFailed;
    } else if (WEXITSTATUS(wait_status) != 0) {
        row.outcome = AttemptOutcome::Refused;
        if (row.failure == AttemptFailure::None)
            row.failure = AttemptFailure::ChildExitedNonzero;
    } else if (parsed.state == AttemptStreamState::CompleteEnd) {
        row.outcome = AttemptOutcome::Complete;
    } else if (read_failed || parsed.state == AttemptStreamState::Invalid) {
        row.outcome = AttemptOutcome::Error;
    } else {
        row.outcome = AttemptOutcome::Partial;
    }
    row.partial_tail_bytes = parsed.partial_tail_bytes;
    row.partial_tail_sha256 = parsed.partial_tail_sha256;
    row.c03_sha256 = c03_identity;
    row.c03_bytes = total;
    row.sealed_c03_device = information.st_dev;
    row.sealed_c03_inode = information.st_ino;
    row.sealed_c03_mode = information.st_mode;
    row.sealed_c03_seals = seals;
    row.sealed_c03_access_mode = O_RDONLY;
    row.sealed_c03.value = std::exchange(owned_capture.value, -1);
    row.financial_run = binding.financial_run;
    row.cohort = binding.cohort;
    row.capture_plan = binding.capture_plan;
    row.projection = binding.projection;
    row.capture_source = binding.capture_source;
    row.capture_build = binding.capture_build;
    row.capture_runtime = binding.capture_runtime;
    row.capture_launcher = binding.capture_launcher;
    row.route_requirement = binding.route_requirement;
    row.route_completion = binding.route_completion;
    row.process_identity = process_identity(attempt, ::getpid(), child, start);
    row.child_exit_identity = child_exit_identity(
        row.process_identity, wait_status, end);
    storage.terminal_seen[round_index] =
        row.outcome == AttemptOutcome::Complete;
    storage.rows.push_back(std::move(row));
    storage.failed_trial = !storage.terminal_seen[round_index];
    storage.retry_closed = storage.failed_trial || binding.round == 2;
}

void validate_history_rows(
        RegisteredTrialAttemptHistoryStorage& storage,
        bool require_complete) {
    need(storage.trial_identity ==
             registered_trial_identity(storage.capture_trial_id) &&
         !storage.rows.empty() && storage.rows.size() <= 2 &&
         storage.retry_closed &&
         storage.failed_trial == !require_complete);
    std::array<std::size_t, 2> complete{};
    for (std::size_t index = 0; index < storage.rows.size(); ++index) {
        const auto& row = storage.rows[index];
        need(row.ordinal == index && row.round == index + 1 &&
             row.retry_ordinal == 0 && row.predecessor == Digest{} &&
             row.trial_predecessor ==
                 (index == 0 ? Digest{} :
                  storage.rows[index - 1].attempt_identity) &&
             row.start_monotonic_ns > 0 &&
             row.end_monotonic_ns >= row.start_monotonic_ns &&
             (index == 0 ||
              row.start_monotonic_ns >=
                  storage.rows.front().start_monotonic_ns) &&
             row.sealed_c03.value >= 0 &&
             row.c03_bytes <= MAX_REGISTERED_ATTEMPT_C03_BYTES &&
             row.sealed_c03_access_mode == O_RDONLY &&
             (::fcntl(row.sealed_c03.value, F_GETFL) & O_ACCMODE) ==
                 O_RDONLY &&
             nonzero(row.c03_sha256) && nonzero(row.process_identity) &&
             nonzero(row.child_exit_identity));
        struct stat information{};
        need(::fstat(row.sealed_c03.value, &information) == 0 &&
             S_ISREG(information.st_mode) &&
             static_cast<std::uint64_t>(information.st_dev) ==
                 row.sealed_c03_device &&
             static_cast<std::uint64_t>(information.st_ino) ==
                 row.sealed_c03_inode && information.st_size >= 0 &&
             static_cast<std::uint64_t>(information.st_size) ==
                 row.c03_bytes &&
             digest_fd(row.sealed_c03.value, row.c03_bytes) ==
                 row.c03_sha256);
#ifdef KPI_REGISTERED_ATTEMPT_HISTORY_TEST_SETUP
        if (row.sealed_c03_seals != 0)
            need(information.st_nlink == 0 &&
                 ::fcntl(row.sealed_c03.value, F_GET_SEALS) ==
                     row.sealed_c03_seals);
        else
#endif
            need(row.sealed_c03_seals == 0 &&
                 information.st_nlink == 0 &&
                 (information.st_mode & 0777) == 0600);
        if (row.outcome == AttemptOutcome::Complete) {
            need(row.c03_bytes > 0 &&
                 row.stream_state == AttemptStreamState::CompleteEnd &&
                 row.failure == AttemptFailure::None &&
                 nonzero(row.route_completion));
            ++complete[index];
            storage.final_indices[index] = index;
        } else if (row.c03_bytes == 0) {
            need(row.stream_state == AttemptStreamState::Empty &&
                 row.partial_tail_bytes == 0 &&
                 row.c03_sha256 ==
                     digest(std::span<const unsigned char>{}));
        }
    }
    if (storage.producer_binding) {
        const auto& binding = *storage.producer_binding;
        need(storage.rows.size() == 2 &&
             binding.trial == storage.trial_identity &&
             nonzero(storage.producer_closure_identity) &&
             nonzero(storage.producer_archive_reservation_identity) &&
             storage.producer_source_slots ==
                 std::array<unsigned, 2>{3, 8} &&
             storage.producer_fixed_fds ==
                 std::array<unsigned, 2>{23, 28} &&
             storage.producer_writer_aliases_closed &&
             (storage.producer_wait_observed ||
              storage.producer_pidfd_exit_observed) &&
             storage.producer_pid > 1 &&
             nonzero(storage.producer_child_exit_identity));
        for (unsigned round = 0; round < 2; ++round) {
            const auto& row = storage.rows[round];
            need(row.round == round + 1 &&
                 binding.financial_runs[round] == row.financial_run &&
                 binding.round_attempts[round] ==
                     capture_attempt_identity(row.attempt_uuid) &&
                 binding.round_cohorts[round] == row.cohort &&
                 binding.round_capture_plans[round] == row.capture_plan &&
                 binding.projections[round] == row.projection &&
                 binding.capture_source == row.capture_source &&
                 binding.capture_build == row.capture_build &&
                 binding.capture_runtime == row.capture_runtime &&
                 binding.capture_launcher == row.capture_launcher);
        }
    }
#ifndef KPI_REGISTERED_ATTEMPT_HISTORY_TEST_SETUP
    else {
        refuse();
    }
#endif
    if (require_complete)
        need(storage.rows.size() == 2 && complete[0] == 1 &&
             complete[1] == 1 && storage.terminal_seen[0] &&
             storage.terminal_seen[1]);
    else
        need(!(storage.rows.size() == 2 && complete[0] == 1 &&
               complete[1] == 1));
    storage.history_identity = history_identity(storage);
    need(nonzero(storage.history_identity));
}

} // namespace

const char* AttemptHistoryRefused::what() const noexcept {
    return "KPB_REGISTERED_TRIAL_ATTEMPT_HISTORY_REFUSED";
}

OwnedSealedC03Fd::OwnedSealedC03Fd(OwnedSealedC03Fd&& other) noexcept
    : value(std::exchange(other.value, -1)) {}

OwnedSealedC03Fd::~OwnedSealedC03Fd() { close_noexcept(value); }

RegisteredTrialAttemptHistoryStorage::RegisteredTrialAttemptHistoryStorage() =
    default;
RegisteredTrialAttemptHistoryStorage::~RegisteredTrialAttemptHistoryStorage() =
    default;

RegisteredTrialAttemptHistoryRecorder::RegisteredTrialAttemptHistoryRecorder(
        std::unique_ptr<RegisteredTrialAttemptHistoryStorage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }

RegisteredTrialAttemptHistoryRecorder::RegisteredTrialAttemptHistoryRecorder(
        RegisteredTrialAttemptHistoryRecorder&& other) noexcept
    : storage_(std::move(other.storage_)),
      live_(other.live_.exchange(false)) {}

RegisteredTrialAttemptHistoryRecorder::~RegisteredTrialAttemptHistoryRecorder() =
    default;

RegisteredTrialAttemptHistoryAuthority::RegisteredTrialAttemptHistoryAuthority(
        std::unique_ptr<RegisteredTrialAttemptHistoryStorage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }

RegisteredTrialAttemptHistoryAuthority::RegisteredTrialAttemptHistoryAuthority(
        RegisteredTrialAttemptHistoryAuthority&& other) noexcept
    : storage_(std::move(other.storage_)) {}

RegisteredTrialAttemptHistoryAuthority::~RegisteredTrialAttemptHistoryAuthority() =
    default;

RegisteredFailedTrialAttemptHistoryAuthority::
RegisteredFailedTrialAttemptHistoryAuthority(
        std::unique_ptr<RegisteredTrialAttemptHistoryStorage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }

RegisteredFailedTrialAttemptHistoryAuthority::
RegisteredFailedTrialAttemptHistoryAuthority(
        RegisteredFailedTrialAttemptHistoryAuthority&& other) noexcept
    : storage_(std::move(other.storage_)) {}

RegisteredFailedTrialAttemptHistoryAuthority::~
RegisteredFailedTrialAttemptHistoryAuthority() = default;

RegisteredUnavailableTrialAttemptHistoryAuthority::
RegisteredUnavailableTrialAttemptHistoryAuthority(
        RegisteredTrialAttemptHistoryRecorder&& recorder,
        kpb::measurement::producer_runtime::
            ProducerAttemptRegisteredOutcomeTransfer&& outcome)
    : recorder_storage_(std::move(recorder.storage_)),
      outcome_(std::in_place, std::move(outcome)) {
    recorder.live_.store(false);
}

RegisteredUnavailableTrialAttemptHistoryAuthority::
RegisteredUnavailableTrialAttemptHistoryAuthority(
        RegisteredUnavailableTrialAttemptHistoryAuthority&& other) noexcept
    : recorder_storage_(std::move(other.recorder_storage_)),
      outcome_(std::move(other.outcome_)) {}

RegisteredUnavailableTrialAttemptHistoryAuthority::~
RegisteredUnavailableTrialAttemptHistoryAuthority() = default;

RegisteredAttemptHistoryAppendOutcomeAuthority::
RegisteredAttemptHistoryAppendOutcomeAuthority(
        RegisteredUnavailableTrialAttemptHistoryAuthority&& unavailable)
    : unavailable_(std::in_place, std::move(unavailable)) {}

RegisteredAttemptHistoryAppendOutcomeAuthority::
RegisteredAttemptHistoryAppendOutcomeAuthority(
        RegisteredAttemptHistoryAppendOutcomeAuthority&& other) noexcept
    : complete_history_(std::move(other.complete_history_)),
      completion_(std::move(other.completion_)),
      failed_history_(std::move(other.failed_history_)),
      unavailable_(std::move(other.unavailable_)) {}

RegisteredAttemptHistoryAppendOutcomeAuthority::~
RegisteredAttemptHistoryAppendOutcomeAuthority() = default;

RegisteredTrialAttemptHistoryAuthority
RegisteredTrialAttemptHistoryRecorder::seal(
        RegisteredTrialAttemptHistoryRecorder&& supplied) {
    const std::lock_guard<std::mutex> lock(supplied.mutex_);
    const bool live = supplied.live_.exchange(false);
    auto storage = std::move(supplied.storage_);
    need(live && storage != nullptr);
    validate_history_rows(*storage, true);
    return RegisteredTrialAttemptHistoryAuthority(std::move(storage));
}

RegisteredFailedTrialAttemptHistoryAuthority
RegisteredTrialAttemptHistoryRecorder::seal_failed(
        RegisteredTrialAttemptHistoryRecorder&& supplied) {
    const std::lock_guard<std::mutex> lock(supplied.mutex_);
    const bool live = supplied.live_.exchange(false);
    auto storage = std::move(supplied.storage_);
    need(live && storage != nullptr);
    validate_history_rows(*storage, false);
    return RegisteredFailedTrialAttemptHistoryAuthority(std::move(storage));
}

RegisteredAttemptHistoryAppendOutcomeAuthority
RegisteredCaptureAttemptHistoryBridge::append_outcome(
        RegisteredTrialAttemptHistoryRecorder&& recorder,
        kpb::measurement::producer_runtime::
            ProducerAttemptOutcomeAuthority&& supplied) {
    // Claim the complete producer outcome before the recorder. A replayed
    // outcome cannot consume a fresh recorder. Until the required typed
    // observer-v5 P1 state capsule is present, even an otherwise complete C03
    // view is deliberately retained as run-invalidating unavailable evidence;
    // it cannot yield a retry or successful ledger arm.
    auto transfer =
        std::move(supplied).consume_for_registered_history();
    RegisteredTrialAttemptHistoryRecorder claimed(std::move(recorder));
    need(claimed.live_.load() && claimed.storage_ != nullptr);
    return RegisteredAttemptHistoryAppendOutcomeAuthority(
        RegisteredUnavailableTrialAttemptHistoryAuthority(
            std::move(claimed), std::move(transfer)));
}

void RegisteredCaptureAttemptHistoryBridge::append_history(
        RegisteredTrialAttemptHistoryRecorder& recorder,
        kpb::measurement::producer_runtime::
            ProducerAttemptC03HistoryAuthority&& supplied) {
    auto transfer = std::move(supplied).consume_for_registered_history();
    const std::lock_guard<std::mutex> lock(recorder.mutex_);
    try {
        need(recorder.live_.load() && recorder.storage_ != nullptr &&
             transfer.writer_aliases_closed_);
        RuntimeHistoryMaterial material;
        material.binding = transfer.binding_;
        material.capture_trial_id = std::move(transfer.capture_trial_id_);
        material.capture_attempt_ids =
            std::move(transfer.capture_attempt_ids_);
        material.closure_identity = transfer.closure_identity_;
        material.archive_reservation_identity =
            transfer.archive_reservation_identity_;
        material.source_slots = transfer.source_slots_;
        material.fixed_fds = transfer.fixed_fds_;
        material.devices = transfer.devices_;
        material.inodes = transfer.inodes_;
        material.sizes = transfer.sizes_;
        material.seals = transfer.seals_;
        material.sha256 = transfer.sha256_;
        material.route_requirements = transfer.route_requirements_;
        material.route_completions = transfer.route_completions_;
        material.writer_aliases_closed = transfer.writer_aliases_closed_;
        material.states = transfer.states_;
        material.failures = transfer.failures_;
        material.attempt_failure = transfer.attempt_failure_;
        material.first_failed_slot = transfer.first_failed_slot_;
        material.start_monotonic_ns = transfer.start_monotonic_ns_;
        material.end_monotonic_ns = transfer.end_monotonic_ns_;
        material.producer_pid = transfer.producer_pid_;
        material.producer_wait_status = transfer.producer_wait_status_;
        material.wait_observed = transfer.wait_observed_;
        material.pidfd_exit_observed = transfer.pidfd_exit_observed_;
        material.producer_child_exit_identity =
            transfer.producer_child_exit_identity_;
        for (unsigned index = 0; index < material.fds.size(); ++index)
            material.fds[index].value =
                std::exchange(transfer.fds_[index], -1);
        append_runtime_material(*recorder.storage_, std::move(material));
    } catch (...) {
        recorder.live_.store(false);
        recorder.storage_.reset();
        refuse();
    }
}

#ifdef KPI_REGISTERED_ATTEMPT_HISTORY_TEST_SETUP
kpb::measurement::producer_runtime::ProducerRuntimeCompletion
RegisteredCaptureAttemptHistoryBridge::append_complete(
        RegisteredTrialAttemptHistoryRecorder& recorder,
        kpb::measurement::producer_runtime::ProducerAttemptDrainResult&&
            supplied) {
    auto history = std::move(supplied.history_);
    auto completion = std::move(supplied.completion_);
    try {
        need(history != nullptr && completion != nullptr);
        append_history(recorder, std::move(*history));
        return kpb::measurement::producer_runtime::ProducerRuntimeCompletion(
            std::move(*completion));
    } catch (...) {
        const std::lock_guard<std::mutex> lock(recorder.mutex_);
        recorder.live_.store(false);
        recorder.storage_.reset();
        refuse();
    }
}

void RegisteredCaptureAttemptHistoryBridge::append_failed(
        RegisteredTrialAttemptHistoryRecorder& recorder,
        kpb::measurement::producer_runtime::ProducerAttemptDrainResult&&
            supplied) {
    auto history = std::move(supplied.history_);
    auto completion = std::move(supplied.completion_);
    try {
        need(history != nullptr && completion == nullptr);
        append_history(recorder, std::move(*history));
    } catch (...) {
        const std::lock_guard<std::mutex> lock(recorder.mutex_);
        recorder.live_.store(false);
        recorder.storage_.reset();
        refuse();
    }
}
#endif

#ifdef KPI_REGISTERED_ATTEMPT_HISTORY_TEST_SETUP
RegisteredTrialAttemptHistoryRecorder
RegisteredTrialAttemptHistoryTestBridge::begin(TestOnlyTrialBinding binding) {
    uuid(binding.capture_trial_id);
    need(static_cast<std::uint8_t>(binding.classification) >= 1 &&
         static_cast<std::uint8_t>(binding.classification) <= 2 &&
         binding.trial_identity ==
             registered_trial_identity(binding.capture_trial_id));
    auto storage = std::make_unique<RegisteredTrialAttemptHistoryStorage>();
    storage->classification = binding.classification;
    storage->capture_trial_id = std::move(binding.capture_trial_id);
    storage->trial_identity = binding.trial_identity;
    return RegisteredTrialAttemptHistoryRecorder(std::move(storage));
}

void RegisteredTrialAttemptHistoryTestBridge::observe(
        RegisteredTrialAttemptHistoryRecorder& recorder,
        TestOnlyAttemptBinding binding,
        std::span<const unsigned char> bytes, std::size_t bytes_to_write,
        TestOnlyChildDisposition disposition, int value) {
    const std::lock_guard<std::mutex> lock(recorder.mutex_);
    need(recorder.live_.load() && recorder.storage_ != nullptr &&
         (disposition == TestOnlyChildDisposition::ExitZero ||
          disposition == TestOnlyChildDisposition::ExitNonzero ||
          disposition == TestOnlyChildDisposition::Signal) &&
         ((disposition == TestOnlyChildDisposition::ExitZero && value == 0) ||
          (disposition == TestOnlyChildDisposition::ExitNonzero &&
           value > 0 && value < 128) ||
          (disposition == TestOnlyChildDisposition::Signal &&
           value > 0 && value < NSIG)));
    SourceAttemptBinding source{
        .round = binding.round,
        .attempt_uuid = std::move(binding.attempt_uuid),
        .financial_run = binding.financial_run,
        .cohort = binding.cohort,
        .capture_plan = binding.capture_plan,
        .projection = binding.projection,
        .capture_source = binding.capture_source,
        .capture_build = binding.capture_build,
        .capture_runtime = binding.capture_runtime,
        .capture_launcher = binding.capture_launcher,
        .route_requirement = binding.route_requirement,
        .route_completion = binding.route_completion,
        .sealed_c03_fault = static_cast<std::uint8_t>(
            binding.sealed_c03_fault),
    };
    validate(source);
    try {
        observe_source_attempt(
            *recorder.storage_, std::move(source), bytes, bytes_to_write,
            static_cast<SourceChildDisposition>(disposition), value);
    } catch (...) {
        recorder.live_.store(false);
        recorder.storage_.reset();
        throw;
    }
}

TestOnlyHistorySummary test_summary(
        std::unique_ptr<RegisteredTrialAttemptHistoryStorage> storage) {
    need(storage != nullptr);
    TestOnlyHistorySummary result;
    result.final_indices = storage->final_indices;
    result.history_identity = storage->history_identity;
    result.rows.reserve(storage->rows.size());
    for (const auto& row : storage->rows) {
        result.rows.push_back({
            .round = row.round,
            .ordinal = row.ordinal,
            .retry_ordinal = row.retry_ordinal,
            .attempt_uuid = row.attempt_uuid,
            .attempt_identity = row.attempt_identity,
            .predecessor = row.predecessor,
            .trial_predecessor = row.trial_predecessor,
            .start_monotonic_ns = row.start_monotonic_ns,
            .end_monotonic_ns = row.end_monotonic_ns,
            .outcome = row.outcome,
            .failure = row.failure,
            .stream_state = row.stream_state,
            .wait_exit_code = row.wait_exit_code,
            .wait_signal = row.wait_signal,
            .partial_tail_bytes = row.partial_tail_bytes,
            .partial_tail_sha256 = row.partial_tail_sha256,
            .c03_sha256 = row.c03_sha256,
            .c03_bytes = row.c03_bytes,
            .sealed_c03_device = row.sealed_c03_device,
            .sealed_c03_inode = row.sealed_c03_inode,
            .sealed_c03_seals = row.sealed_c03_seals,
            .sealed_c03_access_mode = row.sealed_c03_access_mode,
            .route_requirement = row.route_requirement,
            .route_completion = row.route_completion,
            .process_identity = row.process_identity,
            .child_exit_identity = row.child_exit_identity,
        });
    }
    return result;
}

TestOnlyHistorySummary RegisteredTrialAttemptHistoryTestBridge::consume(
        RegisteredTrialAttemptHistoryAuthority&& supplied) {
    return test_summary(std::move(supplied.storage_));
}

TestOnlyHistorySummary
RegisteredTrialAttemptHistoryTestBridge::consume_failed(
        RegisteredFailedTrialAttemptHistoryAuthority&& supplied) {
    return test_summary(std::move(supplied.storage_));
}
#endif

} // namespace kpi::mpc::financial::registered_driver::attempt_history
