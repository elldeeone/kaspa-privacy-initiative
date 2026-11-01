#include "p1_capture_stream.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <openssl/sha.h>
#include <pthread.h>
#include <set>
#include <signal.h>
#include <string_view>
#include <time.h>
#include <unistd.h>
#include <vector>

namespace kpi::mpc::p1_capture {
namespace {

constexpr std::array<unsigned char, 8> MAGIC{
    'K', 'P', 'B', 'P', '1', 'C', '0', '3'};
constexpr std::size_t HEADER_BYTES = 112;
constexpr std::uint8_t PEER_NONE = 0xff;
constexpr std::uint8_t FLAG_FIRST = 1;
constexpr std::uint8_t FLAG_LAST = 2;
constexpr std::size_t SEMANTIC_COUNT = 17;

enum class RecordType : std::uint8_t {
    Hello = 1,
    Data = 2,
    ProjectionSeal = 3,
    Completeness = 4,
    End = 5,
    Fork = 6,
};

[[noreturn]] void refuse() { throw CaptureRefused(); }
void need(bool value) { if (!value) refuse(); }

bool lower_hex(char value) {
    return (value >= '0' && value <= '9') ||
           (value >= 'a' && value <= 'f');
}

void word(const std::string& value) {
    need(value.size() == 64 &&
         std::all_of(value.begin(), value.end(), lower_hex));
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

unsigned char nibble(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    refuse();
}

std::array<unsigned char, 32> unhex(const std::string& value) {
    word(value);
    std::array<unsigned char, 32> result{};
    for (std::size_t index = 0; index < result.size(); ++index)
        result[index] = static_cast<unsigned char>(
            (nibble(value[2 * index]) << 4) | nibble(value[2 * index + 1]));
    return result;
}

std::array<unsigned char, 32> sha256(
        std::span<const unsigned char> value) {
    std::array<unsigned char, 32> result{};
    need(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}

void append(std::vector<unsigned char>& out,
            std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}

void append_text(std::vector<unsigned char>& out, const std::string& value) {
    append(out, {reinterpret_cast<const unsigned char*>(value.data()),
                 value.size()});
}

void be32(std::span<unsigned char, 4> out, std::uint32_t value) {
    for (unsigned index = 0; index < 4; ++index)
        out[index] = static_cast<unsigned char>(value >> (8 * (3 - index)));
}

void be64(std::span<unsigned char, 8> out, std::uint64_t value) {
    for (unsigned index = 0; index < 8; ++index)
        out[index] = static_cast<unsigned char>(value >> (8 * (7 - index)));
}

void append64(std::vector<unsigned char>& out, std::uint64_t value) {
    std::array<unsigned char, 8> encoded{};
    be64(encoded, value); append(out, encoded);
}

std::uint64_t observed_monotonic_ns() {
    timespec now{};
    need(::clock_gettime(CLOCK_MONOTONIC, &now) == 0 &&
         now.tv_sec >= 0 && now.tv_nsec >= 0 && now.tv_nsec < 1000000000L);
    const auto seconds = static_cast<std::uint64_t>(now.tv_sec);
    need(seconds <= (std::numeric_limits<std::uint64_t>::max() -
                     static_cast<std::uint64_t>(now.tv_nsec)) / 1000000000ULL);
    return seconds * 1000000000ULL +
        static_cast<std::uint64_t>(now.tv_nsec);
}

class SigpipeBlock final {
    sigset_t selected_{};
    sigset_t old_{};
    bool already_blocked_{};
public:
    SigpipeBlock() {
        sigemptyset(&selected_); sigaddset(&selected_, SIGPIPE);
        need(pthread_sigmask(SIG_BLOCK, &selected_, &old_) == 0);
        already_blocked_ = sigismember(&old_, SIGPIPE) == 1;
    }
    ~SigpipeBlock() { (void)pthread_sigmask(SIG_SETMASK, &old_, nullptr); }
    void consume() {
        if (already_blocked_) return;
        timespec zero{}; siginfo_t information{};
        while (sigtimedwait(&selected_, &information, &zero) < 0 &&
               errno == EINTR) {}
    }
};

void close_noexcept(int& fd) noexcept {
    if (fd >= 0) {
        const int old = fd; fd = -1; (void)::close(old);
    }
}

void write_all_bounded(int& fd, std::span<const unsigned char> value) {
    SigpipeBlock guard;
    std::size_t offset = 0;
    while (offset < value.size()) {
        const auto count = ::write(fd, value.data() + offset,
                                   value.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            if (errno == EPIPE) guard.consume();
            close_noexcept(fd); refuse();
        }
        offset += static_cast<std::size_t>(count);
    }
}

struct Counter {
    std::uint64_t messages{};
    std::uint64_t chunks{};
    std::uint64_t bytes{};
};

void increase(std::uint64_t& value, std::uint64_t amount) {
    need(amount <= std::numeric_limits<std::uint64_t>::max() - value);
    value += amount;
}

std::size_t lane_index(Semantic value) {
    const auto encoded = static_cast<std::uint8_t>(value);
    need(encoded >= 1 && encoded <= SEMANTIC_COUNT);
    return encoded - 1;
}

} // namespace

const char* CaptureRefused::what() const noexcept {
    return "KPB_P1_CAPTURE_REFUSED";
}

Fr32Lane Fr32Lane::checked(std::span<const unsigned char> value) {
    need(!value.empty() && value.size() % 32 == 0);
    return Fr32Lane(value);
}

G1Lane G1Lane::checked(std::span<const unsigned char> value) {
    need(!value.empty() && value.size() % G1_CAPTURE_BYTES == 0);
    return G1Lane(value);
}

G2Lane G2Lane::checked(std::span<const unsigned char> value) {
    need(!value.empty() && value.size() % G2_CAPTURE_BYTES == 0);
    return G2Lane(value);
}

AuthenticatedG1Lane AuthenticatedG1Lane::checked(
        std::span<const unsigned char> value) {
    need(!value.empty() && value.size() % AUTH_G1_CAPTURE_BYTES == 0);
    return AuthenticatedG1Lane(value);
}

AuthenticatedG2Lane AuthenticatedG2Lane::checked(
        std::span<const unsigned char> value) {
    need(!value.empty() && value.size() % AUTH_G2_CAPTURE_BYTES == 0);
    return AuthenticatedG2Lane(value);
}

class P1CaptureStream::Impl final {
public:
    int fd;
    const unsigned round;
    const RunBinding binding;
    const ForkId root{};
    std::mutex mutex;
    std::uint64_t sequence{};
    std::uint64_t message{};
    std::uint64_t first_monotonic_ns{};
    std::uint64_t last_monotonic_ns{};
    std::array<Counter, SEMANTIC_COUNT> counters{};
    std::uint64_t total_messages{};
    std::uint64_t total_chunks{};
    std::uint64_t total_bytes{};
    std::uint64_t pending_transports{};
    std::uint8_t offset_owners{};
    std::uint8_t preprocessing_owners{};
    std::array<std::uint64_t, 3> offset_bytes{};
    std::array<std::uint64_t, 3> preprocessing_bytes{};
    std::uint64_t instrumented{};
    std::uint64_t scalar_site_bitmap{};
    std::set<ForkId> forks{root};
    bool projection_sealed{};
    bool complete{};
    bool mac_key_recorded{};
    bool query_model_bound{};
    unsigned proof_stage{};
    std::array<unsigned char, AUTH_G1_CAPTURE_BYTES> base_a{};
    std::array<unsigned char, AUTH_G2_CAPTURE_BYTES> base_b2{};

    Impl(int selected_fd, unsigned selected_round, unsigned authenticated_role,
         bool encrypted_transport, RunBinding selected_binding)
        : fd(selected_fd), round(selected_round),
          binding(std::move(selected_binding)) {
        need(P1_CAPTURE_CONFIGURED == 0 && fd >= 0 &&
             (round == 1 || round == 2) &&
             fd == (round == 1 ? 23 : 28) && authenticated_role == 1 &&
             encrypted_transport);
        uuid(binding.attempt_id); word(binding.cohort_sha256);
        word(binding.financial_run_id); uuid(binding.capture_identity);
        word(binding.protocol_source_sha256);
        word(binding.protocol_build_sha256);
        word(binding.protocol_launch_sha256);
        word(binding.model_preimage_sha256);
        word(binding.query_store_preimage_sha256);
        word(binding.scalar_capture_manifest_sha256);
        need(binding.scalar_capture_manifest_sha256 ==
                 SCALAR_CAPTURE_MANIFEST_SHA256 &&
             unhex(binding.scalar_capture_manifest_sha256) == sha256({
                 reinterpret_cast<const unsigned char*>(
                     SCALAR_CAPTURE_MANIFEST.data()),
                 SCALAR_CAPTURE_MANIFEST.size()}));
        const int flags = ::fcntl(fd, F_GETFL);
        need(flags >= 0 && ::fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == 0);

        std::vector<unsigned char> hello;
        hello.reserve(332);
        hello.push_back(static_cast<unsigned char>(round));
        hello.push_back(1); // Authenticated corrupt server component P1.
        hello.push_back(0); // CONFIGURED0.
        hello.push_back(static_cast<unsigned char>(fd));
        append_text(hello, binding.attempt_id);
        const auto cohort = unhex(binding.cohort_sha256);
        const auto run = unhex(binding.financial_run_id);
        const auto source = unhex(binding.protocol_source_sha256);
        const auto build = unhex(binding.protocol_build_sha256);
        const auto launch = unhex(binding.protocol_launch_sha256);
        const auto model = unhex(binding.model_preimage_sha256);
        const auto query = unhex(binding.query_store_preimage_sha256);
        const auto scalar_manifest = unhex(
            binding.scalar_capture_manifest_sha256);
        append(hello, cohort); append(hello, run);
        append_text(hello, binding.capture_identity);
        append(hello, source); append(hello, build); append(hello, launch);
        append(hello, model); append(hello, query);
        append(hello, scalar_manifest);
        need(hello.size() == 332);
        emit_message_locked(
            RecordType::Hello, Semantic::OwnerInputOffsetFrame,
                            Direction::Local, PEER_NONE, root, hello, false);
    }

    ~Impl() { close_noexcept(fd); }

    void frame_locked(RecordType type, Semantic semantic, Direction direction,
                      std::uint8_t peer, std::uint8_t flags,
                      std::uint64_t selected_message, std::uint32_t chunk,
                      const ForkId& fork,
                      std::span<const unsigned char> payload) {
        need(fd >= 0 && !complete && payload.size() <= MAX_CHUNK_BYTES &&
             forks.contains(fork) && sequence !=
                 std::numeric_limits<std::uint64_t>::max());
        std::array<unsigned char, HEADER_BYTES> header{};
        const auto monotonic_ns = observed_monotonic_ns();
        need(monotonic_ns > 0 &&
             (last_monotonic_ns == 0 || monotonic_ns >= last_monotonic_ns));
        if (first_monotonic_ns == 0) first_monotonic_ns = monotonic_ns;
        last_monotonic_ns = monotonic_ns;
        std::copy(MAGIC.begin(), MAGIC.end(), header.begin());
        header[8] = static_cast<std::uint8_t>(type);
        header[9] = static_cast<std::uint8_t>(semantic);
        header[10] = static_cast<std::uint8_t>(direction);
        header[11] = peer;
        header[12] = flags;
        be64(std::span<unsigned char, 8>(header.data() + 16, 8), monotonic_ns);
        be64(std::span<unsigned char, 8>(header.data() + 24, 8), sequence);
        be64(std::span<unsigned char, 8>(header.data() + 32, 8),
             selected_message);
        be32(std::span<unsigned char, 4>(header.data() + 40, 4), chunk);
        be32(std::span<unsigned char, 4>(header.data() + 44, 4),
             static_cast<std::uint32_t>(payload.size()));
        std::copy(fork.begin(), fork.end(), header.begin() + 48);
        const auto digest = sha256(payload);
        std::copy(digest.begin(), digest.end(), header.begin() + 80);
        try {
            write_all_bounded(fd, header);
            write_all_bounded(fd, payload);
            increase(sequence, 1);
        } catch (...) {
            close_noexcept(fd); throw;
        }
    }

    void emit_message_locked(RecordType type, Semantic semantic,
                             Direction direction, std::uint8_t peer,
                             const ForkId& fork,
                             std::span<const unsigned char> payload,
                             bool count) {
        need(message != std::numeric_limits<std::uint64_t>::max());
        const auto selected_message = message++;
        const std::size_t chunks = payload.empty() ? 1 :
            (payload.size() - 1) / MAX_CHUNK_BYTES + 1;
        need(chunks <= static_cast<std::uint64_t>(
                           std::numeric_limits<std::uint32_t>::max()) + 1);
        for (std::size_t index = 0; index < chunks; ++index) {
            const std::size_t first = index * MAX_CHUNK_BYTES;
            const std::size_t size = payload.empty() ? 0 :
                std::min(MAX_CHUNK_BYTES, payload.size() - first);
            std::uint8_t flags = 0;
            if (index == 0) flags |= FLAG_FIRST;
            if (index + 1 == chunks) flags |= FLAG_LAST;
            frame_locked(type, semantic, direction, peer, flags,
                         selected_message, static_cast<std::uint32_t>(index),
                         fork, payload.subspan(first, size));
        }
        if (count) {
            auto& lane = counters.at(lane_index(semantic));
            increase(lane.messages, 1);
            increase(lane.chunks, chunks);
            increase(lane.bytes, payload.size());
            increase(total_messages, 1);
            increase(total_chunks, chunks);
            increase(total_bytes, payload.size());
        }
    }

    void data(Semantic semantic, Direction direction, std::uint8_t peer,
              const ForkId& fork, std::span<const unsigned char> payload) {
        std::lock_guard guard(mutex);
        need(!projection_sealed &&
             (instrumented & (std::uint64_t{1} << lane_index(semantic))) != 0 &&
             (semantic == Semantic::PeerTransport ||
              (semantic == Semantic::MacKeyShare && !mac_key_recorded) ||
              mac_key_recorded));
        emit_message_locked(RecordType::Data, semantic, direction, peer,
                            fork, payload, true);
        if (semantic == Semantic::MacKeyShare) mac_key_recorded = true;
    }

    std::vector<unsigned char> completeness() const {
        std::vector<unsigned char> result;
        result.reserve(496);
        std::array<unsigned char, 4> value32{};
        be32(value32, 9); append(result, value32);
        be32(value32, SEMANTIC_COUNT); append(result, value32);
        append64(result, total_messages);
        append64(result, total_chunks);
        append64(result, total_bytes);
        for (const auto& lane : counters) {
            append64(result, lane.messages);
            append64(result, lane.chunks);
            append64(result, lane.bytes);
        }
        append64(result, instrumented);
        append64(result, offset_owners);
        append64(result, preprocessing_owners);
        append64(result, scalar_site_bitmap);
        append64(result, sequence);
        append64(result, first_monotonic_ns);
        append64(result, last_monotonic_ns);
        need(result.size() == 496 && sequence > 0 &&
             first_monotonic_ns > 0 && last_monotonic_ns >= first_monotonic_ns);
        return result;
    }
};

P1CaptureStream::P1CaptureStream(
        int fd, unsigned round, unsigned authenticated_role,
        bool encrypted_transport, RunBinding binding)
    : impl_(std::make_unique<Impl>(fd, round, authenticated_role,
                                  encrypted_transport, std::move(binding))) {}

P1CaptureStream::~P1CaptureStream() = default;

void P1CaptureStream::TransportRecorder::record(
        Direction direction, unsigned peer, const ForkId& fork,
        std::span<const unsigned char> payload) {
    need((direction == Direction::Send || direction == Direction::Receive) &&
         peer < 3 && peer != 1 &&
         owner_.impl_->forks.contains(fork));
    owner_.impl_->emit_message_locked(
        RecordType::Data, Semantic::PeerTransport, direction,
        static_cast<std::uint8_t>(peer), fork, payload, true);
}

void P1CaptureStream::transport_transaction(
        const std::function<void()>& operation,
        const std::function<void(TransportRecorder&)>& record) {
    need(static_cast<bool>(operation) && static_cast<bool>(record));
    {
        std::lock_guard guard(impl_->mutex);
        need(impl_->fd >= 0 && !impl_->complete &&
             !impl_->projection_sealed && impl_->pending_transports !=
                 std::numeric_limits<std::uint64_t>::max() &&
             (impl_->instrumented & (std::uint64_t{1} <<
                lane_index(Semantic::PeerTransport))) != 0);
        ++impl_->pending_transports;
    }
    try {
        operation();
    } catch (...) {
        poison();
        throw;
    }
    std::lock_guard guard(impl_->mutex);
    need(impl_->fd >= 0 && !impl_->complete && !impl_->projection_sealed &&
         impl_->pending_transports > 0);
    TransportRecorder recorder(*this);
    try {
        record(recorder);
        --impl_->pending_transports;
    } catch (...) {
        close_noexcept(impl_->fd);
        throw;
    }
}

void P1CaptureStream::begin_async_receive(
        const std::function<void()>& operation) {
    need(static_cast<bool>(operation));
    {
        std::lock_guard guard(impl_->mutex);
        need(impl_->fd >= 0 && !impl_->complete &&
             !impl_->projection_sealed && impl_->pending_transports !=
                 std::numeric_limits<std::uint64_t>::max() &&
             (impl_->instrumented & (std::uint64_t{1} <<
                lane_index(Semantic::PeerTransport))) != 0);
        ++impl_->pending_transports;
    }
    try {
        operation();
    } catch (...) {
        poison();
        throw;
    }
}

void P1CaptureStream::finish_async_receive(
        const std::function<void()>& operation,
        const std::function<void(TransportRecorder&)>& record) {
    need(static_cast<bool>(operation) && static_cast<bool>(record));
    {
        std::lock_guard guard(impl_->mutex);
        need(impl_->fd >= 0 && !impl_->complete &&
             !impl_->projection_sealed && impl_->pending_transports > 0);
    }
    try {
        operation();
    } catch (...) {
        poison();
        throw;
    }
    std::lock_guard guard(impl_->mutex);
    need(impl_->fd >= 0 && !impl_->complete && !impl_->projection_sealed &&
         impl_->pending_transports > 0);
    TransportRecorder recorder(*this);
    try {
        record(recorder);
        --impl_->pending_transports;
    } catch (...) {
        close_noexcept(impl_->fd);
        throw;
    }
}

void P1CaptureStream::poison() noexcept {
    if (!impl_) return;
    std::lock_guard guard(impl_->mutex);
    close_noexcept(impl_->fd);
}

const ForkId& P1CaptureStream::root_fork() const {
    need(impl_ != nullptr); return impl_->root;
}

void P1CaptureStream::declare_instrumented(Semantic semantic) {
    const auto index = lane_index(semantic);
    std::lock_guard guard(impl_->mutex);
    need(impl_->fd >= 0 && !impl_->complete && !impl_->projection_sealed);
    impl_->instrumented |= std::uint64_t{1} << index;
}

ForkId P1CaptureStream::register_fork(
        const ForkId& parent, const std::string& suffix) {
    std::lock_guard guard(impl_->mutex);
    need(!impl_->projection_sealed && impl_->forks.contains(parent) &&
         !suffix.empty() && suffix.size() <= 128);
    std::vector<unsigned char> preimage;
    static constexpr std::string_view label = "KPB_P1_CAPTURE_FORK_V1\n";
    append(preimage, {reinterpret_cast<const unsigned char*>(label.data()),
                      label.size()});
    append(preimage, parent);
    std::array<unsigned char, 8> size{};
    be64(size, suffix.size()); append(preimage, size);
    append_text(preimage, suffix);
    const auto child = sha256(preimage);
    need(child != ForkId{} && impl_->forks.insert(child).second);
    std::vector<unsigned char> payload;
    payload.reserve(96);
    append(payload, parent); append(payload, child);
    const auto suffix_digest = sha256({
        reinterpret_cast<const unsigned char*>(suffix.data()), suffix.size()});
    append(payload, suffix_digest);
    impl_->emit_message_locked(RecordType::Fork, Semantic::PeerTransport,
                               Direction::Local, PEER_NONE, parent, payload,
                               false);
    return child;
}

void P1CaptureStream::peer_transport(
        Direction direction, unsigned peer, const ForkId& fork,
        std::span<const unsigned char> payload) {
    need((direction == Direction::Send || direction == Direction::Receive) &&
         peer < 3 && peer != 1);
    impl_->data(Semantic::PeerTransport, direction,
                static_cast<std::uint8_t>(peer), fork, payload);
}

void P1CaptureStream::owner_input_preprocessing_share_frame(
        unsigned owner, Fr32Lane lane) {
    need(owner < 3);
    {
        std::lock_guard guard(impl_->mutex);
        need(!impl_->projection_sealed && impl_->mac_key_recorded &&
             (impl_->instrumented & (std::uint64_t{1} << lane_index(
                Semantic::OwnerInputPreprocessingShareFrame))) != 0 &&
             (impl_->preprocessing_owners & (1U << owner)) == 0);
        impl_->emit_message_locked(
            RecordType::Data, Semantic::OwnerInputPreprocessingShareFrame,
            Direction::Send, static_cast<std::uint8_t>(owner), impl_->root,
            lane.bytes(), true);
        impl_->preprocessing_owners |=
            static_cast<std::uint8_t>(1U << owner);
        impl_->preprocessing_bytes.at(owner) = lane.bytes().size();
    }
}

void P1CaptureStream::owner_input_offset_frame(
        unsigned owner, Fr32Lane lane) {
    need(owner < 3);
    {
        std::lock_guard guard(impl_->mutex);
        need(!impl_->projection_sealed && impl_->mac_key_recorded &&
             (impl_->instrumented & (std::uint64_t{1} <<
                lane_index(Semantic::OwnerInputOffsetFrame))) != 0 &&
             (impl_->offset_owners & (1U << owner)) == 0);
        impl_->emit_message_locked(
            RecordType::Data, Semantic::OwnerInputOffsetFrame,
            Direction::Receive,
            static_cast<std::uint8_t>(owner), impl_->root, lane.bytes(), true);
        impl_->offset_owners |= static_cast<std::uint8_t>(1U << owner);
        impl_->offset_bytes.at(owner) = lane.bytes().size();
    }
}

namespace {
std::array<unsigned char, 16> scalar_binding_payload(
        ScalarCaptureKind kind, ScalarCaptureSite site, std::size_t count) {
    need(valid_scalar_capture_site(site) && scalar_capture_kind(site) == kind &&
         count > 0);
    std::array<unsigned char, 16> payload{};
    payload[0] = 1;
    payload[1] = static_cast<unsigned char>(kind);
    const auto encoded_site = static_cast<std::uint16_t>(site);
    payload[2] = static_cast<unsigned char>(encoded_site >> 8);
    payload[3] = static_cast<unsigned char>(encoded_site);
    be64(std::span<unsigned char, 8>(payload.data() + 4, 8), count);
    return payload;
}
} // namespace

void P1CaptureStream::authenticated_values(
        ScalarCaptureSite site, Fr32Lane shares, Fr32Lane macs) {
    need(shares.elements() == macs.elements());
    const auto binding = scalar_binding_payload(
        ScalarCaptureKind::Authenticated, site, shares.elements());
    std::lock_guard guard(impl_->mutex);
    need(!impl_->projection_sealed && impl_->mac_key_recorded &&
         (impl_->instrumented & (std::uint64_t{1} << lane_index(
            Semantic::ScalarCaptureBinding))) != 0);
    impl_->emit_message_locked(
        RecordType::Data, Semantic::ScalarCaptureBinding, Direction::Local,
        PEER_NONE, impl_->root, binding, true);
    impl_->emit_message_locked(
        RecordType::Data, Semantic::AuthenticatedShare, Direction::Local,
        PEER_NONE, impl_->root, shares.bytes(), true);
    impl_->emit_message_locked(
        RecordType::Data, Semantic::MacShare, Direction::Local,
        PEER_NONE, impl_->root, macs.bytes(), true);
    impl_->scalar_site_bitmap |=
        std::uint64_t{1} << (static_cast<unsigned>(site) - 1);
}

void P1CaptureStream::randomness(
        ScalarCaptureSite site, Fr32Lane shares, Fr32Lane macs) {
    need(shares.elements() == macs.elements());
    const auto binding = scalar_binding_payload(
        ScalarCaptureKind::Randomness, site, shares.elements());
    std::lock_guard guard(impl_->mutex);
    need(!impl_->projection_sealed && impl_->mac_key_recorded &&
         (impl_->instrumented & (std::uint64_t{1} << lane_index(
            Semantic::ScalarCaptureBinding))) != 0);
    impl_->emit_message_locked(
        RecordType::Data, Semantic::ScalarCaptureBinding, Direction::Local,
        PEER_NONE, impl_->root, binding, true);
    impl_->emit_message_locked(
        RecordType::Data, Semantic::RandomnessShare, Direction::Local,
        PEER_NONE, impl_->root, shares.bytes(), true);
    impl_->emit_message_locked(
        RecordType::Data, Semantic::RandomnessMac, Direction::Local,
        PEER_NONE, impl_->root, macs.bytes(), true);
    impl_->scalar_site_bitmap |=
        std::uint64_t{1} << (static_cast<unsigned>(site) - 1);
}

void P1CaptureStream::mac_key_share(Fr32Lane lane) {
    need(lane.elements() == 1);
    impl_->data(Semantic::MacKeyShare, Direction::Local, PEER_NONE,
                impl_->root, lane.bytes());
}

void P1CaptureStream::field_opening(Fr32Lane lane) {
    impl_->data(Semantic::FieldOpening, Direction::Local, PEER_NONE,
                impl_->root, lane.bytes());
}

void P1CaptureStream::masked_field_differences(Fr32Lane lane) {
    need(lane.elements() == 2);
    std::lock_guard guard(impl_->mutex);
    need(!impl_->projection_sealed && impl_->mac_key_recorded &&
         impl_->proof_stage == 3 &&
         (impl_->instrumented & (std::uint64_t{1} << lane_index(
            Semantic::MaskedFieldDifference))) != 0);
    impl_->emit_message_locked(
        RecordType::Data, Semantic::MaskedFieldDifference, Direction::Local,
        PEER_NONE, impl_->root, lane.bytes(), true);
    impl_->proof_stage = 4;
}

void P1CaptureStream::masked_group_differences(G1Lane lane) {
    need(lane.bytes().size() == 2 * G1_CAPTURE_BYTES);
    std::lock_guard guard(impl_->mutex);
    need(!impl_->projection_sealed && impl_->mac_key_recorded &&
         impl_->proof_stage == 4 &&
         (impl_->instrumented & (std::uint64_t{1} << lane_index(
            Semantic::MaskedGroupDifferenceG1))) != 0);
    impl_->emit_message_locked(
        RecordType::Data, Semantic::MaskedGroupDifferenceG1,
        Direction::Local, PEER_NONE, impl_->root, lane.bytes(), true);
    impl_->proof_stage = 5;
}

void P1CaptureStream::authenticated_g1_state(
        GroupStateStage stage, AuthenticatedG1Lane lane) {
    const auto bytes = lane.bytes();
    std::vector<unsigned char> payload;
    payload.reserve(1 + bytes.size());
    payload.push_back(static_cast<unsigned char>(stage));
    append(payload, bytes);
    std::lock_guard guard(impl_->mutex);
    need(!impl_->projection_sealed && impl_->mac_key_recorded &&
         (impl_->instrumented & (std::uint64_t{1} << lane_index(
            Semantic::AuthenticatedG1State))) != 0);
    unsigned next = 0;
    switch (stage) {
        case GroupStateStage::Base:
            need(impl_->proof_stage == 0 &&
                 bytes.size() == 4 * AUTH_G1_CAPTURE_BYTES);
            std::copy_n(bytes.begin(), AUTH_G1_CAPTURE_BYTES,
                        impl_->base_a.begin());
            next = 1;
            break;
        case GroupStateStage::Mixed:
            need(impl_->proof_stage == 2 &&
                 bytes.size() == 6 * AUTH_G1_CAPTURE_BYTES);
            next = 3;
            break;
        case GroupStateStage::Products:
            need(impl_->proof_stage == 5 &&
                 bytes.size() == 2 * AUTH_G1_CAPTURE_BYTES);
            next = 6;
            break;
        case GroupStateStage::Final:
            need(impl_->proof_stage == 6 &&
                 bytes.size() == 2 * AUTH_G1_CAPTURE_BYTES &&
                 std::equal(impl_->base_a.begin(), impl_->base_a.end(),
                            bytes.begin()));
            next = 7;
            break;
        default:
            refuse();
    }
    impl_->emit_message_locked(
        RecordType::Data, Semantic::AuthenticatedG1State, Direction::Local,
        PEER_NONE, impl_->root, payload, true);
    impl_->proof_stage = next;
}

void P1CaptureStream::authenticated_g2_state(
        GroupStateStage stage, AuthenticatedG2Lane lane) {
    const auto bytes = lane.bytes();
    std::vector<unsigned char> payload;
    payload.reserve(1 + bytes.size());
    payload.push_back(static_cast<unsigned char>(stage));
    append(payload, bytes);
    std::lock_guard guard(impl_->mutex);
    need(!impl_->projection_sealed && impl_->mac_key_recorded &&
         (impl_->instrumented & (std::uint64_t{1} << lane_index(
            Semantic::AuthenticatedG2State))) != 0);
    unsigned next = 0;
    if (stage == GroupStateStage::Base) {
        need(impl_->proof_stage == 1 &&
             bytes.size() == AUTH_G2_CAPTURE_BYTES);
        std::copy(bytes.begin(), bytes.end(), impl_->base_b2.begin());
        next = 2;
    } else if (stage == GroupStateStage::Final) {
        need(impl_->proof_stage == 7 &&
             bytes.size() == AUTH_G2_CAPTURE_BYTES &&
             std::equal(impl_->base_b2.begin(), impl_->base_b2.end(),
                        bytes.begin()));
        next = 8;
    } else {
        refuse();
    }
    impl_->emit_message_locked(
        RecordType::Data, Semantic::AuthenticatedG2State, Direction::Local,
        PEER_NONE, impl_->root, payload, true);
    impl_->proof_stage = next;
}

void P1CaptureStream::final_group_opening(G1Lane lane) {
    need(lane.bytes().size() == 2 * G1_CAPTURE_BYTES);
    std::lock_guard guard(impl_->mutex);
    need(!impl_->projection_sealed && impl_->mac_key_recorded &&
         impl_->proof_stage == 8 &&
         (impl_->instrumented & (std::uint64_t{1} << lane_index(
            Semantic::GroupOpeningG1))) != 0);
    impl_->emit_message_locked(
        RecordType::Data, Semantic::GroupOpeningG1, Direction::Local,
        PEER_NONE, impl_->root, lane.bytes(), true);
    impl_->proof_stage = 9;
}

void P1CaptureStream::final_group_opening(G2Lane lane) {
    need(lane.bytes().size() == G2_CAPTURE_BYTES);
    std::lock_guard guard(impl_->mutex);
    need(!impl_->projection_sealed && impl_->mac_key_recorded &&
         impl_->proof_stage == 9 &&
         (impl_->instrumented & (std::uint64_t{1} << lane_index(
            Semantic::GroupOpeningG2))) != 0);
    impl_->emit_message_locked(
        RecordType::Data, Semantic::GroupOpeningG2, Direction::Local,
        PEER_NONE, impl_->root, lane.bytes(), true);
    impl_->proof_stage = 10;
}

void P1CaptureStream::bind_query_model_preimages(
        const std::string& model_sha256,
        const std::string& query_store_sha256) {
    word(model_sha256);
    word(query_store_sha256);
    std::lock_guard guard(impl_->mutex);
    need(!impl_->projection_sealed && !impl_->query_model_bound &&
         model_sha256 == impl_->binding.model_preimage_sha256 &&
         query_store_sha256 ==
            impl_->binding.query_store_preimage_sha256);
    impl_->query_model_bound = true;
}

void P1CaptureStream::seal_projection(
        std::span<const unsigned char> projection) {
    need(projection.size() == 10685);
    std::lock_guard guard(impl_->mutex);
    need(!impl_->projection_sealed && impl_->pending_transports == 0 &&
         impl_->mac_key_recorded && impl_->query_model_bound &&
         (impl_->instrumented & (std::uint64_t{1} <<
            lane_index(Semantic::PublicProjection))) != 0);
    impl_->emit_message_locked(
        RecordType::Data, Semantic::PublicProjection, Direction::Local,
        PEER_NONE, impl_->root, projection, true);
    const auto identity = sha256(projection);
    impl_->emit_message_locked(
        RecordType::ProjectionSeal, Semantic::PublicProjection,
        Direction::Local, PEER_NONE, impl_->root, identity, false);
    impl_->projection_sealed = true;
}

void P1CaptureStream::close_complete() {
    std::lock_guard guard(impl_->mutex);
    for (unsigned owner = 0; owner < 3; ++owner) {
        const auto offset = impl_->offset_bytes.at(owner);
        need(offset > 0 && offset <=
                 std::numeric_limits<std::uint64_t>::max() / 5 &&
             impl_->preprocessing_bytes.at(owner) == 5 * offset);
    }
    const auto exact_lane = [&](Semantic semantic, std::uint64_t bytes) {
        const auto& lane = impl_->counters.at(lane_index(semantic));
        need(lane.messages == 1 && lane.chunks == 1 && lane.bytes == bytes);
    };
    exact_lane(Semantic::MaskedFieldDifference, 2 * 32);
    exact_lane(Semantic::MaskedGroupDifferenceG1, 2 * G1_CAPTURE_BYTES);
    exact_lane(Semantic::GroupOpeningG1, 2 * G1_CAPTURE_BYTES);
    exact_lane(Semantic::GroupOpeningG2, G2_CAPTURE_BYTES);
    exact_lane(Semantic::MacKeyShare, 32);
    const auto& g1_state = impl_->counters.at(
        lane_index(Semantic::AuthenticatedG1State));
    need(g1_state.messages == 4 && g1_state.chunks == 4 &&
         g1_state.bytes == 1824);
    const auto& g2_state = impl_->counters.at(
        lane_index(Semantic::AuthenticatedG2State));
    need(g2_state.messages == 2 && g2_state.chunks == 2 &&
         g2_state.bytes == 518);
    const auto& scalar_bindings = impl_->counters.at(
        lane_index(Semantic::ScalarCaptureBinding));
    const auto& authenticated_shares = impl_->counters.at(
        lane_index(Semantic::AuthenticatedShare));
    const auto& mac_shares = impl_->counters.at(
        lane_index(Semantic::MacShare));
    const auto& randomness_shares = impl_->counters.at(
        lane_index(Semantic::RandomnessShare));
    const auto& randomness_macs = impl_->counters.at(
        lane_index(Semantic::RandomnessMac));
    need(authenticated_shares.messages == mac_shares.messages &&
         authenticated_shares.bytes == mac_shares.bytes &&
         randomness_shares.messages == randomness_macs.messages &&
         randomness_shares.bytes == randomness_macs.bytes &&
         authenticated_shares.messages <=
            std::numeric_limits<std::uint64_t>::max() -
                randomness_shares.messages &&
         scalar_bindings.messages == authenticated_shares.messages +
            randomness_shares.messages &&
         scalar_bindings.chunks == scalar_bindings.messages &&
         scalar_bindings.messages <=
            std::numeric_limits<std::uint64_t>::max() / 16 &&
         scalar_bindings.bytes == 16 * scalar_bindings.messages &&
         impl_->scalar_site_bitmap == SELECTED_SCALAR_SITE_BITMAP);
    need(!impl_->complete && impl_->fd >= 0 && impl_->projection_sealed &&
         impl_->offset_owners == 0x07 &&
         impl_->preprocessing_owners == 0x07 && impl_->proof_stage == 10 &&
         impl_->query_model_bound &&
         impl_->instrumented ==
             ((std::uint64_t{1} << SEMANTIC_COUNT) - 1));
    const auto summary = impl_->completeness();
    impl_->emit_message_locked(
        RecordType::Completeness, Semantic::PublicProjection,
        Direction::Local, PEER_NONE, impl_->root, summary, false);
    impl_->emit_message_locked(
        RecordType::End, Semantic::PublicProjection, Direction::Local,
        PEER_NONE, impl_->root, {}, false);
    const int old = impl_->fd; impl_->fd = -1;
    need(::close(old) == 0);
    impl_->complete = true;
}

SourceStatus source_status() {
    return {
        .schema = "kpb-p1-streaming-capture-source-only/v9",
        .configured = false,
        .registered_driver_integrated = false,
        .producer_integrated = false,
        .launch_authorized = false,
        .actual_receipt_enabled = false,
    };
}

} // namespace kpi::mpc::p1_capture
