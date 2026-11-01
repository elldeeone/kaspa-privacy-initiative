#include "privacy_capture_private_hook.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <map>
#include <optional>
#include <pthread.h>
#include <set>
#include <signal.h>
#include <string_view>
#include <time.h>
#include <unistd.h>
#include <vector>

namespace kpb::capture::detail {
namespace {

constexpr std::array<unsigned char, 8> MAGIC{
    'K', 'P', 'B', 'C', 'E', 'V', '0', '1'};
// The largest selected owner lane is 84,333,120 raw bytes. Hex framing doubles
// it, so 256 MiB leaves explicit headroom without permitting caller-sized
// allocation/write amplification.
constexpr std::size_t MAX_FRAME_BYTES = 1U << 28;
constexpr std::size_t MAX_LANE_BYTES = 1U << 27;
[[noreturn]] void refuse() { throw CaptureRefused(); }
void need(bool value) { if (!value) refuse(); }
bool lower_hex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }
void word(const std::string& value) {
    need(value.size() == 64 && std::all_of(value.begin(), value.end(), lower_hex));
}
void uuid(const std::string& value) {
    need(value.size() == 36);
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) need(value[i] == '-');
        else need(lower_hex(value[i]));
    }
    need(value[14] == '4' && std::string("89ab").find(value[19]) != std::string::npos);
}
void selected(const Binding& value) {
    uuid(value.attempt_id); word(value.cohort_sha256); word(value.financial_run_id);
    uuid(value.capture_identity); word(value.projection_sha256);
}
std::string quote(const std::string& value) {
    need(!value.empty() && std::all_of(value.begin(), value.end(), [](char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
    }));
    return '"' + value + '"';
}
std::span<const unsigned char> bytes(const std::string& value) {
    return {reinterpret_cast<const unsigned char*>(value.data()), value.size()};
}
std::string hex(std::span<const unsigned char> value) {
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string result(2 * value.size(), '0');
    for (std::size_t i = 0; i < value.size(); ++i) {
        result[2 * i] = alphabet[value[i] >> 4]; result[2 * i + 1] = alphabet[value[i] & 15];
    }
    return result;
}
std::string string_array(std::span<const std::string> values) {
    std::string result = "[";
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i) result += ',';
        result += quote(values[i]);
    }
    return result + ']';
}
std::uint64_t monotonic_ns() {
    timespec value{};
    need(::clock_gettime(CLOCK_MONOTONIC, &value) == 0 && value.tv_sec >= 0);
    return static_cast<std::uint64_t>(value.tv_sec) * 1000000000ULL +
           static_cast<std::uint64_t>(value.tv_nsec);
}

class SigpipeBlock final {
public:
    SigpipeBlock() {
        sigemptyset(&set_); sigaddset(&set_, SIGPIPE);
        need(pthread_sigmask(SIG_BLOCK, &set_, &old_) == 0);
        old_blocked_ = sigismember(&old_, SIGPIPE) == 1;
    }
    ~SigpipeBlock() { (void)pthread_sigmask(SIG_SETMASK, &old_, nullptr); }
    void consume() {
        if (old_blocked_) return;
        timespec zero{}; siginfo_t info{};
        while (sigtimedwait(&set_, &info, &zero) < 0 && errno == EINTR) {}
    }
private:
    sigset_t set_{}; sigset_t old_{}; bool old_blocked_{};
};
void write_all(int fd, std::span<const unsigned char> value) {
    SigpipeBlock guard; std::size_t at = 0;
    while (at < value.size()) {
        auto count = ::write(fd, value.data() + at, value.size() - at);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { if (errno == EPIPE) guard.consume(); refuse(); }
        at += static_cast<std::size_t>(count);
    }
}
void close_noexcept(int& fd) noexcept {
    if (fd >= 0) { int old = fd; fd = -1; (void)::close(old); }
}

class Writer final {
public:
    Writer(int fd, unsigned round, const std::string& kind, const Binding& binding)
        : fd_(fd), round_(round), binding_(binding) {
        try {
            need(fd_ >= 0 && (round_ == 1 || round_ == 2)); selected(binding_);
            const auto hello = "{\"attempt_id\":" + quote(binding_.attempt_id) +
                ",\"capture_identity\":" + quote(binding_.capture_identity) +
                ",\"cohort_sha256\":" + quote(binding_.cohort_sha256) +
                ",\"financial_run_id\":" + quote(binding_.financial_run_id) +
                ",\"kind\":" + quote(kind) + ",\"round\":" +
                std::to_string(round_) +
                ",\"schema\":\"kpb-capture-event-channel/v1\"}\n";
            frame(1, bytes(hello));
        } catch (...) { close_noexcept(fd_); throw; }
    }
    ~Writer() { close_noexcept(fd_); }
    void meta(const std::string& value) { frame(2, bytes(value)); }
    void record(const std::string& stream, const std::string& value) {
        const auto record = "{\"stream\":" + quote(stream) +
            ",\"value\":" + value + "}\n";
        frame(3, bytes(record));
    }
    void sourced_record(const std::string& stream, const std::string& source,
                        const std::string& value) {
        const auto record = "{\"source\":" + source +
            ",\"stream\":" + quote(stream) + ",\"value\":" + value + "}\n";
        frame(3, bytes(record));
    }
    void complete() {
        need(!complete_ && fd_ >= 0); frame(5, {});
        const int old = fd_; fd_ = -1; need(::close(old) == 0); complete_ = true;
    }
    unsigned round() const { return round_; }
    const Binding& binding() const { return binding_; }
private:
    int fd_; unsigned round_; Binding binding_; bool complete_{};
    void frame(unsigned char tag, std::span<const unsigned char> payload) {
        need(fd_ >= 0 && tag >= 1 && tag <= 5 && payload.size() <= MAX_FRAME_BYTES);
        std::array<unsigned char, 17> header{};
        std::copy(MAGIC.begin(), MAGIC.end(), header.begin()); header[8] = tag;
        std::uint64_t size = payload.size();
        for (unsigned i = 0; i < 8; ++i)
            header[9 + i] = static_cast<unsigned char>(size >> (8 * (7 - i)));
        try { write_all(fd_, header); write_all(fd_, payload); }
        catch (...) { close_noexcept(fd_); throw; }
    }
};

std::string retry_outcome(RetryOutcome value, bool terminal) {
    if (value == RetryOutcome::Refused) return "refused";
    if (value == RetryOutcome::Disconnected) return "disconnected";
    if (value == RetryOutcome::Completed && !terminal) return "completed";
    if (value == RetryOutcome::Orphaned && terminal) return "orphaned";
    refuse();
}
} // namespace

struct CorruptServerChannel::Impl {
    Writer writer; std::string source; std::uint64_t sequence{};
    std::array<std::size_t, 3> preprocessing_bytes{};
    std::vector<unsigned char> base_a;
    std::vector<unsigned char> base_b2;
    unsigned next_owner{};
    unsigned stage{};
    explicit Impl(int fd, unsigned round, const Binding& binding,
                  const std::string& protocol_source)
        : writer(fd, round, "corrupt-server-capture", binding), source(protocol_source) {
        word(source);
        const auto meta = "{\"build_policy\":{\"corruption_model\":"
            "\"ONE_SERVER_PLUS_OWNER1\",\"debug_mac\":false,\"insecure\":false,"
            "\"no_client_tls\":false,\"print_mac\":false},\"cohort_sha256\":" +
            quote(binding.cohort_sha256) + ",\"projection_sha256\":" +
            quote(binding.projection_sha256) + ",\"protocol_source_sha256\":" +
            quote(source) + ",\"round\":" + std::to_string(round) +
            ",\"schema\":\"kpb-corrupt-server-observer-capture/v1\"," 
            "\"server_component\":1}\n";
        writer.meta(meta);
    }
    void record(const std::string& channel, const std::string& encoding, int owner,
                std::span<const unsigned char> payload, const std::string& phase,
                const std::string& semantic) {
        need(!payload.empty() && payload.size() <= MAX_LANE_BYTES);
        const auto owner_json = owner < 0 ? std::string("null") : std::to_string(owner);
        const auto value = "{\"channel\":" + quote(channel) +
            ",\"encoding\":" + quote(encoding) + ",\"owner_component\":" + owner_json +
            ",\"payload_hex\":" + quote(hex(payload)) + ",\"phase\":" + quote(phase) +
            ",\"semantic\":" + quote(semantic) + ",\"sequence\":" +
            std::to_string(sequence++) + '}';
        writer.record(semantic, value);
    }
    void staged_record(const std::string& encoding, unsigned group_stage,
                       std::span<const unsigned char> payload,
                       const std::string& semantic) {
        need(group_stage >= 1 && group_stage <= 4 &&
             payload.size() < MAX_LANE_BYTES);
        std::vector<unsigned char> tagged;
        tagged.reserve(payload.size() + 1);
        tagged.push_back(static_cast<unsigned char>(group_stage));
        tagged.insert(tagged.end(), payload.begin(), payload.end());
        record("local", encoding, -1, tagged, "proof", semantic);
    }
};

CorruptServerChannel::CorruptServerChannel(int fd, unsigned round,
    const Binding& binding, const std::string& source)
    : impl_(new Impl(fd, round, binding, source)) {}
CorruptServerChannel::~CorruptServerChannel() = default;
void CorruptServerChannel::owner_input_preprocessing_share(unsigned owner,
    std::span<const unsigned char> payload) {
    need(impl_->stage == 0 && owner == impl_->next_owner && owner < 3 &&
         impl_->preprocessing_bytes[owner] == 0 &&
         !payload.empty() && payload.size() % (5 * 32) == 0);
    impl_->preprocessing_bytes[owner] = payload.size();
    impl_->record("owner-tls", "fr32le", owner, payload, "preprocessing",
                  "owner-input-preprocessing-share");
}
void CorruptServerChannel::owner_input_offset(unsigned owner,
    std::span<const unsigned char> payload) {
    need(impl_->stage == 0 && owner == impl_->next_owner && owner < 3 &&
         !payload.empty() && payload.size() % 32 == 0 &&
         impl_->preprocessing_bytes[owner] == 5 * payload.size());
    impl_->record("owner-tls", "fr32le", owner, payload, "intake",
                  "owner-input-offset");
    ++impl_->next_owner;
}
void CorruptServerChannel::mascot_message(std::span<const unsigned char> payload) {
    need(impl_->stage == 0 && impl_->next_owner == 3);
    impl_->stage = 1; impl_->record("peer", "bytes", -1, payload, "preprocessing", "mascot-message");
}
void CorruptServerChannel::mac_key_share(std::span<const unsigned char> payload) {
    need(impl_->stage == 1 && payload.size() == 32); impl_->stage = 2;
    impl_->record("local", "fr32le", -1, payload, "setup", "mac-key-share");
}
void CorruptServerChannel::authenticated_share(std::span<const unsigned char> payload) {
    need(impl_->stage == 2 && !payload.empty() && payload.size() % 32 == 0);
    impl_->stage = 3;
    impl_->record("local", "fr32le", -1, payload, "trace", "authenticated-share");
}
void CorruptServerChannel::mac_share(std::span<const unsigned char> payload) {
    need(impl_->stage == 3 && !payload.empty() && payload.size() % 32 == 0);
    impl_->stage = 4;
    impl_->record("local", "fr32le", -1, payload, "validation", "mac-share");
}
void CorruptServerChannel::randomness_share(std::span<const unsigned char> payload) {
    need(impl_->stage == 4 && !payload.empty() && payload.size() % 32 == 0);
    impl_->stage = 5;
    impl_->record("local", "fr32le", -1, payload, "trace", "randomness-share");
}
void CorruptServerChannel::randomness_mac(std::span<const unsigned char> payload) {
    need(impl_->stage == 5 && !payload.empty() && payload.size() % 32 == 0);
    impl_->stage = 6;
    impl_->record("local", "fr32le", -1, payload, "trace", "randomness-mac");
}
void CorruptServerChannel::field_opening(std::span<const unsigned char> payload) {
    need(impl_->stage == 6 && !payload.empty() && payload.size() % 32 == 0);
    impl_->stage = 7;
    impl_->record("local", "fr32le", -1, payload, "proof", "field-opening");
}
void CorruptServerChannel::authenticated_g1_state(
    unsigned group_stage, std::span<const unsigned char> payload) {
    if (group_stage == 1) {
        need(impl_->stage == 7 && payload.size() == 4 * 130);
        impl_->base_a.assign(payload.begin(), payload.begin() + 130);
        impl_->stage = 8;
    } else if (group_stage == 2) {
        need(impl_->stage == 9 && payload.size() == 6 * 130);
        impl_->stage = 10;
    } else if (group_stage == 3) {
        need(impl_->stage == 12 && payload.size() == 2 * 130);
        impl_->stage = 13;
    } else if (group_stage == 4) {
        need(impl_->stage == 13 && payload.size() == 2 * 130 &&
             impl_->base_a.size() == 130 &&
             std::equal(impl_->base_a.begin(), impl_->base_a.end(),
                        payload.begin()));
        impl_->stage = 14;
    } else {
        refuse();
    }
    impl_->staged_record("g1-share-mac", group_stage, payload,
                         "authenticated-g1-state");
}
void CorruptServerChannel::authenticated_g2_state(
    unsigned group_stage, std::span<const unsigned char> payload) {
    if (group_stage == 1) {
        need(impl_->stage == 8 && payload.size() == 258);
        impl_->base_b2.assign(payload.begin(), payload.end());
        impl_->stage = 9;
    } else if (group_stage == 4) {
        need(impl_->stage == 14 && payload.size() == 258 &&
             impl_->base_b2.size() == payload.size() &&
             std::equal(impl_->base_b2.begin(), impl_->base_b2.end(),
                        payload.begin()));
        impl_->stage = 15;
    } else {
        refuse();
    }
    impl_->staged_record("g2-share-mac", group_stage, payload,
                         "authenticated-g2-state");
}
void CorruptServerChannel::masked_field_intermediate(
    std::span<const unsigned char> payload) {
    need(impl_->stage == 10 && payload.size() == 64); impl_->stage = 11;
    impl_->record("local", "fr32le", -1, payload, "proof",
                  "masked-field-intermediate");
}
void CorruptServerChannel::masked_g1_intermediate(
    std::span<const unsigned char> payload) {
    need(impl_->stage == 11 && payload.size() == 130); impl_->stage = 12;
    impl_->record("local", "g1-65", -1, payload, "proof",
                  "masked-g1-intermediate");
}
void CorruptServerChannel::final_proof_g1(
    std::span<const unsigned char> payload) {
    need(impl_->stage == 15 && payload.size() == 130); impl_->stage = 16;
    impl_->record("local", "g1-65", -1, payload, "proof", "final-proof-g1");
}
void CorruptServerChannel::final_proof_g2(
    std::span<const unsigned char> payload) {
    need(impl_->stage == 16 && payload.size() == 129); impl_->stage = 17;
    impl_->record("local", "g2-129", -1, payload, "proof", "final-proof-g2");
}
void CorruptServerChannel::public_projection(std::span<const unsigned char> payload) {
    need(impl_->stage == 17 && payload.size() == 10685); impl_->stage = 18;
    impl_->record("local", "bytes", -1, payload, "release", "public-projection");
}
void CorruptServerChannel::close_complete() {
    need(impl_->stage == 18); impl_->writer.complete(); impl_->stage = 19;
}

struct ColluderWalletChannel::Impl {
    struct Captured { std::string stream; std::string source; std::string value; };
    Writer writer; unsigned phase{}; std::array<std::string, 3> operations;
    std::array<std::uint64_t, 3> sequences{};
    std::optional<Captured> original; std::optional<Captured> issued;
    std::optional<Captured> accepted; std::optional<Captured> incoming;
    std::optional<Captured> change; std::vector<Captured> retry_rows;
    std::set<std::string> retries;
    explicit Impl(int fd, unsigned round, const Binding& binding,
                  const std::array<std::string, 3>& stage_operations)
        : writer(fd, round, "colluder-wallet-capture", binding),
          operations(stage_operations) {
        for (const auto& operation : operations) word(operation);
        need(std::set<std::string>(operations.begin(), operations.end()).size() == 3);
        const auto meta = "{\"cohort_sha256\":" + quote(binding.cohort_sha256) +
            ",\"owner_component\":1,\"projection_sha256\":" + quote(binding.projection_sha256) +
            ",\"round\":" + std::to_string(round) +
            ",\"schema\":\"kpb-colluder-wallet-observer-capture/v1\"}\n";
        writer.meta(meta);
    }
    Captured capture(const std::string& stream, unsigned stage,
                     const std::string& value) {
        need(stage < 3);
        static const std::array<std::string, 3> names{{"invoice", "pay", "scan"}};
        const unsigned contact = stage == 1 ? (1 + writer.round()) % 3
                                            : (1 + 3 - writer.round()) % 3;
        const auto sequence = sequences[stage]++;
        const auto source = "{\"contact_binding_qualified\":false," 
            "\"contact_owner_component\":" + std::to_string(contact) +
            ",\"observed_monotonic_ns\":" + std::to_string(monotonic_ns()) +
            ",\"observer_stage\":" + quote(names[stage]) +
            ",\"operation_id_sha256\":" + quote(operations[stage]) +
            ",\"source_event_sequence\":" + std::to_string(sequence) +
            ",\"stage_sequence\":" + std::to_string(stage) + '}';
        return {stream, source, value};
    }
    void emit(const Captured& row) {
        writer.sourced_record(row.stream, row.source, row.value);
    }
};
ColluderWalletChannel::ColluderWalletChannel(int fd, unsigned round,
    const Binding& binding, const std::array<std::string, 3>& operations)
    : impl_(new Impl(fd, round, binding, operations)) {}
ColluderWalletChannel::~ColluderWalletChannel() = default;
void ColluderWalletChannel::original(const std::string& nf, std::uint64_t input_amount,
    const std::string& outgoing, std::uint64_t outgoing_amount,
    const std::string& change, std::uint64_t change_amount) {
    need(impl_->phase == 2 && input_amount && outgoing_amount && change_amount);
    word(nf); word(outgoing); word(change); need(outgoing != change); impl_->phase = 3;
    const auto value = "{\"created_outputs\":[{\"amount_sompi\":" +
        std::to_string(outgoing_amount) + ",\"kind\":\"outgoing-payment\",\"tuple_sha256\":" +
        quote(outgoing) + "},{\"amount_sompi\":" + std::to_string(change_amount) +
        ",\"kind\":\"change\",\"tuple_sha256\":" + quote(change) +
        "}],\"input_amount_sompi\":" + std::to_string(input_amount) +
        ",\"input_nf_hex32\":" + quote(nf) + '}';
    impl_->original = impl_->capture("original", 1, value);
}
void ColluderWalletChannel::issued_invoice(unsigned source, const std::string& operation, std::uint64_t amount) {
    const unsigned incoming = (1 + 3 - impl_->writer.round()) % 3;
    need(impl_->phase == 0 && source == incoming && amount); word(operation);
    need(operation == impl_->operations[0]);
    const auto value = "{\"amount_sompi\":" + std::to_string(amount) +
        ",\"direction\":\"issued\",\"operation_id_sha256\":" + quote(operation) +
        ",\"source_owner_component\":" + std::to_string(source) +
        ",\"target_owner_component\":1}";
    impl_->issued = impl_->capture("invoice", 0, value); impl_->phase = 1;
}
void ColluderWalletChannel::accepted_invoice(unsigned target, const std::string& operation, std::uint64_t amount) {
    const unsigned outgoing = (1 + impl_->writer.round()) % 3;
    need(impl_->phase == 1 && target == outgoing && amount); word(operation);
    need(operation == impl_->operations[0]);
    const auto value = "{\"amount_sompi\":" + std::to_string(amount) +
        ",\"direction\":\"accepted\",\"operation_id_sha256\":" + quote(operation) +
        ",\"source_owner_component\":1,\"target_owner_component\":" +
        std::to_string(target) + '}';
    impl_->accepted = impl_->capture("invoice", 1, value); impl_->phase = 2;
}
void ColluderWalletChannel::incoming_receipt(std::uint64_t index, unsigned creator,
    const std::string& tuple, const std::string& cm, std::uint64_t amount) {
    const unsigned incoming = (1 + 3 - impl_->writer.round()) % 3;
    need(impl_->phase == 3 && creator == incoming &&
         index == 2 * impl_->writer.round() - 1 && amount); word(tuple); word(cm);
    const auto value = "{\"amount_sompi\":" + std::to_string(amount) +
        ",\"cm_hex32\":" + quote(cm) + ",\"creator_owner_component\":" +
        std::to_string(creator) + ",\"kind\":\"incoming-payment\",\"receipt_index\":" +
        std::to_string(index) + ",\"tuple_sha256\":" + quote(tuple) + '}';
    impl_->incoming = impl_->capture("decrypted-receipt", 2, value); impl_->phase = 4;
}
void ColluderWalletChannel::change_receipt(std::uint64_t index,
    const std::string& tuple, const std::string& cm, std::uint64_t amount) {
    need(impl_->phase == 4 && index == 2 * impl_->writer.round() && amount);
    word(tuple); word(cm);
    const auto value = "{\"amount_sompi\":" + std::to_string(amount) +
        ",\"cm_hex32\":" + quote(cm) +
        ",\"creator_owner_component\":1,\"kind\":\"change\",\"receipt_index\":" +
        std::to_string(index) + ",\"tuple_sha256\":" + quote(tuple) + '}';
    impl_->change = impl_->capture("decrypted-receipt", 2, value); impl_->phase = 5;
}
void ColluderWalletChannel::retry(const std::string& attempt, std::uint64_t start,
    std::uint64_t complete, RetryOutcome outcome) {
    need(impl_->phase >= 5 && impl_->phase <= 6 && complete >= start &&
         !attempt.empty() && impl_->retries.insert(attempt).second);
    const auto value = "{\"attempt_id\":" + quote(attempt) +
        ",\"complete_monotonic_ns\":" + std::to_string(complete) +
        ",\"outcome\":" + quote(retry_outcome(outcome, false)) +
        ",\"start_monotonic_ns\":" + std::to_string(start) + '}';
    impl_->retry_rows.push_back(impl_->capture("retry", 2, value)); impl_->phase = 6;
}
void ColluderWalletChannel::close_complete() {
    need(impl_->phase >= 5 && impl_->original && impl_->issued && impl_->accepted &&
         impl_->incoming && impl_->change);
    impl_->emit(*impl_->original); impl_->emit(*impl_->issued);
    impl_->emit(*impl_->accepted); impl_->emit(*impl_->incoming);
    impl_->emit(*impl_->change);
    for (const auto& retry : impl_->retry_rows) impl_->emit(retry);
    impl_->writer.complete(); impl_->phase = 7;
}

struct TerminalChannel::Impl {
    Writer writer; unsigned event_stage{}; bool group{}; unsigned phase{};
    std::string candidate; std::map<std::string, std::string> expected_rejected;
    std::set<std::string> emitted_rejected; std::set<std::string> retry_attempts;
    std::uint64_t sequence{}; std::uint64_t prior_time{}; bool has_time{};
    explicit Impl(int fd, unsigned round, const Binding& binding)
        : writer(fd, round, "terminal-history", binding) {
        const auto meta = "{\"amount_observations\":[],\"cohort_sha256\":" +
            quote(binding.cohort_sha256) +
            ",\"mode\":\"UNFUNDED_NETWORK_DISABLED\",\"projection_sha256\":" +
            quote(binding.projection_sha256) + ",\"round\":" + std::to_string(round) +
            ",\"schema\":\"kpb-terminal-observer-history/v1\"}\n";
        writer.meta(meta);
    }
    void event(const std::string& kind, std::uint64_t time, const std::string& selected_candidate) {
        word(selected_candidate); need(!has_time || time >= prior_time);
        if (candidate.empty()) candidate = selected_candidate; else need(candidate == selected_candidate);
        const auto value = "{\"candidate_sha256\":" + quote(selected_candidate) +
            ",\"kind\":" + quote(kind) + ",\"monotonic_ns\":" + std::to_string(time) +
            ",\"outcome\":\"ok\",\"sequence\":" + std::to_string(sequence++) +
            ",\"transaction_id_hex32\":null}";
        writer.record("event", value); prior_time = time; has_time = true;
    }
};
TerminalChannel::TerminalChannel(int fd, unsigned round, const Binding& binding)
    : impl_(new Impl(fd, round, binding)) {}
TerminalChannel::~TerminalChannel() = default;
void TerminalChannel::candidate_constructed(std::uint64_t time, const std::string& candidate) {
    need(impl_->event_stage == 0); impl_->event("candidate-constructed", time, candidate); impl_->event_stage = 1;
}
void TerminalChannel::native_full(std::uint64_t time, const std::string& candidate) {
    need(impl_->event_stage == 1); impl_->event("native-full", time, candidate); impl_->event_stage = 2;
}
void TerminalChannel::trial_closed(std::uint64_t time, const std::string& candidate) {
    need(impl_->event_stage == 2); impl_->event("trial-closed", time, candidate); impl_->event_stage = 3;
}
void TerminalChannel::hidden_group(const std::string& group_id,
    const std::array<std::string, 3>& nfs, const std::array<std::string, 6>& tuples) {
    need(impl_->event_stage == 3 && !impl_->group && impl_->phase == 0); word(group_id);
    for (const auto& value : nfs) word(value);
    for (const auto& value : tuples) word(value);
    std::set<std::string> unique_nfs(nfs.begin(), nfs.end());
    std::set<std::string> unique_tuples(tuples.begin(), tuples.end());
    need(unique_nfs.size() == 3 && unique_tuples.size() == 6);
    const auto value = "{\"group_id_sha256\":" + quote(group_id) +
        ",\"nfs_hex32\":" + string_array(nfs) +
        ",\"owner_component\":null,\"tuple_sha256\":" + string_array(tuples) + '}';
    impl_->writer.record("group", value); impl_->group = true; impl_->phase = 1;
}
void TerminalChannel::retry(const std::string& attempt, RetryOutcome outcome,
    const std::string& candidate) {
    need(impl_->group && impl_->phase == 1 && !attempt.empty() &&
         impl_->retry_attempts.insert(attempt).second); word(candidate);
    const auto status = retry_outcome(outcome, true);
    if (status != "disconnected") {
        const auto inserted = impl_->expected_rejected.emplace(
            candidate, status == "refused" ? "rejected" : "orphaned");
        need(inserted.second);
    }
    const auto value = "{\"attempt_id\":" + quote(attempt) +
        ",\"candidate_sha256\":" + quote(candidate) +
        ",\"outcome\":" + quote(status) + '}';
    impl_->writer.record("retry", value);
}
void TerminalChannel::rejected_or_orphaned(const std::string& candidate,
    RejectedStatus status) {
    need(impl_->group && (impl_->phase == 1 || impl_->phase == 2)); impl_->phase = 2;
    word(candidate); const std::string name = status == RejectedStatus::Rejected ? "rejected" : "orphaned";
    need(impl_->expected_rejected.contains(candidate) &&
         impl_->expected_rejected[candidate] == name && impl_->emitted_rejected.insert(candidate).second);
    const auto value = "{\"candidate_sha256\":" + quote(candidate) +
        ",\"status\":" + quote(name) + '}';
    impl_->writer.record("rejected-or-orphaned", value);
}
void TerminalChannel::reorg(const std::string& old_head, const std::string& new_head,
    std::uint64_t depth) {
    need(impl_->group && impl_->phase <= 3 && depth > 0 && old_head != new_head &&
         impl_->emitted_rejected.size() == impl_->expected_rejected.size());
    impl_->phase = 3; word(old_head); word(new_head);
    const auto value = "{\"depth\":" + std::to_string(depth) +
        ",\"new_head_hex32\":" + quote(new_head) +
        ",\"old_head_hex32\":" + quote(old_head) + '}';
    impl_->writer.record("reorg", value);
}
void TerminalChannel::cross_round_link(const std::string& nf, unsigned output_round,
    const std::string& tuple) {
    need(impl_->group && impl_->phase <= 4 && output_round >= 1 && output_round <= 2 &&
         output_round != impl_->writer.round() &&
         impl_->emitted_rejected.size() == impl_->expected_rejected.size());
    impl_->phase = 4; word(nf); word(tuple);
    const auto value = "{\"input_round\":" + std::to_string(impl_->writer.round()) +
        ",\"nf_hex32\":" + quote(nf) + ",\"output_round\":" +
        std::to_string(output_round) +
        ",\"provenance\":\"terminal-linkage\",\"tuple_sha256\":" + quote(tuple) + '}';
    impl_->writer.record("cross-round-link", value);
}
void TerminalChannel::close_complete() {
    need(impl_->event_stage == 3 && impl_->group &&
         impl_->emitted_rejected.size() == impl_->expected_rejected.size());
    impl_->writer.complete(); impl_->phase = 5;
}

} // namespace kpb::capture::detail
