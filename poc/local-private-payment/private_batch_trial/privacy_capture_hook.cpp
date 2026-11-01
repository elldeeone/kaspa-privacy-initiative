#include "privacy_capture_hook.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <pthread.h>
#include <openssl/sha.h>
#include <signal.h>
#include <stdexcept>
#include <string_view>
#include <time.h>
#include <unistd.h>

namespace kpb::capture {
namespace {

constexpr std::array<unsigned char, 8> MAGIC{
    'K', 'P', 'B', 'C', 'E', 'V', '0', '1'};
constexpr std::size_t MAX_FRAME_BYTES = 1U << 20;

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
         (value[19] == '8' || value[19] == '9' ||
          value[19] == 'a' || value[19] == 'b'));
}

void binding(const Binding& value) {
    uuid(value.attempt_id); word(value.cohort_sha256);
    word(value.financial_run_id); uuid(value.capture_identity);
    word(value.projection_sha256);
    need(value.construction_classification == 1 ||
         value.construction_classification == 2);
    word(value.construction_attempt_sha256);
    word(value.capture_plan_sha256);
}

void binding(const RunBinding& value) {
    uuid(value.attempt_id); word(value.cohort_sha256);
    word(value.financial_run_id); uuid(value.capture_identity);
    need(value.construction_classification == 1 ||
         value.construction_classification == 2);
    word(value.construction_attempt_sha256);
    word(value.capture_plan_sha256);
}

std::span<const unsigned char> bytes(const std::string& value) {
    return {reinterpret_cast<const unsigned char*>(value.data()),
            value.size()};
}

std::string quote(const std::string& value) {
    need(!value.empty() &&
         std::all_of(value.begin(), value.end(), [](char c) {
             return (c >= 'A' && c <= 'Z') ||
                    (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '_' || c == '.' ||
                    c == '-';
         }));
    return '"' + value + '"';
}

std::string optional(const std::string& value) {
    return value.empty() ? "null" : quote(value);
}

void append(std::vector<unsigned char>& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}

void append_u64(std::vector<unsigned char>& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

unsigned char nibble(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    refuse();
}

void append_digest(std::vector<unsigned char>& out, const std::string& value) {
    word(value);
    for (std::size_t index = 0; index < value.size(); index += 2)
        out.push_back(static_cast<unsigned char>(
            (nibble(value[index]) << 4) | nibble(value[index + 1])));
}

std::string hex(std::span<const unsigned char> value) {
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string result(value.size() * 2, '0');
    for (std::size_t index = 0; index < value.size(); ++index) {
        result[2 * index] = alphabet[value[index] >> 4];
        result[2 * index + 1] = alphabet[value[index] & 15];
    }
    return result;
}

void validate_explicit_effects(const ExplicitOwnerPublicEffects& value) {
    word(value.run_sha256); word(value.trial_sha256);
    word(value.attempt_sha256); word(value.cohort_sha256);
    word(value.capture_plan_sha256); word(value.projection_sha256);
    word(value.context_sha256);
    for (unsigned owner = 0; owner < value.owners.size(); ++owner) {
        const auto& row = value.owners[owner];
        need(row.owner_component == owner);
        word(row.owner_contract_sha256); word(row.nf_hex32);
        word(row.tuple_sha256[0]);
        word(row.tuple_sha256[1]);
        need(row.tuple_sha256[0] < row.tuple_sha256[1]);
    }
}

std::vector<unsigned char> explicit_preimage(
        unsigned round, const RunBinding& binding,
        const std::string& projection,
        const ExplicitOwnerPublicEffects& value) {
    validate_explicit_effects(value);
    std::vector<unsigned char> result;
    constexpr std::string_view label =
        "KPB_EXPLICIT_OWNER_PUBLIC_EFFECTS_CAPTURE_V1\n";
    result.reserve(693);
    append(result, label); append_u64(result, 2); append_u64(result, round);
    for (const auto* field : {
             &value.run_sha256, &value.trial_sha256,
             &value.attempt_sha256, &value.cohort_sha256,
             &value.capture_plan_sha256, &value.projection_sha256,
             &value.context_sha256})
        append_digest(result, *field);
    for (const auto& row : value.owners) {
        append_u64(result, row.owner_component);
        append_digest(result, row.owner_contract_sha256);
        append_digest(result, row.nf_hex32);
        append_digest(result, row.tuple_sha256[0]);
        append_digest(result, row.tuple_sha256[1]);
    }
    need(value.run_sha256 == binding.financial_run_id &&
         value.attempt_sha256 == binding.construction_attempt_sha256 &&
         value.cohort_sha256 == binding.cohort_sha256 &&
         value.capture_plan_sha256 == binding.capture_plan_sha256 &&
         value.projection_sha256 == projection && result.size() == 693);
    return result;
}

std::string explicit_exports(const ExplicitOwnerPublicEffects& value) {
    std::string result = "[";
    for (std::size_t index = 0; index < value.owners.size(); ++index) {
        if (index != 0) result += ',';
        const auto& row = value.owners[index];
        result += "{\"attempt_sha256\":" + quote(value.attempt_sha256) +
            ",\"capture_plan_sha256\":" +
            quote(value.capture_plan_sha256) +
            ",\"cohort_sha256\":" + quote(value.cohort_sha256) +
            ",\"context_sha256\":" + quote(value.context_sha256) +
            ",\"nf_hex32\":" + quote(row.nf_hex32) +
            ",\"owner_component\":" +
            std::to_string(row.owner_component) +
            ",\"owner_contract_sha256\":" +
            quote(row.owner_contract_sha256) +
            ",\"projection_sha256\":" +
            quote(value.projection_sha256) +
            ",\"run_sha256\":" + quote(value.run_sha256) +
            ",\"trial_sha256\":" + quote(value.trial_sha256) +
            ",\"tuple_sha256\":[" + quote(row.tuple_sha256[0]) +
            "," + quote(row.tuple_sha256[1]) + "]}";
    }
    return result + "]";
}

unsigned classification_for(ReleasePolicy policy) {
    if (policy == ReleasePolicy::SecretPermutationIndependent) return 1;
    if (policy == ReleasePolicy::ExplicitOwnerPublicEffects) return 2;
    refuse();
}

unsigned policy_code(ReleasePolicy policy) {
    if (policy == ReleasePolicy::SecretPermutationIndependent) return 1;
    if (policy == ReleasePolicy::ExplicitOwnerPublicEffects) return 2;
    refuse();
}

std::vector<unsigned char> release_policy_preimage(
        unsigned round, ReleasePolicy policy, const RunBinding& binding,
        const std::string& projection,
        const std::string& explicit_event_sha256) {
    constexpr std::string_view label =
        "KPB_DISPATCHER_RELEASE_POLICY_BINDING_V1\n";
    std::vector<unsigned char> result;
    result.reserve(265);
    append(result, label);
    append_u64(result, classification_for(policy));
    append_u64(result, policy_code(policy));
    append_u64(result, round);
    append_u64(result,
               policy == ReleasePolicy::ExplicitOwnerPublicEffects ? 3 : 0);
    for (const auto* field : {
             &binding.financial_run_id,
             &binding.construction_attempt_sha256,
             &binding.cohort_sha256,
             &binding.capture_plan_sha256,
             &projection})
        append_digest(result, *field);
    if (policy == ReleasePolicy::ExplicitOwnerPublicEffects) {
        append_digest(result, explicit_event_sha256);
    } else {
        need(explicit_event_sha256.empty());
        result.insert(result.end(), 32, 0);
    }
    need(binding.construction_classification == classification_for(policy) &&
         result.size() == 265);
    return result;
}

class SigpipeBlock final {
public:
    SigpipeBlock() {
        sigemptyset(&set_); sigaddset(&set_, SIGPIPE);
        need(pthread_sigmask(SIG_BLOCK, &set_, &old_) == 0);
        old_blocked_ = sigismember(&old_, SIGPIPE) == 1;
    }
    SigpipeBlock(const SigpipeBlock&) = delete;
    SigpipeBlock& operator=(const SigpipeBlock&) = delete;
    ~SigpipeBlock() { (void)pthread_sigmask(SIG_SETMASK, &old_, nullptr); }
    void consume_new_sigpipe() {
        if (old_blocked_) return;
        timespec zero{}; siginfo_t information{};
        while (sigtimedwait(&set_, &information, &zero) < 0 &&
               errno == EINTR) {}
    }
private:
    sigset_t set_{};
    sigset_t old_{};
    bool old_blocked_{};
};

void write_all(int fd, std::span<const unsigned char> value) {
    SigpipeBlock guard;
    std::size_t at = 0;
    while (at < value.size()) {
        const auto count = ::write(fd, value.data() + at, value.size() - at);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            if (errno == EPIPE) guard.consume_new_sigpipe();
            refuse();
        }
        at += static_cast<std::size_t>(count);
    }
}

void close_fatal(int& fd) {
    need(fd >= 0); const int selected = fd; fd = -1;
    need(::close(selected) == 0);
}

void close_noexcept(int& fd) noexcept {
    if (fd >= 0) { const int selected = fd; fd = -1; (void)::close(selected); }
}

void frame(int& fd, unsigned char tag,
           std::span<const unsigned char> payload) {
    need(fd >= 0 && tag >= 1 && tag <= 5 &&
         payload.size() <= MAX_FRAME_BYTES);
    std::array<unsigned char, 17> header{};
    std::copy(MAGIC.begin(), MAGIC.end(), header.begin()); header[8] = tag;
    std::uint64_t size = payload.size();
    for (unsigned index = 0; index < 8; ++index)
        header[9 + index] = static_cast<unsigned char>(
            size >> (8 * (7 - index)));
    try { write_all(fd, header); write_all(fd, payload); }
    catch (...) { close_noexcept(fd); throw; }
}

std::string hello(unsigned round, const std::string& kind,
                  const RunBinding& value) {
    need(round == 1 || round == 2);
    return "{\"attempt_id\":" + quote(value.attempt_id) +
        ",\"capture_identity\":" + quote(value.capture_identity) +
        ",\"cohort_sha256\":" + quote(value.cohort_sha256) +
        ",\"financial_run_id\":" + quote(value.financial_run_id) +
        ",\"kind\":" + quote(kind) +
        ",\"round\":" + std::to_string(round) +
        ",\"schema\":\"kpb-capture-event-channel/v1\"}\n";
}

RunBinding run_binding(const Binding& value) {
    return {value.attempt_id, value.cohort_sha256, value.financial_run_id,
            value.capture_identity, value.construction_classification,
            value.construction_attempt_sha256,
            value.capture_plan_sha256};
}

} // namespace

const char* CaptureRefused::what() const noexcept {
    return "KPB_CAPTURE_HOOK_REFUSED";
}

namespace detail {

ProjectionChannel::ProjectionChannel(int fd, unsigned round,
                                     const Binding& selected)
    : fd_(fd) {
    try {
        need(fd_ >= 0); binding(selected);
        const auto value = hello(round, "public-projection",
                                 run_binding(selected));
        frame(1, bytes(value));
    } catch (...) { close_noexcept(fd_); throw; }
}

ProjectionChannel::~ProjectionChannel() { close_noexcept(fd_); }

void ProjectionChannel::frame(unsigned char tag,
                              std::span<const unsigned char> payload) {
    ::kpb::capture::frame(fd_, tag, payload);
}

void ProjectionChannel::close_complete() {
    need(!complete_ && fd_ >= 0); frame(5, {}); close_fatal(fd_);
    complete_ = true;
}

void ProjectionChannel::write_and_close(
        std::span<const unsigned char> projection) {
    need(!complete_ && projection.size() == 10685);
    frame(4, projection); close_complete();
}

DispatcherChannel::DispatcherChannel(int fd, unsigned round,
                                     ReleasePolicy policy,
                                     const Binding& selected)
    : DispatcherChannel(fd, round, policy, run_binding(selected)) {
    try {
        binding(selected);
        projection_sha256_ = selected.projection_sha256;
    } catch (...) { close_noexcept(fd_); throw; }
}

DispatcherChannel::DispatcherChannel(int fd, unsigned round,
                                     ReleasePolicy policy,
                                     const RunBinding& selected)
    : fd_(fd), round_(round), policy_(policy), binding_(selected) {
    try {
        need(fd_ >= 0 && (round_ == 1 || round_ == 2) &&
             policy_ != ReleasePolicy::UploadOrderPublicEffects &&
             binding_.construction_classification ==
                 classification_for(policy_));
        binding(binding_);
        const auto first = hello(round_, "dispatcher-capture", binding_);
        frame(1, bytes(first));
    } catch (...) { close_noexcept(fd_); throw; }
}

DispatcherChannel::~DispatcherChannel() { close_noexcept(fd_); }

void DispatcherChannel::frame(unsigned char tag,
                              std::span<const unsigned char> payload) {
    ::kpb::capture::frame(fd_, tag, payload);
}

void DispatcherChannel::emit_metadata() {
    need(!metadata_emitted_ && !projection_sha256_.empty() &&
         policy_bound_ &&
         (policy_ != ReleasePolicy::ExplicitOwnerPublicEffects ||
          explicit_effects_));
    const std::string policy_name =
        policy_ == ReleasePolicy::SecretPermutationIndependent
        ? "SECRET_PERMUTATION_INDEPENDENT"
        : policy_ == ReleasePolicy::UploadOrderPublicEffects
        ? "UPLOAD_ORDER_PUBLIC_EFFECTS"
        : "EXPLICIT_OWNER_PUBLIC_EFFECTS";
    const auto exports = policy_ == ReleasePolicy::ExplicitOwnerPublicEffects
        ? explicit_exports(effects_) : "[]";
    const auto meta = "{\"capture_plan_sha256\":" +
        quote(binding_.capture_plan_sha256) +
        ",\"cohort_sha256\":" + quote(binding_.cohort_sha256) +
        ",\"construction_attempt_sha256\":" +
        quote(binding_.construction_attempt_sha256) +
        ",\"construction_classification\":" +
        std::to_string(binding_.construction_classification) +
        ",\"direct_exports\":" + exports +
        ",\"projection_sha256\":" +
        quote(projection_sha256_) +
        ",\"release_order_policy\":" + quote(policy_name) +
        ",\"round\":" + std::to_string(round_) +
        ",\"run_sha256\":" + quote(binding_.financial_run_id) +
        ",\"schema\":\"kpb-dispatcher-observer-capture/v1\"}\n";
    frame(2, bytes(meta));
    for (const auto& value : pending_records_) frame(3, bytes(value));
    pending_records_.clear();
    metadata_emitted_ = true;
}

void DispatcherChannel::record(const std::string& value) {
    if (!metadata_emitted_) {
        // The ordinary path buffers one listener plus three connections and
        // three completed uploads. The explicit baseline additionally buffers
        // aggregate-release, its one public-effects event, and the typed
        // release-policy binding until metadata is sealed. These are bounded
        // metadata, never private owner/P1 bodies.
        need(pending_records_.size() < 10);
        pending_records_.push_back(value);
    } else {
        frame(3, bytes(value));
    }
}

void DispatcherChannel::bind_projection(
        const std::string& projection_sha256) {
    need(!complete_ && projection_sha256_.empty() &&
         listeners_ && !aggregate_ &&
         std::all_of(uploaded_.begin(), uploaded_.end(),
                     [](bool value) { return value; }));
    word(projection_sha256);
    projection_sha256_ = projection_sha256;
}

void DispatcherChannel::event(const std::string& kind, int owner,
                              const std::string& role,
                              std::uint64_t monotonic_ns,
                              std::uint64_t byte_count,
                              const std::string& filename,
                              const std::string& public_sha256,
                              const std::string& route_sha256) {
    need(!complete_ && fd_ >= 0 &&
         (!has_time_ || monotonic_ns >= prior_time_));
    if (!public_sha256.empty()) word(public_sha256);
    if (!route_sha256.empty()) word(route_sha256);
    const auto owner_json = owner < 0 ? std::string("null")
                                      : std::to_string(owner);
    const auto value = "{\"stream\":\"event\",\"value\":{"
        "\"bytes\":" + std::to_string(byte_count) +
        ",\"filename\":" + optional(filename) +
        ",\"kind\":" + quote(kind) +
        ",\"monotonic_ns\":" + std::to_string(monotonic_ns) +
        ",\"outcome\":\"ok\",\"owner_component\":" + owner_json +
        ",\"public_sha256\":" + optional(public_sha256) +
        ",\"role\":" + quote(role) +
        ",\"route_sha256\":" + optional(route_sha256) +
        ",\"sequence\":" + std::to_string(sequence_) + "}}\n";
    record(value); ++sequence_; prior_time_ = monotonic_ns;
    has_time_ = true;
}

void DispatcherChannel::bind_release_policy(std::uint64_t time) {
    need(aggregate_ && !policy_bound_ && !projection_sha256_.empty() &&
         (policy_ != ReleasePolicy::ExplicitOwnerPublicEffects ||
          (explicit_effects_ && !explicit_event_sha256_.empty())));
    const auto preimage = release_policy_preimage(
        round_, policy_, binding_, projection_sha256_,
        explicit_event_sha256_);
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    need(SHA256(preimage.data(), preimage.size(), digest.data()) != nullptr);
    policy_bound_ = true;
    event("release-policy-bound", -1, "controller", time,
          preimage.size(), "RELEASE-ORDER-POLICY-V1.bin",
          hex(digest), "");
}

void DispatcherChannel::listeners_ready(std::uint64_t time) {
    need(!listeners_ && sequence_ == 0); listeners_ = true;
    event("listeners-ready", -1, "server-roster", time, 0, "", "", "");
}

void DispatcherChannel::owner_connected(unsigned owner,
                                        std::uint64_t time) {
    need(listeners_ && !aggregate_ && owner < connected_.size() &&
         !connected_[owner]); connected_[owner] = true;
    event("owner-connected", static_cast<int>(owner),
          "C" + std::to_string(owner), time, 0, "", "", "");
}

void DispatcherChannel::owner_upload_complete(unsigned owner,
                                              std::uint64_t time,
                                              std::uint64_t byte_count) {
    need(listeners_ && !aggregate_ && owner < uploaded_.size() &&
         connected_[owner] && !uploaded_[owner] && byte_count > 0);
    uploaded_[owner] = true;
    event("owner-upload-complete", static_cast<int>(owner),
          "C" + std::to_string(owner), time, byte_count,
          "OWNER-PRIVATE-INPUT-V2.bin", "", "");
}

void DispatcherChannel::aggregate_release(std::uint64_t time) {
    need(listeners_ && !aggregate_ && !projection_sha256_.empty() &&
         std::all_of(uploaded_.begin(), uploaded_.end(),
                     [](bool value) { return value; }));
    aggregate_ = true;
    event("aggregate-release", -1, "controller", time, 10685,
          "released-projection.bin", projection_sha256_, "");
    if (policy_ == ReleasePolicy::SecretPermutationIndependent) {
        bind_release_policy(time);
        emit_metadata();
    }
}

void DispatcherChannel::explicit_owner_public_effects(
        std::uint64_t time, const ExplicitOwnerPublicEffects& effects) {
    need(policy_ == ReleasePolicy::ExplicitOwnerPublicEffects && aggregate_ &&
         !explicit_effects_ && outbound_ == 0 && !metadata_emitted_ &&
         !projection_sha256_.empty());
    validate_explicit_effects(effects);
    const auto preimage = explicit_preimage(
        round_, binding_, projection_sha256_, effects);
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    need(SHA256(preimage.data(), preimage.size(), digest.data()) != nullptr);
    effects_ = effects;
    explicit_effects_ = true;
    explicit_event_sha256_ = hex(digest);
    event("explicit-owner-public-effects", -1, "controller", time,
          preimage.size(), "EXPLICIT-OWNER-PUBLIC-EFFECTS-V1.bin",
          explicit_event_sha256_, "");
    bind_release_policy(time);
    emit_metadata();
}

void DispatcherChannel::outbound_route(
        std::uint64_t time, const std::string& route_sha256) {
    need(aggregate_ && outbound_ == 0 && metadata_emitted_ && policy_bound_ &&
         (policy_ != ReleasePolicy::ExplicitOwnerPublicEffects ||
          explicit_effects_));
    word(route_sha256); ++outbound_;
    event("outbound-route", -1, "controller", time, 10685,
          "released-projection.bin", projection_sha256_,
          route_sha256);
}

void DispatcherChannel::close_complete() {
    need(!complete_ && aggregate_ && outbound_ == 1 && metadata_emitted_ &&
         policy_bound_ &&
         (policy_ != ReleasePolicy::ExplicitOwnerPublicEffects ||
          explicit_effects_));
    frame(5, {});
    close_fatal(fd_); complete_ = true;
}

} // namespace detail
} // namespace kpb::capture
