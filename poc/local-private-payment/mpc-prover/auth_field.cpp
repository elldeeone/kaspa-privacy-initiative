#include "auth_field.hpp"
#include "p1_capture_seams.hpp"
#include <algorithm>
#include <atomic>
#include <limits>
#include <openssl/sha.h>
#include <stdexcept>

namespace kpi::mpc {
namespace {
uint64_t fresh_context_generation() {
    static std::atomic<uint64_t> next{1};
    auto current = next.load();
    while (true) {
        if (current == std::numeric_limits<uint64_t>::max())
            throw std::runtime_error("context-generation-exhausted");
        if (next.compare_exchange_weak(current, current + 1)) return current;
    }
}
ProtocolSetup<AuthScalar> begin_setup(Player& player, MascotContext::PublicStage stage) {
    if (stage) stage("authenticated-field-and-MAC-setup-started");
    return ProtocolSetup<AuthScalar>(fr_modulus(), player);
}

Fr setup_key(const ProtocolSetup<AuthScalar>& setup, MascotContext::PublicStage stage) {
    if (stage) stage("authenticated-field-and-MAC-setup-ready");
    return setup.get_mac_key();
}

ProtocolSet<AuthScalar> begin_protocols(Player& player, const Fr& alpha_i,
                                       MascotContext::PublicStage stage) {
    if (stage) stage("authenticated-protocol-set-started");
    return ProtocolSet<AuthScalar>(player, alpha_i);
}
}  // namespace

bigint fr_modulus() { return bigint(std::string(FR_MODULUS)); }

void initialize_bn254_field() {
    bigint::init_thread();
    const auto expected = fr_modulus();
    if (Fr::pr(true) == 0)
        Fr::init_field(expected);
    else if (Fr::pr() != expected)
        throw std::runtime_error("wrong-field-before-input");
}

Fr parse_fr(const std::string& text) {
    if (text.empty() || text.size() > 77 ||
        (text.size() > 1 && text.front() == '0') ||
        !std::all_of(text.begin(), text.end(), [](unsigned char c) {
            return c >= '0' && c <= '9';
        }))
        throw std::runtime_error("noncanonical-Fr");
    bigint value(text);
    if (value < 0 || value >= fr_modulus())
        throw std::runtime_error("Fr-alias-or-range");
    return Fr(value);
}

std::string canonical_fr(const Fr& value) {
    bigint canonical;
    to_bigint(canonical, value);
    return canonical.get_str(10);
}

Fr pow_public(Fr base, const bigint& exponent) {
    if (exponent < 0)
        throw std::runtime_error("negative-public-exponent");
    Fr result(1);
    for (size_t bit = 0; bit < mpz_sizeinbase(exponent.get_mpz_t(), 2); ++bit) {
        if (mpz_tstbit(exponent.get_mpz_t(), bit))
            result *= base;
        base *= base;
    }
    return result;
}

std::string sha256_hex(std::span<const unsigned char> bytes) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(bytes.data(), bytes.size(), digest);
    static constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(2 * SHA256_DIGEST_LENGTH);
    for (auto byte : digest) {
        output += digits[byte >> 4];
        output += digits[byte & 15];
    }
    return output;
}

MascotContext::MascotContext(Player& player, PublicStage stage)
    : player_(player), public_stage_(stage), generation_(fresh_context_generation()),
      setup_(begin_setup(player, stage)),
      alpha_i_(setup_key(setup_, stage)), protocols_(begin_protocols(player, alpha_i_, stage)) {
    if (stage) stage("authenticated-protocol-set-ready");
    if (player.num_players() != 3 || !player.is_encrypted() ||
        Fr::pr() != fr_modulus() || OnlineOptions::singleton.has_option("insecure") ||
        OnlineOptions::singleton.has_option("output_mac"))
        throw std::runtime_error("requires-three-encrypted-Fr-MASCOT-parties");
}

ProtocolSetup<AuthScalar> MascotContext::begin_captured_setup(
        Player& player, p1_capture::P1TypedCaptureSeams& capture,
        PublicStage stage) {
    try {
        if (&capture.bound_player() != &player || player.my_num() != 1 ||
            player.num_players() != 3 || !player.is_encrypted())
            throw std::runtime_error("P1-capture-context-binding");
        return begin_setup(player, stage);
    } catch (...) {
        capture.poison();
        throw;
    }
}

Fr MascotContext::captured_setup_key(
        const ProtocolSetup<AuthScalar>& setup,
        p1_capture::P1TypedCaptureSeams& capture, PublicStage stage) {
    try {
        auto key = setup_key(setup, stage);
        capture.mac_key_share(key);
        return key;
    } catch (...) {
        capture.poison();
        throw;
    }
}

ProtocolSetup<AuthScalar>
MascotContext::begin_private_state_captured_setup(
        Player& player, p1_capture::P1TypedCaptureSeams& capture,
        p1_private_state::ContextAndRetryStateHook& private_state,
        p1_private_state::MascotSecretStateHook& mascot_secret_state,
        PublicStage stage) {
    // ContextAndRetry begins only after ProtocolSetup/ProtocolSet construction.
    // The four setup-time stage callbacks (including callback throws) belong
    // to the separate ProtocolSetup state family.  Until that adapter is live,
    // whole-view completeness remains false.
    try {
        return begin_captured_setup(player, capture, stage);
    } catch (...) {
        private_state.context_unavailable_noexcept();
        mascot_secret_state.mascot_secret_unavailable_noexcept();
        throw;
    }
}

Fr MascotContext::private_state_captured_setup_key(
        const ProtocolSetup<AuthScalar>& setup,
        p1_capture::P1TypedCaptureSeams& capture,
        p1_private_state::ContextAndRetryStateHook& private_state,
        PublicStage stage) {
    try {
        return captured_setup_key(setup, capture, stage);
    } catch (...) {
        private_state.context_unavailable_noexcept();
        throw;
    }
}

ProtocolSet<AuthScalar>
MascotContext::begin_private_state_captured_protocols(
        Player& player, const Fr& alpha,
        p1_capture::P1TypedCaptureSeams& capture,
        p1_private_state::ContextAndRetryStateHook& private_state,
        PublicStage stage) {
    try {
        return begin_protocols(player, alpha, stage);
    } catch (...) {
        capture.poison();
        private_state.context_unavailable_noexcept();
        throw;
    }
}

p1_private_state::ContextAndRetryStateHook&
MascotContext::require_private_context_hook(
        const std::unique_ptr<
            p1_private_state::ContextAndRetryStateHook>& hook) {
    if (!hook)
        throw std::runtime_error("P1-context-state-hook-absent");
    return *hook;
}

p1_private_state::MascotSecretStateHook&
MascotContext::require_mascot_secret_hook(
        const std::unique_ptr<
            p1_private_state::MascotSecretStateHook>& hook) {
    if (!hook)
        throw std::runtime_error("P1-MASCOT-secret-state-hook-absent");
    return *hook;
}

uint64_t MascotContext::fresh_private_context_generation(
        p1_private_state::ContextAndRetryStateHook& hook) {
    try {
        return fresh_context_generation();
    } catch (...) {
        hook.context_unavailable_noexcept();
        throw;
    }
}

MascotContext::MascotContext(
        Player& player, p1_capture::P1TypedCaptureSeams& capture,
        PublicStage stage)
    : player_(player), public_stage_(stage), p1_capture_(&capture),
      generation_(fresh_context_generation()),
      setup_(begin_captured_setup(player, capture, stage)),
      alpha_i_(captured_setup_key(setup_, capture, stage)),
      protocols_(begin_protocols(player, alpha_i_, stage)) {
    if (stage) stage("authenticated-protocol-set-ready");
    if (player.num_players() != 3 || !player.is_encrypted() ||
        Fr::pr() != fr_modulus() ||
        OnlineOptions::singleton.has_option("insecure") ||
        OnlineOptions::singleton.has_option("output_mac")) {
        capture.poison();
        throw std::runtime_error(
            "requires-three-encrypted-Fr-MASCOT-parties");
    }
}

MascotContext::MascotContext(
        Player& player, p1_capture::P1TypedCaptureSeams& capture,
        std::unique_ptr<p1_private_state::MascotSecretStateHook>&&
            mascot_secret_state,
        std::unique_ptr<p1_private_state::ContextAndRetryStateHook>&&
            private_state,
        PublicStage stage)
    : player_(player), public_stage_(stage), p1_capture_(&capture),
      p1_mascot_secret_state_(std::move(mascot_secret_state)),
      p1_context_state_(std::move(private_state)),
      generation_(fresh_private_context_generation(
          require_private_context_hook(p1_context_state_))),
      setup_(begin_private_state_captured_setup(
          player, capture, require_private_context_hook(p1_context_state_),
          require_mascot_secret_hook(p1_mascot_secret_state_), stage)),
      alpha_i_(private_state_captured_setup_key(
          setup_, capture, require_private_context_hook(p1_context_state_),
          stage)),
      protocols_(begin_private_state_captured_protocols(
          player, alpha_i_, capture,
          require_private_context_hook(p1_context_state_), stage)) {
    try {
        if (stage) stage("authenticated-protocol-set-ready");
        if (player.num_players() != 3 || player.my_num() != 1 ||
            !player.is_encrypted() ||
            &capture.bound_player() != &player ||
            Fr::pr() != fr_modulus() ||
            OnlineOptions::singleton.has_option("insecure") ||
            OnlineOptions::singleton.has_option("output_mac"))
            throw std::runtime_error(
                "requires-captured-P1-three-encrypted-Fr-MASCOT-parties");
        begin_private_context_capture();
    } catch (...) {
        private_context_unavailable_noexcept();
        capture.poison();
        throw;
    }
}

MascotContext::~MascotContext() {
    if (p1_context_state_ != nullptr && context_state_constructed_ &&
        context_state_available_) {
        try {
            const auto snapshot = private_context_snapshot();
            p1_context_state_->context_terminal(snapshot);
            context_state_constructed_ = false;
        } catch (...) {
            private_context_unavailable_noexcept();
        }
    }
}

std::vector<unsigned char> MascotContext::private_context_snapshot() const {
    if (!p1_context_state_)
        throw std::runtime_error("P1-context-state-hook-absent");
    return p1_private_state::encode_context_and_retry_snapshot({
        .party_id = static_cast<std::uint64_t>(player_.my_num()),
        .player_count = static_cast<std::uint64_t>(player_.num_players()),
        .generation = generation_,
        .failure_epoch = failure_epoch_,
        .check_counter = check_counter_,
        .transition_counter = context_transition_counter_,
        .public_phase_counter = public_phase_counter_,
        .poisoned = poisoned_,
        .encrypted_player = player_.is_encrypted(),
        .transcript_capture_attached = p1_capture_ != nullptr,
        .private_state_hook_attached = bool(p1_context_state_),
        .public_stage_callback_attached = public_stage_ != nullptr,
        .last_public_phase = last_public_phase_,
        .validation_attempts = validation_attempts_,
    });
}

void MascotContext::private_context_unavailable_noexcept() noexcept {
    if (!p1_context_state_ || !context_state_available_) return;
    context_state_available_ = false;
    p1_context_state_->context_unavailable_noexcept();
}

void MascotContext::begin_private_context_capture() {
    if (!p1_context_state_ || context_state_constructed_ ||
        !context_state_available_)
        throw std::runtime_error("P1-context-state-begin-order");
    try {
        const auto snapshot = private_context_snapshot();
        p1_context_state_->context_constructed(snapshot);
        context_state_constructed_ = true;
    } catch (...) {
        private_context_unavailable_noexcept();
        throw;
    }
}

void MascotContext::private_context_transition(
        p1_private_state::ContextTransition transition) {
    if (!p1_context_state_) return;
    if (!context_state_constructed_ || !context_state_available_ ||
        context_transition_counter_ ==
            std::numeric_limits<std::uint64_t>::max()) {
        private_context_unavailable_noexcept();
        throw std::runtime_error("P1-context-state-transition-order");
    }
    const auto before = context_transition_counter_;
    ++context_transition_counter_;
    try {
        const auto snapshot = private_context_snapshot();
        p1_context_state_->context_transition(
            transition, before, context_transition_counter_, snapshot);
    } catch (...) {
        private_context_unavailable_noexcept();
        throw;
    }
}

void MascotContext::require_healthy() const {
    if (poisoned_) throw std::runtime_error("MASCOT-context-poisoned");
}

void MascotContext::poison() noexcept {
    if (!poisoned_) {
        poisoned_ = true;
        if (failure_epoch_ == std::numeric_limits<uint64_t>::max())
            private_context_unavailable_noexcept();
        else
            ++failure_epoch_;
        if (p1_context_state_ && context_state_constructed_ &&
            context_state_available_) {
            try {
                private_context_transition(
                    p1_private_state::ContextTransition::Poison);
            } catch (...) {}
        }
        if (p1_capture_) p1_capture_->poison();
    }
}

void MascotContext::consume_validation_attempt(const std::string& attempt) {
    require_healthy();
    try {
        if (attempt.empty() || attempt.size() > 1024 ||
            attempt.find('\0') != std::string::npos ||
            !validation_attempts_.insert(attempt).second)
            throw std::runtime_error("validation-attempt-already-consumed");
        private_context_transition(
            p1_private_state::ContextTransition::Retry);
    } catch (...) { poison(); throw; }
}

void MascotContext::report_public_phase(const char* phase) {
    require_healthy();
    try {
        if (phase == nullptr ||
            public_phase_counter_ ==
                std::numeric_limits<std::uint64_t>::max())
            throw std::runtime_error("invalid-public-phase");
        std::size_t length = 0;
        while (length <= 1024 && phase[length] != '\0') ++length;
        if (length == 0 || length > 1024)
            throw std::runtime_error("invalid-public-phase");
        last_public_phase_.assign(phase, length);
        ++public_phase_counter_;
        private_context_transition(
            p1_private_state::ContextTransition::Validate);
        // Retain the exact phase entry before invoking an optional callback;
        // if that callback throws, the subsequent Poison transition records
        // the abort from this already-entered phase.
        if (public_stage_) public_stage_(phase);
    } catch (...) { poison(); throw; }
}

const Fr& MascotContext::alpha_i() const {
    // The key remains local. Group code needs its MAC contribution; no export
    // or transcript serializer is supplied.
    return alpha_i_;
}

AuthScalar MascotContext::public_constant(const Fr& value) const {
    return AuthScalar::constant(value, party_id(), alpha_i());
}

AuthScalar MascotContext::random_auth(
        p1_capture::ScalarCaptureSite site) {
    if (p1_capture::scalar_capture_kind(site) !=
        p1_capture::ScalarCaptureKind::Randomness)
        throw std::runtime_error("randomness-scalar-capture-site-kind");
    auto values = random_auth_batch(site, 1);
    return std::move(values[0]);
}

std::vector<AuthScalar> MascotContext::random_auth_batch(
        p1_capture::ScalarCaptureSite site, std::size_t count) {
    require_healthy();
    try {
        if (p1_capture::scalar_capture_kind(site) !=
            p1_capture::ScalarCaptureKind::Randomness)
            throw std::runtime_error("randomness-scalar-capture-site-kind");
        std::vector<AuthScalar> result;
        result.reserve(count);
        for (std::size_t index = 0; index < count; ++index)
            result.push_back(protocols_.preprocessing.get_random());
        if (p1_capture_) p1_capture_->randomness_values(site, result);
        return result;
    }
    catch (...) { poison(); throw; }
}

std::vector<AuthScalar> MascotContext::multiply_batch(
    p1_capture::ScalarCaptureSite site,
    std::span<const AuthScalar> left, std::span<const AuthScalar> right) {
    require_healthy();
    try {
    if (p1_capture::scalar_capture_kind(site) !=
        p1_capture::ScalarCaptureKind::Authenticated)
        throw std::runtime_error("authenticated-scalar-capture-site-kind");
    if (left.size() != right.size())
        throw std::runtime_error("authenticated-multiplication-arity");
    if (left.empty())
        return {};
    auto& protocol = protocols_.protocol;
    protocol.init_mul();
    for (size_t i = 0; i < left.size(); ++i)
        protocol.prepare_mul(left[i], right[i]);
    protocol.exchange();
    std::vector<AuthScalar> result;
    result.reserve(left.size());
    for (size_t i = 0; i < left.size(); ++i)
        result.emplace_back(protocol.finalize_mul());
    if (p1_capture_) p1_capture_->authenticated_values(site, result);
    return result;
    } catch (...) { poison(); throw; }
}

void MascotContext::check_field_pending() {
    require_healthy();
    try {
        protocols_.check();
        player_.Check_Broadcast();
        if (check_counter_ == std::numeric_limits<uint64_t>::max())
            throw std::runtime_error("MASCOT-check-counter-exhausted");
        ++check_counter_;
        private_context_transition(
            p1_private_state::ContextTransition::Validate);
    } catch (...) { poison(); throw; }
}

void MascotContext::agree_public_bytes(
    const std::string& phase, std::span<const unsigned char> bytes) {
    require_healthy();
    try {
    std::vector<octetStream> frames(player_.num_players());
    frames[party_id()].store(phase);
    frames[party_id()].store(sha256_hex(bytes));
    player_.Broadcast_Receive(frames);
    for (const auto& frame : frames)
        if (frame != frames[party_id()])
            throw std::runtime_error("public-model-or-phase-disagreement");
    player_.Check_Broadcast();
    } catch (...) { poison(); throw; }
}

std::vector<Fr> MascotContext::open_public_checked(
        std::span<const AuthScalar> values) {
    require_healthy();
    try {
    check_field_pending();
    std::vector<AuthScalar> selected(values.begin(), values.end());
    std::vector<Fr> opened;
    protocols_.output.POpen(opened, selected, player_);
    check_field_pending();
    if (p1_capture_) p1_capture_->field_openings(opened);
    return opened;
    } catch (...) { poison(); throw; }
}

void MascotContext::attach_p1_capture(
        p1_capture::P1TypedCaptureSeams& capture) {
    require_healthy();
    try {
        if (p1_capture_ != nullptr || &capture.bound_player() != &player_ ||
            party_id() != 1 || player_.num_players() != 3 ||
            !player_.is_encrypted())
            throw std::runtime_error("P1-capture-context-binding");
        p1_capture_ = &capture;
    } catch (...) { capture.poison(); poison(); throw; }
}

void MascotContext::capture_authenticated_values(
        p1_capture::ScalarCaptureSite site,
        std::span<const AuthScalar> values) {
    require_healthy();
    try {
        if (p1_capture::scalar_capture_kind(site) !=
            p1_capture::ScalarCaptureKind::Authenticated)
            throw std::runtime_error("authenticated-scalar-capture-site-kind");
        if (p1_capture_) p1_capture_->authenticated_values(site, values);
    } catch (...) { poison(); throw; }
}

void MascotContext::capture_randomness_values(
        p1_capture::ScalarCaptureSite site,
        std::span<const AuthScalar> values) {
    require_healthy();
    try {
        if (p1_capture::scalar_capture_kind(site) !=
            p1_capture::ScalarCaptureKind::Randomness)
            throw std::runtime_error("randomness-scalar-capture-site-kind");
        if (p1_capture_) p1_capture_->randomness_values(site, values);
    } catch (...) { poison(); throw; }
}

void MascotContext::capture_released_projection(
        std::span<const unsigned char> projection) {
    require_healthy();
    try {
        if (p1_capture_) p1_capture_->released_projection(projection);
    } catch (...) { poison(); throw; }
}

void MascotContext::complete_p1_capture() {
    require_healthy();
    try {
        if (p1_capture_) p1_capture_->close_complete();
    } catch (...) { poison(); throw; }
}
}  // namespace kpi::mpc
