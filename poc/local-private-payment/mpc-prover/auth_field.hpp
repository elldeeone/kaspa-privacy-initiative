#pragma once
#include "p1_scalar_capture_manifest.hpp"
#include "p1_context_state_hook.hpp"
#include "p1_mascot_secret_state_hook.hpp"

// Exact-BN254-Fr, actively authenticated MASCOT arithmetic. No value-only
// secret type is exposed. Public parsers reject aliases before field conversion.
#ifndef NO_MIXED_CIRCUITS
#define NO_MIXED_CIRCUITS
#endif
#include "Machines/maximal.hpp"
#include <memory>
#include <span>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

#if defined(INSECURE) || defined(DEBUG_MAC) || defined(PRINT_MAC) || defined(NO_CLIENT_TLS)
#error "MASCOT proof gate refuses insecure or secret-diagnostic build flags"
#endif

namespace kpi::mpc {
namespace p1_capture { class P1TypedCaptureSeams; }

using Fr = gfp_<0, 4>;
using AuthScalar = Share<Fr>;
inline constexpr const char* FR_MODULUS =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

bigint fr_modulus();
void initialize_bn254_field();
Fr parse_fr(const std::string& canonical_decimal);
std::string canonical_fr(const Fr& value);
Fr pow_public(Fr base, const bigint& exponent);
std::string sha256_hex(std::span<const unsigned char> bytes);

class MascotContext {
public:
    using PublicStage = void (*)(const char*);
private:
    Player& player_;
    PublicStage public_stage_;
    p1_capture::P1TypedCaptureSeams* p1_capture_ = nullptr;
    std::unique_ptr<p1_private_state::MascotSecretStateHook>
        p1_mascot_secret_state_;
    std::unique_ptr<p1_private_state::ContextAndRetryStateHook>
        p1_context_state_;
    uint64_t generation_;
    uint64_t failure_epoch_ = 0;
    uint64_t check_counter_ = 0;
    bool poisoned_ = false;
    uint64_t context_transition_counter_ = 0;
    uint64_t public_phase_counter_ = 0;
    std::string last_public_phase_;
    bool context_state_constructed_ = false;
    bool context_state_available_ = true;
    std::set<std::string> validation_attempts_;
    ProtocolSetup<AuthScalar> setup_;
    Fr alpha_i_;
    ProtocolSet<AuthScalar> protocols_;
    static ProtocolSetup<AuthScalar> begin_captured_setup(
        Player&, p1_capture::P1TypedCaptureSeams&, PublicStage);
    static Fr captured_setup_key(
        const ProtocolSetup<AuthScalar>&,
        p1_capture::P1TypedCaptureSeams&, PublicStage);
    static ProtocolSetup<AuthScalar> begin_private_state_captured_setup(
        Player&, p1_capture::P1TypedCaptureSeams&,
        p1_private_state::ContextAndRetryStateHook&,
        p1_private_state::MascotSecretStateHook&, PublicStage);
    static Fr private_state_captured_setup_key(
        const ProtocolSetup<AuthScalar>&,
        p1_capture::P1TypedCaptureSeams&,
        p1_private_state::ContextAndRetryStateHook&, PublicStage);
    static ProtocolSet<AuthScalar> begin_private_state_captured_protocols(
        Player&, const Fr&, p1_capture::P1TypedCaptureSeams&,
        p1_private_state::ContextAndRetryStateHook&, PublicStage);
    static p1_private_state::ContextAndRetryStateHook&
    require_private_context_hook(
        const std::unique_ptr<
            p1_private_state::ContextAndRetryStateHook>&);
    static p1_private_state::MascotSecretStateHook&
    require_mascot_secret_hook(
        const std::unique_ptr<
            p1_private_state::MascotSecretStateHook>&);
    static uint64_t fresh_private_context_generation(
        p1_private_state::ContextAndRetryStateHook&);
    std::vector<unsigned char> private_context_snapshot() const;
    void begin_private_context_capture();
    void private_context_transition(
        p1_private_state::ContextTransition);
    void private_context_unavailable_noexcept() noexcept;

public:
    explicit MascotContext(Player& player, PublicStage public_stage = nullptr);
    MascotContext(Player& player, p1_capture::P1TypedCaptureSeams& capture,
                  PublicStage public_stage = nullptr);
    MascotContext(
        Player& player, p1_capture::P1TypedCaptureSeams& capture,
        std::unique_ptr<p1_private_state::MascotSecretStateHook>&&
            mascot_secret_state,
        std::unique_ptr<p1_private_state::ContextAndRetryStateHook>&&
            private_state,
        PublicStage public_stage = nullptr);
    ~MascotContext();
    MascotContext(const MascotContext&) = delete;
    MascotContext& operator=(const MascotContext&) = delete;
    MascotContext(MascotContext&&) = delete;
    MascotContext& operator=(MascotContext&&) = delete;

    Player& player() { require_healthy(); return player_; }
    int party_id() const { return player_.my_num(); }
    const Fr& alpha_i() const;
    ProtocolSet<AuthScalar>& protocols() { require_healthy(); return protocols_; }
    void require_healthy() const;
    void poison() noexcept;
    uint64_t generation() const { return generation_; }
    uint64_t failure_epoch() const { return failure_epoch_; }
    uint64_t check_counter() const { return check_counter_; }
    void consume_validation_attempt(const std::string& attempt);
    void report_public_phase(const char* phase);
    AuthScalar public_constant(const Fr& value) const;
    AuthScalar random_auth(p1_capture::ScalarCaptureSite);
    std::vector<AuthScalar> random_auth_batch(
        p1_capture::ScalarCaptureSite, std::size_t count);
    std::vector<AuthScalar> multiply_batch(
        p1_capture::ScalarCaptureSite,
        std::span<const AuthScalar> left,
        std::span<const AuthScalar> right);
    void check_field_pending();
    void agree_public_bytes(const std::string& phase,
                            std::span<const unsigned char> bytes);
    // Only for explicitly approved PUBLIC results such as one validity bit.
    // Never call this on a witness, scalar mask, per-row residual, or private NF.
    std::vector<Fr> open_public_checked(std::span<const AuthScalar> values);
    void attach_p1_capture(p1_capture::P1TypedCaptureSeams& capture);
    p1_capture::P1TypedCaptureSeams* p1_capture_seams() const noexcept {
        return p1_capture_;
    }
    void capture_authenticated_values(
        p1_capture::ScalarCaptureSite,
        std::span<const AuthScalar> values);
    void capture_randomness_values(
        p1_capture::ScalarCaptureSite,
        std::span<const AuthScalar> values);
    void capture_released_projection(
        std::span<const unsigned char> projection10685);
    void complete_p1_capture();
};
}  // namespace kpi::mpc
