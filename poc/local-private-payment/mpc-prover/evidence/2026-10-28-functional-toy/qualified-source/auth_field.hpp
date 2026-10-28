#pragma once

// Exact-BN254-Fr, actively authenticated MASCOT arithmetic. No value-only
// secret type is exposed. Public parsers reject aliases before field conversion.
#ifndef NO_MIXED_CIRCUITS
#define NO_MIXED_CIRCUITS
#endif
#include "Machines/maximal.hpp"
#include <span>
#include <string>
#include <vector>

#if defined(INSECURE) || defined(DEBUG_MAC) || defined(PRINT_MAC) || defined(NO_CLIENT_TLS)
#error "MASCOT proof gate refuses insecure or secret-diagnostic build flags"
#endif

namespace kpi::mpc {
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
    ProtocolSetup<AuthScalar> setup_;
    Fr alpha_i_;
    ProtocolSet<AuthScalar> protocols_;

public:
    explicit MascotContext(Player& player, PublicStage public_stage = nullptr);
    MascotContext(const MascotContext&) = delete;
    MascotContext& operator=(const MascotContext&) = delete;
    MascotContext(MascotContext&&) = delete;
    MascotContext& operator=(MascotContext&&) = delete;

    Player& player() { return player_; }
    int party_id() const { return player_.my_num(); }
    const Fr& alpha_i() const;
    ProtocolSet<AuthScalar>& protocols() { return protocols_; }
    void report_public_phase(const char* phase) const {
        if (public_stage_) public_stage_(phase);
    }
    AuthScalar public_constant(const Fr& value) const;
    AuthScalar random_auth();
    std::vector<AuthScalar> multiply_batch(std::span<const AuthScalar> left,
                                          std::span<const AuthScalar> right);
    void check_field_pending();
    void agree_public_bytes(const std::string& phase,
                            std::span<const unsigned char> bytes);
    // Only for explicitly approved PUBLIC results such as one validity bit.
    // Never call this on a witness, scalar mask, per-row residual, or private NF.
    std::vector<Fr> open_public_checked(std::span<const AuthScalar> values);
};
}  // namespace kpi::mpc
