#include "auth_field.hpp"
#include <algorithm>
#include <openssl/sha.h>
#include <stdexcept>

namespace kpi::mpc {
namespace {
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
    : player_(player), public_stage_(stage), setup_(begin_setup(player, stage)),
      alpha_i_(setup_key(setup_, stage)), protocols_(begin_protocols(player, alpha_i_, stage)) {
    if (stage) stage("authenticated-protocol-set-ready");
    if (player.num_players() != 3 || !player.is_encrypted() ||
        Fr::pr() != fr_modulus() || OnlineOptions::singleton.has_option("insecure") ||
        OnlineOptions::singleton.has_option("output_mac"))
        throw std::runtime_error("requires-three-encrypted-Fr-MASCOT-parties");
}

const Fr& MascotContext::alpha_i() const {
    // The key remains local. Group code needs its MAC contribution; no export
    // or transcript serializer is supplied.
    return alpha_i_;
}

AuthScalar MascotContext::public_constant(const Fr& value) const {
    return AuthScalar::constant(value, party_id(), alpha_i());
}

AuthScalar MascotContext::random_auth() {
    return protocols_.preprocessing.get_random();
}

std::vector<AuthScalar> MascotContext::multiply_batch(
    std::span<const AuthScalar> left, std::span<const AuthScalar> right) {
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
    return result;
}

void MascotContext::check_field_pending() {
    protocols_.check();
    player_.Check_Broadcast();
}

void MascotContext::agree_public_bytes(
    const std::string& phase, std::span<const unsigned char> bytes) {
    std::vector<octetStream> frames(player_.num_players());
    frames[party_id()].store(phase);
    frames[party_id()].store(sha256_hex(bytes));
    player_.Broadcast_Receive(frames);
    for (const auto& frame : frames)
        if (frame != frames[party_id()])
            throw std::runtime_error("public-model-or-phase-disagreement");
    player_.Check_Broadcast();
}

std::vector<Fr> MascotContext::open_public_checked(
    std::span<const AuthScalar> values) {
    check_field_pending();
    std::vector<AuthScalar> selected(values.begin(), values.end());
    std::vector<Fr> opened;
    protocols_.output.POpen(opened, selected, player_);
    check_field_pending();
    return opened;
}
}  // namespace kpi::mpc
