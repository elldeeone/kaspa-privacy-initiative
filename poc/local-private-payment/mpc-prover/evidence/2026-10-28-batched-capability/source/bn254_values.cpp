#include "bn254_values.hpp"
#include <mutex>

namespace kpi::mpc {
namespace {
bool canonical_decimal(const std::string& value, const std::string& modulus) {
    return !value.empty() && (value.size() == 1 || value[0] != '0') &&
           std::all_of(value.begin(), value.end(), [](char c) { return c >= '0' && c <= '9'; }) &&
           (value.size() < modulus.size() || (value.size() == modulus.size() && value < modulus));
}
}

void initialize_bn254_groups() {
    static std::once_flag initialized;
    std::call_once(initialized, [] {
        mcl::initPairing(mcl::BN_SNARK1);
        if (mcl::Fr::getModulo() != FR_MODULUS || mcl::Fp::getModulo() != FQ_MODULUS)
            throw std::runtime_error("BN_SNARK1 parameter mismatch");
        mcl::verifyOrderG1(true);
        mcl::verifyOrderG2(true);
    });
}

mcl::Fp parse_fq(const std::string& decimal) {
    if (!canonical_decimal(decimal, FQ_MODULUS))
        throw std::invalid_argument("noncanonical Fq integer");
    mcl::Fp out;
    out.setStr(decimal, 10);
    if (!out.isValid() || out.getStr(10) != decimal)
        throw std::invalid_argument("Fq roundtrip");
    return out;
}

std::array<unsigned char, 32> fq_bytes(const mcl::Fp& value) {
    if (!value.isValid()) throw std::invalid_argument("invalid Fq");
    // GMP integer export makes byte order explicit; no mcl ETH/stream mode.
    const bigint integer(value.getStr(10));
    std::array<unsigned char, 32> out{};
    size_t written = 0;
    mpz_export(out.data(), &written, -1, 1, 0, 0, integer.get_mpz_t());
    if (written > out.size()) throw std::invalid_argument("Fq length");
    return out;
}

mcl::Fp fq_from_bytes(std::span<const unsigned char, 32> encoded) {
    bigint integer;
    mpz_import(integer.get_mpz_t(), encoded.size(), -1, 1, 0, 0, encoded.data());
    return parse_fq(integer.get_str());
}

mcl::Fr mcl_scalar(const Fr& value) {
    const auto decimal = canonical_fr(value);
    if (!canonical_decimal(decimal, FR_MODULUS))
        throw std::invalid_argument("noncanonical group scalar");
    mcl::Fr out;
    out.setStr(decimal, 10);
    if (out.getStr(10) != decimal) throw std::invalid_argument("Fr bridge");
    return out;
}

bool fq_lexicographically_largest(const mcl::Fp& value) {
    const bigint integer(value.getStr(10));
    const bigint modulus(FQ_MODULUS);
    return integer > modulus - integer;
}

bool fq2_lexicographically_largest(const mcl::Fp2& value) {
    // Arkworks' quadratic-extension ordering compares c1 before c0.
    return value.b.isZero() ? fq_lexicographically_largest(value.a)
                            : fq_lexicographically_largest(value.b);
}
}  // namespace kpi::mpc
