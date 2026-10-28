#include "proof_codec.hpp"

namespace kpi::mpc {
namespace {
std::array<unsigned char, 32> encode_g1(const G1Value& point) {
    point.check();
    if (point.is_identity()) throw std::invalid_argument("proof G1 identity");
    auto normalized = point.point();
    normalized.normalize();
    auto out = fq_bytes(normalized.x);
    if (fq_lexicographically_largest(normalized.y)) out.back() |= 0x80;
    return out;
}

std::array<unsigned char, 64> encode_g2(const G2Value& point) {
    point.check();
    if (point.is_identity()) throw std::invalid_argument("proof G2 identity");
    auto normalized = point.point();
    normalized.normalize();
    const auto c0 = fq_bytes(normalized.x.a);
    const auto c1 = fq_bytes(normalized.x.b);
    std::array<unsigned char, 64> out{};
    std::copy(c0.begin(), c0.end(), out.begin());
    std::copy(c1.begin(), c1.end(), out.begin() + 32);
    if (fq2_lexicographically_largest(normalized.y)) out.back() |= 0x80;
    return out;
}

G1Value decode_g1(std::span<const unsigned char, 32> encoded) {
    if (encoded.back() & 0x40) throw std::invalid_argument("proof G1 infinity flag");
    std::array<unsigned char, 32> x_bytes{};
    std::copy(encoded.begin(), encoded.end(), x_bytes.begin());
    const bool largest = (x_bytes.back() & 0x80) != 0;
    x_bytes.back() &= 0x3f;
    const auto x = fq_from_bytes(x_bytes);
    mcl::Fp rhs, y;
    mcl::G1::getWeierstrass(rhs, x);
    if (!mcl::Fp::squareRoot(y, rhs)) throw std::invalid_argument("proof G1 nonsquare");
    if (fq_lexicographically_largest(y) != largest) y = -y;
    const auto point = G1Value::admit({false, {x.getStr(10)}, {y.getStr(10)}}, false);
    const auto roundtrip = encode_g1(point);
    if (!std::equal(roundtrip.begin(), roundtrip.end(), encoded.begin()))
        throw std::invalid_argument("proof G1 noncanonical");
    return point;
}

G2Value decode_g2(std::span<const unsigned char, 64> encoded) {
    if (encoded.back() & 0x40) throw std::invalid_argument("proof G2 infinity flag");
    std::array<unsigned char, 64> x_bytes{};
    std::copy(encoded.begin(), encoded.end(), x_bytes.begin());
    const bool largest = (x_bytes.back() & 0x80) != 0;
    x_bytes.back() &= 0x3f;
    mcl::Fp2 x, rhs, y;
    x.a = fq_from_bytes(std::span<const unsigned char, 32>(x_bytes.data(), 32));
    x.b = fq_from_bytes(std::span<const unsigned char, 32>(x_bytes.data() + 32, 32));
    mcl::G2::getWeierstrass(rhs, x);
    if (!mcl::Fp2::squareRoot(y, rhs)) throw std::invalid_argument("proof G2 nonsquare");
    if (fq2_lexicographically_largest(y) != largest) y = -y;
    const auto point = G2Value::admit({false, {x.a.getStr(10), x.b.getStr(10)},
                                     {y.a.getStr(10), y.b.getStr(10)}}, false);
    const auto roundtrip = encode_g2(point);
    if (!std::equal(roundtrip.begin(), roundtrip.end(), encoded.begin()))
        throw std::invalid_argument("proof G2 noncanonical");
    return point;
}
}

std::array<unsigned char, 128> encode_native_proof(const ProofPublic& proof) {
    const auto a = encode_g1(proof.a);
    const auto b = encode_g2(proof.b);
    const auto c = encode_g1(proof.c);
    std::array<unsigned char, 128> out{};
    std::copy(a.begin(), a.end(), out.begin());
    std::copy(b.begin(), b.end(), out.begin() + 32);
    std::copy(c.begin(), c.end(), out.begin() + 96);
    return out;
}

ProofPublic decode_native_proof(std::span<const unsigned char> encoded) {
    if (encoded.size() != 128) throw std::invalid_argument("Native128 length");
    return {decode_g1(std::span<const unsigned char, 32>(encoded.data(), 32)),
            decode_g2(std::span<const unsigned char, 64>(encoded.data() + 32, 64)),
            decode_g1(std::span<const unsigned char, 32>(encoded.data() + 96, 32))};
}

std::string proof_hex(const ProofPublic& proof) {
    static constexpr char digits[] = "0123456789abcdef";
    const auto bytes = encode_native_proof(proof);
    std::string out;
    out.reserve(256);
    for (auto byte : bytes) {
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 15]);
    }
    return out;
}
}  // namespace kpi::mpc
