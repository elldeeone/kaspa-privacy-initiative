#pragma once
#include "bn254_values.hpp"

namespace kpi::mpc {
struct ProofPublic {
    G1Value a;
    G2Value b;
    G1Value c;
};

std::array<unsigned char, 128> encode_native_proof(const ProofPublic& proof);
ProofPublic decode_native_proof(std::span<const unsigned char> encoded);
std::string proof_hex(const ProofPublic& proof);
}  // namespace kpi::mpc
