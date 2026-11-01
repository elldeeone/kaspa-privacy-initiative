#pragma once

#include "privacy_measurement_authority.hpp"

#include <array>
#include <bit>
#include <cstdint>
#include <span>

namespace kpb::measurement::detail {

// FIPS 180-4 SHA-256 for exact capsule/protocol byte binding.
inline Digest sha256(std::span<const unsigned char> input) noexcept {
    static constexpr std::array<std::uint32_t, 64> constants{
        0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,
        0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
        0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,
        0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
        0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,
        0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
        0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,
        0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
        0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,
        0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
        0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,
        0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
        0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,
        0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
        0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,
        0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U,
    };
    std::array<std::uint32_t, 8> state{
        0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
        0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U,
    };
    const auto compress = [&](const std::array<unsigned char, 64>& block) {
        std::array<std::uint32_t, 64> words{};
        for (unsigned i = 0; i < 16; ++i) {
            const unsigned at = 4 * i;
            words[i] = static_cast<std::uint32_t>(block[at]) << 24 |
                       static_cast<std::uint32_t>(block[at + 1]) << 16 |
                       static_cast<std::uint32_t>(block[at + 2]) << 8 |
                       static_cast<std::uint32_t>(block[at + 3]);
        }
        for (unsigned i = 16; i < 64; ++i) {
            const auto s0 = std::rotr(words[i - 15], 7) ^
                            std::rotr(words[i - 15], 18) ^
                            (words[i - 15] >> 3);
            const auto s1 = std::rotr(words[i - 2], 17) ^
                            std::rotr(words[i - 2], 19) ^
                            (words[i - 2] >> 10);
            words[i] = words[i - 16] + s0 + words[i - 7] + s1;
        }
        auto a=state[0], b=state[1], c=state[2], d=state[3];
        auto e=state[4], f=state[5], g=state[6], h=state[7];
        for (unsigned i = 0; i < 64; ++i) {
            const auto s1 = std::rotr(e,6)^std::rotr(e,11)^std::rotr(e,25);
            const auto first = h + s1 + ((e&f)^(~e&g)) + constants[i] + words[i];
            const auto s0 = std::rotr(a,2)^std::rotr(a,13)^std::rotr(a,22);
            const auto second = s0 + ((a&b)^(a&c)^(b&c));
            h=g; g=f; f=e; e=d+first; d=c; c=b; b=a; a=first+second;
        }
        state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
        state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
    };
    std::array<unsigned char, 64> block{};
    std::size_t offset = 0;
    while (input.size() - offset >= block.size()) {
        for (unsigned i = 0; i < block.size(); ++i) block[i]=input[offset+i];
        compress(block); offset += block.size();
    }
    block.fill(0);
    const auto remaining = input.size() - offset;
    for (std::size_t i=0; i<remaining; ++i) block[i]=input[offset+i];
    block[remaining]=0x80;
    if (remaining >= 56) { compress(block); block.fill(0); }
    const auto bits = static_cast<std::uint64_t>(input.size()) * 8;
    for (unsigned i=0; i<8; ++i)
        block[63-i]=static_cast<unsigned char>(bits>>(8*i));
    compress(block);
    Digest result{};
    for (unsigned i=0; i<state.size(); ++i)
        for (unsigned j=0; j<4; ++j)
            result[4*i+j]=static_cast<unsigned char>(state[i]>>(24-8*j));
    return result;
}

} // namespace kpb::measurement::detail
