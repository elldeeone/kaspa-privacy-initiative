#pragma once

// Deterministic exact-width projection fixture for offline authority controls.
// This is source bytes, never a receipt/digest minter, and is compiled only by
// test targets.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <openssl/sha.h>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>

namespace kpb::native_terminal::projection_test_fixture {

using Digest = std::array<unsigned char, 32>;
using Projection = std::array<std::byte, 10685>;

inline void put32(std::byte* out, std::uint32_t value) {
    for (unsigned index = 0; index < 4; ++index)
        out[index] = static_cast<std::byte>(value >> (8 * index));
}

inline void put64(std::byte* out, std::uint64_t value) {
    for (unsigned index = 0; index < 8; ++index)
        out[index] = static_cast<std::byte>(value >> (8 * index));
}

inline Digest digest(unsigned seed) {
    Digest result{};
    for (unsigned index = 0; index < result.size(); ++index)
        result[index] = static_cast<unsigned char>(seed + index * 13U);
    return result;
}

inline void copy_digest(const Digest& value, std::byte* out) {
    std::transform(value.begin(), value.end(), out,
                   [](unsigned char byte) {
                       return static_cast<std::byte>(byte);
                   });
}

inline Digest identity(std::span<const std::byte> value) {
    Digest result{};
    if (!SHA256(reinterpret_cast<const unsigned char*>(value.data()),
                value.size(), result.data()))
        throw std::runtime_error("projection fixture sha256");
    return result;
}

inline std::string hex(const Digest& value) {
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (const auto byte : value) {
        result.push_back(alphabet[byte >> 4]);
        result.push_back(alphabet[byte & 0x0f]);
    }
    return result;
}

inline Projection make(unsigned round) {
    if (round != 1 && round != 2)
        throw std::runtime_error("projection fixture round");
    Projection raw{};
    auto* prefix = raw.data();
    auto* body = raw.data() + 193;
    std::memcpy(prefix, "KPBAFX01\x01\0\x01\0", 12);
    std::memcpy(body, "KPBAEF01", 8);
    for (unsigned index = 0; index < 5; ++index) {
        const auto context = digest(0x18 + index);
        copy_digest(context, body + 8 + 32 * index);
    }
    const auto point = digest(0x20 + round);
    copy_digest(point, prefix + 12);
    copy_digest(point, body + 168);
    put32(prefix + 44, round + 1);
    put32(body + 200, round + 1);
    std::fill(prefix + 48, prefix + 56, std::byte{0xff});
    const std::uint64_t old_reserve =
        6'000'000'000ULL - (round - 1) * 30'000'000ULL;
    const std::uint64_t new_reserve = old_reserve - 30'000'000ULL;
    put64(prefix + 56, old_reserve);
    put64(body + 276, old_reserve);
    put64(prefix + 105, new_reserve);
    put64(body + 356, new_reserve);
    put64(body + 364, 30'000'000ULL);
    const std::uint32_t old_cm_count = 3 + (round - 1) * 6;
    const std::uint32_t old_nf_count = 1 + (round - 1) * 3;
    put32(body + 268, old_cm_count);
    put32(body + 272, old_nf_count);
    put32(body + 348, old_cm_count + 6);
    put32(body + 352, old_nf_count + 3);
    const auto old_cm = round == 1 ? digest(0x31) : digest(0x39);
    const auto old_nf = round == 1 ? digest(0x35) : digest(0x3d);
    const auto new_cm = round == 1 ? digest(0x39) : digest(0x41);
    const auto new_nf = round == 1 ? digest(0x3d) : digest(0x45);
    const auto delta = digest(0x40 + round);
    copy_digest(old_cm, body + 204);
    copy_digest(old_nf, body + 236);
    copy_digest(new_cm, body + 284);
    copy_digest(new_nf, body + 316);
    copy_digest(delta, body + 372);
    for (const auto [offset, fill] : {
             std::pair{std::size_t{66},
                       static_cast<unsigned char>(0x50 + round)},
             std::pair{std::size_t{115},
                       static_cast<unsigned char>(0x51 + round)}}) {
        prefix[offset] = std::byte{0};
        prefix[offset + 1] = std::byte{0};
        prefix[offset + 2] = std::byte{0xaa};
        prefix[offset + 3] = std::byte{0x20};
        std::fill(prefix + offset + 4, prefix + offset + 36,
                  static_cast<std::byte>(fill));
        prefix[offset + 36] = std::byte{0x87};
    }
    prefix[64] = std::byte{37};
    prefix[103] = std::byte{1};
    prefix[113] = std::byte{37};
    put32(prefix + 189, 10492);
    for (unsigned index = 0; index < 3; ++index) {
        body[404 + 96 * index] = static_cast<std::byte>(
            100 * round + index + 1);
        std::fill(body + 436 + 96 * index, body + 500 + 96 * index,
                  static_cast<std::byte>(0x60 + index));
    }
    for (unsigned index = 0; index < 6; ++index) {
        auto* row = body + 692 + 520 * index;
        const auto commitment = digest(0x70 + 8 * round + index);
        copy_digest(commitment, row);
        std::fill(row + 32, row + 96,
                  static_cast<std::byte>(0x80 + index));
        std::fill(row + 96, row + 360,
                  static_cast<std::byte>(1 + index));
        Digest ciphertext_hash{};
        if (!SHA256(reinterpret_cast<const unsigned char*>(row + 96), 264,
                    ciphertext_hash.data()))
            throw std::runtime_error("projection fixture ciphertext sha256");
        copy_digest(ciphertext_hash, row + 360);
        std::fill(row + 392, row + 520,
                  static_cast<std::byte>(0x90 + index));
    }
    std::fill(body + 3812, body + 7292,
              static_cast<std::byte>(0xa0 + round));
    std::fill(body + 7292, body + 10364,
              static_cast<std::byte>(0xb0 + round));
    return raw;
}

} // namespace kpb::native_terminal::projection_test_fixture
