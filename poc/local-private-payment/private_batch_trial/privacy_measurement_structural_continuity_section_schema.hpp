#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace kpb::measurement::runtime_bridge::
    structural_continuity_section_schema {

inline constexpr std::array<unsigned char, 8> MAGIC{
    'K', 'P', 'B', 'S', 'P', 'C', '1', 0};
inline constexpr std::uint32_t VERSION = 1;
inline constexpr unsigned ROUND_COUNT = 2;
inline constexpr std::size_t FLAGS_OFFSET = 16;
inline constexpr std::size_t IDENTITY_OFFSET = FLAGS_OFFSET + 4;
inline constexpr std::size_t HEADER_BYTES =
    MAGIC.size() + 4 + 4 + 4 + 32;
inline constexpr std::size_t LINEAGE_DIGEST_COUNT = 14;
inline constexpr std::size_t STRUCTURAL_DIGEST_COUNT = 15;
inline constexpr std::size_t COUNT_FIELD_COUNT = 4;
inline constexpr std::size_t SOMPI_FIELD_COUNT = 3;
inline constexpr std::size_t ROUND_BYTES =
    (LINEAGE_DIGEST_COUNT + STRUCTURAL_DIGEST_COUNT) * 32 +
    COUNT_FIELD_COUNT * 4 + SOMPI_FIELD_COUNT * 8;
inline constexpr std::size_t SECTION_BYTES =
    HEADER_BYTES + ROUND_COUNT * ROUND_BYTES;
static_assert(ROUND_BYTES == 968);
static_assert(HEADER_BYTES == 52);
static_assert(IDENTITY_OFFSET == 20);
static_assert(SECTION_BYTES == 1988);

} // namespace kpb::measurement::runtime_bridge::
  // structural_continuity_section_schema
