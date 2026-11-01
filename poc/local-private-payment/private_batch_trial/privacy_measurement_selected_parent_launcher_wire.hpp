#pragma once

#include <array>
#include <cstddef>

namespace kpb::measurement::selected_parent_wire {

inline constexpr unsigned COMPONENTS = 10;
inline constexpr unsigned FIELDS = 6;
inline constexpr unsigned ARTIFACTS = COMPONENTS * FIELDS;
inline constexpr int CONTROL_FD = 63;
inline constexpr int ARTIFACT_FD_BASE = 100;
inline constexpr std::size_t OFFER_BYTES = 48;
inline constexpr std::size_t SLOT_BYTES = 56;
inline constexpr std::size_t COMPLETION_BYTES =
    8 + 4 + 32 + 8 + ARTIFACTS * SLOT_BYTES;
inline constexpr std::array<unsigned char, 8> OFFER_MAGIC{
    'K', 'P', 'B', 'P', 'L', 'O', '1', 0};
inline constexpr std::array<unsigned char, 8> COMPLETION_MAGIC{
    'K', 'P', 'B', 'P', 'L', 'C', '1', 0};
inline constexpr unsigned VERSION = 1;

} // namespace kpb::measurement::selected_parent_wire
