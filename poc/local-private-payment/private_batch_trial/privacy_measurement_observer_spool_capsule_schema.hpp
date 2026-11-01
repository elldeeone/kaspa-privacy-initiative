#pragma once

#include <array>
#include <cstdint>

namespace kpb::measurement::runtime_bridge::observer_spool_schema {

// Canonical child-private archive created only from the ten retained sealed
// raw-wire memfds. No directory name, path, or mutable filesystem identity is
// part of this schema.
inline constexpr std::array<unsigned char, 8> MAGIC{
    'K', 'P', 'B', 'O', 'S', 'A', '2', 0};
inline constexpr std::uint32_t VERSION = 2;
inline constexpr unsigned ROUND_COUNT = 2;
inline constexpr unsigned LEAVES_PER_ROUND = 5;
inline constexpr unsigned LEAF_COUNT = ROUND_COUNT * LEAVES_PER_ROUND;
inline constexpr std::array<const char*, LEAVES_PER_ROUND> LEAF_NAMES{
    "projection.bin", "terminal.json", "dispatcher.json",
    "corrupt-server.json", "colluder-wallet.json",
};

} // namespace kpb::measurement::runtime_bridge::observer_spool_schema
