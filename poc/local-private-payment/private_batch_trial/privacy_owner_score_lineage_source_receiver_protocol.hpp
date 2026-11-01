#pragma once

#include <array>
#include <cstddef>

namespace kpb::measurement::score_output_lineage_source::receiver_protocol {

inline constexpr int SELECTION_FD = 60;
inline constexpr int CONTROL_FD = 63;
inline constexpr std::array<unsigned char, 8> OFFER_MAGIC{
    'K','P','B','O','S','Q','0','1'};
inline constexpr std::array<unsigned char, 8> RESPONSE_MAGIC{
    'K','P','B','O','S','R','0','1'};
inline constexpr std::size_t OFFER_BYTES = 72;
inline constexpr std::size_t RESPONSE_BYTES = 80;

} // namespace kpb::measurement::score_output_lineage_source::receiver_protocol
