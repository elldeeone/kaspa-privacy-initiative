#pragma once

#include "auth_field.hpp"
#include "Tools/octetStream.h"

#include <array>
#include <cstddef>
#include <span>
#include <vector>

namespace kpi::mpc {

inline constexpr std::size_t DDNNT_COMPONENT_COUNT = 5;
inline constexpr std::size_t DDNNT_S = 0;
inline constexpr std::size_t DDNNT_R = 1;
inline constexpr std::size_t DDNNT_W = 2;
inline constexpr std::size_t DDNNT_V = 3;
inline constexpr std::size_t DDNNT_U = 4;

void require_owner_fr_frame_length(
    const octetStream& frame, std::size_t expected_count);
octetStream pack_owner_fr_frame(std::span<const Fr> values);
std::vector<Fr> decode_owner_fr_frame(
    octetStream& frame, std::size_t expected_count);

// Reconstructs the five DDNNT values from the three computing-party value
// shares and returns s only after checking w=s*r and u=v*r for every field.
std::vector<Fr> reconstruct_checked_ddnnt_masks(
    const std::array<std::vector<Fr>, 3>& party_frames,
    std::size_t input_count);

octetStream make_owner_masked_difference_frame(
    std::span<const Fr> private_values, std::span<const Fr> masks);

void wipe_owner_fr_values(std::vector<Fr>& values) noexcept;

} // namespace kpi::mpc
