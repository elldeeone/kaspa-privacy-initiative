#pragma once

// One source-owned cross-language domain for the raw privacy_launch.py outer
// attempt. The selected Python worker writes the resulting digest into its
// sealed lineage archive; the C++ receiver recomputes it from the retained
// ASCII attempt and requires equality with the registered prelaunch plan.
// This deterministic identity function is not authority or a selector.

#include "privacy_measurement_sha256.hpp"

#include <algorithm>
#include <array>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace kpb::measurement::score_output_lineage_source {

using OuterAttemptDigest = std::array<unsigned char, 32>;

inline constexpr std::string_view OUTER_ATTEMPT_MEASUREMENT_DOMAIN{
    "KPB_MEASUREMENT_ATTEMPT_FROM_OUTER_ASCII_V1\n"};

inline bool canonical_outer_attempt_ascii(std::string_view value) {
    if (value.empty() || value.size() > 128) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char byte) {
        return (byte >= 'a' && byte <= 'z') ||
               (byte >= 'A' && byte <= 'Z') ||
               (byte >= '0' && byte <= '9') || byte == '_' || byte == '-';
    });
}

inline OuterAttemptDigest measurement_attempt_from_outer_ascii(
        std::string_view value) {
    if (!canonical_outer_attempt_ascii(value))
        throw std::runtime_error("invalid-outer-attempt-ascii");
    std::vector<unsigned char> bytes;
    bytes.reserve(OUTER_ATTEMPT_MEASUREMENT_DOMAIN.size() + 2 +
                  value.size());
    bytes.insert(bytes.end(), OUTER_ATTEMPT_MEASUREMENT_DOMAIN.begin(),
                 OUTER_ATTEMPT_MEASUREMENT_DOMAIN.end());
    bytes.push_back(static_cast<unsigned char>(value.size()));
    bytes.push_back(static_cast<unsigned char>(value.size() >> 8));
    bytes.insert(bytes.end(), value.begin(), value.end());
    return detail::sha256(std::span<const unsigned char>(bytes));
}

} // namespace kpb::measurement::score_output_lineage_source
