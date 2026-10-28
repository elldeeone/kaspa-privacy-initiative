#pragma once
// Public canonical compressed point admission only. Both roles retain finite
// coordinate, curve, subgroup, sign and exact roundtrip checks. Only queries
// admit the uniquely encoded identity; there is no unchecked point constructor.
#include "../bn254_values.hpp"

namespace kpi::mpc::packed {
enum class CompressedPointRole { Base, Query };
G1Value admit_compressed_g1(std::span<const unsigned char>, CompressedPointRole);
G2Value admit_compressed_g2(std::span<const unsigned char>, CompressedPointRole);
}
