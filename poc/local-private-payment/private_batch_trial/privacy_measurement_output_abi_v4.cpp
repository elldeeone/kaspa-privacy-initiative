#include "privacy_measurement_output_abi_v4.hpp"

#include <algorithm>
#include <array>

namespace kpb::measurement::runtime_bridge {
namespace {

using Section = std::array<unsigned char, OBSERVER_V4_SECTION_BYTES>;

void put_u16(Section& out, std::size_t& at, std::uint16_t value) {
    out.at(at++) = static_cast<unsigned char>(value >> 8);
    out.at(at++) = static_cast<unsigned char>(value);
}

void put_u32(Section& out, std::size_t& at, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8)
        out.at(at++) = static_cast<unsigned char>(value >> shift);
}

void put_digest(Section& out, std::size_t& at, const Digest& value) {
    for (const auto byte : value) out.at(at++) = byte;
}

Section exact_section() {
    Section result{};
    std::size_t at = 0;
    for (const auto byte : OBSERVER_V4_SECTION_MAGIC) result.at(at++) = byte;
    put_u32(result, at, OBSERVER_V4_VERSION);
    put_u32(result, at, OBSERVER_V4_SECTION_BYTES);
    put_u16(result, at, OBSERVER_V4_FAMILY_ROWS.size());
    put_u16(result, at, OBSERVER_V4_FLAGS);
    put_digest(result, at, OBSERVER_V4_REGISTRY_IDENTITY);
    put_digest(result, at, OBSERVER_V4_MODEL_IDENTITY);
    put_digest(result, at, OBSERVER_OUTPUT_ABI_V4.identity);
    for (const auto& value : OBSERVER_V4_S4_IDENTITIES)
        put_digest(result, at, value);
    for (const auto& value : OBSERVER_V4_S12_IDENTITIES)
        put_digest(result, at, value);
    put_digest(result, at, OBSERVER_V4_S5_EXECUTABLE_IDENTITY);
    for (const auto& row : OBSERVER_V4_FAMILY_ROWS) {
        result.at(at++) = static_cast<unsigned char>(row.family);
        result.at(at++) = static_cast<unsigned char>(row.mode);
        result.at(at++) = static_cast<unsigned char>(row.applicability);
        result.at(at++) = row.pinned_provenance_count;
        put_u16(result, at, row.prerequisite_mask);
        put_u16(result, at, 0);
    }
    if (at != 628) return {};
    return result;
}

} // namespace

bool validate_observer_v4_section(
        std::span<const unsigned char> supplied) {
    if (supplied.size() != OBSERVER_V4_SECTION_BYTES) return false;
    const auto expected = exact_section();
    return std::equal(supplied.begin(), supplied.end(), expected.begin());
}

bool validate_observer_output_v4(
        std::span<const unsigned char> supplied) {
    if (supplied.size() != OBSERVER_OUTPUT_ABI_V4.exact_bytes) return false;
    if (!validate_measurement_output_abi(
            RuntimeChildRole::Observer,
            supplied.first(OBSERVER_V4_PREFIX_BYTES)))
        return false;
    if (!validate_observer_v4_section(supplied.subspan(
            OBSERVER_V4_SECTION_OFFSET, OBSERVER_V4_SECTION_BYTES)))
        return false;
    return std::all_of(
        supplied.begin() + static_cast<std::ptrdiff_t>(
            OBSERVER_V4_USED_BYTES), supplied.end(),
        [](unsigned char value) { return value == 0; });
}

#ifdef KPB_MEASUREMENT_OUTPUT_ABI_V4_TEST_SETUP
std::vector<unsigned char> test_only_observer_output_v4_body() {
    auto result = test_only_measurement_output_abi_body(
        RuntimeChildRole::Observer);
    result.resize(OBSERVER_OUTPUT_ABI_V4.exact_bytes);
    const auto section = exact_section();
    std::copy(section.begin(), section.end(),
              result.begin() + static_cast<std::ptrdiff_t>(
                  OBSERVER_V4_SECTION_OFFSET));
    return result;
}
#endif

} // namespace kpb::measurement::runtime_bridge
