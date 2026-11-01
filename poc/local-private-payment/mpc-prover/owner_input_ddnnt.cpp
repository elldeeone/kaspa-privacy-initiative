#include "owner_input_ddnnt.hpp"

#include <bit>
#include <limits>
#include <openssl/crypto.h>
#include <stdexcept>

namespace kpi::mpc {
namespace {

void require_count(std::size_t count) {
    if (count == 0 ||
        count > std::numeric_limits<std::size_t>::max() /
                    static_cast<std::size_t>(Fr::size()))
        throw std::runtime_error("owner-ddnnt-field-count");
}

Fr unpack_strict(octetStream& frame) {
    static_assert(std::endian::native == std::endian::little,
                  "MP-SPDZ native Montgomery framing requires little endian");
    const auto size = static_cast<std::size_t>(Fr::size());
    if (frame.left() < size)
        throw std::runtime_error("truncated-owner-ddnnt-Fr");
    auto* encoded = frame.consume(size);
    bigint residue;
    mpz_import(residue.get_mpz_t(), size, -1, 1, 0, 0, encoded);
    if (residue >= bigint(FR_MODULUS))
        throw std::runtime_error("owner-ddnnt-Montgomery-Fr-alias");
    octetStream single(size, encoded);
    Fr result;
    result.unpack(single);
    if (!single.done())
        throw std::runtime_error("owner-ddnnt-Fr-not-exhausted");
    return result;
}

} // namespace

void require_owner_fr_frame_length(
        const octetStream& frame, std::size_t expected_count) {
    require_count(expected_count);
    const auto expected_bytes = expected_count *
                                static_cast<std::size_t>(Fr::size());
    if (frame.get_length() != expected_bytes)
        throw std::runtime_error("owner-ddnnt-field-frame-length");
}

octetStream pack_owner_fr_frame(std::span<const Fr> values) {
    require_count(values.size());
    octetStream frame;
    for (const auto& value : values)
        value.pack(frame);
    require_owner_fr_frame_length(frame, values.size());
    return frame;
}

std::vector<Fr> decode_owner_fr_frame(
        octetStream& frame, std::size_t expected_count) {
    require_owner_fr_frame_length(frame, expected_count);
    std::vector<Fr> values;
    values.reserve(expected_count);
    try {
        for (std::size_t index = 0; index < expected_count; ++index)
            values.push_back(unpack_strict(frame));
        if (!frame.done())
            throw std::runtime_error("trailing-owner-ddnnt-field-frame");
        return values;
    } catch (...) {
        wipe_owner_fr_values(values);
        throw;
    }
}

std::vector<Fr> reconstruct_checked_ddnnt_masks(
        const std::array<std::vector<Fr>, 3>& party_frames,
        std::size_t input_count) {
    if (input_count == 0 ||
        input_count > std::numeric_limits<std::size_t>::max() /
                          DDNNT_COMPONENT_COUNT)
        throw std::runtime_error("owner-ddnnt-input-count");
    const auto field_count = input_count * DDNNT_COMPONENT_COUNT;
    for (const auto& frame : party_frames)
        if (frame.size() != field_count)
            throw std::runtime_error("owner-ddnnt-party-frame-shape");

    std::vector<Fr> masks;
    masks.reserve(input_count);
    try {
        for (std::size_t index = 0; index < input_count; ++index) {
            std::array<Fr, DDNNT_COMPONENT_COUNT> values{};
            const auto offset = index * DDNNT_COMPONENT_COUNT;
            for (const auto& party : party_frames)
                for (std::size_t component = 0;
                     component < DDNNT_COMPONENT_COUNT; ++component)
                    values[component] += party[offset + component];
            if (values[DDNNT_W] != values[DDNNT_S] * values[DDNNT_R]) {
                OPENSSL_cleanse(values.data(), sizeof(values));
                throw std::runtime_error("owner-ddnnt-w-equals-s-times-r");
            }
            if (values[DDNNT_U] != values[DDNNT_V] * values[DDNNT_R]) {
                OPENSSL_cleanse(values.data(), sizeof(values));
                throw std::runtime_error("owner-ddnnt-u-equals-v-times-r");
            }
            masks.push_back(values[DDNNT_S]);
            OPENSSL_cleanse(values.data(), sizeof(values));
        }
        return masks;
    } catch (...) {
        wipe_owner_fr_values(masks);
        throw;
    }
}

octetStream make_owner_masked_difference_frame(
        std::span<const Fr> private_values, std::span<const Fr> masks) {
    if (private_values.empty() || private_values.size() != masks.size())
        throw std::runtime_error("owner-ddnnt-private-mask-shape");
    octetStream frame;
    for (std::size_t index = 0; index < private_values.size(); ++index)
        Fr(private_values[index] - masks[index]).pack(frame);
    require_owner_fr_frame_length(frame, private_values.size());
    return frame;
}

void wipe_owner_fr_values(std::vector<Fr>& values) noexcept {
    if (!values.empty())
        OPENSSL_cleanse(values.data(), values.size() * sizeof(Fr));
    values.clear();
    std::vector<Fr>().swap(values);
}

} // namespace kpi::mpc
