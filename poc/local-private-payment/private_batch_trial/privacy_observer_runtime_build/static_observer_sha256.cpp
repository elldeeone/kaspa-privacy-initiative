#include "generated_privacy_measurement_sha256.hpp"

#include <algorithm>
#include <cstddef>
#include <span>

extern "C" int kpb_static_sha256(
        const unsigned char* input, std::size_t size,
        unsigned char output[32]) {
    if ((input == nullptr && size != 0) || output == nullptr) return 0;
    const auto digest = kpb::measurement::detail::sha256(
        std::span(input, size));
    std::copy(digest.begin(), digest.end(), output);
    return 1;
}
