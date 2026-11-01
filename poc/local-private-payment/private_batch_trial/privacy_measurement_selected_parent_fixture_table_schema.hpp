#pragma once

#include "privacy_measurement_authority.hpp"

#include <string_view>

namespace kpb::measurement::selected_parent_fixture {

struct ArtifactSpec final {
    std::string_view path;
    Digest expected_sha256;
};

} // namespace kpb::measurement::selected_parent_fixture
