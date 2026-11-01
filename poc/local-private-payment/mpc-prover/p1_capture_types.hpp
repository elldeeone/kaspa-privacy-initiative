#pragma once

#include <array>
#include <string>

namespace kpi::mpc::p1_capture {

struct RunBinding {
    std::string attempt_id;
    std::string cohort_sha256;
    std::string financial_run_id;
    std::string capture_identity;
    std::string protocol_source_sha256;
    std::string protocol_build_sha256;
    std::string protocol_launch_sha256;
    std::string model_preimage_sha256;
    std::string query_store_preimage_sha256;
    std::string scalar_capture_manifest_sha256;
};

using ForkId = std::array<unsigned char, 32>;

} // namespace kpi::mpc::p1_capture
