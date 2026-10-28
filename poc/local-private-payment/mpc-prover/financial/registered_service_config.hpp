#pragma once
#include "registered_service.hpp"

namespace kpi::mpc::financial::registered_detail {
// A PUBLIC compile-time selection format. There is intentionally no factory
// accepting this type: constructing it does not mint RegisteredService.
struct Configuration {
    history::EpochKey key;
    history::Digest registration;
    std::filesystem::path registration_file;
    history::Digest registration_file_sha256;
    std::array<std::filesystem::path, 3> journals, anchors, certificates;
    std::array<history::Digest, 3> certificate_pem_sha256;
    std::array<std::vector<std::filesystem::path>, 3> private_directories;
    FixedPublicProgram acquisition, exporter;
    history::Digest model, native_parameters, native_tail;
    std::filesystem::path native_parameters_file, native_tail_file;
};
} // namespace kpi::mpc::financial::registered_detail
