#pragma once

#include "registered_service.hpp"
#include <span>

namespace kpi::mpc::financial {

// UNTRUSTED process output only. These bytes do not authorize an accepted head,
// a trace selection, owner intake, publication, FINAL, or settlement.
struct FixedPublicResult {
    std::filesystem::path workspace, output_directory;
    std::vector<unsigned char> stdout_bytes;
    history::Digest input_identity, execution_identity;
};

// Program must be the exact immutable acquisition/exporter object owned by
// this selected service. All inherited private descriptors and private mounts
// are excluded before the selected public program starts. Factories must call
// service.require_live(ctx) before/after and interpret the result themselves.
FixedPublicResult run_fixed_public_program(const RegisteredService&,
    const FixedPublicProgram&, std::span<const unsigned char> input);

// Read a single fresh public result after private metadata/alias exclusions,
// single-link/type/identity checks. Returned bytes remain untrusted data.
std::vector<unsigned char> read_fixed_public_result(const RegisteredService&,
    const FixedPublicResult&, const std::filesystem::path& relative_name);
std::filesystem::path check_fixed_public_result_path(const RegisteredService&,
    const FixedPublicResult&, const std::filesystem::path& relative_name);

// The registered immutable native tail is public. This narrow reader still
// inventories private aliases before body admission and authenticates its pin.
std::vector<unsigned char> read_registered_native_tail(const RegisteredService&);
} // namespace kpi::mpc::financial
