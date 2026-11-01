#pragma once

// Public immutable path/pin selection for the configured registered driver.
// This is data, not authority: only the ROOT-owned selected source header may
// construct it, and every referenced byte is still directly admitted.
#include "../packed/gzip_queries.hpp"
#include <array>
#include <filesystem>
#include <string>

namespace kpi::mpc::financial::registered_detail {

struct DriverConfiguration {
    // PackedModel::admit_compressed reads model.meta below model_directory.
    // Keeping the exact metadata path explicit prevents a selected directory
    // from silently supplying a different basename.
    std::filesystem::path model_directory;
    std::filesystem::path model_metadata;
    std::string model_metadata_sha256;

    // The selected compressed stock PK is fully admitted and sealed before
    // use. canonical_pk_sha256 in query_pins authenticates its decoded bytes.
    std::filesystem::path compressed_query_transport;
    std::filesystem::path verifying_key;
    std::filesystem::path independent_verifier;
    std::string independent_verifier_sha256;
    packed::StockQueryShape query_shape;
    packed::GzipQueryPins query_pins;
    packed::RowsDescriptor rows;

    // Per-role private candidate names and public result names are derived
    // from the fresh compiled-driver attempt identity under these fixed roots.
    // They are never accepted from argv, environment variables, or a job.
    std::array<std::filesystem::path, 3> private_candidate_roots;
    std::array<std::filesystem::path, 3> public_result_roots;

    // The selected authenticated transport owns the inter-party endpoints.
    // This fixed base only selects the three role-local owner listeners.
    int owner_port_base;
    size_t multiplication_batch;
};

} // namespace kpi::mpc::financial::registered_detail
