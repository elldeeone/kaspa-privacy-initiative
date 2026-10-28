#pragma once

// Public, source/model/layout-bound recipes for actively authenticated witness
// extension. This is not a clear witness importer and never opens a wire.
#include "../auth_field.hpp"
#include <cstdint>
#include <filesystem>
#include <memory>

namespace kpi::mpc {
class SealedTraceArtifact;
class PrefixRecipe;

struct TraceBinding {
    std::string trace_sha256;
    std::string source_sha256;
    std::string model_sha256;
    std::string layout_sha256;
    std::filesystem::path layout_path;
    std::vector<int> owner_roles;
    size_t model_variables;
    size_t instances;
    // Required for gzip. Raw legacy programs use the canonical hash as their
    // container hash; their selected raw bytes also determine exact length.
    std::string container_sha256 = {};
    size_t canonical_bytes = 0;
    std::string layout_container_sha256 = {};
    size_t layout_canonical_bytes = 0;
    std::shared_ptr<const PrefixRecipe> prefix_recipe = {};
};

struct TraceOwnerLayout {
    int owner_role;
    std::vector<size_t> columns;
};

struct TraceHeader {
    std::string source_sha256;
    std::string model_sha256;
    std::string layout_sha256;
    size_t model_variables;
    size_t variables;
    size_t instances;
    std::vector<size_t> input_columns;
    size_t operations;
};

struct OwnerTraceInput {
    int owner_role;
    // Ordered exactly as the selected layout and matching DDNNT contract.
    // Move the received vector here; no caller-supplied column remapping.
    std::vector<AuthScalar> values;
};

// Inspection fully parses all recipes, references and write destinations before
// owner input. The selected trace file must be mounted read-only in each role.
struct TraceProgram {
    std::filesystem::path path;
    TraceBinding binding;
    TraceHeader header;
    std::vector<TraceOwnerLayout> owner_layout;
    size_t canonical_bytes;
    size_t expected_private_checks;
    // Public liveness metadata derived from the exact recipe, scratch only.
    std::vector<uint32_t> scratch_last_use32;
    std::vector<size_t> scratch_last_use_wide;
    std::shared_ptr<const SealedTraceArtifact> artifact;
};

struct TraceExecution {
    size_t model_variables;
    // Only the model prefix is retained. Logical scratch never becomes a
    // public proof input and is released after its last public-schedule use.
    std::vector<AuthScalar> wires;
    // These are private residuals, not public failure diagnostics. A prover
    // must combine their validity with the complete SAME-assignment R1CS check
    // before releasing any proof-related opening.
    std::vector<AuthScalar> private_checks;

    std::span<const AuthScalar> model_assignment() const;
};

TraceProgram inspect_trace(const std::filesystem::path& path,
                           const TraceBinding& expected);

// Call once before private intake. execute_trace repeats this public agreement;
// batching affects only operational scheduling and cannot change semantics.
void agree_trace(MascotContext& context, const TraceProgram& program,
                 size_t multiplication_batch = 4096);

TraceExecution execute_trace(MascotContext& context, const TraceProgram& program,
                             std::vector<OwnerTraceInput> inputs,
                             size_t multiplication_batch = 4096);

// Exact full-Fr zero checking, with an authenticated result and NO opening.
// Caller must AND it with complete R1CS validity and open only one aggregate
// result. This utility does not replace R1CS/model/public-prefix validation.
AuthScalar trace_private_checks_hold(MascotContext& context,
                                     std::span<const AuthScalar> checks);

}  // namespace kpi::mpc
