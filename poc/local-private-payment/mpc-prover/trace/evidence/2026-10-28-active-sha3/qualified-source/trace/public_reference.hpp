#pragma once
#ifndef KPI_TRACE_PUBLIC_CONTROLS
#error "The public fixture evaluator is not part of the authenticated runtime"
#endif
#include "trace_witness.hpp"

namespace kpi::mpc {
struct PublicTraceReference {
    std::vector<Fr> model;
    std::vector<Fr> private_checks;
};
// Test-only instantiation of the SAME executor and scheduler. Random entropy
// operations refuse, rather than silently substituting public randomness.
PublicTraceReference evaluate_public_trace_for_controls(
    const TraceProgram& program,
    std::vector<std::pair<int, std::vector<Fr>>> inputs,
    size_t window_size);
}  // namespace kpi::mpc
