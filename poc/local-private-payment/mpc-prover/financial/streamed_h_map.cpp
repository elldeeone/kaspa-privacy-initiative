#include "streamed_h_map.hpp"
#include "../auth_fft.hpp"
#include <algorithm>
#include <limits>
#include <string>

#if defined(INSECURE) || defined(NDEBUG) || defined(DEBUG_MAC) || defined(PRINT_MAC)
#error "Streamed authenticated H-map requires assertions and forbids insecure diagnostics"
#endif

namespace kpi::mpc::financial {
namespace {
constexpr size_t maximum_product_chunk = 4096;

size_t host_size(uint64_t value) {
    if (value > std::numeric_limits<size_t>::max())
        throw std::runtime_error("streamed-H-map-host-size");
    return static_cast<size_t>(value);
}

FftPlan selected_plan(const packed::Metadata& metadata,
                      std::span<const AuthScalar> assignment) {
    if (metadata.instances > std::numeric_limits<uint64_t>::max() - metadata.witnesses ||
        metadata.instances == 0 || metadata.domain == 0 ||
        metadata.domain > (uint64_t{1} << 28) ||
        (metadata.domain & (metadata.domain - 1)) != 0 ||
        metadata.constraints > metadata.domain ||
        metadata.instances > metadata.domain - metadata.constraints ||
        assignment.size() != host_size(metadata.instances + metadata.witnesses) ||
        Fr::pr() != fr_modulus())
        throw std::runtime_error("streamed-H-map-assignment-or-domain-shape");
    // The admitted packed metadata and the retained public FFT both validate
    // roots, inverse normalization and the disjoint multiplicative coset.
    return {host_size(metadata.domain), metadata.omega, metadata.omega_inverse,
            metadata.inv_n, metadata.coset_shift};
}

void fill_axis(const packed::PackedModel& model, unsigned axis,
               std::span<const AuthScalar> assignment,
               std::span<AuthScalar> evaluations) {
    const auto expected = host_size(model.metadata().constraints);
    if (expected > evaluations.size())
        throw std::runtime_error("streamed-H-map-row-domain-range");
    auto cursor = model.rows(axis);
    SparseRow row;
    size_t rows = 0;
    // The false return is required: RowCursor verifies final gzip EOF,
    // checksum, raw byte count and digest there. Never stop after only the
    // expected number of successful reads.
    while (cursor.next(row)) {
        if (rows >= expected)
            throw std::runtime_error("streamed-H-map-extra-row");
        evaluations[rows] = evaluate_linear(row, assignment);
        ++rows;
    }
    if (rows != expected)
        throw std::runtime_error("streamed-H-map-missing-row");
}

void distribute_powers(std::span<AuthScalar> values, const Fr& base) {
    Fr coefficient(1);
    for (auto& value : values) {
        value *= coefficient; // Retains both the value and MAC lanes.
        coefficient *= base;
    }
}

void to_coset(std::span<AuthScalar> values, const FftPlan& plan) {
    auth_ifft(values, plan);
    distribute_powers(values, plan.coset_shift);
    auth_fft(values, plan);
}

void agree_schedule(MascotContext& context, const packed::PackedModel& model,
                    size_t domain, size_t chunk) {
    const auto binding = std::string("KPI_STREAMED_LIBSNARK_H_V1\n") +
        model.identity() + "\n" + std::to_string(domain) + "\n" +
        std::to_string(chunk) + "\n";
    context.agree_public_bytes("streamed-H-map-selected-model-and-schedule", {
        reinterpret_cast<const unsigned char*>(binding.data()), binding.size()});
}
}  // namespace

std::vector<AuthScalar> StreamedWitnessMap::compute(MascotContext& context,
    const packed::PackedModel& model, std::span<const AuthScalar> assignment,
    size_t multiplication_batch) {
    context.require_healthy();
    try {
        if (multiplication_batch == 0)
            throw std::invalid_argument("streamed-H-map-zero-product-chunk");
        model.check_backing_unchanged();
        const auto& metadata = model.metadata();
        const auto plan = selected_plan(metadata, assignment);
        const auto chunk = std::min(multiplication_batch, maximum_product_chunk);
        agree_schedule(context, model, plan.n, chunk);
        context.report_public_phase("streamed-H-map-started");

        // Default AuthScalar is the authenticated additive zero: both lanes
        // are zero. Padding for unused domain rows must remain zero in every
        // axis. As in stock LibSnarkReduction, only A appends the complete
        // instance prefix (including ONE), using the SAME sealed assignment.
        std::vector<AuthScalar> a(plan.n);
        fill_axis(model, 0, assignment, a);
        const auto rows = host_size(metadata.constraints);
        const auto instances = host_size(metadata.instances);
        for (size_t i = 0; i < instances; ++i)
            a[rows + i] = assignment[i];
        {
            std::vector<AuthScalar> b(plan.n);
            fill_axis(model, 1, assignment, b);
            context.report_public_phase("streamed-H-map-A-B-rows-complete");
            to_coset(a, plan);
            to_coset(b, plan);
            context.report_public_phase("streamed-H-map-A-B-coset-complete");
            for (size_t offset = 0; offset < plan.n;) {
                const auto count = std::min(chunk, plan.n - offset);
                // Spans refer directly into A and B. The only result storage
                // outside the two domain vectors is this bounded chunk.
                auto products = context.multiply_batch(
                    std::span<const AuthScalar>(a).subspan(offset, count),
                    std::span<const AuthScalar>(b).subspan(offset, count));
                if (products.size() != count)
                    throw std::runtime_error("streamed-H-map-product-arity");
                std::move(products.begin(), products.end(), a.begin() + offset);
                offset += count;
            }
            context.check_field_pending();
        } // B is destroyed and deallocated BEFORE any C allocation.
        context.report_public_phase("streamed-H-map-product-complete");

        const auto vanishing = pow_public(plan.coset_shift, bigint(plan.n)) - Fr(1);
        if (vanishing == Fr(0))
            throw std::runtime_error("streamed-H-map-zero-coset-vanishing");
        const auto inverse_vanishing = vanishing.invert();
        if (vanishing * inverse_vanishing != Fr(1))
            throw std::runtime_error("streamed-H-map-vanishing-inverse");
        {
            std::vector<AuthScalar> c(plan.n);
            fill_axis(model, 2, assignment, c);
            context.report_public_phase("streamed-H-map-C-rows-complete");
            to_coset(c, plan);
            context.report_public_phase("streamed-H-map-C-coset-complete");
            for (size_t i = 0; i < plan.n; ++i)
                a[i] = (a[i] - c[i]) * inverse_vanishing;
        } // C is destroyed and deallocated before the final transform.

        auth_ifft(a, plan);
        distribute_powers(a, plan.coset_shift.invert());
        model.check_backing_unchanged();
        context.check_field_pending();
        context.report_public_phase("streamed-H-map-complete");
        return a;
    } catch (...) {
        context.poison();
        throw;
    }
}

#ifdef KPI_STREAMED_H_MAP_PUBLIC_FIXTURE_CONTROL
std::vector<AuthScalar> StreamedWitnessMap::public_fixture_compute(MascotContext& context,
    const packed::PackedModel& model, std::span<const AuthScalar> assignment,
    size_t multiplication_batch) {
    return compute(context, model, assignment, multiplication_batch);
}
#endif

}  // namespace kpi::mpc::financial
