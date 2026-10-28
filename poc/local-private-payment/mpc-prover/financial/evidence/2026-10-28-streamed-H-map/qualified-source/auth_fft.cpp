#include "auth_fft.hpp"
#include "batched_assignment.hpp"
#include <algorithm>
#include <array>
#include <stdexcept>

namespace kpi::mpc {
namespace {
// Cooley-Tukey radix-2 butterflies with explicit Arkworks domain roots.
// As in maintained mcl/Ark FFT implementations, all operations in this routine
// are public linear maps. AuthScalar operators apply them to BOTH MAC/value
// lanes. No mcl default BLS12-381 root or secret-share conversion is used.
void transform(std::span<AuthScalar> values, const FftPlan& plan, bool inverse) {
    if (values.size() != plan.n || plan.n == 0 || plan.n > (size_t{1} << 28) ||
        (plan.n & (plan.n - 1)) != 0 ||
        pow_public(plan.omega, bigint(plan.n)) != Fr(1) ||
        (plan.n > 1 && pow_public(plan.omega, bigint(plan.n / 2)) == Fr(1)) ||
        plan.omega * plan.omega_inverse != Fr(1) ||
        Fr(bigint(plan.n)) * plan.inv_n != Fr(1))
        throw std::runtime_error("FFT-arity");
    for (size_t i = 1, j = 0; i < values.size(); ++i) {
        size_t bit = values.size() >> 1;
        for (; j & bit; bit >>= 1)
            j ^= bit;
        j ^= bit;
        if (i < j)
            std::swap(values[i], values[j]);
    }
    const Fr root = inverse ? plan.omega_inverse : plan.omega;
    for (size_t width = 2; width <= values.size(); width <<= 1) {
        const Fr step = pow_public(root, bigint(values.size() / width));
        for (size_t start = 0; start < values.size(); start += width) {
            Fr weight(1);
            for (size_t offset = 0; offset < width / 2; ++offset) {
                auto even = values[start + offset];
                auto odd = values[start + offset + width / 2] * weight;
                values[start + offset] = even + odd;
                values[start + offset + width / 2] = even - odd;
                weight *= step;
            }
        }
    }
    if (inverse)
        for (auto& value : values)
            value *= plan.inv_n;
}

void distribute_powers(std::span<AuthScalar> values, const Fr& base) {
    Fr coefficient(1);
    for (auto& value : values) {
        value *= coefficient;
        coefficient *= base;
    }
}
}  // namespace

AuthScalar evaluate_linear(const SparseRow& row,
                           std::span<const AuthScalar> assignment) {
    AuthScalar sum;
    for (const auto& term : row) {
        if (term.index >= assignment.size())
            throw std::runtime_error("R1CS-index");
        sum += assignment[term.index] * term.coefficient;
    }
    return sum;
}

void auth_fft(std::span<AuthScalar> values, const FftPlan& plan) {
    transform(values, plan, false);
}
void auth_ifft(std::span<AuthScalar> values, const FftPlan& plan) {
    transform(values, plan, true);
}
void scale_public(std::span<AuthScalar> values, std::span<const Fr> coefficients) {
    if (values.size() != coefficients.size())
        throw std::runtime_error("public-scale-arity");
    for (size_t i = 0; i < values.size(); ++i)
        values[i] *= coefficients[i];
}

void require_valid_assignment(MascotContext& context, const PublicModel& model,
                              std::span<const AuthScalar> assignment,
                              std::span<const AuthScalar> additional_private_residuals) {
    context.report_public_phase("full-assignment-check-started");
    validate_public_model(model);
    if (assignment.size() != model.num_instance + model.num_private)
        throw std::runtime_error("full-assignment-arity");
    std::vector<AuthScalar> left, right, residuals;
    for (size_t i = 0; i < model.num_constraints; ++i) {
        left.push_back(evaluate_linear(model.A[i], assignment));
        right.push_back(evaluate_linear(model.B[i], assignment));
    }
    auto products = context.multiply_batch(left, right);
    context.report_public_phase("assignment-row-products-derived");
    for (size_t i = 0; i < model.num_constraints; ++i)
        residuals.push_back(products[i] - evaluate_linear(model.C[i], assignment));
    // Verify ONE and every promised public value using the SAME authenticated
    // assignment consumed by the witness map, before any proof-related opening.
    for (size_t i = 0; i < model.num_instance; ++i)
        residuals.push_back(assignment[i] - context.public_constant(model.public_inputs[i]));
    // Trace-local Boolean/range/overflow conditions join this SAME validity
    // bit. They are never opened independently, and cannot be forgotten by a
    // caller that passes the trace execution's residual span to prove().
    residuals.insert(residuals.end(), additional_private_residuals.begin(),
                     additional_private_residuals.end());

    // Exact full-field Fermat zero test: e^(P-1) is 0 iff e=0 and 1 otherwise.
    // All exponentiation and AND work remains authenticated. Only one global
    // validity bit is opened. Raw residuals, row verdicts and secret masks are
    // never opened. This is deliberately costly and is qualified only for the
    // small full-proof gate; Native-size witness checking needs measurement.
    const bigint exponent(fr_modulus() - 1);
    std::vector<AuthScalar> powers = residuals;
    std::vector<AuthScalar> nonzero(residuals.size(), context.public_constant(Fr(1)));
    const auto bits = mpz_sizeinbase(exponent.get_mpz_t(), 2);
    for (size_t bit = 0; bit < bits; ++bit) {
        if (mpz_tstbit(exponent.get_mpz_t(), bit))
            nonzero = context.multiply_batch(nonzero, powers);
        if (bit + 1 < bits)
            powers = context.multiply_batch(powers, powers);
    }
    std::vector<AuthScalar> all_valid;
    for (const auto& flag : nonzero)
        all_valid.push_back(context.public_constant(Fr(1)) - flag);
    while (all_valid.size() > 1) {
        std::vector<AuthScalar> first, second;
        for (size_t i = 0; i + 1 < all_valid.size(); i += 2) {
            first.push_back(all_valid[i]); second.push_back(all_valid[i + 1]);
        }
        auto next = context.multiply_batch(first, second);
        if (all_valid.size() % 2)
            next.push_back(all_valid.back());
        all_valid = std::move(next);
    }
    const auto validity = context.open_public_checked(all_valid);
    context.report_public_phase("assignment-validity-MAC-checked");
    if (validity.size() != 1 || validity[0] != Fr(1))
        throw std::runtime_error("invalid-extended-assignment");
    context.report_public_phase("full-assignment-check-complete");
}

namespace {
std::vector<AuthScalar> h_map_from_assignment(MascotContext& context,
                                             const PublicModel& model,
                                             std::span<const AuthScalar> assignment) {
    context.report_public_phase("authenticated-H-map-started");
    const auto n = model.domain.n;
    std::vector<AuthScalar> a(n), b(n), c(n);
    for (size_t i = 0; i < model.num_constraints; ++i) {
        a[i] = evaluate_linear(model.A[i], assignment);
        b[i] = evaluate_linear(model.B[i], assignment);
        c[i] = evaluate_linear(model.C[i], assignment);
    }
    for (size_t i = 0; i < model.num_instance; ++i)
        a[model.num_constraints + i] = assignment[i];
    auth_ifft(a, model.domain); auth_ifft(b, model.domain); auth_ifft(c, model.domain);
    distribute_powers(a, model.domain.coset_shift);
    distribute_powers(b, model.domain.coset_shift);
    distribute_powers(c, model.domain.coset_shift);
    auth_fft(a, model.domain); auth_fft(b, model.domain); auth_fft(c, model.domain);
    auto ab = context.multiply_batch(a, b);
    const Fr inverse_vanishing =
        (pow_public(model.domain.coset_shift, bigint(n)) - Fr(1)).invert();
    for (size_t i = 0; i < n; ++i)
        ab[i] = (ab[i] - c[i]) * inverse_vanishing;
    auth_ifft(ab, model.domain);
    distribute_powers(ab, model.domain.coset_shift.invert());
    context.report_public_phase("authenticated-H-map-complete");
    return ab;
}
}  // namespace

std::vector<AuthScalar> libsnark_h(MascotContext& context,
                                  const PublicModel& model,
                                  std::span<const AuthScalar> assignment,
                                  std::span<const AuthScalar> additional_private_residuals) {
    require_valid_assignment(context, model, assignment, additional_private_residuals);
    return h_map_from_assignment(context, model, assignment);
}

std::vector<AuthScalar> ValidatedAssignment::make_h_map(MascotContext& context) const {
    context.require_healthy();
    if (!consumed_ || context_ != &context || generation_ != context.generation() ||
        epoch_ != context.failure_epoch())
        throw std::runtime_error("validated-H-map-capability-refused");
    return h_map_from_assignment(context, model_, assignment_);
}
}  // namespace kpi::mpc
