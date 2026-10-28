#include "packed_assignment.hpp"
#include "streamed_h_map.hpp"
#include "../auth_fft.hpp"
#include "../field_coin.hpp"
#include "Tools/Subroutines.hpp"
#include <array>
#include <fstream>
#include <limits>
#include <sstream>

#if defined(INSECURE) || defined(NDEBUG) || defined(DEBUG_MAC) || defined(PRINT_MAC)
#error "Packed validation requires normal assertions and all security checks"
#endif

namespace kpi::mpc::financial {
namespace {
std::span<const unsigned char> bytes(const std::string& value) {
    return {reinterpret_cast<const unsigned char*>(value.data()), value.size()};
}
void hash_format(const std::string& value) {
    if (value.size() != 64 || value.find_first_not_of("0123456789abcdef") != std::string::npos)
        throw std::runtime_error("packed-validation-binding-format");
}
size_t checked_size(uint64_t value) {
    if (value > std::numeric_limits<size_t>::max()) throw std::runtime_error("packed-size-overflow");
    return static_cast<size_t>(value);
}
size_t add(size_t a, size_t b) {
    if (a > std::numeric_limits<size_t>::max() - b) throw std::runtime_error("packed-size-overflow");
    return a + b;
}
void receipt(const BatchedValidationBinding& b, const char* state,
             const std::string& binding, const std::string& coin, size_t count) {
    if (b.public_receipt_path.empty()) return;
    hash_format(b.attempt_identity);
    auto temporary = b.public_receipt_path;
    temporary += ".new";
    std::ofstream out(temporary);
    out << "{\"schema\":\"kpi-packed-validation-public/v1\",\"state\":\"" << state
        << "\",\"attempt\":\"" << b.attempt_identity << "\",\"binding_sha256\":\""
        << binding << "\",\"public_challenge\":\"" << coin << "\",\"residual_count\":"
        << count << ",\"private_residuals_or_Z_or_shares_exported\":false}\n";
    out.close();
    if (!out) throw std::runtime_error("packed-validation-receipt-persistence");
    std::filesystem::rename(temporary, b.public_receipt_path);
}
std::string binding_text(const packed::PackedModel& model, const BatchedValidationBinding& b,
                         size_t residuals, size_t batch, uint64_t epoch) {
    const auto& m = model.metadata();
    std::ostringstream out;
    out << "KPI_PACKED_PUBLIC_PREFIX_VALIDATION_V1\n"
        << "STOCK_CANONICAL_FR_COIN_POLYNOMIAL_EXACT_FERMAT\n" << FR_MODULUS << '\n';
    for (const auto* value : {&b.attempt_identity, &b.service_identity, &b.history_identity,
         &b.dependency_identity, &b.model_identity, &b.source_identity, &b.matrix_identity,
         &b.trace_identity, &b.layout_identity, &b.input_map_identity, &b.public_context_identity}) {
        hash_format(*value); out << *value << '\n';
    }
    out << m.instances << '\n' << m.witnesses << '\n' << m.constraints << '\n'
        << b.expected_trace_private_checks << '\n' << residuals << '\n' << batch << '\n' << epoch << '\n';
    return out.str();
}
}

PackedValidatedAssignment::PackedValidatedAssignment(MascotContext& context,
    packed::PackedModel model, std::vector<AuthScalar> assignment,
    BatchedValidationBinding binding, std::string identity, std::string coin, size_t count)
    : context_(&context), generation_(context.generation()), epoch_(context.failure_epoch()),
      check_counter_(context.check_counter()), model_(model), assignment_(std::move(assignment)),
      binding_(std::move(binding)), binding_identity_(std::move(identity)),
      challenge_(std::move(coin)), residual_count_(count) {}

PackedValidatedAssignment validate_packed_public_prefix(MascotContext& context,
    const packed::PackedModel& model, const BatchedValidationBinding& binding,
    std::span<const AuthScalar> candidate, std::span<const AuthScalar> candidate_checks,
    size_t batch) {
    context.require_healthy();
    std::string identity, coin;
    size_t residual_count = 0;
    try {
        const auto& m = model.metadata();
        model.check_backing_unchanged();
        if (m.prefix_mode != packed::PrefixMode::KnownPublic || batch == 0 ||
            binding.model_identity != model.identity() || binding.source_identity != m.source_sha256 ||
            binding.matrix_identity != m.matrix_fingerprint ||
            candidate.size() != add(checked_size(m.instances), checked_size(m.witnesses)) ||
            candidate_checks.size() != binding.expected_trace_private_checks ||
            m.public_prefix.size() != m.instances || m.public_prefix[0] != Fr(1))
            throw std::runtime_error("packed-public-validation-shape-or-identity");
        if (OnlineOptions::singleton.has_option("insecure") ||
            OnlineOptions::singleton.has_option("zero_seed") ||
            OnlineOptions::singleton.has_option("allow_zero_seed") ||
            OnlineOptions::singleton.has_option("debug_mac") ||
            OnlineOptions::singleton.has_option("output_mac"))
            throw std::runtime_error("packed-validation-insecure-option");
        hash_format(binding.attempt_identity);
        context.consume_validation_attempt(binding.attempt_identity);
        std::vector<AuthScalar> assignment(candidate.begin(), candidate.end());
        const std::vector<AuthScalar> checks(candidate_checks.begin(), candidate_checks.end());
        const auto rows = checked_size(m.constraints);
        const auto total = add(add(rows, checks.size()), checked_size(m.instances));
        std::vector<AuthScalar> residuals;
        residuals.reserve(total);
        std::vector<AuthScalar> left, right, c;
        left.reserve(std::min(batch, rows)); right.reserve(std::min(batch, rows)); c.reserve(std::min(batch, rows));
        auto a_cursor = model.rows(0), b_cursor = model.rows(1), c_cursor = model.rows(2);
        SparseRow a_row, b_row, c_row;
        const auto flush = [&] {
            if (left.empty()) return;
            const auto products = context.multiply_batch(left, right);
            for (size_t i = 0; i < products.size(); ++i) residuals.push_back(products[i] - c[i]);
            left.clear(); right.clear(); c.clear();
        };
        for (size_t row = 0; row < rows; ++row) {
            if (!a_cursor.next(a_row) || !b_cursor.next(b_row) || !c_cursor.next(c_row))
                throw std::runtime_error("packed-missing-validation-row");
            left.push_back(evaluate_linear(a_row, assignment));
            right.push_back(evaluate_linear(b_row, assignment));
            c.push_back(evaluate_linear(c_row, assignment));
            if (left.size() == batch) flush();
        }
        flush();
        if (a_cursor.next(a_row) || b_cursor.next(b_row) || c_cursor.next(c_row))
            throw std::runtime_error("packed-extra-validation-row");
        residuals.insert(residuals.end(), checks.begin(), checks.end());
        residuals.push_back(assignment[0] - context.public_constant(Fr(1)));
        for (size_t i = 1; i < m.public_prefix.size(); ++i)
            residuals.push_back(assignment[i] - context.public_constant(m.public_prefix[i]));
        const std::vector<AuthScalar> frozen = std::move(residuals);
        residual_count = frozen.size();
        if (residual_count != total || bigint(residual_count) >= fr_modulus())
            throw std::runtime_error("packed-validation-residual-count");
        const auto agreed = binding_text(model, binding, residual_count, batch, context.failure_epoch());
        identity = sha256_hex(bytes(agreed));
        receipt(binding, "FrozenResiduals", identity, coin, residual_count);
        context.report_public_phase("packed-residuals-frozen");
        context.check_field_pending();
        context.agree_public_bytes("packed-frozen-assignment-binding", bytes(agreed));
        receipt(binding, "PendingChecksPassed", identity, coin, residual_count);
        context.report_public_phase("packed-pending-checks-passed");
        CheckedFrContribution contribution;
        Create_Random(contribution, context.player());
        context.player().Check_Broadcast();
        const auto challenge = contribution.public_value();
        coin = canonical_fr(challenge);
        const auto coin_binding = identity + "\n" + coin + "\n";
        context.agree_public_bytes("packed-coin-and-binding", bytes(coin_binding));
        receipt(binding, "CoinAgreed", identity, coin, residual_count);
        context.report_public_phase("packed-coin-agreed");
        AuthScalar z;
        Fr power(1);
        for (const auto& residual : frozen) { z += residual * power; power *= challenge; }
        const bigint exponent(fr_modulus() - 1);
        auto nonzero = context.public_constant(Fr(1));
        auto base = z;
        const auto bits = mpz_sizeinbase(exponent.get_mpz_t(), 2);
        for (size_t bit = 0; bit < bits; ++bit) {
            if (mpz_tstbit(exponent.get_mpz_t(), bit)) {
                const std::array<AuthScalar, 1> a{nonzero}, b{base};
                nonzero = context.multiply_batch(a, b).at(0);
            }
            if (bit + 1 < bits) {
                const std::array<AuthScalar, 1> square{base};
                base = context.multiply_batch(square, square).at(0);
            }
        }
        const std::array<AuthScalar, 1> validity{context.public_constant(Fr(1)) - nonzero};
        const auto opened = context.open_public_checked(validity);
        if (opened.size() != 1 || opened[0] != Fr(1))
            throw std::runtime_error("invalid-packed-extended-assignment");
        model.check_backing_unchanged();
        receipt(binding, "PrivateZeroTestPassed", identity, coin, residual_count);
        context.report_public_phase("packed-private-zero-test-passed");
        return PackedValidatedAssignment(context, model, std::move(assignment), binding,
            identity, coin, residual_count);
    } catch (...) {
        context.poison();
        try { receipt(binding, "Aborted", identity, coin, residual_count); } catch (...) {}
        throw;
    }
}

void PackedValidatedAssignment::consume_public_fixture(MascotContext& context,
                                                       const BatchedValidationBinding& expected) {
    context.require_healthy();
    if (consumed_ || context_ != &context || generation_ != context.generation() ||
        epoch_ != context.failure_epoch() || check_counter_ > context.check_counter() || binding_ != expected ||
        model_.metadata().prefix_mode != packed::PrefixMode::KnownPublic) {
        consumed_ = true; context.poison();
        throw std::runtime_error("packed-validation-capability-refused");
    }
    model_.check_backing_unchanged();
    consumed_ = true;
}

std::vector<AuthScalar> PackedValidatedAssignment::make_h_map(MascotContext& context, size_t batch) const {
    context.require_healthy();
    if (!consumed_ || context_ != &context || generation_ != context.generation() || epoch_ != context.failure_epoch())
        throw std::runtime_error("packed-H-capability-refused");
    return StreamedWitnessMap::compute(context, model_, assignment_, batch);
}
}  // namespace kpi::mpc::financial
