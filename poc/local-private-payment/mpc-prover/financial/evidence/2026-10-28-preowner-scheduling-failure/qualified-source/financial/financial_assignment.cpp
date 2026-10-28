#include "financial_assignment.hpp"
#include "construction.hpp"
#include "../auth_fft.hpp"
#include "../field_coin.hpp"
#include "Tools/Subroutines.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <sstream>

#if defined(INSECURE) || defined(NDEBUG) || defined(DEBUG_MAC) || defined(PRINT_MAC)
#error "Financial validation retains assertions and every authentication check"
#endif

namespace kpi::mpc::financial {
namespace {
std::span<const unsigned char> bytes(const std::string& value) {
    return {reinterpret_cast<const unsigned char*>(value.data()), value.size()};
}
size_t checked_size(uint64_t value) {
    if (value > std::numeric_limits<size_t>::max()) throw std::runtime_error("financial-size-overflow");
    return static_cast<size_t>(value);
}
size_t plus(size_t a, size_t b) {
    if (a > std::numeric_limits<size_t>::max() - b) throw std::runtime_error("financial-size-overflow");
    return a + b;
}
std::string validation_binding(const FinancialConstruction& construction,
    const history::LockedAttempt& locked, const packed::Metadata& metadata,
    size_t trace_checks, size_t history_checks, size_t residuals, size_t batch, uint64_t epoch) {
    std::ostringstream out;
    out << "KPI_FINANCIAL_IMMUTABLE_ASSIGNMENT_V1\n"
        << "PRIVATE_DERIVED_PREFIX_AND_ALL_RELEASED_NF256_TOMBSTONES\n" << FR_MODULUS << '\n'
        << history::hex(locked.binding_identity()) << '\n' << history::hex(locked.seen_identity()) << '\n'
        << construction.binding_identity() << '\n';
    const auto encoded = history::encode(locked.binding());
    out << sha256_hex(encoded) << '\n' << metadata.instances << '\n' << metadata.witnesses << '\n'
        << metadata.constraints << '\n' << trace_checks << '\n' << history_checks << '\n'
        << residuals << '\n' << batch << '\n' << epoch << '\n';
    return out.str();
}
}

history::Digest FinancialValidatedAssignment::policy_identity() {
    const std::string policy = "KPI_FINANCIAL_PRIVATE_VALIDATION_V1\n"
        "ALL_R1CS_TRACE_HISTORY_NF256_ONE_DERIVED_PREFIX\n"
        "STOCK_CANONICAL_FR_COMMIT_REVEAL_POLYNOMIAL_EXACT_FERMAT\n";
    return history::digest(bytes(policy));
}

FinancialValidatedAssignment::FinancialValidatedAssignment(MascotContext& context,
    std::shared_ptr<const FinancialConstruction> construction, history::AttemptBinding attempt,
    history::Digest lock_identity, history::Digest seen_identity, std::string identity,
    std::string challenge, size_t count, size_t history_checks, size_t batch)
    : context_(&context), generation_(context.generation()), epoch_(context.failure_epoch()),
      validated_counter_(context.check_counter()), construction_(std::move(construction)),
      attempt_(std::move(attempt)), lock_identity_(lock_identity), seen_identity_(seen_identity),
      identity_(std::move(identity)), challenge_(std::move(challenge)), residual_count_(count),
      history_assertions_(history_checks), batch_(batch) {}

void FinancialValidatedAssignment::require_same(MascotContext& context,
                                               const FinancialConstruction& construction) const {
    context.require_healthy();
    construction.require_live(context, attempt_);
    construction_->require_live(context, attempt_);
    if (context_ != &context || generation_ != context.generation() || epoch_ != context.failure_epoch() ||
        context.check_counter() < validated_counter_ ||
        construction.binding_identity() != construction_->binding_identity() ||
        construction.assignment().data() != construction_->assignment().data() ||
        construction.assignment().size() != construction_->assignment().size())
        throw std::runtime_error("financial-construction-capability-mismatch");
}

const std::string& FinancialValidatedAssignment::verifying_key_identity() const {
    return construction_->model().metadata().vk_sha256;
}

std::vector<AuthScalar> FinancialHistoryAccess::unseen_nullifier_assertions(MascotContext& context,
    const FinancialConstruction& construction, const history::LockedAttempt& locked) {
    construction.require_live(context, locked.binding());
    locked.require_live(context, locked.binding());
    std::vector<AuthScalar> assertions;
    if (locked.seen_nullifiers().size() > std::numeric_limits<size_t>::max() / 3)
        throw std::runtime_error("financial-history-count-overflow");
    assertions.reserve(3 * locked.seen_nullifiers().size());
    const auto one = context.public_constant(Fr(1));
    for (size_t owner = 0; owner < 3; ++owner) {
        const auto candidate = construction.nullifier_bits(owner);
        if (candidate.size() != 256) throw std::runtime_error("financial-derived-NF256-shape");
        for (const auto& old : locked.seen_nullifiers()) {
            // Exact equality over all256 bits. Bitness is checked by the SAME
            // complete R1CS/trace validity below; no reduction modulo Fr and
            // no per-owner equality result is opened or logged.
            std::vector<AuthScalar> equal_bits;
            equal_bits.reserve(256);
            for (size_t bit = 0; bit < 256; ++bit) {
                AuthScalar equal = candidate[bit];
                if (((old[bit / 8] >> (bit % 8)) & 1) == 0)
                    equal = one - candidate[bit];
                equal_bits.push_back(equal);
            }
            while (equal_bits.size() > 1) {
                std::vector<AuthScalar> left, right;
                left.reserve(equal_bits.size() / 2); right.reserve(equal_bits.size() / 2);
                for (size_t i = 0; i < equal_bits.size(); i += 2) {
                    left.push_back(equal_bits[i]); right.push_back(equal_bits[i + 1]);
                }
                equal_bits = context.multiply_batch(left, right);
            }
            assertions.push_back(equal_bits.at(0)); // Must be zero (unseen).
        }
    }
    return assertions;
}

FinancialValidatedAssignment FinancialValidatedAssignment::validate(MascotContext& context,
    const FinancialConstruction& construction, size_t multiplication_batch) {
    context.require_healthy();
    try {
        auto& locked = construction.locked_attempt();
        const auto& attempt = locked.binding();
        construction.require_live(context, attempt);
        locked.require_live(context, attempt);
        const auto& model = construction.model();
        const auto& metadata = model.metadata();
        const auto assignment = construction.assignment();
        const auto trace_checks = construction.trace_checks();
        const auto prefix = construction.promised_prefix();
        if (metadata.prefix_mode != packed::PrefixMode::SecretDerivedRecipe ||
            !metadata.public_prefix.empty() || metadata.instances != 3 || prefix.size() != 2 ||
            metadata.derived_output_count != prefix.size() || multiplication_batch == 0 ||
            assignment.size() != plus(checked_size(metadata.instances), checked_size(metadata.witnesses)) ||
            history::hex(attempt.model) != model.identity() || history::hex(attempt.source) != metadata.source_sha256 ||
            history::hex(attempt.matrix) != metadata.matrix_fingerprint ||
            history::hex(attempt.prefix_recipe) != metadata.prefix_recipe_sha256 ||
            history::hex(attempt.layout) != metadata.prefix_layout_sha256 ||
            attempt.validation_policy != policy_identity())
            throw std::runtime_error("financial-validation-policy-or-model");
        if (OnlineOptions::singleton.has_option("insecure") ||
            OnlineOptions::singleton.has_option("zero_seed") ||
            OnlineOptions::singleton.has_option("allow_zero_seed") ||
            OnlineOptions::singleton.has_option("debug_mac") ||
            OnlineOptions::singleton.has_option("output_mac"))
            throw std::runtime_error("financial-validation-insecure-option");
        model.check_backing_unchanged();
        context.consume_validation_attempt(history::hex(attempt.attempt));
        const auto batch = std::min(multiplication_batch, size_t{4096});
        const auto history_checks = FinancialHistoryAccess::unseen_nullifier_assertions(context, construction, locked);
        const auto rows = checked_size(metadata.constraints);
        const auto total = plus(plus(plus(rows, trace_checks.size()), history_checks.size()), 3);
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
                throw std::runtime_error("financial-missing-row");
            left.push_back(evaluate_linear(a_row, assignment)); right.push_back(evaluate_linear(b_row, assignment));
            c.push_back(evaluate_linear(c_row, assignment));
            if (left.size() == batch) flush();
        }
        flush();
        if (a_cursor.next(a_row) || b_cursor.next(b_row) || c_cursor.next(c_row))
            throw std::runtime_error("financial-extra-row");
        residuals.insert(residuals.end(), trace_checks.begin(), trace_checks.end());
        residuals.insert(residuals.end(), history_checks.begin(), history_checks.end());
        residuals.push_back(assignment[0] - context.public_constant(Fr(1)));
        for (size_t i = 0; i < prefix.size(); ++i) residuals.push_back(assignment[1 + i] - prefix[i]);
        const std::vector<AuthScalar> frozen = std::move(residuals);
        if (frozen.size() != total || bigint(total) >= fr_modulus())
            throw std::runtime_error("financial-residual-count");
        const auto agreed = validation_binding(construction, locked, metadata, trace_checks.size(),
            history_checks.size(), total, batch, context.failure_epoch());
        const auto identity = sha256_hex(bytes(agreed));
        context.report_public_phase("financial-residuals-frozen");
        context.check_field_pending();
        context.agree_public_bytes("financial-frozen-construction-history-binding", bytes(agreed));
        context.report_public_phase("financial-pending-checks-passed");
        CheckedFrContribution contribution;
        Create_Random(contribution, context.player());
        context.player().Check_Broadcast();
        const auto challenge = contribution.public_value();
        const auto coin = canonical_fr(challenge);
        const auto coin_binding = identity + "\n" + coin + "\n";
        context.agree_public_bytes("financial-coin-and-binding", bytes(coin_binding));
        context.report_public_phase("financial-coin-agreed");
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
                const std::array<AuthScalar, 1> square{base}; base = context.multiply_batch(square, square).at(0);
            }
        }
        const std::array<AuthScalar, 1> validity{context.public_constant(Fr(1)) - nonzero};
        const auto opened = context.open_public_checked(validity);
        if (opened.size() != 1 || opened[0] != Fr(1))
            throw std::runtime_error("invalid-financial-extended-assignment");
        model.check_backing_unchanged();
        context.report_public_phase("financial-private-zero-test-passed");
        // Private copy shares only the already sealed const storage; unlike a
        // moved public vector, no caller ever held an alias into those wires.
        auto owned = std::shared_ptr<const FinancialConstruction>(new FinancialConstruction(construction));
        return FinancialValidatedAssignment(context, std::move(owned), attempt,
            locked.binding_identity(), locked.seen_identity(), identity, coin, total,
            history_checks.size(), batch);
    } catch (...) { context.poison(); throw; }
}

history::PreparedEpochTicket FinancialHistoryAccess::prepare(MascotContext& context,
    const FinancialConstruction& construction, FinancialValidatedAssignment& validated) {
    context.require_healthy();
    try {
        validated.require_same(context, construction);
        auto& locked = construction.locked_attempt();
        locked.require_live(context, validated.attempt_);
        if (validated.preparation_claimed_ || validated.proof_claimed_ ||
            validated.lock_identity_ != locked.binding_identity() || validated.seen_identity_ != locked.seen_identity())
            throw std::runtime_error("financial-preparation-capability-refused");
        validated.preparation_claimed_ = true;
        const auto prefix = construction.promised_prefix();
        const auto opened = context.open_public_checked(prefix);
        if (opened.size() != 2) throw std::runtime_error("financial-effects-digest-shape");
        history::Digest effects{};
        for (size_t part = 0; part < 2; ++part) {
            bigint value(canonical_fr(opened[part]));
            if (value < 0 || value >= (bigint(1) << 128))
                throw std::runtime_error("financial-effects-limb-range");
            size_t written = 0;
            mpz_export(effects.data() + 16 * part, &written, -1, 1, 0, 0, value.get_mpz_t());
            if (written > 16) throw std::runtime_error("financial-effects-limb-length");
        }
        validated.prepared_effects_ = effects;
        const auto durable = locked.journal_.prepare(locked.record_, effects);
        return history::PreparedEpochTicket(context, std::move(locked), durable, effects,
            validated.identity_, construction.binding_identity(), validated.validated_counter_);
    } catch (...) { context.poison(); throw; }
}
}  // namespace kpi::mpc::financial
