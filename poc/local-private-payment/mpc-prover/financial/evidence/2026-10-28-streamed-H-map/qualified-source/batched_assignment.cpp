#include "batched_assignment.hpp"
#include "auth_fft.hpp"
#include "field_coin.hpp"
#include "Tools/Subroutines.hpp"
#include <array>
#include <fstream>
#include <limits>
#include <memory>
#include <openssl/evp.h>
#include <sstream>
#if defined(INSECURE) || defined(NDEBUG) || defined(DEBUG_MAC) || defined(PRINT_MAC)
#error "Batched validation requires assertions and forbids insecure/secret diagnostics"
#endif

namespace kpi::mpc {
namespace {
void require_hash(const std::string& value) {
    if (value.size() != 64 || value.find_first_not_of("0123456789abcdef") != std::string::npos)
        throw std::runtime_error("batched-validation-binding-format");
}
std::string binding_text(const PublicModel& model, const BatchedValidationBinding& binding,
                         size_t residuals, uint64_t epoch) {
    for (const auto* value : {&binding.attempt_identity, &binding.service_identity,
         &binding.history_identity, &binding.dependency_identity, &binding.model_identity,
         &binding.source_identity, &binding.matrix_identity,
         &binding.trace_identity, &binding.layout_identity, &binding.input_map_identity,
         &binding.public_context_identity, &model.model_identity, &model.source_identity})
        require_hash(*value);
    std::ostringstream out;
    out << "KPI_BATCHED_PRIVATE_ASSIGNMENT_V1\n"
        << "POLICY STOCK_FR_COMMIT_REVEAL_POLYNOMIAL_THEN_EXACT_FERMAT\n"
        << "PREFIX INDEPENDENT_PUBLIC_MODEL_CONSTANTS\n" << FR_MODULUS << '\n';
    for (const auto* value : {&binding.attempt_identity, &binding.service_identity,
         &binding.history_identity, &binding.dependency_identity, &model.model_identity,
         &model.source_identity, &binding.matrix_identity, &binding.trace_identity,
         &binding.layout_identity, &binding.input_map_identity, &binding.public_context_identity})
        out << *value << '\n';
    out << model.num_instance << '\n' << model.num_private << '\n'
        << model.num_constraints << '\n' << binding.expected_trace_private_checks << '\n'
        << residuals << '\n' << epoch << '\n';
    return out.str();
}
std::span<const unsigned char> bytes(const std::string& value) {
    return {reinterpret_cast<const unsigned char*>(value.data()), value.size()};
}
void public_receipt(const BatchedValidationBinding& binding, const char* state,
                    const std::string& identity, const std::string& challenge,
                    size_t count) {
    if (binding.public_receipt_path.empty()) return;
    require_hash(binding.attempt_identity);
    auto temporary = binding.public_receipt_path;
    temporary += ".new";
    std::ofstream out(temporary);
    out << "{\"schema\":\"kpi-batched-validation-public/v1\",\"state\":\"" << state
        << "\",\"attempt\":\"" << binding.attempt_identity
        << "\",\"binding_sha256\":\"" << identity << "\",\"public_challenge\":\""
        << challenge << "\",\"residual_count\":" << count
        << ",\"private_residuals_or_Z_or_shares_exported\":false}\n";
    out.close();
    if (!out) throw std::runtime_error("validation-public-receipt-persistence");
    std::filesystem::rename(temporary, binding.public_receipt_path);
}
}

std::string public_matrix_identity(const PublicModel& model) {
    validate_public_model(model);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> hash(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!hash || EVP_DigestInit_ex(hash.get(), EVP_sha256(), nullptr) != 1)
        throw std::runtime_error("public-matrix-hash-initialization");
    const auto update = [&](std::span<const unsigned char> data) {
        if (EVP_DigestUpdate(hash.get(), data.data(), data.size()) != 1)
            throw std::runtime_error("public-matrix-hash-update");
    };
    const auto count = [&](uint64_t value) {
        std::array<unsigned char, 8> encoded{};
        for (unsigned i = 0; i < 8; ++i) encoded[i] = static_cast<unsigned char>(value >> (8 * i));
        update(encoded);
    };
    const std::string domain("KPINAS/R1CS/v1\0", 15);
    update(bytes(domain));
    for (auto value : {model.num_instance, model.num_private, model.num_constraints}) count(value);
    for (const auto* matrix : {&model.A, &model.B, &model.C}) {
        for (const auto& row : *matrix) {
            count(row.size());
            for (const auto& term : row) {
                bigint value(canonical_fr(term.coefficient));
                std::array<unsigned char, 32> canonical{};
                size_t written = 0;
                mpz_export(canonical.data(), &written, -1, 1, 0, 0, value.get_mpz_t());
                if (written > canonical.size()) throw std::runtime_error("matrix-coefficient-length");
                update(canonical);
                count(term.index);
            }
        }
    }
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned length = 0;
    if (EVP_DigestFinal_ex(hash.get(), digest.data(), &length) != 1 || length != 32)
        throw std::runtime_error("public-matrix-hash-finalization");
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    for (unsigned i = 0; i < length; ++i) {
        result.push_back(digits[digest[i] >> 4]);
        result.push_back(digits[digest[i] & 15]);
    }
    return result;
}

ValidatedAssignment::ValidatedAssignment(MascotContext& context, PublicModel model,
    std::vector<AuthScalar> assignment, std::vector<AuthScalar> checks,
    std::vector<AuthScalar> prefix, BatchedValidationBinding binding,
    std::string identity, std::string challenge, size_t residuals)
    : context_(&context), generation_(context.generation()), epoch_(context.failure_epoch()),
      validated_check_counter_(context.check_counter()), model_(std::move(model)),
      assignment_(std::move(assignment)), private_checks_(std::move(checks)),
      promised_prefix_(std::move(prefix)), binding_(std::move(binding)),
      binding_identity_(std::move(identity)), challenge_(std::move(challenge)), residual_count_(residuals) {}

void ValidatedAssignment::consume_for_proof(MascotContext& context,
                                           const BatchedValidationBinding& expected) {
    context.require_healthy();
    if (consumed_ || context_ != &context || generation_ != context.generation() ||
        epoch_ != context.failure_epoch() || binding_ != expected ||
        context.check_counter() < validated_check_counter_) {
        consumed_ = true;
        context.poison();
        throw std::runtime_error("validated-assignment-capability-refused");
    }
    consumed_ = true;
}

ValidatedAssignment validate_batched_public_prefix(MascotContext& context,
    const PublicModel& candidate_model, const BatchedValidationBinding& binding,
    std::span<const AuthScalar> candidate_assignment,
    std::span<const AuthScalar> candidate_checks) {
    context.require_healthy();
    std::string identity, challenge_text;
    size_t residual_count = 0;
    try {
        if (OnlineOptions::singleton.has_option("insecure") ||
            OnlineOptions::singleton.has_option("zero_seed") ||
            OnlineOptions::singleton.has_option("allow_zero_seed") ||
            OnlineOptions::singleton.has_option("debug_mac") ||
            OnlineOptions::singleton.has_option("output_mac"))
            throw std::runtime_error("batched-validation-insecure-option");
        // Re-parse the pinned public bytes instead of trusting mutable cached
        // rows or group queries in the caller's PublicModel object.
        auto model = parse_public_model(candidate_model.encoded_model);
        if (model.model_identity != candidate_model.model_identity ||
            model.source_identity != candidate_model.source_identity ||
            model.model_identity != binding.model_identity ||
            model.source_identity != binding.source_identity ||
            public_matrix_identity(model) != binding.matrix_identity ||
            candidate_assignment.size() != model.num_instance + model.num_private ||
            candidate_checks.size() != binding.expected_trace_private_checks)
            throw std::runtime_error("batched-validation-shape-or-identity");
        require_hash(binding.attempt_identity);
        context.consume_validation_attempt(binding.attempt_identity);
        // DEEP copies close aliases retained by any earlier builder. No public
        // reference to these vectors is ever returned by the capability.
        std::vector<AuthScalar> assignment(candidate_assignment.begin(), candidate_assignment.end());
        std::vector<AuthScalar> checks(candidate_checks.begin(), candidate_checks.end());
        std::vector<AuthScalar> prefix;
        for (size_t i = 1; i < model.num_instance; ++i)
            prefix.push_back(context.public_constant(model.public_inputs[i]));
        std::vector<AuthScalar> left, right;
        for (size_t row = 0; row < model.num_constraints; ++row) {
            left.push_back(evaluate_linear(model.A[row], assignment));
            right.push_back(evaluate_linear(model.B[row], assignment));
        }
        auto residuals = context.multiply_batch(left, right);
        for (size_t row = 0; row < model.num_constraints; ++row)
            residuals[row] -= evaluate_linear(model.C[row], assignment);
        residuals.insert(residuals.end(), checks.begin(), checks.end());
        residuals.push_back(assignment[0] - context.public_constant(Fr(1)));
        for (size_t i = 1; i < model.num_instance; ++i)
            residuals.push_back(assignment[i] - prefix[i - 1]);
        const std::vector<AuthScalar> frozen_residuals = std::move(residuals);
        residual_count = frozen_residuals.size();
        if (frozen_residuals.empty() || bigint(frozen_residuals.size()) >= fr_modulus())
            throw std::runtime_error("batched-validation-polynomial-degree");
        const auto agreed = binding_text(model, binding, residual_count, context.failure_epoch());
        identity = sha256_hex(bytes(agreed));
        public_receipt(binding, "FrozenResiduals", identity, challenge_text, residual_count);
        context.report_public_phase("batched-residuals-frozen");
        context.check_field_pending();
        context.agree_public_bytes("batched-frozen-assignment-binding", bytes(agreed));
        public_receipt(binding, "PendingChecksPassed", identity, challenge_text, residual_count);
        context.report_public_phase("batched-pending-checks-passed");
        CheckedFrContribution contribution;
        Create_Random(contribution, context.player());
        context.player().Check_Broadcast();
        const Fr challenge = contribution.public_value();
        challenge_text = canonical_fr(challenge);
        const auto challenge_binding = identity + "\n" + challenge_text + "\n";
        context.agree_public_bytes("batched-coin-and-binding", bytes(challenge_binding));
        public_receipt(binding, "CoinAgreed", identity, challenge_text, residual_count);
        context.report_public_phase("batched-coin-agreed");
        AuthScalar combination;
        Fr power(1);
        for (const auto& residual : frozen_residuals) {
            combination += residual * power;
            power *= challenge;
        }
        const bigint exponent(fr_modulus() - 1);
        auto value = context.public_constant(Fr(1));
        auto base = combination;
        const auto bits = mpz_sizeinbase(exponent.get_mpz_t(), 2);
        for (size_t bit = 0; bit < bits; ++bit) {
            if (mpz_tstbit(exponent.get_mpz_t(), bit)) {
                const std::array<AuthScalar, 1> a{value}, b{base};
                value = context.multiply_batch(a, b).at(0);
            }
            if (bit + 1 < bits) {
                const std::array<AuthScalar, 1> square{base};
                base = context.multiply_batch(square, square).at(0);
            }
        }
        const std::array<AuthScalar, 1> validity{context.public_constant(Fr(1)) - value};
        const auto opened = context.open_public_checked(validity);
        if (opened.size() != 1 || opened[0] != Fr(1))
            throw std::runtime_error("invalid-batched-extended-assignment");
        public_receipt(binding, "PrivateZeroTestPassed", identity, challenge_text, residual_count);
        context.report_public_phase("batched-private-zero-test-passed");
        return ValidatedAssignment(context, std::move(model), std::move(assignment),
            std::move(checks), std::move(prefix), binding, identity, challenge_text, residual_count);
    } catch (...) {
        context.poison();
        try { public_receipt(binding, "Aborted", identity, challenge_text, residual_count); }
        catch (...) {}
        throw;
    }
}
}  // namespace kpi::mpc
