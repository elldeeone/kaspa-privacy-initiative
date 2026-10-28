#pragma once
#include "public_model.hpp"

namespace kpi::mpc {
struct ProofPublic;

struct BatchedValidationBinding {
    std::string attempt_identity;
    std::string service_identity;
    std::string history_identity;
    std::string dependency_identity;
    std::string model_identity;
    std::string source_identity;
    std::string matrix_identity;
    std::string trace_identity;
    std::string layout_identity;
    std::string input_map_identity;
    std::string public_context_identity;
    size_t expected_trace_private_checks = 0;
    // Optional local PUBLIC sidecar. It contains the already-public field coin
    // and agreed identities/counts, never a residual or authenticated share.
    std::filesystem::path public_receipt_path;
    bool operator==(const BatchedValidationBinding&) const = default;
};

std::string public_matrix_identity(const PublicModel& model);

// This capability owns independent immutable copies, including a model parsed
// from its pinned bytes. No assignment/share view, constructor from bool,
// serialization, copy or move constructor is exposed. Passing std::move(cap)
// to prove_validated consumes that exact instance once.
class ValidatedAssignment {
    const MascotContext* const context_;
    const uint64_t generation_;
    const uint64_t epoch_;
    const uint64_t validated_check_counter_;
    const PublicModel model_;
    const std::vector<AuthScalar> assignment_;
    const std::vector<AuthScalar> private_checks_;
    const std::vector<AuthScalar> promised_prefix_;
    const BatchedValidationBinding binding_;
    const std::string binding_identity_;
    const std::string challenge_;
    const size_t residual_count_;
    bool consumed_ = false;

    ValidatedAssignment(MascotContext&, PublicModel, std::vector<AuthScalar>,
        std::vector<AuthScalar>, std::vector<AuthScalar>, BatchedValidationBinding,
        std::string binding_identity, std::string challenge, size_t residuals);
    void consume_for_proof(MascotContext&, const BatchedValidationBinding&);
    std::vector<AuthScalar> make_h_map(MascotContext&) const;
    friend ValidatedAssignment validate_batched_public_prefix(MascotContext&,
        const PublicModel&, const BatchedValidationBinding&,
        std::span<const AuthScalar>, std::span<const AuthScalar>);
    friend ProofPublic prove_validated(MascotContext&, ValidatedAssignment&&,
                                      const BatchedValidationBinding&);
public:
    ValidatedAssignment(const ValidatedAssignment&) = delete;
    ValidatedAssignment(ValidatedAssignment&&) = delete;
    ValidatedAssignment& operator=(const ValidatedAssignment&) = delete;
    ValidatedAssignment& operator=(ValidatedAssignment&&) = delete;
    const std::string& binding_identity() const { return binding_identity_; }
    const std::string& public_challenge() const { return challenge_; }
    size_t residual_count() const { return residual_count_; }
    uint64_t validated_check_counter() const { return validated_check_counter_; }
};

// Separately selected ADR-0076 research policy. The promised prefix is derived
// internally from the independently public selected model, never from the
// candidate assignment. This entry point is for public-prefix SHA controls;
// financial secret-derived prefixes need a trusted construction capability.
ValidatedAssignment validate_batched_public_prefix(MascotContext& context,
    const PublicModel& model, const BatchedValidationBinding& binding,
    std::span<const AuthScalar> complete_assignment,
    std::span<const AuthScalar> trace_private_checks);

// This is the only new proof entry point. It admits its proving key from the
// capability's own immutable model rather than accepting mutable key queries.
// The returned candidate still requires independent SNARK and native checks
// before its release by the selected driver.
ProofPublic prove_validated(MascotContext&, ValidatedAssignment&&,
                           const BatchedValidationBinding& expected_binding);
}  // namespace kpi::mpc
