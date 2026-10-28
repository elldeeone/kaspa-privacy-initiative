#pragma once
#include "../batched_assignment.hpp"
#include "../packed/packed_model.hpp"
#include "../proof_codec.hpp"

namespace kpi::mpc::financial {

// The initial factory is a PUBLIC-prefix storage/arithmetic integration gate.
// Secret-derived financial construction and its durable prepared-history ticket
// are separate capabilities; this factory must never admit mode2 by fallback.
class PackedValidatedAssignment {
    const MascotContext* const context_;
    const uint64_t generation_, epoch_, check_counter_;
    const packed::PackedModel model_;
    const std::vector<AuthScalar> assignment_;
    const BatchedValidationBinding binding_;
    const std::string binding_identity_, challenge_;
    const size_t residual_count_;
    bool consumed_ = false;
    PackedValidatedAssignment(MascotContext&, packed::PackedModel,
        std::vector<AuthScalar>, BatchedValidationBinding, std::string, std::string, size_t);
    void consume_public_fixture(MascotContext&, const BatchedValidationBinding&);
    std::vector<AuthScalar> make_h_map(MascotContext&, size_t batch) const;
    friend PackedValidatedAssignment validate_packed_public_prefix(MascotContext&,
        const packed::PackedModel&, const BatchedValidationBinding&,
        std::span<const AuthScalar>, std::span<const AuthScalar>, size_t);
    friend ProofPublic prove_packed_public_fixture(MascotContext&,
        PackedValidatedAssignment&&, const BatchedValidationBinding&, size_t);
public:
    PackedValidatedAssignment(const PackedValidatedAssignment&) = delete;
    PackedValidatedAssignment(PackedValidatedAssignment&&) = delete;
    PackedValidatedAssignment& operator=(const PackedValidatedAssignment&) = delete;
    PackedValidatedAssignment& operator=(PackedValidatedAssignment&&) = delete;
    const std::string& binding_identity() const { return binding_identity_; }
    const std::string& public_challenge() const { return challenge_; }
    size_t residual_count() const { return residual_count_; }
};

PackedValidatedAssignment validate_packed_public_prefix(MascotContext&,
    const packed::PackedModel&, const BatchedValidationBinding&,
    std::span<const AuthScalar> complete_assignment,
    std::span<const AuthScalar> trace_checks, size_t multiplication_batch = 4096);

// Candidate only. The selected driver must verify it independently against the
// exact packed root/VK before publication. Mode2 financial proofs additionally
// require the not-yet-integrated trusted construction/history capabilities.
ProofPublic prove_packed_public_fixture(MascotContext&, PackedValidatedAssignment&&,
    const BatchedValidationBinding&, size_t multiplication_batch = 4096);
}  // namespace kpi::mpc::financial
