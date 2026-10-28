#pragma once
#include "../history/epoch_ticket.hpp"
#include "../packed/packed_model.hpp"
#include "../proof_codec.hpp"
#include <memory>

namespace kpi::mpc::financial {
class FinancialConstruction;
class FinancialHistoryAccess;
class VerifiedFinancialProof;

// Distinct from every public-prefix experiment. Only a selected immutable
// FinancialConstruction with a live, already claimed durable LOCK can enter.
class FinancialValidatedAssignment {
    const MascotContext* const context_;
    const uint64_t generation_, epoch_, validated_counter_;
    const std::shared_ptr<const FinancialConstruction> construction_;
    const history::AttemptBinding attempt_;
    const history::Digest lock_identity_, seen_identity_;
    const std::string identity_, challenge_;
    const size_t residual_count_, history_assertions_, batch_;
    bool preparation_claimed_ = false;
    bool proof_claimed_ = false;
    std::optional<history::Digest> prepared_effects_;

    FinancialValidatedAssignment(MascotContext&, std::shared_ptr<const FinancialConstruction>,
        history::AttemptBinding, history::Digest, history::Digest,
        std::string, std::string, size_t, size_t, size_t);
    void require_same(MascotContext&, const FinancialConstruction&) const;
    const std::string& verifying_key_identity() const;
    std::array<unsigned char, 128> make_candidate(MascotContext&,
        history::PreparedEpochTicket&);
    friend class FinancialHistoryAccess;
    friend VerifiedFinancialProof prove_and_verify_financial(MascotContext&,
        FinancialValidatedAssignment&&, history::PreparedEpochTicket&&,
        const std::filesystem::path&, const std::filesystem::path&,
        const std::filesystem::path&, const std::filesystem::path&);
public:
    FinancialValidatedAssignment(const FinancialValidatedAssignment&) = delete;
    FinancialValidatedAssignment(FinancialValidatedAssignment&&) = delete;
    FinancialValidatedAssignment& operator=(const FinancialValidatedAssignment&) = delete;
    FinancialValidatedAssignment& operator=(FinancialValidatedAssignment&&) = delete;
    static history::Digest policy_identity();
    static FinancialValidatedAssignment validate(MascotContext&,
        const FinancialConstruction&, size_t multiplication_batch = 4096);
    const std::string& binding_identity() const { return identity_; }
    const std::string& public_challenge() const { return challenge_; }
    size_t residual_count() const { return residual_count_; }
    uint64_t validated_check_counter() const { return validated_counter_; }
};

// Only this friend bridge sees actual owned NF/core/prefix wires. No public
// API accepts a caller NF span, expected prefix vector or already-checked bool.
class FinancialHistoryAccess {
    friend class FinancialValidatedAssignment;
    static std::vector<AuthScalar> unseen_nullifier_assertions(MascotContext&,
        const FinancialConstruction&, const history::LockedAttempt&);
public:
    static history::PreparedEpochTicket prepare(MascotContext&,
        const FinancialConstruction&, FinancialValidatedAssignment&);
    static history::EgressRelease release_verified(MascotContext&,
        VerifiedFinancialProof&&, history::PreparedEpochTicket&&);
};

// No point/byte accessor or serialization exists before durable EGRESS. This
// object can only be created by the selected independent verification path.
class VerifiedFinancialProof {
    const MascotContext* const context_;
    const uint64_t generation_, epoch_;
    const std::shared_ptr<const FinancialConstruction> construction_;
    const history::AttemptBinding attempt_;
    const std::string validation_identity_, construction_identity_;
    const history::Digest effects_;
    const std::array<unsigned char, 128> proof_;
    bool egress_claimed_ = false;
    VerifiedFinancialProof(MascotContext&, std::shared_ptr<const FinancialConstruction>,
        history::AttemptBinding, std::string, std::string, history::Digest,
        std::array<unsigned char, 128>);
    friend class FinancialHistoryAccess;
    friend VerifiedFinancialProof prove_and_verify_financial(MascotContext&,
        FinancialValidatedAssignment&&, history::PreparedEpochTicket&&,
        const std::filesystem::path&, const std::filesystem::path&,
        const std::filesystem::path&, const std::filesystem::path&);
public:
    VerifiedFinancialProof(const VerifiedFinancialProof&) = delete;
    VerifiedFinancialProof(VerifiedFinancialProof&&) = delete;
    VerifiedFinancialProof& operator=(const VerifiedFinancialProof&) = delete;
    VerifiedFinancialProof& operator=(VerifiedFinancialProof&&) = delete;
};

// Paths are only public metadata, stock VK, the selected independent verifier,
// and a role-private candidate file. The verifier's approved binary identity is
// fixed by this financial implementation, not an arbitrary success callback.
VerifiedFinancialProof prove_and_verify_financial(MascotContext&,
    FinancialValidatedAssignment&&, history::PreparedEpochTicket&&,
    const std::filesystem::path& metadata, const std::filesystem::path& vk,
    const std::filesystem::path& independent_verifier,
    const std::filesystem::path& private_candidate_path);
}  // namespace kpi::mpc::financial
