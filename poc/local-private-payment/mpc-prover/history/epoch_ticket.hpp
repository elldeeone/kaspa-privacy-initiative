#pragma once
#ifdef KPI_HISTORY_UNFUNDED_SETUP
#error "financial MPC history bridge excludes fresh-unfunded setup operations"
#endif
#include "epoch_journal.hpp"
#include "../auth_field.hpp"

namespace kpi::mpc::financial {
// The qualified financial construction/validation implementation owns this
// bridge. It must use actual derived immutable NF/core wires and the same
// validated assignment, never caller-selected wires, prefixes or bools.
class FinancialHistoryAccess;
}

namespace kpi::mpc::history {
class PreparedEpochTicket;
class EgressRelease;

class LockedAttempt {
    EpochJournal journal_;
    const DurableRecord record_;
    const MascotContext* const context_;
    const uint64_t generation_, epoch_, lock_check_counter_;
    const AttemptBinding binding_;
    const Digest binding_identity_, seen_identity_;
    const std::vector<Digest> seen_nullifiers_;
    bool intake_claimed_ = false;
    bool consumed_ = false;
    LockedAttempt(MascotContext&, EpochJournal&, DurableRecord,
                  const PublicSnapshot&, AttemptBinding);
    friend LockedAttempt lock_attempt(MascotContext&, EpochJournal&, const AttemptBinding&);
    friend class PreparedEpochTicket;
    friend class financial::FinancialHistoryAccess;
public:
    LockedAttempt(const LockedAttempt&) = delete;
    LockedAttempt(LockedAttempt&&) = delete;
    LockedAttempt& operator=(const LockedAttempt&) = delete;
    LockedAttempt& operator=(LockedAttempt&&) = delete;
    const Digest& binding_identity() const { return binding_identity_; }
    const Digest& seen_identity() const { return seen_identity_; }
    const std::vector<Digest>& seen_nullifiers() const { return seen_nullifiers_; }
    const AttemptBinding& binding() const { return binding_; }
    void require_live(MascotContext&, const AttemptBinding&) const;
    // Financial owner intake claims the exact capability once. Failure leaves
    // durable LOCK unchanged; no RAII destructor clears an unresolved attempt.
    void claim_owner_intake(MascotContext&, const AttemptBinding&);
};

LockedAttempt lock_attempt(MascotContext&, EpochJournal&, const AttemptBinding&);

class PreparedEpochTicket {
    EpochJournal journal_;
    const DurableRecord record_;
    const MascotContext* const context_;
    const uint64_t generation_, epoch_, validation_check_counter_;
    const AttemptBinding binding_;
    const Digest binding_identity_, effects_;
    const std::string validated_binding_, construction_binding_;
    bool consumed_ = false;

    // FinancialHistoryAccess first performs private actual-NF admission joined
    // with full validity, then journal_.prepare(lock.record_, actual_effects).
    // This constructor rechecks that local durable record and itself performs
    // all-three PREPARED agreement. No success Boolean is an argument.
    PreparedEpochTicket(MascotContext&, LockedAttempt&&, DurableRecord,
        Digest actual_effects, std::string validated_binding,
        std::string construction_binding, uint64_t validation_check_counter);
    friend class financial::FinancialHistoryAccess;
    friend class EgressRelease;
    EpochJournal share_journal() const { return EpochJournal(journal_.core_); }
public:
    PreparedEpochTicket(const PreparedEpochTicket&) = delete;
    PreparedEpochTicket(PreparedEpochTicket&&) = delete;
    PreparedEpochTicket& operator=(const PreparedEpochTicket&) = delete;
    PreparedEpochTicket& operator=(PreparedEpochTicket&&) = delete;
    const Digest& binding_identity() const { return binding_identity_; }
    const Digest& effects() const { return effects_; }
    const std::string& validated_binding() const { return validated_binding_; }
    const std::string& construction_binding() const { return construction_binding_; }

    void consume_for_proof(MascotContext&, const AttemptBinding&,
        const std::string& validated_binding, const std::string& construction_binding,
        const Digest& actual_effects);
};

class EgressRelease {
    EpochJournal journal_;
    const DurableRecord record_;
    const MascotContext* const context_;
    const uint64_t generation_, epoch_;
    const AttemptBinding binding_;
    const Digest binding_identity_;
    const EgressPacket packet_;
    const std::vector<unsigned char> core_, aggregate_proof_, projection_;
    bool final_bound_ = false;

    // Only the qualified bridge calls this after actual independent aggregate
    // proof verification and all field/group MAC checks. It must open exactly
    // its immutable construction's core; no external caller bytes/flags enter.
    EgressRelease(MascotContext&, PreparedEpochTicket&&,
        std::span<const unsigned char> actual_core10364,
        std::span<const unsigned char> verified_aggregate_proof128,
        std::span<const unsigned char> actual_projection10685);
    DurableRecord bind_final_candidate(MascotContext&, const FinalCandidate&);
    friend class financial::FinancialHistoryAccess;
public:
    EgressRelease(const EgressRelease&) = delete;
    EgressRelease(EgressRelease&&) = delete;
    EgressRelease& operator=(const EgressRelease&) = delete;
    EgressRelease& operator=(EgressRelease&&) = delete;
    const EgressPacket& packet() const { return packet_; }
    const Digest& binding_identity() const { return binding_identity_; }
    // A complete object exists only after all-three durable EGRESS agreement.
    std::span<const unsigned char> core() const { return core_; }
    std::span<const unsigned char> aggregate_proof() const { return aggregate_proof_; }
    std::span<const unsigned char> projection() const { return projection_; }
};
} // namespace kpi::mpc::history
