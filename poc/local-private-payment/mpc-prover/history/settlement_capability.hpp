#pragma once
#ifdef KPI_HISTORY_UNFUNDED_SETUP
#error "fresh setup and financial settlement authority cannot share a binary"
#endif
#include "epoch_journal.hpp"

namespace kpi::mpc { class MascotContext; }
namespace kpi::mpc::history {

// Public locations only. Expected CASE/receipt/effects/head identities come
// from the durable journal, never from this request. Compiled server policy
// owns mandatory private exclusions; the caller can only add extra exclusions.
struct SettlementPaths {
    std::filesystem::path selection, final_case, outer_receipt, fresh_workspace;
    std::vector<std::filesystem::path> private_directories; // additional only
    Digest birth_start;
};

struct FinalCandidatePaths {
    std::filesystem::path selection, final_case, outer_receipt, fresh_workspace;
    std::vector<std::filesystem::path> private_directories; // additional only
    // Public untrusted selectors, admitted before the actual independent
    // verifier derives and checks the candidate against durable EGRESS.
    Digest case_sha256, receipt_sha256;
};

// ADR0078 public-only continuation. Its fresh context carries no old private
// wires/MAC shares. It can bind FINAL; it cannot settle or clear any lock.
class VerifiedFinalCandidate {
    EpochJournal journal_;
    const MascotContext* const context_;
    const uint64_t generation_, epoch_, sequence_;
    const Digest checkpoint_, lock_identity_;
    const FinalCandidate candidate_;
    const Digest request_, nonce_, evidence_;
    bool consumed_ = false;
    VerifiedFinalCandidate(MascotContext&, EpochJournal&, const PublicSnapshot&,
        FinalCandidate, Digest request, Digest nonce, Digest evidence);
public:
    VerifiedFinalCandidate(const VerifiedFinalCandidate&) = delete;
    VerifiedFinalCandidate(VerifiedFinalCandidate&&) = delete;
    VerifiedFinalCandidate& operator=(const VerifiedFinalCandidate&) = delete;
    VerifiedFinalCandidate& operator=(VerifiedFinalCandidate&&) = delete;
    static VerifiedFinalCandidate acquire_fresh(MascotContext&, EpochJournal&,
                                               const FinalCandidatePaths&);
    void bind(MascotContext&);
    const FinalCandidate& candidate() const { return candidate_; }
};

// No public constructor, serialization, report import, bool or txid entry.
// A production build must compile-pin its reviewed interpreter, outer launcher,
// complete adapter selection and registered history registration. Without all
// four pins acquire_fresh refuses before reading any public or private body.
class VerifiedSettlement {
    EpochJournal journal_;
    const MascotContext* const context_;
    const uint64_t generation_, epoch_, sequence_;
    const Digest checkpoint_;
    const SettlementRecord settlement_;
    // Individual fresh observations can differ across servers. Retain their
    // local bindings without putting them in the shared journal checkpoint.
    const Digest request_, nonce_, evidence_;
    bool consumed_ = false;
    VerifiedSettlement(MascotContext&, EpochJournal&, const PublicSnapshot&,
                       SettlementRecord, Digest request, Digest nonce, Digest evidence);
public:
    VerifiedSettlement(const VerifiedSettlement&) = delete;
    VerifiedSettlement(VerifiedSettlement&&) = delete;
    VerifiedSettlement& operator=(const VerifiedSettlement&) = delete;
    VerifiedSettlement& operator=(VerifiedSettlement&&) = delete;
    static VerifiedSettlement acquire_fresh(MascotContext&, EpochJournal&,
                                            const SettlementPaths&);
    // All three independently acquire/replay the exact candidate and agree its
    // accepting-block identity; local journal+anchor fsync and all-three durable
    // acknowledgements precede successful return. Tombstones are never removed.
    void resolve(MascotContext&);
    const SettlementRecord& evidence() const { return settlement_; }
};
} // namespace kpi::mpc::history
