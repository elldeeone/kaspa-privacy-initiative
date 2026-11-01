#include "epoch_ticket.hpp"
#include "../financial/registered_capture_session.hpp"
#include "../financial/registered_attempt_supervisor.hpp"
#include <algorithm>

namespace kpi::mpc::history {
namespace {
using Bytes = std::vector<unsigned char>;
void add(Bytes& out, std::span<const unsigned char> bytes) { out.insert(out.end(), bytes.begin(), bytes.end()); }
void text(Bytes& out, const char* value) { while (*value) out.push_back(*value++); }
void integer(Bytes& out, uint64_t value) { for (unsigned i=0;i<8;++i) out.push_back(value>>(8*i)); }
void need(bool value) { if (!value) throw Refused(); }
void canonical(const std::string& value) { need(unhex(value) != Digest{}); }
Bytes record_binding(const PublicSnapshot& prior,const AttemptBinding& binding) {
    Bytes out; text(out,"KPBH-LOCK-AGREEMENT-01");add(out,encode(prior.key));add(out,encode(binding));
    integer(out,prior.sequence);add(out,prior.checkpoint);add(out,prior.seen_identity);return out;
}
Bytes durable_binding(const char* label,const Digest& identity,const DurableRecord& record) {
    Bytes out;text(out,label);add(out,identity);integer(out,record.sequence());add(out,record.checkpoint());out.push_back(static_cast<unsigned char>(record.phase()));return out;
}
EgressPacket actual_packet(const PublicSnapshot& current,const Digest& effects,
    std::span<const unsigned char> core,std::span<const unsigned char> proof,
    std::span<const unsigned char> projection) {
    need(core.size()==10364&&proof.size()==128&&projection.size()==10685
         &&std::equal(core.begin(),core.begin()+8,"KPBAEF01")
         &&std::equal(projection.begin(),projection.begin()+8,"KPBAFX01")
         &&std::equal(core.begin(),core.end(),projection.begin()+193)
         &&std::equal(proof.begin(),proof.end(),projection.begin()+193+10364)
         &&digest(core)==effects&&current.attempt.has_value());
    const auto& key=current.key;const auto& binding=*current.attempt;
    auto matches=[&](size_t at,std::span<const unsigned char> value){return std::equal(value.begin(),value.end(),core.begin()+at);};
    need(matches(8,key.chain)&&matches(40,key.pool)&&matches(72,key.profile)
         &&matches(104,key.domain)&&matches(136,key.service)&&matches(168,binding.old_point)
         &&matches(204,std::span(binding.old_state).subspan(40,32))
         &&matches(236,std::span(binding.old_state).subspan(76,32))
         &&matches(268,std::span(binding.old_state).subspan(72,4))
         &&matches(272,std::span(binding.old_state).subspan(108,4))
         &&std::equal(binding.old_point.begin(),binding.old_point.end(),projection.begin()+12)
         &&std::equal(binding.old_spk.begin(),binding.old_spk.end(),projection.begin()+66));
    for(unsigned i=0;i<8;++i)need(core[276+i]==static_cast<unsigned char>(binding.old_reserve>>(8*i))
         &&projection[56+i]==core[276+i]);
    EgressPacket packet{effects,digest(core),digest(proof),digest(projection),
                        canonical_history_nullifiers(core)};
    (void)encode(packet);return packet;
}
DurableRecord append_actual_egress(MascotContext& context,EpochJournal& journal,
    const DurableRecord& prepared,const Digest& identity,const EgressPacket& packet) {
    auto local=journal.record_egress(prepared,packet);
    need(local.phase()==Phase::Egress);
    auto agreed=durable_binding("KPBH-DURABLE-EGRESS-01",identity,local);add(agreed,encode(packet));
    context.agree_public_bytes("history-all-three-durable-egress",agreed);return local;
}
}

LockedAttempt::LockedAttempt(MascotContext& context,EpochJournal& journal,DurableRecord record,
    const PublicSnapshot& prior,AttemptBinding binding)
    :journal_(EpochTicketJournalBridge::retain_after_lock(journal,record)),
     record_(std::move(record)),context_(&context),
     generation_(context.generation()),epoch_(context.failure_epoch()),lock_check_counter_(context.check_counter()),
     binding_(std::move(binding)),binding_identity_(lock_agreement_identity(prior,binding_)),
     seen_identity_(prior.seen_identity),seen_nullifiers_(prior.seen_nullifiers) {}

LockedAttempt lock_attempt(MascotContext& context,EpochJournal& journal,const AttemptBinding& binding) {
    try {
        context.require_healthy();const auto prior=journal.snapshot();need(prior.phase==Phase::Ready);
        const auto agreed=record_binding(prior,binding);
        context.agree_public_bytes("history-identity-before-owner-input",agreed);
        const auto local=journal.lock(binding);
        const auto identity=digest(agreed);
        context.agree_public_bytes("history-all-three-durable-lock",durable_binding("KPBH-DURABLE-LOCK-01",identity,local));
        return LockedAttempt(context,journal,local,prior,binding);
    } catch (...) { context.poison();throw Refused(); }
}

EpochJournal EpochTicketJournalBridge::retain_after_lock(
        const EpochJournal& journal, const DurableRecord& record) {
    const auto current = journal.snapshot();
    need(record.core_ == journal.core_ && record.phase_ == Phase::Locked &&
         current.phase == Phase::Locked &&
         current.sequence == record.sequence_ &&
         current.checkpoint == record.checkpoint_);
    return EpochJournal(journal.core_);
}

EpochJournal EpochTicketJournalBridge::retain_after_prepare(
        const EpochJournal& journal, const LockedAttempt& locked,
        const DurableRecord& prepared) {
    const auto current = locked.journal_.snapshot();
    need(!locked.consumed_ &&
         journal.core_ == locked.journal_.core_ &&
         prepared.core_ == locked.journal_.core_ &&
         prepared.core_ == locked.record_.core_ &&
         prepared.phase_ == Phase::Prepared &&
         current.phase == Phase::Prepared &&
         current.sequence == prepared.sequence_ &&
         current.checkpoint == prepared.checkpoint_);
    return EpochJournal(locked.journal_.core_);
}

bool EpochTicketJournalBridge::same_journal(
        const LockedAttempt& locked, const DurableRecord& record) {
    return locked.journal_.core_ == locked.record_.core_ &&
           locked.record_.core_ == record.core_;
}

EpochJournal EpochTicketJournalBridge::retain_prepared(
        const EpochJournal& journal, const PreparedEpochTicket& prepared) {
    const auto current = prepared.journal_.snapshot();
    need(journal.core_ == prepared.journal_.core_ &&
         prepared.journal_.core_ == prepared.record_.core_ &&
         current.phase == Phase::Prepared &&
         current.sequence == prepared.record_.sequence_ &&
         current.checkpoint == prepared.record_.checkpoint_);
    return EpochJournal(prepared.journal_.core_);
}

void LockedAttempt::require_live(MascotContext& context,const AttemptBinding& binding) const {
    try {
        context.require_healthy();need(!consumed_&&context_==&context&&generation_==context.generation()
            &&epoch_==context.failure_epoch()&&context.check_counter()>=lock_check_counter_&&binding_==binding);
        const auto current=journal_.snapshot();
        need(current.attempt==binding_&&current.phase==Phase::Locked&&current.sequence==record_.sequence()
            &&current.checkpoint==record_.checkpoint()&&current.seen_identity==seen_identity_);
    } catch (...) { context.poison();throw Refused(); }
}

void LockedAttempt::claim_owner_intake(MascotContext& context,const AttemptBinding& binding) {
    require_live(context,binding);
    if (intake_claimed_) { context.poison();throw Refused(); }
    intake_claimed_=true;
}

void LockedAttempt::claim_registered_owner_intake(
    MascotContext& context, const AttemptBinding& binding, unsigned role,
    financial::attempt_supervisor::OwnerIntakePermit&& permit) {
    try {
        require_live(context, binding);
        need(!intake_claimed_);
        const auto receipt = permit.consume_for_claim(role);
        need(receipt.role == role &&
             receipt.accepted_head == binding_.admitted_head &&
             receipt.durable_lock == binding_identity_);
        intake_claimed_ = true;
    } catch (...) { context.poison(); throw Refused(); }
}

void FinancialConstructionEpochBridge::claim_owner_intake(
        LockedAttempt& locked, MascotContext& context,
        const AttemptBinding& binding) {
    locked.claim_owner_intake(context, binding);
}

void RegisteredOwnerIntakeBridge::claim_owner_intake(
        LockedAttempt& locked, MascotContext& context,
        const AttemptBinding& binding, unsigned role,
        financial::attempt_supervisor::OwnerIntakePermit&& permit) {
    locked.claim_registered_owner_intake(
        context, binding, role, std::move(permit));
}

PreparedEpochTicket::PreparedEpochTicket(MascotContext& context,LockedAttempt&& locked,DurableRecord prepared,
    Digest effects,std::string validated,std::string construction,uint64_t check_counter)
    :journal_(EpochTicketJournalBridge::retain_after_prepare(
         locked.journal_,locked,prepared)),
     record_(std::move(prepared)),context_(&context),
     generation_(context.generation()),epoch_(context.failure_epoch()),validation_check_counter_(check_counter),
     binding_(locked.binding_),binding_identity_(locked.binding_identity_),effects_(effects),
     validated_binding_(std::move(validated)),construction_binding_(std::move(construction)) {
    try {
        context.require_healthy();canonical(validated_binding_);canonical(construction_binding_);
        need(!locked.consumed_&&locked.intake_claimed_&&locked.context_==&context
            &&locked.generation_==generation_&&locked.epoch_==epoch_
            &&check_counter>=locked.lock_check_counter_&&check_counter<=context.check_counter()
            &&EpochTicketJournalBridge::same_journal(locked,record_)
            &&record_.phase()==Phase::Prepared);
        const auto current=journal_.snapshot();
        need(current.phase==Phase::Prepared&&current.attempt==binding_&&current.effects==effects_
            &&current.sequence==record_.sequence()&&current.checkpoint==record_.checkpoint()
            &&record_.sequence()==locked.record_.sequence()+1&&current.seen_identity==locked.seen_identity_);
        auto agreed=durable_binding("KPBH-DURABLE-PREPARED-01",binding_identity_,record_);
        add(agreed,effects_);add(agreed,unhex(validated_binding_));add(agreed,unhex(construction_binding_));
        context.agree_public_bytes("history-all-three-durable-prepared",agreed);
        locked.consumed_=true;
    } catch (...) { context.poison();throw Refused(); }
}

void PreparedEpochTicket::consume_for_proof(MascotContext& context,const AttemptBinding& binding,
    const std::string& validated,const std::string& construction,const Digest& effects) {
    try {
        context.require_healthy();need(!consumed_&&context_==&context&&generation_==context.generation()
            &&epoch_==context.failure_epoch()&&context.check_counter()>=validation_check_counter_
            &&binding_==binding&&validated_binding_==validated&&construction_binding_==construction&&effects_==effects);
        const auto current=journal_.snapshot();
        need(current.phase==Phase::Prepared&&current.sequence==record_.sequence()
            &&current.checkpoint==record_.checkpoint()&&current.effects==effects_&&current.attempt==binding_);
        consumed_=true;
    } catch (...) { context.poison();throw Refused(); }
}

EgressRelease::EgressRelease(MascotContext& context,PreparedEpochTicket&& prepared,
    std::span<const unsigned char> core,std::span<const unsigned char> proof,
    std::span<const unsigned char> projection,
    financial::registered_driver::RegisteredCaptureSession* capture)
    :journal_(prepared.share_journal()),
     record_([&]{
        try {
            context.require_healthy();need(prepared.consumed_&&prepared.context_==&context
                &&prepared.generation_==context.generation()&&prepared.epoch_==context.failure_epoch()
                &&context.check_counter()>=prepared.validation_check_counter_);
            const auto current=journal_.snapshot();
            need(current.phase==Phase::Prepared&&current.sequence==prepared.record_.sequence()
                &&current.checkpoint==prepared.record_.checkpoint()&&current.attempt==prepared.binding_);
            const auto packet=actual_packet(current,prepared.effects_,core,proof,projection);
            return append_actual_egress(context,journal_,prepared.record_,prepared.binding_identity_,packet);
        } catch (...) {context.poison();throw Refused();}
     }()),context_(&context),generation_(context.generation()),epoch_(context.failure_epoch()),
     binding_(prepared.binding_),binding_identity_(prepared.binding_identity_),
     packet_(actual_packet(journal_.snapshot(),prepared.effects_,core,proof,projection)),
     core_(core.begin(),core.end()),aggregate_proof_(proof.begin(),proof.end()),projection_(projection.begin(),projection.end()) {
    // record_ exists only after exact durable EGRESS plus all-three agreement.
    // Capture therefore observes the genuine released projection, never a
    // caller-supplied pre-egress candidate. Hook failure aborts construction
    // and is poisoned by FinancialHistoryAccess.
    if (capture)
        financial::registered_driver::RegisteredCaptureEgressBridge::
            released_projection(*capture, projection_);
    // P1 retains the exact same durable released projection privately, but
    // does not seal it yet: final-candidate agreement can still use Player.
    // A later typed completion authority must seal after the last MPC event.
    context.capture_released_projection(projection_);
}

DurableRecord EgressRelease::bind_final_candidate(MascotContext& context,const FinalCandidate& candidate) {
    try {
        context.require_healthy();need(!final_bound_&&context_==&context&&generation_==context.generation()
            &&epoch_==context.failure_epoch()&&candidate.projection==packet_.projection);
        auto local=journal_.bind_final_candidate(record_,candidate);
        auto agreed=durable_binding("KPBH-DURABLE-FINAL-01",binding_identity_,local);add(agreed,encode(candidate));
        context.agree_public_bytes("history-all-three-durable-final-candidate",agreed);
        context.complete_p1_capture();
        final_bound_=true;return local;
    } catch (...) {context.poison();throw Refused();}
}
} // namespace kpi::mpc::history
