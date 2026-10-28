// PUBLIC STORAGE-ONLY FIXTURE. No production settlement capability/header,
// MPC, proof verifier, node or financial authority is linked into this binary.
#if !defined(KPI_HISTORY_UNFUNDED_SETUP) || !defined(KPI_HISTORY_SETTLEMENT_STORAGE_ONLY_CONTROLS)
#error "standalone public storage controls only"
#endif
#include "../epoch_journal.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

// This separate fixture exercises the private storage primitive only. The
// production header rejects KPI_HISTORY_UNFUNDED_SETUP and defines a different
// complete class; this fixture cannot be linked as financial authority.
namespace kpi::mpc::history {
class VerifiedSettlement {
public:
    static DurableRecord append(EpochJournal& j,const SettlementRecord& r,uint64_t seq,const Digest& cp,FailureOnlyHook hook={}){
        return j.record_verified_settlement(r,seq,cp,hook);
    }
    static void storage(EpochJournal& j,const std::filesystem::path& local,const std::filesystem::path& anchor,const Digest& reg){j.require_fixed_storage(local,anchor,reg);}
};
}
using namespace kpi::mpc::history;
namespace {
std::vector<std::string> passed;
void check(bool v){if(!v)throw std::runtime_error("storage control failed");}
template<class F>void refuses(F&& f){bool denied=false;try{f();}catch(const Refused&){denied=true;}check(denied);}
Digest label(const std::string& s){return digest({reinterpret_cast<const unsigned char*>(s.data()),s.size()});}
EpochKey key(){return {label("chain"),label("pool"),label("domain"),label("profile"),label("service"),label("epoch"),{label("cert0"),label("cert1"),label("cert2")}};}
AttemptBinding job(const std::string& name){
    AttemptBinding a{label(name),label("cohort"),label("contracts"),label("model"),label("source"),label("deps"),label("matrix"),label("trace"),label("layout"),label("inputmap"),label("prefix"),label("policy"),label("head"),{},{},6000000000};
    auto point=label("nonpalindromic-point");std::copy(point.begin(),point.end(),a.old_point.begin());a.old_point[32]=7;
    std::copy_n("KPBAST01",8,a.old_state.begin());auto d=key().domain;std::copy(d.begin(),d.end(),a.old_state.begin()+8);
    a.old_spk[2]=0xaa;a.old_spk[3]=0x20;a.old_spk[36]=0x87;a.immutable_tail=label("tail");a.native_parameters=label("parameters");return a;
}
EgressPacket packet(){EgressPacket p{label("effects"),label("core"),label("aggregate"),label("projection"),{label("nf0"),label("nf1"),label("nf2")}};std::sort(p.nullifiers.begin(),p.nullifiers.end());return p;}
FinalCandidate candidate(){return {label("case"),label("canonical"),label("projection"),label("parameters"),label("image"),label("journal"),label("receipt"),label("native-proof")};}
struct Store {
    std::filesystem::path local,anchor;
    Store(const std::filesystem::path& root,const std::string& name):local(root/(name+"-journal")),anchor(root/(name+"-anchor")){
        for(const auto& p:{local,anchor}){check(std::filesystem::create_directory(p));check(::chmod(p.c_str(),0700)==0);}
    }
    EpochJournal fresh(){return EpochJournal::initialize_fresh_unfunded(local,anchor,key(),label("registered-public-storage-fixture"));}
    EpochJournal open(){return EpochJournal::open_existing(local,anchor,key(),label("registered-public-storage-fixture"));}
};
SettlementRecord ready_candidate(EpochJournal& j){
    auto locked=j.lock(job("round1"));auto prep=j.prepare(locked,label("effects"));auto egress=j.record_egress(prep,packet());(void)j.bind_final_candidate(egress,candidate());
    const auto s=j.snapshot();return {*s.lock_identity,s.attempt->attempt,s.checkpoint,digest(encode(*s.candidate)),s.candidate->raw_case,s.egress->projection,label("adapter-selection"),label("real-acceptance-placeholder-STORAGE-ONLY")};
}
void success(const char* s){passed.emplace_back(s);}
}
int main(int argc,char** argv){try{
    check(argc==2);const auto root=std::filesystem::path(argv[1]);check(!std::filesystem::exists(root));check(std::filesystem::create_directory(root));check(::chmod(root.c_str(),0700)==0);
    Store primary(root,"primary");auto j=primary.fresh();const auto record=ready_candidate(j);const auto final=j.snapshot();
    check(final.lock_identity&&*final.lock_identity==record.lock_identity);success("durable-lock-agreement-identity-reconstructed");
    for(unsigned field=0;field<6;++field){auto bad=record;switch(field){case 0:bad.lock_identity[0]^=1;break;case 1:bad.attempt[0]^=1;break;case 2:bad.final_checkpoint[0]^=1;break;case 3:bad.candidate[0]^=1;break;case 4:bad.raw_case[0]^=1;break;case 5:bad.projection[0]^=1;break;}
        refuses([&]{(void)VerifiedSettlement::append(j,bad,final.sequence,final.checkpoint);});}
    refuses([&]{(void)VerifiedSettlement::append(j,record,final.sequence-1,final.checkpoint);});success("wrong-lock-attempt-checkpoint-candidate-case-projection-and-stale-record-refused");
    auto local=VerifiedSettlement::append(j,record,final.sequence,final.checkpoint);check(local.phase()==Phase::Ready);
    auto settled=j.snapshot();check(settled.phase==Phase::Ready&&!settled.attempt&&!settled.egress&&!settled.candidate&&settled.last_settlement==record&&settled.seen_nullifiers==final.seen_nullifiers&&settled.seen_identity==final.seen_identity);success("storage-settled-retains-all-public-NF-tombstones");
    refuses([&]{(void)VerifiedSettlement::append(j,record,final.sequence,final.checkpoint);});success("settlement-append-one-use-stale-replay-refused");
    auto reopened=primary.open();check(reopened.snapshot().last_settlement==record&&reopened.snapshot().seen_identity==final.seen_identity);success("actual-restart-retains-settlement-and-tombstones");
    const auto before=reopened.snapshot();const auto round2job=job("round2");const auto round2identity=lock_agreement_identity(before,round2job);auto round2=reopened.lock(round2job);
    check(reopened.snapshot().lock_identity==round2identity&&reopened.snapshot().seen_nullifiers==final.seen_nullifiers);success("sequential-second-lock-joins-full-history-and-retains-NFs");
    auto prep2=reopened.prepare(round2,label("effects"));auto duplicate=reopened.record_egress(prep2,packet());check(duplicate.phase()==Phase::ExposureConflict);success("released-NF-reuse-after-settlement-enters-irreversible-conflict");
    Store a(root,"deterministic-a"),b(root,"deterministic-b");auto ja=a.fresh();auto jb=b.fresh();auto ra=ready_candidate(ja);auto rb=ready_candidate(jb);check(ra==rb);auto sa=ja.snapshot();auto sb=jb.snapshot();
    (void)VerifiedSettlement::append(ja,ra,sa.sequence,sa.checkpoint);(void)VerifiedSettlement::append(jb,rb,sb.sequence,sb.checkpoint);check(ja.snapshot().checkpoint==jb.snapshot().checkpoint);success("independent-local-observations-share-canonical-settlement-checkpoint");
    Store clone(root,"clone");{auto c=clone.fresh();(void)c;}
    auto cloned=clone.open();refuses([&]{VerifiedSettlement::storage(cloned,a.local,a.anchor,label("registered-public-storage-fixture"));});success("same-key-registration-cloned-store-path-refused");
    for(auto boundary:{WriteBoundary::JournalWritten,WriteBoundary::JournalSynced,WriteBoundary::AnchorWritten,WriteBoundary::AnchorSynced}){
        Store crash(root,"crash"+std::to_string(static_cast<unsigned>(boundary)));{auto c=crash.fresh();(void)ready_candidate(c);}
        auto pid=::fork();check(pid>=0);if(pid==0){auto c=crash.open();const auto s=c.snapshot();const auto r=SettlementRecord{*s.lock_identity,s.attempt->attempt,s.checkpoint,digest(encode(*s.candidate)),s.candidate->raw_case,s.egress->projection,label("adapter-selection"),label("acceptance-STORAGE-ONLY")};
            (void)VerifiedSettlement::append(c,r,s.sequence,s.checkpoint,[&](auto at){if(at==boundary)::_exit(91);});::_exit(92);}
        int status=0;check(::waitpid(pid,&status,0)==pid&&WIFEXITED(status)&&WEXITSTATUS(status)==91);
        try{auto c=crash.open();check(c.snapshot().phase==Phase::Ready&&c.snapshot().seen_nullifiers==final.seen_nullifiers);}catch(const Refused&){}
    }success("actual-process-crash-all-four-settlement-write-boundaries-safe-or-halt");
    Store partial(root,"partial-peer");auto jp=partial.fresh();(void)ready_candidate(jp);check(jp.snapshot().checkpoint!=ja.snapshot().checkpoint);success("partial-settlement-peer-checkpoints-cannot-agree-next-lock");
    std::cout<<"{\"schema\":\"settlement-storage-controls/v1\",\"financial_authority_or_live_verification\":false,\"count\":"<<passed.size()<<",\"passed\":[";for(size_t i=0;i<passed.size();++i){if(i)std::cout<<',';std::cout<<'"'<<passed[i]<<'"';}std::cout<<"]}\n";
}catch(...){std::cerr<<"storage controls refused\n";return 1;}}
