#include "../epoch_journal.hpp"
#include <algorithm>
#include <csignal>
#include <fstream>
#include <iostream>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace kpi::mpc::history;
namespace {
template<class T> concept HasBoolResolve = requires(T& value) { value.resolve(true); };
template<class T> concept HasTxidAccept = requires(T& value) { value.accept(std::string{}); };
template<class T> concept HasReset = requires(T& value) { value.reset(); };
static_assert(!HasBoolResolve<EpochJournal> && !HasTxidAccept<EpochJournal> && !HasReset<EpochJournal>);
std::vector<std::string> passed;
void check(bool value) { if (!value) throw std::runtime_error("control expectation failed"); }
template<class F> void refuses(F&& call) { bool denied=false;try{call();}catch(const Refused&){denied=true;}check(denied); }
Digest label(const std::string& value) {return digest(std::span(reinterpret_cast<const unsigned char*>(value.data()),value.size()));}
EpochKey key() {return {label("chain"),label("pool"),label("domain"),label("profile"),label("service"),label("epoch"),{label("server0"),label("server1"),label("server2")}};}
AttemptBinding job(const std::string& name="attempt") {
    AttemptBinding v{label(name),label("cohort"),label("contracts"),label("model"),label("source"),label("dependencies"),label("matrix"),label("trace"),label("layout"),label("inputmap"),label("prefix"),label("validation"),label("accepted-head"),{}, {},6000000000ULL};
    auto point=label("nonpalindromic-point");std::copy(point.begin(),point.end(),v.old_point.begin());v.old_point[32]=7;
    std::copy_n("KPBAST01",8,v.old_state.begin());auto domain=key().domain;std::copy(domain.begin(),domain.end(),v.old_state.begin()+8);
    v.old_spk[2]=0xaa;v.old_spk[3]=0x20;v.old_spk[36]=0x87;auto script=label("public-dummy-script");std::copy(script.begin(),script.end(),v.old_spk.begin()+4);
    v.immutable_tail=label("immutable-tail");v.native_parameters=label("native-parameters");return v;
}
EgressPacket packet() {
    EgressPacket p{label("effects"),label("core"),label("aggregate"),label("projection"),{label("nf0"),label("nf1"),label("nf2")}};
    std::sort(p.nullifiers.begin(),p.nullifiers.end());return p;
}
FinalCandidate candidate() {return {label("rawcase"),label("canonicalcase"),label("projection"),label("selection"),label("image"),label("journal"),label("receipt"),label("nativeproof")};}
struct Paths {
    std::filesystem::path local,anchor;
    Paths(const std::filesystem::path& root,const std::string& name) :local(root/name/"local"),anchor(root/name/"anchor") {
        std::filesystem::create_directories(local);std::filesystem::create_directories(anchor);
        check(::chmod(local.c_str(),0700)==0&&::chmod(anchor.c_str(),0700)==0);
    }
    EpochJournal fresh() const {return EpochJournal::initialize_fresh_unfunded(local,anchor,key(),label("trusted-registration"));}
    EpochJournal reopen() const {return EpochJournal::open_existing(local,anchor,key(),label("trusted-registration"));}
};
std::vector<unsigned char> bytes(const std::filesystem::path& path) {std::ifstream s(path,std::ios::binary);return {std::istreambuf_iterator<char>(s),{}};}
void overwrite(const std::filesystem::path& path,const std::vector<unsigned char>& value) {std::ofstream s(path,std::ios::binary|std::ios::trunc);s.write(reinterpret_cast<const char*>(value.data()),value.size());check(bool(s));}
void child_done(pid_t pid,int expected) {int status=0;check(::waitpid(pid,&status,0)==pid&&WIFEXITED(status)&&WEXITSTATUS(status)==expected);}
void success(const std::string& name) {passed.push_back(name);}
}

int main(int argc,char** argv) {
    try {
        check(argc==2);const auto root=std::filesystem::path(argv[1]);check(!std::filesystem::exists(root));std::filesystem::create_directory(root);check(::chmod(root.c_str(),0700)==0);
        {
            Paths p(root,"normal");auto j=p.fresh();check(j.snapshot().phase==Phase::Ready&&j.snapshot().sequence==0);success("fresh-unfunded-durable-genesis");
            const auto journal0=bytes(p.local/"journal.bin"),anchor0=bytes(p.anchor/"latest.bin");
            refuses([&]{(void)p.fresh();});check(bytes(p.local/"journal.bin")==journal0&&bytes(p.anchor/"latest.bin")==anchor0);success("no-reinitialize-or-overwrite");
            auto lock=j.lock(job());check(lock.phase()==Phase::Locked&&j.snapshot().sequence==1);success("durable-lock");
            for (unsigned index = 0; index < 7; ++index) {
                auto changed=job("new-attempt-"+std::to_string(index));
                if(index==1)changed.cohort=label("changed-cohort");
                if(index==2)changed.prefix_recipe=label("changed-effects-recipe");
                if(index>=3){changed.admitted_head=label("changed-head-"+std::to_string(index));changed.old_point[0]^=index;changed.old_reserve-=index;}
                refuses([&]{(void)j.lock(changed);});
            }
            success("changed-nonce-cohort-recipe-head-cannot-reset-lock");
            auto prepared=j.prepare(lock,label("effects"));refuses([&]{(void)j.prepare(lock,label("effects"));});success("stale-local-record-refused");
            auto bad=packet();bad.effects=label("wrong-effects");refuses([&]{(void)j.record_egress(prepared,bad);});check(j.snapshot().phase==Phase::Prepared);success("wrong-effects-refused");
            bad=packet();bad.nullifiers[1]=bad.nullifiers[0];refuses([&]{(void)j.record_egress(prepared,bad);});
            bad=packet();std::swap(bad.nullifiers[0],bad.nullifiers[2]);refuses([&]{(void)j.record_egress(prepared,bad);});
            bad=packet();bad.nullifiers[0]={};refuses([&]{(void)j.record_egress(prepared,bad);});success("duplicate-unsorted-zero-NF-refused");
            const auto actual_packet=packet();auto egress=j.record_egress(prepared,actual_packet);auto current=j.snapshot();check(current.seen_nullifiers==std::vector<Digest>(actual_packet.nullifiers.begin(),actual_packet.nullifiers.end()));success("durable-public-NF-tombstones");
            auto wrong=candidate();wrong.projection=label("wrong-projection");refuses([&]{(void)j.bind_final_candidate(egress,wrong);});success("wrong-projection-final-case-refused");
            auto final=j.bind_final_candidate(egress,candidate());check(final.phase()==Phase::FinalCandidate);auto reopened=p.reopen();check(reopened.snapshot().phase==Phase::FinalCandidate&&reopened.snapshot().seen_nullifiers==current.seen_nullifiers);success("restart-retains-final-candidate-and-NFs");
            refuses([&]{(void)reopened.lock(job("after-final-candidate"));});success("final-candidate-remains-unresolved-no-resolve-API");
            Paths other(root,"same-key-separate-instance");auto j2=other.fresh();(void)j2.lock(job());refuses([&]{(void)j2.prepare(lock,label("effects"));});success("cross-journal-receipt-refused");
        }
        {
            Paths p(root,"missing");auto j=p.fresh();(void)j;std::filesystem::remove(p.local/"journal.bin");std::filesystem::remove(p.anchor/"latest.bin");refuses([&]{(void)p.reopen();});check(!std::filesystem::exists(p.local/"journal.bin")&&!std::filesystem::exists(p.anchor/"latest.bin"));success("both-history-and-anchor-loss-no-auto-init");
        }
        {
            Paths p(root,"rollback");auto j=p.fresh();const auto old=bytes(p.anchor/"latest.bin");(void)j.lock(job());overwrite(p.anchor/"latest.bin",old);refuses([&]{(void)p.reopen();});success("checkpoint-rollback-refused");
        }
        {
            Paths p(root,"history-rollback");auto j=p.fresh();const auto old=bytes(p.local/"journal.bin");(void)j.lock(job());overwrite(p.local/"journal.bin",old);refuses([&]{(void)p.reopen();});success("journal-rollback-refused");
        }
        {
            Paths p(root,"wrong-identity");auto j=p.fresh();(void)j;auto changed=key();changed.pool=label("other-pool");refuses([&]{(void)EpochJournal::open_existing(p.local,p.anchor,changed,label("trusted-registration"));});refuses([&]{(void)EpochJournal::open_existing(p.local,p.anchor,key(),label("other-registration"));});success("wrong-pool-registration-refused");
        }
        {
            Paths p(root,"hardlink");auto j=p.fresh();check(::link((p.local/"journal.bin").c_str(),(p.local/"alias").c_str())==0);refuses([&]{(void)j.snapshot();});success("hardlink-alias-refused");
        }
        {
            Paths p(root,"symlink");auto j=p.fresh();(void)j;auto alias=root/"symlink-alias";std::filesystem::create_directory_symlink(p.local,alias);refuses([&]{(void)EpochJournal::open_existing(alias,p.anchor,key(),label("trusted-registration"));});success("symlink-path-refused");
        }
        {
            Paths p(root,"path-substitution");auto j=p.fresh();std::filesystem::rename(p.local,p.local.string()+"-old");std::filesystem::create_directory(p.local);check(::chmod(p.local.c_str(),0700)==0);refuses([&]{(void)j.snapshot();});success("directory-inode-substitution-refused");
        }
        for(auto boundary:{WriteBoundary::JournalWritten,WriteBoundary::JournalSynced,WriteBoundary::AnchorWritten,WriteBoundary::AnchorSynced}) {
            Paths p(root,"crash-"+std::to_string(static_cast<int>(boundary)));{auto initial=p.fresh();(void)initial;}
            const auto pid=::fork();check(pid>=0);if(pid==0){auto j=p.reopen();(void)j.lock(job(),[&](auto at){if(at==boundary)::_exit(91);});::_exit(92);}child_done(pid,91);
            try {auto j=p.reopen();check(j.snapshot().phase==Phase::Locked);refuses([&]{(void)j.lock(job("new-after-crash"));});}catch(const Refused&){}
            success("actual-process-crash-boundary-"+std::to_string(static_cast<int>(boundary)));
        }
        {
            Paths p(root,"partial-write");{auto j=p.fresh();(void)j;}const auto size=std::filesystem::file_size(p.local/"journal.bin");auto pid=::fork();check(pid>=0);
            if(pid==0){auto j=p.reopen();std::signal(SIGXFSZ,SIG_IGN);struct rlimit limit{size+4,size+4};if(::setrlimit(RLIMIT_FSIZE,&limit)!=0)::_exit(94);try{(void)j.lock(job());}catch(const Refused&){::_exit(93);}::_exit(95);}child_done(pid,93);refuses([&]{(void)p.reopen();});success("actual-partial-write-error-torn-tail-refused");
        }
        {
            Paths p(root,"actual-fsync-error");
            {
                auto j=p.fresh();
                refuses([&]{(void)j.lock(job(),[&](auto at){
                    if(at!=WriteBoundary::JournalWritten)return;
                    bool closed=false;
                    for(const auto& entry:std::filesystem::directory_iterator("/proc/self/fd")){
                        std::error_code error;auto path=std::filesystem::read_symlink(entry.path(),error);
                        if(!error&&path==p.local/"journal.bin"){
                            check(::close(std::stoi(entry.path().filename().string()))==0);closed=true;break;
                        }
                    }
                    check(closed);
                });});
            }
            refuses([&]{(void)p.reopen();});success("actual-fsync-EBADF-refused-with-unresolved-tail");
        }
        {
            Paths p(root,"concurrent");{auto j=p.fresh();(void)j;}int signal_pipe[2];check(::pipe(signal_pipe)==0);auto pid=::fork();check(pid>=0);
            if(pid==0){::close(signal_pipe[1]);char go=0;if(::read(signal_pipe[0],&go,1)!=1)::_exit(96);auto j=p.reopen();try{(void)j.lock(job("child"));::_exit(0);}catch(const Refused&){::_exit(1);}}
            ::close(signal_pipe[0]);auto j=p.reopen();check(::write(signal_pipe[1],"x",1)==1);::close(signal_pipe[1]);bool won=true;try{(void)j.lock(job("parent"));}catch(const Refused&){won=false;}int status=0;check(::waitpid(pid,&status,0)==pid&&WIFEXITED(status));check((won?1:0)+(WEXITSTATUS(status)==0?1:0)==1);auto reopened=p.reopen();check(reopened.snapshot().phase==Phase::Locked&&reopened.snapshot().sequence==1);success("actual-concurrent-processes-only-one-lock");
        }
        std::cout<<"{\"schema\":\"kpb-history-journal-controls/v1\",\"classification\":\"PUBLIC_UNFUNDED_DURABILITY_COMPONENT_ONLY\",\"financial_settlement_or_MPC_privateNF_qualified\":false,\"count\":"<<passed.size()<<",\"passed\":[";
        for(size_t i=0;i<passed.size();++i){if(i)std::cout<<',';std::cout<<'\"'<<passed[i]<<'\"';}std::cout<<"]}\n";
    } catch (...) {std::cerr<<"history controls refused\n";return 1;}
}
