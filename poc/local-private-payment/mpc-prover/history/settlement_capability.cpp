#include "settlement_capability.hpp"
#include "../auth_field.hpp"
#include <algorithm>
#include <cerrno>
#include <csignal>
#include <climits>
#include <fcntl.h>
#include <map>
#include <openssl/rand.h>
#include <set>
#include <sstream>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace kpi::mpc::history {
namespace {
using Bytes=std::vector<unsigned char>;
void need(bool value){if(!value)throw Refused();}
std::span<const unsigned char> raw(const std::string& s){return {reinterpret_cast<const unsigned char*>(s.data()),s.size()};}
void add(Bytes& b,std::span<const unsigned char> v){b.insert(b.end(),v.begin(),v.end());}
std::string bytes_hex(std::span<const unsigned char> value){const char* digits="0123456789abcdef";std::string out;for(auto b:value){out+=digits[b>>4];out+=digits[b&15];}return out;}
std::string quote(const std::string& value){
    std::string out="\"";const char* digits="0123456789abcdef";
    for(unsigned char b:value){if(b=='"'||b=='\\'){out+='\\';out+=b;}else if(b<32){out+="\\u00";out+=digits[b>>4];out+=digits[b&15];}else out+=b;}
    return out+'"';
}
std::string object(const std::map<std::string,std::string>& v){std::string out="{";for(const auto& [k,x]:v){if(out.size()!=1)out+=',';out+=quote(k)+':'+x;}return out+'}';}
std::string qhex(const Digest& d){return quote(hex(d));}
struct Fd {
    int value=-1;explicit Fd(int fd):value(fd){need(fd>=0);}~Fd(){if(value>=0)::close(value);}
    Fd(const Fd&)=delete;Fd& operator=(const Fd&)=delete;
};
void write_all(int fd,std::span<const unsigned char> bytes){size_t at=0;while(at<bytes.size()){auto n=::write(fd,bytes.data()+at,bytes.size()-at);if(n<0&&errno==EINTR)continue;need(n>0);at+=static_cast<size_t>(n);}}
void sync(int fd){int result;do{result=::fsync(fd);}while(result<0&&errno==EINTR);need(result==0);}
bool inside(const std::filesystem::path& a,const std::filesystem::path& b){auto i=a.begin();for(auto j=b.begin();j!=b.end();++j,++i)if(i==a.end()||*i!=*j)return false;return true;}
void require_private_outer(const std::filesystem::path& workspace){
    const std::filesystem::path marker="/kpb-public-only";struct stat info{};
    need(::lstat(marker.c_str(),&info)<0&&errno==ENOENT
        &&!inside(workspace,marker)&&!inside(marker,workspace));
}
void plain(const std::filesystem::path& path){
    need(path.is_absolute()&&path==path.lexically_normal()&&path.string().find('\0')==std::string::npos);
    for(auto p=path;!p.empty();p=p.parent_path()){need(!std::filesystem::is_symlink(std::filesystem::symlink_status(p)));if(p==p.root_path())break;}
}
using Inode=std::pair<dev_t,ino_t>;
struct Exclusions {
    std::vector<std::filesystem::path> roots;std::set<Inode> inodes;
    explicit Exclusions(const std::vector<std::filesystem::path>& paths):roots(paths){
        need(!roots.empty());
        for(const auto& root:roots){plain(root);need(std::filesystem::is_directory(root));
            // No follow_directory_symlink and no skip_permission_denied. An
            // incomplete metadata inventory refuses; no private body is read.
            for(const auto& entry:std::filesystem::recursive_directory_iterator(root)){
                struct stat info{};need(::lstat(entry.path().c_str(),&info)==0);
                if(S_ISREG(info.st_mode))inodes.emplace(info.st_dev,info.st_ino);
            }
        }
    }
    void public_path(const std::filesystem::path& path,bool directory=false)const{
        plain(path);for(const auto& root:roots)need(!inside(path,root)&&(!directory||!inside(root,path)));
    }
};
bool stable(const struct stat& a,const struct stat& b){return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_size==b.st_size&&a.st_nlink==b.st_nlink&&a.st_mtim.tv_sec==b.st_mtim.tv_sec&&a.st_mtim.tv_nsec==b.st_mtim.tv_nsec&&a.st_ctim.tv_sec==b.st_ctim.tv_sec&&a.st_ctim.tv_nsec==b.st_ctim.tv_nsec;}
Bytes admitted_fd(int fd,const std::filesystem::path& path,const Digest& expected,const Exclusions& excluded){
    excluded.public_path(path);struct stat named{},opened{},after{};
    need(::lstat(path.c_str(),&named)==0&&::fstat(fd,&opened)==0&&S_ISREG(opened.st_mode)
        &&opened.st_nlink==1&&opened.st_size>=0&&stable(named,opened)
        &&!excluded.inodes.contains({opened.st_dev,opened.st_ino}));
    Bytes bytes(static_cast<size_t>(opened.st_size));size_t at=0;
    while(at<bytes.size()){auto n=::pread(fd,bytes.data()+at,bytes.size()-at,at);if(n<0&&errno==EINTR)continue;need(n>0);at+=static_cast<size_t>(n);}
    need(::fstat(fd,&after)==0&&stable(opened,after)&&digest(bytes)==expected);return bytes;
}
Bytes admitted(const std::filesystem::path& path,const Digest& expected,const Exclusions& excluded){
    excluded.public_path(path);struct stat info{};need(::lstat(path.c_str(),&info)==0&&S_ISREG(info.st_mode)&&info.st_nlink==1&&!excluded.inodes.contains({info.st_dev,info.st_ino}));
    Fd fd(::open(path.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));return admitted_fd(fd.value,path,expected,excluded);
}
std::string record(const std::filesystem::path& path,const Digest& sha){return object({{"path",quote(path.string())},{"sha256",qhex(sha)}});}
std::string make_request(const PublicSnapshot& s,const SettlementPaths& p,const Digest& nonce){
    need(s.attempt&&s.effects&&s.egress&&s.candidate&&s.lock_identity);const auto& a=*s.attempt;const auto& e=*s.egress;const auto& c=*s.candidate;
    uint32_t index=0;for(unsigned i=0;i<4;++i)index|=uint32_t(a.old_point[32+i])<<(8*i);
    std::string nfs="[";for(size_t i=0;i<3;++i){if(i)nfs+=',';nfs+=qhex(e.nullifiers[i]);}nfs+=']';
    return object({{"schema",quote("kpb-live-settlement-request/v2")},{"nonce_hex32",qhex(nonce)},
        {"history_key_hex32",qhex(digest(encode(s.key)))},{"attempt_id_hex32",qhex(a.attempt)},
        {"locked_binding_sha256",qhex(*s.lock_identity)},{"prepared_core_sha256",qhex(*s.effects)},
        {"context",object({{"chain_hex32",qhex(s.key.chain)},{"pool_hex32",qhex(s.key.pool)},
            {"profile_hex32",qhex(s.key.profile)},{"domain_hex32",qhex(s.key.domain)},
            {"service_hex32",qhex(s.key.service)},{"epoch_hex32",qhex(s.key.epoch)}})},
        {"head",object({{"outpoint",object({{"transactionId",quote(bytes_hex(std::span(a.old_point).first(32)))},{"index",std::to_string(index)}})},
            {"state_hex112",quote(bytes_hex(a.old_state))},{"reserve_sompi",quote(std::to_string(a.old_reserve))}})},
        {"native_policy",object({{"old_script_public_key_hex37",quote(bytes_hex(a.old_spk))},
            {"immutable_tail_sha256",qhex(a.immutable_tail)},{"native_parameters_sha256",qhex(a.native_parameters)}})},
        {"egress",object({{"core_sha256",qhex(e.core)},{"aggregate_proof_sha256",qhex(e.aggregate_proof)},
            {"projection_sha256",qhex(e.projection)},{"nfs_hex32",nfs}})},
        {"final_candidate",object({{"case",record(p.final_case,c.raw_case)},
            {"canonical_case_sha256",qhex(c.canonical_case)},{"r0_receipt",record(p.outer_receipt,c.outer_receipt)},
            {"selection_sha256",qhex(c.selection)},{"image_hex32",qhex(c.image)},
            {"journal_sha256",qhex(c.journal)},{"native_proof_sha256",qhex(c.native_proof)}})},
        {"birth_start_hash",qhex(p.birth_start)}})+'\n';
}
struct CompiledTrust {
    std::filesystem::path launcher,interpreter;
    Digest launcher_sha,interpreter_sha,selection,registration;
    std::array<std::filesystem::path,3> local,anchor;
};
CompiledTrust compiled_trust(){
#if defined(KPI_HISTORY_SETTLEMENT_LAUNCHER_PATH) && defined(KPI_HISTORY_SETTLEMENT_INTERPRETER_PATH) && defined(KPI_HISTORY_SETTLEMENT_LAUNCHER_SHA256) && defined(KPI_HISTORY_SETTLEMENT_INTERPRETER_SHA256) && defined(KPI_HISTORY_SETTLEMENT_SELECTION_SHA256) && defined(KPI_HISTORY_REGISTERED_HISTORY_SHA256) && defined(KPI_HISTORY_LOCAL_DIRECTORY_0) && defined(KPI_HISTORY_LOCAL_DIRECTORY_1) && defined(KPI_HISTORY_LOCAL_DIRECTORY_2) && defined(KPI_HISTORY_ANCHOR_DIRECTORY_0) && defined(KPI_HISTORY_ANCHOR_DIRECTORY_1) && defined(KPI_HISTORY_ANCHOR_DIRECTORY_2)
    CompiledTrust trust{KPI_HISTORY_SETTLEMENT_LAUNCHER_PATH,KPI_HISTORY_SETTLEMENT_INTERPRETER_PATH,
        unhex(KPI_HISTORY_SETTLEMENT_LAUNCHER_SHA256),unhex(KPI_HISTORY_SETTLEMENT_INTERPRETER_SHA256),
        unhex(KPI_HISTORY_SETTLEMENT_SELECTION_SHA256),unhex(KPI_HISTORY_REGISTERED_HISTORY_SHA256),
        {KPI_HISTORY_LOCAL_DIRECTORY_0,KPI_HISTORY_LOCAL_DIRECTORY_1,KPI_HISTORY_LOCAL_DIRECTORY_2},
        {KPI_HISTORY_ANCHOR_DIRECTORY_0,KPI_HISTORY_ANCHOR_DIRECTORY_1,KPI_HISTORY_ANCHOR_DIRECTORY_2}};
    for(const auto* d:{&trust.launcher_sha,&trust.interpreter_sha,&trust.selection,&trust.registration})need(*d!=Digest{});
    return trust;
#else
    // No guessed/default registered service or adapter authority. Root must
    // select the reviewed source closure in the exact production build.
    throw Refused();
#endif
}
CompiledTrust compiled_final_trust(){
#if defined(KPI_HISTORY_FINAL_LAUNCHER_PATH) && defined(KPI_HISTORY_FINAL_LAUNCHER_SHA256) && defined(KPI_HISTORY_FINAL_SELECTION_SHA256) && defined(KPI_HISTORY_SETTLEMENT_INTERPRETER_PATH) && defined(KPI_HISTORY_SETTLEMENT_INTERPRETER_SHA256) && defined(KPI_HISTORY_REGISTERED_HISTORY_SHA256) && defined(KPI_HISTORY_LOCAL_DIRECTORY_0) && defined(KPI_HISTORY_LOCAL_DIRECTORY_1) && defined(KPI_HISTORY_LOCAL_DIRECTORY_2) && defined(KPI_HISTORY_ANCHOR_DIRECTORY_0) && defined(KPI_HISTORY_ANCHOR_DIRECTORY_1) && defined(KPI_HISTORY_ANCHOR_DIRECTORY_2)
    CompiledTrust trust{KPI_HISTORY_FINAL_LAUNCHER_PATH,KPI_HISTORY_SETTLEMENT_INTERPRETER_PATH,
        unhex(KPI_HISTORY_FINAL_LAUNCHER_SHA256),unhex(KPI_HISTORY_SETTLEMENT_INTERPRETER_SHA256),
        unhex(KPI_HISTORY_FINAL_SELECTION_SHA256),unhex(KPI_HISTORY_REGISTERED_HISTORY_SHA256),
        {KPI_HISTORY_LOCAL_DIRECTORY_0,KPI_HISTORY_LOCAL_DIRECTORY_1,KPI_HISTORY_LOCAL_DIRECTORY_2},
        {KPI_HISTORY_ANCHOR_DIRECTORY_0,KPI_HISTORY_ANCHOR_DIRECTORY_1,KPI_HISTORY_ANCHOR_DIRECTORY_2}};
    for(const auto* d:{&trust.launcher_sha,&trust.interpreter_sha,&trust.selection,&trust.registration})need(*d!=Digest{});
    return trust;
#else
    throw Refused();
#endif
}
std::vector<std::filesystem::path> compiled_private_roots(int party,
    const std::vector<std::filesystem::path>& additional){
#if defined(KPI_HISTORY_PRIVATE_DIRECTORIES_0) && defined(KPI_HISTORY_PRIVATE_DIRECTORIES_1) && defined(KPI_HISTORY_PRIVATE_DIRECTORIES_2)
    const std::array<std::vector<std::filesystem::path>,3> fixed{
        std::vector<std::filesystem::path> KPI_HISTORY_PRIVATE_DIRECTORIES_0,
        std::vector<std::filesystem::path> KPI_HISTORY_PRIVATE_DIRECTORIES_1,
        std::vector<std::filesystem::path> KPI_HISTORY_PRIVATE_DIRECTORIES_2};
    need(party>=0&&party<3&&!fixed[party].empty());auto paths=fixed[party];
    paths.insert(paths.end(),additional.begin(),additional.end());
    std::sort(paths.begin(),paths.end());paths.erase(std::unique(paths.begin(),paths.end()),paths.end());return paths;
#else
    (void)party;(void)additional;throw Refused();
#endif
}
std::string make_final_request(const PublicSnapshot& s,const FinalCandidatePaths& paths,const Digest& nonce){
    need(s.attempt&&s.effects&&s.egress&&s.lock_identity);const auto& a=*s.attempt;const auto& e=*s.egress;
    uint32_t index=0;for(unsigned i=0;i<4;++i)index|=uint32_t(a.old_point[32+i])<<(8*i);
    std::string nfs="[",certs="[";for(size_t i=0;i<3;++i){if(i){nfs+=',';certs+=',';}nfs+=qhex(e.nullifiers[i]);certs+=qhex(s.key.server_certificates[i]);}nfs+=']';certs+=']';
    return object({{"schema",quote("kpb-offline-final-request/v1")},{"nonce_hex32",qhex(nonce)},
        {"registered_history_sha256",qhex(s.registration)},{"server_certificates_hex32",certs},
        {"egress_record",object({{"sequence",std::to_string(s.sequence)},{"checkpoint_sha256",qhex(s.checkpoint)}})},
        {"history_key_hex32",qhex(digest(encode(s.key)))},{"attempt_id_hex32",qhex(a.attempt)},
        {"locked_binding_sha256",qhex(*s.lock_identity)},{"prepared_core_sha256",qhex(*s.effects)},
        {"context",object({{"chain_hex32",qhex(s.key.chain)},{"pool_hex32",qhex(s.key.pool)},
            {"profile_hex32",qhex(s.key.profile)},{"domain_hex32",qhex(s.key.domain)},
            {"service_hex32",qhex(s.key.service)},{"epoch_hex32",qhex(s.key.epoch)}})},
        {"head",object({{"outpoint",object({{"transactionId",quote(bytes_hex(std::span(a.old_point).first(32)))},{"index",std::to_string(index)}})},
            {"state_hex112",quote(bytes_hex(a.old_state))},{"reserve_sompi",quote(std::to_string(a.old_reserve))}})},
        {"native_policy",object({{"old_script_public_key_hex37",quote(bytes_hex(a.old_spk))},
            {"immutable_tail_sha256",qhex(a.immutable_tail)},{"native_parameters_sha256",qhex(a.native_parameters)}})},
        {"egress",object({{"core_sha256",qhex(e.core)},{"aggregate_proof_sha256",qhex(e.aggregate_proof)},
            {"projection_sha256",qhex(e.projection)},{"nfs_hex32",nfs}})},
        {"candidate",object({{"case",record(paths.final_case,paths.case_sha256)},
            {"r0_receipt",record(paths.outer_receipt,paths.receipt_sha256)}})}})+'\n';
}
std::string direct_process(const CompiledTrust& t,const SettlementPaths& p,const std::filesystem::path& request,const Digest& request_sha,
    std::span<const unsigned char> launcher,int interpreter){
    Fd script(static_cast<int>(::syscall(SYS_memfd_create,"kpb-selected-settlement",MFD_CLOEXEC|MFD_ALLOW_SEALING)));
    write_all(script.value,launcher);need(::fcntl(script.value,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL)==0);
    need(::lseek(script.value,0,SEEK_SET)==0);
    int pipes[2];need(::pipe2(pipes,O_CLOEXEC)==0);Fd read_end(pipes[0]);Fd write_end(pipes[1]);
    Fd errors(::open((p.fresh_workspace/"adapter.stderr").c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600));
    Fd null(::open("/dev/null",O_RDONLY|O_CLOEXEC));
    // Move all remap sources above the fixed child descriptor range first.
    std::vector<int> held;for(int fd:{null.value,write_end.value,errors.value,script.value,interpreter}){int copy=::fcntl(fd,F_DUPFD_CLOEXEC,10);need(copy>=0);held.push_back(copy);}
    const std::string code="import os; _s=os.fdopen(3,'rb').read(); exec(compile(_s,"+quote(t.launcher.string())+",'exec'),{'__file__':"+quote(t.launcher.string())+",'__name__':'__main__'})";
    std::vector<std::string> args{t.interpreter.string(),"-I","-B","-c",code,"--selection",p.selection.string(),"--selection-sha256",hex(t.selection),
        "--request",request.string(),"--request-sha256",hex(request_sha),"--output",(p.fresh_workspace/"adapter").string()};
    for(const auto& path:p.private_directories){args.push_back("--exclude-private-directory");args.push_back(path.string());}
    std::vector<char*> argv;for(auto& arg:args)argv.push_back(arg.data());argv.push_back(nullptr);
    const auto pid=::fork();need(pid>=0);
    if(pid==0){
        for(int i=0;i<5;++i)if(::dup2(held[i],i)<0)::_exit(126);
        if(::fcntl(4,F_SETFD,FD_CLOEXEC)!=0)::_exit(126);
        // Includes all inherited MASCOT/TLS, key, role, journal and directory
        // descriptors. Only stdin/out/err, sealed source3 and interpreter4 stay.
        if(::syscall(SYS_close_range,5U,UINT_MAX,0U)!=0)::_exit(126);
        char env0[]="PATH=/usr/bin:/bin",env1[]="LANG=C.UTF-8",env2[]="PYTHONDONTWRITEBYTECODE=1";
        char* env[]{env0,env1,env2,nullptr};::fexecve(4,argv.data(),env);::_exit(127);
    }
    for(int fd:held){::close(fd);}
    ::close(write_end.value);write_end.value=-1;
    std::string result;char buffer[4096];
    while(true){auto n=::read(read_end.value,buffer,sizeof(buffer));if(n<0&&errno==EINTR)continue;need(n>=0);if(!n)break;result.append(buffer,n);
        // A typed financial result is one bounded line, never diagnostic/raw
        // output. Extra stdout is a protocol violation, not an execution cap.
        if(result.size()>4096){::kill(pid,SIGTERM);int status=0;while(::waitpid(pid,&status,0)<0&&errno==EINTR){};throw Refused();}}
    int status=0;pid_t waited;do{waited=::waitpid(pid,&status,0);}while(waited<0&&errno==EINTR);
    need(waited==pid&&WIFEXITED(status)&&WEXITSTATUS(status)==0);sync(errors.value);return result;
}
template<size_t N>std::array<Digest,N> parse_tokens(const std::string& result,const char* expected_prefix){
    need(!result.empty()&&result.back()=='\n'&&result.find('\n')==result.size()-1);std::istringstream input(result);std::string prefix;
    need(bool(input>>prefix)&&prefix==expected_prefix);std::array<Digest,N> out{};
    for(auto& d:out){std::string value;need(bool(input>>value));d=unhex(value);need(d!=Digest{});}
    std::string extra;need(!(input>>extra));return out;
}
std::array<Digest,8> result_tokens(const std::string& result){return parse_tokens<8>(result,"KPB_SETTLEMENT_VERIFIED_V1");}
void bind_result(const std::array<Digest,8>& tokens,const std::array<Digest,6>& expected){
    need(std::equal(expected.begin(),expected.end(),tokens.begin()));
}
FinalCandidate bind_final_result(const std::array<Digest,16>& tokens,const std::array<Digest,6>& expected,
    const Digest& case_sha,const Digest& receipt_sha,const Digest& parameters_sha){
    need(std::equal(expected.begin(),expected.end(),tokens.begin()));
    const FinalCandidate candidate{tokens[8],tokens[9],tokens[10],tokens[11],tokens[12],tokens[13],tokens[14],tokens[15]};
    need(candidate.raw_case==case_sha&&candidate.outer_receipt==receipt_sha
        &&candidate.projection==expected[5]&&candidate.selection==parameters_sha
        &&digest(encode(candidate))==tokens[6]);return candidate;
}
Bytes agreement(const PublicSnapshot& s,const SettlementRecord& r){
    Bytes bytes;const std::string label="KPBH-EXACT-LIVE-SETTLEMENT-01";add(bytes,raw(label));add(bytes,encode(s.key));
    add(bytes,r.lock_identity);add(bytes,r.attempt);add(bytes,r.final_checkpoint);add(bytes,r.candidate);
    add(bytes,r.raw_case);add(bytes,r.projection);add(bytes,r.selection);add(bytes,r.acceptance);return bytes;
}
Bytes final_agreement(const PublicSnapshot& s,const Digest& lock,const FinalCandidate& candidate){
    Bytes bytes;const std::string label="KPBH-EXACT-OFFLINE-FINAL-01";add(bytes,raw(label));add(bytes,encode(s.key));
    add(bytes,lock);for(unsigned i=0;i<8;++i)bytes.push_back(s.sequence>>(8*i));add(bytes,s.checkpoint);add(bytes,encode(candidate));return bytes;
}
}

VerifiedFinalCandidate::VerifiedFinalCandidate(MascotContext& ctx,EpochJournal& journal,const PublicSnapshot& s,
    FinalCandidate candidate,Digest request,Digest nonce,Digest evidence)
    :journal_(journal.core_),context_(&ctx),generation_(ctx.generation()),epoch_(ctx.failure_epoch()),
     sequence_(s.sequence),checkpoint_(s.checkpoint),lock_identity_(*s.lock_identity),candidate_(std::move(candidate)),
     request_(request),nonce_(nonce),evidence_(evidence){}

VerifiedFinalCandidate VerifiedFinalCandidate::acquire_fresh(MascotContext& ctx,EpochJournal& journal,const FinalCandidatePaths& paths){
    try{
        ctx.require_healthy();require_private_outer(paths.fresh_workspace);
        const auto trust=compiled_final_trust();const int party=ctx.party_id();need(party>=0&&party<3);
        journal.require_fixed_storage(trust.local[party],trust.anchor[party],trust.registration);const auto s=journal.snapshot();
        need(s.phase==Phase::Egress&&s.attempt&&s.effects&&s.egress&&s.lock_identity
            &&s.registration==trust.registration&&s.key.epoch==unhex("1719a11d82194639da551cd7302ad3ea94e42a0e424962ac40719f5634d38b94")
            &&paths.case_sha256!=Digest{}&&paths.receipt_sha256!=Digest{});
        const auto private_roots=compiled_private_roots(party,paths.private_directories);
        Exclusions excluded(private_roots);excluded.public_path(paths.fresh_workspace,true);
        plain(paths.fresh_workspace.parent_path());struct stat parent{};
        need(::lstat(paths.fresh_workspace.parent_path().c_str(),&parent)==0&&S_ISDIR(parent.st_mode)
            &&parent.st_uid==::getuid()&&(parent.st_mode&0022)==0);
        const auto launcher=admitted(trust.launcher,trust.launcher_sha,excluded);
        excluded.public_path(trust.interpreter);Fd interpreter(::open(trust.interpreter.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC));
        (void)admitted_fd(interpreter.value,trust.interpreter,trust.interpreter_sha,excluded);
        (void)admitted(paths.selection,trust.selection,excluded);
        (void)admitted(paths.final_case,paths.case_sha256,excluded);(void)admitted(paths.outer_receipt,paths.receipt_sha256,excluded);
        need(::mkdir(paths.fresh_workspace.c_str(),0700)==0);Digest nonce{};need(RAND_bytes(nonce.data(),nonce.size())==1&&nonce!=Digest{});
        const auto body=make_final_request(s,paths,nonce);const auto sha=digest(raw(body));const auto request=paths.fresh_workspace/"REQUEST.json";
        {Fd fd(::open(request.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0400));write_all(fd.value,raw(body));sync(fd.value);}
        {Fd fd(::open(paths.fresh_workspace.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));sync(fd.value);}
        SettlementPaths launch_paths{paths.selection,paths.final_case,paths.outer_receipt,paths.fresh_workspace,private_roots,{}};
        const auto tokens=parse_tokens<16>(direct_process(trust,launch_paths,request,sha,launcher,interpreter.value),"KPB_OFFLINE_FINAL_VERIFIED_V1");
        const auto candidate=bind_final_result(tokens,{nonce,sha,trust.selection,*s.lock_identity,s.checkpoint,s.egress->projection},
            paths.case_sha256,paths.receipt_sha256,s.attempt->native_parameters);
        (void)admitted(paths.fresh_workspace/"adapter/FINAL-CANDIDATE.json",tokens[7],excluded);
        const auto current=journal.snapshot();need(current.sequence==s.sequence&&current.checkpoint==s.checkpoint&&current.phase==Phase::Egress);
        ctx.agree_public_bytes("history-independent-offline-final-candidate",final_agreement(s,*s.lock_identity,candidate));
        return VerifiedFinalCandidate(ctx,journal,s,candidate,sha,nonce,tokens[7]);
    }catch(...){ctx.poison();throw Refused();}
}

void VerifiedFinalCandidate::bind(MascotContext& ctx){
    try{
        ctx.require_healthy();need(!consumed_&&context_==&ctx&&generation_==ctx.generation()&&epoch_==ctx.failure_epoch());
        const auto s=journal_.snapshot();need(s.phase==Phase::Egress&&s.sequence==sequence_&&s.checkpoint==checkpoint_
            &&s.lock_identity==lock_identity_);ctx.agree_public_bytes("history-before-durable-exact-final",final_agreement(s,lock_identity_,candidate_));
        consumed_=true;const DurableRecord egress(journal_.core_,sequence_,checkpoint_,Phase::Egress);
        const auto local=journal_.bind_final_candidate(egress,candidate_);Bytes durable=final_agreement(s,lock_identity_,candidate_);
        for(unsigned i=0;i<8;++i){durable.push_back(local.sequence()>>(8*i));}
        add(durable,local.checkpoint());
        ctx.agree_public_bytes("history-all-three-durable-final-continuation",durable);
    }catch(...){ctx.poison();throw Refused();}
}

VerifiedSettlement::VerifiedSettlement(MascotContext& ctx,EpochJournal& journal,const PublicSnapshot& s,SettlementRecord record,
    Digest request,Digest nonce,Digest evidence)
    :journal_(journal.core_),context_(&ctx),generation_(ctx.generation()),epoch_(ctx.failure_epoch()),
     sequence_(s.sequence),checkpoint_(s.checkpoint),settlement_(std::move(record)),
     request_(request),nonce_(nonce),evidence_(evidence){}

VerifiedSettlement VerifiedSettlement::acquire_fresh(MascotContext& ctx,EpochJournal& journal,const SettlementPaths& paths){
    try{
        ctx.require_healthy();require_private_outer(paths.fresh_workspace);
        const auto trust=compiled_trust();const int party=ctx.party_id();need(party>=0&&party<3);
        journal.require_fixed_storage(trust.local[party],trust.anchor[party],trust.registration);
        const auto s=journal.snapshot();
        need(s.phase==Phase::FinalCandidate&&s.attempt&&s.effects&&s.egress&&s.candidate&&s.lock_identity
            &&s.registration==trust.registration&&s.key.epoch==unhex("1719a11d82194639da551cd7302ad3ea94e42a0e424962ac40719f5634d38b94")
            &&paths.birth_start!=Digest{});
        const auto private_roots=compiled_private_roots(party,paths.private_directories);
        Exclusions excluded(private_roots);excluded.public_path(paths.fresh_workspace,true);
        plain(paths.fresh_workspace.parent_path());struct stat parent{};
        need(::lstat(paths.fresh_workspace.parent_path().c_str(),&parent)==0&&S_ISDIR(parent.st_mode)
            &&parent.st_uid==::getuid()&&(parent.st_mode&0022)==0);
        const auto launcher=admitted(trust.launcher,trust.launcher_sha,excluded);
        excluded.public_path(trust.interpreter);Fd interpreter(::open(trust.interpreter.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC));
        (void)admitted_fd(interpreter.value,trust.interpreter,trust.interpreter_sha,excluded);
        (void)admitted(paths.selection,trust.selection,excluded);
        (void)admitted(paths.final_case,s.candidate->raw_case,excluded);
        (void)admitted(paths.outer_receipt,s.candidate->outer_receipt,excluded);
        need(::mkdir(paths.fresh_workspace.c_str(),0700)==0);
        Digest nonce{};need(RAND_bytes(nonce.data(),nonce.size())==1&&nonce!=Digest{});
        const auto body=make_request(s,paths,nonce);const auto sha=digest(raw(body));const auto request=paths.fresh_workspace/"REQUEST.json";
        {Fd fd(::open(request.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0400));write_all(fd.value,raw(body));sync(fd.value);}
        {Fd fd(::open(paths.fresh_workspace.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));sync(fd.value);}
        auto launch_paths=paths;launch_paths.private_directories=private_roots;
        const auto tokens=result_tokens(direct_process(trust,launch_paths,request,sha,launcher,interpreter.value));
        bind_result(tokens,{nonce,sha,trust.selection,*s.lock_identity,s.candidate->raw_case,s.egress->projection});
        (void)admitted(paths.fresh_workspace/"adapter/SETTLEMENT.json",tokens[6],excluded);
        const auto current=journal.snapshot();need(current.sequence==s.sequence&&current.checkpoint==s.checkpoint&&current.phase==Phase::FinalCandidate);
        SettlementRecord record{*s.lock_identity,s.attempt->attempt,s.checkpoint,digest(encode(*s.candidate)),
            s.candidate->raw_case,s.egress->projection,trust.selection,tokens[7]};
        ctx.agree_public_bytes("history-independent-exact-live-settlement",agreement(s,record));
        return VerifiedSettlement(ctx,journal,s,record,sha,nonce,tokens[6]);
    }catch(...){ctx.poison();throw Refused();}
}

void VerifiedSettlement::resolve(MascotContext& ctx){
    try{
        ctx.require_healthy();need(!consumed_&&context_==&ctx&&generation_==ctx.generation()&&epoch_==ctx.failure_epoch());
        const auto s=journal_.snapshot();need(s.sequence==sequence_&&s.checkpoint==checkpoint_&&s.phase==Phase::FinalCandidate);
        ctx.agree_public_bytes("history-before-durable-exact-settlement",agreement(s,settlement_));consumed_=true;
        const auto local=journal_.record_verified_settlement(settlement_,sequence_,checkpoint_);
        Bytes durable=agreement(s,settlement_);for(unsigned i=0;i<8;++i)durable.push_back(local.sequence()>>(8*i));add(durable,local.checkpoint());
        ctx.agree_public_bytes("history-all-three-durable-settlement",durable);
    }catch(...){ctx.poison();throw Refused();}
}
} // namespace kpi::mpc::history
