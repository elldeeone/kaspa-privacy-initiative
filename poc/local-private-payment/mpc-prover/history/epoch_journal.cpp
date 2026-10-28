#include "epoch_journal.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <openssl/evp.h>
#include <set>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace kpi::mpc::history {
namespace {
using Bytes = std::vector<unsigned char>;
constexpr size_t EVENT_FIXED = 85;
constexpr size_t ANCHOR_HEADER = 104;
constexpr size_t ANCHOR_ROW = 40;
constexpr uint64_t MAX_VALUE = 2870000000000000000ULL;

void need(bool good) { if (!good) throw Refused(); }
void tag(Bytes& out, const char* text) { out.insert(out.end(), text, text + 8); }
void add(Bytes& out, std::span<const unsigned char> value) { out.insert(out.end(), value.begin(), value.end()); }
void u64(Bytes& out, uint64_t value) { for (unsigned i = 0; i < 8; ++i) out.push_back(value >> (8*i)); }
void u32(Bytes& out, uint32_t value) { for (unsigned i = 0; i < 4; ++i) out.push_back(value >> (8*i)); }
bool nonzero(const Digest& value) { return value != Digest{}; }

struct Reader {
    std::span<const unsigned char> bytes;
    size_t at = 0;
    std::span<const unsigned char> take(size_t count) {
        need(count <= bytes.size() - at); auto result = bytes.subspan(at, count); at += count; return result;
    }
    void magic(const char* text) { const auto raw = take(8); need(std::equal(raw.begin(), raw.end(), text)); }
    uint64_t integer(size_t count) { uint64_t value = 0; auto raw = take(count); for (size_t i=0;i<count;++i) value |= uint64_t(raw[i]) << (8*i); return value; }
    template<size_t N> std::array<unsigned char, N> fixed() {
        std::array<unsigned char, N> result; auto raw=take(N);std::copy(raw.begin(),raw.end(),result.begin());return result;
    }
    void end() const { need(at == bytes.size()); }
};

void valid(const EpochKey& key) {
    for (const auto* value : {&key.chain,&key.pool,&key.domain,&key.profile,&key.service,&key.epoch}) need(nonzero(*value));
    for (const auto& value : key.server_certificates) need(nonzero(value));
    need(std::set<Digest>(key.server_certificates.begin(),key.server_certificates.end()).size()==3);
}
void valid(const AttemptBinding& value, const EpochKey& key) {
    for (const auto* field : {&value.attempt,&value.cohort,&value.owner_contracts,&value.model,&value.source,
         &value.dependencies,&value.matrix,&value.trace,&value.layout,&value.input_map,&value.prefix_recipe,
         &value.validation_policy,&value.admitted_head,&value.immutable_tail,&value.native_parameters}) need(nonzero(*field));
    need(std::any_of(value.old_point.begin(), value.old_point.begin()+32, [](auto x){return x!=0;}));
    need(std::equal(value.old_state.begin(),value.old_state.begin()+8,"KPBAST01")
         && std::equal(key.domain.begin(),key.domain.end(),value.old_state.begin()+8)
         && value.old_reserve>0 && value.old_reserve<=MAX_VALUE);
    need(value.old_spk[0]==0&&value.old_spk[1]==0&&value.old_spk[2]==0xaa
         &&value.old_spk[3]==0x20&&value.old_spk[36]==0x87);
}
void valid(const EgressPacket& value) {
    for (const auto* field : {&value.effects,&value.core,&value.aggregate_proof,&value.projection}) need(nonzero(*field));
    for (const auto& nf : value.nullifiers) need(nonzero(nf));
    need(std::is_sorted(value.nullifiers.begin(),value.nullifiers.end())
         && std::adjacent_find(value.nullifiers.begin(),value.nullifiers.end())==value.nullifiers.end());
}
void valid(const FinalCandidate& value) {
    for (const auto* field : {&value.raw_case,&value.canonical_case,&value.projection,&value.selection,
         &value.image,&value.journal,&value.outer_receipt,&value.native_proof}) need(nonzero(*field));
}
void valid(const SettlementRecord& value) {
    for(const auto* field:{&value.lock_identity,&value.attempt,&value.final_checkpoint,&value.candidate,
        &value.raw_case,&value.projection,&value.selection,&value.acceptance})need(nonzero(*field));
}

AttemptBinding attempt(std::span<const unsigned char> data) {
    Reader r{data};r.magic("KPBHJOB2");AttemptBinding v;
    for (auto* field : {&v.attempt,&v.cohort,&v.owner_contracts,&v.model,&v.source,&v.dependencies,
         &v.matrix,&v.trace,&v.layout,&v.input_map,&v.prefix_recipe,&v.validation_policy,&v.admitted_head}) *field=r.fixed<32>();
    v.old_point=r.fixed<36>();v.old_state=r.fixed<112>();v.old_reserve=r.integer(8);
    v.old_spk=r.fixed<37>();v.immutable_tail=r.fixed<32>();v.native_parameters=r.fixed<32>();r.end();return v;
}
EgressPacket egress(std::span<const unsigned char> data) {
    Reader r{data};r.magic("KPBHEGR1");EgressPacket v;
    for(auto* field:{&v.effects,&v.core,&v.aggregate_proof,&v.projection})*field=r.fixed<32>();
    for (auto& nf : v.nullifiers) { nf = r.fixed<32>(); }
    r.end(); valid(v); return v;
}
FinalCandidate candidate(std::span<const unsigned char> data) {
    Reader r{data};r.magic("KPBHFIN1");FinalCandidate v;
    for(auto* field:{&v.raw_case,&v.canonical_case,&v.projection,&v.selection,&v.image,&v.journal,&v.outer_receipt,&v.native_proof})*field=r.fixed<32>();
    r.end();valid(v);return v;
}
SettlementRecord settlement(std::span<const unsigned char> data) {
    Reader r{data};r.magic("KPBHSET1");SettlementRecord v;
    for(auto* field:{&v.lock_identity,&v.attempt,&v.final_checkpoint,&v.candidate,&v.raw_case,
        &v.projection,&v.selection,&v.acceptance})*field=r.fixed<32>();
    r.end();valid(v);return v;
}
void matches_settlement(const PublicSnapshot& prior,const SettlementRecord& value) {
    valid(value);need(prior.phase==Phase::FinalCandidate&&prior.attempt&&prior.egress
        &&prior.candidate&&prior.lock_identity&&value.lock_identity==*prior.lock_identity
        &&value.attempt==prior.attempt->attempt&&value.final_checkpoint==prior.checkpoint
        &&value.candidate==digest(encode(*prior.candidate))&&value.raw_case==prior.candidate->raw_case
        &&value.projection==prior.egress->projection);
}

void write_all(int fd, std::span<const unsigned char> data) {
    size_t at=0;
    while(at<data.size()) {
        const auto written=::write(fd,data.data()+at,data.size()-at);
        if(written<0&&errno==EINTR)continue;
        need(written>0);at+=static_cast<size_t>(written);
    }
}
Bytes read_at(int fd, size_t at, size_t count) {
    need(at<=static_cast<size_t>(std::numeric_limits<off_t>::max())
         && count<=static_cast<size_t>(std::numeric_limits<off_t>::max())-at);
    Bytes out(count);size_t done=0;
    while(done<count) {
        auto got=::pread(fd,out.data()+done,count-done,static_cast<off_t>(at+done));
        if(got<0&&errno==EINTR)continue;
        need(got>0);done+=static_cast<size_t>(got);
    }
    return out;
}
size_t file_size(int fd) {
    struct stat info{};need(::fstat(fd,&info)==0&&info.st_size>=0);
    need(static_cast<uintmax_t>(info.st_size)<=std::numeric_limits<size_t>::max());return static_cast<size_t>(info.st_size);
}
void sync(int fd) { int result;do{result=::fsync(fd);}while(result<0&&errno==EINTR);need(result==0); }

std::filesystem::path directory(const std::filesystem::path& raw) {
    auto path=std::filesystem::absolute(raw);need(path==path.lexically_normal());
    for(auto current=path;!current.empty();current=current.parent_path()) {
        need(!std::filesystem::is_symlink(std::filesystem::symlink_status(current)));
        if(current==current.root_path())break;
    }
    struct stat info{};need(::lstat(path.c_str(),&info)==0&&S_ISDIR(info.st_mode)
        && info.st_uid==::getuid()&& (info.st_mode&07777)==0700);return path;
}
bool inside(const std::filesystem::path& a,const std::filesystem::path& b) {
    auto x=a.begin(),y=b.begin();for(;y!=b.end();++x,++y)if(x==a.end()||*x!=*y)return false;return true;
}
void regular(int fd) {
    struct stat info{};need(::fstat(fd,&info)==0&&S_ISREG(info.st_mode)&&info.st_uid==::getuid()
        &&info.st_nlink==1&&(info.st_mode&07777)==0600);
}
struct Exclusive {
    int fd;
    explicit Exclusive(int value):fd(value){int result;do{result=::flock(fd,LOCK_EX);}while(result<0&&errno==EINTR);need(result==0);}
    ~Exclusive(){(void)::flock(fd,LOCK_UN);}
};
Digest seen_digest(const std::set<Digest>& seen) {
    Bytes bytes;tag(bytes,"KPBHSEE1");u64(bytes,seen.size());for(const auto& nf:seen)add(bytes,nf);return digest(bytes);
}
} // namespace

Digest digest(std::span<const unsigned char> bytes) {
    Digest result{};unsigned size=0;
    need(EVP_Digest(bytes.data(),bytes.size(),result.data(),&size,EVP_sha256(),nullptr)==1&&size==result.size());return result;
}
Digest unhex(const std::string& value) {
    need(value.size()==64);Digest result{};
    auto digit=[](char x)->unsigned {if(x>='0'&&x<='9')return x-'0';if(x>='a'&&x<='f')return x-'a'+10;throw Refused();};
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] = (digit(value[2*i]) << 4) | digit(value[2*i+1]);
    }
    return result;
}
std::string hex(const Digest& value) {std::string result;const char* digits="0123456789abcdef";for(auto x:value){result+=digits[x>>4];result+=digits[x&15];}return result;}
Bytes encode(const EpochKey& v) {
    valid(v);Bytes out;tag(out,"KPBHKEY1");for(const auto* field:{&v.chain,&v.pool,&v.domain,&v.profile,&v.service,&v.epoch})add(out,*field);
    for (const auto& cert : v.server_certificates) { add(out, cert); }
    return out;
}
Bytes encode(const AttemptBinding& v) {
    Bytes out;tag(out,"KPBHJOB2");for(const auto* field:{&v.attempt,&v.cohort,&v.owner_contracts,&v.model,&v.source,&v.dependencies,&v.matrix,&v.trace,&v.layout,&v.input_map,&v.prefix_recipe,&v.validation_policy,&v.admitted_head})add(out,*field);
    add(out,v.old_point);add(out,v.old_state);u64(out,v.old_reserve);add(out,v.old_spk);
    add(out,v.immutable_tail);add(out,v.native_parameters);return out;
}
Bytes encode(const EgressPacket& v) {valid(v);Bytes out;tag(out,"KPBHEGR1");for(const auto* f:{&v.effects,&v.core,&v.aggregate_proof,&v.projection})add(out,*f);for(const auto& nf:v.nullifiers)add(out,nf);return out;}
Bytes encode(const FinalCandidate& v) {valid(v);Bytes out;tag(out,"KPBHFIN1");for(const auto* f:{&v.raw_case,&v.canonical_case,&v.projection,&v.selection,&v.image,&v.journal,&v.outer_receipt,&v.native_proof})add(out,*f);return out;}
Bytes encode(const SettlementRecord& v) {valid(v);Bytes out;tag(out,"KPBHSET1");for(const auto* f:{&v.lock_identity,&v.attempt,&v.final_checkpoint,&v.candidate,&v.raw_case,&v.projection,&v.selection,&v.acceptance})add(out,*f);return out;}
Digest binding_identity(const EpochKey& key,const AttemptBinding& value) {valid(value,key);auto out=encode(key);add(out,encode(value));return digest(out);}
Digest lock_agreement_identity(const PublicSnapshot& prior,const AttemptBinding& binding) {
    valid(binding,prior.key);Bytes out;const std::string label="KPBH-LOCK-AGREEMENT-01";
    out.insert(out.end(),label.begin(),label.end());add(out,encode(prior.key));add(out,encode(binding));
    u64(out,prior.sequence);add(out,prior.checkpoint);add(out,prior.seen_identity);return digest(out);
}
std::array<Digest, 3> canonical_history_nullifiers(std::span<const unsigned char> core) {
    need(core.size()==10364 && std::equal(core.begin(),core.begin()+8,"KPBAEF01"));
    std::array<Digest,3> result{};
    for(size_t index=0;index<result.size();++index) {
        std::copy_n(core.begin()+404+index*96,32,result[index].begin());
        need(nonzero(result[index]));
        if(index) need(std::lexicographical_compare(result[index-1].rbegin(),result[index-1].rend(),
                                                   result[index].rbegin(),result[index].rend()));
    }
    std::sort(result.begin(),result.end());
    return result;
}

namespace detail {
struct JournalCore : std::enable_shared_from_this<JournalCore> {
    EpochKey key;Digest registration;
    std::filesystem::path local,anchor;
    int local_dir=-1,anchor_dir=-1,journal=-1,latest=-1;
    mutable std::mutex mutex;
    bool poisoned=false;
    ~JournalCore(){for(int fd:{journal,latest,local_dir,anchor_dir})if(fd>=0)::close(fd);}
    void identities() const {
        need(!poisoned);regular(journal);regular(latest);
        need(directory(local)==local && directory(anchor)==anchor);
        struct stat local_named{}, local_open{}, anchor_named{}, anchor_open{};
        need(::lstat(local.c_str(), &local_named)==0 && ::fstat(local_dir, &local_open)==0
             && ::lstat(anchor.c_str(), &anchor_named)==0 && ::fstat(anchor_dir, &anchor_open)==0
             && local_named.st_dev==local_open.st_dev && local_named.st_ino==local_open.st_ino
             && anchor_named.st_dev==anchor_open.st_dev && anchor_named.st_ino==anchor_open.st_ino
             && (local_open.st_dev!=anchor_open.st_dev || local_open.st_ino!=anchor_open.st_ino));
        for(auto item:{std::pair{local_dir,std::pair{"journal.bin",journal}},std::pair{anchor_dir,std::pair{"latest.bin",latest}}}){
            struct stat named{},opened{};need(::fstatat(item.first,item.second.first,&named,AT_SYMLINK_NOFOLLOW)==0
                &&::fstat(item.second.second,&opened)==0&&named.st_dev==opened.st_dev&&named.st_ino==opened.st_ino);
        }
    }
    Bytes header() const {Bytes out;tag(out,"KPBHLOG1");add(out,registration);add(out,encode(key));return out;}
    Bytes anchor_header(const Digest& genesis) const {Bytes out;tag(out,"KPBHAN01");add(out,registration);add(out,digest(encode(key)));add(out,genesis);return out;}
    PublicSnapshot read() const {
        identities();const auto expected=header();const auto bytes=file_size(journal);
        need(bytes>=expected.size()&&read_at(journal,0,expected.size())==expected);
        PublicSnapshot state{key,0,digest(expected),Phase::Ready,{},{},{},{},{},{},registration,{},{}};
        const auto expected_anchor=anchor_header(state.checkpoint);
        const auto anchor_bytes=file_size(latest);need(expected_anchor.size()==ANCHOR_HEADER&&anchor_bytes>=ANCHOR_HEADER
            &&(anchor_bytes-ANCHOR_HEADER)%ANCHOR_ROW==0&&read_at(latest,0,ANCHOR_HEADER)==expected_anchor);
        std::set<Digest> seen;size_t at=expected.size();
        while(at<bytes){
            need(bytes-at>=EVENT_FIXED);const auto prefix=read_at(journal,at,EVENT_FIXED-32);
            Reader r{prefix};r.magic("KPBHEV01");const auto seq=r.integer(8),length=r.integer(4),kind=r.integer(1);const auto previous=r.fixed<32>();r.end();
            need(length<=2048&&length<=bytes-at-EVENT_FIXED&&state.sequence!=std::numeric_limits<uint64_t>::max()
                &&seq==state.sequence+1&&previous==state.checkpoint);
            const auto payload=read_at(journal,at+EVENT_FIXED-32,length);auto hashed=prefix;add(hashed,payload);
            const auto head=digest(hashed);const auto stored=read_at(journal,at+EVENT_FIXED-32+length,32);need(std::equal(head.begin(),head.end(),stored.begin()));
            if(kind==1){need(state.phase==Phase::Ready);auto value=attempt(payload);valid(value,key);
                state.seen_identity=seen_digest(seen);state.lock_identity=lock_agreement_identity(state,value);
                state.attempt=value;state.phase=Phase::Locked;}
            else if(kind==2){need(state.phase==Phase::Locked&&payload.size()==32);Digest effects{};std::copy(payload.begin(),payload.end(),effects.begin());need(nonzero(effects));state.effects=effects;state.phase=Phase::Prepared;}
            else if(kind==3){need(state.phase==Phase::Prepared);auto value=egress(payload);need(value.effects==state.effects);bool conflict=false;for(const auto& nf:value.nullifiers){conflict|=seen.contains(nf);seen.insert(nf);}state.egress=value;state.phase=conflict?Phase::ExposureConflict:Phase::Egress;}
            else if(kind==4){need(state.phase==Phase::Egress);auto value=candidate(payload);need(value.projection==state.egress->projection);state.candidate=value;state.phase=Phase::FinalCandidate;}
            else if(kind==5){auto value=settlement(payload);matches_settlement(state,value);
                state.last_settlement=value;state.attempt.reset();state.effects.reset();state.egress.reset();
                state.candidate.reset();state.lock_identity.reset();state.phase=Phase::Ready;}
            else throw Refused();
            state.sequence=seq;state.checkpoint=head;
            need(seq<=(anchor_bytes-ANCHOR_HEADER)/ANCHOR_ROW);
            const auto anchor_row = read_at(latest,ANCHOR_HEADER+(seq-1)*ANCHOR_ROW,ANCHOR_ROW);
            Reader a{anchor_row};
            need(a.integer(8)==seq&&a.fixed<32>()==head);a.end();at+=EVENT_FIXED+length;
        }
        need(at==bytes&&state.sequence==(anchor_bytes-ANCHOR_HEADER)/ANCHOR_ROW);
        state.seen_nullifiers.assign(seen.begin(),seen.end());state.seen_identity=seen_digest(seen);identities();return state;
    }
    DurableRecord append(const PublicSnapshot& prior,uint8_t kind,std::span<const unsigned char> payload,Phase phase,const FailureOnlyHook& hook);
};
} // namespace detail

namespace {
std::shared_ptr<detail::JournalCore> open_core(const std::filesystem::path& local,
    const std::filesystem::path& anchor,const EpochKey& key,const Digest& registration,bool create){
    valid(key);need(nonzero(registration));auto core=std::make_shared<detail::JournalCore>();core->key=key;core->registration=registration;
    core->local=directory(local);core->anchor=directory(anchor);need(!inside(core->local,core->anchor)&&!inside(core->anchor,core->local));
    core->local_dir=::open(core->local.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);need(core->local_dir>=0);
    core->anchor_dir=::open(core->anchor.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);need(core->anchor_dir>=0);
    const auto flags=O_RDWR|O_NOFOLLOW|O_CLOEXEC|(create?(O_CREAT|O_EXCL):0);
    core->journal=::openat(core->local_dir,"journal.bin",flags,0600);need(core->journal>=0);
    core->latest=::openat(core->anchor_dir,"latest.bin",flags,0600);need(core->latest>=0);core->identities();
    if(create){const auto header=core->header();const auto anchor_header=core->anchor_header(digest(header));write_all(core->journal,header);sync(core->journal);write_all(core->latest,anchor_header);sync(core->latest);sync(core->local_dir);sync(core->anchor_dir);}
    return core;
}
} // namespace

DurableRecord::DurableRecord(std::shared_ptr<detail::JournalCore> core,uint64_t sequence,Digest checkpoint,Phase phase)
    :core_(std::move(core)),sequence_(sequence),checkpoint_(checkpoint),phase_(phase){}
EpochJournal::EpochJournal(std::shared_ptr<detail::JournalCore> core):core_(std::move(core)){}
#ifdef KPI_HISTORY_UNFUNDED_SETUP
EpochJournal EpochJournal::initialize_fresh_unfunded(const std::filesystem::path& local,const std::filesystem::path& anchor,const EpochKey& key,const Digest& registration){
    auto core=open_core(local,anchor,key,registration,true);(void)core->read();return EpochJournal(std::move(core));
}
#endif
EpochJournal EpochJournal::open_existing(const std::filesystem::path& local,const std::filesystem::path& anchor,const EpochKey& key,const Digest& registration){
    auto core=open_core(local,anchor,key,registration,false);std::lock_guard guard(core->mutex);Exclusive lock(core->journal);(void)core->read();return EpochJournal(std::move(core));
}
PublicSnapshot EpochJournal::snapshot() const {std::lock_guard guard(core_->mutex);Exclusive lock(core_->journal);return core_->read();}

DurableRecord detail::JournalCore::append(const PublicSnapshot& prior,uint8_t kind,std::span<const unsigned char> payload,Phase phase,const FailureOnlyHook& hook){
    need(prior.sequence!=std::numeric_limits<uint64_t>::max()&&payload.size()<=2048);Bytes record;tag(record,"KPBHEV01");u64(record,prior.sequence+1);u32(record,payload.size());record.push_back(kind);add(record,prior.checkpoint);add(record,payload);const auto head=digest(record);add(record,head);
    try{
        identities();need(::lseek(journal,0,SEEK_END)>=0);write_all(journal,record);if(hook)hook(WriteBoundary::JournalWritten);
        sync(journal);if(hook)hook(WriteBoundary::JournalSynced);
        Bytes anchor_record;u64(anchor_record,prior.sequence+1);add(anchor_record,head);need(::lseek(latest,0,SEEK_END)>=0);write_all(latest,anchor_record);if(hook)hook(WriteBoundary::AnchorWritten);
        sync(latest);if(hook)hook(WriteBoundary::AnchorSynced);identities();
    }catch(...){poisoned=true;throw Refused();}
    return DurableRecord(shared_from_this(),prior.sequence+1,head,phase);
}

DurableRecord EpochJournal::lock(const AttemptBinding& value,FailureOnlyHook hook){
    std::lock_guard guard(core_->mutex);Exclusive locked(core_->journal);auto prior=core_->read();need(prior.phase==Phase::Ready);valid(value,core_->key);return core_->append(prior,1,encode(value),Phase::Locked,hook);
}
DurableRecord EpochJournal::prepare(const DurableRecord& locked,const Digest& effects,FailureOnlyHook hook){
    std::lock_guard guard(core_->mutex);Exclusive lock(core_->journal);auto prior=core_->read();need(locked.core_==core_&&locked.phase_==Phase::Locked&&prior.phase==Phase::Locked&&locked.sequence_==prior.sequence&&locked.checkpoint_==prior.checkpoint&&nonzero(effects));return core_->append(prior,2,effects,Phase::Prepared,hook);
}
DurableRecord EpochJournal::record_egress(const DurableRecord& prepared,const EgressPacket& value,FailureOnlyHook hook){
    std::lock_guard guard(core_->mutex);Exclusive lock(core_->journal);auto prior=core_->read();need(prepared.core_==core_&&prepared.phase_==Phase::Prepared&&prior.phase==Phase::Prepared&&prepared.sequence_==prior.sequence&&prepared.checkpoint_==prior.checkpoint&&value.effects==prior.effects);valid(value);bool conflict=false;for(const auto& nf:value.nullifiers)conflict|=std::binary_search(prior.seen_nullifiers.begin(),prior.seen_nullifiers.end(),nf);return core_->append(prior,3,encode(value),conflict?Phase::ExposureConflict:Phase::Egress,hook);
}
DurableRecord EpochJournal::bind_final_candidate(const DurableRecord& egress_record,const FinalCandidate& value,FailureOnlyHook hook){
    std::lock_guard guard(core_->mutex);Exclusive lock(core_->journal);auto prior=core_->read();need(egress_record.core_==core_&&egress_record.phase_==Phase::Egress&&prior.phase==Phase::Egress&&egress_record.sequence_==prior.sequence&&egress_record.checkpoint_==prior.checkpoint&&value.projection==prior.egress->projection);valid(value);return core_->append(prior,4,encode(value),Phase::FinalCandidate,hook);
}
DurableRecord EpochJournal::record_verified_settlement(const SettlementRecord& value,
    uint64_t sequence,const Digest& checkpoint,FailureOnlyHook hook) {
    std::lock_guard guard(core_->mutex);Exclusive lock(core_->journal);auto prior=core_->read();
    need(prior.sequence==sequence&&prior.checkpoint==checkpoint);matches_settlement(prior,value);
    return core_->append(prior,5,encode(value),Phase::Ready,hook);
}
void EpochJournal::require_fixed_storage(const std::filesystem::path& local,
    const std::filesystem::path& anchor,const Digest& registration)const {
    need(local.is_absolute()&&anchor.is_absolute()&&local==local.lexically_normal()
        &&anchor==anchor.lexically_normal()&&core_->local==local&&core_->anchor==anchor
        &&core_->registration==registration);
    (void)snapshot();
}
} // namespace kpi::mpc::history
