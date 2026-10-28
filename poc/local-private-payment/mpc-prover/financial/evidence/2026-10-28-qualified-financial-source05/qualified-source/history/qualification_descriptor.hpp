#pragma once

// Pure public codec for a FIXED, UNREGISTERED qualification namespace.
// It initializes nothing and grants no owner-input/proof/settlement authority.
#include "epoch_journal.hpp"
#include <algorithm>
#include <map>
#include <string_view>

namespace kpi::mpc::history::qualification {
inline constexpr const char* SCOPE = "PUBLIC_UNFUNDED_UNREGISTERED_QUALIFICATION_ONLY";
inline constexpr const char* CONTEXT_SHA = "6efa0e97ae8868b12743d72d45dcd46e858214e3413a1c63c1dee1ab56aacdc0";
inline constexpr const char* HEAD_SHA = "910c09f5ea30ece29b36b1d0428a7c04c10e3b2e7f6ab65457c248b45c6cddf9";
inline constexpr const char* BASE_EPOCH = "1719a11d82194639da551cd7302ad3ea94e42a0e424962ac40719f5634d38b94";
inline constexpr const char* POINT_HEX = "255798360cfa4d4c6b51b7a2f2443d1668a7e5f87cd45d01c4d683bcd76b26e800000000";
inline constexpr const char* STATE_HEX =
    "4b50424153543031a0a1b4fbf4ce8505f17b24b354ffa81fc4201dc1e130b0358e3bc849611186e0"
    "7a57ca7b22d02b09e754543daffa55519806a71d74d365673dd23f0a1db82a4b03000000"
    "7c0266741d661e9f82372372fca9e7cdccc020005a85e7a998b0b5c5dd61882401000000";
inline constexpr const char* OLD_SPK_HEX = "0000aa2070e9dd7935b4467d5fab3f243bdafae624a8129efdb913e9d7e6180578557e1e87";
inline constexpr const char* TAIL_SHA = "4081fc4efb08131bba7b64c38cfe002a3456c8a8a93394622ee9085e3706435d";
inline constexpr const char* PARAMETERS_SHA = "3f9f2f294c8203c8fc99ba66e1a78e769a1eecc4ecc5cf8f8b631eea28138751";
inline constexpr const char* COMPONENT_SHA = "2598cd4baa438e6fb5c95bc4d1f6b8f1f7db607879f428c43f82a5247aca7f36";
inline constexpr const char* IMAGE = "d62eaf8b01ed970048bd8f2565e55ae9f2af3dcad8b7f12d94a40819805dd119";
inline constexpr uint64_t RESERVE = 6000000000ULL;
using Bytes = std::vector<unsigned char>;

inline void need(bool value) { if (!value) throw Refused(); }
inline std::span<const unsigned char> raw(const std::string& value) {
    return {reinterpret_cast<const unsigned char*>(value.data()),value.size()};
}
inline void add(Bytes& out,std::span<const unsigned char> value) {out.insert(out.end(),value.begin(),value.end());}
inline void tag(Bytes& out,const char* value) {
    do {out.push_back(static_cast<unsigned char>(*value));} while(*value++);
}
inline std::string quote(const std::string& value) {
    std::string out="\"";const char* digits="0123456789abcdef";
    for(unsigned char byte:value) {
        if(byte=='"'||byte=='\\'){out+='\\';out+=byte;}
        else if(byte<32){out+="\\u00";out+=digits[byte>>4];out+=digits[byte&15];}
        else out+=byte;
    }
    return out+'"';
}
inline std::string object(const std::map<std::string,std::string>& values) {
    std::string out="{";
    for(const auto& [name,value]:values){if(out.size()!=1)out+=',';out+=quote(name)+':'+value;}
    return out+'}';
}
template<size_t N> inline std::array<unsigned char,N> fixed(const std::string& value) {
    need(value.size()==N*2);std::array<unsigned char,N> out{};
    auto nibble=[](char byte)->unsigned {
        if(byte>='0'&&byte<='9')return byte-'0';
        if(byte>='a'&&byte<='f')return byte-'a'+10;
        throw Refused();
    };
    for(size_t i=0;i<N;++i)out[i]=(nibble(value[2*i])<<4)|nibble(value[2*i+1]);
    return out;
}
inline EpochKey base_key(const std::array<Digest,3>& certificates) {
    EpochKey key{
        unhex("f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370"),
        unhex("d68068e3eecfe9fe1b2fcc63026fe7a5268829efa37f4f64c2e7374798e94adf"),
        unhex("a0a1b4fbf4ce8505f17b24b354ffa81fc4201dc1e130b0358e3bc849611186e0"),
        unhex("ea19260a60a8d0a54b8ad9848f82317c1d84059a1881be34d318bcca42493700"),
        unhex("ce821210834e870b6eebe3851b0b003b1b33cf343b1a17a996987f35dda514b5"),
        unhex(BASE_EPOCH),certificates};
    (void)encode(key);return key;
}
inline Bytes fixture_context(const EpochKey& key) {
    const auto state=fixed<112>(STATE_HEX);const auto point=fixed<36>(POINT_HEX);
    need(std::equal(state.begin(),state.begin()+8,"KPBAST01")
         &&std::equal(key.domain.begin(),key.domain.end(),state.begin()+8));
    Bytes out;for(const auto* id:{&key.chain,&key.pool,&key.profile,&key.domain,&key.service})add(out,*id);
    add(out,point);
    for(const auto& [offset,count]:{std::pair{40U,32U},std::pair{76U,32U},std::pair{72U,4U},std::pair{108U,4U}})
        out.insert(out.end(),state.begin()+offset,state.begin()+offset+count);
    for(unsigned i=0;i<8;++i)out.push_back(RESERVE>>(8*i));
    need(out.size()==276&&digest(out)==unhex(CONTEXT_SHA));return out;
}
struct Inputs {
    std::array<Digest,3> server_certificates;
    Digest public_nonce,source_build_selection,initializer_executable;
    std::filesystem::path qualification_root;
};
struct Descriptor {
    EpochKey key;
    Digest registration_digest,initial_checkpoint,registration_file_sha256;
    std::filesystem::path registration_file;
    std::string canonical_registration,registration_file_bytes;
    std::array<std::filesystem::path,3> role_spec_files;
    std::array<std::string,3> role_specs;
    Bytes context_bytes;
};
inline std::string key_json(const EpochKey& key) {
    std::string certs="[";
    for(size_t i=0;i<3;++i){if(i)certs+=',';certs+=quote(hex(key.server_certificates[i]));}
    certs+=']';return object({{"chain_hex32",quote(hex(key.chain))},{"pool_hex32",quote(hex(key.pool))},
        {"domain_hex32",quote(hex(key.domain))},{"profile_hex32",quote(hex(key.profile))},
        {"service_hex32",quote(hex(key.service))},{"epoch_hex32",quote(hex(key.epoch))},
        {"server_certificate_sha256",certs}});
}
inline Descriptor describe(const Inputs& input) {
    const auto& root=input.qualification_root;
    need(root.is_absolute()&&root==root.lexically_normal()
         &&root.string().find_first_of("\r\n\t")==std::string::npos
         &&root.string().find('\0')==std::string::npos
         &&input.public_nonce!=Digest{}&&input.source_build_selection!=Digest{}
         &&input.initializer_executable!=Digest{});
    const auto base=base_key(input.server_certificates);Descriptor d{};d.key=base;
    d.context_bytes=fixture_context(base);
    Bytes epoch;tag(epoch,"KPBH/UNREGISTERED-QUALIFICATION/EPOCH/v1");add(epoch,encode(base));
    add(epoch,unhex(CONTEXT_SHA));add(epoch,unhex(HEAD_SHA));add(epoch,input.public_nonce);
    d.key.epoch=digest(epoch);need(d.key.epoch!=base.epoch&&d.key.epoch!=Digest{});
    std::string roles="[";
    for(unsigned i=0;i<3;++i){
        if(i)roles+=',';
        const auto role=root/("party-"+std::to_string(i));
        d.role_spec_files[i]=role/"role.spec";
        roles+=object({{"party_id",std::to_string(i)},{"local_directory",quote((role/"journal").string())},
            {"trusted_anchor_directory",quote((role/"anchor").string())},{"role_spec",quote(d.role_spec_files[i].string())}});
    }
    roles+=']';
    d.canonical_registration=object({{"schema",quote("kpb-unregistered-qualification-registration/v2")},
        {"scope",quote(SCOPE)},{"registered_financial_service","false"},
        {"fixture_context_sha256",quote(CONTEXT_SHA)},{"fixture_head_sha256",quote(HEAD_SHA)},
        {"placeholder_outpoint_hex36",quote(POINT_HEX)},{"initial_state_hex112",quote(STATE_HEX)},
        {"initial_reserve_sompi",std::to_string(RESERVE)},{"old_script_public_key_hex37",quote(OLD_SPK_HEX)},
        {"immutable_tail_sha256",quote(TAIL_SHA)},{"native_parameters_sha256",quote(PARAMETERS_SHA)},
        {"component_profile_sha256",quote(COMPONENT_SHA)},{"outer_image_hex32",quote(IMAGE)},
        {"base_service_epoch_hex32",quote(BASE_EPOCH)},{"epoch_key",key_json(d.key)},
        {"qualification_root",quote(root.string())},{"registration_nonce_hex32",quote(hex(input.public_nonce))},
        {"source_build_selection_sha256",quote(hex(input.source_build_selection))},
        {"initializer_executable_sha256",quote(hex(input.initializer_executable))},{"roles",roles}});
    Bytes registration;tag(registration,"KPBH/UNREGISTERED-QUALIFICATION/REGISTRATION/v2");
    add(registration,raw(d.canonical_registration));d.registration_digest=digest(registration);
    Bytes genesis;const std::string magic="KPBHLOG1";add(genesis,raw(magic));
    add(genesis,d.registration_digest);add(genesis,encode(d.key));d.initial_checkpoint=digest(genesis);
    d.registration_file=root/"REGISTRATION.json";
    d.registration_file_bytes=object({{"schema",quote("kpb-unregistered-qualification-bootstrap/v2")},
        {"registration",d.canonical_registration},{"registration_sha256",quote(hex(d.registration_digest))},
        {"initial_checkpoint_hex32",quote(hex(d.initial_checkpoint))}})+'\n';
    d.registration_file_sha256=digest(raw(d.registration_file_bytes));
    for(unsigned party=0;party<3;++party){
        const auto role=root/("party-"+std::to_string(party));
        std::map<std::string,std::string> fields{
            {"scope",SCOPE},{"registered_financial_service","false"},{"party_id",std::to_string(party)},
            {"registration_sha256",hex(d.registration_digest)},{"registration_file_sha256",hex(d.registration_file_sha256)},
            {"registration_file",d.registration_file.string()},{"initial_checkpoint_hex32",hex(d.initial_checkpoint)},
            {"fixture_context_sha256",CONTEXT_SHA},{"fixture_head_sha256",HEAD_SHA},
            {"chain_hex32",hex(d.key.chain)},{"pool_hex32",hex(d.key.pool)},{"domain_hex32",hex(d.key.domain)},
            {"profile_hex32",hex(d.key.profile)},{"service_hex32",hex(d.key.service)},{"epoch_hex32",hex(d.key.epoch)},
            {"base_service_epoch_hex32",BASE_EPOCH},{"qualification_root",root.string()},
            {"registration_nonce_hex32",hex(input.public_nonce)},{"placeholder_outpoint_hex36",POINT_HEX},
            {"old_state_hex112",STATE_HEX},{"old_reserve_sompi",std::to_string(RESERVE)},
            {"old_script_public_key_hex37",OLD_SPK_HEX},{"immutable_tail_sha256",TAIL_SHA},
            {"native_parameters_sha256",PARAMETERS_SHA},{"component_profile_sha256",COMPONENT_SHA},
            {"outer_image_hex32",IMAGE},{"local_directory",(role/"journal").string()},
            {"trusted_anchor_directory",(role/"anchor").string()},
            {"source_build_selection_sha256",hex(input.source_build_selection)},
            {"initializer_executable_sha256",hex(input.initializer_executable)}};
        for(unsigned i=0;i<3;++i)fields["server_certificate_sha256_"+std::to_string(i)]=hex(d.key.server_certificates[i]);
        d.role_specs[party]="KPBQROLE2\n";
        for(const auto& [name,value]:fields)d.role_specs[party]+=name+'\t'+value+'\n';
        d.role_specs[party]+="END\n";
    }
    return d;
}
struct Role {
    Descriptor descriptor;
    unsigned party_id;
    std::filesystem::path local_directory,trusted_anchor_directory;
};
inline Role admit_role_spec(std::span<const unsigned char> bytes,unsigned expected_party) {
    need(expected_party<3);const std::string text(bytes.begin(),bytes.end());
    need(text.starts_with("KPBQROLE2\n")&&text.ends_with("END\n")
         &&text.find('\0')==std::string::npos&&text.find('\r')==std::string::npos);
    std::map<std::string,std::string> fields;size_t at=10;std::string previous;
    while(at<text.size()-4){
        const auto end=text.find('\n',at);need(end!=std::string::npos&&end<text.size()-4);
        const auto line=text.substr(at,end-at);const auto split=line.find('\t');
        need(split!=std::string::npos&&split>0&&split+1<line.size()&&line.find('\t',split+1)==std::string::npos);
        const auto name=line.substr(0,split);need(previous.empty()||previous<name);previous=name;
        need(fields.emplace(name,line.substr(split+1)).second);at=end+1;
    }
    need(at==text.size()-4);
    auto value=[&](const char* name)->const std::string& {auto found=fields.find(name);need(found!=fields.end());return found->second;};
    Inputs input{{unhex(value("server_certificate_sha256_0")),unhex(value("server_certificate_sha256_1")),unhex(value("server_certificate_sha256_2"))},
        unhex(value("registration_nonce_hex32")),unhex(value("source_build_selection_sha256")),
        unhex(value("initializer_executable_sha256")),std::filesystem::path(value("qualification_root"))};
    auto d=describe(input);need(d.role_specs[expected_party]==text);
    const auto role=input.qualification_root/("party-"+std::to_string(expected_party));
    return {std::move(d),expected_party,role/"journal",role/"anchor"};
}
} // namespace kpi::mpc::history::qualification
