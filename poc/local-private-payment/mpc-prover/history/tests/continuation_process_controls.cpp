// PUBLIC PROCESS/ENCODING FIXTURES ONLY: actual acquire_fresh/resolve and every
// MascotContext path are discarded by the standalone link, never invoked.
#include "../settlement_capability.cpp"
#include <iostream>
using namespace kpi::mpc::history;
int main(int argc,char** argv){try{
    need(argc==3);const auto root=std::filesystem::path(argv[1]);const auto python=std::filesystem::path(argv[2]);
    need(!std::filesystem::exists(root)&&std::filesystem::create_directory(root));need(::chmod(root.c_str(),0700)==0);
    auto refuses=[](auto call){bool denied=false;try{call();}catch(const Refused&){denied=true;}need(denied);};
    refuses([]{(void)compiled_trust();});
    refuses([]{(void)compiled_final_trust();});
    refuses([]{(void)compiled_private_roots(0,{});});
    std::array<Digest,8> values{};for(size_t i=0;i<8;++i){values[i][0]=static_cast<unsigned char>(i+1);}
    auto line=[&](const char* prefix){std::string out=prefix;for(const auto& d:values)out+=' '+hex(d);return out+'\n';};
    const auto valid=line("KPB_SETTLEMENT_VERIFIED_V1");need(result_tokens(valid)==values);
    for(const char* prefix:{"KPB_UNQUALIFIED_SETTLEMENT_EVIDENCE_V1","KPB_VERIFIED_EVIDENCE_V1","accepted:true"})refuses([&]{(void)result_tokens(line(prefix));});
    for(const auto& changed:{valid+"extra\n",valid.substr(0,valid.size()-1),valid+"\n"})refuses([&]{(void)result_tokens(changed);});
    std::array<Digest,6> expected{};std::copy_n(values.begin(),6,expected.begin());bind_result(values,expected);
    for(size_t i=0;i<6;++i){auto bad=values;bad[i][0]^=0x80;refuses([&]{bind_result(bad,expected);});}
    std::array<Digest,16> final{};for(size_t i=0;i<16;++i)final[i][0]=static_cast<unsigned char>(i+1);
    final[10]=final[5];const FinalCandidate expected_candidate{final[8],final[9],final[10],final[11],final[12],final[13],final[14],final[15]};final[6]=digest(encode(expected_candidate));
    std::array<Digest,6> expected_final{};std::copy_n(final.begin(),6,expected_final.begin());
    need(bind_final_result(final,expected_final,final[8],final[14],final[11])==expected_candidate);
    for(size_t i=0;i<16;++i){if(i==7)continue;auto bad=final;bad[i][0]^=0x80;refuses([&]{(void)bind_final_result(bad,expected_final,final[8],final[14],final[11]);});}
    std::string final_line="KPB_OFFLINE_FINAL_VERIFIED_V1";for(const auto& d:final)final_line+=' '+hex(d);final_line+='\n';
    need(parse_tokens<16>(final_line,"KPB_OFFLINE_FINAL_VERIFIED_V1")==final);
    refuses([&]{(void)result_tokens(final_line);});refuses([&]{(void)parse_tokens<16>(valid,"KPB_OFFLINE_FINAL_VERIFIED_V1");});
    auto private_root=root/"synthetic-private-exclusion";need(std::filesystem::create_directory(private_root));auto private_file=private_root/"CANARY";
    {Fd fd(::open(private_file.c_str(),O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600));write_all(fd.value,raw("PUBLIC SYNTHETIC CANARY"));}
    Exclusions exclusions({private_root});refuses([&]{(void)admitted(private_file,digest(raw("PUBLIC SYNTHETIC CANARY")),exclusions);});
    auto alias=root/"hardlink-alias";need(::link(private_file.c_str(),alias.c_str())==0);refuses([&]{(void)admitted(alias,digest(raw("PUBLIC SYNTHETIC CANARY")),exclusions);});
    auto workspace=root/"child";need(std::filesystem::create_directory(workspace));SettlementPaths p{};p.fresh_workspace=workspace;
    CompiledTrust trust{};trust.interpreter=python;trust.launcher=root/"fixed-origin/launch.py";trust.selection=values[2];
    Fd interpreter(::open(python.c_str(),O_RDONLY|O_CLOEXEC));Fd canary(::open(private_file.c_str(),O_RDONLY));
    const std::string script="import os\nfrom pathlib import Path\nassert str(Path(__file__).parent)=="+quote(trust.launcher.parent_path().string())+"\nfor n in range(4,4096):\n try: os.fstat(n)\n except OSError: continue\n raise RuntimeError('inherited descriptor')\nprint("+quote(valid.substr(0,valid.size()-1))+")\n";
    const auto out=direct_process(trust,p,root/"request",values[1],raw(script),interpreter.value);need(result_tokens(out)==values);
    struct stat canary_info{};need(::fstat(canary.value,&canary_info)==0);
    p.fresh_workspace=root/"child-failure";need(std::filesystem::create_directory(p.fresh_workspace));refuses([&]{(void)direct_process(trust,p,root/"request",values[1],raw("raise SystemExit(3)\n"),interpreter.value);});
    std::cout<<"{\"schema\":\"settlement-process-controls/v2\",\"financial_or_MPC_execution\":false,\"passed\":[\"absent-compiled-settlement-and-final-authorities-refuse\",\"strict-eight-digest-result\",\"unqualified-and-inner-prefix-refused\",\"extra-stdout-and-missing-newline-refused\",\"six-request-bindings-individually-refused\",\"strict-sixteen-digest-offline-final-result\",\"fifteen-offline-final-substitution-refusals\",\"offline-final-cannot-parse-as-settlement\",\"private-path-and-hardlink-body-admission-refused\",\"actual-sealed-source-canonical-origin\",\"actual-child-closes-inherited-canary-FD\",\"actual-child-nonzero-refused\"]}\n";
}catch(...){std::cerr<<"process controls refused\n";return 1;}}
