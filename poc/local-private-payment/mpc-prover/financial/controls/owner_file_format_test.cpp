// ADR0081 PUBLIC fixture controls; no wallet or private owner record is read.
#include "../owner_file_format.hpp"
#include "historical/owner_file_format_v1.hpp"
#include <fstream>
#include <iostream>
#include <functional>
#include <sys/stat.h>
using namespace kpi::mpc;
namespace fs=std::filesystem;
namespace {
size_t controls=0;
void need(bool x){if(!x)throw std::runtime_error("public-fr32-control");}
template<class F>void rejects(F f){bool bad=false;try{f();}catch(const std::exception&){bad=true;}need(bad);++controls;}
std::vector<unsigned char> bytes(const fs::path& p){std::ifstream f(p,std::ios::binary);need(bool(f));return {std::istreambuf_iterator<char>(f),{}};}
fs::path write(const fs::path& root,const std::string& name,const std::vector<unsigned char>& b,mode_t mode=0600){auto p=root/name;std::ofstream f(p,std::ios::binary);f.write(reinterpret_cast<const char*>(b.data()),b.size());f.close();need(bool(f)&&chmod(p.c_str(),mode)==0);return p;}
auto load(const fs::path& p,int owner=0,size_t n=3){return financial::load_owner_fr32_input_file(p,owner,n,[](const ::bigint& x){return Fr(x);});}
std::array<unsigned char,32> scalar(const bigint& x){std::array<unsigned char,32> out{};size_t n=0;mpz_export(out.data(),&n,-1,1,0,0,x.get_mpz_t());need(n<=32);return out;}
}
int main(int argc,char**argv){try{
 need(argc==3);initialize_bn254_field();const fs::path fixture(argv[1]),root(argv[2]);fs::create_directory(root);
 for(const auto& label:{"A","B"}){
  const auto old=financial::load_owner_input_file(fixture/(std::string("PUBLIC-")+label+".txt"),0,3,[](const std::string& x){return parse_fr(x);});
  const auto fresh=load(fixture/(std::string("PUBLIC-")+label+".bin"));need(old==fresh);++controls;
 }
 const auto a=load(fixture/"PUBLIC-A.bin");need(a==std::vector<Fr>{Fr(0),Fr(1),Fr(fr_modulus()-1)});++controls;
 const auto old_a=fs::file_size(fixture/"PUBLIC-A.txt"),old_b=fs::file_size(fixture/"PUBLIC-B.txt");
 const auto new_a=fs::file_size(fixture/"PUBLIC-A.bin"),new_b=fs::file_size(fixture/"PUBLIC-B.bin");need(old_a!=old_b&&new_a==128&&new_a==new_b);++controls;
 auto valid=bytes(fixture/"PUBLIC-A.bin");
 const auto malformed=[&](const std::string& name,auto change){auto b=valid;change(b);auto p=write(root,name,b);rejects([&]{(void)load(p);});};
 malformed("bad-magic.bin",[](auto&b){b[0]^=1;});
 malformed("bad-version.bin",[](auto&b){b[15]='3';});
 malformed("wrong-owner.bin",[](auto&b){b[16]=1;});
 malformed("owner-overflow.bin",[](auto&b){std::fill(b.begin()+16,b.begin()+24,255);});
 malformed("wrong-count.bin",[](auto&b){b[24]=4;});
 malformed("zero-count.bin",[](auto&b){b[24]=0;});
 malformed("huge-count.bin",[](auto&b){std::fill(b.begin()+24,b.begin()+32,255);});
 malformed("short-header.bin",[](auto&b){b.resize(31);});
 malformed("truncated-field.bin",[](auto&b){b.pop_back();});
 malformed("trailing-byte.bin",[](auto&b){b.push_back(0);});
 malformed("extra-field.bin",[](auto&b){b.resize(b.size()+32,0);});
 for(const bigint& value:{fr_modulus(),bigint(fr_modulus()+1)}){auto b=valid;auto v=scalar(value);std::copy(v.begin(),v.end(),b.begin()+96);auto p=write(root,value==fr_modulus()?"alias-P.bin":"alias-P1.bin",b);rejects([&]{(void)load(p);});}
 auto text=bytes(fixture/"PUBLIC-A.txt");text.resize(128,' ');auto legacy=write(root,"legacy-padded-same-size.bin",text);rejects([&]{(void)load(legacy);});
 auto broad=write(root,"broad.bin",valid,0644);rejects([&]{(void)load(broad);});
 auto link=root/"leaf-link.bin";fs::create_symlink(fixture/"PUBLIC-A.bin",link);rejects([&]{(void)load(link);});
 auto parent=root/"parent-link";fs::create_directory_symlink(fixture,parent);rejects([&]{(void)load(parent/"PUBLIC-A.bin");});
 auto hard=root/"hard.bin";fs::create_hard_link(fixture/"PUBLIC-A.bin",hard);rejects([&]{(void)load(hard);});fs::remove(hard);
 auto fifo=root/"fifo.bin";need(mkfifo(fifo.c_str(),0600)==0);rejects([&]{(void)load(fifo);});
 rejects([&]{(void)load(fixture/"PUBLIC-A.bin",3);});rejects([&]{(void)load(fixture/"PUBLIC-A.bin",0,0);});
 rejects([&]{(void)financial::owner_fr32_file_bytes(std::numeric_limits<size_t>::max());});
 auto drift=write(root,"append-drift.bin",valid);bool changed=false;
 rejects([&]{(void)financial::load_owner_fr32_input_file(drift,0,3,[&](const ::bigint& x){if(!changed){std::ofstream f(drift,std::ios::app|std::ios::binary);f.put(0);f.close();changed=true;}return Fr(x);});});
 drift=write(root,"same-size-drift.bin",valid);changed=false;
 rejects([&]{(void)financial::load_owner_fr32_input_file(drift,0,3,[&](const ::bigint& x){if(!changed){struct stat s{};need(stat(drift.c_str(),&s)==0);timespec times[2]{s.st_atim,s.st_mtim};times[1].tv_sec+=1;need(utimensat(AT_FDCWD,drift.c_str(),times,0)==0);changed=true;}return Fr(x);});});
 for(int role=0;role<3;++role){const auto path=fixture/("PUBLIC-LARGE-"+std::to_string(role)+".bin");need(fs::file_size(path)==84333120);auto v=load(path,role,2635409);const Fr expected=role==0?Fr(0):(role==1?Fr(1):Fr(fr_modulus()-1));need(v.size()==2635409&&std::all_of(v.begin(),v.end(),[&](const auto& x){return x==expected;}));++controls;}
 std::cout<<"{\"schema\":\"kpi-owner-fr32-public-parser-controls/v1\",\"status\":\"PASS\",\"controls\":"<<controls<<",\"old_new_same_fields\":true,\"old_small_bytes\":["<<old_a<<','<<old_b<<"],\"new_small_bytes\":["<<new_a<<','<<new_b<<"],\"old_size_only_template_candidates\":1,\"new_size_only_template_candidates\":2,\"large_owner_count\":3,\"large_values_each\":2635409,\"large_bytes_each\":84333120,\"private_bodies_read_or_hashed\":false,\"MPC_or_financial_privacy_claim\":false}\n";
 return 0;}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
