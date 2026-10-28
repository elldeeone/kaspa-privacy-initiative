#include "../epoch_journal.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
using namespace kpi::mpc::history;
std::vector<unsigned char> decode(const std::string& text) {
    if(text.size()%2)throw Refused();
    std::vector<unsigned char> result;
    auto digit=[](char x)->unsigned{if(x>='0'&&x<='9')return x-'0';if(x>='a'&&x<='f')return x-'a'+10;throw Refused();};
    for(size_t i=0;i<text.size();i+=2) { result.push_back((digit(text[i])<<4)|digit(text[i+1])); }
    return result;
}
int main(int argc,char** argv) {
    try {
        if(argc!=6)return 1;
        std::ifstream file(argv[1],std::ios::binary);std::vector<unsigned char> tail{std::istreambuf_iterator<char>(file),{}};
        const auto a=decode(argv[2]),expected_a=decode(argv[3]),b=decode(argv[4]),expected_b=decode(argv[5]);
        if(a.size()!=112||b.size()!=112||expected_a.size()!=37||expected_b.size()!=37)return 1;
        State sa{},sb{};std::copy(a.begin(),a.end(),sa.begin());std::copy(b.begin(),b.end(),sb.begin());
        const auto before_a=sa,before_b=sb;const auto before_tail=tail;
        const auto got_a=reserve_spk(sa,tail),got_b=reserve_spk(sb,tail);
        if(!std::equal(got_a.begin(),got_a.end(),expected_a.begin())||!std::equal(got_b.begin(),got_b.end(),expected_b.begin())
           ||sa!=before_a||sb!=before_b||tail!=before_tail||got_a==got_b)return 1;
        unsigned refused=0;
        try{(void)reserve_spk(sa,{});}catch(const Refused&){++refused;}
        sa[0]^=1;try{(void)reserve_spk(sa,tail);}catch(const Refused&){++refused;}
        std::vector<unsigned char> oversize(65535-114+1,1);try{(void)reserve_spk(sb,oversize);}catch(const Refused&){++refused;}
        if(refused!=3)return 1;
        std::cout<<"{\"schema\":\"history-public-policy-controls/v1\",\"classification\":\"PUBLIC_NATIVE_EMITTER_COMPARISON_ONLY\",\"two_actual_native_emitter_BLAKE2b256_matches\":true,\"state_tail_unchanged\":true,\"wrong_tag_empty_oversize_refusals\":3,\"financial_proof_or_native_acceptance\":false}\n";
    }catch(...){return 1;}
}
