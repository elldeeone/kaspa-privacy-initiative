#include "../epoch_journal.hpp"
#include <algorithm>
#include <iostream>
using namespace kpi::mpc::history;
int main() {
    try {
        std::vector<unsigned char> core(10364),projection(10685);
        std::copy_n("KPBAEF01",8,core.begin());
        Digest one{},two_fifty_six{},sixty_five_thousand{};
        one[0]=1;two_fifty_six[1]=1;sixty_five_thousand[2]=1;
        const std::array<Digest,3> wire{one,two_fifty_six,sixty_five_thousand};
        for(size_t i=0;i<wire.size();++i)std::copy(wire[i].begin(),wire[i].end(),core.begin()+404+i*96);
        std::copy(core.begin(),core.end(),projection.begin()+193);
        const auto before_core=core,before_projection=projection;
        const auto before_core_sha=digest(core),before_projection_sha=digest(projection);
        const auto history=canonical_history_nullifiers(core);
        if(history!=std::array<Digest,3>{sixty_five_thousand,two_fifty_six,one}
           ||core!=before_core||projection!=before_projection
           ||digest(core)!=before_core_sha||digest(projection)!=before_projection_sha) return 1;
        unsigned refused=0;
        for(unsigned control=0;control<3;++control){
            auto bad=core;
            if(control==0)std::copy_n(core.begin()+500,32,bad.begin()+404);
            if(control==1)std::fill_n(bad.begin()+404,32,0);
            if(control==2){std::copy(wire[2].begin(),wire[2].end(),bad.begin()+404);std::copy(wire[0].begin(),wire[0].end(),bad.begin()+596);}
            try{(void)canonical_history_nullifiers(bad);}catch(const Refused&){++refused;}
        }
        if(refused!=3)return 1;
        std::cout<<"{\"schema\":\"history-NF-order-controls/v1\",\"classification\":\"PUBLIC_ENCODING_ONLY\",\"nonpalindromic_LE_vs_bytelex_regression\":true,\"core_and_projection_bytes_and_SHA_unchanged\":true,\"malformed_order_duplicate_zero_refusals\":3,\"financial_proof_or_privateNF_qualification\":false}\n";
    }catch(...){return 1;}
}
