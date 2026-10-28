#include "epoch_journal.hpp"
#include <algorithm>
#include <sodium/crypto_generichash_blake2b.h>

namespace kpi::mpc::history {
ScriptPublicKey reserve_spk(const State& state,std::span<const unsigned char> tail) {
    if(!std::equal(state.begin(),state.begin()+8,"KPBAST01")||tail.empty()||tail.size()>65535-114)
        throw Refused();
    std::vector<unsigned char> redeem{0x4c,0x70};
    redeem.insert(redeem.end(),state.begin(),state.end());
    redeem.insert(redeem.end(),tail.begin(),tail.end());
    ScriptPublicKey result{};result[2]=0xaa;result[3]=0x20;result[36]=0x87;
    if(crypto_generichash_blake2b(result.data()+4,32,redeem.data(),redeem.size(),nullptr,0)!=0)
        throw Refused();
    return result;
}
} // namespace kpi::mpc::history
