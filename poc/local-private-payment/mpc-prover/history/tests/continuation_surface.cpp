#include "../settlement_capability.hpp"
#include <type_traits>
using namespace kpi::mpc::history;
template<class T>concept HasPublicAppend=requires(T& j,SettlementRecord r){j.record_verified_settlement(r,uint64_t{},Digest{});};
template<class T>concept HasBoolean=requires(T& j){j.resolve(true);};
template<class T>concept HasImport=requires(T& j){j.import_settlement(std::string{});};
static_assert(!HasPublicAppend<EpochJournal>&&!HasBoolean<EpochJournal>&&!HasImport<VerifiedSettlement>);
static_assert(!std::is_default_constructible_v<VerifiedSettlement>&&!std::is_copy_constructible_v<VerifiedSettlement>
    &&!std::is_move_constructible_v<VerifiedSettlement>&&!std::is_constructible_v<VerifiedSettlement,bool>);
static_assert(!std::is_default_constructible_v<VerifiedFinalCandidate>&&!std::is_copy_constructible_v<VerifiedFinalCandidate>
    &&!std::is_move_constructible_v<VerifiedFinalCandidate>&&!std::is_constructible_v<VerifiedFinalCandidate,bool>
    &&!std::is_convertible_v<VerifiedFinalCandidate,VerifiedSettlement>);
int main(){}
