#include "testnet_accepted_history_authority.hpp"
#include "../mpc-prover/financial/fresh_owner_process_adapter.hpp"

#include <utility>

namespace kpi::mpc::financial::fresh_owner_issuance {
namespace {

[[noreturn]] void refuse() { throw identity_registry::Refused(); }

} // namespace

FreshOwnerRound1IssuedAuthority
FreshOwnerProcessSupervisor::issue_round1(
        kpb::testnet_history::AcceptedRound1InputChainAuthority&& chain,
        registered_driver::RegisteredPreidentityReadyAuthority&& ready,
        OwnerIssuanceReplayGuardAuthority&& replay,
        FreshOwnerArmIsolationResidualAuthority&& isolation) {
    // Move every caller capability before the chain is opened.  Any failure
    // burns the caller's chain/replay/isolation tuple and poisons this process
    // supervisor; no half can be retried with a replacement observation.
    auto owned_chain = std::move(chain);
    auto owned_ready = std::move(ready);
    auto owned_replay = std::move(replay);
    auto owned_isolation = std::move(isolation);
    try {
        const auto confirmed =
            std::move(owned_chain).consume_for_fresh_owner();
        return issue_round1_from_testnet_history(
            confirmed, &owned_ready, std::move(owned_replay),
            std::move(owned_isolation));
    } catch (...) {
        poison_testnet_history_admission();
        refuse();
    }
}

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
FreshOwnerRound1IssuedAuthority
FreshOwnerProcessSupervisor::issue_round1(
        kpb::testnet_history::AcceptedRound1InputChainAuthority&& chain,
        OwnerIssuanceReplayGuardAuthority&& replay,
        FreshOwnerArmIsolationResidualAuthority&& isolation) {
    auto owned_chain = std::move(chain);
    auto owned_replay = std::move(replay);
    auto owned_isolation = std::move(isolation);
    try {
        const auto confirmed =
            std::move(owned_chain).consume_for_fresh_owner();
        return issue_round1_from_testnet_history(
            confirmed, nullptr, std::move(owned_replay),
            std::move(owned_isolation));
    } catch (...) {
        poison_testnet_history_admission();
        refuse();
    }
}
#endif

FreshOwnerRound2IssuedAuthority
FreshOwnerProcessSupervisor::issue_round2(
        FreshOwnerRound1IssuedAuthority&& round1,
        kpb::testnet_history::AcceptedRound1SuccessorChainAuthority&& chain) {
    auto owned_round1 = std::move(round1);
    auto owned_chain = std::move(chain);
    try {
        const auto confirmed =
            std::move(owned_chain).consume_for_fresh_owner();
        return issue_round2_from_testnet_history(
            std::move(owned_round1), confirmed);
    } catch (...) {
        poison_testnet_history_admission();
        refuse();
    }
}

} // namespace kpi::mpc::financial::fresh_owner_issuance
