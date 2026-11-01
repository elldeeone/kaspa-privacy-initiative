#include "registered_driver_bridge.hpp"

#include "accepted_head.hpp"
#include "construction.hpp"
#include "../history/epoch_ticket.hpp"
#include "../owner_inputs_active.hpp"

#include <array>
#include <span>
#include <string>
#include <vector>

namespace kpi::mpc::financial::attempt_supervisor {
namespace {
using Digest = identity_registry::Digest;

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }

std::array<Digest, 3> owner_identities(
        std::span<const OwnerInputContract> jobs) {
    need(jobs.size() == 3);
    std::array<Digest, 3> result{};
    for (std::size_t role = 0; role < result.size(); ++role) {
        need(jobs[role].owner_id == static_cast<int>(role));
        const auto canonical = canonical_owner_contract(jobs[role]);
        result[role] = identity_registry::digest(std::span(
            reinterpret_cast<const unsigned char*>(canonical.data()),
            canonical.size()));
        need(result[role] != Digest{});
    }
    return result;
}

std::array<OwnerInputContract, 3> owner_array(
        std::span<const OwnerInputContract> jobs) {
    need(jobs.size() == 3);
    return {jobs[0], jobs[1], jobs[2]};
}

} // namespace

DirectAcceptedHeadCommitment RegisteredProposalBridge::direct_head(
        const AcceptedFinancialHead& head) {
    const auto identity = head.binding().identity;
    need(identity != Digest{});
    return DirectAcceptedHeadCommitment(identity);
}

CanonicalOwnerContractsCommitment RegisteredProposalBridge::owner_contracts(
        std::span<const OwnerInputContract> jobs) {
    return CanonicalOwnerContractsCommitment(owner_identities(jobs));
}

Proposal RegisteredProposalBridge::proposal(
        registered_driver::CompiledFreshAttemptAuthority&& fresh,
        registered_driver::AuthenticatedPartyDeliveryAuthority&& delivery,
        const registered_driver::CompiledDriverSelection& driver,
        const RegisteredService& service, const AcceptedFinancialHead& head,
        std::span<const OwnerInputContract> jobs) {
    try {
        const bool fresh_live = fresh.live_.exchange(false);
        const bool delivery_live = delivery.live_.exchange(false);
        need(fresh_live && delivery_live);
        const auto& f = fresh.value_;
        const auto& d = delivery.value_;
        const auto& selected_driver = driver.value_;
        need(selected_driver.role < 3 &&
             selected_driver.owner_port >= 1024 &&
             selected_driver.owner_port <= 65533 &&
             selected_driver.multiplication_batch > 0);
        for (const auto* value : {
                 &selected_driver.authority_identity,
                 &selected_driver.selection_identity,
                 &selected_driver.service_identity,
                 &selected_driver.source_identity,
                 &selected_driver.build_identity,
                 &selected_driver.roster_identity,
                 &selected_driver.capture_source_identity,
                 &selected_driver.capture_build_identity,
                 &selected_driver.capture_launcher_identity})
            need(*value != Digest{});
        need(f.role < 3 && f.role == selected_driver.role &&
             f.role == service.party_id() && d.role == f.role &&
             f.authority_identity != Digest{} &&
             f.authority_identity == selected_driver.authority_identity &&
             d.authority_identity == f.authority_identity &&
             f.service_identity == service.identity() &&
             f.service_identity == selected_driver.service_identity &&
             d.service_identity == f.service_identity &&
             f.source_identity == selected_driver.source_identity &&
             f.build_identity == selected_driver.build_identity &&
             f.driver_selection_identity == driver.identity_ &&
             d.driver_selection_identity == driver.identity_ &&
             d.supervisor_session != Digest{} && d.party_session != Digest{} &&
             d.supervisor_session != d.party_session);
        for (const auto* value : {&f.run, &f.trial, &f.attempt, &f.cohort})
            need(*value != Digest{});

        const auto& accepted = head.binding();
        need(accepted.identity != Digest{} &&
             accepted.service_identity == service.identity() &&
             accepted.registration == service.registration() &&
             accepted.key == service.key());
        for (const auto& job : jobs)
            need(job.run_nonce == identity_registry::hex(f.attempt) &&
                 job.cohort_identity == identity_registry::hex(f.cohort));

        const auto owners = owner_identities(jobs);
        identity_registry::Selection selection{
            .run = f.run,
            .trial = f.trial,
            .attempt = f.attempt,
            .cohort = f.cohort,
            .accepted_head = accepted.identity,
            .owner_contracts = owners,
        };
        need(identity_registry::selection_identity(selection) ==
             selected_driver.selection_identity);
        return Proposal(
            f.role, f.authority_identity, d.supervisor_session,
            d.party_session,
            AttemptLineageCommitment(f.run, f.trial, f.attempt, f.cohort),
            DirectAcceptedHeadCommitment(accepted.identity),
            CanonicalOwnerContractsCommitment(owners));
    } catch (...) { refuse(); }
}

DurableLockCommitment RegisteredProposalBridge::durable_lock(
        const Proposal& proposal, const history::LockedAttempt& locked,
        std::span<const OwnerInputContract> jobs) {
    const auto& selected = proposal.public_selection_hashes();
    const auto& binding = locked.binding();
    const auto owners = owner_identities(jobs);
    const auto aggregate = FinancialConstruction::owner_contracts_identity(
        owner_array(jobs));
    need(proposal.role() < 3 && owners == selected.owner_contracts &&
         binding.attempt == selected.attempt &&
         binding.cohort == selected.cohort &&
         binding.admitted_head == selected.accepted_head &&
         binding.owner_contracts == aggregate &&
         locked.binding_identity() != Digest{});
    return DurableLockCommitment(
        proposal.role(), identity_registry::selection_identity(selected),
        selected.accepted_head, locked.binding_identity());
}

} // namespace kpi::mpc::financial::attempt_supervisor
