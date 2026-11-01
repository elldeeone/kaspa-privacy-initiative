#include "registered_selected_parent_orchestrator.hpp"
#include "registered_parent_trial_completion_storage.hpp"

#include "authenticated_baseline_owner_receiver.hpp"
#include "registered_party_completion_transport.hpp"

#include <algorithm>
#include <array>
#include <optional>
#include <set>
#include <utility>

namespace kpi::mpc::financial::registered_driver {
namespace {

using baseline_disclosure::PartyBaselineOwnerEffectsAuthority;

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) { return value != Digest{}; }

void require_common_party(
        const PublicPartyDriverCompletion& first,
        const PublicPartyDriverCompletion& party, unsigned role) {
    need(party.role == role && party.round == first.round &&
         party.classification == first.classification &&
         party.capture_trial_id == first.capture_trial_id &&
         party.authority_identity == first.authority_identity &&
         party.selection_identity == first.selection_identity &&
         party.run == first.run && party.trial == first.trial &&
         party.attempt == first.attempt && party.cohort == first.cohort &&
         party.accepted_head == first.accepted_head &&
         party.postlock_accepted_head == first.postlock_accepted_head &&
         party.owner_contracts == first.owner_contracts &&
         party.capture_plan_identity == first.capture_plan_identity &&
         party.capture_source_identity == first.capture_source_identity &&
         party.capture_build_identity == first.capture_build_identity &&
         party.capture_launcher_identity == first.capture_launcher_identity &&
         party.effects_identity == first.effects_identity &&
         party.core_identity == first.core_identity &&
         party.proof_identity == first.proof_identity &&
         party.projection_identity == first.projection_identity &&
         party.full_cohort_barrier_identity ==
             first.full_cohort_barrier_identity &&
         party.full_cohort_barrier_observed_monotonic_ns ==
             first.full_cohort_barrier_observed_monotonic_ns);
}

void require_release_barrier(
        const PublicPartyDriverCompletion& first,
        bool authorized, const Digest& barrier_identity,
        std::uint64_t barrier_monotonic_ns,
        const std::array<Digest, 3>& readiness_identities) {
    need(authorized && nonzero(barrier_identity) &&
         barrier_monotonic_ns > 0 &&
         first.full_cohort_barrier_identity ==
             barrier_identity &&
         first.full_cohort_barrier_observed_monotonic_ns ==
             barrier_monotonic_ns &&
         std::all_of(
             readiness_identities.begin(), readiness_identities.end(),
             [](const Digest& value) { return nonzero(value); }) &&
         readiness_identities[0] != readiness_identities[1] &&
         readiness_identities[0] != readiness_identities[2] &&
         readiness_identities[1] != readiness_identities[2]);
}

} // namespace

struct RegisteredParentRoundCompletionAuthority::Storage final {
    projection_route::ParentRetainedProjectionAuthority retained_projection;
    std::array<ParentObservedPartyCompletionAuthority, 3> party_completions;
    std::array<std::optional<PartyBaselineOwnerEffectsAuthority>, 3>
        baseline_effects;
    PublicParentRoleForkCompletion child_exit;

    Storage(
            projection_route::ParentRetainedProjectionAuthority&& retained,
            std::array<ParentObservedPartyCompletionAuthority, 3>&& parties,
            std::array<std::optional<PartyBaselineOwnerEffectsAuthority>, 3>&&
                effects,
            PublicParentRoleForkCompletion exited)
        : retained_projection(std::move(retained)),
          party_completions(std::move(parties)),
          baseline_effects(std::move(effects)),
          child_exit(std::move(exited)) {}
};

struct RegisteredParentPendingRoundCompletionAuthority::Storage final {
    projection_route::ParentRetainedProjectionAuthority retained_projection;
    std::array<ParentObservedPartyCompletionAuthority, 3> party_completions;
    std::array<std::optional<PartyBaselineOwnerEffectsAuthority>, 3>
        baseline_effects;
    PublicParentRoleForkCompletion channel;

    Storage(
            projection_route::ParentRetainedProjectionAuthority&& retained,
            std::array<ParentObservedPartyCompletionAuthority, 3>&& parties,
            std::array<std::optional<PartyBaselineOwnerEffectsAuthority>, 3>&&
                effects,
            PublicParentRoleForkCompletion round_channel)
        : retained_projection(std::move(retained)),
          party_completions(std::move(parties)),
          baseline_effects(std::move(effects)),
          channel(std::move(round_channel)) {}
};

RegisteredParentRoundCompletionAuthority::
RegisteredParentRoundCompletionAuthority(std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }
RegisteredParentRoundCompletionAuthority::
RegisteredParentRoundCompletionAuthority(
        RegisteredParentRoundCompletionAuthority&&) noexcept = default;
RegisteredParentRoundCompletionAuthority::~
RegisteredParentRoundCompletionAuthority() = default;

RegisteredParentPendingRoundCompletionAuthority::
RegisteredParentPendingRoundCompletionAuthority(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }
RegisteredParentPendingRoundCompletionAuthority::
RegisteredParentPendingRoundCompletionAuthority(
        RegisteredParentPendingRoundCompletionAuthority&&) noexcept = default;
RegisteredParentPendingRoundCompletionAuthority::~
RegisteredParentPendingRoundCompletionAuthority() = default;

RegisteredParentTrialCompletionAuthority::Storage::Storage(
        std::array<projection_route::ParentRetainedProjectionAuthority, 2>&&
            routes,
        std::array<std::array<ParentObservedPartyCompletionAuthority, 3>, 2>&&
            parties,
        std::array<std::array<std::optional<
            PartyBaselineOwnerEffectsAuthority>, 3>, 2>&& effects,
        std::string selected_trial_id,
        detail::PersistentRoleExitEvidence&& selected_exit_evidence)
    : retained_projections(std::move(routes)),
      party_completions(std::move(parties)),
      baseline_effects(std::move(effects)),
      capture_trial_id(std::move(selected_trial_id)),
      exit_evidence(std::move(selected_exit_evidence)) {}

RegisteredParentTrialCompletionAuthority::
RegisteredParentTrialCompletionAuthority(std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }
RegisteredParentTrialCompletionAuthority::
RegisteredParentTrialCompletionAuthority(
        RegisteredParentTrialCompletionAuthority&&) noexcept = default;
RegisteredParentTrialCompletionAuthority::~
RegisteredParentTrialCompletionAuthority() = default;

RegisteredParentRoundCompletionAuthority
RegisteredParentRoundCompletionBridge::join(
        projection_route::ParentRetainedProjectionAuthority&& route,
        ParentObservedRegisteredPartyResult&& role0,
        ParentObservedRegisteredPartyResult&& role1,
        ParentObservedRegisteredPartyResult&& role2,
        ParentRoleChildren& children) {
    try {
        // Claim first. Any later mismatch destroys the only live route rather
        // than leaving an ACKed projection reusable outside this exact join.
        projection_route::ParentRetainedProjectionAuthority claimed_route(
            std::move(route));
        need(claimed_route.live_.load() && claimed_route.receipt_.exact_size &&
             claimed_route.receipt_.read_complete &&
             claimed_route.receipt_.kernel_eof &&
             claimed_route.receipt_.clean &&
             claimed_route.plan_.computing_role == 0 &&
             claimed_route.plan_.round == claimed_route.receipt_.round &&
             claimed_route.plan_.trial == claimed_route.receipt_.trial &&
             claimed_route.plan_.attempt == claimed_route.receipt_.attempt &&
             claimed_route.plan_.cohort == claimed_route.receipt_.cohort &&
             claimed_route.plan_.financial_run ==
                 claimed_route.receipt_.financial_run &&
             nonzero(claimed_route.plan_.capture_plan_identity) &&
             nonzero(claimed_route.projection_identity_) &&
             nonzero(claimed_route.route_identity_) &&
             nonzero(claimed_route.retained_identity_) &&
             nonzero(claimed_route.fork_binding_identity_));

        std::array<ParentObservedRegisteredPartyResult*, 3> supplied{
            &role0, &role1, &role2};
        std::array<std::optional<ParentObservedPartyCompletionAuthority>, 3>
            completions;
        std::array<std::optional<PartyBaselineOwnerEffectsAuthority>, 3>
            baseline_effects;
        for (unsigned role = 0; role < supplied.size(); ++role) {
            const bool baseline = supplied[role]->has_baseline_effects();
            need(baseline ==
                 (claimed_route.plan_.classification == CaptureClassification::
                     ExplicitOwnerPublicEffectsBaseline));
            completions[role].emplace(
                supplied[role]->take_party_completion());
            if (baseline)
                baseline_effects[role].emplace(
                    supplied[role]->take_baseline_effects());
        }

        const auto& first = completions[0]->public_party_completion();
        std::set<Digest> completion_identities;
        std::set<Digest> observation_identities;
        for (unsigned role = 0; role < completions.size(); ++role) {
            const auto& observed = completions[role]->public_observation();
            const auto& party = completions[role]->public_party_completion();
            require_common_party(first, party, role);
            need(observed.role == role && observed.round == party.round &&
                 nonzero(observed.fresh_owner_issuance_identity) &&
                 observed.fresh_owner_issuance_identity ==
                     children.completion_bindings_[role]
                         .fresh_owner_issuance_identity &&
                 observed.party_completion_identity ==
                     party.completion_identity &&
                 completion_identities.insert(
                     party.completion_identity).second &&
                 observation_identities.insert(
                     observed.observation_identity).second);
        }
        need(first.role == 0 &&
             claimed_route.plan_.classification == first.classification &&
             claimed_route.plan_.round == first.round &&
             claimed_route.plan_.trial == first.trial &&
             claimed_route.plan_.financial_run == first.run &&
             claimed_route.plan_.attempt == first.attempt &&
             claimed_route.plan_.cohort == first.cohort &&
             claimed_route.plan_.capture_plan_identity ==
                 first.capture_plan_identity &&
             claimed_route.projection_identity_ == first.projection_identity);
        require_release_barrier(
            first, children.full_cohort_release_authorized_,
            children.full_cohort_barrier_identity_,
            children.full_cohort_barrier_monotonic_ns_,
            children.release_ready_identities_);

        const auto child_exit = children.wait();
        need(child_exit.all_children_exited_zero &&
             nonzero(child_exit.fork_plan_identity));
        for (unsigned role = 0; role < completions.size(); ++role) {
            const auto& observed = completions[role]->public_observation();
            need(observed.fork_plan_identity ==
                     child_exit.fork_plan_identity &&
                 child_exit.acknowledgements[role].role == role &&
                 child_exit.acknowledgements[role].round == first.round &&
                 child_exit.acknowledgements[role].child_pid ==
                     observed.child_pid &&
                 child_exit.acknowledgements[role].offer_identity ==
                     observed.offer_identity &&
                 child_exit.acknowledgements[role].ack_identity ==
                     observed.acknowledgement_identity);
        }

        std::array<ParentObservedPartyCompletionAuthority, 3> parties{
            std::move(*completions[0]), std::move(*completions[1]),
            std::move(*completions[2])};
        return RegisteredParentRoundCompletionAuthority(
            std::make_unique<RegisteredParentRoundCompletionAuthority::
                Storage>(
                    std::move(claimed_route), std::move(parties),
                    std::move(baseline_effects), child_exit));
    } catch (...) { refuse(); }
}

RegisteredParentPendingRoundCompletionAuthority
RegisteredParentRoundCompletionBridge::defer(
        projection_route::ParentRetainedProjectionAuthority&& route,
        ParentObservedRegisteredPartyResult&& role0,
        ParentObservedRegisteredPartyResult&& role1,
        ParentObservedRegisteredPartyResult&& role2,
        ParentRoleChildren& children) {
    try {
        projection_route::ParentRetainedProjectionAuthority claimed_route(
            std::move(route));
        need(claimed_route.live_.load() && claimed_route.receipt_.exact_size &&
             claimed_route.receipt_.read_complete &&
             claimed_route.receipt_.kernel_eof &&
             claimed_route.receipt_.clean &&
             claimed_route.plan_.computing_role == 0 &&
             claimed_route.plan_.round == claimed_route.receipt_.round &&
             claimed_route.plan_.trial == claimed_route.receipt_.trial &&
             claimed_route.plan_.attempt == claimed_route.receipt_.attempt &&
             claimed_route.plan_.cohort == claimed_route.receipt_.cohort &&
             claimed_route.plan_.financial_run ==
                 claimed_route.receipt_.financial_run &&
             nonzero(claimed_route.plan_.capture_plan_identity) &&
             nonzero(claimed_route.projection_identity_) &&
             nonzero(claimed_route.route_identity_) &&
             nonzero(claimed_route.retained_identity_) &&
             nonzero(claimed_route.fork_binding_identity_));

        std::array<ParentObservedRegisteredPartyResult*, 3> supplied{
            &role0, &role1, &role2};
        std::array<std::optional<ParentObservedPartyCompletionAuthority>, 3>
            completions;
        std::array<std::optional<PartyBaselineOwnerEffectsAuthority>, 3>
            effects;
        for (unsigned role = 0; role < supplied.size(); ++role) {
            const bool baseline = supplied[role]->has_baseline_effects();
            need(baseline ==
                 (claimed_route.plan_.classification == CaptureClassification::
                    ExplicitOwnerPublicEffectsBaseline));
            completions[role].emplace(
                supplied[role]->take_party_completion());
            if (baseline)
                effects[role].emplace(
                    supplied[role]->take_baseline_effects());
        }

        const auto& first = completions[0]->public_party_completion();
        std::set<Digest> completion_identities;
        std::set<Digest> observation_identities;
        for (unsigned role = 0; role < completions.size(); ++role) {
            const auto& observed = completions[role]->public_observation();
            const auto& party = completions[role]->public_party_completion();
            require_common_party(first, party, role);
            need(observed.role == role && observed.round == party.round &&
                 nonzero(observed.fresh_owner_issuance_identity) &&
                 observed.fresh_owner_issuance_identity ==
                     children.completion_bindings_[role]
                         .fresh_owner_issuance_identity &&
                 observed.party_completion_identity ==
                     party.completion_identity &&
                 completion_identities.insert(
                     party.completion_identity).second &&
                 observation_identities.insert(
                     observed.observation_identity).second);
        }
        need(first.role == 0 &&
             claimed_route.plan_.classification == first.classification &&
             claimed_route.plan_.round == first.round &&
             claimed_route.plan_.trial == first.trial &&
             claimed_route.plan_.financial_run == first.run &&
             claimed_route.plan_.attempt == first.attempt &&
             claimed_route.plan_.cohort == first.cohort &&
             claimed_route.plan_.capture_plan_identity ==
                 first.capture_plan_identity &&
             claimed_route.projection_identity_ == first.projection_identity);
        require_release_barrier(
            first, children.full_cohort_release_authorized_,
            children.full_cohort_barrier_identity_,
            children.full_cohort_barrier_monotonic_ns_,
            children.release_ready_identities_);

        PublicParentRoleForkCompletion channel;
        {
            need(children.completion_state_ != nullptr);
            std::scoped_lock guard(
                children.mutex_, children.completion_state_->mutex);
            need(children.live_ && !children.process_owner_ &&
                 !children.completion_state_->poisoned &&
                 std::all_of(
                     children.completion_endpoints_taken_.begin(),
                     children.completion_endpoints_taken_.end(),
                     [](bool value) { return value; }) &&
                 std::all_of(
                     children.completion_state_->completed.begin(),
                     children.completion_state_->completed.end(),
                     [](bool value) { return value; }) &&
                 (!nonzero(children.projection_route_identity_) ||
                  children.projection_route_parent_bound_));
            children.live_ = false;
            channel = {
                .fork_plan_identity = children.fork_plan_identity_,
                .acknowledgements = children.acknowledgements_,
                .all_children_exited_zero = false,
            };
        }
        for (unsigned role = 0; role < completions.size(); ++role) {
            const auto& observed = completions[role]->public_observation();
            need(observed.fork_plan_identity == channel.fork_plan_identity &&
                 channel.acknowledgements[role].role == role &&
                 channel.acknowledgements[role].round == first.round &&
                 channel.acknowledgements[role].child_pid ==
                     observed.child_pid &&
                 channel.acknowledgements[role].offer_identity ==
                     observed.offer_identity &&
                 channel.acknowledgements[role].ack_identity ==
                     observed.acknowledgement_identity);
        }

        std::array<ParentObservedPartyCompletionAuthority, 3> parties{
            std::move(*completions[0]), std::move(*completions[1]),
            std::move(*completions[2])};
        return RegisteredParentPendingRoundCompletionAuthority(
            std::make_unique<
                RegisteredParentPendingRoundCompletionAuthority::Storage>(
                    std::move(claimed_route), std::move(parties),
                    std::move(effects), channel));
    } catch (...) { refuse(); }
}

RegisteredParentTrialCompletionAuthority
RegisteredParentTrialCompletionBridge::join(
        RegisteredParentPendingRoundCompletionAuthority&& round1,
        RegisteredParentPendingRoundCompletionAuthority&& round2,
        RegisteredPersistentRoleSession& session) {
    session.claim_trial_join();
    auto first_storage = std::move(round1.storage_);
    auto second_storage = std::move(round2.storage_);
    try {
        need(first_storage != nullptr && second_storage != nullptr);
        const auto& first = first_storage->party_completions[0]
            .public_party_completion();
        const auto& second = second_storage->party_completions[0]
            .public_party_completion();
        need(first.round == 1 && second.round == 2 &&
             first.classification == second.classification &&
             first.capture_trial_id == second.capture_trial_id &&
             first.trial == RegisteredCapturePlanRosterBridge::trial_identity(
                 first.capture_trial_id) &&
             first.trial == second.trial &&
             first.capture_source_identity ==
                 second.capture_source_identity &&
             first.capture_build_identity ==
                 second.capture_build_identity &&
             first.capture_launcher_identity ==
                 second.capture_launcher_identity &&
             first.accepted_head == first.postlock_accepted_head &&
             second.accepted_head == second.postlock_accepted_head &&
             first.run != second.run &&
             first.attempt != second.attempt &&
             first.cohort != second.cohort &&
             first.authority_identity != second.authority_identity &&
             first.capture_plan_identity !=
                 second.capture_plan_identity &&
             first.projection_identity != second.projection_identity &&
             first.full_cohort_barrier_identity !=
                 second.full_cohort_barrier_identity &&
             first.full_cohort_barrier_observed_monotonic_ns <
                 second.full_cohort_barrier_observed_monotonic_ns &&
             first.accepted_head != second.accepted_head &&
             first.owner_contracts != second.owner_contracts &&
             !first_storage->channel.all_children_exited_zero &&
             !second_storage->channel.all_children_exited_zero);

        std::set<Digest> completions;
        std::set<Digest> observations;
        std::set<std::int64_t> role_pids;
        const auto fresh_owner_issuance_identity = first_storage
            ->party_completions[0].public_observation()
            .fresh_owner_issuance_identity;
        need(nonzero(fresh_owner_issuance_identity));
        for (unsigned round = 0; round < 2; ++round) {
            const auto& storage = round == 0
                ? *first_storage : *second_storage;
            for (unsigned role = 0; role < 3; ++role) {
                const auto& party = storage.party_completions[role]
                    .public_party_completion();
                const auto& observed = storage.party_completions[role]
                    .public_observation();
                need(party.round == round + 1 && party.role == role &&
                     party.trial == first.trial &&
                     party.capture_trial_id == first.capture_trial_id &&
                     party.classification == first.classification &&
                     completions.insert(party.completion_identity).second &&
                     observations.insert(observed.observation_identity).second &&
                     observed.role == role &&
                     observed.round == round + 1 &&
                     observed.fresh_owner_issuance_identity ==
                         fresh_owner_issuance_identity &&
                     observed.party_completion_identity ==
                         party.completion_identity);
                if (round == 0)
                    need(role_pids.insert(observed.child_pid).second);
                else
                    need(observed.child_pid == first_storage
                        ->party_completions[role]
                        .public_observation().child_pid);
            }
        }
        need(completions.size() == 6 && observations.size() == 6 &&
             role_pids.size() == 3);

        auto exited = session.finish_wait_for_trial();
        need(exited.all_children_exited_zero_value() &&
             nonzero(exited.process_session_identity_value()));
        const auto& exit_round_channels = exited.round_channels_value();
        const auto& exit_child_pids = exited.child_pids_value();
        for (unsigned round = 0; round < 2; ++round) {
            const auto& pending = round == 0
                ? first_storage->channel : second_storage->channel;
            const auto& final = exit_round_channels[round];
            need(final.all_children_exited_zero &&
                 final.fork_plan_identity == pending.fork_plan_identity);
            for (unsigned role = 0; role < 3; ++role) {
                const auto& before = pending.acknowledgements[role];
                const auto& after = final.acknowledgements[role];
                need(before.role == role && after.role == role &&
                     before.round == round + 1 &&
                     after.round == round + 1 &&
                     before.parent_pid == after.parent_pid &&
                     before.child_pid == after.child_pid &&
                     before.child_pid == exit_child_pids[role] &&
                     before.fork_plan_identity ==
                         after.fork_plan_identity &&
                     before.offer_identity == after.offer_identity &&
                     before.ack_identity == after.ack_identity);
            }
        }

        std::array<projection_route::ParentRetainedProjectionAuthority, 2>
            routes{
                std::move(first_storage->retained_projection),
                std::move(second_storage->retained_projection)};
        std::array<std::array<ParentObservedPartyCompletionAuthority, 3>, 2>
            parties{
                std::move(first_storage->party_completions),
                std::move(second_storage->party_completions)};
        std::array<std::array<std::optional<
            PartyBaselineOwnerEffectsAuthority>, 3>, 2> effects{
                std::move(first_storage->baseline_effects),
                std::move(second_storage->baseline_effects)};
        return RegisteredParentTrialCompletionAuthority(
            std::make_unique<RegisteredParentTrialCompletionAuthority::
                Storage>(
                    std::move(routes), std::move(parties),
                    std::move(effects), first.capture_trial_id,
                    std::move(exited)));
    } catch (...) { refuse(); }
}

} // namespace kpi::mpc::financial::registered_driver
