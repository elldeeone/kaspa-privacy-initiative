#include "../mpc-prover/financial/registered_parent_trial_completion_storage.hpp"
#include "privacy_measurement_authority.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::registered_driver {
namespace {

using MeasurementDigest = kpb::measurement::Digest;
using MeasurementParty = kpb::measurement::PublicPartyCompletion;
using MeasurementPartyAuthority = kpb::measurement::PartyCompletionAuthority;
using MeasurementClassification = kpb::measurement::Classification;

[[noreturn]] void refuse() { throw kpb::measurement::Refused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) { return value != Digest{}; }

void add(std::vector<unsigned char>& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}

void add(std::vector<unsigned char>& out, const Digest& value) {
    out.insert(out.end(), value.begin(), value.end());
}

void add(std::vector<unsigned char>& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

Digest identity(
        std::string_view domain, const Digest& process_session,
        unsigned round, const std::array<Digest, 3>& values) {
    std::vector<unsigned char> bytes;
    add(bytes, domain);
    add(bytes, process_session);
    add(bytes, round);
    for (const auto& value : values) add(bytes, value);
    return identity_registry::digest(bytes);
}

Digest party_identity(
        std::string_view domain, const Digest& process_session,
        const PublicParentRoleAcknowledgement& acknowledgement,
        const PublicParentObservedPartyCompletion& observation,
        const PublicPartyDriverCompletion& party) {
    std::vector<unsigned char> bytes;
    add(bytes, domain);
    add(bytes, process_session);
    add(bytes, party.round);
    add(bytes, party.role);
    add(bytes, static_cast<std::uint64_t>(acknowledgement.parent_pid));
    add(bytes, static_cast<std::uint64_t>(acknowledgement.child_pid));
    for (const auto* value : {
             &acknowledgement.fork_plan_identity,
             &acknowledgement.offer_identity,
             &acknowledgement.ack_identity,
             &observation.observation_identity,
             &party.completion_identity})
        add(bytes, *value);
    return identity_registry::digest(bytes);
}

MeasurementClassification classification(CaptureClassification value) {
    switch (value) {
    case CaptureClassification::HiddenCandidate:
        return MeasurementClassification::HiddenCandidate;
    case CaptureClassification::ExplicitOwnerPublicEffectsBaseline:
        return MeasurementClassification::TransparentBaseline;
    }
    refuse();
}

} // namespace

void RegisteredMeasurementCaptureBridge::destroy_retention(
        void* raw) noexcept {
    delete static_cast<RegisteredParentTrialCompletionAuthority::Storage*>(
        raw);
}

void RegisteredMeasurementCaptureBridge::submit(
        kpb::measurement::TrialCaptureJoiner& joiner,
        RegisteredParentTrialCompletionAuthority&& authority) {
    // Claim the whole trial before taking the joiner lock. A later mismatch
    // destroys both rounds, all six observed completions, both projections,
    // and every retained baseline effect.
    auto storage = std::move(authority.storage_);
    std::lock_guard guard(joiner.mutex_);
    try {
        need(storage != nullptr && !joiner.poisoned_ && !joiner.finished_ &&
             !joiner.registered_trial_.has_value() &&
             joiner.producer_.has_value() &&
             joiner.producer_evidence_.has_value() &&
             joiner.observer_admission_.has_value() &&
             storage->exit_evidence.all_children_exited_zero_value() &&
             nonzero(storage->exit_evidence
                         .process_session_identity_value()));
        kpb::measurement::validate_measurement_run_binding(joiner.binding_);
        for (const auto& round : joiner.parties_)
            for (const auto& party : round) need(!party.has_value());

        std::set<std::int64_t> child_pids;
        const auto& child_pid_values =
            storage->exit_evidence.child_pids_value();
        const auto& round_channel_values =
            storage->exit_evidence.round_channels_value();
        const auto& pidfd_exit_observed =
            storage->exit_evidence.pidfd_exit_observed_value();
        const auto& wait_status_available =
            storage->exit_evidence.wait_status_available_value();
        const auto& pid_identity_exact =
            storage->exit_evidence.pid_identity_exact_value();
        const auto& exit_codes =
            storage->exit_evidence.exit_codes_value();
        const auto& term_signals =
            storage->exit_evidence.term_signals_value();
        const auto& process_session_identity =
            storage->exit_evidence.process_session_identity_value();
        for (const auto pid : child_pid_values)
            need(pid > 1 && child_pids.insert(pid).second);
        need(child_pids.size() == 3);
        for (unsigned role = 0; role < child_pid_values.size(); ++role)
            need(pidfd_exit_observed[role] &&
                 wait_status_available[role] &&
                 pid_identity_exact[role] && exit_codes[role] == 0 &&
                 term_signals[role] == 0);

        std::array<std::array<std::optional<MeasurementPartyAuthority>, 3>, 2>
            converted;
        std::set<Digest> completion_identities;
        std::set<Digest> observation_identities;
        std::set<Digest> process_identities;
        std::set<Digest> child_exit_identities;

        for (unsigned round = 0; round < 2; ++round) {
            const auto& channel = round_channel_values[round];
            const auto& route =
                storage->retained_projections[round].public_receipt();
            need(channel.all_children_exited_zero &&
                 nonzero(channel.fork_plan_identity) &&
                 route.round == round + 1 && route.exact_size &&
                 route.read_complete && route.kernel_eof && route.clean &&
                 route.trial == joiner.binding_.trial &&
                 route.financial_run == joiner.binding_.financial_runs[round] &&
                 route.attempt == joiner.binding_.round_attempts[round] &&
                 route.cohort == joiner.binding_.round_cohorts[round] &&
                 nonzero(route.producer_process_authority) &&
                 nonzero(route.producer_exit_authority) &&
                 nonzero(route.dispatcher_process_authority) &&
                 nonzero(route.dispatcher_exit_authority));

            const auto& projection_stream =
                joiner.producer_->streams[round * 5];
            const auto& dispatcher_stream =
                joiner.producer_->streams[round * 5 + 2];
            need(projection_stream.round == round + 1 &&
                 projection_stream.kind ==
                     kpb::measurement::CaptureKind::PublicProjection &&
                 dispatcher_stream.round == round + 1 &&
                 dispatcher_stream.kind ==
                     kpb::measurement::CaptureKind::Dispatcher &&
                 route.producer_process_authority ==
                     projection_stream.process_identity &&
                 route.producer_exit_authority ==
                     projection_stream.child_exit_identity &&
                 route.dispatcher_process_authority ==
                     dispatcher_stream.process_identity &&
                 route.dispatcher_exit_authority ==
                     dispatcher_stream.child_exit_identity);

            std::array<Digest, 3> durable_locks{};
            std::array<Digest, 3> egress_bindings{};
            for (unsigned role = 0; role < 3; ++role) {
                const auto& observed = storage->party_completions[round][role]
                    .public_observation();
                const auto& party = storage->party_completions[round][role]
                    .public_party_completion();
                const auto& acknowledgement = channel.acknowledgements[role];
                need(party.round == round + 1 && party.role == role &&
                     classification(party.classification) ==
                         joiner.binding_.classification &&
                     party.run == joiner.binding_.financial_runs[round] &&
                     party.trial == joiner.binding_.trial &&
                     party.attempt == joiner.binding_.round_attempts[round] &&
                     party.cohort == joiner.binding_.round_cohorts[round] &&
                     party.capture_plan_identity ==
                         joiner.binding_.round_capture_plans[round] &&
                     party.projection_identity ==
                         joiner.binding_.projections[round] &&
                     party.capture_source_identity ==
                         joiner.binding_.capture_source &&
                     party.capture_build_identity ==
                         joiner.binding_.capture_build &&
                     party.capture_launcher_identity ==
                         joiner.binding_.capture_launcher &&
                     party.accepted_head == party.postlock_accepted_head &&
                     observed.role == role &&
                     observed.round == round + 1 &&
                     observed.child_pid == child_pid_values[role] &&
                     observed.party_completion_identity ==
                         party.completion_identity &&
                     acknowledgement.role == role &&
                     acknowledgement.round == round + 1 &&
                     acknowledgement.child_pid == child_pid_values[role] &&
                     acknowledgement.parent_pid == observed.parent_pid &&
                     acknowledgement.child_pid == observed.child_pid &&
                     acknowledgement.fork_plan_identity ==
                         channel.fork_plan_identity &&
                     acknowledgement.fork_plan_identity ==
                         observed.fork_plan_identity &&
                     acknowledgement.offer_identity == observed.offer_identity &&
                     acknowledgement.ack_identity ==
                         observed.acknowledgement_identity &&
                     completion_identities.insert(
                         party.completion_identity).second &&
                     observation_identities.insert(
                         observed.observation_identity).second &&
                     storage->baseline_effects[round][role].has_value() ==
                         (joiner.binding_.classification ==
                          MeasurementClassification::TransparentBaseline));
                durable_locks[role] = party.durable_lock;
                egress_bindings[role] = party.egress_binding_identity;
            }

            const auto round_lock = identity(
                "KPB_REGISTERED_MEASUREMENT_ROUND_DURABLE_LOCK_V1\n",
                process_session_identity, round + 1,
                durable_locks);
            const auto round_egress = identity(
                "KPB_REGISTERED_MEASUREMENT_ROUND_EGRESS_V1\n",
                process_session_identity, round + 1,
                egress_bindings);
            need(nonzero(round_lock) && nonzero(round_egress));

            const auto& first = storage->party_completions[round][0]
                .public_party_completion();
            for (unsigned role = 0; role < 3; ++role) {
                const auto& observed = storage->party_completions[round][role]
                    .public_observation();
                const auto& party = storage->party_completions[round][role]
                    .public_party_completion();
                const auto& acknowledgement = channel.acknowledgements[role];
                need(party.selection_identity == first.selection_identity &&
                     party.accepted_head == first.accepted_head &&
                     party.effects_identity == first.effects_identity &&
                     party.core_identity == first.core_identity &&
                     party.proof_identity == first.proof_identity &&
                     party.projection_identity == first.projection_identity);
                const auto process_identity = party_identity(
                    "KPB_REGISTERED_MEASUREMENT_PARTY_PROCESS_V1\n",
                    process_session_identity, acknowledgement,
                    observed, party);
                const auto child_exit_identity = party_identity(
                    "KPB_REGISTERED_MEASUREMENT_PARTY_CLEAN_EXIT_V1\n",
                    process_session_identity, acknowledgement,
                    observed, party);
                need(process_identities.insert(process_identity).second &&
                     child_exit_identities.insert(
                         child_exit_identity).second);
                MeasurementParty receipt{
                    .binding = joiner.binding_,
                    .round = round + 1,
                    .role = role,
                    .financial_run = party.run,
                    .trial = party.trial,
                    .attempt = party.attempt,
                    .cohort = party.cohort,
                    .child_exit = child_exit_identity,
                    .driver_completion = party.completion_identity,
                    .selection_identity = party.selection_identity,
                    .proposal_identity = party.proposal_identity,
                    .accepted_head = party.accepted_head,
                    .postlock_accepted_head = party.postlock_accepted_head,
                    .durable_lock = round_lock,
                    .capture_source = party.capture_source_identity,
                    .capture_build = party.capture_build_identity,
                    .capture_runtime = joiner.binding_.capture_runtime,
                    .capture_launcher = party.capture_launcher_identity,
                    .process_identity = process_identity,
                    .egress = round_egress,
                    .proof = party.proof_identity,
                    .projection = party.projection_identity,
                };
                MeasurementPartyAuthority selected(std::move(receipt));
                converted[round][role].emplace(std::move(selected));
            }
        }
        need(completion_identities.size() == 6 &&
             observation_identities.size() == 6 &&
             process_identities.size() == 6 &&
             child_exit_identities.size() == 6);

        RegisteredMeasurementCaptureRetention retention(
            storage.release(), &destroy_retention);
        for (unsigned round = 0; round < 2; ++round)
            for (unsigned role = 0; role < 3; ++role) {
                auto& party = *converted[round][role];
                need(party.live_.exchange(false));
                joiner.parties_[round][role] = party.receipt_;
            }
        joiner.registered_trial_.emplace(std::move(retention));
    } catch (...) {
        joiner.poisoned_ = true;
        refuse();
    }
}

} // namespace kpi::mpc::financial::registered_driver
