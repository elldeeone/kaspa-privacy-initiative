#include "registered_persistent_role_exit_history.hpp"

#include "registered_parent_trial_completion_storage.hpp"
#include "registered_trial_attempt_history.hpp"
#include "registered_trial_attempt_history_storage.hpp"
#include "../../private_batch_trial/privacy_measurement_authority.hpp"

#include <algorithm>
#include <mutex>
#include <set>
#include <span>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::registered_driver::attempt_history {
namespace {

[[noreturn]] void refuse() { throw AttemptHistoryRefused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) { return value != Digest{}; }
void add(std::vector<unsigned char>& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add(std::vector<unsigned char>& out, const Digest& value) {
    out.insert(out.end(), value.begin(), value.end());
}
void integer(std::vector<unsigned char>& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}
void add_ack(std::vector<unsigned char>& out,
             const PublicParentRoleAcknowledgement& value) {
    integer(out, value.role);
    integer(out, value.round);
    integer(out, static_cast<std::uint64_t>(value.parent_pid));
    integer(out, static_cast<std::uint64_t>(value.child_pid));
    add(out, value.fork_plan_identity);
    add(out, value.offer_identity);
    add(out, value.ack_identity);
}

Digest residual_identity(
        const std::string& capture_trial_id, const Digest& trial_identity,
        const std::array<std::int64_t, 3>& child_pids,
        const std::array<bool, 3>& pidfd_exit_observed,
        const std::array<bool, 3>& wait_status_available,
        const std::array<bool, 3>& pid_identity_exact,
        const std::array<int, 3>& exit_codes,
        const std::array<int, 3>& term_signals,
        const std::array<PublicParentRoleForkCompletion, 2>& channels,
        const Digest& process_session_identity) {
    std::vector<unsigned char> preimage;
    add(preimage, "KPB_REGISTERED_PERSISTENT_ROLE_EXIT_HISTORY_V1\n");
    integer(preimage, capture_trial_id.size());
    add(preimage, capture_trial_id);
    add(preimage, trial_identity);
    for (unsigned role = 0; role < child_pids.size(); ++role) {
        integer(preimage, static_cast<std::uint64_t>(child_pids[role]));
        preimage.push_back(pidfd_exit_observed[role] ? 1 : 0);
        preimage.push_back(wait_status_available[role] ? 1 : 0);
        preimage.push_back(pid_identity_exact[role] ? 1 : 0);
        integer(preimage, static_cast<std::uint64_t>(exit_codes[role]));
        integer(preimage, static_cast<std::uint64_t>(term_signals[role]));
    }
    for (const auto& channel : channels) {
        add(preimage, channel.fork_plan_identity);
        preimage.push_back(channel.all_children_exited_zero ? 1 : 0);
        for (const auto& acknowledgement : channel.acknowledgements)
            add_ack(preimage, acknowledgement);
    }
    add(preimage, process_session_identity);
    return identity_registry::digest(preimage);
}

} // namespace

PersistentRoleExitHistoryAuthority::PersistentRoleExitHistoryAuthority(
        std::string capture_trial_id, Digest trial_identity,
        const detail::PersistentRoleExitEvidence& evidence)
    : capture_trial_id_(std::move(capture_trial_id)),
      trial_identity_(trial_identity),
      child_pids_(evidence.child_pids_value()),
      pidfd_exit_observed_(evidence.pidfd_exit_observed_value()),
      wait_status_available_(evidence.wait_status_available_value()),
      pid_identity_exact_(evidence.pid_identity_exact_value()),
      exit_codes_(evidence.exit_codes_value()),
      term_signals_(evidence.term_signals_value()),
      round_channels_(evidence.round_channels_value()),
      process_session_identity_(evidence.process_session_identity_value()) {
    need(evidence.all_children_exited_zero_value());
    authority_identity_ = residual_identity(
        capture_trial_id_, trial_identity_, child_pids_,
        pidfd_exit_observed_, wait_status_available_, pid_identity_exact_,
        exit_codes_, term_signals_, round_channels_,
        process_session_identity_);
    need(nonzero(authority_identity_) && live_and_clean());
}

PersistentRoleExitHistoryAuthority::PersistentRoleExitHistoryAuthority(
        PersistentRoleExitHistoryAuthority&& other) noexcept
    : capture_trial_id_(std::move(other.capture_trial_id_)),
      trial_identity_(std::exchange(other.trial_identity_, {})),
      child_pids_(std::exchange(
          other.child_pids_, std::array<std::int64_t, 3>{{-1, -1, -1}})),
      pidfd_exit_observed_(std::exchange(
          other.pidfd_exit_observed_, std::array<bool, 3>{})),
      wait_status_available_(std::exchange(
          other.wait_status_available_, std::array<bool, 3>{})),
      pid_identity_exact_(std::exchange(
          other.pid_identity_exact_, std::array<bool, 3>{})),
      exit_codes_(std::exchange(
          other.exit_codes_, std::array<int, 3>{{-1, -1, -1}})),
      term_signals_(std::exchange(
          other.term_signals_, std::array<int, 3>{})),
      round_channels_(std::exchange(
          other.round_channels_,
          std::array<PublicParentRoleForkCompletion, 2>{})),
      process_session_identity_(std::exchange(
          other.process_session_identity_, {})),
      authority_identity_(std::exchange(other.authority_identity_, {})),
      live_(other.live_.exchange(false)) {}

PersistentRoleExitHistoryAuthority::~PersistentRoleExitHistoryAuthority() =
    default;

bool PersistentRoleExitHistoryAuthority::live_and_clean() const noexcept {
    if (!live_.load() || capture_trial_id_.empty() ||
        !nonzero(trial_identity_) || !nonzero(process_session_identity_) ||
        !nonzero(authority_identity_))
        return false;
    std::set<std::int64_t> pids;
    for (unsigned role = 0; role < child_pids_.size(); ++role)
        if (child_pids_[role] <= 1 || !pids.insert(child_pids_[role]).second ||
            !pidfd_exit_observed_[role] ||
            !wait_status_available_[role] || !pid_identity_exact_[role] ||
            exit_codes_[role] != 0 || term_signals_[role] != 0)
            return false;
    for (unsigned round = 0; round < round_channels_.size(); ++round) {
        const auto& channel = round_channels_[round];
        if (!channel.all_children_exited_zero ||
            !nonzero(channel.fork_plan_identity)) return false;
        for (unsigned role = 0; role < child_pids_.size(); ++role) {
            const auto& ack = channel.acknowledgements[role];
            if (ack.role != role || ack.round != round + 1 ||
                ack.child_pid != child_pids_[role] ||
                !nonzero(ack.fork_plan_identity) ||
                !nonzero(ack.offer_identity) || !nonzero(ack.ack_identity))
                return false;
        }
    }
    return authority_identity_ == residual_identity(
        capture_trial_id_, trial_identity_, child_pids_,
        pidfd_exit_observed_, wait_status_available_, pid_identity_exact_,
        exit_codes_, term_signals_, round_channels_,
        process_session_identity_);
}

void RegisteredParentTrialHistoryBridge::attach_exit_evidence(
        RegisteredParentTrialCompletionAuthority& trial,
        RegisteredTrialAttemptHistoryRecorder& recorder) {
    auto* const trial_storage = trial.storage_.get();
    need(trial_storage != nullptr &&
         !trial_storage->exit_history_residual_taken.exchange(true) &&
         recorder.live_.load() && recorder.storage_ != nullptr);
    std::lock_guard guard(recorder.mutex_);
    auto& history = *recorder.storage_;
    need(history.persistent_role_exit == nullptr &&
         trial_storage->exit_evidence.all_children_exited_zero_value() &&
         !trial_storage->party_completions[0][0]
             .public_party_completion().capture_trial_id.empty());
    const auto& first = trial_storage->party_completions[0][0]
        .public_party_completion();
    need(first.capture_trial_id == history.capture_trial_id &&
         first.trial == history.trial_identity &&
         first.capture_trial_id == trial_storage->capture_trial_id &&
         first.classification == history.classification);
    if (history.producer_binding != nullptr) {
        need(history.producer_binding->trial == first.trial &&
             history.producer_binding->classification ==
                 (first.classification == CaptureClassification::HiddenCandidate
                      ? kpb::measurement::Classification::HiddenCandidate
                      : kpb::measurement::Classification::TransparentBaseline));
        for (unsigned round = 0; round < 2; ++round) {
            const auto& party = trial_storage->party_completions[round][0]
                .public_party_completion();
            need(history.producer_binding->financial_runs[round] == party.run &&
                 history.producer_binding->round_attempts[round] ==
                     party.attempt &&
                 history.producer_binding->round_cohorts[round] ==
                     party.cohort &&
                 history.producer_binding->round_capture_plans[round] ==
                     party.capture_plan_identity &&
                 history.producer_binding->projections[round] ==
                     party.projection_identity);
        }
    }
    history.persistent_role_exit.reset(
        new PersistentRoleExitHistoryAuthority(
            first.capture_trial_id, first.trial,
            trial_storage->exit_evidence));
}

} // namespace kpi::mpc::financial::registered_driver::attempt_history
