#pragma once

// History-only residual derived once from the genuine persistent pidfd exit
// capability.  It is not a public process receipt: callers cannot construct
// it from PIDs, wait statuses, booleans or digests.

#include "registered_parent_role_fork.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <string>

namespace kpi::mpc::financial::registered_driver {
class RegisteredParentTrialCompletionAuthority;
}

namespace kpi::mpc::financial::registered_driver::attempt_history {

class RegisteredTrialAttemptHistoryRecorder;

class PersistentRoleExitHistoryAuthority final {
    std::string capture_trial_id_;
    Digest trial_identity_{};
    std::array<std::int64_t, 3> child_pids_{{-1, -1, -1}};
    std::array<bool, 3> pidfd_exit_observed_{};
    std::array<bool, 3> wait_status_available_{};
    std::array<bool, 3> pid_identity_exact_{};
    std::array<int, 3> exit_codes_{{-1, -1, -1}};
    std::array<int, 3> term_signals_{};
    std::array<PublicParentRoleForkCompletion, 2> round_channels_{};
    Digest process_session_identity_{};
    Digest authority_identity_{};
    std::atomic_bool live_{true};
    PersistentRoleExitHistoryAuthority(
        std::string capture_trial_id, Digest trial_identity,
        const detail::PersistentRoleExitEvidence&);
    friend class RegisteredParentTrialHistoryBridge;
public:
    PersistentRoleExitHistoryAuthority(
        const PersistentRoleExitHistoryAuthority&) = delete;
    PersistentRoleExitHistoryAuthority& operator=(
        const PersistentRoleExitHistoryAuthority&) = delete;
    PersistentRoleExitHistoryAuthority(
        PersistentRoleExitHistoryAuthority&&) noexcept;
    PersistentRoleExitHistoryAuthority& operator=(
        PersistentRoleExitHistoryAuthority&&) = delete;
    ~PersistentRoleExitHistoryAuthority();

    const std::string& capture_trial_id() const noexcept {
        return capture_trial_id_;
    }
    const Digest& trial_identity() const noexcept { return trial_identity_; }
    const std::array<std::int64_t, 3>& child_pids() const noexcept {
        return child_pids_;
    }
    const std::array<bool, 3>& pidfd_exit_observed() const noexcept {
        return pidfd_exit_observed_;
    }
    const std::array<bool, 3>& wait_status_available() const noexcept {
        return wait_status_available_;
    }
    const std::array<bool, 3>& pid_identity_exact() const noexcept {
        return pid_identity_exact_;
    }
    const std::array<int, 3>& exit_codes() const noexcept {
        return exit_codes_;
    }
    const std::array<int, 3>& term_signals() const noexcept {
        return term_signals_;
    }
    const std::array<PublicParentRoleForkCompletion, 2>&
    round_channels() const noexcept { return round_channels_; }
    const Digest& process_session_identity() const noexcept {
        return process_session_identity_;
    }
    const Digest& authority_identity() const noexcept {
        return authority_identity_;
    }
    bool live_and_clean() const noexcept;
};

class RegisteredParentTrialHistoryBridge final {
    RegisteredParentTrialHistoryBridge() = delete;
public:
    static void attach_exit_evidence(
        RegisteredParentTrialCompletionAuthority&,
        RegisteredTrialAttemptHistoryRecorder&);
};

} // namespace kpi::mpc::financial::registered_driver::attempt_history
