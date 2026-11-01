#include "privacy_registered_fresh_trial_terminal_authority.hpp"

#include "privacy_measurement_run_binding_wire.hpp"
#include "../mpc-prover/financial/registered_capture_plan_roster_bridge_contract.hpp"
#include "../mpc-prover/financial/registered_fresh_trial_history_ledger_storage.hpp"
#include "../mpc-prover/financial/registered_trial_attempt_history_storage.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <set>
#include <span>
#include <string_view>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

namespace kpb::measurement::empirical_result {
namespace {

namespace history =
    kpi::mpc::financial::registered_driver::attempt_history;

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

bool canonical_uuid(std::string_view value) {
    if (value.size() != 36 || value[8] != '-' || value[13] != '-' ||
        value[18] != '-' || value[23] != '-' || value[14] != '4' ||
        std::string_view("89ab").find(value[19]) ==
            std::string_view::npos)
        return false;
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (index == 8 || index == 13 || index == 18 || index == 23)
            continue;
        const char byte = value[index];
        if (!((byte >= '0' && byte <= '9') ||
              (byte >= 'a' && byte <= 'f')))
            return false;
    }
    return true;
}

class HashAccumulator final {
    EVP_MD_CTX* context_{EVP_MD_CTX_new()};
    bool finished_{};
public:
    HashAccumulator() {
        need(context_ != nullptr &&
             EVP_DigestInit_ex(context_, EVP_sha256(), nullptr) == 1);
    }
    HashAccumulator(const HashAccumulator&) = delete;
    HashAccumulator& operator=(const HashAccumulator&) = delete;
    ~HashAccumulator() { EVP_MD_CTX_free(context_); }
    void add(std::span<const unsigned char> value) {
        need(!finished_ && (value.empty() || EVP_DigestUpdate(
            context_, value.data(), value.size()) == 1));
    }
    void add(const Digest& value) { add(std::span<const unsigned char>(value)); }
    void text(std::string_view value) {
        integer(value.size());
        add({reinterpret_cast<const unsigned char*>(value.data()),
             value.size()});
    }
    void integer(std::uint64_t value) {
        std::array<unsigned char, 8> bytes{};
        for (unsigned shift = 0; shift < 64; shift += 8)
            bytes[shift / 8] = static_cast<unsigned char>(value >> shift);
        add(bytes);
    }
    Digest finish() {
        need(!finished_);
        finished_ = true;
        Digest result{};
        unsigned length = 0;
        need(EVP_DigestFinal_ex(context_, result.data(), &length) == 1 &&
             length == result.size() && nonzero(result));
        return result;
    }
};

Digest hash_fd(int fd, std::uint64_t size) {
    HashAccumulator hash;
    std::array<unsigned char, 65536> buffer{};
    std::uint64_t at = 0;
    while (at < size) {
        const auto wanted = static_cast<std::size_t>(
            std::min<std::uint64_t>(buffer.size(), size - at));
        ssize_t count;
        do {
            count = ::pread(fd, buffer.data(), wanted,
                            static_cast<off_t>(at));
        } while (count < 0 && errno == EINTR);
        need(count > 0 && static_cast<std::size_t>(count) <= wanted);
        hash.add(std::span(buffer.data(), static_cast<std::size_t>(count)));
        at += static_cast<std::uint64_t>(count);
    }
    return hash.finish();
}

void exact_c03_fd(
        const history::RegisteredAttemptHistoryRowStorage& row,
        std::set<std::pair<std::uint64_t, std::uint64_t>>& seen_inodes) {
    const int fd = row.sealed_c03.value;
    struct stat before{};
    need(fd >= 0 && ::fstat(fd, &before) == 0 &&
         S_ISREG(before.st_mode) && before.st_nlink == 0 &&
         (before.st_mode & 0777) == 0600 && before.st_size >= 0 &&
         static_cast<std::uint64_t>(before.st_dev) ==
             row.sealed_c03_device &&
         static_cast<std::uint64_t>(before.st_ino) ==
             row.sealed_c03_inode &&
         static_cast<std::uint64_t>(before.st_size) == row.c03_bytes &&
         row.sealed_c03_mode == static_cast<std::uint32_t>(before.st_mode) &&
         row.sealed_c03_seals == 0 &&
         row.sealed_c03_access_mode == O_RDONLY &&
         (::fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDONLY &&
         (::fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0 &&
         seen_inodes.insert({row.sealed_c03_device,
                             row.sealed_c03_inode}).second &&
         nonzero(row.c03_sha256));
    const Digest observed = hash_fd(fd, row.c03_bytes);
    struct stat after{};
    need(observed == row.c03_sha256 && ::fstat(fd, &after) == 0 &&
         before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
         before.st_size == after.st_size && before.st_mode == after.st_mode &&
         before.st_nlink == after.st_nlink);
}

void add_row_identity(
        HashAccumulator& identity,
        const history::RegisteredAttemptHistoryRowStorage& row) {
    identity.integer(row.round);
    identity.integer(row.ordinal);
    identity.integer(row.retry_ordinal);
    identity.text(row.attempt_uuid);
    for (const auto* value : {
             &row.attempt_identity, &row.predecessor,
             &row.trial_predecessor, &row.partial_tail_sha256,
             &row.c03_sha256, &row.financial_run, &row.cohort,
             &row.capture_plan, &row.projection, &row.capture_source,
             &row.capture_build, &row.capture_runtime,
             &row.capture_launcher, &row.route_requirement,
             &row.route_completion, &row.process_identity,
             &row.child_exit_identity})
        identity.add(*value);
    identity.integer(row.start_monotonic_ns);
    identity.integer(row.end_monotonic_ns);
    identity.integer(static_cast<unsigned>(row.outcome));
    identity.integer(static_cast<unsigned>(row.failure));
    identity.integer(static_cast<unsigned>(row.stream_state));
    identity.integer(static_cast<std::uint32_t>(row.wait_status));
    identity.integer(static_cast<std::uint32_t>(row.wait_exit_code));
    identity.integer(static_cast<std::uint32_t>(row.wait_signal));
    identity.integer(row.partial_tail_bytes);
    identity.integer(row.c03_bytes);
    identity.integer(row.sealed_c03_device);
    identity.integer(row.sealed_c03_inode);
}

Digest source_ledger_identity(
        const Digest& prior,
        const history::RegisteredTrialAttemptHistoryStorage& trial,
        std::size_t index) {
    HashAccumulator identity;
    identity.add({reinterpret_cast<const unsigned char*>(
                      "KPB_REGISTERED_FRESH_TRIAL_HISTORY_LEDGER_V1\n"),
                  sizeof("KPB_REGISTERED_FRESH_TRIAL_HISTORY_LEDGER_V1\n") -
                      1});
    identity.add(prior);
    identity.integer(index);
    const std::array<unsigned char, 1> failed{
        static_cast<unsigned char>(trial.failed_trial ? 1 : 0)};
    identity.add(failed);
    identity.text(trial.capture_trial_id);
    identity.add(trial.trial_identity);
    identity.add(trial.history_identity);
    return identity.finish();
}

void exact_persistent_exit(
        const history::RegisteredTrialAttemptHistoryStorage& trial,
        std::set<Digest>& seen_exit_authorities,
        std::set<Digest>& seen_process_sessions,
        HashAccumulator& identity) {
    need(trial.persistent_role_exit != nullptr);
    const auto& exited = *trial.persistent_role_exit;
    need(exited.live_and_clean() &&
         exited.capture_trial_id() == trial.capture_trial_id &&
         exited.trial_identity() == trial.trial_identity &&
         nonzero(exited.authority_identity()) &&
         nonzero(exited.process_session_identity()) &&
         seen_exit_authorities.insert(exited.authority_identity()).second &&
         seen_process_sessions.insert(
             exited.process_session_identity()).second);

    const auto& pids = exited.child_pids();
    const auto& channels = exited.round_channels();
    std::set<Digest> fork_plans;
    std::set<Digest> offers;
    std::set<Digest> acknowledgements;
    std::int64_t parent_pid = -1;
    for (unsigned round = 0; round < channels.size(); ++round) {
        const auto& channel = channels[round];
        need(channel.all_children_exited_zero &&
             nonzero(channel.fork_plan_identity) &&
             fork_plans.insert(channel.fork_plan_identity).second);
        identity.add(channel.fork_plan_identity);
        for (unsigned role = 0; role < pids.size(); ++role) {
            const auto& ack = channel.acknowledgements[role];
            need(ack.role == role && ack.round == round + 1 &&
                 ack.parent_pid > 1 && ack.child_pid == pids[role] &&
                 ack.fork_plan_identity == channel.fork_plan_identity &&
                 nonzero(ack.offer_identity) && nonzero(ack.ack_identity) &&
                 offers.insert(ack.offer_identity).second &&
                 acknowledgements.insert(ack.ack_identity).second);
            if (parent_pid < 0) parent_pid = ack.parent_pid;
            need(ack.parent_pid == parent_pid);
            identity.integer(role);
            identity.integer(round + 1);
            identity.integer(static_cast<std::uint64_t>(ack.parent_pid));
            identity.integer(static_cast<std::uint64_t>(ack.child_pid));
            identity.add(ack.offer_identity);
            identity.add(ack.ack_identity);
        }
    }
    need(fork_plans.size() == 2 && offers.size() == 6 &&
         acknowledgements.size() == 6);
    identity.add(exited.process_session_identity());
    identity.add(exited.authority_identity());
}

void exact_trial(
        const history::RegisteredTrialAttemptHistoryStorage& trial,
        bool final_success,
        std::set<std::pair<std::uint64_t, std::uint64_t>>& seen_inodes,
        std::set<Digest>& seen_trials, std::set<Digest>& seen_histories,
        std::set<Digest>& seen_closures, std::set<Digest>& seen_attempts,
        std::set<Digest>& seen_processes,
        std::set<Digest>& seen_child_exits,
        std::set<Digest>& seen_producer_exits,
        std::set<Digest>& seen_exit_authorities,
        std::set<Digest>& seen_process_sessions,
        HashAccumulator& identity) {
    need(trial.producer_binding != nullptr &&
         canonical_uuid(trial.capture_trial_id) &&
         nonzero(trial.trial_identity) && nonzero(trial.history_identity) &&
         nonzero(trial.producer_closure_identity) &&
         trial.rows.size() == 2 && trial.retry_closed &&
         trial.producer_source_slots == std::array<unsigned, 2>{3, 8} &&
         trial.producer_fixed_fds == std::array<unsigned, 2>{23, 28} &&
         trial.producer_writer_aliases_closed &&
         (trial.producer_wait_observed ||
          trial.producer_pidfd_exit_observed) &&
         trial.producer_pid > 1 &&
         nonzero(trial.producer_child_exit_identity) &&
         seen_trials.insert(trial.trial_identity).second &&
         seen_histories.insert(trial.history_identity).second &&
         seen_closures.insert(trial.producer_closure_identity).second &&
         seen_producer_exits.insert(
             trial.producer_child_exit_identity).second);
    const auto& binding = *trial.producer_binding;
    validate_measurement_run_binding(binding);
    need(binding.trial == trial.trial_identity &&
         binding.trial == kpi::mpc::financial::registered_driver::
             RegisteredCapturePlanRosterBridge::trial_identity(
                 trial.capture_trial_id) &&
         static_cast<unsigned char>(binding.classification) ==
             static_cast<unsigned char>(trial.classification) &&
         trial.failed_trial == !final_success &&
         trial.terminal_seen == (final_success
             ? std::array<bool, 2>{true, true}
             : std::array<bool, 2>{false, false}));
    exact_persistent_exit(
        trial, seen_exit_authorities, seen_process_sessions, identity);

    if (final_success) {
        need(trial.producer_wait_observed &&
             trial.producer_wait_status >= 0 &&
             WIFEXITED(trial.producer_wait_status) &&
             WEXITSTATUS(trial.producer_wait_status) == 0);
    } else if (!trial.producer_wait_observed) {
        need(trial.producer_pidfd_exit_observed &&
             trial.producer_wait_status == -1);
    } else {
        need(trial.producer_wait_status >= 0 &&
             (WIFEXITED(trial.producer_wait_status) ||
              WIFSIGNALED(trial.producer_wait_status)));
    }

    identity.text(trial.capture_trial_id);
    identity.add(trial.trial_identity);
    identity.add(trial.history_identity);
    identity.add(trial.producer_closure_identity);
    const auto binding_bytes = wire::canonical_run_binding_bytes(binding);
    identity.add(binding_bytes);
    identity.integer(final_success ? 1 : 0);

    for (unsigned index = 0; index < 2; ++index) {
        const auto& row = trial.rows[index];
        need(row.round == index + 1 && row.ordinal == index &&
             row.retry_ordinal == 0 && row.predecessor == Digest{} &&
             row.trial_predecessor ==
                 (index == 0 ? Digest{} : trial.rows[0].attempt_identity) &&
             canonical_uuid(row.attempt_uuid) &&
             nonzero(row.attempt_identity) &&
             binding.round_attempts[index] ==
                 kpi::mpc::financial::registered_driver::
                     RegisteredCapturePlanRosterBridge::attempt_identity(
                         row.attempt_uuid) &&
             seen_attempts.insert(row.attempt_identity).second &&
             row.start_monotonic_ns > 0 &&
             row.end_monotonic_ns >= row.start_monotonic_ns &&
             (index == 0 || row.start_monotonic_ns >=
                 trial.rows[0].start_monotonic_ns) &&
             static_cast<unsigned>(row.outcome) >= 1 &&
             static_cast<unsigned>(row.outcome) <= 6 &&
             static_cast<unsigned>(row.failure) <= 16 &&
             static_cast<unsigned>(row.stream_state) >= 1 &&
             static_cast<unsigned>(row.stream_state) <= 6 &&
             row.financial_run == binding.financial_runs[index] &&
             row.cohort == binding.round_cohorts[index] &&
             row.capture_plan == binding.round_capture_plans[index] &&
             row.projection == binding.projections[index] &&
             row.capture_source == binding.capture_source &&
             row.capture_build == binding.capture_build &&
             row.capture_runtime == binding.capture_runtime &&
             row.capture_launcher == binding.capture_launcher &&
             nonzero(row.route_requirement) &&
             nonzero(row.process_identity) &&
             nonzero(row.child_exit_identity) &&
             seen_processes.insert(row.process_identity).second &&
             seen_child_exits.insert(row.child_exit_identity).second);
        exact_c03_fd(row, seen_inodes);

        if (trial.producer_wait_observed) {
            need(row.wait_status == trial.producer_wait_status);
            if (WIFEXITED(trial.producer_wait_status))
                need(row.wait_exit_code ==
                         WEXITSTATUS(trial.producer_wait_status) &&
                     row.wait_signal == 0);
            else
                need(row.wait_exit_code == -1 && row.wait_signal ==
                         WTERMSIG(trial.producer_wait_status));
        } else {
            need(row.wait_status == -1 && row.wait_exit_code == -1 &&
                 row.wait_signal == 0 &&
                 row.outcome == history::AttemptOutcome::Error &&
                 row.failure == history::AttemptFailure::
                     WaitStatusUnavailable);
        }

        if (final_success) {
            need(row.outcome == history::AttemptOutcome::Complete &&
                 row.failure == history::AttemptFailure::None &&
                 row.stream_state == history::AttemptStreamState::
                     CompleteEnd &&
                 row.c03_bytes > 0 && nonzero(row.route_completion) &&
                 row.partial_tail_bytes == 0 &&
                 row.partial_tail_sha256 == Digest{});
        } else {
            need(row.outcome != history::AttemptOutcome::Complete &&
                 (row.stream_state != history::AttemptStreamState::
                      CompleteEnd ||
                  row.failure != history::AttemptFailure::None) &&
                 row.partial_tail_bytes == row.c03_bytes &&
                 row.partial_tail_sha256 == row.c03_sha256);
            if (row.c03_bytes == 0)
                need(row.stream_state ==
                         history::AttemptStreamState::Empty);
        }
        add_row_identity(identity, row);
    }
}

Digest validate_ledger(
        history::RegisteredFreshTrialHistoryLedgerStorage& ledger,
        bool complete) {
    need(!ledger.trials.empty() && nonzero(ledger.ledger_identity) &&
         ledger.complete_seen == complete);
    std::set<std::pair<std::uint64_t, std::uint64_t>> seen_inodes;
    std::set<Digest> seen_trials;
    std::set<Digest> seen_histories;
    std::set<Digest> seen_closures;
    std::set<Digest> seen_attempts;
    std::set<Digest> seen_processes;
    std::set<Digest> seen_child_exits;
    std::set<Digest> seen_producer_exits;
    std::set<Digest> seen_exit_authorities;
    std::set<Digest> seen_process_sessions;
    HashAccumulator identity;
    Digest source_identity{};
    identity.add({reinterpret_cast<const unsigned char*>(
                      "KPB_REGISTERED_FRESH_TRIAL_TERMINAL_V2\n"),
                  sizeof("KPB_REGISTERED_FRESH_TRIAL_TERMINAL_V2\n") - 1});
    identity.add(ledger.ledger_identity);
    identity.integer(ledger.trials.size());
    for (std::size_t index = 0; index < ledger.trials.size(); ++index) {
        need(ledger.trials[index] != nullptr);
        const bool final_success = complete &&
            index + 1 == ledger.trials.size();
        need(ledger.trials[index]->failed_trial == !final_success);
        if (index > 0) {
            const auto& prior = *ledger.trials[index - 1];
            const auto& selected = *ledger.trials[index];
            need(selected.rows.front().start_monotonic_ns >=
                     prior.rows.back().end_monotonic_ns &&
                 static_cast<unsigned char>(selected.classification) ==
                     static_cast<unsigned char>(
                         ledger.trials.front()->classification) &&
                 selected.rows.front().capture_source ==
                     ledger.trials.front()->rows.front().capture_source &&
                 selected.rows.front().capture_build ==
                     ledger.trials.front()->rows.front().capture_build &&
                 selected.rows.front().capture_runtime ==
                     ledger.trials.front()->rows.front().capture_runtime &&
                 selected.rows.front().capture_launcher ==
                     ledger.trials.front()->rows.front().capture_launcher);
        }
        exact_trial(*ledger.trials[index], final_success, seen_inodes,
                    seen_trials, seen_histories, seen_closures,
                    seen_attempts, seen_processes, seen_child_exits,
                    seen_producer_exits, seen_exit_authorities,
                    seen_process_sessions, identity);
        source_identity = source_ledger_identity(
            source_identity, *ledger.trials[index], index);
    }
    need(source_identity == ledger.ledger_identity);
    return identity.finish();
}

void cleanse(Digest& value) noexcept {
    OPENSSL_cleanse(value.data(), value.size());
}

} // namespace

RegisteredFreshTrialTerminalHistoryAuthority::
RegisteredFreshTrialTerminalHistoryAuthority(
        std::unique_ptr<Storage> storage, Digest identity)
    : storage_(std::move(storage)), private_identity_(identity) {
    need(storage_ != nullptr && nonzero(private_identity_));
}

RegisteredFreshTrialTerminalHistoryAuthority::
RegisteredFreshTrialTerminalHistoryAuthority(
        RegisteredFreshTrialTerminalHistoryAuthority&& other) noexcept
    : storage_(std::move(other.storage_)),
      private_identity_(other.private_identity_) {
    cleanse(other.private_identity_);
}

RegisteredFreshTrialTerminalHistoryAuthority::~
RegisteredFreshTrialTerminalHistoryAuthority() {
    cleanse(private_identity_);
}

RegisteredAbortedFreshTrialTerminalHistoryAuthority::
RegisteredAbortedFreshTrialTerminalHistoryAuthority(
        std::unique_ptr<Storage> storage, Digest identity)
    : storage_(std::move(storage)), private_identity_(identity) {
    need(storage_ != nullptr && nonzero(private_identity_));
}

RegisteredAbortedFreshTrialTerminalHistoryAuthority::
RegisteredAbortedFreshTrialTerminalHistoryAuthority(
        RegisteredAbortedFreshTrialTerminalHistoryAuthority&& other) noexcept
    : storage_(std::move(other.storage_)),
      private_identity_(other.private_identity_) {
    cleanse(other.private_identity_);
}

RegisteredAbortedFreshTrialTerminalHistoryAuthority::~
RegisteredAbortedFreshTrialTerminalHistoryAuthority() {
    cleanse(private_identity_);
}

RegisteredTerminalAttemptHistoryJoiner::
RegisteredTerminalAttemptHistoryJoiner(Mode mode) : mode_(mode) {}

RegisteredTerminalAttemptHistoryJoiner
RegisteredTerminalAttemptHistoryJoiner::for_final_success() {
    return RegisteredTerminalAttemptHistoryJoiner(Mode::Success);
}

RegisteredTerminalAttemptHistoryJoiner
RegisteredTerminalAttemptHistoryJoiner::for_aborted_run() {
    return RegisteredTerminalAttemptHistoryJoiner(Mode::Aborted);
}

RegisteredTerminalAttemptHistoryJoiner::
RegisteredTerminalAttemptHistoryJoiner(
        RegisteredTerminalAttemptHistoryJoiner&& other) noexcept
    : mode_(other.mode_), storage_(std::move(other.storage_)),
      private_identity_(other.private_identity_),
      accepting_(other.accepting_.exchange(false)),
      finish_live_(other.finish_live_.exchange(false)),
      poisoned_(other.poisoned_) {
    cleanse(other.private_identity_);
    other.poisoned_ = true;
}

RegisteredTerminalAttemptHistoryJoiner::~
RegisteredTerminalAttemptHistoryJoiner() {
    cleanse(private_identity_);
}

void RegisteredTerminalAttemptHistoryJoiner::accept(
        std::unique_ptr<Storage> supplied, bool complete) {
    auto selected = std::move(supplied);
    try {
        need(accepting_.exchange(false) && !poisoned_ &&
             storage_ == nullptr && selected != nullptr &&
             complete == (mode_ == Mode::Success));
        const std::lock_guard<std::mutex> lock(selected->mutex);
        private_identity_ = validate_ledger(*selected, complete);
        storage_ = std::move(selected);
    } catch (...) {
        poisoned_ = true;
        storage_.reset();
        cleanse(private_identity_);
        refuse();
    }
}

RegisteredFreshTrialTerminalHistoryAuthority
RegisteredTerminalAttemptHistoryJoiner::finish_success() && {
    const bool live = finish_live_.exchange(false);
    auto selected = std::move(storage_);
    Digest identity = private_identity_;
    cleanse(private_identity_);
    need(live && !poisoned_ && mode_ == Mode::Success &&
         selected != nullptr && nonzero(identity));
    return RegisteredFreshTrialTerminalHistoryAuthority(
        std::move(selected), identity);
}

RegisteredAbortedFreshTrialTerminalHistoryAuthority
RegisteredTerminalAttemptHistoryJoiner::finish_aborted() && {
    const bool live = finish_live_.exchange(false);
    auto selected = std::move(storage_);
    Digest identity = private_identity_;
    cleanse(private_identity_);
    need(live && !poisoned_ && mode_ == Mode::Aborted &&
         selected != nullptr && nonzero(identity));
    return RegisteredAbortedFreshTrialTerminalHistoryAuthority(
        std::move(selected), identity);
}

#ifdef KPB_REGISTERED_FRESH_TRIAL_TERMINAL_TEST_SETUP
void RegisteredTerminalAttemptHistoryJoiner::test_only_accept_storage(
        RegisteredTerminalAttemptHistoryJoiner& joiner,
        std::unique_ptr<Storage> storage, bool complete) {
    joiner.accept(std::move(storage), complete);
}
#endif

} // namespace kpb::measurement::empirical_result
