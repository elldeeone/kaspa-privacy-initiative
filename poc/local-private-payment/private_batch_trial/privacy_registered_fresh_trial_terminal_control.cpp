#define _GNU_SOURCE 1

#include "privacy_registered_fresh_trial_terminal_authority.hpp"

#include "../mpc-prover/financial/registered_capture_plan_roster_bridge_contract.hpp"
#include "../mpc-prover/financial/registered_driver_bridge.hpp"
#include "../mpc-prover/financial/registered_fresh_trial_history_ledger_storage.hpp"
#include "../mpc-prover/financial/registered_trial_attempt_history_storage.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <concepts>
#include <cstdio>
#include <fcntl.h>
#include <memory>
#include <openssl/sha.h>
#include <span>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace kpb::measurement;
using namespace kpb::measurement::empirical_result;
namespace registered =
    kpi::mpc::financial::registered_driver;
namespace history = registered::attempt_history;

namespace {

template<class Function>
void expect_refused(Function&& function) {
    bool refused = false;
    try { function(); } catch (const Refused&) { refused = true; }
    assert(refused);
}

Digest hash(std::span<const unsigned char> bytes) {
    Digest result{};
    assert(SHA256(bytes.data(), bytes.size(), result.data()) != nullptr);
    return result;
}

Digest digest(std::string_view domain, std::uint64_t value) {
    std::vector<unsigned char> bytes(domain.begin(), domain.end());
    for (unsigned shift = 0; shift < 64; shift += 8)
        bytes.push_back(static_cast<unsigned char>(value >> shift));
    return hash(bytes);
}

void add(std::vector<unsigned char>& out, const Digest& value) {
    out.insert(out.end(), value.begin(), value.end());
}

void add(std::vector<unsigned char>& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}

void le64(std::vector<unsigned char>& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

void text(std::vector<unsigned char>& out, std::string_view value) {
    le64(out, value.size());
    add(out, value);
}

Digest ledger_identity(
        const Digest& prior,
        const history::RegisteredTrialAttemptHistoryStorage& trial,
        std::size_t index) {
    std::vector<unsigned char> bytes;
    add(bytes, "KPB_REGISTERED_FRESH_TRIAL_HISTORY_LEDGER_V1\n");
    add(bytes, prior);
    le64(bytes, index);
    bytes.push_back(trial.failed_trial ? 1 : 0);
    text(bytes, trial.capture_trial_id);
    add(bytes, trial.trial_identity);
    add(bytes, trial.history_identity);
    return hash(bytes);
}

std::string uuid(std::uint64_t value) {
    std::array<char, 37> result{};
    const int written = std::snprintf(
        result.data(), result.size(),
        "%08x-%04x-4%03x-8%03x-%012llx",
        static_cast<unsigned>(value >> 32),
        static_cast<unsigned>((value >> 16) & 0xffff),
        static_cast<unsigned>((value >> 4) & 0xfff),
        static_cast<unsigned>((value * 17) & 0xfff),
        static_cast<unsigned long long>(value & 0xffffffffffffULL));
    assert(written == 36);
    return result.data();
}

WorkerBinding worker(const ManifestEntry& value) {
    return {
        .source_identity = value.source_identity,
        .build_identity = value.build_identity,
        .runtime_identity = value.runtime_identity,
        .assets_identity = value.assets_identity,
        .pinned_executable_identity = value.pinned_executable_identity,
        .launcher_identity = value.launcher_identity,
    };
}

FiniteManifestBinding manifest() {
    std::array<ManifestEntry, 10> entries{};
    for (unsigned index = 0; index < entries.size(); ++index) {
        entries[index] = {
            .component = static_cast<ManifestComponent>(index + 1),
            .source_identity = digest("manifest-source", index),
            .build_identity = digest("manifest-build", index),
            .runtime_identity = digest("manifest-runtime", index),
            .assets_identity = digest("manifest-assets", index),
            .pinned_executable_identity =
                digest("manifest-executable", index),
            .launcher_identity = digest("manifest-launcher", index),
        };
    }
    return {
        .manifest_identity = recompute_finite_manifest_identity(entries),
        .parent_recomputation_identity = digest("parent-recompute", 1),
        .entries = entries,
    };
}

RunBinding binding(
        std::uint64_t trial_index, const std::string& trial_uuid,
        const std::array<std::string, 2>& attempt_uuids) {
    static const FiniteManifestBinding selected = manifest();
    const auto& capture = selected.entries.at(1);
    return {
        .classification = Classification::HiddenCandidate,
        .comparison_selection = digest("comparison", 1),
        .run_selection = digest("run-selection", trial_index),
        .trial = registered::RegisteredCapturePlanRosterBridge::
            trial_identity(trial_uuid),
        .attempt = digest("outer-attempt", trial_index),
        .cohort = digest("outer-cohort", trial_index),
        .capture = digest("capture", trial_index),
        .method = digest("method", 1),
        .workload = digest("workload", 1),
        .source_closure = digest("source-closure", 1),
        .runtime = digest("runtime", 1),
        .finite_manifest = selected,
        .outer_parent_process = digest("parent-process", 1),
        .outer_parent_executable = digest("parent-executable", 1),
        .capture_source = capture.source_identity,
        .capture_build = capture.build_identity,
        .capture_runtime = capture.runtime_identity,
        .capture_launcher = capture.launcher_identity,
        .observer_worker = worker(selected.entries.at(6)),
        .score_worker = worker(selected.entries.at(7)),
        .aggregate_worker = worker(selected.entries.at(8)),
        .financial_runs = {
            digest("financial-r1", trial_index),
            digest("financial-r2", trial_index)},
        .round_attempts = {
            registered::RegisteredCapturePlanRosterBridge::
                attempt_identity(attempt_uuids[0]),
            registered::RegisteredCapturePlanRosterBridge::
                attempt_identity(attempt_uuids[1])},
        .round_cohorts = {
            digest("cohort-r1", trial_index),
            digest("cohort-r2", trial_index)},
        .round_capture_plans = {
            digest("capture-plan-r1", trial_index),
            digest("capture-plan-r2", trial_index)},
        .projections = {
            digest("projection-r1", trial_index),
            digest("projection-r2", trial_index)},
    };
}

struct PrivateFile final {
    int fd{-1};
    std::uint64_t device{};
    std::uint64_t inode{};
    std::uint64_t size{};
    std::uint32_t mode{};
    Digest sha256{};
};

PrivateFile private_file(std::span<const unsigned char> body) {
    int writer = ::open("/tmp", O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
    assert(writer >= 0);
    assert(::fchmod(writer, 0600) == 0);
    std::size_t at = 0;
    while (at < body.size()) {
        const ssize_t written = ::pwrite(
            writer, body.data() + at, body.size() - at,
            static_cast<off_t>(at));
        assert(written > 0);
        at += static_cast<std::size_t>(written);
    }
    assert(::fsync(writer) == 0);
    std::array<char, 64> path{};
    const int length = std::snprintf(
        path.data(), path.size(), "/proc/self/fd/%d", writer);
    assert(length > 0 && static_cast<std::size_t>(length) < path.size());
    const int reader = ::open(path.data(), O_RDONLY | O_CLOEXEC);
    assert(reader >= 0);
    struct stat information{};
    assert(::fstat(reader, &information) == 0 &&
           S_ISREG(information.st_mode) && information.st_nlink == 0 &&
           (information.st_mode & 0777) == 0600 &&
           information.st_size == static_cast<off_t>(body.size()));
    assert(::close(writer) == 0);
    return {
        .fd = reader,
        .device = static_cast<std::uint64_t>(information.st_dev),
        .inode = static_cast<std::uint64_t>(information.st_ino),
        .size = static_cast<std::uint64_t>(body.size()),
        .mode = static_cast<std::uint32_t>(information.st_mode),
        .sha256 = hash(body),
    };
}

history::RegisteredAttemptHistoryRowStorage row(
        const RunBinding& selected, std::uint64_t trial_index,
        unsigned round, const std::string& attempt_uuid,
        const Digest& prior_attempt, bool success, bool empty) {
    std::vector<unsigned char> body;
    if (!empty) {
        const std::string text_body = success
            ? "authenticated-complete-c03" : "retained-partial-c03";
        body.assign(text_body.begin(), text_body.end());
        body.push_back(static_cast<unsigned char>(trial_index));
        body.push_back(static_cast<unsigned char>(round));
    }
    const auto file = private_file(body);
    history::RegisteredAttemptHistoryRowStorage result;
    result.round = round;
    result.ordinal = round - 1;
    result.retry_ordinal = 0;
    result.attempt_uuid = attempt_uuid;
    result.attempt_identity = digest(
        round == 1 ? "attempt-row-r1" : "attempt-row-r2", trial_index);
    result.predecessor = Digest{};
    result.trial_predecessor = round == 1 ? Digest{} : prior_attempt;
    result.start_monotonic_ns = 1000 + trial_index * 100 + round * 10;
    result.end_monotonic_ns = result.start_monotonic_ns + 5;
    result.outcome = success ? history::AttemptOutcome::Complete
                             : history::AttemptOutcome::Partial;
    result.failure = success ? history::AttemptFailure::None
                             : (empty
                                 ? history::AttemptFailure::EmptyStream
                                 : history::AttemptFailure::MissingEnd);
    result.stream_state = success
        ? history::AttemptStreamState::CompleteEnd
        : (empty ? history::AttemptStreamState::Empty
                 : history::AttemptStreamState::ClosedWithoutEnd);
    result.wait_status = success ? 0 : (111 << 8);
    result.wait_exit_code = success ? 0 : 111;
    result.wait_signal = 0;
    result.partial_tail_bytes = success ? 0 : file.size;
    result.partial_tail_sha256 = success ? Digest{} : file.sha256;
    result.c03_sha256 = file.sha256;
    result.c03_bytes = file.size;
    result.sealed_c03_device = file.device;
    result.sealed_c03_inode = file.inode;
    result.sealed_c03_mode = file.mode;
    result.sealed_c03_seals = 0;
    result.sealed_c03_access_mode = O_RDONLY;
    result.sealed_c03.value = file.fd;
    const auto index = round - 1;
    result.financial_run = selected.financial_runs[index];
    result.cohort = selected.round_cohorts[index];
    result.capture_plan = selected.round_capture_plans[index];
    result.projection = selected.projections[index];
    result.capture_source = selected.capture_source;
    result.capture_build = selected.capture_build;
    result.capture_runtime = selected.capture_runtime;
    result.capture_launcher = selected.capture_launcher;
    result.route_requirement = digest(
        round == 1 ? "route-require-r1" : "route-require-r2",
        trial_index);
    result.route_completion = success
        ? digest(round == 1 ? "route-complete-r1" : "route-complete-r2",
                 trial_index)
        : Digest{};
    result.process_identity = digest(
        round == 1 ? "process-r1" : "process-r2", trial_index);
    result.child_exit_identity = digest(
        round == 1 ? "child-exit-r1" : "child-exit-r2", trial_index);
    return result;
}

std::unique_ptr<history::RegisteredTrialAttemptHistoryStorage> trial(
        std::uint64_t index, bool success, bool pidfd_only = false) {
    const std::string trial_uuid = uuid(0x1000 + index);
    const std::array<std::string, 2> attempts{
        uuid(0x100000 + index * 2),
        uuid(0x100001 + index * 2)};
    auto selected = binding(index + 1, trial_uuid, attempts);
    auto result =
        std::make_unique<history::RegisteredTrialAttemptHistoryStorage>();
    result->classification =
        registered::CaptureClassification::HiddenCandidate;
    result->capture_trial_id = trial_uuid;
    result->trial_identity = selected.trial;
    result->producer_binding = std::make_unique<RunBinding>(selected);
    result->producer_closure_identity = digest("producer-closure", index);
    result->producer_source_slots = {3, 8};
    result->producer_fixed_fds = {23, 28};
    result->producer_writer_aliases_closed = true;
    result->producer_wait_observed = !pidfd_only;
    result->producer_pidfd_exit_observed = true;
    result->producer_pid = static_cast<std::int64_t>(5000 + index);
    result->producer_wait_status = pidfd_only
        ? -1 : (success ? 0 : (111 << 8));
    result->producer_child_exit_identity =
        digest("producer-child-exit", index);
    auto first = row(selected, index, 1, attempts[0], Digest{}, success,
                     false);
    const Digest first_attempt = first.attempt_identity;
    auto second = row(selected, index, 2, attempts[1], first_attempt,
                      success, !success);
    if (pidfd_only) {
        for (auto* value : {&first, &second}) {
            value->wait_status = -1;
            value->wait_exit_code = -1;
            value->wait_signal = 0;
            value->outcome = history::AttemptOutcome::Error;
            value->failure = history::AttemptFailure::WaitStatusUnavailable;
        }
    }
    result->rows.push_back(std::move(first));
    result->rows.push_back(std::move(second));
    result->terminal_seen = success
        ? std::array<bool, 2>{true, true}
        : std::array<bool, 2>{false, false};
    result->retry_closed = true;
    result->failed_trial = !success;
    result->history_identity = digest("history", index);
    return result;
}

std::unique_ptr<history::RegisteredFreshTrialHistoryLedgerStorage> ledger(
        std::size_t failed, bool final_success,
        bool pidfd_only_failures = false) {
    auto result =
        std::make_unique<history::RegisteredFreshTrialHistoryLedgerStorage>();
    Digest identity{};
    for (std::size_t index = 0; index < failed; ++index) {
        auto selected = trial(index, false, pidfd_only_failures);
        identity = ledger_identity(identity, *selected, index);
        result->trials.push_back(std::move(selected));
    }
    if (final_success) {
        auto selected = trial(failed, true);
        identity = ledger_identity(identity, *selected, failed);
        result->trials.push_back(std::move(selected));
    }
    result->ledger_identity = identity;
    result->complete_seen = final_success;
    return result;
}

template<class T>
concept HasReceipt = requires(const T& value) { value.public_receipt(); };
template<class T>
concept HasFd = requires(const T& value) { value.fd(); };
template<class T>
concept HasHash = requires(const T& value) { value.hash(); };
template<class T>
concept HasCount = requires(const T& value) { value.trial_count(); };
template<class T>
concept HasLegacyBytes = requires(T& value, std::span<const unsigned char> b) {
    value.submit_kpbemph1(b);
};

void synthetic_unbounded_success_without_exit_authority_refuses() {
    static_assert(!std::default_initializable<
                  RegisteredFreshTrialTerminalHistoryAuthority>);
    static_assert(!std::copy_constructible<
                  RegisteredFreshTrialTerminalHistoryAuthority>);
    static_assert(std::move_constructible<
                  RegisteredFreshTrialTerminalHistoryAuthority>);
    static_assert(!HasReceipt<
                  RegisteredFreshTrialTerminalHistoryAuthority>);
    static_assert(!HasFd<RegisteredFreshTrialTerminalHistoryAuthority>);
    static_assert(!HasHash<RegisteredFreshTrialTerminalHistoryAuthority>);
    static_assert(!HasCount<RegisteredFreshTrialTerminalHistoryAuthority>);
    static_assert(!HasLegacyBytes<RegisteredTerminalAttemptHistoryJoiner>);
    static_assert(kRegisteredFreshTrialTerminalSourceStatus.
                  ordered_unbounded_fresh_trials);
    static_assert(!kRegisteredFreshTrialTerminalSourceStatus.
                  legacy_kpbemph1_accepted);
    static_assert(!kRegisteredFreshTrialTerminalSourceStatus.
                  typed_pidfd_exit_evidence);
    static_assert(!kRegisteredFreshTrialTerminalSourceStatus.
                  fresh_trial_bound_closure_authority);
    static_assert(!kRegisteredFreshTrialTerminalSourceStatus.
                  final_observer_archive_join);
    static_assert(!kRegisteredFreshTrialTerminalSourceStatus.
                  selected_runtime_callsite);
    static_assert(!kRegisteredFreshTrialTerminalSourceStatus.configured);

    auto joiner = RegisteredTerminalAttemptHistoryJoiner::for_final_success();
    expect_refused([&] {
        RegisteredTerminalAttemptHistoryJoiner::test_only_accept_storage(
            joiner, ledger(65, true), true);
    });
    expect_refused([&] { (void)std::move(joiner).finish_success(); });
}

void flattened_pidfd_only_status_without_exit_authority_refuses() {
    auto joiner = RegisteredTerminalAttemptHistoryJoiner::for_aborted_run();
    expect_refused([&] {
        RegisteredTerminalAttemptHistoryJoiner::test_only_accept_storage(
            joiner, ledger(3, false, true), false);
    });
    expect_refused([&] { (void)std::move(joiner).finish_aborted(); });
}

void mismatch_burns_joiner_and_replay_refuses() {
    auto selected = ledger(2, true);
    selected->trials.back()->producer_fixed_fds[1] = 29;
    auto joiner = RegisteredTerminalAttemptHistoryJoiner::for_final_success();
    expect_refused([&] {
        RegisteredTerminalAttemptHistoryJoiner::test_only_accept_storage(
            joiner, std::move(selected), true);
    });
    expect_refused([&] {
        RegisteredTerminalAttemptHistoryJoiner::test_only_accept_storage(
            joiner, ledger(2, true), true);
    });
    expect_refused([&] { (void)std::move(joiner).finish_success(); });
}

void cross_binding_and_identity_substitution_refuse() {
    {
        auto selected = ledger(1, true);
        selected->trials.back()->producer_binding->round_capture_plans[1] =
            digest("wrong-plan", 1);
        auto joiner =
            RegisteredTerminalAttemptHistoryJoiner::for_final_success();
        expect_refused([&] {
            RegisteredTerminalAttemptHistoryJoiner::test_only_accept_storage(
                joiner, std::move(selected), true);
        });
    }
    {
        auto selected = ledger(1, true);
        selected->trials.back()->capture_trial_id = uuid(0x777777);
        auto joiner =
            RegisteredTerminalAttemptHistoryJoiner::for_final_success();
        expect_refused([&] {
            RegisteredTerminalAttemptHistoryJoiner::test_only_accept_storage(
                joiner, std::move(selected), true);
        });
    }
    {
        auto selected = ledger(1, true);
        selected->ledger_identity = digest("forged-ledger", 1);
        auto joiner =
            RegisteredTerminalAttemptHistoryJoiner::for_final_success();
        expect_refused([&] {
            RegisteredTerminalAttemptHistoryJoiner::test_only_accept_storage(
                joiner, std::move(selected), true);
        });
    }
}

void fd_and_wait_substitution_refuse() {
    {
        auto selected = ledger(1, true);
        selected->trials.back()->rows[1].sealed_c03_inode =
            selected->trials.back()->rows[0].sealed_c03_inode;
        auto joiner =
            RegisteredTerminalAttemptHistoryJoiner::for_final_success();
        expect_refused([&] {
            RegisteredTerminalAttemptHistoryJoiner::test_only_accept_storage(
                joiner, std::move(selected), true);
        });
    }
    {
        auto selected = ledger(1, true);
        selected->trials.back()->rows[1].process_identity =
            selected->trials.back()->rows[0].process_identity;
        auto joiner =
            RegisteredTerminalAttemptHistoryJoiner::for_final_success();
        expect_refused([&] {
            RegisteredTerminalAttemptHistoryJoiner::test_only_accept_storage(
                joiner, std::move(selected), true);
        });
    }
    {
        auto selected = ledger(2, true);
        selected->trials[1]->producer_child_exit_identity =
            selected->trials[0]->producer_child_exit_identity;
        auto joiner =
            RegisteredTerminalAttemptHistoryJoiner::for_final_success();
        expect_refused([&] {
            RegisteredTerminalAttemptHistoryJoiner::test_only_accept_storage(
                joiner, std::move(selected), true);
        });
    }
    {
        auto selected = ledger(1, false, true);
        selected->trials.front()->producer_pidfd_exit_observed = false;
        auto joiner =
            RegisteredTerminalAttemptHistoryJoiner::for_aborted_run();
        expect_refused([&] {
            RegisteredTerminalAttemptHistoryJoiner::test_only_accept_storage(
                joiner, std::move(selected), false);
        });
    }
    {
        auto selected = ledger(1, true);
        selected->trials.back()->rows[0].c03_sha256 =
            digest("wrong-body", 1);
        auto joiner =
            RegisteredTerminalAttemptHistoryJoiner::for_final_success();
        expect_refused([&] {
            RegisteredTerminalAttemptHistoryJoiner::test_only_accept_storage(
                joiner, std::move(selected), true);
        });
    }
}

void wrong_terminal_mode_refuses() {
    auto joiner = RegisteredTerminalAttemptHistoryJoiner::for_aborted_run();
    expect_refused([&] {
        RegisteredTerminalAttemptHistoryJoiner::test_only_accept_storage(
            joiner, ledger(1, true), true);
    });
    expect_refused([&] { (void)std::move(joiner).finish_aborted(); });
}

} // namespace

int main() {
    synthetic_unbounded_success_without_exit_authority_refuses();
    flattened_pidfd_only_status_without_exit_authority_refuses();
    mismatch_burns_joiner_and_replay_refuses();
    cross_binding_and_identity_substitution_refuse();
    fd_and_wait_substitution_refuse();
    wrong_terminal_mode_refuses();
}
