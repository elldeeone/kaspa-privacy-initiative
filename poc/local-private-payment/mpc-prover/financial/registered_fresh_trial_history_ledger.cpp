#include "registered_fresh_trial_history_ledger.hpp"
#include "registered_fresh_trial_history_ledger_storage.hpp"
#include "registered_trial_attempt_history_storage.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <mutex>
#include <openssl/sha.h>
#include <span>
#include <utility>

namespace kpi::mpc::financial::registered_driver::attempt_history {
namespace {

[[noreturn]] void refuse() { throw AttemptHistoryRefused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}
void add(std::vector<unsigned char>& out,
         std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add(std::vector<unsigned char>& out, std::string_view value) {
    add(out, {reinterpret_cast<const unsigned char*>(value.data()),
              value.size()});
}
void le64(std::vector<unsigned char>& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}
void text(std::vector<unsigned char>& out, std::string_view value) {
    le64(out, value.size());
    add(out, value);
}
Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    need(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}

Digest append_identity(
        const Digest& prior, const RegisteredTrialAttemptHistoryStorage& trial,
        std::size_t index) {
    std::vector<unsigned char> preimage;
    add(preimage, "KPB_REGISTERED_FRESH_TRIAL_HISTORY_LEDGER_V1\n");
    add(preimage, prior);
    le64(preimage, index);
    preimage.push_back(trial.failed_trial ? 1 : 0);
    text(preimage, trial.capture_trial_id);
    add(preimage, trial.trial_identity);
    add(preimage, trial.history_identity);
    return hash(preimage);
}

void require_closure_equal(
        const RegisteredTrialAttemptHistoryStorage& first,
        const RegisteredTrialAttemptHistoryStorage& next) {
    need(first.classification == next.classification &&
         !first.rows.empty() && !next.rows.empty() &&
         first.rows.front().capture_source ==
             next.rows.front().capture_source &&
         first.rows.front().capture_build ==
             next.rows.front().capture_build &&
         first.rows.front().capture_runtime ==
             next.rows.front().capture_runtime &&
         first.rows.front().capture_launcher ==
             next.rows.front().capture_launcher);
}

} // namespace

RegisteredFreshTrialHistoryLedgerRecorder::
RegisteredFreshTrialHistoryLedgerRecorder(
        std::unique_ptr<RegisteredFreshTrialHistoryLedgerStorage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }

RegisteredFreshTrialHistoryLedgerRecorder::
RegisteredFreshTrialHistoryLedgerRecorder(
        RegisteredFreshTrialHistoryLedgerRecorder&& other) noexcept
    : storage_(std::move(other.storage_)),
      live_(other.live_.exchange(false)) {}

RegisteredFreshTrialHistoryLedgerRecorder::~
RegisteredFreshTrialHistoryLedgerRecorder() = default;

RegisteredFreshTrialHistoryLedgerAuthority::
RegisteredFreshTrialHistoryLedgerAuthority(
        std::unique_ptr<RegisteredFreshTrialHistoryLedgerStorage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }

RegisteredFreshTrialHistoryLedgerAuthority::
RegisteredFreshTrialHistoryLedgerAuthority(
        RegisteredFreshTrialHistoryLedgerAuthority&& other) noexcept
    : storage_(std::move(other.storage_)) {}

RegisteredFreshTrialHistoryLedgerAuthority::~
RegisteredFreshTrialHistoryLedgerAuthority() = default;

RegisteredAbortedFreshTrialHistoryLedgerAuthority::
RegisteredAbortedFreshTrialHistoryLedgerAuthority(
        std::unique_ptr<RegisteredFreshTrialHistoryLedgerStorage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }

RegisteredAbortedFreshTrialHistoryLedgerAuthority::
RegisteredAbortedFreshTrialHistoryLedgerAuthority(
        RegisteredAbortedFreshTrialHistoryLedgerAuthority&& other) noexcept
    : storage_(std::move(other.storage_)) {}

RegisteredAbortedFreshTrialHistoryLedgerAuthority::~
RegisteredAbortedFreshTrialHistoryLedgerAuthority() = default;

void RegisteredFreshTrialHistoryLedgerBridge::append(
        RegisteredFreshTrialHistoryLedgerRecorder& recorder,
        std::unique_ptr<RegisteredTrialAttemptHistoryStorage> trial,
        bool expected_failed) {
    try {
        need(recorder.live_.load() && recorder.storage_ != nullptr &&
             trial != nullptr);
        const std::lock_guard<std::mutex> lock(recorder.storage_->mutex);
        auto& ledger = *recorder.storage_;
        need(!ledger.complete_seen &&
             trial->failed_trial == expected_failed &&
             nonzero(trial->history_identity) && !trial->rows.empty() &&
             std::none_of(
                 ledger.trials.begin(), ledger.trials.end(),
                 [&](const auto& prior) {
                     return prior->capture_trial_id == trial->capture_trial_id ||
                         prior->trial_identity == trial->trial_identity ||
                         prior->history_identity == trial->history_identity;
                 }));
        if (!ledger.trials.empty()) {
            const auto& prior = *ledger.trials.back();
            require_closure_equal(*ledger.trials.front(), *trial);
            need(trial->rows.front().start_monotonic_ns >=
                 prior.rows.back().end_monotonic_ns);
        }
        ledger.ledger_identity = append_identity(
            ledger.ledger_identity, *trial, ledger.trials.size());
        need(nonzero(ledger.ledger_identity));
        ledger.complete_seen = !expected_failed;
        ledger.trials.push_back(std::move(trial));
    } catch (...) {
        recorder.live_.store(false);
        recorder.storage_.reset();
        refuse();
    }
}

void RegisteredFreshTrialHistoryLedgerBridge::append_failed(
        RegisteredFreshTrialHistoryLedgerRecorder& recorder,
        RegisteredFailedTrialAttemptHistoryAuthority&& supplied) {
    append(recorder, std::move(supplied.storage_), true);
}

void RegisteredFreshTrialHistoryLedgerBridge::append_complete(
        RegisteredFreshTrialHistoryLedgerRecorder& recorder,
        RegisteredTrialAttemptHistoryAuthority&& supplied) {
    append(recorder, std::move(supplied.storage_), false);
}

RegisteredFreshTrialHistoryLedgerAuthority
RegisteredFreshTrialHistoryLedgerBridge::seal(
        RegisteredFreshTrialHistoryLedgerRecorder&& supplied) {
    const bool live = supplied.live_.exchange(false);
    auto storage = std::move(supplied.storage_);
    need(live && storage != nullptr);
    const std::lock_guard<std::mutex> lock(storage->mutex);
    need(storage->complete_seen && !storage->trials.empty() &&
         !storage->trials.back()->failed_trial &&
         nonzero(storage->ledger_identity));
    return RegisteredFreshTrialHistoryLedgerAuthority(std::move(storage));
}

RegisteredAbortedFreshTrialHistoryLedgerAuthority
RegisteredFreshTrialHistoryLedgerBridge::seal_aborted(
        RegisteredFreshTrialHistoryLedgerRecorder&& supplied) {
    const bool live = supplied.live_.exchange(false);
    auto storage = std::move(supplied.storage_);
    need(live && storage != nullptr);
    const std::lock_guard<std::mutex> lock(storage->mutex);
    need(!storage->complete_seen && !storage->trials.empty() &&
         std::all_of(
             storage->trials.begin(), storage->trials.end(),
             [](const auto& trial) { return trial->failed_trial; }) &&
         nonzero(storage->ledger_identity));
    return RegisteredAbortedFreshTrialHistoryLedgerAuthority(
        std::move(storage));
}

#ifdef KPI_REGISTERED_ATTEMPT_HISTORY_TEST_SETUP
RegisteredFreshTrialHistoryLedgerRecorder
RegisteredFreshTrialHistoryLedgerTestBridge::begin() {
    return RegisteredFreshTrialHistoryLedgerRecorder(
        std::make_unique<RegisteredFreshTrialHistoryLedgerStorage>());
}

TestOnlyFreshTrialLedgerSummary
RegisteredFreshTrialHistoryLedgerTestBridge::consume(
        RegisteredFreshTrialHistoryLedgerAuthority&& supplied) {
    auto storage = std::move(supplied.storage_);
    need(storage != nullptr && storage->complete_seen);
    TestOnlyFreshTrialLedgerSummary result;
    result.ledger_identity = storage->ledger_identity;
    for (const auto& trial : storage->trials) {
        result.capture_trial_ids.push_back(trial->capture_trial_id);
        result.failed.push_back(trial->failed_trial);
    }
    return result;
}


TestOnlyFreshTrialLedgerSummary
RegisteredFreshTrialHistoryLedgerTestBridge::consume_aborted(
        RegisteredAbortedFreshTrialHistoryLedgerAuthority&& supplied) {
    auto storage = std::move(supplied.storage_);
    need(storage != nullptr && !storage->complete_seen &&
         !storage->trials.empty());
    TestOnlyFreshTrialLedgerSummary result;
    result.ledger_identity = storage->ledger_identity;
    for (const auto& trial : storage->trials) {
        need(trial->failed_trial);
        result.capture_trial_ids.push_back(trial->capture_trial_id);
        result.failed.push_back(true);
    }
    return result;
}
#endif

} // namespace kpi::mpc::financial::registered_driver::attempt_history
