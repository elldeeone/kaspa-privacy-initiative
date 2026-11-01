#pragma once

// Private storage shared only with the complete terminal bridge
// implementation. Possessing this layout does not mint an authority: both
// public ledger capability constructors remain private and move-only.

#include "registered_trial_attempt_history_storage.hpp"

#include <memory>
#include <mutex>
#include <vector>

namespace kpi::mpc::financial::registered_driver::attempt_history {

struct RegisteredFreshTrialHistoryLedgerStorage final {
    std::mutex mutex;
    std::vector<std::unique_ptr<RegisteredTrialAttemptHistoryStorage>> trials;
    Digest ledger_identity{};
    bool complete_seen{};
};

} // namespace kpi::mpc::financial::registered_driver::attempt_history
