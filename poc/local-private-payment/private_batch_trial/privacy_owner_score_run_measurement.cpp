#include "privacy_measurement_authority.hpp"
#include "privacy_owner_score_output_split_authority.hpp"

#include <algorithm>
#include <memory>
#include <new>
#include <utility>

namespace kpb::measurement {
namespace {

[[noreturn]] void refuse_score_retention() { throw Refused(); }
void need_score_retention(bool value) {
    if (!value) refuse_score_retention();
}

bool retained_observation_present(bool present) noexcept {
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    (void)present;
    return true;
#else
    return present;
#endif
}

struct RetainedOwnerScoreOutcome final {
    score_output_split::OwnerScoreOutputSplitOutcomeAuthority outcome;
    explicit RetainedOwnerScoreOutcome(
            score_output_split::OwnerScoreOutputSplitOutcomeAuthority&& value)
        noexcept : outcome(std::move(value)) {}
};

void destroy_retained_owner_score_outcome(void* storage) noexcept {
    delete static_cast<RetainedOwnerScoreOutcome*>(storage);
}

} // namespace

void RunMeasurement::accept_owner_score_split_impl(
        score_output_split::OwnerScoreOutputSplitOutcomeAuthority&& outcome,
        unsigned char selected_fault) {
    std::lock_guard guard(mutex_);
    try {
        need_score_retention(
            state_ == State::BarrierFrozen && observation_.has_value() &&
            retained_observation_present(observation_output_ != nullptr) &&
            std::all_of(score_issued_.begin(), score_issued_.end(),
                        [](bool issued) { return issued; }) &&
            owner_score_outcome_storage_ == nullptr &&
            outcome.storage_ != nullptr);
    } catch (...) {
        state_ = State::Poisoned;
        refuse_score_retention();
    }

#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    const auto fault = static_cast<TestOnlyOwnerScoreRetentionFault>(
        selected_fault);
    if (fault == TestOnlyOwnerScoreRetentionFault::BeforeClaimAllocation)
        throw std::bad_alloc();
#else
    (void)selected_fault;
#endif

    // Allocation happens before the noexcept move claim. If it fails, the
    // caller still owns the complete success/STOP outcome and this run remains
    // retryable.
    auto retained = std::make_unique<RetainedOwnerScoreOutcome>(
        std::move(outcome));
    try {
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
        if (fault == TestOnlyOwnerScoreRetentionFault::AfterClaim)
            refuse_score_retention();
#endif
        need_score_retention(retained->outcome.storage_ != nullptr);
        const auto& storage = *retained->outcome.storage_;
        need_score_retention(
            storage.bundle.has_value() ||
            storage.stop_reason !=
                score_output_split::OwnerScoreOutputSplitStopReason::None);
        if (storage.bundle.has_value()) {
            const auto& bundle = *storage.bundle;
            need_score_retention(bundle.binding_ == capture_.binding &&
                                 bundle.barrier_ == barrier_);
            for (unsigned owner = 0; owner < 3; ++owner)
                need_score_retention(
                    score_permits_[owner].has_value() &&
                    bundle.completions_[owner].owner == owner &&
                    bundle.completions_[owner].permit_identity ==
                        score_permits_[owner]->permit_identity &&
                    bundle.completions_[owner].barrier == barrier_);
        }
        owner_score_outcome_storage_ = retained.release();
        destroy_owner_score_outcome_storage_ =
            destroy_retained_owner_score_outcome;
        state_ = State::OwnerScoreOutcomeRetained;
    } catch (...) {
        // No allocation is needed to retain a post-claim failure. This remains
        // process-local retention, not the missing durable STOP/final sink.
        owner_score_outcome_storage_ = retained.release();
        destroy_owner_score_outcome_storage_ =
            destroy_retained_owner_score_outcome;
        state_ = State::Poisoned;
        refuse_score_retention();
    }
}

void RunMeasurement::accept_owner_score_split(
        score_output_split::OwnerScoreOutputSplitOutcomeAuthority&& outcome) {
    accept_owner_score_split_impl(std::move(outcome), 0);
}

#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
void RunMeasurement::test_only_accept_owner_score_split(
        score_output_split::OwnerScoreOutputSplitOutcomeAuthority&& outcome,
        TestOnlyOwnerScoreRetentionFault fault) {
    accept_owner_score_split_impl(
        std::move(outcome), static_cast<unsigned char>(fault));
}
#endif

} // namespace kpb::measurement
