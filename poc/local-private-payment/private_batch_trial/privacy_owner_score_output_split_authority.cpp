#include "privacy_owner_score_output_split_authority.hpp"

#include <utility>

namespace kpb::measurement::score_output_split {

OwnerScoreOutputLineageAuthority::OwnerScoreOutputLineageAuthority(
        RunBinding binding,
        std::array<runtime_bridge::OwnerScoreOutputBindingExpectation, 3>
            expected,
        Digest source_authority_identity)
    : binding_(std::move(binding)), expected_(std::move(expected)),
      source_authority_identity_(source_authority_identity) {}

OwnerScoreOutputLineageAuthority::OwnerScoreOutputLineageAuthority(
        OwnerScoreOutputLineageAuthority&& other) noexcept
    : binding_(other.binding_), expected_(other.expected_),
      source_authority_identity_(other.source_authority_identity_),
      live_(other.live_.exchange(false)) {}

#ifdef KPB_OWNER_SCORE_OUTPUT_SPLIT_TEST_SETUP
OwnerScoreOutputLineageAuthority
OwnerScoreOutputLineageAuthority::test_only_mint(
        RunBinding binding,
        std::array<runtime_bridge::OwnerScoreOutputBindingExpectation, 3>
            expected,
        Digest source_authority_identity) {
    return OwnerScoreOutputLineageAuthority(
        std::move(binding), std::move(expected), source_authority_identity);
}
#endif

OwnerScoreOutputSplitBundleAuthority::OwnerScoreOutputSplitBundleAuthority(
        OwnerScoreOutputLineageAuthority&& lineage,
        RunBinding binding, Digest barrier,
        std::array<PublicOwnerScoreCompletion, 3> completions,
        std::array<std::unique_ptr<runtime_bridge::SealedChildOutputAuthority>, 3>&&
            retained_outputs,
        std::array<std::unique_ptr<runtime_bridge::MeasurementInputEndpointAuthority>, 3>&&
            aggregate,
        std::array<std::unique_ptr<runtime_bridge::MeasurementInputEndpointAuthority>, 3>&&
            comparison,
        std::array<std::uint64_t, 3> output_devices,
        std::array<std::uint64_t, 3> output_inodes,
        std::array<std::uint64_t, 3> aggregate_devices,
        std::array<std::uint64_t, 3> aggregate_inodes,
        std::array<std::uint64_t, 3> comparison_devices,
        std::array<std::uint64_t, 3> comparison_inodes,
        std::array<bool, 3> aggregate_read_only,
        std::array<bool, 3> comparison_read_only) noexcept
    : lineage_(std::move(lineage)), binding_(std::move(binding)),
      barrier_(barrier),
      completions_(std::move(completions)),
      retained_outputs_(std::move(retained_outputs)),
      aggregate_(std::move(aggregate)), comparison_(std::move(comparison)),
      output_devices_(output_devices), output_inodes_(output_inodes),
      aggregate_devices_(aggregate_devices),
      aggregate_inodes_(aggregate_inodes),
      comparison_devices_(comparison_devices),
      comparison_inodes_(comparison_inodes),
      aggregate_read_only_(aggregate_read_only),
      comparison_read_only_(comparison_read_only) {}

OwnerScoreOutputSplitBundleAuthority::OwnerScoreOutputSplitBundleAuthority(
        OwnerScoreOutputSplitBundleAuthority&& other) noexcept
    : lineage_(std::move(other.lineage_)), binding_(other.binding_),
      barrier_(other.barrier_),
      completions_(other.completions_),
      retained_outputs_(std::move(other.retained_outputs_)),
      aggregate_(std::move(other.aggregate_)),
      comparison_(std::move(other.comparison_)),
      output_devices_(other.output_devices_),
      output_inodes_(other.output_inodes_),
      aggregate_devices_(other.aggregate_devices_),
      aggregate_inodes_(other.aggregate_inodes_),
      comparison_devices_(other.comparison_devices_),
      comparison_inodes_(other.comparison_inodes_),
      aggregate_read_only_(other.aggregate_read_only_),
      comparison_read_only_(other.comparison_read_only_),
      live_(other.live_.exchange(false)) {}

OwnerScoreOutputSplitBundleAuthority::~OwnerScoreOutputSplitBundleAuthority() =
    default;

#ifdef KPB_OWNER_SCORE_OUTPUT_SPLIT_TEST_SETUP
OwnerScoreOutputSplitBundleAuthority::TestOnlySummary
OwnerScoreOutputSplitBundleAuthority::test_only_summary() const {
    if (!live_.load()) throw Refused();
    TestOnlySummary result{
        .lineage_retained = lineage_.live_.load(),
        .binding = binding_,
        .barrier = barrier_,
        .completions = completions_,
        .output_devices = output_devices_,
        .output_inodes = output_inodes_,
        .aggregate_devices = aggregate_devices_,
        .aggregate_inodes = aggregate_inodes_,
        .comparison_devices = comparison_devices_,
        .comparison_inodes = comparison_inodes_,
        .aggregate_read_only = aggregate_read_only_,
        .comparison_read_only = comparison_read_only_,
    };
    for (unsigned owner = 0; owner < 3; ++owner) {
        result.retained_outputs[owner] =
            retained_outputs_[owner] != nullptr;
        if (aggregate_[owner] != nullptr)
            result.aggregate[owner] = aggregate_[owner]->public_receipt();
        if (comparison_[owner] != nullptr)
            result.comparison[owner] = comparison_[owner]->public_receipt();
    }
    return result;
}
#endif

OwnerScoreOutputSplitOutcomeAuthority::OwnerScoreOutputSplitOutcomeAuthority(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {}

OwnerScoreOutputSplitOutcomeAuthority::OwnerScoreOutputSplitOutcomeAuthority(
        OwnerScoreOutputSplitOutcomeAuthority&& other) noexcept
    : storage_(std::move(other.storage_)) {}

OwnerScoreOutputSplitOutcomeAuthority::~OwnerScoreOutputSplitOutcomeAuthority() =
    default;

#ifdef KPB_OWNER_SCORE_OUTPUT_SPLIT_TEST_SETUP
OwnerScoreOutputSplitOutcomeAuthority::TestOnlySummary
OwnerScoreOutputSplitOutcomeAuthority::test_only_summary() const {
    if (storage_ == nullptr) throw Refused();
    TestOnlySummary result{
        .success = storage_->bundle.has_value(),
        .stop_reason = storage_->stop_reason,
        .lineage_retained = storage_->lineage.has_value() &&
            storage_->lineage->live_.load(),
        .permit_claimed = storage_->permit_claimed,
        .completion_claimed = storage_->completion_claimed,
        .bundle = std::nullopt,
    };
    for (unsigned owner = 0; owner < result.retained_outputs.size(); ++owner)
        result.retained_outputs[owner] =
            storage_->retained_outputs[owner] != nullptr;
    if (storage_->bundle.has_value())
        result.bundle = storage_->bundle->test_only_summary();
    return result;
}
#endif

} // namespace kpb::measurement::score_output_split
