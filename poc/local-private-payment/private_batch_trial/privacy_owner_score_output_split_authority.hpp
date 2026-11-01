#pragma once

#include "privacy_owner_score_output_split_contract.hpp"
#include "privacy_owner_score_lineage_source_contract.hpp"
#include "privacy_measurement_child_output_authority.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>

namespace kpb::measurement::score_output_split {

// Opaque source binding for the exact compact header emitted by each of the
// three selected OwnerScore workers.  The production minter is deliberately
// absent until the selected raw trial/attempt and selection-plan bridge exists.
class OwnerScoreOutputLineageAuthority final {
    RunBinding binding_;
    std::array<runtime_bridge::OwnerScoreOutputBindingExpectation, 3>
        expected_{};
    Digest source_authority_identity_{};
    std::atomic_bool live_{true};
    OwnerScoreOutputLineageAuthority(
        RunBinding,
        std::array<runtime_bridge::OwnerScoreOutputBindingExpectation, 3>,
        Digest);
    friend class score_output_lineage_source::
        RegisteredOwnerScoreLineageSourceBridge;
    friend class OwnerScoreOutputSplitBridge;
    friend class OwnerScoreOutputSplitBundleAuthority;
    friend class OwnerScoreOutputSplitOutcomeAuthority;
public:
    OwnerScoreOutputLineageAuthority(
        const OwnerScoreOutputLineageAuthority&) = delete;
    OwnerScoreOutputLineageAuthority& operator=(
        const OwnerScoreOutputLineageAuthority&) = delete;
    OwnerScoreOutputLineageAuthority(
        OwnerScoreOutputLineageAuthority&&) noexcept;
    OwnerScoreOutputLineageAuthority& operator=(
        OwnerScoreOutputLineageAuthority&&) = delete;
#ifdef KPB_OWNER_SCORE_OUTPUT_SPLIT_TEST_SETUP
    static OwnerScoreOutputLineageAuthority test_only_mint(
        RunBinding,
        std::array<runtime_bridge::OwnerScoreOutputBindingExpectation, 3>,
        Digest);
#endif
};

// An indivisible three-owner bundle. Aggregate endpoints cannot be detached
// from their comparison residuals; future RunMeasurement integration must
// consume the whole object or safely lose liveness.
class OwnerScoreOutputSplitBundleAuthority final {
    OwnerScoreOutputLineageAuthority lineage_;
    RunBinding binding_;
    Digest barrier_{};
    std::array<PublicOwnerScoreCompletion, 3> completions_{};
    std::array<std::unique_ptr<runtime_bridge::SealedChildOutputAuthority>, 3>
        retained_outputs_{};
    std::array<std::unique_ptr<runtime_bridge::MeasurementInputEndpointAuthority>, 3>
        aggregate_{};
    std::array<std::unique_ptr<runtime_bridge::MeasurementInputEndpointAuthority>, 3>
        comparison_{};
    std::array<std::uint64_t, 3> output_devices_{};
    std::array<std::uint64_t, 3> output_inodes_{};
    std::array<std::uint64_t, 3> aggregate_devices_{};
    std::array<std::uint64_t, 3> aggregate_inodes_{};
    std::array<std::uint64_t, 3> comparison_devices_{};
    std::array<std::uint64_t, 3> comparison_inodes_{};
    std::array<bool, 3> aggregate_read_only_{};
    std::array<bool, 3> comparison_read_only_{};
    std::atomic_bool live_{true};
    OwnerScoreOutputSplitBundleAuthority(
        OwnerScoreOutputLineageAuthority&&, RunBinding, Digest,
        std::array<PublicOwnerScoreCompletion, 3>,
        std::array<std::unique_ptr<runtime_bridge::SealedChildOutputAuthority>, 3>&&,
        std::array<std::unique_ptr<runtime_bridge::MeasurementInputEndpointAuthority>, 3>&&,
        std::array<std::unique_ptr<runtime_bridge::MeasurementInputEndpointAuthority>, 3>&&,
        std::array<std::uint64_t, 3>, std::array<std::uint64_t, 3>,
        std::array<std::uint64_t, 3>, std::array<std::uint64_t, 3>,
        std::array<std::uint64_t, 3>, std::array<std::uint64_t, 3>,
        std::array<bool, 3>, std::array<bool, 3>) noexcept;
    friend class ::kpb::measurement::RunMeasurement;
    friend class OwnerScoreOutputSplitBridge;
public:
    OwnerScoreOutputSplitBundleAuthority(
        const OwnerScoreOutputSplitBundleAuthority&) = delete;
    OwnerScoreOutputSplitBundleAuthority& operator=(
        const OwnerScoreOutputSplitBundleAuthority&) = delete;
    OwnerScoreOutputSplitBundleAuthority(
        OwnerScoreOutputSplitBundleAuthority&&) noexcept;
    OwnerScoreOutputSplitBundleAuthority& operator=(
        OwnerScoreOutputSplitBundleAuthority&&) = delete;
    ~OwnerScoreOutputSplitBundleAuthority();
#ifdef KPB_OWNER_SCORE_OUTPUT_SPLIT_TEST_SETUP
    struct TestOnlySummary {
        bool lineage_retained{};
        RunBinding binding;
        Digest barrier{};
        std::array<PublicOwnerScoreCompletion, 3> completions{};
        std::array<bool, 3> retained_outputs{};
        std::array<runtime_bridge::PublicMeasurementInputEndpoint, 3>
            aggregate{};
        std::array<runtime_bridge::PublicMeasurementInputEndpoint, 3>
            comparison{};
        std::array<std::uint64_t, 3> output_devices{};
        std::array<std::uint64_t, 3> output_inodes{};
        std::array<std::uint64_t, 3> aggregate_devices{};
        std::array<std::uint64_t, 3> aggregate_inodes{};
        std::array<std::uint64_t, 3> comparison_devices{};
        std::array<std::uint64_t, 3> comparison_inodes{};
        std::array<bool, 3> aggregate_read_only{};
        std::array<bool, 3> comparison_read_only{};
    };
    TestOnlySummary test_only_summary() const;
#endif
};

enum class OwnerScoreOutputSplitStopReason : unsigned char {
    None,
    StaleOrMissingInput,
    Validation,
    BodyLineage,
    Entropy,
    Reopen,
    Allocation,
    Internal,
};

// Closed sum returned after the bridge begins claiming linear inputs.  A
// failed split retains the source lineage plus every sealed output that was
// actually present; callers cannot inspect or branch on the arm in production.
class OwnerScoreOutputSplitOutcomeAuthority final {
    struct Storage {
        std::optional<OwnerScoreOutputLineageAuthority> lineage;
        std::array<std::unique_ptr<runtime_bridge::SealedChildOutputAuthority>, 3>
            retained_outputs{};
        std::array<PublicOwnerScorePermit, 3> permits{};
        std::array<PublicOwnerScoreCompletion, 3> completions{};
        std::array<bool, 3> permit_claimed{};
        std::array<bool, 3> completion_claimed{};
        OwnerScoreOutputSplitStopReason stop_reason{
            OwnerScoreOutputSplitStopReason::Internal};
        std::optional<OwnerScoreOutputSplitBundleAuthority> bundle;
    };
    std::unique_ptr<Storage> storage_;
    explicit OwnerScoreOutputSplitOutcomeAuthority(
        std::unique_ptr<Storage>) noexcept;
    // RunMeasurement is complete through the source-owned runtime-type include
    // closure before this grant is parsed. It may only test moved-from storage
    // and retain the whole closed sum; it cannot detach either arm.
    friend class ::kpb::measurement::RunMeasurement;
    friend class OwnerScoreOutputSplitBridge;
public:
    OwnerScoreOutputSplitOutcomeAuthority(
        const OwnerScoreOutputSplitOutcomeAuthority&) = delete;
    OwnerScoreOutputSplitOutcomeAuthority& operator=(
        const OwnerScoreOutputSplitOutcomeAuthority&) = delete;
    OwnerScoreOutputSplitOutcomeAuthority(
        OwnerScoreOutputSplitOutcomeAuthority&&) noexcept;
    OwnerScoreOutputSplitOutcomeAuthority& operator=(
        OwnerScoreOutputSplitOutcomeAuthority&&) = delete;
    ~OwnerScoreOutputSplitOutcomeAuthority();
#ifdef KPB_OWNER_SCORE_OUTPUT_SPLIT_TEST_SETUP
    struct TestOnlySummary {
        bool success{};
        OwnerScoreOutputSplitStopReason stop_reason{
            OwnerScoreOutputSplitStopReason::Internal};
        bool lineage_retained{};
        std::array<bool, 3> retained_outputs{};
        std::array<bool, 3> permit_claimed{};
        std::array<bool, 3> completion_claimed{};
        std::optional<OwnerScoreOutputSplitBundleAuthority::TestOnlySummary>
            bundle;
    };
    TestOnlySummary test_only_summary() const;
#endif
};

struct OwnerScoreOutputSplitSourceStatus {
    bool all_three_atomic{};
    bool exact_body_revalidation{};
    bool independent_ro_reopen{};
    bool indivisible_aggregate_comparison_bundle{};
    bool typed_compact_lineage_required{};
    bool semantic_body_lineage_validation{};
    bool post_claim_closed_sum{};
    bool legacy_individual_accept_path_production_absent{};
    bool source_compact_lineage_minter{};
    bool mandatory_stop_sink_integrated{};
    bool run_measurement_integrated{};
    bool aggregate_completion_retains_comparison{};
    bool selected_runtime_callsite{};
    bool configured{};
};

inline constexpr OwnerScoreOutputSplitSourceStatus
kOwnerScoreOutputSplitSourceStatus{
    .all_three_atomic = true,
    .exact_body_revalidation = true,
    .independent_ro_reopen = true,
    .indivisible_aggregate_comparison_bundle = true,
    .typed_compact_lineage_required = true,
    .semantic_body_lineage_validation = true,
    .post_claim_closed_sum = true,
    .legacy_individual_accept_path_production_absent = true,
    .run_measurement_integrated = true,
};

} // namespace kpb::measurement::score_output_split
