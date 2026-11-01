#pragma once

// Opaque, move-only gate for one frozen counterfactual graph rewire.  This
// surface intentionally has no runtime minter, raw-data overload, receipt,
// digest, boolean result, value, key, owner mapping, or candidate accessor.

#include "counterfactual_feasibility_bridge_contract.hpp"
#include "privacy_measurement_authority.hpp"

#include <cstdint>
#include <memory>

namespace kpb::measurement::counterfactual_feasibility {

class CounterfactualPlanSelectionAuthority;
class CounterfactualPrecommitAuthority;
class ObservationCandidateResidualAuthority;
class PostBarrierTruthResidualAuthority;
class CounterfactualArithmeticShapeAuthority;
class LiveCounterfactualSourceInstanceAuthority;
class FullW1WithCloseResidualAuthority;
class CounterfactualJointClosureAuthority;
class CounterfactualFeasibilityAuthority;
class CounterfactualFeasibilityTransfer;

#ifdef KPB_COUNTERFACTUAL_FEASIBILITY_TEST_SETUP
enum class TestOnlyCounterfactualFault : std::uint8_t {
    None = 0,
    PlanAfterObservation,
    WrongWorkloadIdentity,
    WrongRehearsalIdentity,
    WrongRelationIdentity,
    WrongFullW1VerifierIdentity,
    WrongFullW1BridgeIdentity,
    WrongSourceTableIdentity,
    WrongMatrixIdentity,
    WrongMatrixEvidenceIdentity,
    WrongLeakageClosureIdentity,
    InputSwapDisabled,
    ChangeSwapDisabled,
    PaymentSwapEnabled,
    WrongLeakageClass,
    UnequalHonestInput,
    UnequalPayment,
    UnequalFee,
    BadEquation,
    BadValueRange,
    WrongRound2Selection,
    MissingW1Public,
    MissingW1Dispatcher,
    MissingW1CorruptServerWallet,
    MissingW1Union,
    MalformedCandidate,
    ObservationNotComplete,
    BarrierNotComplete,
    ScoresIncomplete,
    MalformedTruthMapping,
    WrongC1VisibleCreator,
    TruthValueMismatch,
    FullWitnessIncomplete,
    FullWitnessWrongW1,
    CloseWrongW1,
    JointWrongW1,
    CloseWrongInstance,
    CloseIncomplete,
};
#endif

class CounterfactualFeasibilityBridge final {
    CounterfactualFeasibilityBridge() = delete;
public:
    // Must be called by a future selected-parent owner before observation.
    static CounterfactualPrecommitAuthority precommit(
        CounterfactualPlanSelectionAuthority&&);

    // The two residuals are future linear splits from the live observation
    // join and the post-barrier/all-three-score join respectively.
    static CounterfactualArithmeticShapeAuthority verify_arithmetic_shape(
        CounterfactualPrecommitAuthority&&,
        ObservationCandidateResidualAuthority&&,
        PostBarrierTruthResidualAuthority&&);

    // Full feasibility additionally requires a source-owned capability proving
    // exact relation satisfaction and the complete descendant closure.
    static CounterfactualFeasibilityAuthority close_full_witness(
        CounterfactualArithmeticShapeAuthority&&,
        CounterfactualJointClosureAuthority&&);

#ifdef KPB_COUNTERFACTUAL_FEASIBILITY_TEST_SETUP
    // Control-only factories. They are absent from production and do not
    // establish a selected source, runtime callsite, or privacy result.
    static CounterfactualPlanSelectionAuthority test_only_plan(
        const RunBinding&, TestOnlyCounterfactualFault);
    static ObservationCandidateResidualAuthority test_only_observation(
        const RunBinding&, TestOnlyCounterfactualFault);
    static PostBarrierTruthResidualAuthority test_only_post_barrier(
        const RunBinding&, TestOnlyCounterfactualFault);
    static LiveCounterfactualSourceInstanceAuthority test_only_live_source(
        const RunBinding&, TestOnlyCounterfactualFault);
    static void test_only_consume(CounterfactualFeasibilityAuthority&&);
#endif
};

class CounterfactualPlanSelectionAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit CounterfactualPlanSelectionAuthority(std::unique_ptr<Storage>);
    friend class CounterfactualFeasibilityBridge;
public:
    CounterfactualPlanSelectionAuthority(
        const CounterfactualPlanSelectionAuthority&) = delete;
    CounterfactualPlanSelectionAuthority& operator=(
        const CounterfactualPlanSelectionAuthority&) = delete;
    CounterfactualPlanSelectionAuthority(
        CounterfactualPlanSelectionAuthority&&) noexcept;
    CounterfactualPlanSelectionAuthority& operator=(
        CounterfactualPlanSelectionAuthority&&) = delete;
    ~CounterfactualPlanSelectionAuthority();
};

class CounterfactualPrecommitAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit CounterfactualPrecommitAuthority(std::unique_ptr<Storage>);
    friend class CounterfactualFeasibilityBridge;
public:
    CounterfactualPrecommitAuthority(
        const CounterfactualPrecommitAuthority&) = delete;
    CounterfactualPrecommitAuthority& operator=(
        const CounterfactualPrecommitAuthority&) = delete;
    CounterfactualPrecommitAuthority(
        CounterfactualPrecommitAuthority&&) noexcept;
    CounterfactualPrecommitAuthority& operator=(
        CounterfactualPrecommitAuthority&&) = delete;
    ~CounterfactualPrecommitAuthority();
};

class ObservationCandidateResidualAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit ObservationCandidateResidualAuthority(std::unique_ptr<Storage>);
    friend class CounterfactualFeasibilityBridge;
    friend class CounterfactualFeasibilityResidualBridge;
public:
    ObservationCandidateResidualAuthority(
        const ObservationCandidateResidualAuthority&) = delete;
    ObservationCandidateResidualAuthority& operator=(
        const ObservationCandidateResidualAuthority&) = delete;
    ObservationCandidateResidualAuthority(
        ObservationCandidateResidualAuthority&&) noexcept;
    ObservationCandidateResidualAuthority& operator=(
        ObservationCandidateResidualAuthority&&) = delete;
    ~ObservationCandidateResidualAuthority();
};

class PostBarrierTruthResidualAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit PostBarrierTruthResidualAuthority(std::unique_ptr<Storage>);
    friend class CounterfactualFeasibilityBridge;
    friend class CounterfactualFeasibilityResidualBridge;
public:
    PostBarrierTruthResidualAuthority(
        const PostBarrierTruthResidualAuthority&) = delete;
    PostBarrierTruthResidualAuthority& operator=(
        const PostBarrierTruthResidualAuthority&) = delete;
    PostBarrierTruthResidualAuthority(
        PostBarrierTruthResidualAuthority&&) noexcept;
    PostBarrierTruthResidualAuthority& operator=(
        PostBarrierTruthResidualAuthority&&) = delete;
    ~PostBarrierTruthResidualAuthority();
};

class CounterfactualArithmeticShapeAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit CounterfactualArithmeticShapeAuthority(std::unique_ptr<Storage>);
    friend class CounterfactualFeasibilityBridge;
public:
    CounterfactualArithmeticShapeAuthority(
        const CounterfactualArithmeticShapeAuthority&) = delete;
    CounterfactualArithmeticShapeAuthority& operator=(
        const CounterfactualArithmeticShapeAuthority&) = delete;
    CounterfactualArithmeticShapeAuthority(
        CounterfactualArithmeticShapeAuthority&&) noexcept;
    CounterfactualArithmeticShapeAuthority& operator=(
        CounterfactualArithmeticShapeAuthority&&) = delete;
    ~CounterfactualArithmeticShapeAuthority();
};

class LiveCounterfactualSourceInstanceAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit LiveCounterfactualSourceInstanceAuthority(
        std::unique_ptr<Storage>);
    friend class CounterfactualFeasibilityBridge;
    friend class CounterfactualFullW1WitnessBridge;
public:
    LiveCounterfactualSourceInstanceAuthority(
        const LiveCounterfactualSourceInstanceAuthority&) = delete;
    LiveCounterfactualSourceInstanceAuthority& operator=(
        const LiveCounterfactualSourceInstanceAuthority&) = delete;
    LiveCounterfactualSourceInstanceAuthority(
        LiveCounterfactualSourceInstanceAuthority&&) noexcept;
    LiveCounterfactualSourceInstanceAuthority& operator=(
        LiveCounterfactualSourceInstanceAuthority&&) = delete;
    ~LiveCounterfactualSourceInstanceAuthority();
};

class FullW1WithCloseResidualAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit FullW1WithCloseResidualAuthority(std::unique_ptr<Storage>);
    friend class CounterfactualFullW1WitnessBridge;
    friend class CounterfactualRuntimeCloseBridge;
public:
    FullW1WithCloseResidualAuthority(
        const FullW1WithCloseResidualAuthority&) = delete;
    FullW1WithCloseResidualAuthority& operator=(
        const FullW1WithCloseResidualAuthority&) = delete;
    FullW1WithCloseResidualAuthority(
        FullW1WithCloseResidualAuthority&&) noexcept;
    FullW1WithCloseResidualAuthority& operator=(
        FullW1WithCloseResidualAuthority&&) = delete;
    ~FullW1WithCloseResidualAuthority();
};

class CounterfactualJointClosureAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit CounterfactualJointClosureAuthority(std::unique_ptr<Storage>);
    friend class CounterfactualRuntimeCloseBridge;
    friend class CounterfactualFeasibilityBridge;
public:
    CounterfactualJointClosureAuthority(
        const CounterfactualJointClosureAuthority&) = delete;
    CounterfactualJointClosureAuthority& operator=(
        const CounterfactualJointClosureAuthority&) = delete;
    CounterfactualJointClosureAuthority(
        CounterfactualJointClosureAuthority&&) noexcept;
    CounterfactualJointClosureAuthority& operator=(
        CounterfactualJointClosureAuthority&&) = delete;
    ~CounterfactualJointClosureAuthority();
};

class CounterfactualFeasibilityAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit CounterfactualFeasibilityAuthority(std::unique_ptr<Storage>);
    friend class CounterfactualFeasibilityBridge;
    CounterfactualFeasibilityTransfer transfer_for_acceptance() &&;
    friend class kpb::measurement::acceptance_v4::
        CounterfactualFeasibilityAcceptanceBridge;
public:
    CounterfactualFeasibilityAuthority(
        const CounterfactualFeasibilityAuthority&) = delete;
    CounterfactualFeasibilityAuthority& operator=(
        const CounterfactualFeasibilityAuthority&) = delete;
    CounterfactualFeasibilityAuthority(
        CounterfactualFeasibilityAuthority&&) noexcept;
    CounterfactualFeasibilityAuthority& operator=(
        CounterfactualFeasibilityAuthority&&) = delete;
    ~CounterfactualFeasibilityAuthority();
};

// Private ownership transfer only. It carries the already-joined shape, Rust
// FullW1 and runtime Close storage without exposing its RunBinding,
// SourceInstanceBinding, effects identities, graph, values, digest or Boolean.
// Only the native ABI-v4 acceptance bridge may consume it.
class CounterfactualFeasibilityTransfer final {
    void* storage_{};
    void (*destroy_)(void*) noexcept{};
    CounterfactualFeasibilityTransfer(
        void*, void (*)(void*) noexcept);
    friend class CounterfactualFeasibilityAuthority;
    friend class kpb::measurement::acceptance_v4::
        CounterfactualFeasibilityAcceptanceBridge;
public:
    CounterfactualFeasibilityTransfer(
        const CounterfactualFeasibilityTransfer&) = delete;
    CounterfactualFeasibilityTransfer& operator=(
        const CounterfactualFeasibilityTransfer&) = delete;
    CounterfactualFeasibilityTransfer(
        CounterfactualFeasibilityTransfer&&) noexcept;
    CounterfactualFeasibilityTransfer& operator=(
        CounterfactualFeasibilityTransfer&&) = delete;
    ~CounterfactualFeasibilityTransfer();
};

struct CounterfactualFeasibilitySourceStatus {
    bool exact_identity_workload_relation_matrix_precommit{};
    bool fixed_input_and_change_rewire{};
    bool two_round_arithmetic_shape_check{};
    bool four_view_different_pair_survival{};
    bool opaque_one_shot_output{};
    bool observation_join_friend{};
    bool post_barrier_score_join_friend{};
    bool pinned_rust_full_w1_typed_bridge{};
    bool rust_full_w1_closure_consumer{};
    bool full_w1_witness_constructor{};
    bool exact_full_relation_satisfaction_check{};
    bool complete_close_descendant_check{};
    bool production_plan_minter{};
    bool selected_runtime_callsite{};
    bool configured{};
};

inline constexpr CounterfactualFeasibilitySourceStatus
    kCounterfactualFeasibilityStatus{
        .exact_identity_workload_relation_matrix_precommit = true,
        .fixed_input_and_change_rewire = true,
        .two_round_arithmetic_shape_check = true,
        .four_view_different_pair_survival = true,
        .opaque_one_shot_output = true,
        .pinned_rust_full_w1_typed_bridge = true,
    };

} // namespace kpb::measurement::counterfactual_feasibility
