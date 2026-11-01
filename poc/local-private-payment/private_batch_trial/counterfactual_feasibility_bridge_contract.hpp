#pragma once

// Future friendship boundary only.  The phase-scope owner must mint the
// observation source by splitting the live ObservationOutputJoinAuthority;
// the actual-acceptance owner must mint the post-barrier source only after the
// global candidate barrier and all three sealed owner-score outputs are joined.
// Neither source may be recreated from a receipt, digest, boolean, truth body,
// public candidate list, or BarrierFreezeAuthority.

namespace kpb::measurement::counterfactual_feasibility {

class ObservationFeasibilitySourceAuthority;
class PostBarrierFeasibilitySourceAuthority;
class ObservationCandidateResidualAuthority;
class PostBarrierTruthResidualAuthority;
class LiveCounterfactualSourceInstanceAuthority;
class FullW1WithCloseResidualAuthority;
class CounterfactualJointClosureAuthority;
class CounterfactualFeasibilityAuthority;
class CounterfactualFeasibilityTransfer;

class CounterfactualFeasibilityResidualBridge final {
    CounterfactualFeasibilityResidualBridge() = delete;
public:
    static ObservationCandidateResidualAuthority split_observation(
        ObservationFeasibilitySourceAuthority&&);
    static PostBarrierTruthResidualAuthority split_post_barrier(
        PostBarrierFeasibilitySourceAuthority&&);
};

// Future source owner only. `LiveCounterfactualSourceInstanceAuthority` is one
// indivisible, fresh-epoch capability atomically derived from the sole live W0
// truth + authenticated C1 + accepted-public-lineage join. It contains the
// complete W1 witness and the sole runtime-Close residual. Independent arms
// with merely equal caller bytes are not accepted. The relation check consumes
// the instance once and returns the verified Rust closure together with that
// same retained Close residual as one move-only authority. The present C++
// seam only accepts an opaque relation-evidence body; the future Rust adapter
// is responsible for minting it after the complete exact relation succeeds.
class CounterfactualFullW1WitnessBridge final {
    CounterfactualFullW1WitnessBridge() = delete;
public:
    static FullW1WithCloseResidualAuthority construct_and_verify(
        LiveCounterfactualSourceInstanceAuthority&&);
};

// Separate future runtime Close owner. It consumes the linear residual from
// the successful Rust relation step and an opaque Close-evidence body that a
// production owner may mint only after validating every exact projection,
// dispatcher, terminal and archive descendant. It returns a joint authority
// that still contains both evidence bodies. Close evidence may not be minted
// from a manifest, digest, receipt, caller Boolean or independently
// reconstructed identity. No production evidence minter exists yet.
class CounterfactualRuntimeCloseBridge final {
    CounterfactualRuntimeCloseBridge() = delete;
public:
    static CounterfactualJointClosureAuthority close_descendants(
        FullW1WithCloseResidualAuthority&&);
};

} // namespace kpb::measurement::counterfactual_feasibility

namespace kpb::measurement::acceptance_v4 {

// Complete dependency-neutral consumer contract. Its sole implementation is
// owned by the pinned counterfactual authority translation unit. A downstream
// ABI-v4 acceptance bridge calls this method and retains the returned opaque
// transfer; it is never friended directly and cannot redefine this class.
class CounterfactualFeasibilityAcceptanceBridge final {
    CounterfactualFeasibilityAcceptanceBridge() = delete;
public:
    static counterfactual_feasibility::CounterfactualFeasibilityTransfer take(
        counterfactual_feasibility::CounterfactualFeasibilityAuthority&&);
};

} // namespace kpb::measurement::acceptance_v4
