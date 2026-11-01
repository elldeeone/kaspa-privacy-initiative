#pragma once

// Complete sealed declaration for the parent/child registered bootstrap.
// Keeping this class complete before any private friendship prevents another
// translation unit from defining a lookalike friend and minting capabilities.

#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

namespace kpi::mpc {
class SealedTraceArtifact;
struct OwnerInputContract;
namespace packed { class PackedModel; }
namespace financial {
namespace fresh_owner_issuance {
class ConsumedFreshOwnerRoundBootstrap;
struct PublicFreshOwnerRoundReceipt;
}
namespace registered_driver {

class CapturePlanAuthority;
class ChildRoleCompletionEndpointAuthority;
class CompiledDriverSelection;
class InheritedSealedQueryArtifact;
class ParentAuthenticatedPartyDeliveryAuthority;
class ParentRoleChildren;
class ParentBootstrapPlanAuthority;
class RegisteredChildBootstrapPending;
class RegisteredAdmittedRoleBootstrap;
class RosterBoundCapturePlan;

#ifdef KPI_REGISTERED_PARENT_BOOTSTRAP_TEST_SETUP
enum class ParentBootstrapTestFault : std::uint8_t {
    None = 0,
    SwapRoleZeroAndOneOffers = 1,
    WrongAdmissionAcknowledgement = 2,
};
#endif

class RegisteredParentBootstrapTransport final {
    RegisteredParentBootstrapTransport() = delete;
    static void deliver_impl(
        ParentBootstrapPlanAuthority&&, ParentRoleChildren&,
        std::uint8_t fault);
    static RegisteredAdmittedRoleBootstrap authorize_impl(
        RegisteredChildBootstrapPending&&,
        std::string_view model_identity,
        std::string_view query_store_identity,
        bool test_wrong_ack);
public:
    // Public query material only. This validates the actual kernel-sealed
    // artifact and retains its shared immutable pread backing; it does not
    // authorize a model, query store, driver, or launch.
    static InheritedSealedQueryArtifact admit_public_query_artifact(
        std::shared_ptr<const SealedTraceArtifact>);

    // Consumes the typed fresh-owner/history result and the one parent capture
    // plan. Driver configurations are immutable compiled selections, not
    // caller-supplied JSON or digests.
    static ParentBootstrapPlanAuthority prepare(
        fresh_owner_issuance::ConsumedFreshOwnerRoundBootstrap&&,
        RosterBoundCapturePlan&&,
        std::span<const CompiledDriverSelection>,
        const InheritedSealedQueryArtifact&,
        ParentRoleChildren&);

    // The child validates the kernel-authenticated role delivery and fixed
    // bootstrap packet against the exact inherited artifact before obtaining
    // a pending object. No driver capability is released at this stage.
    static RegisteredChildBootstrapPending receive(
        ChildRoleCompletionEndpointAuthority&,
        const ParentAuthenticatedPartyDeliveryAuthority&,
        const InheritedSealedQueryArtifact&);
    static std::shared_ptr<const SealedTraceArtifact> query_artifact(
        const RegisteredChildBootstrapPending&);

    // Only a fully admitted PackedModel can advance the child to usable
    // proposal/driver/capture capabilities. The model and gzip-query transport
    // identities must equal the compiled v9 plan.
    static RegisteredAdmittedRoleBootstrap authorize_admitted_model(
        RegisteredChildBootstrapPending&&, const packed::PackedModel&);

    // Sends exactly one role-bound offer to each retained child channel and
    // returns only after three model-admission acknowledgements.
    static void deliver(
        ParentBootstrapPlanAuthority&&, ParentRoleChildren&);

#ifdef KPI_REGISTERED_PARENT_BOOTSTRAP_TEST_SETUP
    struct TestModelBinding {
        const char* model_identity;
        const char* query_store_identity;
        bool wrong_ack{};
    };
    static RegisteredAdmittedRoleBootstrap test_only_authorize_admitted_model(
        RegisteredChildBootstrapPending&&, const TestModelBinding&);
    static void test_only_deliver(
        ParentBootstrapPlanAuthority&&, ParentRoleChildren&,
        ParentBootstrapTestFault);
    static ParentBootstrapPlanAuthority test_only_prepare(
        fresh_owner_issuance::PublicFreshOwnerRoundReceipt,
        std::span<const OwnerInputContract>, CapturePlanAuthority&&,
        std::span<const CompiledDriverSelection>,
        const InheritedSealedQueryArtifact&, ParentRoleChildren&);
#endif
};

} // namespace registered_driver
} // namespace financial
} // namespace kpi::mpc

