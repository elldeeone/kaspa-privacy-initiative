#pragma once

// One terminal child-to-parent packet for a registered financial party.  The
// packet always carries the genuine party durable-EGRESS authority.  The
// explicit-owner-effects baseline additionally carries its private scorer
// authority; hidden candidates are required to use an all-zero baseline
// section.  No descriptor, packet, JSON, digest, or Boolean factory is public.

#include "registered_identity_registry.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>

namespace kpi::mpc::financial::registered_driver {

struct PublicPartyDriverCompletion;
class PartyDriverCompletionAuthority;
class ChildRoleCompletionEndpointAuthority;
class ParentRoleCompletionEndpointAuthority;

namespace baseline_disclosure {
class PartyBaselineOwnerEffectsAuthority;
}

struct PublicParentObservedPartyCompletion {
    unsigned role{};
    unsigned round{};
    std::int64_t parent_pid{};
    std::int64_t child_pid{};
    identity_registry::Digest fork_plan_identity{};
    identity_registry::Digest offer_identity{};
    identity_registry::Digest acknowledgement_identity{};
    identity_registry::Digest fresh_owner_issuance_identity{};
    identity_registry::Digest party_completion_identity{};
    identity_registry::Digest observation_identity{};
};

// Parent-only proof that a kernel-authenticated child submitted one genuine
// role completion on the retained fork channel.  Public metadata cannot
// reconstruct or replay this capability.
class ParentObservedPartyCompletionAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit ParentObservedPartyCompletionAuthority(
        std::unique_ptr<Storage>);
    friend class RegisteredPartyCompletionTransport;
public:
    ParentObservedPartyCompletionAuthority(
        const ParentObservedPartyCompletionAuthority&) = delete;
    ParentObservedPartyCompletionAuthority& operator=(
        const ParentObservedPartyCompletionAuthority&) = delete;
    ParentObservedPartyCompletionAuthority(
        ParentObservedPartyCompletionAuthority&&) noexcept;
    ParentObservedPartyCompletionAuthority& operator=(
        ParentObservedPartyCompletionAuthority&&) = delete;
    ~ParentObservedPartyCompletionAuthority();

    const PublicParentObservedPartyCompletion& public_observation() const;
    const PublicPartyDriverCompletion& public_party_completion() const;
};

// Opaque tagged-union result.  Baseline effects remain private and can only be
// moved into the parent scorer; the hidden-candidate result has no such value.
class ParentObservedRegisteredPartyResult final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit ParentObservedRegisteredPartyResult(std::unique_ptr<Storage>);
    friend class RegisteredPartyCompletionTransport;
public:
    ParentObservedRegisteredPartyResult(
        const ParentObservedRegisteredPartyResult&) = delete;
    ParentObservedRegisteredPartyResult& operator=(
        const ParentObservedRegisteredPartyResult&) = delete;
    ParentObservedRegisteredPartyResult(
        ParentObservedRegisteredPartyResult&&) noexcept;
    ParentObservedRegisteredPartyResult& operator=(
        ParentObservedRegisteredPartyResult&&) = delete;
    ~ParentObservedRegisteredPartyResult();

    bool has_baseline_effects() const;
    ParentObservedPartyCompletionAuthority take_party_completion();
    baseline_disclosure::PartyBaselineOwnerEffectsAuthority
    take_baseline_effects();
};

class RegisteredPartyCompletionTransport final {
    RegisteredPartyCompletionTransport() = delete;
public:
    static constexpr std::size_t BASELINE_SECTION_BYTES = 1524;
    static constexpr std::size_t PACKET_BYTES = 2584;

    static void submit_hidden(
        PartyDriverCompletionAuthority&&,
        ChildRoleCompletionEndpointAuthority&&);
    static void submit_baseline(
        PartyDriverCompletionAuthority&&,
        baseline_disclosure::PartyBaselineOwnerEffectsAuthority&&,
        ChildRoleCompletionEndpointAuthority&&);
    static ParentObservedRegisteredPartyResult receive(
        ParentRoleCompletionEndpointAuthority&&);
#ifdef KPI_REGISTERED_PARTY_COMPLETION_TRANSPORT_TEST_SETUP
    static void test_only_submit_hidden_invalid_baseline_tag(
        PartyDriverCompletionAuthority&&,
        ChildRoleCompletionEndpointAuthority&&);
    static void test_only_submit_hidden_duplicate_terminal(
        PartyDriverCompletionAuthority&&,
        ChildRoleCompletionEndpointAuthority&&);
#endif
};

#ifdef KPI_REGISTERED_PARTY_COMPLETION_TRANSPORT_TEST_SETUP
class RegisteredPartyCompletionTransportTestBridge final {
public:
    static PartyDriverCompletionAuthority mint_party(
        PublicPartyDriverCompletion);
};
#endif

} // namespace kpi::mpc::financial::registered_driver
