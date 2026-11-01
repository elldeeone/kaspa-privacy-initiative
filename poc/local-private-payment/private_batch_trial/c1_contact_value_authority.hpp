#pragma once

// Two-phase authority for the owner-C1 contact/value capture source.
//
// The prelaunch half is derived only while a live parent-owned ten-stream
// producer authority exists. It carries one immutable kernel-sealed offer into
// the selected C1 supervisor on fixed FD 31. The other half never enters
// Python. It remains a move-only C++ residual for the post-END/EOF observer
// admission join with the live ProducerClosureAuthority.

#include "c1_contact_value_authority_bridge_contract.hpp"
#include "c1_registered_plan_route_bridge_contract.hpp"
#include "privacy_capture_producer_runtime.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <optional>
#include <string>

namespace kpb::measurement::runtime_bridge {
class ObserverCaptureCapsuleBridge;
}

namespace kpb::measurement::c1_capture {

inline constexpr int C1_CONTACT_VALUE_OFFER_FIXED_FD = 31;
inline constexpr std::size_t C1_CONTACT_VALUE_OFFER_BYTES = 646;

#ifdef KPB_C1_CONTACT_VALUE_AUTHORITY_TEST_SETUP
enum class TestC1OfferInstallFault : std::uint8_t {
    None = 0,
    AfterDup = 1,
    AfterInstalledFstat = 2,
    AfterClearCloexec = 3,
};
#endif

struct PublicC1LifecycleStagePlan {
    RunBinding binding;
    unsigned round{};
    std::string capture_attempt_id;
    std::string capture_identity;
    std::array<std::string, 3> operation_ids{};
    Digest expected_route_identity{};
    Digest expected_route_source_identity{};
    Digest stage_plan_identity{};
};

struct PublicC1InvoiceRoute {
    RunBinding binding;
    unsigned round{};
    // Explicit authenticated contacts in invoice, pay, scan order.
    std::array<unsigned, 3> contact_owner_components{};
    std::array<std::string, 3> operation_ids{};
    Digest route_identity{};
    Digest route_source_identity{};
};

class C1LifecycleStagePlanAuthority final {
    PublicC1LifecycleStagePlan value_;
    std::atomic_bool live_{true};
    explicit C1LifecycleStagePlanAuthority(PublicC1LifecycleStagePlan);
    friend class C1ContactValueAuthorityBridge;
    friend class RegisteredC1PlanRouteBridge;
public:
    C1LifecycleStagePlanAuthority(
        const C1LifecycleStagePlanAuthority&) = delete;
    C1LifecycleStagePlanAuthority& operator=(
        const C1LifecycleStagePlanAuthority&) = delete;
    C1LifecycleStagePlanAuthority(
        C1LifecycleStagePlanAuthority&&) noexcept;
    C1LifecycleStagePlanAuthority& operator=(
        C1LifecycleStagePlanAuthority&&) = delete;
#ifdef KPB_C1_CONTACT_VALUE_AUTHORITY_TEST_SETUP
    static C1LifecycleStagePlanAuthority test_only_mint(
        PublicC1LifecycleStagePlan);
#endif
};

class C1InvoiceRouteAuthority final {
    PublicC1InvoiceRoute value_;
    std::atomic_bool live_{true};
    explicit C1InvoiceRouteAuthority(PublicC1InvoiceRoute);
    friend class C1ContactValueAuthorityBridge;
    friend class RegisteredC1PlanRouteBridge;
public:
    C1InvoiceRouteAuthority(const C1InvoiceRouteAuthority&) = delete;
    C1InvoiceRouteAuthority& operator=(
        const C1InvoiceRouteAuthority&) = delete;
    C1InvoiceRouteAuthority(C1InvoiceRouteAuthority&&) noexcept;
    C1InvoiceRouteAuthority& operator=(C1InvoiceRouteAuthority&&) = delete;
#ifdef KPB_C1_CONTACT_VALUE_AUTHORITY_TEST_SETUP
    static C1InvoiceRouteAuthority test_only_mint(PublicC1InvoiceRoute);
#endif
};

class C1ContactValueOfferAuthority final {
    int fd_{-1};
    std::uint64_t device_{};
    std::uint64_t inode_{};
    std::atomic_bool live_{true};
#ifdef KPB_C1_CONTACT_VALUE_AUTHORITY_TEST_SETUP
    TestC1OfferInstallFault test_only_install_fault_{
        TestC1OfferInstallFault::None};
#endif

    explicit C1ContactValueOfferAuthority(int);
    friend class C1ContactValueAuthorityBridge;
    friend class RegisteredC1PlanRouteBridge;
public:
    C1ContactValueOfferAuthority(const C1ContactValueOfferAuthority&) = delete;
    C1ContactValueOfferAuthority& operator=(
        const C1ContactValueOfferAuthority&) = delete;
    C1ContactValueOfferAuthority(C1ContactValueOfferAuthority&&) noexcept;
    C1ContactValueOfferAuthority& operator=(
        C1ContactValueOfferAuthority&&) = delete;
    ~C1ContactValueOfferAuthority();

    // Child-side only: consumes the authority, installs the fully sealed
    // regular file on FD31 and makes exactly that descriptor survive exec.
    void install_for_child() &&;

#ifdef KPB_C1_CONTACT_VALUE_AUTHORITY_TEST_SETUP
    int test_only_take_fd();
    int test_only_source_fd() const;
    void test_only_set_install_fault(TestC1OfferInstallFault);
#endif
};

class C1PostcaptureAdmissionAuthority final {
    RunBinding binding_;
    unsigned round_{};
    unsigned fixed_capture_fd_{};
    Digest contact_value_authority_identity_{};
    Digest role_launch_identity_{};
    Digest route_manifest_identity_{};
    Digest route_source_identity_{};
    Digest stage_plan_identity_{};
    Digest process_identity_{};
    Digest expected_child_exit_identity_{};
    WorkerBinding c1_worker_;
    std::array<unsigned, 3> contact_owner_components_{};
    std::array<Digest, 3> operation_identities_{};
    std::atomic_bool live_{true};

    C1PostcaptureAdmissionAuthority(
        RunBinding, unsigned, unsigned, Digest, Digest, Digest, Digest,
        Digest, Digest, Digest, WorkerBinding, std::array<unsigned, 3>,
        std::array<Digest, 3>);
    friend class C1ContactValueAuthorityBridge;
    friend class RegisteredC1PlanRouteBridge;
    friend class ::kpb::measurement::runtime_bridge::
        ObserverCaptureCapsuleBridge;
public:
    C1PostcaptureAdmissionAuthority(
        const C1PostcaptureAdmissionAuthority&) = delete;
    C1PostcaptureAdmissionAuthority& operator=(
        const C1PostcaptureAdmissionAuthority&) = delete;
    C1PostcaptureAdmissionAuthority(
        C1PostcaptureAdmissionAuthority&&) noexcept;
    C1PostcaptureAdmissionAuthority& operator=(
        C1PostcaptureAdmissionAuthority&&) = delete;
    ~C1PostcaptureAdmissionAuthority() = default;

#ifdef KPB_C1_CONTACT_VALUE_AUTHORITY_TEST_SETUP
    static C1PostcaptureAdmissionAuthority test_only_mint(
        RunBinding, unsigned, unsigned, Digest, Digest, Digest, Digest,
        Digest, Digest, Digest, WorkerBinding, std::array<unsigned, 3>,
        std::array<Digest, 3>);
    bool test_only_matches(
        const RunBinding&, unsigned, const Digest&, const Digest&,
        const std::array<Digest, 3>&) const;
#endif
};

class C1ContactValueAuthoritySplit final {
    std::optional<C1ContactValueOfferAuthority> offer_;
    std::optional<C1PostcaptureAdmissionAuthority> residual_;
    C1ContactValueAuthoritySplit(
        C1ContactValueOfferAuthority&&,
        C1PostcaptureAdmissionAuthority&&);
    friend class C1ContactValueAuthorityBridge;
public:
    C1ContactValueAuthoritySplit(const C1ContactValueAuthoritySplit&) = delete;
    C1ContactValueAuthoritySplit& operator=(
        const C1ContactValueAuthoritySplit&) = delete;
    C1ContactValueAuthoritySplit(C1ContactValueAuthoritySplit&&) noexcept =
        default;
    C1ContactValueAuthoritySplit& operator=(
        C1ContactValueAuthoritySplit&&) = delete;

    C1ContactValueOfferAuthority take_offer();
    C1PostcaptureAdmissionAuthority take_postcapture_residual();
};

struct C1ContactValueAuthoritySourceStatus {
    bool live_parent_producer_authority_required{};
    bool immutable_sealed_fixed_fd_offer{};
    bool caller_contact_fields_forbidden{};
    bool move_only_postcapture_residual{};
    bool controller_stage_plan_authority_integrated{};
    bool authenticated_invoice_route_authority_integrated{};
    bool selected_launcher_consumes_offer{};
    bool observer_admission_join_implemented{};
    bool actual_launch_enabled{};
};

inline constexpr C1ContactValueAuthoritySourceStatus
kC1ContactValueAuthoritySourceStatus{
    .live_parent_producer_authority_required = true,
    .immutable_sealed_fixed_fd_offer = true,
    .caller_contact_fields_forbidden = true,
    .move_only_postcapture_residual = true,
    .controller_stage_plan_authority_integrated = false,
    .authenticated_invoice_route_authority_integrated = false,
    .selected_launcher_consumes_offer = false,
    // ObserverCaptureCapsuleBridge::admit now consumes both C1 residuals and
    // the sealed ten-stream archive.  No selected callsite exists yet.
    .observer_admission_join_implemented = true,
    .actual_launch_enabled = false,
};

} // namespace kpb::measurement::c1_capture
