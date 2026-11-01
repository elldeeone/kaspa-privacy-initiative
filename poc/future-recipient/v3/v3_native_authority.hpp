#pragma once

// Network-off ADR-0092 authority layer.  This source implements the native
// descriptor and durable-state mechanics, but has no production minter or
// selected lifecycle callsite.  kV3NativeAuthoritySourceStatus.configured
// therefore remains false.

#include "privacy_measurement_authority.hpp"
#include "../../local-private-payment/mpc-prover/financial/fresh_owner_v3_lifecycle_contract.hpp"
#include "../../local-private-payment/private_batch_trial/honest_owner_material_v3_contract.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>

namespace kpb::future_recipient::v3_native {

using Digest = measurement::Digest;
using Invoice208 = std::array<unsigned char, 208>;

// Pure canonical identity used to bind the hidden owner plan to the exact
// measurement RunBinding. It creates no authority.
Digest recompute_v3_run_binding_identity(
    const measurement::RunBinding&);

inline constexpr int V3_OWNER_INVOICE_FIXED_FD = 33;
inline constexpr int V3_OWNER_RUN_BINDING_FIXED_FD = 34;
inline constexpr int V3_OWNER_ACCEPT_CAPABILITY_FIXED_FD = 35;

enum class LifecycleState : std::uint8_t {
    Allocated = 1,
    Exported = 2,
    Accepted = 3,
    Consumed = 4,
    Poisoned = 5,
};

enum class DurableBoundary : std::uint8_t {
    JournalWritten = 1,
    JournalSynced = 2,
    HeadWritten = 3,
    HeadSynced = 4,
    DirectorySynced = 5,
    ExternalHeadWritten = 6,
    ExternalHeadSynced = 7,
    ExternalDirectorySynced = 8,
};

using FailureOnlyHook = std::function<void(DurableBoundary)>;

class NativeRefused final : public std::runtime_error {
public:
    NativeRefused();
};

namespace detail {
struct ParentCore;
struct ExternalHeadCore;
}

class V3NativeAuthorityBridge;
class V3NativeAuthorityTestSetup;
class ParentV3Authority;

class InvoiceMaterialAuthority final {
    Invoice208 invoice_{};
    Digest binding_identity_{};
    Digest accepted_history_identity_{};
    Digest parent_instance_identity_{};
    Digest source_generation_identity_{};
    std::atomic_bool live_{true};
    InvoiceMaterialAuthority(Invoice208, Digest, Digest, Digest, Digest);
    friend class ParentV3Authority;
    friend class ::kpb::honest_owner_material::V3InvoiceMaterialMinter;
public:
    InvoiceMaterialAuthority(const InvoiceMaterialAuthority&) = delete;
    InvoiceMaterialAuthority& operator=(const InvoiceMaterialAuthority&) =
        delete;
    InvoiceMaterialAuthority(InvoiceMaterialAuthority&&) noexcept;
    InvoiceMaterialAuthority& operator=(InvoiceMaterialAuthority&&) = delete;
#ifdef KPB_V3_NATIVE_AUTHORITY_TEST_SETUP
    static InvoiceMaterialAuthority test_only_mint(
        ParentV3Authority&, Invoice208);
#endif
};

class LatestHeadAuthority final {
    Digest binding_identity_{};
    std::uint64_t sequence_{};
    Digest head_{};
    std::atomic_bool live_{true};
    LatestHeadAuthority(Digest, std::uint64_t, Digest);
    friend class V3NativeAuthorityBridge;
    friend class V3NativeAuthorityTestSetup;
    friend struct detail::ParentCore;
public:
    LatestHeadAuthority(const LatestHeadAuthority&) = delete;
    LatestHeadAuthority& operator=(const LatestHeadAuthority&) = delete;
    LatestHeadAuthority(LatestHeadAuthority&&) noexcept;
    LatestHeadAuthority& operator=(LatestHeadAuthority&&) = delete;
#ifdef KPB_V3_NATIVE_AUTHORITY_TEST_SETUP
    static LatestHeadAuthority test_only_mint(
        const measurement::RunBinding&, std::uint64_t, Digest);
#endif
};

class ParentLedgerDescriptorsAuthority final {
    int directory_fd_{-1};
    int journal_fd_{-1};
    int heads_fd_{-1};
    int mac_key_fd_{-1};
    std::atomic_bool live_{true};
    ParentLedgerDescriptorsAuthority(int, int, int, int);
    friend class V3NativeAuthorityBridge;
    friend class V3NativeAuthorityTestSetup;
public:
    ParentLedgerDescriptorsAuthority(
        const ParentLedgerDescriptorsAuthority&) = delete;
    ParentLedgerDescriptorsAuthority& operator=(
        const ParentLedgerDescriptorsAuthority&) = delete;
    ParentLedgerDescriptorsAuthority(
        ParentLedgerDescriptorsAuthority&&) noexcept;
    ParentLedgerDescriptorsAuthority& operator=(
        ParentLedgerDescriptorsAuthority&&) = delete;
    ~ParentLedgerDescriptorsAuthority();
};

// Independently persisted latest-head authority.  It owns the live external
// anchor descriptors and updates them only after the local journal, local
// head chain, and local directory have been synchronized.  No public latest
// sequence/head accessor exists.
class ExternalLatestHeadUpdaterAuthority final {
    std::unique_ptr<detail::ExternalHeadCore> core_;
    explicit ExternalLatestHeadUpdaterAuthority(
        std::unique_ptr<detail::ExternalHeadCore>);
    friend class V3NativeAuthorityBridge;
    friend class V3NativeAuthorityTestSetup;
    friend class V3LifecycleControllerAuthority;
    friend struct detail::ParentCore;
public:
    ExternalLatestHeadUpdaterAuthority(
        const ExternalLatestHeadUpdaterAuthority&) = delete;
    ExternalLatestHeadUpdaterAuthority& operator=(
        const ExternalLatestHeadUpdaterAuthority&) = delete;
    ExternalLatestHeadUpdaterAuthority(
        ExternalLatestHeadUpdaterAuthority&&) noexcept;
    ExternalLatestHeadUpdaterAuthority& operator=(
        ExternalLatestHeadUpdaterAuthority&&) = delete;
    ~ExternalLatestHeadUpdaterAuthority();
};

// Source-only conjunction of the full canonical RunBinding, the issuance-
// validated accepted-history residual, and the independent latest-head
// updater. It remains unmintable in production until the upstream accepted-
// history authority itself has a genuine production minter.
class V3LifecycleControllerAuthority final {
    Digest binding_identity_{};
    Digest accepted_history_identity_{};
    ExternalLatestHeadUpdaterAuthority updater_;
    std::atomic_bool live_{true};
    V3LifecycleControllerAuthority(
        Digest, Digest, ExternalLatestHeadUpdaterAuthority&&);
    friend class V3LifecycleControllerMinter;
    friend class V3NativeAuthorityBridge;
public:
    V3LifecycleControllerAuthority(
        const V3LifecycleControllerAuthority&) = delete;
    V3LifecycleControllerAuthority& operator=(
        const V3LifecycleControllerAuthority&) = delete;
    V3LifecycleControllerAuthority(
        V3LifecycleControllerAuthority&&) noexcept;
    V3LifecycleControllerAuthority& operator=(
        V3LifecycleControllerAuthority&&) = delete;
};

class AllocatedInvoiceAuthority final {
    ParentV3Authority* parent_{};
    Digest parent_instance_identity_{};
    Digest source_generation_identity_{};
    std::uint64_t index_{};
    Invoice208 invoice_{};
    std::atomic_bool live_{true};
    AllocatedInvoiceAuthority(
        ParentV3Authority*, Digest, Digest, std::uint64_t, Invoice208);
    friend class ParentV3Authority;
public:
    AllocatedInvoiceAuthority(const AllocatedInvoiceAuthority&) = delete;
    AllocatedInvoiceAuthority& operator=(const AllocatedInvoiceAuthority&) =
        delete;
    AllocatedInvoiceAuthority(AllocatedInvoiceAuthority&&) noexcept;
    AllocatedInvoiceAuthority& operator=(AllocatedInvoiceAuthority&&) = delete;
};

class OwnerOfferAuthority final {
    int invoice_fd_{-1};
    int binding_fd_{-1};
    int capability_fd_{-1};
    std::array<std::uint64_t, 6> identities_{};
    std::atomic_bool live_{true};
    OwnerOfferAuthority(int, int, int);
    friend class ParentV3Authority;
public:
    OwnerOfferAuthority(const OwnerOfferAuthority&) = delete;
    OwnerOfferAuthority& operator=(const OwnerOfferAuthority&) = delete;
    OwnerOfferAuthority(OwnerOfferAuthority&&) noexcept;
    OwnerOfferAuthority& operator=(OwnerOfferAuthority&&) = delete;
    ~OwnerOfferAuthority();

    void install_for_owner() &&;
};

class ParentOfferResidual final {
    ParentV3Authority* parent_{};
    Digest parent_instance_identity_{};
    Digest source_generation_identity_{};
    std::uint64_t index_{};
    Invoice208 invoice_{};
    int capability_fd_{-1};
    std::array<std::uint64_t, 2> capability_identity_{};
    Digest expected_ack_{};
    std::atomic_bool live_{true};
    ParentOfferResidual(
        ParentV3Authority*, Digest, Digest, std::uint64_t, Invoice208, int,
        Digest);
    friend class ParentV3Authority;
public:
    ParentOfferResidual(const ParentOfferResidual&) = delete;
    ParentOfferResidual& operator=(const ParentOfferResidual&) = delete;
    ParentOfferResidual(ParentOfferResidual&&) noexcept;
    ParentOfferResidual& operator=(ParentOfferResidual&&) = delete;
    ~ParentOfferResidual();
};

class OwnerRouteSplit final {
    std::optional<OwnerOfferAuthority> offer_;
    std::optional<ParentOfferResidual> residual_;
    OwnerRouteSplit(OwnerOfferAuthority&&, ParentOfferResidual&&);
    friend class ParentV3Authority;
public:
    OwnerRouteSplit(const OwnerRouteSplit&) = delete;
    OwnerRouteSplit& operator=(const OwnerRouteSplit&) = delete;
    OwnerRouteSplit(OwnerRouteSplit&&) noexcept = default;
    OwnerRouteSplit& operator=(OwnerRouteSplit&&) = delete;

    OwnerOfferAuthority take_owner_offer();
    ParentOfferResidual take_parent_residual();
};

class AcceptedInvoiceAuthority final {
    ParentV3Authority* parent_{};
    Digest parent_instance_identity_{};
    Digest source_generation_identity_{};
    std::uint64_t index_{};
    Invoice208 invoice_{};
    std::atomic_bool live_{true};
    AcceptedInvoiceAuthority(
        ParentV3Authority*, Digest, Digest, std::uint64_t, Invoice208);
    friend class ParentV3Authority;
    friend class ::kpb::honest_owner_material::V3InvoiceMaterialMinter;
public:
    AcceptedInvoiceAuthority(const AcceptedInvoiceAuthority&) = delete;
    AcceptedInvoiceAuthority& operator=(const AcceptedInvoiceAuthority&) =
        delete;
    AcceptedInvoiceAuthority(AcceptedInvoiceAuthority&&) noexcept;
    AcceptedInvoiceAuthority& operator=(AcceptedInvoiceAuthority&&) = delete;
};

class ParentV3Authority final {
    std::unique_ptr<detail::ParentCore> core_;
    Digest binding_identity_{};
    Digest accepted_history_identity_{};
    Digest instance_identity_{};
    explicit ParentV3Authority(
        std::unique_ptr<detail::ParentCore>, Digest);
    friend class InvoiceMaterialAuthority;
    friend class V3NativeAuthorityBridge;
    friend class V3NativeAuthorityTestSetup;
    friend class ::kpb::honest_owner_material::V3InvoiceMaterialMinter;
public:
    ParentV3Authority(const ParentV3Authority&) = delete;
    ParentV3Authority& operator=(const ParentV3Authority&) = delete;
    ParentV3Authority(ParentV3Authority&&) = delete;
    ParentV3Authority& operator=(ParentV3Authority&&) = delete;
    ~ParentV3Authority();

    AllocatedInvoiceAuthority allocate(
        InvoiceMaterialAuthority&&, FailureOnlyHook = {});
    OwnerRouteSplit export_to_owner(
        AllocatedInvoiceAuthority&&, FailureOnlyHook = {});
    AcceptedInvoiceAuthority accept_from_owner(
        ParentOfferResidual&&, FailureOnlyHook = {});
    void consume(AcceptedInvoiceAuthority&&, FailureOnlyHook = {});
    void poison(AllocatedInvoiceAuthority&&, FailureOnlyHook = {});
    void poison(ParentOfferResidual&&, FailureOnlyHook = {});
    void poison(AcceptedInvoiceAuthority&&, FailureOnlyHook = {});

#ifdef KPB_V3_NATIVE_AUTHORITY_TEST_SETUP
    std::pair<std::uint64_t, Digest> test_only_latest() const;
    LifecycleState test_only_state(std::uint64_t) const;
#endif
};

class V3NativeAuthorityBridge final {
    V3NativeAuthorityBridge() = delete;
    static std::unique_ptr<ParentV3Authority> open_legacy(
        ParentLedgerDescriptorsAuthority&&, LatestHeadAuthority&&,
        const measurement::RunBinding&);
    static std::unique_ptr<ParentV3Authority> open_external(
        ParentLedgerDescriptorsAuthority&&,
        ExternalLatestHeadUpdaterAuthority&&,
        const measurement::RunBinding&, Digest);
public:
    static std::unique_ptr<ParentV3Authority> open_existing(
        ParentLedgerDescriptorsAuthority&&,
        V3LifecycleControllerAuthority&&,
        const measurement::RunBinding&);
#ifdef KPB_V3_NATIVE_AUTHORITY_TEST_SETUP
    static std::unique_ptr<ParentV3Authority> test_only_open_existing(
        ParentLedgerDescriptorsAuthority&&, LatestHeadAuthority&&,
        const measurement::RunBinding&);
    static std::unique_ptr<ParentV3Authority> test_only_open_existing(
        ParentLedgerDescriptorsAuthority&&,
        ExternalLatestHeadUpdaterAuthority&&,
        const measurement::RunBinding&);
#endif
    [[noreturn]] static void refuse_recovery_without_latest_head(
        ParentLedgerDescriptorsAuthority&&,
        const measurement::RunBinding&);
};

class V3NativeAuthorityTestSetup final {
    V3NativeAuthorityTestSetup() = delete;
public:
#ifdef KPB_V3_NATIVE_AUTHORITY_TEST_SETUP
    static std::pair<ParentLedgerDescriptorsAuthority, LatestHeadAuthority>
    initialize_fresh(const char*, const measurement::RunBinding&, Digest);
    static ParentLedgerDescriptorsAuthority open_descriptors(
        const char*, Digest);
    static std::pair<ParentLedgerDescriptorsAuthority,
                     ExternalLatestHeadUpdaterAuthority>
    initialize_fresh_with_external_head(
        const char*, const char*, const measurement::RunBinding&, Digest);
    static ExternalLatestHeadUpdaterAuthority open_external_latest_head(
        const char*, const measurement::RunBinding&, Digest);
#endif
};

// Child-side operation. It accepts only the three fixed descriptors installed
// by OwnerOfferAuthority and emits one acknowledgement on the socket
// capability. No path, body, digest, or caller-authored invoice is accepted.
void owner_accept_from_fixed_fds();

struct V3NativeAuthoritySourceStatus {
    bool parent_owned_descriptors;
    bool sealed_invoice208_fd;
    bool exact_run_binding_fd;
    bool one_use_os_accept_capability;
    bool authenticated_append_only_edges;
    bool file_and_directory_fsync;
    bool exact_inode_mode_checks;
    bool missing_latest_head_refuses;
    bool external_latest_head_updater;
    bool external_head_file_and_directory_fsync;
    bool external_one_side_rollback_refusal;
    bool external_cross_trial_refusal;
    bool external_joint_rollback_protection_integrated;
    bool typed_lifecycle_controller_source_seam;
    bool production_open_requires_lifecycle_controller;
    bool invoice_material_bound_to_parent_history;
    bool per_open_instance_bound_lifecycle;
    bool opaque_source_generation_bound_through_accept;
    bool production_ledger_descriptor_minter_available;
    bool production_external_updater_minter_available;
    bool production_invoice_material_minter_available;
    bool production_accepted_history_minter_available;
    bool lifecycle_controller_minter_integrated;
    bool selected_owner_launcher_integrated;
    bool accepted_public_history_join_integrated;
    bool configured;
};

inline constexpr V3NativeAuthoritySourceStatus kV3NativeAuthoritySourceStatus{
    .parent_owned_descriptors = true,
    .sealed_invoice208_fd = true,
    .exact_run_binding_fd = true,
    .one_use_os_accept_capability = true,
    .authenticated_append_only_edges = true,
    .file_and_directory_fsync = true,
    .exact_inode_mode_checks = true,
    .missing_latest_head_refuses = true,
    .external_latest_head_updater = true,
    .external_head_file_and_directory_fsync = true,
    .external_one_side_rollback_refusal = true,
    .external_cross_trial_refusal = true,
    .external_joint_rollback_protection_integrated = false,
    .typed_lifecycle_controller_source_seam = true,
    .production_open_requires_lifecycle_controller = true,
    .invoice_material_bound_to_parent_history = true,
    .per_open_instance_bound_lifecycle = true,
    .opaque_source_generation_bound_through_accept = true,
    .production_ledger_descriptor_minter_available = false,
    .production_external_updater_minter_available = false,
    .production_invoice_material_minter_available = false,
    .production_accepted_history_minter_available = false,
    .lifecycle_controller_minter_integrated = false,
    .selected_owner_launcher_integrated = false,
    .accepted_public_history_join_integrated = false,
    .configured = false,
};

} // namespace kpb::future_recipient::v3_native
