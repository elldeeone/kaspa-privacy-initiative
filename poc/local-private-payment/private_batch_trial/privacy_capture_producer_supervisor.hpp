#pragma once

// Private producer-to-observer spool and C03 launch capabilities. The
// selected producer supervisor and pinned Python runtime closure remain
// deliberately disabled until their authenticated exec path exists.

#include "privacy_measurement_observer_capture_bridge.hpp"
#include "privacy_measurement_worker_capsule.hpp"

#include <array>
#include <atomic>
#include <cstdint>

namespace kpb::measurement::producer_supervisor {

struct C03RoleLaunchRoundBinding {
    unsigned round{};
    unsigned fixed_fd{};
    Digest financial_run{};
    Digest attempt{};
    Digest cohort{};
    Digest capture_plan{};
    Digest projection{};
    Digest source_identity{};
    Digest build_identity{};
    Digest runtime_identity{};
    Digest launcher_identity{};
    Digest process_identity{};
    Digest child_exit_identity{};
    Digest model_preimage_identity{};
    Digest query_store_preimage_identity{};
    Digest scalar_capture_manifest_identity{};
    bool operator==(const C03RoleLaunchRoundBinding&) const = default;
};

// Owns the only descriptor for one completed producer spool. There is no
// public descriptor, path, body, digest, or serialization accessor. The exact
// observer supervisor consumes it directly and installs the capability in its
// private child capsule.
class ProducerSpoolAuthority final {
    struct PrivateLeafEvidence {
        unsigned round{};
        CaptureKind kind{};
        unsigned fixed_fd{};
        std::uint64_t device{};
        std::uint64_t inode{};
        std::uint64_t size{};
        std::uint32_t mode{};
        std::uint32_t uid{};
        std::uint32_t link_count{};
    };

    RunBinding binding_;
    Digest opaque_closure_authority_identity_{};
    Digest spool_identity_{};
    Digest producer_process_identity_{};
    Digest writer_alias_closure_identity_{};
    Digest path_alias_closure_identity_{};
    ProducerClosureEvidence producer_closure_evidence_{};
    std::array<PrivateLeafEvidence, 10> leaves_{};
    PrivateLeafEvidence producer_receipt_leaf_{};
    std::uint64_t device_{};
    std::uint64_t inode_{};
    int directory_fd_{-1};
    std::atomic_bool live_{true};

    ProducerSpoolAuthority(
        RunBinding, Digest opaque_closure_authority_identity,
        Digest spool_identity, Digest producer_process_identity,
        Digest writer_alias_closure_identity,
        Digest path_alias_closure_identity,
        ProducerClosureEvidence, int directory_fd);
    friend class runtime_bridge::ObserverCaptureCapsuleBridge;
public:
    ProducerSpoolAuthority(const ProducerSpoolAuthority&) = delete;
    ProducerSpoolAuthority& operator=(const ProducerSpoolAuthority&) = delete;
    ProducerSpoolAuthority(ProducerSpoolAuthority&&) noexcept;
    ProducerSpoolAuthority& operator=(ProducerSpoolAuthority&&) = delete;
    ~ProducerSpoolAuthority();

#ifdef KPB_CAPTURE_PRODUCER_SUPERVISOR_TEST_SETUP
    static ProducerSpoolAuthority test_only_mint(
        RunBinding, Digest opaque_closure_authority_identity,
        Digest spool_identity, Digest producer_process_identity,
        Digest writer_alias_closure_identity,
        Digest path_alias_closure_identity,
        ProducerClosureEvidence, int directory_fd);
    bool test_only_matches(
        const RunBinding&, const Digest& opaque_closure_authority_identity,
        const Digest& spool_identity,
        const Digest& producer_process_identity,
        const ProducerClosureEvidence&) const;
    int test_only_take_directory();
#endif
};

// One-shot admission for the two real P1 C03 role launches. A caller cannot
// substitute a JSON authority or infer admission from a public closure row.
// The observer bridge consumes this alongside ProducerSpoolAuthority and
// requires exact binding/producer/closure equality before parsing FD40.
class C03RoleLaunchAdmissionAuthority final {
    RunBinding binding_;
    Digest opaque_closure_authority_identity_{};
    Digest producer_process_identity_{};
    Digest producer_child_exit_identity_{};
    Digest producer_receipt_identity_{};
    std::array<C03RoleLaunchRoundBinding, 2> rounds_{};
    std::atomic_bool live_{true};

    C03RoleLaunchAdmissionAuthority(
        RunBinding, Digest opaque_closure_authority_identity,
        Digest producer_process_identity,
        Digest producer_child_exit_identity,
        Digest producer_receipt_identity,
        std::array<C03RoleLaunchRoundBinding, 2>);
    friend class runtime_bridge::ObserverCaptureCapsuleBridge;
public:
    C03RoleLaunchAdmissionAuthority(
        const C03RoleLaunchAdmissionAuthority&) = delete;
    C03RoleLaunchAdmissionAuthority& operator=(
        const C03RoleLaunchAdmissionAuthority&) = delete;
    C03RoleLaunchAdmissionAuthority(
        C03RoleLaunchAdmissionAuthority&&) noexcept;
    C03RoleLaunchAdmissionAuthority& operator=(
        C03RoleLaunchAdmissionAuthority&&) = delete;

#ifdef KPB_CAPTURE_PRODUCER_SUPERVISOR_TEST_SETUP
    static C03RoleLaunchAdmissionAuthority test_only_mint(
        RunBinding, Digest opaque_closure_authority_identity,
        Digest producer_process_identity,
        Digest producer_child_exit_identity,
        Digest producer_receipt_identity,
        std::array<C03RoleLaunchRoundBinding, 2>);
    bool test_only_matches(
        const RunBinding&, const Digest& opaque_closure_authority_identity,
        const Digest& producer_process_identity,
        const Digest& producer_child_exit_identity,
        const Digest& producer_receipt_identity,
        const std::array<C03RoleLaunchRoundBinding, 2>&) const;
    void test_only_consume();
#endif
};

struct ProducerSupervisorSourceStatus {
    bool move_only_spool_authority{};
    bool private_directory_capability{};
    bool observer_only_consumer{};
    bool writer_alias_closure_bound{};
    bool finite_ten_leaf_manifest_bound{};
    bool c03_role_launch_admission{};
    bool authenticated_exec_supervisor{};
    bool python_runtime_closure_sealed{};
    bool registered_ten_stream_adapter{};
    bool selected_main{};
    bool actual_launch_enabled{};
};

inline constexpr ProducerSupervisorSourceStatus
kProducerSupervisorSourceStatus{
    .move_only_spool_authority = true,
    .private_directory_capability = true,
    .observer_only_consumer = true,
    .writer_alias_closure_bound = true,
    .finite_ten_leaf_manifest_bound = true,
    .c03_role_launch_admission = true,
    .authenticated_exec_supervisor = false,
    .python_runtime_closure_sealed = false,
    .registered_ten_stream_adapter = false,
    .selected_main = false,
    .actual_launch_enabled = false,
};

} // namespace kpb::measurement::producer_supervisor
