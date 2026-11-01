#pragma once

// Private fixed-size output capability for isolated measurement children.
// The only production constructor is the authenticated child supervisor. A
// selected parent/worker callsite is still absent, so this remains CONFIGURED0.

#include "privacy_measurement_output_abi.hpp"
#include "privacy_native_phase_scope_bridge_contract.hpp"
#include "privacy_observation_barrier_fanout_contract.hpp"
#include "privacy_owner_score_output_split_contract.hpp"
#include "privacy_measurement_worker_capsule.hpp"

#include <atomic>
#include <cstdint>
#include <memory>

namespace kpb::measurement::runtime_bridge {

struct PrivateChildOutputOffer {
    RunBinding binding;
    RuntimeChildRole role{};
    unsigned owner{NO_OWNER};
    Digest permit_identity{};
    WorkerBinding worker{};
    Digest transport_session{};
    Digest output_authority_identity{};
    Digest output_abi_identity{};
    std::uint64_t exact_size{};
    bool operator==(const PrivateChildOutputOffer&) const = default;
};

struct PrivateChildOutputCompletion {
    PrivateChildOutputOffer offer;
    Digest content_hash{};
    Digest process_identity{};
    Digest child_exit_identity{};
    std::uint64_t authenticated_pid{};
    std::uint64_t waited_pid{};
    int exit_code{-1};
    int term_signal{-1};
    bool credentials_verified{};
    bool eof_observed{};
    bool operator==(const PrivateChildOutputCompletion&) const = default;
};

class MeasurementChildOutputPlane;

class PendingChildOutputAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit PendingChildOutputAuthority(std::unique_ptr<Storage>);
    friend class MeasurementChildOutputPlane;
    friend class MeasurementChildSupervisor;
    int take_child_fd();
public:
    PendingChildOutputAuthority(const PendingChildOutputAuthority&) = delete;
    PendingChildOutputAuthority& operator=(
        const PendingChildOutputAuthority&) = delete;
    PendingChildOutputAuthority(PendingChildOutputAuthority&&) noexcept;
    PendingChildOutputAuthority& operator=(
        PendingChildOutputAuthority&&) = delete;
    ~PendingChildOutputAuthority();
#ifdef KPB_MEASUREMENT_CHILD_OUTPUT_TEST_SETUP
    int test_only_take_child_fd();
#endif
};

class AuthenticatedChildOutputCompletionAuthority final {
    PrivateChildOutputCompletion completion_;
    std::atomic_bool live_{true};
    explicit AuthenticatedChildOutputCompletionAuthority(
        PrivateChildOutputCompletion);
    friend class MeasurementChildOutputPlane;
    friend class MeasurementChildSupervisor;
public:
    AuthenticatedChildOutputCompletionAuthority(
        const AuthenticatedChildOutputCompletionAuthority&) = delete;
    AuthenticatedChildOutputCompletionAuthority& operator=(
        const AuthenticatedChildOutputCompletionAuthority&) = delete;
    AuthenticatedChildOutputCompletionAuthority(
        AuthenticatedChildOutputCompletionAuthority&&) noexcept;
    AuthenticatedChildOutputCompletionAuthority& operator=(
        AuthenticatedChildOutputCompletionAuthority&&) = delete;
#ifdef KPB_MEASUREMENT_CHILD_OUTPUT_TEST_SETUP
    static AuthenticatedChildOutputCompletionAuthority test_only_mint(
        PrivateChildOutputCompletion);
#endif
};

class SealedChildOutputAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit SealedChildOutputAuthority(std::unique_ptr<Storage>);
    int owner_score_split_read_fd() const;
    friend class MeasurementChildOutputPlane;
    friend class RuntimeCompletionBridge;
    friend class kpb::measurement::phase_scope::
        NativePrivacyPhaseScopeBridge;
    friend class kpb::measurement::observation_fanout::
        ObservationBarrierFanoutBridge;
    friend class kpb::measurement::score_output_split::
        OwnerScoreOutputSplitBridge;
    const PrivateChildOutputCompletion& retained_completion() const;
    const Digest& retained_identity() const;
    int native_phase_scope_read_fd() const;
public:
    SealedChildOutputAuthority(const SealedChildOutputAuthority&) = delete;
    SealedChildOutputAuthority& operator=(
        const SealedChildOutputAuthority&) = delete;
    SealedChildOutputAuthority(SealedChildOutputAuthority&&) noexcept;
    SealedChildOutputAuthority& operator=(
        SealedChildOutputAuthority&&) = delete;
    ~SealedChildOutputAuthority();
#ifdef KPB_MEASUREMENT_CHILD_OUTPUT_TEST_SETUP
    int test_only_duplicate_read_fd() const;
    bool test_only_matches(
        const PrivateChildOutputCompletion&, const Digest&) const;
#endif
};

class MeasurementChildOutputPlane final {
    MeasurementChildOutputPlane() = delete;
    static PendingChildOutputAuthority begin(PrivateChildOutputOffer);
    friend class MeasurementChildSupervisor;
public:
    static SealedChildOutputAuthority finish(
        PendingChildOutputAuthority&&,
        AuthenticatedChildOutputCompletionAuthority&&);
#ifdef KPB_MEASUREMENT_CHILD_OUTPUT_TEST_SETUP
    static PendingChildOutputAuthority test_only_begin(
        PrivateChildOutputOffer);
#endif
};

struct ChildOutputSourceStatus {
    bool fixed_size_empty_parent_memfd{};
    bool exact_private_completion{};
    bool parent_recomputed_hash{};
    bool sealed_read_only_authority{};
    bool selected_supervisor_factory{};
    bool selected_worker_output_abi{};
    bool observer_fanout{};
    bool owner_score_fanout{};
    bool barrier_output_join{};
    bool configured{};
};

inline constexpr ChildOutputSourceStatus kChildOutputSourceStatus{
    .fixed_size_empty_parent_memfd = true,
    .exact_private_completion = true,
    .parent_recomputed_hash = true,
    .sealed_read_only_authority = true,
};

} // namespace kpb::measurement::runtime_bridge
