#pragma once

// One fresh registered trial owns exactly one ten-stream producer closure.
// Production binding consumes the dedicated child minted by genuine fresh
// issuance; it never consumes or returns the whole issuance authority. The
// selected runtime schema/callsite remains CONFIGURED0.

#include "privacy_capture_producer_runtime.hpp"
#include "privacy_registered_fresh_trial_producer_closure_contract.hpp"
#include "../mpc-prover/financial/fresh_owner_trial_issuance.hpp"

#include <memory>

namespace kpi::mpc::financial::registered_driver {

class RegisteredFreshTrialProducerClosureAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredFreshTrialProducerClosureAuthority(
        std::unique_ptr<Storage>);
    friend class RegisteredFreshTrialProducerClosureBridge;
public:
    RegisteredFreshTrialProducerClosureAuthority(
        const RegisteredFreshTrialProducerClosureAuthority&) = delete;
    RegisteredFreshTrialProducerClosureAuthority& operator=(
        const RegisteredFreshTrialProducerClosureAuthority&) = delete;
    RegisteredFreshTrialProducerClosureAuthority(
        RegisteredFreshTrialProducerClosureAuthority&&) noexcept;
    RegisteredFreshTrialProducerClosureAuthority& operator=(
        RegisteredFreshTrialProducerClosureAuthority&&) = delete;
    ~RegisteredFreshTrialProducerClosureAuthority();

#ifdef KPI_REGISTERED_FRESH_TRIAL_PRODUCER_CLOSURE_TEST_SETUP
    struct TestSummary {
        identity_registry::Digest closure_identity{};
        kpb::measurement::RunBinding binding;
        std::string capture_trial_id;
        std::array<std::string, 2> capture_attempt_ids;
        std::array<unsigned, 2> corrupt_server_source_slots{};
        std::array<unsigned, 2> corrupt_server_fixed_fds{};
        std::array<std::uint64_t, 10> devices{};
        std::array<std::uint64_t, 10> inodes{};
        std::array<std::uint32_t, 10> file_types{};
        identity_registry::Digest reservation_identity{};
        std::array<std::uint64_t, 10> archive_devices{};
        std::array<std::uint64_t, 10> archive_inodes{};
    };
    TestSummary test_only_summary() const;
#endif
};

struct RegisteredFreshTrialProducerClosureSourceStatus {
    bool dedicated_fresh_owner_closure_child_contract{};
    bool dedicated_fresh_owner_closure_child_consumed{};
    bool full_run_binding_bound{};
    bool raw_trial_and_attempt_ids_bound{};
    bool exact_ten_read_end_topology_bound{};
    bool corrupt_server_slots_3_8_bound{};
    bool corrupt_server_fds_23_28_bound{};
    bool linear_split_and_start{};
    bool preissuance_topology_reservation{};
    bool all_three_pidfds_bound_before_issuance{};
    bool registered_build_closure{};
    bool production_topology_factory{};
    bool prelaunch_authority_consumed{};
    bool same_ten_archive_runtime_start{};
    bool postrun_projection_exit_join{};
    bool reservation_identity_in_final_history{};
    bool selected_parent_callsite{};
    bool configured{};
    bool launch_enabled{};
};

inline constexpr RegisteredFreshTrialProducerClosureSourceStatus
    kRegisteredFreshTrialProducerClosureSourceStatus{
        .dedicated_fresh_owner_closure_child_contract = true,
        .dedicated_fresh_owner_closure_child_consumed = false,
        // The former full RunBinding shape includes post-run projections and
        // child-exit identities. It is intentionally not a production
        // prelaunch authority; only macro-gated controls exercise it.
        .full_run_binding_bound = false,
        .raw_trial_and_attempt_ids_bound = false,
        .exact_ten_read_end_topology_bound = false,
        .corrupt_server_slots_3_8_bound = false,
        .corrupt_server_fds_23_28_bound = false,
        .linear_split_and_start = false,
        .preissuance_topology_reservation = false,
        .all_three_pidfds_bound_before_issuance = false,
        .registered_build_closure = false,
        .production_topology_factory = false,
        .prelaunch_authority_consumed = false,
        .same_ten_archive_runtime_start = true,
        .postrun_projection_exit_join = false,
        .reservation_identity_in_final_history = false,
        .selected_parent_callsite = false,
        .configured = false,
        .launch_enabled = false,
    };

} // namespace kpi::mpc::financial::registered_driver
