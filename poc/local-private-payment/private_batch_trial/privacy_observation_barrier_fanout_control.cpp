#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreturn-type"
#define main kpb_phase_scope_prerequisite_control_main
#include "privacy_native_phase_scope_authority_control.cpp"
#undef main
#pragma GCC diagnostic pop

#include "privacy_observation_barrier_fanout_authority.hpp"

using namespace kpb::measurement::observation_fanout;

namespace {

OpenObservationFanoutAuthority make_fanout() {
    const auto selected = offer();
    const auto bytes = test_only_measurement_output_abi_body(
        RuntimeChildRole::Observer);
    auto sealed = produce(selected, bytes);
    auto empirical = empirical_fixture::exact(selected.binding);
    auto joined = NativePrivacyPhaseScopeBridge::validate_for_observation(
        std::move(sealed), std::move(empirical));
    return ObservationBarrierFanoutBridge::prepare(std::move(joined));
}

void exact_three_independent_fd41_endpoints_are_nonauthorizing() {
    auto fanout = make_fanout();
    const auto summary = fanout.test_only_summary();
    assert(summary.barrier != Digest{});
    assert(summary.device != 0 && summary.inode != 0 &&
           summary.exact_size == OBSERVER_OUTPUT_ABI.exact_bytes);
    for (unsigned owner = 0; owner < 3; ++owner) {
        const auto& endpoint = summary.endpoints[owner];
        assert(endpoint.kind == MeasurementInputKind::ScoreObservation);
        assert(endpoint.owner == NO_OWNER);
        assert(endpoint.fixed_fd == MEASUREMENT_SCORE_OBSERVATION_FD);
        assert(endpoint.identity != Digest{});
        assert(endpoint.lineage.classification ==
               Classification::HiddenCandidate);
        assert(endpoint.lineage.barrier == summary.barrier);
        assert(endpoint.lineage.trial == binding().trial);
        assert(endpoint.lineage.capture_plan_identities ==
               binding().round_capture_plans);
        assert(endpoint.lineage.financial_runs == binding().financial_runs);
        assert(endpoint.lineage.round_attempts == binding().round_attempts);
        assert(endpoint.lineage.round_cohorts == binding().round_cohorts);
        assert(endpoint.lineage.projections == binding().projections);
        assert(summary.endpoint_devices[owner] == summary.device);
        assert(summary.endpoint_inodes[owner] == summary.inode);
        assert(summary.endpoint_read_only[owner]);
    }
    assert(summary.endpoints[0].identity != summary.endpoints[1].identity &&
           summary.endpoints[0].identity != summary.endpoints[2].identity &&
           summary.endpoints[1].identity != summary.endpoints[2].identity);
}

void replay_and_same_body_dictionary_oracle_refuse() {
    auto first = make_fanout();
    const auto first_summary = first.test_only_summary();
    auto second = make_fanout();
    const auto second_summary = second.test_only_summary();
    assert(first_summary.barrier != second_summary.barrier);
    for (unsigned owner = 0; owner < 3; ++owner)
        assert(first_summary.endpoints[owner].identity !=
               second_summary.endpoints[owner].identity);

    const auto selected = offer();
    const auto bytes = test_only_measurement_output_abi_body(
        RuntimeChildRole::Observer);
    auto sealed = produce(selected, bytes);
    auto empirical = empirical_fixture::exact(selected.binding);
    auto joined = NativePrivacyPhaseScopeBridge::validate_for_observation(
        std::move(sealed), std::move(empirical));
    auto consumed = ObservationBarrierFanoutBridge::prepare(
        std::move(joined));
    (void)consumed;
    expect_refused([&] {
        (void)ObservationBarrierFanoutBridge::prepare(std::move(joined));
    });
}

} // namespace

int main() {
    static_assert(kObservationFanoutSourceStatus.sealed_join_consumed);
    static_assert(kObservationFanoutSourceStatus.salted_barrier_identity);
    static_assert(kObservationFanoutSourceStatus.independent_fd41_fanout);
    static_assert(kObservationFanoutSourceStatus.open_v3_nonauthorizing);
    static_assert(!kObservationFanoutSourceStatus.barrier_freeze_authority);
    static_assert(!kObservationFanoutSourceStatus.score_permit_authority);
    static_assert(!kObservationFanoutSourceStatus.selected_runtime_callsite);
    static_assert(!kObservationFanoutSourceStatus.configured);
    exact_three_independent_fd41_endpoints_are_nonauthorizing();
    replay_and_same_body_dictionary_oracle_refuse();
}
