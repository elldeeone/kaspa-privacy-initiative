#include "privacy_registered_fresh_trial_capture_topology_reservation.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <concepts>
#include <set>
#include <string_view>

using namespace kpi::mpc::financial::registered_driver;

namespace {

template<class Function>
void refuses(Function&& function) {
    bool did_refuse = false;
    try { function(); }
    catch (const std::exception&) { did_refuse = true; }
    assert(did_refuse);
}

void exact_preidentity_reservation() {
    static_assert(!std::copy_constructible<
        FreshTrialCaptureTopologyReservation>);
    static_assert(!std::default_initializable<
        FreshTrialCaptureTopologyReservation>);
    auto reservation =
        FreshTrialCaptureTopologyReservationBridge::
            test_only_reserve_unbound();
    const auto summary = reservation.test_only_summary();
    assert(summary.contracts == kFreshTrialCaptureWriterContracts);
    assert(std::ranges::all_of(
        summary.read_ends_valid, [](bool value) { return value; }));
    assert(std::ranges::all_of(
        summary.writer_aliases_valid, [](bool value) { return value; }));
    assert(std::ranges::all_of(
        summary.archives_valid, [](bool value) { return value; }));
    assert(summary.p1_state_contracts ==
           kFreshTrialP1StateArchiveContracts);
    assert(std::ranges::all_of(
        summary.p1_state_parent_reads_valid,
        [](bool value) { return value; }));
    assert(std::ranges::all_of(
        summary.p1_state_writer_aliases_valid,
        [](bool value) { return value; }));
    assert(summary.reservation_identity != kpb::measurement::Digest{});
    std::set<std::pair<std::uint64_t, std::uint64_t>> endpoints;
    std::set<std::pair<std::uint64_t, std::uint64_t>> archives;
    for (unsigned slot = 0; slot < 10; ++slot) {
        assert(endpoints.emplace(
            summary.endpoint_devices[slot],
            summary.endpoint_inodes[slot]).second);
        assert(archives.emplace(
            summary.archive_devices[slot],
            summary.archive_inodes[slot]).second);
        assert(summary.contracts[slot].source_slot == slot);
        assert(summary.contracts[slot].round == slot / 5 + 1);
        assert(summary.contracts[slot].fixed_fd == 20 + slot);
        assert((summary.archive_modes[slot] & 0777U) == 0600U);
        assert(summary.archive_nlinks[slot] == 0);
        assert(summary.archive_sizes[slot] == 0);
    }
    for (unsigned slot = 0; slot < 2; ++slot) {
        assert(summary.p1_state_contracts[slot].state_slot == slot);
        assert(summary.p1_state_contracts[slot].round == slot + 1);
        assert(summary.p1_state_contracts[slot].manifest_semantic == 1);
        assert(!summary.p1_state_contracts[slot]
                    .fixed_child_fd_required);
        assert(archives.emplace(
            summary.p1_state_devices[slot],
            summary.p1_state_inodes[slot]).second);
        assert((summary.p1_state_modes[slot] & 0777U) == 0600U);
        assert(summary.p1_state_nlinks[slot] == 0);
        assert(summary.p1_state_sizes[slot] == 0);
    }
    assert(summary.contracts[3].fixed_fd == 23 &&
           summary.contracts[8].fixed_fd == 28 &&
           summary.contracts[3].kind ==
               kpb::measurement::CaptureKind::CorruptServer &&
           summary.contracts[8].kind ==
               kpb::measurement::CaptureKind::CorruptServer);
    auto second = FreshTrialCaptureTopologyReservationBridge::
        test_only_reserve_unbound();
    assert(second.test_only_summary().reservation_identity !=
           summary.reservation_identity);
}

void move_is_linear() {
    auto first = FreshTrialCaptureTopologyReservationBridge::
        test_only_reserve_unbound();
    auto second = std::move(first);
    FreshTrialCaptureTopologyReservationBridge::test_only_require_valid(
        second);
    refuses([&] {
        FreshTrialCaptureTopologyReservationBridge::test_only_require_valid(
            first);
    });
}

void substitutions_refuse() {
    {
        auto value = FreshTrialCaptureTopologyReservationBridge::
            test_only_reserve_unbound();
        FreshTrialCaptureTopologyReservationBridge::test_only_close_read_end(
            value, 3);
        refuses([&] {
            FreshTrialCaptureTopologyReservationBridge::
                test_only_require_valid(value);
        });
    }
    {
        auto value = FreshTrialCaptureTopologyReservationBridge::
            test_only_reserve_unbound();
        FreshTrialCaptureTopologyReservationBridge::
            test_only_close_p1_state_parent_read(value, 0);
        refuses([&] {
            FreshTrialCaptureTopologyReservationBridge::
                test_only_require_valid(value);
        });
    }
    {
        auto value = FreshTrialCaptureTopologyReservationBridge::
            test_only_reserve_unbound();
        FreshTrialCaptureTopologyReservationBridge::
            test_only_close_p1_state_writer_alias(value, 1);
        refuses([&] {
            FreshTrialCaptureTopologyReservationBridge::
                test_only_require_valid(value);
        });
    }
    {
        auto value = FreshTrialCaptureTopologyReservationBridge::
            test_only_reserve_unbound();
        FreshTrialCaptureTopologyReservationBridge::
            test_only_close_writer_alias(value, 8);
        refuses([&] {
            FreshTrialCaptureTopologyReservationBridge::
                test_only_require_valid(value);
        });
    }
    {
        auto value = FreshTrialCaptureTopologyReservationBridge::
            test_only_reserve_unbound();
        FreshTrialCaptureTopologyReservationBridge::test_only_close_archive(
            value, 3);
        refuses([&] {
            FreshTrialCaptureTopologyReservationBridge::
                test_only_require_valid(value);
        });
    }
}

void postclaim_quarantine_retains_exact_resources() {
    auto reservation =
        FreshTrialCaptureTopologyReservationBridge::
            test_only_reserve_unbound();
    const auto selected = reservation.test_only_summary();
    std::array<bool, 10> transferred{};
    transferred[0] = true;
    transferred[2] = true;
    transferred[3] = true;
    auto quarantine = std::move(reservation)
        .test_only_take_quarantine_residual(transferred);
    const auto retained = quarantine.test_only_summary();
    assert(retained.reservation_identity == selected.reservation_identity &&
           retained.archive_devices == selected.archive_devices &&
           retained.archive_inodes == selected.archive_inodes);
    for (unsigned slot = 0; slot < 10; ++slot) {
        assert(retained.read_ends_retained[slot]);
        assert(retained.archives_retained[slot]);
        assert(retained.writer_aliases_retained[slot] == !transferred[slot]);
    }
    assert(retained.p1_state_devices == selected.p1_state_devices);
    assert(retained.p1_state_inodes == selected.p1_state_inodes);
    assert(std::ranges::all_of(
        retained.p1_state_parent_reads_retained,
        [](bool value) { return value; }));
    assert(std::ranges::all_of(
        retained.p1_state_writers_retained,
        [](bool value) { return value; }));
    auto moved = std::move(quarantine);
    (void)moved.test_only_summary();
    refuses([&] { (void)quarantine.test_only_summary(); });
}

void p1_state_parent_residual_is_linear() {
    auto reservation = FreshTrialCaptureTopologyReservationBridge::
        test_only_reserve_unbound();
    const auto selected = reservation.test_only_summary();
    auto residual = std::move(reservation)
        .test_only_take_p1_state_archive_residual();
    const auto summary = residual.test_only_summary();
    assert(summary.devices == selected.p1_state_devices);
    assert(summary.inodes == selected.p1_state_inodes);
    assert(summary.reservation_identity == selected.reservation_identity);
    assert(std::ranges::all_of(
        summary.parent_reads_retained,
        [](bool value) { return value; }));
    auto moved = std::move(residual);
    (void)moved.test_only_summary();
    refuses([&] { (void)residual.test_only_summary(); });
}

void status_is_fail_closed() {
    static_assert(kFreshTrialCaptureTopologyReservationSourceStatus
        .no_trial_identity_input);
    static_assert(kFreshTrialCaptureTopologyReservationSourceStatus
        .exact_ten_read_end_reservation);
    static_assert(kFreshTrialCaptureTopologyReservationSourceStatus
        .exact_ten_writer_alias_reservation);
    static_assert(kFreshTrialCaptureTopologyReservationSourceStatus
        .exact_ten_anonymous_disk_archives);
    static_assert(kFreshTrialCaptureTopologyReservationSourceStatus
        .private_resource_schedule_identity);
    static_assert(kFreshTrialCaptureTopologyReservationSourceStatus
        .archive_mode_nlink_size_bound);
    static_assert(kFreshTrialCaptureTopologyReservationSourceStatus
        .corrupt_server_slots_3_8_and_fds_23_28);
    static_assert(kFreshTrialCaptureTopologyReservationSourceStatus
        .descriptor_fingerprints_revalidated);
    static_assert(kFreshTrialCaptureTopologyReservationSourceStatus
        .exact_two_p1_state_archives);
    static_assert(kFreshTrialCaptureTopologyReservationSourceStatus
        .p1_state_parent_read_descriptions);
    static_assert(kFreshTrialCaptureTopologyReservationSourceStatus
        .p1_state_sole_writer_aliases);
    static_assert(kFreshTrialCaptureTopologyReservationSourceStatus
        .p1_state_labeled_scm_contract);
    static_assert(kFreshTrialCaptureTopologyReservationSourceStatus
        .p1_state_fixed_child_fds_absent);
    static_assert(!kFreshTrialCaptureTopologyReservationSourceStatus
        .p1_state_scm_activation_integration);
    static_assert(!kFreshTrialCaptureTopologyReservationSourceStatus
        .p1_state_capsule_source_bridge);
    static_assert(!kFreshTrialCaptureTopologyReservationSourceStatus
        .p1_state_terminal_disposition_bound);
    static_assert(!kFreshTrialCaptureTopologyReservationSourceStatus
        .p1_state_parent_rehydration);
    static_assert(!kFreshTrialCaptureTopologyReservationSourceStatus
        .p1_state_completion_authority);
    static_assert(kFreshTrialCaptureTopologyReservationSourceStatus
        .unbound_production_reserve_absent);
    static_assert(kFreshTrialCaptureTopologyReservationSourceStatus
        .process_derived_reservation_permit_contract);
    static_assert(kFreshTrialCaptureTopologyReservationSourceStatus
        .process_derived_reservation_permit_consumed);
    static_assert(kFreshTrialCaptureTopologyReservationSourceStatus
        .hidden_process_epoch_bound);
    static_assert(kFreshTrialCaptureTopologyReservationSourceStatus
        .child_postfork_fd_enumeration_control);
    static_assert(kFreshTrialCaptureTopologyReservationSourceStatus
        .postclaim_quarantine_residual);
    static_assert(!kFreshTrialCaptureTopologyReservationSourceStatus
        .no_allocation_unavailable_composite);
    static_assert(kFreshTrialCaptureTopologyReservationSourceStatus
        .launch_authority_absent);
    static_assert(!kFreshTrialCaptureTopologyReservationSourceStatus
        .all_three_pidfds_reserved_before_issuance);
    static_assert(!kFreshTrialCaptureTopologyReservationSourceStatus
        .selected_run_binding_factory);
    static_assert(!kFreshTrialCaptureTopologyReservationSourceStatus
        .fresh_trial_bind_integration);
    static_assert(!kFreshTrialCaptureTopologyReservationSourceStatus
        .selected_parent_callsite);
    static_assert(!kFreshTrialCaptureTopologyReservationSourceStatus
        .configured);
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::string_view scenario(argv[1]);
    if (scenario == "reserve") exact_preidentity_reservation();
    else if (scenario == "move") move_is_linear();
    else if (scenario == "substitute") substitutions_refuse();
    else if (scenario == "quarantine")
        postclaim_quarantine_retains_exact_resources();
    else if (scenario == "p1-state")
        p1_state_parent_residual_is_linear();
    else if (scenario == "status") status_is_fail_closed();
    else assert(false);
}
