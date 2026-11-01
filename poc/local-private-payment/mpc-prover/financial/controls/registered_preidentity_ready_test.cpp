#include "financial/registered_parent_role_fork.hpp"
#include "financial/registered_preidentity_ready.hpp"
#include "privacy_registered_fresh_trial_capture_topology_reservation.hpp"

#include <cassert>
#include <array>
#include <cerrno>
#include <cstdint>
#include <dirent.h>
#include <string>
#include <type_traits>
#include <utility>
#include <unistd.h>

namespace {

using namespace kpi::mpc::financial::registered_driver;

class UnreachableRoundProgram final : public RegisteredRoleChildProgram {
public:
    int run(ParentAuthenticatedPartyDeliveryAuthority&&,
            ChildRoleCompletionEndpointAuthority&&) override {
        return 99;
    }
};

class GenericPreIdentityProgram final :
        public RegisteredPreIdentityPersistentRoleChildProgram {
    std::array<UnreachableRoundProgram, 2> rounds_;
public:
    RegisteredRoleChildProgram& round_program(unsigned round) override {
        assert(round == 1 || round == 2);
        return rounds_[round - 1];
    }
};

template<class Callable>
void refuses(Callable&& callable) {
    bool did_refuse = false;
    try { callable(); }
    catch (const kpi::mpc::financial::identity_registry::Refused&) {
        did_refuse = true;
    }
    assert(did_refuse);
}

unsigned open_descriptor_count() {
    DIR* directory = ::opendir("/proc/self/fd");
    assert(directory != nullptr);
    unsigned result = 0;
    errno = 0;
    while (const auto* entry = ::readdir(directory))
        if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') ++result;
    assert(errno == 0);
    assert(::closedir(directory) == 0);
    return result;
}

void require_abort_complete(
        detail::PersistentRoleReservationAbortEvidence& evidence) {
    assert(evidence.all_children_settled_value());
    const auto& pids = evidence.child_pids_value();
    for (unsigned role = 0; role < 3; ++role) {
        assert(pids[role] > 1);
    }
}

void exact_join_is_linear_and_resource_clean() {
    static_assert(!std::is_default_constructible_v<
                  RegisteredPreidentityReadyAuthority>);
    static_assert(!std::is_copy_constructible_v<
                  RegisteredPreidentityReadyAuthority>);
    static_assert(std::is_nothrow_move_constructible_v<
                  RegisteredPreidentityReadyAuthority>);

    const auto before = open_descriptor_count();
    {
        GenericPreIdentityProgram program;
        auto process = RegisteredParentPersistentRoleFork::reserve(program);
        auto permit = process.issue_topology_reservation_permit();
        auto topology = FreshTrialCaptureTopologyReservationBridge::reserve(
            std::move(permit));
        auto ready = RegisteredPreidentityReadyBridge::join(
            std::move(topology), std::move(process));
        RegisteredPreidentityReadyAuthority retained(std::move(ready));
        (void)retained;
    }
    assert(open_descriptor_count() == before);
}

void owner_permits_and_residual_are_one_shot() {
    const auto before = open_descriptor_count();
    {
        GenericPreIdentityProgram program;
        auto process = RegisteredParentPersistentRoleFork::reserve(program);
        auto permit = process.issue_topology_reservation_permit();
        auto topology = FreshTrialCaptureTopologyReservationBridge::reserve(
            std::move(permit));
        auto ready = RegisteredPreidentityReadyBridge::join(
            std::move(topology), std::move(process));
        auto session = RegisteredPreidentityReadyIssuanceBridge::begin(
            std::move(ready));
        refuses([&] {
            (void)RegisteredPreidentityReadyIssuanceBridge::begin(
                std::move(ready));
        });
        auto owner0 = RegisteredPreidentityReadyIssuanceBridge::
            take_owner_permit(session, 0);
        refuses([&] {
            (void)RegisteredPreidentityReadyIssuanceBridge::
                take_owner_permit(session, 0);
        });
        auto owner1 = RegisteredPreidentityReadyIssuanceBridge::
            take_owner_permit(session, 1);
        refuses([&] {
            (void)RegisteredPreidentityReadyIssuanceBridge::finish(
                std::move(session));
        });
        auto owner2 = RegisteredPreidentityReadyIssuanceBridge::
            take_owner_permit(session, 2);
        (void)owner0;
        (void)owner1;
        (void)owner2;
        auto residual = RegisteredPreidentityReadyIssuanceBridge::finish(
            std::move(session));
        refuses([&] {
            (void)RegisteredPreidentityReadyIssuanceBridge::finish(
                std::move(session));
        });
        RegisteredPreidentityReadyIssuanceResidual retained(
            std::move(residual));
        (void)retained;
    }
    assert(open_descriptor_count() == before);
}

void invalid_topology_refusal_preserves_both_callers() {
    const auto before = open_descriptor_count();
    {
        GenericPreIdentityProgram program;
        auto process = RegisteredParentPersistentRoleFork::reserve(program);
        auto permit = process.issue_topology_reservation_permit();
        auto topology = FreshTrialCaptureTopologyReservationBridge::reserve(
            std::move(permit));
        FreshTrialCaptureTopologyReservationBridge::test_only_close_writer_alias(
            topology, 0);

        refuses([&] {
            (void)RegisteredPreidentityReadyBridge::join(
                std::move(topology), std::move(process));
        });

        // The rejected join did not move either caller. The invalid topology
        // remains source-owned: its test-only fault bridge can still reach the
        // original storage and close another exact descriptor. Destruction is
        // then the source-owned fail-closed cleanup for this pre-claim fault.
        FreshTrialCaptureTopologyReservationBridge::test_only_close_writer_alias(
            topology, 1);

        auto aborted = RegisteredParentPersistentRoleFork::abort(
            std::move(process));
        require_abort_complete(aborted);
    }
    assert(open_descriptor_count() == before);
}

void invalid_process_refusal_preserves_both_callers() {
    const auto before = open_descriptor_count();
    {
        GenericPreIdentityProgram program;
        auto process = RegisteredParentPersistentRoleFork::reserve(program);
        auto permit = process.issue_topology_reservation_permit();
        auto topology = FreshTrialCaptureTopologyReservationBridge::reserve(
            std::move(permit));
        const auto selected = topology.test_only_summary();
        ParentRoleForkTestProcessBridge::close_reservation_channel(
            process, 1, 1);

        refuses([&] {
            (void)RegisteredPreidentityReadyBridge::join(
                std::move(topology), std::move(process));
        });

        const auto retained_topology = topology.test_only_summary();
        assert(retained_topology.reservation_identity ==
               selected.reservation_identity);
        for (unsigned slot = 0; slot < 10; ++slot) {
            assert(retained_topology.read_ends_valid[slot]);
            assert(retained_topology.writer_aliases_valid[slot]);
            assert(retained_topology.archives_valid[slot]);
        }
        std::array<bool, 10> transferred{};
        auto quarantine = std::move(topology)
            .test_only_take_quarantine_residual(transferred);
        const auto retained = quarantine.test_only_summary();
        assert(retained.reservation_identity == selected.reservation_identity);
        for (unsigned slot = 0; slot < 10; ++slot) {
            assert(retained.read_ends_retained[slot]);
            assert(retained.writer_aliases_retained[slot]);
            assert(retained.archives_retained[slot]);
        }

        auto aborted = RegisteredParentPersistentRoleFork::abort(
            std::move(process));
        require_abort_complete(aborted);
    }
    assert(open_descriptor_count() == before);
}

void mismatched_process_epoch_refuses_without_claiming() {
    const auto before = open_descriptor_count();
    {
        GenericPreIdentityProgram first_program;
        GenericPreIdentityProgram second_program;
        auto first_process =
            RegisteredParentPersistentRoleFork::reserve(first_program);
        auto first_permit =
            first_process.issue_topology_reservation_permit();
        auto first_topology =
            FreshTrialCaptureTopologyReservationBridge::reserve(
                std::move(first_permit));
        const auto selected = first_topology.test_only_summary();

        auto second_process =
            RegisteredParentPersistentRoleFork::reserve(second_program);
        auto second_permit =
            second_process.issue_topology_reservation_permit();

        refuses([&] {
            (void)RegisteredPreidentityReadyBridge::join(
                std::move(first_topology), std::move(second_process));
        });

        // Both mismatched inputs remain caller-owned. The second permit also
        // remains live, so its matching topology can still be opened.
        assert(first_topology.test_only_summary().reservation_identity ==
               selected.reservation_identity);
        auto second_topology =
            FreshTrialCaptureTopologyReservationBridge::reserve(
                std::move(second_permit));
        const auto second_selected = second_topology.test_only_summary();
        assert(second_selected.reservation_identity !=
               selected.reservation_identity);

        std::array<bool, 10> transferred{};
        auto first_quarantine = std::move(first_topology)
            .test_only_take_quarantine_residual(transferred);
        auto second_quarantine = std::move(second_topology)
            .test_only_take_quarantine_residual(transferred);
        assert(first_quarantine.test_only_summary().reservation_identity ==
               selected.reservation_identity);
        assert(second_quarantine.test_only_summary().reservation_identity ==
               second_selected.reservation_identity);

        auto first_abort = RegisteredParentPersistentRoleFork::abort(
            std::move(first_process));
        auto second_abort = RegisteredParentPersistentRoleFork::abort(
            std::move(second_process));
        require_abort_complete(first_abort);
        require_abort_complete(second_abort);
    }
    assert(open_descriptor_count() == before);
}

void stale_permit_after_process_abort_opens_no_topology() {
    const auto before = open_descriptor_count();
    {
        GenericPreIdentityProgram program;
        auto process = RegisteredParentPersistentRoleFork::reserve(program);
        auto permit = process.issue_topology_reservation_permit();
        auto aborted = RegisteredParentPersistentRoleFork::abort(
            std::move(process));
        require_abort_complete(aborted);
        const auto after_abort = open_descriptor_count();

        refuses([&] {
            (void)FreshTrialCaptureTopologyReservationBridge::reserve(
                std::move(permit));
        });
        assert(open_descriptor_count() == after_abort);
        // The opener validates before allocation or permit consumption.
        refuses([&] {
            (void)FreshTrialCaptureTopologyReservationBridge::reserve(
                std::move(permit));
        });
        assert(open_descriptor_count() == after_abort);
    }
    assert(open_descriptor_count() == before);
}

void source_status_stays_unconfigured() {
    static_assert(kRegisteredPreidentityReadySourceStatus.
                  topology_and_process_join_core);
    static_assert(!kRegisteredPreidentityReadySourceStatus.
                  causal_owner_issuance_consumer);
    static_assert(!kRegisteredPreidentityReadySourceStatus.
                  phase2_activation_extraction);
    static_assert(!kRegisteredPreidentityReadySourceStatus.
                  postissuance_failure_composite);
    static_assert(!kRegisteredPreidentityReadySourceStatus.
                  selected_parent_callsite);
    static_assert(!kRegisteredPreidentityReadySourceStatus.configured);
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::string selected(argv[1]);
    if (selected == "exact") exact_join_is_linear_and_resource_clean();
    else if (selected == "owner-permits")
        owner_permits_and_residual_are_one_shot();
    else if (selected == "invalid-topology")
        invalid_topology_refusal_preserves_both_callers();
    else if (selected == "invalid-process")
        invalid_process_refusal_preserves_both_callers();
    else if (selected == "wrong-epoch")
        mismatched_process_epoch_refuses_without_claiming();
    else if (selected == "stale-permit")
        stale_permit_after_process_abort_opens_no_topology();
    else if (selected == "status") source_status_stays_unconfigured();
    else return 2;
    return 0;
}
