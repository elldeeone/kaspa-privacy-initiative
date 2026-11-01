#include "c1_registered_plan_route_minters.hpp"

#include <array>
#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

// Reuse the already-reviewed registered parent/lineage fixture in this one
// test translation unit.  Its main is retained under a different name so all
// of its single-round controls remain compiled without creating a second
// production fixture surface.
#define main registered_c1_legacy_control_main
#include "c1_registered_plan_route_bridge_control.cpp"
#undef main

namespace {

struct SourceFile final {
    int fd{-1};

    explicit SourceFile(std::string_view value) {
        fd = ::memfd_create(
            "kpb-c1-source-control", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        assert(fd >= 0 && ::fchmod(fd, 0600) == 0);
        std::size_t at = 0;
        while (at < value.size()) {
            const auto count = ::write(
                fd, value.data() + at, value.size() - at);
            if (count < 0 && errno == EINTR) continue;
            assert(count > 0);
            at += static_cast<std::size_t>(count);
        }
        assert(::lseek(fd, 0, SEEK_SET) == 0);
    }
    SourceFile(const SourceFile&) = delete;
    SourceFile& operator=(const SourceFile&) = delete;
    SourceFile(SourceFile&& other) noexcept
        : fd(std::exchange(other.fd, -1)) {}
    ~SourceFile() { close_fd(fd); }
};

struct OrdinaryFile final {
    int fd{-1};

    explicit OrdinaryFile(std::uint64_t byte_count) {
        char path[] = "/tmp/kpb-c1-ordinary-control-XXXXXX";
        fd = ::mkstemp(path);
        assert(fd >= 0 && ::unlink(path) == 0 &&
               ::fchmod(fd, 0600) == 0 &&
               ::ftruncate(fd, static_cast<off_t>(byte_count)) == 0);
        const int flags = ::fcntl(fd, F_GETFD);
        assert(flags >= 0 &&
               ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0);
    }
    OrdinaryFile(const OrdinaryFile&) = delete;
    OrdinaryFile& operator=(const OrdinaryFile&) = delete;
    ~OrdinaryFile() { close_fd(fd); }
};

std::array<std::string, 3> round_operations(unsigned round) {
    if (round == 1) return operations();
    return {
        "66666666-6666-4666-8666-666666666666",
        "77777777-7777-4777-8777-777777777777",
        "88888888-8888-4888-8888-888888888888",
    };
}

RegisteredC1RoundRouteEvidenceAuthority produce_round(
        ParentTenReadEndsAuthority& topology,
        const PublicProducerLaunchPlan& selected_plan,
        unsigned round,
        const std::array<std::string, 3>& selected_operations,
        int reused_route_zero_fd = -1) {
    const auto selected_lineage = lineage(selected_plan, round);
    auto lineage_authority =
        RegisteredC1RoundLineageAuthority::test_only_mint(
            selected_lineage);
    auto selection_callsite =
        RegisteredC1RuntimeCallsiteBridge::begin_controller_selection(
            std::move(lineage_authority), std::string(CAPTURE));
    for (unsigned index = 0; index < 3; ++index) {
        SourceFile source(
            "selection-round-" + std::to_string(round) + "-stage-" +
            std::to_string(index) + "-" + selected_operations[index]);
        auto observed = RegisteredC1RouteMinterTestFixture::selection_source(
            selection_callsite, static_cast<C1ControllerStage>(index),
            selected_operations[index], source.fd);
        selection_callsite.observe_selected_stage(std::move(observed));
    }
    auto selected_round = std::move(selection_callsite).finish();
    auto launch = RegisteredC1RuntimeCallsiteBridge::prepare_selected(
        topology, std::move(selected_round));
    auto offer = launch.take_fd31_offer();
    std::move(offer).install_for_child();
    auto terminal = launch.take_terminal_callsite();
    auto parsed = RegisteredC1RouteMinterTestFixture::fd31_parse_source(
        terminal);
    terminal.observe_fd31_offer_parse(std::move(parsed));

    SourceFile invoice_result(
        "terminal-round-" + std::to_string(round) + "-invoice");
    auto invoice_terminal =
        RegisteredC1RouteMinterTestFixture::terminal_source(
            terminal, C1ControllerStage::Invoice, invoice_result.fd, 0);
    terminal.observe_controller_terminal(std::move(invoice_terminal));
    SourceFile pay_result(
        "terminal-round-" + std::to_string(round) + "-pay");
    auto pay_terminal = RegisteredC1RouteMinterTestFixture::terminal_source(
        terminal, C1ControllerStage::Pay, pay_result.fd, 0);
    terminal.observe_controller_terminal(std::move(pay_terminal));
    for (unsigned owner = 0; owner < 3; ++owner) {
        if (owner == 0 && reused_route_zero_fd >= 0) {
            auto route = RegisteredC1RouteMinterTestFixture::route_source(
                terminal, owner, reused_route_zero_fd);
            terminal.observe_route_artifact(std::move(route));
            continue;
        }
        SourceFile route(
            "route-round-" + std::to_string(round) + "-owner-" +
            std::to_string(owner));
        auto observed_route =
            RegisteredC1RouteMinterTestFixture::route_source(
                terminal, owner, route.fd);
        terminal.observe_route_artifact(std::move(observed_route));
    }
    SourceFile scan_result(
        "terminal-round-" + std::to_string(round) + "-scan");
    auto scan_terminal = RegisteredC1RouteMinterTestFixture::terminal_source(
        terminal, C1ControllerStage::Scan, scan_result.fd, 0);
    terminal.observe_controller_terminal(std::move(scan_terminal));
    auto completion =
        RegisteredC1RouteMinterTestFixture::completion_source(terminal);
    terminal.observe_authenticated_completion(std::move(completion));
    auto admitted = std::move(terminal).finish();
    auto observer_admission = admitted.take_admission();
    (void)observer_admission;
    auto evidence = admitted.take_route_evidence();
    refuses([&] { (void)admitted.take_admission(); });
    refuses([&] { (void)admitted.take_route_evidence(); });
    return evidence;
}

void positive_two_round_join() {
    const auto selected_plan = plan();
    PipeSet pipes;
    auto topology = parent(pipes, selected_plan);
    auto round1 = produce_round(
        topology, selected_plan, 1, round_operations(1));
    auto round2 = produce_round(
        topology, selected_plan, 2, round_operations(2));
    RegisteredC1TwoRoundRouteEvidenceJoiner joiner;
    joiner.accept(std::move(round1));
    joiner.accept(std::move(round2));
    auto complete = std::move(joiner).finish();
    (void)complete;
    refuses([&] { joiner.accept(std::move(round1)); });
}

void selection_refusal_poison_and_snapshot_immutability() {
    {
        const auto selected_plan = plan();
        const auto selected_lineage = lineage(selected_plan, 1);
        auto lineage_authority =
            RegisteredC1RoundLineageAuthority::test_only_mint(
                selected_lineage);
        auto callsite =
            RegisteredC1RuntimeCallsiteBridge::begin_controller_selection(
                std::move(lineage_authority), std::string(CAPTURE));
        SourceFile wrong("wrong-order");
        auto wrong_source =
            RegisteredC1RouteMinterTestFixture::selection_source(
                callsite, C1ControllerStage::Pay,
                round_operations(1)[1], wrong.fd);
        refuses([&] {
            callsite.observe_selected_stage(std::move(wrong_source));
        });
        SourceFile correct("correct-after-poison");
        auto correct_source =
            RegisteredC1RouteMinterTestFixture::selection_source(
                callsite, C1ControllerStage::Invoice,
                round_operations(1)[0], correct.fd);
        refuses([&] {
            callsite.observe_selected_stage(std::move(correct_source));
        });
        refuses([&] { (void)std::move(callsite).finish(); });
    }
    {
        const auto selected_plan = plan();
        const auto selected_lineage = lineage(selected_plan, 1);
        auto lineage_authority =
            RegisteredC1RoundLineageAuthority::test_only_mint(
                selected_lineage);
        auto callsite =
            RegisteredC1RuntimeCallsiteBridge::begin_controller_selection(
                std::move(lineage_authority), std::string(CAPTURE));
        const auto selected_operations = round_operations(1);
        std::array<SourceFile, 3> sources{
            SourceFile("mutable-selection-0"),
            SourceFile("mutable-selection-1"),
            SourceFile("mutable-selection-2"),
        };
        for (unsigned index = 0; index < 3; ++index)
        {
            auto observed =
                RegisteredC1RouteMinterTestFixture::selection_source(
                    callsite, static_cast<C1ControllerStage>(index),
                    selected_operations[index], sources[index].fd);
            callsite.observe_selected_stage(std::move(observed));
        }
        const unsigned char changed = 'X';
        assert(::pwrite(sources[0].fd, &changed, 1, 0) == 1);
        // The opaque source authority retained the exact bytes it observed in
        // a sealed snapshot; later mutation of the caller's original FD does
        // not rewrite that evidence.
        auto selected = std::move(callsite).finish();
        (void)selected;
    }
}

void ordinary_file_on_fd31_is_refused() {
    const auto selected_plan = plan();
    PipeSet pipes;
    auto topology = parent(pipes, selected_plan);
    auto lineage_authority =
        RegisteredC1RoundLineageAuthority::test_only_mint(
            lineage(selected_plan, 1));
    auto selection_callsite =
        RegisteredC1RuntimeCallsiteBridge::begin_controller_selection(
            std::move(lineage_authority), std::string(CAPTURE));
    const auto selected_operations = round_operations(1);
    for (unsigned index = 0; index < 3; ++index) {
        SourceFile source(
            "ordinary-fd31-selection-" + std::to_string(index));
        auto observed = RegisteredC1RouteMinterTestFixture::selection_source(
            selection_callsite, static_cast<C1ControllerStage>(index),
            selected_operations[index], source.fd);
        selection_callsite.observe_selected_stage(std::move(observed));
    }
    auto selected_round = std::move(selection_callsite).finish();
    auto launch = RegisteredC1RuntimeCallsiteBridge::prepare_selected(
        topology, std::move(selected_round));
    auto offer = launch.take_fd31_offer();
    std::move(offer).install_for_child();
    auto terminal = launch.take_terminal_callsite();

    OrdinaryFile ordinary(C1_CONTACT_VALUE_OFFER_BYTES);
    assert(ordinary.fd != C1_CONTACT_VALUE_OFFER_FIXED_FD);
    errno = 0;
    assert(::fcntl(ordinary.fd, F_GET_SEALS) < 0);
    assert(::dup3(ordinary.fd, C1_CONTACT_VALUE_OFFER_FIXED_FD,
                  O_CLOEXEC) == C1_CONTACT_VALUE_OFFER_FIXED_FD);
    refuses([&] {
        (void)RegisteredC1RouteMinterTestFixture::fd31_parse_source(
            terminal);
    });
    errno = 0;
    assert(::fcntl(C1_CONTACT_VALUE_OFFER_FIXED_FD, F_GETFD) == -1 &&
           errno == EBADF);
}

void incomplete_and_wrong_order_joins_poison() {
    {
        const auto selected_plan = plan();
        PipeSet pipes;
        auto topology = parent(pipes, selected_plan);
        auto round1 = produce_round(
            topology, selected_plan, 1, round_operations(1));
        RegisteredC1TwoRoundRouteEvidenceJoiner joiner;
        joiner.accept(std::move(round1));
        refuses([&] { (void)std::move(joiner).finish(); });
    }
    {
        const auto selected_plan = plan();
        PipeSet pipes;
        auto topology = parent(pipes, selected_plan);
        auto round2 = produce_round(
            topology, selected_plan, 2, round_operations(2));
        RegisteredC1TwoRoundRouteEvidenceJoiner joiner;
        refuses([&] { joiner.accept(std::move(round2)); });
        refuses([&] { (void)std::move(joiner).finish(); });
    }
}

void cross_round_operation_and_file_reuse_refuse() {
    {
        const auto selected_plan = plan();
        PipeSet pipes;
        auto topology = parent(pipes, selected_plan);
        const auto reused_operations = round_operations(1);
        auto round1 = produce_round(
            topology, selected_plan, 1, reused_operations);
        auto round2 = produce_round(
            topology, selected_plan, 2, reused_operations);
        RegisteredC1TwoRoundRouteEvidenceJoiner joiner;
        joiner.accept(std::move(round1));
        refuses([&] { joiner.accept(std::move(round2)); });
        refuses([&] { (void)std::move(joiner).finish(); });
    }
    {
        SourceFile reused_route("same-route-file-across-rounds");
        const auto selected_plan = plan();
        PipeSet pipes;
        auto topology = parent(pipes, selected_plan);
        auto round1 = produce_round(
            topology, selected_plan, 1, round_operations(1),
            reused_route.fd);
        auto round2 = produce_round(
            topology, selected_plan, 2, round_operations(2),
            reused_route.fd);
        RegisteredC1TwoRoundRouteEvidenceJoiner joiner;
        joiner.accept(std::move(round1));
        refuses([&] { joiner.accept(std::move(round2)); });
        refuses([&] { (void)std::move(joiner).finish(); });
    }
}

void cross_trial_and_same_round_refuse() {
    {
        auto first_plan = plan();
        auto second_plan = plan();
        second_plan.capture_trial_id = std::string(OTHER_TRIAL);
        second_plan.binding.trial = trial_identity(OTHER_TRIAL);
        PipeSet first_pipes;
        PipeSet second_pipes;
        auto first_parent = parent(first_pipes, first_plan);
        auto second_parent = parent(second_pipes, second_plan);
        auto round1 = produce_round(
            first_parent, first_plan, 1, round_operations(1));
        auto round2 = produce_round(
            second_parent, second_plan, 2, round_operations(2));
        RegisteredC1TwoRoundRouteEvidenceJoiner joiner;
        joiner.accept(std::move(round1));
        refuses([&] { joiner.accept(std::move(round2)); });
    }
    {
        const auto first_plan = plan();
        const auto second_plan = plan();
        PipeSet first_pipes;
        PipeSet second_pipes;
        auto first_parent = parent(first_pipes, first_plan);
        auto second_parent = parent(second_pipes, second_plan);
        auto first = produce_round(
            first_parent, first_plan, 1, round_operations(1));
        auto duplicate = produce_round(
            second_parent, second_plan, 1, round_operations(2));
        RegisteredC1TwoRoundRouteEvidenceJoiner joiner;
        joiner.accept(std::move(first));
        refuses([&] { joiner.accept(std::move(duplicate)); });
    }
}

void source_status_is_honest() {
    const auto value = registered_c1_plan_route_source_status();
    assert(value.schema == "kpb-registered-c1-plan-route-source/v2");
    assert(value.status == "SOURCE_AUTHORITY_CORES_SELECTED_RUNTIME0");
    assert(value.immutable_sealed_source_snapshot_core);
    assert(value.opaque_source_controller_selection_minter_core);
    assert(value.opaque_source_fd31_completion_ack_minter_core);
    assert(value.opaque_source_controller_terminal_minter_core);
    assert(value.opaque_source_observed_route_minter_core);
    assert(!value.production_controller_selection_minter);
    assert(!value.production_fd31_completion_ack_minter);
    assert(!value.production_controller_terminal_minter);
    assert(!value.production_observed_route_minter);
    assert(!value.production_two_round_route_evidence_minter);
    assert(value.typed_launcher_terminal_callsite_contract_core);
    assert(value.two_round_route_evidence_join_core);
    assert(!value.exact_launcher_terminal_callsite_contract);
    assert(value.fail_closed_two_round_route_join);
    assert(!value.registered_prelaunch_split_core);
    assert(!value.selected_launcher_consumes_offer);
    assert(!value.selected_terminal_admission_callsite);
    assert(!value.selected_two_round_route_callsite);
    assert(!value.selected_consumer_uses_same_source_snapshot);
    assert(!value.owner_truth_input && !value.actual_receipt_emitted);
    assert(!value.configured && !value.actual_launch && !value.complete);
}

} // namespace

int main() {
    positive_two_round_join();
    selection_refusal_poison_and_snapshot_immutability();
    ordinary_file_on_fd31_is_refused();
    incomplete_and_wrong_order_joins_poison();
    cross_round_operation_and_file_reuse_refuse();
    cross_trial_and_same_round_refuse();
    source_status_is_honest();
    return 0;
}
