#define KPI_FRESH_OWNER_PROCESS_ADAPTER_FIXTURE_NO_MAIN
#include "../mpc-prover/financial/controls/fresh_owner_process_adapter_test.cpp"

#include "honest_owner_material_authority.hpp"
#include "../../future-recipient/v3/v3_native_authority.hpp"

#include <algorithm>
#include <cassert>
#include <filesystem>
#include <memory>
#include <openssl/sha.h>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

using namespace kpb::future_recipient::v3_native;
using namespace kpb::honest_owner_material;

namespace {

template<class Function>
void native_refuses(Function&& function) {
    bool refused = false;
    try { function(); } catch (...) { refused = true; }
    assert(refused);
}

V3AcceptedRound1HistoryResidualAuthority genuine_v3_history(
        const kpb::measurement::RunBinding& selected) {
    auto selected_plan = hidden_plan();
    selected_plan.measurement_run_binding_identity =
        recompute_v3_run_binding_identity(selected);
    Roots roots;
    auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
        CompiledPrivateLifecycleOwnerProgramAuthority::test_only_mint(
            selected_plan,
            std::make_shared<CandidatePrivateLifecycleProgram>()),
        root_authorities(roots));
    auto round1 = supervisor.issue_round1(
        accepted_input_history(),
        replay_guard(std::make_shared<MemoryReplayRegistry>()),
        arm_residual(supervisor, CaptureClassification::HiddenCandidate));
    consume_round1_bootstrap(round1);
    auto round2 = supervisor.issue_round2(
        std::move(round1), accepted_history());
    consume_round2_bootstrap(round2);
    return round2.take_v3_history_residual();
}

std::unique_ptr<ParentV3Authority> production_parent(
        const std::filesystem::path& root, const std::string& stem,
        const kpb::measurement::RunBinding& selected) {
    const auto ledger = root / (stem + "-ledger");
    const auto external = root / (stem + "-external");
    assert(::mkdir(ledger.c_str(), 0700) == 0);
    assert(::mkdir(external.c_str(), 0700) == 0);
    auto store = V3NativeAuthorityTestSetup::initialize_fresh_with_external_head(
        ledger.c_str(), external.c_str(), selected, id(0x7f01));
    auto controller = V3LifecycleControllerMinter::mint(
        selected, genuine_v3_history(selected), std::move(store.second));
    return V3NativeAuthorityBridge::open_existing(
        std::move(store.first), std::move(controller), selected);
}

Invoice208 invoice(std::uint64_t index, unsigned char seed) {
    Invoice208 result{};
    std::copy_n("KPX3IN01", 8, result.begin());
    for (unsigned byte = 0; byte < 8; ++byte)
        result[40 + byte] = static_cast<unsigned char>(index >> (8 * byte));
    for (const auto offset : {8U, 48U, 80U, 112U, 144U, 176U})
        for (unsigned byte = 0; byte < 32; ++byte)
            result[offset + byte] = static_cast<unsigned char>(
                seed + offset + byte + 1);
    return result;
}

Output520 output(unsigned char seed) {
    Output520 result{};
    for (unsigned index = 0; index < result.size(); ++index)
        result[index] = static_cast<unsigned char>(seed + index + 1);
    assert(SHA256(result.data() + 96, 264, result.data() + 360) != nullptr);
    return result;
}

Digest nullifier(unsigned char seed) {
    Digest result{};
    result.fill(seed);
    return result;
}

HonestInvoiceSourceAuthority invoice_source_for(
        ParentV3Authority& parent,
        const kpb::measurement::RunBinding& selected,
        unsigned round, unsigned owner, unsigned slot,
        std::uint64_t index, Invoice208 selected_invoice) {
    auto injected = HonestOwnerMaterialTestFixture::invoice_source(
        selected, id(0x7f10), round, owner, slot, index, selected_invoice);
    return V3InvoiceMaterialMinter::test_only_bind_to_parent(
        std::move(injected), parent);
}

HonestOwnerOutputAuthority output_source_for(
        ParentV3Authority& parent,
        const kpb::measurement::RunBinding& selected,
        unsigned round, unsigned owner, unsigned slot,
        std::uint64_t index, Invoice208 selected_invoice,
        Digest nf, Output520 selected_output) {
    auto injected = HonestOwnerMaterialTestFixture::output_source(
        selected, id(0x7f11), round, owner, slot, index, selected_invoice,
        nf, selected_output);
    return V3InvoiceMaterialMinter::test_only_bind_to_parent(
        std::move(injected), parent);
}

AcceptedInvoiceAuthority accept_invoice(
        ParentV3Authority& parent,
        HonestInvoiceSourceAuthority&& source,
        const kpb::measurement::RunBinding& selected,
        const char* executable) {
    auto material = V3InvoiceMaterialMinter::mint(
        std::move(source), parent, selected);
    auto allocated = parent.allocate(std::move(material));
    auto split = parent.export_to_owner(std::move(allocated));
    auto residual = split.take_parent_residual();
    auto offer = split.take_owner_offer();
    const pid_t child = ::fork();
    assert(child >= 0);
    if (child == 0) {
        try {
            std::move(offer).install_for_owner();
            ::execl(executable, executable, "--owner-accept",
                    static_cast<char*>(nullptr));
        } catch (...) {}
        ::_exit(111);
    }
    auto accepted = parent.accept_from_owner(std::move(residual));
    int status = 0;
    assert(::waitpid(child, &status, 0) == child &&
           WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return accepted;
}

void exact_lifecycle_and_negative_controls(
        const std::filesystem::path& root, const char* executable) {
    const auto selected = candidate_measurement_binding();
    auto parent1 = production_parent(root, "parent1", selected);
    auto parent2 = production_parent(root, "parent2", selected);

    {
        const auto selected_invoice = invoice(1, 0x11);
        auto source = invoice_source_for(
            *parent1, selected, 1, 0, 0, 1, selected_invoice);
        auto material = V3InvoiceMaterialMinter::mint(
            std::move(source), *parent1, selected);
        native_refuses([&] {
            (void)parent2->allocate(std::move(material));
        });
    }
    {
        const auto selected_invoice = invoice(2, 0x21);
        auto accepted = accept_invoice(
            *parent1, invoice_source_for(
                *parent1, selected, 1, 0, 0, 2, selected_invoice),
            selected, executable);
        auto output_source = output_source_for(
            *parent1, selected, 1, 0, 0, 2, selected_invoice,
            nullifier(0x41), output(0x31));
        auto produced = V3InvoiceMaterialMinter::consume_for_output(
            *parent1, std::move(accepted), std::move(output_source));
        assert(parent1->test_only_state(2) == LifecycleState::Consumed);
        native_refuses([&] {
            (void)V3InvoiceMaterialMinter::consume_for_output(
                *parent1, std::move(accepted), std::move(output_source));
        });
        (void)produced;
    }
    {
        const auto selected_invoice = invoice(3, 0x51);
        auto accepted = accept_invoice(
            *parent1, invoice_source_for(
                *parent1, selected, 1, 1, 0, 3, selected_invoice),
            selected, executable);
        auto wrong_round = output_source_for(
            *parent1, selected, 2, 1, 0, 3, selected_invoice,
            nullifier(0x61), output(0x71));
        native_refuses([&] {
            (void)V3InvoiceMaterialMinter::consume_for_output(
                *parent1, std::move(accepted), std::move(wrong_round));
        });
        assert(parent1->test_only_state(3) == LifecycleState::Poisoned);
    }
    {
        const auto selected_invoice = invoice(4, 0x81);
        auto accepted = accept_invoice(
            *parent1, invoice_source_for(
                *parent1, selected, 1, 0, 1, 4, selected_invoice),
            selected, executable);
        auto wrong_owner = output_source_for(
            *parent1, selected, 1, 2, 1, 4, selected_invoice,
            nullifier(0x91), output(0xa1));
        native_refuses([&] {
            (void)V3InvoiceMaterialMinter::consume_for_output(
                *parent1, std::move(accepted), std::move(wrong_owner));
        });
        assert(parent1->test_only_state(4) == LifecycleState::Poisoned);
    }
    {
        const auto selected_invoice = invoice(5, 0xa1);
        auto accepted = accept_invoice(
            *parent1, invoice_source_for(
                *parent1, selected, 1, 2, 0, 5, selected_invoice),
            selected, executable);
        auto wrong_slot = output_source_for(
            *parent1, selected, 1, 2, 1, 5, selected_invoice,
            nullifier(0xb1), output(0xc1));
        native_refuses([&] {
            (void)V3InvoiceMaterialMinter::consume_for_output(
                *parent1, std::move(accepted), std::move(wrong_slot));
        });
        assert(parent1->test_only_state(5) == LifecycleState::Poisoned);
    }
    {
        const auto selected_invoice = invoice(6, 0xd1);
        auto accepted = accept_invoice(
            *parent1, invoice_source_for(
                *parent1, selected, 2, 2, 0, 6, selected_invoice),
            selected, executable);
        auto selected_output = output_source_for(
            *parent1, selected, 2, 2, 0, 6, selected_invoice,
            nullifier(0xe1), output(0xf1));
        native_refuses([&] {
            (void)V3InvoiceMaterialMinter::consume_for_output(
                *parent2, std::move(accepted), std::move(selected_output));
        });
        assert(parent1->test_only_state(6) == LifecycleState::Accepted);
        native_refuses([&] {
            (void)V3InvoiceMaterialMinter::consume_for_output(
                *parent1, std::move(accepted), std::move(selected_output));
        });
        assert(parent1->test_only_state(6) == LifecycleState::Accepted);
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string(argv[1]) == "--owner-accept") {
        owner_accept_from_fixed_fds();
        return 0;
    }
    assert(argc == 2);
    const std::filesystem::path root(argv[1]);
    assert(root.is_absolute());
    static_assert(kHonestOwnerMaterialSourceStatus.v3_accepted_history_join);
    static_assert(kHonestOwnerMaterialSourceStatus.
                  live_parent_exactly_matches_accepted_authority);
    static_assert(kHonestOwnerMaterialSourceStatus.
                  accepted_invoice_exact_match);
    static_assert(kHonestOwnerMaterialSourceStatus.
                  cm_cv_ciphertext_proof_exact_row_match);
    static_assert(!kHonestOwnerMaterialSourceStatus.
                  production_invoice_source_minter_available);
    static_assert(!kHonestOwnerMaterialSourceStatus.
                  production_output_source_minter_available);
    static_assert(!kHonestOwnerMaterialSourceStatus.
                  selected_lifecycle_callsite_integrated);
    static_assert(!kHonestOwnerMaterialSourceStatus.configured);
    exact_lifecycle_and_negative_controls(root, argv[0]);
    return 0;
}
