#include "construction_storage.hpp"
#include "accepted_head.hpp"
#include "registered_driver_bridge.hpp"
#include "registered_capture_session.hpp"
#include "registered_selection.hpp"
#include "../trace/prefix_recipe.hpp"
#include "../trace/sealed_trace.hpp"
#include <algorithm>

namespace kpi::mpc::financial {
namespace {
using Bytes = std::vector<unsigned char>;
[[noreturn]] void refuse() { throw history::Refused(); }
void need(bool value) { if (!value) refuse(); }
void add(Bytes& out, std::span<const unsigned char> value) { out.insert(out.end(), value.begin(), value.end()); }
void integer(Bytes& out, uint64_t value) { for (unsigned i = 0; i < 8; ++i) out.push_back(value >> (8 * i)); }
Bytes context_bytes(const history::EpochKey& key, const history::AttemptBinding& binding) {
    need(std::equal(binding.old_state.begin(), binding.old_state.begin() + 8, "KPBAST01") &&
         std::equal(key.domain.begin(), key.domain.end(), binding.old_state.begin() + 8));
    Bytes result;
    for (const auto* value : {&key.chain, &key.pool, &key.profile, &key.domain, &key.service}) add(result, *value);
    add(result, binding.old_point); add(result, std::span(binding.old_state).subspan(40, 32));
    add(result, std::span(binding.old_state).subspan(76, 32));
    add(result, std::span(binding.old_state).subspan(72, 4));
    add(result, std::span(binding.old_state).subspan(108, 4)); integer(result, binding.old_reserve);
    need(result.size() == FinancialConstruction::CONTEXT_CHECKS); return result;
}
AuthScalar byte_value(MascotContext& context, std::span<const AuthScalar> assignment, size_t byte) {
    auto value = context.public_constant(Fr(0));
    for (size_t bit = 0; bit < 8; ++bit)
        value += assignment[FinancialConstruction::CORE_FIRST_BIT_COLUMN + 8 * byte + bit] * Fr(1 << bit);
    return value;
}
} // namespace

FinancialConstruction FinancialConstruction::construct_registered(MascotContext& context,
    RegisteredFinancialSelection&& selection, const std::array<OwnerInputContract, 3>& jobs,
    const history::AttemptBinding& binding,
    registered_driver::DriverAttempt&& driver_authority) {
    try {
        selection.require_live(context);
        const auto& service =
            RegisteredSelectionConstructionBridge::service(selection);
        const auto& model =
            RegisteredSelectionConstructionBridge::model(selection);
        const auto& program =
            RegisteredSelectionConstructionBridge::program(selection);
        const auto& selected = program.binding;
        const auto owner_effects_recipe =
            RegisteredSelectionConstructionBridge::owner_effects_recipe(
                selection);
        const auto& metadata = model.metadata();
        const auto& driver =
            registered_driver::RegisteredConstructionAuthorityBridge::
                selected_driver(driver_authority);
        const auto& proposal =
            registered_driver::RegisteredConstructionAuthorityBridge::
                proposal(driver_authority);
        const auto& proposed = proposal.public_selection_hashes();
        const int owner_port = driver.owner_port;
        const size_t multiplication_batch = driver.multiplication_batch;
        need(owner_port >= 1024 && owner_port <= 65533 && multiplication_batch &&
             owner_effects_recipe != nullptr &&
             owner_effects_recipe->source_identity() == metadata.source_sha256 &&
             owner_effects_recipe->layout_identity() == selected.layout_sha256 &&
             owner_effects_recipe->model_variables() == program.header.model_variables &&
             owner_effects_recipe->instances() == program.header.instances &&
             driver.role == service.party_id() &&
             driver.service_identity == service.identity() &&
             proposal.role() == driver.role &&
             proposal.authority_identity() == driver.authority_identity &&
             identity_registry::selection_identity(proposed) ==
                 driver.selection_identity &&
             proposed.attempt == binding.attempt &&
             proposed.cohort == binding.cohort &&
             proposed.accepted_head == binding.admitted_head &&
             selection.attempt_binding(context, jobs, binding.attempt, binding.cohort) == binding);
        for (size_t owner = 0; owner < 3; ++owner) {
            const auto& job = jobs[owner]; (void)canonical_owner_contract(job);
            const auto canonical = canonical_owner_contract(job);
            const auto owner_identity = history::digest(std::span(
                reinterpret_cast<const unsigned char*>(canonical.data()),
                canonical.size()));
            need(job.owner_id == static_cast<int>(owner) &&
                 proposed.owner_contracts[owner] == owner_identity &&
                 job.input_count == OWNER_INPUT_COUNT &&
                 job.input_count == program.owner_layout.at(owner).columns.size() &&
                 job.model_identity == model.identity() && job.source_identity == metadata.source_sha256 &&
                 job.proving_key_identity == metadata.pk_sha256 && job.verifying_key_identity == metadata.vk_sha256 &&
                 job.trace_identity == selected.trace_sha256 && job.layout_identity == selected.layout_sha256 &&
                 job.run_nonce == history::hex(binding.attempt) && job.cohort_identity == history::hex(binding.cohort));
            for (size_t party = 0; party < 3; ++party)
                need(job.server_certificate_sha256[party] == history::hex(service.key().server_certificates[party]));
        }
        const auto expected_context = context_bytes(service.key(), binding);
        const auto selected_tail =
            RegisteredSelectionConstructionBridge::native_tail(selection);
        Bytes tail(selected_tail.begin(), selected_tail.end());
        need(history::digest(tail) == binding.immutable_tail &&
             history::reserve_spk(binding.old_state, tail) == binding.old_spk);
        auto journal = history::EpochJournal::open_existing(service.journal_directory(), service.anchor_directory(),
                                                          service.key(), service.registration());
        Bytes public_binding;
        const std::string label = "KPB_REGISTERED_FINANCIAL_CONSTRUCTION_V1\n";
        public_binding.insert(public_binding.end(), label.begin(), label.end());
        add(public_binding, history::unhex(selection.identity()));
        add(public_binding, history::unhex(program.artifact->container_sha256()));
        add(public_binding, history::unhex(program.artifact->decoder_identity()));
        add(public_binding, history::unhex(model.query_transport_identity()));
        add(public_binding, history::unhex(owner_effects_recipe->identity()));
        integer(public_binding, program.expected_private_checks); integer(public_binding, CONTEXT_CHECKS);
        integer(public_binding, multiplication_batch);
        agree_trace(context, program, multiplication_batch);
        context.agree_public_bytes("registered-financial-construction-before-lock", public_binding);
        // Heavy preflight is complete. The exact direct head used by the
        // supervisor recheck is also consumed by the registered selection;
        // there is no metadata-only gap between recheck and LOCK.
        auto before_lock = AcceptedFinancialHead::acquire_fresh(context, service);
        need(before_lock.binding().identity == binding.admitted_head);
        registered_driver::RegisteredConstructionAuthorityBridge::
            recheck_before_lock(driver_authority,
            attempt_supervisor::RegisteredProposalBridge::direct_head(
                before_lock));
        RegisteredSelectionConstructionBridge::consume_for_lock(
            selection, context, std::move(before_lock));
        context.report_public_phase("registered-financial-durable-lock-started");
        auto locked = std::unique_ptr<history::LockedAttempt>(
            new history::LockedAttempt(history::lock_attempt(context, journal, binding)));
        add(public_binding, locked->binding_identity());
        context.agree_public_bytes("registered-financial-construction-before-owner-input", public_binding);
        // Close the post-LOCK stale-head window, then mint the durable-lock
        // capability only from this exact LockedAttempt and burn the fresh
        // supervisor authority at the owner-intake claim itself.
        auto after_lock = AcceptedFinancialHead::acquire_fresh(context, service);
        need(after_lock.binding().identity == binding.admitted_head);
        auto durable_lock =
            attempt_supervisor::RegisteredProposalBridge::durable_lock(
                proposal, *locked, jobs);
        auto authorized =
            registered_driver::RegisteredConstructionAuthorityBridge::
                after_durable_lock(driver_authority,
            attempt_supervisor::RegisteredProposalBridge::direct_head(after_lock),
            std::move(durable_lock));
        need(authorized != nullptr);
        registered_driver::RegisteredConstructionAuthorityBridge::
            claim_owner_intake(*authorized, context, *locked, binding);
        auto& capture =
            registered_driver::RegisteredConstructionAuthorityBridge::
                capture_session(*authorized);
        ActiveOwnerInputServer receiver(context, owner_port);
        registered_driver::RegisteredCaptureConstructionBridge::
            listeners_ready(capture);
        context.report_public_phase("owner-listeners-ready");
        auto cohort = receiver.receive_cohort(jobs, capture);
        std::vector<OwnerTraceInput> inputs;
        inputs.reserve(cohort.size());
        for (size_t owner = 0; owner < jobs.size(); ++owner) {
            inputs.push_back({static_cast<int>(owner),
                              std::move(cohort[owner])});
        }
        context.report_public_phase("hidden-owner-cohort-input-received");
        context.report_public_phase("authenticated-financial-trace-started");
        auto result = execute_trace(context, program, std::move(inputs), multiplication_batch);
        context.report_public_phase("authenticated-financial-trace-complete");
        need(result.model_variables == metadata.instances + metadata.witnesses &&
             result.wires.size() == result.model_variables &&
             result.private_checks.size() == program.expected_private_checks);
        // Bind the genuine raw trace assertions exactly once before any
        // registered-context residual is appended. Sites 12/13/14 capture the
        // complete authenticated reduction; site 16 later retains both the raw
        // assertions and this equivalent aggregate residual.
        const auto raw_trace_checks_hold = trace_private_checks_hold(
            context, result.private_checks, program.expected_private_checks);
        result.private_checks.push_back(
            context.public_constant(Fr(1)) - raw_trace_checks_hold);
        for (size_t byte = 0; byte < expected_context.size(); ++byte)
            result.private_checks.push_back(byte_value(context, result.wires, 8 + byte) -
                                            context.public_constant(Fr(expected_context[byte])));
        std::vector<AuthScalar> prefix;
        for (const auto& linear : selected.prefix_recipe->outputs()) {
            auto value = context.public_constant(Fr(0));
            for (const auto& term : linear) value += result.wires[term.column] * term.coefficient;
            prefix.push_back(std::move(value));
        }
        need(prefix.size() == 2);
        const auto identity = history::hex(history::digest(public_binding));
        auto storage = std::make_shared<const Storage>(model, std::move(result.wires), std::move(result.private_checks),
            std::move(prefix), std::move(tail), std::move(locked),
            std::move(authorized), owner_effects_recipe, owner_port, jobs);
        return FinancialConstruction(context, std::move(storage), binding, identity);
    } catch (...) { context.poison(); refuse(); }
}
} // namespace kpi::mpc::financial
