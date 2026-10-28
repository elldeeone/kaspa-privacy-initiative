#include "construction_storage.hpp"
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
    const history::AttemptBinding& binding, int owner_port, size_t multiplication_batch) {
    try {
        selection.require_live(context);
        const auto& service = selection.service(); const auto& model = selection.model();
        const auto& program = selection.program(); const auto& selected = program.binding;
        const auto& metadata = model.metadata();
        need(owner_port >= 1024 && owner_port <= 65533 && multiplication_batch &&
             selection.attempt_binding(context, jobs, binding.attempt, binding.cohort) == binding);
        for (size_t owner = 0; owner < 3; ++owner) {
            const auto& job = jobs[owner]; (void)canonical_owner_contract(job);
            need(job.owner_id == static_cast<int>(owner) &&
                 job.input_count == program.owner_layout.at(owner).columns.size() &&
                 job.model_identity == model.identity() && job.source_identity == metadata.source_sha256 &&
                 job.proving_key_identity == metadata.pk_sha256 && job.verifying_key_identity == metadata.vk_sha256 &&
                 job.trace_identity == selected.trace_sha256 && job.layout_identity == selected.layout_sha256 &&
                 job.run_nonce == history::hex(binding.attempt) && job.cohort_identity == history::hex(binding.cohort));
            for (size_t party = 0; party < 3; ++party)
                need(job.server_certificate_sha256[party] == history::hex(service.key().server_certificates[party]));
        }
        const auto expected_context = context_bytes(service.key(), binding);
        Bytes tail(selection.native_tail().begin(), selection.native_tail().end());
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
        integer(public_binding, program.expected_private_checks); integer(public_binding, CONTEXT_CHECKS);
        integer(public_binding, multiplication_batch);
        agree_trace(context, program, multiplication_batch);
        context.agree_public_bytes("registered-financial-construction-before-lock", public_binding);
        // Source compilation, complete admission and full owner-layout
        // agreement are finished. The last private transition performs fresh
        // native/history verification, compares the SAME immutable head, and
        // consumes selection once. Only its tiny agreement and LOCK follow.
        selection.consume_for_lock(context);
        context.report_public_phase("registered-financial-durable-lock-started");
        auto locked = std::unique_ptr<history::LockedAttempt>(
            new history::LockedAttempt(history::lock_attempt(context, journal, binding)));
        add(public_binding, locked->binding_identity());
        context.agree_public_bytes("registered-financial-construction-before-owner-input", public_binding);
        locked->claim_owner_intake(context, binding);
        ActiveOwnerInputServer receiver(context, owner_port);
        context.report_public_phase("owner-listeners-ready");
        std::vector<OwnerTraceInput> inputs;
        constexpr std::array<const char*, 3> phases{
            "first-owner-input-received", "second-owner-input-received", "third-owner-input-received"};
        for (size_t owner = 0; owner < jobs.size(); ++owner) {
            inputs.push_back({static_cast<int>(owner), receiver.receive(jobs[owner])});
            context.report_public_phase(phases[owner]);
        }
        context.report_public_phase("authenticated-financial-trace-started");
        auto result = execute_trace(context, program, std::move(inputs), multiplication_batch);
        context.report_public_phase("authenticated-financial-trace-complete");
        need(result.model_variables == metadata.instances + metadata.witnesses &&
             result.wires.size() == result.model_variables &&
             result.private_checks.size() == program.expected_private_checks);
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
            std::move(prefix), std::move(tail), std::move(locked));
        return FinancialConstruction(context, std::move(storage), binding, identity);
    } catch (...) { context.poison(); refuse(); }
}
} // namespace kpi::mpc::financial
