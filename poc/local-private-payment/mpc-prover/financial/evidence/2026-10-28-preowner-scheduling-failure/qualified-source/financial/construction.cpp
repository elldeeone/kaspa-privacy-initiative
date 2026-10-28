#include "construction.hpp"
#include "../trace/prefix_recipe.hpp"
#include "../trace/sealed_trace.hpp"
#include <algorithm>
#include <set>

namespace kpi::mpc::financial {
namespace {
using Bytes = std::vector<unsigned char>;
constexpr size_t MODEL_VARIABLES = 12949821;
constexpr std::array<size_t, 3> NF_BYTE_OFFSETS{404, 500, 596};
// This source family has one reviewed physical layout and actual setup. A new
// relation/profile needs its own explicit selection and source review.
constexpr const char* MODEL = "f3ca3c18f17ed8175fa420364e9aa2824a12af4320ca1dc00ba2508f60ba28ff";
constexpr const char* SOURCE = "3ff31adfc6f2666ac53606ecf60336366d850951fda22a38b7445262f380d829";
constexpr const char* LAYOUT = "9a3ee5f5eb98384273e2b608f71a60f89c49e6fc9c1029586f8f201b84617e1e";
constexpr const char* RECIPE = "ef6279fa5633c77230a8a8b8ae9b70a58770a30e6c6f5e0bcf97edba0d0e0edb";
constexpr const char* TRACE = "4c3dec7c553f66e45775bff2c950417060980cf443ab83a2d198587fc604808e";
constexpr const char* TRACE_CONTAINER = "0edbd4f22706d54a56ec5a670a2cf89f7075dd286130b3f64dbc73767cdef95c";
constexpr const char* LAYOUT_CONTAINER = "b69d19619ebe92e5512ad268b6ba299f2e04255d504aeac1a2d3cca55ef68942";
constexpr const char* NATIVE_PARAMETERS = "3f9f2f294c8203c8fc99ba66e1a78e769a1eecc4ecc5cf8f8b631eea28138751";
constexpr const char* NATIVE_TAIL = "4081fc4efb08131bba7b64c38cfe002a3456c8a8a93394622ee9085e3706435d";

[[noreturn]] void refuse() { throw std::runtime_error("financial-construction-refused"); }
void need(bool value) { if (!value) refuse(); }
void add(Bytes& out, std::span<const unsigned char> value) { out.insert(out.end(), value.begin(), value.end()); }
void text(Bytes& out, const std::string& value) { out.insert(out.end(), value.begin(), value.end()); }
void integer(Bytes& out, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) out.push_back(static_cast<unsigned char>(value >> (8 * i)));
}
void selected_model(const packed::PackedModel& model) {
    const auto& m = model.metadata();
    need(model.identity() == MODEL && m.source_sha256 == SOURCE &&
        m.prefix_mode == packed::PrefixMode::SecretDerivedRecipe && m.public_prefix.empty() &&
        m.instances == 3 && m.witnesses + m.instances == MODEL_VARIABLES &&
        m.constraints == 13093029 && m.domain == 16777216 && m.derived_output_count == 2 &&
        m.prefix_layout_sha256 == LAYOUT && m.prefix_recipe_sha256 == RECIPE);
    model.check_backing_unchanged();
}

void contract_family(const std::array<OwnerInputContract, 3>& jobs) {
    std::set<std::string> owner_certificates;
    for (size_t owner = 0; owner < jobs.size(); ++owner) {
        const auto& job = jobs[owner];
        (void) canonical_owner_contract(job);
        need(job.owner_id == static_cast<int>(owner) &&
            job.input_count == FinancialConstruction::OWNER_INPUT_COUNT &&
            !job.trace_identity.empty() && !job.layout_identity.empty() &&
            job.run_nonce == jobs[0].run_nonce && job.cohort_identity == jobs[0].cohort_identity &&
            job.server_certificate_sha256 == jobs[0].server_certificate_sha256 &&
            owner_certificates.insert(job.owner_certificate_sha256).second);
    }
}

std::array<unsigned char, 276> context_bytes(const history::EpochKey& key,
                                          const history::AttemptBinding& binding) {
    need(std::equal(binding.old_state.begin(), binding.old_state.begin() + 8, "KPBAST01"));
    need(std::equal(key.domain.begin(), key.domain.end(), binding.old_state.begin() + 8));
    Bytes out;
    for (const auto* value : {&key.chain, &key.pool, &key.profile, &key.domain, &key.service}) add(out, *value);
    add(out, binding.old_point);
    add(out, std::span(binding.old_state).subspan(40, 32));  // CM root.
    add(out, std::span(binding.old_state).subspan(76, 32));  // NF root.
    add(out, std::span(binding.old_state).subspan(72, 4));
    add(out, std::span(binding.old_state).subspan(108, 4));
    integer(out, binding.old_reserve);
    need(out.size() == 276);
    std::array<unsigned char, 276> result{};
    std::copy(out.begin(), out.end(), result.begin()); return result;
}

AuthScalar byte_value(MascotContext& context, std::span<const AuthScalar> assignment, size_t byte) {
    auto result = context.public_constant(Fr(0));
    for (size_t bit = 0; bit < 8; ++bit)
        result += assignment[FinancialConstruction::CORE_FIRST_BIT_COLUMN + 8 * byte + bit] * Fr(1 << bit);
    return result;
}
}  // namespace

struct FinancialConstruction::Storage {
    const packed::PackedModel model;
    const std::vector<AuthScalar> assignment, checks, prefix;
    const Bytes tail;
    // Ownership is shared only through this immutable storage. The pointed-to
    // history capability alone advances its private one-use state.
    const std::unique_ptr<history::LockedAttempt> locked;
    Storage(const packed::PackedModel& m, std::vector<AuthScalar> a, std::vector<AuthScalar> c,
            std::vector<AuthScalar> p, Bytes t, std::unique_ptr<history::LockedAttempt> l)
        : model(m), assignment(std::move(a)), checks(std::move(c)), prefix(std::move(p)),
          tail(std::move(t)), locked(std::move(l)) {}
};

FinancialConstruction::FinancialConstruction(MascotContext& context, std::shared_ptr<const Storage> storage,
    history::AttemptBinding attempt, std::string identity)
    : storage_(std::move(storage)), context_(&context), generation_(context.generation()),
      epoch_(context.failure_epoch()), construction_check_counter_(context.check_counter()),
      attempt_(std::move(attempt)), binding_identity_(std::move(identity)) {}
FinancialConstruction::~FinancialConstruction() = default;

history::Digest FinancialConstruction::input_map_identity(const packed::PackedModel& model) {
    selected_model(model);
    Bytes bytes; text(bytes, "KPB_FINANCIAL_FIXED_CORE_MAP_V1\n");
    for (const auto& identity : {model.identity(), model.metadata().source_sha256,
         model.metadata().matrix_fingerprint, model.metadata().prefix_layout_sha256,
         model.metadata().prefix_recipe_sha256}) add(bytes, history::unhex(identity));
    for (auto value : {uint64_t(CORE_FIRST_BIT_COLUMN), uint64_t(CORE_BIT_COUNT), uint64_t(CORE_BYTES),
                      uint64_t(CONTEXT_CHECKS), uint64_t(OWNER_INPUT_COUNT)}) integer(bytes, value);
    for (auto value : NF_BYTE_OFFSETS) integer(bytes, value);
    return history::digest(bytes);
}

history::Digest FinancialConstruction::owner_contracts_identity(const std::array<OwnerInputContract, 3>& jobs) {
    contract_family(jobs);
    Bytes bytes; text(bytes, "KPB_FINANCIAL_OWNER_CONTRACT_SET_V1\n");
    for (const auto& job : jobs) {
        const auto canonical = canonical_owner_contract(job);
        integer(bytes, canonical.size()); text(bytes, canonical);
    }
    return history::digest(bytes);
}

history::Digest FinancialConstruction::native_parameters_identity() { return history::unhex(NATIVE_PARAMETERS); }

FinancialConstruction FinancialConstruction::construct(MascotContext& context,
    const packed::PackedModel& model, const std::filesystem::path& trace_path, const TraceBinding& selected,
    const std::array<OwnerInputContract, 3>& jobs, std::span<const unsigned char> native_tail,
    history::EpochJournal& journal,
    const history::AttemptBinding& binding, int owner_port, size_t multiplication_batch) {
    try {
        context.require_healthy(); selected_model(model); contract_family(jobs);
        const auto& m = model.metadata();
        Bytes admitted_tail(native_tail.begin(), native_tail.end());
        need(owner_port >= 1024 && owner_port <= 65533 && multiplication_batch &&
            selected.model_sha256 == model.identity() &&
            selected.source_sha256 == m.source_sha256 && selected.layout_sha256 == m.prefix_layout_sha256 &&
            selected.trace_sha256 == TRACE && selected.container_sha256 == TRACE_CONTAINER &&
            selected.canonical_bytes == 2576450912ULL &&
            selected.layout_container_sha256 == LAYOUT_CONTAINER && selected.layout_canonical_bytes == 62346077 &&
            selected.model_variables == MODEL_VARIABLES && selected.instances == 3 &&
            selected.owner_roles == std::vector<int>({0, 1, 2}) && selected.prefix_recipe &&
            selected.prefix_recipe->identity() == m.prefix_recipe_sha256 &&
            history::hex(binding.model) == model.identity() && history::hex(binding.source) == m.source_sha256 &&
            history::hex(binding.matrix) == m.matrix_fingerprint &&
            history::hex(binding.trace) == selected.trace_sha256 && history::hex(binding.layout) == selected.layout_sha256 &&
            history::hex(binding.prefix_recipe) == m.prefix_recipe_sha256 &&
            binding.input_map == input_map_identity(model) && binding.owner_contracts == owner_contracts_identity(jobs) &&
            binding.native_parameters == native_parameters_identity() &&
            binding.immutable_tail == history::unhex(NATIVE_TAIL) &&
            history::digest(admitted_tail) == binding.immutable_tail &&
            history::reserve_spk(binding.old_state, admitted_tail) == binding.old_spk);
        for (const auto& job : jobs)
            need(job.model_identity == model.identity() && job.source_identity == m.source_sha256 &&
                job.proving_key_identity == m.pk_sha256 && job.verifying_key_identity == m.vk_sha256 &&
                job.trace_identity == selected.trace_sha256 && job.layout_identity == selected.layout_sha256 &&
                job.run_nonce == history::hex(binding.attempt) && job.cohort_identity == history::hex(binding.cohort));
        // Inspection is internal: no caller Boolean or chosen NF columns can
        // stand in for this complete source/model/layout/recipe verification.
        context.report_public_phase("financial-trace-full-preflight-started");
        const auto program = inspect_trace(trace_path, selected);
        context.report_public_phase("financial-trace-full-preflight-complete");
        need(program.owner_layout.size() == 3 && program.header.variables == 31326437 &&
            program.header.operations == 15474590 && program.expected_private_checks == 33896);
        for (const auto& owner : program.owner_layout) need(owner.columns.size() == OWNER_INPUT_COUNT);
        const auto prior = journal.snapshot();
        const auto expected_context = context_bytes(prior.key, binding);
        for (const auto& job : jobs)
            for (size_t party = 0; party < 3; ++party)
                need(job.server_certificate_sha256[party] == history::hex(prior.key.server_certificates[party]));
        context.report_public_phase("financial-durable-lock-started");
        auto locked = std::unique_ptr<history::LockedAttempt>(
            new history::LockedAttempt(history::lock_attempt(context, journal, binding)));
        Bytes public_binding; text(public_binding, "KPB_FINANCIAL_CONSTRUCTION_V1\n");
        add(public_binding, locked->binding_identity()); add(public_binding, binding.input_map);
        add(public_binding, history::unhex(program.artifact->container_sha256()));
        add(public_binding, history::unhex(program.artifact->decoder_identity()));
        add(public_binding, history::unhex(model.query_transport_identity()));
        integer(public_binding, program.expected_private_checks); integer(public_binding, CONTEXT_CHECKS);
        integer(public_binding, multiplication_batch);
        context.agree_public_bytes("financial-construction-before-owner-input", public_binding);
        agree_trace(context, program, multiplication_batch);
        locked->claim_owner_intake(context, binding);
        // No listening socket or owner receiver exists before durable LOCK
        // and its exact one-use claim.
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
        need(result.model_variables == MODEL_VARIABLES && result.wires.size() == MODEL_VARIABLES &&
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
        auto storage = std::make_shared<const Storage>(model, std::move(result.wires),
            std::move(result.private_checks), std::move(prefix), std::move(admitted_tail), std::move(locked));
        return FinancialConstruction(context, std::move(storage), binding, identity);
    } catch (...) { context.poison(); refuse(); }
}

const packed::PackedModel& FinancialConstruction::model() const { return storage_->model; }
std::span<const AuthScalar> FinancialConstruction::assignment() const { return storage_->assignment; }
std::span<const AuthScalar> FinancialConstruction::trace_checks() const { return storage_->checks; }
std::span<const AuthScalar> FinancialConstruction::promised_prefix() const { return storage_->prefix; }
std::span<const AuthScalar> FinancialConstruction::core_bits() const {
    return std::span(storage_->assignment).subspan(CORE_FIRST_BIT_COLUMN, CORE_BIT_COUNT);
}
std::span<const AuthScalar> FinancialConstruction::nullifier_bits(size_t sorted_input_index) const {
    need(sorted_input_index < NF_BYTE_OFFSETS.size());
    return core_bits().subspan(NF_BYTE_OFFSETS[sorted_input_index] * 8, 256);
}
std::span<const unsigned char> FinancialConstruction::native_tail() const { return storage_->tail; }
history::LockedAttempt& FinancialConstruction::locked_attempt() const { return *storage_->locked; }
void FinancialConstruction::require_live(MascotContext& context, const history::AttemptBinding& binding) const {
    try {
        context.require_healthy();
        need(context_ == &context && generation_ == context.generation() && epoch_ == context.failure_epoch() &&
             construction_check_counter_ <= context.check_counter() && attempt_ == binding);
        storage_->model.check_backing_unchanged();
    } catch (...) { context.poison(); refuse(); }
}
}  // namespace kpi::mpc::financial
