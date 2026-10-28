#include "registered_selection.hpp"
#include "accepted_head.hpp"
#include "fixed_public_run.hpp"
#include "construction.hpp"
#include "financial_assignment.hpp"
#include "../trace/prefix_recipe.hpp"
#include "../trace/sealed_trace.hpp"
#include <algorithm>
#include <charconv>
#include <fstream>
#include <sstream>

namespace kpi::mpc::financial {
namespace {
using Bytes = std::vector<unsigned char>;
[[noreturn]] void refuse() { throw history::Refused(); }
void need(bool value) { if (!value) refuse(); }
void add(Bytes& out, std::span<const unsigned char> value) { out.insert(out.end(), value.begin(), value.end()); }
void integer(Bytes& out, uint64_t value) { for (unsigned i = 0; i < 8; ++i) out.push_back(value >> (8 * i)); }
Bytes tag(const std::string& value) { return Bytes(value.begin(), value.end()); }
struct Container { std::string raw_sha, encoded_sha; size_t raw_bytes, encoded_bytes; };
struct Descriptor {
    std::string model, source, matrix, history_sha, recipe_sha;
    size_t variables, instances, rows, domain, recipe_bytes;
    Container trace, layout;
};
size_t natural(std::istream& in) {
    std::string s; need(bool(in >> s) && !s.empty() && (s.size() == 1 || s[0] != '0'));
    size_t n{}; const auto r = std::from_chars(s.data(), s.data() + s.size(), n);
    need(r.ec == std::errc{} && r.ptr == s.data() + s.size()); return n;
}
std::string hash(std::istream& in) {
    std::string s; need(bool(in >> s)); (void)history::unhex(s); return s;
}
void token(std::istream& in, const char* expected) {
    std::string s; need(bool(in >> s) && s == expected);
}
Descriptor parse_descriptor(const Bytes& data) {
    std::istringstream in(std::string(data.begin(), data.end()));
    Descriptor d{}; token(in, "KPB_REGISTERED_EXPORT_V1");
    token(in, "MODEL"); d.model = hash(in); token(in, "SOURCE"); d.source = hash(in);
    token(in, "MATRIX"); d.matrix = hash(in); token(in, "VARIABLES"); d.variables = natural(in);
    token(in, "INSTANCES"); d.instances = natural(in); token(in, "ROWS"); d.rows = natural(in);
    token(in, "DOMAIN"); d.domain = natural(in); token(in, "HISTORY"); d.history_sha = hash(in);
    const auto container = [&](const char* name) {
        token(in, name); Container c; c.raw_sha = hash(in); c.raw_bytes = natural(in);
        c.encoded_sha = hash(in); c.encoded_bytes = natural(in); return c;
    };
    d.trace = container("TRACE"); d.layout = container("LAYOUT");
    token(in, "RECIPE"); d.recipe_sha = hash(in); d.recipe_bytes = natural(in); token(in, "END");
    std::string extra; need(!(in >> extra)); return d;
}
Bytes read_tail(const RegisteredService& service) {
    const auto owned = service.native_tail(); Bytes result(owned.begin(), owned.end());
    need(history::digest(result) == service.native_tail_identity()); return result;
}
history::Digest compiler_identity(const RegisteredService& service) {
    // service.identity authenticates all fixed executable, consumed source
    // closure, specification, namespace/runtime and store/roster bytes.
    auto bytes = tag("KPB_REGISTERED_SOURCE_COMPILER_V1\n"); add(bytes, service.identity());
    const auto& compiler = service.exporter();
    for (const auto& pin : {compiler.executable_sha256, compiler.source_closure_sha256,
         compiler.specification_sha256, compiler.interpreter_sha256, compiler.namespace_tool_sha256}) add(bytes, pin);
    return history::digest(bytes);
}
} // namespace

// The only friend allowed to consume an AcceptedFinancialHead is this closed
// factory implementation. No header declares a public consumption function.
class RegisteredSelectionAccess {
public:
    static void consume(MascotContext& c, AcceptedFinancialHead& head,
                        const RegisteredService& service, const history::Digest& history_sha) {
        head.consume_for_selection(c, service.identity(), history_sha);
    }
};

struct RegisteredFinancialSelection::Storage {
    const RegisteredService service;
    const packed::PackedModel model;
    const AcceptedHeadBinding head;
    const TraceProgram program;
    const Bytes tail;
    const history::Digest compiler;
    const std::string identity;
    Storage(const RegisteredService& s, const packed::PackedModel& m, AcceptedHeadBinding h,
            TraceProgram p, Bytes t, history::Digest c, std::string i)
        : service(s), model(m), head(std::move(h)), program(std::move(p)), tail(std::move(t)), compiler(c), identity(std::move(i)) {}
};
RegisteredFinancialSelection::RegisteredFinancialSelection(MascotContext& c, std::shared_ptr<const Storage> s)
    : storage_(std::move(s)), context_(&c), generation_(c.generation()), epoch_(c.failure_epoch()),
      checked_counter_(c.check_counter()) {}
RegisteredFinancialSelection::~RegisteredFinancialSelection() = default;

RegisteredFinancialSelection RegisteredFinancialSelection::admit(MascotContext& context,
    const RegisteredService& service, AcceptedFinancialHead&& accepted, const packed::PackedModel& model) {
    try {
        service.require_live(context); model.check_backing_unchanged();
        const auto& metadata = model.metadata();
        const auto head = accepted.binding(); const auto public_history = accepted.public_history_bytes();
        need(service.model_identity() == history::unhex(model.identity()) && head.key == service.key() &&
             head.service_identity == service.identity() && head.registration == service.registration() &&
             head.public_history == history::digest(public_history) &&
             head.native_parameters == service.native_parameters_identity() &&
             head.immutable_tail == service.native_tail_identity() &&
             metadata.prefix_mode == packed::PrefixMode::SecretDerivedRecipe && metadata.public_prefix.empty() &&
             metadata.instances == 3 && metadata.witnesses == 12949818 && metadata.constraints == 13093029 &&
             metadata.domain == 16777216 && metadata.matrix_fingerprint ==
                 "c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab");
        RegisteredSelectionAccess::consume(context, accepted, service, head.public_history);
        // Keep peak PUBLIC setup synthesis bounded to one role at a time.
        // Each honest role still directly executes and checks every row itself.
        std::unique_ptr<FixedPublicResult> output;
        for (unsigned role = 0; role < 3; ++role) {
            if (service.party_id() == role) {
                context.report_public_phase("registered-public-compiler-started");
                output = std::make_unique<FixedPublicResult>(
                    run_fixed_public_program(service, service.exporter(), public_history));
                context.report_public_phase("registered-public-compiler-complete");
            }
            auto slot = tag("KPB_REGISTERED_PUBLIC_COMPILER_SLOT_V1\n"); integer(slot, role);
            context.agree_public_bytes("registered-public-compiler-slot", slot);
        }
        need(bool(output) && output->input_identity == head.public_history);
        const auto descriptor = parse_descriptor(read_fixed_public_result(service, *output, "REGISTERED-EXPORT.txt"));
        need(descriptor.model == model.identity() && descriptor.source == metadata.source_sha256 &&
             descriptor.matrix == metadata.matrix_fingerprint && descriptor.history_sha == history::hex(head.public_history) &&
             descriptor.instances == metadata.instances && descriptor.variables == metadata.instances + metadata.witnesses &&
             descriptor.rows == metadata.constraints && descriptor.domain == metadata.domain &&
             descriptor.recipe_sha == metadata.prefix_recipe_sha256 && descriptor.layout.raw_sha == metadata.prefix_layout_sha256);
        const auto trace_path = check_fixed_public_result_path(service, *output, "trace.txt.gz");
        const auto layout_path = check_fixed_public_result_path(service, *output, "layout.txt.gz");
        const auto recipe_path = check_fixed_public_result_path(service, *output, "PREFIX-RECIPE.bin");
        need(std::filesystem::file_size(trace_path) == descriptor.trace.encoded_bytes &&
             std::filesystem::file_size(layout_path) == descriptor.layout.encoded_bytes &&
             std::filesystem::file_size(recipe_path) == descriptor.recipe_bytes);
        const auto recipe = PrefixRecipe::load(recipe_path, descriptor.recipe_sha, descriptor.variables, descriptor.instances);
        TraceBinding selected{descriptor.trace.raw_sha, descriptor.source, descriptor.model, descriptor.layout.raw_sha,
            layout_path, {0,1,2}, descriptor.variables, descriptor.instances, descriptor.trace.encoded_sha,
            descriptor.trace.raw_bytes, descriptor.layout.encoded_sha, descriptor.layout.raw_bytes, recipe};
        auto program = inspect_trace(trace_path, selected);
        need(program.owner_layout.size() == 3 && program.header.model_variables == descriptor.variables);
        for (size_t owner = 0; owner < 3; ++owner)
            need(program.owner_layout[owner].owner_role == static_cast<int>(owner) &&
                 program.owner_layout[owner].columns.size() == FinancialConstruction::OWNER_INPUT_COUNT);
        auto tail = read_tail(service); need(history::reserve_spk(head.state, tail) == head.script_public_key);
        const auto compiler = compiler_identity(service);
        auto binding = tag("KPB_REGISTERED_FINANCIAL_SELECTION_V1\n");
        for (const auto& value : {service.identity(), head.identity, head.public_history, compiler,
             history::unhex(model.identity()), history::unhex(program.artifact->canonical_sha256()),
             history::unhex(program.artifact->container_sha256()), history::unhex(program.artifact->decoder_identity()),
             history::unhex(model.query_transport_identity())}) add(binding, value);
        integer(binding, program.header.variables); integer(binding, program.header.operations);
        integer(binding, program.expected_private_checks);
        service.require_live(context); model.check_backing_unchanged();
        context.agree_public_bytes("registered-complete-head-program-selection", binding);
        const auto identity = history::hex(history::digest(binding));
        return RegisteredFinancialSelection(context, std::make_shared<const Storage>(service, model, head,
            std::move(program), std::move(tail), compiler, identity));
    } catch (...) { context.poison(); refuse(); }
}
void RegisteredFinancialSelection::require_live(MascotContext& c) const {
    try {
        storage_->service.require_live(c); storage_->model.check_backing_unchanged();
        need(!consumed_ && context_ == &c && generation_ == c.generation() && epoch_ == c.failure_epoch() &&
             c.check_counter() >= checked_counter_);
    } catch (...) { c.poison(); refuse(); }
}
void RegisteredFinancialSelection::consume_for_lock(MascotContext& c) {
    require_live(c);
    auto fresh = AcceptedFinancialHead::acquire_fresh(c, storage_->service);
    need(fresh.binding().identity == storage_->head.identity &&
         fresh.binding().public_history == storage_->head.public_history &&
         fresh.binding().context == storage_->head.context);
    RegisteredSelectionAccess::consume(c, fresh, storage_->service, storage_->head.public_history);
    c.require_healthy();
    need(!consumed_ && context_ == &c && generation_ == c.generation() && epoch_ == c.failure_epoch() &&
         c.check_counter() >= checked_counter_);
    consumed_ = true;
    c.agree_public_bytes("registered-financial-head-refreshed-before-lock", storage_->head.identity);
}
const TraceProgram& RegisteredFinancialSelection::program() const { return storage_->program; }
const packed::PackedModel& RegisteredFinancialSelection::model() const { return storage_->model; }
const RegisteredService& RegisteredFinancialSelection::service() const { return storage_->service; }
std::span<const unsigned char> RegisteredFinancialSelection::native_tail() const { return storage_->tail; }
const std::string& RegisteredFinancialSelection::identity() const { return storage_->identity; }
const TraceBinding& RegisteredFinancialSelection::trace_binding() const { return storage_->program.binding; }
size_t RegisteredFinancialSelection::expected_trace_assertions() const { return storage_->program.expected_private_checks; }
std::array<size_t, 3> RegisteredFinancialSelection::owner_input_counts() const {
    const auto& layout = storage_->program.owner_layout;
    return {layout.at(0).columns.size(), layout.at(1).columns.size(), layout.at(2).columns.size()};
}
history::AttemptBinding RegisteredFinancialSelection::attempt_binding(MascotContext& c,
    const std::array<OwnerInputContract, 3>& jobs, const history::Digest& attempt, const history::Digest& cohort) const {
    require_live(c); const auto& head = storage_->head; const auto& metadata = storage_->model.metadata();
    history::AttemptBinding result{}; result.attempt = attempt; result.cohort = cohort;
    result.owner_contracts = FinancialConstruction::owner_contracts_identity(jobs);
    result.model = history::unhex(storage_->model.identity()); result.source = history::unhex(metadata.source_sha256);
    result.dependencies = storage_->compiler; result.matrix = history::unhex(metadata.matrix_fingerprint);
    result.trace = history::unhex(trace_binding().trace_sha256); result.layout = history::unhex(metadata.prefix_layout_sha256);
    result.input_map = FinancialConstruction::input_map_identity(storage_->model);
    result.prefix_recipe = history::unhex(metadata.prefix_recipe_sha256);
    result.validation_policy = FinancialValidatedAssignment::policy_identity(); result.admitted_head = head.identity;
    result.old_point = head.point; result.old_state = head.state; result.old_reserve = head.reserve_sompi;
    result.old_spk = head.script_public_key; result.immutable_tail = head.immutable_tail;
    result.native_parameters = head.native_parameters; return result;
}
} // namespace kpi::mpc::financial
