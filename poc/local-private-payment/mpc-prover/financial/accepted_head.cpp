#include "accepted_head.hpp"
#include "fixed_public_run.hpp"
#include <algorithm>
#include <openssl/rand.h>
#include <sstream>

namespace kpi::mpc::financial {
namespace {
using Bytes = std::vector<unsigned char>;
using Digest = history::Digest;
void need(bool value) { if (!value) throw history::Refused(); }
void add(Bytes& bytes, std::span<const unsigned char> value) {
    bytes.insert(bytes.end(), value.begin(), value.end());
}
void add(Bytes& bytes, const std::string& text) {
    add(bytes, std::span(reinterpret_cast<const unsigned char*>(text.data()), text.size()));
}
template<size_t N> std::array<unsigned char, N> take(std::span<const unsigned char> bytes, size_t& at) {
    need(at <= bytes.size() && N <= bytes.size() - at);
    std::array<unsigned char, N> result{}; std::copy_n(bytes.begin() + at, N, result.begin()); at += N;
    return result;
}
uint64_t number(std::span<const unsigned char> bytes) {
    need(bytes.size() <= 8); uint64_t value = 0;
    for (size_t i = 0; i < bytes.size(); ++i) value |= uint64_t(bytes[i]) << (8 * i);
    return value;
}
std::array<Digest, 7> tokens(const Bytes& bytes) {
    const std::string text(bytes.begin(), bytes.end());
    need(!text.empty() && text.back() == '\n' && text.find('\n') == text.size() - 1);
    std::istringstream input(text); std::string prefix;
    need(bool(input >> prefix) && prefix == "KPB_ACCEPTED_FINANCIAL_HEAD_V1");
    std::array<Digest, 7> result{};
    for (auto& value : result) {
        std::string token; need(bool(input >> token)); value = history::unhex(token);
        need(value != Digest{} && history::hex(value) == token);
    }
    std::string extra; need(!(input >> extra)); return result;
}
Digest request_identity(const RegisteredService& service, const Digest& nonce) {
    Bytes bytes; add(bytes, "KPB_REGISTERED_HEAD_REQUEST_V1\n"); add(bytes, nonce);
    add(bytes, service.registered_identity()); add(bytes, service.registration());
    add(bytes, history::digest(history::encode(service.key())));
    add(bytes, service.acquisition().specification_sha256); return history::digest(bytes);
}
Bytes request_bytes(const RegisteredService& service, const Digest& nonce, const Digest& request) {
    const std::string input = "{\"history_key_hex32\":\"" + history::hex(history::digest(history::encode(service.key()))) +
        "\",\"nonce_hex32\":\"" + history::hex(nonce) +
        "\",\"registered_history_sha256\":\"" + history::hex(service.registration()) +
        "\",\"request_sha256\":\"" + history::hex(request) +
        "\",\"schema\":\"kpb-registered-head-request/v1\",\"service_sha256\":\"" +
        history::hex(service.registered_identity()) + "\"}\n";
    return Bytes(input.begin(), input.end());
}
Digest head_identity(const std::array<Digest, 15>& values, const history::Point& genesis,
    std::span<const unsigned char> context, const history::ScriptPublicKey& script) {
    Bytes bytes; add(bytes, "KPB_REGISTERED_ACCEPTED_HEAD_V1\n");
    for (size_t i : {2U, 3U, 4U, 7U}) add(bytes, values[i]);
    add(bytes, genesis);
    for (size_t i : {8U, 9U, 10U, 11U, 12U}) add(bytes, values[i]);
    add(bytes, context); add(bytes, script); return history::digest(bytes);
}
AcceptedHeadBinding binding_from(const RegisteredService& service,
    const std::array<Digest, 15>& values, const history::Point& genesis,
    const std::array<unsigned char, 276>& context, const history::ScriptPublicKey& script) {
    const auto& key = service.key();
    const std::array<Digest, 5> expected{key.chain, key.pool, key.profile, key.domain, key.service};
    for (size_t i = 0; i < expected.size(); ++i)
        need(std::equal(expected[i].begin(), expected[i].end(), context.begin() + 32 * i));
    AcceptedHeadBinding binding{};
    binding.key = key; binding.service_identity = service.identity(); binding.registration = service.registration();
    binding.genesis_case = values[7]; binding.public_history = values[12];
    binding.identity = head_identity(values, genesis, context, script);
    binding.native_parameters = values[8]; binding.immutable_tail = values[9]; binding.genesis_point = genesis;
    std::copy_n(context.begin() + 160, 36, binding.point.begin());
    binding.context = context; binding.script_public_key = script;
    binding.reserve_sompi = number(std::span(context).subspan(268, 8));
    // Live native reserve is always output0. Terminal Exit has no head and
    // cannot be repackaged as a live zero-valued Context.
    need(binding.reserve_sompi >= 60000000 &&
         number(std::span(binding.point).subspan(32)) == 0 && number(std::span(genesis).subspan(32)) == 0 &&
         !std::all_of(binding.point.begin(), binding.point.begin() + 32, [](auto b) { return b == 0; }) &&
         !std::all_of(genesis.begin(), genesis.begin() + 32, [](auto b) { return b == 0; }));
    const uint64_t commitments = number(std::span(context).subspan(260, 4));
    const uint64_t nullifiers = number(std::span(context).subspan(264, 4));
    need(commitments >= 3 && commitments <= 65536 && nullifiers >= 1 && nullifiers <= 65536);
    const std::string tag = "KPBAST01"; std::copy(tag.begin(), tag.end(), binding.state.begin());
    std::copy_n(context.begin() + 96, 32, binding.state.begin() + 8);
    std::copy_n(context.begin() + 196, 32, binding.state.begin() + 40);
    std::copy_n(context.begin() + 260, 4, binding.state.begin() + 72);
    std::copy_n(context.begin() + 228, 32, binding.state.begin() + 76);
    std::copy_n(context.begin() + 264, 4, binding.state.begin() + 108);
    const auto tail = service.native_tail();
    need(history::reserve_spk(binding.state, tail) == script);
    return binding;
}
} // namespace

struct AcceptedFinancialHead::Storage {
    const AcceptedHeadBinding binding;
    const Bytes history_bytes;
    const Digest nonce, request, execution, acquisition, verification;
    Storage(AcceptedHeadBinding b, Bytes h, Digest n, Digest r, Digest e, Digest a, Digest v)
        : binding(std::move(b)), history_bytes(std::move(h)), nonce(n), request(r), execution(e), acquisition(a), verification(v) {}
};
AcceptedFinancialHead::AcceptedFinancialHead(MascotContext& ctx, std::shared_ptr<const Storage> storage)
    : storage_(std::move(storage)), context_(&ctx), generation_(ctx.generation()), epoch_(ctx.failure_epoch()) {}
AcceptedFinancialHead::~AcceptedFinancialHead() = default;

AcceptedFinancialHead AcceptedFinancialHead::acquire_fresh(MascotContext& ctx, const RegisteredService& service) {
    try {
        service.require_live(ctx); Digest nonce{};
        need(::RAND_bytes(nonce.data(), nonce.size()) == 1 && nonce != Digest{});
        const Digest request = request_identity(service, nonce);
        const auto input = request_bytes(service, nonce, request);
        const auto result = run_fixed_public_program(service, service.acquisition(), input);
        const auto line = tokens(result.stdout_bytes);
        const auto summary = read_fixed_public_result(service, result, "HEAD-SUMMARY.bin");
        const auto public_history = read_fixed_public_result(service, result, "PUBLIC-HISTORY.json");
        need(summary.size() == 837 && line[0] == nonce && line[1] == request &&
             line[2] == service.acquisition().specification_sha256 && line[3] == history::digest(input) &&
             line[3] == result.input_identity && line[4] == history::digest(summary) &&
             line[5] == history::digest(public_history));
        size_t at = 0; const auto tag = take<8>(summary, at);
        const std::string expected_tag = "KPBHAD01";
        need(std::equal(tag.begin(), tag.end(), expected_tag.begin()));
        std::array<Digest, 15> values{};
        for (auto& value : values) { value = take<32>(summary, at); need(value != Digest{}); }
        const auto genesis = take<36>(summary, at);
        const auto context = take<276>(summary, at);
        const auto script = take<37>(summary, at); need(at == summary.size());
        need(values[0] == line[2] && values[1] == line[3] && values[2] == service.registered_identity() &&
             values[3] == service.registration() && values[4] == history::digest(history::encode(service.key())) &&
             values[5] == nonce && values[6] == request && values[8] == service.native_parameters_identity() &&
             values[9] == service.native_tail_identity() && values[12] == line[5] && values[13] == line[6]);
        auto binding = binding_from(service, values, genesis, context, script);
        service.require_live(ctx);
        ctx.agree_public_bytes("registered-accepted-financial-head", binding.identity);
        return AcceptedFinancialHead(ctx, std::make_shared<const Storage>(std::move(binding), public_history,
            nonce, request, result.execution_identity, values[13], values[14]));
    } catch (...) { ctx.poison(); throw history::Refused(); }
}
void AcceptedFinancialHead::consume_for_selection(MascotContext& ctx, const Digest& service, const Digest& history_sha) {
    try {
        ctx.require_healthy(); need(!consumed_ && context_ == &ctx && generation_ == ctx.generation() &&
            epoch_ == ctx.failure_epoch() && service == storage_->binding.service_identity &&
            history_sha == storage_->binding.public_history && history::digest(storage_->history_bytes) == history_sha);
        consumed_ = true;
    } catch (...) { ctx.poison(); throw history::Refused(); }
}
const AcceptedHeadBinding& AcceptedFinancialHead::binding() const { return storage_->binding; }
const std::vector<unsigned char>& AcceptedFinancialHead::public_history_bytes() const { return storage_->history_bytes; }
} // namespace kpi::mpc::financial
