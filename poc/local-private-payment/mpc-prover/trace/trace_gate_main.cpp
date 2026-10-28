// Public abc SHA-256 fixture on the actual owner-input/trace/Groth16 route.
// The expected public prefix is deliberately known. This executable has no
// financial derived-prefix or durable-history release policy.
#include "trace_witness.hpp"
#include "../batched_assignment.hpp"
#include "../auth_groth16.hpp"
#include "../owner_inputs_active.hpp"
#include <cerrno>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string_view>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
using namespace kpi::mpc;
std::filesystem::path stage_path;
const char* public_phase = "preflight";

void stage(const char* phase, const char* status = "running") {
    public_phase = phase;
    if (stage_path.empty()) return;
    std::ofstream output(stage_path);
    output << "{\"schema\":\"kpi-mascot-public-stage/v1\",\"phase\":\"" << phase
           << "\",\"status\":\"" << status << "\"}\n";
    if (!output) throw std::runtime_error("trace-public-stage-persistence");
}

std::vector<unsigned char> public_bytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("trace-selected-public-file");
    return {std::istreambuf_iterator<char>(input), {}};
}

std::string hash_text(const std::string& text) {
    return sha256_hex({reinterpret_cast<const unsigned char*>(text.data()), text.size()});
}

int canonical_int(const std::string& value, int lower, int upper) {
    if (value.empty() || (value.size() > 1 && value.front() == '0') ||
        value.find_first_not_of("0123456789") != std::string::npos)
        throw std::invalid_argument("trace-integer-encoding");
    size_t consumed = 0;
    const auto result = std::stoi(value, &consumed);
    if (consumed != value.size() || result < lower || result > upper)
        throw std::invalid_argument("trace-integer-range");
    return result;
}

PublicModel selected_model(const std::filesystem::path& path, const std::string& expected) {
    auto model = load_public_model(path);
    // A new relation needs its own reviewed driver. This gate exercises the
    // exact actual public abc fixture, rather than accepting arbitrary models.
    if (model.model_identity != expected || model.num_instance != 3 ||
        model.num_private != 28539 || model.num_constraints != 28849 ||
        model.domain.n != 32768 || model.public_inputs.size() != 3 ||
        model.public_inputs[0] != Fr(1) ||
        model.public_inputs[1] != parse_fr("46703054521935740510813883890411141306") ||
        model.public_inputs[2] != parse_fr("230065500708363406770752671329774797744"))
        throw std::invalid_argument("trace-public-sha-model");
    return model;
}

TraceProgram selected_trace(const PublicModel& model, const std::filesystem::path& trace,
                            const std::string& trace_sha, const std::filesystem::path& layout,
                            const std::string& layout_sha) {
    return inspect_trace(trace, {trace_sha, model.source_identity, model.model_identity,
        layout_sha, layout, {0, 1}, model.num_instance + model.num_private, model.num_instance});
}

void require_owner_jobs(const PublicModel& model, const TraceProgram& trace,
                        const OwnerInputContract& first, const OwnerInputContract& second) {
    const std::array<const OwnerInputContract*, 2> jobs{&first, &second};
    if (trace.owner_layout.size() != jobs.size())
        throw std::invalid_argument("trace-owner-layout-arity");
    for (size_t i = 0; i < jobs.size(); ++i) {
        const auto& job = *jobs[i];
        if (job.model_identity != model.model_identity || job.source_identity != model.source_identity ||
            job.proving_key_identity != model.proving_key_identity ||
            job.verifying_key_identity != model.verifying_key_identity ||
            job.trace_identity != trace.binding.trace_sha256 ||
            job.layout_identity != trace.binding.layout_sha256 ||
            job.owner_id != trace.owner_layout[i].owner_role ||
            job.input_count != trace.owner_layout[i].columns.size())
            throw std::invalid_argument("trace-owner-job-map-or-identity");
    }
    if (first.run_nonce != second.run_nonce || first.cohort_identity != second.cohort_identity ||
        first.server_certificate_sha256 != second.server_certificate_sha256 ||
        first.owner_certificate_sha256 == second.owner_certificate_sha256)
        throw std::invalid_argument("trace-owner-cohort");
}

void verify_independently(const std::filesystem::path& verifier, const std::string& verifier_sha,
    const std::filesystem::path& model_path, const std::string& model_sha,
    const std::filesystem::path& proof_file) {
    if (sha256_hex(public_bytes(verifier)) != verifier_sha)
        throw std::runtime_error("trace-independent-verifier-identity");
    const auto child = fork();
    if (child == -1) throw std::runtime_error("trace-independent-verifier-launch");
    if (child == 0) {
        const auto sink = open("/dev/null", O_WRONLY);
        if (sink == -1 || dup2(sink, STDOUT_FILENO) == -1 || dup2(sink, STDERR_FILENO) == -1)
            _exit(126);
        close(sink);
        execl(verifier.c_str(), verifier.c_str(), "verify", model_path.c_str(), proof_file.c_str(),
            "46703054521935740510813883890411141306,230065500708363406770752671329774797744",
            model_sha.c_str(), nullptr);
        _exit(127);
    }
    int status = 0;
    while (waitpid(child, &status, 0) == -1)
        if (errno != EINTR) throw std::runtime_error("trace-independent-verifier-wait");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        throw std::runtime_error("trace-independent-Ark-rejection");
}

int serve(int argc, char** argv) {
    if (argc != 17) throw std::invalid_argument("trace-serve-arity");
    const int party = canonical_int(argv[2], 0, 2);
    const int network_port = canonical_int(argv[3], 1024, 65520);
    const int owner_port = canonical_int(argv[4], 1024, 65520);
    const std::filesystem::path model_path = std::filesystem::absolute(argv[5]);
    const auto model = selected_model(model_path, argv[6]);
    const auto trace = selected_trace(model, argv[7], argv[8], argv[9], argv[10]);
    const auto first = load_owner_contract(argv[11]), second = load_owner_contract(argv[12]);
    require_owner_jobs(model, trace, first, second);
    const auto verifier = std::filesystem::absolute(argv[13]);
    const std::string verifier_sha = argv[14], control = argv[16];
    if (sha256_hex(public_bytes(verifier)) != verifier_sha ||
        (control != "positive" && control != "invalid-assignment" && control != "tamper-mac"))
        throw std::invalid_argument("trace-verifier-or-control");
    // Reject bad public job bindings before expensive curve admission, while
    // still admitting every query before network setup or private intake.
    (void) admit_proving_key(model);
    const std::filesystem::path output = std::filesystem::absolute(argv[15]);
    if (mkdir(output.c_str(), 0700) != 0)
        throw std::runtime_error("trace-fresh-output-required");
    stage_path = output / "PUBLIC-STAGE.json";
    stage("preinput-admitted");
    Names names(party, 3, "127.0.0.1", network_port);
    stage("interparty-addresses-ready");
    CryptoPlayer player(names);
    stage("interparty-TLS-ready");
    MascotContext context(player, [](const char* phase) { stage(phase); });
    stage("three-party-context-ready");
    context.agree_public_bytes("public-sha-selected-model-before-input", model.encoded_model);
    agree_trace(context, trace);
    context.agree_public_bytes("public-sha-control-before-input", {
        reinterpret_cast<const unsigned char*>(control.data()), control.size()});
    ActiveOwnerInputServer owners(context, owner_port);
    stage("owner-listeners-ready");
    std::vector<OwnerTraceInput> inputs;
    inputs.push_back({first.owner_id, owners.receive(first)});
    stage("first-owner-input-received");
    inputs.push_back({second.owner_id, owners.receive(second)});
    stage("second-owner-input-received");
    auto execution = execute_trace(context, trace, std::move(inputs));
    stage("authenticated-SHA-trace-complete");
    if (control == "invalid-assignment") execution.wires.back() += context.public_constant(Fr(1));
    if (control == "tamper-mac" && party == 0)
        execution.wires.back().set_mac(execution.wires.back().get_mac() + Fr(1));
    BatchedValidationBinding binding{
        first.run_nonce, hash_text("KPI_PUBLIC_SHA3_TRACE_GATE_V1"),
        hash_text("PUBLIC_ABC_FIXTURE_NO_PAYMENT_HISTORY"), first.cohort_identity,
        model.model_identity, model.source_identity,
        public_matrix_identity(model), trace.binding.trace_sha256, trace.binding.layout_sha256,
        trace.binding.layout_sha256, hash_text("PUBLIC_ABC_SHA256_TWO_LIMBS_V1"),
        trace.expected_private_checks, output / "PUBLIC-VALIDATION.json"};
    auto validated = validate_batched_public_prefix(context, model, binding,
        execution.model_assignment(), execution.private_checks);
    stage("complete-assignment-and-trace-validated");
    const auto proof = prove_validated(context, std::move(validated), binding);
    stage("complete-proof-and-MAC-checks");
    const auto encoded = encode_native_proof(proof);
    const auto proof_file = output / "candidate-proof.bin";
    {
        std::ofstream stream(proof_file, std::ios::binary);
        stream.write(reinterpret_cast<const char*>(encoded.data()), encoded.size());
        if (!stream) throw std::runtime_error("trace-proof-persistence");
    }
    verify_independently(verifier, verifier_sha, model_path, model.model_identity, proof_file);
    stage("independent-Ark-verification-complete");
    {
        std::ofstream receipt(output / "PUBLIC-RESULT.json");
        receipt << "{\"schema\":\"kpi-mascot-trace-party/v1\",\"status\":\"VERIFIED\",\"party\":"
            << party << ",\"model_sha256\":\"" << model.model_identity << "\",\"trace_sha256\":\""
            << trace.binding.trace_sha256 << "\",\"proof_sha256\":\"" << sha256_hex(encoded)
            << "\",\"proof_hex\":\"" << proof_hex(proof)
            << "\",\"same_assignment_and_trace_checks\":true,\"field_and_group_MAC_checks\":true,"
               "\"independent_Ark_verified\":true,\"public_fixture_only\":true,\"payment_privacy_qualified\":false}\n";
        if (!receipt) throw std::runtime_error("trace-result-persistence");
    }
    stage("complete", "verified");
    return 0;
}
}  // namespace

int main(int argc, char** argv) {
    try {
        initialize_bn254_field();
        initialize_bn254_groups();
        if (argc == 8 && std::string(argv[1]) == "preflight") {
            const auto model = selected_model(argv[2], argv[3]);
            (void) admit_proving_key(model);
            (void) selected_trace(model, argv[4], argv[5], argv[6], argv[7]);
            std::cout << "PUBLIC_SHA_TRACE_PREFLIGHT_PASS\n";
            return 0;
        }
        if (argc > 1 && std::string(argv[1]) == "serve") return serve(argc, argv);
        throw std::invalid_argument("trace-command");
    } catch (const mac_fail&) {
        try { stage(public_phase, "mac-refused"); } catch (...) {}
    } catch (const std::exception& error) {
        const auto message = std::string_view(error.what());
        try { stage(public_phase, message == "invalid-extended-assignment" ||
            message == "invalid-batched-extended-assignment" ? "invalid-assignment-refused" : "refused"); }
        catch (...) {}
    } catch (...) {
        try { stage(public_phase, "refused"); } catch (...) {}
    }
    std::cerr << "KPI_MPC_TRACE_REFUSED\n";
    return 1;
}
