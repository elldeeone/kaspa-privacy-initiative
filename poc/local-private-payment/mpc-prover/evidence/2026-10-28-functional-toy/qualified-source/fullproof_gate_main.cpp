#include "auth_groth16.hpp"
#include "owner_inputs_active.hpp"
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string_view>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

namespace {
using namespace kpi::mpc;
std::filesystem::path public_stage_path;
const char* public_phase = "preflight";

void stage(const char* phase, const char* status = "running",
           const char* error_category = nullptr) {
    public_phase = phase;
    if (!public_stage_path.empty()) {
        std::ofstream stream(public_stage_path);
        stream << "{\"schema\":\"kpi-mascot-public-stage/v1\",\"phase\":\""
               << phase << "\",\"status\":\"" << status << "\"";
        if (error_category)
            stream << ",\"error_category\":\"" << error_category << "\"";
        stream << "}\n";
        if (!stream) throw std::runtime_error("typed public stage persistence");
    }
}

void require_digest(const std::string& value) {
    if (value.size() != 64 || value.find_first_not_of("0123456789abcdef") != std::string::npos)
        throw std::invalid_argument("expected digest format");
}

int canonical_int(const std::string& text, int lower, int upper) {
    if (text.empty() || (text.size() > 1 && text.front() == '0') ||
        text.find_first_not_of("0123456789") != std::string::npos)
        throw std::invalid_argument("integer format");
    size_t consumed = 0;
    const auto value = std::stoi(text, &consumed);
    if (consumed != text.size() || value < lower || value > upper)
        throw std::invalid_argument("integer range");
    return value;
}

std::vector<unsigned char> read_public_file(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) throw std::runtime_error("selected public file unavailable");
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(stream), {});
}

PublicModel selected_toy_model(const std::filesystem::path& path, const std::string& expected) {
    require_digest(expected);
    auto model = load_public_model(path);
    if (model.model_identity != expected || model.num_instance != 2 ||
        model.num_private != 3 || model.num_constraints != 2 || model.domain.n != 4 ||
        model.public_inputs.size() != 2 || model.public_inputs[0] != Fr(1) ||
        model.public_inputs[1] != Fr(128))
        throw std::invalid_argument("selected toy model identity or shape");
    return model;
}

void require_owner_jobs(const PublicModel& model, const OwnerInputContract& x,
                        const OwnerInputContract& y) {
    for (const auto* job : {&x, &y}) {
        if (job->model_identity != model.model_identity || job->source_identity != model.source_identity ||
            job->proving_key_identity != model.proving_key_identity ||
            job->verifying_key_identity != model.verifying_key_identity || job->input_count != 1)
            throw std::invalid_argument("owner job does not approve selected model");
    }
    if (x.owner_id != 0 || y.owner_id != 1 || x.run_nonce != y.run_nonce ||
        x.cohort_identity != y.cohort_identity || x.server_certificate_sha256 != y.server_certificate_sha256 ||
        x.owner_certificate_sha256 == y.owner_certificate_sha256)
        throw std::invalid_argument("toy owner roles or cohort");
}

void verify_independently(const std::filesystem::path& verifier,
                          const std::string& expected_verifier,
                          const std::filesystem::path& model,
                          const std::string& expected_model,
                          const std::filesystem::path& proof_file) {
    require_digest(expected_verifier);
    if (sha256_hex(read_public_file(verifier)) != expected_verifier)
        throw std::runtime_error("independent verifier binary identity");
    const auto child = fork();
    if (child == -1) throw std::runtime_error("independent verifier launch");
    if (child == 0) {
        // The selected verifier handles only public model/proof bytes. Keep its
        // process diagnostics local; the accepted typed result is emitted below.
        const auto sink = open("/dev/null", O_WRONLY);
        if (sink == -1 || dup2(sink, STDOUT_FILENO) == -1 || dup2(sink, STDERR_FILENO) == -1)
            _exit(126);
        close(sink);
        execl(verifier.c_str(), verifier.c_str(), "verify", model.c_str(),
              proof_file.c_str(), "128", expected_model.c_str(), nullptr);
        _exit(127);
    }
    int status = 0;
    while (waitpid(child, &status, 0) == -1) {
        if (errno != EINTR) throw std::runtime_error("independent verifier wait");
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        throw std::runtime_error("independent Ark proof rejection");
}

int serve(int argc, char** argv) {
    if (argc != 12 && argc != 13) throw std::invalid_argument("serve argument count");
    const std::string control = argc == 13 ? argv[12] : "positive";
    if (control != "positive" && control != "invalid-assignment" && control != "tamper-mac")
        throw std::invalid_argument("unsupported failure-only toy control");
    const auto party = canonical_int(argv[2], 0, 2);
    const auto network_port = canonical_int(argv[3], 1024, 65520);
    const auto owner_port = canonical_int(argv[4], 1024, 65520);
    const std::filesystem::path model_path = std::filesystem::absolute(argv[5]);
    const std::string expected_model = argv[6];
    const auto model = selected_toy_model(model_path, expected_model);
    const auto key = admit_proving_key(model);
    const auto job_x = load_owner_contract(argv[7]);
    const auto job_y = load_owner_contract(argv[8]);
    require_owner_jobs(model, job_x, job_y);
    const auto verifier = std::filesystem::absolute(argv[9]);
    const std::string expected_verifier = argv[10];
    require_digest(expected_verifier);
    if (sha256_hex(read_public_file(verifier)) != expected_verifier)
        throw std::runtime_error("unselected public verifier");
    const std::filesystem::path output = std::filesystem::absolute(argv[11]);
    if (mkdir(output.c_str(), 0700) != 0)
        throw std::runtime_error("fresh result directory required");
    public_stage_path = output / "PUBLIC-STAGE.json";
    stage("preinput-admitted");

    Names names(party, 3, "127.0.0.1", network_port);
    stage("interparty-addresses-ready");
    CryptoPlayer player(names);
    stage("interparty-TLS-ready");
    MascotContext ctx(player, [](const char* phase) { stage(phase); });
    stage("three-party-context-ready");
    ctx.agree_public_bytes("toy-selected-model-before-input", model.encoded_model);
    ctx.agree_public_bytes("toy-failure-control-before-input", std::span(
        reinterpret_cast<const unsigned char*>(control.data()), control.size()));
    ActiveOwnerInputServer owners(ctx, owner_port);
    stage("owner-listeners-ready");
    const auto x = owners.receive(job_x).at(0);
    stage("first-owner-input-received");
    const auto y = owners.receive(job_y).at(0);
    stage("second-owner-input-received");
    const std::array<AuthScalar, 1> xs{x}, ys{y};
    const auto z = ctx.multiply_batch(xs, ys).at(0);
    stage("cross-owner-auxiliary-derived");
    std::array<AuthScalar, 5> assignment{
        ctx.public_constant(Fr(1)), ctx.public_constant(Fr(128)), x, y, z};
    // Explicit, agreed failure-only controls for this public synthetic gate.
    // Neither path changes a check or provides a success override.
    if (control == "invalid-assignment")
        assignment[4] += ctx.public_constant(Fr(1));
    if (control == "tamper-mac" && party == 0)
        assignment[4].set_mac(assignment[4].get_mac() + Fr(1));
    const auto proof = prove(ctx, model, key, assignment);
    stage("complete-proof-and-MAC-checks");
    const auto encoded = encode_native_proof(proof);
    const auto proof_file = output / "candidate-proof.bin";
    {
        std::ofstream stream(proof_file, std::ios::binary);
        stream.write(reinterpret_cast<const char*>(encoded.data()), encoded.size());
        if (!stream) throw std::runtime_error("proof candidate persistence");
    }
    verify_independently(verifier, expected_verifier, model_path, expected_model, proof_file);
    stage("independent-Ark-verification-complete");
    const std::string proof_identity = sha256_hex(encoded);
    const std::string body = "{\"schema\":\"kpi-mascot-fullproof-party/v1\",\"status\":\"VERIFIED\","
        "\"party\":" + std::to_string(party) + ",\"model_sha256\":\"" + expected_model +
        "\",\"proof_sha256\":\"" + proof_identity + "\",\"proof_hex\":\"" + proof_hex(proof) +
        "\",\"external_owners\":2,\"server_parties\":3,\"full_assignment_checked\":true,"
        "\"field_and_group_MAC_checks\":true,\"independent_Ark_verified\":true,"
        "\"payment_privacy_qualified\":false}\n";
    {
        std::ofstream receipt(output / "PUBLIC-RESULT.json");
        receipt << body;
        if (!receipt) throw std::runtime_error("public result persistence");
    }
    std::cout << "KPI_MPC_FULLPROOF_VERIFIED " << proof_identity << '\n';
    stage("complete", "verified");
    return 0;
}
}

int main(int argc, char** argv) {
    try {
        initialize_bn254_field();
        initialize_bn254_groups();
        if (argc == 4 && std::string(argv[1]) == "preflight") {
            const auto model = selected_toy_model(argv[2], argv[3]);
            (void) admit_proving_key(model);
            std::cout << "{\"preflight\":\"accepted\"}\n";
            return 0;
        }
        if (argc > 1 && std::string(argv[1]) == "serve") return serve(argc, argv);
        throw std::invalid_argument("command");
    } catch (const mac_fail&) {
        std::cerr << "KPI_MPC_FULLPROOF_REFUSED\n";
        try { stage(public_phase, "mac-refused"); } catch (...) {}
        return 1;
    } catch (const std::exception& error) {
        // Classify this one application-defined validity error inside the
        // worker. Never export arbitrary upstream exception text or values.
        const bool invalid_assignment =
            std::string_view(error.what()) == "invalid-extended-assignment";
        const char* category = "upstream-exception";
        if (dynamic_cast<const IO_Error*>(&error)) category = "upstream-io";
        else if (dynamic_cast<const std::invalid_argument*>(&error)) category = "invalid-argument";
        else if (std::string_view(error.what()) == "gfp not initialized") category = "field-not-initialized";
        else if (std::string_view(error.what()) == "gf2n not initialized") category = "binary-field-not-initialized";
        else if (std::string_view(error.what()) == "Zp_Data instance already initialized") category = "field-reinitialization";
        else if (std::string_view(error.what()) == "no BaseMachine singleton") category = "machine-context-absent";
        else if (std::string_view(error.what()) == "couldn't initialize libsodium") category = "sodium-initialization-refused";
        else if (std::string_view(error.what()) == "insufficient allocation") category = "public-integer-storage-refused";
        else if (std::string_view(error.what()) == "mismatch among parties") category = "party-preprocessing-state-disagreement";
        else if (std::string_view(error.what()) == "base sender outputs are the same") category = "base-OT-output-collision";
        else if (std::string_view(error.what()) == "mismatch in number of base OTs") category = "base-OT-arity";
        else if (std::string_view(error.what()) == "wrong number of choice bits") category = "OT-choice-arity";
        else if (std::string_view(error.what()).starts_with("Sender outputs are the same at ")) category = "base-OT-collision";
        else if (std::string_view(error.what()) == "correlation check") category = "OT-correlation-refused";
        else if (std::string_view(error.what()) == "unexpected length") category = "upstream-frame-length";
        else if (std::string_view(error.what()) == "seed is all zero") category = "RNG-zero-refused";
        else if (std::string_view(error.what()) == "bounded randomness error") category = "RNG-bound-refused";
        else if (std::string_view(error.what()) == "requires-three-encrypted-Fr-MASCOT-parties") category = "context-policy";
        else if (dynamic_cast<const std::runtime_error*>(&error)) category = "upstream-runtime";
        std::cerr << "KPI_MPC_FULLPROOF_REFUSED\n";
        try { stage(public_phase, invalid_assignment ? "invalid-assignment-refused" : "refused", category); }
        catch (...) {}
        return 1;
    } catch (...) {
        // Fixed public failure only. Stock process logs stay with its isolated
        // role; no scalar, mask, key, per-row residual or auxiliary B1 escapes.
        std::cerr << "KPI_MPC_FULLPROOF_REFUSED\n";
        try { stage(public_phase, "refused"); } catch (...) {}
        return 1;
    }
}
