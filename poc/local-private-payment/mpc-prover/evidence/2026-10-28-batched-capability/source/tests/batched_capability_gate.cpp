// Separate PUBLIC-fixture control binary. This is not an owner-input or
// financial prover, and cannot inject a challenge into the production API.
#include "../auth_groth16.hpp"
#include "../batched_assignment.hpp"
#include "../field_coin.hpp"
#include "Tools/Subroutines.hpp"
#include <array>
#include <cerrno>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <optional>
#include <set>
#include <string_view>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
using namespace kpi::mpc;
const std::set<std::string> cases{
    "valid", "caller-mutation", "reuse", "different-context-generation",
    "poisoned-context", "post-validation-MAC-failure", "skipped-assertion",
    "extra-assertion", "bad-assertion", "bad-ONE", "bad-prefix", "bad-witness",
    "wrong-model", "wrong-source", "wrong-matrix", "wrong-trace", "wrong-layout",
    "wrong-input-map", "wrong-attempt", "wrong-history", "wrong-context",
    "wrong-dependency", "wrong-service", "wrong-assertion-count",
    "malformed-contribution", "commitment-mismatch", "repeat-validation-attempt",
    "repeat-after-invalid"};

std::filesystem::path result_directory;
std::string selected_case;
const char* phase = "startup";
std::map<std::string, size_t> events;

void stage(const char* value) {
    phase = value;
    ++events[value];
    if (result_directory.empty()) return;
    const auto target = result_directory / "PUBLIC-STAGE.json";
    const auto temporary = result_directory / "PUBLIC-STAGE.json.new";
    std::ofstream out(temporary);
    out << "{\"schema\":\"kpi-batched-capability-stage/v1\",\"phase\":\""
        << value << "\",\"status\":\"running\"}\n";
    out.close();
    if (!out) throw std::runtime_error("control-stage-persistence");
    std::filesystem::rename(temporary, target);
}

std::string hash_text(const std::string& text) {
    return sha256_hex({reinterpret_cast<const unsigned char*>(text.data()), text.size()});
}

void require_hash(const std::string& text) {
    if (text.size() != 64 || text.find_first_not_of("0123456789abcdef") != std::string::npos)
        throw std::runtime_error("control-hash-format");
}

int number(const std::string& text, int lower, int upper) {
    size_t consumed = 0;
    const auto value = std::stoi(text, &consumed);
    if (std::to_string(value) != text || consumed != text.size() || value < lower || value > upper)
        throw std::runtime_error("control-integer-format");
    return value;
}

std::vector<unsigned char> public_bytes(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("control-public-file");
    return {std::istreambuf_iterator<char>(in), {}};
}

void verify(const ProofPublic& proof, const std::filesystem::path& verifier,
            const std::string& verifier_sha, const std::filesystem::path& model,
            const std::string& model_sha) {
    if (sha256_hex(public_bytes(verifier)) != verifier_sha)
        throw std::runtime_error("control-verifier-pin");
    const auto encoded = encode_native_proof(proof);
    const auto candidate = result_directory / "verified-control-proof.bin";
    {
        std::ofstream out(candidate, std::ios::binary);
        out.write(reinterpret_cast<const char*>(encoded.data()), encoded.size());
        if (!out) throw std::runtime_error("control-proof-persistence");
    }
    const auto child = fork();
    if (child == -1) throw std::runtime_error("control-verifier-launch");
    if (child == 0) {
        const auto sink = open("/dev/null", O_WRONLY);
        if (sink == -1 || dup2(sink, STDOUT_FILENO) == -1 || dup2(sink, STDERR_FILENO) == -1)
            _exit(126);
        close(sink);
        execl(verifier.c_str(), verifier.c_str(), "verify", model.c_str(), candidate.c_str(),
              "128", model_sha.c_str(), nullptr);
        _exit(127);
    }
    int status = 0;
    while (waitpid(child, &status, 0) == -1)
        if (errno != EINTR) throw std::runtime_error("control-verifier-wait");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        throw std::runtime_error("control-independent-proof-rejection");
}

void require(bool value, const char* error) {
    if (!value) throw std::runtime_error(error);
}

void expected_refusal(MascotContext& context, ValidatedAssignment&& capability,
                      const BatchedValidationBinding& binding, std::string_view expected) {
    const auto h_before = events["authenticated-H-map-started"];
    const auto pair_before = events["masked-A-and-B1-MAC-checked"];
    const auto final_before = events["final-B2-and-C-MAC-checked"];
    bool refused = false;
    try {
        (void) prove_validated(context, std::move(capability), binding);
    } catch (const std::runtime_error& error) {
        refused = std::string_view(error.what()) == expected;
    }
    require(refused, "control-wrong-or-missing-capability-refusal");
    require(events["authenticated-H-map-started"] == h_before &&
            events["masked-A-and-B1-MAC-checked"] == pair_before &&
            events["final-B2-and-C-MAC-checked"] == final_before,
            "control-refusal-followed-H-or-proof-opening");
}

void mutate_binding(BatchedValidationBinding& binding) {
    const auto changed = hash_text("PUBLIC-DIFFERENT-EXPECTED-BINDING:" + selected_case);
    if (selected_case == "wrong-model") binding.model_identity = changed;
    else if (selected_case == "wrong-source") binding.source_identity = changed;
    else if (selected_case == "wrong-matrix") binding.matrix_identity = changed;
    else if (selected_case == "wrong-trace") binding.trace_identity = changed;
    else if (selected_case == "wrong-layout") binding.layout_identity = changed;
    else if (selected_case == "wrong-input-map") binding.input_map_identity = changed;
    else if (selected_case == "wrong-attempt") binding.attempt_identity = changed;
    else if (selected_case == "wrong-history") binding.history_identity = changed;
    else if (selected_case == "wrong-context") binding.public_context_identity = changed;
    else if (selected_case == "wrong-dependency") binding.dependency_identity = changed;
    else if (selected_case == "wrong-service") binding.service_identity = changed;
    else if (selected_case == "wrong-assertion-count") ++binding.expected_trace_private_checks;
    else throw std::runtime_error("control-unsupported-binding-mutation");
}

void final_result(bool passed, const char* category, int party, bool issued,
                  bool proof_verified, const std::string& proof_hex_value,
                  uint64_t before_generation, uint64_t after_generation,
                  uint64_t epoch, uint64_t checked_before, uint64_t checked_after) {
    if (result_directory.empty()) return;
    std::ofstream out(result_directory / "PUBLIC-RESULT.json");
    out << "{\"schema\":\"kpi-batched-capability-control/v1\",\"case\":\"" << selected_case
        << "\",\"status\":\"" << (passed ? "PASS" : "FAIL")
        << "\",\"category\":\"" << category << "\",\"party\":" << party
        << ",\"capability_issued\":" << (issued ? "true" : "false")
        << ",\"independent_proof_verified\":" << (proof_verified ? "true" : "false")
        << ",\"proof_hex\":\"" << proof_hex_value << "\",\"context_generation_before\":"
        << before_generation << ",\"context_generation_after\":" << after_generation
        << ",\"failure_epoch\":" << epoch << ",\"check_counter_before\":" << checked_before
        << ",\"check_counter_after\":" << checked_after << ",\"final_phase\":\"" << phase
        << "\",\"events\":{";
    bool first = true;
    for (const auto& [name, count] : events) {
        if (!first) out << ',';
        first = false;
        out << '"' << name << "\":" << count;
    }
    out << "},\"public_fixture_only\":true,\"owner_input_or_financial_claim\":false,"
           "\"raw_diagnostics_or_TLS_private_keys_read\":false}\n";
    if (!out) throw std::runtime_error("control-result-persistence");
}

void adversarial_public_coin(Player& player, bool malformed) {
    // Deliberately corrupt role 0 in this TEST TU only. This is the same two
    // Commit/Broadcast_Receive steps as Tools/Subroutines.hpp:13-28 at stock
    // MP-SPDZ 113c4e47dd94bca9ecab029d2f0abe649bea5c52. Honest roles use the
    // unmodified stock Create_Random<CheckedFrContribution> below.
    std::vector<octetStream> commitments(3), openings(3);
    octetStream body;
    if (malformed) {
        std::array<unsigned char, 32> encoded{};
        const auto value = fr_modulus();
        size_t written = 0;
        mpz_export(encoded.data(), &written, -1, 1, 0, 0, value.get_mpz_t());
        require(written <= encoded.size(), "control-malformed-contribution-size");
        body.append(encoded.data(), encoded.size()); // Exactly P, correctly committed.
    } else {
        CheckedFrContribution zero;
        zero.assign_zero();
        zero.pack(body);
    }
    Commit(commitments[0], openings[0], body, 0);
    if (!malformed) {
        require(commitments[0].get_length() > 0, "control-empty-commitment");
        commitments[0].get_data()[0] ^= 1; // Opening stays unchanged and must fail.
    }
    player.Broadcast_Receive(commitments);
    player.Broadcast_Receive(openings);
}

void coin_fault_control(MascotContext& context, int party) {
    stage("fault-test-coin-started");
    const bool malformed = selected_case == "malformed-contribution";
    const char* outcome = "malicious-role-sent";
    if (party == 0) {
        adversarial_public_coin(context.player(), malformed);
    } else {
        bool refused = false;
        try {
            CheckedFrContribution contribution;
            Create_Random(contribution, context.player());
        } catch (const invalid_commitment&) {
            refused = !malformed;
            outcome = "commitment-opening-refused";
        } catch (const std::runtime_error& error) {
            refused = malformed && std::string_view(error.what()) == "coin-contribution-noncanonical";
            outcome = "canonical-peer-contribution-refused";
        }
        require(refused, "control-peer-fault-not-specifically-refused");
    }
    context.poison();
    require(events["authenticated-H-map-started"] == 0 &&
            events["masked-A-and-B1-MAC-checked"] == 0 &&
            events["final-B2-and-C-MAC-checked"] == 0,
            "control-coin-fault-released-proof-events");
    final_result(true, outcome, party, false, false, "", context.generation(),
                 context.generation(), context.failure_epoch(), context.check_counter(), context.check_counter());
}

int run(int argc, char** argv) {
    if (argc != 11 || std::string_view(argv[1]) != "control")
        throw std::runtime_error("control-argument-arity");
    const auto party = number(argv[2], 0, 2), port = number(argv[3], 1024, 65510);
    const std::filesystem::path model_path = argv[4];
    const std::string model_sha = argv[5], attempt = argv[7], verifier_sha = argv[9];
    const std::filesystem::path verifier = argv[8];
    selected_case = argv[6];
    require(cases.contains(selected_case), "control-unsupported-case");
    for (const auto* value : {&model_sha, &attempt, &verifier_sha}) require_hash(*value);
    auto model = load_public_model(model_path);
    require(model.model_identity == model_sha && model.num_instance == 2 &&
        model.num_private == 3 && model.num_constraints == 2 && model.domain.n == 4 &&
        model.public_inputs == std::vector<Fr>{Fr(1), Fr(128)}, "control-unselected-public-toy");
    require(sha256_hex(public_bytes(verifier)) == verifier_sha, "control-unselected-verifier");
    result_directory = argv[10];
    require(mkdir(result_directory.c_str(), 0700) == 0, "control-fresh-output-required");
    stage("preinput-admitted");
    Names names(party, 3, "127.0.0.1", port);
    CryptoPlayer player(names);
    std::optional<MascotContext> context;
    context.emplace(player, stage);
    const auto generation = context->generation();
    const auto binding_label = selected_case + "\n" + attempt;
    context->agree_public_bytes("public-batched-capability-control", {
        reinterpret_cast<const unsigned char*>(binding_label.data()), binding_label.size()});
    if (selected_case == "malformed-contribution" || selected_case == "commitment-mismatch") {
        context->check_field_pending();
        coin_fault_control(*context, party);
        return 0;
    }
    BatchedValidationBinding binding{
        attempt, hash_text("PUBLIC-CAPABILITY-CONTROL-SERVICE"),
        hash_text("PUBLIC-CAPABILITY-CONTROL-HISTORY:" + attempt),
        hash_text("PUBLIC-CAPABILITY-CONTROL-FROZEN-STANDARD-VENDOR"),
        model.model_identity, model.source_identity, public_matrix_identity(model),
        hash_text("PUBLIC-CAPABILITY-CONTROL-NO-TRACE"),
        hash_text("PUBLIC-CAPABILITY-CONTROL-NO-OWNER-LAYOUT"),
        hash_text("PUBLIC-CAPABILITY-CONTROL-PUBLIC-CONSTANT-INPUTS"),
        hash_text("PUBLIC-CAPABILITY-CONTROL-T128"), 2,
        result_directory / "PUBLIC-VALIDATION.json"};
    std::vector<AuthScalar> assignment;
    for (auto value : {1, 128, 3, 5, 15}) assignment.push_back(context->public_constant(Fr(value)));
    std::vector<AuthScalar> checks(2, context->public_constant(Fr(0)));
    if (selected_case == "skipped-assertion") checks.pop_back();
    if (selected_case == "extra-assertion") checks.push_back(context->public_constant(Fr(0)));
    if (selected_case == "bad-assertion" || selected_case == "repeat-after-invalid")
        checks[0] += context->public_constant(Fr(1));
    if (selected_case == "bad-ONE") assignment[0] += context->public_constant(Fr(1));
    if (selected_case == "bad-prefix") assignment[1] += context->public_constant(Fr(1));
    if (selected_case == "bad-witness") assignment[4] += context->public_constant(Fr(1));
    bool issued = false, proof_verified = false;
    std::string published_proof;
    uint64_t checked_before = context->check_counter(), checked_after = checked_before;
    uint64_t after_generation = generation, epoch = 0;
    try {
        auto capability = validate_batched_public_prefix(*context, model, binding, assignment, checks);
        issued = true;
        checked_before = capability.validated_check_counter();
        require(capability.residual_count() == 6, "control-residual-coverage");
        if (selected_case == "valid" || selected_case == "caller-mutation" || selected_case == "reuse") {
            context->check_field_pending();
            require(context->check_counter() > checked_before, "control-healthy-check-did-not-advance");
            if (selected_case == "caller-mutation") {
                for (auto& value : assignment) value += context->public_constant(Fr(9));
                for (auto& value : checks) value += context->public_constant(Fr(7));
                model.A[0][0].coefficient += Fr(1);
                model.public_inputs[1] = Fr(129);
                model.alpha_g1.x[0] = "0";
                model.encoded_model[0] ^= 1;
                model.model_identity = hash_text("PUBLIC-MUTATED-CALLER-MODEL");
                model.source_identity = hash_text("PUBLIC-MUTATED-CALLER-SOURCE");
            }
            const auto proof = prove_validated(*context, std::move(capability), binding);
            verify(proof, verifier, verifier_sha, model_path, model_sha);
            proof_verified = true;
            published_proof = proof_hex(proof);
            require(events["authenticated-H-map-started"] == 1 &&
                events["masked-A-and-B1-MAC-checked"] == 1 &&
                events["final-B2-and-C-MAC-checked"] == 1, "control-incomplete-proof-event-chain");
            if (selected_case == "reuse")
                expected_refusal(*context, std::move(capability), binding,
                                 "validated-assignment-capability-refused");
        } else if (selected_case.starts_with("wrong-")) {
            auto changed = binding;
            mutate_binding(changed);
            expected_refusal(*context, std::move(capability), changed,
                             "validated-assignment-capability-refused");
        } else if (selected_case == "repeat-validation-attempt") {
            auto repeated = binding;
            // Keep the first already-public coin record. The adversarial
            // second API call uses a separate diagnostic path, but the SAME
            // attempt identity and context and must never generate a coin.
            repeated.public_receipt_path = result_directory / "PUBLIC-REPEATED-VALIDATION.json";
            bool refused = false;
            try {
                (void) validate_batched_public_prefix(*context, model, repeated, assignment, checks);
            } catch (const std::runtime_error& error) {
                refused = std::string_view(error.what()) == "validation-attempt-already-consumed";
            }
            require(refused && events["batched-coin-agreed"] == 1 &&
                    events["authenticated-H-map-started"] == 0,
                    "control-repeated-validation-generated-another-coin");
            expected_refusal(*context, std::move(capability), binding, "MASCOT-context-poisoned");
        } else if (selected_case == "poisoned-context") {
            context->poison();
            require(context->failure_epoch() == 1, "control-poison-epoch");
            expected_refusal(*context, std::move(capability), binding, "MASCOT-context-poisoned");
        } else if (selected_case == "post-validation-MAC-failure") {
            auto bad = context->public_constant(Fr(0));
            if (party == 0) bad.set_mac(bad.get_mac() + Fr(1));
            bool mac_refused = false;
            try {
                const std::array<AuthScalar, 1> input{bad};
                (void) context->open_public_checked(input); // Public synthetic zero only.
            } catch (const mac_fail&) { mac_refused = true; }
            require(mac_refused && context->failure_epoch() == 1, "control-post-validation-MAC-not-refused");
            expected_refusal(*context, std::move(capability), binding, "MASCOT-context-poisoned");
        } else if (selected_case == "different-context-generation") {
            const auto* old_address = &*context;
            context.reset();
            Names next_names(party, 3, "127.0.0.1", port + 8);
            CryptoPlayer next_player(next_names);
            context.emplace(next_player, stage); // The optional storage address is deliberately reused.
            after_generation = context->generation();
            require(&*context == old_address && after_generation != generation,
                    "control-context-generation-not-fresh");
            expected_refusal(*context, std::move(capability), binding,
                             "validated-assignment-capability-refused");
            epoch = context->failure_epoch();
            checked_after = context->check_counter();
            context.reset(); // Before next_player's destruction.
        } else throw std::runtime_error("control-invalid-input-was-accepted");
    } catch (const std::runtime_error& error) {
        const auto message = std::string_view(error.what());
        const bool shape = selected_case == "skipped-assertion" || selected_case == "extra-assertion";
        const bool invalid = selected_case == "bad-assertion" || selected_case == "bad-ONE" ||
                             selected_case == "bad-prefix" || selected_case == "bad-witness" ||
                             selected_case == "repeat-after-invalid";
        require(!issued && ((shape && message == "batched-validation-shape-or-identity") ||
                (invalid && message == "invalid-batched-extended-assignment")),
                "control-unexpected-runtime-refusal");
        require(events["authenticated-H-map-started"] == 0 &&
                events["masked-A-and-B1-MAC-checked"] == 0 &&
                events["final-B2-and-C-MAC-checked"] == 0, "control-invalid-released-proof-events");
        require(events["batched-coin-agreed"] == (shape ? 0 : 1), "control-invalid-coin-order");
        if (selected_case == "repeat-after-invalid") {
            checks[0] = context->public_constant(Fr(0));
            bool refused = false;
            try {
                (void) validate_batched_public_prefix(*context, model, binding, assignment, checks);
            } catch (const std::runtime_error& retry_error) {
                refused = std::string_view(retry_error.what()) == "MASCOT-context-poisoned";
            }
            require(refused && events["batched-coin-agreed"] == 1 &&
                    events["authenticated-H-map-started"] == 0,
                    "control-invalid-attempt-was-retried");
        }
    }
    if (context) {
        checked_after = context->check_counter();
        epoch = context->failure_epoch();
    }
    final_result(true, "expected-case-complete", party, issued, proof_verified, published_proof,
                 generation, after_generation, epoch, checked_before, checked_after);
    return 0;
}
}  // namespace

int main(int argc, char** argv) {
    int party = -1;
    try {
        initialize_bn254_field();
        initialize_bn254_groups();
        if (argc > 2) party = number(argv[2], 0, 2);
        return run(argc, argv);
    } catch (...) {
        try { final_result(false, "unexpected-control-failure", party, false, false, "", 0, 0, 0, 0, 0); }
        catch (...) {}
        std::cerr << "KPI_BATCHED_CAPABILITY_CONTROL_FAILED\n";
        return 1;
    }
}
