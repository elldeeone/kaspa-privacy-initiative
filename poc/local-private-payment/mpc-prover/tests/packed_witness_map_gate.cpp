// Separate known PUBLIC fixture. This binary alone admits the fixture H-map
// control seam; the financial builder must not define that compile-time flag.
#ifndef KPI_STREAMED_H_MAP_PUBLIC_FIXTURE_CONTROL
#error "This control requires its separate fixture-only build"
#endif
#include "../financial/packed_assignment.hpp"
#include "../financial/streamed_h_map.hpp"
#include <filesystem>
#include <fstream>
#include <map>
#include <string_view>
#include <sys/stat.h>

namespace {
using namespace kpi::mpc;
std::filesystem::path output;
std::map<std::string, size_t> phases;
const char* current = "preflight";
void stage(const char* phase) {
    current = phase; ++phases[phase];
    if (output.empty()) return;
    std::ofstream out(output / "PUBLIC-STAGE.json");
    out << "{\"schema\":\"kpi-packed-H-public-stage/v1\",\"phase\":\"" << phase << "\"}\n";
    if (!out) throw std::runtime_error("control-public-stage");
}
std::string label(const std::string& text) {
    return sha256_hex({reinterpret_cast<const unsigned char*>(text.data()), text.size()});
}
void require(bool value) { if (!value) throw std::runtime_error("packed-public-control-refused"); }
int number(const std::string& text, int low, int high) {
    size_t consumed = 0;
    const auto value = std::stoi(text, &consumed);
    require(consumed == text.size() && std::to_string(value) == text && value >= low && value <= high);
    return value;
}

int run(int argc, char** argv) {
    require(argc == 11 && std::string_view(argv[1]) == "control" && std::string_view(argv[6]) == "valid");
    const auto party = number(argv[2], 0, 2), port = number(argv[3], 1024, 65510);
    const std::string attempt = argv[7];
    require(attempt.size() == 64 && attempt.find_first_not_of("0123456789abcdef") == std::string::npos);
    require(std::string_view(argv[5]) == "ef8e22906f0c4dc232cbd49e0905db10000ed3ba4d87020516d449066ffc30d9");
    output = argv[10];
    require(mkdir(output.c_str(), 0700) == 0);
    const auto model = packed::PackedModel::admit("/app/packed", "/app/packed/pk.bin", "/app/packed/vk.bin",
        "aa5e8cba630ce787d7087a2b32a22a37d7167343b1c6d1f7c5840d21964f99d6");
    stage("public-packed-model-admitted");
    Names names(party, 3, "127.0.0.1", port);
    CryptoPlayer player(names);
    MascotContext context(player, stage);
    std::vector<AuthScalar> assignment;
    for (auto value : {1, 128, 3, 5, 15}) assignment.push_back(context.public_constant(Fr(value)));
    const auto h = financial::StreamedWitnessMap::public_fixture_compute(context, model, assignment, 2);
    const auto opened = context.open_public_checked(h);
    const std::array<const char*, 4> expected{
        "10944121435919637611123202872628637544274182200208017171849102093287904247724",
        "2736030358979909618768928262673107670592930172561329085880035060824496512943",
        "8208091076939728358211715144543768804610311694346156612748129106192166866223", "0"};
    require(opened.size() == expected.size());
    for (size_t i = 0; i < expected.size(); ++i) require(opened[i] == parse_fr(expected[i]));
    stage("all-four-public-H-coefficients-exact-Ark-match");
    BatchedValidationBinding binding{attempt, label("packed-public-control-service"),
        label("packed-public-control-history"), label("packed-public-control-dependency"),
        model.identity(), model.metadata().source_sha256, model.metadata().matrix_fingerprint,
        label("packed-public-control-trace"), label("packed-public-control-layout"),
        label("packed-public-control-input-map"), label("packed-public-control-public-prefix"), 2,
        output / "PUBLIC-VALIDATION.json"};
    const std::array<AuthScalar, 2> checks{context.public_constant(Fr(0)), context.public_constant(Fr(0))};
    auto validated = financial::validate_packed_public_prefix(context, model, binding, assignment, checks, 2);
    require(validated.residual_count() == 6);
    const auto proof = financial::prove_packed_public_fixture(context, std::move(validated), binding, 2);
    const auto encoded = encode_native_proof(proof);
    require(phases["streamed-H-map-started"] == 2 && phases["streamed-H-map-complete"] == 2 &&
        phases["packed-masked-A-and-B1-MAC-checked"] == 1 && phases["packed-final-B2-and-C-MAC-checked"] == 1);
    stage("public-packed-control-complete");
    std::ofstream out(output / "PUBLIC-RESULT.json");
    out << "{\"schema\":\"kpi-packed-witness-map-control/v1\",\"status\":\"PASS\",\"party\":" << party
        << ",\"attempt\":\"" << attempt << "\",\"H_coefficients_checked\":4,\"H_exact_Ark_match\":true,"
           "\"complete_proof_hex\":\"" << proof_hex(proof) << "\",\"proof_bytes\":" << encoded.size()
        << ",\"residuals\":6,\"nonempty_private_assertion_count\":2,\"group_MAC_opening_pairs\":2,"
           "\"all_public_fixture_only\":true,\"private_owner_input_read\":false,\"financial_qualified\":false}\n";
    require(bool(out));
    return 0;
}
}
int main(int argc, char** argv) {
    try { return run(argc, argv); }
    catch (...) {
        if (!output.empty()) {
            std::ofstream out(output / "PUBLIC-RESULT.json");
            out << "{\"schema\":\"kpi-packed-witness-map-control/v1\",\"status\":\"FAIL\",\"phase\":\""
                << current << "\"}\n";
        }
        return 1;
    }
}
