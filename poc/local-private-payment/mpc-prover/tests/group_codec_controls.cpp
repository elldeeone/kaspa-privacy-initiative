#include "bn254_values.hpp"
#include "proof_codec.hpp"
#include <functional>
#include <iostream>

using namespace kpi::mpc;

namespace {
std::array<unsigned char, 32> modulus_bytes() {
    bigint modulus(FQ_MODULUS);
    std::array<unsigned char, 32> bytes{};
    size_t count = 0;
    mpz_export(bytes.data(), &count, -1, 1, 0, 0, modulus.get_mpz_t());
    if (count > bytes.size()) throw std::runtime_error("public fixture length");
    return bytes;
}

AffinePoint nonsubgroup_g2_fixture() {
    // Deterministic PUBLIC malformed-input construction. Production admission
    // never calls set(...,false); it performs every curve and order check.
    for (int n = 0; n < 128; ++n) {
        mcl::Fp2 x, rhs, y;
        x.a = n;
        x.b = 1;
        mcl::G2::getWeierstrass(rhs, x);
        if (!mcl::Fp2::squareRoot(y, rhs)) continue;
        mcl::G2 point;
        bool accepted = false;
        point.set(&accepted, x, y, false);
        if (accepted && y * y == rhs && !point.isValidOrder())
            return {false, {x.a.getStr(10), x.b.getStr(10)},
                    {y.a.getStr(10), y.b.getStr(10)}};
    }
    throw std::runtime_error("no public non-subgroup fixture found");
}

template<class Action>
bool rejects_argument(Action action) {
    try { action(); }
    catch (const std::invalid_argument&) { return true; }
    return false;
}

template<class Action>
bool rejects_fr(Action action) {
    try { action(); }
    catch (const std::runtime_error&) { return true; }
    return false;
}
}

int main(int argc, char** argv) {
    try {
        if (argc != 3) throw std::runtime_error("MODEL EXPECTED_SHA256 required");
        initialize_bn254_field();
        initialize_bn254_groups();
        const auto model = load_public_model(argv[1]);
        if (model.model_identity != argv[2]) throw std::runtime_error("public model pin");
        const auto g1 = G1Value::admit({false, {"1"}, {"2"}}, false);
        const auto g2 = G2Value::admit(model.beta_g2, false);
        const bigint maximum_scalar = fr_modulus() - 1;
        const Fr zero(0), one(1), minus_one(maximum_scalar);
        const auto inverse_g1 = g1 * minus_one;
        const auto inverse_g2 = g2 * minus_one;
        std::vector<std::pair<std::string, bool>> controls;
        auto check = [&](std::string name, bool passed) { controls.emplace_back(std::move(name), passed); };

        check("g1.zero.identity", G1Value().is_identity());
        check("g2.zero.identity", G2Value().is_identity());
        check("g1.scalar.zero", (g1 * zero).is_identity());
        check("g2.scalar.zero", (g2 * zero).is_identity());
        check("g1.scalar.one", g1 * one == g1);
        check("g2.scalar.one", g2 * one == g2);
        check("g1.inverse.cancellation", (g1 + inverse_g1).is_identity());
        check("g2.inverse.cancellation", (g2 + inverse_g2).is_identity());
        check("g1.equal.addition", g1 + g1 == g1 * Fr(2));
        check("g2.equal.addition", g2 + g2 == g2 * Fr(2));
        check("g1.network.roundtrip", G1Value::from_network_bytes(g1.network_bytes()) == g1);
        check("g2.network.roundtrip", G2Value::from_network_bytes(g2.network_bytes()) == g2);
        check("g1.network.identity", G1Value::from_network_bytes(G1Value().network_bytes()).is_identity());
        check("g2.network.identity", G2Value::from_network_bytes(G2Value().network_bytes()).is_identity());
        check("g1.final.identity.refused", rejects_argument([] { G1Value::admit({true, {"0"}, {"0"}}, false); }));
        check("g2.final.identity.refused", rejects_argument([] { G2Value::admit({true, {"0", "0"}, {"0", "0"}}, false); }));
        auto malformed_identity = G1Value().network_bytes();
        malformed_identity[1] = 1;
        check("g1.network.identity.payload.refused", rejects_argument([&] { G1Value::from_network_bytes(malformed_identity); }));
        auto alias = g1.network_bytes();
        const auto modulus = modulus_bytes();
        std::copy(modulus.begin(), modulus.end(), alias.begin() + 1);
        check("g1.network.field.alias.refused", rejects_argument([&] { G1Value::from_network_bytes(alias); }));
        const auto wrong_subgroup = nonsubgroup_g2_fixture();
        check("g2.oncurve.nonsubgroup.refused", rejects_argument([&] { G2Value::admit(wrong_subgroup, true); }));

        // This is a codec fixture, not an assertion that these three arbitrary
        // points form a Groth16 proof. The actual proof gets independent Ark verification.
        const ProofPublic fixture{g1, g2, inverse_g1};
        const auto encoded = encode_native_proof(fixture);
        const auto decoded = decode_native_proof(encoded);
        check("Native128.point.roundtrip", decoded.a == fixture.a && decoded.b == fixture.b && decoded.c == fixture.c);
        auto wrong_flag = encoded;
        wrong_flag[31] |= 0x40;
        check("Native128.infinity.flag.refused", rejects_argument([&] { decode_native_proof(wrong_flag); }));
        auto proof_alias = encoded;
        std::copy(modulus.begin(), modulus.end(), proof_alias.begin());
        check("Native128.field.alias.refused", rejects_argument([&] { decode_native_proof(proof_alias); }));
        check("Native128.short.refused", rejects_argument([&] { decode_native_proof(std::span(encoded).first(127)); }));
        auto negated_a = fixture;
        negated_a.a = inverse_g1;
        const auto negative_a = encode_native_proof(negated_a);
        check("Native128.G1.sign.flag", (encoded[31] ^ negative_a[31]) == 0x80 && std::equal(encoded.begin(), encoded.begin() + 31, negative_a.begin()));
        auto negated_b = fixture;
        negated_b.b = inverse_g2;
        const auto negative_b = encode_native_proof(negated_b);
        check("Native128.G2.sign.flag", (encoded[95] ^ negative_b[95]) == 0x80 && std::equal(encoded.begin() + 32, encoded.begin() + 95, negative_b.begin() + 32));
        check("Fr.zero", parse_fr("0") == zero);
        check("Fr.maximum", parse_fr(maximum_scalar.get_str()) == minus_one);
        check("Fr.alias.refused", rejects_fr([] { parse_fr(FR_MODULUS); }));
        check("Fr.negative.refused", rejects_fr([] { parse_fr("-1"); }));
        check("Fr.leading.zero.refused", rejects_fr([] { parse_fr("00"); }));

        bool all_passed = true;
        std::cout << "{\"schema\":\"kpi-public-group-codec-controls/v1\",\"cases\":[";
        for (size_t i = 0; i < controls.size(); ++i) {
            if (i) std::cout << ',';
            std::cout << "{\"case\":\"" << controls[i].first << "\",\"passed\":"
                      << (controls[i].second ? "true" : "false") << '}';
            all_passed = all_passed && controls[i].second;
        }
        std::cout << "],\"count\":" << controls.size() << ",\"passed\":"
                  << (all_passed ? "true" : "false") << ",\"MPC_or_proof_executed\":false}\n";
        return all_passed ? 0 : 1;
    } catch (...) {
        std::cout << "{\"status\":\"PUBLIC_CONTROL_FAILURE\"}\n";
        return 1;
    }
}
