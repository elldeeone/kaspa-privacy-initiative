// PUBLIC boundary controls only. No players, owner input, MAC keys or MPC run.
#include "field_coin.hpp"
#include <algorithm>
#include <array>
#include <functional>
#include <iostream>
#include <vector>

using namespace kpi::mpc;

namespace {
using Bytes = std::array<unsigned char, 32>;

// Deliberately independent of the adapter's mpz_export serialization.
Bytes little_endian(bigint value) {
    Bytes bytes{};
    for (auto& byte : bytes) {
        byte = static_cast<unsigned char>(mpz_fdiv_ui(value.get_mpz_t(), 256));
        mpz_fdiv_q_2exp(value.get_mpz_t(), value.get_mpz_t(), 8);
    }
    if (value != 0) throw std::runtime_error("public-fixture-out-of-range");
    return bytes;
}

octetStream frame(std::span<const unsigned char> bytes) {
    octetStream output;
    output.append(bytes.data(), bytes.size());
    return output;
}

CheckedFrContribution admitted(const bigint& value) {
    auto input = frame(little_endian(value));
    CheckedFrContribution result;
    result.unpack(input);
    if (!input.done()) throw std::runtime_error("public-fixture-not-consumed");
    return result;
}

bool packs_exactly(const CheckedFrContribution& value, const Bytes& expected) {
    octetStream encoded;
    value.pack(encoded);
    return encoded.get_length() == expected.size() &&
        std::equal(expected.begin(), expected.end(), encoded.get_data());
}

template<class Action>
bool rejects(Action action) {
    try { action(); }
    catch (const std::runtime_error&) { return true; }
    return false;
}
}  // namespace

int main() {
    try {
        initialize_bn254_field();
        const bigint modulus = fr_modulus();
        const bigint maximum = modulus - 1;
        std::vector<std::pair<std::string, bool>> controls;
        auto check = [&](std::string name, bool valid) {
            controls.emplace_back(std::move(name), valid);
        };
        for (const auto& [name, value] : std::vector<std::pair<std::string, bigint>>{
            {"zero", bigint(0)}, {"one", bigint(1)}, {"P-minus-one", maximum},
            {"asymmetric-LE", (bigint(1) << 200) + bigint(0x01020304)},
        }) {
            const auto contribution = admitted(value);
            check(name + ".admission", contribution.public_value() == Fr(value));
            check(name + ".exact-pack", packs_exactly(contribution, little_endian(value)));
        }

        for (const auto& [name, value] : std::vector<std::pair<std::string, bigint>>{
            {"P", modulus}, {"P-plus-one", modulus + 1},
            {"maximum-256-bit", (bigint(1) << 256) - 1},
        }) {
            check(name + ".refused", rejects([&] {
                auto input = frame(little_endian(value));
                CheckedFrContribution contribution;
                contribution.unpack(input);
            }));
        }
        for (const auto length : {size_t(0), size_t(31), size_t(33), size_t(41)}) {
            check("frame-length-" + std::to_string(length) + ".refused", rejects([&] {
                std::vector<unsigned char> bytes(length, 0);
                auto input = frame(bytes);
                CheckedFrContribution contribution;
                contribution.unpack(input);
            }));
        }
        check("partially-consumed-32-byte-frame.refused", rejects([&] {
            auto input = frame(little_endian(bigint(0)));
            input.consume(1);
            CheckedFrContribution contribution;
            contribution.unpack(input);
        }));
        check("leading-byte-with-32-unread.refused", rejects([&] {
            std::vector<unsigned char> bytes(33, 0);
            auto input = frame(bytes);
            input.consume(1);
            CheckedFrContribution contribution;
            contribution.unpack(input);
        }));
        check("same-frame-second-unpack.refused", rejects([&] {
            auto input = frame(little_endian(bigint(1)));
            CheckedFrContribution contribution;
            contribution.unpack(input);
            contribution.unpack(input);
        }));
        auto previous = admitted(bigint(1));
        const bool invalid_refused = rejects([&] {
            auto input = frame(little_endian(modulus));
            previous.unpack(input);
        });
        check("invalid-unpack-preserves-valid-object", invalid_refused &&
              previous.public_value() == Fr(1));
        auto sum = admitted(maximum);
        sum += admitted(bigint(1));
        check("canonical-addition-wraps-at-P", sum.public_value() == Fr(0) &&
              packs_exactly(sum, Bytes{}));
        auto reset = admitted(maximum);
        reset.assign_zero();
        check("assign-zero-packs-canonically", packs_exactly(reset, Bytes{}));

        // Fixed coins exist ONLY in this separately compiled public control.
        // A caller-supplied production coin would permit cancelling residuals.
        const Fr first_coin(1), second_coin(2);
        const Fr e0 = Fr(0) - first_coin, e1(1);
        check("fixed-coin-cancellation-is-real", e0 + first_coin * e1 == Fr(0));
        check("changed-coin-detects-same-nonzero-vector", e0 + second_coin * e1 != Fr(0));
        check("zero-coin-root-is-counted-not-retried", Fr(0) + Fr(0) * e1 == Fr(0));
        const bigint exponent = modulus - 1;
        check("public-Fermat-zero", Fr(1) - pow_public(Fr(0), exponent) == Fr(1));
        check("public-Fermat-one", Fr(1) - pow_public(Fr(1), exponent) == Fr(0));
        check("public-Fermat-P-minus-one", Fr(1) - pow_public(Fr(maximum), exponent) == Fr(0));

        bool passed = true;
        std::cout << "{\"schema\":\"kpi-field-coin-public-boundary-controls/v1\",\"controls\":[";
        for (size_t index = 0; index < controls.size(); ++index) {
            if (index) std::cout << ',';
            const auto& [name, valid] = controls[index];
            std::cout << "{\"name\":\"" << name << "\",\"passed\":"
                      << (valid ? "true" : "false") << '}';
            passed = passed && valid;
        }
        std::cout << "],\"count\":" << controls.size()
                  << ",\"MPC_or_private_input_executed\":false,\"passed\":"
                  << (passed ? "true" : "false") << "}\n";
        return passed ? 0 : 1;
    } catch (const std::exception&) {
        // No data-dependent diagnostic values enter this public test protocol.
        std::cerr << "public-field-coin-control-error\n";
        return 2;
    }
}
