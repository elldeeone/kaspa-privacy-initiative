// Public arithmetic/parser controls. This executable creates no MPC context,
// consumes no private input and makes no private-execution/financial claim.
#include "trace_witness.hpp"
#include "bit_add.hpp"
#include "public_reference.hpp"
#include "prefix_recipe.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace kpi::mpc;

struct PublicArithmetic {
    std::vector<Fr> multiply_batch(std::span<const Fr> left, std::span<const Fr> right) {
        if (left.size() != right.size())
            throw std::runtime_error("public-oracle-arity");
        std::vector<Fr> result;
        for (size_t i = 0; i < left.size(); ++i)
            result.push_back(left[i] * right[i]);
        return result;
    }
};

std::vector<Fr> bits(const bigint& value, size_t width) {
    std::vector<Fr> result;
    for (size_t i = 0; i < width; ++i)
        result.push_back(Fr(mpz_tstbit(value.get_mpz_t(), i)));
    return result;
}

bigint integer(const std::vector<Fr>& bits) {
    bigint value(0);
    for (size_t i = 0; i < bits.size(); ++i) {
        if (bits[i] != Fr(0) && bits[i] != Fr(1))
            throw std::runtime_error("public-adder-not-a-bit");
        if (bits[i] == Fr(1))
            value += bigint(1) << i;
    }
    return value;
}

void arithmetic() {
    PublicArithmetic context;
    size_t cases = 0;
    for (unsigned x = 0; x < 32; ++x)
        for (unsigned y = 0; y < 32; ++y) {
            const auto sum = trace_detail::add_words(context, bits(bigint(x), 6), bits(bigint(y), 6));
            if (integer(sum) != bigint(x + y))
                throw std::runtime_error("public-adder-differential");
            ++cases;
        }
    for (size_t width : {size_t(1), size_t(2), size_t(32), size_t(33), size_t(64),
                         size_t(66), size_t(128), size_t(252), size_t(253), size_t(254), size_t(256)}) {
        const bigint limit(bigint(1) << (width - 1));
        const std::vector<bigint> values = {bigint(0), bigint(1), limit - 1};
        for (const auto& x : values)
            for (const auto& y : values) {
                const auto sum = trace_detail::add_words(context, bits(x, width), bits(y, width));
                if (integer(sum) != (x + y) % (bigint(1) << width))
                    throw std::runtime_error("public-adder-wide-differential");
                ++cases;
            }
    }
    std::cout << "PUBLIC_ARITHMETIC_PASS " << cases << '\n';
}

std::vector<std::pair<size_t, Fr>> read_values(const char* path, const char* expected_tag) {
    std::ifstream input(path);
    std::string tag, text;
    size_t count = 0;
    if (!(input >> tag >> count) || tag != expected_tag)
        throw std::runtime_error("public-control-value-file");
    std::vector<std::pair<size_t, Fr>> values;
    for (size_t i = 0; i < count; ++i) {
        size_t column;
        if (!(input >> column >> text) || (i && column <= values.back().first))
            throw std::runtime_error("public-control-value-order");
        values.emplace_back(column, parse_fr(text));
    }
    if (input >> text || !input.eof())
        throw std::runtime_error("public-control-value-trailing");
    return values;
}

void evaluate_control(const TraceProgram& program, char** argv) {
    const auto values = read_values(argv[11], "PUBLIC_FIXTURE_INPUTS_V1");
    std::vector<std::pair<int, std::vector<Fr>>> inputs;
    for (const auto& owner : program.owner_layout) {
        std::vector<Fr> selected;
        for (const auto column : owner.columns) {
            const auto found = std::lower_bound(values.begin(), values.end(), column,
                [](const auto& value, size_t target) { return value.first < target; });
            if (found == values.end() || found->first != column)
                throw std::runtime_error("public-control-missing-input");
            selected.push_back(found->second);
        }
        inputs.emplace_back(owner.owner_role, std::move(selected));
    }
    if (values.size() != program.header.input_columns.size())
        throw std::runtime_error("public-control-extra-input");
    const auto actual = evaluate_public_trace_for_controls(program, std::move(inputs), std::stoull(argv[14]));
    const auto expected = read_values(argv[12], "PUBLIC_FIXTURE_EXPECTED_V1");
    if (expected.size() != actual.model.size())
        throw std::runtime_error("public-control-model-size");
    for (size_t i = 0; i < actual.model.size(); ++i)
        if (expected[i].first != i || expected[i].second != actual.model[i])
            throw std::runtime_error("public-control-model-differential");
    std::vector<Fr> checks(actual.private_checks.size(), Fr(0));
    if (std::string(argv[13]) != "-") {
        const auto expected_checks = read_values(argv[13], "PUBLIC_FIXTURE_EXPECTED_CHECKS_V1");
        if (expected_checks.size() != checks.size())
            throw std::runtime_error("public-control-check-size");
        for (size_t i = 0; i < checks.size(); ++i) {
            if (expected_checks[i].first != i)
                throw std::runtime_error("public-control-check-order");
            checks[i] = expected_checks[i].second;
        }
    }
    if (checks != actual.private_checks)
        throw std::runtime_error("public-control-ordered-check-differential");
    if (program.binding.prefix_recipe) {
        const auto& outputs = program.binding.prefix_recipe->outputs();
        for (size_t limb = 0; limb < outputs.size(); ++limb) {
            Fr value(0);
            for (const auto& term : outputs[limb]) value += actual.model[term.column] * term.coefficient;
            if (value != actual.model[limb + 1])
                throw std::runtime_error("public-control-prefix-recipe-differential");
        }
    }
    std::cout << "PUBLIC_TRACE_EVALUATION_PASS " << actual.model.size() << ' '
              << actual.private_checks.size() << '\n';
}

int main(int argc, char** argv) {
    try {
        initialize_bn254_field();
        if (argc == 2 && std::string(argv[1]) == "arithmetic") {
            arithmetic();
            return 0;
        }
        const std::string command = argc > 1 ? argv[1] : "";
        const bool prefix = command == "inspect-prefix" || command == "evaluate-prefix";
        const auto selected_argc = argc - (prefix ? 2 : 0);
        const bool evaluate = (selected_argc == 15 || selected_argc == 17 || selected_argc == 19) &&
                              (command == "evaluate" || command == "evaluate-prefix");
        if (!evaluate && ((selected_argc != 11 && selected_argc != 13 && selected_argc != 15) ||
                          (command != "inspect" && command != "inspect-prefix")))
            throw std::runtime_error("public-control-arguments");
        std::vector<int> roles;
        std::string selected(argv[10]);
        if (selected != "-") {
            size_t start = 0;
            while (true) {
                const auto comma = selected.find(',', start);
                roles.push_back(std::stoi(selected.substr(start, comma - start)));
                if (comma == std::string::npos) break;
                start = comma + 1;
            }
        }
        TraceBinding binding{argv[3], argv[4], argv[5], argv[6], argv[9], roles,
                             std::stoull(argv[7]), std::stoull(argv[8])};
        if ((!evaluate && selected_argc >= 13) || (evaluate && selected_argc >= 17)) {
            const auto start = evaluate ? 15 : 11;
            binding.container_sha256 = argv[start];
            binding.canonical_bytes = std::stoull(argv[start + 1]);
            if ((!evaluate && selected_argc == 15) || (evaluate && selected_argc == 19)) {
                binding.layout_container_sha256 = argv[start + 2];
                binding.layout_canonical_bytes = std::stoull(argv[start + 3]);
            }
        }
        if (prefix)
            binding.prefix_recipe = PrefixRecipe::load(argv[argc - 2], argv[argc - 1],
                                                        binding.model_variables, binding.instances);
        const auto program = inspect_trace(argv[2], binding);
        if (evaluate) {
            evaluate_control(program, argv);
            return 0;
        }
        std::cout << "PUBLIC_TRACE_INSPECT_PASS " << program.header.variables << ' '
                  << program.header.operations << '\n';
        return 0;
    } catch (const std::exception& error) {
        // Only public parser/control categories reach this executable.
        std::cout << "PUBLIC_CONTROL_REFUSED " << error.what() << '\n';
        return 1;
    }
}
