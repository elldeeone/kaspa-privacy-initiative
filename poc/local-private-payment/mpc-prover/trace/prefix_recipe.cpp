#include "prefix_recipe.hpp"
#include "sealed_trace.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>

namespace kpi::mpc {
namespace {
[[noreturn]] void refuse(const char* reason) { throw std::runtime_error(reason); }

template<size_t N>
std::array<unsigned char, N> bytes(std::istream& input) {
    std::array<unsigned char, N> result{};
    input.read(reinterpret_cast<char*>(result.data()), result.size());
    if (input.gcount() != static_cast<std::streamsize>(result.size()))
        refuse("prefix-recipe-truncated");
    return result;
}

size_t count(std::istream& input) {
    const auto data = bytes<8>(input);
    uint64_t result = 0;
    for (size_t i = 0; i < data.size(); ++i)
        result |= static_cast<uint64_t>(data[i]) << (8 * i);
    if (result > std::numeric_limits<size_t>::max())
        refuse("prefix-recipe-integer-overflow");
    return static_cast<size_t>(result);
}

bigint integer(const std::array<unsigned char, 32>& data) {
    bigint result;
    mpz_import(result.get_mpz_t(), data.size(), -1, 1, 0, 0, data.data());
    return result;
}
}  // namespace

PrefixRecipe::PrefixRecipe(std::string identity, size_t variables, size_t instances,
    std::vector<PrefixLinear> outputs, std::vector<size_t> columns)
    : identity_(std::move(identity)), model_variables_(variables), instances_(instances),
      outputs_(std::move(outputs)), referenced_columns_(std::move(columns)) {}

std::shared_ptr<const PrefixRecipe> PrefixRecipe::load(const std::filesystem::path& path,
    const std::string& expected_identity, size_t model_variables, size_t instances) {
    if (expected_identity.size() != 64 ||
        expected_identity.find_first_not_of("0123456789abcdef") != std::string::npos ||
        instances < 2 || model_variables < instances)
        refuse("prefix-recipe-expected-binding");
    const auto artifact = SealedTraceArtifact::load(path);
    if (artifact->gzip() || artifact->canonical_sha256() != expected_identity ||
        artifact->container_sha256() != expected_identity)
        refuse("prefix-recipe-file-identity");
    auto input_owner = artifact->stream(); auto& input = *input_owner;
    const auto tag = bytes<16>(input);
    const std::string expected_tag("KPI_PREFIX_LC_V1", 16);
    if (!std::equal(tag.begin(), tag.end(), expected_tag.begin()) ||
        integer(bytes<32>(input)) != fr_modulus() || count(input) != model_variables ||
        count(input) != instances || count(input) != instances - 1)
        refuse("prefix-recipe-header-or-shape");
    std::vector<PrefixLinear> outputs;
    std::vector<size_t> columns;
    for (size_t output = 1; output < instances; ++output) {
        const auto terms = count(input);
        if (!terms || terms > model_variables || terms > artifact->canonical_bytes() / 40)
            refuse("prefix-recipe-linear-arity");
        PrefixLinear linear;
        bool has_witness = false;
        for (size_t i = 0; i < terms; ++i) {
            const auto coefficient = integer(bytes<32>(input));
            const auto column = count(input);
            if (coefficient <= 0 || coefficient >= fr_modulus() || column >= model_variables ||
                (column && column < instances) || (i && column <= linear.back().column))
                refuse("prefix-recipe-term-canonicality");
            has_witness = has_witness || column >= instances;
            linear.push_back({parse_fr(coefficient.get_str()), column});
            columns.push_back(column);
        }
        // Secret-derived mode must use actual witness terms. Known constants
        // have their own separately admitted public-prefix policy.
        if (!has_witness) refuse("prefix-recipe-constant-output");
        outputs.push_back(std::move(linear));
    }
    if (input.peek() != std::char_traits<char>::eof() || !input.eof())
        refuse("prefix-recipe-trailing-data");
    std::sort(columns.begin(), columns.end());
    columns.erase(std::unique(columns.begin(), columns.end()), columns.end());
    return std::shared_ptr<const PrefixRecipe>(new PrefixRecipe(expected_identity, model_variables,
        instances, std::move(outputs), std::move(columns)));
}
}  // namespace kpi::mpc
