#pragma once
#include "../auth_field.hpp"
#include <filesystem>
#include <memory>

namespace kpi::mpc {
struct PrefixTerm {
    Fr coefficient;
    size_t column;
};
using PrefixLinear = std::vector<PrefixTerm>;

// Public source-derived recipe, never a vector of caller prefix values.
// The expected identity must come from the admitted model metadata.
class PrefixRecipe {
    std::string identity_;
    size_t model_variables_, instances_;
    std::vector<PrefixLinear> outputs_;
    std::vector<size_t> referenced_columns_;
    PrefixRecipe(std::string, size_t, size_t, std::vector<PrefixLinear>, std::vector<size_t>);
public:
    PrefixRecipe(const PrefixRecipe&) = delete;
    PrefixRecipe& operator=(const PrefixRecipe&) = delete;
    static std::shared_ptr<const PrefixRecipe> load(const std::filesystem::path&,
        const std::string& expected_identity, size_t model_variables, size_t instances);
    const std::string& identity() const { return identity_; }
    size_t model_variables() const { return model_variables_; }
    size_t instances() const { return instances_; }
    const std::vector<PrefixLinear>& outputs() const { return outputs_; }
    const std::vector<size_t>& referenced_columns() const { return referenced_columns_; }
};
}  // namespace kpi::mpc
