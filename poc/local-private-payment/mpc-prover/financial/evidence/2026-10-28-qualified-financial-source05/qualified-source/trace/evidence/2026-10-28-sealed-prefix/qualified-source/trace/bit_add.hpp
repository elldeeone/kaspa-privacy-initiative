#pragma once
#include "../auth_field.hpp"
#include <stdexcept>

namespace kpi::mpc::trace_detail {

// The same arithmetic kernel is instantiated for authenticated shares in the
// interpreter and public Fr fixtures in differential controls. The latter is
// an arithmetic oracle check, not evidence of an executed private protocol.
template<class Context, class Scalar>
std::vector<Scalar> add_words(Context& context, const std::vector<Scalar>& first,
                             const std::vector<Scalar>& second) {
    if (first.size() != second.size() || first.empty())
        throw std::runtime_error("trace-add-runtime-arity");
    const auto width = first.size();
    auto generate = context.multiply_batch(first, second);
    std::vector<Scalar> original, propagate;
    original.reserve(width);
    for (size_t i = 0; i < width; ++i)
        original.push_back(first[i] + second[i] - generate[i] * Fr(2));
    propagate = original;
    // Binary generate/propagate composition is a fixed public schedule. Its
    // ANDs use authenticated multiplication when Scalar is AuthScalar.
    for (size_t distance = 1; distance < width; distance *= 2) {
        std::vector<Scalar> left, right;
        for (size_t i = distance; i < width; ++i) {
            left.push_back(propagate[i]); right.push_back(generate[i - distance]);
            left.push_back(propagate[i]); right.push_back(propagate[i - distance]);
        }
        const auto products = context.multiply_batch(left, right);
        auto next_generate = generate;
        auto next_propagate = propagate;
        for (size_t i = distance; i < width; ++i) {
            const auto at = 2 * (i - distance);
            next_generate[i] = generate[i] + products[at];
            next_propagate[i] = products[at + 1];
        }
        generate = std::move(next_generate);
        propagate = std::move(next_propagate);
    }
    std::vector<Scalar> left, right;
    for (size_t i = 1; i < width; ++i) {
        left.push_back(original[i]); right.push_back(generate[i - 1]);
    }
    const auto products = context.multiply_batch(left, right);
    std::vector<Scalar> result;
    result.reserve(width);
    result.push_back(original[0]);
    for (size_t i = 1; i < width; ++i)
        result.push_back(original[i] + generate[i - 1] - products[i - 1] * Fr(2));
    return result;
}

}  // namespace kpi::mpc::trace_detail
