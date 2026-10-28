#include "batched_assignment.hpp"
#include <type_traits>

using namespace kpi::mpc;
static_assert(!std::is_constructible_v<ValidatedAssignment, bool>);
static_assert(!std::is_copy_constructible_v<ValidatedAssignment>);
static_assert(!std::is_move_constructible_v<ValidatedAssignment>);
static_assert(!std::is_copy_assignable_v<ValidatedAssignment>);
static_assert(!std::is_move_assignable_v<ValidatedAssignment>);
static_assert(std::is_destructible_v<ValidatedAssignment>);
static_assert(std::is_same_v<decltype(std::declval<const ValidatedAssignment&>().binding_identity()), const std::string&>);
static_assert(std::is_same_v<decltype(std::declval<const ValidatedAssignment&>().public_challenge()), const std::string&>);
using ProofEntry = ProofPublic (*)(MascotContext&, ValidatedAssignment&&,
                                  const BatchedValidationBinding&);
static_assert(std::is_same_v<decltype(&prove_validated), ProofEntry>);

void rvalue_reference_to_same_capability_is_allowed(ValidatedAssignment& capability) {
    ValidatedAssignment&& same_instance = std::move(capability);
    static_cast<void>(same_instance);
}

void public_metadata_is_readable(const ValidatedAssignment& validated) {
    static_cast<void>(validated.binding_identity());
    static_cast<void>(validated.public_challenge());
    static_cast<void>(validated.residual_count());
    static_cast<void>(validated.validated_check_counter());
}
