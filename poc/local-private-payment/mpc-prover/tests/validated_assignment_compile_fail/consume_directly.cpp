#include "batched_assignment.hpp"
void illegal(kpi::mpc::ValidatedAssignment& target, kpi::mpc::MascotContext& context,
             const kpi::mpc::BatchedValidationBinding& binding) {
    target.consume_for_proof(context, binding);
}
