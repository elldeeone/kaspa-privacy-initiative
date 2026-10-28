#include "batched_assignment.hpp"
void illegal(kpi::mpc::MascotContext& context) {
    using namespace kpi::mpc;
    ValidatedAssignment forged(context, PublicModel{}, std::vector<AuthScalar>{},
        std::vector<AuthScalar>{}, std::vector<AuthScalar>{}, BatchedValidationBinding{}, "", "", 0);
}
