#include "batched_assignment.hpp"
void illegal(kpi::mpc::ValidatedAssignment& target, kpi::mpc::ValidatedAssignment&& source) {
    target = std::move(source);
}
