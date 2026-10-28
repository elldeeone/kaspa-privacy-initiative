#include "batched_assignment.hpp"
void illegal(kpi::mpc::ValidatedAssignment& target, const kpi::mpc::ValidatedAssignment& source) {
    target = source;
}
