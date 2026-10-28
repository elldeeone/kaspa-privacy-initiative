#include "batched_assignment.hpp"
void illegal(kpi::mpc::ValidatedAssignment&& source) {
    kpi::mpc::ValidatedAssignment moved(std::move(source));
}
