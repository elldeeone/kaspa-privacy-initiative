#pragma once
// Implementation-private shared definition for the two closed constructor
// translation units. This header provides no public constructor or factory.
#include "construction.hpp"

namespace kpi::mpc::financial {
struct FinancialConstruction::Storage {
    const packed::PackedModel model;
    const std::vector<AuthScalar> assignment, checks, prefix;
    const std::vector<unsigned char> tail;
    // Only the private history capability advances its one-use state. Shared
    // ownership never exposes a mutable witness, checks or promised prefix.
    const std::unique_ptr<history::LockedAttempt> locked;
    Storage(const packed::PackedModel& m, std::vector<AuthScalar> a, std::vector<AuthScalar> c,
            std::vector<AuthScalar> p, std::vector<unsigned char> t,
            std::unique_ptr<history::LockedAttempt> l)
        : model(m), assignment(std::move(a)), checks(std::move(c)), prefix(std::move(p)),
          tail(std::move(t)), locked(std::move(l)) {}
};
} // namespace kpi::mpc::financial
