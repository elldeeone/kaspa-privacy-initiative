#pragma once
// Implementation-private shared definition for the two closed constructor
// translation units. This header provides no public constructor or factory.
#include "construction.hpp"
#include "registered_driver_bridge.hpp"

namespace kpi::mpc::financial {
struct FinancialConstruction::Storage {
    const packed::PackedModel model;
    const std::vector<AuthScalar> assignment, checks, prefix;
    const std::vector<unsigned char> tail;
    const std::shared_ptr<const registered_driver::baseline_disclosure::
        BaselineOwnerEffectsRecipe> owner_effects_recipe;
    const int baseline_owner_port;
    const std::array<OwnerInputContract, 3> baseline_owner_contracts;
    // Only the private history capability advances its one-use state. Shared
    // ownership never exposes a mutable witness, checks or promised prefix.
    const std::unique_ptr<history::LockedAttempt> locked;
    const std::unique_ptr<registered_driver::AuthorizedDriverAttempt>
        registered;
    Storage(const packed::PackedModel& m, std::vector<AuthScalar> a, std::vector<AuthScalar> c,
            std::vector<AuthScalar> p, std::vector<unsigned char> t,
            std::unique_ptr<history::LockedAttempt> l,
            std::unique_ptr<registered_driver::AuthorizedDriverAttempt> r = {},
            std::shared_ptr<const registered_driver::baseline_disclosure::
                BaselineOwnerEffectsRecipe> owner_recipe = {},
            int owner_port = 0,
            std::array<OwnerInputContract, 3> owner_contracts = {})
        : model(m), assignment(std::move(a)), checks(std::move(c)), prefix(std::move(p)),
          tail(std::move(t)), owner_effects_recipe(std::move(owner_recipe)),
          baseline_owner_port(owner_port),
          baseline_owner_contracts(std::move(owner_contracts)),
          locked(std::move(l)), registered(std::move(r)) {}
};
} // namespace kpi::mpc::financial
