#pragma once

// Complete authority adapters for the accepted-head -> registered-selection
// -> construction path.  Each class is defined before private friendship is
// granted, so a hostile translation unit cannot define the friend name and
// mint, duplicate, consume, or inspect an authority.

#include "../history/epoch_journal.hpp"

#include <memory>
#include <span>

namespace kpi::mpc {

class MascotContext;
struct TraceProgram;
namespace packed { class PackedModel; }

namespace financial {

class AcceptedFinancialHead;
class RegisteredFinancialSelection;
class RegisteredService;
namespace registered_driver::baseline_disclosure {
class BaselineOwnerEffectsRecipe;
}

class RegisteredSelectionAccess final {
    RegisteredSelectionAccess() = delete;
public:
    static void consume_head(
        MascotContext&, AcceptedFinancialHead&, const RegisteredService&,
        const history::Digest& public_history);
};

class RegisteredServiceSelectionBridge final {
    RegisteredServiceSelectionBridge() = delete;
public:
    static RegisteredService retain(const RegisteredService&);
};

class RegisteredSelectionConstructionBridge final {
    RegisteredSelectionConstructionBridge() = delete;
public:
    static const TraceProgram& program(
        const RegisteredFinancialSelection&);
    static const packed::PackedModel& model(
        const RegisteredFinancialSelection&);
    static const RegisteredService& service(
        const RegisteredFinancialSelection&);
    static const std::shared_ptr<const registered_driver::baseline_disclosure::
        BaselineOwnerEffectsRecipe>& owner_effects_recipe(
            const RegisteredFinancialSelection&);
    static std::span<const unsigned char> native_tail(
        const RegisteredFinancialSelection&);
    static void consume_for_lock(
        RegisteredFinancialSelection&, MascotContext&,
        AcceptedFinancialHead&&);
};

} // namespace financial
} // namespace kpi::mpc
