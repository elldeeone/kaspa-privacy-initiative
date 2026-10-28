#pragma once
#include "registered_service.hpp"
#include "../owner_inputs_active.hpp"
#include "../packed/packed_model.hpp"
#include "../trace/trace_witness.hpp"

namespace kpi::mpc::financial {
class AcceptedFinancialHead;
class FinancialConstruction;
class RegisteredSelectionAccess;

// Authority is produced by direct accepted-head acquisition and direct pinned
// public compilation. Neither this metadata nor a serialized receipt can
// construct this one-use capability.
class RegisteredFinancialSelection {
    struct Storage;
    const std::shared_ptr<const Storage> storage_;
    const MascotContext* const context_;
    const uint64_t generation_, epoch_, checked_counter_;
    bool consumed_ = false;
    RegisteredFinancialSelection(MascotContext&, std::shared_ptr<const Storage>);
    void consume_for_lock(MascotContext&);
    const TraceProgram& program() const;
    const packed::PackedModel& model() const;
    const RegisteredService& service() const;
    std::span<const unsigned char> native_tail() const;
    friend class FinancialConstruction;
    friend class RegisteredSelectionAccess;
public:
    RegisteredFinancialSelection(const RegisteredFinancialSelection&) = delete;
    RegisteredFinancialSelection(RegisteredFinancialSelection&&) = delete;
    RegisteredFinancialSelection& operator=(const RegisteredFinancialSelection&) = delete;
    RegisteredFinancialSelection& operator=(RegisteredFinancialSelection&&) = delete;
    ~RegisteredFinancialSelection();
    static RegisteredFinancialSelection admit(MascotContext&, const RegisteredService&,
        AcceptedFinancialHead&&, const packed::PackedModel&);
    void require_live(MascotContext&) const;
    const std::string& identity() const;
    const TraceBinding& trace_binding() const;
    size_t expected_trace_assertions() const;
    std::array<size_t, 3> owner_input_counts() const;
    // The job may choose fresh attempt/cohort identifiers. All head/context,
    // source, store, policy and compiler authority comes from this selection.
    history::AttemptBinding attempt_binding(MascotContext&,
        const std::array<OwnerInputContract, 3>&,
        const history::Digest& attempt, const history::Digest& cohort) const;
};
} // namespace kpi::mpc::financial
