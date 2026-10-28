#pragma once
#include "../history/epoch_ticket.hpp"
#include "../owner_inputs_active.hpp"
#include "../packed/packed_model.hpp"
#include "../trace/trace_witness.hpp"
#include <array>

namespace kpi::mpc::financial {
class FinancialValidatedAssignment;
class FinancialHistoryAccess;
class RegisteredFinancialSelection;

// Construction authority for the selected RFC-0030 financial relation. It
// receives owners itself after a real durable LOCK, then owns all authenticated
// data. Public metadata identities do not commit or expose private share bytes.
class FinancialConstruction {
    struct Storage;
    const std::shared_ptr<const Storage> storage_;
    const MascotContext* const context_;
    const uint64_t generation_, epoch_, construction_check_counter_;
    const history::AttemptBinding attempt_;
    const std::string binding_identity_;

    FinancialConstruction(MascotContext&, std::shared_ptr<const Storage>,
                          history::AttemptBinding, std::string);
    // Only trusted validation/history classes may retain an immutable copy.
    FinancialConstruction(const FinancialConstruction&) = default;
    const packed::PackedModel& model() const;
    std::span<const AuthScalar> assignment() const;
    std::span<const AuthScalar> trace_checks() const;
    std::span<const AuthScalar> promised_prefix() const;  // Excludes ONE.
    std::span<const AuthScalar> core_bits() const;
    // Canonically sorted input-record index, never an owner attribution.
    std::span<const AuthScalar> nullifier_bits(size_t sorted_input_index) const;
    std::span<const unsigned char> native_tail() const;
    history::LockedAttempt& locked_attempt() const;
    void require_live(MascotContext&, const history::AttemptBinding&) const;
    friend class FinancialValidatedAssignment;
    friend class FinancialHistoryAccess;
public:
    FinancialConstruction(FinancialConstruction&&) = delete;
    FinancialConstruction& operator=(const FinancialConstruction&) = delete;
    FinancialConstruction& operator=(FinancialConstruction&&) = delete;
    ~FinancialConstruction();

    static constexpr size_t CORE_BYTES = 10364;
    static constexpr size_t CORE_FIRST_BIT_COLUMN = 201;
    static constexpr size_t CORE_BIT_COUNT = CORE_BYTES * 8;
    static constexpr size_t CONTEXT_CHECKS = 276;
    static constexpr size_t OWNER_INPUT_COUNT = 2635409;

    // Public metadata helpers let a driver form the exact AttemptBinding
    // before acquiring LOCK. Neither helper authorizes intake or proof.
    static history::Digest input_map_identity(const packed::PackedModel&);
    static history::Digest owner_contracts_identity(const std::array<OwnerInputContract, 3>&);
    static history::Digest native_parameters_identity();

    // No owner values, WTNS, caller-selected core/NF columns, promised prefix
    // values, preflight Boolean or synthetic ticket are accepted here.
    static FinancialConstruction construct(MascotContext&, const packed::PackedModel&,
        const std::filesystem::path& trace_path, const TraceBinding&, const std::array<OwnerInputContract, 3>&,
        std::span<const unsigned char> selected_native_tail,
        history::EpochJournal&, const history::AttemptBinding&, int owner_port,
        size_t multiplication_batch = 4096);

    // Registered callers cannot supply a journal, context/head, native tail,
    // program path or preflight claim. The consumed accepted-head/compiler
    // capability supplies them, and only its fixed existing store is opened.
    static FinancialConstruction construct_registered(MascotContext&, RegisteredFinancialSelection&&,
        const std::array<OwnerInputContract, 3>&, const history::AttemptBinding&, int owner_port,
        size_t multiplication_batch = 4096);

    const std::string& binding_identity() const { return binding_identity_; }
};
}  // namespace kpi::mpc::financial
