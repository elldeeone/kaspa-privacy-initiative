#pragma once
#include "../history/epoch_ticket.hpp"
#include "../owner_inputs_active.hpp"
#include "../packed/packed_model.hpp"
#include "../trace/trace_witness.hpp"
#include "financial_assignment.hpp"
#include "registered_driver_bridge.hpp"
#include "baseline_owner_effects_recipe.hpp"
#include "authenticated_baseline_owner_receiver.hpp"
#include <array>

namespace kpi::mpc::financial {
class RegisteredFinancialSelection;
namespace registered_driver {
class DriverAttempt;
class AuthorizedDriverAttempt;
class RegisteredCaptureSession;
}

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
    registered_driver::AuthorizedDriverAttempt& registered_authority() const;
    registered_driver::RegisteredCaptureSession&
        registered_capture_session() const;
    void require_live(MascotContext&, const history::AttemptBinding&) const;
    friend class FinancialValidatedAssignment;
    friend class FinancialHistoryAccess;
    friend class RegisteredBaselineConstructionBridge;
    friend class registered_driver::baseline_disclosure::
        BaselineOwnerEffectsRecipeBridge;
    friend class registered_driver::baseline_disclosure::
        AuthenticatedBaselineOwnerReceiver;
    friend class registered_driver::baseline_disclosure::
        ExplicitOwnerPublicEffectsAuthority;
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
        const std::array<OwnerInputContract, 3>&, const history::AttemptBinding&,
        registered_driver::DriverAttempt&&);

    const std::string& binding_identity() const { return binding_identity_; }
};

// Fully defined authority adapter: it can extract the one-shot post-EGRESS
// baseline claim from a genuine FinancialConstruction, but accepts no public
// receipt, digest or caller Boolean.
class RegisteredBaselineConstructionBridge final {
public:
    static registered_driver::AuthorizedDriverAttempt::BaselineEffectsClaim
    claim_baseline_effects(const FinancialConstruction&);
};
}  // namespace kpi::mpc::financial
