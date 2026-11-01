#pragma once

#include "registered_selection_authority_contract.hpp"
#include "registered_service.hpp"
#include <array>
#include <memory>

namespace kpi::mpc::financial {

// Plain, immutable public facts. This structure alone is never accepted-head
// authority: only the private factory below can create that capability.
struct AcceptedHeadBinding {
    history::EpochKey key;
    history::Digest service_identity, registration, genesis_case;
    history::Digest public_history, identity, native_parameters, immutable_tail;
    history::Point genesis_point, point;
    history::State state;
    history::ScriptPublicKey script_public_key;
    uint64_t reserve_sompi;
    std::array<unsigned char, 276> context;
};

// ADR0079: independently acquire the fixed registered GEN3 origin, replay every
// accepted transition with the selected SDK/native/proof programs, and finish
// with a fresh current-UTXO check. No report import or caller head/config entry.
class AcceptedFinancialHead {
    struct Storage;
    const std::shared_ptr<const Storage> storage_;
    const MascotContext* const context_;
    const uint64_t generation_, epoch_;
    bool consumed_ = false;
    AcceptedFinancialHead(MascotContext&, std::shared_ptr<const Storage>);
    void consume_for_selection(MascotContext&, const history::Digest& service,
                               const history::Digest& public_history);
    friend class RegisteredSelectionAccess;
public:
    AcceptedFinancialHead(const AcceptedFinancialHead&) = delete;
    AcceptedFinancialHead(AcceptedFinancialHead&&) = delete;
    AcceptedFinancialHead& operator=(const AcceptedFinancialHead&) = delete;
    AcceptedFinancialHead& operator=(AcceptedFinancialHead&&) = delete;
    ~AcceptedFinancialHead();
    static AcceptedFinancialHead acquire_fresh(MascotContext&, const RegisteredService&);
    const AcceptedHeadBinding& binding() const;
    const std::vector<unsigned char>& public_history_bytes() const;
};
} // namespace kpi::mpc::financial
