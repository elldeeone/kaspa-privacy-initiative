#pragma once

// Contract implemented by a selected TLS Player transport. This interface
// performs no I/O and grants no authority by itself. A configured
// RegisteredService cross-casts its existing Player to this interface and
// compares the complete immutable binding before accepting the transport.
#include "../history/epoch_journal.hpp"
#include <array>
#include <string>

namespace kpi::mpc::financial {

struct RegisteredRosterBinding {
    std::string trial_id;
    history::Digest selection_candidate;
    history::Digest registration;
    history::Digest trial_authority;
    history::Digest ready_checkpoint;
    history::Digest certificate_authority;
    std::array<history::Digest, 3> server_certificates;

    // Accepted-head acquisition and its closed runner are independently
    // source/build bound. Imported head reports cannot satisfy this contract.
    history::Digest accepted_head_source_closure;
    history::Digest accepted_head_build;

    // The current public exporter adapter, its native source manifest, and
    // its native binary are fixed independently. A configured selection must
    // additionally provide the still-missing FixedPublicProgram SPEC.
    history::Digest exporter_adapter;
    history::Digest exporter_source_closure;
    history::Digest exporter_build;

    // The complete registered financial qualifier closure/build is distinct
    // from the historical fixed Source05 qualification.
    history::Digest qualifier_source_closure;
    history::Digest qualifier_build;
    history::Digest qualifier_authority_build;
    history::Digest qualifier_build_contract;
    history::Digest qualifier_configuration_selection;

    // Native selection remains explicit even when other relation bytes match.
    history::Digest native_parameters;
    history::Digest immutable_tail;
    history::Digest component_profile;
    history::Digest outer_image;
    history::Digest native_program;
    history::Digest native_codec;

    bool operator==(const RegisteredRosterBinding&) const = default;
};

class RosterPinnedPlayer {
public:
    virtual ~RosterPinnedPlayer() = default;
    virtual const std::array<history::Digest, 3>&
        authenticated_roster() const noexcept = 0;
    virtual const RegisteredRosterBinding&
        authenticated_registered_binding() const noexcept = 0;
};

} // namespace kpi::mpc::financial
