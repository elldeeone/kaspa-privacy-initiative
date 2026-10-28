#pragma once
#include "auth_field.hpp"
#include "ExternalIO/Client.h"
#include "owner_connections.hpp"
#include <array>
#include <filesystem>
#include <set>

#ifdef NO_CLIENT_TLS
#error "The owner-input boundary requires authenticated TLS"
#endif

namespace kpi::mpc {
struct OwnerInputContract {
    std::string run_nonce;
    std::string model_identity;
    std::string source_identity;
    std::string proving_key_identity;
    std::string verifying_key_identity;
    std::string cohort_identity;
    int owner_id;
    size_t input_count;
    std::array<std::string, 3> server_certificate_sha256;
    std::string owner_certificate_sha256;
    // Both empty means the retained V1 toy contract. V2 binds the exact
    // joint recipe and owner-column map before the owner acknowledges masks.
    std::string trace_identity;
    std::string layout_identity;
};

std::string canonical_owner_contract(const OwnerInputContract& contract);
OwnerInputContract load_owner_contract(const std::filesystem::path& path);

class ActiveOwnerInputServer {
    MascotContext& context_;
    PatientOwnerConnections clients_;
    int port_base_;
    std::set<int> consumed_roles_;

public:
    ActiveOwnerInputServer(MascotContext& context, int port_base);
    std::vector<AuthScalar> receive(const OwnerInputContract& contract);
};

// A separate owner process supplies its own canonical private values, connects
// to all three selected servers, checks strict 3*n triples, and never exports
// reconstructed masks or plaintext to a computing server/coordinator.
void send_private_inputs_active(const std::array<std::string, 3>& hostnames,
                                int port_base,
                                const OwnerInputContract& contract,
                                std::span<const Fr> private_values);
}  // namespace kpi::mpc
