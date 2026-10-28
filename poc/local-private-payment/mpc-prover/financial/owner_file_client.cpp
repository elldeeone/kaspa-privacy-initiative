#include "../owner_inputs_active.hpp"
#include "owner_file_format.hpp"
#include <iostream>
#include <stdexcept>

int main(int argc, char** argv) {
    try {
        if (argc != 7) throw std::runtime_error("financial-owner-client-arguments");
        kpi::mpc::initialize_bn254_field();
        const auto contract = kpi::mpc::load_owner_contract(argv[1]);
        // No V1 toy contract or shape override can admit a financial input.
        if (contract.trace_identity.empty() || contract.layout_identity.empty()
            || contract.owner_id < 0 || contract.owner_id > 2
            || contract.input_count != 2635409)
            throw std::runtime_error("financial-owner-selected-V2-contract");
        size_t consumed;
        const std::string text(argv[2]);
        const int port = std::stoi(text, &consumed);
        if (consumed != text.size() || text != std::to_string(port)
            || port < 1024 || port > 65533)
            throw std::runtime_error("financial-owner-port");
        // Parse completely BEFORE TLS/masks. Wrong jobs are independently
        // refused by all three authenticated V2 contract/TLS acknowledgements
        // in the unchanged send_private_inputs_active protocol.
        const auto values = kpi::mpc::financial::load_owner_fr32_input_file(argv[6],
            contract.owner_id, contract.input_count,
            [](const ::bigint& canonical) { return kpi::mpc::Fr(canonical); });
        kpi::mpc::send_private_inputs_active({argv[3], argv[4], argv[5]}, port, contract, values);
        std::cout << "{\"owner_input_status\":\"submitted\"}\n";
        return 0;
    } catch (...) {
        // No path, value, mask, key, parser error or private exception export.
        std::cerr << "{\"owner_input_status\":\"refused\"}\n";
        return 1;
    }
}
