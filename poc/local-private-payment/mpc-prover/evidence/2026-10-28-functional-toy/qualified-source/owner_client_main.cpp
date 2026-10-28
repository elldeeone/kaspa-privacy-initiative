#include "owner_inputs_active.hpp"
#include <iostream>
#include <stdexcept>

int main(int argc, char** argv) {
    try {
        if (argc != 6)
            throw std::runtime_error("usage: owner-client CONTRACT PORT_BASE HOST0 HOST1 HOST2; private canonical Fr values on stdin");
        kpi::mpc::initialize_bn254_field();
        const auto contract = kpi::mpc::load_owner_contract(argv[1]);
        size_t consumed;
        const int port = std::stoi(argv[2], &consumed);
        if (consumed != std::string(argv[2]).size() || port < 1024 || port > 65533)
            throw std::runtime_error("owner-port-range");
        std::vector<kpi::mpc::Fr> values;
        for (size_t i = 0; i < contract.input_count; ++i) {
            std::string text;
            if (!(std::cin >> text))
                throw std::runtime_error("missing-owner-private-input");
            values.push_back(kpi::mpc::parse_fr(text));
        }
        std::string trailing;
        if (std::cin >> trailing)
            throw std::runtime_error("trailing-owner-private-input");
        kpi::mpc::send_private_inputs_active({argv[3], argv[4], argv[5]}, port,
                                            contract, values);
        std::cout << "{\"owner_input_status\":\"submitted\"}\n";
        return 0;
    } catch (...) {
        // Fixed public status only; never serialize input/mask/key exceptions.
        std::cerr << "{\"owner_input_status\":\"refused\"}\n";
        return 1;
    }
}
