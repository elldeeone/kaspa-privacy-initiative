#include "../docker_monotonic_anchor_client.hpp"

#include <cassert>
#include <iostream>
#include <string>

using namespace kpi::mpc::financial;

namespace {
std::string capability_from_stdin() {
    std::string value;
    assert(bool(std::getline(std::cin, value)));
    std::string extra;
    assert(!std::getline(std::cin, extra));
    return value;
}

docker_anchor::PublicConfiguration configuration(char** argv) {
    return docker_anchor::PublicConfiguration{
        .socket_path = argv[2],
        .authority_identity = identity_registry::unhex(argv[3]),
        .configuration_identity = identity_registry::unhex(argv[4]),
        .instance_identity = identity_registry::unhex(argv[5]),
        .service_uid = 65532,
    };
}
} // namespace

int main(int argc, char** argv) {
    try {
        assert(argc >= 7);
        auto capability = docker_anchor::SupervisorCapability::test_only_mint(
            capability_from_stdin());
        auto client = docker_anchor::Client::test_only_connect(
            configuration(argv), std::move(capability));
        const std::string operation(argv[1]);
        if (operation == "status") {
            assert(argc == 8);
            const auto state = client.snapshot();
            assert(state.sequence == std::stoull(argv[6]));
            assert(state.checkpoint == identity_registry::unhex(argv[7]));
        } else if (operation == "advance") {
            assert(argc == 10);
            attempt_supervisor::ExternalAnchorSnapshot expected{
                .authority_identity = identity_registry::unhex(argv[3]),
                .sequence = std::stoull(argv[6]),
                .checkpoint = identity_registry::unhex(argv[7]),
            };
            attempt_supervisor::ExternalAnchorSnapshot next{
                .authority_identity = identity_registry::unhex(argv[3]),
                .sequence = std::stoull(argv[8]),
                .checkpoint = identity_registry::unhex(argv[9]),
            };
            client.compare_and_advance(expected, next);
            assert(client.snapshot() == next);
        } else {
            assert(false);
        }
        const auto status = docker_anchor::source_status();
        assert(status.real_docker_controls);
        assert(status.mutual_peer_credentials);
        assert(!status.selected_bridge_integration);
        assert(!status.selected_party_namespace_integration);
        assert(status.docker_operator_can_rollback);
        assert(!status.registered_driver_configured);
        assert(!status.launch_authorized);
        return 0;
    } catch (...) {
        return 1;
    }
}
