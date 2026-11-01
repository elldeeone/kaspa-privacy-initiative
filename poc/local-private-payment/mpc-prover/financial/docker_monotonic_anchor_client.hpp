#pragma once

// Parent-only C++ adapter for the bounded Docker monotonic-anchor service.
// This is a local Testnet research boundary; the rootful Docker operator can
// still roll back the volume and remains trusted.

#include "registered_attempt_supervisor.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>

namespace kpi::mpc::financial::docker_anchor {

using Digest = identity_registry::Digest;

struct PublicConfiguration {
    std::filesystem::path socket_path;
    Digest authority_identity;
    Digest configuration_identity;
    Digest instance_identity;
    std::uint32_t service_uid;
};

class SupervisorCapability final {
    std::array<unsigned char, 32> value_{};
    std::atomic_bool live_{true};
    explicit SupervisorCapability(std::array<unsigned char, 32>);
    friend class Client;
    friend class attempt_supervisor::RegisteredProposalBridge;
public:
    ~SupervisorCapability();
    SupervisorCapability(const SupervisorCapability&) = delete;
    SupervisorCapability& operator=(const SupervisorCapability&) = delete;
    SupervisorCapability(SupervisorCapability&&) noexcept;
    SupervisorCapability& operator=(SupervisorCapability&&) = delete;
#ifdef KPI_DOCKER_ANCHOR_CLIENT_TEST_SETUP
    static SupervisorCapability test_only_mint(const std::string& hex32);
#endif
};

class Client final : public attempt_supervisor::ExternalMonotonicAnchor {
    PublicConfiguration configuration_;
    std::array<unsigned char, 32> capability_{};
    std::mutex mutex_;
    bool poisoned_ = false;

    Client(PublicConfiguration, SupervisorCapability&&);
    friend class attempt_supervisor::RegisteredProposalBridge;
    attempt_supervisor::ExternalAnchorSnapshot snapshot_unlocked();
public:
    ~Client() override;
    Client(const Client&) = delete;
    Client(Client&&) = delete;
    Client& operator=(const Client&) = delete;
    Client& operator=(Client&&) = delete;

#ifdef KPI_DOCKER_ANCHOR_CLIENT_TEST_SETUP
    static Client test_only_connect(PublicConfiguration,
                                    SupervisorCapability&&);
#endif
    attempt_supervisor::ExternalAnchorSnapshot snapshot() override;
    void compare_and_advance(
        const attempt_supervisor::ExternalAnchorSnapshot& expected,
        const attempt_supervisor::ExternalAnchorSnapshot& next) override;
};

struct SourceStatus {
    std::string schema;
    std::string status;
    bool real_docker_controls;
    bool mutual_peer_credentials;
    bool selected_bridge_integration;
    bool selected_party_namespace_integration;
    bool docker_operator_can_rollback;
    bool registered_driver_configured;
    bool launch_authorized;
};

SourceStatus source_status();

} // namespace kpi::mpc::financial::docker_anchor
