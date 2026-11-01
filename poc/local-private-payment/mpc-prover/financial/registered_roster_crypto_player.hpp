#pragma once

// Concrete encrypted three-party transport for the future selected registered
// driver. It verifies the certificate actually presented by every live TLS
// peer, agrees one immutable registered binding over those channels, and
// preserves that binding across MP-SPDZ forks. No selected authority factory or
// gate callsite exists while CONFIGURED remains zero.

#include "registered_roster_transport.hpp"
#include "registered_capture_plan_roster_bridge_contract.hpp"
#include "Networking/CryptoPlayer.h"

#ifdef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
#include "../../private_batch_trial/privacy_p1_corrupt_state_capsule_authority.hpp"
#endif

#include <array>
#include <atomic>
#include <memory>
#include <string>
#include <type_traits>

namespace kpi::mpc::financial::registered_driver {
class RegisteredRole1P1StateRecorderFacade;
}

namespace kpi::mpc::financial {

class RegisteredRosterPlayerRuntime;

struct PublicImmutableRosterSelection {
    unsigned role{};
    std::array<std::string, 3> hosts{};
    int port_base{};
    std::array<history::Digest, 3> server_certificates{};
    RegisteredRosterBinding registered_binding{};
    history::Digest transport_source_identity{};
    history::Digest transport_build_identity{};
    history::Digest transport_launcher_identity{};
};

static_assert(std::is_nothrow_move_constructible_v<
              PublicImmutableRosterSelection>);

class ImmutableRegisteredRosterAuthority final {
    PublicImmutableRosterSelection value_;
    history::Digest authority_identity_{};
    history::Digest transport_identity_{};
    std::atomic_bool live_{true};
    explicit ImmutableRegisteredRosterAuthority(
        PublicImmutableRosterSelection);
    void require_valid_for_capture_plan() const;
    friend class RegisteredRosterCryptoPlayer;
    friend class RegisteredRosterPlayerRuntime;
    friend class registered_driver::RegisteredCapturePlanRosterBridge;
public:
    ImmutableRegisteredRosterAuthority(
        const ImmutableRegisteredRosterAuthority&) = delete;
    ImmutableRegisteredRosterAuthority& operator=(
        const ImmutableRegisteredRosterAuthority&) = delete;
    ImmutableRegisteredRosterAuthority(
        ImmutableRegisteredRosterAuthority&&) noexcept;
    ImmutableRegisteredRosterAuthority& operator=(
        ImmutableRegisteredRosterAuthority&&) = delete;
#ifdef KPI_REGISTERED_ROSTER_TEST_SETUP
    static ImmutableRegisteredRosterAuthority test_only_mint(
        PublicImmutableRosterSelection);
#endif
};

class RegisteredRosterCryptoPlayer final
    : public ::CryptoPlayer, public RosterPinnedPlayer {
    const PublicImmutableRosterSelection selection_;
    const history::Digest transport_identity_;
#ifdef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
    p1_private_state::PlayerTlsStateHook* player_tls_state_{};
    std::string source_player_id_;
#endif

    RegisteredRosterCryptoPlayer(
        const ::Names&, PublicImmutableRosterSelection,
        history::Digest transport_identity, std::string id);
#ifdef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
    RegisteredRosterCryptoPlayer(
        const ::Names&, PublicImmutableRosterSelection,
        history::Digest transport_identity, std::string id,
        std::string parent_id,
        p1_private_state::PlayerTlsStateHook&);
#endif
    void require_live_tls_channels();
    void verify_live_roster_and_agree_binding();
public:
    RegisteredRosterCryptoPlayer(const RegisteredRosterCryptoPlayer&) = delete;
    RegisteredRosterCryptoPlayer& operator=(
        const RegisteredRosterCryptoPlayer&) = delete;
#ifdef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
    ~RegisteredRosterCryptoPlayer() override;
#endif

    static std::unique_ptr<RegisteredRosterCryptoPlayer> begin(
        const ::Names&, ImmutableRegisteredRosterAuthority&&);
#ifdef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
    static std::unique_ptr<RegisteredRosterCryptoPlayer> begin(
        const ::Names&, ImmutableRegisteredRosterAuthority&&,
        p1_private_state::PlayerTlsStateHook&);
#endif

    const std::array<history::Digest, 3>&
        authenticated_roster() const noexcept override;
    const RegisteredRosterBinding&
        authenticated_registered_binding() const noexcept override;
    const history::Digest& transport_identity() const noexcept {
        return transport_identity_;
    }
    ::Player* fresh_fork(std::string suffix) override;
#if defined(KPI_REGISTERED_ROSTER_TEST_SETUP) && \
    defined(KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1)
    enum class TestOnlyTlsLaneFault {
        Missing,
        Duplicate,
        SubstitutedPeer,
    };
    void test_only_require_tls_lane_fault_refuses(TestOnlyTlsLaneFault);
#endif
};

// Selected-child adapter.  It consumes the immutable roster capability and
// constructs Names only after the role fork, so no listening socket or player
// thread is inherited from the parent.  Names is retained for the complete
// CryptoPlayer lifetime.
class RegisteredRosterPlayerRuntime final {
    std::unique_ptr<::Names> names_;
#ifdef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
    std::unique_ptr<
        kpb::measurement::p1_state_capsule::P1PlayerTlsStateAdapter>
        player_tls_state_;
#endif
    std::unique_ptr<RegisteredRosterCryptoPlayer> player_;
    RegisteredRosterPlayerRuntime(
        std::unique_ptr<::Names>,
        std::unique_ptr<RegisteredRosterCryptoPlayer>);
#ifdef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
    RegisteredRosterPlayerRuntime(
        std::unique_ptr<::Names>,
        std::unique_ptr<
            kpb::measurement::p1_state_capsule::P1PlayerTlsStateAdapter>,
        std::unique_ptr<RegisteredRosterCryptoPlayer>);
#endif
public:
    RegisteredRosterPlayerRuntime(const RegisteredRosterPlayerRuntime&) =
        delete;
    RegisteredRosterPlayerRuntime& operator=(
        const RegisteredRosterPlayerRuntime&) = delete;
    RegisteredRosterPlayerRuntime(RegisteredRosterPlayerRuntime&&) = delete;
    RegisteredRosterPlayerRuntime& operator=(
        RegisteredRosterPlayerRuntime&&) = delete;

    static std::unique_ptr<RegisteredRosterPlayerRuntime> begin_after_fork(
        ImmutableRegisteredRosterAuthority&&);
#ifdef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
    static std::unique_ptr<RegisteredRosterPlayerRuntime> begin_after_fork(
        ImmutableRegisteredRosterAuthority&&,
        registered_driver::RegisteredRole1P1StateRecorderFacade&,
        const kpb::measurement::p1_state_capsule::
            P1StateThreadEpochAuthority&);
#endif
    RegisteredRosterCryptoPlayer& player() { return *player_; }
};

struct RegisteredRosterCryptoPlayerSourceStatus {
    std::string schema;
    std::string status;
    bool live_tls_certificate_authority_verified;
    bool live_tls_peer_certificate_der_verified;
    bool exact_three_role_binding_agreement;
    bool mp_spdz_fork_preserves_roster;
    bool source_pinned_player_tls_hook;
    bool private_state_runtime_overload;
    bool openssl_complete_private_state;
    bool accepts_argv_or_environment;
    bool selected_authority_factory_integration;
    bool selected_gate_callsite_integration;
    bool registered_driver_configured;
    bool launch_authorized;
};

RegisteredRosterCryptoPlayerSourceStatus
registered_roster_crypto_player_source_status();

} // namespace kpi::mpc::financial
