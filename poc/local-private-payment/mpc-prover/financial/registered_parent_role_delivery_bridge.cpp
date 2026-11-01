#include "registered_parent_role_fork.hpp"

#include <array>
#include <cstdint>

namespace kpi::mpc::financial::attempt_supervisor {
namespace {

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }

std::array<int, 2> expected_capture_fds(
        unsigned round, unsigned role, std::uint8_t& count) {
    need((round == 1 || round == 2) && role < 3);
    const int offset = round == 1 ? 0 : 5;
    if (role == 0) {
        count = 2;
        return {20 + offset, 22 + offset};
    }
    if (role == 1) {
        count = 1;
        return {23 + offset, -1};
    }
    count = 0;
    return {-1, -1};
}

} // namespace

registered_driver::AuthenticatedPartyDeliveryAuthority
RegisteredProposalBridge::authenticated_party_delivery(
        registered_driver::ParentAuthenticatedPartyDeliveryAuthority&&
            delivered,
        const registered_driver::CompiledDriverSelection& driver) {
    try {
        need(delivered.live_.exchange(false));
        const auto& value = delivered.value_;
        const auto& selected = driver.value_;
        need(value.role < 3 && value.role == selected.role &&
             (value.round == 1 || value.round == 2) &&
             value.parent_pid > 1 && value.child_pid > 1 &&
             value.parent_pid != value.child_pid &&
             value.authority_identity == selected.authority_identity &&
             value.service_identity == selected.service_identity &&
             value.driver_selection_identity == driver.identity_ &&
             value.capture_source_identity ==
                 selected.capture_source_identity &&
             value.capture_build_identity ==
                 selected.capture_build_identity &&
             value.capture_launcher_identity ==
                 selected.capture_launcher_identity);
        for (const auto* field : {
                 &value.authority_identity, &value.supervisor_session,
                 &value.party_session, &value.service_identity,
                 &value.driver_selection_identity,
                 &value.capture_plan_identity,
                 &value.capture_source_identity,
                 &value.capture_build_identity,
                 &value.capture_launcher_identity,
                 &value.fork_plan_identity, &value.offer_identity,
                 &value.ack_identity})
            need(*field != identity_registry::Digest{});
        std::uint8_t count = 0;
        const auto expected = expected_capture_fds(
            value.round, value.role, count);
        need(value.fixed_capture_fd_count == count &&
             value.fixed_capture_fds == expected);
        return registered_driver::AuthenticatedPartyDeliveryAuthority(
            registered_driver::PublicAuthenticatedPartyDelivery{
                .role = value.role,
                .authority_identity = value.authority_identity,
                .supervisor_session = value.supervisor_session,
                .party_session = value.party_session,
                .service_identity = value.service_identity,
                .driver_selection_identity =
                    value.driver_selection_identity,
            });
    } catch (...) { refuse(); }
}

} // namespace kpi::mpc::financial::attempt_supervisor
