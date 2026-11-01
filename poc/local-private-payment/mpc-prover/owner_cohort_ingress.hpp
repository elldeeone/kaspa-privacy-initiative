#pragma once

#include <array>
#include <cstddef>
#include <stdexcept>
#include <string_view>

namespace kpi::mpc {

inline constexpr std::string_view REGISTERED_COMMON_OWNER_INGRESS =
    "REGISTERED_COMMON_OWNER_INGRESS";

// Private, role-local state for the common owner ingress. Arrival order is
// deliberately not exposed: it is available only to the private capture
// observer at the actual authenticated socket boundary. MPC work is released
// in canonical role order after every owner has authenticated, so different
// network schedules cannot change all-three agreement/preprocessing order.
class OwnerCohortIngressState final {
    std::array<std::size_t, 3> fixed_frame_bytes_{};
    std::array<bool, 3> authenticated_{};
    std::array<bool, 3> uploaded_{};
    std::size_t authenticated_count_{};
    std::size_t canonical_role_{};
    bool sealed_{};

    [[noreturn]] static void refuse() {
        throw std::runtime_error("owner-hidden-cohort-ingress-refused");
    }

public:
    explicit OwnerCohortIngressState(
        const std::array<std::size_t, 3>& fixed_frame_bytes)
        : fixed_frame_bytes_(fixed_frame_bytes) {
        for (const auto bytes : fixed_frame_bytes_)
            if (bytes == 0 || bytes != fixed_frame_bytes_[0]) refuse();
    }

    void authenticated(unsigned role) {
        if (sealed_ || role >= authenticated_.size() ||
            authenticated_[role])
            refuse();
        authenticated_[role] = true;
        ++authenticated_count_;
    }

    void require_full_authentication() const {
        if (sealed_ || authenticated_count_ != authenticated_.size())
            refuse();
    }

    void upload_complete(unsigned role, std::size_t bytes) {
        require_full_authentication();
        if (role != canonical_role_ || role >= uploaded_.size() ||
            uploaded_[role] || bytes != fixed_frame_bytes_[role])
            refuse();
        uploaded_[role] = true;
        ++canonical_role_;
    }

    void seal() {
        require_full_authentication();
        if (canonical_role_ != uploaded_.size()) refuse();
        sealed_ = true;
    }

    bool sealed() const noexcept { return sealed_; }
};

} // namespace kpi::mpc
