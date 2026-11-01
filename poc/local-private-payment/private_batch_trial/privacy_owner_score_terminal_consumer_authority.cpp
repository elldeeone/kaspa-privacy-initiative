#include "privacy_owner_score_terminal_consumer_authority.hpp"

#include <utility>

namespace kpb::measurement::score_terminal {

#define KPB_DEFINE_OPAQUE_TERMINAL_AUTHORITY(Type)                          \
Type::Type(void* storage, void (*destroy)(void*) noexcept) noexcept         \
    : storage_(storage), destroy_storage_(destroy) {}                       \
Type::Type(Type&& other) noexcept                                           \
    : storage_(std::exchange(other.storage_, nullptr)),                     \
      destroy_storage_(std::exchange(other.destroy_storage_, nullptr)) {}   \
Type::~Type() {                                                            \
    if (storage_ != nullptr && destroy_storage_ != nullptr)                 \
        destroy_storage_(storage_);                                         \
}

KPB_DEFINE_OPAQUE_TERMINAL_AUTHORITY(
    RunMeasurementOwnerScoreOutcomeTransferAuthority)
KPB_DEFINE_OPAQUE_TERMINAL_AUTHORITY(OwnerScoreDurableStopSinkAuthority)
KPB_DEFINE_OPAQUE_TERMINAL_AUTHORITY(
    OwnerScoreAggregateComparisonConsumerAuthority)
KPB_DEFINE_OPAQUE_TERMINAL_AUTHORITY(
    OwnerScoreTerminalConsumeResultAuthority)

#undef KPB_DEFINE_OPAQUE_TERMINAL_AUTHORITY

} // namespace kpb::measurement::score_terminal
