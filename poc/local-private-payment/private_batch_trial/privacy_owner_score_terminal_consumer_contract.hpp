#pragma once

// Complete dependency-neutral name for the future sole closed-sum consumer.
// It deliberately has no operation while its three required live inputs do
// not exist. A hostile translation unit cannot redefine the name and obtain
// friendship later.

namespace kpb::measurement::score_terminal {

class OwnerScoreTerminalConsumerBridge final {
public:
    OwnerScoreTerminalConsumerBridge() = delete;
};

} // namespace kpb::measurement::score_terminal
