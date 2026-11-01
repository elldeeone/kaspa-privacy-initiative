#include "../../p1_mac_check_source_capture.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace kpi::mpc::p1_private_state;

namespace {

void need(bool value) {
    if (!value) throw std::runtime_error("P1-MAC-check-source-control");
}

template<std::size_t N>
std::array<unsigned char, N> bytes(unsigned char first) {
    std::array<unsigned char, N> result{};
    for (std::size_t index = 0; index < result.size(); ++index)
        result[index] = static_cast<unsigned char>(first + index);
    return result;
}

struct Record final {
    MacCheckSourceSite site{};
    MacCheckEventIdentity identity;
    std::vector<unsigned char> encoding;
};

class Hook final : public MacCheckStateHook {
public:
    std::vector<Record> records;
    MacCheckSourceSite reject_site{};
    unsigned terminal_count{};
    unsigned unavailable_count{};
    bool terminal_accept{true};
    bool unavailable_accept{true};
    bool bypass_event_validation{};
    int unavailable_marker_fd{-1};
    MacCheckUnavailableSite last_unavailable_site{};
    MacCheckUnavailableReason last_unavailable_reason{};
    std::uint64_t last_completed_check_count{};
    std::uint64_t last_active_check_epoch{};
    std::uint64_t last_completed_edge_count{};
    std::uint64_t last_expected_thread_epoch{};
    std::uint64_t last_observed_thread_epoch{};
    std::uint64_t last_pending_open_count{};
    std::vector<unsigned char> last_unavailable_encoding;

    Hook() : MacCheckStateHook(TestOnlyConstruction{}) {}

    bool retain(
            MacCheckSourceSite site, const MacCheckEventIdentity& identity,
            std::vector<unsigned char> encoding) noexcept {
        try {
            records.push_back({site, identity, std::move(encoding)});
            return reject_site != site;
        }
        catch (...) {
            return false;
        }
    }

    bool record_mac_check_begin(
            const MacCheckBeginView& value) noexcept override {
        try {
            if (bypass_event_validation)
                return retain(
                    MacCheckSourceSite::CheckBegin, value.identity, {});
            return retain(
                MacCheckSourceSite::CheckBegin, value.identity,
                encode_mac_check_begin(value));
        } catch (...) { return false; }
    }

    bool record_mac_check_collective_seed(
            const MacCheckCollectiveSeedView& value) noexcept override {
        try {
            if (bypass_event_validation)
                return retain(
                    MacCheckSourceSite::CollectiveSeed,
                    value.identity, {});
            return retain(
                MacCheckSourceSite::CollectiveSeed, value.identity,
                encode_mac_check_collective_seed(value));
        } catch (...) { return false; }
    }

    bool record_mac_check_local_tau(
            const MacCheckLocalTauView& value) noexcept override {
        try {
            if (bypass_event_validation)
                return retain(
                    MacCheckSourceSite::LocalTau, value.identity, {});
            return retain(
                MacCheckSourceSite::LocalTau, value.identity,
                encode_mac_check_local_tau(value));
        } catch (...) { return false; }
    }

    bool record_mac_check_success_reset(
            const MacCheckSuccessResetView& value) noexcept override {
        try {
            if (bypass_event_validation)
                return retain(
                    MacCheckSourceSite::SuccessReset,
                    value.identity, {});
            return retain(
                MacCheckSourceSite::SuccessReset, value.identity,
                encode_mac_check_success_reset(value));
        } catch (...) { return false; }
    }

    bool mac_check_capture_terminal_noexcept() noexcept override {
        ++terminal_count;
        return terminal_accept;
    }

    bool record_mac_check_unavailable(
            const MacCheckUnavailableView& value) noexcept override {
        try {
            last_unavailable_encoding = encode_mac_check_unavailable(value);
            last_unavailable_site = value.site;
            last_unavailable_reason = value.reason;
            last_completed_check_count = value.completed_check_count;
            last_active_check_epoch = value.active_check_epoch;
            last_completed_edge_count = value.completed_edge_count;
            last_expected_thread_epoch = value.expected_thread_epoch;
            last_observed_thread_epoch = value.observed_thread_epoch;
            last_pending_open_count = value.pending_open_count;
            ++unavailable_count;
            if (unavailable_marker_fd >= 0) {
                const unsigned char marker = 0xb8;
                const auto written = ::write(
                    unavailable_marker_fd, &marker, 1);
                (void)written;
            }
            return unavailable_accept;
        } catch (...) { return false; }
    }
};

struct Fixture final {
    std::array<unsigned char, MAC_CHECK_FIELD_BYTES> alpha = bytes<32>(0x10);
    std::array<unsigned char, 2 * MAC_CHECK_FIELD_BYTES> values = bytes<64>(0x20);
    std::array<unsigned char, 2 * MAC_CHECK_FIELD_BYTES> macs = bytes<64>(0x40);
    std::array<unsigned char, MAC_CHECK_SEED_BYTES> seed = bytes<16>(0x60);
    std::array<unsigned char, 2 * MAC_CHECK_FIELD_BYTES> coefficients = bytes<64>(0x70);
    std::array<unsigned char, MAC_CHECK_FIELD_BYTES> tau = bytes<32>(0x90);
    std::array<unsigned char, MAC_CHECK_FIELD_BYTES> zero{};
};

void complete_attempt(Fixture& value) {
    auto attempt = MacCheckSourceBridge::test_only_check_begin(
        1, 3, 2, value.alpha, value.values, value.macs);
    MacCheckSourceBridge::test_only_collective_seed(attempt, value.seed);
    MacCheckSourceBridge::test_only_local_tau(
        attempt, 2, value.coefficients, value.tau);
    MacCheckSourceBridge::test_only_success_reset(attempt, 0, value.zero);
}

void exact_sequence_and_explicit_thread() {
    Fixture value;

    // No selected P1 scope is behavior-compatible and inert.
    complete_attempt(value);

    Hook hook;
    auto scope = MacCheckScopeFactoryBridge::test_only_install(
        hook, 71, 1, 101, 1, 3);
    complete_attempt(value);
    need(hook.records.size() == 4);
    for (std::size_t index = 0; index < hook.records.size(); ++index) {
        const auto& record = hook.records[index];
        need(static_cast<unsigned>(record.site) == index + 1 &&
             record.identity.logical_process_epoch == 71 &&
             record.identity.logical_thread_epoch == 101 &&
             record.identity.source_round == 1 &&
             record.identity.check_epoch == 1 &&
             record.identity.event_counter_before == index &&
             record.identity.event_counter_after == index + 1 &&
             record.identity.local_role == 1 &&
             record.identity.player_count == 3 &&
             record.identity.pending_open_count == 2);
        const std::string_view encoded(
            reinterpret_cast<const char*>(record.encoding.data()),
            record.encoding.size());
        need(encoded.starts_with(MAC_CHECK_EVENT_ENCODING_DOMAIN) &&
             encoded.find(mac_check_source_domain(record.site)) !=
                 std::string_view::npos);
    }

    std::thread worker([&] {
        auto binding = MacCheckScopeFactoryBridge::test_only_bind_thread(202);
        complete_attempt(value);
    });
    worker.join();
    need(hook.records.size() == 8);
    for (std::size_t index = 4; index < hook.records.size(); ++index)
        need(hook.records[index].identity.logical_thread_epoch == 202 &&
             hook.records[index].identity.check_epoch == 2);

    need(std::move(scope).finish_noexcept());
    need(hook.terminal_count == 1 && hook.unavailable_count == 0);
}

void dropped_and_terminal_refusal_are_unavailable() {
    Fixture value;
    {
        Hook hook;
        auto scope = MacCheckScopeFactoryBridge::test_only_install(
            hook, 72, 2, 102, 1, 3);
        {
            auto attempt = MacCheckSourceBridge::test_only_check_begin(
                1, 3, 2, value.alpha, value.values, value.macs);
            MacCheckSourceBridge::test_only_collective_seed(
                attempt, value.seed);
        }
        need(hook.unavailable_count == 1);
        need(hook.last_unavailable_site ==
                 MacCheckUnavailableSite::AttemptScope &&
             hook.last_unavailable_reason ==
                 MacCheckUnavailableReason::AttemptDropped &&
             hook.last_completed_check_count == 0 &&
             hook.last_active_check_epoch == 1 &&
             hook.last_completed_edge_count == 2 &&
             hook.last_expected_thread_epoch == 102 &&
             hook.last_observed_thread_epoch == 102 &&
             hook.last_pending_open_count == 2);
        const std::string_view unavailable(
            reinterpret_cast<const char*>(
                hook.last_unavailable_encoding.data()),
            hook.last_unavailable_encoding.size());
        need(unavailable.starts_with(
                 MAC_CHECK_UNAVAILABLE_ENCODING_DOMAIN) &&
             unavailable.find(mac_check_source_domain(
                 MacCheckSourceSite::CollectiveSeed)) !=
                 std::string_view::npos);
        need(!std::move(scope).finish_noexcept());
    }
    {
        Hook hook;
        hook.terminal_accept = false;
        auto scope = MacCheckScopeFactoryBridge::test_only_install(
            hook, 73, 2, 103, 1, 3);
        complete_attempt(value);
        need(!std::move(scope).finish_noexcept());
        need(hook.terminal_count == 1 && hook.unavailable_count == 1 &&
             hook.last_unavailable_site ==
                 MacCheckUnavailableSite::CaptureTerminal &&
             hook.last_unavailable_reason ==
                 MacCheckUnavailableReason::TerminalRejected &&
             hook.last_completed_check_count == 1 &&
             hook.last_active_check_epoch == 0 &&
             hook.last_completed_edge_count == 0 &&
             hook.last_expected_thread_epoch == 103 &&
             hook.last_observed_thread_epoch == 103);
    }
    {
        Hook hook;
        auto scope = MacCheckScopeFactoryBridge::test_only_install(
            hook, 75, 1, 105, 1, 3);
        need(!std::move(scope).finish_noexcept());
        need(hook.terminal_count == 0 && hook.unavailable_count == 1 &&
             hook.last_unavailable_site ==
                 MacCheckUnavailableSite::CaptureTerminal &&
             hook.last_unavailable_reason ==
                 MacCheckUnavailableReason::TerminalIncomplete &&
             hook.last_completed_check_count == 0 &&
             hook.last_active_check_epoch == 0 &&
             hook.last_completed_edge_count == 0);
    }
}

void protocol_failure_retains_prefix_and_nonzero_tau() {
    Fixture value;
    Hook hook;
    auto scope = MacCheckScopeFactoryBridge::test_only_install(
        hook, 74, 2, 104, 1, 3);
    auto attempt = MacCheckSourceBridge::test_only_check_begin(
        1, 3, 2, value.alpha, value.values, value.macs);
    MacCheckSourceBridge::test_only_collective_seed(attempt, value.seed);
    MacCheckSourceBridge::test_only_local_tau(
        attempt, 2, value.coefficients, value.tau);
    auto nonzero = value.zero;
    nonzero.back() = 1;
    MacCheckSourceBridge::test_only_failure_reset(
        attempt, 0, nonzero);
    need(hook.unavailable_count == 1 && hook.terminal_count == 0 &&
         hook.last_unavailable_site ==
             MacCheckUnavailableSite::FailureReset &&
         hook.last_unavailable_reason ==
             MacCheckUnavailableReason::ProtocolMacFailure &&
         hook.last_completed_check_count == 0 &&
         hook.last_active_check_epoch == 1 &&
         hook.last_completed_edge_count == 3 &&
         hook.last_expected_thread_epoch == 104 &&
         hook.last_observed_thread_epoch == 104 &&
         hook.last_pending_open_count == 2 &&
         hook.last_unavailable_encoding.size() >= nonzero.size() &&
         std::equal(
             nonzero.begin(), nonzero.end(),
             hook.last_unavailable_encoding.end() - nonzero.size()));
    need(!std::move(scope).finish_noexcept());
    need(hook.unavailable_count == 1 && hook.terminal_count == 0);
}

enum class AbortCase {
    WrongOrder,
    RejectedSeed,
    InvalidBeginWidth,
    UnboundWorker,
    InvalidCoefficientCount,
    InvalidCoefficientWidth,
    InvalidTauWidth,
    PendingNotReset,
    NonzeroTauSum,
    ProtocolTerminalRejected,
};

void expect_fail_stop(AbortCase selected) {
    int marker_pipe[2]{};
    need(::pipe(marker_pipe) == 0);
    const auto child = ::fork();
    need(child >= 0);
    if (child == 0) {
        (void)::close(marker_pipe[0]);
        const rlimit no_core{.rlim_cur = 0, .rlim_max = 0};
        if (::setrlimit(RLIMIT_CORE, &no_core) != 0)
            ::_exit(91);
        Fixture value;
        Hook hook;
        hook.unavailable_marker_fd = marker_pipe[1];
        if (selected == AbortCase::RejectedSeed)
            hook.reject_site = MacCheckSourceSite::CollectiveSeed;
        if (selected == AbortCase::ProtocolTerminalRejected)
            hook.unavailable_accept = false;
        if (selected == AbortCase::InvalidCoefficientCount ||
            selected == AbortCase::InvalidCoefficientWidth ||
            selected == AbortCase::InvalidTauWidth ||
            selected == AbortCase::PendingNotReset ||
            selected == AbortCase::NonzeroTauSum)
            hook.bypass_event_validation = true;
        auto scope = MacCheckScopeFactoryBridge::test_only_install(
            hook, 80, 1, 110, 1, 3);
        if (selected == AbortCase::InvalidBeginWidth) {
            std::array<unsigned char, MAC_CHECK_FIELD_BYTES - 1> short_alpha{};
            (void)MacCheckSourceBridge::test_only_check_begin(
                1, 3, 2, short_alpha, value.values, value.macs);
        } else if (selected == AbortCase::UnboundWorker) {
            std::thread worker([&] {
                (void)MacCheckSourceBridge::test_only_check_begin(
                    1, 3, 2, value.alpha, value.values, value.macs);
            });
            worker.join();
        } else {
            auto attempt = MacCheckSourceBridge::test_only_check_begin(
                1, 3, 2, value.alpha, value.values, value.macs);
            if (selected == AbortCase::WrongOrder) {
                MacCheckSourceBridge::test_only_local_tau(
                    attempt, 2, value.coefficients, value.tau);
            } else if (selected == AbortCase::RejectedSeed) {
                MacCheckSourceBridge::test_only_collective_seed(
                    attempt, value.seed);
            } else {
                MacCheckSourceBridge::test_only_collective_seed(
                    attempt, value.seed);
                if (selected == AbortCase::InvalidCoefficientCount) {
                    MacCheckSourceBridge::test_only_local_tau(
                        attempt, 1, value.coefficients, value.tau);
                } else if (selected == AbortCase::InvalidCoefficientWidth) {
                    std::array<unsigned char,
                        2 * MAC_CHECK_FIELD_BYTES - 1> short_coefficients{};
                    MacCheckSourceBridge::test_only_local_tau(
                        attempt, 2, short_coefficients, value.tau);
                } else if (selected == AbortCase::InvalidTauWidth) {
                    std::array<unsigned char,
                        MAC_CHECK_FIELD_BYTES - 1> short_tau{};
                    MacCheckSourceBridge::test_only_local_tau(
                        attempt, 2, value.coefficients, short_tau);
                } else {
                    MacCheckSourceBridge::test_only_local_tau(
                        attempt, 2, value.coefficients, value.tau);
                    if (selected == AbortCase::PendingNotReset) {
                        MacCheckSourceBridge::test_only_success_reset(
                            attempt, 1, value.zero);
                    } else if (selected == AbortCase::NonzeroTauSum) {
                        auto nonzero = value.zero;
                        nonzero.back() = 1;
                        MacCheckSourceBridge::test_only_success_reset(
                            attempt, 0, nonzero);
                    } else {
                        auto nonzero = value.zero;
                        nonzero.back() = 1;
                        MacCheckSourceBridge::test_only_failure_reset(
                            attempt, 0, nonzero);
                    }
                }
            }
        }
        (void)scope;
        ::_exit(92);
    }
    need(::close(marker_pipe[1]) == 0);
    int status{};
    while (::waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) need(false);
    }
    unsigned char marker{};
    const auto marker_size = ::read(marker_pipe[0], &marker, 1);
    need(::close(marker_pipe[0]) == 0);
    need(marker_size == 1 && marker == 0xb8 && WIFSIGNALED(status) &&
         WTERMSIG(status) == SIGABRT);
}

void manifest_is_ordered_and_typed() {
    const std::array checks{
        MacCheckManifestCheck{1, 101},
        MacCheckManifestCheck{2, 202},
    };
    const auto ordered = encode_mac_check_manifest(checks);
    auto reversed = checks;
    std::swap(reversed[0], reversed[1]);
    need(ordered != encode_mac_check_manifest(reversed));
    auto invalid = checks;
    invalid[0].logical_thread_epoch = 0;
    bool refused = false;
    try {
        (void)encode_mac_check_manifest(invalid);
    } catch (const std::runtime_error&) { refused = true; }
    need(refused);
}

} // namespace

int main() {
    exact_sequence_and_explicit_thread();
    dropped_and_terminal_refusal_are_unavailable();
    protocol_failure_retains_prefix_and_nonzero_tau();
    for (const auto selected : {
             AbortCase::WrongOrder,
             AbortCase::RejectedSeed,
             AbortCase::InvalidBeginWidth,
             AbortCase::UnboundWorker,
             AbortCase::InvalidCoefficientCount,
             AbortCase::InvalidCoefficientWidth,
             AbortCase::InvalidTauWidth,
             AbortCase::PendingNotReset,
             AbortCase::NonzeroTauSum,
             AbortCase::ProtocolTerminalRejected})
        expect_fail_stop(selected);
    manifest_is_ordered_and_typed();

    static_assert(kMacCheckStateSourceStatus.semantic_source_sites_fixed);
    static_assert(kMacCheckStateSourceStatus.exact_pending_state_schema);
    static_assert(kMacCheckStateSourceStatus.exact_collective_seed);
    static_assert(kMacCheckStateSourceStatus.exact_coefficient_consumption);
    static_assert(kMacCheckStateSourceStatus.exact_local_tau_and_reset);
    static_assert(
        kMacCheckStateSourceStatus.explicit_process_round_thread_epochs);
    static_assert(kMacCheckStateSourceStatus.typed_partial_unavailable);
    static_assert(!kMacCheckStateSourceStatus.source_patch_selected);
    static_assert(!kMacCheckStateSourceStatus.capsule_family_adapter);
    static_assert(!kMacCheckStateSourceStatus.selected_role1_installation);
    static_assert(!kMacCheckStateSourceStatus.complete_mac_check_family);
    static_assert(!kMacCheckStateSourceStatus.complete_corrupt_p1_view);
    static_assert(!kMacCheckStateSourceStatus.configured);
}
