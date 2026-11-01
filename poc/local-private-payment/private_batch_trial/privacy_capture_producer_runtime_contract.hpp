#pragma once

// Complete, dependency-neutral contract for the sole ten-stream producer.

#include "privacy_registered_fresh_trial_producer_closure_contract.hpp"

#include <array>
#include <cstdint>
#include <memory>

namespace kpb::measurement::producer_archive {
class ProducerSealedArchiveBuilder;
}

namespace kpb::measurement::producer_runtime {
class ParentTenReadEndsAuthority;
class ProducerRuntimeCompletion;
class ProducerAttemptDrainResult;
class ProducerAttemptOutcomeAuthority;
class ParentAggregateMailboxRoutesAuthority;
class RunningCaptureProducer;

class ParentOwnedCaptureProducer final {
    ParentOwnedCaptureProducer() = delete;
    static RunningCaptureProducer start_impl(
        ParentTenReadEndsAuthority&&,
        std::unique_ptr<producer_archive::ProducerSealedArchiveBuilder>);
    static RunningCaptureProducer start_prebuilt(
        ParentTenReadEndsAuthority&&,
        producer_archive::ProducerSealedArchiveBuilder&&);
    static ProducerAttemptOutcomeAuthority finish_outcome_impl(
        RunningCaptureProducer&&,
        ParentAggregateMailboxRoutesAuthority*);
    friend class ::kpi::mpc::financial::registered_driver::
        RegisteredFreshTrialProducerClosureBridge;
public:
    static RunningCaptureProducer start(ParentTenReadEndsAuthority&&);
#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
    static ProducerRuntimeCompletion finish(
        RunningCaptureProducer&&,
        ParentAggregateMailboxRoutesAuthority&&);
#endif
    static ProducerAttemptOutcomeAuthority finish_outcome(
        RunningCaptureProducer&&);
    static ProducerAttemptOutcomeAuthority finish_outcome(
        RunningCaptureProducer&&,
        ParentAggregateMailboxRoutesAuthority&&);
#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP
    static ProducerAttemptDrainResult finish_attempt(
        RunningCaptureProducer&&);
    static ProducerAttemptDrainResult finish_attempt(
        RunningCaptureProducer&&,
        ParentAggregateMailboxRoutesAuthority&&);
    static void test_only_invalidate_running_packet_fd(
        RunningCaptureProducer&);
    struct TestOnlyArchiveIdentity {
        std::array<std::uint64_t, 10> devices{};
        std::array<std::uint64_t, 10> inodes{};
    };
    static TestOnlyArchiveIdentity test_only_archive_identity(
        const RunningCaptureProducer&);
#endif
};
} // namespace kpb::measurement::producer_runtime
