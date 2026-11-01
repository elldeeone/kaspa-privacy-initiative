#pragma once

// Complete neutral contract joining the sole producer drain result to the
// registered parent's private linear attempt history. It carries no public
// descriptor, body, digest, JSON, or receipt constructor.

namespace kpb::measurement::producer_runtime {
class ProducerAttemptC03HistoryAuthority;
class ProducerAttemptDrainResult;
class ProducerAttemptOutcomeAuthority;
class ProducerAttemptRegisteredOutcomeTransfer;
class ProducerRuntimeCompletion;
}

namespace kpi::mpc::financial::registered_driver::attempt_history {

class RegisteredTrialAttemptHistoryRecorder;
class RegisteredAttemptHistoryAppendOutcomeAuthority;

class RegisteredCaptureAttemptHistoryBridge final {
    RegisteredCaptureAttemptHistoryBridge() = delete;
    static void append_history(
        RegisteredTrialAttemptHistoryRecorder&,
        kpb::measurement::producer_runtime::
            ProducerAttemptC03HistoryAuthority&&);
public:
    static RegisteredAttemptHistoryAppendOutcomeAuthority append_outcome(
        RegisteredTrialAttemptHistoryRecorder&&,
        kpb::measurement::producer_runtime::
            ProducerAttemptOutcomeAuthority&&);
#ifdef KPI_REGISTERED_ATTEMPT_HISTORY_TEST_SETUP
    static kpb::measurement::producer_runtime::ProducerRuntimeCompletion
    append_complete(
        RegisteredTrialAttemptHistoryRecorder&,
        kpb::measurement::producer_runtime::ProducerAttemptDrainResult&&);
    static void append_failed(
        RegisteredTrialAttemptHistoryRecorder&,
        kpb::measurement::producer_runtime::ProducerAttemptDrainResult&&);
#endif
};

} // namespace kpi::mpc::financial::registered_driver::attempt_history
