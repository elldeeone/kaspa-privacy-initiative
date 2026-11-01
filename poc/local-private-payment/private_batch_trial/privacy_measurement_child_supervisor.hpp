#pragma once

#include "privacy_measurement_worker_capsule.hpp"

namespace kpb::measurement::runtime_bridge {

struct RuntimeInputOffer {
    PublicMeasurementInputEndpoint endpoint;
    std::int64_t feeder_pid{};
    Digest feeder_session{};
    Digest feeder_exit_identity{};
    bool operator==(const RuntimeInputOffer&) const = default;
};

struct PublicRuntimeChildOffer {
    RuntimeChildRole role{};
    unsigned owner{NO_OWNER};
    Digest permit_identity{};
    WorkerBinding worker{};
    Digest outer_parent_process{};
    Digest outer_parent_executable{};
    Digest capsule_identity{};
    Digest descriptor_manifest_identity{};
    Digest opaque_completion_authority_identity{};
    Digest opaque_capsule_authority_identity{};
    Digest output_authority_identity{};
    Digest output_abi_identity{};
    std::uint64_t output_exact_size{};
    std::array<RuntimeInputOffer, MAX_MEASUREMENT_INPUTS> inputs{};
    unsigned input_count{};
    Digest transport_session{};
    Digest offer_identity{};
    std::uint64_t parent_pid{};
    std::uint64_t child_pid{};
};

struct RuntimeChildResult {
    AggregateOutcome aggregate_outcome{};
    OwnerComparisonOutcome comparison_outcome{};
    Digest private_output_content_hash{};
};

class MeasurementChildProgram {
public:
    virtual ~MeasurementChildProgram() = default;
    virtual RuntimeChildResult execute(
        const PublicRuntimeChildOffer&) = 0;
};

// Entry point for the exact source-pinned executable. It reads the inherited
// fixed endpoint, authenticates the outer parent, ACKs one offer, emits one
// fixed completion, closes the endpoint and returns zero. It accepts no argv,
// environment contract, caller receipt or serialized authority.
int run_measurement_child(MeasurementChildProgram&) noexcept;

enum class TestChildProtocolFault : unsigned char {
    None = 0,
    WrongAckOffer = 1,
    WrongAckPid = 2,
    CredentialRelay = 3,
    WrongCompletionRole = 4,
    DuplicateCompletion = 5,
    NoCompletion = 6,
    WrongCompletionPermit = 7,
    WrongCompletionOwner = 8,
    WrongCompletionOpaqueAuthority = 9,
    WrongCapsuleOpaqueAuthority = 10,
    ZeroAckBeforeClose = 13,
    ZeroCompletionBeforeClose = 14,
};
#ifdef KPB_MEASUREMENT_CHILD_SUPERVISOR_TEST_SETUP
int test_only_run_measurement_child(
    MeasurementChildProgram&, TestChildProtocolFault) noexcept;
bool test_only_zero_offer_record_refused(int endpoint_fd) noexcept;
#endif

} // namespace kpb::measurement::runtime_bridge
