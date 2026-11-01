#pragma once

#include "privacy_owner_score_lineage_source_contract.hpp"
#include "privacy_outer_attempt_domain.hpp"
#include "../mpc-prover/financial/registered_selected_producer_activation_contract.hpp"
#include "../mpc-prover/financial/registered_selected_producer_run_binding.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace kpb::measurement::score_output_lineage_source {

using SourceDigest = OuterAttemptDigest;

// Opaque selected-parent source half.  A future source-owned launcher fills
// it only from one sealed diagnostic selection and one sealed executable
// worker.  It deliberately exposes no descriptor, bytes, path, digest, plan,
// or receipt.  The selected activation bridge is its sole production
// consumer.
class SelectedOwnerScoreLineagePrelaunchSourceAuthority final {
    struct Storage;
    struct ActivationBundle final {
        kpi::mpc::financial::registered_driver::
            RegisteredSelectedProducerPrelaunchPlan plan;
        int selection_fd{-1};
        int worker_fd{-1};
        SourceDigest worker_sha256{};
        ActivationBundle(
            kpi::mpc::financial::registered_driver::
                RegisteredSelectedProducerPrelaunchPlan,
            int, int, SourceDigest) noexcept;
        ActivationBundle(const ActivationBundle&) = delete;
        ActivationBundle& operator=(const ActivationBundle&) = delete;
        ActivationBundle(ActivationBundle&&) noexcept;
        ActivationBundle& operator=(ActivationBundle&&) = delete;
        ~ActivationBundle();
    };
    std::unique_ptr<Storage> storage_;
    explicit SelectedOwnerScoreLineagePrelaunchSourceAuthority(
        std::unique_ptr<Storage>) noexcept;
    ActivationBundle consume_for_selected_activation() &&;
    friend class ::kpi::mpc::financial::registered_driver::
        RegisteredSelectedProducerActivationBridge;
#ifdef KPB_SELECTED_PRODUCER_ACTIVATION_TEST_SETUP
    friend class SelectedOwnerScoreLineagePrelaunchSourceTestBridge;
#endif
public:
    SelectedOwnerScoreLineagePrelaunchSourceAuthority(
        const SelectedOwnerScoreLineagePrelaunchSourceAuthority&) = delete;
    SelectedOwnerScoreLineagePrelaunchSourceAuthority& operator=(
        const SelectedOwnerScoreLineagePrelaunchSourceAuthority&) = delete;
    SelectedOwnerScoreLineagePrelaunchSourceAuthority(
        SelectedOwnerScoreLineagePrelaunchSourceAuthority&&) noexcept;
    SelectedOwnerScoreLineagePrelaunchSourceAuthority& operator=(
        SelectedOwnerScoreLineagePrelaunchSourceAuthority&&) = delete;
    ~SelectedOwnerScoreLineagePrelaunchSourceAuthority();
};

inline constexpr std::array<unsigned char, 8>
    OWNER_SCORE_LINEAGE_ARCHIVE_MAGIC{
        'K','P','B','O','S','L','0','2'};
inline constexpr std::uint32_t OWNER_SCORE_LINEAGE_ARCHIVE_VERSION = 2;
inline constexpr std::size_t OWNER_SCORE_LINEAGE_ARCHIVE_HEADER_BYTES = 416;

enum class OwnerScoreSourceClassification : unsigned char {
    HiddenCandidate = 1,
    TransparentBaseline = 2,
};

#ifdef KPB_OWNER_SCORE_LINEAGE_SOURCE_TEST_SETUP
enum class TestOnlyPrivacyLaunchSourceFault : unsigned char {
    None,
    WritableDescriptor,
    MissingSeals,
};

enum class TestOnlyLineageAdmissionFault : unsigned char {
    None,
    AllocationBeforeClaim,
};

struct TestOnlyPrivacyLaunchLineageExpected final {
    SourceDigest method_sha256{};
    SourceDigest run_selection_sha256{};
    SourceDigest diagnostic_selection_sha256{};
    SourceDigest source_closure_sha256{};
    SourceDigest runtime_identity_sha256{};
    SourceDigest measurement_attempt_identity{};
    std::string trial_id;
    std::string attempt_id;
    OwnerScoreSourceClassification classification{
        OwnerScoreSourceClassification::HiddenCandidate};
};
#endif

// The future receiver constructs this only after authenticating the selected
// privacy_launch.py child, its single sealed archive descriptor, exact EOF,
// and wait status.  Generic archive bytes or a public launch receipt cannot
// construct it.  The test mint exists only to exercise the frozen archive
// parser while that selected transport remains absent.
class AuthenticatedPrivacyLaunchLineageSourceAuthority final {
    struct Storage;
    struct ReceiverExpectation final {
        SourceDigest method_sha256{};
        SourceDigest run_selection_sha256{};
        SourceDigest diagnostic_selection_sha256{};
        SourceDigest source_closure_sha256{};
        SourceDigest runtime_identity_sha256{};
        SourceDigest registered_prelaunch_identity{};
        SourceDigest measurement_attempt_identity{};
        SourceDigest receiver_session_identity{};
        SourceDigest receiver_process_identity{};
        SourceDigest receiver_exit_identity{};
        std::string trial_id;
        OwnerScoreSourceClassification classification{
            OwnerScoreSourceClassification::HiddenCandidate};
        SourceDigest exact_archive_sha256{};
    };
    std::unique_ptr<Storage> storage_;
    explicit AuthenticatedPrivacyLaunchLineageSourceAuthority(
        std::unique_ptr<Storage>) noexcept;
    static AuthenticatedPrivacyLaunchLineageSourceAuthority
        adopt_received_archive(int, ReceiverExpectation);
    friend class PrivacyLaunchLineageSourceReceiverBridge;
    friend class SelectedOwnerScoreLineageAdmissionBridge;
public:
    AuthenticatedPrivacyLaunchLineageSourceAuthority(
        const AuthenticatedPrivacyLaunchLineageSourceAuthority&) = delete;
    AuthenticatedPrivacyLaunchLineageSourceAuthority& operator=(
        const AuthenticatedPrivacyLaunchLineageSourceAuthority&) = delete;
    AuthenticatedPrivacyLaunchLineageSourceAuthority(
        AuthenticatedPrivacyLaunchLineageSourceAuthority&&) noexcept;
    AuthenticatedPrivacyLaunchLineageSourceAuthority& operator=(
        AuthenticatedPrivacyLaunchLineageSourceAuthority&&) = delete;
    ~AuthenticatedPrivacyLaunchLineageSourceAuthority();

#ifdef KPB_OWNER_SCORE_LINEAGE_SOURCE_TEST_SETUP
    static AuthenticatedPrivacyLaunchLineageSourceAuthority test_only_mint(
        const std::vector<unsigned char>&,
        const TestOnlyPrivacyLaunchLineageExpected&,
        TestOnlyPrivacyLaunchSourceFault fault =
            TestOnlyPrivacyLaunchSourceFault::None);
#endif
};

// The only production-visible result of the selected-source admission.  It
// privately retains the exact sealed diagnostic.run_selection bytes and raw
// attempt text.  It has no fd, bytes, digest, text, receipt, or arm getter.
class SelectedOwnerScoreLineageSourceTransferAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit SelectedOwnerScoreLineageSourceTransferAuthority(
        std::unique_ptr<Storage>) noexcept;
    friend class SelectedOwnerScoreLineageAdmissionBridge;
    friend class RegisteredOwnerScoreLineageSourceBridge;
public:
    SelectedOwnerScoreLineageSourceTransferAuthority(
        const SelectedOwnerScoreLineageSourceTransferAuthority&) = delete;
    SelectedOwnerScoreLineageSourceTransferAuthority& operator=(
        const SelectedOwnerScoreLineageSourceTransferAuthority&) = delete;
    SelectedOwnerScoreLineageSourceTransferAuthority(
        SelectedOwnerScoreLineageSourceTransferAuthority&&) noexcept;
    SelectedOwnerScoreLineageSourceTransferAuthority& operator=(
        SelectedOwnerScoreLineageSourceTransferAuthority&&) = delete;
    ~SelectedOwnerScoreLineageSourceTransferAuthority();
};

// Reserved at RegisteredSelectedProducerPrelaunchBindingFactory::compile.
// No public-plan reconstruction or mint exists while the source-owned split
// has not landed.
class RegisteredOwnerScorePrelaunchResidualAuthority final {
    void* storage_{};
    void (*destroy_storage_)(void*) noexcept{};
    RegisteredOwnerScorePrelaunchResidualAuthority(
        void*, void (*)(void*) noexcept) noexcept;
    friend class RegisteredOwnerScoreLineageSourceBridge;
public:
    RegisteredOwnerScorePrelaunchResidualAuthority(
        const RegisteredOwnerScorePrelaunchResidualAuthority&) = delete;
    RegisteredOwnerScorePrelaunchResidualAuthority& operator=(
        const RegisteredOwnerScorePrelaunchResidualAuthority&) = delete;
    RegisteredOwnerScorePrelaunchResidualAuthority(
        RegisteredOwnerScorePrelaunchResidualAuthority&&) noexcept;
    RegisteredOwnerScorePrelaunchResidualAuthority& operator=(
        RegisteredOwnerScorePrelaunchResidualAuthority&&) = delete;
    ~RegisteredOwnerScorePrelaunchResidualAuthority();
};

// Reserved for the existing RegisteredMeasurementCaptureBridge.  It must
// forward the private raw trial UUID without detaching party/route retention.
class RegisteredOwnerScoreTrialResidualAuthority final {
    void* storage_{};
    void (*destroy_storage_)(void*) noexcept{};
    RegisteredOwnerScoreTrialResidualAuthority(
        void*, void (*)(void*) noexcept) noexcept;
    friend class RegisteredOwnerScoreLineageSourceBridge;
public:
    RegisteredOwnerScoreTrialResidualAuthority(
        const RegisteredOwnerScoreTrialResidualAuthority&) = delete;
    RegisteredOwnerScoreTrialResidualAuthority& operator=(
        const RegisteredOwnerScoreTrialResidualAuthority&) = delete;
    RegisteredOwnerScoreTrialResidualAuthority(
        RegisteredOwnerScoreTrialResidualAuthority&&) noexcept;
    RegisteredOwnerScoreTrialResidualAuthority& operator=(
        RegisteredOwnerScoreTrialResidualAuthority&&) = delete;
    ~RegisteredOwnerScoreTrialResidualAuthority();
};

#ifdef KPB_OWNER_SCORE_LINEAGE_SOURCE_TEST_SETUP
struct TestOnlyOwnerScoreLineageSummary final {
    SourceDigest method_sha256{};
    SourceDigest run_selection_sha256{};
    SourceDigest diagnostic_selection_sha256{};
    SourceDigest source_closure_sha256{};
    SourceDigest runtime_identity_sha256{};
    SourceDigest measurement_attempt_identity{};
    std::string trial_id;
    std::string attempt_id;
    OwnerScoreSourceClassification classification{
        OwnerScoreSourceClassification::HiddenCandidate};
    std::uint64_t run_selection_bytes{};
    std::uint64_t archive_device{};
    std::uint64_t archive_inode{};
};

SourceDigest test_only_digest(std::string_view);
#endif

struct OwnerScoreLineageSourceStatus final {
    bool python_source_parser_located{};
    bool exact_selection_bytes_observed{};
    bool raw_outer_attempt_observed{};
    bool source_archive_encoder{};
    bool cpp_archive_parser{};
    bool opaque_one_shot_transfer{};
    bool credentialed_receiver_transport_core{};
    bool authenticated_python_receiver{};
    bool outer_attempt_source_join{};
    bool prelaunch_linear_residual{};
    bool trial_linear_residual{};
    bool output_lineage_minter{};
    bool selected_callsite{};
    bool configured{};
};

inline constexpr OwnerScoreLineageSourceStatus
kOwnerScoreLineageSourceStatus{
    .python_source_parser_located = true,
    .exact_selection_bytes_observed = true,
    .raw_outer_attempt_observed = true,
    .source_archive_encoder = true,
    .cpp_archive_parser = true,
    .opaque_one_shot_transfer = true,
    .credentialed_receiver_transport_core = true,
    .authenticated_python_receiver = false,
    .outer_attempt_source_join = true,
    .prelaunch_linear_residual = false,
    .trial_linear_residual = false,
    .output_lineage_minter = false,
    .selected_callsite = false,
    .configured = false,
};

} // namespace kpb::measurement::score_output_lineage_source
