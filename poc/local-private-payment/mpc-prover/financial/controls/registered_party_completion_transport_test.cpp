#include "../authenticated_baseline_owner_receiver.hpp"
#include "../registered_parent_role_fork.hpp"
#include "../registered_party_completion_transport.hpp"

#include <array>
#include <cassert>
#include <fcntl.h>
#include <string_view>
#include <unistd.h>

using namespace kpi::mpc::financial;
using namespace kpi::mpc::financial::registered_driver;
using namespace kpi::mpc::financial::registered_driver::baseline_disclosure;

namespace {
constexpr std::string_view TRIAL_UUID =
    "11111111-1111-4111-8111-111111111111";

Digest id(unsigned long long value) {
    Digest result{};
    for (unsigned index = 0; index < 8; ++index)
        result[index] = static_cast<unsigned char>(value >> (8 * index));
    result[31] = static_cast<unsigned char>(value ^ 0x6dU);
    return result;
}

template<class Callable> void refuses(Callable&& callable) {
    bool rejected = false;
    try { callable(); }
    catch (const identity_registry::Refused&) { rejected = true; }
    assert(rejected);
}

PublicParentRoleForkPlan plan(CaptureClassification classification) {
    PublicParentRoleForkPlan result{
        .classification = classification,
        .round = 1,
        .capture_trial_id = std::string(TRIAL_UUID),
        .trial = RegisteredCapturePlanRosterBridge::trial_identity(
            TRIAL_UUID),
        .financial_run = id(0x102),
        .attempt = id(0x103),
        .cohort = id(0x104),
        .fresh_owner_issuance_identity = id(0x10b),
        .authority_identity = id(0x105),
        .supervisor_session = id(0x106),
        .capture_plan_identity = id(0x107),
        .capture_source_identity = id(0x108),
        .capture_build_identity = id(0x109),
        .capture_launcher_identity = id(0x10a),
    };
    for (unsigned role = 0; role < 3; ++role)
        result.roles[role] = {
            .role = role,
            .party_session = id(0x120 + role),
            .service_identity = id(0x130),
            .driver_selection_identity = id(0x140 + role),
        };
    return result;
}

struct Pipes {
    std::array<std::array<int, 2>, 3> value{};
    Pipes() {
        for (auto& pair : value) assert(::pipe2(pair.data(), O_CLOEXEC) == 0);
    }
    Pipes(const Pipes&) = delete;
    ~Pipes() {
        for (const auto& pair : value)
            for (const int fd : pair) if (fd >= 0) ::close(fd);
    }
    void close_writes() {
        for (auto& pair : value) {
            assert(::close(pair[1]) == 0);
            pair[1] = -1;
        }
    }
};

std::array<InheritedCaptureEndpointAuthority, 3> endpoints(
        const PublicParentRoleForkPlan& selected, const Pipes& pipes) {
    return {
        InheritedCaptureEndpointAuthority::test_only_mint(
            {.kind = InheritedCaptureKind::Projection, .role = 0,
             .round = 1, .fixed_fd = 20, .authority_identity = id(0x201),
             .capture_plan_identity = selected.capture_plan_identity},
            pipes.value[0][1]),
        InheritedCaptureEndpointAuthority::test_only_mint(
            {.kind = InheritedCaptureKind::Dispatcher, .role = 0,
             .round = 1, .fixed_fd = 22, .authority_identity = id(0x202),
             .capture_plan_identity = selected.capture_plan_identity},
            pipes.value[1][1]),
        InheritedCaptureEndpointAuthority::test_only_mint(
            {.kind = InheritedCaptureKind::CorruptServer, .role = 1,
             .round = 1, .fixed_fd = 23, .authority_identity = id(0x203),
             .capture_plan_identity = selected.capture_plan_identity},
            pipes.value[2][1]),
    };
}

PublicPartyDriverCompletion party(
        const PublicParentRoleForkPlan& selected, unsigned role) {
    PublicPartyDriverCompletion result{
        .role = role,
        .round = selected.round,
        .classification = selected.classification,
        .capture_trial_id = selected.capture_trial_id,
        .authority_identity = selected.authority_identity,
        .driver_selection_identity =
            selected.roles[role].driver_selection_identity,
        .selection_identity = id(0x220),
        .run = selected.financial_run,
        .trial = selected.trial,
        .attempt = selected.attempt,
        .cohort = selected.cohort,
        .accepted_head = id(0x221),
        .postlock_accepted_head = id(0x221),
        .attempt_identity = id(0x230 + role),
        .proposal_identity = id(0x240 + role),
        .durable_lock = id(0x250 + role),
        .owner_contracts = {id(0x260), id(0x261), id(0x262)},
        .capture_plan_identity = selected.capture_plan_identity,
        .capture_source_identity = selected.capture_source_identity,
        .capture_build_identity = selected.capture_build_identity,
        .capture_launcher_identity = selected.capture_launcher_identity,
        .authorization_identity = id(0x270 + role),
        .egress_binding_identity = id(0x250 + role),
        .effects_identity = id(0x280),
        .core_identity = id(0x281),
        .proof_identity = id(0x282),
        .projection_identity = id(0x283),
        .full_cohort_barrier_identity = id(0x284),
        .full_cohort_barrier_observed_monotonic_ns = 1000001,
    };
    return result;
}

PrivatePartyBaselineOwnerEffects effects(
        const PublicPartyDriverCompletion& completion) {
    PrivatePartyBaselineOwnerEffects result{
        .classification = completion.classification,
        .round = completion.round,
        .role = completion.role,
        .run = completion.run,
        .trial = completion.trial,
        .attempt = completion.attempt,
        .cohort = completion.cohort,
        .capture_plan_identity = completion.capture_plan_identity,
        .projection_identity = completion.projection_identity,
        .context_identity = id(0x301),
        .relation_source_identity = id(0x302),
        .owner_effects_recipe_identity = id(0x303),
        .baseline_plan_identity = id(0x310 + completion.role),
        .verified_egress_identity = id(0x320 + completion.role),
        .policy_identity = id(0x330),
        .roster_authority_identity = id(0x331),
        .roster_root_identity = id(0x332),
        .consent_nonce = id(0x333),
        .owner_contracts = completion.owner_contracts,
    };
    for (unsigned owner = 0; owner < 3; ++owner) {
        result.logical_owner_identities[owner] = id(0x340 + owner);
        result.pre_disclosure_challenge_identities[owner] =
            id(0x350 + owner);
        result.owner_sessions[owner] =
            id(0x360 + 4 * completion.role + owner);
        auto& truth = result.owner_truth[owner];
        truth.owner = owner;
        truth.round = completion.round;
        truth.run = completion.run;
        truth.trial = completion.trial;
        truth.attempt = completion.attempt;
        truth.cohort = completion.cohort;
        truth.capture_plan_identity = completion.capture_plan_identity;
        truth.projection_identity = completion.projection_identity;
        truth.context_identity = result.context_identity;
        truth.owner_contract_identity = completion.owner_contracts[owner];
        truth.logical_owner_identity = result.logical_owner_identities[owner];
        truth.roster_authority_identity = result.roster_authority_identity;
        truth.roster_root_identity = result.roster_root_identity;
        truth.pre_disclosure_challenge_identity =
            result.pre_disclosure_challenge_identities[owner];
        truth.public_nullifier = id(0x400 + owner);
        truth.public_tuple_hashes = {
            id(0x410 + 2 * owner), id(0x411 + 2 * owner)};
        truth.public_tuple_commitments = {
            id(0x420 + 2 * owner), id(0x421 + 2 * owner)};
    }
    return result;
}

enum class Fault {
    None,
    WrongClassification,
    WrongRun,
    WrongTrial,
    WrongAttempt,
    WrongCohort,
    WrongAuthority,
    WrongDriverSelection,
    WrongSource,
    WrongBuild,
    WrongLauncher,
    WrongCapturePlan,
    InvalidBaselineTag,
    DuplicateTerminal,
    MissingBaseline,
    HiddenBaselineSmuggle,
};

class Program final : public RegisteredRoleChildProgram {
    PublicParentRoleForkPlan plan_;
    Fault fault_;
public:
    Program(PublicParentRoleForkPlan selected, Fault fault)
        : plan_(std::move(selected)), fault_(fault) {}

    int run(ParentAuthenticatedPartyDeliveryAuthority&& delivered,
            ChildRoleCompletionEndpointAuthority&& endpoint) override {
        try {
            auto value = party(plan_, delivered.public_receipt().role);
            if (fault_ == Fault::WrongClassification)
                value.classification = value.classification ==
                    CaptureClassification::HiddenCandidate
                    ? CaptureClassification::ExplicitOwnerPublicEffectsBaseline
                    : CaptureClassification::HiddenCandidate;
            if (fault_ == Fault::WrongRun) value.run = id(0xf01);
            if (fault_ == Fault::WrongTrial) value.trial = id(0xf02);
            if (fault_ == Fault::WrongAttempt) value.attempt = id(0xf03);
            if (fault_ == Fault::WrongCohort) value.cohort = id(0xf04);
            if (fault_ == Fault::WrongAuthority)
                value.authority_identity = id(0xf07);
            if (fault_ == Fault::WrongDriverSelection)
                value.driver_selection_identity = id(0xf08);
            if (fault_ == Fault::WrongSource)
                value.capture_source_identity = id(0xf09);
            if (fault_ == Fault::WrongBuild)
                value.capture_build_identity = id(0xf05);
            if (fault_ == Fault::WrongLauncher)
                value.capture_launcher_identity = id(0xf0a);
            if (fault_ == Fault::WrongCapturePlan)
                value.capture_plan_identity = id(0xf06);
            auto completion = RegisteredPartyCompletionTransportTestBridge::
                mint_party(value);

            if (fault_ == Fault::InvalidBaselineTag) {
                RegisteredPartyCompletionTransport::
                    test_only_submit_hidden_invalid_baseline_tag(
                        std::move(completion), std::move(endpoint));
            } else if (fault_ == Fault::DuplicateTerminal) {
                RegisteredPartyCompletionTransport::
                    test_only_submit_hidden_duplicate_terminal(
                        std::move(completion), std::move(endpoint));
            } else if (plan_.classification ==
                       CaptureClassification::HiddenCandidate) {
                if (fault_ == Fault::HiddenBaselineSmuggle) {
                    auto baseline = PartyBaselineOwnerEffectsAuthority::
                        test_only_mint(effects(value));
                    RegisteredPartyCompletionTransport::submit_baseline(
                        std::move(completion), std::move(baseline),
                        std::move(endpoint));
                } else {
                    RegisteredPartyCompletionTransport::submit_hidden(
                        std::move(completion), std::move(endpoint));
                }
            } else if (fault_ == Fault::MissingBaseline) {
                RegisteredPartyCompletionTransport::submit_hidden(
                    std::move(completion), std::move(endpoint));
            } else {
                auto baseline = PartyBaselineOwnerEffectsAuthority::
                    test_only_mint(effects(value));
                RegisteredPartyCompletionTransport::submit_baseline(
                    std::move(completion), std::move(baseline),
                    std::move(endpoint));
            }
            return 0;
        } catch (const identity_registry::Refused&) {
            return 0;
        }
    }
};

ParentRoleChildren launch(
        const PublicParentRoleForkPlan& selected, Fault fault, Pipes& pipes) {
    auto fork = ParentRoleForkPlanAuthority::test_only_mint(
        selected, endpoints(selected, pipes));
    pipes.close_writes();
    static std::optional<Program> retained;
    retained.emplace(selected, fault);
    return RegisteredParentRoleFork::launch(std::move(fork), *retained);
}

void happy(CaptureClassification classification) {
    Pipes pipes;
    const auto selected = plan(classification);
    auto children = launch(selected, Fault::None, pipes);
    BaselineOwnerScoringParentCollector collector;
    for (unsigned role = 0; role < 3; ++role) {
        auto result = RegisteredPartyCompletionTransport::receive(
            children.take_completion_endpoint(role));
        assert(result.has_baseline_effects() ==
               (classification == CaptureClassification::
                    ExplicitOwnerPublicEffectsBaseline));
        auto completion = result.take_party_completion();
        const auto& observed = completion.public_observation();
        const auto& party_receipt = completion.public_party_completion();
        assert(observed.role == role && observed.round == 1 &&
               observed.child_pid > 1 &&
               observed.party_completion_identity ==
                   party_receipt.completion_identity &&
               observed.observation_identity != Digest{} &&
               party_receipt.classification == classification &&
               party_receipt.run == selected.financial_run);
        refuses([&] { (void)result.take_party_completion(); });
        if (result.has_baseline_effects()) {
            collector.submit(result.take_baseline_effects());
            refuses([&] { (void)result.take_baseline_effects(); });
        } else {
            refuses([&] { (void)result.take_baseline_effects(); });
        }
    }
    assert(children.wait().all_children_exited_zero);
}

void fault(CaptureClassification classification, Fault selected_fault) {
    Pipes pipes;
    const auto selected = plan(classification);
    auto children = launch(selected, selected_fault, pipes);
    refuses([&] {
        (void)RegisteredPartyCompletionTransport::receive(
            children.take_completion_endpoint(0));
    });
    refuses([&] { (void)children.wait(); });
}
} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::string_view selected(argv[1]);
    if (selected == "hidden")
        happy(CaptureClassification::HiddenCandidate);
    else if (selected == "baseline")
        happy(CaptureClassification::ExplicitOwnerPublicEffectsBaseline);
    else if (selected == "wrong-class")
        fault(CaptureClassification::HiddenCandidate,
              Fault::WrongClassification);
    else if (selected == "wrong-run")
        fault(CaptureClassification::HiddenCandidate, Fault::WrongRun);
    else if (selected == "wrong-trial")
        fault(CaptureClassification::HiddenCandidate, Fault::WrongTrial);
    else if (selected == "wrong-attempt")
        fault(CaptureClassification::HiddenCandidate, Fault::WrongAttempt);
    else if (selected == "wrong-cohort")
        fault(CaptureClassification::HiddenCandidate, Fault::WrongCohort);
    else if (selected == "wrong-authority")
        fault(CaptureClassification::HiddenCandidate, Fault::WrongAuthority);
    else if (selected == "wrong-driver")
        fault(CaptureClassification::HiddenCandidate,
              Fault::WrongDriverSelection);
    else if (selected == "wrong-source")
        fault(CaptureClassification::HiddenCandidate, Fault::WrongSource);
    else if (selected == "wrong-build")
        fault(CaptureClassification::HiddenCandidate, Fault::WrongBuild);
    else if (selected == "wrong-launcher")
        fault(CaptureClassification::HiddenCandidate, Fault::WrongLauncher);
    else if (selected == "wrong-plan")
        fault(CaptureClassification::HiddenCandidate,
              Fault::WrongCapturePlan);
    else if (selected == "invalid-tag")
        fault(CaptureClassification::HiddenCandidate,
              Fault::InvalidBaselineTag);
    else if (selected == "duplicate-terminal")
        fault(CaptureClassification::HiddenCandidate,
              Fault::DuplicateTerminal);
    else if (selected == "missing-baseline")
        fault(CaptureClassification::ExplicitOwnerPublicEffectsBaseline,
              Fault::MissingBaseline);
    else if (selected == "hidden-baseline")
        fault(CaptureClassification::HiddenCandidate,
              Fault::HiddenBaselineSmuggle);
    else return 2;
    return 0;
}
