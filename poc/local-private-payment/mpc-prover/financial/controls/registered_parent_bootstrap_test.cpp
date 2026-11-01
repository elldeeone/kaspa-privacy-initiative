#include "../registered_parent_bootstrap.hpp"
#include "../registered_parent_role_fork.hpp"
#include "../fresh_owner_trial_issuance.hpp"
#include "../../trace/sealed_trace.hpp"

#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <iterator>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace kpi::mpc;
using namespace kpi::mpc::financial;
using namespace kpi::mpc::financial::fresh_owner_issuance;
using namespace kpi::mpc::financial::registered_driver;

namespace {
constexpr std::string_view TRIAL_UUID =
    "11111111-1111-4111-8111-111111111111";

Digest id(unsigned value) {
    Digest result{};
    result[0] = static_cast<unsigned char>(value);
    result[1] = static_cast<unsigned char>(value >> 8);
    result[31] = static_cast<unsigned char>(value ^ 0xa7U);
    return result;
}

template<class Callable>
void refuses(Callable&& callable) {
    bool did_refuse = false;
    try { callable(); }
    catch (const identity_registry::Refused&) { did_refuse = true; }
    assert(did_refuse);
}

std::string hex(unsigned value) {
    return identity_registry::hex(id(value));
}

OwnerInputContract contract(unsigned owner) {
    OwnerInputContract value{
        .run_nonce = hex(20),
        .model_identity = hex(50),
        .source_identity = hex(51),
        .proving_key_identity = hex(52),
        .verifying_key_identity = hex(53),
        .cohort_identity = hex(22),
        .owner_id = static_cast<int>(owner),
        .input_count = OWNER_PRIVATE_INPUT_V2_BYTES / 32 - 1,
        .server_certificate_sha256 = {
            hex(60), hex(61), hex(62)},
        .owner_certificate_sha256 = hex(70 + owner),
        .trace_identity = hex(54),
        .layout_identity = hex(55),
    };
    return value;
}

std::string canonical(const OwnerInputContract& value) {
    static constexpr std::string_view modulus =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617";
    return std::string("KPI_MASCOT_OWNER_DDNNT_INPUT_V2\nBN254\nFr\n") +
        std::string(modulus) + "\nDDNNT_ACTIVE_5N\n" + value.run_nonce +
        "\n" + value.model_identity + "\n" + value.source_identity +
        "\n" + value.proving_key_identity + "\n" +
        value.verifying_key_identity + "\n" + value.trace_identity + "\n" +
        value.layout_identity + "\n" + value.cohort_identity + "\n" +
        std::to_string(value.owner_id) + "\n" +
        std::to_string(value.input_count) + "\nP0\n" +
        value.server_certificate_sha256[0] + "\nP1\n" +
        value.server_certificate_sha256[1] + "\nP2\n" +
        value.server_certificate_sha256[2] + "\nC" +
        std::to_string(value.owner_id) + "\n" +
        value.owner_certificate_sha256 + "\n";
}

Digest contract_identity(const OwnerInputContract& value) {
    const auto bytes = canonical(value);
    return identity_registry::digest(std::span(
        reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()));
}

std::array<OwnerInputContract, 3> contracts() {
    return {contract(0), contract(1), contract(2)};
}

PublicFreshOwnerRoundReceipt round_value() {
    return {
        .classification = CaptureClassification::HiddenCandidate,
        .round = 1,
        .authority_identity = id(1),
        .registration_identity = id(2),
        .service_identity = id(3),
        .controller_source_identity = id(4),
        .controller_build_identity = id(5),
        .run = id(10),
        .trial = RegisteredCapturePlanRosterBridge::trial_identity(
            TRIAL_UUID),
        .attempt = id(20),
        .cohort = id(22),
        .accepted_input_head_identity = id(23),
        .history_gate_identity = id(24),
        .root_identity = id(25),
        .issuance_identity = id(26),
    };
}

Digest selected_identity(const PublicFreshOwnerRoundReceipt& round,
                         const std::array<OwnerInputContract, 3>& jobs) {
    identity_registry::Selection selection{
        .run = round.run,
        .trial = round.trial,
        .attempt = round.attempt,
        .cohort = round.cohort,
        .accepted_head = round.accepted_input_head_identity,
        .owner_contracts = {
            contract_identity(jobs[0]), contract_identity(jobs[1]),
            contract_identity(jobs[2])},
    };
    return identity_registry::selection_identity(selection);
}

PublicCapturePlan capture_value() {
    return {
        .classification = CaptureClassification::HiddenCandidate,
        .round = 1,
        .capture_trial_id = std::string(TRIAL_UUID),
        .capture_attempt_id = "123e4567-e89b-42d3-a456-426614174000",
        .capture_identity = "123e4567-e89b-42d3-b456-426614174001",
        .run = id(10),
        .trial = RegisteredCapturePlanRosterBridge::trial_identity(
            TRIAL_UUID),
        .attempt = id(20),
        .cohort = id(22),
        .source_identity = id(31),
        .build_identity = id(32),
        .launcher_identity = id(33),
        .model_preimage_identity = id(50),
        .query_store_preimage_identity = id(56),
        .scalar_capture_manifest_identity = identity_registry::unhex(
            "5e6903569bc71cbfb5549b369b79a19ecda6686dc4ab25fca0d161c6e1527b6b"),
        .fixed_fds = {20, 21, 22, 23, 24, 25, 26, 27, 28, 29},
    };
}

Digest capture_identity(const PublicCapturePlan& value) {
    std::vector<unsigned char> bytes;
    const auto add = [&](std::span<const unsigned char> item) {
        bytes.insert(bytes.end(), item.begin(), item.end());
    };
    const auto text = [&](std::string_view item) {
        add(std::span(reinterpret_cast<const unsigned char*>(item.data()),
                      item.size()));
    };
    const auto number = [&](std::uint64_t item) {
        for (unsigned shift = 0; shift < 64; shift += 8)
            bytes.push_back(static_cast<unsigned char>(item >> shift));
    };
    text("KPB_REGISTERED_CAPTURE_PLAN_V4\n");
    number(static_cast<std::uint8_t>(value.classification));
    number(value.round);
    number(value.capture_trial_id.size()); text(value.capture_trial_id);
    number(value.capture_attempt_id.size()); text(value.capture_attempt_id);
    number(value.capture_identity.size()); text(value.capture_identity);
    for (const auto* item : {
             &value.run, &value.trial, &value.attempt, &value.cohort,
             &value.source_identity, &value.build_identity,
             &value.launcher_identity, &value.model_preimage_identity,
             &value.query_store_preimage_identity,
             &value.scalar_capture_manifest_identity}) add(*item);
    for (const int fd : value.fixed_fds)
        number(static_cast<std::uint64_t>(fd));
    return identity_registry::digest(bytes);
}

PublicDriverSelection driver_value(unsigned role,
                                   const Digest& selection) {
    const auto capture = capture_value();
    return {
        .role = role,
        .authority_identity = id(1),
        .selection_identity = selection,
        .service_identity = id(3),
        .source_identity = id(4),
        .build_identity = id(5),
        .roster_identity = id(30),
        .capture_source_identity = capture.source_identity,
        .capture_build_identity = capture.build_identity,
        .capture_launcher_identity = capture.launcher_identity,
        .model_preimage_identity = capture.model_preimage_identity,
        .query_store_preimage_identity =
            capture.query_store_preimage_identity,
        .scalar_capture_manifest_identity =
            capture.scalar_capture_manifest_identity,
        .owner_port = 32100,
        .multiplication_batch = 4096,
    };
}

struct Pipes {
    std::array<std::array<int, 2>, 3> values{};
    Pipes() {
        for (auto& pipe : values)
            assert(::pipe2(pipe.data(), O_CLOEXEC) == 0);
    }
    ~Pipes() {
        for (const auto& pipe : values)
            for (const int fd : pipe)
                if (fd >= 0) ::close(fd);
    }
    void close_writes() {
        for (auto& pipe : values) {
            assert(::close(pipe[1]) == 0);
            pipe[1] = -1;
        }
    }
};

ParentRoleForkPlanAuthority fork_authority(
        PublicParentRoleForkPlan value, const Pipes& pipes) {
    const int offset = value.round == 1 ? 0 : 5;
    std::array<InheritedCaptureEndpointAuthority, 3> endpoints{
        InheritedCaptureEndpointAuthority::test_only_mint(
            {InheritedCaptureKind::Projection, 0, value.round, 20 + offset,
             id(80), value.capture_plan_identity}, pipes.values[0][1]),
        InheritedCaptureEndpointAuthority::test_only_mint(
            {InheritedCaptureKind::Dispatcher, 0, value.round, 22 + offset,
             id(81), value.capture_plan_identity}, pipes.values[1][1]),
        InheritedCaptureEndpointAuthority::test_only_mint(
            {InheritedCaptureKind::CorruptServer, 1, value.round, 23 + offset,
             id(82), value.capture_plan_identity}, pipes.values[2][1]),
    };
    return ParentRoleForkPlanAuthority::test_only_mint(
        std::move(value), std::move(endpoints));
}

PublicParentRoleForkPlan fork_plan(
        const std::array<CompiledDriverSelection, 3>& drivers) {
    const auto capture = capture_value();
    PublicParentRoleForkPlan value{
        .classification = capture.classification,
        .round = 1,
        .capture_trial_id = capture.capture_trial_id,
        .trial = capture.trial,
        .financial_run = capture.run,
        .attempt = capture.attempt,
        .cohort = capture.cohort,
        .fresh_owner_issuance_identity = id(26),
        .authority_identity = id(1),
        .supervisor_session = id(90),
        .capture_plan_identity = capture_identity(capture),
        .capture_source_identity = capture.source_identity,
        .capture_build_identity = capture.build_identity,
        .capture_launcher_identity = capture.launcher_identity,
    };
    for (unsigned role = 0; role < 3; ++role)
        value.roles[role] = {
            .role = role,
            .party_session = id(91 + role),
            .service_identity = id(3),
            .driver_selection_identity = drivers[role].identity(),
        };
    return value;
}

enum class ChildFault { None, WrongModel, WrongAck, ArtifactMixup };

class BootstrapProgram final : public RegisteredRoleChildProgram {
    InheritedSealedQueryArtifact artifact_;
    InheritedSealedQueryArtifact wrong_artifact_;
    ChildFault fault_;
public:
    BootstrapProgram(InheritedSealedQueryArtifact artifact,
                     InheritedSealedQueryArtifact wrong_artifact,
                     ChildFault fault)
        : artifact_(std::move(artifact)),
          wrong_artifact_(std::move(wrong_artifact)), fault_(fault) {}

    int run(ParentAuthenticatedPartyDeliveryAuthority&& delivery,
            ChildRoleCompletionEndpointAuthority&& endpoint) override {
        try {
            const auto role = delivery.public_receipt().role;
            const auto& selected_artifact =
                (fault_ == ChildFault::ArtifactMixup && role == 0)
                    ? wrong_artifact_ : artifact_;
            auto pending = RegisteredParentBootstrapTransport::receive(
                endpoint, delivery, selected_artifact);
            auto public_artifact =
                RegisteredParentBootstrapTransport::query_artifact(pending);
            auto input = public_artifact->stream();
            const std::string decoded{
                std::istreambuf_iterator<char>(*input),
                std::istreambuf_iterator<char>()};
            if (decoded != "registered-parent-bootstrap-public-query\n")
                return 31;

            auto model = identity_registry::hex(
                pending.public_receipt().model_preimage_identity);
            auto query = identity_registry::hex(
                pending.public_receipt().query_store_preimage_identity);
            if (fault_ == ChildFault::WrongModel && role == 1)
                query = identity_registry::hex(id(199));
            auto admitted = RegisteredParentBootstrapTransport::
                test_only_authorize_admitted_model(
                    std::move(pending), {model.c_str(), query.c_str(),
                        fault_ == ChildFault::WrongAck && role == 2});
            if (admitted.public_receipt().role != role) return 32;
            auto fresh = admitted.take_fresh_attempt();
            auto driver = admitted.take_driver_selection();
            auto capture = admitted.take_capture_plan();
            auto owner_contracts = admitted.take_owner_contracts();
            const auto jobs = owner_contracts.contracts();
            (void)fresh; (void)capture;
            if (driver.public_selection().role != role) return 33;
            for (unsigned owner = 0; owner < 3; ++owner)
                if (jobs[owner].owner_id != static_cast<int>(owner)) return 34;
            refuses([&] { (void)admitted.take_fresh_attempt(); });
            refuses([&] { (void)admitted.take_driver_selection(); });
            refuses([&] { (void)admitted.take_capture_plan(); });
            refuses([&] { (void)admitted.take_owner_contracts(); });
            const std::array<unsigned char, 1> payload{
                static_cast<unsigned char>(role)};
            ParentRoleForkTestCompletionBridge::submit(
                std::move(endpoint), id(210), payload);
            return 0;
        } catch (...) { return 35; }
    }
};

void run_transport(std::string_view scenario, const char* artifact_path,
                   const char* wrong_artifact_path) {
    auto artifact = RegisteredParentBootstrapTransport::
        admit_public_query_artifact(SealedTraceArtifact::load(artifact_path));
    auto wrong_artifact = RegisteredParentBootstrapTransport::
        admit_public_query_artifact(
            SealedTraceArtifact::load(wrong_artifact_path));
    const auto jobs = contracts();
    const auto round = round_value();
    const auto selection = selected_identity(round, jobs);
    std::array<CompiledDriverSelection, 3> drivers{
        CompiledDriverSelection::test_only_mint(driver_value(0, selection)),
        CompiledDriverSelection::test_only_mint(driver_value(1, selection)),
        CompiledDriverSelection::test_only_mint(driver_value(2, selection)),
    };
    auto public_fork = fork_plan(drivers);
    Pipes pipes;
    auto fork = fork_authority(public_fork, pipes);
    pipes.close_writes();
    ChildFault child_fault = ChildFault::None;
    if (scenario == "wrong-model") child_fault = ChildFault::WrongModel;
    if (scenario == "wrong-ack") child_fault = ChildFault::WrongAck;
    if (scenario == "artifact-mixup") child_fault = ChildFault::ArtifactMixup;
    BootstrapProgram program(artifact, wrong_artifact, child_fault);
    auto children = RegisteredParentRoleFork::launch(
        std::move(fork), program);

    auto capture = capture_value();
    if (scenario == "wrong-trial") capture.trial = id(0xff);
    std::optional<ParentBootstrapPlanAuthority> plan;
    try {
        plan.emplace(RegisteredParentBootstrapTransport::test_only_prepare(
            round, jobs, CapturePlanAuthority::test_only_mint(capture),
            drivers, artifact, children));
    } catch (const identity_registry::Refused&) {
        assert(scenario == "wrong-trial");
        return;
    }
    try {
        if (scenario == "wrong-role")
            RegisteredParentBootstrapTransport::test_only_deliver(
                std::move(*plan), children,
                ParentBootstrapTestFault::SwapRoleZeroAndOneOffers);
        else
            RegisteredParentBootstrapTransport::deliver(
                std::move(*plan), children);
    } catch (const identity_registry::Refused&) {
        assert(scenario == "wrong-role" || scenario == "wrong-model" ||
               scenario == "wrong-ack" || scenario == "artifact-mixup");
        return;
    }
    assert(scenario == "valid" || scenario == "take-replay");
    for (unsigned role = 0; role < 3; ++role) {
        auto endpoint = children.take_completion_endpoint(role);
        const auto payload = ParentRoleForkTestCompletionBridge::receive(
            std::move(endpoint), id(210), 1);
        assert(payload.size() == 1 && payload[0] == role);
    }
    assert(children.wait().all_children_exited_zero);
}

void status() {
    const auto value = parent_bootstrap_source_status();
    assert(value.status == "SOURCE_ONLY_CONFIGURED0" &&
           value.typed_fresh_owner_history_consumption &&
           value.exact_three_role_authenticated_transport &&
           value.one_parent_sealed_query_artifact &&
           value.independent_child_pread_streams &&
           value.child_full_model_and_query_admission_gate &&
           !value.caller_digest_or_json_authority_route &&
           !value.production_selected_driver_factory &&
           !value.production_round1_history_minter &&
           !value.production_round2_successor_history_minter &&
           !value.selected_gate_callsite_integration &&
           !value.registered_driver_configured && !value.launch_authorized);
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 4);
    const std::string_view scenario(argv[1]);
    if (scenario == "status") status();
    else run_transport(scenario, argv[2], argv[3]);
    return 0;
}

