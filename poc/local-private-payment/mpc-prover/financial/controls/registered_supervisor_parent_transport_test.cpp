#include "../registered_parent_role_fork.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <filesystem>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

using namespace kpi::mpc::financial;
using namespace kpi::mpc::financial::attempt_supervisor;
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

identity_registry::Authority registry_authority() {
    return {
        .registration = id(1),
        .service = id(2),
        .source = id(3),
        .build = id(4),
        .aborted_runs = {identity_registry::mandatory_aborted_run()},
    };
}

struct Root final {
    std::filesystem::path path, journal, anchor;
    Root() {
        std::array<char, 96> pattern{};
        constexpr char prefix[] = "/tmp/kpb-supervisor-parent-XXXXXX";
        std::copy_n(prefix, sizeof(prefix), pattern.begin());
        const auto made = ::mkdtemp(pattern.data());
        assert(made != nullptr);
        path = made;
        journal = path / "journal";
        anchor = path / "anchor";
        assert(std::filesystem::create_directory(journal));
        assert(std::filesystem::create_directory(anchor));
        assert(::chmod(journal.c_str(), 0700) == 0);
        assert(::chmod(anchor.c_str(), 0700) == 0);
    }
    ~Root() { std::filesystem::remove_all(path); }
};

class MemoryAnchor final : public ExternalMonotonicAnchor {
    std::mutex mutex_;
    ExternalAnchorSnapshot value_;
public:
    explicit MemoryAnchor(const identity_registry::PublicSnapshot& value)
        : value_{value.authority_identity, value.sequence, value.checkpoint} {}
    ExternalAnchorSnapshot snapshot() override {
        std::lock_guard guard(mutex_);
        return value_;
    }
    void compare_and_advance(
            const ExternalAnchorSnapshot& expected,
            const ExternalAnchorSnapshot& next) override {
        std::lock_guard guard(mutex_);
        if (value_ != expected) throw identity_registry::Refused();
        value_ = next;
    }
};

SupervisorAnchorPolicy anchor_policy(identity_registry::Registry& registry) {
    return SupervisorAnchorPolicy::test_only_mint(
        PublicAnchorPolicy{
            .policy_identity = id(0x50),
            .permission_separated = true,
            .monotonic = true,
            .child_path_exposed = false,
            .child_fd_exposed = false,
        },
        std::make_shared<MemoryAnchor>(registry.snapshot()));
}

Selection common_selection() {
    return {
        .run = id(0x100),
        .trial = id(0x101),
        .attempt = id(0x102),
        .cohort = id(0x103),
        .accepted_head = id(0x104),
        .owner_contracts = {id(0x105), id(0x106), id(0x107)},
    };
}

Proposal proposal(
        unsigned role, const PublicParentAuthenticatedPartyDelivery& delivery,
        Selection selected) {
    return Proposal::test_only_mint(
        role, delivery.authority_identity, delivery.supervisor_session,
        delivery.party_session,
        AttemptLineageCommitment::test_only_mint(
            selected.run, selected.trial, selected.attempt, selected.cohort),
        DirectAcceptedHeadCommitment::test_only_mint(
            selected.accepted_head),
        CanonicalOwnerContractsCommitment::test_only_mint(
            selected.owner_contracts));
}

struct Pipes final {
    std::array<std::array<int, 2>, 3> values{};
    Pipes() {
        for (auto& pipe : values)
            assert(::pipe2(pipe.data(), O_CLOEXEC) == 0);
    }
    ~Pipes() {
        for (const auto& pipe : values)
            for (const auto fd : pipe)
                if (fd >= 0) ::close(fd);
    }
    void close_writes() {
        for (auto& pipe : values) {
            assert(::close(pipe[1]) == 0);
            pipe[1] = -1;
        }
    }
};

PublicParentRoleForkPlan plan(
        const Digest& authority, const Digest& supervisor_session) {
    PublicParentRoleForkPlan value{
        .classification = CaptureClassification::HiddenCandidate,
        .round = 1,
        .capture_trial_id = std::string(TRIAL_UUID),
        .trial = RegisteredCapturePlanRosterBridge::trial_identity(
            TRIAL_UUID),
        .financial_run = id(0x19),
        .attempt = id(0x1a),
        .cohort = id(0x1b),
        .fresh_owner_issuance_identity = id(0x1c),
        .authority_identity = authority,
        .supervisor_session = supervisor_session,
        .capture_plan_identity = id(0x20),
        .capture_source_identity = id(0x21),
        .capture_build_identity = id(0x22),
        .capture_launcher_identity = id(0x23),
    };
    for (unsigned role = 0; role < 3; ++role)
        value.roles[role] = {
            .role = role,
            .party_session = id(0x30 + role),
            .service_identity = id(0x40),
            .driver_selection_identity = id(0x41 + role),
        };
    return value;
}

std::array<InheritedCaptureEndpointAuthority, 3> endpoints(
        const PublicParentRoleForkPlan& value, const Pipes& pipes) {
    return {
        InheritedCaptureEndpointAuthority::test_only_mint(
            {.kind = InheritedCaptureKind::Projection, .role = 0,
             .round = 1, .fixed_fd = 20, .authority_identity = id(0x60),
             .capture_plan_identity = value.capture_plan_identity},
            pipes.values[0][1]),
        InheritedCaptureEndpointAuthority::test_only_mint(
            {.kind = InheritedCaptureKind::Dispatcher, .role = 0,
             .round = 1, .fixed_fd = 22, .authority_identity = id(0x61),
             .capture_plan_identity = value.capture_plan_identity},
            pipes.values[1][1]),
        InheritedCaptureEndpointAuthority::test_only_mint(
            {.kind = InheritedCaptureKind::CorruptServer, .role = 1,
             .round = 1, .fixed_fd = 23, .authority_identity = id(0x62),
             .capture_plan_identity = value.capture_plan_identity},
            pipes.values[2][1]),
    };
}

template<class Callable>
void refuses(Callable&& callable) {
    bool refused = false;
    try { callable(); }
    catch (const identity_registry::Refused&) { refused = true; }
    assert(refused);
}

class Program final : public RegisteredRoleChildProgram {
public:
    enum class Mutation { None, MixedSelection, WrongRole, WrongAck,
                          DuplicateProposal, DuplicateAck } mutation_;
    explicit Program(Mutation mutation) : mutation_(mutation) {}

    int run(
            ParentAuthenticatedPartyDeliveryAuthority&& delivered,
            ChildRoleCompletionEndpointAuthority&& endpoint) override {
        const auto delivery = delivered.public_receipt();
        auto selected = common_selection();
        if (mutation_ == Mutation::MixedSelection && delivery.role == 2)
            selected.cohort = id(0xdead);
        const auto proposed_role =
            mutation_ == Mutation::WrongRole && delivery.role == 2
                ? 1U : delivery.role;
        auto local = proposal(proposed_role, delivery, selected);
        SupervisorTransportTestFault fault = SupervisorTransportTestFault::None;
        if (mutation_ == Mutation::WrongAck && delivery.role == 1)
            fault = SupervisorTransportTestFault::WrongApprovalAck;
        if (mutation_ == Mutation::DuplicateProposal && delivery.role == 1)
            fault = SupervisorTransportTestFault::DuplicateProposal;
        if (mutation_ == Mutation::DuplicateAck && delivery.role == 1)
            fault = SupervisorTransportTestFault::DuplicateApprovalAck;
        auto approval = RegisteredSupervisorParentTransport::
            test_only_submit_and_wait(local, endpoint, fault);
        if (approval.public_receipt().role != delivery.role ||
            approval.public_receipt().party_session != delivery.party_session ||
            approval.public_receipt().selection_identity !=
                identity_registry::selection_identity(selected)) return 10;
        auto fresh = approval.recheck_before_lock(
            local, DirectAcceptedHeadCommitment::test_only_mint(
                       selected.accepted_head));
        if (fresh.public_receipt().role != delivery.role) return 11;
        const std::array<unsigned char, 1> payload{
            static_cast<unsigned char>(delivery.role)};
        ParentRoleForkTestCompletionBridge::submit(
            std::move(endpoint), id(0x90), payload);
        return 0;
    }
};

void receive_completion(ParentRoleChildren& children) {
    for (unsigned role = 0; role < 3; ++role) {
        auto endpoint = children.take_completion_endpoint(role);
        const auto payload = ParentRoleForkTestCompletionBridge::receive(
            std::move(endpoint), id(0x90), 1);
        assert(payload.size() == 1 && payload[0] == role);
    }
    assert(children.wait().all_children_exited_zero);
}

void run_happy() {
    Root root;
    auto registry = identity_registry::Registry::initialize_fresh_unfunded(
        root.journal, root.anchor, registry_authority());
    const auto authority = registry.snapshot().authority_identity;
    const auto supervisor_session = id(0x70);
    Supervisor supervisor(
        registry, supervisor_session, anchor_policy(registry));
    const auto selected_plan = plan(authority, supervisor_session);
    Pipes pipes;
    auto fork_plan = ParentRoleForkPlanAuthority::test_only_mint(
        selected_plan, endpoints(selected_plan, pipes));
    pipes.close_writes();
    Program program(Program::Mutation::None);
    auto children = RegisteredParentRoleFork::launch(
        std::move(fork_plan), program);
    RegisteredSupervisorParentTransport::test_only_approve(
        supervisor, children);
    assert(registry.snapshot().sequence == 1);
    receive_completion(children);
}

void run_refusal(Program::Mutation mutation) {
    Root root;
    auto registry = identity_registry::Registry::initialize_fresh_unfunded(
        root.journal, root.anchor, registry_authority());
    const auto authority = registry.snapshot().authority_identity;
    const auto supervisor_session = id(0x71);
    Supervisor supervisor(
        registry, supervisor_session, anchor_policy(registry));
    const auto selected_plan = plan(authority, supervisor_session);
    Pipes pipes;
    auto fork_plan = ParentRoleForkPlanAuthority::test_only_mint(
        selected_plan, endpoints(selected_plan, pipes));
    pipes.close_writes();
    Program program(mutation);
    auto children = RegisteredParentRoleFork::launch(
        std::move(fork_plan), program);
    refuses([&] {
        RegisteredSupervisorParentTransport::test_only_approve(
            supervisor, children);
    });
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::string scenario(argv[1]);
    if (scenario == "happy") run_happy();
    else if (scenario == "mixed")
        run_refusal(Program::Mutation::MixedSelection);
    else if (scenario == "wrong-role")
        run_refusal(Program::Mutation::WrongRole);
    else if (scenario == "wrong-ack")
        run_refusal(Program::Mutation::WrongAck);
    else if (scenario == "duplicate-proposal")
        run_refusal(Program::Mutation::DuplicateProposal);
    else if (scenario == "duplicate-ack")
        run_refusal(Program::Mutation::DuplicateAck);
    else return 64;
    return 0;
}
