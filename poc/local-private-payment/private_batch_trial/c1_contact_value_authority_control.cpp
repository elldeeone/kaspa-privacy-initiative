#include "c1_contact_value_authority.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <openssl/sha.h>
#include <span>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/wait.h>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace kpb::measurement;
using namespace kpb::measurement::c1_capture;
using namespace kpb::measurement::producer_runtime;

namespace kpb::measurement::c1_capture {
void c1_contact_value_test_fail_next_get_seals();
}

namespace {

using Bytes = std::vector<unsigned char>;

constexpr std::string_view ATTEMPT_DOMAIN = "KPB_CAPTURE_ATTEMPT_ID_V1\n";
constexpr std::string_view CAPTURE_DOMAIN = "KPB_CAPTURE_IDENTITY_V1\n";
constexpr std::string_view STAGE_DOMAIN =
    "KPB_C1_CONTACT_VALUE_STAGE_PLAN_V1\n";
constexpr std::string_view ROUTE_DOMAIN =
    "KPB_C1_AUTHENTICATED_INVOICE_ROUTE_V1\n";
constexpr std::string_view ATTEMPT =
    "11111111-1111-4111-8111-111111111111";
constexpr std::string_view SECOND_ATTEMPT =
    "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
constexpr std::string_view TRIAL =
    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
constexpr std::string_view CAPTURE =
    "22222222-2222-4222-8222-222222222222";
constexpr std::array<std::string_view, 3> OPERATIONS{
    "33333333-3333-4333-8333-333333333333",
    "44444444-4444-4444-8444-444444444444",
    "55555555-5555-4555-8555-555555555555",
};

template<class Function>
void expect_refused(Function&& function) {
    bool refused = false;
    try { function(); } catch (const Refused&) { refused = true; }
    assert(refused);
}

Digest digest(unsigned char value) {
    Digest result{};
    result.fill(value);
    return result;
}

Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    assert(SHA256(value.data(), value.size(), result.data()));
    return result;
}

Digest hash(std::string_view value) {
    return hash(std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
}

Digest domain_hash(std::string_view domain, std::string_view value) {
    Bytes bytes(domain.begin(), domain.end());
    bytes.insert(bytes.end(), value.begin(), value.end());
    return hash(bytes);
}

Digest registered_trial_identity(std::string_view value) {
    constexpr std::string_view domain =
        "KPB_REGISTERED_TRIAL_UUID_IDENTITY_V1\n";
    Bytes bytes(domain.begin(), domain.end());
    const auto size = static_cast<std::uint64_t>(value.size());
    for (unsigned shift = 0; shift < 64; shift += 8)
        bytes.push_back(static_cast<unsigned char>(size >> shift));
    bytes.insert(bytes.end(), value.begin(), value.end());
    return hash(bytes);
}

void add(Bytes& out, const Digest& value) {
    out.insert(out.end(), value.begin(), value.end());
}

void add(Bytes& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}

std::array<std::string, 3> operations() {
    return {std::string(OPERATIONS[0]), std::string(OPERATIONS[1]),
            std::string(OPERATIONS[2])};
}

Digest stage_identity(const std::array<std::string, 3>& selected,
                      unsigned round = 1) {
    Bytes bytes(STAGE_DOMAIN.begin(), STAGE_DOMAIN.end());
    bytes.push_back(static_cast<unsigned char>(round));
    bytes.push_back(1);
    for (unsigned index = 0; index < selected.size(); ++index) {
        bytes.push_back(static_cast<unsigned char>(index));
        bytes.push_back(static_cast<unsigned char>(index + 1));
        add(bytes, selected[index]);
        bytes.push_back(index == 1 ? 1 : 0);
        if (index == 1) add(bytes, selected[0]);
        else bytes.insert(bytes.end(), 36, 0);
    }
    return hash(bytes);
}

Digest route_identity(const std::array<unsigned, 3>& contacts,
                      const std::array<std::string, 3>& selected,
                      const Digest& route_source, unsigned round = 1) {
    Bytes bytes(ROUTE_DOMAIN.begin(), ROUTE_DOMAIN.end());
    bytes.push_back(static_cast<unsigned char>(round));
    bytes.push_back(1);
    add(bytes, route_source);
    for (unsigned index = 0; index < selected.size(); ++index) {
        bytes.push_back(static_cast<unsigned char>(index));
        bytes.push_back(static_cast<unsigned char>(contacts[index]));
        add(bytes, selected[index]);
        bytes.push_back(index == 1 ? 1 : 0);
        if (index == 1) add(bytes, selected[0]);
        else bytes.insert(bytes.end(), 36, 0);
    }
    return hash(bytes);
}

WorkerBinding worker(const ManifestEntry& entry) {
    return {
        .source_identity = entry.source_identity,
        .build_identity = entry.build_identity,
        .runtime_identity = entry.runtime_identity,
        .assets_identity = entry.assets_identity,
        .pinned_executable_identity = entry.pinned_executable_identity,
        .launcher_identity = entry.launcher_identity,
    };
}

RunBinding binding() {
    std::array<ManifestEntry, 10> entries{};
    for (unsigned index = 0; index < entries.size(); ++index) {
        const auto seed = static_cast<unsigned char>(0xb0 + index * 6);
        entries[index] = ManifestEntry{
            .component = static_cast<ManifestComponent>(index + 1),
            .source_identity = digest(seed),
            .build_identity = digest(static_cast<unsigned char>(seed + 1)),
            .runtime_identity = digest(static_cast<unsigned char>(seed + 2)),
            .assets_identity = digest(static_cast<unsigned char>(seed + 3)),
            .pinned_executable_identity =
                digest(static_cast<unsigned char>(seed + 4)),
            .launcher_identity = digest(static_cast<unsigned char>(seed + 5)),
        };
    }
    FiniteManifestBinding manifest{
        .manifest_identity = recompute_finite_manifest_identity(entries),
        .parent_recomputation_identity = digest(0xaf),
        .entries = entries,
    };
    const auto& capture_entry = manifest.entries[1];
    return RunBinding{
        .classification = Classification::HiddenCandidate,
        .comparison_selection = digest(0x10),
        .run_selection = digest(0x11),
        .trial = registered_trial_identity(TRIAL),
        .attempt = digest(0x13),
        .cohort = digest(0x14),
        .capture = domain_hash(CAPTURE_DOMAIN, CAPTURE),
        .method = digest(0x16),
        .workload = digest(0x17),
        .source_closure = digest(0x18),
        .runtime = digest(0x19),
        .finite_manifest = manifest,
        .outer_parent_process = digest(0x1a),
        .outer_parent_executable = digest(0x1b),
        .capture_source = capture_entry.source_identity,
        .capture_build = capture_entry.build_identity,
        .capture_runtime = capture_entry.runtime_identity,
        .capture_launcher = capture_entry.launcher_identity,
        .observer_worker = worker(manifest.entries[6]),
        .score_worker = worker(manifest.entries[7]),
        .aggregate_worker = worker(manifest.entries[8]),
        .financial_runs = {digest(0x20), digest(0x21)},
        .round_attempts = {
            domain_hash(ATTEMPT_DOMAIN, ATTEMPT),
            domain_hash(ATTEMPT_DOMAIN, SECOND_ATTEMPT)},
        .round_cohorts = {digest(0x24), digest(0x25)},
        .round_capture_plans = {digest(0x26), digest(0x27)},
        .projections = {digest(0x28), digest(0x29)},
    };
}

PublicProducerLaunchPlan plan() {
    const auto selected = binding();
    PublicProducerLaunchPlan result{
        .binding = selected,
        .capture_trial_id = std::string(TRIAL),
        .capture_attempt_ids = {
            std::string(ATTEMPT),
            std::string(SECOND_ATTEMPT),
        },
        .producer_process_identity = selected.outer_parent_process,
        .role_closure_identity = selected.source_closure,
        .manifest_seal = selected.finite_manifest.manifest_identity,
        .construction_policy =
            ConstructionPolicy::SecretPermutationIndependent,
        .construction_classification_receipt = digest(0x30),
        .opaque_closure_authority_identity = digest(0x35),
        .route_requirements = {
            PublicAggregateMailboxRouteRequirement{
                .round = 1,
                .projection_identity = selected.projections[0],
                .projection_bytes = 10685,
                .route_endpoint_count = 1,
                .owner_ack_count = 0,
                .role_blind_required = true,
                .after_full_cohort_barrier_required = true,
                .owner_socket_or_path_derivation_forbidden = true,
            },
            PublicAggregateMailboxRouteRequirement{
                .round = 2,
                .projection_identity = selected.projections[1],
                .projection_bytes = 10685,
                .route_endpoint_count = 1,
                .owner_ack_count = 0,
                .role_blind_required = true,
                .after_full_cohort_barrier_required = true,
                .owner_socket_or_path_derivation_forbidden = true,
            },
        },
    };
    for (unsigned index = 0; index < result.streams.size(); ++index) {
        result.streams[index] = PublicProducerStreamPlan{
            .round = index / 5 + 1,
            .kind = static_cast<CaptureKind>(index % 5 + 1),
            .fixed_fd = 20 + index,
            .process_identity =
                digest(static_cast<unsigned char>(0x40 + index)),
            .child_exit_identity =
                digest(static_cast<unsigned char>(0x50 + index)),
        };
    }
    return result;
}

void close_fd(int& fd) {
    if (fd < 0) return;
    (void)::close(fd);
    fd = -1;
}

struct PipeSet {
    std::array<int, 10> reads{};
    std::array<int, 10> writes{};
    PipeSet() {
        reads.fill(-1);
        writes.fill(-1);
        for (unsigned index = 0; index < reads.size(); ++index) {
            int pair[2]{};
            assert(::pipe2(pair, O_CLOEXEC) == 0);
            reads[index] = pair[0];
            writes[index] = pair[1];
        }
    }
    ~PipeSet() {
        for (auto& fd : reads) close_fd(fd);
        for (auto& fd : writes) close_fd(fd);
    }
};

ParentTenReadEndsAuthority parent(PipeSet& pipes,
                                  const PublicProducerLaunchPlan& selected) {
    auto reads = pipes.reads;
    pipes.reads.fill(-1);
    return ParentTenReadEndsAuthority::test_only_mint(
        selected, std::move(reads));
}

PublicC1InvoiceRoute route_value(
        const RunBinding& selected,
        const std::array<std::string, 3>& selected_operations,
        std::array<unsigned, 3> contacts = {0, 2, 0},
        Digest route_source = digest(0x71)) {
    return PublicC1InvoiceRoute{
        .binding = selected,
        .round = 1,
        .contact_owner_components = contacts,
        .operation_ids = selected_operations,
        .route_identity = route_identity(
            contacts, selected_operations, route_source),
        .route_source_identity = route_source,
    };
}

PublicC1LifecycleStagePlan stage_value(
        const RunBinding& selected,
        const std::array<std::string, 3>& selected_operations,
        const PublicC1InvoiceRoute& route) {
    return PublicC1LifecycleStagePlan{
        .binding = selected,
        .round = 1,
        .capture_attempt_id = std::string(ATTEMPT),
        .capture_identity = std::string(CAPTURE),
        .operation_ids = selected_operations,
        .expected_route_identity = route.route_identity,
        .expected_route_source_identity = route.route_source_identity,
        .stage_plan_identity = stage_identity(selected_operations),
    };
}

C1ContactValueAuthoritySplit prepare(
        ParentTenReadEndsAuthority& selected_parent,
        const RunBinding& selected_binding,
        const std::array<std::string, 3>& selected_operations,
        const PublicC1InvoiceRoute& route) {
    auto stage = C1LifecycleStagePlanAuthority::test_only_mint(
        stage_value(selected_binding, selected_operations, route));
    auto route_authority = C1InvoiceRouteAuthority::test_only_mint(route);
    return C1ContactValueAuthorityBridge::prepare(
        selected_parent, std::move(stage), std::move(route_authority));
}

Bytes read_exact(int fd) {
    Bytes result(C1_CONTACT_VALUE_OFFER_BYTES);
    std::size_t at = 0;
    while (at < result.size()) {
        const auto count = ::pread(fd, result.data() + at,
                                   result.size() - at,
                                   static_cast<off_t>(at));
        if (count < 0 && errno == EINTR) continue;
        assert(count > 0);
        at += static_cast<std::size_t>(count);
    }
    return result;
}

void write_all(int fd, std::span<const unsigned char> value) {
    std::size_t at = 0;
    while (at < value.size()) {
        const auto count = ::write(fd, value.data() + at, value.size() - at);
        if (count < 0 && errno == EINTR) continue;
        assert(count > 0);
        at += static_cast<std::size_t>(count);
    }
}

void emit_offer_fixture() {
    auto selected_plan = plan();
    PipeSet pipes;
    auto selected_parent = parent(pipes, selected_plan);
    const auto selected_operations = operations();
    const auto route = route_value(
        selected_plan.binding, selected_operations);
    auto split = prepare(selected_parent, selected_plan.binding,
                         selected_operations, route);
    auto offer = split.take_offer();
    int fd = offer.test_only_take_fd();
    const auto raw = read_exact(fd);
    close_fd(fd);
    write_all(STDOUT_FILENO, raw);
}

void positive_and_replay_controls() {
    auto selected_plan = plan();
    PipeSet pipes;
    auto selected_parent = parent(pipes, selected_plan);
    const auto selected_operations = operations();
    const auto route = route_value(
        selected_plan.binding, selected_operations);
    auto split = prepare(selected_parent, selected_plan.binding,
                         selected_operations, route);
    auto offer = split.take_offer();
    int fd = offer.test_only_take_fd();
    const auto raw = read_exact(fd);
    assert(std::equal(raw.begin(), raw.begin() + 8,
                      std::array<unsigned char, 8>{
                          'K','P','B','C','1','O','F','1'}.begin()));
    assert(raw[8] == 2 && raw[9] == 1 && raw[10] == 1 &&
           raw[11] == 24 && raw[12] == 31 && raw[13] == 3 &&
           raw[14] == 0 && raw[15] == 2 && raw[16] == 0 && raw[17] == 0);
    const auto& c1 = selected_plan.binding.finite_manifest.entries[2];
    assert(std::equal(c1.assets_identity.begin(), c1.assets_identity.end(),
                      raw.begin() + 250));
    assert(std::equal(c1.pinned_executable_identity.begin(),
                      c1.pinned_executable_identity.end(),
                      raw.begin() + 282));
    Digest authority_identity{};
    std::copy(raw.end() - 32, raw.end(), authority_identity.begin());
    close_fd(fd);

    std::array<Digest, 3> operation_identities{};
    for (unsigned index = 0; index < selected_operations.size(); ++index)
        operation_identities[index] = hash(selected_operations[index]);
    auto residual = split.take_postcapture_residual();
    assert(residual.test_only_matches(
        selected_plan.binding, 1, authority_identity,
        stage_identity(selected_operations), operation_identities));
    expect_refused([&] { (void)split.take_offer(); });
    expect_refused([&] { (void)split.take_postcapture_residual(); });

    expect_refused([&] {
        (void)prepare(selected_parent, selected_plan.binding,
                      selected_operations, route);
    });
}

void cross_binding_controls() {
    const auto selected_operations = operations();

    {
        auto selected_plan = plan();
        PipeSet pipes;
        auto selected_parent = parent(pipes, selected_plan);
        const auto expected_route = route_value(
            selected_plan.binding, selected_operations);
        auto alternate_route = route_value(
            selected_plan.binding, selected_operations, {2, 0, 2},
            digest(0x72));
        auto stage = C1LifecycleStagePlanAuthority::test_only_mint(
            stage_value(selected_plan.binding, selected_operations,
                        expected_route));
        auto route = C1InvoiceRouteAuthority::test_only_mint(
            alternate_route);
        expect_refused([&] {
            (void)C1ContactValueAuthorityBridge::prepare(
                selected_parent, std::move(stage), std::move(route));
        });
        // A failed prelaunch join poisons this parent/round. It cannot be
        // repaired by retrying with a different authority tuple.
        expect_refused([&] {
            (void)prepare(selected_parent, selected_plan.binding,
                          selected_operations, expected_route);
        });
    }

    {
        auto selected_plan = plan();
        PipeSet pipes;
        auto selected_parent = parent(pipes, selected_plan);
        auto changed_operations = selected_operations;
        changed_operations[2] =
            "66666666-6666-4666-8666-666666666666";
        const auto expected_route = route_value(
            selected_plan.binding, selected_operations);
        auto other_route = route_value(
            selected_plan.binding, changed_operations);
        auto stage = C1LifecycleStagePlanAuthority::test_only_mint(
            stage_value(selected_plan.binding, selected_operations,
                        expected_route));
        auto route = C1InvoiceRouteAuthority::test_only_mint(other_route);
        expect_refused([&] {
            (void)C1ContactValueAuthorityBridge::prepare(
                selected_parent, std::move(stage), std::move(route));
        });
    }

    {
        auto selected_plan = plan();
        PipeSet pipes;
        auto selected_parent = parent(pipes, selected_plan);
        auto other_binding = selected_plan.binding;
        other_binding.run_selection = digest(0x91);
        const auto route = route_value(other_binding, selected_operations);
        auto stage = C1LifecycleStagePlanAuthority::test_only_mint(
            stage_value(other_binding, selected_operations, route));
        auto route_authority = C1InvoiceRouteAuthority::test_only_mint(route);
        expect_refused([&] {
            (void)C1ContactValueAuthorityBridge::prepare(
                selected_parent, std::move(stage),
                std::move(route_authority));
        });
    }

    {
        const auto selected_plan = plan();
        const auto& entry =
            selected_plan.binding.finite_manifest.entries[2];
        const std::array<Digest, 3> distinct_operations{
            digest(0x81), digest(0x82), digest(0x83)};
        expect_refused([&] {
            (void)C1PostcaptureAdmissionAuthority::test_only_mint(
                selected_plan.binding, 1, 24, digest(0x70),
                selected_plan.binding.source_closure, digest(0x71),
                digest(0x72), digest(0x73),
                selected_plan.streams[4].process_identity,
                selected_plan.streams[4].child_exit_identity,
                worker(entry), {0, 0, 0}, distinct_operations);
        });
        expect_refused([&] {
            (void)C1PostcaptureAdmissionAuthority::test_only_mint(
                selected_plan.binding, 1, 24, digest(0x70),
                selected_plan.binding.source_closure, digest(0x71),
                digest(0x72), digest(0x73),
                selected_plan.streams[4].process_identity,
                selected_plan.streams[4].child_exit_identity,
                worker(entry), {0, 2, 0},
                {digest(0x81), digest(0x81), digest(0x83)});
        });
    }
}

void sealed_install_control() {
    auto selected_plan = plan();
    PipeSet pipes;
    auto selected_parent = parent(pipes, selected_plan);
    const auto selected_operations = operations();
    const auto route = route_value(
        selected_plan.binding, selected_operations);
    auto split = prepare(selected_parent, selected_plan.binding,
                         selected_operations, route);
    auto offer = split.take_offer();

    const auto child = ::fork();
    assert(child >= 0);
    if (child == 0) {
        try {
            std::move(offer).install_for_child();
            struct stat state{};
            constexpr int seals = F_SEAL_SEAL | F_SEAL_SHRINK |
                                  F_SEAL_GROW | F_SEAL_WRITE;
            const int flags = ::fcntl(C1_CONTACT_VALUE_OFFER_FIXED_FD,
                                      F_GETFD);
            const int observed_seals = ::fcntl(
                C1_CONTACT_VALUE_OFFER_FIXED_FD, F_GET_SEALS);
            if (::fstat(C1_CONTACT_VALUE_OFFER_FIXED_FD, &state) != 0 ||
                !S_ISREG(state.st_mode) || state.st_size !=
                    static_cast<off_t>(C1_CONTACT_VALUE_OFFER_BYTES) ||
                observed_seals < 0 ||
                (observed_seals & seals) != seals || flags < 0 ||
                (flags & FD_CLOEXEC) != 0)
                _exit(70);
            _exit(0);
        } catch (...) { _exit(71); }
    }
    int status = 0;
    assert(::waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

void seal_query_failure_is_refused() {
    auto selected_plan = plan();
    PipeSet pipes;
    auto selected_parent = parent(pipes, selected_plan);
    const auto selected_operations = operations();
    const auto route = route_value(
        selected_plan.binding, selected_operations);
    c1_contact_value_test_fail_next_get_seals();
    expect_refused([&] {
        (void)prepare(selected_parent, selected_plan.binding,
                      selected_operations, route);
    });
}

C1ContactValueOfferAuthority install_fault_offer() {
    auto selected_plan = plan();
    PipeSet pipes;
    auto selected_parent = parent(pipes, selected_plan);
    const auto selected_operations = operations();
    const auto route = route_value(
        selected_plan.binding, selected_operations);
    auto split = prepare(selected_parent, selected_plan.binding,
                         selected_operations, route);
    return split.take_offer();
}

void install_refusal_closes_and_invalidates_fds() {
    for (const auto fault : {
             TestC1OfferInstallFault::AfterDup,
             TestC1OfferInstallFault::AfterInstalledFstat,
             TestC1OfferInstallFault::AfterClearCloexec}) {
        int source = -1;
        {
            auto offer = install_fault_offer();
            source = offer.test_only_source_fd();
            assert(source >= 0 &&
                   source != C1_CONTACT_VALUE_OFFER_FIXED_FD);
            offer.test_only_set_install_fault(fault);
            expect_refused([&] {
                std::move(offer).install_for_child();
            });
            errno = 0;
            assert(::fcntl(source, F_GETFD) == -1 && errno == EBADF);
            errno = 0;
            assert(::fcntl(C1_CONTACT_VALUE_OFFER_FIXED_FD, F_GETFD) == -1 &&
                   errno == EBADF);

            int base = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
            assert(base >= 0);
            const int sentinel = ::fcntl(base, F_DUPFD_CLOEXEC, 64);
            assert(sentinel >= 64);
            close_fd(base);
            assert(::dup3(sentinel, source, O_CLOEXEC) == source);
            assert(::dup3(sentinel, C1_CONTACT_VALUE_OFFER_FIXED_FD,
                          O_CLOEXEC) ==
                   C1_CONTACT_VALUE_OFFER_FIXED_FD);
            int owned_sentinel = sentinel;
            close_fd(owned_sentinel);
        }
        // Destruction of the consumed authority must not close descriptor
        // numbers that were reused after the refusal.
        assert(::fcntl(source, F_GETFD) >= 0);
        assert(::fcntl(C1_CONTACT_VALUE_OFFER_FIXED_FD, F_GETFD) >= 0);
        close_fd(source);
        int target = C1_CONTACT_VALUE_OFFER_FIXED_FD;
        close_fd(target);
    }
}

void ordinary_file_replacement_is_refused() {
    auto offer = install_fault_offer();
    const int source = offer.test_only_source_fd();
    assert(source >= 0 && source != C1_CONTACT_VALUE_OFFER_FIXED_FD);

    char path[] = "/tmp/kpb-c1-contact-ordinary-control-XXXXXX";
    int ordinary = ::mkstemp(path);
    assert(ordinary >= 0 && ordinary != source &&
           ::unlink(path) == 0 && ::fchmod(ordinary, 0600) == 0 &&
           ::ftruncate(
               ordinary,
               static_cast<off_t>(C1_CONTACT_VALUE_OFFER_BYTES)) == 0 &&
           ::dup3(ordinary, source, O_CLOEXEC) == source);
    close_fd(ordinary);

    expect_refused([&] {
        std::move(offer).install_for_child();
    });
    errno = 0;
    assert(::fcntl(source, F_GETFD) == -1 && errno == EBADF);
    errno = 0;
    assert(::fcntl(C1_CONTACT_VALUE_OFFER_FIXED_FD, F_GETFD) == -1 &&
           errno == EBADF);
}

} // namespace

static_assert(!std::is_copy_constructible_v<
              C1LifecycleStagePlanAuthority>);
static_assert(!std::is_copy_constructible_v<C1InvoiceRouteAuthority>);
static_assert(!std::is_copy_constructible_v<
              C1ContactValueOfferAuthority>);
static_assert(!std::is_copy_constructible_v<
              C1PostcaptureAdmissionAuthority>);
static_assert(!std::is_constructible_v<
              C1PostcaptureAdmissionAuthority, RunBinding, unsigned,
              unsigned, Digest, Digest, Digest, Digest, Digest, Digest,
              Digest, WorkerBinding, std::array<unsigned, 3>,
              std::array<Digest, 3>>);

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--emit-offer") {
        emit_offer_fixture();
        return 0;
    }
    assert(argc == 1);
    positive_and_replay_controls();
    cross_binding_controls();
    sealed_install_control();
    seal_query_failure_is_refused();
    install_refusal_closes_and_invalidates_fds();
    ordinary_file_replacement_is_refused();
    return 0;
}
