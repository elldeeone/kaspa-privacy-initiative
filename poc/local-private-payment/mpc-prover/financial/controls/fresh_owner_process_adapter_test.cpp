#include "../fresh_owner_arm_isolation.hpp"
#include "../registered_parent_role_fork.hpp"
#include "../registered_preidentity_ready.hpp"
#include "../../../private_batch_trial/privacy_measurement_authority.hpp"
#include "../../../private_batch_trial/privacy_fresh_owner_transactional_replay_authority.hpp"
#include "../../../private_batch_trial/privacy_registered_fresh_trial_capture_topology_reservation.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <climits>
#include <concepts>
#include <csignal>
#include <cstdlib>
#include <dirent.h>
#include <exception>
#include <fcntl.h>
#include <memory>
#include <new>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using namespace kpi::mpc;
using namespace kpi::mpc::financial;
using namespace kpi::mpc::financial::fresh_owner_issuance;
using namespace kpi::mpc::financial::registered_driver;
using kpi::mpc::financial::registered_driver::CaptureClassification;

namespace {

namespace replay =
    kpb::measurement::fresh_owner_transactional_replay;

Digest id(unsigned value) {
    Digest result{};
    result[0] = static_cast<unsigned char>(value);
    result[1] = static_cast<unsigned char>(value >> 8);
    result[31] = static_cast<unsigned char>(value ^ 0x6dU);
    return result;
}

std::string hex(unsigned value) {
    return identity_registry::hex(id(value));
}

LogicalOwnerIdentity logical_id(unsigned owner) {
    LogicalOwnerIdentity result{};
    result[0] = static_cast<unsigned char>(0x40 + owner);
    result[31] = static_cast<unsigned char>(0xe0 + owner);
    return result;
}

kpb::measurement::WorkerBinding measurement_worker(
        const kpb::measurement::ManifestEntry& entry) {
    return {
        .source_identity = entry.source_identity,
        .build_identity = entry.build_identity,
        .runtime_identity = entry.runtime_identity,
        .assets_identity = entry.assets_identity,
        .pinned_executable_identity = entry.pinned_executable_identity,
        .launcher_identity = entry.launcher_identity,
    };
}

kpb::measurement::FiniteManifestBinding measurement_manifest() {
    using namespace kpb::measurement;
    std::array<ManifestEntry, 10> entries{};
    for (unsigned index = 0; index < entries.size(); ++index) {
        const unsigned base = 0x7000 + index * 0x10;
        entries[index] = ManifestEntry{
            .component = static_cast<ManifestComponent>(index + 1),
            .source_identity = id(base + 1),
            .build_identity = id(base + 2),
            .runtime_identity = id(base + 3),
            .assets_identity = id(base + 4),
            .pinned_executable_identity = id(base + 5),
            .launcher_identity = id(base + 6),
        };
    }
    return {
        .manifest_identity = recompute_finite_manifest_identity(entries),
        .parent_recomputation_identity = id(0x70f0),
        .entries = entries,
    };
}

kpb::measurement::RunBinding candidate_measurement_binding() {
    using namespace kpb::measurement;
    const auto manifest = measurement_manifest();
    const auto& capture = manifest.entries[1];
    return {
        .classification = Classification::HiddenCandidate,
        .comparison_selection = id(0x7101),
        .run_selection = id(0x7102),
        .trial = id(9),
        .attempt = id(0x7103),
        .cohort = id(0x7104),
        .capture = id(0x7105),
        .method = id(0x7106),
        .workload = id(0x7107),
        .source_closure = id(0x7108),
        .runtime = id(0x7109),
        .finite_manifest = manifest,
        .outer_parent_process = id(0x710a),
        .outer_parent_executable = id(0x710b),
        .capture_source = capture.source_identity,
        .capture_build = capture.build_identity,
        .capture_runtime = capture.runtime_identity,
        .capture_launcher = capture.launcher_identity,
        .observer_worker = measurement_worker(manifest.entries[6]),
        .score_worker = measurement_worker(manifest.entries[7]),
        .aggregate_worker = measurement_worker(manifest.entries[8]),
        .financial_runs = {id(0xf10), id(0xf20)},
        .round_attempts = {id(0x101), id(0x201)},
        .round_cohorts = {id(0x102), id(0x202)},
        .round_capture_plans = {id(0xf11), id(0xf21)},
        .projections = {id(0xf12), id(0xf22)},
    };
}

kpb::measurement::RunMeasurement candidate_measurement(
        const kpb::measurement::RunBinding& binding) {
    using namespace kpb::measurement;
    PublicTrialCaptureCompletion completion{};
    completion.binding = binding;
    completion.producer_worker =
        measurement_worker(binding.finite_manifest.entries[5]);
    completion.completion_identity = id(0x7200);
    return RunMeasurement(
        TrialCaptureCompletionAuthority::test_only_mint(
            std::move(completion)));
}

kpb::measurement::CandidateTruthBarrierReleaseAuthority
genuine_candidate_barrier_release(
        kpb::measurement::RunBinding binding =
            candidate_measurement_binding()) {
    using namespace kpb::measurement;
    auto measurement = candidate_measurement(binding);
    auto observer = measurement.issue_observer();
    const auto observer_receipt = observer.public_receipt();
    auto observation = ObservationCompletionAuthority::test_only_mint(
        PublicObservationCompletion{
            .binding = binding,
            .permit_identity = observer_receipt.permit_identity,
            .trial_capture_identity =
                observer_receipt.trial_capture_identity,
            .child_exit = id(0x7201),
            .observation_receipt = id(0x7202),
            .worker = binding.observer_worker,
            .process_identity = id(0x7203),
        });
    const auto public_observation = observation.public_receipt();
    auto execution = std::move(observer).test_only_take_execution();
    measurement.accept_observer(
        std::move(execution), std::move(observation));
    measurement.freeze_barrier(BarrierFreezeAuthority::test_only_mint(
        PublicBarrierFreeze{
            .binding = binding,
            .trial_capture_identity =
                public_observation.trial_capture_identity,
            .observation_receipt = public_observation.observation_receipt,
            .barrier_receipt = id(0xf01),
            .outer_parent_process = binding.outer_parent_process,
            .outer_parent_executable = binding.outer_parent_executable,
            .manifest_recomputation_receipt =
                binding.finite_manifest.parent_recomputation_identity,
        }));
    return measurement.issue_candidate_truth_barrier_release();
}

OwnerInputContract contract(unsigned owner, unsigned round) {
    const unsigned base = round == 1 ? 0x100 : 0x200;
    return OwnerInputContract{
        .run_nonce = hex(base + 1),
        .model_identity = hex(0x300),
        .source_identity = hex(0x301),
        .proving_key_identity = hex(0x302),
        .verifying_key_identity = hex(0x303),
        .cohort_identity = hex(base + 2),
        .owner_id = static_cast<int>(owner),
        .input_count = 2'635'409,
        .server_certificate_sha256 = {
            hex(base + 10), hex(base + 11), hex(base + 12)},
        .owner_certificate_sha256 = hex(base + 20 + owner),
        .trace_identity = hex(0x304),
        .layout_identity = hex(0x305),
    };
}

PublicFreshOwnerProcessPlan plan() {
    PublicFreshOwnerProcessPlan value{
        .classification =
            CaptureClassification::ExplicitOwnerPublicEffectsBaseline,
        .process_authority_identity = id(1),
        .registration_identity = id(2),
        .service_identity = id(3),
        .controller_source_identity = id(4),
        .controller_build_identity = id(5),
        .owner_issuer_source_identity = id(6),
        .owner_issuer_build_identity = id(7),
        .owner_runtime_identity = id(0x70),
        .run = id(8),
        .trial = id(9),
        .root_identity = id(10),
        .baseline_policy_identity = id(0x700),
        .roster_authority_identity = id(0x600),
    };
    for (unsigned owner = 0; owner < 3; ++owner) {
        auto& selected = value.owners[owner];
        selected.owner_component = owner;
        for (unsigned round = 1; round <= 2; ++round) {
            const unsigned base = round == 1 ? 0x100 : 0x200;
            auto& item = selected.rounds[round - 1];
            item.round = round;
            item.attempt = id(base + 1);
            item.cohort = id(base + 2);
            if (round == 1) {
                item.accepted_input_head_identity = id(base + 3);
                item.history_gate_identity = id(base + 4);
            } else {
                item.accepted_input_head_identity = id(base + 3);
                item.history_gate_identity = id(base + 4);
            }
            item.contract = contract(owner, round);
            item.file_identity = {};
            item.file_metadata_identity = {};
            item.file_bytes = OWNER_PRIVATE_INPUT_V2_BYTES;
            item.owner_tls_spki_identity = id(base + 50 + owner);
            item.server_tls_spki_identities = {
                id(base + 60), id(base + 61), id(base + 62)};
        }
    }
    return value;
}

PublicFreshOwnerProcessPlan hidden_plan() {
    auto value = plan();
    value.classification = CaptureClassification::HiddenCandidate;
    value.baseline_policy_identity = {};
    value.roster_authority_identity = {};
    value.candidate_truth_financial_runs = {id(0xf10), id(0xf20)};
    value.candidate_truth_capture_plan_identities = {
        id(0xf11), id(0xf21)};
    value.candidate_truth_projection_identities = {id(0xf12), id(0xf22)};
    value.candidate_truth_context_identities = {id(0xf13), id(0xf23)};
    value.measurement_run_binding_identity = id(0x7f00);
    return value;
}

PublicFreshOwnerProcessPlan isolated_hidden_plan() {
    auto value = hidden_plan();
    value.process_authority_identity = id(0x6000);
    value.owner_runtime_identity = id(0x6001);
    for (unsigned owner = 0; owner < 3; ++owner) {
        for (unsigned index = 0; index < 2; ++index) {
            const unsigned base = index == 0 ? 0x4000 : 0x5000;
            auto& round = value.owners[owner].rounds[index];
            round.contract.owner_certificate_sha256 =
                hex(base + 20 + owner);
            round.contract.server_certificate_sha256 = {
                hex(base + 10), hex(base + 11), hex(base + 12)};
            round.owner_tls_spki_identity = id(base + 50 + owner);
            round.server_tls_spki_identities = {
                id(base + 60), id(base + 61), id(base + 62)};
        }
    }
    return value;
}

class TestVerifier final : public LongLivedOwnerProofVerifier {
    LogicalOwnerIdentity identity_;
public:
    explicit TestVerifier(LogicalOwnerIdentity identity)
        : identity_(identity) {}
private:
    LogicalOwnerIdentity logical_identity() const override {
        return identity_;
    }
    bool verify(std::span<const unsigned char> challenge,
                std::span<const unsigned char> proof) const override {
        return challenge.size() == 2 && proof.size() == 2 &&
               proof[0] == identity_[0] && proof[1] == challenge[0];
    }
};

class TestPrivateLifecycleProgram
    : public PrivateLifecycleOwnerChildProgram {
    int exit_code_{};
    bool candidate_{};
public:
    explicit TestPrivateLifecycleProgram(
            int exit_code = 0, bool candidate = false)
        : exit_code_(exit_code), candidate_(candidate) {}
    PrivateOwnerChildRoundResult issue_round(
            unsigned owner, unsigned round, int root_fd,
            const PublicOwnerRoundIssuance& selected) override {
        assert(owner < 3 && (round == 1 || round == 2));
        assert(root_fd == FRESH_OWNER_FIXED_ROOT_FD);
        assert(selected.round == round);
        assert(selected.file_identity == Digest{});
        assert(selected.file_metadata_identity == Digest{});
        for (int fd = 3; fd < 256; ++fd) {
            const bool expected =
                fd == FRESH_OWNER_FIXED_CONTROL_FD ||
                fd == FRESH_OWNER_FIXED_ROOT_FD ||
                (candidate_ && fd == FRESH_OWNER_FIXED_TRUTH_FD);
            errno = 0;
            const bool open = ::fcntl(fd, F_GETFD) >= 0 || errno != EBADF;
            assert(open == expected);
        }
        DIR* directory = ::opendir("/proc/self/fd");
        assert(directory != nullptr);
        const int scan_fd = ::dirfd(directory);
        assert(scan_fd >= 0);
        std::set<int> open_fds;
        errno = 0;
        while (const auto* entry = ::readdir(directory)) {
            char* end = nullptr;
            const long parsed = std::strtol(entry->d_name, &end, 10);
            if (end == entry->d_name || *end != '\0') continue;
            assert(parsed >= 0 && parsed <= INT_MAX);
            if (parsed != scan_fd)
                open_fds.insert(static_cast<int>(parsed));
        }
        assert(errno == 0);
        assert(::closedir(directory) == 0);
        std::set<int> expected_fds{
            STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
            FRESH_OWNER_FIXED_CONTROL_FD, FRESH_OWNER_FIXED_ROOT_FD};
        if (candidate_) expected_fds.insert(FRESH_OWNER_FIXED_TRUTH_FD);
        assert(open_fds == expected_fds);
        if (round == 2) {
            assert(selected.accepted_input_head_identity == id(0x203));
            assert(selected.history_gate_identity != Digest{});
        }
        const char* name = round == 1
            ? "ROUND1-OWNER-PRIVATE-INPUT-V2.bin"
            : "ROUND2-OWNER-PRIVATE-INPUT-V2.bin";
        const int fd = ::openat(root_fd, name,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        assert(fd >= 0);
        assert(::ftruncate(fd,
            static_cast<off_t>(OWNER_PRIVATE_INPUT_V2_BYTES)) == 0);
        struct stat info{};
        assert(::fstat(fd, &info) == 0 && S_ISREG(info.st_mode));
        assert(static_cast<std::uint64_t>(info.st_size) ==
               OWNER_PRIVATE_INPUT_V2_BYTES);
        assert(::close(fd) == 0);
        PrivateOwnerChildRoundResult result{
            .file_identity = id(0x800 + 20 * round + owner),
            .file_metadata_identity = id(0x900 + 20 * round + owner),
            .input_lineage_identity = id(0xe00 + 20 * round + owner),
            .logical_owner_identity = logical_id(owner),
            .binding_nonce = id(0xa00 + owner),
        };
        result.verifier_record[0] = logical_id(owner)[0];
        result.verifier_record[63] = logical_id(owner)[31];
        if (candidate_) {
            result.candidate_truth = PrivateOwnerCandidateRoundTruth{
                .actual_public_nullifier =
                    id(0x1100 + 20 * round + owner),
                .created_row_sha256s = {
                    id(0x1200 + 40 * round + 2 * owner),
                    id(0x1201 + 40 * round + 2 * owner)},
                .created_commitments = {
                    id(0x1300 + 40 * round + 2 * owner),
                    id(0x1301 + 40 * round + 2 * owner)},
            };
        }
        return result;
    }

    std::shared_ptr<const LongLivedOwnerProofVerifier>
    admit_parent_verifier(
            unsigned owner,
            const std::array<unsigned char, 64>& record) const override {
        assert(record[0] == logical_id(owner)[0] &&
               record[63] == logical_id(owner)[31]);
        return std::make_shared<TestVerifier>(logical_id(owner));
    }

    PrivateOwnerChildIdentity owner_identity(unsigned owner) const override {
        PrivateOwnerChildIdentity result{
            .logical_owner_identity = logical_id(owner),
            .binding_nonce = id(0xa00 + owner),
            .file_identities = {
                id(0x800 + 20 + owner), id(0x800 + 40 + owner)},
            .file_metadata_identities = {
                id(0x900 + 20 + owner), id(0x900 + 40 + owner)},
            .input_lineage_identities = {
                id(0xe00 + 20 + owner), id(0xe00 + 40 + owner)},
        };
        result.verifier_record[0] = logical_id(owner)[0];
        result.verifier_record[63] = logical_id(owner)[31];
        return result;
    }

    int exit_code_after_round2(unsigned) const override {
        return exit_code_;
    }
};

class CandidatePrivateLifecycleProgram
    : public TestPrivateLifecycleProgram {
public:
    explicit CandidatePrivateLifecycleProgram(int exit_code = 0)
        : TestPrivateLifecycleProgram(exit_code, true) {}
};

class MissingCandidateTruthProgram final
    : public CandidatePrivateLifecycleProgram {
public:
    PrivateOwnerChildRoundResult issue_round(
            unsigned owner, unsigned round, int root_fd,
            const PublicOwnerRoundIssuance& selected) override {
        auto result = CandidatePrivateLifecycleProgram::issue_round(
            owner, round, root_fd, selected);
        if (owner == 1 && round == 1) result.candidate_truth = {};
        return result;
    }
};

class EofPrivateLifecycleProgram final
    : public TestPrivateLifecycleProgram {
public:
    PrivateOwnerChildRoundResult issue_round(
            unsigned owner, unsigned round, int root_fd,
            const PublicOwnerRoundIssuance& selected) override {
        if (owner == 0 && round == 1) ::_exit(0);
        return TestPrivateLifecycleProgram::issue_round(
            owner, round, root_fd, selected);
    }
};

class CredentialSubstitutionProgram final
    : public TestPrivateLifecycleProgram {
public:
    PrivateOwnerChildRoundResult issue_round(
            unsigned owner, unsigned round, int root_fd,
            const PublicOwnerRoundIssuance& selected) override {
        if (owner == 0 && round == 1) {
            const pid_t pid = ::fork();
            assert(pid >= 0);
            if (pid > 0) ::_exit(0);
        }
        return TestPrivateLifecycleProgram::issue_round(
            owner, round, root_fd, selected);
    }
};

class MismatchedVerifierProgram final
    : public TestPrivateLifecycleProgram {
public:
    std::shared_ptr<const LongLivedOwnerProofVerifier>
    admit_parent_verifier(
            unsigned owner,
            const std::array<unsigned char, 64>& record) const override {
        if (owner == 0) return std::make_shared<TestVerifier>(logical_id(9));
        return TestPrivateLifecycleProgram::admit_parent_verifier(
            owner, record);
    }
};

class AlternateRosterProgram final
    : public TestPrivateLifecycleProgram {
public:
    PrivateOwnerChildIdentity owner_identity(unsigned owner) const override {
        auto result = TestPrivateLifecycleProgram::owner_identity(owner);
        result.logical_owner_identity = logical_id(owner + 10);
        result.verifier_record = {};
        result.verifier_record[0] = result.logical_owner_identity[0];
        result.verifier_record[63] = result.logical_owner_identity[31];
        return result;
    }
    PrivateOwnerChildRoundResult issue_round(
            unsigned owner, unsigned round, int root_fd,
            const PublicOwnerRoundIssuance& selected) override {
        auto result = TestPrivateLifecycleProgram::issue_round(
            owner, round, root_fd, selected);
        result.logical_owner_identity = logical_id(owner + 10);
        result.verifier_record = {};
        result.verifier_record[0] = result.logical_owner_identity[0];
        result.verifier_record[63] = result.logical_owner_identity[31];
        return result;
    }
    std::shared_ptr<const LongLivedOwnerProofVerifier>
    admit_parent_verifier(
            unsigned owner,
            const std::array<unsigned char, 64>& record) const override {
        assert(record[0] == logical_id(owner + 10)[0] &&
               record[63] == logical_id(owner + 10)[31]);
        return std::make_shared<TestVerifier>(logical_id(owner + 10));
    }
};

class IsolatedCandidateRosterProgram final
    : public CandidatePrivateLifecycleProgram {
public:
    PrivateOwnerChildIdentity owner_identity(unsigned owner) const override {
        auto result = CandidatePrivateLifecycleProgram::owner_identity(owner);
        result.logical_owner_identity = logical_id(owner + 20);
        result.binding_nonce = id(0x1a00 + owner);
        result.file_identities = {
            id(0x1800 + 20 + owner), id(0x1800 + 40 + owner)};
        result.file_metadata_identities = {
            id(0x1900 + 20 + owner), id(0x1900 + 40 + owner)};
        result.input_lineage_identities = {
            id(0x1e00 + 20 + owner), id(0x1e00 + 40 + owner)};
        result.verifier_record = {};
        result.verifier_record[0] = result.logical_owner_identity[0];
        result.verifier_record[63] = result.logical_owner_identity[31];
        return result;
    }
    PrivateOwnerChildRoundResult issue_round(
            unsigned owner, unsigned round, int root_fd,
            const PublicOwnerRoundIssuance& selected) override {
        auto result = CandidatePrivateLifecycleProgram::issue_round(
            owner, round, root_fd, selected);
        result.file_identity = id(0x1800 + 20 * round + owner);
        result.file_metadata_identity =
            id(0x1900 + 20 * round + owner);
        result.input_lineage_identity =
            id(0x1e00 + 20 * round + owner);
        result.logical_owner_identity = logical_id(owner + 20);
        result.binding_nonce = id(0x1a00 + owner);
        result.verifier_record = {};
        result.verifier_record[0] = result.logical_owner_identity[0];
        result.verifier_record[63] = result.logical_owner_identity[31];
        return result;
    }
    std::shared_ptr<const LongLivedOwnerProofVerifier>
    admit_parent_verifier(
            unsigned owner,
            const std::array<unsigned char, 64>& record) const override {
        assert(record[0] == logical_id(owner + 20)[0] &&
               record[63] == logical_id(owner + 20)[31]);
        return std::make_shared<TestVerifier>(logical_id(owner + 20));
    }
};

class MissingLineageProgram final
    : public TestPrivateLifecycleProgram {
public:
    PrivateOwnerChildIdentity owner_identity(unsigned owner) const override {
        auto result = TestPrivateLifecycleProgram::owner_identity(owner);
        if (owner == 1) result.input_lineage_identities[1] = {};
        return result;
    }
};

struct Roots {
    std::array<std::string, 3> paths{};
    std::array<int, 3> fds{{-1, -1, -1}};
    std::array<std::uint64_t, 3> devices{}, inodes{};
    Roots() {
        for (unsigned owner = 0; owner < 3; ++owner) {
            std::array<char, 80> pattern{};
            const std::string value =
                "/tmp/kpb-owner-process-" + std::to_string(owner) +
                "-XXXXXX";
            std::copy(value.begin(), value.end(), pattern.begin());
            const char* made = ::mkdtemp(pattern.data());
            assert(made != nullptr);
            paths[owner] = made;
            fds[owner] = ::open(made, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            assert(fds[owner] >= 0);
            struct stat info{};
            assert(::fstat(fds[owner], &info) == 0);
            devices[owner] = static_cast<std::uint64_t>(info.st_dev);
            inodes[owner] = static_cast<std::uint64_t>(info.st_ino);
        }
    }
    ~Roots() {
        for (unsigned owner = 0; owner < 3; ++owner) {
            if (fds[owner] >= 0) ::close(fds[owner]);
            (void)::unlink((paths[owner] +
                "/ROUND1-OWNER-PRIVATE-INPUT-V2.bin").c_str());
            (void)::unlink((paths[owner] +
                "/ROUND2-OWNER-PRIVATE-INPUT-V2.bin").c_str());
            (void)::rmdir(paths[owner].c_str());
        }
    }
};

std::array<OwnerPrivateRootAuthority, 3> root_authorities(Roots& roots) {
    std::array<OwnerPrivateRootAuthority, 3> result{
        OwnerPrivateRootAuthority::test_only_mint(
            PublicOwnerPrivateRoot{0, id(10), id(0xb00)}, roots.fds[0]),
        OwnerPrivateRootAuthority::test_only_mint(
            PublicOwnerPrivateRoot{1, id(10), id(0xb01)}, roots.fds[1]),
        OwnerPrivateRootAuthority::test_only_mint(
            PublicOwnerPrivateRoot{2, id(10), id(0xb02)}, roots.fds[2]),
    };
    roots.fds = {-1, -1, -1};
    return result;
}

bool parent_has_root_alias(const Roots& roots) {
    const long limit = std::min<long>(::sysconf(_SC_OPEN_MAX), 4096);
    for (int fd = 3; fd < limit; ++fd) {
        struct stat info{};
        if (::fstat(fd, &info) != 0) continue;
        for (unsigned owner = 0; owner < 3; ++owner)
            if (static_cast<std::uint64_t>(info.st_dev) ==
                    roots.devices[owner] &&
                static_cast<std::uint64_t>(info.st_ino) ==
                    roots.inodes[owner]) return true;
    }
    return false;
}

unsigned open_fd_count() {
    const long raw_limit = std::min<long>(::sysconf(_SC_OPEN_MAX), 4096);
    unsigned result = 0;
    for (int fd = 3; fd < raw_limit; ++fd) {
        errno = 0;
        if (::fcntl(fd, F_GETFD) >= 0 || errno != EBADF) ++result;
    }
    return result;
}

class MemoryReplayRegistry final : public ExternalOwnerIssuanceReplayRegistry {
    std::vector<Digest> consumed_;
public:
    void consume(std::span<const Digest> values) override {
        for (const auto& value : values)
            for (const auto& prior : consumed_)
                if (value == prior) throw identity_registry::Refused();
        consumed_.insert(consumed_.end(), values.begin(), values.end());
    }
};

class PreparedTransactionalReplay final :
        public replay::OwnerReplayPreparedOperation {
    replay::OwnerReplayBackendCommitDisposition disposition_;
public:
    explicit PreparedTransactionalReplay(
            replay::OwnerReplayBackendCommitDisposition disposition)
        : disposition_(disposition) {}
    replay::OwnerReplayBackendCommitDisposition
    commit_prepared() noexcept override { return disposition_; }
};

class TransactionalReplayRegistry final :
        public replay::TransactionalOwnerReplayRegistry {
    replay::OwnerReplayBackendCommitDisposition disposition_;
public:
    explicit TransactionalReplayRegistry(
            replay::OwnerReplayBackendCommitDisposition disposition)
        : disposition_(disposition) {}
    std::unique_ptr<replay::OwnerReplayPreparedOperation> prepare(
            const replay::ExactOwnerReplaySet&) override {
        return std::make_unique<PreparedTransactionalReplay>(disposition_);
    }
};

replay::SelectedOwnerReplayRegistryAuthority transactional_registry(
        replay::OwnerReplayBackendCommitDisposition disposition) {
    return replay::FreshOwnerTransactionalReplayTestBridge::mint_registry(
        std::make_shared<TransactionalReplayRegistry>(disposition),
        id(0xc10), id(0xc11));
}

OwnerIssuanceReplayGuardAuthority replay_guard(
        const std::shared_ptr<ExternalOwnerIssuanceReplayRegistry>& registry) {
    return OwnerIssuanceReplayGuardAuthority::test_only_mint(
        PublicOwnerIssuanceReplayPolicy{
            .authority_identity = id(0xc00),
            .policy_identity = id(0xc01),
            .permission_separated = true,
            .monotonic = true,
            .child_path_exposed = false,
            .child_fd_exposed = false,
        }, registry);
}

CompiledPrivateLifecycleOwnerProgramAuthority compiled_plan(
        std::shared_ptr<PrivateLifecycleOwnerChildProgram> program =
            std::make_shared<TestPrivateLifecycleProgram>()) {
    return CompiledPrivateLifecycleOwnerProgramAuthority::test_only_mint(
        plan(), std::move(program));
}

CompiledPrivateLifecycleOwnerProgramAuthority compiled_hidden_plan(
        std::shared_ptr<PrivateLifecycleOwnerChildProgram> program =
            std::make_shared<CandidatePrivateLifecycleProgram>()) {
    return CompiledPrivateLifecycleOwnerProgramAuthority::test_only_mint(
        hidden_plan(), std::move(program));
}

CompiledPrivateLifecycleOwnerProgramAuthority compiled_isolated_hidden_plan() {
    return CompiledPrivateLifecycleOwnerProgramAuthority::test_only_mint(
        isolated_hidden_plan(),
        std::make_shared<IsolatedCandidateRosterProgram>());
}

FreshOwnerArmIsolationResidualAuthority mint_arm_residual(
        FreshOwnerProcessSupervisor& supervisor,
        CaptureClassification classification =
            CaptureClassification::ExplicitOwnerPublicEffectsBaseline,
        Digest isolation_identity = id(0xd90)) {
    const auto launch = supervisor.public_receipt();
    return FreshOwnerArmIsolationResidualAuthority::test_only_mint(
        PrivateArmIsolationResidualTestEvidence{
            .classification = classification,
            .isolation_authority_identity = isolation_identity,
            .process_authority_identity =
                launch.process_authority_identity,
            .supervisor_session_identity =
                launch.supervisor_session_identity,
        });
}

FreshOwnerArmIsolationResidualAuthority arm_residual(
        FreshOwnerProcessSupervisor& supervisor,
        CaptureClassification classification =
            CaptureClassification::ExplicitOwnerPublicEffectsBaseline,
        Digest isolation_identity = id(0xd90)) {
    (void)supervisor.take_private_arm_launch();
    return mint_arm_residual(
        supervisor, classification, isolation_identity);
}

std::array<Digest, 3> input_lineages(unsigned round) {
    return {
        id(0xe00 + 20 * round),
        id(0xe00 + 20 * round + 1),
        id(0xe00 + 20 * round + 2),
    };
}

std::array<Digest, 3> isolated_candidate_input_lineages(unsigned round) {
    return {
        id(0x1e00 + 20 * round),
        id(0x1e00 + 20 * round + 1),
        id(0x1e00 + 20 * round + 2),
    };
}

AcceptedRound1SuccessorHistoryAuthority accepted_history() {
    return AcceptedRound1SuccessorHistoryAuthority::test_only_mint(
        PublicAcceptedRound1SuccessorHistory{
            .authority_identity = id(0xd00),
            .run = id(8), .trial = id(9),
            .round1_attempt = id(0x101),
            .round1_cohort = id(0x102),
            .accepted_successor_head_identity = id(0x203),
            .history_gate_identity = id(0x204),
        }, input_lineages(2));
}

AcceptedRound1InputHistoryAuthority accepted_input_history() {
    return AcceptedRound1InputHistoryAuthority::test_only_mint(
        PublicAcceptedRound1InputHistory{
            .authority_identity = id(0xd10),
            .run = id(8), .trial = id(9),
            .round1_attempt = id(0x101),
            .round1_cohort = id(0x102),
            .accepted_input_head_identity = id(0x103),
            .history_gate_identity = id(0x104),
        }, input_lineages(1));
}

PublicCandidateOwnerTruthPostBarrier post_barrier_receipt() {
    return PublicCandidateOwnerTruthPostBarrier{
        .classification = CaptureClassification::HiddenCandidate,
        .authority_identity = id(0xf00),
        .trial = id(9),
        .barrier_identity = id(0xf01),
        .financial_runs = {id(0xf10), id(0xf20)},
        .attempts = {id(0x101), id(0x201)},
        .cohorts = {id(0x102), id(0x202)},
        .capture_plan_identities = {id(0xf11), id(0xf21)},
        .projection_identities = {id(0xf12), id(0xf22)},
        .context_identities = {id(0xf13), id(0xf23)},
    };
}

CandidateOwnerTruthPostBarrierAuthority post_barrier() {
    return CandidateOwnerTruthPostBarrierAuthority::test_only_mint(
        post_barrier_receipt());
}

Digest packet_digest(
        const std::array<unsigned char,
            candidate_truth_schema::PACKET_BYTES>& packet,
        std::size_t offset) {
    Digest result{};
    std::copy_n(packet.begin() + static_cast<std::ptrdiff_t>(offset),
                result.size(), result.begin());
    return result;
}

void consume_round1_bootstrap(FreshOwnerRound1IssuedAuthority& round1) {
    auto driver = round1.take_driver_round();
    auto consumed = FreshOwnerRoundBootstrapBridge::consume(
        std::move(driver), round1.take_bootstrap_history(),
        round1.take_continuity());
    (void)round1.take_same_round_retry();
    assert(consumed.public_receipt().round == 1);
}

void consume_round2_bootstrap(FreshOwnerRound2IssuedAuthority& round2) {
    auto driver = round2.take_driver_round();
    auto consumed = FreshOwnerRoundBootstrapBridge::consume(
        std::move(driver), round2.take_bootstrap_history(),
        round2.take_continuity());
    (void)round2.take_same_round_retry();
    assert(consumed.public_receipt().round == 2);
}

template<class Callable>
void refuses(Callable&& callable) {
    bool did_refuse = false;
    try { callable(); }
    catch (const identity_registry::Refused&) { did_refuse = true; }
    assert(did_refuse);
}

template<class Callable>
void measurement_refuses(Callable&& callable) {
    bool did_refuse = false;
    try { callable(); }
    catch (const kpb::measurement::Refused&) { did_refuse = true; }
    assert(did_refuse);
}

class UnreachableRegisteredRoundProgram final :
        public RegisteredRoleChildProgram {
public:
    int run(ParentAuthenticatedPartyDeliveryAuthority&&,
            ChildRoleCompletionEndpointAuthority&&) override {
        return 99;
    }
};

class PreidentityRegisteredRoleProgram final :
        public RegisteredPreIdentityPersistentRoleChildProgram {
    std::array<UnreachableRegisteredRoundProgram, 2> rounds_;
public:
    RegisteredRoleChildProgram& round_program(unsigned round) override {
        assert(round == 1 || round == 2);
        return rounds_[round - 1];
    }
};

RegisteredPreidentityReadyAuthority causal_preidentity_ready(
        PreidentityRegisteredRoleProgram& program) {
    auto process = RegisteredParentPersistentRoleFork::reserve(program);
    auto permit = process.issue_topology_reservation_permit();
    auto topology = FreshTrialCaptureTopologyReservationBridge::reserve(
        std::move(permit));
    return RegisteredPreidentityReadyBridge::join(
        std::move(topology), std::move(process));
}

void happy_real_process_flow() {
    static_assert(!std::copy_constructible<FreshOwnerProcessSupervisor>);
    static_assert(!std::copy_constructible<FreshOwnerRound1IssuedAuthority>);
    static_assert(!std::default_initializable<OwnerPrivateRootAuthority>);
    Roots roots;
    if (roots.fds[0] != FRESH_OWNER_FIXED_CONTROL_FD) {
        assert(::dup3(roots.fds[0], FRESH_OWNER_FIXED_CONTROL_FD,
                      O_CLOEXEC) == FRESH_OWNER_FIXED_CONTROL_FD);
        assert(::close(roots.fds[0]) == 0);
        roots.fds[0] = FRESH_OWNER_FIXED_CONTROL_FD;
    }
    const int inherited_extra = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(inherited_extra >= 0 && inherited_extra < 256);
    PreidentityRegisteredRoleProgram registered_roles;
    auto ready = causal_preidentity_ready(registered_roles);
    auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
        compiled_plan(), root_authorities(roots));
    assert(!parent_has_root_alias(roots));
    const auto launch = supervisor.public_receipt();
    assert(launch.parent_pid == static_cast<std::int64_t>(::getpid()));
    for (unsigned owner = 0; owner < 3; ++owner) {
        assert(launch.children[owner].owner_component == owner);
        assert(launch.children[owner].child_pid > 1);
        assert(launch.children[owner].child_session_identity != Digest{});
    }
    assert(launch.children[0].child_pid != launch.children[1].child_pid);
    assert(launch.children[0].child_pid != launch.children[2].child_pid);
    assert(launch.children[1].child_pid != launch.children[2].child_pid);
    auto registry = std::make_shared<MemoryReplayRegistry>();
    auto round1 = supervisor.issue_round1(
        accepted_input_history(), std::move(ready), replay_guard(registry),
        arm_residual(supervisor));
    auto persistent_activation = round1.take_persistent_activation();
    auto producer_closure = round1.take_producer_closure();
    (void)persistent_activation;
    (void)producer_closure;
    auto driver1 = round1.take_driver_round();
    const auto round1_receipt = driver1.public_receipt();
    auto bootstrap1 = FreshOwnerRoundBootstrapBridge::consume(
        std::move(driver1), round1.take_bootstrap_history(),
        round1.take_continuity());
    (void)round1.take_same_round_retry();
    assert(bootstrap1.public_receipt().round == 1);
    assert(bootstrap1.contracts()[0].owner_id == 0);
    refuses([&] { (void)round1.take_driver_round(); });
    auto round2 = supervisor.issue_round2(
        std::move(round1), accepted_history());
    auto driver2 = round2.take_driver_round();
    const auto round2_receipt = driver2.public_receipt();
    auto bootstrap2 = FreshOwnerRoundBootstrapBridge::consume(
        std::move(driver2), round2.take_bootstrap_history(),
        round2.take_continuity());
    (void)round2.take_same_round_retry();
    assert(bootstrap2.public_receipt().round == 2);
    assert(round1_receipt.attempt != round2_receipt.attempt);
    assert(round1_receipt.cohort != round2_receipt.cohort);
    assert(bootstrap2.public_receipt().accepted_input_head_identity ==
           id(0x203));
    assert(bootstrap2.public_receipt().history_gate_identity == id(0x204));
    auto roster = round2.take_baseline_roster();
    refuses([&] { (void)round2.take_v3_history_residual(); });
    assert(roster.public_receipt().run == id(8));
    assert(supervisor.completed());
    const auto completion = supervisor.public_completion();
    assert(completion.all_children_exited_zero);
    for (unsigned owner = 0; owner < 3; ++owner)
        assert(completion.children[owner].child_pid ==
               launch.children[owner].child_pid);
    assert(::close(inherited_extra) == 0);
}

void transactional_round1_closed_sum() {
    Roots roots;
    PreidentityRegisteredRoleProgram registered_roles;
    auto ready = causal_preidentity_ready(registered_roles);
    auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
        compiled_plan(), root_authorities(roots));
    auto outcome = supervisor.issue_round1_transactional(
        accepted_input_history(), std::move(ready),
        transactional_registry(
            replay::OwnerReplayBackendCommitDisposition::Committed),
        arm_residual(supervisor));
    assert(FreshOwnerRound1AttemptOutcomeTestBridge::inspect(outcome) ==
           TestFreshOwnerRound1AttemptOutcome::Success);
    auto round1 = FreshOwnerRound1AttemptOutcomeTestBridge::take_success(
        std::move(outcome));
    (void)round1.take_persistent_activation();
    (void)round1.take_producer_closure();
    consume_round1_bootstrap(round1);
    auto round2 = supervisor.issue_round2(
        std::move(round1), accepted_history());
    consume_round2_bootstrap(round2);
    (void)round2.take_baseline_roster();
    assert(supervisor.completed());
}

void transactional_round2_closed_sum() {
    Roots roots;
    PreidentityRegisteredRoleProgram registered_roles;
    auto ready = causal_preidentity_ready(registered_roles);
    auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
        compiled_plan(), root_authorities(roots));
    auto round1_outcome = supervisor.issue_round1_transactional(
        accepted_input_history(), std::move(ready),
        transactional_registry(
            replay::OwnerReplayBackendCommitDisposition::Committed),
        arm_residual(supervisor));
    assert(FreshOwnerRound1AttemptOutcomeTestBridge::inspect(round1_outcome) ==
           TestFreshOwnerRound1AttemptOutcome::Success);
    auto round1 = FreshOwnerRound1AttemptOutcomeTestBridge::take_success(
        std::move(round1_outcome));
    (void)round1.take_persistent_activation();
    (void)round1.take_producer_closure();
    consume_round1_bootstrap(round1);

    auto round2_outcome = supervisor.issue_round2_transactional(
        std::move(round1), accepted_history());
    assert(FreshOwnerRound2AttemptOutcomeTestBridge::inspect(round2_outcome) ==
           TestFreshOwnerRound2AttemptOutcome::Success);
    auto round2 = FreshOwnerRound2AttemptOutcomeTestBridge::take_success(
        std::move(round2_outcome));
    consume_round2_bootstrap(round2);
    (void)round2.take_baseline_roster();
    assert(supervisor.completed());
}

void transactional_round2_faults_are_typed_stop() {
    constexpr std::array faults{
        FreshOwnerRound2AttemptTestFault::AfterInputClaim,
        FreshOwnerRound2AttemptTestFault::AfterFirstChildSend,
        FreshOwnerRound2AttemptTestFault::AfterFirstChildResponse,
        FreshOwnerRound2AttemptTestFault::AfterAllChildResponses,
        FreshOwnerRound2AttemptTestFault::BeforeCommit,
    };
    for (const auto fault : faults) {
        Roots roots;
        PreidentityRegisteredRoleProgram registered_roles;
        auto ready = causal_preidentity_ready(registered_roles);
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(roots));
        auto round1_outcome = supervisor.issue_round1_transactional(
            accepted_input_history(), std::move(ready),
            transactional_registry(
                replay::OwnerReplayBackendCommitDisposition::Committed),
            arm_residual(supervisor));
        assert(FreshOwnerRound1AttemptOutcomeTestBridge::inspect(
                   round1_outcome) ==
               TestFreshOwnerRound1AttemptOutcome::Success);
        auto round1 = FreshOwnerRound1AttemptOutcomeTestBridge::take_success(
            std::move(round1_outcome));
        (void)round1.take_persistent_activation();
        (void)round1.take_producer_closure();
        consume_round1_bootstrap(round1);

        FreshOwnerRound2AttemptOutcomeTestBridge::set_fault(fault);
        auto round2_outcome = supervisor.issue_round2_transactional(
            std::move(round1), accepted_history());
        FreshOwnerRound2AttemptOutcomeTestBridge::set_fault(
            FreshOwnerRound2AttemptTestFault::None);
        assert(FreshOwnerRound2AttemptOutcomeTestBridge::inspect(
                   round2_outcome) ==
               TestFreshOwnerRound2AttemptOutcome::UnavailableStop);
        assert(FreshOwnerRound2AttemptOutcomeTestBridge::
            stop_retains_claimed_lineage(round2_outcome));
        FreshOwnerRound2AttemptOutcomeTestBridge::discard_stop_for_test(
            std::move(round2_outcome));
    }

    // Candidate STOP retains its separately prepared truth and V3-history
    // descendants; the baseline loop above cannot exercise that arm.
    Roots roots;
    PreidentityRegisteredRoleProgram registered_roles;
    auto ready = causal_preidentity_ready(registered_roles);
    auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
        compiled_hidden_plan(), root_authorities(roots));
    auto round1_outcome = supervisor.issue_round1_transactional(
        accepted_input_history(), std::move(ready),
        transactional_registry(
            replay::OwnerReplayBackendCommitDisposition::Committed),
        arm_residual(
            supervisor, CaptureClassification::HiddenCandidate));
    auto round1 = FreshOwnerRound1AttemptOutcomeTestBridge::take_success(
        std::move(round1_outcome));
    (void)round1.take_persistent_activation();
    (void)round1.take_producer_closure();
    consume_round1_bootstrap(round1);
    FreshOwnerRound2AttemptOutcomeTestBridge::set_fault(
        FreshOwnerRound2AttemptTestFault::BeforeCommit);
    auto candidate_stop = supervisor.issue_round2_transactional(
        std::move(round1), accepted_history());
    FreshOwnerRound2AttemptOutcomeTestBridge::set_fault(
        FreshOwnerRound2AttemptTestFault::None);
    assert(FreshOwnerRound2AttemptOutcomeTestBridge::inspect(candidate_stop) ==
           TestFreshOwnerRound2AttemptOutcome::UnavailableStop);
    assert(FreshOwnerRound2AttemptOutcomeTestBridge::
        stop_retains_claimed_lineage(candidate_stop));
    FreshOwnerRound2AttemptOutcomeTestBridge::discard_stop_for_test(
        std::move(candidate_stop));
}

void transactional_round2_outcome_drop_is_fail_stop() {
    std::set_terminate(+[] { ::_exit(87); });
    Roots roots;
    PreidentityRegisteredRoleProgram registered_roles;
    auto ready = causal_preidentity_ready(registered_roles);
    auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
        compiled_plan(), root_authorities(roots));
    auto round1_outcome = supervisor.issue_round1_transactional(
        accepted_input_history(), std::move(ready),
        transactional_registry(
            replay::OwnerReplayBackendCommitDisposition::Committed),
        arm_residual(supervisor));
    auto round1 = FreshOwnerRound1AttemptOutcomeTestBridge::take_success(
        std::move(round1_outcome));
    (void)round1.take_persistent_activation();
    (void)round1.take_producer_closure();
    consume_round1_bootstrap(round1);
    auto round2_outcome = supervisor.issue_round2_transactional(
        std::move(round1), accepted_history());
    assert(FreshOwnerRound2AttemptOutcomeTestBridge::inspect(round2_outcome) ==
           TestFreshOwnerRound2AttemptOutcome::Success);
    // Returning without the future production consumer must fail-stop.
}

void transactional_round1_unavailable_is_typed_stop() {
    Roots roots;
    PreidentityRegisteredRoleProgram registered_roles;
    auto ready = causal_preidentity_ready(registered_roles);
    auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
        compiled_plan(), root_authorities(roots));
    auto outcome = supervisor.issue_round1_transactional(
        accepted_input_history(), std::move(ready),
        transactional_registry(
            replay::OwnerReplayBackendCommitDisposition::
                InfrastructureUnavailable),
        arm_residual(supervisor));
    assert(FreshOwnerRound1AttemptOutcomeTestBridge::inspect(outcome) ==
           TestFreshOwnerRound1AttemptOutcome::UnavailableStop);
    assert(FreshOwnerRound1AttemptOutcomeTestBridge::
        stop_retains_claimed_lineage(outcome));
    FreshOwnerRound1AttemptOutcomeTestBridge::discard_stop_for_test(
        std::move(outcome));
}

void transactional_round1_outcome_drop_is_fail_stop() {
    std::set_terminate(+[] { ::_exit(86); });
    Roots roots;
    PreidentityRegisteredRoleProgram registered_roles;
    auto ready = causal_preidentity_ready(registered_roles);
    auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
        compiled_plan(), root_authorities(roots));
    auto outcome = supervisor.issue_round1_transactional(
        accepted_input_history(), std::move(ready),
        transactional_registry(
            replay::OwnerReplayBackendCommitDisposition::
                InfrastructureUnavailable),
        arm_residual(supervisor));
    assert(FreshOwnerRound1AttemptOutcomeTestBridge::inspect(outcome) ==
           TestFreshOwnerRound1AttemptOutcome::UnavailableStop);
    // Returning without the explicit test consumer must invoke the production
    // fail-stop destructor; reaching the caller normally is forbidden.
}

void transactional_round1_faults_are_typed_stop() {
    constexpr std::array faults{
        FreshOwnerRound1AttemptTestFault::AfterTransactionalJoin,
        FreshOwnerRound1AttemptTestFault::AfterFirstChildSend,
        FreshOwnerRound1AttemptTestFault::AfterFirstChildResponse,
        FreshOwnerRound1AttemptTestFault::AfterAllChildResponses,
        FreshOwnerRound1AttemptTestFault::BeforeIssuanceSplit,
        FreshOwnerRound1AttemptTestFault::AfterSplitDescendantsRetained,
        FreshOwnerRound1AttemptTestFault::AfterContinuityPrepared,
    };
    for (const auto fault : faults) {
        Roots roots;
        PreidentityRegisteredRoleProgram registered_roles;
        auto ready = causal_preidentity_ready(registered_roles);
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(roots));
        FreshOwnerRound1AttemptOutcomeTestBridge::set_fault(fault);
        auto outcome = supervisor.issue_round1_transactional(
            accepted_input_history(), std::move(ready),
            transactional_registry(
                replay::OwnerReplayBackendCommitDisposition::Committed),
            arm_residual(supervisor));
        FreshOwnerRound1AttemptOutcomeTestBridge::set_fault(
            FreshOwnerRound1AttemptTestFault::None);
        assert(FreshOwnerRound1AttemptOutcomeTestBridge::inspect(outcome) ==
               TestFreshOwnerRound1AttemptOutcome::UnavailableStop);
        assert(FreshOwnerRound1AttemptOutcomeTestBridge::
            stop_retains_claimed_lineage(outcome));
        FreshOwnerRound1AttemptOutcomeTestBridge::discard_stop_for_test(
            std::move(outcome));
    }

    Roots roots;
    PreidentityRegisteredRoleProgram registered_roles;
    auto ready = causal_preidentity_ready(registered_roles);
    auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
        compiled_plan(), root_authorities(roots));
    FreshOwnerTrialIssuanceBridge::test_only_set_split_postprepare_hook(
        +[] { throw std::bad_alloc(); });
    auto split_outcome = supervisor.issue_round1_transactional(
        accepted_input_history(), std::move(ready),
        transactional_registry(
            replay::OwnerReplayBackendCommitDisposition::Committed),
        arm_residual(supervisor));
    FreshOwnerTrialIssuanceBridge::test_only_set_split_postprepare_hook(
        nullptr);
    assert(FreshOwnerRound1AttemptOutcomeTestBridge::inspect(split_outcome) ==
           TestFreshOwnerRound1AttemptOutcome::UnavailableStop);
    assert(FreshOwnerRound1AttemptOutcomeTestBridge::
        stop_retains_claimed_lineage(split_outcome));
    FreshOwnerRound1AttemptOutcomeTestBridge::discard_stop_for_test(
        std::move(split_outcome));
}

void transactional_stop_uses_pidfd_settlement() {
    {
        Roots roots;
        PreidentityRegisteredRoleProgram registered_roles;
        auto ready = causal_preidentity_ready(registered_roles);
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(roots));
        FreshOwnerRound1AttemptOutcomeTestBridge::set_fault(
            FreshOwnerRound1AttemptTestFault::AfterTransactionalJoin);
        FreshOwnerRound1AttemptOutcomeTestBridge::set_pidfd_wait_fault(
            FreshOwnerOwnerPidfdWaitTestFault::FirstInterrupted);
        auto outcome = supervisor.issue_round1_transactional(
            accepted_input_history(), std::move(ready),
            transactional_registry(
                replay::OwnerReplayBackendCommitDisposition::Committed),
            arm_residual(supervisor));
        FreshOwnerRound1AttemptOutcomeTestBridge::set_fault(
            FreshOwnerRound1AttemptTestFault::None);
        FreshOwnerRound1AttemptOutcomeTestBridge::set_pidfd_wait_fault(
            FreshOwnerOwnerPidfdWaitTestFault::None);
        assert(FreshOwnerRound1AttemptOutcomeTestBridge::inspect(outcome) ==
               TestFreshOwnerRound1AttemptOutcome::UnavailableStop);
        assert(FreshOwnerRound1AttemptOutcomeTestBridge::
            stop_retains_claimed_lineage(outcome));
        assert(!FreshOwnerRound1AttemptOutcomeTestBridge::
            stop_retains_unsettled_pidfds(outcome));
        FreshOwnerRound1AttemptOutcomeTestBridge::discard_stop_for_test(
            std::move(outcome));
    }

    {
        Roots roots;
        PreidentityRegisteredRoleProgram registered_roles;
        auto ready = causal_preidentity_ready(registered_roles);
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(roots));
        FreshOwnerRound1AttemptOutcomeTestBridge::set_fault(
            FreshOwnerRound1AttemptTestFault::AfterTransactionalJoin);
        FreshOwnerRound1AttemptOutcomeTestBridge::set_pidfd_wait_fault(
            FreshOwnerOwnerPidfdWaitTestFault::PersistentChildUnavailable);
        auto outcome = supervisor.issue_round1_transactional(
            accepted_input_history(), std::move(ready),
            transactional_registry(
                replay::OwnerReplayBackendCommitDisposition::Committed),
            arm_residual(supervisor));
        FreshOwnerRound1AttemptOutcomeTestBridge::set_fault(
            FreshOwnerRound1AttemptTestFault::None);
        assert(FreshOwnerRound1AttemptOutcomeTestBridge::inspect(outcome) ==
               TestFreshOwnerRound1AttemptOutcome::UnavailableStop);
        assert(FreshOwnerRound1AttemptOutcomeTestBridge::
            stop_retains_claimed_lineage(outcome));
        assert(FreshOwnerRound1AttemptOutcomeTestBridge::
            stop_retains_unsettled_pidfds(outcome));
        // The opaque STOP retains the exact pidfds and PIDs. Restore the real
        // settle path before destruction so its private owner reaps them.
        FreshOwnerRound1AttemptOutcomeTestBridge::set_pidfd_wait_fault(
            FreshOwnerOwnerPidfdWaitTestFault::None);
        FreshOwnerRound1AttemptOutcomeTestBridge::discard_stop_for_test(
            std::move(outcome));
    }
}

void unsafe_sigchld_refuses_before_owner_claim() {
    Roots roots;
    auto program = compiled_plan();
    auto owner_roots = root_authorities(roots);
    struct sigaction ignored{}, prior{};
    ignored.sa_handler = SIG_IGN;
    assert(::sigemptyset(&ignored.sa_mask) == 0);
    assert(::sigaction(SIGCHLD, &ignored, &prior) == 0);
    refuses([&] {
        (void)FreshOwnerProcessSupervisor::launch_exact_three(
            std::move(program), std::move(owner_roots));
    });
    assert(::sigaction(SIGCHLD, &prior, nullptr) == 0);

    // The pre-fork refusal happened before either authority was claimed.
    auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
        std::move(program), std::move(owner_roots));
    assert(supervisor.public_receipt().children[0].child_pid > 1);
}

void hidden_candidate_truth_flow() {
    namespace baseline_schema =
        registered_driver::baseline_disclosure::truth_capsule_schema;
    static_assert(candidate_truth_schema::PACKET_BYTES == 813);
    static_assert(candidate_truth_schema::PACKET_BYTES ==
                  baseline_schema::PACKET_BYTES);
    static_assert(candidate_truth_schema::MAGIC == baseline_schema::MAGIC);
    static_assert(candidate_truth_schema::ROUNDS_OFFSET ==
                  baseline_schema::ROUNDS_OFFSET);
    static_assert(static_cast<unsigned>(
                      CaptureClassification::HiddenCandidate) ==
                  candidate_truth_schema::HIDDEN_CANDIDATE_CLASSIFICATION);
    static_assert(static_cast<unsigned>(
                      CaptureClassification::ExplicitOwnerPublicEffectsBaseline)
                  == 2);
    static_assert(!std::copy_constructible<
                  CandidateOwnerTruthEndpointAuthority>);
    static_assert(!std::copy_constructible<
                  CandidateOwnerTruthPostBarrierAuthority>);

    Roots roots;
    auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
        compiled_hidden_plan(), root_authorities(roots));
    const auto launch = supervisor.public_receipt();
    auto round1 = supervisor.issue_round1(
        accepted_input_history(),
        replay_guard(std::make_shared<MemoryReplayRegistry>()),
        arm_residual(supervisor, CaptureClassification::HiddenCandidate));
    consume_round1_bootstrap(round1);
    auto round2 = supervisor.issue_round2(
        std::move(round1), accepted_history());
    consume_round2_bootstrap(round2);
    auto v3_history = round2.take_v3_history_residual();
    (void)v3_history;
    refuses([&] { (void)round2.take_v3_history_residual(); });
    refuses([&] { (void)round2.take_baseline_roster(); });
    auto pending = round2.take_candidate_truth_pending();
    refuses([&] { (void)round2.take_candidate_truth_pending(); });
    assert(!supervisor.completed());

    auto release = genuine_candidate_barrier_release();
    auto endpoints = CandidateOwnerTruthPostBarrierBridge::release(
        supervisor, std::move(release), std::move(pending));
    assert(supervisor.completed());
    refuses([&] {
        (void)CandidateOwnerTruthPostBarrierBridge::release(
            supervisor, std::move(release), std::move(pending));
    });
    const auto completion = supervisor.public_completion();
    assert(completion.all_children_exited_zero);

    const auto barrier = post_barrier_receipt();
    for (unsigned owner = 0; owner < 3; ++owner) {
        auto endpoint = endpoints.take(owner);
        const auto receipt = endpoint.public_receipt();
        assert(receipt.classification ==
               CaptureClassification::HiddenCandidate);
        assert(receipt.owner_component == owner);
        assert(receipt.fixed_fd == FRESH_OWNER_FIXED_TRUTH_FD);
        assert(receipt.trial == id(9));
        assert(receipt.barrier_identity == id(0xf01));
        assert(receipt.financial_runs == barrier.financial_runs);
        assert(receipt.attempts == barrier.attempts);
        assert(receipt.cohorts == barrier.cohorts);
        assert(receipt.capture_plan_identities ==
               barrier.capture_plan_identities);
        assert(receipt.projection_identities ==
               barrier.projection_identities);
        assert(receipt.context_identities == barrier.context_identities);
        assert(receipt.feeder_pid == launch.children[owner].child_pid);
        assert(completion.children[owner].child_pid ==
               launch.children[owner].child_pid);
        const auto packet = endpoint.test_only_receive_packet();
        assert(packet[candidate_truth_schema::CLASSIFICATION_OFFSET] == 1);
        assert(packet[candidate_truth_schema::OWNER_OFFSET] == owner);
        for (unsigned round_index = 0; round_index < 2; ++round_index) {
            using Field = candidate_truth_schema::RoundDigestField;
            const unsigned round = round_index + 1;
            assert(packet_digest(packet,
                candidate_truth_schema::round_digest_offset(
                    round_index, Field::ActualPublicNullifier)) ==
                id(0x1100 + 20 * round + owner));
            assert(packet_digest(packet,
                candidate_truth_schema::round_digest_offset(
                    round_index, Field::CreatedRowSha256_0)) ==
                id(0x1200 + 40 * round + 2 * owner));
            assert(packet_digest(packet,
                candidate_truth_schema::round_digest_offset(
                    round_index, Field::CreatedRowSha256_1)) ==
                id(0x1201 + 40 * round + 2 * owner));
            assert(packet_digest(packet,
                candidate_truth_schema::round_digest_offset(
                    round_index, Field::CreatedCommitment_0)) ==
                id(0x1300 + 40 * round + 2 * owner));
            assert(packet_digest(packet,
                candidate_truth_schema::round_digest_offset(
                    round_index, Field::CreatedCommitment_1)) ==
                id(0x1301 + 40 * round + 2 * owner));
        }
        refuses([&] { (void)endpoint.test_only_receive_packet(); });
        refuses([&] { (void)endpoints.take(owner); });
    }
}

void unread_candidate_truth_endpoints_close_without_decode() {
    const unsigned before = open_fd_count();
    {
        Roots roots;
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_hidden_plan(), root_authorities(roots));
        auto round1 = supervisor.issue_round1(
            accepted_input_history(),
            replay_guard(std::make_shared<MemoryReplayRegistry>()),
            arm_residual(
                supervisor, CaptureClassification::HiddenCandidate));
        consume_round1_bootstrap(round1);
        auto round2 = supervisor.issue_round2(
            std::move(round1), accepted_history());
        consume_round2_bootstrap(round2);
        auto pending = round2.take_candidate_truth_pending();
        auto release = genuine_candidate_barrier_release();
        auto endpoints = CandidateOwnerTruthPostBarrierBridge::release(
            supervisor, std::move(release), std::move(pending));
        // One endpoint is moved out and all three are deliberately destroyed
        // unread. No parent-side parser or drain is needed for child exit.
        auto owner1 = endpoints.take(1);
        (void)owner1.public_receipt();
        assert(supervisor.completed());
    }
    assert(open_fd_count() == before);
}

void hidden_candidate_truth_refusals() {
    {
        auto measurement = candidate_measurement(
            candidate_measurement_binding());
        measurement_refuses([&] {
            (void)measurement.issue_candidate_truth_barrier_release();
        });
    }
    {
        Roots roots;
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_hidden_plan(), root_authorities(roots));
        const auto launch = supervisor.public_receipt();
        auto round1 = supervisor.issue_round1(
            accepted_input_history(),
            replay_guard(std::make_shared<MemoryReplayRegistry>()),
            arm_residual(
                supervisor, CaptureClassification::HiddenCandidate));
        consume_round1_bootstrap(round1);
        auto round2 = supervisor.issue_round2(
            std::move(round1), accepted_history());
        consume_round2_bootstrap(round2);
        auto pending = round2.take_candidate_truth_pending();
        auto changed = candidate_measurement_binding();
        changed.round_capture_plans[1] = id(0xfffb);
        auto release = genuine_candidate_barrier_release(changed);
        refuses([&] {
            (void)CandidateOwnerTruthPostBarrierBridge::release(
                supervisor, std::move(release), std::move(pending));
        });
        assert(!supervisor.completed());
        for (const auto& child : launch.children) {
            errno = 0;
            assert(::kill(static_cast<pid_t>(child.child_pid), 0) == -1);
            assert(errno == ESRCH);
        }
        // Both inputs are burned before validation; neither a corrected
        // release nor the same pending batch can revive this process tree.
        refuses([&] {
            (void)CandidateOwnerTruthPostBarrierBridge::release(
                supervisor, std::move(release), std::move(pending));
        });
    }
    {
        Roots roots;
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_hidden_plan(
                std::make_shared<MissingCandidateTruthProgram>()),
            root_authorities(roots));
        refuses([&] {
            (void)supervisor.issue_round1(
                accepted_input_history(),
                replay_guard(std::make_shared<MemoryReplayRegistry>()),
                arm_residual(
                    supervisor, CaptureClassification::HiddenCandidate));
        });
    }
    for (unsigned mismatch = 0; mismatch < 4; ++mismatch) {
        Roots roots;
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_hidden_plan(), root_authorities(roots));
        auto round1 = supervisor.issue_round1(
            accepted_input_history(),
            replay_guard(std::make_shared<MemoryReplayRegistry>()),
            arm_residual(
                supervisor, CaptureClassification::HiddenCandidate));
        consume_round1_bootstrap(round1);
        auto round2 = supervisor.issue_round2(
            std::move(round1), accepted_history());
        consume_round2_bootstrap(round2);
        auto pending = round2.take_candidate_truth_pending();
        auto wrong = post_barrier_receipt();
        if (mismatch == 0) wrong.trial = id(0xffff);
        else if (mismatch == 1) wrong.attempts[1] = id(0xfffe);
        else if (mismatch == 2)
            wrong.capture_plan_identities[1] = id(0xfffd);
        else wrong.context_identities[1] = id(0xfffc);
        refuses([&] {
            (void)supervisor.test_only_release_candidate_truth(
                std::move(pending),
                CandidateOwnerTruthPostBarrierAuthority::test_only_mint(
                    wrong));
        });
        assert(!supervisor.completed());
    }
    {
        Roots roots;
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_hidden_plan(
                std::make_shared<CandidatePrivateLifecycleProgram>(7)),
            root_authorities(roots));
        auto round1 = supervisor.issue_round1(
            accepted_input_history(),
            replay_guard(std::make_shared<MemoryReplayRegistry>()),
            arm_residual(
                supervisor, CaptureClassification::HiddenCandidate));
        consume_round1_bootstrap(round1);
        auto round2 = supervisor.issue_round2(
            std::move(round1), accepted_history());
        consume_round2_bootstrap(round2);
        auto pending = round2.take_candidate_truth_pending();
        refuses([&] {
            (void)supervisor.test_only_release_candidate_truth(
                std::move(pending), post_barrier());
        });
    }
    {
        Roots roots;
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(roots));
        auto round1 = supervisor.issue_round1(
            accepted_input_history(),
            replay_guard(std::make_shared<MemoryReplayRegistry>()),
            arm_residual(supervisor));
        consume_round1_bootstrap(round1);
        auto round2 = supervisor.issue_round2(
            std::move(round1), accepted_history());
        consume_round2_bootstrap(round2);
        refuses([&] { (void)round2.take_candidate_truth_pending(); });
        (void)round2.take_baseline_roster();
        assert(supervisor.completed());
    }
}

void arm_isolation_join_is_mandatory() {
    {
        Roots roots;
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(roots));
        // Even a shape-correct residual cannot bypass consumption of this
        // supervisor's private launch authority by the two-arm join.
        auto residual = mint_arm_residual(supervisor);
        refuses([&] {
            (void)supervisor.issue_round1(
                accepted_input_history(),
                replay_guard(std::make_shared<MemoryReplayRegistry>()),
                std::move(residual));
        });
        for (const auto& path : roots.paths)
            assert(::access((path +
                "/ROUND1-OWNER-PRIVATE-INPUT-V2.bin").c_str(), F_OK) == -1);
    }
    {
        Roots roots;
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(roots));
        (void)supervisor.take_private_arm_launch();
        auto wrong_arm = mint_arm_residual(
            supervisor, CaptureClassification::HiddenCandidate);
        refuses([&] {
            (void)supervisor.issue_round1(
                accepted_input_history(),
                replay_guard(std::make_shared<MemoryReplayRegistry>()),
                std::move(wrong_arm));
        });
    }
    {
        Roots first_roots;
        Roots second_roots;
        auto first = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(first_roots));
        auto second = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(second_roots));
        auto cross_tree = arm_residual(first);
        (void)second.take_private_arm_launch();
        refuses([&] {
            (void)second.issue_round1(
                accepted_input_history(),
                replay_guard(std::make_shared<MemoryReplayRegistry>()),
                std::move(cross_tree));
        });
    }
    {
        Roots first_roots;
        Roots second_roots;
        auto first = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(first_roots));
        auto replayed = arm_residual(first);
        auto wrong = accepted_input_history().public_receipt();
        wrong.accepted_input_head_identity = id(0xffff);
        refuses([&] {
            (void)first.issue_round1(
                AcceptedRound1InputHistoryAuthority::test_only_mint(
                    wrong, input_lineages(1)),
                replay_guard(std::make_shared<MemoryReplayRegistry>()),
                std::move(replayed));
        });
        auto second = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(second_roots));
        (void)second.take_private_arm_launch();
        refuses([&] {
            (void)second.issue_round1(
                accepted_input_history(),
                replay_guard(std::make_shared<MemoryReplayRegistry>()),
                std::move(replayed));
        });
    }
}

void paired_private_arm_join_issues_both_round1_files() {
    Roots baseline_roots;
    Roots candidate_roots;
    auto baseline = FreshOwnerProcessSupervisor::launch_exact_three(
        compiled_plan(), root_authorities(baseline_roots));
    auto candidate = FreshOwnerProcessSupervisor::launch_exact_three(
        compiled_isolated_hidden_plan(), root_authorities(candidate_roots));
    auto joined = FreshOwnerArmIsolationBridge::join(
        baseline.take_private_arm_launch(),
        candidate.take_private_arm_launch());
    auto baseline_residual = joined.take_baseline_residual();
    auto candidate_residual = joined.take_hidden_candidate_residual();

    auto baseline_round1 = baseline.issue_round1(
        accepted_input_history(),
        replay_guard(std::make_shared<MemoryReplayRegistry>()),
        std::move(baseline_residual));
    auto candidate_round1 = candidate.issue_round1(
        AcceptedRound1InputHistoryAuthority::test_only_mint(
            accepted_input_history().public_receipt(),
            isolated_candidate_input_lineages(1)),
        replay_guard(std::make_shared<MemoryReplayRegistry>()),
        std::move(candidate_residual));
    consume_round1_bootstrap(baseline_round1);
    consume_round1_bootstrap(candidate_round1);
    for (unsigned owner = 0; owner < 3; ++owner) {
        assert(::access((baseline_roots.paths[owner] +
            "/ROUND1-OWNER-PRIVATE-INPUT-V2.bin").c_str(), F_OK) == 0);
        assert(::access((candidate_roots.paths[owner] +
            "/ROUND1-OWNER-PRIVATE-INPUT-V2.bin").c_str(), F_OK) == 0);
    }
}

void wrong_history_refuses_before_round_generation() {
    {
        Roots roots;
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(roots));
        auto wrong = PublicAcceptedRound1InputHistory{
            .authority_identity = id(0xd10),
            .run = id(8), .trial = id(9),
            .round1_attempt = id(0x101),
            .round1_cohort = id(0x102),
            .accepted_input_head_identity = id(0xffff),
            .history_gate_identity = id(0x104),
        };
        refuses([&] {
            (void)supervisor.issue_round1(
                AcceptedRound1InputHistoryAuthority::test_only_mint(
                    wrong, input_lineages(1)),
                replay_guard(std::make_shared<MemoryReplayRegistry>()),
                arm_residual(supervisor));
        });
    }
    {
        Roots roots;
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(roots));
        auto registry = std::make_shared<MemoryReplayRegistry>();
        auto round1 = supervisor.issue_round1(
            accepted_input_history(), replay_guard(registry),
            arm_residual(supervisor));
        consume_round1_bootstrap(round1);
        auto wrong = PublicAcceptedRound1SuccessorHistory{
            .authority_identity = id(0xd00),
            .run = id(8), .trial = id(9),
            .round1_attempt = id(0x101),
            .round1_cohort = id(0x102),
            .accepted_successor_head_identity = id(0xffff),
            .history_gate_identity = id(0x204),
        };
        refuses([&] {
            (void)supervisor.issue_round2(
                std::move(round1),
                AcceptedRound1SuccessorHistoryAuthority::test_only_mint(
                    wrong, input_lineages(2)));
        });
    }
}

void wrong_slot_and_root_alias_refuse() {
    {
        Roots roots;
        std::array<OwnerPrivateRootAuthority, 3> authorities{
            OwnerPrivateRootAuthority::test_only_mint(
                PublicOwnerPrivateRoot{1, id(10), id(0xb00)}, roots.fds[0]),
            OwnerPrivateRootAuthority::test_only_mint(
                PublicOwnerPrivateRoot{0, id(10), id(0xb01)}, roots.fds[1]),
            OwnerPrivateRootAuthority::test_only_mint(
                PublicOwnerPrivateRoot{2, id(10), id(0xb02)}, roots.fds[2]),
        };
        roots.fds = {-1, -1, -1};
        refuses([&] {
            (void)FreshOwnerProcessSupervisor::launch_exact_three(
                compiled_plan(), std::move(authorities));
        });
    }
    {
        Roots roots;
        const int duplicate = ::dup(roots.fds[0]);
        assert(duplicate >= 0);
        std::array<OwnerPrivateRootAuthority, 3> authorities{
            OwnerPrivateRootAuthority::test_only_mint(
                PublicOwnerPrivateRoot{0, id(10), id(0xb00)}, roots.fds[0]),
            OwnerPrivateRootAuthority::test_only_mint(
                PublicOwnerPrivateRoot{1, id(10), id(0xb01)}, duplicate),
            OwnerPrivateRootAuthority::test_only_mint(
                PublicOwnerPrivateRoot{2, id(10), id(0xb02)}, roots.fds[2]),
        };
        roots.fds[0] = -1;
        roots.fds[2] = -1;
        refuses([&] {
            (void)FreshOwnerProcessSupervisor::launch_exact_three(
                compiled_plan(), std::move(authorities));
        });
    }
    {
        Roots roots;
        auto authorities = root_authorities(roots);
        auto wrong_plan = plan();
        wrong_plan.root_identity = id(0xbeef);
        auto selected =
            CompiledPrivateLifecycleOwnerProgramAuthority::test_only_mint(
                std::move(wrong_plan),
                std::make_shared<TestPrivateLifecycleProgram>());
        refuses([&] {
            (void)FreshOwnerProcessSupervisor::launch_exact_three(
                std::move(selected), std::move(authorities));
        });
    }
    {
        Roots roots;
        const int transferred_fd = roots.fds[0];
        auto authorities = root_authorities(roots);
        const int substituted = ::open(
            roots.paths[1].c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        assert(substituted >= 0);
        assert(::dup2(substituted, transferred_fd) == transferred_fd);
        if (substituted != transferred_fd) assert(::close(substituted) == 0);
        refuses([&] {
            (void)FreshOwnerProcessSupervisor::launch_exact_three(
                compiled_plan(), std::move(authorities));
        });
    }
}

void child_eof_credential_substitution_and_nonzero_exit_refuse() {
    for (unsigned failure = 0; failure < 3; ++failure) {
        Roots roots;
        std::shared_ptr<PrivateLifecycleOwnerChildProgram> program;
        if (failure == 0)
            program = std::make_shared<EofPrivateLifecycleProgram>();
        else if (failure == 1)
            program = std::make_shared<CredentialSubstitutionProgram>();
        else
            program = std::make_shared<TestPrivateLifecycleProgram>(7);
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(std::move(program)), root_authorities(roots));
        if (failure < 2) {
            auto registry = std::make_shared<MemoryReplayRegistry>();
            refuses([&] {
                (void)supervisor.issue_round1(
                    accepted_input_history(), replay_guard(registry),
                    arm_residual(supervisor));
            });
        } else {
            auto registry = std::make_shared<MemoryReplayRegistry>();
            auto round1 = supervisor.issue_round1(
                accepted_input_history(), replay_guard(registry),
                arm_residual(supervisor));
            consume_round1_bootstrap(round1);
            refuses([&] {
                (void)supervisor.issue_round2(
                    std::move(round1), accepted_history());
            });
        }
    }
}

void ambiguous_child_failure_burns_trial_before_reuse() {
    for (unsigned failure = 0; failure < 3; ++failure) {
        auto registry = std::make_shared<MemoryReplayRegistry>();
        {
            Roots roots;
            std::shared_ptr<PrivateLifecycleOwnerChildProgram> program;
            if (failure == 0)
                program = std::make_shared<EofPrivateLifecycleProgram>();
            else if (failure == 1)
                program =
                    std::make_shared<CredentialSubstitutionProgram>();
            else
                program = std::make_shared<TestPrivateLifecycleProgram>(7);
            auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
                compiled_plan(std::move(program)), root_authorities(roots));
            if (failure < 2) {
                refuses([&] {
                    (void)supervisor.issue_round1(
                        accepted_input_history(), replay_guard(registry),
                        arm_residual(supervisor));
                });
            } else {
                auto round1 = supervisor.issue_round1(
                    accepted_input_history(), replay_guard(registry),
                    arm_residual(supervisor));
                consume_round1_bootstrap(round1);
                refuses([&] {
                    (void)supervisor.issue_round2(
                        std::move(round1), accepted_history());
                });
            }
        }
        {
            Roots fresh_roots;
            auto replayed = FreshOwnerProcessSupervisor::launch_exact_three(
                compiled_plan(), root_authorities(fresh_roots));
            refuses([&] {
                (void)replayed.issue_round1(
                    accepted_input_history(), replay_guard(registry),
                    arm_residual(replayed));
            });
            for (const auto& path : fresh_roots.paths) {
                errno = 0;
                assert(::access((path +
                    "/ROUND1-OWNER-PRIVATE-INPUT-V2.bin").c_str(), F_OK) ==
                    -1);
                assert(errno == ENOENT);
            }
        }
    }
}

void mismatched_child_and_verifier_identity_refuses_before_generation() {
    Roots roots;
    auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
        compiled_plan(std::make_shared<MismatchedVerifierProgram>()),
        root_authorities(roots));
    refuses([&] {
        (void)supervisor.issue_round1(
            accepted_input_history(),
            replay_guard(std::make_shared<MemoryReplayRegistry>()),
            arm_residual(supervisor));
    });
    for (const auto& path : roots.paths) {
        errno = 0;
        assert(::access((path +
            "/ROUND1-OWNER-PRIVATE-INPUT-V2.bin").c_str(), F_OK) == -1);
        assert(errno == ENOENT);
    }
}

void private_continuity_substitution_refuses() {
    {
        Roots roots;
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(roots));
        auto wrong = input_lineages(1);
        wrong[1] = id(0xf101);
        refuses([&] {
            (void)supervisor.issue_round1(
                AcceptedRound1InputHistoryAuthority::test_only_mint(
                    accepted_input_history().public_receipt(), wrong),
                replay_guard(std::make_shared<MemoryReplayRegistry>()),
                arm_residual(supervisor));
        });
    }
    {
        Roots roots;
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(roots));
        auto registry = std::make_shared<MemoryReplayRegistry>();
        auto round1 = supervisor.issue_round1(
            accepted_input_history(), replay_guard(registry),
            arm_residual(supervisor));
        consume_round1_bootstrap(round1);
        auto wrong = input_lineages(2);
        wrong[2] = id(0xf202);
        refuses([&] {
            (void)supervisor.issue_round2(
                std::move(round1),
                AcceptedRound1SuccessorHistoryAuthority::test_only_mint(
                    accepted_history().public_receipt(), wrong));
        });
    }
    {
        Roots first_roots;
        Roots second_roots;
        auto first = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(first_roots));
        auto second = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(std::make_shared<AlternateRosterProgram>()),
            root_authorities(second_roots));
        auto first_round = first.issue_round1(
            accepted_input_history(), replay_guard(
                std::make_shared<MemoryReplayRegistry>()),
            arm_residual(first));
        auto second_round = second.issue_round1(
            accepted_input_history(), replay_guard(
                std::make_shared<MemoryReplayRegistry>()),
            arm_residual(second));
        auto first_driver = first_round.take_driver_round();
        auto first_history = first_round.take_bootstrap_history();
        auto wrong_roster_continuity = second_round.take_continuity();
        refuses([&] {
            (void)FreshOwnerRoundBootstrapBridge::consume(
                std::move(first_driver), std::move(first_history),
                std::move(wrong_roster_continuity));
        });
    }
    {
        Roots roots;
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(roots));
        auto round1 = supervisor.issue_round1(
            accepted_input_history(), replay_guard(
                std::make_shared<MemoryReplayRegistry>()),
            arm_residual(supervisor));
        (void)round1.take_driver_round();
        (void)round1.take_bootstrap_history();
        auto wrong_round_continuity = round1.take_continuity();
        auto round2 = supervisor.issue_round2(
            std::move(round1), accepted_history());
        auto driver2 = round2.take_driver_round();
        auto history2 = round2.take_bootstrap_history();
        refuses([&] {
            (void)FreshOwnerRoundBootstrapBridge::consume(
                std::move(driver2), std::move(history2),
                std::move(wrong_round_continuity));
        });
    }
    {
        Roots roots;
        refuses([&] {
            (void)FreshOwnerProcessSupervisor::launch_exact_three(
                compiled_plan(std::make_shared<MissingLineageProgram>()),
                root_authorities(roots));
        });
    }
}

void replay_store_refuses_second_process_tree() {
    auto registry = std::make_shared<MemoryReplayRegistry>();
    {
        Roots roots;
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(roots));
        auto round1 = supervisor.issue_round1(
            accepted_input_history(), replay_guard(registry),
            arm_residual(supervisor));
        consume_round1_bootstrap(round1);
        auto round2 = supervisor.issue_round2(
            std::move(round1), accepted_history());
        consume_round2_bootstrap(round2);
        (void)round2.take_baseline_roster();
    }
    {
        Roots roots;
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(roots));
        refuses([&] {
            (void)supervisor.issue_round1(
                accepted_input_history(), replay_guard(registry),
                arm_residual(supervisor));
        });
        for (const auto& path : roots.paths) {
            errno = 0;
            assert(::access((path +
                "/ROUND1-OWNER-PRIVATE-INPUT-V2.bin").c_str(), F_OK) == -1);
            assert(errno == ENOENT);
        }
    }
}

void typed_history_and_bootstrap_replay_refuse() {
    auto input_history = accepted_input_history();
    {
        Roots roots;
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(roots));
        auto registry = std::make_shared<MemoryReplayRegistry>();
        auto round1 = supervisor.issue_round1(
            std::move(input_history), replay_guard(registry),
            arm_residual(supervisor));
        auto driver = round1.take_driver_round();
        auto bootstrap = round1.take_bootstrap_history();
        auto continuity = round1.take_continuity();
        auto consumed = FreshOwnerRoundBootstrapBridge::consume(
            std::move(driver), std::move(bootstrap),
            std::move(continuity));
        assert(consumed.public_receipt().round == 1);
        refuses([&] {
            (void)FreshOwnerRoundBootstrapBridge::consume(
                std::move(driver), std::move(bootstrap),
                std::move(continuity));
        });
    }
    {
        Roots roots;
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(roots));
        refuses([&] {
            (void)supervisor.issue_round1(
                std::move(input_history),
                replay_guard(std::make_shared<MemoryReplayRegistry>()),
                arm_residual(supervisor));
        });
    }
    {
        Roots roots;
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            compiled_plan(), root_authorities(roots));
        auto registry = std::make_shared<MemoryReplayRegistry>();
        auto round1 = supervisor.issue_round1(
            accepted_input_history(), replay_guard(registry),
            arm_residual(supervisor));
        // R2 cannot begin until both scoped R1 bootstrap capabilities leave
        // the continuation object for the selected parent bridge.
        refuses([&] {
            (void)supervisor.issue_round2(
                std::move(round1), accepted_history());
        });
        for (const auto& path : roots.paths)
            assert(::access((path +
                "/ROUND2-OWNER-PRIVATE-INPUT-V2.bin").c_str(), F_OK) == -1);
    }
}

void status_closed() {
    const auto value = fresh_owner_process_adapter_source_status();
    assert(value.schema ==
           "kpi-fresh-owner-process-adapter-source-status/v3");
    assert(value.exact_three_long_lived_children);
    assert(value.inherited_seqpacket_scm_credentials);
    assert(value.fixed_private_root_descriptors);
    assert(value.parent_root_aliases_after_ack == false);
    assert(value.round2_requires_typed_accepted_history);
    assert(value.round2_typed_attempt_outcome);
    assert(value.round2_postclaim_typed_stop);
    assert(!value.production_round2_consumer);
    assert(!value.path_body_or_body_hash_export);
    assert(!value.selected_private_lifecycle_program);
    assert(!value.production_root_authority_minter);
    assert(!value.production_history_authority_minter);
    assert(value.typed_testnet_history_adapter);
    assert(value.issuance_validated_v3_history_residual);
    assert(!value.production_v3_lifecycle_controller_minter);
    assert(!value.production_replay_store_minter);
    assert(!value.same_round_retry_minter);
    assert(value.hidden_candidate_fd42_truth_endpoint);
    assert(!value.production_post_barrier_truth_minter);
    assert(!value.registered_driver_configured);
    assert(!value.launch_authorized);
}

} // namespace

#ifndef KPI_FRESH_OWNER_PROCESS_ADAPTER_FIXTURE_NO_MAIN
int main(int argc, char** argv) {
    assert(argc == 2);
    const std::string_view scenario(argv[1]);
    if (scenario == "happy") happy_real_process_flow();
    else if (scenario == "transactional-round1")
        transactional_round1_closed_sum();
    else if (scenario == "transactional-round2")
        transactional_round2_closed_sum();
    else if (scenario == "transactional-round2-faults")
        transactional_round2_faults_are_typed_stop();
    else if (scenario == "transactional-round2-drop")
        transactional_round2_outcome_drop_is_fail_stop();
    else if (scenario == "transactional-stop")
        transactional_round1_unavailable_is_typed_stop();
    else if (scenario == "transactional-drop")
        transactional_round1_outcome_drop_is_fail_stop();
    else if (scenario == "transactional-faults")
        transactional_round1_faults_are_typed_stop();
    else if (scenario == "transactional-pidfd")
        transactional_stop_uses_pidfd_settlement();
    else if (scenario == "unsafe-sigchld")
        unsafe_sigchld_refuses_before_owner_claim();
    else if (scenario == "candidate-truth") hidden_candidate_truth_flow();
    else if (scenario == "candidate-unread")
        unread_candidate_truth_endpoints_close_without_decode();
    else if (scenario == "candidate-refuse")
        hidden_candidate_truth_refusals();
    else if (scenario == "arm-gate") arm_isolation_join_is_mandatory();
    else if (scenario == "paired-arm")
        paired_private_arm_join_issues_both_round1_files();
    else if (scenario == "wrong-history")
        wrong_history_refuses_before_round_generation();
    else if (scenario == "wrong-root")
        wrong_slot_and_root_alias_refuse();
    else if (scenario == "child-failure")
        child_eof_credential_substitution_and_nonzero_exit_refuse();
    else if (scenario == "failure-burn")
        ambiguous_child_failure_burns_trial_before_reuse();
    else if (scenario == "verifier-mismatch")
        mismatched_child_and_verifier_identity_refuses_before_generation();
    else if (scenario == "continuity")
        private_continuity_substitution_refuses();
    else if (scenario == "replay") replay_store_refuses_second_process_tree();
    else if (scenario == "gate-replay")
        typed_history_and_bootstrap_replay_refuse();
    else if (scenario == "status") status_closed();
    else return 2;
}
#endif
