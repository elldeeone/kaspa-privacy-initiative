#include "bounded_setup_authority.hpp"

#include <array>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <openssl/evp.h>
#include <span>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {
using namespace kpb::bounded_setup;

struct DirectoryCloser final {
    void operator()(DIR* value) const noexcept {
        if (value != nullptr && ::closedir(value) != 0) {}
    }
};

Digest file_hash(const char* path) {
    std::ifstream input(path, std::ios::binary);
    assert(input.good());
    EVP_MD_CTX* raw = EVP_MD_CTX_new();
    assert(raw != nullptr && EVP_DigestInit_ex(raw, EVP_sha256(), nullptr) == 1);
    std::array<char, 8192> buffer{};
    while (input.good()) {
        input.read(buffer.data(), buffer.size());
        const auto count = input.gcount();
        if (count > 0)
            assert(EVP_DigestUpdate(raw, buffer.data(),
                                    static_cast<std::size_t>(count)) == 1);
    }
    assert(input.eof());
    Digest result{};
    unsigned size = 0;
    assert(EVP_DigestFinal_ex(raw, result.data(), &size) == 1 &&
           size == result.size());
    EVP_MD_CTX_free(raw);
    return result;
}

template<class F> void expect_refused(F&& call) {
    bool refused = false;
    try { call(); } catch (const SetupRefused&) { refused = true; }
    assert(refused);
}

FrozenSetupPlanBinding plan_binding() {
    return BoundedSetupTestFixture::pre_setup_plan(
        BoundedSetupTestFixture::digest(std::string(64, '3')));
}

FrozenTwoRunPlanAuthority plan() {
    return BoundedSetupTestFixture::freeze_plan(
        plan_binding(),
        BoundedSetupTestFixture::output_closure(),
        BoundedSetupTestFixture::aggregate_closure());
}

SetupWorkerSelectionAuthority worker(const char* path) {
    return BoundedSetupTestFixture::select_worker(path, file_hash(path));
}

std::string fresh_case(const std::string& root, unsigned index) {
    const auto result = root + "/case-" + std::to_string(index);
    assert(::mkdir(result.c_str(), 0700) == 0);
    return result;
}

bool empty(const std::string& path) {
    DIR* raw = ::opendir(path.c_str());
    if (raw == nullptr) return false;
    std::unique_ptr<DIR, DirectoryCloser> directory(raw);
    errno = 0;
    while (auto* item = ::readdir(directory.get()))
        if (std::strcmp(item->d_name, ".") != 0 &&
            std::strcmp(item->d_name, "..") != 0)
            return false;
    return errno == 0;
}

void validate_published_outputs(const std::string& path) {
    constexpr std::array<const char*, 4> names{
        "OUTPUT-PK.bin", "OUTPUT-VK.bin",
        "AGGREGATE-PK.bin", "AGGREGATE-VK.bin"};
    constexpr std::array<off_t, 4> sizes{4096, 328, 8192, 328};
    for (std::size_t i = 0; i < names.size(); ++i) {
        struct stat status{};
        const auto file = path + "/" + names[i];
        assert(::lstat(file.c_str(), &status) == 0);
        assert(S_ISREG(status.st_mode));
        assert((status.st_mode & 07777) == 0400);
        assert(status.st_uid == ::geteuid() && status.st_nlink == 1);
        assert(status.st_size == sizes[i]);
    }
}

void validate_receipt(const BoundedSetupReceipt& value) {
    assert(value.worker_pids[0] > 0 && value.worker_pids[1] > 0);
    assert(value.worker_pids[0] != value.worker_pids[1]);
    assert(value.selected_plan == plan_binding());
    assert(value.circuits[0].role == CircuitRole::Output);
    assert(value.circuits[1].role == CircuitRole::Aggregate);
    assert(value.artifacts[0].proving_key && !value.artifacts[1].proving_key);
    assert(value.artifacts[2].proving_key && !value.artifacts[3].proving_key);
    assert(value.source_and_matrix_bound && value.exact_two_run_plan);
    assert(value.pre_setup_only_plan);
    assert(value.post_setup_artifacts_excluded_from_plan);
    assert(value.dedicated_one_shot_process_per_circuit);
    assert(value.single_threaded_controller);
    assert(value.inherited_private_output_fds && value.exact_allowed_outputs);
    assert(value.environment_empty && value.unknown_descriptors_closed);
    assert(value.network_syscalls_denied && value.source_opens_denied);
    assert(value.descendant_processes_denied && value.debugger_attachment_denied);
    assert(value.core_dumps_disabled);
    assert(value.swap_max_zero_before_and_after && value.eof_observed);
    assert(value.finite_memory_and_disk_guard_satisfied);
    assert(value.wait_status_zero && value.outputs_fsynced);
    assert(value.directory_fsynced && value.process_terminated);
    assert(value.parent_death_kills_worker);
    assert(value.worker_reported_erasure_attempt);
    assert(value.best_effort_erasure_only);
    assert(!value.erasure_cryptographically_proven);
    assert(!value.setup_honesty_cryptographically_proven);
    assert(!value.ceremony_claimed && !value.s4_selected && !value.s12_selected);
    assert(!value.configured);
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 11);
    const std::string root = argv[1];
    const auto vector = plan_binding();
    assert(vector.financial_runs[0] == BoundedSetupTestFixture::digest(
        "570fec2056d38f569c66b902e40b847279b752990efc9112f287cbdd7a1186e2"));
    assert(vector.financial_runs[1] == BoundedSetupTestFixture::digest(
        "2ad33544b56955b606899418651055dd55c739bb91f49ad577322abc5f69ba9e"));
    assert(vector.round_attempts[0] == BoundedSetupTestFixture::digest(
        "a724ae74c37c0ca13d9a7bffd679088fef02ed5c4e566d21d7ed8f1225598d5f"));
    assert(vector.round_attempts[1] == BoundedSetupTestFixture::digest(
        "8d256d22727f353331ca268d359b7719588eb6d0b7c08f680718f0d6db8995a4"));
    assert(vector.round_cohorts[0] == BoundedSetupTestFixture::digest(
        "09f5792c2e433c5c9e0a2c7e5edbd5dd53fd8bc0bfba8909e28c7fa1f9bc3227"));
    assert(vector.round_cohorts[1] == BoundedSetupTestFixture::digest(
        "571d5ee6fc0d7c4289f93346bbe787166ec2c39afdfb232a1474f2044ddc7e7b"));
    assert(kBoundedSetupSourceStatus.exact_output_closure_bound);
    assert(kBoundedSetupSourceStatus.exact_aggregate_closure_bound);
    assert(kBoundedSetupSourceStatus.exact_two_run_plan_abi);
    assert(kBoundedSetupSourceStatus.pre_setup_only_plan_abi);
    assert(kBoundedSetupSourceStatus.post_setup_artifacts_excluded);
    assert(kBoundedSetupSourceStatus.dedicated_process_per_circuit);
    assert(kBoundedSetupSourceStatus.source_closed_static_worker_required);
    assert(kBoundedSetupSourceStatus.aggregate_sources_fd_bound);
    assert(kBoundedSetupSourceStatus.fd_only_parameter_outputs);
    assert(kBoundedSetupSourceStatus.network_core_swap_policy_mechanism);
    assert(kBoundedSetupSourceStatus.finite_memory_and_disk_guard_mechanism);
    assert(kBoundedSetupSourceStatus.source_owned_worker_selector);
    assert(!kBoundedSetupSourceStatus.source_owned_plan_selector);
    assert(!kBoundedSetupSourceStatus.typed_w1_pre_setup_handoff);
    assert(!kBoundedSetupSourceStatus.typed_w1_post_setup_measured_key_join);
    assert(kBoundedSetupSourceStatus.actual_fd_setup_worker);
    assert(!kBoundedSetupSourceStatus.full_output_setup_executed);
    assert(!kBoundedSetupSourceStatus.full_aggregate_setup_executed);
    assert(!kBoundedSetupSourceStatus.setup_honesty_or_erasure_proven);
    assert(!kBoundedSetupSourceStatus.s4_selected);
    assert(!kBoundedSetupSourceStatus.s12_selected);
    assert(!kBoundedSetupSourceStatus.configured);
    assert(!kBoundedSetupPlanBlocker.production_trial_root_authority_present);
    assert(!kBoundedSetupPlanBlocker.typed_post_setup_key_join_present);

    auto wrong_output = BoundedSetupTestFixture::output_closure();
    wrong_output.source_identity[0] ^= 1;
    expect_refused([&] {
        (void)BoundedSetupTestFixture::freeze_plan(
            plan_binding(),
            wrong_output, BoundedSetupTestFixture::aggregate_closure());
    });
    wrong_output = BoundedSetupTestFixture::output_closure();
    wrong_output.matrix_identity[0] ^= 1;
    expect_refused([&] {
        (void)BoundedSetupTestFixture::freeze_plan(
            plan_binding(),
            wrong_output, BoundedSetupTestFixture::aggregate_closure());
    });
    auto wrong_aggregate = BoundedSetupTestFixture::aggregate_closure();
    wrong_aggregate.matrix_identity[31] ^= 1;
    expect_refused([&] {
        (void)BoundedSetupTestFixture::freeze_plan(
            plan_binding(),
            BoundedSetupTestFixture::output_closure(), wrong_aggregate);
    });
    wrong_aggregate = BoundedSetupTestFixture::aggregate_closure();
    wrong_aggregate.source_identity[31] ^= 1;
    expect_refused([&] {
        (void)BoundedSetupTestFixture::freeze_plan(
            plan_binding(),
            BoundedSetupTestFixture::output_closure(), wrong_aggregate);
    });
    wrong_aggregate = BoundedSetupTestFixture::aggregate_closure();
    ++wrong_aggregate.constraints;
    expect_refused([&] {
        (void)BoundedSetupTestFixture::freeze_plan(
            plan_binding(),
            BoundedSetupTestFixture::output_closure(), wrong_aggregate);
    });
    expect_refused([&] {
        auto reused = plan_binding();
        reused.financial_runs[1] = reused.financial_runs[0];
        (void)BoundedSetupTestFixture::freeze_plan(
            reused, BoundedSetupTestFixture::output_closure(),
            BoundedSetupTestFixture::aggregate_closure());
    });
    expect_refused([&] {
        auto missing = plan_binding();
        missing.round_cohorts[0] = {};
        (void)BoundedSetupTestFixture::freeze_plan(
            missing,
            BoundedSetupTestFixture::output_closure(),
            BoundedSetupTestFixture::aggregate_closure());
    });
    expect_refused([&] {
        auto reused = plan_binding();
        reused.round_cohorts[1] = reused.round_cohorts[0];
        (void)BoundedSetupTestFixture::freeze_plan(
            reused,
            BoundedSetupTestFixture::output_closure(),
            BoundedSetupTestFixture::aggregate_closure());
    });
    expect_refused([&] {
        auto aliased = plan_binding();
        aliased.round_attempts[0] = aliased.financial_runs[0];
        (void)BoundedSetupTestFixture::freeze_plan(
            aliased,
            BoundedSetupTestFixture::output_closure(),
            BoundedSetupTestFixture::aggregate_closure());
    });
    auto wrong_worker = file_hash(argv[2]);
    wrong_worker[0] ^= 1;
    expect_refused([&] {
        (void)BoundedSetupTestFixture::select_worker(argv[2], wrong_worker);
    });
    expect_refused([&] {
        (void)BoundedSetupTestFixture::select_worker(argv[0], file_hash(argv[0]));
    });

    assert(::setenv("KPB_SETUP_SEED", "caller-seed-must-not-cross-exec", 1) == 0);
    const int sentinel = ::open("/dev/null", O_RDONLY);
    assert(sentinel >= 0 && ::dup2(sentinel, 200) == 200);
    ::close(sentinel);
    auto selected = worker(argv[2]);
    auto frozen = plan();
    const auto positive_dir = fresh_case(root, 0);
    auto completion = BoundedSetupTestFixture::execute(
        std::move(selected), std::move(frozen), positive_dir);
    validate_receipt(completion.receipt());
    validate_published_outputs(positive_dir);
    // This is an actual post-setup test PK identity. It cannot masquerade as
    // any one of the seven precommitted lifecycle identities on the wire.
    // A future production selector must additionally prove the provenance of
    // the trial root itself; until then no production plan can be minted.
    for (unsigned slot = 0; slot < 7; ++slot) {
        expect_refused([&, slot] {
            auto smuggled = plan_binding();
            const auto output_pk = completion.receipt().artifacts[0].sha256;
            if (slot == 0) smuggled.trial = output_pk;
            if (slot == 1) smuggled.financial_runs[0] = output_pk;
            if (slot == 2) smuggled.financial_runs[1] = output_pk;
            if (slot == 3) smuggled.round_attempts[0] = output_pk;
            if (slot == 4) smuggled.round_attempts[1] = output_pk;
            if (slot == 5) smuggled.round_cohorts[0] = output_pk;
            if (slot == 6) smuggled.round_cohorts[1] = output_pk;
            (void)BoundedSetupTestFixture::freeze_plan(
                smuggled,
                BoundedSetupTestFixture::output_closure(),
                BoundedSetupTestFixture::aggregate_closure());
        });
    }
    assert(::close(200) == 0);
    expect_refused([&] { (void)completion.consume_for_test();
                         (void)completion.consume_for_test(); });

    auto moved_worker = worker(argv[2]);
    auto retained_moved_worker = std::move(moved_worker);
    auto moved_plan = plan();
    auto retained_moved_plan = std::move(moved_plan);
    expect_refused([&] {
        (void)BoundedSetupTestFixture::execute(
            std::move(moved_worker), plan(), fresh_case(root, 1));
    });
    expect_refused([&] {
        (void)BoundedSetupTestFixture::execute(
            worker(argv[2]), std::move(moved_plan), fresh_case(root, 2));
    });
    (void)retained_moved_worker;
    (void)retained_moved_plan;

    for (unsigned behavior = 1; behavior <= 8; ++behavior) {
        const auto directory = fresh_case(root, behavior + 2);
        expect_refused([&] {
            (void)BoundedSetupTestFixture::execute(
                worker(argv[2 + behavior]), plan(), directory);
        });
        assert(empty(directory));
    }
    errno = 0;
    assert(::access("/tmp/kpb-bounded-setup-forbidden-output", F_OK) == -1 &&
           errno == ENOENT);
    return 0;
}
