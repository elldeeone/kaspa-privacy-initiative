#include "privacy_capture_producer_supervisor.hpp"

#include <array>
#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>

using namespace kpb::measurement;
using namespace kpb::measurement::producer_supervisor;

namespace {

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

RunBinding binding() {
    RunBinding result{};
    result.run_selection = digest(0x11);
    result.capture = digest(0x12);
    result.finite_manifest.manifest_identity = digest(0x13);
    result.round_capture_plans = {digest(0x14), digest(0x15)};
    result.financial_runs = {digest(0x16), digest(0x17)};
    result.round_attempts = {digest(0x18), digest(0x19)};
    result.round_cohorts = {digest(0x1a), digest(0x1b)};
    result.projections = {digest(0x1c), digest(0x1d)};
    return result;
}

ProducerClosureEvidence closure_evidence(const Digest& opaque) {
    ProducerClosureEvidence result{};
    result.opaque_closure_authority_identity = opaque;
    result.producer_child_exit = digest(0x23);
    result.producer_receipt = digest(0x24);
    result.producer_identity = digest(0x25);
    for (unsigned index = 0; index < result.streams.size(); ++index) {
        result.streams[index].record_root =
            digest(static_cast<unsigned char>(0x30 + index));
        result.streams[index].end_frame_identity =
            digest(static_cast<unsigned char>(0x40 + index));
        result.streams[index].eof_identity =
            digest(static_cast<unsigned char>(0x50 + index));
        result.streams[index].record_count = 1 + index;
        result.streams[index].payload_bytes = 100 + index;
        result.streams[index].raw_wire_bytes = 200 + index;
    }
    return result;
}

void close_fd(int fd);

void write_leaf(const std::string& path) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                    0400);
    assert(fd >= 0);
    const unsigned char value = 1;
    assert(::write(fd, &value, 1) == 1);
    close_fd(fd);
}

void populate_spool(const char* directory) {
    write_leaf(std::string(directory) + "/PRODUCER.json");
    constexpr std::array<const char*, 5> names{
        "projection.bin", "terminal.json", "dispatcher.json",
        "corrupt-server.json", "colluder-wallet.json",
    };
    for (unsigned round = 1; round <= 2; ++round) {
        const std::string root = std::string(directory) + "/round-" +
                                 std::to_string(round);
        assert(::mkdir(root.c_str(), 0700) == 0);
        for (const char* name : names)
            write_leaf(root + "/" + name);
    }
}

void remove_spool(const char* directory) {
    constexpr std::array<const char*, 5> names{
        "projection.bin", "terminal.json", "dispatcher.json",
        "corrupt-server.json", "colluder-wallet.json",
    };
    assert(::unlink((std::string(directory) + "/PRODUCER.json").c_str()) == 0);
    for (unsigned round = 1; round <= 2; ++round) {
        const std::string root = std::string(directory) + "/round-" +
                                 std::to_string(round);
        for (const char* name : names)
            assert(::unlink((root + "/" + name).c_str()) == 0);
        assert(::rmdir(root.c_str()) == 0);
    }
    assert(::rmdir(directory) == 0);
}

std::array<C03RoleLaunchRoundBinding, 2> c03_rounds(
        const RunBinding& selected) {
    std::array<C03RoleLaunchRoundBinding, 2> result{};
    for (unsigned index = 0; index < result.size(); ++index) {
        result[index] = {
            .round = index + 1,
            .fixed_fd = 23 + 5 * index,
            .financial_run = selected.financial_runs[index],
            .attempt = selected.round_attempts[index],
            .cohort = selected.round_cohorts[index],
            .capture_plan = selected.round_capture_plans[index],
            .projection = selected.projections[index],
            .source_identity = digest(
                static_cast<unsigned char>(0x60 + index)),
            .build_identity = digest(
                static_cast<unsigned char>(0x62 + index)),
            .runtime_identity = digest(
                static_cast<unsigned char>(0x64 + index)),
            .launcher_identity = digest(
                static_cast<unsigned char>(0x66 + index)),
            .process_identity = digest(
                static_cast<unsigned char>(0x68 + index)),
            .child_exit_identity = digest(
                static_cast<unsigned char>(0x6a + index)),
            .model_preimage_identity = digest(
                static_cast<unsigned char>(0x6c + index)),
            .query_store_preimage_identity = digest(
                static_cast<unsigned char>(0x6e + index)),
            .scalar_capture_manifest_identity = digest(
                static_cast<unsigned char>(0x70 + index)),
        };
    }
    return result;
}

void close_fd(int fd) {
    while (::close(fd) != 0 && errno == EINTR) {}
}

void move_only_directory_capability_is_consumed_once() {
    static_assert(!std::is_copy_constructible_v<ProducerSpoolAuthority>);
    static_assert(std::is_move_constructible_v<ProducerSpoolAuthority>);
    std::array<char, 48> name{};
    const char pattern[] = "/tmp/kpb-producer-spool-control-XXXXXX";
    std::copy(std::begin(pattern), std::end(pattern), name.begin());
    char* directory = ::mkdtemp(name.data());
    assert(directory != nullptr);
    populate_spool(directory);
    const int fd = ::open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                         O_CLOEXEC);
    assert(fd >= 0);
    const auto selected = binding();
    const auto receipt = digest(0x21);
    const auto spool = digest(0x22);
    const auto process = digest(0x26);
    const auto evidence = closure_evidence(receipt);
    auto authority = ProducerSpoolAuthority::test_only_mint(
        selected, receipt, spool, process, digest(0x27), digest(0x28),
        evidence, fd);
    assert(authority.test_only_matches(
        selected, receipt, spool, process, evidence));
    ProducerSpoolAuthority moved(std::move(authority));
    expect_refused([&] { (void)authority.test_only_take_directory(); });
    assert(moved.test_only_matches(
        selected, receipt, spool, process, evidence));
    auto swapped = selected;
    std::swap(swapped.round_capture_plans[0],
              swapped.round_capture_plans[1]);
    assert(!moved.test_only_matches(
        swapped, receipt, spool, process, evidence));
    const int consumed = moved.test_only_take_directory();
    struct stat status{};
    assert(::fstat(consumed, &status) == 0 && S_ISDIR(status.st_mode));
    expect_refused([&] { (void)moved.test_only_take_directory(); });
    close_fd(consumed);
    remove_spool(directory);
}

void nonprivate_or_nondirectory_capability_refuses() {
    std::array<char, 48> name{};
    const char pattern[] = "/tmp/kpb-producer-spool-refuse-XXXXXX";
    std::copy(std::begin(pattern), std::end(pattern), name.begin());
    char* directory = ::mkdtemp(name.data());
    assert(directory != nullptr && ::chmod(directory, 0755) == 0);
    int fd = ::open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                    O_CLOEXEC);
    assert(fd >= 0);
    expect_refused([&] {
        (void)ProducerSpoolAuthority::test_only_mint(
            binding(), digest(0x31), digest(0x32), digest(0x33),
            digest(0x34), digest(0x35), closure_evidence(digest(0x31)), fd);
    });
    assert(::chmod(directory, 0700) == 0 && ::rmdir(directory) == 0);

    std::array<char, 48> file_name{};
    const char file_pattern[] = "/tmp/kpb-producer-spool-file-XXXXXX";
    std::copy(std::begin(file_pattern), std::end(file_pattern),
              file_name.begin());
    fd = ::mkstemp(file_name.data());
    assert(fd >= 0);
    const int descriptor_flags = ::fcntl(fd, F_GETFD);
    assert(descriptor_flags >= 0 &&
           ::fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) == 0);
    expect_refused([&] {
        (void)ProducerSpoolAuthority::test_only_mint(
            binding(), digest(0x36), digest(0x37), digest(0x38),
            digest(0x39), digest(0x3a), closure_evidence(digest(0x36)), fd);
    });
    assert(::unlink(file_name.data()) == 0);
}

void zero_or_unbound_identity_refuses() {
    std::array<char, 48> name{};
    const char pattern[] = "/tmp/kpb-producer-spool-zero-XXXXXX";
    std::copy(std::begin(pattern), std::end(pattern), name.begin());
    char* directory = ::mkdtemp(name.data());
    assert(directory != nullptr);
    int fd = ::open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                    O_CLOEXEC);
    assert(fd >= 0);
    expect_refused([&] {
        (void)ProducerSpoolAuthority::test_only_mint(
            binding(), Digest{}, digest(0x42), digest(0x43), digest(0x44),
            digest(0x45), closure_evidence(digest(0x41)), fd);
    });
    fd = ::open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0);
    auto unbound = binding();
    unbound.capture = {};
    expect_refused([&] {
        (void)ProducerSpoolAuthority::test_only_mint(
            unbound, digest(0x46), digest(0x47), digest(0x48), digest(0x49),
            digest(0x4a), closure_evidence(digest(0x46)), fd);
    });

    fd = ::open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0);
    auto zero_plan = binding();
    zero_plan.round_capture_plans[0] = {};
    expect_refused([&] {
        (void)ProducerSpoolAuthority::test_only_mint(
            zero_plan, digest(0x4b), digest(0x4c), digest(0x4d),
            digest(0x4e), digest(0x4f), closure_evidence(digest(0x4b)), fd);
    });

    fd = ::open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0);
    auto reused_plan = binding();
    reused_plan.round_capture_plans[1] =
        reused_plan.round_capture_plans[0];
    expect_refused([&] {
        (void)ProducerSpoolAuthority::test_only_mint(
            reused_plan, digest(0x50), digest(0x51), digest(0x52),
            digest(0x53), digest(0x54), closure_evidence(digest(0x50)), fd);
    });
    assert(::rmdir(directory) == 0);
}

void writable_hardlinked_or_unbound_leaf_refuses() {
    std::array<char, 48> name{};
    const char pattern[] = "/tmp/kpb-producer-spool-leaf-XXXXXX";
    std::copy(std::begin(pattern), std::end(pattern), name.begin());
    char* directory = ::mkdtemp(name.data());
    assert(directory != nullptr);
    populate_spool(directory);
    const std::string projection =
        std::string(directory) + "/round-1/projection.bin";
    const std::string alias = std::string(directory) + "-alias";
    assert(::link(projection.c_str(), alias.c_str()) == 0);
    int fd = ::open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                    O_CLOEXEC);
    assert(fd >= 0);
    expect_refused([&] {
        (void)ProducerSpoolAuthority::test_only_mint(
            binding(), digest(0x91), digest(0x92), digest(0x93),
            digest(0x94), digest(0x95), closure_evidence(digest(0x91)), fd);
    });
    assert(::unlink(alias.c_str()) == 0);

    assert(::chmod(projection.c_str(), 0600) == 0);
    fd = ::open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0);
    expect_refused([&] {
        (void)ProducerSpoolAuthority::test_only_mint(
            binding(), digest(0x91), digest(0x92), digest(0x93),
            digest(0x94), digest(0x95), closure_evidence(digest(0x91)), fd);
    });
    assert(::chmod(projection.c_str(), 0400) == 0);

    auto evidence = closure_evidence(digest(0x91));
    evidence.streams[3].record_root = {};
    fd = ::open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0);
    expect_refused([&] {
        (void)ProducerSpoolAuthority::test_only_mint(
            binding(), digest(0x91), digest(0x92), digest(0x93),
            digest(0x94), digest(0x95), evidence, fd);
    });
    remove_spool(directory);
}

void c03_role_launch_admission_is_exact_and_one_shot() {
    static_assert(!std::is_copy_constructible_v<
                  C03RoleLaunchAdmissionAuthority>);
    static_assert(std::is_move_constructible_v<
                  C03RoleLaunchAdmissionAuthority>);
    const auto selected = binding();
    const auto rounds = c03_rounds(selected);
    auto authority = C03RoleLaunchAdmissionAuthority::test_only_mint(
        selected, digest(0x81), digest(0x82), digest(0x83), digest(0x84),
        rounds);
    assert(authority.test_only_matches(
        selected, digest(0x81), digest(0x82), digest(0x83), digest(0x84),
        rounds));
    C03RoleLaunchAdmissionAuthority moved(std::move(authority));
    expect_refused([&] { authority.test_only_consume(); });
    auto swapped = rounds;
    std::swap(swapped[0], swapped[1]);
    assert(!moved.test_only_matches(
        selected, digest(0x81), digest(0x82), digest(0x83), digest(0x84),
        swapped));
    moved.test_only_consume();
    expect_refused([&] { moved.test_only_consume(); });

    auto wrong = rounds;
    wrong[1].model_preimage_identity = {};
    expect_refused([&] {
        (void)C03RoleLaunchAdmissionAuthority::test_only_mint(
            selected, digest(0x81), digest(0x82), digest(0x83),
            digest(0x84), wrong);
    });
}

} // namespace

int main() {
    move_only_directory_capability_is_consumed_once();
    nonprivate_or_nondirectory_capability_refuses();
    zero_or_unbound_identity_refuses();
    writable_hardlinked_or_unbound_leaf_refuses();
    c03_role_launch_admission_is_exact_and_one_shot();
}
