#include "v3_native_authority.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/wait.h>
#include <type_traits>
#include <unistd.h>
#include <utility>

using namespace kpb::measurement;
using namespace kpb::future_recipient::v3_native;

namespace {

template<class Function>
void expect_refused(Function&& function) {
    bool refused = false;
    try { function(); } catch (...) { refused = true; }
    assert(refused);
}

Digest digest(unsigned char value) {
    Digest result{};
    result.fill(value);
    return result;
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

RunBinding binding(unsigned char variation = 0) {
    std::array<ManifestEntry, 10> entries{};
    for (unsigned index = 0; index < entries.size(); ++index) {
        const auto seed = static_cast<unsigned char>(0x80 + index * 6);
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
        .parent_recomputation_identity = digest(0xef),
        .entries = entries,
    };
    const auto& capture = manifest.entries[1];
    return RunBinding{
        .classification = Classification::HiddenCandidate,
        .comparison_selection = digest(0x10),
        .run_selection = digest(static_cast<unsigned char>(0x11 + variation)),
        .trial = digest(0x12),
        .attempt = digest(0x13),
        .cohort = digest(0x14),
        .capture = digest(0x15),
        .method = digest(0x16),
        .workload = digest(0x17),
        .source_closure = digest(0x18),
        .runtime = digest(0x19),
        .finite_manifest = manifest,
        .outer_parent_process = digest(0x1a),
        .outer_parent_executable = digest(0x1b),
        .capture_source = capture.source_identity,
        .capture_build = capture.build_identity,
        .capture_runtime = capture.runtime_identity,
        .capture_launcher = capture.launcher_identity,
        .observer_worker = worker(manifest.entries[6]),
        .score_worker = worker(manifest.entries[7]),
        .aggregate_worker = worker(manifest.entries[8]),
        .financial_runs = {digest(0x20), digest(0x21)},
        .round_attempts = {digest(0x22), digest(0x23)},
        .round_cohorts = {digest(0x24), digest(0x25)},
        .round_capture_plans = {digest(0x26), digest(0x27)},
        .projections = {digest(0x28), digest(0x29)},
    };
}

Invoice208 invoice(std::uint64_t index, unsigned char seed) {
    Invoice208 result{};
    constexpr std::string_view magic = "KPX3IN01";
    std::copy(magic.begin(), magic.end(), result.begin());
    for (unsigned offset = 0; offset < 8; ++offset)
        result[40 + offset] = static_cast<unsigned char>(index >> (8 * offset));
    for (std::size_t at = 8; at < result.size(); ++at)
        if (at < 40 || at >= 48)
            result[at] = static_cast<unsigned char>(seed + at);
    return result;
}

Digest ledger_key(unsigned char seed = 0x61) { return digest(seed); }

std::filesystem::path make_case(
        const std::filesystem::path& root, const std::string& name) {
    const auto result = root / name;
    assert(::mkdir(result.c_str(), 0700) == 0);
    return result;
}

std::unique_ptr<ParentV3Authority> initialize(
        const std::filesystem::path& directory,
        const RunBinding& selected = binding()) {
    auto setup = V3NativeAuthorityTestSetup::initialize_fresh(
        directory.c_str(), selected, ledger_key());
    return V3NativeAuthorityBridge::test_only_open_existing(
        std::move(setup.first), std::move(setup.second), selected);
}

std::unique_ptr<ParentV3Authority> initialize_external(
        const std::filesystem::path& directory,
        const std::filesystem::path& external,
        const RunBinding& selected = binding()) {
    auto setup = V3NativeAuthorityTestSetup::
        initialize_fresh_with_external_head(
            directory.c_str(), external.c_str(), selected, ledger_key());
    return V3NativeAuthorityBridge::test_only_open_existing(
        std::move(setup.first), std::move(setup.second), selected);
}

std::unique_ptr<ParentV3Authority> reopen_external(
        const std::filesystem::path& directory,
        const std::filesystem::path& external,
        const RunBinding& selected = binding()) {
    auto descriptors = V3NativeAuthorityTestSetup::open_descriptors(
        directory.c_str(), ledger_key());
    auto updater = V3NativeAuthorityTestSetup::open_external_latest_head(
        external.c_str(), selected, ledger_key());
    return V3NativeAuthorityBridge::test_only_open_existing(
        std::move(descriptors), std::move(updater), selected);
}

std::vector<unsigned char> file_bytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    assert(input.good());
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

void replace_file_bytes(const std::filesystem::path& path,
                        const std::vector<unsigned char>& bytes) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_TRUNC | O_CLOEXEC);
    assert(fd >= 0);
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto count = ::write(
            fd, bytes.data() + offset, bytes.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        assert(count > 0);
        offset += static_cast<std::size_t>(count);
    }
    assert(::fsync(fd) == 0 && ::close(fd) == 0);
}

struct OwnerLaunch {
    ParentOfferResidual residual;
    pid_t child;
};

OwnerLaunch launch_owner(OwnerRouteSplit&& split, const char* executable) {
    auto residual = split.take_parent_residual();
    const auto child = [&] {
        auto offer = split.take_owner_offer();
        const pid_t result = ::fork();
        assert(result >= 0);
        if (result == 0) {
            try {
                std::move(offer).install_for_owner();
                ::execl(executable, executable, "--owner-accept",
                        static_cast<char*>(nullptr));
            } catch (...) {}
            ::_exit(111);
        }
        return result;
    }();
    return {std::move(residual), child};
}

AcceptedInvoiceAuthority accept_route(
        ParentV3Authority& parent, OwnerRouteSplit&& split,
        const char* executable) {
    auto launched = launch_owner(std::move(split), executable);
    auto accepted = parent.accept_from_owner(std::move(launched.residual));
    int status = 0;
    assert(::waitpid(launched.child, &status, 0) == launched.child &&
           WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
    expect_refused([&] {
        parent.accept_from_owner(std::move(launched.residual));
    });
    return accepted;
}

void happy_path(const std::filesystem::path& root, const char* executable) {
    const auto directory = make_case(root, "happy");
    auto parent = initialize(directory);
    auto material = InvoiceMaterialAuthority::test_only_mint(*parent, invoice(7, 0x31));
    auto allocated = parent->allocate(std::move(material));
    expect_refused([&] { parent->allocate(std::move(material)); });
    auto split = parent->export_to_owner(std::move(allocated));
    auto accepted = accept_route(*parent, std::move(split), executable);
    parent->consume(std::move(accepted));
    expect_refused([&] { parent->consume(std::move(accepted)); });
    assert(parent->test_only_state(7) == LifecycleState::Consumed);
    const auto latest = parent->test_only_latest();
    parent.reset();

    auto descriptors = V3NativeAuthorityTestSetup::open_descriptors(
        directory.c_str(), ledger_key());
    auto authority = LatestHeadAuthority::test_only_mint(
        binding(), latest.first, latest.second);
    auto reopened = V3NativeAuthorityBridge::test_only_open_existing(
        std::move(descriptors), std::move(authority), binding());
    assert(reopened->test_only_state(7) == LifecycleState::Consumed);
}

void external_head_happy_path(
        const std::filesystem::path& root, const char* executable) {
    const auto directory = make_case(root, "external-happy-ledger");
    const auto external = make_case(root, "external-happy-anchor");
    auto parent = initialize_external(directory, external);
    auto allocated = parent->allocate(
        InvoiceMaterialAuthority::test_only_mint(*parent, invoice(70, 0x71)));
    auto accepted = accept_route(
        *parent, parent->export_to_owner(std::move(allocated)), executable);
    parent->consume(std::move(accepted));
    parent.reset();
    auto reopened = reopen_external(directory, external);
    assert(reopened->test_only_state(70) == LifecycleState::Consumed);
}

void poison_paths(const std::filesystem::path& root, const char* executable) {
    const auto directory = make_case(root, "poison");
    auto parent = initialize(directory);

    auto allocated = parent->allocate(
        InvoiceMaterialAuthority::test_only_mint(*parent, invoice(8, 0x41)));
    parent->poison(std::move(allocated));
    assert(parent->test_only_state(8) == LifecycleState::Poisoned);

    auto exported = parent->export_to_owner(parent->allocate(
        InvoiceMaterialAuthority::test_only_mint(*parent, invoice(9, 0x42))));
    auto residual = exported.take_parent_residual();
    auto unused_offer = exported.take_owner_offer();
    parent->poison(std::move(residual));
    assert(parent->test_only_state(9) == LifecycleState::Poisoned);

    auto accepted = accept_route(
        *parent,
        parent->export_to_owner(parent->allocate(
            InvoiceMaterialAuthority::test_only_mint(*parent, invoice(10, 0x43)))),
        executable);
    parent->poison(std::move(accepted));
    assert(parent->test_only_state(10) == LifecycleState::Poisoned);
}

void cross_parent_material_refuses(const std::filesystem::path& root) {
    auto left = initialize(make_case(root, "material-parent-left"));
    auto right = initialize(make_case(root, "material-parent-right"));
    auto material = InvoiceMaterialAuthority::test_only_mint(
        *left, invoice(11, 0x44));
    expect_refused([&] { right->allocate(std::move(material)); });
    expect_refused([&] { left->allocate(std::move(material)); });

    auto replacement = InvoiceMaterialAuthority::test_only_mint(
        *left, invoice(11, 0x44));
    auto allocated = left->allocate(std::move(replacement));
    left->poison(std::move(allocated));
    assert(left->test_only_state(11) == LifecycleState::Poisoned);
}

void missing_latest_and_cross_binding(const std::filesystem::path& root) {
    {
        const auto directory = make_case(root, "missing-latest");
        auto setup = V3NativeAuthorityTestSetup::initialize_fresh(
            directory.c_str(), binding(), ledger_key());
        expect_refused([&] {
            V3NativeAuthorityBridge::refuse_recovery_without_latest_head(
                std::move(setup.first), binding());
        });
    }
    {
        const auto directory = make_case(root, "cross-binding");
        auto setup = V3NativeAuthorityTestSetup::initialize_fresh(
            directory.c_str(), binding(), ledger_key());
        expect_refused([&] {
            V3NativeAuthorityBridge::test_only_open_existing(
                std::move(setup.first), std::move(setup.second), binding(1));
        });
    }
    {
        const auto directory = make_case(root, "wrong-key");
        auto parent = initialize(directory);
        const auto latest = parent->test_only_latest();
        parent.reset();
        auto descriptors = V3NativeAuthorityTestSetup::open_descriptors(
            directory.c_str(), ledger_key(0x62));
        auto authority = LatestHeadAuthority::test_only_mint(
            binding(), latest.first, latest.second);
        expect_refused([&] {
            V3NativeAuthorityBridge::test_only_open_existing(
                std::move(descriptors), std::move(authority), binding());
        });
    }
}

void crash_boundaries(const std::filesystem::path& root,
                      const char* executable) {
    for (const auto edge : {
             LifecycleState::Allocated, LifecycleState::Exported,
             LifecycleState::Accepted, LifecycleState::Consumed,
             LifecycleState::Poisoned}) {
        for (const auto boundary : {
                 DurableBoundary::JournalWritten,
                 DurableBoundary::JournalSynced,
                 DurableBoundary::HeadWritten,
                 DurableBoundary::HeadSynced,
                 DurableBoundary::DirectorySynced}) {
            const auto edge_number = static_cast<unsigned>(edge);
            const auto boundary_number = static_cast<unsigned>(boundary);
            const auto directory = make_case(
                root, "crash-" + std::to_string(edge_number) + "-" +
                      std::to_string(boundary_number));
            auto parent = initialize(directory);
            const auto index = 1000 + edge_number * 10 + boundary_number;
            auto hook = [boundary](DurableBoundary reached) {
                if (reached == boundary) throw NativeRefused();
            };
            std::optional<std::pair<std::uint64_t, Digest>> prior;
            std::optional<pid_t> child;
            expect_refused([&] {
                switch (edge) {
                case LifecycleState::Allocated:
                    prior = parent->test_only_latest();
                    parent->allocate(
                        InvoiceMaterialAuthority::test_only_mint(*parent,
                            invoice(index, 0x51)), hook);
                    break;
                case LifecycleState::Exported:
                    {
                    auto allocated = parent->allocate(
                        InvoiceMaterialAuthority::test_only_mint(*parent,
                            invoice(index, 0x52)));
                    prior = parent->test_only_latest();
                    parent->export_to_owner(std::move(allocated), hook);
                    }
                    break;
                case LifecycleState::Accepted:
                    {
                    auto split = parent->export_to_owner(parent->allocate(
                        InvoiceMaterialAuthority::test_only_mint(*parent,
                            invoice(index, 0x53))));
                    auto launched = launch_owner(std::move(split), executable);
                    child = launched.child;
                    prior = parent->test_only_latest();
                    parent->accept_from_owner(
                        std::move(launched.residual), hook);
                    }
                    break;
                case LifecycleState::Consumed:
                    {
                    auto accepted = accept_route(
                        *parent,
                        parent->export_to_owner(parent->allocate(
                            InvoiceMaterialAuthority::test_only_mint(*parent,
                                invoice(index, 0x54)))),
                        executable);
                    prior = parent->test_only_latest();
                    parent->consume(std::move(accepted), hook);
                    }
                    break;
                case LifecycleState::Poisoned:
                    {
                    auto allocated = parent->allocate(
                        InvoiceMaterialAuthority::test_only_mint(*parent,
                            invoice(index, 0x55)));
                    prior = parent->test_only_latest();
                    parent->poison(std::move(allocated), hook);
                    }
                    break;
                }
            });
            if (child.has_value()) {
                int status = 0;
                assert(::waitpid(*child, &status, 0) == *child &&
                       WIFEXITED(status) && WEXITSTATUS(status) == 0);
            }
            assert(prior.has_value());
            parent.reset();
            auto descriptors = V3NativeAuthorityTestSetup::open_descriptors(
                directory.c_str(), ledger_key());
            auto latest = LatestHeadAuthority::test_only_mint(
                binding(), prior->first, prior->second);
            expect_refused([&] {
                V3NativeAuthorityBridge::test_only_open_existing(
                    std::move(descriptors), std::move(latest), binding());
            });
        }
    }
}

void external_crash_boundaries(const std::filesystem::path& root,
                               const char* executable) {
    for (const auto edge : {
             LifecycleState::Allocated, LifecycleState::Exported,
             LifecycleState::Accepted, LifecycleState::Consumed,
             LifecycleState::Poisoned}) {
        for (const auto boundary : {
                 DurableBoundary::JournalWritten,
                 DurableBoundary::JournalSynced,
                 DurableBoundary::HeadWritten,
                 DurableBoundary::HeadSynced,
                 DurableBoundary::DirectorySynced,
                 DurableBoundary::ExternalHeadWritten,
                 DurableBoundary::ExternalHeadSynced,
                 DurableBoundary::ExternalDirectorySynced}) {
            const auto edge_number = static_cast<unsigned>(edge);
            const auto boundary_number = static_cast<unsigned>(boundary);
            const auto stem = "external-crash-" +
                std::to_string(edge_number) + "-" +
                std::to_string(boundary_number);
            const auto directory = make_case(root, stem + "-ledger");
            const auto external = make_case(root, stem + "-anchor");
            auto parent = initialize_external(directory, external);
            const auto index = 2000 + edge_number * 10 + boundary_number;
            auto hook = [boundary](DurableBoundary reached) {
                if (reached == boundary) throw NativeRefused();
            };
            std::optional<pid_t> child;
            expect_refused([&] {
                switch (edge) {
                case LifecycleState::Allocated:
                    parent->allocate(
                        InvoiceMaterialAuthority::test_only_mint(*parent,
                            invoice(index, 0x81)), hook);
                    break;
                case LifecycleState::Exported: {
                    auto allocated = parent->allocate(
                        InvoiceMaterialAuthority::test_only_mint(*parent,
                            invoice(index, 0x82)));
                    parent->export_to_owner(std::move(allocated), hook);
                    break;
                }
                case LifecycleState::Accepted: {
                    auto split = parent->export_to_owner(parent->allocate(
                        InvoiceMaterialAuthority::test_only_mint(*parent,
                            invoice(index, 0x83))));
                    auto launched = launch_owner(std::move(split), executable);
                    child = launched.child;
                    parent->accept_from_owner(
                        std::move(launched.residual), hook);
                    break;
                }
                case LifecycleState::Consumed: {
                    auto accepted = accept_route(
                        *parent,
                        parent->export_to_owner(parent->allocate(
                            InvoiceMaterialAuthority::test_only_mint(*parent,
                                invoice(index, 0x84)))),
                        executable);
                    parent->consume(std::move(accepted), hook);
                    break;
                }
                case LifecycleState::Poisoned: {
                    auto allocated = parent->allocate(
                        InvoiceMaterialAuthority::test_only_mint(*parent,
                            invoice(index, 0x85)));
                    parent->poison(std::move(allocated), hook);
                    break;
                }
                }
            });
            if (child.has_value()) {
                int status = 0;
                assert(::waitpid(*child, &status, 0) == *child &&
                       WIFEXITED(status) && WEXITSTATUS(status) == 0);
            }
            parent.reset();
            const bool external_commit_reached =
                boundary_number >= static_cast<unsigned>(
                    DurableBoundary::ExternalHeadWritten);
            const bool terminal = edge == LifecycleState::Consumed ||
                                  edge == LifecycleState::Poisoned;
            if (external_commit_reached && terminal) {
                auto reopened = reopen_external(directory, external);
                assert(reopened->test_only_state(index) == edge);
            } else {
                expect_refused([&] {
                    (void)reopen_external(directory, external);
                });
            }
        }
    }
}

void external_rollback_and_cross_trial(const std::filesystem::path& root) {
    const auto directory = make_case(root, "external-rollback-ledger");
    const auto external = make_case(root, "external-rollback-anchor");
    auto parent = initialize_external(directory, external);
    parent->poison(parent->allocate(
        InvoiceMaterialAuthority::test_only_mint(*parent, invoice(80, 0x91))));
    parent.reset();

    const auto journal_prior = file_bytes(directory / "journal.bin");
    const auto heads_prior = file_bytes(directory / "heads.bin");
    const auto anchor_prior = file_bytes(external / "latest-head.bin");

    parent = reopen_external(directory, external);
    parent->poison(parent->allocate(
        InvoiceMaterialAuthority::test_only_mint(*parent, invoice(81, 0x92))));
    parent.reset();

    replace_file_bytes(directory / "journal.bin", journal_prior);
    replace_file_bytes(directory / "heads.bin", heads_prior);
    expect_refused([&] { (void)reopen_external(directory, external); });

    // Restore the local latest state from a separate genuine run, then roll
    // back only the independent anchor. Either side lagging must refuse.
    const auto directory2 = make_case(root, "external-anchor-rollback-ledger");
    const auto external2 = make_case(root, "external-anchor-rollback-anchor");
    auto parent2 = initialize_external(directory2, external2);
    const auto anchor2_prior = file_bytes(external2 / "latest-head.bin");
    parent2->poison(parent2->allocate(
        InvoiceMaterialAuthority::test_only_mint(
            *parent2, invoice(82, 0x93))));
    parent2.reset();
    replace_file_bytes(external2 / "latest-head.bin", anchor2_prior);
    expect_refused([&] { (void)reopen_external(directory2, external2); });

    // An anchor is trial-bound and cannot authorize another RunBinding.
    auto descriptors = V3NativeAuthorityTestSetup::open_descriptors(
        directory2.c_str(), ledger_key());
    expect_refused([&] {
        auto updater = V3NativeAuthorityTestSetup::open_external_latest_head(
            external2.c_str(), binding(1), ledger_key());
        (void)V3NativeAuthorityBridge::test_only_open_existing(
            std::move(descriptors), std::move(updater), binding(1));
    });

    (void)anchor_prior;
}

void external_tamper_mode_inode_and_colocation_refuse(
        const std::filesystem::path& root) {
    {
        const auto directory = make_case(root, "external-tamper-ledger");
        const auto external = make_case(root, "external-tamper-anchor");
        auto parent = initialize_external(directory, external);
        parent->poison(parent->allocate(
            InvoiceMaterialAuthority::test_only_mint(*parent, invoice(90, 0xa1))));
        parent.reset();
        const auto path = external / "latest-head.bin";
        const int fd = ::open(path.c_str(), O_RDWR | O_CLOEXEC);
        assert(fd >= 0);
        unsigned char byte = 0;
        assert(::pread(fd, &byte, 1, 120) == 1);
        byte ^= 0x01;
        assert(::pwrite(fd, &byte, 1, 120) == 1 && ::fsync(fd) == 0 &&
               ::close(fd) == 0);
        expect_refused([&] { (void)reopen_external(directory, external); });
    }
    {
        const auto directory = make_case(root, "external-truncate-ledger");
        const auto external = make_case(root, "external-truncate-anchor");
        auto parent = initialize_external(directory, external);
        parent->poison(parent->allocate(
            InvoiceMaterialAuthority::test_only_mint(*parent, invoice(91, 0xa2))));
        parent.reset();
        const auto path = external / "latest-head.bin";
        const int fd = ::open(path.c_str(), O_RDWR | O_CLOEXEC);
        assert(fd >= 0);
        struct stat state{};
        assert(::fstat(fd, &state) == 0 && state.st_size > 1 &&
               ::ftruncate(fd, state.st_size - 1) == 0 &&
               ::fsync(fd) == 0 && ::close(fd) == 0);
        expect_refused([&] { (void)reopen_external(directory, external); });
    }
    {
        const auto directory = make_case(root, "external-mode-ledger");
        const auto external = make_case(root, "external-mode-anchor");
        auto parent = initialize_external(directory, external);
        parent.reset();
        assert(::chmod((external / "latest-head.bin").c_str(), 0644) == 0);
        expect_refused([&] { (void)reopen_external(directory, external); });
    }
    {
        const auto directory = make_case(root, "external-lock-ledger");
        const auto external = make_case(root, "external-lock-anchor");
        auto parent = initialize_external(directory, external);
        expect_refused([&] {
            (void)V3NativeAuthorityTestSetup::open_external_latest_head(
                external.c_str(), binding(), ledger_key());
        });
        parent.reset();
    }
    {
        const auto directory = make_case(root, "external-inode-ledger");
        const auto external = make_case(root, "external-inode-anchor");
        auto parent = initialize_external(directory, external);
        const auto replacement = external / "replacement";
        const int fd = ::open(replacement.c_str(),
                              O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        assert(fd >= 0 && ::fsync(fd) == 0 && ::close(fd) == 0);
        assert(::rename(replacement.c_str(),
                        (external / "latest-head.bin").c_str()) == 0);
        expect_refused([&] {
            parent->poison(parent->allocate(
                InvoiceMaterialAuthority::test_only_mint(*parent,
                    invoice(92, 0xa3))));
        });
    }
    {
        const auto directory = make_case(root, "external-colocated");
        expect_refused([&] {
            (void)V3NativeAuthorityTestSetup::
                initialize_fresh_with_external_head(
                    directory.c_str(), directory.c_str(), binding(),
                    ledger_key());
        });
    }
}

void tamper_mode_and_inode(const std::filesystem::path& root) {
    {
        const auto directory = make_case(root, "tamper");
        auto parent = initialize(directory);
        parent->poison(parent->allocate(
            InvoiceMaterialAuthority::test_only_mint(*parent, invoice(20, 0x61))));
        const auto latest = parent->test_only_latest();
        parent.reset();
        const int fd = ::open(
            (directory / "journal.bin").c_str(), O_RDWR | O_CLOEXEC);
        assert(fd >= 0);
        unsigned char byte = 0;
        assert(::pread(fd, &byte, 1, 45) == 1);
        byte ^= 1;
        assert(::pwrite(fd, &byte, 1, 45) == 1 && ::fsync(fd) == 0);
        assert(::close(fd) == 0);
        auto descriptors = V3NativeAuthorityTestSetup::open_descriptors(
            directory.c_str(), ledger_key());
        auto authority = LatestHeadAuthority::test_only_mint(
            binding(), latest.first, latest.second);
        expect_refused([&] {
            V3NativeAuthorityBridge::test_only_open_existing(
                std::move(descriptors), std::move(authority), binding());
        });
    }
    {
        const auto directory = make_case(root, "mode");
        auto parent = initialize(directory);
        const auto latest = parent->test_only_latest();
        parent.reset();
        assert(::chmod((directory / "heads.bin").c_str(), 0644) == 0);
        auto descriptors = V3NativeAuthorityTestSetup::open_descriptors(
            directory.c_str(), ledger_key());
        auto authority = LatestHeadAuthority::test_only_mint(
            binding(), latest.first, latest.second);
        expect_refused([&] {
            V3NativeAuthorityBridge::test_only_open_existing(
                std::move(descriptors), std::move(authority), binding());
        });
    }
    {
        const auto directory = make_case(root, "inode");
        auto parent = initialize(directory);
        const auto replacement = directory / "replacement";
        const int fd = ::open(replacement.c_str(),
                              O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        assert(fd >= 0 && ::fsync(fd) == 0 && ::close(fd) == 0);
        assert(::rename(replacement.c_str(),
                        (directory / "journal.bin").c_str()) == 0);
        expect_refused([&] {
            parent->allocate(InvoiceMaterialAuthority::test_only_mint(*parent,
                invoice(21, 0x62)));
        });
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--owner-accept") {
        try {
            owner_accept_from_fixed_fds();
            return 0;
        } catch (...) {
            return 1;
        }
    }
    assert(argc == 2);
    const std::filesystem::path root(argv[1]);
    assert(root.is_absolute());

    static_assert(!std::is_copy_constructible_v<InvoiceMaterialAuthority>);
    static_assert(!std::is_copy_constructible_v<LatestHeadAuthority>);
    static_assert(!std::is_copy_constructible_v<
                  ExternalLatestHeadUpdaterAuthority>);
    static_assert(!std::is_copy_constructible_v<
                  ParentLedgerDescriptorsAuthority>);
    static_assert(!std::is_copy_constructible_v<OwnerOfferAuthority>);
    static_assert(!std::is_copy_constructible_v<ParentOfferResidual>);
    static_assert(!std::is_copy_constructible_v<AcceptedInvoiceAuthority>);
    static_assert(kV3NativeAuthoritySourceStatus.parent_owned_descriptors);
    static_assert(kV3NativeAuthoritySourceStatus.sealed_invoice208_fd);
    static_assert(kV3NativeAuthoritySourceStatus.exact_run_binding_fd);
    static_assert(kV3NativeAuthoritySourceStatus.one_use_os_accept_capability);
    static_assert(kV3NativeAuthoritySourceStatus.authenticated_append_only_edges);
    static_assert(kV3NativeAuthoritySourceStatus.file_and_directory_fsync);
    static_assert(kV3NativeAuthoritySourceStatus.exact_inode_mode_checks);
    static_assert(kV3NativeAuthoritySourceStatus.missing_latest_head_refuses);
    static_assert(kV3NativeAuthoritySourceStatus.external_latest_head_updater);
    static_assert(kV3NativeAuthoritySourceStatus.
                  external_head_file_and_directory_fsync);
    static_assert(kV3NativeAuthoritySourceStatus.
                  external_one_side_rollback_refusal);
    static_assert(kV3NativeAuthoritySourceStatus.
                  external_cross_trial_refusal);
    static_assert(!kV3NativeAuthoritySourceStatus.
                  external_joint_rollback_protection_integrated);
    static_assert(kV3NativeAuthoritySourceStatus.
                  typed_lifecycle_controller_source_seam);
    static_assert(kV3NativeAuthoritySourceStatus.
                  production_open_requires_lifecycle_controller);
    static_assert(kV3NativeAuthoritySourceStatus.
                  invoice_material_bound_to_parent_history);
    static_assert(kV3NativeAuthoritySourceStatus.
                  per_open_instance_bound_lifecycle);
    static_assert(kV3NativeAuthoritySourceStatus.
                  opaque_source_generation_bound_through_accept);
    static_assert(!kV3NativeAuthoritySourceStatus.
                  production_ledger_descriptor_minter_available);
    static_assert(!kV3NativeAuthoritySourceStatus.
                  production_external_updater_minter_available);
    static_assert(!kV3NativeAuthoritySourceStatus.
                  production_invoice_material_minter_available);
    static_assert(!kV3NativeAuthoritySourceStatus.
                  production_accepted_history_minter_available);
    static_assert(!kV3NativeAuthoritySourceStatus.
                  lifecycle_controller_minter_integrated);
    static_assert(!kV3NativeAuthoritySourceStatus.
                  selected_owner_launcher_integrated);
    static_assert(!kV3NativeAuthoritySourceStatus.
                  accepted_public_history_join_integrated);
    static_assert(!kV3NativeAuthoritySourceStatus.configured);

    validate_measurement_run_binding(binding());
    happy_path(root, argv[0]);
    external_head_happy_path(root, argv[0]);
    poison_paths(root, argv[0]);
    cross_parent_material_refuses(root);
    missing_latest_and_cross_binding(root);
    crash_boundaries(root, argv[0]);
    external_crash_boundaries(root, argv[0]);
    external_rollback_and_cross_trial(root);
    external_tamper_mode_inode_and_colocation_refuse(root);
    tamper_mode_and_inode(root);
    return 0;
}
