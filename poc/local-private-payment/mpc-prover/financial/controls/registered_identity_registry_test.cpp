#include "../registered_identity_registry.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <concepts>
#include <filesystem>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace kpi::mpc::financial::identity_registry;

namespace {
Digest id(unsigned value) {
    Digest result{};
    result[0] = static_cast<unsigned char>(value);
    result[1] = static_cast<unsigned char>(value >> 8);
    result[31] = static_cast<unsigned char>(value ^ 0xa5U);
    return result;
}

Authority authority() {
    return Authority{
        .registration = id(1),
        .service = id(2),
        .source = id(3),
        .build = id(4),
        .aborted_runs = {mandatory_aborted_run()},
    };
}

Selection selection(unsigned base) {
    return Selection{
        .run = id(base),
        .trial = id(base + 1),
        .attempt = id(base + 2),
        .cohort = id(base + 3),
        .accepted_head = id(base + 4),
        .owner_contracts = {id(base + 5), id(base + 6), id(base + 7)},
    };
}

struct Root {
    std::filesystem::path path;
    std::filesystem::path journal;
    std::filesystem::path anchor;
    Root() {
        std::array<char, 80> pattern{};
        const std::string prefix = "/tmp/kpb-identity-registry-XXXXXX";
        std::copy(prefix.begin(), prefix.end(), pattern.begin());
        char* made = ::mkdtemp(pattern.data());
        assert(made != nullptr);
        path = std::filesystem::path(made);
        journal = path / "journal";
        anchor = path / "anchor";
        assert(std::filesystem::create_directory(journal));
        assert(std::filesystem::create_directory(anchor));
        assert(::chmod(journal.c_str(), 0700) == 0);
        assert(::chmod(anchor.c_str(), 0700) == 0);
    }
    ~Root() { std::filesystem::remove_all(path); }
};

template<class Callable>
void expect_refusal(Callable&& callable) {
    bool refused = false;
    try { callable(); } catch (const Refused&) { refused = true; }
    assert(refused);
}

std::vector<unsigned char> read_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void write_file(const std::filesystem::path& path,
                const std::vector<unsigned char>& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    output.close();
    assert(output.good());
    assert(::chmod(path.c_str(), 0600) == 0);
}

template<class T>
concept HasRunGetter = requires(const T& value) { value.run(); };
template<class T>
concept HasOwnerGetter = requires(const T& value) { value.owner_contracts(); };
template<class T>
concept HasPrivateBodyGetter = requires(const T& value) { value.private_body(); };

void fresh_restart() {
    static_assert(!std::copy_constructible<ConsumedIdentity>);
    static_assert(!std::move_constructible<ConsumedIdentity>);
    static_assert(!HasRunGetter<ConsumedIdentity>);
    static_assert(!HasOwnerGetter<ConsumedIdentity>);
    static_assert(!HasPrivateBodyGetter<ConsumedIdentity>);

    Root root;
    const auto auth = authority();
    const auto first = selection(0x100);
    Digest first_checkpoint{};
    {
        auto registry = Registry::initialize_fresh_unfunded(
            root.journal, root.anchor, auth);
        const auto before = registry.snapshot();
        assert(before.authority_identity == authority_identity(auth));
        assert(before.sequence == 0);
        auto consumed = registry.consume(first);
        const auto& receipt = consumed.public_receipt();
        assert(receipt.authority_identity == authority_identity(auth));
        assert(receipt.selection_identity == selection_identity(first));
        assert(receipt.sequence == 1);
        assert(receipt.checkpoint != Digest{});
        assert(receipt.consumed_set_identity != Digest{});
        first_checkpoint = receipt.checkpoint;
    }
    {
        auto registry = Registry::open_existing(root.journal, root.anchor, auth);
        const auto restarted = registry.snapshot();
        assert(restarted.sequence == 1);
        assert(restarted.checkpoint == first_checkpoint);
        auto second = registry.consume(selection(0x200));
        assert(second.public_receipt().sequence == 2);
        assert(second.public_receipt().checkpoint != first_checkpoint);
    }
}

void reuse_and_omission() {
    Root root;
    const auto auth = authority();
    auto registry = Registry::initialize_fresh_unfunded(root.journal, root.anchor, auth);
    const auto used = selection(0x300);
    (void)registry.consume(used);

    for (unsigned field = 0; field < 8; ++field) {
        auto candidate = selection(0x400 + field * 0x20);
        if (field == 0) candidate.run = used.run;
        if (field == 1) candidate.trial = used.trial;
        if (field == 2) candidate.attempt = used.attempt;
        if (field == 3) candidate.cohort = used.cohort;
        if (field == 4) candidate.accepted_head = used.accepted_head;
        if (field >= 5) candidate.owner_contracts[field - 5] = used.owner_contracts[field - 5];
        expect_refusal([&] { (void)registry.consume(candidate); });
    }

    auto cross_kind = selection(0x600);
    cross_kind.run = used.trial;
    expect_refusal([&] { (void)registry.consume(cross_kind); });

    auto duplicate = selection(0x700);
    duplicate.owner_contracts[2] = duplicate.owner_contracts[0];
    expect_refusal([&] { (void)registry.consume(duplicate); });

    for (unsigned field = 0; field < 8; ++field) {
        auto omitted = selection(0x800 + field * 0x20);
        if (field == 0) omitted.run = {};
        if (field == 1) omitted.trial = {};
        if (field == 2) omitted.attempt = {};
        if (field == 3) omitted.cohort = {};
        if (field == 4) omitted.accepted_head = {};
        if (field >= 5) omitted.owner_contracts[field - 5] = {};
        expect_refusal([&] { (void)registry.consume(omitted); });
    }
    assert(registry.snapshot().sequence == 1);
}

void aborted_run() {
    {
        Root root;
        auto missing = authority();
        missing.aborted_runs.clear();
        expect_refusal([&] {
            (void)Registry::initialize_fresh_unfunded(
                root.journal, root.anchor, missing);
        });
    }
    Root root;
    const auto auth = authority();
    auto registry = Registry::initialize_fresh_unfunded(root.journal, root.anchor, auth);
    auto aborted = selection(0x900);
    aborted.run = mandatory_aborted_run();
    expect_refusal([&] { (void)registry.consume(aborted); });
    aborted = selection(0xa00);
    aborted.owner_contracts[1] = mandatory_aborted_run();
    expect_refusal([&] { (void)registry.consume(aborted); });
    assert(registry.snapshot().sequence == 0);
}

void authority_drift() {
    Root root;
    const auto auth = authority();
    {
        auto registry = Registry::initialize_fresh_unfunded(
            root.journal, root.anchor, auth);
        (void)registry.snapshot();
    }
    for (unsigned field = 0; field < 5; ++field) {
        auto changed = auth;
        if (field == 0) changed.registration = id(0xb1);
        if (field == 1) changed.service = id(0xb2);
        if (field == 2) changed.source = id(0xb3);
        if (field == 3) changed.build = id(0xb4);
        if (field == 4) changed.aborted_runs.push_back(id(0xb5));
        if (field == 4) std::sort(changed.aborted_runs.begin(), changed.aborted_runs.end());
        expect_refusal([&] {
            (void)Registry::open_existing(root.journal, root.anchor, changed);
        });
    }
}

void storage_tamper() {
    const auto auth = authority();
    {
        Root root;
        {
            auto registry = Registry::initialize_fresh_unfunded(root.journal, root.anchor, auth);
            (void)registry.snapshot();
        }
        const auto alias = root.path / "journal-hardlink";
        std::filesystem::create_hard_link(root.journal / "journal.bin", alias);
        expect_refusal([&] { (void)Registry::open_existing(root.journal, root.anchor, auth); });
    }
    {
        Root root;
        {
            auto registry = Registry::initialize_fresh_unfunded(root.journal, root.anchor, auth);
            (void)registry.snapshot();
        }
        const auto original = root.journal / "journal.saved";
        std::filesystem::rename(root.journal / "journal.bin", original);
        std::filesystem::create_symlink("journal.saved", root.journal / "journal.bin");
        expect_refusal([&] { (void)Registry::open_existing(root.journal, root.anchor, auth); });
    }
    {
        Root root;
        {
            auto registry = Registry::initialize_fresh_unfunded(root.journal, root.anchor, auth);
            (void)registry.consume(selection(0xc00));
        }
        const auto journal = root.journal / "journal.bin";
        const auto original = read_file(journal);
        auto truncated = original;
        truncated.pop_back();
        write_file(journal, truncated);
        expect_refusal([&] { (void)Registry::open_existing(root.journal, root.anchor, auth); });
        write_file(journal, original);
        auto reopened = Registry::open_existing(root.journal, root.anchor, auth);
        assert(reopened.snapshot().sequence == 1);
    }
    {
        Root root;
        std::vector<unsigned char> old_anchor;
        {
            auto registry = Registry::initialize_fresh_unfunded(root.journal, root.anchor, auth);
            (void)registry.consume(selection(0xd00));
            old_anchor = read_file(root.anchor / "latest.bin");
            (void)registry.consume(selection(0xe00));
        }
        write_file(root.anchor / "latest.bin", old_anchor);
        expect_refusal([&] { (void)Registry::open_existing(root.journal, root.anchor, auth); });
    }
    {
        Root root;
        auto registry = Registry::initialize_fresh_unfunded(root.journal, root.anchor, auth);
        const auto journal = root.journal / "journal.bin";
        const auto saved = root.journal / "journal.old";
        const auto bytes = read_file(journal);
        std::filesystem::rename(journal, saved);
        write_file(journal, bytes);
        expect_refusal([&] { (void)registry.snapshot(); });
    }
    {
        Root root;
        {
            auto registry = Registry::initialize_fresh_unfunded(root.journal, root.anchor, auth);
            (void)registry.consume(selection(0xe80));
        }
        const auto journal = root.journal / "journal.bin";
        const auto bytes = read_file(journal);
        std::filesystem::rename(journal, root.path / "replaced-journal.bin");
        write_file(journal, bytes);
        expect_refusal([&] {
            (void)Registry::open_existing(root.journal, root.anchor, auth);
        });
    }
    {
        Root root;
        {
            auto registry = Registry::initialize_fresh_unfunded(root.journal, root.anchor, auth);
            (void)registry.consume(selection(0xec0));
        }
        const auto anchor = root.anchor / "latest.bin";
        const auto bytes = read_file(anchor);
        std::filesystem::rename(anchor, root.path / "replaced-latest.bin");
        write_file(anchor, bytes);
        expect_refusal([&] {
            (void)Registry::open_existing(root.journal, root.anchor, auth);
        });
    }
    {
        Root root;
        {
            auto registry = Registry::initialize_fresh_unfunded(root.journal, root.anchor, auth);
            (void)registry.snapshot();
        }
        assert(::chmod((root.anchor / "latest.bin").c_str(), 0644) == 0);
        expect_refusal([&] { (void)Registry::open_existing(root.journal, root.anchor, auth); });
    }
}

void crash_boundaries() {
    for (const auto boundary : {WriteBoundary::JournalWritten,
                                WriteBoundary::JournalSynced,
                                WriteBoundary::AnchorWritten,
                                WriteBoundary::AnchorSynced}) {
        Root root;
        const auto auth = authority();
        const auto selected = selection(0xf00 + static_cast<unsigned>(boundary) * 0x20);
        {
            auto registry = Registry::initialize_fresh_unfunded(root.journal, root.anchor, auth);
            expect_refusal([&] {
                (void)registry.consume(selected, [&](WriteBoundary at) {
                    if (at == boundary) throw std::runtime_error("injected crash");
                });
            });
            expect_refusal([&] { (void)registry.snapshot(); });
        }
        if (boundary == WriteBoundary::JournalWritten ||
            boundary == WriteBoundary::JournalSynced) {
            expect_refusal([&] {
                (void)Registry::open_existing(root.journal, root.anchor, auth);
            });
        } else {
            auto restarted = Registry::open_existing(root.journal, root.anchor, auth);
            assert(restarted.snapshot().sequence == 1);
            expect_refusal([&] { (void)restarted.consume(selected); });
        }
    }
}

// Retained negative control: no pair of replayable files can prove its own
// monotonicity. The trusted anchor must therefore live in a protection domain
// that the journal writer/children cannot roll back together with the journal.
void coordinated_rollback_boundary() {
    Root root;
    const auto auth = authority();
    std::vector<unsigned char> journal_after_first;
    std::vector<unsigned char> anchor_after_first;
    {
        auto registry = Registry::initialize_fresh_unfunded(root.journal, root.anchor, auth);
        (void)registry.consume(selection(0x1000));
        journal_after_first = read_file(root.journal / "journal.bin");
        anchor_after_first = read_file(root.anchor / "latest.bin");
        (void)registry.consume(selection(0x1040));
        assert(registry.snapshot().sequence == 2);
    }
    write_file(root.journal / "journal.bin", journal_after_first);
    write_file(root.anchor / "latest.bin", anchor_after_first);
    auto replayed = Registry::open_existing(root.journal, root.anchor, auth);
    assert(replayed.snapshot().sequence == 1);
    const auto status = source_status();
    assert(status.trusted_anchor_required);
    assert(status.coordinated_anchor_rollback_in_scope == false);
    assert(status.registered_driver_configured == false);
    assert(status.launch_authorized == false);
}

void concurrent_consumption() {
    Root root;
    const auto auth = authority();
    auto first = Registry::initialize_fresh_unfunded(root.journal, root.anchor, auth);
    auto second = Registry::open_existing(root.journal, root.anchor, auth);
    const auto selected = selection(0x1100);
    std::atomic<unsigned> succeeded{0};
    std::atomic<unsigned> refused{0};
    const auto consume = [&](Registry& registry) {
        try {
            (void)registry.consume(selected);
            ++succeeded;
        } catch (const Refused&) {
            ++refused;
        }
    };
    std::thread a(consume, std::ref(first));
    std::thread b(consume, std::ref(second));
    a.join();
    b.join();
    assert(succeeded == 1);
    assert(refused == 1);
    assert(first.snapshot().sequence == 1);
    assert(second.snapshot().sequence == 1);
}

int scan_inherited_fds(const std::filesystem::path& journal,
                       const std::filesystem::path& anchor) {
    const std::array targets{journal / "journal.bin", anchor / "latest.bin"};
    std::error_code error;
    for (std::filesystem::directory_iterator it("/proc/self/fd", error), end;
         !error && it != end; it.increment(error)) {
        std::error_code link_error;
        const auto target = std::filesystem::read_symlink(it->path(), link_error);
        if (link_error) continue;
        for (const auto& forbidden : targets)
            if (target == forbidden) return 1;
    }
    return error ? 2 : 0;
}

void exec_child_fd_isolation(const char* executable) {
    Root root;
    const auto auth = authority();
    auto registry = Registry::initialize_fresh_unfunded(root.journal, root.anchor, auth);
    const pid_t child = ::fork();
    assert(child >= 0);
    if (child == 0) {
        ::execl(executable, executable, "scan-inherited-fds",
                root.journal.c_str(), root.anchor.c_str(), nullptr);
        _exit(127);
    }
    int status = 0;
    assert(::waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(registry.snapshot().sequence == 0);
}

void source_boundary() {
    const auto status = source_status();
    assert(status.schema == "kpb-registered-identity-registry-source-only/v1");
    assert(status.status == "UNQUALIFIED_SOURCE_ONLY");
    assert(status.trial03_retrofit_allowed == false);
    assert(status.trusted_anchor_required == true);
    assert(status.coordinated_anchor_rollback_in_scope == false);
    assert(status.direct_accepted_head_integration == false);
    assert(status.selected_configured_build_integration == false);
    assert(status.one_shot_private_intake_integration == false);
    assert(status.registered_driver_configured == false);
    assert(status.launch_authorized == false);
    assert(hex(mandatory_aborted_run()) ==
           "a86414d108d6886768f367a3384fd24de49d4fde7475d8469d92adee29c0e6ab");
}
} // namespace

int main(int argc, char** argv) {
    if (argc == 4 && std::string(argv[1]) == "scan-inherited-fds")
        return scan_inherited_fds(argv[2], argv[3]);
    assert(argc == 2);
    const std::string name(argv[1]);
    if (name == "fresh-restart") fresh_restart();
    else if (name == "reuse-and-omission") reuse_and_omission();
    else if (name == "aborted-run") aborted_run();
    else if (name == "authority-drift") authority_drift();
    else if (name == "storage-tamper") storage_tamper();
    else if (name == "crash-boundaries") crash_boundaries();
    else if (name == "coordinated-rollback-boundary") coordinated_rollback_boundary();
    else if (name == "concurrent-consumption") concurrent_consumption();
    else if (name == "exec-child-fd-isolation") exec_child_fd_isolation(argv[0]);
    else if (name == "source-boundary") source_boundary();
    else assert(false);
}
