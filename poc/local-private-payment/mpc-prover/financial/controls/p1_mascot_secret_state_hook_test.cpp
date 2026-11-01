#include "../../p1_mascot_secret_state_hook.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

namespace state = kpi::mpc::p1_private_state;

namespace kpi::mpc::p1_private_state {

class TestOnlyMascotSecretStateScope final {
    std::unique_ptr<MascotSecretStateHookScope> scope_;
public:
    explicit TestOnlyMascotSecretStateScope(MascotSecretStateHook& hook)
        : scope_(MascotSecretStateScopeFactoryBridge::test_only_install(
              hook, 1, 3, true, "selected-P1",
              "21888242871839275222246405745257275088548364400416034343698204186575808495617")) {}
};

} // namespace kpi::mpc::p1_private_state

namespace {

class Sink final : public state::MascotSecretStateHook {
public:
    std::vector<state::MascotSecretEventKind> kinds;
    std::vector<std::uint64_t> sequences;
    std::vector<std::vector<unsigned char>> encoded;
    std::vector<bool> before_initialized;
    std::vector<bool> after_initialized;
    std::vector<std::vector<unsigned char>> complete_before;
    std::vector<std::vector<unsigned char>> complete_after;
    std::vector<std::vector<unsigned char>> scalar_before;
    std::vector<std::vector<unsigned char>> scalar_after;
    std::vector<std::vector<unsigned char>> prep_scalar_before;
    std::vector<std::vector<unsigned char>> prep_scalar_after;
    std::vector<std::vector<unsigned char>> expected_scalar;
    std::vector<bool> bit_prep_aliases_main;
    std::vector<std::vector<unsigned char>> derived_complete;
    std::vector<state::MascotSecretAbortEventKind> abort_kinds;
    std::vector<std::vector<unsigned char>> encoded_aborts;
    unsigned unavailable{};

    Sink() : MascotSecretStateHook(TestOnlyConstruction{}) {}

    bool record_mascot_secret_event(
            const state::MascotSecretEventView& event) noexcept override {
        try {
            kinds.push_back(event.kind);
            sequences.push_back(event.sequence);
            encoded.push_back(state::encode_mascot_secret_event(event));
            before_initialized.push_back(
                event.complete_key_before_initialized);
            after_initialized.push_back(
                event.complete_key_after_initialized);
            complete_before.emplace_back(
                event.complete_key_before.begin(),
                event.complete_key_before.end());
            complete_after.emplace_back(
                event.complete_key_after.begin(),
                event.complete_key_after.end());
            scalar_before.emplace_back(
                event.scalar_key_before.begin(),
                event.scalar_key_before.end());
            scalar_after.emplace_back(
                event.scalar_key_after.begin(),
                event.scalar_key_after.end());
            prep_scalar_before.emplace_back(
                event.prep_scalar_key_before.begin(),
                event.prep_scalar_key_before.end());
            prep_scalar_after.emplace_back(
                event.prep_scalar_key_after.begin(),
                event.prep_scalar_key_after.end());
            expected_scalar.emplace_back(
                event.expected_scalar_key.begin(),
                event.expected_scalar_key.end());
            bit_prep_aliases_main.push_back(
                event.bit_prep_aliases_main);
            derived_complete.emplace_back(
                event.derived_complete_key.begin(),
                event.derived_complete_key.end());
            return true;
        } catch (...) {
            return false;
        }
    }

    bool record_mascot_secret_abort_event(
            const state::MascotSecretAbortEventView& event)
            noexcept override {
        try {
            abort_kinds.push_back(event.kind);
            encoded_aborts.push_back(
                state::encode_mascot_secret_abort_event(event));
            return true;
        } catch (...) {
            return false;
        }
    }

    void mascot_secret_unavailable_noexcept() noexcept override {
        ++unavailable;
    }
};

state::MascotFileMetadataView metadata(std::uint64_t size) {
    return {
        .present = true,
        .device = 11,
        .inode = 22,
        .mode = 0100600,
        .uid = 1000,
        .gid = 1000,
        .link_count = 1,
        .size = size,
        .mtime_seconds = 123,
        .mtime_nanoseconds = 456,
        .ctime_seconds = 124,
        .ctime_nanoseconds = 789,
    };
}

state::MascotFileSnapshotView captured_file(
        std::span<const unsigned char> bytes, bool write) {
    const auto meta = metadata(bytes.size());
    return {
        .result = state::MascotFileResult::Captured,
        .operation_errno = 0,
        .open_flags = write ? 0x80241U : 0x80000U,
        .no_follow = true,
        .bytes_transferred = bytes.size(),
        .parent_directory_result = state::MascotStepResult::NotAttempted,
        .parent_directory_errno = 0,
        .fsync_result = write ? state::MascotStepResult::Succeeded
                              : state::MascotStepResult::NotAttempted,
        .fsync_errno = 0,
        .rename_result = state::MascotStepResult::NotAttempted,
        .rename_errno = 0,
        .unlink_result = state::MascotStepResult::NotAttempted,
        .unlink_errno = 0,
        .path_lstat_before = meta,
        .descriptor_before = meta,
        .descriptor_after = meta,
        .path_lstat_after = meta,
        .reopened_descriptor = meta,
        .exact_file_bytes = bytes,
    };
}

state::MascotFileSnapshotView captured_prep_file(
        std::span<const unsigned char> bytes) {
    auto result = captured_file(bytes, true);
    result.parent_directory_result = state::MascotStepResult::Succeeded;
    return result;
}

state::MascotFileSnapshotView missing_file() {
    return {
        .result = state::MascotFileResult::Missing,
        .operation_errno = 2,
        .open_flags = 0x80000U,
        .no_follow = true,
        .bytes_transferred = 0,
        .parent_directory_result = state::MascotStepResult::NotAttempted,
        .parent_directory_errno = 0,
        .fsync_result = state::MascotStepResult::NotAttempted,
        .rename_result = state::MascotStepResult::NotAttempted,
        .unlink_result = state::MascotStepResult::NotAttempted,
        .path_lstat_before = {},
        .descriptor_before = {},
        .descriptor_after = {},
        .path_lstat_after = {},
        .reopened_descriptor = {},
        .exact_file_bytes = {},
    };
}

state::MascotFileSnapshotView partial_prep_file(
        std::span<const unsigned char> prefix) {
    auto result = captured_prep_file(prefix);
    result.result = state::MascotFileResult::Partial;
    result.operation_errno = 5;
    result.fsync_result = state::MascotStepResult::NotAttempted;
    return result;
}

constexpr std::string_view domain =
    "Share-gfp-256-specification-checksum";
constexpr std::string_view path =
    "Player-Data/Mascot-Secrets-p-256-checksum-P1-3";
constexpr std::string_view prep_path =
    "Player-Data/3-p-256//Player-MAC-Keys-p-P1";

std::span<const unsigned char> default_complete_key() {
    static constexpr unsigned char packed[]{0};
    return packed;
}

std::span<const unsigned char> default_prep_scalar() {
    static constexpr unsigned char packed[]{0xa0};
    return packed;
}

std::span<const unsigned char> default_online_scalar() {
    static constexpr unsigned char packed[]{0xa0};
    return packed;
}

bool scalar_state_begin(
        std::span<const unsigned char> prep = default_prep_scalar(),
        std::span<const unsigned char> online = default_online_scalar()) {
    return state::MascotSecretStateSourceBridge::scalar_state_begin(
        domain, path, 1000, 4, 40, true, false, prep, online);
}

bool setup_with_state(
        bool initialized, std::span<const unsigned char> key,
        std::span<const unsigned char> prep = default_prep_scalar(),
        std::span<const unsigned char> online = default_online_scalar()) {
    if (!scalar_state_begin(prep, online)) return false;
    return state::MascotSecretStateSourceBridge::setup_begin(
        domain, path, 1000, 4, 40, true, false, initialized, key);
}

bool setup() { return setup_with_state(false, default_complete_key()); }

void expect_sequence(const Sink& sink) {
    for (std::size_t index = 0; index < sink.sequences.size(); ++index)
        assert(sink.sequences[index] == index + 1);
}

void finish_static_reuse() {
    Sink sink;
    const std::vector<unsigned char> complete{1, 2, 3};
    const std::vector<unsigned char> scalar{9, 8};
    {
        state::TestOnlyMascotSecretStateScope scope(sink);
        assert(setup_with_state(true, complete, scalar, scalar));
        assert(state::MascotSecretStateSourceBridge::static_installed(
            true, complete, scalar, scalar, scalar));
        assert(state::MascotSecretStateSourceBridge::teardown(
            true, complete, scalar, false, default_complete_key(), scalar,
            scalar, scalar));
    }
    assert(sink.unavailable == 0);
    assert((sink.kinds == std::vector{
        state::MascotSecretEventKind::ScalarStateBegin,
        state::MascotSecretEventKind::SetupBegin,
        state::MascotSecretEventKind::StaticInstalled,
        state::MascotSecretEventKind::Teardown}));
    const std::string encoded_prefix(
        sink.encoded.front().begin(), sink.encoded.front().begin() +
            state::MASCOT_SECRET_EVENT_ENCODING_DOMAIN.size());
    assert(encoded_prefix == state::MASCOT_SECRET_EVENT_ENCODING_DOMAIN);
    assert(encoded_prefix != "KPI_P1_MASCOT_SECRET_STATE_V1\n");
    expect_sequence(sink);
}

void finish_root_abort_prefix() {
    Sink sink;
    const std::vector<unsigned char> complete{1, 2, 3};
    const std::vector<unsigned char> scalar{9, 8};
    {
        state::TestOnlyMascotSecretStateScope scope(sink);
        assert(setup_with_state(true, complete, scalar, scalar));
        assert(state::MascotSecretStateSourceBridge::static_installed(
            true, complete, scalar, scalar, scalar));
        auto before = metadata(3);
        assert(state::MascotSecretStateSourceBridge::
            abort_cache_unlink_noexcept(
                state::MascotSecretAbortClass::MacCheckFailure,
                path, true, 0, before, {}));
        assert(state::MascotSecretStateSourceBridge::teardown(
            true, complete, scalar, false, default_complete_key(), scalar,
            scalar, scalar));
    }
    assert(sink.unavailable == 0);
    assert((sink.abort_kinds == std::vector{
        state::MascotSecretAbortEventKind::CacheUnlink,
        state::MascotSecretAbortEventKind::Teardown,
        state::MascotSecretAbortEventKind::AbortTerminal}));
    assert(sink.encoded_aborts.size() == 3);
    const std::string prefix(
        sink.encoded_aborts.front().begin(),
        sink.encoded_aborts.front().begin() +
            state::MASCOT_SECRET_ABORT_EVENT_ENCODING_DOMAIN.size());
    assert(prefix == state::MASCOT_SECRET_ABORT_EVENT_ENCODING_DOMAIN);
    assert(prefix != state::MASCOT_SECRET_EVENT_ENCODING_DOMAIN);
}

void finish_cache_hit() {
    Sink sink;
    const std::vector<unsigned char> file{8, 0, 0, 0, 0, 0, 0, 0,
                                          1, 2, 3, 4, 5, 6, 7, 8};
    const std::vector<unsigned char> loaded{1, 2, 3};
    const std::vector<unsigned char> after_file_fresh{4, 5, 6};
    const std::vector<unsigned char> after_bit_fresh{7, 8, 9};
    const auto& installed = after_bit_fresh;
    const std::vector<unsigned char> scalar{10, 11};
    const std::vector<unsigned char> prep_file{3, '\n', 10, 11};
    {
        state::TestOnlyMascotSecretStateScope scope(sink);
        assert(setup());
        assert(state::MascotSecretStateSourceBridge::cache_opened(
            path, captured_file(file, false)));
        assert(state::MascotSecretStateSourceBridge::cache_local_validation(
            state::MascotStepResult::Succeeded, true, loaded, {}));
        assert(state::MascotSecretStateSourceBridge::cache_peer_validation(
            state::MascotStepResult::Succeeded, {}));
        assert(state::MascotSecretStateSourceBridge::write_candidate(
            true, loaded, true, after_file_fresh, file));
        assert(state::MascotSecretStateSourceBridge::writeback(
            path, state::MascotStepResult::Succeeded,
            captured_file(file, true), {}));
        assert(state::MascotSecretStateSourceBridge::prep_static_installed(
            default_prep_scalar(), scalar, scalar));
        assert(state::MascotSecretStateSourceBridge::prep_mac_file_write(
            prep_path, state::MascotStepResult::Succeeded,
            captured_prep_file(prep_file), prep_file, {}));
        assert(state::MascotSecretStateSourceBridge::bit_prep_derived(
            after_file_fresh, after_bit_fresh, after_bit_fresh, true));
        assert(state::MascotSecretStateSourceBridge::static_installed(
            true, installed, default_online_scalar(), scalar, scalar));
        assert(state::MascotSecretStateSourceBridge::teardown(
            true, installed, scalar, false, default_complete_key(), scalar,
            scalar, scalar));
    }
    assert(sink.unavailable == 0);
    assert(std::find(sink.kinds.begin(), sink.kinds.end(),
                     state::MascotSecretEventKind::Regeneration) ==
           sink.kinds.end());
    assert(sink.kinds.size() == 12);
    assert(sink.kinds[9] == state::MascotSecretEventKind::BitPrepDerived);
    assert(sink.bit_prep_aliases_main[9]);
    assert(sink.derived_complete[9] == after_bit_fresh);
    expect_sequence(sink);
}

void finish_regeneration() {
    Sink sink;
    // The source branch treats the zero scalar as uninitialized, but live
    // OTTripleSetup bytes still have to survive the exact pre-state capture.
    const std::vector<unsigned char> zero_scalar_with_ot{0, 0xaa, 0xbb};
    const std::vector<unsigned char> rejected_loaded{0, 0xcc};
    const std::vector<unsigned char> generated{3, 1, 4};
    const std::vector<unsigned char> after_file_fresh{1, 5, 9};
    const std::vector<unsigned char> after_bit_fresh{2, 7, 1};
    const std::vector<unsigned char> file{3, 0, 0, 0, 0, 0, 0, 0,
                                          2, 6, 5};
    const auto& installed = after_bit_fresh;
    const std::vector<unsigned char> scalar{9, 3};
    const std::vector<unsigned char> prep_file{3, '\n', 9, 3};
    {
        state::TestOnlyMascotSecretStateScope scope(sink);
        assert(setup_with_state(false, zero_scalar_with_ot));
        assert(state::MascotSecretStateSourceBridge::cache_opened(
            path, missing_file()));
        assert(state::MascotSecretStateSourceBridge::cache_local_validation(
            state::MascotStepResult::Failed, false,
            rejected_loaded, "ENOENT"));
        assert(state::MascotSecretStateSourceBridge::cache_peer_validation(
            state::MascotStepResult::Succeeded, {}));
        assert(state::MascotSecretStateSourceBridge::regeneration(
            true, generated));
        assert(state::MascotSecretStateSourceBridge::write_candidate(
            true, generated, true, after_file_fresh, file));
        assert(state::MascotSecretStateSourceBridge::writeback(
            path, state::MascotStepResult::Succeeded,
            captured_file(file, true), {}));
        assert(state::MascotSecretStateSourceBridge::prep_static_installed(
            default_prep_scalar(), scalar, scalar));
        assert(state::MascotSecretStateSourceBridge::prep_mac_file_write(
            prep_path, state::MascotStepResult::Succeeded,
            captured_prep_file(prep_file), prep_file, {}));
        assert(state::MascotSecretStateSourceBridge::bit_prep_derived(
            after_file_fresh, after_bit_fresh, after_bit_fresh, true));
        assert(state::MascotSecretStateSourceBridge::static_installed(
            true, installed, default_online_scalar(), scalar, scalar));
        assert(state::MascotSecretStateSourceBridge::teardown(
            true, installed, scalar, false, default_complete_key(), scalar,
            scalar, scalar));
    }
    assert(sink.unavailable == 0);
    assert(sink.kinds.size() == 13);
    assert(sink.kinds[5] == state::MascotSecretEventKind::Regeneration);
    assert(!sink.before_initialized.at(1));
    assert(sink.complete_before.at(1) == zero_scalar_with_ot);
    assert(!sink.after_initialized.at(3));
    assert(sink.complete_after.at(3) == rejected_loaded);
    expect_sequence(sink);
}

void persistent_two_round_scalar_correspondence() {
    Sink sink;
    const std::vector<unsigned char> alpha{0xd1, 0xd2};
    const std::vector<unsigned char> generated{1, 2, 3};
    const std::vector<unsigned char> file_fresh_r1{4, 5, 6};
    const std::vector<unsigned char> bit_fresh_r1{7, 8, 9};
    const std::vector<unsigned char> file_r1{
        1, 0, 0, 0, 0, 0, 0, 0, 1};
    const std::vector<unsigned char> prep_file{'3', '\n', 0xd1, 0xd2};
    {
        state::TestOnlyMascotSecretStateScope scope(sink);
        assert(setup());
        assert(state::MascotSecretStateSourceBridge::cache_opened(
            path, missing_file()));
        assert(state::MascotSecretStateSourceBridge::cache_local_validation(
            state::MascotStepResult::Failed, false,
            default_complete_key(), "missing"));
        assert(state::MascotSecretStateSourceBridge::cache_peer_validation(
            state::MascotStepResult::Succeeded, {}));
        assert(state::MascotSecretStateSourceBridge::regeneration(
            true, generated));
        assert(state::MascotSecretStateSourceBridge::write_candidate(
            true, generated, true, file_fresh_r1, file_r1));
        assert(state::MascotSecretStateSourceBridge::writeback(
            path, state::MascotStepResult::Succeeded,
            captured_file(file_r1, true), {}));
        assert(state::MascotSecretStateSourceBridge::prep_static_installed(
            default_prep_scalar(), alpha, alpha));
        assert(state::MascotSecretStateSourceBridge::prep_mac_file_write(
            prep_path, state::MascotStepResult::Succeeded,
            captured_prep_file(prep_file), prep_file, {}));
        assert(state::MascotSecretStateSourceBridge::bit_prep_derived(
            file_fresh_r1, bit_fresh_r1, bit_fresh_r1, true));
        assert(state::MascotSecretStateSourceBridge::static_installed(
            true, bit_fresh_r1, default_online_scalar(), alpha, alpha));
        assert(state::MascotSecretStateSourceBridge::teardown(
            true, bit_fresh_r1, alpha, false, default_complete_key(), alpha,
            alpha, alpha));
    }

    const std::vector<unsigned char> loaded_r2{10, 11, 12};
    const std::vector<unsigned char> file_fresh_r2{13, 14, 15};
    const std::vector<unsigned char> bit_fresh_r2{16, 17, 18};
    const std::vector<unsigned char> file_r2{
        1, 0, 0, 0, 0, 0, 0, 0, 2};
    const std::size_t round_two_begin = sink.kinds.size();
    assert(round_two_begin == 13);
    {
        state::TestOnlyMascotSecretStateScope scope(sink);
        assert(setup_with_state(
            false, default_complete_key(), alpha, alpha));
        assert(state::MascotSecretStateSourceBridge::cache_opened(
            path, captured_file(file_r2, false)));
        assert(state::MascotSecretStateSourceBridge::cache_local_validation(
            state::MascotStepResult::Succeeded, true, loaded_r2, {}));
        assert(state::MascotSecretStateSourceBridge::cache_peer_validation(
            state::MascotStepResult::Succeeded, {}));
        assert(state::MascotSecretStateSourceBridge::write_candidate(
            true, loaded_r2, true, file_fresh_r2, file_r2));
        assert(state::MascotSecretStateSourceBridge::writeback(
            path, state::MascotStepResult::Succeeded,
            captured_file(file_r2, true), {}));
        assert(state::MascotSecretStateSourceBridge::prep_static_installed(
            alpha, alpha, alpha));
        assert(state::MascotSecretStateSourceBridge::prep_mac_file_write(
            prep_path, state::MascotStepResult::Succeeded,
            captured_prep_file(prep_file), prep_file, {}));
        assert(state::MascotSecretStateSourceBridge::bit_prep_derived(
            file_fresh_r2, bit_fresh_r2, bit_fresh_r2, true));
        assert(state::MascotSecretStateSourceBridge::static_installed(
            true, bit_fresh_r2, alpha, alpha, alpha));
        assert(state::MascotSecretStateSourceBridge::teardown(
            true, bit_fresh_r2, alpha, false, default_complete_key(), alpha,
            alpha, alpha));
    }
    assert(sink.unavailable == 0);
    assert(sink.kinds.size() == 25);
    assert(sink.kinds[round_two_begin] ==
        state::MascotSecretEventKind::ScalarStateBegin);
    assert(sink.prep_scalar_before[round_two_begin] == alpha);
    assert(sink.scalar_before[round_two_begin] == alpha);
    const std::size_t round_two_prep_static = round_two_begin + 7;
    assert(sink.prep_scalar_before[round_two_prep_static] == alpha);
    assert(sink.prep_scalar_after[round_two_prep_static] == alpha);
    assert(sink.expected_scalar[round_two_prep_static] == alpha);
    const std::size_t round_two_online_static = round_two_begin + 10;
    assert(sink.scalar_before[round_two_online_static] == alpha);
    assert(sink.scalar_after[round_two_online_static] == alpha);
    assert(sink.expected_scalar[round_two_online_static] == alpha);
    for (std::size_t index = 0; index < 13; ++index)
        assert(sink.sequences[index] == index + 1);
    for (std::size_t index = round_two_begin; index < sink.sequences.size();
         ++index)
        assert(sink.sequences[index] == index - round_two_begin + 1);
}

void advance_cache_hit_to_prep_static(
        std::span<const unsigned char> loaded,
        std::span<const unsigned char> after_file_fresh,
        std::span<const unsigned char> file) {
    assert(setup());
    assert(state::MascotSecretStateSourceBridge::cache_opened(
        path, captured_file(file, false)));
    assert(state::MascotSecretStateSourceBridge::cache_local_validation(
        state::MascotStepResult::Succeeded, true, loaded, {}));
    assert(state::MascotSecretStateSourceBridge::cache_peer_validation(
        state::MascotStepResult::Succeeded, {}));
    assert(state::MascotSecretStateSourceBridge::write_candidate(
        true, loaded, true, after_file_fresh, file));
    assert(state::MascotSecretStateSourceBridge::writeback(
        path, state::MascotStepResult::Succeeded,
        captured_file(file, true), {}));
}

void advance_cache_hit_to_bit_edge(
        std::span<const unsigned char> loaded,
        std::span<const unsigned char> after_file_fresh,
        std::span<const unsigned char> file) {
    advance_cache_hit_to_prep_static(loaded, after_file_fresh, file);
    static constexpr unsigned char prep_scalar[]{0xc1};
    static constexpr unsigned char prep_file[]{'3', '\n', 0xc1};
    assert(state::MascotSecretStateSourceBridge::prep_static_installed(
        default_prep_scalar(), prep_scalar, prep_scalar));
    assert(state::MascotSecretStateSourceBridge::prep_mac_file_write(
        prep_path, state::MascotStepResult::Succeeded,
        captured_prep_file(prep_file), prep_file, {}));
}

void bit_prep_edge_hostile_controls() {
    const std::vector<unsigned char> file{
        1, 0, 0, 0, 0, 0, 0, 0, 7};
    const std::vector<unsigned char> loaded{1, 2};
    const std::vector<unsigned char> after_file_fresh{3, 4};
    const std::vector<unsigned char> after_bit_fresh{5, 6};
    const std::vector<unsigned char> substituted{7, 8};
    const std::vector<unsigned char> scalar{9};
    {
        Sink sink;
        state::TestOnlyMascotSecretStateScope scope(sink);
        advance_cache_hit_to_bit_edge(loaded, after_file_fresh, file);
        assert(!state::MascotSecretStateSourceBridge::static_installed(
            true, after_bit_fresh, default_online_scalar(), scalar, scalar));
        assert(sink.unavailable == 1);
    }
    {
        Sink sink;
        state::TestOnlyMascotSecretStateScope scope(sink);
        advance_cache_hit_to_bit_edge(loaded, after_file_fresh, file);
        assert(!state::MascotSecretStateSourceBridge::bit_prep_derived(
            substituted, after_bit_fresh, after_bit_fresh, true));
        assert(sink.unavailable == 1);
    }
    {
        Sink sink;
        state::TestOnlyMascotSecretStateScope scope(sink);
        advance_cache_hit_to_bit_edge(loaded, after_file_fresh, file);
        assert(!state::MascotSecretStateSourceBridge::bit_prep_derived(
            after_file_fresh, after_bit_fresh, after_bit_fresh, false));
        assert(sink.unavailable == 1);
    }
    {
        Sink sink;
        state::TestOnlyMascotSecretStateScope scope(sink);
        advance_cache_hit_to_bit_edge(loaded, after_file_fresh, file);
        assert(!state::MascotSecretStateSourceBridge::bit_prep_derived(
            after_file_fresh, after_bit_fresh, substituted, true));
        assert(sink.unavailable == 1);
    }
    {
        Sink sink;
        state::TestOnlyMascotSecretStateScope scope(sink);
        advance_cache_hit_to_bit_edge(loaded, after_file_fresh, file);
        assert(state::MascotSecretStateSourceBridge::bit_prep_derived(
            after_file_fresh, after_bit_fresh, after_bit_fresh, true));
        assert(!state::MascotSecretStateSourceBridge::bit_prep_derived(
            after_bit_fresh, substituted, substituted, true));
        assert(sink.unavailable == 1);
    }
}

void prep_scalar_and_file_hostile_controls() {
    const std::vector<unsigned char> file{
        1, 0, 0, 0, 0, 0, 0, 0, 7};
    const std::vector<unsigned char> loaded{1, 2};
    const std::vector<unsigned char> after_file_fresh{3, 4};
    const std::vector<unsigned char> prep_scalar{5, 6};
    const std::vector<unsigned char> substituted{7, 8};
    const std::vector<unsigned char> prep_file{'3', '\n', 5, 6};
    {
        Sink sink;
        state::TestOnlyMascotSecretStateScope scope(sink);
        advance_cache_hit_to_prep_static(loaded, after_file_fresh, file);
        assert(!state::MascotSecretStateSourceBridge::bit_prep_derived(
            after_file_fresh, substituted, substituted, true));
        assert(sink.unavailable == 1);
    }
    {
        Sink sink;
        state::TestOnlyMascotSecretStateScope scope(sink);
        advance_cache_hit_to_prep_static(loaded, after_file_fresh, file);
        assert(!state::MascotSecretStateSourceBridge::prep_static_installed(
            substituted, prep_scalar, prep_scalar));
        assert(sink.unavailable == 1);
    }
    {
        Sink sink;
        state::TestOnlyMascotSecretStateScope scope(sink);
        advance_cache_hit_to_prep_static(loaded, after_file_fresh, file);
        assert(!state::MascotSecretStateSourceBridge::prep_static_installed(
            default_prep_scalar(), prep_scalar, substituted));
        assert(sink.unavailable == 1);
    }
    {
        Sink sink;
        state::TestOnlyMascotSecretStateScope scope(sink);
        advance_cache_hit_to_prep_static(loaded, after_file_fresh, file);
        assert(state::MascotSecretStateSourceBridge::prep_static_installed(
            default_prep_scalar(), prep_scalar, prep_scalar));
        assert(!state::MascotSecretStateSourceBridge::bit_prep_derived(
            after_file_fresh, substituted, substituted, true));
        assert(sink.unavailable == 1);
    }
    {
        Sink sink;
        state::TestOnlyMascotSecretStateScope scope(sink);
        advance_cache_hit_to_prep_static(loaded, after_file_fresh, file);
        assert(state::MascotSecretStateSourceBridge::prep_static_installed(
            default_prep_scalar(), prep_scalar, prep_scalar));
        assert(!state::MascotSecretStateSourceBridge::prep_mac_file_write(
            prep_path, state::MascotStepResult::Succeeded,
            captured_prep_file(substituted), prep_file, {}));
        assert(sink.unavailable == 1);
    }
    {
        Sink sink;
        state::TestOnlyMascotSecretStateScope scope(sink);
        advance_cache_hit_to_prep_static(loaded, after_file_fresh, file);
        assert(state::MascotSecretStateSourceBridge::prep_static_installed(
            default_prep_scalar(), prep_scalar, prep_scalar));
        const std::span<const unsigned char> prefix(prep_file.data(), 2);
        assert(state::MascotSecretStateSourceBridge::prep_mac_file_write(
            prep_path, state::MascotStepResult::Failed,
            partial_prep_file(prefix), prep_file, "partial-write"));
        assert(sink.unavailable == 1);
    }
}

void omission_and_replay_fail_closed() {
    {
        Sink sink;
        state::TestOnlyMascotSecretStateScope scope(sink);
        assert(setup());
        assert(!state::MascotSecretStateSourceBridge::cache_local_validation(
            state::MascotStepResult::Failed, false,
            default_complete_key(), "omitted-open"));
        assert(sink.unavailable == 1);
    }
    {
        Sink sink;
        state::TestOnlyMascotSecretStateScope scope(sink);
        assert(setup());
        assert(!setup());
        assert(sink.unavailable == 1);
    }
}

void wrong_thread_fails_closed() {
    Sink sink;
    {
        state::TestOnlyMascotSecretStateScope scope(sink);
        bool required = false;
        bool accepted = true;
        std::thread worker([&] {
            required = state::MascotSecretStateSourceBridge::
                capture_required_noexcept();
            accepted = setup();
        });
        worker.join();
        assert(required);
        assert(!accepted);
        assert(sink.unavailable == 1);
    }
}

void substitution_and_duplicate_close_fail_closed() {
    {
        Sink sink;
        const std::vector<unsigned char> generated{1};
        const std::vector<unsigned char> after_fresh{2};
        const std::vector<unsigned char> candidate{1, 0, 0, 0, 0, 0, 0, 0,
                                                   7};
        const std::vector<unsigned char> substitute{1, 0, 0, 0, 0, 0, 0, 0,
                                                    8};
        state::TestOnlyMascotSecretStateScope scope(sink);
        assert(setup());
        assert(state::MascotSecretStateSourceBridge::cache_opened(
            path, missing_file()));
        assert(state::MascotSecretStateSourceBridge::cache_local_validation(
            state::MascotStepResult::Failed, false,
            default_complete_key(), "missing"));
        assert(state::MascotSecretStateSourceBridge::cache_peer_validation(
            state::MascotStepResult::Succeeded, {}));
        assert(state::MascotSecretStateSourceBridge::regeneration(
            true, generated));
        assert(state::MascotSecretStateSourceBridge::write_candidate(
            true, generated, true, after_fresh, candidate));
        assert(!state::MascotSecretStateSourceBridge::writeback(
            path, state::MascotStepResult::Succeeded,
            captured_file(substitute, true), {}));
        assert(sink.unavailable == 1);
    }
    {
        Sink sink;
        const std::vector<unsigned char> generated{1};
        const std::vector<unsigned char> substituted_key{2};
        const std::vector<unsigned char> after_fresh{3};
        const std::vector<unsigned char> candidate{1, 0, 0, 0, 0, 0, 0, 0,
                                                   7};
        state::TestOnlyMascotSecretStateScope scope(sink);
        assert(setup());
        assert(state::MascotSecretStateSourceBridge::cache_opened(
            path, missing_file()));
        assert(state::MascotSecretStateSourceBridge::cache_local_validation(
            state::MascotStepResult::Failed, false,
            default_complete_key(), "missing"));
        assert(state::MascotSecretStateSourceBridge::cache_peer_validation(
            state::MascotStepResult::Succeeded, {}));
        assert(state::MascotSecretStateSourceBridge::regeneration(
            true, generated));
        assert(!state::MascotSecretStateSourceBridge::write_candidate(
            true, substituted_key, true, after_fresh, candidate));
        assert(sink.unavailable == 1);
    }
    {
        Sink sink;
        const std::vector<unsigned char> complete{1};
        const std::vector<unsigned char> substituted{2};
        const std::vector<unsigned char> scalar{3};
        state::TestOnlyMascotSecretStateScope scope(sink);
        assert(setup_with_state(true, complete, scalar, scalar));
        assert(!state::MascotSecretStateSourceBridge::static_installed(
            true, substituted, scalar, scalar, scalar));
        assert(sink.unavailable == 1);
    }
    {
        Sink sink;
        const std::vector<unsigned char> complete{1};
        const std::vector<unsigned char> substituted{2};
        const std::vector<unsigned char> scalar{3};
        state::TestOnlyMascotSecretStateScope scope(sink);
        assert(setup_with_state(true, complete, scalar, scalar));
        assert(state::MascotSecretStateSourceBridge::static_installed(
            true, complete, scalar, scalar, scalar));
        assert(!state::MascotSecretStateSourceBridge::teardown(
            true, substituted, scalar, false, default_complete_key(),
            scalar, scalar, scalar));
        assert(sink.unavailable == 1);
    }
    {
        Sink sink;
        const std::vector<unsigned char> complete{1};
        const std::vector<unsigned char> scalar{2};
        state::TestOnlyMascotSecretStateScope scope(sink);
        assert(setup_with_state(true, complete, scalar, scalar));
        assert(state::MascotSecretStateSourceBridge::static_installed(
            true, complete, scalar, scalar, scalar));
        assert(state::MascotSecretStateSourceBridge::teardown(
            true, complete, scalar, false, default_complete_key(), scalar,
            scalar, scalar));
        assert(!state::MascotSecretStateSourceBridge::teardown(
            true, complete, scalar, false, default_complete_key(), scalar,
            scalar, scalar));
        assert(sink.unavailable == 1);
    }
}

void unavailable_abort_and_truncated_metadata_fail() {
    {
        Sink sink;
        {
            state::TestOnlyMascotSecretStateScope scope(sink);
            assert(setup());
            state::MascotSecretStateSourceBridge::unavailable_noexcept();
        }
        assert(sink.unavailable == 1);
    }
    Sink sink;
    const std::vector<unsigned char> raw{1, 2, 3};
    state::MascotSecretEventView event{
        .kind = state::MascotSecretEventKind::CacheOpened,
        .sequence = 2,
        .local_role = 1,
        .player_count = 3,
        .encrypted_player = true,
        .batch_size = 1000,
        .bucket_size = 4,
        .statistical_security = 40,
        .uses_security_parameter = true,
        .uses_kos = false,
        .native_size_width = 8,
        .native_byte_order = 1,
        .branch = state::MascotCacheBranch::Undecided,
        .local_validation = state::MascotStepResult::NotAttempted,
        .peer_validation = state::MascotStepResult::NotAttempted,
        .regeneration = state::MascotStepResult::NotAttempted,
        .writeback = state::MascotStepResult::NotAttempted,
        .prep_mac_write = state::MascotStepResult::NotAttempted,
        .player_id = "selected-P1",
        .field_modulus = "17",
        .canonical_cache_domain = domain,
        .diagnostic_path = path,
        .failure_reason = {},
        .file = captured_file(raw, false),
        .complete_key_before = {},
        .complete_key_after = {},
        .scalar_key_before = {},
        .scalar_key_after = {},
        .prep_scalar_key_before = {},
        .prep_scalar_key_after = {},
        .expected_scalar_key = {},
        .bit_prep_aliases_main = false,
        .derived_complete_key = {},
        .exact_write_candidate = {},
    };
    event.file.descriptor_after.size = raw.size() + 1;
    bool refused = false;
    try {
        (void)state::encode_mascot_secret_event(event);
    } catch (const std::runtime_error&) {
        refused = true;
    }
    assert(refused);
}

} // namespace

int main() {
    static_assert(!std::is_default_constructible_v<
                  state::MascotSecretStateHook>);
    static_assert(!state::kMascotSecretStateHookSourceStatus
                       .exact_cache_file_and_complete_key_bytes);
    static_assert(state::kMascotSecretStateHookSourceStatus
                      .capsule_family_adapter);
    static_assert(!state::kMascotSecretStateHookSourceStatus
                       .selected_role1_installation);
    static_assert(!state::kMascotSecretStateHookSourceStatus.configured);
    finish_static_reuse();
    finish_root_abort_prefix();
    finish_cache_hit();
    finish_regeneration();
    persistent_two_round_scalar_correspondence();
    bit_prep_edge_hostile_controls();
    prep_scalar_and_file_hostile_controls();
    omission_and_replay_fail_closed();
    wrong_thread_fails_closed();
    substitution_and_duplicate_close_fail_closed();
    unavailable_abort_and_truncated_metadata_fail();
}
