#include "p1_softspoken_random_tape_state_hook.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>

namespace kpi::mpc::p1_private_state {

struct SoftSpokenRandomTapeStateHookAccess final {
    static bool record(
            SoftSpokenRandomTapeStateHook& hook,
            const SoftSpokenEventView& view) noexcept {
        return hook.record_softspoken_event(view);
    }
    static bool bind(
            SoftSpokenRandomTapeStateHook& hook, SoftSpokenRole role,
            std::uint64_t& epoch) noexcept {
        return hook.bind_softspoken_worker_epoch(role, epoch);
    }
    static bool terminal(
            SoftSpokenRandomTapeStateHook& hook) noexcept {
        return hook.softspoken_terminal_noexcept();
    }
    static void unavailable(
            SoftSpokenRandomTapeStateHook& hook) noexcept {
        hook.softspoken_unavailable_noexcept();
    }
};

namespace {

constexpr std::string_view MP_OT_EXTENSION_SHA256 =
    "229e22315d8e002e9ce2fb216e8318e9e447fd5908ce32d7d51986a71979ce44";
constexpr std::string_view LIBOTE_MAL_CPP_SHA256 =
    "827f82adbf64bc915842882768e9c33ed6c2cb783ed726ae3827ea0030e43f7b";
constexpr std::string_view LIBOTE_SUBSPACE_MAL_SHA256 =
    "da0d92cb886d8d18a85627e95f2a163f72d4c9f333c42e5a2810badbd86b338e";
constexpr std::size_t MAX_SNAPSHOT_BYTES = 64U * 1024U * 1024U;

constexpr std::array<SoftSpokenEventDescriptor, 23> DESCRIPTORS{{
    {SoftSpokenEventKind::Construct, SoftSpokenSnapshotMask::None,
     "KPI:p1_softspoken_random_tape:Construct",
     SOFTSPOKEN_SOURCE_CLOSURE_SHA256},
    {SoftSpokenEventKind::PathSelected, SoftSpokenSnapshotMask::None,
     "MP-SPDZ/OT/OTExtensionWithMatrix.cpp:extend/selected-malicious-k2",
     MP_OT_EXTENSION_SHA256},
    {SoftSpokenEventKind::StateLookup, SoftSpokenSnapshotMask::None,
     "MP-SPDZ/OT/OTExtensionWithMatrix.cpp:extend/state-lookup",
     MP_OT_EXTENSION_SHA256},
    {SoftSpokenEventKind::StateConstructBegin, SoftSpokenSnapshotMask::None,
     "MP-SPDZ/OT/OTExtensionWithMatrix.cpp:SoftState/construct-begin",
     MP_OT_EXTENSION_SHA256},
    {SoftSpokenEventKind::StateConstructEnd, SoftSpokenSnapshotMask::None,
     "MP-SPDZ/OT/OTExtensionWithMatrix.cpp:SoftState/construct-end",
     MP_OT_EXTENSION_SHA256},
    {SoftSpokenEventKind::CallBegin, SoftSpokenSnapshotMask::None,
     "MP-SPDZ/OT/OTExtensionWithMatrix.cpp:SoftState::generate/begin",
     MP_OT_EXTENSION_SHA256},
    {SoftSpokenEventKind::RoleBegin, SoftSpokenSnapshotMask::None,
     "MP-SPDZ/OT/OTExtensionWithMatrix.cpp:SoftState::soft-role/begin",
     MP_OT_EXTENSION_SHA256},
    {SoftSpokenEventKind::SeededPrng,
     SoftSpokenSnapshotMask::Seed | SoftSpokenSnapshotMask::Prng,
     "MP-SPDZ/OT/OTExtensionWithMatrix.cpp:soft-role/post-sysRandomSeed",
     MP_OT_EXTENSION_SHA256},
    {SoftSpokenEventKind::BaseInstalled,
     SoftSpokenSnapshotMask::Base | SoftSpokenSnapshotMask::Object |
         SoftSpokenSnapshotMask::Prng,
     "MP-SPDZ/OT/OTExtensionWithMatrix.cpp:soft-role/post-setBaseOts",
     MP_OT_EXTENSION_SHA256},
    {SoftSpokenEventKind::VoleExpanded,
     SoftSpokenSnapshotMask::Seed | SoftSpokenSnapshotMask::Object |
         SoftSpokenSnapshotMask::Prng,
     "libOTe/SoftSpokenMalOtExt.cpp:post-vole-expand",
     LIBOTE_MAL_CPP_SHA256},
    {SoftSpokenEventKind::TapeConsumed,
     SoftSpokenSnapshotMask::Object | SoftSpokenSnapshotMask::Prng,
     "libOTe/SoftSpokenMalOtExt.cpp:post-batches",
     LIBOTE_MAL_CPP_SHA256},
    {SoftSpokenEventKind::ChallengeBound,
     SoftSpokenSnapshotMask::Object | SoftSpokenSnapshotMask::Prng,
     "libOTe/SoftSpokenMalOtExt.cpp:post-malicious-challenge",
     LIBOTE_MAL_CPP_SHA256},
    {SoftSpokenEventKind::RtcrBound,
     SoftSpokenSnapshotMask::Object | SoftSpokenSnapshotMask::Prng |
         SoftSpokenSnapshotMask::Transient,
     "libOTe/SoftSpokenMalOtExt.cpp:post-rtcr-key",
     LIBOTE_MAL_CPP_SHA256},
    {SoftSpokenEventKind::CheckDerived,
     SoftSpokenSnapshotMask::Object | SoftSpokenSnapshotMask::Prng |
         SoftSpokenSnapshotMask::Transient,
     "libOTe/SubspaceVoleMaliciousLeaky.h:derived-check-state",
     LIBOTE_SUBSPACE_MAL_SHA256},
    {SoftSpokenEventKind::CheckTerminal,
     SoftSpokenSnapshotMask::Object | SoftSpokenSnapshotMask::Prng,
     "libOTe/SoftSpokenMalOtExt.cpp:post-check-terminal",
     LIBOTE_MAL_CPP_SHA256},
    {SoftSpokenEventKind::OutputReady,
     SoftSpokenSnapshotMask::Object | SoftSpokenSnapshotMask::Prng |
         SoftSpokenSnapshotMask::Output,
     "MP-SPDZ/OT/OTExtensionWithMatrix.cpp:soft-role/output-ready",
     MP_OT_EXTENSION_SHA256},
    {SoftSpokenEventKind::RoleEnd, SoftSpokenSnapshotMask::None,
     "MP-SPDZ/OT/OTExtensionWithMatrix.cpp:SoftState::soft-role/end",
     MP_OT_EXTENSION_SHA256},
    {SoftSpokenEventKind::Join, SoftSpokenSnapshotMask::None,
     "MP-SPDZ/OT/OTExtensionWithMatrix.cpp:SoftState::generate/join",
     MP_OT_EXTENSION_SHA256},
    {SoftSpokenEventKind::CallEnd, SoftSpokenSnapshotMask::None,
     "MP-SPDZ/OT/OTExtensionWithMatrix.cpp:SoftState::generate/end",
     MP_OT_EXTENSION_SHA256},
    {SoftSpokenEventKind::StateDestructorBegin,
     SoftSpokenSnapshotMask::None,
     "MP-SPDZ/OT/OTExtensionWithMatrix.cpp:SoftState::~begin",
     MP_OT_EXTENSION_SHA256},
    {SoftSpokenEventKind::StateDestructorTerminal,
     SoftSpokenSnapshotMask::None,
     "MP-SPDZ/OT/OTExtensionWithMatrix.cpp:SoftState::~post-join",
     MP_OT_EXTENSION_SHA256},
    {SoftSpokenEventKind::PathRejected, SoftSpokenSnapshotMask::None,
     "MP-SPDZ/OT/OTExtensionWithMatrix.cpp:extend/rejected-path",
     MP_OT_EXTENSION_SHA256},
    {SoftSpokenEventKind::Abort, SoftSpokenSnapshotMask::None,
     "KPI:p1_softspoken_random_tape:Abort/dynamic-source",
     SOFTSPOKEN_SOURCE_CLOSURE_SHA256},
}};

void wipe(std::vector<unsigned char>& value) noexcept {
    volatile unsigned char* cursor = value.data();
    for (std::size_t index = 0; index < value.size(); ++index)
        cursor[index] = 0;
    value.clear();
}

bool is_lower_hex_sha(std::string_view value) noexcept {
    return value.size() == 64U && std::all_of(
        value.begin(), value.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        });
}

std::size_t checked_add(std::size_t left, std::size_t right) {
    if (left > MAX_SNAPSHOT_BYTES ||
        right > MAX_SNAPSHOT_BYTES - left)
        throw std::runtime_error("P1-SoftSpoken-event-size");
    return left + right;
}

void require_append(
        const std::vector<unsigned char>& output, std::size_t count) {
    if (count > output.capacity() - output.size())
        throw std::runtime_error("P1-SoftSpoken-event-capacity");
}

void append_u64(
        std::vector<unsigned char>& output, std::uint64_t value) {
    require_append(output, 8U);
    for (int shift = 56; shift >= 0; shift -= 8)
        output.push_back(static_cast<unsigned char>(value >> shift));
}

void append_bytes(
        std::vector<unsigned char>& output,
        std::span<const unsigned char> value) {
    require_append(output, checked_add(8U, value.size()));
    append_u64(output, value.size());
    output.insert(output.end(), value.begin(), value.end());
}

void append_text(
        std::vector<unsigned char>& output, std::string_view value) {
    append_bytes(output, std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
}

bool same(
        std::span<const unsigned char> left,
        const std::vector<unsigned char>& right) noexcept {
    return left.size() == right.size() &&
        std::equal(left.begin(), left.end(), right.begin());
}

void replace_secret(
        std::vector<unsigned char>& target,
        std::span<const unsigned char> source) {
    wipe(target);
    target.assign(source.begin(), source.end());
}

struct RoleState final {
    SoftSpokenRolePhase phase{SoftSpokenRolePhase::None};
    std::thread::id thread{};
    std::uint64_t worker_epoch{};
    std::vector<unsigned char> prng;
    std::vector<unsigned char> object;
    std::vector<unsigned char> pending_check;
};

struct ActiveCapture final {
    SoftSpokenRandomTapeStateHook* hook{};
    const void* source_player{};
    std::thread::id root_thread{};
    std::uint64_t generation{};
    std::uint64_t sequence{};
    std::uint64_t persistent_child_epoch{};
    std::uint64_t player_epoch{};
    std::uint64_t root_worker_epoch{};
    std::uint64_t state_epoch{};
    std::uint64_t call_epoch{};
    std::uint64_t local_role{};
    std::uint64_t peer_role{};
    std::uint64_t ot_role_mask{};
    std::uint64_t n_ots{};
    std::uint64_t softspoken_k{};
    bool just_bits{};
    bool healthy{true};
    bool terminal{};
    bool path_ready{};
    bool state_lookup_seen{};
    bool state_constructing{};
    bool state_constructed{};
    bool call_active{};
    bool joined{};
    bool destructor_begun{};
    RoleState sender;
    RoleState receiver;
};

struct ThreadContext final {
    ActiveCapture* active{};
    std::uint64_t generation{};
    std::uint64_t call_epoch{};
    SoftSpokenRole role{SoftSpokenRole::None};
};

std::mutex capture_mutex;
ActiveCapture* active_capture{};
std::uint64_t next_generation{1};
thread_local ThreadContext thread_context;

RoleState& role_state(ActiveCapture& active, SoftSpokenRole role) {
    if (role == SoftSpokenRole::Sender) return active.sender;
    if (role == SoftSpokenRole::Receiver) return active.receiver;
    throw std::runtime_error("P1-SoftSpoken-role");
}

void clear_role(RoleState& role) noexcept {
    wipe(role.prng);
    wipe(role.object);
    wipe(role.pending_check);
    role.phase = SoftSpokenRolePhase::None;
    role.thread = {};
    role.worker_epoch = 0;
}

void mark_unavailable_locked(ActiveCapture& active) noexcept {
    if (!active.healthy) return;
    active.healthy = false;
    active.sender.phase = SoftSpokenRolePhase::Poisoned;
    active.receiver.phase = SoftSpokenRolePhase::Poisoned;
    SoftSpokenRandomTapeStateHookAccess::unavailable(*active.hook);
}

bool emit_locked(
        ActiveCapture& active, SoftSpokenEventKind kind,
        SoftSpokenRole role = SoftSpokenRole::None,
        SoftSpokenPathClass path = SoftSpokenPathClass::None,
        SoftSpokenAbortClass abort = SoftSpokenAbortClass::None,
        SoftSpokenRolePhase phase = SoftSpokenRolePhase::None,
        std::span<const unsigned char> seed = {},
        std::span<const unsigned char> prng = {},
        std::span<const unsigned char> base = {},
        std::span<const unsigned char> object = {},
        std::span<const unsigned char> transient = {},
        std::span<const unsigned char> output = {},
        bool source_succeeded = true) noexcept {
    if (!active.healthy) return false;
    try {
        const auto& descriptor = softspoken_event_descriptor(kind);
        if (!is_lower_hex_sha(descriptor.source_identity_sha256) ||
            active.sequence == std::numeric_limits<std::uint64_t>::max()) {
            mark_unavailable_locked(active);
            return false;
        }
        std::uint64_t worker_epoch{};
        if (role != SoftSpokenRole::None)
            worker_epoch = role_state(active, role).worker_epoch;
        SoftSpokenEventView view{
            .kind = kind,
            .path_class = path,
            .abort_class = abort,
            .role_phase = phase,
            .role = role,
            .sequence = ++active.sequence,
            .persistent_child_epoch = active.persistent_child_epoch,
            .player_epoch = active.player_epoch,
            .root_worker_epoch = active.root_worker_epoch,
            .worker_epoch = worker_epoch,
            .state_epoch = active.state_epoch,
            .call_epoch = active.call_epoch,
            .local_role = active.local_role,
            .peer_role = active.peer_role,
            .ot_role_mask = active.ot_role_mask,
            .n_ots = active.n_ots,
            .softspoken_k = active.softspoken_k,
            .just_bits = active.just_bits,
            .source_succeeded = source_succeeded,
            .source_site = descriptor.source_site,
            .source_identity_sha256 = descriptor.source_identity_sha256,
            .seed_material = seed,
            .prng_state = prng,
            .base_material = base,
            .object_state = object,
            .transient_state = transient,
            .output_state = output,
        };
        if (!SoftSpokenRandomTapeStateHookAccess::record(
                *active.hook, view)) {
            mark_unavailable_locked(active);
            return false;
        }
        return true;
    } catch (...) {
        mark_unavailable_locked(active);
        return false;
    }
}

void poison_locked(
        ActiveCapture& active, SoftSpokenAbortClass abort,
        SoftSpokenRole role = SoftSpokenRole::None,
        SoftSpokenRolePhase phase = SoftSpokenRolePhase::Poisoned) noexcept {
    if (!active.healthy) return;
    (void)emit_locked(active, SoftSpokenEventKind::Abort, role,
                      SoftSpokenPathClass::None, abort, phase, {}, {}, {}, {},
                      {}, {}, false);
    mark_unavailable_locked(active);
}

bool source_matches_locked(
        ActiveCapture& active, const void* source_player) noexcept {
    if (source_player == active.source_player) return true;
    poison_locked(active, SoftSpokenAbortClass::ScopeUnlinked);
    return false;
}

ActiveCapture* current_or_poison_locked() noexcept {
    auto* active = active_capture;
    if (!active || !active->healthy)
        return nullptr;
    if (thread_context.active != active ||
        thread_context.generation != active->generation ||
        thread_context.call_epoch != active->call_epoch ||
        thread_context.role == SoftSpokenRole::None) {
        const auto role = thread_context.role == SoftSpokenRole::Sender ||
                thread_context.role == SoftSpokenRole::Receiver ?
            thread_context.role : SoftSpokenRole::None;
        poison_locked(*active, SoftSpokenAbortClass::WrongWorker, role);
        thread_context = {};
        return nullptr;
    }
    return active;
}

bool transition_locked(
        ActiveCapture& active, SoftSpokenEventKind kind,
        SoftSpokenRolePhase expected, SoftSpokenRolePhase next,
        std::span<const unsigned char> seed,
        std::span<const unsigned char> prng,
        std::span<const unsigned char> base,
        std::span<const unsigned char> object,
        std::span<const unsigned char> transient,
        std::span<const unsigned char> output) noexcept {
    const auto role = thread_context.role;
    auto& state = role_state(active, role);
    if (state.phase != expected || state.thread != std::this_thread::get_id() ||
        (kind != SoftSpokenEventKind::RoleEnd &&
         (prng.empty() || (kind != SoftSpokenEventKind::SeededPrng &&
                           object.empty())))) {
        poison_locked(active, SoftSpokenAbortClass::PartialRoleGraph,
                      role, state.phase);
        return true;
    }

    bool continuity_ok = true;
    switch (kind) {
    case SoftSpokenEventKind::SeededPrng:
        continuity_ok = !seed.empty() && !prng.empty();
        break;
    case SoftSpokenEventKind::BaseInstalled:
        continuity_ok = !base.empty() && same(prng, state.prng);
        break;
    case SoftSpokenEventKind::VoleExpanded:
        continuity_ok = !seed.empty() && !same(prng, state.prng) &&
            !same(object, state.object);
        break;
    case SoftSpokenEventKind::TapeConsumed:
        continuity_ok = role == SoftSpokenRole::Sender ?
            same(prng, state.prng) : !same(prng, state.prng);
        continuity_ok = continuity_ok && !same(object, state.object);
        break;
    case SoftSpokenEventKind::ChallengeBound:
        continuity_ok = role == SoftSpokenRole::Sender ?
            !same(prng, state.prng) : same(prng, state.prng);
        continuity_ok = continuity_ok && !same(object, state.object);
        break;
    case SoftSpokenEventKind::RtcrBound:
        continuity_ok = !transient.empty() &&
            (role == SoftSpokenRole::Sender ?
                 !same(prng, state.prng) : same(prng, state.prng));
        break;
    case SoftSpokenEventKind::CheckDerived:
        continuity_ok = !transient.empty() && same(prng, state.prng);
        break;
    case SoftSpokenEventKind::CheckTerminal:
        continuity_ok = same(prng, state.prng);
        break;
    case SoftSpokenEventKind::OutputReady:
        continuity_ok = !output.empty() && same(prng, state.prng);
        break;
    default:
        break;
    }
    if (!continuity_ok) {
        poison_locked(active, SoftSpokenAbortClass::PartialRoleGraph,
                      role, state.phase);
        return true;
    }

    state.phase = next;
    if (!prng.empty()) replace_secret(state.prng, prng);
    if (!object.empty()) replace_secret(state.object, object);
    (void)emit_locked(active, kind, role, SoftSpokenPathClass::None,
                      SoftSpokenAbortClass::None, next, seed, prng, base,
                      object, transient, output);
    return true;
}

SoftSpokenPathClass classify_path(
        std::uint64_t mask, std::uint64_t k, bool passive, bool kos,
        bool silent, bool libote1) noexcept {
    if (libote1) return SoftSpokenPathClass::LibOte1;
    if (kos) return SoftSpokenPathClass::Kos;
    if (silent) return SoftSpokenPathClass::Silent;
    if (passive) return SoftSpokenPathClass::SemiHonest;
    if (k != 2U) return SoftSpokenPathClass::HighOrOtherK;
    // MP-SPDZ OT/BaseOT.h at the pinned 113c4e47 commit defines BOTH as
    // RECEIVER (0x01) | SENDER (0x10), not as two adjacent low bits.
    if (mask != 0x11U) return SoftSpokenPathClass::UnsupportedRole;
    return SoftSpokenPathClass::SelectedMaliciousK2;
}

} // namespace

std::span<const SoftSpokenEventDescriptor>
softspoken_event_descriptors() noexcept {
    return DESCRIPTORS;
}

const SoftSpokenEventDescriptor& softspoken_event_descriptor(
        SoftSpokenEventKind kind) {
    const auto ordinal = static_cast<unsigned>(kind);
    if (ordinal == 0U || ordinal > DESCRIPTORS.size())
        throw std::runtime_error("P1-SoftSpoken-event-kind");
    return DESCRIPTORS[ordinal - 1U];
}

SoftSpokenCanonicalBytes::SoftSpokenCanonicalBytes(
        std::vector<unsigned char> value) : value_(std::move(value)) {}
SoftSpokenCanonicalBytes::SoftSpokenCanonicalBytes(
        SoftSpokenCanonicalBytes&& other) noexcept = default;
SoftSpokenCanonicalBytes& SoftSpokenCanonicalBytes::operator=(
        SoftSpokenCanonicalBytes&& other) noexcept {
    if (this != &other) {
        wipe(value_);
        value_ = std::move(other.value_);
    }
    return *this;
}
SoftSpokenCanonicalBytes::~SoftSpokenCanonicalBytes() { wipe(value_); }

SoftSpokenCanonicalBytes encode_softspoken_event(
        const SoftSpokenEventView& view) {
    if (view.sequence == 0 || view.persistent_child_epoch == 0 ||
        view.player_epoch == 0 || view.root_worker_epoch == 0 ||
        !is_lower_hex_sha(view.source_identity_sha256) ||
        view.source_site.empty())
        throw std::runtime_error("P1-SoftSpoken-event-invalid");
    std::size_t required = SOFTSPOKEN_RANDOM_TAPE_DOMAIN.size();
    required = checked_add(required, 25U * 8U);
    for (const auto bytes : {
             view.seed_material, view.prng_state, view.base_material,
             view.object_state, view.transient_state, view.output_state})
        required = checked_add(required, checked_add(8U, bytes.size()));
    required = checked_add(required, checked_add(8U, view.source_site.size()));
    required = checked_add(
        required, checked_add(8U, view.source_identity_sha256.size()));

    std::vector<unsigned char> output;
    output.reserve(required);
    require_append(output, SOFTSPOKEN_RANDOM_TAPE_DOMAIN.size());
    output.insert(output.end(), SOFTSPOKEN_RANDOM_TAPE_DOMAIN.begin(),
                  SOFTSPOKEN_RANDOM_TAPE_DOMAIN.end());
    for (const auto value : {
             static_cast<std::uint64_t>(view.kind),
             static_cast<std::uint64_t>(view.path_class),
             static_cast<std::uint64_t>(view.abort_class),
             static_cast<std::uint64_t>(view.role_phase),
             static_cast<std::uint64_t>(view.role), view.sequence,
             view.persistent_child_epoch, view.player_epoch,
             view.root_worker_epoch, view.worker_epoch, view.state_epoch,
             view.call_epoch, view.local_role, view.peer_role,
             view.ot_role_mask, view.n_ots, view.softspoken_k,
             static_cast<std::uint64_t>(view.just_bits),
             static_cast<std::uint64_t>(view.source_succeeded),
             std::uint64_t{0}, std::uint64_t{0}, std::uint64_t{0},
             std::uint64_t{0}, std::uint64_t{0}, std::uint64_t{0}})
        append_u64(output, value);
    append_text(output, view.source_site);
    append_text(output, view.source_identity_sha256);
    append_bytes(output, view.seed_material);
    append_bytes(output, view.prng_state);
    append_bytes(output, view.base_material);
    append_bytes(output, view.object_state);
    append_bytes(output, view.transient_state);
    append_bytes(output, view.output_state);
    if (output.size() != required)
        throw std::runtime_error("P1-SoftSpoken-event-size-mismatch");
    return SoftSpokenCanonicalBytes(std::move(output));
}

struct SoftSpokenRandomTapeStateScope::Storage final {
    ActiveCapture active;
    bool installed{};
};

SoftSpokenRandomTapeStateScope::SoftSpokenRandomTapeStateScope(
        SoftSpokenRandomTapeStateHook& hook, const void* source_player,
        std::uint64_t persistent_child_epoch, std::uint64_t player_epoch,
        std::uint64_t root_worker_epoch, std::uint64_t local_role,
        std::uint64_t peer_role) : storage_(std::make_unique<Storage>()) {
    if (!source_player || persistent_child_epoch == 0 || player_epoch == 0 ||
        root_worker_epoch == 0 || local_role > 1U || peer_role > 1U ||
        local_role == peer_role)
        throw std::runtime_error("P1-SoftSpoken-scope-invalid");
    std::lock_guard lock(capture_mutex);
    if (active_capture)
        throw std::runtime_error("P1-SoftSpoken-scope-already-installed");
    if (next_generation == 0 ||
        next_generation == std::numeric_limits<std::uint64_t>::max())
        throw std::runtime_error("P1-SoftSpoken-generation-exhausted");
    auto& active = storage_->active;
    active.hook = &hook;
    active.source_player = source_player;
    active.root_thread = std::this_thread::get_id();
    active.generation = next_generation++;
    active.persistent_child_epoch = persistent_child_epoch;
    active.player_epoch = player_epoch;
    active.root_worker_epoch = root_worker_epoch;
    active.local_role = local_role;
    active.peer_role = peer_role;
    active_capture = &active;
    storage_->installed = true;
    if (!emit_locked(active, SoftSpokenEventKind::Construct)) {
        active_capture = nullptr;
        storage_->installed = false;
        throw std::runtime_error("P1-SoftSpoken-construct-rejected");
    }
}

SoftSpokenRandomTapeStateScope::~SoftSpokenRandomTapeStateScope() {
    if (!storage_ || !storage_->installed) return;
    std::lock_guard lock(capture_mutex);
    auto& active = storage_->active;
    if (active_capture == &active) {
        if (!active.terminal)
            poison_locked(active, SoftSpokenAbortClass::ScopeUnlinked);
        active_capture = nullptr;
    }
    clear_role(active.sender);
    clear_role(active.receiver);
    storage_->installed = false;
}

bool SoftSpokenRandomTapeStateSourceBridge::
capture_required_pointer_noexcept(const void* source_player) noexcept {
    std::lock_guard lock(capture_mutex);
    // An installed-but-poisoned scope remains selected.  Returning false
    // after the first failure would let an upstream retry silently run as an
    // uncaptured call, contrary to the bridge's fail-closed contract.
    return active_capture &&
        active_capture->source_player == source_player;
}

bool SoftSpokenRandomTapeStateSourceBridge::
capture_required_current_noexcept() noexcept {
    std::lock_guard lock(capture_mutex);
    if (!active_capture) return false;
    if (active_capture->healthy)
        (void)current_or_poison_locked();
    // A poisoned or stale selected scope remains selected.  Returning false
    // here would let the exact source continue without capture calls.
    return true;
}

bool SoftSpokenRandomTapeStateSourceBridge::path_selected(
        const void* source_player, std::uint64_t local_role,
        std::uint64_t peer_role, std::uint64_t ot_role_mask,
        std::uint64_t softspoken_k, bool passive_only,
        bool use_kos, bool silent_ot, bool libote1) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return false;
    if (!active->healthy) return true;
    if (!source_matches_locked(*active, source_player)) return true;
    const auto path = classify_path(ot_role_mask, softspoken_k, passive_only,
                                    use_kos, silent_ot, libote1);
    active->ot_role_mask = ot_role_mask;
    active->softspoken_k = softspoken_k;
    if (std::this_thread::get_id() != active->root_thread ||
        active->call_active || active->path_ready ||
        local_role != active->local_role || peer_role != active->peer_role ||
        path != SoftSpokenPathClass::SelectedMaliciousK2) {
        (void)emit_locked(*active, SoftSpokenEventKind::PathRejected,
                          SoftSpokenRole::None, path,
                          SoftSpokenAbortClass::RejectedPath,
                          SoftSpokenRolePhase::None, {}, {}, {}, {}, {}, {},
                          false);
        mark_unavailable_locked(*active);
        return true;
    }
    active->path_ready = true;
    (void)emit_locked(*active, SoftSpokenEventKind::PathSelected,
                      SoftSpokenRole::None, path);
    return true;
}

bool SoftSpokenRandomTapeStateSourceBridge::path_rejected(
        const void* source_player, SoftSpokenPathClass path) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return false;
    if (!active->healthy) return true;
    if (!source_matches_locked(*active, source_player)) return true;
    (void)emit_locked(*active, SoftSpokenEventKind::PathRejected,
                      SoftSpokenRole::None, path,
                      SoftSpokenAbortClass::RejectedPath,
                      SoftSpokenRolePhase::None, {}, {}, {}, {}, {}, {},
                      false);
    mark_unavailable_locked(*active);
    return true;
}

bool SoftSpokenRandomTapeStateSourceBridge::state_lookup(
        const void* source_player, bool existing) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return false;
    if (!active->healthy) return true;
    if (!source_matches_locked(*active, source_player)) return true;
    if (!active->path_ready || active->call_active ||
        active->state_lookup_seen || existing != active->state_constructed) {
        poison_locked(*active, SoftSpokenAbortClass::PartialRoleGraph);
        return true;
    }
    active->state_lookup_seen = true;
    (void)emit_locked(*active, SoftSpokenEventKind::StateLookup);
    return true;
}

bool SoftSpokenRandomTapeStateSourceBridge::state_construct_begin(
        const void* source_player) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return false;
    if (!active->healthy) return true;
    if (!source_matches_locked(*active, source_player)) return true;
    if (!active->state_lookup_seen || active->state_constructed ||
        active->state_constructing) {
        poison_locked(*active, SoftSpokenAbortClass::StateConstructor);
        return true;
    }
    active->state_constructing = true;
    if (active->state_epoch == std::numeric_limits<std::uint64_t>::max()) {
        poison_locked(*active, SoftSpokenAbortClass::StateConstructor);
        return true;
    }
    ++active->state_epoch;
    (void)emit_locked(*active, SoftSpokenEventKind::StateConstructBegin);
    return true;
}

bool SoftSpokenRandomTapeStateSourceBridge::state_construct_end(
        const void* source_player, bool succeeded) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return false;
    if (!active->healthy) return true;
    if (!source_matches_locked(*active, source_player)) return true;
    if (!active->state_constructing || !succeeded) {
        poison_locked(*active, SoftSpokenAbortClass::StateConstructor);
        return true;
    }
    active->state_constructing = false;
    active->state_constructed = true;
    (void)emit_locked(*active, SoftSpokenEventKind::StateConstructEnd);
    return true;
}

bool SoftSpokenRandomTapeStateSourceBridge::call_begin(
        const void* source_player, std::uint64_t n_ots,
        bool just_bits) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return false;
    if (!active->healthy) return true;
    if (!source_matches_locked(*active, source_player)) return true;
    if (!active->path_ready || !active->state_lookup_seen ||
        !active->state_constructed || active->state_constructing ||
        active->call_active || n_ots == 0 ||
        active->call_epoch == std::numeric_limits<std::uint64_t>::max()) {
        poison_locked(*active, SoftSpokenAbortClass::CallException);
        return true;
    }
    clear_role(active->sender);
    clear_role(active->receiver);
    ++active->call_epoch;
    active->n_ots = n_ots;
    active->just_bits = just_bits;
    active->call_active = true;
    active->joined = false;
    active->path_ready = false;
    active->state_lookup_seen = false;
    (void)emit_locked(*active, SoftSpokenEventKind::CallBegin);
    return true;
}

bool SoftSpokenRandomTapeStateSourceBridge::role_begin(
        const void* source_player, SoftSpokenRole role) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return false;
    if (!active->healthy) return true;
    if (!source_matches_locked(*active, source_player)) return true;
    if (!active->call_active || role == SoftSpokenRole::None) {
        poison_locked(*active, SoftSpokenAbortClass::PartialRoleGraph);
        return true;
    }
    auto& state = role_state(*active, role);
    if (state.phase != SoftSpokenRolePhase::None) {
        poison_locked(*active, SoftSpokenAbortClass::PartialRoleGraph,
                      role, state.phase);
        return true;
    }
    const auto current = std::this_thread::get_id();
    if (role == SoftSpokenRole::Sender) {
        if (current != active->root_thread) {
            poison_locked(*active, SoftSpokenAbortClass::WrongWorker, role);
            return true;
        }
        state.worker_epoch = active->root_worker_epoch;
    } else {
        if (current == active->root_thread ||
            !SoftSpokenRandomTapeStateHookAccess::bind(
                *active->hook, role, state.worker_epoch) ||
            state.worker_epoch == 0 ||
            state.worker_epoch == active->root_worker_epoch) {
            poison_locked(*active, SoftSpokenAbortClass::WrongWorker, role);
            return true;
        }
    }
    state.thread = current;
    state.phase = SoftSpokenRolePhase::Begun;
    thread_context = ThreadContext{
        .active = active,
        .generation = active->generation,
        .call_epoch = active->call_epoch,
        .role = role,
    };
    (void)emit_locked(*active, SoftSpokenEventKind::RoleBegin, role,
                      SoftSpokenPathClass::None,
                      SoftSpokenAbortClass::None, state.phase);
    return true;
}

bool SoftSpokenRandomTapeStateSourceBridge::seeded_prng(
        std::span<const unsigned char> seed,
        std::span<const unsigned char> prng) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = current_or_poison_locked();
    if (!active) return active_capture != nullptr;
    return transition_locked(*active, SoftSpokenEventKind::SeededPrng,
        SoftSpokenRolePhase::Begun, SoftSpokenRolePhase::Seeded,
        seed, prng, {}, {}, {}, {});
}

bool SoftSpokenRandomTapeStateSourceBridge::base_installed(
        std::span<const unsigned char> base,
        std::span<const unsigned char> object,
        std::span<const unsigned char> prng) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = current_or_poison_locked();
    if (!active) return active_capture != nullptr;
    return transition_locked(*active, SoftSpokenEventKind::BaseInstalled,
        SoftSpokenRolePhase::Seeded, SoftSpokenRolePhase::Base,
        {}, prng, base, object, {}, {});
}

bool SoftSpokenRandomTapeStateSourceBridge::vole_expanded(
        std::span<const unsigned char> object,
        std::span<const unsigned char> prng,
        std::span<const unsigned char> seed) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = current_or_poison_locked();
    if (!active) return active_capture != nullptr;
    return transition_locked(*active, SoftSpokenEventKind::VoleExpanded,
        SoftSpokenRolePhase::Base, SoftSpokenRolePhase::Expanded,
        seed, prng, {}, object, {}, {});
}

bool SoftSpokenRandomTapeStateSourceBridge::tape_consumed(
        std::span<const unsigned char> object,
        std::span<const unsigned char> prng) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = current_or_poison_locked();
    if (!active) return active_capture != nullptr;
    return transition_locked(*active, SoftSpokenEventKind::TapeConsumed,
        SoftSpokenRolePhase::Expanded, SoftSpokenRolePhase::Tape,
        {}, prng, {}, object, {}, {});
}

bool SoftSpokenRandomTapeStateSourceBridge::challenge_bound(
        std::span<const unsigned char> object,
        std::span<const unsigned char> prng) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = current_or_poison_locked();
    if (!active) return active_capture != nullptr;
    return transition_locked(*active, SoftSpokenEventKind::ChallengeBound,
        SoftSpokenRolePhase::Tape, SoftSpokenRolePhase::Challenge,
        {}, prng, {}, object, {}, {});
}

bool SoftSpokenRandomTapeStateSourceBridge::rtcr_bound(
        std::span<const unsigned char> object,
        std::span<const unsigned char> prng,
        std::span<const unsigned char> transient) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = current_or_poison_locked();
    if (!active) return active_capture != nullptr;
    return transition_locked(*active, SoftSpokenEventKind::RtcrBound,
        SoftSpokenRolePhase::Challenge, SoftSpokenRolePhase::Rtcr,
        {}, prng, {}, object, transient, {});
}

bool SoftSpokenRandomTapeStateSourceBridge::stage_check_transient(
        std::span<const unsigned char> transient) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = current_or_poison_locked();
    if (!active) return active_capture != nullptr;
    auto& state = role_state(*active, thread_context.role);
    if (state.phase != SoftSpokenRolePhase::Rtcr || transient.empty() ||
        !state.pending_check.empty()) {
        poison_locked(*active, SoftSpokenAbortClass::PartialRoleGraph,
                      thread_context.role, state.phase);
        return true;
    }
    replace_secret(state.pending_check, transient);
    return true;
}

bool SoftSpokenRandomTapeStateSourceBridge::check_derived(
        std::span<const unsigned char> object,
        std::span<const unsigned char> prng,
        std::span<const unsigned char> transient) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = current_or_poison_locked();
    if (!active) return active_capture != nullptr;
    auto& state = role_state(*active, thread_context.role);
    const auto effective = transient.empty() ?
        std::span<const unsigned char>(state.pending_check) : transient;
    const auto result = transition_locked(
        *active, SoftSpokenEventKind::CheckDerived,
        SoftSpokenRolePhase::Rtcr, SoftSpokenRolePhase::CheckDerived,
        {}, prng, {}, object, effective, {});
    wipe(state.pending_check);
    return result;
}

bool SoftSpokenRandomTapeStateSourceBridge::check_terminal(
        std::span<const unsigned char> object,
        std::span<const unsigned char> prng) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = current_or_poison_locked();
    if (!active) return active_capture != nullptr;
    return transition_locked(*active, SoftSpokenEventKind::CheckTerminal,
        SoftSpokenRolePhase::CheckDerived,
        SoftSpokenRolePhase::CheckTerminal,
        {}, prng, {}, object, {}, {});
}

bool SoftSpokenRandomTapeStateSourceBridge::output_ready(
        std::span<const unsigned char> object,
        std::span<const unsigned char> prng,
        std::span<const unsigned char> output) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = current_or_poison_locked();
    if (!active) return active_capture != nullptr;
    return transition_locked(*active, SoftSpokenEventKind::OutputReady,
        SoftSpokenRolePhase::CheckTerminal, SoftSpokenRolePhase::Output,
        {}, prng, {}, object, {}, output);
}

bool SoftSpokenRandomTapeStateSourceBridge::role_end(
        SoftSpokenRole role) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = current_or_poison_locked();
    if (!active) return active_capture != nullptr;
    if (thread_context.role != role) {
        poison_locked(*active, SoftSpokenAbortClass::WrongWorker, role);
        return true;
    }
    auto& state = role_state(*active, role);
    if (state.phase != SoftSpokenRolePhase::Output ||
        state.thread != std::this_thread::get_id()) {
        poison_locked(*active, SoftSpokenAbortClass::PartialRoleGraph,
                      role, state.phase);
        return true;
    }
    state.phase = SoftSpokenRolePhase::Ended;
    (void)emit_locked(*active, SoftSpokenEventKind::RoleEnd, role,
                      SoftSpokenPathClass::None,
                      SoftSpokenAbortClass::None, state.phase);
    thread_context = {};
    return true;
}

bool SoftSpokenRandomTapeStateSourceBridge::join(
        const void* source_player) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return false;
    if (!active->healthy) return true;
    if (!source_matches_locked(*active, source_player)) return true;
    if (!active->call_active || active->joined ||
        std::this_thread::get_id() != active->root_thread ||
        active->sender.phase != SoftSpokenRolePhase::Ended ||
        active->receiver.phase != SoftSpokenRolePhase::Ended) {
        poison_locked(*active, SoftSpokenAbortClass::PartialRoleGraph);
        return true;
    }
    active->joined = true;
    (void)emit_locked(*active, SoftSpokenEventKind::Join);
    return true;
}

bool SoftSpokenRandomTapeStateSourceBridge::call_end(
        const void* source_player) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return false;
    if (!active->healthy) return true;
    if (!source_matches_locked(*active, source_player)) return true;
    if (!active->call_active || !active->joined ||
        std::this_thread::get_id() != active->root_thread) {
        poison_locked(*active, SoftSpokenAbortClass::CallException);
        return true;
    }
    (void)emit_locked(*active, SoftSpokenEventKind::CallEnd);
    active->call_active = false;
    active->joined = false;
    clear_role(active->sender);
    clear_role(active->receiver);
    return true;
}

bool SoftSpokenRandomTapeStateSourceBridge::state_destructor_begin(
        const void* source_player) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return false;
    if (!active->healthy) return true;
    if (!source_matches_locked(*active, source_player)) return true;
    if (!active->state_constructed || active->call_active ||
        active->destructor_begun || active->call_epoch == 0) {
        poison_locked(*active, SoftSpokenAbortClass::PartialRoleGraph);
        return true;
    }
    active->destructor_begun = true;
    (void)emit_locked(*active, SoftSpokenEventKind::StateDestructorBegin);
    return true;
}

bool SoftSpokenRandomTapeStateSourceBridge::state_destructor_terminal(
        const void* source_player) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return false;
    if (!active->healthy) return true;
    if (!source_matches_locked(*active, source_player)) return true;
    if (!active->destructor_begun || !active->state_constructed ||
        active->call_active) {
        poison_locked(*active, SoftSpokenAbortClass::PartialRoleGraph);
        return true;
    }
    active->state_constructed = false;
    (void)emit_locked(*active,
                      SoftSpokenEventKind::StateDestructorTerminal);
    active->terminal = active->healthy &&
        SoftSpokenRandomTapeStateHookAccess::terminal(*active->hook);
    if (!active->terminal) mark_unavailable_locked(*active);
    return true;
}

void SoftSpokenRandomTapeStateSourceBridge::abort_current_noexcept(
        SoftSpokenAbortClass abort, SoftSpokenRolePhase phase) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = current_or_poison_locked();
    if (!active) return;
    poison_locked(*active, abort, thread_context.role, phase);
    thread_context = {};
}

void SoftSpokenRandomTapeStateSourceBridge::abort_player_noexcept(
        const void* source_player, SoftSpokenAbortClass abort) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active || !active->healthy) return;
    if (!source_matches_locked(*active, source_player)) return;
    poison_locked(*active, abort);
}

#ifdef KPI_P1_SOFTSPOKEN_RANDOM_TAPE_STATE_HOOK_TEST_SETUP
std::unique_ptr<SoftSpokenRandomTapeStateScope>
SoftSpokenRandomTapeStateTestBridge::install(
        SoftSpokenRandomTapeStateHook& hook, const void* source_player,
        std::uint64_t persistent_child_epoch, std::uint64_t player_epoch,
        std::uint64_t root_worker_epoch, std::uint64_t local_role,
        std::uint64_t peer_role) {
    return std::unique_ptr<SoftSpokenRandomTapeStateScope>(
        new SoftSpokenRandomTapeStateScope(
            hook, source_player, persistent_child_epoch, player_epoch,
            root_worker_epoch, local_role, peer_role));
}
#endif

} // namespace kpi::mpc::p1_private_state

std::unique_ptr<
    ::kpi::mpc::p1_private_state::SoftSpokenRandomTapeStateScope>
kpb::measurement::p1_state_capsule::
P1SoftSpokenRandomTapeStateAdapterFactoryBridge::install_source_scope(
        ::kpi::mpc::p1_private_state::SoftSpokenRandomTapeStateHook& hook,
        const void* source_player, std::uint64_t persistent_child_epoch,
        std::uint64_t player_epoch, std::uint64_t root_worker_epoch,
        std::uint64_t local_role, std::uint64_t peer_role) {
    using Scope = ::kpi::mpc::p1_private_state::
        SoftSpokenRandomTapeStateScope;
    return std::unique_ptr<Scope>(new Scope(
        hook, source_player, persistent_child_epoch, player_epoch,
        root_worker_epoch, local_role, peer_role));
}
