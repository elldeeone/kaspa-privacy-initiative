#include "p1_ondemand_ot_state_hook.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <utility>

namespace kpi::mpc::p1_private_state {
namespace {

constexpr std::string_view OT_TRIPLE_SETUP_HEADER_SHA256 =
    "93e71b45a31f1f5f17abde80d069ea559789bbf7d28555a2f4a44252c25f7c1b";
constexpr std::string_view OT_TRIPLE_SETUP_CPP_SHA256 =
    "05d1988b32947701965a4e6fa891c285637c40678d2267828f7bf0ca355a61aa";
constexpr std::size_t MAX_SNAPSHOT_BYTES = 8U * 1024U * 1024U;

constexpr std::array<OnDemandOtEventDescriptor, 19> DESCRIPTORS{{
    {OnDemandOtEventKind::Construct, OnDemandOtTransitionClass::Construct,
     OnDemandOtSnapshotMask::None,
     "KPI:p1_ondemand_ot_map:Construct", ONDEMAND_OT_SOURCE_CLOSURE_SHA256},
    {OnDemandOtEventKind::RoundBegin, OnDemandOtTransitionClass::Round,
     OnDemandOtSnapshotMask::None,
     "KPI:selected-persistent-role1:OnDemandOtMapRoundBegin",
     ONDEMAND_OT_SOURCE_CLOSURE_SHA256},
    {OnDemandOtEventKind::MapLookup,
     OnDemandOtTransitionClass::MapTopology,
     OnDemandOtSnapshotMask::StateBefore,
     "MP-SPDZ/OT/OTTripleSetup.h:OnDemandOTTripleSetup::get_fresh/map-lookup",
     OT_TRIPLE_SETUP_HEADER_SHA256},
    {OnDemandOtEventKind::MapEntryCreateBegin,
     OnDemandOtTransitionClass::MapTopology, OnDemandOtSnapshotMask::None,
     "MP-SPDZ/OT/OTTripleSetup.h:OnDemandOTTripleSetup::get_fresh/create",
     OT_TRIPLE_SETUP_HEADER_SHA256},
    {OnDemandOtEventKind::PrngBeforeChoiceConsume,
     OnDemandOtTransitionClass::PrngConsume, OnDemandOtSnapshotMask::Prng,
     "MP-SPDZ/OT/OTTripleSetup.cpp:OTTripleSetup::setup/post-ReSeed",
     OT_TRIPLE_SETUP_CPP_SHA256},
    {OnDemandOtEventKind::PrngAfterChoiceConsume,
     OnDemandOtTransitionClass::PrngConsume, OnDemandOtSnapshotMask::Prng,
     "MP-SPDZ/OT/OTTripleSetup.cpp:OTTripleSetup::setup/post-base-choices",
     OT_TRIPLE_SETUP_CPP_SHA256},
    {OnDemandOtEventKind::OtSetupWorkerBegin,
     OnDemandOtTransitionClass::OtSetup, OnDemandOtSnapshotMask::None,
     "MP-SPDZ/OT/OTTripleSetup.cpp:OTTripleSetup::SetupJob::run/begin",
     OT_TRIPLE_SETUP_CPP_SHA256},
    {OnDemandOtEventKind::OtSetupWorkerEnd,
     OnDemandOtTransitionClass::OtSetup, OnDemandOtSnapshotMask::None,
     "MP-SPDZ/OT/OTTripleSetup.cpp:OTTripleSetup::SetupJob::run/end",
     OT_TRIPLE_SETUP_CPP_SHA256},
    {OnDemandOtEventKind::MapEntryCreated,
     OnDemandOtTransitionClass::MapTopology,
     OnDemandOtSnapshotMask::StoredAfter,
     "MP-SPDZ/OT/OTTripleSetup.h:OnDemandOTTripleSetup::get_fresh/created",
     OT_TRIPLE_SETUP_HEADER_SHA256},
    {OnDemandOtEventKind::GetFreshBegin,
     OnDemandOtTransitionClass::OtExtend,
     OnDemandOtSnapshotMask::StateBefore,
     "MP-SPDZ/OT/OTTripleSetup.h:OnDemandOTTripleSetup::get_fresh/begin",
     OT_TRIPLE_SETUP_HEADER_SHA256},
    {OnDemandOtEventKind::OtExtendBefore,
     OnDemandOtTransitionClass::OtExtend,
     OnDemandOtSnapshotMask::StateBefore,
     "MP-SPDZ/OT/OTTripleSetup.cpp:OTTripleSetup::get_base/before",
     OT_TRIPLE_SETUP_CPP_SHA256},
    {OnDemandOtEventKind::OtSeededInitialAdvance,
     OnDemandOtTransitionClass::OtExtend,
     OnDemandOtSnapshotMask::ReturnedAfter,
     "MP-SPDZ/OT/OTTripleSetup.cpp:OTTripleSetup::get_base/post-set_seeds",
     OT_TRIPLE_SETUP_CPP_SHA256},
    {OnDemandOtEventKind::OtExtendStoredAdvance,
     OnDemandOtTransitionClass::OtExtend,
     OnDemandOtSnapshotMask::StoredAfter |
         OnDemandOtSnapshotMask::ReturnedAfter,
     "MP-SPDZ/OT/OTTripleSetup.cpp:OTTripleSetup::get_base/stored-advance",
     OT_TRIPLE_SETUP_CPP_SHA256},
    {OnDemandOtEventKind::OtExtendReturnedAdvance,
     OnDemandOtTransitionClass::OtExtend,
     OnDemandOtSnapshotMask::ReturnedAfter,
     "MP-SPDZ/OT/OTTripleSetup.cpp:OTTripleSetup::get_base/returned-advance",
     OT_TRIPLE_SETUP_CPP_SHA256},
    {OnDemandOtEventKind::GetFreshEnd,
     OnDemandOtTransitionClass::OtExtend,
     OnDemandOtSnapshotMask::StoredAfter |
         OnDemandOtSnapshotMask::ReturnedAfter,
     "MP-SPDZ/OT/OTTripleSetup.h:OnDemandOTTripleSetup::get_fresh/end",
     OT_TRIPLE_SETUP_HEADER_SHA256},
    {OnDemandOtEventKind::RoundEnd, OnDemandOtTransitionClass::Round,
     OnDemandOtSnapshotMask::None,
     "KPI:selected-persistent-role1:OnDemandOtMapRoundEnd",
     ONDEMAND_OT_SOURCE_CLOSURE_SHA256},
    {OnDemandOtEventKind::MapDestructorBegin,
     OnDemandOtTransitionClass::Terminal,
     OnDemandOtSnapshotMask::StateBefore |
         OnDemandOtSnapshotMask::StoredAfter,
     "MP-SPDZ/OT/OTTripleSetup.h:OnDemandOTTripleSetup::~begin",
     OT_TRIPLE_SETUP_HEADER_SHA256},
    {OnDemandOtEventKind::MapDestructorTerminal,
     OnDemandOtTransitionClass::Terminal, OnDemandOtSnapshotMask::None,
     "MP-SPDZ/OT/OTTripleSetup.h:OnDemandOTTripleSetup::~post-clear",
     OT_TRIPLE_SETUP_HEADER_SHA256},
    {OnDemandOtEventKind::Abort, OnDemandOtTransitionClass::Abort,
     OnDemandOtSnapshotMask::None,
     "KPI:p1_ondemand_ot_map:Abort/dynamic-source",
     ONDEMAND_OT_SOURCE_CLOSURE_SHA256},
}};

void wipe(std::vector<unsigned char>& value) noexcept {
    volatile unsigned char* cursor = value.data();
    for (std::size_t index = 0; index < value.size(); ++index)
        cursor[index] = 0;
    value.clear();
}

void append_u64(std::vector<unsigned char>& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        output.push_back(static_cast<unsigned char>(value >> shift));
}

void append_bytes(
        std::vector<unsigned char>& output,
        std::span<const unsigned char> value) {
    if (value.size() > MAX_SNAPSHOT_BYTES ||
        output.size() > std::numeric_limits<std::size_t>::max() - 8U ||
        value.size() >
            std::numeric_limits<std::size_t>::max() - output.size() - 8U)
        throw std::runtime_error("P1-OnDemandOT-snapshot-size");
    append_u64(output, value.size());
    output.insert(output.end(), value.begin(), value.end());
}

void append_text(
        std::vector<unsigned char>& output, std::string_view value) {
    append_bytes(output, std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
}

bool is_lower_hex_sha(std::string_view value) {
    return value.size() == 64 && std::all_of(
        value.begin(), value.end(), [](unsigned char byte) {
            return (byte >= '0' && byte <= '9') ||
                (byte >= 'a' && byte <= 'f');
        });
}

bool is_worker_event(OnDemandOtEventKind kind) {
    return kind == OnDemandOtEventKind::OtSetupWorkerBegin ||
        kind == OnDemandOtEventKind::OtSetupWorkerEnd;
}

bool is_root_peer_event(OnDemandOtEventKind kind) {
    return kind == OnDemandOtEventKind::OtExtendBefore ||
        kind == OnDemandOtEventKind::OtSeededInitialAdvance ||
        kind == OnDemandOtEventKind::OtExtendStoredAdvance ||
        kind == OnDemandOtEventKind::OtExtendReturnedAdvance;
}

std::pair<std::string_view, std::string_view> abort_source(
        OnDemandOtAbortClass abort_class) {
    switch (abort_class) {
    case OnDemandOtAbortClass::SetupWorkerException:
        return {
            "MP-SPDZ/OT/OTTripleSetup.cpp:OTTripleSetup::SetupJob::run/catch",
            OT_TRIPLE_SETUP_CPP_SHA256};
    case OnDemandOtAbortClass::SetupRootException:
        return {"MP-SPDZ/OT/OTTripleSetup.cpp:OTTripleSetup::setup/abort",
                OT_TRIPLE_SETUP_CPP_SHA256};
    case OnDemandOtAbortClass::GetFreshException:
        return {
            "MP-SPDZ/OT/OTTripleSetup.h:OnDemandOTTripleSetup::get_fresh/catch",
            OT_TRIPLE_SETUP_HEADER_SHA256};
    case OnDemandOtAbortClass::SourceSerialization:
        return {"KPI:p1_ondemand_ot_source_capture:fieldwise-serialization",
                ONDEMAND_OT_SOURCE_CLOSURE_SHA256};
    case OnDemandOtAbortClass::ScopeUnlinked:
        return {"KPI:p1_ondemand_ot_map:scope-unlinked",
                ONDEMAND_OT_SOURCE_CLOSURE_SHA256};
    case OnDemandOtAbortClass::TerminalPrefixIncomplete:
        return {
            "MP-SPDZ/OT/OTTripleSetup.h:OnDemandOTTripleSetup::~incomplete",
            OT_TRIPLE_SETUP_HEADER_SHA256};
    case OnDemandOtAbortClass::None:
        break;
    }
    return {};
}

std::uint64_t peer_role_for(
        std::uint64_t local_role, std::uint64_t index) {
    return index >= local_role ? index + 1 : index;
}

bool snapshot_present(
        OnDemandOtSnapshotMask mask, OnDemandOtSnapshotMask field) {
    return (static_cast<unsigned>(mask) & static_cast<unsigned>(field)) != 0;
}

void require_event_shape(const OnDemandOtEventView& value) {
    const auto kind_value = static_cast<unsigned>(value.kind);
    const auto branch_value = static_cast<unsigned>(value.branch);
    const auto abort_value = static_cast<unsigned>(value.abort_class);
    const auto phase_value = static_cast<unsigned>(value.phase);
    if (kind_value == 0 || kind_value > DESCRIPTORS.size() ||
        branch_value > static_cast<unsigned>(OnDemandOtMapBranch::ExistingReuse) ||
        abort_value >
            static_cast<unsigned>(OnDemandOtAbortClass::TerminalPrefixIncomplete) ||
        phase_value == 0 ||
        phase_value > static_cast<unsigned>(OnDemandOtPhase::Poisoned) ||
        value.sequence == 0 || value.persistent_child_epoch == 0 ||
        value.player_epoch == 0 || value.root_thread_epoch == 0 ||
        value.local_role >= 3 || value.player_count != 3 ||
        value.local_role >= value.player_count)
        throw std::runtime_error("invalid-P1-OnDemandOT-event");

    const auto& descriptor = ondemand_ot_event_descriptor(value.kind);
    if (value.transition != descriptor.transition)
        throw std::runtime_error("P1-OnDemandOT-transition-class");
    auto expected_site = descriptor.source_site;
    auto expected_sha = descriptor.source_identity_sha256;
    if (value.kind == OnDemandOtEventKind::Abort) {
        if (value.abort_class == OnDemandOtAbortClass::None)
            throw std::runtime_error("P1-OnDemandOT-abort-class");
        std::tie(expected_site, expected_sha) = abort_source(value.abort_class);
    } else if (value.abort_class != OnDemandOtAbortClass::None) {
        throw std::runtime_error("P1-OnDemandOT-unexpected-abort-class");
    }
    if (value.source_site != expected_site ||
        value.source_identity_sha256 != expected_sha ||
        !is_lower_hex_sha(value.source_identity_sha256))
        throw std::runtime_error("P1-OnDemandOT-source-identity");

    if (value.kind == OnDemandOtEventKind::Construct) {
        if (value.round != 0 || value.call_in_round != 0 ||
            value.map_entry_epoch != 0)
            throw std::runtime_error("P1-OnDemandOT-construct-shape");
    } else if ((value.round == 0 &&
                value.kind != OnDemandOtEventKind::Abort) ||
               value.round > 2) {
        throw std::runtime_error("P1-OnDemandOT-round");
    }

    if (is_worker_event(value.kind)) {
        if (value.worker_thread_epoch == 0 ||
            value.worker_thread_epoch == value.root_thread_epoch ||
            value.peer_index >= value.player_count - 1 ||
            value.peer_role !=
                peer_role_for(value.local_role, value.peer_index))
            throw std::runtime_error("P1-OnDemandOT-worker-identity");
    } else if (is_root_peer_event(value.kind)) {
        if (value.worker_thread_epoch != 0 ||
            value.peer_index >= value.player_count - 1 ||
            value.peer_role !=
                peer_role_for(value.local_role, value.peer_index))
            throw std::runtime_error("P1-OnDemandOT-root-peer-identity");
    } else if (value.worker_thread_epoch != 0 || value.peer_index != 0 ||
               value.peer_role != 0) {
        throw std::runtime_error("P1-OnDemandOT-unexpected-peer-identity");
    }

    const auto& snapshots = descriptor.snapshots;
    if (value.kind != OnDemandOtEventKind::MapLookup &&
        (snapshot_present(snapshots, OnDemandOtSnapshotMask::StateBefore) !=
             !value.state_before.empty() ||
         snapshot_present(snapshots, OnDemandOtSnapshotMask::StoredAfter) !=
             !value.stored_after.empty() ||
         snapshot_present(snapshots, OnDemandOtSnapshotMask::ReturnedAfter) !=
             !value.returned_after.empty() ||
         snapshot_present(snapshots, OnDemandOtSnapshotMask::Prng) !=
             !value.prng_state.empty()))
        throw std::runtime_error("P1-OnDemandOT-snapshot-shape");
    if (value.kind == OnDemandOtEventKind::MapLookup) {
        if (value.map_entry_found != !value.state_before.empty() ||
            !value.stored_after.empty() || !value.returned_after.empty() ||
            !value.prng_state.empty())
            throw std::runtime_error("P1-OnDemandOT-lookup-snapshot");
    }
    for (const auto bytes : {value.state_before, value.stored_after,
                             value.returned_after, value.prng_state})
        if (bytes.size() > MAX_SNAPSHOT_BYTES)
            throw std::runtime_error("P1-OnDemandOT-snapshot-size");
}

struct WorkerState final {
    std::thread::id thread;
    std::uint64_t logical_epoch{};
    std::uint64_t peer_index{};
    bool present{};
    bool active{};
    bool ended{};
};

} // namespace

std::span<const OnDemandOtEventDescriptor> ondemand_ot_event_descriptors() {
    return DESCRIPTORS;
}

const OnDemandOtEventDescriptor& ondemand_ot_event_descriptor(
        OnDemandOtEventKind kind) {
    const auto value = static_cast<unsigned>(kind);
    if (value == 0 || value > DESCRIPTORS.size())
        throw std::runtime_error("P1-OnDemandOT-event-kind");
    const auto& result = DESCRIPTORS.at(value - 1);
    if (result.kind != kind)
        throw std::runtime_error("P1-OnDemandOT-descriptor-order");
    return result;
}

std::vector<OnDemandOtManifestStep> recompute_ondemand_ot_branch_manifest(
        std::uint64_t round, std::span<const OnDemandOtMapBranch> calls,
        std::uint64_t local_role, std::uint64_t player_count,
        bool include_construct, bool include_terminal) {
    if (round == 0 || round > 2 || player_count != 3 ||
        local_role >= player_count || calls.empty() ||
        (include_construct && round != 1) ||
        (include_terminal && round != 2))
        throw std::runtime_error("P1-OnDemandOT-manifest-input");
    for (std::size_t index = 0; index < calls.size(); ++index) {
        const auto expected = round == 1 && index == 0 ?
            OnDemandOtMapBranch::MissingCreate :
            OnDemandOtMapBranch::ExistingReuse;
        if (calls[index] != expected)
            throw std::runtime_error("P1-OnDemandOT-manifest-branch");
    }

    std::vector<OnDemandOtManifestStep> result;
    const auto add = [&](OnDemandOtEventKind kind,
                         OnDemandOtMapBranch branch,
                         std::uint64_t peer_index = 0,
                         std::uint64_t peer_role = 0) {
        result.push_back({kind, branch, peer_index, peer_role});
    };
    if (include_construct)
        add(OnDemandOtEventKind::Construct, OnDemandOtMapBranch::None);
    add(OnDemandOtEventKind::RoundBegin, OnDemandOtMapBranch::None);
    for (const auto branch : calls) {
        add(OnDemandOtEventKind::MapLookup, branch);
        if (branch == OnDemandOtMapBranch::MissingCreate) {
            add(OnDemandOtEventKind::MapEntryCreateBegin, branch);
            add(OnDemandOtEventKind::PrngBeforeChoiceConsume, branch);
            add(OnDemandOtEventKind::PrngAfterChoiceConsume, branch);
            for (std::uint64_t peer_index = 0;
                 peer_index < player_count - 1; ++peer_index) {
                const auto peer = peer_role_for(local_role, peer_index);
                add(OnDemandOtEventKind::OtSetupWorkerBegin, branch,
                    peer_index, peer);
                add(OnDemandOtEventKind::OtSetupWorkerEnd, branch,
                    peer_index, peer);
            }
            add(OnDemandOtEventKind::MapEntryCreated, branch);
        }
        add(OnDemandOtEventKind::GetFreshBegin, branch);
        for (std::uint64_t peer_index = 0;
             peer_index < player_count - 1; ++peer_index) {
            const auto peer = peer_role_for(local_role, peer_index);
            add(OnDemandOtEventKind::OtExtendBefore, branch,
                peer_index, peer);
            add(OnDemandOtEventKind::OtSeededInitialAdvance, branch,
                peer_index, peer);
            add(OnDemandOtEventKind::OtExtendStoredAdvance, branch,
                peer_index, peer);
            add(OnDemandOtEventKind::OtExtendReturnedAdvance, branch,
                peer_index, peer);
        }
        add(OnDemandOtEventKind::GetFreshEnd, branch);
    }
    add(OnDemandOtEventKind::RoundEnd, OnDemandOtMapBranch::None);
    if (include_terminal) {
        add(OnDemandOtEventKind::MapDestructorBegin,
            OnDemandOtMapBranch::ExistingReuse);
        add(OnDemandOtEventKind::MapDestructorTerminal,
            OnDemandOtMapBranch::ExistingReuse);
    }
    return result;
}

OnDemandOtCanonicalBytes::OnDemandOtCanonicalBytes(
        std::vector<unsigned char> value) {
    value_.swap(value);
}

OnDemandOtCanonicalBytes::OnDemandOtCanonicalBytes(
        OnDemandOtCanonicalBytes&& other) noexcept {
    value_.swap(other.value_);
}

OnDemandOtCanonicalBytes& OnDemandOtCanonicalBytes::operator=(
        OnDemandOtCanonicalBytes&& other) noexcept {
    if (this != &other) {
        wipe(value_);
        value_.swap(other.value_);
    }
    return *this;
}

OnDemandOtCanonicalBytes::~OnDemandOtCanonicalBytes() {
    wipe(value_);
}

OnDemandOtCanonicalBytes encode_ondemand_ot_event(
        const OnDemandOtEventView& value) {
    require_event_shape(value);
    std::vector<unsigned char> output;
    output.reserve(
        ONDEMAND_OT_STATE_DOMAIN.size() + 21U * 8U +
        ONDEMAND_OT_SELECTED_COMMIT.size() + 8U +
        ONDEMAND_OT_SELECTED_TYPE.size() + 8U +
        ONDEMAND_OT_MAP_TYPE.size() + 8U +
        ONDEMAND_OT_SOURCE_CLOSURE_MANIFEST.size() + 8U +
        ONDEMAND_OT_SOURCE_CLOSURE_SHA256.size() + 8U +
        value.source_site.size() + 8U +
        value.source_identity_sha256.size() + 8U +
        value.state_before.size() + value.stored_after.size() +
        value.returned_after.size() + value.prng_state.size() + 4U * 8U);
    output.insert(output.end(), ONDEMAND_OT_STATE_DOMAIN.begin(),
                  ONDEMAND_OT_STATE_DOMAIN.end());
    for (const auto field : {
             static_cast<std::uint64_t>(value.kind),
             static_cast<std::uint64_t>(value.transition),
             static_cast<std::uint64_t>(value.branch),
             static_cast<std::uint64_t>(value.abort_class),
             static_cast<std::uint64_t>(value.phase), value.sequence,
             value.persistent_child_epoch, value.player_epoch,
             value.root_thread_epoch, value.worker_thread_epoch, value.round,
             value.call_in_round, value.map_entry_epoch, value.local_role,
             value.player_count, value.peer_role, value.peer_index,
             value.map_size_before, value.map_size_after,
             static_cast<std::uint64_t>(value.map_entry_found),
             static_cast<std::uint64_t>(value.source_succeeded)})
        append_u64(output, field);
    append_text(output, ONDEMAND_OT_SELECTED_COMMIT);
    append_text(output, ONDEMAND_OT_SELECTED_TYPE);
    append_text(output, ONDEMAND_OT_MAP_TYPE);
    append_text(output, ONDEMAND_OT_SOURCE_CLOSURE_MANIFEST);
    append_text(output, ONDEMAND_OT_SOURCE_CLOSURE_SHA256);
    append_text(output, value.source_site);
    append_text(output, value.source_identity_sha256);
    append_bytes(output, value.state_before);
    append_bytes(output, value.stored_after);
    append_bytes(output, value.returned_after);
    append_bytes(output, value.prng_state);
    return OnDemandOtCanonicalBytes(std::move(output));
}

struct OnDemandOtStateScope::Storage final {
    OnDemandOtStateHook* hook{};
    const void* source_player{};
    std::thread::id root_thread;
    std::uint64_t persistent_child_epoch{};
    std::uint64_t player_epoch{};
    std::uint64_t root_thread_epoch{};
    std::uint64_t local_role{};
    std::uint64_t player_count{};
    std::uint64_t sequence{};
    std::uint64_t active_round{};
    std::uint64_t completed_rounds{};
    std::uint64_t call_in_round{};
    std::uint64_t map_entry_epoch{};
    std::uint64_t current_peer_index{};
    OnDemandOtPhase phase{OnDemandOtPhase::None};
    OnDemandOtMapBranch branch{OnDemandOtMapBranch::None};
    bool map_exists{};
    bool prng_before_seen{};
    bool prng_after_seen{};
    bool terminal{};
    bool unavailable_notified{};
    std::array<WorkerState, 2> workers{};
    std::vector<unsigned char> expected_entry_state;

    bool record(const OnDemandOtEventView& value) noexcept {
        return hook->record_ondemand_ot_event(value);
    }
    bool bind_worker(
            std::uint64_t peer_index, std::uint64_t peer_role,
            std::uint64_t& logical_epoch) noexcept {
        return hook->bind_ondemand_ot_worker_epoch(
            peer_index, peer_role, logical_epoch);
    }
    bool terminal_noexcept() noexcept {
        return hook->ondemand_ot_terminal_noexcept();
    }
    void unavailable_noexcept() noexcept {
        hook->ondemand_ot_unavailable_noexcept();
    }
};

namespace {

std::mutex registry_mutex;
OnDemandOtStateScope::Storage* active_scope{};
bool install_consumed{};

void notify_unavailable(OnDemandOtStateScope::Storage& value) noexcept {
    value.phase = OnDemandOtPhase::Poisoned;
    wipe(value.expected_entry_state);
    if (!value.unavailable_notified) {
        value.unavailable_notified = true;
        value.unavailable_noexcept();
    }
}

bool equal_bytes(
        std::span<const unsigned char> left,
        const std::vector<unsigned char>& right) noexcept {
    return left.size() == right.size() &&
        std::equal(left.begin(), left.end(), right.begin());
}

bool replace_secret(
        OnDemandOtStateScope::Storage& owner,
        std::span<const unsigned char> value) noexcept {
    try {
        std::vector<unsigned char> replacement(value.begin(), value.end());
        wipe(owner.expected_entry_state);
        owner.expected_entry_state.swap(replacement);
        return true;
    } catch (...) {
        notify_unavailable(owner);
        return false;
    }
}

bool valid_root(
        const OnDemandOtStateScope::Storage& value,
        const void* source_player) {
    return source_player != nullptr && source_player == value.source_player &&
        std::this_thread::get_id() == value.root_thread;
}

std::uint64_t current_map_size(
        const OnDemandOtStateScope::Storage& value) {
    return value.map_exists ? 1U : 0U;
}

bool emit(
        OnDemandOtStateScope::Storage& value, OnDemandOtEventKind kind,
        OnDemandOtMapBranch branch = OnDemandOtMapBranch::None,
        OnDemandOtAbortClass abort_class = OnDemandOtAbortClass::None,
        std::uint64_t worker_epoch = 0, std::uint64_t peer_role = 0,
        std::uint64_t peer_index = 0, std::uint64_t map_before = 0,
        std::uint64_t map_after = 0, bool found = false,
        bool succeeded = true,
        std::span<const unsigned char> state_before = {},
        std::span<const unsigned char> stored_after = {},
        std::span<const unsigned char> returned_after = {},
        std::span<const unsigned char> prng = {}) noexcept {
    if (value.sequence == std::numeric_limits<std::uint64_t>::max()) {
        notify_unavailable(value);
        return false;
    }
    const auto& descriptor = ondemand_ot_event_descriptor(kind);
    auto source_site = descriptor.source_site;
    auto source_sha = descriptor.source_identity_sha256;
    if (kind == OnDemandOtEventKind::Abort)
        std::tie(source_site, source_sha) = abort_source(abort_class);
    OnDemandOtEventView event{
        .kind = kind,
        .transition = descriptor.transition,
        .branch = branch,
        .abort_class = abort_class,
        .phase = value.phase,
        .sequence = ++value.sequence,
        .persistent_child_epoch = value.persistent_child_epoch,
        .player_epoch = value.player_epoch,
        .root_thread_epoch = value.root_thread_epoch,
        .worker_thread_epoch = worker_epoch,
        .round = value.active_round == 0 ? value.completed_rounds :
                                           value.active_round,
        .call_in_round = value.call_in_round,
        .map_entry_epoch = value.map_entry_epoch,
        .local_role = value.local_role,
        .player_count = value.player_count,
        .peer_role = peer_role,
        .peer_index = peer_index,
        .map_size_before = map_before,
        .map_size_after = map_after,
        .map_entry_found = found,
        .source_succeeded = succeeded,
        .source_site = source_site,
        .source_identity_sha256 = source_sha,
        .state_before = state_before,
        .stored_after = stored_after,
        .returned_after = returned_after,
        .prng_state = prng,
    };
    try {
        require_event_shape(event);
        if (!value.record(event)) {
            notify_unavailable(value);
            return false;
        }
        return true;
    } catch (...) {
        notify_unavailable(value);
        return false;
    }
}

void abort_locked(
        OnDemandOtStateScope::Storage& value,
        OnDemandOtAbortClass abort_class) noexcept {
    if (value.phase == OnDemandOtPhase::Poisoned || value.terminal) {
        notify_unavailable(value);
        return;
    }
    (void)emit(value, OnDemandOtEventKind::Abort, value.branch, abort_class,
               0, 0, 0, current_map_size(value), current_map_size(value),
               value.map_exists, false);
    notify_unavailable(value);
}

bool begin_round_locked(
        OnDemandOtStateScope::Storage& value, std::uint64_t round) noexcept {
    const auto expected_phase = round == 1 ? OnDemandOtPhase::Constructed :
                                            OnDemandOtPhase::BetweenRounds;
    if (value.phase != expected_phase || value.terminal ||
        round != value.completed_rounds + 1 || round > 2 ||
        std::this_thread::get_id() != value.root_thread ||
        value.map_exists != (round == 2)) {
        notify_unavailable(value);
        return false;
    }
    value.active_round = round;
    value.call_in_round = 0;
    value.phase = OnDemandOtPhase::Round;
    return emit(value, OnDemandOtEventKind::RoundBegin,
                OnDemandOtMapBranch::None, OnDemandOtAbortClass::None,
                0, 0, 0, current_map_size(value), current_map_size(value),
                value.map_exists);
}

bool end_round_locked(
        OnDemandOtStateScope::Storage& value, std::uint64_t round) noexcept {
    if (value.phase != OnDemandOtPhase::Round ||
        value.active_round != round || value.call_in_round == 0 ||
        !value.map_exists || std::this_thread::get_id() != value.root_thread) {
        notify_unavailable(value);
        return false;
    }
    value.phase = OnDemandOtPhase::BetweenRounds;
    if (!emit(value, OnDemandOtEventKind::RoundEnd,
              OnDemandOtMapBranch::None, OnDemandOtAbortClass::None,
              0, 0, 0, 1, 1, true))
        return false;
    value.completed_rounds = round;
    value.active_round = 0;
    value.call_in_round = 0;
    return true;
}

} // namespace

OnDemandOtStateScope::OnDemandOtStateScope(
        OnDemandOtStateHook& hook, const void* source_player,
        std::uint64_t persistent_child_epoch, std::uint64_t player_epoch,
        std::uint64_t root_thread_epoch, std::uint64_t local_role,
        std::uint64_t player_count)
    : storage_(std::make_unique<Storage>()) {
    if (source_player == nullptr || persistent_child_epoch == 0 ||
        player_epoch == 0 || root_thread_epoch == 0 || player_count != 3 ||
        local_role >= player_count)
        throw std::runtime_error("P1-OnDemandOT-scope-input");
    storage_->hook = &hook;
    storage_->source_player = source_player;
    storage_->root_thread = std::this_thread::get_id();
    storage_->persistent_child_epoch = persistent_child_epoch;
    storage_->player_epoch = player_epoch;
    storage_->root_thread_epoch = root_thread_epoch;
    storage_->local_role = local_role;
    storage_->player_count = player_count;
    storage_->phase = OnDemandOtPhase::Constructed;
    std::lock_guard lock(registry_mutex);
    if (active_scope != nullptr || install_consumed)
        throw std::runtime_error("P1-OnDemandOT-scope-one-use");
    install_consumed = true;
    active_scope = storage_.get();
    (void)emit(*storage_, OnDemandOtEventKind::Construct);
}

OnDemandOtStateScope::~OnDemandOtStateScope() {
    if (!storage_) return;
    std::lock_guard lock(registry_mutex);
    if (active_scope == storage_.get()) {
        if (!storage_->terminal &&
            storage_->phase != OnDemandOtPhase::Poisoned)
            abort_locked(*storage_, OnDemandOtAbortClass::ScopeUnlinked);
        else if (!storage_->terminal)
            notify_unavailable(*storage_);
        active_scope = nullptr;
    }
    wipe(storage_->expected_entry_state);
}

bool OnDemandOtStateSourceBridge::capture_required_noexcept(
        const void* source_player, std::uint64_t local_role,
        std::uint64_t player_count) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!active_scope) return false;
    if (active_scope->source_player != source_player ||
        active_scope->local_role != local_role ||
        active_scope->player_count != player_count)
        notify_unavailable(*active_scope);
    return true;
}

bool OnDemandOtStateSourceBridge::capture_required_pointer_noexcept(
        const void* source_player) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!active_scope) return false;
    if (active_scope->source_player != source_player)
        notify_unavailable(*active_scope);
    return true;
}

bool OnDemandOtStateSourceBridge::map_lookup(
        const void* source_player, std::uint64_t map_size_before,
        bool found, std::span<const unsigned char> entry_before) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!active_scope) return false;
    auto& value = *active_scope;
    if (!valid_root(value, source_player) ||
        value.phase != OnDemandOtPhase::Round || map_size_before > 1 ||
        found != value.map_exists ||
        map_size_before != current_map_size(value) ||
        found != !entry_before.empty() ||
        (found && !equal_bytes(entry_before, value.expected_entry_state)) ||
        (!found && !value.expected_entry_state.empty())) {
        notify_unavailable(value);
        return true;
    }
    ++value.call_in_round;
    value.branch = found ? OnDemandOtMapBranch::ExistingReuse :
                           OnDemandOtMapBranch::MissingCreate;
    value.phase = found ? OnDemandOtPhase::LookupReady :
                          OnDemandOtPhase::LookupMissing;
    (void)emit(value, OnDemandOtEventKind::MapLookup, value.branch,
               OnDemandOtAbortClass::None, 0, 0, 0, map_size_before,
               map_size_before, found, true, entry_before);
    return true;
}

bool OnDemandOtStateSourceBridge::map_entry_create_begin(
        const void* source_player) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!active_scope) return false;
    auto& value = *active_scope;
    if (!valid_root(value, source_player) ||
        value.phase != OnDemandOtPhase::LookupMissing ||
        value.map_entry_epoch != 0 || value.active_round != 1 ||
        value.call_in_round != 1) {
        notify_unavailable(value);
        return true;
    }
    value.map_entry_epoch = 1;
    value.phase = OnDemandOtPhase::Creating;
    value.prng_before_seen = false;
    value.prng_after_seen = false;
    value.workers = {};
    (void)emit(value, OnDemandOtEventKind::MapEntryCreateBegin, value.branch);
    return true;
}

bool OnDemandOtStateSourceBridge::prng_before_choice_consume(
        const void* source_player,
        std::span<const unsigned char> exact_prng_state) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!active_scope) return false;
    auto& value = *active_scope;
    if (!valid_root(value, source_player) ||
        value.phase != OnDemandOtPhase::Creating ||
        value.prng_before_seen || value.prng_after_seen ||
        exact_prng_state.empty()) {
        notify_unavailable(value);
        return true;
    }
    value.prng_before_seen = true;
    (void)emit(value, OnDemandOtEventKind::PrngBeforeChoiceConsume,
               value.branch, OnDemandOtAbortClass::None, 0, 0, 0, 0, 0,
               false, true, {}, {}, {}, exact_prng_state);
    return true;
}

bool OnDemandOtStateSourceBridge::prng_after_choice_consume(
        const void* source_player,
        std::span<const unsigned char> exact_prng_state) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!active_scope) return false;
    auto& value = *active_scope;
    if (!valid_root(value, source_player) ||
        value.phase != OnDemandOtPhase::Creating ||
        !value.prng_before_seen || value.prng_after_seen ||
        exact_prng_state.empty()) {
        notify_unavailable(value);
        return true;
    }
    value.prng_after_seen = true;
    (void)emit(value, OnDemandOtEventKind::PrngAfterChoiceConsume,
               value.branch, OnDemandOtAbortClass::None, 0, 0, 0, 0, 0,
               false, true, {}, {}, {}, exact_prng_state);
    return true;
}

bool OnDemandOtStateSourceBridge::ot_setup_worker_begin(
        const void* source_player, std::uint64_t index,
        std::uint64_t peer) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!active_scope) return false;
    auto& value = *active_scope;
    const auto thread = std::this_thread::get_id();
    auto& worker = value.workers.at(
        index < value.workers.size() ? index : 0);
    if (source_player != value.source_player ||
        value.phase != OnDemandOtPhase::Creating ||
        !value.prng_after_seen || thread == value.root_thread ||
        index >= value.player_count - 1 ||
        peer != peer_role_for(value.local_role, index) ||
        worker.present ||
        std::any_of(value.workers.begin(), value.workers.end(),
                    [&](const auto& item) {
                        return item.present && item.thread == thread;
                    })) {
        notify_unavailable(value);
        return true;
    }
    std::uint64_t worker_epoch{};
    if (!value.bind_worker(index, peer, worker_epoch) ||
        worker_epoch == 0 || worker_epoch == value.root_thread_epoch ||
        std::any_of(value.workers.begin(), value.workers.end(),
                    [&](const auto& item) {
                        return item.present &&
                            item.logical_epoch == worker_epoch;
                    })) {
        notify_unavailable(value);
        return true;
    }
    worker = WorkerState{thread, worker_epoch, index, true, true, false};
    (void)emit(value, OnDemandOtEventKind::OtSetupWorkerBegin, value.branch,
               OnDemandOtAbortClass::None, worker_epoch, peer, index);
    return true;
}

bool OnDemandOtStateSourceBridge::ot_setup_worker_end(
        const void* source_player, std::uint64_t index,
        std::uint64_t peer, bool succeeded) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!active_scope) return false;
    auto& value = *active_scope;
    auto& worker = value.workers.at(
        index < value.workers.size() ? index : 0);
    if (source_player != value.source_player ||
        value.phase != OnDemandOtPhase::Creating ||
        index >= value.player_count - 1 ||
        peer != peer_role_for(value.local_role, index) ||
        !worker.present || worker.peer_index != index || !worker.active ||
        worker.ended || worker.thread != std::this_thread::get_id()) {
        notify_unavailable(value);
        return true;
    }
    worker.active = false;
    worker.ended = true;
    (void)emit(value, OnDemandOtEventKind::OtSetupWorkerEnd, value.branch,
               OnDemandOtAbortClass::None, worker.logical_epoch,
               peer, index, 0, 0, false, succeeded);
    if (!succeeded)
        abort_locked(value, OnDemandOtAbortClass::SetupWorkerException);
    return true;
}

bool OnDemandOtStateSourceBridge::map_entry_created(
        const void* source_player, std::uint64_t map_size_after,
        std::span<const unsigned char> entry_after) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!active_scope) return false;
    auto& value = *active_scope;
    const bool workers_complete = std::all_of(
        value.workers.begin(), value.workers.end(), [](const auto& item) {
            return item.present && item.ended && !item.active;
        });
    if (!valid_root(value, source_player) ||
        value.phase != OnDemandOtPhase::Creating ||
        !value.prng_before_seen || !value.prng_after_seen ||
        !workers_complete || map_size_after != 1 || entry_after.empty()) {
        notify_unavailable(value);
        return true;
    }
    if (!replace_secret(value, entry_after)) return true;
    value.map_exists = true;
    value.phase = OnDemandOtPhase::LookupReady;
    (void)emit(value, OnDemandOtEventKind::MapEntryCreated, value.branch,
               OnDemandOtAbortClass::None, 0, 0, 0, 0, 1, false, true, {},
               entry_after);
    return true;
}

bool OnDemandOtStateSourceBridge::get_fresh_begin(
        const void* source_player,
        std::span<const unsigned char> entry_before) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!active_scope) return false;
    auto& value = *active_scope;
    if (!valid_root(value, source_player) ||
        value.phase != OnDemandOtPhase::LookupReady || !value.map_exists ||
        entry_before.empty() ||
        !equal_bytes(entry_before, value.expected_entry_state)) {
        notify_unavailable(value);
        return true;
    }
    value.current_peer_index = 0;
    value.phase = OnDemandOtPhase::Fresh;
    (void)emit(value, OnDemandOtEventKind::GetFreshBegin, value.branch,
               OnDemandOtAbortClass::None, 0, 0, 0, 1, 1, true, true,
               entry_before);
    return true;
}

bool OnDemandOtStateSourceBridge::ot_extend_before(
        const void* source_player, std::uint64_t index,
        std::uint64_t peer,
        std::span<const unsigned char> setup_before) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!active_scope) return false;
    auto& value = *active_scope;
    if (!valid_root(value, source_player) ||
        value.phase != OnDemandOtPhase::Fresh ||
        index != value.current_peer_index ||
        peer != peer_role_for(value.local_role, index) ||
        setup_before.empty() ||
        !equal_bytes(setup_before, value.expected_entry_state)) {
        notify_unavailable(value);
        return true;
    }
    value.phase = OnDemandOtPhase::ExtendBefore;
    (void)emit(value, OnDemandOtEventKind::OtExtendBefore, value.branch,
               OnDemandOtAbortClass::None, 0, peer, index, 1, 1, true, true,
               setup_before);
    return true;
}

bool OnDemandOtStateSourceBridge::ot_seeded_initial_advance(
        const void* source_player, std::uint64_t index,
        std::uint64_t peer,
        std::span<const unsigned char> seeded_base) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!active_scope) return false;
    auto& value = *active_scope;
    if (!valid_root(value, source_player) ||
        value.phase != OnDemandOtPhase::ExtendBefore ||
        index != value.current_peer_index ||
        peer != peer_role_for(value.local_role, index) ||
        seeded_base.empty()) {
        notify_unavailable(value);
        return true;
    }
    value.phase = OnDemandOtPhase::SeededInitial;
    (void)emit(value, OnDemandOtEventKind::OtSeededInitialAdvance,
               value.branch, OnDemandOtAbortClass::None, 0, peer, index,
               1, 1, true, true, {}, {}, seeded_base);
    return true;
}

bool OnDemandOtStateSourceBridge::ot_extend_stored_advance(
        const void* source_player, std::uint64_t index,
        std::uint64_t peer,
        std::span<const unsigned char> stored_setup,
        std::span<const unsigned char> first_advanced_base) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!active_scope) return false;
    auto& value = *active_scope;
    if (!valid_root(value, source_player) ||
        value.phase != OnDemandOtPhase::SeededInitial ||
        index != value.current_peer_index ||
        peer != peer_role_for(value.local_role, index) ||
        stored_setup.empty() || first_advanced_base.empty()) {
        notify_unavailable(value);
        return true;
    }
    if (!replace_secret(value, stored_setup)) return true;
    value.phase = OnDemandOtPhase::StoredAdvanced;
    (void)emit(value, OnDemandOtEventKind::OtExtendStoredAdvance,
               value.branch, OnDemandOtAbortClass::None, 0, peer, index,
               1, 1, true, true, {}, stored_setup, first_advanced_base);
    return true;
}

bool OnDemandOtStateSourceBridge::ot_extend_returned_advance(
        const void* source_player, std::uint64_t index,
        std::uint64_t peer,
        std::span<const unsigned char> returned_base) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!active_scope) return false;
    auto& value = *active_scope;
    if (!valid_root(value, source_player) ||
        value.phase != OnDemandOtPhase::StoredAdvanced ||
        index != value.current_peer_index ||
        peer != peer_role_for(value.local_role, index) ||
        returned_base.empty()) {
        notify_unavailable(value);
        return true;
    }
    value.phase = OnDemandOtPhase::Fresh;
    (void)emit(value, OnDemandOtEventKind::OtExtendReturnedAdvance,
               value.branch, OnDemandOtAbortClass::None, 0, peer, index,
               1, 1, true, true, {}, {}, returned_base);
    ++value.current_peer_index;
    return true;
}

bool OnDemandOtStateSourceBridge::get_fresh_end(
        const void* source_player, std::uint64_t map_size_after,
        std::span<const unsigned char> stored_entry_after,
        std::span<const unsigned char> returned_setup) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!active_scope) return false;
    auto& value = *active_scope;
    if (!valid_root(value, source_player) ||
        value.phase != OnDemandOtPhase::Fresh ||
        value.current_peer_index != value.player_count - 1 ||
        map_size_after != 1 || stored_entry_after.empty() ||
        returned_setup.empty() ||
        !equal_bytes(stored_entry_after, value.expected_entry_state)) {
        notify_unavailable(value);
        return true;
    }
    value.phase = OnDemandOtPhase::Round;
    (void)emit(value, OnDemandOtEventKind::GetFreshEnd, value.branch,
               OnDemandOtAbortClass::None, 0, 0, 0, 1, 1, true, true, {},
               stored_entry_after, returned_setup);
    value.branch = OnDemandOtMapBranch::None;
    return true;
}

bool OnDemandOtStateSourceBridge::map_destructor_begin(
        const void* source_player, std::uint64_t map_size_before,
        std::span<const unsigned char> exact_map_state,
        std::span<const unsigned char> exact_entry_state) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!active_scope) return false;
    auto& value = *active_scope;
    if (!valid_root(value, source_player) ||
        value.phase != OnDemandOtPhase::BetweenRounds ||
        value.completed_rounds != 2 || !value.map_exists ||
        map_size_before != 1 || exact_map_state.empty() ||
        exact_entry_state.empty() ||
        !equal_bytes(exact_entry_state, value.expected_entry_state)) {
        abort_locked(value, OnDemandOtAbortClass::TerminalPrefixIncomplete);
        return true;
    }
    value.active_round = 2;
    value.phase = OnDemandOtPhase::Destructor;
    (void)emit(value, OnDemandOtEventKind::MapDestructorBegin,
               OnDemandOtMapBranch::ExistingReuse,
               OnDemandOtAbortClass::None, 0, 0, 0, 1, 1, true, true,
               exact_map_state, exact_entry_state);
    return true;
}

bool OnDemandOtStateSourceBridge::map_destructor_terminal(
        const void* source_player, std::uint64_t map_size_after) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!active_scope) return false;
    auto& value = *active_scope;
    if (!valid_root(value, source_player) ||
        value.phase != OnDemandOtPhase::Destructor ||
        value.completed_rounds != 2 || !value.map_exists ||
        map_size_after != 0) {
        abort_locked(value, OnDemandOtAbortClass::TerminalPrefixIncomplete);
        return true;
    }
    value.map_exists = false;
    wipe(value.expected_entry_state);
    value.phase = OnDemandOtPhase::Terminal;
    if (!emit(value, OnDemandOtEventKind::MapDestructorTerminal,
              OnDemandOtMapBranch::ExistingReuse,
              OnDemandOtAbortClass::None, 0, 0, 0, 1, 0, true))
        return true;
    value.terminal = value.terminal_noexcept();
    if (!value.terminal) notify_unavailable(value);
    return true;
}

void OnDemandOtStateSourceBridge::empty_map_destructor_noexcept() noexcept {
    std::lock_guard lock(registry_mutex);
    if (active_scope)
        abort_locked(*active_scope,
                     OnDemandOtAbortClass::TerminalPrefixIncomplete);
}

void OnDemandOtStateSourceBridge::setup_root_abort_noexcept(
        const void* source_player) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!active_scope) return;
    if (!valid_root(*active_scope, source_player))
        notify_unavailable(*active_scope);
    else
        abort_locked(*active_scope,
                     OnDemandOtAbortClass::SetupRootException);
}

void OnDemandOtStateSourceBridge::get_fresh_abort_noexcept(
        const void* source_player) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!active_scope) return;
    if (!valid_root(*active_scope, source_player))
        notify_unavailable(*active_scope);
    else
        abort_locked(*active_scope,
                     OnDemandOtAbortClass::GetFreshException);
}

void OnDemandOtStateSourceBridge::source_serialization_abort_noexcept(
        const void* source_player) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!active_scope) return;
    auto& value = *active_scope;
    const auto thread = std::this_thread::get_id();
    const bool bound_worker = std::any_of(
        value.workers.begin(), value.workers.end(), [&](const auto& item) {
            return item.present && item.thread == thread && item.active;
        });
    if (source_player != value.source_player ||
        (thread != value.root_thread && !bound_worker))
        notify_unavailable(value);
    else
        abort_locked(value, OnDemandOtAbortClass::SourceSerialization);
}

void OnDemandOtStateSourceBridge::unavailable_noexcept() noexcept {
    std::lock_guard lock(registry_mutex);
    if (active_scope) notify_unavailable(*active_scope);
}

#ifdef KPI_P1_ONDEMAND_OT_STATE_HOOK_TEST_SETUP
std::unique_ptr<OnDemandOtStateScope> OnDemandOtStateTestBridge::install(
        OnDemandOtStateHook& hook, const void* source_player,
        std::uint64_t persistent_child_epoch, std::uint64_t player_epoch,
        std::uint64_t root_thread_epoch, std::uint64_t local_role,
        std::uint64_t player_count) {
    return std::unique_ptr<OnDemandOtStateScope>(new OnDemandOtStateScope(
        hook, source_player, persistent_child_epoch, player_epoch,
        root_thread_epoch, local_role, player_count));
}

bool OnDemandOtStateTestBridge::round_begin(
        OnDemandOtStateScope& scope, std::uint64_t round) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!scope.storage_ || active_scope != scope.storage_.get()) return false;
    return begin_round_locked(*scope.storage_, round);
}

bool OnDemandOtStateTestBridge::round_end(
        OnDemandOtStateScope& scope, std::uint64_t round) noexcept {
    std::lock_guard lock(registry_mutex);
    if (!scope.storage_ || active_scope != scope.storage_.get()) return false;
    return end_round_locked(*scope.storage_, round);
}
#endif

} // namespace kpi::mpc::p1_private_state

namespace kpb::measurement::p1_state_capsule {

std::unique_ptr<::kpi::mpc::p1_private_state::OnDemandOtStateScope>
P1OnDemandOtMapStateAdapterFactoryBridge::install_source_scope(
        ::kpi::mpc::p1_private_state::OnDemandOtStateHook& hook,
        const void* source_player, std::uint64_t persistent_child_epoch,
        std::uint64_t player_epoch, std::uint64_t root_thread_epoch,
        std::uint64_t local_role, std::uint64_t player_count) {
    using Scope = ::kpi::mpc::p1_private_state::OnDemandOtStateScope;
    return std::unique_ptr<Scope>(new Scope(
        hook, source_player, persistent_child_epoch, player_epoch,
        root_thread_epoch, local_role, player_count));
}

bool P1OnDemandOtMapStateAdapterFactoryBridge::round_begin(
        ::kpi::mpc::p1_private_state::OnDemandOtStateScope& scope,
        std::uint64_t round) noexcept {
    using namespace ::kpi::mpc::p1_private_state;
    std::lock_guard lock(registry_mutex);
    if (!scope.storage_ || active_scope != scope.storage_.get()) return false;
    return begin_round_locked(*scope.storage_, round);
}

bool P1OnDemandOtMapStateAdapterFactoryBridge::round_end(
        ::kpi::mpc::p1_private_state::OnDemandOtStateScope& scope,
        std::uint64_t round) noexcept {
    using namespace ::kpi::mpc::p1_private_state;
    std::lock_guard lock(registry_mutex);
    if (!scope.storage_ || active_scope != scope.storage_.get()) return false;
    return end_round_locked(*scope.storage_, round);
}

} // namespace kpb::measurement::p1_state_capsule
