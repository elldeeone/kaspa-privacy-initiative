#include "privacy_selected_producer_byte_schedule_authority.hpp"
#include "privacy_measurement_run_binding_wire.hpp"

#include <limits>
#include <openssl/sha.h>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace kpb::measurement::producer_schedule {
namespace {

enum class CompleteProducerByteBoundKind : std::uint8_t {
    ExactBytes = 1,
    ProtocolUpperBound = 2,
};

struct CompleteProducerByteScheduleSlot {
    unsigned ordinal{};
    unsigned round{};
    CaptureKind kind{};
    unsigned fixed_fd{};
    ProducerWireGrammar grammar{};
    CompleteProducerByteBoundKind bound_kind{};
    std::uint64_t max_wire_bytes{};
    WorkerBinding writer;
    Digest source_derivation_identity{};
};

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

constexpr std::uint64_t EVENT_HEADER_BYTES = 17;
constexpr std::uint64_t P1_CHUNK_HEADER_BYTES = 112;
constexpr std::uint64_t P1_MAX_CHUNK_BYTES = 1U << 16;
constexpr std::array<std::uint64_t, 5> C1_RECORD_MAX_BYTES{
    1'202, 983, 983, 1'060, 1'059,
};

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right) {
    need(left <= std::numeric_limits<std::uint64_t>::max() - right);
    return left + right;
}

std::uint64_t checked_multiply(std::uint64_t left, std::uint64_t right) {
    if (left == 0 || right == 0) return 0;
    need(left <= std::numeric_limits<std::uint64_t>::max() / right);
    return left * right;
}

std::uint64_t event_frame(std::uint64_t payload) {
    return checked_add(EVENT_HEADER_BYTES, payload);
}

std::uint64_t public_projection_bytes() {
    // privacy_capture_hook.cpp::ProjectionChannel: fixed HELLO, exact 10,685B
    // financial projection, and empty END under the 17B event-frame grammar.
    auto result = checked_add(event_frame(358), event_frame(10'685));
    result = checked_add(result, event_frame(0));
    need(result == 11'094);
    return result;
}

std::uint64_t terminal_history_bound(Classification classification) {
    // privacy_terminal_capture_v2.cpp pre-network branch only.
    // Candidate has nine payload frames plus END; baseline has eleven plus END.
    // The payload sums use twenty decimal digits for each of five uint64 times.
    if (classification == Classification::HiddenCandidate) {
        const auto result = checked_add(5'282, checked_multiply(10, 17));
        need(result == 5'452);
        return result;
    }
    need(classification == Classification::TransparentBaseline);
    const auto result = checked_add(5'891, checked_multiply(12, 17));
    need(result == 6'095);
    return result;
}

std::uint64_t dispatcher_bound(Classification classification) {
    // privacy_capture_hook.cpp::DispatcherChannel with the fixed financial
    // owner cohort from financial/construction.hpp and owner_inputs_active.cpp.
    // Candidate has twelve payload frames plus END; baseline thirteen plus END.
    // Owner uploads are exactly 2,635,409 Fr32 values per owner. Every runtime
    // uint64 timestamp is charged at its maximum twenty-decimal-digit encoding.
    if (classification == Classification::HiddenCandidate) {
        const auto result = checked_add(3'620, checked_multiply(13, 17));
        need(result == 3'841);
        return result;
    }
    need(classification == Classification::TransparentBaseline);
    const auto result = checked_add(6'752, checked_multiply(14, 17));
    need(result == 6'990);
    return result;
}

std::uint64_t c1_capture_bound() {
    // c1_capture_supervisor.py frozen qualified no-retry schedule:
    // HELLO, META, exactly five ordered records, then END. The record maxima
    // charge every validated uint64 field at twenty decimal digits. Any retry
    // durably invalidates the whole fresh trial before commit or final output.
    auto result = checked_add(event_frame(364), event_frame(353));
    for (const auto payload : C1_RECORD_MAX_BYTES)
        result = checked_add(result, event_frame(payload));
    result = checked_add(result, event_frame(0));
    need(result == 6'140);
    return result;
}

ManifestComponent component(CaptureKind kind) {
    switch (kind) {
    case CaptureKind::PublicProjection:
        return ManifestComponent::FinancialCore;
    case CaptureKind::TerminalHistory:
        return ManifestComponent::TerminalCapture;
    case CaptureKind::Dispatcher:
        return ManifestComponent::Dispatcher;
    case CaptureKind::CorruptServer:
        return ManifestComponent::P1Capture;
    case CaptureKind::ColluderWallet:
        return ManifestComponent::C1Supervisor;
    }
    refuse();
}

const ManifestEntry& entry(const RunBinding& binding,
                           ManifestComponent selected) {
    const auto index = static_cast<unsigned>(selected) - 1;
    need(index < binding.finite_manifest.entries.size() &&
         binding.finite_manifest.entries[index].component == selected);
    return binding.finite_manifest.entries[index];
}

WorkerBinding worker(const ManifestEntry& value) {
    return {
        .source_identity = value.source_identity,
        .build_identity = value.build_identity,
        .runtime_identity = value.runtime_identity,
        .assets_identity = value.assets_identity,
        .pinned_executable_identity = value.pinned_executable_identity,
        .launcher_identity = value.launcher_identity,
    };
}

void append(std::vector<unsigned char>& out,
            std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}

void append(std::vector<unsigned char>& out, const Digest& value) {
    append(out, std::span<const unsigned char>(value));
}

void append(std::vector<unsigned char>& out, const WorkerBinding& value) {
    for (const auto* field : {
             &value.source_identity, &value.build_identity,
             &value.runtime_identity, &value.assets_identity,
             &value.pinned_executable_identity, &value.launcher_identity})
        append(out, *field);
}

void append_text(std::vector<unsigned char>& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}

void append_u64(std::vector<unsigned char>& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    need(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}

std::string_view descriptor(CaptureKind kind, Classification classification) {
    switch (kind) {
    case CaptureKind::PublicProjection:
        return "KPB_SOURCE_BOUND_PUBLIC_PROJECTION_V1:H17+P358+H17+P10685+H17";
    case CaptureKind::TerminalHistory:
        return classification == Classification::HiddenCandidate
            ? "KPB_SOURCE_BOUND_TERMINAL_V2_HIDDEN:10H17+P5282"
            : "KPB_SOURCE_BOUND_TERMINAL_V2_BASELINE:12H17+P5891";
    case CaptureKind::Dispatcher:
        return classification == Classification::HiddenCandidate
            ? "KPB_SOURCE_BOUND_DISPATCHER_V1_HIDDEN:13H17+P3620"
            : "KPB_SOURCE_BOUND_DISPATCHER_V1_BASELINE:14H17+P6752";
    case CaptureKind::CorruptServer:
        return "KPB_MISSING_P1_V9_SELECTED_MESSAGE_MULTIPLICITY_AND_PAYLOAD_SCHEDULE";
    case CaptureKind::ColluderWallet:
        return "KPB_SOURCE_BOUND_C1_QUALIFIED_NO_RETRY_V2:(H17+P364)+(H17+P353)+(H17+P1202)+(H17+P983)+(H17+P983)+(H17+P1060)+(H17+P1059)+H17";
    }
    refuse();
}

ProducerWireGrammar grammar(CaptureKind kind) {
    switch (kind) {
    case CaptureKind::PublicProjection:
        return ProducerWireGrammar::PublicProjectionEventV1;
    case CaptureKind::TerminalHistory:
        return ProducerWireGrammar::TerminalHistoryV2;
    case CaptureKind::Dispatcher:
        return ProducerWireGrammar::DispatcherEventV1;
    case CaptureKind::CorruptServer:
        return ProducerWireGrammar::P1ChunkV9;
    case CaptureKind::ColluderWallet:
        return ProducerWireGrammar::C1CaptureV2;
    }
    refuse();
}

ProducerByteBoundKind bound_kind(CaptureKind kind) {
    if (kind == CaptureKind::PublicProjection)
        return ProducerByteBoundKind::ExactBytes;
    if (kind == CaptureKind::CorruptServer)
        return ProducerByteBoundKind::Missing;
    return ProducerByteBoundKind::ProtocolUpperBound;
}

std::uint64_t bound(CaptureKind kind, Classification classification) {
    switch (kind) {
    case CaptureKind::PublicProjection:
        return public_projection_bytes();
    case CaptureKind::TerminalHistory:
        return terminal_history_bound(classification);
    case CaptureKind::Dispatcher:
        return dispatcher_bound(classification);
    case CaptureKind::CorruptServer:
        return 0;
    case CaptureKind::ColluderWallet:
        return c1_capture_bound();
    }
    refuse();
}

Digest slot_identity(
        const RunBinding& binding,
        const NonAuthorizingProducerByteScheduleSlot& slot) {
    std::vector<unsigned char> bytes;
    append_text(bytes, "KPB_SELECTED_PRODUCER_BYTE_SLOT_DERIVATION_V2\n");
    const auto canonical = wire::canonical_run_binding_bytes(binding);
    append(bytes, canonical);
    append_u64(bytes, slot.ordinal);
    append_u64(bytes, slot.round);
    bytes.push_back(static_cast<unsigned char>(slot.kind));
    append_u64(bytes, slot.fixed_fd);
    bytes.push_back(static_cast<unsigned char>(slot.grammar));
    bytes.push_back(static_cast<unsigned char>(slot.bound_kind));
    append_u64(bytes, slot.max_wire_bytes);
    append(bytes, slot.writer);
    append_text(bytes, descriptor(slot.kind, binding.classification));
    return hash(bytes);
}

Digest schedule_identity(
        const RunBinding& binding, const WorkerBinding& producer,
        const Digest& formula_identity,
        const std::array<NonAuthorizingProducerByteScheduleSlot, 10>& slots) {
    std::vector<unsigned char> bytes;
    append_text(bytes, "KPB_NONAUTHORIZING_PRODUCER_BYTE_SCHEDULE_BLOCKER_V2\n");
    const auto canonical = wire::canonical_run_binding_bytes(binding);
    append(bytes, canonical);
    append(bytes, producer);
    append(bytes, formula_identity);
    for (const auto& slot : slots) {
        append(bytes, slot.source_derivation_identity);
        append_u64(bytes, slot.max_wire_bytes);
    }
    return hash(bytes);
}

Digest derivation_formula_identity() {
    std::vector<unsigned char> bytes;
    append_text(bytes,
        "KPB_SELECTED_PRODUCER_BYTE_SCHEDULE_FORMULAS_V2\n");
    for (const auto classification : {
             Classification::HiddenCandidate,
             Classification::TransparentBaseline}) {
        for (unsigned value = 1; value <= 5; ++value) {
            const auto kind = static_cast<CaptureKind>(value);
            append_text(bytes, descriptor(kind, classification));
            append_u64(bytes, bound(kind, classification));
            bytes.push_back(static_cast<unsigned char>(bound_kind(kind)));
        }
    }
    return hash(bytes);
}

} // namespace

struct SelectedProducerByteScheduleAuthority::Storage {
    RunBinding binding;
    WorkerBinding producer_worker;
    Digest producer_executable_identity{};
    Digest producer_launcher_identity{};
    Digest schedule_derivation_source_identity{};
    Digest schedule_derivation_build_identity{};
    std::array<CompleteProducerByteScheduleSlot, 10> slots{};
    Digest schedule_identity{};
};

SelectedProducerByteScheduleAuthority::SelectedProducerByteScheduleAuthority(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) {
    need(storage_ != nullptr);
}

SelectedProducerByteScheduleAuthority::SelectedProducerByteScheduleAuthority(
        SelectedProducerByteScheduleAuthority&&) noexcept = default;
SelectedProducerByteScheduleAuthority::~SelectedProducerByteScheduleAuthority() =
    default;

NonAuthorizingProducerByteScheduleBlocker
derive_non_authorizing_source_bounded_schedule(const RunBinding& binding) {
    validate_measurement_run_binding(binding);
    NonAuthorizingProducerByteScheduleBlocker result{
        .schema = "kpb-nonauthorizing-producer-byte-schedule-blocker/v2",
        .binding = binding,
        .trial = binding.trial,
        .classification = binding.classification,
        .workload = binding.workload,
        .producer_worker = worker(entry(
            binding, ManifestComponent::Producer)),
    };
    result.producer_executable_identity =
        result.producer_worker.pinned_executable_identity;
    result.producer_launcher_identity =
        result.producer_worker.launcher_identity;
    result.schedule_derivation_formula_identity =
        derivation_formula_identity();
    for (unsigned ordinal = 0; ordinal < result.slots.size(); ++ordinal) {
        const auto round = ordinal / 5 + 1;
        const auto kind = static_cast<CaptureKind>(ordinal % 5 + 1);
        auto& slot = result.slots[ordinal];
        slot = {
            .ordinal = ordinal,
            .round = round,
            .kind = kind,
            .fixed_fd = 20 + ordinal,
            .grammar = grammar(kind),
            .bound_kind = bound_kind(kind),
            .max_wire_bytes = bound(kind, binding.classification),
            .writer = worker(entry(binding, component(kind))),
        };
        slot.source_derivation_identity = slot_identity(binding, slot);
        if (slot.bound_kind == ProducerByteBoundKind::Missing)
            ++result.missing_slot_count;
        else
            ++result.source_bounded_slot_count;
    }
    need(result.source_bounded_slot_count == 8 &&
         result.missing_slot_count == 2 &&
         result.slots[3].kind == CaptureKind::CorruptServer &&
         result.slots[3].fixed_fd == 23 &&
         result.slots[8].kind == CaptureKind::CorruptServer &&
         result.slots[8].fixed_fd == 28);
    result.schedule_identity = schedule_identity(
        binding, result.producer_worker,
        result.schedule_derivation_formula_identity, result.slots);
    result.schedule_derivation_source_bound = false;
    result.schedule_derivation_build_bound = false;
    result.complete = false;
    return result;
}

#ifdef KPB_SELECTED_PRODUCER_BYTE_SCHEDULE_TEST_SETUP
void test_only_verify_formula_overflow_controls() {
    need(c1_capture_bound() == 6'140);
    const auto refuses = [](auto&& operation) {
        try { operation(); }
        catch (const Refused&) { return true; }
        return false;
    };
    need(refuses([] {
        (void)checked_add(std::numeric_limits<std::uint64_t>::max(), 1);
    }));
    need(refuses([] {
        (void)checked_multiply(
            std::numeric_limits<std::uint64_t>::max(), 2);
    }));
}
#endif

static_assert(P1_CHUNK_HEADER_BYTES == 112);
static_assert(P1_MAX_CHUNK_BYTES == 65'536);

} // namespace kpb::measurement::producer_schedule
