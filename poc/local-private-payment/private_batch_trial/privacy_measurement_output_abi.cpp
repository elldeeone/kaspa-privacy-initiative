#include "privacy_measurement_output_abi.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>

namespace kpb::measurement::runtime_bridge {
namespace {

constexpr std::size_t ATTEMPT_BYTES = 128;
constexpr std::size_t MAX_CATEGORY_ROWS = OUTPUT_ABI_CATEGORY_ROWS;
constexpr std::size_t WORKLOAD_BITMAP_BYTES = 36450;
constexpr std::size_t INPUT_MASK_BYTES = 1;
constexpr std::size_t OUTPUT_MASK_BYTES = 12;
constexpr std::size_t ROUND_JOINT_MASK_BYTES = 68;

class Reader final {
    std::span<const unsigned char> raw_;
    std::size_t at_{};
    bool ok_{true};
public:
    explicit Reader(std::span<const unsigned char> raw) : raw_(raw) {}
    std::span<const unsigned char> take(std::size_t count) {
        if (!ok_ || count > raw_.size() - std::min(at_, raw_.size())) {
            ok_ = false;
            return {};
        }
        auto result = raw_.subspan(at_, count);
        at_ += count;
        return result;
    }
    unsigned u8() {
        const auto value = take(1);
        return value.size() == 1 ? value[0] : 0;
    }
    unsigned u16() {
        const auto value = take(2);
        return value.size() == 2 ?
            (static_cast<unsigned>(value[0]) << 8 | value[1]) : 0;
    }
    std::uint32_t u32() {
        const auto value = take(4);
        if (value.size() != 4) return 0;
        return static_cast<std::uint32_t>(value[0]) << 24 |
               static_cast<std::uint32_t>(value[1]) << 16 |
               static_cast<std::uint32_t>(value[2]) << 8 | value[3];
    }
    Digest digest() {
        Digest result{};
        const auto value = take(result.size());
        if (value.size() == result.size())
            std::copy(value.begin(), value.end(), result.begin());
        return result;
    }
    bool ok() const { return ok_; }
    std::size_t at() const { return at_; }
};

bool all_zero(std::span<const unsigned char> value) {
    return std::all_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte == 0; });
}

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

template<std::size_t Size>
bool distinct_nonzero(const std::array<Digest, Size>& values) {
    for (std::size_t index = 0; index < Size; ++index) {
        if (!nonzero(values[index])) return false;
        for (std::size_t other = 0; other < index; ++other)
            if (values[index] == values[other]) return false;
    }
    return true;
}

bool attempt_character(unsigned char value) {
    return (value >= 'A' && value <= 'Z') ||
           (value >= 'a' && value <= 'z') ||
           (value >= '0' && value <= '9') || value == '_' || value == '-';
}

bool parse_binding(
        Reader& reader,
        OwnerScoreOutputBindingExpectation* parsed = nullptr) {
    const auto method = reader.digest();
    const auto selection = reader.digest();
    const auto trial = reader.take(16);
    if (!nonzero(method) || !nonzero(selection) || all_zero(trial))
        return false;
    const auto length = reader.u8();
    const auto attempt = reader.take(ATTEMPT_BYTES);
    if (length == 0 || length > ATTEMPT_BYTES ||
        !std::all_of(attempt.begin(), attempt.begin() + length,
                     attempt_character) ||
        !all_zero(attempt.subspan(length))) return false;
    if (parsed != nullptr) {
        parsed->method_sha256 = method;
        parsed->selection_sha256 = selection;
        std::copy(trial.begin(), trial.end(), parsed->trial_id.begin());
        parsed->attempt_length = static_cast<unsigned char>(length);
        std::copy(attempt.begin(), attempt.end(), parsed->attempt_id.begin());
    }
    return true;
}

template<std::size_t Size>
bool read_distinct_digests(Reader& reader) {
    std::array<Digest, Size> values{};
    for (auto& value : values) value = reader.digest();
    return distinct_nonzero(values);
}

bool parse_public_round(Reader& reader) {
    return nonzero(reader.digest()) && nonzero(reader.digest()) &&
           read_distinct_digests<3>(reader) &&
           read_distinct_digests<6>(reader) &&
           read_distinct_digests<6>(reader);
}

unsigned pair_index(unsigned left, unsigned right) {
    if (left > right) std::swap(left, right);
    unsigned result = 0;
    for (unsigned first = 0; first < left; ++first)
        result += 5 - first;
    return result + right - left - 1;
}

bool parse_constraints(Reader& reader) {
    std::array<bool, 18> inputs{};
    std::array<bool, 36> creators{};
    std::array<bool, 15> pairs{};
    std::array<bool, 135> nf_pairs{};
    int last_input = -1;
    int last_creator = -1;
    int last_pair = -1;
    int last_nf_pair = -1;

    const auto input_count = reader.u8();
    if (input_count > 18) return false;
    for (unsigned index = 0; index < 18; ++index) {
        const auto record = reader.take(1);
        if (record.size() != 1) return false;
        if (index >= input_count) {
            if (!all_zero(record)) return false;
            continue;
        }
        const auto value = record[0];
        const auto owner = value & 3U;
        const auto slot = value >> 2 & 3U;
        const auto provenance = value >> 4 & 1U;
        if ((value >> 5) != 0 || owner >= 3 || slot >= 3) return false;
        const auto key = (owner * 3 + slot) * 2 + provenance;
        if (inputs[key] || static_cast<int>(key) <= last_input) return false;
        inputs[key] = true;
        last_input = static_cast<int>(key);
    }

    const auto creator_count = reader.u8();
    if (creator_count > 36) return false;
    for (unsigned index = 0; index < 36; ++index) {
        const auto record = reader.take(1);
        if (record.size() != 1) return false;
        if (index >= creator_count) {
            if (!all_zero(record)) return false;
            continue;
        }
        const auto value = record[0];
        const auto owner = value & 3U;
        const auto slot = value >> 2 & 7U;
        const auto provenance = value >> 5 & 1U;
        if ((value >> 6) != 0 || owner >= 3 || slot >= 6) return false;
        const auto key = (owner * 6 + slot) * 2 + provenance;
        if (creators[key] || static_cast<int>(key) <= last_creator)
            return false;
        creators[key] = true;
        last_creator = static_cast<int>(key);
    }

    const auto pair_count = reader.u8();
    if (pair_count > 15) return false;
    for (unsigned index = 0; index < 15; ++index) {
        const auto record = reader.take(1);
        if (record.size() != 1) return false;
        if (index >= pair_count) {
            if (!all_zero(record)) return false;
            continue;
        }
        const auto value = record[0];
        const auto left = value & 7U;
        const auto right = value >> 3 & 7U;
        if ((value >> 6) != 0 || left >= 6 || right >= 6 || left >= right)
            return false;
        const auto key = pair_index(left, right);
        if (pairs[key] || static_cast<int>(key) <= last_pair) return false;
        pairs[key] = true;
        last_pair = static_cast<int>(key);
    }

    const auto nf_pair_count = reader.u8();
    if (nf_pair_count > 135) return false;
    for (unsigned index = 0; index < 135; ++index) {
        const auto record = reader.take(2);
        if (record.size() != 2) return false;
        if (index >= nf_pair_count) {
            if (!all_zero(record)) return false;
            continue;
        }
        const auto nf = record[0] & 3U;
        const auto left = record[0] >> 2 & 7U;
        const auto right = record[0] >> 5 & 7U;
        const auto provenance = record[1];
        if (nf >= 3 || left >= 6 || right >= 6 || left >= right ||
            provenance >= 3) return false;
        const auto key = (nf * 15 + pair_index(left, right)) * 3 +
                         provenance;
        if (nf_pairs[key] || static_cast<int>(key) <= last_nf_pair)
            return false;
        nf_pairs[key] = true;
        last_nf_pair = static_cast<int>(key);
    }
    return reader.u8() == 0;
}

struct CategoryBound {
    unsigned char artifacts{};
    unsigned char fields{};
};

constexpr std::array<CategoryBound, 32> PUBLIC_CATEGORY_BOUNDS{{
    {2, 4}, {2, 12}, {2, 4}, {2, 8}, {2, 2}, {2, 6}, {2, 4},
    {2, 4}, {2, 2}, {2, 2}, {2, 14}, {2, 4}, {2, 12},
}};
constexpr std::array<CategoryBound, 32> DISPATCHER_CATEGORY_BOUNDS{{
    {2, 4}, {2, 12}, {2, 2}, {2, 4}, {2, 2}, {2, 8}, {2, 2},
    {2, 2}, {2, 2}, {2, 6}, {2, 4}, {2, 2}, {2, 2}, {2, 4},
    {2, 4}, {2, 2}, {2, 2}, {2, 2}, {2, 2}, {2, 14}, {2, 4},
    {2, 2}, {2, 12},
}};
constexpr std::array<CategoryBound, 32> CORRUPT_CATEGORY_BOUNDS{{
    {2, 4}, {2, 26}, {2, 52}, {2, 12}, {2, 4}, {2, 2}, {2, 4},
    {2, 4}, {2, 4}, {2, 8}, {2, 2}, {2, 6}, {2, 4}, {2, 4},
    {2, 2}, {2, 2}, {2, 2}, {2, 12}, {2, 8}, {2, 8}, {2, 14},
    {2, 4}, {2, 12},
}};
constexpr std::array<CategoryBound, 32> UNION_CATEGORY_BOUNDS{{
    {2, 4}, {2, 26}, {2, 52}, {2, 12}, {2, 2}, {2, 4}, {2, 2},
    {2, 4}, {2, 4}, {2, 4}, {2, 2}, {2, 8}, {2, 2}, {2, 2},
    {2, 2}, {2, 6}, {2, 4}, {2, 2}, {2, 2}, {2, 4}, {2, 4},
    {2, 2}, {2, 2}, {4, 4}, {2, 2}, {2, 12}, {2, 8}, {2, 8},
    {2, 14}, {2, 4}, {2, 2}, {2, 12},
}};

constexpr std::array<unsigned, 4> CATEGORY_COUNTS{13, 23, 23, 32};
constexpr std::array<unsigned, 4> VIEW_ARTIFACT_COUNTS{4, 6, 8, 10};

const std::array<CategoryBound, 32>& category_bounds(unsigned view) {
    switch (view) {
    case 0: return PUBLIC_CATEGORY_BOUNDS;
    case 1: return DISPATCHER_CATEGORY_BOUNDS;
    case 2: return CORRUPT_CATEGORY_BOUNDS;
    default: return UNION_CATEGORY_BOUNDS;
    }
}

bool parse_categories(Reader& reader, unsigned view) {
    const auto& bounds = category_bounds(view);
    for (unsigned index = 0; index < MAX_CATEGORY_ROWS; ++index) {
        const auto row = reader.take(6);
        if (row.size() != 6) return false;
        if (index >= CATEGORY_COUNTS[view]) {
            if (!all_zero(row)) return false;
            continue;
        }
        const auto bound = bounds[index];
        const unsigned modeled = row[0], unmodeled = row[1], missing = row[2];
        const unsigned constraint = row[3], assumption = row[4],
                       unknown = row[5];
        if (modeled != bound.artifacts || unmodeled > bound.artifacts ||
            missing != 0 || constraint + assumption + unknown != bound.fields ||
            ((unknown > 0) != (unmodeled > 0))) return false;
    }
    return true;
}

std::uint64_t bitmap_count(std::span<const unsigned char> value) {
    std::uint64_t result = 0;
    for (const auto byte : value)
        result += std::popcount(static_cast<unsigned>(byte));
    return result;
}

bool same_magic(std::span<const unsigned char> value,
                const std::array<unsigned char, 8>& expected) {
    return value.size() == expected.size() &&
           std::equal(value.begin(), value.end(), expected.begin());
}

bool parse_observer_phase_v2(std::span<const unsigned char> raw) {
    if (raw.size() != OBSERVER_PHASE_V2_BYTES) return false;
    Reader reader(raw);
    if (!same_magic(reader.take(8), OBSERVER_PHASE_V2_MAGIC) ||
        reader.u16() != 1 ||
        reader.u16() != OBSERVER_PHASE_V2_BYTES ||
        reader.u8() != 4 || reader.u8() != 4 ||
        reader.u8() != 1 || reader.u8() != 2)
        return false;
    for (unsigned view = 0; view < 4; ++view) {
        if (reader.u8() != view + 1 || reader.u8() != 1) return false;
        const auto total = reader.u16();
        const auto deferred = reader.u16();
        const auto step2 = reader.u16();
        if (total != 4 || deferred != 4 || step2 != 0 ||
            total < deferred || total - deferred != step2)
            return false;
        for (const auto& expected : OBSERVER_PHASE_V2_RECORDS) {
            if (reader.u8() != expected.round ||
                reader.u8() != static_cast<unsigned char>(
                    ObserverPhaseArtifact::PublicProjection) ||
                reader.u8() != static_cast<unsigned char>(expected.family) ||
                reader.u8() != static_cast<unsigned char>(
                    ObserverPhaseResolution::
                        DirectConstraintPendingSourceAuthority) ||
                reader.u8() != static_cast<unsigned char>(
                    ObserverPhaseEvidence::
                        Step3AcceptedChainStateAndOutpointHistoryAuthority) ||
                reader.u8() != 0)
                return false;
        }
    }
    return reader.ok() && reader.at() == OBSERVER_PHASE_V2_BYTES;
}

bool parse_observer_step2_v3(std::span<const unsigned char> raw) {
    if (raw.size() != OBSERVER_STEP2_V3_BYTES) return false;
    Reader reader(raw);
    if (!same_magic(reader.take(8), OBSERVER_STEP2_V3_MAGIC) ||
        reader.u16() != 1 || reader.u16() != OBSERVER_STEP2_V3_BYTES ||
        reader.u8() != 4 ||
        reader.u8() != OBSERVER_STEP2_FAMILY_ROWS.size() ||
        reader.u8() != 5 || reader.u8() != 2 ||
        reader.u16() != 1 || reader.u16() != 0)
        return false;
    for (const auto expected : OBSERVER_STEP2_VIEW_TOTALS)
        if (reader.u16() != expected) return false;
    for (const auto expected : OBSERVER_STEP2_DEFERRED_STEP3_COUNTS)
        if (reader.u8() != expected) return false;
    if (reader.digest() != OBSERVER_STEP2_REGISTRY_IDENTITY ||
        reader.digest() != OBSERVER_STEP2_MODEL_IDENTITY)
        return false;
    for (const auto& expected : OBSERVER_STEP2_FAMILY_ROWS) {
        if (reader.u8() != expected.code) return false;
        for (const auto count : expected.counts)
            if (reader.u8() != count) return false;
        if (reader.u8() != static_cast<unsigned char>(
                expected.disposition)) return false;
    }
    return reader.u16() == OBSERVER_STEP2_EMPIRICAL_OPEN_MASK &&
           reader.u16() == 0 && reader.ok() &&
           reader.at() == OBSERVER_STEP2_V3_BYTES;
}

bool parse_observer(std::span<const unsigned char> raw) {
    if (raw.size() != OBSERVER_OUTPUT_ABI.exact_bytes) return false;
    Reader reader(raw);
    if (!same_magic(reader.take(8), OBSERVER_OUTPUT_ABI.magic) ||
        !parse_binding(reader) || !parse_public_round(reader) ||
        !parse_public_round(reader)) return false;
    std::array<Digest, 4> salts{};
    for (unsigned view = 0; view < 4; ++view) {
        salts[view] = reader.digest();
        if (!nonzero(salts[view])) return false;
        for (unsigned prior = 0; prior < view; ++prior)
            if (salts[prior] == salts[view]) return false;
        if (!parse_constraints(reader) || !parse_constraints(reader))
            return false;
        const auto modeled = reader.u8();
        const auto unmodeled = reader.u8();
        const auto missing = reader.u8();
        const auto terminal = reader.u8();
        if (modeled != VIEW_ARTIFACT_COUNTS[view] ||
            unmodeled > modeled || missing != 0 || terminal != 1 ||
            !parse_categories(reader, view)) return false;
        const auto cross = reader.u8();
        const auto flags = reader.u8();
        if (cross > 36 || (flags & ~3U) != 0 ||
            !nonzero(reader.digest()) || !nonzero(reader.digest()))
            return false;
        const auto honest = reader.u32();
        const auto bitmap = reader.take(WORKLOAD_BITMAP_BYTES);
        if (honest > bitmap_count(bitmap)) return false;
    }
    if (reader.at() != OBSERVER_PHASE_V2_OFFSET ||
        !parse_observer_phase_v2(reader.take(OBSERVER_PHASE_V2_BYTES)))
        return false;
    if (reader.at() != OBSERVER_STEP2_V3_OFFSET ||
        !parse_observer_step2_v3(reader.take(OBSERVER_STEP2_V3_BYTES)))
        return false;
    return reader.ok() && reader.at() == OBSERVER_OUTPUT_ABI.used_bytes &&
           all_zero(reader.take(raw.size() - reader.at())) && reader.ok();
}

bool bits_clear_after(std::span<const unsigned char> value,
                      std::uint64_t bit_count) {
    if (bit_count > value.size() * 8ULL) return false;
    const auto complete = static_cast<std::size_t>(bit_count / 8);
    const auto remainder = static_cast<unsigned>(bit_count % 8);
    if (remainder != 0) {
        const auto mask = static_cast<unsigned char>(0xffU << remainder);
        if ((value[complete] & mask) != 0) return false;
    }
    const auto start = complete + (remainder != 0 ? 1 : 0);
    return all_zero(value.subspan(start));
}

bool parse_counters(Reader& reader) {
    const auto eligible_inputs = reader.u8();
    const auto eligible_outputs = reader.u8();
    const auto correct_inputs = reader.u8();
    const auto wrong_inputs = reader.u8();
    const auto correct_outputs = reader.u8();
    const auto wrong_outputs = reader.u8();
    const auto correct_pairs = reader.u8();
    const auto wrong_pairs = reader.u8();
    const auto floor = reader.u8();
    return eligible_inputs <= 1 && eligible_outputs <= 2 &&
           correct_inputs <= 1 && wrong_inputs <= 1 &&
           correct_outputs <= 2 && wrong_outputs <= 2 &&
           correct_pairs <= 1 && wrong_pairs <= 1 && floor <= 1 &&
           correct_inputs + wrong_inputs <= eligible_inputs &&
           correct_outputs + wrong_outputs <= eligible_outputs &&
           correct_pairs + wrong_pairs <= eligible_inputs;
}

struct CandidateCounts {
    unsigned inputs{};
    unsigned outputs{};
    unsigned joint{};
};

bool parse_score(
        std::span<const unsigned char> raw,
        const OwnerScoreOutputBindingExpectation* expected = nullptr) {
    if (raw.size() != OWNER_SCORE_OUTPUT_ABI.exact_bytes) return false;
    Reader reader(raw);
    OwnerScoreOutputBindingExpectation parsed{};
    if (!same_magic(reader.take(8), OWNER_SCORE_OUTPUT_ABI.magic) ||
        !parse_binding(reader, &parsed)) return false;
    parsed.run_selection_sha256 = reader.digest();
    parsed.owner = reader.u8();
    if (!nonzero(parsed.run_selection_sha256) || parsed.owner >= 3 ||
        (expected != nullptr && parsed != *expected)) return false;
    std::array<Digest, 4> seals{};
    for (unsigned view = 0; view < 4; ++view) {
        seals[view] = reader.digest();
        if (!nonzero(seals[view])) return false;
        for (unsigned prior = 0; prior < view; ++prior)
            if (seals[prior] == seals[view]) return false;
        std::array<CandidateCounts, 2> counts{};
        for (auto& value : counts) {
            value.inputs = reader.u8();
            value.outputs = reader.u8();
            value.joint = reader.u16();
            if (value.inputs > 6 || value.outputs > 90 ||
                value.joint > 540 ||
                value.joint > value.inputs * value.outputs) return false;
        }
        for (unsigned round = 0; round < 2; ++round) {
            for (unsigned index = 0; index < 2; ++index)
                if (!bits_clear_after(reader.take(INPUT_MASK_BYTES),
                                      counts[round].inputs)) return false;
            for (unsigned index = 0; index < 2; ++index)
                if (!bits_clear_after(reader.take(OUTPUT_MASK_BYTES),
                                      counts[round].outputs)) return false;
            for (unsigned index = 0; index < 2; ++index)
                if (!bits_clear_after(reader.take(ROUND_JOINT_MASK_BYTES),
                                      counts[round].joint)) return false;
            if (!parse_counters(reader)) return false;
        }
        const auto workload = reader.u32();
        if (workload > OUTPUT_ABI_MAX_WORKLOAD_CANDIDATES) return false;
        for (unsigned index = 0; index < 2; ++index)
            if (!bits_clear_after(reader.take(WORKLOAD_BITMAP_BYTES),
                                  workload)) return false;
        if (!parse_counters(reader) || !parse_counters(reader)) return false;
    }
    return reader.ok() && reader.at() == OWNER_SCORE_OUTPUT_ABI.used_bytes &&
           all_zero(reader.take(raw.size() - reader.at())) && reader.ok();
}

#ifdef KPB_MEASUREMENT_OUTPUT_ABI_TEST_SETUP
class TestWriter final {
    std::vector<unsigned char> bytes_;
public:
    explicit TestWriter(std::size_t reserve) { bytes_.reserve(reserve); }
    void raw(std::span<const unsigned char> value) {
        bytes_.insert(bytes_.end(), value.begin(), value.end());
    }
    void zeros(std::size_t count) { bytes_.insert(bytes_.end(), count, 0); }
    void u8(unsigned value) {
        bytes_.push_back(static_cast<unsigned char>(value));
    }
    void u16(unsigned value) { u8(value >> 8); u8(value); }
    void u32(std::uint32_t value) {
        u8(value >> 24); u8(value >> 16); u8(value >> 8); u8(value);
    }
    void digest(unsigned char value) {
        bytes_.insert(bytes_.end(), 32, value);
    }
    void binding() {
        digest(0x11); digest(0x12);
        bytes_.insert(bytes_.end(), 16, 0x13);
        u8(1); u8('a'); zeros(ATTEMPT_BYTES - 1);
    }
    void constraints() {
        u8(0); zeros(18);
        u8(0); zeros(36);
        u8(0); zeros(15);
        u8(0); zeros(135 * 2);
        u8(0);
    }
    void counters() { zeros(9); }
    std::vector<unsigned char> finish(
            std::size_t used, std::size_t exact) {
        if (bytes_.size() != used) return {};
        zeros(exact - used);
        return std::move(bytes_);
    }
};

std::vector<unsigned char> test_observer_body() {
    TestWriter writer(OBSERVER_OUTPUT_ABI.exact_bytes);
    writer.raw(OBSERVER_OUTPUT_ABI.magic);
    writer.binding();
    for (unsigned round = 0; round < 2; ++round) {
        writer.digest(static_cast<unsigned char>(0x20 + round * 20));
        writer.digest(static_cast<unsigned char>(0x21 + round * 20));
        for (unsigned index = 0; index < 3; ++index)
            writer.digest(static_cast<unsigned char>(0x22 + round * 20 + index));
        for (unsigned index = 0; index < 6; ++index)
            writer.digest(static_cast<unsigned char>(0x26 + round * 20 + index));
        for (unsigned index = 0; index < 6; ++index)
            writer.digest(static_cast<unsigned char>(0x30 + round * 20 + index));
    }
    for (unsigned view = 0; view < 4; ++view) {
        writer.digest(static_cast<unsigned char>(0x70 + view));
        writer.constraints(); writer.constraints();
        writer.u8(VIEW_ARTIFACT_COUNTS[view]);
        writer.u8(0); writer.u8(0); writer.u8(1);
        const auto& bounds = category_bounds(view);
        for (unsigned index = 0; index < MAX_CATEGORY_ROWS; ++index) {
            if (index < CATEGORY_COUNTS[view]) {
                writer.u8(bounds[index].artifacts);
                writer.u8(0); writer.u8(0);
                writer.u8(bounds[index].fields);
                writer.u8(0); writer.u8(0);
            } else {
                writer.zeros(6);
            }
        }
        writer.u8(0); writer.u8(0);
        writer.digest(static_cast<unsigned char>(0x80 + view));
        writer.digest(static_cast<unsigned char>(0x90 + view));
        writer.u32(0); writer.zeros(WORKLOAD_BITMAP_BYTES);
    }
    writer.raw(OBSERVER_PHASE_V2_MAGIC);
    writer.u16(1); writer.u16(OBSERVER_PHASE_V2_BYTES);
    writer.u8(4); writer.u8(4); writer.u8(1); writer.u8(2);
    for (unsigned view = 0; view < 4; ++view) {
        writer.u8(view + 1); writer.u8(1);
        writer.u16(4); writer.u16(4); writer.u16(0);
        for (const auto& record : OBSERVER_PHASE_V2_RECORDS) {
            writer.u8(record.round);
            writer.u8(static_cast<unsigned char>(
                ObserverPhaseArtifact::PublicProjection));
            writer.u8(static_cast<unsigned char>(record.family));
            writer.u8(static_cast<unsigned char>(
                ObserverPhaseResolution::
                    DirectConstraintPendingSourceAuthority));
            writer.u8(static_cast<unsigned char>(
                ObserverPhaseEvidence::
                    Step3AcceptedChainStateAndOutpointHistoryAuthority));
            writer.u8(0);
        }
    }
    writer.raw(OBSERVER_STEP2_V3_MAGIC);
    writer.u16(1); writer.u16(OBSERVER_STEP2_V3_BYTES);
    writer.u8(4); writer.u8(OBSERVER_STEP2_FAMILY_ROWS.size());
    writer.u8(5); writer.u8(2); writer.u16(1); writer.u16(0);
    for (const auto total : OBSERVER_STEP2_VIEW_TOTALS) writer.u16(total);
    for (const auto count : OBSERVER_STEP2_DEFERRED_STEP3_COUNTS)
        writer.u8(count);
    writer.raw(OBSERVER_STEP2_REGISTRY_IDENTITY);
    writer.raw(OBSERVER_STEP2_MODEL_IDENTITY);
    for (const auto& row : OBSERVER_STEP2_FAMILY_ROWS) {
        writer.u8(row.code);
        for (const auto count : row.counts) writer.u8(count);
        writer.u8(static_cast<unsigned char>(row.disposition));
    }
    writer.u16(OBSERVER_STEP2_EMPIRICAL_OPEN_MASK); writer.u16(0);
    return writer.finish(OBSERVER_OUTPUT_ABI.used_bytes,
                         OBSERVER_OUTPUT_ABI.exact_bytes);
}

std::vector<unsigned char> test_score_body(
        const OwnerScoreOutputBindingExpectation& expected) {
    if (expected.owner >= 3 || expected.attempt_length == 0 ||
        expected.attempt_length > expected.attempt_id.size()) return {};
    TestWriter writer(OWNER_SCORE_OUTPUT_ABI.exact_bytes);
    writer.raw(OWNER_SCORE_OUTPUT_ABI.magic);
    writer.raw(expected.method_sha256);
    writer.raw(expected.selection_sha256);
    writer.raw(expected.trial_id);
    writer.u8(expected.attempt_length);
    writer.raw(expected.attempt_id);
    writer.raw(expected.run_selection_sha256);
    writer.u8(expected.owner);
    for (unsigned view = 0; view < 4; ++view) {
        writer.digest(static_cast<unsigned char>(0xb0 + view));
        for (unsigned round = 0; round < 2; ++round) {
            writer.u8(0); writer.u8(0); writer.u16(0);
        }
        for (unsigned round = 0; round < 2; ++round) {
            writer.zeros(2 * INPUT_MASK_BYTES);
            writer.zeros(2 * OUTPUT_MASK_BYTES);
            writer.zeros(2 * ROUND_JOINT_MASK_BYTES);
            writer.counters();
        }
        writer.u32(0);
        writer.zeros(2 * WORKLOAD_BITMAP_BYTES);
        writer.counters(); writer.counters();
    }
    return writer.finish(OWNER_SCORE_OUTPUT_ABI.used_bytes,
                         OWNER_SCORE_OUTPUT_ABI.exact_bytes);
}

OwnerScoreOutputBindingExpectation default_test_score_expectation(
        unsigned owner) {
    OwnerScoreOutputBindingExpectation expected{};
    expected.method_sha256.fill(0x11);
    expected.selection_sha256.fill(0x12);
    expected.trial_id.fill(0x13);
    expected.attempt_length = 1;
    expected.attempt_id[0] = 'a';
    expected.run_selection_sha256.fill(0xa0);
    expected.owner = owner;
    return expected;
}
#endif

} // namespace

bool validate_measurement_output_abi(
        RuntimeChildRole role,
        std::span<const unsigned char> raw) noexcept {
    try {
        if (role == RuntimeChildRole::Observer) return parse_observer(raw);
        if (role == RuntimeChildRole::OwnerScore) return parse_score(raw);
        return false;
    } catch (...) {
        return false;
    }
}

bool validate_owner_score_output_abi_for_expected_lineage(
        std::span<const unsigned char> raw,
        const OwnerScoreOutputBindingExpectation& expected) noexcept {
    try {
        return parse_score(raw, &expected);
    } catch (...) {
        return false;
    }
}

bool validate_observer_phase_v2_section(
        std::span<const unsigned char> raw) noexcept {
    try {
        return parse_observer_phase_v2(raw);
    } catch (...) {
        return false;
    }
}

bool validate_observer_step2_v3_section(
        std::span<const unsigned char> raw) noexcept {
    try {
        return parse_observer_step2_v3(raw);
    } catch (...) {
        return false;
    }
}

#ifdef KPB_MEASUREMENT_OUTPUT_ABI_TEST_SETUP
std::vector<unsigned char> test_only_measurement_output_abi_body(
        RuntimeChildRole role, unsigned owner) {
    if (role == RuntimeChildRole::Observer && owner == NO_OWNER)
        return test_observer_body();
    if (role == RuntimeChildRole::OwnerScore)
        return test_score_body(default_test_score_expectation(owner));
    return {};
}


std::vector<unsigned char> test_only_owner_score_output_abi_body(
        const OwnerScoreOutputBindingExpectation& expected) {
    return test_score_body(expected);
}
#endif

} // namespace kpb::measurement::runtime_bridge
