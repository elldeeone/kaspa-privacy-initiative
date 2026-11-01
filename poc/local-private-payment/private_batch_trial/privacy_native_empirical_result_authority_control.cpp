#include "privacy_native_empirical_result_authority.hpp"

#include "privacy_measurement_run_binding_wire.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <openssl/sha.h>
#include <span>
#include <sys/mman.h>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace kpb::measurement;
using namespace kpb::measurement::empirical_result;

namespace {

constexpr std::array<unsigned char, 8> HISTORY_MAGIC{
    'K', 'P', 'B', 'E', 'M', 'P', 'H', '1'};
constexpr std::array<unsigned char, 8> CANDIDATE_MAGIC{
    'K', 'P', 'B', 'E', 'M', 'P', 'C', '1'};
constexpr std::array<unsigned char, 40> FIELD_AGGREGATE_DOMAIN{
    'K','P','B','_','N','A','T','I','V','E','_','E','M','P','I','R','I','C','A','L',
    '_','F','I','E','L','D','_','A','G','G','R','E','G','A','T','E','_','V','1','\n'};
constexpr std::size_t COMMON_HEADER_BYTES =
    16 + kpb::measurement::wire::RUN_BINDING_BYTES + 4;
constexpr std::size_t ATTEMPT_BYTES = 264;
constexpr std::size_t CANDIDATE_BYTES =
    32 + EMPIRICAL_OCCURRENCES * 32;

template<class Function>
void expect_refused(Function&& function) {
    bool refused = false;
    try { function(); } catch (const Refused&) { refused = true; }
    assert(refused);
}

Digest word(unsigned char value) {
    Digest result{};
    result.fill(value);
    return result;
}

Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    assert(SHA256(value.data(), value.size(), result.data()) != nullptr);
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

RunBinding binding(unsigned char seed = 0x10) {
    RunBinding result{};
    result.classification = Classification::HiddenCandidate;
    result.comparison_selection = word(seed);
    result.run_selection = word(static_cast<unsigned char>(seed + 1));
    result.trial = word(static_cast<unsigned char>(seed + 2));
    result.attempt = word(static_cast<unsigned char>(seed + 3));
    result.cohort = word(static_cast<unsigned char>(seed + 4));
    result.capture = word(static_cast<unsigned char>(seed + 5));
    result.method = word(static_cast<unsigned char>(seed + 6));
    result.workload = word(static_cast<unsigned char>(seed + 7));
    result.source_closure = word(static_cast<unsigned char>(seed + 8));
    result.runtime = word(static_cast<unsigned char>(seed + 9));
    result.outer_parent_process = word(
        static_cast<unsigned char>(seed + 10));
    result.outer_parent_executable = word(
        static_cast<unsigned char>(seed + 11));
    result.financial_runs = {word(0x20), word(0x21)};
    result.round_attempts = {word(0x22), word(0x23)};
    result.round_cohorts = {word(0x24), word(0x25)};
    result.round_capture_plans = {word(0x26), word(0x27)};
    result.projections = {word(0x28), word(0x29)};
    for (unsigned index = 0;
         index < result.finite_manifest.entries.size(); ++index) {
        const auto component_seed =
            static_cast<unsigned char>(0x40 + index * 7);
        result.finite_manifest.entries[index] = {
            .component = static_cast<ManifestComponent>(index + 1),
            .source_identity = word(component_seed),
            .build_identity = word(
                static_cast<unsigned char>(component_seed + 1)),
            .runtime_identity = word(
                static_cast<unsigned char>(component_seed + 2)),
            .assets_identity = word(
                static_cast<unsigned char>(component_seed + 3)),
            .pinned_executable_identity = word(
                static_cast<unsigned char>(component_seed + 4)),
            .launcher_identity = word(
                static_cast<unsigned char>(component_seed + 5)),
        };
    }
    result.finite_manifest.manifest_identity =
        recompute_finite_manifest_identity(result.finite_manifest.entries);
    result.finite_manifest.parent_recomputation_identity = word(0xfc);
    const auto& p1 = result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::P1Capture) - 1];
    result.capture_source = p1.source_identity;
    result.capture_build = p1.build_identity;
    result.capture_runtime = p1.runtime_identity;
    result.capture_launcher = p1.launcher_identity;
    result.observer_worker = worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Observer) - 1]);
    result.score_worker = worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::OwnerScore) - 1]);
    result.aggregate_worker = worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Aggregate) - 1]);
    validate_measurement_run_binding(result);
    return result;
}

void add_u32(std::vector<unsigned char>& out, std::uint32_t value) {
    for (unsigned shift : {0U, 8U, 16U, 24U})
        out.push_back(static_cast<unsigned char>(value >> shift));
}

void add_word(std::vector<unsigned char>& out, const Digest& value) {
    out.insert(out.end(), value.begin(), value.end());
}

void set_u32(std::vector<unsigned char>& out, std::size_t offset,
             std::uint32_t value) {
    assert(offset + 4 <= out.size());
    for (unsigned index = 0; index < 4; ++index)
        out[offset + index] =
            static_cast<unsigned char>(value >> (index * 8));
}

void add_header(std::vector<unsigned char>& out,
                const std::array<unsigned char, 8>& magic,
                const RunBinding& selected) {
    out.insert(out.end(), magic.begin(), magic.end());
    add_u32(out, 1);
    add_u32(out, 0);
    const auto encoded =
        kpb::measurement::wire::canonical_run_binding_bytes(selected);
    out.insert(out.end(), encoded.begin(), encoded.end());
    out.push_back(EMPIRICAL_ROUNDS);
    out.push_back(EMPIRICAL_FIELDS);
    out.push_back(0);
    out.push_back(0);
}

struct Attempt {
    Digest identity{};
    Digest capture{};
    EmpiricalAttemptOutcome outcome{};
    EmpiricalStreamState state{};
    std::array<Digest, EMPIRICAL_FIELDS> fields{};
};

using RoundAttempts = std::vector<Attempt>;
using Aggregates =
    std::array<std::array<Digest, EMPIRICAL_FIELDS>, EMPIRICAL_ROUNDS>;

Attempt attempt(unsigned char identity_seed, unsigned char capture_seed,
                EmpiricalAttemptOutcome outcome,
                EmpiricalStreamState state,
                unsigned char field_seed) {
    Attempt result{
        .identity = word(identity_seed),
        .capture = word(capture_seed),
        .outcome = outcome,
        .state = state,
    };
    for (unsigned field = 0; field < EMPIRICAL_FIELDS; ++field)
        result.fields[field] = word(
            static_cast<unsigned char>(field_seed + field));
    return result;
}

std::array<RoundAttempts, EMPIRICAL_ROUNDS> selected_attempts() {
    return {{
        {
            attempt(0x80, 0x90, EmpiricalAttemptOutcome::Aborted,
                    EmpiricalStreamState::PartialPayload, 0xa0),
            attempt(0x81, 0x91, EmpiricalAttemptOutcome::Complete,
                    EmpiricalStreamState::CompleteEnd, 0xa8),
        },
        {
            attempt(0x82, 0x92, EmpiricalAttemptOutcome::Complete,
                    EmpiricalStreamState::CompleteEnd, 0xb0),
        },
    }};
}

Digest aggregate(unsigned round, unsigned field,
                 const RoundAttempts& attempts) {
    std::vector<unsigned char> preimage;
    for (unsigned ordinal = 0; ordinal < attempts.size(); ++ordinal) {
        const auto& selected = attempts[ordinal];
        const Digest predecessor = ordinal == 0 ? Digest{} :
            attempts[ordinal - 1].identity;
        preimage.insert(preimage.end(), FIELD_AGGREGATE_DOMAIN.begin(),
                        FIELD_AGGREGATE_DOMAIN.end());
        preimage.push_back(static_cast<unsigned char>(round + 1));
        preimage.push_back(static_cast<unsigned char>(field + 1));
        add_u32(preimage, ordinal);
        add_word(preimage, selected.identity);
        add_word(preimage, predecessor);
        preimage.push_back(static_cast<unsigned char>(selected.outcome));
        preimage.push_back(static_cast<unsigned char>(selected.state));
        add_word(preimage, selected.capture);
        add_word(preimage, selected.fields[field]);
    }
    return hash(preimage);
}

std::pair<std::vector<unsigned char>, Aggregates> history_body(
        const RunBinding& selected) {
    auto attempts = selected_attempts();
    Aggregates aggregates{};
    std::vector<unsigned char> out;
    add_header(out, HISTORY_MAGIC, selected);
    for (unsigned round = 0; round < EMPIRICAL_ROUNDS; ++round) {
        out.push_back(static_cast<unsigned char>(round + 1));
        out.insert(out.end(), 3, 0);
        add_u32(out, static_cast<std::uint32_t>(attempts[round].size()));
        for (unsigned ordinal = 0;
             ordinal < attempts[round].size(); ++ordinal) {
            const auto& value = attempts[round][ordinal];
            add_u32(out, ordinal);
            add_word(out, value.identity);
            add_word(out, ordinal == 0 ? Digest{} :
                     attempts[round][ordinal - 1].identity);
            out.push_back(static_cast<unsigned char>(value.outcome));
            out.push_back(static_cast<unsigned char>(value.state));
            out.insert(out.end(), 2, 0);
            add_word(out, value.capture);
            for (const auto& field : value.fields) add_word(out, field);
        }
        for (unsigned field = 0; field < EMPIRICAL_FIELDS; ++field)
            aggregates[round][field] = aggregate(
                round, field, attempts[round]);
    }
    set_u32(out, 12, static_cast<std::uint32_t>(out.size()));
    return {std::move(out), aggregates};
}

std::vector<unsigned char> candidate_body(const RunBinding& selected,
                                          const Aggregates& aggregates) {
    std::vector<unsigned char> out;
    add_header(out, CANDIDATE_MAGIC, selected);
    for (unsigned candidate = 0;
         candidate < EMPIRICAL_CANDIDATES; ++candidate) {
        add_word(out, word(static_cast<unsigned char>(0xc0 + candidate)));
        for (unsigned round = 0; round < EMPIRICAL_ROUNDS; ++round)
            for (unsigned field = 0; field < EMPIRICAL_FIELDS; ++field) {
                auto predicted = aggregates[round][field];
                if (candidate == 1 && round == 0 && field == 0)
                    predicted = word(0xee);
                add_word(out, predicted);
            }
    }
    set_u32(out, 12, static_cast<std::uint32_t>(out.size()));
    assert(out.size() == COMMON_HEADER_BYTES +
           EMPIRICAL_CANDIDATES * CANDIDATE_BYTES);
    return out;
}

int sealed_read_fd(std::span<const unsigned char> value) {
    const int writer = ::memfd_create(
        "kpb-native-empirical-control", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    assert(writer >= 0);
    std::size_t at = 0;
    while (at < value.size()) {
        ssize_t amount;
        do {
            amount = ::write(writer, value.data() + at, value.size() - at);
        } while (amount < 0 && errno == EINTR);
        assert(amount > 0);
        at += static_cast<std::size_t>(amount);
    }
    constexpr int seals =
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    assert(::fcntl(writer, F_ADD_SEALS, seals) == 0);
    char path[64]{};
    assert(std::snprintf(path, sizeof(path), "/proc/self/fd/%d", writer) > 0);
    const int reader = ::open(path, O_RDONLY | O_CLOEXEC);
    assert(reader >= 0);
    assert(::close(writer) == 0);
    return reader;
}

std::array<int, 2> sealed_read_aliases(
        std::span<const unsigned char> value) {
    const int writer = ::memfd_create(
        "kpb-native-empirical-alias", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    assert(writer >= 0);
    std::size_t at = 0;
    while (at < value.size()) {
        const auto amount = ::write(
            writer, value.data() + at, value.size() - at);
        assert(amount > 0);
        at += static_cast<std::size_t>(amount);
    }
    constexpr int seals =
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    assert(::fcntl(writer, F_ADD_SEALS, seals) == 0);
    char path[64]{};
    assert(std::snprintf(path, sizeof(path), "/proc/self/fd/%d", writer) > 0);
    std::array<int, 2> readers{
        ::open(path, O_RDONLY | O_CLOEXEC),
        ::open(path, O_RDONLY | O_CLOEXEC),
    };
    assert(readers[0] >= 0 && readers[1] >= 0);
    assert(::close(writer) == 0);
    return readers;
}

void valid_internal_derivation_and_replay_refusal() {
    const auto selected = binding();
    const auto [history, aggregates] = history_body(selected);
    const auto candidates = candidate_body(selected, aggregates);
    auto history_authority =
        NativeEmpiricalResultDeriver::test_only_admit_history(
            selected, sealed_read_fd(history));
    auto candidate_authority =
        NativeEmpiricalResultDeriver::test_only_admit_candidate_set(
            selected, sealed_read_fd(candidates));
    auto result = NativeEmpiricalResultDeriver::derive(
        std::move(history_authority), std::move(candidate_authority));
    const auto summary = NativeEmpiricalResultDeriver::test_only_consume(
        std::move(result));
    assert(summary.candidate_match_masks[0] == 0x1);
    for (unsigned index = 1; index < EMPIRICAL_OCCURRENCES; ++index)
        assert(summary.candidate_match_masks[index] == 0x3);
    assert(summary.retained_candidate_mask == 0x1);
    assert((summary.bound_view_codes == std::array<std::uint8_t, 2>{3, 4}));
    expect_refused([&] {
        (void)NativeEmpiricalResultDeriver::test_only_consume(
            std::move(result));
    });
    auto fresh_candidates =
        NativeEmpiricalResultDeriver::test_only_admit_candidate_set(
            selected, sealed_read_fd(candidates));
    expect_refused([&] {
        (void)NativeEmpiricalResultDeriver::derive(
            std::move(history_authority), std::move(fresh_candidates));
    });
    auto fresh_history =
        NativeEmpiricalResultDeriver::test_only_admit_history(
            selected, sealed_read_fd(history));
    expect_refused([&] {
        (void)NativeEmpiricalResultDeriver::derive(
            std::move(fresh_history), std::move(fresh_candidates));
    });
}

void mutated_history_refuses() {
    const auto selected = binding();
    const auto [canonical, aggregates] = history_body(selected);
    const auto candidates = candidate_body(selected, aggregates);
    const std::size_t first_attempt = COMMON_HEADER_BYTES + 8;
    const std::size_t second_attempt = first_attempt + ATTEMPT_BYTES;
    std::vector<std::vector<unsigned char>> mutations;
    mutations.emplace_back(canonical.begin(), canonical.end() - 1);
    mutations.push_back(canonical);
    mutations.back().push_back(0);
    mutations.push_back(canonical);
    mutations.back()[second_attempt + 36] ^= 1;
    mutations.push_back(canonical);
    std::copy(mutations.back().begin() + first_attempt + 4,
              mutations.back().begin() + first_attempt + 36,
              mutations.back().begin() + second_attempt + 4);
    mutations.push_back(canonical);
    mutations.back()[second_attempt + 68] =
        static_cast<unsigned char>(EmpiricalAttemptOutcome::Partial);
    mutations.push_back(canonical);
    std::fill(mutations.back().begin() + first_attempt + 104,
              mutations.back().begin() + first_attempt + 136, 0);
    mutations.push_back(canonical);
    mutations.back()[COMMON_HEADER_BYTES] = 2;
    for (auto mutation : mutations) {
        if (mutation.size() >= 16)
            set_u32(mutation, 12,
                    static_cast<std::uint32_t>(mutation.size()));
        auto history_authority =
            NativeEmpiricalResultDeriver::test_only_admit_history(
                selected, sealed_read_fd(mutation));
        auto candidate_authority =
            NativeEmpiricalResultDeriver::test_only_admit_candidate_set(
                selected, sealed_read_fd(candidates));
        expect_refused([&] {
            (void)NativeEmpiricalResultDeriver::derive(
                std::move(history_authority),
                std::move(candidate_authority));
        });
    }
}

void mutated_candidates_and_cross_binding_refuse() {
    const auto selected = binding();
    const auto [history, aggregates] = history_body(selected);
    const auto canonical = candidate_body(selected, aggregates);
    const std::size_t first_mapping = COMMON_HEADER_BYTES;
    const std::size_t second_mapping =
        COMMON_HEADER_BYTES + CANDIDATE_BYTES;
    std::vector<std::vector<unsigned char>> mutations;
    mutations.emplace_back(canonical.begin(), canonical.end() - 1);
    mutations.push_back(canonical);
    mutations.back().push_back(0);
    mutations.push_back(canonical);
    std::copy(mutations.back().begin() + first_mapping,
              mutations.back().begin() + first_mapping + 32,
              mutations.back().begin() + second_mapping);
    mutations.push_back(canonical);
    std::fill(mutations.back().begin() + first_mapping + 32,
              mutations.back().begin() + first_mapping + 64, 0);
    mutations.push_back(canonical);
    std::fill(mutations.back().begin() + first_mapping + 32,
              mutations.back().begin() + first_mapping + 64, 0xef);
    mutations.push_back(canonical);
    mutations.back()[16] ^= 1;
    for (auto mutation : mutations) {
        if (mutation.size() >= 16)
            set_u32(mutation, 12,
                    static_cast<std::uint32_t>(mutation.size()));
        auto history_authority =
            NativeEmpiricalResultDeriver::test_only_admit_history(
                selected, sealed_read_fd(history));
        auto candidate_authority =
            NativeEmpiricalResultDeriver::test_only_admit_candidate_set(
                selected, sealed_read_fd(mutation));
        expect_refused([&] {
            (void)NativeEmpiricalResultDeriver::derive(
                std::move(history_authority),
                std::move(candidate_authority));
        });
    }
    auto other = binding(0x11);
    auto history_authority =
        NativeEmpiricalResultDeriver::test_only_admit_history(
            selected, sealed_read_fd(history));
    auto candidate_authority =
        NativeEmpiricalResultDeriver::test_only_admit_candidate_set(
            other, sealed_read_fd(candidate_body(other, aggregates)));
    expect_refused([&] {
        (void)NativeEmpiricalResultDeriver::derive(
            std::move(history_authority), std::move(candidate_authority));
    });
}

void aliases_and_writable_inputs_refuse() {
    const auto selected = binding();
    const auto [history, aggregates] = history_body(selected);
    const auto candidates = candidate_body(selected, aggregates);
    const auto aliases = sealed_read_aliases(candidates);
    auto history_alias =
        NativeEmpiricalResultDeriver::test_only_admit_history(
            selected, aliases[0]);
    auto candidate_alias =
        NativeEmpiricalResultDeriver::test_only_admit_candidate_set(
            selected, aliases[1]);
    expect_refused([&] {
        (void)NativeEmpiricalResultDeriver::derive(
            std::move(history_alias), std::move(candidate_alias));
    });

    const int writable = ::memfd_create(
        "kpb-native-empirical-writable", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    assert(writable >= 0);
    assert(::write(writable, history.data(), history.size()) ==
           static_cast<ssize_t>(history.size()));
    auto writable_history =
        NativeEmpiricalResultDeriver::test_only_admit_history(
            selected, writable);
    auto candidate_authority =
        NativeEmpiricalResultDeriver::test_only_admit_candidate_set(
            selected, sealed_read_fd(candidates));
    expect_refused([&] {
        (void)NativeEmpiricalResultDeriver::derive(
            std::move(writable_history), std::move(candidate_authority));
    });
}

} // namespace

int main() {
    static_assert(EMPIRICAL_EVIDENCE_FAMILY_CODE == 24);
    static_assert(EMPIRICAL_OCCURRENCE_MASK == 0x03ff);
    static_assert(EMPIRICAL_FIELD_PATHS[0] ==
        "attempt.abort_retry_partial_transcript");
    static_assert(EMPIRICAL_FIELD_PATHS[4] ==
        "wire.frames[].sequence_message_chunk_order");
    static_assert(kNativeEmpiricalResultStatus.
        exact_two_round_five_field_registry);
    static_assert(kNativeEmpiricalResultStatus.
        sealed_history_and_candidate_inputs);
    static_assert(kNativeEmpiricalResultStatus.
        derives_candidate_effect_internally);
    static_assert(kNativeEmpiricalResultStatus.opaque_one_shot_residual);
    static_assert(!kNativeEmpiricalResultStatus.
        terminal_attached_observer_minter);
    static_assert(!kNativeEmpiricalResultStatus.fd62_v3_join);
    static_assert(!kNativeEmpiricalResultStatus.selected_runtime_callsite);
    static_assert(!kNativeEmpiricalResultStatus.configured);
    valid_internal_derivation_and_replay_refusal();
    mutated_history_refuses();
    mutated_candidates_and_cross_binding_refuse();
    aliases_and_writable_inputs_refuse();
}
