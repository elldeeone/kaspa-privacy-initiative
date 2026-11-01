#pragma once

// Shared control-only constructor for a genuine NativeEmpiricalResultAuthority.
// It exercises the existing sealed-history and sealed-candidate parsers; no
// production symbol or receipt-only mint is introduced.

#ifndef KPB_NATIVE_EMPIRICAL_RESULT_TEST_SETUP
#error "native empirical test fixture requires test setup"
#endif

#include "privacy_native_empirical_result_authority.hpp"
#include "privacy_measurement_run_binding_wire.hpp"

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

namespace kpb::measurement::empirical_result::test_fixture {
namespace detail {

inline constexpr std::array<unsigned char, 8> HISTORY_MAGIC{
    'K', 'P', 'B', 'E', 'M', 'P', 'H', '1'};
inline constexpr std::array<unsigned char, 8> CANDIDATE_MAGIC{
    'K', 'P', 'B', 'E', 'M', 'P', 'C', '1'};
inline constexpr std::array<unsigned char, 40> FIELD_AGGREGATE_DOMAIN{
    'K','P','B','_','N','A','T','I','V','E','_','E','M','P','I','R','I','C','A','L',
    '_','F','I','E','L','D','_','A','G','G','R','E','G','A','T','E','_','V','1','\n'};

using Aggregates =
    std::array<std::array<Digest, EMPIRICAL_FIELDS>, EMPIRICAL_ROUNDS>;

struct Attempt {
    Digest identity{};
    Digest capture{};
    EmpiricalAttemptOutcome outcome{};
    EmpiricalStreamState state{};
    std::array<Digest, EMPIRICAL_FIELDS> fields{};
};

using RoundAttempts = std::vector<Attempt>;

inline Digest word(unsigned char value) {
    Digest result{};
    result.fill(value);
    return result;
}

inline Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    assert(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}

inline void add_u32(std::vector<unsigned char>& out, std::uint32_t value) {
    for (unsigned shift : {0U, 8U, 16U, 24U})
        out.push_back(static_cast<unsigned char>(value >> shift));
}

inline void add_word(std::vector<unsigned char>& out, const Digest& value) {
    out.insert(out.end(), value.begin(), value.end());
}

inline void set_u32(std::vector<unsigned char>& out, std::size_t offset,
                    std::uint32_t value) {
    assert(offset + 4 <= out.size());
    for (unsigned index = 0; index < 4; ++index)
        out[offset + index] =
            static_cast<unsigned char>(value >> (index * 8));
}

inline void add_header(std::vector<unsigned char>& out,
                       const std::array<unsigned char, 8>& magic,
                       const RunBinding& selected) {
    out.insert(out.end(), magic.begin(), magic.end());
    add_u32(out, 1);
    add_u32(out, 0);
    const auto encoded = wire::canonical_run_binding_bytes(selected);
    out.insert(out.end(), encoded.begin(), encoded.end());
    out.push_back(EMPIRICAL_ROUNDS);
    out.push_back(EMPIRICAL_FIELDS);
    out.push_back(0);
    out.push_back(0);
}

inline Attempt attempt(unsigned char identity_seed,
                       unsigned char capture_seed,
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

inline std::array<RoundAttempts, EMPIRICAL_ROUNDS> selected_attempts() {
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

inline Digest aggregate(unsigned round, unsigned field,
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

inline std::pair<std::vector<unsigned char>, Aggregates> history_body(
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

inline std::vector<unsigned char> candidate_body(
        const RunBinding& selected, const Aggregates& aggregates) {
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
    return out;
}

inline int sealed_read_fd(std::span<const unsigned char> value) {
    const int writer = ::memfd_create(
        "kpb-native-empirical-join-control",
        MFD_CLOEXEC | MFD_ALLOW_SEALING);
    assert(writer >= 0);
    std::size_t at = 0;
    while (at < value.size()) {
        ssize_t amount;
        do {
            amount = ::write(
                writer, value.data() + at, value.size() - at);
        } while (amount < 0 && errno == EINTR);
        assert(amount > 0);
        at += static_cast<std::size_t>(amount);
    }
    constexpr int seals =
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    assert(::fcntl(writer, F_ADD_SEALS, seals) == 0);
    char path[64]{};
    assert(std::snprintf(
        path, sizeof(path), "/proc/self/fd/%d", writer) > 0);
    const int reader = ::open(path, O_RDONLY | O_CLOEXEC);
    assert(reader >= 0);
    assert(::close(writer) == 0);
    return reader;
}

} // namespace detail

inline NativeEmpiricalResultAuthority exact(const RunBinding& selected) {
    const auto [history, aggregates] = detail::history_body(selected);
    const auto candidates = detail::candidate_body(selected, aggregates);
    auto history_authority =
        NativeEmpiricalResultDeriver::test_only_admit_history(
            selected, detail::sealed_read_fd(history));
    auto candidate_authority =
        NativeEmpiricalResultDeriver::test_only_admit_candidate_set(
            selected, detail::sealed_read_fd(candidates));
    return NativeEmpiricalResultDeriver::derive(
        std::move(history_authority), std::move(candidate_authority));
}

} // namespace kpb::measurement::empirical_result::test_fixture
