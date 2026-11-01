#pragma once

// Constants-only wire schema shared by the private feeder and the pinned
// scorer runtime. It deliberately contains no parser, descriptor access,
// authority constructor, truth value, or serialization API.

#include <array>
#include <cstddef>
#include <cstdint>

namespace kpi::mpc::financial::registered_driver::baseline_disclosure::
    truth_capsule_schema {

inline constexpr std::array<unsigned char, 8> MAGIC{
    'K', 'P', 'B', 'B', 'O', 'T', '1', 0};
inline constexpr std::uint8_t VERSION = 1;
inline constexpr std::uint8_t HIDDEN_CANDIDATE_CLASSIFICATION = 1;
inline constexpr std::uint8_t EXPLICIT_BASELINE_CLASSIFICATION = 2;
inline constexpr std::size_t DIGEST_BYTES = 32;
inline constexpr std::size_t ROUND_COUNT = 2;
inline constexpr std::size_t ROUND_DIGEST_COUNT = 11;
inline constexpr std::size_t ROUND_BYTES = 1 +
    ROUND_DIGEST_COUNT * DIGEST_BYTES;

inline constexpr std::size_t MAGIC_OFFSET = 0;
inline constexpr std::size_t VERSION_OFFSET = MAGIC_OFFSET + MAGIC.size();
inline constexpr std::size_t CLASSIFICATION_OFFSET = VERSION_OFFSET + 1;
inline constexpr std::size_t OWNER_OFFSET = CLASSIFICATION_OFFSET + 1;
inline constexpr std::size_t ENDPOINT_IDENTITY_OFFSET = OWNER_OFFSET + 1;
inline constexpr std::size_t FEEDER_SESSION_OFFSET =
    ENDPOINT_IDENTITY_OFFSET + DIGEST_BYTES;
inline constexpr std::size_t TRIAL_OFFSET =
    FEEDER_SESSION_OFFSET + DIGEST_BYTES;
inline constexpr std::size_t ROUNDS_OFFSET = TRIAL_OFFSET + DIGEST_BYTES;
inline constexpr std::size_t PACKET_BYTES =
    ROUNDS_OFFSET + ROUND_COUNT * ROUND_BYTES;

enum class RoundDigestField : std::size_t {
    FinancialRun = 0,
    Attempt = 1,
    Cohort = 2,
    CapturePlan = 3,
    Projection = 4,
    Context = 5,
    PublicNullifier = 6,
    TupleHash0 = 7,
    TupleHash1 = 8,
    TupleCommitment0 = 9,
    TupleCommitment1 = 10,
};

constexpr std::size_t round_offset(std::size_t round_index) {
    return ROUNDS_OFFSET + round_index * ROUND_BYTES;
}

constexpr std::size_t round_number_offset(std::size_t round_index) {
    return round_offset(round_index);
}

constexpr std::size_t round_digest_offset(
        std::size_t round_index, RoundDigestField field) {
    return round_offset(round_index) + 1 +
        static_cast<std::size_t>(field) * DIGEST_BYTES;
}

static_assert(MAGIC_OFFSET == 0 && VERSION_OFFSET == 8 &&
              CLASSIFICATION_OFFSET == 9 && OWNER_OFFSET == 10 &&
              ENDPOINT_IDENTITY_OFFSET == 11 &&
              FEEDER_SESSION_OFFSET == 43 && TRIAL_OFFSET == 75 &&
              ROUNDS_OFFSET == 107 && ROUND_BYTES == 353 &&
              round_offset(1) == 460 &&
              round_digest_offset(1, RoundDigestField::TupleCommitment1) ==
                  781 &&
              PACKET_BYTES == 813);

} // namespace kpi::mpc::financial::registered_driver::baseline_disclosure::truth_capsule_schema
