#pragma once

// Constants-only hidden-candidate view of the one frozen owner-truth scorer
// packet. Both arms use the exact baseline schema and 813-byte framing; only
// the canonical classification byte differs. The parent never parses it.

#include "baseline_owner_truth_capsule_schema.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace kpi::mpc::financial::fresh_owner_issuance::
    candidate_truth_schema {

namespace common =
    registered_driver::baseline_disclosure::truth_capsule_schema;

inline constexpr auto MAGIC = common::MAGIC;
inline constexpr std::uint8_t VERSION = common::VERSION;
inline constexpr std::uint8_t HIDDEN_CANDIDATE_CLASSIFICATION =
    common::HIDDEN_CANDIDATE_CLASSIFICATION;
inline constexpr std::size_t DIGEST_BYTES = common::DIGEST_BYTES;
inline constexpr std::size_t ROUND_COUNT = common::ROUND_COUNT;
inline constexpr std::size_t ROUND_DIGEST_COUNT = common::ROUND_DIGEST_COUNT;
inline constexpr std::size_t ROUND_BYTES = common::ROUND_BYTES;

inline constexpr std::size_t MAGIC_OFFSET = common::MAGIC_OFFSET;
inline constexpr std::size_t VERSION_OFFSET = common::VERSION_OFFSET;
inline constexpr std::size_t CLASSIFICATION_OFFSET =
    common::CLASSIFICATION_OFFSET;
inline constexpr std::size_t OWNER_OFFSET = common::OWNER_OFFSET;
inline constexpr std::size_t ENDPOINT_IDENTITY_OFFSET =
    common::ENDPOINT_IDENTITY_OFFSET;
inline constexpr std::size_t FEEDER_SESSION_OFFSET =
    common::FEEDER_SESSION_OFFSET;
inline constexpr std::size_t TRIAL_OFFSET = common::TRIAL_OFFSET;
inline constexpr std::size_t ROUNDS_OFFSET = common::ROUNDS_OFFSET;
inline constexpr std::size_t PACKET_BYTES = common::PACKET_BYTES;

enum class RoundDigestField : std::size_t {
    FinancialRun = 0,
    Attempt = 1,
    Cohort = 2,
    CapturePlan = 3,
    Projection = 4,
    Context = 5,
    ActualPublicNullifier = 6,
    CreatedRowSha256_0 = 7,
    CreatedRowSha256_1 = 8,
    CreatedCommitment_0 = 9,
    CreatedCommitment_1 = 10,
};

constexpr std::size_t round_offset(std::size_t round_index) {
    return common::round_offset(round_index);
}

constexpr std::size_t round_digest_offset(
        std::size_t round_index, RoundDigestField field) {
    return round_offset(round_index) + 1 +
        static_cast<std::size_t>(field) * DIGEST_BYTES;
}

static_assert(MAGIC == common::MAGIC && VERSION == common::VERSION &&
              HIDDEN_CANDIDATE_CLASSIFICATION == 1 &&
              HIDDEN_CANDIDATE_CLASSIFICATION !=
                  common::EXPLICIT_BASELINE_CLASSIFICATION &&
              MAGIC_OFFSET == common::MAGIC_OFFSET &&
              VERSION_OFFSET == common::VERSION_OFFSET &&
              CLASSIFICATION_OFFSET == common::CLASSIFICATION_OFFSET &&
              OWNER_OFFSET == common::OWNER_OFFSET &&
              ENDPOINT_IDENTITY_OFFSET == common::ENDPOINT_IDENTITY_OFFSET &&
              FEEDER_SESSION_OFFSET == common::FEEDER_SESSION_OFFSET &&
              TRIAL_OFFSET == common::TRIAL_OFFSET &&
              ROUNDS_OFFSET == common::ROUNDS_OFFSET &&
              ROUND_BYTES == common::ROUND_BYTES &&
              PACKET_BYTES == common::PACKET_BYTES && PACKET_BYTES == 813);

} // namespace kpi::mpc::financial::fresh_owner_issuance::candidate_truth_schema
