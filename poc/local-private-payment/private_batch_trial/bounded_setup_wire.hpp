#pragma once

#include <array>
#include <cstddef>

namespace kpb::bounded_setup::wire {

inline constexpr int RUNTIME_FD = 39;
inline constexpr int CIRCUIT_CLOSURE_FD = 40;
inline constexpr int PLAN_FD = 42;
inline constexpr int AGGREGATE_CONTEXT_FD = 43;
inline constexpr int AGGREGATE_SIGNATURE_FD = 44;
inline constexpr int SWAP_MAX_FD = 45;
inline constexpr std::array<int, 2> OUTPUT_FDS{50, 51};
inline constexpr int STATUS_FD = 54;

inline constexpr std::array<unsigned char, 8> CLOSURE_MAGIC{
    'K','P','B','C','R','S','C','1'};
inline constexpr std::array<unsigned char, 8> PLAN_MAGIC{
    'K','P','B','C','R','S','P','1'};
inline constexpr std::array<unsigned char, 8> STATUS_MAGIC{
    'K','P','B','C','R','S','O','1'};
inline constexpr std::array<unsigned char, 31> PRECOMMIT_DOMAIN{
    'K','P','B','_','B','O','U','N','D','E','D','_','S','E','T','U','P','_',
    'P','R','E','C','O','M','M','I','T','_','V','1','\n'};
inline constexpr unsigned char PRECOMMIT_FINANCIAL_RUN = 1;
inline constexpr unsigned char PRECOMMIT_ROUND_ATTEMPT = 2;
inline constexpr unsigned char PRECOMMIT_ROUND_COHORT = 3;

inline constexpr std::size_t CLOSURE_BYTES = 112;
// The setup plan carries only identities that may be source-selected before
// CRS generation: trial, both financial runs, both attempt nonces and both
// cohorts, followed by the exact Output and aggregate circuit closures.
// Capture-plan identities, projections, measurement selections and the 10x6
// selected-parent manifest are deliberately excluded: their current schemas
// are post-setup or are not proven independent of setup/proof outputs.
inline constexpr std::size_t PLAN_BYTES = 424;
inline constexpr std::size_t PLAN_TRIAL_AT = 8;
inline constexpr std::size_t PLAN_FINANCIAL_RUNS_AT = 40;
inline constexpr std::size_t PLAN_ROUND_ATTEMPTS_AT = 104;
inline constexpr std::size_t PLAN_ROUND_COHORTS_AT = 168;
inline constexpr std::size_t PLAN_OUTPUT_CLOSURE_AT = 232;
inline constexpr std::size_t PLAN_AGGREGATE_CLOSURE_AT = 328;
inline constexpr std::size_t STATUS_BYTES = 48;

inline constexpr unsigned long long POLICY_DUMPABLE_DISABLED = 1ULL << 0;
inline constexpr unsigned long long POLICY_CORE_DISABLED = 1ULL << 1;
inline constexpr unsigned long long POLICY_ENVIRONMENT_EMPTY = 1ULL << 2;
inline constexpr unsigned long long POLICY_UNKNOWN_FDS_CLOSED = 1ULL << 3;
inline constexpr unsigned long long POLICY_NETWORK_DENIED = 1ULL << 4;
inline constexpr unsigned long long POLICY_SWAP_ZERO = 1ULL << 5;
inline constexpr unsigned long long POLICY_CLOSURES_EXACT = 1ULL << 6;
inline constexpr unsigned long long POLICY_PLAN_EXACT = 1ULL << 7;
inline constexpr unsigned long long POLICY_SOURCE_OPENS_DENIED = 1ULL << 8;
inline constexpr unsigned long long POLICY_DESCENDANTS_DENIED = 1ULL << 9;
inline constexpr unsigned long long POLICY_ERASURE_ATTEMPTED = 1ULL << 10;
inline constexpr unsigned long long REQUIRED_POLICY =
    POLICY_DUMPABLE_DISABLED | POLICY_CORE_DISABLED |
    POLICY_ENVIRONMENT_EMPTY | POLICY_UNKNOWN_FDS_CLOSED |
    POLICY_NETWORK_DENIED | POLICY_SWAP_ZERO |
    POLICY_CLOSURES_EXACT | POLICY_PLAN_EXACT |
    POLICY_SOURCE_OPENS_DENIED | POLICY_DESCENDANTS_DENIED |
    POLICY_ERASURE_ATTEMPTED;

} // namespace kpb::bounded_setup::wire
