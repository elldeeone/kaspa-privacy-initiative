#pragma once

// Concrete, callback-free serializers for the registered financial query/MSM
// types.  This file is intentionally not included by the selected callsite yet.
// The future adapter must pass the exact canonical point bytes returned by the
// pinned query cursor; a hash, pointer, callback order, or caller-authored
// completion flag is not a substitute.

#include "auth_groups.hpp"
#include "p1_query_msm_state_hook.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace kpi::mpc::p1_private_state::query_msm_source {

inline constexpr std::size_t COMPRESSED_G1_BYTES = 32;
inline constexpr std::size_t COMPRESSED_G2_BYTES = 64;
inline constexpr std::size_t FR_BYTES = 32;
inline constexpr std::size_t G1_BYTES = 65;
inline constexpr std::size_t G2_BYTES = 129;

// QueryBegin.  H must pass all domain scalars; its unused final scalar is
// retained directly.  Other queries require exact point/scalar arity.
void begin_g1_query(
    QueryMsmStateScope&, QueryMsmKind,
    std::uint64_t points, std::span<const AuthScalar> scalars);
void begin_g2_query(
    QueryMsmStateScope&, std::uint64_t points,
    std::span<const AuthScalar> scalars);

// One selected 1024-point-or-smaller chunk.  compressed_points is the exact
// decompressed proving-key point frame (32 bytes/G1, 64 bytes/G2) before point
// admission.  The fixed source implementation launches exactly three workers
// (or one per point when smaller), captures each live prefix, preserves actual
// completion interleaving, then reduces partials in worker-ordinal order.
AuthG1 captured_g1_chunk(
    QueryMsmStateScope&, std::uint64_t first,
    std::span<const unsigned char> compressed_points,
    std::span<const G1Value> decoded_points,
    std::span<const AuthScalar> scalars);
AuthG2 captured_g2_chunk(
    QueryMsmStateScope&, std::uint64_t first,
    std::span<const unsigned char> compressed_points,
    std::span<const G2Value> decoded_points,
    std::span<const AuthScalar> scalars);

void g1_accumulator(QueryMsmStateScope&, const AuthG1&);
void g2_accumulator(QueryMsmStateScope&, const AuthG2&);
void terminal_g1(QueryMsmStateScope&, const AuthG1&);
void terminal_g2(QueryMsmStateScope&, const AuthG2&);

// Query-adjacent outer buffers.  Direct_MC challenge/randomness state belongs
// to the separate MAC-check source family; these functions retain every
// concrete mixed-protocol and checker vector in auth_groups.cpp.
void mixed_inputs(
    QueryMsmStateScope&, std::span<const AuthG1, 2> groups,
    std::span<const AuthScalar, 2> scalars);
void mixed_masks_and_differences(
    QueryMsmStateScope&,
    std::span<const AuthScalar, 6> triples,
    std::span<const AuthG1, 2> group_masks,
    std::span<const AuthScalar, 2> scalar_masks,
    std::span<const AuthG1, 2> product_masks,
    std::span<const AuthG1, 2> masked_groups,
    std::span<const AuthScalar, 2> masked_scalars,
    std::span<const Fr, 2> scalar_differences,
    std::span<const G1Value, 2> group_differences);
void mixed_products(
    QueryMsmStateScope&, std::span<const AuthG1, 2> products);
void final_checker_inputs(
    QueryMsmStateScope&, const AuthG1&, const AuthG2&, const AuthG1&);
void final_checker_opened(
    QueryMsmStateScope&, std::span<const G1Value, 2>, const G2Value&);
void final_checker_returned(
    QueryMsmStateScope&, std::span<const G1Value, 2>, const G2Value&);

} // namespace kpi::mpc::p1_private_state::query_msm_source
