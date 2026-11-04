# ADR-0104: Unfunded native-draft authorization interoperability

**Status:** Accepted for isolated local authorization research only.
**Date:** 4 November 2026.
**Origin:** Owner direction to continue after [ADR-0103](0103-native-shielded-consensus-specification.md).

## Problem

The [native draft](../spec/native-shielded/transactions.md) has exact signature
preimages but no genuinely authorized transaction examples. The old packet's
signatures authorize another message. Native consensus/accounting adoption still
requires independent review, including the explicit proposed I-1/I-2 amendment.

## Decision

Build a separate [unfunded package](../../poc/native-tx-validation/README.md)
that encodes the native draft and verifies actual Schnorr, low-S compact ECDSA,
complete repaired Orchard V2 Halo2 and both RedPallas signature roles. Derive
messages from the complete effects and ordered lookup of explicitly synthetic
UTXO records. Retain the existing packet, key capsule, encoding examples and
historical evidence unchanged. Preserve the same reviewed Orchard source and
construction; introduce no cryptographic primitive.

The local verifier also checks public equations and supplied domain/anchor/
spentness/balance as rejection controls. It cannot apply state or emit a native
acceptance verdict. Restrict local context to non-coinbase inputs, zero absolute
lock and final sequences; refuse unsupported chain checks. Storage mass is a
signed placeholder, not a calculated valid fee. A pinned upstream key constructor
with a fail-closed build diagnostic is used; the capsule is checked for fixed
identity but is not imported as a verifier.

## Review boundary

This does not adopt the accounting amendment, implement an accepted value
transition, integrate a native node or qualify a chain/snapshot. It does not
change SECURITY-INVARIANTS.md. Independent review must precede the gated native
transition implementation. No real/Testnet funds, broadcast, RPC, provider,
privileged exit or paused MPC work is authorized or needed for this package.

The result answers whether the proposed message can be constructed and verified
with the selected existing cryptography. It cannot establish backing, consensus
soundness, privacy, practical costs or independent recovery. Carry those limits
in [the review](../../poc/native-tx-validation/REVIEW.md) and machine-readable
fixture output.
