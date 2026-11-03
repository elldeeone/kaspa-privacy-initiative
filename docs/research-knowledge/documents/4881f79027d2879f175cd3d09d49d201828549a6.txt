# ADR-0043: Native public admission in the new-format experiment

**Status:** Accepted for bounded offline implementation and measurement.
**Date:** 2026-10-23 UTC.

## Context

Even a cheap independent exit cannot meet complete-lifecycle fees while retaining
an unamortized admission proof. The new note commitment hashes a public ingress
opening and integer native amount. Existing native introspection, hashing,
signatures and authenticated empty-slot updates can test public admission without
asserting a private spend or introducing a new primitive.

## Decision

Implement the independently reviewed [1,344-byte admission contract](../../research/next-session/private-integration/NATIVE-ADMISSION-CONTRACT.md)
as a third branch of the same new-format immutable union. One ordinary ALL-signed
P2PK funding input supplies the positive note value, actual fee and optional
same-owner native change. The reserve gains exactly the new liability; old
reserve principal pays none of the admission fee. Authenticate the exact public
Note168, sealed receipt, empty CM append and immutable successor. Preserve NF
root/count. The pool input's inactive signature/proof items are exactly zero;
the official native validator must verify the actual funding input signature.

Select the receive-V2 separation from [ADR-0042](0042-separate-delivery-and-note-receive-fields.md).
Publish Note168, never the complete Invoice208 or stable delivery public key.
Native byte/hash validation does not prove correct encryption or receiver
ownership; strict recipient acceptance remains required.

For a singleton n=m=1 input, require its public genesis opening to match actual
reserve value, exact singleton raw-CM root and sentinel-only NF root. For every
other state the genesis-opening field is zero. This coherence guard does not
select a canonical founding transaction or authenticate chain history.

## Evidence and limits

The offline lifecycle must retain an ordinary signed founding body, compare its
actual output to the coherent singleton, and link each subsequent input to the
actual prior body txid/index/amount/script. All source fixtures remain public
synthetic DO_NOT_FUND. Supplied initial funding UTXOs and the selected genesis/
current-lineage oracle remain explicit assumptions; no chain acceptance follows.

The clean fee pilot consumes one payer's genesis60M note and its admitted note
into two distinct10-tKAS recipient notes with no change. Both independent final
reveals drain the reserve; there is no unpriced founding-note tail. This special
two-payment case is separate from generic recipient-plus-change payments, which
remain one useful payment and fail the direct-verifier ordinary fee floor.
Count funding/founding, admission, all actual fees and final cashouts per user.

Whole-union bytes and actual compute/transient/storage mass must be remeasured
on every branch. No previous NOP envelope qualifies the new branch. Passing this
experiment does not establish financial privacy, production cryptography,
testnet readiness, independent chain recovery or a relaxed fee target.
