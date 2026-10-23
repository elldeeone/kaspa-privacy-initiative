# ADR-0047: Exact SHA circuit cost experiment

**Status:** Accepted for isolated synthesis and genuine performance measurement,
not adoption.
**Date:** 2026-10-23 UTC.

The original relation has 4,650,533 constraints, forcing a 2^23 proving domain.
Its genuine cached proof still peaks at 5.39 GiB and takes about 24.6 seconds
for proving/verification. Faster key loading does not close those wallet limits.

In a separate source copy, measure the same SHA-256 function with established
Boolean conditional-selection identities for its compression round:
`Ch(e,f,g) = select(e,f,g)` and
`Maj(a,b,c) = select(a XOR b,c,a)`. Exhaustive bit truth tables and SHA known
answers must match before full synthesis. Preserve byte order, rotations,
padding, all note/HMAC/Merkle/Auth formulas and every ownership/value constraint.
Do not merge the differently sized real/dummy HMAC messages in this experiment.

Freeze the source and prospective 2^22 constraint threshold, then measure one
isolated full relation at 2 CPU / 3 GiB after the live trial's heavy phase.
Preserve negative results.
Never edit the active trial, original circuit or closed artifacts. Identical
wire semantics do not make the new constraint matrices compatible with an old
Groth16 proving/verification key; any adoption needs a fresh setup and genuine
verification/native controls under its own identity.

This is an implementation cost experiment using the established SHA-256
primitive, not a new hash or a cryptographic/security/privacy claim.

## Prospective genuine performance follow-up

The first frozen synthesis passes with 3,497,893 constraints and three instance
variables, crossing 2^22. A separate reviewed source/fixture-frozen package may
now generate exactly one fresh setup with OS randomness, keep that new PK
resident, prove the unchanged public synthetic fixture and run the original
checked verifier plus an additional verification. It accepts no old PK or
matrix input. Record actual query dimensions, source/construction identity and
separate setup/proving timers; do not claim an uncomputed raw-matrix digest.
Serialize the official uncompressed artifact after proving and keep it outside
Git. Measure at four CPU workers, 16 GiB operational memory allowance and zero
swap. Compare measured peaks with the unchanged 4 GiB wallet limit without using
that qualification limit to abort the experiment. One observation cannot
establish p95, whole-wallet compliance, native adoption or security. The active
testnet trial retains its original circuit/key and is untouched.
