# ADR-0036: Use budget 1600 in the fixed-v6 transaction factory

**Status:** Accepted — local experimental resource parameter and compatible replay.

**Date:** 2026-10-23 Australia/Sydney.

The fixed-v6 factory declared budget 3000 although the
[reviewed source bound](../../research/v6-native-budget-upper-bound-2026-10-22.md)
is 15,857,502 script units, below budget-1600's 16,009,999 allowance. Declared
budget affects transaction compute mass even when actual verification work is
unchanged. Retaining 3000 unnecessarily limits the current 40m-sompi fee
envelope. Adopt 1600 for this fixed-v6 factory after genuine factory/replay and
boundary qualification; preserve the existing relation and historical evidence.

## Decision

1. Set only `two_input::covenant::BUDGET` to 1600. Other protocol versions retain
   their existing constants. This changes the reserve input's declared compute
   budget, not the emitted redeem/P2SH scripts, private relation, proof,
   authorization, ciphertexts, outputs, signatures or actual 40m-sompi fee.
   Keeping 3000 remains valid historical behavior; smaller budgets are not
   selected without the same source coverage and operating margin.
2. Preserve the supplied reserve input's typed v1 `ComputeBudget` during public
   replay. Rebuilding old transactions with the new factory default alone would
   reject genuine 3000-budget history. Finalize/recompute mass, require the exact
   reconstructed body, then perform full native validation, pinned
   compute/storage/transient mass caps (500k/500k/1m) and unchanged fee/accounting
   checks. Do not add a relay-fee rule to historical replay or accept an
   unchecked budget as authorization.
3. Keep historical packets immutable. Earlier 3000-default source, the
   [13 genuine-case screen](../../poc/shared-pool/PUBLIC-NATIVE-BUDGET.md) and
   [48 synthetic-context boundary cases](../../poc/shared-pool/PUBLIC-NATIVE-BUDGET-BOUNDARIES.md)
   retain their source/artifact identities. The integration boundary helper
   explicitly constructs a 3000 comparison baseline. The new adoption regression
   must actually call the current factory, rather than only patch a saved body.

## Evidence and compatibility

The [new factory regression](../../poc/shared-pool/PUBLIC-V6-BUDGET-1600.md)
passes all 13 `settle`-built 1600 candidates. Canonical bodies differ from their
genuine historical originals only in reserve compute budget. Contextual storage
mass, full scripts/SPKs, proof/auth/ciphertext bytes, outputs, signatures, IDs and
SIG_HASH_ALL remain identical; full hashes change and match earlier independent
1600 vectors. Complete historical3000 and factory1600 replays yield the same
public state and integer-sompi accounting. Other-version constants are checked.

Five controls reject at the intended layers: genuine native underbudget,
unexpected fee/output, wrong genuine proof and excessive declared budget. The
excessive-budget proof predicate passes before the explicit mass-cap rejection.
A focused independent source pass confirmed that budget preservation leaves
exact-body reconstruction, native validation, fees and conservation mandatory.

[Validation](../../poc/shared-pool/evidence/2026-10-22-v6-budget-adoption/attempt-01/validation.json)
and [manifest](../../poc/shared-pool/evidence/2026-10-22-v6-budget-adoption/attempt-01/MANIFEST.json)
retain the new source/binary/input identities. Manifest SHA-256:
`2687fcec0f8b69127a58dc8d9c127d5271714946a75ac11704439e79f4968c7b`.
All five artifact hashes/sizes and 49 source pins were independently rechecked.
Covenant source SHA-256:
`52f11865f8a6fd92cd0046c859c9e49e501c6fe1bda6cc27adbf0c6ef2c17abe`;
replay source SHA-256:
`d1b025a002f98ad242de7f31a3b72fa8a30bc5df9988b9940853eb24732cc3b4`.

## Limits and reconsideration

At the pinned v1 rules, IDs and SIG_HASH_ALL exclude compute budget; full hashes
include it. Native metering and transaction-capacity checks remain essential.
The source bound applies only to successful fixed-shape standard-P2SH v6 reserve
input 0; it is not compiler verification, a malformed-input bound or coverage
of another input, covenant or new state-aware script. Re-derive/requalify if
that shape, arity, emitted bytes or charging schedule changes.

The fee is not reduced. The worst measured rate-500 quote remains 95,814,000
sompi, above the 60m minimum note; even the proof-only floor is 73.75m, so that
singleton exit still cannot cover it. The 48 synthetic contexts do not establish reachable history,
backing or chain acceptance. No privacy target, setup, exit authority, reserve
rule, production architecture or mainnet/funding scope changes. Preserve
[RFC-0012](../rfc/0012-useful-privacy-requirements.md), the
[security invariants](../../SECURITY-INVARIANTS.md) and all earlier failures.
