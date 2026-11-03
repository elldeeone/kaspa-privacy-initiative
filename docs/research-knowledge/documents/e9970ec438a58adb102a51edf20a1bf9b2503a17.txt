# ADR-0040: Measure a public revealing-exit candidate

**Status:** Accepted for a standalone public offline feasibility experiment only.
No private protocol, production architecture, migration or requirements change.
**Date:** 2026-10-23 Australia/Sydney. DO_NOT_FUND.

## Why this experiment

The [existing terminal-claim investigation](0039-exit-liability-and-native-claim-experiments.md)
does not supply an exit for a note whose withdrawal request is not yet accepted.
Its upstream fee contract additionally requires external funding. Repeating the
known fresh-Groth16 cost or proving the unchanged claim again cannot answer
whether a different, revealing native path can self-fund a small claim.

The [source-grounded architecture review](../../research/next-session/exit-fee/ARCHITECTURE-OPTIONS.md)
and [adversarial review](../../research/next-session/exit-fee/EXIT-OBLIGATIONS-REVIEW.md)
support testing the conditional two-secret/native-key relation in
[RFC-0019 candidate C](../rfc/0019-fees-and-independent-exit-obligations.md#candidate-c-public-only-authorization-and-native-cost-experiment).
Use established SHA256/HMAC, Schnorr, Merkle and indexed-set techniques. This is
a new composition requiring further review, not a new cryptographic primitive
or a claim of security. The private owner secret stays private when the separate
note-local NF credential is revealed. Requiring a native signature only on one
branch would not repair a private branch authorized by the revealed key alone;
that deliberately unsafe variant is a required negative reference case.

## Scope and release gates

Implement an isolated, public-credential reference relation and a native reveal
checker under new tags/state/version. Do not import owner wallets, saved private
material, proving/PK restoration, ledger replay or the rejected S7 workflow.
Use supplied synthetic CM/NF/reserve contexts. There is no private-proof verifier
or usable private-spend branch in this policy. A private reference predicate is
an assumption/conformance oracle, never a genuine SNARK result.

Before execution freeze sources, canonical layout, index/range semantics,
scripts, exact positive amounts, actual owner-signed fees and expected negative
results. Obtain a second adversarial pass. Preserve current-NF cross-path
exclusion, exact destination/fee/value conservation and immutable successor.
Use official native isolation/Full checks and full compute/storage/mining mass,
with no skipped verifier/mass check. Record underlying ScriptEngine separately.

The decisive economic screen is60M principal, at least10M native payout,
rate500 and no external input: full mining mass at most100,000 and fees at most
50M. Include a continuing reserve and high-index/capacity boundary, not only a
single terminal input. The actual probe's size is not the unknown future union
script's size: test declared padded size envelopes and make all such economic
inferences conditional. Do not silently omit future code/witness costs.

Include a conditional terminal R=V case. Complete nonnegative prior liabilities
L satisfy V<=L<=R under authenticated unspentness and I-1, so R=V implies L=V
and whole-note consumption leaves no liability/reserve. The
[reviewed accounting argument](../../research/next-session/exit-fee/TERMINAL-ACCOUNTING.md)
states the load-bearing prior-validity assumption; the public probe does not
prove it or accept an underbacked hidden state as a valid protocol history.

This can establish only the frozen public native authorization/state/cost seam.
The future private circuit, accepted funding, one-command independent recovery,
backup/descriptor validation, DA, contention/reorg operation, complete-lifecycle
fees, latency and unchanged financial-privacy targets remain open. The old
single-secret relation, old VK/domain and immutable covenants are unchanged.
Neither historical stranded liabilities nor old rejected privacy results vanish.

No funding, broadcasts, mainnet, real funds, privileged withdrawal, paid compute
or external disclosure is authorized by this ADR. It does not retry or recreate
the tool-rejected S7 owner CLI/replay/DRAIN workflow. Use existing Forge CPU
capacity; no unchanged GPU proof is necessary. Keep failed/incomplete results.
