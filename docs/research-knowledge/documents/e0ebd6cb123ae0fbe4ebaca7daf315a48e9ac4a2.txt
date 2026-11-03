# RFC-0014: Owner-aware evaluation of the 32-user privacy claim

**Status:** Open. The owner directed starting the 32-user/eight-adversary test.
This RFC does not accept a protocol change or relax RFC-0012.

**Date:** 2026-10-20. Candidate: `aa6ed4947f7c25db128cd5d89b7c021d6b8fe690`.

## Question

Can public amounts, current-wallet ownership rules, pooled participant records
and later withdrawals force an undisclosed payment's sender, recipient or amount,
even with 32 participating modeled users?

The [completed calibration](../../poc/shared-pool/EARLY-PRIVACY.md) tested amount
extrema without common input ownership. Scaling that relaxation cannot answer
this question. The [source review](../../research/shielded-kas-32-role-evaluation-2026-10-20.md)
identifies the relevant wallet semantics and evidence limits.

## Approach

Start with the [falsification specification](../../poc/shared-pool/POPULATION-PRIVACY-SPEC.md).
Use the existing integer conservation relation with a new, explicit owner layer:
32 stable identities, declared funding associations, common ownership of selected
inputs, recipient output 0, sender change at output 1, and one-or-two-input exits.
Keep participants' received records separate from their authored records. Combine
identities through a declared shared addressbook, not historical view-local aliases.

Reuse the independently encoded CP-SAT and Z3 arithmetic models and exact-query
controls. Reject H15/H16's single-input exit rule and anonymous-owner labels.
Compare a public-only observer, separate participant disclosures, pooled records
and records of active participants. Attacker actions must actually affect the
workload. If pooled P and pooled P+A contain identical information on a particular
history, report that equivalence rather than count it as independent evidence.

The first workload has four independent request sets, each with paired persistent
and prompt-cashout histories. It tests deterministic forced disclosures, not
guessing-rate qualification. Generated history is a wallet-semantics model:
it does not contain newly verified cryptographic proofs or accepted native
transactions. The model assumes hiding identifiers and correct cryptography.
It can exhibit a conditional metadata counterexample; absence of one cannot
qualify the complete native byte surface.

## Solver-limited follow-up measurements

Full-history reconstruction has not returned an initial feasible assignment;
the preserved CP-SAT attempts and an out-of-memory Z3 probe are incomplete,
not evidence of privacy. Two bounded follow-ups use the same frozen histories:

- [Local disclosure relaxation](../../poc/shared-pool/POPULATION-PRIVACY-METHOD-04.md):
  retain selected input equations without deleting public records. A forced
  slice fact can establish a full-model fact once full truth inclusion is checked;
  slice alternatives cannot establish full-history ambiguity or privacy.
- [Deterministic cashout guesses](../../poc/shared-pool/POPULATION-PRIVACY-METHOD-05.md):
  measure exact and within-10% amount guesses and recipient guesses under fixed
  rules. Seal every history's predictions before any score. Report all attacks
  and their limited diagnostic baselines separately. These exploratory rates
  are neither logical disclosure certificates nor statistical qualification.

Neither follow-up changes the workload, target eligibility, asset model or
RFC-0012 thresholds. The [results](../../poc/shared-pool/POPULATION-PRIVACY.md)
must distinguish completed measurements from the unresolved whole-history search.

## Decision rules and remaining work

A supported, previously undisclosed fact is a counterexample only after both
encodings certify it and the isolated scorer checks it against private truth.
Model inconsistency, invalid controls or an unresolved query means incomplete.
Preserve attempted runs and the exact point of any early stop.

If a counterexample survives review, stop expansion of the candidate and identify
a redesign or an explicitly reviewed scope change. Otherwise continue to the
remaining views/horizons and a separately powered, frozen qualification study.
Four request sets are four sampling units, irrespective of the number of payments,
views or policy arms. No confidence-bound or guessing-rate pass is available from
this first test. All RFC-0012 targets remain unchanged.

Qualification still needs frozen strong prior/attack algorithms, sample size and
simultaneous ledger-level confidence procedures for every required rate,
advantage and selective-precision comparison. Infrastructure observations and
independent real users remain separate obligations.

No wallet, circuit, covenant, key derivation or asset model changes are proposed.
All security invariants remain unchanged; no funds, broadcasts or new proofs.
