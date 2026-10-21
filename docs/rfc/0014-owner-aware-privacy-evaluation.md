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

## Native script-reuse diagnostic

The owner-authorized [offline follow-up](../../poc/shared-pool/ADDRESS-REUSE.md)
confirms an allowed native funding/exit script collision using seven fresh
proofs. Its sparse two-funded-wallet case exposes sender, recipient and exact
amount only after the link is included, under known funding associations and
the declared self-bootstrap/current-wallet policies. Same-transcript ablation,
creation horizons and the different-index control leave those fields ambiguous.
Generic wallet PAY does not enforce self-bootstrap, so this is a conditional
diagnostic, not a three-field disclosure claim for arbitrary histories.

The finding motivates a separate funding/exit key-separation and recovery design
review. That follow-up is now implemented at `52c2092`: the
[ten-proof offline retest](../../poc/shared-pool/ADDRESS-KEY-SEPARATION.md) removes
the tested link for fresh v2 backups while preserving legacy recovery and its
known weakness. Neither experiment instantiates or replaces this RFC's 32-role
qualification or relaxes RFC-0012. Frozen population results remain unchanged.

## Stronger practical screen after key separation

The owner authorized a [fresh prospective screen](../../poc/shared-pool/POPULATION-PRIVACY-STRONG-SPEC.md)
against candidate `52c209296184d880221432fcbf56bb20d3f64d10`. Freeze its attacks,
criteria, source and dependencies before sampling hidden seeds. Use 16 independent
persistent-balance histories with 32 roles, eight colluding active roles and four
payment rounds; half overlap and half have modeled quiet gaps. Start with pooled
participant records through full drainage. The new minimum capital/distributions
and exact workload are explicit in the new specification, not edits to old runs.

Three practical attacks combine known deposits/notes, tagged receipts, timing
and possible cashout splits. They predict both parties and amounts against a
frozen policy-aware prior, with relationship ranking at fixed coverage. They
issue guesses, not forced-disclosure certificates. Seal every prediction before
private scoring. Validate actual history/policy/accounting separately, including
truth inclusion in both original full encodings.

The fixed 99-comparison uncertainty family uses independent-history means, with
wide simultaneous bounds. Raw cap exceedances are exploratory signals; only the
specified lower-bound breaches certify a screen failure. Sixteen histories are
a bounded attack-screen budget, not adequate qualification power. No outcome can
pass the complete early privacy gate. Missing views/horizons, stronger priors,
actual native-byte surfaces and independent-user evidence remain open.

### Completed stronger-screen result

The [frozen batch](../../poc/shared-pool/POPULATION-PRIVACY-STRONG.md) completed
all sixteen histories and 2,048 ordinary predictions, including 968 primary
eligible payments. All controls, policy/accounting checks and truth inclusion
in both full encodings passed. A separate author-team checker reproduced all
scores and 99 intervals. Every prediction was sealed before private scoring;
no seeds, attacks or criteria were replaced after seeing outcomes.

The strongest tested variant guessed 36/968 senders, 55/968 recipients and 42/968
amounts within 10%; the prior guessed 31, 52 and 37 respectively. No declared
primary estimate exceeds its cap and no simultaneous lower bound certifies a breach.
The recorded outcome is `bounded-screen-complete-no-certified-breach`, with
`qualification_pass: false`. The approximately 50.88-percentage-point rate
radius at sixteen histories cannot establish the adopted thresholds. Correct
exact guesses are not forced-disclosure certificates.

Retain this result as a completed bounded measurement. The other views/horizons,
stronger priors, realistic workload/native surfaces and adequate qualification
power remain open before the early gate can close. No protocol, wallet, setup
or invariant change follows from this screen.

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
All security invariants remain unchanged. The population measurements generated
no native proofs. The separate address-reuse diagnostic generated seven offline
proofs with synthetic ancestry; neither experiment used funds or broadcasts.
