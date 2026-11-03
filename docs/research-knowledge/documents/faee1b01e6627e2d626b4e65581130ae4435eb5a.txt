# 32-role privacy evaluation: sources and design recommendations

Reviewed 2026-10-20 after calibration commit
`aa6ed4947f7c25db128cd5d89b7c021d6b8fe690` was pushed.
Scope: the unchanged v6 wallet and [RFC-0012](../docs/rfc/0012-useful-privacy-requirements.md)
targets, with 32 modeled roles and eight active/colluding roles.
This is design research, not the frozen evaluation specification or a result.
No held-out truth, private wallet directories, proofs or funds were accessed.

## Source status and reuse

The same-day [source inventory](shielded-kas-privacy-requirements-2026-10-20.md)
and [public-surface review](shielded-kas-privacy-surface-sources-2026-10-20.md)
remain applicable. Their pinned protocol sources need no cryptographic redesign
for this experiment. Fresh read-only checks show initiative main still at
`52bb2b4e7a1e0a8f98aecb58d33933f0b03d9e33`.
[Issue #13][issue13] remains open with zero comments, last updated
`2026-10-02T13:58:54Z`. Its timing/amount/wallet/network leakage requirements are
not an endorsement of this experiment, its thresholds or any privacy result.

| Primary source | Reuse for this evaluation | Limit/rejection |
| --- | --- | --- |
| [Aztec timing/counterparty example][timing] | Test adversary-chosen payment timing and later recognizable reactions together. | Eight adversarial roles do not define their transaction share or scheduling powers. |
| [Aztec fingerprints and root-age caveat][aztec] | Model operation shapes, anchors and side information jointly; candidate notes need not include all earlier notes. | A pool containing 32 roles does not provide 32 plausible honest owners at every target. |
| [Orchard output ordering][orchard] | Audit the actual v6 payment/change ordering as observable client policy. | Orchard's shuffling motivates an attack question; it does not establish a v6 fix. |
| [ZIP-224 privacy boundary][zip224] | Separate persistent shielded payments from public ingress/egress and matched prompt cashout. | Exit values remain visible; more notes do not automatically mean more independent people. |
| [Official grouped-validation guidance][grouped] | Keep related observations together when separating development from evaluation. | No new classifier/library is required; grouping does not by itself validate the attack or confidence procedure. |
| [Field and Welsh, clustered bootstrap][cluster] | Choose uncertainty methods that respect clustered observations and state their assumptions. | The inspected abstract makes consistency model-dependent. It does not certify a small-ledger bootstrap or this experiment's finite-sample coverage. |

The inherited Monero/MWEB/RAILGUN, Kaspa, vProgs and research reviews still apply
to observation boundaries, public reconstruction and confidential-versus-public
data. No primitives, runtime or consensus changes are selected here.

## What the calibrated model still omits

The [calibration](../poc/shared-pool/EARLY-PRIVACY.md) validates public projection
and integer amount constraints on a published three-wallet history. Its
[`current_wallet_shape` model](../poc/shared-pool/early_privacy_amounts.py)
does not model common input ownership, counterparty records or ranked guessing.
Scaling that relaxation to 32 roles cannot establish owner privacy.

The [current wallet](../poc/shared-pool/src/two_input/wallet.rs) selects notes
owned by one wallet, permits one or two real inputs, creates payment output 0
for the recipient and output 1 as sender change, and puts admission credit in
output 0. An owner-aware model should therefore represent:

- A stable owner variable for each positive note, separate from its value,
  commitment bytes, position and source transaction. Zero padding adds no owner.
- One sender owning every selected real input, and positive change owned by that
  sender. Output 0's recipient is a distinct variable; self-payment must follow
  the frozen workload policy rather than an unstated prohibition.
- Declared public funding-to-owner associations and legitimate participant
  records. Receiving a note does not reveal an unobserved sender, sibling
  plaintext or the recipient's future nullifier.
- Current spentness, positioned notes, historical anchors, exact fees and the
  complete later withdrawal history, preserving the calibrated two-input DRAIN.

Known common control collapses owner candidates; a shared funding parent alone
does not prove common ownership. Do not count multiple notes or receive addresses
belonging to one known owner as several independent alternatives.

## Strongest early falsifier before a large run

First validate the owner-aware relation on tiny exhaustive known-answer controls.
Then seek a forced **previously unknown internal-payment** identity, relationship
or amount using pooled eight-party records, fixed change roles and later cashouts.
The earlier [H16 disclosure finding](../poc/shared-pool/PARTICIPANT-PRIVACY.md)
is a useful regression clue, not a current owner/amount result.

Try chosen-amount and timing probes with normal value-conserving payments:
an adversary knows the amount, recipient and time of its own payment, then tries
to recognize a later uninvolved payment or withdrawal. The initial known payment
is not an unauthorized disclosure. An honest recipient's response or spending
policy cannot be silently controlled by the attacker.

Any useful counterexample must instantiate the frozen supported workload and
observations. Embed a candidate failure in the 32-role/eight-adversary setting
without changing its assumptions; adding dormant honest balances does not
automatically remove leakage. Conversely, a singleton control or prohibited
schedule cannot alone fail the supported 32-role claim.

Also retain the source-derived native-script reuse case from calibration:
funding and payout share a derivation namespace, and a matching funding index
can equal a later exit's minimum selected position. This can link public
boundaries. Show separately whether it reveals any protected internal fact;
do not rename every public deposit/exit association a private-payment failure.

## Freeze a meaningful public prior

Give observers stable candidate identities, declared funding associations and
published workload distributions. Keep only actual hidden assignments, evaluator
seeds and undisclosed records private. The baseline's data access and timing must
be fixed before scoring; it cannot secretly receive the tested disclosure.

Uniform guessing over 24 honest roles is justified only by an actually uniform
conditional owner prior. Interleaved admissions, activity rates, sparse periods
and known adversarial ownership can make it wrong. Freeze stronger baseline
attacks using the allowed priors and development data.

For amounts, choose the guess maximizing the published probability mass inside
the RFC's exact integer ±10% acceptance band; a median need not be optimal.
If public priors put more than 20% of eligible payments in one such band, the
absolute amount gate is already unattainable for that workload. Report that
information limit rather than hiding the distribution or changing targets.

Eligibility is fact-specific and frozen before outcomes. Exclude genuinely
already-known facts; do not exclude cases merely because the tested transcript
makes them easy. Counterparty disclosures must not remove later uninvolved
targets from evaluation.

## Blinding, activity and uncertainty

Freeze the workload, attack family, baselines, eligibility, horizons, coverage
rounding/tie rules and statistical plan before generating held-out assignments.
Published three-wallet traces and deliberately constructed controls are
development/calibration data only.

Separate generator/scorer truth from observer inputs and finish predictions
before scoring. Commit file hashes and restrict observer filesystem/network
access. Prevent truth leakage through deterministic role-derived byte labels,
filenames, seeds, timing diagnostics or globally shared participant aliases.
Include deliberate contamination and owner-label permutation controls.

Use 32 modeled roles, including eight active/colluding roles, but also freeze
their transaction/value shares, recipient choices, timing powers and knowledge.
Model interleaved admission, repeated spending, private change, sparse periods,
tagging and complete exits. Pair persistent balances with prompt cashout under
the same underlying economic workload; report the arms separately.

Sample independent ledger/session seeds. Keep every view, target horizon and
matched cashout variant of one ledger in the same development/evaluation group.
Payment rows within that ledger are correlated. Resampling thousands of rows
from a handful of ledgers cannot create independent evidence.

Predeclare whether scores weight ledgers equally or weight eligible targets,
and retain each ledger's numerators/denominators. Compute attack-minus-baseline
differences on matched ledgers. If using cluster resampling, resample complete
ledgers and recompute the declared metric, including coverage selection; justify
the number of independent ledgers and check uncertainty behavior on development
controls. Freeze a finite multiple-comparison family for the required one-sided
95% bounds. Insufficient power or unjustified interval coverage means incomplete,
not a pass. A forced-disclosure certificate is checked separately from rate bounds.

## Feasibility and decision boundary

Thirty-two roles do not approach v6's fixed tree capacity by themselves:
[tree growth](../poc/shared-pool/src/two_input/tree.rs) depends on operations,
with two commitments per non-DRAIN transition, not user count. Exact owner/value
search can nevertheless become expensive as possible input combinations grow.
Use development workloads to choose tractable query strategies without rounding
sompi or silently excluding valid assignments. Solver unknowns remain incomplete.

The larger evaluation may use modeled histories calibrated to actual v6 bytes,
but must distinguish them from genuine proof/native validation. It cannot claim
new cryptographic or network evidence. Keep all RFC gates and known cost/latency
failures unchanged. A supported forced disclosure justifies stopping expansion
for a concrete redesign/claim decision; a passing finite attack suite only
supports proceeding under its stated assumptions.

[issue13]: https://github.com/olafweller/kaspa-privacy-initiative/issues/13
[timing]: https://github.com/aztec-labs-eng/aztec-node/blob/9babccfcfc083915a5bda1f378fe8bda3a6bd2b8/docs/docs-developers/docs/resources/considerations/privacy_considerations.md#L59-L71
[aztec]: https://github.com/aztec-labs-eng/aztec-node/blob/9babccfcfc083915a5bda1f378fe8bda3a6bd2b8/docs/docs-developers/docs/resources/considerations/privacy_considerations.md#L73-L127
[orchard]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/builder.rs#L1490-L1508
[zip224]: https://github.com/zcash/zips/blob/a34cfc091434275120ff017c92c3b50d3cef623a/zips/zip-0224.rst#L235-L251
[grouped]: https://scikit-learn.org/stable/modules/cross_validation.html#cross-validation-iterators-for-grouped-data
[cluster]: https://rss.onlinelibrary.wiley.com/doi/abs/10.1111/j.1467-9868.2007.00593.x
