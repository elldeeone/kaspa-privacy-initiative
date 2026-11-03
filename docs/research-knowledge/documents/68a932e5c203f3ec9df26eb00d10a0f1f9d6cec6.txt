# Stronger privacy screen: sources and decision boundaries

Reviewed 2026-10-21 against candidate
`52c209296184d880221432fcbf56bb20d3f64d10`.
This supports a fresh, prospective attack screen under
[RFC-0012](../docs/rfc/0012-useful-privacy-requirements.md) and
[RFC-0014](../docs/rfc/0014-owner-aware-privacy-evaluation.md).
It does not change cryptography, wallet policy, consensus or adopted targets.
No held-out truth, private wallet artifacts or funds were accessed for this review.

## Sources refreshed and retained

Read-only upstream checks on 2026-10-21 reconfirmed rusty-kaspa HEAD
`4edcbbccb449f84832afb1ca157904b35f37d006` and Kaspa docs HEAD
`0ac77d043a802fc8196abfd5812ac2afbd97a2b9`. These are source identities, not
observations of deployed nodes. The specific transaction and inline-ZK files
below were retrieved again.

Initiative HEAD is now [`7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1`][initiative],
dated 2026-10-20 21:46:11 UTC. The three-commit comparison from the previous
`52bb2b4e7a1e0a8f98aecb58d33933f0b03d9e33` pin contains TN10 recovery evidence,
packaging and local wallet onboarding. That path/commit review is not an audit
of those experiments and supplies no new privacy measurement for this branch.
[Issue #13][issue13] remains open, with zero comments and last update
`2026-10-02T13:58:54Z`; it still calls for timing, amount, wallet, infrastructure
and public-payload analysis without endorsing any local threshold.

Reuse the [prior protocol inventory](shielded-kas-privacy-requirements-2026-10-20.md),
[surface review](shielded-kas-privacy-surface-sources-2026-10-20.md),
[32-role review](shielded-kas-32-role-evaluation-2026-10-20.md) and
[key-separation review](shielded-kas-native-key-separation-2026-10-21.md).
The inherited vProgs/research, RAILGUN, Monero and MWEB pins are context, not
fresh deployment checks. The previously unread vProgs PDF remains unread.

| Source | Reuse/adapt for this screen | Reject or limit |
| --- | --- | --- |
| [Kaspa transaction structures][transaction] | Inventory actual input outpoints, signatures, sequence/budget, native output values/scripts, payload and envelope fields. | An algebraic reduction is not the complete native observation surface. |
| [Toccata inline ZK][inline] | Keep proof validity, successor enforcement and publicly visible transaction data separate. | A valid confidential transition does not establish transaction unlinkability or require a new runtime. |
| [Orchard output-order implementation][orchard] | Test fixed recipient/change conventions as source-visible client policy. | Do not import Orchard's shuffling or security claims as a proven remedy. |
| [Aztec privacy guidance][aztec] | Combine timing, recognizable reactions, public fingerprints and historical-root age; distinguish provider observations. | A chain-only model cannot qualify network/RPC privacy; synthetic timing is not human behavior. |
| [ZIP-224 privacy boundary][zip224] | Separate internal confidentiality from visible pool ingress/egress values and transaction shape. | More hidden notes or simulated roles do not establish independent honest anonymity. |
| [ZIP-315 correlation guidance][zip315] (Draft) | Test chosen-value payments, receipt-triggered activity, action counts and colluding counterparties jointly. | Draft wallet guidance is not a deployed mitigation or evidence that this pool resists the attack. |
| [Möser et al., PoPETs 2018][monero-analysis], §§3–4 | Separate iterative logical elimination from age-based ranking; retain later disclosures when testing older payments. | The paper studies Monero through April 2017. Neither historical rates nor ring-decoy algorithms transfer to Kaspa. |

These sources motivate attacks and observation boundaries, not a new primitive.
The established protocols have different transaction, delivery and trust models.
ZIP-224/315 were retrieved at the reused ZIP pin on 2026-10-21; this does not
assert a fresh repository HEAD. The publisher's paper was inspected separately.

## What the current candidate actually supports

The [native key-separation evidence](../poc/shared-pool/ADDRESS-KEY-SEPARATION.md)
is retained at this candidate. Rechecking its public export verified all 177
files and all 174 source/derivative entries. Its export-manifest SHA-256 remains
`fbf1316b9ab45d816ae4414d6b76a3035c250677793cc5b9e398970619ea307d`.
The recorded ten genuine proofs and native validation are offline evidence with
synthetic ancestry, not newly observed chain acceptance. Its completion record
explicitly leaves privacy qualification false.

Fresh v2 separates funding and exit derivation purposes; explicit v1 retains
its known equality risk. The matched native calibration removes the tested
script-equality inference in v2 and preserves pre-activity-backup recovery for
the tested cases. It does not establish general anonymity, index discovery,
legacy migration safety or absence of other native-byte correlations.

The [actual wallet](../poc/shared-pool/src/two_input/wallet.rs) accepts caller-supplied
one/two-note positions, checks ownership/spentness, emits recipient output 0
and sender change output 1, and derives an EXIT key from the minimum selected
position. There is no implemented automatic least-excess coin selector.
The [population generator](../poc/shared-pool/population_privacy_workload.py)
adds least excess, then fewest inputs, then lexicographic positions as a
**modeled spending policy**. Its drainage order is another workload policy.
Any attack using these policies must name them. Omitting them from an exact
search enlarges the feasible set and makes ambiguity weaker evidence.

The [authorization encoder](../poc/shared-pool/src/two_input/mod.rs) and
[public-byte decoder](../poc/shared-pool/early_privacy_surface.py) show the gap:
real transactions publish native scripts/funding ancestry, reserve lineage,
authorization anchors/counts, nullifiers, commitments, ciphertexts, proof and
public settlement witnesses, with actual lengths/order/envelope fields.
The population model instead uses independent opaque labels, current anchors
and modeled minute slots. It does not synthesize proof/ciphertext/witness bytes,
real native script relationships, native broadcast traffic or provider queries.
An attack on retained modeled fields can be useful; absence of such an attack
cannot qualify the omitted surface. Full public-byte records remain available
in the separate calibration and must not be described as fresh modeled traces.

## Recommended experimental contract

Freeze source/dependency/specification identities before sampling new evaluation
seeds. Prior published histories, including the negative and incomplete attempts,
are development/calibration data. Never count a new attack on an old history as
a fresh held-out sample or erase its earlier result.

Observers receive every declared public target and their permitted records,
not a scorer-generated eligibility mask. Keep generation, attack execution and
scoring separate; seal the complete prediction batch before any score is read.
Public generator and development-control source may explain the workload policy;
hidden-seed metadata, copied truth or another history's records must stay out.
Directory names, opaque
labels and timestamps must not encode hidden roles or the sampling seed.

Score each fact against its creation-time knowledge boundary. A counterparty's
known receipt amount is excluded for that counterparty, but later knowledge or
inference does not retrospectively exclude an uninvolved target. Report startup,
adversarial-endpoint and primary mature-pool counts separately. Do not shrink
the eligible denominator because an attack lacks a candidate, mispredicts or
finds the target easy. Rank and tie-break selective predictions before truth;
apply the frozen coverage denominator and rounding rule exactly.

Require concrete generated history to satisfy integer accounting and both
original full-model encodings in the isolated scorer. This prevents an invalid
model from calling excluded truth private. It does not prove exhaustive attack
coverage, cryptographic openings for alternative histories or correct priors.
Preserve generation failures and impossible requests; do not resample them away.

Requests sharing a ledger, matched arms, horizons and participant views are
correlated observations. Keep them together for development/evaluation and
uncertainty; report ledger-level numerators and denominators. Freeze the finite
attack/prior/profile/horizon comparison family and adjustment before scoring.
Attack probabilities or confidence scores require calibration; a ranking or
feasible-history count alone supplies neither.
For amount/cashout split heuristics, reject contradictions with all disclosed
spends, including later spends, and prevent reuse of one known coinput across
two drains. Matching sums still assumes the hypothesized notes survived
intervening activity. Rank these as guesses, never forced facts, unless a
separate complete-model argument proves uniqueness without excluding truth.

## Fail, survive and incomplete

- **Fail a supported claim:** independently reproduce an unauthorized forced
  identity/relationship/exact-value disclosure on an eligible persistent-payment
  target, with actual truth included. A finite guessing-rate threshold breach is
  a screen finding; a population-rate violation needs the frozen inferential
  justification. Report the exact affected observer, horizon and policy.
- **Survive this screen:** every required case/control completes, predictions
  predate scoring, truth is included, eligibility stays fixed and no frozen
  attack breaches the screen's criteria. If claiming an RFC rate gate, every
  required adjusted one-sided 95% upper bound must also meet its absolute and
  advantage limits. Survival concerns only these attacks and modeled policies;
  it is not general privacy, 32 independent people or a full RFC qualification.
- **Incomplete:** missing observations, unsupported scenarios, solver unknowns,
  disagreement, truth exclusion, contamination, outcome-dependent eligibility,
  unaccounted comparison selection or insufficient statistical precision.
  An interval crossing an acceptance limit cannot become a pass. Preserve the
  failed attempt; repair the method prospectively before fresh evaluation.

Prompt cashout is a comparison arm, not an excuse to relax the persistent arm's
absolute gates. Never condition exits on a privacy delay or other users' action.
No source inspection or passing implementation control establishes cryptographic
security, real-world anonymity or production readiness.

## Read-only implementation review

The new [workload](../poc/shared-pool/population_privacy_strong_workload.py),
[observer](../poc/shared-pool/population_privacy_strong.py),
[scorer](../poc/shared-pool/population_privacy_strong_score.py),
[runner](../poc/shared-pool/population_privacy_strong_trial.py) and
[prospective specification](../poc/shared-pool/POPULATION-PRIVACY-STRONG-SPEC.md)
were inspected before held-out generation. The final freeze, not this note's
candidate commit alone, identifies the newly added experiment sources.

The runner samples after copying/hashing sources and controls, mounts one public
history/view/policy per observer, and seals all sixteen predictions before any
scorer receives truth. Public source availability includes declared controls and
generation policy, not hidden generation results. The observer adds no guessed
notes to its known-note registry. Split hypotheses reject known-spend conflicts,
coinput reuse and inconsistent owner/order assignments; global survival remains
an explicit heuristic assumption. The scorer retains misses in eligibility,
orders guesses using only sealed ranks, checks the realized workload separately
and requires truth in both original relation encodings.

The frozen design deliberately evaluates pooled final observations only, not
every RFC profile/horizon. Its 99 two-sided Hoeffding intervals use independent
history units, both Bonferroni tails and width two for paired differences.
At sixteen histories, the approximately 0.509 rate radius cannot certify even
maximal selective-precision or paired-advantage breaches; very large absolute
identity/amount failures remain detectable. Raw exceedances must be reported.
This conservative failure screen cannot qualify the adopted privacy gates.

This is an author-team source review, not an external audit or execution result.
Passing prospective controls, the frozen identities and the fresh run's evidence
must be reported separately. No new proofs or native/network tests were run here.

[transaction]: https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/core/src/tx.rs#L119-L295
[inline]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx
[initiative]: https://github.com/olafweller/kaspa-privacy-initiative/commit/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1
[issue13]: https://github.com/olafweller/kaspa-privacy-initiative/issues/13
[orchard]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/builder.rs#L786-L814
[aztec]: https://github.com/aztec-labs-eng/aztec-node/blob/29853ddaf2a9f70441fc2f733ada555eb50dbdc0/docs/docs-developers/docs/resources/considerations/privacy_considerations.md
[zip224]: https://github.com/zcash/zips/blob/d167dd3994e40790971f8f00b0b330885d2c9fe5/zips/zip-0224.rst#security-and-privacy-considerations
[zip315]: https://github.com/zcash/zips/blob/d167dd3994e40790971f8f00b0b330885d2c9fe5/zips/zip-0315.rst#L513-L566
[monero-analysis]: https://petsymposium.org/popets/2018/popets-2018-0025.pdf
