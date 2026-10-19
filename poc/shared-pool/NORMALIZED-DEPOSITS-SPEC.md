# H12: equal net credits and deposit-origin inference

Freeze this specification before generating evaluation workloads. Baseline
`5cfa94d`, branch `shared-pool-four-wallet`. The owner authorized the offline
comparison and, conditionally on useful results, complete TN10 validation.
No push, upstream post, mainnet, new token or cryptographic/protocol change.

## Question and decision

Can a wallet funding policy that gives each of four depositors the same private
balance **after the admission fee** materially reduce reconstruction of the
original deposit after all notes leave? H11 measured creating transactions as
its primary target; this study deliberately targets **funding deposits**.

Retain fresh latest-root proofs, with creation-root proofs kept privately as
fallbacks. Test the existing v4 private relation/parameters and v5 covenant.
If useful, retain equal net credit as a candidate wallet policy and validate
its payment/independent-exit path on TN10. If not, record the negative result
and investigate payment splitting/full withdrawals separately. Do not implement
a relation redesign in this experiment.

## Paired workloads

Use 32 paired ledgers per regime, sparse seeds 221000..221031 and burst seeds
222000..222031. Each ledger has four wallets and three funding policies:

1. **Varied:** four gross contributions drawn uniformly from 8.0..16.0 tKAS,
   in 0.1-tKAS steps, as in H11.
2. **Equal gross:** each contributes one quarter of that ledger's gross total.
3. **Equal net:** each receives one quarter of that ledger's total private
   credit; its contribution adds its own exact admission fee.

All quantities are integer sompi. Divisibility is exact on this grid: the
bootstrap fee is 21,893,200 and each later admission fee is 22,005,200.
All three arms have identical total gross funding, total credited value, number
of notes, fees, clocks, ownership topology and exit order. The common amount
can differ between ledgers; this tests equalization within one pool, not a
globally fixed denomination or mixed-denomination privacy.

Use separate deterministic random streams for contributions, splitting, payment
selection and withdrawal order, with labels derived from the experiment seed.
Public transaction/destination labels use OS randomness, not the reproducibility
seed. They are opaque and must not encode truth. No seed/label key goes to the
observer. The published seed schedule is for reproducibility, not a privacy
assumption about real wallets.

Choose each payment input uniformly from live positions eligible in **all three
arms**; each must cover two 60,000,000-sompi floor notes plus its fee. Use the
same other-wallet receiver and shared uniform split quantile mapped to each
arm's valid 0.1-tKAS grid. Sibling change absorbs the exact remainder. This
controlled common-topology workload is intentionally not three independent
populations. Report that conditioning. If no common input exists, retain the
failure; never redraw/exclude a ledger. Actual payment amounts can differ
between arms; eligibility, topology, draw quantiles and clocks do not.

Sparse admissions: minutes 0/60/120/180; payments 195/225; exits from 240.
Burst admissions: 0/5/10/15; payments 18/24/30/36; exits from 45. Genesis is at
minute -1. All payments occur after all four admissions. Shuffle live notes
once, then withdraw every note with three minutes between requests. No further
traffic, waiting, merging or partial withdrawals. These are synthetic clocks.
Each wallet keeps change and must have at least one independent exit.

Controls: singleton with no other funding; the paired equal-gross arm; shared
allocator ancestry for the first ledger of each regime; and an explicit
early-exit fixture before the other deposits. Equal net credits must not invent
privacy when a withdrawal precedes every possible alternative source. Retain
H11's complete result without pooling its data into this new experiment.

## Observer, attacks and metrics

Reuse the H11 public decoder and exact integer feasible-history observer.
Its process sees only its own public trace and attack software, without truth,
generator, seed, other arms, home directory or network. It sees public funding
values/ancestry, fees, operation types/order/clocks, commitment counts/anchors,
full-exit payouts, destinations and reserve balances. Native calibration also
supplies complete serialized transactions and ordinary prevout contexts.
Private values, ownership, consumption and true deposit ancestry stay with the
separate scorer. Ciphertexts/proofs/commitments are assumed confidential; byte
fingerprints beyond the decoder projection are not exhaustively assessed.

Keep timing, amount-bound and joint-history source attacks unchanged. For the
new primary target, report the joint history's deposit candidates and use two
fixed full-coverage deposit rankings: most recent and oldest feasible deposit.
Report each, the stronger **aggregate** accuracy (not a truth-selected per-exit
attack), and uniform expected success within candidate sets. Report initial
eligible-deposit prior, unique-deposit precision/coverage/abstention, source and
note candidates, and funding-cluster candidates separately. Logical candidates
are not equally probable people. Multiple notes from one wallet are not users.

Primary horizon: complete drain. Also report what was inferable when each exit
occurred. Score every withdrawal in every retained ledger; equal ledger weight.
Paired bootstrap of whole ledgers, 10,000 draws, seed 223000, percentile 95%
intervals. Never treat notes, arms, or funding controls as independent samples.
Validate all true note/source/deposit assignments remain feasible before scoring.

## Frozen screening criteria

For **both** sparse and burst regimes, equal net credits must:

- reduce the unique-deposit fraction by at least 50% relative to varied funding,
  with the paired absolute reduction's 95% lower bound above zero;
- leave at most 25% of withdrawals with one logically possible deposit, and at
  least three deposit candidates on average;
- keep the stronger fixed deposit-ranking accuracy at or below 50% (four
  candidates' uniform benchmark is 25%; this is a screen, not adequate anonymity);
- improve unique-deposit reconstruction over equal gross funding, with the
  paired absolute improvement's 95% lower bound above zero;
- add no transactions or scheduled waiting, at most 25% native fee overhead,
  and preserve every independently payable claim and private fallback.

These thresholds select a further test; they do not certify useful anonymity.
Record absolute results even if every screen passes. In particular, equal-net
root permutation may explain the outcome for this all-deposits-first workload;
state that structural explanation instead of portraying 64 samples as new
cryptographic evidence. Workload-informed priors, interleaved activity, unequal
denominations and off-chain knowledge can break that symmetry.

## Native and conditional TN10 validation

Realize the **first equal-net ledger in each regime**, without selecting after
scoring, using genuine proofs, the existing parameters and native full/policy
validation. Compare decoded public projection and exact inference candidates
with the model. Settle complete saved and fresh alternatives offline, with no
wallet secrets or proving key in exit processes. Check both same-note winner
orders reject the losing bundle against current state; preserve H10's hostile
native duplicate controls. Record unchanged selected proof/auth bytes, zero
liabilities/reserve, payout floors, all four wallets paid, fee/mass and proving
time. No claim of four separate machines or general reorg robustness.

Only if the frozen screen and native validation pass: create a fresh TN10
identity in one command, run a complete rehearsal, then a separate fresh
measured trial. Use the first sparse equal-net economic plan for both, fresh
keys/domains/notes each time. Actual submission/confirmation times replace any
claim about synthetic minutes. Stop the prover before exits; each wallet uses
only its own bundle, pinned public material and its own verified node view.
The controller may schedule test calls but must supply no private proof repair,
new authorization or special signature to make an exit possible.

Verify every accepted body/full hash, payout and all ordinary change; reconcile
fees and complete drainage. Use the existing test funding, explicitly retaining
its shared ancestry. This is mechanism/fee validation, **not** independent-user
or network-privacy evidence. Keep RPC/IP observations outside the chain-only
study. Never silently rebroadcast a used submission identity. Diagnose failures,
retain evidence and use fresh trial identities; recover accepted claims through
ordinary authorized exits if needed.

## Integrity and stop conditions

Freeze the specification in Git before generation. Pin implementation bytes and
workloads before evaluation. Unknown/incomplete solver results are errors, not
extra privacy. Reuse independent tiny enumeration and solver crosschecks; add
equal-net symmetry, fee-fingerprint, pairing/conservation, malformed inputs and
no-cover negative checks. Do an adversarial second pass for inflation, duplicate
spends, wrong exits, stale state, privacy, lost dependencies and hidden trust.

Keep seeds/truth, wallets/note openings, funding keys and unused fallback bundles
outside Git. Export allowlisted public fresh evidence and aggregate scores,
scan for actual secret values and unused proof bytes, and update the journal,
plan and relevant policy decision. Do not change SECURITY-INVARIANTS.md.

Stop policy adoption if any frozen screen fails, if correct accounting or an
independent exit fails, or if an apparent benefit needs hidden observer inputs,
omitted withdrawals, added fictitious users or protocol changes. A completed
negative result is useful. Operational slowness alone is not a research failure.

## Sources and reused components

Reuse [H11's source review](../../research/compact-policy-study-sources-2026-10-20.md)
and [H10's mature-protocol comparison](../../research/compact-deposits-source-review-2026-10-19.md).
This changes funding policy and an experiment harness, not notes, nullifiers,
proof semantics, cryptography, scanning or covenant rules. Orchard's membership
boundaries and established amount/joint-elimination attacks remain applicable;
no vProgs runtime, token, relayer privilege, ring signature or MWEB consensus is
introduced. Reopened [KIP 17](https://github.com/kaspanet/kips/blob/master/kip-0017.md)
and [Orchard commitment-tree documentation](https://github.com/zcash/orchard/blob/main/book/src/design/commitment-tree.md)
on 2026-10-19 UTC. Rusty Kaspa head is now `4edcbbccb449f84832afb1ca157904b35f37d006`,
whose change since H11 is workflow/WASM/wRPC maintenance. Native dependencies
remain pinned to `01b532e8b553523216471682649693af92f0fd16`; do not silently
upgrade them. Validate actual TN10 acceptance separately from source inspection.
