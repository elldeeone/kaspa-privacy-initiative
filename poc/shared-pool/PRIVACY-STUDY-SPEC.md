# H11: fresh exit proofs under independent low-activity funding

Frozen before generating or scoring H11 ledgers. Baseline `b3a6259`;
branch `shared-pool-four-wallet`. This is an offline experiment authorized by
the owner, not an upstream protocol decision. No broadcast or new cryptography.

## Question and decision

Does a fresh proof using the latest available commitment root, with the old
proof kept privately as an exit fallback, materially reduce inference of the
transaction that created a withdrawn note? Does that benefit survive all the
other notes being withdrawn? Select continued wallet-policy work or a change
to the note/withdrawal relation before more wallet development.

Keep the existing screening targets: at least 25% relative reduction in correct
top-1 inference at full coverage in **both** low-activity regimes, paired 95%
intervals excluding no improvement, at most 25% additional native fees, and p95
additional withdrawal delay at most 30 minutes. Report absolute success and
public-prior performance too; these thresholds do not define real anonymity.
The primary endpoint is the complete-drain horizon and all matched withdrawals,
not the best-looking individual payment. At-withdrawal results are secondary.

## Evidence levels

1. Generate 32 independent synthetic ledgers per regime. An integer constraint
   model covers the existing v5 relation; its inputs are explicitly modeled
   public fields, not fabricated valid Kaspa transactions. Cryptographic byte
   strings are opaque under the existing confidentiality assumptions. This
   model can falsify the policy using a subset of actual chain information; a
   passing model alone cannot qualify practical privacy.
2. Realize the first ledger of each regime using genuine proofs, the unchanged
   v4 circuit/parameters and v5 covenant/native validator. Compare the public
   decoder's projection and candidates against the model, and test both full
   drains. This is a calibration of the tested relation, not 64 native trials.
   Do not replace proof bytes with a changed anchor. Preserve old bundles.
3. Record the result, uncertainty, limits and keep/redesign decision. A negative
   result completes the study but does not pass the candidate. A TN10 rerun is
   unnecessary unless a new chain mechanism needs validation.

## Frozen ledgers and clocks

Python `random.Random(seed)` generates workload choices only. Keys, note secrets
and proof randomness in native calibration use the existing OS RNG. The observer
knows the workload distributions and protocol, but receives neither seeds nor
their draws, wallets, truth, other arms or experiment labels. Publicly describing
synthetic seeds is a reproducibility aid, not an operational anonymity claim.

| Regime | Seeds | Admission minutes | Additional payment minutes | Withdrawal requests |
| --- | --- | --- | --- | --- |
| Sparse | 211000..211031 | 0, 60, 120, 180 | 195, 225 | 240 plus 3 minutes per randomly ordered live note |
| Short burst | 212000..212031 | 0, 5, 10, 15 | 18, 24, 30, 36 | 45 plus 3 minutes per randomly ordered live note |

Four independently controlling wallets join. Genesis is one minute before the
first self-split; the first admission is that required bootstrap. The other
three are actual v5 two-note admissions. Each contribution is sampled uniformly
from 8.0..16.0 tKAS in 0.1-tKAS steps. Each admission's first note is sampled on
the 0.1-tKAS grid, leaving a valid sibling after the exact fee. Each payment
chooses uniformly among live notes that can pay two floor notes and its fee,
sends a uniformly chosen valid grid amount to a uniformly chosen other wallet,
and returns change to its owner. No wallet or note is counted as a real person.
All live notes eventually exit in a uniform shuffled order. No further traffic
is invented after the last listed payment. Amounts are integer sompi throughout.

Two matched public funding controls: four unrelated synthetic funding roots,
and visibly shared allocator ancestry. The latter changes the external-funding
clustering result, not the hidden ledger or sample size. Independent roots are
an explicit favorable assumption, not proof of unrelated owners.

Additional controls: one wallet/bootstrap/two exits with no other activity;
eight equal-contribution ledgers per regime (10 tKAS, seeds 213000..213007 and
214000..214007). Equal-contribution controls are reported separately and never
substituted for the primary workload after seeing results. No learned attack
training or tuning on evaluation truth.

## Policies and matched arms

- **Saved:** each exiting note uses a proof saved at its creation root.
- **Fresh:** all exiting notes use the latest root available at their requested
  withdrawal. The old bundle remains private. No scheduling delay is added.
- **Fresh plus wait control:** shift every requested withdrawal by 20 minutes,
  then refresh. No new traffic arrives during that interval. This deliberately
  tests waiting without assuming free cover traffic; it must not manufacture
  candidates. The same-order economic trace, destinations and fees are retained.

This tests one mechanism and its bounded-wait variant, within the two-policy
limit. Both policies require local proving, keys and retained authenticated
history; neither needs a protocol change, trusted relayer or operator signature.
Partial exits and aggregation are **not implemented here**. Note values, owners,
payment choices, order and observation horizons match across arms. Native
transaction IDs/outpoints and genuine proof bytes can differ. Keep exact payout
scripts, nullifiers, values and fees; only anchor fields in exit authorizations
may change. Fresh-proof startup and proving are added separately to schedule
delay; report estimates from calibration, not simulated network latency.

## Observer and hidden truth

An actual chain observer can read ordinary funding ancestry and values, reserve
ancestry and values, input/output scripts, fees, operation shape, accepted order
and timestamps, the complete proof and redeem script, authorizations (domain,
anchor count/root, nullifier, commitments, mode, payout, fee, destination,
bootstrap value, ciphertext hash), ciphertexts, successor state and public
Merkle/nullifier witnesses. Native calibration supplies all serialized fields
and ordinary prevout contexts to a separate decoder. Synthetic timestamps are
declared clocks, not block observations.

The model projects funding ancestry, initial reserve, operation order/time,
deposit value, current and authorized commitment counts, fee, payout, created
positions and an opaque unique destination. Roots/paths expose accepted public
history and anchor selection; they do not reveal private membership paths.
No duplicate commitments, reused payout addresses or leaked fallback bundles
are generated. We do not claim the projection exhausts possible byte-level
attacks. A negative result with fewer fields is sufficient to reject the policy;
a positive result needs broader validation.

Truth contains actual consumed position, note value, wallet ownership and
deposit ancestor. A separate scorer reads it only after the isolated observer
finishes. Observer processes mount only their own public arm and attack code,
with no home directory, generator/config/seed file, truth, other arm or network.
RPC query logs, IP addresses, mempool observations, collusion, known merchants
and off-chain payment information are excluded, not assumed protected.

## Attacks, metrics and controls

Freeze these attacks before evaluation:

1. Public-prior comparator: uniform over eligible creating transactions.
   Timing/order baseline picks the most recent eligible transaction.
2. Amount bounds: reject candidates whose maximum possible value (funding,
   accumulated fees and sibling floor) is below payout plus fee; rank remaining
   sources by recency. No secret amount or ownership is available.
3. Joint integer histories: real spends consume different eligible positions;
   deposits create two notes summing to funding minus fee; transfers consume one
   note and create two positive notes; full exits reveal their input value.
   Enforce backing and all observed exits jointly. Infer possible creating
   transactions and deposit ancestors; rank feasible sources by recency.

Use transaction ID lexical order only for equal-time ties. Also report expected
uniform success within each feasible source set. For the primary endpoint use
the strongest observed aggregate success among the three fixed full-coverage
attacks in each arm; do not select different attacks for individual targets
using truth. Report each attack separately. Count each ledger equally, pairing
arms. Bootstrap whole ledgers 10,000 times using seed 215000 (percentile 95%
intervals), recomputing the strongest aggregate attack per resample. Do not
treat correlated notes/arms/funding controls as independent samples.

At withdrawal and full drain report: top-1 accuracy; unique-source precision,
coverage and abstention; source, exact-note and deposit-ancestor candidates;
uniform-prior expected success; total transactions/fees and extra scheduling/
proof work. Report funding-cluster candidates separately from deposit origins.
Candidate counts are logical possibilities, not posterior probabilities or
numbers of anonymous people. Compare delayed arm predictions for equality.

Required failure controls: actual truth must remain feasible; singleton remains
source-unique; deliberate impossible balances, wrong counts, duplicate spends
and missing history are rejected; same-total symmetric deposits must retain
ambiguity where history permits it. An independently enumerable tiny integer
fixture checks the solver's candidate sets. Unknown/incomplete solver results
are not ambiguity or a pass. Any operational problem is diagnosed and recorded;
do not drop hard ledgers or redraw amounts.

Native calibration verifies full/native policy checks, exact accounting and
zero liabilities in both arms, identical saved proof bytes, actual fresh proof
generation, and the same nullifier/exact recipient/amount/fee. Reuse H9/H10's
existing same-note duplicate-spend evidence and add current-state losing-bundle
rejection in these paired ledgers. Run the saved arm without a prover. Raw old
arms, unused proofs, wallets and truth stay outside Git. Export allowlisted
fresh-arm public evidence and aggregate paired scores; scan for all known
secrets and unused old proof bytes before committing.

## Stop and source boundary

Reject the policy if it misses the registered tradeoff, if useful results rely
on hidden observations, cherry-picked exits, fictitious users, unlimited delay,
or an operator. If amount/topology reconstruction defeats the freshest possible
anchors at full drain, stop adding delay and scope the smallest change to the
withdrawal/value relation separately. Do not implement that redesign here.

This adapts the existing [source review](../../research/compact-privacy-source-review-2026-10-19.md):
Orchard separates historical membership from privacy; Kappos et al. motivate
value/time attacks; Moser et al. motivate elimination and age baselines. It does
not reuse their historical success rates. The v5 circuit/covenant and H10 fees
remain pinned to the branch and native dependency `01b532e`.
Sources refreshed before implementation: Rusty Kaspa `24854ef`, KIPs `e4ae233`,
vProgs `f9b84a8`, research `c923fac`, Orchard `616a669`, RAILGUN `36bcf5e`,
initiative `05ea24a`. Existing Aztec/Monero/MWEB comparisons remain research
references, not imported capabilities. No consensus or architecture change is
needed to implement this analysis harness.
