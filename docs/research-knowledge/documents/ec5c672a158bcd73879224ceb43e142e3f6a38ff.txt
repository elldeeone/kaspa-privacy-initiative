# Fresh proofs help; funding links survive

H11 completed offline, 2026-10-20 (Australia/Sydney). The existing fresh-proof
policy **passes the frozen screening thresholds**. It is worth retaining with
a private saved exit fallback. It does not yet provide strong payment privacy:
full drainage makes most funding deposits uniquely reconstructable.

[Frozen specification](PRIVACY-STUDY-SPEC.md),
[evidence](evidence/2026-10-20-privacy-study),
[adversarial self-review](PRIVACY-STUDY-REVIEW.md),
[source refresh](../../research/compact-policy-study-sources-2026-10-20.md).
No new circuit, covenant, setup, token, consensus rule or chain transaction.

## Results that select the next design step

The primary target is the **transaction creating the withdrawn note**, not a
person, sender address, recipient identity or its original funding deposit.
The strongest of the three frozen attacks is scored at full coverage after
every claim exits. Both regimes contain 32 generated four-wallet ledgers.

| Primary workload | Withdrawals | Saved-proof correct guesses | Fresh-proof correct guesses | Relative reduction, paired 95% interval |
| --- | ---: | ---: | ---: | ---: |
| Sparse: two later payments | 320 | 100% | **64.4%** | **35.6%** [32.2%, 39.1%] |
| Short burst: four later payments | 384 | 100% | **38.5%** | **61.5%** [58.3%, 64.6%] |

Both exceed the predeclared 25% reduction, with intervals excluding no benefit.
These are synthetic-workload bootstrap intervals across whole ledgers, not
estimates of network users' anonymity. The saved baseline uses creation-time
anchors, making recency especially informative. No attacks were trained or
selected per withdrawal using truth.

Later observations weaken privacy substantially:

| Fresh-proof joint-history attack | Sparse | Short burst |
| --- | ---: | ---: |
| Correct source guesses at withdrawal | 33.4% | 20.8% |
| Correct source guesses after complete drain | 64.4% | 38.5% |
| Source uniquely determined after drain | 44.1% | 21.6% |
| Mean possible source transactions after drain | 2.16 | 4.24 |
| Mean possible exact notes after drain | 4.31 | 8.48 |
| **Funding deposit uniquely determined after drain** | **94.4%** | **88.5%** |

Singleton predictions are correct on these traces; the remaining cases are
abstentions for that high-precision attack. A full-coverage attacker still guesses
in ambiguous cases. Guessing uniformly among joint-compatible sources gives
62.5% / 37.0% expected success; recency gives 64.4% / 38.5%. A uniform public-anchor
prior, before value/joint elimination, gives 14.3% / 11.1%. Much of the eventual
leakage therefore comes from value/structure constraints, not a clever time rule.
Candidate sets are logical possibilities, not probability distributions.

The 20-minute waiting arm produced identical candidates and predictions: no
new activity arrived during its extra wait. It adds delay without helping this
workload. This is not a claim that timing policies never help other traffic.

## Controls and what they do not establish

- The no-activity control remains source-unique in every arm. Two notes do not
  create two independent sources or people.
- Eight equal-*gross*-contribution ledgers per regime reduce fresh full-drain
  source guessing to 38.8% / 25.0%; unique funding-deposit reconstruction remains
  21.3% / 25.0%. These are separately generated controls, not a matched causal
  test of denomination policy and not replacements for the primary workloads.
- Shared allocator ancestry leaves source/deposit candidates unchanged but
  collapses the public funding-cluster count to one. Independent funding roots
  are an explicit favorable assumption; neither root count nor common ancestry
  establishes how many people control the wallets.
- All 81 ledgers and all 882 withdrawals were retained, in four arms and two
  horizons. The primary sample remains 64 ledgers/704 withdrawals. Alternate
  arms, controls and correlated notes are not counted as independent samples.
- Ground truth stayed in the controller/scorer. Each observer saw only its own
  public projection or native trace plus attack code/runtime, in a namespace
  without the host home directory or network. Raw alternate capabilities and
  native old arms remain outside Git. Experiment seeds/distributions are
  reproducibility inputs, not a claim of secrecy against someone studying the
  published experiment itself.

## Genuine native calibration and cost

The first frozen ledger of each primary regime was also built with genuine
proofs, the existing v4 private relation/PK/VK and v5 deposit covenant. Their
exact public transaction fields produce the same projection, candidate sets
and scores as the model. This is two native calibrations, not 64 native trials.

- 58 genuine proofs were generated. Only the anchor fields changed between
  matched exit authorizations; nullifier, recipient, amount and fee stayed equal.
- Saved and fresh arms both drained in isolated processes without wallet secrets
  or the proving key: 17 / 21 transactions per arm, **76 native-validated
  transaction occurrences** across the four exclusive worlds. All 44 withdrawal
  occurrences used unchanged selected proof bytes and left zero liabilities.
- The current-state builder rejected the other proof after either winner. H10's
  hostile native duplicate-witness controls remain the stronger underlying
  nullifier evidence; H11 does not mislabel these new builder rejections as new
  hostile native tests.
- Native Full validation, relay-policy calculations, JSON round trips and exact
  backing passed. Supplied synthetic UTXOs are not live UTXO acceptance, finality
  or reorg evidence. No transaction was broadcast.

At the configured 100 sompi/mass (100,000,000 sompi = 1 tKAS):

| One native arm | Sparse | Short burst |
| --- | ---: | ---: |
| Pool fees, sompi | 351,039,200 | 438,694,400 |
| Ordinary genesis fee, sompi | 204,900 | 204,900 |
| Total hypothetical native fees, tKAS | **3.512441** | **4.388993** |
| Additional native fee from refreshing | **0** | **0** |

The pairs have identical mass and fees. Native money spent in this task: **0**.
These are the tested layouts/rate, not a current network quotation. Ordinary
external funding ancestry/creation costs beyond the supplied UTXOs are excluded
equally from both arms. H10's different funding layout had different genesis fees.

Cold PK loading took 100.541 seconds. The 22 fresh exit proofs took
9.579–26.977 seconds each; the slower part ran alongside other CPU work. Adding
that cold load to every proof gives a conservative *component estimate* of
122.057 seconds at p95 (maximum 127.518 seconds). Fresh adds no scheduling wait;
the waiting arm adds 20 minutes, yielding about 22.03 minutes at p95 for these
components. Both fit the 30-minute screening budget. This is not measured
end-to-end wallet/network latency: history retrieval, queues and confirmation
are not included, and there is only one measured cold load.

## Exact model and validation

The model uses integer sompi, public operation/anchor/fee/value constraints,
one spend per note and joint backing. It allows all protocol-compatible hidden
values; it does not read private amounts, owners or the payment graph.
Cryptographic byte strings are treated as opaque under the existing assumptions.
The native observer receives the full serialized trace, then decodes its public
projection; further byte-level, wallet-policy and external-information attacks
remain possible. A favorable result is evidence for this mechanism, not proof
of practical anonymity.

The first Z3 implementation was too slow for several four-payment cases.
CP-SAT's explicit matching helped, but partial-drain queries remained expensive.
The final implementation uses an exact specialization for the fresh arm:
enumerate transfer source choices, then partition public exit values among their
single funding ancestors. For each fixed transfer tree, enough integer value
must remain to fund every unwithdrawn leaf's floor; a fully withdrawn tree must
balance exactly. All internal note values can then be reconstructed as sums of
descendant leaves and intervening fees. This avoids searching arbitrary private
amounts. Nonmatching layouts use the general integer model.

The reduction preserves the frozen attacks and feasible histories. It does not
add a new policy or drop hard cases. It matched every candidate in both horizons
of 45 completed CP-SAT fresh cases; the CP-SAT formulation matched the original
Z3 four-wallet result. Tiny exhaustive enumeration checks source/note/ancestor
sets, including every prefix and symmetric possibilities. Balanced but impossible
cross-deposit payouts, malformed history/counts, double consumption and private
field injection are rejected. The final Python suite passed 25 tests; all 12
existing Rust library tests also passed. Slow attempts and performance probes
remain private; all 81 final draws and both native plans were byte-identical
across implementation revisions. These are implementation checks, not an audit.

## Decision and smallest next question

**Keep fresh proofs as the normal candidate path and saved proofs as a private
exit fallback.** This clears H11's preregistered screen without changing L1.
Do not add a default wait when no compatible activity arrives. The bounded
Stage 2 comparison is complete; strong privacy and broader rollout are not.

The next smallest question is whether **equal net credited deposits**, with
fresh proofs, materially reduce the remaining funding-origin inference. It can
use the existing covenant and fees. Equal gross amounts leave a small public
fingerprint: bootstrap costs 21,893,200 sompi, while a later admission costs
22,005,200. Their shielded totals differ by **112,000 sompi (0.00112 tKAS)**.
The proposed next comparison should normalize the credited amount, include the
equal-gross control, preserve withdrawals/fallbacks and measure complete drain.
This is a hypothesis suggested by the controls and code, **not a tested fix**.
Scope it separately before changing the experiment. Partial withdrawals or
aggregation would be larger relation changes; this result does not yet require
either or a consensus change.

## Reproduce and evidence

The frozen spec was committed as `294dfc6` before generating/scoring the study.
All raw identities, truth and alternate authorizations must remain outside Git.
The requirements pin the model solvers; the runner's `VENV` path identifies the
isolated Python environment. The model run needs no wallet, PK or test coins:

```sh
python3 -m venv /home/luke/.local/share/kpi-shared-pool-tools
/home/luke/.local/share/kpi-shared-pool-tools/bin/pip install -r poc/shared-pool/privacy-study-requirements.txt
python3 poc/shared-pool/privacy-study.py prepare /PRIVATE/new-study
python3 poc/shared-pool/privacy-study.py evaluate /PRIVATE/new-study
```

For the two genuine calibrations, use the existing pinned parameters:

```sh
CARGO_TARGET_DIR=/home/luke/projects/kaspa-privacy-self-funded/poc/self-funded/target cargo +1.95.0 build --release --manifest-path poc/shared-pool/Cargo.toml --bin kpi-privacy-study
python3 poc/shared-pool/privacy-study-native.py prepare /PRIVATE/new-study --params /PRIVATE/params
python3 poc/shared-pool/privacy-study-native.py analyze /PRIVATE/new-study
```

The evidence contains the frozen-spec/source hashes, per-ledger aggregate scores,
full primary/control summaries, fresh public model/native traces, observer and
no-prover isolation receipts, native fee/proof measurements and solver checks.
It deliberately omits native old arms, wallets, note openings, truth and pending
bundles. The export scan checks exact known secrets, unused saved proof bytes
and distinct old authorizations, plus injection controls. Evidence is local on
the shared-pool branch; this task performs no push or upstream posting.
