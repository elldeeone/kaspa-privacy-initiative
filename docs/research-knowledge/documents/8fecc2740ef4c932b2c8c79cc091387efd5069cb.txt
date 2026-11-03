# Four-wallet shared native-KAS pool — TN10

This report describes **version 2 at checkpoint `62c8550`**. Its evidence is
unchanged. Reproduce its code and observer model from that checkpoint; the
current native code uses a new version-3 domain and proof relation. The
[note-floor and contention follow-up](CONTENTION.md) records that separate test.
The additional `kpi-anchored` executable tests a different authorization/settlement
split. Its [completed offline and TN10 result](ANCHORED.md) shows Bob reusing his
private proof after Alice's payment; it leaves the earlier experiment intact.
The separate [compact-state experiment](COMPACT.md) extends this question to
100 intervening payments using fixed-depth native Merkle checks.
The [independent recovery follow-up](RECOVERY.md) tests restoring three wallets
from pre-payment backups and public data after the original services stop.
The [fresh-proof comparison](FRESH-PROOF.md) tests the compact privacy mechanism
offline, retaining an old private exit fallback while preventing a second spend.
The [independent-deposit experiment](DEPOSITS.md) adds a separate immutable v5
pool accepting independently signed two-note deposits while preserving saved
exit proofs. Offline, complete TN10 rehearsal and a fresh measured trial passed
with all four wallets paid and no remaining reserve. The original v2 report below remains unchanged.

Both funded runs completed on 2026-10-19 using the owner's existing TN10 node.
Four separate wallet processes re-spent received notes and independently proved
their exits. Every native payout was confirmed, both reserve outputs were fully
spent, and all 42 submitted transaction bodies/full hashes matched the node's
retrieved accepted-chain data. No token, operator withdrawal key, vProgs runtime
or node/consensus change was used.

This is a bounded, unaudited experiment. It demonstrates the tested sequence on
one TN10 node, not production safety or general adversarial exit liveness.

## Result and cost

| | Full withdrawals | Partial withdrawals, then drain |
| --- | ---: | ---: |
| Confirmed transactions, including allocation/bootstrap | 19 | 23 |
| Private payments / later deposits | 5 / 3 | 5 / 3 |
| Withdrawals | 9 full | 4 partial + 9 full |
| Total fee, tKAS | 2.849380 | 3.517918 |
| Pool-operation fee, excluding allocation/bootstrap | 2.840851 | 3.509371 |
| Warm proving median | 10.967 s | 10.956 s |
| Sum of proof-generation time | 186.767 s | 230.564 s |
| Sequential live broadcast/confirmation observation | 38.976 s | 47.221 s |
| First four withdrawals to full drain | 10.336 s | 18.598 s |
| Reserve left | 0 | 0 |

Partial withdrawals added four eventual exits: **0.668520 tKAS in additional
pool fees**. Ordinary allocation fees differed by another 0.000018 tKAS because
storage mass depends on input/change amounts. Combined fees were **6.367298
tKAS**. After both runs, the original 189.997951 tKAS funding input reconciled
exactly to fees plus **183.630653 tKAS in 25 confirmed ordinary native outputs**.
Those include wallet payouts and unused ordinary funding change; none is a pool
reserve. Existing prior-trial balances are outside this reconciliation.

The node quoted 100 sompi/gram. Actual fees were 0.166718 tKAS per transfer,
0.167838 per later deposit, 0.167130 per continuing full/partial withdrawal and
0.166707 for the terminal withdrawal. These are experimental transaction costs,
not a production fee forecast or a dollar price.

All proofs were precomputed before funding. Live observation used two-second
UTXO polling, so its roughly two-second per-transaction observations are not
precise consensus latency measurements or interactive payment latency. Warm
proof generation ranged from 10.804 to 11.236 seconds across both runs.

The proving key is 646,913,872 bytes. Four wallet processes loaded and validated
it concurrently; each took 172.725–177.994 seconds. Setup took 63.543 seconds
and produced 3,231,940 constraints. Proving used four Rayon threads per active
wallet on the local CPU. No GPU acceleration was used. The namespace launcher
resource wrapper does not provide a reliable prover peak-RSS measurement.

## Privacy result

For the first four withdrawals, in their public order:

| Chain-only inference | Full | Partial with equal first payouts |
| --- | --- | --- |
| Possible source transactions after those four withdrawals | 5, 5, 5, 5 | 8, 9, 10, 11 |
| Possible source transactions after complete drain | 5, 5, 5, 5 | 5, 6, 7, 8 |
| Possible consumed notes after complete drain | 10, 10, 10, 10 | 10, 11, 12, 13 |
| Possible deposit ancestors after complete drain | 4 each | 4 each |
| Exact original note amounts inferred after complete drain | 4 of 4 | 0 of 4 |

Partial withdrawal increased candidate counts for all four exits at the first
horizon, and three of four after drainage. Neither arm uniquely identified a
source transaction for these exits, so the experiment does **not** show a
reduction in unique-source identification. Deposit-origin ambiguity was also
unchanged for them. Additional partial-arm candidates include earlier partial
change outputs; they are not additional people or additional original private
payments. All five private transfers have identical final candidate counts
across arms. One later withdrawal in each arm has a unique deposit ancestor.

The recency heuristic tied on all four selected full exits. For partial exits it
made three unique guesses and all three were wrong, at both horizons. Across
all withdrawals after drainage it guessed correctly on 1 of 2 calls in the full
arm and 2 of 12 in the partial arm; these small fixed samples are descriptive.
See the [comparison](evidence/2026-10-19-tn10/comparison.json) and detailed
[full](evidence/2026-10-19-tn10/full/scored.json) /
[partial](evidence/2026-10-19-tn10/partial/scored.json) scores.

Full withdrawals expose the entire spent note value as payout plus public fee.
The supplementary amount attack found all four selected full-exit note values
exactly. All four corresponding partial-exit input values admitted multiple
solutions at the first-withdrawal horizon and again after complete drainage.
Two exhibited feasible values prove non-uniqueness under this model; they are
not a range, probability distribution or real-world anonymity estimate.

The comparison tests **partial withdrawal with equal 0.25 tKAS first payouts**.
It does not isolate partial-change support from withdrawal-size policy. Fresh
payout keys avoid direct address-reuse clustering. Public deposit amounts,
payouts, transaction modes/counts, fees, reserve lineage and chronology remain
visible. The initial one-note bootstrap spend is unambiguously linked to its
sole source. Four synthetic wallets were deliberately funded from one common
visible wallet: they are not four independent anonymity participants.

## Workload and observation boundary

Each arm has a fresh domain and four fresh wallets, with the same public proof
parameters and fixed workload. One ordinary allocation gives each wallet
12 tKAS. Alice funds a 10 tKAS reserve and performs the first private spend,
which proves initial backing. Bob, Carol and Dave each deposit their ordinary
12 tKAS input; each new note receives the deposit minus that transaction's fee.
A deposit before the bootstrap proof is rejected.

The five private payments are:

1. Alice → Bob: 4 tKAS from the initial note.
2. Bob → Carol: 3 tKAS from the received note.
3. Carol → Dave: 5 tKAS from Carol's deposit note.
4. Dave → Alice: 2 tKAS from the received note.
5. Alice → Bob: 1 tKAS from the received note.

Alice's last change, Bob's last receipt, Carol's 3 tKAS receipt and Dave's change
from the 5→2 payment are selected for the first four withdrawals. The full arm
spends each whole note; the partial arm pays 0.25 tKAS from each and creates
private change. Each wallet then scans and exits all its remaining notes.
There are no unrelated pool users, background transactions, intentional delays,
batching, cover traffic or independent sampling runs. The schedule is sequential
and known to the experiment coordinator, but excluded from observer inputs.

The observer receives only canonical accepted transaction bodies, spent-output
context and the published format. These are retrieved through RPC as transport
for public chain data. It does **not** receive RPC client identities, network
traffic, mempool arrival timing, the wallet manifest, keys, viewing material,
private selections, ownership labels or the workload plan. Its namespace mounts
only the analysis software/dependencies and the chain transcript. The scorer
receives hidden truth only after inference. Synthetic truth without keys or note
randomness is disclosed in the evidence for reproducible scoring.

The model enumerates marginal possible consumed commitments, creating
transactions and deposit ancestors using integer conservation, one-input
semantics, no repeated spend, chronology and reserve backing. Creation-event
counts prevent interchangeable sibling notes from being counted as independent
source transactions. A separate recency heuristic selects the latest feasible
creation event and reports ties rather than inventing a confident guess.
Candidates are logical possibilities, not equal-probability users or counts of
joint histories. The graph model uses protocol-positive amounts; it does not
silently import this wallet's minimum-note policy.

Each horizon builds a new solver from only its prefix: single-note bootstrap,
first four withdrawals, and complete drain. The scorer checks that every true
candidate survives and pins the entire true joint history to verify it satisfies
the model. The supplementary amount test asks whether a second distinct input
value exists and checks every uniquely inferred value against hidden truth.
Its addition after the original full-arm graph result is documented rather than
presented as preregistered. Redundant arithmetic bounds accelerate the solver
without adding observer knowledge or excluding feasible histories. The selected
model adds per-deposit conservation implied by the one-input/no-merge format.
Its full-arm candidates exactly match the original model. The selected partial
analysis completed in 263 seconds for the final horizon; two redundant, slower
profiling runs were stopped afterwards, not counted as results or privacy.
Source snapshots and amendments are preserved under
[methodology](evidence/2026-10-19-tn10/methodology).

## Current-L1 layout

See [ADR-0016](../../docs/adr/0016-four-wallet-shared-pool-trial.md),
[RFC-0004](../../docs/rfc/0004-four-wallet-shared-pool.md) and the
[source review](../../research/shared-pool-four-wallet-source-review-2026-10-19.md).

- Standard P2SH reserve; immutable script/VK suffix propagation uses current
  introspection, SHA256 and native BN254 Groth16 verification.
- Fixed 24-slot append-only commitments/nullifiers; 1,539-byte state,
  1,918-byte payload, 1,795-byte bound transcript, two 128-bit public limbs.
- 128-byte proof, 328-byte verifying key, 4,096-byte redeem script and
  4,229-byte signature script. Full exits append no commitment and work at
  capacity in the tested circuit.
- Later deposits consume reserve input 0 plus the depositor's signed ordinary
  input 1. Other operations consume only the reserve. Fees reduce the consumed
  private claim, or the new depositor's credit, and match the actual native fee.
- A partial exit creates one public P2PK payout and one encrypted private change
  note. A full exit creates no note; the final full exit proves exhaustion.

The Rust/native and WASM SDK pin is Kaspa v2.1.0 commit
`01b532e8b553523216471682649693af92f0fd16`; the actual node reports `2.0.0`.
Relevant later upstream changes were reviewed in the source note. The node's
executable hash was not attested. Live acceptance supplements local native Full
validation and default-policy checks; these are distinct evidence levels.

## What independent exits mean here

Each wallet process gets its own spending/viewing/native-key file, the public
parameters and history, and its own output directory. It has no network, host
home, other wallet files or operator process. It scans its own encrypted notes,
validates history, generates its own proof and derives a fresh native payout key.
The relay handles only already-built public transactions. Nobody else's secret
or approval authorizes an exit. All four wallets rescan the final history and
have no remaining accepted notes in each arm.

This proves separate authority and successful exits for the chosen sequence.
It does not prove availability under arbitrary reorgs, competing spends,
malicious small notes, missing archives, unavailable proving parameters or setup
compromise. All users share a serial reserve outpoint: another accepted spend
can stale a proof and force rebuilding/reproving. No contention test was run.

Wallets quarantine notes too small to pay the configured exit fee plus a
0.1 tKAS native payout, without blocking usable notes. The circuit still permits
smaller positive notes. An adversarial tiny liability can make a later remaining
reserve fail native storage-mass limits. A protocol-level rule or dust-handling
mechanism remains necessary before claiming adversarial exit liveness.

Single-party Groth16 setup, retained public artifacts and unaudited circuit/key
code remain assumptions. RPC/network anonymity was not tested. Native-KAS
backing was exercised on TN10 only; no mainnet safety claim follows.

The result supports keeping partial withdrawal and private change in the next
prototype. Before scaling the wallet count, address protocol-level dust and
test two wallets racing the same reserve: the losing wallet must rescan,
rebuild and complete its exit without the winning wallet or an operator. This
would test a missing usability/liveness property rather than repeat the
sequential demonstration. No such follow-on trial was run here.

## Checks and reproduction

Six Rust tests passed across the circuit/encryption and wallet-policy groups.
The circuit cases include over-crediting, under-backed bootstrap, authorization,
range/overflow, spent-note replay, state overwrite, changed ciphertext, stale or
foreign state, premature terminal exit and capacity exhaustion. Native controls
reject 53 mutations in the full arm and 65 in the partial arm, covering all five
modes; deposit outpoint/amount/owner cases also require reserve-input rejection
independently of the ordinary depositor signature. All 42 transactions passed
native validation, exact SDK round trips, relay admission, UTXO confirmation and
accepted-body/full-hash comparison. Eight analytic observer controls passed.
See [review and remaining limits](ADVERSARIAL-REVIEW.md), the
[verification record](evidence/2026-10-19-tn10/verification.json), and the
[final paired accounting](evidence/2026-10-19-tn10/paired-final-check.json).

```sh
cargo +1.95.0 build --locked --release --manifest-path poc/shared-pool/Cargo.toml
cargo +1.95.0 test --locked --release --manifest-path poc/shared-pool/Cargo.toml
python3 -m venv /path/to/analysis-venv
/path/to/analysis-venv/bin/pip install z3-solver==4.15.4.0
/path/to/analysis-venv/bin/python poc/shared-pool/test_observer.py
```

`kpi-shared-pool setup PARAMS` generates experimental parameters. Creating an
unfunded identity is one command: `kpi-shared-pool init PARAMS NEW_TRIAL`.
The funded runner requires an owner-provided **TN10-only** funding key file and
SDK. Set `KPI_BINARY`, `KPI_SDK_PATH`, `KPI_TN10_RPC`, and `KPI_FUNDING_DIR` as
needed; funding.json contains `network: testnet-10` and its address, while
funding.key is a local 0600 file. Do not put key bytes in arguments or reports.

```sh
node poc/shared-pool/run.mjs prepare PARAMS TRIAL_BASE full
# Use the printed new trial path. Preparation includes every terminal proof.
node poc/shared-pool/fetch-chain.mjs anchor TRIAL
node poc/shared-pool/run.mjs live TRIAL
node poc/shared-pool/fetch-chain.mjs fetch TRIAL
python3 poc/shared-pool/analyze-isolated.py TRIAL/chain-confirmed.json TRIAL/blind-observer --venv /path/to/analysis-venv
python3 poc/shared-pool/analyze-isolated.py TRIAL/chain-confirmed.json TRIAL/blind-amounts --amounts --venv /path/to/analysis-venv
/path/to/analysis-venv/bin/python poc/shared-pool/score.py TRIAL/private-truth.json TRIAL/blind-observer/observer.json TRIAL/scored-complete.json --chain TRIAL/chain-confirmed.json --amounts TRIAL/blind-amounts/amounts.json
```

Repeat with `partial` and a fresh identity. A used live identity cannot be
rebroadcast. A failed trial requires a fresh identity, not weakened checks.
Wallet secrets and public proving parameters remain outside Git. Public
transaction evidence embeds the verification key and can be checked without
proving parameters. Native private payout keys remain derivable from each
wallet file using `Wallet::payout_key(domain, step)`.
