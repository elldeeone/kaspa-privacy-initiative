# Independent deposits with saved exits

H10 tests four separately controlled wallets joining one native-tKAS pool. The
new immutable v5 covenant accepts later deposits while retaining the exact v4
private relation and parameters. Earlier v5 exit proofs must survive later v5
deposits. This is not a migration of v4 claims.

**Passed, 2026-10-20 (Australia/Sydney):** offline gate, complete TN10 rehearsal
and fresh measured trial. All four wallets exited with their saved proofs.
No mainnet, new token, new setup or consensus change. The earlier variants and evidence remain intact. [Design](../../docs/rfc/0010-compact-independent-deposits.md),
[decision](../../docs/adr/0022-compact-two-note-deposits.md),
[self-review](DEPOSITS-REVIEW.md).

## What was built

A deposit spends the current reserve and one ordinary signed P2PK input. Its
unchanged private proof establishes two notes whose values sum to that input
less the admission fee. The covenant binds the actual funding amount, exact
successor reserve and commitment/history appends. It preserves the nullifier
root/count. The virtual input used by the admission proof is never a pool claim.
Ordinary transfers and exits retain real historical membership and current
nullifier insertion. There is no operator withdrawal key or admission signature.

The four-source list is a bounded harness fixture, not an on-chain allowlist.
Each depositor validates the descriptor, canonical genesis and preceding native
transitions, checks its own encrypted deliveries before signing, then scans the
accepted ciphertexts. Alice bootstraps; Bob, Carol and Dave join separately.
All contribute 1,000,000,000 sompi, each producing two notes. Their saved proofs
use commitment counts 3, 5, 7 and 9 respectively.

Each exit client gets only its own two saved bundles plus authenticated public
descriptor/VK data. It has no wallet keys, PK, original prover files or other
wallet's files. The prover processes have exited. Live clients fetch accepted
history themselves through TN10 RPC and verify the current UTXO. The host starts
these isolated processes; this is same-host namespace isolation, not separate
hardware or protection from a malicious host. A failed primary public source is
replaced with an authenticated local descriptor/VK copy.

## Offline evidence

- Twelve library tests passed, including existing proof/range/tree regressions.
- Four drain orders passed: D,C,B,A; A,B,C,D; A,C,D,B; A,B,D,C. All 32 settlements
  reused the eight saved proof/authorization pairs unchanged. Every wallet took
  the terminal role. Each ledger had 13 transactions and drained completely.
- The final control suite rejected 35 native mutations; 32 also failed the
  reserve script itself. Mutated deposit intents were re-signed where needed,
  so a bad funding signature did not mask the reserve check.
- Genuine old/fresh proofs for the same claim were tested in both winner orders;
  the loser failed against the current successor. A private transfer of a
  deposited note paid both recipients. Repeated admission proof bytes with new
  signed backing created separately spendable positions. Two exact-minimum
  notes also exited. All these control ledgers drained.
- Balanced floor mutations, one-sompi overcredit with recomputed commitments,
  invalid aggregate input bounds and corrupted delivery were rejected. With a
  fixed two-floor total, moving one sompi to either note makes the other too small.
- Missing history, missing middle transaction, corrupted genesis and wrong VK
  were rejected. A valid stale prefix can pass local replay; the separate current
  outpoint check supplies freshness. Populated-UTXO validation alone cannot prove
  an external input remains unspent; the replay ledger rejects reused funding.
- The independent Python checker reconstructed all four public traces and exact
  balances. Its amount/root/funding-replay negative controls failed. It does not
  implement Groth16 or replace native/accepted-chain verification.
- A supplementary constructed 65,535-commitment state accepted the last fitting
  admission, rejected an additional admission in builder/native script, and
  accepted an existing genuine saved exit proof. This is a boundary fixture,
  not a replayed 32,000-deposit chain or complete capacity drain.

Main preparation generated 12 genuine proofs; the adversarial control suite
added 9. Earlier validation attempts remain private evidence; the final candidate
is pinned in the exported summary. Initial proof preparation preceded additional
harness controls; the unchanged circuit/covenant and actual saved proofs were
validated by the final candidate. Live runs use that final candidate throughout.

## TN10 result

Both the complete rehearsal and fresh measured trial confirmed 14 transactions
each: one ordinary allocation and 13 in the main sequence. Each run paid all
eight payouts, all exact accepted bodies/full hashes matched, and the
reserve/liability balance reached zero.
The independent Python state/amount check agrees. All eight saved proof/auth
pairs matched their actual transaction bytes; recorded prover-stop times precede
every exit submission. Alice's count-three proofs settled after count reached
nine and all other wallets had withdrawn.

Measured local settlement took **25.848–46.605 ms** per exit, including public
replay/native checks but excluding RPC discovery and confirmation. Cold parameter
loading took 100.716–100.865 seconds per wallet; individual proof work took
9.324–9.721 seconds. Peak prover RSS was 3,439,300 KiB. The full serial measured
run took 560.081 seconds; rehearsal took 577.973 seconds. These are CPU/local-host
measurements, not GPU or general wallet-performance claims. Exit clients had no
proving parameters. [Aggregate receipts](evidence/2026-10-20-deposits/summary.json),
[measured proof comparisons](evidence/2026-10-20-deposits/trial/saved-proof-equality.json).

The node reported `testnet-10`, synchronized, with software version `2.0.0`.
That advertised version is not a server-binary commit attestation. The local
native validation code and SDK keep their recorded source pins; actual TN10
acceptance is separate evidence.

## Fees and layout

All arithmetic uses integer sompi; 100,000,000 sompi = 1 tKAS. The configured rate
is 100 sompi per mass unit. Fixed exit fees cover continuing and terminal shapes.

| Operation | Sompi | tKAS |
| --- | ---: | ---: |
| Bootstrap / private transfer | 21,893,200 | 0.218932 |
| Later deposit | 22,005,200 | 0.220052 |
| Full exit, per note | 21,934,400 | 0.219344 |
| One bootstrap + three deposits + eight exits | 263,384,000 | 2.633840 |

Those pool fees leave **3,736,616,000 sompi (37.36616 tKAS)** in eight payouts from
40 tKAS. Ordinary genesis/input-allocation fees are additional:

| Run | Pool | Genesis | Ordinary allocation | Total tKAS |
| --- | ---: | ---: | ---: | ---: |
| Rehearsal | 2.633840 | 0.010193 | 0.004026 | 2.648059 |
| Measured | 2.633840 | 0.010193 | 0.012900 | **2.656933** |

Allocation fees differ because storage mass depends on its input/change amounts.
Including both live runs and the 82 ordinary consolidations, this task confirmed
110 transactions and spent **5.530164 tKAS** in fees. No reserve remains in either
pool. Payout totals exclude unused ordinary funding change.

The 60,000,000-sompi note floor exceeds the fixed exit fee plus the
10,000,000-sompi payout floor. Minimum admission is 142,005,200 sompi, producing
two floor notes; each floor note exits for 38,065,600 sompi.

The proof is 128 bytes, authorization 265, VK 328, compact state 105 and payload
3,892. The immutable redeem script is 14,336 bytes; its input witness is 14,469.
Reserve compute budget is 2,000 units of 10,000 execution units. Ordinary funding
uses a canonical Schnorr SIGHASH_ALL signature. That signature excludes scriptSig
bytes and compute budgets; native execution/policy checks remain necessary.

Old ordinary test payouts were fragmented. Preparing both live runs required
82 two-input ordinary consolidations, costing 22,517,200 sompi (0.225172 tKAS).
Every consolidation was built/validated offline, then confirmed on TN10. An
initial offline-only plan exposed an old payout-key lookup bug: the proof's
address index can precede its settlement index by more than one. The helper now
searches earlier indices and still requires an exact public-script/key match.
No failed-plan transaction was broadcast and no pool reserve was consolidated.

## Evidence layout

[Evidence](evidence/2026-10-20-deposits) separates offline, ordinary funding,
rehearsal and measured trial. Each live folder contains exact accepted transaction
bodies/full hashes, the pinned public descriptor/VK, native fee/mass reports,
client mount inventories, proof/prover timings and confirmation receipts. The
independent checker can run directly against each exported `public` folder.
The exporter refuses to replace another trial identity at an existing evidence
path; set `KPI_DEPOSIT_EVIDENCE` for a different run. Only successful main-path
proofs appear in public transaction traces; unused old/fresh control alternatives, notes, keys and proving material remain private.
The exported aggregate labels are research ground truth, not a chain observer's
inputs. Mount paths are sanitized; transaction bytes are not rewritten.

The main runtime sources and binary are pinned by the offline gate and checked
again before live execution. Supplementary source hashes cover the independent
checker, capacity example, ordinary funding helper, tests, transport and exporter.
The source pin describes a local build; it is not a reproducible-build attestation
or an independent audit. Node-reported software version is recorded separately.

## Reproduce

Requires the pinned Rust/SDK dependencies, Node, bubblewrap and the existing
private parameter directory. Raw identities, keys, notes, proof bundles and
unused alternatives must live outside Git. Set `KPI_DEPOSIT_BINARY`,
`KPI_SDK_PATH`, `KPI_FUNDING_DIR` and `KPI_TN10_RPC` when using different local
paths or a different TN10 node. Run from the repository root:

```sh
CARGO_TARGET_DIR=/home/luke/projects/kaspa-privacy-self-funded/poc/self-funded/target cargo +1.95.0 build --release --manifest-path poc/shared-pool/Cargo.toml --bin kpi-deposits
node poc/shared-pool/deposits.mjs new /PRIVATE/params /PRIVATE/trials
node poc/shared-pool/deposits.mjs offline /PRIVATE/params /PRIVATE/trials
python3 poc/shared-pool/check-deposit-state.py /PRIVATE/trials/OFFLINE/evaluation-ID/order-3210/public
```

`new` only creates a fresh unfunded identity; `offline` makes its own fresh
identity. `evaluate ROOT PARAMS` repeats controls/public settlements against an
already prepared private fixture without replacing its original proofs.
The capacity example takes that prepared private root and uses no PK:

```sh
cargo +1.95.0 run --release --manifest-path poc/shared-pool/Cargo.toml --example deposit-capacity -- /PRIVATE/trials/OFFLINE
```

Only after the complete offline gate, with test coins available:

```sh
node poc/shared-pool/deposits-live.mjs rehearsal /PRIVATE/params /PRIVATE/live /PRIVATE/OFFLINE-EVALUATION
node poc/shared-pool/deposits-live.mjs trial /PRIVATE/params /PRIVATE/live /PRIVATE/OFFLINE-EVALUATION /PRIVATE/REHEARSAL
```

Each invocation creates a fresh identity. Submission records are write-once;
never retry a used trial identity. Preserve failures and recover any funded
claims through ordinary exits before starting another trial. Exact body/full-hash
acceptance and ordinary output accounting supplement mempool replies.

## Limits and decision

Independent means separately controlled funding/signing keys and autonomous
settlement from saved proofs. The live test coins share a visible funding
ancestor; this is not four unrelated people or an anonymity result. Deposits,
pair totals, exits, old anchors and timing are public. RPC/network observation
is separate from a chain-only observer. Publishing research labels is not part
of the observer model for any later study.

Single-party setup, unaudited cryptography, retained authenticated history and a
correct node view remain assumptions. Saved fees cannot reprice themselves.
The reserve serializes updates; this test does not cover a live deposit race,
continuous contention, reorgs, pruning or loss of every public-data copy. A
malicious depositor can create undeliverable own notes; correct ciphertexts are
a wallet check, not a proved encryption relation. No cryptographic safety or
production-readiness claim follows from passing these tests.

Retain this bounded admission/exit candidate and return to preregistering
Stage 2's population comparison. Two-note admission adds two exits per depositor; measure
whether that cost is justified before extending wallet features or selecting a
production architecture.
