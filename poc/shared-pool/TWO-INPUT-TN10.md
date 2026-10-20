# Two-input payments and saved-proof exits on TN10

**The complete TN10 rehearsal and fresh measured trial both passed.**
This follow-up uses the same bounded H13 workload as the
[offline result](TWO-INPUT.md), with the unchanged v6 circuit, covenant and
verification key. Stage 2's practical privacy question remains open.

Date: 2026-10-20 UTC. Branch: `shared-pool-four-wallet`. No mainnet funds,
consensus changes, push or upstream posting. Code baseline: `bf64f3d` plus the
transport adapter committed with this report.

## Observed results

In each run, all 15 transactions were accepted, including six saved exits from four isolated
clients and the terminal payout. The final recorder matched every full body and
hash to accepted chain data. Each saved proof and authorization was byte-for-byte
unchanged. All pool liabilities were paid and both reserves reached zero. The
following payouts were the same in both runs.

| Wallet | Saved-exit payouts, tKAS | Partial payout, tKAS | Total, tKAS |
| --- | ---: | ---: | ---: |
| Alice | 11.49 | 0 | 11.49 |
| Bob | 12.50 | 2.11 | 14.61 |
| Carol | 12.50 | 0 | 12.50 |
| Dave | 12.20 | 0 | 12.20 |

| Cost | Rehearsal, sompi | Measured trial, sompi |
| --- | ---: | ---: |
| 13 pool operations | 520,000,000 | 520,000,000 |
| Ordinary allocation | 521,900 | 607,900 |
| Reserve genesis | 1,012,600 | 1,012,600 |
| Total per run | 521,534,500 | 521,620,500 |

The measured workload cost **5.216205 tKAS**. The differing ordinary allocation
fee reflects its native storage mass and change amount. Ten/eight ordinary
consolidation transactions cost another 2,746,000/2,196,800 sompi. Total fees
for both runs and funding reuse were **1,048,097,800 sompi (10.480978 tKAS)**.
The runner found every expected final
ordinary output unspent at reconciliation; some were then recycled into the
next trial using their owners' ordinary keys.

Preparation took 513.77/512.61 seconds, including 204.154/201.797-second cold
parameter loads and fifteen warm proofs per run. Warm proofs took
20.036–21.430 seconds. Peak RSS was 6,653,888/6,750,992 KiB (about 6.35/6.44 GiB).
In the rehearsal, isolated native history replay plus saved-exit construction
and validation took 0.04–0.06 seconds per exit, excluding RPC discovery and broadcast.
The complete proving workload and its native controls ran before any pool was
funded. The native unfunded-identity command took 12/14 milliseconds; including
source hashing and recording, the CLI reported 32/36 milliseconds.

Pool mining mass was 330,497–331,628, with 30,137–30,258 estimated bytes and
14,847,316–15,029,211 measured script units. The reserve declares 30,000,000
units. Each chosen 40,000,000-sompi fee was actually accepted by this TN10 node.
The budget is deliberately unoptimized; this is not a future fee quote.

## Evidence and identity

- [Rehearsal result](evidence/2026-10-20-two-input-tn10/rehearsal/result.json)
  and [measured result](evidence/2026-10-20-two-input-tn10/trial/result.json)
  record payouts, exact fees, zero reserve, source hashes and each client's
  native validation and public discovery receipts.
- [Accepted rehearsal bodies](evidence/2026-10-20-two-input-tn10/rehearsal/chain-confirmed.json)
  and [accepted measured bodies](evidence/2026-10-20-two-input-tn10/trial/chain-confirmed.json)
  contain the 15 full transactions and their full hashes per run. The
  [proof comparisons](evidence/2026-10-20-two-input-tn10/trial/proof-reuse.json)
  match saved versus accepted proof/authorization hashes; the exporter also
  checked the underlying bytes.
- [Namespace evidence](evidence/2026-10-20-two-input-tn10/trial/isolation.json),
  [prover-stop ordering](evidence/2026-10-20-two-input-tn10/trial/prover-stopped.json),
  [measurements](evidence/2026-10-20-two-input-tn10/trial/measurements.json) and
  [preflight resources](evidence/2026-10-20-two-input-tn10/trial/preflight.json)
  delimit independence and cost. All observations use the owner's synced
  `testnet-10` node reporting version `2.0.0`.
- [Corrected offline gate](evidence/2026-10-20-two-input-tn10/offline/summary.json)
  and [fixture correction](evidence/2026-10-20-two-input-tn10/offline/qualification-correction.json)
  preserve the intended negative-check results and the initial invalid ones.
- [Public replay](evidence/2026-10-20-two-input-tn10/public-replay-check.json)
  independently reconstructed both lineages from the exported bodies and VK in
  filesystem/network-isolated processes. All 14 pool-lineage transactions per
  run passed native replay; all 15 full hashes matched. No private run files
  were mounted. This checks the export's contents, not an independent proof of
  chain finality or a second validator implementation.

The unchanged VK SHA-256 is
`9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef`.
The executed adapter SHA-256 is
`13dd7faf0ee72e2e6c4e8490c1bb1f92bd9b32919ab8caacedad342b52c3fb23`.
Native validation remains pinned to Rusty Kaspa
[`01b532e8b553523216471682649693af92f0fd16`](https://github.com/kaspanet/rusty-kaspa/tree/01b532e8b553523216471682649693af92f0fd16).
The circuit and covenant source files are byte-identical to `bf64f3d`.
Use the evidence source hashes for the other exact files. The setup remains
single-party experimental material, with no independent cryptographic audit.

## Qualification correction

The first adapter-negative fixtures reserialized the descriptor. That changed
its pinned byte hash, making every negative fail at descriptor identity rather
than its intended check. This invalid negative result is retained privately and
excluded from the success claim. The corrected fixtures preserve the descriptor
bytes unless substitution is the test, and assert each expected rejection cause.
All six corrected controls passed before any pool was funded. An ordinary
ten-transaction coin consolidation had already completed; it did not create or
spend a reserve.

The six controls cover missing history, a removed middle transaction, descriptor
substitution, altered transaction value/ID, damaged saved proof, and a new exit
request after complete drain. The last is a drained-pool refusal; current-NF
double-spend and both normal/fallback winner orders are separately exercised by
the unchanged genuine-proof preflight. Its 279 reserve-script mutations run on
each newly prepared workload. These checks do not close the larger RFC's
qualification checklist.

Release builds and the five existing two-input unit tests passed. New JavaScript
files pass syntax checks; the Python exporter compiles. Staged artifacts parse
and pass a scan against the generated spending/viewing/native keys, initial
note secrets and funding key. These packaging checks supplement the genuine
proofs, native controls and funded runs; they are not an independent audit.

## Scope and method

The owner authorized TN10 execution on `shared-pool-four-wallet`. Qualify the
new transport adapter offline, complete the entire funded path in a fresh
rehearsal, then repeat with another fresh identity. Each run generates four
wallets and a pool domain. The existing single-party experimental setup is
reused; no old deployed pool or proof is migrated.

The proof generator finishes before the first live broadcast. It prepares the
same genuine private authorizations as the offline fixture. The live path adds
ordinary funding allocation and reserve genesis to the 13 pool operations:

1. Alice deposits 20 tKAS and splits into 9 and 10.6. Bob, Carol and Dave add
   11, 12 and 13 respectively, each crediting its value less a 0.4 fee. Bob
   saves his original note's exit before the later admissions.
2. Alice combines 9 and 10.6, pays Bob 7.31 and keeps 11.89 private change.
   Both wallets decrypt their outputs; Alice saves her change's exit.
3. Bob withdraws 2.11 publicly, retaining 4.8 private change. He decrypts and
   spends that change to pay Carol 1.7 and keep 2.7.
4. Four isolated clients settle six saved exits, ordered Bob, Carol, Dave,
   then Alice. This differs from the preparation fixture's exit order. Each
   client rebuilds current public witnesses while preserving the exact private
   proof and authorization, including Alice's terminal exit.

The expected pool accounting is integer sompi throughout:
`5,600,000,000 = 5,080,000,000 payouts + 520,000,000 fees + 0 reserve`.
Ordinary allocation, genesis and recycled-funding fees are accounted separately.

## What an independent exit receives

Each client has only its own saved capabilities, the pinned descriptor and VK,
software and system libraries. Its filesystem/PID namespace excludes the host
home, wallet keys, proving parameters and every other wallet's capabilities.
Network access is enabled for the public RPC. The original proving process has
already exited; it cannot supply a new proof or current state.

For each claim, the client downloads accepted transactions from its saved chain
anchor, checks the actual funding parents, follows the reserve outpoint lineage,
and natively validates/reconstructs every transition. It checks the live reserve
UTXO, constructs its transaction, submits it once, and observes its payout UTXO.
Only its own saved exit bytes and public history are used. A final read-only
recorder compares all 15 accepted transaction bodies and full hashes, replays
the pool, and reconciles ordinary input/output values and all fees.

This is **four isolated clients on one host using one correct RPC node**. The
controller created the fixture and launches the clients sequentially. The
public descriptor pins the four known funding sources; this adapter is not a
general wallet for arbitrary future depositors. The result does not establish
cross-host recovery, malicious-node resistance, pruning tolerance, reorg
recovery, or liveness under competing reserve spends. It tests independent
saved-capability settlement within those explicit assumptions.

## Privacy boundary

Recipients locally decrypt private payment/change notes. Their openings and
spend keys are absent from the transaction. Public deposits, withdrawal amounts
and scripts, fees, anchors, timing, nullifiers and ciphertexts remain visible.
All four test deposits share ordinary funding ancestry. The fixture is small
and deliberately publishes ground truth for verification.

Successful private change is a payment-mechanics result. It neither measures
anonymity nor removes the inference risks in the
[observer review](TWO-INPUT-PRIVACY-REVIEW.md). RPC sees these clients' requests
and submissions; this experiment adds no network-privacy protection. Unused
alternative fallbacks must remain private. Once a fallback is used its old
anchor and public payout can constrain the possible source and amount.

## Adversarial second pass

- **Backing and unauthorized payout:** retain the existing circuit's integer
  conservation/range checks and covenant's actual funding/payout binding. Replay
  compares the whole canonical body and executes native validation, including
  the depositor signature. No descriptor or operator signature authorizes a
  reserve release.
- **Double spending and stale state:** retain sequential current nullifier
  insertion and the original normal/fallback exclusivity controls. A saved
  proof can authorize a fresh settlement only while its real note is unspent.
  Terminal release follows reserve value, not padded commitment/NF counts.
- **Missing or corrupt data:** missing history, a broken lineage, wrong
  descriptor, altered transaction and damaged saved proof must fail closed.
  The adapter does not repair unavailable history or an ambiguous submission.
  Failed identities are preserved; no broadcast is repeated within one.
- **Dependency failure:** saved settlement needs no wallet secret or PK, but
  still needs the saved capability, public VK/history, compatible software and
  a usable fee. The exact 0.4-tKAS authorization cannot be raised without a new
  proof. There is no privileged rescue or fee subsidy.
- **Trust and disclosure:** single-party setup, unaudited composition, one RPC
  view, shared host and precomputed capabilities remain explicit. Passing
  local controls and TN10 acceptance are not cryptographic correctness or a
  claim of real-world privacy.

## Reproduction

Build from `poc/shared-pool` with Rust 1.95.0:

```sh
cargo +1.95.0 build --release --bin kpi-two-input-live --bin kpi-compact-funding
export KPI_TWO_INPUT_BINARY="$PWD/target/release/kpi-two-input-live"
```

Use private directories outside Git for `PARAMS` (the existing v6 setup), `RUNS`
and funding credentials. Set `KPI_SDK_PATH`, `KPI_TN10_RPC` and `KPI_FUNDING_DIR`
for the matching TN10 environment. A fresh unfunded identity is one command:

```sh
node two-input-run.mjs new "$PARAMS" "$RUNS"
node two-input-run.mjs offline "$PARAMS" "$RUNS"
node two-input-run.mjs rehearsal "$PARAMS" "$RUNS" "$OFFLINE_ROOT"
node two-input-run.mjs trial "$PARAMS" "$RUNS" "$OFFLINE_ROOT" "$REHEARSAL_ROOT"
```

`OFFLINE_ROOT` and `REHEARSAL_ROOT` are the respective successful run paths.
The live runner verifies their program/source identities. Full proof generation
and native controls complete before it funds a reserve. Every submitted
transaction has a write-ahead record. `reconcile ROOT` is read-only and may be
repeated without sending anything. The ordinary funding helper can recycle
owned payout UTXOs; it has no reserve-spending branch.

Export only successful accepted bodies and allowlisted measurements with
`export-two-input.py`. Never copy a raw run directory: it contains private keys,
note data and unused capabilities. The original offline evidence remains
unchanged.
