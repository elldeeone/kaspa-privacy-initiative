# Compact-state reusable exits

Passed, 2026-10-19: the offline 100-payment gate, complete two-payment TN10
rehearsal and fresh 100-payment TN10 trial. Bob reused exactly the same proof
after 100 payments, with both original provers stopped. Every claim exited.
See [ADR-0019](../../docs/adr/0019-compact-public-settlement.md) and
[RFC-0007](../../docs/rfc/0007-compact-state.md). Preserve ANCHORED.md and all
preceding experiments. This separate relation uses test KAS only.

## Question and workload

Can Bob prepare one private exit authorization, go offline through 100 unrelated
payments, and settle it using public chain data and exactly the same proof?

The initial 100-tKAS claim belongs to Alice. Bootstrap creates Bob's 4-tKAS claim
and Alice's change. Bob proves a full exit. Alice then makes 100 two-output
payments of 60,000,000 sompi each to Carol, spending her largest change note each
time. Both original provers stop before Bob's public-only process discovers the
100 accepted updates and broadcasts his exit. Carol and Alice then independently
prove their own exits and drain the pool. Bob's prover never restarts. A short
10-tKAS rehearsal uses two intervening payments and the same protocol/binary.

Offline proof generation initially shares a process; a separate sandbox rebuild
then receives only public artifacts and no wallet or proving key. Live proving
uses separate network-isolated wallet processes, and the public rebuilder obtains
new transactions from the node by reserve ancestry, not an operator's list of
transaction IDs. Its retained pre-payment bootstrap metadata is explicit input.

This is a serial synthetic workload with three wallets, not a concurrency or
real-world anonymity measurement. It has no later deposits or partial withdrawals.

## Encoding and native checks

All amounts are integer sompi. Depth is 16 (65,536 leaves). The largest reachable
commitment count is 65,535, permitting 32,767 two-output transfers from genesis;
the final nullifier insertion uses index 65,535 because index zero is a sentinel.
Exits remain possible at capacity. This is finite capacity, not unlimited state.

The 105-byte state is version 4, two little-endian u32 counts, and three 32-byte
roots: commitments, current nullifiers, and accepted historical note roots.
Counts describe economic notes/spends; the nullifier sentinel is additional.
Commitments append in pairs. Historical root index is `(commitment_count-1)/2`.

The 265-byte authorization retains the preceding layout with a four-byte count:

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 8 | `KPICU01\0` |
| 8 | 32 | Pool domain |
| 40 | 4 | Historical commitment count, little endian |
| 44 | 32 | Historical commitment root |
| 76 | 32 | Positioned economic nullifier |
| 108 | 64 | Two output commitments, zero on full exit |
| 172 | 1 | Transfer (1) or full exit (2) |
| 173 | 8 | Native payout |
| 181 | 8 | Exact miner fee |
| 189 | 36 | P2PK payout script/version, zero on transfer |
| 225 | 8 | Initial backing, zero after bootstrap |
| 233 | 32 | Ciphertext digest |

Its SHA256 halves are the two Groth16 public inputs. Private constraints enforce
owner knowledge, indexed membership under the fixed old root, private index less
than the anchor count, positioned HMAC nullifier, value/range conservation and
authorized outputs/recipient/fee. A private proof does not contain the current
reserve outpoint or current spentness root. SHA256/HMAC, BN254 Groth16 and sealed
box notes are established primitives; this application relation is unreviewed.

Merkle inner nodes are `SHA256(0x01 || left || right)`; note leaves use
`SHA256(0x00 || commitment)`, nullifier leaves use
`SHA256(0x02 || value32 || next_index_u32 || next_value32)`, and history leaves use
`SHA256(0x03 || count_u32 || commitment_root)`. Empty leaves are 32 zero bytes.
Public indices/directions are checked against depth/counts. All 256 nullifier bits
participate in unsigned little-endian ordering; seven-byte native numeric limbs
avoid signed 64-bit interpretation. Nullifiers include the private note index
under `KPI-positioned-nullifier-v1\0`, keeping repeated commitments at distinct
funded positions independently spendable.

Payload: magic `KPICR01\0`, authorization, 370 ciphertext bytes, successor state,
then 3,144 witness bytes (3,892 bytes total). Witness order:
historical-root membership path; predecessor index/preimage/path; fresh
nullifier append path after predecessor update; two sequential empty note append
paths; empty history append path. Each path has 16 sibling hashes. Exit-only
unused append paths/ciphertexts must be zero. Current nullifier insertion must
authenticate a strict predecessor gap, preserve its previous successor, update
the predecessor, and insert at the exact next empty index.

The 12,288-byte P2SH covenant propagates its exact immutable suffix/VK/domain,
checks all roots and exact counts, bootstrap sentinel/history/backing, native
recipient/value/fee and terminal shape. Signature script is 12,421 bytes; the
private proof remains 128 bytes. Execution budget is 2,000 (20 million script
units). There is no operator signature or second proof.

## Results and evidence boundaries

The full offline run completed 204 native transactions and 203 genuine private
proofs, including bootstrap, 100 payments, Bob's unchanged-proof exit and the
remaining 101 exits. Every claim drained. All 204 transactions passed the pinned
native Full validator, default relay-policy checks and exact SDK round trips.
Separate public-only sandbox reconstruction took 347.882 ms, including process
startup and native validation; it received no wallet or proving key.

The two-payment TN10 rehearsal confirmed all eight transactions, matched their
accepted bodies/full hashes, confirmed Bob's unchanged-proof payout after both
original provers stopped, and drained the pool. Bob's local rebuild took
27.439 ms, excluding RPC discovery and confirmation. Its total fees were
152,188,500 sompi (1.521885 tKAS), including ordinary funding.

The measured 100-payment TN10 trial confirmed all 204 transactions and matched
their accepted bodies/full hashes. Its 203 private proofs include bootstrap,
100 payments and 102 full exits. Bob's authorization and 128-byte proof were
identical before and after the payments; no settlement proof was added. His
public-only process found all updates by reserve ancestry and received the
3.782704-tKAS payout. The original provers had exited before its submission,
and its namespace had no wallet, proving key or host home access.

| Measured result | TN10 rehearsal | TN10 100-payment trial |
| --- | ---: | ---: |
| Payments after Bob authorized | 2 | 100 |
| Confirmed native transactions | 8 | 204 |
| Genuine private proofs | 7 | 203 |
| New proofs for Bob's settlement | 0 | 0 |
| Local public rebuild, ms | 27.439 | 352.426 |
| Separate RPC history discovery, ms | 1,179.474 | 11,356.203 |
| Bob's initial private proof, ms | 9,681 | 9,759 |
| Bob's payout, sompi | 378,270,400 | 378,270,400 |
| Total fees including funding, sompi | 152,188,500 | 4,407,152,500 |
| Remaining private claims / reserve | 0 / 0 | 0 / 0 |

The measured trial spent 44.071525 tKAS in fees: 44.069476 from private claims
and 0.002049 for ordinary funding. Rehearsal cost 1.521885 tKAS. Twelve ordinary
consolidations reusing existing test coins cost another 0.032952 tKAS. Combined
cost: **45.626362 tKAS**, across 224 confirmed native transactions. No real funds.
The 100-tKAS pool reconciles to 55.930524 tKAS in user payouts plus 44.069476 tKAS
in pool fees. No reserve or private claim remains.

First funding submission to observed terminal payout took 42 minutes 2 seconds,
including live proof generation and the cleanup provers' cold starts. Bob's
submission-to-payout observation was 1.053 seconds with polling; this is not a
precise consensus-latency or finality measurement. The 352-ms rebuild excludes
RPC discovery and confirmation.

[Evidence index](evidence/2026-10-19-compact/README.md),
[trial summary](evidence/2026-10-19-compact/trial-summary.json),
[independent public-state reconstruction](evidence/2026-10-19-compact/trial-state.json),
[complete cost accounting](evidence/2026-10-19-compact/cost.json).

Five Rust test groups cover framing/capacity, tree and indexed-set consistency,
positioned membership/authorization, unsigned native comparisons and economic
boundaries. The unsigned comparison group checks 1,764 pairs. The native hostile
controls rejected 113 mutations, plus four output mutations that retained a
valid private proof. These include a second withdrawal with Bob's genuine proof
and freshly constructed duplicate-insertion paths, changed successor VK/domain/
rules and redirected payout. Independent Python reconstruction matched every
public tree transition, native amount and successor script; it is not a second
Groth16 or consensus verifier.

A separate synthetic current-state fixture confirms a terminal exit at 65,535
commitments using Bob's genuine old proof. Its preceding history was not executed
and is not counted as workload evidence.

At offline and TN10 payments 1, 10 and 100, each transfer measures 16,514 estimated bytes,
216,884 compute mass and 21,688,400 sompi fee. Bob's exit measures 16,566 bytes,
217,296 compute mass and 21,729,600 sompi fee. Fees use 100 sompi per mass unit.
Both live runs accepted these fee amounts on TN10. Note floor is 60,000,000
sompi; payout floor is 10,000,000. Fixed exit fee/payout work for both continuing
and terminal shapes. Fee repricing requires new authorization.

The compact state is 105 bytes versus the prior anchored variant's 1,539 bytes.
The complete transaction is larger because it carries paths and native checks;
the continuing exit fee is about 2.75% higher than the prior 21,148,700 sompi.
This is a capacity experiment, not evidence of lower total chain storage or fees.

The application relation has 2,169,419 constraints. Its single-party setup took
21,631 ms and produced a 478,600,432-byte proving key. Rehearsal authorization
proofs took about 9.6–10.1 seconds on CPU. The measured trial's 203 proofs took
9.428–9.919 seconds each (median 9.631 seconds), totaling 1,956.452 seconds.
Its four cold parameter loads took 101.372–102.316 seconds each.
These are observations on the local Ryzen 7 5800X environment with four Rayon
threads, not a controlled hardware benchmark.
This is a different application relation from upstream's Orchard/RISC Zero
outer proofs; its timings are not a comparison with the earlier P11 benchmark.

All 17 recorded candidate source hashes and the binary remained unchanged
between rehearsal and trial. The binary SHA256 is
`a60c98e1cfcaaf72aef9988c426d10776c4ae4801abd8411acd49f930c4d132c`;
the VK SHA256 is
`79ed99da1d7b586887edf13e1d7404f5692479b0cb759ab8701a039eb340d1b4`.
Node RPC reported version 2.0.0, synchronized Testnet-10 with a UTXO index.
Its binary hash was not established. Exact node receipts and source hashes are
in the live exports.

Single-party experimental setup, serial reserve contention, public data retention,
pre-payment bootstrap metadata, a correct full-node view and stable accepted
history remain assumptions. The setup file is about 479 MB and initial private
proving remains substantial. No arbitrary-reorg recovery or independent audit
claim. Transactions expose fees, exits, nullifiers, anchors, timing and lineage.
An old anchor limits Bob's candidates to the old count, even after 100 payments;
the additional payments do not retroactively enlarge his anonymity set. RPC
metadata is a separate observer surface. No real-user anonymity estimate.
Specifically, Bob's authorization still names the three-commitment root while
current state has 203 commitments. Three historical entries do not imply three
plausible notes or people: identified earlier spends and amount information can
reduce the possibilities further. Choosing a newer anchor would require a new
private proof in this design.

The subsequent [Stage 2 audit](PRIVACY.md) constructs that source-link certificate
from public fields: both surviving note positions belong to the first transfer.
It retains reusable exits but selects a fresh-authorization policy comparison
before further wallet expansion. No private relation changed in that audit.

## Reproduction

Use Rust 1.95.0 and the existing locked native/SDK pin
`01b532e8b553523216471682649693af92f0fd16`. Keep all runtime paths outside Git.
Configure `KPI_BINARY`, `KPI_SDK_PATH`, `KPI_TN10_RPC` and `KPI_FUNDING_DIR` as in
the previous experiment. Ordinary funding reuse has its own native-validated
builder; it never spends a privacy reserve.

```sh
cargo +1.95.0 build --release --locked --manifest-path poc/shared-pool/Cargo.toml --bin kpi-compact --bin kpi-compact-funding
cargo +1.95.0 test --release --locked --manifest-path poc/shared-pool/Cargo.toml --lib compact -- --test-threads=1
kpi-compact setup /private/parameters
kpi-compact init /private/parameters /private/unfunded-identity
kpi-compact offline /private/parameters /private/offline
node poc/shared-pool/compact.mjs sdk /private/offline
node poc/shared-pool/compact.mjs smoke /private/offline
node poc/shared-pool/compact.mjs live /private/parameters /private/trials rehearsal /private/offline
node poc/shared-pool/compact.mjs live /private/parameters /private/trials trial /private/offline /private/COMPLETE_REHEARSAL
```

Only after the full offline gate: use a fresh identity and once-only submissions.
Require complete rehearsal terminal payout before the measured trial. Export
only the explicit allowlist with `export-compact.py`; independently check public
evidence with `summarize-compact.py`. Neither script is a second consensus engine.
