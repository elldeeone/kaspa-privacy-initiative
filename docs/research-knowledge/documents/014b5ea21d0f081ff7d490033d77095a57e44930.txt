# Direct self-funded native-KAS trial

This bounded TN10 experiment asks whether a private payment and independent
native exits can pay miner fees from their own reserve, using existing L1
introspection and the native Groth16 verifier. No new token, sponsor input,
operator signature, vProgs service or consensus change is used.

Status: the complete funded sequence succeeded on 2026-10-19, using the owner's
unmodified TN10 node reporting v2.0.0. This is unaudited experimental code.

## Funded result

All four transactions were accepted and their outputs observed through the
node's virtual-chain UTXO index. The three reserve outpoints were consumed in
sequence; both participant payouts and the ordinary funding change remained
unspent on a second read. No experimental reserve remains.

| Transaction | Fee (tKAS) | Compute mass | Script units | Native result |
|---|---:|---:|---:|---|
| Funding | 0.002049 | 2,049 | 100,001 | 10-tKAS reserve; 189.997951 change |
| Private payment | 0.163390 | 163,390 | 14,768,307 | 9.836610 reserve |
| Bob exit | 0.163802 | 163,802 | 14,768,359 | 3.836198 payout; 5.836610 reserve |
| Alice final exit | 0.163379 | 163,379 | 14,759,422 | 5.673231 payout; no reserve |

**Total fees: 0.492620 tKAS.** The remaining 199.507380 tKAS is held across the
funding change and the two participant wallets. Payment and exit transactions
each have exactly one reserve input; no outside fee input was used. This is the
cost of this deliberately fixed layout, not an optimized protocol minimum.

The node rejected the valid low-fee proof transaction with exactly 16,338,999
sompi paid against a required 16,339,000. It rejected the alternative payment
after its predecessor was spent as an orphan with orphans disallowed. That is
evidence of native outpoint single-spending; the separate circuit tests cover
spent-note/nullifier reuse. All 36 native mutations were rejected, including
diverted exits, changed values/state/payload, foreign domains, altered verifier
bytes and insufficient script budget. Four Rust tests and six exact SDK
transaction round trips passed.

Bob and Alice each generated their exit in an isolated process using only their
own wallet and public artifacts. Bob's process took 68.97 seconds; Alice's took
66.69 seconds. Actual proof generation took 5.16–5.67 seconds for the three
positive proof spends; most remaining process time was loading and validating
the 286,756,528-byte proving key. The measured payment process peaked at
1,628,548 KiB RSS. Fresh setup took 29.83 seconds and peaked at 1,126,140 KiB.
These are CPU results with four Rayon threads, not GPU benchmarks.

Public receipts, exact transaction JSON, source hashes, parameter checksums,
control errors and resource measurements are in
[evidence/2026-10-19-tn10](evidence/2026-10-19-tn10).
The [final accounting check](evidence/2026-10-19-tn10/live/final-recheck.json)
matches the original 200-tKAS input minus all four fees. This is evidence from
one TN10 node, not independent-node finality or mainnet validation.

The trial answers the bounded feasibility question positively: the consumed
private entitlement can pay its own L1 fee, and the recipient can produce an
authorized exit without another participant's secret or an operator signature.
It does not establish production privacy, security or scalable performance.

## Scope

A 10-tKAS reserve initially backs one Alice note. Alice consumes it, paying
Bob a hidden 4-tKAS note and creating private change. The payment fee reduces
both Alice's entitlement and the native reserve. Bob consumes his whole note
and receives native tKAS minus his exit fee. Alice then consumes the final note,
receives the remaining native tKAS minus her exit fee, and leaves no reserve.

Only one private transfer is supported. Four commitment slots and four nullifier
slots replace a scalable tree. The unspent reserve outpoint serializes state
updates. Nullifiers prevent a previously consumed note from being reused in
later state. Both mechanisms are tested separately.

The circuit checks hidden membership, spending authority, note and native
conservation, preserved commitments/nullifiers, genesis backing and final reserve
exhaustion. It recomputes both SHA256 layers of the native transition binding.
The covenant reconstructs the actual transcript through introspection and
propagates its executed immutable suffix. Native withdrawal amounts/scripts,
reserve lineage, fees, state and ciphertexts are public.

Bob's exit process receives his wallet file, public parameters and public
transaction history. Bubblewrap hides other wallets and the source checkout,
and isolates network and process namespaces. It does not demonstrate recovery
without those public artifacts. It demonstrates no need for Alice's key or a
cooperating remote prover once those artifacts are available.

Design: [ADR-0015](../../docs/adr/0015-direct-self-funded-tn10-trial.md) and
[RFC-0003](../../docs/rfc/0003-direct-self-funded-trial.md).

## Reproduction

Requires Rust 1.95.0, Node, Python, bubblewrap, native build prerequisites for the
pinned Rusty Kaspa crates, and the official Kaspa v2.1.0 Node WASM SDK. The SDK
archive used here has SHA256
`ba674e109ff5dd8bedc4dc2ee8a5ecdf4b600b1178a541d77888ec58310b6124`.
Set `KPI_SDK_PATH`, `KPI_TN10_RPC` and `KPI_FUNDING_DIR` as needed. The funding
directory contains `funding.json` with `network` and `address`, and a protected
`funding.key` file. Never put keys or wallet/note files in evidence or Git.

```sh
RAYON_NUM_THREADS=4 cargo +1.95.0 test --locked --release --manifest-path poc/self-funded/Cargo.toml -j 4 -- --test-threads=1
cargo +1.95.0 build --locked --release --manifest-path poc/self-funded/Cargo.toml -j 4
RAYON_NUM_THREADS=4 poc/self-funded/target/release/kpi-self-funded setup /private/path/parameters
poc/self-funded/target/release/kpi-self-funded init /private/path/parameters /private/path/fresh-trial
```

`init` is the single-command, unfunded identity operation. `prepare` calls it
with a new UUID, prepares the entire sequence, runs both isolated exits, checks
36 native mutations, and round-trips all six transactions through the SDK:

```sh
node poc/self-funded/run.mjs prepare /private/path/parameters /private/path/trials
node poc/self-funded/run.mjs live /private/path/trials/NEW-TRIAL
```

Only `live` broadcasts. It verifies all prepared transaction hashes before
funding, validates each real predecessor UTXO, records each attempted submission
durably, and confirms outputs through the node's virtual-chain UTXO index.
It also submits a consensus-valid payment one sompi below the relay floor before
the real payment, and an alternative valid payment after that outpoint is spent.
The latter tests native outpoint reuse, not the nullifier circuit.

A used trial is never rebroadcast. Start a new identity for another attempt;
retain any old trial's data, keys and receipts. Operational waiting has no short
timeout that could declare an otherwise valid trial a protocol failure.

## Evidence boundaries

The relation has 1,384,153 constraints. Its public inputs are two 128-bit halves
of a SHA256 digest, encoded as canonical BN254 scalars. The compressed proof is
128 bytes, verification key 328 bytes, redeem script 2,048 bytes, and payload
638 bytes. Fresh single-party setup is a test assumption, not a production setup
ceremony. Passing tests and proofs are not a cryptographic audit.

The fixed fee rate is 100 sompi/gram, matching the node quote at preparation.
Actual fees, script usage, proof timings and chain receipts must be reported
separately from estimates. Setup and per-process resource logs include parameter
loading; `proving_ms` measures proof generation only.

This two-person synthetic sequence provides no useful anonymity measurement.
Do not generalize its confidentiality mechanics into real-world unlinkability.
RPC and network exposure are separate from chain-visible information. Production
data availability, malicious setup, scalable state, contention, fee repricing,
multiple deposits and long-term recovery remain open.

## Pinned native sources

- [Rusty Kaspa v2.1.0](https://github.com/kaspanet/rusty-kaspa/tree/01b532e8b553523216471682649693af92f0fd16): consensus, transaction mass, script engine and verifier used by this executable.
- [Rusty Kaspa v2.0.0](https://github.com/kaspanet/rusty-kaspa/tree/90dbf074275d60c1fe74a3491883196f110970c0): source comparison for the reported live-node version. The node's executable hash is not established.
- [vProgs covenant suffix propagation](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/covenant/src/script.rs): adapted without the vProgs runtime.

The source/lockfile hashes, exact transaction JSON, full hashes, metrics,
validation errors and public parameter checksums belong with trial receipts.
Retain the large public proving parameter file outside Git and publish it only
through a separately authorized artifact-sharing step.
