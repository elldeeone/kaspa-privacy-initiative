# Reusable private authorization on current Kaspa L1

H5 tests whether Bob can keep the same private withdrawal proof after Alice
makes an unrelated private payment. This separate experimental relation leaves
the earlier version-3 code and evidence intact. It uses native test KAS, one
P2SH reserve and the existing native Groth16 verifier, without an operator key,
second settlement proof, new token, vProgs service or consensus change.

Design: [ADR-0018](../../docs/adr/0018-reusable-private-authorization.md),
[RFC-0006](../../docs/rfc/0006-reusable-private-authorization.md),
[source review](../../research/reusable-authorization-source-review-2026-10-19.md),
[adversarial self-review](ANCHORED-REVIEW.md),
[research journal](../../docs/RESEARCH-JOURNAL.md).

## Status

**Passed offline and in a complete funded rehearsal plus fresh measured TN10
trial on 2026-10-19.** Bob received his payout after Alice's payment using the
same 128 proof bytes and 262 authorization bytes. His prover had already stopped;
the public-only rebuilder had no wallet or proving key. Both pools fully drained.
No real-world anonymity or production-security claim follows from this result.

| Measurement | Rehearsal | Fresh measured trial |
| --- | ---: | ---: |
| Confirmed native transactions | 6 | 6 |
| Additional proofs to refresh Bob's exit | 0 | 0 |
| Bob's original authorization proving time | 5.358 s | 5.405 s |
| Complete local rebuild process, including validation | 20.650 ms | 20.783 ms |
| Inner rebuild, including historical native validation | 5.843 ms | 5.915 ms |
| RPC discovery and validation, separately | 59.305 ms | 55.412 ms |
| Submit to observed Bob payout UTXO | 1.053 s | 1.056 s |
| Bob's original-claim payout | 3.788513 tKAS | 3.788513 tKAS |
| Bob exit fee | 0.211487 tKAS | 0.211487 tKAS |
| All accepted fees, including funding | 1.058660 tKAS | 1.061836 tKAS |
| Remaining private claims / reserve UTXOs | 0 / 0 | 0 / 0 |

Combined live cost: **2.120496 tKAS**. There were no rejected or repeated live
submissions and no interrupted funded identities in this experiment. The ordinary
funding fee was 0.002049 tKAS in rehearsal and 0.005225 tKAS in the measured trial:
the smaller native change output increased storage mass. Private transfer/exit
fees were unchanged. All amounts reconcile to the funding inputs and final
ordinary UTXOs; both wallets independently rescanned to zero private claims.

Bob's authorization used commitment count 3; Alice advanced the accepted state
to 5 commitments and 2 nullifiers. The rebuilder discovered Alice's transaction
through `getVirtualChainFromBlockV2 Full`, selected by the spent reserve outpoint.
It retained Alice's complete state and added Bob's nullifier. Later attempts to
reuse Bob's authorization after that nullifier was consumed rejected offline.

Offline verification included four Rust test groups (ownership/membership,
integer/floor boundaries, framing/capacity and immutable-suffix/fee checks), five
public-chain transport tests, 80 hostile native mutations, the synthetic
capacity/terminal fixture, six exact SDK round trips and actual sandbox checks.
The native consensus validator and separate mass/relay checks passed; both live
runs also fetched all six accepted bodies and matched their IDs/full hashes.

Evidence: [offline](evidence/2026-10-19-anchored/offline/offline-result.json),
[rehearsal](evidence/2026-10-19-anchored/rehearsal/result.json),
[measured result](evidence/2026-10-19-anchored/trial/result.json),
[accepted chain bodies](evidence/2026-10-19-anchored/trial/chain-confirmed.json),
[Bob's public-only receipt](evidence/2026-10-19-anchored/trial/rebuilder/result.json).
The measured Bob transaction is
`51774e9ffd22e48d726c10ff45bb001cc2a014370299868eb283d81ead1e428e`.
The measured original/submitted proof SHA-256 is
`36617ab6067a9403b54a1cd70ae217ba910ea994327c587e87b7fe6b573897a9`.
The tested binary SHA-256 is
`04ed4ddf94fb11d660e3b49930f63ea40567e027f03bb758637a0265522a5bbc`;
source hashes are in each result. Node-reported version was 2.0.0; no node change
was made. The running node executable's hash is not established.

**Decision:** retain authorization/current-settlement separation for further
direct-L1 research. It removed private reproving for this unrelated update
without moving that work to a second prover. It did not prove fairness under
ongoing contention or scalable privacy. The larger covenant raises the continuing
exit fee from the version-3 0.167130 to 0.211487 tKAS, about 26.5% at the same
assumed rate; this is a material tradeoff. These are different layouts, not a
controlled end-to-end performance benchmark.

## Exact authorization and settlement

The private proof authenticates SHA-256 of this 262-byte statement. Its digest
is split into two 128-bit little-endian limbs, padded to the native verifier's
32-byte field encoding. The compressed BN254 proof is 128 bytes, VK 328 bytes.

| Offset | Bytes | Field |
| --- | ---: | --- |
| 0 | 8 | `KPIAU01\0` |
| 8 | 32 | Immutable pool domain |
| 40 | 1 | Historical commitment count |
| 41 | 32 | SHA-256(count + 24 padded commitment slots) |
| 73 | 32 | Economic nullifier |
| 105 | 64 | Two output commitments, or zero padding on full exit |
| 169 | 1 | Mode: 1 transfer, 2 full exit |
| 170 | 8 | Public payout, integer sompi LE64 |
| 178 | 8 | Exact miner fee, integer sompi LE64 |
| 186 | 36 | Payout P2PK SPK, or zero padding on transfer |
| 222 | 8 | Bootstrap backing value; zero after bootstrap |
| 230 | 32 | SHA-256 of the two 185-byte ciphertext slots |

The relation proves secret-key ownership, private membership in the historical
commitment prefix, deterministic nullifier derivation and private conservation.
All real notes are 40,000,000–2,900,000,000,000,000,000 sompi; withdrawals are at
least 10,000,000 sompi. Active output commitments are nonzero and distinct;
inactive values/commitments are zero. Recipient wallets validate delivered
plaintext against commitment, ownership and floors. Encryption correctness is
not a circuit predicate, as in the preceding experimental relation.

The native transaction has one reserve input and either one successor output
(transfer), successor + P2PK payout (continuing exit), or one payout (terminal).
Version 1, native subnetwork, zero lock time/gas, max input sequence and no
covenant metadata are fixed. Its 2,179-byte payload is `KPIAR01\0`, authorization,
370 ciphertext bytes, then the existing canonical 1,539-byte public state codec.
The state codec version remains 3; the distinct envelope, domain and VK identify
this new relation. The witness is a canonical 128-byte proof push followed by
an 8,192-byte redeem-script push: 8,325 bytes in total.

The script authenticates the historical prefix against CURRENT commitments,
checks the nullifier against CURRENT spentness, and constructs the exact next
state from retained old entries plus authorized appends. It binds actual output
scripts/values/fee, verifies exhaustion before omitting the reserve, and copies
its immutable suffix/VK to the successor. It then verifies the unchanged private
authorization. Thus an old authorization can remain valid; an old settlement
that discards Alice's update cannot.

This bounded rule accepts any authenticated nonempty commitment prefix, not
only counts that were once complete accepted pool states. The wallet chooses
the complete accepted count when preparing each authorization. This avoids a
root-history registry, but does not implement Orchard's block-boundary anchor
policy or anchor expiry. A smaller prefix can reduce privacy without granting
authority over another claim or bypassing current nullifiers.

One initial note is backed by 1,000,000,000 sompi. Bootstrap must prove that
exact value before Bob accepts his first claim. This smallest variant supports
two-output transfers and full exits. It does not implement later deposits or
partial exits; those remain in the prior experiment.

## Workload and boundaries

1. Alice bootstraps Bob's 400,000,000-sompi claim and her private change.
2. Bob proves an exit against that state. His prover then stops.
3. Alice privately pays Bob another 100,000,000 sompi from her different note.
4. A separate public-only process discovers Alice's accepted spend by reserve
   outpoint, verifies the body/history, rebuilds Bob's transaction with exactly
   the old authorization/proof, submits it and confirms his native payout.
5. Only after that payout, a restarted Bob prover exits the new separate claim;
   Alice then terminal-exits. Both wallets rescan to zero remaining claims.

The rebuilder is not given Alice's future ID, transaction plan or private files.
It has no wallet/proving key mounted. RPC supplies public chain data and a full
node's acceptance view, not withdrawal authority. Host orchestration schedules
the experiment; it cannot redirect Bob's already-authorized payout. The original
Bob prover's recorded exit precedes Alice's payment and target payout.

Record byte equality separately from transaction identity: changing the reserve
outpoint/current state necessarily changes the native transaction, while the
128 proof bytes and 262 authorization bytes remain equal.

## Costs and limits

At 100 sompi/gram, the calculated/measured offline transfer fee is 21,107,500
sompi, and the fixed full-exit fee is 21,148,700 sompi. The same authorized fee is
kept for a terminal exit, paying 42,300 sompi above its lower relay floor rather
than changing Bob's authorized payout. A complete six-transaction sequence is
105,866,000 sompi (1.058660 tKAS) in the offline funding context. Ordinary funding
may cost more when its change is small; the confirmed live totals above record
that difference rather than treating the estimate as a fixed whole-trial fee.

The relation has 1,384,541 constraints and a 286,895,888-byte proving key. The
first offline run measured roughly 5.5–5.8 seconds per authorization and 63.3
seconds for checked parameter loading; these are local machine observations,
not performance guarantees. The public rebuild needs neither that parameter
loading nor another proof. Count complete process/native-validation time as
well as the inner rebuild; exclude RPC discovery and confirmation explicitly.

This does not remove the serialized reserve, finite state or starvation risk.
Transfers append two commitments; the largest reachable count is 23 in this
variant's 24-slot array. Exits remain possible at capacity. Fixed fees may become
insufficient; fee changes require fresh authorization. Setup is single-party
and experimental. Retained public artifacts, correct full-node data and stable
accepted history are assumed. Reorg recovery and independent cryptographic
review remain open.

Privacy is not measured here. The public anchor count reveals an earlier
membership horizon and may narrow candidates. Public fees, payouts, commitment
counts, reserve ancestry and timing remain observable. These are two synthetic
wallets funded from a common source. RPC/network metadata is not a chain-only
observation, and none of these results estimates real-user anonymity.

## Reproduce

Build with Rust 1.95.0 and the locked dependencies. Native/SDK pin:
`01b532e8b553523216471682649693af92f0fd16`. Configure `KPI_BINARY` to the built
`kpi-anchored` executable, and use the existing `KPI_SDK_PATH`, `KPI_TN10_RPC` and
`KPI_FUNDING_DIR` settings. Keep all private paths outside Git.

```sh
cargo +1.95.0 test --release --locked --manifest-path poc/shared-pool/Cargo.toml --lib anchored -- --test-threads=1
cargo +1.95.0 build --release --locked --manifest-path poc/shared-pool/Cargo.toml --bin kpi-anchored
node --test poc/shared-pool/chain.test.mjs

RAYON_NUM_THREADS=4 "$KPI_BINARY" setup /private/params
# This alone creates a fresh UNFUNDED identity, without loading proving parameters.
"$KPI_BINARY" init /private/params /private/fresh-identity
RAYON_NUM_THREADS=4 "$KPI_BINARY" offline /private/params /private/offline
node poc/shared-pool/anchored.mjs sdk /private/offline
node poc/shared-pool/anchored.mjs smoke /private/offline

# Owner-authorized testnet broadcasts; each run creates a fresh identity.
node poc/shared-pool/anchored.mjs live /private/params /private/trials rehearsal /private/offline
node poc/shared-pool/anchored.mjs live /private/params /private/trials trial /private/offline /private/trials/COMPLETED_REHEARSAL
```

The live runner binds its offline result to the exact binary. Measured trials
require a completed rehearsal with matching code/binary hashes. Broadcasts use
exclusive durable submission records and are never repeated. Unknown or failed
outcomes preserve evidence and require a fresh trial, not a weakened check.
`export-anchored.py` copies only explicitly allowed public evidence.
Run `python3 poc/shared-pool/summarize-anchored.py EXPORTED_RUN` to check exported
proof/auth equality, the commitment-prefix transition, prover-stop ordering and
fee accounting. This consistency script is not an independent consensus verifier.
