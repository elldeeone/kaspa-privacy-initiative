> Imported documentation snapshot. [Canonical status and ownership](../../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# Conditional public-transaction structure option

Date: 2026-10-22 Australia/Sydney. Source/design review only. The active 512-ledger test was not inspected, rescored or modified. No builds, proofs, simulations, broadcasts, source edits, commits or external messages were performed.

## Decision

Retain direct L1 as the baseline. If the completed test establishes additional **public-transcript** signal and subsequent attribution identifies per-payment grouping or timing boundaries as a contributor, the narrow alternative worth screening is **an optional atomic batch of two independent internal SPEND authorizations, with their individual records hidden inside verification and only flat state updates published**. It stays a direct covenant spend, uses native KAS, and retains a separately executable individual exit.

This is a candidate public format, not an implemented or qualified protocol. Do not start with a general runtime, sharding, a new token, mandatory waiting, consensus changes or vProgs. Simply batching unchanged public authorizations is not the proposed privacy mechanism.

Relevance conditions are strict:

- The frozen public C+D-versus-price comparison exceeding the five-point margin makes public structure worth investigating; a smaller established effect may motivate only a correspondingly narrow claim. C+D includes the funding-owner directory, so this does not isolate an on-chain field.
- A pooled-only gain primarily directs work toward participant knowledge. A batch with known co-participants can lose its ambiguity by subtraction; the alternative is not a response to a colluder-only result by default.
- Below-five or unresolved results do not establish privacy, nor justify this implementation. The present experiment cannot qualify its unchanged absolute privacy target because the price prior already exceeds it.
- If the surviving inference needs only visible native payouts, funding ancestry and total reserves, and does not depend on the grouping/timing removed below, **do not build this alternative**. No final outcome of the live test is assumed here. [S1]

## What is actually exposed

In the current v6 source, each native payload contains the full 377-byte authorization: historical count/root, two nullifiers, two commitments, mode, payout, fee, payout script, deposit/funding identity and ciphertext hash. Two 185-byte encrypted receipts accompany it. `settle()` produces a single reserve successor and, when applicable, an ordinary value-bearing payout. The circuit's two public field elements are a digest of that authorization; this does **not** conceal its independently published preimage. [S2]

Thus there are three separate questions:

1. **Encryption:** receipt encryption hides note plaintext under its assumptions; it does not hide the creating transaction, native payout, public authorization or subsequent reserve changes.
2. **Proof amortization:** one outer verification may replace several L1 verifications. It does not automatically reduce total proving, bytes, mass, user fees or delay.
3. **Observable linkage:** deleting the individual authorization records and their associations can remove a public partition of nullifiers/outputs and individual operation boundaries. This is a hypothesis about an actual disclosure, not a claim of improved amount inference. Transparent batching retains that partition.

## Decision matrix

| Dimension | Current direct v6 | Transparent operation packing | Selected screening candidate: flat two-SPEND batch |
|---|---|---|---|
| Native/public shape | One authorization and reserve transition per operation | Several authorizations in one spend; requires a new covenant format | One reserve spend; one verified batch statement; flat four nullifiers and four commitment/ciphertext pairs; one successor |
| Privacy change | Known baseline disclosures | Timing may coarsen, but each operation's fields/group remain recoverable | Individual authorization/anchor/pair grouping and intrabatch order absent from L1; aggregate size, accepted time, current roots and fee remain visible |
| Native amounts | Deposits and payouts explicitly visible | Every ordinary output still has its own amount | Initial screen contains only zero-payout internal spends; admission and exit values remain public and unchanged |
| Supported primitives | Existing Groth16 proof plus native introspection | Same primitives, but current fixed v6 cannot pack records | Existing user-local Groth16 authorizations verified inside an outer supported proof; new immutable covenant/statement required |
| Coordination / liveness | Shared reserve contention | Builder collects operations; stale reserve requires retry | Optional replaceable collector; only settled L1 state is spendable. No promised off-chain balance, queue priority or required batch partner |
| Independent exit | Existing direct no-append exit semantics | Must preserve individual route | New pool must preserve direct single-holder exit before and after a batch; it cannot require the collector or outer prover to exit |
| Data availability | Full accepted public history plus parameters | At least the same public data | All flat leaves, ciphertexts, nullifiers and deterministic append/history rules remain public. Private operation grouping must not be needed to replay or exit |
| Fees / implementation | Measured, unoptimized budget | Multiple verifier charges remain; no assumed saving | Outer proving and large proof encoding may outweigh saved verification. Exact authorized fees must sum to actual native fee |
| Sparse activity / collusion | Weak available traffic | Packing cannot manufacture independent users | Lone users use the individual path. One known member of a two-operation batch identifies the other's residual group; the collector sees submission grouping |
| Disposition | Retain | Useful disclosure/cost control; not a privacy redesign | Run only the cheap feasibility gate below if the relevance conditions hold |

The two alternatives are technically expressible using the available proof/introspection interfaces; neither is an existing v6 feature or established to fit its fee/latency envelope.

## Precise candidate boundary

For two unrelated zero-payout SPENDs whose input notes already exist before the batch, each wallet proves locally. The collector receives proofs, authorizations and encrypted delivery records, **not note openings or spend keys**. An outer statement checks the authorized inner proofs, allowed historical roots, cross-operation duplicate rejection, exact native conservation and the binding of every output/delivery item. It publishes one flat, deterministically ordered nullifier collection and one independently ordered collection of commitment/ciphertext pairs. The individual auth preimages, inner proof digests, operation IDs, pair partitions and intermediate per-operation state journals must not be included elsewhere in L1 data. A shared payload transaction that first publishes them would undo the mechanism.

Retain commitment-to-ciphertext association for recipient discovery; hide only which pairs/nullifiers belong to a particular inner authorization. The new public replay rule must derive positions and accepted root history without that partition. Do not silently carry over v6's fixed two-entry append/index assumptions. Each signed/proved fee remains explicit to its author; aggregate fee is their exact sum. Keeping today's 0.4-tKAS authorization fee would not pass savings back to users just because verification became cheaper. [S2, S3]

This adds a privacy-sensitive collector, not a withdrawal authority. It learns grouping and arrival metadata and can publish them; no protection against that observation is claimed. A new confidentiality protocol hiding submissions from every collector is outside this proposal. Omission before settlement leaves notes unspent, so the user can withdraw or resubmit independently. An exit racing a batch must make one fail through the same current nullifier set. After settlement, a recipient must derive its accepted position from published data and use the individual exit route. No pending liability may be discharged by mere batch submission.

Public data still needs retention after node pruning. Publishing only an opaque new state root would reduce disclosure by removing the data needed for independent recovery and is rejected. Batching must not introduce a private archive or unavailable inner authorization as a recovery dependency. [S3, S4]

## Why this is expressible, but expensive and unproven

Official Rusty Kaspa sources currently dispatch `OpZkPrecompile` to BN254 Groth16 (`0x20`) and RISC Zero Succinct (`0x21`); transaction introspection can bind outputs/payload/state. Official inline-ZK guidance explicitly separates proof validity from checking the actual successor. Ordinary outputs contain a public `u64 value`, so encrypting a payload cannot hide cashout amounts. [P1, P2, P3]

The repository already contains a BN254 proof verifier inside a RISC Zero guest which commits only its aggregate journal. That is evidence for composing existing primitives; its older one-input relation/lane architecture is **not** an implementation of the proposed v6 wrapper and must not be transplanted wholesale. [S5]

Costs are a material warning: the older private-note outer proof took 243.088 seconds on an L40S, with a 223,930-byte serialized receipt. Those are neither a forecast nor native transaction-byte measurements for this candidate. Existing v6 measured about 330,508 mining mass for an internal payment with an intentionally oversized budget; actual script use was roughly half that declaration. Therefore compare against an honestly costed direct baseline, not a gratuitously expensive one. Proof base charges alone cannot establish savings, and neither historical benchmark meets the adopted small-device/payment targets merely by being successful. [S6, S7]

## ONE smallest falsifiable experiment: public-format and replay gate

**Purpose:** disprove the candidate cheaply before a new setup, outer-proof job, runtime or fresh population study. This is an unfunded deterministic reference-format experiment, not native acceptance or statistical privacy qualification. Use only expressly public synthetic development fixtures, never the active evaluation's histories, truth, seeds or masks.

**Input:** two independently valid zero-payout v6-style authorizations with different historical anchors and separate output pairs, plus an unrelated unspent claim. Freeze their individual records as the transparent control. Use their authorized exact fees and actual public state inputs. No chaining of the two new payments inside this smallest batch.

**One check:** encode the proposed flat public envelope; have an independent reference replayer, denied both individual authorizations and their partition, reconstruct the same commitment/nullifier/history successor. In parallel, a private-input reference checker validates the complete inner records using the existing verifier and derives that same public envelope. The unrelated holder must be able to form its individual exit's required public witness from the replay result without receiving the partition. This validates a data/statement dependency, not an executable new covenant. An ordinary native-value/fee listing is included unchanged; nothing is “hidden” by dropping required transaction fields.

**Pass only if all hold:**

1. Every public byte has a specified source, and no auth preimage/digest, deterministic order, root schedule or redundant field reintroduces the original two-operation partition. A deliberately injected partition marker must be detected by the disclosure review.
2. Public replay exactly reconstructs the agreed state and the unrelated holder's exit witness using only the flat data. Changed ciphertext/commitment binding, repeated nullifier, unauthorized fee change and wrong prior state each cause deterministic rejection in the reference checker.
3. A small explicit enumeration under the ideal-hiding model leaves at least two valid operation partitions of the public skeleton, while the transparent control identifies the original partition. This is only a structural ambiguity test; it does not establish equal probabilities or improved payment-amount privacy. Revealing one entire member's record should demonstrate the two-member subtraction limit.

**Fail/abandon:** reject this encoding if public replay or individual exit needs the private partition; if retaining sound binding requires publishing it; or if ordinary native fields deterministically reconstruct it. Do not fix failure by withholding ciphertexts, requiring a trusted service, waiting for traffic, changing amounts or dropping inconvenient operations. Stop the whole candidate if the motivating leakage survives without the removed partition/boundary, or if the required threat model includes a collector from whom this design cannot hide it.

Passing authorizes only consideration of a separate ADR and genuine proof/native-cost prototype. It establishes no production architecture, native acceptance, latency, soundness or privacy gain. A later comparative privacy evaluation must preserve every original economic target through complete drain; hiding an operation's L1 label is not permission to remove it from the scoring denominator. New proofs, tests or source changes are not part of this report.

## Evidence pins

All local references below are under `/home/luke/projects/kaspa-privacy-shared-pool/` on Forge. Inspected HEAD was `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`; the six source files listed below matched that HEAD. The experiment's runtime and dirty files were left alone.

- **S1:** `poc/shared-pool/PRICE-LEAKAGE-SPEC.md`; `docs/rfc/0017-price-priors-and-transaction-leakage.md`; `docs/adr/0033-price-baseline-evaluation.md`. Used only as frozen design documents, not live results.
- **S2:** `poc/shared-pool/src/two_input/mod.rs:24-118,153-239`; `circuit.rs:109-278`. Authorization framing, public digest, native values and output construction.
- **S3:** `poc/shared-pool/src/two_input/covenant.rs:202-239,354-455,493-583`; `tree.rs:105-135`. Fixed native shape, authenticated historical root/current nullifiers, append/state rules.
- **S4:** [SECURITY-INVARIANTS.md](../../../../../SECURITY-INVARIANTS.md) I-1/I-2/I-4/I-7/I-8/I-10/I-11/I-16; [docs/rfc/0011-two-input-private-payments.md](../../../../../docs/rfc/0011-two-input-private-payments.md); [docs/rfc/0012-useful-privacy-requirements.md](../../../../../docs/rfc/0012-useful-privacy-requirements.md); [research/kaspa-toccata-vprogs.md](../../../../kaspa-toccata-vprogs.md) pruning section.
- **S5:** [poc/private-note-chain/common/src/lib.rs:25-69](../../../../../poc/private-note-chain/common/src/lib.rs); [poc/private-note-chain/guest/src/main.rs:19-25](../../../../../poc/private-note-chain/guest/src/main.rs). Existing in-guest verifier and aggregate journal; different prior relation.
- **S6:** [poc/private-note-proof/gpu-2026-10-18/RESULTS.md](../../../../../poc/private-note-proof/gpu-2026-10-18/RESULTS.md), actual measurements; **S7:** [poc/shared-pool/TWO-INPUT.md](../../../../../poc/shared-pool/TWO-INPUT.md), measured cost/fee envelope.
- **P1:** [Official verifier tags](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/zk_precompiles/tags.rs), [Groth16 arity/metering](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/zk_precompiles/groth16/mod.rs).
- **P2:** [Official native output structure](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/core/src/tx.rs#L176-L190).
- **P3:** [Official inline-ZK architecture](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx). Current default heads of Rusty Kaspa and docs were rechecked by read-only GitHub API requests from Forge on this date and matched these pins; KIPs head was `e4ae2332117b5cb68bd6188e065ef885b6d17939`. This is source freshness, not a fresh network-activation or relay test. The experiment's compiled Rusty Kaspa dependency remains pinned separately to `01b532e8b553523216471682649693af92f0fd16`.

Inspected source SHA-256 values:

```text
255f8e908fcb1c4a76dcc8ebe0ca5f4e9ddbadc8ba46f63036cb413298bc8150  two_input/mod.rs
59071901c3abc25daab68c982ef065f8755c09abbb2ce30e6010d821813dd2a7  two_input/circuit.rs
3b6d73c1ebada11d156f3020b444c881160e2f4d8eb7ae629a23ac267bf0d96d  two_input/covenant.rs
9fc004721ae2a22c6faa26f2a046eefd7bb707e3c83077be01a7913b464891ed  two_input/tree.rs
f640acf4771227ea33812108b95ff0a1355cd996ec600f9b7ad833f53ef1158c  private-note-chain/common/src/lib.rs
89b0f4e22319b3af55785ac04503512a5a6a5d7b3b512141c773baffc6440bee  private-note-chain/guest/src/main.rs
```
