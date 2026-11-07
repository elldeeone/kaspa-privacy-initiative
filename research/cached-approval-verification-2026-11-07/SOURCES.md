# Cached approval verification: source review and trial route

Reviewed **7 November 2026**, starting from local `bd0bb946` on
`research/native-kas-withdrawal-privacy`. This is a source review and design
inference, not an executed cache benchmark or qualification of a new bank.

**Decision: test the optimization.** RISC Zero's existing receipt composition
can prove expensive wallet-proof verification once, then reuse that proof while
proving each fresh bank transition. The current L1 can verify the resulting
ordinary unconditional Groth16 receipt without a consensus change. Whether this
saves enough time or total cost requires measurement: the first cached receipt
costs work, and every settlement still needs fresh execution, recursive resolution
and Groth16 compression. Cache only proof validity, never current spendability.

Read alongside [project status](../../docs/PROJECT-STATUS.md),
[security invariants](../../SECURITY-INVARIANTS.md), the
[proof](../../docs/research-knowledge/proofs.md),
[reuse](../../docs/research-knowledge/reuse.md),
[recovery](../../docs/research-knowledge/recovery.md),
[operations](../../docs/research-knowledge/operations.md),
[privacy](../../docs/research-knowledge/privacy.md) and
[cost](../../docs/research-knowledge/costs.md) guides, and
[ADR-0111](../../docs/adr/0111-reusable-withdrawal-intents.md).

## Exact composition route

The installed `risc0-zkvm = 3.0.3` package records upstream source commit
`fba0c0179f0125afe23bd15eb4c34428aacf5705` in `.cargo_vcs_info.json`.
The official `env.rs` and `host/server/prove/mod.rs` at that commit were fetched
and matched the installed crate byte for byte. Their SHA-256 values are
`7e0678028670089ba3ef8d34956cf1f58a42f8ba7635bb5a0bc7f13a843bf2c6`
and `a3e5fdccbd4719820274c8b466fe7c211941b3fa24979f6eeddf5d1da4a347c9`.
Keep the existing complete Cargo locks, component/control identities, disabled
development mode and qualified GPU/guest toolchain; the top-level SDK version
alone does not fix every component version.

1. A separate authorization guest verifies every complete wallet proof under
   the fixed checked wallet key. It commits a domain-separated digest binding
   the exact canonical ordered packet, including full intent and proof bytes,
   pool and wallet-key identity. Its receipt must be complete and unconditional.
2. Retain its **Succinct receipt**. Supply that actual receipt through
   `ExecutorEnv::builder().add_assumption(receipt)`. Passing a `Receipt` creates
   a `Proven` assumption; passing only a `ReceiptClaim` creates an unresolved
   assumption and is insufficient. [S1], [S3]
3. The new settlement guest pins the authorization image and calls
   `env::verify(image, exact_journal)`. This establishes a claim for that image
   and journal with an empty assumptions list, zero input hash and successful
   completion. It does not trust a host boolean or an arbitrary image. [S2]
4. Execute all current state/effect checks. The existing prover joins the fresh
   execution segments and recursively resolves each proven assumption, producing
   an unconditional Succinct receipt. Then compress that receipt to Groth16.
   Resolution is real proving work on every fresh transition. [S4], [S5]
5. Independently require the exact expected image and journal, actual Groth16
   variant, `ReceiptClaim::ok` digest, empty assumptions and disabled development
   mode. Convert using the existing checked native-proof path and run the actual
   complete native transaction validator. The native script must bind the claim
   to the actual predecessor, amounts, packet and installed outputs. [L1], [L2]

**SDK pitfall:** `InnerAssumptionReceipt` can represent a Groth16 receipt, but
the pinned `composite_to_succinct` implementation explicitly rejects Groth16
assumptions. Retaining only a compressed cache receipt loses the supported
recursive path. Use a proven Succinct cache receipt; the final L1 receipt remains
Groth16. The same implementation rejects fake receipt assumptions. [S3], [S4]

At the pinned native source, `compute_assert_claim` fixes `Halted(0)`, zero input,
the expected image/journal and zero assumptions. A conditionally proved assertion
does not become a valid final claim merely because its journal matches. The
existing local generic-Groth16 covenant similarly constructs the expected full
claim, using fixed official verifier parameters. Both the SDK and actual native
checks must remain; native acceptance of this new composed image is still an
experiment to execute. [K1], [L1], [L5]

## Static and fresh obligations

| Reusable verified fact | Must be checked again in the fresh transition |
| --- | --- |
| These exact wallet proofs verify for these exact complete canonical statements and delivery records. | Accepted historical anchor membership; present nullifier/deposit spentness; sequential state mutation and backing. |
| The certificate binds a fixed pool, wallet domain/version, key and whole ordered packet/full intent. | Full cohort/intent validity, native payout set/value, actual fee and cap, refund policy, continuation versus terminal branch. |
| The fixed authorization image attests only to that proof-validity relation. | Actual current bank root/outpoint/value, successor root and installed script, complete ordered payload and effects. |

The existing `Packet::read` rejects trailing bytes; preserve canonical complete
consumption and compare re-encoded bytes when admitting new framing. A compact
128-byte cache journal can contain four fixed digests: purpose/domain, pool,
wallet VK and complete packet. The wallet-domain/version must be fixed by the
purpose/image and checked operation relation. The settlement image must pin the
authorization image; an attacker-supplied image or key is not a cache. Hashing
statements alone omits proof/delivery/intent substitutions unless the complete
canonical packet is also bound. Changed cohort, payout, cap or nonce needs a new
certificate and, where ADR-0111 requires it, new owner consent. [L3], [L4]

The simplest safe adaptation keeps `Ledger::apply` intact and substitutes only
the proof-verifier implementation after the exact certificate has been verified.
Its configured key identity and `op.check_public` obligations remain. Do not skip
the rest of `apply`: it checks current accepted anchors, rejects zero/spent
economic nullifiers, handles deposit ownership/status/value, updates commitments
and liabilities, and commits only a successful cloned state. Each operation in
a dependent batch runs against its successive state. Cache validity does not
permit replaying the packet's economic effects. [L3]

This changes the settlement guest image, so **start a new bank**. No existing
immutable bank is silently upgraded. Retained old packets may support supplied
state-context diagnostics; proving them under a new image does not establish an
accepted new-bank lineage or transfer authority over an old bank. Preserve I-6.
If a cache is missing, recreate it from public operations and the exact available
parameters/software or use a qualified uncached path; never accept an unproven
claim to restore liveness. A seed or old receipt does not replace those data.

## Prior work and mature protocols

The historical composition review and addendum at
`85e39398fd97ff0299e07fad8899cd3f4cc454ac`, and
[ADR-0034](../../docs/research-knowledge/documents/958d861d48a9c5d61bf5403e56006abcc2d459e2.txt), distinguish
checking two wallet proofs from authenticating current state and native effects.
Its J42 binds a public projection, but does not itself establish accepted anchors,
current nullifiers, reserve lineage or recovery. Later J336/native Full checks
were stronger, separately scoped experiments with supplied predecessors. Reuse
the checked BN254 adapter, exact claim/image binding, complete proof/compression
route and intended-error controls. Do not label those old receipts a benchmark
of this new reusable certificate. The old review already identifies RISC Zero
composition and vProgs child-image/state-continuity checks; no new cryptographic
primitive or full runtime migration is needed. [H1], [H2]

The [five-protocol review](../native-kas-shielded-value-sources-2026-11-03.md) and
[preceding intent source review](../reusable-withdrawal-approvals-2026-11-06/SOURCES.md)
retain wider implementation/recovery findings. Carry these specific mechanisms:

| Source | Reuse/adapt | Do not import or infer |
| --- | --- | --- |
| Orchard/Zcash | Historical note membership plus independently current nullifiers; full effects authorization. [O1], [Z1] | Orchard consensus, native confidential KAS or reusable current-state validity. |
| Aztec | User-local private authorization followed by fresh execution/state/nullifier checks; chain/version context. [A1], [A2] | Its L2/kernel/PXE/sequencer runtime as a requirement. |
| RAILGUN | Seen roots and bound effects context, followed by current nullifier rejection/recording. [R1] | EVM custody, token/admin assumptions or a cached spentness check. |
| Monero | Reject duplicate key images within the block and against chain history. [M1] | RingCT/CLSAG/decoy or native consensus changes. |
| Litecoin MWEB | Present unspent-input checks and explicit supply/peg-out accounting. [W1] | Extension-block rules or confidential ordinary Kaspa outputs. |
| vProgs/Kaspa research | Fixed child image, authenticated ordered execution and successor continuity. [V1], [V2] | A requirement to expand the prototype runtime/operator infrastructure. |

## Fresh upstream identities

Official GitHub commit API reads at **2026-11-07 05:51:37 UTC** resolved the
following heads. Olaf's `main` is unchanged; this check does not inspect unseen
work outside that branch. All nine protocol heads match the preceding review
except Aztec. Its two decisive documents were fetched at the new head and are
byte-identical to their preceding `c03bf6c7` versions. Their SHA-256 values are
`68f101753f911bb0f131545ddb2ae6c7e260f9b47e0e6e755baf4f11f6b7b57e`
and `6412cfb7b1c33e1e7a53da697d6edea6f62c8c11f3cfd769b1e74248452bdc11`.
Unchanged heads or files do not establish deployed versions or a fresh full audit.

| Repository | Exact head |
| --- | --- |
| Olaf KPI `main` | `7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1` |
| kaspanet/docs | `0ac77d043a802fc8196abfd5812ac2afbd97a2b9` |
| kaspanet/rusty-kaspa | `4863866fce8439d0305b410fc4d802e7261d54d0` |
| kaspanet/vprogs | `f9b84a863a7c7c20586a9cf947550475e894f72e` |
| kaspanet/research | `c923faca11a49148fa7d912d27ce00197a5c5a4a` |
| zcash/orchard | `616a669df8c9a59c33d47064d3ce04b25d026b2e` |
| AztecProtocol/aztec-packages | `6def0f4939dabbb22890e4214b439324771e6fbc` |
| Railgun-Privacy/contract | `36bcf5ed7cf94bfafb6e1a303e1832c769c16780` |
| monero-project/monero | `b14fae7bca4099cea56205e44c1005602834b7bd` |
| litecoin-project/litecoin | `ec1b6489a900d09cf5991e220dce089c77a232a2` |

## Measurement and privacy boundary

Freeze a matched workload before running it. Count initial cache creation and
verification, cold wallet/public-parameter loading, every fresh settlement,
recursive resolution/compression, cancellations, misses, retries and queue wait.
For `n` repeated attempts, compare measured `C + n*S` with `n*F`, where `C` is
cache construction and `S`/`F` are complete cached/uncached attempt costs. If
`F <= S`, this cache has no reuse break-even. Otherwise savings begin only above
`C/(F-S)` attempts, with real failed/cancelled work included. Never report only
warm settlement time as the full lifecycle cost. Distinguish service cost, energy,
conditional tariff valuation, quoted native fees and fees actually paid on TN10.

Combine the actual private-payment wallet, protected blind registration,
unchanged owner approvals, stale-worker cancellation, oldest-request priority and
optional payment batching in one fresh history before calling the combination
demonstrated. Each currently has separate evidence. Keep all current fee, backing,
stale-root, replay and exact-effect controls. Exercise terminal drainage and spend
the actual payout outputs with restored receiver keys. The unchanged depth-four
wallet supports at most 16 appended commitments; spending does not free leaves.

Caching itself adds no payout-owner anonymity. The existing protected onion
registration retains six assignments in its declared service-only view; labelled
client timing or later owner disclosure collapses it to one. The latest busy-pool
test instead used identified entitlement replies and already mapped every payout.
The new combined test must preserve actual service-visible messages and logs,
separate local controller instructions/private truth, and report all relevant
counterfactual observer views. Native output values/scripts remain public. [P1],
[P2]

## Minimal fresh Testnet route

The owner now authorized a small fresh TN10 trial conditional on the complete
functional flow passing. Historical documents that say no release was granted
describe their old sessions, not a reason to ask for authorization again. The
current AGENTS.md still requires a successful real terminal broadcast and confirmed
payout rehearsal before claiming trial readiness.

The latest completed live reference is
[depth-four attempt 06](../full-drainage-executed-lifecycle-2026-11-01/run/tn10-attempt-06-public/README.md):
seven settlements and five confirmed payouts, with its later privacy correction.
It is a different lane/permission guest. Do not replay its transaction files,
wallet keys, trial identity, program constants or old orchestrator wholesale.

1. Provide one offline command that creates a new profile-bound trial ID, fresh
   wallet/payout/sponsor keys, public receive metadata and private `0700`/`0600`
   backups. Existing `private-native-tn10 init` and
   `recovery-tn10 init-full-drainage` show this mechanism, but pin historical
   profiles and cannot initialize the new bank unchanged. Reuse public parameters
   only with their exact authenticated key/relation identity. [T1], [T2]
2. Build the complete inline-bank path against actual ordinary test-KAS inputs,
   starting a new bank with the new image. Reuse the checked signing, final
   storage-mass/fee calculation, exact SDK roundtrip and native Full validation
   patterns. The current busy/batched funding helper creates supplied synthetic
   inputs, so it still needs an actual-UTXO/RPC adapter. Prove from the genuine
   created bank and preserve all accepted predecessors. [L2], [T3]
3. Reuse `live-chain.mjs`'s exact-integer JSON-RPC transport: query synchronized
   `testnet-10` context from the primary and independently operated witness,
   compare relevant actual input UTXOs, persist one submission intent before
   submitting once, and retain the accepted transaction body after ten
   confirmations. Ambiguous results trigger read-only reconciliation, never
   automatic rebroadcast. Adapt profile-specific envelope checks explicitly. [T3]
4. Confirm the actual terminal payouts and final reserve/liability accounting on
   both synchronized routes, and exercise restored-key payout spending. Adapt
   `final-corroborate.mjs`'s generic UTXO checks: its five-payout/state-rent constants
   belong to the old design. Retain raw evidence, exact source/image/claim/proof
   identities, paid fees and fresh trial identity. A failed trial gets a new
   identity rather than replaying the failed one. [T4]

Read-only `getServerInfo` requests at **2026-11-07 05:53:27 UTC** found both
existing TLS JSON-RPC routes reachable, synchronized, with UTXO indexes and
`networkId=testnet-10`, `serverVersion=2.1.0`, API version 1/revision 0:
`electron-10.kaspa.blue` (DAA `616958963`) and
`vector-10.kaspa.green` (DAA `616958962`). This is current route availability,
not a source-to-deployed-binary attestation or chain acceptance of the new bank.
Recheck before mutation. This source review created no identity, service, funding,
proof or transaction and broadcast nothing.

## Primary references

[S1]: https://github.com/risc0/risc0/blob/fba0c0179f0125afe23bd15eb4c34428aacf5705/risc0/zkvm/src/host/client/env.rs#L408-L425
[S2]: https://github.com/risc0/risc0/blob/fba0c0179f0125afe23bd15eb4c34428aacf5705/risc0/zkvm/src/guest/env/verify.rs#L24-L108
[S3]: https://github.com/risc0/risc0/blob/fba0c0179f0125afe23bd15eb4c34428aacf5705/risc0/zkvm/src/receipt.rs#L644-L789
[S4]: https://github.com/risc0/risc0/blob/fba0c0179f0125afe23bd15eb4c34428aacf5705/risc0/zkvm/src/host/server/prove/mod.rs#L350-L389
[S5]: https://github.com/risc0/risc0/blob/fba0c0179f0125afe23bd15eb4c34428aacf5705/risc0/zkvm/src/host/recursion/prove/mod.rs#L215-L249
[K1]: https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/crypto/txscript/src/zk_precompiles/risc0/receipt_claim.rs#L48-L64
[L1]: ../../poc/batched-payment-costs/host/src/prover.rs
[L2]: ../../poc/batched-payment-costs/host/src/bench.rs
[L3]: ../../poc/private-note-wallet/src/ledger.rs
[L4]: ../../poc/reusable-withdrawal-approvals/common/src/lib.rs
[L5]: ../../poc/batched-payment-costs/host/src/receipt_script.rs
[H1]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/85e39398fd97ff0299e07fad8899cd3f4cc454ac/research/native-proof-composition-source-review-2026-10-22.md
[H2]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/85e39398fd97ff0299e07fad8899cd3f4cc454ac/research/native-proof-composition-source-review-2026-10-22-full-addendum.md
[O1]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/bundle.rs
[Z1]: https://github.com/zcash/zips/blob/ff594de6e95bb9e9e7d2ace09510281531c30447/protocol/protocol.tex#L4322-L4402
[A1]: https://github.com/AztecProtocol/aztec-packages/blob/6def0f4939dabbb22890e4214b439324771e6fbc/docs/docs-developers/docs/foundational-topics/transactions.md#L33-L61
[A2]: https://github.com/AztecProtocol/aztec-packages/blob/6def0f4939dabbb22890e4214b439324771e6fbc/docs/docs-developers/docs/foundational-topics/advanced/storage/indexed_merkle_tree.mdx#L40-L60
[R1]: https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/RailgunLogic.sol#L420-L509
[M1]: https://github.com/monero-project/monero/blob/b14fae7bca4099cea56205e44c1005602834b7bd/src/cryptonote_core/blockchain.cpp#L2853-L2880
[W1]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/consensus.md#L73-L107
[V1]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/abi/src/batch_aggregator/verifier.rs
[V2]: https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/vProgs/main.tex
[P1]: ../withdrawal-request-and-busy-pool-2026-11-06/RESULT.md
[P2]: ../busy-pool-payment-flow-2026-11-06/RESULT.md
[T1]: ../../poc/private-native-tn10/src/main.rs
[T2]: ../../poc/recovery-tn10/src/main.rs
[T3]: ../../poc/recovery-tn10/live-chain.mjs
[T4]: ../../poc/recovery-tn10/final-corroborate.mjs


## Executed Claim-only correction, 7 November

The public API documentation describes unresolved assumptions as conditional
receipts, but the pinned implementation rejects the normal proving request
before producing any receipt. The actual negative control returned
`no receipt available for unresolved assumption`.
`host/server/prove/prover_impl.rs:141-153` requires an actual receipt for each
non-internal assumption, and `host/server/prove/tests.rs:769-784` preserves the
same expected failure (TODO982). This refines the generic API description above.
Pinned primary files:
[prover implementation](https://github.com/risc0/risc0/blob/fba0c0179f0125afe23bd15eb4c34428aacf5705/risc0/zkvm/src/host/server/prove/prover_impl.rs#L141-L153)
and [existing test](https://github.com/risc0/risc0/blob/fba0c0179f0125afe23bd15eb4c34428aacf5705/risc0/zkvm/src/host/server/prove/tests.rs#L769-L784).
The first unfunded rehearsal harness incorrectly expected to receive a
conditional proof; it stopped before any test-coin submission. Preserve the
failure, check the precise SDK refusal, and use a fresh trial identity. The
production complete-claim checks are unchanged. No actual conditional native
receipt was generated or tested through this SDK path; native zero-assumption
binding remains source-grounded, with other actual native wrong-proof/effect
controls executed separately.
