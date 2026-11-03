# Accepted exit tickets and independently claimable native KAS

**2026-10-25 — source research and a proposal for review. No architecture is
selected and no implementation, circuit, key, GPU job, live campaign or cold
software changed.**

One verified checkpoint could convert private notes into fully funded native
exit entitlements, after which each owner claims with ordinary hashes/signatures
rather than another Groth16 verification. That is a credible direction to test.
It requires accepted note consumption and allocated backing first. It does not
give an unmaterialized note a cheap exit when the checkpoint service disappears.
The existing expensive direct Exit must remain available for that case.

The unchanged six-payment/nine-exit **2% fee verdict remains FAIL**. Amortizing
only exits cannot fix six unchanged native payment verifications. This memo
compares prospective architectures; it does not relabel the frozen workload.

## Start from the existing decisions

[RFC-0019](../../../../docs/rfc/0019-fees-and-independent-exit-obligations.md)
already distinguishes an unconsumed private note, an accepted unpaid exit
liability, and an owner-controlled native output. [ADR-0039](../../../../docs/adr/0039-exit-liability-and-native-claim-experiments.md)
selected bounded liability/service-loss and native-claim research, not a new exit
architecture. Reuse its state/accounting obligations and retained negative cases;
do not recreate that bootstrap or treat an ideal authorization oracle as a proof.
The earlier [primary-source review](../../exit-fee/PRIMARY-SOURCE-OPTIONS.md) and
[exit-obligation review](../../exit-fee/EXIT-OBLIGATIONS-REVIEW.md) cover the same
accepted-entitlement distinction and data-availability boundary.

[ADR-0066](../../../../docs/adr/0066-local-native-kas-payment-prototype.md)
preserves the direct full-note Exit152, exact consent/current-state binding,
original-seed recovery and unchanged fee/privacy targets. The
[asynchronous batching memo](ASYNCHRONOUS-BATCHING-01.md) explains why existing
whole-effects authorizations cannot simply be repacked into a later batch.
[I-1–I-7, I-10–I-11 and I-14–I-16](../../../../SECURITY-INVARIANTS.md) apply to
both notes and unpaid tickets.

## What current Aztec actually supplies

Refreshed official `AztecProtocol/aztec-packages:next` resolved to
`c1b606f97dcd56668ccd8087a794190c34b4c571` (2026-10-23). These are inspected
source identities, not deployment, audit or production-security claims. Current
[messaging documentation](https://docs.aztec.network/developers/testnet/docs/aztec-nr/framework-description/ethereum_aztec_messaging)
identifies itself as Testnet v6.0.0-rc.1. It describes initiating the withdrawal
on L2, then consuming its message after an epoch proof reaches L1. Its example
witness API returns a leaf index and sibling path; that API's existence does not
establish permanent witness availability after all services disappear.

| Inspected primary source | Concrete reusable contract |
| --- | --- |
| [EpochProofLib, proof acceptance and insertion](https://github.com/AztecProtocol/aztec-packages/blob/c1b606f97dcd56668ccd8087a794190c34b4c571/l1-contracts/src/core/libraries/rollup/EpochProofLib.sol#L114-L180) | Proof verification, canonical header/archive context and the out-hash precede insertion into Outbox. The out-hash is a proof public input. A locally produced message or checkpoint proposal is insufficient. |
| [Outbox, source and consumption](https://github.com/AztecProtocol/aztec-packages/blob/c1b606f97dcd56668ccd8087a794190c34b4c571/l1-contracts/src/core/messagebridge/Outbox.sol#L103-L169) | Only the configured Rollup inserts roots. Consumption checks protocol version, portal recipient, L1 chain, an inserted root, membership and previously unconsumed leaf identity. It sets consumed state without a new SNARK. |
| [Message hashing](https://github.com/AztecProtocol/aztec-packages/blob/c1b606f97dcd56668ccd8087a794190c34b4c571/l1-contracts/src/core/libraries/crypto/Hash.sol#L31-L53) | The hash binds L2 sender/version, L1 recipient/chain and application content. A generic Merkle leaf does not supply these domains automatically. Reuse domain binding, not Aztec's field truncation/ABI bytes as a Kaspa codec. |
| [TokenPortal test example](https://github.com/AztecProtocol/aztec-packages/blob/c1b606f97dcd56668ccd8087a794190c34b4c571/l1-contracts/test/portals/TokenPortal.sol#L113-L150) | Reconstruct withdrawal content from recipient, amount and optional caller, consume the message, then transfer escrowed tokens. This is an ERC20 example under `test/`, not a native-KAS reserve implementation. |

The Outbox caller is the **portal**, not necessarily the withdrawing owner. The
portal example can bind a specified caller or permit a relayer while fixing the
payout recipient. An owner transaction signature in a Kaspa ticket is therefore
a proposed authority/fee rule, not something Aztec Outbox itself requires.

Partial-root replay is a useful established warning. Current
[Outbox design comments](https://github.com/AztecProtocol/aztec-packages/blob/c1b606f97dcd56668ccd8087a794190c34b4c571/l1-contracts/src/core/messagebridge/Outbox.sol#L23-L48)
state that consumed state is shared across roots of one epoch and leaf identity
must remain stable as proof coverage grows. The proving system must enforce
that stability; Outbox cannot detect the same economic message moving to a
different identity. This is an explicit composition boundary, not an upstream
vulnerability finding. The [current tests](https://github.com/AztecProtocol/aztec-packages/blob/c1b606f97dcd56668ccd8087a794190c34b4c571/l1-contracts/test/Outbox.t.sol)
were inspected as source, not run here.

Do not import the whole trust model. The inspected
[RollupCore](https://github.com/AztecProtocol/aztec-packages/blob/c1b606f97dcd56668ccd8087a794190c34b4c571/l1-contracts/src/core/RollupCore.sol#L73-L145)
documents committee/data-availability assumptions and public-execution training
wheels; proof submission also performs attestation checks. Outbox itself does
not prove a token burn or correct application accounting. A KAS checkpoint must
prove its own note authority, NF updates, backing and native effects. An operator
signature or committee assertion cannot replace those obligations.

## Three layouts worth comparing

These are engineering inferences, not implemented or measured candidates.

| Layout | Claim and backing | Main tradeoff |
| --- | --- | --- |
| **Checkpoint pays ordinary P2PK outputs** | Accepted checkpoint consumes each note NF and creates its authorized native output. Later spending is ordinary owner self-custody; no Merkle claim is needed. | Simplest native delivery. Withdrawal is already complete at checkpoint acceptance, so a later wallet spend cannot be counted as a second protocol withdrawal. Requires owners' exact prior payout consent. |
| **Checkpoint creates one funded ticket UTXO per owner** | Each ticket holds its complete gross liability and a fixed owner/destination/fee policy. Native UTXO consumption prevents a second claim. | Independently claimable without a shared claim head. Membership is normally redundant when accepted creation already validated the exact ticket script/value. More outputs and small-ticket storage mass must be measured. |
| **Checkpoint creates one funded outbox UTXO per closed batch** | Immutable entitlement root plus current paid-state commitment. Claim consumes that outbox UTXO, verifies membership/signature, updates paid state and preserves the exact remaining backing. | Closest to Outbox; fewer creation outputs. Claims serialize on the outbox head and need public witness refresh after other claims. They can be separated from the private payment head. |

Prefer a closed immutable batch root for a first comparison. Extending roots,
moving tickets between escrows or merging batches adds migration/overlap proof
obligations. None is necessary to test the fee-location hypothesis.

The intended ticket is a withdrawal entitlement, **not a new asset or privacy
token**. It must have no issuer mint key, admin redemption, expiry confiscation
or operator-controlled release. No transferrable ticket market is proposed.

## Authorization and conservation that must precede the cheap claim

An owner-approved record must bind the chain and authenticated pool lineage,
protocol/profile/role, stable ticket identity, the original note NF, gross
integer sompi liability, exact payout destination or committed claim authority,
and the exact fee rule. Any owner key must be controlled/recoverable from that
owner's original backup. The checkpoint's genuine relation must connect these
fields to the consumed note and authorized value; a batcher's tuple or hash is
not consent. Prove each owner's conversion, exact change and settlement-fee
allocation separately; a correct global sum cannot authorize redistribution of
ticket principal or fees between owners.

Current [Exit152](../../../../poc/local-private-payment/relation/src/statements.rs#L115-L169)
and [native Exit](../../../../poc/local-private-payment/verification/native/src/policy.rs#L474-L584)
bind exact actual effects and a native P2PK payout. They do not authorize replacing
that payout with an unpaid ticket. Reusing their cryptographic gadgets may be
appropriate; reinterpreting saved proofs/signatures is not. A new withdrawal
intent/checkpoint profile, codec, proof identity and explicit ADR are required.
Point-bound intents stale when the reserve head moves. Durable intents need the
separate reviewed consent/anchor rules described in the batching memo.

For checkpoint inputs `v`, private change `w`, new gross tickets `c`, and
owner-authorized settlement fee `f_s`, require checked integer equations:

```text
sum(v) = sum(w) + sum(c) + f_s
private liabilities' = private liabilities - sum(v) + sum(w)
unpaid ticket liabilities' = unpaid ticket liabilities + sum(c)
total user backing' = total user backing - f_s
```

Allocating `sum(c)` from private reserve into funded ticket/outbox outputs moves
backing; it does not pay users yet or reduce total backing a second time. Every
consumed NF must be absent in the **actual current** NF set, then inserted once
in the same accepted transition that creates all funded tickets. The continuing
private reserve backs only remaining private liabilities; ticket backing is
separately locked. A terminal private head cannot release an unpaid outbox.

For a simple self-funded claim, `c_i = payout_i + claim_fee_i`; the escrow loses
exactly `c_i` while the ticket liability decreases by exactly `c_i`. A shared
outbox successor retains the sum of every unclaimed gross ticket. On the last
claim, no unexplained rent, fee credit or other entitlement may disappear.
External fee inputs/refunds are separate accounting and count toward total
cost. Another user's principal cannot fund them.

Exact fixed fees simplify a first experiment but can fail liveness after a fee
rise. Flexible fees require explicit owner consent, a maximum fee/payout rule
and bound refund destinations. Neither a sponsor nor the executor gets fee
discretion. No fixed-price assumption or hidden subsidy establishes the 2% goal.

## Native feasibility and concrete barriers

Refreshed Kaspa heads remain rusty-kaspa
`4edcbbccb449f84832afb1ca157904b35f37d006`, KIPs
`e4ae2332117b5cb68bd6188e065ef885b6d17939`, and vProgs
`f9b84a863a7c7c20586a9cf947550475e894f72e`.

Native [amount/script introspection](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/opcodes/mod.rs#L1099-L1174),
SHA and [Schnorr verification](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/opcodes/mod.rs#L827-L856)
can express a supplied authenticated leaf, signature and exact payout/continuation
predicate. [KIP-20](https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0020.md#L283-L319)
describes bounded one-to-many covenant authorization and native lineage. These
are capability evidence, not a validated combined ticket script.

Two shortcuts cannot enforce the proposed authorization:

1. **Merkle + signature against a caller-provided root is insufficient.** The
   root must already be authenticated by accepted native state and its selected
   verifier; the leaf must already bind the legitimate owner's key/value. An
   arbitrary valid signature proves neither private note ownership nor NF state.
2. **An independent ticket cannot read a global mutable spent map for free.**
   Introspection accesses transaction inputs/outputs; covenant input/output
   indexing is transaction-local. A shared current-state UTXO must participate,
   or accepted conversion must first consume the note and allocate isolated
   backing. A witness asserting the latest pool root is not native authentication.

The unchanged KPXA native policy has no ticket materialization or cheap-claim
branch. Its fixed state/effects/output rules cannot be extended by a host flag.
This is a selected-policy limitation, not evidence that Toccata lacks the generic
capability. New covenant lineage must be genuine and tied to the selected pool;
matching a domain string alone is insufficient.

Use the intended exact signature hash mode. [CheckSig accepts several modes](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/core/src/hashing/sighash_type.rs#L7-L23);
it does not force SIGHASH_ALL. An intended ordinary claim should enforce its
selected full-input/output authorization and independently check policy-sensitive
fields not covered by that signature. A supplied-message signature is not a
substitute for connecting its digest to actual native effects.

Do not adopt the unchanged vProgs permission emitter as a shortcut. The existing
review identifies independently consumed old/new Merkle walks and externally
funded fees in that pinned source. These are retained source-level reuse
barriers, not newly reproduced attacks. A shared-outbox update must recompute
both old/new roots with the **same authenticated siblings and index** and prove
that every other entitlement survives. The update replaces only the
authenticated old leaf or paid bit; old and replacement leaf values differ.
No hostile fixture was run here.

No requirement for a full based-app/vProgs runtime follows from this claim
pattern alone. It may become useful for execution/aggregation/availability at
scale; native checkpoint-plus-covenant layouts deserve comparison first, as the
[Toccata state-layout guide](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/decision-guide.mdx)
also advises. This memo establishes neither necessity nor dispensability.

## Adversarial and service-loss obligations

| Boundary | Required outcome |
| --- | --- |
| Private spend/direct Exit races ticket materialization | Both consume the same original NF against current state. At most one accepted path wins. A proposal or private pending lock creates no ticket and removes no liability. |
| Duplicate/extended/remapped tickets | One stable economic identity survives root ordering and proof coverage changes; no root-local-index reset. Prefer no extension in the minimum candidate. No second escrow may fund a duplicate entitlement while the old one remains redeemable. |
| Reserve split or counterfeit ticket | Checkpoint proves all outputs' exact values/scripts/policy/lineage and sum. Standalone fabricated roots or counterfeit tickets cannot debit a genuine reserve. |
| Cross-pool/chain/role replay | Bind real pool lineage, chain/genesis, profile, batch/ticket identity and claim outpoint. The same key, NF bytes or leaf value in another pool is not authority. |
| Current outpoint changes | Final checkpoint must consume the real current private head. Shared-outbox claims must consume their real current escrow head. Stale proofs reject; neither other owners' presence nor an operator signature repairs them. |
| Claim A then B / B then A | Both remain independently claimable from accepted public updates. Paid-state updates preserve the other leaf and backing; a missing witness produces an explicit liveness failure. |
| Reorg | Roll back conversion, ticket UTXOs, paid state and payout observations together with their accepted ancestors. Orphan tickets authorize nothing on another fork. Observer knowledge and disappearing services do not roll back. |
| Coordinator disappears before conversion | Unmaterialized notes retain the direct G16 route and remaining private backing. Its existing fee/prover/data costs remain; do not claim cheap singleton exit economics. |
| Coordinator disappears after conversion | Original backup plus declared public software/history/ticket data must reconstruct claim authority, leaf/path and current escrow state. No coordinator map, invoice-index export, later private journal or another owner's key may be required. |
| Data withheld | A root is not its leaves. Publish sufficient authenticated ticket/update data, or prove another explicit retention model. A node witness RPC alone is not durable availability. |
| Small tickets, fee changes, last claim | Measure complete creation/claim transaction compute, transient/storage mass and allowed fees. No liability deletion, admin rescue or relaxed check repairs a fee-exhausted claim. |

The [native storage calculation](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/core/src/mass/mod.rs#L410-L484)
depends on all input/output values and script pluralities. More ticket UTXOs,
small leftovers or large scripts can outweigh saved verification work.

Public tickets expose destination/authority, gross amount, checkpoint grouping
and timing earlier than final redemption. Merkle proofs and Tor do not erase
invoice, counterparty, key-reuse or network correlation. This design supplies
**no privacy improvement claim** and changes no old observer/metric/result.

## Conditional arithmetic, not a new fee result

Using the requested optimistic native floors of 14.75 million SU for direct Exit
and 15.5 million SU for an R0 checkpoint, the current conversion is 100 SU/gram.
At 100 sompi/gram those correspond to roughly 0.1475 and 0.155 KAS respectively.
[Official conversion constants](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/core/src/mass/units.rs#L4-L23);
[retained fee research](../fees/FEE-FLOOR-01.md).

| Hypothetical verifier-only accounting | KAS before claim/creation bytes, deposits, storage, proving and retries |
| --- | ---: |
| Nine unchanged direct exits | 1.3275 |
| Six unchanged payments + one new R0 exit checkpoint | 1.085 |
| Two prospective payment batches + a separate R0 exit checkpoint | 0.465 |
| Frozen 2% of 21 KAS | **0.42** |

The new checkpoint's actual cost is unmeasured and may be higher. Even the
optimistic two-batch-plus-separate-checkpoint row exceeds the entire budget
before claims. Combining ticket creation with an already necessary settlement
could avoid that extra verification, but exact consent, output availability,
dependency order and the complete matched workload would need review. It is not
permission to merge current proofs or move costs outside the denominator.

If the fee contract must also hold when the service disappears before any ticket
is accepted and all nine users take the current direct fallback, that route
still exceeds 0.42 KAS. Good-weather amortization does not establish that stronger
recovery-cost promise. A future review must distinguish those conditions without
weakening or retroactively redefining the existing target.

## Smallest next falsification after design/ADR review

1. **Reuse the finite liability model.** Two owners, two converted notes and one
   still-private note suffice. Add explicit private/escrow backing, a closed
   batch root, stable IDs, exact owner fee/payout rules and one rollback. Explore
   both claim orders, direct-Exit/materialization races and service loss before
   and after acceptance. Freeze expected counterexamples before executing.
2. **Choose one layout, then test native capability without new private setup.**
   Use public synthetic supplied UTXOs and ordinary signature/hash/Merkle checks
   to measure two claims and the terminal case with official native Full checks.
   Retain assumed accepted authorization as an explicit oracle boundary; this
   step does not prove valid checkpoint creation or native backing. Reject wrong
   signer/hash mode, changed destination/fee, foreign pool, duplicate paid ID,
   wrong current point and mismatched old/new update paths. Include meaningful
   mutants that omit each conservation/identity/path binding.
3. **Only after those gates and a new reviewed authorization profile**, perform
   genuine checkpoint creation and original-seed recovery after the batcher/
   prover is removed. One unmaterialized note must still direct-exit; both tickets
   must independently pay native test KAS. Measure every creation, claim, proof,
   retry and storage cost under a prospectively frozen comparison. No mainnet,
   real funds, old-domain migration or current campaign change is authorized.

Stop on an authorization/accounting mismatch; report data/service dependence or
economic failure honestly. Passing a finite model or supplied-context claim
does not qualify cryptographic correctness, settlement, recovery or privacy.
