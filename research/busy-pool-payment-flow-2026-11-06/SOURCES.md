# Busy-pool payment flow: sources and reuse boundary

Reviewed 6 November 2026 against local `39666456b52b61c279031d33392851ade552643f`.
This file records source facts and the bounded experiment recommended from them;
it does not report an executed queue experiment or testnet readiness.

**Recommendation:** keep the withdrawal that arrived first at the front of a
cooperative queue, even after an unrelated accepted bank update forces a retry.
Reuse its fixed owner consent, create a fresh current-state receipt, then batch
compatible waiting private payments using the existing `PAYMENT` mode. This can
avoid self-inflicted starvation. It cannot prevent independent actors from
spending the same current bank UTXO first. No consensus change, administrator
lock, mixed payment/withdrawal packet, wallet-circuit change or new primitive.

Read first: [project status](../../docs/PROJECT-STATUS.md),
[operations](../../docs/research-knowledge/operations.md),
[privacy](../../docs/research-knowledge/privacy.md),
[proofs](../../docs/research-knowledge/proofs.md),
[costs](../../docs/research-knowledge/costs.md),
[security invariants](../../SECURITY-INVARIANTS.md),
[ADR-0111](../../docs/adr/0111-reusable-withdrawal-intents.md) and the
[preceding primary-source review](../reusable-withdrawal-approvals-2026-11-06/SOURCES.md).
Earlier failures, observer corrections, complete-cost limits and conditional
consent timing risks remain applicable.

## Established facts

1. **Owner consent and settlement are different objects.** The existing optional
   intent binds pool/config, accepted reference anchor, complete claim set,
   complete equal-value payout set, nonce and aggregate fee cap. The final
   receipt still binds the exact current old/new state, actual predecessor/value,
   outputs and ordered packet. The successful earlier experiment reused literal
   owner proofs; it did not reuse a stale state-transition receipt. [L1], [L2]
2. **Historical membership is conditional, not current spendability.**
   `Ledger::apply` verifies the proof, requires `anchors.contains(statement.anchor)`,
   rejects zero/already-spent economic nullifiers for TRANSFER/EXIT, and inserts
   that nullifier into a cloned current state before committing a successful
   operation. Each successfully applied operation inserts its resulting tree
   root into the accepted-anchor set. Acceptance of an old note root never
   authorizes ignoring today's nullifier set. [L3]
3. **This separation has mature precedents.** Zcash requires an Orchard anchor
   from an earlier block's final note tree, while independently forbidding repeat
   nullifiers within or across transactions. Its append-only note tree proves
   existence and does not itself prevent double spending. RAILGUN checks seen
   root history and proof context, then rejects and records current nullifiers.
   Adapt that separation; do not import either system's consensus or custody.
   These sources do not prove this Kaspa composition sound. [Z1], [R1]
4. **The existing packet already batches private payments.** `PAYMENT` accepts
   a sequence of CREDIT/TRANSFER operations and calls the same Ledger on each.
   Withdrawal modes accept EXIT/RECOVER instead. The current adapter bounds a
   packet to 32 operations and eight native outputs; these are application
   bounds, not claims about universal L1 capacity. Sequential dependent payments
   must still verify against the successive authenticated states. [L1]
5. **Kaspa transaction ID excludes proof-witness bytes.** At the pinned upstream,
   v0 ID encoding excludes signature scripts and mass commitments. For v1, the
   ID combines the payload digest with a body digest that excludes signature
   scripts and mass commitments. The final v1 ID still commits to the payload;
   it also commits to body fields including predecessor, sequence and outputs.
   `tx.hash()` is a separate full-transaction hash. Our existing `finish()`
   asserts that replacing the proof witness leaves `tx.id()` unchanged and then
   runs native Full validation. [K1], [L4]
6. **A proof cannot substitute for installing its successor.** Toccata's inline-ZK
   description requires the expected program/current old and new commitments,
   as well as checking that actual native outputs install the proven successor.
   Neither a planned ID nor a valid proof for another predecessor discharges
   these requirements. [K2]

## Queue and admission design inference

These are proposed application scheduling rules derived from the facts above,
not an L1 ordering guarantee or a mature protocol's ready-made queue design.

1. **Freeze the work item.** Give the admitted withdrawal a stable identity and
   arrival sequence. Retain its immutable intent, exact original owner-proof
   bytes and proof-byte digest. Keep it as the oldest pending item while proving;
   retrying after a stale bank must not silently append it behind newer requests.
   Changes to payout, amount, cohort, cap or configuration require fresh consent.
2. **Separate submitted, projected and applied state.** New requests can enter a
   queue while the current receipt is being proved. Validate their syntax and
   authorization without declaring a projection settled. Keep speculative tree,
   notes, nullifiers, reserve and parent references separate from applied state.
   Never acknowledge a payout or spendable accepted note merely because the
   coordinator constructed it. Current nullifier and anchor checks run again at
   actual execution. [L1], [L3]
3. **Public pending children are possible, with explicit dependencies.** Once
   the parent's ID-bearing body and payload are fixed, its native outpoint can
   be computed before the parent proof exists. An actor can prepare a child
   against that public projection without revealing wallet secrets. This follows
   from witness exclusion; it does not prove the parent will succeed. Apply the
   child only after the real parent's complete receipt and native Full validation
   pass in the offline applied history. Live settlement additionally requires
   real chain acceptance and reorg handling. A failed/replaced parent invalidates
   descendants that depend on its outpoint, notes or unaccepted anchor; rebuild
   those dependencies instead of treating planned state as accepted. [K1], [L3], [L4]
4. **Retry the oldest item against the real winner.** If another actor's valid
   update wins first, authenticate and apply that update, retain the withdrawal's
   original priority, recheck its accepted anchor/current claims/cap, and prove
   a fresh exact transition. The reusable consent survives only while its
   predicates remain true. A spent cohort note or removed anchor must refuse;
   queue position cannot override authorization. [L1]–[L3]
5. **Drain compatible payments afterward.** Batch waiting CREDIT/TRANSFER
   operations with the existing `PAYMENT` mode, retaining dependencies and
   deterministic order. Do not combine EXIT and TRANSFER by changing packet
   semantics. Batching is a candidate to reduce receipts/native fees; measure
   complete costs, discarded proving and queue delay before claiming savings.

This scheduling applies only to cooperating arrivals. No administrator reserves
the bank, no new key blocks independent exits, and no operator promise makes a
conflicting outpoint spend valid. Another independent accepted update can force
another fresh receipt at any time. An attacker can therefore still contest the
bank; a finite successful burst does not demonstrate sustained or adversarial
liveness. The optional released consent also retains ADR-0111's longer execution
window: whoever holds the complete proof set can execute it while valid.

## What the next experiment can establish

- Start from a frozen, genuine private-payment/withdrawal workload; use the
  existing wallet proofs, application image and native Full validator. Record
  one real competing accepted payment during outer proving, an unchanged
  original withdrawal work item/consent digest across retry, and actual queued
  arrivals. Precomputed or mocked arrivals cannot establish those observations.
- Require an old real receipt transplanted into a changed current native
  statement to fail **cryptographically**. The existing replay control demands
  `ZkIntegrity` and `Groth16 verification failed`; a host stale-outpoint error,
  malformed packet or insufficient resource limit is a different failure. Keep
  changed effect/payload, current spentness, successor and accounting controls.
  [L2]
- Keep public replay separate from private wallet execution. Independent wallet
  processes can demonstrate that the coordinator does not read their keys;
  processes on one machine are not independent people or network anonymity.
  Retain the complete observer view, amount/timing/contact facts and later owner
  disclosures. Fewer consent messages are not a larger privacy score.
- The selected wallet profile has depth four: at most **16 appended note
  commitments**. Spending a note does not delete its historical leaf. A finite
  burst that fits this tree cannot qualify unbounded sustained traffic, tree
  rollover, pruning or production capacity. Stop rather than silently changing
  the circuit/setup or borrowing another experiment's capacity claim. [L5]
- Reconcile integer-sompi principal, fees, allowance refunds and liabilities
  through all later cashouts. Count abandoned outer-proof work and waiting time
  separately; supplied-UTXO quotes are not paid chain fees. The unchanged
  complete-cost/privacy targets remain gates, not assumptions.
- **Testnet readiness is conditional.** No automatic funded trial follows from
  a source review or passing prefix. If offline safety, declared privacy or full
  cost gates fail, retain that result and reassess the contribution before a
  funded trial. A testnet candidate still needs the entire real terminal payout
  and confirmation rehearsal required by current AGENTS.md. No real funds or
  mainnet action is authorized by this note.

## Current upstream heads and reuse

The nine official default heads were resolved read-only through GitHub's commit
API at **2026-11-06 10:33:58 UTC**. All match the preceding source review. The
decisive native ID, inline-ZK, historical-anchor and current-nullifier sources
were reread at exact pins. Unchanged heads do not mean a fresh audit of all files,
deployed versions or complete protocols. The preceding review retains the wider
five-protocol comparison and exact additional file links.

| Upstream / exact head | Reuse or adapt | Exclude |
| --- | --- | --- |
| Kaspa docs `0ac77d043a802fc8196abfd5812ac2afbd97a2b9` [K2] | Exact proof/program/successor binding | New verifier/output rules |
| rusty-kaspa `4863866fce8439d0305b410fc4d802e7261d54d0` [K1] | Current native transaction ID and Full validation | Consensus patches or assumed chain acceptance |
| vprogs `f9b84a863a7c7c20586a9cf947550475e894f72e` [V1] | Ordered authenticated execution references | Requiring its evolving runtime for this queue |
| kaspanet/research `c923faca11a49148fa7d912d27ce00197a5c5a4a` [V2] | State/order/accounting research references | Treating the model as deployed infrastructure |
| Orchard `616a669df8c9a59c33d47064d3ce04b25d026b2e` [O1], protocol [Z1] | Historical membership plus current nullifiers | Orchard consensus or cached transition validity |
| Aztec `c03bf6c776bcef428e9247fff8a5c385ab7ae994` [A1] | Separate user-local private authorization and execution checks | Its L2/sequencer/PXE runtime |
| RAILGUN `36bcf5ed7cf94bfafb6e1a303e1832c769c16780` [R1] | Seen roots, bound proof context, current nullification | EVM custody/admin/token assumptions |
| Monero `b14fae7bca4099cea56205e44c1005602834b7bd` [M1] | Current spent-image checks | Native RingCT/CLSAG consensus and decoy assumptions |
| Litecoin `ec1b6489a900d09cf5991e220dce089c77a232a2` [W1] | Current unspent inputs and supply/peg-out accounting | MWEB consensus/confidential outputs/maturity rules |

None supplies hidden ordinary Kaspa output amounts, independent-user evidence,
or a permissionless global queue without the current-bank conflict. Reuse these
component lessons within the optional shared-batching contribution; do not infer
a superior complete financial-privacy architecture from smoother scheduling.

## Primary references

[K1]: https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/consensus/core/src/hashing/tx.rs#L20-L237
[K2]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx#L25-L70
[V1]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md
[V2]: https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/vProgs/main.tex
[Z1]: https://github.com/zcash/zips/blob/ff594de6e95bb9e9e7d2ace09510281531c30447/protocol/protocol.tex#L4322-L4402
[O1]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/bundle.rs
[A1]: https://github.com/AztecProtocol/aztec-packages/blob/c03bf6c776bcef428e9247fff8a5c385ab7ae994/docs/docs-developers/docs/foundational-topics/transactions.md#L33-L61
[R1]: https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/RailgunLogic.sol#L420-L509
[M1]: https://github.com/monero-project/monero/blob/b14fae7bca4099cea56205e44c1005602834b7bd/src/cryptonote_core/blockchain.cpp#L2853-L2880
[W1]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/consensus.md#L73-L107
[L1]: ../../poc/reusable-withdrawal-approvals/common/src/lib.rs
[L2]: ../../poc/reusable-withdrawal-approvals/host/src/replay.rs
[L3]: ../../poc/private-note-wallet/src/ledger.rs
[L4]: ../../poc/batched-payment-costs/host/src/bench.rs
[L5]: ../../poc/private-note-wallet/src/protocol.rs
