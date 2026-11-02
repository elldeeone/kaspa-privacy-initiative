# RFC-0004: Native-KAS private payments and the transparent-exit boundary

**Status:** Open — proposed architecture recommendation, not accepted

**Date:** 2026-11-02

## Decision in plain language

For current Kaspa, use a **wallet-local shielded note ledger with a direct
inline-ZK covenant settlement path** as the minimum-trust reference
architecture. Wallets keep spending secrets, construct their own proofs and can
spend or exit from the latest accepted state without an MPC committee or
privileged withdrawal signature. Replaceable relayers, provers and archives may
improve liveness, but receive no spending authority.

This architecture supports confidential payments and permissionless immediate
withdrawal. It does **not** make an ordinary transparent KAS withdrawal private
against an observer who validly knows the output owner. Current consensus puts
an explicit `u64` amount and script public key in every ordinary native output.

No current application-only design meets the stronger guarantee that every
ordinary transparent exit conceals its amount or ownership under the declared
known-owner/full-drainage observer. That guarantee requires either:

1. a consensus-native confidential or shielded KAS output/value-pool design; or
2. an explicit claim change acknowledging that a completed transparent exit is
   a public boundary.

The first option is still native KAS, not a new token. It is also a consensus
proposal, not a covenant or vProgs configuration change.

## Fixed requirements

- Native KAS is the backing asset; no new privacy token.
- Spending and recovery secrets remain in user wallets.
- No fixed MPC/server committee has spending authority.
- No privileged withdrawal signature or administrative rescue withdrawal.
- No forced delay, lock or requirement to leave user principal in the pool.
- Any user can withdraw a valid accepted claim independently.
- All [security invariants](../../SECURITY-INVARIANTS.md) remain unchanged.
- The known-owner/full-drainage observer remains in scope.
- Earlier failed attempts' retained test balances remain a separate open item;
  this design performs and authorizes no funding or recovery action.

## What the completed run proves—and does not prove

The corrected attempt-06 assessment is the starting evidence, not a universal
anonymity claim:

- **Demonstrated:** all five ordinary native payouts completed and all user
  principal/liabilities drained to zero.
- **Demonstrated:** with the experiment's owner mappings, three-operation graph
  and full transparent withdrawals, two complete gross payment histories
  survived. `B -> M = 20,000,000` sompi was common to both; `A -> M` remained
  either 30,000,000 or 40,000,000 sompi.
- **Demonstrated:** reserve ancestry exposed each payout's deposit-funding
  origin. The synthetic common-reserve mitigation changed origin candidates
  from one to two but left payment histories at `2 -> 2`, so it was rejected as
  a direct-payment fix.
- **Not demonstrated:** that every ordinary workload uniquely reconstructs
  payments, or that every chain observer has the auxiliary owner mappings.
- **Counterexample established:** a universal claim that transparent full
  drainage always hides net balances is false under the declared observer.

Conservation does not always reveal the full gross history. It reveals net
boundary balances when the observer knows enough owners and flows; additional
unknown activity can leave many histories. The architecture must nevertheless
survive the fully constrained case if it claims privacy against that case.

Two properties must not be conflated. A confidential-payment system can hide
on-domain sender, recipient and amount while guaranteeing every valid holder an
independent right to exit. It cannot also promise that exercising that right
through an ordinary transparent output erases the public amount, owner mapping
or all correlations with prior activity. Exit liveness and exit privacy are
separate claims.

## Compact comparison

| Direction | Buildable with current Kaspa? | Independent immediate exit | What remains public | Recommendation |
|---|---|---|---|---|
| Wallet-local notes + one inline-ZK state covenant | Yes as a proposed adaptation of current primitives; production qualification remains open | Yes from the latest accepted state, subject to ordinary UTXO contention and proof refresh | Deposits, nullifiers/commitments, state transitions, fees, timing, and ordinary exit amount/script | **Current reference** |
| Based app/vProgs carrying the same note state | Prototype/runtime components exist; complete private semantics and recovery remain application work | Only if a valid user can advance or exit from the latest settled state without the default operator | Lane activity, settlement cadence, proofs, permission outputs, ordinary exit amount/script | Defer until shared-state throughput requires it |
| Consensus-native confidential KAS UTXOs | No current output type or validation rule | Could be, with wallet-held keys and consensus validation | Ownership may remain visible if scripts are mapped; amounts can be hidden | Stronger amount-privacy research direction |
| Consensus-native shielded KAS pool | No current output type/value-pool rules | Could be, with wallet-held notes/nullifiers and public recovery data | Pool crossings, timing, fees and later transparentization | Strongest established pattern; consensus change |

No row makes a later ordinary transparent output private by assertion. A fresh
address or relay is useful hygiene but does not defeat an observer already given
a valid owner mapping.

## Recommended current-Kaspa transaction flow

### 1. Native deposit

```text
ordinary KAS input
-> covenant-controlled reserve
-> one proof-bound encrypted recipient note
-> successor shielded-state commitment
```

Public: deposit amount, reserve outpoint/script, fee input, transaction timing,
note commitment/ciphertext and successor state commitment.

Private: recipient key, note opening, future spending secret and any private
change semantics. The proof binds one accepted deposit to one credit and rejects
replay.

### 2. Confidential transfer and re-spend

The spending wallet locally proves:

- membership under an allowed note anchor;
- spend authority and a correctly derived nullifier;
- current spent-state binding and nullifier freshness;
- integer-sompi range and exact input/output/fee conservation;
- recipient-spendable output commitments and authenticated ciphertexts; and
- the exact successor commitment and protocol/version domain.

The transaction consumes the current state covenant and creates its successor.
The chain sees the nullifier, output commitments, ciphertexts, proof, state
change, fee sponsor and timing. It does not receive note openings, recipient
keys or private amounts. The recipient scans authenticated public updates and
reconstructs the note locally before accepting it.

This singleton state is sequential. A competing accepted transition can stale a
proof and require refresh; that is a liveness/throughput cost, not permission for
weaker root or double-spend checks. It imposes no protocol delay or withdrawal
lock. “Immediate” here means eligible without a protocol timelock or operator
approval, not guaranteed mempool inclusion or freedom from stale-state retries.

### 3. Independent native exit

```text
wallet-held note + current authenticated public state
-> wallet-local exit proof
-> direct state-covenant transition
-> exact reserve debit + ordinary native payout
```

The covenant, not an operator signature, verifies the proof and binds the
successor state, consumed nullifier, reserve input/change, payout script/value
and explicit fee. A replaceable relay may submit the complete transaction; it
cannot redirect or enlarge the payout. The user can withdraw the entire valid
claim immediately. State rent remains separate from user principal.

Public at the completed boundary: payout amount, destination script, reserve
ancestry, fee inputs, timing and transaction shape. These public fields can
reveal the user's net balance when combined with valid owner mappings. This is
the residual privacy boundary, not a proving failure.

## Removing avoidable links

These measures improve ordinary privacy without changing the transparent-exit
limit:

- **Ownership and delivery:** encrypt every note to a recipient viewing key;
  publish ciphertexts in authenticated state history; wallets scan locally
  rather than query selected notes.
- **Fee funding:** accept permissionless relayers or one-time sponsors; bind any
  shielded fee/reimbursement into the proof and covenant effects. Never require
  the user's long-lived public wallet as the protocol fee input.
- **Reserve origin:** select pooled reserve inputs independently of deposit
  identity where safe. This can remove exact funding ancestry but, as the
  retained failed mitigation showed, does not hide full-drainage net balances.
- **Construction metadata:** use generic wallet artifacts, randomized output
  ordering and no semantic role labels in publishable records.
- **Network origin:** allow self-broadcast and replaceable relays over
  privacy-preserving transport. Treat network anonymity as a separate,
  unproven property; a relay is not cryptographic anonymity.

None requires fixed MPC. None justifies cover deposits, forced waiting or
retaining user principal.

## Why vProgs is not the baseline requirement

Official Kaspa guidance makes state layout the deciding question. Inline ZK is
the current fit for one covenant action and one hidden transition. A based app
becomes justified when many users must mutate one shared state, operations need
batching, exits derive from a span of activity, or lane-local ordering is
required. [Decision guide][K-DECISION] and [inline-ZK boundary][K-INLINE].
KIP-21 supplies authenticated lane ordering and activity-proportional proving;
it does not define private notes or confidential native outputs. [KIP-21][K-LANES].

The note/nullifier state is logically shared, so throughput may eventually
justify a based app. It does not follow that vProgs is required for note
confidentiality or spend authorization. The current vProgs repository is
explicitly early/prototype, and its withdrawal path uses a public `u64` amount,
public destination and permission script that checks the native output amount
and script. [Prototype status][V-README], [withdraw action][V-WITHDRAW],
[permission checks][V-PERMISSION].

If adopted later, an executor/prover is a liveness dependency only when:

- wallets retain all spending authority and private witnesses;
- L1 verifies the exact state program, roots, nullifiers and effects;
- public/replicated data is enough for independent state reconstruction; and
- a user can advance or exit a valid **settled** claim without the default
  executor.

Pending unproved operations are not spendable settled claims. A batch cadence
cannot be advertised as an unrestricted immediate exit from pending state.

## Stronger settlement needed to break the observed balance attack

### Exact missing current capability

Current consensus defines an ordinary output as public
`TransactionOutput { value: u64, script_public_key, covenant }`, validates every
value/range and publicly sums input/output values. [Output type][K-OUTPUT],
[value checks][K-VALUE] and [input/output balance][K-CONSERVE]. Current proof tags verify Groth16 or RISC Zero
statements; they do not replace that native output representation.
[Verifier tags][K-TAGS].

Therefore an encrypted application state or witness cannot hide the amount of
an ordinary native payout. To hide it, consensus must recognize and validate a
different native value representation. This conclusion follows from current
consensus serialization and validation, not from the limitations of this PoC.

### Established mechanisms to adapt, not invent

**Confidential native UTXO.** MWEB demonstrates native confidential outputs
with Pedersen commitments, range proofs, commitment balance rules, encrypted
values and stealth output keys. Its peg-outs deliberately publish exact amount
and script and add maturity, so that boundary is rejected for this requirement.
[MWEB consensus][M-CONSENSUS], [kernel peg-outs][M-KERNELS], [stealth
outputs][M-STEALTH].

For Kaspa, hiding the full-drainage arithmetic would require the reserve and
payout sides to use confidential commitments under consensus rules; a public
reserve change would reveal the committed payout by subtraction. Ownership
would still be linkable if a valid observer maps the output key.

**Native shielded KAS pool.** Orchard demonstrates wallet-held notes, encrypted
recipients, note commitments, nullifiers, homomorphic value commitments and a
binding signature that enforces transaction balance. [Actions][O-ACTIONS],
[recipient encryption][O-ENCRYPT], [balance rule][O-BALANCE]. A native Kaspa
adaptation would need consensus-recognized commitments/ciphertexts/nullifiers,
proof and binding rules, authenticated scanning data and wallet recovery.

This removes the observed attack inputs: no public per-owner payout `u64` and,
for a shielded note, no public recipient script. Conservation remains verified
over commitments/proofs instead of exposed values. The known-owner balance
enumerator can no longer assign terminal amounts it cannot observe.

The limitation remains explicit: Zcash states that transfers between transparent
and shielded pools reveal the transferred amount, and MWEB peg-outs publish
amount and script. [Zcash boundary][O-BOUNDARY], [MWEB peg-outs][M-KERNELS]. A
user staying in a consensus-native shielded KAS domain has native KAS, but has
not converted it into an ordinary transparent output. Later transparentization
re-exposes that boundary.

### Required consensus work

A stronger Kaspa design needs a reviewed KIP-level specification for at least:

- native confidential/shielded output encoding and transaction hashing;
- value commitments, ranges, balance, fees and supply accounting;
- recipient encryption or stealth/shielded ownership;
- spend authorization, nullifiers or confidential-UTXO spentness;
- proof-system/verifier integration and version migration;
- mempool, block, UTXO-set and pruning/recovery rules; and
- transparent-to-private and private-to-transparent boundary accounting.

The current Orchard Halo 2 construction is not accepted by Kaspa's two verifier
tags. Adapting its relation to Groth16/RISC Zero or adding another consensus
verifier is unresolved specialist work, not a claimed port.

## Property classification

| Property | Classification | Evidence / status |
|---|---|---|
| Ordinary KAS output amount/script are public | Source-supported | Rusty Kaspa output type and value validation at current head |
| Toccata can verify hidden transitions and bind successor outputs | Source-supported | Official inline-ZK guide and current verifier dispatch |
| Actual proof-authorized native payouts can complete | Demonstrated in our run | Attempt 06; bounded TN10 evidence only |
| Known-owner full drainage leaks net payment constraints | Demonstrated in our run | Corrected sealed observer; two retained gross histories |
| Common reserve breaks direct-payment inference | Rejected by measurement | Funding origin improved; histories stayed `2 -> 2` |
| Wallet-local note/nullifier/conservation relation | Proposed adaptation | Orchard-style design using current Kaspa verifier/covenant boundary |
| Encrypted delivery and local scanning | Proposed adaptation | Orchard pattern; Kaspa archival availability remains unresolved |
| Relayer-funded fees remove user-wallet linkage | Proposed adaptation | Requires exact effect binding and a practical relay market |
| Singleton-state contention is acceptable | Unresolved | Safety can fail closed; useful throughput and retry privacy unknown |
| vProgs supplies no-trust immediate independent exits | Unresolved/currently unsupported | Prototype path requires proved settlement and public permission payout |
| Consensus-native confidential/shielded KAS | Proposed consensus direction | Exact current output/validation capability is missing |
| Every ordinary transparent exit conceals its past | No candidate meets | Boundary amount/script are public; valid owner mapping remains valid |

## Reuse, adapt and reject

- **Reuse as design:** Orchard notes, separated spending/viewing authority,
  recipient encryption, commitment/nullifier relations and transaction balance.
- **Adapt:** integer sompi, Kaspa domain/version binding, accepted state roots,
  current verifier ABI, covenant-bound reserve/payout effects and Kaspa recovery
  after pruning.
- **Reuse selectively:** MWEB commitment/range/stealth rules as evidence for a
  native confidential output design.
- **Reject:** MWEB's public, maturity-delayed peg-out as the requested private
  immediate exit.
- **Reject:** fresh addresses, relays, reserve merging or larger labels as a
  solution to valid known-owner/full-drainage amount knowledge.
- **Reject:** fixed MPC, privileged signatures, retained user balances, cover
  value and invented cryptographic primitives.

## Security and trust boundary

The current recommendation preserves I-1 through I-16. Proofs and covenants
must bind value conservation, authorization, nullifier uniqueness, current
state, reserve continuation, payout effects, fees and protocol version. A
missing prover, relay or archive may stop progress but cannot authorize theft.

Recovery requires wallet secrets plus authenticated commitments, nullifiers,
ciphertexts, accepted ordering, witnesses/snapshots, verifier artifacts and
independent software. A state root alone is not recoverable data. Public data
availability and singleton contention remain liveness risks, not hidden
custodians.

## Smallest next engineering step

After this RFC is reviewed, specify—without a funded trial—the exact direct
inline-ZK transition ABI for the current-Kaspa reference flow. It must cover
deposit, private transfer/re-spend and full direct exit from the latest accepted
state, including relayer fees and recovery inputs.

**Falsifiable acceptance condition:** from only one user's wallet backup,
authenticated public history and pinned public software, a clean process can
construct and fully validate a transaction that spends the user's entire valid
claim to an ordinary KAS output with no executor/MPC/operator signature and no
timelock. Wrong root, duplicate nullifier, unauthorized note, overflow,
under/overpayment, diverted payout and extra-output variants must reject. The
report must also show the payout amount/script as public and must not claim that
this step fixes the known-owner/full-drainage leak.

If the required property instead includes hiding that completed exit, stop the
application implementation and produce a separate KIP-style confidential or
shielded native-output specification. Acceptance then requires identifying
every affected consensus representation and balance rule; an application proof
alone is insufficient.

## Outcome, when known

Open. No ADR is created until review accepts or rejects this recommendation.
This RFC authorizes no implementation, funded trial, broadcast, proof campaign,
runtime deployment, recovery action, commit or push. MPC remains paused.

## Current source pins

- Rusty Kaspa `4edcbbccb449f84832afb1ca157904b35f37d006`
- Kaspa docs `0ac77d043a802fc8196abfd5812ac2afbd97a2b9`
- Kaspa KIPs `d832dbd89347dcb16d3d83bf6755b081714cbcb2`
- vProgs `f9b84a863a7c7c20586a9cf947550475e894f72e`
- Kaspa research `c923faca11a49148fa7d912d27ce00197a5c5a4a`
- Orchard `616a669df8c9a59c33d47064d3ce04b25d026b2e`
- Zcash protocol `ff594de6e95bb9e9e7d2ace09510281531c30447`
- Litecoin `ec1b6489a900d09cf5991e220dce089c77a232a2`

[K-DECISION]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/decision-guide.mdx#L6-L40
[K-INLINE]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx#L85-L127
[K-OUTPUT]: https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/core/src/tx.rs#L176-L190
[K-VALUE]: https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs#L147-L169
[K-CONSERVE]: https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs#L116-L124
[K-TAGS]: https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/zk_precompiles/tags.rs#L5-L20
[K-LANES]: https://github.com/kaspanet/kips/blob/d832dbd89347dcb16d3d83bf6755b081714cbcb2/kip-0021.md#L13-L50
[V-README]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md#L1-L7
[V-WITHDRAW]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/runtime-processor/src/action/withdraw.rs#L9-L64
[V-PERMISSION]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/permission_script.rs#L270-L290
[O-ACTIONS]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/book/src/design/actions.md#L1-L19
[O-ENCRYPT]: https://github.com/zcash/zips/blob/ff594de6e95bb9e9e7d2ace09510281531c30447/protocol/protocol.tex#L6691-L6727
[O-BALANCE]: https://github.com/zcash/zips/blob/ff594de6e95bb9e9e7d2ace09510281531c30447/protocol/protocol.tex#L7413-L7522
[O-BOUNDARY]: https://github.com/zcash/zips/blob/ff594de6e95bb9e9e7d2ace09510281531c30447/protocol/protocol.tex#L3240-L3256
[M-CONSENSUS]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/consensus.md
[M-KERNELS]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/kernels.md#L31-L36
[M-STEALTH]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/stealth-addresses.md
