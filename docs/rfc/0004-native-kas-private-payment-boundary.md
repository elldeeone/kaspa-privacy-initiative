# RFC-0004: Native-KAS private payments and the transparent-exit boundary

**Status:** Open — current-Kaspa reference and proposed native shielded-value consensus design; not accepted

**Date:** 2026-11-02; extended 2026-11-03 using consolidated prior research and refreshed primary sources.

## Decision in plain language

The 3 November extension develops a **consensus-native shielded-value proposal**
for review. Its [capability table](#capability-and-assumption-table),
[accounting](#value-conservation-public-balance-and-supply),
[prior-learning traceability](#prior-learning-traceability) and
[review questions](#review-questions-and-stop-conditions) distinguish supported
facts, proposed rules and unresolved work. It does not select a production
architecture, amend an invariant or claim the financial-privacy target is met.

For current Kaspa, use a **wallet-local shielded note ledger with a direct
inline-ZK covenant settlement path** as the minimum-trust reference
architecture. Wallets keep spending secrets, construct their own proofs and can
spend or exit from the latest accepted state without an MPC committee or
privileged withdrawal signature. Replaceable relayers, provers and archives may
improve liveness, but receive no spending authority.

This reference targets confidential payments and permissionless immediate
withdrawal; complete qualification remains open. It does **not** make an ordinary
transparent KAS withdrawal private
against an observer who validly knows the output owner. Current consensus puts
an explicit `u64` amount and script public key in every ordinary native output.

No design conceals the amount/script of an ordinary output after publishing
it. A consensus-native confidential or shielded value representation could
provide hidden native ownership **while value stays in that representation**.
Later transparentization remains public. Alternatively, accepting ordinary
transparent exits as outside a stronger claim requires an explicit owner
decision. This proposal makes neither a silent claim change nor a privacy pass.
The new representation would still be native KAS, not a new token; it requires
consensus rules rather than a covenant/vProgs configuration change.

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

In a confidential-UTXO design, a public reserve change, known fees and other
known flows reveal the aggregate confidential outflow by subtraction. With only
one unknown payout, that determines its amount; with several, individual amounts
depend on further information. Confidential reserve/value commitments remove
that explicit observation but do not establish full-drainage privacy. Ownership
can still be linked if a valid observer maps the output key.

**Native shielded KAS pool.** Orchard demonstrates wallet-held notes, encrypted
recipients, note commitments, nullifiers, homomorphic value commitments and a
binding signature that enforces transaction balance. [Actions][O-ACTIONS],
[recipient encryption][O-ENCRYPT], [balance rule][O-BALANCE]. A native Kaspa
adaptation would need consensus-recognized commitments/ciphertexts/nullifiers,
proof and binding rules, authenticated scanning data and wallet recovery.

This removes the explicit ordinary per-owner payout fields used in that run:
no payout `u64` and, for a shielded note, no public recipient script. Conservation
would instead be verified over commitments/proofs. Public aggregate `b`/`B`,
isolated activity and legitimate counterparty disclosures may still imply
amounts or relationships. Absence of an explicit amount field is not evidence
that an observer cannot infer it or that the required privacy score is met.

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

## Reviewable native shielded-value proposal

**Classification:** proposed consensus design for specialist review. This is a
requirements-level specification, not an allocated transaction version, final
cryptographic relation, accepted KIP, implemented capability or privacy pass.
The [Kaspa source refresh](../../research/native-kas-consensus-boundary-2026-11-03.md)
and [mature-protocol review](../../research/native-kas-shielded-value-sources-2026-11-03.md)
separate source facts from the design choices below. Public issues
[#1](https://github.com/olafweller/kaspa-privacy-initiative/issues/1),
[#3](https://github.com/olafweller/kaspa-privacy-initiative/issues/3),
[#4–#8](https://github.com/olafweller/kaspa-privacy-initiative/issues/6),
[#10–#13](https://github.com/olafweller/kaspa-privacy-initiative/issues/10),
[#19](https://github.com/olafweller/kaspa-privacy-initiative/issues/19) and
[#23](https://github.com/olafweller/kaspa-privacy-initiative/issues/23)
remain open; this proposal supplies review inputs rather than closing them.

### Candidate, asset and authority

Use one **consensus-recognized shielded native-KAS value pool** as the reference
candidate for reviewing the stronger capability. Its notes are a native value
representation enforced by consensus, not a new token, ERC-20, operator IOU or
separate issued asset. A transparent input moves existing KAS value into the
pool; a transparent output moves value out. There is no administrator mint or
withdrawal key and no development-treasury access to pool value.

The native pool has no application reserve UTXO that every transfer must spend.
Consensus maintains its accounting and spentness directly. This removes that
particular singleton-outpoint race, not shared-state ordering, block capacity,
proof costs, censorship or fee competition. vProgs is not a prerequisite for
this proposed consensus path. A later application/runtime must justify its own
batching or shared-state requirement and preserve independent authorization.

A holder can receive and spend a shielded native note without transparentizing
it. That holder has not drained all value into ordinary public KAS. Independent
native ownership, exit from an application and transparent withdrawal are
separate requirements. If the fixed requirement means every owner must both
transparentize fully and conceal that known public boundary, this candidate
cannot meet it. Review question Q1 keeps that incompatibility explicit; the
proposal does not impose a waiting period or silently redefine an exit.

A confidential-UTXO alternative remains credible for hiding amounts, using
established commitment/range/balance rules. It exposes a different spend graph
and may retain mapped output ownership. The native note-pool candidate is
preferred **for this review** because hidden membership and recipient discovery
address additional relationship channels. No production choice is accepted.

### Capability and assumption table

| Requirement | Current Kaspa reference | Proposed native pool | Still unresolved |
| --- | --- | --- | --- |
| Native asset/backing | Covenant holds ordinary KAS against private claims. | Consensus recognizes pool KAS once, with public aggregate balance and hidden ownership. | Inductive supply/backing argument and I-1 mapping. |
| Hidden internal amount/recipient | Encrypted note ledger and exact proof/settlement bindings. | Hidden notes, commitments, nullifiers and encrypted discovery records. | Concrete reviewed primitives/relation; effective privacy. |
| Ordinary transparent exit | Output amount/script are public. | Still public when chosen. | No proposal conceals already published fields. |
| Hidden native ownership after payment | Application-private claims remain inside a transparent reserve. | Consensus-native shielded notes; no per-owner public payout amount/script required. | Does not by itself pass the frozen financial-privacy target. |
| Independent spending/exit | Requires accepted state, exact parameters/history and contention handling. | User's authority plus authenticated native state, available note data and compatible public artifacts. | Complete service-loss/fee/inclusion/retention model. |
| Data after pruning | Ordinary UTXO/pruning data is insufficient to invent missing ciphertexts. | Additional authenticated shielded state and recovery records. | Bootstrap/retention specification and sustainable cost. |
| Practical fees/throughput | Retained matched benchmark failed; specialized offline layout differed. | Public fees and bounded new verification/state work. | Actual mass, full lifecycle cost and useful concurrency. |
| Quantum resistance | Existing proof and ownership layers have different properties. | Unselected; explicitly versioned profile. | Proof, signatures, encryption and migration inventory, not one PQ label. |

### Native state and bootstrap

Proposed state is keyed by immutable network/genesis and native pool identity:

| Component | Required meaning |
| --- | --- |
| `B` | Public integer-sompi native value reserved in this consensus domain, bounded by `MAX_SOMPI`. |
| `C`, `n` | Ordered note-commitment accumulator/frontier and append count, including protocol-defined padding/multiplicity. |
| `N` | Current accepted nullifier set, or an authenticated representation with the same deterministic membership/uniqueness semantics. |
| `A` | Consensus-defined accepted note anchors and their branch/order context; not arbitrary caller-supplied roots. |
| `D` | Authenticated discovery/recovery record commitments and exact accepted order/positions. |
| `P` | Immutable creation-domain and permitted proof/encoding profiles, with explicit activation/migration rules. |

Start an optional newly activated pool with `B=0`, empty spentness and a defined
empty commitment state. Coinbase issuance into it is outside the first profile;
coinbase remains on its existing reward path. No existing covenant reserve,
wallet note, development setup, verification key or discarded proving key is
converted automatically. A future migration must authorize the actual old spend,
remove its old liability exactly once and prove the corresponding native credit.

`B` is **not also an ordinary reserve UTXO**. Counting both as backing or native
supply would duplicate the same KAS. Existing application pools and their pending
exit liabilities remain separate domains. Adapting I-1 to consensus-reserved
native value and handling a boundary transaction under I-2 require explicit
review; the unchanged invariant file is not reinterpreted by this table.

### Proposed transaction bundle and encoding obligations

Keep ordinary KAS inputs/outputs under their existing rules. A new transaction
version/profile introduces a native shielded bundle through consensus encoding,
not a payload interpreted only by an application. The proposed logical fields
are:

| Field | Proposed encoding/meaning | Review boundary |
| --- | --- | --- |
| Transaction/profile discriminator | Consensus-allocated transaction version plus `u16` bundle version; fixed little-endian integer encoding. | Numeric allocations are unassigned; old formats keep their old rules. |
| Network, pool and creation domain | Explicit identities bound to the proof/signing statement and note derivation. | Exact digest construction must reuse reviewed primitives. |
| Accepted anchor/context | Exact commitment root plus the context needed to disambiguate accepted history. | Anchor validity/retention window needs consensus specification. |
| Public `b` | Canonical signed `i64` little-endian balance, bounded to `[-MAX_SOMPI, MAX_SOMPI]`; positive means value leaves the shielded pool. | Reject the signed minimum/out-of-range values before negation or narrowing. |
| Public `F` | `u64` little-endian network fee, bounded to `[0, MAX_SOMPI]`; it must equal the contextual balance equation. | A public fee is deliberate; it exposes cost/shape metadata. |
| Spends | Bounded length-prefixed vector of nullifiers, spend-authorization material and profile-required public fields. | Final count type/limits, dummy-action rules and point/scalar lengths await profile review. |
| Outputs | Ordered commitments, ephemeral delivery keys, ciphertexts and optional profile-defined recovery data. | No public recipient script/value inside a shielded note; exact encryption/framing is unselected. |
| Proof and binding authorization | Exact profile/key or image identity, public statement and effect-binding authorization. | No witness-selected verifier or assumption-bearing development receipt. |

Every length and cryptographic encoding must be canonical, fully consumed and
bounded before expensive allocation/verification. Unknown versions, alternate
encodings, wrong arity, trailing data, invalid field/group encodings,
wrong-subgroup points and mismatched vector counts reject at the intended layer.
Reject identity points where the reviewed construction forbids them for that
specific role; a value commitment need not have the same rule as a signing key
or proof element. Final byte offsets,
cryptographic constants, action limits and proof sizes are **not frozen** here;
Q2/Q3 must close them before a runnable protocol profile is proposed.

Define an effects digest covering network/pool/profile, all ordinary input
outpoints and actual output amounts/scripts/covenants, `b`, `F`, anchors,
nullifiers, ordered note commitments, delivery/recovery ciphertexts, lock/sequence
constraints and any other mutable economic effect. Exclude only the proof and
authorization bytes that would create a digest fixed point, under a reviewed
rule. Specify transaction ID, full hash, ordinary signatures and shielded
signatures separately; the existing hash functions are not automatically aware
of new fields. Relay/sponsor mutation is invalid unless the authorization scheme
explicitly permits and constrains that exact modification.

With no shielded bundle, `b=0` and no shielded state changes are permitted; old
ordinary transaction rules still apply. An old transaction version cannot gain
new native accounting authority by carrying a lookalike payload. Bind selected
compute/storage commitments and other mutable economic limits under the reviewed
effects/signature rules as well as checking their consensus validity.

A pure shielded transaction has no ordinary input to satisfy today's
`NoTxInputs` rule. Its new validity path must require an actually authorized
shielded spend, or an ordinary deposit input; a nonempty/dummy bundle alone is
not authorization. Deposit/creation paths still need range, binding and balance
verification. The existing ordinary-input rule remains unchanged for old formats.

### Value conservation, public balance and supply

All values below are **integer sompi**, not field elements or floating values:

- `T_in`, `T_out`: sums of actual ordinary native input/output values.
- `S_in`, `S_out`: private totals of real shielded notes consumed/created.
- `F`: explicit total network fee. Any service payment is separately authorized
  value, not an undisclosed network fee or treasury entitlement.
- `b = S_in - S_out`: public signed shielded balance, positive toward ordinary
  outputs or the network fee.

The **proposed cross-domain** relations are:

```text
S_in + T_in = S_out + T_out + F
T_in + b    = T_out + F
B_next      = B - b
```

Require each real note and each total to be in its selected monetary range,
`0 <= B_next <= MAX_SOMPI`, and all public amounts to obey their existing native
range rules. Use checked wide host arithmetic (`i128`/`u128` as appropriate) and
proved integer/aggregate bounds; equality modulo a curve field alone is
insufficient. No implicit wrapping, absolute-value overflow, negative output,
truncation, floating sompi or unchecked signed-to-unsigned conversion is allowed.

A proof of hidden-note validity plus an established aggregate binding/balance
construction must tie the exact public `b` to those bounded private totals.
Spend authorization binds the effects digest, including payout destinations and
fees. A public pool counter alone cannot rule out counterfeit private claims.
Conservation, note creation, spend authority and spentness are separate obligations.

The following are arithmetic-only illustrations in sompi, **not fee quotes,
valid transaction fixtures or executed proofs**:

| Case | `T_in` | `T_out` | `S_in` | `S_out` | `F` | `b` | Change in `B` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Shield | 101 | 0 | 0 | 100 | 1 | -100 | +100 |
| Private transfer with shielded fee | 0 | 0 | 100 | 99 | 1 | 1 | -1 |
| Partial transparent withdrawal | 0 | 59 | 100 | 40 | 1 | 60 | -60 |
| Full remaining transparent withdrawal | 0 | 39 | 40 | 0 | 1 | 40 | -40 |
| External fee contribution, no pool crossing | 1 | 0 | 100 | 100 | 1 | 0 | 0 |

The [accounting vectors](0004-native-value-accounting-vectors.json) include these
five cases, monetary/zero-fee boundaries, sign/fee/output/pool/range/encoding
negatives and a four-step zero-ending arithmetic sequence. Supplied private
totals in these vectors are not verified notes; passing their arithmetic is not
proof, native acceptance or a new fee/privacy result. Amount strings are decoded
once to exact bounded integers at the JSON boundary.
Run `python3 scripts/check_rfc0004_accounting.py` from the repository root to
repeat this arithmetic-only check; documentation CI runs it as well.

**I-2 is unresolved, not amended.** Its literal current private-transition
equation omits native boundary credits/debits. The archived feasibility branch
already identified a payout-inclusive alternative; that alternative is not
adopted here. The equations above are an explicit candidate generalization for
boundary actions. A purely shielded transfer paying `F` from shielded value
reduces to existing I-2. Deposit/withdrawal classification, native-reserve meaning
under I-1, pending claims and any necessary wording change require a reviewed
ADR and explicit invariant change before implementation. Payout principal must
never be disguised as an allowed fee to make the current text appear satisfied.

For an ordinary accepted non-coinbase transaction, represented native stock
`sum(ordinary UTXO value) + B` changes by `-F`, with every existing native domain
counted once. Feed that exact fee into the existing accepted-fee/reward path;
do not mint it again from `B` or assume the same block pays it. Kaspa's mergeset
reward rules make a naive same-block supply equation inappropriate. Any burns,
other native domains, coinbase changes and activation/migration must be listed
explicitly in a full supply argument. Hidden note totals are not a second supply.

The first profile uses **atomic direct boundary actions**. A note remains a user
claim until an accepted transaction consumes it and installs its authorized
native effects. There is no interval where a failed payout burns a settled
claim. If a later architecture queues exits, the whole unpaid amount remains a
backed liability until paid, and its queue needs separate exact-once accounting.
State rent/treasury balances cannot substitute for user backing.

### Proof, authority and current spentness

A candidate validity statement must establish all of the following together:

1. Every real spend has authenticated membership under an allowed accepted
   anchor, correct network/pool/creation scope and wallet-held spend authority.
2. Its nullifier is correctly derived, not caller-chosen. All published spend
   markers, including padded-slot markers if the profile publishes them, are
   distinct within the transaction and absent from the **current** accepted
   spent set. An unreviewed dummy-marker exception cannot bypass these checks.
   Historical membership does not prove current unspentness.
3. Note values, aggregate sums and fee/boundary arithmetic are bounded integers.
   Output commitments bind the intended spendable notes; the aggregate proof and
   binding authorization agree on the exact `b` and full transaction effects.
4. No malformed padding/dummy input creates credit, bypasses ownership or passes
   a missing-input check. Output multiplicity and note identity follow one
   reviewed construction rather than a mixture of incompatible branch schemes.
5. Exact verifier/key or image, public-input count/order, proof decoding and
   network/profile identity match consensus. New or migrated profiles preserve
   spentness across every mutually accepting version.

Existing Groth16/RISC Zero tags do not accept Orchard Halo2/Pasta proofs as-is.
Candidate review choices are an independently reviewed relation adaptation to a
supported backend, a reviewed wrapper of an established verifier, or a new
consensus verifier. Each adds correctness, setup, memory, cost and upgrade
obligations. No backend, curve, hash instantiation, ceremony or trusted setup is
selected here. Historical development keys are not production parameters.

The versioning rule is substantive: changing only a verifier/profile identifier
must not give an already consumed note a fresh nullifier. Preserve its immutable
creation/spend domain and common spentness, or specify an exact-once authorized
migration that invalidates the old claim. Recovery of old valid notes and public
artifacts must survive a supported upgrade; no administrator rescue or downgrade.
A STARK verifier alone establishes no quantum-resistance claim for ownership
signatures, note encryption, commitments, nullifiers or retained ciphertexts.

### DAG acceptance, conflict resolution and reorgs

The new state transitions must follow Kaspa's authenticated accepted transaction
order, including mergeset conflicts; they cannot use a private service's arrival
order or treat every DAG transaction as accepted. Parallel proof verification is
permitted only with deterministic conflict resolution and state application.

Acceptance atomically validates and installs ordinary UTXO effects, `B_next`,
nullifier insertions, ordered commitment appends, accepted anchors, discovery
records and the one calculated network fee. Two transactions spending the same
note in different DAG blocks cannot both commit, even if they spend no common
ordinary outpoint. Aggregate pool underflow must also be checked in accepted
order, not just against a shared pre-batch counter.

A rejected transaction leaves every component unchanged. Reorg/virtual-state
changes undo and reapply **all** components and fee/acceptance records coherently.
Cached proof validity may avoid repeated cryptography for the same exact
statement; it must not skip current nullifier membership, pool balance, anchor
acceptance or actual transaction-effect checks in a different context. Existing
script-skip/parallel-validation paths need explicit auditing for this new state.

Mempool policy indexes both ordinary input conflicts and shielded nullifiers,
validates profile/size/fee rules, and handles anchors that leave the accepted set.
An obsolete anchor causes witness refresh/reproof or rejection, not acceptance
against a stale fork. Wallets preserve accepted and pending states separately.
Capacity refusal leaves complete state unchanged. No host-supplied root or
synthetic predecessor establishes an initialized native history.

### Recipient discovery, identity and backups

Public accepted records contain enough to identify the exact ordered commitment
positions, encrypted note data, ephemeral keys and spent markers needed by the
selected construction. Wallets scan locally with viewing authority and retain
spending authority separately. A server receives no spending key or private
witness by default. Incoming and outgoing recovery capabilities must be specified
separately; a viewing key is not automatically a complete spentness backup.

Before crediting a payment, the recipient verifies accepted-chain context,
exact ciphertext framing/decryption, note commitment, asset/domain/range and
whatever ownership/spendability checks the reviewed construction requires.
Bind delivered bytes into authorized effects. Choose explicitly between proved
correct delivery and sender-malformed delivery that the recipient deterministically
rejects before acceptance; mere decryption success or a view-tag hit is insufficient
for I-14. Current Aztec offers materially different constrained/unconstrained
modes; its refreshed source must accompany this choice.

Preserve record **multiplicity and global positions**. The legacy v6 scanner
allowed equal openings at different positions with separately positioned
nullifiers. That does not mean an Orchard-style marker has the same identity
rule. A native profile must choose one coherent note-freshness/nullifier scheme
and prove that each counted output gives the intended spendable claim. Do not
silently deduplicate equal commitments/ciphertexts, or count two liabilities
whose chosen marker scheme permits only one to be spent. Duplicate-record and
cross-position controls belong in Q4/I-14 review.

A minimal versioned owner backup records spending/viewing derivation material,
network/genesis/pool/creation/profile identifiers and recovery start context.
Pin the public compatible software, proving/verifying artifacts and authenticated
history source. Exact reproducible public proving parameters must remain
available when the selected proof system needs them; the old missing-parameter
failure is not repaired by a new setup or an old valid proof.

### Pruning, public recovery data and independent availability

A root commits to data; it does not recreate missing bytes. The source refresh
shows no automatic extension of today's UTXO/pruning bootstrap to this proposed
state. The draft's conservative recovery reference is to retain the complete
accepted shielded commitment/delivery log plus enough accepted ordering and
spentness data to reconstruct witnesses from activation. This retention has an
unmeasured permanent cost and is not a production scalability claim.

| Recovery material | Reference source/retention obligation | Authentication and failure behavior |
| --- | --- | --- |
| Network/profile and activation state | Public protocol/software and consensus-agreed start state. | Reject wrong network, pool, verifier or invented genesis. |
| `B`, commitment frontier/count, accepted anchors, current `N` | Full state replay from activation; a future fast snapshot is optional and unreviewed. | A snapshot needs consensus-authenticated complete state and update rules; a server signature/self-hash is not sufficient. |
| Ordered note/ciphertext records | Independently retained accepted log, not only the wallet's normal indexer. | Check order, completeness, position, branch and commitment bindings; missing history blocks an honest recovery claim. |
| Witness updates/reorg data | Reconstruct from authenticated retained records; owner snapshots can accelerate. | Detect stale/corrupt/truncated records and rollback; old membership alone does not prove current state. |
| Public prover/verifier artifacts | Exact independently retrievable bytes, hashes and compatible software; no coordinator-only store. | A different ceremony/key cannot repair an existing instance's missing parameters. |
| Owner secrets/backup | User-controlled encrypted backup with version/domain metadata. | No other owner's keys, private truth or privileged operator state required. |

The full-node/storage/peer role must explicitly retain and serve the required
records independently of normal application services. Consensus commitments do
not force another machine to retain or serve bytes. At least one reachable
independent source of the authenticated retained history, or a sufficiently
complete owner-held copy, remains a liveness assumption; state it and test it.
All designated operators/hosted state services can disappear only if required
public data still exists outside them. A claim that every copy can disappear
while a seed/root alone restores the payment is unsupported.

Nullifiers cannot be discarded merely because ordinary UTXOs were pruned.
Hidden spent-note linkage also prevents assuming that each ciphertext can be
safely deleted as soon as an unrelated public marker appears. Snapshot proofs,
pruning commitments, storage charging and any safe garbage collection are
unresolved Q6; none is supplied by a convenient unverified archive.

### Fees, resource limits and permissionless exits

Use `F` as the actual network fee in the cross-domain equation. A user can fund
it from owned shielded value, ordinary inputs or an explicitly authorized
contributor; no designated sponsor is required. If a claim cannot cover prevailing
fees without additional value, do not promise a free economic exit or silently
skim its principal. Distinguish authorization to exit, fee affordability, relay
acceptance and timely inclusion. Q7 and public issue #23 remain open.

Relays can submit an already authorized complete transaction and may censor it;
they cannot alter recipients, boundaries or fees. Any compensation is an explicit
authorized transfer, and any permitted fee contribution/repricing mechanism must
be reviewed against input/output reordering, signature attribution, substitution,
replay and reserve diversion. Do not import fixed branch fees, withdrawal delays,
minimum retained balances, an admin rescue or a mandatory service allowlist.

Charge proof verification, encoded bytes/ciphertexts, commitment/nullifier growth
and retained recovery data under reviewed consensus mass/storage rules. Set
finite security bounds and price invalid-verification work before deployment.
These anti-DoS consensus rules differ from generous operational time/memory
allowances for a research trial. Never classify a resource failure as semantic
proof rejection or copy a bare verifier mass as a complete transaction quote.

Cost acceptance remains the adopted full-lifecycle benchmark, including funding,
deposits, transfers, change, every exit, rent/retention, network and service fees,
with useful-recipient value as the declared denominator. The retained 12.5793%
failed benchmark and separate approximately 1.85% offline layout remain distinct.
Faster key loading or a 31.20% smaller synthesis is not a measured lifecycle pass.

### Prior-learning traceability

The [full knowledge coverage](../research-knowledge/coverage.md) retains every
original branch/commit/doc identity. This table carries the unique lessons into
specific review obligations; historical successful, failed, proposed and
source-only results keep their original evidence levels.

| Prior work / lesson | Consequence in this proposal | Local evidence |
| --- | --- | --- |
| A0/A1 native release, successor, physical-loss/reorg recovery | Exact native effects, atomic claim/payout and rollback; no complete-service-loss claim from one-machine loss. | [Recovery guide](../research-knowledge/recovery.md), [A1 trial](../poc-a1-official-trial-2026-10-08.md) |
| Completed Based App/recursive public-account milestone | Separate public runtime feasibility from private value; vProgs must earn its complexity through a requirement. | [Scoped conclusion](../based-app-feasibility-2026-10-17.md) |
| Offline wallet and independent self-funded exits | Wallet-owned authority, explicit native backing and scoped setup/fee assumptions. | [Reuse decisions](../research-knowledge/reuse.md) |
| Compact state, reusable authorization, conflict retries, scanning | Accepted order, current spentness, rollback and local recovery; authorization is not a latest-state guarantee. | [Recovery guide](../research-knowledge/recovery.md) |
| Independent/equal-net deposits, two-input spending, known wallet rules | Entry equalization and larger candidate sets do not establish complete-lifecycle privacy. | [Privacy guide](../research-knowledge/privacy.md) |
| Participant disclosure and address reuse/key separation | Legitimate knowledge remains in the observer; mitigate specific channels without a general anonymity claim. | [Current lessons](../RESEARCH-LESSONS.md) |
| Working-balance/common-payout/timing policies and price priors | Preserve rejected policies, proper guessing baseline and unresolved absolute-target tension. | [Current lessons](../RESEARCH-LESSONS.md), [privacy guide](../research-knowledge/privacy.md) |
| Inserted answers, hidden chain-label scores, wrong live contact edge | Observable-role scoring and complete joint truth retention; original errors stay corrected, not overwritten. | [Current corrections](../RESEARCH-LESSONS.md) |
| Private re-spending/change and common-reserve mitigation | Retain interim benefits; later transparentization still exposes public constraints. | [Current corrections](../RESEARCH-LESSONS.md) |
| Native payout/successor/per-input admission control branches | Bind exact effects and isolate native covenant rejection from funding-signature failure. | [Regression contracts](../research-knowledge/controls.md) |
| Ownership/range/padding/tree-capacity controls | Bounded integers, coherent dummy rules, position identity, full-state no-mutation refusal. | [Regression contracts](../research-knowledge/controls.md) |
| One-v6 adapters and actual changed-input rejection | Distinguish compatibility, expected fixture bytes and cryptographic statement binding. | [Regression contracts](../research-knowledge/controls.md) |
| Paired proofs, state-aware journal and fresh native supplied-context tests | Actual predecessor/accepted lineage remains necessary; a stronger journal cannot inherit an older proof statement. | [Proof guide](../research-knowledge/proofs.md), [unfinished reviews](../research-knowledge/unfinished.md) |
| Retained CPU/GPU failures, partial/full receipts and RTX reproduction | Preserve source/profile/resource/evidence levels; no extrapolated throughput. | [Proof guide](../research-knowledge/proofs.md) |
| Uncompressed parameter cache, HMAC sizing, reveal exits, favorable fee layout | Conditional performance/tradeoff candidates; preserve failed memory/fee/privacy gates. | [Cost guide](../research-knowledge/costs.md) |
| Missing public proving parameters, cold/hosted replay and backup exits | Exact available bytes and independent retention, not root/seed alone; failure domains differ. | [Recovery guide](../research-knowledge/recovery.md) |
| Bounded owner-map construction, Tor delivery and disabled registered MPC path | Constructor privacy, transport and network anonymity are distinct; no MPC spending authority or automatic restart. | [Paused handoff](../research-knowledge/documents/8afbd3d859a68dc4d80194cbdc3f0cc36e5e9961.txt) |
| Exact RPC/header integers, mass, source closure and watchdog fixes | Integer sompi, original identity pins, correct error layers and independent process lifetime; source validity is not native privacy. | [Operations guide](../research-knowledge/operations.md) |
| Fifteen unfinished feasibility/replay/review/publication notes | Preserve corrected offsets/counts, state/claim identity, position multiplicity and incomplete publication assumptions. | [Unfinished work](../research-knowledge/unfinished.md) |

### Invariant and threat review

| Invariants | Required review argument / unresolved boundary |
| --- | --- |
| I-1, I-2 | Native backing/supply counted once; atomic liabilities; explicit review of proposed boundary equations and native-reserve interpretation. No invariant amendment is accepted. |
| I-3, I-4, I-5 | Wallet authority, sound bounded relation, current unique nullifiers and exact verifier/profile; no witness-selected key or cached-absence shortcut. |
| I-6, I-11, I-15 | Authenticated accepted ordering, exact effects/domain, deterministic decoding, atomic updates and complete reorg undo. |
| I-7, I-8, I-12, I-13 | Authorized exact withdrawal, no privileged confiscation/treasury path; upgrades preserve existing claims and spentness without an admin rescue. |
| I-9, I-10 | Invalid/unavailable evidence halts safely; sufficient independently available data/artifacts must still permit recovery under the declared failure model. Safety alone is not recovery. |
| I-14 | Recipient detects invalid delivery/spendability before credit; note multiplicity/freshness follows the chosen cryptographic identity. |
| I-16 | Scope public fees, boundary values, legitimate disclosures, timing, queries and transport separately from cryptographic confidentiality. |

The adversarial review must challenge hidden inflation/balance-sign errors,
replayed notes across versions, duplicated deposits, payout/ciphertext diversion,
false accepted roots, same-nullifier DAG races, underfunded fees, unauthenticated
snapshots, missing parameters, recipient traps and migration-stranded users.
It must include wallet/prover collusion and network/fee metadata; a public-output
amount removed from a hypothetical dataset is not an executed privacy result.

### Review questions and stop conditions

| ID | Question requiring an explicit answer | Required reviewer/evidence |
| --- | --- | --- |
| Q1 | What is independent native ownership versus transparentization under the unchanged known-owner/full-drainage requirement? | Owner/privacy review; retain counterparty knowledge, public entry/exit arithmetic and the fixed target/price-prior tension. |
| Q2 | Which established note/value-commitment, encryption, nullifier and authorization construction is selected? | Cryptography review of bounded balance, complete effects, delivery/I-14 and note identity; no mixed-protocol primitive substitution. |
| Q3 | Adapt to current tags, wrap a verifier or add a verifier? What are exact bytes, curve/setup/parameters, resource bounds and activation rules? | Kaspa/ZK review; later complete positive/negative proof and native qualification under one profile. |
| Q4 | How do creation identity, padding, duplicate commitments/positions, current nullifiers and upgrades interact? | Cross-version/cross-domain/double-spend and recipient-spendability argument plus vectors. |
| Q5 | How are `B`, note state, spentness, effects and fees accepted/undone across the DAG and parallel/cache paths? | Consensus/storage review and deterministic conflicting-block/reorg vectors. |
| Q6 | What authenticates new bootstrap/pruning state and guarantees retrievable note/parameter data? | Full replay or reviewed authenticated snapshot; clean independent recovery with normal services gone; measured retention cost. |
| Q7 | How do users reprice/pay exits without a designated sponsor, hidden haircut or fixed-fee lockup? | Fee/mempool review under issue #23, separated from consensus validity and inclusion guarantees. |
| Q8 | Does the boundary accounting generalization preserve I-1/I-2/I-7/I-12 and the emission/reward rules? | Explicit invariant/ADR review before any implementation; include pending liabilities, fees, rent and migration. |
| Q9 | What classical/PQ and upgrade assumptions apply separately to proof, ownership, encryption and long-lived data? | Primitive inventory and authorized, non-stranding migration; no PQ conclusion from one verifier tag. |
| Q10 | Does a complete fresh profile meet privacy, full fees, recovery, memory and useful throughput targets together? | Frozen observer/truth/metrics and matched lifecycle evidence after the design gates; no retuning failed historical runs. |

**Stop implementation** while the selected primitive/profile, soundness and
native supply/balance rules, accepted state semantics, necessary invariant
resolution or recoverable data contract remain undefined. A review-ready RFC
may be complete with these questions open; a consensus implementation cannot
claim readiness from that document. No architecture is adopted and no accepted
ADR is created by this extension.


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
| Amount/script of an already ordinary transparent payout stay hidden | Incompatible with that representation | Published fields remain public; inference about earlier payments is observer/workload-specific |

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

The current reference targets I-1 through I-16; its experimental results are not
a complete proof of those properties. The proposed native-domain interpretation
and cross-boundary accounting require the explicit I-1/I-2 review above.
SECURITY-INVARIANTS.md is unchanged. Proofs and covenants
must bind value conservation, authorization, nullifier uniqueness, current
state, reserve continuation, payout effects, fees and protocol version. A
missing prover, relay or archive may stop progress but cannot authorize theft.

Recovery requires wallet secrets plus authenticated commitments, nullifiers,
ciphertexts, accepted ordering, witnesses/snapshots, verifier artifacts and
independent software. A state root alone is not recoverable data. Public data
availability and singleton contention remain liveness risks, not hidden
custodians.

## Smallest next engineering step

The requirements-level extension is ready for specialist review, not adoption.
Resolve Q1–Q9 into one exact profile and reviewed invariant/accounting decision
before proposing protocol implementation. Produce fixed encoding, boundary,
DAG/reorg and recovery vectors alongside that decision. Keep Q10's privacy,
cost and independent-recovery gates explicit.

A subsequent prototype would use synthetic values/test KAS only and compare
shielded native ownership with optional ordinary transparent withdrawal under
the same declared observer. A current-Kaspa direct-inline-ZK experiment may
remain a reference for transparent exits, but is not a substitute demonstration
of the missing confidential native representation. No new trial, setup, proof
campaign, infrastructure or MPC work is part of this documentation task.

## Outcome, when known

Open. No ADR is created until review accepts or rejects this recommendation.
This RFC accepts no implementation, funded trial, broadcast, proof campaign,
runtime deployment or recovery action. The owner authorized this documentation
extension and logical commits; that authorization does not adopt the proposal
or restart paused MPC work.

## Current source pins

The [Kaspa source manifest](../../research/native-kas-consensus-sources-2026-11-03.json)
and [five-protocol review](../../research/native-kas-shielded-value-sources-2026-11-03.md)
record the complete refreshed identities, exact files and applicability limits.
Source inspection is not a network activation or cryptographic qualification claim.

- Rusty Kaspa `b85380d16514e65136001530e7c717eef304e654`
- Kaspa docs `0ac77d043a802fc8196abfd5812ac2afbd97a2b9`
- Kaspa KIPs `d832dbd89347dcb16d3d83bf6755b081714cbcb2`
- vProgs `f9b84a863a7c7c20586a9cf947550475e894f72e`
- Kaspa research `c923faca11a49148fa7d912d27ce00197a5c5a4a`
- Orchard `616a669df8c9a59c33d47064d3ce04b25d026b2e`
- Zcash protocol `ff594de6e95bb9e9e7d2ace09510281531c30447`
- Litecoin `ec1b6489a900d09cf5991e220dce089c77a232a2`

[K-DECISION]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/decision-guide.mdx#L6-L40
[K-INLINE]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx#L85-L127
[K-OUTPUT]: https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/core/src/tx.rs#L176-L190
[K-VALUE]: https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs#L147-L169
[K-CONSERVE]: https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs#L116-L124
[K-TAGS]: https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/crypto/txscript/src/zk_precompiles/tags.rs#L5-L20
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
