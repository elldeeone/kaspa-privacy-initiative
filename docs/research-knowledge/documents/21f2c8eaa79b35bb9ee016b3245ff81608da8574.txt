# Independent exit obligations and finite-model review

Source/design review, 2026-10-22, baseline
`8d7d719f18ae5975e651a4a114f8cecceb3e8b7c`. No format or architecture is adopted
here. No owner CLI, ledger replayer, DRAIN workflow, PK restore, proving, funding
or broadcast was performed. This note owns no implementation outside this file.

**A cheap terminal claim is useful only after an enforceable, backed entitlement
exists. It does not establish an inexpensive independent exit from every live
private note.** The useful next experiment is a finite liability/authorization
model that tests the boundary between those two states, before another prover
or native implementation. The current proof-verifier cost result remains valid
for its stated path; it is not a lower bound on every future revealing branch.

## The two transitions that must not be conflated

| State or proposal | What is established | What still needs authorization |
| --- | --- | --- |
| Live private note N | An accepted private liability, possibly with a saved proof | Current unspentness, authorized consumption, reserve/payout/fee binding |
| Submitted proof, signed ticket, local receipt or proposed batch | A candidate authorization; no accepted-state change | Native/settlement acceptance and backing allocation |
| Accepted withdrawal entitlement E | Note consumption, unique entitlement and allocated native backing were accepted atomically | One redemption to its bound owner/destination with the allowed fee |
| Observed accepted native payout P | The entitlement was consumed and its native value paid under the named chain-view policy | Reorg tracking; no second redemption |

Current v6's private path uses its proof to establish ownership, note membership,
value and the positioned NF relation; native/current S7 state enforces current
spentness. Existing valid saved authorizations can be reusable under their
specified anchor rules; this is not a claim that every retry needs a freshly
generated proof. A candidate that authenticates N→E earlier moves that cost. It
must account for the whole path when the operator disappears **before** E.

Creating E only after withdrawal authorization gives a conditional unilateral
claim. Creating a spendable E alongside a still-spendable N instead creates two
authorities over one principal unless every private transfer and claim shares
the same atomic exclusion. A detached ticket UTXO cannot remain independently
redeemable after its associated note privately transfers. Conversely, requiring
an operator to cancel or release that ticket is an exit veto.

## Concrete authority finding and the refined future hypothesis

The current note opening is `(owner, incoming, value, rho)`. A sender constructs
it from public receive data; the opening alone is not recipient authority.
`owner = SHA256(tag || domain || wallet.spending || incoming)`, while the real
NF is HMAC under `wallet.spending` over the positioned commitment. Native payout
keys derive from an independent `wallet.native`. See
[note/receive/keys](../../../poc/shared-pool/src/protocol.rs#L65-L180) and
[actual private ownership/NF constraints](../../../poc/shared-pool/src/two_input/circuit.rs#L128-L204).
Thus an independently supplied native signature is not automatically bound to
the existing note, and exposing `wallet.spending` discloses reusable authority.

**Rejected one-credential variant:** emergency reveals a note-local secret that
alone authorizes private SPEND, but only emergency requires the committed native
signature. An observer copies the revealed secret, proves a private SPEND to
attacker outputs, and races the emergency transaction. Same-NF first-wins can
prevent inflation while paying the attacker. A fixed emergency destination does
not constrain this other branch. Note-local scope limits sibling exposure; it
does not prevent this same-note theft. Speed assumptions about which prover or
transaction wins are not authorization.

Root's refined, still unadopted hypothesis separates the credentials:

- Private consumption requires the existing **undisclosed wallet.spending**
  ownership relation **and** the commitment-bound note-local NF secret.
- Revealing exit discloses only that local NF secret/opening and requires a
  signature under the native authority already bound into the same note.
- Both paths derive the identical positioned NF and update the same current
  spentness domain. The opening, NF-secret commitment and native authority must
  all be covered by the note's creation/receipt checks.

This separation addresses the stated theft trace conditionally. Merely hashing
a public native key into the note does not prove knowledge of its signing key
in the private path; the undisclosed ownership relation must actually remain.
Sender-known `rho` must not replace a recipient-secret NF credential. Reusing a
receive descriptor/local secret can expose several notes when one is revealed;
“one-time” needs a precise issuance/acceptance rule, not a label. Recovery must
derive or discover the required credentials from a backup predating the payment
and available public data, without a sender's later cooperation or private export.
Both branches need recipient rejection of malformed/unspendable descriptors.

## Minimal finite model to freeze first

Use two owners, two value lineages, at most one transfer per lineage, two batch
prefixes and one rollback. This is sufficient to discriminate the failures
below; it does not model cryptographic soundness, unbounded contention or the
complete money range. Keep the current integer-sompi ranges as separate tests.

Each lineage has one accepted state: `N(owner, note-id, position)`,
`E(owner, ticket-id, gross-value, destination, fee-policy)` or `P`. Retain old
note IDs and their NFs after a private transfer; the successor is a different
note with its own authority. The model also carries:

1. Current reserve outpoint/version, backing amounts, current NF set and spent
   ticket set or exact unspent ticket UTXOs.
2. Accepted entitlement roots and the stable entitlement IDs they cover.
   Prefix1 covers A; prefix2 extends it with B. Proposed roots are separate.
3. Private liabilities, unpaid entitlement liabilities, refundable user credits,
   actual payouts and explicit fees. Sponsor assets are a separate domain.
4. External data-availability/actor-presence flags and adversary knowledge, plus
   a preceding complete accepted-chain snapshot for rollback. Flags cannot
   change accepted liabilities. Chain rollback cannot erase knowledge or
   restore a disappeared service/data copy.

Use opaque authorization predicates: `private_authority`, `local_NF_secret`,
`native_signature`, `accepted_root`, `current_unspent`. The model must not grant
one from knowledge of another or assume that an operator's assertion verifies
a predicate. The adversary knows all sender-created openings, public records
and every revealed local NF secret, but not honest wallet/native signing keys.

| Transition | Required precondition | Atomic effect |
| --- | --- | --- |
| Private transfer N→N′ | Both private credentials, accepted historical membership, **current** NF absence and correct current reserve/state | Consume old NF; create owned N′ with conserved value/allowed fee; preserve all unrelated liabilities |
| Authorize N→E | Valid owner authorization, same current NF exclusion, accepted complete settlement and backed ticket fields | Consume N once; add E once; preserve its gross liability and allocated backing |
| Reveal N→P | Local opening/NF relation, committed native authority/signature, current NF absence, correct reserve and payout/fee | Consume the identical NF and pay the owner atomically; no surviving N or unpaid E for that value |
| Redeem E→P | Accepted E, current ticket unspentness, intended chain/pool/version, exact owner/destination/fee policy | Consume E once; pay exact allowed outputs; remove its liability only with payment |
| Propose/withhold/service loss | None that changes accepted ownership | No reserve or liability change; progress may fail explicitly |
| Roll back | Named accepted-chain rollback | Restore ancestor chain state, including tickets, spentness, backing and payouts; preserve external knowledge/service-loss flags and reject descendants outside that accepted view |

No transition may change N→P through a root that only establishes membership.
Unspentness and ownership are separate conditions. Shared-reserve claims need
paths valid at the current accepted spent-ticket/NF state, or an explicit safe
update mechanism; an old inclusion proof alone cannot spend a current reserve.
Dedicated ticket UTXOs use native UTXO consumption for redemption exclusion,
but their creation and every competing note branch must already be synchronized.
Publishing a reveal proposal exposes its local credential even if the candidate
is rejected or later orphaned. Keep that knowledge in the one-credential mutant;
otherwise a model may wrongly grant safety by forgetting the disclosure.

## Conservation invariants

Let `B` be all protocol-controlled user backing, including any dedicated ticket
outputs; `L_N` spendable-note liabilities; `L_E` gross unpaid entitlements; and
`C` separately tracked refundable user fee/rent credits. Require at every valid
accepted state:

```text
B >= L_N + L_E + C
each input is consumed by at most one accepted transition
each entitlement has at most one accepted native redemption
owner payout >= the owner-authorized amount after explicitly allowed fees
```

An authorized transition may split its input into several outputs; conservation
constrains their total. The model's one-successor lineage is a finite scope
choice, not a proposed ban on legitimate private splits.

For an N→E conversion consuming inputs `v`, creating private change `w`, gross
entitlements `x` and an authorized settlement fee `f_s`:

```text
sum(v) = sum(w) + sum(x) + f_s
L_N' = L_N - sum(v) + sum(w)
L_E' = L_E + sum(x)
B'   = B - f_s
```

Moving `x` into a dedicated native ticket output reallocates backing; it does
not reduce total B a second time. For a shared-reserve claim of gross value `x`,
owner payout `p`, sponsor inputs `s`, sponsor refunds `q` and successor reserve
`R'`, require `R' = R-x`, `x-p = authorized owner claim fee` and native miner fee
`(x-p)+(s-q)`. Sponsor debit/refund authorization is checked separately. At claim,
`L_E` falls by x together with backing x; fee credit cannot also be charged or
silently confiscated. Other users' principal cannot pay a sponsor's refund or
another claimant's fee. Cancellation/reissue, if allowed, consumes the old E
atomically and recreates conserved liability; expiry cannot erase a valid claim.

## Adversarial traces and decisive controls

These are proposed finite-model falsifiers, not executed test results. A test
that merely corrupts every witness does not isolate the target obligation.

| Trace | Required outcome / meaningful control |
| --- | --- |
| Private SPEND and reveal from the same current state, in both orders | Exactly one NF consumption/payout or successor. The loser can never substitute an emergency-only marker. With opening+local NF secret exposed, an adversary lacking wallet.spending/native key cannot redirect through **either** branch. Retain the one-credential variant as an intentionally failing model. |
| Sender reuses a known opening or supplies its own payout key | Membership may be valid; authority/key binding must still reject, or recipient acceptance must reject before credit. Also test a valid signature under the wrong committed key. |
| Valid old commitment anchor after its NF was spent | Old membership remains valid; current NF insertion/claim must reject. Existing S7 checks historical membership separately from current NF insertion at [state core](../../../poc/s7-owner-lifecycle/state/src/lib.rs#L163-L190). |
| Local proof or batch proposal produces E, but native settlement fails | No redeemable E, no paid marker, and no liability removal. A software receipt or VM/Full test with supplied synthetic UTXO context is not accepted lineage. |
| Prefix1 accepted, prefix2 only proposed; then prefix2 accepted | A is claimable once, B only after its accepted coverage. Claim A against prefix1, then attempt A against prefix2, reordered leaves and a different root-local index: reject the second economic redemption. |
| Authorization/claim accepted, then one-step reorg | All dependent roots, spent markers, ticket outputs and payouts track the accepted fork. A proof from the orphan cannot redeem against a different reserve/lane. A lost payout observation is not final liability extinction. |
| Root published, leaf/siblings/ciphertext withheld; operator then disappears | No invented witness, privileged rescue or erased claim. Explicitly fail recoverability if a pre-payment backup plus declared public data cannot recover the correct current claim. A root commits data; it does not supply it. |
| Operator disappears before N→E | E-only redemption is unavailable. Demonstrate another user-controlled authorization path within the stated fee/hardware/data envelope or report this supported-note liveness failure. Mandatory batch fill or someone else's private proof export is not independence. |
| Duplicate ticket, repeated CM, cross-pool/version/lane/chain replay | Bind a unique economic entitlement identity and authorized spending domain. Equal CMs at distinct authenticated positions are not automatically the same liability; root-local positions or transaction indices alone must not reset identity. Test exact body with only the intended domain changed. |
| Colluding sponsor/prover chooses excessive fees or priority | Owner fee authorization and sponsor contribution/refund limits still hold. Include actual authorization, claim, retry and service costs; label subsidies. Changing payer cannot prove reduced complete cost or permit other users' reserve debits. |
| Claim A then B versus B then A; nearly full state; final private note but unpaid E | Both supported users remain claimable under declared inclusion assumptions. No CM/NF/history capacity dead end, state-count shortcut, or terminal reserve release while E/C remain unpaid. Honest contention must not require the winner's return. |
| Many minimum tickets, tiny remainder/refund, larger script plurality, fee rise | Recompute the whole native transaction in each valid ordering. A compute-fee reduction cannot waive storage/transient caps; larger fees can shrink the remainder and make storage mass worse. Reject creation of unsupported new value rather than abandoning old liability. |

Ticket identity must remain stable across partial-root extensions and regrouping.
The pinned [Aztec Outbox](https://github.com/AztecProtocol/aztec-packages/blob/49a592109ec4f18d79212b43d621891aaf36f7b6/l1-contracts/src/core/messagebridge/Outbox.sol#L28-L43)
explicitly relies on its rollup preserving message leaf IDs; it shares the
nullification bitmap across an epoch's roots and checks accepted-root coverage,
recipient, chain and version. Reuse that obligation, not a claim that its EVM
implementation supplies a Kaspa reserve covenant. Its source documents this
boundary; this is not an upstream vulnerability finding.

A separate source-only reuse blocker was independently checked in vProgs at
`f9b84a863a7c7c20586a9cf947550475e894f72e`. Its
[permission emitter](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/permission_script.rs#L352-L380)
authenticates one old-root walk, then consumes a second walk for the new root.
The [step emitter](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/permission_script.rs#L623-L635)
does not retain/compare siblings or directions; successor-SPK reconstruction
binds the computed new root without supplying that equality. The
[honest test builder](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/test-suite/tests/permission_spend.rs#L155-L179)
duplicates the arrays by convention. I found no compensating binding in the
emitter's complete call sequence. Therefore it does not establish the required
local-update equation `newRoot = Fold(newLeaf, authenticatedOldPathAndIndex)`.
Treat remaining-entitlement preservation as unresolved before reuse. No hostile
fixture, VM execution, complete exploit or accepted-chain claim was made; a
happy-path cost measurement cannot establish this missing equality. A separately
authorized synthetic cost diagnostic can still measure that exact emitter; it
must report this boundary rather than qualify preservation of other claims.

## Economic and liveness gates before a native candidate

For a supported60M-sompi note and10M payout floor, the complete fee allowance is
at most50M. At the declared500-sompi/gram scenario, a one-transaction route needs
normalized mining mass at most100,000 **before any other lifecycle costs**.
Current two-scalar G16 alone costs147,500grams; a future proof-free branch is
outside that assumption and needs its own full calculation. The100/200/500
values are research scenarios, not market quotes or a guarantee of inclusion.

Splitting a reserve into many tickets creates persistent UTXOs. Pinned native
mass code sums `floor(C * plurality^2 / output_value)` before its applicable
input subtraction and chooses harmonic/arithmetic input treatment according to
the full layout. A smaller payout/change/ticket and larger script plurality can
dominate storage mass. See native
[`calc_storage_mass`, 01b532e](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/mod.rs#L439-L512),
inspected in the retained source checkout, and the earlier
[note-floor argument](../../../docs/adr/0017-note-floor-and-independent-exit-retry.md).
That old fixed-layout bound does not transfer to a new ticket layout. Check
individual-claim and last-claim storage, creation/funding, public metadata,
owner fee repricing, sponsor refunds and reserve fragmentation with the full
native calculator/limits; an isolated opcode quote is insufficient.

The finite model should first reject the one-credential theft variant,
N-plus-detached-E double authority, root-local duplicate redemption and premature
liability release, then preserve both owners through an honest claim ordering
and one rollback. These are inexpensive decisive architecture checks. Passing
them would justify a separately authorized native predicate/cost experiment;
it would not qualify receipt delivery, accepted chain state, user recovery,
privacy or complete exits. A public revealing path may expose position, amount,
counterparty linkage and later history; evaluate that observation horizon rather
than calling it ordinary private spending. Existing immutable v6/S7 covenants do
not gain a new branch from this proposal. Any selected format/state/range/count
change needs a new explicit RFC/ADR and synchronized invariant obligations.

Authoritative constraints: [I-1/I-3/I-4/I-7/I-10/I-14](../../../SECURITY-INVARIANTS.md),
[RFC-0012 R1/R2/R5/R6/R7/R8](../../../docs/rfc/0012-useful-privacy-requirements.md#L131-L143)
and its [cost/recovery contract](../../../docs/rfc/0012-useful-privacy-requirements.md#L190-L209).
The unchanged invariant equations, backed unpaid claims, independent exits and
pre-payment-backup requirement are gates, not optional operational policies.

## Selected finite-plan second pass

The reviewed planning snapshots were RFC-0019 SHA256 `095e35b258d8a721cf8942b41298ddea2fa01e2f236e743d1e6b985e6f133de7`,
ADR-0039 `77b5d71e56c663abaf5cf3106973ffea5460679dc6f2ba852b7b4ee52da7cab8`
and IMPLEMENTATION-SEAM `6950729d1e81662f8b2c4aa9ce640783df46d4883f6b6db6850d11b6eb04c3f8`.
The selected three-origin scope is larger than the minimal two-lineage screen:
`(2 values × 2 owners)^3 × 2 modes = 128` initial configurations. Three private
replacements, at most three accepted batches and three claims give the stated
nine value-changing-operation bound. Exhaustive canonical-state traversal must
still finish without a depth cutoff; those bounds are not measured results.
Current-format reveal remains unresolved, separately from any ideal-oracle run.

No model-only architecture blocker was found. Two concrete specification checks
were sent before implementation: publish/reject/orphan exposure must survive
rollback independently of chain state, and the stable-ID mutant must actually
cover one entitlement in two accepted root/index contexts. Malformed membership
rejection alone cannot demonstrate that property. Deliberately broken rules
must produce the promised counterexamples; an ideal authorization oracle or
successful accounting trace cannot substitute for a future native relation.
