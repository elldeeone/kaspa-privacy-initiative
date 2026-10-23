# Exit-fee implementation seam: source patterns and proposed model boundary

Source-grounded planning note, 2026-10-22. ADR-0039 subsequently released only
the isolated offline model described below; no native architecture was adopted.
Local source inspected at
`8d7d719f18ae5975e651a4a114f8cecceb3e8b7c`. No architecture adopted,
implementation, proof generation, jobs, funding or chain activity. This note
extends the pinned [fee-alternatives review](../native-kas-singleton-fee-alternatives-2026-10-22.md);
it does not establish native-KAS claim enforceability or a transaction fee bound.

## Primary-source facts

| Pattern and exact source pin | Verified behavior | Boundary for this research |
|---|---|---|
| Aztec Outbox, `49a592109ec4f18d79212b43d621891aaf36f7b6` | Only its configured rollup inserts roots. `consume` checks version, recipient, chain, accepted root, Merkle membership and an unused leaf ID, then records consumption. There is no fresh SNARK call in this claim path. The example portal binds recipient, amount and optional caller into the message, consumes it, then transfers. | This is a claim against an **already authenticated withdrawal message**, not a new spend of an unaccepted private note. The example portal is test source, not deployment evidence. [Outbox](https://github.com/AztecProtocol/aztec-packages/blob/49a592109ec4f18d79212b43d621891aaf36f7b6/l1-contracts/src/core/messagebridge/Outbox.sol#L96-L155); [portal](https://github.com/AztecProtocol/aztec-packages/blob/49a592109ec4f18d79212b43d621891aaf36f7b6/l1-contracts/test/portals/TokenPortal.sol#L115-L137). |
| StarkEx revealing escape, `f3b250690c5d927a6e398e9c1735d9193a643034` | A Pedersen Merkle proof reveals owner key, asset and balance. `escape` requires a frozen system, the current frozen vault root, a matching registered fact and an unused vault ID; it credits pending withdrawal. Final `withdraw` clears that balance and pays the registered owner address; anyone can trigger it. | The exclusion mechanism is global freeze plus per-vault use, rather than a concurrent private-note nullifier. Merkle witness availability remains necessary; the source distinguishes rollup reconstruction from validium availability assumptions. [Verifier](https://github.com/starkware-libs/starkex-contracts/blob/f3b250690c5d927a6e398e9c1735d9193a643034/scalable-dex/contracts/src/starkex/components/EscapeVerifier.sol#L28-L56); [escape](https://github.com/starkware-libs/starkex-contracts/blob/f3b250690c5d927a6e398e9c1735d9193a643034/scalable-dex/contracts/src/starkex/components/Escapes.sol#L10-L21); [checks](https://github.com/starkware-libs/starkex-contracts/blob/f3b250690c5d927a6e398e9c1735d9193a643034/scalable-dex/contracts/src/starkex/components/Escapes.sol#L37-L62); [payout](https://github.com/starkware-libs/starkex-contracts/blob/f3b250690c5d927a6e398e9c1735d9193a643034/scalable-dex/contracts/src/interactions/Withdrawals.sol#L108-L125). |
| Privacy Pools ragequit, `d494b63e79f33bb2b0c8ece6cdacdca465c3b884` | Ragequit checks the original depositor, verifies a Groth16 proof, checks commitment existence and consumes the nullifier hash. Ordinary withdrawal calls the same `_spend` function and mapping. The commitment circuit binds value, label, nullifier and secret, with `Poseidon(nullifier)` as nullifier hash. | Useful cross-branch exclusion analogue; **not proof-free**, and original-depositor authorization does not model ownership of a transferred note. [Branches](https://github.com/0xbow-io/privacy-pools-core/blob/d494b63e79f33bb2b0c8ece6cdacdca465c3b884/packages/contracts/src/contracts/PrivacyPool.sol#L99-L135); [spent map](https://github.com/0xbow-io/privacy-pools-core/blob/d494b63e79f33bb2b0c8ece6cdacdca465c3b884/packages/contracts/src/contracts/State.sol#L109-L118); [binding](https://github.com/0xbow-io/privacy-pools-core/blob/d494b63e79f33bb2b0c8ece6cdacdca465c3b884/packages/circuits/circuits/commitment.circom#L20-L36). |

**Accepted historical root is not automatically stale authorization.** Aztec
retains earlier partial-epoch roots and shares one spent bitmap across them.
Its source explicitly assigns stable leaf IDs across extending roots to the
rollup proving system: moving one message to another ID would permit another
consumption. This is a material authorization boundary, not a membership check
the Outbox independently supplies. [Exact explanation](https://github.com/AztecProtocol/aztec-packages/blob/49a592109ec4f18d79212b43d621891aaf36f7b6/l1-contracts/src/core/messagebridge/Outbox.sol#L22-L43).

**Existing local authority differs.** Current v6 proves the secret-derived owner
relation and positioned HMAC nullifier, rather than ownership under an ordinary
public signing key. A public note opening or independently supplied payout
signature does not establish those relations. Revealing a reusable spending
secret would change the privacy boundary. Any future revealing path must
exclude the existing private path through the identical existing NF; an
already accepted withdrawal claim instead needs its own stable, authenticated
single-use identity after the originating NF was consumed.
Sources: [owner/commitment](../../../poc/shared-pool/src/protocol.rs),
[positioned NF](../../../poc/shared-pool/src/compact/mod.rs),
[v6 constraints](../../../poc/shared-pool/src/two_input/circuit.rs), all at the
local commit above. These are source facts, not approval of a new branch.

## Model recommendations; not source-established properties

Start with an offline state machine separating **accepted unpaid claims** from
**current private liabilities**. In integer sompi, changing a note into an
authenticated claim must move its liability, never remove its backing;
payment removes the claim and corresponding reserve exactly once. Model
explicit authorized fees as separate conserved amounts. Preserve
[I-1/I-3/I-4/I-6/I-7/I-10](../../../SECURITY-INVARIANTS.md).

The smallest decisive screen should try duplicate and reordered claims,
duplicated identities across roots/batches, payout/amount/domain substitution,
unaccepted or revoked roots, stale spent-state snapshots, and shutdown before
or after acceptance. For an accepted retained root, require current single-use
state; for a reorg-removed authorization, reject its claim. A missing service
must not turn a pending liability into free reserve. Witness loss may block
recovery and should be reported as such, not treated as authorization failure
or success.

Keep a future revealing-current-note exit as a distinct, unimplemented model
operation with unresolved authority/NF binding. Do not require a fresh SNARK
for an already authenticated claim merely because the present private-note
path uses one; do not assume a Merkle opening authenticates an unaccepted
current-note spend. Native covenant enforceability, available witnesses,
privacy disclosure and complete-path economics remain separate open questions.

## Local code seams and bounded exhaustive model

### Proposed experiment, frozen before implementation

Use a small explicit-state breadth-first search, with an independent accounting
oracle and deliberately broken transition variants. No transaction builder,
wallet, private ledger reader, proof API or network client belongs in it. This
is a finite **falsifier**, not a proof of an unbounded protocol or a new native
branch. Root must select this model/RFC/ADR before any implementation.

The decisive distinction is:

1. `AcceptBatch` consumes the original private NF and atomically creates a
   **new, fully backed entitlement**. A later claim consumes that entitlement's
   stable ID. Its separate ID is sound only because the original NF was
   already consumed and the transformation conserved value.
2. A hypothetical `Reveal` spends an **unconsumed private note**. It must use
   that note's identical original NF against current spent state. A separate
   emergency-spent namespace does not exclude the private branch.

Compare two accounting/control locations without selecting an architecture:

| Mode | Acceptance | Later action and accounting |
| --- | --- | --- |
| Native P2PK ticket | The accepted batch creates an owner-controlled native output of principal q. Shared reserve falls by q plus the authorized acceptance fee. | Withdrawal from the pool has already occurred. Model its later ordinary key-authorized spend only to count its fee and prevent the same output being consumed twice; it is not a second protocol escape or deferred proof-free authorization. |
| Shared claim root | Accepted claim records of principal q remain liabilities against the continuing shared native reserve. Only explicit acceptance fees leave the reserve. | An owner/recipient-authorized claim checks an accepted root plus current global spent-ID state, removes q exactly once and sends q minus its authorized claim fee to the fixed recipient. The immutable reserve policy must enforce this before any real implementation claim. |

### State and action alphabet

Use integer **model units**, never floating amounts or a claimed native fee
conversion. The oracle separately records each origin's initial principal and
where every unit currently resides. Candidate transitions may not consult this
ghost ledger to decide authorization.

| State | Exact bounded representation |
| --- | --- |
| Instance/context | One valid domain/pool/policy atom, one distinct wrong-instance atom; current reserve outpoint revision and accepted ancestry. |
| Private resources | Three origin IDs; each has at most original note revision0 and one replacement revision1. Immutable tuple includes position/NF identity, owner A/B and positive value. Historical CM roots name concrete snapshots; duplicate CM symbols at different positions remain different notes. |
| Current exclusion | One canonical consumed-NF set shared by private spend, accepted entitlement creation and hypothetical reveal. Old historical roots never roll this set back. |
| Entitlements | At most three immutable records: origin revision's NF, stable claim ID, recipient, principal and fee authorization. Shared-mode accepted roots map to ordered records; one global current spent-claim-ID set spans every accepted root. Native-mode tickets have distinct native output IDs and a current unspent-output set. |
| Native accounting | Shared reserve R, outstanding native ticket escrows E, delivered native amounts P and explicit authorized fees F. No treasury, sponsor, subsidy, top-up or mint action. |
| Environment | Acceptance service ON/OFF; owner key retained; claim/public witness available or absent; native claim-cost quote c initially1, allowed to rise once to2. Service shutdown does not silently delete owner-held/public data. |

Generate these actions, including invalid proposals, from each reachable state:

- `PrivateSpend(note, recipient, fee)` consumes its NF and creates its one
  allowed replacement note; `fee` is0 or1 and the remainder must be positive.
  Revision1 cannot be privately spent again in this bounded model. This is an
  abstract competing private transition, not an owner transaction workflow.
- `AcceptBatch(1..3 distinct current notes, recipients, fees)` requires accepted
  private authorization under an authentic current/historical CM root and
  current unspent NFs. Consume all NFs and create all entitlements atomically;
  principal q equals each consumed value minus its authorized fee. Failed
  proposals change nothing. This abstracts earlier proof acceptance; it does
  not simulate or waive its cryptographic/economic cost.
- `Claim(id, accepted root, current predecessor, recipient, fee)` performs the
  mode-specific single-use payout. A historical **accepted** claim root remains
  usable if identity is stable and current spent state is fresh. Wrong amount,
  recipient, domain, policy, ID, proof membership or predecessor rejects.
- `Shutdown`, `LoseHostedWitness`, and `RaiseQuote(1→2)` change only their stated
  environment fields. A separate retained/public-witness flag distinguishes
  service loss from genuine data loss. No operator may cancel a pending claim.
- `Reveal(note, original NF, current predecessor, recipient)` is considered
  only in an explicitly marked **conditional symbolic run** assuming a perfect
  authority/exact-NF oracle. In the current-format result it returns
  `UNRESOLVED_AUTH_ASSUMPTION`, with no transition or liveness credit. The oracle
  is not a proposed primitive, accepted note format or solved implementation.
- `RetireEmpty` is an abstract accounting guard, not withdrawal code: permit it
  only if no private or pending shared liability remains. Try it with accepted
  unpaid claims to expose premature reserve release.

Unaccepted roots, changed/reordered leaves, duplicate records across roots,
removed/noncanonical root ancestry and stale current-state witnesses are
adversarial action arguments, not valid roots automatically added to state.
A reorg fixture selects either canonical ancestor view and reconstructs the
whole corresponding balances/spent state atomically; it never erases only the
spent marker while retaining the payout or claim authorization. A spent native
output or predecessor from the orphaned view cannot authorize a new action.

### Exact search envelope

Freeze128 initial configurations:
`({value2,value3} × {ownerA,ownerB})^3 × {P2PK,shared-root}`.
All start fully backed, with retained owner keys, public witness data and service
ON. Service loss before/after acceptance and the quote rise are reachable
actions, not hand-picked successful fixtures.

There are at most six note revisions, three accepted entitlements, three
private-spend hops and three entitlement claims. Each origin terminates through
one ticket or conditional reveal path. Successful reserve-changing operations
are at most nine; accepted claim-root history has at most three extensions.
Enumerate all reachable canonical states to exhaustion, **without a depth or
sampling cut-off**. Record the exact visited-state/edge counts, shortest
counterexample traces and independent per-initial-configuration completion.
No count is a claimed performance result before execution. Parallelize only by
these initial configurations, preserving their deterministic order/results.

Fee0 is an accounting boundary control, not a claim that native processing is
free. Acceptance fee is0 or1; claim fee must meet current quote c and leave at
least1 payout unit. A ticket with q≤c is an **expected economic-liveness
counterexample** despite remaining fully backed. Quantify postaccept
service-independence only for economically feasible claims with retained
owner key and available public witness. No bounded quote assumption establishes
liveness at arbitrary future native fees.

The base model excludes root collisions and forged proofs/signatures by using
explicit finite accepted-membership/authority relations. This is a visible
abstraction boundary. The conditional reveal run assesses exclusion/accounting
only and must not be combined with base-model qualification as proof of a safe
opening/signature scheme.

### Independent properties and required counterexamples

The oracle reconstructs balances from immutable origin amounts and accepted
history, separately from transition bookkeeping:

- Conservation: `R + sum(E) + P + F = initial native principal`. In shared mode,
  `sum(live private value) + sum(unpaid claim principal) <= R`; in P2PK mode the
  delivered ticket principal is outside the pool liability, with E retained
  only as an ownership/accounting bucket. Fees debit each origin once and only
  with its authorization; no fee appears simultaneously as paid and refundable.
- Exclusion/authority: no origin's value can be both live-private and newly
  claim-backed; no paid claim or native output pays twice; recipient/amount
  substitution never creates an accepted transition. Claims under extending or
  reordered roots retain one identity. Failed batches are atomic.
- State binding: old private membership may remain authentic, but consumption
  tests current NF state. After `AcceptBatch`, old-note private spend/reveal
  rejects. After an unrelated claim/root extension, an unpaid accepted claim
  remains claimable using fresh current state. Replaying an old current state,
  orphaned outpoint or wrong instance rejects.
- Shutdown: before acceptance, serviceOFF can strand an unaccepted private
  note safely if no independent authorization route is established; retain that
  counterexample. After acceptance, every feasible retained-data/key claim must
  have an owner-only terminal path with acceptance serviceOFF, without a fresh
  SNARK/prover/collector. This is existence of a fair, accepted native path, not
  a promise against indefinite transaction censorship.

Deliberate mutant toggles must produce short counterexamples; a harness that
passes everything is insufficient. Require at least:

| Broken rule | Expected shortest trace family |
| --- | --- |
| Omit original NF consumption at acceptance | AcceptBatch → competing PrivateSpend/conditional Reveal → Claim: duplicate source liability or release. |
| Drop pending liability or subtract claim principal without delivering it | AcceptBatch → RetireEmpty/Claim: lost backing or unaccounted disappearance. |
| Omit current spent-claim/native-output test | Claim → Claim: double release. |
| Make claim identity depend on mutable root/index | Accept root → pay → reorder/extend same entitlement → pay again. |
| Read spent state from historical witness | Pay → retry old witness/outpoint: second release. |
| Require a live service for an accepted claim | AcceptBatch → Shutdown: feasible backed claim has no owner-only path. |
| Accept substituted recipient/amount or wrong-instance root | Accepted record → forged Claim: theft/inflation or cross-instance release. |
| Treat q≤c as an executable positive payout | Quote rise/accept small q → Claim: economic shortfall, not saved by backing. |

In addition to exhaustive action exploration, use order/multiplicity
metamorphisms: distinct claims commute in balances and spent identities (their
native outpoint/root bytes need not commute); replaying one accepted identity
never commutes with paying it twice; equal-CM/different-position resources must
retain separate positioned NFs. These checks compare semantic histories, not a
second copy of transition code.

### Concrete source seams and next release gate

- Existing positioned note identity is `compact::nullifier` and v6 circuit's
  owner/HMAC constraints in `two_input/circuit.rs` (135–218). `Wallet::receive`
  hashes spending secret plus incoming key; `payout_key` derives a separate
  native key. An ordinary native payout signature is not currently committed
  as this note's ownership predicate. A safe revealing authority/NF binding
  remains unresolved; revealing the reusable secret is not silently accepted.
- `two_input::tree::PublicState::witness` authenticates old CM-root membership
  while checking/inserting NFs against its evolving current root. Its sequential
  insertion discipline is reusable as a model obligation, not as a model oracle.
- S7 `StateGate::evaluate` authenticates exact predecessor context in J336,
  checks current indexed NF insertion and four CM/two prefix-history appends,
  then derives `R'=R-fee`. It has **no entitlement root or unpaid-claim balance**;
  J336 and old immutable S7 cannot be reinterpreted as authorizing these claims.
- S7 `native::paired_settle`/`pair_body` enforce one continuing native reserve
  output and exact aggregate fee; `ordinary_settle` directly accounts payout,
  reserve and fee. Neither creates the proposed pending-claim state. Existing
  SHA256/Merkle folding, native signatures and output/amount/policy introspection
  are relevant primitives, but their presence proves no new script's soundness,
  size, full mass, fee or available-witness bound.

The proposed executable seam is an isolated stdlib model with finite symbols
and an independently reconstructed value ledger. It must not import wallet,
replay, proving or native transaction construction modules. After root freezes
an offline-only RFC/ADR and the model, produce retained complete search results
plus deliberately broken-rule counterexamples. Native script/proof experiments,
new note formats and an adopted architecture require separate review/release.


Source identity (SHA256 at the inspected commit):

- `poc/shared-pool/src/protocol.rs`: `5243cab1b36e0d9cae8bf13e81b7fcdb033c8dc1bc7405daa401c69334cc4ec4`
- `poc/shared-pool/src/compact/mod.rs`: `d59eb33bd27cfaf8cfdcb1780d09609e309b5bdbaf6f6fa6d7512981e030e5c3`
- `poc/shared-pool/src/two_input/circuit.rs`: `59071901c3abc25daab68c982ef065f8755c09abbb2ce30e6010d821813dd2a7`
- `poc/shared-pool/src/two_input/tree.rs`: `9fc004721ae2a22c6faa26f2a046eefd7bb707e3c83077be01a7913b464891ed`
- `poc/s7-owner-lifecycle/state/src/lib.rs`: `d0aa212a1652642d0b2475fac903e0ab18c8276317cc0107305b8d51fadd200f`
- `poc/shared-pool/src/s7_lifecycle/native.rs`: `7df243d9b94224e464cd2b49f60cbcce24b0ae2db649c89d7241fd3cdde689cb`


## Pre-runtime implementation refinements

[ADR-0039](../../../docs/adr/0039-exit-liability-and-native-claim-experiments.md)
selected the isolated [stdlib package](../../../poc/exit-liability-model/README.md).
The full implementation/config selection is
[freeze02](liability-model/source-freeze-02.json), SHA256
`3d72f799914df77a59bda810b939850bd1f7283f36cf0984d072fd1d19967dd6`.
The following details make the earlier proposal executable without treating its
bounds as broken-model admission guards:

- Root snapshots are cumulative **sorted** immutable records, with injective
  finite identity including positioned NF, recipient and principal. Extension
  can move an existing record's index. Stable spending identity remains the NF;
  no unaccepted malformed root is needed to expose a root/index-local-ID bug.
- Exact eight-way service/public-data/retained-current-witness products are
  enumerated at each financial state. Losses only disable financial actions;
  applying them after any maximally available prefix gives exact reachability
  without storing duplicate financial state. Quote1/2 remains inside BFS.
  Keys are assumed retained. Sufficient current witness/archive capability is
  an ideal premise, not a proved scanner/data-availability implementation.
- The independent Ghost ledger drives **every unpaid entitlement** liveness
  query, and exact immutable candidate representation must match it. Reviewer
  found that candidate-only iteration could hide a vanished entitlement while
  backing remained intact. Unused freeze01 and its full source snapshot are
  retained; it never ran. Freeze02 adds this cross-check and an eleventh
  missing-entitlement/backing-intact mutation control before runtime.
- `RetireEmpty` sets reserve0 and marks the empty pool retired. Its broken
  pending-liability guard abandons backing; no administrator is authorized.
  Normal three-claim/terminal limits arise from exclusion, not hidden phase
  guards that could prevent a mutant's second payment.
- Ancestor financial states are already inside the graph. Chain-only rollback
  closure is checked explicitly for eight availability/four knowledge products;
  it removes orphaned claim authorization but preserves outages and published
  secrets. This is not concrete Kaspa reorg validation. A separate unsafe
  credential-publication control works even without an accepted opening.
- Sensitivity BFS stops at its first counterexample. One separately labeled
  root/index-shift trace intentionally continues after its first backing
  violation to demonstrate a second accepted model payout.

The first source-frozen smoke configuration completed before the larger search;
its original result is reused rather than rerun. Complete results, failures and
resource limits are recorded separately under `liability-model/`; no result is
a current-format revealing-exit, native fee, cryptographic or full-lifecycle
qualification.

Additional explicit availability premise: native P2PK ticket UTXO/context is
assumed observable from the native UTXO set with retained owner key. The two
data-loss flags concern the shared entitlement current witness/archive. The
model does not establish native-node availability or recovery when every
copy of an owner output identity is unavailable.
