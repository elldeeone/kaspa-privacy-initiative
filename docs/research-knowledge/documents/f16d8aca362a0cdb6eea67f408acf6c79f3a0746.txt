# Accepted exit liabilities and proof-free native claims: primary-source review

Reviewed 2026-10-22, official refs rechecked before 23:38 UTC; open PRs read
subsequently in the same review. Repository base
`8d7d719f18ae5975e651a4a114f8cecceb3e8b7c`; research only in this lane. This
extends the [earlier fee-alternatives review](../native-kas-singleton-fee-alternatives-2026-10-22.md)
with exact authorization, funding and witness boundaries. It does not adopt a
future note format or qualify the existing notes for a new exit branch.

**Answer:** current Toccata primitives can express a proof-free native terminal
claim **after its withdrawal entitlement has been authenticated and accepted**.
The official vProgs permission script is a concrete example, not merely an
analogy. That moves authorization work earlier; it does not give an unaccepted
private note a cheap independent exit. The unchanged vProgs script also requires
external fee funding, and its continuing-root path has a source-level binding
gap. Neither limitation should be hidden behind a small terminal script cost.

## Source identity and evidence level

Official GitHub refs were read through the connected GitHub tools. These are
source observations, not chain activation, accepted backing or runtime results.

| Source | Exact observed commit | Relationship to retained experiments |
|---|---|---|
| [rusty-kaspa master](https://github.com/kaspanet/rusty-kaspa/commit/4edcbbccb449f84832afb1ca157904b35f37d006) | `4edcbbccb449f84832afb1ca157904b35f37d006` | Nine commits after the executed native baseline; do not relabel old execution as current-master evidence. |
| [Native v2.1.0 baseline](https://github.com/kaspanet/rusty-kaspa/commit/01b532e8b553523216471682649693af92f0fd16) | `01b532e8b553523216471682649693af92f0fd16` | Native mass/signature/validator source used below and by the existing offline checker. |
| [vProgs master](https://github.com/kaspanet/vprogs/commit/f9b84a863a7c7c20586a9cf947550475e894f72e) | `f9b84a863a7c7c20586a9cf947550475e894f72e` | Exact permission emitter reviewed; evolving reference infrastructure. |
| [Kaspa research main](https://github.com/kaspanet/research/commit/c923faca11a49148fa7d912d27ce00197a5c5a4a) | `c923faca11a49148fa7d912d27ce00197a5c5a4a` | Research context, not an additional cheap native verifier. |
| [KIPs master](https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/README.md) | `e4ae2332117b5cb68bd6188e065ef885b6d17939` | Protocol proposals/status are distinct from this supplied-context experiment. |

The exact cached vProgs checkout is
`/home/luke/.cargo/git/checkouts/vprogs-12fa1eb54d96a3a2/f9b84a8`.
Its permission emitter SHA256 is
`f23c746cc15203e3f52c64dc66c2b651b688ddc49e62722a067b6178f5c13d5e`.
Its [Cargo.lock](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/Cargo.lock#L4322-L4324)
resolves native `9fdbaf1b1886fb5742783d2da73c36239bd6f272`, whereas our reusable
native checker uses `01b532e8…`. Crossing that boundary is an explicit source
adaptation requiring opcode/SPK/covenant compatibility checks and a new lock.

## Which state must the solitary owner have reached?

| Owner's state when services disappear | What remains necessary | Fresh singleton proof avoided? |
|---|---|---|
| Unaccepted private note; no withdrawal request accepted | Ownership and current spentness authentication, available note/state data, and an independently executable authorization/settlement route | **No conclusion.** A terminal claim mechanism does not create this entitlement. |
| Locally saved signed request, proof or settlement certificate | Actual native acceptance, its funding and any required settlement verification | **Not automatically.** Offchain preparation is not accepted reserve liability. |
| Accepted funded permission/ticket plus complete claim witness | Current outpoint, authenticated leaf/path and current-state data, fee capacity, native inclusion | **Yes for the final claim**, conditional on the selected script and correct funding. Prior authorization costs still count. |
| Ordinary native payout UTXO already created | Normal native spending authority and inclusion | Native self-custody; it has already crossed the shielded-to-transparent boundary. |

The acceptance point cannot be defined as merely adding a local database row.
The native reserve transition must authenticate the liability, prevent spending
the underlying note again, and preserve backing for **all unpaid liabilities**.
The abstract service-loss work models those obligations separately from script
validity. A service disappearing before authorization remains the decisive
counterexample to calling every accepted-ticket system an independent note exit.

## Existing vProgs mechanism: what is actually reusable

The [permission emitter](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/permission_script.rs#L1-L17)
implements public claims over leaves
`SHA256(LeafTag || destination_script_bytes || u64LE(amount))`. It verifies
membership, positive deduction, bound output0 destination, amount/rent rules,
remaining permission state and delegated funding. **It has neither a claimant
Schnorr signature nor a ZK call.** Anyone with the public witness may trigger a
payment to the committed destination. Copying that witness cannot change the
destination through this branch; a fee input signature is the fee payer's
authority, not evidence of private note ownership.
[Leaf/destination checks](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/permission_script.rs#L249-L349).

The earlier runtime withdrawal verifies its account lock, minimum and available
balance, debits the balance and emits the public destination/amount. The verified
batch aggregation commits emitted exits into the permission script hash.
Those are the earlier authorization steps; a public claim does not repeat them.
[Withdrawal processing](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/runtime-processor/src/action/withdraw.rs#L31-L64),
[verified exit accumulation](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/abi/src/batch_aggregator/verifier.rs#L99-L137).
This source is an account-runtime withdrawal entitlement; it does not establish
our private-note ownership/nullifier relation or accepted native reserve backing.

**Funding restriction:** continuation rent is preserved exactly; on the final
claim output0 must pay at least `deduct + permission_input_value`. Recognized
delegate input value minus deduct must become the prescribed delegate change.
For the intended accounted inputs, all permission/delegate value is therefore
assigned to mandatory outputs. Positive miner fees need an additional
nondelegate fee input. There is no unchanged-script deduction of fees from the
authorized principal. The default 50M permission seed is separate protocol rent;
its final refund is not free fee capacity or part of the 60M claim principal.
[Payout/rent](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/permission_script.rs#L407-L509),
[delegate accounting](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/permission_script.rs#L514-L614),
[seed and settlement funding](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/covenant/src/settlement.rs#L68-L135).

**Continuing-root reuse blocker:** the emitter authenticates one old Merkle
walk, then consumes a second walk to compute the replacement root. The source
does not retain/check equality of their siblings and directions. The test helper
duplicates the path by host convention. Binding output1 to the resulting new
root does not establish that only the authenticated leaf was updated. This
source-level missing relation was independently confirmed; no hostile witness,
VM experiment or complete-system exploit was produced.
[Separate walks](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/permission_script.rs#L352-L380),
[consuming Merkle step](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/permission_script.rs#L623-L635),
[host witness convention](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/test-suite/tests/permission_spend.rs#L155-L179).

A **count1→0 full terminal claim** discards the computed replacement root and
requires no continuation. It can isolate terminal cost without relying on
preservation of another entitlement. Use the normal accumulator's depth1:
`required_depth(1)=1`. Depth0 is not its ordinary emitted profile.
[Terminal branch](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/permission_script.rs#L423-L450),
[normal depth rule](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/core/merkle-tree/src/streaming_builder.rs#L62-L72).
This narrow example is not endorsement of the continuing permission tree.

## Data availability is part of the exit credential

An owner needs the accepted current permission outpoint/redeem/root/count/depth,
destination/remaining amount, leaf position and siblings, and available matching
delegate backing. A shared mutable root requires updated witnesses after other
claims, or sufficient available update data to reconstruct them. A state hash
alone cannot supply that information. Fee inputs must also be available under
the unchanged contract.

The reviewed settlement journal and aggregate artifact carry
`permission_spk_hash`, not a complete owner claim export. Those types establish
the commitment boundary; they do **not** establish durable delivery of every
leaf/path or recovery when the service is gone.
[Journal fields](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/abi/src/batch_aggregator/journal/state_transition.rs#L8-L35),
[settlement artifact](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/aggregate-prover/src/settlement_artifact.rs#L9-L33).
Checking a supplied UTXO entry with native Full validation is likewise not a
proof that the entry is current, unspent, accepted or sufficiently final.

The established comparison is Aztec's released Outbox: only its rollup inserts
roots; claim consumption checks an existing root, recipient/chain, membership
and a consumed-leaf bitmap. The terminal operation has no new SNARK, but prior
root authentication and message/path availability are prerequisites. This is
the same cost-location distinction, not a Kaspa implementation recipe.
[Aztec v5.2.0 Outbox, commit49a5921](https://github.com/AztecProtocol/aztec-packages/blob/49a592109ec4f18d79212b43d621891aaf36f7b6/l1-contracts/src/core/messagebridge/Outbox.sol#L103-L169).

### Relevant unmerged vProgs work

Current public PR search found concrete work on the missing client seam. The
following PRs were **open**, and their exact heads are separate from master and
from the selected cost probe. Their reported tests were not executed here.

| Open work and exact head | Source observation and limit |
|---|---|
| [PR139: claim builder and exit feed](https://github.com/kaspanet/vprogs/pull/139), `5a2e855853300378f3e434a5461c69156e74a657` | Public `permission_sig_script`, `build_permission_spend` and path construction; a per-bundle channel carries the full canonical leaf list. The builder expressly documents zero-fee transactions that may fail minimum-relay policy. |
| [PR138: permission watcher/index](https://github.com/kaspanet/vprogs/pull/138), `1fee04f4790b161601c370c671e3163ef79bef2d` | Tracks permission outpoints and pairs exits with settlements. Also changes native bytecode to exact payouts plus a trailing nondelegate collateral input/change fee lane: depth1 redeem489B, not master's467B. It remains externally fee-funded. |
| [PR146: reorg handling](https://github.com/kaspanet/vprogs/pull/146), `42353f2efe0fe577a47fe984a4006ee9661fa4eb` | Journals/reverses settlement pairing and permission spends by chain index. The journal is in memory; the source explicitly retains a restart-within-reorg-window limitation. |

The [PR139 feed type](https://github.com/kaspanet/vprogs/blob/5a2e855853300378f3e434a5461c69156e74a657/zk/aggregate-prover/src/exit_feed.rs#L1-L33)
is useful existing work to study for owner exports; a host channel is not by
itself durable owner-held data availability. Its
[builder contract](https://github.com/kaspanet/vprogs/blob/5a2e855853300378f3e434a5461c69156e74a657/zk/backend/risc0/app-kit/src/claim.rs#L46-L97)
supports the fee restriction above rather than eliminating it. The PR138
[watcher checks path equality](https://github.com/kaspanet/vprogs/blob/1fee04f4790b161601c370c671e3163ef79bef2d/l1/bridge/src/permission_watch.rs#L121-L174),
but its [native emitter still consumes independent walks](https://github.com/kaspanet/vprogs/blob/1fee04f4790b161601c370c671e3163ef79bef2d/zk/backend/risc0/api/src/permission_script.rs#L357-L385).
Offchain watcher filtering does not establish the missing native continuation
relation. The [PR146 journal caveat](https://github.com/kaspanet/vprogs/blob/42353f2efe0fe577a47fe984a4006ee9661fa4eb/runner/src/exit_index.rs#L264-L272)
also remains distinct from permanent service-loss recovery. These are candidates
for selective source reuse/review, not a reason to silently replace the frozen
master emitter or claim a complete exit system already exists.

## What current native primitives can and cannot enforce

Toccata has native SHA256/Blake2b, script construction and transaction
introspection for actual input/output amounts and script bytes. Existing vProgs
uses those operations to hash authenticated data and bind payout/successor
scripts. P2SH validates the supplied redeem preimage against the spent output;
copying an arbitrary state root into a witness does not authenticate it.
[Actual-context opcodes](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L1100-L1174).
UTXO consumption gives single use of that accepted outpoint; a covenant ID
indexes authorized inputs/outputs, but does not by itself prove conservation or
that unrelated leaves survive. These remain explicit script/accepted-state
obligations.
[Covenant-context construction](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/covenants.rs#L96-L161).

Native Schnorr can bind an owner to a transaction. **CheckSig does not force
SIGHASH_ALL:** it supports the allowed hash flags. ALL commits the inputs,
actual current input SPK/amount, outputs and header data according to its
defined hash; nonempty native payload is included. Version1 computeBudget is
excluded, and the witness is not directly signed. A future policy depending on
whole-transaction authorization must enforce its intended flag and independently
validate witness semantics. CheckSigFromStack verifies a supplied message hash;
the script must connect that hash to actual transaction intent.
[Flags](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/hashing/sighash_type.rs#L6-L23),
[signed fields](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/hashing/sighash.rs#L250-L284),
[payload](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/hashing/sighash.rs#L185-L198),
[stack-message signature](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L1438-L1445).
Known script version0 must be selected: unknown higher SPK versions follow
forward-compatibility behavior, not evidence that the intended script executed.
[Version handling](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/lib.rs#L650-L665).

Hash/Merkle work is metered by bytes and runtime stack creation, with native
signatures charged separately; it does not inherit the Groth16 tag tariff.
Nevertheless complete serialization, committed compute, transient mass and
KIP9 contextual storage all count. A small remaining reserve/change output can
dominate cost. The [cost envelope](COST-ENVELOPE.md) records the exact integer
equations and source-only upper bounds; it is not measured script execution.
[Native mass implementation](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/mod.rs#L335-L512).

## Revealing a future private note is a separate design question

The present v6 opening commits `owner,incoming,value,rho`, while owner derivation
and the positioned nullifier depend on the reusable `wallet.spending` secret.
Native payout keys derive from a separate native master and are not bound by
that owner commitment. Revealing the current spending secret would expose
reusable authority and nullifier privacy; revealing only the sender-known
opening proves neither ownership nor the correct current nullifier.
[Existing commitment/keys](../../../poc/shared-pool/src/protocol.rs),
[v6 private ownership/nullifier relation](../../../poc/shared-pool/src/two_input/circuit.rs),
[positioned nullifier](../../../poc/shared-pool/src/compact/mod.rs).

A separately adopted format might commit a note-local emergency native key and
fixed destination, and use existing hashes/signatures. Expressing those checks
is not a new primitive. **A complete compatible note/authority construction has
not been established here.** In particular:

1. The sender must not learn a nullifier precursor that makes ordinary private
   spends publicly recognizable. Orchard illustrates the underlying requirement:
   its nullifier derivation depends on the spender's secret nullifier key, not
   merely sender-known note randomness. Its curve construction is not a drop-in
   native-SHA proposal.
   [Orchard616a669, nullifier specification and derivation](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note/nullifier.rs#L1-L81).
2. **An emergency signature alone does not protect the other branch.** If the
   revealed secret is sufficient to authorize a private spend, an observer can
   race that same note through the private branch to another output. A shared
   nullifier prevents two successes but does not guarantee the rightful branch
   wins. Note-local scope only limits sibling exposure. The independent private
   authority or exclusion semantics remain an open design obligation.
3. A native Merkle opening must share the exact current spentness state with
   private spends, bind the immutable policy and destination, conserve all
   unpaid liabilities, and survive stale-root/reorg/withheld-witness conditions.
   A sender-created note must be checked against the recipient's intended key;
   a receive descriptor is not magically single use.
4. Revealing note position/value/path and timing can violate the durable privacy
   target. Existing RFC0012 permits investigating a revealing immediate exit;
   it does not erase effects on other users or relax the fixed observer gates.
   [Privacy requirements](../../../docs/rfc/0012-useful-privacy-requirements.md).

No old commitment, verifier key or immutable policy can acquire this format by
documentation or adapter. This review selects neither a new format nor a rescue
authority.

## Smallest useful next experiment and remaining decision

[ADR0039](../../../docs/adr/0039-exit-liability-and-native-claim-experiments.md)
authorizes a separately scoped offline diagnostic. Reuse the official public
emitter rather than reimplementing its bytecode: API `default-features=false`
exposes permission/tree/delegate functions without host/guest/CUDA; its build
script only precomputes SHA empty-tree hashes. The upstream full test suite
enables proving dependencies and is not the minimal harness.
[Feature graph](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/Cargo.toml#L6-L56),
[public exports](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/lib.rs#L32-L37).

The selected proposal is normal depth1, one60M liability, full terminal claim,
separate50M permission rent, matching60M delegate backing and an explicit signed
external fee input. Use native isolation then Full on supplied public UTXOs,
separate source-adapted relay/fee checks and actual contextual mass. Freeze exact
case semantics before execution: wrong payout/path/amount/domain/backing,
invalid fee signature, duplicate input, and claim-funded-fee underpayment.
Retain the zero-fee consensus case separately from positive-fee policy. No
continuing-root qualification, hostile continuation fixture, proof generation,
funding/broadcast or old owner/replay workflow is needed.
The [probe plan](NATIVE-CLAIM-PROBE-PLAN.md) owns implementation details and any
later runtime evidence; **this note records source/design findings only**.

The decision that would remain after a cheap measured claim is substantial:
who can independently authorize and publish it before services disappear, what
data the owner already possesses, and who pays the earlier authorization plus
terminal fees. Existing 147,500-gram fresh-proof floor at scenario500 remains
73.75M before transaction overhead, exceeding60M. The full10-KAS lifecycle fee
target, earlier proving-time failures, and failed21.09772557% versus20% privacy
prior remain unchanged. Earlier paid80M pair fees are not repriced by a cheaper
necessary quote. Accepted liabilities can relocate/amortize authorization cost;
they do not yet close complete native-KAS private payments with independent
exits before authorization.
