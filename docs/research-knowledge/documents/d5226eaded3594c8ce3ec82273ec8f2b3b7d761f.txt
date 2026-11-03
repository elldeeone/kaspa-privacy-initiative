# Privacy architecture: independent payments

**Status: prospective design for root/adversary review. No new heldout sample
or privacy implementation is authorized by this document.** Base source is
`5aaf99532d8714e510d421102df719f60f54d073`. The old 27-file package, 96 views,
thresholds, failures and public evidence stay immutable.

The next useful result is a falsifiable answer to three different questions:

1. Does one invoice expose unrelated outputs in the same authorization?
2. Can invoice knowledge and global spentness reveal later sender change?
3. Can a payment exit before a second real funding source avoid singleton
   funding ancestry?

Reducing the first disclosure does not answer the other two.

## Existing facts and the practical wallet candidate

The [completed study](../../compact-batch/privacy/heldout-study-01/REPORT-01.md)
recorded a correct payer-role guess for 248/248 other modeled outputs in each
complete wide C+1 cell. Public-C staggered wide histories forced the first
64/64 withdrawal ancestries across four clusters. These are application-role
and funding observations; neither is a human-identity proof.

The practical candidate exposes **one legitimate invoice per existing compact
private action, plus sender change or a zero dummy**. It uses the existing
serial relation. It is a safer wallet interface, not a new anonymity protocol.
A merchant's own invoice no longer supplies a direct label for 31 unrelated
payment recipients inside that action. The sibling still carries valuable
information: if positive, it is sender change under this wallet policy.

The selected preparation API currently requires positive sender change at the
Note floor; the observer must receive that fact. Zero/dummy change remains a
separate generic-relation control, not a valid call to that API.

The source/recovery canary is owned by `change_sources` in
`poc/independent-single-payment` and `privacy-wallet`. It must preserve exact
Auth/NF/CM/fee data, receiver original-backup recovery, sender-change recovery,
repeated one-invoice calls and terminal native obligations. A light public
canary is development evidence; new proof/native claims need their own gates.

A stronger observer must exploit the sibling change. If a later action cannot
consume the observer's own receipt (its original NF is absent), and all other
previous claims are spent or unavailable, that sibling is the only possible
positive input. The known sender role then propagates to a later invoice under
the declared sender-change policy. Fresh receiver/payout keys do not erase
this argument. It must be tested before claiming an improvement.

## Current public binding and candidate comparison

Each existing Auth528 binds an exact prior pool outpoint/state, reserve,
fees/payout/SPK, ordered CM digest, ciphertext digest and next state. Native
settlement publishes the corresponding ordered 2- or 32-output block and two
NF insertions. Each local proof conserves value over its own output partition.
The [source review](../sources/SOURCE-REFRESH.md) and the track-1 public harness
must determine any new settlement semantics; simultaneous proofs against one
state are competing successors, not an aggregate.

| Candidate | Actual dependency | Privacy conclusion allowed now |
| --- | --- | --- |
| Existing single-issuer wide32 | 32 genuine already-due invoices; current wide relation | Retains the observed invoice/cohort amplification. No fake users or padding counted as useful payments. |
| One invoice + change per compact action | Existing relation; explicit wallet acceptance/recovery policy | Limits direct same-action economic cohort size. Still vulnerable to change-chain, amounts, timing and sparse ancestry. Existing serial baseline, not a new privacy design. |
| Shared settlement of those local proofs | New exact accepted-state, fee, NF/currentness and output equations; track-1 gate | Can seek fee amortization. If public inner CM partitions remain, it does not remove their labels. |
| Separate spend/output proofs with global balance and hidden component assignment | New relation, authorization/binding specification, parameters and native/possibly Based-App settlement | A source-backed redesign family. No implementation, cost or privacy result is claimed. |

An outer event, public permutation or merged output array does not hide an
already disclosed component set. This statement is conditional on those sets
remaining public. If a redesign hides assignments rather than disclosing them,
it must prove exact once-only funding/coverage of the final output set; merely
verifying old public Auth digests against an unrelated final set is unsound.

## Source-backed hidden-assignment direction

[Source pins](../sources/SOURCE-PINS.json) cover current Kaspa, Orchard/Sapling,
PCZT, Aztec, RAILGUN, Monero and MWEB. Reuse established primitives and state
explicitly where composition is new.

**Separate components.** A local spend proof can prove ownership, membership,
original nullifier and a value commitment for an existing Note. A separate
output proof can bind a well-formed Note commitment and the same value to its
output value commitment. A final transaction-level balance equation covers all
inputs, outputs, authorized native payouts and fees. The current SHA-note
per-action conservation proof does not provide those interfaces.

**Owner-local authorization.** The owner must independently authorize the
complete final effect, including outputs, currentness, native destinations and
fee limits, without releasing its spend/owner witnesses. Sapling's separated
spend/output and authorization roles are precedents. PCZT does not solve
witness privacy automatically: the inspected prover role needs private data.
A coordinator must not become the owner prover by collecting those witnesses.
Orchard's [randomized SpendAuth signing/verification](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/builder.rs#L1698-L1789)
uses a common sighash; [ZIP244](https://zips.z.cash/zip-0244) defines full
transaction digest construction. An arbitrary caller-provided 32 bytes is not
proof that all outputs were bound. The current SHA-owner relation lacks this
randomized authorization-key/SpendAuthSig interface. Neither proof-of-knowledge
alone nor MWEB's narrower kernel message is silently substituted for it.

**Binding options, not a selected protocol.** Sapling/Orchard transaction binding
is one reference; a single builder's possession of all commitment trapdoors is
not an acceptable multiparty assumption. MWEB's independently signed excess
kernels and aggregate offset are another reference for merged input/output
sets. Publishing individual offsets or original grouped requests can restore
linkage. MWEB kernel signatures bind their documented feature fields; they do
not automatically sign this project's entire final effect. A whole-effect
spend authorization, input/output coverage, current NF validation and native
backing are additional explicit obligations here. No ad hoc threshold/MPC
signature protocol is proposed.

A concrete candidate specification must settle these points before coding:

1. Choose an established curve/commitment/signature suite and exact relation,
   with range bounds excluding modular value creation. New setup/Note/key
   formats and old-claim recovery implications require a new ADR and review.
2. Specify spend/output public inputs separately and exactly how the native
   policy verifies aggregate value balance and once-only coverage. Owner
   authorizations must bind the actual final effect, not a coordinator promise.
3. Specify construction/abort messages. Each owner verifies its requested
   outputs and fee before local authorization. A missing party can halt the
   batch; it must not release anyone else's reserve or create a privileged exit.
4. State who sees pre-aggregation groups and offsets. A coordinator/relay that
   receives labeled components may learn the grouping without learning spend
   keys. Public-chain privacy is not coordinator/network privacy.
5. Price permissionless fallback and availability. Common settlement and a
   Based App do not supply demand, accepted-head currentness, data retention or
   private unilateral exits automatically.

This is a protocol dependency proposal using established designs. It is not a
reviewed composition or an implemented privacy improvement.

## Unavoidable sparse boundary

Start with zero user reserve/liability. Before a target withdrawal, suppose
only one genuine independent funding source has entered. Under exact
nonnegative conservation, no outside subsidy and no privileged reserve path,
every positive liability/native payout in that prefix has that source as its
only possible original funding ancestor. Splitting or merging notes, using two
real inputs, partial cashouts, fresh keys, proof aggregation or output ordering
cannot introduce another source.

A future legitimate arrival cannot conceal an earlier event. Existing genuine
users may supply a different usage condition, but they must be actually present
and separately reported. No forced wait, compulsory balance, fake user, change,
fee credit or treasury may be counted as a useful independent payment. Timely
unilateral exit remains available and its actual privacy/fee limit is reported.

## Measurement scope and next gate

First freeze and run the finite public falsification controls in
[CONTROLS-PLAN-01.md](CONTROLS-PLAN-01.md): retained partitions, direct cohort
breadth, cross-action change propagation, singleton causality, and guards
against counterparty-to-origin substitution or one-real/full-only assumptions.
No old case is rescored.

The observer receives exact public action partitions, amounts/reserves/fees,
order/time, physical sparse CM positions, framing/ciphertexts, NFs, native
payout/SPKs, declared invoice policy and legitimate participant records. It
must not receive global private owner/purpose/source maps. A merchant may know
its invoice payer, own receipt/value/original NF and whether that NF appeared.
The known policy's positive-change ownership is a legitimate conditional fact.
Counterparty identity must never simply become original funding lineage: a
payer can spend value previously received from another funder.

Both protocol-capability and honest-wallet profiles must be explicit. The new
model must allow one or two real inputs and partial cashout/change in the
protocol profile. Nonterminal no-append/full-input mode, if selected under a
new profile, is public and cannot be omitted. A one-owner or one-real wallet
restriction is separately labelled, never a protocol-wide forcedness claim.

Global exact integer conservation, every-prefix backing and single spend are
required. SAT arithmetic/owner labels do not establish realizable cryptographic
alternative worlds or equal probabilities. UNKNOWN is incomplete, never forced
or private. Actual hidden-history compatibility is independently checked.

The old 45-KAS prior has analytic within-10% success 21103/100025 (>20%). The
uniform32 control and singleton ancestry already block original qualification.
Do not draw a large holdout to obscure those failures. If a genuinely changed,
implemented candidate later survives the public controls, size independent
sampling units for an explicit target as described in
[POWER-AND-FREEZE-01.md](POWER-AND-FREEZE-01.md), and obtain a root/adversary
freeze before any new heldout seed draw.
