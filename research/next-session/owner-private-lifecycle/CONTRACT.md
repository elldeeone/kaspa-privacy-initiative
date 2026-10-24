# Integrated lifecycle financial and recovery contract

2026-10-24 UTC. Implementation selection under
[ADR-0064](../../../docs/adr/0064-owner-private-native-kas-lifecycle.md) and the
root-selected [interfaces](INTERFACES-01.md). This document records agreed
financial meaning and canonical interfaces. It is not execution evidence.

## Identity and unchanged primitive semantics

The exact fixed domain is
`be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480`,
SHA256 of ASCII `KPX8 owner-private native KAS lifecycle v1 / TN10 RESEARCH ONLY`
without newline. The selected network is TN10, not mainnet. Every role/parser,
key manifest, profile, wallet backup, body/state and native policy must agree on
this domain before private inputs are opened.

Retain the reviewed Note168/Invoice208/Receipt216/CF264 encodings, domain-tagged
SHA note/owner/key commitments, positioned HMAC original NF, depth16 CM tree,
depth17 indexed NF tree, explicit integer sompi and the selected Arkworks0.6
BabyJubjub Pedersen setup from the
[ADR-0063 primitive contract](../owner-private-prototype/CONTRACT.md).
Only new domain/role identities are selected; old programs/profiles/keys are not
compatible authorities. The fresh Spend/Output/Exit setups use private OS
entropy, not the public transparent-generator seed. Public proving-key delivery
must exclude secret setup randomness and owner witnesses.

All real note values remain in
`[60_000_000, 2_870_000_000_000_000_000]`. Native payout floor is 10,000,000 sompi,
distinct from the private-note floor. Fees are positive bounded integer sompi.
Use checked integer sums before field/group conservation; no field reduction,
float, string/int cross-comparison or overflowing sum is an amount check.

## GN3 admitted backing

The exact 1,576-byte public frame is:

```text
KPX8GN01 | final_profile_SHA25632 | D32 | trial_UUID16 |
three ordered (Note168 | CM32 | CF264 | SHA256(CF)32) records
```

There are exactly three distinct ordinary noncoinbase, noncovenant P2PK funding
sources. Each source owner independently checks the whole frame, its immutable
initial record and locally recoverable receipt, exact canonical headers/outputs,
funding point/context and own integer fee allocation before signing only its
own source with native SIGHASH_ALL. V1 budgets require explicit complete-body
approval because transaction ID/signature hashing omit them. The combiner
receives signatures and approvals, never funding keys or shielded seeds.

Admitted CMs occupy positions0,1,2. The CM cursor n is3; NF count m is1 with the
empty indexed sentinel. Reserve R equals the checked sum of the three admitted
values. Output0 is exactly State112 plus the externally selected immutable native
tail at reserve R. Other outputs are positive ordinary changes to their own
sources, in source order; no coordinator/sponsor withdrawal output is allowed.
For total native fee F, shares are `[F//3,F//3,F-2*(F//3)]`; each input equals its
note value plus its ordinary change plus its share exactly.

The complete initial Note168 is public, including owner/incoming fields, value,
rho, key commitment and native key. This is the transparent admission boundary;
it is not an initially private claim. Ordinary source keys are derived owner
locally from the same immutable seed at reserved existing-derivation index
`0xffffffff`, so ordinary change recovery does not need a second private backup.
That index is unavailable for invoices, payments or exits. Exits use fresh other
indices according to the exact derivation below.

Profile SHA includes actual selected public financial/software identities but
not a trial or founding point. Component profile is compiled before guest/image;
the final profile is selected afterward. No self-image/tail/profile hash cycle
is accepted. A signed/native-valid funding transaction establishes acceptance
only after actual accepted-chain acquisition and currentness verification.

## Mixed payments and recipient recovery

Each genuine round has three private input notes, six positive independently
proved complete outputs, and a single continuing reserve. Preserve the prior
Spend200 and Output168 layouts with tags `KPX8SP01` and `KPX8OU01`, D fixed above.
The selected live malicious MP-SPDZ/MASCOT sort and private scalar sum operate on
the same whole-tuple schema and exact subgroup field. Session/program/roster
bindings and private per-owner beta contributions remain owner-local. Reveal
only the complete mixed tuples and global Delta.

Owners recompute complete effects, all Output proofs, delivery inclusion,
current state, reserve/fee and global balance before producing effects-bound
Spend proofs. Fresh input commitment randomness needs no old output blinding.
The guest verifies all nine proofs, indexed original-NF updates and sequential
CM appends under the exact component profile. The native policy independently
binds the actual predecessor, state, reserve, outputs and guest claim.

Each round changes `(n,m)` by `(6,3)` and
`R_after = R_before - fee`. The actual proof witness stays outside the effects
preimage; complete Output proof bytes remain included. Valid Spend-proof
rerandomization does not change financial authority. A stale authorized body
may still settle after timeout, so attempts must reconcile current accepted
state before reusing any input.

Original shielded backups plus authenticated accepted public admission/output
ciphertexts and CM/NF history support owner-local recognition. Invoice indices
are recovered from encrypted receipts rather than an operator map. Recipients
must decrypt, reconstruct invoice/note/CM and verify genuine Output proofs
before treating delivery as received value. Public READY exposes participant,
session, NF and CVin, never recovered note CM/position or private output tuples.
No public count-only diagnostic is a product authorization API.

## One-owner direct full-note exit

The exact public Exit statement is 152 bytes:

```text
KPX8EX01 | D32 | anchor_CMroot32 | NF32 | effects32 | payout_u64LE8 | fee_u64LE8
```

Its witness is the owned Note168, owner/nullifier secrets, original physical
position and CM path. Prove ownership, accepted hidden membership, stable
positioned NF, bounded note value and exact integer `value = payout + fee`.
There is no CV opening, new private output, other participant or outer RISC Zero
prover in this exit path. The native policy pins the new Exit VK and reconstructs
its own expected statement. Proof128 is in the native input witness only.

The payout is a fresh owner-controlled native key rather than the consumed
note's invoice key. For counter values0 through `2^32-1` in order, compute
`SHA256(KPX8EP01|D32|actual_reserve_point36|original_NF32|counter_u32LE)` and read
its first8 bytes as unsigned64 little-endian index. Select the first index not
equal to0, `0xffffffff`, the consumed note's original index or another known
own invoice index. Derive the native key through existing `Receiver.keys(index)`.
Refuse counter exhaustion; do not fall back to a reserved/reused key. The
existing seed derivation and authenticated public history reconstruct this key
after restoration. No private payout-index map is a recovery prerequisite.

The native author's agreed Exit body is exactly 1,632 bytes:

| Offset | Bytes | Field |
| --- | ---: | --- |
| 0 | 8 | `KPX8XB01` |
| 8 | 8 | u16LE version1, spend1, output0, mode1 |
| 16 | 32 | D |
| 48 | 32 | nonzero session |
| 80 | 32 | reserved zero |
| 112 | 36 | actual previous txid32/index_u32LE |
| 148 | 112 | old State112 |
| 260 | 8 | old reserve |
| 268 | 112 | new State112 |
| 380 | 8 | remaining reserve |
| 388 | 8 | fee |
| 396 | 8 | payout |
| 404 | 36 | exact payout SPK |
| 440 | 32 | original NF |
| 472 | 1160 | indexed NF absence/insertion witness |

Payout SPK is exact36 bytes: version u16BE zero, `OpData32` (`0x20`), x-only
key32, `OpCheckSig` (`0xac`). Canonical native projection tag is `KPX8FX01`.
Prefix is240 bytes for continuing exit (reserve successor plus payout),192 for
terminal exit (one payout), and193 for a mixed batch. Actual output ordering,
amounts, SPKs, absence of output covenant metadata, predecessor point, sequence,
header and full payload are reconstructed from native introspection. A host
supplied projection is never financial authority.

For exit, `effects = SHA256(KPX8EF01 | canonical_native_prefix | body1632)`.
The complete body contains no Exit proof, so there is no proof/hash cycle.
Native CM root/cursor remain unchanged, NF count increases by1 with the exact
authenticated indexed insertion, and
`remaining_reserve = old_reserve - payout - fee`. Positive remainder continues
under the identical immutable policy; zero remainder has no reserve successor.
Changing payout, destination, fee, predecessor, state, NF witness or mode must
invalidate the original proof/body combination.

For valid selected history, semantic live-note count U satisfies
`m + U = n + 1`: initial `(3,1,3)`, round delta `(6,3,3)`, exit delta `(0,1,-1)`.
A live note therefore has room for its single NF insert even at full CM
capacity. No exit requires a CM append. This is an induction over valid selected
history, not authentication of an arbitrary supplied prestate.

A previously authorized mixed body may remain valid after its coordinator
disappears. Preserve its durable disclosure barrier and do not reopen its maps.
Conservative restrictions on a new mixed retry must not block direct exit of a
still-current unspent note. A direct exit uses the same original NF and latest
authenticated reserve point; whichever conflicting native spend is accepted
first prevents the other. Exit construction does not revoke the old body.
Retain focused controls for authorized-but-unsettled mix followed by direct exit,
and for fresh seed-recoverable payout keys distinct from reserved/invoice keys.

## Accepted history, infrastructure loss and completion

Public reconstruction starts at actual GN3 and follows physical native
successors with complete accepted bodies/contexts, proof/native verification,
removed/added history, UTXO observations and fresh race/reorg reconciliation.
Pruned/missing/conflicting bodies, ciphertexts, sources or latest-head evidence
remain INCOMPLETE. Trusted validating RPC observations and selected software
remain explicit premises; a second URL is not independent consensus.

Stop the original coordinator and shared outer prover, then use fresh owner
clients to retrieve/authenticate public software, full history and complete
proving keys and produce direct exits. Loss isolation requires the original
paths/services to be unavailable in those clients. Real separately administered
storage requires configured external control and actual retrieval; a personal
Drive, local copy, same-admin GitHub release or fixture does not establish it.
Do not erase private originals or public recovery objects to simulate loss.

All new owner/MPC/controller-private material stays beneath the declared
`/var/tmp/kpi-owner-private-lifecycle-01/private` parent. Supervisors inspect
private metadata only. Old original backups and all private maps remain outside
root reads, hashes and publication. Public evidence uses explicit typed
selection; it must not publish owner-to-note/receipt/payout correspondence.

Complete the genuine local route before live funding. A fresh testnet identity
requires no new setup. A used broadcast intent is immutable and submitted once;
uncertainty requires read-only reconciliation. Actual confirmed native payouts,
zero remaining user liabilities/reserve, all claimed backups reconciled and a
complete integer source/change/payout/fee ledger are the financial completion
criterion. Acquisition and every independent exit count in the fee total.
The existing 2% fee target is a separate verdict; change/refunds are not extra
useful payments. This execution does not run the expanded step4 privacy study
or establish a cryptographic privacy theorem, production security or indefinite
data availability.
