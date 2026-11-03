# RFC-0018: Paired native settlement experiment

**Status:** Open — source/design proposal; no settlement implementation or
execution release. **Date:** 2026-10-23 Australia/Sydney.

**Question:** can a new immutable test pool combine two independent zero-payout
v6 SPENDs into one atomic native transition, while each owner retains a direct
exit that needs neither another user nor an outer prover?

This proposal preserves native KAS backing and all security invariants. It does
not migrate or upgrade an old reserve, adopt a production architecture, introduce
a token, grant a rescue key, or claim privacy, settlement or recovery evidence.
Review this RFC before prototyping. Funding/broadcast remains a later gate.

## Established boundary and missing assertion

The [two-v6 package](../../poc/two-v6-binding/README.md) checks two real inner
proofs, common private count/anchor, four distinct nonzero NFs, exact complete
CM/ciphertext records and fees. Its exact public bytes are P[1,088];
`J = "KPI2V6J1" || u16le(1) || SHA256(P)` is 42 bytes. Native receipt
verification must use **SHA256(J)**, not SHA256(P), with the independently fixed
image/control, successful final claim and no unresolved assumptions.

That statement omits authenticated history, current spentness, successor state,
actual reserve amounts and owner exits. In particular **the existing receipt
does not bind a publicly supplied anchor to its hidden witness**. Appending a
host-selected count/anchor/Merkle path beside J does not repair that omission.
Another valid partition with the same P is allowed by the original contract.

The compatible pair uses a separate public development instance: domain
`d47cb91ef9ac74dda71c7db1519381526c3dfac5f525b904f744b97a7df713bd`,
VK SHA256 `2a9acd1639fb7b454384c65fb317a139695f5a2cbb3ebd941dd13b5f6045a2f4`.
It has synthetic count 3/history, and its test proving key was not retained.
It cannot be relabelled an accepted native pool or used to generate new exits.
The original rehearsal's missing compatible pair remains a separate gap.

## Minimal alternatives

| Option | What it establishes; disposition |
| --- | --- |
| Two ordinary v6 settlements | Existing direct Groth16 proofs can use the same historical anchor sequentially, updating current witnesses between them. Useful control; exposes original groups, is not one atomic paired transaction and does not make J settlement authority. |
| Receipt plus both disclosed original bundles, reverified natively | **Rejected as a valid transaction candidate at the native pin.** The verifier floor is 250,000 + 2×147,500 = 545,000 compute grams, already above the 500,000 block cap before payload/state work. It may be retained as a standalone composition/mass negative, never a positive native settlement. Extra fees cannot repair that limit. |
| New state-aware guest and native adapter | Proposed next complete composition. Reuse the checked two-v6 relation, authenticate the common anchor against the actual prior history root, apply four NF/CM updates, and bind the complete transition in a **new journal/image**. One native outer verification replaces two direct native inner verifications. Additional outer proving is required; old J cannot substitute. No new inner setup is needed to reverify the existing public pair. |

A guest exposing count/anchor in an amended journal is another possible
composition, with a new public equality handle and privacy review. It is not
the existing 42-byte contract. A guest that merely verifies the old receipt
then accepts unrelated supplied authorizations is rejected: existential P
binding does not authenticate those authorizations' anchors. A universal runtime
or privileged collector is not needed for the scoped experiment.

The rejected floor follows the pinned `zk_precompiles/tags.rs` costs and
Groth16's three-IC tariff; `TESTNET_PARAMS.block_mass_limits.compute` is 500,000.
An officially supported Groth16-wrapped outer route would have a different
floor (450,000 for the same three checks), but would need its own proof/mapping
qualification and still has no demonstrated full-transaction fit. It is not a
silent fallback. The selected single R0Succinct route has a 250,000 verifier
floor; its complete transaction size/mass/fee fit remains to be measured.

## Proposed transition and native obligations

Use a fresh explicit pool descriptor, domain/VK, state version, immutable script
and independently expected guest/control identities. Its initial reserve and
liabilities must be authenticated by its own genesis/admission rules before
any later funded trial. A synthetic state root is not evidence of that history.

Let the actual input-0 reserve be R, prior state
`S=(n,m,CMroot,NFroot,HistoryRoot)`, and P expose aggregate fee F. The paired
branch must enforce all of these, atomically:

1. Exactly one tracked reserve input and one continuing reserve output; native
   v1, fixed lane/subnetwork, sequence and metadata policy. No admission, payout,
   sponsor input, operator withdrawal, zero-valued reserve or extra output.
   Derive predecessor outpoint, R and locking-script identity from native
   introspection; never accept a host success flag or receipt metadata.
2. Bind complete P to the new J_state and selected state-aware image/control.
   The existing J42 image is not a settlement image. Fix the
   expected domain/VK in the program and covenant, never in prover input.
   The guest verifies both original A/Q/C bundles, exact SHA256 authorization
   limbs and original ordered ciphertext hashes, and their complete bijections
   to P, before applying state rules. All four public records remain available.
3. Authenticate the actual proofs' common `(a,anchor)` with
   `history_leaf(a,anchor)` at index `(a-1)/2` under **S.HistoryRoot**;
   require odd `1 <= a <= n`. A current root match alone does not validate an
   arbitrary historical anchor. No changed root/count is accepted by relabelling.
4. Insert every P.NF once into the **current** indexed NF tree, with four
   sequential authenticated predecessor/empty-slot updates. New count is m+4;
   insertions use indices m+1…m+4 after the sentinel. Reject an NF already
   present, including replay after another paired or direct-exit branch.
5. Append P's four complete records in their public sorted order: CM positions
   n…n+3, with original CM/ciphertext pairing and duplicate-record multiplicity.
   Verify each prior empty slot and intermediate root. New CM count is n+4.
   Ciphertext availability and wallet position assignment follow this order.
6. Use checked integer sompi: `F <= MAX_SOMPI`, `F < R <= MAX_SOMPI`,
   `R' = R-F > 0`. Output 0 must have exactly R' and the exact successor script
   with all immutable policy/exit pins preserved. Actual native transaction fee
   is exactly F. Inner private liability falls by F; this preserves backing
   **conditionally on an authenticated backed predecessor**, not from a balance
   declared in a fixture. The wider u128 P fee range alone is not native solvency.

For native arithmetic, require P's upper eight fee bytes zero and check the
lower u64 against MAX_SOMPI before comparison/subtraction; never truncate u128
or compare a JSON number/KAS float to sompi. The paired and owner branches need
unambiguous version/framing/selectors; a selector is not an authority or bypass.

P's NF order is unsigned lexicographic **raw-byte** order. The existing indexed
set's `less`/`less256` uses **little-endian numeric** order. Preserve that native
predecessor comparator; do not substitute P sorting. Insert in public P order
while constructing each predecessor witness against the then-current root.

## Four appends and honest history semantics

Current v6 state is 105 bytes: version, two u32 counts and three roots. Its
history has one leaf for every odd commitment prefix:
`history_leaf(2*i+1, prefix_root)`. Thus `history_count=(n+1)/2`, and
`PublicState::compact` requires exactly that many roots and the final CM root.
These equations are not a transaction counter.

**Proposed minimal convention:** retain the five fields and hash/path algorithms
in a **new versioned state/covenant** (proposed state discriminator `0x07`,
subject to the descriptor/version review), and append two history leaves:

```text
h = (n+1)/2
r2 = CM root after sorted P.O[0], P.O[1] at positions n,n+1
r4 = CM root after all four records at positions n…n+3
History[h]   = history_leaf(n+2, r2)
History[h+1] = history_leaf(n+4, r4)
```

Both updates must prove the old history slots empty and chain their intermediate
history roots. Require n+4 < 65,536 and all NF/history capacity bounds; preserve
odd n, even m, and the existing state range checks. For the count-3 fixture the
new leaves are count 5/index 2 and count 7/index 3, with final count 7.

This is sound only with the explicit definition **accepted commitment-prefix
history**. r2 is a prefix of four records accepted atomically; it is not a
separately accepted native state, reserve checkpoint or transaction. Future
membership proofs may use that prefix after the whole pair settles. It conveys
no private bundle partition because its first two records are publicly sorted.
The proposed semantics must be reviewed, rather than silently attributed to
unchanged v6 consensus or replay code.

Appending only r4 to the old layout is rejected: the implicit index/count
formula then labels count 7 as 5 and `compact` fails. Treating n+2 as an
intermediate settled reserve is also rejected. If history must represent only
transaction-end states, use a genuinely new format with explicit history count
and explicit `(count,root)` records/index witnesses, updating native checks,
replay and wallets. That is a larger alternative; old code cannot infer its
history length from CM count. No decision here changes deployed v6 bytes.

## State-aware guest continuation and independent exits

For the hidden-witness option, the guest must check both inner proofs and the
same P binding **plus** historical membership and all state updates. Native code
must bind the supplied predecessor state to input 0, rather than trust a prior
root because the guest echoed it. One concrete proposed new journal is:

```text
"KPI2V6S1" || u16le(1) || SHA256(P)[32] || fixed_pool_id[32]
|| actual_prior_outpoint[36] || prior_state[105] || next_state[105]
|| u64le(R) || u64le(R')                         # 336 bytes
```

`fixed_pool_id` is independently selected before script/program construction,
not derived circularly from a transaction containing that script. Native code
reconstructs the exact journal from current input/state, P and proposed output,
checks SHA256 of those bytes, and pins the independently expected new image and
compatible final control. This is a proposed serialization for review, not an
implemented image, receipt or compatibility result. The old 42-byte receipt may
remain diagnostic evidence but cannot replace this transition assertion.

The new immutable reserve must also have a **direct owner DRAIN branch** using
the same inner relation/VK and authentic historical prefix/current NF checks.
It must work without a paired receipt, collector signature, service, other user
or outer prover; insert its two NFs, create no new commitments, bind the owner's
destination/payout and fee, and enforce exact positive-change or terminal drain.
Every branch must continue the same policy and shared NF/history state. There
is no weaker alternate exit, grace-period operator key or old-pool migration.

This reuses DRAIN's rules, not its current byte offsets or successful execution:
new state/version/suffix, witness and replay formats require new qualification.
Owners need authenticated public records/positions, their backups and durable
public proving parameters, or genuine previously prepared authorized exits.
The current development fixture has only SPEND proofs and no retained PK;
public wallet labels do not manufacture new DRAIN proofs. Consequently it
cannot demonstrate exits or justify funding. A later funded candidate needs a
separately qualified parameter/exit plan and genuine post-pair owner withdrawals
after collector loss. Preserve this as a blocking requirement.

Capacity must reserve the direct path, not merely admit the paired path. A
candidate reachability bound is `positive outstanding notes <= n-m/2`: one
initial note, at least one real input per active proof, two appended slots per
SPEND and two inserted NFs per proof. Authenticated ADMIT adds at most two
positive notes with n+2 and no NF insertion. A pair preserves the bound with n+4/m+4;
a DRAIN consumes at least one note with n/m+2. This argument and every branch
must be independently checked against genesis, dummy slots and conservation.
It would imply space for two NFs whenever a positive claim remains, including
at CM capacity; an arbitrary syntactically valid state does not establish it.
Require that boundary test before funding. No spent-CM/ciphertext deduplication
is permitted: equal output records at different positions remain two records.

## Smallest meaningful offline fixture and stop rules

After review, propose one new local state-aware module/guest and native checker,
using the public development VK, both unmodified inner bundles and complete P.
No inner proving key is needed to reverify those statements. The smallest full
positive native transition needs a **new state-aware outer receipt**, not the
existing binding receipt; first qualify the host transition and guest execution,
then separately review a bounded proof/native test.

The current public J42 receipt can still qualify a standalone native
image/journal predicate, paired with two separate ordinary native transitions
as a control. Keep those separate results and the rejected 545,000-gram combined
floor; they cannot be reported as one accepted atomic state transition.

Construct a labelled **synthetic** prior UTXO/state from the public three-CM
context and an explicitly declared NF set/history. Authenticate its root from
the locking script in the local TxScriptEngine; do not call it a chain-accepted
genesis or proven initial backing. Proposed positive target: n=3, m=2,
R=1,700,000,000, F=80,000,000 and R'=1,620,000,000 sompi; use two public,
noncolliding placeholder predecessor NFs and the real count-1/count-3 CM prefix
roots. This m=2 state is a declared fixture, not a reconstructed bootstrap.
Freeze its exact prior/next roots and native body independently after review.
For the state-aware branch require one positive atomic 4-NF/4-CM transition with exact
independently rebuilt prefix roots and R-F. This tests application composition,
not merely a free-standing receipt predicate. Authorizations stay inside the
guest input; the development fixture already published them, so its new journal
cannot erase that history or establish privacy.

Require semantic rejections for wrong image/control/J/P, substituted A anchor
or count, unrelated historical path, stale NF root, already-spent NF, branch
replay, missing/fifth NF, reordered or re-paired record, duplicate-record
deduplication, occupied append slot, only-one history append, forged prefix root,
CM/NF/history capacity boundary, wrong predecessor outpoint, changed successor
policy, R/F overflow or underflow, diverted/extra output and unequal reserve
change, plus ambiguous selectors/mixed branch witnesses. Test P-sort versus
NF-comparator disagreement explicitly. Resource or
decoding failures do not count as required semantic rejection.

Record actual script units, committed compute budget, final serialized size,
storage/compute mass and fee-rate bounds after canonical finalization. Do not
assume 2× direct-proof cost or reuse the old covenant's fixed budget. If the
single state-aware receipt transaction cannot fit the protocol mass limits or
exact 80M-sompi fixture fee, retain that negative result; do not modify its authorizations,
weaken native checks or claim relay readiness. Sponsored fees require a separate
explicitly conserved profile, not an incidental extra input.

Stop before funding or a settlement-readiness claim if authentic predecessor
lineage, complete public reconstruction, genuine independent owner exits,
parameter availability or resource/fee qualification remains missing. A missing
receipt or incompatible native control is also a failed prerequisite, never a
reason to substitute a fake proof. This proposal concerns a bounded state-aware
composition experiment, not a production launch.

## Exact reuse seams

Source baseline is public project `ec6aa15d586bcc8a90f7232b433fd48d8c73d509`
with native SDK `01b532e8b553523216471682649693af92f0fd16`;
no current-upstream capability beyond those pins is assumed.

| Source seam | Reuse / required derivative |
| --- | --- |
| `two_input/circuit.rs:109–278`, `mod.rs:69–112` | Unchanged ownership/value relation, two authorization hash limbs and modes. Public verification needs no PK; new wallet proofs do. |
| `two_input/tree.rs:13–25,107–203,209–292` | Hashes, roots, indexed set and witnesses; add four sequential CM/NF updates and two authenticated history appends in a separate version. |
| `two_input/covenant.rs:137–142,355–453,495–538,555–621` | Historical membership, current NF proofs, CM/history append, successor/amount checks. Existing `0x20`/128-byte witness is not an `0x21` receipt adapter. |
| `two_input/mod.rs:158–263` | Derive amounts from native inputs, exact reserve continuation and native mass builder. New paired framing cannot be called `KPICR06` or accepted by old `settle`. |
| `two_input/replay.rs:186–320`, `wallet.rs:501–535` | Public reconstruction and owner DRAIN path; new positional record/history format requires explicit replay/scanner support. |
| `poc/two-v6-binding/common` | Reuse exact binding/encoding checks; keep default original instance separate from compiled development parameters. |
| Native `zk_precompiles/risc0/{mod.rs,receipt_claim.rs}`, SDK succinct fragments | Reuse the checked `0x21` claim/seal/control boundary and actual journal hash. A whole Based App runtime is not implied. |

The established-protocol grounding in [RFC-0011](0011-two-input-private-payments.md)
and its pinned source review remains applicable: historical membership and
current spentness are distinct; ciphertext binding is not encryption correctness;
transparent entry/exit and RPC/network observation remain separate. No new
cryptographic primitive or privacy measurement is introduced by this proposal.
