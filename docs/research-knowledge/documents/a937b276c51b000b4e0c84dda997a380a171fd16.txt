# Compact commitment updates: source findings and proposed fee experiment

Status: proposed public-only feasibility experiment. No implementation, native
execution, proof, setup, PK/seed access, funding or RPC run has occurred here.
The previous fee packets remain unchanged. Source identities are in
[SOURCE-PINS-01.json](SOURCE-PINS-01.json); the current official-source refresh is
[SOURCES.md](../SOURCES.md).

The most promising small experiment is to replace repeated native leaf appends
with one authenticated, power-of-two commitment-subtree update. This retains
native nullifier checks and the existing split between native public updates and
Groth16 private ownership/conservation. It addresses the common-program growth
which defeated the previous wider-payment unroller. It cannot reduce the native
Groth16 tariff or make two useful recipients pass the complete-lifecycle target.

## Native source facts

The runtime source remains rusty-kaspa v2.1.0 commit
`01b532e8b553523216471682649693af92f0fd16`.

- [The interpreter](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/lib.rs#L612-L711)
  traverses a parsed script once. P2SH performs one additional redeem execution.
  The exhaustive opcode table has no loop, jump, call or eval instruction.
  Concatenating or selecting witness bytes does not execute them. A nested
  P2SH-shaped redeem is not recursively evaluated as a second authorization.
- [Dynamic stack selection](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L464-L479)
  and dynamic substring offsets are available. They can share data/offset
  selection in a compact emitted program; they cannot implement a subroutine.
- [Stack pushes](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/data_stack.rs#L471-L479)
  are metered by pushed byte count. Replacing repeated code with many Pick/Dup
  operations can save wire bytes while increasing execution units. Both matter.
- The current stack limit is244 entries; script, element and operation limits
  are1,000,000. The existing policy additionally selects canonical PUSHDATA2
  framing with a65,535-byte redeem limit. That framing is a profile choice.
- [Groth16 pricing](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/tags.rs#L29-L35)
  is140,000 grams plus
  [250,000 script units per gamma-ABC element](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/groth16/mod.rs#L16-L49).
  Two public inputs require three elements:147,500 normalized mass per verifier.
  Neither faster proving nor a shorter native script removes this charge.
- [Compute mass](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/mod.rs#L332-L369)
  includes bytes, output-script bytes and committed input budgets. Transient and
  contextual storage remain separate possible maxima. A low measured unit count
  alone does not justify selecting a smaller valid-path budget.

The existing `policy.rs::append_cm` authenticates an empty leaf through16 native
hash levels, then computes the replacement root through another16 levels. A
naive N-leaf payment repeats these two walks N times and makes every independent
exit carry the resulting common redeem.

## Candidate comparison

| Candidate | Source-supported opportunity | Remaining obligation |
| --- | --- | --- |
| Native loop or script-call refactor | Absent in the pinned opcode set | Requires a consensus/runtime feature change; unavailable for this experiment |
| Dynamic stack and offset selection | Share offset selection and avoid duplicated mode-specific public checks | Derive a valid-path push-unit bound and enforce exact frame/count/range semantics |
| Separate programs behind a router | Carry only selected authorization code after an additional routed UTXO transition | No one-step witness eval; routing must preserve all backing/state and authenticate the exact next policy, and all extra transactions/bytes must be charged |
| Move public tree transitions into the already-required proof | Potentially remove most native Merkle code and public update bytes | New proof constraints must enforce exact NF absence/insertion, CM empty-slot updates, counts/current roots and successor binding; current circuit explicitly delegates these checks to native |
| Authenticated CM-subtree append | Replace N pairs of deep walks with one pair plus N−1 internal hashes | New layout/alignment and capacity semantics, exact output binding, independent recovery and full lifecycle pricing |

The subtree screen is preferable first: it tests a concrete native improvement
without changing the nullifier or private proof relation. Wider private outputs
would still need a new reviewed circuit and parameters after this screen. This
experiment does not implement those outputs or authorize any financial spend.

The reused design is ordinary binary-Merkle composition. Zcash's
[incremental Merkle tree](https://github.com/zcash/incrementalmerkletree) and
[ShardTree](https://github.com/zcash/incrementalmerkletree/blob/main/shardtree/src/lib.rs)
likewise treat subtrees/frontiers as composable tree state; its multiple-append
API avoids repeated traversals. We adapt the repository's existing SHA256/domain
tags and fixed tree depth, rather than adopt another protocol's hash or note
format. No new cryptographic primitive is proposed. The current web references
establish analogous structure, not source authority for a native implementation.

## Exact candidate semantics for the screen

Let the commitment tree have depth16, next physical index `n`, and selected batch
size `N=2^k`. Define `s=ceil(n/N)*N` and `n'=s+N`, checked with bounded integers
before any path/hash operation. Existing count/capacity limits still apply.

1. Authenticate the canonical empty subtree of height `k` at subtree index `s/N`
   against the actual old CM root, using one path of `16-k` siblings.
2. Compute the replacement subtree from exactly N ordered CM32 leaves, using the
   existing `SHA256(CM_NODE || left || right)` at every internal node.
3. Reuse that exact path and index to derive the new root; bind the new root and
   `n'` to the public successor state. No independent unauthenticated path exists.

This costs `N-1 + 2*(16-k)` native hashes instead of `32*N`. At N32 this is53
hashes instead of1024. This is an operation count, not a byte/unit/fee result.

For a full profile the inductive invariant must be explicit: every position at
or beyond `n` is canonical empty. Genesis establishes it; an authenticated empty
block update preserves it. The skipped gap `[n,s)` is not a receipt or a positive
note. Merely checking an empty target block does not, by itself, prove a random
existing tree's intervening gap empty. An adapter must assign real delivery
positions from authenticated range metadata, never from an operator map.

This proposal changes layout. Initial `n=1` can waste N−1 physical slots, and
later batches can create more gaps. Count NF liabilities, CM capacity and the
ability of every remaining owner to exit must therefore be rederived. The
current continuing-exit rule still appends two dummy CMs even for a full cashout;
CM exhaustion remains a liveness issue. A terminal-only skip does not establish
independent exits for several remaining owners. No capacity or recovery
qualification follows from a fast append kernel. An exact contiguous-range
multiproof would avoid gaps, at greater native implementation complexity.

## Smallest falsifiable native experiment

After root agreement, create a new isolated `poc/compact-cm-append` package.
Use public deterministic synthetic CM32 values and existing empty/branch tags.
No notes, keys, witnesses from a funded trial, PK, setup, proving or chain access.

For N4/8/16/32, compare two emitted scripts on the **same aligned old tree,
identical positions/leaves and identical expected new root**:

- Baseline: sequential empty-leaf authentication and replacement, matching the
  present per-leaf policy semantics.
- Candidate: one empty-subtree authentication, one bottom-up replacement subtree
  and one replacement boundary walk.

The host reference computes all intermediate roots separately. Use a nonempty
public prefix to exercise real left/right siblings and prevent an all-empty
symmetric fixture from concealing an index bug. Required controls hold the old
state and expected new state fixed: changed leaf, changed sibling, wrong bound
index, nonempty target block, truncated path and trailing-frame bytes must
reject. A fully changed valid statement is not a proof-reuse rejection control.

Run the public synthetic cases through the existing pinned native APIs in one
network-off namespace under ordinary ADR0054 read-only executables. Report
emitted bytes, exact measured script units, committed-budget compute mass,
transient/storage components and actual native outcomes. Generous operational
limits must not turn a resource cap into a validity predicate. The fixture is a
Merkle kernel, not a payment policy: it has no financial authorization and must
be prominently marked DO_NOT_FUND.

Freeze source/fixtures and have an independent reviewer check the update
semantics before that one bounded run. There is no reason for a Groth16 setup
or funded experiment at this stage.

## What constitutes useful fee progress

The preserved wider-payment screen found an optimistic unroller minimum of
2.099209%, already failing the2% complete target. For a hypothetical common
budget1600 and N32, its prior necessary floor allowed only3,165 net additional
common-redeem bytes. The kernel result must expose the remaining allowance after
accounting for replacement of the current two-leaf code, compact exit handling,
wide/small mode dispatch, extra VK material and dynamic-offset sharing.

A positive kernel result is only permission to emit and price a full candidate.
No saving is credited until common program, every frame, every independent exit,
entry/change/tails and integer contextual storage are included. No exact-case
measurement establishes an upper bound for all legitimate Merkle paths.

Wider payments count only one payer's already demanded simultaneous useful
payments. Independent owners never provide private witnesses or cooperate in an
exit proof. Sequential demand, an extra fictional recipient, split payments to
one recipient and a future arrival do not earn an amortization credit.

## Private change and repeated payments cost more under the current shape

Two separate one-recipient payments with retained payer change, followed by both
recipient cashouts and the payer's own change cashout, require **five** Groth16
verifications. At reference100 the verifier-only total is73,750,000 sompi:
3.6875% per useful10-KAS payment, before any other cost. If the last payment
leaves no positive payer change, four verifiers still cost2.95% per useful
10-KAS payment. These are distinct routes; change recovery is not counted as a
third useful payment.

Using current measured shape atoms only, two P0 actions, two continuing cashouts
and one terminal cashout total948,748 normalized mass:
`2*189587 + 2*189999 + 189576`. At rate100 this is94,874,800 sompi, or4.74374%
per useful10-KAS payment, **plus full entry/ordinary change/tails**. This is
conditional shape arithmetic, not an emitted or accepted new lifecycle or a
storage guarantee. It must be replaced by the private-change lane's actual body
quotes and exact amounts if that route is implemented.

The compact native screen targets program growth for genuinely wider payment
actions. It does not remove this repeated-demand verifier count. Financial
privacy, recovery, fee and production qualification remain open.
