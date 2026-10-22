# Synthetic state-aware assertion — DO NOT FUND

This additive version7 core verifies the unchanged genuine development pair
through the immutable `CompiledResearchGate`, then derives a local state
transition. It is conditional on prior well-formedness. It does not authenticate
actual UTXOs, native KAS backing, genesis, policy continuity or permissionless
exits. No reserve release or deployable pool is implemented. The original v6
and paired P1088/J42/images are unchanged. See RFC-0018 and ADR-0035.

`StateGate::new()?.evaluate(input)` accepts exactly11,219 bytes. There is no
caller-selected key/domain or proof-verdict callback. On the host, the compiled
key receives the existing complete checked validation; guest static-key handling
is inherited unchanged from the separately reviewed binding crate.

| Input | Offset | Bytes |
|---|---:|---:|
| Unchanged pair input | 0 | 2846 |
| Declared prior outpoint: rawID32 + u32LE index | 2846 | 36 |
| Prior version7 state | 2882 | 105 |
| Reserve u64LE sompi | 2987 | 8 |
| Historical anchor path, depth16 | 2995 | 512 |
| Four sequential indexed-NF updates | 3507 | 4640 |
| Four CM empty-slot paths | 8147 | 2048 |
| Two history empty-slot paths | 10195 | 1024 |

Each NF update is `u32LE predecessor_index || predecessor_leaf68 || path544 ||
empty_append_path544`. Its leaf is `value32 || u32LE next_index || next_value32`.
Hashes reuse the existing native SHA256 tree domains: node1, CM0, NF2, history3.
An unoccupied slot is raw zero32, not a hashed zero commitment or sentinel.

State is `7 || u32LE n || u32LE m || CMroot32 || NFroot32 || historyroot32`.
The predecessor must have odd1<=n<65536 and even2<=m<=2n. The v6 bootstrap
branch is excluded. After four inserts/appends, n+4<65536 and m+4<131071.
The historical odd count a must satisfy a<=n, and `(a,anchor)` must be in
history at index(a-1)/2. For a==n the anchor also equals the current CM root.
This local check does not reconstruct or certify unrelated history/tree leaves.

P nullifiers retain their raw-byte sort order, while indexed-set comparisons
interpret values as little-endian uint256. Each predecessor and intermediate
empty slot is authenticated against the immediately preceding root. Compared
with old v6, one explicit stricter local reachable-state check requires
`predecessor_index==0 iff predecessor_value==zero`. Terminal next-value zero
requires next-index zero; nonterminal next-index is in[1,new_index).

Four sorted complete P records append four CM leaves, preserving duplicate
record/CM multiplicity. The first two append operations produce prefix r2; all
four produce r4. History appends `(n+2,r2)` then `(n+4,r4)` at consecutive
indices(n+1)/2 and(n+1)/2+1. The intermediate prefix is not a second accepted
native UTXO state. No fake authorizations or old duplicate-rejecting witness
builder is used.

Fee F is the proved P u128 sum, checked positive and <=MAX_SOMPI before u64
narrowing. Require F<R<=MAX_SOMPI; derive R'=R-F with checked integer math.

Exact336-byte journal:

| Journal | Offset | Bytes |
|---|---:|---:|
| ASCII KPI2V6S1, u16LE profile1 | 0 | 10 |
| SHA256(P) | 10 | 32 |
| Fixed NONFUNDABLE poolID | 42 | 32 |
| Declared predecessor outpoint | 74 | 36 |
| Prior state | 110 | 105 |
| Derived next state | 215 | 105 |
| R and derived R', u64LE | 320 | 16 |

PoolID is SHA256 of exact ASCII `KPI/public-two-v6-state/DO-NOT-FUND/v1` with
no NUL. A valid changed outpoint or reserve produces a changed journal; the
guest cannot authenticate L1 context by itself. A native checker must reconstruct
the exact journal from authenticated transaction/UTXO context under a separately
fixed new image. J336 is a new assertion, never an extension or reinterpretation
of the immutable nonsettling J42 receipt.

The two public fixtures in `../public-fixtures` come from the independent stdlib
oracle `../public_state_oracle.py`. Both reuse the original2846-byte pair intact.
Current n3 becomes7, historical n5 becomes9; both m2 becomes6 and
1,700,000,000-80,000,000=1,620,000,000 sompi. Their roots, prior state and
backing are deliberately supplied synthetic context, not authentic genesis or
funded state. The independent oracle claims byte/tree checks only; Rust tests
also verify both genuine proofs. Public fixture manifest SHA256:
`3dec202e797fd714547de6ef77e76489c557188f4e4e38b2d01c0618c495f9c6`.

Tests include exact independent all-byte positives, malformed framing, initialized
state/count/capacity boundaries, checked sompi/narrowing, stale/cross-context roots,
each NF predecessor and append path, replay/reordering, sentinel/link/order rules,
each CM and both history paths, duplicate CM multiplicity (tree-only), comparator
counterexample, genuine-proof/publication mutation and declared-context binding.
Arithmetic-only and tree-only controls do not manufacture new valid proofs.

## Retained host results

`evidence/host-checks` retains the locked/offline release command, source and
fixture identities before/after, complete logs and resource accounting. All
14 test groups passed, including exact current/historical independent outputs
and the reviewer's authenticated already-spent NF control. Build plus tests
took 24.96 seconds; tests took 0.18 seconds, peak RAM was 885,420,032 bytes.

`examples/evaluate_batch.rs` is a read-only differential adapter. It reads
actual inputs and emits actual journals/states or typed errors; it never reads
expected results. `evidence/corpus-differential` retains its source/binary hashes,
raw output and all 163 original outcomes against the independently frozen corpus
manifest `19fc246c682a9545da41bec205535a6c76b6207dd05fdbf98ccf2fe1c9a74e6f`.
All 128 positives match the complete J336 and next state105, including n65531,
dense indexed sets, physical permutations, sentinel/middle/tail insertions and
R=F+1/MAX. All 35 negatives reject; 34 original expected error families match.

One frozen expected label is wrong: `nf-equality-wire` changes predecessor
index0 to have a nonzero value. The explicit sentinel check returns
`NullifierLink(0)` before the corpus's predicted `NullifierOrder(0)`. The oracle
author and independent reviewer documented this before Rust execution in
`observer/artifacts/public-state-correctness-corpus-20261022T132924Z/PRE-RUST-EXPECTATION-ERRATUM.md`.
The original plan/manifest/inputs were preserved, and the differential process
exits1 to retain this sole mismatch. The separate authenticated already-spent
control correctly reaches `NullifierOrder(0)`. No core fix, pruning or retuning
was applied. Full report SHA256:
`df25a0a41e30186d22f5a0b600731b86716bad441ae31db33d469bdd2ccfa14e`.

These host checks do not qualify a guest image, receipt, native transaction,
backing, genesis, funding or owner exits. Those remain separate gates.
