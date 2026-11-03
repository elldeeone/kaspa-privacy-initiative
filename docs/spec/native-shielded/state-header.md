# Native state, DAG acceptance and header version 3

[Common definitions](README.md) and [transaction rules](transactions.md) apply.
All roots below commit to **accepted** effects, not every DAG transaction.

## State and the depth-32 forest

The native state is one immutable-domain view alongside ordinary UTXOs:

| Component | Meaning |
| --- | --- |
| B | Consensus-reserved native sompi, U64, <=M. |
| g | Global appended commitment count, U64. Includes zero padding. |
| t,c,C | Active tree ID U64, active count U64 in [0,2^32], canonical Orchard root[32]. |
| Frontier | Occupied depth-32 left-subtree nodes for the active tree. |
| N | Global map of every accepted published nullifier to byte 1; never tree- or accepting-verifier-scoped. |
| A | All eligible completed accepted anchor tuples `(tree_id,count,root)` in the current branch. |
| L,e | Ordered complete accepted native event log and event count U64. Supplies discovery, proof and replay data. |

Always require `g = 2*e = |N|` and `g = t*2^32 + c`, using checked wide
arithmetic. At activation, B=g=e=t=c=0, N/L empty, C the upstream empty-tree
root, and A contains only `(0,0,C)`. Its empty anchor permits dummy-spend deposit
construction, not an authorized positive spend. The domain/profile come from
the activation manifest; no caller initializes a different genesis.

Each accepted bundle appends **both** cmx values in Action order, inserts both
markers and appends one complete event. A position is `(tree_id,local_index)`;
its global ordinal is `tree_id*2^32+local_index`. The index passed to the unchanged
Orchard membership relation is U32; tree ID is an externally authorized anchor
coordinate, not an added input to note/nullifier cryptography.

If c=2^32 before appending a bundle, atomically retain that full tree/root,
increment t, set c=0 and initialize the empty frontier. Append both outputs to
the new tree. Since counts start even and each bundle appends 2, one bundle
never straddles a boundary. A tree filling during a batch is sealed and its
full root queued for eligibility at the batch boundary. At the boundary also
retain the final active root if changed; insert tuples in ascending tree ID.
Duplicate tuples do not create duplicate A entries. All completed full roots
stay in A, so old notes remain spendable after rollover. No old N entry clears.

An unchanged bundle has one anchor for its two spend slots. It cannot combine
real notes from different trees in one bundle. The owner may first spend/rebase
each old-tree note into the active tree through separate authorized bundles;
this adds cost and metadata, not custody or a mandatory waiting period.
Never import a root or change nullifier derivation to simulate cross-tree spends.

Global counter overflow still rejects atomically. This draft avoids the much
earlier fixed-depth lockup, not every finite-format capacity limit. A deployed
protocol needs reviewed migration before the global format is exhausted; no
claim that safely halting preserves economic exit liveness follows.

## Exact commitment encodings

For X=N or A use a standard binary sparse Merkle tree of depth 256. Its path
is the key's bytes in order, most-significant bit first in each byte. At depth
256 the absent leaf is `H("NEmpty",empty)` or `H("AEmpty",empty)`.
At internal depth d (root d=0):

```text
node_X(d,left,right) = H("NNode" or "ANode", U16(d)||left||right)
empty_X[d] = node_X(d,empty_X[d+1],empty_X[d+1])
```

N key is the exact canonical nf[32], value U8(1); present leaf is
`H("NLeaf", key||U8(1))`. A value is `U64(t)||U64(c)||root[32]`, key
`H("AKey",value)` and leaf `H("ALeaf",key||value)`. Conflicting values for one
key reject; a collision is not silently treated as identical state. Physical
path compression/storage is optional but must produce these exact roots.
This explicit format is not an assertion that KIP-21's existing SMT bytes/root
are interchangeable with these domains.

An event is:

```text
U64(event_index) || origin_block_hash[32] || U32(index_within_block)
|| U64(first_global_cm_position) || V64(Wire(tx))
```

Indices are exact and contiguous from zero. `first_global_cm_position=2*index`.
Record actual full authorization/proof bytes, not only an economic ID. L is a
binary append accumulator of depth 64, indexed by U64 event index (MSB first).
Its path is numeric index bits 63,62,...,0, independently of the little-endian
index field inside event bytes. Its present leaf is `H("EventLeaf",event_bytes)`, absent depth-64 leaf
`H("EventEmpty",empty)`, internal node at depth d is
`H("EventNode",U16(d)||left||right)`. Empty subtrees recurse identically.
This log root/count authenticates full recovery bytes, their order and their
origin metadata; availability and actual acceptance still require the bootstrap
rules. An origin hash is already known when applying that block to a child's
past state, so this introduces no header/self-hash fixed point.

The active Orchard frontier is encoded:

```text
U64(t)||U64(c)||C[32]||U32(bitmap)||occupied_nodes[32 each]
```

For c<2^32, bitmap is its low 32 bits; nodes appear in increasing set-bit/level
order. A level-i node covers its completed left subtree of 2^i leaves. Recompute
the Orchard root using these nodes and standard Orchard empty roots. For c=0,
there are no nodes and C must be empty. For c=2^32, bitmap=0/no nodes and C is
the full root also retained as a sealed anchor. Full replay validates it from
leaves; snapshot import binds it to the independently qualified state. Use
the unchanged Sinsemilla/Orchard tree compression, not H, inside note trees.
`frontier_hash = H("Frontier",frontier_bytes)`.

The exact StateRecord is:

```text
ASCII("KNSSTA01")[8] || U16(1) || domain_id[32] || profile_id[32]
|| activation_id[32] || U64(B)||U64(g)||U64(t)||U64(c)||C[32]
|| frontier_hash[32] || U64(|N|)||N_root[32]
|| U64(|A|)||A_root[32] || U64(e)||L_root[32]
```

`native_state_commitment = H("State",StateRecord)`.
Counts, domains, canonical frontier, all roots and profile are committed.
A root without its complete required data is not a recoverable state.

## Accepted ordering and block qualification

The existing Kaspa source computes past UTXO state from the selected parent,
then its consensus-ordered mergeset, and checks the current block against that
past state. It validates transactions in parallel assuming ordinary body checks
have established independence. New notes have no common ordinary outpoint;
that assumption does not establish native independence.

For a candidate block B, start from its selected parent's stored **past**
ordinary/native view. Process the selected parent first (its coinbase retains
the existing ordinary effect), then
`consensus_ordered_mergeset_without_selected_parent`, retaining original
transaction indices. Within each origin block, visit non-coinbase transactions
in increasing original index. Never use arrival order or thread completion.

For each batch/origin block:

1. Freeze A at batch entry for anchor eligibility. Full trees sealed during the
   batch and its new final active root become eligible only at the boundary.
   No real note created in this block can be spent by an intermediate root.
2. Check ordinary current inputs, native current N/B, exact eligible anchor,
   all contextual rules, complete authorization and resource limits serially
   against the evolving combined view. Independent cryptography may run in
   parallel first; sort by original index before applying effects.
3. An accepted transaction changes ordinary UTXOs, B, forest/frontier, N, L,
   acceptance identity and fee/reward data atomically. Reject/skip changes none.
4. Complete the batch's A insertions, including every tree sealed in it and its
   final changed active root. Save one coherent diff with preimages/undo data.

During **mergeset acceptance**, a later ordinary/native conflict is skipped as
an entire transaction. A side block may have qualified under its own past but
have an ineligible anchor/spent resource here; block inclusion is not settlement.
Do not import all roots from arbitrary side-block headers into A.

During **current-block chain qualification**, require unique ordinary outpoints
and native markers across its entire body, no ordinary intra-block chaining,
and every non-coinbase transaction valid. Apply native effects to scratch state
in body order with the same frozen-entry A rule. Any failure fails qualification;
do not quietly drop a current-block invalid transaction. Discard scratch state
after checking; the header commits past state, not this scratch poststate.

Selected-parent script-skip/cached paths may reuse exact context-independent
cryptographic validity, but MUST recheck current N/B/anchors/actual input effects.
An old proof/root proves no current absence. Reorg/virtual changes restore and
reapply **every** ordinary/native/log/anchor/fee/acceptance component from the
same predecessor, in the new consensus order. Crash recovery publishes no
partially committed roots/counters. Mempool indexes ordinary outpoints and all
published markers and refreshes contextual validity after tip/anchor changes.

## Header version 3 and proof of work

Version 2 already denotes KIP-21 in current source. The proposed version 3
header adds exactly `native_state_commitment[32]` immediately after
`utxo_commitment`, committing the **same authenticated past-state point**.
Retain the version-2 fields/order otherwise:

```text
U16(3) || U64(parent_level_count)
|| each expanded parent level: U64(parent_count)||parent_hashes[32 each]
|| hash_merkle_root[32] || accepted_id_merkle_root[32] || utxo_commitment[32]
|| native_state_commitment[32]
|| U64(timestamp)||U32(bits)||U64(nonce)||U64(daa_score)||U64(blue_score)
|| V64(blue_work_big_endian_without_leading_zeros) || pruning_point[32]
```

Parent level/order/selected-parent checks remain Kaspa rules; hashing does not
sort parent bytes differently. `BlockHash` is the existing keyed BLAKE2b-256
with key ASCII `BlockHash`. The nonce/time override used to derive PoW prehash
MUST retain the new commitment too. PoW/block ID, header serializers, RPC/P2P
conversion, pruning proof and selected-chain processing all include the new
field and version. An ignored RPC extension is not this commitment.

Header native root is checked against the combined accepted-past reconstruction,
alongside existing UTXO/KIP-21/pruning/coinbase commitments. No UTXO MuHash or
accepted-ID field is silently repurposed. Native full transaction hashes enter
body Merkle leaves, native economic IDs enter accepted-ID/lane processing, and
native subnetwork gas remains zero. Both old and new transaction families use
their explicit version dispatch. A future no-bundle transaction cannot change B.

Exact current source anchors:
[past/qualification](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/pipeline/virtual_processor/utxo_validation.rs#L110-L265),
[parallel assumption](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/pipeline/virtual_processor/utxo_validation.rs#L297-L350),
[body conflicts](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/pipeline/body_processor/body_validation_in_isolation.rs#L126-L151),
[header hash](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/core/src/hashing/header.rs#L7-L30),
[version constants](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/core/src/constants.rs#L1-L15).
