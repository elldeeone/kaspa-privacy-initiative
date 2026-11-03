# Activation, bootstrap and recovery

[Draft scope](README.md) applies. Commitment authentication and data availability
are separate properties; no root or seed recreates missing ciphertexts/proofs.

## Activation and old state

Native state is conceptually empty/inactive before the configured activation
DAA score. New transaction eligibility is checked against its **origin block's**
DAA score: below activation, v2 rejects; at/above activation, it uses this exact
manifest/profile. Version-3 headers are required at/above activation; older
headers retain old parsing/hash rules below it. Mixed-era mergesets process each
origin's validity rules and the normal consensus order. Do not assume the first
locally observed post-activation header has empty past if another eligible DAG
block was already accepted into that past.

All preactivation native history is empty; ordinary UTXOs remain real KAS. No
funded application reserve, old wallet note, legacy setup/root or administrator
signature initializes native claims. Users enter by an actual authorized
ordinary spend. Any future migration must atomically consume the old claim once,
preserve its entire liability, create a backed replacement and preserve spentness
across all accepting old/new profiles. There is no automatic migration here.

An incomplete/unknown manifest, mismatched genesis/domain/profile/capsule,
unspecified mass schedule or premature native transaction fails closed. Header
3/transaction 2 remain proposed allocations until Kaspa approves/activates them.
No document or conformance fixture selects a live activation score.

## Full validator bootstrap: retained replay first

The first profile enables **full validation replay**, not a new fast-native
snapshot shortcut. Inputs are:

1. The exact consensus manifest and supported portable capsule/software, obtained
   independently of a witness/provider; verify their fixed identities.
2. A legitimately established preactivation ordinary Kaspa state and all required
   headers/GHOSTDAG/body context thereafter, with provably empty predecessor
   native history. Reuse only existing validated Kaspa bootstrap assumptions;
   a self-signed activation UTXO file is not equivalent. If that starting state
   cannot be established, replay retained required history from genesis.
3. Every required accepted and conflicting DAG body/ordinary transaction context
   from that point, plus all complete v2 transactions/proofs/signatures. A
   shielded log alone cannot establish real funding or calculate accepted order.

Reconstruct ordinary and native views together, verify all version/domain/
ordinary-authorization/proof/value/marker rules, each qualified header's paired
UTXO/native roots and existing coinbase/pruning/KIP-21 commitments. At every
batch verify complete position/count/frontier/anchor/log evolution. Persist
combined state atomically. A corrupt/missing body or parameter stops bootstrap;
do not accept a caller root or synthetic predecessor to continue.

This needs independently available postactivation history. The reference native
archive role retains and serves it; ordinary pruning alone cannot discard the
only copy needed by a fresh validator. Permanent service/data availability and
storage costs are explicit unqualified assumptions, not forced by a hash.

## Authenticated snapshot format and restricted import

An export/import snapshot accelerates an **already independently qualified**
point P. It is not the fresh-validator path in profile 1. The snapshot manifest
has this exact encoding:

```text
ASCII("KNSSNP01")[8]||U16(1)||qualified_header_hash[32]
||utxo_commitment[32]||native_state_commitment[32]||activation_id[32]
||V64(StateRecord)||V64(frontier_bytes)
||U64(N_entry_count)||U64(A_entry_count)||U64(event_count)
||U64(file_count)||for each file:
  U8(kind)||U64(start_index)||U64(record_count)||U64(byte_length)||SHA256(file)[32]
```

Kinds are 0=N, 1=A, 2=events. Files are ordered by kind then start index, cover
each logical stream exactly once without holes/overlap, and are at most 16 MiB.
Count/byte lengths must fit remaining declared totals before allocation. A
record cannot straddle files. Reject duplicate/unknown manifest entries/tags,
noncanonical bytes, suffixes, truncated chunks, missing records or excess data.

N records are exactly canonical nf[32] in strictly increasing byte order,
implicitly value 1. A records are `key[32]||U64(tree)||U64(count)||root[32]`,
strictly increasing by key, with exact AKey recomputation. Event files contain
`V64(event_bytes)` in continuous event-index order. Counts must match StateRecord
and `g=|N|=2*e`; frontier and all roots must match. File hashes authenticate
transport only. Native state authentication comes from P's **qualified header**
with correctly checked PoW/hash/new field and actual accepted-past point.

After independently establishing P and its ordinary state, stream/decode all
records, recompute N/A/L roots and frontier commitment, and compare the complete
StateRecord root to P. Independently replaying native events must yield the same
markers, forest positions/roots and anchor batches; an event's origin metadata
does not by itself prove funding/accepted order. A full validator still needs
the DAG/ordinary replay above. A snapshot provider's signature or a matching
self-provided hash is never a substitute for P's independent qualification.

P2P pruning proofs, trusted-set import and header-only first-parent segments
must preserve the version-3 field and correct native/ordinary point pairing.
Current pruning code does not supply native coverage automatically. A fresh
native fast-sync/import mechanism needs a separate reviewed protocol; this draft
does not silently enable one with a new unreviewed trust assumption.

## Owner recovery and retained material

A wallet restoring on an independently qualified native chain needs its own
spending/derivation material, creation-domain/profile metadata, complete ordered
accepted event/discovery history or sufficient authenticated witness data,
current spentness/eligible anchors and compatible exact public artifacts.
Viewing authority and outgoing/spentness backup capability are different. Use
standard Orchard note/plaintext/commitment/key checks before crediting received
value. Retain both scopes when the declared backup requires them.

Scan both Actions per event, preserve every accepted tree/position, derive note
nullifiers by the unchanged position-independent rule, and avoid crediting one
spend identity twice. Reconstruct old-tree witnesses from retained leaves and
eligible full/partial roots. Root/membership alone does not establish current
unspentness. Cross-tree consolidation and fee repricing are owner-authorized
new transactions, not privileged recovery. Handle reorg by rolling accepted and
pending wallet state back to their authenticated common predecessor.

The owner may run its own native-enabled full node or use an explicitly stated
independent chain-qualification model; a hosted indexer's assertion is not
trustless native acceptance. Clean service-loss qualification must remove all
normal hosted services, start from the declared owner backup, retrieve exact
required data/software from independent sources, reconstruct a fresh authorized
spend and settle it. No such complete native-profile trial has run.

At least one reachable sufficient independent source, or a sufficiently complete
owner-held copy plus settlement connectivity, remains a liveness assumption.
Neither every copy disappearing nor guaranteed arbitrary-fee inclusion can be
repaired by a seed. Nullifiers and ciphertexts are not pruned because ordinary
UTXOs were pruned or an unrelated marker appeared. The full-retention reference
has an unmeasured long-term storage cost.

Current pruning source boundary:
[apply.rs](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/processes/pruning_proof/apply.rs),
[qualified first-parent checks](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/pipeline/virtual_processor/utxo_validation.rs#L221-L265).
