# State-aware reuse of the unchanged public pair

The existing public pair can be reverified under its unchanged inner circuit,
domain and VK in a **new state-aware outer program**. No inner setup or proving
key is needed for that verification. The smallest authorized next step is a
**NONFUNDABLE synthetic assertion**, with current and historical anchor cases;
it is not a new reserve implementation or a qualified owner-exit path.

This reviews integration RFC0018, SHA256
`4713abed161c49248b6f66e35a825e32b7c75ad090258802d539ddf75e457348`,
and the ec6aa15 fixed-v6 sources. Root subsequently authorized source/test work
on the synthetic assertion. Guest execution, proof production and native runs
still require the separately selected source/image and resource release.

## Exact relationship to existing evidence

The new program must verify both original A/Q/C bundles and their complete
bijections to P, then use **those same authorization bytes** for historical
anchor membership. The old J42 proves an existential partition of P, not a
caller-supplied anchor sidecar. Verifying that receipt and then accepting an
unrelated pair of authorizations would not bind the historical predicate to
the statements previously proved.

The existing `CompiledResearchGate::verify` can be reused unchanged, followed
by parsing the same immutable input bytes at its fixed bundle offsets. Do not
let a separate state-side bundle supply an anchor. Its static-key optimization
still requires the existing independent host key preflight and image freeze;
submitted proofs retain checked canonical/subgroup decoding. Default original
rehearsal parameters remain a separate contract.

The preserved genuine bundle hashes are
`3f8f0a13f4ce7a73b61fd093c5aad01fc2cb2ea0ca3db65ed4f0d44de72019a9`
and `1cc3094a335dfa94897929fde258d05da2a3270314738919b972838e61e2d7b8`.
The frozen original pair input is 2,846 bytes, SHA256
`7771a2e610d37fdb12b1d668b8e229bd3cd1e5fe83c5993847daa0fef8c93b36`;
P remains 1,088 bytes, SHA256
`9ac720aa55e7bd6eaec674788d418aa3314bc7af1010b7c9f09a493d9aa76ce9`.

## State obligations that cannot be omitted

1. Parse a distinct S7 frame, with checked odd CM count, even NF count,
   `m <= 2*n`, capacity and checked count additions. Authenticate the actual
   pair's common odd `a` with `1 <= a <= n` at history index `(a-1)/2`.
2. Insert all four distinct P nullifiers against the **current** NF root.
   Each update authenticates its predecessor leaf, checks strict little-endian
   numeric bounds and pointer bounds, updates that leaf, proves the new slot
   empty against the intermediate root, then installs the new leaf. Insert
   indices are `m+1..m+4`; sentinel index 0 is excluded from NF count.
3. Append all four P records in public complete-record order at CM indices
   `n..n+3`. Prove raw-zero empty leaves before each update. `cm_leaf(0)` is
   not the empty leaf. Keep each CM with its original ciphertext and preserve
   multiplicity; no set conversion or spent-record deduplication.
4. Keep the root after two appends and after four. Append both history leaves,
   proving each history slot empty and chaining roots. For prior n=3 the
   added leaves are `(5,r2)` at index 2 and `(7,r4)` at index 3; prior n=5
   instead adds counts 7 and 9 at indices 3 and 4.
5. Check P fee as u128 before conversion, require its upper eight bytes zero,
   `0 < F < R <= MAX_SOMPI`, and checked `R'=R-F`. A root-consistent fixture
   with a declared R does not establish liabilities or backing.

P sorts raw unsigned bytes. NF predecessor comparison reverses the bytes for
256-bit little-endian numeric comparison. The genuine four-NF fixture already
has different orders; the independent manifest retains both. Sorting the NF
linked set by P's comparator would change the relation.

The two-history-leaf convention means **accepted commitment-prefix history**.
r2 is a prefix of records accepted atomically, not a separately accepted UTXO,
reserve checkpoint or inner-bundle partition. Appending only r4 breaks the
existing implicit odd-prefix index/count relation. The new version must state
this convention explicitly; it is not a silent change to old v6 semantics.

`PublicState::witness` should not simply be called twice on fabricated old
authorizations: its fixed two-output grouping rejects equal CMs within that
group, while the aggregate relation permits repeated cross-bundle records.
Reuse its lower-level hash/path/indexed-set algorithms and explicitly verify
four record appends, rather than inventing two new inner authorizations.

## Frozen independent public oracle

`poc/two-v6-state/public_state_oracle.py` is stdlib-only and imports no Rust
implementation or producer helper. It reconstructs full tiny public CM/NF/
history trees, builds every path, and separately folds each predecessor,
empty-slot and successor path back to the reconstructed roots. It verifies
the original pair/P/bundle/VK hashes, exact public bijections and ciphertext
digests. It performs no Groth16 or native verification.

The input format agreed with the state-core owner is exactly 11,219 bytes:

| Offset | Field | Bytes |
| ---: | --- | ---: |
| 0 | Unchanged complete pair input | 2,846 |
| 2,846 | Declared predecessor raw txid32 + u32le output index | 36 |
| 2,882 | Prior S7: version7, two u32le counts, three roots | 105 |
| 2,987 | u64le reserve R | 8 |
| 2,995 | Common-anchor depth-16 history path | 512 |
| 3,507 | Four NF witnesses, each predIndex4 + oldLeaf68 + two depth-17 paths | 4,640 |
| 8,147 | Four depth-16 CM empty-slot paths | 2,048 |
| 10,195 | Two chained depth-16 history empty-slot paths | 1,024 |

J336 is exactly
`KPI2V6S1 || u16le(1) || SHA256(P) || poolID || outpoint || S7prev || S7next || u64le(R) || u64le(R')`.
The fixed test pool ID is SHA256 of exact ASCII
`KPI/public-two-v6-state/DO-NOT-FUND/v1`, no NUL:
`ca2c2ab5087bc62965db817ed821a3898b255d06c789e7c20491afad88ca7756`.

Both contexts declare NF values LE256(1), LE256(2), the sentinel and ordinary
linked pointers, m=2, R=1,700,000,000, F=80,000,000 and R'=1,620,000,000 sompi.
The current context uses the three published commitments and outpoint
`[0x33;32] || u32le(1)`. The historical context adds SHA256 of exact ASCII
`KPI/public-two-v6-state/DO-NOT-FUND/extra-cm/0` and `/1`, then uses
`[0x55;32] || u32le(2)`. Its prior history contains the real count-3 anchor,
while its current root/count are 5. These are declared synthetic predecessors;
neither is reconstructed from accepted bootstrap or admission transactions.

Frozen outputs are under `poc/two-v6-state/public-fixtures/`:

| Case | Input SHA256 | J336 SHA256 |
| --- | --- | --- |
| Current anchor, n3→7 | `a929815b643811c64ab881fda95f39bec30849e5129778f4c70cc041f36bbdc6` | `7e373ada5dd73210c5ba345142c5df89893ee31a3ba9b27a12d77d54f6e83572` |
| Historical anchor, n5→9 | `544219aaba5b4738a546691eed6cc7b93a4cda6f2c3b158ef51fbf8c4bcbf462` | `457a9c09edd5840a978f8b785e165af3656c77f579b43ff322a9b3548a88c3f3` |

Manifest SHA256 is
`3dec202e797fd714547de6ef77e76489c557188f4e4e38b2d01c0618c495f9c6`;
oracle SHA256 is
`77788cb3cb15a497ad02b6c9fd08c659fe2909e691823b855243be69afd8372e`.
It contains every prior/next state, intermediate NF/CM/history root, full
declared public leaves, source identities and file hashes. Generation and a
second read-only `--check` both completed. An encoding-only repeated-record
control preserves four records; it is not claimed as a new genuine proof pair.

The independent reviewer also reproduced every byte in both fixtures using
recursive sparse-subtree hashes and a freshly rebuilt numeric-ordered linked
set, rather than this oracle's incremental links. Its retained report is
`review/research/intensive-2026-10-22/review/state-assertion-independent-recount.json`;
the independent source `state_assertion_recount.py` has SHA256
`df4387b0eba76b061a73c51daad28e1976074fd83044b382e7246c87c7e52a26`.
This is independent public state/wire agreement, not proof or native acceptance.

## Native boundary and qualification order

The guest establishes a transition relative to its supplied predecessor. A
future native adapter must reconstruct this exact J from the actual prior
outpoint, script-committed S7, input amount, P and output state/amount. Echoing
the prior roots in J does not itself authenticate an actual input. Its script
must enforce immutable policy, exact one input/output, metadata, correct output
amount and actual fee. The current assertion has no continuing reserve/exit
policy and must never be funded or presented as a deployable pool.

First compare host-core results with both independent J336 fixtures and retain
typed semantic failures for history, spentness, path/root/count boundaries,
fee conversion, wrong P and framing. Then select the distinct guest image and
measure execution before any separately allocated proof. A real receipt can
subsequently qualify one native outer predicate or a separately labelled
synthetic transaction-context diagnostic; neither qualifies owner exits.

The old 0x21 + two native inner-proof transaction remains rejected by its
545,000-gram verifier floor above the 500,000 cap. The now-tested official
Groth16 compression of the old J42 changes that receipt's representation, not
its missing state assertion. No old receipt or default budget can qualify the
new image or transaction by inference.

## Reusable pinned source

| Module | Reuse / limitation |
| --- | --- |
| `two_input/tree.rs:9-103` | Tagged hashes, depth16/17 Merkle trees, raw-zero empty paths; SHA256 `9fc004721ae2a22c6faa26f2a046eefd7bb707e3c83077be01a7913b464891ed` |
| `compact/tree.rs:44-49` | NfLeaf68 and LE comparator only; its older state/count rules are not v6. SHA256 `4ac46cb3e514e58181d0a4e2195e882f22d1df83d8dc6ea926fac47102ea0dc6` |
| `two_input/tree.rs:184-292` | Source model for history and sequential NF updates; adapt four/two appends in a new version |
| `two_input/covenant.rs:359-453,495-621` | Native anchor/current-NF/append/amount constraints; old offsets/witness cannot be reused as a receipt adapter |
| `two_input/replay.rs:186-320` | Full public reconstruction, tracked outpoint continuity and native/accounting checks; new framing needs new replay |
| `two_input/wallet.rs:501-535` | Direct owner DRAIN preparation requires genuine parameters and selected owned notes, absent from this fixture |
| `poc/two-v6-binding/common` | Unchanged checked pair relation and fixed compiled development gate, distinct from original default instance |

The fresh inner PK was destroyed, so no new owner DRAIN proof can be generated
for this setup. The filler commitment and declared predecessor NFs do not prove
an accepted liability history. Funding readiness, service-independent owner
exit, privacy and production safety remain unestablished.
