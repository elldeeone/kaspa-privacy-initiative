# Loading the new development proving key

Status: source-only review, 2026-10-23. No key load, conversion, benchmark,
setup, proof, or active-run change was performed for this note. The only
selected key discussed here is the fresh KPX2 development instance. All data
is synthetic `DO_NOT_FUND` research.

**Recommended smallest change:** a separate, explicitly trusted loader may
verify the entire current PK against independently selected, compiled pins,
then call Arkworks' supported `deserialize_compressed_unchecked` on those
exact immutable bytes. Keep the existing fully checked path for every
untrusted key, VK and submitted proof. This can remove repeated point
validation; it cannot remove compressed-point square roots, so a speedup is
unmeasured and may be modest. Do not modify or restart the baseline to test it.

## Current source and evidence

The frozen runner hashes the compressed file, opens it again, calls
`ProvingKey::<Bn254>::deserialize_compressed`, rejects trailing data, extracts
the VK through the payment library's checked VK function, and compares it to
the selected VK. See [frozen runner](../lifecycle/source-setup-01/poc/future-lifecycle/src/main.rs)
and [pre-proof selection](../lifecycle/PRE-PROOF-FREEZE-01.json).

The following are observed small metadata/pin values, not a new read or hash
of the 1 GB PK:

| Selected object | Identity |
| --- | --- |
| Typed `new-key-selection.json` | SHA256 `8c207d6e1220601c91a3eed3955e968949b46d9550c449b66bbd414df75027b9` |
| Compressed PK | Expected SHA256 `e95202462feaeeeed6761ae0ae137c86c9730c54612df42252d3b3c085e86bfb`; filesystem length `1,006,401,200` bytes |
| Native-compatible VK328 | SHA256 `5f551fa7b0cbeb9ec89ccf0e198575b1803db4c8012919166436af625e0136bc` |
| Circuit source | SHA256 `e1e3e3e6201ef817516fda2c48fa6dbefb275fecf56632c10c4d7fe915798bd3` |
| Library source | SHA256 `fc38cee6232d35b5685f8e78c097dbe9f749acddb91111b22991146ec08cecf2` |
| Domain | `9de4f84dbdaec6250d0029ca4b38ae12b9081a549e231eb529075af7fe59e85c` |

The retained [proof-01 report](../lifecycle/proof-01/report.json), read after
it appeared, reports `genuine_Groth16_verified=true` and total runner wall
`198.038799921` seconds. Its SHA256 is
`465eab9f805074a96f3c466ca32e0c3f52452d0a2465a51575d9d21ef83afe0d`.
The [time record](../lifecycle/proof-01/resources.log), SHA256
`7df184e7509fa4c4a3d331c4dcf9f082e0222f393198daa53001c0fa3ae8f960`,
records 628.62 user CPU seconds, 3:18.12 wall, 5,674,112 KiB maximum RSS and
zero swaps. Those are **whole-process** measurements, not isolated PK load
or proving times. The existing runner has no timing boundary around
deserialization. Interim CPU observations cannot establish a final loader
duration or locate the exact internal phase. A completed saved report is
also not an independently repeated proof verification or native validation.

## Why fourteen threads do not parallelize the entire load

Arkworks 0.6 already enables `ark-serialize/parallel`: Groth16 defaults to
`parallel`, forwarding it through `ark-ec`. The default validity batch
uses Rayon over individual elements. Explicitly adding this same feature
does not create further parallelism. This is point-by-point validation
distributed between threads, not a new algebraic batch-check primitive.
Sources: [Groth16 features](https://github.com/arkworks-rs/groth16/blob/0bb3e604c534bd118ed477eaf1231f591d6fc40f/Cargo.toml#L45-L55),
[EC feature forwarding](https://github.com/arkworks-rs/algebra/blob/bffa52711f225e888c1a91e1ec9fc59f2d9d5c94/ec/Cargo.toml#L51-L58),
[validity batch implementation](https://github.com/arkworks-rs/algebra/blob/d168323a6c7adf25210030fdd2c0be734b52f85b/serialize/src/lib.rs#L69-L107).

The derived PK decoder visits its fields in order. For each query vector,
the collection decoder first reads and decompresses its points sequentially,
then calls the parallel validity batch. It finishes that vector before
moving to the next. No built-in parallel compressed PK decoding entry point
was found in these pinned sources. Sources:
[PK fields](https://github.com/arkworks-rs/groth16/blob/0bb3e604c534bd118ed477eaf1231f591d6fc40f/src/data_structures.rs#L124-L143),
[derive](https://github.com/arkworks-rs/algebra/blob/a5460be2d98e709133f3947eae535d3d67ca3355/serialize-derive/src/deserialize.rs#L135-L208),
[vector decoder](https://github.com/arkworks-rs/algebra/blob/d168323a6c7adf25210030fdd2c0be734b52f85b/serialize/src/impls/collections.rs#L72-L95).

Compressed affine decoding reconstructs a y coordinate using a square root,
even with `Validate::No`. The later validity check verifies the curve
equation and subgroup. Thus a long low-CPU interval is consistent with
sequential decompression; it is not evidence that Rayon is disabled.
Uncompressed decoding reads x and y and avoids that square root. Sources:
[compression switch](https://github.com/arkworks-rs/algebra/blob/bffa52711f225e888c1a91e1ec9fc59f2d9d5c94/ec/src/models/short_weierstrass/mod.rs#L148-L193),
[square root](https://github.com/arkworks-rs/algebra/blob/bffa52711f225e888c1a91e1ec9fc59f2d9d5c94/ec/src/models/short_weierstrass/affine.rs#L129-L141),
[affine checks](https://github.com/arkworks-rs/algebra/blob/bffa52711f225e888c1a91e1ec9fc59f2d9d5c94/ec/src/models/short_weierstrass/affine.rs#L414-L431).

## Trusted exact-bytes loader boundary

Arkworks explicitly exposes checked and unchecked compressed/uncompressed
APIs and limits unchecked use to input the caller can guarantee is valid.
The caller must supply that guarantee; the function does not authenticate
its source. [API contract](https://github.com/arkworks-rs/algebra/blob/d168323a6c7adf25210030fdd2c0be734b52f85b/serialize/src/lib.rs#L182-L219).

A useful narrow API would accept a privately constructed
`VerifiedDevelopmentPkBytes`, not arbitrary bytes plus a caller-selected
hash or a generic `unchecked: bool`. The constructor should:

1. Require an independent root-selected typed selection digest and compiled
   PK length/hash, exact VK bytes/hash, domain and circuit/library source
   pins. Check the selection's exact bytes before parsing it and validate
   its schema/classification. A digest in an adjacent prover-created file
   provides consistency only. The frozen root/caller selection supplies
   authority; it must not be replaceable alongside the key.
2. Require recorded provenance from this fresh valid setup and, preferably,
   the already completed checked baseline for exactly that full PK digest.
   Group validity does not prove a correct ceremony, circuit correspondence,
   trapdoor erasure or parameter honesty. Existing local development setup
   assumptions remain unchanged. A matching VK alone does not authenticate
   all PK query vectors.
3. Read exactly the pinned length into an owned byte buffer, reject extra or
   missing bytes, hash that entire buffer and compare with the compiled PK
   digest **before** any unchecked deserialization. Deserialize from that
   same immutable buffer. This closes the hash-file/reopen-file race. A
   read-only bind of a path alone does not prevent another writable alias
   from changing its contents. Drop the source buffer before proving and
   measure its temporary memory cost.
4. Call the official `deserialize_compressed_unchecked` only inside this
   private trusted constructor. Require complete consumption. Extract the
   VK through the existing fully checked VK helper and require exact
   equality to the independently pinned native VK328. The selected origin
   and full-byte hash carry the other query vectors' provenance; optional
   length diagnostics do not replace them. Do not infer circuit validity
   from canonical decoding alone.
5. Leave Authorization validation, all untrusted proof/VK checked decoding,
   canonical round trips, subgroup/nonidentity checks, arity checks and
   genuine verification against the fixed native VK unchanged. A PK mismatch
   fails the trusted path; do not silently accept a new pin or switch keys.

This changes parameter-loading cost only. The trusted object is the exact
new PK, never a submitted proof. It neither alters the circuit nor turns a
self-selected VK into an accepted native policy.

## Alternatives and practical order

| Option | Source-supported effect | Remaining cost / decision |
| --- | --- | --- |
| Keep checked compressed load | Existing behavior; vector validity already parallel | Sequential square roots; baseline remains immutable |
| Retain a checked PK in memory | Avoid a repeat load in the same process | Warm-process optimization only; resident memory persists |
| Exact pinned compressed unchecked load | Skip repeated point validity checks | Sequential square roots remain; smallest new trusted-loader experiment |
| New checked uncompressed cache | Skip square roots without skipping validity | New representation and pin; roughly twice the disk bytes; validity still costs CPU |
| Exact pinned uncompressed unchecked cache | Skip square roots and repeated validity | Separate authenticated derived artifact; larger I/O; strongest source-backed cold-load hypothesis |

For an uncompressed cache, create a new artifact from the selected **checked**
PK, using official `serialize_uncompressed`, then flush/fsync it and freeze
its full hash, size, source compressed hash, format/version and originating
selection. Do not overwrite or reinterpret the compressed file. A future
load must hash the exact bytes it subsequently decodes, as above. The
uncompressed cache pin must be independently selected after provenance
review, not taken on trust from the cache generator. Retaining the same VK
does not identify the rest of that cache.

The serialized point coordinates double in uncompressed form, while six
u64 vector lengths stay eight bytes each. For this PK layout and compressed
length, the predicted uncompressed size is `2*1,006,401,200-48 =
2,012,802,352` bytes. This is source arithmetic, not an observed cache.
An owned-buffer implementation temporarily holds encoded bytes plus the
decoded PK; do not advertise a 4 GiB client peak before measuring it.

First measure hash, decode, checked-VK comparison and total loader time
separately in a loader-only new stage after root approval. Preserve CPU
seconds, wall, peak RSS, swap and filesystem/cache conditions. It can compare
the resulting checked VK without generating another proof or setup. If
compressed unchecked still spends most time decoding, a separately pinned
uncompressed cache is more promising than a custom parallel point parser.
No support or performance result for such a loader is claimed here.

The R8 cold-start target, four-core CPU-only laptop target, whole-wallet
memory bound, warm proof latency and end-to-end recognition latency remain
separate gates. Even removing all PK load time would not establish any of
them from one whole-process run. No GPU acceleration is implied by Rayon.

## Review and scope

A parallel read-only source pass independently confirmed the vector decoder,
existing Rayon feature path, sequential square roots and official
uncompressed alternative. It also conditionally accepted the narrow trusted
loader after the exact checked baseline, with compiled authority,
hash-before-parse of the same owned bytes, full consumption and unchanged
proof/VK checks. Production library/circuit, active runner,
selected key and all frozen packets were left unchanged. This note proposes
one small loader boundary; it does not authorize a new experiment.
