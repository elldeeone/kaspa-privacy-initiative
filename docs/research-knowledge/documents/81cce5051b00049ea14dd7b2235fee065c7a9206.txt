# Aggregate gzip-to-R1CS streaming design

Status: the retained aggregate path remains a read-only design. The admission
scanner is implemented. A source-pinned tiny fixture now has a fail-closed
streaming exporter and a separately implemented streaming verifier, but both
are structurally pinned to three rows and reject the aggregate artifacts before
output. No full R1CS export, setup, zkey, Powers of Tau, or ceremony was run.

The 2026-10-29 admission scanned every frozen row and term in 6.20 seconds with
2,880 KiB peak RSS. It proved all coefficients nonzero/canonical, all columns
in-range and strictly increasing/unique per LC, every gzip/raw identity exact,
and the `c02320...56ab` fingerprint equal. Axis maximum row arities were A=1032,
B=8, C=446. The create-new receipt is retained at
`.local/r1cs-bridge-aggregate-admission-20261029-01/RECEIPT.json`, SHA-256
`41b39354f9c87b5fa00880e31fdf7c9f121ce2bab8dd27f577e0907766523191`.

## Frozen input

The retained current-source artifact is
`.local/private-batch-current-matrix-equivalence-20261029-01/artifact/`.
Its exact manifest SHA-256 is
`34cb8d48a1a2c9e6cbb8fb2481cfb73fc53d46d6f91c07655234485228e363e5`.
The tracked equivalence receipt is
`private-batch-relation/evidence/2026-10-28-full-financial-source/current-matrix-equivalence-2026-10-29.json`.

The adapter must compile these constants into its source. It must not accept
caller-supplied replacement paths, counts, or digests.

| Axis | gzip bytes | gzip SHA-256 | raw bytes | raw SHA-256 | terms |
|---|---:|---|---:|---|---:|
| A | 132,280,879 | `4a78fccf7f49e9f25a77b2f212fb99b9beb0a6da63240567c13ae2d7754ff048` | 1,439,778,032 | `002b86f052e75f6e98eebfd27f977c5dcb7362a15d0a25d5af6642ac0cd2ecee` | 33,375,843 |
| B | 39,357,111 | `8fe2d65194704b601f911099a5ed4123a2fd4f374aaefb1b1d620cc1603ca34c` | 703,804,592 | `a32c39c1e0a087172fb396a019ee3ad3ebff5b5833281ef1d72162e38cf5d565` | 14,976,507 |
| C | 71,201,926 | `7e921a7eda84e389c91e2a9b6674b74c8c0dbc056ac78d9953976a95912f6d92` | 1,036,906,272 | `000b71a3433cb0b0e0ed3bb155a064314710fca5be5e26088ab5606aa588dbae` | 23,304,049 |

The axis format is `KPI_R1CS_AXIS_V1`: an 80-byte header, then for every row
an eight-byte term count and `count` pairs of coefficient32LE then column64LE.
The canonical Arkworks matrix fingerprint is
`c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab`.
Geometry is three instances including `ONE`, 12,949,818 witnesses,
12,949,821 variables, and 13,093,029 rows.

Term counts follow exactly from the pinned raw sizes:

```text
axis_terms = (raw_bytes - 80 - 8*rows) / 40
```

Admission must recompute them from every decoded row; the formula alone is not
authority.

## Exact standard R1CS v1 output

The output freezes three sections in order: header (1), constraints (2), and
wire-to-label map (3). The header is:

```text
field bytes       32
prime             BN254 scalar modulus, canonical 32LE
nVars             12,949,821
nOutputs          0
nPubInputs        2
nPrvInputs        12,949,818
nLabels           12,949,821
nConstraints      13,093,029
```

Wire 0 is Arkworks `ONE`; wires 1 and 2 are `INSTANCE[0..2)`; wires 3 onward
are Arkworks witnesses without an offset change. The map is the identity
`0..12,949,821` encoded as u64LE.

The constraint section is row-major `A[row], B[row], C[row]`. Each linear
combination contains count32LE followed by exact pairs of wire32LE then the
unchanged coefficient32LE. Terms are neither sorted, combined, nor dropped by
the adapter.

Exact checked sizes are:

```text
total terms              71,656,399
row/axis count framing      157,116,348 = rows * 3 * 4
term framing/data          2,579,630,364 = terms * 36
constraint section        2,736,746,712
identity wire map           103,598,568 = variables * 8
complete R1CS file        2,840,345,392 bytes
```

All file and section arithmetic uses checked u64. Counts written in u32 fields
must be checked before narrowing. These exact values fit the format.

## Bounded fail-closed passes

1. The controller opens the three regular input files without following
   symlinks and passes read-only descriptors. The adapter accepts no paths.
2. Admission streams each single gzip member to canonical EOF, rejecting bad
   CRC, truncation, trailing bytes, a second member, size/hash drift, wrong
   magic/axis/field/geometry, extra rows, and early EOF. It recomputes all raw
   hashes and the `KPINAS/R1CS/v1` matrix fingerprint.
3. Every term is checked as a canonical nonzero field residue with a column
   below 12,949,821. Every row must have a u32 term count and strictly
   increasing columns. This proves zero terms and duplicate/reordered columns
   cannot be lost by snarkjs' object representation. A failure emits no R1CS.
4. Only after complete admission does the controller provide a private fresh
   output descriptor. A second pass keeps one decoder cursor per axis and
   streams A/B/C in row lockstep. It copies each coefficient byte-for-byte and
   performs only checked u64-to-u32 column conversion.
5. The second pass rechecks every compressed/raw hash, header, row, term, and
   canonical EOF. It writes the exact precomputed section sizes, then the
   identity map, verifies the final file size, hashes the entire output, and
   calls `fsync`.
6. A separately built verifier reparses the output and lockstep-compares every
   term to fresh input cursors. It checks section order/sizes, header, map,
   exact EOF, output SHA-256, and all frozen input identities. Only verifier
   exit 0 permits an atomic durable publish and receipt.

No pass retains a row. It needs three fixed decoder windows, one 40-byte input
term, one 36-byte output term, and bounded I/O buffers. Memory therefore does
not grow with 13,093,029 rows or 71,656,399 terms.

The receipt binds the adapter/verifier source and binary identities, all input
pins, matrix fingerprint, exact geometry and term totals, every section size,
complete output bytes/SHA-256, and successful EOF/fsync/verifier status. It is
an R1CS conversion receipt, never a setup or toxic-waste-erasure receipt.

## Tiny implementation evidence

`stream_tiny_r1cs` implements the two-pass structure against the frozen
three-row fixture. It binds the exact plan, fixture source, gzip/raw inputs,
matrix fingerprint, running exporter binary, output, and false authority flags.
It publishes the durable R1CS first and the durable export receipt last; that
receipt is the exporter commit marker, not a multi-file atomic transaction.

`verify_streamed_r1cs.py` uses Python `zlib`, not the Rust decoder or parser.
It independently checks a single gzip member and CRC/EOF, replays every input
row/term against the standard R1CS stream, verifies the identity map and exact
section bytes/EOF, binds the exporter binary and complete export receipt, and
only then publishes its create-new receipt. In this tiny prototype the verify
receipt, not mere presence of the R1CS, records successful independent review.

The streamed R1CS is byte-identical to the direct encoder: 736 bytes, SHA-256
`786364162a371e862488ed92dbb12e36670024c9fbb8c3acc1391f4c2bce33ab`.
Pinned `snarkjs` 0.7.6 reads it as BN254 with six wires and three constraints.
The combined Python suites have 25 controls (8 direct plus 17 streaming); the
Rust suite has four tests. A positive run used 2,980 KiB peak RSS in the Rust
exporter and 18,604 KiB in the Python verifier, with no swaps; all published
files had mode `0600`.

## Required hostile controls

- swapped A/B descriptors, row reorder, and term reorder;
- zero, noncanonical, changed, duplicate, and out-of-range terms;
- wrong field, counts, source/matrix identity, or manifest;
- gzip truncation, CRC failure, trailing garbage, and concatenated member;
- count/section overflow and wrong public/private split;
- partial output, output corruption, nonidentity wire map, extra section, and
  trailing output bytes;
- verifier nonzero exit, signal, partial read, or input substitution between
  admission and verification.

## Remaining blockers

1. Only the six-wire adapter/verifier is implemented. A production adapter
   must replace the tiny compile-time pins with the reviewed aggregate pins,
   inherited input/output descriptors, full source-closure identity, resource
   guard, and independent production-binary selection. That change is not
   authorized by the tiny plan.
2. The exact Output matrix has no equivalent frozen gzip-axis artifact. This
   design currently covers only the retained aggregate matrix.
3. Hybrid relation work is still in flight. Source/build closure must stabilize
   before any production pin or worker identity is refreshed.
4. The current aggregate rows are retained local artifacts, not an immutable,
   independently distributed ceremony input.
5. `snarkjs` 0.7.6 reads the constraint section and constructs all constraints
   in memory for `zkey new`. Export streaming does not make that Phase-2 path
   bounded; its memory/resource guard or a reviewed streaming-compatible tool
   remains unresolved.
6. No zkey-to-Arkworks-0.6/mcl conversion and cross-proof corpus exists. The
   identity-map/private-input policy also needs end-to-end witness validation.
7. A verified Power-24 Phase-1 transcript, ceremony governance, the pre-key
   trial authority, post-setup measured-key join, and 60 selected-parent
   artifacts remain missing.
