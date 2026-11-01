# THROWAWAY: Arkworks to Circom/snarkjs R1CS bridge prototype

This prototype answers one narrow question: can the exact Arkworks 0.6 BN254
instance/witness/row order be encoded deterministically in the standard binary
R1CS v1 format and independently recovered?

It does **not** export either real payment relation. It creates no Powers of
Tau file, `zkey`, proving key, verifying key, proof, ceremony contribution, or
setup randomness.

## Frozen tiny fixture

BN254 scalar modulus:

```text
21888242871839275222246405745257275088548364400416034343698204186575808495617
```

Coefficients are canonical residues in 32-byte little-endian form. Negative
one is `modulus - 1`. Explicit zero terms are forbidden.

| Wire | Arkworks source | Fixture value |
|---:|---|---:|
| 0 | implicit `ONE` | 1 |
| 1 | `INSTANCE[0]` / `public_left` | 7 |
| 2 | `INSTANCE[1]` / `public_right` | 11 |
| 3 | `WITNESS[0]` / `x` | 3 |
| 4 | `WITNESS[1]` / `y` | 5 |
| 5 | `WITNESS[2]` / `product` | 15 |

The header freezes `nPubOut=0`, `nPubIn=2`, `nPrvIn=3`, six wires, six
identity labels, and three constraints. Rows remain in Arkworks enforcement
order. Terms within each A/B/C row remain in strictly increasing Arkworks wire
order.

The canonical fixture is 736 bytes with SHA-256
`786364162a371e862488ed92dbb12e36670024c9fbb8c3acc1391f4c2bce33ab`.

The three rows are:

```text
x * y = product
(product + 2*public_left + 3) * 1 = 2*public_right + 10
(public_left - x) * (public_right - y) = product + 9
```

The first source LC contains an explicit zero term. Arkworks removes it at the
matrix boundary; the exporter refuses any zero term that survives that
boundary.

## Run

```sh
cd poc/local-private-payment/private_batch_trial/r1cs_bridge_prototype
cargo build --locked --offline
./target/debug/kpb-r1cs-bridge-prototype /tmp/kpb-tiny.r1cs
python3 verify_r1cs.py /tmp/kpb-tiny.r1cs
python3 -m unittest -v test_r1cs_bridge.py
```

The official compatibility check is read-only and does not perform setup:

```sh
npm exec --yes --package=snarkjs@0.7.6 -- \
  snarkjs r1cs info /tmp/kpb-tiny.r1cs
```

The separate full aggregate admission scan reads the already frozen gzip axes
but never writes an R1CS:

```sh
cargo build --release --locked --offline --bin scan_frozen_aggregate
./target/release/scan_frozen_aggregate \
  A.r1cs.bin.gz B.r1cs.bin.gz C.r1cs.bin.gz NEW-RECEIPT.json
```

The retained 2026-10-29 scan passed all 13,093,029 rows and 71,656,399 terms
with 2,880 KiB peak RSS. Its create-new receipt is
`.local/r1cs-bridge-aggregate-admission-20261029-01/RECEIPT.json`, SHA-256
`41b39354f9c87b5fa00880e31fdf7c9f121ce2bab8dd27f577e0907766523191`.
It records `r1cs_exported=false`, `zkey_generated=false`, and
`setup_executed=false`.

The bounded streaming implementation is intentionally compiled for the tiny
fixture only. Its plan has `aggregate_full_export_authorized=false`, and the
production gzip axes fail its exact compressed-size pins before any output is
created. The hostile suite generates the three pinned tiny gzip axes, runs the
two-pass Rust exporter, and then runs the separately implemented Python
streaming verifier:

```sh
cargo build --release --locked --offline --bin stream_tiny_r1cs
python3 -m unittest -v test_streaming_r1cs.py
```

The exporter requires a fresh empty output directory. It admits every input
byte before output, reopens and rechecks all three axes for the export pass,
publishes `tiny.r1cs` create-new after `fsync`, and publishes
`EXPORT-RECEIPT.json` last as its commit marker. The verifier independently
preflights the inputs, lockstep-compares every output term, requires exact
sections/map/EOF and the exporter binary identity, then create-new publishes
`VERIFY-RECEIPT.json`. A complete positive run used 2,980 KiB peak RSS for the
Rust exporter and 18,604 KiB for Python; neither swapped. All three published
files had mode `0600`.

## Independent controls

The Rust exporter uses Arkworks matrices. The Python verifier does not import
the exporter and freezes the field, counts, wire order, assignment, every
A/B/C term, row order, section order, identity wire map, and final file hash.

The test suite requires rejection of:

- reordered constraint rows, even though the resulting relation is equivalent;
- an explicit zero coefficient;
- a changed canonical coefficient and a noncanonical field encoding;
- a same-shape, still-satisfied `x*y -> y*x` matrix substitution;
- a substituted field modulus; and
- substituted variable counts.

The streaming suite additionally rejects changed/truncated/swapped gzip input,
caller plan substitution, a wrong exporter binary, altered input pins in the
export receipt, partial/corrupt output, extra output-directory entries,
symlink output directories, exporter/verifier reuse, and the real aggregate
artifacts. The streaming file is byte-identical to the direct encoder: 736
bytes and the canonical SHA-256 above.

## What this establishes

For this six-wire fixture only, the standard format can carry the exact
Arkworks matrix and ordering without ambiguity, and both an independent parser
and pinned `snarkjs` can read it. This is format-bridge evidence, not ceremony,
cryptographic-correctness, privacy, or production evidence.

## Blockers before streaming the real relations

1. The Hybrid-owned relation source and complete build closure must stabilize.
2. `ConstraintSystem::to_matrices()` materializes the full matrix. The tiny
   bounded adapter proves the two-pass format mechanics, but it is structurally
   unable to select the 13,093,029-row aggregate. The production-sized adapter
   in `STREAMING-DESIGN.md` still has no executable export path.
3. The full exporter must prove that its row source is byte-identical to the
   already frozen A/B/C matrix identity, including instance/witness offsets and
   empty rows. Counts or a semantic spot-check are insufficient.
4. This prototype classifies every Arkworks witness wire as a private input and
   uses an identity wire-to-label map. `snarkjs` Phase 2 uses the public split
   and total wire count, but a full witness/cross-proving path must separately
   freeze private-input versus internal-label semantics.
5. A complete, independently verified Phase-1 transcript is still unselected.
6. No `zkey -> Arkworks 0.6 -> mcl` key/query converter or cross-proof corpus
   exists.
7. The source-owned pre-key trial authority and post-setup measured-key join
   remain missing. Generated key identities are post-setup outputs only.

## Pinned format and ordering sources

- `r1csfile` v0.0.48 format and reader/writer, commit
  [`d82959da1f88fbd06db0407051fde94afbf8824a`](https://github.com/iden3/r1csfile/tree/d82959da1f88fbd06db0407051fde94afbf8824a)
- `snarkjs` v0.7.6, commit
  [`9a8f1c0083d18b9b5e18f526cfd729e7259423be`](https://github.com/iden3/snarkjs/tree/9a8f1c0083d18b9b5e18f526cfd729e7259423be)
- Arkworks `ark-relations` 0.6.0 source commit
  [`d027f19d699d3af459ae4924366d71159231bc82`](https://github.com/arkworks-rs/snark/tree/d027f19d699d3af459ae4924366d71159231bc82/relations)
