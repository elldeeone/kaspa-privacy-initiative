# Shared compressed stock proving-key reader

`gzip_queries.cpp` implements the existing stock Ark0.6 compressed proving-key
format over one immutable gzip artifact. `PackedModel::admit_compressed` binds a
completely admitted store to the exact existing model metadata, VK and three
matrix transports. The raw-PK mmap prototype remains available separately.
Neither public storage API grants assignment validity or financial acceptance.

## Admission and ownership

The controller seals the compressed artifact once. Roles use
`SealedTraceArtifact::adopt_sealed_fd`; adoption duplicates only a regular
kernel-sealed descriptor and re-stats after observing all seals. Independent
streams use `pread` and separate decoder state over those same encoded bytes.
There is no decoded PK spool, whole query vector or per-role key copy. The
store retains only the small VK, fixed bases/prefix and immutable shared handle.

`GzipQueryStore::admit` requires the actual container and canonical PK hashes and
sizes, pinned decoder identity, shape and VK identity. It deep-copies the small
VK, checks all role-specific VK/base points, identical PK prefix bytes and exact
stock A, B1, B2, H, L vector lengths. Bounded chunks of 4096 public encoded points
use up to eight public decoder workers. Every point passes the existing strict
finite-coordinate, curve, subgroup and canonical round-trip checks. Identity is
accepted only for query roles. Complete canonical EOF/hash/CRC/trailer checks
precede factory return. The shared store handle copies even when passed an
rvalue, preserving the admitted-store invariant.

Each move-only `GzipQueryCursor` rechecks the fixed prefix and consumes stock
A -> B1 -> B2 -> H -> L. `next_g1(Query)` and `next_g2()` enforce role, order and
counts. `finish()` requires all elements and exact canonical EOF/hash/CRC.
Failure poisons that cursor; moved or completed cursors refuse reuse. Independent
cursors cannot change each other's offsets.

The versioned query transport identity binds canonical PK/VK, physical gzip,
decoder, encoded/raw sizes and shape. It is separate from the proving-model
identity. The financial construction agrees both identities before intake.
`PackedModel::admit_compressed(directory, admitted_store, vk_path, metadata_sha,
rows_descriptor)` requires store shape/key pins and explicit matrix descriptors
to match the actual metadata, then completely scans all matrix rows through the
existing strict cursors and fingerprint check. Compressed queries require the
sequential cursor; random access deliberately refuses. Bases, gammaABC and
counts retain the previous semantics.

## Evidence and limits

The focused build uses assertions and all canonical/subgroup checks, with
`-Wall -Wextra -Werror`, existing pinned dependencies and the reviewed sealed
codec. Reproduce with:

```sh
python3 poc/local-private-payment/mpc-prover/packed/build_gzip_controls.py \
  --root "$PWD" --out .local/gzip-query-backend-build-FRESH
```

Build02 and the small actual stock-PK control passed. The 35 controls cover exact
bases/VK/all-query equivalence across four independent/moved/adopted passes,
wrong order/group, early finish, absorbed failures, every transport pin,
metadata/row binding, malformed framing/points and unsealed descriptors. The
small public fixture compared 84 query points, without private input or MPC.
The larger existing SHA fixture is covered by its separate typed result.

The runtime's separate actual-MPC packed witness-map control also passed: all
four H coefficients matched retained independent Ark values, all three parties
produced the same proof, and the independent verifier accepted public input128
and rejected129. That is a small public fixture control. It does not qualify the
full financial proof, wallet lifecycle, privacy or production use.

The masked proof formula is unchanged. H must be ready before the sequential
query pass; its contribution can precede L by linear addition. The financial
prover must finish the complete cursor and all required protocol/MAC checks
before the first masked A/B1 group opening. Public PK admission does not replace
those checks. No caller-provided Boolean can bypass complete store admission.

Source/build/control receipts are under `packed/evidence/2026-10-28/`. Full
financial key admission and the financial proof are separate runtime milestones;
the public reader controls do not assert they have completed.
