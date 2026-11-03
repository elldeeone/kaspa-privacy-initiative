# Compact public model prototype, version 1

This is an unfunded public-fixture storage prototype. It does not change the
R1CS, Groth16 setup, authenticated arithmetic or proof-release policy. It is
not integrated into the financial prover. Mode1 admits independently public
prefixes. Mode2 carries only a secret-derived prefix recipe identity and shape;
its financial use needs the separately reviewed trusted-construction capability.
Zero placeholders and fixed public-fixture digests are not financial prefixes.

Existing primary sources reused:

- `ark-groth16 0.6.0/src/data_structures.rs`: the unmodified compressed
  `ProvingKey<Bn254>` and `VerifyingKey<Bn254>` byte streams and field order.
- `ark-serialize 0.6.0`: canonical compressed points and vector length framing.
- The existing strict BN_SNARK1 mcl adapter and Native128 codec: canonical Fq,
  curve, subgroup, identity and sign policies.
- Standard gzip framing and zlib decompression; no new compression primitive.

Every integer below is unsigned little endian. Fr values are canonical32-byte
integers in `[0,P)`, not Montgomery representations. All counts use64bits.
Readers reject overflow, truncation, extra bytes, unknown modes, noncanonical
field values and any count or digest mismatch. Exact row and term order,
coefficients, indices, zero terms and duplicate terms are preserved.

## Three exact public matrix streams

`A.rows.gz`, `B.rows.gz`, `C.rows.gz` contain one gzip member each. Producers use
standard `gzip -1 -n` (or equivalent level1, zero mtime and no name). Compression
bytes are separately pinned, so compressor differences create different
transport identities. Concatenated members and trailing garbage are rejected.
Each decompressed stream contains:

| Field | Bytes |
| --- | ---: |
| ASCII magic `KPI_R1CS_AXIS_V1`, no NUL |16|
| Axis0=A,1=B,2=C |8|
| P, the BN254 scalar modulus (header integer, not an Fr element) |32|
| Instance count including ONE |8|
| Witness count |8|
| Row count |8|
| For each row: term count |8|
| For each term: canonical coefficient |32|
| For each term: column index |8|

The header is80bytes. Its complete raw size is `80+8*rows+40*terms`.
There is no model, proving-key or setup claim in an axis stream. The matrix
fingerprint is the existing `KPINAS/R1CS/v1\0` hash: domain15bytes, instance/
witness/row counts as64LE, then all A/B/C rows, each64LE term count followed by
32LE coefficient and64LE column. It identifies exact finalized matrices.

Separate axis streams support lockstep bounded row batches: one cursor for
A, one forB and one forC. No public row collection needs to grow with total
row count. A reader may retain one current row per axis; its heap bound then
depends on maximum row arity, not the number of rows.

## Original stock proving key

`pk.bin` remains the exact stock Ark compressed proving key. It is not re-encoded
or duplicated in a decimal query model. `vk.bin` must exactly equal its prefix.
Its layout is:

1. VK: alpha G1(32), beta/gamma/delta G2(64 each),64LE gamma_abc length,
   gamma_abc G1 points(32 each).
2. beta G1(32), delta G1(32).
3. Five64LE-length vectors in order: a G1, b G1, b G2, h G1, l G1.

Query lengths are variables, variables, variables, domain-1 and witnesses.
Only queries admit identity. VK/bases retain the existing nonidentity policy.
Canonical compressed identity is all zero coordinates plus the infinity flag;
sign+infinity or nonzero infinity coordinates reject. Finite points must retain
canonical coordinates, curve/subgroup checks and an exact codec roundtrip.

For `I` instances, `W` witnesses, `N=I+W` and domain`D`, exact PK bytes are:
`(232+32*I)+64+40+128*N+32*W+32*(D-1)`.
For the current13M-variable financial projection, `I=3,N=12,949,821,D=2^24`,
this is2,608,842,576bytes (2.430GiB), excluding matrices and trace. This is an
arithmetic size calculation, not a generated financial key.

## Canonical metadata root

`model.meta` is the packed model root, identified by SHA256 of these exact
bytes. It binds the original source/model identities, all compressed/raw matrix
hashes and sizes, PK/VK, field/domain parameters and public prefix. Layout:

| Field | Encoding |
| --- | --- |
| Magic | ASCII `KPI_PACKED_V1` followed by3NUL bytes,16bytes total |
| Prefix mode |64LE `1` KnownPublicPrefix or `2` SecretDerivedPrefixRecipe; others reject |
| P, then BN254 base modulus Q |32LE each |
| source SHA256 |32raw bytes |
| original decimal public-model SHA256 |32raw bytes for mode1; allzero for mode2 means no legacy decimal identity exists |
| original stock PK SHA256, then VK SHA256 |32raw bytes each |
| finalized matrix fingerprint |32raw bytes |
| compressed A/B/C SHA256 |3*32raw bytes |
| decompressed A/B/C SHA256 |3*32raw bytes |
| instances,witnesses,rows,domain |4*64LE |
| PK bytes,VK bytes |2*64LE |
| compressed A/B/C bytes |3*64LE |
| decompressed A/B/C bytes |3*64LE |
| omega,omega inverse,1/domain,coset shift |4*32canonical Fr |
| public prefix value count |64LE; mode1 must equal instances, mode2 must be0 |
| mode1 only: public prefix including ONE |count*32canonical Fr |
| mode2 only: derived output count |64LE, must equal instances-1 |
| mode2 only: prefix recipe SHA256 |32raw bytes, nonzero |
| mode2 only: prefix layout SHA256 |32raw bytes, nonzero |

Mode1 metadata is exactly`672+32*instances`bytes. Mode2 is exactly744bytes.
Unknown fields/trailing bytes reject. The supported arithmetic and reduction
are fixed BN254/LibSnark. The allzero legacy-reference marker is an absent
identity, never a public field value or a claim that a legacy model existed.
Mode2 binds the actual public SLOT count and independent recipe/layout/source;
it transmits no secret-derived public values. The trusted recipe must derive
the two actual digest limb LCs from private digest-bit model columns before
assigning instance columns1/2 and must not refer to instance1/2 themselves.
Values may be released only after sealed validation and the durable barrier.
The current prototype does not implement that financial construction or release.

## Immutable access and integration boundary

An admitted reader hashes every mapped public file, parses all row frames and
query lengths, verifies the exact matrix fingerprint, and admits every point
before it becomes usable for private execution. Mappings are read-only and no
mutable pointer or writable file descriptor is exported. Query iteration uses
bounded point chunks and rows use bounded cursors. The host/controller must
mount the admitted files read-only for each role and preserve the trusted-host
assumption; a read-only mapping alone does not defend against a malicious host
that can modify the underlying inode. Public page-cache sharing avoids three
heap copies. This storage type does not replace the sealed assignment or its
MAC/epoch/attempt capability.

The small-fixture control must compare every original row/term and every
original query against the compact reader, exercise malformed inputs, and
report measured memory/bytes. A passing storage prototype does not establish
financial correctness, privacy, native settlement or full-model feasibility.
