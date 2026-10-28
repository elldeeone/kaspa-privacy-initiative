# ADR-0081: Fixed-width private owner records

Date: 2026-10-28.

Status: Implemented. Thirty-one parser/producer controls passed, including all
three full-size vectors. A genuine three-party small MPC proof passed through
the binary reader, with independent valid/changed-statement verification.
Canonical producer build and writer unit checks passed, as did seventeen
integrated receipt, metadata and routing controls. This does not qualify a
complete financial batch. The active immutable Source05 run is unchanged.

The follow-up local metadata repair is also implemented. Signature inputs,
normalized witness, matrix, mapping and immediate auxiliary request/record stay
on the owner's existing namespace-local `/tmp` tmpfs. Five focused record tests
and the existing genuine public-known-seed colluder fixture passed. A real stock
signature-generator/normalizer check reproduced the same 10,049-variable witness
bytes while leaving the host-bound owner directory empty. These controls use
public fixtures, not actual private owner data.

## Privacy problem

The owner auxiliary producer writes one unpadded decimal integer per field
element. Its private contents stay within the owner role, but its byte length
depends on those values. File lengths belong to the declared dispatcher view.
The existing fixed field count and fixed-width DDNNT wire messages do not erase
that earlier local metadata exposure. This is a value-dependent side channel;
no unique NF or payment linkage has yet been demonstrated from it.

## Decision and exact encoding

Replace the owner-local text handoff with one explicitly selected binary format:

```text
"KPB_OWNER_FR32V2"  (16 literal ASCII bytes)
owner              u64 little-endian
count              u64 little-endian
values             count * 32 bytes, canonical BN254 Fr little-endian
```

The owner must be 0, 1 or 2. The count must equal the selected public job's exact
count before allocation or value consumption. Each encoded integer must be
strictly below Fr's modulus; never reduce a noncanonical value. Reject truncation,
extra fields/bytes, wrong magic, wrong role/count and malformed input. Check a
stable regular single-link file through its opened descriptor and preserve the
existing private namespace and path restrictions. Do not guess a format or
silently fall back to decimal parsing.

For the current financial job, all owners supply 2,635,409 values: 84,333,088
payload bytes and exactly 84,333,120 total bytes, independent of private values.
Do not compress this file into a value-dependent container on the observed path.
Only public format/count/size metadata may enter controller receipts; do not
publish a private body hash.

## Temporary material and retained colluder knowledge

Fixing the final Fr32 file alone leaves variable-length signature JSON files in
the host-bound owner directory. Keep those intermediates on private namespace
tmpfs instead. The existing colluder diagnostic legitimately consumes the full
owner-local record later; deleting it would weaken that observer.

Retain every existing record field using `OWNER-LOCAL-RECORD-V2.bin`, exactly
32,768 bytes: 16-byte `KPB_OWNER_REC_V2`, owner u64LE, private JSON length u64LE,
the unchanged canonical full JSON, then zero padding. The existing public field
widths and integer ranges bound that JSON at 9,823 bytes. The strict decoder
checks the exact owner, frame size, field schema/ranges, canonical encoding and
zero padding. It has no text fallback and exports no private-content hash.
Only the isolated owner/colluder roles read that body. Persist it after the
existing auxiliary checks succeed; keep the genuine CF/NF knowledge unchanged.

Both pay and Exit normalization reuse the existing `/tmp` mount. Its namespace
placement removes these host-bound directory entries from the declared metadata
view; it does not protect against a host administrator inspecting process memory
or namespaces. File-size statements concern the selected dense, uncompressed
files. Timing, access patterns and the complete server view remain separate.

Reuse the existing Fr semantics, owner auxiliary ordering, public job binding,
TLS authentication, masked DDNNT input, private assignment and proof checks.
This changes the local file codec, not the field, cryptographic relation, proof
keys, D/Profile or network V2 contract. Preserve old qualified text snapshots;
the new producer and reader must be selected together under a fresh execution
identity. No active private file or running snapshot is rewritten.

## Required evidence and limits

Before execution, freeze a paired public-fixture control using equal field
counts and different canonical values. Decimal lengths must expose their actual
variation; binary lengths must be identical, and both decoded vectors must match
their intended fields exactly. Include 0, 1 and P-1, Fr aliases P/P+1, malformed
headers, truncation, trailing bytes, wrong role/count and file mutation cases.

Run one genuine three-party owner-input/MPC proof through the selected binary
reader, with independent valid-proof acceptance and changed-statement refusal.
A parser-only test cannot qualify the actual handoff.

This removes a specific file-size dependency. Cohort membership, connection
order, timing, receipt paths, all real protocol bytes and corrupt-server state
remain observable under the existing model. The old privacy failure and missing
view coverage remain recorded; constant file length is not an anonymity proof.
No mainnet, real funds, new primitive or withdrawal authority is introduced.
