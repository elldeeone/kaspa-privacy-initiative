# Optional public-object chunk transport

This additive adapter implements the fixed 1 GiB recipe in the frozen
[distribution plan](../DISTRIBUTION-PLAN-01.md). Existing capsule schemas, five
typed objects, trusted role selection and whole-PK loader stay unchanged. Earlier
evidence snapshots stay unchanged; the narrowly corrected outer iterable guards
are bound through [SOURCE-SUPERSESSION.json](SOURCE-SUPERSESSION.json). Source
research is recorded separately in [SOURCES.md](SOURCES.md).

The caller supplies an independently selected complete raw-file byte length and
SHA256. Neither a mirror's chunk manifest, that manifest's digest, chunk hashes,
filenames nor successful reconstruction selects a financial instance. The tool
handles opaque public bytes only; it does not select/execute software, inspect
backups, decode parameters, prove, broadcast or establish current state.

`poc/recovery-portability/chunk_public.py` has two commands:

```text
pack --source PUBLIC_FILE --expected-bytes N --expected-sha256 H --output-dir NEW
restore --manifest INDEX --expected-bytes N --expected-sha256 H \
        --mirror CHUNK_DIR [--mirror FALLBACK_DIR ...] --output NEW_FILE
```

Both accept repeated `--forbidden PATH` inode exclusions. Restore also accepts
repeated `--must-be-absent PATH` metadata probes. Exclusions are statted before
public reads; one-shot exclusion/probe iterables are materialized before reuse.
Component-wise no-follow opens reject symlinks and forbidden inode
aliases before content-open, and opened metadata is rechecked. Missing/corrupt
candidate chunks may fall back only to the exact same expected chunk. No archive,
compression, network, recursive directory discovery or URL logic is introduced.

The strict canonical JSON index has exactly `schema`, `object_bytes`,
`object_sha256`, `chunk_bytes`, and `chunks`. Schema is
`kpx4-public-object-chunks/v1`; `chunk_bytes` is 1,073,741,824. Each ordered chunk
has exactly `index`, `offset`, `bytes`, `sha256`, and `basename`. Indices and
offsets must cover the complete object once, with full-size chunks and only the
final remainder. Basename is derived exactly as
`chunk-INDEX8-SHA256.bin`, never interpreted as a path. Expected complete length
and SHA must equal the independently supplied anchor before any chunk is opened.
Index parsing is bounded to 1 MiB. No manifest signatures or new authority layer
are added.

Packing streams to a fresh private output directory and authenticates the whole
source before publishing its index. Restore streams bounded buffers into a fresh
owned temporary file, checks every chunk and the complete raw object, fsyncs and
publishes a read-only destination atomically without replacing an existing file.
On error it removes only its own known temporary objects. Output parents use
component-wise no-follow directory opens. File metadata is checked before/after
reads. The existing trusted-host assumption still applies; consumers must repeat
their established full-owned-buffer parameter authentication before private
input. A path receipt is not everlasting byte verification.

Tiny public controls will cover corruption, truncation/trailing bytes, reordered
or self-consistently substituted chunks, wrong external whole anchor, unsafe
paths/symlinks/inode aliases, fallback, source absence and atomic no-clobber/error
cleanup. Tiny multi-chunk fixtures replace the imported module's chunk-size
constant only inside the isolated test process. The CLI has no chunk-size option;
real compact/wide roundtrips use the fixed production 1 GiB rule.

After independent plan/source review, actual compact and wide public PKs will be
packed and reconstructed separately with original paths absent inside the restore
namespace. Caps are 4 CPU / 4 GiB / swap 0. No backup, proof, main private history,
external upload or paid storage is involved. Retain only public manifests,
sanitized identities/results/resources, exact source snapshots and a finite
allowlist. Same-host offline roundtrips establish byte transport, not independent
provider retention, setup soundness, live payout or accepted-chain currentness.
