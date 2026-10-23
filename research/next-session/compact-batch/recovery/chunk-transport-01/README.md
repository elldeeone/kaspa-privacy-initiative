# Fixed-chunk public parameter transport

The optional `chunk_public.py` CLI now packs and restores opaque public files in
fixed **1 GiB raw chunks**. Existing capsule schemas and trusted selection stay
unchanged; the shared iterator guard correction is documented below.
An independently selected complete length and SHA256 are required for both
commands. A mirror's index or chunk hashes cannot authorize different bytes.

```sh
python3 -B poc/recovery-portability/chunk_public.py pack \
  --source /public/parameters.pk --expected-bytes "$SELECTED_LENGTH" \
  --expected-sha256 "$SELECTED_SHA256" --output-dir /new/chunks

python3 -B poc/recovery-portability/chunk_public.py restore \
  --manifest /download/manifest.json --expected-bytes "$SELECTED_LENGTH" \
  --expected-sha256 "$SELECTED_SHA256" --mirror /download/chunks \
  --mirror /fallback/chunks --output /new/parameters.pk
```

The destination must be new. Restore verifies each ordered chunk and the whole
file before atomically publishing a read-only output. Candidate mirrors are
local directories; this adapter performs no network request or upload. The
existing parameter loader must still authenticate its entire owned bytes before
private inputs. See [plan/API](PLAN-AND-API.md) and [primary sources](SOURCES.md).

**17 distinct chunk controls passed on corrected source.** The original 15 ran in
`controls-01`; the peer-requested missing-final-chunk control alone ran in
`controls-02`. The generator exclusion regression then caught and verified a real
API fix. `fixed-controls-01` retains all 17 passing on corrected chunk source.
They cover
corruption, truncation/trailing bytes, reordered and self-consistently substituted
data, wrong external anchor, duplicate fields/unsafe names, fallback, legitimate
repeated chunk hashes, symlinks, atomic no-clobber, source loss and calibrated
kernel IN_OPEN checks showing no forbidden source/index/chunk content-open.
Tiny multi-chunk fixtures replace the imported chunk-size constant only inside
the isolated tests; the production CLI has no chunk-size override.

Review found the same consumed-iterator pattern in the capsule, local packer and
HTTPS outer APIs. Those entry points now preserve one-shot exclusions before any
public read. **46 current controls passed** in `current-api-controls-01`: 12
capsule, 6 local packer, 8 loopback HTTP, 17 chunk and 3 independently authored
outer iterator controls. These overlap the earlier suites and are not added to
them as extra distinct tests. Calibrated expected failures, exact old snapshots
and the narrow old actual-run scope are retained in
[ITERATOR-GUARD-FIX.md](ITERATOR-GUARD-FIX.md). The
[source supersession map](SOURCE-SUPERSESSION.json) binds old archives and current
files without rewriting historical manifests or claiming their old production
path hashes describe current code.

Both **actual public parameter files passed** the fixed production rule:

| Public file | Exact bytes | Chunks | Pack | Restore | Separate output readback |
| --- | ---: | ---: | ---: | ---: | ---: |
| compact2 | 1,307,894,256 | 2 | 2.296s | 1.795s | 0.636s |
| wide32 | 2,892,421,872 | 3 | 4.473s | 11.561s | 2.284s |

Each restore ran in a fresh network-off namespace with the original source file,
its cache directory and original repository absent. Only selected transport
files, read-only public chunks, system files and a fresh output were mounted.
After restore, a separate full-file readback matched the same externally selected
length/SHA. Exact selected anchors, raw public chunk indexes, safe outcomes and
executed source snapshots are retained in [actual-roundtrip-03](actual-roundtrip-03).
This final run used corrected chunk source `c713a487` and capsule source
`ba6fba07`. Earlier runs `actual-roundtrip-01` and `actual-roundtrip-02` remain
historical byte-transport evidence for their pinned old source versions, not
additional independent retention or proof successes.

The final combined actual job took **23.106s**, with 13.268s systemd aggregate CPU.
Observed caps were 4 CPU / 4 GiB / swap 0. Cgroup memory peaked at 4G, including
large-file cache; swap stayed 0B. The manager reported collected/inactive/dead/PID0;
direct kernel process observations remain null. No backup, parameter decoding,
proof, native validation, main private history or external upload was involved.

This proves local chunk reconstruction and byte identity for these files. It
does not establish independent hosting, long-term retention, setup soundness,
accepted-chain state, live payout or production readiness. The wide PK remains
unnecessary for a compact owner's exit. The frozen distribution plan still
describes the whole-object staging layer; this new adapter prepares a verified
whole file for that unchanged layer.
