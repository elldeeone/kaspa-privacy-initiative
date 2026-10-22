> Imported documentation snapshot. [Canonical status and ownership](../../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# Mac public-capsule staging receipt

Staging is complete. This is a frozen public v1 source snapshot for independent Mac correctness/profile work, not an execution qualification for the Forge GPU package. No observer, package script, dependency installer, JIT, GPU operation, or test was run by this lane.

**Operational update, 2026-10-22:** the parent placed further Mac CPU-adapter execution on hold after the pooled reference case crossed its preset system-swap limit. The earlier one-worker capacity acceptance below is historical, not current authorization to launch a new case. See [CPU-ADAPTER-PREFLIGHT.md](CPU-ADAPTER-PREFLIGHT.md).

## Exact snapshot and provenance

- Snapshot: `mac-artifact:work/mac-validation/snapshots/compute-v1-a3281bbc72d3`
- Source: SSH alias `forge`, exact directory `/home/luke/projects/kpi-orchestration/2026-10-22/compute-plan`.
- Raw `manifest.json` SHA-256: `a3281bbc72d32627c16fba035fb01937f7963555da6ff3e39abe513110735270`.
- All 18 manifested files match their recorded SHA-256 and size. They total 939,845 bytes; the manifest adds 3,360 bytes, for 943,205 bytes across 19 files. The manifest itself is identified by the raw-byte hash above, not a canonical JSON digest.
- Exact allowlist and individual hashes: [../../SNAPSHOT-RECEIPT.json](source-snapshot-receipt.json). SCP copied the explicit paths, not a recursive checkout or runtime directory. Only the manifest, four package files, four capsule source files, eight public fixture files and two public expected-output files were copied.
- Upstream public archive: [/home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool/evidence/2026-10-21-working-balance/public-evidence.tar.gz](../../../../../poc/shared-pool/evidence/2026-10-21-working-balance/public-evidence.tar.gz); SHA-256 `05b3d80d080aa51ec48fed387caecd0197ca64efe141eb18dfa33af5830a5950`. Its hash was rechecked on Forge during staging. The preceding static review independently compared all 12 archive-mapped source/fixture/expected-output members byte-for-byte. Identical archive and manifest hashes bind this copy to that verification. The 24,880,496-byte archive itself was not copied to the Mac.
- Source contents were reverified after staging: no symlinks, unexpected files, hash changes, or size changes. Every file is mode `0444`, every source directory `0555`, and every source node has macOS `UF_IMMUTABLE`. This is a local accidental-mutation guard, not a separate-user security boundary. Do not clear the flags to make changes; prepare a new versioned snapshot.
- No active private evaluation, seed/secret file, live checkout, `.venv`, runtime/cache directory, or whole archive was transferred. No configured Python or global tool was changed. No applicable ancestor [AGENTS.md](../../../../../AGENTS.md) was found in the local staging path.

## Runtime, capacity and ownership

Existing runtime: `/opt/homebrew/Cellar/python@3.14/3.14.6/bin/python3.14`, Python 3.14.6, arm64. Mac: Apple M3 / Mac15,12, 8 logical CPUs, 16 GiB RAM. The initial sample had load 5.99/6.20/5.73, about 6.5 GiB compressed memory, and 13,021 MiB swap in use. A later lightweight check recorded load 3.98/5.16/5.40 and 12,802 MiB swap in use. `memory_pressure -Q` reported 31% system-wide free at the latter check; that is not 31% unused physical RAM. Timestamped raw readings and final immutable verification are in `CAPACITY-AND-VERIFICATION.json`.

The parent accepted one additional compute worker, owned only by `/root/statistical_review`: nice 10, one thread, stop at sampled RSS above 1 GiB, and at most 300 seconds per case. The parent retains aggregate scheduling. Other lanes may perform source/design/light toy checks, with no parallel array work or installs. Existing memory pressure makes a larger worker count unjustified by CPU count alone. These are sampled operating limits, not hard OS memory isolation.

Separate writable worker directories (mode `0700`) exist beneath `../../workers/`: `statistical-review-reference-001`, `parent-static-review-001`, and this `staging-provenance` lane. The statistical reviewer received the exact paths, hash, runtime and limits immediately after staging. This lane did not duplicate its reference benchmark.

## Status and next evidence

**READY:** immutable public input staging and provenance for the authorized Mac reference lane. **NOT QUALIFIED:** Mac GPU/array performance, Linux Bubblewrap isolation, Forge CUDA execution, or privacy conclusions. The separate Forge static execution review remains **BLOCKED** pending its four prerequisites: bound adapter allocation before construction, finite timeout cleanup, align VRAM accounting with its advertised budget, and close path/import manifest integrity gaps.

Follow [VALIDATION-GUIDE.md](VALIDATION-GUIDE.md) for the Mac/Forge evidence boundary and stop rules. Profile results belong to the statistical review lane; they are not included or implied by this staging report.
