> Imported documentation snapshot. [Canonical status and ownership](../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# GPU package v2: independent execution-safety delta review

**Recommendation: retain BLOCKED.** V2 substantially addresses the four v1 execution-review findings, but one new PID-identity defect in its cleanup tracker must be corrected before any bounded qualification. Static review does not establish cgroup delegation, package installation, namespace behavior, CUDA compatibility or measured performance. The Mac pressure hold remains in effect.

## Immutable review identity and method

- Directory: `/home/luke/projects/kpi-orchestration/2026-10-22/compute-plan/revisions/v2`.
- Raw manifest SHA-256: `7fdac38ef8ef02fa339c86b72edd5bb73abd973e71546922e27fd440eac63052`.
- STATUS SHA-256: `02086d8fab1ea4ef2940fa05039a7edc0a023b87b514473617d72d902a592f7c`.
- Independently verified all 24 manifest files, totaling 986,709 bytes; both pinned prior-review hashes; no unexpected files or source/ancestor symlinks. All 18 original v1 files and its raw manifest remain unchanged. All 12 inherited archive-member hashes match v1; the upstream public archive was independently rehashed to `05b3d80d080aa51ec48fed387caecd0197ca64efe141eb18dfa33af5830a5950`.
- Reviewed authored source as text only: no source import, parse/compile, setup, cgroup write, test, profile, GPU operation or installation. Hash/JSON/file inspection used only independent stdlib commands. Statistical/prediction equivalence remains the other reviewer's ownership.

## Required correction: tracked PIDs can lose their original identity [P2]

`guards.py:124-141` unconditionally seeds `roots` with `self.process.pid`, then assigns `self.seen[p] = all_rows[p]["start"]` for every found PID. After `process.poll()` reaps a short-lived wrapper, that PID may be reused before a later refresh/cleanup. The new process is then adopted as the old root and its new start time overwrites the saved identity. `send()` at lines 145-154 faithfully opens a pidfd for that replacement and compares against the newly accepted start time, so its identity check does not prevent signaling an unrelated process.

The same unconditional assignment permits a discovered descendant's previously recorded identity to be replaced if that numeric PID is rediscovered through another path. This contradicts the advertised identity-safe cleanup and can matter during the repeated helper/worker cleanup calls. PID reuse is a race condition, not an observed event in this review; the faulty state transition is directly visible in the source.

Pin the root's initial start identity and retain it. Only seed a live root when its current start identity matches; never overwrite an already tracked PID with a different start identity. Newly adopted descendants need the same identity discipline. Keep v2 frozen and make the correction in a separate revision. A short-lived-process/reaping qualification must later confirm that cleanup signals only the intended identities. The author and parent received this finding before this report.

## V1 findings: delta assessment

| Earlier issue | V2 source result | Remaining execution evidence |
|---|---|---|
| Late allocation bound and Python packing duplication | `capsule/adapter.py:53-72` bounds count before the index/table, allocates one contiguous table, and streams existing rows. It removes the concatenated `_rows` and list-of-lists copy. The unchanged superclass still creates candidates first. | The 4 GiB worker cgroup is required; actual candidate/index/two-engine/NumPy overhead is not measured. |
| Unbounded waits and weak cleanup evidence | `guards.py:159-230` uses finite polling, TERM/KILL, subreaper adoption and pidfds; `benchmark.py:201-245` retains pending/final resource receipts, uses cgroup.kill and checks emptiness. There is no unbounded wait/communicate path. | Fix the identity defect above, then exercise the CPU-only forked-child timeout probe and inspect receipts/cgroup emptiness. Kernel tasks that survive signals must remain blocked. |
| Compute-process telemetry mislabeled as total device memory | `benchmark.py:67-91,151-157,187-220` now queries whole-device `memory.used`, verifies device UUID, records baseline/peak/post-cleanup state, and separately checks compute owners. | Numeric telemetry, 8192 MiB device-total expectation and namespace/driver access remain unqualified. The 3 GiB stop is explicitly sampled, not a hard VRAM quota; the 2 GiB CuPy pool cap is distinct. |
| Open paths/importable source closure | `benchmark.py:20-59,93-138` and `setup.py:11-50` reject escaping manifest paths, ancestor/leaf symlinks, extra source/input files and unexpected root entries, then copy only manifested code and one view into read-only per-worker snapshots. Worker `-I -S -B` suppresses startup hooks. | Filesystem permissions are not an independent-user security boundary. Concurrent privileged mutation remains outside the stated scope. No current source-path discrepancy was found. |

The exact public-fixture arithmetic is still useful context: per-engine packed arrays are loosely bounded by 148.54 MiB for C+D and 320.54 MiB for pooled, with both engines retained during pooled observation. Those figures do not bound total RSS; v2 correctly makes the cgroup—not raw array size—the whole-worker memory boundary.

## Resource, scheduling and runtime assessment

`launch.py:6-20` checks the dedicated group's limits and emptiness and attaches itself before exec of Bubblewrap. This covers observer imports, unchanged candidate construction, packing and descendants. `guards.py:235-246` requires attach/kill permission and exact memory.max=4 GiB, memory.swap.max=0, memory.oom.group=1, pids.max=64 and two-CPU quota. `benchmark.py:221-245` rejects new memory max/OOM events and any remaining membership. `PROVISION-CGROUP.sh:4-20` requires explicit parent flags and already enabled delegated controllers, creates only the named fresh child, and does not enable parent controllers or alter services. Whether that path is writable and these controllers are available has not been established. Setup/helper/controller processes are outside this worker cgroup; their deadlines/affinity are bounded, but the 4 GiB memory claim should continue to be understood as worker-scoped.

The common flock lease and process guard (`guards.py:47-80`) prevent cooperating duplicate controllers and poll for `price_leakage_trial.py` during helpers/workers. They do not replace the parent's exclusive scheduling decision or govern a legacy v1 launcher; the documents now say so. Source verification and explicit capacity gates precede adapter import/JIT. Worker namespaces expose only the declared runtime, closed code, one public fixture and fresh outputs; expected outputs remain controller-side.

Setup uses a clean child configuration, explicit PyPI index, `uv --no-config`, wheel-only hash resolution/sync and private caches; it preserves failed attempts (`setup.py:66-114`). The runtime attestation checks exact installed names/versions against the lock, RECORD integrity, the full venv, stdlib, named tools and driver identities (`runtime_identity.py:79-136`). The controller recomputes and compares that attestation before workers (`benchmark.py:298-304`). This is a meaningful improvement over recording only a resolution-lock hash; it is not yet an installed-runtime result or an attestation of every `/usr` shared library.

Cold execution is now a distinct fresh one-observation worker; warm execution is separately launched with one warmup and two measured calls. This removes v1's synthetic subtraction. Polling/telemetry can still overestimate observed process completion, and the other reviewer owns the consequences for comparisons. No timing or gain is claimed by this review.

## Prerequisites for a minimal qualification

1. Freeze and independently review the PID-identity correction. Preserve the v1/v2 records.
2. Parent confirms frozen-run terminal completion and exclusive fresh Forge capacity; no Mac retry follows from this review.
3. Parent explicitly provisions and verifies the empty delegated cgroup, including limits, membership and kill permission. An unavailable controller is a blocked prerequisite, not permission to weaken the bound.
4. Resolve/install only the private runtime under its finite setup envelope, then inspect and independently pin its actual runtime-lock bytes. A source-based compatibility assessment is not sufficient.
5. Run only the documented CPU namespace/control/forked-child cleanup qualification first, under its outer timeout. Require the two probe receipts, successful descendant cleanup, empty cgroup and no memory-boundary event. Preserve incomplete/failure evidence and do not dispatch a next worker after failed cleanup.

After these prerequisites, the fixed full screen still requires both-view reference parity/hotspot evidence before GPU selection. The current STATUS being BLOCKED is accurate; its completed-source corrections do not imply execution readiness.
