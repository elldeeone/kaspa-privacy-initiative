> Imported documentation snapshot. [Canonical status and ownership](../../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# Cross-platform validation guide

**Current hold, 2026-10-22:** no new Mac CPU-adapter run is authorized. The parent stopped the pooled reference case when system swap exceeded its preset limit. The operating instructions below apply only after a fresh scheduling/capacity decision; see [CPU-ADAPTER-PREFLIGHT.md](CPU-ADAPTER-PREFLIGHT.md).

Use the immutable v1 snapshot identified in [REPORT.md](REPORT.md) and [../../SNAPSHOT-RECEIPT.json](source-snapshot-receipt.json). The parent is the scheduler; the prior accepted budget assigned one compute worker only to the statistical review lane. Keep its runner and all outputs in `../statistical-review-reference-001`, outside the snapshot. Use a fresh case directory for each attempt, including failures.

## Mac evidence

1. Before each case, verify the raw manifest hash and all manifested input hashes. Record the snapshot ID, source hash, exact interpreter/version, arm64/macOS platform, case/view, command, limits and timestamps. Do not edit, unlock or add files beneath the snapshot.
2. Use the existing interpreter `/opt/homebrew/Cellar/python@3.14/3.14.6/bin/python3.14` with `-I -B -S` for a separate stdlib reference runner. The runner can explicitly insert the verified capsule path for importing the frozen observer. Do not invoke `SETUP.sh`, `benchmark.py` or the original Linux worker on the Mac: they target Linux paths/namespaces and Forge execution. Do not install NumPy, CuPy, Metal/MPS or replacement runtimes in this lane. If the existing runtime cannot support the check, report the incompatibility to the parent.
3. Feed only one allowlisted public fixture view into the observer. Expected outputs are comparator/controller evidence and must not become observer input. Keep fixture, expected result, produced prediction, and comparison result separately named. Full canonical prediction agreement can supply Mac reference regression evidence; the statistical reviewer owns the exact comparator and numerical interpretation.
4. A stdlib function profile can identify likely algorithmic work and support the next implementation decision. Record profiling overhead and avoid extrapolating a Mac reference timing into an RTX 3070 speedup or Forge wall time. Record cold startup and repeated work consistently; do not silently exclude failed or timed-out cases.

## Budget and stop rules

Run at nice 10, one worker/one thread, with a parent/controller sampling the worker's RSS, a 1 GiB RSS stop, and a 300-second per-case elapsed timeout. Nice does not pin a Mac process to one CPU; the single-thread design controls the intended concurrency. Sampled RSS can miss allocation spikes and does not constitute a hard memory quota.

Stop the owned worker if the RSS/time threshold is crossed, pressure becomes materially worse, the Mac becomes sluggish, the user steers the task, or the parent revokes capacity. Preserve the failure/timeout/stop receipt and partial output. Terminate only the lane's own worker/process group, use finite TERM then KILL waits, and verify it is gone before starting another case. Report a surviving process immediately; do not launch another case. Do not increase limits or start a second compute lane to recover a failure. Root alone can change the aggregate schedule.

The capacity sample is a point in time, not a reservation. The Mac had 16 GiB RAM with roughly 12.5 GiB swap already in use at the final staging check. Recheck pressure before computation and after a case. Other readers must avoid concurrent large allocations or dependency installs.

## What still requires Forge

Mac regression/profile results do not validate Linux Bubblewrap namespaces/mounts/device exposure, driver/CUDA/CuPy compatibility, RTX 3070 memory behavior, child-process cleanup, or Forge performance under its real workload. Those require a separately authorized, bounded Forge execution after the package's static review prerequisites and an exclusive capacity lease are satisfied. Preserve the reviewed v1 snapshot and use a new manifest/snapshot for any repaired package. Do not connect this Mac lane to the ongoing frozen private price evaluation.

A correctness match or faster observer is not evidence that the privacy hypothesis succeeded. Protocol, privacy and price-baseline conclusions remain tied to their own frozen experiment artifacts and review gates.
