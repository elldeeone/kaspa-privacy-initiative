> Imported documentation snapshot. [Canonical status and ownership](../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# Bounded Mac reference check — 22 October 2026

**C+D correctness: PASS. Pooled correctness and full profiling gate: INCOMPLETE, resource stop. Local compute slot released.**

The unchanged stdlib observer reproduced the entire existing C+D public development prediction: all 64 target rows, all 13 variants, ordering, ranks and metadata. The pooled attempt was stopped by the preset system-swap guard before it produced a complete prediction; it supplies no 26-variant parity result. Neither attempt qualifies CUDA or establishes Forge performance.

## Scope and provenance

Only the immutable, allowlisted public development capsule was read. Its 18 manifest file hashes were checked before and after the run; all remained unchanged. The original `working_balance_observer.py` was imported directly. The benchmark adapter, its known-invalid cold proxy, NumPy, CUDA and setup scripts were not invoked. No held-out data or active Forge experiment was read or changed.

- Snapshot: `work/mac-validation/snapshots/compute-v1-a3281bbc72d3`.
- Manifest SHA256: `a3281bbc72d32627c16fba035fb01937f7963555da6ff3e39abe513110735270`.
- Observer SHA256: `b492d5a2e63836751f51f5151c002c3ec6492c224b518846c45eca23f3ea7495`.
- Public archive identity supplied and verified by staging: `05b3d80d080aa51ec48fed387caecd0197ca64efe141eb18dfa33af5830a5950`.
- Wrapper SHA256: `0cab8f72344e498aee36dab5f04336494585e1f62106b4206d16ad14a62d8efc`.
- Runtime: arm64 Python 3.14.6 at `/opt/homebrew/Cellar/python@3.14/3.14.6/bin/python3.14`, on the M3 Mac.

One single-thread worker ran at a time, under `nice -n 10` and Python `-I -B -S`. Each case allowed at most 300 seconds and 1 GiB sampled worker RSS. RSS sampling was approximately every 0.25 seconds and system-pressure/swap sampling approximately every 2 seconds. These were sampled stops, not hard memory limits. The guard also stopped on pressure-level increase or at least 64 MiB swap growth over the session baseline. This extra conservative swap rule was fixed before starting.

## Actual results

| Measure | C+D public | Pooled |
|---|---:|---:|
| Whole-process elapsed | 61.8566 s | 57.8797 s to stop/exit |
| Profiled observe elapsed | 61.7242 s | 57.7615 s, partial |
| Peak sampled worker RSS | 162.3 MiB | 223.6 MiB |
| Exit code | 0 | 143, SIGTERM handled |
| Complete prediction parity | All 64 targets × 13 variants | Not available |
| `eligible` calls | 63,178,835 | 66,314,696, partial |
| `eligible` cumulative time | 21.1608 s | 23.6687 s, partial |
| `eligible` / profile total | 34.2934% | 40.9772%, partial |

The C+D canonical prediction SHA256 is `e9820f48ff7ae47ec9f74db1ba6dfaf8707ea426e4e2abd2362ad4e4d2a39b86`, identical to the canonical expected output. Expected outputs were compared in the controller after worker completion, not provided to the observer.

The session ran from 07:56:52 to 07:58:52 UTC. Pressure level remained 2. System swap was 13,255.56 MiB at session start, 13,024.25 MiB after C+D, and 13,525.94 MiB after the pooled stop. The final increase exceeded the fixed session-baseline allowance. System swap includes other applications: this observation does not establish that the observer caused the increase.

Both worker PIDs, 79295 and 79668, were waited for and subsequently confirmed absent with `ps`. No further compute was started.

## Useful hotspot evidence and limits

The completed C+D profile identifies material repeated eligibility work: 18.8852 seconds self time and 21.1608 seconds cumulative across over 63 million calls. Other substantial work remains in `offer` (14.6929 seconds self; 17.6988 cumulative), `books` (7.9911 self) and `split` (6.0518 self). Cumulative times overlap and must not be added. The partial pooled profile shows repeated eligibility work too, but it is censored and cannot substitute for a complete second-view profile.

The published gate requires at least 25% eligibility time and 100,000 calls in **both** views. C+D clears those numerical conditions on this profiled Mac case. The overall gate is unresolved because pooled is incomplete and this is not the specified Forge measurement environment. It does not warrant recording either `CANDIDATE_FOR_NEW_DEVELOPMENT_FREEZE` or a completed two-view `NO_GO_HOTSPOT_GATE`.

`cProfile` instrumentation is included in these times and affects call-heavy functions. There was no unprofiled control or repeated timing study. Whole-process elapsed directly measures one launched, profiled observation including imports, reads, serialization, profile writes and exit; it is not the v1 subtraction proxy, but it is also not an unprofiled cold-performance estimate. No speedup, CUDA viability or 20% adoption conclusion follows.

## Next decision

Preserve C+D parity and hotspot evidence; defer a complete pooled check until a newly approved resource slot is available with acceptable pressure, or until Forge's active work has released capacity. Do not relax the stop rule or rerun immediately. Before any accelerator adoption screen, retain the separate requirement for a reviewed benchmark revision with genuine single-observation cold timing and complete two-view prediction parity. The current frozen privacy evaluation remains unchanged.

Evidence is beside this report: `summary.json`, `session-start.json`, `reference_profile.py`, public `receipt.json`, `worker-complete.json`, `prediction.json`, `profile.json`/`.pstats`, and pooled `receipt.json`, `partial-profile.json`/`.pstats`. Each case also retains launch receipts, resource samples and logs. The wrapper's console field `completed_cases: 2` counts attempted cases; `all_views_complete: false` and the per-case receipts are authoritative.
