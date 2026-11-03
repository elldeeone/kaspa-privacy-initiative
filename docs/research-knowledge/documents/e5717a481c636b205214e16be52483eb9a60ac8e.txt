> Imported documentation snapshot. [Canonical status and ownership](../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# GPU benchmark independent static review

**Verdict: CHANGES REQUIRED before using this package's automated candidate decision.** One concrete timing defect prevents its cold-process comparison from establishing the property claimed. Static inspection found no mathematical mismatch in the packed eligibility predicate for validated fixture inputs, and the complete-prediction comparison is substantially stronger than score equality. This verdict is not authorization to execute; resource release and environment qualification remain separate gates.

Reviewed 2026-10-22 on Forge over SSH. Package: `/home/luke/projects/kpi-orchestration/2026-10-22/compute-plan/`. References below are relative to that directory. No package code was imported, executed, compiled or profiled; no dependencies were installed; no private evaluation data was accessed. Only text, public JSON data and hashes were inspected. The author's package was not edited.

## Required correction

### P2 — the cold-regression gate compares synthetic upper estimates, not single-invocation process times

`benchmark.py:233-252` defines `cold_process_upper_seconds = process_wall_seconds - sum(durations[1:])`, then requires the GPU estimate to be no larger than both CPU estimates. But `capsule/worker.py:52-75` times only `observer.observe()` and performs canonical serialization, prediction writes and bookkeeping **outside** that timer for every repetition. Subtracting the second and third observation durations leaves those repetitions' serialization/output/bookkeeping in the purported cold figure. It also retains the cleanup and final reporting behavior of a three-observation process, not a one-observation process.

The comment correctly calls the value an upper estimate; the comparison is the defect. An upper estimate for each backend is not an order-preserving estimate of their actual one-job process times. For illustration only, true cold times of 10 s CPU and 12 s GPU, with residual extra-repeat overheads of 4 s and 1 s, would compare as 14 s versus 13 s and incorrectly pass the GPU no-regression rule. Equal prediction bytes do not prove equal extra-repeat overhead or equal scheduling/cleanup effects. Conversely, the construction can reject a real improvement.

**Smallest repair:** in a separately reviewed revision, measure a genuinely single-observation fresh process for each backend/view, with identical output and receipt work, and use that process wall time for the cold comparison. Keep repeated observations for the distinct warm metric. Record process launch/setup, first observation, serialization and teardown clearly. Recalculate the bounded worker roster if adding workers; preserve the existing resource limits or explicitly review a revised budget. Do not replace this with a more elaborate subtraction presented as exact cold timing. Re-pin the revision; retain this original package.

## Other justified limits on interpreting the screen

- **The 20% rule is warm-only.** `benchmark.py:244-258` can nominate a candidate with 20% warm improvement and *zero* cold improvement. That implements the text at `BENCHMARK.md:17`, but it does not demonstrate a 20% improvement in the current fresh-process-per-view pipeline (`BENCHMARK.md:17`; `REPORT.md:23,61`). Label a pass as warm-process development potential only, or, if the actual decision is accelerating that fresh-process pipeline, require a predeclared meaningful improvement in its directly measured end-to-end metric. Do not call the existing criterion general end-to-end adoption evidence.
- **Two warm observations in one process do not establish a stable 20% population speedup.** `capsule/worker.py:26,51-64` and `benchmark.py:228-235` use one fixed-order process per backend/view and two warm observations; their median is just the average of those two samples. No spread or repeated-process evidence is collected. This is acceptable as a clearly labeled bounded development screen, as the spec already states, but timing jitter/order/allocator state can move a close result across 0.8. A pass is a reason for subsequent validation, not evidence about p95, all ledgers, or a 12-worker/GPU production schedule.
- **The profile gate is a scoped stop rule.** `benchmark.py:212-227` measures cProfile cumulative `eligible` time and calls in both historical views. It selects this kernel when that instrumented workload passes its gate; it does not establish an uninstrumented speedup ceiling or GPU infeasibility if the gate fails. The reference loop performs repeated Python method/set work, and profiling overhead can affect the share. The later unprofiled whole-observer comparison is therefore necessary. No replacement hotspot should be selected after a failed frozen gate.

These limits do not require speculative architecture work or extra held-out sampling. The cold measurement correction is the concrete blocker for this package's current decision logic.

## Equivalence and fairness checks that passed static inspection

| Area | Source-grounded conclusion |
| --- | --- |
| Predicate truth conditions | Reference `capsule/working_balance_observer.py:353-363` rejects an old/early support, an unavailable anchor position, co-input conflicts, an incompatible disclosed spend, or inconsistent known value/owner. The NumPy mask (`capsule/adapter.py:83-107`) and CUDA predicate (`:9-26`) encode those same conditions. The nonempty input conflict remains exact Python membership at `:134-142`; for the original integer tuples it is equivalent to the reference's set membership. |
| Integer/sign handling | Packed values are range/type checked before int64 conversion (`capsule/adapter.py:29-32,57-67`); CUDA scalar arguments are also checked (`:113-117`). The kernel uses signed 64-bit comparisons, bounded index arithmetic, and no amount arithmetic or floating-point arithmetic. `-1` represents absent owner/co-input/event slots; source validation and construction keep real positions, owners and event indices nonnegative (`capsule/working_balance_observer.py:83-108,123-149,283-350`). Disclosed zero-valued notes remain known notes, not unknowns. Out-of-range candidates stop instead of truncating. |
| Frozen fixture ranges | Data-only inspection found maximum payout 143,981,400,000 sompi, maximum public integer 2,660,000,000,000, and maximum anchor 258. Three maximum payouts plus three 40,000,000-sompi fees fit below 2^39. Candidate arithmetic remains Python integer arithmetic; bounds are checked when packed. This verifies a broad safe envelope for the selected fixture, not arbitrary future histories. |
| Candidate construction and boundaries | `PackedEngine.__init__` calls the unchanged superclass before packing (`capsule/adapter.py:50-67`). Residual/sum generation, merged amount intervals, half-open bisect boundaries, partial-tail classification and integer sums stay in `capsule/working_balance_observer.py:283-350`. No GPU-generated candidates or changed value windows were found. |
| Ordering, tie rules, dedup and support cap | The adapter adds identity-to-mask lookups without replacing the original candidate iteration, dictionaries or sets. Fixed ranks, per-leg first-eight selection, overall first-eight selection, support identities and final rank ties remain unchanged (`capsule/working_balance_observer.py:404-410,452-544`). Unknown records/non-output positions fall back to the original predicate (`capsule/adapter.py:134-138`). |
| Public versus pooled | The reference creates the pooled engine and its public-only copy (`capsule/working_balance_observer.py:554-575`); replacing the global Engine class wraps both. The public fixture has no participant records; the pooled fixture has members 0–7, 38 authored records and 42 receipts. Workers receive one fixture directory, and expected predictions are checked by the controller rather than mounted into workers (`benchmark.py:93-113,172-177`). |
| Complete prediction equality | Each saved prediction is canonicalized and compared with the **entire** published expected object (`benchmark.py:172-177`), preserving list ordering and numeric types. It covers metadata/input digests, target rows, every guess and rank, not just successful guesses or checksums. Both expected objects contain 64 target rows through event 172; each row has 13 C+D or 26 pooled variants. Fresh reference outputs pass the same check, so successful array/GPU comparisons are transitively equal to fresh reference outputs too. Identical complete predictions imply identical deterministic scores for fixed truth; no truth/scoring is needed here. |
| Baselines and GPU timing | Unchanged Python reference and a packed NumPy CPU control are both required (`benchmark.py:228-255`). The GPU does not receive credit for beating only an unoptimized baseline. Context/JIT setup is separately recorded; the outer process time includes it (`capsule/adapter.py:39-49`; `capsule/worker.py:36-41`). Kernel events are synchronized and mask transfer is included in each observation (`capsule/adapter.py:111-128`). Separate workers/output caches keep control compilation from erasing measured measurement-worker compilation (`benchmark.py:102-103,228-232`). |
| Failure semantics | Worker errors, limits and full-prediction mismatches stop the comparison (`benchmark.py:130-179,260-264`). The summary records `BLOCKED_OR_FAILED`; the profile gate and insufficient speedup have separate no-go statuses. Failures do not become privacy evidence. The existing handmade controls include known amount, co-input/tail, pooled-copy, prefix, malformed-type and hidden-field checks, but they are not a proof of generic backend equivalence. |

Passing the future full-output comparison would establish parity on these two historical views and exercised controls only. It would not establish equivalence on all valid future integer inputs, all histories, fresh sampling, or a full newly frozen experiment. That limitation is a development boundary, not a discovered predicate mismatch.

## Provenance

All 18 listed package file digests were read and matched their manifest entries. The capsule observer's hash also matches the previously reviewed current source. The historical archive was not re-extracted or independently re-attested in this review. Author-provided expected public outputs were inspected as public test fixtures only.

Review snapshot SHA-256:

Captured UTC: 2026-10-22T07:48:40.981092+00:00

```text
a3281bbc72d32627c16fba035fb01937f7963555da6ff3e39abe513110735270  manifest.json
1c8a2c6e4407eaf470022c4463c7af517039070e90138ba2c3a1aa79ecf86671  benchmark.py
207595c04c894dd1deb094b1161d61ee655960f95b869818c2ed339d67bc7d3c  BENCHMARK.md
fd893ebe87b43aecad0ee3c02be7e752528074da79585a7770dd2d89d7e85d12  capsule/adapter.py
4ea5aedb8ab2d1c35b180383b2711a28c20d164e1cac60ff09e3181993047fbd  capsule/worker.py
b492d5a2e63836751f51f5151c002c3ec6492c224b518846c45eca23f3ea7495  capsule/working_balance_observer.py
0f2ac35622e23dfafa960e8877b743118500c3530015eaa9b59b49c208d38147  capsule/working_balance_observer_tests.py
1028ad2729aaea3e0af1da5ec04b8f54062c248f169bd85b991996bdede0f9c8  expected/public.json
cc5ad976f320fefd783e8af9638722fdd8172ce00bf7dc4c756a5a6f68ab31a4  expected/pooled.json
```
