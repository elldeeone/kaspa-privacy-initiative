# GPU v4 runtime result — 2026-10-22

**Do not adopt or rerun this GPU candidate merely to occupy the device.** The completed C+D comparison fails the fixed speed criterion. The CUDA runtime and kernel work, but this implementation does not provide material end-to-end benefit over either required CPU control. Captured public evidence supports leaving the GPU idle for this observer workload. No further GPU experiment is recommended from this screen alone.

The overall run is **BLOCKED_OR_FAILED**: the first pooled GPU worker stopped at an ownership guard before producing a prediction. This is separate from the successful source/runtime/namespace/kernel/C+D-parity checks, and from the already-failed C+D speed criterion. Pooled GPU correctness and timing remain incomplete.

## Scope and immutable receipts

Attempt root: `/home/luke/projects/kpi-orchestration/2026-10-22/compute-plan/executions/20261022T092500Z`. Full run: `package/runs/20261022T093037.341789Z`.

- Source manifest: `2515abffcb08c0ff2e942e5551c21b017b74c7a862e1e0e693ed35db2daa8e61`.
- Runtime lock: `438bae3f3ff1c490b34b919290f13bebcaa0a11cad606ca93f7ad0c9c4fbf194`.
- Receipt manifest: `16f97707a1c1de272b80581a02a547e9106803fe5ab98df7376703e53bdac955`.
- Derived receipt index: `93c3bdbbd54aaadcaa9ed5879d41aec53ec10d21b1347984b7e6c1c170e72969`.
- Terminal cleanup: `31935df9e8cb83e935b137d4fbfbb0dc4a65dc81d266a912f3fee3a7ec5ca94a`.

The sole fixed historical PUBLIC fixture came from `2026-10-21-working-balance/public-evidence.tar.gz`, archive SHA `05b3d80d080aa51ec48fed387caecd0197ca64efe141eb18dfa33af5830a5950`. Each view had 64 targets; C+D retained 13 variants and pooled retained 26. No current private evaluation, seeds/truth, attack change or held-out retuning was used. The full source/containment/unit evidence is in [RUNTIME-QUALIFICATION.md](RUNTIME-QUALIFICATION.md).

## Profile and exactness gates

The unchanged reference ran before any GPU import/kernel selection.

| View | Profile total (s) | Eligible calls | Eligible cumulative (s) | Share |
| --- | ---: | ---: | ---: | ---: |
| C+D | 70.508775 | 63,178,835 | 25.689928 | 36.4351% |
| Pooled | 138.578032 | 138,515,792 | 53.773506 | 38.8038% |

Both exceeded the frozen 25% / 100,000-call gate and matched their complete prediction oracle. These instrumented times establish hotspot evidence, not unprofiled speed estimates.

Reference and NumPy cold/warm paths passed full canonical parity for both views; GPU cold plus warm-up and two warm observations passed it for C+D. All 22 completed prediction files were independently rechecked as complete canonical matches. Canonical oracle SHA-256 values are `e9820f48ff7ae47ec9f74db1ba6dfaf8707ea426e4e2abd2362ad4e4d2a39b86` (C+D) and `7d58a4e59bcfefdbca7b8e23f2c7aed842bbe4dba5474b9bfcb88130d91cd62b` (pooled). The GPU pooled worker emitted no prediction; it does not count toward parity coverage.

## End-to-end measurements

Cold is one observation in a genuinely fresh process, including startup/setup and output serialization until observed process exit. Cold observer time is separately shown. Warm median is the median of two whole-observer observations after one excluded warm-up, with setup and serialization separately recorded. Fixed order was reference, NumPy, then GPU. No sample counts, ordering or numerical gates changed.

| Backend / view | Cold fresh process (s) | Cold observer (s) | Warm observer median (s) |
| --- | ---: | ---: | ---: |
| Reference / C+D | 38.434073 | 38.223442 | 38.885625 |
| NumPy / C+D | 41.226754 | 40.918053 | 43.880589 |
| GPU / C+D | 43.599220 | 42.738405 | 43.154559 |
| Reference / pooled | 73.633386 | 73.490850 | 80.591631 |
| NumPy / pooled | 83.975812 | 83.654087 | 85.889992 |
| GPU / pooled | incomplete | incomplete | not run |

The rule required GPU time <= 0.8 times BOTH CPU controls for cold AND warm on BOTH views. For C+D the GPU/reference ratios were 1.134390 cold and 1.109782 warm; GPU/NumPy ratios were 1.057547 cold and 0.983454 warm. GPU cold was 13.44% slower than reference and 5.75% slower than NumPy. GPU warm was 10.98% slower than reference and only 1.65% faster than NumPy. This necessary condition already fails; resolving the later ownership stop cannot turn these captured C+D values into a pass.

The C+D GPU cold observation recorded:

| Component | Measured duration |
| --- | ---: |
| Backend import/setup | 0.558135 s |
| Candidate packing, 442,751 records | 0.495222 s |
| Host-to-device transfer | 0.019640 s |
| Eligibility stage, including kernel and return copy | 0.018893 s |
| Kernel time (subset of eligibility stage) | 6.763872 ms |
| Device-to-host transfer (subset of eligibility stage) | 0.009405 s |

These rows overlap as labelled and must not be summed as independent stages. The NumPy C+D mask stage was 0.294369 s in a 40.918053-s observation; pooled masks took 1.179659 s in 83.654087 s. The GPU made the small mask calculation fast while the adapter retained per-candidate Python calls, lookups and selection in the observer. The measured mask stage is already under 1% of C+D and under 1.5% of pooled CPU observer time. The existing evidence does not justify more engineering or another same-workload run of this mask kernel. This statement does not rule out a differently designed algorithm; no such redesign or experiment was performed or proposed for execution here.

## Ownership stop: evidence and limits of inference

At 09:53:45 UTC, `cold-gpu-pooled/telemetry/owners-118/stdout` reported `1010025, 154`. The guard raised `unrelated GPU compute owner appeared`. The worker receipt records wrapper PID 1010024 / start tick 35558791 and descendant PID 1010025 / start tick 35558802. Cleanup finished in 1.259959 s; total failed worker job was 2.672259 s. Post-cleanup ownership was empty and device usage returned to 1 MiB. The terminal audit found both identities absent.

Source inspection shows the controller obtains a process-tree live set before two sequential device/owner queries. Those two queries took 0.416844 s and 0.309764 s here. The device query reported 1 MiB; the later ownership query reported the newly present 154-MiB owner. The same reported PID appears in the worker's later owned-descendant record. This supports a stale-snapshot explanation, but the exact pre-query live set was not serialized; it is an inference, not a definitive race diagnosis. The receipts do not demonstrate a foreign GPU job. No guard relaxation, source patch or retry followed.

## Resource/load interpretation and final disposition

This remains a DEVELOPMENT SCREEN, with one cold sample, two warm samples, fixed order, capped controller overhead and non-atomic/polled telemetry. It is not uncontended or adoption evidence.

- The original 30-minute clock ran from 09:26:48 to a fixed 09:56:48 UTC deadline. The screen stopped at 09:53:47 due to the ownership check, not timeout. All earlier estimated deadline risks remained estimates; no deadline extension occurred.
- The parked recovery proof never ran. No proof background is claimed.
- Tree unit `kpi-tree-capacity-v1-20261022.service`, invocation `088e5fda59fb44b6872c0da628bcaba7`, existed during 09:41:36–09:44:29. Its owner reported a 2.99-s build and about 0.22 CPU-seconds of runtime controls, with most overlap spent idle at a footprint barrier. The sampler retained the actual cgroup/process activity. Its short build overlapped the end of reference pooled warm measurements, not a sustained three-minute CPU load.
- Native v1 stopped before any compiler. Native v2's compiler began at 09:53:57 UTC, after completed GPU observations and the ownership abort/cleanup. Therefore no native compiler load overlaps these GPU measurements. Its later work is outside this attempt.
- The 275 screen load samples covered 09:30:37–09:53:45. Minimum MemAvailable was 20,736,876,544 bytes (about 19.31 GiB); even subtracting the largest combined hard reservations of 16.125 GiB conservatively leaves about 3.19 GiB. Swap-out growth was zero; swap-in grew by 722 pages.
- The preserved pressure excursion peaked at 2.6834% full stall over 10.045 seconds at 09:49:15–09:49:25. It was escalated during execution; fresh 09:49:41–09:49:51 counters showed zero subsequent full stalls. A retrospective receipt audit also identified a separate 1.1530% interval at 09:39:43–09:39:53, which was not detected by the coarser live inspection at that moment. These excursions are retained rather than describing the host as pressure-free.
- Peak sampled worker RSS was 718,598,144 bytes and whole-device usage 189 MiB, below the recorded worker/VRAM bounds. All worker cleanup receipts completed. Final audit removed the empty owned worker cgroup, found all 58 recorded identities absent and no GPU compute owner, and made the 4.125-GiB reservation releasable.

All public receipts and the failed stage remain preserved. Root released the reservation. Canonical documents are handed to the evidence-lineage owner for provenance validation and Git commit; the compute lane does not stage or commit other work.
