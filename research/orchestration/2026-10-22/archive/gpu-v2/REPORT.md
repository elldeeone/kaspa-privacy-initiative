> Imported documentation snapshot. [Canonical status and ownership](../../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# Compute lane v2 revision report

**Recommendation: retain this as a BLOCKED development candidate. Do not install or run it during the frozen Forge evaluation.** GPU eligibility offload is plausible in principle, but no measured GPU gain or compatible isolated runtime is established. The independent Mac public reference profile supports a real eligibility hotspot; pooled was stopped by its memory-pressure guard and the complete two-view gate remains unresolved. Parent should use both-view profile evidence to decide whether to proceed before spending time on GPU setup.

## Revision scope and reviewed findings

V1 remains at /home/luke/projects/kpi-orchestration/2026-10-22/compute-plan, manifest raw SHA-256 a3281bbc72d32627c16fba035fb01937f7963555da6ff3e39abe513110735270. V2 is this separate directory, /home/luke/projects/kpi-orchestration/2026-10-22/compute-plan/revisions/v2, with its own manifest, STATUS and frozen BENCHMARK spec. All inherited source, fixture and expected-output bytes retain their original hashes. No active checkout or runtime has been edited by this lane.

Both final reviews were read before freezing v2:
- statistical-review/GPU-BENCHMARK-STATIC-REVIEW.md
- evidence-lineage/GPU-PACKAGE-EXECUTION-REVIEW.md
under /home/luke/projects/kpi-orchestration/2026-10-22/. Their hashes are retained in the new manifest.

| Review issue | Authored v2 correction | Remaining validation |
| --- | --- | --- |
| Synthetic cold estimate | Distinct fresh worker performs exactly one observe call. Process wall time includes launch, setup/JIT, one observation, serialization/receipt and exit; no warm-duration subtraction. Warm samples run in another process. | Execute later; monitor polling can overestimate process wall time. |
| Late candidate allocation bound | Check candidate count/table bytes before creating the index/NumPy table. Stream existing rows into one contiguous array; remove concatenated references and list-of-lists copy. | Actual candidate/index/NumPy overhead is unmeasured. Require 4 GiB cgroup first. |
| RSS sampling alone | Dedicated job cgroup before exec enforces memory.max=4 GiB, swap=0, 64 tasks; detect any new max/OOM counter. | Parent-authorized provisioning/writability and kill path must qualify; no global/service changes. |
| Unbounded wait/descendant cleanup | No unbounded wait/communicate; bounded PID-identity signaling, subreaper adoption, cgroup.kill, finite poll/reap, persisted pending/final receipts and post-GPU audit. Forced child-timeout qualification added. | Execute the CPU-only qualification later. Unkillable kernel tasks remain BLOCKED_CLEANUP. |
| Runtime lock merely recorded | Exact installed versions versus resolution lock, RECORD integrity, complete venv hashes, stdlib/named tools/driver files, real device and NVRTC/runtime package identities; recompute before dispatch. | Future wheel resolution and environment must be separately pinned/reviewed. CUDA namespace compatibility remains unqualified. |
| Compute-app memory called total | Query whole-device memory.used and UUID, baseline and post-cleanup state; retain separate compute-owner telemetry. 3 GiB whole-device sampled stop plus independent 2 GiB pool cap. | Telemetry/driver visibility unqualified; sampling is explicitly not a hard total VRAM limit. |
| Open code/import/path capsule | Reject escaping manifest paths, ancestor/leaf links, extra source/input files and unexpected root entries. Verify external raw manifest pin, copy only manifested source/one view into a read-only dispatch snapshot, suppress site startup hooks. | Delta review and later namespace qualification. |
| Ambient setup config / duplicate scheduling | Clean child config, explicit index/no-config, private caches, preserve failed attempts, common lane lease and active-run guard during jobs/helpers. | Parent must hold exclusive release and prohibit legacy/concurrent dispatch. |
| Cold metric not meaningful pipeline gain | Require 20% GPU improvement for directly measured fresh-process AND warm metrics against BOTH CPU controls in BOTH views. | Stronger than v1; no performance result yet. |
| Manifest representation ambiguity | Use explicitly named raw SHA-256 fields and external raw pins. | Parent/reviewers must record those exact pins. |

This is a bounded screen, not a general GPU orchestration framework. Nothing beyond the eligibility mask has been ported. Controls, integer sums, deterministic ordering, deduplication, complete predictions and the unchanged scorer input are preserved. No gate has been loosened.

## Profile evidence available at preparation

The statistical reviewer reported one completed independent Mac M3/Python 3.14.6 stdlib profile on the immutable historical C+D fixture: 61.724 s profiled observe, 61.857 s whole process, 162.3 MiB sampled RSS; eligible() 63,178,835 calls / 21.161 s cumulative / 34.293% of profiled time. Complete canonical parity passed for all 64 targets and 13 variants. The raw evidence is in the parent's Mac workspace at work/mac-validation/workers/statistical-review-reference-001/public/{profile.json,receipt.json,prediction.json}. This lane did not execute or independently re-read those local artifacts. Pooled was stopped at 57.8797 seconds by the preset system swap-growth guard. Its partial profile recorded 66,314,696 eligible calls and 40.977% cumulative share, but there is no complete pooled prediction or 26-variant parity result. The censored result does not pass the full two-view gate. No Mac retry is scheduled. The reviewer report is MAC-REFERENCE-PROFILE-REVIEW.md (reported SHA-256 98c98a9f572ff2997f1a8f9b0a4b5bcc807e703ea625e654bdf8c8e37b0df95a).

That C+D result passes the predeclared selection threshold for one view. Instrumented Mac timings neither predict Forge speed nor establish a GPU speedup ceiling. Packing, per-target transfers, Python mask lookup and the remaining books/split/offer work can erase savings. An array CPU path may be the better outcome. A complete pooled reference check remains queued for released Forge capacity; do not manufacture GPU work merely because the card is idle.

## Hardware and proof-stack separation

Earlier read-only Forge inventory found 14 virtual CPUs, RTX3070/8 GiB, driver595.99.02, Python3.14 and uv, libcuda but no installed CuPy/usable NVRTC toolkit in the inspected system environment. Exact tool and driver-library paths used in the v2 runtime attestation exist, but no versions/imports/CUDA behavior are newly qualified here.

The original compute-plan/REPORT.md retains the full direct-proof feasibility map: the current BN254/Groth16 v6 wallet uses arkworks0.6 CPU/Rayon and has no ready GPU adapter; its retained wallet proof/preparation/memory/fee targets are unmet. Orchard was a design comparison. The historical L40S RISC Zero outer-proof job is a different circuit/proof/workload and consumed more VRAM than Forge's 8 GiB. None of those facts is evidence that the current Python privacy observer can be accelerated by invoking a prover binary. No proving benchmark is added in v2.

## Status and exact next steps

Preparation is source-only. Manifest/hash/JSON/file inspection is the only validation performed on this revision; not even a syntax import or test has run. STATUS must remain BLOCKED until:
1. Parent receives independent v2 delta reviews and both-view reference hotspot/parity evidence.
2. Current frozen evaluation finishes and parent grants exclusive Forge resources.
3. Parent explicitly authorizes a dedicated empty job cgroup; fixed 4 GiB limit and cleanup permission qualify.
4. The bounded wheel-only private setup succeeds, installed bytes match its resolved lock, and parent records/reviews the runtime hash.
5. The CPU namespace/control/forced-child cleanup command passes, followed only then by the fixed full screen whose reference profiles gate GPU selection.

BENCHMARK.md contains the exact bounded commands and stop rules. Outputs stay in this version's private runs/cache/.venv; the only additional future host object is the explicitly authorized dedicated job cgroup and common lane lease. No install, cgroup write, GPU operation, profile, benchmark, commit, push or external post occurred during preparation. A later failure is preserved; there is no global configuration/install fallback.

The appropriate answer to Luke is: **the next privacy run may benefit from a narrow GPU predicate offload, but it is not ready now; first compare exact outputs and whole-process performance against a batched CPU control. Leave the card idle while the frozen run completes.**
