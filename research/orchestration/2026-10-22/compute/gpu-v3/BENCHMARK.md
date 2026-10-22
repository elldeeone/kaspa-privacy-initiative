> Imported documentation snapshot. [Canonical status and ownership](../../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# V3 frozen development screen: exact eligibility offload

**BLOCKED — awaiting independent v3 delta review and real Forge qualification.** The only semantic change from v2 fixes immutable PID identity tracking. A tiny Mac regression AST-extracted its process-tracker methods and executed them with every process/proc/pidfd/signal/wait/clock endpoint mocked; it did not import the guards module or perform live cleanup. No authored code has been executed on Forge, and no environment, cgroup, GPU context or cache has been created by this revision. Reviewed v1 and v2 remain intact. REPORT.md records the exact mock scope, source pins, passing cases and resource receipt.

## Question, workload and controls

Can one unchanged historical privacy observer finish materially faster when only its repeated candidate eligibility predicates use packed masks? Compare (1) the exact reference Python observer, (2) a NumPy packed-array CPU control, and (3) an optional CuPy CUDA predicate. GPU work does not include the Groth16 wallet prover or the historical RISC Zero outer proof. No privacy model, attack, value arithmetic, rank, relation, support cap, fee or scorer is changed.

The manifest pins historical public archive 2026-10-21-working-balance/public-evidence.tar.gz (SHA-256 05b3d80d080aa51ec48fed387caecd0197ca64efe141eb18dfa33af5830a5950), exact observer b492d5a2e63836751f51f5151c002c3ec6492c224b518846c45eca23f3ea7495, retained controls, fixtures and expected results. Cases are inputs/observe-1504 (C+D) and observe-1505 (pooled), the final sparse-correlated/partial pair. Each includes 173 events, 76 payouts and 64 targets. Check every field and ordered row in all 13 C+D / 26 pooled variants against the published complete expected prediction. No seed, truth, private evaluation output or current checkout is copied or mounted.

## Frozen sequence and decision

1. Parent must hold exclusive resource release for the entire setup/run. The common lane lease rejects cooperating duplicate controllers; active price-run detection runs before and throughout helpers/workers. The parent remains responsible for other schedulers and any legacy v1 invocation.
2. Verify the externally supplied raw manifest hash, every manifest leaf, closed source/input directories, no symlinked ancestors/destinations, and the independently pinned runtime lock. Recompute installed runtime identity before dispatch. Create a fresh read-only code/input copy per worker containing only manifested files; no bytecode or extra import is admitted in /code.
3. Qualify CPU namespace/control behavior, then deliberately time out a worker with a forked child and require both child receipts plus an empty cgroup and no surviving tracked descendants. The qualification-only command ends here, before profiling/GPU import.
4. Profile the unchanged reference observer on BOTH cases. Select this already specified kernel only if eligible() cumulative cProfile time is >=25% of total profile time AND >=100,000 calls in both cases. Otherwise retain NO_GO_HOTSPOT_GATE. Do not replace a failed kernel selection mid-run. Instrumented fractions are a selection screen, not an uninstrumented speedup ceiling.
5. For each backend, run retained controls (reference controls already ran), then separate COLD and WARM workers for each case. A cold worker is a fresh process with exactly ONE observe call and one prediction/receipt write. Its process timer runs from before launch until process exit/reap. A separate fresh warm worker performs one warmup and two measured observe calls. Each worker has private, initially empty CUDA/CuPy caches; no control worker can warm a measurement worker's disk cache.
6. Require canonical equality of every complete prediction, including the newly run reference, all guesses and ranks, metadata and input digests. A mismatch, overflow, error or resource failure is BLOCKED_OR_FAILED, never a successful privacy rejection.
7. Require GPU cold fresh-process time <=80% of BOTH CPU controls AND GPU median of the two warm observe times <=80% of BOTH CPU controls, independently in EACH view. The v2/v3 policy strengthens v1's cold non-regression gate; no criterion was relaxed. There is no synthetic cold subtraction. A pass means CANDIDATE_FOR_REPEATED_DEVELOPMENT_VALIDATION only, not adoption, robust population speedup, p95, multiworker scheduling or held-out evidence. Fixed order and two warm samples can be affected by jitter.

The maximum full roster is 18 sequential workers: 3 controls, 1 timeout/descendant probe, 2 profiles, 6 single-call cold workers and 6 warm workers. The global budget may stop this roster early; do not extend it to force completion. Existing exact Fraction scores are not recomputed because identical complete predictions preserve the scorer input for fixed truth. No current held-out result is retuned.

## Kernel and allocation contract

The unchanged superclass constructs candidate sums/residuals with Python integers. The adapter checks count <= floor(1 GiB / 56) BEFORE constructing its index or NumPy table. It allocates one bounded contiguous seven-int64-column array and fills it incrementally from chained existing candidates; there is no concatenated reference list or list-of-lists packing copy. The 1 GiB bound is per Engine table. Original candidates, the index, two simultaneously live pooled/public engines and NumPy temporaries remain subject to the whole job's kernel memory boundary.

Seven columns hold up to three event indices, exact value, owner, coinput and first-anchor count. Scalar range/type checks precede all int64 casts. The kernel performs only integer comparisons, not amount arithmetic or float scoring. Exact nonempty input-conflict checks stay in Python; unrecognized candidate records retain the reference predicate. Candidate iteration, deduplication, first-eight support pruning and deterministic tie rules are unchanged.

The old loose combinatorial upper bound is about 8.7M records; it is not a measured memory requirement. A large fixture can fail the 4 GiB job limit even if its packed table is under 1 GiB. Failure is useful evidence, not grounds to raise the limit. Mac reference RSS is not a bound on NumPy/GPU packing.

## Resource and cleanup contract

- At most two assigned logical CPUs, inherited affinity plus a two-CPU cgroup quota. OpenMP/OpenBLAS are set to one thread. At most one benchmark worker and one GPU job at a time.
- The worker enters the dedicated empty cgroup BEFORE exec/Bubblewrap/candidate allocation: memory.max=4,294,967,296 bytes, memory.swap.max=0, memory.oom.group=1, pids.max=64, cpu.max="200000 100000". A fresh cgroup must be explicitly provisioned after release using already delegated controllers. No parent controller/service/global configuration is changed. If permissions or limits cannot be established, remain BLOCKED. This is kernel enforcement, with the kernel's documented possible temporary charge overshoot; it is not merely sampled RSS. Any new memory max/OOM event blocks.
- A worker has 300 seconds including cleanup/audit reserve: normal work stops by 278 seconds. The timeout probe stops after one second. Controller work/cleanup gets 1,770 seconds; the required outer timeout sends TERM at 1,790 and KILL ten seconds later, keeping the nominal total envelope at 1,800 seconds. Setup work/cleanup gets 870 seconds; the outer TERM-at-890/KILL-after-10 backstop caps its nominal envelope at 900 seconds.
- The parent samples RSS at a target 50 ms interval, except while telemetry is running. GPU telemetry queries have two-second helper deadlines and bounded cleanup; samples are spaced one second after the previous queries finish, not guaranteed exact 1 Hz.
- The 3,072 MiB stop is WHOLE-DEVICE memory.used, including baseline/graphics/driver allocations visible to that device query. Record baseline, sampled maximum, post-cleanup device memory and device UUID. Separate compute-process telemetry prohibits another compute owner and audits no surviving GPU compute owner after cleanup. Missing/nonnumeric/changed-device telemetry blocks. A 2 GiB CuPy pool cap is separate; it excludes context/driver allocations. Neither the sampled whole-device stop nor the pool cap is a hard 3 GiB total VRAM limit, and brief peaks may be missed.
- Save a pending failure/resource receipt before cleanup. Cleanup uses tracked PID identities/pidfds, child-subreaper adoption, TERM, cgroup.kill/SIGKILL and nonblocking polls/reaps with a finite deadline. There is no unbounded process.wait()/communicate() path. If anything remains, write BLOCKED_CLEANUP and schedule no further worker. The kernel can leave an uninterruptible process alive despite signals; the controller reports that state instead of waiting forever or claiming success.
- memory.peak/memory.events snapshots are cumulative for the dedicated reused cgroup; per-job RSS peaks and counter deltas are reported separately.

A same-host concurrent privileged mutation or a kernel/driver failure is outside this development harness's prevention claim. External review pins, parent scheduling, kernel memory enforcement and fail-closed namespace/cleanup qualification are the prerequisites; this is not a production execution platform.

## Runtime provenance and containment

SETUP.sh invokes bounded setup.py with a clean child environment, explicit PyPI index, uv --no-config, wheel-only hash resolution/install, private caches, no Python download, and the existing /usr/bin/python3.14. It cannot overwrite a previous attempt, including a dangling .venv link. It has no apt/sudo/system-Python/driver/service change. Its host execution is not a filesystem sandbox; trusted uv is constrained to explicit private venv/cache/output paths and configuration, and failure artifacts are preserved.

runtime_identity.py executes with the exact isolated Python and -I -S -B. It does not import NumPy/CuPy or call CUDA. It checks installed names/versions against every exact resolved requirement, verifies wheel RECORD hashes, hashes the full venv file tree (with only controlled internal/interpreter symlinks), Python stdlib and named interpreter/uv/Bubblewrap/nvidia-smi/timeout/driver-library binaries. It records the actual driver text, device records and CUDA runtime/NVRTC distribution versions. A later run recomputes these identities and requires complete equality with the externally pinned runtime-lock.json; a mere resolution-lock hash is insufficient. Unsupported conditional/direct-url lock syntax stops for review. Named-tool/driver/stdlib attestation is not a claim that every host /usr library was frozen.

Workers use -I -S -B and explicitly add only /code and the pinned /env site-packages; startup .pth/sitecustomize hooks do not run. A new Bubblewrap mount/PID/user/network namespace exposes /usr, the exact venv, closed source snapshot and one public input view read-only; only fresh /out is writable. GPU nodes are added only for GPU workers. No active checkout, host HOME, truth, expected answers or credentials are mounted. Existing Bubblewrap configuration is untouched. Actual CUDA wheel availability, namespace visibility, NVRTC compilation and GPU telemetry remain unqualified.

## Future bounded verification commands — DO NOT RUN while frozen work is active

First obtain the independent v3 identity delta review and retain the v2 timing/equivalence review and the two-view public reference profile. If those profiles rule out this kernel, stop here without installing a GPU runtime. The parent alone releases Forge capacity after the frozen evaluation ends and authorizes the dedicated cgroup. Replace REVIEWED_MANIFEST_SHA256 and REVIEWED_RUNTIME_SHA256 with actual independently recorded hashes; never infer them from an unreviewed replacement manifest.

All commands below run on Forge in this exact revision:

```sh
cd /home/luke/projects/kpi-orchestration/2026-10-22/compute-plan/revisions/v3

# Provision only the empty dedicated job cgroup; preserve any partial failure.
KPI_BENCH_CAPACITY_RELEASED=1 KPI_BENCH_CGROUP_PROVISION_AUTHORIZED=1 \
  timeout --signal=TERM --kill-after=5s 10s bash PROVISION-CGROUP.sh

# Fresh private environment and installed-byte attestation; not GPU qualification.
KPI_BENCH_CAPACITY_RELEASED=1 \
  timeout --signal=TERM --kill-after=10s 890s bash SETUP.sh \
  --execute-after-capacity-release --expected-manifest-sha256 REVIEWED_MANIFEST_SHA256

# Parent inspects setup-receipt.json, requirements.lock and runtime-lock.json,
# records the actual raw runtime hash and confirms no unexpected distributions.
# One bounded CPU namespace/control/forced-descendant-cleanup qualification.
KPI_BENCH_CAPACITY_RELEASED=1 \
  timeout --signal=TERM --kill-after=10s 180s /usr/bin/python3.14 -I -S -B benchmark.py \
  --execute-after-capacity-release --qualification-only \
  --expected-manifest-sha256 REVIEWED_MANIFEST_SHA256 \
  --expected-runtime-sha256 REVIEWED_RUNTIME_SHA256

# Only after that qualification passes, one fixed full screen.
KPI_BENCH_CAPACITY_RELEASED=1 \
  timeout --signal=TERM --kill-after=10s 1790s /usr/bin/python3.14 -I -S -B benchmark.py \
  --execute-after-capacity-release \
  --expected-manifest-sha256 REVIEWED_MANIFEST_SHA256 \
  --expected-runtime-sha256 REVIEWED_RUNTIME_SHA256
```

No fallback to system installs, broader mounts, changed thresholds, larger budgets or shared compiler caches. Close-to-threshold results need a separately reviewed repeat plan; this screen cannot establish a precise speedup.

## Deliverables and primary references

runs/<UTC>/summary.json, profile/function tables, all complete predictions, per-worker cold/warm/stage timing, packing/H2D/kernel/D2H metrics, immutable dispatch copies, setup/runtime attestation, resource/cleanup receipts and failure logs. NO_GO_HOTSPOT_GATE and NO_GO_END_TO_END_GAIN are valid outcomes. BLOCKED_OR_FAILED or BLOCKED_CLEANUP require diagnosis before any subsequent dispatch. A candidate still requires independent repeated performance validation and a newly frozen development experiment.

- [CuPy installation](https://docs.cupy.dev/en/stable/install.html)
- [CuPy performance and timing](https://docs.cupy.dev/en/stable/user_guide/performance.html)
- [CuPy memory limits](https://docs.cupy.dev/en/stable/user_guide/memory.html)
- [uv command/configuration reference](https://docs.astral.sh/uv/reference/cli/)
- [Linux cgroup v2 memory and kill interfaces](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
