> Imported documentation snapshot. [Canonical status and ownership](../../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# Frozen development benchmark: GPU eligibility feasibility

Status at preparation: **BLOCKED for execution** by the active price run and missing isolated GPU dependencies. Code is authored and statically reviewed, but unexecuted, uncompiled and unvalidated. This is not a readiness claim for the next held-out study.

## Question and fixed comparison

Does exact packed candidate eligibility on Forge's RTX 3070 improve whole-observer time enough to justify integration into a later newly frozen privacy experiment? Compare unchanged reference CPU, a NumPy packed-array CPU control, and an optional CuPy RawKernel predicate implementation. No model, attack, threshold, solver budget, relation, fee, support cap or score changes.

Reference source and tests are byte-for-byte from the published historical working-balance archive identified in manifest.json. Inputs are its final sparse-correlated/partial observation pair 1504 and 1505. Each has 173 public events, 76 payouts, 64 targets; views are C+D and pooled. Expected predictions are also published historical outputs. Observers see only one view's public.json, directory.json, view.json and targets.json. No truth, seed, active output or other case is mounted.

## Sequence and selection rule

1. Verify all package file hashes, create a fresh run directory, confirm parent release of CPU capacity and absence of the active price controller. Use at most two scheduler CPUs.
2. Profile the unchanged observer for each view. Require eligible() cumulative time >=25% of total profile time AND at least 100,000 calls in BOTH views. If not met, stop with NO_GO_HOTSPOT_GATE; retain the profile and do not invent a replacement kernel mid-run.
3. Execute retained handmade controls in separate workers, then measure reference, array and GPU paths. Each view runs three full observations in a fresh process: first invocation and two warm invocations. GPU controls and measurement workers use separate compiler caches so controls cannot erase measured cold compilation.
4. Compare every full prediction to the historical reference JSON, including schema, hashes, all targets, all 13 C+D / 26 pooled variants, amount/sender/recipient and relationship_rank. Equality is canonical JSON equality, not accuracy equality.
5. A promising candidate requires warm median GPU time <=80% of BOTH controls in EACH view. Also require the cold process estimate not to regress against either control, because the current pipeline starts an isolated observer per view. Report cold overhead and its break-even; do not assume cross-ledger process reuse. Two warm samples support a development screen only, not p95 qualification or a 512-ledger scaling claim.

No truth or scorer runs are needed here. Prediction byte-equivalence under canonical encoding preserves the input to the unchanged scorer; no score calculation is retuned.

## Kernel scope and exactness

Only Engine.eligible predicates are replaced with precomputed masks. Payout subset creation, all integer sums, candidate dictionaries, support sets, role selection, deterministic ranking, exact first-eight support cap, prior and final assembly stay in the pinned source. The subclass uses a packed row table with event indices, value, owner, coinput and first-anchor count. None is an explicit -1 sentinel only for validated nonnegative fields. Every converted scalar is range-checked before int64 conversion; unsupported integers cause a stop, not truncation.

CPU and GPU compute the same predicate. Nonempty input hypotheses still perform their exact coinput conflict check on CPU. Unknown candidate records fall back to the original predicate. Two masks are materialized per current target; no target-by-ledger tensor or cross-ledger cache is created. The adapter is a performance hypothesis, not an optimization result. GPU launch and mask transfer overhead may make the CPU array control faster.

## Containment and metrics

One sequential worker at a time, assigned at most two vCPUs, 300 seconds per worker and 30 minutes total benchmark time after environment setup. Sample process-tree RSS every 0.1 s and stop at 4 GiB; sample GPU process memory about once per second and stop at 3 GiB. CUDA pool limit is 2 GiB and packed input limit is 1 GiB. RSS/VRAM monitoring is sampled and can miss brief peaks; it is not a cgroup hard limit. No RLIMIT_AS is imposed on CUDA's virtual address reservation.

The public fixture's loose upper bound is 8.7M records, about 531 MiB at 64 bytes per record; actual size and Python object overhead are unmeasured. Stop if bounds are reached; do not expand the scope/budget to force success. Do not start if another GPU compute process exists; stop if one appears.

Worker metrics include full observer wall time, cold process upper estimate including launch/teardown, adapter import/setup, packing, host-to-device transfer, synchronized kernel time, device-to-host transfer and pool usage. The parent records process wall time, sampled process-tree RSS and total observed GPU usage. All failure evidence is retained; timed-out jobs never count as correct rejection evidence.

Each worker uses a new Bubblewrap namespace with network disabled; only /usr, the isolated venv, code capsule, one input view and fresh output are mounted. GPU workers additionally mount only the named NVIDIA device nodes. /proc is a new procfs inside the PID namespace for driver compatibility, not a host procfs bind. Existing Bubblewrap configuration and active runtime are untouched. GPU compiler/driver caches are under that worker's /out. No HOME directory, credentials, project checkout, expected answers or truth is mounted.

## Exact future commands

Run only after the parent confirms the current 12-worker evaluation is finished and releases capacity:

```sh
cd /home/luke/projects/kpi-orchestration/2026-10-22/compute-plan
KPI_BENCH_CAPACITY_RELEASED=1 timeout 900s taskset -c 0,1 bash SETUP.sh
KPI_BENCH_CAPACITY_RELEASED=1 /usr/bin/python3 -I -B benchmark.py --execute-after-capacity-release
```

SETUP.sh creates only this directory's .venv and caches. It pins NumPy 2.3.5 and CuPy CUDA12 14.2.0, resolves a hash-locked wheel-only dependency closure, uses the existing /usr/bin/python3.14, and disables managed-Python downloads. It cannot overwrite an existing .venv. No apt, sudo, driver update, system Python change or global cache installation is used. Compatibility still needs actual qualification after setup. Missing wheels/libraries/namespace access are BLOCKED, not grounds to weaken isolation.

The environment assertion is an explicit parent scheduling gate, not a claim that a CPU affinity mask makes spare physical cores available. No benchmark/profile/setup command has been executed during preparation.

## Deliverables and stop rules

runs/<UTC>/summary.json plus profiles, complete predictions, worker/resource receipts and logs. Status is NO_GO_HOTSPOT_GATE, NO_GO_END_TO_END_GAIN, BLOCKED_OR_FAILED or CANDIDATE_FOR_NEW_DEVELOPMENT_FREEZE. Stop on any mismatch, overflow, worker error, time/RAM/VRAM limit, competing GPU workload, active price-run detection or missing prerequisite. A passing screen authorizes review for a later experiment; it never replaces or reinterprets the current held-out evidence.

## Provenance and primary runtime references

manifest.json pins all copied sources, public fixtures, expected predictions and authored code. requirements.lock is produced only by the future isolated setup and its SHA-256 is recorded with each run. Setup has not been attempted.

- https://docs.cupy.dev/en/stable/install.html
- https://docs.cupy.dev/en/stable/user_guide/performance.html
- https://docs.cupy.dev/en/stable/user_guide/memory.html
- https://docs.nvidia.com/cuda/cuda-c-best-practices-guide/index.html
