# Separate local CUDA qualification

The owner authorized GPU qualification and the complete private-payment
specification in parallel, with no mainnet or real funds. A local RTX 3070 is
available, so this experiment creates no rental or paid service. See
[ADR-0016](../../docs/adr/0016-local-cuda-qualification.md).

This is a **separate sm86/8GB hardware experiment**. The original remote
L40S/sm89/48GB [plan](PLAN.md), hardware checks, guard and lease rules remain
unchanged. A local result does not qualify that provider/host/driver/billing path.
The actual 2026-10-18 outcome and retained receipts are in
[LOCAL-RESULTS.md](LOCAL-RESULTS.md): segment memory failure, followed by a
successful separately labelled GPU recursion diagnostic.

## Reproduce

From repository root, using Docker with working NVIDIA GPU access:

```bash
mkdir -p .local
python3 poc/remote-cuda/prepare_local.py .local/cuda-sm86-NEW --build
RISC0_PROVER=ipc python3 poc/remote-cuda/check_cpu_compare.py \
  .local/cuda-sm86-NEW/package/bin/kpi-takeover-host
python3 poc/remote-cuda/local_qualification.py \
  .local/cuda-sm86-NEW/package .local/cuda-sm86-NEW/output .local/cuda-sm86-NEW/results
```

Use new directories. Do not run these validators with Python `-O`; optimized
execution is explicitly rejected because the reused original validators contain
assertions. An existing recursion archive may be provided with
`--recursion-archive PATH`; its SHA-256 must still match. Preparation without
`--build` records the exact Docker command in `preparation.json` and starts no
container/proof job. The task-owned build container is retained for inspection;
build output/logs remain in the declared output directory. No other container,
host compiler/driver installation, wallet data or secret is modified.

The CPU-only build uses the exact upstream source/lockfile, Rust 1.89.0,
`cuda,disable-dev-mode`, original CUDA 12.8.1 base image by digest and Clang.
It changes only the explicit target to `sm_86`, records binary/build metadata,
and gives the compiler four CPUs, 16GiB RAM and 20GiB RAM-plus-swap. All source
fetches/artifacts are public; no private witnesses or provider credentials are
passed to it. Build/setup time is separate from proof time.

## Proof and verification conditions

The workload is the exact original public PR40 segment assets 24/25 and program,
input, journal and CPU claims. It produces segment 24, lift 24, segment 25,
lift 25 and their adjacent join. Preflight rejects an sm89/substituted binary,
changed source/lockfile, changed policy/input/verifier or active competing
compute process. The reference CPU verifier remains unchanged and is checked
against its original hash.

Every proof phase must show NVIDIA process/VRAM activity matching the monitored
native process group, with real utilization observed. Per-phase and one-hour
aggregate limits, four compute threads and the existing sampled host-RSS policy
are retained. First-use GPU kernel initialization is included in the first
phase. Receipt claim hashes must equal the independently pinned original CPU
claims. A separate original CPU-verifier process checks saved seals, claims,
continuity and mutation rejection with development mode disabled.
Positive per-process SM utilization is additionally required on this desktop
GPU. The one-second NVIDIA sampler starts 0.55 seconds before proof timing to
observe subsecond recursion; absent matching samples remain inconclusive.
Post-run CPU verification has its own bounded budget even if proving timed out.

Only all five verified phases with GPU activity can pass this local
qualification. A failed phase retains its logs/resources and any saved receipts;
partial verification reports the actual count and cannot pass the five-phase
gate. The 8GB device may fail on memory; such a result does not authorize smaller
segments, changed traces/security conditions or a reported CUDA speedup.

If segment proving fails, the separate diagnostic command is:

```bash
python3 poc/remote-cuda/local_qualification.py \
  .local/cuda-sm86-NEW/package .local/cuda-sm86-NEW/output \
  .local/cuda-sm86-NEW/recursion-results --recursion-only
```

It checks the two CPU segment input receipts against the pinned public archive,
records their origins, then runs GPU lift/lift/join and CPU seal verification.
`recursionDiagnosticPassed` may become true; `cudaQualificationPassed` always
remains false in this mode. Exit zero means this explicitly selected diagnostic
passed, not that segment proving or the original five-GPU-phase gate passed.

These are two middle segments of the old proxy classifier, not a full-classifier
receipt or the full private payment relation in [RFC-0003](../../docs/rfc/0003-private-payment-proof-and-settlement.md).
Comparison with earlier four-CPU timings changes both CPU host and accelerator;
report the measured environment and phase costs, not a causal GPU-only or
universal performance factor. R13 and R16 remain open after this qualification.
