# Prospective actor18 resource profile: source review

This read-only review preserves the original 6656 MiB admission failure.
The completed IPC18 phase analysis gives 3828 MiB primary and 2926 MiB recursion;
adding the frozen 512 MiB margin gives **7266 MiB > 6656 MiB**. The source and
measurement records do not authorize or certify a new actor run.

The source supports **two GPU-task worker processes**, with one active GPU task
per process. It does **not** support the stronger statement that only two CUDA
contexts exist or that no additional persistent caches exist. A separate
7680 MiB profile can be framed as a guarded experiment on that two-worker
topology, subject to independent review. It cannot be described as a source-
proven upper memory bound or as a pass of the original profile.

## Exact identities

- Worker: SHA256 `3f22b68b6d32904fe766e14e62ce011febdc946dd98d015747f40ce5fb5fffc7`.
- Retained image: `sha256:e0729e3f109c1a351cf8121e688c9f2bb947442b486872b2ddfe9717ad882772`.
- Official RISC Zero source HEAD in image:
  `14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6`, package `risc0-r0vm 3.0.3`.
- No changes were present in the inspected actor/lib/generic CUDA HAL paths
  relative to that image's HEAD.
- Read-only snapshots are recorded in `source-reference/manifest.json`, SHA256
  `37ddcef24ca264dc12bad7f3612518e27b7441a26a96b5860a0fb0428c5f0066`,
  plus `manifest-addendum-01.json`, SHA256
  `a61de661e761b4b6d3ae5bc4fed746765bc902107da1036824e233216d373809`.
  These hashes identify the actual exported bytes. The public `sppark 0.1.12`
  package's VCS metadata records `9cd5cbd310433665a9e8c26837355cb41ca88b06`
  with `dirty=true`; do not call it an exact clean Git checkout.

All source paths below are relative to `source-reference/risc0/`, so the
repository's existing `risc0/` directory appears as a second path component.

## Known topology and lifetimes

1. The host `DefaultProver` creates a Unix socket and starts the selected worker
   with `--rpc`; its constructor contains no CUDA operation.
   `risc0/zkvm/src/host/client/prove/default.rs:41-51`.
2. With `RISC0_DEFAULT_PROVER_NUM_GPUS=1`, the RPC parent's worker count is one.
   `unwrap_or_else` does not call the NVML device-count fallback when that
   explicit argument is present. The parent creates one Execute-only pool and
   spawns exactly two child processes for device 0: one ProveSegment/ProveKeccak
   pool and one Lift/Join/Union/Resolve pool. Each pool has count 1 and no dev
   profile. No fourth prover subprocess is spawned by this RPC path.
   `risc0/r0vm/src/actors/mod.rs:180-251`.
3. The parent's Execute task builds the CPU executor and sends segment/Keccak
   task messages. It does not call a prover or construct a CUDA HAL. Its GPU
   processor exists as an idle queue consumer but cannot receive a GPU task
   from its Execute-only task-kind filter.
   `risc0/r0vm/src/actors/worker.rs:156-172,182-247,467-525`.
   No CUDA/sppark/GPU use was found in the inspected executor source paths.
4. Each child's GPU loop awaits the current task before receiving the next.
   Queued tasks are not concurrent GPU provers in that child. CPU preflight
   runs separately; the RV32IM preflight function computes host-side preflight
   results, and only `prove_core` invokes the HAL factory.
   `risc0/r0vm/src/actors/worker.rs:277-319,528-549`;
   `risc0/circuit/rv32im/src/prove/hal/mod.rs:129-162`.
5. The completed IPC18 run of this exact fixed guest/input reported zero
   ProveKeccak and zero Keccak calls. It reported 227539 BigInt calls. Therefore
   no Keccak proving task is expected for the unchanged guest/input under actor
   scheduling. This is specific to that public input and image, not a general
   assertion about all SDK guests. Actual actor task logs would still need to
   confirm the expected task set.
6. RV32IM's HAL factory creates a fresh `Rc<CudaHalPoseidon2>` and circuit HAL
   for each core proof. Recursion constructs a fresh recursion prover/HAL for
   each lift or join, retained by local `Rc` owners through that proof. No
   persistent Rust recursion-HAL cache was found in the inspected production
   paths. This does not imply that CUDA runtime or C++ caches are released.
   `risc0/circuit/rv32im/src/prove/hal/cuda.rs:233-239`;
   `risc0/circuit/recursion/src/prove/mod.rs:145-148`;
   `risc0/circuit/recursion/src/prove/hal/cuda.rs:187-203`.

## Extra state that must remain explicit

- The generic CUDA HAL's singleton mutex is process-local. It provides no
  cross-process serialization between actor primary and recursion children.
  The HAL calls `sppark_init()` and then `cust::init`, selects visible device 0,
  creates `Context::new(device)` and selects `SCHED_AUTO`.
  `risc0/zkp/src/hal/cuda.rs:46-49,397-417`.
- `sppark_init` calls `select_gpu()` and runs an NTT. Its GPU objects are lazy
  process-static objects, not additional processes. They retain CUDA streams.
  `risc0/sys/kernels/zkp/cuda/supra/ntt.cu:4-23`;
  `sppark-0.1.12/sppark/util/all_gpus.cpp:11-53`;
  `sppark-0.1.12/sppark/util/gpu_t.cuh:174-188`.
- NTT parameters contain forward and inverse GPU tables in a lazy process-
  static `all_params`. Allocations use stream-scoped `cudaMallocAsync` and
  `cudaFreeAsync`. Therefore each GPU worker can retain tables/runtime pool
  state beyond an individual Rust HAL lifetime.
  `sppark-0.1.12/sppark/ntt/parameters.cuh:213-270,299-326`;
  `sppark-0.1.12/sppark/util/gpu_t.cuh:71-77`.
- The observed IPC peaks already include that process's actual context and
  allocator history. Adding the two complete phase peaks counts those observed
  costs twice, but does not prove the two new actor processes have identical
  allocation histories. No cache amount may be subtracted to force admission.
  Source review does not rule out driver/runtime/JIT or concurrency-dependent
  allocation differences, nor short peaks missed by sampling.

## Consequence for a separate profile

Using the owner's stated 8192 MiB card capacity, a 7680 MiB guard leaves 512 MiB
outside the selected workload limit. The measured phase sum plus the separate
512 MiB prediction margin is 7266 MiB, leaving 414 MiB below that guard. These
are arithmetic margins, not a CUDA allocator quota or an OOM guarantee.

A defensible prospective experiment would fix the exact existing image, input,
worker, one-GPU/two-worker topology and complete-phase values before launch;
retain independent exact-claim checks; count every GPU PID in the owned cgroup;
and reject unexpected parent/third-worker CUDA use, foreign processes, missing
telemetry, swap or the new guard being crossed. Global device memory should
also be observed because an owned-PID sum does not account for all driver or
foreign device use. Stop and retain a resource failure; do not weaken the
original gate or tune the new profile after observing its result.

If admission requires a source-proven statement of no extra contexts/caches or
a guaranteed 7680 MiB allocation ceiling, the requirement is **not established**.
The source justifies a bounded two-worker resource hypothesis, not that stronger
claim. No actor proof or resource qualification was launched in this review.
