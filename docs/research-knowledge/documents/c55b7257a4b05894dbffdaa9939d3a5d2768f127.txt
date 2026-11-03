# ADR-0016: Local RTX 3070 CUDA qualification

Status: Accepted for the owner-authorized GPU qualification, 2026-10-18.
No rental, mainnet, funded transaction or private witness is involved.

## Evidence and decision

Current local preflight finds one NVIDIA GeForce RTX 3070, compute capability
8.6, 8192 MiB VRAM, driver 595.99.02 and no compute process. Docker GPU access
works. Host RAM is 24 GiB with about 17 GiB available at preflight. This differs
from the prepared remote L40S/sm89/48GB experiment; do not weaken or relabel that
experiment's hardware checks.

Use a separately identified local experiment with the same pinned RISC Zero
3.0.3 source `14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6`, committed lockfile,
`cuda,disable-dev-mode` features, original PR40 public program/inputs and CPU
claims. Compile CUDA kernels for sm86 and record the new binary identity.
Upstream build_kernel explicitly honors NVCC_APPEND_FLAGS; NVIDIA's Ampere
compatibility guidance requires matching code/PTX capability. An sm89 build
must not be silently treated as an sm86 build.

Reuse the existing five phases (segments 24/25, two lifts, one join), telemetry,
and independent CPU receipt/mutation checks. A native host prover makes GPU PIDs
directly comparable to the monitored process group. Record local hardware,
CUDA activity, host memory, VRAM and per-phase wall/CPU time. Each completed
phase must match the original CPU claim; independently verify saved receipts.
On a desktop GPU, additionally require positive per-process SM utilization for
a PID observed in the proof's process group; graphics utilization alone is
insufficient. Retain only matching process samples. Final CPU verification has
its own bounded budget so an expired proof deadline cannot suppress checking
already returned receipts.
Never count missing telemetry, memory failure, timeout or a CPU fallback as a
successful CUDA result. Keep any verified partial results if a later phase fails.

The 8GB device may be insufficient. An out-of-memory result is a measured limit,
not permission to reduce the security workload. Build in an isolated task-owned
container with four CPUs and a generous 16GiB RAM/20GiB RAM-plus-swap limit;
store source/build metadata and logs separately from proof time. Proving retains
the existing phase/aggregate diagnostic limits and sampled host-RSS policy.
Any local speed comparison is specific to this device/host, not the L40S or a
complete-classifier throughput claim.

No external watchdog/lease is needed because no paid resource is created and
proof groups run locally with independent deadlines. The remote rental path and
its billing/retention safeguards remain unchanged. Do not upload wallet secrets,
use development receipts, change the circuit/VK or launch a full-classifier
attempt as part of this five-phase qualification. R13/R16 remain open.

After a measured segment-memory failure, a separately labelled recursion-only
diagnostic may lift the two retained original CPU segment receipts and join the
GPU lifts. Check CPU input bytes against the pinned public archive, record their
origins, verify all returned seals/claims and require GPU process evidence. This
can establish three recursion phases on the device, but can never pass the
five-GPU-phase qualification or relabel the CPU segment inputs as GPU work.

Sources: [pinned build support](https://github.com/risc0/risc0/blob/14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6/risc0/build_kernel/src/lib.rs),
[NVIDIA Ampere compatibility](https://docs.nvidia.com/cuda/ampere-compatibility-guide/index.html),
[original experiment](../../poc/remote-cuda/PLAN.md).
