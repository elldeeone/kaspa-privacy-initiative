# Use the RTX 3070 with smaller proof segments

Owner-authorized local experiment under
[ADR-0017](../../docs/adr/0017-rtx3070-smaller-segments.md). No funds, native
transactions, mainnet, paid services or private witnesses. The original
[po2=20 memory failure](../remote-cuda/LOCAL-RESULTS.md) is preserved.
See the [adversarial self-review](ADVERSARIAL-REVIEW.md) for acceptance limits.
The [measured result](RESULTS.md) is a complete proxy classifier receipt in
7m36s with po2=19, reverified by the original CPU verifier.

## Workload and qualification

Re-execute the exact public classifier program/input at po2=19 and po2=18.
Program image, input and complete journal hashes are independently fixed in
`main.rs`; segmentation does not change the accepted relation. Export new
traces with the pinned SDK, check the full execution claim/journal and benchmark
two adjacent full-sized segments near 24M user cycles, both lifts and their join.
Every partial receipt gets cryptographic seal/claim mutation checks.

Compare observed API times and segment counts to choose a candidate. The
selection estimate is a heuristic, not measured complete-session performance.
Use the official complete succinct-prover API for the chosen segmentation,
requiring an actual succinct seal, expected image and exact 167-byte journal,
successful exit and no unresolved assumptions. Verify a seal mutation, wrong
image and five altered journal fields. Recheck the saved receipt in a separate
process using the original pinned CPU verifier. Partial proofs do not pass.

The runner reuses the locally qualified CUDA binary and original preflight/input
checks. No CPU fallback or development mode is allowed. It retains four compute
threads, records matching GPU process/VRAM/device and per-PID SM samples, and
runs one GPU job at a time. The final proof may retain GPU allocations between
segments; its real observed memory/time still has to qualify separately.

Operational guards are generous: 192M execution cycles, 20GiB sampled host RSS,
two hours per full proof. Final CPU verification has its own bounded budget.
No GPU clock, voltage, power limit, driver or firmware is changed. No claim of
optimality across all hardware/settings follows from two configurations.

## Build and run

First prepare a fresh [local sm86 CUDA build](../remote-cuda/LOCAL.md). Its
stopped task-owned build container contains the pinned upstream source and
compiled kernels. Save that container to an experiment-only local Docker image;
do not publish it. Run `build_adapter.sh` inside that image, mounting this folder
read-only at `/opt/experiment`, the original recursion archive directory at
`/opt/build`, and a fresh writable directory at `/opt/experiment-output`.
Use four CPUs and 16GiB RAM/20GiB RAM-plus-swap for building.

The build script restores Rust 1.89.0 if the initial build removed it. It adds
only a direct reference to the already-locked JSON dependency for the adapter;
the manifest/lock dependency-list diff is retained. All original dependency
versions, checksum pins and cryptographic sources stay fixed. The original
CUDA prover binary is reused unchanged; adapter source/binary identities are
recorded separately. Compiler/setup time is outside proof timings.

```bash
python3 poc/gpu-segments/run.py \
  PUBLIC_PACKAGE CUDA_BUILD_OUTPUT ADAPTER_BINARY NEW_RESULT_DIRECTORY
```

The public package is the original pinned archive extracted by the local
preparation command. Use fresh result directories. The runner retains failed
configurations, successful partial receipts, source identities, samples and
complete/independent verification results. It never changes earlier evidence.

Even a complete proxy classifier receipt does not implement the full private
payment relation in [RFC-0003](../../docs/rfc/0003-private-payment-proof-and-settlement.md),
prove financial privacy, close real-private R13/R16 or authorize native trials.
