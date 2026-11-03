# Local RTX 3070 result, 2026-10-18

**The unchanged segment workload exceeds this GPU's 8GB memory. Two lifts and
their join did produce real, independently verified GPU receipts.** The original
five-GPU-phase qualification remains **failed**. R13/R16 remain open.

The later [smaller-segment experiment](../gpu-segments/RESULTS.md) succeeds on
the same card with po2=19 and a complete proxy classifier receipt. The original
po2=20 failure below remains unchanged; a larger GPU is not required for that
separately qualified segmentation.

This is the separate local experiment in [ADR-0016](../../docs/adr/0016-local-cuda-qualification.md),
not execution of the remote L40S path. No rental, native transaction, mainnet or
real funds were used. [Reproduction instructions](LOCAL.md) retain both modes.

## Hardware and build

One NVIDIA GeForce RTX 3070, 8192MiB, compute capability 8.6, driver 595.99.02.
The host reports AMD Ryzen 7 5800X under KVM with 24GiB RAM. Proof processes use
CPU affinity 0–3 and four compute threads; no competing compute process was
present at preflight. Memory/utilization figures below are sampled, not exact
peaks. The GPU has display activity disabled.

RISC Zero 3.0.3 is built from
`14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6`, with the original pinned Cargo.lock,
Rust 1.89.0, CUDA 12.8.1, Clang and `cuda,disable-dev-mode`. Only the original
kernel target changes from sm89 to sm86. The resulting binary SHA-256 is
`3f22b68b6d32904fe766e14e62ce011febdc946dd98d015747f40ce5fb5fffc7`.
Build time is 12m10s, separate from proving. An initial container failed before
compilation because Rust environment paths were missing; the corrected command
and both logs are retained. No host compiler/driver installation was changed.

## Original qualification: measured memory failure

The first original phase, segment 24, exited after 1.612s. Its own compute
process reached 6510MiB sampled VRAM and positive per-process SM utilization;
CUDA then failed a 1,728,053,248-byte allocation with `out of memory`. No segment
receipt was returned. The independent partial verifier rejected the empty set.
Segment 25, lifts and join were not attempted in this five-phase run.

The result remains `cudaQualificationPassed=false`, with zero completed phases.
No smaller segment, changed trace, CPU fallback or weaker receipt check was
used to turn this failure into success. The allocation failure is evidence
about this device/workload, not an exact minimum-memory recommendation for
another GPU.

## Separate recursion diagnostic

This diagnostic takes the two **original CPU segment receipts** from the pinned
public archive as inputs, then creates two new GPU lifts and their GPU join.
The input receipt bytes/hashes and origins are checked and retained separately.
No CPU-produced segment is counted as a GPU proof.

| GPU phase | API wall s | Whole phase s | Sampled prover VRAM MiB | Positive own-PID SM | Result |
| --- | ---: | ---: | ---: | --- | --- |
| Lift 24 | 0.661 | 0.819 | 1528 | Yes | Real new succinct receipt verified |
| Lift 25 | 0.588 | 0.790 | 1656 | Yes | Real new succinct receipt verified |
| Join 24–25 | 0.640 | 1.082 | 618 | Yes | Real adjacent-composition receipt verified |

The successful diagnostic takes 6.995s overall, including telemetry startup,
input checking and separate CPU comparison. A one-second NVIDIA sampler is
started 0.55s before each proof timer. The preceding diagnostic returned a valid
lift but missed an own-PID utilization sample during its subsecond lifetime;
it remains retained as **inconclusive GPU attribution**, not a successful run.
Only sampler startup changed for the fresh successful diagnostic; the workload,
binary, seal checks and positive own-PID utilization requirement did not change.

The original CPU verifier, whose binary hash is pinned in the workload policy,
checks all five saved seals: **two CPU input segments plus three new GPU
recursion receipts**. Development mode is false. Original claim hashes match;
seal/claim mutations reject; segment continuity and the join claim verify.
After archiving, a fresh extraction was hash-checked and all five saved receipts
were verified again in a separate CPU process, with mutation controls.

`recursionDiagnosticPassed=true` does **not** set `cudaQualificationPassed=true`.
Neither run proves the full classifier or private-payment relation.

The [earlier four-CPU measurements](../proof-phase-diagnostics/RESULTS.md) had
lift/join API times of 34.075s, 33.322s and 36.293s. The local GPU results above
are substantially shorter for those exact phases, but change both CPU host and
accelerator. They are not a controlled GPU-only speedup or a forecast for the
complete classifier, full private note relation or native settlement.

## Retained evidence and review

- [Manifest](evidence/local-rtx3070-2026-10-18.json): individual hashes, original
  qualification false, recursion diagnostic true, three GPU/two CPU origins.
- [Verification report](evidence/local-rtx3070-verification-2026-10-18.json):
  fresh archive extraction and CPU receipt checks, negative preflight controls
  and the 13 passing original controller tests. Those tests are not GPU proofs.
- [Public artifact archive](evidence/local-rtx3070-2026-10-18.tar.gz): 106 files,
  3,679,725 bytes; SHA-256
  `a1d60fe69c1a1e617b52a6db3f22aee79d5b0749c24b3dd1bbbbbeb58b225532`.
  Contains all three run outcomes, actual receipts, sampled resources, matching
  GPU PIDs, build/source metadata, logs and final runner source. No CUDA cache,
  compiled CUDA binary, wallet keys or private witnesses is included.

The original remote evidence and manifest were checked against every retained
hash and remain unchanged. No remote hardware/lease/guard checks were modified.
Adversarial review found that aggregate timeout could suppress final CPU
verification/reporting; final verification now has its own bounded budget.
Missing GPU telemetry, invalid seals, wrong claims or partial receipts still
cannot pass the five-GPU-phase gate. Source/self-review and local checks are
not an independent cryptographic audit.

Next GPU work needs a larger available device for the **unchanged segment
workload**, followed by all five phases. Separately,
[RFC-0003 P1](../../docs/rfc/0003-private-payment-proof-and-settlement.md#11-review-blockers-and-falsifiable-completion-gates)
requires exact suite/composition review before implementing the full relation.
