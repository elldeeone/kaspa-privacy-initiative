# Separate actor18 experiment on the full 8 GiB card

**Status:** prospectively selected operational resource experiment, before actor
execution. Identity: `actor18-8gib-20261022-01`. This does not reopen the original
actor admission result: the frozen6656MiB rule failed and remains failed.

## Reason for a separate profile

The completed IPC18 run produced a genuine independently verified receipt for
the exact original claim. Its complete measured primary and recursion peaks
were3828 and2926MiB. Their sum plus512MiB is7266MiB: above the original6656MiB
admission threshold, but below this card's8192MiB physical capacity.

Independent source review finds exactly two GPU worker processes for this
one-GPU actor configuration, plus CPU execution. Primary tasks serialize; the
secondary handles lift/join/resolve. The fixed guest has no Keccak tasks or
assumptions. This is not a static allocation bound: per-instance CUDA contexts,
persistent NTT caches, overlap and driver effects may increase the live sum.

One new prospective run tests whether supported pipelining finishes correctly
within a7680MiB sampled process-sum guard, leaving512MiB below physical capacity.
The observed sum is empirical admission evidence, not a guaranteed fit. The
original failure and this changed operational envelope must be reported side
by side. No cryptographic, state, authorization or product acceptance check is
weakened. No new guest, witness, setup, native transaction or owner workflow is
created. This iterative performance experiment is not a retuned privacy study.

## Fixed execution and outcomes

Use the exact reviewed client `84e3b0e2773e25e1a3fe528c42f69729d0b2471a177a9a82a8ef778a6e4e93cb`,
qualified CUDA worker, SDK3.0.3 and unchanged program/input/image/J/claim from
[the original plan](../AGGREGATE-COST-DESIGN.md). Backend is actor, segment18,
one GPU,6CPU,8GiB host RAM,zero job swap and generous60min completion allowance.
Use fresh output/cache/work directories. Record the exact command, source,
runner and input hashes before launch. Only one full proof job uses the GPU.

Require a clean device with no foreign compute workload and reliable all-PID
telemetry before launch. Sample all owned GPU processes, cgroup membership,
start identities, summed VRAM, host memory/swap, CPU counters and GPU clocks.
Missing/malformed samples remain missing. Resource evidence with unresolved
gaps is incomplete; it cannot establish a memory pass. On an observed sum over
7680MiB, stop all owned processes and retain the overshoot/failure. Sampling is
detection, not a hard CUDA quota. Do not change the guard or select another
backend within this run after seeing an outcome.

Save and fsync the candidate before verification/cleanup. Independently verify
the saved receipt using the original immutable CPU verifier, exact successful
claim/image/J/JOIN, development mode disabled and no unresolved assumptions.
Preserve the existing crypto/control and field-mutation negatives. A returned
or cached image, executor-only trace or development receipt is not success.

Record startup, API response, independent verification, worker cleanup and total
wall time separately. Actor's missing paging/reserved statistics remain
unavailable. Compare with IPC18 under its actual caps/concurrent workload;
this single diagnostic cannot establish causal speedup, p95, CPU-wallet or
end-to-end payment qualification. The60s product diagnostic remains unchanged
and is not an operational timeout. Keep a slower/failed run. No compression,
funding, external service, installation or broadcast is part of this experiment.
