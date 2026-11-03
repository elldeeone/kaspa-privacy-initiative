# ADR-0038: Qualify cost and proving limits before expanding the payment design

**Status:** Accepted for bounded offline experiments; no production architecture
or requirements change. **Date:** 2026-10-22 UTC. DO_NOT_FUND.

## Problem and evidence

The combined research baseline is `0fcd409`, preserving the independent
`85e3939` and `68d7b03` experiments. Their native/proof positives do not establish
a complete payment lifecycle. The unchanged [RFC-0012](../rfc/0012-useful-privacy-requirements.md)
also has two known failures: the declared price prior exceeds its absolute
amount cap, and a single Groth16 verification at the 500-sompi scenario costs
more than the supported minimum claim. Larger batches alone repair neither.

Existing B2 proving took about 303 seconds on this GPU. Its actual fixed fee is
40M sompi per payment, despite a lower minimum native mass quote. Increasing
arity before understanding latency and per-user cost would answer a weaker
question. The [boundary plan](../../research/next-session/BOUNDARY-TEST-PLAN.md)
also identifies an existing overflow control whose stale commitment can reject
before the arithmetic constraint under test.

## Decision

Run three independent, prospectively scoped experiments:

1. **Ordinary native budget:** retain the existing S7 factory budget1700 and all
   frozen transactions. In a separate checker, qualify prospective ordinary1600
   versus1700 using the same genuine initial proofs, exact native Full validation
   and typed negatives. Independently rederive the whole ordinary source bound;
   a small positive fixture is insufficient. Paired remains1700. Re-sign only
   legitimate deterministic DO_NOT_FUND funding inputs when a native transaction
   field change requires it. Keep all integer-sompi authorizations, fees, proof,
   nullifier, successor, owner and payout checks. Do not implement owner exits,
   public replay or the parked workflow. Report100/200/500 quotes and actual fees.
2. **Existing B2 proof latency:** retain the exact selected guest, input, image,
   journal and completed claim. Inspect the pinned SDK's supported backend and
   segmentation settings, then freeze one justified performance comparison before
   execution. No new circuit, batch workload, statement or setup is selected.
   Independently verify any receipt with development mode disabled, no unresolved
   assumptions and exact identities. A faster GPU service does not qualify the
   CPU-only wallet requirement. Keep slower/failed outcomes. Do not run an
   arbitrary larger aggregate merely to consume resources.
3. **Arithmetic and witness boundaries:** execute the frozen self-consistent
   full-circuit controls, rebuilding commitments/anchors/nullifiers as required
   so an earlier mismatch cannot substitute for the tested amount bound. Record
   synthesis failure separately from unsatisfied constraints and a passing
   relation. This is constraint testing, not proof generation, cryptographic
   correctness or independent-owner recovery.

Reuse the existing v6 circuit, established Groth16 implementation, RISC Zero
SDK3.0.3, official native validator and pinned source bounds. The current-source
and mature-protocol comparison is a separate research input; do not silently
upgrade the measured native baseline. A new subsystem or changed value relation
requires its own research/design decision.

## Evidence and assumptions

Each lane freezes its exact source, inputs, commands and expected outcomes before
execution, writes fresh outputs, and retains negative results. Historical manifests
and adopted thresholds remain unchanged. Use useful parallel CPU work and one GPU
job at a time, with private targets, task-owned processes and no per-job swap.
Resource safeguards must allow the experiment to finish; the60s/4GiB product
targets score results and are not operational abort timers. No new rental,
installation, mainnet use, real funds or broadcast is authorized by this ADR.

Adversarial second-pass review covers inflation, duplicate spends, unauthorized
reserve release, stale/cross-domain state, privacy disclosure, missing dependencies
and hidden trust. A declared budget must not bypass proof or mass checks. Changed
native IDs and funding signatures must follow actual serialization. A backend
comparison must not substitute a cached, development or unresolved receipt.

No result from these experiments closes R2/R3/R4/R6/R7, the blocked owner workflow,
accepted lineage or the complete minimum deposit-to-confirmed-payout milestone.
Record measured improvements and remaining failures separately before deciding
whether a further implementation is justified.
