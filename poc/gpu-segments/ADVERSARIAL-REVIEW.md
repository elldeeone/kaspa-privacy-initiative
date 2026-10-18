# Adversarial self-review of the smaller-segment experiment

This is source/self-review of a local computation experiment, not an independent
cryptographic audit. It reuses established SDK segmentation/proving; no private
payment construction, native script, reserve or wallet key changes.

| Question | Enforcement and limit |
| --- | --- |
| Could a faster setting change accepted monetary behavior? | Program image, public input and complete journal hashes are independently fixed. Segmentation changes execution boundaries only. The full receipt must bind successful completion of that exact image and journal. This is still the historical synthetic predicate, not real private-money enforcement. |
| Could partial proofs, a host verdict or fake receipt become success? | Partial benchmarks are labelled partial. Full success requires an actual succinct receipt, disabled development mode, no unresolved assumptions, seal/image/journal mutation rejection and separate original CPU verification. A candidate is saved before checking but cannot pass on existence alone. |
| Could the CPU do the work while results claim GPU acceleration? | Reuse the unchanged CUDA-only prover binary/source/build identity, explicit IPC selection, matching process-group GPU memory/utilization and positive own-PID SM evidence. Missing telemetry is inconclusive, never proof of acceleration. Full-run telemetry proves GPU participation, not per-kernel timing or exclusive causation of a speedup. |
| Could inflation, double spending or unauthorized native release occur? | No funds, wallets or native IO exist in this adapter. It cannot establish the full native-KAS invariants either. Real-private R13 and native R16 remain open. |
| Could a changed segmentation reuse old intermediate claims? | Each configuration exports fresh traces and records their hashes, segment counts and selected span. Different segmentations have different intermediate claims. Only the complete expected program/journal is invariant. The original po2=20 OOM record stays unchanged. |
| What if a dependency disappears or the GPU runs out of memory? | Retain source/build failures, progress, logs and any candidate receipts. No security check or expected journal changes. An alternative declared segmentation uses fresh output; resource/IPC failure is not valid rejection or a completed proof. |
| Could proof output expose wallet information? | Inputs are already-public synthetic classifier fixtures. No spending/viewing keys, private note witness, provider credentials or mainnet data are read or forwarded. Do not infer witness privacy for a later hosted prover. |
| What happens on a reorg or stale native state? | This experiment uses fixed synthetic ordered input. No live canonical state or payout is asserted; a full proxy receipt does not establish native freshness or recoverability. |
| Could a repeated command overwrite evidence? | Save-new output files/directories. Second-pass review found the generic exception handler could write a failure marker into an existing directory. The final runner rejects an existing output before preflight and avoids that handler on a mkdir race. A sentinel-file control confirms no existing evidence changes. The exact earlier executed runner is retained separately. |
| What hidden trust remains? | The pinned program/SDK/verifier, trusted local source/build environment and original public fixture provenance. The unsigned benchmark export manifest is a trusted local diagnostic, not a consensus checkpoint. Full independent cryptographic verification is the acceptance boundary. GPU counters and short two-segment selection estimates are sampled/heuristic; no global-optimality or universal-speedup claim follows. |

Negative preflight controls reject an altered independently expected journal and
development mode before output creation/execution. Actual benchmark calls reject
seal/claim mutations; actual full-receipt controls and independent verification
must be recorded with the final measured result before claiming completion.
