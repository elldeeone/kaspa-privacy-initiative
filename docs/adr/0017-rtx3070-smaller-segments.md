# ADR-0017: Smaller segments for the local RTX 3070

Status: Accepted for the owner-authorized local computation experiment,
2026-10-18. No mainnet, funds, transaction, rental or production suite change.

## Decision and evidence

The owner asks to make maximum practical use of the existing RTX 3070. The
unchanged po2=20 segment fails CUDA memory allocation, while recursion succeeds
in [ADR-0016](0016-local-cuda-qualification.md). That historical failure remains.
The pinned RISC Zero 3.0.3 `ExecutorEnvBuilder::segment_limit_po2` explicitly
supports lower memory through smaller segments, approximately linear in size.

Create a separate experiment using po2=19 and po2=18, sequential GPU proof work,
and the same public classifier program, input and independently pinned journal.
Re-execute to export new segments; never relabel old traces or expect different
segmentations to have identical intermediate claims. Compare two adjacent
full-sized segments near the same 24M-user-cycle point, their lifts and join.
Measure whole phase/API costs and GPU process utilization, VRAM and host memory.
Choose the faster measured verified configuration for a complete succinct
classifier proof. If neither fits, po2=17 is an explicitly allowed fallback.

Keep the pinned CUDA prover binary/source/features, ordinary BN254 verification,
wallet fixtures, public ordering input, program image and complete journal.
Development receipts, supplied assumptions, skipped checks and CPU proving
fallback cannot qualify GPU work. The independent original CPU verifier must
check any full receipt, expected image/journal, successful exit, empty
assumptions, wrong-image rejection and five journal mutations. Also mutate a
seal. A partial receipt or execution report is never a complete proof.

Use an experiment-only host adapter built in the same pinned upstream r0vm
package/lockfile; record its source/binary hashes. No original host/guest is
edited. The adapter exposes the already-locked `serde_json` dependency directly
in the upstream r0vm manifest/lock dependency list; retain that exact diff, with
no changed dependency versions/checksums or cryptographic source. The SDK session
cycle cap is a generous 192M operational guard; it does
not change the guest, proof relation or accepted output. Proof groups have a
generous two-hour diagnostic deadline and 20GiB sampled host-RSS threshold on
the 24GiB machine. Preserve any failed result and candidate receipt. No power,
clock, driver or firmware settings are changed; no parallel GPU provers compete
for the 8GB device. CPU thread/initialization overhead is measured, not hidden.

This changes execution segmentation, not a privacy construction, native
settlement or invariant. It may prove the full **proxy** classifier; it cannot
close RFC-0003 P1/P2, real-private-relation R13 or independent native R16.

Sources: [pinned segment sizing](https://github.com/risc0/risc0/blob/14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6/risc0/zkvm/src/host/client/env.rs#L178-L193),
[official local proving guidance](https://dev.risczero.com/api/generating-proofs/local-proving).
