# The RTX 3070 proves the complete proxy classifier

**The full succinct classifier receipt completed and passed independent CPU
verification in 7m36s.** Half-sized segments fit the existing 8GB GPU. No new
hardware, rental, funds or native transaction was needed.

This follows [ADR-0017](../../docs/adr/0017-rtx3070-smaller-segments.md) and the
[reproduction guide](README.md). The earlier
[original-segment memory failure](../remote-cuda/LOCAL-RESULTS.md) remains a
valid negative result; its workload/evidence was not rewritten.

## What changed

Use the supported segment-size setting: po2=19 instead of po2=20, with po2=18
also benchmarked. Re-execute to export fresh traces. Keep exactly the original
program, input, wallet fixtures, BN254 verification and complete journal:

- Image: `397bcdca688462b9573a4b55e3516e1a2511140512c53337eb54da0849a93716`.
- Input SHA-256: `56e5010fd63dfd974d4f166a58c24bd4e0ae6bb38d437b9d624a8b8b850f5c90`.
- Journal SHA-256: `625f5c4cc784d3736663b796174e5342cd9ab95ee62507f6680a128f95d99ce2`.

The unchanged CUDA prover has SHA-256
`3f22b68b6d32904fe766e14e62ce011febdc946dd98d015747f40ce5fb5fffc7`:
RISC Zero 3.0.3, pinned source, sm86, disabled development mode. The experiment
host adapter has SHA-256
`c24e24a73d8958a708776d27e0f0cc583dc5ea85af319b55e0597e0a2c84b06f`.
Its build adds only a direct reference to the already-locked JSON dependency;
the exact manifest/lock-list diff is retained. No cryptographic source/version,
native script or original host executable changes.

## Fit and selection measurements

Each row proves two adjacent full-sized segments near 24M user cycles, lifts
both and joins them. All ten partial receipts across the two configurations
pass actual seal/claim mutation checks. Each benchmark has positive own-PID
GPU SM evidence. Different segmentations have different intermediate claims.

| Configuration | Exported segments for whole session | Mean segment API s | Mean lift API s | Join API s | Pair benchmark wall s | Peak sampled prover VRAM MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| po2=19, half-sized | 256 | 1.504 | 0.554 | 0.629 | 5.143 | 5750 |
| po2=18, quarter-sized | 587 | 0.904 | 0.557 | 0.612 | 3.806 | 3828 |

The smaller individual quarter-sized segment is faster but requires more than
twice as many segments/lifts/joins. The two-segment selection heuristic predicts
687s for po2=19 versus 1216s for po2=18, so the complete attempt uses po2=19.
Those figures are **estimates**, not measured full-session costs. Only po2=19
gets a complete run here; no claim of globally optimal settings or a measured
po2=18 full-run comparison follows.

## Actual complete proof

The official complete succinct-prover API executes the unchanged classifier,
proves all segments and performs the required recursive compression. The
result is a complete receipt, not a join of two middle segments.

| Measurement | Actual result |
| --- | --- |
| Proof API, including execution | 455.920s |
| Whole proof phase | 456.270s, about 7m36s |
| Separate original CPU verification phase | 0.218s |
| User cycles / total trace cycles | 117,473,222 / 134,217,728 |
| Proven segments | 256 |
| Receipt bytes | 223,560 |
| Sampled peak prover VRAM | 6096MiB, about 5.95GiB |
| Sampled peak summed host RSS | 671,064,064 bytes, about 0.625GiB |
| GPU device utilization with matching prover PID | Mean 80.4%, maximum 100%; 1808 samples |
| Positive own-process SM activity | Observed |

The GPU is the same RTX 3070, driver 595.99.02. Proof affinity is CPUs 0–3 and
four compute threads. Host CPU usage is about 456s over the 456s proof phase;
extra GPU jobs would compete for the 8GB rather than provide free memory.
No clock, voltage, power, driver or firmware setting was changed.

An additional hardware interval starts 53s after launch, with 767 samples. It
observes a maximum core temperature of 61C and 168.21W power. Some power/thermal
clock-reason flags appear, but post-run counters report zero; these samples do
not diagnose a thermal/power bottleneck. They are not exact full-run maxima.
The experiment-local CUDA cache is shared by benchmarks and the full proof;
there is no clean-machine cold-start claim. Build time is separate: the
corrected adapter compiles in 55.89s; the initial compile errors are retained.

## Acceptance and independent recheck

Receipt SHA-256:
`7c8d7a462c9f839c11650c5bfe3561dbd9b1c6c151343d516b3b261e2cab10a1`.
It proves successful completion of the independently expected image, exact
167-byte journal and empty assumptions with development mode false. Journal
outcomes are `[0,3,0]`: accept, cryptographically reject, accept. Synthetic
balances are `[600000000,600000000,500000000]` from initial `1000000000`;
the rejected operation does not change the balance.

The adapter cryptographically rejects a changed seal, wrong image and five
altered journal fields. The unchanged original CPU host independently checks
the saved receipt, expected image/journal, wrong-image and five journal mutation
controls. A fresh extraction of the retained archive repeats that verification
again, checking original verifier/source/input identities and all member hashes.

Negative controls also reject altered expected-journal bytes and development
mode before execution. The final runner rejects an existing output directory
without changing its sentinel evidence. The exact earlier executed runner and
the later exception-handler preservation fix are distinguished in the archive.
See the [adversarial self-review](ADVERSARIAL-REVIEW.md).

## Evidence and limits

- [Manifest and measurements](evidence/rtx3070-small-segments-2026-10-18.json).
- [Public archive](evidence/rtx3070-small-segments-2026-10-18.tar.gz): 76 files,
  3,111,671 bytes; SHA-256
  `a5c4490663915d3f880fe789f06adfe09805abb223aae4534509773852df14d9`.
- [Fresh archive/CPU re-verification](evidence/retained-verification-2026-10-18.json).

The archive includes real partial/full receipts, selected fresh traces, complete
session hash lists, input expectations, sampled process/GPU/hardware logs,
build failures/success, dependency diff and exact executed source. Unselected
bulk exports, CUDA caches and compiled binaries are omitted. Original public
fixtures/verifier are available through the pinned earlier public package.

This closes the missing **complete proxy-classifier receipt** for this exact
workload. The earlier CPU timeout remains historical evidence, not a controlled
GPU-only speed comparison. The old po2=20 five-phase and remote L40S experiments
remain unqualified. This does not implement note ownership/nullifiers/delivery,
prove financial privacy, authenticate live L1 input, provide native payouts or
close full-private-relation R13/R16. Those follow RFC-0003 P1–P5.
