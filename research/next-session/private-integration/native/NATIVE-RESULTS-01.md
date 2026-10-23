# Actual new-union native results

One reviewed63-case run used freeze
`aea1f6eae052ac98ed690f7fb700130a6bc48e6655030add46286b6979e0c526`.
Results: **7 positives accepted and56 negatives rejected by official Full**.
The exact frozen per-input typed predictions matched **60/63**. All isolation
checks passed; every actual input engine was inspected. The three prediction
failures remain failures in the original machine result, without a rerun.

The actual wrong-transcript control retained the genuine valid-curve proof/VK,
changed ciphertext and recomputed Auth's cipher hash. Native public/context
checks passed and the official precompile rejected with exact
`ZkIntegrity("Groth16 verification failed")`. Current authenticated spent-NF
equality/path controls reject in both cross-branch directions before Groth16 or
signature verification. These initial equality cases explicitly reuse a proof
that is not claimed valid for altered Auth; separate genuinely proved fork
contexts are the planned stronger follow-up.

Admission's genuinely signed NONE2 control failed the pool's exact-ALL guard
while the funding input accepted that real signature. Corrupt/wrong-key funding
signatures passed pool input0's public checks but failed funding input1 and Full.
Positive same-key change, later Gzero admission, reversed recipient exit order
and conditional terminal consumption all accepted. Those alternative supplied
funding contexts are semantic controls and do not enter the primary lifecycle
fee denominator or claim affordable fee fixed points.

The constructive capacity context has43,691 CM slots,65,536 existing NF leaves
and one60M unspent spine. Its actual terminal exit appended at index65,536,
used174,595 script units and passed Full. Fee24,816,000 at500 sompi/mass left
payout35,184,000. Official dimensions: compute45,176; transient99,264;
storage11,756; complete mining mass49,632. The corrupted17th-level append-path
companion rejected with `VerifyError`. The supplied history derives every CM,
real/dummy NF and physical index; no historical proof, accepted backing, relay
affordability of its one-sompi historical fees, complete encrypted archive or
privacy qualification is asserted.

## Frozen signature-error prediction erratum

The following original predictions expected `NullFail` but actually returned
`EvalFalse`, with Full `SignatureInvalid(EvalFalse)`:

- `admit-corrupt-funding-signature`: pool ACCEPT, funding `EvalFalse`.
- `admit-wrong-funding-key`: pool ACCEPT, funding `EvalFalse`.
- `reveal-wrong-signer`: reveal input `EvalFalse`.

The producer and independent review misread the error behavior. Official native
commit `01b532e8…`, `crypto/txscript/src/opcodes/mod.rs:827`, `OpCheckSig`, pushes
the boolean signature result. `crypto/txscript/src/lib.rs:747` rejects a false
final stack result with `EvalFalse`. The `NullFail` at `lib.rs:839` belongs to the
separate multisig implementation. No covenant or dependency changed; the
original expected table and60/63 typed score remain immutable. This erratum is
source interpretation, not a retrospectively corrected test pass.

## Evidence and limits

Machine verdicts and all per-input units are in
[`control-runtime-01/evaluation/RESULTS.json`](control-runtime-01/evaluation/RESULTS.json).
All63 raw cases, source/binary and expected outcomes were frozen before native
execution. Runtime used0.349s wall,0.354CPU-seconds,29.1MiB cgroup peak, swap0;
the systemd unit is inactive/dead with MainPID0. No network, new setup/proof,
funding or broadcast occurred in this lane.

The historical producer helper3f155 is retained byte-for-byte under
`historical-producer-sources/assemble-3f155480.py`; current7b4f is also retained.
Capacity preparation metadata names intermediate helper5fd9. Its exact retained
source is currently unavailable, and the helper changed during the preparation
period. This is a preparation-source provenance limitation; no exact5fd9 source
reproduction is claimed. The frozen raw signed bodies, full physical-history
records and actual native ELF remain closed and independently reviewable. This
does not affect the measured supplied-context native verdict and does not turn
the capacity history into accepted lineage.

The original Source04 ELF's former mutable build path is resolved by the
byte-identical immutable archive in [`ELF-ARCHIVE-MAP.json`](ELF-ARCHIVE-MAP.json).
Source05 adds only unsigned control normalization; its native library and
executing policy match Source04. All claims remain synthetic/offline research;
passing these checks is not cryptographic correctness, financial privacy,
independent network availability or production security.
