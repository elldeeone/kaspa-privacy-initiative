# Two-owner aggregate: 29 actual constraint checks matched

**Seven accepts, 22 rejects, zero generation-only results.** One selected run02
completed all 29 actual R1CS checks. Every witness's 2,091 public fields matched
its selected input. This is synthetic authorization/correspondence evidence,
not a Groth16 proof or a privacy qualification.

Two existing owner-signed records satisfied one aggregate relation with
independently ordered public NF and whole-output-tuple arrays. NF reversal,
output interleaving/reversal and swapping private owner component slots
preserved validity. The separately authorized owner-0 alternative also passed.
No owner process, signing key or signature was regenerated.

Actual constraint checks rejected duplicate NFs/tuples, invalid bijections,
non-Boolean field-linear selectors, swapped signatures, partial-tuple movement,
changed CF bytes, unauthorized fees/redistribution, context/anchor changes,
out-of-interval height and byte/fee range mutations. Each rejection used a
complete candidate witness checked against the ordinary R1CS; no parser or
generator rejection counted as a passing negative. Several checks overlap;
there is no independently signed duplicate-CM fixture and no isolated
CM-distinctness coverage claim.

**Identical same-state replay accepted**, exactly as P07 required. This relation
has no historical spent-state database or cancellation rule. Its uint64 values
and 65-bit aggregate fee establish toy integer conservation, not CV algebra or
native KAS accounting. CV64, CF/CFH and proof bytes are authorization-bound but
their cryptographic/output validity remains unimplemented.

Compiled public-symbol and R1CS-header audits confirmed **2,091 public inputs,
zero public outputs and no owner-input/child-output aliases into public wires**.
The circuit has 1,163,533 constraints and 1,146,261 wires. Ordinary and official
assertion-disabled C++ R1CS files remained byte-identical before and after the
checks: 258,572,020 bytes, SHA256
`aa806976b76b1417613d56010f41710ba735203e18cad7c04c0a15e1503131d6`.

[Result](run-02-public/RESULT.json):
`49eaeb223eb6ed128af582e4bacd49a13f198ef439ddb3b6d0cf6e47b6d90d7c`.
[Run record](run-02-public/RUN-RECORD.json):
`4aa762926de31fbcf10bf87bed04620ba92bc6934cd7514c1a6154e7be8b0cfa`.
[Exact reuse record](run-02-public/COPY-RECORD.json):
`5cadd55ff67771592365f24d4b0fe7d71dbd660c7ae1905cad90bce751dde484`.
[Evidence closure](run-02-public/EVIDENCE-CLOSURE-01.json) pins the small public
copies and retained primary positive witnesses. No large build, tool, R1CS,
symbol, binary, data, raw log or witness bytes entered the repository. Those
primary artifacts remain in volatile tmpfs.

The [failed run01](OUTCOME-01.md) remains unchanged. It stopped before any
witness/check because a 645-MB symbol file exceeded Node's single-string limit.
The prospective line reader preserved every per-row condition and passed
23 small parser controls. A fresh run02 received 37 exclusive, guarded,
full-byte-compared copies of the exact same cases/handoff/compiled files.
There was no case regeneration, recompilation, rekey or expectation change.
One orchestration typo before copying started is separately retained; it
created no run02 artifact and altered no selected source.

The check phase took 581.05 seconds wall time and 611.29 CPU seconds. Recorded
executable phases, including the first stopped attempt and exact reuse, total
979.14 CPU seconds. Highest GNUtime process RSS was about 5.16 GiB during
compilation; combined retained scratch was 2,656,028,899 bytes. These remained
inside the selected envelope. Process-tree sampling follows children of every
thread; summed RSS can double-count shared pages and miss short-lived peaks.
GNUtime completed-child CPU and individual-process RSS are separate metrics,
not a hard physical-memory sandbox.

The plaintext constructor and deliberately public owner-coded fixture reveal
the complete map. Private permutation wires do **not** demonstrate anonymity,
coordinator-map hiding or malicious-MPC security. The 2,091-field debug ABI is
not a native verification/fee design. Current native 1NF→2CM grouping, profile,
note/KDF/Spend/Exit rules and actual financial runtime are unchanged. No setup,
PK, Groth16 proof, native transaction/state, independent recovery or actual
Original operation occurred. Active retry, data availability and the frozen
2% fee failure remain unresolved.
