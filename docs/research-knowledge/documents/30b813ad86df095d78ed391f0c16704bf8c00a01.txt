# Run 02: bounded authorization checks matched

**49 actual R1CS checks: 5 accepted, 44 rejected, zero generation-only results.**
The one approved run matched every frozen expectation. This is **NON-PRIVATE
authorization-predicate evidence**, not a Groth16, native-KAS or privacy proof.

Both owners' unchanged records and their separately signed alternatives
remained valid with the owners stopped. No owner, signing key or signature
was regenerated: run 02 reused public handoff
`284aef4352a57132a289dc81a8067290a0b15e6dc66e8735c5da71e73ae7f218`.
The SHA companion's four padding vectors and every accepted full-tuple digest
byte, LE128 limb and message matched Node's independent computation.

Actual R1CS checks rejected altered payment/value/NF/fee/context/anchor/nonce,
every tested complete-tuple component and order mutation, byte=256, wrong or
missing signatures, replacement signing/nullifying keys against the original
input leaf, wrong leaf/sibling and signed-height/conservation cases, malformed/subgroup/encoding
cases, out-of-range S and both stale derived digest limbs. Overlapping
rejections do not establish isolated coverage or universal cryptographic
correctness. This was one finite set with two synthetic owners.

The harness correction changed **only witness generation** to the exact
official C++ backend, `--sanity_check 0 --no_asm`, with the standard Makefile
and no `NDEBUG`, generated-code patch, ignored callback or partial-witness
fallback. This permits candidate assignments for invalid inputs to reach the
checker. The original, copied and C++-emitted R1CS were byte-for-byte identical:
128,534,220 bytes, SHA256
`ec0a3bedc3a64f8ae25096743e24f2be07ac2a623cea1b77114067483d12783d`.
The same selected serial checker remained the acceptance authority. The
[failed run 01](OUTCOME-01.md) is preserved unchanged, including its first
negative's generator assertion; it was not reclassified as a 49-row success.

[Result](run-02-public/RESULT.json):
`55446254fa17e454cd34406cd5e035e251486193eabfe8fde9afeff14dfd6eb9`.
[Run record](run-02-public/RUN-RECORD.json):
`fcc8015bc4db255c6763d232772df2854aae4e67c26ea3f412e61dd8a089611a`.
[Evidence closure](run-02-public/EVIDENCE-CLOSURE-01.json) pins the retained
primary artifacts. All logs, source/build objects, executable/data and positive
witnesses remain in dedicated tmpfs. Only selected small public JSON copies
entered the repo; the tools symlink, logs, builds and witnesses were excluded.
Tmpfs retention is volatile. Expected rejected witnesses were deleted exactly
as frozen; result rows remain complete.

C++ generation, build and check consumed 437.04 CPU seconds combined, below
30 minutes. Highest reported process RSS was 2,907,852 KiB during C++ source
generation, below 4 GiB; sampled make and check process-tree peaks were
1,490,232 and 1,195,788 KiB. These are measured observations with sampled
child accounting, not a hard whole-machine sandbox or native fee estimate.

The plaintext prover still knows the entire owner/NF/output/value map. The
public fixture recipe also encodes owner/output-slot information in fictional
tuple bytes, so even private partition wires would not turn this fixture into
a mapping-privacy experiment. Full encryption/output/receipt validity, the
current note/profile/KDF and native acceptance, spent-state/replay handling,
recovery, malicious MPC and hidden-partition proving remain unbuilt. No
setup/proving key/Groth16 proof, funds/network submission or actual Original
operation occurred. Current 2% fee and active-retry failures, the 25-file model
closure and all existing financial source/runtime remain unchanged.
