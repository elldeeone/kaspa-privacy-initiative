> Imported documentation snapshot. [Canonical status and ownership](../../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# Flat two-SPEND model prerequisite — completed

**Both narrow gates pass, conditionally.** Grouping is unnecessary for reconstructing a recipient's witness in the specified flat-data model, and two different valid payment assignments share exactly the same projected public bytes. This establishes neither useful privacy nor native/proof feasibility.

The final deterministic run completed **34 checks in 0.0248 seconds**, with **23.23 MiB peak RSS**, using Python 3.14.6 on the Mac. Nothing was installed. Forge access was source-only; no private/frozen evaluation data was accessed.

| Check | Result |
|---|---|
| Public projection | Four sorted commitment/ciphertext pairs, four independently sorted NFs, exact aggregate fee, prior/successor state summaries. No individual auth, proof, owner or grouping fields. |
| Distinct assignments | A/B each spend two notes totaling 10.4 tKAS, each paying 0.4 in fees. Fixed outputs are R:3, A-change:7, S:3, B-change:7. Exchanging which sender pays R/S preserves every output opening and all public bytes, while each sender keeps its own change. |
| Bounded enumeration | Six allocations checked; four satisfy the protocol model; **two** also keep each sender's own change. No amount/rate/privacy distribution is inferred. |
| Recipient recovery | R discovers its fixed note at position 8 using only its key-bound ideal decryption capability and public history. Its individual exit payout is 260,000,000 sompi. Commitment membership, historical-root membership and both sequential indexed-NF insertion paths verify. |
| Later activity | A second batch uses one-real-input/dummy-NF operations. R's position and historical private authorization remain unchanged; current public exit paths rebuild. The unrelated prior holder also reconstructs its witness. |
| Rejection controls | Wrong/replayed sequence, append order, missing data, stale/wrong state binding, duplicate/zero/spent NFs, duplicate CMs, input reuse, wrong owner/anchor, inflating outputs, fee changes, noncanonical numbers and misbound recipient delivery reject at their specified layer. |

The following **failed variants and limits are retained as findings**, not repaired away:

- Adding per-operation authorization digests reduces compatible assignments from four to one. An ideal interface that separately verifies each inner proof against candidate statements does the same. This is a finite-fixture exposure result; actual Groth16 bytes were not generated or tested.
- A participant who knows one complete operation can subtract it and recover the other group: one compatible assignment remains. The collector also knows submission grouping. This two-member example offers no protection from those views.
- Public replay accepts a deliberately inflated but internally consistent public projection if the private validity check is bypassed. The private reference checker rejects it. **A real sound proof of the hidden transitions is essential; roots and native reserve subtraction alone are insufficient.**
- Undeliverable recipient ciphertext yields no recovered note. Missing committed data cannot be repaired using an unavailable private partition.

## What the check assumes

[SPEC.md](SPEC.md) was written before execution and defines the public projection, hidden assignments, client API, exact criteria and pinned source mapping. `check.py` implements SHA-256 trees and positioned HMAC nullifiers at tiny depth 5. It uses an **ideal key-restricted lookup for sealed-box decryption** and a private reference validator in place of cryptographic proofs. These are explicit assumptions, not implemented security mechanisms. Client independence is an input/API boundary, not separate-process or independently implemented verification. All keys/openings are deterministic public test fixtures. Real outer-proof bytes are absent: equality of this projection does not establish indistinguishability of actual receipts.

The checkpoint and accepted headers are assumed authentic and complete. The proposed history rule records sorted flat-prefix roots after each pair of appended commitments, without recording operation boundaries. Current v6 does not accept these four-output batch transitions; its covenant and wallet cannot be reused unchanged. Native serialization, setup/soundness, actual ciphertext handling, reorgs, pruning, real proof performance, fees and network acceptance remain untested. Equal-sized payments were deliberately chosen for this existence witness; distinctive values or extra knowledge can remove its ambiguity.

The first run passed 32 controls. Source review then tightened header equality to canonical JSON bytes, preventing Python boolean/float equality from satisfying integer headers, and added the private aggregate amount bound. The final run passed 34 controls. [RESULT-initial.json](archive/RESULT-initial.json) retains the earlier measurement; [RESULT.json](RESULT.json) pins the final source and unchanged spec.

## Next indispensable experiment

Only if the removed grouping/boundary is relevant to the observed leakage, test a **new immutable offline candidate** that actually verifies two independently generated user proofs inside one supported outer proof, publishes the complete flat state/delivery data, and never publishes separately testable inner proofs or authorization digests. Using real sealed-box ciphertexts, a recipient must reconstruct state and produce a direct individual exit accepted by the native validator with the collector stopped. Mutated output/fee, omitted delivery, duplicate NF and stale-state cases must reject at the applicable proof, replay or recipient-acceptance boundary; a ciphertext hash alone does not establish valid delivery. Measure complete proof latency, actual native bytes/mass and fees. The existing v6 pool and proofs do not migrate.

That genuine proof/native experiment is necessary to validate the assumptions that this toy intentionally leaves open. No further toy expansion is needed for the present gate.
