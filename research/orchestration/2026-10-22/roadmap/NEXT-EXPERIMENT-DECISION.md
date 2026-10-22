# Next experiment decision

**Decision: retain v6 as the research platform. No worthwhile independent heavy job is ready from the reviewed evidence.** Free Forge capacity is not a reason to repeat the failed observer benchmark, settled controls or arithmetic reconstruction. This note is prioritization only, not an execution release or an architecture ADR.

## One consequential open decision

**Should the project pursue a new native-KAS pool that hides per-operation grouping, rather than continue with the present v6 settlement?** Today the answer is **not yet**: neither a demonstrated native privacy benefit from that change nor a concrete compatible outer verifier has been established. This does not select vProgs or rule it out.

The [completed price result](../statistical/FROZEN-RESULT-INTERPRETATION.md) bounds one heuristic under a synthetic generator. It supplies no causal attribution to operation grouping and does not revive the failed withdrawal policy. The [batching feasibility review](../architecture/BATCHING-NATIVE-FEASIBILITY-REVIEW.md) establishes the concrete engineering barrier: current bundles expose their own two-nullifier/two-output grouping; current proofs, covenant layout and fixed VK cannot accept the toy batch. A batch would need a newly founded pool, setup and settlement contract. The existing reserve cannot be switched through an unimplemented upgrade path.

The toy's ideal validity/delivery assumptions remain unimplemented. A collector receiving existing public bundles need not receive wallet spending secrets, but still sees grouping and submission provenance. A joint circuit populated with current private witnesses would introduce a different trust boundary. These are material constraints, not implementation details that more toy sampling can settle.

## Candidate experiment, conditional and not ready

The existing review identifies the smallest useful compatibility experiment. Retain that gate instead of inventing another workload.

| Item | Required specification before any execution |
| --- | --- |
| Hypothesis | One named, established outer-verification implementation can verify two unchanged public v6 bundles, conceal their partition from its public statement, bind a declared aggregate, and produce a receipt accepted by the pinned Kaspa proof interface without wallet keys or note openings. |
| Public inputs | Exactly two already-public development/rehearsal v6 bundles, their authorizations and ciphertexts, fixed inner VK, pool/domain binding and the exact native verifier dependency. Select and hash the public files explicitly; no evaluation archives, participant records, private truth or recovery wrappers. |
| Minimum observations | One valid pair is CPU-verified and its final receipt is accepted by the pinned native proof interface. Separately altering the proof, authorization or ciphertext binding must fail the corresponding relation. Inspect the complete public statement and output for exposed inner bundles, individually testable proofs, hidden grouping identifiers or omitted flattened fields. Record setup/VK identity and collector knowledge. |
| Prerequisites | A concrete upstream implementation and exact source/dependency pins; documented inner verification relation; final receipt/tag and public-input mapping; setup assumptions; a buildable existing route and measured or defensible resource estimate. None is supplied by the toy, the observer CUDA kernel or the current arkworks prover. |
| Exclusive scope | A future owner gets one isolated public compatibility fixture and new output directory. No wallet changes, batch covenant, reserve migration, deployment, privacy attack or exit/recovery execution. Keep both parked jobs parked. |
| Resource budget | This prioritization pass: zero builds, workers, proofs or GPU use. For the conditional experiment: no reservation or runtime budget approved. Backend selection must precede a numeric CPU/RAM/time proposal; a cost inferred from the toy would be unsupported. Default to one sequential public fixture and no GPU unless the selected existing backend demonstrably requires one. |
| Stop rule | Stop before execution while any prerequisite is missing. Later, under a separately released finite budget, stop on the first unexpected validity/binding outcome, unsupported native receipt, need for spending secrets, changed inner setup, or budget exhaustion. Preserve failure; do not substitute a toy/new relation or tune it into success. |
| Interpretation | Passing would establish one proof-composition/native-receipt compatibility boundary. It would not establish beneficial privacy, indistinguishability of actual transactions, correct recipient delivery, spentness enforcement, an accepted batch pool or independent exits. A negative result rules out that exact route, not batching in general. |

A positive compatibility result still leaves the settlement/state contract, delivery and privacy rationale unresolved. No privileged withdrawal route, operator custody, new token or weakened backing/conservation rule is an acceptable way around those obligations. Independent exits must remain possible with user-held secrets, available public data and ordinary proving/fee resources.

## Why the other available proposals do not outrank this decision

The [singleton-field review](../architecture/PUBLIC-FIELD-SPEC-REVIEW.md) already establishes redundancy by conservation; another reconstruction framework would mostly test its own implementation. The [native mapping](../native/public-observation/README.md) has a completed structural parser and deliberately false proof/VM/transaction-ID/public-witness-recomputation flags. Its proposed retained-trace replay could close a useful lightweight mechanics gap, but the reviewed documents do not establish an already-built pinned binary, complete selected funding ancestry or an interface that regenerates witnesses from public history. Validating supplied witness bytes alone would not establish reconstruction. Stop if those prerequisites are absent; do not compile or broaden the task. Such a check cannot establish grouping-related privacy benefit, real timing/owner knowledge or current-wallet partial-payout equivalence, so it is not a new heavy lane.

Native guard, relation, continuation, tree-capacity and pending admission-adapter controls concern different correctness obligations. Consume their owner reports; do not duplicate them here. Current-runtime handoffs not yet committed to the reviewed index were not independently inspected by this pass. The coordinator's newer GPU failure and pending adapter status remain scheduling context, not newly attested results in this note.

## Handoff and source identity

Next action is a **single source-selection gate** owned by the existing batching lane: identify one existing supported outer-verifier route and its full binding/setup/receipt contract, or explicitly retain deferral. Cap that future source pass at 30 minutes and one concrete route; no installation, build, benchmark or new cryptographic subsystem. This note does not authorize it. Missing evidence after that cap remains an unresolved/deferred route, not an architecture failure or a privacy pass.

This document was written on Forge. Evidence-lineage is the sole staging/commit owner for this documentation worktree. Only this exclusive note is authored by this pass; other files and the Git index are unchanged. No external posting, funds, mainnet, paid infrastructure or project experiment was used.

Reviewed documentation commit: `c1e0f25aa1c305bfd29c61398e757b4c1f2d913d`. Scientific record: `ec6aa15d586bcc8a90f7232b433fd48d8c73d509`; frozen report SHA-256 `ee0001d5e54f36368b75fe48ae4c55a5979e5eb637e61fa0208a4f64fec87d14`.

The following are SHA-256 identities of the exact committed documents read, relative to this record's parent directory. They are historical input pins; subsequent owner updates require their own assessment.

```text
6333debcc1b3beb0d144d54ce336b95579fb3928aa63a65f33f644790fab253c  README.md
efcfebe8b848c0e38ff013d144e0aa6d4eee525852ee1cfa084ff38f5d01e54a  FIELD-GUIDE.md
ec00b9174297171a14eba05d8788937aa1f90f927d2b4bb7ba296ae51f5c2d9f  architecture/BATCHING-NATIVE-FEASIBILITY-REVIEW.md
af5997d6e218959ea5184cf115c6c09d70097e25dced7b1c322eb1be850983d6  architecture/PUBLIC-FIELD-SPEC-REVIEW.md
2029bc1c7b62cf1d56744cf2e95c0ab75abc1e188fd5b4a0e3ce96fd99d0603a  native/REPORT.md
67d846f9208b1366b95da5d7656ef505c278323208812bf99e420c307eedaea4  native/public-observation/README.md
c025ce3ad9bbc57eb67dfc288a9d6e4a8100c58344a73f325a8587d041443452  workload/DECISION-CONTRACT.md
```
