# KPI orchestration research record — 22 October 2026

This is the canonical documentation snapshot for the orchestration work. It is based on research checkpoint `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`. The lead-owned active experiment and its uncommitted source are outside this import. No terminal privacy result is introduced here. Historical reports retain their original evidence scope and conclusions.

Start with the [field guide](FIELD-GUIDE.md), [decision register](evidence-lineage/decision-register.tsv), and [evidence-lineage review](evidence-lineage/REPORT.md). The project's [security invariants](../../../SECURITY-INVARIANTS.md) continue to apply.

## Current decisions and evidence boundaries

| Topic | Retained status | Canonical documents |
|---|---|---|
| Privacy experiment | Frozen arithmetic study was pending in the imported snapshots. No result is inferred from progress. Previous privacy failures and the absolute cap remain in force. | [Statistical scope review](statistical/REPORT.md), [post-result decision contract](workload/DECISION-CONTRACT.md) |
| Current v6 relation and native binding | Bounded source/evidence reviews found no demonstrated bypass in their scopes. Historical proof/native results are version-specific; source acceptance is not a fresh proof, formal audit or live qualification. | [Relation invariants](workload/V6-RELATION-INVARIANTS.md), [relation pins](workload/V6-RELATION-INVARIANTS-PINS.sha256), [settlement binding](native/CURRENT-V6-SETTLEMENT-BINDING.md), [binding pins](native/CURRENT-V6-SETTLEMENT-BINDING-PINS.sha256) |
| GPU observer v3 | Narrow source correction accepted. No GPU readiness or demonstrated speedup. Complete two-view reference parity/profile, exclusive resource release, cgroup/cleanup qualification and an attested private runtime are still required. | [V3 preparation](compute/gpu-v3/REPORT.md), [bounded protocol](compute/gpu-v3/BENCHMARK.md), [v3 execution review](evidence-lineage/GPU-PACKAGE-V3-DELTA-REVIEW.md), [inherited v2 timing review](statistical/GPU-BENCHMARK-V2-DELTA-REVIEW.md) |
| Mac public reference | C+D matched; pooled stopped at the resource guard and has no complete parity result. No retry or further array/profile work is implied. Mac timing does not qualify Forge. | [Reference review](statistical/MAC-REFERENCE-PROFILE-REVIEW.md), [allocation preflight](archive/mac-staging/CPU-ADAPTER-PREFLIGHT.md) |
| Current-version exit recovery/race | Prepared four-proof/two-order composition has bounded static acceptance. No build, fresh proof or execution result; increased-fee minimum-claim failure remains retained. | [Protocol](exit-recovery/implementation-v1/PROTOCOL.md), [source/envelope review](evidence-lineage/EXIT-RECOVERY-IMPLEMENTATION-SOURCE-REVIEW.md), [semantic review](statistical/RECOVERY-RACE-SOURCE-REVIEW.md) |
| Native public observation | Historical bytes support a partial field mapping. No complete model parity, proof/native VM/chain verification, or privacy result. | [Mapping specification](native/PUBLIC-FIELD-RECONSTRUCTION-SPEC.md), [public observation record](native/public-observation/README.md), [independent review](statistical/NATIVE-OBSERVATION-STATIC-REVIEW.md) |
| Flat batching | Tiny model gates passed conditionally; transparent authorizations, one colluder and missing sound validity/delivery remain adverse findings. Heavy genuine batching is deferred. | [Model spec](architecture/flat-batching/SPEC.md), [completed model report](architecture/flat-batching/REPORT.md), [native feasibility review](architecture/BATCHING-NATIVE-FEASIBILITY-REVIEW.md) |
| Prover GPU alternatives | Current v6 prover differs from the historical outer-proof GPU workload. No drop-in compatibility or performance claim. | [Compatibility review](workload/GPU-PROVER-COMPATIBILITY.md) |

## Historical and superseded records

- [GPU v1](archive/gpu-v1/REPORT.md) is superseded; its allocation, timing, identity and cleanup findings are retained in the original reviews. Do not execute v1.
- [GPU v2](archive/gpu-v2/REPORT.md) is superseded by v3's process-identity correction. The [v2 execution review](evidence-lineage/GPU-PACKAGE-V2-DELTA-REVIEW.md) retains the defect. Do not execute v2.
- [Cash-coupling proposal](workload/archive/CASH-COUPLING-PROPOSAL.md) is deferred/superseded, not a scheduled 128-master experiment. Read its [independent follow-up review](statistical/WORKLOAD-FOLLOWUP-REVIEW.md) and the current decision contract.
- [Initial batching proposal](architecture/archive/INITIAL-BATCHING-PROPOSAL.md) predates the completed toy and native feasibility review. Its suggested next steps are historical.
- [Coordination through 19:10 AEDT](archive/COORDINATION-THROUGH-1910.md) is a historical record, not current scheduling authority. Private attempt locators and operational UUIDs were omitted.
- [Mac staging](archive/mac-staging/REPORT.md) records an earlier staging/capacity decision. Its one-worker permission and v1 remediation state are historical; the later compute hold and v3 review take precedence.

## Ownership and future workflow

Luke directs the project; the root orchestrator schedules and monitors delegated agents. The existing lead retains the frozen evaluation, scoring, recount and active research checkout. Each research lane owns its assigned source review or isolated experiment. Aggregate capacity and permission to execute remain with the orchestrator; an authored protocol or static pass never releases resources.

Future project reports/specifications/reviews belong in the KPI repository on Forge and must be committed there. Use an isolated branch/worktree when the active checkout is lead-owned or dirty. Keep executable experiments and private/runtime material out of this documentation collection. Do not push or publish without separate authority. Small local cursor/owner/gate state may remain as operational pointers; new Mac project deliverable documents are not canonical.

## Provenance and exclusions

[PROVENANCE.json](PROVENANCE.json) records every original source SHA256, imported SHA256, target and transformation. Imported Markdown gains a status notice and normalized links; transformed bytes are never represented as the original hash. Pinned source links resolve against the unchanged research checkpoint. [DOCUMENT-INVENTORY.md](DOCUMENT-INVENTORY.md) lists the imported records. [SOURCE-REFERENCES.json](SOURCE-REFERENCES.json) records normalized tracked-source links.

Manifests, statuses, source pin lists and small completed public control summaries are archival metadata about their original packages. Their internal hashes identify original package files, not the renamed/transformed documentation files here. They do not make this directory a runnable benchmark or proof package. Original Forge package locations are retained where needed for reproduction. Historical Mac artifact identifiers record origin only; no absolute Mac path is a current documentation dependency.

Excluded: private evaluation inputs/results, seeds, truth and predictions; active runtime/profile/resource dumps; fixture/source archives; serialized native fixtures and generated native surfaces; executable experimental code; binaries/build products; dependency environments/caches; raw machine evidence; and the lead-owned dirty/untracked research files. Original frozen packages, immutable public snapshots and machine evidence remain untouched. Documentation migration runs no project tests, builds, proofs or GPU jobs and changes no research outcome.
