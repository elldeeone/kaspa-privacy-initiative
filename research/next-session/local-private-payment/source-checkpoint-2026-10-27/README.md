# Preserved source drafts from the October 27 handoff

These are exact copies of the selected public source and design files that
previously lived outside Git. [COPY-MANIFEST.json](COPY-MANIFEST.json) records
each original path, destination, byte count and SHA256. The original files,
runtime evidence and private material remain in place.

| Directory | Entry point | Recorded state |
| --- | --- | --- |
| `fr-scalar` | [Scalar gate specification03](fr-scalar/SCALAR-GATE-SPEC-03.md) | The handoff reports completed three-party BN254-Fr scalar compatibility. Full private Groth16 proving remains unqualified. Runtime results are local. |
| `groth16-integration` | [Implementation plan03](groth16-integration/INTEGRATION-IMPLEMENTATION-PLAN-03.md) | Proposed backend and owner-input contracts; implementation is unfinished. |
| `native-authority` | [Specification03](native-authority/SPEC-03.md) and [repair handoff](native-authority/repairs/build-02/WRAP-UP-DRAFT-01.json) | All 96 frozen source02 files are preserved. The recorded build failed; import-only repair overlays are separate, unapplied and untested. |
| `recovery-checkers` | [Source freeze](recovery-checkers/SOURCE-FREEZE-01.json) | Corrected preparation checkers and both control harness versions. The final publication audit remains incomplete. |
| `recovery-namespace` | [Contract and status](recovery-namespace/CONTRACT-AND-STATUS.md) | Source-reviewed optimization proposal; runtime and full graph acceptance remain unqualified. |

Frozen manifests and scripts retain their historical absolute paths, hashes,
statuses and dependency references. Some pre-execution status fields predate
later observations in the [session handoff](../SESSION-HANDOFF-2026-10-27.md).
They are historical records, not automatic execution instructions.
The source copies do not provide a portable runnable distribution: installed
toolchains, MP-SPDZ binaries, full JS packages, captured upstream references,
runtime data and generated artifacts are not all vendored here. A future
implementation change must explicitly select its working paths and dependencies.

No source predicate, expectation, cryptographic relation or frozen experiment
was changed by this import. No compiler, signer, witness generator, prover,
MPC engine, RPC client, financial trial or recovery publication was started.
The [third-party notices](native-authority/THIRD-PARTY-NOTICES.txt) describe
the copied dependency excerpts and included license text.
