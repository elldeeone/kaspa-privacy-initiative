# Final host source review and initial-finding closure

Date: 2026-10-18. Separate AI reviewer: `/root/crypto_composition_review`.

**Source decision: W1 and W2 are addressed at the actual restore boundary. Own-backup-only reconstruction is implemented in the restore command and restored-spend builder. No remaining source-level blocker was found for running the bounded offline proof/replay/restore exercise. Actual receipt-backed lifecycle and restore evidence is still pending.**

W3 remains an explicitly documented, nonblocking typed-helper precondition on the frozen guest path. I found a separate erroneous exercise assertion (W4) in the first final-host snapshot; its revised replacement-pin branch assertion is coherent and retained in the reviewed v2 snapshot. No new note-relation inflation/theft bypass was demonstrated.

This is source review by the same separate AI agent sharing model/platform/host with the author. It is not independent human/external audit, cryptographic certification, an R13 outer proof, native acceptance/payout qualification, or proof of independent operators. The GPU proof was still running when this report was written.

## Frozen inputs

`final-inputs/manifest.json` records the first 13-file host/docs snapshot. `final-inputs-v2/manifest.json` records the final reviewed snapshot after W4's assertion correction and three host-only refactors. Only `recovery.rs`, `proof.rs`, and `fixture.rs` changed between these snapshots. All v2 manifest hashes were recomputed and matched. The initial core/guest source remained byte-identical to `manifest.json` from the initial code review, preserving the declared guest image `7461de1c1231e61823431d4800d70f1d8378cf7722b195e82321a028151b2ade`.

Final reviewed identities, under `poc/private-payment/` unless stated:

| File | SHA-256 |
| --- | --- |
| `wallet-host/src/history.rs` | `d45d7db3b3a1f7dc573ac3fa57c0ede7a7143692e2233ca16367e3935fac7794` |
| `wallet-host/src/recovery.rs` | `e91aa6f4a4822f0ba489b7f364db9f98a5784e6c91ab5e0a60fcca66e197f764` |
| `wallet-host/src/state.rs` | `f6e4d84e7749a4a38d7430489e8c9188ee13885a3912f3a70a96c6c041a97594` |
| `wallet-host/src/scan.rs` | `0036521e1b144f053ea2ab8f3826683aaa2fd8430a2b0ff54f61835e54f7b08f` |
| `wallet-host/src/fixture.rs` | `e9957eea0a350be4545b57cc2c212e187e74f626f34686a6238d3b53da97f146` |
| `wallet-host/src/proof.rs` | `757fcbef121e796f84e2eeba111919762a05688a4eb49b0285fb9b63d71e8c71` |
| `wallet-host/src/main.rs` | `37c42034767f1ee4dd549d954f5b2150807ad22aa8f956e1ca70201a088f18dd` |
| `wallet-host/src/adversarial.rs` | `fec4abd4c45b25c0c06ee06743dc9bf04b3fe25fd3958ff7dde017011351d705` |
| `wallet-host/Cargo.toml` | `ec048d22ca41c91e40f1945446b6f7d80e0200efd8465bdd184c31e2feceb10e` |
| `wallet-host/Cargo.lock` | `afa3c374543d24e1b1ba265456c2b2459c8ef53bebfa5877e0dc2b09c6450653` |
| `WALLET.md` | `a2729fe706e24f3f85164db99d0338ef33a426396d65779e99cfe93de40e8e23` |
| `WALLET-PLAN.md` | `9db965115e97ff1ebcf36e146df37851aaf512635d04207c91fedafdcea84725` |
| `docs/adr/0020-offline-wallet-relation.md` | `8a656e7dbb364c4ceab722fd6f7c213ed9668ac6ecb1781db9f4c094f2e69884` |

## W1 — closed in source at the verified-history entry point

`history::restore` calls `replay` before scanning (`history.rs`:91–136). Replay first checks the entire raw history against the externally supplied expected SHA-256 (39–48), which binds the synthetic bootstrap policy, record order, complete public intent/auth bytes and receipt hashes. Receipt names are restricted to ASCII alphanumeric/hyphen and each loaded file is hashed before deserialization (27–37). File absence, changed receipt bytes, hash mismatch or malformed receipt envelope propagates as an error; it is not converted into a zero balance.

For each available typed receipt, `State::apply` decodes the exact public intent, compares all immutable context fields, verifies actual image/parameters and complete journal, and applies current anchor/nullifier/pending/conservation rules atomically. Only verifier/state-admitted operations are passed to scanning. The private scanner now documents this precondition (`scan.rs`:1–3). It still cannot independently authenticate arbitrary iterators, but the CLI no longer exposes that unsupported usage as a restore operation.

The externally trusted **latest** history pin remains a real assumption. A digest computed from received data authenticates no canonical origin or freshness. The synthetic pin replaces neither Kaspa acceptance/ordering proof nor an independently retained native checkpoint. W1 is closed for the explicitly trusted synthetic-history boundary, not for arbitrary network-provided history.

Runtime closure still requires observing the specified same-length mutation controls with real saved receipts. The code's original-pin check rejects changed bytes before scan; journal binding must reject changed intent/ciphertext against the original receipt if a different synthetic branch is deliberately supplied with a new pin.

## W2 — closed in source and public helper control

`history::keys` requires a nonempty inventory, decodes each key to exactly 32 bytes, and rejects duplicate **decoded bytes** using a BTreeSet (`history.rs`:66–89). Thus lowercase/uppercase hex aliases do not duplicate an owned note. `restore` passes only that checked key vector to scan.

I compiled `host_boundary_probe.rs` against the frozen v2 source and existing pinned release libraries. Without reading any backup/witness file, it confirmed that one public synthetic key is accepted, literal duplicates and mixed-case aliases reject, and an empty inventory rejects. It also exercised all 12 capacity count/mode boundary combinations plus unknown mode rejection. Results are in `host-boundary-results.json`. These are source/helper controls, not receipt-backed restore runtime evidence.

## Own-backup-only reconstruction — source path verified

The restore CLI (`main.rs`:20–25 -> `recovery::command` -> `history::restore`) reads the caller's selected actor backup, raw public history, externally supplied pin and public receipt directory. It does not call `proof::inputs` and does not read original `input.bin` files or another actor backup. This differs from the separate proving/CPU-case verification command, which intentionally has local witness input available.

Prepared Alice and Bob backups each contain only their actor's Orchard key (`fixture.rs`:277–298). Alice alone retains the independent Ed25519 deposit seed/reference. Both are saved through the 0600 secret-file helper under the private task directory. The combined original backup remains a lab-generation artifact, not restore input.

Both note scopes are scanned with the actor key; full incoming decryption validates recipient/commitment/ephemeral data, current nullifiers filter spent notes, and membership witnesses are reconstructed from replayed public leaves. In `recovery.rs`:312–332, Alice's restored exit uses `a[0]` from that scan plus her own key, fresh dummy/output material and the public program file. It does not reuse an original private transfer witness to recover the internal change. The exercise process reads both actor backups for lab assertions and the alternate-signature adversarial control; that is not an independently operated user or process-isolation claim. The standalone restore command is the own-backup boundary.

The source includes checks of backup context, paired pending seed/reference presence, seed-to-recovery-key agreement and exact reference metadata (`history.rs`:97–134). Correct retention of the user's original secrets remains an assumption. Incoming-only delivery still does not recover outgoing payment audit history.

## W4 — incorrect replacement-pin expectation fixed in v2

The first final snapshot expected `restore(changed_ciphertext_history, hash(changed_history))` to return Err. That contradicted the chosen semantics: an available, well-formed false receipt/intent pair is an invalid operation and must become a no-op, while later records continue. A new caller-supplied pin explicitly chooses a different locally trusted synthetic branch.

I reported this before the real-receipt exercise ran. In the v2 source (`recovery.rs`:224–242), the old trusted pin still errors. Under a deliberately replaced pin, the changed transfer must fail journal binding and its dependent exit must fail admission; only CREDIT may be accepted, Alice must retain the original 1000 synthetic sompi, Bob must receive no payment and no exit liability may be created. That is the correct counterexample/control for the defined host semantics.

The report now distinguishes seven actual history/backup error cases from the replacement-pin branch admission control. This source correction closes the mistaken assertion; successful runtime execution remains pending. A replacement pin must never be advertised as proof that a history is the original canonical lineage.

## Additional admission/replay assessment

- All eight immutable context fields are compared to prior synthetic policy before proof/state effects. The actual permitted wallet image comes from that policy and is supplied to the SDK verifier; the journal's string is not accepted as image authority. Shared N is fixed by the one admitted policy/D. None of these host checks is a proved outer transition.
- State clones before economic changes; rejection leaves the economic encoding unchanged while advancing checked cursor/activity. Inclusive expiry is checked against the pre-increment zero-based ordinal. Cursor overflow errors before any effect. Current nullifiers cover old roots and all slot dummies.
- Pending principal is authenticated only to the locally trusted bootstrap fixture, credited once and moved into private value without reserve duplication. Exit/fee values move into backed unpaid claims and remain in reserve. The harness implements one synthetic deposit and no native payout; it does not demonstrate refunds, paid markers, native reserve consumption, terminal drain or native reorg reconciliation.
- The capacity helper now isolates exact count/mode checks without allocating a full tree. Boundary arithmetic includes 2^32 and rejects impossible counts/unknown modes. Real `exit_only` still depends on the verified guest's two-zero-output predicate; the helper alone cannot authorize it. The report correctly says no full tree was materialized.
- Well-formed cryptographically false receipts can be skipped only after actual host verification returns rejection. Missing files/hash mismatches/deserialization failure halt before classification. This admitted language is narrower than a total native ordinary verifier, which remains explicitly outside R13 qualification.
- The mixed valid-invalid-valid case serializes a mutated real receipt, hashes that exact false artifact into a pinned synthetic record, and replays it through the host verifier. Its no-op result is not a validity bit supplied by the host fixture and is not an invalidity proof.
- The two-valid-signatures control uses the established Ed25519 raw-signing API only to vary an unfunded test key's nonce prefix; both signatures must verify under the same key/message and differ. The original receipt must reject pairing with the second envelope through the auth journal digest. Honest fixture signing remains the standard deterministic signer. The host alone enables `hazmat`; `cargo tree --locked --offline` confirmed the guest's Ed25519 feature graph excludes hazmat, batch and legacy compatibility. This does not introduce another signature primitive or change the guest verification profile.
- Receipt proof mode is succinct-only with dev-mode rejection, successful actual-image verification, exact journal comparison and empty assumptions. Host-only refactors in v2 do not alter those predicates or the core/guest source. There is still no independently rebuilt source-to-image proof in this reviewer report.
- Plaintext research backups, OS entropy, local machine/prover confidentiality, workload timing and correct external pin retention remain explicit assumptions. No private key, backup or witness file was copied or printed during this final source review.

## Bounded evidence read, not upgraded into proof claims

The four owner-designated public reports were copied unchanged into `public-evidence` with hashes in its manifest:

- Native shared-relation controls: three valid lifecycle relations, two extra boundary relations, 111 rejected relation negatives, 12,720 framing rejections; no full tree/native transactions.
- Real VM execution negatives: five expected relation failures—bad recovery signature, inflation, wrong delivery, wrong owner and wrong position—using the declared wallet image. They produced no receipt proving invalidity. Common report fields such as `noUnresolvedAssumptions=true` in an execution-negative report are not receipt/seal evidence.
- Public byte/signature interoperability: three positive-case intents/journals and one libsodium CREDIT signature check; the tool reports no private inputs/backups read. This does not test a wallet proof or independent subgroup policy assurance.
- Public wire interoperability: nine retained golden intents and 15,568 parser truncation/trailing cases. This is codec evidence, not state admission or soundness evidence.

I did not rerun GPU work, interfere with the running prover, mutate repository sources, create a wallet, submit transactions, use funds, change infrastructure, send external messages, commit or push. The only new dynamic checks in this final review were local public host-boundary helpers; all reviewer writes remain inside this task folder.

## What can be concluded now

The host source addresses the initial scanner/duplicate-key findings and implements the claimed own-backup-only reconstruction path. W3 is documented and nonblocking on shape-validated paths; W4's mistaken assertion is fixed. This supports continuing the authorized unfunded offline exercise.

It does **not** establish that the four intended real wallet receipts, saved CPU verification, actual host restore/alternate-signature/replay controls or restored spend have passed. Those results must be reviewed when retained. External audit, full proved outer verification, native authority/ordering, payouts and independent R16 remain open regardless of the later offline result.
