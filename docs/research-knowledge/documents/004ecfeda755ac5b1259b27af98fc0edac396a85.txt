# First real CREDIT receipt: separate-agent CPU/runtime review

Date: 2026-10-18. Reviewer: `/root/crypto_composition_review`.

**PASS for this bounded first-credit integration check.** I independently loaded the public saved receipt on CPU, verified it with the reviewed SDK/backend and frozen host verification code, and admitted it through the reviewed synthetic state adapter. It moved 1000 synthetic sompi from pending to private value while reserve stayed 1000. Same-credit replay, all eight wrong context fields and four changed authorization envelopes rejected atomically. Actual image-byte interpretation, initial anchor, both appended leaves/nullifiers and wrong-image/seal/journal controls passed.

This is separate-agent, same-model/platform/host/backend CPU/runtime evidence. It is **not** independent human/external audit, independent cryptographic verifier assurance, an R13 outer proof, native backing/ordering/payout evidence or full lifecycle/restore completion. No GPU work was started, stopped or inspected by the reviewer.

## Frozen public inputs and exact identities

All nine owner-designated public files were copied into `credit-runtime-inputs` before testing. SHA-256/byte lengths are in its `manifest.json`; all were recomputed afterward and matched. No `input.bin`, backup, seed or selected-note witness was read or copied.

```text
Program image:       7461de1c1231e61823431d4800d70f1d8378cf7722b195e82321a028151b2ade
Program SHA256:      3887533bb6855403ee137799b63b95b68e29e6e932c758bc721a6515a93226a0
Receipt SHA256:      2f43a8b38919d68a53500911e8eac36d09ea187b4cb08ddcece32328dab81442
Receipt bytes:       223684
Intent SHA256:       bec36af0c39f122324b60635f4cf9d5b6197af365f0a1b89b0aa9783c91e8c2e
Authorization SHA256:09a24be81e75a7f0b994b47e21a3cbc228b96c6cf67b49318f82cc6b8081a4ff
Journal SHA256:      a97cd2c7945e74990c119ea693cffe432a5e2e7e1cea7405ca77cba1f885bd2c
Journal bytes:       229
Verifier parameters: ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013
```

The owner's public proof report records 1210.174563087 seconds, 691 segments and 299,957,660 user cycles. Those are retained producer measurements, not a GPU timing measurement repeated by this reviewer. The saved CPU report identifies the same receipt/image/journal and records 11 rejected proof mutations. The reviewer did not rely solely on those report assertions: the receipt and current-state controls were executed again below.

The public case metadata's program/journal hashes and expected image were checked. Its witness-input hash was deliberately **not** verified because this review used public inputs only. This review also did not reproducibly rebuild the original guest from source; actual wrapped program image was recomputed from the supplied public program bytes.

## Reviewer-run runtime controls

`credit_runtime_probe.rs` compiles the frozen reviewed v2 `fixture.rs`, `proof.rs`, and `state.rs` modules against existing local release libraries. Link artifact paths/hashes are in `credit-runtime-link-artifacts.json`. Core/guest source was rechecked against the initial immutable snapshot and remained identical. The probe reads only the frozen public files, and its output is `credit-runtime-results.json`.

1. **Public transcript and actual image:** decode canonical intent, recompute its complete expected journal from actual auth bytes, check the retained journal/hash, compute the actual program image, and require the policy image's byte representation to decode to exactly that image. This verifies the concrete SDK `Digest` byte interpretation, not just two equal display strings.
2. **CREDIT authority:** independently verify the public strict Ed25519 signature under the public deposit key over the complete G-hash/intent-id message. This checks the signature-to-intent relation; it does not authenticate the key to a real native outpoint.
3. **Real receipt:** require succinct mode, disabled dev mode, current default pinned verifier parameters, successful actual-image/journal verification and empty unresolved assumptions through the reviewed verifier. The saved receipt passed on CPU.
4. **Genesis and first credit:** require count zero, exactly the canonical depth-32 Orchard empty allowed anchor, cursor zero and synthetic pending/reserve 1000/private zero. Apply the real CREDIT receipt. Require pending zero, private 1000, reserve still 1000, credited=true, cursor one, exactly two spent slot nullifiers, exactly two leaves, a second post-operation allowed root and no claims. Reconciliation passed.
5. **Replay:** apply the identical CREDIT again. It rejected on already-spent nullifiers; economic bytes were unchanged and the rejection cursor advanced exactly once. This tests same-credit replay. A newly proved CREDIT with different dummy nullifiers against the already consumed deposit was not generated in this check; its separate pending-consumption guard remains source-reviewed.
6. **All eight immutable contexts:** independently mutate each context field and attempt admission against unchanged genesis policy with the real original receipt. Every case rejected specifically at the immutable-policy comparison, preserved economics and advanced the synthetic rejection cursor once.
7. **Authorization envelope:** reject one signature-byte mutation, absent CREDIT authorization, trailing auth data and an unknown auth flag, preserving economic state for each. This is not the later two-distinct-valid-signatures exercise; that remains pending in the lifecycle driver.
8. **Receipt boundaries:** wrong actual image, mutated succinct seal and changed expected authorization-digest/journal bytes all rejected.

No failed control or new code finding emerged. The CPU receipt check, signature check and state admission all used the same backend family as the author's code; this supplies a separate execution/checking path, not independent proof-system assurance.

## Recovery output-only delta

The current `recovery.rs` was separately frozen at `credit-runtime-inputs/host-source-delta/poc/private-payment/wallet-host/src/recovery.rs`, with its exact SHA-256 in that directory's manifest. Compared with `final-inputs-v2`, it only saves the already computed public pre-exit history bytes as `before-exit-history.json` and adds their digest to the public report. It changes no relation, verification, admission, key inventory, replay or balance predicate. The intended isolated own-backup runtime controls have not yet been observed.

## Remaining evidence

Transfer, Bob's exit, receipt-backed history/restore controls, two-valid-signature binding, and Alice's restored spend remain pending. This first-credit pass resolves a real foundational integration question—actual image bytes, real receipt verification, genesis admission and backed pending-to-private accounting—but does not establish those later results.

Synthetic genesis policy/deposit is still locally trusted, no real deposit is recognized, and all reserve/liability values here are test fixtures. Native authority/bootstrap/ordering, full ordinary proved outer classification, refunds/payouts, terminal native drain, independent operators and external audit remain open.

All reviewer writes stayed inside the review task folder. No repository edits, witnesses/backups, wallet creation, funds, broadcasts, infrastructure changes, external messages, commits or pushes were involved.
