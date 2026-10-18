# Focused re-review of C1–C4 fixes

Date: 2026-10-18. Reviewer: `/root/crypto_composition_review`, the same separate AI agent that produced `review.md`.

**Decision: C1–C3 are closed at design level. C4 is approved at design level, conditional only on applying the exact reviewed invariant proposal. With that exact proposal applied, these four findings do not block an unfunded offline research implementation of the specified generic wallet relation.**

This does not establish a completed wallet implementation, cryptographic soundness, successful full-relation proof, outer classifier, native deposit authority, or testnet readiness. No native acceptance or payout gate is cleared. The reviewer shares the author's model/platform/host; this is the owner's selected separate-agent research review route, **not an independent human/external audit**.

## Explicit invariant disposition

**APPROVE applying the exact bytes of**:

```text
fix-inputs/proposed-SECURITY-INVARIANTS.md
SHA256 35e180449636d24abe40a117fc291f6b897d1592fcdaa43ba795a40a4ca55331
```

The reviewed change at lines 24–49 retains the closed private transfer equation and explicitly adds the native-boundary equation. It requires credited principal to consume one authenticated, still-pending, backed deposit exactly once, forbids counting reserve twice, preserves an unpaid exit liability until actual payout, and separates native fees/rent/sponsor accounting. It does not weaken backing, authorization, single consumption, or integer conservation. This is the explicit disposition requested before application; the reviewer has not applied it. Different bytes need separate disposition.

This approval is under the bounded owner-selected AI review method in ADR-0019. It is not a claim of independent human/external security review or authorization to accept liabilities.

## Reviewed snapshot and checks

Inputs were frozen under `/tmp/kpi-crypto-composition-review-20261018/fix-inputs`. All 11 manifest file hashes were recomputed before review and after test execution; all matched and the frozen files remained unchanged. Important exact identities:

| File | SHA-256 |
| --- | --- |
| ADR-0019 | `4619cdbd08704edb8d1be5d5dcfe0c212e97818816f1151907848cbd576cd624` |
| RFC-0003 | `135fa7f64747d420e35c3c1acf7b135c550050ff75aa619234c80d26011c474c` |
| RFC-0004 | `4fe1e19578db9209a57964723af17b9aaa165895e5e3671d100f561ce3f83630` |
| Proposed SECURITY-INVARIANTS | `35e180449636d24abe40a117fc291f6b897d1592fcdaa43ba795a40a4ca55331` |
| Rust auth/journal library | `743a68215021fe31c4f935e76fedae611cab9e8993d9fce0e7d86d8bc2a8bb01` |
| Rust binding checker | `8c8e612c44e99dad4cf9a16cf50da57b3674555ea7b0834695874884eb2930ea` |
| Python public-binding module | `35effdf289f0fcd8626f61bb1e8ac00ccbea3401d9526f3d5609ab3f8058fae9` |
| Python binding checker | `9fa16cc7f5bac3713b7c187d5691212aa071f7cc69b01ce7b3d69d62ba84e620` |
| Suite candidate | `aaec6a23be8295c1196e946a9e637e199814075cf3f1af3b501069305355b676` |
| Auth Cargo.toml | `61cf938faabb52e1e7547b9e11008996f870e0e558b9c2a181b0dedaf0b56173` |
| Auth Cargo.lock | `66e506287307fed43ed7fe9ce6dbb0bf20e95239494c11992d46e66682a3a284` |

Test artifacts read:

```text
ebd4f76d5f10947e853bcc2c90d1d58b2bcb844c9ac2018b558f463b33129be0  public-binding-vectors-v2.json
b9d46b7967b28c345d9ff888bab2500a6b8c199c3c09f818d32865cc448a46cf  public-binding-report-v2.json
```

Reviewer-run checks:

1. Built and ran the **frozen** Rust binding checker with `cargo run --release --locked --offline`, using a new target/output directory inside this review folder. Output exactly matched the supplied vectors. It generated nine journals, rejected 182 malformed authorization frames and verified that 128 individual CREDIT signature-byte mutations both failed strict verification and changed the authorization digest/journal.
2. Executed the reviewed Python checker against the supplied Rust vectors and unchanged original intent corpus. Its output exactly matched the supplied report: nine matching journals, 191 Python framing rejections and 209 context/authorization substitutions bound to different journal bytes. These are binding tests, **not immutable-policy rejection tests**.
3. Independently computed `orchard::Anchor::empty_tree().to_bytes()` using the pinned Orchard library. It exactly produced the new RFC genesis root `ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f`.
4. Compared the proposed invariant against the original frozen invariant, and inspected all revised RFC/ADR text and public-binding library/checker code for the four findings and authorization/domain/bootstrap cycles.

Reviewer-produced outputs are `reviewer-public-binding-vectors.json`, `reviewer-reproduced-public-binding-report.json`, and `genesis_anchor_experiment.rs`/binary under the task folder. The underlying unchanged intent encoder/corpora were read from the workspace; full wallet/private native relations were not executed.

## Finding dispositions

### C1 — CLOSED at design level; public byte tooling corroborates the format

RFC-0003 now requires exact canonical authorization framing and the SHA-256 authorization digest; RFC-0004 adds that digest as the final fixed journal field. The CREDIT guest must strictly verify the same signature bytes whose digest it commits. The proved outer verifier must derive its expected digest from the actual public operation envelope and compare the entire journal.

The tag and fixed framing are unambiguous: CREDIT is exactly `01 || signature[64]`; TRANSFER/EXIT are exactly `00`. Unknown flags/kinds, missing/irrelevant signatures, truncation and trailing bytes reject. The revised journal is exactly 229 bytes for this profile. Public helpers mirror the specified tag/field order and reject malformed authorization framing; helper functions deliberately provide no proof or policy authority.

The signature still signs the unchanged G-hash/intent tuple, so the new journal digest introduces no signature/proof/native-ID self-reference. A receipt using valid private signature S cannot authorize a public envelope containing S' unless their hash matches, under the ordinary SHA-256 collision-resistance assumption. A second different valid signature on the same intent is likewise a different envelope and needs its own matching receipt/journal.

**Remaining implementation obligation:** the real guest must compute this digest from its actually verified bytes, and the outer verifier must compute its expected journal from accepted bytes. There is no real guest/outer enforcement yet. Passing these codec tests cannot close P2/P3.

### C2 — CLOSED at design level; outer admission remains unimplemented

RFC-0003's generic-wallet paragraph and revised relation table now explicitly move pool admission to the proved outer transition. The guest binds all supplied context through complete I and its journal without embedding G or its own image. Before effects, the outer must authenticate policy from authorized prior state, compare all eight duplicated context fields, verify against the actual admitted image/parameters, and only then select the authorized shared N[D]. RFC-0004 states the same allocation.

This is a coherent separation: the guest's role is a cryptographic relation about I; the outer's role includes authorizing the immutable context and backing. D/network/pool/lane need not all appear as separate journal fields because the complete canonical intent digest binds them, provided the outer compares those actual intent fields with authenticated policy.

**Remaining implementation obligation:** actual immutable-policy rejection, real-image/parameter verification, canonical shared economic spentness, and native descriptor/bootstrap authentication. Existing mutation tests establish byte binding only and accurately say so. The synthetic fixture policy cannot recognize a native deposit or authorize reserve release.

### C3 — CLOSED at design level

RFC-0003 explicitly initializes C to the depth-32 empty Orchard tree, count zero, and A to exactly its published root. It separately admits complete canonical post-operation anchors, forbids the intermediate single-append root, preserves current spentness, specifies genesis rollback, and requires a count representation able to store 2^32 while note positions remain u32.

The exact root matches the pinned library. This removes the first-CREDIT deadlock without creating membership for a positive note at the empty tree.

**Remaining implementation obligation:** genesis initialization and allowed-anchor/current-state enforcement in the actual transition, including first CREDIT, full-capacity branches and reorg/restore tests.

### C4 — APPROVED; closes on exact proposal application

The exact proposal is approved above. The RFC's unchanged kind equations specialize the generalized boundary equation correctly: CREDIT has zero private in/exit/fee and authenticated p; TRANSFER has no public entry/exit; EXIT consumes private value into change, exit principal and authorized fee. The revised text expressly states credit does not add reserve again and exit remains unpaid backed liability.

**Remaining action:** apply only the reviewed invariant bytes and record their disposition with this report. Until application the repository's literal old I-2 and the new boundary equations still differ, so the readiness decision is conditional on that concrete action. Actual checked u64/u128 computation and ledger/native conservation need later implementation/proof tests.

## Additional consistency observations

- Inclusive, zero-based accepted-native-transaction expiry is now exact enough for the ordered state implementation: one operation per transaction, malformed/rejected accepted entries still advance the authenticated cursor, checked u64 increment occurs before effects, overflow halts atomically. The generic wallet binds expiry bytes and does not decide accepted order. No fixed-point/native-ID dependency is added.
- Public I and authorization remain public even when passed through the same VM input stream as private note material. Placement in the witness stream does not make a signature a private key. The revised explicit scope statements resolve that potential reading.
- ADR-0019 accurately records the owner-selected separate-agent route, shared-model/platform/host limits, reviewed corrections and later native gates. It does not claim independent human audit or successful native implementation. Existing older references to independent review should be read under this explicit bounded method; status metadata saying `pending`/`unreviewed` may be updated to cite the completed AI design review, while external review remains unavailable.
- No new cryptographic primitive or asset is introduced. The auth digest uses SHA-256 with a distinct fixed domain tag. Original intent bytes remain unchanged; this is a deliberately revised journal shape for an initial profile with no accepted deployed wallet image. Exact journal length/equality must prevent accepting the previous shorter shape.
- The earlier N1–N3 native findings and R1 implementation requirements remain in force. Native recovery-key/principal/outpoint binding, full bootstrap dependency graph, funded registration recognition, ordinary outer invalid-proof classification, claim/paid/reorg conservation, terminal payout, complete recovery inventory, entropy handling and proof-envelope leakage policy are not solved by this re-review.

## Readiness boundary

After applying the reviewed invariant proposal, an unfunded offline implementation may begin against the fixed profile and explicitly synthetic policy/deposit fixtures. Its complete proof must still demonstrate all note ownership/membership/nullifier/encryption/conservation predicates; tests must challenge them adversarially. The code/proof results and actual images/control identities then need further review.

There are **no remaining C1–C4 design blockers for that bounded offline work**, conditional on exact C4 application. There is no approval of an implemented wallet, P1 completion as a whole, P2/P3 success, native trial funding, credit/refund/payout contract, mainnet, real funds, external audit assurance, or production safety.

No source changes, wallets, funding, broadcasts, infrastructure changes, external messages, commits or pushes were made by this reviewer. Only review/test outputs inside this task folder were written.
