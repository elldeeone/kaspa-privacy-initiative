# Initial adversarial code review: offline wallet relation

Reviewer: separate agent `/root/crypto_composition_review`, 2026-10-18.

**Initial result: no demonstrated inflation, unauthorized spend, double-spend acceptance, or output-delivery bypass in the reviewed core/guest. The frozen host scanner requires authenticated-history and unique-key preconditions; those need validation in the pending final host driver. One minor public helper panic is nonblocking on the current decoded guest path.**

This is a fresh code pass of the initial implementation, not a continuation of design-only approval. It is not a completed review of the still-changing restore/history driver, an independent human/external audit, proof of cryptographic correctness, or clearance of any native/R13 gate. The reviewer shares the author's model/platform/host. The supplied GPU proof was still pending at initial review; no claim of successful proving is made here.

## Frozen identities and scope

Before reading implementation contents, I copied 21 present source/configuration/document files to `/tmp/kpi-offline-wallet-code-review-20261018` and recorded SHA-256 and byte length in `manifest.json`. All frozen hashes were rechecked. Root's declared initial wallet image is `7461de1c1231e61823431d4800d70f1d8378cf7722b195e82321a028151b2ade`; this review did not independently rebuild that guest or establish a source-to-image reproduction.

| Reviewed initial file | SHA-256 |
| --- | --- |
| `wallet-core/src/codec.rs` | `376a20eeed3c1e6fac4a4ac38adb5af787778c68550edbd7bb93536492089a0b` |
| `wallet-core/src/lib.rs` | `09a984d88b52f7c4202e33a928613c74f4fc90bc2bfb419cc81842ebb5143cba` |
| `wallet-guest/src/main.rs` | `c88cc7db59fb1b2307c5f7eebec22326dcaa2c181934371c73efc7ec10f31a2d` |
| `wallet-host/src/fixture.rs` | `2b47675f5c806422ba15d913cf4f7eaed2fdc4f9588994299cb08aeb33d0e3bb` |
| `wallet-host/src/proof.rs` | `20eec51c026507457cc1df71221d5906876adefd298bbfe33093cad91d63932f` |
| `wallet-host/src/state.rs` | `90f42bec82b18f8162f8de830076478fa61859d5673e554370f03175d994abd1` |
| `wallet-host/src/scan.rs` | `268e71ef626d912145d1977ccc46680b28a80af450a4d8b83782253e54ccc33f` |
| `wallet-host/src/adversarial.rs` | `045fe3a38290c51bd485733faabb8ec68bba2057f7818856d3bce8fe5e02b310` |
| `wallet-host/src/main.rs` | `15dd3e6f0f2183a287de2d8f70d800e79da83e1a439e117f2268db0de8e31eee` |
| ADR-0020 | `8a656e7dbb364c4ceab722fd6f7c213ed9668ac6ecb1781db9f4c094f2e69884` |
| WALLET-PLAN | `9db965115e97ff1ebcf36e146df37851aaf512635d04207c91fedafdcea84725` |

Code paths in the table are under `poc/private-payment/`; the ADR is `docs/adr/0020-offline-wallet-relation.md`. Line references below refer to this initial snapshot. Supporting strict-auth dependency source/manifest/lock were separately captured under `supporting-dependencies` with their own hashes. The previously reviewed pinned Orchard/Ed25519/RISC Zero source remained the relevant primitive baseline; this pass did not re-audit every dependency.

## Findings and dispositions required

| ID | Severity / enforcement location | Initial finding | Required disposition |
| --- | --- | --- | --- |
| W1 | P2 recovery correctness; history/scan boundary | Same-length corrupted delivery can silently remove an owned note if raw history reaches `scan`. | Final driver must authenticate the complete history and each receipt before scanning; regression must reject corruption even with a recomputed attacker hash. |
| W2 | P2 balance correctness; backup/scan boundary | Duplicate retained keys cause duplicate returned owned notes. | Reject duplicate key inventory or deduplicate note results by canonical position/nullifier; test the actual restore entry point. |
| W3 | P3 API robustness; core helper | Direct malformed typed `Intent::journal` can panic before returning a validation error. | Document current decoded-path precondition or validate shape before conversions in a later reviewed revision. Current guest acceptance path is not bypassed. |

W1/W2 are not demonstrated note theft or inflation. W1's ability to affect the final restore command depends on whether the pending driver actually violates the verified-history precondition. The implementation author reports that a new driver will enforce it; that later source has not yet been reviewed here. W2 can exaggerate wallet balance reporting, but attempting to use the same note twice is still rejected by the core's duplicate nullifier check.

### W1 — scanner alone does not authenticate completeness or delivery bytes

**Location:** `scan.rs`:13–39, especially 15,25–31,39.

The scanner checks history context and final append count. It checks a leaf's position only after the output successfully decrypts as an unspent own note. Given an authentic state with one remaining owned note, flip a byte of that note's ciphertext while leaving history length, context and commitment unchanged. Trial decryption returns None, no leaf-position validation for that note occurs, and final count still equals the tree size. `scan` returns `Ok(empty)`, which could become a false zero balance if exposed without authenticated history replay.

**Observed control:** `scan_boundary_probe.rs` reads the local unfunded lifecycle witnesses only into memory, validates all three relations, reconstructs the initial scanner state and mutates a single ciphertext byte. `scan-boundary-results.json` records `sameLengthCiphertextMutationReturnsEmpty=true`; no private keys/seeds/witness bytes were printed or copied.

**Smallest correction at the intended boundary:** keep this private scanner behind a history driver that verifies an externally pinned complete synthetic history, hashes and parses all actual public intent/auth bytes, verifies every corresponding real receipt against fixed policy/current state, and only then supplies the authenticated accepted history plus resulting state to scan. State length alone and a freely recomputed local history checksum are insufficient. The verified-history precondition should be explicit in the scanner API/docs; a private module is useful but does not itself authenticate data.

Test missing, truncated, reordered and same-length mutated history; changed ciphertext with the original external pin; and changed ciphertext with a recomputed attacker pin. The latter must fail receipt/journal binding. Do not merely test that the changed bytes alter a checksum. Missing receipt or history must produce unavailable before scanning.

### W2 — duplicate backup keys duplicate recovered note entries

**Location:** `scan.rs`:22–35; initial `fixture.rs`:42,58.

`scan` iterates every key and pushes each matching positive unspent note once for each occurrence. Passing `[K,K]` produces two copies of the same note. If a caller sums values, it reports double the balance; selecting both copies cannot spend twice because their derived nullifiers are equal.

The same local probe records `duplicateKeyDuplicatesOwnedNote=true`. It emits no keys or amounts. This is not a new secret-dependent cryptographic attack; it is an inventory/data-validation error.

**Correction:** reject repeated decoded Orchard keys in the actor backup before scan, or return owned notes keyed by canonical append position and assert that no duplicate resource is counted. The final restore entry point must include the negative control, rather than relying only on the prepared backup having unique entries.

### W3 — `Intent::journal` validates widths after unwrapping them

**Location:** `wallet-core/src/codec.rs`:223–229.

The method converts IDs 0/5/6/7 to arrays with `unwrap()` before `self.encode()?` runs `shape()`. A directly constructed `Intent` with an empty G hash therefore panics despite the method returning `Result`.

The local probe verified this with `catch_unwind` and a suppressed panic hook, without printing any witness data. This does **not** bypass or break the reviewed guest's decoded path: `Witness::decode` decodes/shape-checks I, and `validate` shape-checks first. The current `State::apply` also decodes before calling this helper. Treat this as a nonblocking typed-API precondition for the frozen proof; do not claim a malicious wire payload can use it to mint or spend.

**Minimal future correction:** call `self.shape()?` or compute the encoded intent before converting fixed IDs. A regression on direct malformed typed IDs should return Err. Any core change creates a new source/image revision and should retain the current proof's identity as historical evidence rather than pretending the image is unchanged.

## C1–C4 implementation tracing

**C1:** `validate` checks strict CREDIT authorization on the same public auth bytes at `lib.rs`:131–138, then returns `i.journal(&w.auth)`. `Intent::journal` hashes the complete canonical intent and passes the canonical authorization digest into the established expected-journal helper. `Witness::decode` requires exact auth framing and end-of-frame. The guest commits only the validated journal bytes. The host verifies the complete expected journal computed from the actual supplied public I/auth (`state.rs`:32–34; `proof.rs`:23–27). This is coherent code-level enforcement of the reviewed auth binding, conditional on verification against the actual built guest image.

**C2:** the generic guest binds context but does not admit a pool. The host compares all eight `ids` arrays to its prior synthetic state, derives the permitted actual image from that state, and verifies the receipt against it before selecting effects. The code explicitly labels policy/deposits/history as locally trusted synthetic input. `State::genesis` derives its initial data from the designated synthetic CREDIT, so the later driver must pin that bootstrap outside the attacker-controlled history and validate actor backup context; otherwise replacing both genesis and history merely replaces the trusted fixture. This is a required harness trust boundary, not native authentication. No host test is an R13 outer proof.

**C3:** genesis initializes the allowed set with `Anchor::empty_tree`, and `Tree::default().root_path(None)` uses the same established depth-32 empty root. Accepted full operations append exactly both slots before recording the post-operation root. `exit_only` appends nothing. Current spentness is consulted separately from anchor membership. Tree capacity is checked before mutation, but maximum-tree states are not materialized by this initial harness; `adversarial.rs` accurately reports that limitation.

**C4:** all note/principal/fee fields are u64; private equation accumulators and promoted public terms are checked u128 (`lib.rs`:73–115). Kind-specific equations and irrelevant-field checks preserve the reviewed boundary. State ledgers use checked u64 addition/subtraction and clone-before-commit; credit consumes pending into private without adding reserve again, exit moves principal into an unpaid claim, and reconciliation compares the full synthetic liability sum with reserve. No native payout is implemented or implied.

## Other adversarial checks and remaining evidence

- Full SK parsing derives FVK and the selected external/internal recipient from the same SK/diversifier (`lib.rs`:18–41), without trusted caller-supplied derived keys. Old notes, commitment, nk and nullifier remain coupled. Positive notes require complete 32-level membership; zero dummies cannot bring membership or positive value with them.
- Input nullifiers must be distinct within the relation. Each is recomputed from the same old note/FVK. The host checks the current spent set before all effects and inserts both slot nullifiers, including dummies. Old-root membership alone therefore cannot reset current spentness in the intended sequential adapter.
- Output rho derives from the exact same nf slot; checked recipient/seed construct the output note. The relation recomputes commitment, derived epk and all 580 ciphertext bytes using `OrchardNoteEncryption::new(None, same_note, same_memo)` and compares all public bytes. No witness-supplied esk/rho intermediate substitutes for those computations.
- `exit_only` additionally proves both new values zero and still runs their full note/delivery computations. Capacity bypass is safe only because the permitted guest proves those zero-output conditions; a native outer or alternative guest must not infer that from the public mode string alone.
- Codec field ordering matches the reviewed intent/witness format. Lengths are checked before attacker-sized allocations, flags are exactly 0/1, intent re-encoding is compared, and complete inner frames reject trailing bytes. The 64KiB witness cap exceeds the selected bounded script/path/note profile. Guest transport may contain unused external input bytes after its declared frame; these are not part of the admitted canonical witness and cannot alter the committed public intent or grant authority.
- `proof::verify` requires a succinct receipt, explicit dev-mode prohibition, default pinned verifier parameters, successful image/journal verification, and empty assumptions. Upstream `Receipt::verify_with_context` constructs the expected successful `Halted(0)` claim; it is stronger than a seal-integrity check alone. Real succinct receipts and saved CPU verification still need to be observed; source checks are not completed proof evidence.
- Proving requires explicit IPC rather than defaulting to a remote-prover selection. The caller still supplies the local prover/toolchain environment; this code alone does not attest the identity of an arbitrary replacement IPC executable. Entropy comes from `/dev/urandom`, errors propagate, and established constructors rejection-sample valid keys/rho/seed. These are implementation observations under an uncompromised local-machine/OS assumption, not entropy or side-channel proofs.
- Secret inputs/backups use 0600 files under a 0700 research directory. I found no secret-value printing in the reviewed modules. Plaintext local backups, memory copies, workload timing and local-process trust remain declared research assumptions. Do not publish input.bin, combined lab backups, selected-note records or fresh private keys.
- The initial fixture backup contains both lab actors' keys. That does not by itself demonstrate own-backup-only recovery. The author reports a pending final actor backup/restore command that will give each actor only its own key, preserve the depositor-only recovery seed/reference, read only public history/receipts, and reconstruct a spend from scanned internal change. That claim remains pending source and runtime review.
- Initial native negative tests cover many relation and framing failures and accurately label their evidence as native checks, not proofs of invalidity. They do not yet establish all current-state/capacity/restore/receipt controls. In particular, invalid-operation classification by this host is not a proved ordinary outer classifier; native backing/order, refunds, paid markers, terminal payout, and independently operated recovery remain outside this prototype.

## Local evidence provenance and limits

The boundary probe compiled the frozen scanner/fixture/state/proof source against existing local release library artifacts. Their paths/hashes are recorded in `probe-link-artifacts.json`; the current core/guest source was checked to match the frozen snapshot. This is a bounded implementation probe, not a reproducible rebuild or soundness proof of the whole program. The first compilation attempt selected incompatible build-dependency anyhow artifacts; choosing the actual release-library profile resolved that reviewer harness issue. No protocol source was changed.

No wallets were created, keys printed/copied, funding/broadcasts performed, infrastructure changed, external messages sent, or commits/pushes made by this reviewer. Existing unfunded local research inputs were read in memory for the probe only; report outputs contain booleans/counts and source identities. All reviewer writes stayed in this review folder.

The next review must freeze the final host history/restore modules and their tests, inspect the authenticated-history and unique-key boundaries, and verify actual saved receipt evidence before marking the intended offline lifecycle/restore exercise complete. This initial result supplies no approval of funds, mainnet, native deployment, external audit assurance, or production safety.
