# Existing native outer-receipt constraints: selected RISC Zero route

**SOURCE-ONLY INVENTORY COMPLETE; genuine v6 outer execution remains DEFERRED.** The pinned native SDK implements the R0Succinct receipt boundary, including image/journal claim binding. It does not supply the missing two-v6-bundle guest, its expected image, or its settlement journal. The generic BN254 verifier remains a potentially reusable component. No fundamental incompatibility, fresh proof/native qualification, performance result or execution release follows from this note.

## Scope and identities

| Item | Identity |
| --- | --- |
| Owner | `/root/native_surface_review`; exclusive author of this note; root owns scheduling |
| Actual start / deadline | 2026-10-22 **10:23:23 UTC** / **10:53:23 UTC** |
| Source inspection stopped | 2026-10-22 **10:32:46 UTC**; subsequent work only records the inspected sources and their identities |
| Documentation input | `6b4fc65d5e64a91a134e722ff88ebc429960abe9`; source-selection SHA-256 `e20846438c5c70590f279e3fc1ced2b5e8cb8a6fcb4aa95f704d2bcecc1ea601` |
| Public project source | `ec6aa15d586bcc8a90f7232b433fd48d8c73d509`, `/home/luke/projects/kaspa-privacy-shared-pool` |
| Native SDK source | `01b532e8b553523216471682649693af92f0fd16`, `/home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e` |
| Selected historical prover record | RISC Zero SDK/r0vm 3.0.3; recorded upstream checkout `14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6` |
| Arithmetic helper pin | `substrate-bn` git `22108fe8c6ea1ebc1358fc4fd6854a6bf46e3509` |

Read-only Git/source inspection and stdlib byte/hash comparisons ran on Forge. No executable dependency imports, builds, setup, proofs, runtime tests, benchmarks, fixture generation, private evaluation reads, network transactions or GPU allocation occurred. No parked attack-design or recovery wrapper was accessed. No code, staging, index or publication change was made by this lane. Existing security invariants remain mandatory.

This fills the native-boundary inventory left unassessed in the [source-selection gate](../roadmap/OUTER-VERIFIER-SOURCE-SELECTION.md). The separate `roadmap/TWO-V6-BUNDLE-BINDING-CONTRACT.md` belongs to the lead's batching reviewer; this note does not author its guest semantics or assume that review is complete.

## Receipt-to-native map

All entries in this section are direct source facts at the pins above, unless labelled inference. Immediately before `OpZkPrecompile`, the R0Succinct stack is, **bottom to top**:

`claim | control_index | control_digests | seal | journal_digest | image_id | control_id | hashfn | tag`

The SDK witness helper supplies the first four fields. The locking fragment supplies image/control/hash/tag; the journal digest must already be on the stack or embedded by its fixed-journal variant. This is a script-field encoding, not a serialized `Receipt`, bincode object, raw journal or Groth16 proof blob.

| Field / condition | Existing encoding and enforcement | Source |
| --- | --- | --- |
| Dispatch | Exactly one tag byte; `0x21` is R0Succinct, `0x20` is direct Groth16. Opcode charges the tag cost, verifies, then pushes true only on success. | [tags][tags] lines 8–20, [dispatch][dispatch] 20–37, [opcode][opcode] 759–771 |
| Hash suite | Exactly one byte. Although the enum names other suites, this native receipt entry point accepts **Poseidon2 = 1 only**. | [R0 entry][r0] 50–57, 95–107; [receipt][receipt] 28–32 |
| Digests | `claim`, `image_id`, `control_id`, `journal_digest` are 32-byte digests. `control_digests` is a concatenation of 32-byte digests with no remainder; at most **8 siblings**, not a mandatory 8. | [R0 entry][r0] 24, 34–37, 68–75, 109–119 |
| Index and seal | Index is exactly 4 bytes, little-endian `u32`. Seal is packed little-endian `u32` words; its byte length must be a multiple of 4. No fixed v6 seal size is established. | [R0 entry][r0] 39–47, 59–65; [witness preparation][prepare] 22–34 |
| Recursion identity | The control ID recovered during seal verification must equal the supplied control ID; its inclusion proof must verify against the **compiled allowed control root**. The control root decoded from verified globals must also equal that root, and the decoded output hash must equal the supplied claim. | [receipt][receipt] 98–152 |
| Claim identity | Recomputes the SHA-based `risc0.ReceiptClaim`: pre-state = image ID; post-state = `{pc: 0, merkle_root: ZERO}`; exit = `Halted(0)`; input digest = ZERO; output = `{journal: journal_digest, assumptions: ZERO}`. Requires exact equality with the verified claim. | [claim binding][claim] 50–75, 99–100 |
| Journal bytes | The host SDK defines the journal digest as SHA-256 over exact journal bytes. The native precompile receives only that digest; it neither parses nor authenticates application field meanings separately. | [SDK journal][journal] 272–293; [claim binding][claim] 50–62 |
| Resource envelope | The R0 tag is priced at `Gram(1000 * 250).into()`; script and pushed-element maxima are each 1,000,000 bytes, stack limit 244. Actual script budgeting and the surrounding transaction still apply. These are source constants, not measured v6 capacity or throughput. | [tags][tags] 29–34; [engine][engine] 76–80, 587–594, 635–637, 691–692 |

**Consequence:** a valid receipt proves the expected program/output only when the application supplies the independently expected image and journal digest. The generic finalizer can take a caller-provided journal digest; that convenience is not application settlement validation. The locking SDK commits image, control ID and hash function into script bytes, with an optional fixed journal. A non-fixed journal must be constructed or checked against the intended native state/transaction by the surrounding covenant. [Commit helper][commit] lines 14–34; [script fragments][fragments] 38–70; [finalizer][finalizer] 12–42.

The required zero-assumptions claim matters if a future program uses recursive receipt assumptions: the final receipt must have discharged them. This is a constraint on the accepted final receipt, not a proposal to change the guest architecture. The native entry point does not accept a developer-mode stand-in merely because a host API can deserialize one.

## Existing historical integration and current v6 boundary

The older takeover covenant is a concrete source example of supplying trusted application values. Its script embeds the program/inner image pins and computes SHA-256 over an exact **352-byte** concatenation:

`prev_state || prev_lane_tip || new_state || new_lane_tip || new_seq_commit || covenant_id || tx_image_id || batch_image_id || permission_spk_hash || deposit_spk_hash || lane_key`

The construction appends actual covenant ID, embedded inner-image pins, checked output/deposit commitments and lane key before `OpSHA256`; the native call then supplies the pinned outer image. The `Succinct` variant pins `resolve.zkr` control ID `53a7b23d07f99e5d5685e85874f5181e8486aa267a0ae607ffe9ba47c8bdda4a`; the separate `SuccinctJoin` variant pins `join.zkr` ID `7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e`. Both select hash byte 1 and tag `0x21`. These are distinct recursion-program identities, **not guest image IDs**. The future guest's final control ID has not been selected. [Historical covenant][historical] lines 77–105, 168–190, 199–236, 589–651, 938–953.

The historical host obtains the expected image using `compute_image_id` of its program. Its wrap path constructs a `ProgramBinary` from raw ELF **and V1COMPAT ELF**, so the raw ELF alone is not the complete program identity. Receipt fields are explicitly unpacked for the native witness. These existing sources explain an encoding path, not an executed result in this review. [Historical host][host] lines 126–143, 454–493.

**Current v6 is a different application interface.** It hashes its exact 377-byte authorization, zero-pads the two 16-byte hash halves into two little-endian 32-byte Fr values, embeds the current VK and invokes tag **`0x20`**. Its signature builder requires a **128-byte** Groth16 proof. Therefore a succinct receipt is not a replacement blob accepted by the unchanged v6 covenant. This does not show a limitation in the existing `0x21` primitive or require a claim about new consensus rules; it identifies the missing application integration. [v6 authorization][auth] lines 24, 69–112; [v6 covenant][v6cov] 597–634.

Neither the older 352-byte journal nor its join/resolve selection is the missing two-v6-bundle journal. The inspected historical classifier image `397bcdca688462b9573a4b55e3516e1a2511140512c53337eb54da0849a93716` remains an older proxy-classifier identity, as scoped by the source-selection report. No v6 image, image reproduction, expected journal, native acceptance, pool transition or exit qualification was established here.

## Setup and parameter inventory

| Component | Existing source fact / unresolved obligation |
| --- | --- |
| Inner proof relation and VK | The reusable helper accepts a caller-validated, program-pinned VK and input vector. Its built-in `pinned()` instead selects the older PR37 key. The missing guest would need the exact existing v6 relation/VK binding; no new inner setup is justified by receipt packaging. Retained proofs can be verified from public proofs/VK/inputs without wallet secrets or proving keys. This does not audit the original inner setup's trust assumptions. [Helper][helper] 66–118. |
| Outer verification parameters | R0Succinct calls the recursion STARK verifier with compiled circuit/hash parameters and control roots. It consumes no caller-provided outer Groth16 VK or SRS. The separate Groth16-wrapped RISC Zero route is outside this selected `0x21` inventory. [Receipt][receipt] 98–152. |
| Accepted root | Recursion 4.0.4 and 4.0.5 `src/control_id.rs` are byte-identical in the inspected, archive-matched sources. Both declare root `a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56` at lines 53–55. This is a source equality, not proof interoperability. |
| Verifier-parameter digest | Native source test 174–186 and SDK 3.0.3 source test 396–399 both assert `ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013`. The digest binds control root, inner control root, proof-system info and circuit info. Neither test ran. The native entry does not accept arbitrary caller-selected verifier parameters. |
| Proving resources | The historical upstream record names recursion archive SHA-256 `744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849`. It was not fetched, unpacked or qualified here. Its presence in a record is not a new toolchain/setup attestation. [Upstream record][upstream] 5–8, 28–30. |
| Guest/program identity | Missing implemented two-v6-bundle guest and wrapped program/image are decisive prerequisites. Compiler, toolchain, program wrapper and exact dependency resolution affect identity. No guest image or resource estimate is invented from old timing/cycle records. |

**Version labels are insufficient.** The classifier guest lock has `risc0-zkvm 3.0.3` but recursion **4.0.5**, binfmt/zkp **3.0.5**, core **3.0.2** and platform **2.2.3**. The older takeover host lock retains zkvm **3.0.3** with recursion **4.0.4**, binfmt/zkp **3.0.4**, core **3.0.1** and platform **2.2.2**. Current native source pins the latter recursion/binfmt/zkp/core/platform versions and declares zkvm **3.0.4**. Thus the recorded r0vm checkout, a published `risc0-zkvm 3.0.3` crate, and each effective lock graph are separate identities. Their common declared control root and parameter digest remove an immediate source-root mismatch concern; full effective compatibility remains unqualified. [Native dependency pins][nativecargo] 301–313; the three exact lock hashes are below.

## Arkworks 0.5.0 helper versus 0.6.0 v6/native

| Boundary | Source fact and resulting constraint |
| --- | --- |
| Rust types and arity | The helper's `VerifyingKey<Bn254>`/Fr types are Arkworks 0.5.0; current v6/native use 0.6.0. They are not interchangeable Rust types. `verify_inputs` is generic over input-vector length, requiring `IC.len() == inputs.len() + 1`; v6 requires two inputs/three IC points. The old 14-input caller is not an arity limitation of this function. |
| Proof encoding | Both versions' inspected Groth16 data-structure files are byte-identical and declare proof fields A(G1), B(G2), C(G1), plus the same VK field order. Both inspected short-Weierstrass serializers use compressed x plus sign/infinity flags and checked on-curve/subgroup decoding. The helper additionally requires exactly 128 bytes, complete consumption, canonical reserialization and nonidentity A/B/C. The native parser uses checked compressed decode and rejects trailing bytes; this review does not claim equal acceptance sets. [Helper][helper] 100–118; [native Groth16][groth] 20–61, 104–118. |
| Field and point conversion | The helper converts already-validated Ark Fq/Fr coordinates to 32-byte big-endian substrate values, preserves explicit G2 c0/c1 order, and calls strict `Fr::new` rather than reducing arbitrary input with `Fr::from_slice`. The pinned substrate source documents/implements `Fr::new` as returning `None` at or above the modulus. [Helper][helper] 11–48; [substrate constructor][bn] 71–81. |
| Authorization/public input encoding | v6's public values are the two 128-bit hash limbs interpreted little-endian; native stack Fr encoding is exactly 32 bytes with checked Ark deserialization. A bridge must reproduce those values and their order, not reinterpret the entire hash or reverse limbs when changing representation. [Authorization][auth] 89–91; [native fields][fields] 22–31; [v6 covenant][v6cov] 601–619. |
| What is not established | No existing v6 VK/proof was decoded or verified across 0.6.0 and 0.5.0 here. No byte-roundtrip or pairing-equivalence execution occurred. Matching structure/length and selected serializer logic support a concrete interoperability obligation; they do not prove it or show incompatibility. Canonical keys must be validated before using the helper constructor; its unchecked built-in PR37 prepared-key path is not a v6 key loader. |

## Minimum cross-review needs; no execution release

1. **Guest contract owner:** supply the reviewed two-v6-bundle semantic contract and, later, an implemented program with an independently expected wrapped image/journal. At the native boundary it must explain exactly how those committed values relate to actual settlement state. Preserve current v6 validity, backing/no inflation, wallet-secret ownership, delivery, nullifier/state rules and independent exits. This note does not design that relation or authorize changing a pool.
2. **Serialization/dependency reviewer:** check the exact effective lock graph, allowed final recursion control identity and claim parameters; assess the checked 0.6.0-to-0.5.0 VK/proof/public-input boundary. Any later public-fixture parity execution needs its own authorization. Common roots and source assertions alone are insufficient.
3. **Native binding reviewer:** once actual image/journal and covenant integration exist, verify trusted image/control placement, byte-exact journal reconstruction from the relevant native values, successful/assumption-free claim shape, proof witness packaging and actual transaction resource limits. Generic `0x21` integrity is not evidence of current v6 reserve or exit enforcement.

No subsequent build, proof, fixture test, benchmark, pool setup, runtime validation or GPU work is authorized by this inventory. Missing guest/image and unqualified interoperability remain explicit dependencies. Historical and already completed current-v6 results are unchanged.

## Source identities

All project/native/substrate rows below are SHA-256 of exact `git show COMMIT:PATH` bytes. Links locate the reviewed files, but the recorded commit/hash governs if a checkout later moves. Registry files were read as data, matched byte-for-byte to their cached `.crate` archives, and each archive SHA matched the relevant committed Cargo.lock checksum. This was source-provenance checking only. No package code ran.

### Documentation input — `6b4fc65d5e64a91a134e722ff88ebc429960abe9`

| Path | SHA-256 |
| --- | --- |
| [AGENTS.md](/home/luke/projects/kpi-orchestration-docs-2026-10-22/AGENTS.md) | `c605a5c07d1edbdee45ada102e0c21913e663a506219190818d846179bc6d6fb` |
| [SECURITY-INVARIANTS.md](/home/luke/projects/kpi-orchestration-docs-2026-10-22/SECURITY-INVARIANTS.md) | `44cf983d06c8895c61a492107f65487725331a1b2f93d1c89e7353fb5399733d` |
| [research/orchestration/2026-10-22/README.md](/home/luke/projects/kpi-orchestration-docs-2026-10-22/research/orchestration/2026-10-22/README.md) | `0b8babd73fb650f937927adc4c9492256c16933eca6752c683205f3a9592678c` |
| [research/orchestration/2026-10-22/roadmap/OUTER-VERIFIER-SOURCE-SELECTION.md](/home/luke/projects/kpi-orchestration-docs-2026-10-22/research/orchestration/2026-10-22/roadmap/OUTER-VERIFIER-SOURCE-SELECTION.md) | `e20846438c5c70590f279e3fc1ced2b5e8cb8a6fcb4aa95f704d2bcecc1ea601` |

### Public project — `ec6aa15d586bcc8a90f7232b433fd48d8c73d509`

| Path | SHA-256 |
| --- | --- |
| [poc/accelerated-bn254/classifier-guest/Cargo.lock](/home/luke/projects/kaspa-privacy-shared-pool/poc/accelerated-bn254/classifier-guest/Cargo.lock) | `4e85f6e675336c6c0ae14ccfc239c43a8820013d976af82da215138102a479fd` |
| [poc/accelerated-bn254/common/Cargo.toml](/home/luke/projects/kaspa-privacy-shared-pool/poc/accelerated-bn254/common/Cargo.toml) | `fe44804b55e4432784f60507b079986eb2f9c71f7bdfd99744b953340cef8833` |
| [poc/accelerated-bn254/common/src/lib.rs](/home/luke/projects/kaspa-privacy-shared-pool/poc/accelerated-bn254/common/src/lib.rs) | `ff8ef9d2ea1ef93440cadcfaac086ebafad33b2ae505ba3880b596b34660041e` |
| [poc/remote-cuda/UPSTREAM.md](/home/luke/projects/kaspa-privacy-shared-pool/poc/remote-cuda/UPSTREAM.md) | `5ebd69a4cdd54b9067020e0f9e1f69fa094b1d7cd0a9a660aeab7084ecfd535b` |
| [poc/shared-pool/Cargo.lock](/home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool/Cargo.lock) | `13007a446f0d9561d50b18897b52a98c951584b2e6c7c721c95580287f5edc64` |
| [poc/shared-pool/src/two_input/covenant.rs](/home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool/src/two_input/covenant.rs) | `3b6d73c1ebada11d156f3020b444c881160e2f4d8eb7ae629a23ac267bf0d96d` |
| [poc/shared-pool/src/two_input/mod.rs](/home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool/src/two_input/mod.rs) | `255f8e908fcb1c4a76dcc8ebe0ca5f4e9ddbadc8ba46f63036cb413298bc8150` |
| [poc/takeover/Cargo.lock](/home/luke/projects/kaspa-privacy-shared-pool/poc/takeover/Cargo.lock) | `6e2715918e0dfb9d1a9968021513065bc6653d8ae22d4b97d9b2d5e7d993e0ea` |
| [poc/takeover/host/src/main.rs](/home/luke/projects/kaspa-privacy-shared-pool/poc/takeover/host/src/main.rs) | `62a25be5abbb6bc036da3226abb859be4566d5eb887d00e1028fe257a370e5e3` |
| [poc/takeover/vendor/covenant/src/script.rs](/home/luke/projects/kaspa-privacy-shared-pool/poc/takeover/vendor/covenant/src/script.rs) | `94955037b54200fb5894574ec3cee3fdb64b1360f3d2a7c730b954df5d90cf0c` |

### Native SDK — `01b532e8b553523216471682649693af92f0fd16`

| Path | SHA-256 |
| --- | --- |
| [Cargo.toml](/home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/Cargo.toml) | `307fb6594f26627e19fc4186d7f84d97b20bec754c245682169455628e32eb5e` |
| [crypto/txscript/src/lib.rs](/home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/src/lib.rs) | `f8011e2f992172f4ecfc0e5d30a89b78e07c1a3b1d0b981065bcfd0518593b53` |
| [crypto/txscript/src/opcodes/mod.rs](/home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/src/opcodes/mod.rs) | `201d69b5a8de3db27b94b3e850a7ee62c4920532886c1d19544baed7fd163731` |
| [crypto/txscript/src/zk_precompiles/fields/mod.rs](/home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/src/zk_precompiles/fields/mod.rs) | `142b04ab8f49303539cbe8bb0af090e81cbb9c35c039e56edc78480fad99c164` |
| [crypto/txscript/src/zk_precompiles/groth16/mod.rs](/home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/src/zk_precompiles/groth16/mod.rs) | `cb9fa14115d445c727cb8639ba384bde37d9a01f6c6f7fd1c92f77861f8a388d` |
| [crypto/txscript/src/zk_precompiles/mod.rs](/home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/src/zk_precompiles/mod.rs) | `4382c35fd412fb4885a475f75dcc9b55af00698476fcef6afe666d42da50989c` |
| [crypto/txscript/src/zk_precompiles/risc0/mod.rs](/home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/src/zk_precompiles/risc0/mod.rs) | `7d67128ac18975fcddf8f85167e81b962b0a42732f7db3bedbcaf19c43b19ba8` |
| [crypto/txscript/src/zk_precompiles/risc0/rcpt.rs](/home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/src/zk_precompiles/risc0/rcpt.rs) | `9952a2c84e728653ee2702fa4405e89f59eb31628cc09898c8d030c1b4faf110` |
| [crypto/txscript/src/zk_precompiles/risc0/receipt_claim.rs](/home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/src/zk_precompiles/risc0/receipt_claim.rs) | `2f5206ca6f15e93ef0f36e368da12f04497a73800c62fc4da6bc49c71c9df188` |
| [crypto/txscript/src/zk_precompiles/tags.rs](/home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/src/zk_precompiles/tags.rs) | `b3288d447e0ea09447e6564c921389bd6d5668d6d302c8d409ded7895919ef03` |
| [crypto/txscript/zk-sdk/src/zk_to_script/builder/commit/succinct.rs](/home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/zk-sdk/src/zk_to_script/builder/commit/succinct.rs) | `f9a5d34e4b9373a05e14b0ac30811628f09410d1aa7cc95bfabe9f8402d81f12` |
| [crypto/txscript/zk-sdk/src/zk_to_script/builder/proof/succinct.rs](/home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/zk-sdk/src/zk_to_script/builder/proof/succinct.rs) | `874f185f0ee039b0e4a14bd4eef4bdf410ae98b223d04fdb20066608b1a7f302` |
| [crypto/txscript/zk-sdk/src/zk_to_script/fragments/prepare/succinct.rs](/home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/zk-sdk/src/zk_to_script/fragments/prepare/succinct.rs) | `624a5187ee3bd0199959543733a45dbf12cf4c7fb6e0c4af1e46243bd6bcb57c` |
| [crypto/txscript/zk-sdk/src/zk_to_script/fragments/succinct.rs](/home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/zk-sdk/src/zk_to_script/fragments/succinct.rs) | `fda2a6ef220a2f7ae1fd701bd0958467958f17e450d069d9d61a6bd6972bb040` |

### substrate-bn — `22108fe8c6ea1ebc1358fc4fd6854a6bf46e3509`

| Path | SHA-256 |
| --- | --- |
| [src/lib.rs](/home/luke/.cargo/git/checkouts/paritytech-bn-236b913e4d848777/22108fe/src/lib.rs) | `d25705466cd77d222194b6b0256e826e23c6fefc47b9346e283a3f5580ff7183` |

### Registry source and cached archive checks

| Crate archive | SHA-256 (matches pinned lock) |
| --- | --- |
| `risc0-zkvm-3.0.3` | `3fcce11648a9ff60b8e7af2f0ce7fbf8d25275ab6d414cc91b9da69ee75bc978` |
| `risc0-circuit-recursion-4.0.4` | `2347e909c6b2a65584b5898f3802eec5b8c1b4b45329edfdd8587b6a04dd3357` |
| `risc0-circuit-recursion-4.0.5` | `40dd640122abcc67d4d4e4f055c68cbc3ad2efb8589c65c2b23d354632971b60` |
| `ark-ec-0.5.0` | `43d68f2d516162846c1238e755a7c4d131b892b70cc70c471a8e3ca3ed818fce` |
| `ark-ec-0.6.0` | `8352a2b2aedf6ba2cc38f7520fc51191d518dde96175c729af19f2d059f191c4` |
| `ark-groth16-0.5.0` | `88f1d0f3a534bb54188b8dcc104307db6c56cdae574ddc3212aec0625740fc7e` |
| `ark-groth16-0.6.0` | `a293328aa422e65527e285614ce5d1dceb0bd7b8b18d18b1b63191ee1f74cb41` |

| Source file under registry source root | SHA-256 (matches cached archive) |
| --- | --- |
| [risc0-zkvm-3.0.3/src/receipt.rs](/home/luke/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/risc0-zkvm-3.0.3/src/receipt.rs) | `5b7b75d7f17eae46517f78129e1235145f204a7b4d73104f922da4d1b542b1a6` |
| [risc0-zkvm-3.0.3/src/receipt/succinct.rs](/home/luke/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/risc0-zkvm-3.0.3/src/receipt/succinct.rs) | `26bd5e9e4f69bcef7fedd558e68c20307166e4f7258107a47d09af963e811c39` |
| [risc0-circuit-recursion-4.0.4/src/control_id.rs](/home/luke/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/risc0-circuit-recursion-4.0.4/src/control_id.rs) | `6fedf46fad3ca0ce3e537139be7873a43dd68fee5fc803d3e58604b4e9ae16cb` |
| [risc0-circuit-recursion-4.0.5/src/control_id.rs](/home/luke/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/risc0-circuit-recursion-4.0.5/src/control_id.rs) | `6fedf46fad3ca0ce3e537139be7873a43dd68fee5fc803d3e58604b4e9ae16cb` |
| [ark-ec-0.5.0/src/models/short_weierstrass/mod.rs](/home/luke/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/ark-ec-0.5.0/src/models/short_weierstrass/mod.rs) | `c7c37abf4a4c00feb4a105105e338d483e25cdb336dffc119a0c8e2650ade55b` |
| [ark-ec-0.5.0/src/models/short_weierstrass/affine.rs](/home/luke/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/ark-ec-0.5.0/src/models/short_weierstrass/affine.rs) | `225252ec363498d45685d5c3a2c3fa438947eb1944f059a32e4cf448d637e099` |
| [ark-ec-0.6.0/src/models/short_weierstrass/mod.rs](/home/luke/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/ark-ec-0.6.0/src/models/short_weierstrass/mod.rs) | `975f3c9b4b041f23cdaa12144f4c61e8559a5b52def9244afc9956694a4c42b9` |
| [ark-ec-0.6.0/src/models/short_weierstrass/affine.rs](/home/luke/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/ark-ec-0.6.0/src/models/short_weierstrass/affine.rs) | `d433d2e802ce603423341671d186fa1b5f9e637f07336eeae1cefc8ae24cf96e` |
| [ark-groth16-0.5.0/src/data_structures.rs](/home/luke/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/ark-groth16-0.5.0/src/data_structures.rs) | `b4f55d91a20107d51a9f93dcd1cfb56d184a9b99ff962057675ca2c9ec49ec08` |
| [ark-groth16-0.6.0/src/data_structures.rs](/home/luke/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/ark-groth16-0.6.0/src/data_structures.rs) | `b4f55d91a20107d51a9f93dcd1cfb56d184a9b99ff962057675ca2c9ec49ec08` |

The published `risc0-zkvm 3.0.3` archive records VCS commit `fba0c0179f0125afe23bd15eb4c34428aacf5705`; the historical r0vm checkout is separately recorded as `14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6`. This inventory does not equate those identities or attest to a newly built binary.

[tags]: /home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/src/zk_precompiles/tags.rs:8
[dispatch]: /home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/src/zk_precompiles/mod.rs:20
[opcode]: /home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/src/opcodes/mod.rs:759
[r0]: /home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/src/zk_precompiles/risc0/mod.rs:83
[receipt]: /home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/src/zk_precompiles/risc0/rcpt.rs:98
[claim]: /home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/src/zk_precompiles/risc0/receipt_claim.rs:50
[prepare]: /home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/zk-sdk/src/zk_to_script/fragments/prepare/succinct.rs:22
[fragments]: /home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/zk-sdk/src/zk_to_script/fragments/succinct.rs:38
[commit]: /home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/zk-sdk/src/zk_to_script/builder/commit/succinct.rs:14
[finalizer]: /home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/zk-sdk/src/zk_to_script/builder/proof/succinct.rs:12
[engine]: /home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/src/lib.rs:76
[journal]: /home/luke/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/risc0-zkvm-3.0.3/src/receipt.rs:272
[historical]: /home/luke/projects/kaspa-privacy-shared-pool/poc/takeover/vendor/covenant/src/script.rs:589
[host]: /home/luke/projects/kaspa-privacy-shared-pool/poc/takeover/host/src/main.rs:126
[auth]: /home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool/src/two_input/mod.rs:69
[v6cov]: /home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool/src/two_input/covenant.rs:597
[helper]: /home/luke/projects/kaspa-privacy-shared-pool/poc/accelerated-bn254/common/src/lib.rs:87
[upstream]: /home/luke/projects/kaspa-privacy-shared-pool/poc/remote-cuda/UPSTREAM.md:5
[nativecargo]: /home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/Cargo.toml:301
[groth]: /home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/src/zk_precompiles/groth16/mod.rs:20
[fields]: /home/luke/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e/crypto/txscript/src/zk_precompiles/fields/mod.rs:22
[bn]: /home/luke/.cargo/git/checkouts/paritytech-bn-236b913e4d848777/22108fe/src/lib.rs:71

Recorded and frozen on Forge at 2026-10-22 10:35:17 UTC.
